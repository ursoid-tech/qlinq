#include "tun_metrics.h"
#include "tun_json.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* prometheus label escaping differs from JSON escaping */
static void label(FILE *out, const char *text) {
  fputc('"', out);
  for (; *text; text++) {
    if (*text == '\n')
      fputs("\\n", out);
    else {
      if (*text == '\\' || *text == '"')
        fputc('\\', out);
      fputc(*text, out);
    }
  }
  fputc('"', out);
}

static void help(FILE *out, const char *name, const char *type,
                 const char *description) {
  fprintf(out, "# HELP qlinq_tun_%s %s\n# TYPE qlinq_tun_%s %s\n", name,
          description, name, type);
}

static void sample(FILE *out, const char *metric, const char *name,
                   const char *interface, const char *address) {
  fprintf(out, "qlinq_tun_%s{tunnel=", metric);
  label(out, name);
  if (interface) {
    fputs(",interface=", out);
    label(out, interface);
    fputs(",address=", out);
    label(out, address);
  }
  fputs("} ", out);
}

static void gauge(FILE *out, const char *metric, const char *description,
                  const char *name, uint64_t value) {
  help(out, metric, "gauge", description);
  sample(out, metric, name, NULL, NULL);
  fprintf(out, "%" PRIu64 "\n", value);
}

typedef struct {
  const char *key, *metric, *type, *description;
} metric;

static const metric totals[] = {
    {"sent", "tx_packets_total", "counter",
     "Inner IP packets accepted for transport sending, not delivery "
     "confirmations."},
    {"received", "rx_packets_total", "counter",
     "Valid inner IP packets received before writing to the TUN device."},
    {"tx_bytes", "tx_bytes_total", "counter",
     "Inner IP bytes accepted for transport sending."},
    {"rx_bytes", "rx_bytes_total", "counter",
     "Valid inner IP bytes received before writing to the TUN device."},
    {"dropped", "dropped_packets_total", "counter",
     "Combined transmit and receive packet drops in the TUN worker."},
    {"fec_recovered", "fec_completed_objects_total", "counter",
     "Completed datagram objects, including objects requiring no FEC "
     "decoding."},
    {"fec_decoded", "fec_decoded_objects_total", "counter",
     "Completed datagram objects that required successful FEC decoding."},
    {"fec_lost", "fec_lost_objects_total", "counter",
     "Datagram objects counted lost by the receive assembler."},
    {"reconnects", "reconnect_attempts_total", "counter",
     "Transport reconnect attempts during the worker lifetime."},
    {"queued_bytes", "transport_queued_bytes", "gauge",
     "Bytes currently queued for transport datagram egress."},
};

static const metric path_metrics[] = {
    {"active", "path_active", "gauge",
     "Whether the physical path is active and validated in the last snapshot."},
    {"rtt_ms", "path_rtt_seconds", "gauge",
     "Last RTT estimate for an active path; absent without a nonzero "
     "measurement."},
    {"tx_bytes", "path_tx_bytes_total", "counter",
     "Wire bytes sent on the physical socket; resets when the socket is "
     "replaced."},
    {"rx_bytes", "path_rx_bytes_total", "counter",
     "Wire bytes received on the physical socket; resets when the socket is "
     "replaced."},
    {"packets_lost", "path_packets_lost", "gauge",
     "Packets lost on the current QUIC path connection; resets on reconnect."},
};

char *tm_format(const char *name, const char *reply, size_t *size) {
  size_t local_size = 0;
  if (!size)
    size = &local_size;
  tj_doc *doc = calloc(1, sizeof(*doc));
  if (!doc)
    return NULL;
  char *text = NULL;
  FILE *out = NULL;
  bool ok = false;
  if (!tj_parse(doc, reply) || doc->nodes[0].type != TJ_OBJECT)
    goto done;
  const tj_node *root = &doc->nodes[0];
  const char *state = tj_string(doc, root, "state");
  const char *states[] = {"starting",  "listening", "connecting",
                          "connected", "degraded",  "reconnecting",
                          "error",     "stopping",  "stopped"};
  bool known = false;
  for (size_t i = 0; state && i < sizeof(states) / sizeof(states[0]); i++)
    if (!strcmp(state, states[i]))
      known = true;
  if (!known)
    goto done;
  uint64_t age = 0;
  const tj_node *age_node = tj_get(doc, root, "snapshot_age_ms");
  if (age_node && !tj_u64(age_node, &age))
    goto done;
  bool running = strcmp(state, "stopped") != 0;
  /* starting state has no worker snapshot yet */
  bool fresh = running && strcmp(state, "starting") && age_node && age <= 3000;
  time_t now = time(NULL);
  if (now == (time_t)-1)
    goto done;
  out = open_memstream(&text, size);
  if (!out)
    goto done;
  gauge(out, "running", "Whether a tunnel supervisor is running.", name,
        running);
  gauge(out, "snapshot_fresh",
        "Whether a worker snapshot is at most three seconds old.", name, fresh);
  gauge(out, "connected", "Whether a fresh worker snapshot reports connected.",
        name, fresh && !strcmp(state, "connected"));
  gauge(out, "metrics_export_time_seconds", "Unix time of this metrics export.",
        name, (uint64_t)now);
  help(out, "state", "gauge",
       "Last reported tunnel state; check snapshot_fresh for freshness.");
  fputs("qlinq_tun_state{tunnel=", out);
  label(out, name);
  fputs(",state=", out);
  label(out, state);
  fputs("} 1\n", out);
  if (age_node && running) {
    help(out, "snapshot_age_seconds", "gauge",
         "Age of the supervisor's cached worker snapshot.");
    sample(out, "snapshot_age_seconds", name, NULL, NULL);
    fprintf(out, "%" PRIu64 ".%03" PRIu64 "\n", age / 1000, age % 1000);
  }
  if (!running) {
    ok = true;
    goto done;
  }
  for (size_t i = 0; i < sizeof(totals) / sizeof(totals[0]); i++) {
    const metric *m = &totals[i];
    const tj_node *node = tj_get(doc, root, m->key);
    if (!node)
      continue;
    uint64_t value;
    if (!tj_u64(node, &value))
      goto done;
    help(out, m->metric, m->type, m->description);
    sample(out, m->metric, name, NULL, NULL);
    fprintf(out, "%" PRIu64 "\n", value);
  }
  const tj_node *paths = tj_get(doc, root, "paths");
  if (paths && paths->type != TJ_ARRAY)
    goto done;
  /* validate identities before emitting path families */
  for (int i = paths ? paths->child : -1; i >= 0; i = doc->nodes[i].next) {
    const tj_node *path = &doc->nodes[i];
    const char *interface = tj_string(doc, path, "interface");
    const char *address = tj_string(doc, path, "address");
    const tj_node *active = tj_get(doc, path, "active");
    if (!interface || !address || !active || active->type != TJ_LITERAL ||
        (strcmp(active->text, "true") && strcmp(active->text, "false")))
      goto done;
    for (int j = paths->child; j != i; j = doc->nodes[j].next) {
      const char *other_interface = tj_string(doc, &doc->nodes[j], "interface");
      const char *other_address = tj_string(doc, &doc->nodes[j], "address");
      if (other_interface && other_address &&
          !strcmp(interface, other_interface) &&
          !strcmp(address, other_address))
        goto done;
    }
  }
  /* keep every metric family contiguous across all paths */
  for (size_t j = 0; paths && paths->child >= 0 &&
                     j < sizeof(path_metrics) / sizeof(path_metrics[0]);
       j++) {
    const metric *m = &path_metrics[j];
    help(out, m->metric, m->type, m->description);
    for (int i = paths->child; i >= 0; i = doc->nodes[i].next) {
      const tj_node *path = &doc->nodes[i];
      const tj_node *node = tj_get(doc, path, m->key);
      if (!node)
        continue;
      uint64_t value;
      bool seconds = !strcmp(m->key, "rtt_ms");
      if (!strcmp(m->key, "active"))
        value = !strcmp(node->text, "true");
      else if (!tj_u64(node, &value))
        goto done;
      if (seconds &&
          (!value || strcmp(tj_get(doc, path, "active")->text, "true")))
        continue;
      sample(out, m->metric, name, tj_string(doc, path, "interface"),
             tj_string(doc, path, "address"));
      if (seconds)
        fprintf(out, "%" PRIu64 ".%03" PRIu64 "\n", value / 1000, value % 1000);
      else
        fprintf(out, "%" PRIu64 "\n", value);
    }
  }
  ok = true;
done:
  if (out) {
    if (ferror(out))
      ok = false;
    if (fclose(out))
      ok = false;
  }
  free(doc);
  if (!ok) {
    free(text);
    errno = EINVAL;
    return NULL;
  }
  return text;
}

bool tm_write_file(const char *path, const char *text, size_t size) {
  /* temporary file in target directory allows atomic rename; mkstemp prevents
   * races */
  char *temporary;
  if (asprintf(&temporary, "%s.XXXXXX", path) < 0)
    return false;
  int fd = mkstemp(temporary);
  if (fd < 0) {
    free(temporary);
    return false;
  }
  bool ok = false;
  const char *cursor = text;
  size_t left = size;
  while (left) {
    ssize_t n = write(fd, cursor, left);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      if (!n)
        errno = EIO;
      goto done;
    }
    cursor += n;
    left -= n;
  }
  /* metrics contain no credentials; keep private until complete, then mode 0644
   */
  if (fchmod(fd, 0644))
    goto done;
  if (close(fd)) {
    fd = -1;
    goto done;
  }
  fd = -1;
  if (rename(temporary, path))
    goto done;
  ok = true;
done: {
  int error = errno;
  if (fd >= 0)
    close(fd);
  if (!ok)
    unlink(temporary);
  free(temporary);
  errno = error;
  return ok;
}
}
