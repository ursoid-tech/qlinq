/* Sustained public-API workload. Run the endpoints in separate processes on
 * the same host: latency uses CLOCK_MONOTONIC, including across net namespaces.
 */
#include "qlinq.h"
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define HIST_BINS 10001U /* 1 ms bins; final bin contains >=10 seconds. */
#define SEEN_SLOTS (1U << 18)
#define SOURCE_SECONDS 3601U /* Maximum run plus its final partial second. */

typedef struct {
  uint64_t offered, admitted, blocked, received, bytes, duplicates, corrupt,
      stale, send_attempts;
  bool pending_record;
  uint64_t hist[HIST_BINS], interval_hist[HIST_BINS];
  uint64_t *seen, last_receive_ns, max_gap_ns;
  uint64_t deadline_ns, received_late;
  struct {
    uint64_t offered, admitted, received, late;
  } source_cohorts[SOURCE_SECONDS];
} measurements_t;

typedef struct {
  measurements_t *measurements;
  const uint8_t *expected_payload;
  size_t record_bytes;
  const uint64_t *start;
} record_consumer_t;

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000U + ts.tv_nsec;
}
static void put64(uint8_t *p, uint64_t value) {
  for (size_t i = 0; i < 8; i++)
    p[7 - i] = value >> (8 * i);
}
static uint64_t get64(const uint8_t *p) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; i++)
    value = (value << 8) | p[i];
  return value;
}

static void consume_record(record_consumer_t *consumer,
                           const qlinq_record_t *record) {
  measurements_t *m = consumer->measurements;
  uint64_t received_at = now_ns();
  const uint8_t *data = record->data;
  size_t record_bytes = consumer->record_bytes;
  uint64_t start = *consumer->start;
  if (record->size != record_bytes ||
      memcmp(data + 16, consumer->expected_payload + 16, record_bytes - 16))
    m->corrupt++;
  else {
    uint64_t id = get64(data), sent_at = get64(data + 8);
    if (!id || !start || sent_at < start || sent_at > received_at ||
        (sent_at - start) / 1000000000U >= SOURCE_SECONDS)
      m->corrupt++;
    else if (m->seen[id % SEEN_SLOTS] == id)
      m->duplicates++;
    else if (m->seen[id % SEEN_SLOTS] > id)
      m->stale++;
    else {
      m->seen[id % SEEN_SLOTS] = id;
      m->received++;
      m->bytes += record_bytes;
      size_t cohort = (sent_at - start) / 1000000000U;
      m->source_cohorts[cohort].received++;
      if (received_at - sent_at > m->deadline_ns) {
        m->received_late++;
        m->source_cohorts[cohort].late++;
      }
      size_t bin = (received_at - sent_at) / 1000000;
      if (bin >= HIST_BINS)
        bin = HIST_BINS - 1;
      m->hist[bin]++;
      m->interval_hist[bin]++;
      uint64_t gap =
          received_at - (m->last_receive_ns ? m->last_receive_ns : start);
      if (gap > m->max_gap_ns)
        m->max_gap_ns = gap;
      m->last_receive_ns = received_at;
    }
  }
}

static bool consume_record_callback(void *user_data,
                                    const qlinq_event_t *event) {
  record_consumer_t *consumer = user_data;
  consume_record(consumer, &event->record);
  return true;
}
static double number(const char *s, double lo, double hi) {
  char *end;
  errno = 0;
  double n = strtod(s, &end);
  if (errno || end == s || *end || !isfinite(n) || n < lo || n > hi) {
    fprintf(stderr, "invalid argument: %s\n", s);
    exit(2);
  }
  return n;
}
static uint32_t integer(const char *text, uint32_t minimum, uint32_t maximum) {
  double value = number(text, minimum, maximum);
  if (value != floor(value)) {
    fprintf(stderr, "invalid integer: %s\n", text);
    exit(2);
  }
  return (uint32_t)value;
}

static double p99(const uint64_t *hist) {
  uint64_t total = 0, count = 0;
  for (size_t i = 0; i < HIST_BINS; i++)
    total += hist[i];
  if (!total)
    return -1;
  for (size_t i = 0; i < HIST_BINS; i++) {
    count += hist[i];
    if (count >= total - total / 100)
      return i == HIST_BINS - 1 ? 10000 : i + 1;
  }
  return -1;
}
static void report(const char *event, const char *role,
                   const char *receive_delivery, measurements_t *m,
                   qlinq_endpoint_t *ep, uint64_t start, uint64_t now,
                   uint64_t previous_bytes, uint64_t previous_ns) {
  qlinq_endpoint_stats_t stats = {0};
  qlinq_endpoint_get_stats(ep, &stats);
  struct rusage usage;
  getrusage(RUSAGE_SELF, &usage);
  double cpu = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6 +
               usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6;
  printf(
      "{\"event\":\"%s\",\"role\":\"%s\","
      "\"receive_delivery\":\"%s\",\"time\":%.6f,"
      "\"offered\":%" PRIu64 ",\"admitted\":%" PRIu64
      ",\"backpressured\":%" PRIu64 ","
      "\"received\":%" PRIu64 ",\"received_bytes\":%" PRIu64
      ",\"goodput_mbps\":%.6f,"
      "\"duplicates\":%" PRIu64 ",\"corrupt\":%" PRIu64
      ",\"outside_reorder_window\":%" PRIu64 ","
      "\"p99_ms\":%.0f,\"interval_p99_ms\":%.0f,\"max_completion_gap_ms\":%.3f,"
      "\"queued_bytes\":%zu,\"recovery_bytes\":%zu,\"repair_symbols\":%" PRIu64
      ","
      "\"fec_objects_lost\":%" PRIu64 ",\"fec_objects_recovered\":%" PRIu64 ","
      "\"send_attempts\":%" PRIu64 ",\"source_pending_records\":%u,"
      "\"cpu_seconds\":%.6f,\"max_rss_kib\":%ld,"
      "\"deadline_ms\":%.3f,\"received_late\":%" PRIu64,
      event, role, receive_delivery, (now - start) / 1e9, m->offered,
      m->admitted, m->blocked, m->received, m->bytes,
      now > previous_ns
          ? (m->bytes - previous_bytes) * 8000.0 / (now - previous_ns)
          : 0,
      m->duplicates, m->corrupt, m->stale, p99(m->hist), p99(m->interval_hist),
      m->max_gap_ns / 1e6, stats.queued_bytes,
      stats.recovery_cache_payload_bytes, stats.repair_symbols_sent,
      stats.fec_objects_lost, stats.fec_objects_recovered, m->send_attempts,
      m->pending_record ? 1U : 0U, cpu, usage.ru_maxrss, m->deadline_ns / 1e6,
      m->received_late);
  printf(",\"repair_requests_sent\":%" PRIu64
         ",\"repair_requests_received\":%" PRIu64
         ",\"repair_requests_deferred\":%" PRIu64
         ",\"repair_requests_coalesced\":%" PRIu64 ",\"recovery_entries\":%zu",
         stats.repair_requests_sent, stats.repair_requests_received,
         stats.repair_requests_deferred, stats.repair_requests_coalesced,
         stats.recovery_cache_entries);
  printf(",\"stream_egress_bytes\":%zu,\"stream_egress_peak_bytes\":%zu,"
         "\"stream_egress_frames\":%zu,\"stream_egress_peak_frames\":%zu",
         stats.stream_egress_bytes, stats.stream_egress_peak_bytes,
         stats.stream_egress_frames, stats.stream_egress_peak_frames);
  printf(",\"stream_egress_blocked\":%" PRIu64
         ",\"stream_control_failures\":%" PRIu64 ",\"queued_packets\":%zu",
         stats.stream_egress_blocked, stats.stream_control_failures,
         stats.queued_packets);
  printf(",\"record_events_queued\":%" PRIu64
         ",\"record_payload_bytes_copied\":%" PRIu64
         ",\"record_callbacks_accepted\":%" PRIu64
         ",\"record_callbacks_rejected\":%" PRIu64,
         stats.record_events_queued, stats.record_payload_bytes_copied,
         stats.record_callbacks_accepted, stats.record_callbacks_rejected);
  printf(",\"path_stats\":[");
  bool first_path = true;
  for (size_t path = 0; path < QLINQ_MAX_PATHS; path++) {
    qlinq_path_info_t path_info;
    if (!qlinq_endpoint_get_path(ep, path, &path_info))
      break;
    printf("%s{\"path\":%zu,\"state\":%u,\"bytes_sent\":%" PRIu64
           ",\"bytes_received\":%" PRIu64 ",\"packets_sent\":%" PRIu64
           ",\"packets_acked\":%" PRIu64 ",\"packets_lost\":%" PRIu64
           ",\"bytes_acked\":%" PRIu64 ",\"rtt_ms\":%u"
           ",\"cwnd_bytes\":%u,\"bytes_in_flight\":%u"
           ",\"relative_owd_ms\":%.6f,\"ewma_latency_ms\":%.6f}",
           first_path ? "" : ",", path, (unsigned)path_info.state,
           path_info.bytes_sent, path_info.bytes_received,
           path_info.packets_sent, path_info.packets_acked,
           path_info.packets_lost, path_info.bytes_acked,
           path_info.smoothed_rtt_ms, path_info.congestion_window_bytes,
           path_info.bytes_in_flight, path_info.relative_one_way_delay_ms,
           path_info.ewma_latency_ms);
    first_path = false;
  }
  printf("]");
  if (!strcmp(event, "sample")) {
    /* Sparse interval bins permit record-weighted phase percentiles. Averaging
     * per-second p99 values cannot reconstruct the phase distribution. */
    printf(",\"interval_start\":%.6f,\"latency_histogram_ms\":[",
           (previous_ns - start) / 1e9);
    bool first = true;
    for (size_t i = 0; i < HIST_BINS; i++) {
      if (!m->interval_hist[i])
        continue;
      printf("%s[%zu,%" PRIu64 "]", first ? "" : ",", i, m->interval_hist[i]);
      first = false;
    }
    printf("]");
  }
  if (!strcmp(event, "summary")) {
    printf(",\"source_cohorts\":[");
    bool first = true;
    for (size_t i = 0; i < SOURCE_SECONDS; i++) {
      if (!m->source_cohorts[i].offered && !m->source_cohorts[i].received)
        continue;
      printf("%s{\"second\":%zu,\"offered\":%" PRIu64 ",\"admitted\":%" PRIu64
             ",\"received\":%" PRIu64 ",\"late\":%" PRIu64 "}",
             first ? "" : ",", i, m->source_cohorts[i].offered,
             m->source_cohorts[i].admitted, m->source_cohorts[i].received,
             m->source_cohorts[i].late);
      first = false;
    }
    printf("]");
  }
  printf("}\n");
  memset(m->interval_hist, 0, sizeof(m->interval_hist));
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  const char *role = NULL, *start_file = NULL, *mode = "fixed-fec",
             *receive_delivery = "queue";
  bool retry_backpressure = false;
  double seconds = 90, drain = 5, mbps = 1200, deadline_ms = 200;
  int service_wait_ms = 1;
  size_t send_batch = 32;
  double step_at = 0, step_mbps = 0;
  bool step_announced = false;
  size_t record_bytes = 8000;
  size_t max_queued_events = 8192;
  size_t max_queued_event_bytes = 128U * 1024U * 1024U;
  qlinq_endpoint_config_t cfg = {.port = 19871};
  cfg.security.allow_insecure_peer = true;
  cfg.security.certificate_file = "t/assets/server.crt";
  cfg.security.private_key_file = "t/assets/server.key";
  for (int i = 1; i < argc; i++) {
    if (i + 1 >= argc) {
      fprintf(stderr, "missing value for %s\n", argv[i]);
      return 2;
    }
    const char *key = argv[i], *value = argv[++i];
    if (!strcmp(key, "--role"))
      role = value;
    else if (!strcmp(key, "--start-file"))
      start_file = value;
    else if (!strcmp(key, "--mode"))
      mode = value;
    else if (!strcmp(key, "--receive-delivery")) {
      if (strcmp(value, "queue") && strcmp(value, "callback"))
        return 2;
      receive_delivery = value;
    } else if (!strcmp(key, "--congestion-control")) {
      if (!strcmp(value, "default"))
        cfg.congestion_control = QLINQ_CC_DEFAULT;
      else if (!strcmp(value, "reno"))
        cfg.congestion_control = QLINQ_CC_RENO;
      else if (!strcmp(value, "pico"))
        cfg.congestion_control = QLINQ_CC_PICO;
      else if (!strcmp(value, "cubic"))
        cfg.congestion_control = QLINQ_CC_CUBIC;
      else
        return 2;
    } else if (!strcmp(key, "--pacing")) {
      if (!strcmp(value, "default"))
        cfg.pacing = QLINQ_PACING_DEFAULT;
      else if (!strcmp(value, "off"))
        cfg.pacing = QLINQ_PACING_DISABLED;
      else if (!strcmp(value, "on"))
        cfg.pacing = QLINQ_PACING_ENABLED;
      else
        return 2;
    } else if (!strcmp(key, "--source-policy")) {
      if (strcmp(value, "discard") && strcmp(value, "retry"))
        return 2;
      retry_backpressure = !strcmp(value, "retry");
    } else if (!strcmp(key, "--seconds"))
      seconds = number(value, 1, 3600);
    else if (!strcmp(key, "--drain"))
      drain = number(value, 0.1, 60);
    else if (!strcmp(key, "--deadline-ms"))
      deadline_ms = number(value, 0.1, 60000);
    else if (!strcmp(key, "--service-wait-ms")) {
      uint32_t n = integer(value, 0, 1000);
      service_wait_ms = (int)n;
    } else if (!strcmp(key, "--send-batch")) {
      uint32_t n = integer(value, 1, 4096);
      send_batch = n;
    } else if (!strcmp(key, "--mbps"))
      mbps = number(value, 0.01, 100000);
    else if (!strcmp(key, "--step-at"))
      step_at = number(value, 0.01, 3600);
    else if (!strcmp(key, "--step-mbps"))
      step_mbps = number(value, 0.01, 100000);
    else if (!strcmp(key, "--record-bytes")) {
      uint32_t n = integer(value, 32, 16000);
      record_bytes = n;
    } else if (!strcmp(key, "--event-queue-events") ||
               !strcmp(key, "--event-queue-bytes")) {
      uint32_t n = integer(value, 1, UINT32_MAX);
      if (!strcmp(key, "--event-queue-events"))
        max_queued_events = n;
      else
        max_queued_event_bytes = n;
    } else if (!strcmp(key, "--receive-objects")) {
      uint32_t n = integer(value, 1, 1024);
      cfg.limits.max_active_receive_objects_per_peer = n;
    } else if (!strcmp(key, "--repair-requests-per-second") ||
               !strcmp(key, "--aggregate-repair-requests-per-second") ||
               !strcmp(key, "--aggregate-nack-requests-per-second")) {
      uint32_t n = integer(value, 1, UINT16_MAX);
      if (!strcmp(key, "--repair-requests-per-second"))
        cfg.limits.max_repair_requests_per_second = n;
      else if (!strcmp(key, "--aggregate-repair-requests-per-second"))
        cfg.limits.max_aggregate_repair_requests_per_second = n;
      else
        cfg.limits.max_aggregate_nack_requests_per_second = n;
    } else if (!strcmp(key, "--stream-egress-bytes") ||
               !strcmp(key, "--total-stream-egress-bytes") ||
               !strcmp(key, "--receive-memory-bytes") ||
               !strcmp(key, "--recovery-cache-bytes") ||
               !strcmp(key, "--egress-packets") ||
               !strcmp(key, "--egress-bytes") ||
               !strcmp(key, "--packets-per-service")) {
      uint32_t n = integer(value, 1, UINT32_MAX);
      if (!strcmp(key, "--total-stream-egress-bytes"))
        cfg.limits.max_total_stream_egress_bytes = n;
      else if (!strcmp(key, "--stream-egress-bytes"))
        cfg.limits.max_stream_egress_bytes = n;
      else if (!strcmp(key, "--receive-memory-bytes"))
        cfg.limits.max_receive_memory_bytes = n;
      else if (!strcmp(key, "--recovery-cache-bytes"))
        cfg.limits.max_recovery_cache_bytes = n;
      else if (!strcmp(key, "--egress-packets"))
        cfg.limits.max_egress_packets_per_socket = n;
      else if (!strcmp(key, "--egress-bytes"))
        cfg.limits.max_egress_bytes_per_socket = n;
      else
        cfg.limits.max_packets_per_service = n;
    } else if (!strcmp(key, "--bind") &&
               cfg.bind_address_count < QLINQ_MAX_PATHS)
      cfg.bind_addresses[cfg.bind_address_count++] = value;
    else if (!strcmp(key, "--remote") &&
             cfg.remote_address_count < QLINQ_MAX_PATHS)
      cfg.remote_addresses[cfg.remote_address_count++] = value;
    else {
      fprintf(stderr, "unknown/excess argument: %s\n", key);
      return 2;
    }
  }
  if ((step_at != 0) != (step_mbps != 0) || step_at >= seconds) {
    fprintf(stderr, "step requires --step-at before end and --step-mbps\n");
    return 2;
  }
  if (!role || (strcmp(role, "send") && strcmp(role, "receive")) ||
      !start_file || !cfg.bind_address_count) {
    fprintf(stderr, "requires --role send|receive, --bind, --start-file\n");
    return 2;
  }
  bool sending = !strcmp(role, "send");
  if ((sending && cfg.remote_address_count) ||
      (!sending && cfg.remote_address_count != cfg.bind_address_count))
    return 2;
  qlinq_stream_config_t stream_cfg = {.content_type = QLINQ_CONTENT_DATA,
                                      .name = "transit"};
  if (!strcmp(mode, "fixed-fec"))
    stream_cfg.delivery = QLINQ_DELIVERY_FIXED_FEC;
  else if (!strcmp(mode, "rateless"))
    stream_cfg.delivery = QLINQ_DELIVERY_RATELESS;
  else if (!strcmp(mode, "reliable"))
    stream_cfg.delivery = QLINQ_DELIVERY_RELIABLE;
  else {
    fprintf(stderr, "unknown mode\n");
    return 2;
  }
  measurements_t *m = calloc(1, sizeof(*m));
  uint8_t *payload = malloc(record_bytes);
  if (!m || !payload || !(m->seen = calloc(SEEN_SLOTS, sizeof(*m->seen))))
    return 1;
  m->deadline_ns = (uint64_t)(deadline_ms * 1e6);
  for (size_t i = 0; i < record_bytes; i++)
    payload[i] = (uint8_t)i;
  /* qlinq delivers one copied public event per completed record. At 2.3 Gbps
   * of 8 KiB records, the library's interactive default (1,024 events) can
   * fill in one receive service pass before this cooperative consumer drains
   * it. These are explicit, bounded harness resources, not transport knobs. */
  const char *actual_receive_delivery = !sending ? receive_delivery : "queue";
  record_consumer_t record_consumer = {.measurements = m,
                                       .expected_payload = payload,
                                       .record_bytes = record_bytes};
  qlinq_context_config_t context_cfg = {
      .max_queued_events = max_queued_events,
      .max_queued_event_bytes = max_queued_event_bytes,
      .record_callback = !strcmp(actual_receive_delivery, "callback")
                             ? consume_record_callback
                             : NULL,
      .record_user_data = !strcmp(actual_receive_delivery, "callback")
                              ? &record_consumer
                              : NULL};
  qlinq_context_t *ctx = qlinq_context_create(&context_cfg);
  if (!ctx)
    return 1;
  qlinq_endpoint_t *ep =
      sending ? qlinq_listen(ctx, &cfg) : qlinq_connect(ctx, &cfg);
  qlinq_stream_t *stream = ep ? (sending ? qlinq_publish(ep, &stream_cfg)
                                         : qlinq_subscribe(ep, &stream_cfg))
                              : NULL;
  if (!stream) {
    fprintf(stderr, "endpoint/stream creation failed\n");
    return 1;
  }
  uint64_t start = 0, opened = now_ns(), next_report = 0, previous_ns = 0,
           previous_bytes = 0;
  record_consumer.start = &start;
  uint32_t peer = 0;
  bool announced = false, failed = false;
  while (!failed) {
    uint64_t now = now_ns();
    if (start && now >= start + (uint64_t)((seconds + drain) * 1e9))
      break;
    int wait_ms = service_wait_ms;
    if (sending && start && now >= start &&
        now < start + (uint64_t)(seconds * 1e9)) {
      double next_megabits = (m->offered + 1) * (8.0 * record_bytes / 1e6);
      double due_seconds = next_megabits / mbps;
      if (step_at && due_seconds > step_at)
        due_seconds = step_at + (next_megabits - step_at * mbps) / step_mbps;
      uint64_t due = start + (uint64_t)(due_seconds * 1e9);
      if (due <= now || due - now < 1000000)
        wait_ms = 0;
    }
    qlinq_status_t status = qlinq_service(ctx, wait_ms);
    if (status < 0) {
      fprintf(stderr, "service failed: %d\n", status);
      failed = true;
      break;
    }
    qlinq_event_t ev;
    while (qlinq_next_event(ctx, &ev)) {
      if (ev.type == QLINQ_EVENT_PEER_READY)
        peer = ev.peer_id;
      bool end_reached =
          start && now_ns() >= start + (uint64_t)((seconds + drain) * 1e9);
      if ((ev.type == QLINQ_EVENT_PEER_DISCONNECTED && !end_reached) ||
          ev.type == QLINQ_EVENT_PEER_REJECTED ||
          ev.type == QLINQ_EVENT_ERROR) {
        fprintf(stderr, "endpoint event failed: %d %s\n", ev.type,
                ev.message ? ev.message : "");
        failed = true;
      }
      if (ev.type == QLINQ_EVENT_RECORD)
        consume_record(&record_consumer, &ev.record);
      qlinq_event_release(&ev);
    }
    if (!announced && peer) {
      qlinq_peer_info_t info;
      qlinq_stream_stats_t stats;
      if (qlinq_endpoint_get_peer(ep, peer, &info) && info.ready &&
          info.paths_validated + 1 >= cfg.bind_address_count &&
          qlinq_stream_get_stats(stream, &stats) &&
          (!sending || stats.subscribers)) {
        printf("{\"event\":\"ready\",\"role\":\"%s\",\"paths\":%zu}\n", role,
               cfg.bind_address_count);
        announced = true;
      }
    }
    if (!start) {
      if (now - opened > UINT64_C(30000000000)) {
        fprintf(stderr, "start/handshake timeout\n");
        failed = true;
        break;
      }
      if (announced) {
        FILE *f = fopen(start_file, "r");
        if (f) {
          if (fscanf(f, "%" SCNu64, &start) != 1 || start <= now) {
            fprintf(stderr, "invalid or late common start\n");
            failed = true;
          }
          fclose(f);
          previous_ns = start;
          next_report = start + 1000000000U;
        }
      }
      continue;
    }
    if (now < start)
      continue;
    if (!sending && now < start + (uint64_t)(seconds * 1e9)) {
      uint64_t last = m->last_receive_ns ? m->last_receive_ns : start;
      if (now > last && now - last > m->max_gap_ns)
        m->max_gap_ns = now - last;
    }
    if (sending &&
        (m->pending_record || now < start + (uint64_t)(seconds * 1e9))) {
      uint64_t elapsed = now - start;
      if (elapsed > (uint64_t)(seconds * 1e9))
        elapsed = (uint64_t)(seconds * 1e9);
      double elapsed_seconds = elapsed / 1e9;
      double before =
          step_at ? fmin(elapsed_seconds, step_at) : elapsed_seconds;
      double after = step_at ? fmax(0, elapsed_seconds - step_at) : 0;
      uint64_t target = (uint64_t)((before * mbps + after * step_mbps) * 1e6 /
                                   (8.0 * record_bytes));
      if (step_at && !step_announced && elapsed_seconds >= step_at) {
        printf("{\"event\":\"rate_change\",\"time\":%.6f,\"mbps\":%.6f,"
               "\"scheduled_time\":%.6f}\n",
               elapsed_seconds, step_mbps, step_at);
        step_announced = true;
      }
      for (size_t batch = 0; batch < send_batch; batch++) {
        if (!m->pending_record) {
          uint64_t submitted_at = now_ns();
          if (submitted_at >= start + (uint64_t)(seconds * 1e9) ||
              m->offered >= target)
            break;
          uint64_t id = ++m->offered;
          put64(payload, id);
          put64(payload + 8, submitted_at);
          size_t cohort = (get64(payload + 8) - start) / 1000000000U;
          if (cohort >= SOURCE_SECONDS) {
            failed = true;
            break;
          }
          m->source_cohorts[cohort].offered++;
          m->pending_record = true;
        }
        /* A cooperative producer holds at most one rejected record, retaining
         * its identity and original submission timestamp across service calls.
         * Generation shortfall still fails the target-load gate. */
        qlinq_record_t record = {.sequence = get64(payload),
                                 .data = payload,
                                 .size = record_bytes,
                                 .priority = 2};
        m->send_attempts++;
        qlinq_send_result_t result = qlinq_stream_send(stream, &record);
        if (result == QLINQ_SEND_SENT || result == QLINQ_SEND_BUFFERED) {
          m->admitted++;
          m->source_cohorts[(get64(payload + 8) - start) / 1000000000U]
              .admitted++;
          m->pending_record = false;
        } else if (result == QLINQ_SEND_WOULD_BLOCK) {
          m->blocked++;
          if (retry_backpressure)
            break;
          m->pending_record = false;
        } else {
          fprintf(stderr, "send failed: %d\n", result);
          failed = true;
          break;
        }
      }
    }
    if (now >= next_report) {
      uint64_t report_at = now_ns();
      report("sample", role, actual_receive_delivery, m, ep, start, report_at,
             previous_bytes, previous_ns);
      previous_bytes = m->bytes;
      previous_ns = report_at;
      next_report = report_at + 1000000000U;
    }
  }
  uint64_t ended = now_ns();
  if (start)
    report("summary", role, actual_receive_delivery, m, ep, start, ended, 0,
           start);
  qlinq_context_destroy(ctx);
  free(m->seen);
  free(m);
  free(payload);
  return failed ? 1 : 0;
}
