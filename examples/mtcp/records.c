/* Matched fixed-size, paced records for qlinq and TCP/MPTCP + TLS 1.3.
 * Run only in the isolated same-host testbed: timestamps use CLOCK_MONOTONIC.
 * Record format is host-endian and is deliberately identical for both backends.
 */
#define _GNU_SOURCE
#include "qlinq.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define RECORD 8192
#define PORT 18443
#define DRAIN_NS 10000000000ULL
static uint64_t start, finish, count, sent, blocked, received, in_window,
    timely;
static uint64_t duplicate, corrupt, rejected, late_admissions, last_rx, max_gap;
static double *latencies, rate, cpu_at_start = -1, cpu_at_finish = -1;
static unsigned char *seen;
static FILE *samples;
static int sender;
static const char *mode;
static uint64_t now_ns(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static double cpu_now(void) {
  struct rusage u;
  getrusage(RUSAGE_SELF, &u);
  return u.ru_utime.tv_sec + u.ru_utime.tv_usec / 1e6 + u.ru_stime.tv_sec +
         u.ru_stime.tv_usec / 1e6;
}
static void observe_cpu(void) {
  uint64_t t = now_ns();
  if (t >= start && cpu_at_start < 0)
    cpu_at_start = cpu_now();
  if (t >= finish && cpu_at_finish < 0)
    cpu_at_finish = cpu_now();
}
static void die(const char *s) {
  perror(s);
  ERR_print_errors_fp(stderr);
  exit(2);
}
static void require(int ok, const char *s) {
  if (!ok)
    die(s);
}
static uint64_t scheduled(uint64_t seq) {
  return start + (uint64_t)((double)seq * RECORD * 8e9 / rate);
}
static void fill(unsigned char *p, uint64_t seq) {
  uint64_t h[4] = {seq, scheduled(seq), count, start};
  memcpy(p, h, sizeof h);
  for (size_t i = sizeof h; i < RECORD; i++)
    p[i] = (unsigned char)(i ^ seq);
}
static void receive_record(const void *data, size_t n) {
  uint64_t t = now_ns(), h[4];
  if (n != RECORD) {
    corrupt++;
    return;
  }
  memcpy(h, data, sizeof h);
  if (h[0] >= count || h[1] != scheduled(h[0]) || h[2] != count ||
      h[3] != start) {
    corrupt++;
    return;
  }
  const unsigned char *p = data;
  for (size_t i = sizeof h; i < RECORD; i++)
    if (p[i] != (unsigned char)(i ^ h[0])) {
      corrupt++;
      return;
    }
  if (seen[h[0]]) {
    duplicate++;
    return;
  }
  seen[h[0]] = 1;
  double ms = (double)(t - h[1]) / 1e6;
  latencies[received++] = ms;
  in_window += t <= finish;
  timely += ms <= 100.;
  if (last_rx && t - last_rx > max_gap)
    max_gap = t - last_rx;
  last_rx = t;
  fprintf(samples, "%lu,%lu,%.6f\n", (unsigned long)h[0], (unsigned long)t, ms);
}
static int double_cmp(const void *a, const void *b) {
  double x = *(const double *)a, y = *(const double *)b;
  return (x > y) - (x < y);
}
static double percentile(double p) {
  return received ? latencies[(size_t)((received - 1) * p)] : -1.;
}
static void report(void) {
  struct rusage u;
  getrusage(RUSAGE_SELF, &u);
  double cpu = cpu_now();
  qsort(latencies, received, sizeof(double), double_cmp);
  printf(
      "{\"mode\":\"%s\",\"sender\":%s,\"offered_records\":%lu,\"accepted_"
      "records\":%lu,"
      "\"would_block_calls\":%lu,\"rejected_records\":%lu,\"late_admissions\":%"
      "lu,"
      "\"received_records\":%lu,\"in_window_records\":%lu,\"within_100ms\":%lu,"
      "\"duplicates\":%lu,\"corrupt\":%lu,\"p50_ms\":%.6f,\"p95_ms\":%.6f,"
      "\"p99_ms\":%.6f,"
      "\"max_gap_ms\":%.6f,\"last_receive_ns\":%lu,\"cpu_seconds\":%.6f,\"cpu_"
      "offered_seconds\":%.6f,\"maxrss_kib\":%ld}\n",
      mode, sender ? "true" : "false", (unsigned long)count,
      (unsigned long)sent, (unsigned long)blocked, (unsigned long)rejected,
      (unsigned long)late_admissions, (unsigned long)received,
      (unsigned long)in_window, (unsigned long)timely, (unsigned long)duplicate,
      (unsigned long)corrupt, percentile(.5), percentile(.95), percentile(.99),
      max_gap / 1e6, (unsigned long)last_rx, cpu, cpu_at_finish - cpu_at_start,
      u.ru_maxrss);
}
static void log_event(void *unused, const qlinq_log_event_t *e) {
  (void)unused;
  if (e->level >= QLINQ_LOG_WARNING)
    fprintf(stderr, "qlinq: %s\n", e->message);
}
/* Match CPU-study policy explicitly without changing record generation,
 * delivery, or the library defaults. These settings are read before offering.
 */
static void configure_policy(qlinq_endpoint_config_t *cfg) {
  const char *cc = getenv("QLINQ_BENCH_CC");
  const char *pacing = getenv("QLINQ_BENCH_PACING");
  if (!cc || !*cc)
    cc = "default";
  if (!pacing || !*pacing)
    pacing = "default";
  if (!strcmp(cc, "default"))
    cfg->congestion_control = QLINQ_CC_DEFAULT;
  else if (!strcmp(cc, "reno"))
    cfg->congestion_control = QLINQ_CC_RENO;
  else if (!strcmp(cc, "pico"))
    cfg->congestion_control = QLINQ_CC_PICO;
  else if (!strcmp(cc, "cubic"))
    cfg->congestion_control = QLINQ_CC_CUBIC;
  else {
    fprintf(stderr, "invalid QLINQ_BENCH_CC: %s\n", cc);
    exit(2);
  }
  if (!strcmp(pacing, "default"))
    cfg->pacing = QLINQ_PACING_DEFAULT;
  else if (!strcmp(pacing, "off"))
    cfg->pacing = QLINQ_PACING_DISABLED;
  else if (!strcmp(pacing, "on"))
    cfg->pacing = QLINQ_PACING_ENABLED;
  else {
    fprintf(stderr, "invalid QLINQ_BENCH_PACING: %s\n", pacing);
    exit(2);
  }
  fprintf(stderr,
          "qlinq requested controller=%s pacing=%s initial_cwnd_packets=100\n",
          cc, pacing);
}

static void run_qlinq(int paths, const char *cert, const char *key) {
  qlinq_context_config_t cc = {.log_callback = log_event};
  qlinq_context_t *ctx = qlinq_context_create(&cc);
  require(ctx != NULL, "qlinq context");
  qlinq_endpoint_config_t cfg = {
      .port = PORT,
      .idle_timeout_ms = 30000,
      .bind_address_count = sender ? (size_t)paths : 1,
      .remote_address_count = sender ? 1 : 0,
      .security = {.shared_secret = "isolated-comparison",
                   .shared_secret_size = 19,
                   .certificate_file = cert,
                   .private_key_file = key,
                   .trust_store_file = cert,
                   .verify_peer = true}};
  configure_policy(&cfg);
  cfg.bind_addresses[0] = sender ? "10.231.1.1" : "10.232.1.2";
  cfg.bind_addresses[1] = "10.231.2.1";
  cfg.remote_addresses[0] = "10.232.1.2";
  cfg.path_interface_names[0] = sender ? "c1" : "s1";
  cfg.path_interface_names[1] = "c2";
  cfg.path_interface_count = cfg.bind_address_count;
  /* explicit bounded stream budget; kernel and library accounting differ */
  cfg.limits.max_stream_egress_bytes = 4 * 1024 * 1024;
  cfg.limits.max_total_stream_egress_bytes = 8 * 1024 * 1024;
  cfg.limits.max_recovery_cache_bytes = 32 * 1024 * 1024;
  cfg.limits.max_receive_memory_bytes = 64 * 1024 * 1024;
  qlinq_endpoint_t *ep =
      sender ? qlinq_connect(ctx, &cfg) : qlinq_listen(ctx, &cfg);
  require(ep != NULL, "qlinq endpoint");
  qlinq_stream_config_t sc = {
      .name = "comparison",
      .content_type = QLINQ_CONTENT_DATA,
      .delivery = !strcmp(mode, "fec")        ? QLINQ_DELIVERY_FIXED_FEC
                  : !strcmp(mode, "rateless") ? QLINQ_DELIVERY_RATELESS
                                              : QLINQ_DELIVERY_RELIABLE};
  qlinq_stream_t *stream =
      sender ? qlinq_publish(ep, &sc) : qlinq_subscribe(ep, &sc);
  require(stream != NULL, "qlinq stream");
  unsigned char payload[RECORD];
  uint64_t seq = 0;
  int ready = 0, checked = 0;
  while (now_ns() < finish + DRAIN_NS) {
    observe_cpu();
    require(qlinq_service(ctx, 1) >= 0, "qlinq service");
    qlinq_event_t e;
    while (qlinq_next_event(ctx, &e)) {
      if (e.type == QLINQ_EVENT_SUBSCRIBER_JOINED ||
          (!sender && e.type == QLINQ_EVENT_PEER_READY))
        ready = 1;
      if (e.type == QLINQ_EVENT_RECORD)
        receive_record(e.record.data, e.record.size);
      if (e.type == QLINQ_EVENT_PEER_DISCONNECTED)
        fprintf(stderr, "peer disconnected at %.3f seconds\n",
                ((double)now_ns() - (double)start) / 1e9);
      if (e.type == QLINQ_EVENT_ERROR || e.type == QLINQ_EVENT_PEER_REJECTED) {
        fprintf(stderr, "qlinq event %d: %s\n", e.type,
                e.message ? e.message : "");
        exit(2);
      }
      qlinq_event_release(&e);
    }
    if (now_ns() >= start && !checked) {
      require(ready, "qlinq not ready at scheduled start");
      checked = 1;
    }
    if (!sender || !ready)
      continue;
    for (int batch = 0;
         seq < count && batch < 128 && now_ns() >= scheduled(seq); batch++) {
      /* preserve offered schedule under backpressure; do not reset timestamps
       */
      if (now_ns() >= finish) {
        rejected += count - seq;
        seq = count;
        break;
      }
      fill(payload, seq);
      qlinq_record_t record = {.sequence = seq,
                               .group_id = seq,
                               .data = payload,
                               .size = RECORD,
                               .priority = 1};
      qlinq_send_result_t r = qlinq_stream_send(stream, &record);
      if (r == QLINQ_SEND_WOULD_BLOCK) {
        blocked++;
        /* bound application retries while continuing transport service */
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 100000};
        nanosleep(&pause, NULL);
        break;
      }
      require(r == QLINQ_SEND_SENT || r == QLINQ_SEND_BUFFERED, "qlinq send");
      late_admissions += now_ns() - scheduled(seq) > 1000000;
      sent++;
      seq++;
    }
  }
  FILE *paths_log = fopen("paths.json", "w");
  require(paths_log != NULL, "paths log");
  fprintf(paths_log, "[");
  for (size_t i = 0; i < QLINQ_MAX_PATHS; i++) {
    qlinq_path_stats_t ps = {0};
    qlinq_endpoint_get_path_stats(ep, i, &ps);
    fprintf(paths_log,
            "%s{\"slot\":%zu,\"active\":%s,\"sent_bytes\":%lu,\"received_"
            "bytes\":%lu,\"lost_packets\":%lu,\"rtt_ms\":%u}",
            i ? "," : "", i, ps.active ? "true" : "false",
            (unsigned long)ps.bytes_sent, (unsigned long)ps.bytes_received,
            (unsigned long)ps.packets_lost, ps.rtt_ms);
  }
  fprintf(paths_log, "]\n");
  fclose(paths_log);
  qlinq_context_destroy(ctx);
}
static void run_tls(const char *cert, const char *key) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  require(ctx != NULL, "TLS context");
  require(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1,
          "TLS version");
  require(SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1,
          "TLS version");
  require(SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) == 1,
          "TLS certificate");
  require(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) == 1,
          "TLS key");
  require(SSL_CTX_load_verify_locations(ctx, cert, NULL) == 1, "TLS trust");
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     NULL);
  int fd =
      socket(AF_INET, SOCK_STREAM, !strcmp(mode, "mptcp") ? 262 : IPPROTO_TCP);
  require(fd >= 0, "socket");
  int listener = -1, one = 1, buffer = 2 * 1024 * 1024;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  /* linux doubles SO_SNDBUF/SO_RCVBUF, giving a 4 MiB socket memory budget */
  require(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffer, sizeof buffer) == 0,
          "send buffer");
  require(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buffer, sizeof buffer) == 0,
          "receive buffer");
  struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(PORT)};
  inet_pton(AF_INET, "10.232.1.2", &addr.sin_addr);
  if (sender)
    require(connect(fd, (void *)&addr, sizeof addr) == 0, "connect");
  else {
    require(bind(fd, (void *)&addr, sizeof addr) == 0, "bind");
    require(listen(fd, 1) == 0, "listen");
    int acceptfd = accept(fd, NULL, NULL);
    require(acceptfd >= 0, "accept");
    listener = fd;
    fd = acceptfd;
  }
  require(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) == 0,
          "nodelay");
  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl, fd);
  if (sender)
    require(X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), "10.232.1.2") ==
                1,
            "verify IP");
  require((sender ? SSL_connect(ssl) : SSL_accept(ssl)) == 1, "TLS handshake");
  fprintf(stderr, "TLS %s %s; peer verified\n", SSL_get_version(ssl),
          SSL_get_cipher_name(ssl));
  require(now_ns() < start, "TLS not ready at scheduled start");
  require(fcntl(fd, F_SETFL, O_NONBLOCK) == 0, "nonblocking");
  unsigned char payload[RECORD];
  uint64_t seq = 0;
  size_t offset = 0;
  int loaded = 0;
  while (now_ns() < finish + DRAIN_NS) {
    observe_cpu();
    if (sender) {
      if (seq >= count || (now_ns() >= finish && !loaded)) {
        if (seq < count) {
          rejected += count - seq;
          seq = count;
        }
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 5000000};
        nanosleep(&pause, NULL);
        continue;
      }
      if (!loaded && now_ns() < scheduled(seq)) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 100000};
        nanosleep(&ts, NULL);
        continue;
      }
      if (!loaded) {
        fill(payload, seq);
        loaded = 1;
      }
      int r = SSL_write(ssl, payload, RECORD);
      if (r == RECORD) {
        late_admissions += now_ns() - scheduled(seq) > 1000000;
        sent++;
        seq++;
        loaded = 0;
        continue;
      }
      int err = SSL_get_error(ssl, r);
      require(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE,
              "TLS write");
      blocked++;
      struct pollfd f = {
          .fd = fd, .events = err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT};
      poll(&f, 1, 1);
    } else {
      int r = SSL_read(ssl, payload + offset, RECORD - offset);
      if (r > 0) {
        offset += r;
        if (offset == RECORD) {
          receive_record(payload, RECORD);
          offset = 0;
        }
        continue;
      }
      int err = SSL_get_error(ssl, r);
      if (err == SSL_ERROR_ZERO_RETURN || (r == 0 && now_ns() > finish))
        break;
      require(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE,
              "TLS read");
      struct pollfd f = {
          .fd = fd, .events = err == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN};
      poll(&f, 1, 1);
    }
  }
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  close(fd);
  if (listener >= 0)
    close(listener);
}
int main(int argc, char **argv) {
  if (argc == 2 && !strcmp(argv[1], "--start")) {
    printf("%llu\n", (unsigned long long)(now_ns() + 5000000000ULL));
    return 0;
  }
  if (argc != 10) {
    fprintf(stderr, "mode sender|receiver cert key paths start_ns seconds mbps "
                    "samples.csv\n");
    return 2;
  }
  mode = argv[1];
  if (strcmp(mode, "mptcp") && strcmp(mode, "reliable")) {
    fprintf(stderr, "mode must be mptcp or reliable\n");
    return 2;
  }
  if (strcmp(argv[2], "sender") && strcmp(argv[2], "receiver"))
    return 2;
  if (strcmp(argv[5], "2"))
    return 2;
  signal(SIGPIPE, SIG_IGN);
  sender = !strcmp(argv[2], "sender");
  start = strtoull(argv[6], NULL, 10);
  double seconds = atof(argv[7]);
  rate = atof(argv[8]) * 1e6;
  finish = start + (uint64_t)(seconds * 1e9);
  count = (uint64_t)(seconds * rate / (RECORD * 8));
  require(count > 0 && count < 10000000, "record count");
  latencies = calloc(count, sizeof(double));
  seen = calloc(count, 1);
  require(latencies && seen, "allocate metrics");
  samples = fopen(argv[9], "w");
  require(samples != NULL, "sample file");
  fprintf(samples, "sequence,receive_ns,latency_ms\n");
  if (!strcmp(mode, "tcp") || !strcmp(mode, "mptcp"))
    run_tls(argv[3], argv[4]);
  else
    run_qlinq(atoi(argv[5]), argv[3], argv[4]);
  if (sender)
    rejected = count - sent;
  report();
  fclose(samples);
  free(seen);
  free(latencies);
  return corrupt ? 3 : 0;
}
