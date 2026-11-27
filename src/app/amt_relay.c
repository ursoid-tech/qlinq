#include "amt_relay.h"
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
static volatile sig_atomic_t stopping;
static void stop(int sig) {
  (void)sig;
  stopping = 1;
}
static int64_t clock_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts))
    return -1;
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static void print_stats(qlinq_relay_t *relay) {
  qlinq_relay_stats_t s;
  qlinq_relay_get_stats(relay, &s);
  fprintf(stderr,
          "{\"network_mode\":\"amt-relay\",\"clients\":%zu,\"groups\":%zu,"
          "\"sources\":%zu,\"sent\":%" PRIu64 ",\"input_drops\":%" PRIu64
          ",\"send_errors\":%" PRIu64 ",\"mtu_drops\":%" PRIu64
          ",\"upstream_errors\":%" PRIu64 "}\n",
          s.clients, s.groups, s.sources, s.packets_sent, s.input_drops,
          s.send_errors, s.mtu_drops, s.upstream_errors);
}
int app_amt_relay_run(const qlinq_relay_config_t *config, unsigned stats_ms) {
  qlinq_relay_t *relay = qlinq_relay_open(config);
  if (!relay) {
    fprintf(stderr, "qlinq-app: cannot open AMT relay: %s\n", strerror(errno));
    return 1;
  }
  stopping = 0;
  struct sigaction action = {0}, previous_int, previous_term;
  action.sa_handler = stop;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGINT, &action, &previous_int)) {
    qlinq_relay_close(relay);
    return 1;
  }
  if (sigaction(SIGTERM, &action, &previous_term)) {
    (void)sigaction(SIGINT, &previous_int, NULL);
    qlinq_relay_close(relay);
    return 1;
  }
  fprintf(stderr, "qlinq-app: transparent AMT relay on %s:%u, upstream %s\n",
          config->bind_address ? config->bind_address : "0.0.0.0",
          config->port ? config->port : 2268, config->upstream_interface);
  int failed = 0;
  int64_t start = clock_ms();
  if (start < 0)
    failed = 1;
  int64_t next_stats = start + stats_ms;
  while (!stopping && !failed) {
    if (qlinq_relay_service(relay,
                            stats_ms && stats_ms < 100 ? (int)stats_ms : 100)) {
      fprintf(stderr, "qlinq-app: AMT relay service failed: %s\n",
              strerror(errno));
      failed = 1;
      break;
    }
    int64_t now = clock_ms();
    if (now < 0) {
      failed = 1;
      break;
    }
    if (stats_ms && now >= next_stats) {
      print_stats(relay);
      next_stats = now + stats_ms;
    }
  }
  print_stats(relay);
  qlinq_relay_close(relay);
  (void)sigaction(SIGINT, &previous_int, NULL);
  (void)sigaction(SIGTERM, &previous_term, NULL);
  return failed;
}
