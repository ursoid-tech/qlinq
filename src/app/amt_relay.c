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
static void print_stats(qlinq_relay_t *relay, bool disable_classic,
                        bool has_amtq) {
  qlinq_relay_stats_t s;
  qlinq_relay_get_stats(relay, &s);
  const char *mode = disable_classic ? "amtq-relay" : "amt-relay";
  if (!has_amtq) {
    fprintf(stderr,
            "{\"network_mode\":\"%s\",\"clients\":%zu,\"groups\":%zu,"
            "\"sources\":%zu,\"sent\":%" PRIu64 ",\"input_drops\":%" PRIu64
            ",\"send_errors\":%" PRIu64 ",\"mtu_drops\":%" PRIu64
            ",\"upstream_errors\":%" PRIu64 "}\n",
            mode, s.clients, s.groups, s.sources, s.packets_sent, s.input_drops,
            s.send_errors, s.mtu_drops, s.upstream_errors);
    return;
  }
  fprintf(stderr,
          "{\"network_mode\":\"%s\",\"clients\":%zu,\"amtq_clients\":%zu,"
          "\"groups\":%zu,\"sources\":%zu,\"sent\":%" PRIu64
          ",\"amtq_sent\":%" PRIu64 ",\"amtq_datagrams\":%" PRIu64
          ",\"amtq_reliable_blocks\":%" PRIu64 ",\"input_drops\":%" PRIu64
          ",\"amtq_input_drops\":%" PRIu64 ",\"send_errors\":%" PRIu64
          ",\"amtq_send_errors\":%" PRIu64 ",\"mtu_drops\":%" PRIu64
          ",\"upstream_errors\":%" PRIu64 "}\n",
          mode, s.clients, s.amtq_clients, s.groups, s.sources, s.packets_sent,
          s.amtq_packets_sent, s.amtq_datagrams, s.amtq_reliable_blocks,
          s.input_drops, s.amtq_input_drops, s.send_errors, s.amtq_send_errors,
          s.mtu_drops, s.upstream_errors);
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
  const char *bind_ip = config->bind_address ? config->bind_address : "0.0.0.0";
  bool has_amtq = config->disable_classic_amt || config->amtq_port != 0;
  uint16_t amtq_port = config->amtq_port ? config->amtq_port : 2269;
  if (config->disable_classic_amt) {
    fprintf(stderr, "qlinq-app: AMTQ relay on %s:%u, upstream %s\n", bind_ip,
            amtq_port, config->upstream_interface);
  } else if (has_amtq) {
    fprintf(stderr,
            "qlinq-app: dual AMT/AMTQ relay on %s:%u (AMTQ %u), upstream %s\n",
            bind_ip, config->port ? config->port : 2268, amtq_port,
            config->upstream_interface);
  } else {
    fprintf(stderr, "qlinq-app: transparent AMT relay on %s:%u, upstream %s\n",
            bind_ip, config->port ? config->port : 2268,
            config->upstream_interface);
  }
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
      print_stats(relay, config->disable_classic_amt, has_amtq);
      next_stats = now + stats_ms;
    }
  }
  print_stats(relay, config->disable_classic_amt, has_amtq);
  qlinq_relay_close(relay);
  (void)sigaction(SIGINT, &previous_int, NULL);
  (void)sigaction(SIGTERM, &previous_term, NULL);
  return failed;
}
