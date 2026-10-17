/* examples/data_multipath_benchmark.c */

#include "transport.h"
#include "transport_internal.h" /* benchmark-only native ABBA selection */
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BENCHMARK_MAX_PACKETS 1048576
#define BENCHMARK_MAX_FPS 100000
#define PACKET_SIZE 8000 /* 8KB general data payload */
#define BENCHMARK_STREAM_EGRESS_BYTES (32U * 1024U * 1024U)
#define BENCHMARK_TOTAL_STREAM_EGRESS_BYTES (64U * 1024U * 1024U)
#define BENCHMARK_RECOVERY_CACHE_FLOOR (16U * 1024U * 1024U)
#define BENCHMARK_RECOVERY_CACHE_MAX (128U * 1024U * 1024U)

typedef struct {
  double scheduled_time;
  double send_time;
  double recv_time;
  bool arrived;
  bool admitted;
  bool attempted;
} frame_metrics_t;

typedef struct {
  bool connected;
  bool disconnected;
  bool subscribed;
  bool grouped;
  frame_metrics_t packets[BENCHMARK_MAX_PACKETS];
  int frames_received;
  transport_t *transport;
} benchmark_state_t;

typedef struct {
  double all_active_at, sampled_at_ms, start_ms, end_ms;
  double fixed_start_ms, fixed_end_ms;
  transport_path_stats_t start[4], end[4];
  bool started, interrupted;
} path_window_t;

static double get_time_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

/* Compare paths over the same interval, after hot-added paths have had time to
 * validate and settle. Lifetime totals favor the paths that joined first. */
static void sample_path_window(transport_t *transport, size_t expected_paths,
                               double warmup_ms, path_window_t *window) {
  transport_path_stats_t current[4];
  double now = get_time_ms();
  if (window->fixed_end_ms &&
      (now < window->fixed_start_ms || now >= window->fixed_end_ms))
    return;
  if (now - window->sampled_at_ms < 1)
    return;
  window->sampled_at_ms = now;
  for (size_t i = 0; i < expected_paths; i++) {
    if (!transport_get_path_stats(transport, i, &current[i]) ||
        current[i].lifecycle != TRANSPORT_PATH_ACTIVE) {
      window->all_active_at = 0;
      window->interrupted |= window->started;
      return;
    }
  }
  if (window->all_active_at == 0)
    window->all_active_at = now;
  if (!window->fixed_end_ms && now - window->all_active_at < warmup_ms)
    return;
  if (!window->started) {
    memcpy(window->start, current, expected_paths * sizeof(current[0]));
    window->start_ms = now;
    window->started = true;
  }
  memcpy(window->end, current, expected_paths * sizeof(current[0]));
  window->end_ms = now;
}

static int compare_latency(const void *a, const void *b) {
  double left = *(const double *)a, right = *(const double *)b;
  return (left > right) - (left < right);
}

static void report_window_delivery(const path_window_t *window,
                                   const benchmark_state_t *client,
                                   int packets_sent) {
  double start =
      window->fixed_end_ms ? window->fixed_start_ms : window->start_ms;
  double end = window->fixed_end_ms ? window->fixed_end_ms : window->end_ms;
  if ((!window->fixed_end_ms && !window->started) || end <= start)
    return;
  static double latencies[BENCHMARK_MAX_PACKETS];
  double total_latency = 0;
  size_t sent = 0, admitted = 0, received = 0, completed_in_window = 0;
  size_t attempted = 0, attempted_in_window = 0;
  for (int i = 0; i < packets_sent; i++) {
    const frame_metrics_t *packet = &client->packets[i];
    double offered_at =
        window->fixed_end_ms ? packet->scheduled_time : packet->send_time;
    if (packet->arrived && packet->recv_time >= start &&
        packet->recv_time < end)
      completed_in_window++;
    if (offered_at < start || offered_at >= end)
      continue;
    sent++;
    attempted += packet->attempted;
    attempted_in_window += packet->attempted && packet->send_time >= start &&
                           packet->send_time < end;
    admitted += packet->admitted;
    if (packet->arrived) {
      /* fixed-time source measures latency from scheduled publication */
      latencies[received] = packet->recv_time - offered_at;
      total_latency += latencies[received++];
    }
  }
  qsort(latencies, received, sizeof(latencies[0]), compare_latency);
  printf("window_offered: %zu\nwindow_admitted: %zu\nwindow_received: %zu\n",
         sent, admitted, received);
  printf("window_goodput_mbps: %.3f\n", completed_in_window *
                                            (double)PACKET_SIZE * 8 /
                                            ((end - start) * 1000));
  printf("window_duration_ms: %.3f\n", end - start);
  printf("window_completed_in_interval: %zu\n", completed_in_window);
  printf("window_mean_latency_ms: %.3f\n",
         received ? total_latency / received : 0);
  printf("window_p95_latency_ms: %.3f\n",
         received ? latencies[(received * 95 + 99) / 100 - 1] : 0);
  printf("window_p99_latency_ms: %.3f\n",
         received ? latencies[(received * 99 + 99) / 100 - 1] : 0);
  if (window->fixed_end_ms) {
    size_t count = 0;
    for (int i = 0; i < packets_sent; i++) {
      const frame_metrics_t *packet = &client->packets[i];
      if (packet->scheduled_time >= start && packet->scheduled_time < end &&
          packet->attempted)
        latencies[count++] =
            fmax(0, packet->send_time - packet->scheduled_time);
    }
    qsort(latencies, count, sizeof(latencies[0]), compare_latency);
    printf("window_attempted: %zu\nwindow_attempted_in_interval: %zu\n"
           "window_unattempted: %zu\nwindow_source_deadline_misses: %zu\n",
           attempted, attempted_in_window, sent - attempted,
           sent - attempted_in_window);
    printf("window_source_p99_lateness_ms: %.3f\n"
           "window_source_max_lateness_ms: %.3f\n",
           count ? latencies[(count * 99 + 99) / 100 - 1] : 0,
           count ? latencies[count - 1] : 0);
    printf("window_source_mbps: %.3f\n", attempted_in_window *
                                             (double)PACKET_SIZE * 8 /
                                             ((end - start) * 1000));
  }
}

/* invert cumulative linear-ramp schedule for scheduled record f */
static double scheduled_offset_ms(int f, double fps, double warmup_fps,
                                  double warmup_ms) {
  if (warmup_fps > 0 && warmup_ms > 0) {
    double seconds = warmup_ms / 1000;
    double ramp_packets = (warmup_fps + fps) * seconds / 2;
    if (f < ramp_packets) {
      double slope = (fps - warmup_fps) / seconds;
      return 2000.0 * f /
             (warmup_fps + sqrt(warmup_fps * warmup_fps + 2 * slope * f));
    }
    return warmup_ms + (f - ramp_packets) * 1000.0 / fps;
  }
  return f * 1000.0 / fps;
}

static double numeric_argument(const char *text, double minimum,
                               double maximum) {
  char *end;
  errno = 0;
  double value = strtod(text, &end);
  if (errno || end == text || *end || !isfinite(value) || value < minimum ||
      value > maximum) {
    fprintf(stderr, "invalid numeric argument: %s\n", text);
    exit(2);
  }
  return value;
}

static int named_argument(const char *value, const char *const *names,
                          size_t count) {
  for (size_t i = 0; i < count; i++)
    if (strcmp(value, names[i]) == 0)
      return (int)i;
  fprintf(stderr, "invalid selection: %s\n", value);
  exit(2);
}

static bool select_cipher(transport_t *transport, int cipher,
                          ptls_cipher_suite_t **selected, size_t capacity) {
  if (!cipher)
    return true;
  uint16_t id = cipher == 1 ? PTLS_CIPHER_SUITE_AES_128_GCM_SHA256
                            : PTLS_CIPHER_SUITE_AES_256_GCM_SHA384;
  ptls_cipher_suite_t **available = transport->tls_ctx.cipher_suites;
  for (ptls_cipher_suite_t **suite = available; *suite != NULL; suite++) {
    if ((*suite)->id == id) {
      selected[0] = *suite;
      size_t count = 1;
      for (ptls_cipher_suite_t **other = available; *other != NULL; other++) {
        if (*other == *suite)
          continue;
        if (count + 1 >= capacity) {
          fprintf(stderr, "benchmark cipher preference array is too small\n");
          return false;
        }
        selected[count++] = *other;
      }
      selected[count] = NULL;
      /* set server cipher preference while retaining suites for initial packets
       */
      transport->tls_ctx.cipher_suites = selected;
      transport->tls_ctx.server_cipher_preference = 1;
      return true;
    }
  }
  fprintf(stderr, "requested cipher is unavailable in selected backend\n");
  return false;
}

static size_t benchmark_recovery_cache_bytes(double fps) {
  /* Retain two seconds of offered payload so a delayed checkpoint ACK cannot
   * turn a high-rate run into application backpressure. The fixed maximum is
   * the benchmark's explicit memory cap. */
  double requested = fps * PACKET_SIZE * 2.0;
  if (requested < BENCHMARK_RECOVERY_CACHE_FLOOR)
    return BENCHMARK_RECOVERY_CACHE_FLOOR;
  if (requested >= BENCHMARK_RECOVERY_CACHE_MAX)
    return BENCHMARK_RECOVERY_CACHE_MAX;
  return (size_t)requested;
}

static bool report_path_window(const path_window_t *window, size_t paths,
                               const char *preferred_interface) {
  double seconds = (window->end_ms - window->start_ms) / 1000.0;
  if (!window->started || window->interrupted || seconds < 1) {
    printf("\nall-path comparison: unavailable "
           "(needs >=1 s after all paths settle)\n");
    return preferred_interface == NULL;
  }
  uint64_t total_bytes = 0, preferred_bytes = 0;
  bool found_preferred = false;
  for (size_t i = 0; i < paths; i++)
    total_bytes += window->end[i].bytes_sent - window->start[i].bytes_sent;
  printf("\n--- SERVER TRAFFIC WITH ALL %zu PATHS ACTIVE (%.3f s) ---\n", paths,
         seconds);
  printf("Counts include protocol traffic; rates are observed UDP payload "
         "rates, not link capacity.\n");
  for (size_t i = 0; i < paths; i++) {
    const transport_path_stats_t *end = &window->end[i];
    uint64_t bytes = end->bytes_sent - window->start[i].bytes_sent;
    printf("path %zu: interface=%s address=%s sent=%lu bytes=%lu "
           "rate=%.0f B/s share=%.1f%% quic_rtt=%u ms\n",
           i, end->interface_name, end->local_address,
           (unsigned long)(end->sent - window->start[i].sent),
           (unsigned long)bytes, bytes / seconds,
           total_bytes ? 100.0 * bytes / total_bytes : 0.0, end->rtt);
    if (preferred_interface &&
        strcmp(end->interface_name, preferred_interface) == 0) {
      preferred_bytes = bytes;
      found_preferred = true;
    }
  }
  if (!preferred_interface)
    return true;
  bool passed =
      found_preferred && total_bytes > 0 && preferred_bytes > total_bytes / 2;
  printf("preferred-link check (%s carries >50%% of server bytes): %s\n",
         preferred_interface, passed ? "PASS" : "FAIL");
  return passed;
}

static void report_transport_pressure(const char *role,
                                      transport_t *transport) {
  transport_stats_t stats;
  if (!transport_get_stats(transport, &stats))
    return;
  printf("--- %s TRANSPORT PRESSURE ---\n", role);
  printf("publish: delivered=%" PRIu64 " buffered=%" PRIu64 " partial=%" PRIu64
         " backpressure=%" PRIu64 " errors=%" PRIu64 "\n",
         stats.publish_delivered, stats.publish_buffered, stats.publish_partial,
         stats.publish_backpressure, stats.publish_errors);
  printf("egress: peak_packets=%zu peak_bytes=%zu dropped=%" PRIu64
         " would_block=%" PRIu64 "\n",
         stats.egress_peak_packets, stats.egress_peak_bytes,
         stats.egress_packets_dropped, stats.udp_would_block);
  printf("streams: blocked=%" PRIu64 " peak_frames=%zu peak_bytes=%zu"
         " peak_vectors=%zu\n",
         stats.stream_egress_blocked, stats.stream_egress_peak_frames,
         stats.stream_egress_peak_bytes, stats.stream_egress_peak_vectors);
  printf("recovery: cache_backpressure=%" PRIu64 " peak_bytes=%zu"
         " peak_entries=%zu checkpoints_sent=%" PRIu64
         " checkpoints_received=%" PRIu64 " checkpoint_acks_sent=%" PRIu64
         " checkpoint_acks_received=%" PRIu64 " cache_releases=%" PRIu64
         " checkpoints_pending=%zu\n",
         stats.recovery_cache_backpressure,
         stats.recovery_cache_peak_payload_bytes,
         stats.recovery_cache_peak_entries, stats.recovery_checkpoints_sent,
         stats.recovery_checkpoints_received,
         stats.recovery_checkpoint_acks_sent,
         stats.recovery_checkpoint_acks_received, stats.recovery_cache_releases,
         stats.recovery_checkpoints_pending);
}

static void on_server_event(void *user_data, const transport_event_t *event) {
  benchmark_state_t *state = user_data;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    state->connected = true;
    break;
  case TRANSPORT_EVENT_SUBSCRIBE:
    if (strcmp(event->track_id.name, "data_benchmark") == 0) {
      state->subscribed = true;
    }
    break;
  case TRANSPORT_EVENT_AUTH:
    transport_respond_auth(state->transport, event->conn, true);
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    fprintf(stderr,
            "disconnected: code=%" PRIu64 " raw=%" PRId64
            " remote=%d application=%d reason=%s\n",
            event->disconnect.error_code, event->disconnect.raw_error,
            event->disconnect.remote, event->disconnect.application_error,
            event->disconnect.reason ? event->disconnect.reason : "none");
    state->connected = false;
    state->disconnected = true;
    break;
  default:
    break;
  }
}

static void on_client_event(void *user_data, const transport_event_t *event) {
  benchmark_state_t *state = user_data;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    transport_send_auth(state->transport, event->conn,
                        (const uint8_t *)"secret_token_123",
                        strlen("secret_token_123"));
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    if (event->auth.success) {
      state->connected = true;
    }
    break;
  case TRANSPORT_EVENT_OBJECT:
    if (strcmp(event->track_id.name, "data_benchmark") == 0) {
      if (!state->grouped) {
        uint64_t fid;
        if (event->object.size == PACKET_SIZE) {
          memcpy(&fid, event->object.data, sizeof(fid));
          if (fid < BENCHMARK_MAX_PACKETS && !state->packets[fid].arrived) {
            state->packets[fid].recv_time = get_time_ms();
            state->packets[fid].arrived = true;
            state->frames_received++;
          }
        }
        break;
      }
      size_t remaining = event->object.size;
      const uint8_t *ptr = event->object.data;
      while (remaining >= 2) {
        uint16_t pkt_len;
        memcpy(&pkt_len, ptr, 2);
        pkt_len = ntohs(pkt_len);
        if (remaining < 2 + (size_t)pkt_len) {
          break;
        }
        if (pkt_len == PACKET_SIZE) {
          uint64_t fid;
          memcpy(&fid, ptr + 2, sizeof(uint64_t));
          if (fid < BENCHMARK_MAX_PACKETS && !state->packets[fid].arrived) {
            state->packets[fid].recv_time = get_time_ms();
            state->packets[fid].arrived = true;
            state->frames_received++;
          }
        }
        ptr += 2 + pkt_len;
        remaining -= 2 + pkt_len;
      }
    }
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    fprintf(stderr,
            "disconnected: code=%" PRIu64 " raw=%" PRId64
            " remote=%d application=%d reason=%s\n",
            event->disconnect.error_code, event->disconnect.raw_error,
            event->disconnect.remote, event->disconnect.application_error,
            event->disconnect.reason ? event->disconnect.reason : "none");
    state->connected = false;
    state->disconnected = true;
    break;
  default:
    break;
  }
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  bool use_reliable = false;
  bool use_rateless = false;
  bool use_datagram = false;
  const char *server_bind_hosts[4] = {"0.0.0.0"};
  int num_server_bind = 1;
  const char *client_bind_hosts[4] = {"0.0.0.0"};
  int num_client_bind = 1;
  const char *server_path_interfaces[4] = {0};
  int num_server_path_interfaces = 0;
  const char *client_path_interfaces[4] = {0};
  int num_client_path_interfaces = 0;
  const char *client_remote_hosts[4] = {"127.0.0.1"};
  int num_client_remote = 1;
  const char *qlog_socket = NULL;
  const char *preferred_interface = NULL;
  int packet_count = 600;
  double fps = 60, warmup_ms = 500, drain_ms = 1500;
  double warmup_fps = 0, duration_ms = 0;
  bool wait_all_paths = false;
  bool continue_backpressure = false;
  bool packet_count_explicit = false;
  size_t udp_payload_size = 1280;
  size_t source_batch = 4;
  const char *const cc_names[] = {"default", "reno", "pico", "cubic"};
  const char *const toggle_names[] = {"default", "off", "on"};
  const char *const cipher_names[] = {"default", "aes128gcm", "aes256gcm"};
  int congestion_control = 0, pacing = 0, abba = 0, cipher = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--reliable") == 0) {
      use_reliable = true;
    } else if (strcmp(argv[i], "--rateless") == 0) {
      use_rateless = true;
    } else if (strcmp(argv[i], "--datagram") == 0) {
      use_datagram = true;
    } else if (strcmp(argv[i], "--server-bind") == 0 && i + 1 < argc) {
      server_bind_hosts[0] = argv[++i];
      num_server_bind = 1;
      while (i + 1 < argc && argv[i + 1][0] != '-') {
        server_bind_hosts[num_server_bind++] = argv[++i];
      }
    } else if (strcmp(argv[i], "--client-bind") == 0 && i + 1 < argc) {
      client_bind_hosts[0] = argv[++i];
      num_client_bind = 1;
      while (i + 1 < argc && argv[i + 1][0] != '-') {
        client_bind_hosts[num_client_bind++] = argv[++i];
      }
    } else if (strcmp(argv[i], "--server-interface") == 0 && i + 1 < argc) {
      num_server_path_interfaces = 0;
      while (i + 1 < argc && argv[i + 1][0] != '-' &&
             num_server_path_interfaces < 4)
        server_path_interfaces[num_server_path_interfaces++] = argv[++i];
    } else if (strcmp(argv[i], "--client-interface") == 0 && i + 1 < argc) {
      num_client_path_interfaces = 0;
      while (i + 1 < argc && argv[i + 1][0] != '-' &&
             num_client_path_interfaces < 4)
        client_path_interfaces[num_client_path_interfaces++] = argv[++i];
    } else if (strcmp(argv[i], "--client-remote") == 0 && i + 1 < argc) {
      client_remote_hosts[0] = argv[++i];
      num_client_remote = 1;
      while (i + 1 < argc && argv[i + 1][0] != '-') {
        client_remote_hosts[num_client_remote++] = argv[++i];
      }
    } else if (strcmp(argv[i], "--qlog-unix-socket") == 0 && i + 1 < argc) {
      qlog_socket = argv[++i];
    } else if (strcmp(argv[i], "--expect-preferred-interface") == 0 &&
               i + 1 < argc) {
      preferred_interface = argv[++i];
    } else if (strcmp(argv[i], "--packets") == 0 && i + 1 < argc) {
      double value = numeric_argument(argv[++i], 1, BENCHMARK_MAX_PACKETS);
      if (value != floor(value))
        return 2;
      packet_count = (int)value;
      packet_count_explicit = true;
    } else if (strcmp(argv[i], "--fps") == 0 && i + 1 < argc) {
      fps = numeric_argument(argv[++i], 1, BENCHMARK_MAX_FPS);
    } else if (strcmp(argv[i], "--warmup-ms") == 0 && i + 1 < argc) {
      warmup_ms = numeric_argument(argv[++i], 0, 30000);
    } else if (strcmp(argv[i], "--duration-ms") == 0 && i + 1 < argc) {
      duration_ms = numeric_argument(argv[++i], 1, 60000);
    } else if (strcmp(argv[i], "--source-batch") == 0 && i + 1 < argc) {
      double value = numeric_argument(argv[++i], 1, 64);
      if (value != floor(value))
        return 2;
      source_batch = (size_t)value;
    } else if (strcmp(argv[i], "--congestion-control") == 0 && i + 1 < argc) {
      congestion_control = named_argument(argv[++i], cc_names, 4);
    } else if (strcmp(argv[i], "--pacing") == 0 && i + 1 < argc) {
      pacing = named_argument(argv[++i], toggle_names, 3);
    } else if (strcmp(argv[i], "--abba") == 0 && i + 1 < argc) {
      abba = named_argument(argv[++i], toggle_names, 3);
    } else if (strcmp(argv[i], "--cipher") == 0 && i + 1 < argc) {
      cipher = named_argument(argv[++i], cipher_names, 3);
    } else if (strcmp(argv[i], "--warmup-fps") == 0 && i + 1 < argc) {
      warmup_fps = numeric_argument(argv[++i], 1, BENCHMARK_MAX_FPS);
    } else if (strcmp(argv[i], "--udp-payload-size") == 0 && i + 1 < argc) {
      double value = numeric_argument(argv[++i], 1200, 1500);
      if (value != floor(value))
        return 2;
      udp_payload_size = (size_t)value;
    } else if (strcmp(argv[i], "--drain-ms") == 0 && i + 1 < argc) {
      drain_ms = numeric_argument(argv[++i], 0, 10000);
    } else if (strcmp(argv[i], "--wait-all-paths") == 0) {
      wait_all_paths = true;
    } else if (strcmp(argv[i], "--continue-backpressure") == 0) {
      continue_backpressure = true;
    } else {
      fprintf(stderr, "unknown or incomplete option: %s\n", argv[i]);
      return 2;
    }
  }

  if (duration_ms) {
    if (duration_ms <= warmup_ms) {
      fprintf(stderr, "fixed duration requires duration > warmup\n");
      return 2;
    }
    double ramp_count = warmup_fps > 0 ? (warmup_fps + fps) * warmup_ms / 2000.0
                                       : fps * warmup_ms / 1000.0;
    double count = ceil(ramp_count + fps * (duration_ms - warmup_ms) / 1000.0);
    if (count > BENCHMARK_MAX_PACKETS ||
        (packet_count_explicit && packet_count != (int)count)) {
      fprintf(stderr,
              "duration schedule needs %.0f records (limit %d); "
              "--packets must match when supplied\n",
              count, BENCHMARK_MAX_PACKETS);
      return 2;
    }
    packet_count = (int)count;
  }
  if (abba == 2 && congestion_control != TRANSPORT_CC_CUBIC) {
    fprintf(stderr, "--abba on requires --congestion-control cubic\n");
    return 2;
  }

  if (qlog_socket) {
    if (transport_enable_qlog(qlog_socket) < 0) {
      fprintf(stderr, "failed to connect to qlog unix socket: %s\n",
              qlog_socket);
    } else {
      printf("qlog streaming enabled via unix socket\n");
    }
  }

  if (use_reliable + use_rateless + use_datagram > 1) {
    fprintf(stderr, "delivery modes cannot be combined\n");
    return 2;
  }
  printf("starting data multipath benchmark (%s mode)...\n",
         use_reliable   ? "reliable stream"
         : use_rateless ? "rateless fec"
         : use_datagram ? "datagram"
                        : "fixed fec");
  printf("benchmark_options: cc=%s pacing=%s abba=%s cipher=%s "
         "source_batch=%zu duration_ms=%.3f\n",
         cc_names[congestion_control], toggle_names[pacing], toggle_names[abba],
         cipher_names[cipher], source_batch, duration_ms);
  size_t recovery_cache_bytes = benchmark_recovery_cache_bytes(fps);

  /* The gigabit benchmark retains enough per-object metrics to exceed the
   * process stack when both endpoint states are automatic variables. */
  static benchmark_state_t server_state;
  static benchmark_state_t client_state;
  client_state.grouped = !use_reliable && !use_datagram;

  /* create server transport config */
  transport_config_t server_cfg = {
      .port = 9999,
      .cert_file = "t/assets/server.crt",
      .key_file = "t/assets/server.key",
      .callback = on_server_event,
      .limits = {.max_stream_egress_bytes = BENCHMARK_STREAM_EGRESS_BYTES,
                 .max_total_stream_egress_bytes =
                     BENCHMARK_TOTAL_STREAM_EGRESS_BYTES,
                 .max_udp_payload_size = udp_payload_size,
                 .max_recovery_cache_bytes = recovery_cache_bytes},
      .allow_insecure_peer = true,
      .congestion_control = (unsigned)congestion_control,
      .pacing = (unsigned)pacing,
      .user_data = &server_state};
  server_cfg.num_bind_hosts = num_server_bind;
  for (int i = 0; i < num_server_bind; i++)
    server_cfg.bind_hosts[i] = server_bind_hosts[i];
  server_cfg.num_path_interface_names = num_server_path_interfaces;
  for (int i = 0; i < num_server_path_interfaces; i++)
    server_cfg.path_interface_names[i] = server_path_interfaces[i];

  /* create client transport config */
  transport_config_t client_cfg = {
      .port = 9999,
      .cert_file = NULL,
      .key_file = NULL,
      .callback = on_client_event,
      .limits = {.max_stream_egress_bytes = BENCHMARK_STREAM_EGRESS_BYTES,
                 .max_total_stream_egress_bytes =
                     BENCHMARK_TOTAL_STREAM_EGRESS_BYTES,
                 .max_udp_payload_size = udp_payload_size,
                 .max_recovery_cache_bytes = recovery_cache_bytes},
      .allow_insecure_peer = true,
      .congestion_control = (unsigned)congestion_control,
      .pacing = (unsigned)pacing,
      .user_data = &client_state};
  client_cfg.num_bind_hosts = num_client_bind;
  for (int i = 0; i < num_client_bind; i++)
    client_cfg.bind_hosts[i] = client_bind_hosts[i];
  client_cfg.num_path_interface_names = num_client_path_interfaces;
  for (int i = 0; i < num_client_path_interfaces; i++)
    client_cfg.path_interface_names[i] = client_path_interfaces[i];
  client_cfg.num_remote_hosts = num_client_remote;
  for (int i = 0; i < num_client_remote; i++)
    client_cfg.remote_hosts[i] = client_remote_hosts[i];

  transport_t *server = transport_create(&server_cfg);
  if (!server) {
    fprintf(stderr, "failed to create server transport\n");
    return 1;
  }
  server_state.transport = server;
  ptls_cipher_suite_t *server_suites[8];
  if (!select_cipher(server, cipher, server_suites,
                     sizeof(server_suites) / sizeof(server_suites[0]))) {
    transport_destroy(server);
    return 2;
  }
  if (abba)
    server->quic_ctx.egress[0].cc.abba = abba == 2;

  transport_t *client = transport_create(&client_cfg);
  if (!client) {
    fprintf(stderr, "failed to create client transport\n");
    transport_destroy(server);
    return 1;
  }
  client_state.transport = client;
  /* client handshake already started; server preference selects cipher */
  if (abba)
    client->quic_ctx.egress[0].cc.abba = abba == 2;

  /* wait for connection */
  int retries = 200;
  while (retries-- > 0 &&
         (!server_state.connected || !client_state.connected)) {
    transport_tick(server);
    transport_tick(client);
    usleep(5000);
  }

  if (!server_state.connected || !client_state.connected) {
    fprintf(stderr, "failed to establish connection\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  /* client subscribes to benchmark track */
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = use_reliable   ? MOQ_TRACK_FLAG_RELIABLE
                                   : use_rateless ? MOQ_TRACK_FLAG_FEC_RATELESS
                                   : use_datagram ? 0
                                                  : MOQ_TRACK_FLAG_FEC_ENABLED};
  strcpy(track.name, "data_benchmark");

  if (!transport_subscribe(client, track)) {
    fprintf(stderr, "failed to subscribe to track\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  /* wait for subscription match */
  retries = 200;
  while (retries-- > 0 && !server_state.subscribed) {
    transport_tick(server);
    transport_tick(client);
    usleep(5000);
  }

  if (!server_state.subscribed) {
    fprintf(stderr, "subscription handshake failed\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  size_t expected_paths = num_server_path_interfaces
                              ? (size_t)num_server_path_interfaces
                              : (size_t)num_server_bind;
  if (wait_all_paths) {
    bool ready = false;
    double deadline = get_time_ms() + 5000;
    while (!ready && get_time_ms() < deadline) {
      transport_tick(server);
      transport_tick(client);
      ready = true;
      for (size_t i = 0; i < expected_paths; i++) {
        transport_path_stats_t stats;
        ready &= transport_get_path_stats(server, i, &stats) &&
                 stats.lifecycle == TRANSPORT_PATH_ACTIVE;
      }
      usleep(500);
    }
    if (!ready) {
      fprintf(stderr, "not all configured paths became active\n");
      transport_destroy(client);
      transport_destroy(server);
      return 1;
    }
  }
  printf("handshake established. streaming %d packets at %.3ffps...\n",
         packet_count, fps);
  if (transport_connection_count(server)) {
    transport_conn_t *conn = transport_connection_at(server, 0);
    ptls_cipher_suite_t *negotiated =
        ptls_get_cipher(quicly_get_tls(conn->quic));
    printf("negotiated_cipher: %s\n",
           negotiated ? negotiated->name : "unknown");
    if (cipher && (!negotiated ||
                   negotiated->id !=
                       (cipher == 1 ? PTLS_CIPHER_SUITE_AES_128_GCM_SHA256
                                    : PTLS_CIPHER_SUITE_AES_256_GCM_SHA384))) {
      fprintf(stderr, "negotiated cipher does not match requested control\n");
      transport_destroy(client);
      transport_destroy(server);
      return 2;
    }
  }
  const char *effective_cc =
      server->quic_ctx.egress[0].cc.init_cc == &quicly_cc_cubic_init  ? "cubic"
      : server->quic_ctx.egress[0].cc.init_cc == &quicly_cc_reno_init ? "reno"
      : server->quic_ctx.egress[0].cc.init_cc == &quicly_cc_pico_init ? "pico"
                                                                      : "other";
  printf("effective_controller: cc=%s pacing=%u abba=%u\n", effective_cc,
         server->quic_ctx.egress[0].pacing, server->quic_ctx.egress[0].cc.abba);

  uint8_t *frame_payload = malloc(PACKET_SIZE);
  if (!frame_payload) {
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }
  memset(frame_payload, 0xAA, PACKET_SIZE);

  /* initialize scheduled cohort before starting clock */
  for (int f = 0; f < packet_count; f++)
    client_state.packets[f].scheduled_time =
        scheduled_offset_ms(f, fps, warmup_fps, warmup_ms);
  double start_benchmark = get_time_ms();
  for (int f = 0; f < packet_count; f++)
    client_state.packets[f].scheduled_time += start_benchmark;
  int packets_sent = 0;
  int packets_admitted = 0, backpressured = 0;
  uint64_t retry_attempts = 0;
  bool publish_failed = false;
  path_window_t path_window = {0};
  if (duration_ms) {
    path_window.fixed_start_ms = start_benchmark + warmup_ms;
    path_window.fixed_end_ms = start_benchmark + duration_ms;
    printf("benchmark_start_monotonic_ms: %.6f\n"
           "window_start_monotonic_ms: %.6f\n"
           "window_end_monotonic_ms: %.6f\n",
           start_benchmark, path_window.fixed_start_ms,
           path_window.fixed_end_ms);
    printf("latency_origin: scheduled\n");
  } else {
    printf("latency_origin: submitted\n");
  }

  for (int f = 0; f < packet_count; f++) {
    double publish_target = client_state.packets[f].scheduled_time;
    while (get_time_ms() < publish_target) {
      transport_tick(server);
      transport_tick(client);
      sample_path_window(server, expected_paths, warmup_ms, &path_window);
      usleep(500);
    }

    double submitted_at = get_time_ms();
    if (duration_ms && submitted_at >= path_window.fixed_end_ms)
      break;
    client_state.packets[f].send_time = submitted_at;
    client_state.packets[f].attempted = true;

    uint64_t *payload_fid = (uint64_t *)frame_payload;
    *payload_fid = f;

    moq_object_t obj = {
        .track_id = track,
        .group_id = 0,
        .object_id = f,
        .priority = 2,
        .data = frame_payload,
        .size = PACKET_SIZE,
        .is_keyframe = (f % 30 == 0) /* keyframe every 30 packets */
    };

    transport_publish_result_t result = transport_publish_ex(server, &obj);
    if (result == TRANSPORT_PUBLISH_BACKPRESSURE)
      backpressured++;
    /* retry backpressure until deadline unless discarding */
    double retry_until = client_state.packets[f].send_time + drain_ms;
    if (duration_ms)
      retry_until = fmin(retry_until, path_window.fixed_end_ms);
    while (result == TRANSPORT_PUBLISH_BACKPRESSURE && !continue_backpressure &&
           get_time_ms() < retry_until && !server_state.disconnected &&
           !client_state.disconnected) {
      transport_tick(server);
      transport_tick(client);
      sample_path_window(server, expected_paths, warmup_ms, &path_window);
      usleep(500);
      retry_attempts++;
      result = transport_publish_ex(server, &obj);
    }
    if (result == TRANSPORT_PUBLISH_BACKPRESSURE &&
        (continue_backpressure ||
         (duration_ms && get_time_ms() >= path_window.fixed_end_ms))) {
      /* counted as offered but unadmitted below */
    } else if (result != TRANSPORT_PUBLISH_DELIVERED &&
               result != TRANSPORT_PUBLISH_BUFFERED) {
      fprintf(stderr, "publish failed at packet %d (result=%d)\n", f, result);
      publish_failed = true;
      break;
    } else {
      client_state.packets[f].admitted = true;
      packets_admitted++;
    }
    packets_sent++;

    /* source batching is independent of native packet batch */
    if ((f + 1) % source_batch == 0 || f + 1 == packet_count) {
      transport_tick(server);
      transport_tick(client);
      sample_path_window(server, expected_paths, warmup_ms, &path_window);
    }
    if (server_state.disconnected || client_state.disconnected)
      break;
  }

  printf("source_finished_monotonic_ms: %.6f\n", get_time_ms());
  /* service endpoints until fixed measurement window ends */
  while (duration_ms && get_time_ms() < path_window.fixed_end_ms) {
    transport_tick(server);
    transport_tick(client);
    sample_path_window(server, expected_paths, warmup_ms, &path_window);
  }

  /* drain/wait for final packets to arrive */
  double drain_start = duration_ms ? path_window.fixed_end_ms : get_time_ms();
  while (get_time_ms() < drain_start + drain_ms) {
    transport_tick(server);
    transport_tick(client);
    usleep(5000);
  }

  /* calculate metrics */
  double total_latency = 0;
  double max_latency = 0;
  int samples = 0;
  int freezes = 0;
  double last_recv_time = 0;

  for (int f = 0; f < packets_sent; f++) {
    if (client_state.packets[f].arrived) {
      double lat = client_state.packets[f].recv_time -
                   (duration_ms ? client_state.packets[f].scheduled_time
                                : client_state.packets[f].send_time);
      total_latency += lat;
      if (lat > max_latency) {
        max_latency = lat;
      }
      samples++;

      if (last_recv_time > 0) {
        double gap = client_state.packets[f].recv_time - last_recv_time;
        if (gap > 33.3) { /* missed more than one packet render interval */
          freezes++;
        }
      }
      last_recv_time = client_state.packets[f].recv_time;
    }
  }

  double mean_latency = samples > 0 ? total_latency / samples : 0;

  /* calculate jitter */
  double sum_sq_diff = 0;
  for (int f = 0; f < packets_sent; f++) {
    if (client_state.packets[f].arrived) {
      double lat = client_state.packets[f].recv_time -
                   (duration_ms ? client_state.packets[f].scheduled_time
                                : client_state.packets[f].send_time);
      sum_sq_diff += pow(lat - mean_latency, 2);
    }
  }
  double jitter = samples > 1 ? sqrt(sum_sq_diff / (samples - 1)) : 0;

  printf("--- RESULTS ---\n");
  printf("mode: %s\n", use_reliable   ? "reliable"
                       : use_rateless ? "rateless"
                       : use_datagram ? "datagram"
                                      : "fixed-fec");
  printf("offered: %d\nsent: %d\nbackpressured: %d\n", packets_sent,
         packets_admitted, backpressured);
  if (duration_ms)
    printf("scheduled: %d\nunattempted: %d\n", packet_count,
           packet_count - packets_sent);
  printf("retry_attempts: %" PRIu64 "\n", retry_attempts);
  printf("received: %d\n", samples);
  printf("loss_pct: %.1f%%\n",
         packets_sent > 0
             ? ((double)(packets_sent - samples) / packets_sent) * 100.0
             : 0.0);
  printf("mean_latency: %.3f ms\n", mean_latency);
  printf("max_latency: %.3f ms\n", max_latency);
  printf("jitter: %.3f ms\n", jitter);
  printf("freezes: %d\n", freezes);
  printf("===============\n");
  report_transport_pressure("SERVER", server);
  report_transport_pressure("CLIENT", client);

  bool path_check_passed =
      report_path_window(&path_window, expected_paths, preferred_interface);
  report_window_delivery(&path_window, &client_state,
                         duration_ms ? packet_count : packets_sent);

  /* print multipath path statistics for client and server */
  printf("\nLifetime totals include different path join times.\n");
  printf("QUIC RTT includes the ACK return path, which can use a different "
         "link.\n");
  printf("\n--- MULTIPATH PATH STATISTICS (CLIENT) ---\n");
  for (size_t i = 0; i < 4; i++) {
    transport_path_stats_t pstats;
    if (transport_get_path_stats(client, i, &pstats)) {
      printf("path %zu: interface=%s address=%s sent=%lu lost=%lu "
             "quic_rtt=%u ms relative_owd=%.3f ms "
             "ewma_latency=%.3f ms\n",
             i, pstats.interface_name, pstats.local_address,
             (unsigned long)pstats.sent, (unsigned long)pstats.lost, pstats.rtt,
             pstats.relative_owd, pstats.ewma_latency);
    }
  }
  printf("\n--- MULTIPATH PATH STATISTICS (SERVER) ---\n");
  for (size_t i = 0; i < 4; i++) {
    transport_path_stats_t pstats;
    if (transport_get_path_stats(server, i, &pstats)) {
      printf("path %zu: interface=%s address=%s sent=%lu lost=%lu "
             "quic_rtt=%u ms relative_owd=%.3f ms "
             "ewma_latency=%.3f ms\n",
             i, pstats.interface_name, pstats.local_address,
             (unsigned long)pstats.sent, (unsigned long)pstats.lost, pstats.rtt,
             pstats.relative_owd, pstats.ewma_latency);
    }
  }
  printf("==========================================\n");

  free(frame_payload);
  bool failed = !path_check_passed || publish_failed ||
                server_state.disconnected || client_state.disconnected ||
                (!duration_ms && packets_sent != packet_count);
  transport_destroy(client);
  transport_destroy(server);
  return failed ? 1 : 0;
}
