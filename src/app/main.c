/* qlinq-app: direct transport API file and stream bridge. */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "cli_parse.h"
#include "portable_sockets.h"
#include "transport.h"
#include "transport_wire.h"
#include "quicly/constants.h"
#include "xfer.h"

#include <errno.h>
#include <inttypes.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define APP_REORDER_OBJECTS 65536U
#define APP_REORDER_MAX_BYTES (64U * 1024U * 1024U)
#define APP_PV_INTERVAL_MS 1000U

typedef struct {
  uint8_t *data;
  size_t size;
  uint64_t object_id;
  bool active;
} reorder_entry_t;

typedef struct {
  uint32_t interface_index;
  char local_address[64];
  uint64_t bytes_sent;
  uint64_t bytes_received;
  bool initialized;
} pv_path_t;

typedef struct {
  moq_track_id_t track;
  const uint8_t *auth_token;
  size_t auth_token_len;
  const char *node_id;
  uint64_t count_limit;
  uint64_t receive_limit;
  size_t required_subscriptions;
  uint32_t interval_ms;
  uint32_t drain_ms;
  uint32_t stats_ms;
  uint32_t pv_ms;
  bool is_server;
  bool one_shot;
  bool transfer;
  bool streaming_source_hash;
  uint32_t transfer_timeout_ms;
  bool pv;
  bool verbose;
  bool help;
  const char *bind_host;
  const char *bind_hosts[TRANSPORT_MAX_PATHS];
  size_t num_bind_hosts;
  const char *peer_arg;
  const char *peer_args[TRANSPORT_MAX_PATHS];
  size_t num_peer_args;
  size_t stripes;
  bool multihome;
  unsigned congestion_control;
  uint32_t initial_cwnd_packets;
  size_t max_udp_payload_size;
  uint32_t jumpstart_packets;
  bool jumpstart_set;
  const char *cert_file;
  const char *key_file;
  const char *ca_file;
  qlinq_tls_group_policy_t tls_group_policy;
  const char *input_path;
  const char *output_path;
  const char *stats_path;
  uint16_t listen_port;
  uint64_t idle_timeout_ms;
  uint8_t simulated_loss;
  size_t message_size;
  size_t max_connections;
  size_t max_repair_requests;
  size_t max_aggregate_repairs;
  transport_repair_mode_t repair_mode;
  size_t send_batch;
  double mbps;
  bool verify_peer;
  bool allow_insecure;
} options_t;

typedef struct {
  const options_t *options;
  transport_t *transport;
  app_xfer_t *xfer;
  transport_conn_t *xfer_conn;
  int64_t transfer_progress_at;
  int64_t transfer_notify_at;
  int64_t transfer_failure_at;
  int64_t transfer_done_at;
  uint64_t transfer_disk_bytes;
  bool transfer_batch_ready;
  bool transfer_flush_pending;
  FILE *input;
  FILE *output;
  FILE *stats_output;
  uint8_t *message;
  size_t pending_size;
  uint64_t sent_records;
  uint64_t received_records;
  uint64_t received_bytes;
  size_t subscriptions;
  int64_t next_send_at;
  int64_t next_stats_at;
  int64_t finished_at;
  int64_t received_at;
  int64_t started_at;
  int64_t pv_last_at;
  int64_t next_pv_at;
  bool input_eof;
  bool track_finished;
  bool failed;
  bool reorder_initialized;
  uint64_t reorder_group_id;
  uint64_t reorder_next_object_id;
  size_t reorder_bytes;
  reorder_entry_t *reorder;
  pv_path_t pv_paths[TRANSPORT_MAX_PATHS];
} app_t;

static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t reload_credentials_requested = 0;

static void handle_signal(int sig) {
#ifdef SIGHUP
  if (sig == SIGHUP) {
    reload_credentials_requested = 1;
    return;
  }
#endif
  (void)sig;
  running = 0;
}

static void show_help(FILE *out, const char *program) {
  fprintf(
      out,
      "usage: %s (--listen PORT | --peer HOST[:PORT]) [options]\n\n"
      "Network:\n"
      "  --bind ADDRESS              numeric local address (repeatable)\n"
      "  --stripes N                 multi-socket striping paths (1..4)\n"
      "  --multihome                 auto-bind all active non-loopback "
      "interfaces\n"
      "  --cc cubic|cuback       congestion controller (default: cubic)\n"
      "  --initial-cwnd N            initial window packets (default: 4096)\n"
      "  --udp-payload N             maximum UDP payload, 1200..1500 bytes "
      "(default: 1280; must fit the path MTU)\n"
      "  --jumpstart N               quickstart initial window packets "
      "(default: 256 for transfer)\n"
      "  --cert FILE --key FILE      TLS identity; required for listeners "
      "and verified peers\n"
      "  --ca FILE                   peer CA bundle\n"
      "  --auth-token TOKEN          application authentication token\n"
      "  --tls-group-policy POLICY   classical (default), prefer-hybrid, "
      "require-hybrid\n"
      "  --insecure-no-verify        test-only certificate bypass\n"
      "  --idle-timeout-ms MS        QUIC session idle timeout\n"
      "  --max-connections N         listener connection capacity\n"
      "  --max-repair-requests N     per-peer repair requests/second\n"
      "  --max-aggregate-repairs N   source-wide repair requests/second\n"
      "  --loss PERCENT              test-only simulated packet loss\n\n"
      "Data:\n"
      "  --track NAME                default qlinq-app/data (xfer-v1 for "
      "--transfer)\n"
      "  --mode datagram|fixedrate|rateless|reliable (fec is an alias)\n"
      "  --repair-mode auto|indexed|rateless\n"
      "  --transfer                  verified, resumable single-file copy\n"
      "  --transfer-timeout-ms MS     no-progress timeout; default 60000\n"
      "  --streaming-source-hash     experimental sender hash during transfer; "
      "new peers required\n"
      "  --input FILE|-              publish fixed-size records\n"
      "  --output FILE|-             write received records\n"
      "  --message-size BYTES        default 1200\n"
      "  --count N                   stop after N sent records\n"
      "  --receive-count N           exit after N received records\n"
      "  --wait-subscribers N        default 1 when publishing\n"
      "  --send-batch N              batch send size; default 32\n"
      "  --mbps RATE                 target send rate in Mbps (0 unpaced)\n"
      "  --interval-ms MS            minimum send interval\n"
      "  --one-shot                  exit after input and drain\n"
      "  --drain-ms MS               default 1000\n"
      "  --stats-ms MS               periodically print counters\n"
      "  --stats-file FILE           write TSV counter snapshots\n"
      "  --pv                        pv-style throughput per interface\n"
      "  --pv-ms MS                  pv snapshot interval; default 1000\n"
      "  --node-id ID                TSV node label\n"
      "  --verbose\n\n"
      "Signals:\n"
      "  SIGHUP                      reload --cert and --key atomically\n",
      program);
}

static bool write_payload(app_t *app, const moq_track_id_t *track,
                          const uint8_t *data, size_t size) {
  if (track->type == MOQ_TRACK_DATA &&
      (track->flags &
       (MOQ_TRACK_FLAG_FEC_ENABLED | MOQ_TRACK_FLAG_FEC_RATELESS)) != 0) {
    qlinq_wire_cursor_t cursor = {data, size};
    while (cursor.remaining != 0) {
      const uint8_t *record;
      size_t record_size;
      if (!qlinq_wire_next_record(&cursor, &record, &record_size) ||
          record_size == 0) {
        fprintf(stderr, "qlinq-app: invalid wire record remaining=%zu\n",
                cursor.remaining);
        return false;
      }
      if (app->xfer) {
        if (!app_xfer_receive(app->xfer, record, record_size)) {
          fprintf(stderr, "qlinq-app: invalid transfer record size=%zu\n",
                  record_size);
          return false;
        }
        app->transfer_progress_at = transport_get_time_ms();
      } else if (app->output &&
                 fwrite(record, 1, record_size, app->output) != record_size) {
        return false;
      }
      app->received_records++;
      app->received_bytes += record_size;
    }
  } else {
    if (app->xfer) {
      if (!app_xfer_receive(app->xfer, data, size)) {
        fprintf(stderr,
                "qlinq-app: app_xfer_receive un-grouped failed size=%zu\n",
                size);
        return false;
      }
      app->transfer_progress_at = transport_get_time_ms();
    } else if (app->output && size != 0 &&
               fwrite(data, 1, size, app->output) != size) {
      return false;
    }
    app->received_records++;
    app->received_bytes += size;
  }
  if (!app->xfer && app->options->receive_limit != 0 &&
      app->received_records >= app->options->receive_limit) {
    if (app->output && fflush(app->output) != 0)
      return false;
    if (app->received_at == 0)
      app->received_at = transport_get_time_ms();
  }
  return true;
}

static bool write_object(app_t *app, const transport_event_t *event) {
  bool ordered = event->track_id.type == MOQ_TRACK_DATA &&
                 (event->track_id.flags & (MOQ_TRACK_FLAG_FEC_ENABLED |
                                           MOQ_TRACK_FLAG_FEC_RATELESS)) != 0;
  if (!ordered)
    return write_payload(app, &event->track_id, event->object.data,
                         event->object.size);
  if (!app->reorder_initialized) {
    app->reorder_initialized = true;
    app->reorder_group_id = event->object.group_id;
    app->reorder_next_object_id = 0;
  }
  if (event->object.group_id > app->reorder_group_id) {
    /* advance to next group and reset per-group reorder window */
    for (size_t i = 0; i < APP_REORDER_OBJECTS; i++) {
      if (app->reorder[i].active) {
        free(app->reorder[i].data);
        memset(&app->reorder[i], 0, sizeof(app->reorder[i]));
      }
    }
    app->reorder_bytes = 0;
    app->reorder_group_id = event->object.group_id;
    app->reorder_next_object_id = 0;
  } else if (event->object.group_id < app->reorder_group_id ||
             event->object.object_id < app->reorder_next_object_id) {
    /* drop duplicate or stale object from older group */
    return true;
  }
  uint64_t distance = event->object.object_id - app->reorder_next_object_id;
  if (distance >= APP_REORDER_OBJECTS ||
      event->object.size > APP_REORDER_MAX_BYTES - app->reorder_bytes) {
    fprintf(stderr,
            "qlinq-app: reorder reject obj=%" PRIu64 " next=%" PRIu64
            " distance=%" PRIu64 " bytes=%zu (max %u)\n",
            event->object.object_id, app->reorder_next_object_id, distance,
            app->reorder_bytes, APP_REORDER_MAX_BYTES);
    return false;
  }
  size_t slot = (size_t)(event->object.object_id % APP_REORDER_OBJECTS);
  reorder_entry_t *entry = &app->reorder[slot];
  if (entry->active)
    return entry->object_id == event->object.object_id;
  entry->data = malloc(event->object.size);
  if (!entry->data)
    return false;
  memcpy(entry->data, event->object.data, event->object.size);
  entry->size = event->object.size;
  entry->object_id = event->object.object_id;
  entry->active = true;
  app->reorder_bytes += entry->size;

  while (true) {
    slot = (size_t)(app->reorder_next_object_id % APP_REORDER_OBJECTS);
    entry = &app->reorder[slot];
    if (!entry->active || entry->object_id != app->reorder_next_object_id)
      break;
    if (!write_payload(app, &event->track_id, entry->data, entry->size))
      return false;
    app->reorder_bytes -= entry->size;
    free(entry->data);
    memset(entry, 0, sizeof(*entry));
    app->reorder_next_object_id++;
  }
  return true;
}

static void subscribe(app_t *app, transport_conn_t *conn) {
  if (!transport_subscribe_conn(app->transport, conn, app->options->track)) {
    fprintf(stderr, "qlinq-app: unable to subscribe to '%s'\n",
            app->options->track.name);
    app->failed = true;
  }
}

static void on_event(void *user_data, const transport_event_t *event) {
  app_t *app = user_data;
  const options_t *options = app->options;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    if (options->pv) {
      transport_conn_stats_t stats;
      if (transport_get_conn_stats(app->transport, event->conn, &stats))
        fprintf(stderr, "qlinq-app: conn=%u cc=%s\n", stats.id,
                stats.congestion_control);
    }
    if (options->verbose)
      fprintf(stderr, "qlinq-app: peer connected\n");
    if (!options->is_server &&
        !transport_send_auth(app->transport, event->conn, options->auth_token,
                             options->auth_token_len))
      app->failed = true;
    break;
  case TRANSPORT_EVENT_AUTH: {
    bool accepted = options->is_server &&
                    event->auth.token_len == options->auth_token_len &&
                    CRYPTO_memcmp(event->auth.token, options->auth_token,
                                  options->auth_token_len) == 0;
    if (!transport_respond_auth(app->transport, event->conn, accepted))
      app->failed = true;
    if (accepted) {
      if (app->xfer) {
        app->xfer_conn = event->conn;
        app_xfer_link(app->xfer, true);
      }
      subscribe(app, event->conn);
    }
    break;
  }
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    if (event->auth.success) {
      if (app->xfer) {
        app->xfer_conn = event->conn;
        app_xfer_link(app->xfer, true);
      }
      subscribe(app, event->conn);
    } else {
      app->failed = true;
    }
    break;
  case TRANSPORT_EVENT_SUBSCRIBE:
    if (event->track_id.type == options->track.type &&
        strcmp(event->track_id.name, options->track.name) == 0)
      app->subscriptions++;
    break;
  case TRANSPORT_EVENT_UNSUBSCRIBE:
    if (event->track_id.type == options->track.type &&
        strcmp(event->track_id.name, options->track.name) == 0 &&
        app->subscriptions != 0)
      app->subscriptions--;
    break;
  case TRANSPORT_EVENT_OBJECT:
    if (event->track_id.type == options->track.type &&
        strcmp(event->track_id.name, options->track.name) == 0) {
      if (app->xfer && event->conn != app->xfer_conn)
        break;
      if (!write_object(app, event)) {
        fprintf(stderr, "qlinq-app: malformed object or output error\n");
        app->failed = true;
      }
    }
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    if (app->xfer && event->conn == app->xfer_conn) {
      app->subscriptions = 0;
      app->xfer_conn = NULL;
      app_xfer_link(app->xfer, false);
    }
    if (options->verbose)
      fprintf(stderr,
              "qlinq-app: peer disconnected origin=%s class=%s code=%" PRIu64
              " raw=%" PRId64 " reason=%s\n",
              event->disconnect.remote ? "remote" : "local",
              event->disconnect.application_error ? "application"
              : QUICLY_ERROR_IS_QUIC_TRANSPORT(event->disconnect.raw_error)
                  ? "transport"
                  : "internal",
              event->disconnect.error_code, event->disconnect.raw_error,
              event->disconnect.reason && event->disconnect.reason[0]
                  ? event->disconnect.reason
                  : "none");
    break;
  case TRANSPORT_EVENT_OBJECT_LOST:
    if (options->verbose)
      fprintf(stderr, "qlinq-app: object recovery failed\n");
    break;
  case TRANSPORT_EVENT_KEYFRAME_REQUEST:
    break;
  }
}

static void service_publish(app_t *app, int64_t now) {
  if (!app->input || app->input_eof ||
      app->subscriptions < app->options->required_subscriptions)
    return;

  uint64_t target_records = UINT64_MAX;
  if (app->options->mbps > 0) {
    int64_t elapsed_ms = now - app->started_at;
    if (elapsed_ms < 0)
      elapsed_ms = 0;
    target_records =
        (uint64_t)((double)elapsed_ms / 1000.0 * (app->options->mbps * 1e6) /
                   (8.0 * app->options->message_size));
  }

  size_t batch = app->options->send_batch ? app->options->send_batch : 32;
  for (size_t i = 0; i < batch; i++) {
    if (app->options->count_limit != 0 &&
        app->sent_records >= app->options->count_limit) {
      app->input_eof = true;
      break;
    }
    if (app->sent_records >= target_records)
      break;
    if (now < app->next_send_at)
      break;

    if (app->pending_size == 0) {
      ssize_t n =
          read(fileno(app->input), app->message, app->options->message_size);
      if (n > 0) {
        app->pending_size = (size_t)n;
      } else if (n == 0) {
        app->input_eof = true;
        break;
      } else {
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
          fprintf(stderr, "qlinq-app: input read failed: %s\n",
                  strerror(errno));
          app->failed = true;
        }
        break;
      }
    }

    moq_object_t object = {.track_id = app->options->track,
                           .group_id = 0,
                           .object_id = app->sent_records,
                           .data = app->message,
                           .size = app->pending_size,
                           .priority = 1};
    transport_publish_result_t result =
        transport_publish_ex(app->transport, &object);
    if (result == TRANSPORT_PUBLISH_BACKPRESSURE)
      break;
    if (result == TRANSPORT_PUBLISH_INVALID ||
        result == TRANSPORT_PUBLISH_ERROR ||
        result == TRANSPORT_PUBLISH_PARTIAL) {
      fprintf(stderr, "qlinq-app: publication failed (%d)\n", result);
      app->failed = true;
      break;
    }
    app->pending_size = 0;
    app->sent_records++;
    app->next_send_at = now + app->options->interval_ms;
  }
}

static void finish_track(app_t *app, int64_t now) {
  if (!app->input_eof || app->pending_size != 0 || app->track_finished)
    return;
  if ((app->options->track.flags & MOQ_TRACK_FLAG_FEC_RATELESS) != 0 &&
      !transport_finish_track(app->transport, app->options->track))
    return;
  app->track_finished = true;
  app->finished_at = now;
}

static void print_stats(app_t *app, int64_t now, bool force) {
  if (!force && (app->options->stats_ms == 0 || now < app->next_stats_at))
    return;
  if (app->options->stats_ms == 0 && !app->stats_output)
    return;
  transport_stats_t stats = {0};
  if (!transport_get_stats(app->transport, &stats))
    return;
  if (app->stats_output) {
    fprintf(app->stats_output,
            "%" PRId64 "\t%s\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%zu"
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRIu64 "\t%" PRIu64 "\t%zu\t%" PRIu64 "\t%zu\t%zu\t%zu\t%zu"
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\n",
            now - app->started_at, app->options->node_id, app->sent_records,
            app->received_records, app->received_bytes, stats.track_ends_sent,
            stats.track_ends_received, stats.recovery_checkpoints_sent,
            stats.recovery_checkpoints_received, stats.active_connections,
            stats.reconnect_attempts, stats.reconnect_succeeded,
            stats.reconnect_failed, stats.repair_requests_sent,
            stats.repair_requests_received, stats.repair_requests_deferred,
            stats.repair_requests_throttled +
                stats.repair_requests_aggregate_throttled,
            stats.recovery_checkpoints_pending,
            stats.recovery_oldest_checkpoint_age_ms,
            stats.egress_current_packets, stats.egress_current_bytes,
            stats.egress_peak_packets, stats.egress_peak_bytes,
            stats.udp_would_block, stats.publish_backpressure,
            stats.publish_errors);
    fflush(app->stats_output);
  } else {
    fprintf(stderr,
            "qlinq-app: tx=%" PRIu64 " rx=%" PRIu64 " bytes=%" PRIu64
            " connections=%zu\n",
            app->sent_records, app->received_records, app->received_bytes,
            stats.active_connections);
  }
  app->next_stats_at = now + app->options->stats_ms;
}

static void format_bytes(double bytes, char *output, size_t capacity) {
  static const char *const units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
  size_t unit = 0;
  while (bytes >= 1024.0 && unit + 1 < sizeof(units) / sizeof(units[0])) {
    bytes /= 1024.0;
    unit++;
  }
  if (unit == 0)
    snprintf(output, capacity, "%.0f %s", bytes, units[unit]);
  else
    snprintf(output, capacity, "%.2f %s", bytes, units[unit]);
}

static void print_pv(app_t *app, int64_t now, bool force) {
  if (!app->options->pv || (!force && now < app->next_pv_at))
    return;
  int64_t interval_ms = now - app->pv_last_at;
  if (interval_ms <= 0)
    interval_ms = 1;
  uint64_t elapsed_seconds =
      now > app->started_at ? (uint64_t)(now - app->started_at) / 1000U : 0;

  for (size_t path = 0; path < TRANSPORT_MAX_PATHS; path++) {
    transport_path_stats_t stats;
    if (!transport_get_path_stats(app->transport, path, &stats))
      break;
    pv_path_t *previous = &app->pv_paths[path];
    bool same_path = previous->initialized &&
                     previous->interface_index == stats.interface_index &&
                     strcmp(previous->local_address, stats.local_address) == 0;
    uint64_t sent_delta = same_path && stats.bytes_sent >= previous->bytes_sent
                              ? stats.bytes_sent - previous->bytes_sent
                              : stats.bytes_sent;
    uint64_t received_delta =
        same_path && stats.bytes_received >= previous->bytes_received
            ? stats.bytes_received - previous->bytes_received
            : stats.bytes_received;
    double sent_rate = (double)sent_delta * 1000.0 / (double)interval_ms;
    double received_rate =
        (double)received_delta * 1000.0 / (double)interval_ms;

    char sent_total[32], received_total[32], sent_per_second[32];
    char received_per_second[32], label[136];
    format_bytes((double)stats.bytes_sent, sent_total, sizeof(sent_total));
    format_bytes((double)stats.bytes_received, received_total,
                 sizeof(received_total));
    format_bytes(sent_rate, sent_per_second, sizeof(sent_per_second));
    format_bytes(received_rate, received_per_second,
                 sizeof(received_per_second));
    if (stats.local_address[0] &&
        strcmp(stats.interface_name, stats.local_address) != 0)
      snprintf(label, sizeof(label), "%s (%s)", stats.interface_name,
               stats.local_address);
    else
      snprintf(label, sizeof(label), "%s", stats.interface_name);
    fprintf(stderr,
            "qlinq-app: pv %s tx %s %" PRIu64 ":%02" PRIu64 ":%02" PRIu64
            " [%s/s] rx %s [%s/s] path=%zu state=%u rtt_ms=%u cwnd=%u "
            "inflight=%u tx_bytes=%" PRIu64 " rx_bytes=%" PRIu64
            " packets_sent=%" PRIu64 " acked=%" PRIu64 " lost=%" PRIu64 "\n",
            label, sent_total, elapsed_seconds / 3600U,
            (elapsed_seconds / 60U) % 60U, elapsed_seconds % 60U,
            sent_per_second, received_total, received_per_second, path,
            (unsigned)stats.lifecycle, stats.rtt, stats.cwnd,
            stats.bytes_in_flight, stats.bytes_sent, stats.bytes_received,
            stats.sent, stats.acked, stats.lost);

    previous->interface_index = stats.interface_index;
    memcpy(previous->local_address, stats.local_address,
           sizeof(previous->local_address));
    previous->bytes_sent = stats.bytes_sent;
    previous->bytes_received = stats.bytes_received;
    previous->initialized = true;
  }
  transport_conn_stats_t conn_stats;
  if (app->xfer_conn &&
      transport_get_conn_stats(app->transport, app->xfer_conn, &conn_stats)) {
    fprintf(stderr,
            "qlinq-app: pv conn=%u cc=%s jumpstart_applicable=%" PRIu64
            " primary_jumpstart_cwnd=%u quic_packets_sent=%" PRIu64
            " quic_packets_lost=%" PRIu64
            " quic_packets_lost_time_threshold=%" PRIu64
            " quic_packets_late_acked=%" PRIu64 "\n",
            conn_stats.id, conn_stats.congestion_control,
            conn_stats.jumpstart_applicable, conn_stats.primary_jumpstart_cwnd,
            conn_stats.quic_packets_sent, conn_stats.quic_packets_lost,
            conn_stats.quic_packets_lost_time_threshold,
            conn_stats.quic_packets_late_acked);
    fprintf(
        stderr,
        "qlinq-app: pv stream elapsed_ms=%" PRId64 " send_permitted=%" PRIu64
        " sent=%" PRIu64 " data_blocked_frames=%" PRIu64
        " stream_data_blocked_frames=%" PRIu64
        " tracks=%zu track_unsent=%" PRIu64 " track_retained=%" PRIu64
        " track_flow_limited=%zu\n",
        now - app->started_at, conn_stats.quic_send_permitted,
        conn_stats.quic_stream_bytes_sent, conn_stats.quic_data_blocked_frames,
        conn_stats.quic_stream_data_blocked_frames, conn_stats.track_streams,
        conn_stats.track_unsent_bytes, conn_stats.track_retained_bytes,
        conn_stats.track_flow_limited_streams);
  }
  if (app->xfer) {
    app_xfer_status_t status;
    app_xfer_status(app->xfer, &status);
    transport_stats_t aggregate_stats = {0};
    (void)transport_get_stats(app->transport, &aggregate_stats);
    fprintf(stderr,
            "qlinq-app: pv file source_prepare_ms=%" PRIu64
            " commit_ms=%" PRIu64 " credit_wait_ms=%" PRIu64
            " input_queue_bytes=%zu output_queue_bytes=%zu"
            " stream_egress_bytes=%zu publish_backpressure=%" PRIu64 "\n",
            status.source_prepare_ms, status.commit_ms, status.credit_wait_ms,
            status.input_queue_bytes, status.output_queue_bytes,
            aggregate_stats.stream_egress_bytes,
            aggregate_stats.publish_backpressure);
  }
  app->pv_last_at = now;
  app->next_pv_at = now + app->options->pv_ms;
}

static void cleanup_reorder(app_t *app) {
  if (!app->reorder)
    return;
  for (size_t i = 0; i < APP_REORDER_OBJECTS; i++)
    free(app->reorder[i].data);
  free(app->reorder);
  app->reorder = NULL;
}

static bool parse_options(int argc, char **argv, options_t *options) {
  *options = (options_t){.track = {.type = MOQ_TRACK_DATA,
                                   .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                                   .name = "qlinq-app/data"},
                         .drain_ms = 1000,
                         .pv_ms = APP_PV_INTERVAL_MS,
                         .transfer_timeout_ms = 60000,
                         .node_id = "qlinq-app",
                         .message_size = 1200,
                         .send_batch = 32,
                         .congestion_control = TRANSPORT_CC_CUBIC,
                         .initial_cwnd_packets = 4096,
                         .mbps = 0.0,
                         .repair_mode = TRANSPORT_REPAIR_MODE_AUTO,
                         .verify_peer = true};
  uint64_t parsed;
  bool mode_set = false, raw_options = false, transfer_timeout_set = false;
  bool track_set = false;

  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];
    if (strcmp(arg, "--help") == 0) {
      options->help = true;
      return true;
    }
    if (strcmp(arg, "--insecure-no-verify") == 0) {
      options->verify_peer = false;
      options->allow_insecure = true;
      continue;
    }
    if (strcmp(arg, "--transfer") == 0) {
      options->transfer = true;
      continue;
    }
    if (strcmp(arg, "--streaming-source-hash") == 0) {
      options->streaming_source_hash = true;
      continue;
    }
    if (strcmp(arg, "--one-shot") == 0) {
      options->one_shot = true;
      continue;
    }
    if (strcmp(arg, "--pv") == 0) {
      options->pv = true;
      continue;
    }
    if (strcmp(arg, "--verbose") == 0) {
      options->verbose = true;
      continue;
    }
    if (++i >= argc)
      goto invalid;
    const char *value = argv[i];
    if (strcmp(arg, "--message-size") == 0 || strcmp(arg, "--count") == 0 ||
        strcmp(arg, "--receive-count") == 0 ||
        strcmp(arg, "--wait-subscribers") == 0 ||
        strcmp(arg, "--repair-mode") == 0 ||
        strcmp(arg, "--max-repair-requests") == 0 ||
        strcmp(arg, "--max-aggregate-repairs") == 0 ||
        strcmp(arg, "--send-batch") == 0 || strcmp(arg, "--batch") == 0 ||
        strcmp(arg, "--mbps") == 0)
      raw_options = true;
    if (strcmp(arg, "--transfer-timeout-ms") == 0) {
      if (!cli_parse_u64(value, UINT32_MAX, &parsed) || parsed == 0)
        goto invalid;
      options->transfer_timeout_ms = (uint32_t)parsed;
      transfer_timeout_set = true;
    } else if (strcmp(arg, "--listen") == 0) {
      if (!cli_parse_u64(value, UINT16_MAX, &parsed) || parsed == 0)
        goto invalid;
      options->listen_port = (uint16_t)parsed;
    } else if (strcmp(arg, "--peer") == 0) {
      if (options->num_peer_args < TRANSPORT_MAX_PATHS) {
        options->peer_args[options->num_peer_args++] = value;
      }
      options->peer_arg = options->peer_args[0];
    } else if (strcmp(arg, "--bind") == 0) {
      if (options->num_bind_hosts < TRANSPORT_MAX_PATHS) {
        options->bind_hosts[options->num_bind_hosts++] = value;
      }
      options->bind_host = options->bind_hosts[0];
    } else if (strcmp(arg, "--stripes") == 0) {
      if (!cli_parse_u64(value, TRANSPORT_MAX_PATHS, &parsed) || parsed == 0)
        goto invalid;
      options->stripes = (size_t)parsed;
    } else if (strcmp(arg, "--multihome") == 0) {
      options->multihome = true;
    } else if (strcmp(arg, "--cc") == 0) {
      if (strcmp(value, "cubic") == 0)
        options->congestion_control = TRANSPORT_CC_CUBIC;
      else if (strcmp(value, "cuback") == 0)
        options->congestion_control = TRANSPORT_CC_CUBACK;
      else
        goto invalid;
    } else if (strcmp(arg, "--initial-cwnd") == 0) {
      if (!cli_parse_u64(value, 65535, &parsed) || parsed == 0)
        goto invalid;
      options->initial_cwnd_packets = (uint32_t)parsed;
    } else if (strcmp(arg, "--udp-payload") == 0) {
      if (!cli_parse_u64(value, 1500, &parsed) || parsed < 1200)
        goto invalid;
      options->max_udp_payload_size = (size_t)parsed;
    } else if (strcmp(arg, "--jumpstart") == 0 ||
               strcmp(arg, "--quickstart") == 0) {
      if (!cli_parse_u64(value, 65535, &parsed))
        goto invalid;
      options->jumpstart_packets = (uint32_t)parsed;
      options->jumpstart_set = true;
    } else if (strcmp(arg, "--cert") == 0) {
      options->cert_file = value;
    } else if (strcmp(arg, "--key") == 0) {
      options->key_file = value;
    } else if (strcmp(arg, "--tls-group-policy") == 0) {
      if (!qlinq_tls_group_policy_parse(value, &options->tls_group_policy))
        goto invalid;
    } else if (strcmp(arg, "--ca") == 0) {
      options->ca_file = value;
    } else if (strcmp(arg, "--auth-token") == 0) {
      options->auth_token = (const uint8_t *)value;
    } else if (strcmp(arg, "--idle-timeout-ms") == 0) {
      if (!cli_parse_u64(value, UINT64_MAX, &options->idle_timeout_ms) ||
          options->idle_timeout_ms == 0)
        goto invalid;
    } else if (strcmp(arg, "--max-connections") == 0) {
      if (!cli_parse_u64(value, TRANSPORT_HARD_MAX_CONNECTIONS, &parsed) ||
          parsed == 0)
        goto invalid;
      options->max_connections = (size_t)parsed;
    } else if (strcmp(arg, "--max-repair-requests") == 0) {
      if (!cli_parse_u64(value, UINT16_MAX, &parsed) || parsed == 0)
        goto invalid;
      options->max_repair_requests = (size_t)parsed;
    } else if (strcmp(arg, "--max-aggregate-repairs") == 0) {
      if (!cli_parse_u64(value, UINT16_MAX, &parsed) || parsed == 0)
        goto invalid;
      options->max_aggregate_repairs = (size_t)parsed;
    } else if (strcmp(arg, "--loss") == 0) {
      if (!cli_parse_u64(value, 100, &parsed))
        goto invalid;
      options->simulated_loss = (uint8_t)parsed;
    } else if (strcmp(arg, "--track") == 0) {
      track_set = true;
      if (strlen(value) >= sizeof(options->track.name))
        goto invalid;
      strcpy(options->track.name, value);
    } else if (strcmp(arg, "--mode") == 0) {
      mode_set = true;
      if (!cli_parse_track_mode(value, &options->track.flags))
        goto invalid;
    } else if (strcmp(arg, "--repair-mode") == 0) {
      if (strcmp(value, "auto") == 0)
        options->repair_mode = TRANSPORT_REPAIR_MODE_AUTO;
      else if (strcmp(value, "indexed") == 0)
        options->repair_mode = TRANSPORT_REPAIR_MODE_INDEXED;
      else if (strcmp(value, "rateless") == 0)
        options->repair_mode = TRANSPORT_REPAIR_MODE_RATELESS;
      else
        goto invalid;
    } else if (strcmp(arg, "--input") == 0) {
      options->input_path = value;
    } else if (strcmp(arg, "--output") == 0) {
      options->output_path = value;
    } else if (strcmp(arg, "--message-size") == 0) {
      if (!cli_parse_u64(value, TRANSPORT_MAX_FEC_OBJECT_SIZE, &parsed) ||
          parsed == 0)
        goto invalid;
      options->message_size = (size_t)parsed;
    } else if (strcmp(arg, "--count") == 0) {
      if (!cli_parse_u64(value, UINT64_MAX, &options->count_limit))
        goto invalid;
    } else if (strcmp(arg, "--receive-count") == 0) {
      if (!cli_parse_u64(value, UINT64_MAX, &options->receive_limit) ||
          options->receive_limit == 0)
        goto invalid;
    } else if (strcmp(arg, "--wait-subscribers") == 0) {
      if (!cli_parse_u64(value, SIZE_MAX, &parsed))
        goto invalid;
      options->required_subscriptions = (size_t)parsed;
    } else if (strcmp(arg, "--interval-ms") == 0) {
      if (!cli_parse_u64(value, UINT32_MAX, &parsed))
        goto invalid;
      options->interval_ms = (uint32_t)parsed;
    } else if (strcmp(arg, "--drain-ms") == 0) {
      if (!cli_parse_u64(value, UINT32_MAX, &parsed))
        goto invalid;
      options->drain_ms = (uint32_t)parsed;
    } else if (strcmp(arg, "--stats-ms") == 0) {
      if (!cli_parse_u64(value, UINT32_MAX, &parsed))
        goto invalid;
      options->stats_ms = (uint32_t)parsed;
    } else if (strcmp(arg, "--pv-ms") == 0) {
      if (!cli_parse_u64(value, UINT32_MAX, &parsed) || parsed == 0)
        goto invalid;
      options->pv_ms = (uint32_t)parsed;
    } else if (strcmp(arg, "--stats-file") == 0) {
      options->stats_path = value;
    } else if (strcmp(arg, "--node-id") == 0) {
      if (!value[0] || strchr(value, '\t') || strchr(value, '\n'))
        goto invalid;
      options->node_id = value;
    } else if (strcmp(arg, "--send-batch") == 0 ||
               strcmp(arg, "--batch") == 0) {
      if (!cli_parse_u64(value, 4096, &parsed) || parsed == 0)
        goto invalid;
      options->send_batch = (size_t)parsed;
    } else if (strcmp(arg, "--mbps") == 0) {
      char *end = NULL;
      options->mbps = strtod(value, &end);
      if (end == value || *end != '\0' || options->mbps < 0)
        goto invalid;
    } else {
      goto invalid;
    }
  }

  if ((options->cert_file == NULL) != (options->key_file == NULL) ||
      ((options->listen_port != 0 || options->verify_peer) &&
       options->cert_file == NULL)) {
    fprintf(stderr,
            "qlinq-app: a TLS identity is required; use both --cert and "
            "--key (insecure clients may omit both)\n");
    return false;
  }
  if ((options->listen_port == 0) == (options->peer_arg == NULL) ||
      (!options->input_path && !options->output_path) ||
      (options->one_shot && !options->input_path) || !options->auth_token ||
      !options->auth_token[0])
    goto invalid;
  if (options->streaming_source_hash &&
      (!options->transfer || !options->input_path))
    goto invalid;
  if (options->transfer) {
    if ((options->input_path != NULL) == (options->output_path != NULL) ||
        strcmp(options->input_path ? options->input_path : options->output_path,
               "-") == 0 ||
        raw_options || options->max_connections > 1 ||
        options->track.name[0] == '\0' ||
        (mode_set && options->track.flags != MOQ_TRACK_FLAG_RELIABLE &&
         options->track.flags != MOQ_TRACK_FLAG_FEC_ENABLED &&
         options->track.flags != MOQ_TRACK_FLAG_FEC_RATELESS)) {
      fprintf(stderr,
              "qlinq-app: --transfer requires one regular input or output "
              "file, valid mode (reliable, fixedrate, rateless), and one peer; "
              "raw record options are incompatible\n");
      return false;
    }
    if (!track_set)
      strcpy(options->track.name, "qlinq-app/xfer-v1");
    if (!mode_set)
      options->track.flags = MOQ_TRACK_FLAG_RELIABLE;
    options->max_connections = 1;
  } else if (transfer_timeout_set) {
    goto invalid;
  }
  options->auth_token_len = strlen((const char *)options->auth_token);
  if (options->auth_token_len > UINT16_MAX ||
      ((options->track.flags &
        (MOQ_TRACK_FLAG_FEC_ENABLED | MOQ_TRACK_FLAG_FEC_RATELESS)) != 0 &&
       options->message_size > TRANSPORT_MAX_FEC_RECORD_SIZE))
    goto invalid;
  options->is_server = options->listen_port != 0;
  if (options->input_path && options->required_subscriptions == 0)
    options->required_subscriptions = 1;

  return true;

invalid:
  fprintf(stderr, "qlinq-app: invalid command line\n");
  show_help(stderr, argv[0]);
  return false;
}

/* service transfer worker queue and completion handshake */
static bool service_transfer(app_t *app, int64_t now) {
  const options_t *options = app->options;
  app->transfer_batch_ready = false;
  if (now >= app->transfer_notify_at) {
    app_xfer_progress(app->xfer);
    uint32_t interval = options->transfer_timeout_ms / 3;
    if (interval == 0)
      interval = 1;
    if (interval > 1000)
      interval = 1000;
    app->transfer_notify_at = now + interval;
  }
  unsigned published = 0;
  for (; app->subscriptions != 0 && published < 64; published++) {
    if (app->transfer_flush_pending) {
      if (!transport_publish_flush(app->transport))
        break;
      app->transfer_flush_pending = false;
    }
    const void *data;
    size_t size;
    bool is_data;
    if (!app_xfer_peek(app->xfer, &data, &size, &is_data) ||
        (is_data && now < app->next_send_at))
      break;
    moq_object_t object = {.track_id = options->track,
                           .object_id = app->sent_records,
                           .data = data,
                           .size = size,
                           .priority = 1};
    transport_publish_result_t result =
        transport_publish_ex(app->transport, &object);
    if (result == TRANSPORT_PUBLISH_BACKPRESSURE ||
        result == TRANSPORT_PUBLISH_NO_RECIPIENTS)
      break;
    if (result != TRANSPORT_PUBLISH_DELIVERED &&
        result != TRANSPORT_PUBLISH_BUFFERED) {
      fprintf(stderr, "qlinq-app: transfer publication failed (%d)\n", result);
      app->failed = true;
      return false;
    }
    app_xfer_consume(app->xfer);
    app->sent_records++;
    app->transfer_progress_at = now;
    if (is_data)
      app->next_send_at = now + options->interval_ms;
    else
      app->transfer_flush_pending = !transport_publish_flush(app->transport);
  }
  app->transfer_batch_ready = published == 64;
  app_xfer_status_t status;
  app_xfer_status(app->xfer, &status);
  transport_stats_t stats;
  transport_get_stats(app->transport, &stats);
  if (status.failed) {
    /* allow time for diagnostic egress to drain */
    if (app->transfer_failure_at == 0)
      app->transfer_failure_at = now;
    if ((!status.output_pending && stats.stream_egress_bytes == 0) ||
        !app->xfer_conn ||
        now - app->transfer_failure_at >= options->drain_ms) {
      fprintf(stderr, "qlinq-app: transfer failed: %s\n", status.error);
      app->failed = true;
    }
    return false;
  }
  if (status.done &&
      (!status.output_pending && stats.stream_egress_bytes == 0)) {
    (void)transport_publish_flush(app->transport);
    if (app->transfer_done_at == 0)
      app->transfer_done_at = now;
    if (!options->input_path || !app->xfer_conn ||
        now - app->transfer_done_at >= 100) {
      fprintf(stderr, "qlinq-app: transfer committed\n");
      return true;
    }
  } else if (status.done && !app->xfer_conn) {
    (void)transport_publish_flush(app->transport);
    fprintf(stderr, "qlinq-app: transfer committed\n");
    return true;
  }
  if (status.disk_bytes != app->transfer_disk_bytes) {
    app->transfer_disk_bytes = status.disk_bytes;
    app->transfer_progress_at = now;
  }
  if (now - app->transfer_progress_at >= options->transfer_timeout_ms) {
    fprintf(stderr, "qlinq-app: transfer timed out without progress\n");
    app->failed = true;
  }
  return false;
}

static void service_app(app_t *app) {
  const options_t *options = app->options;
  app->started_at = transport_get_time_ms();
  app->transfer_progress_at = app->started_at;
  app->next_stats_at = app->started_at + options->stats_ms;
  app->pv_last_at = app->started_at;
  app->next_pv_at = app->started_at + options->pv_ms;
  while (running && !app->failed) {
    int64_t now = transport_get_time_ms();
#ifdef SIGHUP
    if (reload_credentials_requested) {
      reload_credentials_requested = 0;
      if (!options->cert_file) {
        fprintf(stderr, "qlinq-app: TLS credential reload skipped; no identity "
                        "configured\n");
      } else if (!transport_reload_credentials(
                     app->transport, options->cert_file, options->key_file)) {
        fprintf(stderr, "qlinq-app: TLS credential reload failed\n");
      } else {
        fprintf(stderr, "qlinq-app: TLS credentials reloaded\n");
      }
    }
#endif
    transport_tick(app->transport);
    if (app->xfer) {
      app_xfer_drain(app->xfer);
      if (service_transfer(app, now))
        break;
    } else {
      service_publish(app, now);
      finish_track(app, now);
    }
    print_stats(app, now, false);
    print_pv(app, now, false);

    bool send_done =
        !options->one_shot ||
        (app->track_finished && now - app->finished_at >= options->drain_ms);
    bool receive_done =
        options->receive_limit == 0 ||
        (app->received_at != 0 && now - app->received_at >= options->drain_ms);
    if (!app->xfer && (options->one_shot || options->receive_limit != 0) &&
        send_done && receive_done)
      break;

    struct pollfd fds[TRANSPORT_MAX_POLL_FDS + 1];
    size_t num_fds = transport_get_poll_fds(app->transport, fds,
                                            sizeof(fds) / sizeof(fds[0]));
    if (app->xfer)
      fds[num_fds++] =
          (struct pollfd){.fd = app_xfer_get_fd(app->xfer), .events = POLLIN};
    int timeout = 10;
    int64_t deadline = transport_get_first_timeout(app->transport);
    /* Packet and file service can consume part of a pacing interval. Calculate
     * the remaining wait against the clock after that work, not loop entry. */
    int64_t poll_now = transport_get_time_ms();
    if (deadline != INT64_MAX && deadline <= poll_now)
      timeout = 0;
    else if (deadline != INT64_MAX && deadline - poll_now < timeout)
      timeout = (int)(deadline - poll_now);

    /* A full transfer batch is runnable work, not an application idle period.
     * Sleeping 10 ms after every 64 x 16 KiB batch caps bulk publication near
     * 839 Mbps. An empty, paced, or backpressured batch still uses normal poll.
     */
    if (app->transfer_batch_ready)
      timeout = 0;

    /* if actively sending and not paced or backpressured, poll with 0 timeout
     */
    if (app->input && !app->input_eof && app->pending_size == 0 &&
        app->subscriptions >= options->required_subscriptions) {
      if (options->mbps <= 0) {
        timeout = 0;
      } else {
        int64_t elapsed_ms = poll_now - app->started_at;
        uint64_t target =
            (uint64_t)((double)elapsed_ms / 1000.0 * (options->mbps * 1e6) /
                       (8.0 * options->message_size));
        if (app->sent_records < target)
          timeout = 0;
      }
    }
    if (num_fds) {
#ifdef __linux__
      /* Transport deadlines name absolute millisecond boundaries. Waiting a
       * whole relative millisecond from partway through the current tick can
       * oversleep a pacing deadline by almost another millisecond. */
      struct timespec wait = {.tv_nsec = (long)timeout * 1000000L};
      if (timeout > 0 && deadline != INT64_MAX) {
        struct timespec current;
        clock_gettime(CLOCK_MONOTONIC, &current);
        int64_t current_ms =
            (int64_t)current.tv_sec * 1000 + current.tv_nsec / 1000000;
        int64_t remaining_ms = deadline - current_ms;
        if (remaining_ms <= 0)
          wait.tv_nsec = 0;
        else if (remaining_ms <= timeout)
          wait.tv_nsec =
              (long)remaining_ms * 1000000L - current.tv_nsec % 1000000L;
      }
      ppoll(fds, num_fds, &wait, NULL);
#else
      poll(fds, num_fds, timeout);
#endif
    }
  }
  if (app->xfer) {
    app_xfer_status_t status;
    app_xfer_status(app->xfer, &status);
    if (!status.done || status.failed)
      app->failed = true;
  }
  int64_t shutdown_started = transport_get_time_ms();
  transport_shutdown(app->transport,
                     running ? "application complete" : "signal shutdown");
  while (!transport_is_drained(app->transport) &&
         transport_get_time_ms() - shutdown_started < options->drain_ms) {
    transport_tick(app->transport);
    usleep(1000);
  }
  int64_t stopped_at = transport_get_time_ms();
  print_stats(app, stopped_at, true);
  print_pv(app, stopped_at, true);
}

static int run_app(const options_t *options) {
  app_t app = {.options = options};
  if (options->input_path && !options->transfer) {
    app.input = strcmp(options->input_path, "-") == 0
                    ? stdin
                    : fopen(options->input_path, "rb");
    if (!app.input) {
      fprintf(stderr, "qlinq-app: unable to open input: %s\n", strerror(errno));
      app.failed = true;
      goto cleanup;
    }
  }
  if (options->output_path && !options->transfer) {
    app.output = strcmp(options->output_path, "-") == 0
                     ? stdout
                     : fopen(options->output_path, "wb");
    if (!app.output) {
      fprintf(stderr, "qlinq-app: unable to open output: %s\n",
              strerror(errno));
      app.failed = true;
      goto cleanup;
    }
  }
  if (options->stats_path) {
    app.stats_output = fopen(options->stats_path, "w");
    if (!app.stats_output) {
      fprintf(stderr, "qlinq-app: unable to open stats: %s\n", strerror(errno));
      app.failed = true;
      goto cleanup;
    }
    fprintf(app.stats_output,
            "elapsed_ms\tnode\ttx_records\trx_records\trx_bytes\t"
            "track_ends_sent\ttrack_ends_received\tcheckpoints_sent\t"
            "checkpoints_received\tactive_connections\treconnect_attempts\t"
            "reconnect_succeeded\treconnect_failed\trepair_requests_sent\t"
            "repair_requests_received\trepair_requests_deferred\t"
            "repair_requests_throttled\trecovery_checkpoints_pending\t"
            "recovery_oldest_checkpoint_age_ms\tegress_current_packets\t"
            "egress_current_bytes\tegress_peak_packets\tegress_peak_bytes\t"
            "udp_would_block\tpublish_backpressure\tpublish_errors\n");
  }
  if (options->transfer) {
    app.xfer = options->streaming_source_hash
                   ? app_xfer_create_streaming(options->input_path,
                                               options->output_path)
                   : app_xfer_create(options->input_path, options->output_path);
    if (!app.xfer) {
      fprintf(stderr, "qlinq-app: unable to create transfer worker\n");
      app.failed = true;
      goto cleanup;
    }
  }
  app.message = malloc(options->message_size);
  if (!app.message) {
    app.failed = true;
    goto cleanup;
  }
  app.reorder = calloc(APP_REORDER_OBJECTS, sizeof(*app.reorder));
  if (!app.reorder) {
    app.failed = true;
    goto cleanup;
  }

  if (portable_socket_init() != 0) {
    app.failed = true;
    goto cleanup;
  }
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);
#ifdef SIGHUP
  signal(SIGHUP, handle_signal);
#endif

  char peer_hosts[TRANSPORT_MAX_PATHS][256];
  memset(peer_hosts, 0, sizeof(peer_hosts));
  uint16_t port = options->listen_port;
  size_t num_remotes = options->num_peer_args;
  if (num_remotes > 0) {
    port = 8888;
    for (size_t i = 0; i < num_remotes; i++) {
      uint16_t p = 8888;
      if (!cli_parse_endpoint(options->peer_args[i], peer_hosts[i],
                              sizeof(peer_hosts[i]), &p, NULL)) {
        app.failed = true;
        goto cleanup_sockets;
      }
      if (i == 0)
        port = p;
    }
  }

  transport_config_t config = {0};
  config.multihome = options->multihome;
  const char *default_bind =
      (num_remotes > 0 && strchr(peer_hosts[0], ':')) ? "::" : "0.0.0.0";
  size_t effective_stripes = options->stripes ? options->stripes : 1;
  if (options->num_bind_hosts > 0) {
    for (size_t i = 0; i < options->num_bind_hosts; i++)
      config.bind_hosts[i] = options->bind_hosts[i];
    config.num_bind_hosts = options->num_bind_hosts;
    if (options->num_bind_hosts == 1 && effective_stripes > 1) {
      for (size_t i = 1; i < effective_stripes && i < TRANSPORT_MAX_PATHS; i++)
        config.bind_hosts[i] = options->bind_hosts[0];
      config.num_bind_hosts = effective_stripes;
    }
  } else {
    for (size_t i = 0; i < effective_stripes && i < TRANSPORT_MAX_PATHS; i++)
      config.bind_hosts[i] = default_bind;
    config.num_bind_hosts = effective_stripes;
  }
  if (num_remotes > 0) {
    for (size_t i = 0; i < num_remotes && i < TRANSPORT_MAX_PATHS; i++)
      config.remote_hosts[i] = peer_hosts[i];
    config.num_remote_hosts = num_remotes;
  }
  config.port = port;
  config.quic_idle_timeout_ms = options->idle_timeout_ms;
  config.cert_file = options->cert_file;
  config.key_file = options->key_file;
  config.tls_group_policy = options->tls_group_policy;
  config.ca_file = options->ca_file;
  config.verify_peer = options->verify_peer;
  config.allow_insecure_peer = options->allow_insecure;
  config.callback = on_event;
  config.user_data = &app;
  config.simulated_loss_rate = options->simulated_loss;
  config.reconnect_enabled = options->peer_arg != NULL;
  config.repair_mode = options->repair_mode;
  config.congestion_control = options->congestion_control;
  config.limits.max_stream_egress_bytes = 128 * 1024 * 1024;
  config.limits.max_total_stream_egress_bytes = 256 * 1024 * 1024;
  config.limits.max_egress_packets_per_socket = 8192;
  config.limits.max_egress_bytes_per_socket = 16 * 1024 * 1024;
  config.limits.max_recovery_cache_bytes = 64 * 1024 * 1024;
  /* A transfer has one connection. Return to ACK and file-worker service
   * after a short packet turn rather than draining the full default budget. */
  if (options->transfer)
    config.limits.max_packets_per_tick = 128;
  config.limits.max_connections = options->max_connections;
  config.limits.max_repair_requests_per_second =
      options->max_repair_requests ? options->max_repair_requests : 16384;
  config.limits.max_aggregate_repair_requests_per_second =
      options->max_aggregate_repairs ? options->max_aggregate_repairs : 32768;
  config.limits.max_aggregate_nack_requests_per_second = 32768;
  config.initial_cwnd_packets = options->initial_cwnd_packets;
  config.limits.max_udp_payload_size = options->max_udp_payload_size;
  if (options->jumpstart_set) {
    config.default_jumpstart_packets = options->jumpstart_packets;
    config.max_jumpstart_packets =
        options->jumpstart_packets != 0 ? options->jumpstart_packets : 4096;
  } else if (options->transfer) {
    config.default_jumpstart_packets = 256;
    config.max_jumpstart_packets = 4096;
  }
  fprintf(stderr, "qlinq-app: tls-group-policy=%s\n",
          qlinq_tls_group_policy_name(options->tls_group_policy));
  app.transport = transport_create(&config);
  if (!app.transport) {
    fprintf(stderr, "qlinq-app: unable to create transport\n");
    app.failed = true;
    goto cleanup_sockets;
  }

  service_app(&app);

cleanup_sockets:
  if (app.transport)
    transport_destroy(app.transport);
  portable_socket_cleanup();
cleanup:
  app_xfer_destroy(app.xfer);
  cleanup_reorder(&app);
  free(app.message);
  if (app.input && app.input != stdin)
    fclose(app.input);
  if (app.output && app.output != stdout && fclose(app.output) != 0) {
    fprintf(stderr, "qlinq-app: output close failed\n");
    app.failed = true;
  }
  if (app.stats_output)
    fclose(app.stats_output);
  return app.failed ? 1 : 0;
}

int main(int argc, char **argv) {
  options_t options;
  if (!parse_options(argc, argv, &options))
    return 1;
  if (options.help) {
    show_help(stdout, argv[0]);
    return 0;
  }
  return run_app(&options);
}
