/* main.c (daemon) */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "cli_parse.h"
#include "data_uds.h"
#include "portable_sockets.h"
#include "transport.h"
#include "transport_wire.h"
#include "quicly/constants.h"
#include <errno.h>
#include <inttypes.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload_credentials = 0;

static void handle_signal(int sig) {
#ifdef SIGHUP
  if (sig == SIGHUP) {
    g_reload_credentials = 1;
    return;
  }
#endif
  (void)sig;
  g_running = 0;
}

#define MAX_TRANSPORTS 16
#define MAX_DATA_POLL_FDS 17
#define MAX_DAEMON_POLL_FDS                                                    \
  (MAX_DATA_POLL_FDS + MAX_TRANSPORTS * TRANSPORT_MAX_POLL_FDS)

static void show_help(FILE *out, const char *program) {
  fprintf(
      out,
      "usage: %s (--listen PORT | --peer HOST[:PORT]) [options]\n\n"
      "  --bind ADDRESS              numeric listener address\n"
      "  --peer HOST[:PORT]          add an outbound peer (repeatable)\n"
      "  --cert FILE --key FILE      TLS identity\n"
      "  --ca FILE                   peer CA bundle\n"
      "  --auth-token TOKEN          application authentication token\n"
      "  --insecure-no-verify        test-only certificate bypass\n"
      "  --socket NAME               Unix data socket name\n"
      "  --track NAME                subscribe to a track (repeatable)\n"
      "  --stats-ms MS               periodically print transport counters\n"
      "  --mode datagram|fixedrate|rateless|reliable (default fixedrate)\n"
      "                              fec is an alias for fixedrate\n"
      "  --reliable                  alias for --mode reliable\n"
      "  --rateless                  alias for --mode rateless\n"
      "  --verbose\n\n"
      "SIGHUP reloads --cert and --key atomically.\n",
      program);
}

static bool parse_port(const char *text, int *port) {
  uint64_t parsed;
  if (!port || !cli_parse_u64(text, UINT16_MAX, &parsed) || parsed == 0)
    return false;
  *port = (int)parsed;
  return true;
}

static bool parse_u32(const char *text, uint32_t *value) {
  uint64_t parsed;
  if (!value || !cli_parse_u64(text, UINT32_MAX, &parsed) || parsed == 0)
    return false;
  *value = (uint32_t)parsed;
  return true;
}

struct daemon_ctx_s;

typedef struct {
  struct daemon_ctx_s *daemon;
  transport_t *transport;
  bool is_server;
} daemon_transport_ctx_t;

typedef struct {
  const char *argument;
  char host[256];
  uint16_t port;
} peer_options_t;

typedef struct {
  int listen_port;
  const char *listen_host;
  peer_options_t peers[MAX_TRANSPORTS - 1];
  size_t num_peers;
  const char *cert_file;
  const char *key_file;
  const char *ca_file;
  bool verify_peer;
  bool allow_insecure_peer;
  const char *socket_name;
  const char *auth_token;
  size_t auth_token_len;
  char subscribe_tracks[16][64];
  size_t num_subscribe_tracks;
  uint8_t track_flags;
  uint32_t stats_ms;
  bool verbose;
  bool help;
} options_t;

typedef struct daemon_ctx_s {
  const options_t *options;
  daemon_transport_ctx_t transports[MAX_TRANSPORTS];
  size_t num_transports;
  data_uds_t *data_pipe;
  int64_t next_stats_at;
} daemon_ctx_t;

static void subscribe_to_tracks(transport_t *t, daemon_ctx_t *ctx) {
  const options_t *options = ctx->options;
  for (size_t i = 0; i < options->num_subscribe_tracks; i++) {
    moq_track_id_t t_data = {.type = MOQ_TRACK_DATA,
                             .flags = options->track_flags};
    strncpy(t_data.name, options->subscribe_tracks[i], sizeof(t_data.name) - 1);
    t_data.name[sizeof(t_data.name) - 1] = '\0';
    transport_subscribe(t, t_data);
  }
}

static void on_transport_event(void *user_data,
                               const transport_event_t *event) {
  daemon_transport_ctx_t *tctx = user_data;
  daemon_ctx_t *ctx = tctx->daemon;
  const options_t *options = ctx->options;
  transport_t *t = tctx->transport;

  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    printf("peer connected\n");
    if (!tctx->is_server) {
      transport_send_auth(t, event->conn, (const uint8_t *)options->auth_token,
                          options->auth_token_len);
    }
    break;
  case TRANSPORT_EVENT_AUTH:
    if (tctx->is_server) {
      bool success = false;
      if (event->auth.token_len == options->auth_token_len &&
          CRYPTO_memcmp(event->auth.token, options->auth_token,
                        event->auth.token_len) == 0) {
        success = true;
        printf("peer authentication successful\n");
      } else {
        printf("peer authentication failed\n");
      }
      transport_respond_auth(t, event->conn, success);
      if (success)
        subscribe_to_tracks(t, ctx);
    }
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    if (event->auth.success) {
      printf("authentication to peer successful\n");
      subscribe_to_tracks(t, ctx);
    } else {
      fprintf(stderr, "authentication failed, disconnecting from peer\n");
      transport_close_conn(t, event->conn);
    }
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    printf("peer disconnected origin=%s class=%s code=%" PRIu64 " raw=%" PRId64
           " reason=%s\n",
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
  case TRANSPORT_EVENT_SUBSCRIBE:
    printf("daemon: peer subscribed to track '%s' (type %d)\n",
           event->track_id.name, event->track_id.type);
    break;
  case TRANSPORT_EVENT_UNSUBSCRIBE:
    printf("daemon: peer unsubscribed from track '%s' (type %d)\n",
           event->track_id.name, event->track_id.type);
    break;
  case TRANSPORT_EVENT_OBJECT:
    if (options->verbose && event->track_id.type == MOQ_TRACK_DATA) {
      printf("daemon: received object from peer on track '%s', size=%zu, "
             "flags=%d, type=%d\n",
             event->track_id.name, event->object.size, event->track_id.flags,
             event->track_id.type);
    }
    if (ctx->data_pipe && event->track_id.type == MOQ_TRACK_DATA &&
        (event->track_id.flags &
         (MOQ_TRACK_FLAG_FEC_ENABLED | MOQ_TRACK_FLAG_FEC_RATELESS))) {
      qlinq_wire_cursor_t cursor = {event->object.data, event->object.size};
      const uint8_t *record;
      size_t size;
      while (qlinq_wire_next_record(&cursor, &record, &size)) {
        if (!data_uds_send(ctx->data_pipe, &event->track_id, record, size,
                           event->object.priority) &&
            options->verbose)
          fprintf(stderr, "daemon: UDS output queue unavailable\n");
      }
    } else if (ctx->data_pipe) {
      /* Forward raw packet for reliable tracks */
      if (!data_uds_send(ctx->data_pipe, &event->track_id, event->object.data,
                         event->object.size, event->object.priority) &&
          options->verbose)
        fprintf(stderr, "daemon: UDS output queue unavailable\n");
    }
    break;
  case TRANSPORT_EVENT_OBJECT_LOST:
    printf("daemon: object lost event\n");
    break;
  case TRANSPORT_EVENT_KEYFRAME_REQUEST:
    break;
  }
}

static data_uds_result_t on_data_packet(void *user_data,
                                        data_uds_record_t *record) {
  daemon_ctx_t *ctx = user_data;
  if (!ctx)
    return DATA_UDS_FATAL;
  moq_object_t obj = {.track_id = *record->track_id,
                      .group_id = 0,
                      .object_id = record->id,
                      .data = record->data,
                      .size = record->size,
                      .priority = record->priority};
  bool blocked = false;
  for (size_t i = 0; i < ctx->num_transports; i++) {
    uint64_t bit = UINT64_C(1) << i;
    if ((record->progress & bit) != 0 || !ctx->transports[i].transport)
      continue;
    transport_publish_result_t result =
        transport_publish_ex(ctx->transports[i].transport, &obj);
    switch (result) {
    case TRANSPORT_PUBLISH_DELIVERED:
    case TRANSPORT_PUBLISH_BUFFERED:
    case TRANSPORT_PUBLISH_NO_RECIPIENTS:
      record->progress |= bit;
      break;
    case TRANSPORT_PUBLISH_BACKPRESSURE:
      blocked = true;
      break;
    default:
      /* A partial publication cannot be retried as a broadcast without
       * duplicating accepted recipients. Signal a failed local channel. */
      fprintf(stderr, "daemon: publication failed (%d); disconnecting helper\n",
              result);
      return DATA_UDS_FATAL;
    }
  }
  return blocked ? DATA_UDS_RETRY : DATA_UDS_ACCEPTED;
}

static bool on_is_track_ready(void *user_data, const moq_track_id_t *track_id) {
  daemon_ctx_t *ctx = user_data;
  if (!ctx)
    return false;
  for (size_t i = 0; i < ctx->num_transports; i++) {
    if (ctx->transports[i].transport &&
        !transport_is_track_ready(ctx->transports[i].transport, track_id)) {
      return false;
    }
  }
  return true;
}

/* drive daemon event loop processing */
static void daemon_tick(daemon_ctx_t *ctx) {
  data_uds_tick(ctx->data_pipe);
  for (size_t i = 0; i < ctx->num_transports; i++) {
    transport_tick(ctx->transports[i].transport);
  }
}

static void daemon_print_stats(daemon_ctx_t *ctx, int64_t now_ms) {
  if (!ctx || ctx->options->stats_ms == 0)
    return;
  if (ctx->next_stats_at == 0) {
    ctx->next_stats_at = now_ms + ctx->options->stats_ms;
    return;
  }
  if (now_ms < ctx->next_stats_at)
    return;
  for (size_t i = 0; i < ctx->num_transports; i++) {
    transport_stats_t stats = {0};
    if (!transport_get_stats(ctx->transports[i].transport, &stats))
      continue;
    fprintf(stderr,
            "daemon: stats transport=%zu role=%s connections=%zu "
            "reconnect_attempts=%" PRIu64 " reconnect_succeeded=%" PRIu64
            " reconnect_failed=%" PRIu64 " repair_requests_sent=%" PRIu64
            " repair_requests_received=%" PRIu64
            " repair_requests_deferred=%" PRIu64
            " recovery_pending=%zu recovery_oldest_ms=%" PRIu64
            " egress_packets=%zu egress_bytes=%zu udp_would_block=%" PRIu64
            " publish_backpressure=%" PRIu64 " publish_errors=%" PRIu64 "\n",
            i, ctx->transports[i].is_server ? "server" : "client",
            stats.active_connections, stats.reconnect_attempts,
            stats.reconnect_succeeded, stats.reconnect_failed,
            stats.repair_requests_sent, stats.repair_requests_received,
            stats.repair_requests_deferred, stats.recovery_checkpoints_pending,
            stats.recovery_oldest_checkpoint_age_ms,
            stats.egress_current_packets, stats.egress_current_bytes,
            stats.udp_would_block, stats.publish_backpressure,
            stats.publish_errors);
  }
  ctx->next_stats_at = now_ms + ctx->options->stats_ms;
}

/* run daemon loop driven by socket polling and quicly pacer timeouts */
static void daemon_run(daemon_ctx_t *ctx) {
  const options_t *options = ctx->options;
  printf("daemon is running. press ctrl+c to exit.\n");
  while (g_running) {
#ifdef SIGHUP
    if (g_reload_credentials) {
      g_reload_credentials = 0;
      if (!options->cert_file) {
        fprintf(stderr, "daemon: TLS credential reload skipped; no identity "
                        "configured\n");
      } else {
        bool ok = true;
        for (size_t i = 0; i < ctx->num_transports; i++) {
          if (!transport_reload_credentials(ctx->transports[i].transport,
                                            options->cert_file,
                                            options->key_file))
            ok = false;
        }
        fprintf(stderr, "daemon: TLS credential reload %s\n",
                ok ? "complete" : "failed");
      }
    }
#endif
    daemon_tick(ctx);

    int64_t now_ms = transport_get_time_ms();
    daemon_print_stats(ctx, now_ms);
    int64_t earliest_timeout_ms = INT64_MAX;

    for (size_t i = 0; i < ctx->num_transports; i++) {
      if (ctx->transports[i].transport) {
        int64_t to = transport_get_first_timeout(ctx->transports[i].transport);
        if (to < earliest_timeout_ms) {
          earliest_timeout_ms = to;
        }
      }
    }

    int timeout_ms = 10; /* default maximum poll timeout */
    if (earliest_timeout_ms != INT64_MAX) {
      int delta = (int)(earliest_timeout_ms - now_ms);
      if (delta < 0) {
        timeout_ms = 0;
      } else if (delta < timeout_ms) {
        timeout_ms = delta;
      }
    }

    struct pollfd fds[MAX_DAEMON_POLL_FDS];
    size_t num_fds = 0;

    if (ctx->data_pipe) {
      num_fds += data_uds_get_poll_fds(ctx->data_pipe, fds + num_fds,
                                       MAX_DAEMON_POLL_FDS - num_fds);
    }
    for (size_t i = 0; i < ctx->num_transports; i++) {
      if (ctx->transports[i].transport) {
        num_fds +=
            transport_get_poll_fds(ctx->transports[i].transport, fds + num_fds,
                                   MAX_DAEMON_POLL_FDS - num_fds);
      }
    }

    if (num_fds > 0) {
      poll(fds, num_fds, timeout_ms);
    } else if (timeout_ms > 0) {
      usleep(timeout_ms * 1000);
    }
  }
  printf("\nshutting down daemon cleanly...\n");
}

static bool parse_options(int argc, char **argv, options_t *options) {
  *options = (options_t){.listen_port = -1,
                         .listen_host = "0.0.0.0",
                         .verify_peer = true,
                         .socket_name = "qlinq-data",
                         .track_flags = MOQ_TRACK_FLAG_FEC_ENABLED};
  bool have_mode = false;

  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];
    if (strcmp(arg, "--help") == 0) {
      options->help = true;
      return true;
    }
    if (strcmp(arg, "--verify-peer") == 0) {
      options->verify_peer = true;
      options->allow_insecure_peer = false;
      continue;
    }
    if (strcmp(arg, "--insecure-no-verify") == 0) {
      options->verify_peer = false;
      options->allow_insecure_peer = true;
      continue;
    }
    if (strcmp(arg, "--verbose") == 0) {
      options->verbose = true;
      continue;
    }

    const char *value;
    if (strcmp(arg, "--reliable") == 0 || strcmp(arg, "--rateless") == 0) {
      value = arg + 2;
      arg = "--mode";
    } else {
      if (++i >= argc)
        goto invalid;
      value = argv[i];
    }
    if (strcmp(arg, "--listen") == 0) {
      if (!parse_port(value, &options->listen_port))
        goto invalid;
    } else if (strcmp(arg, "--bind") == 0) {
      options->listen_host = value;
    } else if (strcmp(arg, "--cert") == 0) {
      options->cert_file = value;
    } else if (strcmp(arg, "--key") == 0) {
      options->key_file = value;
    } else if (strcmp(arg, "--ca") == 0) {
      options->ca_file = value;
    } else if (strcmp(arg, "--auth-token") == 0) {
      options->auth_token = value;
    } else if (strcmp(arg, "--socket") == 0 || strcmp(arg, "-s") == 0) {
      options->socket_name = value;
    } else if (strcmp(arg, "--peer") == 0) {
      if (options->num_peers >= MAX_TRANSPORTS - 1)
        goto invalid;
      peer_options_t *peer = &options->peers[options->num_peers];
      peer->argument = value;
      peer->port = 8888;
      if (!cli_parse_endpoint(value, peer->host, sizeof(peer->host),
                              &peer->port, NULL))
        goto invalid;
      options->num_peers++;
    } else if (strcmp(arg, "--track") == 0) {
      if (options->num_subscribe_tracks >= 15 ||
          strlen(value) >= sizeof(options->subscribe_tracks[0]))
        goto invalid;
      strcpy(options->subscribe_tracks[options->num_subscribe_tracks++], value);
    } else if (strcmp(arg, "--stats-ms") == 0) {
      if (!parse_u32(value, &options->stats_ms))
        goto invalid;
    } else if (strcmp(arg, "--mode") == 0) {
      uint8_t flags;
      if (!cli_parse_track_mode(value, &flags) ||
          (have_mode && flags != options->track_flags))
        goto invalid;
      options->track_flags = flags;
      have_mode = true;
    } else {
      goto invalid;
    }
  }

  if (!options->auth_token)
    options->auth_token = getenv("QLINQ_AUTH_TOKEN");
  if (!options->auth_token || options->auth_token[0] == '\0') {
    fprintf(stderr, "an authentication token is required; use --auth-token or "
                    "QLINQ_AUTH_TOKEN\n");
    return false;
  }
  if ((options->cert_file == NULL) != (options->key_file == NULL) ||
      ((options->listen_port > 0 || options->verify_peer) &&
       options->cert_file == NULL)) {
    fprintf(stderr, "a TLS identity is required; use both --cert and --key "
                    "(insecure clients may omit both)\n");
    return false;
  }
  options->auth_token_len = strlen(options->auth_token);
  if (options->auth_token_len > UINT16_MAX) {
    fprintf(stderr, "authentication token is too long\n");
    return false;
  }

  if (options->num_subscribe_tracks == 0) {
    strcpy(options->subscribe_tracks[options->num_subscribe_tracks++],
           "bishnc/default");
    strcpy(options->subscribe_tracks[options->num_subscribe_tracks++],
           "tund/tun0");
    strcpy(options->subscribe_tracks[options->num_subscribe_tracks++], "");
  }

  return true;

invalid:
  fprintf(stderr, "invalid command line\n");
  show_help(stderr, argv[0]);
  return false;
}

static bool add_transport(daemon_ctx_t *ctx, const peer_options_t *peer) {
  const options_t *options = ctx->options;
  daemon_transport_ctx_t *tctx = &ctx->transports[ctx->num_transports];
  tctx->daemon = ctx;
  tctx->is_server = peer == NULL;
  transport_config_t config = {.port = peer ? peer->port : options->listen_port,
                               .num_bind_hosts = 1,
                               .cert_file = options->cert_file,
                               .key_file = options->key_file,
                               .ca_file = options->ca_file,
                               .verify_peer = options->verify_peer,
                               .allow_insecure_peer =
                                   options->allow_insecure_peer,
                               .reconnect_enabled = peer != NULL,
                               .callback = on_transport_event,
                               .user_data = tctx};
  config.bind_hosts[0] = peer ? (strchr(peer->host, ':') ? "::" : "0.0.0.0")
                              : options->listen_host;
  if (peer) {
    config.remote_hosts[0] = peer->host;
    config.num_remote_hosts = 1;
  }
  tctx->transport = transport_create(&config);
  if (!tctx->transport)
    return false;
  ctx->num_transports++;
  return true;
}

static void drain_transports(daemon_ctx_t *ctx) {
  for (size_t i = 0; i < ctx->num_transports; i++)
    transport_shutdown(ctx->transports[i].transport, "daemon shutdown");
  int64_t shutdown_started = transport_get_time_ms();
  bool drained = false;
  while (!drained && transport_get_time_ms() - shutdown_started < 1000) {
    drained = true;
    for (size_t i = 0; i < ctx->num_transports; i++) {
      transport_tick(ctx->transports[i].transport);
      if (!transport_is_drained(ctx->transports[i].transport))
        drained = false;
    }
    if (!drained)
      usleep(1000);
  }
}

static int run_daemon(const options_t *options) {
  daemon_ctx_t ctx = {.options = options};
  int status = 1;
  if (options->listen_port > 0) {
    if (!add_transport(&ctx, NULL)) {
      fprintf(stderr, "failed to create server transport\n");
      goto cleanup;
    }
    printf("listening on %s:%d\n", options->listen_host, options->listen_port);
  }
  for (size_t i = 0; i < options->num_peers; i++) {
    const peer_options_t *peer = &options->peers[i];
    if (!add_transport(&ctx, peer)) {
      fprintf(stderr, "failed to create client transport for %s\n",
              peer->argument);
      continue;
    }
    printf("connecting to peer %s:%d\n", peer->host, peer->port);
  }
  if (ctx.num_transports == 0) {
    fprintf(stderr, "no listener or peers specified. exiting.\n");
    goto cleanup;
  }
  ctx.data_pipe = data_uds_create_ex(options->socket_name, on_data_packet,
                                     on_is_track_ready, &ctx);
  if (!ctx.data_pipe) {
    fprintf(stderr, "failed to create UDS data pipe\n");
    goto cleanup;
  }

  daemon_run(&ctx);
  drain_transports(&ctx);
  status = 0;

cleanup:
  if (ctx.data_pipe)
    data_uds_destroy(ctx.data_pipe);
  for (size_t i = 0; i < ctx.num_transports; i++)
    transport_destroy(ctx.transports[i].transport);
  return status;
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
#ifndef _WIN32
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);
#ifdef SIGHUP
  signal(SIGHUP, handle_signal);
#endif
#endif
  printf("starting qlinqd peer mesh daemon...\n");
  if (portable_socket_init() != 0) {
    fprintf(stderr, "failed to initialize sockets\n");
    return 1;
  }

  int status = 1;
  options_t options;
  if (!parse_options(argc, argv, &options))
    goto cleanup;
  if (options.help) {
    show_help(stdout, argv[0]);
    status = 0;
  } else {
    status = run_daemon(&options);
  }
cleanup:
  portable_socket_cleanup();
  return status;
}
