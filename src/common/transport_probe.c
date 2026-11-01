#include "transport_internal.h"
#include "transport_probe.h"

static int64_t next_probe_at(int64_t now, uint32_t interval) {
  return now > INT64_MAX - interval ? INT64_MAX : now + interval;
}

static int64_t probe_paths(transport_conn_t *conn, int64_t now, bool request) {
  transport_t *t = conn->transport;
  uint32_t interval = t->path_probe_interval_ms;
  if (interval == 0 || t->shutting_down || !conn->quic_ready || !conn->quic ||
      quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
    return INT64_MAX;

  /* Readiness can precede handshake confirmation. Do not leave requested
   * control traffic due before the native sender can emit its probe. */
  if (!conn->path_probe_handshake_confirmed) {
    quicly_stats_t stats;
    if (quicly_get_stats(conn->quic, &stats) != 0 ||
        stats.handshake_confirmed_msec == UINT64_MAX)
      return INT64_MAX;
    conn->path_probe_handshake_confirmed = true;
  }

  int64_t deadline = INT64_MAX;
  quicly_path_scheduler_t *scheduler = t->quic_ctx.path_scheduler;
  for (size_t path = 0; path < TRANSPORT_MAX_QUIC_PATHS; path++) {
    transport_probe_state_t *state = &conn->path_probes[path];
    quicly_path_health_t health;
    quicly_path_stats_t stats;
    if (quicly_get_path_health(conn->quic, path, &health) != 0 ||
        !health.validated || health.probe_only || health.abandoned ||
        health.state != QUICLY_PATH_USABLE ||
        !quicly_is_path_available(conn->quic, path) ||
        (scheduler && scheduler->is_path_eligible &&
         !scheduler->is_path_eligible(scheduler, conn->quic, path)) ||
        quicly_get_path_stats(conn->quic, path, &stats) != 0) {
      state->active = false;
      continue;
    }

    /* A native index may be reused, or its address candidate may migrate.
     * Each incarnation receives a full idle interval before its first probe. */
    if (!state->active || state->path_id != health.path_id ||
        !transport_endpoint_equal(&state->local.sa, &stats.local.sa) ||
        !transport_endpoint_equal(&state->remote.sa, &stats.remote.sa)) {
      *state =
          (transport_probe_state_t){.local = stats.local,
                                    .remote = stats.remote,
                                    .bytes_acked = stats.bytes_acked,
                                    .next_at_ms = next_probe_at(now, interval),
                                    .path_id = health.path_id,
                                    .active = true};
    }

    /* Only ACK-eliciting packets consume native flight/ACKed bytes. Total
     * packet counters include ACK-only replies, which cannot prove liveness.
     * An outstanding flight or native PTO recovery owns its own timer.
     * A negative speculative count can survive a fully ACKed flight. */
    if (stats.bytes_in_flight != 0 || health.pto_count > 0 ||
        stats.bytes_acked != state->bytes_acked) {
      state->bytes_acked = stats.bytes_acked;
      state->next_at_ms = next_probe_at(now, interval);
      if (stats.bytes_in_flight != 0 || health.pto_count > 0)
        continue;
    }

    if (request && state->next_at_ms <= now && now != INT64_MAX) {
      /* Match the native send loop's complete-batch output reservation. A
       * blocked host must not gain an immediately due native control frame. */
      bool room = true;
      for (size_t i = 0; i < t->socket_count && room; i++)
        room = transport_egress_can_accept(&t->sockets[i].egress, 64U,
                                           64U * 1500U);
      if (room)
        (void)quicly_request_path_probe(conn->quic, path);
      /* Requests coalesce in Quicly. A rejected or congestion-blocked request
       * must also wait a full interval before this policy asks again. */
      state->next_at_ms = next_probe_at(now, interval);
    }
    if (state->next_at_ms < deadline)
      deadline = state->next_at_ms;
  }
  return deadline;
}

void transport_probe_tick(transport_conn_t *conn, int64_t now_ms) {
  (void)probe_paths(conn, now_ms, true);
}

int64_t transport_probe_deadline(transport_conn_t *conn, int64_t now_ms) {
  return probe_paths(conn, now_ms, false);
}
