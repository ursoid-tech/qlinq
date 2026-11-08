#include "transport_protocol.h"
#include "transport_recovery.h"

#include "fec.h"
#include "transport_policy_scheduler.h"
#include "transport_publish.h"
#include "transport_repair.h"
#include "transport_stream.h"
#include "transport_tracks.h"
#include "transport_tls.h"
#include "transport_wire.h"

#include "quicly/sendstate.h"
#include "quicly/streambuf.h"

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t local_capabilities(const transport_t *t) {
  uint32_t capabilities =
      QLINQ_WIRE_CAP_RELIABLE | QLINQ_WIRE_CAP_DATAGRAM |
      QLINQ_WIRE_CAP_FEC_REED_SOLOMON | QLINQ_WIRE_CAP_FEC_RATELESS |
      QLINQ_WIRE_CAP_MULTIPATH | QLINQ_WIRE_CAP_AUTHENTICATION |
      QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS | QLINQ_WIRE_CAP_RATELESS_REPAIR |
      QLINQ_WIRE_CAP_RECOVERY_RETIREMENT;
  if (t->flexicast_enabled)
    capabilities |= QLINQ_WIRE_CAP_FLEXICAST_DATAGRAM;
  return capabilities;
}

bool transport_protocol_send_hello(transport_conn_t *conn) {
  if (!transport_tls_application_allowed(conn))
    return false;
  if (!conn || conn->hello_sent || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return conn && conn->hello_sent;
  transport_t *t = conn->transport;
  size_t datagram_size = t->limits.max_udp_payload_size;
  if (datagram_size > UINT16_MAX)
    datagram_size = UINT16_MAX;
  qlinq_wire_hello_t hello = {
      .role = t->is_server ? QLINQ_WIRE_ROLE_SERVER : QLINQ_WIRE_ROLE_CLIENT,
      .max_paths = (uint16_t)t->socket_count,
      .capabilities = local_capabilities(t),
      .max_reliable_object_size = (uint32_t)t->limits.max_reliable_object_size,
      .max_fec_object_size = (uint32_t)t->limits.max_fec_object_size,
      .max_subscriptions = (uint16_t)t->limits.max_subscriptions_per_connection,
      .max_datagram_size = (uint16_t)datagram_size};
  uint8_t payload[QLINQ_WIRE_HELLO_SIZE];
  if (qlinq_wire_encode_hello(payload, sizeof(payload), &hello) !=
          QLINQ_WIRE_OK ||
      !transport_stream_write_frame(conn->stream, QLINQ_WIRE_HELLO, payload,
                                    sizeof(payload)))
    return false;
  conn->hello_sent = true;
  return true;
}

void transport_protocol_maybe_emit_connected(transport_conn_t *conn) {
  if (!conn || conn->connected_emitted || !conn->quic_ready ||
      !conn->protocol_ready || !transport_tls_application_allowed(conn))
    return;
  conn->connected_emitted = true;
  transport_t *t = conn->transport;
  t->stats.protocol_handshakes_completed++;
  if (t->reconnect_in_progress) {
    t->stats.reconnect_succeeded++;
    t->reconnect_in_progress = false;
    t->reconnect_current_delay_ms = t->reconnect_initial_delay_ms;
    transport_log(t, TRANSPORT_LOG_INFO, "connection", conn->id, SIZE_MAX,
                  "reconnect completed");
  }
  transport_event_t event = {.type = TRANSPORT_EVENT_CONNECTED, .conn = conn};
  transport_emit_event(t, &event);
}

static bool receive_hello(transport_conn_t *conn, const uint8_t *payload,
                          size_t payload_len) {
  if (!conn || conn->hello_received)
    return false;
  qlinq_wire_hello_t hello;
  if (qlinq_wire_decode_hello(payload, payload_len, &hello) != QLINQ_WIRE_OK)
    return false;
  transport_t *t = conn->transport;
  uint8_t expected_role =
      t->is_server ? QLINQ_WIRE_ROLE_CLIENT : QLINQ_WIRE_ROLE_SERVER;
  uint32_t required = QLINQ_WIRE_CAP_RELIABLE | QLINQ_WIRE_CAP_DATAGRAM;
  if (hello.role != expected_role ||
      (hello.capabilities & required) != required)
    return false;

  conn->peer_capabilities = hello.capabilities;
  conn->negotiated_limits = t->limits;
  if (conn->negotiated_limits.max_reliable_object_size >
      hello.max_reliable_object_size)
    conn->negotiated_limits.max_reliable_object_size =
        hello.max_reliable_object_size;
  if (conn->negotiated_limits.max_fec_object_size > hello.max_fec_object_size)
    conn->negotiated_limits.max_fec_object_size = hello.max_fec_object_size;
  if (conn->negotiated_limits.max_subscriptions_per_connection >
      hello.max_subscriptions)
    conn->negotiated_limits.max_subscriptions_per_connection =
        hello.max_subscriptions;
  if (conn->negotiated_limits.max_udp_payload_size > hello.max_datagram_size)
    conn->negotiated_limits.max_udp_payload_size = hello.max_datagram_size;
  /* Older peers advertised this ceiling only in HELLO. Keep native probes
   * and packets inside that bound without rewriting their QUIC parameters. */
  if (quicly_set_max_udp_payload_size(
          conn->quic, (uint16_t)conn->negotiated_limits.max_udp_payload_size) !=
      0)
    return false;
  conn->hello_received = true;
  if (!transport_protocol_send_hello(conn))
    return false;
  conn->protocol_ready = true;
  transport_protocol_maybe_emit_connected(conn);
  return true;
}

static bool close_protocol_error(transport_conn_t *conn, const char *reason) {
  conn->transport->stats.protocol_errors++;
  quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL, reason);
  return false;
}

static void close_wire_error(transport_conn_t *conn,
                             qlinq_wire_result_t result) {
  const char *reason = result == QLINQ_WIRE_UNSUPPORTED_VERSION
                           ? "protocol version mismatch"
                           : "protocol error: malformed frame";
  (void)close_protocol_error(conn, reason);
}

static bool repair_request_allowed(transport_conn_t *conn) {
  int64_t now = transport_now_ms(conn->transport);
  conn->transport->stats.repair_requests_received++;
  if (!transport_repair_limiter_take(
          &conn->repair_request_limiter,
          conn->transport->limits.max_repair_requests_per_second, now)) {
    conn->transport->stats.repair_requests_throttled++;
    return false;
  }
  return true;
}

static bool receive_track_command(transport_t *t, transport_conn_t *conn,
                                  uint8_t type, ptls_iovec_t input) {
  qlinq_wire_track_t wire_track;
  if (qlinq_wire_decode_track(input.base, input.len, &wire_track) !=
      QLINQ_WIRE_OK) {
    return close_protocol_error(conn, "protocol error: invalid track");
  }

  if (!conn->authenticated) {
    quicly_close(conn->quic, TRANSPORT_APP_ERROR_AUTHENTICATION,
                 "unauthorized");
    return false;
  }

  uint8_t alias = wire_track.alias;
  uint8_t track_type = wire_track.track_type;
  uint8_t flags = wire_track.flags;
  if (!transport_track_type_valid(track_type) ||
      (flags & ~(MOQ_TRACK_FLAG_RELIABLE | MOQ_TRACK_FLAG_FEC_ENABLED |
                 MOQ_TRACK_FLAG_FEC_RATELESS)) != 0) {
    return close_protocol_error(conn, "protocol error: invalid track");
  }

  moq_track_id_t parsed_track = {.type = (moq_track_type_t)track_type,
                                 .flags = flags};
  strcpy(parsed_track.name, wire_track.name);

  if (type == QLINQ_WIRE_SUBSCRIBE) {
    moq_track_id_t aliased_track;
    if (transport_subscriptions_find_by_alias(&conn->send_subscriptions, alias,
                                              &aliased_track) == 0 &&
        (aliased_track.type != parsed_track.type ||
         strcmp(aliased_track.name, parsed_track.name) != 0)) {
      return close_protocol_error(conn,
                                  "protocol error: track alias collision");
    }
    const track_subscription_t *existing = transport_subscriptions_find_const(
        &conn->send_subscriptions, &parsed_track);
    bool already_same_alias = existing && existing->active &&
                              existing->track_id.flags == flags &&
                              existing->alias == alias;
    if (existing && existing->active && existing->track_id.flags == flags &&
        existing->alias != alias) {
      transport_publish_checkpoint_member_removed(t, conn, &parsed_track,
                                                  existing->alias);
    }
    quicly_debug_printf(
        conn->quic,
        "Subscription mapping: track '%s' (type %d) mapped to alias %d",
        wire_track.name, track_type, alias);
    if (!transport_subscriptions_add(&conn->send_subscriptions,
                                     (moq_track_type_t)track_type, flags,
                                     wire_track.name, alias)) {
      t->stats.resource_limit_errors++;
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                   "protocol error: too many tracks");
      return false;
    }
    if (!transport_flexicast_offer(t, conn, &parsed_track, alias) &&
        !already_same_alias)
      transport_publish_checkpoint_member_added(t, conn, &parsed_track, alias);
  } else if (type == QLINQ_WIRE_UNSUBSCRIBE) {
    transport_flexicast_remove_member(t, conn, &parsed_track);
    transport_publish_checkpoint_member_removed(t, conn, &parsed_track, alias);
    transport_subscriptions_remove(&conn->send_subscriptions,
                                   (moq_track_type_t)track_type,
                                   wire_track.name);
  }

  transport_event_type_t ev_type = TRANSPORT_EVENT_SUBSCRIBE;
  if (type == QLINQ_WIRE_UNSUBSCRIBE) {
    ev_type = TRANSPORT_EVENT_UNSUBSCRIBE;
  } else if (type == QLINQ_WIRE_KEYFRAME_REQUEST) {
    ev_type = TRANSPORT_EVENT_KEYFRAME_REQUEST;
  }

  transport_event_t ev = {
      .type = ev_type, .conn = conn, .track_id = parsed_track};
  transport_emit_event(t, &ev);
  return true;
}

typedef struct {
  transport_publication_path_t native[TRANSPORT_MAX_QUIC_PATHS];
  path_t paths[TRANSPORT_MAX_QUIC_PATHS];
  size_t count;
  size_t capacity[TRANSPORT_MAX_PATHS], queued[TRANSPORT_MAX_PATHS];
} repair_placement_t;

static void collect_repair_paths(transport_conn_t *conn, size_t packet_len,
                                 fp_t horizon, repair_placement_t *plan) {
  memset(plan, 0, sizeof(*plan));
  uint64_t admission_ns = transport_now_ns(conn->transport);
  plan->count = transport_publish_collect_native_paths(
      conn->transport, conn, packet_len, packet_len, admission_ns,
      plan->native);
  for (size_t i = 0; i < plan->count; i++) {
    const transport_publication_path_t *native = &plan->native[i];
    fp_t success = FP_ONE - native->state.p_ewma;
    fp_t usable_b = success > 0 ? FP_MUL(native->state.b_ewma, success) : 0;
    fp_t latency = native->state.l_ewma;
    if (horizon != FP_MAX && !conn->paths[native->physical].state_overridden)
      latency = native->rate_known ? native->sample.l : 0;
    plan->paths[i] = (path_t){.b = usable_b,
                              .l = latency,
                              .p = native->state.p_ewma,
                              .q = native->state.q_ewma};
    size_t capacity =
        horizon == FP_MAX
            ? TRANSPORT_REPAIR_MAX_SYMBOLS
            : transport_publish_path_capacity(conn, native, admission_ns);
    /* Sibling native paths share one admission budget. Taking its maximum
     * usable allowance lets them cooperate without multiplying that budget. */
    if (capacity > plan->capacity[native->physical])
      plan->capacity[native->physical] = capacity;
  }
}

static size_t select_repair_path(const repair_placement_t *plan, fp_t horizon) {
  size_t best = SIZE_MAX, fallback = SIZE_MAX;
  fp_t earliest = FP_MAX;
  for (size_t i = 0; i < plan->count; i++) {
    const transport_publication_path_t *native = &plan->native[i];
    const path_t *path = &plan->paths[i];
    if (path->x >= native->available ||
        plan->queued[native->physical] >= plan->capacity[native->physical])
      continue;
    if (fallback == SIZE_MAX ||
        native->sample.q < plan->native[fallback].sample.q ||
        (native->sample.q == plan->native[fallback].sample.q &&
         native->sample.l < plan->native[fallback].sample.l))
      fallback = i;
    if (path->b <= 0 || path->p >= FP_ONE)
      continue;
    /* Include all work admitted on the shared socket in every sibling's
     * finish estimate, while retaining each native path's RTT and queue. */
    fp_t finish =
        FP_ADD(path->l,
               FP_DIV(FP_ADD(FP_FROM_INT(path->q),
                             FP_FROM_INT(plan->queued[native->physical] + 1U)),
                      path->b));
    if (finish <= horizon && finish < earliest) {
      earliest = finish;
      best = i;
    }
  }
  /* Unbounded repairs retain the legacy fallback when estimates are unusable.
   * A deadline always requires an eligible predicted completion. */
  return best == SIZE_MAX && horizon == FP_MAX ? fallback : best;
}

static size_t queue_repairs(transport_conn_t *conn, uint8_t alias,
                            const sent_object_cache_t *cached,
                            const transport_repair_batch_t *repair,
                            repair_placement_t *plan, fp_t horizon) {
  size_t queued = 0;
  for (size_t i = 0; i < repair->count; i++) {
    size_t slot = select_repair_path(plan, horizon);
    if (slot == SIZE_MAX)
      break;
    size_t path = plan->native[slot].quic;
    uint8_t packet[QLINQ_WIRE_FEC_HEADER_SIZE + QLINQ_FEC_MAX_SYMBOL_SIZE];
    qlinq_wire_fec_header_t header = {.alias = alias,
                                      .is_keyframe = cached->is_keyframe,
                                      .priority = cached->priority,
                                      .path_id = (uint8_t)path,
                                      .group_id = cached->group_id,
                                      .object_id = cached->object_id,
                                      .symbol_index = repair->indices[i],
                                      .total_symbols = repair->total_symbols,
                                      .data_symbols = cached->data_symbols,
                                      .symbol_size = repair->symbol_size,
                                      .original_size = (uint32_t)cached->size,
                                      .send_time_ns =
                                          transport_now_ns(conn->transport)};
    size_t payload_size = qlinq_wire_fec_payload_size(&header);
    size_t wire_len = QLINQ_WIRE_FEC_HEADER_SIZE + payload_size;
    if (payload_size == 0 || wire_len > sizeof(packet) ||
        qlinq_wire_encode_fec_header(packet, wire_len, &header) !=
            QLINQ_WIRE_OK)
      break;
    memcpy(packet + QLINQ_WIRE_FEC_HEADER_SIZE,
           repair->symbols + i * repair->symbol_size, payload_size);
    if (!transport_queue_datagram(conn, path,
                                  ptls_iovec_init(packet, wire_len)))
      break;
    plan->paths[slot].x++;
    size_t physical = plan->native[slot].physical;
    plan->queued[physical]++;
    if (horizon != FP_MAX && !conn->paths[physical].state_overridden)
      transport_path_budget_charge(&conn->paths[physical].budget);
    queued++;
  }
  return queued;
}

static bool receive_nack(transport_t *t, transport_conn_t *conn,
                         ptls_iovec_t input) {
  qlinq_wire_nack_t nack;
  if (qlinq_wire_decode_nack(input.base, input.len, &nack) != QLINQ_WIRE_OK)
    return close_protocol_error(conn, "protocol error: invalid nack");
  if (!conn->authenticated) {
    quicly_close(conn->quic, TRANSPORT_APP_ERROR_AUTHENTICATION,
                 "unauthorized");
    return false;
  }
  if (!repair_request_allowed(conn))
    return true;
  moq_track_id_t track;
  if (transport_subscriptions_find_by_alias(&conn->send_subscriptions,
                                            nack.alias, &track) != 0)
    return true;
  transport_track_profile_t profile = transport_get_track_profile(t, &track);
  bool rateless = (nack.flags & QLINQ_WIRE_NACK_RATELESS) != 0;
  if (rateless &&
      (!profile.fec_rateless ||
       (conn->peer_capabilities & QLINQ_WIRE_CAP_RATELESS_REPAIR) == 0))
    return close_protocol_error(conn, "protocol error: repair mode mismatch");
  if (rateless)
    t->stats.repair_rateless_requests_received++;
  else
    t->stats.repair_indexed_requests_received++;
  if (!profile.reactive_repair) {
    t->stats.repair_cache_misses++;
    if (profile.checkpoint_recovery)
      (void)transport_recovery_send_retire(conn, nack.alias, nack.group_id,
                                           nack.object_id);
    return true;
  }
  int64_t now = transport_now_ms(t);
  sent_object_cache_t *cached = transport_sent_cache_find(
      &t->sent_cache, &track, nack.group_id, nack.object_id);
  if (!cached || (cached->expires_at_ms > 0 && now >= cached->expires_at_ms) ||
      cached->remaining_repair_symbols == 0) {
    t->stats.repair_cache_misses++;
    const transport_checkpoint_ack_state_t *ack =
        transport_checkpoint_ack(conn, nack.alias);
    /* An expired group may be checkpointed without ever allocating source
     * storage. Repeat its terminal response after receiver control pressure,
     * but never retire arbitrary future objects or records predating a join. */
    bool outstanding =
        ack && ack->participating && ack->sent_initialized &&
        ack->sent_group_id == nack.group_id &&
        nack.object_id <= ack->sent_object_id &&
        (!ack->acked_initialized || ack->acked_group_id != nack.group_id ||
         nack.object_id > ack->acked_object_id);
    if (profile.checkpoint_recovery && (cached || outstanding))
      (void)transport_recovery_send_retire(conn, nack.alias, nack.group_id,
                                           nack.object_id);
    return true;
  }

  uint16_t missing[TRANSPORT_REPAIR_MAX_SYMBOLS] = {0};
  size_t missing_count = nack.missing_count;
  if (missing_count > TRANSPORT_REPAIR_MAX_SYMBOLS)
    missing_count = TRANSPORT_REPAIR_MAX_SYMBOLS;
  bool indices_valid = true;
  if (!rateless) {
    for (size_t i = 0; i < missing_count; i++) {
      if (!qlinq_wire_nack_index(&nack, i, &missing[i]) ||
          missing[i] >= QLINQ_FEC_MAX_TOTAL_SYMBOLS) {
        indices_valid = false;
        break;
      }
    }
    if (indices_valid)
      missing_count =
          transport_repair_normalize_indices(missing, missing_count);
  }
  bool whole_object = (nack.flags & QLINQ_WIRE_NACK_WHOLE_OBJECT) != 0;
  if (rateless && whole_object) {
    missing_count = cached->data_symbols;
    if (missing_count > TRANSPORT_REPAIR_MAX_SYMBOLS)
      missing_count = TRANSPORT_REPAIR_MAX_SYMBOLS;
  }
  if (missing_count > cached->remaining_repair_symbols)
    missing_count = cached->remaining_repair_symbols;
  if (!transport_repair_limiter_take(
          &t->aggregate_repair_limiter,
          t->limits.max_aggregate_repair_requests_per_second, now)) {
    t->stats.repair_requests_aggregate_throttled++;
    return true;
  }
  /* charge the request, but avoid encoding when no eligible path can deliver */
  size_t packet_len = QLINQ_WIRE_FEC_HEADER_SIZE + cached->symbol_size;
  fp_t horizon = transport_policy_remaining_horizon(cached->expires_at_ms, now);
  repair_placement_t plan;
  collect_repair_paths(conn, packet_len, horizon, &plan);
  bool can_queue = select_repair_path(&plan, horizon) != SIZE_MAX;
  if (indices_valid && missing_count != 0 && !can_queue) {
    if (rateless && cached->next_repair_symbol >= QLINQ_FEC_MAX_TOTAL_SYMBOLS)
      t->stats.repair_rateless_exhausted++;
    t->stats.repair_queue_failures++;
    return true;
  }

  transport_repair_batch_t repair;
  bool systematic_fallback = false;
  bool built = indices_valid &&
               (rateless ? transport_repair_build_rateless(
                               &t->fec_cache, cached, missing_count, &repair)
                         : transport_repair_build_for_recipient(
                               &t->fec_cache, cached, conn->id, whole_object,
                               missing, missing_count, &repair));
  if (!built && indices_valid && rateless &&
      cached->next_repair_symbol >= QLINQ_FEC_MAX_TOTAL_SYMBOLS) {
    t->stats.repair_rateless_exhausted++;
    built = transport_repair_build_systematic_fallback(&t->fec_cache, cached,
                                                       missing_count, &repair);
    systematic_fallback = built;
  }
  if (!built) {
    t->stats.repair_build_failures++;
    return true;
  }
  if (repair.count > cached->remaining_repair_symbols)
    repair.count = cached->remaining_repair_symbols;

  size_t queued =
      queue_repairs(conn, nack.alias, cached, &repair, &plan, horizon);
  if (queued < repair.count)
    t->stats.repair_queue_failures++;
  if (cached->remaining_repair_symbols != UINT32_MAX) {
    cached->remaining_repair_symbols =
        queued < cached->remaining_repair_symbols
            ? cached->remaining_repair_symbols - (uint32_t)queued
            : 0U;
  }
  if (queued != 0 && rateless) {
    bool committed =
        systematic_fallback
            ? transport_repair_commit_systematic_fallback(cached, &repair,
                                                          queued)
            : transport_repair_commit_rateless(cached, &repair, queued);
    if (!committed)
      t->stats.protocol_errors++;
  }
  t->stats.repair_symbols_sent += queued;
  if (rateless)
    t->stats.repair_rateless_symbols_sent += queued;
  transport_repair_batch_destroy(&repair);
  return true;
}

static bool receive_control_frame(transport_t *t, transport_conn_t *conn,
                                  const qlinq_wire_frame_t *frame) {
  if (!transport_tls_application_allowed(conn))
    return false;
  ptls_iovec_t input = ptls_iovec_init(frame->payload, frame->payload_len);
  switch (frame->type) {
  case QLINQ_WIRE_HELLO: {
    if (conn->stream_frames_received != 1 ||
        !receive_hello(conn, input.base, input.len)) {
      return close_protocol_error(conn, "protocol error: invalid HELLO");
    }
    return true;
  }
  case QLINQ_WIRE_UNICAST: {
    size_t payload_size = input.len;
    if (payload_size > conn->negotiated_limits.max_reliable_object_size) {
      t->stats.resource_limit_errors++;
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                   "protocol error: payload too large");
      return false;
    }

    if (!conn->authenticated) {
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_AUTHENTICATION,
                   "unauthorized");
      return false;
    }

    transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT,
                            .conn = conn,
                            .track_id = {.type = MOQ_TRACK_INPUT},
                            .object = {.track_id = {.type = MOQ_TRACK_INPUT},
                                       .group_id = 0,
                                       .object_id = 0,
                                       .data = input.base,
                                       .size = payload_size,
                                       .is_keyframe = false}};
    transport_emit_event(t, &ev);
    return true;
  }
  case QLINQ_WIRE_AUTH_REQUEST: {
    size_t token_len = input.len;
    if (token_len > UINT16_MAX) {
      t->stats.resource_limit_errors++;
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                   "protocol error: auth token too large");
      return false;
    }

    if (!t->is_server) {
      return close_protocol_error(conn,
                                  "protocol error: unexpected auth request");
    }

    transport_event_t ev = {.type = TRANSPORT_EVENT_AUTH,
                            .conn = conn,
                            .auth = {.token = input.base,
                                     .token_len = token_len,
                                     .success = false}};
    transport_emit_event(t, &ev);
    return true;
  }
  case QLINQ_WIRE_AUTH_RESPONSE: {
    if (input.len != 1 || input.base[0] > 1) {
      return close_protocol_error(conn,
                                  "protocol error: invalid auth response");
    }

    if (t->is_server) {
      return close_protocol_error(conn,
                                  "protocol error: unexpected auth response");
    }

    uint8_t status = input.base[0];
    if (status == 1) {
      conn->authenticated = true;
    }
    transport_event_t ev = {
        .type = TRANSPORT_EVENT_AUTH_COMPLETE,
        .conn = conn,
        .auth = {.token = NULL, .token_len = 0, .success = (status == 1)}};
    transport_emit_event(t, &ev);
    return true;
  }
  case QLINQ_WIRE_TRACK_OBJECT: {
    return close_protocol_error(
        conn, "protocol error: track object on control stream");
  }
  case QLINQ_WIRE_TRACK_CHECKPOINT: {
    qlinq_wire_track_checkpoint_t checkpoint;
    moq_track_id_t resolved_track;
    if (!conn->authenticated ||
        (conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS) == 0 ||
        qlinq_wire_decode_track_checkpoint(input.base, input.len,
                                           &checkpoint) != QLINQ_WIRE_OK ||
        transport_subscriptions_find_by_alias(&conn->receive_subscriptions,
                                              checkpoint.alias,
                                              &resolved_track) != 0 ||
        !transport_get_receive_track_profile(t, &resolved_track)
             .checkpoint_recovery) {
      return close_protocol_error(
          conn, "protocol error: invalid recovery checkpoint");
    }
    const char *reason = transport_recovery_checkpoint(conn, &checkpoint);
    if (reason) {
      return close_protocol_error(conn, reason);
    }
    t->stats.recovery_checkpoints_received++;
    return true;
  }
  case QLINQ_WIRE_TRACK_CHECKPOINT_ACK: {
    qlinq_wire_track_checkpoint_ack_t ack;
    moq_track_id_t resolved_track;
    if (!conn->authenticated ||
        qlinq_wire_decode_track_checkpoint_ack(input.base, input.len, &ack) !=
            QLINQ_WIRE_OK ||
        transport_subscriptions_find_by_alias(
            &conn->send_subscriptions, ack.alias, &resolved_track) != 0 ||
        !transport_get_track_profile(t, &resolved_track).checkpoint_recovery ||
        !transport_publish_checkpoint_acked(t, conn, &ack, &resolved_track)) {
      return close_protocol_error(
          conn, "protocol error: invalid recovery checkpoint ACK");
    }
    t->stats.recovery_checkpoint_acks_received++;
    return true;
  }
  case QLINQ_WIRE_OBJECT_RETIRE:
  case QLINQ_WIRE_OBJECT_RETIRE_ACK: {
    qlinq_wire_object_retire_t retire;
    moq_track_id_t track;
    bool from_sender = frame->type == QLINQ_WIRE_OBJECT_RETIRE;
    if (!conn->authenticated ||
        !(conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_RETIREMENT) ||
        qlinq_wire_decode_object_retire(input.base, input.len, &retire) !=
            QLINQ_WIRE_OK ||
        transport_subscriptions_find_by_alias(from_sender
                                                  ? &conn->receive_subscriptions
                                                  : &conn->send_subscriptions,
                                              retire.alias, &track) != 0)
      return close_protocol_error(conn, "protocol error: invalid retirement");
    transport_track_profile_t profile =
        from_sender ? transport_get_receive_track_profile(t, &track)
                    : transport_get_track_profile(t, &track);
    if (!profile.checkpoint_recovery)
      return close_protocol_error(conn,
                                  "protocol error: invalid retirement track");
    if (from_sender)
      (void)transport_recovery_retire(conn, retire.alias, retire.group_id,
                                      retire.object_id);
    /* RETIRE_ACK explicitly reports failed delivery. Its following cumulative
     * checkpoint ACK releases storage after all recipients are terminal. No
     * successful-delivery event or counter is synthesized for this outcome. */
    return true;
  }
  case QLINQ_WIRE_TRACK_END: {
    qlinq_wire_track_end_t end;
    moq_track_id_t resolved_track;
    if (!conn->authenticated ||
        qlinq_wire_decode_track_end(input.base, input.len, &end) !=
            QLINQ_WIRE_OK ||
        transport_subscriptions_find_by_alias(
            &conn->receive_subscriptions, end.alias, &resolved_track) != 0 ||
        !transport_get_receive_track_profile(t, &resolved_track)
             .checkpoint_recovery) {
      return close_protocol_error(conn,
                                  "protocol error: invalid track completion");
    }

    const char *reason = transport_recovery_finish(conn, &end);
    if (reason) {
      return close_protocol_error(conn, reason);
    }
    t->stats.track_ends_received++;
    return true;
  }
  case QLINQ_WIRE_SUBSCRIBE:
  case QLINQ_WIRE_UNSUBSCRIBE:
  case QLINQ_WIRE_KEYFRAME_REQUEST:
    return receive_track_command(t, conn, frame->type, input);
  case QLINQ_WIRE_NACK:
    return receive_nack(t, conn, input);
  case QLINQ_WIRE_FLEXICAST_BIND: {
    qlinq_wire_flexicast_bind_t bind;
    if (!conn->authenticated ||
        (conn->peer_capabilities & QLINQ_WIRE_CAP_FLEXICAST_DATAGRAM) == 0 ||
        qlinq_wire_decode_flexicast_bind(input.base, input.len, &bind) !=
            QLINQ_WIRE_OK ||
        !transport_flexicast_receive_bind(t, conn, &bind)) {
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                   "protocol error: invalid Flexicast binding");
      return false;
    }
    return true;
  }
  default:
    return close_protocol_error(conn, "protocol error: unexpected frame");
  }
}

/* The dispatcher borrows payload bytes; consume each accepted frame once. */
static void parse_control_messages(transport_t *t, transport_conn_t *conn,
                                   quicly_stream_t *stream) {
  if (!transport_tls_application_allowed(conn))
    return;
  while (true) {
    ptls_iovec_t input = transport_stream_ingress_get(stream);
    if (input.len == 0)
      return;
    qlinq_wire_frame_t frame;
    qlinq_wire_result_t result = qlinq_wire_decode_frame(
        input.base, input.len, TRANSPORT_WIRE_MAX_STREAM_PAYLOAD, &frame);
    if (result == QLINQ_WIRE_NEED_MORE)
      return;
    if (result != QLINQ_WIRE_OK) {
      close_wire_error(conn, result);
      return;
    }
    t->stats.stream_frames_received++;
    conn->stream_frames_received++;
    if (frame.type != QLINQ_WIRE_HELLO && !conn->hello_received) {
      (void)close_protocol_error(conn, "protocol error: HELLO must be first");
      return;
    }
    if (!receive_control_frame(t, conn, &frame))
      return;
    transport_stream_ingress_shift(stream, frame.consumed);
  }
}

static void release_deferred(transport_conn_t *conn, quicly_stream_t *stream) {
  transport_stream_ctx_t *ctx = stream->data;
  if (!ctx->tls_deferred)
    return;
  quicly_stream_t **link = &conn->tls_deferred_head;
  while (*link && *link != stream)
    link = &((transport_stream_ctx_t *)(*link)->data)->tls_deferred_next;
  if (*link)
    *link = ctx->tls_deferred_next;
  conn->tls_deferred_bytes -= ctx->tls_deferred_extent;
  ctx->tls_deferred_extent = 0;
  ctx->tls_deferred_next = NULL;
  ctx->tls_deferred = false;
  conn->tls_deferred = conn->tls_deferred_head != NULL;
}

static void on_stream_destroy(quicly_stream_t *stream, quicly_error_t err) {
  transport_conn_t *conn = *quicly_get_data(stream->conn);
  if (conn) {
    transport_stream_ctx_t *ctx = stream->data;
    if (ctx)
      release_deferred(conn, stream);
    transport_subscriptions_clear_stream(&conn->send_subscriptions, stream);
  }
  transport_stream_destroy(stream, err);
}

static void parse_track_stream_messages(transport_t *t, transport_conn_t *conn,
                                        quicly_stream_t *stream) {
  if (!transport_tls_application_allowed(conn))
    return;
  transport_stream_ctx_t *ctx = (transport_stream_ctx_t *)stream->data;
  ptls_iovec_t input = transport_stream_ingress_get(stream);
  size_t consumed = 0;
  while (consumed < input.len) {
    qlinq_wire_frame_t frame;
    qlinq_wire_result_t result =
        qlinq_wire_decode_frame(input.base + consumed, input.len - consumed,
                                TRANSPORT_WIRE_MAX_STREAM_PAYLOAD, &frame);
    if (result == QLINQ_WIRE_NEED_MORE)
      break;
    if (result != QLINQ_WIRE_OK) {
      close_wire_error(conn, result);
      break;
    }
    t->stats.stream_frames_received++;
    conn->stream_frames_received++;
    if (frame.type != QLINQ_WIRE_TRACK_OBJECT ||
        frame.payload_len < QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE) {
      (void)close_protocol_error(conn,
                                 "protocol error: unexpected track frame");
      break;
    }

    if (!conn->authenticated) {
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_AUTHENTICATION,
                   "unauthorized");
      break;
    }

    qlinq_wire_track_object_t wire_object;
    const uint8_t *object_payload = NULL;
    size_t payload_size = 0;
    if (qlinq_wire_decode_track_object(frame.payload, frame.payload_len,
                                       &wire_object, &object_payload,
                                       &payload_size) != QLINQ_WIRE_OK) {
      (void)close_protocol_error(conn, "protocol error: invalid track object");
      break;
    }
    if (payload_size > conn->negotiated_limits.max_reliable_object_size) {
      t->stats.resource_limit_errors++;
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                   "protocol error: reliable object too large");
      break;
    }
    uint8_t alias = wire_object.alias;
    if (ctx->alias_bound && ctx->alias != alias) {
      (void)close_protocol_error(conn, "protocol error: track alias changed");
      break;
    }
    if (!ctx->alias_bound) {
      ctx->alias = alias;
      ctx->alias_bound = true;
    }

    moq_track_id_t resolved_track = {0};
    if (transport_subscriptions_find_by_alias(&conn->receive_subscriptions,
                                              alias, &resolved_track) == 0) {
      if ((resolved_track.flags & MOQ_TRACK_FLAG_RELIABLE) == 0) {
        (void)close_protocol_error(conn,
                                   "protocol error: stream on datagram track");
        break;
      }
      transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT,
                              .conn = conn,
                              .track_id = resolved_track,
                              .object = {.track_id = resolved_track,
                                         .group_id = wire_object.group_id,
                                         .object_id = wire_object.object_id,
                                         .data = object_payload,
                                         .size = payload_size,
                                         .is_keyframe = wire_object.is_keyframe,
                                         .priority = wire_object.priority}};
      transport_emit_event(t, &ev);
    }

    consumed += frame.consumed;
  }
  /* A repaired gap can release many objects at once. Keep callback payloads
   * borrowed until dispatch returns, then compact the unconsumed tail once. */
  if (consumed != 0)
    transport_stream_ingress_shift(stream, consumed);
}

/* Pending application input stays in QUIC's ingress buffer, under explicit
 * per-stream and per-connection bounds. ACK/CRYPTO processing is unaffected. */
static void dispatch_stream(transport_conn_t *conn, quicly_stream_t *stream) {
  transport_stream_ctx_t *ctx = stream->data;
  release_deferred(conn, stream);
  if (ctx->is_control)
    parse_control_messages(conn->transport, conn, stream);
  else
    parse_track_stream_messages(conn->transport, conn, stream);
}

void transport_protocol_resume_deferred(transport_conn_t *conn) {
  if (!conn->tls_deferred || !transport_tls_application_allowed(conn))
    return;
  /* Pop owned stream entries rather than walking Quicly's mutable hash table:
   * application callbacks can open/reset streams while controls are replayed.
   */
  if (conn->stream &&
      ((transport_stream_ctx_t *)conn->stream->data)->tls_deferred)
    dispatch_stream(conn, conn->stream);
  while (conn->tls_deferred_head && transport_tls_application_allowed(conn))
    dispatch_stream(conn, conn->tls_deferred_head);
}

static void on_receive(quicly_stream_t *stream, size_t off, const void *src,
                       size_t len) {
  transport_conn_t *conn = *quicly_get_data(stream->conn);
  if (!conn)
    return;
  bool allowed = transport_tls_application_allowed(conn);
  if (!allowed) {
    if (len == 0 || conn->tls.exchange == QLINQ_TLS_EXCHANGE_REJECTED)
      return;
    transport_stream_ctx_t *ctx = stream->data;
    enum {
      STREAM_PENDING_MAX = 64 * 1024,
      CONNECTION_PENDING_MAX = 256 * 1024
    };
    if (off > STREAM_PENDING_MAX || len > STREAM_PENDING_MAX - off) {
      conn->transport->stats.resource_limit_errors++;
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                   "pending TLS stream bound exceeded");
      return;
    }
    size_t extent = off + len > ctx->tls_deferred_extent
                        ? off + len
                        : ctx->tls_deferred_extent;
    size_t growth = extent - ctx->tls_deferred_extent;
    if (growth > CONNECTION_PENDING_MAX - conn->tls_deferred_bytes) {
      conn->transport->stats.resource_limit_errors++;
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                   "pending TLS connection bound exceeded");
      return;
    }
    if (!ctx->tls_deferred) {
      ctx->tls_deferred_next = conn->tls_deferred_head;
      conn->tls_deferred_head = stream;
    }
    ctx->tls_deferred = conn->tls_deferred = true;
    conn->tls_deferred_bytes += growth;
    ctx->tls_deferred_extent = extent;
  }
  if (transport_stream_ingress_receive(stream, off, src, len) != 0 || !allowed)
    return;
  dispatch_stream(conn, stream);
}

static void on_stop_sending(quicly_stream_t *stream, quicly_error_t err) {
  transport_stream_ctx_t *ctx = (transport_stream_ctx_t *)stream->data;
  if (ctx && ctx->is_control) {
    quicly_close(stream->conn, 0, "");
  } else {
    quicly_reset_stream(stream, err);
  }
}

static void on_receive_reset(quicly_stream_t *stream, quicly_error_t err) {
  transport_stream_ctx_t *ctx = (transport_stream_ctx_t *)stream->data;
  if (ctx && ctx->is_control) {
    quicly_close(stream->conn, 0, "");
  } else {
    quicly_reset_stream(stream, err);
  }
}

static quicly_error_t on_stream_open(quicly_stream_open_t *self,
                                     quicly_stream_t *stream) {
  (void)self;
  static const quicly_stream_callbacks_t stream_callbacks = {
      on_stream_destroy,
      transport_stream_egress_shift,
      transport_stream_egress_emit,
      on_stop_sending,
      on_receive,
      on_receive_reset};
  int ret;

  if ((ret = quicly_streambuf_create(stream, sizeof(transport_stream_ctx_t))) !=
      0)
    return ret;
  stream->callbacks = &stream_callbacks;

  transport_stream_ctx_t *ctx = (transport_stream_ctx_t *)stream->data;
  ctx->owner = NULL;
  ctx->retained_frame_bytes = 0;
  ctx->tls_deferred = false;
  ctx->tls_deferred_next = NULL;
  ctx->tls_deferred_extent = 0;
  ctx->is_control = (stream->stream_id == 0);
  ctx->alias_bound = false;

  /* client saves the stream pointer */
  transport_conn_t *conn = *quicly_get_data(stream->conn);
  if (conn && ctx->is_control) {
    conn->stream = stream;
  }

  return 0;
}

static bool completed_contains(const transport_conn_t *conn, uint8_t alias,
                               uint64_t generation, uint64_t group_id,
                               uint64_t object_id) {
  size_t bucket = transport_receive_bucket(alias, group_id, object_id);
  for (uint16_t ref = conn->completed_buckets[bucket]; ref != 0;) {
    size_t i = ref - 1U;
    ref = conn->completed_objects[i].hash_next;
    if (conn->completed_objects[i].active &&
        conn->completed_objects[i].alias == alias &&
        conn->completed_objects[i].generation == generation &&
        conn->completed_objects[i].group_id == group_id &&
        conn->completed_objects[i].object_id == object_id)
      return true;
  }
  return false;
}

static void completed_remember(transport_conn_t *conn, uint8_t alias,
                               uint64_t generation, uint64_t group_id,
                               uint64_t object_id) {
  size_t completed = conn->completed_cursor;
  conn->completed_cursor = (completed + 1U) % QLINQ_COMPLETED_OBJECTS;
  if (conn->completed_objects[completed].active) {
    size_t bucket =
        transport_receive_bucket(conn->completed_objects[completed].alias,
                                 conn->completed_objects[completed].group_id,
                                 conn->completed_objects[completed].object_id);
    uint16_t *link = &conn->completed_buckets[bucket];
    while (*link != 0 && *link != completed + 1U)
      link = &conn->completed_objects[*link - 1U].hash_next;
    if (*link != 0)
      *link = conn->completed_objects[completed].hash_next;
  }
  size_t bucket = transport_receive_bucket(alias, group_id, object_id);
  conn->completed_objects[completed].hash_next =
      conn->completed_buckets[bucket];
  conn->completed_buckets[bucket] = (uint16_t)(completed + 1U);
  conn->completed_objects[completed].active = true;
  conn->completed_objects[completed].alias = alias;
  conn->completed_objects[completed].generation = generation;
  conn->completed_objects[completed].group_id = group_id;
  conn->completed_objects[completed].object_id = object_id;
}

void transport_protocol_receive_datagram(transport_conn_t *tconn,
                                         ptls_iovec_t payload,
                                         bool allow_telemetry) {
  if (!tconn)
    return;

  transport_t *t = tconn->transport;
  t->stats.datagrams_received++;
  tconn->datagrams_received++;
  if (!transport_tls_application_allowed(tconn) || !tconn->authenticated)
    return;

  uint8_t datagram_type;
  qlinq_wire_result_t wire_result = qlinq_wire_decode_datagram_type(
      payload.base, payload.len, &datagram_type);
  if (wire_result != QLINQ_WIRE_OK)
    goto malformed_datagram;

  if (datagram_type == QLINQ_WIRE_DATAGRAM_TELEMETRY) {
    if (!allow_telemetry)
      return;
    qlinq_wire_telemetry_t telemetry;
    if (qlinq_wire_decode_telemetry(payload.base, payload.len, &telemetry) !=
        QLINQ_WIRE_OK)
      goto malformed_datagram;
    /* The wire carries a QUIC path index, while scheduling state follows
     * physical sockets (which can be compacted after interface removal). */
    size_t pid = SIZE_MAX;
    quicly_path_stats_t path;
    if (quicly_get_path_stats(tconn->quic, telemetry.path_id, &path) == 0 &&
        quicly_is_path_available(tconn->quic, telemetry.path_id)) {
      for (size_t i = 0; i < t->socket_count; i++) {
        if (transport_path_matches_local(&path, &t->sockets[i].local_addr)) {
          pid = i;
          break;
        }
      }
    }
    if (pid == SIZE_MAX)
      return; /* A delayed reply may refer to a retired path. */
    uint64_t s_ns = telemetry.send_time_ns, r_ns = telemetry.recv_time_ns;
    if (s_ns > INT64_MAX || r_ns > INT64_MAX)
      goto malformed_datagram;
    transport_conn_path_t *physical = &tconn->paths[pid];
    if (physical->owd_initialized &&
        physical->telemetry_path == telemetry.path_id &&
        s_ns <= physical->last_telemetry_s_ns)
      return; /* Do not let reordered replies move a newer baseline. */

    /* Both operands are nonnegative signed values, so their difference fits.
     * Subtract the baseline as unsigned to represent the full possible span. */
    int64_t current = (int64_t)r_ns - (int64_t)s_ns;
    uint64_t relative = 0;
    if (!physical->owd_initialized ||
        physical->telemetry_path != telemetry.path_id ||
        current < physical->min_owd_ns) {
      physical->min_owd_ns = current;
    } else {
      relative = (uint64_t)current - (uint64_t)physical->min_owd_ns;
      /* Beyond ten seconds this is not a useful queue-delay sample. Treat it
       * as a clock discontinuity and establish a fresh baseline. */
      if (relative > UINT64_C(10000000000)) {
        physical->min_owd_ns = current;
        relative = 0;
      }
    }
    physical->owd_initialized = true;
    physical->telemetry_path = telemetry.path_id;
    physical->latest_owd_fp = FP_FROM_INT(relative / 1000U) / 1000000;
    physical->last_telemetry_s_ns = s_ns;
    return;
  }

  qlinq_wire_fec_header_t hdr;
  if (qlinq_wire_decode_fec_header(payload.base, payload.len, &hdr) !=
      QLINQ_WIRE_OK)
    goto malformed_datagram;

  uint8_t track_id = hdr.alias;
  moq_track_id_t resolved_track;
  if (transport_subscriptions_find_by_alias(&tconn->receive_subscriptions,
                                            track_id, &resolved_track) != 0) {
    return;
  }

  if ((resolved_track.flags & MOQ_TRACK_FLAG_RELIABLE) != 0) {
    (void)close_protocol_error(tconn,
                               "protocol error: datagram on reliable track");
    return;
  }

  uint8_t is_keyframe = hdr.is_keyframe;
  uint64_t group_id = hdr.group_id;
  uint64_t object_id = hdr.object_id;
  uint16_t symbol_index = hdr.symbol_index;
  uint16_t total_symbols = hdr.total_symbols;
  uint16_t data_symbols = hdr.data_symbols;
  uint16_t symbol_size = hdr.symbol_size;
  uint32_t original_size = hdr.original_size;

  size_t payload_size = qlinq_wire_fec_payload_size(&hdr);
  if (payload_size == 0 || total_symbols > QLINQ_FEC_MAX_TOTAL_SYMBOLS ||
      symbol_size > QLINQ_FEC_MAX_SYMBOL_SIZE ||
      original_size > tconn->negotiated_limits.max_fec_object_size ||
      payload.len != QLINQ_WIRE_FEC_HEADER_SIZE + payload_size)
    goto malformed_datagram;

  /* The echoed ID belongs to the sender, never to our local path table.
   * Bound feedback per wire path, and reserve queue space for application data.
   */
  uint64_t now_ns = transport_now_ns(t);
  if (allow_telemetry && hdr.path_id < TRANSPORT_MAX_QUIC_PATHS &&
      now_ns >= tconn->telemetry_reply_at_ns[hdr.path_id]) {
    tconn->telemetry_reply_at_ns[hdr.path_id] = now_ns + 10000000U;
    size_t reply_path = transport_select_datagram_path_for_size(
        tconn, QLINQ_WIRE_TELEMETRY_SIZE);
    if (reply_path != SIZE_MAX &&
        quicly_get_num_datagram_frames_path(tconn->quic, reply_path) <
            quicly_get_max_datagram_frames_path(tconn->quic, reply_path) / 2) {
      uint8_t reply[QLINQ_WIRE_TELEMETRY_SIZE];
      qlinq_wire_telemetry_t telemetry = {.path_id = hdr.path_id,
                                          .send_time_ns = hdr.send_time_ns,
                                          .recv_time_ns = now_ns};
      if (qlinq_wire_encode_telemetry(reply, sizeof(reply), &telemetry) ==
          QLINQ_WIRE_OK)
        (void)transport_queue_datagram(tconn, reply_path,
                                       ptls_iovec_init(reply, sizeof(reply)));
    }
  }

  transport_track_profile_t profile =
      transport_get_receive_track_profile(t, &resolved_track);
  bool rateless = profile.fec_rateless;
  bool rateless_data = profile.checkpoint_recovery;
  transport_subscription_state_t *subscription_state =
      transport_subscriptions_get_state(&tconn->receive_subscriptions,
                                        track_id);
  if (!subscription_state)
    return;
  uint64_t generation = subscription_state->generation;
  transport_object_gap_state_t *object_state = &subscription_state->object_gap;
  transport_assembler_observe_receive(tconn, symbol_size);
  if (completed_contains(tconn, track_id, generation, group_id, object_id)) {
    t->stats.fec_duplicate_objects_suppressed++;
    return;
  }
  if (rateless_data &&
      (transport_recovery_was_delivered(object_state, object_id) ||
       transport_recovery_was_retired(object_state, object_id))) {
    t->stats.fec_duplicate_objects_suppressed++;
    return;
  }

  if (rateless_data)
    transport_recovery_observe_at(object_state, transport_now_ms(t), group_id,
                                  object_id);

  frame_assembler_t *asm_slot =
      transport_find_assembler(tconn, track_id, group_id, object_id);
  if (asm_slot && (asm_slot->symbol_size != symbol_size ||
                   asm_slot->data_symbols != data_symbols ||
                   asm_slot->original_size != original_size ||
                   (!rateless && asm_slot->total_symbols != total_symbols)))
    goto malformed_datagram;

  if (!asm_slot) {
    /* Completed small records leave reusable slots behind. Do not evict a
     * still-assembling image merely because the round-robin cursor wrapped
     * after several chat/PLI records. If every slot is occupied, evict the
     * object that has gone longest without a new symbol. Ring order reflects
     * slot reuse, not progress; it can otherwise discard a fresh object while
     * retaining old incomplete objects whose remaining symbols never arrive.
     * Equal timestamps retain the rotating cursor's tie-breaking order. */
    size_t assembler_limit =
        transport_assembler_window(tconn, total_symbols, symbol_size);
    size_t selected = tconn->assembler_index % assembler_limit;
    for (size_t offset = 0; offset < assembler_limit; offset++) {
      size_t index = (tconn->assembler_index + offset) % assembler_limit;
      if (tconn->assemblers[index].total_symbols == 0) {
        selected = index;
        break;
      }
      if (tconn->assemblers[index].last_activity_time_ms <
          tconn->assemblers[selected].last_activity_time_ms)
        selected = index;
    }
    tconn->assembler_index = selected;
    asm_slot = &tconn->assemblers[tconn->assembler_index];
    tconn->assembler_index = (tconn->assembler_index + 1) % assembler_limit;

    transport_unindex_assembler(asm_slot);
    if (asm_slot->total_symbols > 0) {
      uint8_t evicted_alias = asm_slot->track_id;
      uint64_t evicted_group = asm_slot->group_id;
      uint64_t evicted_object = asm_slot->object_id;
      asm_slot->total_symbols = 0;
      moq_track_id_t evicted_track;
      if (transport_subscriptions_find_by_alias(&tconn->receive_subscriptions,
                                                evicted_alias,
                                                &evicted_track) == 0) {
        transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT_LOST,
                                .conn = tconn,
                                .track_id = evicted_track,
                                .object = {.track_id = evicted_track,
                                           .group_id = evicted_group,
                                           .object_id = evicted_object}};
        t->stats.fec_objects_lost++;
        transport_emit_event(tconn->transport, &ev);
        /* A loss callback may unsubscribe and reuse this alias. Never retain
         * state across that boundary without checking its lifetime. */
        subscription_state = transport_subscriptions_get_state(
            &tconn->receive_subscriptions, track_id);
        if (!subscription_state ||
            subscription_state->generation != generation ||
            quicly_get_state(tconn->quic) >= QUICLY_STATE_CLOSING) {
          transport_release_assembler(t, asm_slot);
          return;
        }
        object_state = &subscription_state->object_gap;
      }
    }

    if (!asm_slot->buffers || asm_slot->capacity_symbols < total_symbols ||
        asm_slot->capacity_symbol_size < symbol_size) {
      transport_release_assembler(t, asm_slot);
      if (!transport_grow_assembler(t, asm_slot, total_symbols, symbol_size)) {
        transport_release_assembler(t, asm_slot);
        return;
      }
    }

    memset(asm_slot->received_mask, 0,
           asm_slot->capacity_symbols * sizeof(bool));
    asm_slot->track_id = track_id;
    asm_slot->group_id = group_id;
    asm_slot->object_id = object_id;
    asm_slot->total_symbols = total_symbols;
    asm_slot->data_symbols = data_symbols;
    asm_slot->symbol_size = symbol_size;
    asm_slot->original_size = original_size;
    asm_slot->priority = hdr.priority;
    asm_slot->received_count = 0;
    asm_slot->nack_sent = false;
    asm_slot->first_symbol_time_ms = transport_now_ms(t);
    asm_slot->last_activity_time_ms = asm_slot->first_symbol_time_ms;
    transport_index_assembler(tconn, asm_slot);
  }

  if (rateless && total_symbols > asm_slot->total_symbols) {
    if (!transport_grow_assembler(t, asm_slot, total_symbols, symbol_size)) {
      return;
    }
    asm_slot->total_symbols = total_symbols;
  }

  total_symbols = asm_slot->total_symbols;
  data_symbols = asm_slot->data_symbols;
  symbol_size = asm_slot->symbol_size;
  original_size = asm_slot->original_size;

  if (symbol_index >= asm_slot->total_symbols)
    return;

  if (!asm_slot->received_mask[symbol_index]) {
    memcpy(asm_slot->buffers[symbol_index],
           payload.base + QLINQ_WIRE_FEC_HEADER_SIZE, payload_size);
    /* zero any omitted source tail before FEC decoding */
    memset(asm_slot->buffers[symbol_index] + payload_size, 0,
           symbol_size - payload_size);
    asm_slot->received_mask[symbol_index] = true;
    asm_slot->received_count++;
    asm_slot->last_activity_time_ms = transport_now_ms(t);
  }

  if (asm_slot->received_count >= data_symbols) {
    bool got_all_data = true;
    for (size_t i = 0; i < data_symbols; i++) {
      if (!asm_slot->received_mask[i]) {
        got_all_data = false;
        break;
      }
    }

    bool success = false;
    if (got_all_data) {
      success = true;
    } else {
      size_t parity_symbols = total_symbols - data_symbols;
      if (parity_symbols > 0) {
        /* Match the sender's codec for every content type. DATA alone uses
         * the additional gap tracking and recovery-checkpoint machinery. */
        fec_type_t fec_type = fec_select_type(rateless, total_symbols);
        fec_t *fec = transport_fec_cache_get(
            &t->fec_cache, fec_type, data_symbols, parity_symbols, symbol_size);
        if (fec) {
          for (size_t i = 0; i < total_symbols; i++) {
            asm_slot->missing_mask[i] = !asm_slot->received_mask[i];
          }
          success = fec_decode(fec, asm_slot->buffers, asm_slot->missing_mask);
        }
      }
    }

    if (success) {
      /* Reused slots may have a wider stride. Compact toward the start;
       * each destination ends before the next source block begins. */
      uint8_t *full_data = asm_slot->buffer_storage;
      size_t bytes_left = original_size;
      for (size_t i = 0; i < data_symbols; i++) {
        size_t chunk = (bytes_left < symbol_size) ? bytes_left : symbol_size;
        if (chunk > 0) {
          if (full_data + i * symbol_size != asm_slot->buffers[i])
            memmove(full_data + i * symbol_size, asm_slot->buffers[i], chunk);
          bytes_left -= chunk;
        }
      }

      /* Preserve the negotiated identity for every datagram delivery mode. */
      transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT,
                              .conn = tconn,
                              .track_id = resolved_track,
                              .object = {.track_id = resolved_track,
                                         .group_id = group_id,
                                         .object_id = object_id,
                                         .data = full_data,
                                         .size = original_size,
                                         .is_keyframe = (is_keyframe != 0),
                                         .priority = asm_slot->priority}};
      /* Completing a recovery window can retire this assembler while queuing
       * its checkpoint ACK. Detach the payload before that bookkeeping, and
       * retain it through the callback (which may itself unsubscribe). */
      asm_slot->buffer_storage = NULL;
      transport_release_assembler(t, asm_slot);
      completed_remember(tconn, track_id, generation, group_id, object_id);
      if (rateless_data) {
        transport_recovery_delivered(tconn, track_id, group_id, object_id);
      }
      t->stats.fec_objects_recovered++;
      if (!got_all_data)
        t->stats.fec_objects_decoded++;
      transport_emit_event(t, &ev);
      free(full_data);
    }
  }
  return;

malformed_datagram:
  t->stats.malformed_datagrams++;
  tconn->malformed_datagrams++;
}

static void on_receive_datagram_frame(quicly_receive_datagram_frame_t *self,
                                      quicly_conn_t *conn,
                                      ptls_iovec_t payload) {
  (void)self;
  transport_protocol_receive_datagram(*quicly_get_data(conn), payload, true);
}

static quicly_error_t
on_receive_flexicast_frame(quicly_receive_flexicast_frame_t *self,
                           quicly_conn_t *conn,
                           const quicly_flexicast_frame_t *frame) {
  (void)self;
  transport_conn_t *tconn = *quicly_get_data(conn);
  if (!tconn || !tconn->authenticated ||
      !transport_flexicast_receive_quic_frame(tconn->transport, tconn, frame))
    return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
  return 0;
}

static quicly_error_t
on_receive_flexicast_ack(quicly_receive_flexicast_ack_t *self,
                         quicly_conn_t *conn, uint64_t flow_id,
                         const quicly_ack_frame_t *ack) {
  (void)self;
  transport_conn_t *tconn = *quicly_get_data(conn);
  if (!tconn || !tconn->authenticated ||
      !transport_flexicast_receive_path_ack(tconn->transport, tconn, flow_id,
                                            ack))
    return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
  return 0;
}

void transport_protocol_setup(transport_t *t) {
  if (!t)
    return;
  t->stream_open.cb = on_stream_open;
  t->receive_datagram.cb = on_receive_datagram_frame;
  t->receive_flexicast.cb = on_receive_flexicast_frame;
  t->receive_flexicast_ack.cb = on_receive_flexicast_ack;
}
