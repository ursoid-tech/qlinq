#include "transport_recovery.h"

#include "transport_internal.h"
#include "transport_stream.h"

#include "quicly/sendstate.h"

#include <limits.h>
#include <string.h>

#define RECOVERY_CONTROL_RETRY_MS 25

bool transport_recovery_was_delivered(const transport_object_gap_state_t *state,
                                      uint64_t object_id) {
  if (!state->delivered_initialized || object_id > state->largest_delivered)
    return false;
  uint64_t distance = state->largest_delivered - object_id;
  if (distance >= QLINQ_RECOVERY_HISTORY_OBJECTS)
    return false;
  return (state->delivered_mask[distance / 64U] &
          (UINT64_C(1) << (distance % 64U))) != 0;
}

bool transport_recovery_was_retired(const transport_object_gap_state_t *state,
                                    uint64_t object_id) {
  if (!state->retired_initialized || object_id > state->largest_retired)
    return false;
  uint64_t distance = state->largest_retired - object_id;
  if (distance >= QLINQ_RECOVERY_HISTORY_OBJECTS)
    return false;
  return (state->retired_mask[distance / 64U] &
          (UINT64_C(1) << (distance % 64U))) != 0;
}

static void sync_gap_group(transport_object_gap_state_t *state,
                           uint64_t group_id) {
  if (!state)
    return;
  if (!state->seen_initialized && !state->delivered_initialized &&
      !state->retired_initialized && state->pending_mask == 0) {
    state->group_id = group_id;
    return;
  }
  if (group_id <= state->group_id)
    return;
  state->last_seen = 0;
  state->seen_initialized = false;
  state->pending_base = 0;
  state->pending_mask = 0;
  state->pending_cursor = 0;
  state->largest_delivered = 0;
  memset(state->delivered_mask, 0, sizeof(state->delivered_mask));
  state->delivered_initialized = false;
  state->largest_retired = 0;
  memset(state->retired_mask, 0, sizeof(state->retired_mask));
  state->retired_initialized = false;
  state->group_id = group_id;
}

bool transport_recovery_is_terminal(const transport_object_gap_state_t *state,
                                    uint64_t group_id, uint64_t object_id) {
  if (!state)
    return false;
  for (size_t i = 0; i < QLINQ_RECOVERY_MAX_WINDOWS; i++) {
    const transport_recovery_window_t *window = &state->recovery_windows[i];
    if (window->active && window->group_id == group_id &&
        object_id >= window->first_object_id &&
        object_id <= window->final_object_id) {
      uint32_t bit = (uint32_t)(object_id - window->first_object_id);
      if ((window->missing_mask & (UINT32_C(1) << bit)) == 0)
        return true;
    }
  }
  if (state->acked_initialized && state->acked_group_id == group_id &&
      object_id <= state->acked_object_id)
    return true;
  if ((state->seen_initialized || state->delivered_initialized ||
       state->retired_initialized || state->pending_mask != 0) &&
      state->group_id == group_id) {
    return transport_recovery_was_delivered(state, object_id) ||
           transport_recovery_was_retired(state, object_id);
  }
  return false;
}

static bool
object_is_recently_delivered(const transport_object_gap_state_t *state,
                             uint64_t object_id) {
  if (!state->delivered_initialized || object_id > state->largest_delivered)
    return false;
  uint64_t distance = state->largest_delivered - object_id;
  return distance < QLINQ_RECOVERY_HISTORY_OBJECTS &&
         (state->delivered_mask[distance / 64U] &
          (UINT64_C(1) << (distance % 64U))) != 0;
}

static bool
object_is_recently_terminal(const transport_object_gap_state_t *state,
                            uint64_t object_id) {
  return object_is_recently_delivered(state, object_id) ||
         (state->retired_initialized && object_id <= state->largest_retired &&
          state->largest_retired - object_id < QLINQ_RECOVERY_HISTORY_OBJECTS &&
          transport_recovery_was_retired(state, object_id));
}

static void mark_object_delivered(transport_object_gap_state_t *state,
                                  uint64_t object_id) {
  if (!state->delivered_initialized) {
    state->delivered_initialized = true;
    state->largest_delivered = object_id;
    state->delivered_mask[0] = 1;
    return;
  }
  if (object_id > state->largest_delivered) {
    uint64_t distance = object_id - state->largest_delivered;
    uint64_t shifted[QLINQ_RECOVERY_HISTORY_OBJECTS / 64U] = {0};
    if (distance < QLINQ_RECOVERY_HISTORY_OBJECTS) {
      size_t word_shift = (size_t)(distance / 64U);
      unsigned bit_shift = (unsigned)(distance % 64U);
      for (size_t dst = QLINQ_RECOVERY_HISTORY_OBJECTS / 64U; dst-- > 0;) {
        if (dst < word_shift)
          continue;
        size_t src = dst - word_shift;
        shifted[dst] = state->delivered_mask[src] << bit_shift;
        if (bit_shift != 0 && src > 0)
          shifted[dst] |= state->delivered_mask[src - 1U] >> (64U - bit_shift);
      }
    }
    memcpy(state->delivered_mask, shifted, sizeof(shifted));
    state->delivered_mask[0] |= 1;
    state->largest_delivered = object_id;
  } else {
    uint64_t distance = state->largest_delivered - object_id;
    if (distance < QLINQ_RECOVERY_HISTORY_OBJECTS)
      state->delivered_mask[distance / 64U] |= UINT64_C(1) << (distance % 64U);
  }
}

static void mark_object_retired(transport_object_gap_state_t *state,
                                uint64_t object_id) {
  /* Use the same bounded history transition while keeping successful delivery
   * and abandonment distinct. Late symbols consult both histories. */
  transport_object_gap_state_t history = {
      .largest_delivered = state->largest_retired,
      .delivered_initialized = state->retired_initialized};
  memcpy(history.delivered_mask, state->retired_mask,
         sizeof(history.delivered_mask));
  mark_object_delivered(&history, object_id);
  state->largest_retired = history.largest_delivered;
  state->retired_initialized = history.delivered_initialized;
  memcpy(state->retired_mask, history.delivered_mask,
         sizeof(state->retired_mask));
}

static bool send_retirement(transport_conn_t *conn, uint8_t type, uint8_t alias,
                            uint64_t group_id, uint64_t object_id) {
  if (!conn || !conn->stream ||
      !(conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_RETIREMENT) ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;
  qlinq_wire_object_retire_t retire = {alias, group_id, object_id};
  uint8_t payload[QLINQ_WIRE_OBJECT_RETIRE_SIZE];
  if (qlinq_wire_encode_object_retire(payload, sizeof(payload), &retire) !=
      QLINQ_WIRE_OK)
    return false;
  if (transport_stream_has_retained_frame(conn->stream, type, payload,
                                          sizeof(payload)))
    return true;
  return transport_stream_can_accept(
             conn->stream, QLINQ_WIRE_FRAME_HEADER_SIZE + sizeof(payload),
             false) &&
         transport_stream_write_frame(conn->stream, type, payload,
                                      sizeof(payload));
}

bool transport_recovery_send_retire(transport_conn_t *conn, uint8_t alias,
                                    uint64_t group_id, uint64_t object_id) {
  return send_retirement(conn, QLINQ_WIRE_OBJECT_RETIRE, alias, group_id,
                         object_id);
}

static void record_acked_watermark(transport_object_gap_state_t *state,
                                   uint64_t group_id,
                                   uint64_t final_object_id) {
  if (!state)
    return;
  if (!state->acked_initialized || group_id > state->acked_group_id ||
      (group_id == state->acked_group_id &&
       final_object_id > state->acked_object_id)) {
    state->acked_initialized = true;
    state->acked_group_id = group_id;
    state->acked_object_id = final_object_id;
  }
}

static bool send_checkpoint_ack(transport_conn_t *conn, uint8_t alias,
                                uint64_t group_id, uint64_t final_object_id) {
  if (!conn ||
      (conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS) == 0 ||
      !conn->stream || !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;
  if (!transport_stream_write_track_checkpoint_ack_frame(
          conn->stream, alias, group_id, final_object_id))
    return false;
  conn->transport->stats.recovery_checkpoint_acks_sent++;
  record_acked_watermark(transport_object_gap(conn, alias), group_id,
                         final_object_id);
  return true;
}

static bool send_or_defer_checkpoint_ack(transport_conn_t *conn, uint8_t alias,
                                         uint64_t group_id,
                                         uint64_t final_object_id) {
  if (!conn ||
      (conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS) == 0 ||
      !conn->stream || !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;
  transport_object_gap_state_t *state = transport_object_gap(conn, alias);
  if (!state)
    return false;
  if (!transport_stream_can_accept(conn->stream,
                                   QLINQ_WIRE_FRAME_HEADER_SIZE +
                                       QLINQ_WIRE_TRACK_CHECKPOINT_ACK_SIZE,
                                   false)) {
    if (!state->ack_pending || group_id > state->pending_ack_group_id ||
        (group_id == state->pending_ack_group_id &&
         final_object_id >= state->pending_ack_object_id)) {
      state->ack_pending = true;
      state->pending_ack_group_id = group_id;
      state->pending_ack_object_id = final_object_id;
    }
    record_acked_watermark(state, group_id, final_object_id);
    return true;
  }
  if (!send_checkpoint_ack(conn, alias, group_id, final_object_id))
    return false;
  if (state->ack_pending && state->pending_ack_group_id == group_id &&
      state->pending_ack_object_id <= final_object_id)
    state->ack_pending = false;
  return true;
}

static transport_recovery_window_t *
find_recovery_window(transport_object_gap_state_t *state, uint64_t group_id,
                     uint64_t first_object_id, uint64_t final_object_id) {
  for (size_t i = 0; i < QLINQ_RECOVERY_MAX_WINDOWS; i++) {
    transport_recovery_window_t *window = &state->recovery_windows[i];
    if (window->active && window->group_id == group_id &&
        window->first_object_id == first_object_id &&
        window->final_object_id == final_object_id)
      return window;
  }
  return NULL;
}

static void retire_recovery_through(transport_conn_t *conn, uint8_t alias,
                                    uint64_t group_id,
                                    uint64_t final_object_id) {
  if (!conn || !conn->transport)
    return;
  transport_t *t = conn->transport;
  transport_object_gap_state_t *gap = transport_object_gap(conn, alias);
  if (gap && gap->pending_mask != 0 && gap->group_id == group_id &&
      gap->pending_base <= final_object_id) {
    uint64_t distance = final_object_id - gap->pending_base;
    uint32_t covered = distance >= 31U
                           ? UINT32_MAX
                           : (UINT32_C(1) << (uint32_t)(distance + 1U)) - 1U;
    gap->pending_mask &= ~covered;
  }
  for (size_t i = transport_next_assembler(conn, 0);
       i < t->limits.max_assemblers_per_connection;
       i = transport_next_assembler(conn, i + 1)) {
    frame_assembler_t *assembler = &conn->assemblers[i];
    if (assembler->total_symbols > 0 && assembler->track_id == alias &&
        assembler->group_id == group_id &&
        assembler->object_id <= final_object_id) {
      transport_release_assembler(t, assembler);
    }
  }
}

static bool acknowledge_completed_recovery_windows(transport_conn_t *conn,
                                                   uint8_t alias) {
  transport_object_gap_state_t *state = transport_object_gap(conn, alias);
  while (true) {
    transport_recovery_window_t *first = NULL;
    for (size_t i = 0; i < QLINQ_RECOVERY_MAX_WINDOWS; i++) {
      transport_recovery_window_t *window = &state->recovery_windows[i];
      if (!window->active ||
          (first && window->first_object_id >= first->first_object_id))
        continue;
      first = window;
    }
    if (!first || first->missing_mask != 0)
      return true;
    uint64_t group_id = first->group_id;
    uint64_t final_object_id = first->final_object_id;
    /* One cumulative ACK covers the completed prefix. Stop at the first
     * incomplete window or different group; never acknowledge across a gap. */
    while (true) {
      transport_recovery_window_t *next = NULL;
      for (size_t i = 0; i < QLINQ_RECOVERY_MAX_WINDOWS; i++) {
        transport_recovery_window_t *window = &state->recovery_windows[i];
        if (!window->active || window->first_object_id <= final_object_id ||
            (next && window->first_object_id >= next->first_object_id))
          continue;
        next = window;
      }
      if (!next || next->missing_mask != 0 || next->group_id != group_id)
        break;
      final_object_id = next->final_object_id;
    }
    if (!conn->stream || !quicly_sendstate_is_open(&conn->stream->sendstate))
      return false;
    /* Keep completed windows until their ACK can be retained. Temporary
     * control pressure must not close the connection or release source data.
     * transport_tick retries independently of the NACK token budget. */
    if (!transport_stream_can_accept(conn->stream,
                                     QLINQ_WIRE_FRAME_HEADER_SIZE +
                                         QLINQ_WIRE_TRACK_CHECKPOINT_ACK_SIZE,
                                     false))
      return true;
    if (!send_checkpoint_ack(conn, alias, group_id, final_object_id))
      return false;
    retire_recovery_through(conn, alias, group_id, final_object_id);
    for (size_t i = 0; i < QLINQ_RECOVERY_MAX_WINDOWS; i++) {
      transport_recovery_window_t *window = &state->recovery_windows[i];
      if (window->active && window->group_id == group_id &&
          window->final_object_id <= final_object_id)
        memset(window, 0, sizeof(*window));
    }
  }
}

bool transport_recovery_retire(transport_conn_t *conn, uint8_t alias,
                               uint64_t group_id, uint64_t object_id) {
  moq_track_id_t track;
  if (!conn || transport_subscriptions_find_by_alias(
                   &conn->receive_subscriptions, alias, &track) != 0)
    return false;
  transport_object_gap_state_t *state = transport_object_gap(conn, alias);
  bool terminal = transport_recovery_is_terminal(state, group_id, object_id);
  if (!terminal) {
    /* admit the explicit failed outcome before the cumulative checkpoint ACK */
    if (!send_retirement(conn, QLINQ_WIRE_OBJECT_RETIRE_ACK, alias, group_id,
                         object_id))
      return false;
    sync_gap_group(state, group_id);
    mark_object_retired(state, object_id);
  }
  /* reconcile stale missing state even for an already terminal object */
  if (state->group_id == group_id && object_id >= state->pending_base &&
      object_id - state->pending_base < 32)
    state->pending_mask &= ~(UINT32_C(1) << (object_id - state->pending_base));
  for (size_t i = 0; i < QLINQ_RECOVERY_MAX_WINDOWS; i++) {
    transport_recovery_window_t *window = &state->recovery_windows[i];
    if (window->active && window->group_id == group_id &&
        object_id >= window->first_object_id &&
        object_id <= window->final_object_id)
      window->missing_mask &=
          ~(UINT32_C(1) << (object_id - window->first_object_id));
  }
  frame_assembler_t *assembler =
      transport_find_assembler(conn, alias, group_id, object_id);
  if (assembler)
    transport_release_assembler(conn->transport, assembler);
  (void)acknowledge_completed_recovery_windows(conn, alias);
  if (terminal)
    return true;
  transport_event_t event = {.type = TRANSPORT_EVENT_OBJECT_LOST,
                             .conn = conn,
                             .track_id = track,
                             .object = {.track_id = track,
                                        .group_id = group_id,
                                        .object_id = object_id}};
  conn->transport->stats.fec_objects_lost++;
  transport_emit_event(conn->transport, &event);
  return true;
}

void transport_recovery_flush_acks(transport_conn_t *conn) {
  if (!conn || !conn->authenticated || !conn->stream ||
      quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
    return;
  for (size_t i = 0; i < conn->receive_subscriptions.capacity; i++) {
    const track_subscription_t *sub = &conn->receive_subscriptions.entries[i];
    if (!sub->active ||
        !transport_get_receive_track_profile(conn->transport, &sub->track_id)
             .checkpoint_recovery)
      continue;
    transport_object_gap_state_t *gap = transport_object_gap(conn, sub->alias);
    if (gap && gap->ack_pending &&
        transport_stream_can_accept(conn->stream,
                                    QLINQ_WIRE_FRAME_HEADER_SIZE +
                                        QLINQ_WIRE_TRACK_CHECKPOINT_ACK_SIZE,
                                    false)) {
      if (send_checkpoint_ack(conn, sub->alias, gap->pending_ack_group_id,
                              gap->pending_ack_object_id))
        gap->ack_pending = false;
    }
    (void)acknowledge_completed_recovery_windows(conn, sub->alias);
  }
}

static bool receive_recovery_checkpoint(transport_conn_t *conn, uint8_t alias,
                                        uint64_t group_id,
                                        uint64_t first_object_id,
                                        uint64_t final_object_id,
                                        bool acknowledge) {
  if (!conn || first_object_id > final_object_id ||
      final_object_id - first_object_id >= QLINQ_RECOVERY_WINDOW_OBJECTS)
    return false;
  transport_object_gap_state_t *state = transport_object_gap(conn, alias);
  if (find_recovery_window(state, group_id, first_object_id, final_object_id))
    return true;

  if (state->checkpoint_initialized) {
    if (final_object_id <= state->last_checkpoint_object_id)
      return !acknowledge || send_or_defer_checkpoint_ack(conn, alias, group_id,
                                                          final_object_id);
    if (state->last_checkpoint_object_id == UINT64_MAX ||
        first_object_id != state->last_checkpoint_object_id + 1U)
      return false;
  }

  transport_recovery_window_t *window = NULL;
  for (size_t i = 0; i < QLINQ_RECOVERY_MAX_WINDOWS; i++) {
    if (!state->recovery_windows[i].active) {
      window = &state->recovery_windows[i];
      break;
    }
  }
  if (!window)
    return false;

  memset(window, 0, sizeof(*window));
  window->group_id = group_id;
  window->first_object_id = first_object_id;
  window->final_object_id = final_object_id;
  window->created_at_ms = transport_now_ms(conn->transport);
  uint32_t count = (uint32_t)(final_object_id - first_object_id + 1U);
  bool same_group =
      (state->delivered_initialized || state->retired_initialized) &&
      state->group_id == group_id;
  for (uint32_t bit = 0; bit < count; bit++)
    if (!same_group ||
        !object_is_recently_terminal(state, first_object_id + bit))
      window->missing_mask |= 1U << bit;

  state->checkpoint_initialized = true;
  state->last_checkpoint_object_id = final_object_id;
  window->active = true;
  if (!acknowledge) {
    if (window->missing_mask == 0)
      memset(window, 0, sizeof(*window));
    return true;
  }
  return acknowledge_completed_recovery_windows(conn, alias);
}

void transport_recovery_delivered(transport_conn_t *conn, uint8_t alias,
                                  uint64_t group_id, uint64_t object_id) {
  transport_object_gap_state_t *state = transport_object_gap(conn, alias);
  sync_gap_group(state, group_id);
  mark_object_delivered(state, object_id);
  for (size_t i = 0; i < QLINQ_RECOVERY_MAX_WINDOWS; i++) {
    transport_recovery_window_t *window = &state->recovery_windows[i];
    if (!window->active || window->group_id != group_id ||
        object_id < window->first_object_id ||
        object_id > window->final_object_id)
      continue;
    window->missing_mask &=
        ~(1U << (uint32_t)(object_id - window->first_object_id));
  }
  (void)acknowledge_completed_recovery_windows(conn, alias);
}

static bool queue_missing_objects(transport_object_gap_state_t *state,
                                  int64_t now_ms, uint64_t group_id,
                                  uint64_t first_missing,
                                  uint64_t missing_count) {
  if (!state || missing_count == 0)
    return true;
  if (missing_count > 32)
    return false;
  if (state->pending_mask == 0) {
    state->pending_base = first_missing;
    state->pending_cursor = 0;
    state->detected_at_ms = now_ms;
    state->first_missing_at_ms = now_ms;
    state->group_id = group_id;
  }
  if (first_missing < state->pending_base ||
      first_missing - state->pending_base >= 32)
    return false;
  uint32_t offset = (uint32_t)(first_missing - state->pending_base);
  uint32_t available = 32 - offset;
  uint32_t count =
      missing_count < available ? (uint32_t)missing_count : available;
  for (uint32_t bit = 0; bit < count; bit++) {
    uint64_t object_id = first_missing + bit;
    if (!transport_recovery_was_delivered(state, object_id) &&
        !transport_recovery_was_retired(state, object_id))
      state->pending_mask |= UINT32_C(1) << (offset + bit);
  }
  return count == missing_count;
}

void transport_recovery_observe_at(transport_object_gap_state_t *gap,
                                   int64_t now_ms, uint64_t group_id,
                                   uint64_t object_id) {
  sync_gap_group(gap, group_id);
  if (group_id < gap->group_id)
    return;
  if (!gap->seen_initialized) {
    gap->seen_initialized = true;
    gap->last_seen = object_id;
  } else if (object_id > gap->last_seen) {
    if (object_id - gap->last_seen > 1) {
      uint64_t first_missing = gap->last_seen + 1;
      uint64_t missing_count = object_id - first_missing;
      (void)queue_missing_objects(gap, now_ms, group_id, first_missing,
                                  missing_count);
    }
    gap->last_seen = object_id;
  } else if (gap->pending_mask != 0 && object_id >= gap->pending_base &&
             object_id - gap->pending_base < 32) {
    gap->pending_mask &= ~(1U << (object_id - gap->pending_base));
  }
}

const char *
transport_recovery_checkpoint(transport_conn_t *conn,
                              const qlinq_wire_track_checkpoint_t *checkpoint) {
  if ((checkpoint->flags & QLINQ_WIRE_CHECKPOINT_BASELINE) != 0) {
    transport_object_gap_state_t *gap =
        transport_object_gap(conn, checkpoint->alias);
    if (checkpoint->first_object_id != checkpoint->final_object_id ||
        (gap->checkpoint_initialized &&
         checkpoint->final_object_id < gap->last_checkpoint_object_id) ||
        !send_or_defer_checkpoint_ack(conn, checkpoint->alias,
                                      checkpoint->group_id,
                                      checkpoint->final_object_id))
      return "protocol error: invalid recovery baseline";
    gap->checkpoint_initialized = true;
    gap->last_checkpoint_object_id = checkpoint->final_object_id;
  } else if (!receive_recovery_checkpoint(conn, checkpoint->alias,
                                          checkpoint->group_id,
                                          checkpoint->first_object_id,
                                          checkpoint->final_object_id, true)) {
    return "protocol error: invalid recovery checkpoint window";
  }
  return NULL;
}

const char *transport_recovery_finish(transport_conn_t *conn,
                                      const qlinq_wire_track_end_t *end) {
  transport_object_gap_state_t *gap = transport_object_gap(conn, end->alias);
  bool acknowledge =
      (conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS) != 0;
  uint64_t first_object_id;
  if (acknowledge && gap->checkpoint_initialized) {
    if (end->final_object_id <= gap->last_checkpoint_object_id) {
      bool outstanding = false;
      for (size_t i = 0; i < QLINQ_RECOVERY_MAX_WINDOWS; i++)
        outstanding |= gap->recovery_windows[i].active;
      if (!outstanding) {
        if (!send_or_defer_checkpoint_ack(conn, end->alias, end->group_id,
                                          end->final_object_id))
          return "protocol error: completion ACK failed";
        retire_recovery_through(conn, end->alias, end->group_id,
                                end->final_object_id);
      }
      return NULL;
    }
    first_object_id = gap->last_checkpoint_object_id + 1U;
  } else {
    first_object_id =
        end->final_object_id >= 31 ? end->final_object_id - 31 : 0;
  }
  if (!receive_recovery_checkpoint(conn, end->alias, end->group_id,
                                   first_object_id, end->final_object_id,
                                   acknowledge))
    return "protocol error: invalid track completion window";
  return NULL;
}

bool transport_recovery_send_nack(transport_conn_t *conn, uint8_t alias,
                                  uint64_t group_id, uint64_t object_id,
                                  const uint16_t *missing, uint16_t count,
                                  bool whole_object) {
  if (!conn || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;

  if (count > QLINQ_WIRE_MAX_NACK_SYMBOLS)
    return false;
  moq_track_id_t track_id;
  if (transport_subscriptions_find_by_alias(&conn->receive_subscriptions, alias,
                                            &track_id) != 0)
    return false;
  if (!transport_get_receive_track_profile(conn->transport, &track_id)
           .reactive_repair)
    return false;
  bool rateless =
      transport_get_effective_repair_mode(conn->transport, conn, &track_id) ==
      TRANSPORT_REPAIR_MODE_RATELESS;
  if (rateless ? (!whole_object && (count == 0 || missing != NULL))
               : (!whole_object && (count == 0 || missing == NULL)))
    return false;
  uint8_t buf[20U + 2U * QLINQ_WIRE_MAX_NACK_SYMBOLS];

  size_t written = 0;
  bool sent = false;
  uint8_t flags = whole_object ? QLINQ_WIRE_NACK_WHOLE_OBJECT : 0;
  if (rateless)
    flags |= QLINQ_WIRE_NACK_RATELESS;
  if (qlinq_wire_encode_nack(buf, sizeof(buf), alias, flags, group_id,
                             object_id, missing, count,
                             &written) == QLINQ_WIRE_OK) {
    if (transport_stream_has_retained_frame(conn->stream, QLINQ_WIRE_NACK, buf,
                                            written)) {
      /* QUIC owns retransmission until this exact request is released. A
       * later application retry can recover a lost repair response. */
      conn->transport->stats.repair_requests_coalesced++;
      sent = true;
    } else if (!transport_stream_can_accept(
                   conn->stream, QLINQ_WIRE_FRAME_HEADER_SIZE + written,
                   true)) {
      /* Recovery timers retain the missing objects and retry after pressure
       * clears. Preserve essential control capacity without spending tokens. */
      conn->transport->stats.repair_requests_deferred++;
    } else if (transport_repair_limiter_wait_ms(
                   &conn->nack_request_limiter,
                   conn->transport->limits.max_repair_requests_per_second,
                   transport_now_ms(conn->transport)) != 0 ||
               transport_repair_limiter_wait_ms(
                   &conn->transport->aggregate_nack_limiter,
                   conn->transport->limits
                       .max_aggregate_nack_requests_per_second,
                   transport_now_ms(conn->transport)) != 0) {
      conn->transport->stats.repair_requests_deferred++;
    } else if (transport_stream_write_frame(conn->stream, QLINQ_WIRE_NACK, buf,
                                            written)) {
      int64_t admitted_at_ms = transport_now_ms(conn->transport);
      (void)transport_repair_limiter_take(
          &conn->nack_request_limiter,
          conn->transport->limits.max_repair_requests_per_second,
          admitted_at_ms);
      (void)transport_repair_limiter_take(
          &conn->transport->aggregate_nack_limiter,
          conn->transport->limits.max_aggregate_nack_requests_per_second,
          admitted_at_ms);
      conn->transport->stats.repair_requests_sent++;
      if (rateless)
        conn->transport->stats.repair_rateless_requests_sent++;
      else
        conn->transport->stats.repair_indexed_requests_sent++;
      if (whole_object)
        conn->transport->stats.repair_whole_object_requests_sent++;
      sent = true;
    }
  }

  return sent;
}

/* bound both idle gaps between symbols and total incomplete lifetime */
static int64_t assembler_deadline_ms(const transport_t *t,
                                     const frame_assembler_t *assembler) {
  int64_t idle_timeout = (int64_t)t->fec_assembler_timeout_ms;
  int64_t max_age =
      idle_timeout > INT64_MAX / (int64_t)QLINQ_FEC_ASSEMBLER_MAX_AGE_FACTOR
          ? INT64_MAX
          : idle_timeout * (int64_t)QLINQ_FEC_ASSEMBLER_MAX_AGE_FACTOR;
  if (assembler->owner) {
    moq_track_id_t resolved_track;
    if (transport_subscriptions_find_by_alias(
            &assembler->owner->receive_subscriptions, assembler->track_id,
            &resolved_track) == 0) {
      transport_track_profile_t profile =
          transport_get_receive_track_profile(t, &resolved_track);
      if (profile.policy.enabled && profile.policy.max_object_age_ms != 0)
        max_age = (int64_t)profile.policy.max_object_age_ms;
    }
  }
  int64_t idle_expires =
      assembler->last_activity_time_ms > INT64_MAX - idle_timeout
          ? INT64_MAX
          : assembler->last_activity_time_ms + idle_timeout;
  int64_t age_expires = assembler->first_symbol_time_ms > INT64_MAX - max_age
                            ? INT64_MAX
                            : assembler->first_symbol_time_ms + max_age;
  return idle_expires < age_expires ? idle_expires : age_expires;
}

static bool retirement_due(const transport_track_profile_t *profile,
                           int64_t first_ms, int64_t now_ms) {
  return (!profile->reactive_repair &&
          now_ms - first_ms >= QLINQ_FEC_NACK_DELAY_MS) ||
         (profile->policy.max_object_age_ms != 0 &&
          now_ms - first_ms >= profile->policy.max_object_age_ms);
}

static bool recovery_subscription_current(transport_conn_t *conn, uint8_t alias,
                                          uint64_t generation) {
  transport_subscription_state_t *state =
      transport_subscriptions_get_state(&conn->receive_subscriptions, alias);
  return state && state->generation == generation;
}

static void retire_due_objects(transport_conn_t *conn, int64_t now_ms,
                               size_t *budget) {
  if (!(conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_RETIREMENT))
    return;
  for (size_t i = 0; i < conn->receive_subscriptions.capacity && *budget; i++) {
    const track_subscription_t *sub = &conn->receive_subscriptions.entries[i];
    if (!sub->active)
      continue;
    transport_track_profile_t profile =
        transport_get_receive_track_profile(conn->transport, &sub->track_id);
    if (!profile.checkpoint_recovery)
      continue;
    uint8_t alias = sub->alias;
    transport_subscription_state_t *state =
        transport_subscriptions_get_state(&conn->receive_subscriptions, alias);
    uint64_t generation = state->generation;
    transport_object_gap_state_t *gap = &state->object_gap;
    if (retirement_due(&profile, gap->first_missing_at_ms, now_ms)) {
      for (unsigned bit = 0; bit < 32 && *budget; bit++) {
        if (!(gap->pending_mask & (UINT32_C(1) << bit)))
          continue;
        if (!transport_recovery_retire(conn, alias, gap->group_id,
                                       gap->pending_base + bit))
          return;
        --*budget;
        if (!recovery_subscription_current(conn, alias, generation))
          return;
      }
    }
    for (size_t j = 0; j < QLINQ_RECOVERY_MAX_WINDOWS && *budget; j++) {
      transport_recovery_window_t *window = &gap->recovery_windows[j];
      if (!window->active ||
          !retirement_due(&profile, window->created_at_ms, now_ms))
        continue;
      for (unsigned bit = 0; bit < QLINQ_RECOVERY_WINDOW_OBJECTS && *budget;
           bit++) {
        if (!(window->missing_mask & (UINT32_C(1) << bit)))
          continue;
        if (!transport_recovery_retire(conn, alias, window->group_id,
                                       window->first_object_id + bit))
          return;
        --*budget;
        if (!recovery_subscription_current(conn, alias, generation))
          return;
      }
    }
  }
}

void transport_recovery_tick(transport_t *t, int64_t now_nack_ms) {
  /* Expiration releases memory and reports loss even when the receiver-wide
   * NACK budget is exhausted. It must not be gated by request admission. */
  size_t active_conns = transport_connection_count(t);
  size_t retirement_budget = 32;
  for (size_t c = 0; c < active_conns; c++) {
    transport_conn_t *conn = transport_connection_at(t, c);
    if (!conn || !conn->quic ||
        quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
      continue;
    transport_recovery_flush_acks(conn);
    retire_due_objects(conn, now_nack_ms, &retirement_budget);
    for (size_t i = transport_next_assembler(conn, 0);
         i < t->limits.max_assemblers_per_connection;
         i = transport_next_assembler(conn, i + 1U)) {
      frame_assembler_t *asm_slot = &conn->assemblers[i];
      if (asm_slot->total_symbols == 0)
        continue;
      if (now_nack_ms >= assembler_deadline_ms(t, asm_slot)) {
        moq_track_id_t resolved_track;
        if (transport_subscriptions_find_by_alias(&conn->receive_subscriptions,
                                                  asm_slot->track_id,
                                                  &resolved_track) == 0) {
          transport_track_profile_t profile =
              transport_get_receive_track_profile(t, &resolved_track);
          if (profile.checkpoint_recovery &&
              retirement_due(&profile, asm_slot->first_symbol_time_ms,
                             now_nack_ms) &&
              (conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_RETIREMENT) !=
                  0) {
            (void)transport_recovery_retire(conn, asm_slot->track_id,
                                            asm_slot->group_id,
                                            asm_slot->object_id);
            continue;
          }
          transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT_LOST,
                                  .conn = conn,
                                  .track_id = resolved_track,
                                  .object = {.track_id = resolved_track,
                                             .group_id = asm_slot->group_id,
                                             .object_id = asm_slot->object_id}};
          t->stats.fec_objects_lost++;
          transport_emit_event(t, &ev);
        }
        transport_release_assembler(t, asm_slot);
        continue;
      }
    }
  }

  /* Bound aggregate feedback and rotate the starting peer after admission.
   * Skip the more expensive alias/repair scans while no token is available. */
  size_t object_nack_budget = 32;
  uint64_t aggregate_wait = transport_repair_limiter_wait_ms(
      &t->aggregate_nack_limiter,
      t->limits.max_aggregate_nack_requests_per_second, now_nack_ms);
  if (aggregate_wait != 0)
    goto aggregate_nack_exhausted;
  t->aggregate_nack_retry_at_ms = 0;
  size_t recovery_start =
      active_conns == 0 ? 0 : t->recovery_conn_cursor % active_conns;
  for (size_t offset = 0; offset < active_conns; offset++) {
    size_t c = (recovery_start + offset) % active_conns;
    transport_conn_t *conn = transport_connection_at(t, c);
    if (!conn || !conn->quic ||
        quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
      continue;

    for (size_t slot = 0;
         slot < conn->receive_subscriptions.capacity && object_nack_budget > 0;
         slot++) {
      const track_subscription_t *sub =
          &conn->receive_subscriptions.entries[slot];
      /* object gaps and checkpoint windows exist only for rateless data */
      transport_track_profile_t profile =
          transport_get_receive_track_profile(t, &sub->track_id);
      if (!sub->active || !profile.checkpoint_recovery)
        continue;
      uint8_t alias = sub->alias;
      uint64_t generation =
          transport_subscriptions_get_state(&conn->receive_subscriptions, alias)
              ->generation;
      transport_object_gap_state_t *gap = transport_object_gap(conn, alias);
      if (!gap)
        continue;
      if (gap->pending_mask != 0 &&
          now_nack_ms - gap->detected_at_ms >= QLINQ_FEC_NACK_DELAY_MS) {
        int64_t idle_timeout = (int64_t)t->fec_assembler_timeout_ms;
        int64_t default_max_age =
            idle_timeout >
                    INT64_MAX / (int64_t)QLINQ_FEC_ASSEMBLER_MAX_AGE_FACTOR
                ? INT64_MAX
                : idle_timeout * (int64_t)QLINQ_FEC_ASSEMBLER_MAX_AGE_FACTOR;
        int64_t gap_max_age =
            profile.policy.enabled && profile.policy.max_object_age_ms != 0
                ? (int64_t)profile.policy.max_object_age_ms
                : default_max_age;
        if ((conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_RETIREMENT) ==
                0 &&
            now_nack_ms - gap->first_missing_at_ms >= gap_max_age) {
          /* expire stale uncheckpointed gap bits when peer lacks retirement */
          gap->pending_mask = 0;
          gap->pending_cursor = 0;
        }
        uint32_t first_bit = gap->pending_cursor % 32U;
        bool completed_pass = true;
        bool sent_any = false;
        for (uint32_t attempt = 0; attempt < 32; attempt++) {
          uint32_t bit = (first_bit + attempt) % 32U;
          if ((gap->pending_mask & (1U << bit)) == 0)
            continue;
          if (object_nack_budget == 0) {
            completed_pass = false;
            break;
          }
          if (!profile.reactive_repair ||
              (profile.policy.max_object_age_ms != 0 &&
               now_nack_ms - gap->first_missing_at_ms >=
                   profile.policy.max_object_age_ms)) {
            if (transport_recovery_retire(conn, alias, gap->group_id,
                                          gap->pending_base + bit))
              object_nack_budget--;
            if (!recovery_subscription_current(conn, alias, generation))
              goto next_receive_subscription;
            continue;
          }
          aggregate_wait = transport_repair_limiter_wait_ms(
              &t->aggregate_nack_limiter,
              t->limits.max_aggregate_nack_requests_per_second, now_nack_ms);
          if (aggregate_wait != 0)
            goto aggregate_nack_exhausted;
          if (transport_recovery_send_nack(conn, (uint8_t)alias, gap->group_id,
                                           gap->pending_base + bit, NULL, 0,
                                           true)) {
            gap->pending_cursor = (uint8_t)((bit + 1U) % 32U);
            sent_any = true;
            object_nack_budget--;
            t->recovery_conn_cursor = (c + 1U) % active_conns;
          } else {
            completed_pass = false;
            break;
          }
        }
        if (completed_pass && sent_any)
          gap->detected_at_ms = now_nack_ms;
      }

      for (size_t window_index = 0;
           window_index < QLINQ_RECOVERY_MAX_WINDOWS && object_nack_budget > 0;
           window_index++) {
        transport_recovery_window_t *window =
            &gap->recovery_windows[window_index];
        int64_t retry_delay = window->last_request_ms == 0
                                  ? QLINQ_FEC_NACK_DELAY_MS
                                  : QLINQ_FEC_COMPLETION_RETRY_MS;
        int64_t reference_ms = window->last_request_ms == 0
                                   ? window->created_at_ms
                                   : window->last_request_ms;
        if (!window->active || window->missing_mask == 0 ||
            now_nack_ms - reference_ms < retry_delay)
          continue;
        /* Pipeline distinct missing objects within the existing tick, token
         * and control-queue budgets. One request per retry interval adds
         * 500 ms between requests for a burst of lost objects. Keep the start
         * fixed while the cursor advances after each admitted request. */
        uint32_t first_bit = window->cursor;
        for (uint32_t attempt = 0;
             attempt < QLINQ_RECOVERY_WINDOW_OBJECTS && object_nack_budget > 0;
             attempt++) {
          uint32_t bit = (first_bit + attempt) % QLINQ_RECOVERY_WINDOW_OBJECTS;
          if ((window->missing_mask & (1U << bit)) == 0)
            continue;
          uint64_t object_id = window->first_object_id + bit;
          if (object_id > window->final_object_id)
            continue;
          if (!profile.reactive_repair ||
              (profile.policy.max_object_age_ms != 0 &&
               now_nack_ms - window->created_at_ms >=
                   profile.policy.max_object_age_ms)) {
            if (transport_recovery_retire(conn, alias, window->group_id,
                                          object_id))
              object_nack_budget--;
            if (!recovery_subscription_current(conn, alias, generation))
              goto next_receive_subscription;
            continue;
          }
          if (transport_find_assembler(conn, alias, window->group_id,
                                       object_id))
            continue;
          aggregate_wait = transport_repair_limiter_wait_ms(
              &t->aggregate_nack_limiter,
              t->limits.max_aggregate_nack_requests_per_second, now_nack_ms);
          if (aggregate_wait != 0)
            goto aggregate_nack_exhausted;
          if (transport_recovery_send_nack(conn, (uint8_t)alias,
                                           window->group_id, object_id, NULL, 0,
                                           true)) {
            window->cursor =
                (uint8_t)((bit + 1U) % QLINQ_RECOVERY_WINDOW_OBJECTS);
            window->last_request_ms = now_nack_ms;
            object_nack_budget--;
            t->recovery_conn_cursor = (c + 1U) % active_conns;
          } else {
            break;
          }
        }
      }
    next_receive_subscription:;
    }

    for (size_t i = transport_next_assembler(conn, 0);
         i < t->limits.max_assemblers_per_connection;
         i = transport_next_assembler(conn, i + 1U)) {
      frame_assembler_t *asm_slot = &conn->assemblers[i];
      if (asm_slot->total_symbols == 0)
        continue;

      if (now_nack_ms - asm_slot->first_symbol_time_ms >=
              QLINQ_FEC_NACK_DELAY_MS &&
          (!asm_slot->nack_sent || now_nack_ms - asm_slot->last_nack_time_ms >=
                                       QLINQ_FEC_NACK_DELAY_MS)) {
        moq_track_id_t resolved_track;
        if (transport_subscriptions_find_by_alias(&conn->receive_subscriptions,
                                                  asm_slot->track_id,
                                                  &resolved_track) != 0)
          continue;
        transport_track_profile_t profile =
            transport_get_receive_track_profile(t, &resolved_track);
        if (!profile.reactive_repair) {
          if (profile.checkpoint_recovery)
            (void)transport_recovery_retire(conn, asm_slot->track_id,
                                            asm_slot->group_id,
                                            asm_slot->object_id);
          continue; /* reactive repair disabled for this track */
        }
        transport_repair_mode_t repair_mode =
            transport_get_effective_repair_mode(t, conn, &resolved_track);
        uint16_t missing_count = 0;
        const uint16_t *missing = NULL;
        if (repair_mode == TRANSPORT_REPAIR_MODE_RATELESS) {
          missing_count = asm_slot->received_count < asm_slot->data_symbols
                              ? (uint16_t)(asm_slot->data_symbols -
                                           asm_slot->received_count)
                              : 1U;
          if (missing_count > TRANSPORT_REPAIR_MAX_SYMBOLS)
            missing_count = TRANSPORT_REPAIR_MAX_SYMBOLS;
        } else {
          for (uint16_t s = 0; s < asm_slot->total_symbols; s++) {
            if (!asm_slot->received_mask[s] &&
                missing_count < TRANSPORT_REPAIR_MAX_SYMBOLS) {
              asm_slot->missing_indices[missing_count++] = s;
            }
          }
          missing = asm_slot->missing_indices;
        }
        if (missing_count > 0) {
          aggregate_wait = transport_repair_limiter_wait_ms(
              &t->aggregate_nack_limiter,
              t->limits.max_aggregate_nack_requests_per_second, now_nack_ms);
          if (aggregate_wait != 0)
            goto aggregate_nack_exhausted;
          if (transport_recovery_send_nack(
                  conn, asm_slot->track_id, asm_slot->group_id,
                  asm_slot->object_id, missing, missing_count, false)) {
            asm_slot->nack_sent = true;
            asm_slot->last_nack_time_ms = now_nack_ms;
            t->recovery_conn_cursor = (c + 1U) % active_conns;
          }
        }
      }
    }
  }

  return;

aggregate_nack_exhausted:
  t->aggregate_nack_retry_at_ms =
      aggregate_wait == UINT64_MAX ||
              aggregate_wait > (uint64_t)(INT64_MAX - now_nack_ms)
          ? INT64_MAX
          : now_nack_ms + (int64_t)aggregate_wait;
}

static int64_t add_clamped_ms(int64_t base, int64_t delta) {
  return base > INT64_MAX - delta ? INT64_MAX : base + delta;
}

static int64_t clamp_nack_due(const transport_conn_t *conn, int64_t now,
                              int64_t due, bool nack_stream_ready) {
  if (due > now)
    return due;
  const transport_t *t = conn->transport;
  transport_repair_limiter_t peer = conn->nack_request_limiter;
  transport_repair_limiter_t agg = t->aggregate_nack_limiter;
  uint64_t peer_wait = transport_repair_limiter_wait_ms(
      &peer, t->limits.max_repair_requests_per_second, now);
  uint64_t agg_wait = transport_repair_limiter_wait_ms(
      &agg, t->limits.max_aggregate_nack_requests_per_second, now);
  uint64_t wait = peer_wait > agg_wait ? peer_wait : agg_wait;
  if (wait != 0) {
    return wait == UINT64_MAX || wait > (uint64_t)(INT64_MAX - now)
               ? INT64_MAX
               : now + (int64_t)wait;
  }
  if (!nack_stream_ready)
    return add_clamped_ms(now, RECOVERY_CONTROL_RETRY_MS);
  return due;
}

int64_t transport_recovery_deadline(const transport_conn_t *conn) {
  const transport_t *t = conn->transport;
  int64_t first_timeout = INT64_MAX;
  int64_t now = transport_now_ms(t);
  bool retirement_ready = transport_stream_can_accept(
      conn->stream,
      QLINQ_WIRE_FRAME_HEADER_SIZE + QLINQ_WIRE_OBJECT_RETIRE_SIZE, false);
  bool ack_ready = transport_stream_can_accept(
      conn->stream,
      QLINQ_WIRE_FRAME_HEADER_SIZE + QLINQ_WIRE_TRACK_CHECKPOINT_ACK_SIZE,
      false);
  bool nack_stream_ready = transport_stream_can_accept(
      conn->stream, QLINQ_WIRE_FRAME_HEADER_SIZE + 20U, true);
  for (size_t i = transport_next_assembler(conn, 0);
       i < t->limits.max_assemblers_per_connection;
       i = transport_next_assembler(conn, i + 1U)) {
    const frame_assembler_t *assembler = &conn->assemblers[i];
    if (assembler->total_symbols == 0)
      continue;
    int64_t expires = assembler_deadline_ms(t, assembler);
    moq_track_id_t track;
    bool has_track =
        transport_subscriptions_find_by_alias(&conn->receive_subscriptions,
                                              assembler->track_id, &track) == 0;
    transport_track_profile_t profile = {0};
    if (has_track)
      profile = transport_get_receive_track_profile(t, &track);
    if (expires <= now && !retirement_ready && has_track &&
        profile.checkpoint_recovery &&
        retirement_due(&profile, assembler->first_symbol_time_ms, now)) {
      expires = add_clamped_ms(now, RECOVERY_CONTROL_RETRY_MS);
    }
    if (expires < first_timeout)
      first_timeout = expires;
    if (has_track && profile.reactive_repair &&
        assembler->received_count < assembler->data_symbols) {
      int64_t nack_due =
          add_clamped_ms(assembler->nack_sent ? assembler->last_nack_time_ms
                                              : assembler->first_symbol_time_ms,
                         QLINQ_FEC_NACK_DELAY_MS);
      nack_due = clamp_nack_due(conn, now, nack_due, nack_stream_ready);
      if (nack_due < first_timeout)
        first_timeout = nack_due;
    }
  }
  bool has_retirement_cap =
      (conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_RETIREMENT) != 0;
  for (size_t i = 0; i < conn->receive_subscriptions.capacity; i++) {
    const track_subscription_t *sub = &conn->receive_subscriptions.entries[i];
    if (!sub->active)
      continue;
    transport_track_profile_t profile =
        transport_get_receive_track_profile(t, &sub->track_id);
    if (!profile.checkpoint_recovery)
      continue;
    const transport_object_gap_state_t *gap =
        transport_object_gap((transport_conn_t *)conn, sub->alias);
    if (!gap)
      continue;

    const transport_recovery_window_t *first_window = NULL;
    for (size_t j = 0; j < QLINQ_RECOVERY_MAX_WINDOWS; j++) {
      const transport_recovery_window_t *window = &gap->recovery_windows[j];
      if (!window->active ||
          (first_window &&
           window->first_object_id >= first_window->first_object_id))
        continue;
      first_window = window;
    }
    if ((gap->ack_pending ||
         (first_window && first_window->missing_mask == 0)) &&
        !ack_ready) {
      int64_t ack_due = add_clamped_ms(now, RECOVERY_CONTROL_RETRY_MS);
      if (ack_due < first_timeout)
        first_timeout = ack_due;
    } else if (gap->ack_pending ||
               (first_window && first_window->missing_mask == 0)) {
      if (now < first_timeout)
        first_timeout = now;
    }

    if (profile.reactive_repair) {
      if (gap->pending_mask != 0) {
        int64_t nack_due =
            add_clamped_ms(gap->detected_at_ms, QLINQ_FEC_NACK_DELAY_MS);
        nack_due = clamp_nack_due(conn, now, nack_due, nack_stream_ready);
        if (nack_due < first_timeout)
          first_timeout = nack_due;
      }
      for (size_t j = 0; j < QLINQ_RECOVERY_MAX_WINDOWS; j++) {
        const transport_recovery_window_t *window = &gap->recovery_windows[j];
        if (!window->active || window->missing_mask == 0)
          continue;
        bool needs_whole_nack = false;
        for (uint32_t bit = 0; bit < QLINQ_RECOVERY_WINDOW_OBJECTS; bit++) {
          if ((window->missing_mask & (1U << bit)) == 0)
            continue;
          uint64_t object_id = window->first_object_id + bit;
          if (object_id <= window->final_object_id &&
              !transport_find_assembler((transport_conn_t *)conn, sub->alias,
                                        window->group_id, object_id)) {
            needs_whole_nack = true;
            break;
          }
        }
        if (!needs_whole_nack)
          continue;
        int64_t win_due =
            window->last_request_ms == 0
                ? add_clamped_ms(window->created_at_ms, QLINQ_FEC_NACK_DELAY_MS)
                : add_clamped_ms(window->last_request_ms,
                                 QLINQ_FEC_COMPLETION_RETRY_MS);
        win_due = clamp_nack_due(conn, now, win_due, nack_stream_ready);
        if (win_due < first_timeout)
          first_timeout = win_due;
      }
    }

    if (!has_retirement_cap)
      continue;
    int64_t delay =
        profile.reactive_repair ? INT64_MAX : QLINQ_FEC_NACK_DELAY_MS;
    if (profile.policy.max_object_age_ms &&
        profile.policy.max_object_age_ms < (uint64_t)delay)
      delay = profile.policy.max_object_age_ms;
    if (delay == INT64_MAX)
      continue;
    int64_t first = gap->pending_mask ? gap->first_missing_at_ms : INT64_MAX;
    for (size_t j = 0; j < QLINQ_RECOVERY_MAX_WINDOWS; j++) {
      const transport_recovery_window_t *window = &gap->recovery_windows[j];
      if (window->active && window->missing_mask &&
          window->created_at_ms < first)
        first = window->created_at_ms;
    }
    if (first > INT64_MAX - delay)
      continue;
    int64_t expires = first + delay;
    if (expires <= now && !retirement_ready)
      expires = add_clamped_ms(now, RECOVERY_CONTROL_RETRY_MS);
    if (expires < first_timeout)
      first_timeout = expires;
  }
  return first_timeout;
}
