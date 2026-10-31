#include "transport_stream.h"

#include "transport_internal.h"
#include "transport_tls.h"
#include "transport_wire.h"

#include "quicly/streambuf.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  transport_stream_ctx_t *ctx;
  uint8_t bytes[];
} retained_frame_t;

bool transport_stream_control_pending(const quicly_stream_t *stream) {
  if (!stream || !stream->data)
    return false;
  const transport_stream_ctx_t *ctx = stream->data;
  return stream->sendstate.pending.num_ranges != 0 &&
         stream->sendstate.pending.ranges[0].start < ctx->control_end;
}

static transport_t *stream_owner(quicly_stream_t *stream) {
  transport_conn_t *conn = *quicly_get_data(stream->conn);
  return conn ? conn->transport : NULL;
}

static size_t vector_growth(const quicly_sendbuf_t *sb) {
  return sb->vecs.size < sb->vecs.capacity ? 0
         : sb->vecs.capacity               ? sb->vecs.capacity
                                           : 4;
}

static bool stream_can_accept_reserved(quicly_stream_t *stream,
                                       size_t frame_len,
                                       bool preserve_control_reserve,
                                       size_t *reserved_bytes,
                                       size_t *reserved_vectors) {
  if (!stream || !stream->conn || !stream->data ||
      !quicly_sendstate_is_open(&stream->sendstate) ||
      quicly_get_state(stream->conn) >= QUICLY_STATE_CLOSING ||
      frame_len >
          TRANSPORT_WIRE_MAX_STREAM_PAYLOAD + QLINQ_WIRE_FRAME_HEADER_SIZE)
    return false;
  transport_t *t = stream_owner(stream);
  if (!t)
    return false;
  transport_stream_ctx_t *ctx = stream->data;
  quicly_sendbuf_t *sb = &ctx->streambuf.egress;
  size_t stream_limit = t->limits.max_stream_egress_bytes;
  size_t endpoint_limit = t->limits.max_total_stream_egress_bytes;
  size_t vector_limit = TRANSPORT_STREAM_ENDPOINT_MAX_VECTORS;
  /* Bound tiny control frames without making large-object throughput depend on
   * a fixed frame count. The retained-byte and vector budgets below remain the
   * hard resource limits. */
  size_t frame_limit =
      stream_limit / TRANSPORT_STREAM_MIN_FRAME_ACCOUNTING_BYTES;
  if (frame_limit > vector_limit)
    frame_limit = vector_limit;
  if (preserve_control_reserve) {
    endpoint_limit -= TRANSPORT_STREAM_ENDPOINT_CONTROL_BYTE_RESERVE;
    vector_limit -= TRANSPORT_STREAM_ENDPOINT_CONTROL_VECTOR_RESERVE;
    if (ctx->is_control) {
      stream_limit -= TRANSPORT_STREAM_CONTROL_BYTE_RESERVE;
      frame_limit -= TRANSPORT_STREAM_CONTROL_FRAME_RESERVE;
    }
  }
  if (frame_limit == 0)
    return false;
  size_t frame_bytes = sizeof(retained_frame_t) + frame_len;
  size_t stream_bytes = ctx->retained_frame_bytes +
                        sb->vecs.capacity * sizeof(quicly_sendbuf_vec_t);
  if (sb->vecs.size >= frame_limit || stream_bytes > stream_limit ||
      frame_bytes > stream_limit - stream_bytes ||
      t->stats.stream_egress_bytes > endpoint_limit ||
      *reserved_bytes > endpoint_limit - t->stats.stream_egress_bytes ||
      frame_bytes >
          endpoint_limit - t->stats.stream_egress_bytes - *reserved_bytes ||
      t->stats.stream_egress_vector_capacity > vector_limit ||
      *reserved_vectors > vector_limit - t->stats.stream_egress_vector_capacity)
    return false;
  /* Quicly normally doubles the vector array. Near a byte/vector limit, use
   * the remaining capacity instead of stranding up to half the budget. */
  size_t growth = vector_growth(sb);
  size_t available =
      vector_limit - t->stats.stream_egress_vector_capacity - *reserved_vectors;
  size_t stream_slots = (stream_limit - stream_bytes - frame_bytes) /
                        sizeof(quicly_sendbuf_vec_t);
  size_t endpoint_slots = (endpoint_limit - t->stats.stream_egress_bytes -
                           *reserved_bytes - frame_bytes) /
                          sizeof(quicly_sendbuf_vec_t);
  if (growth > available)
    growth = available;
  if (growth > stream_slots)
    growth = stream_slots;
  if (growth > endpoint_slots)
    growth = endpoint_slots;
  if (sb->vecs.size == sb->vecs.capacity && growth == 0)
    return false;
  *reserved_bytes += frame_bytes + growth * sizeof(quicly_sendbuf_vec_t);
  *reserved_vectors += growth;
  return true;
}

bool transport_stream_can_accept(quicly_stream_t *stream, size_t frame_len,
                                 bool preserve_control_reserve) {
  size_t bytes = 0, vectors = 0;
  return stream_can_accept_reserved(stream, frame_len, preserve_control_reserve,
                                    &bytes, &vectors);
}

bool transport_stream_can_accept_batch(quicly_stream_t *stream,
                                       size_t frame_len, size_t *bytes,
                                       size_t *vectors) {
  return stream_can_accept_reserved(stream, frame_len, true, bytes, vectors);
}

static quicly_error_t flatten_frame(quicly_sendbuf_vec_t *vec, void *dst,
                                    size_t off, size_t len) {
  retained_frame_t *frame = vec->cbdata;
  memcpy(dst, frame->bytes + off, len);
  return 0;
}

static void discard_frame(quicly_sendbuf_vec_t *vec) {
  retained_frame_t *frame = vec->cbdata;
  size_t bytes = sizeof(*frame) + vec->len;
  transport_stream_ctx_t *ctx = frame->ctx;
  assert(ctx->retained_frame_bytes >= bytes &&
         ctx->owner->stats.stream_egress_bytes >= bytes);
  ctx->retained_frame_bytes -= bytes;
  ctx->owner->stats.stream_egress_bytes -= bytes;
  assert(ctx->owner->stats.stream_egress_frames != 0);
  ctx->owner->stats.stream_egress_frames--;
  free(frame);
}

static const quicly_streambuf_sendvec_callbacks_t retained_callbacks = {
    flatten_frame, discard_frame};

bool transport_stream_has_retained_frame(quicly_stream_t *stream, uint8_t type,
                                         const void *payload,
                                         size_t payload_len) {
  if (!stream || !stream->conn || !stream->data ||
      !quicly_sendstate_is_open(&stream->sendstate) ||
      quicly_get_state(stream->conn) >= QUICLY_STATE_CLOSING ||
      (payload_len != 0 && !payload) ||
      payload_len > TRANSPORT_WIRE_MAX_STREAM_PAYLOAD)
    return false;
  uint8_t header[QLINQ_WIRE_FRAME_HEADER_SIZE];
  if (qlinq_wire_encode_frame_header(header, sizeof(header), type, payload_len,
                                     TRANSPORT_WIRE_MAX_STREAM_PAYLOAD) !=
      QLINQ_WIRE_OK)
    return false;
  transport_stream_ctx_t *ctx = stream->data;
  const quicly_sendbuf_t *sb = &ctx->streambuf.egress;
  /* QUIC owns retransmission while the request is retained, including partial
   * ACKs and later ACKed ranges held behind an unacknowledged prefix. Once the
   * complete frame shifts out, a missing repair response can trigger a fresh
   * application request. The frame budget bounds this scan; no index is
   * allocated. */
  for (size_t i = sb->vecs.size; i != 0; i--) {
    const quicly_sendbuf_vec_t *vec = &sb->vecs.entries[i - 1];
    if (vec->cb != &retained_callbacks ||
        vec->len != sizeof(header) + payload_len)
      continue;
    const retained_frame_t *frame = vec->cbdata;
    if (memcmp(frame->bytes, header, sizeof(header)) == 0 &&
        (payload_len == 0 ||
         memcmp(frame->bytes + sizeof(header), payload, payload_len) == 0))
      return true;
  }
  return false;
}

static void release_vector_capacity(transport_stream_ctx_t *ctx, size_t count) {
  if (!count)
    return;
  assert(ctx->owner &&
         ctx->owner->stats.stream_egress_vector_capacity >= count);
  ctx->owner->stats.stream_egress_vector_capacity -= count;
  size_t bytes = count * sizeof(quicly_sendbuf_vec_t);
  assert(ctx->owner->stats.stream_egress_bytes >= bytes);
  ctx->owner->stats.stream_egress_bytes -= bytes;
}

void transport_stream_egress_shift(quicly_stream_t *stream, size_t delta) {
  transport_stream_ctx_t *ctx = stream->data;
  quicly_sendbuf_t *sb = &ctx->streambuf.egress;
  size_t capacity = sb->vecs.capacity, size = sb->vecs.size;
  size_t first_offset = sb->off_in_first_vec;
  quicly_streambuf_egress_shift(stream, delta);
  size_t removed = size - sb->vecs.size;
  if (ctx->emit_index < removed) {
    ctx->emit_index = ctx->emit_prefix = 0;
  } else {
    ctx->emit_index -= removed;
    ctx->emit_prefix -= first_offset + delta - sb->off_in_first_vec;
  }
  /* Quicly keeps a vector array at its historical high-water capacity until
   * the stream becomes empty. Many concurrent control streams can accumulate
   * that slack across peers. */
  if (sb->vecs.capacity > 4 && sb->vecs.size <= sb->vecs.capacity / 4) {
    size_t compact = 4;
    while (compact < sb->vecs.size)
      compact *= 2;
    quicly_sendbuf_vec_t *entries =
        realloc(sb->vecs.entries, compact * sizeof(*entries));
    if (entries) {
      sb->vecs.entries = entries;
      sb->vecs.capacity = compact;
    }
  }
  /* Partial ACKs keep their entire frame allocation charged. Quicly also
   * retains its vector array until the last entry is released unless the
   * compaction above reclaims its unused tail. */
  release_vector_capacity(ctx, capacity - sb->vecs.capacity);
}

void transport_stream_egress_emit(quicly_stream_t *stream, size_t off,
                                  void *dst, size_t *len, int *wrote_all) {
  transport_stream_ctx_t *ctx = stream->data;
  quicly_sendbuf_t *sb = &ctx->streambuf.egress;
  if (*len == 0) {
    quicly_sendbuf_emit(stream, sb, off, dst, len, wrote_all);
    return;
  }
  size_t position = off + sb->off_in_first_vec;
  size_t index = 0, prefix = 0;
  if (position >= ctx->emit_prefix) {
    index = ctx->emit_index;
    prefix = ctx->emit_prefix;
  }
  while (index < sb->vecs.size &&
         position - prefix >= sb->vecs.entries[index].len) {
    prefix += sb->vecs.entries[index++].len;
  }
  /* Retransmitting older bytes must not discard the forward-send cursor.
   * Indices also survive append reallocations and ACK-driven compaction. */
  if (prefix >= ctx->emit_prefix) {
    ctx->emit_index = index;
    ctx->emit_prefix = prefix;
  }
  quicly_sendbuf_t suffix = *sb;
  if (index != 0)
    suffix.vecs.entries += index;
  suffix.vecs.size -= index;
  suffix.vecs.capacity -= index;
  suffix.off_in_first_vec = 0;
  quicly_sendbuf_emit(stream, &suffix, position - prefix, dst, len, wrote_all);
}

ptls_iovec_t transport_stream_ingress_get(quicly_stream_t *stream) {
  transport_stream_ctx_t *ctx = stream->data;
  ptls_buffer_t remaining = ctx->streambuf.ingress;
  if (ctx->ingress_prefix != 0)
    remaining.base += ctx->ingress_prefix;
  remaining.off -= ctx->ingress_prefix;
  return quicly_recvbuf_get(stream, &remaining);
}

int transport_stream_ingress_receive(quicly_stream_t *stream, size_t off,
                                     const void *src, size_t len) {
  transport_stream_ctx_t *ctx = stream->data;
  ptls_buffer_t *buffer = &ctx->streambuf.ingress;
  if (len == 0)
    return 0;
  if (off > SIZE_MAX - ctx->ingress_prefix ||
      len > SIZE_MAX - ctx->ingress_prefix - off) {
    transport_t *t = stream_owner(stream);
    if (t)
      t->stats.resource_limit_errors++;
    quicly_close(stream->conn, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                 "stream receive offset overflow");
    return -1;
  }
  size_t remaining = buffer->off - ctx->ingress_prefix;
  /* Keep the consumed prefix while the allocation has room. Moving an
   * out-of-order tail on every consumption threshold wastes bandwidth even
   * when subsequent input only fills holes in the existing extent. Compact
   * before growing, and copy no more bytes than have been consumed. */
  if (off + ctx->ingress_prefix + len > buffer->capacity &&
      ctx->ingress_prefix != 0 && ctx->ingress_prefix >= remaining) {
    memmove(buffer->base, buffer->base + ctx->ingress_prefix, remaining);
    buffer->off = remaining;
    ctx->ingress_prefix = 0;
  }
  return quicly_recvbuf_receive(stream, buffer, off + ctx->ingress_prefix, src,
                                len);
}

void transport_stream_ingress_shift(quicly_stream_t *stream, size_t delta) {
  transport_stream_ctx_t *ctx = stream->data;
  ptls_buffer_t *buffer = &ctx->streambuf.ingress;
  assert(delta <= buffer->off - ctx->ingress_prefix);
  ctx->ingress_prefix += delta;
  size_t remaining = buffer->off - ctx->ingress_prefix;
  /* An empty buffer can reuse its allocation immediately. Otherwise defer
   * compaction until receiving more bytes would need additional capacity. */
  if (remaining == 0) {
    buffer->off = 0;
    ctx->ingress_prefix = 0;
  }
  quicly_stream_sync_recvbuf(stream, delta);
}

void transport_stream_destroy(quicly_stream_t *stream, quicly_error_t err) {
  transport_stream_ctx_t *ctx = stream->data;
  release_vector_capacity(ctx, ctx->streambuf.egress.vecs.capacity);
  quicly_streambuf_destroy(stream, err);
}

static bool write_failed(quicly_stream_t *stream, bool application_data) {
  if (!application_data) {
    transport_conn_t *conn = *quicly_get_data(stream->conn);
    if (conn && quicly_get_state(stream->conn) < QUICLY_STATE_CLOSING) {
      conn->transport->stats.stream_control_failures++;
      conn->transport->stats.resource_limit_errors++;
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                   "reliable control queue exhausted");
    }
  }
  return false;
}

bool transport_stream_write_parts(quicly_stream_t *stream, uint8_t type,
                                  const void *prefix, size_t prefix_len,
                                  const void *payload, size_t payload_len) {
  if (!stream || !stream->conn || !stream->data ||
      prefix_len > SIZE_MAX - payload_len || (prefix_len > 0 && !prefix) ||
      (payload_len > 0 && !payload))
    return false;
  if (!transport_tls_application_allowed(*quicly_get_data(stream->conn)))
    return false;
  size_t wire_payload_len = prefix_len + payload_len;
  if (wire_payload_len > TRANSPORT_WIRE_MAX_STREAM_PAYLOAD ||
      wire_payload_len > SIZE_MAX - QLINQ_WIRE_FRAME_HEADER_SIZE)
    return false;

  bool application_data =
      type == QLINQ_WIRE_TRACK_OBJECT || type == QLINQ_WIRE_UNICAST;
  size_t frame_len = QLINQ_WIRE_FRAME_HEADER_SIZE + wire_payload_len;
  size_t reserved_bytes = 0, planned_growth = 0;
  if (!stream_can_accept_reserved(stream, frame_len, application_data,
                                  &reserved_bytes, &planned_growth)) {
    transport_t *t = stream_owner(stream);
    if (t)
      t->stats.stream_egress_blocked++;
    return write_failed(stream, application_data);
  }
  transport_stream_ctx_t *ctx = stream->data;
  ctx->owner = stream_owner(stream);
  retained_frame_t *retained = malloc(sizeof(*retained) + frame_len);
  if (!retained)
    return write_failed(stream, application_data);
  retained->ctx = ctx;
  uint8_t *frame = retained->bytes;
  if (qlinq_wire_encode_frame_header(frame, frame_len, type, wire_payload_len,
                                     TRANSPORT_WIRE_MAX_STREAM_PAYLOAD) !=
      QLINQ_WIRE_OK) {
    free(retained);
    return false;
  }
  if (prefix_len > 0)
    memcpy(frame + QLINQ_WIRE_FRAME_HEADER_SIZE, prefix, prefix_len);
  if (payload_len > 0)
    memcpy(frame + QLINQ_WIRE_FRAME_HEADER_SIZE + prefix_len, payload,
           payload_len);

  quicly_sendbuf_vec_t vec = {&retained_callbacks, frame_len, retained};
  quicly_sendbuf_t *sb = &ctx->streambuf.egress;
  size_t old_size = sb->vecs.size, old_capacity = sb->vecs.capacity;
  if (planned_growth != vector_growth(sb)) {
    size_t capacity = old_capacity + planned_growth;
    quicly_sendbuf_vec_t *entries =
        realloc(sb->vecs.entries, capacity * sizeof(*entries));
    if (!entries) {
      free(retained);
      return write_failed(stream, application_data);
    }
    sb->vecs.entries = entries;
    sb->vecs.capacity = capacity;
  }
  int ret = quicly_streambuf_egress_write_vec(stream, &vec);
  transport_stats_t *stats = &ctx->owner->stats;
  size_t growth = sb->vecs.capacity - old_capacity;
  stats->stream_egress_vector_capacity += growth;
  stats->stream_egress_bytes += growth * sizeof(quicly_sendbuf_vec_t);
  bool appended = sb->vecs.size != old_size;
  if (appended) {
    if (!application_data)
      ctx->control_end = sb->bytes_written;
    size_t bytes = sizeof(*retained) + frame_len;
    ctx->retained_frame_bytes += bytes;
    stats->stream_egress_bytes += bytes;
    stats->stream_egress_frames++;
  } else {
    free(retained);
  }
  if (stats->stream_egress_bytes > stats->stream_egress_peak_bytes)
    stats->stream_egress_peak_bytes = stats->stream_egress_bytes;
  if (stats->stream_egress_frames > stats->stream_egress_peak_frames)
    stats->stream_egress_peak_frames = stats->stream_egress_frames;
  if (stats->stream_egress_vector_capacity > stats->stream_egress_peak_vectors)
    stats->stream_egress_peak_vectors = stats->stream_egress_vector_capacity;
  /* A send-state allocation can fail after Quicly appended the vector. The
   * stream owns it in that case; fail the connection rather than free it twice
   * or let an application retry a frame that could subsequently be sent. */
  return ret == 0 ? true : write_failed(stream, application_data && !appended);
}

bool transport_stream_write_frame(quicly_stream_t *stream, uint8_t type,
                                  const void *payload, size_t payload_len) {
  return transport_stream_write_parts(stream, type, payload, payload_len, NULL,
                                      0);
}

bool transport_stream_write_track_frame(quicly_stream_t *stream, uint8_t type,
                                        uint8_t alias,
                                        const moq_track_id_t *track_id) {
  if (!track_id)
    return false;
  size_t name_len = strnlen(track_id->name, sizeof(track_id->name));
  if (name_len > QLINQ_WIRE_MAX_TRACK_NAME)
    return false;

  qlinq_wire_track_t wire_track = {.alias = alias,
                                   .track_type = (uint8_t)track_id->type,
                                   .flags = track_id->flags};
  memcpy(wire_track.name, track_id->name, name_len);
  wire_track.name[name_len] = '\0';
  uint8_t payload[4 + QLINQ_WIRE_MAX_TRACK_NAME];
  size_t encoded_len = 0;
  if (qlinq_wire_encode_track(payload, sizeof(payload), &wire_track,
                              &encoded_len) != QLINQ_WIRE_OK)
    return false;
  return transport_stream_write_frame(stream, type, payload, encoded_len);
}

bool transport_stream_write_object_frame(quicly_stream_t *stream, uint8_t alias,
                                         const moq_object_t *object) {
  if (!stream || !object || (object->size > 0 && !object->data) ||
      object->size > TRANSPORT_MAX_RELIABLE_OBJECT_SIZE)
    return false;
  uint8_t header[QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE];
  qlinq_wire_track_object_t wire_object = {.alias = alias,
                                           .is_keyframe = object->is_keyframe,
                                           .priority = object->priority,
                                           .group_id = object->group_id,
                                           .object_id = object->object_id};
  if (qlinq_wire_encode_track_object(header, sizeof(header), &wire_object) !=
      QLINQ_WIRE_OK)
    return false;
  return transport_stream_write_parts(stream, QLINQ_WIRE_TRACK_OBJECT, header,
                                      sizeof(header), object->data,
                                      object->size);
}

bool transport_stream_write_track_end_frame(quicly_stream_t *stream,
                                            uint8_t alias, uint64_t group_id,
                                            uint64_t final_object_id) {
  uint8_t payload[QLINQ_WIRE_TRACK_END_SIZE];
  qlinq_wire_track_end_t end = {
      .alias = alias, .group_id = group_id, .final_object_id = final_object_id};
  if (qlinq_wire_encode_track_end(payload, sizeof(payload), &end) !=
      QLINQ_WIRE_OK)
    return false;
  return transport_stream_write_frame(stream, QLINQ_WIRE_TRACK_END, payload,
                                      sizeof(payload));
}

bool transport_stream_write_track_checkpoint_frame(
    quicly_stream_t *stream, uint8_t alias, uint64_t group_id,
    uint64_t first_object_id, uint64_t final_object_id, bool baseline) {
  uint8_t payload[QLINQ_WIRE_TRACK_CHECKPOINT_SIZE];
  qlinq_wire_track_checkpoint_t checkpoint = {
      .alias = alias,
      .flags = baseline ? QLINQ_WIRE_CHECKPOINT_BASELINE : 0,
      .group_id = group_id,
      .first_object_id = first_object_id,
      .final_object_id = final_object_id};
  if (qlinq_wire_encode_track_checkpoint(payload, sizeof(payload),
                                         &checkpoint) != QLINQ_WIRE_OK)
    return false;
  return transport_stream_write_frame(stream, QLINQ_WIRE_TRACK_CHECKPOINT,
                                      payload, sizeof(payload));
}

bool transport_stream_write_track_checkpoint_ack_frame(
    quicly_stream_t *stream, uint8_t alias, uint64_t group_id,
    uint64_t final_object_id) {
  uint8_t payload[QLINQ_WIRE_TRACK_CHECKPOINT_ACK_SIZE];
  qlinq_wire_track_checkpoint_ack_t ack = {
      .alias = alias, .group_id = group_id, .final_object_id = final_object_id};
  if (qlinq_wire_encode_track_checkpoint_ack(payload, sizeof(payload), &ack) !=
      QLINQ_WIRE_OK)
    return false;
  return transport_stream_write_frame(stream, QLINQ_WIRE_TRACK_CHECKPOINT_ACK,
                                      payload, sizeof(payload));
}
