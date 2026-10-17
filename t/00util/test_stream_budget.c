#include "quicly/streambuf.h"
#include "transport_config.h"
#include "transport_internal.h"
#include "transport_recovery.h"
#include "transport_stream.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(test)                                                            \
  do {                                                                         \
    if (!(test)) {                                                             \
      fprintf(stderr, "stream budget line %d: %s\n", __LINE__, #test);         \
      failed = 1;                                                              \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

static void ignore_event(void *data, const transport_event_t *event) {
  (void)data;
  (void)event;
}

static transport_t *fixture(void) {
  transport_config_t config = {.bind_hosts = {"127.0.0.1"},
                               .num_bind_hosts = 1,
                               .remote_hosts = {"127.0.0.1"},
                               .num_remote_hosts = 1,
                               .port = 19869,
                               .allow_insecure_peer = true,
                               .callback = ignore_event};
  return transport_create(&config);
}

/* Invoke the actual QUIC stream destruction callbacks while the transport's
 * accounting still exists. These fixtures have no packet I/O or assemblers. */
static bool dispose(transport_t *t) {
  if (!t)
    return false;
  transport_conn_t *conn = t->client_conn;
  if (conn) {
    quicly_free(conn->quic);
    transport_subscriptions_destroy(&conn->send_subscriptions);
    transport_subscriptions_destroy(&conn->receive_subscriptions);
    free(conn);
    t->client_conn = NULL;
  }
  bool released = t->stats.stream_egress_bytes == 0 &&
                  t->stats.stream_egress_frames == 0 &&
                  t->stats.stream_egress_vector_capacity == 0;
  transport_destroy(t);
  return released;
}

static bool acknowledge(quicly_stream_t *stream, size_t bytes) {
  uint64_t first = stream->sendstate.acked.ranges[0].end;
  quicly_sendstate_sent_t sent = {.start = first, .end = first + bytes};
  if (stream->sendstate.size_inflight < sent.end)
    stream->sendstate.size_inflight = sent.end;
  size_t shift = 0;
  if (quicly_sendstate_acked(&stream->sendstate, &sent, &shift) != 0 ||
      shift != bytes)
    return false;
  stream->callbacks->on_send_shift(stream, shift);
  return true;
}

static bool emission_matches(quicly_stream_t *stream, size_t off, size_t size) {
  uint8_t expected[1536], actual[1536];
  if (size > sizeof(actual))
    return false;
  memset(expected, 0xa5, sizeof(expected));
  memset(actual, 0xa5, sizeof(actual));
  size_t expected_size = size, actual_size = size;
  int expected_all = -1, actual_all = -1;
  quicly_streambuf_egress_emit(stream, off, expected, &expected_size,
                               &expected_all);
  stream->callbacks->on_send_emit(stream, off, actual, &actual_size,
                                  &actual_all);
  return expected_size == actual_size && expected_all == actual_all &&
         memcmp(expected, actual, sizeof(actual)) == 0;
}

static bool replay_emissions(quicly_stream_t *stream) {
  quicly_sendbuf_t *sb =
      &((transport_stream_ctx_t *)stream->data)->streambuf.egress;
  size_t remaining = sb->bytes_written - stream->sendstate.acked.ranges[0].end;
  for (size_t off = 0; off < remaining; off += 733)
    if (!emission_matches(stream, off, 1536))
      return false;
  /* Retransmit backwards after the forward pass, revisit newer bytes, and
   * check both exact exhaustion and a zero-capacity request. */
  return emission_matches(stream, 0, 1536) &&
         emission_matches(stream, remaining / 2, 1) &&
         emission_matches(stream, remaining / 3, 1200) &&
         emission_matches(stream, remaining ? remaining - 1 : 0, 1) &&
         emission_matches(stream, remaining, 1536) &&
         emission_matches(stream, remaining, 0);
}

static bool append_emission_frames(quicly_stream_t *stream, size_t count) {
  uint8_t payload[4096];
  for (size_t i = 0; i < count; i++) {
    size_t size = 1 + i * 997 % sizeof(payload);
    for (size_t j = 0; j < size; j++)
      payload[j] = (uint8_t)(i + j);
    if (!transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, payload,
                                      size))
      return false;
  }
  return true;
}

static int stream_emission_cursor(void) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn && t->client_conn->stream);
  quicly_stream_t *stream = t->client_conn->stream;
  quicly_sendbuf_t *sb =
      &((transport_stream_ctx_t *)stream->data)->streambuf.egress;
  CHECK(append_emission_frames(stream, 8) && replay_emissions(stream));
  CHECK(acknowledge(stream, 1) && replay_emissions(stream));
  CHECK(acknowledge(stream, sb->vecs.entries[0].len - 1 +
                                sb->vecs.entries[1].len + 3) &&
        replay_emissions(stream));
  size_t old_capacity = sb->vecs.capacity;
  CHECK(append_emission_frames(stream, 40) &&
        sb->vecs.capacity > old_capacity && replay_emissions(stream));
  size_t remaining = sb->bytes_written - stream->sendstate.acked.ranges[0].end;
  CHECK(acknowledge(stream, remaining - 1) && replay_emissions(stream));
  CHECK(acknowledge(stream, 1) && replay_emissions(stream));
  /* ACK past a cursor near the beginning, retaining later vectors. */
  CHECK(append_emission_frames(stream, 8) && emission_matches(stream, 0, 1));
  CHECK(acknowledge(stream,
                    sb->vecs.entries[0].len + sb->vecs.entries[1].len + 1) &&
        replay_emissions(stream));
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

static int entry_limit_and_control_failure(void) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn && t->client_conn->stream);
  quicly_stream_t *stream = t->client_conn->stream;
  size_t accepted = 0;
  while (accepted <= TRANSPORT_STREAM_ENDPOINT_MAX_VECTORS &&
         transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, "x", 1))
    accepted++;
  CHECK(accepted > 0 && accepted < TRANSPORT_STREAM_ENDPOINT_MAX_VECTORS);
  CHECK(quicly_get_state(stream->conn) < QUICLY_STATE_CLOSING);
  size_t retained = t->stats.stream_egress_bytes;
  size_t vectors = t->stats.stream_egress_vector_capacity;
  CHECK(acknowledge(stream, 1));
  CHECK(t->stats.stream_egress_bytes == retained &&
        t->stats.stream_egress_frames == accepted);
  CHECK(!transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, "x", 1));
  CHECK(acknowledge(stream, QLINQ_WIRE_FRAME_HEADER_SIZE));
  CHECK(t->stats.stream_egress_bytes < retained &&
        t->stats.stream_egress_vector_capacity == vectors);
  CHECK(transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, "x", 1));
  size_t controls = 0;
  while (controls < TRANSPORT_STREAM_ENDPOINT_MAX_VECTORS &&
         transport_stream_write_track_checkpoint_frame(stream, 1, 0, controls,
                                                       controls, false))
    controls++;
  CHECK(controls > 0 &&
        accepted + controls <= TRANSPORT_STREAM_ENDPOINT_MAX_VECTORS);
  CHECK(quicly_get_state(stream->conn) >= QUICLY_STATE_CLOSING &&
        t->stats.stream_control_failures == 1 &&
        t->stats.resource_limit_errors == 1);
  CHECK(QUICLY_ERROR_GET_ERROR_CODE(
            quicly_get_close_reason(stream->conn, NULL, NULL, NULL)) == 0x102);
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

static int byte_limits_and_recovery(void) {
  int failed = 0;
  transport_t *t = fixture();
  uint8_t *payload = malloc(TRANSPORT_MAX_RELIABLE_OBJECT_SIZE);
  CHECK(t && t->client_conn && payload);
  memset(payload, 0x5a, TRANSPORT_MAX_RELIABLE_OBJECT_SIZE);
  transport_conn_t *conn = t->client_conn;
  conn->authenticated = conn->protocol_ready = true;
  conn->negotiated_limits = t->limits;
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_RELIABLE,
                          .name = "pressure"};
  CHECK(transport_subscriptions_add(&conn->send_subscriptions, track.type,
                                    track.flags, track.name, 1));
  moq_object_t object = {.track_id = track,
                         .data = payload,
                         .size = TRANSPORT_MAX_RELIABLE_OBJECT_SIZE};
  CHECK(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_DELIVERED);
  quicly_stream_t *stream =
      transport_subscriptions_find(&conn->send_subscriptions, &track)->stream;
  CHECK(stream);
  CHECK(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_BACKPRESSURE);
  size_t retained = t->stats.stream_egress_bytes;
  CHECK(retained <= TRANSPORT_STREAM_MAX_BYTES);
  size_t frame_size = QLINQ_WIRE_FRAME_HEADER_SIZE +
                      QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE + object.size;
  CHECK(acknowledge(stream, frame_size / 2));
  CHECK(t->stats.stream_egress_bytes == retained);
  CHECK(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_BACKPRESSURE);
  CHECK(acknowledge(stream, frame_size - frame_size / 2));
  CHECK(t->stats.stream_egress_bytes == 0 &&
        t->stats.stream_egress_vector_capacity == 0);
  CHECK(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_DELIVERED);
  /* Open independent streams so endpoint pressure cannot be mistaken for the
   * per-stream byte or frame limits. No socket service/ACKs occur in this part.
   */
  size_t streams = 1;
  while (streams < 32) {
    CHECK(quicly_open_stream(conn->quic, &stream, 1) == 0);
    if (!transport_stream_write_object_frame(stream, 1, &object))
      break;
    streams++;
  }
  CHECK(streams >= 8 && streams < 32);
  CHECK(t->stats.stream_egress_bytes <= TRANSPORT_STREAM_ENDPOINT_MAX_BYTES);
  CHECK(quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING);
  CHECK(transport_stream_write_track_checkpoint_frame(conn->stream, 1, 0, 0, 0,
                                                      false));
cleanup:
  free(payload);
  if (!dispose(t))
    failed = 1;
  return failed;
}

static int endpoint_vector_limit(void) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn);
  size_t accepted = 0;
  for (size_t n = 0; n < 32; n++) {
    quicly_stream_t *stream;
    CHECK(quicly_open_stream(t->client_conn->quic, &stream, 1) == 0);
    size_t before = accepted;
    for (size_t i = 0; i < TRANSPORT_STREAM_ENDPOINT_MAX_VECTORS; i++) {
      if (!transport_stream_write_frame(stream, QLINQ_WIRE_TRACK_OBJECT, "x",
                                        1))
        break;
      accepted++;
    }
    if (accepted == before)
      break;
  }
  CHECK(accepted > 256 && accepted < TRANSPORT_STREAM_ENDPOINT_MAX_VECTORS);
  CHECK(t->stats.stream_egress_bytes < 1024 * 1024 &&
        t->stats.stream_egress_vector_capacity <=
            TRANSPORT_STREAM_ENDPOINT_MAX_VECTORS);
  CHECK(transport_stream_write_track_checkpoint_frame(t->client_conn->stream, 1,
                                                      0, 0, 0, false));
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

static int vector_capacity_compaction(void) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn && t->client_conn->stream);
  quicly_stream_t *stream = t->client_conn->stream;
  const size_t frame_size = QLINQ_WIRE_FRAME_HEADER_SIZE + 1;
  for (size_t i = 0; i < 129; i++)
    CHECK(transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, "x", 1));
  CHECK(t->stats.stream_egress_frames == 129 &&
        t->stats.stream_egress_vector_capacity == 256);
  CHECK(acknowledge(stream, 120 * frame_size));
  CHECK(t->stats.stream_egress_frames == 9 &&
        t->stats.stream_egress_vector_capacity == 16);
  CHECK(acknowledge(stream, 9 * frame_size));
  CHECK(t->stats.stream_egress_frames == 0 &&
        t->stats.stream_egress_vector_capacity == 0);
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

static int configurable_limits(void) {
  int failed = 0;
  transport_t *t = NULL;
  transport_limits_t requested = {
      .max_reliable_object_size = 64U * 1024U,
      .max_stream_egress_bytes = 128U * 1024U + 1024U,
      .max_total_stream_egress_bytes =
          128U * 1024U + 1024U +
          TRANSPORT_STREAM_ENDPOINT_CONTROL_BYTE_RESERVE};
  transport_limits_t resolved;
  char error[256];
  CHECK(transport_limits_resolve(&requested, &resolved, error, sizeof(error)));
  requested.max_stream_egress_bytes--;
  CHECK(!transport_limits_resolve(&requested, &resolved, error, sizeof(error)));
  requested.max_stream_egress_bytes++;
  requested.max_total_stream_egress_bytes--;
  CHECK(!transport_limits_resolve(&requested, &resolved, error, sizeof(error)));
  requested.max_total_stream_egress_bytes++;
  transport_config_t config = {.bind_hosts = {"127.0.0.1"},
                               .num_bind_hosts = 1,
                               .remote_hosts = {"127.0.0.1"},
                               .num_remote_hosts = 1,
                               .port = 19869,
                               .allow_insecure_peer = true,
                               .callback = ignore_event,
                               .limits = requested};
  t = transport_create(&config);
  CHECK(t && t->client_conn && t->client_conn->stream);
  quicly_stream_t *stream;
  CHECK(quicly_open_stream(t->client_conn->quic, &stream, 1) == 0);
  uint8_t payload[64U * 1024U] = {0};
  CHECK(transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, payload,
                                     sizeof(payload)));
  CHECK(transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, payload,
                                     sizeof(payload)));
  CHECK(!transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, payload,
                                      sizeof(payload)));
  CHECK(t->stats.stream_egress_bytes <= requested.max_stream_egress_bytes);
  CHECK(acknowledge(stream,
                    2U * (sizeof(payload) + QLINQ_WIRE_FRAME_HEADER_SIZE)));
  CHECK(t->stats.stream_egress_bytes == 0);
  CHECK(transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, payload,
                                     sizeof(payload)));
cleanup:
  if (t && !dispose(t))
    failed = 1;
  return failed;
}

/* Tiny frames should scale with the configured byte budget, rather than
 * stopping at the old 256-frame cap. These sizes reach the frame bound before
 * either the retained-byte or endpoint-vector budget is exhausted. */
static int configured_frame_capacity(size_t stream_bytes, size_t expected) {
  int failed = 0;
  transport_config_t config = {
      .bind_hosts = {"127.0.0.1"},
      .num_bind_hosts = 1,
      .remote_hosts = {"127.0.0.1"},
      .num_remote_hosts = 1,
      .port = 19869,
      .allow_insecure_peer = true,
      .callback = ignore_event,
      .limits = {.max_reliable_object_size = 1024,
                 .max_stream_egress_bytes = stream_bytes}};
  transport_t *t = transport_create(&config);
  CHECK(t && t->client_conn);
  quicly_stream_t *stream;
  CHECK(quicly_open_stream(t->client_conn->quic, &stream, 1) == 0);
  for (size_t i = 0; i < expected; i++)
    CHECK(transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, "x", 1));
  CHECK(!transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, "x", 1));
  CHECK(t->stats.stream_egress_frames == expected &&
        t->stats.stream_egress_bytes < stream_bytes);
  CHECK(acknowledge(stream, QLINQ_WIRE_FRAME_HEADER_SIZE + 1));
  CHECK(transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, "x", 1));
  CHECK(transport_stream_write_track_checkpoint_frame(t->client_conn->stream, 1,
                                                      0, 0, 0, false));
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

static int retained_nack_retries(bool rateless) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn && t->client_conn->stream);
  transport_conn_t *conn = t->client_conn;
  quicly_stream_t *stream = conn->stream;
  quicly_sendbuf_t *sb =
      &((transport_stream_ctx_t *)stream->data)->streambuf.egress;
  uint8_t flags =
      MOQ_TRACK_FLAG_FEC_ENABLED | (rateless ? MOQ_TRACK_FLAG_FEC_RATELESS : 0);
  conn->peer_capabilities |= QLINQ_WIRE_CAP_RATELESS_REPAIR;
  moq_track_id_t track = {
      .type = MOQ_TRACK_DATA, .flags = flags, .name = "nack-one"};
  CHECK(transport_get_effective_repair_mode(t, conn, &track) ==
        (rateless ? TRANSPORT_REPAIR_MODE_RATELESS
                  : TRANSPORT_REPAIR_MODE_INDEXED));
  CHECK(transport_subscriptions_add(&conn->receive_subscriptions,
                                    MOQ_TRACK_DATA, flags, "nack-one", 1));
  CHECK(transport_subscriptions_add(&conn->receive_subscriptions,
                                    MOQ_TRACK_DATA, flags, "nack-two", 2));
  CHECK(transport_recovery_send_nack(conn, 1, 7, 11, NULL, 0, true));
  size_t first_size = sb->bytes_written;
  CHECK(t->stats.stream_egress_frames == 1);
  /* Repeated timer callbacks cannot multiply a request which has not had a
   * chance to leave this reliable stream. No packet service occurs here. */
  for (size_t i = 0; i < 512; i++) {
    CHECK(transport_recovery_send_nack(conn, 1, 7, 11, NULL, 0, true));
    CHECK(t->stats.stream_egress_frames == 1 &&
          sb->bytes_written == first_size);
  }
  CHECK(t->stats.repair_requests_sent == 1);
  CHECK(t->stats.repair_requests_coalesced == 512 &&
        t->stats.repair_requests_deferred == 0);
  fprintf(stderr,
          "%s: 512 unsent retries retained %zu frame, %zu vector slots, %zu "
          "bytes\n",
          rateless ? "rateless" : "fixed", t->stats.stream_egress_frames,
          t->stats.stream_egress_vector_capacity, t->stats.stream_egress_bytes);
  CHECK(quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING);
  /* QUIC owns reliable retransmission until the request is acknowledged.
   * Repeated application timers must not append another identical frame even
   * when packet service has marked every queued byte as transmitted. */
  for (size_t i = 0; i < 512; i++) {
    stream->sendstate.size_inflight = sb->bytes_written;
    CHECK(transport_recovery_send_nack(conn, 1, 7, 11, NULL, 0, true));
    CHECK(t->stats.stream_egress_frames == 1 &&
          sb->bytes_written == first_size);
  }
  CHECK(t->stats.repair_requests_sent == 1 &&
        t->stats.repair_requests_coalesced == 1024);
  /* A partial ACK retains the entire original frame and must still coalesce. */
  CHECK(acknowledge(stream, 1));
  CHECK(transport_recovery_send_nack(conn, 1, 7, 11, NULL, 0, true));
  CHECK(t->stats.stream_egress_frames == 1);
  CHECK(acknowledge(stream, first_size - 1));
  CHECK(t->stats.stream_egress_bytes == 0 &&
        t->stats.stream_egress_vector_capacity == 0);
  /* The request arrived, but its repair response can be lost. After QUIC
   * releases that request, the existing application retry can enqueue again. */
  CHECK(transport_recovery_send_nack(conn, 1, 7, 11, NULL, 0, true));
  CHECK(t->stats.repair_requests_sent == 2 &&
        t->stats.stream_egress_frames == 1);
  stream->sendstate.size_inflight = sb->bytes_written;
  CHECK(acknowledge(stream, first_size));
  CHECK(t->stats.stream_egress_bytes == 0 &&
        t->stats.stream_egress_vector_capacity == 0);
  CHECK(transport_recovery_send_nack(conn, 1, 7, 11, NULL, 0, true));
  CHECK(t->stats.repair_requests_sent == 3);
  /* Different aliases, groups, objects, request scopes and missing symbols
   * are independent requests, even when none has been transmitted. */
  CHECK(transport_recovery_send_nack(conn, 2, 7, 11, NULL, 0, true));
  CHECK(transport_recovery_send_nack(conn, 1, 8, 11, NULL, 0, true));
  CHECK(transport_recovery_send_nack(conn, 1, 7, 12, NULL, 0, true));
  uint16_t missing[] = {3, 5};
  CHECK(transport_recovery_send_nack(conn, 1, 7, 11, rateless ? NULL : missing,
                                     2, false));
  missing[1] = 6;
  CHECK(transport_recovery_send_nack(conn, 1, 7, 11, rateless ? NULL : missing,
                                     rateless ? 3 : 2, false));
  CHECK(t->stats.repair_requests_sent == 8 &&
        t->stats.stream_egress_frames == 6);
  uint16_t maximum_missing[QLINQ_WIRE_MAX_NACK_SYMBOLS];
  for (size_t i = 0; i < QLINQ_WIRE_MAX_NACK_SYMBOLS; i++)
    maximum_missing[i] = (uint16_t)i;
  const uint16_t *indices = rateless ? NULL : maximum_missing;
  CHECK(!transport_recovery_send_nack(conn, 1, 7, 13, indices,
                                      QLINQ_WIRE_MAX_NACK_SYMBOLS + 1U, false));
  CHECK(t->stats.repair_requests_sent == 8 &&
        t->stats.stream_egress_frames == 6);
  CHECK(transport_recovery_send_nack(conn, 1, 7, 13, indices,
                                     QLINQ_WIRE_MAX_NACK_SYMBOLS, false));
  uint8_t payload[20U + 2U * QLINQ_WIRE_MAX_NACK_SYMBOLS];
  size_t written = 0;
  CHECK(qlinq_wire_encode_nack(payload, sizeof(payload), 1,
                               rateless ? QLINQ_WIRE_NACK_RATELESS : 0, 7, 13,
                               indices, QLINQ_WIRE_MAX_NACK_SYMBOLS,
                               &written) == QLINQ_WIRE_OK);
  CHECK(written == (rateless ? 20U : sizeof(payload)) &&
        transport_stream_has_retained_frame(stream, QLINQ_WIRE_NACK, payload,
                                            written));
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

/* QUIC can ACK a later STREAM range before its prefix arrives. That frame
 * remains retained and the peer cannot parse it until the prefix is repaired.
 */
static int retained_nack_ack_gap(bool rateless) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn && t->client_conn->stream);
  transport_conn_t *conn = t->client_conn;
  conn->peer_capabilities |= QLINQ_WIRE_CAP_RATELESS_REPAIR;
  uint8_t flags =
      MOQ_TRACK_FLAG_FEC_ENABLED | (rateless ? MOQ_TRACK_FLAG_FEC_RATELESS : 0);
  CHECK(transport_subscriptions_add(&conn->receive_subscriptions,
                                    MOQ_TRACK_DATA, flags, "ack-gap", 1));
  moq_track_id_t track = {
      .type = MOQ_TRACK_DATA, .flags = flags, .name = "ack-gap"};
  CHECK(transport_get_effective_repair_mode(t, conn, &track) ==
        (rateless ? TRANSPORT_REPAIR_MODE_RATELESS
                  : TRANSPORT_REPAIR_MODE_INDEXED));
  quicly_stream_t *stream = conn->stream;
  quicly_sendbuf_t *sb =
      &((transport_stream_ctx_t *)stream->data)->streambuf.egress;
  CHECK(transport_recovery_send_nack(conn, 1, 7, 11, NULL, 0, true));
  size_t first_size = sb->bytes_written;
  CHECK(transport_recovery_send_nack(conn, 1, 7, 12, NULL, 0, true));
  stream->sendstate.size_inflight = sb->bytes_written;
  quicly_sendstate_sent_t later = {.start = first_size,
                                   .end = sb->bytes_written};
  size_t shift = 0;
  CHECK(quicly_sendstate_acked(&stream->sendstate, &later, &shift) == 0 &&
        shift == 0);
  stream->callbacks->on_send_shift(stream, shift);
  CHECK(transport_recovery_send_nack(conn, 1, 7, 12, NULL, 0, true));
  CHECK(t->stats.stream_egress_frames == 2 &&
        t->stats.repair_requests_sent == 2);
  CHECK(transport_recovery_send_nack(conn, 1, 7, 11, NULL, 0, true));
  CHECK(t->stats.stream_egress_frames == 2 &&
        t->stats.repair_requests_coalesced == 2);
  quicly_sendstate_sent_t first = {.start = 0, .end = first_size};
  CHECK(quicly_sendstate_acked(&stream->sendstate, &first, &shift) == 0 &&
        shift == sb->bytes_written);
  stream->callbacks->on_send_shift(stream, shift);
  CHECK(t->stats.stream_egress_frames == 0 &&
        t->stats.stream_egress_bytes == 0 &&
        t->stats.stream_egress_vector_capacity == 0);
  CHECK(transport_recovery_send_nack(conn, 1, 7, 12, NULL, 0, true));
  CHECK(t->stats.stream_egress_frames == 1 &&
        t->stats.repair_requests_sent == 3);
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

static int repair_pressure(bool endpoint, bool rateless) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn && t->client_conn->stream);
  transport_conn_t *conn = t->client_conn;
  conn->peer_capabilities |= QLINQ_WIRE_CAP_RATELESS_REPAIR;
  uint8_t flags =
      MOQ_TRACK_FLAG_FEC_ENABLED | (rateless ? MOQ_TRACK_FLAG_FEC_RATELESS : 0);
  CHECK(transport_subscriptions_add(&conn->receive_subscriptions,
                                    MOQ_TRACK_DATA, flags, "pressure", 1));
  moq_track_id_t track = {
      .type = MOQ_TRACK_DATA, .flags = flags, .name = "pressure"};
  CHECK(transport_get_effective_repair_mode(t, conn, &track) ==
        (rateless ? TRANSPORT_REPAIR_MODE_RATELESS
                  : TRANSPORT_REPAIR_MODE_INDEXED));
  quicly_stream_t *release = conn->stream;
  if (endpoint) {
    /* Fill independent streams to exhaust endpoint capacity while the actual
     * control stream is empty. This distinguishes endpoint and stream caps. */
    size_t total = 0;
    for (unsigned n = 0; n < 32; n++) {
      quicly_stream_t *stream;
      CHECK(quicly_open_stream(conn->quic, &stream, 1) == 0);
      if (n == 0)
        release = stream;
      size_t before = total;
      while (transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, "x", 1))
        total++;
      if (total == before)
        break;
    }
    CHECK(total > 256 && total <= TRANSPORT_STREAM_ENDPOINT_MAX_VECTORS);
  } else {
    size_t total = 0;
    while (
        transport_stream_write_frame(conn->stream, QLINQ_WIRE_UNICAST, "x", 1))
      total++;
    CHECK(total > 256 && total < TRANSPORT_STREAM_ENDPOINT_MAX_VECTORS);
  }
  size_t bytes = t->stats.stream_egress_bytes;
  size_t frames = t->stats.stream_egress_frames;
  size_t vectors = t->stats.stream_egress_vector_capacity;
  /* Repair timers own retry state. Queue pressure must neither consume the
   * essential-control reserve nor turn an unanswered request into a close. */
  for (unsigned n = 0; n < 512; n++) {
    CHECK(!transport_recovery_send_nack(conn, 1, 7, 11, NULL, 0, true));
    CHECK(t->stats.stream_egress_bytes == bytes &&
          t->stats.stream_egress_frames == frames &&
          t->stats.stream_egress_vector_capacity == vectors);
    CHECK(quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING);
  }
  CHECK(t->stats.repair_requests_sent == 0 &&
        t->stats.repair_requests_deferred == 512 &&
        t->stats.stream_control_failures == 0 &&
        t->stats.resource_limit_errors == 0);
  CHECK(transport_stream_write_track_checkpoint_frame(conn->stream, 1, 7, 0, 11,
                                                      false));
  quicly_sendbuf_t *sb =
      &((transport_stream_ctx_t *)release->data)->streambuf.egress;
  CHECK(acknowledge(release, sb->bytes_written));
  CHECK(transport_recovery_send_nack(conn, 1, 7, 11, NULL, 0, true));
  CHECK(t->stats.repair_requests_sent == 1 &&
        t->stats.repair_requests_deferred == 512 &&
        t->stats.stream_control_failures == 0 &&
        t->stats.resource_limit_errors == 0);
  fprintf(stderr,
          "%s %s: 512 deferred requests, essential checkpoint accepted, retry "
          "after ACK accepted\n",
          endpoint ? "endpoint" : "stream", rateless ? "rateless" : "fixed");
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

static bool receive_bytes(quicly_stream_t *stream, const uint8_t *data,
                          size_t size) {
  size_t offset = transport_stream_ingress_get(stream).len;
  size_t received = size;
  if (quicly_recvstate_update(&stream->recvstate,
                              stream->recvstate.data_off + offset, &received, 0,
                              32) != 0 ||
      received != size)
    return false;
  stream->callbacks->on_receive(stream, offset, data, size);
  return true;
}

static bool receive_ingress_range(quicly_stream_t *stream, size_t off,
                                  const uint8_t *data, size_t size, bool fin) {
  size_t received = size;
  return quicly_recvstate_update(&stream->recvstate, off, &received, fin, 32) ==
             0 &&
         received == size &&
         transport_stream_ingress_receive(
             stream, off - stream->recvstate.data_off, data, size) == 0;
}

static bool ingress_matches(quicly_stream_t *stream, const uint8_t *data,
                            size_t off, size_t size) {
  ptls_iovec_t input = transport_stream_ingress_get(stream);
  return stream->recvstate.data_off == off && input.len == size &&
         (size == 0 || memcmp(input.base, data + off, size) == 0);
}

static int ingress_compaction(void) {
  int failed = 0;
  transport_t *t = fixture();
  uint8_t *data = malloc(98304);
  CHECK(t && t->client_conn && data);
  for (size_t i = 0; i < 98304; i++)
    data[i] = (uint8_t)(i * 37 + (i >> 8));
  quicly_stream_t *stream = NULL;
  CHECK(quicly_get_or_open_stream(t->client_conn->quic, 3, &stream) == 0 &&
        stream);
  transport_stream_ctx_t *ctx = stream->data;
  ptls_buffer_t *buffer = &ctx->streambuf.ingress;
  CHECK(receive_ingress_range(stream, 0, data, 4096, false));
  CHECK(receive_ingress_range(stream, 8192, data + 8192, 57344, false));
  CHECK(ingress_matches(stream, data, 0, 4096));
  /* Retire the available prefix without moving the large sparse tail. QUIC
   * receives consumption credit immediately, before physical compaction. */
  transport_stream_ingress_shift(stream, 4096);
  CHECK(ctx->ingress_prefix == 4096 && buffer->off == 65536 &&
        ingress_matches(stream, data, 4096, 0));
  CHECK(receive_ingress_range(stream, 4096, data + 4096, 4096, false));
  CHECK(ingress_matches(stream, data, 4096, 61440));
  transport_stream_ingress_shift(stream, 8192);
  CHECK(ctx->ingress_prefix == 12288 &&
        ingress_matches(stream, data, 12288, 53248));
  /* Growing an allocation with a retained prefix must preserve both offsets
   * and bytes. The next shift crosses the amortized compaction threshold. */
  size_t capacity = buffer->capacity;
  CHECK(receive_ingress_range(stream, 65536, data + 65536, 32768, false));
  CHECK(buffer->capacity > capacity &&
        ingress_matches(stream, data, 12288, 86016));
  transport_stream_ingress_shift(stream, 40960);
  CHECK(ctx->ingress_prefix == 0 && buffer->off == 45056 &&
        ingress_matches(stream, data, 53248, 45056));
  /* FIN uses the physical buffer extent in Quicly; the virtual view must
   * exclude consumed bytes even when receive ranges become empty. */
  transport_stream_ingress_shift(stream, 4096);
  CHECK(ctx->ingress_prefix == 4096);
  CHECK(receive_ingress_range(stream, 98304, NULL, 0, true));
  CHECK(ingress_matches(stream, data, 57344, 40960));
  transport_stream_ingress_shift(stream, 40960);
  CHECK(ctx->ingress_prefix == 0 && buffer->off == 0 &&
        ingress_matches(stream, data, 98304, 0));
  CHECK(transport_stream_ingress_receive(stream, SIZE_MAX, data, 1) == -1 &&
        quicly_get_state(stream->conn) >= QUICLY_STATE_CLOSING);
  CHECK(t->stats.resource_limit_errors == 1 &&
        QUICLY_ERROR_GET_ERROR_CODE(
            quicly_get_close_reason(stream->conn, NULL, NULL, NULL)) == 0x102);
cleanup:
  free(data);
  if (!dispose(t))
    failed = 1;
  return failed;
}

static bool receive_control(quicly_stream_t *stream, uint8_t type,
                            const uint8_t *payload, size_t payload_size) {
  uint8_t frame[128];
  size_t size = QLINQ_WIRE_FRAME_HEADER_SIZE + payload_size;
  if (size > sizeof(frame) ||
      qlinq_wire_encode_frame_header(frame, sizeof(frame), type, payload_size,
                                     TRANSPORT_WIRE_MAX_STREAM_PAYLOAD) !=
          QLINQ_WIRE_OK)
    return false;
  memcpy(frame + QLINQ_WIRE_FRAME_HEADER_SIZE, payload, payload_size);
  if (!receive_bytes(stream, frame, size))
    return false;
  if (quicly_get_state(stream->conn) >= QUICLY_STATE_CLOSING) {
    const char *reason = NULL;
    (void)quicly_get_close_reason(stream->conn, NULL, &reason, NULL);
    fprintf(stderr, "control receive closed: %s\n",
            reason ? reason : "unknown");
    return false;
  }
  return true;
}

/* repair queue preflight when datagram queue is full */
static int repair_queue_preflight(size_t queued, uint16_t first_esi) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn && t->client_conn->stream);
  transport_conn_t *conn = t->client_conn;
  conn->authenticated = conn->protocol_ready = conn->hello_received = true;
  conn->negotiated_limits = t->limits;
  conn->peer_capabilities |= QLINQ_WIRE_CAP_RATELESS_REPAIR;
  CHECK(transport_subscriptions_add(&conn->send_subscriptions, MOQ_TRACK_DATA,
                                    MOQ_TRACK_FLAG_FEC_RATELESS, "repair", 7));

  uint8_t data[32008] = {0};
  moq_object_t object = {.track_id = {.type = MOQ_TRACK_DATA,
                                      .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                                      .name = "repair"},
                         .group_id = 3,
                         .object_id = 9,
                         .data = data,
                         .size = sizeof(data)};
  CHECK(
      transport_sent_cache_store(&t->sent_cache, &object, 24, 24, 1372, false));
  sent_object_cache_t *cached =
      transport_sent_cache_find(&t->sent_cache, &object.track_id, 3, 9);
  CHECK(cached);
  cached->next_repair_symbol = first_esi;
  const uint8_t filler = 0;
  for (size_t i = 0; i < queued; i++)
    CHECK(transport_queue_datagram(conn, 0, ptls_iovec_init(&filler, 1)));
  CHECK(quicly_get_num_datagram_frames_path(conn->quic, 0) == queued);

  uint8_t payload[32];
  size_t payload_size;
  CHECK(qlinq_wire_encode_nack(payload, sizeof(payload), 7,
                               QLINQ_WIRE_NACK_RATELESS |
                                   QLINQ_WIRE_NACK_WHOLE_OBJECT,
                               3, 9, NULL, 0, &payload_size) == QLINQ_WIRE_OK);
  bool fallback = first_esi == QLINQ_FEC_MAX_TOTAL_SYMBOLS;
  size_t admitted = QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY - queued;
  for (size_t request = 0; request < 2; request++) {
    /* start full so token spending does not depend on clock */
    uint64_t peer_tokens = t->limits.max_repair_requests_per_second * 1000U;
    uint64_t aggregate_tokens =
        t->limits.max_aggregate_repair_requests_per_second * 1000U;
    int64_t now = transport_get_time_ms();
    conn->repair_request_limiter =
        (transport_repair_limiter_t){peer_tokens, now};
    t->aggregate_repair_limiter =
        (transport_repair_limiter_t){aggregate_tokens, now};
    CHECK(
        receive_control(conn->stream, QLINQ_WIRE_NACK, payload, payload_size));
    CHECK(conn->repair_request_limiter.tokens_milli == peer_tokens - 1000U &&
          t->aggregate_repair_limiter.tokens_milli == aggregate_tokens - 1000U);
    CHECK(quicly_get_num_datagram_frames_path(conn->quic, 0) ==
          QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY);
    CHECK(cached->next_repair_symbol == first_esi + (fallback ? 0 : admitted) &&
          cached->next_systematic_repair_symbol == (fallback ? admitted : 0));
    CHECK(t->stats.repair_requests_received == request + 1 &&
          t->stats.repair_rateless_requests_received == request + 1 &&
          t->stats.repair_symbols_sent == admitted &&
          t->stats.repair_rateless_symbols_sent == admitted &&
          t->stats.repair_rateless_exhausted == (fallback ? request + 1 : 0) &&
          t->stats.repair_requests_throttled == 0 &&
          t->stats.repair_requests_aggregate_throttled == 0 &&
          t->stats.protocol_errors == 0);
    size_t fec_contexts = 0;
    for (size_t i = 0; i < TRANSPORT_FEC_CACHE_SIZE; i++) {
      const transport_fec_cache_entry_t *entry = &t->fec_cache.entries[i];
      if (entry->fec) {
        fec_contexts++;
        CHECK(!fallback && admitted == 1 && entry->type == FEC_RAPTORQ &&
              entry->data_symbols == 24 && entry->parity_symbols == 24 &&
              entry->symbol_size == 1372);
      }
    }
    /* second request after partial admission does not re-encode */
    CHECK(fec_contexts == (!fallback && admitted == 1 ? 1U : 0U));
  }
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

static void count_objects(void *data, const transport_event_t *event) {
  if (event->type == TRANSPORT_EVENT_OBJECT)
    (*(size_t *)data)++;
}

typedef struct {
  transport_t *transport;
  size_t received;
  bool invalid;
} track_dispatch_state_t;

static void check_track_object(void *data, const transport_event_t *event) {
  if (event->type != TRANSPORT_EVENT_OBJECT)
    return;
  track_dispatch_state_t *state = data;
  const moq_object_t *object = &event->object;
  state->invalid |=
      object->group_id != 7 || object->object_id != state->received ||
      object->size != 8192 || strcmp(event->track_id.name, "burst") != 0;
  /* Publishing is allowed from a callback and must leave its borrowed input
   * valid until return, even with later objects waiting in the same buffer. */
  if (!transport_send_unicast(state->transport, event->conn, object->data,
                              object->size))
    state->invalid = true;
  for (size_t i = 0; i < object->size; i++)
    state->invalid |= object->data[i] != (uint8_t)state->received;
  state->received++;
}

static int track_dispatch_consumption(void) {
  int failed = 0;
  const size_t frame_size =
      QLINQ_WIRE_FRAME_HEADER_SIZE + QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE + 8192;
  uint8_t *frames = malloc(131 * frame_size);
  transport_t *t = fixture();
  CHECK(t && t->client_conn && frames);
  track_dispatch_state_t state = {.transport = t};
  t->callback = check_track_object;
  t->user_data = &state;
  transport_conn_t *conn = t->client_conn;
  conn->authenticated = conn->protocol_ready = true;
  conn->negotiated_limits = t->limits;
  CHECK(transport_subscriptions_add(&conn->receive_subscriptions,
                                    MOQ_TRACK_DATA, MOQ_TRACK_FLAG_RELIABLE,
                                    "burst", 7));
  quicly_stream_t *stream = NULL;
  CHECK(quicly_get_or_open_stream(conn->quic, 3, &stream) == 0 && stream);
  for (size_t i = 0; i < 131; i++) {
    uint8_t *frame = frames + i * frame_size;
    qlinq_wire_track_object_t object = {
        .alias = i == 130 ? 8 : 7, .group_id = 7, .object_id = i};
    CHECK(qlinq_wire_encode_frame_header(
              frame, frame_size, QLINQ_WIRE_TRACK_OBJECT,
              frame_size - QLINQ_WIRE_FRAME_HEADER_SIZE,
              TRANSPORT_WIRE_MAX_STREAM_PAYLOAD) == QLINQ_WIRE_OK);
    CHECK(qlinq_wire_encode_track_object(frame + QLINQ_WIRE_FRAME_HEADER_SIZE,
                                         QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE,
                                         &object) == QLINQ_WIRE_OK);
    memset(frame + frame_size - 8192, (uint8_t)i, 8192);
  }
  /* A large contiguous burst ends first in a partial header, then in a
   * partial payload. Neither may repeat callbacks for the consumed prefix. */
  size_t first = 128 * frame_size + 3;
  CHECK(receive_bytes(stream, frames, first));
  CHECK(!state.invalid && state.received == 128 &&
        stream->recvstate.data_off == 128 * frame_size &&
        transport_stream_ingress_get(stream).len == 3);
  size_t second = frame_size - 8;
  CHECK(receive_bytes(stream, frames + first, second));
  ptls_iovec_t tail = transport_stream_ingress_get(stream);
  CHECK(!state.invalid && state.received == 128 && tail.len == frame_size - 5 &&
        memcmp(tail.base, frames + 128 * frame_size, tail.len) == 0);
  /* An invalid alias after two complete objects must close the connection
   * while retiring only the accepted prefix, including the previous tail. */
  CHECK(receive_bytes(stream, frames + first + second, 2 * frame_size + 5));
  tail = transport_stream_ingress_get(stream);
  CHECK(!state.invalid && state.received == 130 &&
        stream->recvstate.data_off == 130 * frame_size &&
        tail.len == frame_size &&
        memcmp(tail.base, frames + 130 * frame_size, tail.len) == 0);
  CHECK(quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING &&
        t->stats.protocol_errors == 1 &&
        t->stats.stream_frames_received == 131);
cleanup:
  free(frames);
  if (!dispose(t))
    failed = 1;
  return failed;
}

/* A fragmented request and the next frame must each be consumed exactly once,
 * including the NACK path that runs out of aggregate repair tokens. */
static int control_dispatch_consumption(void) {
  int failed = 0;
  transport_t *t = fixture();
  size_t delivered = 0;
  CHECK(t && t->client_conn && t->client_conn->stream);
  t->callback = count_objects;
  t->user_data = &delivered;
  transport_conn_t *conn = t->client_conn;
  conn->authenticated = conn->protocol_ready = conn->hello_received = true;
  conn->negotiated_limits = t->limits;
  t->limits.max_aggregate_repair_requests_per_second = 0;
  moq_object_t object = {.track_id = {.type = MOQ_TRACK_DATA,
                                      .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                                      .name = "throttled"},
                         .data = (const uint8_t *)"abc",
                         .size = 3};
  CHECK(transport_subscriptions_add(&conn->send_subscriptions,
                                    object.track_id.type, object.track_id.flags,
                                    object.track_id.name, 1));
  CHECK(transport_sent_cache_store(&t->sent_cache, &object, 1, 1, 3, false));
  uint8_t nack[20], frames[64];
  size_t nack_size = 0, first_size = 0, second_size = 0;
  CHECK(qlinq_wire_encode_nack(nack, sizeof(nack), 1,
                               QLINQ_WIRE_NACK_WHOLE_OBJECT, 0, 0, NULL, 0,
                               &nack_size) == QLINQ_WIRE_OK);
  CHECK(qlinq_wire_encode_frame(frames, sizeof(frames), QLINQ_WIRE_NACK, nack,
                                nack_size, TRANSPORT_WIRE_MAX_STREAM_PAYLOAD,
                                &first_size) == QLINQ_WIRE_OK);
  CHECK(qlinq_wire_encode_frame(frames + first_size,
                                sizeof(frames) - first_size, QLINQ_WIRE_UNICAST,
                                "x", 1, TRANSPORT_WIRE_MAX_STREAM_PAYLOAD,
                                &second_size) == QLINQ_WIRE_OK);
  CHECK(receive_bytes(conn->stream, frames, 3));
  CHECK(t->stats.stream_frames_received == 0 && delivered == 0);
  CHECK(receive_bytes(conn->stream, frames + 3, first_size + second_size - 3));
  CHECK(quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING &&
        transport_stream_ingress_get(conn->stream).len == 0);
  CHECK(t->stats.stream_frames_received == 2 && delivered == 1 &&
        t->stats.repair_requests_received == 1 &&
        t->stats.repair_requests_aggregate_throttled == 1 &&
        t->stats.protocol_errors == 0);
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

static int control_error_accounting(void) {
  static const struct {
    uint8_t type;
    bool hello, authenticated, valid_nack;
    uint64_t error;
    const char *reason;
  } cases[] = {{QLINQ_WIRE_UNICAST, false, false, false, 0x100,
                "protocol error: HELLO must be first"},
               {QLINQ_WIRE_NACK, true, false, false, 0x100,
                "protocol error: invalid nack"},
               {QLINQ_WIRE_NACK, true, false, true, 0x101, "unauthorized"},
               {QLINQ_WIRE_TRACK_CHECKPOINT, true, false, false, 0x100,
                "protocol error: invalid recovery checkpoint"},
               {QLINQ_WIRE_AUTH_RESPONSE, true, true, false, 0x100,
                "protocol error: invalid auth response"},
               {QLINQ_WIRE_UNICAST, true, false, false, 0x102,
                "protocol error: payload too large"},
               {QLINQ_WIRE_TRACK_END, true, true, false, 0x100,
                "protocol error: invalid track completion"}};
  int failed = 0;
  transport_t *t = NULL;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    t = fixture();
    CHECK(t && t->client_conn && t->client_conn->stream);
    transport_conn_t *conn = t->client_conn;
    conn->hello_received = cases[i].hello;
    conn->authenticated = cases[i].authenticated;
    conn->negotiated_limits = t->limits;
    if (cases[i].error == 0x102)
      conn->negotiated_limits.max_reliable_object_size = 0;
    uint8_t payload[20] = {2}, frame[64];
    size_t payload_size = 1, frame_size = 0;
    if (cases[i].valid_nack)
      CHECK(qlinq_wire_encode_nack(payload, sizeof(payload), 1,
                                   QLINQ_WIRE_NACK_WHOLE_OBJECT, 0, 0, NULL, 0,
                                   &payload_size) == QLINQ_WIRE_OK);
    CHECK(qlinq_wire_encode_frame(
              frame, sizeof(frame), cases[i].type, payload, payload_size,
              TRANSPORT_WIRE_MAX_STREAM_PAYLOAD, &frame_size) == QLINQ_WIRE_OK);
    CHECK(receive_bytes(conn->stream, frame, frame_size));
    const char *reason = NULL;
    quicly_error_t error =
        quicly_get_close_reason(conn->quic, NULL, &reason, NULL);
    CHECK(quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING &&
          QUICLY_ERROR_GET_ERROR_CODE(error) == cases[i].error && reason &&
          strcmp(reason, cases[i].reason) == 0);
    CHECK(t->stats.protocol_errors == (cases[i].error == 0x100) &&
          t->stats.resource_limit_errors == (cases[i].error == 0x102));
    bool released = dispose(t);
    t = NULL;
    CHECK(released);
  }
cleanup:
  if (t && !dispose(t))
    failed = 1;
  return failed;
}

static int checkpoint_retires_redundant_recovery(void) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn && t->client_conn->stream);
  transport_conn_t *conn = t->client_conn;
  conn->authenticated = conn->protocol_ready = true;
  conn->negotiated_limits = t->limits;
  conn->hello_received = true;
  conn->peer_capabilities |= QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS;
  CHECK(transport_subscriptions_add(&conn->receive_subscriptions,
                                    MOQ_TRACK_DATA, MOQ_TRACK_FLAG_FEC_RATELESS,
                                    "completion", 7));
  transport_object_gap_state_t *gap = transport_object_gap(conn, 7);
  gap->group_id = 3;
  gap->pending_base = 10;
  gap->pending_mask = 7;
  gap->last_seen = gap->largest_delivered = 11;
  gap->seen_initialized = gap->delivered_initialized = true;
  gap->delivered_mask[0] = 3;
  /* Covered, future, other-track and other-group partial objects coexist. */
  for (unsigned i = 0; i < 4; i++) {
    frame_assembler_t *a = &conn->assemblers[i];
    CHECK(transport_grow_assembler(t, a, 2, 32));
    a->track_id = i == 2 ? 8 : 7;
    a->group_id = i == 3 ? 4 : 3;
    a->object_id = i == 1 ? 13 : 11;
    a->total_symbols = 2;
  }
  size_t memory = t->assembler_memory_bytes;
  uint8_t payload[QLINQ_WIRE_TRACK_CHECKPOINT_SIZE];
  qlinq_wire_track_checkpoint_t checkpoint = {
      .alias = 7, .group_id = 3, .first_object_id = 10, .final_object_id = 11};
  CHECK(qlinq_wire_encode_track_checkpoint(payload, sizeof(payload),
                                           &checkpoint) == QLINQ_WIRE_OK);
  CHECK(receive_control(conn->stream, QLINQ_WIRE_TRACK_CHECKPOINT, payload,
                        sizeof(payload)));
  CHECK(t->stats.recovery_checkpoint_acks_sent == 1 && gap->pending_mask == 4);
  CHECK(conn->assemblers[0].total_symbols == 0 &&
        t->assembler_memory_bytes < memory);
  for (unsigned i = 1; i < 4; i++)
    CHECK(conn->assemblers[i].total_symbols == 2);
  /* A repeated completion also retires stale duplicates behind its watermark.
   */
  gap->pending_mask = 7;
  CHECK(transport_grow_assembler(t, &conn->assemblers[0], 2, 32));
  conn->assemblers[0].track_id = 7;
  conn->assemblers[0].group_id = 3;
  conn->assemblers[0].object_id = 11;
  conn->assemblers[0].total_symbols = 2;
  uint8_t end_payload[QLINQ_WIRE_TRACK_END_SIZE];
  qlinq_wire_track_end_t end = {
      .alias = 7, .group_id = 3, .final_object_id = 11};
  CHECK(qlinq_wire_encode_track_end(end_payload, sizeof(end_payload), &end) ==
        QLINQ_WIRE_OK);
  CHECK(receive_control(conn->stream, QLINQ_WIRE_TRACK_END, end_payload,
                        sizeof(end_payload)));
  CHECK(t->stats.recovery_checkpoint_acks_sent == 2 && gap->pending_mask == 4 &&
        conn->assemblers[0].total_symbols == 0);
  /* An incomplete next window retains recovery until the actual data arrives.
   */
  checkpoint.first_object_id = checkpoint.final_object_id = 12;
  CHECK(qlinq_wire_encode_track_checkpoint(payload, sizeof(payload),
                                           &checkpoint) == QLINQ_WIRE_OK);
  CHECK(receive_control(conn->stream, QLINQ_WIRE_TRACK_CHECKPOINT, payload,
                        sizeof(payload)));
  CHECK(t->stats.recovery_checkpoint_acks_sent == 2 && gap->pending_mask == 4);
  uint8_t datagram[QLINQ_WIRE_FEC_HEADER_SIZE + 3] = {0};
  qlinq_wire_fec_header_t header = {.alias = 7,
                                    .group_id = 3,
                                    .object_id = 12,
                                    .total_symbols = 1,
                                    .data_symbols = 1,
                                    .symbol_size = 3,
                                    .original_size = 3};
  CHECK(qlinq_wire_encode_fec_header(datagram, sizeof(datagram), &header) ==
        QLINQ_WIRE_OK);
  memcpy(datagram + QLINQ_WIRE_FEC_HEADER_SIZE, "abc", 3);
  t->receive_datagram.cb(&t->receive_datagram, conn->quic,
                         ptls_iovec_init(datagram, sizeof(datagram)));
  CHECK(t->stats.recovery_checkpoint_acks_sent == 3 && gap->pending_mask == 0);
  CHECK(t->stats.fec_objects_recovered == 1);
  for (unsigned i = 1; i < 4; i++)
    CHECK(conn->assemblers[i].total_symbols == 2);
cleanup:
  if (t) {
    for (size_t i = 0; i < t->limits.max_assemblers_per_connection; i++)
      transport_release_assembler(t, &t->client_conn->assemblers[i]);
    if (t->assembler_memory_bytes != 0 || !dispose(t))
      failed = 1;
  }
  return failed;
}

/* A burst of entirely absent objects must request distinct repairs in one
 * bounded sweep, including cursor wrap, without exceeding either token cap. */
static int checkpoint_repair_batch(size_t peer_limit, size_t aggregate_limit) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn && t->client_conn->stream);
  transport_conn_t *conn = t->client_conn;
  conn->authenticated = conn->protocol_ready = true;
  conn->negotiated_limits = t->limits;
  conn->peer_capabilities |= QLINQ_WIRE_CAP_RATELESS_REPAIR;
  t->limits.max_repair_requests_per_second = peer_limit;
  t->limits.max_aggregate_nack_requests_per_second = aggregate_limit;
  CHECK(transport_subscriptions_add(&conn->receive_subscriptions,
                                    MOQ_TRACK_DATA, MOQ_TRACK_FLAG_FEC_RATELESS,
                                    "batch", 7));
  transport_object_gap_state_t *gap = transport_object_gap(conn, 7);
  for (size_t n = 0; n < 2; n++) {
    gap->recovery_windows[n] =
        (transport_recovery_window_t){.active = true,
                                      .group_id = 3,
                                      .first_object_id = 32 * n,
                                      .final_object_id = 32 * n + 31,
                                      .missing_mask = UINT32_MAX,
                                      .cursor = 13};
  }
  size_t expected = peer_limit < aggregate_limit ? peer_limit : aggregate_limit;
  if (expected > 32)
    expected = 32;
  transport_tick(t);
  CHECK(t->stats.repair_requests_sent == expected);
  CHECK(t->stats.repair_whole_object_requests_sent == expected);
  CHECK(gap->recovery_windows[0].cursor == (13 + expected) % 32);
  CHECK(gap->recovery_windows[0].last_request_ms > 0);
  CHECK(gap->recovery_windows[1].last_request_ms == 0);
  for (size_t n = 0; n < 32; n++) {
    uint8_t payload[32];
    size_t written;
    CHECK(qlinq_wire_encode_nack(
              payload, sizeof(payload), 7,
              QLINQ_WIRE_NACK_RATELESS | QLINQ_WIRE_NACK_WHOLE_OBJECT, 3,
              (13 + n) % 32, NULL, 0, &written) == QLINQ_WIRE_OK);
    CHECK(transport_stream_has_retained_frame(conn->stream, QLINQ_WIRE_NACK,
                                              payload,
                                              written) == (n < expected));
  }
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

/* Completing several windows may happen behind a full retained control queue.
 * Keep the completed prefix and later acknowledge it with one cumulative frame.
 */
static int checkpoint_ack_pressure(void) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn && t->client_conn->stream);
  transport_conn_t *conn = t->client_conn;
  conn->authenticated = conn->protocol_ready = true;
  conn->negotiated_limits = t->limits;
  conn->peer_capabilities |= QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS;
  CHECK(transport_subscriptions_add(&conn->receive_subscriptions,
                                    MOQ_TRACK_DATA, MOQ_TRACK_FLAG_FEC_RATELESS,
                                    "ack-pressure", 7));
  transport_object_gap_state_t *gap = transport_object_gap(conn, 7);
  /* Deliberately reverse physical slots: ACK order is by object ID. */
  for (size_t i = 0; i < 5; i++) {
    gap->recovery_windows[4 - i] = (transport_recovery_window_t){
        .active = true,
        .group_id = 3,
        .first_object_id = 32 * i,
        .final_object_id = 32 * i + 31,
        .missing_mask = (i == 0 || i == 3) ? 1U : 0U};
  }
  gap->recovery_windows[0].group_id = 4; /* Must never merge distinct groups. */
  const size_t frame_size =
      QLINQ_WIRE_FRAME_HEADER_SIZE + QLINQ_WIRE_TRACK_CHECKPOINT_SIZE;
  while (transport_stream_can_accept(conn->stream, frame_size, false))
    CHECK(transport_stream_write_track_checkpoint_frame(conn->stream, 7, 3, 0,
                                                        31, false));
  CHECK(t->stats.stream_egress_frames > 256 &&
        t->stats.stream_egress_frames <= TRANSPORT_STREAM_ENDPOINT_MAX_VECTORS);
  uint8_t datagram[QLINQ_WIRE_FEC_HEADER_SIZE + 3] = {0};
  qlinq_wire_fec_header_t header = {.alias = 7,
                                    .group_id = 3,
                                    .object_id = 0,
                                    .total_symbols = 1,
                                    .data_symbols = 1,
                                    .symbol_size = 3,
                                    .original_size = 3};
  CHECK(qlinq_wire_encode_fec_header(datagram, sizeof(datagram), &header) ==
        QLINQ_WIRE_OK);
  memcpy(datagram + QLINQ_WIRE_FEC_HEADER_SIZE, "abc", 3);
  t->receive_datagram.cb(&t->receive_datagram, conn->quic,
                         ptls_iovec_init(datagram, sizeof(datagram)));
  CHECK(quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING);
  CHECK(t->stats.stream_control_failures == 0 &&
        t->stats.recovery_checkpoint_acks_sent == 0);
  CHECK(gap->recovery_windows[4].active &&
        gap->recovery_windows[4].missing_mask == 0);
  CHECK(transport_get_first_timeout(t) <=
        (int64_t)t->last_pathflow_update + 25);
  CHECK(
      acknowledge(conn->stream, frame_size)); /* Only one frame becomes free. */
  /* Empty feedback tokens cannot prevent completion acknowledgment. */
  t->aggregate_nack_limiter.last_refill_ms = transport_get_time_ms();
  t->aggregate_nack_limiter.tokens_milli = 0;
  transport_tick(t);
  CHECK(t->stats.recovery_checkpoint_acks_sent == 1 &&
        t->stats.stream_control_failures == 0);
  for (size_t i = 2; i < 5; i++)
    CHECK(!gap->recovery_windows[i].active);
  CHECK(gap->recovery_windows[1].active &&
        gap->recovery_windows[1].missing_mask == 1 &&
        gap->recovery_windows[0].active);
  uint8_t payload[QLINQ_WIRE_TRACK_CHECKPOINT_ACK_SIZE];
  qlinq_wire_track_checkpoint_ack_t ack = {
      .alias = 7, .group_id = 3, .final_object_id = 95};
  CHECK(qlinq_wire_encode_track_checkpoint_ack(payload, sizeof(payload),
                                               &ack) == QLINQ_WIRE_OK);
  CHECK(transport_stream_has_retained_frame(
      conn->stream, QLINQ_WIRE_TRACK_CHECKPOINT_ACK, payload, sizeof(payload)));
  transport_recovery_flush_acks(conn);
  CHECK(t->stats.recovery_checkpoint_acks_sent == 1);
  /* Once the gap closes, two groups require two separate cumulative ACKs. */
  header.object_id = 96;
  CHECK(qlinq_wire_encode_fec_header(datagram, sizeof(datagram), &header) ==
        QLINQ_WIRE_OK);
  t->receive_datagram.cb(&t->receive_datagram, conn->quic,
                         ptls_iovec_init(datagram, sizeof(datagram)));
  CHECK(quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING &&
        t->stats.recovery_checkpoint_acks_sent == 1);
  CHECK(acknowledge(conn->stream, 2 * frame_size));
  transport_recovery_flush_acks(conn);
  CHECK(t->stats.recovery_checkpoint_acks_sent == 3 &&
        !gap->recovery_windows[0].active && !gap->recovery_windows[1].active);
  for (unsigned group = 3; group <= 4; group++) {
    ack.group_id = group;
    ack.final_object_id = group == 3 ? 127 : 159;
    CHECK(qlinq_wire_encode_track_checkpoint_ack(payload, sizeof(payload),
                                                 &ack) == QLINQ_WIRE_OK);
    CHECK(transport_stream_has_retained_frame(conn->stream,
                                              QLINQ_WIRE_TRACK_CHECKPOINT_ACK,
                                              payload, sizeof(payload)));
  }
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

int main(void) {
  int failed =
      stream_emission_cursor() || ingress_compaction() ||
      track_dispatch_consumption() || control_dispatch_consumption() ||
      control_error_accounting() || checkpoint_ack_pressure() ||
      repair_queue_preflight(64, 24) || repair_queue_preflight(64, 1000) ||
      repair_queue_preflight(63, 24) ||
      repair_queue_preflight(64, QLINQ_FEC_MAX_TOTAL_SYMBOLS) ||
      repair_queue_preflight(63, QLINQ_FEC_MAX_TOTAL_SYMBOLS) ||
      checkpoint_repair_batch(1024, 1024) || checkpoint_repair_batch(2, 1024) ||
      checkpoint_repair_batch(1024, 3) || entry_limit_and_control_failure() ||
      byte_limits_and_recovery() || endpoint_vector_limit() ||
      vector_capacity_compaction() || configurable_limits() ||
      configured_frame_capacity(128U * 1024U, 2048) ||
      configured_frame_capacity(256U * 1024U, 4096) ||
      retained_nack_retries(false) || retained_nack_retries(true) ||
      retained_nack_ack_gap(false) || retained_nack_ack_gap(true) ||
      repair_pressure(false, false) || repair_pressure(false, true) ||
      repair_pressure(true, false) || repair_pressure(true, true) ||
      checkpoint_retires_redundant_recovery();
  if (!failed)
    puts("===STREAM BUDGET OK===");
  return failed;
}
