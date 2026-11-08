#include "transport_fixture.h"
#include "transport_paths.h"
#include "transport_publish.h"
#include "transport_protocol.h"
#include "transport_repair.h"
#include "transport_sim_host.h"
#include "transport_stream.h"
#include "transport_wire.h"

#include <stdio.h>

static void inject_nack(quicly_stream_t *stream, uint8_t alias,
                        uint64_t group_id, uint64_t object_id,
                        const uint16_t *missing, uint16_t count) {
  uint8_t nack[64], frame[128];
  size_t nack_len = 0;
  assert(qlinq_wire_encode_nack(nack, sizeof(nack), alias, 0, group_id,
                                object_id, missing, count,
                                &nack_len) == QLINQ_WIRE_OK);
  assert(qlinq_wire_encode_frame_header(
             frame, sizeof(frame), QLINQ_WIRE_NACK, nack_len,
             TRANSPORT_WIRE_MAX_STREAM_PAYLOAD) == QLINQ_WIRE_OK);
  memcpy(frame + QLINQ_WIRE_FRAME_HEADER_SIZE, nack, nack_len);
  size_t size = QLINQ_WIRE_FRAME_HEADER_SIZE + nack_len;
  size_t offset = transport_stream_ingress_get(stream).len;
  size_t received = size;
  uint64_t absolute_offset = stream->recvstate.data_off + offset;
  assert(quicly_recvstate_update(&stream->recvstate, &absolute_offset,
                                 &received, 0, UINT64_MAX) == 0 &&
         received == size);
  stream->callbacks->on_receive(stream, offset, frame, size);
}

static void check_constrained_multipath(void) {
  transport_fixture_t f = {0};
  f.server.server = true;
  transport_config_t config = {.bind_hosts = {"127.84.3.1", "127.84.4.1"},
                               .num_bind_hosts = 2,
                               .port = 19877,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .allow_insecure_peer = true,
                               .callback = fixture_event,
                               .user_data = &f.server};
  f.server.transport = transport_create(&config);
  assert(f.server.transport);
  config.bind_hosts[0] = "127.84.3.2";
  config.bind_hosts[1] = "127.84.4.2";
  config.remote_hosts[0] = "127.84.3.1";
  config.remote_hosts[1] = "127.84.4.1";
  config.num_remote_hosts = 2;
  config.user_data = &f.client;
  f.client.transport = transport_create(&config);
  assert(f.client.transport);

  transport_publication_path_t paths[TRANSPORT_MAX_PATHS];
  size_t path_count = 0;
  for (size_t attempt = 0; attempt < 2000; attempt++) {
    fixture_tick(&f);
    if (f.server.authenticated && f.client.authenticated) {
      path_count = transport_publish_collect_paths(
          f.server.transport, f.server.conn, 1200, 0,
          transport_get_monotonic_ns(), paths);
      if (path_count == 2)
        break;
    }
  }
  assert(path_count == 2);

  moq_track_id_t track = {.type = MOQ_TRACK_VIDEO,
                          .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                          .name = "partial-capacity"};
  fixture_subscribe(&f, &f.client, track);
  for (size_t i = 0; i < 100; i++)
    fixture_tick(&f);

  transport_t *t = f.server.transport;
  transport_conn_t *conn = f.server.conn;
  qlinq_repair_policy_t reactive = {.present = QLINQ_REPAIR_REACTIVE,
                                    .reactive_repair = true};
  assert(transport_set_track_repair_policy(t, &track, &reactive));

  /* leave 2 datagram slots on each path so a 3-symbol object must split */
  uint8_t ignored = 0xff;
  ptls_iovec_t frame = ptls_iovec_init(&ignored, 1);
  for (size_t p = 0; p < 2; p++) {
    while (quicly_get_num_datagram_frames_path(conn->quic, paths[p].quic) <
           QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY - 2U)
      assert(transport_queue_datagram(conn, paths[p].quic, frame));
  }
  assert(transport_mock_path_state(t, 0, 100000, 10, 0));
  assert(transport_mock_path_state(t, 1, 20000, 10, 0));

  uint8_t payload[2000];
  memset(payload, 0x3c, sizeof(payload));
  moq_object_t object = {.track_id = track,
                         .group_id = 1,
                         .object_id = 0,
                         .data = payload,
                         .size = sizeof(payload)};
  assert(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_DELIVERED);
  assert(quicly_get_num_datagram_frames_path(conn->quic, paths[0].quic) ==
         QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY);
  assert(quicly_get_num_datagram_frames_path(conn->quic, paths[1].quic) ==
         QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY - 1U);
  fixture_receive(&f, &f.client, 1);
  assert(f.client.payload_size == sizeof(payload) &&
         memcmp(f.client.payload, payload, sizeof(payload)) == 0);

  /* repair responses must avoid a degraded path when a healthy path exists */
  assert(transport_sent_cache_find(&t->sent_cache, &track, 1, 0));
  uint8_t alias = 0;
  assert(transport_subscriptions_find_alias(&conn->send_subscriptions, &track,
                                            &alias) == 0);
  assert(transport_mock_path_state(t, 0, 100000, 10, 0.95f));
  assert(transport_mock_path_state(t, 1, 100000, 10, 0.0f));
  size_t p0_before =
      quicly_get_num_datagram_frames_path(conn->quic, paths[0].quic);
  size_t p1_before =
      quicly_get_num_datagram_frames_path(conn->quic, paths[1].quic);
  const uint16_t missing[2] = {0, 1};
  inject_nack(conn->stream, alias, 1, 0, missing, 2);
  assert(quicly_get_num_datagram_frames_path(conn->quic, paths[0].quic) ==
         p0_before);
  assert(quicly_get_num_datagram_frames_path(conn->quic, paths[1].quic) ==
         p1_before + 2U);

  /* deadline-aware publication and repair must exclude paths above max age */
  for (size_t i = 0; i < 20; i++)
    fixture_tick(&f);
  qlinq_repair_policy_t deadline_policy = {.present = QLINQ_REPAIR_REACTIVE |
                                                      QLINQ_REPAIR_MAX_AGE |
                                                      QLINQ_REPAIR_MAX_EXTRA,
                                           .reactive_repair = true,
                                           .max_object_age_ms = 25,
                                           .max_extra_percent = 200};
  assert(transport_set_track_repair_policy(t, &track, &deadline_policy));
  assert(transport_mock_path_state(t, 0, 100000, 100, 0.0f));
  assert(transport_mock_path_state(t, 1, 100000, 100, 0.0f));
  moq_object_t deadline_obj = {.track_id = track,
                               .group_id = 2,
                               .object_id = 0,
                               .data = payload,
                               .size = sizeof(payload)};
  assert(transport_publish_ex(t, &deadline_obj) ==
         TRANSPORT_PUBLISH_BACKPRESSURE);

  assert(transport_mock_path_state(t, 0, 100000, 100, 0.0f));
  assert(transport_mock_path_state(t, 1, 100000, 5, 0.0f));
  p0_before = quicly_get_num_datagram_frames_path(conn->quic, paths[0].quic);
  p1_before = quicly_get_num_datagram_frames_path(conn->quic, paths[1].quic);
  assert(transport_publish_ex(t, &deadline_obj) == TRANSPORT_PUBLISH_DELIVERED);
  assert(quicly_get_num_datagram_frames_path(conn->quic, paths[0].quic) ==
         p0_before);
  assert(quicly_get_num_datagram_frames_path(conn->quic, paths[1].quic) >
         p1_before);
  fixture_receive(&f, &f.client, 1);

  sent_object_cache_t *deadline_cached =
      transport_sent_cache_find(&t->sent_cache, &track, 2, 0);
  assert(deadline_cached && deadline_cached->expires_at_ms > 0);
  deadline_cached->expires_at_ms =
      (int64_t)(transport_get_monotonic_ns() / 1000000ULL) + 20;
  uint32_t budget_before = deadline_cached->remaining_repair_symbols;
  assert(budget_before >= 2U);

  /* neither path can meet a 20 ms remaining deadline at 100 ms latency */
  assert(transport_mock_path_state(t, 0, 100000, 100, 0.0f));
  assert(transport_mock_path_state(t, 1, 100000, 100, 0.0f));
  p0_before = quicly_get_num_datagram_frames_path(conn->quic, paths[0].quic);
  p1_before = quicly_get_num_datagram_frames_path(conn->quic, paths[1].quic);
  inject_nack(conn->stream, alias, 2, 0, missing, 2);
  assert(quicly_get_num_datagram_frames_path(conn->quic, paths[0].quic) ==
         p0_before);
  assert(quicly_get_num_datagram_frames_path(conn->quic, paths[1].quic) ==
         p1_before);
  assert(deadline_cached->remaining_repair_symbols == budget_before);

  /* cap repair burst to the 1 symbol that can finish before deadline */
  deadline_cached->expires_at_ms =
      (int64_t)(transport_get_monotonic_ns() / 1000000ULL) + 20;
  conn->paths[1].state.b_ewma = FP_FROM_INT(100);
  conn->paths[1].state.l_ewma = FP_FROM_FLOAT(0.005f);
  conn->paths[1].state.p_ewma = 0;
  conn->paths[1].state.q_ewma = 0;
  inject_nack(conn->stream, alias, 2, 0, missing, 2);
  assert(quicly_get_num_datagram_frames_path(conn->quic, paths[0].quic) ==
         p0_before);
  assert(quicly_get_num_datagram_frames_path(conn->quic, paths[1].quic) ==
         p1_before + 1U);
  assert(deadline_cached->remaining_repair_symbols == budget_before - 1U);
  fixture_destroy(&f);
}

static void create_shared_socket(transport_fixture_t *f, size_t paths[2]) {
  memset(f, 0, sizeof(*f));
  f->server.server = true;
  transport_config_t config = {.bind_hosts = {"127.84.1.1"},
                               .num_bind_hosts = 1,
                               .port = 19876,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .allow_insecure_peer = true,
                               .callback = fixture_event,
                               .user_data = &f->server};
  f->server.transport = transport_create(&config);
  assert(f->server.transport);
  config.bind_hosts[0] = "127.84.1.2";
  config.bind_hosts[1] = "127.84.2.2";
  config.num_bind_hosts = 2;
  config.remote_hosts[0] = "127.84.1.1";
  config.num_remote_hosts = 1;
  config.user_data = &f->client;
  f->client.transport = transport_create(&config);
  assert(f->client.transport);

  size_t count = 0;
  for (size_t attempt = 0; attempt < 2000; attempt++) {
    fixture_tick(f);
    count = 0;
    if (f->server.authenticated && f->client.authenticated)
      for (size_t path = 0; path < TRANSPORT_MAX_QUIC_PATHS && count < 2;
           path++) {
        quicly_path_health_t health;
        if (quicly_get_path_health(f->server.conn->quic, path, &health) == 0 &&
            health.validated && !health.abandoned && !health.probe_only &&
            health.state == QUICLY_PATH_USABLE)
          paths[count++] = path;
      }
    if (count == 2)
      break;
  }
  assert(f->server.transport->socket_count == 1 && count == 2);
}

static void update_measurements(transport_fixture_t *f) {
  f->server.transport->last_pathflow_update = 0;
  transport_tick(f->server.transport);
}

static void check_feedback(transport_fixture_t *f,
                           const moq_track_id_t *track) {
  transport_conn_t *conn = f->client.conn;
  transport_t *t = conn->transport;
  uint8_t alias;
  assert(transport_subscriptions_find_alias(&conn->receive_subscriptions, track,
                                            &alias) == 0);
  size_t path = transport_select_datagram_path(conn);
  assert(path != SIZE_MAX && path != 63);
  size_t before = quicly_get_num_datagram_frames_path(conn->quic, path);
  uint8_t packet[QLINQ_WIRE_FEC_HEADER_SIZE + 3] = {0};
  qlinq_wire_fec_header_t header = {.alias = alias,
                                    .path_id = 63,
                                    .group_id = 999,
                                    .object_id = 999,
                                    .total_symbols = 2,
                                    .data_symbols = 2,
                                    .symbol_size = 3,
                                    .original_size = 6};
  assert(qlinq_wire_encode_fec_header(packet, sizeof(packet), &header) ==
         QLINQ_WIRE_OK);
  t->receive_datagram.cb(&t->receive_datagram, conn->quic,
                         ptls_iovec_init(packet, sizeof(packet)));
  assert(quicly_get_num_datagram_frames_path(conn->quic, path) == before + 1);
  assert(quicly_get_num_datagram_frames_path(conn->quic, 63) == 0);
  conn->telemetry_reply_at_ns[63] = transport_get_time_ns() + 1000000000U;
  for (size_t i = 0; i < 100; i++)
    t->receive_datagram.cb(&t->receive_datagram, conn->quic,
                           ptls_iovec_init(packet, sizeof(packet)));
  assert(quicly_get_num_datagram_frames_path(conn->quic, path) == before + 1);
  header.path_id = UINT8_MAX;
  assert(qlinq_wire_encode_fec_header(packet, sizeof(packet), &header) ==
         QLINQ_WIRE_OK);
  t->receive_datagram.cb(&t->receive_datagram, conn->quic,
                         ptls_iovec_init(packet, sizeof(packet)));
  assert(quicly_get_num_datagram_frames_path(conn->quic, path) == before + 1);
  header.path_id = 62;
  header.original_size = 0;
  assert(qlinq_wire_encode_fec_header(packet, sizeof(packet), &header) ==
         QLINQ_WIRE_OK);
  t->receive_datagram.cb(&t->receive_datagram, conn->quic,
                         ptls_iovec_init(packet, sizeof(packet)));
  assert(quicly_get_num_datagram_frames_path(conn->quic, path) == before + 1);
  /* Clear the incomplete synthetic object without affecting delivery counts. */
  for (size_t i = 0; i < t->limits.max_assemblers_per_connection; i++)
    if (conn->assemblers[i].total_symbols)
      transport_release_assembler(t, &conn->assemblers[i]);
}

static void receive_fixed_symbol(transport_conn_t *conn, uint8_t alias,
                                 uint16_t index, uint16_t total,
                                 const sent_object_cache_t *object,
                                 const uint8_t *payload) {
  uint8_t packet[QLINQ_WIRE_FEC_HEADER_SIZE + QLINQ_FEC_MAX_SYMBOL_SIZE];
  qlinq_wire_fec_header_t header = {.alias = alias,
                                    .group_id = object->group_id,
                                    .object_id = object->object_id,
                                    .symbol_index = index,
                                    .total_symbols = total,
                                    .data_symbols = object->data_symbols,
                                    .symbol_size = object->symbol_size,
                                    .original_size = (uint32_t)object->size};
  size_t payload_size = qlinq_wire_fec_payload_size(&header);
  assert(qlinq_wire_encode_fec_header(packet, sizeof(packet), &header) ==
         QLINQ_WIRE_OK);
  memcpy(packet + QLINQ_WIRE_FEC_HEADER_SIZE, payload, payload_size);
  transport_protocol_receive_datagram(
      conn, ptls_iovec_init(packet, QLINQ_WIRE_FEC_HEADER_SIZE + payload_size),
      false);
}

/* A shared source cache must reproduce each recipient's fixed codeword,
 * including when path estimates change before a publication retry. */
static void check_fixed_recipient_geometry(void) {
  sim_network_t net = {.now_ns = 1000000000};
  sim_node_t nodes[3] = {0};
  fixture_endpoint_t endpoints[3] = {0};
  transport_drive_host_t hosts[3];
  const char *addresses[] = {"127.0.0.1", "127.0.0.2", "127.0.0.3"};
  for (size_t i = 0; i < 3; i++)
    hosts[i] = sim_host(&nodes[i], &net);
  for (size_t i = 0; i < 3; i++) {
    endpoints[i].server = i == 0;
    transport_config_t config = {.bind_hosts = {addresses[i]},
                                 .num_bind_hosts = 1,
                                 .port = 19928,
                                 .callback = fixture_event,
                                 .user_data = &endpoints[i],
                                 .allow_insecure_peer = true,
                                 .cert_file = "t/assets/server.crt",
                                 .key_file = "t/assets/server.key",
                                 .drive_host = &hosts[i]};
    if (i) {
      config.remote_hosts[0] = addresses[0];
      config.num_remote_hosts = 1;
    }
    nodes[i].transport = endpoints[i].transport =
        transport_drive_create(&config);
    assert(nodes[i].transport);
  }
  for (size_t i = 0; i < 1000; i++)
    sim_advance(&net, 1000000);
  assert(endpoints[1].authenticated && endpoints[2].authenticated);
  moq_track_id_t track = {.type = MOQ_TRACK_VIDEO,
                          .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                          .name = "fixed-geometry"};
  assert(transport_subscribe(endpoints[1].transport, track));
  assert(transport_subscribe(endpoints[2].transport, track));
  for (size_t i = 0; i < 100; i++)
    sim_advance(&net, 1000000);
  assert(endpoints[0].subscriptions == 2);
  transport_t *sender = endpoints[0].transport;
  qlinq_repair_policy_t policy = {.present = QLINQ_REPAIR_REACTIVE,
                                  .reactive_repair = true};
  assert(transport_set_track_repair_policy(sender, &track, &policy));
  for (size_t i = 0; i < 2; i++) {
    transport_conn_t *conn = transport_connection_at(sender, i);
    conn->paths[0].state_overridden = true;
    conn->paths[0].state = (path_state_t){.initialized = true,
                                          .b_ewma = FP_FROM_INT(100000),
                                          .l_ewma = FP_FROM_FLOAT(.01f),
                                          .p_ewma = i ? FP_FROM_FLOAT(.5f) : 0};
  }
  uint8_t payload[3000];
  for (size_t i = 0; i < sizeof(payload); i++)
    payload[i] = (uint8_t)(i * 37U + i / 64U);
  moq_object_t object = {.track_id = track,
                         .group_id = 1,
                         .object_id = 1,
                         .data = payload,
                         .size = sizeof(payload)};
  assert(transport_publish_ex(sender, &object) == TRANSPORT_PUBLISH_DELIVERED);
  sent_object_cache_t *cached = transport_sent_cache_find(
      &sender->sent_cache, &track, object.group_id, object.object_id);
  assert(cached && cached->data_symbols == 3 && cached->recipient_count == 2);
  uint16_t totals[2];
  for (size_t i = 0; i < 2; i++) {
    transport_conn_t *conn = transport_connection_at(sender, i);
    totals[i] = transport_sent_recipient_total(cached, conn->id);
    assert(totals[i] == quicly_get_num_datagram_frames_path(conn->quic, 0));
    conn->paths[0].state.p_ewma = i ? 0 : FP_FROM_FLOAT(.5f);
  }
  assert(totals[0] < totals[1] && cached->total_symbols == totals[1]);
  assert(transport_publish_ex(sender, &object) == TRANSPORT_PUBLISH_DELIVERED);
  for (size_t i = 0; i < 2; i++) {
    transport_conn_t *conn = transport_connection_at(sender, i);
    assert(quicly_get_num_datagram_frames_path(conn->quic, 0) ==
           2U * totals[i]);
    assert(transport_sent_recipient_total(cached, conn->id) == totals[i]);
    transport_conn_t *receiver = endpoints[i + 1].conn;
    uint8_t alias;
    assert(transport_subscriptions_find_alias(&receiver->receive_subscriptions,
                                              &track, &alias) == 0);
    /* Deliver two systematic symbols, then repair with parity: this also
     * verifies the encoder uses the recipient's geometry, not just its header.
     */
    for (uint16_t symbol = 0; symbol < 2; symbol++)
      receive_fixed_symbol(receiver, alias, symbol, totals[i], cached,
                           cached->data + symbol * cached->symbol_size);
    uint16_t missing[] = {cached->data_symbols};
    transport_repair_batch_t repair;
    assert(transport_repair_build_for_recipient(
        &sender->fec_cache, cached, conn->id, false, missing, 1, &repair));
    assert(repair.total_symbols == totals[i]);
    receive_fixed_symbol(receiver, alias, repair.indices[0],
                         repair.total_symbols, cached, repair.symbols);
    transport_repair_batch_destroy(&repair);
    assert(endpoints[i + 1].objects == 1);
    assert(endpoints[i + 1].payload_size == sizeof(payload));
    assert(memcmp(endpoints[i + 1].payload, payload, sizeof(payload)) == 0);
    assert(receiver->transport->stats.malformed_datagrams == 0);
  }
  transport_repair_batch_t repair;
  const uint16_t missing[] = {0};
  assert(!transport_repair_build_for_recipient(
      &sender->fec_cache, cached, UINT32_MAX, false, missing, 1, &repair));
  assert(transport_sent_cache_release_track(&sender->sent_cache, &track) == 1);
  assert(sender->sent_cache.count == 0);
  for (size_t i = 3; i > 0; i--)
    transport_destroy(nodes[i - 1].transport);
}

int main(void) {
  check_fixed_recipient_geometry();
  transport_fixture_t f;
  size_t paths[2];
  create_shared_socket(&f, paths);
  moq_track_id_t track = {.type = MOQ_TRACK_VIDEO,
                          .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                          .name = "native-path-history"};
  fixture_subscribe(&f, &f.client, track);
  for (size_t i = 0; i < 100; i++)
    fixture_tick(&f);

  check_feedback(&f, &track);

  /* An occupied primary queue must not hide another native path sharing
   * the same local socket. Both repair routing and readiness need it. */
  uint8_t ignored = 0xff;
  ptls_iovec_t frame = ptls_iovec_init(&ignored, 1);
  for (size_t i =
           quicly_get_num_datagram_frames_path(f.server.conn->quic, paths[0]);
       i < QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY; i++)
    assert(transport_queue_datagram(f.server.conn, paths[0], frame));
  assert(transport_select_datagram_path(f.server.conn) == paths[1]);
  assert(transport_is_track_ready(f.server.transport, &track));
  uint8_t shared_payload[2000];
  memset(shared_payload, 0x24, sizeof(shared_payload));
  moq_object_t shared_obj = {.track_id = track,
                             .group_id = 0,
                             .object_id = 0,
                             .data = shared_payload,
                             .size = sizeof(shared_payload)};
  assert(transport_publish_ex(f.server.transport, &shared_obj) ==
         TRANSPORT_PUBLISH_DELIVERED);
  assert(quicly_get_num_datagram_frames_path(f.server.conn->quic, paths[1]) >
         0);
  fixture_receive(&f, &f.client, 1);
  assert(f.client.payload_size == sizeof(shared_payload) &&
         memcmp(f.client.payload, shared_payload, sizeof(shared_payload)) == 0);
  for (size_t i = 0; i < 100; i++)
    fixture_tick(&f);

  transport_conn_path_t *physical = &f.server.conn->paths[0];
  quicly_path_stats_t stats;
  assert(transport_path_get_eligible_by_local(
             f.server.conn->quic, &f.server.transport->sockets[0].local_addr,
             &stats) == paths[0]);

  /* A reply from a second remote path must not become the first path's OWD
   * through their shared physical EWMA. The matching-path control still uses
   * the same two-second queue-delay observation. */
  physical->state = (path_state_t){0};
  physical->owd_initialized = true;
  physical->telemetry_path = paths[1];
  physical->latest_owd_fp = FP_FROM_INT(2);
  update_measurements(&f);
  assert(physical->measurement.quic_path == paths[0]);
  assert(physical->state.l_ewma < FP_ONE);
  physical->state = (path_state_t){0};
  physical->telemetry_path = paths[0];
  update_measurements(&f);
  assert(physical->state.l_ewma >= FP_FROM_INT(2));
  physical->owd_initialized = false;

  /* When native measurement ownership changes, old loss and latency history
   * must reset along with its counters rather than survive in the new EWMA. */
  physical->measurement.quic_path = paths[1];
  physical->state = (path_state_t){.b_ewma = FP_ONE,
                                   .l_ewma = FP_FROM_INT(5),
                                   .p_ewma = FP_ONE,
                                   .initialized = true};
  update_measurements(&f);
  assert(physical->measurement.quic_path == paths[0]);
  assert(physical->state.p_ewma < FP_ONE / 2);
  assert(physical->state.l_ewma < FP_ONE);

  /* Publish immediately after the first native path retires, before periodic
   * measurement can switch ownership. Its 100% loss history must not prevent
   * admission of a coded object on the independently healthy alternate. */
  physical->state = (path_state_t){.b_ewma = FP_ONE,
                                   .l_ewma = FP_FROM_INT(5),
                                   .p_ewma = FP_ONE,
                                   .initialized = true};
  physical->budget = (transport_path_budget_t){0};
  physical->owd_initialized = true;
  physical->telemetry_path = paths[0];
  physical->latest_owd_fp = FP_FROM_INT(2);
  quicly_path_health_t health;
  assert(quicly_get_path_health(f.server.conn->quic, paths[0], &health) == 0);
  assert(quicly_abandon_path(f.server.conn->quic, health.path_id, 0) == 0);
  assert(transport_path_get_eligible_by_local(
             f.server.conn->quic, &f.server.transport->sockets[0].local_addr,
             &stats) == paths[1]);
  assert(transport_select_datagram_path(f.server.conn) == paths[1]);
  assert(transport_is_track_ready(f.server.transport, &track));
  uint8_t payload[2000];
  memset(payload, 0x5a, sizeof(payload));
  moq_object_t object = {.track_id = track,
                         .group_id = 1,
                         .object_id = 0,
                         .data = payload,
                         .size = sizeof(payload)};
  /* An explicit physical override still governs its alternate native path.
   * Only automatic measurements must be kept separate. */
  physical->state_overridden = true;
  update_measurements(&f);
  assert(physical->state.p_ewma == FP_ONE &&
         physical->measurement.quic_path == paths[0]);
  assert(transport_publish_ex(f.server.transport, &object) !=
         TRANSPORT_PUBLISH_DELIVERED);
  physical->state_overridden = false;
  assert(transport_publish_ex(f.server.transport, &object) ==
         TRANSPORT_PUBLISH_DELIVERED);
  assert(quicly_get_num_datagram_frames_path(f.server.conn->quic, paths[1]) >
         0);
  assert(physical->budget.rate > FP_ONE);
  update_measurements(&f);
  assert(physical->measurement.initialized &&
         physical->measurement.quic_path == paths[1]);
  assert(physical->state.p_ewma < FP_ONE / 2);
  assert(physical->state.l_ewma < FP_ONE);
  fixture_receive(&f, &f.client, 2);
  assert(f.client.payload_size == sizeof(payload) &&
         memcmp(f.client.payload, payload, sizeof(payload)) == 0);
  fixture_destroy(&f);
  check_constrained_multipath();
  puts("===MULTIPATH PUBLICATION OK===");
  return 0;
}
