/* Regression cases for the evaluated fx-deep-review findings. */
#include "transport_repair_planner.h"

static void test_review_control(fixture_t *fixture) {
  transport_t *t = fixture->source.transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  uint8_t byte = 42;
  CHECK(tf_enqueue_payload(t, flow, ptls_iovec_init(&byte, 1)));
  CHECK(quicly_flexicast_cc_enable_flow_trace(flow->crypto, 64) == 0);
  transport_flexicast_flow_t *before = malloc(sizeof(*before));
  CHECK(before);
  *before = *flow;
  transport_flexicast_registry_t registry = t->flexicast;
  for (unsigned i = 0; i < 100; i++)
    CHECK(transport_flexicast_get_first_timeout(t) != INT64_MAX);
  CHECK(memcmp(before, flow, sizeof(*before)) == 0);
  CHECK(memcmp(&registry, &t->flexicast, sizeof(registry)) == 0);
  quicly_flexicast_cc_trace_event_t event;
  uint64_t overwritten;
  CHECK(quicly_flexicast_cc_read_flow_trace(flow->crypto, &event, 1,
                                            &overwritten) == 0);
  free(before);
  tf_queue_clear(&flow->data_queue);
  uint32_t epoch = flow->key_epoch;
  transport_flexicast_member_t *member = &flow->members[0];
  quicly_flexicast_frame_t state =
      state_frame(fixture, epoch, QUICLY_FLEXICAST_STATE_LEAVE);
  CHECK(transport_flexicast_receive_quic_frame(t, member->conn, &state));
  size_t changes = flow->rekey_pending_changes;
  state.data.state.action = QUICLY_FLEXICAST_STATE_JOIN;
  CHECK(transport_flexicast_receive_quic_frame(t, member->conn, &state));
  CHECK(!member->joined && flow->rekey_pending_changes == changes);
  flow->rekey_ready_at_ms = transport_get_time_ms();
  transport_flexicast_tick(t);
  CHECK(flow->key_epoch > epoch);
  CHECK(transport_flexicast_receive_quic_frame(t, member->conn, &state));
  CHECK(!member->joined && !flow->rekey_pending);
  if (flow->member_count > 1) {
    member = &flow->members[1];
    CHECK(member->joined && !member->listening);
    member->key_pending = true;
    state = state_frame(fixture, flow->key_epoch, QUICLY_FLEXICAST_STATE_READY);
    CHECK(transport_flexicast_receive_quic_frame(t, member->conn, &state));
    CHECK(!member->listening && member->key_pending);
  }
}

static void test_review_reoffer(fixture_t *fixture) {
  transport_t *t = fixture->source.transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  size_t count = flow->member_count;
  for (size_t i = 0; i < count; i++)
    CHECK(transport_flexicast_offer(t, flow->members[i].conn, &fixture->track,
                                    flow->members[i].alias));
  CHECK(flow->rekey_pending);
  flow->rekey_ready_at_ms = transport_get_time_ms();
  transport_flexicast_tick(t);
  CHECK(flow->active && flow->member_count == count);
  for (size_t i = 0; i < count; i++)
    CHECK(!flow->members[i].reoffer_pending &&
          flow->members[i].offer_epoch == flow->key_epoch);
  for (size_t attempt = 0; attempt < 1000 && flow->listening_count != count;
       attempt++)
    pump(fixture, 2);
  CHECK(flow->listening_count == count);
}

static void test_review_systematic(fixture_t *fixture) {
  transport_t *t = fixture->source.transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  uint8_t data[6000] = {42};
  moq_object_t object = object_for(fixture, data, sizeof(data));
  for (size_t i = 0; i < flow->member_count; i++) {
    transport_conn_t *conn = flow->members[i].conn;
    for (size_t p = 0; p < t->socket_count; p++) {
      conn->paths[p].state_overridden = true;
      conn->paths[p].state = (path_state_t){.initialized = true,
                                            .b_ewma = FP_FROM_INT(1000),
                                            .l_ewma = FP_ONE / 50,
                                            .p_ewma = FP_ONE / 4};
    }
  }
  flow->rekey_pending = true; /* Inspect source symbols before dispatch. */
  CHECK(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_DELIVERED);
  CHECK(flow->data_queue.count > 1);
  for (size_t i = 0; i < flow->data_queue.count; i++) {
    const transport_flexicast_queued_payload_t *packet =
        tf_queue_at_const(&flow->data_queue, i);
    qlinq_wire_fec_header_t header;
    CHECK(qlinq_wire_decode_fec_header(packet->data, packet->size, &header) ==
          QLINQ_WIRE_OK);
    CHECK(header.total_symbols == header.data_symbols &&
          header.symbol_index < header.data_symbols);
  }
  for (size_t i = 0; i < TRANSPORT_FEC_CACHE_SIZE; i++)
    CHECK(t->fec_cache.entries[i].fec == NULL);
}

static void test_review_repairs(fixture_t *fixture, bool rateless) {
  transport_t *t = fixture->source.transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  CHECK(flow->member_count == 2);
  transport_conn_t *healthy = flow->members[0].conn;
  transport_conn_t *blocked = flow->members[1].conn;
  /* Both client paths target the same server socket. Retire slot zero and
   * require forced repair to select the validated nonzero QUIC path. */
  size_t primary = transport_select_datagram_path(healthy);
  CHECK(primary != SIZE_MAX);
  quicly_path_health_t health;
  CHECK(quicly_get_path_health(healthy->quic, primary, &health) == 0);
  CHECK(quicly_abandon_path(healthy->quic, health.path_id,
                            QUICLY_PATH_ABANDON_ERROR_APPLICATION) == 0);
  size_t alternate = transport_select_datagram_path(healthy);
  CHECK(alternate != SIZE_MAX && alternate != primary);
  uint8_t bytes[128] = {42};
  moq_object_t object = {.track_id = fixture->track,
                         .group_id = 17,
                         .object_id = 23,
                         .data = bytes,
                         .size = sizeof(bytes)};
  CHECK(transport_sent_cache_store(&t->sent_cache, &object, 4, 4, 32, false));
  sent_object_cache_t *cached =
      transport_sent_cache_find(&t->sent_cache, &fixture->track, 17, 23);
  CHECK(cached);
  t->flexicast_repair_route = TRANSPORT_FLEXICAST_REPAIR_UNICAST;
  uint16_t indices[] = {2, 3};
  uint16_t blocked_indices[] = {0, 1};
  transport_repair_mode_t mode =
      rateless ? TRANSPORT_REPAIR_MODE_RATELESS : TRANSPORT_REPAIR_MODE_INDEXED;
  int64_t now = transport_get_time_ms();
  CHECK(transport_flexicast_schedule_repair(t, flow, cached, healthy->id, mode,
                                            false, rateless ? NULL : indices, 2,
                                            now));
  CHECK(transport_flexicast_schedule_repair(
      t, flow, cached, blocked->id, mode, false,
      rateless ? NULL : blocked_indices, 2, now));
  uint8_t dummy = 0;
  size_t path;
  while ((path = transport_select_datagram_path(blocked)) != SIZE_MAX)
    CHECK(transport_queue_datagram(blocked, path, ptls_iovec_init(&dummy, 1)));
  size_t before = quicly_get_num_datagram_frames_path(healthy->quic, alternate);
  uint16_t esi = cached->next_repair_symbol;
  tf_materialize_pending_repairs(t, flow, now + 100);
  CHECK(quicly_get_num_datagram_frames_path(healthy->quic, alternate) ==
        before + 2);
  CHECK(flow->pending_repair_count == 1);
  if (rateless)
    CHECK(cached->next_repair_symbol == esi + 2);
  /* Discard blocked-peer output locally, without sending dummy plaintext to
   * the receiver; this frees admission for the retained repair demand. */
  for (unsigned attempt = 0;
       attempt < 20 && transport_select_datagram_path(blocked) == SIZE_MAX;
       attempt++) {
    quicly_address_t dest, src;
    struct iovec datagrams[64];
    uint8_t buffer[64 * 1500];
    size_t count = 64;
    CHECK(quicly_send(blocked->quic, &dest, &src, datagrams, &count, buffer,
                      sizeof(buffer)) == 0);
  }
  CHECK(transport_select_datagram_path(blocked) != SIZE_MAX);
  tf_materialize_pending_repairs(t, flow, now + 101);
  CHECK(flow->pending_repair_count == 0);
  CHECK(quicly_get_num_datagram_frames_path(healthy->quic, alternate) ==
        before + 2);
  if (rateless)
    CHECK(cached->next_repair_symbol == esi + 4);
}

static void test_review_shadow(fixture_t *fixture) {
  transport_t *t = fixture->source.transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  CHECK(flow->listening_count == 2 && !flow->native_multicast);
  t->repair_shadow_log = tmpfile();
  CHECK(t->repair_shadow_log);
  uint8_t bytes[128] = {42};
  moq_object_t object = {.track_id = fixture->track,
                         .group_id = 11,
                         .object_id = 19,
                         .data = bytes,
                         .size = sizeof(bytes)};
  CHECK(transport_sent_cache_store(&t->sent_cache, &object, 4, 4, 32, false));
  sent_object_cache_t *cached =
      transport_sent_cache_find(&t->sent_cache, &fixture->track, 11, 19);
  CHECK(cached);
  uint16_t missing = 1;
  int64_t now = transport_get_time_ms();
  for (size_t i = 0; i < flow->member_count; i++)
    transport_flexicast_observe_repair_request(
        t, flow, cached, flow->members[i].conn->id,
        TRANSPORT_REPAIR_MODE_INDEXED, false, &missing, 1,
        TRANSPORT_FLEXICAST_OBS_ACCEPTED, now);
  CHECK(flow->shadow_requesters.count == 2);
  flow->pacing_rate_bytes_per_second = 1000000;
  for (size_t i = 0; i < flow->shadow_requesters.count; i++)
    flow->shadow_requesters.entries[i].delivery_rate_bytes_per_second = 500000;
  /* An unused physical interface must not become a phantom planner path. */
  size_t sockets = t->socket_count;
  CHECK(sockets == 1);
  transport_socket_t unused = t->sockets[sockets];
  t->sockets[sockets].local_addr = (struct sockaddr_storage){0};
  struct sockaddr_in *address =
      (struct sockaddr_in *)&t->sockets[sockets].local_addr;
  address->sin_family = AF_INET;
  address->sin_addr.s_addr = htonl(0x7f000063);
  t->socket_count++;
  tf_emit_ready_shadow_observations(t, flow, now + 1000);
  t->socket_count = sockets;
  t->sockets[sockets] = unused;
  rewind(t->repair_shadow_log);
  transport_repair_planner_snapshot_t snapshot = {0};
  transport_repair_planner_recorded_result_t result;
  CHECK(transport_repair_planner_record_read(t->repair_shadow_log, &snapshot,
                                             &result));
  CHECK(snapshot.requester_count == 2 && snapshot.shared_physical_copies == 2);
  for (size_t i = 0; i < snapshot.requester_count; i++) {
    CHECK(snapshot.requesters[i].shared_delivery_probability_ppm == 1000000U);
    CHECK(snapshot.requesters[i].path_count == 1);
    CHECK(snapshot.requesters[i].paths[0].measurement_known &&
          snapshot.requesters[i].paths[0].estimate.b > 0);
  }
  transport_repair_planner_record_destroy(&snapshot);
  fclose(t->repair_shadow_log);
  t->repair_shadow_log = NULL;
}
