#include "picotls/openssl.h"
#include "portable_sockets.h"
#include "quicly/defaults.h"
#include "transport_flexicast_internal.h"
#include "transport_internal.h"
#include "transport_publish.h"
#include "transport_protocol.h"
#include "transport_publish.h"
#include "transport_subscriptions.h"
#include "transport_tracks.h"
#include "transport_udp.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
#define MAX_CLIENTS 12

typedef struct {
  transport_t *transport;
  bool connected;
  size_t received;
  size_t last_size;
  uint64_t last_checksum;
} endpoint_t;

typedef struct {
  endpoint_t source, clients[MAX_CLIENTS];
  size_t count;
  moq_track_id_t track;
  transport_flexicast_flow_t *flow;
} fixture_t;

static void source_event(void *data, const transport_event_t *event) {
  endpoint_t *endpoint = data;
  if (event->type == TRANSPORT_EVENT_AUTH)
    CHECK(transport_respond_auth(endpoint->transport, event->conn, true));
}

static void client_event(void *data, const transport_event_t *event) {
  endpoint_t *endpoint = data;
  if (event->type == TRANSPORT_EVENT_CONNECTED)
    CHECK(transport_send_auth(endpoint->transport, event->conn,
                              (uint8_t *)"test", 4));
  if (event->type == TRANSPORT_EVENT_AUTH_COMPLETE)
    endpoint->connected = event->auth.success;
  if (event->type == TRANSPORT_EVENT_OBJECT) {
    endpoint->received++;
    endpoint->last_size = event->object.size;
    endpoint->last_checksum = 0;
    for (size_t i = 0; i < event->object.size; i++)
      endpoint->last_checksum =
          endpoint->last_checksum * 33 + event->object.data[i];
  }
}

static void pump(fixture_t *fixture, size_t milliseconds) {
  for (size_t i = 0; i < milliseconds; i++) {
    transport_tick(fixture->source.transport);
    for (size_t j = 0; j < fixture->count; j++)
      if (fixture->clients[j].transport)
        transport_tick(fixture->clients[j].transport);
    usleep(1000);
  }
}

static void create_fixture(fixture_t *fixture, size_t count, bool adaptive,
                           const char *mode) {
  memset(fixture, 0, sizeof(*fixture));
  fixture->count = count;
  fixture->track =
      (moq_track_id_t){.type = MOQ_TRACK_VIDEO, .name = "regression"};
  if (strstr(mode, "fixed") || strstr(mode, "rateless")) {
    fixture->track.type = MOQ_TRACK_DATA;
    fixture->track.flags = MOQ_TRACK_FLAG_FEC_ENABLED;
    if (strstr(mode, "rateless"))
      fixture->track.flags |= MOQ_TRACK_FLAG_FEC_RATELESS;
  }
  if (strcmp(mode, "video-rateless") == 0 ||
      strcmp(mode, "review-systematic-rateless") == 0)
    fixture->track.type = MOQ_TRACK_VIDEO;
  transport_config_t config = {.bind_hosts = {"127.0.0.1"},
                               .num_bind_hosts = 1,
                               .port = 19761,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .allow_insecure_peer = true,
                               .enable_flexicast = true,
                               .callback = source_event,
                               .user_data = &fixture->source};
  /* Do not override controller rates: first-packet progress must work with
   * the same defaults applications receive. */
  if (adaptive)
    config.flexicast_cc_mode = TRANSPORT_FLEXICAST_CC_ADAPTIVE;
  if (strcmp(mode, "pacer-high") == 0 || strcmp(mode, "pacer-maximum") == 0) {
    config.flexicast_cc_startup_rate = strcmp(mode, "pacer-high") == 0
                                           ? UINT64_C(625000000)
                                           : UINT64_C(1073741824);
    config.flexicast_cc_minimum_rate = config.flexicast_cc_startup_rate;
    config.flexicast_cc_maximum_rate = config.flexicast_cc_startup_rate;
  }
  bool native = strstr(mode, "native") != NULL;
  if (native) {
    config.bind_hosts[0] = "127.0.0.2";
    config.bind_hosts[1] = "127.0.0.1";
    config.num_bind_hosts = 2;
    if (strstr(mode, "wildcard")) {
      config.bind_hosts[0] = "0.0.0.0";
      config.num_bind_hosts = 1;
    }
    config.flexicast_group = "232.42.42.61";
    config.flexicast_group_port = 19763;
    config.flexicast_interface = "127.0.0.1";
  }
  CHECK((fixture->source.transport = transport_create(&config)) != NULL);
  for (size_t j = 0; j < count; j++) {
    transport_config_t client = {.bind_hosts = {"127.0.0.1"},
                                 .num_bind_hosts = 1,
                                 .remote_hosts = {"127.0.0.1"},
                                 .num_remote_hosts = 1,
                                 .port = 19761,
                                 .allow_insecure_peer = true,
                                 .enable_flexicast = true,
                                 .callback = client_event,
                                 .user_data = &fixture->clients[j]};
    if (strcmp(mode, "review-fixed") == 0 ||
        strcmp(mode, "review-rateless") == 0) {
      client.bind_hosts[1] = "127.0.0.2";
      client.num_bind_hosts = 2;
    }
    if (native)
      client.flexicast_interface = "127.0.0.1";
    if (strcmp(mode, "limits") == 0 && j == count - 1)
      client.limits.max_fec_object_size = 1024;
    CHECK((fixture->clients[j].transport = transport_create(&client)) != NULL);
    for (size_t attempt = 0; attempt < 1000 && !fixture->clients[j].connected;
         attempt++)
      pump(fixture, 2);
    CHECK(fixture->clients[j].connected);
    /* Give one member a different local alias for the same shared track. */
    if (strstr(mode, "aliases") != NULL && j == count - 1) {
      moq_track_id_t other = {.type = MOQ_TRACK_VIDEO, .name = "alias-offset"};
      CHECK(transport_subscribe(fixture->clients[j].transport, other));
    }
    CHECK(transport_subscribe(fixture->clients[j].transport, fixture->track));
  }
  size_t cohort = count;
  for (size_t attempt = 0; attempt < 1500; attempt++) {
    pump(fixture, 2);
    fixture->flow = transport_flexicast_find_source(fixture->source.transport,
                                                    &fixture->track);
    size_t ready = 0;
    bool pending = false;
    transport_t *source = fixture->source.transport;
    for (size_t f = 0; f < source->flexicast.capacity; f++) {
      transport_flexicast_flow_t *flow = &source->flexicast.flows[f];
      if (flow->active && flow->source &&
          transport_track_id_equal(&flow->track_id, &fixture->track)) {
        ready += flow->listening_count;
        pending |= flow->rekey_pending;
      }
    }
    if (fixture->flow && ready == count && !pending)
      break;
  }
  CHECK(fixture->flow && fixture->flow->listening_count == cohort &&
        !fixture->flow->rekey_pending);
}

static void destroy_fixture(fixture_t *fixture) {
  for (size_t i = 0; i < fixture->count; i++)
    transport_destroy(fixture->clients[i].transport);
  transport_destroy(fixture->source.transport);
}

static moq_object_t object_for(fixture_t *fixture, uint8_t *bytes,
                               size_t size) {
  return (moq_object_t){
      .track_id = fixture->track, .data = bytes, .size = size, .priority = 1};
}

static void check_delivery(fixture_t *fixture, size_t objects, size_t members) {
  bool complete = false;
  for (size_t attempt = 0; attempt < 30000 && !complete; attempt++) {
    pump(fixture, 2);
    complete = true;
    for (size_t i = 0; i < members; i++)
      complete &= fixture->clients[i].received == objects;
  }
  for (size_t i = 0; i < members; i++) {
    if (fixture->clients[i].received != objects)
      fprintf(stderr, "member %zu: received %zu expected %zu\n", i,
              fixture->clients[i].received, objects);
    CHECK(fixture->clients[i].received == objects);
    CHECK(fixture->clients[i].transport->stats.malformed_datagrams == 0);
  }
}

static void test_delivery(fixture_t *fixture, bool native) {
  uint8_t bytes[32] = {42};
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  transport_t *source = fixture->source.transport;
  uint64_t bytes_before = source->stats.flexicast_physical_bytes_sent;
  uint64_t packets_before = source->stats.flexicast_packets_sent;
  for (size_t i = 0; i < 4; i++) {
    object.object_id = i;
    CHECK(transport_publish_ex(source, &object) == TRANSPORT_PUBLISH_DELIVERED);
    check_delivery(fixture, i + 1, fixture->count);
  }
  CHECK(fixture->flow->data_queue.count == 0);
  size_t cohorts = 0;
  for (size_t f = 0; f < source->flexicast.capacity; f++)
    if (source->flexicast.flows[f].active &&
        source->flexicast.flows[f].source &&
        transport_track_id_equal(&source->flexicast.flows[f].track_id,
                                 &fixture->track))
      cohorts++;
  CHECK(source->stats.flexicast_packets_sent - packets_before == 4 * cohorts);
  CHECK(source->stats.flexicast_payloads_accepted == 4 * cohorts);
  size_t copies = native ? 1 : fixture->count;
  CHECK(source->stats.flexicast_physical_packets_sent == 4 * copies);
  size_t symbol_size = transport_get_datagram_symbol_size(source);
  if (symbol_size > sizeof(bytes))
    symbol_size = sizeof(bytes);
  size_t plaintext = QLINQ_WIRE_FEC_HEADER_SIZE + symbol_size;
  CHECK(source->stats.flexicast_plaintext_bytes_accepted ==
        4 * cohorts * plaintext);
  uint64_t expected =
      4 * copies *
      quicly_flexicast_datagram_size(fixture->flow->crypto, plaintext);
  CHECK(source->stats.flexicast_physical_bytes_sent - bytes_before == expected);
  if (native) {
    CHECK(source->stats.flexicast_native_packets_sent == 4);
    for (size_t i = 0; i < fixture->count; i++)
      CHECK(fixture->clients[i]
                .transport->stats.flexicast_multicast_datagrams_received == 4);
  }
}

static void test_blocked_fanout(fixture_t *fixture) {
  transport_t *source = fixture->source.transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  CHECK(!flow->native_multicast && fixture->count >= 2);
  uint8_t bytes[32] = {42};
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  size_t packet_size = quicly_flexicast_datagram_size(
      flow->crypto, QLINQ_WIRE_FEC_HEADER_SIZE + sizeof(bytes));
  uint64_t sent = source->stats.flexicast_physical_packets_sent;
  int64_t oldest = transport_get_time_ms() - 10000;
  for (size_t replica = 0; replica < fixture->count; ++replica) {
    /* Admit precisely one successful replica. Freeze refills so clock speed
     * cannot let an unsent member escape the blocked-fanout assertions. */
    flow->pacing_tokens = packet_size;
    flow->pacing_last_refill_ms = INT64_MAX;
    if (replica == 0)
      CHECK(transport_publish_ex(source, &object) ==
            TRANSPORT_PUBLISH_DELIVERED);
    else
      tf_drain_paced_payloads(source, flow);
    CHECK(source->stats.flexicast_physical_packets_sent == sent + replica + 1);
    CHECK(flow->data_queue.count == (replica + 1 < fixture->count ? 1U : 0U));
    CHECK(flow->feedback_outstanding_count == replica + 1);
    for (size_t i = 0; i < fixture->count; ++i) {
      transport_flexicast_member_t *member = &flow->members[i];
      if (i <= replica) {
        CHECK(tf_member_feedback_deadline(flow, member) != INT64_MAX);
        if (i == replica)
          CHECK(member->first_unacknowledged_ms > oldest + 3000);
      } else {
        CHECK(member->first_unacknowledged_ms == 0);
        CHECK(tf_member_feedback_deadline(flow, member) == INT64_MAX);
      }
    }
    if (replica == 0)
      flow->members[0].first_unacknowledged_ms = oldest;
    else
      CHECK(flow->members[0].first_unacknowledged_ms == oldest);
  }
  /* Existing debt was preserved while every later replica started its own
   * deadline. Restore the aged fixture clock before processing real ACKs. */
  flow->members[0].first_unacknowledged_ms = transport_get_time_ms();
  flow->pacing_last_refill_ms = transport_get_time_ms();
  check_delivery(fixture, 1, fixture->count);
  pump(fixture, 50);
  CHECK(flow->listening_count == fixture->count);
  CHECK(flow->feedback_outstanding_count == 0);
  CHECK(source->stats.flexicast_feedback_fallbacks == 0);
}

static void test_native_ingress(fixture_t *fixture) {
  transport_t *source = fixture->source.transport;
  transport_t *receiver = fixture->clients[0].transport;
  transport_flexicast_flow_t *flow = NULL;
  for (size_t i = 0; i < receiver->flexicast.capacity; i++)
    if (receiver->flexicast.flows[i].active &&
        receiver->flexicast.flows[i].flow_id == fixture->flow->flow_id)
      flow = &receiver->flexicast.flows[i];
  CHECK(flow && flow->crypto && flow->interface_index);
  uint8_t ciphertext[2048], original[2048], received[2048];
  uint8_t body[32] = {42};
  size_t size;
  uint64_t number;
  CHECK(quicly_flexicast_send_datagram_at(
            fixture->flow->crypto, ptls_iovec_init(body, sizeof(body)),
            ciphertext, sizeof(ciphertext), &size, &number,
            transport_get_time_ms()) == QUICLY_FLEXICAST_OK);
  memcpy(original, ciphertext, size);
  transport_flexicast_ingress_t ingress = {.ip_version = flow->ip_version,
                                           .destination_port = flow->udp_port,
                                           .interface_index =
                                               flow->interface_index};
  memcpy(ingress.source_ip, flow->source_ip, 16);
  memcpy(ingress.group_ip, flow->group_ip, 16);
  CHECK(transport_flexicast_native_packet_valid(receiver, ciphertext, size,
                                                &ingress));
  transport_flexicast_ingress_t bad = ingress;
  bad.source_ip[3] ^= 1;
  CHECK(!transport_flexicast_native_packet_valid(receiver, ciphertext, size,
                                                 &bad));
  bad = ingress;
  bad.group_ip[3] ^= 1;
  CHECK(!transport_flexicast_native_packet_valid(receiver, ciphertext, size,
                                                 &bad));
  bad = ingress;
  bad.destination_port++;
  CHECK(!transport_flexicast_native_packet_valid(receiver, ciphertext, size,
                                                 &bad));
  bad = ingress;
  bad.interface_index++;
  CHECK(!transport_flexicast_native_packet_valid(receiver, ciphertext, size,
                                                 &bad));
  bad = ingress;
  bad.interface_index = 0;
  CHECK(!transport_flexicast_native_packet_valid(receiver, ciphertext, size,
                                                 &bad));
  bad = ingress;
  bad.ip_version = 6;
  CHECK(!transport_flexicast_native_packet_valid(receiver, ciphertext, size,
                                                 &bad));
  bad = ingress;
  bad.truncated = true;
  CHECK(!transport_flexicast_native_packet_valid(receiver, ciphertext, size,
                                                 &bad));
  flow->multicast_unavailable = true;
  CHECK(!transport_flexicast_native_packet_valid(receiver, ciphertext, size,
                                                 &ingress));
  flow->multicast_unavailable = false;
  flow->membership_acquired = false;
  CHECK(!transport_flexicast_native_packet_valid(receiver, ciphertext, size,
                                                 &ingress));
  flow->membership_acquired = true;
  /* Exercise the real recvmsg boundary: a valid ciphertext replayed to the
   * wildcard receive socket's unicast address must not consume its packet
   * number. Neither may a truncated multicast packet. */
  struct sockaddr_in local = {.sin_family = AF_INET,
                              .sin_port = htons(flow->udp_port)};
  CHECK(inet_pton(AF_INET, "127.0.0.1", &local.sin_addr) == 1);
  struct sockaddr_in sender = {.sin_family = AF_INET};
  memcpy(&sender.sin_addr, flow->source_ip, 4);
  size_t source_fd = SIZE_MAX;
  for (size_t i = 0; i < source->socket_count; i++)
    if (((struct sockaddr_in *)&source->sockets[i].local_addr)
            ->sin_addr.s_addr == sender.sin_addr.s_addr)
      source_fd = i;
  CHECK(source_fd != SIZE_MAX);
  struct iovec vector = {.iov_base = ciphertext, .iov_len = size};
  CHECK(transport_udp_send_from(
            source->sockets[source_fd].fd, (struct sockaddr *)&local,
            (struct sockaddr *)&sender, source->flexicast_interface_index,
            &vector) == 1);
  transport_conn_t *conn = NULL;
  ptls_iovec_t payload = {0};
  CHECK(transport_flexicast_receive_native(receiver, 0, received,
                                           sizeof(received), &conn,
                                           &payload) == (ssize_t)size);
  CHECK(!conn && !payload.base && !memcmp(received, original, size));
  local.sin_port++;
  CHECK(transport_flexicast_receive_unicast(
      receiver, ciphertext, size, (struct sockaddr *)&local, &conn, &payload));
  CHECK(!conn && !payload.base && !memcmp(ciphertext, original, size));
  CHECK(
      transport_udp_send_from(source->sockets[source_fd].fd,
                              (struct sockaddr *)&source->flexicast_group_addr,
                              (struct sockaddr *)&sender,
                              source->flexicast_interface_index, &vector) == 1);
  CHECK(transport_flexicast_receive_native(receiver, 0, received, 16, &conn,
                                           &payload) == 16);
  CHECK(!conn && !payload.base);
  CHECK(
      transport_udp_send_from(source->sockets[source_fd].fd,
                              (struct sockaddr *)&source->flexicast_group_addr,
                              (struct sockaddr *)&sender,
                              source->flexicast_interface_index, &vector) == 1);
  CHECK(transport_flexicast_receive_native(receiver, 0, received,
                                           sizeof(received), &conn,
                                           &payload) == (ssize_t)size);
  CHECK(conn == flow->control_conn && payload.len == sizeof(body) &&
        !memcmp(payload.base, body, sizeof(body)));
  CHECK(receiver->stats.flexicast_packets_received == 1);
}

static quicly_flexicast_frame_t state_frame(fixture_t *fixture, uint64_t epoch,
                                            uint64_t action) {
  quicly_flexicast_frame_t frame = {.type = QUICLY_FRAME_TYPE_FC_STATE};
  frame.data.state.flow_id.len = QUICLY_FLEXICAST_FLOW_ID_SIZE;
  quicly_encode64(frame.data.state.flow_id.bytes, fixture->flow->flow_id);
  frame.data.state.sequence = epoch;
  frame.data.state.action = action;
  return frame;
}

static void test_rekey(fixture_t *fixture, const char *mode) {
  bool partial = strcmp(mode, "partial-rekey") == 0;
  bool pressure = strcmp(mode, "control-queue") == 0;
  bool backlog = strcmp(mode, "egress-rekey") == 0;
  transport_t *source = fixture->source.transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  transport_conn_t *departed = flow->members[fixture->count - 1].conn;
  uint8_t bytes[32] = {42};
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  uint32_t old_epoch = flow->key_epoch;
  uint8_t old_secret[sizeof(flow->secret)];
  memcpy(old_secret, flow->secret, sizeof(old_secret));
  if (pressure) {
    quicly_flexicast_key_frame_t key = {
        .flow_id = state_frame(fixture, old_epoch, 0).data.state.flow_id,
        .sequence = old_epoch,
        .first_packet_number =
            quicly_flexicast_get_next_packet_number(flow->crypto),
        .key = ptls_iovec_init(flow->secret, sizeof(flow->secret)),
        .algorithm = PTLS_CIPHER_SUITE_AES_128_GCM_SHA256};
    size_t accepted = 0;
    while (quicly_flexicast_send_key(flow->members[0].conn->quic, &key) ==
           QUICLY_FLEXICAST_OK)
      CHECK(++accepted <= 256);
    CHECK(accepted != 0);
  }
  if (backlog) {
    transport_egress_t *egress = &source->sockets[0].egress;
    CHECK(egress->count == 0);
    transport_egress_packet_t *packet = &egress->packets[egress->head];
    packet->destination = source->sockets[0].local_addr;
    packet->destination_len = sizeof(struct sockaddr_in);
    packet->data = malloc(1);
    CHECK(packet->data);
    packet->data[0] = 0;
    packet->size = 1;
    egress->count = egress->bytes = 1;
    CHECK(transport_publish_ex(source, &object) == TRANSPORT_PUBLISH_DELIVERED);
    CHECK(flow->data_queue.count == 1);
    CHECK(flow->data_queue.entries[flow->data_queue.head].packet != NULL);
    CHECK(source->stats.flexicast_physical_packets_sent == 0);
  }
  if (partial) {
    /* Precisely one replica can pass. The logical packet stays owned by the
     * flow, allowing rotation of its remaining replicas. */
    flow->pacing_tokens = quicly_flexicast_datagram_size(
        flow->crypto,
        QLINQ_WIRE_FEC_HEADER_SIZE +
            (sizeof(bytes) < transport_get_datagram_symbol_size(source)
                 ? sizeof(bytes)
                 : transport_get_datagram_symbol_size(source)));
    flow->pacing_last_refill_ms = transport_get_time_ms();
    CHECK(transport_publish_ex(source, &object) == TRANSPORT_PUBLISH_DELIVERED);
    CHECK(flow->data_queue.count == 1);
    CHECK(flow->data_queue.entries[flow->data_queue.head].next_member >= 1);
  }
  transport_subscriptions_remove(&departed->send_subscriptions,
                                 fixture->track.type, fixture->track.name);
  flow->cc_supply_empty_since_ms = 1;
  flow->cc_supply_ready_at_ms = 2;
  flow->cc_supply_idle_ready_at_ms = 3;
  transport_flexicast_remove_member(source, departed, &fixture->track);
  CHECK(flow->rekey_pending);
  CHECK(flow->cc_supply_empty_since_ms == 0 &&
        flow->cc_supply_ready_at_ms == 0);
  CHECK(flow->cc_supply_idle_ready_at_ms == 0);
  uint64_t packet_number =
      quicly_flexicast_get_next_packet_number(flow->crypto);
  if (!partial && !backlog)
    CHECK(transport_publish_ex(source, &object) == TRANSPORT_PUBLISH_DELIVERED);
  CHECK(quicly_flexicast_get_next_packet_number(flow->crypto) == packet_number);
  CHECK(flow->data_queue.count == 1);
  CHECK(source->sockets[0].egress.count == (backlog ? 1U : 0U));
  CHECK(flow->key_epoch == old_epoch);
  /* A second membership event cannot postpone the already scheduled epoch. */
  int64_t deadline = flow->rekey_ready_at_ms;
  quicly_flexicast_frame_t frame =
      state_frame(fixture, old_epoch, QUICLY_FLEXICAST_STATE_READY);
  CHECK(transport_flexicast_receive_quic_frame(source, departed, &frame));
  CHECK(flow->rekey_ready_at_ms == deadline);
  if (pressure) {
    flow->rekey_ready_at_ms = transport_get_time_ms();
    transport_flexicast_tick(source);
    CHECK(flow->members[0].key_pending);
    CHECK(!flow->members[0].listening);
  }
  check_delivery(fixture, 1, fixture->count - 1);
  CHECK(flow->key_epoch > old_epoch);
  CHECK(memcmp(old_secret, flow->secret, sizeof(old_secret)) != 0);
  CHECK(flow->data_queue.count == 0);
  pump(fixture, 50);
  for (size_t i = 0; i < fixture->count - 1; i++)
    CHECK(fixture->clients[i].received == 1);
  CHECK(fixture->clients[fixture->count - 1].received == 0);
  quicly_flexicast_config_t crypto_config = {
      .flow_id = flow->flow_id,
      .first_packet_number = packet_number,
      .cipher_suite = &ptls_openssl_aes128gcmsha256,
      .crypto_engine = &quicly_default_crypto_engine,
      .traffic_secret = ptls_iovec_init(old_secret, sizeof(old_secret))};
  quicly_flexicast_flow_t *observer = NULL;
  CHECK(quicly_flexicast_flow_create(&observer, &crypto_config) ==
        QUICLY_FLEXICAST_OK);
  uint8_t packet[256];
  size_t packet_size;
  ptls_iovec_t decoded;
  CHECK(quicly_flexicast_send_datagram(flow->crypto,
                                       ptls_iovec_init(bytes, sizeof(bytes)),
                                       packet, sizeof(packet), &packet_size,
                                       &packet_number) == QUICLY_FLEXICAST_OK);
  CHECK(quicly_flexicast_receive_datagram(observer, packet, packet_size,
                                          &decoded, &packet_number) !=
        QUICLY_FLEXICAST_OK);
  quicly_flexicast_flow_free(observer);
}

static void test_ready_baseline(fixture_t *fixture) {
  transport_t *source = fixture->source.transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  transport_flexicast_member_t *member = &flow->members[0];
  transport_conn_t *conn = member->conn;
  uint8_t alias;
  CHECK(transport_subscriptions_find_alias(&conn->send_subscriptions,
                                           &fixture->track, &alias) == 0);
  transport_checkpoint_ack_state_t *ack = transport_checkpoint_ack(conn, alias);
  *ack = (transport_checkpoint_ack_state_t){.participating = true,
                                            .sent_initialized = true,
                                            .sent_group_id = 1,
                                            .sent_object_id = 17,
                                            .oldest_unacked_sent_at_ms = 1,
                                            .acked_initialized = true,
                                            .acked_group_id = 1,
                                            .acked_object_id = 3,
                                            .finish_target = true};
  transport_checkpoint_ack_state_t before = *ack;
  member->recovery_baseline_pending = true;
  quicly_flexicast_frame_t frame =
      state_frame(fixture, flow->key_epoch, QUICLY_FLEXICAST_STATE_READY);
  CHECK(transport_flexicast_receive_quic_frame(source, conn, &frame));
  CHECK(!memcmp(ack, &before, sizeof(before)));
  CHECK(!member->recovery_baseline_pending);
  frame = state_frame(fixture, flow->key_epoch, QUICLY_FLEXICAST_STATE_LEAVE);
  CHECK(transport_flexicast_receive_quic_frame(source, conn, &frame));
  CHECK(!memcmp(ack, &before, sizeof(before)));
}

static void test_controls(fixture_t *fixture) {
  transport_t *source = fixture->source.transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  transport_conn_t *conn = flow->members[fixture->count - 1].conn;
  uint64_t epoch = flow->key_epoch;
  quicly_flexicast_frame_t frame =
      state_frame(fixture, epoch, QUICLY_FLEXICAST_STATE_LEAVE);
  CHECK(transport_flexicast_receive_quic_frame(source, conn, &frame));
  CHECK(flow->rekey_pending);
  int64_t deadline = flow->rekey_ready_at_ms;
  /* Deterministic stateful control permutations: obsolete and future READYs,
   * repeated LEAVEs, JOINs crossing the pending rotation, and throttling. */
  uint32_t random = 0x72a9b;
  for (size_t i = 0; i < 256; i++) {
    random = random * 1664525U + 1013904223U;
    unsigned action = (random >> 24) % 4;
    frame = state_frame(fixture, epoch + (action == 3),
                        action == 0   ? QUICLY_FLEXICAST_STATE_LEAVE
                        : action == 1 ? QUICLY_FLEXICAST_STATE_JOIN
                                      : QUICLY_FLEXICAST_STATE_READY);
    CHECK(transport_flexicast_receive_quic_frame(source, conn, &frame) ==
          (action != 3));
    CHECK(flow->rekey_ready_at_ms == deadline);
    CHECK(!transport_flexicast_member_is_listening(flow, conn));
  }
  transport_flexicast_remove_member(source, conn, &fixture->track);
  frame = state_frame(fixture, epoch, QUICLY_FLEXICAST_STATE_READY);
  CHECK(transport_flexicast_receive_quic_frame(source, conn, &frame));
  frame.data.state.sequence = epoch + 1;
  CHECK(!transport_flexicast_receive_quic_frame(source, conn, &frame));
}

static void test_limits(fixture_t *fixture) {
  uint8_t bytes[2048] = {42};
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  CHECK(transport_publish_ex(fixture->source.transport, &object) ==
        TRANSPORT_PUBLISH_INVALID);
  pump(fixture, 50);
  for (size_t i = 0; i < fixture->count; i++) {
    CHECK(fixture->clients[i].received == 0);
    CHECK(fixture->clients[i].transport->stats.malformed_datagrams == 0);
  }
}

static void test_recovery(fixture_t *fixture) {
  uint8_t bytes[32] = {42};
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  transport_t *source = fixture->source.transport;
  /* Lose a complete leading object and a complete interior object which
   * will be more than 32 objects behind the terminal watermark. */
  for (size_t group = 0; group < 40; group++) {
    fixture->clients[1].transport->simulated_loss_rate =
        (group == 0 || group == 3) ? 100 : 0;
    for (size_t k = 0; k < 4; k++) {
      transport_publish_result_t result = transport_publish_ex(source, &object);
      CHECK(result == TRANSPORT_PUBLISH_DELIVERED ||
            result == TRANSPORT_PUBLISH_BUFFERED);
    }
    pump(fixture, 60);
  }
  fixture->clients[1].transport->simulated_loss_rate = 0;
  CHECK(source->stats.recovery_checkpoints_sent > 0);
  CHECK(transport_finish_track(source, fixture->track));
  check_delivery(fixture, 40, fixture->count);
  for (size_t attempt = 0;
       attempt < 1000 && source->stats.recovery_cache_releases < 40; attempt++)
    pump(fixture, 2);
  CHECK(source->stats.recovery_cache_releases == 40);
  for (size_t i = 0; i < fixture->count; i++) {
    transport_conn_t *conn = fixture->clients[i].transport->client_conn;
    uint8_t alias;
    CHECK(transport_subscriptions_find_alias(&conn->receive_subscriptions,
                                             &fixture->track, &alias) == 0);
    CHECK(transport_object_gap(conn, alias)->finish_emitted);
  }
}

static void test_cache_pressure(fixture_t *fixture) {
  transport_t *source = fixture->source.transport;
  uint8_t bytes[32] = {42};
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  /* Model a completely unconfirmed prefix occupying the bounded repair
   * cache. New publication must not evict even its oldest object. */
  for (size_t i = 0; i < TRANSPORT_SENT_CACHE_SIZE; i++) {
    object.object_id = i;
    CHECK(transport_sent_cache_store(&source->sent_cache, &object, 1, 1, 32,
                                     false));
  }
  CHECK(!transport_sent_cache_has_space(&source->sent_cache));
  object.object_id = TRANSPORT_SENT_CACHE_SIZE;
  CHECK(transport_publish_ex(source, &object) == TRANSPORT_PUBLISH_BUFFERED);
  CHECK(!transport_publish_flush_grouped(source));
  CHECK(source->stats.recovery_cache_backpressure == 1);
  CHECK(source->stats.flexicast_packets_sent == 0);
  for (size_t i = 0; i < TRANSPORT_SENT_CACHE_SIZE; i++)
    CHECK(transport_sent_cache_find(&source->sent_cache, &fixture->track, 0,
                                    i) != NULL);
}

static void test_video_rateless(fixture_t *fixture) {
  transport_t *source = fixture->source.transport;
  uint8_t bytes[6000];
  uint64_t checksum = 0;
  for (size_t i = 0; i < sizeof(bytes); i++) {
    bytes[i] = (uint8_t)(i * 7);
    checksum = checksum * 33 + bytes[i];
  }
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  /* Hold the encoded payloads before protection so the decoder can be fed a
   * precise erasure pattern, independent of RNG and operating-system loss. */
  fixture->flow->rekey_pending = true;
  CHECK(transport_publish_ex(source, &object) == TRANSPORT_PUBLISH_DELIVERED);
  transport_flexicast_queue_t *queue = &fixture->flow->data_queue;
  CHECK(queue->count > 1);
  for (size_t i = 0; i < queue->count; i++) {
    transport_flexicast_queued_payload_t *payload =
        &queue->entries[(queue->head + i) % queue->capacity];
    qlinq_wire_fec_header_t header;
    CHECK(qlinq_wire_decode_fec_header(payload->data, payload->size, &header) ==
          QLINQ_WIRE_OK);
    if (header.symbol_index == 0)
      continue;
    transport_protocol_receive_datagram(
        fixture->clients[0].transport->client_conn,
        ptls_iovec_init(payload->data, payload->size), false);
  }
  CHECK(fixture->clients[0].received == 0);
  /* Rateless publication is systematic-only. Recover the erased source
   * symbol using on-demand RaptorQ repair, rather than proactive parity. */
  /* Video does not retain the reliable-data recovery cache. Seed a local
   * repair fixture using the exact source envelope to exercise its decoder. */
  qlinq_wire_fec_header_t source_header;
  transport_flexicast_queued_payload_t *first = &queue->entries[queue->head];
  CHECK(qlinq_wire_decode_fec_header(first->data, first->size,
                                     &source_header) == QLINQ_WIRE_OK);
  CHECK(transport_sent_cache_store(
      &source->sent_cache, &object, source_header.total_symbols,
      source_header.data_symbols, source_header.symbol_size, false));
  sent_object_cache_t *cached = transport_sent_cache_find(
      &source->sent_cache, &fixture->track, object.group_id, object.object_id);
  CHECK(cached);
  transport_repair_batch_t repair;
  CHECK(
      transport_repair_build_rateless(&source->fec_cache, cached, 4, &repair));
  for (size_t i = 0; i < repair.count; i++) {
    uint8_t packet[QLINQ_WIRE_FEC_HEADER_SIZE + QLINQ_FEC_MAX_SYMBOL_SIZE];
    qlinq_wire_fec_header_t header = {.alias = fixture->flow->alias,
                                      .group_id = object.group_id,
                                      .object_id = object.object_id,
                                      .symbol_index = repair.indices[i],
                                      .total_symbols = repair.total_symbols,
                                      .data_symbols = cached->data_symbols,
                                      .symbol_size = repair.symbol_size,
                                      .original_size = sizeof(bytes)};
    size_t size = QLINQ_WIRE_FEC_HEADER_SIZE + repair.symbol_size;
    CHECK(qlinq_wire_encode_fec_header(packet, size, &header) == QLINQ_WIRE_OK);
    memcpy(packet + QLINQ_WIRE_FEC_HEADER_SIZE,
           repair.symbols + i * repair.symbol_size, repair.symbol_size);
    transport_protocol_receive_datagram(
        fixture->clients[0].transport->client_conn,
        ptls_iovec_init(packet, size), false);
  }
  transport_repair_batch_destroy(&repair);
  CHECK(fixture->clients[0].received == 1);
  CHECK(fixture->clients[0].last_size == sizeof(bytes));
  CHECK(fixture->clients[0].last_checksum == checksum);
}

/* Feed one systematic symbol directly, so loss and feedback timing do not
 * depend on the network RNG or congestion controller. */
static frame_assembler_t *seed_partial(fixture_t *fixture, uint8_t alias,
                                       uint64_t group_id, uint64_t object_id) {
  uint8_t packet[QLINQ_WIRE_FEC_HEADER_SIZE + 32] = {0};
  qlinq_wire_fec_header_t header = {.alias = alias,
                                    .group_id = group_id,
                                    .object_id = object_id,
                                    .symbol_index = 0,
                                    .total_symbols = 5,
                                    .data_symbols = 4,
                                    .symbol_size = 32,
                                    .original_size = 128,
                                    .priority = 1};
  CHECK(qlinq_wire_encode_fec_header(packet, sizeof(packet), &header) ==
        QLINQ_WIRE_OK);
  transport_conn_t *conn = fixture->clients[0].transport->client_conn;
  transport_protocol_receive_datagram(
      conn, ptls_iovec_init(packet, sizeof(packet)), false);
  frame_assembler_t *assembler =
      transport_find_assembler(conn, alias, group_id, object_id);
  CHECK(assembler && assembler->received_count == 1);
  assembler->first_symbol_time_ms = transport_get_time_ms() - 10000;
  return assembler;
}

static void test_recovery_fairness(fixture_t *fixture) {
  transport_t *receiver = fixture->clients[0].transport;
  transport_conn_t *conn = receiver->client_conn;
  uint8_t alias;
  CHECK(transport_subscriptions_find_alias(&conn->receive_subscriptions,
                                           &fixture->track, &alias) == 0);
  conn->assembler_limit = 32;
  frame_assembler_t *partial = seed_partial(fixture, alias, 0, 0);
  /* Leave enough unrepairable partial objects to keep the partial queue busy
   * after its first request. Whole-object debt must still receive admission. */
  for (size_t i = 0; i < 16; i++)
    (void)seed_partial(fixture, alias, 0, 100 + i);
  transport_object_gap_state_t *gap = transport_object_gap(conn, alias);
  memset(gap, 0, sizeof(*gap));
  int64_t now = transport_get_time_ms();
  gap->pending_base = 1;
  gap->pending_mask = UINT16_MAX;
  gap->detected_at_ms = now - 10000;
  for (size_t i = 0; i < 2; i++)
    gap->recovery_windows[i] =
        (transport_recovery_window_t){.active = true,
                                      .first_object_id = 1 + i * 32,
                                      .final_object_id = 32 + i * 32,
                                      .missing_mask = UINT32_MAX,
                                      .last_request_ms = now - 10000};

  /* Cache only the partial object and the first entirely missing object.
   * Their peers remain missing throughout this test. */
  uint8_t bytes[128] = {0};
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  for (size_t id = 0; id < 2; id++) {
    object.object_id = id;
    CHECK(transport_sent_cache_store(&fixture->source.transport->sent_cache,
                                     &object, 5, 4, 32, false));
  }
  receiver->limits.max_repair_requests_per_second = 1;
  receiver->limits.max_aggregate_nack_requests_per_second = 1;
  uint64_t requests = receiver->stats.repair_requests_sent;
  uint64_t whole = receiver->stats.repair_whole_object_requests_sent;
  for (size_t round = 0; round < 4; round++) {
    /* Replenish exactly one token without sleeping or advancing assembler
     * expiry. Alternation must survive exhausting both admission limits. */
    now = transport_get_time_ms();
    conn->nack_request_limiter = (transport_repair_limiter_t){
        .tokens_milli = 1000, .last_refill_ms = now};
    receiver->aggregate_nack_limiter = conn->nack_request_limiter;
    transport_tick(receiver);
    CHECK(receiver->stats.repair_requests_sent == requests + round + 1);
    CHECK(receiver->stats.repair_whole_object_requests_sent ==
          whole + (round + 2) / 2);
  }
  CHECK(partial->object_id == 0 && partial->nack_attempt == 1);
  CHECK(gap->pending_mask != 0);
  CHECK(gap->recovery_windows[0].missing_mask != 0);
  for (size_t attempt = 0; attempt < 1500 && fixture->clients[0].received < 2;
       attempt++)
    pump(fixture, 1);
  if (fixture->clients[0].received != 2)
    fprintf(
        stderr,
        "fairness received=%zu lost=%llu sent=%llu whole=%llu "
        "source_requests=%llu symbols=%llu partial_count=%u\n",
        fixture->clients[0].received,
        (unsigned long long)receiver->stats.fec_objects_lost,
        (unsigned long long)receiver->stats.repair_requests_sent,
        (unsigned long long)receiver->stats.repair_whole_object_requests_sent,
        (unsigned long long)
            fixture->source.transport->stats.repair_requests_received,
        (unsigned long long)
            fixture->source.transport->stats.repair_symbols_sent,
        partial->received_count);
  CHECK(fixture->clients[0].received == 2);
  CHECK(fixture->clients[0].last_size == sizeof(bytes));
  CHECK(fixture->clients[0].last_checksum == 0);
  CHECK(receiver->stats.fec_objects_lost == 0);
}

static void test_recovery_dedup(fixture_t *fixture) {
  transport_t *receiver = fixture->clients[0].transport;
  transport_conn_t *conn = receiver->client_conn;
  uint8_t alias;
  CHECK(transport_subscriptions_find_alias(&conn->receive_subscriptions,
                                           &fixture->track, &alias) == 0);
  receiver->limits.max_repair_requests_per_second = 128;
  receiver->limits.max_aggregate_nack_requests_per_second = 128;
  for (size_t shared = 0; shared < 2; shared++) {
    frame_assembler_t *partial = seed_partial(fixture, alias, shared, 0);
    partial->shared_delivery = shared != 0;
    transport_object_gap_state_t *gap = transport_object_gap(conn, alias);
    memset(gap, 0, sizeof(*gap));
    gap->group_id = shared;
    gap->pending_mask = UINT16_MAX;
    gap->shared_delivery = shared != 0;
    gap->detected_at_ms = transport_get_time_ms() - 10000;
    gap->recovery_windows[0] =
        (transport_recovery_window_t){.active = true,
                                      .group_id = shared,
                                      .final_object_id = 15,
                                      .missing_mask = UINT16_MAX,
                                      .last_request_ms = gap->detected_at_ms};
    memset(&conn->nack_request_limiter, 0, sizeof(conn->nack_request_limiter));
    memset(&receiver->aggregate_nack_limiter, 0,
           sizeof(receiver->aggregate_nack_limiter));
    uint64_t sent = receiver->stats.repair_requests_sent;
    uint64_t whole = receiver->stats.repair_whole_object_requests_sent;
    uint64_t coalesced = receiver->stats.repair_requests_coalesced;
    transport_tick(receiver);
    /* Fifteen entirely missing objects and one partial, each requested once.
     * In particular, the gap pass must not duplicate the window's requests or
     * request the whole object already owned by the partial assembler. */
    if (receiver->stats.repair_requests_sent != sent + 16)
      fprintf(stderr,
              "dedup shared=%zu sent=%llu whole=%llu coalesced=%llu "
              "partial_attempt=%u\n",
              shared,
              (unsigned long long)(receiver->stats.repair_requests_sent - sent),
              (unsigned long long)(receiver->stats
                                       .repair_whole_object_requests_sent -
                                   whole),
              (unsigned long long)(receiver->stats.repair_requests_coalesced -
                                   coalesced),
              partial->nack_attempt);
    CHECK(receiver->stats.repair_requests_sent == sent + 16);
    CHECK(receiver->stats.repair_whole_object_requests_sent == whole + 15);
    CHECK(receiver->stats.repair_requests_coalesced == coalesced);
    CHECK(partial->nack_attempt == 1);
    transport_release_assembler(receiver, partial);
  }
}

static void test_feedback_deadline(void) {
  transport_flexicast_flow_t flow = {0};
  transport_flexicast_member_t member = {0};
  flow.cc_config.feedback_timeout_msec = 1000;
  flow.cc_config.minimum_rate_bytes_per_second = 250;
  flow.cc_config.maximum_datagram_size = 1280;
  flow.ack_delay_msec = 25;
  flow.delivery_epoch = 1;
  member.listening = true;
  member.acknowledged_delivery_epoch = 1;
  CHECK(tf_member_feedback_deadline(&flow, &member) == INT64_MAX);
  member.acknowledged_delivery_epoch = 0;
  /* No actual submitted packet means no timer, even with queued debt. */
  CHECK(tf_member_feedback_deadline(&flow, &member) == INT64_MAX);
  member.first_unacknowledged_ms = 1000;
  CHECK(tf_member_feedback_deadline(&flow, &member) == 4000);
  flow.cc_config.minimum_rate_bytes_per_second = 1;
  CHECK(tf_member_feedback_deadline(&flow, &member) == 4000);
  flow.ack_delay_msec = 2000;
  CHECK(tf_member_feedback_deadline(&flow, &member) == 7000);
  member.acknowledged_delivery_epoch = 1;
  CHECK(tf_member_feedback_deadline(&flow, &member) == INT64_MAX);
}

#include "test_flexicast_ecn.inc"
#include "test_flexicast_pacer.inc"
#include "test_flexicast_review.inc"

int main(int argc, char **argv) {
  test_feedback_deadline();
  const char *mode = argc > 1 ? argv[1] : "pacing";
  size_t count = argc > 2 ? strtoul(argv[2], NULL, 10) : 2;
  CHECK(count > 0 && count <= MAX_CLIENTS);
  fixture_t fixture;
  create_fixture(&fixture, count, argc > 3, mode);
  if (strcmp(mode, "review-shadow") == 0)
    test_review_shadow(&fixture);
  else if (strcmp(mode, "review-control") == 0)
    test_review_control(&fixture);
  else if (strcmp(mode, "review-reoffer") == 0)
    test_review_reoffer(&fixture);
  else if (strcmp(mode, "review-systematic-rateless") == 0)
    test_review_systematic(&fixture);
  else if (strcmp(mode, "review-fixed") == 0 ||
           strcmp(mode, "review-rateless") == 0)
    test_review_repairs(&fixture, strstr(mode, "rateless") != NULL);
  else if (strcmp(mode, "pacer-high") == 0 ||
           strcmp(mode, "pacer-maximum") == 0)
    test_high_rate_pacer(&fixture);
  else if (strcmp(mode, "pacer-aliases") == 0)
    test_aggregate_pacer(&fixture);
  else if (strcmp(mode, "pacer-rtt") == 0)
    test_submitted_rtt(&fixture);
  else if (strcmp(mode, "pacer-native-fallback") == 0)
    test_native_fallback_pacing(&fixture);
  else if (strcmp(mode, "ecn") == 0 || strcmp(mode, "native-ecn") == 0)
    test_ecn(&fixture, strstr(mode, "native") != NULL);
  else if (strcmp(mode, "blocked-fanout") == 0)
    test_blocked_fanout(&fixture);
  else if (strcmp(mode, "native-ingress") == 0)
    test_native_ingress(&fixture);
  else if (strcmp(mode, "rateless-recovery-fairness") == 0)
    test_recovery_fairness(&fixture);
  else if (strcmp(mode, "rateless-recovery-dedup") == 0)
    test_recovery_dedup(&fixture);
  else if (strcmp(mode, "rateless-ready-baseline") == 0)
    test_ready_baseline(&fixture);
  else if (strstr(mode, "rekey") || strcmp(mode, "control-queue") == 0)
    test_rekey(&fixture, mode);
  else if (strcmp(mode, "controls") == 0)
    test_controls(&fixture);
  else if (strcmp(mode, "limits") == 0)
    test_limits(&fixture);
  else if (strstr(mode, "cache"))
    test_cache_pressure(&fixture);
  else if (strcmp(mode, "video-rateless") == 0)
    test_video_rateless(&fixture);
  else if (strstr(mode, "fixed") || strstr(mode, "rateless"))
    test_recovery(&fixture);
  else
    test_delivery(&fixture, strstr(mode, "native") != NULL);
  destroy_fixture(&fixture);
  puts("===FLEXICAST REGRESSIONS OK===");
  return 0;
}
