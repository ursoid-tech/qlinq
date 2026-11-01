#include "transport_fixture.h"
#include "transport_publish.h"
#include "transport_sim_host.h"
#include "transport_stream.h"
#include "transport_wire.h"

#include <stdio.h>
#include <stdlib.h>

/* Drop over-MTU UDP packets after the host accepts them. This exercises the
 * native probe and loss timers without sockets or direct Quicly state edits. */
typedef struct {
  sim_node_t node;
  size_t mtu[TRANSPORT_MAX_PATHS];
  size_t oversized[TRANSPORT_MAX_PATHS];
  size_t largest[TRANSPORT_MAX_PATHS];
} mtu_host_t;

typedef struct mtu_endpoint mtu_endpoint_t;
typedef struct {
  quicly_receive_datagram_frame_t callback;
  mtu_endpoint_t *endpoint;
} capture_t;

struct mtu_endpoint {
  fixture_endpoint_t base;
  capture_t capture;
  size_t symbols, largest_symbol;
  uint64_t observe_group;
  size_t observed_symbols, observed_symbol_size;
};

typedef struct {
  sim_network_t network;
  mtu_host_t hosts[2];
  mtu_endpoint_t endpoints[2];
} mtu_fixture_t;

static ssize_t send_mtu(void *context, const transport_drive_path_t *path,
                        const struct sockaddr *source,
                        const struct sockaddr *destination, socklen_t len,
                        uint32_t ifindex, uint8_t ecn, size_t gso,
                        const struct iovec *datagrams, size_t count) {
  mtu_host_t *host = context;
  size_t physical = 0;
  while (physical < host->node.path_count &&
         host->node.paths[physical].id != path->id)
    physical++;
  assert(physical < host->node.path_count);
  size_t mtu = host->mtu[physical];
  for (size_t n = 0; n < host->node.network->nodes_count; n++) {
    mtu_host_t *peer = (mtu_host_t *)host->node.network->nodes[n];
    for (size_t p = 0; p < peer->node.path_count; p++)
      if (transport_endpoint_equal(
              destination,
              (const struct sockaddr *)&peer->node.paths[p].local) &&
          peer->mtu[p] < mtu)
        mtu = peer->mtu[p];
  }
  size_t accepted = 0;
  for (size_t i = 0; i < count; i++) {
    if (datagrams[i].iov_len > host->largest[physical])
      host->largest[physical] = datagrams[i].iov_len;
    if (datagrams[i].iov_len > mtu) {
      host->oversized[physical]++;
      host->node.network->dropped++;
      accepted++;
      continue;
    }
    ssize_t sent = sim_send(&host->node, path, source, destination, len,
                            ifindex, ecn, gso, &datagrams[i], 1);
    if (sent <= 0)
      return accepted ? (ssize_t)accepted : sent;
    accepted++;
  }
  return (ssize_t)accepted;
}

static void capture_datagram(quicly_receive_datagram_frame_t *self,
                             quicly_conn_t *quic, ptls_iovec_t payload) {
  mtu_endpoint_t *endpoint = ((capture_t *)self)->endpoint;
  qlinq_wire_fec_header_t header;
  if (qlinq_wire_decode_fec_header(payload.base, payload.len, &header) ==
      QLINQ_WIRE_OK) {
    assert(payload.len == QLINQ_WIRE_FEC_HEADER_SIZE + header.symbol_size);
    endpoint->symbols++;
    if (header.symbol_size > endpoint->largest_symbol)
      endpoint->largest_symbol = header.symbol_size;
    if (header.group_id == endpoint->observe_group) {
      endpoint->observed_symbols++;
      if (endpoint->observed_symbol_size)
        assert(endpoint->observed_symbol_size == header.symbol_size);
      endpoint->observed_symbol_size = header.symbol_size;
    }
  }
  transport_t *t = endpoint->base.transport;
  t->receive_datagram.cb(&t->receive_datagram, quic, payload);
}

static void step(mtu_fixture_t *f, size_t milliseconds) {
  for (size_t i = 0; i < milliseconds; i++) {
    sim_advance(&f->network, 1000000U);
    assert(!f->endpoints[0].base.failed && !f->endpoints[1].base.failed);
  }
}

static mtu_fixture_t *create_topology(size_t paths, size_t first_mtu,
                                      size_t second_mtu, size_t server_limit,
                                      size_t client_limit, bool legacy_server,
                                      bool shared_socket) {
  mtu_fixture_t *f = calloc(1, sizeof(*f));
  assert(f);
  f->network.now_ns = 1000000000U;
  f->endpoints[0].base.server = true;
  for (size_t i = 0; i < 2; i++) {
    f->hosts[i].mtu[0] = shared_socket && !i ? second_mtu : first_mtu;
    f->hosts[i].mtu[1] = second_mtu;
    transport_drive_host_t host = sim_host(&f->hosts[i].node, &f->network);
    host.send = send_mtu;
    transport_config_t config = {
        .bind_hosts = {i ? "127.85.1.2" : "127.85.1.1",
                       i ? "127.85.2.2" : "127.85.2.1"},
        .num_bind_hosts = shared_socket && !i ? 1 : paths,
        .port = 19879,
        .allow_insecure_peer = true,
        .callback = fixture_event,
        .user_data = &f->endpoints[i].base,
        .cert_file = "t/assets/server.crt",
        .key_file = "t/assets/server.key",
        .drive_host = &host,
        .limits = {.max_udp_payload_size = i ? client_limit : server_limit}};
    if (i) {
      config.remote_hosts[0] = "127.85.1.1";
      config.remote_hosts[1] = "127.85.2.1";
      config.num_remote_hosts = shared_socket ? 1 : paths;
    }
    transport_t *t = transport_drive_create(&config);
    assert(t && t->quic_ctx.egress[0].enable_pmtud);
    /* Older QLINQ advertised its default native receive size independently
     * of the lower application ceiling subsequently sent in HELLO. */
    if (legacy_server && i == 0)
      t->quic_ctx.transport_params.max_udp_payload_size = 1472;
    f->endpoints[i].base.transport = t;
    f->hosts[i].node.transport = t;
    f->endpoints[i].capture = (capture_t){.callback = {capture_datagram},
                                          .endpoint = &f->endpoints[i]};
    t->quic_ctx.receive_datagram_frame = &f->endpoints[i].capture.callback;
  }
  for (size_t i = 0; i < 10000 && !f->endpoints[1].base.authenticated; i++)
    step(f, 1);
  assert(f->endpoints[0].base.authenticated &&
         f->endpoints[1].base.authenticated);
  return f;
}

static mtu_fixture_t *create_limits_native(size_t paths, size_t first_mtu,
                                           size_t second_mtu,
                                           size_t server_limit,
                                           size_t client_limit,
                                           bool legacy_server) {
  return create_topology(paths, first_mtu, second_mtu, server_limit,
                         client_limit, legacy_server, false);
}

static mtu_fixture_t *create_limits(size_t paths, size_t first_mtu,
                                    size_t second_mtu, size_t server_limit,
                                    size_t client_limit) {
  return create_limits_native(paths, first_mtu, second_mtu, server_limit,
                              client_limit, false);
}

static mtu_fixture_t *create(size_t paths, size_t first_mtu,
                             size_t second_mtu) {
  return create_limits(paths, first_mtu, second_mtu, 1280, 1280);
}

static void destroy(mtu_fixture_t *f) {
  for (size_t i = 0; i < 2; i++) {
    transport_destroy(f->endpoints[i].base.transport);
    f->hosts[i].node.transport = NULL;
  }
  free(f);
}

static void subscribe(mtu_fixture_t *f, moq_track_id_t track) {
  fixture_endpoint_t *client = &f->endpoints[1].base;
  size_t expected = f->endpoints[0].base.subscriptions + 1;
  assert(transport_subscribe_conn(client->transport, client->conn, track));
  for (size_t i = 0; i < 5000 && f->endpoints[0].base.subscriptions < expected;
       i++)
    step(f, 1);
  assert(f->endpoints[0].base.subscriptions == expected);
}

static size_t native_path(mtu_fixture_t *f, size_t physical) {
  transport_t *t = f->endpoints[0].base.transport;
  quicly_path_stats_t stats;
  return transport_path_get_eligible_by_local(f->endpoints[0].base.conn->quic,
                                              &t->sockets[physical].local_addr,
                                              &stats);
}

static void receive_object(mtu_fixture_t *f, size_t expected,
                           const uint8_t *payload, size_t size) {
  for (size_t i = 0; i < 5000 && f->endpoints[1].base.objects < expected; i++)
    step(f, 1);
  fixture_endpoint_t *client = &f->endpoints[1].base;
  assert(client->objects == expected && client->payload_size == size &&
         memcmp(client->payload, payload, size) == 0);
}

static void inject_nack(quicly_stream_t *stream, uint8_t alias, uint64_t group,
                        uint64_t object) {
  uint8_t nack[64], frame[128];
  uint16_t missing = 0;
  size_t nack_len;
  assert(qlinq_wire_encode_nack(nack, sizeof(nack), alias, 0, group, object,
                                &missing, 1, &nack_len) == QLINQ_WIRE_OK);
  assert(qlinq_wire_encode_frame_header(
             frame, sizeof(frame), QLINQ_WIRE_NACK, nack_len,
             TRANSPORT_WIRE_MAX_STREAM_PAYLOAD) == QLINQ_WIRE_OK);
  memcpy(frame + QLINQ_WIRE_FRAME_HEADER_SIZE, nack, nack_len);
  size_t received = QLINQ_WIRE_FRAME_HEADER_SIZE + nack_len;
  size_t offset = transport_stream_ingress_get(stream).len;
  uint64_t absolute_offset = stream->recvstate.data_off + offset;
  assert(quicly_recvstate_update(&stream->recvstate, &absolute_offset,
                                 &received, 0, UINT64_MAX) == 0);
  assert(received == QLINQ_WIRE_FRAME_HEADER_SIZE + nack_len);
  stream->callbacks->on_receive(stream, offset, frame, received);
}

static void differing_path_mtu(void) {
  mtu_fixture_t *f = create(2, 1200, 1280);
  moq_track_id_t track = {.type = MOQ_TRACK_VIDEO,
                          .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                          .name = "path-mtu"};
  subscribe(f, track);
  /* Let each native PMTU search finish, including lost probes on path zero. */
  step(f, 5000);
  transport_t *t = f->endpoints[0].base.transport;
  transport_conn_t *conn = f->endpoints[0].base.conn;
  size_t paths[2] = {native_path(f, 0), native_path(f, 1)};
  assert(paths[0] != SIZE_MAX && paths[1] != SIZE_MAX);
  size_t limits[2] = {quicly_get_datagram_payload_limit(conn->quic, paths[0]),
                      quicly_get_datagram_payload_limit(conn->quic, paths[1])};
  assert(limits[0] > QLINQ_WIRE_FEC_HEADER_SIZE && limits[1] > limits[0]);
  assert(transport_mock_path_state(t, 0, 100000, 10, 0));
  assert(transport_mock_path_state(t, 1, 100000, 10, 0));
  uint8_t payload[3000];
  memset(payload, 0x5a, sizeof(payload));
  moq_object_t object = {.track_id = track,
                         .group_id = 1,
                         .object_id = 0,
                         .data = payload,
                         .size = sizeof(payload)};
  assert(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_DELIVERED);
  receive_object(f, 1, payload, sizeof(payload));
  assert(f->endpoints[1].symbols > 0 &&
         f->endpoints[1].largest_symbol + QLINQ_WIRE_FEC_HEADER_SIZE <=
             limits[0]);

  /* A cached object keeps its original symbol size; repair placement must
   * avoid the smaller path even when its queue and bandwidth look preferable.
   */
  step(f, 100);
  size_t symbol_size = limits[1] - QLINQ_WIRE_FEC_HEADER_SIZE;
  object.group_id = 900;
  object.size = 2000;
  assert(transport_sent_cache_store(&t->sent_cache, &object, 2, 2,
                                    (uint16_t)symbol_size, true));
  sent_object_cache_t *cached =
      transport_sent_cache_find(&t->sent_cache, &track, 900, 0);
  assert(cached && cached->symbol_size == symbol_size);
  uint8_t alias;
  assert(transport_subscriptions_find_alias(&conn->send_subscriptions, &track,
                                            &alias) == 0);
  size_t before[2] = {
      quicly_get_num_datagram_frames_path(conn->quic, paths[0]),
      quicly_get_num_datagram_frames_path(conn->quic, paths[1])};
  f->endpoints[1].observe_group = 900;
  inject_nack(conn->stream, alias, 900, 0);
  assert(quicly_get_num_datagram_frames_path(conn->quic, paths[0]) ==
         before[0]);
  assert(quicly_get_num_datagram_frames_path(conn->quic, paths[1]) ==
         before[1] + 1);
  for (size_t i = 0; i < 100 && !f->endpoints[1].observed_symbols; i++)
    step(f, 1);
  assert(f->endpoints[1].observed_symbols > 0 &&
         f->endpoints[1].observed_symbol_size == symbol_size &&
         cached->symbol_size == symbol_size);
  assert(f->hosts[0].largest[0] <= 1280 && f->hosts[0].largest[1] <= 1280);
  destroy(f);
}

static void admission_limits(void) {
  mtu_fixture_t *f = create(1, 1280, 0);
  moq_track_id_t track = {.type = MOQ_TRACK_VIDEO,
                          .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                          .name = "native-admission"};
  subscribe(f, track);
  step(f, 100);
  transport_t *t = f->endpoints[0].base.transport;
  transport_conn_t *conn = f->endpoints[0].base.conn;
  size_t path = native_path(f, 0);
  assert(path != SIZE_MAX);
  quicly_discard_datagram_frames(conn->quic, path);
  t->quic_ctx.max_datagram_frame_payloads = 4;
  assert(quicly_get_max_datagram_frames_path(conn->quic, path) == 4);
  size_t limit = quicly_get_datagram_payload_limit(conn->quic, path);
  uint8_t payload[1500] = {0xff};
  assert(limit > 0 && limit < sizeof(payload));
  assert(!transport_queue_datagram(conn, path,
                                   ptls_iovec_init(payload, limit + 1)));
  assert(quicly_get_num_datagram_frames_path(conn->quic, path) == 0);
  assert(transport_mock_path_state(t, 0, 100000, 10, 0));
  assert(transport_is_track_ready(t, &track));
  for (size_t i = 0; i < 4; i++)
    assert(transport_queue_datagram(conn, path, ptls_iovec_init(payload, 1)));
  assert(quicly_get_datagram_payload_limit(conn->quic, path) == 0);
  assert(!transport_is_track_ready(t, &track));
  assert(!transport_queue_datagram(conn, path, ptls_iovec_init(payload, 1)));
  moq_object_t object = {.track_id = track, .data = payload, .size = 1000};
  assert(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_BACKPRESSURE);
  assert(quicly_get_num_datagram_frames_path(conn->quic, path) == 4);
  step(f, 100);
  assert(quicly_get_num_datagram_frames_path(conn->quic, path) == 0);
  assert(transport_is_track_ready(t, &track));
  assert(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_DELIVERED);
  receive_object(f, 1, payload, 1000);
  destroy(f);
}

static void mtu_blackhole_fallback(void) {
  mtu_fixture_t *f = create(1, 1280, 0);
  moq_track_id_t track = {.type = MOQ_TRACK_VIDEO,
                          .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                          .name = "mtu-fallback"};
  subscribe(f, track);
  step(f, 200);
  transport_t *t = f->endpoints[0].base.transport;
  transport_conn_t *conn = f->endpoints[0].base.conn;
  size_t path = native_path(f, 0);
  assert(path != SIZE_MAX);
  size_t large_limit = quicly_get_datagram_payload_limit(conn->quic, path);
  assert(large_limit > 1200);
  uint8_t object_payload[3000];
  memset(object_payload, 0x6b, sizeof(object_payload));
  moq_object_t object = {
      .track_id = track, .group_id = 54, .data = object_payload, .size = 2000};
  size_t original_symbol = large_limit - QLINQ_WIRE_FEC_HEADER_SIZE;
  assert(transport_sent_cache_store(&t->sent_cache, &object, 2, 2,
                                    (uint16_t)original_symbol, true));
  sent_object_cache_t *cached =
      transport_sent_cache_find(&t->sent_cache, &track, 54, 0);
  assert(cached);
  f->hosts[0].mtu[0] = 1200;
  uint8_t payload[1500] = {0xff};
  size_t small_limit = large_limit;
  for (size_t i = 0; i < 100 && small_limit == large_limit; i++) {
    /* Full packets are lost while small packets and their ACKs still pass. */
    assert(transport_queue_datagram(conn, path,
                                    ptls_iovec_init(payload, large_limit)));
    step(f, 10);
    assert(transport_queue_datagram(conn, path, ptls_iovec_init(payload, 1)));
    step(f, 30);
    small_limit = quicly_get_datagram_payload_limit(conn->quic, path);
  }
  assert(f->hosts[0].oversized[0] >= 3 && small_limit > 0 &&
         small_limit < large_limit && small_limit < 1200);
  assert(!transport_queue_datagram(conn, path,
                                   ptls_iovec_init(payload, large_limit)));
  /* A cached repair cannot be resized after its object envelope was sent.
   * With no sufficiently large path, it must remain out of the native queue. */
  uint8_t alias;
  assert(transport_subscriptions_find_alias(&conn->send_subscriptions, &track,
                                            &alias) == 0);
  size_t queued = quicly_get_num_datagram_frames_path(conn->quic, path);
  uint64_t failures = t->stats.repair_queue_failures;
  inject_nack(conn->stream, alias, 54, 0);
  assert(quicly_get_num_datagram_frames_path(conn->quic, path) == queued &&
         t->stats.repair_queue_failures > failures &&
         cached->symbol_size == original_symbol);
  assert(transport_mock_path_state(t, 0, 100000, 10, 0));
  object.group_id = 55;
  object.size = sizeof(object_payload);
  assert(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_DELIVERED);
  receive_object(f, 1, object_payload, sizeof(object_payload));
  assert(f->endpoints[1].largest_symbol + QLINQ_WIRE_FEC_HEADER_SIZE <=
         small_limit);
  assert(f->hosts[0].largest[0] <= 1280);
  destroy(f);
}

static void asymmetric_configured_limits(void) {
  /* The peer and physical network allow 1472, but the server's configured
   * 1280 ceiling must bound native probes as well as application packets. */
  mtu_fixture_t *f = create_limits(1, 1472, 0, 1280, 1472);
  step(f, 500);
  quicly_conn_t *server = f->endpoints[0].base.conn->quic;
  quicly_conn_t *client = f->endpoints[1].base.conn->quic;
  assert(quicly_get_remote_transport_parameters(server)->max_udp_payload_size ==
         1472);
  assert(quicly_get_remote_transport_parameters(client)->max_udp_payload_size ==
         1280);
  size_t limit = quicly_get_datagram_payload_limit(server, native_path(f, 0));
  assert(limit > 1200 && limit < 1280);
  assert(f->hosts[0].largest[0] <= 1280 && f->hosts[1].largest[0] <= 1280);
  assert(!f->hosts[0].oversized[0] && !f->hosts[1].oversized[0]);
  destroy(f);
}

static void legacy_hello_limit(void) {
  mtu_fixture_t *f = create_limits_native(1, 1472, 0, 1200, 1472, true);
  transport_t *sender = f->endpoints[1].base.transport;
  transport_conn_t *conn = f->endpoints[1].base.conn;
  assert(conn->negotiated_limits.max_udp_payload_size == 1200);
  assert(quicly_get_remote_transport_parameters(conn->quic)
             ->max_udp_payload_size == 1472);
  assert(quicly_set_max_udp_payload_size(conn->quic, 1199) == -1);
  assert(quicly_set_max_udp_payload_size(NULL, 1200) == -1);
  /* HELLO has completed. Every subsequent UDP packet, including PMTU probes
   * and repair/control traffic, must respect its additional 1200-byte cap. */
  f->hosts[1].largest[0] = 0;
  moq_track_id_t track = {.type = MOQ_TRACK_VIDEO,
                          .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                          .name = "legacy-hello"};
  fixture_endpoint_t *receiver = &f->endpoints[0].base;
  assert(transport_subscribe_conn(receiver->transport, receiver->conn, track));
  for (size_t i = 0; i < 5000 && !f->endpoints[1].base.subscriptions; i++)
    step(f, 1);
  assert(f->endpoints[1].base.subscriptions == 1);
  assert(transport_mock_path_state(sender, 0, 100000, 10, 0));
  uint8_t payload[3000];
  memset(payload, 0x5d, sizeof(payload));
  moq_object_t object = {.track_id = track,
                         .group_id = 902,
                         .data = payload,
                         .size = sizeof(payload)};
  assert(transport_publish_ex(sender, &object) == TRANSPORT_PUBLISH_DELIVERED);
  for (size_t i = 0; i < 5000 && !receiver->objects; i++)
    step(f, 1);
  assert(receiver->objects == 1 && receiver->payload_size == sizeof(payload));
  assert(memcmp(receiver->payload, payload, sizeof(payload)) == 0);
  step(f, 5000);
  assert(f->hosts[1].largest[0] > 0 && f->hosts[1].largest[0] <= 1200);
  assert(quicly_get_remote_transport_parameters(conn->quic)
             ->max_udp_payload_size == 1472);
  destroy(f);
}

static void shared_socket_mtu(void) {
  mtu_fixture_t *f = create_topology(2, 1200, 1280, 1280, 1280, false, true);
  moq_track_id_t track = {.type = MOQ_TRACK_VIDEO,
                          .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                          .name = "shared-socket-mtu"};
  subscribe(f, track);
  step(f, 5000);
  transport_t *t = f->endpoints[0].base.transport;
  transport_conn_t *conn = f->endpoints[0].base.conn;
  assert(t->socket_count == 1 && f->hosts[1].node.path_count == 2);
  size_t paths[2], limits[2], count = 0;
  for (size_t path = 0; path < TRANSPORT_MAX_QUIC_PATHS; path++) {
    size_t limit = transport_datagram_payload_limit(conn, path);
    if (limit != 0) {
      assert(count < 2);
      paths[count] = path;
      limits[count++] = limit;
    }
  }
  assert(count == 2 && limits[0] < limits[1]);
  assert(transport_mock_path_state(t, 0, 100000, 10, 0));
  /* The first path on this socket cannot fit the cached symbol. Selection
   * must continue to the alternate instead of dropping the physical socket. */
  transport_publication_path_t candidates[TRANSPORT_MAX_PATHS];
  assert(transport_publish_collect_paths(t, conn, limits[1], limits[1],
                                         transport_now_ns(t), candidates) == 1);
  assert(candidates[0].physical == 0 && candidates[0].quic == paths[1]);
  uint8_t payload[2000];
  memset(payload, 0x79, sizeof(payload));
  moq_object_t object = {.track_id = track,
                         .group_id = 903,
                         .data = payload,
                         .size = sizeof(payload)};
  size_t symbol_size = limits[1] - QLINQ_WIRE_FEC_HEADER_SIZE;
  assert(transport_sent_cache_store(&t->sent_cache, &object, 2, 2,
                                    (uint16_t)symbol_size, true));
  uint8_t alias;
  assert(transport_subscriptions_find_alias(&conn->send_subscriptions, &track,
                                            &alias) == 0);
  size_t before[2] = {
      quicly_get_num_datagram_frames_path(conn->quic, paths[0]),
      quicly_get_num_datagram_frames_path(conn->quic, paths[1])};
  f->endpoints[1].observe_group = 903;
  inject_nack(conn->stream, alias, 903, 0);
  assert(quicly_get_num_datagram_frames_path(conn->quic, paths[0]) ==
         before[0]);
  assert(quicly_get_num_datagram_frames_path(conn->quic, paths[1]) ==
         before[1] + 1);
  for (size_t i = 0; i < 100 && !f->endpoints[1].observed_symbols; i++)
    step(f, 1);
  assert(f->endpoints[1].observed_symbols &&
         f->endpoints[1].observed_symbol_size == symbol_size);
  destroy(f);
}

int main(void) {
  differing_path_mtu();
  admission_limits();
  mtu_blackhole_fallback();
  asymmetric_configured_limits();
  legacy_hello_limit();
  shared_socket_mtu();
  puts("===DATAGRAM MTU OK===");
  return 0;
}
