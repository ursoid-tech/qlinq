#include "transport_internal.h"
#include "transport_wire.h"

#include <assert.h>
#include <stdio.h>
#include <unistd.h>

typedef struct {
  transport_t *transport;
  transport_conn_t *conn;
  bool server, authenticated, subscribed;
  size_t received;
} endpoint_t;

static void event(void *data, const transport_event_t *e) {
  endpoint_t *endpoint = data;
  if (e->type == TRANSPORT_EVENT_CONNECTED) {
    endpoint->conn = e->conn;
    if (!endpoint->server)
      assert(transport_send_auth(endpoint->transport, e->conn,
                                 (const uint8_t *)"feedback", 8));
  } else if (e->type == TRANSPORT_EVENT_AUTH) {
    assert(transport_respond_auth(endpoint->transport, e->conn, true));
    endpoint->authenticated = true;
  } else if (e->type == TRANSPORT_EVENT_AUTH_COMPLETE) {
    assert(e->auth.success);
    endpoint->authenticated = true;
  } else if (e->type == TRANSPORT_EVENT_SUBSCRIBE) {
    endpoint->subscribed = true;
  } else if (e->type == TRANSPORT_EVENT_OBJECT) {
    assert(e->object.object_id == endpoint->received);
    assert(e->object.size == 4096);
    for (size_t i = 0; i < e->object.size; i++)
      assert(e->object.data[i] == (uint8_t)(endpoint->received + i));
    endpoint->received++;
  } else if (e->type == TRANSPORT_EVENT_DISCONNECTED) {
    assert(!"unexpected disconnect");
  }
}

static void tick(endpoint_t *server, endpoint_t *client) {
  transport_tick(server->transport);
  transport_tick(client->transport);
}

static void check_reliable_override(endpoint_t *server, endpoint_t *client,
                                    moq_track_id_t track,
                                    size_t measured_path) {
  transport_conn_path_t *physical = &server->conn->paths[0];
  /* Exercise an explicit override before any automatic measurement, then an
   * override with history for only one of the socket's two remote paths.
   * Automatic history belongs to one native path; an explicit physical test
   * override must apply to every native path using that socket. */
  *physical = (transport_conn_path_t){0};
  if (measured_path != SIZE_MAX) {
    quicly_path_stats_t stats;
    assert(quicly_get_path_stats(server->conn->quic, measured_path, &stats) ==
           0);
    assert(transport_path_measure(&physical->measurement, &stats, measured_path,
                                  0, (uint64_t)transport_get_time_ms()));
  }
  assert(transport_mock_path_state(server->transport, 0, 1000, 0.0, 1.0));
  size_t before = client->received;
  uint8_t payload[4096];
  for (size_t i = 0; i < sizeof(payload); i++)
    payload[i] = (uint8_t)(before + i);
  moq_object_t object = {.track_id = track,
                         .group_id = 1,
                         .object_id = before,
                         .data = payload,
                         .size = sizeof(payload)};
  assert(transport_publish(server->transport, &object));
  for (size_t attempt = 0; attempt < 20; attempt++) {
    tick(server, client);
    usleep(1000);
  }
  assert(client->received == before);
  assert(quicly_has_pending_stream_data(server->conn->quic));
  assert(physical->measurement.initialized == (measured_path != SIZE_MAX));
  if (measured_path != SIZE_MAX)
    assert(physical->measurement.quic_path == measured_path);

  /* Removing the deterministic block restores delivery of the same queued
   * record, proving that admission or subscription did not reject it. */
  *physical = (transport_conn_path_t){0};
  for (size_t attempt = 0; attempt < 1000 && client->received == before;
       attempt++) {
    tick(server, client);
    usleep(1000);
  }
  assert(client->received == before + 1);
}

int main(void) {
  endpoint_t server = {.server = true}, client = {0};
  transport_config_t config = {.bind_hosts = {"127.83.1.1"},
                               .num_bind_hosts = 1,
                               .port = 19877,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .allow_insecure_peer = true,
                               .callback = event,
                               .user_data = &server};
  server.transport = transport_create(&config);
  assert(server.transport);
  config.bind_hosts[0] = "127.83.1.2";
  config.bind_hosts[1] = "127.83.2.2";
  config.num_bind_hosts = 2;
  config.remote_hosts[0] = "127.83.1.1";
  config.num_remote_hosts = 1;
  config.user_data = &client;
  client.transport = transport_create(&config);
  assert(client.transport);

  size_t paths[2], count = 0;
  for (size_t attempt = 0; attempt < 2000; attempt++) {
    tick(&server, &client);
    count = 0;
    if (server.authenticated && client.authenticated)
      for (size_t path = 0; path < TRANSPORT_MAX_QUIC_PATHS && count < 2;
           path++) {
        quicly_path_health_t health;
        if (quicly_get_path_health(server.conn->quic, path, &health) == 0 &&
            health.validated && !health.abandoned && !health.probe_only &&
            health.state == QUICLY_PATH_USABLE)
          paths[count++] = path;
      }
    if (count == 2)
      break;
    usleep(1000);
  }
  assert(server.transport->socket_count == 1 && count == 2);
  for (size_t i = 0; i < 100; i++) {
    tick(&server, &client);
    usleep(1000);
  }

  /* The listener owns one socket but both remote paths have path-bound
   * feedback. A physical-socket-only scheduler drains path zero and leaves
   * the other queue permanently runnable, spinning the application's poll. */
  for (size_t i = 0; i < 2; i++) {
    uint8_t payload[QLINQ_WIRE_TELEMETRY_SIZE];
    qlinq_wire_telemetry_t telemetry = {.path_id = (uint8_t)paths[i],
                                        .send_time_ns = 1000U + i,
                                        .recv_time_ns = 2000U + i};
    assert(qlinq_wire_encode_telemetry(payload, sizeof(payload), &telemetry) ==
           QLINQ_WIRE_OK);
    assert(transport_queue_datagram(server.conn, paths[i],
                                    ptls_iovec_init(payload, sizeof(payload))));
  }
  for (size_t attempt = 0; attempt < 100; attempt++) {
    tick(&server, &client);
    usleep(1000);
  }
  for (size_t i = 0; i < 2; i++) {
    assert(quicly_get_num_datagram_frames_path(server.conn->quic, paths[i]) ==
           0);
    bool received = false;
    for (size_t physical = 0; physical < client.transport->socket_count;
         physical++) {
      const transport_conn_path_t *path = &client.conn->paths[physical];
      received |= path->owd_initialized && path->telemetry_path == paths[i] &&
                  path->last_telemetry_s_ns == 1000U + i;
    }
    assert(received);
  }
  size_t immediate = 0;
  for (size_t attempt = 0; attempt < 1000; attempt++) {
    tick(&server, &client);
    immediate += transport_get_first_timeout(server.transport) <=
                 transport_get_time_ms();
  }
  assert(immediate < 1000); /* No permanently due but unserviceable queue. */

  /* Reverse reliable traffic has the same topology. Filling the first path's
   * congestion window must leave the second path eligible for stream data,
   * rather than repeatedly reporting a runnable path the scorer cannot see. */
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_RELIABLE,
                          .name = "reverse"};
  assert(transport_subscribe_conn(client.transport, client.conn, track));
  for (size_t attempt = 0; attempt < 2000 && !server.subscribed; attempt++) {
    tick(&server, &client);
    usleep(1000);
  }
  assert(server.subscribed);
  uint64_t sent_before[2];
  for (size_t i = 0; i < 2; i++) {
    quicly_path_stats_t stats;
    assert(quicly_get_path_stats(server.conn->quic, paths[i], &stats) == 0);
    sent_before[i] = stats.sent;
  }
  for (size_t sequence = 0; sequence < 128; sequence++) {
    uint8_t payload[4096];
    for (size_t i = 0; i < sizeof(payload); i++)
      payload[i] = (uint8_t)(sequence + i);
    moq_object_t object = {.track_id = track,
                           .group_id = 1,
                           .object_id = sequence,
                           .data = payload,
                           .size = sizeof(payload)};
    assert(transport_publish(server.transport, &object));
  }
  immediate = 0;
  for (size_t attempt = 0; attempt < 128; attempt++) {
    transport_tick(server.transport); /* Withhold ACK input to fill windows. */
    immediate += transport_get_first_timeout(server.transport) <=
                 transport_get_time_ms();
  }
  for (size_t i = 0; i < 2; i++) {
    quicly_path_stats_t stats;
    assert(quicly_get_path_stats(server.conn->quic, paths[i], &stats) == 0);
    assert(stats.sent > sent_before[i] + 4);
  }
  assert(immediate < 128);
  for (size_t attempt = 0; attempt < 3000 && client.received != 128;
       attempt++) {
    tick(&server, &client);
    usleep(1000);
  }
  assert(client.received == 128);
  for (size_t i = 0; i < 100; i++) {
    tick(&server, &client);
    usleep(1000);
  }
  check_reliable_override(&server, &client, track, SIZE_MAX);
  check_reliable_override(&server, &client, track, paths[0]);
  transport_destroy(client.transport);
  transport_destroy(server.transport);
  puts("===MULTIPATH FEEDBACK OK===");
  return 0;
}
