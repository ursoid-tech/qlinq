#include "transport_internal.h"
#include "transport_paths.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* exercise connection lifecycle with injected return values */
static quicly_error_t send_error, receive_error;
static unsigned close_calls, receive_calls, disconnects;
static quicly_error_t last_error;
static quicly_conn_t *sample_path;
static quicly_path_health_t sample_health;

quicly_error_t __real_quicly_send(quicly_conn_t *, quicly_address_t *,
                                  quicly_address_t *, struct iovec *, size_t *,
                                  void *, size_t);
quicly_error_t __wrap_quicly_send(quicly_conn_t *conn, quicly_address_t *dest,
                                  quicly_address_t *src,
                                  struct iovec *datagrams, size_t *count,
                                  void *buffer, size_t size) {
  if (send_error) {
    *count = 0;
    quicly_error_t ret = send_error;
    send_error = 0;
    return ret;
  }
  return __real_quicly_send(conn, dest, src, datagrams, count, buffer, size);
}
quicly_error_t __real_quicly_receive(quicly_conn_t *, struct sockaddr *,
                                     struct sockaddr *,
                                     quicly_decoded_packet_t *);
quicly_error_t __wrap_quicly_receive(quicly_conn_t *conn, struct sockaddr *dest,
                                     struct sockaddr *src,
                                     quicly_decoded_packet_t *packet) {
  receive_calls++;
  if (receive_error) {
    quicly_error_t ret = receive_error;
    receive_error = 0;
    return ret;
  }
  return __real_quicly_receive(conn, dest, src, packet);
}
quicly_error_t __real_quicly_close(quicly_conn_t *, quicly_error_t,
                                   const char *);
quicly_error_t __wrap_quicly_close(quicly_conn_t *conn, quicly_error_t err,
                                   const char *reason) {
  close_calls++;
  return __real_quicly_close(conn, err, reason);
}
int __real_quicly_get_path_health(quicly_conn_t *, size_t,
                                  quicly_path_health_t *);
int __wrap_quicly_get_path_health(quicly_conn_t *conn, size_t path,
                                  quicly_path_health_t *health) {
  if (conn == sample_path && path == 0) {
    *health = sample_health;
    return 0;
  }
  return __real_quicly_get_path_health(conn, path, health);
}
static void event(void *data, const transport_event_t *ev) {
  (void)data;
  if (ev->type == TRANSPORT_EVENT_DISCONNECTED) {
    disconnects++;
    last_error = ev->disconnect.raw_error;
    assert(!ev->disconnect.remote && !ev->disconnect.application_error);
    assert(ev->disconnect.reason && strstr(ev->disconnect.reason, "failure"));
  }
}
static transport_config_t config(bool server) {
  transport_config_t c = {.bind_hosts = {"127.0.0.1"},
                          .num_bind_hosts = 1,
                          .port = 19946,
                          .callback = event,
                          .allow_insecure_peer = true};
  if (server) {
    c.cert_file = "t/assets/server.crt";
    c.key_file = "t/assets/server.key";
  } else {
    c.remote_hosts[0] = "127.0.0.1";
    c.num_remote_hosts = 1;
    c.reconnect_enabled = true;
    c.reconnect_initial_delay_ms = 10;
    c.reconnect_max_delay_ms = 100;
  }
  return c;
}
static void reset(void) {
  send_error = receive_error = last_error = 0;
  close_calls = receive_calls = disconnects = 0;
}
static void test_send_error(quicly_error_t error) {
  reset();
  transport_config_t c = config(false);
  transport_t *client = transport_create(&c);
  assert(client && client->client_conn);
  send_error = error;
  transport_tick(client);
  assert(!send_error);
  if (error == QUICLY_ERROR_STATE_EXHAUSTION) {
    assert(close_calls == 1 && disconnects == 0 && client->client_conn);
    assert(quicly_get_state(client->client_conn->quic) >= QUICLY_STATE_CLOSING);
  } else {
    assert(close_calls == 0 && disconnects == 1 && !client->client_conn);
    assert(last_error == error && client->stats.connections_closed == 1);
    assert(client->reconnect_at_ms > 0);
    client->reconnect_at_ms = transport_get_time_ms();
    transport_tick(client);
    assert(client->client_conn && client->stats.reconnect_attempts == 1);
  }
  transport_destroy(client);
}
static void test_receive_error(quicly_error_t error) {
  reset();
  transport_config_t sc = config(true), cc = config(false);
  transport_t *server = transport_create(&sc), *client = transport_create(&cc);
  assert(server && client);
  receive_error = error;
  for (unsigned i = 0; receive_error && i < 100; i++) {
    transport_tick(client);
    transport_tick(server);
    usleep(1000);
  }
  assert(receive_calls && !receive_error);
  if (error == QUICLY_ERROR_PACKET_IGNORED) {
    assert(!disconnects && !close_calls && server->conn_count == 1);
  } else if (error == QUICLY_ERROR_STATE_EXHAUSTION) {
    assert(!disconnects && close_calls == 1 && server->conn_count == 1);
  } else {
    assert(disconnects == 1 && close_calls == 0 && server->conn_count == 0);
    assert(last_error == error && server->stats.connections_closed == 1);
    for (size_t i = 0; i < QLINQ_CONNECTION_CACHE_SLOTS; i++)
      assert(!server->connection_cache[i]);
  }
  transport_destroy(client);
  transport_destroy(server);
}
static void test_fractional_rtt(void) {
  transport_config_t c = config(false);
  transport_t *client = transport_create(&c);
  assert(client);
  sample_path = client->client_conn->quic;
  quicly_path_stats_t stats = {.cwnd = 12000};
  sample_health =
      (quicly_path_health_t){.rtt_is_sampled = 1, .rtt_smoothed = 0.25f};
  path_t fast =
      transport_path_estimate_on_path(sample_path, 0, &stats, 0, 0, 1000, 0);
  sample_health.rtt_smoothed = 0.75f;
  path_t slow =
      transport_path_estimate_on_path(sample_path, 0, &stats, 0, 0, 1000, 0);
  assert(fast.b == FP_FROM_INT(48000) && slow.b == FP_FROM_INT(16000));
  assert(fast.l > 0 && fast.l < slow.l && slow.l < FP_ONE / 1000);
  sample_health.rtt_smoothed = 0.01f;
  path_t ultra_fast =
      transport_path_estimate_on_path(sample_path, 0, &stats, 0, 0, 1000, 0);
  assert(ultra_fast.l == 1);
  sample_health.rtt_is_sampled = 0;
  path_t cold =
      transport_path_estimate_on_path(sample_path, 0, &stats, 0, 0, 1000, 0);
  assert(cold.b == FP_FROM_INT(100) && cold.l == FP_FROM_FLOAT(0.050f));
  stats.rtt_smoothed = 333;
  cold = transport_path_estimate_on_path(sample_path, 0, &stats, 0, 0, 1000, 0);
  assert(cold.b == transport_path_estimate(&stats, 0, 0, 1000, 0).b);
  sample_health.rtt_is_sampled = 1;
  sample_health.rtt_smoothed = NAN;
  assert(transport_path_estimate_on_path(sample_path, 0, &stats, 0, 0, 1000, 0)
             .b == cold.b);
  sample_path = NULL;
  transport_destroy(client);
}
static void test_native_ecn(void) {
  reset();
  transport_config_t sc = config(true), cc = config(false);
  transport_t *server = transport_create(&sc), *client = transport_create(&cc);
  assert(server && client);
  bool validated = false;
  for (unsigned i = 0; i < 1000; i++) {
    transport_tick(client);
    transport_tick(server);
    quicly_stats_t stats;
    assert(client->client_conn);
    assert(quicly_get_stats(client->client_conn->quic, &stats) == 0);
    if (stats.num_paths.ecn_validated &&
        stats.num_packets.acked_ecn_counts[0] != 0) {
      validated = true;
      break;
    }
    usleep(1000);
  }
  assert(validated && server->conn_count == 1);
  quicly_stats_t stats;
  assert(quicly_get_stats(server->conns[0]->quic, &stats) == 0);
  assert(stats.num_packets.received_ecn_counts[0] != 0);
  transport_destroy(client);
  transport_destroy(server);
}

int main(void) {
  test_native_ecn();
  test_fractional_rtt();
  test_send_error(PTLS_ERROR_NO_MEMORY);
  test_send_error(QUICLY_TRANSPORT_ERROR_INTERNAL);
  test_send_error(QUICLY_ERROR_STATE_EXHAUSTION);
  test_receive_error(PTLS_ERROR_NO_MEMORY);
  test_receive_error(QUICLY_ERROR_PACKET_IGNORED);
  test_receive_error(QUICLY_ERROR_STATE_EXHAUSTION);
  puts("===QUICLY INTEGRATION OK===");
  return 0;
}
