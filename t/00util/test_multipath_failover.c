#include "transport_internal.h"
#include "transport_paths.h"
#include "transport_udp.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define transport_udp_send_batch real_udp_send_batch
#include "../../src/common/transport_udp.c"
#undef transport_udp_send_batch

/* Replace only the socket send boundary. Both real QLINQ schedulers and
 * encrypted QUIC recovery run unchanged; a dropped send still succeeds. */
static int dropped_fds[2] = {-1, -1};
static size_t dropped_packets;
static size_t forced_path;

/* Hold only the client's primary flight while allowing the secondary through.
 * Every held UDP datagram is delivered once, so a setup loss can only come
 * from protocol ordering, not the simulated network dropping a packet. */
static transport_t *startup_client;
static bool startup_delay, startup_released;
static int64_t startup_hold_at;
static size_t startup_early_secondary, startup_held_count, startup_delivered;
static struct {
  struct sockaddr_storage destination;
  socklen_t destination_len;
  size_t size;
  uint8_t data[1500];
} startup_held[64];

static quicly_error_t force_path(quicly_path_scheduler_t *scheduler,
                                 quicly_conn_t *conn,
                                 quicly_send_context_t *s) {
  (void)scheduler;
  return quicly_send_on_path(conn, s, forced_path, NULL);
}

static quicly_path_scheduler_t forced_scheduler = {.do_send = force_path};

ssize_t transport_udp_send_batch(int fd, const struct sockaddr *destination,
                                 socklen_t destination_len,
                                 const struct iovec *datagrams, size_t count) {
  if (startup_client && startup_client->client_conn) {
    quicly_conn_t *quic = startup_client->client_conn->quic;
    quicly_stats_t stats;
    assert(quicly_get_stats(quic, &stats) == 0);
    bool confirmed = stats.handshake_confirmed_msec != UINT64_MAX;
    if (fd == startup_client->sockets[1].fd && !confirmed)
      startup_early_secondary += count;
    if (startup_delay && !startup_released &&
        fd == startup_client->sockets[0].fd && !confirmed &&
        quicly_connection_is_ready(quic)) {
      if (startup_hold_at == 0)
        startup_hold_at = transport_get_time_ms();
      for (size_t i = 0; i < count; i++) {
        assert(startup_held_count < 64);
        assert(datagrams[i].iov_len <= sizeof(startup_held[0].data));
        assert(destination_len <= sizeof(startup_held[0].destination));
        size_t slot = startup_held_count++;
        memcpy(&startup_held[slot].destination, destination, destination_len);
        startup_held[slot].destination_len = destination_len;
        startup_held[slot].size = datagrams[i].iov_len;
        memcpy(startup_held[slot].data, datagrams[i].iov_base,
               datagrams[i].iov_len);
      }
      return (ssize_t)count;
    }
  }
  if (fd == dropped_fds[0] || fd == dropped_fds[1]) {
    dropped_packets += count;
    return (ssize_t)count;
  }
  size_t sent = 0;
  for (; sent < count; sent++) {
    ssize_t ret;
    do {
      ret = sendto(fd, datagrams[sent].iov_base, datagrams[sent].iov_len, 0,
                   destination, destination_len);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0) {
      if (sent || errno == EAGAIN || errno == EWOULDBLOCK)
        return (ssize_t)sent;
      return -1;
    }
    assert((size_t)ret == datagrams[sent].iov_len);
  }
  return (ssize_t)sent;
}

typedef struct {
  transport_t *transport;
  transport_conn_t *conn;
  bool server, authenticated, subscribed;
  size_t received;
} endpoint_t;

static void event(void *data, const transport_event_t *e) {
  endpoint_t *ep = data;
  ep->conn = e->conn;
  switch (e->type) {
  case TRANSPORT_EVENT_CONNECTED:
    if (!ep->server)
      assert(transport_send_auth(ep->transport, e->conn,
                                 (const uint8_t *)"test", 4));
    break;
  case TRANSPORT_EVENT_AUTH:
    assert(transport_respond_auth(ep->transport, e->conn, true));
    ep->authenticated = true;
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    assert(e->auth.success);
    ep->authenticated = true;
    break;
  case TRANSPORT_EVENT_SUBSCRIBE:
    ep->subscribed = true;
    break;
  case TRANSPORT_EVENT_OBJECT:
    assert(e->object.object_id == ep->received && e->object.size == 4096);
    for (size_t i = 0; i < e->object.size; i++)
      assert(e->object.data[i] == (uint8_t)(ep->received + i));
    ep->received++;
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    assert(!"unexpected disconnect");
    break;
  default:
    break;
  }
}

static void tick(endpoint_t *server, endpoint_t *client) {
  transport_tick(client->transport);
  transport_tick(server->transport);
  usleep(1000);
}

static void release_startup_flight(void) {
  if (!startup_delay || startup_released || startup_hold_at == 0 ||
      transport_get_time_ms() - startup_hold_at < 20)
    return;
  /* The release deadline is independent of secondary activity: a correct
   * implementation waits for this primary handshake instead of opening it. */
  startup_released = true;
  for (size_t i = 0; i < startup_held_count; i++) {
    struct iovec datagram = {.iov_base = startup_held[i].data,
                             .iov_len = startup_held[i].size};
    assert(real_udp_send_batch(startup_client->sockets[0].fd,
                               (struct sockaddr *)&startup_held[i].destination,
                               startup_held[i].destination_len, &datagram,
                               1) == 1);
    startup_delivered++;
  }
}

static bool run_startup(bool delay_primary) {
  endpoint_t server = {.server = true}, client = {0};
  transport_config_t config = {.bind_hosts = {"127.85.1.1"},
                               .num_bind_hosts = 1,
                               .port = (uint16_t)(19873 + delay_primary),
                               .allow_insecure_peer = true,
                               .congestion_control = TRANSPORT_CC_CUBIC,
                               .pacing = TRANSPORT_PACING_ENABLED,
                               .callback = event,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .user_data = &server};
  server.transport = transport_create(&config);
  assert(server.transport);
  config.bind_hosts[0] = "127.85.1.2";
  config.bind_hosts[1] = "127.85.2.2";
  config.num_bind_hosts = 2;
  config.remote_hosts[0] = "127.85.1.1";
  config.num_remote_hosts = 1;
  config.user_data = &client;
  client.transport = transport_create(&config);
  assert(client.transport);
  client.conn = client.transport->client_conn;
  assert(client.conn);
  startup_client = client.transport;
  startup_delay = delay_primary;
  startup_released = !delay_primary;
  startup_hold_at = 0;
  startup_early_secondary = startup_held_count = startup_delivered = 0;

  bool opened_early = false, validated = false;
  uint32_t minimum_cwnd = UINT32_MAX;
  uint64_t losses = 0;
  size_t settled = 0;
  for (size_t i = 0; i < 3000; i++) {
    release_startup_flight();
    tick(&server, &client);
    quicly_stats_t stats;
    assert(quicly_get_stats(client.conn->quic, &stats) == 0);
    quicly_path_stats_t secondary;
    size_t path = transport_path_get_stats_by_local(
        client.conn->quic, &client.transport->sockets[1].local_addr,
        &secondary);
    if (path == SIZE_MAX)
      continue;
    opened_early |= stats.handshake_confirmed_msec == UINT64_MAX;
    if (secondary.cwnd < minimum_cwnd)
      minimum_cwnd = secondary.cwnd;
    losses = secondary.lost;
    quicly_path_health_t health;
    assert(quicly_get_path_health(client.conn->quic, path, &health) == 0);
    validated = health.validated && !health.probe_only;
    if (validated && server.authenticated && client.authenticated &&
        ++settled == 250)
      break;
  }
  uint32_t initial_cwnd = quicly_cc_calc_initial_cwnd(
      client.transport->quic_ctx.egress[0].cc.initcwnd_packets,
      client.transport->quic_ctx.initial_egress_max_udp_payload_size);
  bool success = startup_released &&
                 (!delay_primary || startup_held_count != 0) &&
                 startup_held_count == startup_delivered && !opened_early &&
                 startup_early_secondary == 0 && validated &&
                 server.authenticated && client.authenticated &&
                 minimum_cwnd >= initial_cwnd && losses == 0 && settled == 250;
  fprintf(success ? stdout : stderr,
          "startup %s: held=%zu delivered=%zu early_packets=%zu early_path=%d "
          "validated=%d min_cwnd=%u initial_cwnd=%u lost=%llu\n",
          delay_primary ? "reordered" : "ordinary", startup_held_count,
          startup_delivered, startup_early_secondary, opened_early, validated,
          minimum_cwnd, initial_cwnd, (unsigned long long)losses);
  startup_client = NULL;
  transport_destroy(client.transport);
  transport_destroy(server.transport);
  return success;
}

static quicly_path_stats_t path_stats(endpoint_t *ep, size_t physical) {
  quicly_path_stats_t stats;
  assert(transport_path_get_stats_by_local(
             ep->conn->quic, &ep->transport->sockets[physical].local_addr,
             &stats) != SIZE_MAX);
  return stats;
}

static quicly_path_health_state_t path_health(endpoint_t *ep, size_t physical) {
  quicly_path_stats_t stats;
  size_t path = transport_path_get_stats_by_local(
      ep->conn->quic, &ep->transport->sockets[physical].local_addr, &stats);
  quicly_path_health_t health;
  assert(path != SIZE_MAX &&
         quicly_get_path_health(ep->conn->quic, path, &health) == 0);
  return health.state;
}

static void publish(endpoint_t *ep, moq_track_id_t track, size_t *offered) {
  for (size_t n = 0; n < 8; n++) {
    uint8_t payload[4096];
    for (size_t i = 0; i < sizeof(payload); i++)
      payload[i] = (uint8_t)(*offered + i);
    moq_object_t object = {.track_id = track,
                           .group_id = 1,
                           .object_id = *offered,
                           .data = payload,
                           .size = sizeof(payload)};
    if (!transport_publish(ep->transport, &object))
      break;
    (*offered)++;
  }
}

static void run(size_t failed_path, bool bidirectional) {
  endpoint_t server = {.server = true}, client = {0};
  transport_config_t config = {
      .bind_hosts = {"127.82.1.1", "127.82.2.1"},
      .num_bind_hosts = 2,
      .port = (uint16_t)(19880 + failed_path + 2 * bidirectional),
      .allow_insecure_peer = true,
      .callback = event,
      .cert_file = "t/assets/server.crt",
      .key_file = "t/assets/server.key",
      .user_data = &server};
  server.transport = transport_create(&config);
  assert(server.transport);
  /* Establish the fixture before testing the opt-in health policy. Sparse
   * validation/control traffic alone need not keep an unused path progressing.
   */
  server.transport->quic_ctx.multipath_failover_pto_threshold = 0;
  config.bind_hosts[0] = "127.82.1.2";
  config.bind_hosts[1] = "127.82.2.2";
  config.remote_hosts[0] = "127.82.1.1";
  config.remote_hosts[1] = "127.82.2.1";
  config.num_remote_hosts = 2;
  config.user_data = &client;
  client.transport = transport_create(&config);
  assert(client.transport);
  client.transport->quic_ctx.multipath_failover_pto_threshold = 0;
  for (size_t i = 0; i < 2000; i++) {
    tick(&server, &client);
    transport_conn_stats_t stats;
    if (client.authenticated && server.authenticated &&
        transport_get_conn_stats(client.transport, client.conn, &stats) &&
        stats.quic_paths_validated >= 2)
      break;
  }
  assert(client.authenticated && server.authenticated);
  moq_track_id_t track = {.type = MOQ_TRACK_VIDEO,
                          .flags = MOQ_TRACK_FLAG_RELIABLE,
                          .name = "failover"};
  assert(transport_subscribe_conn(server.transport, server.conn, track));
  for (size_t i = 0; i < 2000 && !client.subscribed; i++)
    tick(&server, &client);
  assert(client.subscribed);
  size_t offered = 0;
  for (size_t i = 0; i < 100; i++) {
    publish(&client, track, &offered);
    tick(&server, &client);
  }
  size_t before = server.received;
  assert(before > 0);
  quicly_path_scheduler_t *scheduler =
      client.transport->quic_ctx.path_scheduler;
  client.transport->quic_ctx.path_scheduler = &forced_scheduler;
  /* Exercise both paths before faulting either one, even at loopback rates
   * where the normal scheduler can satisfy all demand with one path. */
  size_t warm_paths[2];
  for (size_t p = 0; p < 2; p++) {
    quicly_path_stats_t stats;
    warm_paths[p] = transport_path_get_stats_by_local(
        client.conn->quic, &client.transport->sockets[p].local_addr, &stats);
    assert(warm_paths[p] != SIZE_MAX);
  }
  /* Alternate while warming so outstanding work on either path can progress.
   * Forcing one path for seconds can make the other suspect before the fault.
   */
  for (size_t i = 0; i < 4000; i++) {
    forced_path = warm_paths[i % 2];
    publish(&client, track, &offered);
    tick(&server, &client);
    if (path_stats(&client, 0).acked > 10 &&
        path_stats(&client, 1).acked > 10 &&
        path_health(&client, 0) == QUICLY_PATH_USABLE &&
        path_health(&client, 1) == QUICLY_PATH_USABLE)
      break;
  }
  for (size_t p = 0; p < 2; p++) {
    quicly_path_stats_t warm = path_stats(&client, p);
    if (warm.acked <= 10 || path_health(&client, p) != QUICLY_PATH_USABLE)
      fprintf(stderr,
              "warm p%zu sent=%llu acked=%llu health=%d cwnd=%u flight=%u "
              "received=%zu offered=%zu\n",
              p, (unsigned long long)warm.sent, (unsigned long long)warm.acked,
              path_health(&client, p), warm.cwnd, warm.bytes_in_flight,
              server.received, offered);
    assert(warm.acked > 10 && path_health(&client, p) == QUICLY_PATH_USABLE);
  }
  client.transport->quic_ctx.multipath_failover_pto_threshold = 2;
  server.transport->quic_ctx.multipath_failover_pto_threshold = 2;
  dropped_fds[0] = client.transport->sockets[failed_path].fd;
  dropped_fds[1] =
      bidirectional ? server.transport->sockets[failed_path].fd : -1;
  dropped_packets = 0;
  quicly_path_stats_t stats;
  forced_path = transport_path_get_stats_by_local(
      client.conn->quic, &client.transport->sockets[failed_path].local_addr,
      &stats);
  publish(&client, track, &offered);
  tick(&server, &client);
  client.transport->quic_ctx.path_scheduler = scheduler;
  bool suspected = false;
  size_t received_mid_fault = 0;
  for (size_t i = 0; i < 1000; i++) {
    publish(&client, track, &offered);
    tick(&server, &client);
    suspected |= path_health(&client, failed_path) == QUICLY_PATH_SUSPECT;
    if (i == 500)
      received_mid_fault = server.received;
  }
  if (!suspected) {
    fprintf(
        stderr,
        "no suspicion: path=%zu drop=%zu before=%zu received=%zu offered=%zu\n",
        failed_path, dropped_packets, before, server.received, offered);
    for (size_t p = 0; p < 2; p++) {
      quicly_path_stats_t s = path_stats(&client, p);
      fprintf(stderr, "p%zu state=%d sent=%llu acked=%llu flight=%u cwnd=%u\n",
              p, path_health(&client, p), (unsigned long long)s.sent,
              (unsigned long long)s.acked, s.bytes_in_flight, s.cwnd);
    }
  }
  assert(dropped_packets > 0 && suspected);
  if (server.received <= received_mid_fault + 100)
    fprintf(stderr,
            "outage stalled: path=%zu bidirectional=%d mid=%zu end=%zu\n",
            failed_path, bidirectional, received_mid_fault, server.received);
  assert(server.received > received_mid_fault + 100);
  dropped_fds[0] = dropped_fds[1] = -1;
  bool recovered = false;
  for (size_t i = 0; i < 5000; i++) {
    publish(&client, track, &offered);
    tick(&server, &client);
    if (path_health(&client, failed_path) == QUICLY_PATH_USABLE) {
      recovered = true;
      break;
    }
  }
  assert(recovered);
  for (size_t i = 0; i < 3000 && server.received != offered; i++)
    tick(&server, &client);
  assert(server.received == offered);
  printf("path %zu %s: %zu records delivered, %zu packets dropped\n",
         failed_path, bidirectional ? "bidirectional" : "forward", offered,
         dropped_packets);
  transport_destroy(client.transport);
  transport_destroy(server.transport);
}

int main(int argc, char **argv) {
  assert(argc == 1 || (argc == 2 && strcmp(argv[1], "--startup-only") == 0));
  if (!run_startup(true) || !run_startup(false))
    return 1;
  puts("===MULTIPATH STARTUP OK===");
  if (argc == 2)
    return 0;
  run(0, false);
  run(1, false);
  run(0, true);
  puts("===MULTIPATH FAILOVER OK===");
  return 0;
}
