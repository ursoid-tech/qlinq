#include "portable_sockets.h"
#include "transport.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CLIENTS 64
static void ignore_event(void *data, const transport_event_t *event) {
  (void)data;
  (void)event;
}

static void ignore_log(void *data, const transport_log_event_t *event) {
  (void)data;
  (void)event;
}

/* A small deterministic socket-policy check plus a live ephemeral-port cohort.
 * Looking only for a random collision would make this regression flaky. */
static unsigned exclusive_port(transport_t *transport, int family) {
  struct pollfd fds[TRANSPORT_MAX_PATHS + 2];
  size_t count =
      transport_get_poll_fds(transport, fds, sizeof(fds) / sizeof(fds[0]));
  for (size_t i = 0; i < count; i++) {
    struct sockaddr_storage address;
    socklen_t length = sizeof(address);
    if (getsockname(fds[i].fd, (struct sockaddr *)&address, &length) ||
        address.ss_family != family)
      continue;
    int reuse = -1;
    length = sizeof(reuse);
    if (getsockopt(fds[i].fd, SOL_SOCKET, SO_REUSEADDR, &reuse, &length) ||
        reuse)
      return 0;
    return family == AF_INET
               ? ntohs(((struct sockaddr_in *)&address)->sin_port)
               : ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
  }
  return 0;
}

static int run_family(const char *host, int family) {
  transport_config_t config = {.bind_hosts = {host},
                               .num_bind_hosts = 1,
                               .port = 19865,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .allow_insecure_peer = true,
                               .callback = ignore_event,
                               .log_callback = ignore_log,
                               .limits = {.max_connections = CLIENTS}};
  transport_t *listener = NULL, *duplicate = NULL, *clients[CLIENTS] = {0};
  unsigned ports[CLIENTS] = {0};
  int result = 1;
  listener = transport_create(&config);
  if (!listener || exclusive_port(listener, family) != config.port)
    goto Exit;
  duplicate = transport_create(&config);
  if (duplicate)
    goto Exit;
  if (family == AF_INET) {
    /* A returning last interface must keep the listener's configured port. */
    for (size_t turn = 0; turn < 2; turn++) {
      transport_mock_iface_remove(listener, host);
      transport_tick(listener);
      if (exclusive_port(listener, family) != 0)
        goto Exit;
      transport_mock_iface_add(listener, host);
      transport_tick(listener);
      if (exclusive_port(listener, family) != config.port)
        goto Exit;
    }
  }
  config.remote_hosts[0] = host;
  config.num_remote_hosts = 1;
  config.limits.max_connections = 1;
  for (size_t i = 0; i < CLIENTS; i++) {
    clients[i] = transport_create(&config);
    if (!clients[i] || !(ports[i] = exclusive_port(clients[i], family)) ||
        ports[i] == config.port)
      goto Exit;
    for (size_t j = 0; j < i; j++)
      if (ports[j] == ports[i])
        goto Exit;
  }
  result = 0;
Exit:
  for (size_t i = 0; i < CLIENTS; i++)
    if (clients[i])
      transport_destroy(clients[i]);
  if (duplicate)
    transport_destroy(duplicate);
  if (listener)
    transport_destroy(listener);
  if (result)
    fprintf(stderr, "exclusive unicast binding failed for %s\n", host);
  return result;
}

typedef struct {
  transport_t *transport;
  transport_conn_t *conn;
  unsigned authenticated;
  bool is_client;
  bool disconnected;
  bool received;
} recovery_state_t;

static void recovery_event(void *data, const transport_event_t *event) {
  recovery_state_t *state = data;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    state->conn = event->conn;
    if (state->is_client)
      transport_send_auth(state->transport, event->conn,
                          (const uint8_t *)"recovery", 8);
    break;
  case TRANSPORT_EVENT_AUTH:
    transport_respond_auth(state->transport, event->conn, true);
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    if (event->auth.success)
      state->authenticated++;
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    state->conn = NULL;
    state->disconnected = !event->disconnect.remote &&
                          event->disconnect.error_code == 0x10;
    break;
  case TRANSPORT_EVENT_OBJECT:
    state->received = event->object.size == 8 &&
                      memcmp(event->object.data, "returned", 8) == 0;
    break;
  default:
    break;
  }
}

static int run_last_interface_recovery(void) {
  recovery_state_t server = {0}, client = {.is_client = true};
  transport_config_t config = {.bind_hosts = {"127.0.0.1"},
                               .num_bind_hosts = 1,
                               .port = 19869,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .allow_insecure_peer = true,
                               .callback = recovery_event,
                               .user_data = &server,
                               .log_callback = ignore_log,
                               .limits = {.max_connections = 4}};
  int result = 1;
  server.transport = transport_create(&config);
  config.remote_hosts[0] = "127.0.0.1";
  config.num_remote_hosts = 1;
  config.reconnect_enabled = true;
  config.reconnect_initial_delay_ms = 10;
  config.reconnect_max_delay_ms = 50;
  config.user_data = &client;
  client.transport = transport_create(&config);
  if (!server.transport || !client.transport)
    goto Exit;
  for (unsigned session = 1; session <= 3; session++) {
    int64_t deadline = transport_get_time_ms() + 3000;
    while (client.authenticated < session && transport_get_time_ms() < deadline) {
      transport_tick(server.transport);
      transport_tick(client.transport);
      usleep(1000);
    }
    if (client.authenticated != session || !client.conn ||
        !transport_send_unicast(client.transport, client.conn, "returned", 8))
      goto Exit;
    server.received = false;
    deadline = transport_get_time_ms() + 3000;
    while (!server.received && transport_get_time_ms() < deadline) {
      transport_tick(client.transport);
      transport_tick(server.transport);
      usleep(1000);
    }
    if (!server.received)
      goto Exit;
    if (session == 3)
      break;
    client.disconnected = false;
    transport_mock_iface_remove(client.transport, "127.0.0.1");
    transport_tick(client.transport);
    if (!client.disconnected || exclusive_port(client.transport, AF_INET) != 0)
      goto Exit;
    transport_mock_iface_add(client.transport, "127.0.0.1");
    transport_tick(client.transport);
  }
  result = 0;
Exit:
  transport_destroy(client.transport);
  transport_destroy(server.transport);
  if (result)
    fprintf(stderr, "last client interface did not reconnect and deliver data\n");
  return result;
}

static int run_dual_wildcard(void) {
  const char *hosts[] = {"0.0.0.0", "::"};
  for (size_t order = 0; order < 2; order++) {
    transport_config_t config = {.bind_hosts = {hosts[order], hosts[1 - order]},
                                 .num_bind_hosts = 2,
                                 .port = 19866,
                                 .cert_file = "t/assets/server.crt",
                                 .key_file = "t/assets/server.key",
                                 .allow_insecure_peer = true,
                                 .callback = ignore_event,
                                 .log_callback = ignore_log};
    transport_t *listener = transport_create(&config);
    if (!listener)
      return 1;
    bool valid = exclusive_port(listener, AF_INET) == config.port &&
                 exclusive_port(listener, AF_INET6) == config.port;
    transport_destroy(listener);
    if (!valid)
      return 1;
  }
  return 0;
}

static int run_partial_bind_failure(const char *host, int family) {
  const char *second_hosts[] = {"invalid-address", host};
  for (size_t i = 0; i < sizeof(second_hosts) / sizeof(*second_hosts); i++) {
    transport_config_t config = {.bind_hosts = {host, second_hosts[i]},
                                 .num_bind_hosts = 2,
                                 .port = 19867,
                                 .cert_file = "t/assets/server.crt",
                                 .key_file = "t/assets/server.key",
                                 .allow_insecure_peer = true,
                                 .callback = ignore_event,
                                 .log_callback = ignore_log};
    transport_t *transport = transport_create(&config);
    if (transport) {
      transport_destroy(transport);
      return 1;
    }
    /* A parse or bind failure on the second socket must release the first. */
    config.num_bind_hosts = 1;
    transport = transport_create(&config);
    bool valid = transport && exclusive_port(transport, family) == config.port;
    transport_destroy(transport);
    if (!valid)
      return 1;
  }
  return 0;
}

static int run_wildcard_stripes(const char *wildcard, const char *peer) {
  transport_config_t config = {.bind_hosts = {wildcard},
                               .num_bind_hosts = 1,
                               .port = 19868,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .allow_insecure_peer = true,
                               .callback = ignore_event,
                               .log_callback = ignore_log};
  transport_t *listener = transport_create(&config);
  config.cert_file = config.key_file = NULL;
  config.remote_hosts[0] = peer;
  config.num_remote_hosts = 1;
  config.bind_hosts[1] = config.bind_hosts[2] = wildcard;
  config.num_bind_hosts = 3;
  transport_t *client = transport_create(&config);
  bool all_active = false;
  if (listener && client) {
    int64_t deadline = transport_get_time_ms() + 3000;
    while (transport_get_time_ms() < deadline) {
      transport_tick(listener);
      transport_tick(client);
      all_active = true;
      for (size_t i = 0; i < 3; i++) {
        transport_path_stats_t stats;
        if (!transport_get_path_stats(client, i, &stats) ||
            stats.lifecycle != TRANSPORT_PATH_ACTIVE)
          all_active = false;
      }
      if (all_active)
        break;
      usleep(1000);
    }
  }
  if (!all_active && client) {
    for (size_t i = 0; i < 3; i++) {
      transport_path_stats_t stats;
      if (transport_get_path_stats(client, i, &stats))
        fprintf(stderr, "stripe %zu state=%d tx=%llu rx=%llu rtt=%u\n", i,
                stats.lifecycle, (unsigned long long)stats.bytes_sent,
                (unsigned long long)stats.bytes_received, stats.rtt);
    }
  }
  transport_destroy(client);
  transport_destroy(listener);
  if (!all_active)
    fprintf(stderr,
            "wildcard stripes did not all validate on distinct ports\n");
  return !all_active;
}

int main(void) {
  if (portable_socket_init())
    return 1;
  int result = run_family("127.0.0.1", AF_INET) ||
               run_family("::1", AF_INET6) || run_last_interface_recovery() ||
               run_dual_wildcard() ||
               run_partial_bind_failure("127.0.0.1", AF_INET) ||
               run_partial_bind_failure("::1", AF_INET6) ||
               run_wildcard_stripes("0.0.0.0", "127.0.0.1") ||
               run_wildcard_stripes("::", "::1");
  portable_socket_cleanup();
  if (!result)
    puts("===UNICAST BIND OWNERSHIP OK===");
  return result;
}
