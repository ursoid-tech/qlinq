#include "portable_sockets.h"
#include "transport.h"
#include "transport_internal.h"

#include <inttypes.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  transport_t *transport;
  bool connected;
  size_t subscriptions;
  size_t unsubscriptions;
  size_t auth_requests;
  bool received;
  size_t objects_received;
  uint8_t payload[64];
  size_t payload_size;
} flexicast_test_state_t;

static void on_server(void *user_data, const transport_event_t *event) {
  flexicast_test_state_t *state = user_data;
  if (event->type == TRANSPORT_EVENT_CONNECTED) {
    state->connected = true;
  } else if (event->type == TRANSPORT_EVENT_AUTH) {
    state->auth_requests++;
    (void)transport_respond_auth(state->transport, event->conn, true);
  } else if (event->type == TRANSPORT_EVENT_SUBSCRIBE) {
    state->subscriptions++;
  } else if (event->type == TRANSPORT_EVENT_UNSUBSCRIBE) {
    state->unsubscriptions++;
  }
}

static void on_client(void *user_data, const transport_event_t *event) {
  flexicast_test_state_t *state = user_data;
  if (event->type == TRANSPORT_EVENT_CONNECTED) {
    (void)transport_send_auth(state->transport, event->conn,
                              (const uint8_t *)"flexicast-test", 14);
  } else if (event->type == TRANSPORT_EVENT_AUTH_COMPLETE &&
             event->auth.success) {
    state->connected = true;
  } else if (event->type == TRANSPORT_EVENT_OBJECT) {
    state->objects_received++;
    if (event->object.size <= sizeof(state->payload)) {
      memcpy(state->payload, event->object.data, event->object.size);
      state->payload_size = event->object.size;
      state->received = true;
    }
  }
}

static void drive(transport_t *server, transport_t *a, transport_t *b) {
  transport_tick(server);
  if (a)
    transport_tick(a);
  if (b)
    transport_tick(b);
}

static int run_unsubscribe_lifecycle(bool ipv6) {
  flexicast_test_state_t server_state = {0}, client_a_state = {0},
                         client_b_state = {0};
  transport_config_t server_config = {.bind_hosts = {"127.0.0.1"},
                                      .num_bind_hosts = 1,
                                      .port = 10041,
                                      .cert_file = "t/assets/server.crt",
                                      .key_file = "t/assets/server.key",
                                      .allow_insecure_peer = true,
                                      .enable_flexicast = true,
                                      .flexicast_group = "232.42.42.41",
                                      .flexicast_group_port = 10042,
                                      .flexicast_interface = "127.0.0.1",
                                      .callback = on_server,
                                      .user_data = &server_state};
  transport_config_t client_config = {.bind_hosts = {"127.0.0.1"},
                                      .num_bind_hosts = 1,
                                      .remote_hosts = {"127.0.0.1"},
                                      .num_remote_hosts = 1,
                                      .port = 10041,
                                      .allow_insecure_peer = true,
                                      .enable_flexicast = true,
                                      .flexicast_interface = "127.0.0.1",
                                      .callback = on_client,
                                      .user_data = &client_a_state};
  if (ipv6) {
    server_config.bind_hosts[0] = "::1";
    server_config.flexicast_group = "ff32::8000:41";
    server_config.flexicast_interface = "::1";
    client_config.bind_hosts[0] = "::1";
    client_config.remote_hosts[0] = "::1";
    client_config.flexicast_interface = "::1";
  }
  transport_config_t client_b_config = client_config;
  client_b_config.user_data = &client_b_state;

  transport_t *server = transport_create(&server_config);
  transport_t *client_a = transport_create(&client_config);
  transport_t *client_b = transport_create(&client_b_config);
  if (!server || !client_a || !client_b) {
    fprintf(stderr, "failed to create unsubscribe lifecycle transports\n");
    goto Fail;
  }
  server_state.transport = server;
  client_a_state.transport = client_a;
  client_b_state.transport = client_b;

  int retries = 1200;
  while (retries-- > 0 &&
         (!client_a_state.connected || !client_b_state.connected)) {
    drive(server, client_a, client_b);
    usleep(5000);
  }
  if (!client_a_state.connected || !client_b_state.connected) {
    fprintf(stderr, "unsubscribe lifecycle clients did not authenticate\n");
    goto Fail;
  }

  moq_track_id_t track = {.type = MOQ_TRACK_VIDEO, .name = "unsubscribe/video"};
  if (!transport_subscribe(client_a, track) ||
      !transport_subscribe(client_b, track)) {
    fprintf(stderr, "unsubscribe lifecycle subscriptions failed\n");
    goto Fail;
  }

  transport_stats_t source_stats = {0}, a_stats = {0}, b_stats = {0};
  retries = 600;
  while (retries-- > 0) {
    drive(server, client_a, client_b);
    (void)transport_get_stats(server, &source_stats);
    (void)transport_get_stats(client_a, &a_stats);
    (void)transport_get_stats(client_b, &b_stats);
    if (source_stats.flexicast_active_members == 2 &&
        a_stats.flexicast_active_memberships == 1 &&
        b_stats.flexicast_active_memberships == 1)
      break;
    usleep(5000);
  }
  if (source_stats.flexicast_active_members != 2 ||
      a_stats.flexicast_active_memberships != 1 ||
      b_stats.flexicast_active_memberships != 1) {
    fprintf(stderr, "unsubscribe lifecycle cohort did not become ready\n");
    goto Fail;
  }

  uint64_t rekeys_before_leave = source_stats.flexicast_rekeys;
  if (!transport_unsubscribe(client_a, track) ||
      !transport_get_stats(client_a, &a_stats) ||
      a_stats.flexicast_active_flows != 0 ||
      a_stats.flexicast_active_memberships != 0 ||
      a_stats.flexicast_membership_leaves != 1) {
    fprintf(stderr, "unsubscribe did not immediately release membership\n");
    goto Fail;
  }

  retries = 600;
  while (retries-- > 0) {
    drive(server, client_a, client_b);
    (void)transport_get_stats(server, &source_stats);
    if (server_state.unsubscriptions == 1 &&
        source_stats.flexicast_active_members == 1 &&
        source_stats.flexicast_rekeys > rekeys_before_leave)
      break;
    usleep(5000);
  }
  if (server_state.unsubscriptions != 1 ||
      source_stats.flexicast_active_members != 1 ||
      source_stats.flexicast_rekeys <= rekeys_before_leave) {
    fprintf(stderr, "remaining cohort was not rekeyed after unsubscribe\n");
    goto Fail;
  }

  static const uint8_t remaining_payload[] = "remaining subscriber";
  moq_object_t object = {.track_id = track,
                         .group_id = 1,
                         .object_id = 1,
                         .data = remaining_payload,
                         .size = sizeof(remaining_payload),
                         .priority = 1};
  client_a_state.received = false;
  client_b_state.received = false;
  if (!transport_publish(server, &object)) {
    fprintf(stderr, "remaining cohort publication failed\n");
    goto Fail;
  }
  retries = 400;
  while (retries-- > 0 && !client_b_state.received) {
    drive(server, client_a, client_b);
    usleep(5000);
  }
  if (client_a_state.received || !client_b_state.received) {
    fprintf(stderr, "unsubscribed receiver still received publication\n");
    goto Fail;
  }

  uint64_t rekeys_before_rejoin = source_stats.flexicast_rekeys;
  if (!transport_subscribe(client_a, track)) {
    fprintf(stderr, "resubscribe failed\n");
    goto Fail;
  }
  retries = 600;
  while (retries-- > 0) {
    drive(server, client_a, client_b);
    (void)transport_get_stats(server, &source_stats);
    (void)transport_get_stats(client_a, &a_stats);
    if (source_stats.flexicast_active_members == 2 &&
        source_stats.flexicast_rekeys > rekeys_before_rejoin &&
        a_stats.flexicast_active_memberships == 1)
      break;
    usleep(5000);
  }
  if (source_stats.flexicast_active_members != 2 ||
      source_stats.flexicast_rekeys <= rekeys_before_rejoin ||
      a_stats.flexicast_membership_joins != 2 ||
      a_stats.flexicast_active_memberships != 1) {
    fprintf(stderr, "resubscribe did not establish a fresh SSM join\n");
    goto Fail;
  }

  static const uint8_t rejoined_payload[] = "rejoined subscriber";
  object.object_id++;
  object.data = rejoined_payload;
  object.size = sizeof(rejoined_payload);
  client_a_state.received = false;
  client_b_state.received = false;
  if (!transport_publish(server, &object)) {
    fprintf(stderr, "rejoined cohort publication failed\n");
    goto Fail;
  }
  retries = 400;
  while (retries-- > 0 &&
         (!client_a_state.received || !client_b_state.received)) {
    drive(server, client_a, client_b);
    usleep(5000);
  }
  if (!client_a_state.received || !client_b_state.received) {
    fprintf(stderr, "rejoined cohort did not receive publication\n");
    goto Fail;
  }

  if (!transport_unsubscribe(client_a, track) ||
      !transport_unsubscribe(client_b, track)) {
    fprintf(stderr, "final unsubscribe failed\n");
    goto Fail;
  }
  (void)transport_get_stats(client_a, &a_stats);
  (void)transport_get_stats(client_b, &b_stats);
  if (a_stats.flexicast_membership_leaves != 2 ||
      b_stats.flexicast_membership_leaves != 1 ||
      a_stats.flexicast_active_memberships != 0 ||
      b_stats.flexicast_active_memberships != 0) {
    fprintf(stderr, "final unsubscribe retained a kernel membership\n");
    goto Fail;
  }
  retries = 400;
  while (retries-- > 0) {
    drive(server, client_a, client_b);
    (void)transport_get_stats(server, &source_stats);
    if (server_state.unsubscriptions == 3 &&
        source_stats.flexicast_active_flows == 0)
      break;
    usleep(5000);
  }
  if (server_state.unsubscriptions != 3 ||
      source_stats.flexicast_active_flows != 0) {
    fprintf(stderr, "source retained the final unsubscribed cohort\n");
    goto Fail;
  }

  printf(ipv6 ? "===FLEXICAST IPV6 UNSUBSCRIBE OK===\n"
              : "===FLEXICAST UNSUBSCRIBE OK===\n");
  transport_destroy(client_b);
  transport_destroy(client_a);
  transport_destroy(server);
  return 0;

Fail:
  if (client_b)
    transport_destroy(client_b);
  if (client_a)
    transport_destroy(client_a);
  if (server)
    transport_destroy(server);
  return 1;
}

static int run_membership_lifecycle(bool ipv6) {
  flexicast_test_state_t server_state = {0}, client_state = {0};
  transport_config_t server_config = {.bind_hosts = {"127.0.0.1"},
                                      .num_bind_hosts = 1,
                                      .port = 10031,
                                      .cert_file = "t/assets/server.crt",
                                      .key_file = "t/assets/server.key",
                                      .allow_insecure_peer = true,
                                      .enable_flexicast = true,
                                      .flexicast_group = "232.42.42.31",
                                      .flexicast_group_port = 10032,
                                      .flexicast_interface = "127.0.0.1",
                                      /* keep feedback deadline short */
                                      .flexicast_cc_minimum_rate = 64000,
                                      .flexicast_cc_feedback_timeout_ms = 100,
                                      .callback = on_server,
                                      .user_data = &server_state};
  transport_config_t client_config = {.bind_hosts = {"127.0.0.1"},
                                      .num_bind_hosts = 1,
                                      .remote_hosts = {"127.0.0.1"},
                                      .num_remote_hosts = 1,
                                      .port = 10031,
                                      .allow_insecure_peer = true,
                                      .enable_flexicast = true,
                                      .flexicast_interface = "127.0.0.1",
                                      .callback = on_client,
                                      .user_data = &client_state};
  if (ipv6) {
    server_config.bind_hosts[0] = "::1";
    server_config.flexicast_group = "ff32::8000:31";
    server_config.flexicast_interface = "::1";
    client_config.bind_hosts[0] = "::1";
    client_config.remote_hosts[0] = "::1";
    client_config.flexicast_interface = "::1";
  }
  transport_t *server = transport_create(&server_config);
  transport_t *client = transport_create(&client_config);
  if (!server || !client) {
    fprintf(stderr, "failed to create membership lifecycle transports\n");
    goto Fail;
  }
  server_state.transport = server;
  client_state.transport = client;

  int retries = 1000;
  while (retries-- > 0 && !client_state.connected) {
    drive(server, client, NULL);
    usleep(5000);
  }
  if (!client_state.connected) {
    fprintf(stderr, "membership lifecycle client did not authenticate\n");
    goto Fail;
  }

  moq_track_id_t tracks[2] = {
      {.type = MOQ_TRACK_VIDEO, .name = "membership/video"},
      {.type = MOQ_TRACK_AUDIO, .name = "membership/audio"}};
  if (!transport_subscribe(client, tracks[0]) ||
      !transport_subscribe(client, tracks[1])) {
    fprintf(stderr, "membership lifecycle subscriptions failed\n");
    goto Fail;
  }

  transport_stats_t source_stats = {0}, receiver_stats = {0};
  retries = 600;
  while (retries-- > 0) {
    drive(server, client, NULL);
    (void)transport_get_stats(server, &source_stats);
    (void)transport_get_stats(client, &receiver_stats);
    if (source_stats.flexicast_active_flows == 2 &&
        source_stats.flexicast_active_members == 2 &&
        receiver_stats.flexicast_active_memberships == 1)
      break;
    usleep(5000);
  }
  if (source_stats.flexicast_active_flows != 2 ||
      source_stats.flexicast_active_members != 2 ||
      receiver_stats.flexicast_membership_joins != 1 ||
      receiver_stats.flexicast_active_memberships != 1) {
    fprintf(stderr,
            "two flows did not share one kernel membership "
            "(flows=%zu, members=%zu, joins=%" PRIu64 ", active=%zu)\n",
            source_stats.flexicast_active_flows,
            source_stats.flexicast_active_members,
            receiver_stats.flexicast_membership_joins,
            receiver_stats.flexicast_active_memberships);
    goto Fail;
  }

  uint8_t interface_address[16] = {0};
  uint32_t interface_index = if_nametoindex("lo");
  int family = ipv6 ? AF_INET6 : AF_INET;
  if (interface_index == 0 ||
      inet_pton(family, ipv6 ? "::1" : "127.0.0.1", interface_address) != 1) {
    fprintf(stderr, "unable to identify loopback multicast interface\n");
    goto Fail;
  }
  /* exercise interface index-only teardown path */
  transport_flexicast_interface_removed(client, 0, NULL, interface_index);
  (void)transport_get_stats(client, &receiver_stats);
  if (receiver_stats.flexicast_active_memberships != 0 ||
      receiver_stats.flexicast_membership_leaves != 1 ||
      receiver_stats.flexicast_interface_fallbacks != 2) {
    fprintf(stderr, "interface loss did not release shared membership\n");
    goto Fail;
  }
  retries = 400;
  while (retries-- > 0) {
    drive(server, client, NULL);
    (void)transport_get_stats(server, &source_stats);
    if (source_stats.flexicast_active_members == 0)
      break;
    usleep(5000);
  }
  if (source_stats.flexicast_active_members != 0) {
    fprintf(stderr, "source did not fall back after interface loss\n");
    goto Fail;
  }

  transport_flexicast_interface_added(client, ipv6 ? 6U : 4U, interface_address,
                                      interface_index);
  retries = 600;
  while (retries-- > 0) {
    drive(server, client, NULL);
    (void)transport_get_stats(server, &source_stats);
    (void)transport_get_stats(client, &receiver_stats);
    if (source_stats.flexicast_active_members == 2 &&
        receiver_stats.flexicast_active_memberships == 1)
      break;
    usleep(5000);
  }
  if (source_stats.flexicast_active_members != 2 ||
      receiver_stats.flexicast_active_memberships != 1 ||
      receiver_stats.flexicast_membership_joins != 2 ||
      receiver_stats.flexicast_interface_rejoins != 2) {
    fprintf(stderr,
            "Flexicast cohort did not recover after interface return\n");
    goto Fail;
  }

  static const uint8_t probe[] = "membership timeout probe";
  for (size_t track_index = 0; track_index < 2; track_index++) {
    for (uint64_t i = 0; i < 40; i++) {
      moq_object_t object = {.track_id = tracks[track_index],
                             .group_id = 1,
                             .object_id = i,
                             .data = probe,
                             .size = sizeof(probe),
                             .priority = 1};
      if (!transport_publish(server, &object)) {
        fprintf(stderr, "membership timeout probe publication failed\n");
        goto Fail;
      }
    }
  }

  retries = 800;
  while (retries-- > 0) {
    transport_tick(server); /* deliberately withhold receiver PATH_ACKs */
    (void)transport_get_stats(server, &source_stats);
    if (source_stats.flexicast_feedback_fallbacks >= 2 &&
        source_stats.flexicast_active_members == 0)
      break;
    usleep(5000);
  }
  if (source_stats.flexicast_feedback_fallbacks != 2 ||
      source_stats.flexicast_active_members != 0) {
    fprintf(stderr,
            "feedback loss did not retire both multicast flows "
            "(fallbacks=%" PRIu64 ", members=%zu)\n",
            source_stats.flexicast_feedback_fallbacks,
            source_stats.flexicast_active_members);
    goto Fail;
  }

  retries = 300;
  while (retries-- > 0) {
    drive(server, client, NULL);
    (void)transport_get_stats(client, &receiver_stats);
    if (receiver_stats.flexicast_active_memberships == 0 &&
        receiver_stats.flexicast_membership_leaves == 2)
      break;
    usleep(5000);
  }
  if (receiver_stats.flexicast_membership_joins != 2 ||
      receiver_stats.flexicast_membership_leaves != 2 ||
      receiver_stats.flexicast_active_memberships != 0) {
    fprintf(stderr,
            "last flow did not drop the shared kernel membership "
            "(joins=%" PRIu64 ", leaves=%" PRIu64 ", active=%zu)\n",
            receiver_stats.flexicast_membership_joins,
            receiver_stats.flexicast_membership_leaves,
            receiver_stats.flexicast_active_memberships);
    goto Fail;
  }

  printf(ipv6 ? "===FLEXICAST IPV6 MEMBERSHIP OK===\n"
              : "===FLEXICAST MEMBERSHIP OK===\n");
  transport_destroy(client);
  transport_destroy(server);
  return 0;

Fail:
  if (client)
    transport_destroy(client);
  if (server)
    transport_destroy(server);
  return 1;
}

int main(int argc, char **argv) {
  const char *mode = argc == 2 ? argv[1] : NULL;
  if (argc == 2 && strcmp(mode, "--membership") == 0)
    return run_membership_lifecycle(false);
  if (argc == 2 && strcmp(mode, "--membership6") == 0)
    return run_membership_lifecycle(true);
  if (argc == 2 && strcmp(mode, "--unsubscribe") == 0)
    return run_unsubscribe_lifecycle(false);
  if (argc == 2 && strcmp(mode, "--unsubscribe6") == 0)
    return run_unsubscribe_lifecycle(true);
  bool native_multicast =
      argc == 2 &&
      (strcmp(mode, "--native") == 0 || strcmp(mode, "--native6") == 0 ||
       strcmp(mode, "--join-fallback") == 0 ||
       strcmp(mode, "--ack-fallback") == 0 || strcmp(mode, "--pacing") == 0);
  bool join_fallback = argc == 2 && strcmp(mode, "--join-fallback") == 0;
  bool ack_fallback = argc == 2 && strcmp(mode, "--ack-fallback") == 0;
  bool pacing = argc == 2 && strcmp(mode, "--pacing") == 0;
  bool control_flood = argc == 2 && strcmp(mode, "--control-flood") == 0;
  bool base = argc == 1 || (argc == 2 && strcmp(mode, "--base") == 0);
  bool ipv6 = argc == 2 && strcmp(mode, "--native6") == 0;
  if (argc > 2 || (!base && !native_multicast && !control_flood)) {
    fprintf(
        stderr,
        "usage: %s "
        "[--base|--native|--native6|--join-fallback|--ack-fallback|--pacing|"
        "--control-flood|--membership|--membership6|--unsubscribe|"
        "--unsubscribe6]\n",
        argv[0]);
    return 1;
  }
  flexicast_test_state_t server_state = {0};
  flexicast_test_state_t client_a_state = {0};
  flexicast_test_state_t client_b_state = {0};
  transport_config_t server_config = {.bind_hosts = {"127.0.0.1"},
                                      .num_bind_hosts = 1,
                                      .port = 10001,
                                      .cert_file = "t/assets/server.crt",
                                      .key_file = "t/assets/server.key",
                                      .allow_insecure_peer = true,
                                      .enable_flexicast = true,
                                      .callback = on_server,
                                      .user_data = &server_state};
  transport_config_t client_a_config = {.bind_hosts = {"127.0.0.1"},
                                        .num_bind_hosts = 1,
                                        .remote_hosts = {"127.0.0.1"},
                                        .num_remote_hosts = 1,
                                        .port = 10001,
                                        .allow_insecure_peer = true,
                                        .enable_flexicast = true,
                                        .callback = on_client,
                                        .user_data = &client_a_state};
  if (ipv6) {
    server_config.bind_hosts[0] = "::1";
    client_a_config.bind_hosts[0] = "::1";
    client_a_config.remote_hosts[0] = "::1";
  }
  if (native_multicast) {
    server_config.flexicast_group = ipv6 ? "ff32::8000:1" : "232.42.42.1";
    server_config.flexicast_group_port = 10002;
    server_config.flexicast_interface = ipv6 ? "::1" : "127.0.0.1";
    client_a_config.flexicast_interface =
        join_fallback ? "192.0.2.99" : "127.0.0.1";
    if (ipv6)
      client_a_config.flexicast_interface = "::1";
  }
  transport_config_t client_b_config = client_a_config;
  client_b_config.user_data = &client_b_state;
  if (ack_fallback) {
    client_b_config.simulated_flexicast_feedback_loss_rate = 100;
    /* keep deterministic fallback test short */
    server_config.flexicast_cc_minimum_rate = 12000;
  }

  transport_t *server = transport_create(&server_config);
  transport_t *client_a = transport_create(&client_a_config);
  transport_t *client_b = NULL;
  if (!server || !client_a) {
    fprintf(stderr, "failed to create Flexicast transports\n");
    if (client_a)
      transport_destroy(client_a);
    if (server)
      transport_destroy(server);
    return 1;
  }
  server_state.transport = server;
  client_a_state.transport = client_a;

  int retries = 1000;
  while (retries-- > 0 && !client_a_state.connected) {
    drive(server, client_a, NULL);
    usleep(5000);
  }
  if (!client_a_state.connected) {
    fprintf(stderr, "first Flexicast client did not authenticate\n");
    goto Fail;
  }

  client_b = transport_create(&client_b_config);
  if (!client_b) {
    fprintf(stderr, "failed to create second Flexicast client\n");
    goto Fail;
  }
  client_b_state.transport = client_b;
  retries = 1000;
  while (retries-- > 0 && !client_b_state.connected) {
    drive(server, client_a, client_b);
    usleep(5000);
  }
  if (!client_b_state.connected) {
    transport_stats_t connection_stats = {0};
    transport_stats_t b_stats = {0};
    (void)transport_get_stats(server, &connection_stats);
    (void)transport_get_stats(client_b, &b_stats);
    fprintf(stderr,
            "Flexicast clients did not authenticate (server=%d, a=%d, b=%d, "
            "connections=%zu, handshakes=%" PRIu64 ", auth=%zu, "
            "protocol_errors=%" PRIu64 "; b_handshakes=%" PRIu64
            ", b_closed=%" PRIu64 ")\n",
            server_state.connected, client_a_state.connected,
            client_b_state.connected, connection_stats.active_connections,
            connection_stats.protocol_handshakes_completed,
            server_state.auth_requests, connection_stats.protocol_errors,
            b_stats.protocol_handshakes_completed, b_stats.connections_closed);
    goto Fail;
  }

  moq_track_id_t track = {
      .type = MOQ_TRACK_VIDEO,
      .flags = ((ack_fallback || pacing) ? 0 : MOQ_TRACK_FLAG_FEC_ENABLED)};
  strcpy(track.name, "shared-video");
  if (!transport_subscribe(client_a, track) ||
      !transport_subscribe(client_b, track)) {
    fprintf(stderr, "Flexicast subscriptions failed\n");
    goto Fail;
  }

  transport_stats_t source_stats = {0};
  retries = 300;
  while (retries-- > 0) {
    drive(server, client_a, client_b);
    (void)transport_get_stats(server, &source_stats);
    if (server_state.subscriptions == 2 &&
        source_stats.flexicast_active_flows == 1 &&
        source_stats.flexicast_active_members == (join_fallback ? 0U : 2U))
      break;
    usleep(5000);
  }
  if (source_stats.flexicast_active_flows != 1 ||
      source_stats.flexicast_active_members != (join_fallback ? 0U : 2U)) {
    fprintf(stderr, "subscribers did not join one shared flow\n");
    goto Fail;
  }

  static const uint8_t payload[] = "one ciphertext, two subscribers";
  moq_object_t object = {.track_id = track,
                         .group_id = 7,
                         .object_id = 11,
                         .data = payload,
                         .size = sizeof(payload),
                         .is_keyframe = true,
                         .priority = 2};
  if (!transport_publish(server, &object)) {
    fprintf(stderr, "shared publication failed\n");
    goto Fail;
  }
  retries = 300;
  while (retries-- > 0 &&
         (!client_a_state.received || !client_b_state.received)) {
    drive(server, client_a, client_b);
    usleep(5000);
  }
  for (int i = 0; i < 10; i++)
    drive(server, client_a, client_b);
  (void)transport_get_stats(server, &source_stats);
  transport_stats_t client_a_stats = {0}, client_b_stats = {0};
  (void)transport_get_stats(client_a, &client_a_stats);
  (void)transport_get_stats(client_b, &client_b_stats);
  if (!client_a_state.received || !client_b_state.received ||
      client_a_state.payload_size != sizeof(payload) ||
      client_b_state.payload_size != sizeof(payload) ||
      memcmp(client_a_state.payload, payload, sizeof(payload)) != 0 ||
      memcmp(client_b_state.payload, payload, sizeof(payload)) != 0 ||
      (!join_fallback && source_stats.flexicast_packets_sent == 0) ||
      (native_multicast && !join_fallback &&
       source_stats.flexicast_native_packets_sent == 0 &&
       (!ipv6 || source_stats.flexicast_fallbacks == 0)) ||
      (!join_fallback && source_stats.flexicast_rekeys == 0) ||
      (join_fallback && (client_a_stats.flexicast_fallbacks == 0 ||
                         client_b_stats.flexicast_fallbacks == 0)) ||
      (!join_fallback && !ack_fallback &&
       source_stats.flexicast_acks_received < 2) ||
      (ack_fallback && source_stats.flexicast_acks_received < 1)) {
    fprintf(stderr,
            "shared delivery failed (a=%d, b=%d, packets=%" PRIu64
            ", acks=%" PRIu64 ")\n",
            client_a_state.received, client_b_state.received,
            source_stats.flexicast_packets_sent,
            source_stats.flexicast_acks_received);
    goto Fail;
  }

  if (ack_fallback) {
    client_a_state.received = false;
    client_b_state.received = false;
    static const uint8_t loss_probe[] = "multicast health probe";
    for (uint64_t i = 0; i < 40; i++) {
      moq_object_t probe = {.track_id = track,
                            .group_id = 8,
                            .object_id = 100 + i,
                            .data = loss_probe,
                            .size = sizeof(loss_probe),
                            .priority = 1};
      if (!transport_publish(server, &probe)) {
        fprintf(stderr, "feedback fallback probe failed\n");
        goto Fail;
      }
      drive(server, client_a, client_b);
    }
    retries = 2000;
    while (retries-- > 0) {
      drive(server, client_a, client_b);
      (void)transport_get_stats(server, &source_stats);
      if (source_stats.flexicast_feedback_fallbacks >= 1 &&
          source_stats.flexicast_active_members == 1)
        break;
      usleep(5000);
    }
    if (source_stats.flexicast_feedback_fallbacks != 1 ||
        source_stats.flexicast_active_members != 1) {
      fprintf(stderr,
              "missing PATH_ACK did not demote one member (fallbacks=%" PRIu64
              ", members=%zu)\n",
              source_stats.flexicast_feedback_fallbacks,
              source_stats.flexicast_active_members);
      goto Fail;
    }

    for (int i = 0; i < 40; i++)
      drive(server, client_a, client_b);
    static const uint8_t fallback_payload[] = "unicast after feedback timeout";
    moq_object_t fallback_object = {.track_id = track,
                                    .group_id = 9,
                                    .object_id = 200,
                                    .data = fallback_payload,
                                    .size = sizeof(fallback_payload),
                                    .priority = 2};
    client_a_state.received = false;
    client_b_state.received = false;
    if (!transport_publish(server, &fallback_object)) {
      fprintf(stderr, "post-timeout publication failed\n");
      goto Fail;
    }
    retries = 300;
    while (retries-- > 0 &&
           (!client_a_state.received || !client_b_state.received)) {
      drive(server, client_a, client_b);
      usleep(5000);
    }
    if (!client_a_state.received || !client_b_state.received ||
        client_a_state.payload_size != sizeof(fallback_payload) ||
        client_b_state.payload_size != sizeof(fallback_payload) ||
        memcmp(client_a_state.payload, fallback_payload,
               sizeof(fallback_payload)) != 0 ||
        memcmp(client_b_state.payload, fallback_payload,
               sizeof(fallback_payload)) != 0) {
      transport_stats_t a_diagnostic = {0}, b_diagnostic = {0};
      (void)transport_get_stats(client_a, &a_diagnostic);
      (void)transport_get_stats(client_b, &b_diagnostic);
      fprintf(
          stderr,
          "post-timeout unicast fallback delivery failed "
          "(a=%d/%zu rx=%" PRIu64 " errors=%" PRIu64 ", b=%d/%zu rx=%" PRIu64
          " errors=%" PRIu64 " conns=%zu closed=%" PRIu64
          ", source_packets=%" PRIu64 " udp=%" PRIu64
          " egress=%zu conns=%zu queued=%zu drops=%" PRIu64 ")\n",
          client_a_state.received, client_a_state.payload_size,
          a_diagnostic.datagrams_received, a_diagnostic.protocol_errors,
          client_b_state.received, client_b_state.payload_size,
          b_diagnostic.datagrams_received, b_diagnostic.protocol_errors,
          b_diagnostic.active_connections, b_diagnostic.connections_closed,
          source_stats.flexicast_packets_sent, source_stats.udp_packets_sent,
          source_stats.egress_current_packets, source_stats.active_connections,
          source_stats.flexicast_queued_packets,
          source_stats.flexicast_pacing_dropped);
      goto Fail;
    }
  }

  if (pacing) {
    static const uint8_t paced_payload[32] = {0x51, 0x4c, 0x49, 0x4e, 0x51};
    size_t accepted = 0;
    bool saw_backpressure = false;
    client_a_state.received = false;
    client_b_state.received = false;
    for (uint64_t i = 0; i < 400; i++) {
      moq_object_t paced = {.track_id = track,
                            .group_id = 10,
                            .object_id = 300 + i,
                            .data = paced_payload,
                            .size = sizeof(paced_payload),
                            .priority = 1};
      if (!transport_publish(server, &paced)) {
        saw_backpressure = true;
        break;
      }
      accepted++;
    }
    (void)transport_get_stats(server, &source_stats);
    if (!saw_backpressure || accepted == 0 ||
        source_stats.flexicast_queued_packets == 0 ||
        source_stats.flexicast_pacing_delays == 0 ||
        source_stats.flexicast_pacing_backpressure == 0 ||
        transport_is_track_ready(server, &track) ||
        source_stats.flexicast_pacing_rate_bytes_per_second == 0) {
      fprintf(stderr,
              "multicast burst bypassed bounds (accepted=%zu, queued=%zu, "
              "delays=%" PRIu64 ", backpressure=%" PRIu64
              ", ready=%d, rate=%" PRIu64 ")\n",
              accepted, source_stats.flexicast_queued_packets,
              source_stats.flexicast_pacing_delays,
              source_stats.flexicast_pacing_backpressure,
              transport_is_track_ready(server, &track),
              source_stats.flexicast_pacing_rate_bytes_per_second);
      goto Fail;
    }
    retries = 600;
    while (retries-- > 0) {
      drive(server, client_a, client_b);
      (void)transport_get_stats(server, &source_stats);
      if (source_stats.flexicast_queued_packets == 0 &&
          client_a_state.received && client_b_state.received)
        break;
      usleep(5000);
    }
    if (source_stats.flexicast_queued_packets != 0 ||
        !client_a_state.received || !client_b_state.received ||
        source_stats.flexicast_paced_packets < accepted + 1U) {
      fprintf(stderr,
              "paced queue did not drain (queued=%zu, paced=%" PRIu64 ")\n",
              source_stats.flexicast_queued_packets,
              source_stats.flexicast_paced_packets);
      goto Fail;
    }
  }

  if (control_flood) {
    transport_flexicast_flow_t *flow =
        transport_flexicast_find_source(server, &track);
    if (!flow || flow->member_count < 2) {
      fprintf(stderr, "control-throttle flow was not established\n");
      goto Fail;
    }
    transport_flexicast_member_t *member = &flow->members[0];
    quicly_flexicast_frame_t frame = {.type = QUICLY_FRAME_TYPE_FC_STATE};
    frame.data.state.flow_id.len = QUICLY_FLEXICAST_FLOW_ID_SIZE;
    quicly_encode64(frame.data.state.flow_id.bytes, flow->flow_id);
    frame.data.state.sequence = flow->key_epoch;
    for (size_t i = 0;
         i < TRANSPORT_FLEXICAST_MEMBER_TRANSITIONS_PER_SECOND + 1U; i++) {
      /* rotate pending epoch before flooding next transition */
      if (!member->joined && flow->rekey_pending) {
        flow->rekey_ready_at_ms = transport_get_time_ms();
        transport_flexicast_tick(server);
      }
      frame.data.state.sequence = flow->key_epoch;
      frame.data.state.action = member->joined ? QUICLY_FLEXICAST_STATE_LEAVE
                                               : QUICLY_FLEXICAST_STATE_JOIN;
      if (!transport_flexicast_receive_quic_frame(server, member->conn,
                                                  &frame)) {
        fprintf(stderr, "control transition was rejected at %zu\n", i);
        goto Fail;
      }
    }
    (void)transport_get_stats(server, &source_stats);
    if (source_stats.flexicast_control_frames_throttled == 0 ||
        member->joined || member->listening) {
      fprintf(stderr,
              "control transition flood was not safely demoted "
              "(throttled=%" PRIu64 ")\n",
              source_stats.flexicast_control_frames_throttled);
      goto Fail;
    }
  }

  printf(ipv6               ? "===FLEXICAST IPV6 MULTICAST OK===\n"
         : pacing           ? "===FLEXICAST PACING OK===\n"
         : control_flood    ? "===FLEXICAST CONTROL THROTTLE OK===\n"
         : ack_fallback     ? "===FLEXICAST ACK FALLBACK OK===\n"
         : join_fallback    ? "===FLEXICAST JOIN FALLBACK OK===\n"
         : native_multicast ? "===FLEXICAST MULTICAST OK===\n"
                            : "===FLEXICAST TRANSPORT OK===\n");
  transport_destroy(client_b);
  transport_destroy(client_a);
  transport_destroy(server);
  return 0;

Fail:
  if (client_b)
    transport_destroy(client_b);
  transport_destroy(client_a);
  transport_destroy(server);
  return 1;
}
