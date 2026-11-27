#include "portable_sockets.h"
#include "transport.h"
#include "transport_internal.h"

#include <assert.h>
#ifdef __linux__
#include <ifaddrs.h>
#endif
#include <inttypes.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef QLINQ_TEST_AMT
#include "amt_native_fixture.h"
#include "transport_amt_host.h"
#endif

typedef struct {
  transport_t *transport;
  bool connected;
  size_t subscriptions;
  size_t unsubscriptions;
  size_t auth_requests;
  bool received;
  size_t objects_received;
  uint8_t payload[2048];
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
#ifdef QLINQ_TEST_AMT
  fixture_pump();
#endif
  transport_tick(server);
  if (a)
    transport_tick(a);
  if (b)
    transport_tick(b);
#ifdef QLINQ_TEST_AMT
  fixture_pump();
#endif
}

static void test_mixed_group_retry(transport_t *server,
                                   const flexicast_test_state_t *shared,
                                   const flexicast_test_state_t *unicast,
                                   const moq_track_id_t *track) {
  transport_flexicast_flow_t *flow = NULL;
  for (size_t i = 0; i < server->flexicast.capacity; i++) {
    transport_flexicast_flow_t *candidate = &server->flexicast.flows[i];
    if (candidate->active && candidate->source &&
        transport_track_id_equal(&candidate->track_id, track)) {
      flow = candidate;
      break;
    }
  }
  assert(flow && flow->listening_count == 1 && flow->data_queue.count == 0);
  transport_conn_t *blocked = NULL;
  for (size_t i = 0; i < server->conn_count; i++)
    if (!transport_flexicast_member_is_listening(flow, server->conns[i]))
      blocked = server->conns[i];
  assert(blocked);

  /* Leave the native datagram size query usable while blocking admission of
   * this two-symbol group on the ordinary unicast connection. */
  const size_t queue_limit = QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY - 1;
  uint8_t filler = 0xff;
  ptls_iovec_t frame = ptls_iovec_init(&filler, sizeof(filler));
  for (size_t queued = quicly_get_num_datagram_frames_path(blocked->quic, 0);
       queued < queue_limit; queued++) {
    quicly_send_datagram_frames_path(blocked->quic, 0, &frame, 1);
    assert(quicly_get_num_datagram_frames_path(blocked->quic, 0) == queued + 1);
  }

  static const uint8_t payload[2000] = {17, 23, 41};
  moq_object_t object = {
      .track_id = *track, .data = payload, .size = sizeof(payload)};
  uint64_t sent_before = server->stats.flexicast_packets_sent;
  flow->dispatch_retry_at_ms = INT64_MAX;
  assert(transport_publish_ex(server, &object) == TRANSPORT_PUBLISH_BUFFERED);
  assert(!transport_publish_flush(server));
  size_t admitted = flow->data_queue.count;
  assert(admitted > 0 && server->stats.flexicast_packets_sent == sent_before);
  assert(!transport_publish_flush(server));
  assert(flow->data_queue.count == admitted);
  assert(quicly_get_num_datagram_frames_path(blocked->quic, 0) == queue_limit);

  flow->dispatch_retry_at_ms = 0;
  tf_drain_paced_payloads(server, flow);
  assert(flow->data_queue.count == 0);
  uint64_t sent = server->stats.flexicast_packets_sent;
  assert(sent - sent_before == admitted);
  assert(!transport_publish_flush(server));
  assert(flow->data_queue.count == 0 &&
         server->stats.flexicast_packets_sent == sent);

  quicly_discard_datagram_frames(blocked->quic, 0);
  assert(transport_publish_flush(server));
  assert(flow->data_queue.count == 0 &&
         server->stats.flexicast_packets_sent == sent);
  for (size_t i = 0; i < 400 && (!shared->received || !unicast->received); i++) {
    drive(server, shared->transport, unicast->transport);
    usleep(5000);
  }
  const size_t framed_size = 2 + sizeof(payload);
  assert(shared->objects_received == 1 && unicast->objects_received == 1);
  assert(shared->payload_size == framed_size &&
         unicast->payload_size == framed_size);
  assert(memcmp(shared->payload + 2, payload, sizeof(payload)) == 0 &&
         memcmp(unicast->payload + 2, payload, sizeof(payload)) == 0);
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

static const char ipv6_group[] = "ff32::8000:1";

/* Verify native SSM independently of the transport and its fallback. */
static const char *native_ipv6_unavailable(const char *address) {
#if defined(__linux__) && defined(MCAST_JOIN_SOURCE_GROUP)
  struct sockaddr_in6 source = {.sin6_family = AF_INET6};
  if (inet_pton(AF_INET6, address, &source.sin6_addr) != 1)
    return "invalid IPv6 test address";
  struct ifaddrs *interfaces = NULL;
  unsigned int ifindex = 0;
  if (getifaddrs(&interfaces) != 0)
    return "cannot list IPv6 interfaces";
  for (const struct ifaddrs *item = interfaces; item; item = item->ifa_next) {
    if (item->ifa_addr && item->ifa_addr->sa_family == AF_INET6 &&
        memcmp(&((const struct sockaddr_in6 *)item->ifa_addr)->sin6_addr,
               &source.sin6_addr, sizeof(source.sin6_addr)) == 0) {
      ifindex = if_nametoindex(item->ifa_name);
      break;
    }
  }
  freeifaddrs(interfaces);
  if (ifindex == 0)
    return "no interface has the IPv6 test address";

  int receiver = socket(AF_INET6, SOCK_DGRAM, 0);
  int sender = socket(AF_INET6, SOCK_DGRAM, 0);
  const char *reason = "cannot open IPv6 UDP sockets";
  if (receiver < 0 || sender < 0)
    goto Done;

  const int enabled = 1;
  struct sockaddr_in6 local = {.sin6_family = AF_INET6};
  socklen_t local_len = sizeof(local);
  reason = "cannot bind IPv6 UDP sockets";
  if (bind(receiver, (struct sockaddr *)&local, sizeof(local)) != 0 ||
      getsockname(receiver, (struct sockaddr *)&local, &local_len) != 0 ||
      bind(sender, (struct sockaddr *)&source, sizeof(source)) != 0)
    goto Done;

  struct sockaddr_in6 destination = {.sin6_family = AF_INET6,
                                     .sin6_port = local.sin6_port,
                                     .sin6_scope_id = ifindex};
  if (inet_pton(AF_INET6, ipv6_group, &destination.sin6_addr) != 1)
    abort();
  struct group_source_req request = {.gsr_interface = ifindex};
  struct sockaddr_in6 group = {.sin6_family = AF_INET6,
                                .sin6_addr = destination.sin6_addr};
  memcpy(&request.gsr_group, &group, sizeof(group));
  memcpy(&request.gsr_source, &source, sizeof(source));
  reason = "cannot join IPv6 source-specific multicast on the test interface";
  if (setsockopt(receiver, IPPROTO_IPV6, IPV6_RECVPKTINFO, &enabled,
                 sizeof(enabled)) != 0 ||
      setsockopt(receiver, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, &request,
                 sizeof(request)) != 0)
    goto Done;

  const uint8_t probe = 0x42;
  reason = "cannot send IPv6 source-specific multicast on the test interface";
  if (sendto(sender, &probe, sizeof(probe), 0,
             (struct sockaddr *)&destination, sizeof(destination)) !=
      sizeof(probe))
    goto Done;

  struct pollfd ready = {.fd = receiver, .events = POLLIN};
  uint8_t received = 0;
  reason = "IPv6 source-specific multicast did not reach the test socket";
  int result;
  do {
    result = poll(&ready, 1, 250);
  } while (result < 0 && errno == EINTR);
  if (result == 1 && (ready.revents & POLLIN) &&
      recv(receiver, &received, sizeof(received), 0) == sizeof(received) &&
      received == probe)
    reason = NULL;

Done:
  if (receiver >= 0)
    CLOSE_SOCKET(receiver);
  if (sender >= 0)
    CLOSE_SOCKET(sender);
  return reason;
#else
  (void)address;
  return "IPv6 source-specific multicast socket support is unavailable";
#endif
}

static transport_drive_host_t ipv6_fallback_host;
static size_t ipv6_multicast_send_failures;

static ssize_t fail_ipv6_multicast_send(
    void *context, const transport_drive_path_t *path,
    const struct sockaddr *source, const struct sockaddr *destination,
    socklen_t destination_len, uint32_t interface_index, uint8_t ecn,
    size_t max_gso_segments, const struct iovec *datagrams, size_t count) {
  if (destination->sa_family == AF_INET6 &&
      IN6_IS_ADDR_MULTICAST(&((const struct sockaddr_in6 *)destination)
                                ->sin6_addr)) {
    ipv6_multicast_send_failures++;
    errno = ENETUNREACH;
    return -1;
  }
  return ipv6_fallback_host.send(
      context, path, source, destination, destination_len, interface_index,
      ecn, max_gso_segments, datagrams, count);
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
  bool native6 = argc == 2 && strcmp(mode, "--native6") == 0;
  bool native6_fallback = argc == 2 && strcmp(mode, "--native6-fallback") == 0;
  bool mixed_retry = argc == 2 && strcmp(mode, "--mixed-retry") == 0;
  bool native_multicast =
      argc == 2 &&
      (strcmp(mode, "--native") == 0 || native6 || native6_fallback ||
       strcmp(mode, "--join-fallback") == 0 ||
       strcmp(mode, "--ack-fallback") == 0 || strcmp(mode, "--pacing") == 0);
#ifdef QLINQ_TEST_AMT
  bool amt = !strcmp(mode, "--amt") || !strcmp(mode, "--amt-mixed") ||
             !strcmp(mode, "--amt-unavailable");
  bool unavailable = !strcmp(mode, "--amt-unavailable");
  bool mixed = !strcmp(mode, "--amt-mixed");
  native_multicast |= amt;
#else
  bool amt = false;
#endif
  bool join_fallback = argc == 2 && strcmp(mode, "--join-fallback") == 0;
  bool ack_fallback = argc == 2 && strcmp(mode, "--ack-fallback") == 0;
  bool pacing = argc == 2 && strcmp(mode, "--pacing") == 0;
  bool control_flood = argc == 2 && strcmp(mode, "--control-flood") == 0;
#ifdef QLINQ_TEST_AMT
  join_fallback |= unavailable;
#endif
  bool base = argc == 1 || (argc == 2 && strcmp(mode, "--base") == 0);
  bool ipv6 = native6 || native6_fallback;
  if (argc > 2 ||
      (!base && !native_multicast && !control_flood && !mixed_retry)) {
    fprintf(
        stderr,
        "usage: %s "
        "[--base|--native|--native6|--native6-fallback|--join-fallback|"
        "--ack-fallback|--pacing|--control-flood|--membership|--membership6|"
        "--unsubscribe|--unsubscribe6|--mixed-retry]\n",
        argv[0]);
    return 1;
  }
  const char *ipv6_address = "::1";
  if (native6) {
    const char *configured_address = getenv("QLINQ_TEST_NATIVE6_ADDRESS");
    if (configured_address)
      ipv6_address = configured_address;
    const char *reason = native_ipv6_unavailable(ipv6_address);
    if (reason) {
      if (configured_address) {
        fprintf(stderr, "IPv6 SSM on %s: %s\n", ipv6_address, reason);
        return 1;
      }
      printf("SKIP %s\n", reason);
      return 0;
    }
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
    server_config.bind_hosts[0] = ipv6_address;
    client_a_config.bind_hosts[0] = ipv6_address;
    client_a_config.remote_hosts[0] = ipv6_address;
  }
  if (native_multicast) {
    server_config.flexicast_group = ipv6 ? ipv6_group : "232.42.42.1";
    server_config.flexicast_group_port = 10002;
    server_config.flexicast_interface = ipv6 ? ipv6_address : "127.0.0.1";
    client_a_config.flexicast_interface =
        ipv6 ? ipv6_address : join_fallback ? "192.0.2.99" : "127.0.0.1";
  }
  if (mixed_retry) {
    server_config.limits.max_udp_payload_size = 1452;
    client_a_config.limits.max_udp_payload_size = 1200;
  }
#ifdef QLINQ_TEST_AMT
  if (amt) {
    if (!unavailable)
      fixture_open(true);
    client_a_config.flexicast_interface = NULL;
    client_a_config.flexicast_receiver_backend = TRANSPORT_GROUP_AMT;
    client_a_config.flexicast_relay_address = "127.0.0.1";
    client_a_config.flexicast_relay_port = unavailable ? 10169 : 10168;
  }
#endif
  transport_config_t client_b_config = client_a_config;
  if (mixed_retry)
    client_b_config.enable_flexicast = false;
#ifdef QLINQ_TEST_AMT
  if (mixed) {
    client_b_config.flexicast_receiver_backend = TRANSPORT_GROUP_NATIVE;
    client_b_config.flexicast_relay_address = NULL;
    client_b_config.flexicast_relay_port = 0;
    client_b_config.flexicast_interface = "127.0.0.1";
  }
#endif
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
#ifdef QLINQ_TEST_AMT
    fixture_close();
#endif
    return 1;
  }
  if (native6_fallback) {
    ipv6_fallback_host = server->drive_host;
    server->drive_host.send = fail_ipv6_multicast_send;
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
      .type = mixed_retry ? MOQ_TRACK_DATA : MOQ_TRACK_VIDEO,
      .flags = ((ack_fallback || pacing) ? 0 : MOQ_TRACK_FLAG_FEC_ENABLED)};
  strcpy(track.name, mixed_retry ? "mixed-retry" : "shared-video");
  if (!transport_subscribe(client_a, track) ||
      !transport_subscribe(client_b, track)) {
    fprintf(stderr, "Flexicast subscriptions failed\n");
    goto Fail;
  }

  transport_stats_t source_stats = {0};
  const size_t expected_members = join_fallback ? 0U : mixed_retry ? 1U : 2U;
  retries = 300;
  while (retries-- > 0) {
    drive(server, client_a, client_b);
    (void)transport_get_stats(server, &source_stats);
    if (server_state.subscriptions == 2 &&
        source_stats.flexicast_active_flows == 1 &&
        source_stats.flexicast_active_members == expected_members)
      break;
    usleep(5000);
  }
  if (source_stats.flexicast_active_flows != 1 ||
      source_stats.flexicast_active_members != expected_members) {
    fprintf(stderr, "subscribers did not join one shared flow\n");
    goto Fail;
  }

  if (mixed_retry) {
    test_mixed_group_retry(server, &client_a_state, &client_b_state, &track);
    puts("===FLEXICAST MIXED GROUP RETRY OK===");
    goto Success;
  }

#ifdef QLINQ_TEST_AMT
  if (unavailable) {
    transport_t *clients[] = {client_a, client_b};
    for (size_t i = 0; i < 2; ++i) {
      for (unsigned wait = 0; wait < 200; ++wait) {
        bool offered = false;
        for (size_t f = 0; f < clients[i]->flexicast.capacity; ++f)
          offered |= clients[i]->flexicast.flows[f].announcement_received;
        if (offered)
          break;
        drive(server, client_a, client_b);
        usleep(1000);
      }
      clients[i]->drive_now_ns += UINT64_C(16000000000);
      clients[i]->turn_active = true;
      transport_amt_host_service(clients[i], NULL, 0);
      clients[i]->turn_active = false;
      clients[i]->drive_now_ns -= UINT64_C(16000000000);
      for (size_t f = 0; f < clients[i]->flexicast.capacity; ++f)
        if (clients[i]->flexicast.flows[f].active &&
            (!clients[i]->flexicast.flows[f].multicast_unavailable ||
             clients[i]->flexicast.flows[f].amt_tunnel ||
             clients[i]->flexicast.flows[f].join_sent))
          goto Fail;
    }
  }
#endif
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
  /* For native IPv6, both peers must receive a Flexicast packet and all
   * shared submissions must have used the multicast destination. */
  if ((amt && !join_fallback &&
       (!client_a_stats.flexicast_amt_packets_received ||
        client_a_stats.flexicast_amt_packets_rejected)) ||
      !client_a_state.received || !client_b_state.received ||
      client_a_state.payload_size != sizeof(payload) ||
      client_b_state.payload_size != sizeof(payload) ||
      memcmp(client_a_state.payload, payload, sizeof(payload)) != 0 ||
      memcmp(client_b_state.payload, payload, sizeof(payload)) != 0 ||
      (!join_fallback && source_stats.flexicast_packets_sent == 0) ||
      (native_multicast && !join_fallback && !native6_fallback &&
       source_stats.flexicast_native_packets_sent == 0) ||
      (native6 && source_stats.flexicast_native_packets_sent !=
                      source_stats.flexicast_packets_sent) ||
      (ipv6 && (client_a_stats.flexicast_packets_received == 0 ||
                client_b_stats.flexicast_packets_received == 0)) ||
      (native6_fallback && (ipv6_multicast_send_failures == 0 ||
                            source_stats.flexicast_fallbacks == 0 ||
                            source_stats.flexicast_native_packets_sent != 0)) ||
      (!join_fallback && source_stats.flexicast_rekeys == 0) ||
      (join_fallback && (client_a_stats.flexicast_fallbacks == 0 ||
                         client_b_stats.flexicast_fallbacks == 0)) ||
      (!join_fallback && !ack_fallback &&
       source_stats.flexicast_acks_received < 2) ||
      (ack_fallback && source_stats.flexicast_acks_received < 1)) {
    fprintf(stderr,
            "shared delivery failed (a=%d, b=%d, packets=%" PRIu64
            ", native=%" PRIu64 ", a_rx=%" PRIu64 ", b_rx=%" PRIu64
            ", acks=%" PRIu64 ")\n",
            client_a_state.received, client_b_state.received,
            source_stats.flexicast_packets_sent,
            source_stats.flexicast_native_packets_sent,
            client_a_stats.flexicast_packets_received,
            client_b_stats.flexicast_packets_received,
            source_stats.flexicast_acks_received);
    goto Fail;
  }

  if (base) {
    transport_flexicast_flow_t *flow = NULL;
    for (size_t i = 0; i < server->flexicast.capacity; i++) {
      if (server->flexicast.flows[i].active &&
          server->flexicast.flows[i].source &&
          transport_track_id_equal(&server->flexicast.flows[i].track_id,
                                   &track)) {
        flow = &server->flexicast.flows[i];
        break;
      }
    }
    if (!flow || flow->listening_count != 2) {
      fprintf(stderr, "replicated flow missing two active listeners\n");
      goto Fail;
    }
    /* verify 1x logical pacing deduction across 2-member replicated unicast */
    flow->pacing_tokens = flow->pacing_burst_bytes;
    flow->pacing_last_refill_ms = transport_now_ms(server);
    uint64_t tokens_before = flow->pacing_tokens;
    static const uint8_t holdoff_payload[] = "nonblocking holdoff check";
    size_t wire_len = QLINQ_WIRE_FEC_HEADER_SIZE + sizeof(holdoff_payload);
    size_t expected_cost =
        quicly_flexicast_datagram_size(flow->crypto, wire_len);
    /* verify rekey holdoff does not stall active listening subscribers */
    flow->rekey_pending = true;
    flow->rekey_ready_at_ms = transport_now_ms(server) + 60000;
    client_a_state.received = false;
    client_b_state.received = false;
    moq_object_t holdoff_obj = {.track_id = track,
                                .group_id = 7,
                                .object_id = 12,
                                .data = holdoff_payload,
                                .size = sizeof(holdoff_payload),
                                .is_keyframe = false,
                                .priority = 1};
    if (!transport_publish(server, &holdoff_obj)) {
      fprintf(stderr, "holdoff publication failed\n");
      goto Fail;
    }
    uint64_t spent = tokens_before >= flow->pacing_tokens
                         ? tokens_before - flow->pacing_tokens
                         : UINT64_MAX;
    if (expected_cost == 0 || spent != expected_cost) {
      fprintf(stderr,
              "replicated pacing charged %" PRIu64 " bytes instead of %zu\n",
              spent, expected_cost);
      goto Fail;
    }
    retries = 100;
    while (retries-- > 0 &&
           (!client_a_state.received || !client_b_state.received)) {
      drive(server, client_a, client_b);
      usleep(2000);
    }
    flow->rekey_pending = false;
    flow->rekey_ready_at_ms = 0;
    if (!client_a_state.received || !client_b_state.received) {
      fprintf(stderr, "rekey_pending stalled active listening members\n");
      goto Fail;
    }
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
    transport_flexicast_flow_t *flow = NULL;
    for (size_t i = 0; i < server->flexicast.capacity; i++) {
      transport_flexicast_flow_t *candidate = &server->flexicast.flows[i];
      if (candidate->active && candidate->source &&
          transport_track_id_equal(&candidate->track_id, &track) &&
          transport_flexicast_listening_members(candidate) != 0) {
        flow = candidate;
        break;
      }
    }
    if (!flow || flow->member_count < 2) {
      fprintf(stderr, "control-throttle flow was not established\n");
      goto Fail;
    }
    transport_flexicast_member_t *member = &flow->members[0];
    quicly_flexicast_frame_t frame = {.type = QUICLY_FRAME_TYPE_FC_STATE};
    frame.data.state.flow_id.len = TRANSPORT_FLEXICAST_FLOW_ID_SIZE;
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

  printf(native6            ? "===FLEXICAST IPV6 MULTICAST OK===\n"
         : native6_fallback ? "===FLEXICAST IPV6 SEND FALLBACK OK===\n"
         : pacing           ? "===FLEXICAST PACING OK===\n"
         : control_flood    ? "===FLEXICAST CONTROL THROTTLE OK===\n"
         : ack_fallback     ? "===FLEXICAST ACK FALLBACK OK===\n"
         : join_fallback    ? "===FLEXICAST JOIN FALLBACK OK===\n"
         : native_multicast ? "===FLEXICAST MULTICAST OK===\n"
                            : "===FLEXICAST TRANSPORT OK===\n");
Success:
  transport_destroy(client_b);
  transport_destroy(client_a);
  transport_destroy(server);
#ifdef QLINQ_TEST_AMT
  fixture_close();
#endif
  return 0;

Fail:
  if (client_b)
    transport_destroy(client_b);
  transport_destroy(client_a);
  transport_destroy(server);
#ifdef QLINQ_TEST_AMT
  fixture_close();
#endif
  return 1;
}
