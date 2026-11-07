/* Inspect effective native configuration through the real public bridge. */
#include "../../src/common/qlinq.c"
#include "transport_internal.h"
#include "quicly/defaults.h"
#include <assert.h>
#include <stdio.h>

static void ignore_transport_event(void *data, const transport_event_t *event) {
  (void)data;
  (void)event;
}

typedef struct {
  qlinq_context_t *context;
  qlinq_endpoint_t *expected_endpoint;
  size_t calls;
  bool allow;
  bool valid;
  uint32_t last_index;
  char last_name[64];
  char last_address[64];
  int last_family;
} iface_filter_state_t;

static bool filter_interface(void *user_data, qlinq_endpoint_t *endpoint,
                             const qlinq_interface_info_t *iface) {
  iface_filter_state_t *state = user_data;
  state->calls++;
  state->valid &= endpoint == state->expected_endpoint && iface != NULL &&
                  iface->interface_name != NULL && iface->local_address != NULL;
  /* re-entrant API calls must be rejected while the callback is active */
  state->valid &=
      qlinq_service(state->context, 0) == QLINQ_STATUS_STATE &&
      qlinq_context_last_status(state->context) == QLINQ_STATUS_INVALID;
  if (iface) {
    state->last_index = iface->interface_index;
    snprintf(state->last_name, sizeof(state->last_name), "%s",
             iface->interface_name);
    snprintf(state->last_address, sizeof(state->last_address), "%s",
             iface->local_address);
    state->last_family = iface->address_family;
  }
  return state->allow;
}

int main(void) {
  qlinq_context_t *context = qlinq_context_create(NULL);
  assert(context);
  qlinq_endpoint_config_t config = {.bind_addresses = {"127.0.0.1"},
                                    .bind_address_count = 1,
                                    .remote_addresses = {"127.0.0.1"},
                                    .remote_address_count = 1,
                                    .port = 19938,
                                    .security = {.allow_insecure_peer = true}};
  for (unsigned cc = QLINQ_CC_DEFAULT; cc <= QLINQ_CC_CUBIC; cc++) {
    for (unsigned pacing = QLINQ_PACING_DEFAULT; pacing <= QLINQ_PACING_ENABLED;
         pacing++) {
      config.congestion_control = (qlinq_congestion_control_t)cc;
      config.pacing = (qlinq_pacing_t)pacing;
      qlinq_endpoint_t *endpoint = qlinq_connect(context, &config);
      assert(endpoint);
      quicly_init_cc_t *expected = cc == QLINQ_CC_PICO ? &quicly_cc_pico_init
                                   : cc == QLINQ_CC_CUBIC
                                       ? &quicly_cc_cubic_init
                                       : &quicly_cc_reno_init;
      assert(endpoint->transport->quic_ctx.egress[0].cc.init_cc == expected);
      assert(endpoint->transport->quic_ctx.egress[0].pacing ==
             (pacing == QLINQ_PACING_ENABLED));
      assert(endpoint->transport->quic_ctx.egress[0].cc.initcwnd_packets ==
             100);
      qlinq_endpoint_close(endpoint);
    }
  }
  const uint32_t probe_intervals[] = {0, 250, UINT32_MAX};
  for (size_t i = 0; i < sizeof(probe_intervals) / sizeof(probe_intervals[0]);
       i++) {
    config.path_probe_interval_ms = probe_intervals[i];
    qlinq_endpoint_t *endpoint = qlinq_connect(context, &config);
    assert(endpoint &&
           endpoint->transport->path_probe_interval_ms == probe_intervals[i]);
    qlinq_endpoint_close(endpoint);
  }
  config.path_probe_interval_ms = 0;
  /* Exercise the actual native connection: BBR cannot allocate a path unless
   * the public policy enabled its required pacer. */
  config.congestion_control = QLINQ_CC_BBR;
  for (unsigned pacing = QLINQ_PACING_DEFAULT; pacing <= QLINQ_PACING_ENABLED;
       pacing++) {
    config.pacing = (qlinq_pacing_t)pacing;
    qlinq_endpoint_t *endpoint = qlinq_connect(context, &config);
    if (pacing == QLINQ_PACING_DISABLED) {
      assert(!endpoint);
      assert(qlinq_context_last_status(context) == QLINQ_STATUS_INVALID);
      continue;
    }
    assert(endpoint && endpoint->transport->client_conn);
    assert(endpoint->transport->quic_ctx.egress[0].pacing == 1);
    assert(endpoint->transport->quic_ctx.egress[0].ecn ==
           QUICLY_ECN_MODE_CLASSIC);
    quicly_stats_t stats;
    assert(quicly_get_stats(endpoint->transport->client_conn->quic, &stats) ==
           0);
    assert(stats.cc.type == &quicly_cc_type_bbr);
    assert(stats.cc.state.bbr.stats.pacing_interval_m != 0);
    qlinq_endpoint_close(endpoint);
  }
  config.congestion_control = QLINQ_CC_CUBIC;
  const uint32_t initial_windows[] = {0, 1, 10, 100,
                                      QLINQ_MAX_INITIAL_CWND_PACKETS};
  for (size_t i = 0; i < sizeof(initial_windows) / sizeof(initial_windows[0]);
       i++) {
    config.initial_cwnd_packets = initial_windows[i];
    qlinq_endpoint_t *endpoint = qlinq_connect(context, &config);
    assert(endpoint);
    uint32_t expected = initial_windows[i] != 0 ? initial_windows[i] : 100;
    transport_t *transport = endpoint->transport;
    assert(transport->quic_ctx.egress[0].cc.initcwnd_packets == expected);
    /* Inspect the created native path too: one requested packet is floored
     * to two, while zero must retain QLINQ's 100-packet default. */
    assert(transport->client_conn && transport->client_conn->quic);
    quicly_path_stats_t stats;
    assert(quicly_get_path_stats(transport->client_conn->quic, 0, &stats) == 0);
    uint32_t mtu = transport->quic_ctx.transport_params.max_udp_payload_size;
    if (mtu > 1472)
      mtu = 1472;
    assert(stats.cwnd == (expected < 2 ? 2 : expected) * mtu);
    qlinq_endpoint_close(endpoint);
  }
  const uint32_t invalid_windows[] = {QLINQ_MAX_INITIAL_CWND_PACKETS + 1U,
                                      (uint32_t)-1};
  for (size_t i = 0; i < sizeof(invalid_windows) / sizeof(invalid_windows[0]);
       i++) {
    config.initial_cwnd_packets = invalid_windows[i];
    assert(!qlinq_connect(context, &config));
    assert(qlinq_context_last_status(context) == QLINQ_STATUS_INVALID);
  }
  config.initial_cwnd_packets = 0;

  /* test jumpstart configuration */
  config.default_jumpstart_packets = 256;
  config.max_jumpstart_packets = 1024;
  qlinq_endpoint_t *js_endpoint = qlinq_connect(context, &config);
  assert(js_endpoint);
  assert(js_endpoint->transport->quic_ctx.egress[0].default_jumpstart_packets ==
         256);
  assert(js_endpoint->transport->quic_ctx.egress[0].max_jumpstart_packets ==
         1024);
  assert(js_endpoint->transport->quic_ctx.egress[0].pacing == 1);
  assert(js_endpoint->transport->quic_ctx.egress[0].cc.rapid_start == 1);
  qlinq_endpoint_close(js_endpoint);
  config.default_jumpstart_packets = 0;
  config.max_jumpstart_packets = 0;

  /* Internal callers bypass the public bridge and require the same bound. */
  transport_config_t native_config = {.bind_hosts = {"127.0.0.1"},
                                      .num_bind_hosts = 1,
                                      .remote_hosts = {"127.0.0.1"},
                                      .num_remote_hosts = 1,
                                      .port = 19939,
                                      .allow_insecure_peer = true,
                                      .callback = ignore_transport_event};
  transport_t *native = transport_create(&native_config);
  assert(native);
  assert(native->quic_ctx.egress[0].cc.initcwnd_packets == 100);
  transport_destroy(native);
  for (size_t i = 0; i < sizeof(invalid_windows) / sizeof(invalid_windows[0]);
       i++) {
    native_config.initial_cwnd_packets = invalid_windows[i];
    assert(!transport_create(&native_config));
  }
  native_config.initial_cwnd_packets = 0;
  native_config.congestion_control = TRANSPORT_CC_BBR;
  native = transport_create(&native_config);
  assert(native && native->client_conn);
  quicly_stats_t native_stats;
  assert(quicly_get_stats(native->client_conn->quic, &native_stats) == 0);
  assert(native_stats.cc.type == &quicly_cc_type_bbr);
  assert(native->quic_ctx.egress[0].pacing == 1);
  transport_destroy(native);
  native_config.pacing = TRANSPORT_PACING_DISABLED;
  native_config.default_jumpstart_packets = 256;
  assert(!transport_create(&native_config));
  config.congestion_control = (qlinq_congestion_control_t)-1;
  assert(!qlinq_connect(context, &config));
  assert(qlinq_context_last_status(context) == QLINQ_STATUS_INVALID);
  config.congestion_control = (qlinq_congestion_control_t)(QLINQ_CC_CUBIC + 1);
  assert(!qlinq_connect(context, &config));
  assert(qlinq_context_last_status(context) == QLINQ_STATUS_INVALID);
  config.congestion_control = (qlinq_congestion_control_t)(QLINQ_CC_BBR + 1);
  assert(!qlinq_connect(context, &config));
  config.congestion_control = QLINQ_CC_BBR;
  config.pacing = QLINQ_PACING_DISABLED;
  config.default_jumpstart_packets = 256;
  assert(!qlinq_connect(context, &config));
  assert(qlinq_context_last_status(context) == QLINQ_STATUS_INVALID);
  config.default_jumpstart_packets = 0;
  config.congestion_control = QLINQ_CC_DEFAULT;
  config.pacing = (qlinq_pacing_t)-1;
  assert(!qlinq_connect(context, &config));
  config.pacing = (qlinq_pacing_t)(QLINQ_PACING_ENABLED + 1);
  assert(!qlinq_connect(context, &config));
  assert(qlinq_context_last_status(context) == QLINQ_STATUS_INVALID);
  config.initial_cwnd_packets = 0;
  config.congestion_control = QLINQ_CC_DEFAULT;
  config.pacing = QLINQ_PACING_DEFAULT;
  for (int policy = 0; policy <= QLINQ_TLS_GROUP_REQUIRE_HYBRID; policy++) {
    config.security.tls_group_policy = policy;
    qlinq_endpoint_t *endpoint = qlinq_connect(context, &config);
    if (!endpoint) {
      assert(policy == QLINQ_TLS_GROUP_REQUIRE_HYBRID);
      continue;
    }
    assert(endpoint->transport->tls_group_policy ==
           config.security.tls_group_policy);
    config.security.tls_group_policy = QLINQ_TLS_GROUP_CLASSICAL;
    assert(endpoint->transport->tls_group_policy ==
           (qlinq_tls_group_policy_t)policy);
    qlinq_endpoint_close(endpoint);
  }
  config.security.tls_group_policy = -1;
  assert(!qlinq_connect(context, &config));
  assert(qlinq_context_last_status(context) == QLINQ_STATUS_INVALID);
  config.security.tls_group_policy = 3;
  assert(!qlinq_connect(context, &config));
  assert(qlinq_context_last_status(context) == QLINQ_STATUS_INVALID);
  /* Verify the public peer snapshot carries the actual verified TLS result. */
  qlinq_endpoint_config_t server_config = {
      .bind_addresses = {"127.0.0.1"},
      .bind_address_count = 1,
      .port = 20203,
      .security = {.certificate_file = "t/assets/verified.crt",
                   .private_key_file = "t/assets/verified.key",
                   .trust_store_file = "t/assets/verified.crt",
                   .verify_peer = true,
                   .tls_group_policy = QLINQ_TLS_GROUP_PREFER_HYBRID}};
  qlinq_endpoint_t *server = qlinq_listen(context, &server_config);
  assert(server);
  qlinq_endpoint_config_t client_config = server_config;
  client_config.remote_addresses[0] = "127.0.0.1";
  client_config.remote_address_count = 1;
  qlinq_endpoint_t *client = qlinq_connect(context, &client_config);
  assert(client);
  for (int i = 0; i < 3000; i++) {
    assert(qlinq_service(context, 1) == QLINQ_STATUS_OK);
    qlinq_event_t event;
    while (qlinq_next_event(context, &event))
      qlinq_event_release(&event);
    if (server->peers && client->peers && server->peers->ready &&
        client->peers->ready)
      break;
  }
  assert(server->peers && client->peers);
  qlinq_peer_info_t server_info, client_info;
  assert(qlinq_endpoint_get_peer(server, server->peers->id, &server_info));
  assert(qlinq_endpoint_get_peer(client, client->peers->id, &client_info));
  assert(server_info.ready && client_info.ready);
  assert(server_info.tls.complete && client_info.tls.complete);
  assert(server_info.tls.policy_accepted && client_info.tls.policy_accepted);
  assert(server_info.tls.verify_peer && client_info.tls.verify_peer);
  assert(server_info.tls.selected_group == client_info.tls.selected_group);
  assert(server_info.tls.selected_group ==
         (server->transport->tls_hybrid_available ? PTLS_GROUP_X25519MLKEM768
                                                  : PTLS_GROUP_SECP256R1));

  /* test synchronous interface filter callback on hot-added interfaces */
  iface_filter_state_t filter_state = {.context = context, .valid = true};
  qlinq_endpoint_config_t filter_config = client_config;
  filter_config.port = 20204;
  filter_config.interface_callback = filter_interface;
  filter_config.interface_user_data = &filter_state;
  qlinq_endpoint_t *filtered = qlinq_connect(context, &filter_config);
  assert(filtered);
  filter_state.expected_endpoint = filtered;

  struct sockaddr_storage cand = {0};
  struct sockaddr_in *sin = (struct sockaddr_in *)&cand;
  sin->sin_family = AF_INET;
  assert(inet_pton(AF_INET, "127.0.0.2", &sin->sin_addr) == 1);

  /* reject candidate interface first */
  filter_state.allow = false;
  assert(
      transport_drive_interface(filtered->transport, true, &cand, 42, "tun0"));
  assert(filter_state.valid && filter_state.calls == 1);
  assert(filter_state.last_index == 42 &&
         strcmp(filter_state.last_name, "tun0") == 0 &&
         strcmp(filter_state.last_address, "127.0.0.2") == 0 &&
         filter_state.last_family == AF_INET);
  assert(filtered->transport->socket_count == 1);

  /* accept candidate interface (even virtual tun0 that default filter hides) */
  filter_state.allow = true;
  assert(
      transport_drive_interface(filtered->transport, true, &cand, 42, "tun0"));
  assert(filter_state.valid && filter_state.calls == 2);
  assert(filtered->transport->socket_count == 2);
  qlinq_path_stats_t path_stats = {0};
  assert(qlinq_endpoint_get_path_stats(filtered, 1, &path_stats));
  assert(strcmp(path_stats.interface_name, "tun0") == 0);
  assert(strcmp(path_stats.local_address, "127.0.0.2") == 0);
  qlinq_endpoint_close(filtered);

  qlinq_context_destroy(context);
  puts("===QLINQ POLICY OK===");
  return 0;
}
