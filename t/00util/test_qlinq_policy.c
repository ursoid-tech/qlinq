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
  config.congestion_control = (qlinq_congestion_control_t)-1;
  assert(!qlinq_connect(context, &config));
  assert(qlinq_context_last_status(context) == QLINQ_STATUS_INVALID);
  config.congestion_control = (qlinq_congestion_control_t)(QLINQ_CC_CUBIC + 1);
  assert(!qlinq_connect(context, &config));
  config.congestion_control = QLINQ_CC_DEFAULT;
  config.pacing = (qlinq_pacing_t)-1;
  assert(!qlinq_connect(context, &config));
  config.pacing = (qlinq_pacing_t)(QLINQ_PACING_ENABLED + 1);
  assert(!qlinq_connect(context, &config));
  assert(qlinq_context_last_status(context) == QLINQ_STATUS_INVALID);
  qlinq_context_destroy(context);
  puts("===QLINQ POLICY OK===");
  return 0;
}
