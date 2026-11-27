#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include "amt_native_fixture.h"
#include "amtq_posix.h"
#include "nanoamt/openssl.h"
#include "nanoamt/posix.h"
#include "transport_amt_host.h"
#include "transport_poll_host.h"
static int64_t now_ms(void) {
  struct timespec ts;
  assert(!clock_gettime(CLOCK_MONOTONIC, &ts));
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static void join(nanoamt_posix *gateway) {
  for (unsigned n = 0; n < 1000; ++n) {
    assert(nanoamt_posix_send(gateway, now_ms()) >= 0);
    fixture_pump();
    nanoamt_packet packet;
    int rc;
    while ((rc = nanoamt_posix_receive(gateway, now_ms(), &packet)) !=
           NANOAMT_AGAIN)
      assert(rc >= 0);
    if (nanoamt_posix_is_joined(gateway)) {
      fixture_pump();
      return;
    }
    usleep(1000);
  }
  assert(!"AMT handshake timed out");
}
static void check_packet(nanoamt_posix *gateway, const uint8_t *ip, size_t size,
                         const uint8_t *payload, size_t payload_size) {
  assert(send(fixture_pair[1], ip, size, 0) == (ssize_t)size);
  bool received = false;
  for (unsigned n = 0; n < 1000 && !received; ++n) {
    fixture_pump();
    nanoamt_packet packet;
    int rc = nanoamt_posix_receive(gateway, now_ms(), &packet);
    assert(rc >= 0);
    if (rc == NANOAMT_PACKET) {
      assert(packet.ip_size == size && !memcmp(packet.ip_data, ip, size));
      assert(packet.size == payload_size &&
             !memcmp(packet.data, payload, payload_size));
      received = true;
    }
  }
  assert(received);
}
static void check_shared_membership(void) {
  transport_config_t config = {.enable_flexicast = true,
                               .flexicast_receiver_backend =
                                   TRANSPORT_GROUP_AMT,
                               .flexicast_relay_address = "127.0.0.1",
                               .flexicast_relay_port = 10168};
  transport_poll_host_t host = {.amt = transport_amt_host_new(&config)};
  assert(host.amt);
  transport_t t = {.drive_host = {.context = &host},
                   .drive_now_ns = (uint64_t)now_ms() * 1000000};
  transport_flexicast_flow_t first = {.ip_version = 4,
                                      .udp_port = 10002,
                                      .source_ip = {127, 0, 0, 1},
                                      .group_ip = {232, 42, 42, 1}};
  transport_flexicast_flow_t second = first;
  assert(transport_amt_host_join(&t, &first));
  assert(transport_amt_host_join(&t, &second));
  assert(transport_amt_host_memberships(&t) == 1);
  struct pollfd fds[TRANSPORT_MAX_POLL_FDS];
  assert(transport_amt_host_poll(&t, fds, TRANSPORT_MAX_POLL_FDS) == 1);
  assert(!transport_amt_host_ready(&t, &first));
  transport_amt_host_leave(&t, &first);
  assert(transport_amt_host_memberships(&t) == 1);
  transport_amt_host_leave(&t, &second);
  assert(!transport_amt_host_memberships(&t));
  assert(!transport_amt_host_poll(&t, fds, TRANSPORT_MAX_POLL_FDS));
  transport_amt_host_free(host.amt);
}
typedef struct {
  bool received;
  unsigned count;
  size_t size;
  uint8_t payload[4096];
} amtq_rx_t;
static void on_amtq_packet(void *ctx, uint64_t cid, nanoamt_packet *p) {
  (void)cid;
  amtq_rx_t *rx = ctx;
  assert(p->size <= sizeof(rx->payload));
  memcpy(rx->payload, p->data, p->size);
  rx->size = p->size;
  rx->received = true;
  rx->count++;
}
static void join_amtq(amtq_posix *client) {
  for (unsigned n = 0; n < 1000; ++n) {
    assert(amtq_posix_send(client, now_ms()) >= 0);
    fixture_pump();
    while (amtq_posix_receive(client, now_ms()) == NANOAMTQ_PACKET) {
    }
    assert(!amtq_posix_error(client));
    if (amtq_posix_is_ready(client) &&
        amtq_posix_memberships_submitted(client)) {
      fixture_pump();
      return;
    }
    usleep(1000);
  }
  assert(!"AMTQ handshake timed out");
}
static void check_amtq_packet(amtq_posix *client, amtq_rx_t *rx,
                              const uint8_t *ip, size_t size,
                              const uint8_t *payload, size_t payload_size) {
  rx->received = false;
  assert(send(fixture_pair[1], ip, size, 0) == (ssize_t)size);
  for (unsigned n = 0; n < 1000 && !rx->received; ++n) {
    fixture_pump();
    while (amtq_posix_receive(client, now_ms()) == NANOAMTQ_PACKET) {
    }
    assert(amtq_posix_send(client, now_ms()) >= 0);
    if (!rx->received)
      usleep(1000);
  }
  assert(rx->received && rx->size == payload_size &&
         !memcmp(rx->payload, payload, payload_size));
}
static void check_amtq_and_dual_stack(const uint8_t *opaque, size_t opaque_len,
                                      const uint8_t *ip6, size_t ip6_len) {
  assert(transport_amt_host_mtu_usable(4, 6, 1280, 1358));
  assert(!transport_amt_host_mtu_usable(4, 6, 1280, 1357));
  assert(transport_amt_host_mtu_usable(6, 6, 1280, 1378));
  assert(!transport_amt_host_mtu_usable(6, 6, 1280, 1377));
  assert(!transport_amt_host_mtu_usable(6, 6, 1280, 1280));
  assert(transport_amt_host_mtu_usable(6, 4, 1280, 1280));
  assert(transport_amt_host_mtu_usable(6, 6, 1280, 0));

  /* validation: AMTQ requires cert/key and distinct port in dual-stack mode */
  qlinq_relay_config_t bad = {.upstream_interface = "lo", .amtq_port = 10169};
  assert(!qlinq_relay_open(&bad) && errno == EINVAL);
  bad = (qlinq_relay_config_t){.upstream_interface = "lo",
                               .port = 10168,
                               .amtq_port = 10168,
                               .amtq_cert_file = "t/assets/verified.crt",
                               .amtq_key_file = "t/assets/verified.key"};
  assert(!qlinq_relay_open(&bad) && errno == EINVAL);
  bad = (qlinq_relay_config_t){.upstream_interface = "lo",
                               .disable_classic_amt = true,
                               .linux_gateway_family = 4,
                               .amtq_cert_file = "t/assets/verified.crt",
                               .amtq_key_file = "t/assets/verified.key"};
  assert(!qlinq_relay_open(&bad) && errno == EINVAL);
  bad =
      (qlinq_relay_config_t){.upstream_interface = "lo", .max_sources = 65536};
  assert(!qlinq_relay_open(&bad) && errno == EINVAL);
  qlinq_relay_config_t max_src_cfg = {.bind_address = "127.0.0.1",
                                      .port = 10168,
                                      .amtq_port = 10169,
                                      .amtq_cert_file = "t/assets/verified.crt",
                                      .amtq_key_file = "t/assets/verified.key",
                                      .upstream_interface = "lo",
                                      .max_sources = 65535};
  qlinq_relay_t *max_src_relay = qlinq_relay_open(&max_src_cfg);
  assert(max_src_relay);
  qlinq_relay_close(max_src_relay);

  /* dual-stack: classic AMT + AMTQ datagram + AMTQ reliable block on 1 group */
  fixture_groups = 0;
  fixture_open_dual(false, "127.0.0.1", NULL);
  nanoamt_config classic_cfg = {
      .discovery = {.ip = {127, 0, 0, 1}, .ip_version = 4, .port = 10168},
      .source = {127, 0, 0, 1},
      .group = {232, 42, 42, 1},
      .port = 10002,
      .ip_version = 4,
      .random_bytes = nanoamt_openssl_random};
  nanoamt_posix *classic = nanoamt_posix_open(&classic_cfg, now_ms());
  assert(classic);
  join(classic);

  amtq_rx_t dgram_rx = {0}, rel_rx = {0};
  amtq_posix_config dgram_cfg = {
      .listen = {.ip_version = 4},
      .peer = {.ip = {127, 0, 0, 1}, .ip_version = 4, .port = 10169},
      .server_name = "localhost",
      .ca_file = "t/assets/verified.crt",
      .session = {.gateway = {.ip_version = 4},
                  .packet = on_amtq_packet,
                  .packet_context = &dgram_rx}};
  amtq_posix *dgram_client = amtq_posix_open(&dgram_cfg, now_ms());
  assert(dgram_client);
  nanoamtq_membership m4 = {
      .source = {127, 0, 0, 1}, .group = {232, 42, 42, 1}, .port = 10002};
  assert(!amtq_posix_set_memberships(dgram_client, &m4, 1));
  join_amtq(dgram_client);

  amtq_posix_config rel_cfg = dgram_cfg;
  rel_cfg.session.gateway.data_modes = 3;
  rel_cfg.session.gateway.preferred_mode = 1;
  rel_cfg.session.packet_context = &rel_rx;
  amtq_posix *rel_client = amtq_posix_open(&rel_cfg, now_ms());
  assert(rel_client);
  assert(!amtq_posix_set_memberships(rel_client, &m4, 1));
  join_amtq(rel_client);
  assert(fixture_groups == 1);

  uint8_t ip[3028];
  size_t size = fixture_ipv4(ip, opaque, 64, m4.source, m4.group, 10002);
  check_amtq_packet(dgram_client, &dgram_rx, ip, size, opaque, 64);
  for (unsigned n = 0; n < 500 && !rel_rx.received; ++n) {
    fixture_pump();
    while (amtq_posix_receive(rel_client, now_ms()) == NANOAMTQ_PACKET) {
    }
    assert(amtq_posix_send(rel_client, now_ms()) >= 0);
    if (!rel_rx.received)
      usleep(1000);
  }
  assert(rel_rx.received && rel_rx.size == 64 &&
         !memcmp(rel_rx.payload, opaque, 64));
  nanoamt_packet classic_pkt;
  assert(nanoamt_posix_receive(classic, now_ms(), &classic_pkt) ==
         NANOAMT_PACKET);

  /* fragmented 3000-byte payload over AMTQ datagram + single reliable block */
  size = fixture_ipv4(ip, opaque, opaque_len, m4.source, m4.group, 10002);
  rel_rx.received = false;
  check_amtq_packet(dgram_client, &dgram_rx, ip, size, opaque, opaque_len);
  for (unsigned n = 0; n < 500 && !rel_rx.received; ++n) {
    fixture_pump();
    while (amtq_posix_receive(rel_client, now_ms()) == NANOAMTQ_PACKET) {
    }
    assert(amtq_posix_send(rel_client, now_ms()) >= 0);
    if (!rel_rx.received)
      usleep(1000);
  }
  assert(rel_rx.received && rel_rx.size == opaque_len &&
         !memcmp(rel_rx.payload, opaque, opaque_len));
  qlinq_relay_stats_t stats;
  qlinq_relay_get_stats(fixture_relay, &stats);
  assert(stats.clients == 1 && stats.amtq_clients == 2 &&
         stats.amtq_datagrams >= 3 && stats.amtq_reliable_blocks == 2);

  /* burst coalescing + send budget with 1 active peer: 8 queued packets deliver
   * cleanly and coalesce into fewer reliable blocks than packets */
  dgram_rx.count = 0;
  rel_rx.count = 0;
  size = fixture_ipv4(ip, opaque, 128, m4.source, m4.group, 10002);
  for (unsigned b = 0; b < 8; ++b)
    assert(send(fixture_pair[1], ip, size, 0) == (ssize_t)size);
  for (unsigned n = 0; n < 500 && (dgram_rx.count < 8 || rel_rx.count < 8);
       ++n) {
    fixture_pump();
    while (amtq_posix_receive(dgram_client, now_ms()) == NANOAMTQ_PACKET) {
    }
    while (amtq_posix_receive(rel_client, now_ms()) == NANOAMTQ_PACKET) {
    }
    assert(amtq_posix_send(dgram_client, now_ms()) >= 0);
    assert(amtq_posix_send(rel_client, now_ms()) >= 0);
    if (dgram_rx.count < 8 || rel_rx.count < 8)
      usleep(1000);
  }
  qlinq_relay_get_stats(fixture_relay, &stats);
  assert(dgram_rx.count == 8 && rel_rx.count == 8 && !stats.amtq_input_drops &&
         stats.amtq_reliable_blocks <= 4);

  /* withdrawing one group with an unacked reliable block preserves sibling
   * groups on the same AMTQ session */
  nanoamtq_membership m4_pair[2] = {m4, m4};
  m4_pair[1].group[3] = 2;
  assert(!amtq_posix_set_memberships(rel_client, m4_pair, 2));
  for (unsigned n = 0; n < 200 && fixture_groups < 2; ++n) {
    assert(amtq_posix_send(rel_client, now_ms()) >= 0);
    fixture_pump();
    while (amtq_posix_receive(rel_client, now_ms()) == NANOAMTQ_PACKET) {
    }
    usleep(1000);
  }
  assert(fixture_groups == 2);
  size =
      fixture_ipv4(ip, opaque, 96, m4_pair[0].source, m4_pair[0].group, 10002);
  assert(send(fixture_pair[1], ip, size, 0) == (ssize_t)size);
  fixture_pump();
  /* withdraw group 0 before rel_client ACKs the in-flight reliable stream */
  assert(!amtq_posix_set_memberships(rel_client, &m4_pair[1], 1));
  for (unsigned n = 0; n < 200; ++n) {
    assert(amtq_posix_send(rel_client, now_ms()) >= 0);
    fixture_pump();
    while (amtq_posix_receive(rel_client, now_ms()) == NANOAMTQ_PACKET) {
    }
    if (amtq_posix_memberships_submitted(rel_client))
      break;
    usleep(1000);
  }
  fixture_pump();
  rel_rx.received = false;
  size =
      fixture_ipv4(ip, opaque, 80, m4_pair[1].source, m4_pair[1].group, 10002);
  check_amtq_packet(rel_client, &rel_rx, ip, size, opaque, 80);
  qlinq_relay_get_stats(fixture_relay, &stats);
  assert(!stats.amtq_session_errors && stats.amtq_clients == 2);

  amtq_posix_close(rel_client);
  amtq_posix_close(dgram_client);
  nanoamt_posix_close(classic);
  fixture_close();

  /* AMTQ-only mTLS enforcement + IPv6 AMTQ */
  fixture_open_amtq_only(false, "::1", "t/assets/verified-v6.crt");
  amtq_rx_t v6_rx = {0};
  amtq_posix_config unauth_cfg = {
      .listen = {.ip_version = 6},
      .peer = {.ip = {[15] = 1}, .ip_version = 6, .port = 10169},
      .server_name = "::1",
      .ca_file = "t/assets/verified-v6.crt",
      .session = {.gateway = {.ip_version = 6},
                  .packet = on_amtq_packet,
                  .packet_context = &v6_rx}};
  amtq_posix *unauth = amtq_posix_open(&unauth_cfg, now_ms());
  assert(unauth);
  nanoamtq_membership m6 = {.port = 10002};
  m6.source[0] = 0x20;
  m6.source[1] = 1;
  m6.source[2] = 0x0d;
  m6.source[3] = 0xb8;
  m6.source[15] = 1;
  m6.group[0] = 0xff;
  m6.group[1] = 0x3e;
  m6.group[15] = 1;
  assert(!amtq_posix_set_memberships(unauth, &m6, 1));
  for (unsigned n = 0; n < 200 && !amtq_posix_error(unauth); ++n) {
    (void)amtq_posix_send(unauth, now_ms());
    fixture_pump();
    while (amtq_posix_receive(unauth, now_ms()) == NANOAMTQ_PACKET) {
    }
    usleep(1000);
  }
  assert(amtq_posix_error(unauth) != 0);
  amtq_posix_close(unauth);

  amtq_posix_config mtls_cfg = unauth_cfg;
  mtls_cfg.certificate = "t/assets/verified-v6.crt";
  mtls_cfg.private_key = "t/assets/verified-v6.key";
  amtq_posix *mtls_client = amtq_posix_open(&mtls_cfg, now_ms());
  assert(mtls_client);
  assert(!amtq_posix_set_memberships(mtls_client, &m6, 1));
  join_amtq(mtls_client);
  check_amtq_packet(mtls_client, &v6_rx, ip6, ip6_len, opaque, 64);
  amtq_posix_close(mtls_client);
  fixture_close();
}
int main(void) {
  check_shared_membership();
  qlinq_relay_config_t bad = {.upstream_interface = "lo", .path_mtu = 575};
  assert(!qlinq_relay_open(&bad) && errno == EINVAL);
  bad.path_mtu = 0;
  bad.bind_address = "not-an-ip";
  assert(!qlinq_relay_open(&bad) && errno == EINVAL);
  assert(qlinq_relay_service(NULL, 0) == -1 && errno == EINVAL);
  fixture_open(false);
  nanoamt_config config = {
      .discovery = {.ip = {127, 0, 0, 1}, .ip_version = 4, .port = 10168},
      .source = {127, 0, 0, 1},
      .group = {232, 42, 42, 1},
      .port = 10002,
      .ip_version = 4,
      .random_bytes = nanoamt_openssl_random};
  nanoamt_posix *gateway = nanoamt_posix_open(&config, now_ms());
  assert(gateway);
  join(gateway);
  assert(fixture_authorizations && fixture_groups == 1);
  /* these bytes deliberately contain no qlinq framing or keys; the relay
   * must forward an opaque payload and preserve the complete inner IP packet */
  uint8_t opaque[3000], ip[3028];
  for (size_t i = 0; i < sizeof(opaque); ++i)
    opaque[i] = (uint8_t)(i * 37U);
  size_t size =
      fixture_ipv4(ip, opaque, 64, config.source, config.group, config.port);
  check_packet(gateway, ip, size, opaque, 64);
  size = fixture_ipv4(ip, opaque, sizeof(opaque), config.source, config.group,
                      config.port);
  check_packet(gateway, ip, size, opaque,
               sizeof(opaque)); /* outer PMTU fragmentation/reassembly */
  qlinq_relay_stats_t stats;
  qlinq_relay_get_stats(fixture_relay, &stats);
  assert(stats.clients == 1 && stats.packets_sent >= 2 && !stats.send_errors);
  /* wrong source/group cannot enter an established subscriber's tunnel */
  ip[16] = 233;
  assert(send(fixture_pair[1], ip, size, 0) == (ssize_t)size);
  fixture_pump();
  nanoamt_packet packet;
  assert(nanoamt_posix_receive(gateway, now_ms(), &packet) == NANOAMT_AGAIN);
  assert(!nanoamt_posix_leave(gateway, now_ms()));
  assert(nanoamt_posix_send(gateway, now_ms()) >= 0);
  fixture_pump();
  nanoamt_posix_close(gateway);
  fixture_close();
  /* IPv6 multicast inside an IPv6 AMT tunnel, including UDP checksum */
  fixture_open_address(false, "::1");
  memset(&config, 0, sizeof(config));
  config.discovery.ip_version = 6;
  config.discovery.ip[15] = 1;
  config.discovery.port = 10168;
  config.ip_version = 6;
  config.port = 10002;
  config.source[0] = 0x20;
  config.source[1] = 1;
  config.source[2] = 0x0d;
  config.source[3] = 0xb8;
  config.source[15] = 1;
  config.group[0] = 0xff;
  config.group[1] = 0x3e;
  config.group[15] = 1;
  config.random_bytes = nanoamt_openssl_random;
  gateway = nanoamt_posix_open(&config, now_ms());
  assert(gateway);
  join(gateway);
  uint8_t ip6[112] = {0x60};
  ip6[5] = 72;
  ip6[6] = 17;
  ip6[7] = 63;
  memcpy(ip6 + 8, config.source, 16);
  memcpy(ip6 + 24, config.group, 16);
  ip6[40] = 0x27;
  ip6[41] = 0x11;
  ip6[42] = 0x27;
  ip6[43] = 0x12;
  ip6[45] = 72;
  memcpy(ip6 + 48, opaque, 64);
  uint32_t sum = 72 + 17;
  for (size_t i = 8; i < sizeof(ip6); i += 2)
    sum += ((uint32_t)ip6[i] << 8) | ip6[i + 1];
  while (sum >> 16)
    sum = (sum & 65535) + (sum >> 16);
  uint16_t checksum = (uint16_t)~sum;
  if (!checksum)
    checksum = 65535;
  ip6[46] = (uint8_t)(checksum >> 8);
  ip6[47] = (uint8_t)checksum;
  check_packet(gateway, ip6, sizeof(ip6), opaque, 64);
  nanoamt_posix_close(gateway);
  fixture_close();
  check_amtq_and_dual_stack(opaque, sizeof(opaque), ip6, sizeof(ip6));
  puts("===AMT TRANSPARENT RELAY OK===");
  return 0;
}
