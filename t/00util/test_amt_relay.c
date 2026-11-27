#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include "nanoamt/openssl.h"
#include "nanoamt/posix.h"
#include "amt_native_fixture.h"
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
  puts("===AMT TRANSPARENT RELAY OK===");
  return 0;
}
