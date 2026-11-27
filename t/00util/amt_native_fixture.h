/* replace privileged packet capture only; exercise real AMT UDP/wire cores */
#ifndef QLINQ_AMT_NATIVE_FIXTURE_H
#define QLINQ_AMT_NATIVE_FIXTURE_H
#include "nanoamt/native.h"
#include "qlinq_relay.h"
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
static int fixture_pair[2] = {-1, -1};
static int fixture_capture = -1;
static uint8_t fixture_packet[65535];
static size_t fixture_groups;
static unsigned fixture_authorizations;
static unsigned fixture_denied;
static qlinq_relay_t *fixture_relay;
static size_t fixture_ipv4(uint8_t *out, const uint8_t *data, size_t size,
                           const uint8_t source[4], const uint8_t group[4],
                           uint16_t port) {
  assert(size <= 65507);
  memset(out, 0, 28);
  out[0] = 0x45;
  out[2] = (uint8_t)((size + 28) >> 8);
  out[3] = (uint8_t)(size + 28);
  out[8] = 63;
  out[9] = 17;
  memcpy(out + 12, source, 4);
  memcpy(out + 16, group, 4);
  uint32_t sum = 0;
  for (size_t i = 0; i < 20; i += 2)
    sum += ((unsigned)out[i] << 8) | out[i + 1];
  while (sum >> 16)
    sum = (sum & 65535) + (sum >> 16);
  out[10] = (uint8_t)(~sum >> 8);
  out[11] = (uint8_t)~sum;
  out[20] = 0x27;
  out[21] = 0x11;
  out[22] = (uint8_t)(port >> 8);
  out[23] = (uint8_t)port;
  out[24] = (uint8_t)((size + 8) >> 8);
  out[25] = (uint8_t)(size + 8);
  memcpy(out + 28, data, size);
  return size + 28;
}
nanoamt_native *
__wrap_nanoamt_native_open(const nanoamt_native_config *config) {
  assert(config->interface_index);
  assert(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, fixture_pair) == 0);
  return (nanoamt_native *)fixture_pair;
}
void __wrap_nanoamt_native_close(nanoamt_native *native) {
  if (!native)
    return;
  close(fixture_pair[0]);
  close(fixture_pair[1]);
  fixture_pair[0] = fixture_pair[1] = -1;
}
int __wrap_nanoamt_native_fd(const nanoamt_native *native) {
  (void)native;
  return fixture_pair[0];
}
int __wrap_nanoamt_native_reconcile(nanoamt_native *native,
                                    const nanoamt_memberships *aggregate) {
  (void)native;
  fixture_groups = nanoamt_memberships_count(aggregate);
  return 0;
}
int __wrap_nanoamt_native_authorize(void *context, const nanoamt_endpoint *peer,
                                    const nanoamt_memberships *requested,
                                    const nanoamt_memberships *aggregate) {
  (void)context;
  (void)peer;
  (void)requested;
  fixture_authorizations++;
  if (fixture_denied)
    return -1;
  fixture_groups = nanoamt_memberships_count(aggregate);
  return 0;
}
int __wrap_nanoamt_native_receive(nanoamt_native *native,
                                  nanoamt_native_packet *packet) {
  (void)native;
  ssize_t size =
      recv(fixture_pair[0], fixture_packet, sizeof(fixture_packet), 0);
  if (size < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK ? NANOAMT_AGAIN
                                                   : NANOAMT_ERROR_IO;
  *packet = (nanoamt_native_packet){
      .ip = fixture_packet, .size = (size_t)size, .interface_index = 1};
  return NANOAMT_PACKET;
}
void __wrap_nanoamt_native_mtu_feedback(void *context, int64_t now,
                                        const uint8_t *ip, size_t size,
                                        uint32_t mtu) {
  (void)context;
  (void)now;
  (void)ip;
  (void)size;
  (void)mtu;
}
void __wrap_nanoamt_native_get_stats(const nanoamt_native *native,
                                     nanoamt_native_stats *stats) {
  (void)native;
  *stats = (nanoamt_native_stats){.groups = fixture_groups};
}
static void fixture_open_config(bool capture, const qlinq_relay_config_t *c) {
  fixture_relay = qlinq_relay_open(c);
  assert(fixture_relay);
  if (!capture)
    return;
  fixture_capture = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
  assert(fixture_capture >= 0);
  int reuse = 1;
  assert(!setsockopt(fixture_capture, SOL_SOCKET, SO_REUSEADDR, &reuse,
                     sizeof(reuse)));
  struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(10002)};
  assert(!bind(fixture_capture, (struct sockaddr *)&local, sizeof(local)));
  struct ip_mreq_source join = {0};
  assert(inet_pton(AF_INET, "232.42.42.1", &join.imr_multiaddr) == 1);
  assert(inet_pton(AF_INET, "127.0.0.1", &join.imr_sourceaddr) == 1);
  join.imr_interface = join.imr_sourceaddr;
  assert(!setsockopt(fixture_capture, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP,
                     &join, sizeof(join)));
}
static void fixture_open_address(bool capture, const char *address) {
  qlinq_relay_config_t c = {
      .bind_address = address, .port = 10168, .upstream_interface = "lo"};
  fixture_open_config(capture, &c);
}
static void fixture_open_dual(bool capture, const char *address,
                              const char *ca_file) {
  bool v6 = strchr(address, ':') != NULL;
  qlinq_relay_config_t c = {.bind_address = address,
                            .port = 10168,
                            .amtq_port = 10169,
                            .amtq_cert_file = v6 ? "t/assets/verified-v6.crt"
                                                 : "t/assets/verified.crt",
                            .amtq_key_file = v6 ? "t/assets/verified-v6.key"
                                                : "t/assets/verified.key",
                            .amtq_ca_file = ca_file,
                            .upstream_interface = "lo"};
  fixture_open_config(capture, &c);
}
static void fixture_open_amtq_only(bool capture, const char *address,
                                   const char *ca_file) {
  bool v6 = strchr(address, ':') != NULL;
  qlinq_relay_config_t c = {.bind_address = address,
                            .disable_classic_amt = true,
                            .amtq_port = 10169,
                            .amtq_cert_file = v6 ? "t/assets/verified-v6.crt"
                                                 : "t/assets/verified.crt",
                            .amtq_key_file = v6 ? "t/assets/verified-v6.key"
                                                : "t/assets/verified.key",
                            .amtq_ca_file = ca_file,
                            .upstream_interface = "lo"};
  fixture_open_config(capture, &c);
}
static void fixture_open(bool capture) {
  fixture_open_address(capture, "127.0.0.1");
}
static void fixture_pump(void) {
  if (!fixture_relay)
    return;
  if (fixture_capture >= 0) {
    uint8_t payload[2048], ip[2076];
    ssize_t size;
    const uint8_t source[] = {127, 0, 0, 1}, group[] = {232, 42, 42, 1};
    while ((size = recv(fixture_capture, payload, sizeof(payload), 0)) >= 0) {
      size_t ip_size =
          fixture_ipv4(ip, payload, (size_t)size, source, group, 10002);
      assert(send(fixture_pair[1], ip, ip_size, 0) == (ssize_t)ip_size);
    }
  }
  assert(!qlinq_relay_service(fixture_relay, 0));
}
static void fixture_close(void) {
  qlinq_relay_close(fixture_relay);
  fixture_relay = NULL;
  if (fixture_capture >= 0)
    close(fixture_capture);
  fixture_capture = -1;
}
#endif
