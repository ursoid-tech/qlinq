#include "tun_segment.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned word(const uint8_t *p) {
  return p[0] * 256U + p[1];
}
static uint32_t number(const uint8_t *p) {
  return (uint32_t)word(p) * 65536U + word(p + 2);
}
static void w16(uint8_t *p, unsigned n) {
  p[0] = n >> 8;
  p[1] = n;
}
static void w32(uint8_t *p, uint32_t n) {
  w16(p, n >> 16);
  w16(p + 2, n);
}
/* byte-wise independent checksum oracle */
static unsigned sum(const uint8_t *p, size_t n) {
  unsigned s = 0;
  for (size_t i = 0; i < n; i++)
    s += (unsigned)p[i] << (i % 2 ? 0 : 8);
  return s;
}
static unsigned fold(unsigned s) {
  while (s >> 16)
    s = (s & 65535U) + (s >> 16);
  return s;
}
static unsigned pseudo(const uint8_t *p, unsigned version, size_t length,
                       unsigned proto) {
  return sum(p + (version == 4 ? 12 : 8), version == 4 ? 8 : 32) + proto +
         length;
}

static void tcp_case(unsigned version, size_t ip_options, size_t tcp_options,
                     size_t payload, size_t mss, unsigned flags) {
  size_t ip = (version == 4 ? 20 : 40) + ip_options, tcp = 20 + tcp_options;
  size_t length = ip + tcp + payload;
  uint8_t *frame = calloc(length, 1), out[2048];
  assert(frame);
  if (version == 4) {
    frame[0] = 0x40 | (ip / 4);
    w16(frame + 2, length);
    w16(frame + 4, 65534);
    w16(frame + 6, 0x4000);
    frame[8] = 64;
    frame[9] = 6;
    frame[12] = 10;
    frame[15] = 1;
    frame[16] = 10;
    frame[19] = 2;
    w16(frame + 10, ~fold(sum(frame, ip)));
  } else {
    frame[0] = 0x60;
    w16(frame + 4, length - 40);
    frame[6] = ip_options ? 60 : 6;
    frame[7] = 64;
    frame[8] = 0xfd;
    frame[23] = 1;
    frame[24] = 0xfd;
    frame[39] = 2;
    if (ip_options) {
      frame[40] = 6;
      frame[41] = ip_options / 8 - 1;
    }
  }
  uint8_t *t = frame + ip;
  w16(t, 1234);
  w16(t + 2, 443);
  w32(t + 4, 0xfffffff0);
  t[12] = (tcp / 4) << 4;
  t[13] = flags;
  w16(t + 14, 32768);
  w16(t + 18, 5);
  w16(t + 16, fold(pseudo(frame, version, tcp + payload, 6)));
  for (size_t i = 0; i < payload; i++)
    t[tcp + i] = (uint8_t)(i * 7 + 3);
  tun_packet_config_t config = {.mtu = 1400, .max_packet_size = 2048};
  tun_packet_input_t input = {
      .data = frame, .size = length, .origin = TUN_PACKET_FROM_DEVICE};
  tun_offload_t meta = {
      .flags = TUN_CSUM_PARTIAL,
      .gso_type = (version == 4 ? TUN_GSO_TCP4 : TUN_GSO_TCP6) | TUN_GSO_ECN,
      .header_length = ip + tcp,
      .gso_size = mss,
      .checksum_start = ip,
      .checksum_offset = 16};
  tun_segment_t plan;
  assert(tun_segment_prepare(&plan, &config, &input, &meta));
  size_t expected_count = (payload + mss - 1) / mss;
  assert(tun_segment_remaining(&plan) == expected_count);
  tun_packet_output_t output;
  memset(&output, 0xa5, sizeof(output));
  uint8_t saved[sizeof(output)];
  memcpy(saved, &output, sizeof(output));
  assert(tun_segment_next(&plan, out, 1, &output).status ==
         TUN_PACKET_OUTPUT_FULL);
  assert(!memcmp(saved, &output, sizeof(output)) && !plan.offset);
  size_t received = 0, emitted = 0;
  while (tun_segment_remaining(&plan)) {
    tun_packet_result_t result =
        tun_segment_next(&plan, out, sizeof(out), &output);
    assert(result.status == TUN_PACKET_OK && result.count == 1);
    size_t n = output.packet.size, data = n - ip - tcp;
    assert(n <= 1400 && output.destination == TUN_PACKET_TO_TRANSPORT);
    assert(number(out + ip + 4) == (uint32_t)(0xfffffff0U + received));
    assert(!memcmp(out + ip + tcp, t + tcp + received, data));
    bool last = received + data == payload;
    assert((out[ip + 13] & 9U) == (last ? flags & 9U : 0));
    assert((out[ip + 13] & 0x80U) == (received ? 0 : flags & 0x80U));
    assert((out[ip + 13] & 0x40U) == (flags & 0x40U));
    if (flags & 0x20U) {
      assert((out[ip + 13] & 0x20U) == (received < 5 ? 0x20U : 0));
      assert(word(out + ip + 18) == (received < 5 ? 5 - received : 0));
    }
    if (version == 4) {
      assert(word(out + 2) == n && fold(sum(out, ip)) == 65535);
      assert(word(out + 4) == ((65534U + emitted) & 65535U));
    } else
      assert(word(out + 4) + 40 == n);
    assert(fold(pseudo(out, version, n - ip, 6) + sum(out + ip, n - ip)) ==
           65535);
    received += data;
    emitted++;
  }
  assert(received == payload && emitted == expected_count);
  assert(tun_segment_cancel(&plan) == 0);
  if (length <= 1400) {
    tun_offload_t ordinary = meta;
    ordinary.gso_type = TUN_GSO_NONE;
    ordinary.gso_size = 0;
    assert(tun_segment_prepare(&plan, &config, &input, &ordinary));
    assert(tun_segment_next(&plan, out, sizeof(out), &output).status ==
           TUN_PACKET_OK);
    assert(fold(pseudo(out, version, length - ip, 6) +
                sum(out + ip, length - ip)) == 65535);
  }
  /* segmentation derives headers from IP/TCP even if hint includes payload */
  meta.header_length = length <= 65535U ? length : 0;
  assert(tun_segment_prepare(&plan, &config, &input, &meta));
  assert(tun_segment_cancel(&plan) == expected_count);
  meta.checksum_offset = 15;
  assert(!tun_segment_prepare(&plan, &config, &input, &meta));
  assert(!tun_segment_remaining(&plan));
  meta.checksum_offset = 16;
  meta.gso_size = 0;
  assert(!tun_segment_prepare(&plan, &config, &input, &meta));
  meta.gso_size = mss;
  meta.flags = 4;
  assert(!tun_segment_prepare(&plan, &config, &input, &meta));
  meta.flags = 3;
  assert(!tun_segment_prepare(&plan, &config, &input, &meta));
  meta.flags = TUN_CSUM_PARTIAL;
  meta.gso_type = 3;
  assert(!tun_segment_prepare(&plan, &config, &input, &meta));
  meta.gso_type = version == 4 ? TUN_GSO_TCP6 : TUN_GSO_TCP4;
  assert(!tun_segment_prepare(&plan, &config, &input, &meta));
  meta.gso_type = version == 4 ? TUN_GSO_TCP4 : TUN_GSO_TCP6;
  meta.gso_size = 1400;
  assert(!tun_segment_prepare(&plan, &config, &input, &meta));
  meta.gso_size = mss;
  t[13] |= 2;
  assert(!tun_segment_prepare(&plan, &config, &input, &meta));
  t[13] &= ~2U;
  if (version == 4)
    w16(frame + 6, 0x2000);
  else
    frame[6] = 44;
  assert(!tun_segment_prepare(&plan, &config, &input, &meta));
  free(frame);
}

static void udp_case(unsigned version) {
  uint8_t frame[64] = {0}, out[64];
  size_t ip = version == 4 ? 20 : 40, length = ip + 10;
  frame[0] = version == 4 ? 0x45 : 0x60;
  if (version == 4) {
    w16(frame + 2, length);
    frame[9] = 17;
  } else {
    w16(frame + 4, 10);
    frame[6] = 17;
  }
  uint8_t *u = frame + ip;
  w16(u, 1234);
  w16(u + 2, 4321);
  w16(u + 4, 10);
  w16(u + 6, fold(pseudo(frame, version, 10, 17)));
  /* force a computed zero: UDP must transmit 0xffff instead of disabling CSUM
   */
  w16(u + 8, ~fold(sum(u, 8)));
  tun_packet_config_t config = {.mtu = 1400, .max_packet_size = 2048};
  tun_packet_input_t input = {
      .data = frame, .size = length, .origin = TUN_PACKET_FROM_DEVICE};
  tun_offload_t meta = {
      .flags = TUN_CSUM_PARTIAL, .checksum_start = ip, .checksum_offset = 6};
  tun_segment_t plan;
  tun_packet_output_t output;
  assert(tun_segment_prepare(&plan, &config, &input, &meta));
  assert(tun_segment_next(&plan, out, sizeof(out), &output).status ==
         TUN_PACKET_OK);
  assert(word(out + ip + 6) == 65535);
  assert(fold(pseudo(out, version, 10, 17) + sum(out + ip, 10)) == 65535);
  meta.flags = TUN_CSUM_VALID;
  assert(tun_segment_prepare(&plan, &config, &input, &meta));
  assert(tun_segment_next(&plan, out, sizeof(out), &output).status ==
         TUN_PACKET_OK);
  assert(!memcmp(frame, out, length));
  input.origin = TUN_PACKET_FROM_PEER;
  assert(!tun_segment_prepare(&plan, &config, &input, &meta));
}

static void generic_partial(void) {
  uint8_t frame[65] = {0x45, 0, 0, 65}, out[65];
  frame[9] = 253; /* generic CSUM is not restricted to TCP/UDP */
  for (unsigned i = 20; i < sizeof(frame); i++)
    frame[i] = (uint8_t)i;
  frame[27] = frame[28] = 0;
  tun_packet_config_t config = {.mtu = 1400, .max_packet_size = 2048};
  tun_packet_input_t input = {
      .data = frame, .size = sizeof(frame), .origin = TUN_PACKET_FROM_DEVICE};
  tun_offload_t meta = {
      .flags = TUN_CSUM_PARTIAL, .checksum_start = 20, .checksum_offset = 7};
  tun_segment_t plan;
  tun_packet_output_t output;
  assert(tun_segment_prepare(&plan, &config, &input, &meta));
  assert(tun_segment_next(&plan, out, sizeof(out), &output).status ==
         TUN_PACKET_OK);
  assert(fold(sum(out + 20, sizeof(out) - 20)) == 65535);
  for (unsigned i = 0; i < sizeof(frame); i++)
    if (i != 27 && i != 28)
      assert(out[i] == frame[i]);
  meta.checksum_offset = 44;
  assert(!tun_segment_prepare(&plan, &config, &input, &meta));
  meta.checksum_offset = 7;
  meta.checksum_start = 19;
  assert(!tun_segment_prepare(&plan, &config, &input, &meta));
}

int main(void) {
  tcp_case(4, 0, 0, 60001, 1360, 0xd9);
  tcp_case(6, 0, 12, 60003, 1328, 0xd9);
  tcp_case(6, 0, 0, 65476, 1340, 0x19); /* full 64-KiB aggregate */
  tcp_case(4, 12, 12, 21, 3, 0xf9);
  tcp_case(6, 8, 0, 21, 3, 0xf9);
  udp_case(4);
  udp_case(6);
  generic_partial();
  puts("===TUN SEGMENT OK===");
}
