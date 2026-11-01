#include "tun_coalesce.h"
#include <assert.h>
#include <stdio.h>
#include "tun_tcp_fixture.h"
static uint8_t packets[64][2048], scratch[65536], segment[2048];
static tun_packet_view_t views[64];
static void setup(unsigned version, size_t payload, bool options) {
  for (unsigned i = 0; i < 64; i++) {
    size_t n =
        fixture_packet(packets[i], version, payload, 0xfffffff0U + i * payload,
                       (65530U + i) & 65535U, 0x10, options);
    assert(tun_packet_parse(packets[i], n, 2048, views + i));
  }
}
static void roundtrip(unsigned version, size_t payload, bool options) {
  setup(version, payload, options);
  size_t ip = version == 4 ? 20 : 40;
  /* a short PSH/FIN final segment closes the aggregate */
  views[7].size = fixture_packet(packets[7], version, payload / 2,
                                 0xfffffff0U + 7 * payload, 1, 0x19, options);
  assert(tun_coalesce_candidate(&views[0]));
  assert(!tun_coalesce_candidate(&views[7]));
  tun_coalesce_output_t o;
  assert(tun_coalesce(views, 8, scratch, sizeof(scratch), &o) && o.count == 8);
  assert(o.offload.gso_size == payload && o.packet.data == scratch);
  tun_packet_config_t c = {.mtu = 2048, .max_packet_size = 2048};
  tun_packet_input_t in = {.data = o.packet.data,
                           .size = o.packet.size,
                           .origin = TUN_PACKET_FROM_DEVICE};
  tun_segment_t plan;
  assert(tun_segment_prepare(&plan, &c, &in, &o.offload));
  for (unsigned i = 0; i < 8; i++) {
    tun_packet_output_t out;
    assert(tun_segment_next(&plan, segment, sizeof(segment), &out).status ==
           TUN_PACKET_OK);
    assert(out.packet.size == views[i].size);
    assert(!memcmp(segment, views[i].data, views[i].size));
  }
  assert(!plan.pending);
  /* independent checksums are reconstructed exactly */
  (void)ip;
}
int main(void) {
  for (unsigned v = 4; v <= 6; v += 2) {
    roundtrip(v, 101, false);
    roundtrip(v, 1300, true);
    setup(v, 1300, false);
    tun_coalesce_output_t o;
    assert(tun_coalesce(views, 64, scratch, 65535, &o) && o.count > 1 &&
           o.count < 64);
    assert(o.packet.size <= 65535);
    assert(tun_coalesce(views, 64, scratch, views[0].size + 1299, &o) &&
           o.count == 1);
    assert(o.packet.data == views[0].data);
    assert(tun_coalesce(views, 64, NULL, 65535, &o) && o.count == 1);
    for (unsigned mutation = 0; mutation < 15; mutation++) {
      setup(v, 101, false);
      size_t ip = v == 4 ? 20 : 40;
      switch (mutation) {
      case 0:
        packets[1][ip]++;
        break; /* different port */
      case 1:
        packets[1][ip + 4]++;
        break; /* reordered sequence */
      case 2:
        packets[1][ip + 8]++;
        break; /* ACK */
      case 3:
        packets[1][ip + 14]++;
        break; /* window */
      case 4:
        packets[1][ip + 13] |= 0x80;
        break; /* CWR */
      case 5:
        packets[1][ip + 13] |= 0x40;
        break; /* ECE */
      case 6:
        packets[1][ip + 13] |= 0x20;
        break; /* URG */
      case 7:
        packets[1][ip + 13] |= 2;
        break; /* SYN */
      case 8:
        packets[1][ip + 13] |= 4;
        break; /* RST */
      case 9:
        packets[1][ip + 12] |= 1;
        break; /* reserved */
      case 10:
        packets[1][v == 4 ? 15 : 23]++;
        break; /* address */
      case 11:
        packets[1][v == 4 ? 8 : 7]--;
        break; /* TTL */
      case 12:
        packets[1][1]++;
        break; /* TOS/flow */
      case 13:
        packets[1][ip + 18]++;
        break; /* urgent pointer */
      case 14:
        views[1].size--;
        break; /* truncated */
      }
      if (mutation != 14)
        fixture_checksum(packets[1], views[1].size);
      assert(tun_coalesce(views, 3, scratch, sizeof(scratch), &o) &&
             o.count == 1);
    }
    setup(v, 101, false);
    packets[1][views[1].size - 1] ^= 1;
    assert(tun_coalesce(views, 3, scratch, sizeof(scratch), &o) &&
           o.count == 1);
    setup(v, 101, false);
    packets[1][v == 4 ? 10 : 56] ^= 1;
    assert(tun_coalesce(views, 3, scratch, sizeof(scratch), &o) &&
           o.count == 1);
    setup(v, 101, true);
    packets[1][(v == 4 ? 20 : 40) + 24]++;
    fixture_checksum(packets[1], views[1].size);
    assert(tun_coalesce(views, 3, scratch, sizeof(scratch), &o) &&
           o.count == 1);
    setup(v, 101, true);
    for (unsigned i = 0; i < 3; i++) {
      packets[i][(v == 4 ? 20 : 40) + 22] =
          30; /* identical unknown options must not merge */
      fixture_checksum(packets[i], views[i].size);
    }
    assert(tun_coalesce(views, 3, scratch, sizeof(scratch), &o) &&
           o.count == 1);
    setup(v, 101, false);
    assert(tun_coalesce_pair(views, views + 1));
    assert(!tun_coalesce_pair(views + 1, views));
    /* duplicate or gap: preserve compatible prefix without skipping bad input
     */
    views[2] = views[1];
    assert(tun_coalesce(views, 4, scratch, sizeof(scratch), &o) &&
           o.count == 2);
  }
  assert(!tun_coalesce(NULL, 0, scratch, sizeof(scratch), NULL));
  assert(!tun_coalesce_pair(NULL, views));
  puts("===TUN COALESCE OK===");
}
