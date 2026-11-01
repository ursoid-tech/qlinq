/* independent byte-wise checksum oracle and ordinary TCP record generator */
#ifndef TUN_TCP_FIXTURE_H
#define TUN_TCP_FIXTURE_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
static unsigned fixture_sum(const uint8_t *p, size_t n) {
  unsigned s = 0;
  for (size_t i = 0; i < n; i++)
    s += (unsigned)p[i] << (i % 2 ? 0 : 8);
  while (s >> 16)
    s = (s & 65535) + (s >> 16);
  return s;
}
static void fixture_put(uint8_t *p, unsigned n) {
  p[0] = n >> 8;
  p[1] = n;
}
static void fixture_num(uint8_t *p, uint32_t n) {
  fixture_put(p, n >> 16);
  fixture_put(p + 2, n);
}
static void fixture_checksum(uint8_t *p, size_t n) {
  size_t ip = p[0] >> 4 == 4 ? 20 : 40;
  p[ip + 16] = p[ip + 17] = 0;
  unsigned s = fixture_sum(p + (ip == 20 ? 12 : 8), ip == 20 ? 8 : 32) + 6 + n -
               ip + fixture_sum(p + ip, n - ip);
  while (s >> 16)
    s = (s & 65535) + (s >> 16);
  fixture_put(p + ip + 16, ~s);
  if (ip == 20) {
    p[10] = p[11] = 0;
    fixture_put(p + 10, ~fixture_sum(p, 20));
  }
}
static size_t fixture_packet(uint8_t *p, unsigned version, size_t payload,
                             uint32_t sequence, unsigned id, unsigned flags,
                             bool options) {
  size_t ip = version == 4 ? 20 : 40, tcp = options ? 32 : 20,
         n = ip + tcp + payload;
  memset(p, 0, n);
  if (version == 4) {
    p[0] = 0x45;
    fixture_put(p + 2, n);
    fixture_put(p + 4, id);
    fixture_put(p + 6, 0x4000);
    p[8] = 64;
    p[9] = 6;
    p[12] = 10;
    p[15] = 2;
    p[16] = 10;
    p[19] = 1;
  } else {
    p[0] = 0x60;
    fixture_put(p + 4, n - 40);
    p[6] = 6;
    p[7] = 64;
    p[8] = p[24] = 0xfd;
    p[23] = 2;
    p[39] = 1;
  }
  fixture_put(p + ip, 30101);
  fixture_put(p + ip + 2, 30100);
  fixture_num(p + ip + 4, sequence);
  fixture_num(p + ip + 8, 500);
  p[ip + 12] = (tcp / 4) << 4;
  p[ip + 13] = flags;
  fixture_put(p + ip + 14, 60000);
  if (options) {
    p[ip + 20] = p[ip + 21] = 1;
    p[ip + 22] = 8;
    p[ip + 23] = 10;
    fixture_num(p + ip + 24, 12345);
    fixture_num(p + ip + 28, 67890);
  }
  for (size_t i = 0; i < payload; i++)
    p[ip + tcp + i] = (uint8_t)(sequence + i);
  fixture_checksum(p, n);
  return n;
}
#endif
