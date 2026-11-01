#include "tun_coalesce.h"
#include <string.h>

static unsigned word(const uint8_t *p) {
  return (unsigned)p[0] * 256 + p[1];
}
static uint32_t number(const uint8_t *p) {
  return (uint32_t)word(p) * 65536U + word(p + 2);
}
static void put(uint8_t *p, unsigned n) {
  p[0] = n >> 8;
  p[1] = n;
}
static unsigned sum(const uint8_t *p, size_t n) {
  unsigned s = 0;
  for (; n >= 2; p += 2, n -= 2)
    s += word(p);
  if (n)
    s += (unsigned)*p << 8;
  return s;
}
static unsigned fold(unsigned s) {
  while (s >> 16)
    s = (s & 65535U) + (s >> 16);
  return s;
}
static unsigned pseudo(const uint8_t *p, size_t n) {
  return (p[0] >> 4 == 4 ? sum(p + 12, 8) : sum(p + 8, 32)) + 6 + n;
}

/* allow only NOP padding and a single RFC timestamp option */
static bool options(const uint8_t *tcp, size_t header) {
  bool timestamp = false;
  for (size_t i = 20; i < header;) {
    unsigned kind = tcp[i];
    if (kind == 0)
      return true;
    if (kind == 1) {
      i++;
      continue;
    }
    if (kind != 8 || timestamp || header - i < 10 || tcp[i + 1] != 10)
      return false;
    timestamp = true;
    i += 10;
  }
  return true;
}

typedef struct {
  size_t ip, header, payload;
  uint8_t flags;
} tcp_t;
static bool decode(const tun_packet_view_t *v, tcp_t *t, bool checksums) {
  if (!v)
    return false;
  tun_packet_view_t checked;
  const uint8_t *p = v->data;
  if (!tun_packet_parse(p, v->size, TUN_RX_AGGREGATE_CAPACITY, &checked))
    return false;
  size_t ip = checked.version == 4 ? 20 : 40;
  /* reject IP options or extension headers; keep as ordinary packets */
  if (checked.version == 4) {
    if (p[0] != 0x45 || p[9] != 6 || (word(p + 6) & ~0x4000U) ||
        (checksums && fold(sum(p, 20)) != 65535U))
      return false;
  } else if (p[6] != 6)
    return false;
  if (v->size < ip + 20)
    return false;
  const uint8_t *tcp = p + ip;
  size_t h = (size_t)(tcp[12] >> 4) * 4;
  /* coalesce ACK data only; PSH and FIN terminate an aggregate */
  if (h < 20 || ip + h >= v->size || (tcp[12] & 15) || (tcp[13] & ~0x19U) ||
      !(tcp[13] & 0x10) || word(tcp + 18) ||
      (checksums &&
       fold(pseudo(p, v->size - ip) + sum(tcp, v->size - ip)) != 65535U))
    return false;
  if (!options(tcp, h))
    return false;
  *t = (tcp_t){ip, ip + h, v->size - ip - h, tcp[13]};
  return true;
}
static bool compatible(const uint8_t *a, const uint8_t *b, const tcp_t *t,
                       size_t offset, size_t index) {
  if (t->ip == 20) {
    if (a[1] != b[1] || memcmp(a + 6, b + 6, 4) || memcmp(a + 12, b + 12, 8) ||
        word(b + 4) != ((word(a + 4) + index) & 65535U))
      return false;
  } else if (memcmp(a, b, 4) || memcmp(a + 6, b + 6, 34))
    return false;
  a += t->ip;
  b += t->ip;
  return !memcmp(a, b, 4) &&
         number(b + 4) == number(a + 4) + (uint32_t)offset &&
         !memcmp(a + 8, b + 8, 5) && !memcmp(a + 14, b + 14, 2) &&
         !memcmp(a + 20, b + 20, t->header - t->ip - 20);
}
bool tun_coalesce_candidate(const tun_packet_view_t *packet) {
  tcp_t decoded;
  return decode(packet, &decoded, false) && !(decoded.flags & 9);
}
bool tun_coalesce_pair(const tun_packet_view_t *a, const tun_packet_view_t *b) {
  tcp_t first, next;
  return decode(a, &first, false) && decode(b, &next, false) &&
         !(first.flags & 9) && first.ip == next.ip &&
         first.header == next.header && next.payload <= first.payload &&
         compatible(a->data, b->data, &first, first.payload, 1);
}

bool tun_coalesce(const tun_packet_view_t *packets, size_t count, void *scratch,
                  size_t capacity, tun_coalesce_output_t *out) {
  if (!out)
    return false;
  *out = (tun_coalesce_output_t){0};
  if (!packets || !count || !packets[0].data || !packets[0].size)
    return false;
  *out = (tun_coalesce_output_t){.packet = packets[0], .count = 1};
  tcp_t first;
  if (!scratch || !decode(packets, &first, true) || (first.flags & 9))
    return true;
  size_t used = 1, size = packets[0].size, payload = first.payload;
  uint8_t flags = first.flags;
  if (capacity > TUN_RX_AGGREGATE_CAPACITY)
    capacity = TUN_RX_AGGREGATE_CAPACITY;
  while (used < count) {
    tcp_t next;
    if (!decode(packets + used, &next, true) || first.ip != next.ip ||
        first.header != next.header || next.payload > first.payload ||
        size > capacity || next.payload > capacity - size ||
        !compatible(packets[0].data, packets[used].data, &first, payload, used))
      break;
    size += next.payload;
    payload += next.payload;
    flags = next.flags;
    used++;
    if ((flags & 9) || next.payload < first.payload)
      break;
  }
  if (used == 1)
    return true;
  uint8_t *p = scratch;
  memcpy(p, packets[0].data, packets[0].size);
  size_t offset = packets[0].size;
  for (size_t i = 1; i < used; i++) {
    size_t n = packets[i].size - first.header;
    memcpy(p + offset, packets[i].data + first.header, n);
    offset += n;
  }
  if (first.ip == 20) {
    put(p + 2, size);
    put(p + 10, 0);
    put(p + 10, ~fold(sum(p, 20)));
  } else
    put(p + 4, size - 40);
  p[first.ip + 13] = flags;
  /* CHECKSUM_PARTIAL carries the folded pseudo-header seed */
  put(p + first.ip + 16, fold(pseudo(p, size - first.ip)));
  *out = (tun_coalesce_output_t){
      .packet = {.data = p,
                 .size = size,
                 .header_size = first.ip,
                 .version = first.ip == 20 ? 4 : 6},
      .offload = {.flags = TUN_CSUM_PARTIAL,
                  .gso_type = first.ip == 20 ? TUN_GSO_TCP4 : TUN_GSO_TCP6,
                  .header_length = first.header,
                  .gso_size = first.payload,
                  .checksum_start = first.ip,
                  .checksum_offset = 16},
      .count = used};
  return true;
}
