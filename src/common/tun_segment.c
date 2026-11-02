#include "tun_segment.h"

#include <string.h>

static unsigned get16(const uint8_t *p) {
  return (unsigned)p[0] << 8 | p[1];
}
static uint32_t get32(const uint8_t *p) {
  return (uint32_t)get16(p) << 16 | get16(p + 2);
}
static void put16(uint8_t *p, unsigned n) {
  p[0] = (uint8_t)(n >> 8);
  p[1] = (uint8_t)n;
}
static void put32(uint8_t *p, uint32_t n) {
  put16(p, n >> 16);
  put16(p + 2, n);
}
static uint32_t sum(const uint8_t *p, size_t size) {
  uint32_t result = 0;
  for (; size >= 2; p += 2, size -= 2)
    result += get16(p);
  if (size)
    result += (uint32_t)*p << 8;
  return result;
}
static unsigned fold(uint32_t n) {
  while (n >> 16)
    n = (n & 65535U) + (n >> 16);
  return n;
}

/* locate TCP/UDP from IP headers instead of virtio hdr_len hint */
static bool transport(const uint8_t *p, size_t size, uint8_t version,
                      size_t *offset, unsigned *protocol) {
  if (version == 4) {
    *offset = (size_t)(p[0] & 15U) * 4;
    *protocol = p[9];
    return (get16(p + 6) & ~0x4000U) == 0;
  }
  *offset = 40;
  *protocol = p[6];
  while (*protocol != 6 && *protocol != 17) {
    if ((*protocol != 0 && *protocol != 43 && *protocol != 60) ||
        size - *offset < 2)
      return false;
    size_t length = ((size_t)p[*offset + 1] + 1U) * 8;
    if (length > size - *offset)
      return false;
    *protocol = p[*offset];
    *offset += length;
  }
  return true;
}

bool tun_segment_prepare(tun_segment_t *plan, const tun_packet_config_t *config,
                         const tun_packet_input_t *input,
                         const tun_offload_t *offload) {
  *plan = (tun_segment_t){0};
  if (!config || !input || !offload ||
      input->origin != TUN_PACKET_FROM_DEVICE || (offload->flags & ~3U) ||
      offload->flags == 3 || input->size > TUN_TX_FRAME_CAPACITY)
    return false;
  tun_packet_view_t packet;
  if (!tun_packet_parse(input->data, input->size, TUN_TX_FRAME_CAPACITY,
                        &packet))
    return false;
  size_t limit = config->mtu < config->max_packet_size
                     ? config->mtu
                     : config->max_packet_size;
  tun_segment_t decoded = {.data = packet.data,
                           .size = packet.size,
                           .version = packet.version,
                           .pending = true,
                           .partial = (offload->flags & TUN_CSUM_PARTIAL) != 0,
                           .segmented = offload->gso_type != TUN_GSO_NONE};
  if (!decoded.segmented && (packet.size > limit || offload->gso_size ||
                             offload->header_length > packet.size))
    return false;
  if (decoded.partial) {
    size_t start = offload->checksum_start, field = offload->checksum_offset;
    if (start < packet.header_size || start >= packet.size ||
        field >= packet.size - start || packet.size - start - field < 2)
      return false;
    decoded.tcp = start;
    decoded.checksum_field = start + field;
  }
  if (decoded.segmented) {
    unsigned protocol;
    if (!transport(packet.data, packet.size, packet.version, &decoded.tcp,
                   &protocol))
      return false;
    size_t length = packet.size - decoded.tcp;
    if (protocol == 6) {
      if (length < 20)
        return false;
      size_t tcp_length = (size_t)(packet.data[decoded.tcp + 12] >> 4) * 4;
      if (tcp_length < 20 || tcp_length > length)
        return false;
      decoded.header = decoded.tcp + tcp_length;
    } else if (protocol == 17) {
      if (length < 8 || get16(packet.data + decoded.tcp + 4) != length)
        return false;
      decoded.header = decoded.tcp + 8;
    } else
      return false;
    if (decoded.partial &&
        (offload->checksum_start != decoded.tcp ||
         offload->checksum_offset != (protocol == 6 ? 16U : 6U)))
      return false;
    unsigned kind = offload->gso_type & ~TUN_GSO_ECN;
    if (protocol != 6 || !decoded.partial ||
        (kind != TUN_GSO_TCP4 && kind != TUN_GSO_TCP6) ||
        packet.version != (kind == TUN_GSO_TCP4 ? 4 : 6) ||
        (packet.data[decoded.tcp + 13] & 6U) || decoded.header >= packet.size ||
        (offload->header_length && offload->header_length < decoded.header) ||
        offload->header_length > packet.size || !offload->gso_size ||
        decoded.header > limit || offload->gso_size > limit - decoded.header)
      return false;
    decoded.segment = offload->gso_size;
  }
  *plan = decoded;
  return true;
}

size_t tun_segment_remaining(const tun_segment_t *plan) {
  if (!plan->pending)
    return 0;
  return plan->segmented
             ? (plan->size - plan->header - plan->offset + plan->segment - 1) /
                   plan->segment
             : 1;
}

size_t tun_segment_cancel(tun_segment_t *plan) {
  size_t remaining = tun_segment_remaining(plan);
  *plan = (tun_segment_t){0};
  return remaining;
}

tun_packet_result_t tun_segment_next(tun_segment_t *plan, void *storage,
                                     size_t capacity,
                                     tun_packet_output_t *output) {
  if (!plan->pending || !storage || !output)
    return (tun_packet_result_t){.status = TUN_PACKET_INVALID};
  size_t payload =
      plan->segmented ? plan->size - plan->header - plan->offset : 0;
  if (payload > plan->segment && plan->segmented)
    payload = plan->segment;
  size_t size = plan->segmented ? plan->header + payload : plan->size;
  if (size > capacity)
    return (tun_packet_result_t){.status = TUN_PACKET_OUTPUT_FULL};
  uint8_t *out = storage;
  const uint8_t *p = plan->data;
  if (!plan->segmented) {
    if (out != p)
      memcpy(out, p, size);
    if (plan->partial) {
      unsigned check = (~fold(sum(out + plan->tcp, size - plan->tcp))) & 65535U;
      if ((plan->checksum_field - plan->tcp) & 1U)
        check = (check >> 8) | ((check & 255U) << 8);
      put16(out + plan->checksum_field, check ? check : 65535U);
    }
    plan->pending = false;
  } else {
    memcpy(out, p, plan->header);
    memcpy(out + plan->header, p + plan->header + plan->offset, payload);
    bool last = plan->offset + payload == plan->size - plan->header;
    uint8_t *tcp = out + plan->tcp;
    put32(tcp + 4, get32(p + plan->tcp + 4) + (uint32_t)plan->offset);
    if (!last)
      tcp[13] &= ~9U; /* FIN/PSH only on the final segment */
    if (plan->offset)
      tcp[13] &= ~0x80U; /* CWR only on the first segment */
    if (tcp[13] & 0x20U) {
      unsigned urgent = get16(p + plan->tcp + 18);
      if (urgent > plan->offset)
        put16(tcp + 18, urgent - plan->offset);
      else {
        tcp[13] &= ~0x20U;
        put16(tcp + 18, 0);
      }
    }
    if (plan->version == 4) {
      put16(out + 2, size);
      put16(out + 4, get16(p + 4) + plan->offset / plan->segment);
      put16(out + 10, 0);
      put16(out + 10, ~fold(sum(out, plan->tcp)));
    } else
      put16(out + 4, size - 40);
    uint32_t seed = get16(p + plan->tcp + 16) +
                    ((~(plan->size - plan->tcp)) & 65535U) + size - plan->tcp;
    put16(tcp + 16, 0);
    put16(tcp + 16, ~fold(seed + sum(tcp, size - plan->tcp)));
    plan->offset += payload;
    plan->pending = !last;
  }
  *output = (tun_packet_output_t){
      .packet = {.data = out,
                 .size = size,
                 .version = plan->version,
                 .header_size =
                     plan->version == 4 ? (size_t)(out[0] & 15U) * 4 : 40},
      .destination = TUN_PACKET_TO_TRANSPORT};
  return (tun_packet_result_t){.status = TUN_PACKET_OK, .count = 1};
}
