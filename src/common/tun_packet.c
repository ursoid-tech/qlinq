#include "tun_packet.h"

tun_packet_result_t tun_packet_process(const tun_packet_config_t *config,
                                       const tun_packet_input_t *input,
                                       tun_packet_output_t *outputs,
                                       size_t output_capacity) {
  if (!config || !input ||
      (input->origin != TUN_PACKET_FROM_DEVICE &&
       input->origin != TUN_PACKET_FROM_PEER))
    return (tun_packet_result_t){.status = TUN_PACKET_INVALID};
  size_t limit = config->mtu < config->max_packet_size
                     ? config->mtu
                     : config->max_packet_size;
  tun_packet_view_t packet;
  if (!tun_packet_parse(input->data, input->size, limit, &packet))
    return (tun_packet_result_t){.status = TUN_PACKET_INVALID};
  if (!output_capacity)
    return (tun_packet_result_t){.status = TUN_PACKET_OUTPUT_FULL};
  if (!outputs)
    return (tun_packet_result_t){.status = TUN_PACKET_INVALID};
  outputs[0] = (tun_packet_output_t){.packet = packet,
                                     .destination =
                                         input->origin == TUN_PACKET_FROM_DEVICE
                                             ? TUN_PACKET_TO_TRANSPORT
                                             : TUN_PACKET_TO_DEVICE};
  return (tun_packet_result_t){.status = TUN_PACKET_OK, .count = 1};
}

bool tun_packet_parse(const void *data, size_t size, size_t max_size,
                      tun_packet_view_t *view) {
  if (view)
    *view = (tun_packet_view_t){0};
  if (!data || size == 0 || size > max_size)
    return false;
  const uint8_t *bytes = data;
  const uint8_t version = bytes[0] >> 4;
  size_t header_size;
  if (version == 4 && size >= 20) {
    header_size = (size_t)(bytes[0] & 15U) * 4U;
    size_t total_size = ((size_t)bytes[2] << 8) | bytes[3];
    if (header_size < 20 || header_size > size || total_size != size)
      return false;
  } else if (version == 6 && size >= 40) {
    header_size = 40;
    size_t payload_size = ((size_t)bytes[4] << 8) | bytes[5];
    if (payload_size + 40U != size)
      return false;
  } else {
    return false;
  }
  if (view)
    *view = (tun_packet_view_t){.data = bytes,
                                .size = size,
                                .header_size = header_size,
                                .version = version};
  return true;
}
