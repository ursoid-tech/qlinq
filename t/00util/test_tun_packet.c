#include "tun_packet.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void rejected(const void *data, size_t size, size_t limit) {
  tun_packet_view_t view = {
      .data = data, .size = 1, .header_size = 1, .version = 1};
  assert(!tun_packet_parse(data, size, limit, &view));
  assert(!view.data && !view.size && !view.header_size && !view.version);
  assert(!tun_packet_parse(data, size, limit, NULL));
  tun_packet_config_t config = {.mtu = limit, .max_packet_size = limit};
  for (int origin = TUN_PACKET_FROM_DEVICE; origin <= TUN_PACKET_FROM_PEER;
       origin++) {
    tun_packet_input_t input = {.data = data, .size = size, .origin = origin};
    tun_packet_output_t output = {0};
    tun_packet_result_t result =
        tun_packet_process(&config, &input, &output, 1);
    assert(result.status == TUN_PACKET_INVALID && result.count == 0);
    result = tun_packet_process(&config, &input, NULL, 0);
    assert(result.status == TUN_PACKET_INVALID && result.count == 0);
  }
}

static void accepted(const uint8_t *data, size_t size, size_t limit,
                     unsigned version, size_t header_size) {
  uint8_t *copy = malloc(size);
  assert(copy);
  memcpy(copy, data, size);
  tun_packet_view_t view;
  assert(tun_packet_parse(data, size, limit, &view));
  assert(view.data == data && view.size == size);
  assert(view.version == version && view.header_size == header_size);
  assert(tun_packet_parse(data, size, limit, NULL));
  tun_packet_config_t config = {.mtu = limit, .max_packet_size = limit};
  tun_packet_input_t input = {
      .data = data, .size = size, .origin = TUN_PACKET_FROM_DEVICE};
  tun_packet_output_t output;
  tun_packet_result_t result = tun_packet_process(&config, &input, &output, 1);
  assert(result.status == TUN_PACKET_OK && result.count == 1);
  assert(output.destination == TUN_PACKET_TO_TRANSPORT);
  assert(output.packet.data == data && output.packet.size == size);
  assert(output.packet.header_size == header_size &&
         output.packet.version == version);
  /* feed published bytes back through the peer side without a device */
  input = (tun_packet_input_t){.data = output.packet.data,
                               .size = output.packet.size,
                               .origin = TUN_PACKET_FROM_PEER};
  result = tun_packet_process(&config, &input, &output, 1);
  assert(result.status == TUN_PACKET_OK && result.count == 1);
  assert(output.destination == TUN_PACKET_TO_DEVICE);
  assert(output.packet.data == data && output.packet.size == size);
  assert(!memcmp(copy, data, size));
  free(copy);
}

static void processing_contract(void) {
  uint8_t bytes[1400] = {0x45, 0, 5, 120};
  tun_packet_config_t config = {.mtu = 1400, .max_packet_size = 2048};
  tun_packet_input_t input = {
      .data = bytes, .size = sizeof(bytes), .origin = TUN_PACKET_FROM_DEVICE};
  tun_packet_output_t output[2];
  memset(output, 0xa5, sizeof(output));
  uint8_t saved[sizeof(output)];
  memcpy(saved, output, sizeof(output));

  tun_packet_result_t result = tun_packet_process(&config, &input, output, 0);
  assert(result.status == TUN_PACKET_OUTPUT_FULL && result.count == 0);
  assert(!memcmp(saved, output, sizeof(output)));
  result = tun_packet_process(&config, &input, NULL, 0);
  assert(result.status == TUN_PACKET_OUTPUT_FULL && result.count == 0);
  /* retry with room; nothing was consumed or mutated on failure */
  result = tun_packet_process(&config, &input, output, 1);
  assert(result.status == TUN_PACKET_OK && result.count == 1);
  assert(output[0].packet.data == bytes &&
         output[0].packet.size == sizeof(bytes));
  assert(!memcmp(saved + sizeof(output[0]), &output[1], sizeof(output[1])));
  result = tun_packet_process(&config, &input, output, 2);
  assert(result.status == TUN_PACKET_OK && result.count == 1);
  assert(!memcmp(saved + sizeof(output[0]), &output[1], sizeof(output[1])));

  memcpy(saved, output, sizeof(output));
  config.mtu = 1399;
  result = tun_packet_process(&config, &input, output, 1);
  assert(result.status == TUN_PACKET_INVALID && result.count == 0);
  config.mtu = 1400;
  config.max_packet_size = 1399;
  result = tun_packet_process(&config, &input, output, 1);
  assert(result.status == TUN_PACKET_INVALID && result.count == 0);
  config.max_packet_size = 2048;
  input.origin = (tun_packet_origin_t)99;
  result = tun_packet_process(&config, &input, output, 1);
  assert(result.status == TUN_PACKET_INVALID && result.count == 0);
  input.origin = TUN_PACKET_FROM_DEVICE;
  result = tun_packet_process(NULL, &input, output, 1);
  assert(result.status == TUN_PACKET_INVALID && result.count == 0);
  result = tun_packet_process(&config, NULL, output, 1);
  assert(result.status == TUN_PACKET_INVALID && result.count == 0);
  result = tun_packet_process(&config, &input, NULL, 1);
  assert(result.status == TUN_PACKET_INVALID && result.count == 0);
  assert(!memcmp(saved, output, sizeof(output)));
}

int main(void) {
  processing_contract();
  /* header-only IPv4, options, fragments, and bad checksums are accepted */
  uint8_t v4[60] = {0x45, 0, 0, 20};
  accepted(v4, 20, 1400, 4, 20);
  v4[0] = 0x4f;
  v4[3] = 60;
  accepted(v4, sizeof(v4), 1400, 4, 60);
  v4[6] = 0x20;
  v4[10] = 0xff;
  accepted(v4, sizeof(v4), 1400, 4, 60);
  v4[0] = 0x44;
  rejected(v4, sizeof(v4), 1400); /* invalid IHL */
  v4[0] = 0x4f;
  v4[3] = 59;
  rejected(v4, 59, 1400); /* options truncated */
  v4[0] = 0x45;
  rejected(v4, 60, 1400); /* trailing byte */
  v4[3] = 61;
  rejected(v4, 60, 1400); /* payload truncated */

  uint8_t v6[48] = {0x60};
  accepted(v6, 40, 1400, 6, 40);
  v6[5] = 8;
  v6[6] = 60; /* extension headers remain opaque */
  accepted(v6, sizeof(v6), 1400, 6, 40);
  rejected(v6, 47, 1400);
  v6[5] = 7;
  rejected(v6, 48, 1400);
  v6[5] = 0;
  rejected(v6, 48, 1400); /* zero payload length does not enable jumbograms */

  /* use exact allocations so sanitizers detect reads past a truncated header */
  for (unsigned version = 4; version <= 6; version += 2) {
    size_t header_size = version == 4 ? 20 : 40;
    for (size_t size = 1; size < header_size; size++) {
      uint8_t *short_packet = calloc(size, 1);
      assert(short_packet);
      short_packet[0] = (uint8_t)((version << 4) | (version == 4 ? 5 : 0));
      rejected(short_packet, size, 1400);
      free(short_packet);
    }
  }

  /* caller owns the MTU and storage policy */
  uint8_t large[2049] = {0x45, 0, 8, 1};
  accepted(large, sizeof(large), sizeof(large), 4, 20);
  rejected(large, sizeof(large), 2048);
  large[2] = 5;
  large[3] = 120; /* 1400 */
  accepted(large, 1400, 1400, 4, 20);
  rejected(large, 1400, 1399);
  rejected(large, 1400, 0);
  large[0] = 0x50;
  rejected(large, 1400, 1400);
  rejected(NULL, 20, 1400);
  rejected(large, 0, 1400);
  puts("===TUN PACKET OK===");
  return 0;
}
