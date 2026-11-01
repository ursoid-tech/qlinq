#ifndef QLINQ_TUN_SEGMENT_H
#define QLINQ_TUN_SEGMENT_H

#include "tun_packet.h"

#define TUN_TX_FRAME_CAPACITY 65536U
#define TUN_VNET_HEADER_SIZE 10U

/* normalized virtio metadata decoded from the 10-byte LE header */
typedef struct {
  uint8_t flags, gso_type;
  uint16_t header_length, gso_size, checksum_start, checksum_offset;
} tun_offload_t;

enum { TUN_CSUM_PARTIAL = 1, TUN_CSUM_VALID = 2 };
enum {
  TUN_GSO_NONE = 0,
  TUN_GSO_TCP4 = 1,
  TUN_GSO_TCP6 = 4,
  TUN_GSO_ECN = 128
};

/* borrows input storage until all segments are materialized or cancelled */
typedef struct {
  const uint8_t *data;
  size_t size, tcp, header, segment, offset, checksum_field;
  uint8_t version;
  bool pending, segmented, partial;
} tun_segment_t;

bool tun_segment_prepare(tun_segment_t *plan, const tun_packet_config_t *config,
                         const tun_packet_input_t *input,
                         const tun_offload_t *offload);
size_t tun_segment_remaining(const tun_segment_t *plan);
tun_packet_result_t tun_segment_next(tun_segment_t *plan, void *storage,
                                     size_t capacity,
                                     tun_packet_output_t *output);
/* cancel plan and return number of unmaterialized segments discarded */
size_t tun_segment_cancel(tun_segment_t *plan);

#endif
