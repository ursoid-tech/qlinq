#ifndef QLINQ_TUN_COALESCE_H
#define QLINQ_TUN_COALESCE_H

#include "tun_segment.h"

#define TUN_RX_AGGREGATE_CAPACITY 65535U

typedef struct {
  tun_packet_view_t packet;
  tun_offload_t offload;
  size_t count;
} tun_coalesce_output_t;

/* synchronous prefix coalescing of compatible FIFO TCP packets */
bool tun_coalesce_pair(const tun_packet_view_t *first,
                       const tun_packet_view_t *next);
/* check if packet can start a multi-packet coalesced run */
bool tun_coalesce_candidate(const tun_packet_view_t *packet);

bool tun_coalesce(const tun_packet_view_t *packets, size_t count, void *scratch,
                  size_t capacity, tun_coalesce_output_t *output);

#endif
