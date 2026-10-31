#ifndef QLINQ_TUN_RECEIVE_BATCH_H
#define QLINQ_TUN_RECEIVE_BATCH_H

#include "tun_packet.h"

#define TUN_RX_PACKET_CAPACITY 2048U
#define TUN_RX_BATCH_CAPACITY 64U

typedef struct {
  size_t packets, bytes;
  uint64_t max_age_ms, flush_delay_ms;
} tun_rx_limits_t;

typedef struct {
  uint8_t bytes[TUN_RX_PACKET_CAPACITY];
  size_t size, header_size;
  uint8_t version;
  uint64_t queued_ms, batch_id;
  bool end_of_batch;
} tun_rx_slot_t;

/* fixed storage arena; no allocation or retained callback pointers */
typedef struct {
  tun_rx_slot_t slots[TUN_RX_BATCH_CAPACITY];
  tun_rx_limits_t limits;
  size_t head, count, bytes;
  uint64_t dropped, batch_id;
  bool active;
} tun_rx_batch_t;

typedef struct {
  tun_packet_view_t packet;
  uint64_t queued_ms, batch_id;
  bool end_of_batch;
} tun_rx_view_t;

bool tun_rx_batch_init(tun_rx_batch_t *batch, const tun_rx_limits_t *limits);
/* start one owner-defined batch for a service turn */
bool tun_rx_batch_begin(tun_rx_batch_t *batch);
void tun_rx_batch_end(tun_rx_batch_t *batch);
/* copy a processed packet into the bounded batch arena */
bool tun_rx_batch_push(tun_rx_batch_t *batch, const tun_packet_view_t *packet,
                       uint64_t now_ms);
/* expire stale packets and expose the head when ready to flush */
bool tun_rx_batch_peek(tun_rx_batch_t *batch, uint64_t now_ms,
                       tun_rx_view_t *view);
void tun_rx_batch_consume(tun_rx_batch_t *batch);
void tun_rx_batch_expire(tun_rx_batch_t *batch, uint64_t now_ms);
/* earliest outstanding flush or expiry deadline */
bool tun_rx_batch_deadline(const tun_rx_batch_t *batch, uint64_t *deadline_ms);
/* drop all owned packets and close the active batch */
void tun_rx_batch_cancel(tun_rx_batch_t *batch);

#endif
