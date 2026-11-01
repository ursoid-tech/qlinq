#include "tun_receive_batch.h"

#include <string.h>

static uint64_t add_time(uint64_t time, uint64_t delta) {
  return time > UINT64_MAX - delta ? UINT64_MAX : time + delta;
}

bool tun_rx_batch_init(tun_rx_batch_t *batch, const tun_rx_limits_t *limits) {
  if (!batch || !limits || !limits->packets ||
      limits->packets > TUN_RX_BATCH_CAPACITY || !limits->bytes ||
      limits->bytes > TUN_RX_BATCH_CAPACITY * TUN_RX_PACKET_CAPACITY ||
      !limits->max_age_ms || !limits->flush_delay_ms ||
      limits->flush_delay_ms > limits->max_age_ms)
    return false;
  *batch = (tun_rx_batch_t){.limits = *limits};
  return true;
}

bool tun_rx_batch_begin(tun_rx_batch_t *batch) {
  if (batch->active)
    return false;
  /* advance batch identity on each new batch */
  batch->batch_id++;
  batch->active = true;
  return true;
}

void tun_rx_batch_end(tun_rx_batch_t *batch) {
  if (!batch->active)
    return;
  if (batch->count) {
    size_t tail = (batch->head + batch->count - 1) % TUN_RX_BATCH_CAPACITY;
    if (batch->slots[tail].batch_id == batch->batch_id)
      batch->slots[tail].end_of_batch = true;
  }
  batch->active = false;
}

void tun_rx_batch_consume(tun_rx_batch_t *batch) {
  if (!batch->count)
    return;
  batch->bytes -= batch->slots[batch->head].size;
  batch->head = (batch->head + 1) % TUN_RX_BATCH_CAPACITY;
  batch->count--;
}

void tun_rx_batch_expire(tun_rx_batch_t *batch, uint64_t now_ms) {
  while (batch->count && now_ms - batch->slots[batch->head].queued_ms >=
                             batch->limits.max_age_ms) {
    tun_rx_batch_consume(batch);
    batch->dropped++;
  }
}

bool tun_rx_batch_push(tun_rx_batch_t *batch, const tun_packet_view_t *packet,
                       uint64_t now_ms) {
  tun_rx_batch_expire(batch, now_ms);
  if (!batch->active || !packet || !packet->data || !packet->size ||
      packet->size > TUN_RX_PACKET_CAPACITY ||
      batch->count == batch->limits.packets ||
      packet->size > batch->limits.bytes - batch->bytes) {
    batch->dropped++;
    return false;
  }
  size_t tail = (batch->head + batch->count) % TUN_RX_BATCH_CAPACITY;
  tun_rx_slot_t *slot = &batch->slots[tail];
  memcpy(slot->bytes, packet->data, packet->size);
  slot->size = packet->size;
  slot->header_size = packet->header_size;
  slot->version = packet->version;
  slot->queued_ms = now_ms;
  slot->batch_id = batch->batch_id;
  slot->end_of_batch = false;
  batch->count++;
  batch->bytes += packet->size;
  return true;
}

bool tun_rx_batch_peek(tun_rx_batch_t *batch, uint64_t now_ms,
                       tun_rx_view_t *view) {
  *view = (tun_rx_view_t){0};
  tun_rx_batch_expire(batch, now_ms);
  if (!batch->count)
    return false;
  const tun_rx_slot_t *slot = &batch->slots[batch->head];
  if (batch->active && slot->batch_id == batch->batch_id &&
      now_ms - slot->queued_ms < batch->limits.flush_delay_ms &&
      batch->count < batch->limits.packets &&
      batch->bytes < batch->limits.bytes)
    return false;
  *view = (tun_rx_view_t){.packet = {.data = slot->bytes,
                                     .size = slot->size,
                                     .header_size = slot->header_size,
                                     .version = slot->version},
                          .queued_ms = slot->queued_ms,
                          .batch_id = slot->batch_id,
                          .end_of_batch = slot->end_of_batch};
  return true;
}

bool tun_rx_batch_deadline(const tun_rx_batch_t *batch, uint64_t *deadline_ms) {
  if (!batch->count)
    return false;
  const tun_rx_slot_t *slot = &batch->slots[batch->head];
  uint64_t delay = batch->limits.max_age_ms;
  if (batch->active && slot->batch_id == batch->batch_id)
    delay = batch->limits.flush_delay_ms;
  *deadline_ms = add_time(slot->queued_ms, delay);
  return true;
}

void tun_rx_batch_cancel(tun_rx_batch_t *batch) {
  batch->dropped += batch->count;
  batch->head = batch->count = batch->bytes = 0;
  batch->active = false;
}
