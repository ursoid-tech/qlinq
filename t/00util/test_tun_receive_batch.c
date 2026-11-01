#include "tun_receive_batch.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  tun_rx_batch_t batch;
  tun_rx_limits_t limits = {
      .packets = 3, .bytes = 128, .max_age_ms = 20, .flush_delay_ms = 5};
  assert(tun_rx_batch_init(&batch, &limits));
  uint8_t bytes[64] = {0x45, 0, 0, 64};
  tun_packet_view_t packet = {
      .data = bytes, .size = sizeof(bytes), .header_size = 20, .version = 4};
  tun_rx_view_t view;
  uint64_t deadline;
  assert(!tun_rx_batch_deadline(&batch, &deadline));
  assert(tun_rx_batch_begin(&batch));
  assert(!tun_rx_batch_begin(&batch));
  assert(tun_rx_batch_push(&batch, &packet, 100));
  bytes[20] = 99; /* callback storage may be reused immediately */
  assert(!tun_rx_batch_peek(&batch, 104, &view));
  assert(tun_rx_batch_deadline(&batch, &deadline) && deadline == 105);
  assert(tun_rx_batch_peek(&batch, 105, &view));
  assert(view.packet.data != bytes && view.packet.data[20] == 0);
  assert(view.packet.header_size == 20 && view.packet.version == 4);
  assert(!view.end_of_batch && view.batch_id == 1 && view.queued_ms == 100);
  tun_rx_batch_consume(&batch);
  assert(batch.count == 0 && batch.bytes == 0);
  assert(tun_rx_batch_push(&batch, &packet, 106));
  tun_rx_batch_end(&batch);
  assert(tun_rx_batch_deadline(&batch, &deadline) && deadline == 126);
  assert(
      tun_rx_batch_peek(&batch, 106, &view)); /* end flushes without waiting */
  assert(view.end_of_batch && view.batch_id == 1 && view.packet.data[20] == 99);

  assert(tun_rx_batch_begin(&batch));
  bytes[20] = 1;
  assert(tun_rx_batch_push(&batch, &packet, 107));
  bytes[20] = 2;
  assert(!tun_rx_batch_push(&batch, &packet, 107)); /* independent byte bound */
  assert(batch.count == 2 && batch.bytes == 128 && batch.dropped == 1);
  assert(tun_rx_batch_peek(&batch, 107, &view) && view.batch_id == 1);
  tun_rx_batch_consume(&batch);
  tun_rx_batch_end(&batch);
  assert(tun_rx_batch_peek(&batch, 107, &view));
  assert(view.batch_id == 2 && view.end_of_batch && view.packet.data[20] == 1);
  tun_rx_batch_consume(&batch);

  /* packet bound triggers early readiness before end or deadline */
  limits.packets = 2;
  limits.bytes = 1024;
  assert(tun_rx_batch_init(&batch, &limits));
  for (unsigned round = 0; round < 100; round++) {
    assert(tun_rx_batch_begin(&batch));
    assert(tun_rx_batch_push(&batch, &packet, 200 + round));
    assert(!tun_rx_batch_peek(&batch, 200 + round, &view));
    assert(tun_rx_batch_push(&batch, &packet, 200 + round));
    assert(tun_rx_batch_peek(&batch, 200 + round, &view));
    assert(!tun_rx_batch_push(&batch, &packet, 200 + round));
    tun_rx_batch_end(&batch);
    for (unsigned i = 0; i < 2; i++) {
      assert(tun_rx_batch_peek(&batch, 200 + round, &view));
      assert(view.end_of_batch == (i == 1));
      tun_rx_batch_consume(&batch);
    }
    assert(batch.bytes == 0 && batch.count == 0);
  }
  assert(tun_rx_batch_begin(&batch));
  assert(tun_rx_batch_push(&batch, &packet, 400));
  assert(tun_rx_batch_push(&batch, &packet, 401));
  uint64_t dropped = batch.dropped;
  /* at the exact age boundary, intake reclaims only expired head storage */
  assert(tun_rx_batch_push(&batch, &packet, 420));
  assert(batch.count == 2 && batch.dropped == dropped + 1);
  assert(tun_rx_batch_peek(&batch, 420, &view) && view.queued_ms == 401);
  tun_rx_batch_expire(&batch, 421);
  assert(batch.count == 1 && batch.bytes == 64);
  uint64_t id = batch.batch_id;
  tun_rx_batch_cancel(&batch);
  assert(!batch.active && batch.count == 0 && batch.bytes == 0);
  assert(!tun_rx_batch_peek(&batch, 421, &view) && !view.packet.data);
  assert(!tun_rx_batch_deadline(&batch, &deadline));
  assert(tun_rx_batch_begin(&batch) && batch.batch_id != id);
  tun_rx_batch_end(&batch);
  tun_rx_batch_end(&batch); /* cancel or empty close is safe */
  assert(!tun_rx_batch_push(&batch, &packet, 422));

  assert(tun_rx_batch_begin(&batch));
  packet.size = TUN_RX_PACKET_CAPACITY + 1;
  assert(!tun_rx_batch_push(&batch, &packet, 422));
  packet.size = 0;
  assert(!tun_rx_batch_push(&batch, &packet, 422));
  packet.size = sizeof(bytes);
  packet.data = NULL;
  assert(!tun_rx_batch_push(&batch, &packet, 422));
  assert(!tun_rx_batch_push(&batch, NULL, 422));
  assert(batch.count == 0 && batch.bytes == 0);
  tun_rx_batch_end(&batch);

  limits.packets = TUN_RX_BATCH_CAPACITY + 1;
  assert(!tun_rx_batch_init(&batch, &limits));
  limits.packets = 2;
  limits.flush_delay_ms = 21;
  assert(!tun_rx_batch_init(&batch, &limits));
  limits.flush_delay_ms = 0;
  assert(!tun_rx_batch_init(&batch, &limits));
  limits.flush_delay_ms = 5;
  limits.bytes = 0;
  assert(!tun_rx_batch_init(&batch, &limits));
  puts("===TUN RECEIVE BATCH OK===");
  return 0;
}
