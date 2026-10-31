/* test direct tun receive and queue backpressure ordering */
#include "../../src/host/linux/tun_direct.c"
#include <assert.h>
static bool blocked, fail_write;
static unsigned writes, expected;
ssize_t __wrap_tun_write(int fd, const void *data, size_t size) {
  (void)fd;
  if (fail_write) {
    errno = EIO;
    return -1;
  }
  if (blocked) {
    errno = EAGAIN;
    return -1;
  }
  uint32_t sequence;
  memcpy(&sequence, (const uint8_t *)data + 20, sizeof(sequence));
  assert(sequence == expected++);
  writes++;
  return (ssize_t)size;
}
int main(void) {
  receive_queue_t queue = {0};
  tunnel_receiver_t receiver = {
      .queue = &queue, .fd = 7, .mtu = 1400, .max_age = 1000};
  uint8_t packet[64] = {0x45, 0, 0, 64};
  qlinq_event_t event = {.record = {.data = packet, .size = sizeof(packet)}};
  for (uint32_t i = 0; i < 2048; i++) {
    memcpy(packet + 20, &i, sizeof(i));
    assert(receive_packet(&receiver, &event));
  }
  assert(writes == 2048 && queue.count == 0 && queue.dropped == 0);
  blocked = true;
  for (uint32_t i = 2048; i < 2050; i++) {
    memcpy(packet + 20, &i, sizeof(i));
    assert(receive_packet(&receiver, &event));
  }
  assert(queue.count == 2 && queue.dropped == 0);
  blocked = false;
  assert(flush_packets(&queue, 7, 1000));
  assert(writes == 2050 && queue.count == 0);
  event.record.size = 1;
  assert(receive_packet(&receiver, &event));
  assert(queue.dropped == 1);
  event.record.size = sizeof(packet);
  fail_write = true;
  assert(!receive_packet(&receiver, &event));
  puts("===TUN DIRECT RECEIVE OK===");
  return 0;
}
