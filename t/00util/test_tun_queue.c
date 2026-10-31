/* test direct tun receive and queue backpressure ordering */
#include "../../src/host/linux/tun_direct.c"
#include <assert.h>
#include "tun_tcp_fixture.h"
static bool blocked, fail_write;
static unsigned writes, expected, calls, interrupts;
static bool short_write;
static const void *last_data;
ssize_t __wrap_tun_write(int fd, const void *data, size_t size) {
  (void)fd;
  calls++;
  last_data = data;
  if (interrupts) {
    interrupts--;
    errno = EINTR;
    return -1;
  }
  if (short_write)
    return (ssize_t)size - 1;
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
static bool checking_coalesce;
static unsigned accepted_coalesce, offload_attempts;
static uint8_t coalesce_records[4][160];
ssize_t __wrap_tun_write_vnet(int fd, const void *data, size_t size) {
  if (!checking_coalesce)
    return __wrap_tun_write(fd, data, size);
  calls++;
  if (blocked) {
    errno = EAGAIN;
    return -1;
  }
  assert(accepted_coalesce < 4 && size == 141);
  assert(!memcmp(data, coalesce_records[accepted_coalesce++], size));
  return size;
}
ssize_t __wrap_tun_write_offload(int fd, const void *data, size_t size,
                                 const tun_offload_t *metadata) {
  (void)fd;
  assert(checking_coalesce);
  calls++;
  offload_attempts++;
  if (interrupts) {
    interrupts--;
    errno = EINTR;
    return -1;
  }
  if (blocked) {
    errno = EAGAIN;
    return -1;
  }
  if (short_write)
    return size - 1;
  if (fail_write) {
    errno = EIO;
    return -1;
  }
  tun_segment_t plan;
  tun_packet_config_t config = {1400, 2048};
  tun_packet_input_t input = {
      .data = data, .size = size, .origin = TUN_PACKET_FROM_DEVICE};
  assert(tun_segment_prepare(&plan, &config, &input, metadata));
  while (plan.pending) {
    uint8_t packet[2048];
    tun_packet_output_t o;
    assert(tun_segment_next(&plan, packet, sizeof(packet), &o).status ==
           TUN_PACKET_OK);
    assert(accepted_coalesce < 4 && o.packet.size == 141);
    assert(!memcmp(packet, coalesce_records[accepted_coalesce++], 141));
  }
  return size;
}
static void receive_coalescing(void) {
  tun_rx_batch_t queue;
  tun_rx_limits_t limits = {64, 64 * 1400, 1000, 1};
  assert(tun_rx_batch_init(&queue, &limits));
  tunnel_receiver_t rx = {
      .queue = &queue, .fd = 7, .mtu = 1400, .vnet = true, .coalesce = true};
  checking_coalesce = true;
  for (unsigned i = 0; i < 4; i++)
    fixture_packet(coalesce_records[i], 4, 101, 5000 + i * 101, 100 + i, 0x10,
                   false);
  begin_receive_batch(&rx);
  /* use direct owned intake for deterministic flush-deadline tests */
  for (unsigned i = 0; i < 4; i++) {
    tun_packet_view_t packet = {.data = coalesce_records[i],
                                .size = 141,
                                .version = 4,
                                .header_size = 20};
    assert(tun_rx_batch_push(&queue, &packet, monotonic_ms()));
  }
  blocked = true;
  unsigned before = calls;
  assert(end_receive_batch(&rx, monotonic_ms()));
  assert(calls == before + 1 && queue.count == 4 && !accepted_coalesce);
  assert(flush_packets(&rx, monotonic_ms()) && calls == before + 1);
  /* EAGAIN and EINTR leave all original records owned in FIFO order */
  blocked = false;
  interrupts = 2;
  begin_receive_batch(&rx);
  assert(flush_packets(&rx, monotonic_ms()));
  assert(end_receive_batch(&rx, monotonic_ms()));
  assert(!queue.count && accepted_coalesce == 4 && rx.aggregates == 1);
  assert(rx.written_packets == 4 && rx.coalesced_packets == 4);
  accepted_coalesce = 0;
  begin_receive_batch(&rx);
  for (unsigned i = 0; i < 4; i++) {
    uint8_t borrowed[160];
    memcpy(borrowed, coalesce_records[i], 141);
    qlinq_event_t event = {.record = {.data = borrowed, .size = 141}};
    assert(receive_packet(&rx, &event));
    memset(borrowed, 0xee, sizeof(borrowed));
  }
  assert(end_receive_batch(&rx, monotonic_ms()));
  assert(accepted_coalesce == 4 && !queue.count);
  /* a new service batch cannot merge with the blocked previous batch */
  accepted_coalesce = 0;
  blocked = true;
  begin_receive_batch(&rx);
  for (unsigned i = 0; i < 2; i++) {
    qlinq_event_t e = {.record = {.data = coalesce_records[i], .size = 141}};
    assert(receive_packet(&rx, &e));
  }
  assert(end_receive_batch(&rx, monotonic_ms()));
  begin_receive_batch(&rx);
  for (unsigned i = 2; i < 4; i++) {
    qlinq_event_t e = {.record = {.data = coalesce_records[i], .size = 141}};
    assert(receive_packet(&rx, &e));
  }
  assert(end_receive_batch(&rx, monotonic_ms()));
  blocked = false;
  unsigned ag = rx.aggregates;
  begin_receive_batch(&rx);
  assert(flush_packets(&rx, monotonic_ms()));
  assert(end_receive_batch(&rx, monotonic_ms()));
  assert(accepted_coalesce == 4 && rx.aggregates == ag + 2);
  /* an open batch's 1 ms deadline releases its prefix without batch end */
  accepted_coalesce = 0;
  begin_receive_batch(&rx);
  for (unsigned i = 0; i < 2; i++) {
    tun_packet_view_t p = {.data = coalesce_records[i],
                           .size = 141,
                           .version = 4,
                           .header_size = 20};
    assert(tun_rx_batch_push(&queue, &p, monotonic_ms() - 1));
  }
  assert(flush_packets(&rx, monotonic_ms()));
  assert(accepted_coalesce == 2 && !queue.count);
  assert(end_receive_batch(&rx, monotonic_ms()));
  /* an incompatible arrival flushes the prior prefix during its callback */
  accepted_coalesce = 0;
  coalesce_records[1][20 + 14]++;
  fixture_checksum(coalesce_records[1], 141);
  begin_receive_batch(&rx);
  for (unsigned i = 0; i < 2; i++) {
    qlinq_event_t e = {.record = {.data = coalesce_records[i], .size = 141}};
    assert(receive_packet(&rx, &e));
  }
  assert(accepted_coalesce >= 1);
  assert(end_receive_batch(&rx, monotonic_ms()));
  assert(accepted_coalesce == 2 && !queue.count);
  fixture_packet(coalesce_records[1], 4, 101, 5101, 101, 0x10, false);
  /* short writes latch failure without accepting or consuming any prefix */
  accepted_coalesce = 0;
  begin_receive_batch(&rx);
  for (unsigned i = 0; i < 2; i++) {
    tun_packet_view_t p = {.data = coalesce_records[i],
                           .size = 141,
                           .version = 4,
                           .header_size = 20};
    assert(tun_rx_batch_push(&queue, &p, monotonic_ms()));
  }
  short_write = true;
  assert(!end_receive_batch(&rx, monotonic_ms()));
  short_write = false;
  assert(queue.count == 2 && !accepted_coalesce && rx.failed);
  tun_rx_batch_cancel(&queue);
  rx.failed = false;
  /* expiry removes stale data before materialization; cancellation is final */
  begin_receive_batch(&rx);
  tun_packet_view_t p = {.data = coalesce_records[0],
                         .size = 141,
                         .version = 4,
                         .header_size = 20};
  assert(tun_rx_batch_push(&queue, &p, monotonic_ms() - 1000));
  before = calls;
  assert(end_receive_batch(&rx, monotonic_ms()));
  assert(!queue.count && calls == before);
  begin_receive_batch(&rx);
  assert(tun_rx_batch_push(&queue, &p, monotonic_ms()));
  tun_rx_batch_cancel(&queue);
  rx.stopped = true;
  qlinq_event_t e = {.record = {.data = coalesce_records[0], .size = 141}};
  assert(receive_packet(&rx, &e));
  assert(!queue.count);
  rx.stopped = false;
  accepted_coalesce = 0;
  fixture_packet(coalesce_records[0], 4, 101, 5000, 100, 0x19, false);
  begin_receive_batch(&rx);
  qlinq_event_t final = {.record = {.data = coalesce_records[0], .size = 141}};
  unsigned aggregates = rx.aggregates;
  assert(receive_packet(&rx, &final));
  assert(!queue.count && accepted_coalesce == 1 && rx.aggregates == aggregates);
  assert(end_receive_batch(&rx, monotonic_ms()));
  checking_coalesce = false;
}

static unsigned input_reads;
static bool bad_input, plain_input;
ssize_t __wrap_tun_read_vnet(int fd, void *data, size_t capacity,
                             tun_offload_t *metadata) {
  (void)fd;
  assert(capacity >= 104);
  uint8_t *p = data;
  memset(p, 0, 104);
  p[0] = 0x45;
  p[3] = 104;
  p[9] = 6;
  p[20 + 12] = 0x50;
  p[20 + 13] = 0x10;
  p[20 + 17] = 90; /* TCP pseudo-header seed: protocol + upper-layer length */
  for (unsigned i = 0; i < 64; i++)
    p[40 + i] = i;
  if (plain_input) {
    *metadata = (tun_offload_t){0};
    input_reads++;
    return 104;
  }
  *metadata = (tun_offload_t){.flags = bad_input ? 4 : TUN_CSUM_PARTIAL,
                              .gso_type = TUN_GSO_TCP4,
                              .header_length = 40,
                              .gso_size = 16,
                              .checksum_start = 20,
                              .checksum_offset = 16};
  input_reads++;
  return 104;
}

static void transmit_lifetimes(void) {
  tunnel_transmitter_t tx = {.vnet = true, .offload = true};
  uint8_t frame[TUN_TX_FRAME_CAPACITY + 1], saved[56];
  packet_t packet;
  tun_packet_output_t output;
  tun_packet_config_t config = {.mtu = 1400,
                                .max_packet_size = PACKET_CAPACITY};
  assert(read_transmit(&tx, 7, frame, &packet, &output, &config, 100) == 56);
  assert(input_reads == 1 && output.packet.data == packet.bytes);
  assert(tun_segment_remaining(&tx.plan) == 3 && packet.queued_ms == 100);
  memcpy(saved, packet.bytes, sizeof(saved));
  /* blocked publication keeps its own bounded record while pending */
  expire_transmit(&tx, 109, 10);
  assert(tun_segment_remaining(&tx.plan) == 3);
  assert(!memcmp(saved, output.packet.data, sizeof(saved)) && input_reads == 1);
  expire_transmit(&tx, 110, 10);
  assert(!tx.plan.pending && tx.dropped == 3);
  assert(!memcmp(saved, output.packet.data, sizeof(saved)));
  assert(read_transmit(&tx, 7, frame, &packet, &output, &config, 111) == 56);
  assert(input_reads == 2 && packet.queued_ms == 111);
  tx.dropped += tun_segment_cancel(&tx.plan);
  assert(tx.dropped ==
         6); /* disconnect discards the whole unmaterialized tail */
  bad_input = true;
  assert(read_transmit(&tx, 7, frame, &packet, &output, &config, 112) == -1);
  assert(errno == EBADMSG && !tx.plan.pending && tx.dropped == 7);
  bad_input = false;
  assert(read_transmit(&tx, 7, frame, &packet, &output, &config, 113) == 56);
  assert(input_reads == 4); /* invalid metadata does not poison the next read */
  assert(tun_segment_cancel(&tx.plan) == 3);
  plain_input = true;
  tx = (tunnel_transmitter_t){.vnet = true};
  memset(frame, 0xa5, sizeof(frame));
  assert(read_transmit(&tx, 7, frame, &packet, &output, &config, 114) == 104);
  assert(input_reads == 5 && !tx.plan.pending && tx.frames == 1);
  assert(packet.queued_ms == 114 && packet.bytes[0] == 0x45 &&
         frame[0] == 0xa5);
  tun_packet_input_t ordinary = {
      .data = packet.bytes, .size = 104, .origin = TUN_PACKET_FROM_DEVICE};
  assert(tun_packet_process(&config, &ordinary, &output, 1).status ==
         TUN_PACKET_OK);
  assert(output.packet.data == packet.bytes);
  plain_input = false;
  assert(read_transmit(&tx, 7, frame, &packet, &output, &config, 115) == -1);
  assert(errno == EBADMSG && tx.dropped == 1 && !tx.plan.pending);
}

/* verify QUIC control traffic progresses while TUN stays unwritable */
static void pressure_transport(bool coalesce) {
  tun_rx_batch_t queue;
  tun_rx_limits_t limits = {
      .packets = 4, .bytes = 256, .max_age_ms = 20, .flush_delay_ms = 1};
  assert(tun_rx_batch_init(&queue, &limits));
  tunnel_receiver_t receiver = {.queue = &queue,
                                .fd = 7,
                                .mtu = 1400,
                                .vnet = coalesce,
                                .coalesce = coalesce};
  qlinq_context_config_t cc = {.record_callback = receive_packet,
                               .record_user_data = &receiver};
  qlinq_context_t *context = qlinq_context_create(&cc);
  assert(context);
  qlinq_endpoint_config_t config = {
      .bind_addresses = {"127.0.0.1"},
      .bind_address_count = 1,
      .port = 19959,
      .security = {.shared_secret = "rx-pressure",
                   .shared_secret_size = 11,
                   .certificate_file = "t/assets/server.crt",
                   .private_key_file = "t/assets/server.key",
                   .allow_insecure_peer = true}};
  qlinq_endpoint_t *server = qlinq_listen(context, &config);
  config.security.certificate_file = config.security.private_key_file = NULL;
  config.remote_addresses[0] = "127.0.0.1";
  config.remote_address_count = 1;
  qlinq_endpoint_t *client = qlinq_connect(context, &config);
  assert(server && client);
  qlinq_stream_config_t sc = {.content_type = QLINQ_CONTENT_DATA,
                              .delivery = QLINQ_DELIVERY_RELIABLE,
                              .name = "rx-pressure"};
  qlinq_stream_t *publisher = qlinq_publish(server, &sc);
  receiver.subscriber = qlinq_subscribe(client, &sc);
  assert(publisher && receiver.subscriber);
  bool joined = false, closing = false, closed = false;
  uint8_t bytes[64] = {0x45, 0, 0, 64};
  qlinq_record_t record = {.data = bytes, .size = sizeof(bytes), .priority = 1};
  blocked = true;
  unsigned before_writes = writes;
  for (unsigned turn = 0; turn < 1000 && !closed; turn++) {
    begin_receive_batch(&receiver);
    unsigned before_calls = calls;
    assert(qlinq_service(context, 1) == QLINQ_STATUS_OK);
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_SUBSCRIBER_JOINED)
        joined = true;
      if (event.type == QLINQ_EVENT_PEER_DISCONNECTED)
        closed = true;
      qlinq_event_release(&event);
    }
    assert(end_receive_batch(&receiver, monotonic_ms()));
    assert(calls <= before_calls + 1);
    assert(queue.count <= limits.packets && queue.bytes <= limits.bytes);
    if (joined && !closing) {
      for (unsigned n = 0; n < 16; n++) {
        record.sequence++;
        qlinq_send_result_t sent = qlinq_stream_send(publisher, &record);
        assert(sent != QLINQ_SEND_INVALID && sent != QLINQ_SEND_FAILED);
      }
    }
    if (receiver.received >= 100 && !closing) {
      assert(queue.dropped > 0);
      assert(qlinq_endpoint_shutdown(server, "pressure control probe") ==
             QLINQ_STATUS_OK);
      closing = true;
    }
  }
  assert(closed && closing && receiver.received >= 100);
  assert(writes == before_writes);
  receiver.stopped = true;
  tun_rx_batch_cancel(&queue);
  assert(!queue.count && !queue.bytes);
  qlinq_context_destroy(context);
}

int main(void) {
  tun_rx_batch_t queue;
  tun_rx_limits_t limits = {.packets = TUN_RX_BATCH_CAPACITY,
                            .bytes = TUN_RX_BATCH_CAPACITY * 1400,
                            .max_age_ms = 1000,
                            .flush_delay_ms = 1};
  assert(tun_rx_batch_init(&queue, &limits));
  tunnel_receiver_t receiver = {.queue = &queue, .fd = 7, .mtu = 1400};
  uint8_t packet[64] = {0x45, 0, 0, 64};
  qlinq_event_t event = {.record = {.data = packet, .size = sizeof(packet)}};
  begin_receive_batch(&receiver);
  for (uint32_t i = 0; i < 2048; i++) {
    memcpy(packet + 20, &i, sizeof(i));
    assert(receive_packet(&receiver, &event));
  }
  assert(writes == 2048 && queue.count == 0 && queue.dropped == 0);
  assert(last_data == packet); /* no copy on the immediate path */
  assert(end_receive_batch(&receiver, monotonic_ms()));
  begin_receive_batch(&receiver);
  blocked = true;
  for (uint32_t i = 2048; i < 2050; i++) {
    memcpy(packet + 20, &i, sizeof(i));
    assert(receive_packet(&receiver, &event));
  }
  assert(queue.count == 2 && queue.dropped == 0);
  unsigned blocked_calls = calls;
  assert(end_receive_batch(&receiver, monotonic_ms()));
  assert(calls == blocked_calls); /* EAGAIN is not retried within the turn */
  blocked = false;
  begin_receive_batch(&receiver);
  assert(flush_packets(&receiver, monotonic_ms()));
  assert(writes == 2050 && queue.count == 0);
  event.record.size = 1;
  assert(receive_packet(&receiver, &event));
  assert(queue.dropped == 1);
  uint8_t oversized[1401] = {0x45, 0, 5, 121};
  event.record.data = oversized;
  event.record.size = sizeof(oversized);
  assert(receive_packet(&receiver, &event));
  assert(queue.dropped == 2 && writes == 2050);
  /* IPv6 follows the same borrowed fast path and MTU policy */
  memset(packet, 0, sizeof(packet));
  packet[0] = 0x60;
  packet[5] = sizeof(packet) - 40;
  uint32_t sequence = 2050;
  memcpy(packet + 20, &sequence, sizeof(sequence));
  event.record.data = packet;
  event.record.size = sizeof(packet);
  assert(receive_packet(&receiver, &event));
  assert(writes == 2051 && queue.count == 0 && queue.dropped == 2);
  assert(end_receive_batch(&receiver, monotonic_ms()));
  begin_receive_batch(&receiver);
  fail_write = true;
  assert(!receive_packet(&receiver, &event));
  fail_write = false;
  assert(!end_receive_batch(&receiver, monotonic_ms()));
  receiver.failed = false;
  begin_receive_batch(&receiver);
  short_write = true;
  assert(!receive_packet(&receiver, &event));
  short_write = false;
  assert(!end_receive_batch(&receiver, monotonic_ms()));
  receiver.failed = false;

  /* a permanent EINTR storm yields to timers and control after one budget */
  begin_receive_batch(&receiver);
  interrupts = RECEIVE_WRITE_BUDGET + 1;
  unsigned before_calls = calls;
  memcpy(packet + 20, &expected, sizeof(expected));
  assert(receive_packet(&receiver, &event));
  assert(calls - before_calls == RECEIVE_WRITE_BUDGET && queue.count == 1);
  assert(receiver.write_budget == 0);
  assert(end_receive_batch(&receiver, monotonic_ms()));
  begin_receive_batch(&receiver);
  assert(flush_packets(&receiver, monotonic_ms()));
  assert(queue.count == 0 && interrupts == 0);
  assert(end_receive_batch(&receiver, monotonic_ms()));

  blocked = true;
  begin_receive_batch(&receiver);
  unsigned prefix = expected;
  uint64_t drops = queue.dropped;
  before_calls = calls;
  for (uint32_t i = 0; i < TUN_RX_BATCH_CAPACITY + 6; i++) {
    uint32_t n = prefix + i;
    memcpy(packet + 20, &n, sizeof(n));
    assert(receive_packet(&receiver, &event));
  }
  assert(calls == before_calls + 1);
  assert(queue.count == TUN_RX_BATCH_CAPACITY && queue.bytes == 64 * 64);
  assert(queue.dropped == drops + 6);
  assert(end_receive_batch(&receiver, monotonic_ms()));
  uint64_t queued = queue.slots[queue.head].queued_ms;
  assert(receive_poll_timeout(&receiver, 50, queued + 997) == 3);
  assert(receive_poll_timeout(&receiver, 50, queued + 1000) == 0);
  blocked = false;
  begin_receive_batch(&receiver);
  assert(flush_packets(
      &receiver,
      monotonic_ms())); /* deep copies preserve the accepted prefix */
  assert(queue.count == 0 && queue.bytes == 0);
  assert(end_receive_batch(&receiver, monotonic_ms()));

  blocked = true;
  begin_receive_batch(&receiver);
  assert(receive_packet(&receiver, &event));
  drops = queue.dropped;
  tun_rx_batch_cancel(&queue); /* disconnect discards all retained data */
  assert(queue.dropped == drops + 1 && !queue.count);
  receiver.stopped = true;
  assert(receive_packet(&receiver, &event));
  assert(queue.count == 0); /* shutdown/drain callbacks cannot replay data */
  receiver.stopped = false;
  begin_receive_batch(&receiver);
  tun_packet_view_t owned = {
      .data = packet, .size = sizeof(packet), .version = 6, .header_size = 40};
  assert(tun_rx_batch_push(&queue, &owned, monotonic_ms()));
  blocked = false;
  fail_write = true;
  assert(!end_receive_batch(&receiver, monotonic_ms()));
  assert(queue.count == 1 &&
         receiver.failed); /* no false acceptance on error */
  before_calls = calls;
  assert(!receive_packet(&receiver, &event));
  assert(calls == before_calls);
  receiver.stopped = true;
  tun_rx_batch_cancel(&queue);
  fail_write = false;
  transmit_lifetimes();
  receive_coalescing();
  pressure_transport(false);
  pressure_transport(true);
  puts("===TUN DIRECT RECEIVE OK===");
  return 0;
}
