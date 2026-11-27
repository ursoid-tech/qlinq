#include "emcon_rateless.h"
#include "emcon_manifest.h"

#include "picotls/openssl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "EMCON rateless test failed: %s\n", message);            \
      return 1;                                                                \
    }                                                                          \
  } while (0)

typedef struct {
  uint8_t **packets;
  size_t *sizes;
  uint16_t *symbols;
  size_t count;
  size_t capacity;
} capture_t;

static bool capture_packet(void *user_data, uint16_t symbol_index,
                           const uint8_t *packet, size_t packet_size) {
  capture_t *capture = user_data;
  if (capture->count == capture->capacity)
    return false;
  capture->packets[capture->count] = malloc(packet_size);
  if (!capture->packets[capture->count])
    return false;
  memcpy(capture->packets[capture->count], packet, packet_size);
  capture->sizes[capture->count] = packet_size;
  capture->symbols[capture->count] = symbol_index;
  capture->count++;
  return true;
}

static int test_late_join(void) {
  const uint8_t secret[32] = {0x37};
  const uint8_t payload[] = "late multicast delivery";
  const uint64_t first = 100, last = first + QUICLY_FLEXICAST_SENT_WINDOW + 1;
  uint8_t packet[128];
  size_t packet_size;
  uint64_t number;
  qlinq_emcon_sender_t *sender = NULL;
  CHECK(qlinq_emcon_sender_create(&sender, 44, 3, first, first, secret,
                                  sizeof(secret)) == QLINQ_EMCON_OK,
        "create EMCON sender before listeners exist");
  for (uint64_t expected = first; expected <= last; ++expected) {
    CHECK(qlinq_emcon_flexicast_seal(sender, QLINQ_EMCON_RECORD_DATA,
                                     ptls_iovec_init(payload, sizeof(payload)),
                                     packet, sizeof(packet), &packet_size,
                                     &number) == QLINQ_EMCON_OK &&
              number == expected,
          "continue sending past the connected flow's history window");
  }
  qlinq_emcon_sender_free(sender);

  for (size_t i = 0; i < 2; ++i) {
    quicly_flexicast_flow_t *receiver = NULL;
    CHECK(qlinq_emcon_flexicast_create(&receiver, 44, 3, first, secret,
                                       sizeof(secret)) == QLINQ_EMCON_OK,
          "initialize a late listener from the initial epoch");
    uint8_t copy[sizeof(packet)];
    memcpy(copy, packet, packet_size);
    ptls_iovec_t decoded;
    CHECK(quicly_flexicast_receive_datagram(receiver, copy, packet_size,
                                            &decoded, &number, 0,
                                            0) == QUICLY_FLEXICAST_OK &&
              number == last && decoded.len == 1 + sizeof(payload) &&
              decoded.base[0] == QLINQ_EMCON_RECORD_DATA &&
              memcmp(decoded.base + 1, payload, sizeof(payload)) == 0,
          "ordinary Flexicast decoder reads the EMCON DATAGRAM");
    memcpy(copy, packet, packet_size);
    CHECK(quicly_flexicast_receive_datagram(receiver, copy, packet_size,
                                            &decoded, &number, 0,
                                            0) == QUICLY_FLEXICAST_ERROR_REPLAY,
          "ordinary Flexicast decoder rejects a replay");
    quicly_flexicast_flow_free(receiver);
  }
  puts("===EMCON LATE JOIN OK===");
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--late-join") == 0)
    return test_late_join();
  if (argc != 1)
    return 1;
  enum { PACKET_CAPACITY = 128 };
  uint8_t secret[PTLS_MAX_DIGEST_SIZE] = {0};
  uint8_t input[5000], second[5000], third[5000];
  uint8_t *packets[PACKET_CAPACITY] = {0};
  size_t sizes[PACKET_CAPACITY] = {0};
  uint16_t symbols[PACKET_CAPACITY] = {0};
  capture_t capture = {.packets = packets,
                       .sizes = sizes,
                       .symbols = symbols,
                       .capacity = PACKET_CAPACITY};

  for (size_t i = 0; i < sizeof(input); i++) {
    input[i] = (uint8_t)(i * 37U + 11U);
    second[i] = (uint8_t)(i * 17U + 3U);
    third[i] = (uint8_t)(i * 29U + 5U);
  }
  memset(secret, 0xa6, ptls_openssl_aes128gcmsha256.hash->digest_size);
  qlinq_emcon_sender_t *sender = NULL;
  quicly_flexicast_flow_t *receiver_protection = NULL;
  size_t secret_size = ptls_openssl_aes128gcmsha256.hash->digest_size;
  CHECK(qlinq_emcon_sender_create(&sender, 44, 3, 1000, 1000, secret,
                                  secret_size) == QLINQ_EMCON_OK &&
            qlinq_emcon_flexicast_create(&receiver_protection, 44, 3, 1000,
                                         secret, secret_size) == QLINQ_EMCON_OK,
        "protection setup");

  qlinq_emcon_rateless_config_t config = {
      .alias = 7, .symbol_size = 256, .repair_symbols = 10};
  CHECK(qlinq_emcon_send_object(sender, &config, 12, 34, true, 2, input,
                                sizeof(input), capture_packet,
                                &capture) == QLINQ_EMCON_OK,
        "encode object");
  CHECK(capture.count == 30, "expected original plus repair count");

  /* Drop five original symbols, then deliver everything else in reverse order.
   * This exercises proactive RaptorQ repair and packet reordering without any
   * feedback path. */
  qlinq_emcon_receiver_t *receiver =
      qlinq_emcon_receiver_create(receiver_protection, 7);
  CHECK(receiver, "receiver setup");
  qlinq_emcon_record_t record = {0};
  int result = QLINQ_EMCON_INCOMPLETE;
  for (size_t at = capture.count; at-- > 0;) {
    if (symbols[at] < 5)
      continue;
    result =
        qlinq_emcon_receiver_ingest(receiver, packets[at], sizes[at], &record);
    CHECK(result == QLINQ_EMCON_INCOMPLETE || result == QLINQ_EMCON_OK,
          "ingest protected symbol");
    if (result == QLINQ_EMCON_OK)
      break;
  }
  CHECK(result == QLINQ_EMCON_OK, "reconstruct without feedback");
  CHECK(record.alias == 7 && record.group_id == 12 && record.object_id == 34 &&
            record.keyframe && record.priority == 2 &&
            record.size == sizeof(input) &&
            memcmp(record.data, input, sizeof(input)) == 0,
        "exact reconstructed record");

  qlinq_emcon_record_release(&record);

  /* Keep two objects active at once and deliver both in a crossed order. FEC
   * reordering is useful only if the receive window does not discard symbols
   * from the adjacent object. */
  CHECK(qlinq_emcon_send_object(sender, &config, 12, 35, false, 1, second,
                                sizeof(second), capture_packet,
                                &capture) == QLINQ_EMCON_OK &&
            qlinq_emcon_send_object(sender, &config, 12, 36, false, 1, third,
                                    sizeof(third), capture_packet,
                                    &capture) == QLINQ_EMCON_OK &&
            capture.count == 90,
        "encode interleaved objects");
  bool second_complete = false, third_complete = false;
  for (size_t offset = 30; offset-- > 0;) {
    size_t indices[2] = {30 + offset, 60 + offset};
    for (size_t which = 0; which < 2; which++) {
      size_t at = indices[which];
      if (symbols[at] < 5)
        continue;
      result = qlinq_emcon_receiver_ingest(receiver, packets[at], sizes[at],
                                           &record);
      CHECK(result == QLINQ_EMCON_INCOMPLETE || result == QLINQ_EMCON_OK ||
                result == QLINQ_EMCON_DUPLICATE,
            "ingest crossed object symbol");
      if (result != QLINQ_EMCON_OK)
        continue;
      if (record.object_id == 35) {
        CHECK(record.size == sizeof(second) &&
                  memcmp(record.data, second, sizeof(second)) == 0,
              "second interleaved object");
        second_complete = true;
      } else if (record.object_id == 36) {
        CHECK(record.size == sizeof(third) &&
                  memcmp(record.data, third, sizeof(third)) == 0,
              "third interleaved object");
        third_complete = true;
      } else {
        CHECK(false, "unexpected interleaved object identity");
      }
      qlinq_emcon_record_release(&record);
    }
  }
  CHECK(second_complete && third_complete,
        "both interleaved objects reconstructed");

  uint8_t replay_packets[3][64];
  size_t replay_sizes[3];
  uint8_t payload = 0;
  uint64_t number;
  for (size_t i = 0; i <= QLINQ_EMCON_REPLAY_WINDOW_PACKETS; i++) {
    size_t slot = i < 2 ? i : 2;
    CHECK(qlinq_emcon_flexicast_seal(
              sender, QLINQ_EMCON_RECORD_SESSION, ptls_iovec_init(&payload, 1),
              replay_packets[slot], sizeof(replay_packets[slot]),
              &replay_sizes[slot], &number) == QLINQ_EMCON_OK,
          "seal replay-window test packet");
  }
  qlinq_emcon_message_t replay_message;
  CHECK(qlinq_emcon_flexicast_open(receiver_protection, replay_packets[2],
                                   replay_sizes[2],
                                   &replay_message) == QLINQ_EMCON_OK &&
            qlinq_emcon_flexicast_open(receiver_protection, replay_packets[1],
                                       replay_sizes[1],
                                       &replay_message) == QLINQ_EMCON_OK &&
            qlinq_emcon_flexicast_open(receiver_protection, replay_packets[0],
                                       replay_sizes[0], &replay_message) ==
                QLINQ_EMCON_DUPLICATE,
        "accept reordering within the advertised window and reject older "
        "packets");

  uint64_t before_failed_emit = qlinq_emcon_sender_next_packet_number(sender);
  capture_t rejected = {0};
  CHECK(qlinq_emcon_send_object(sender, &config, 12, 37, false, 1, input,
                                sizeof(input), capture_packet,
                                &rejected) == QLINQ_EMCON_EMIT_FAILED &&
            qlinq_emcon_flexicast_seal(
                sender, QLINQ_EMCON_RECORD_SESSION,
                ptls_iovec_init(&payload, 1), replay_packets[0],
                sizeof(replay_packets[0]), &replay_sizes[0],
                &number) == QLINQ_EMCON_OK &&
            number == before_failed_emit + 1,
        "a failed FEC emission still consumes its protected packet number");

  qlinq_emcon_receiver_free(receiver);
  quicly_flexicast_flow_free(receiver_protection);
  qlinq_emcon_sender_free(sender);
  for (size_t i = 0; i < capture.count; i++)
    free(packets[i]);
  puts("===EMCON RATELESS OK===");
  return 0;
}
