#include "emcon_rateless.h"

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

static quicly_flexicast_flow_t *make_flow(const uint8_t *secret, bool sender) {
  quicly_flexicast_flow_t *flow = NULL;
  return qlinq_emcon_flexicast_create(
             &flow, 44, 3, 1000, secret,
             ptls_openssl_aes128gcmsha256.hash->digest_size,
             sender) == QLINQ_EMCON_OK
             ? flow
             : NULL;
}

int main(void) {
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
  quicly_flexicast_flow_t *sender = make_flow(secret, true);
  quicly_flexicast_flow_t *receiver_protection = make_flow(secret, false);
  CHECK(sender && receiver_protection, "protection setup");

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

  qlinq_emcon_receiver_free(receiver);
  quicly_flexicast_flow_free(receiver_protection);
  quicly_flexicast_flow_free(sender);
  for (size_t i = 0; i < capture.count; i++)
    free(packets[i]);
  puts("===EMCON RATELESS OK===");
  return 0;
}
