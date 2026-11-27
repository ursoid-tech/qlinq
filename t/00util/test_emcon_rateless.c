#include "../../src/emcon/emcon_rateless.h"
#include "../../src/emcon/emcon_manifest.h"
#include "transport_wire.h"

#include "picotls/openssl.h"
#include "quicly/defaults.h"

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

static int open_and_ingest_record(qlinq_emcon_ingress_t *ingress,
                                  qlinq_emcon_receiver_t *receiver,
                                  uint8_t *packet, size_t packet_size,
                                  qlinq_emcon_record_t *record) {
  ptls_iovec_t datagram;
  uint64_t pn;
  qlinq_emcon_event_t event;
  memset(record, 0, sizeof(*record));
  int ret =
      qlinq_emcon_flexicast_open(ingress, packet, packet_size, &datagram, &pn);
  if (ret != QLINQ_EMCON_OK)
    return ret;
  ret = qlinq_emcon_receiver_ingest(receiver, pn, datagram, &event);
  if (ret != QLINQ_EMCON_OK)
    return ret;
  if (event.type != QLINQ_EMCON_EVENT_RECORD)
    return QLINQ_EMCON_ERR_INVALID;
  *record = event.value.record;
  return QLINQ_EMCON_OK;
}

static int ingest_symbol(qlinq_emcon_receiver_t *receiver, uint64_t pn,
                         uint64_t group, uint64_t object, uint16_t index,
                         qlinq_emcon_event_t *event) {
  uint8_t wire[QLINQ_WIRE_FEC_HEADER_SIZE + 1];
  qlinq_wire_fec_header_t header = {.alias = 7,
                                    .group_id = group,
                                    .object_id = object,
                                    .symbol_index = index,
                                    .data_symbols = 3,
                                    .total_symbols = 4,
                                    .symbol_size = 1,
                                    .original_size = 3};
  if (qlinq_wire_encode_fec_header(wire, sizeof(wire), &header) !=
      QLINQ_WIRE_OK)
    return QLINQ_EMCON_ERR_INVALID;
  wire[QLINQ_WIRE_FEC_HEADER_SIZE] = (uint8_t)('A' + index);
  return qlinq_emcon_receiver_ingest(
      receiver, pn, ptls_iovec_init(wire, sizeof(wire)), event);
}

static int test_partial_objects(void) {
  CHECK(qlinq_emcon_receiver_create(7, 1, 1, 0) == NULL &&
            qlinq_emcon_receiver_create(7, 0, 1, 64) == NULL &&
            qlinq_emcon_receiver_create(7, 1, 0, 64) == NULL,
        "reject zero geometry or maximum record size");
  qlinq_emcon_receiver_t *receiver = qlinq_emcon_receiver_create(7, 1, 1, 64);
  CHECK(receiver != NULL, "create bounded object assembler");
  qlinq_emcon_event_t event;
  uint64_t pn = 100;
  for (uint64_t i = 0; i < QLINQ_EMCON_MAX_ACTIVE_OBJECTS; ++i)
    CHECK(ingest_symbol(receiver, pn++, 1, i, 0, &event) ==
              QLINQ_EMCON_INCOMPLETE,
          "leave one partial object in each slot");
  CHECK(ingest_symbol(receiver, pn++, 1, 0, 1, &event) ==
            QLINQ_EMCON_INCOMPLETE,
        "refresh an object with a useful new symbol");
  CHECK(ingest_symbol(receiver, pn++, 2, 0, 0, &event) ==
            QLINQ_EMCON_INCOMPLETE,
        "start a new group after permanent loss fills the slots");
  CHECK(ingest_symbol(receiver, 99, 1, 1, 1, &event) == QLINQ_EMCON_INCOMPLETE,
        "a delayed symbol cannot evict newer partial objects");
  CHECK(ingest_symbol(receiver, pn++, 1, 2, 1, &event) ==
                QLINQ_EMCON_INCOMPLETE &&
            ingest_symbol(receiver, pn++, 1, 2, 2, &event) == QLINQ_EMCON_OK &&
            event.value.record.object_id == 2,
        "the oldest retained object survives the delayed symbol");
  qlinq_emcon_event_release(&event);
  CHECK(ingest_symbol(receiver, pn++, 1, 0, 2, &event) == QLINQ_EMCON_OK &&
            event.type == QLINQ_EMCON_EVENT_RECORD &&
            event.value.record.group_id == 1 && event.value.record.size == 3 &&
            memcmp(event.value.record.data, "ABC", 3) == 0,
        "keep the recently active object and its data");
  qlinq_emcon_event_release(&event);
  CHECK(ingest_symbol(receiver, pn++, 2, 0, 1, &event) ==
                QLINQ_EMCON_INCOMPLETE &&
            ingest_symbol(receiver, pn, 2, 0, 2, &event) == QLINQ_EMCON_OK &&
            event.type == QLINQ_EMCON_EVENT_RECORD &&
            event.value.record.group_id == 2 && event.value.record.size == 3 &&
            memcmp(event.value.record.data, "ABC", 3) == 0,
        "deliver a complete record from the newer group");
  qlinq_emcon_event_release(&event);

  uint8_t bad_wire[QLINQ_WIRE_FEC_HEADER_SIZE + 1500] = {0};
  qlinq_wire_fec_header_t wrong_sym = {.alias = 7,
                                       .group_id = 9,
                                       .object_id = 0,
                                       .symbol_index = 0,
                                       .data_symbols = 1,
                                       .total_symbols = 2,
                                       .symbol_size = 64,
                                       .original_size = 64};
  CHECK(qlinq_wire_encode_fec_header(bad_wire, sizeof(bad_wire), &wrong_sym) ==
                QLINQ_WIRE_OK &&
            qlinq_emcon_receiver_ingest(
                receiver, 498,
                ptls_iovec_init(bad_wire, QLINQ_WIRE_FEC_HEADER_SIZE + 64),
                &event) == QLINQ_EMCON_ERR_INVALID,
        "reject symbol_size exceeding manifest FEC geometry");

  qlinq_wire_fec_header_t wrong_repairs = {.alias = 7,
                                           .group_id = 9,
                                           .object_id = 0,
                                           .symbol_index = 0,
                                           .data_symbols = 1,
                                           .total_symbols = 1024,
                                           .symbol_size = 1,
                                           .original_size = 1};
  CHECK(qlinq_wire_encode_fec_header(bad_wire, sizeof(bad_wire),
                                     &wrong_repairs) == QLINQ_WIRE_OK &&
            qlinq_emcon_receiver_ingest(
                receiver, 499,
                ptls_iovec_init(bad_wire, QLINQ_WIRE_FEC_HEADER_SIZE + 1),
                &event) == QLINQ_EMCON_ERR_INVALID,
        "reject repair_symbols exceeding manifest FEC geometry");

  qlinq_emcon_receiver_t *receiver64 =
      qlinq_emcon_receiver_create(7, 64, 1, 64);
  qlinq_emcon_receiver_t *receiver32 =
      qlinq_emcon_receiver_create(7, 32, 1, 64);
  qlinq_emcon_receiver_t *receiver65 =
      qlinq_emcon_receiver_create(7, 65, 1, 64);
  CHECK(receiver64 && receiver32 && receiver65,
        "create geometry-specific test assemblers");

  qlinq_wire_fec_header_t padded_tail = {.alias = 7,
                                         .group_id = 9,
                                         .object_id = 1,
                                         .symbol_index = 0,
                                         .data_symbols = 1,
                                         .total_symbols = 2,
                                         .symbol_size = 64,
                                         .original_size = 20};
  CHECK(qlinq_wire_encode_fec_header(bad_wire, sizeof(bad_wire),
                                     &padded_tail) == QLINQ_WIRE_OK &&
            qlinq_emcon_receiver_ingest(
                receiver64, 500,
                ptls_iovec_init(bad_wire, QLINQ_WIRE_FEC_HEADER_SIZE + 64),
                &event) == QLINQ_EMCON_ERR_INVALID,
        "reject zero-padded v2 final source symbol");

  qlinq_wire_fec_header_t loose_k = {.alias = 7,
                                     .group_id = 9,
                                     .object_id = 2,
                                     .symbol_index = 0,
                                     .data_symbols = 2,
                                     .total_symbols = 3,
                                     .symbol_size = 32,
                                     .original_size = 32};
  CHECK(qlinq_wire_encode_fec_header(bad_wire, sizeof(bad_wire), &loose_k) ==
                QLINQ_WIRE_OK &&
            qlinq_emcon_receiver_ingest(
                receiver32, 501,
                ptls_iovec_init(bad_wire, QLINQ_WIRE_FEC_HEADER_SIZE + 32),
                &event) == QLINQ_EMCON_ERR_INVALID,
        "reject empty trailing source symbols");

  qlinq_wire_fec_header_t oversize = {.alias = 7,
                                      .group_id = 9,
                                      .object_id = 3,
                                      .symbol_index = 0,
                                      .data_symbols = 1,
                                      .total_symbols = 2,
                                      .symbol_size = 65,
                                      .original_size = 65};
  CHECK(qlinq_wire_encode_fec_header(bad_wire, sizeof(bad_wire), &oversize) ==
                QLINQ_WIRE_OK &&
            qlinq_emcon_receiver_ingest(
                receiver65, 502,
                ptls_iovec_init(bad_wire, QLINQ_WIRE_FEC_HEADER_SIZE + 65),
                &event) == QLINQ_EMCON_ERR_INVALID,
        "reject object exceeding stream maximum_record_size");

  qlinq_emcon_receiver_free(receiver65);
  qlinq_emcon_receiver_free(receiver32);
  qlinq_emcon_receiver_free(receiver64);
  qlinq_emcon_receiver_free(receiver);
  return 0;
}

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

static int test_receive_packet_hardening(void) {
  const uint8_t secret[32] = {0x49};
  const uint8_t digest[QLINQ_EMCON_MANIFEST_DIGEST_SIZE] = {0x91};
  const uint8_t other_digest[QLINQ_EMCON_MANIFEST_DIGEST_SIZE] = {0x92};
  qlinq_emcon_sender_t *sender = NULL;
  qlinq_emcon_ingress_t *other_rx = NULL, *limited_rx = NULL, *strict_rx = NULL;
  CHECK(qlinq_emcon_sender_create(&sender, 77, 1, digest, 0, 64, 1, 64, secret,
                                  sizeof(secret)) == QLINQ_EMCON_OK &&
            qlinq_emcon_ingress_create(&other_rx, 77, 1, other_digest, 0,
                                       secret,
                                       sizeof(secret)) == QLINQ_EMCON_OK &&
            qlinq_emcon_ingress_create(&limited_rx, 77, 1, other_digest, 1,
                                       secret,
                                       sizeof(secret)) == QLINQ_EMCON_OK &&
            qlinq_emcon_ingress_create(&strict_rx, 77, 1, digest, 1, secret,
                                       sizeof(secret)) == QLINQ_EMCON_OK,
        "create hardened receive flows");

  uint8_t packet[128], copy[128];
  size_t packet_size = 0;
  uint64_t pn = 0;
  ptls_iovec_t datagram;
  qlinq_emcon_receiver_t *assembler = qlinq_emcon_receiver_create(7, 64, 1, 64);
  qlinq_emcon_event_t event;
  CHECK(assembler &&
            qlinq_emcon_seal_end(sender, 7, 3, 42, packet, sizeof(packet),
                                 &packet_size, &pn) == QLINQ_EMCON_OK,
        "seal terminal metadata packet");
  memcpy(copy, packet, packet_size);
  CHECK(qlinq_emcon_flexicast_open(strict_rx, copy, packet_size, &datagram,
                                   &pn) == QLINQ_EMCON_OK &&
            qlinq_emcon_receiver_ingest(assembler, pn, datagram, &event) ==
                QLINQ_EMCON_OK &&
            event.type == QLINQ_EMCON_EVENT_END && event.value.end.alias == 7 &&
            event.value.end.group_id == 3 &&
            event.value.end.final_object_id == 42,
        "authenticate and decode TRACK_END frame");
  qlinq_emcon_event_release(&event);
  qlinq_emcon_receiver_free(assembler);

  /* valid packets must not consume max_authentication_failures budget */
  uint8_t second_pkt[128];
  size_t second_size = 0;
  CHECK(qlinq_emcon_seal_end(sender, 7, 3, 42, second_pkt, sizeof(second_pkt),
                             &second_size, &pn) == QLINQ_EMCON_OK &&
            qlinq_emcon_flexicast_open(strict_rx, second_pkt, second_size,
                                       &datagram, &pn) == QLINQ_EMCON_OK &&
            qlinq_emcon_ingress_authentication_failures(strict_rx) == 0,
        "multiple valid packets succeed with max_authentication_failures=1");

  uint8_t bad_pkt[128];
  size_t bad_size = 0;
  CHECK(qlinq_emcon_seal_end(sender, 7, 3, 42, bad_pkt, sizeof(bad_pkt),
                             &bad_size, &pn) == QLINQ_EMCON_OK,
        "encode packet for tag corruption");
  bad_pkt[bad_size - 1] ^= 0x01U;
  CHECK(qlinq_emcon_flexicast_open(strict_rx, bad_pkt, bad_size, &datagram,
                                   &pn) == QLINQ_EMCON_ERR_CRYPTO &&
            qlinq_emcon_ingress_authentication_failures(strict_rx) == 1,
        "first failed authentication trips max_authentication_failures=1");

  /* manifest digest mismatch must fail AEAD and trip failure limit */
  memcpy(copy, packet, packet_size);
  CHECK(qlinq_emcon_flexicast_open(other_rx, copy, packet_size, &datagram,
                                   &pn) == QLINQ_EMCON_DISCARDED &&
            qlinq_emcon_ingress_authentication_failures(other_rx) == 1,
        "discard packet bound to another manifest digest");
  memcpy(copy, packet, packet_size);
  CHECK(qlinq_emcon_flexicast_open(limited_rx, copy, packet_size, &datagram,
                                   &pn) == QLINQ_EMCON_ERR_CRYPTO,
        "trip failure limit on wrong manifest digest");

  qlinq_emcon_ingress_free(strict_rx);
  qlinq_emcon_ingress_free(limited_rx);
  qlinq_emcon_ingress_free(other_rx);
  qlinq_emcon_sender_free(sender);
  return 0;
}

static int test_late_join(void) {
  const uint8_t secret[32] = {0x37};
  const uint8_t digest[QLINQ_EMCON_MANIFEST_DIGEST_SIZE] = {0x55};
  const uint8_t payload[] = "late multicast delivery";
  const uint64_t start_pn = 70000;
  const uint64_t last = start_pn + QUICLY_FLEXICAST_SENT_WINDOW + 5;
  uint8_t packet[128];
  size_t packet_size;
  uint64_t number;
  qlinq_emcon_sender_t *sender = NULL;
  CHECK(qlinq_emcon_sender_create(&sender, 44, 3, digest, start_pn, 64, 1, 64,
                                  secret, sizeof(secret)) == QLINQ_EMCON_OK,
        "create EMCON sender past 16-bit PN range");
  for (uint64_t expected = start_pn; expected <= last; ++expected) {
    CHECK(qlinq_emcon_flexicast_seal(
              sender, ptls_iovec_init(payload, sizeof(payload)), packet,
              sizeof(packet), &packet_size, &number) == QLINQ_EMCON_OK &&
              number == expected,
          "continue sending past connected flow history window");
  }
  qlinq_emcon_sender_free(sender);

  for (size_t i = 0; i < 2; ++i) {
    qlinq_emcon_ingress_t *receiver = NULL;
    CHECK(qlinq_emcon_ingress_create(&receiver, 44, 3, digest, 0, secret,
                                     sizeof(secret)) == QLINQ_EMCON_OK,
          "initialize late listener at epoch start");
    uint8_t copy[sizeof(packet)];
    memcpy(copy, packet, packet_size);
    ptls_iovec_t datagram;
    uint64_t opened_pn;
    CHECK(qlinq_emcon_flexicast_open(receiver, copy, packet_size, &datagram,
                                     &opened_pn) == QLINQ_EMCON_OK &&
              (copy[0] & 3U) == 3U && opened_pn == last &&
              datagram.len == sizeof(payload) &&
              memcmp(datagram.base, payload, sizeof(payload)) == 0,
          "late listener authenticates 4-byte PN directly");
    memcpy(copy, packet, packet_size);
    CHECK(qlinq_emcon_flexicast_open(receiver, copy, packet_size, &datagram,
                                     &opened_pn) == QLINQ_EMCON_DUPLICATE,
          "ingress decoder rejects replay");
    qlinq_emcon_ingress_free(receiver);
  }
  return 0;
}

static int test_packet_number_ceiling(void) {
  const uint8_t secret[32] = {0x38};
  const uint8_t digest[QLINQ_EMCON_MANIFEST_DIGEST_SIZE] = {0x56};
  const uint64_t ceiling = QLINQ_EMCON_MAX_PACKETS_PER_KEY - 1;
  uint8_t payload[] = "last packet";
  qlinq_emcon_sender_t *sender = NULL;
  qlinq_emcon_ingress_t *receiver = NULL;
  CHECK(qlinq_emcon_sender_create(&sender, 44, 4, digest, ceiling, 64, 1, 64,
                                  secret, sizeof(secret)) == QLINQ_EMCON_OK &&
            qlinq_emcon_ingress_create(&receiver, 44, 4, digest, 0, secret,
                                       sizeof(secret)) == QLINQ_EMCON_OK,
        "initialize sender at final epoch packet number");
  uint8_t packet[128], replay[sizeof(packet)];
  size_t packet_size;
  uint64_t number, opened_pn;
  ptls_iovec_t data = ptls_iovec_init(payload, sizeof(payload)), opened;
  CHECK(qlinq_emcon_flexicast_seal(sender, data, packet, sizeof(packet),
                                   &packet_size, &number) == QLINQ_EMCON_OK &&
            number == ceiling &&
            qlinq_emcon_sender_next_packet_number(sender) == ceiling + 1,
        "seal final epoch packet number");
  memcpy(replay, packet, packet_size);
  CHECK(qlinq_emcon_flexicast_open(receiver, packet, packet_size, &opened,
                                   &opened_pn) == QLINQ_EMCON_OK &&
            opened_pn == ceiling && opened.len == sizeof(payload) &&
            memcmp(opened.base, payload, sizeof(payload)) == 0 &&
            qlinq_emcon_flexicast_open(receiver, replay, packet_size, &opened,
                                       &opened_pn) == QLINQ_EMCON_DUPLICATE,
        "authenticate final epoch packet and reject replay");
  CHECK(qlinq_emcon_flexicast_seal(sender, data, packet, sizeof(packet),
                                   &packet_size,
                                   &number) == QLINQ_EMCON_ERR_EXHAUSTED,
        "refuse to seal past per-key packet limit");
  qlinq_emcon_ingress_free(receiver);
  qlinq_emcon_sender_free(sender);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--late-join") == 0) {
    if (test_late_join() != 0 || test_packet_number_ceiling() != 0 ||
        test_receive_packet_hardening() != 0)
      return 1;
    puts("===EMCON LATE JOIN OK===");
    return 0;
  }
  if (argc != 1)
    return 1;
  CHECK(test_partial_objects() == 0, "bounded assembly after loss");
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
  size_t secret_size = ptls_openssl_aes128gcmsha256.hash->digest_size;
  memset(secret, 0xa6, secret_size);
  const uint8_t digest[QLINQ_EMCON_MANIFEST_DIGEST_SIZE] = {0x57};
  qlinq_emcon_sender_t *sender = NULL;
  qlinq_emcon_ingress_t *receiver_protection = NULL;
  CHECK(qlinq_emcon_sender_create(&sender, 44, 3, digest, 1000, 256, 10, 8192,
                                  secret, secret_size) == QLINQ_EMCON_OK &&
            qlinq_emcon_ingress_create(&receiver_protection, 44, 3, digest, 0,
                                       secret, secret_size) == QLINQ_EMCON_OK,
        "protection setup");

  CHECK(qlinq_emcon_send_object(sender, 7, 12, 34, true, 2, input,
                                sizeof(input), capture_packet,
                                &capture) == QLINQ_EMCON_OK,
        "encode object");
  CHECK(capture.count == 30, "expected original plus repair count");

  /* verify systematic emission order and v2 tail omission (136 B) */
  size_t short_symbols = 0;
  for (size_t i = 0; i < capture.count; i++) {
    CHECK(symbols[i] == i, "emit source symbols before repair symbols");
    if (symbols[i] == 19) {
      CHECK(sizes[i] == 212, "final source symbol omits implicit zero tail");
      short_symbols++;
    } else {
      CHECK(sizes[i] == 332, "full source and repair symbols use symbol_size");
    }
  }
  CHECK(short_symbols == 1, "exactly one short final source symbol");

  /* drop five original symbols and deliver the rest in reverse order */
  qlinq_emcon_receiver_t *receiver =
      qlinq_emcon_receiver_create(7, 256, 10, 8192);
  CHECK(receiver, "receiver setup");
  qlinq_emcon_record_t record = {0};
  int result = QLINQ_EMCON_INCOMPLETE;
  for (size_t at = capture.count; at-- > 0;) {
    if (symbols[at] < 5)
      continue;
    result = open_and_ingest_record(receiver_protection, receiver, packets[at],
                                    sizes[at], &record);
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

  /* interleave two active objects to verify FEC receive window retention */
  CHECK(qlinq_emcon_send_object(sender, 7, 12, 35, false, 1, second,
                                sizeof(second), capture_packet,
                                &capture) == QLINQ_EMCON_OK &&
            qlinq_emcon_send_object(sender, 7, 12, 36, false, 1, third,
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
      result = open_and_ingest_record(receiver_protection, receiver,
                                      packets[at], sizes[at], &record);
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

  uint8_t replay_packets[3][96];
  size_t replay_sizes[3];
  uint64_t number, opened_pn;
  ptls_iovec_t opened;
  for (size_t i = 0; i <= QLINQ_EMCON_REPLAY_WINDOW_PACKETS; i++) {
    size_t slot = i < 2 ? i : 2;
    CHECK(qlinq_emcon_seal_end(sender, 7, 12, 36, replay_packets[slot],
                               sizeof(replay_packets[slot]),
                               &replay_sizes[slot], &number) == QLINQ_EMCON_OK,
          "seal replay-window test packet");
  }
  CHECK(qlinq_emcon_flexicast_open(receiver_protection, replay_packets[2],
                                   replay_sizes[2], &opened,
                                   &opened_pn) == QLINQ_EMCON_OK &&
            qlinq_emcon_flexicast_open(receiver_protection, replay_packets[1],
                                       replay_sizes[1], &opened,
                                       &opened_pn) == QLINQ_EMCON_OK &&
            qlinq_emcon_flexicast_open(receiver_protection, replay_packets[0],
                                       replay_sizes[0], &opened,
                                       &opened_pn) == QLINQ_EMCON_DUPLICATE,
        "accept reordering within the advertised window and reject older "
        "packets");

  uint64_t before_failed_emit = qlinq_emcon_sender_next_packet_number(sender);
  capture_t rejected = {0};
  CHECK(qlinq_emcon_send_object(sender, 7, 12, 37, false, 1, input,
                                sizeof(input), capture_packet,
                                &rejected) == QLINQ_EMCON_ERR_EMIT_FAILED &&
            qlinq_emcon_seal_end(sender, 7, 12, 37, replay_packets[0],
                                 sizeof(replay_packets[0]), &replay_sizes[0],
                                 &number) == QLINQ_EMCON_OK &&
            number == before_failed_emit + 1,
        "a failed FEC emission still consumes its protected packet number");

  qlinq_emcon_receiver_free(receiver);
  qlinq_emcon_ingress_free(receiver_protection);
  qlinq_emcon_sender_free(sender);
  for (size_t i = 0; i < capture.count; i++)
    free(packets[i]);
  puts("===EMCON RATELESS OK===");
  return 0;
}
