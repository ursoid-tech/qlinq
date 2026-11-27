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
  qlinq_emcon_message_t message;
  qlinq_emcon_event_t event;
  memset(record, 0, sizeof(*record));
  int ret = qlinq_emcon_flexicast_open(ingress, packet, packet_size, &message);
  if (ret != QLINQ_EMCON_OK)
    return ret;
  ret = qlinq_emcon_receiver_ingest_message(receiver, &message, &event);
  if (ret != QLINQ_EMCON_OK)
    return ret;
  if (event.type != QLINQ_EMCON_EVENT_RECORD)
    return QLINQ_EMCON_INVALID;
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
    return QLINQ_EMCON_INVALID;
  wire[QLINQ_WIRE_FEC_HEADER_SIZE] = (uint8_t)('A' + index);
  qlinq_emcon_message_t message = {.type = QLINQ_EMCON_RECORD_DATA,
                                   .packet_number = pn,
                                   .payload =
                                       ptls_iovec_init(wire, sizeof(wire))};
  return qlinq_emcon_receiver_ingest_message(receiver, &message, event);
}

static int test_partial_objects(void) {
  CHECK(qlinq_emcon_receiver_create(7, 0) == NULL,
        "reject zero maximum record size");
  qlinq_emcon_receiver_t *receiver = qlinq_emcon_receiver_create(7, 64);
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

  /* enforce v2 tail omission, tight data_symbols, and maximum_record_size */
  uint8_t bad_wire[QLINQ_WIRE_FEC_HEADER_SIZE + 256] = {0};
  qlinq_wire_fec_header_t padded_tail = {.alias = 7,
                                         .group_id = 9,
                                         .object_id = 1,
                                         .symbol_index = 0,
                                         .data_symbols = 1,
                                         .total_symbols = 2,
                                         .symbol_size = 64,
                                         .original_size = 20};
  CHECK(qlinq_wire_encode_fec_header(bad_wire, sizeof(bad_wire),
                                     &padded_tail) == QLINQ_WIRE_OK,
        "encode padded-tail fixture");
  qlinq_emcon_message_t bad_msg = {
      .type = QLINQ_EMCON_RECORD_DATA,
      .packet_number = 500,
      .payload = ptls_iovec_init(bad_wire, QLINQ_WIRE_FEC_HEADER_SIZE + 64)};
  CHECK(qlinq_emcon_receiver_ingest_message(receiver, &bad_msg, &event) ==
            QLINQ_EMCON_INVALID,
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
            QLINQ_WIRE_OK,
        "encode non-minimal data_symbols fixture");
  bad_msg.payload = ptls_iovec_init(bad_wire, QLINQ_WIRE_FEC_HEADER_SIZE + 32);
  CHECK(qlinq_emcon_receiver_ingest_message(receiver, &bad_msg, &event) ==
            QLINQ_EMCON_INVALID,
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
            QLINQ_WIRE_OK,
        "encode oversize record fixture");
  bad_msg.payload = ptls_iovec_init(bad_wire, QLINQ_WIRE_FEC_HEADER_SIZE + 65);
  CHECK(qlinq_emcon_receiver_ingest_message(receiver, &bad_msg, &event) ==
            QLINQ_EMCON_INVALID,
        "reject object exceeding stream maximum_record_size");

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
  const uint64_t start = 500;
  qlinq_emcon_ingress_t *receiver = NULL, *other_receiver = NULL,
                        *limited_receiver = NULL;
  CHECK(qlinq_emcon_ingress_create(&receiver, 77, 1, digest, start, 0, secret,
                                   sizeof(secret)) == QLINQ_EMCON_OK &&
            qlinq_emcon_ingress_create(&other_receiver, 77, 1, other_digest,
                                       start, 0, secret,
                                       sizeof(secret)) == QLINQ_EMCON_OK &&
            qlinq_emcon_ingress_create(&limited_receiver, 77, 1, other_digest,
                                       start, 1, secret,
                                       sizeof(secret)) == QLINQ_EMCON_OK,
        "create hardened receive flows");

  /* derive the same manifest-bound epoch secret to craft raw packets */
  ptls_cipher_suite_t *suite = &ptls_openssl_aes128gcmsha256;
  uint8_t derived[PTLS_MAX_DIGEST_SIZE];
  uint8_t context[4 + QLINQ_EMCON_MANIFEST_DIGEST_SIZE];
  quicly_encode32(context, 1);
  memcpy(context + 4, digest, sizeof(digest));
  CHECK(ptls_hkdf_expand_label(
            suite->hash, derived, suite->hash->digest_size,
            ptls_iovec_init(secret, sizeof(secret)), "qlinq emcon epoch",
            ptls_iovec_init(context, sizeof(context)), NULL) == 0,
        "derive test epoch secret");
  quicly_flexicast_egress_t egress = {.crypto_engine =
                                          &quicly_default_crypto_engine};
  CHECK(egress.crypto_engine->setup_cipher(
            egress.crypto_engine, NULL, QUICLY_EPOCH_1RTT, 1,
            &egress.header_protection, &egress.aead, suite->aead, suite->hash,
            derived) == 0,
        "setup raw egress cipher");
  ptls_clear_memory(derived, sizeof(derived));

  uint8_t flow_bytes[8];
  quicly_encode64(flow_bytes, 77);
  quicly_flexicast_flow_id_t flow_id =
      quicly_flexicast_flow_id_init(flow_bytes, sizeof(flow_bytes));
  uint8_t framed[1 + QLINQ_WIRE_TRACK_END_SIZE] = {QLINQ_EMCON_RECORD_END};
  qlinq_wire_track_end_t end = {
      .alias = 7, .group_id = 3, .final_object_id = 42};
  CHECK(qlinq_wire_encode_track_end(framed + 1, QLINQ_WIRE_TRACK_END_SIZE,
                                    &end) == QLINQ_WIRE_OK,
        "encode terminal metadata");
  uint8_t packet[128];
  size_t packet_size = 0;
  qlinq_emcon_message_t message;

  /* 2-byte truncated wire packet number must fail without replay commit */
  CHECK(quicly_flexicast_encode_datagram_packet(
            &egress, &flow_id, start, QUICLY_SEND_PN_SIZE,
            ptls_iovec_init(framed, sizeof(framed)), packet, sizeof(packet),
            &packet_size) == QUICLY_FLEXICAST_OK &&
            qlinq_emcon_flexicast_open(receiver, packet, packet_size,
                                       &message) == QLINQ_EMCON_INVALID,
        "reject 2-byte wire packet number");

  /* packet number at or above the epoch's 2^23 limit must not advance replay */
  uint64_t past_limit = qlinq_emcon_packet_number_limit(start);
  CHECK(quicly_flexicast_encode_datagram_packet(
            &egress, &flow_id, past_limit, 4,
            ptls_iovec_init(framed, sizeof(framed)), packet, sizeof(packet),
            &packet_size) == QUICLY_FLEXICAST_OK &&
            qlinq_emcon_flexicast_open(receiver, packet, packet_size,
                                       &message) == QLINQ_EMCON_INVALID,
        "reject packet number at epoch upper bound");

  /* valid 4-byte PN at start still opens because invalid PNs were not committed
   */
  qlinq_emcon_receiver_t *assembler = qlinq_emcon_receiver_create(7, 64);
  qlinq_emcon_event_t event;
  CHECK(assembler &&
            quicly_flexicast_encode_datagram_packet(
                &egress, &flow_id, start, 4,
                ptls_iovec_init(framed, sizeof(framed)), packet, sizeof(packet),
                &packet_size) == QUICLY_FLEXICAST_OK &&
            qlinq_emcon_flexicast_open(receiver, packet, packet_size,
                                       &message) == QLINQ_EMCON_OK &&
            qlinq_emcon_receiver_ingest_message(assembler, &message, &event) ==
                QLINQ_EMCON_OK &&
            event.type == QLINQ_EMCON_EVENT_END && event.value.end.alias == 7 &&
            event.value.end.group_id == 3 &&
            event.value.end.final_object_id == 42,
        "authenticate start packet after rejecting invalid packet numbers");
  qlinq_emcon_event_release(&event);
  qlinq_emcon_receiver_free(assembler);

  /* manifest digest mismatch must fail AEAD and trip failure limit */
  CHECK(quicly_flexicast_encode_datagram_packet(
            &egress, &flow_id, start, 4,
            ptls_iovec_init(framed, sizeof(framed)), packet, sizeof(packet),
            &packet_size) == QUICLY_FLEXICAST_OK &&
            qlinq_emcon_flexicast_open(other_receiver, packet, packet_size,
                                       &message) == QLINQ_EMCON_DISCARDED &&
            qlinq_emcon_ingress_authentication_failures(other_receiver) == 1 &&
            quicly_flexicast_encode_datagram_packet(
                &egress, &flow_id, start, 4,
                ptls_iovec_init(framed, sizeof(framed)), packet, sizeof(packet),
                &packet_size) == QUICLY_FLEXICAST_OK &&
            qlinq_emcon_flexicast_open(limited_receiver, packet, packet_size,
                                       &message) == QLINQ_EMCON_CRYPTO,
        "reject packet bound to a different manifest digest");

  ptls_cipher_free(egress.header_protection);
  ptls_aead_free(egress.aead);
  qlinq_emcon_ingress_free(limited_receiver);
  qlinq_emcon_ingress_free(other_receiver);
  qlinq_emcon_ingress_free(receiver);
  return 0;
}

static int test_late_join(void) {
  const uint8_t secret[32] = {0x37};
  const uint8_t digest[QLINQ_EMCON_MANIFEST_DIGEST_SIZE] = {0x55};
  const uint8_t payload[] = "late multicast delivery";
  const uint64_t first = UINT32_MAX - 3;
  const uint64_t last = first + QUICLY_FLEXICAST_SENT_WINDOW + 1;
  uint8_t packet[128];
  size_t packet_size;
  uint64_t number;
  qlinq_emcon_sender_t *sender = NULL;
  CHECK(qlinq_emcon_sender_create(&sender, 44, 3, digest, first, first, secret,
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
    qlinq_emcon_ingress_t *receiver = NULL;
    CHECK(qlinq_emcon_ingress_create(&receiver, 44, 3, digest, first, 0, secret,
                                     sizeof(secret)) == QLINQ_EMCON_OK,
          "initialize a late listener from the initial epoch");
    uint8_t copy[sizeof(packet)];
    memcpy(copy, packet, packet_size);
    qlinq_emcon_message_t message;
    CHECK(qlinq_emcon_flexicast_open(receiver, copy, packet_size, &message) ==
                  QLINQ_EMCON_OK &&
              (copy[0] & 3U) == 3U && message.packet_number == last &&
              message.type == QLINQ_EMCON_RECORD_DATA &&
              message.payload.len == sizeof(payload) &&
              memcmp(message.payload.base, payload, sizeof(payload)) == 0,
          "late Flexicast listener authenticates after 32-bit rollover");
    memcpy(copy, packet, packet_size);
    CHECK(qlinq_emcon_flexicast_open(receiver, copy, packet_size, &message) ==
              QLINQ_EMCON_DUPLICATE,
          "EMCON ingress decoder rejects a replay");
    qlinq_emcon_ingress_free(receiver);
  }
  return 0;
}

static int test_packet_number_ceiling(void) {
  const uint8_t secret[32] = {0x38};
  const uint8_t digest[QLINQ_EMCON_MANIFEST_DIGEST_SIZE] = {0x56};
  const uint64_t ceiling = (UINT64_C(1) << 62) - 1;
  uint8_t payload[] = "last packet";
  qlinq_emcon_sender_t *sender = NULL;
  qlinq_emcon_ingress_t *receiver = NULL;
  CHECK(qlinq_emcon_sender_create(&sender, 44, 4, digest, ceiling, ceiling,
                                  secret, sizeof(secret)) == QLINQ_EMCON_OK &&
            qlinq_emcon_ingress_create(&receiver, 44, 4, digest, ceiling, 0,
                                       secret,
                                       sizeof(secret)) == QLINQ_EMCON_OK,
        "initialize sender and receiver at the last QUIC packet number");
  uint8_t packet[128], replay[sizeof(packet)];
  size_t packet_size;
  uint64_t number;
  ptls_iovec_t data = ptls_iovec_init(payload, sizeof(payload));
  CHECK(qlinq_emcon_flexicast_seal(sender, QLINQ_EMCON_RECORD_DATA, data,
                                   packet, sizeof(packet), &packet_size,
                                   &number) == QLINQ_EMCON_OK &&
            number == ceiling &&
            qlinq_emcon_sender_next_packet_number(sender) == ceiling + 1,
        "seal the final QUIC packet number");
  memcpy(replay, packet, packet_size);
  qlinq_emcon_message_t message;
  CHECK(qlinq_emcon_flexicast_open(receiver, packet, packet_size, &message) ==
                QLINQ_EMCON_OK &&
            message.packet_number == ceiling &&
            message.payload.len == sizeof(payload) &&
            memcmp(message.payload.base, payload, sizeof(payload)) == 0 &&
            qlinq_emcon_flexicast_open(receiver, replay, packet_size,
                                       &message) == QLINQ_EMCON_DUPLICATE,
        "authenticate the final packet and reject its replay");
  CHECK(qlinq_emcon_flexicast_seal(
            sender, QLINQ_EMCON_RECORD_DATA, data, packet, sizeof(packet),
            &packet_size, &number) == QLINQ_EMCON_PACKET_NUMBER_EXHAUSTED,
        "refuse to seal past the QUIC packet-number ceiling");
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
  memset(secret, 0xa6, ptls_openssl_aes128gcmsha256.hash->digest_size);
  const uint8_t digest[QLINQ_EMCON_MANIFEST_DIGEST_SIZE] = {0x57};
  qlinq_emcon_sender_t *sender = NULL;
  qlinq_emcon_ingress_t *receiver_protection = NULL;
  size_t secret_size = ptls_openssl_aes128gcmsha256.hash->digest_size;
  CHECK(qlinq_emcon_sender_create(&sender, 44, 3, digest, 1000, 1000, secret,
                                  secret_size) == QLINQ_EMCON_OK &&
            qlinq_emcon_ingress_create(&receiver_protection, 44, 3, digest,
                                       1000, 0, secret,
                                       secret_size) == QLINQ_EMCON_OK,
        "protection setup");

  qlinq_emcon_rateless_config_t config = {
      .alias = 7, .symbol_size = 256, .repair_symbols = 10};
  CHECK(qlinq_emcon_send_object(sender, &config, 12, 34, true, 2, input,
                                sizeof(input), capture_packet,
                                &capture) == QLINQ_EMCON_OK,
        "encode object");
  CHECK(capture.count == 30, "expected original plus repair count");

  /* verify wire v2 omits zero padding from the final source symbol (136 B) */
  size_t short_symbols = 0;
  for (size_t i = 0; i < capture.count; i++) {
    if (symbols[i] == 19) {
      CHECK(sizes[i] == 213, "final source symbol omits implicit zero tail");
      short_symbols++;
    } else {
      CHECK(sizes[i] == 333, "full source and repair symbols use symbol_size");
    }
  }
  CHECK(short_symbols == 1, "exactly one short final source symbol");

  /* drop five original symbols and deliver the rest in reverse order */
  qlinq_emcon_receiver_t *receiver = qlinq_emcon_receiver_create(7, 8192);
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

  uint8_t replay_packets[3][64];
  size_t replay_sizes[3];
  uint8_t payload = 0;
  uint64_t number;
  for (size_t i = 0; i <= QLINQ_EMCON_REPLAY_WINDOW_PACKETS; i++) {
    size_t slot = i < 2 ? i : 2;
    CHECK(qlinq_emcon_flexicast_seal(
              sender, QLINQ_EMCON_RECORD_END, ptls_iovec_init(&payload, 1),
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
                sender, QLINQ_EMCON_RECORD_END, ptls_iovec_init(&payload, 1),
                replay_packets[0], sizeof(replay_packets[0]), &replay_sizes[0],
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
