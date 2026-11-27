#include "emcon_metadata.h"
#include "emcon_rateless.h"

#include "picotls/openssl.h"
#include "quicly/defaults.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "EMCON metadata test failed: %s\n", message);            \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int test_plain_metadata(void) {
  uint8_t wire[QLINQ_EMCON_SESSION_WIRE_SIZE];
  qlinq_emcon_session_metadata_t session = {.source_time_ms =
                                                UINT64_C(0x0102030405060708),
                                            .stream_table_revision = 17};
  qlinq_emcon_session_metadata_t decoded_session = {0};
  for (size_t i = 0; i < QLINQ_EMCON_SESSION_ID_SIZE; i++)
    session.session_id[i] = (uint8_t)(i + 1);
  for (size_t i = 0; i < QLINQ_EMCON_DIGEST_SIZE; i++)
    session.manifest_digest[i] = (uint8_t)(0xa0 + i);
  CHECK(qlinq_emcon_encode_session(wire, sizeof(wire), &session) ==
                QLINQ_EMCON_METADATA_OK &&
            qlinq_emcon_decode_session(wire, sizeof(wire), &decoded_session) ==
                QLINQ_EMCON_METADATA_OK &&
            memcmp(&session, &decoded_session, sizeof(session)) == 0,
        "session roundtrip");
  wire[2] = 1;
  CHECK(qlinq_emcon_decode_session(wire, sizeof(wire), &decoded_session) ==
            QLINQ_EMCON_METADATA_INVALID,
        "session reserved bits rejected");

  qlinq_emcon_window_metadata_t window = {.alias = 7,
                                          .group_id = 9,
                                          .first_object_id = 20,
                                          .final_object_id = 27,
                                          .final_window = true};
  qlinq_emcon_window_metadata_t decoded_window = {0};
  CHECK(qlinq_emcon_encode_window(wire, sizeof(wire), &window) ==
                QLINQ_EMCON_METADATA_OK &&
            qlinq_emcon_decode_window(wire, QLINQ_EMCON_WINDOW_WIRE_SIZE,
                                      &decoded_window) ==
                QLINQ_EMCON_METADATA_OK &&
            decoded_window.alias == window.alias &&
            decoded_window.group_id == window.group_id &&
            decoded_window.first_object_id == window.first_object_id &&
            decoded_window.final_object_id == window.final_object_id &&
            decoded_window.final_window,
        "window roundtrip");

  qlinq_emcon_end_metadata_t end = {
      .alias = 7, .group_id = 9, .final_object_id = 27};
  qlinq_emcon_end_metadata_t decoded_end = {0};
  for (size_t i = 0; i < QLINQ_EMCON_NONCE_SIZE; i++)
    end.transmission_nonce[i] = (uint8_t)(0x50 + i);
  CHECK(qlinq_emcon_encode_end(wire, sizeof(wire), &end) ==
                QLINQ_EMCON_METADATA_OK &&
            qlinq_emcon_decode_end(wire, QLINQ_EMCON_END_WIRE_SIZE,
                                   &decoded_end) == QLINQ_EMCON_METADATA_OK &&
            decoded_end.alias == end.alias &&
            decoded_end.group_id == end.group_id &&
            decoded_end.final_object_id == end.final_object_id &&
            memcmp(decoded_end.transmission_nonce, end.transmission_nonce,
                   QLINQ_EMCON_NONCE_SIZE) == 0,
        "end roundtrip");

  qlinq_emcon_abort_metadata_t abort = {.reason = 33};
  qlinq_emcon_abort_metadata_t decoded_abort = {0};
  memcpy(abort.transmission_nonce, end.transmission_nonce,
         QLINQ_EMCON_NONCE_SIZE);
  CHECK(qlinq_emcon_encode_abort(wire, sizeof(wire), &abort) ==
                QLINQ_EMCON_METADATA_OK &&
            qlinq_emcon_decode_abort(wire, QLINQ_EMCON_ABORT_WIRE_SIZE,
                                     &decoded_abort) ==
                QLINQ_EMCON_METADATA_OK &&
            decoded_abort.reason == abort.reason &&
            memcmp(decoded_abort.transmission_nonce, abort.transmission_nonce,
                   QLINQ_EMCON_NONCE_SIZE) == 0,
        "abort roundtrip");
  return 0;
}

static int test_protected_dispatch(void) {
  uint8_t secret[PTLS_MAX_DIGEST_SIZE] = {0};
  uint8_t payload[QLINQ_EMCON_WINDOW_WIRE_SIZE], packet[256];
  size_t packet_size;
  uint64_t packet_number;
  qlinq_emcon_window_metadata_t window = {.alias = 7,
                                          .group_id = 3,
                                          .first_object_id = 100,
                                          .final_object_id = 109,
                                          .final_window = false};
  memset(secret, 0x19, ptls_openssl_aes128gcmsha256.hash->digest_size);
  qlinq_emcon_sender_t *sender = NULL;
  quicly_flexicast_flow_t *receiver_flow = NULL;
  size_t secret_size = ptls_openssl_aes128gcmsha256.hash->digest_size;
  CHECK(qlinq_emcon_sender_create(&sender, 91, 5, PTLS_QUICINT_MAX,
                                  PTLS_QUICINT_MAX, secret,
                                  secret_size) == QLINQ_EMCON_OK &&
            qlinq_emcon_flexicast_create(&receiver_flow, 91, 5,
                                         PTLS_QUICINT_MAX, secret,
                                         secret_size) == QLINQ_EMCON_OK,
        "set up an epoch at the last QUIC packet number");
  qlinq_emcon_receiver_t *receiver =
      qlinq_emcon_receiver_create(receiver_flow, 7);
  CHECK(sender && receiver_flow && receiver, "protected fixture");
  CHECK(
      qlinq_emcon_encode_window(payload, sizeof(payload), &window) ==
              QLINQ_EMCON_METADATA_OK &&
          qlinq_emcon_flexicast_seal(sender, QLINQ_EMCON_RECORD_WINDOW,
                                     ptls_iovec_init(payload, sizeof(payload)),
                                     packet, sizeof(packet), &packet_size,
                                     &packet_number) == QLINQ_EMCON_OK &&
          packet_number == PTLS_QUICINT_MAX,
      "protect window at the last packet number");
  /* receiver with a different key and 1 auth failure left reports exhaustion */
  uint8_t flow_id[8] = {0, 0, 0, 0, 0, 0, 0, 91};
  quicly_flexicast_config_t limited_config = {
      .flow_id = quicly_flexicast_flow_id_init(flow_id, sizeof(flow_id)),
      .cipher_suite = &ptls_openssl_aes128gcmsha256,
      .crypto_engine = &quicly_default_crypto_engine,
      .traffic_secret = ptls_iovec_init(secret, secret_size),
      .max_authentication_failures = 1};
  quicly_flexicast_flow_t *limited = NULL;
  uint8_t copy[sizeof(packet)];
  memcpy(copy, packet, packet_size);
  qlinq_emcon_message_t message;
  CHECK(quicly_flexicast_flow_create(&limited, &limited_config) == 0 &&
            qlinq_emcon_flexicast_open(limited, copy, packet_size, &message) ==
                QLINQ_EMCON_CRYPTO,
        "key exhaustion remains fatal");
  quicly_flexicast_flow_free(limited);
  qlinq_emcon_event_t event;
  CHECK(qlinq_emcon_receiver_ingest_packet(receiver, packet, packet_size,
                                           &event) == QLINQ_EMCON_OK &&
            event.type == QLINQ_EMCON_EVENT_WINDOW &&
            event.value.window.group_id == 3 &&
            event.value.window.first_object_id == 100 &&
            event.value.window.final_object_id == 109,
        "authenticated window dispatch");
  qlinq_emcon_event_release(&event);
  CHECK(qlinq_emcon_flexicast_seal(sender, QLINQ_EMCON_RECORD_WINDOW,
                                   ptls_iovec_init(payload, sizeof(payload)),
                                   packet, sizeof(packet), &packet_size,
                                   &packet_number) ==
            QLINQ_EMCON_PACKET_NUMBER_EXHAUSTED,
        "refuse protection after the last packet number");
  qlinq_emcon_receiver_free(receiver);
  quicly_flexicast_flow_free(receiver_flow);
  qlinq_emcon_sender_free(sender);
  return 0;
}

int main(void) {
  CHECK(test_plain_metadata() == 0, "plain metadata suite");
  CHECK(test_protected_dispatch() == 0, "protected dispatch suite");
  puts("===EMCON METADATA OK===");
  return 0;
}
