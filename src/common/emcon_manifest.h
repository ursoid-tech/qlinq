#ifndef QLINQ_EMCON_MANIFEST_H
#define QLINQ_EMCON_MANIFEST_H

#include <openssl/evp.h>

#include <stddef.h>
#include <stdint.h>

#define QLINQ_EMCON_MANIFEST_VERSION 1U
#define QLINQ_EMCON_MANIFEST_HEADER_SIZE 208U
#define QLINQ_EMCON_MANIFEST_STREAM_SIZE 72U
#define QLINQ_EMCON_MANIFEST_MAX_STREAMS 16U
#define QLINQ_EMCON_MANIFEST_MAX_SIZE                                          \
  (QLINQ_EMCON_MANIFEST_HEADER_SIZE +                                          \
   QLINQ_EMCON_MANIFEST_MAX_STREAMS * QLINQ_EMCON_MANIFEST_STREAM_SIZE)
#define QLINQ_EMCON_MANIFEST_SIGNATURE_SIZE 64U
#define QLINQ_EMCON_MANIFEST_ID_SIZE 16U
#define QLINQ_EMCON_MANIFEST_KEY_ID_SIZE 32U
#define QLINQ_EMCON_MANIFEST_STREAM_NAME_SIZE 64U

#define QLINQ_EMCON_CIPHER_AES_128_GCM_SHA256 1U
#define QLINQ_EMCON_DELIVERY_RATELESS 3U
#define QLINQ_EMCON_REPLAY_WINDOW_PACKETS 64U
#define QLINQ_EMCON_MAX_PACKETS_PER_KEY (UINT64_C(1) << 23)
#define QLINQ_EMCON_FLEXICAST_OVERHEAD 64U

typedef enum {
  QLINQ_EMCON_MANIFEST_OK = 0,
  QLINQ_EMCON_MANIFEST_INVALID = -1,
  QLINQ_EMCON_MANIFEST_BUFFER_TOO_SMALL = -2,
  QLINQ_EMCON_MANIFEST_UNSUPPORTED = -3,
  QLINQ_EMCON_MANIFEST_EXPIRED = -4,
  QLINQ_EMCON_MANIFEST_NOT_YET_VALID = -5,
  QLINQ_EMCON_MANIFEST_SIGNATURE = -6,
  QLINQ_EMCON_MANIFEST_IO = -7,
  QLINQ_EMCON_MANIFEST_KEY_MISMATCH = -8
} qlinq_emcon_manifest_result_t;

typedef struct {
  uint8_t family; /* 4 or 6 */
  uint8_t address[16];
  uint16_t port;
} qlinq_emcon_manifest_endpoint_t;

typedef struct {
  uint8_t alias;
  uint8_t delivery;
  uint8_t content_type;
  uint32_t maximum_record_size;
  char name[QLINQ_EMCON_MANIFEST_STREAM_NAME_SIZE];
} qlinq_emcon_manifest_stream_t;

typedef struct {
  uint8_t session_id[QLINQ_EMCON_MANIFEST_ID_SIZE];
  uint8_t sender_id[QLINQ_EMCON_MANIFEST_ID_SIZE];
  uint8_t traffic_key_id[QLINQ_EMCON_MANIFEST_KEY_ID_SIZE];
  uint64_t flow_id;
  uint32_t key_epoch;
  uint16_t cipher_suite;
  uint64_t initial_packet_number;
  uint64_t valid_from_ms;
  uint64_t expires_at_ms;
  qlinq_emcon_manifest_endpoint_t source;
  qlinq_emcon_manifest_endpoint_t destination;
  uint32_t interface_index;
  uint32_t replay_window_packets;
  uint64_t rate_bytes_per_second;
  uint32_t burst_bytes;
  uint32_t metadata_repeat_interval_ms;
  uint16_t terminal_repeat_count;
  uint16_t symbol_size;
  uint16_t repair_symbols;
  uint16_t stream_count;
  qlinq_emcon_manifest_stream_t streams[QLINQ_EMCON_MANIFEST_MAX_STREAMS];
} qlinq_emcon_manifest_t;

int qlinq_emcon_manifest_validate(const qlinq_emcon_manifest_t *manifest,
                                  uint64_t now_ms);
/* Exclusive end of the sender packet-number range for a validated manifest. */
uint64_t qlinq_emcon_manifest_packet_number_limit(
    const qlinq_emcon_manifest_t *manifest);
int qlinq_emcon_manifest_encode(const qlinq_emcon_manifest_t *manifest,
                                uint8_t *output, size_t capacity,
                                size_t *output_size);
int qlinq_emcon_manifest_decode(qlinq_emcon_manifest_t *manifest,
                                const uint8_t *input, size_t input_size,
                                uint64_t now_ms);
int qlinq_emcon_manifest_digest(const qlinq_emcon_manifest_t *manifest,
                                uint8_t digest[32]);

int qlinq_emcon_manifest_sign(
    const qlinq_emcon_manifest_t *manifest, EVP_PKEY *private_key,
    uint8_t signature[QLINQ_EMCON_MANIFEST_SIGNATURE_SIZE]);
int qlinq_emcon_manifest_verify(
    const qlinq_emcon_manifest_t *manifest, EVP_PKEY *public_key,
    const uint8_t signature[QLINQ_EMCON_MANIFEST_SIGNATURE_SIZE]);
int qlinq_emcon_manifest_load_signed(qlinq_emcon_manifest_t *manifest,
                                     const char *manifest_file,
                                     const char *signature_file,
                                     const char *public_key_file,
                                     uint64_t now_ms);

int qlinq_emcon_traffic_key_id(
    const uint8_t *secret, size_t secret_size,
    uint8_t key_id[QLINQ_EMCON_MANIFEST_KEY_ID_SIZE]);
int qlinq_emcon_traffic_key_load(const char *key_file, uint8_t *secret,
                                 size_t capacity, size_t *secret_size);
int qlinq_emcon_manifest_check_traffic_key(
    const qlinq_emcon_manifest_t *manifest, const uint8_t *secret,
    size_t secret_size);

#endif
