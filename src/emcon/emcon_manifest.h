#ifndef QLINQ_EMCON_MANIFEST_H
#define QLINQ_EMCON_MANIFEST_H

#include <openssl/evp.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define QLINQ_EMCON_MANIFEST_MAX_STREAMS 16U
#define QLINQ_EMCON_MANIFEST_MAX_SIZE 2048U
#define QLINQ_EMCON_MANIFEST_SIGNATURE_SIZE 64U
#define QLINQ_EMCON_MANIFEST_KEY_ID_SIZE 32U
#define QLINQ_EMCON_MANIFEST_DIGEST_SIZE 32U
#define QLINQ_EMCON_MANIFEST_STREAM_NAME_SIZE 64U

#define QLINQ_EMCON_REPLAY_WINDOW_PACKETS 64U
#define QLINQ_EMCON_MAX_PACKETS_PER_KEY (UINT64_C(1) << 23)
#define QLINQ_EMCON_FLEXICAST_OVERHEAD 64U

typedef enum {
  QLINQ_EMCON_OK = 0,
  QLINQ_EMCON_INCOMPLETE = 1,
  QLINQ_EMCON_DUPLICATE = 2,
  QLINQ_EMCON_WOULD_BLOCK = 3,
  QLINQ_EMCON_DISCARDED = 4,
  QLINQ_EMCON_ERR_INVALID = -1,
  QLINQ_EMCON_ERR_NO_MEMORY = -2,
  QLINQ_EMCON_ERR_IO = -3,
  QLINQ_EMCON_ERR_CRYPTO = -4,
  QLINQ_EMCON_ERR_SIGNATURE = -5,
  QLINQ_EMCON_ERR_KEY_MISMATCH = -6,
  QLINQ_EMCON_ERR_NOT_YET_VALID = -7,
  QLINQ_EMCON_ERR_EXPIRED = -8,
  QLINQ_EMCON_ERR_TOO_LARGE = -9,
  QLINQ_EMCON_ERR_UNKNOWN_ALIAS = -10,
  QLINQ_EMCON_ERR_ACTIVATION = -11,
  QLINQ_EMCON_ERR_LOCKED = -12,
  QLINQ_EMCON_ERR_REUSED = -13,
  QLINQ_EMCON_ERR_EXHAUSTED = -14,
  QLINQ_EMCON_ERR_TRANSFER_MISMATCH = -15,
  QLINQ_EMCON_ERR_INTERRUPTED = -16,
  QLINQ_EMCON_ERR_EMIT_FAILED = -17
} qlinq_emcon_err_t;

typedef struct {
  uint8_t family; /* 4 or 6 */
  uint8_t address[16];
  uint16_t port;
} qlinq_emcon_manifest_endpoint_t;

typedef struct {
  uint8_t alias;
  uint8_t content_type;
  uint32_t maximum_record_size;
  char name[QLINQ_EMCON_MANIFEST_STREAM_NAME_SIZE];
} qlinq_emcon_manifest_stream_t;

typedef struct {
  uint8_t traffic_key_id[QLINQ_EMCON_MANIFEST_KEY_ID_SIZE];
  uint64_t flow_id;
  uint32_t key_epoch;
  uint64_t valid_from_ms;
  uint64_t expires_at_ms;
  qlinq_emcon_manifest_endpoint_t source;
  qlinq_emcon_manifest_endpoint_t destination;
  uint32_t interface_index;
  uint64_t rate_bytes_per_second;
  uint32_t burst_bytes;
  uint16_t terminal_repeat_count;
  uint16_t symbol_size;
  uint16_t repair_symbols;
  uint16_t stream_count;
  qlinq_emcon_manifest_stream_t streams[QLINQ_EMCON_MANIFEST_MAX_STREAMS];
} qlinq_emcon_manifest_t;

static inline uint64_t qlinq_emcon_realtime_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_REALTIME, &now) != 0)
    return 0;
  return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

const char *qlinq_emcon_strerror(int error);

int qlinq_emcon_manifest_validate(const qlinq_emcon_manifest_t *manifest,
                                  uint64_t now_ms);
int qlinq_emcon_manifest_encode(const qlinq_emcon_manifest_t *manifest,
                                uint8_t *output, size_t capacity,
                                size_t *output_size);
int qlinq_emcon_manifest_decode(qlinq_emcon_manifest_t *manifest,
                                const uint8_t *input, size_t input_size,
                                uint64_t now_ms);
int qlinq_emcon_manifest_parse_conf(const char *path,
                                    qlinq_emcon_manifest_t *manifest);
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
