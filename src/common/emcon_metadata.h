#ifndef QLINQ_EMCON_METADATA_H
#define QLINQ_EMCON_METADATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define QLINQ_EMCON_METADATA_VERSION 1U
#define QLINQ_EMCON_SESSION_ID_SIZE 16U
#define QLINQ_EMCON_DIGEST_SIZE 32U
#define QLINQ_EMCON_NONCE_SIZE 16U

#define QLINQ_EMCON_SESSION_WIRE_SIZE 64U
#define QLINQ_EMCON_WINDOW_WIRE_SIZE 32U
#define QLINQ_EMCON_END_WIRE_SIZE 40U
#define QLINQ_EMCON_ABORT_WIRE_SIZE 24U

typedef enum {
  QLINQ_EMCON_METADATA_OK = 0,
  QLINQ_EMCON_METADATA_INVALID = -1,
  QLINQ_EMCON_METADATA_BUFFER_TOO_SMALL = -2,
  QLINQ_EMCON_METADATA_UNSUPPORTED_VERSION = -3
} qlinq_emcon_metadata_result_t;

typedef struct {
  uint8_t session_id[QLINQ_EMCON_SESSION_ID_SIZE];
  uint8_t manifest_digest[QLINQ_EMCON_DIGEST_SIZE];
  uint64_t source_time_ms;
  uint32_t stream_table_revision;
} qlinq_emcon_session_metadata_t;

typedef struct {
  uint8_t alias;
  uint64_t group_id;
  uint64_t first_object_id;
  uint64_t final_object_id;
  bool final_window;
} qlinq_emcon_window_metadata_t;

typedef struct {
  uint8_t alias;
  uint64_t group_id;
  uint64_t final_object_id;
  uint8_t transmission_nonce[QLINQ_EMCON_NONCE_SIZE];
} qlinq_emcon_end_metadata_t;

typedef struct {
  uint16_t reason;
  uint8_t transmission_nonce[QLINQ_EMCON_NONCE_SIZE];
} qlinq_emcon_abort_metadata_t;

int qlinq_emcon_encode_session(uint8_t *dst, size_t capacity,
                               const qlinq_emcon_session_metadata_t *metadata);
int qlinq_emcon_decode_session(const uint8_t *src, size_t size,
                               qlinq_emcon_session_metadata_t *metadata);
int qlinq_emcon_encode_window(uint8_t *dst, size_t capacity,
                              const qlinq_emcon_window_metadata_t *metadata);
int qlinq_emcon_decode_window(const uint8_t *src, size_t size,
                              qlinq_emcon_window_metadata_t *metadata);
int qlinq_emcon_encode_end(uint8_t *dst, size_t capacity,
                           const qlinq_emcon_end_metadata_t *metadata);
int qlinq_emcon_decode_end(const uint8_t *src, size_t size,
                           qlinq_emcon_end_metadata_t *metadata);
int qlinq_emcon_encode_abort(uint8_t *dst, size_t capacity,
                             const qlinq_emcon_abort_metadata_t *metadata);
int qlinq_emcon_decode_abort(const uint8_t *src, size_t size,
                             qlinq_emcon_abort_metadata_t *metadata);

#endif
