#include "emcon_metadata.h"

#include "emcon_endian.h"

#include <string.h>

static int validate_prefix(const uint8_t *src, size_t size,
                           size_t expected_size) {
  if (!src || size != expected_size)
    return QLINQ_EMCON_METADATA_INVALID;
  if (src[0] != QLINQ_EMCON_METADATA_VERSION)
    return QLINQ_EMCON_METADATA_UNSUPPORTED_VERSION;
  return QLINQ_EMCON_METADATA_OK;
}

int qlinq_emcon_encode_session(uint8_t *dst, size_t capacity,
                               const qlinq_emcon_session_metadata_t *metadata) {
  if (!dst || !metadata)
    return QLINQ_EMCON_METADATA_INVALID;
  if (capacity < QLINQ_EMCON_SESSION_WIRE_SIZE)
    return QLINQ_EMCON_METADATA_BUFFER_TOO_SMALL;
  memset(dst, 0, QLINQ_EMCON_SESSION_WIRE_SIZE);
  dst[0] = QLINQ_EMCON_METADATA_VERSION;
  memcpy(dst + 4, metadata->session_id, QLINQ_EMCON_SESSION_ID_SIZE);
  memcpy(dst + 20, metadata->manifest_digest, QLINQ_EMCON_DIGEST_SIZE);
  qlinq_emcon_write_u64(dst + 52, metadata->source_time_ms);
  qlinq_emcon_write_u32(dst + 60, metadata->stream_table_revision);
  return QLINQ_EMCON_METADATA_OK;
}

int qlinq_emcon_decode_session(const uint8_t *src, size_t size,
                               qlinq_emcon_session_metadata_t *metadata) {
  int ret = validate_prefix(src, size, QLINQ_EMCON_SESSION_WIRE_SIZE);
  if (ret != QLINQ_EMCON_METADATA_OK || !metadata)
    return ret == QLINQ_EMCON_METADATA_OK ? QLINQ_EMCON_METADATA_INVALID : ret;
  if (src[1] != 0 || src[2] != 0 || src[3] != 0)
    return QLINQ_EMCON_METADATA_INVALID;
  memcpy(metadata->session_id, src + 4, QLINQ_EMCON_SESSION_ID_SIZE);
  memcpy(metadata->manifest_digest, src + 20, QLINQ_EMCON_DIGEST_SIZE);
  metadata->source_time_ms = qlinq_emcon_read_u64(src + 52);
  metadata->stream_table_revision = qlinq_emcon_read_u32(src + 60);
  return QLINQ_EMCON_METADATA_OK;
}

int qlinq_emcon_encode_window(uint8_t *dst, size_t capacity,
                              const qlinq_emcon_window_metadata_t *metadata) {
  if (!dst || !metadata ||
      metadata->first_object_id > metadata->final_object_id)
    return QLINQ_EMCON_METADATA_INVALID;
  if (capacity < QLINQ_EMCON_WINDOW_WIRE_SIZE)
    return QLINQ_EMCON_METADATA_BUFFER_TOO_SMALL;
  memset(dst, 0, QLINQ_EMCON_WINDOW_WIRE_SIZE);
  dst[0] = QLINQ_EMCON_METADATA_VERSION;
  dst[1] = metadata->alias;
  dst[2] = metadata->final_window ? 1U : 0U;
  qlinq_emcon_write_u64(dst + 8, metadata->group_id);
  qlinq_emcon_write_u64(dst + 16, metadata->first_object_id);
  qlinq_emcon_write_u64(dst + 24, metadata->final_object_id);
  return QLINQ_EMCON_METADATA_OK;
}

int qlinq_emcon_decode_window(const uint8_t *src, size_t size,
                              qlinq_emcon_window_metadata_t *metadata) {
  int ret = validate_prefix(src, size, QLINQ_EMCON_WINDOW_WIRE_SIZE);
  if (ret != QLINQ_EMCON_METADATA_OK || !metadata)
    return ret == QLINQ_EMCON_METADATA_OK ? QLINQ_EMCON_METADATA_INVALID : ret;
  if (src[2] > 1 || src[3] != 0 || src[4] != 0 || src[5] != 0 || src[6] != 0 ||
      src[7] != 0)
    return QLINQ_EMCON_METADATA_INVALID;
  metadata->alias = src[1];
  metadata->final_window = src[2] != 0;
  metadata->group_id = qlinq_emcon_read_u64(src + 8);
  metadata->first_object_id = qlinq_emcon_read_u64(src + 16);
  metadata->final_object_id = qlinq_emcon_read_u64(src + 24);
  return metadata->first_object_id <= metadata->final_object_id
             ? QLINQ_EMCON_METADATA_OK
             : QLINQ_EMCON_METADATA_INVALID;
}

int qlinq_emcon_encode_end(uint8_t *dst, size_t capacity,
                           const qlinq_emcon_end_metadata_t *metadata) {
  if (!dst || !metadata)
    return QLINQ_EMCON_METADATA_INVALID;
  if (capacity < QLINQ_EMCON_END_WIRE_SIZE)
    return QLINQ_EMCON_METADATA_BUFFER_TOO_SMALL;
  memset(dst, 0, QLINQ_EMCON_END_WIRE_SIZE);
  dst[0] = QLINQ_EMCON_METADATA_VERSION;
  dst[1] = metadata->alias;
  qlinq_emcon_write_u64(dst + 8, metadata->group_id);
  qlinq_emcon_write_u64(dst + 16, metadata->final_object_id);
  memcpy(dst + 24, metadata->transmission_nonce, QLINQ_EMCON_NONCE_SIZE);
  return QLINQ_EMCON_METADATA_OK;
}

int qlinq_emcon_decode_end(const uint8_t *src, size_t size,
                           qlinq_emcon_end_metadata_t *metadata) {
  int ret = validate_prefix(src, size, QLINQ_EMCON_END_WIRE_SIZE);
  if (ret != QLINQ_EMCON_METADATA_OK || !metadata)
    return ret == QLINQ_EMCON_METADATA_OK ? QLINQ_EMCON_METADATA_INVALID : ret;
  for (size_t i = 2; i < 8; i++)
    if (src[i] != 0)
      return QLINQ_EMCON_METADATA_INVALID;
  metadata->alias = src[1];
  metadata->group_id = qlinq_emcon_read_u64(src + 8);
  metadata->final_object_id = qlinq_emcon_read_u64(src + 16);
  memcpy(metadata->transmission_nonce, src + 24, QLINQ_EMCON_NONCE_SIZE);
  return QLINQ_EMCON_METADATA_OK;
}

int qlinq_emcon_encode_abort(uint8_t *dst, size_t capacity,
                             const qlinq_emcon_abort_metadata_t *metadata) {
  if (!dst || !metadata || metadata->reason == 0)
    return QLINQ_EMCON_METADATA_INVALID;
  if (capacity < QLINQ_EMCON_ABORT_WIRE_SIZE)
    return QLINQ_EMCON_METADATA_BUFFER_TOO_SMALL;
  memset(dst, 0, QLINQ_EMCON_ABORT_WIRE_SIZE);
  dst[0] = QLINQ_EMCON_METADATA_VERSION;
  qlinq_emcon_write_u16(dst + 2, metadata->reason);
  memcpy(dst + 8, metadata->transmission_nonce, QLINQ_EMCON_NONCE_SIZE);
  return QLINQ_EMCON_METADATA_OK;
}

int qlinq_emcon_decode_abort(const uint8_t *src, size_t size,
                             qlinq_emcon_abort_metadata_t *metadata) {
  int ret = validate_prefix(src, size, QLINQ_EMCON_ABORT_WIRE_SIZE);
  if (ret != QLINQ_EMCON_METADATA_OK || !metadata)
    return ret == QLINQ_EMCON_METADATA_OK ? QLINQ_EMCON_METADATA_INVALID : ret;
  if (src[1] != 0 || src[4] != 0 || src[5] != 0 || src[6] != 0 || src[7] != 0 ||
      qlinq_emcon_read_u16(src + 2) == 0)
    return QLINQ_EMCON_METADATA_INVALID;
  metadata->reason = qlinq_emcon_read_u16(src + 2);
  memcpy(metadata->transmission_nonce, src + 8, QLINQ_EMCON_NONCE_SIZE);
  return QLINQ_EMCON_METADATA_OK;
}
