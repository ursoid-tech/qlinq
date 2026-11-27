#ifndef QLINQ_EMCON_ENDIAN_H
#define QLINQ_EMCON_ENDIAN_H

#include <stddef.h>
#include <stdint.h>

static inline void qlinq_emcon_write_u16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value >> 8);
  dst[1] = (uint8_t)value;
}

static inline void qlinq_emcon_write_u32(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)(value >> 24);
  dst[1] = (uint8_t)(value >> 16);
  dst[2] = (uint8_t)(value >> 8);
  dst[3] = (uint8_t)value;
}

static inline void qlinq_emcon_write_u64(uint8_t *dst, uint64_t value) {
  for (size_t i = 0; i < 8; i++)
    dst[i] = (uint8_t)(value >> (56U - 8U * i));
}

static inline uint16_t qlinq_emcon_read_u16(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8) | src[1]);
}

static inline uint32_t qlinq_emcon_read_u32(const uint8_t *src) {
  return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
         ((uint32_t)src[2] << 8) | src[3];
}

static inline uint64_t qlinq_emcon_read_u64(const uint8_t *src) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; i++)
    value = (value << 8) | src[i];
  return value;
}

#endif
