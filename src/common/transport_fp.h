#ifndef QLINQ_TRANSPORT_FP_H
#define QLINQ_TRANSPORT_FP_H

#include <stddef.h>
#include <stdint.h>

typedef int64_t fp_t;
__extension__ typedef __int128 fp_wide_t;

/* q46.17 fixed-point representation for path rates, latencies and probabilities
 */
#define FP_FRAC_BITS 17
#define FP_ONE ((fp_t)(INT64_C(1) << FP_FRAC_BITS))
#define FP_MAX INT64_MAX
#define FP_MAX_WHOLE ((size_t)(INT64_MAX >> FP_FRAC_BITS))
#define FP_SAFE_WHOLE ((size_t)(INT64_MAX >> (2 * FP_FRAC_BITS)))

#define FP_FROM_INT(x) ((fp_t)((int64_t)(x) * (INT64_C(1) << FP_FRAC_BITS)))
#define FP_TO_INT(x) ((x) >> FP_FRAC_BITS)
#define FP_FROM_FLOAT(x) ((fp_t)((x) * (float)FP_ONE))
#define FP_TO_FLOAT(x) ((float)(x) / (float)FP_ONE)

static inline fp_t fp_clamp_wide(fp_wide_t value) {
  if (value > INT64_MAX)
    return INT64_MAX;
  if (value < INT64_MIN)
    return INT64_MIN;
  return (fp_t)value;
}

static inline fp_t fp_mul(fp_t a, fp_t b) {
  return fp_clamp_wide(((fp_wide_t)a * b) / FP_ONE);
}

static inline fp_t fp_add(fp_t a, fp_t b) {
  return fp_clamp_wide((fp_wide_t)a + b);
}

static inline fp_t fp_sub(fp_t a, fp_t b) {
  return fp_clamp_wide((fp_wide_t)a - b);
}

static inline fp_t fp_div(fp_t a, fp_t b) {
  if (b == 0)
    return a < 0 ? INT64_MIN : INT64_MAX;
  return fp_clamp_wide(((fp_wide_t)a * FP_ONE) / b);
}

#define FP_MUL(a, b) fp_mul((a), (b))
#define FP_ADD(a, b) fp_add((a), (b))
#define FP_SUB(a, b) fp_sub((a), (b))
#define FP_DIV(a, b) fp_div((a), (b))

static inline fp_t fp_abs(fp_t a) {
  if (a == INT64_MIN)
    return INT64_MAX;
  return a < 0 ? -a : a;
}

static inline fp_t fp_floor(fp_t a) {
  return a & ~(FP_ONE - 1);
}

static inline fp_t fp_ceil(fp_t a) {
  return fp_add(a, FP_ONE - 1) & ~(FP_ONE - 1);
}

static inline fp_t fp_round(fp_t a) {
  return fp_add(a, FP_ONE >> 1) & ~(FP_ONE - 1);
}

/* integer square root adapted for fixed-point values */
static inline fp_t fp_sqrt(fp_t val) {
  if (val <= 0)
    return 0;
  fp_wide_t scaled = (fp_wide_t)val * FP_ONE;
  fp_wide_t res = 0;
  int top_bit = 63 - __builtin_clzll((uint64_t)val) + FP_FRAC_BITS;
  fp_wide_t bit = (fp_wide_t)1 << (top_bit & ~1);
  while (bit != 0) {
    if (scaled >= res + bit) {
      scaled -= res + bit;
      res = (res >> 1) + bit;
    } else {
      res >>= 1;
    }
    bit >>= 2;
  }
  return (fp_t)res;
}

#endif
