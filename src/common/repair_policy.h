#ifndef QLINQ_REPAIR_POLICY_H
#define QLINQ_REPAIR_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QLINQ_REPAIR_CONFIDENCE (1U << 0)
#define QLINQ_REPAIR_MAX_AGE (1U << 1)
#define QLINQ_REPAIR_REACTIVE (1U << 2)
#define QLINQ_REPAIR_MAX_EXTRA (1U << 3)
#define QLINQ_REPAIR_MIN_INITIAL (1U << 4)
#define QLINQ_REPAIR_MAX_INITIAL_EXTRA (1U << 5)
#define QLINQ_REPAIR_PRIMARY_FIELDS 0x0fU
#define QLINQ_REPAIR_ALL_FIELDS 0x3fU
#define QLINQ_REPAIR_MAX_PERCENT 10000U
#define QLINQ_REPAIR_MAX_SYMBOLS 1024U

/* Defaults for standalone policy resolution, before applying a delivery mode.
 */
#define QLINQ_REPAIR_DEFAULT_CONFIDENCE 99U
#define QLINQ_REPAIR_DEFAULT_MAX_AGE_MS 150U
#define QLINQ_REPAIR_DEFAULT_REACTIVE true
#define QLINQ_REPAIR_DEFAULT_MAX_EXTRA_PERCENT 100U

/* presence is independent of values. initialize before setting fields. a zero
 * present mask preserves legacy behavior, even in zero-initialized callers.
 * Standalone resolution fills omitted primary fields with the defaults above.
 * Transport streams instead preserve their delivery mode for omitted fields:
 * fixed-rate enables proactive FEC; rateless enables reactive repair. There is
 * no policy deadline or total repair cap unless its presence bit is set. The
 * minimum defaults to zero; the initial ceiling inherits the total ceiling.
 * Explicit zero values override inherited values.
 *
 * confidence is double so fractional/non-finite inputs can be rejected before
 * conversion to pathflow's integer representation. percentages are integer
 * source-symbol byte percentages, bounded to 10,000 (100 times the source).
 * max_object_age_ms == 0 explicitly means no deadline; finite values are in
 * 1..UINT32_MAX. all fields without a presence bit are ignored. */
typedef struct {
  uint32_t present;
  double proactive_confidence;
  uint64_t max_object_age_ms;
  bool reactive_repair;
  uint64_t max_extra_percent;
  uint64_t min_initial_parity_symbols;
  uint64_t max_initial_extra_percent;
} qlinq_repair_policy_t;

typedef struct {
  bool enabled;
  /* In stream/transport getters, this is the merged explicit constraint mask.
   * Returned values reflect the applied delivery profile. In particular, an
   * absent MAX_EXTRA bit means reactive repairs have no policy total cap;
   * max_extra_percent then describes the initial scheduler's planning bound. */
  uint32_t present;
  uint8_t proactive_confidence;
  uint32_t max_object_age_ms;
  bool reactive_repair;
  uint32_t max_extra_percent;
  uint16_t min_initial_parity_symbols; /* effective zero at confidence zero */
  uint32_t max_initial_extra_percent;
} qlinq_effective_repair_policy_t;

void qlinq_repair_policy_init(qlinq_repair_policy_t *policy);
/* validate present fields without requiring a complete inherited policy */
bool qlinq_repair_policy_validate(const qlinq_repair_policy_t *policy,
                                  char *error, size_t capacity);
/* resolve a stream override over endpoint defaults. does not modify output on
 * failure. NULL is an absent policy. diagnostics are optional. */
bool qlinq_repair_policy_resolve(const qlinq_repair_policy_t *endpoint,
                                 const qlinq_repair_policy_t *stream,
                                 qlinq_effective_repair_policy_t *effective,
                                 char *error, size_t capacity);

#ifdef __cplusplus
}
#endif
#endif
