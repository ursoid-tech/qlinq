#ifndef QLINQ_TRANSPORT_REPAIR_POLICY_H
#define QLINQ_TRANSPORT_REPAIR_POLICY_H
#include "repair_policy.h"

#define TRANSPORT_PROTECTION_DISABLED                                          \
  QLINQ_REPAIR_REASON_BIT(QLINQ_REPAIR_PROACTIVE_DISABLED)
#define TRANSPORT_PROTECTION_INITIAL_LIMIT                                     \
  QLINQ_REPAIR_REASON_BIT(QLINQ_REPAIR_INITIAL_LIMIT)
#define TRANSPORT_PROTECTION_TOTAL_LIMIT                                       \
  QLINQ_REPAIR_REASON_BIT(QLINQ_REPAIR_TOTAL_LIMIT)
#define TRANSPORT_PROTECTION_CODEC_LIMIT                                       \
  QLINQ_REPAIR_REASON_BIT(QLINQ_REPAIR_CODEC_LIMIT)
#define TRANSPORT_PROTECTION_MINIMUM_UNMET                                     \
  QLINQ_REPAIR_REASON_BIT(QLINQ_REPAIR_MINIMUM_UNMET)

typedef struct {
  size_t initial_parity;
  size_t initial_extra_limit;
  size_t total_extra_limit;
  size_t parity_capacity; /* unique reserved IDs, not generated payloads */
  uint32_t reasons;
} transport_protection_plan_t;

/* requested estimator output is rounded up by the estimator before this call.
 * ceilings always round down. geometry is bounded by max_total_symbols. */
bool transport_repair_policy_plan(const qlinq_effective_repair_policy_t *policy,
                                  size_t source_symbols,
                                  size_t requested_parity,
                                  size_t max_total_symbols,
                                  transport_protection_plan_t *plan);
/* monotonic local clock, milliseconds. zero expiry means no deadline.
 * a caller-supplied expiry can only shorten the policy lifetime. */
bool transport_repair_policy_expiry(
    const qlinq_effective_repair_policy_t *policy, uint64_t accepted_ms,
    uint64_t earlier_expiry_ms, uint64_t *expiry_ms);
#endif
