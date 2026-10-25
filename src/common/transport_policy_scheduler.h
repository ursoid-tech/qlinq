#ifndef QLINQ_TRANSPORT_POLICY_SCHEDULER_H
#define QLINQ_TRANSPORT_POLICY_SCHEDULER_H

#include "pathflow.h"
#include "transport_repair_policy.h"

#define TRANSPORT_POLICY_PATHS 4U
#define TRANSPORT_PROTECTION_QUEUE_LIMIT                                       \
  QLINQ_REPAIR_REASON_BIT(QLINQ_REPAIR_QUEUE_LIMIT)
#define TRANSPORT_PROTECTION_TIME_LIMIT                                        \
  QLINQ_REPAIR_REASON_BIT(QLINQ_REPAIR_TIME_LIMIT)

typedef struct {
  path_t measurement;
  size_t capacity; /* additional symbols admissible on this path */
} transport_policy_path_t;

typedef struct {
  size_t source[TRANSPORT_POLICY_PATHS];
  size_t parity[TRANSPORT_POLICY_PATHS];
  size_t requested_parity;
  transport_protection_plan_t protection;
  fp_t completion_seconds;
} transport_policy_schedule_t;

/* pathflow's integer fixed-point approximation. zero confidence bypasses the
 * quantile calculation. returns SIZE_MAX for invalid/out-of-range input. */
size_t transport_policy_estimate_parity(size_t sources, fp_t loss,
                                        unsigned confidence);

/* bounded greedy source placement. every candidate is evaluated with its actual
 * capped object-wide parity, queue capacity and completion horizon. a floor
 * that cannot be met is reported, without preventing useful source admission.
 * horizon_seconds == FP_MAX means no deadline. the caller subtracts current
 * encoding/decoding/feedback uncertainty from its local remaining lifetime.
 * outputs physical source and parity counts separately. */
bool transport_policy_schedule(const qlinq_effective_repair_policy_t *policy,
                               const transport_policy_path_t *paths,
                               size_t path_count, size_t source_symbols,
                               size_t max_total_symbols, fp_t horizon_seconds,
                               transport_policy_schedule_t *schedule);

#endif
