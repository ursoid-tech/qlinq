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

/* defaults apply only after an explicit nonzero presence mask opts in */
#define QLINQ_REPAIR_DEFAULT_CONFIDENCE 99U
#define QLINQ_REPAIR_DEFAULT_MAX_AGE_MS 150U
#define QLINQ_REPAIR_DEFAULT_REACTIVE true
#define QLINQ_REPAIR_DEFAULT_MAX_EXTRA_PERCENT 100U

/* local attempt retirement and confirmed peer outcome are reported separately.
 * a local failure cannot be rewritten by a late delivery confirmation. */
typedef enum {
  QLINQ_OUTCOME_PENDING = 0,
  QLINQ_OUTCOME_DELIVERED = 1,
  QLINQ_OUTCOME_EXPIRED = 2,
  QLINQ_OUTCOME_ABANDONED = 3
} qlinq_delivery_outcome_t;

typedef struct {
  qlinq_delivery_outcome_t local;
  qlinq_delivery_outcome_t peer;
} qlinq_delivery_report_t;

/* presence is independent of values. initialize before setting fields. a zero
 * present mask preserves legacy behavior, even in zero-initialized callers.
 * after endpoint/stream inheritance, omitted primary fields use the defaults
 * above. the minimum defaults to zero; the initial ceiling inherits the total
 * ceiling. explicit zero values override defaults and inherited values.
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
  uint8_t proactive_confidence;
  uint32_t max_object_age_ms;
  bool reactive_repair;
  uint32_t max_extra_percent;
  uint16_t min_initial_parity_symbols; /* effective zero at confidence zero */
  uint32_t max_initial_extra_percent;
} qlinq_effective_repair_policy_t;

/* reasons are independent: one obligation may encounter several. counters in
 * endpoint diagnostics count each reason once per accepted recipient attempt.
 */
typedef enum {
  QLINQ_REPAIR_PROACTIVE_DISABLED,
  QLINQ_REPAIR_INITIAL_LIMIT,
  QLINQ_REPAIR_TOTAL_LIMIT,
  QLINQ_REPAIR_CODEC_LIMIT,
  QLINQ_REPAIR_MINIMUM_UNMET,
  QLINQ_REPAIR_QUEUE_LIMIT,
  QLINQ_REPAIR_TIME_LIMIT,
  QLINQ_REPAIR_FIXED_SOURCE_FALLBACK,
  QLINQ_REPAIR_EXTRA_EXHAUSTED,
  QLINQ_REPAIR_EXPIRED,
  QLINQ_REPAIR_ABANDONED,
  QLINQ_REPAIR_SOURCE_RESOURCE,
  QLINQ_REPAIR_ENCODING_RESOURCE,
  QLINQ_REPAIR_UNSUPPORTED,
  QLINQ_REPAIR_PATH_UNAVAILABLE,
  QLINQ_REPAIR_PEER_UNAVAILABLE,
  QLINQ_REPAIR_NO_PROGRESS,
  QLINQ_REPAIR_FINAL_WAIT,
  QLINQ_REPAIR_REACTIVE_DISABLED,
  QLINQ_REPAIR_CONTROL_PENDING,
  QLINQ_REPAIR_REASON_COUNT
} qlinq_repair_reason_t;
#define QLINQ_REPAIR_REASON_BIT(reason) (UINT32_C(1) << (reason))
const char *qlinq_repair_reason_name(qlinq_repair_reason_t reason);

typedef struct {
  uint32_t peer_id, reasons;
  uint64_t epoch, attempt_id;
  uint16_t source_symbols, total_symbols, symbol_size;
  uint64_t requested_initial_parity, planned_initial_parity;
  uint64_t initial_extra_limit, total_extra_limit;
  /* a modeled plan, never an observed delivery probability or outcome */
  qlinq_effective_repair_policy_t effective;
} qlinq_repair_plan_sample_t;

typedef struct {
  uint64_t plans;
  uint64_t obligations_by_reason[QLINQ_REPAIR_REASON_COUNT];
  /* before acceptance: counts rejected calls, including caller retries */
  uint64_t admission_refusals[QLINQ_REPAIR_REASON_COUNT];
  /* application framing bytes admitted/received, including the frame header.
   * QUIC retransmissions and IP/QUIC headers are not included. */
  uint64_t control_frames_admitted, control_bytes_admitted;
  uint64_t control_frames_received, control_bytes_received;
  uint64_t duplicate_symbols_received, terminal_symbols_suppressed;
  uint64_t expired_symbols_received;
  /* unique-symbol decode attempts. failure does not assert matrix rank;
   * reported codec-quota refusals are counted separately, not as failures. */
  uint64_t decode_attempts, decode_failures_after_k, decoded_after_failure;
  uint64_t receive_window_evictions;
  /* sender: acceptance to locally timely peer confirmation */
  uint64_t confirmed_completions, confirmation_latency_ms_sum,
      confirmation_latency_ms_max;
  /* receiver: first symbol to useful application handoff, including grouped
   * event-queue residence. one completion per coding object, not per member. */
  uint64_t useful_receive_completions, receive_latency_ms_sum,
      receive_latency_ms_max;
  /* one bounded latest plan. logs sample the first and every 64th plan. */
  qlinq_repair_plan_sample_t last_plan;
} qlinq_repair_diagnostics_t;

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
