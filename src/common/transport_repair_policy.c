#include "transport_repair_policy.h"
#include <math.h>
#include <stdio.h>
#include <string.h>

const char *qlinq_repair_reason_name(qlinq_repair_reason_t reason) {
  static const char *const names[QLINQ_REPAIR_REASON_COUNT] = {
      "proactive-disabled", "initial-limit",
      "total-limit",        "codec-limit",
      "minimum-unmet",      "queue-limit",
      "time-limit",         "fixed-source-fallback",
      "extra-exhausted",    "expired",
      "abandoned",          "source-resource",
      "encoding-resource",  "unsupported",
      "path-unavailable",   "peer-unavailable",
      "no-progress",        "final-wait",
      "reactive-disabled",  "control-pending"};
  return (unsigned)reason < QLINQ_REPAIR_REASON_COUNT ? names[reason]
                                                      : "unknown";
}

void qlinq_repair_policy_init(qlinq_repair_policy_t *policy) {
  if (policy)
    memset(policy, 0, sizeof(*policy));
}

static bool invalid(char *error, size_t capacity, const char *reason) {
  if (error && capacity)
    snprintf(error, capacity, "%s", reason);
  return false;
}

bool qlinq_repair_policy_validate(const qlinq_repair_policy_t *p, char *error,
                                  size_t cap) {
  if (!p)
    return true;
  if (p->present & ~QLINQ_REPAIR_ALL_FIELDS)
    return invalid(error, cap, "unknown repair policy presence bits");
  if ((p->present & QLINQ_REPAIR_CONFIDENCE) &&
      (!isfinite(p->proactive_confidence) ||
       (p->proactive_confidence != 0 &&
        (p->proactive_confidence < 50 || p->proactive_confidence > 99 ||
         floor(p->proactive_confidence) != p->proactive_confidence))))
    return invalid(error, cap,
                   "proactive_confidence must be 0 or an integer 50..99");
  if ((p->present & QLINQ_REPAIR_MAX_AGE) && p->max_object_age_ms > UINT32_MAX)
    return invalid(error, cap, "max_object_age_ms exceeds UINT32_MAX");
  if (((p->present & QLINQ_REPAIR_MAX_EXTRA) &&
       p->max_extra_percent > QLINQ_REPAIR_MAX_PERCENT) ||
      ((p->present & QLINQ_REPAIR_MAX_INITIAL_EXTRA) &&
       p->max_initial_extra_percent > QLINQ_REPAIR_MAX_PERCENT))
    return invalid(error, cap, "extra percent exceeds 10000");
  if ((p->present & QLINQ_REPAIR_MIN_INITIAL) &&
      p->min_initial_parity_symbols > QLINQ_REPAIR_MAX_SYMBOLS)
    return invalid(error, cap, "minimum initial parity exceeds codec bound");
  return true;
}

bool qlinq_repair_policy_resolve(const qlinq_repair_policy_t *endpoint,
                                 const qlinq_repair_policy_t *stream,
                                 qlinq_effective_repair_policy_t *effective,
                                 char *error, size_t capacity) {
  if (!effective)
    return invalid(error, capacity, "missing effective repair policy output");
  if (!qlinq_repair_policy_validate(endpoint, error, capacity) ||
      !qlinq_repair_policy_validate(stream, error, capacity))
    return false;
  qlinq_repair_policy_t merged = {
      .proactive_confidence = QLINQ_REPAIR_DEFAULT_CONFIDENCE,
      .max_object_age_ms = QLINQ_REPAIR_DEFAULT_MAX_AGE_MS,
      .reactive_repair = QLINQ_REPAIR_DEFAULT_REACTIVE,
      .max_extra_percent = QLINQ_REPAIR_DEFAULT_MAX_EXTRA_PERCENT};
  const qlinq_repair_policy_t *layers[] = {endpoint, stream};
  for (size_t i = 0; i < 2; i++) {
    const qlinq_repair_policy_t *p = layers[i];
    if (!p)
      continue;
#define OVERLAY(bit, field)                                                    \
  if (p->present & (bit))                                                      \
  merged.field = p->field
    OVERLAY(QLINQ_REPAIR_CONFIDENCE, proactive_confidence);
    OVERLAY(QLINQ_REPAIR_MAX_AGE, max_object_age_ms);
    OVERLAY(QLINQ_REPAIR_REACTIVE, reactive_repair);
    OVERLAY(QLINQ_REPAIR_MAX_EXTRA, max_extra_percent);
    OVERLAY(QLINQ_REPAIR_MIN_INITIAL, min_initial_parity_symbols);
    OVERLAY(QLINQ_REPAIR_MAX_INITIAL_EXTRA, max_initial_extra_percent);
#undef OVERLAY
    merged.present |= p->present;
  }
  qlinq_effective_repair_policy_t result = {0};
  if (merged.present != 0) {
    if (!(merged.present & QLINQ_REPAIR_MAX_INITIAL_EXTRA))
      merged.max_initial_extra_percent = merged.max_extra_percent;
    if (merged.max_initial_extra_percent > merged.max_extra_percent)
      return invalid(error, capacity,
                     "initial extra ceiling exceeds total extra ceiling");
    result.enabled = true;
    result.proactive_confidence = (uint8_t)merged.proactive_confidence;
    result.max_object_age_ms = (uint32_t)merged.max_object_age_ms;
    result.reactive_repair = merged.reactive_repair;
    result.max_extra_percent = (uint32_t)merged.max_extra_percent;
    result.min_initial_parity_symbols =
        merged.proactive_confidence == 0
            ? 0
            : (uint16_t)merged.min_initial_parity_symbols;
    result.max_initial_extra_percent =
        (uint32_t)merged.max_initial_extra_percent;
  }
  *effective = result;
  if (error && capacity)
    error[0] = '\0';
  return true;
}

bool transport_repair_policy_plan(const qlinq_effective_repair_policy_t *policy,
                                  size_t source_symbols,
                                  size_t requested_parity,
                                  size_t max_total_symbols,
                                  transport_protection_plan_t *plan) {
  if (!policy || !policy->enabled || !plan || source_symbols == 0 ||
      max_total_symbols > QLINQ_REPAIR_MAX_SYMBOLS ||
      source_symbols > max_total_symbols ||
      policy->max_extra_percent > QLINQ_REPAIR_MAX_PERCENT ||
      policy->max_initial_extra_percent > policy->max_extra_percent)
    return false;
  /* multiplication is bounded by 1024 * 10000 even on a 32-bit host */
  transport_protection_plan_t p = {
      .initial_extra_limit =
          source_symbols * policy->max_initial_extra_percent / 100U,
      .total_extra_limit = source_symbols * policy->max_extra_percent / 100U};
  p.parity_capacity = max_total_symbols - source_symbols;
  if (p.parity_capacity > p.total_extra_limit)
    p.parity_capacity = p.total_extra_limit;
  if (policy->proactive_confidence == 0) {
    p.reasons = TRANSPORT_PROTECTION_DISABLED;
  } else {
    size_t requested = requested_parity;
    if (requested < policy->min_initial_parity_symbols)
      requested = policy->min_initial_parity_symbols;
    if (requested > p.initial_extra_limit)
      p.reasons |= TRANSPORT_PROTECTION_INITIAL_LIMIT;
    if (requested > p.total_extra_limit)
      p.reasons |= TRANSPORT_PROTECTION_TOTAL_LIMIT;
    if (requested > max_total_symbols - source_symbols)
      p.reasons |= TRANSPORT_PROTECTION_CODEC_LIMIT;
    p.initial_parity = requested;
    if (p.initial_parity > p.initial_extra_limit)
      p.initial_parity = p.initial_extra_limit;
    if (p.initial_parity > p.parity_capacity)
      p.initial_parity = p.parity_capacity;
    if (p.initial_parity < policy->min_initial_parity_symbols)
      p.reasons |= TRANSPORT_PROTECTION_MINIMUM_UNMET;
  }
  *plan = p;
  return true;
}

bool transport_repair_policy_expiry(
    const qlinq_effective_repair_policy_t *policy, uint64_t accepted_ms,
    uint64_t earlier_expiry_ms, uint64_t *expiry_ms) {
  if (!policy || !policy->enabled || !expiry_ms ||
      (earlier_expiry_ms != 0 && earlier_expiry_ms <= accepted_ms))
    return false;
  uint64_t expiry = 0;
  if (policy->max_object_age_ms != 0) {
    if (accepted_ms > UINT64_MAX - policy->max_object_age_ms)
      return false;
    expiry = accepted_ms + policy->max_object_age_ms;
  }
  if (earlier_expiry_ms != 0 && (expiry == 0 || earlier_expiry_ms < expiry))
    expiry = earlier_expiry_ms;
  *expiry_ms = expiry;
  return true;
}
