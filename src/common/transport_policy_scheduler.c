#include "transport_policy_scheduler.h"
#include <string.h>

size_t transport_policy_estimate_parity(size_t sources, fp_t loss,
                                        unsigned confidence) {
  if (sources > QLINQ_REPAIR_MAX_SYMBOLS ||
      (confidence != 0 && (confidence < 50 || confidence > 99)))
    return SIZE_MAX;
  if (confidence == 0 || sources == 0)
    return 0;
  /* same quantiles, clamping, rounding and operation order as the pinned
   * pathflow pathflow.c qnorm/calculate_n. keep equivalence tests against the
   * native optimizer: constrained candidates cannot use its unlimited costs. */
  static const float z[] = {
      0.000f, 0.025f, 0.050f, 0.075f, 0.100f, 0.126f, 0.151f, 0.176f, 0.202f,
      0.228f, 0.253f, 0.279f, 0.305f, 0.332f, 0.358f, 0.385f, 0.412f, 0.440f,
      0.468f, 0.496f, 0.524f, 0.553f, 0.583f, 0.613f, 0.643f, 0.674f, 0.706f,
      0.739f, 0.772f, 0.806f, 0.842f, 0.878f, 0.915f, 0.954f, 0.994f, 1.036f,
      1.080f, 1.126f, 1.175f, 1.227f, 1.282f, 1.341f, 1.405f, 1.476f, 1.555f,
      1.645f, 1.751f, 1.881f, 2.054f, 2.326f};
  fp_t p = loss < 0 ? 0 : loss;
  if (p > FP_FROM_FLOAT(0.999f))
    p = FP_FROM_FLOAT(0.999f);
  fp_t denominator = FP_ONE - p;
  fp_t c1 = FP_DIV(FP_MUL(FP_FROM_FLOAT(z[confidence - 50]), fp_sqrt(p)),
                   denominator);
  fp_t c2 = FP_DIV(p, denominator);
  fp_t n = FP_ADD(FP_MUL(c1, fp_sqrt(FP_FROM_INT(sources))),
                  FP_MUL(c2, FP_FROM_INT(sources)));
  return n <= 0 ? 0 : (size_t)FP_TO_INT(fp_ceil(n));
}

static fp_t finish(const transport_policy_path_t *path, size_t count) {
  if (count == 0)
    return 0;
  if (path->measurement.b <= 0 || path->measurement.p >= FP_ONE ||
      count > path->capacity)
    return FP_MAX;
  return FP_ADD(
      path->measurement.l,
      FP_DIV(FP_ADD(FP_FROM_INT(path->measurement.q), FP_FROM_INT(count)),
             path->measurement.b));
}

/* finish-time sequences are monotone. precompute only their feasible lengths;
 * no parity payload, heap allocation or per-symbol workspace is needed. */
static size_t feasible_count(const transport_policy_path_t *path, size_t limit,
                             fp_t horizon) {
  if (limit > path->capacity)
    limit = path->capacity;
  size_t low = 0, high = limit;
  while (low < high) {
    size_t middle = low + (high - low + 1U) / 2U;
    fp_t time = finish(path, middle);
    if (time != FP_MAX && time <= horizon)
      low = middle;
    else
      high = middle - 1U;
  }
  return low;
}

static bool evaluate(const qlinq_effective_repair_policy_t *policy,
                     const transport_policy_path_t *paths, size_t path_count,
                     size_t object_sources, size_t max_total_symbols,
                     fp_t horizon, size_t feasible_total, fp_t rate_sum,
                     fp_t minimum_latency, fp_t incumbent,
                     transport_policy_schedule_t *plan) {
  plan->requested_parity = 0;
  size_t sources = 0, placed = 0;
  for (size_t i = 0; i < path_count; i++) {
    fp_t source_finish = finish(&paths[i], plan->source[i]);
    if (plan->source[i] > paths[i].capacity || source_finish == FP_MAX ||
        source_finish > horizon)
      return false;
    size_t requested = transport_policy_estimate_parity(
        plan->source[i], paths[i].measurement.p, policy->proactive_confidence);
    if (requested == SIZE_MAX || requested > SIZE_MAX - plan->requested_parity)
      return false;
    plan->requested_parity += requested;
    sources += plan->source[i];
    placed += plan->parity[i];
  }
  if (!transport_repair_policy_plan(policy, object_sources,
                                    plan->requested_parity, max_total_symbols,
                                    &plan->protection))
    return false;
  size_t target = plan->protection.initial_parity;
  size_t room = feasible_total - sources;
  size_t attainable = target < room ? target : room;
  /* ignoring queue and all latency above the smallest path latency is a
   * lower bound even with fixed-point truncation. strictly worse candidates
   * cannot win, including the existing equal-time/higher-parity tie rule. */
  fp_t lower = FP_ADD(minimum_latency,
                      FP_DIV(FP_FROM_INT(sources + attainable), rate_sum));
  if (incumbent != FP_MAX && lower > incumbent)
    return false;
  /* source addition consumes the first old parity position on its path. the
   * caller removes that position; all remaining selections are still the
   * cheapest prefix of the new merged finish-time sequences. adjust only the
   * changed target, removing later path indices first on equal finish times. */
  while (placed > attainable) {
    size_t worst = SIZE_MAX;
    fp_t latest = -1;
    for (size_t i = 0; i < path_count; i++) {
      if (!plan->parity[i])
        continue;
      fp_t time = finish(&paths[i], plan->source[i] + plan->parity[i]);
      if (time >= latest) {
        latest = time;
        worst = i;
      }
    }
    if (worst == SIZE_MAX)
      return false;
    plan->parity[worst]--;
    placed--;
  }
  for (; placed < attainable; placed++) {
    size_t best = SIZE_MAX;
    fp_t earliest = FP_MAX;
    for (size_t i = 0; i < path_count; i++) {
      fp_t time = finish(&paths[i], plan->source[i] + plan->parity[i] + 1U);
      if (time <= horizon && time < earliest) {
        best = i;
        earliest = time;
      }
    }
    if (best == SIZE_MAX)
      break;
    plan->parity[best]++;
  }
  plan->protection.initial_parity = placed;
  if (placed < target) {
    bool queue_limited = true;
    for (size_t i = 0; i < path_count; i++)
      if (plan->source[i] + plan->parity[i] < paths[i].capacity &&
          paths[i].measurement.b > 0 && paths[i].measurement.p < FP_ONE)
        queue_limited = false;
    plan->protection.reasons |= queue_limited ? TRANSPORT_PROTECTION_QUEUE_LIMIT
                                              : TRANSPORT_PROTECTION_TIME_LIMIT;
    if (placed < policy->min_initial_parity_symbols)
      plan->protection.reasons |= TRANSPORT_PROTECTION_MINIMUM_UNMET;
  }
  plan->completion_seconds = 0;
  for (size_t i = 0; i < path_count; i++) {
    fp_t time = finish(&paths[i], plan->source[i] + plan->parity[i]);
    if (time > plan->completion_seconds)
      plan->completion_seconds = time;
  }
  return true;
}

bool transport_policy_schedule(const qlinq_effective_repair_policy_t *policy,
                               const transport_policy_path_t *paths,
                               size_t path_count, size_t source_symbols,
                               size_t max_total_symbols, fp_t horizon_seconds,
                               transport_policy_schedule_t *schedule) {
  if (!policy || !policy->enabled || !paths || !schedule || path_count == 0 ||
      path_count > TRANSPORT_POLICY_PATHS || source_symbols == 0 ||
      source_symbols > max_total_symbols ||
      max_total_symbols > QLINQ_REPAIR_MAX_SYMBOLS || horizon_seconds < 0)
    return false;
  for (size_t i = 0; i < path_count; i++)
    if (paths[i].measurement.q > FP_SAFE_WHOLE || paths[i].measurement.l < 0 ||
        paths[i].measurement.b < 0 ||
        paths[i].measurement.b > FP_FROM_INT(FP_SAFE_WHOLE) ||
        paths[i].measurement.l > FP_FROM_INT(FP_SAFE_WHOLE))
      return false;
  size_t feasible_total = 0;
  fp_t rate_sum = 0, minimum_latency = FP_MAX;
  for (size_t i = 0; i < path_count; i++) {
    size_t count =
        feasible_count(&paths[i], max_total_symbols, horizon_seconds);
    feasible_total += count;
    if (count) {
      rate_sum = FP_ADD(rate_sum, paths[i].measurement.b);
      if (paths[i].measurement.l < minimum_latency)
        minimum_latency = paths[i].measurement.l;
    }
  }
  if (feasible_total < source_symbols || rate_sum <= 0)
    return false;
  transport_policy_schedule_t current = {0};
  for (size_t symbol = 0; symbol < source_symbols; symbol++) {
    bool found = false;
    transport_policy_schedule_t best = {0};
    for (size_t i = 0; i < path_count; i++) {
      if (paths[i].measurement.b <= 0 || paths[i].measurement.p >= FP_ONE ||
          current.source[i] >= paths[i].capacity)
        continue;
      transport_policy_schedule_t candidate = current;
      candidate.source[i]++;
      if (candidate.parity[i])
        candidate.parity[i]--;
      if (!evaluate(policy, paths, path_count, source_symbols,
                    max_total_symbols, horizon_seconds, feasible_total,
                    rate_sum, minimum_latency,
                    found ? best.completion_seconds : FP_MAX, &candidate))
        continue;
      if (!found || candidate.completion_seconds < best.completion_seconds ||
          (candidate.completion_seconds == best.completion_seconds &&
           candidate.protection.initial_parity >
               best.protection.initial_parity)) {
        best = candidate;
        found = true;
      }
    }
    if (!found)
      return false;
    current = best;
  }
  *schedule = current;
  return true;
}
