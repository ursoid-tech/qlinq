#include "transport_policy_scheduler.h"
#include "transport_repair_policy.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

bool policy_schedule_reference(const qlinq_effective_repair_policy_t *,
                               const transport_policy_path_t *, size_t, size_t,
                               size_t, fp_t, transport_policy_schedule_t *);

static void equivalent(const qlinq_effective_repair_policy_t *policy,
                       const transport_policy_path_t *paths, size_t n, size_t k,
                       size_t total, fp_t horizon) {
  transport_policy_schedule_t actual = {0}, reference = {0};
  bool a =
      transport_policy_schedule(policy, paths, n, k, total, horizon, &actual);
  bool b = policy_schedule_reference(policy, paths, n, k, total, horizon,
                                     &reference);
  assert(a == b);
  if (!a)
    return;
  assert(!memcmp(actual.source, reference.source, sizeof(actual.source)) &&
         !memcmp(actual.parity, reference.parity, sizeof(actual.parity)) &&
         actual.requested_parity == reference.requested_parity &&
         actual.protection.initial_parity ==
             reference.protection.initial_parity &&
         actual.protection.initial_extra_limit ==
             reference.protection.initial_extra_limit &&
         actual.protection.total_extra_limit ==
             reference.protection.total_extra_limit &&
         actual.protection.parity_capacity ==
             reference.protection.parity_capacity &&
         actual.protection.reasons == reference.protection.reasons &&
         actual.completion_seconds == reference.completion_seconds);
}

static void test_greedy_equivalence(void) {
  uint32_t random = 73;
  for (size_t sample = 0; sample < 1000; sample++) {
    random = random * 1664525U + 1013904223U;
    size_t n = 1 + random % 4, k = 1 + (random >> 3) % 64;
    size_t total = k + (random >> 9) % 128;
    qlinq_effective_repair_policy_t policy = {
        .enabled = true,
        .proactive_confidence = sample % 7 ? (uint8_t)(50 + sample % 50) : 0,
        .max_extra_percent = (uint32_t)(sample % 501),
        .max_initial_extra_percent = (uint32_t)(sample % 501) / 2,
        .min_initial_parity_symbols = (uint16_t)(sample % 70)};
    transport_policy_path_t paths[4] = {0};
    for (size_t p = 0; p < n; p++) {
      random = random * 1664525U + 1013904223U;
      paths[p] = (transport_policy_path_t){
          .measurement = {.b = sample % 11 ? FP_FROM_INT(random % 10000)
                                           : FP_FROM_INT(FP_SAFE_WHOLE),
                          .p = FP_FROM_INT((random >> 8) % 101) / 100,
                          .l = sample % 11
                                   ? FP_FROM_INT((random >> 16) % 100) / 1000
                                   : 0,
                          .q = (random >> 20) % 20},
          .capacity = (random >> 25) % 130};
    }
    fp_t horizon = sample % 3    ? FP_MAX
                   : sample % 11 ? FP_FROM_INT(sample % 250) / 1000
                                 : 0;
    equivalent(&policy, paths, n, k, total, horizon);
  }
  for (size_t n = 1; n <= 4; n++) {
    qlinq_effective_repair_policy_t policy = {.enabled = true,
                                              .proactive_confidence = 99,
                                              .max_extra_percent = 100,
                                              .max_initial_extra_percent = 100,
                                              .min_initial_parity_symbols =
                                                  512};
    transport_policy_path_t paths[4] = {0};
    for (size_t p = 0; p < n; p++)
      paths[p] =
          (transport_policy_path_t){.measurement = {.b = FP_FROM_INT(5000),
                                                    .p = FP_FROM_INT(90) / 100,
                                                    .l = FP_FROM_INT(5) / 1000},
                                    .capacity = 1024};
    equivalent(&policy, paths, n, 512, 1024, FP_MAX);
    paths[0].measurement.p = 0;
    for (size_t p = 1; p < n; p++)
      paths[p].measurement.b = FP_FROM_INT(20);
    policy.min_initial_parity_symbols = 0;
    equivalent(&policy, paths, n, 512, 1024, FP_MAX);
  }
  /* fixed-point ties and saturated/very slow paths are part of the original
   * greedy contract, including no-deadline and exactly zero horizons */
  for (size_t sample = 0; sample < 128; sample++) {
    qlinq_effective_repair_policy_t policy = {
        .enabled = true,
        .proactive_confidence = 99,
        .max_extra_percent = 10000,
        .max_initial_extra_percent = 10000,
        .min_initial_parity_symbols = (uint16_t)(sample % 17)};
    transport_policy_path_t paths[4] = {0};
    for (size_t p = 0; p < 4; p++)
      paths[p] = (transport_policy_path_t){
          .measurement = {.b = p % 2 ? 1 : FP_FROM_INT(FP_SAFE_WHOLE),
                          .p = p == 3 ? FP_ONE : 0,
                          .l = sample % 2 ? 0 : FP_FROM_INT(1),
                          .q = sample % 3 ? 0 : FP_SAFE_WHOLE},
          .capacity = sample % 20};
    equivalent(&policy, paths, 4, 1 + sample % 16, 64, sample % 2 ? FP_MAX : 0);
  }
}

static qlinq_repair_policy_t example(void) {
  qlinq_repair_policy_t p;
  qlinq_repair_policy_init(&p);
  p.present = QLINQ_REPAIR_ALL_FIELDS;
  p.proactive_confidence = 99;
  p.max_object_age_ms = 100;
  p.reactive_repair = true;
  p.max_extra_percent = 50;
  p.min_initial_parity_symbols = 1;
  p.max_initial_extra_percent = 25;
  return p;
}

static void test_estimator(void) {
  const size_t counts[] = {1, 32, 100};
  const float losses[] = {0, 0.0001f, 0.01f, 0.1f, 0.5f, 0.999f};
  pathflow_context_t context = {0};
  for (unsigned confidence = 50; confidence <= 99; confidence++) {
    for (size_t c = 0; c < sizeof(counts) / sizeof(counts[0]); c++) {
      for (size_t l = 0; l < sizeof(losses) / sizeof(losses[0]); l++) {
        path_t path = {.b = FP_FROM_INT(1000),
                       .l = FP_FROM_FLOAT(0.01f),
                       .p = FP_FROM_FLOAT(losses[l])};
        assert(pathflow_optimize(&context, 1, counts[c], &path, FP_FROM_INT(10),
                                 confidence,
                                 PATHFLOW_SOLVER_GREEDY) != PATHFLOW_ERROR);
        assert(transport_policy_estimate_parity(
                   counts[c], path.p, confidence) == path.x - counts[c]);
      }
    }
  }
  assert(transport_policy_estimate_parity(100, FP_FROM_FLOAT(0.5f), 99) == 133);
  assert(transport_policy_estimate_parity(100, FP_FROM_FLOAT(0.5f), 50) == 100);
  assert(transport_policy_estimate_parity(100, FP_FROM_FLOAT(0.5f), 0) == 0);
  assert(transport_policy_estimate_parity(SIZE_MAX, FP_ONE, 99) == SIZE_MAX);
}

static void test_scheduler(void) {
  qlinq_repair_policy_t p = example();
  p.max_extra_percent = 200;
  p.max_initial_extra_percent = 200;
  p.min_initial_parity_symbols = 2;
  qlinq_effective_repair_policy_t e;
  assert(qlinq_repair_policy_resolve(&p, NULL, &e, NULL, 0));
  transport_policy_path_t paths[4] = {0};
  for (size_t i = 0; i < 4; i++) {
    paths[i].measurement.b = FP_FROM_INT(1000);
    paths[i].capacity = 64;
  }
  transport_policy_schedule_t schedule;
  assert(transport_policy_schedule(&e, paths, 4, 32, 1024, FP_MAX, &schedule));
  assert(schedule.protection.initial_parity ==
         2); /* object floor, not per path */
  paths[0].capacity = 1;
  assert(transport_policy_schedule(&e, paths, 1, 1, 1024, FP_MAX, &schedule));
  assert(schedule.source[0] == 1 && schedule.protection.initial_parity == 0);
  assert(schedule.protection.reasons & TRANSPORT_PROTECTION_MINIMUM_UNMET);
  assert(schedule.protection.reasons & TRANSPORT_PROTECTION_QUEUE_LIMIT);
  paths[0].capacity = 64;
  /* deadline permits one source but no floor parity */
  assert(transport_policy_schedule(
      &e, paths, 1, 1, 1024, FP_DIV(FP_ONE, FP_FROM_INT(1000)), &schedule));
  assert(schedule.source[0] == 1 && schedule.protection.initial_parity == 0);
  assert(schedule.protection.reasons & TRANSPORT_PROTECTION_TIME_LIMIT);
  paths[0].measurement.l = FP_ONE;
  assert(!transport_policy_schedule(&e, paths, 1, 1, 1024, FP_FROM_FLOAT(0.01f),
                                    &schedule));
  /* with zero overhead allowance, evaluate the fast lossy path at the actual
   * 32 transmissions, rather than rejecting its unlimited-parity cost */
  p.max_extra_percent = p.max_initial_extra_percent = 0;
  assert(qlinq_repair_policy_resolve(&p, NULL, &e, NULL, 0));
  paths[0].measurement.l = 0;
  paths[0].measurement.p = FP_FROM_FLOAT(0.9f);
  paths[1].measurement.b = FP_FROM_INT(10);
  assert(transport_policy_schedule(&e, paths, 2, 32, 1024, FP_MAX, &schedule));
  assert(schedule.source[0] == 32 && schedule.source[1] == 0 &&
         schedule.protection.initial_parity == 0);
  paths[0].measurement.p = FP_ONE;
  assert(transport_policy_schedule(&e, paths, 2, 32, 1024, FP_MAX, &schedule));
  assert(schedule.source[0] == 0 && schedule.source[1] == 32);
  /* deterministic variety covers rounding, zero capacity, codecs and horizons
   */
  for (unsigned seed = 1; seed <= 250; seed++) {
    size_t n = seed % 4 + 1, k = seed % 64 + 1;
    p.max_extra_percent = seed % 201;
    p.max_initial_extra_percent = p.max_extra_percent / 2;
    p.proactive_confidence = seed % 5 == 0 ? 0 : 50 + seed % 50;
    assert(qlinq_repair_policy_resolve(&p, NULL, &e, NULL, 0));
    for (size_t i = 0; i < n; i++) {
      paths[i].measurement =
          (path_t){.b = FP_FROM_INT(100 + seed % 1000),
                   .p = FP_DIV(FP_FROM_INT((seed + i) % 10), FP_FROM_INT(10)),
                   .l = FP_DIV(FP_FROM_INT((seed * i) % 10), FP_FROM_INT(1000)),
                   .q = seed % 5};
      paths[i].capacity = (seed * (i + 1)) % 65;
    }
    fp_t horizon = seed % 2 ? FP_MAX : FP_FROM_FLOAT(0.1f);
    if (!transport_policy_schedule(&e, paths, n, k, k + seed % 100, horizon,
                                   &schedule))
      continue;
    size_t source = 0, parity = 0;
    for (size_t i = 0; i < n; i++) {
      source += schedule.source[i];
      parity += schedule.parity[i];
      assert(schedule.source[i] + schedule.parity[i] <= paths[i].capacity);
    }
    assert(source == k && parity == schedule.protection.initial_parity);
    assert(parity <= k * e.max_initial_extra_percent / 100);
    assert(parity <= schedule.protection.parity_capacity);
    assert(schedule.completion_seconds <= horizon);
    assert(e.proactive_confidence || parity == 0);
  }
}

int main(void) {
  test_greedy_equivalence();
  test_estimator();
  test_scheduler();
  qlinq_repair_policy_t p = example(), override = {0};
  qlinq_effective_repair_policy_t e;
  char error[128];
  assert(qlinq_repair_policy_resolve(NULL, NULL, &e, error, sizeof(error)));
  assert(!e.enabled);
  assert(
      qlinq_repair_policy_resolve(&override, NULL, &e, error, sizeof(error)));
  assert(!e.enabled);
  assert(qlinq_repair_policy_resolve(&p, NULL, &e, error, sizeof(error)));
  assert(e.enabled && e.min_initial_parity_symbols == 1);
  transport_protection_plan_t plan;
  assert(transport_repair_policy_plan(&e, 32, 12, 1024, &plan));
  assert(plan.initial_parity == 8 && plan.initial_extra_limit == 8 &&
         plan.total_extra_limit == 16 && plan.parity_capacity == 16);
  assert(plan.reasons == TRANSPORT_PROTECTION_INITIAL_LIMIT);
  assert(transport_repair_policy_plan(&e, 1, 0, 1024, &plan));
  assert(plan.initial_parity == 0 && plan.parity_capacity == 0 &&
         (plan.reasons & TRANSPORT_PROTECTION_MINIMUM_UNMET));
  override.present = QLINQ_REPAIR_CONFIDENCE | QLINQ_REPAIR_MAX_AGE;
  override.proactive_confidence = 0;
  override.max_object_age_ms = 0;
  assert(qlinq_repair_policy_resolve(&p, &override, &e, NULL, 0));
  assert(e.enabled && e.proactive_confidence == 0 &&
         e.min_initial_parity_symbols == 0 && e.reactive_repair &&
         e.max_object_age_ms == 0);
  assert(transport_repair_policy_plan(&e, 32, SIZE_MAX, 1024, &plan));
  assert(plan.initial_parity == 0 && plan.total_extra_limit == 16 &&
         plan.reasons == TRANSPORT_PROTECTION_DISABLED);
  uint64_t expiry;
  assert(transport_repair_policy_expiry(&e, 1000, 0, &expiry) && expiry == 0);
  assert(transport_repair_policy_expiry(&e, 1000, 1050, &expiry) &&
         expiry == 1050);
  assert(!transport_repair_policy_expiry(&e, 1000, 1000, &expiry));
  assert(qlinq_repair_policy_resolve(&p, NULL, &e, NULL, 0));
  assert(transport_repair_policy_expiry(&e, 1000, 0, &expiry) &&
         expiry == 1100);
  assert(transport_repair_policy_expiry(&e, 1000, 1050, &expiry) &&
         expiry == 1050);
  assert(transport_repair_policy_expiry(&e, 1000, 1200, &expiry) &&
         expiry == 1100);
  assert(!transport_repair_policy_expiry(&e, UINT64_MAX - 99, 0, &expiry));
  assert(transport_repair_policy_plan(&e, 32, SIZE_MAX, 35, &plan));
  assert(plan.initial_parity == 3 &&
         (plan.reasons & TRANSPORT_PROTECTION_CODEC_LIMIT));
  assert(!transport_repair_policy_plan(&e, SIZE_MAX, 0, 1024, &plan));
  assert(!transport_repair_policy_plan(&e, 32, 0, SIZE_MAX, &plan));
  const double bad[] = {-1,   1,   49,  49.9,     50.5,
                        99.9, 100, NAN, INFINITY, -INFINITY};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    p.proactive_confidence = bad[i];
    qlinq_effective_repair_policy_t before = e;
    assert(!qlinq_repair_policy_resolve(&p, NULL, &e, error, sizeof(error)));
    assert(error[0] && memcmp(&e, &before, sizeof(e)) == 0);
  }
  for (unsigned confidence = 50; confidence <= 99; confidence++) {
    p.proactive_confidence = confidence;
    assert(qlinq_repair_policy_resolve(&p, NULL, &e, NULL, 0));
  }
  p = example();
  p.max_initial_extra_percent = 51;
  assert(!qlinq_repair_policy_resolve(&p, NULL, &e, NULL, 0));
  p = example();
  p.present &= ~QLINQ_REPAIR_MAX_INITIAL_EXTRA;
  assert(qlinq_repair_policy_resolve(&p, NULL, &e, NULL, 0));
  assert(e.max_initial_extra_percent == e.max_extra_percent);
  p.max_extra_percent = 0;
  assert(qlinq_repair_policy_resolve(&p, NULL, &e, NULL, 0));
  assert(transport_repair_policy_plan(&e, 32, SIZE_MAX, 1024, &plan));
  assert(plan.initial_parity == 0 && plan.total_extra_limit == 0);
  p.max_extra_percent = UINT64_MAX;
  assert(!qlinq_repair_policy_resolve(&p, NULL, &e, NULL, 0));
  p = example();
  p.max_object_age_ms = UINT64_MAX;
  assert(!qlinq_repair_policy_resolve(&p, NULL, &e, NULL, 0));
  p = example();
  p.min_initial_parity_symbols = UINT64_MAX;
  assert(!qlinq_repair_policy_resolve(&p, NULL, &e, NULL, 0));
  p = example();
  p.present |= 1U << 31;
  assert(!qlinq_repair_policy_resolve(&p, NULL, &e, NULL, 0));
  p = example();
  p.present = QLINQ_REPAIR_CONFIDENCE;
  assert(qlinq_repair_policy_resolve(&p, NULL, &e, NULL, 0));
  assert(e.enabled && e.proactive_confidence == p.proactive_confidence &&
         e.max_object_age_ms == 150 && e.reactive_repair &&
         e.max_extra_percent == 100 && e.max_initial_extra_percent == 100 &&
         e.min_initial_parity_symbols == 0);
  /* every individual presence bit opts in; unset garbage is ignored */
  for (unsigned bit = 0; bit < 6; ++bit) {
    p = (qlinq_repair_policy_t){.present = 1U << bit};
    assert(qlinq_repair_policy_resolve(&p, NULL, &e, NULL, 0));
    assert(e.enabled);
    assert(e.proactive_confidence == (bit == 0 ? 0 : 99));
    assert(e.max_object_age_ms == (bit == 1 ? 0 : 150));
    assert(e.reactive_repair == (bit != 2));
    assert(e.max_extra_percent == (bit == 3 ? 0 : 100));
    assert(e.max_initial_extra_percent == (bit == 3 || bit == 5 ? 0 : 100));
    assert(e.min_initial_parity_symbols == 0);
  }
  p = (qlinq_repair_policy_t){.present = QLINQ_REPAIR_MAX_EXTRA,
                              .max_extra_percent = 25};
  override = (qlinq_repair_policy_t){.present = QLINQ_REPAIR_MAX_INITIAL_EXTRA,
                                     .max_initial_extra_percent = 26};
  qlinq_effective_repair_policy_t unchanged = e;
  assert(!qlinq_repair_policy_resolve(&p, &override, &e, error, sizeof(error)));
  assert(error[0] && memcmp(&e, &unchanged, sizeof(e)) == 0);
  override.max_initial_extra_percent = 0;
  assert(qlinq_repair_policy_resolve(&p, &override, &e, NULL, 0));
  assert(e.max_extra_percent == 25 && e.max_initial_extra_percent == 0);
  puts("===REPAIR POLICY OK===");
  return 0;
}
