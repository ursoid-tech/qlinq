#include "transport_group_cc.h"
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct {
  quicly_flexicast_cc_t *cc;
  int64_t now;
  uint64_t epochs[64], rtt_epochs[64];
  struct {
    quicly_flexicast_feedback_t feedback;
    transport_group_cc_trace_state_t state_after;
    uint32_t reason;
  } event;
} fixture_t;
static uint64_t rate(quicly_flexicast_cc_t *cc) {
  return cc->output.rate_bytes_per_second;
}
static fixture_t create(void) {
  fixture_t w = {.now = 100000};
  quicly_flexicast_cc_config_t cfg = {.maximum_members = 63,
                                      .startup_rate_bytes_per_second = 32000,
                                      .minimum_rate_bytes_per_second = 250,
                                      .maximum_datagram_size = 1200,
                                      .feedback_timeout_msec = 1000};
  w.cc = transport_group_cc_mcbbr_new(&cfg, w.now);
  assert(w.cc != NULL);
  assert(quicly_flexicast_cc_on_member_added(w.cc, 1, w.now) == 0);
  return w;
}
static quicly_flexicast_feedback_t input(fixture_t *w, unsigned id,
                                         uint32_t rtt, int64_t step) {
  assert(id > 0 && id < 64);
  w->now += step;
  quicly_flexicast_feedback_t f = {0};
  f.member_id = id;
  f.epoch = ++w->epochs[id];
  f.now = w->now;
  f.acked_packets = 1;
  f.acked_bytes = 1200;
  f.largest_acknowledged = w->epochs[id];
  f.latest_rtt_msec = rtt;
  f.minimum_rtt_msec = 10;
  f.smoothed_rtt_msec = rtt;
  f.raw_rtt_msec = rtt + 10;
  f.rtt_ack_delay_msec = f.applied_ack_delay_msec = 10;
  f.rtt_sample_flags = QUICLY_FLEXICAST_RTT_VALID;
  f.rtt_sample_epoch = ++w->rtt_epochs[id];
  f.rtt_sample_at = w->now;
  f.delivery_sample_flags = 0;
  f.delivery_rate_sample_epoch = w->epochs[id];
  return f;
}
static void sample(quicly_flexicast_feedback_t *f, uint64_t ref,
                   uint64_t delivered) {
  f->delivery_sample_flags = QUICLY_FLEXICAST_SAMPLE_VALID;
  f->delivery_sample_fanout = 1;
  f->delivery_sample_pacing_rate_bytes_per_second = ref;
  f->delivery_rate_bytes_per_second = delivered;
  f->delivery_sample_bytes = delivered;
  f->delivery_sample_sent_at_start = f->now - f->raw_rtt_msec - 1001;
  f->delivery_sample_sent_at_end = f->now - f->raw_rtt_msec - 1;
  f->delivery_sample_acked_at_start = f->now - 1001;
  f->delivery_sample_acked_at_end = f->now - 1;
}
static void submit(fixture_t *w, const quicly_flexicast_feedback_t *f) {
  quicly_flexicast_cc_on_feedback(w->cc, f);
  w->event.feedback = *f;
  w->event.reason = w->cc->output.reason;
  assert(transport_group_cc_mcbbr_get_trace_state(w->cc, f->member_id, f->now,
                                                  &w->event.state_after));
}
static void warm(fixture_t *w, bool capacity) {
  for (unsigned e = 0; e < 10; e++) {
    quicly_flexicast_feedback_t f = input(w, 1, 100, 1000);
    if (capacity)
      sample(&f, rate(w->cc), rate(w->cc));
    submit(w, &f);
  }
}
static void ce(fixture_t *w) {
  quicly_flexicast_feedback_t f = input(w, 1, 100, 1000);
  f.ecn_ce_count = 1;
  submit(w, &f);
}
static void bounded_recovery(void) {
  fixture_t w = create();
  warm(&w, false);
  assert(rate(w.cc) == 32000);
  ce(&w);
  uint64_t reduced = rate(w.cc);
  assert(reduced == 27200);
  for (unsigned i = 0; i < 30; i++) {
    quicly_flexicast_feedback_t f = input(&w, 1, 100, 1000);
    submit(&w, &f);
    assert(rate(w.cc) <= 32000);
  }
  assert(rate(w.cc) > reduced && rate(w.cc) == 32000);
  assert(w.event.feedback.latest_rtt_msec == 100 &&
         w.event.feedback.minimum_rtt_msec == 10);
  transport_group_cc_mcbbr_free(w.cc);
}
static void no_unsupported_growth(unsigned mode) {
  fixture_t w = create();
  warm(&w, false);
  ce(&w);
  uint64_t before = rate(w.cc);
  for (unsigned e = 0; e < 20; e++) {
    quicly_flexicast_feedback_t f = input(&w, 1, 100, 1000);
    if (mode == 0)
      f.acked_packets = f.acked_bytes = 0;
    if (mode == 1)
      f.rtt_sample_flags = 0;
    if (mode == 2)
      f.rtt_sample_flags |= QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT;
    if (mode == 3)
      f.rtt_sample_epoch = 1;
    if (mode == 4)
      f.rtt_sample_at = f.now + 1;
    if (mode == 5)
      f.rtt_sample_at = f.now - 2000;
    if (mode == 6)
      f.raw_rtt_msec = 50;
    if (mode == 7)
      f.epoch = 1;
    if (mode == 8)
      f.lost_packets = 1;
    submit(&w, &f);
    assert(rate(w.cc) == before);
  }
  transport_group_cc_mcbbr_free(w.cc);
}
static void proof_and_invalid_capacity(unsigned mode) {
  fixture_t w = create();
  warm(&w, true);
  uint64_t before = rate(w.cc);
  assert(before > 32000);
  for (unsigned e = 0; e < 8; e++) {
    quicly_flexicast_feedback_t f = input(&w, 1, 100, 1000);
    sample(&f, before, before);
    switch (mode) {
    case 0:
      f.delivery_sample_flags |= QUICLY_FLEXICAST_SAMPLE_APP_LIMITED;
      break;
    case 1:
      f.delivery_sample_flags |= QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED;
      break;
    case 2:
      f.delivery_sample_flags |= QUICLY_FLEXICAST_SAMPLE_MIXED;
      break;
    case 3:
      f.delivery_sample_flags = 0;
      break;
    case 4:
      f.delivery_rate_sample_epoch = 1;
      break;
    case 5:
      f.delivery_sample_fanout = 0;
      break;
    case 6:
      f.delivery_sample_bytes = 0;
      break;
    case 7:
      f.delivery_sample_pacing_rate_bytes_per_second = 0;
      break;
    case 8:
      f.delivery_sample_sent_at_end = f.delivery_sample_sent_at_start - 1;
      break;
    case 9:
      f.delivery_sample_acked_at_end = f.now + 1;
      break;
    case 10:
      f.delivery_sample_acked_at_end = f.delivery_sample_acked_at_start;
      break;
    case 11:
      f.delivery_sample_acked_at_start -= 2000;
      f.delivery_sample_acked_at_end -= 2000;
      f.delivery_sample_sent_at_start -= 2000;
      f.delivery_sample_sent_at_end -= 2000;
      break;
    case 12:
      f.delivery_sample_sent_at_end = f.now;
      break;
    case 13:
      f.delivery_sample_sent_at_start = -1;
      break;
    case 14:
      sample(&f, 32000, 32000);
      break; /* A lower old pacing rate is no proof of the current rate. */
    default:
      assert(0);
    }
    submit(&w, &f);
    assert(rate(w.cc) == before);
  }
  transport_group_cc_mcbbr_free(w.cc);
}
static void capacity_and_radio_loss(bool growing) {
  fixture_t w = create();
  warm(&w, true);
  assert(w.event.state_after.baseline_delivery_ratio_ppm == 1000000);
  uint64_t before = rate(w.cc);
  for (unsigned e = 0; e < (growing ? 2U : 6U); e++) {
    quicly_flexicast_feedback_t f =
        input(&w, 1, growing ? (e == 0 ? 130 : 170) : 100, 1000);
    sample(&f, rate(w.cc), rate(w.cc) / 4);
    submit(&w, &f);
    if (!growing)
      assert(rate(w.cc) >= before);
  }
  if (growing)
    assert(rate(w.cc) <= before / 2 + 1 &&
           w.event.state_after.delivery_sample_post_cut);
  else
    assert(w.event.state_after.baseline_delivery_ratio_ppm <= 250000);
  transport_group_cc_mcbbr_free(w.cc);
}
static void loss_burst_vetoes_growth(void) {
  fixture_t w = create();
  warm(&w, true);
  uint64_t before = rate(w.cc);
  for (unsigned e = 0; e < 2; e++) {
    quicly_flexicast_feedback_t f = input(&w, 1, 100, 1000);
    sample(&f, rate(w.cc), rate(w.cc));
    f.lost_packets = 100;
    submit(&w, &f);
    assert(rate(w.cc) == before);
  }
  transport_group_cc_mcbbr_free(w.cc);
}
static void cumulative_growth(void) {
  fixture_t w = create();
  warm(&w, false);
  uint64_t before = rate(w.cc);
  for (unsigned e = 1; e <= 60; e++) {
    quicly_flexicast_feedback_t f = input(&w, 1, 100 + e, 1000);
    submit(&w, &f);
  }
  transport_group_cc_stats_t out;
  assert(transport_group_cc_mcbbr_get_stats(w.cc, &out));
  assert(out.rtt_reduction_events >= 2 && rate(w.cc) < before);
  transport_group_cc_mcbbr_free(w.cc);
}
static void correlated_receivers(void) {
  fixture_t w = create();
  for (unsigned id = 2; id <= 50; id++)
    quicly_flexicast_cc_on_member_added(w.cc, id, w.now);
  for (unsigned phase = 0; phase < 3; phase++)
    for (unsigned id = 1; id <= 50; id++) {
      quicly_flexicast_feedback_t f = input(&w, id, 100 + 20 * phase, 30);
      submit(&w, &f);
    }
  transport_group_cc_stats_t o;
  assert(transport_group_cc_mcbbr_get_stats(w.cc, &o));
  assert(o.rtt_reduction_events == 1 && rate(w.cc) == 28800);
  /* Large old flights cannot furnish post-cut trend evidence. */
  for (unsigned id = 1; id <= 50; id++) {
    quicly_flexicast_feedback_t f = input(&w, id, 5000, 1);
    submit(&w, &f);
  }
  assert(transport_group_cc_mcbbr_get_stats(w.cc, &o));
  assert(o.rtt_reduction_events == 1);
  quicly_flexicast_feedback_t first_post_cut = input(&w, 2, 5500, 15000);
  submit(&w, &first_post_cut);
  assert(transport_group_cc_mcbbr_get_stats(w.cc, &o));
  assert(o.rtt_reduction_events == 1);
  transport_group_cc_mcbbr_free(w.cc);
}
static void lower_path_then_renewed_growth(void) {
  fixture_t w = create();
  warm(&w, false);
  for (unsigned e = 0; e < 6; e++) {
    quicly_flexicast_feedback_t f = input(&w, 1, 5000, 5000);
    submit(&w, &f);
  }
  for (unsigned e = 0; e < 6; e++) {
    quicly_flexicast_feedback_t f = input(&w, 1, 1000, 1000);
    submit(&w, &f);
  }
  uint64_t before = rate(w.cc);
  quicly_flexicast_feedback_t f = input(&w, 1, 1100, 1500);
  submit(&w, &f);
  f = input(&w, 1, 1250, 1500);
  submit(&w, &f);
  assert(rate(w.cc) < before);
  transport_group_cc_mcbbr_free(w.cc);
}
static void slowest_flight(void) {
  fixture_t w = create();
  quicly_flexicast_cc_on_member_added(w.cc, 2, w.now);
  quicly_flexicast_feedback_t f = input(&w, 2, 5000, 1000);
  submit(&w, &f);
  for (unsigned e = 0; e < 3; e++) {
    f = input(&w, 1, 100 + 20 * e, 1000);
    submit(&w, &f);
  }
  uint64_t before = rate(w.cc);
  assert(before == 28800);
  for (unsigned e = 0; e < 25; e++) {
    f = input(&w, 1, 160 + 10 * e, 100);
    submit(&w, &f);
    assert(rate(w.cc) == before);
  }
  transport_group_cc_mcbbr_free(w.cc);
}
static void timeout_and_members(void) {
  fixture_t w = create();
  warm(&w, false);
  for (unsigned e = 1; e <= 3; e++)
    quicly_flexicast_cc_on_timeout(w.cc, w.now + 1000 * e);
  assert(rate(w.cc) == 16000);
  uint64_t before = rate(w.cc);
  for (unsigned e = 0; e < 10; e++)
    quicly_flexicast_cc_on_timeout(w.cc, w.now + 3000);
  assert(rate(w.cc) == before);
  quicly_flexicast_cc_on_member_suspended(w.cc, 1, w.now + 3000);
  quicly_flexicast_cc_output_t o = w.cc->output;
  assert(o.next_timeout == INT64_MAX && o.limiting_member_id == 0);
  quicly_flexicast_cc_on_timeout(w.cc, w.now + 100000);
  assert(rate(w.cc) == before);
  quicly_flexicast_cc_on_member_added(w.cc, 1, w.now + 100000);
  w.now += 100000;
  warm(&w, false);
  assert(rate(w.cc) <= 32000 && rate(w.cc) > before);
  quicly_flexicast_cc_on_member_removed(w.cc, 1, w.now);
  quicly_flexicast_feedback_t f = input(&w, 1, 100, 1000);
  submit(&w, &f);
  assert(!w.event.state_after.member_present);
  transport_group_cc_mcbbr_free(w.cc);
}
static void epoch_clears_samples(void) {
  fixture_t w = create();
  warm(&w, false);
  ce(&w);
  uint64_t before = rate(w.cc);
  quicly_flexicast_cc_on_epoch_reset(w.cc, w.now);
  w.epochs[1] = w.rtt_epochs[1] = 0;
  quicly_flexicast_feedback_t f = input(&w, 1, 100, 1000);
  submit(&w, &f);
  assert(rate(w.cc) == before &&
         w.event.state_after.last_rtt_sample_epoch == 1);
  assert(w.event.state_after.rising_delay_epochs == 0);
  transport_group_cc_mcbbr_free(w.cc);
}
static void external_and_hard_bound(void) {
  fixture_t w = create();
  warm(&w, false);
  ce(&w);
  uint64_t before = rate(w.cc);
  transport_group_cc_hints_t h = {.external_load_epoch = 1,
                                  .external_load_queued_bytes = 1000};
  transport_group_cc_mcbbr_set_hints(w.cc, &h, w.now);
  warm(&w, false);
  assert(rate(w.cc) == before);
  h.external_load_queued_bytes = 0;
  for (unsigned e = 0; e < 4; e++) {
    transport_group_cc_mcbbr_set_hints(w.cc, &h, w.now);
    warm(&w, false);
    assert(rate(w.cc) == before);
  }
  for (unsigned e = 0; e < 2; e++) {
    ++h.external_load_epoch;
    transport_group_cc_mcbbr_set_hints(w.cc, &h, w.now);
    warm(&w, false);
    assert(rate(w.cc) == before);
  }
  ++h.external_load_epoch;
  transport_group_cc_mcbbr_set_hints(w.cc, &h, w.now);
  warm(&w, false);
  assert(rate(w.cc) > before);
  h.aggregate_rate_limit_bytes_per_second = 200;
  transport_group_cc_mcbbr_set_hints(w.cc, &h, w.now);
  assert(rate(w.cc) == 200);
  warm(&w, true);
  assert(rate(w.cc) == 200);
  transport_group_cc_mcbbr_free(w.cc);
}
static void precut_capacity_is_not_current_proof(void) {
  fixture_t w = create();
  warm(&w, true);
  ce(&w);
  int64_t cut_at = w.now;
  uint64_t before = rate(w.cc);
  assert(before > 32000);
  warm(&w, false);
  assert(rate(w.cc) == before);
  quicly_flexicast_feedback_t f = input(&w, 1, 100, 1000);
  sample(&f, before, before);
  f.delivery_sample_sent_at_start = cut_at - 10;
  f.delivery_sample_sent_at_end = cut_at - 1;
  submit(&w, &f);
  assert(rate(w.cc) == before);
  assert(w.event.state_after.delivery_ceiling_eligible &&
         !w.event.state_after.delivery_sample_post_cut);
  transport_group_cc_mcbbr_free(w.cc);
}
static void minimum_and_burst_bounds(void) {
  fixture_t w = create();
  for (unsigned e = 0; e < 100; e++) {
    ce(&w);
    assert(rate(w.cc) >= 250);
    quicly_flexicast_cc_output_t o = w.cc->output;
    assert(o.burst_bytes >= 4800 && o.burst_bytes <= 12000 &&
           o.inflight_bytes == o.burst_bytes);
  }
  assert(rate(w.cc) == 250);
  transport_group_cc_mcbbr_free(w.cc);
}
static void zero_clock_and_overflow(void) {
  fixture_t w = create();
  quicly_flexicast_cc_on_epoch_reset(w.cc, 0);
  w.now = 0;
  w.epochs[1] = 0;
  quicly_flexicast_feedback_t f = {
      .member_id = 1, .epoch = 1, .ecn_ce_count = 1, .now = 0};
  submit(&w, &f);
  uint64_t before = rate(w.cc);
  assert(before == 27200);
  f.epoch = 2;
  f.now = 1;
  submit(&w, &f);
  assert(rate(w.cc) == before);
  f.epoch = 3;
  f.now = 250;
  submit(&w, &f);
  assert(rate(w.cc) == 23120);
  quicly_flexicast_cc_on_epoch_reset(w.cc, INT64_MAX - 500);
  w.now = INT64_MAX - 500;
  w.epochs[1] = 0;
  quicly_flexicast_cc_on_timeout(w.cc, INT64_MAX);
  before = rate(w.cc);
  for (unsigned e = 0; e < 10; e++)
    quicly_flexicast_cc_on_timeout(w.cc, INT64_MAX);
  assert(rate(w.cc) == before);
  transport_group_cc_mcbbr_free(w.cc);
  w = create();
  warm(&w, true);
  before = rate(w.cc);
  f = input(&w, 1, 100, 1000);
  sample(&f, UINT64_MAX, UINT64_MAX);
  f.delivery_sample_fanout = UINT32_MAX;
  submit(&w, &f);
  assert(rate(w.cc) > before &&
         w.event.state_after.recent_delivery_ratio_ppm == 1000000);
  transport_group_cc_mcbbr_free(w.cc);
}
static void bbrv3_drain_and_cohort(void) {
  /* windowed min-RTT filter expiry and cross-member corroboration */
  fixture_t w = create();
  quicly_flexicast_cc_on_member_added(w.cc, 2, w.now);
  quicly_flexicast_feedback_t f2 = input(&w, 2, 2000, 100);
  f2.minimum_rtt_msec = 0;
  submit(&w, &f2);
  quicly_flexicast_feedback_t f1 = input(&w, 1, 100, 100);
  f1.minimum_rtt_msec = 0;
  submit(&w, &f1);
  assert(w.event.state_after.minimum_rtt == 100);
  /* single uncorroborated rise on member 1 blocks only for member 1's flight */
  f1 = input(&w, 1, 120, 100);
  f1.minimum_rtt_msec = 0;
  submit(&w, &f1);
  assert(w.event.state_after.growth_blocked_until == f1.now + 250);
  /* corroborated rise on member 1 when member 2 also rises blocks for group */
  f2 = input(&w, 2, 2200, 100);
  f2.minimum_rtt_msec = 0;
  submit(&w, &f2);
  assert(w.event.state_after.growth_blocked_until == f2.now + 2210);
  transport_group_cc_mcbbr_free(w.cc);

  /* cohort median catch-up and drain lifecycle */
  w = create();
  warm(&w, true);
  uint64_t base = rate(w.cc);
  transport_group_cc_hints_t h = {
      .active_senders = 1, .median_sender_rate_bytes_per_second = base + 1500};
  transport_group_cc_mcbbr_set_hints(w.cc, &h, w.now);
  quicly_flexicast_feedback_t f = input(&w, 1, 100, 1000);
  sample(&f, base, base);
  submit(&w, &f);
  assert(rate(w.cc) == base + 1500);
  f = input(&w, 1, 130, 1000);
  sample(&f, rate(w.cc), rate(w.cc) / 2);
  submit(&w, &f);
  assert(w.event.state_after.drain_phase == 1);
  f = input(&w, 1, 100, 1000);
  sample(&f, rate(w.cc), rate(w.cc));
  submit(&w, &f);
  assert(w.event.state_after.drain_phase == 0 &&
         (w.event.reason & TRANSPORT_GROUP_CC_REASON_DRAIN_CLEAR));
  transport_group_cc_mcbbr_free(w.cc);
}

static void drain_active_and_hint_isolation(void) {
  /* active drain cuts toward 0.8 * ceiling with DRAIN_CUT */
  fixture_t w = create();
  warm(&w, true);
  uint64_t peak = rate(w.cc);
  uint64_t cap = (peak * 3) / 4;
  quicly_flexicast_feedback_t f = input(&w, 1, 130, 1000);
  sample(&f, peak, cap);
  submit(&w, &f);
  assert(w.event.state_after.drain_phase == 1);
  f = input(&w, 1, 165, 1000);
  sample(&f, peak, cap);
  submit(&w, &f);
  uint64_t expected_target = (cap * 80) / 100;
  assert(w.event.state_after.drain_phase == 2);
  assert((w.event.reason & TRANSPORT_GROUP_CC_REASON_DRAIN_ENTER) &&
         (w.event.reason & TRANSPORT_GROUP_CC_REASON_DRAIN_CUT));
  assert(rate(w.cc) == w.event.state_after.drain_target_bytes_per_second);
  assert(rate(w.cc) + 2 >= expected_target &&
         rate(w.cc) <= expected_target + 2);
  transport_group_cc_mcbbr_free(w.cc);

  /* stale external-load epochs are ignored and rate limits avoid cut_seen */
  w = create();
  transport_group_cc_hints_t h = {.aggregate_rate_limit_bytes_per_second =
                                      10000,
                                  .external_load_epoch = 10,
                                  .external_load_queued_bytes = 4096};
  transport_group_cc_mcbbr_set_hints(w.cc, &h, w.now);
  assert(transport_group_cc_mcbbr_get_trace_state(w.cc, 1, w.now,
                                                  &w.event.state_after));
  assert(rate(w.cc) == 10000 && w.event.state_after.last_reduction_epoch == 0 &&
         w.event.state_after.external_load);
  for (uint64_t ep = 1; ep <= 4; ep++) {
    transport_group_cc_hints_t stale = {.active_senders = 8,
                                        .external_load_epoch = ep};
    transport_group_cc_mcbbr_set_hints(w.cc, &stale, w.now + (int64_t)ep);
    assert(transport_group_cc_mcbbr_get_trace_state(
        w.cc, 1, w.now + (int64_t)ep, &w.event.state_after));
  }
  assert(w.event.state_after.external_load);
  transport_group_cc_mcbbr_free(w.cc);
}

static uint32_t next_rng(uint64_t *state) {
  *state =
      *state * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
  return (uint32_t)(*state >> 32);
}

static void exp13_fifty_writer_equilibrium(void) {
  /* 50 writers on shared 11 mbps wifi with +2000ms RTT step and burst loss */
  enum { WRITERS = 50, PEERS = 49 };
  quicly_flexicast_cc_t *ccs[WRITERS];
  uint64_t fb_epoch[WRITERS][PEERS + 1] = {{0}};
  uint64_t rtt_epoch[WRITERS][PEERS + 1] = {{0}};
  int64_t last_ack_at[WRITERS][PEERS + 1] = {{0}};
  uint64_t last_ack_rate[WRITERS][PEERS + 1] = {{0}};
  unsigned next_peer[WRITERS] = {0};
  double sum_rates[WRITERS] = {0};
  unsigned rate_samples[WRITERS] = {0};
  int64_t low_start[WRITERS];
  int64_t longest_low[WRITERS] = {0};
  for (unsigned i = 0; i < WRITERS; i++)
    low_start[i] = -1;

  quicly_flexicast_cc_config_t cfg = {.maximum_members = 50,
                                      .startup_rate_bytes_per_second = 32000,
                                      .minimum_rate_bytes_per_second = 250,
                                      .maximum_datagram_size = 1200,
                                      .feedback_timeout_msec = 1000};
  int64_t start = 100000;
  for (unsigned i = 0; i < WRITERS; i++) {
    ccs[i] = transport_group_cc_mcbbr_new(&cfg, start);
    assert(ccs[i] != NULL);
    for (unsigned m = 1; m <= PEERS; m++) {
      quicly_flexicast_cc_on_member_added(ccs[i], m, start);
      last_ack_at[i][m] = start;
      last_ack_rate[i][m] = 32000;
    }
    next_peer[i] = i % PEERS;
  }

  const double capacity_bps = 620000.0;
  double queue_bytes = 0.0;
  uint64_t rng = UINT64_C(0x5eed130013);
  bool ge_bad[WRITERS] = {0};

  for (int64_t elapsed = 250; elapsed <= 270000; elapsed += 250) {
    int64_t now = start + elapsed;
    double agg = 0.0;
    uint64_t cur_rates[WRITERS];
    for (unsigned i = 0; i < WRITERS; i++) {
      uint64_t r = rate(ccs[i]);
      /* node airtime limit ~24 KB/s in exp 13 */
      cur_rates[i] = r > 24000 ? 24000 : r;
      agg += (double)cur_rates[i];
    }
    queue_bytes += (agg - capacity_bps) * 0.25;
    if (queue_bytes < 0.0)
      queue_bytes = 0.0;
    if (queue_bytes > 480000.0)
      queue_bytes = 480000.0;

    double loss_cong =
        agg > capacity_bps * 1.15 ? (agg - capacity_bps * 1.15) / agg : 0.0;
    double delivery_share = agg > capacity_bps ? capacity_bps / agg : 1.0;
    uint32_t base_rtt = elapsed >= 20000 ? 2040U : 40U;
    uint32_t queue_ms = (uint32_t)(queue_bytes * 1000.0 / capacity_bps);

    /* update cohort hints once per second */
    if (elapsed % 1000 == 0) {
      uint64_t sorted[WRITERS];
      for (unsigned i = 0; i < WRITERS; i++)
        sorted[i] = (uint64_t)((double)cur_rates[i] * delivery_share * 0.96);
      for (unsigned i = 1; i < WRITERS; i++) {
        uint64_t v = sorted[i];
        unsigned j = i;
        while (j > 0 && sorted[j - 1] > v) {
          sorted[j] = sorted[j - 1];
          --j;
        }
        sorted[j] = v;
      }
      uint64_t med = (sorted[WRITERS / 2 - 1] + sorted[WRITERS / 2]) / 2;
      for (unsigned i = 0; i < WRITERS; i++) {
        transport_group_cc_hints_t h = {.active_senders = WRITERS,
                                        .delivery_rate_divisor = 1,
                                        .median_sender_rate_bytes_per_second =
                                            med};
        transport_group_cc_mcbbr_set_hints(ccs[i], &h, now);
      }
    }

    for (unsigned i = 0; i < WRITERS; i++) {
      quicly_flexicast_cc_on_timeout(ccs[i], now);
      /* QGFB DRR delivers ~16 of 49 peers per 2000ms RTT (~2 per 250ms tick) */
      unsigned reports = elapsed >= 20000 ? 2U : 6U;
      for (unsigned rep = 0; rep < reports; rep++) {
        unsigned member = (next_peer[i] % PEERS) + 1;
        ++next_peer[i];
        if (elapsed >= 20000 && (next_rng(&rng) % 100) < 10)
          continue;

        uint32_t jitter = next_rng(&rng) % (elapsed >= 20000 ? 180U : 16U);
        uint32_t rtt = base_rtt + queue_ms + jitter;
        uint64_t ref = rate(ccs[i]);
        bool host_lim = ref > 24000;
        bool mixed = ref != last_ack_rate[i][member];
        last_ack_rate[i][member] = ref;

        int64_t prev_ack = last_ack_at[i][member];
        uint64_t span_ms = now > prev_ack ? (uint64_t)(now - prev_ack) : 500U;
        uint64_t pkts = (cur_rates[i] * span_ms) / (1000U * 1100U);
        if (pkts < 2)
          pkts = 2;
        uint64_t lost = 0;
        for (uint64_t p = 0; p < pkts; p++) {
          if (elapsed >= 20000) {
            uint32_t u = next_rng(&rng) % 100;
            ge_bad[i] = ge_bad[i] ? (u >= 2) : (u < 1);
          }
          double p_loss =
              loss_cong + (elapsed >= 20000 ? (ge_bad[i] ? 0.50 : 0.01) : 0.0);
          if ((double)(next_rng(&rng) % 10000) / 10000.0 < p_loss)
            ++lost;
        }
        uint64_t acked = pkts > lost ? pkts - lost : 1;

        quicly_flexicast_feedback_t f = {0};
        f.member_id = member;
        uint32_t ack_delay = 450U + (next_rng(&rng) % 6000U);
        uint32_t raw_rtt = rtt + ack_delay;
        uint32_t min_raw = 40U + 450U;
        f.epoch = ++fb_epoch[i][member];
        f.now = now;
        f.acked_packets = acked;
        f.lost_packets = lost;
        f.acked_bytes = acked * 1100;
        f.largest_acknowledged = fb_epoch[i][member];
        f.minimum_rtt_msec = raw_rtt < min_raw ? raw_rtt : min_raw;
        f.raw_rtt_msec = raw_rtt;
        f.rtt_ack_delay_msec = ack_delay;
        if ((uint64_t)raw_rtt >= (uint64_t)f.minimum_rtt_msec + ack_delay) {
          f.latest_rtt_msec = raw_rtt - ack_delay;
          f.applied_ack_delay_msec = ack_delay;
          f.rtt_sample_flags = QUICLY_FLEXICAST_RTT_VALID;
        } else {
          f.latest_rtt_msec = raw_rtt;
          f.applied_ack_delay_msec = 0;
          f.rtt_sample_flags = QUICLY_FLEXICAST_RTT_VALID |
                               QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT;
        }
        f.smoothed_rtt_msec = f.latest_rtt_msec;
        f.rtt_sample_epoch = ++rtt_epoch[i][member];
        f.rtt_sample_at = now;
        f.delivery_sample_flags =
            QUICLY_FLEXICAST_SAMPLE_VALID |
            (host_lim ? QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED : 0) |
            (mixed ? QUICLY_FLEXICAST_SAMPLE_MIXED : 0);
        if (mixed)
          f.delivery_sample_flags &= ~QUICLY_FLEXICAST_SAMPLE_VALID;
        f.delivery_rate_sample_epoch = fb_epoch[i][member];
        f.delivery_sample_fanout = 1;
        f.delivery_sample_pacing_rate_bytes_per_second = ref;
        uint64_t deliv = (uint64_t)((double)cur_rates[i] * delivery_share *
                                    (double)acked / (double)(acked + lost));
        if (!deliv)
          deliv = 1;
        f.delivery_rate_bytes_per_second = deliv;
        f.delivery_sample_bytes = deliv * 2;
        if (prev_ack >= now - 1)
          prev_ack = now - 500;
        f.delivery_sample_acked_at_start = prev_ack - 500;
        f.delivery_sample_acked_at_end = prev_ack;
        f.delivery_sample_sent_at_start =
            prev_ack - (int64_t)f.raw_rtt_msec - 500;
        f.delivery_sample_sent_at_end = prev_ack - (int64_t)f.raw_rtt_msec;
        if (f.delivery_sample_sent_at_start < 0)
          f.delivery_sample_sent_at_start = 0;
        if (f.delivery_sample_sent_at_end < f.delivery_sample_sent_at_start)
          f.delivery_sample_sent_at_end = f.delivery_sample_sent_at_start;
        last_ack_at[i][member] = now;
        quicly_flexicast_cc_on_feedback(ccs[i], &f);
      }
    }

    if (elapsed >= 150000 && elapsed <= 270000) {
      for (unsigned i = 0; i < WRITERS; i++) {
        uint64_t r = rate(ccs[i]);
        sum_rates[i] += (double)r;
        ++rate_samples[i];
        if (r <= 3750) {
          if (low_start[i] < 0)
            low_start[i] = elapsed;
          if (elapsed - low_start[i] > longest_low[i])
            longest_low[i] = elapsed - low_start[i];
        } else {
          low_start[i] = -1;
        }
      }
    }
  }

  double means[WRITERS], sum = 0.0, sum_sq = 0.0, min_mean = 1e18;
  unsigned healthy = 0;
  int64_t worst_low = 0;
  for (unsigned i = 0; i < WRITERS; i++) {
    means[i] = sum_rates[i] / (double)rate_samples[i];
    sum += means[i];
    sum_sq += means[i] * means[i];
    if (means[i] < min_mean)
      min_mean = means[i];
    if (means[i] * 8.0 >= 33000.0)
      ++healthy;
    if (longest_low[i] > worst_low)
      worst_low = longest_low[i];
    transport_group_cc_mcbbr_free(ccs[i]);
  }
  for (unsigned i = 1; i < WRITERS; i++) {
    double v = means[i];
    unsigned j = i;
    while (j > 0 && means[j - 1] > v) {
      means[j] = means[j - 1];
      --j;
    }
    means[j] = v;
  }
  double mean_all = sum / (double)WRITERS;
  double jain = (sum * sum) / ((double)WRITERS * sum_sq);
  double median_bps =
      ((means[WRITERS / 2 - 1] + means[WRITERS / 2]) * 0.5) * 8.0;
  printf("exp13 sim: jain=%.4f min_mean=%.4f median_bps=%.0f healthy=%u "
         "worst_low_ms=%lld\n",
         jain, min_mean / mean_all, median_bps, healthy, (long long)worst_low);
  assert(worst_low < 22500);
  assert(jain >= 0.85);
  assert(min_mean / mean_all >= 0.50);
  assert(median_bps >= 55000.0 && median_bps <= 125000.0);
  assert(healthy == WRITERS);
}

static void loopback_low_startup_ramp(void) {
  /* 1250 B/s startup on 0..3 ms loopback RTT ramps without false queue cuts */
  quicly_flexicast_cc_t *cc = NULL;
  quicly_flexicast_cc_config_t cfg = {.maximum_members = 8,
                                      .startup_rate_bytes_per_second = 1250,
                                      .minimum_rate_bytes_per_second = 250,
                                      .maximum_datagram_size = 1200,
                                      .feedback_timeout_msec = 1000};
  int64_t now = 100000;
  cc = transport_group_cc_mcbbr_new(&cfg, now);
  assert(cc != NULL);
  quicly_flexicast_cc_on_member_added(cc, 1, now);
  for (unsigned step = 1; step <= 10; step++) {
    now += 260;
    uint32_t rtt = step % 3; /* 0, 1, 2 ms sub-ms and poll quantized RTT */
    quicly_flexicast_feedback_t f = {0};
    f.member_id = 1;
    f.epoch = step;
    f.now = now;
    f.acked_packets = 2;
    f.acked_bytes = 2400;
    f.largest_acknowledged = step * 2;
    f.latest_rtt_msec = rtt;
    f.raw_rtt_msec = rtt;
    f.rtt_sample_flags = QUICLY_FLEXICAST_RTT_VALID;
    f.rtt_sample_epoch = step;
    f.rtt_sample_at = now;
    f.delivery_sample_flags = 0;
    if (step >= 3) {
      f.delivery_rate_sample_epoch = step - 2;
      sample(&f, rate(cc), rate(cc));
    }
    quicly_flexicast_cc_on_feedback(cc, &f);
  }
  transport_group_cc_stats_t st;
  assert(transport_group_cc_mcbbr_get_stats(cc, &st));
  assert(st.rtt_reduction_events == 0);
  assert(cc->output.rate_bytes_per_second >= 10000);
  transport_group_cc_mcbbr_free(cc);
}

static void quicly_unsubtracted_min_rtt_recovery(void) {
  /* recover from pre-feedback timeout cut when quicly flags ack_delay */
  fixture_t w = create();
  for (unsigned e = 1; e <= 9; e++)
    quicly_flexicast_cc_on_timeout(w.cc, w.now + 1000 * (int64_t)e);
  w.now += 9000 + 2500;
  assert(rate(w.cc) <= 4000);
  for (unsigned step = 1; step <= 16; step++) {
    w.now += 600;
    uint32_t wire_rtt = 2040;
    uint32_t ack_delay = 300 + (step % 4) * 300;
    uint32_t raw_rtt = wire_rtt + ack_delay;
    quicly_flexicast_feedback_t f = {0};
    f.member_id = 1;
    f.epoch = ++w.epochs[1];
    f.now = w.now;
    f.acked_packets = 8;
    f.lost_packets = step % 2 ? 2 : 1;
    f.acked_bytes = 9600;
    f.largest_acknowledged = f.epoch * 8;
    f.minimum_rtt_msec = 2340;
    f.raw_rtt_msec = raw_rtt;
    f.latest_rtt_msec = raw_rtt;
    f.smoothed_rtt_msec = raw_rtt;
    f.rtt_ack_delay_msec = ack_delay;
    f.applied_ack_delay_msec = 0;
    f.rtt_sample_flags = QUICLY_FLEXICAST_RTT_VALID |
                         QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT;
    f.rtt_sample_epoch = ++w.rtt_epochs[1];
    f.rtt_sample_at = w.now;
    sample(&f, rate(w.cc), (rate(w.cc) * 8) / 10);
    f.delivery_sample_sent_at_start = w.now - (int64_t)wire_rtt - 600;
    f.delivery_sample_sent_at_end = w.now - (int64_t)wire_rtt;
    f.delivery_sample_acked_at_start = w.now - 600;
    f.delivery_sample_acked_at_end = w.now - 1;
    f.delivery_rate_sample_epoch = f.epoch;
    submit(&w, &f);
  }
  assert(rate(w.cc) >= 12000);
  transport_group_cc_mcbbr_free(w.cc);
}

static void silence_cut_app_limited_recovery(void) {
  /* silence-cut flow recovers off floor on calm RTT under app-limited repair */
  fixture_t w = create();
  for (unsigned m = 2; m <= 8; m++)
    quicly_flexicast_cc_on_member_added(w.cc, m, w.now);
  transport_group_cc_hints_t h = {.active_senders = 16,
                                  .delivery_rate_divisor = 1,
                                  .median_sender_rate_bytes_per_second = 9000};
  transport_group_cc_mcbbr_set_hints(w.cc, &h, w.now);
  for (unsigned t = 0; t < 15; t++) {
    w.now += 1500;
    quicly_flexicast_cc_on_timeout(w.cc, w.now);
  }
  uint64_t floored = rate(w.cc);
  assert(floored <= 1000);
  w.now += 3500;
  for (unsigned step = 0; step < 8; step++) {
    unsigned mid = (step % 8) + 1;
    quicly_flexicast_feedback_t f = input(&w, mid, 2050, 300);
    f.delivery_sample_flags =
        QUICLY_FLEXICAST_SAMPLE_VALID | QUICLY_FLEXICAST_SAMPLE_APP_LIMITED;
    submit(&w, &f);
  }
  assert(rate(w.cc) >= 4000);
  transport_group_cc_mcbbr_free(w.cc);
}

static void queue_drain_and_post_congestion_timeout_recovery(void) {
  /* min-RTT tracks >2x queue drain under INCONSISTENT and recovers after cut */
  fixture_t w = create();
  transport_group_cc_hints_t h = {.active_senders = 50,
                                  .delivery_rate_divisor = 1};
  transport_group_cc_mcbbr_set_hints(w.cc, &h, w.now);
  assert(rate(w.cc) >= 9000 && rate(w.cc) <= 10000);

  /* initial queued sample at 16000 ms wire RTT + ECN sets congestion_seen */
  w.now += 1000;
  quicly_flexicast_feedback_t f0 = {0};
  f0.member_id = 1;
  f0.epoch = ++w.epochs[1];
  f0.now = w.now;
  f0.acked_packets = 4;
  f0.acked_bytes = 4800;
  f0.largest_acknowledged = 4;
  f0.ecn_ce_count = 1;
  f0.minimum_rtt_msec = 21000;
  f0.raw_rtt_msec = 21000;
  f0.latest_rtt_msec = 21000;
  f0.smoothed_rtt_msec = 21000;
  f0.rtt_ack_delay_msec = 5000;
  f0.applied_ack_delay_msec = 0;
  f0.rtt_sample_flags =
      QUICLY_FLEXICAST_RTT_VALID | QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT;
  f0.rtt_sample_epoch = ++w.rtt_epochs[1];
  f0.rtt_sample_at = w.now;
  submit(&w, &f0);
  assert(w.event.state_after.previous_rtt == 16000);

  /* silence timeouts cut rate while 16000 ms win_min is still in window */
  for (unsigned t = 0; t < 6; t++) {
    w.now += 17500;
    quicly_flexicast_cc_on_timeout(w.cc, w.now);
  }
  assert(rate(w.cc) <= 2000);

  /* queue drains to 2050 ms (< 16000 / 2) with INCONSISTENT ack_delay */
  for (unsigned step = 0; step < 12; step++) {
    w.now += 600;
    uint32_t wire = 2050;
    uint32_t ack_delay = 1500 + (step % 3) * 400;
    uint32_t raw = wire + ack_delay;
    quicly_flexicast_feedback_t f = {0};
    f.member_id = 1;
    f.epoch = ++w.epochs[1];
    f.now = w.now;
    f.acked_packets = 2;
    f.acked_bytes = 2400;
    f.largest_acknowledged = 4 + (step + 1) * 2;
    f.minimum_rtt_msec = 21000;
    f.raw_rtt_msec = raw;
    f.latest_rtt_msec = raw;
    f.smoothed_rtt_msec = raw;
    f.rtt_ack_delay_msec = ack_delay;
    f.applied_ack_delay_msec = 0;
    f.rtt_sample_flags = QUICLY_FLEXICAST_RTT_VALID |
                         QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT;
    f.rtt_sample_epoch = ++w.rtt_epochs[1];
    f.rtt_sample_at = w.now;
    f.delivery_sample_flags =
        QUICLY_FLEXICAST_SAMPLE_VALID | QUICLY_FLEXICAST_SAMPLE_MIXED;
    submit(&w, &f);
  }
  assert(w.event.state_after.previous_rtt == 2050);
  assert(rate(w.cc) >= 4500);
  transport_group_cc_mcbbr_free(w.cc);
}

static void channel_share_large_startup_rate(void) {
  quicly_flexicast_cc_config_t config = {
      .startup_rate_bytes_per_second = UINT64_MAX};
  quicly_flexicast_cc_t *cc = transport_group_cc_mcbbr_new(&config, 1000);
  assert(cc != NULL);
  transport_group_cc_hints_t hints = {.active_senders = 21};
  transport_group_cc_mcbbr_set_hints(cc, &hints, 1000);
  assert(rate(cc) == UINT64_MAX / 2);
  transport_group_cc_mcbbr_free(cc);
}

static void channel_share_scaling(void) {
  /* smooth 1/N shared-medium scaling with no cliff across N = 31 -> 32 */
  static const uint32_t counts[] = {2, 4, 8, 16, 31, 32, 50};
  uint64_t prev = UINT64_MAX;
  uint64_t r31 = 0, r32 = 0;
  for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
    fixture_t w = create();
    transport_group_cc_hints_t h = {.active_senders = counts[i],
                                    .delivery_rate_divisor = 1};
    transport_group_cc_mcbbr_set_hints(w.cc, &h, w.now);
    uint64_t cur = rate(w.cc);
    assert(cur < prev);
    prev = cur;
    if (counts[i] == 31)
      r31 = cur;
    if (counts[i] == 32)
      r32 = cur;
    if (counts[i] == 50)
      assert(cur >= 9000 && cur <= 10000);
    transport_group_cc_mcbbr_free(w.cc);
  }
  assert(r32 < r31 && r31 - r32 <= r31 / 20);
}

static void sticky_ack_leader_and_outlier_fade(void) {
  /* sticky bottleneck leader + single-member fade/jitter outlier filtering */
  fixture_t w = create();
  for (unsigned id = 2; id <= 6; id++)
    quicly_flexicast_cc_on_member_added(w.cc, id, w.now);
  for (unsigned round = 0; round < 6; round++) {
    for (unsigned id = 1; id <= 6; id++) {
      quicly_flexicast_feedback_t f = input(&w, id, 100, 100);
      sample(&f, rate(w.cc), rate(w.cc));
      submit(&w, &f);
    }
  }
  uint64_t steady = rate(w.cc);
  /* single-member unbloated RTT wiggle does not cut cohort rate */
  for (unsigned step = 1; step <= 2; step++) {
    quicly_flexicast_feedback_t f = input(&w, 4, 100 + 25 * step, 300);
    submit(&w, &f);
  }
  assert(rate(w.cc) == steady);
  /* single-member 25% RF loss burst on flat calm RTT does not cut rate */
  quicly_flexicast_feedback_t rf = input(&w, 5, 100, 300);
  rf.acked_packets = 6;
  rf.lost_packets = 2;
  submit(&w, &rf);
  assert(rate(w.cc) == steady);
  /* bottleneck ECN + queue bloat on member 3 pins sticky leader to 3 */
  quicly_flexicast_feedback_t cong = input(&w, 3, 280, 400);
  cong.ecn_ce_count = 1;
  submit(&w, &cong);
  quicly_flexicast_cc_output_t o = w.cc->output;
  assert(o.limiting_member_id == 3 && o.rate_bytes_per_second < steady);
  /* calm ACK from member 2 preserves member 3 as sticky ACK leader */
  quicly_flexicast_feedback_t calm = input(&w, 2, 100, 200);
  submit(&w, &calm);
  o = w.cc->output;
  assert(o.limiting_member_id == 3);
  /* suspending member 3 releases sticky leader */
  quicly_flexicast_cc_on_member_suspended(w.cc, 3, w.now + 50);
  o = w.cc->output;
  assert(o.limiting_member_id != 3);
  transport_group_cc_mcbbr_free(w.cc);
}

static void bbrv3_startup_plateau_and_probebw(void) {
  /* 3-round STARTUP full-pipe plateau exit and ProbeBW CRUISE->REFILL->UP */
  quicly_flexicast_cc_t *cc = NULL;
  quicly_flexicast_cc_config_t cfg = {.maximum_members = 8,
                                      .startup_rate_bytes_per_second = 8000,
                                      .minimum_rate_bytes_per_second = 250,
                                      .maximum_datagram_size = 1200,
                                      .feedback_timeout_msec = 1000};
  int64_t now = 100000;
  uint64_t ep = 0, rtt_ep = 0;
  cc = transport_group_cc_mcbbr_new(&cfg, now);
  assert(cc != NULL);
  quicly_flexicast_cc_on_member_added(cc, 1, now);
  /* grow in STARTUP while link supports full rate up to 24000 B/s */
  while (rate(cc) < 24000) {
    now += 400;
    quicly_flexicast_feedback_t f = {0};
    f.member_id = 1;
    f.epoch = ++ep;
    f.now = now;
    f.acked_packets = 4;
    f.acked_bytes = 4800;
    f.largest_acknowledged = ep * 4;
    f.latest_rtt_msec = 100;
    f.minimum_rtt_msec = 10;
    f.smoothed_rtt_msec = 100;
    f.raw_rtt_msec = 110;
    f.rtt_ack_delay_msec = f.applied_ack_delay_msec = 10;
    f.rtt_sample_flags = QUICLY_FLEXICAST_RTT_VALID;
    f.rtt_sample_epoch = ++rtt_ep;
    f.rtt_sample_at = now;
    f.delivery_rate_sample_epoch = ep;
    sample(&f, rate(cc), rate(cc));
    quicly_flexicast_cc_on_feedback(cc, &f);
  }
  uint64_t plateau = rate(cc);
  /* non-growing rounds capped at 20000 B/s exit STARTUP without bloat/loss */
  for (unsigned r = 0; r < 2; r++) {
    now += 400;
    quicly_flexicast_feedback_t f = {0};
    f.member_id = 1;
    f.epoch = ++ep;
    f.now = now;
    f.acked_packets = 4;
    f.acked_bytes = 4800;
    f.largest_acknowledged = ep * 4;
    f.latest_rtt_msec = 100;
    f.minimum_rtt_msec = 10;
    f.smoothed_rtt_msec = 100;
    f.raw_rtt_msec = 110;
    f.rtt_ack_delay_msec = f.applied_ack_delay_msec = 10;
    f.rtt_sample_flags = QUICLY_FLEXICAST_RTT_VALID;
    f.rtt_sample_epoch = ++rtt_ep;
    f.rtt_sample_at = now;
    f.delivery_rate_sample_epoch = ep;
    sample(&f, rate(cc), 20000);
    quicly_flexicast_cc_on_feedback(cc, &f);
  }
  assert(rate(cc) == plateau);
  /* when link capacity rises, ProbeBW uses 1/16 gain (not STARTUP 1/8) */
  uint64_t first_probe = 0;
  for (unsigned r = 0; r < 6; r++) {
    now += 1200;
    quicly_flexicast_feedback_t f = {0};
    f.member_id = 1;
    f.epoch = ++ep;
    f.now = now;
    f.acked_packets = 6;
    f.acked_bytes = 7200;
    f.largest_acknowledged = ep * 6;
    f.latest_rtt_msec = 100;
    f.minimum_rtt_msec = 10;
    f.smoothed_rtt_msec = 100;
    f.raw_rtt_msec = 110;
    f.rtt_ack_delay_msec = f.applied_ack_delay_msec = 10;
    f.rtt_sample_flags = QUICLY_FLEXICAST_RTT_VALID;
    f.rtt_sample_epoch = ++rtt_ep;
    f.rtt_sample_at = now;
    f.delivery_rate_sample_epoch = ep;
    sample(&f, rate(cc), rate(cc));
    quicly_flexicast_cc_on_feedback(cc, &f);
    if (r == 0)
      first_probe = rate(cc);
  }
  assert(first_probe > plateau && first_probe - plateau <= plateau / 12);
  assert(rate(cc) > first_probe);
  transport_group_cc_mcbbr_free(cc);
}

static void tdma_long_cycle_slot_quantization(void) {
  /* multi-second TDMA slot phase jitter must not pin rate to floor */
  quicly_flexicast_cc_config_t c = {.startup_rate_bytes_per_second = 953,
                                    .minimum_rate_bytes_per_second = 250,
                                    .maximum_datagram_size = 1200,
                                    .feedback_timeout_msec = 24960,
                                    .maximum_members = 99};
  int64_t now = 1000;
  quicly_flexicast_cc_t *cc = transport_group_cc_mcbbr_new(&c, now);
  assert(cc);
  for (unsigned m = 1; m <= 99; m++)
    quicly_flexicast_cc_on_member_added(cc, m, now);
  transport_group_cc_hints_t h = {.active_senders = 3,
                                  .delivery_rate_divisor = 1};
  transport_group_cc_mcbbr_set_hints(cc, &h, now);
  uint64_t ep[100] = {0}, rtt_ep[100] = {0};
  for (unsigned round = 0; round < 30; round++) {
    for (unsigned m = 1; m <= 99; m++) {
      now += 120;
      uint32_t min_rtt = 1200 + (m % 5) * 600;
      uint32_t slot_jitter = ((round + m) % 4 == 0) ? 7200 : 2800;
      uint32_t cur_rtt = min_rtt + slot_jitter;
      quicly_flexicast_feedback_t f = {0};
      f.member_id = m;
      f.epoch = ++ep[m];
      f.now = now;
      f.acked_packets = 3;
      f.lost_packets = (m + round) % 4 == 0 ? 1 : 0;
      f.acked_bytes = 3300;
      f.largest_acknowledged = ep[m] * 3;
      f.latest_rtt_msec = cur_rtt;
      f.minimum_rtt_msec = min_rtt;
      f.smoothed_rtt_msec = cur_rtt;
      f.raw_rtt_msec = cur_rtt + 400;
      f.rtt_ack_delay_msec = f.applied_ack_delay_msec = 400;
      f.rtt_sample_flags = QUICLY_FLEXICAST_RTT_VALID;
      f.rtt_sample_epoch = ++rtt_ep[m];
      f.rtt_sample_at = now;
      f.delivery_sample_flags =
          QUICLY_FLEXICAST_SAMPLE_VALID | QUICLY_FLEXICAST_SAMPLE_APP_LIMITED;
      quicly_flexicast_cc_on_feedback(cc, &f);
    }
  }
  assert(rate(cc) >= 850);
  transport_group_cc_mcbbr_free(cc);
}

int main(void) {
  bounded_recovery();
  for (unsigned m = 0; m < 9; m++)
    no_unsupported_growth(m);
  for (unsigned m = 0; m < 15; m++)
    proof_and_invalid_capacity(m);
  capacity_and_radio_loss(false);
  capacity_and_radio_loss(true);
  loss_burst_vetoes_growth();
  cumulative_growth();
  correlated_receivers();
  lower_path_then_renewed_growth();
  slowest_flight();
  timeout_and_members();
  epoch_clears_samples();
  external_and_hard_bound();
  precut_capacity_is_not_current_proof();
  minimum_and_burst_bounds();
  zero_clock_and_overflow();
  bbrv3_drain_and_cohort();
  drain_active_and_hint_isolation();
  loopback_low_startup_ramp();
  quicly_unsubtracted_min_rtt_recovery();
  silence_cut_app_limited_recovery();
  queue_drain_and_post_congestion_timeout_recovery();
  channel_share_scaling();
  channel_share_large_startup_rate();
  sticky_ack_leader_and_outlier_fade();
  bbrv3_startup_plateau_and_probebw();
  tdma_long_cycle_slot_quantization();
  exp13_fifty_writer_equilibrium();
  puts("===GROUP RECOVERY CC OK===");
}
