#include "transport_group_cc.h"
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
void test_fifty_writer_fifo(void);

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
  assert(transport_group_cc_mcbbr_get_trace_state(w->cc, f->member_id,
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
      break; /* lower old pacing rate is no proof of current rate */
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
static void stable_delay_loss_response(bool policed) {
  fixture_t w = create();
  uint64_t initial = rate(w.cc);
  unsigned cuts = 0;
  for (unsigned e = 0; e < 40; e++) {
    uint64_t paced = rate(w.cc);
    uint64_t delivered = paced / 4;
    if (policed)
      delivered = paced > 8000 ? 8000 : paced;
    quicly_flexicast_feedback_t f = input(&w, 1, 40, 1000);
    sample(&f, paced, delivered);
    f.acked_packets = delivered / 100;
    f.lost_packets = (paced - delivered) / 100;
    f.acked_bytes = delivered;
    f.lost_bytes = paced - delivered;
    submit(&w, &f);
    if (rate(w.cc) < paced)
      ++cuts;
  }
  if (policed) {
    assert(cuts >= 2 && rate(w.cc) >= 8000 && rate(w.cc) <= 9000);
    for (unsigned e = 0; e < 12; ++e) {
      quicly_flexicast_feedback_t f = input(&w, 1, 40, 1000);
      sample(&f, rate(w.cc), rate(w.cc));
      submit(&w, &f);
    }
    assert(rate(w.cc) > 9000);
  } else {
    assert(cuts <= 1 && rate(w.cc) >= initial);
  }
  transport_group_cc_mcbbr_free(w.cc);
}

static void completed_sample(quicly_flexicast_feedback_t *f, uint64_t paced,
                             uint64_t delivered, int64_t acked_at_end) {
  sample(f, paced, delivered);
  f->delivery_sample_acked_at_start = acked_at_end - 1000;
  f->delivery_sample_acked_at_end = acked_at_end;
  f->delivery_sample_sent_at_start = acked_at_end - 1000 - f->raw_rtt_msec;
  f->delivery_sample_sent_at_end = acked_at_end - f->raw_rtt_msec;
}

static void group_service_provenance(void) {
  enum {
    MATCHED_SERVICE,
    MATCHED_RADIO,
    NATIVE_SHARED_LOSS,
    UNMATCHED,
    MIXED,
    STALE,
    ACK_STRETCHED,
    ZERO_SEND_SPAN,
    CAPPED_RATIO
  };
  for (unsigned mode = MATCHED_SERVICE; mode <= CAPPED_RATIO; ++mode) {
    fixture_t w = create();
    assert(quicly_flexicast_cc_on_member_added(w.cc, 2, w.now) == 0);
    quicly_flexicast_feedback_t prior = input(&w, 1, 100, 1000);
    prior.acked_packets = 4;
    prior.lost_packets =
        mode == MATCHED_RADIO || mode == NATIVE_SHARED_LOSS ? 4 : 0;
    submit(&w, &prior);

    uint64_t paced = rate(w.cc);
    quicly_flexicast_feedback_t f =
        input(&w, 1, 100, mode == STALE ? 10000 : 1000);
    completed_sample(&f, paced, paced / 4, prior.now - (mode == UNMATCHED));
    f.delivery_sample_fanout = 2;
    if (mode == NATIVE_SHARED_LOSS) {
      f.delivery_sample_fanout = 1;
      f.delivery_rate_bytes_per_second = paced / 2;
    } else if (mode == ACK_STRETCHED) {
      f.delivery_sample_sent_at_start = f.delivery_sample_sent_at_end - 500;
    } else if (mode == ZERO_SEND_SPAN) {
      f.delivery_sample_sent_at_start = f.delivery_sample_sent_at_end;
    } else if (mode == CAPPED_RATIO) {
      f.delivery_sample_pacing_rate_bytes_per_second = UINT64_MAX;
      f.delivery_rate_bytes_per_second = UINT64_MAX / 3;
      f.delivery_sample_sent_at_start = f.delivery_sample_sent_at_end - 1;
      f.delivery_sample_flags |= QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED;
    }
    if (mode == MIXED)
      f.delivery_sample_flags |= QUICLY_FLEXICAST_SAMPLE_MIXED;
    f.acked_packets = 4;
    /* newer frame would reverse pressure decision in matched modes */
    f.lost_packets = mode == MATCHED_RADIO ? 1 : 4;
    submit(&w, &f);
    bool should_cut = mode == MATCHED_SERVICE || mode == NATIVE_SHARED_LOSS;
    assert(rate(w.cc) == (should_cut ? paced * 7 / 8 : paced));
    transport_group_cc_mcbbr_free(w.cc);
  }
}

static void group_service_drains_after_queue_evidence(void) {
  fixture_t w = create();
  assert(quicly_flexicast_cc_on_member_added(w.cc, 2, w.now) == 0);
  quicly_flexicast_feedback_t f = input(&w, 1, 100, 1000);
  f.acked_packets = 8;
  submit(&w, &f);
  int64_t previous_at = f.now;

  uint64_t paced = rate(w.cc);
  f = input(&w, 1, 100, 1000);
  completed_sample(&f, paced, paced / 2, previous_at);
  f.acked_packets = 8;
  f.lost_packets = 4;
  submit(&w, &f);
  uint64_t discovery_rate = paced * 7 / 8;
  assert(rate(w.cc) == discovery_rate);
  assert(w.event.state_after.growth_blocked_until == f.now + 2000);

  f = input(&w, 1, 140, 100);
  f.lost_packets = 4;
  submit(&w, &f);
  assert(rate(w.cc) == discovery_rate);

  f = input(&w, 1, 140, 1000);
  f.lost_packets = 4;
  submit(&w, &f);
  assert(rate(w.cc) == discovery_rate / 2);
  assert(w.event.state_after.growth_blocked_until == f.now + 5000);
  transport_group_cc_mcbbr_free(w.cc);
}

static void group_service_respects_a_fully_served_offer(void) {
  fixture_t w = create();
  assert(quicly_flexicast_cc_on_member_added(w.cc, 2, w.now) == 0);
  quicly_flexicast_feedback_t f = input(&w, 1, 100, 1000);
  f.acked_packets = 8;
  submit(&w, &f);
  int64_t previous_at = f.now;
  f = input(&w, 2, 100, 0);
  f.acked_packets = 8;
  submit(&w, &f);

  uint64_t paced = rate(w.cc);
  f = input(&w, 1, 100, 1000);
  completed_sample(&f, paced, paced / 2, previous_at);
  f.acked_packets = 8;
  submit(&w, &f);
  assert(rate(w.cc) == paced);

  /* receiver was fully served at a lower stamped pacing rate */
  f = input(&w, 2, 100, 0);
  completed_sample(&f, paced / 4, paced / 4, previous_at);
  f.acked_packets = 8;
  f.lost_packets = 4;
  submit(&w, &f);
  assert(rate(w.cc) == paced);
  transport_group_cc_mcbbr_free(w.cc);
}

static void group_service_holds_then_allows_growth(bool expire) {
  fixture_t w = create();
  assert(quicly_flexicast_cc_on_member_added(w.cc, 2, w.now) == 0);
  warm(&w, true);
  uint64_t paced = rate(w.cc);
  quicly_flexicast_feedback_t f = input(&w, 1, 100, 1000);
  f.acked_packets = 8;
  submit(&w, &f);
  int64_t previous_at = f.now;
  f = input(&w, 1, 100, 1000);
  completed_sample(&f, paced, paced / 2, previous_at);
  f.acked_packets = 8;
  submit(&w, &f);
  assert(rate(w.cc) == paced);

  for (unsigned e = 0; e < 3; ++e) {
    f = input(&w, 1, 100, 1000);
    sample(&f, paced, paced);
    f.acked_packets = 8;
    submit(&w, &f);
    assert(rate(w.cc) == paced);
  }
  for (unsigned e = 0; e < 16 && rate(w.cc) == paced; ++e) {
    previous_at = f.now;
    f = input(&w, 1, 100, expire ? 7000 : 1000);
    if (expire)
      sample(&f, paced, paced);
    else
      completed_sample(&f, paced, paced, previous_at);
    f.acked_packets = 8;
    submit(&w, &f);
  }
  assert(rate(w.cc) > paced);
  transport_group_cc_mcbbr_free(w.cc);
}

static void effective_rate_and_idle_timeout(void) {
  fixture_t w = create();
  transport_group_cc_hints_t h = {.aggregate_rate_limit_bytes_per_second =
                                      4000};
  transport_group_cc_mcbbr_set_hints(w.cc, &h, w.now);
  assert(rate(w.cc) == 4000);
  ce(&w);
  assert(rate(w.cc) == 3400);
  transport_group_cc_mcbbr_free(w.cc);

  w = create();
  transport_group_cc_mcbbr_set_hints(w.cc, &h, w.now);
  w.now += 10000;
  for (unsigned e = 0; e < 9; e++, w.now += 1000)
    quicly_flexicast_cc_on_timeout(w.cc, w.now);
  assert(rate(w.cc) == 4000 && w.cc->output.next_timeout == INT64_MAX);

  transport_group_cc_mcbbr_on_submitted(w.cc, w.now);
  assert(w.cc->output.next_timeout == w.now + 1000);
  quicly_flexicast_cc_on_timeout(w.cc, w.now + 999);
  quicly_flexicast_cc_on_timeout(w.cc, w.now + 1000);
  quicly_flexicast_cc_on_timeout(w.cc, w.now + 2000);
  assert(rate(w.cc) == 4000);
  transport_group_cc_mcbbr_on_delivery_clear(w.cc);
  w.now += 10000;
  quicly_flexicast_cc_on_timeout(w.cc, w.now);
  assert(rate(w.cc) == 4000 && w.cc->output.next_timeout == INT64_MAX);

  transport_group_cc_mcbbr_on_submitted(w.cc, w.now);
  quicly_flexicast_cc_on_timeout(w.cc, w.now + 1000);
  quicly_flexicast_cc_on_timeout(w.cc, w.now + 2000);
  assert(rate(w.cc) == 4000);
  quicly_flexicast_cc_on_timeout(w.cc, w.now + 3000);
  assert(rate(w.cc) == 2000);

  h.aggregate_rate_limit_bytes_per_second = 200;
  w.now += 3000;
  transport_group_cc_mcbbr_set_hints(w.cc, &h, w.now);
  ce(&w);
  assert(rate(w.cc) == 200);
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
  /* large old flights cannot furnish post-cut trend evidence */
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
  transport_group_cc_mcbbr_on_submitted(w.cc, w.now);
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

static void suspended_member_compaction(void) {
  fixture_t w = create();
  for (unsigned id = 2; id <= 4; ++id) {
    assert(quicly_flexicast_cc_on_member_added(w.cc, id, w.now) == 0);
    quicly_flexicast_feedback_t f = input(&w, id, id * 100, 1000);
    submit(&w, &f);
  }
  quicly_flexicast_cc_on_member_suspended(w.cc, 2, w.now);
  quicly_flexicast_cc_on_member_removed(w.cc, 3, w.now);
  quicly_flexicast_feedback_t ignored = input(&w, 2, 999, 1000);
  submit(&w, &ignored);
  assert(w.event.state_after.member_present &&
         w.event.state_after.previous_rtt == 200);
  assert(quicly_flexicast_cc_on_member_added(w.cc, 2, w.now) == 0);
  quicly_flexicast_feedback_t resumed = input(&w, 2, 100, 1000);
  submit(&w, &resumed);
  assert(w.event.state_after.previous_rtt == 100);
  assert(quicly_flexicast_cc_on_member_added(w.cc, 3, w.now) == 0);
  transport_group_cc_trace_state_t state;
  assert(transport_group_cc_mcbbr_get_trace_state(w.cc, 3, &state));
  assert(state.member_present && state.last_rtt_sample_epoch == 0);
  assert(transport_group_cc_mcbbr_get_trace_state(w.cc, 4, &state));
  assert(state.member_present && state.previous_rtt == 400);
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
  transport_group_cc_mcbbr_on_submitted(w.cc, w.now);
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
  transport_group_cc_mcbbr_on_delivery_clear(w.cc);
  int64_t drain_deadline = w.cc->output.next_timeout;
  assert(drain_deadline > w.now && drain_deadline != INT64_MAX);
  quicly_flexicast_cc_on_timeout(w.cc, drain_deadline);
  assert(w.cc->output.next_timeout == INT64_MAX &&
         (w.cc->output.reason & TRANSPORT_GROUP_CC_REASON_DRAIN_EXPIRE) &&
         !(w.cc->output.reason & QUICLY_FLEXICAST_CC_REASON_TIMEOUT));
  transport_group_cc_mcbbr_free(w.cc);

  /* stale external-load epochs are ignored and rate limits avoid cut_seen */
  w = create();
  transport_group_cc_hints_t h = {.aggregate_rate_limit_bytes_per_second =
                                      10000,
                                  .external_load_epoch = 10,
                                  .external_load_queued_bytes = 4096};
  transport_group_cc_mcbbr_set_hints(w.cc, &h, w.now);
  assert(
      transport_group_cc_mcbbr_get_trace_state(w.cc, 1, &w.event.state_after));
  assert(rate(w.cc) == 10000 && w.event.state_after.last_reduction_epoch == 0 &&
         w.event.state_after.external_load);
  for (uint64_t ep = 1; ep <= 4; ep++) {
    transport_group_cc_hints_t stale = {.active_senders = 8,
                                        .external_load_epoch = ep};
    transport_group_cc_mcbbr_set_hints(w.cc, &stale, w.now + (int64_t)ep);
    assert(transport_group_cc_mcbbr_get_trace_state(w.cc, 1,
                                                    &w.event.state_after));
  }
  assert(w.event.state_after.external_load);
  transport_group_cc_mcbbr_free(w.cc);
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
  transport_group_cc_mcbbr_on_submitted(w.cc, w.now);
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
                                  .median_sender_rate_bytes_per_second = 9000};
  transport_group_cc_mcbbr_set_hints(w.cc, &h, w.now);
  transport_group_cc_mcbbr_on_submitted(w.cc, w.now);
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
  transport_group_cc_hints_t h = {.active_senders = 50};
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
  transport_group_cc_mcbbr_on_submitted(w.cc, w.now);
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
  quicly_flexicast_cc_config_t config = {.startup_rate_bytes_per_second =
                                             UINT64_MAX};
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
    transport_group_cc_hints_t h = {.active_senders = counts[i]};
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

static quicly_flexicast_feedback_t steady_feedback(uint64_t ep, int64_t now,
                                                   uint64_t acked_packets,
                                                   uint64_t ref_rate,
                                                   uint64_t delivered_rate) {
  quicly_flexicast_feedback_t f = {.member_id = 1,
                                   .epoch = ep,
                                   .now = now,
                                   .acked_packets = acked_packets,
                                   .acked_bytes = acked_packets * 1200,
                                   .largest_acknowledged = ep * acked_packets,
                                   .latest_rtt_msec = 100,
                                   .minimum_rtt_msec = 10,
                                   .smoothed_rtt_msec = 100,
                                   .raw_rtt_msec = 110,
                                   .rtt_ack_delay_msec = 10,
                                   .applied_ack_delay_msec = 10,
                                   .rtt_sample_flags =
                                       QUICLY_FLEXICAST_RTT_VALID,
                                   .rtt_sample_epoch = ep,
                                   .rtt_sample_at = now,
                                   .delivery_rate_sample_epoch = ep};
  sample(&f, ref_rate, delivered_rate);
  return f;
}

static void bbrv3_startup_plateau_and_probebw(void) {
  /* 3-round STARTUP full-pipe plateau exit and ProbeBW CRUISE->REFILL->UP */
  quicly_flexicast_cc_config_t cfg = {.maximum_members = 8,
                                      .startup_rate_bytes_per_second = 8000,
                                      .minimum_rate_bytes_per_second = 250,
                                      .maximum_datagram_size = 1200,
                                      .feedback_timeout_msec = 1000};
  int64_t now = 100000;
  uint64_t ep = 0;
  quicly_flexicast_cc_t *cc = transport_group_cc_mcbbr_new(&cfg, now);
  assert(cc != NULL);
  quicly_flexicast_cc_on_member_added(cc, 1, now);
  /* grow in STARTUP while link supports full rate up to 24000 B/s */
  while (rate(cc) < 24000) {
    now += 400;
    quicly_flexicast_feedback_t f =
        steady_feedback(++ep, now, 4, rate(cc), rate(cc));
    quicly_flexicast_cc_on_feedback(cc, &f);
  }
  uint64_t plateau = rate(cc);
  /* non-growing rounds capped at 20000 B/s exit STARTUP without bloat/loss */
  for (unsigned r = 0; r < 2; r++) {
    now += 400;
    quicly_flexicast_feedback_t f =
        steady_feedback(++ep, now, 4, rate(cc), 20000);
    quicly_flexicast_cc_on_feedback(cc, &f);
  }
  assert(rate(cc) == plateau);
  /* when link capacity rises, ProbeBW uses 1/16 gain (not STARTUP 1/8) */
  uint64_t first_probe = 0;
  for (unsigned r = 0; r < 6; r++) {
    now += 1200;
    quicly_flexicast_feedback_t f =
        steady_feedback(++ep, now, 6, rate(cc), rate(cc));
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
  transport_group_cc_hints_t h = {.active_senders = 3};
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
  stable_delay_loss_response(true);
  stable_delay_loss_response(false);
  group_service_provenance();
  group_service_drains_after_queue_evidence();
  group_service_respects_a_fully_served_offer();
  group_service_holds_then_allows_growth(false);
  group_service_holds_then_allows_growth(true);
  effective_rate_and_idle_timeout();
  cumulative_growth();
  correlated_receivers();
  lower_path_then_renewed_growth();
  slowest_flight();
  timeout_and_members();
  suspended_member_compaction();
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
  test_fifty_writer_fifo();
  puts("===GROUP RECOVERY CC OK===");
}
