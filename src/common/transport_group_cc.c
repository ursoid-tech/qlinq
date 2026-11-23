/* unified BBRv3-inspired MCBBR multicast congestion controller */
#include "transport_group_cc.h"
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define PPM 1000000U
#define DELAY_POINTS 4
/* Preserve the response horizon when feedback spans rounds. */
#define FEEDBACK_ENTRIES_PER_ROUND 16U
#define DRAIN_IDLE 0U
#define DRAIN_OBSERVING 1U
#define DRAIN_ACTIVE 2U
#define BBR_STARTUP 0U
#define BBR_CRUISE 1U
#define BBR_REFILL 2U
#define BBR_UP 3U

typedef struct {
  uint32_t rtt;
  int64_t at;
} delay_point_t;

typedef struct {
  uint32_t phase;
  uint64_t member_id;
  uint64_t ceiling;
  uint64_t target;
  int64_t started_at;
  int64_t deadline;
  int64_t ended_at;
  bool needs_growth;
} mcbbr_drain_t;

typedef struct {
  uint64_t id, feedback_epoch, rtt_epoch, delivery_epoch;
  int64_t feedback_at, rtt_at, stable_at;
  uint32_t rtt, raw_rtt, flight_rtt, minimum_rtt, reference, stable_rtt, rising;
  uint32_t recent_ratio, supports_streak;
  uint64_t recent_delivery, expected_delivery;
  delay_point_t win_min[3];
  delay_point_t points[DELAY_POINTS];
  unsigned point_count, point_next;
  uint32_t clean_ratio, candidate_ratio, candidate_count, degraded;
  uint32_t loss_baseline, loss_candidate, loss_epochs;
  uint64_t ceiling, bw_hi, bw_lo;
  bool active, feedback_seen, capacity_eligible, capacity_post_cut,
      window_stable, bloated_last;
} mcbbr_peer_t;

typedef struct {
  quicly_flexicast_cc_t super;
  quicly_flexicast_cc_config_t config;
  transport_group_cc_hints_t hints;
  transport_group_cc_stats_t stats;
  mcbbr_peer_t *peers;
  size_t active;
  uint64_t rate, bw_hi, bw_lo, leader_id, startup_bw_anchor, prev_output_rate,
      burst_bytes;
  int64_t last_cut, last_growth, blocked_until, next_timeout, last_timeout;
  int64_t phase_at, leader_at, startup_round_at;
  uint32_t unanswered, clear_load_epochs, bbr_phase, startup_probes,
      startup_flat_rounds;
  uint64_t load_epoch;
  bool load_seen, cut_seen, congestion_seen, last_cut_was_timeout, growth_seen,
      at_floor;
  mcbbr_drain_t drain;
} group_mcbbr_t;

static int64_t after(int64_t now, uint64_t delta) {
  if (now < 0)
    now = 0;
  return delta > (uint64_t)(INT64_MAX - now) ? INT64_MAX : now + (int64_t)delta;
}

static uint64_t scale(uint64_t n, uint32_t a, uint32_t b) {
  return n / b * a + n % b * a / b; /* a <= b */
}

static uint32_t ratio(uint64_t n, uint64_t d) {
  if (!d || !n)
    return 0;
  if (n >= d)
    return PPM;
  while (n > UINT64_MAX / PPM) {
    n >>= 1;
    d >>= 1;
  }
  return (uint32_t)(n * PPM / d);
}

static uint64_t interval(const group_mcbbr_t *s) {
  uint64_t n = s->config.feedback_timeout_msec / 4;
  return n < 25 ? 25 : n;
}

static mcbbr_peer_t *find(group_mcbbr_t *s, uint64_t id) {
  if (!id)
    return NULL;
  for (size_t i = 0; i < s->config.maximum_members; i++)
    if (s->peers[i].id == id)
      return &s->peers[i];
  return NULL;
}

/* sender-wide cuts use the slowest active member's response horizon */
static uint64_t control_flight(const group_mcbbr_t *s, int64_t now) {
  uint32_t senders = s->hints.active_senders ? s->hints.active_senders : 1;
  uint64_t drr_span =
      senders > FEEDBACK_ENTRIES_PER_ROUND
          ? ((uint64_t)(senders + FEEDBACK_ENTRIES_PER_ROUND - 1U) /
             FEEDBACK_ENTRIES_PER_ROUND) *
                interval(s)
          : 0;
  uint64_t flight = s->config.feedback_timeout_msec + drr_span;
  for (size_t i = 0; i < s->config.maximum_members; i++) {
    const mcbbr_peer_t *m = &s->peers[i];
    uint32_t frtt = m->flight_rtt ? m->flight_rtt : m->raw_rtt;
    if (m->active && m->rtt_at > 0 && now >= m->rtt_at &&
        (uint64_t)(now - m->rtt_at) <=
            6 * (uint64_t)frtt + s->config.feedback_timeout_msec &&
        frtt > flight)
      flight = frtt;
  }
  return flight;
}

/* shared-medium 1/N channel share replacing 1/sqrt(N) heuristics */
static uint64_t channel_share_rate(const group_mcbbr_t *s) {
  if (s->hints.aggregate_rate_limit_bytes_per_second)
    return s->hints.aggregate_rate_limit_bytes_per_second;
  uint32_t senders = s->hints.active_senders ? s->hints.active_senders : 1;
  uint64_t divisor = senders + 19ULL;
  uint64_t startup = s->config.startup_rate_bytes_per_second;
  uint64_t base =
      startup / divisor * 20U + startup % divisor * 20U / divisor;
  if (!base)
    base = s->config.minimum_rate_bytes_per_second;
  return base;
}

static bool any_other_rising(const group_mcbbr_t *s, const mcbbr_peer_t *self,
                             int64_t now) {
  size_t count = 0;
  size_t need = s->active >= 16 ? 3 : (s->active >= 6 ? 2 : 1);
  for (size_t i = 0; i < s->config.maximum_members; i++) {
    const mcbbr_peer_t *m = &s->peers[i];
    uint32_t frtt = m->flight_rtt ? m->flight_rtt : m->raw_rtt;
    if (m == self || !m->active || m->rtt_at <= 0 || now < m->rtt_at)
      continue;
    if ((uint64_t)(now - m->rtt_at) <=
            6 * (uint64_t)frtt + s->config.feedback_timeout_msec &&
        m->rising > 0 && ++count >= need)
      return true;
  }
  return false;
}

/* sticky representative bottleneck member with hysteresis */
static void update_ack_leader(group_mcbbr_t *s, const mcbbr_peer_t *cand,
                              int64_t now, uint64_t group_flight) {
  const mcbbr_peer_t *leader = s->leader_id ? find(s, s->leader_id) : NULL;
  if (leader && (!leader->active || leader->feedback_at <= 0 ||
                 (now > leader->feedback_at &&
                  (uint64_t)(now - leader->feedback_at) > 2 * group_flight))) {
    leader = NULL;
    s->leader_id = 0;
  }
  if (!leader) {
    s->leader_id = cand->id;
    s->leader_at = now;
    return;
  }
  if (leader->id == cand->id) {
    s->leader_at = now;
    return;
  }
  bool worse_loss_or_cap = (cand->degraded >= 2 && leader->degraded == 0) ||
                           (cand->ceiling && leader->ceiling &&
                            cand->ceiling < scale(leader->ceiling, 9, 10));
  bool worse_delay =
      cand->bloated_last && !leader->bloated_last && leader->rising == 0;
  if (worse_loss_or_cap || worse_delay) {
    s->leader_id = cand->id;
    s->leader_at = now;
  }
}

static bool external(const group_mcbbr_t *s) {
  return s->load_seen || s->hints.external_load_queued_bytes ||
         s->hints.external_load_oldest_age_msec ||
         s->hints.external_load_fraction_ppm > 100000;
}

static uint64_t bound_config(const group_mcbbr_t *s, uint64_t rate) {
  if (rate < s->config.minimum_rate_bytes_per_second)
    rate = s->config.minimum_rate_bytes_per_second;
  if (s->config.maximum_rate_bytes_per_second &&
      rate > s->config.maximum_rate_bytes_per_second)
    rate = s->config.maximum_rate_bytes_per_second;
  return rate;
}

static uint64_t bound(const group_mcbbr_t *s, uint64_t rate) {
  rate = bound_config(s, rate);
  if (s->hints.aggregate_rate_limit_bytes_per_second &&
      rate > s->hints.aggregate_rate_limit_bytes_per_second)
    rate = s->hints.aggregate_rate_limit_bytes_per_second;
  return rate;
}

static uint32_t end_drain(group_mcbbr_t *s, int64_t now, uint32_t reason) {
  s->drain.phase = DRAIN_IDLE;
  s->drain.ended_at = now;
  if (reason == TRANSPORT_GROUP_CC_REASON_DRAIN_EXPIRE)
    s->drain.needs_growth = true;
  return reason;
}

static uint32_t expire_drain(group_mcbbr_t *s, int64_t now) {
  return s->drain.phase != DRAIN_IDLE && now >= s->drain.deadline
             ? end_drain(s, now, TRANSPORT_GROUP_CC_REASON_DRAIN_EXPIRE)
             : 0;
}

static void record_stats(group_mcbbr_t *s, uint64_t prev_rate,
                         uint64_t next_rate, uint32_t reason) {
  uint64_t floor_rate = s->config.minimum_rate_bytes_per_second;
  bool now_floor = next_rate <= floor_rate;
  if (next_rate > prev_rate) {
    s->stats.rate_increase_events++;
    if (reason & QUICLY_FLEXICAST_CC_REASON_ACK)
      s->stats.ack_growth_events++;
    else
      s->stats.other_growth_events++;
  } else if (next_rate < prev_rate) {
    s->stats.rate_reduction_events++;
    if (reason & QUICLY_FLEXICAST_CC_REASON_ECN)
      s->stats.ecn_reduction_events++;
    else if (reason & QUICLY_FLEXICAST_CC_REASON_TIMEOUT)
      s->stats.timeout_reduction_events++;
    else if (reason & TRANSPORT_GROUP_CC_REASON_RATE_LIMIT)
      s->stats.rate_limit_reduction_events++;
    else if (reason & QUICLY_FLEXICAST_CC_REASON_LOSS)
      s->stats.loss_reduction_events++;
    else if (reason & QUICLY_FLEXICAST_CC_REASON_RTT)
      s->stats.rtt_reduction_events++;
    else
      s->stats.other_reduction_events++;
  }
  if (!s->at_floor && now_floor)
    s->stats.floor_entry_events++;
  else if (s->at_floor && !now_floor)
    s->stats.floor_exit_events++;
  s->at_floor = now_floor;
  if ((reason & (TRANSPORT_GROUP_CC_REASON_EXTERNAL_LOAD |
                 TRANSPORT_GROUP_CC_REASON_GROWTH_FROZEN)) ==
      (TRANSPORT_GROUP_CC_REASON_EXTERNAL_LOAD |
       TRANSPORT_GROUP_CC_REASON_GROWTH_FROZEN))
    s->stats.external_load_growth_freeze_events++;
}

static void output(group_mcbbr_t *s, uint64_t member, uint32_t reason,
                   bool track_stats) {
  quicly_flexicast_cc_output_t *o = &s->super.output;
  uint32_t senders = s->hints.active_senders ? s->hints.active_senders : 1;
  s->rate = bound_config(s, s->rate);
  uint64_t bounded = bound(s, s->rate);
  if (s->hints.aggregate_rate_limit_bytes_per_second &&
      s->rate > s->hints.aggregate_rate_limit_bytes_per_second)
    reason |= TRANSPORT_GROUP_CC_REASON_RATE_LIMIT;
  if (track_stats)
    record_stats(s, s->prev_output_rate, bounded, reason);
  else
    s->at_floor = bounded <= s->config.minimum_rate_bytes_per_second;
  s->prev_output_rate = bounded;
  uint64_t mss =
      s->config.maximum_datagram_size ? s->config.maximum_datagram_size : 1200;
  uint64_t burst = bounded / 20, low = senders >= 16 ? mss * 2 : mss * 4,
           high = mss * 10;
  o->rate_bytes_per_second = bounded;
  o->burst_bytes = burst < low ? low : burst > high ? high : burst;
  s->burst_bytes = o->burst_bytes;
  o->inflight_bytes = o->burst_bytes;
  uint64_t lim_id = (s->active > 1 && s->leader_id) ? s->leader_id : member;
  if (!lim_id && s->leader_id)
    lim_id = s->leader_id;
  o->limiting_member_id = s->active ? lim_id : 0;
  o->next_timeout = s->active ? s->next_timeout : INT64_MAX;
  if (s->drain.phase != DRAIN_IDLE && o->next_timeout > s->drain.deadline)
    o->next_timeout = s->drain.deadline;
  o->reason = reason;
}

static int added(quicly_flexicast_cc_t *cc, uint64_t id, int64_t now) {
  group_mcbbr_t *s = (group_mcbbr_t *)cc;
  uint32_t reason = expire_drain(s, now);
  mcbbr_peer_t *m = find(s, id);
  if (!m && id)
    for (size_t i = 0; i < s->config.maximum_members; i++)
      if (!s->peers[i].id) {
        m = &s->peers[i];
        m->id = id;
        break;
      }
  if (!m)
    return -1;
  if (!m->active) {
    m->active = true;
    if (!s->active++) {
      s->next_timeout = after(now, s->config.feedback_timeout_msec);
      s->unanswered = 0;
    }
  }
  output(s, id, reason, true);
  return 0;
}

static void suspended(quicly_flexicast_cc_t *cc, uint64_t id, int64_t now) {
  group_mcbbr_t *s = (group_mcbbr_t *)cc;
  uint32_t reason = expire_drain(s, now);
  if (s->drain.phase != DRAIN_IDLE && s->drain.member_id == id)
    reason |= end_drain(s, now, TRANSPORT_GROUP_CC_REASON_DRAIN_CLEAR);
  if (s->leader_id == id)
    s->leader_id = 0;
  mcbbr_peer_t *m = find(s, id);
  if (m && m->active) {
    m->active = false;
    --s->active;
    m->stable_at = 0;
    m->point_count = 0;
    m->window_stable = false;
    m->bloated_last = false;
  }
  if (!s->active) {
    s->unanswered = 0;
    s->leader_id = 0;
  } else if (!s->leader_id) {
    uint32_t worst_rtt = 0;
    for (size_t i = 0; i < s->config.maximum_members; i++) {
      if (s->peers[i].active && s->peers[i].rtt >= worst_rtt) {
        worst_rtt = s->peers[i].rtt;
        s->leader_id = s->peers[i].id;
        s->leader_at = now;
      }
    }
  }
  output(s, s->leader_id, reason, true);
}

static void removed(quicly_flexicast_cc_t *cc, uint64_t id, int64_t now) {
  suspended(cc, id, now);
  group_mcbbr_t *s = (group_mcbbr_t *)cc;
  mcbbr_peer_t *m = find(s, id);
  if (m)
    memset(m, 0, sizeof(*m));
}

static void epoch_reset(quicly_flexicast_cc_t *cc, int64_t now) {
  group_mcbbr_t *s = (group_mcbbr_t *)cc;
  uint32_t reason =
      s->drain.phase != DRAIN_IDLE ? TRANSPORT_GROUP_CC_REASON_DRAIN_CLEAR : 0;
  memset(&s->drain, 0, sizeof(s->drain));
  for (size_t i = 0; i < s->config.maximum_members; i++) {
    mcbbr_peer_t *m = &s->peers[i];
    uint64_t id = m->id, bw_hi = m->bw_hi;
    bool active = m->active;
    uint32_t clean = m->clean_ratio, loss = m->loss_baseline;
    memset(m, 0, sizeof(*m));
    m->id = id;
    m->active = active;
    m->clean_ratio = clean;
    m->loss_baseline = loss;
    m->bw_hi = bw_hi;
  }
  s->last_cut = s->last_growth = s->blocked_until = 0;
  s->bw_lo = 0;
  s->leader_id = 0;
  s->leader_at = 0;
  s->startup_bw_anchor = s->bw_hi;
  s->startup_round_at = now;
  s->startup_flat_rounds = 0;
  s->bbr_phase = s->bw_hi ? BBR_CRUISE : BBR_STARTUP;
  s->startup_probes = s->bw_hi ? 5 : 0;
  s->phase_at = now;
  s->unanswered = 0;
  s->cut_seen = s->congestion_seen = s->last_cut_was_timeout = s->growth_seen =
      false;
  s->last_timeout = now;
  s->next_timeout = after(now, s->config.feedback_timeout_msec);
  output(s, 0, reason, true);
}

static void apply_cut_peers(group_mcbbr_t *s, uint64_t next) {
  for (size_t i = 0; i < s->config.maximum_members; i++) {
    mcbbr_peer_t *m = &s->peers[i];
    if (m->rtt > m->reference)
      m->reference = m->rtt;
    m->rising = 0;
    m->supports_streak = 0;
    m->bw_lo = next;
  }
}

/* congestion cut records bw_hi/bw_lo bounds and enters cruise recovery */
static void congestion_cut(group_mcbbr_t *s, uint64_t member_id, uint64_t next,
                           uint64_t ceiling_hint, int64_t now,
                           uint64_t flight) {
  s->startup_probes = 5;
  next = bound_config(s, next);
  if (flight < interval(s))
    flight = interval(s);
  if (next >= s->rate) {
    int64_t short_blk = after(now, interval(s));
    if (short_blk > s->blocked_until)
      s->blocked_until = short_blk;
    return;
  }
  uint64_t hold_mult = (s->hints.active_senders >= 8 || s->active >= 8) ? 1 : 2;
  int64_t blocked = after(now, hold_mult * flight);
  if (blocked > s->blocked_until)
    s->blocked_until = blocked;
  if (member_id) {
    s->leader_id = member_id;
    s->leader_at = now;
  }
  uint64_t hi = ceiling_hint && ceiling_hint < s->rate ? ceiling_hint : s->rate;
  if (hi < next)
    hi = next;
  s->bw_hi = hi;
  s->rate = next;
  s->bw_lo = next;
  s->bbr_phase = BBR_CRUISE;
  s->phase_at = now;
  s->last_cut = now;
  s->cut_seen = true;
  s->congestion_seen = true;
  s->last_cut_was_timeout = false;
  apply_cut_peers(s, next);
}

/* silence cut backs off rate without overwriting proven bandwidth ceiling */
static void timeout_cut(group_mcbbr_t *s, uint64_t next, int64_t now,
                        uint64_t flight) {
  (void)flight;
  s->startup_probes = 5;
  next = bound_config(s, next);
  if (next >= s->rate)
    return;
  int64_t blocked = after(now, interval(s));
  if (blocked > s->blocked_until)
    s->blocked_until = blocked;
  s->rate = next;
  s->bw_lo = next;
  if (s->bw_hi) {
    s->bbr_phase = BBR_CRUISE;
    s->phase_at = now;
  }
  s->last_cut = now;
  s->cut_seen = true;
  s->last_cut_was_timeout = true;
  apply_cut_peers(s, next);
}

/* extract path wire RTT, recovering samples flagged by unsubtracted min_rtt */
static bool extract_rtt(const group_mcbbr_t *s, const mcbbr_peer_t *m,
                        const quicly_flexicast_feedback_t *f,
                        uint32_t *wire_out, uint32_t *raw_out,
                        uint32_t *flight_out) {
  (void)m;
  if (!(f->rtt_sample_flags & QUICLY_FLEXICAST_RTT_VALID) ||
      !f->rtt_sample_epoch || f->latest_rtt_msec > f->raw_rtt_msec ||
      f->rtt_sample_at <= 0 || f->rtt_sample_at > f->now ||
      f->rtt_sample_at < f->raw_rtt_msec ||
      (uint64_t)(f->now - f->rtt_sample_at) > s->config.feedback_timeout_msec)
    return false;
  uint32_t raw = f->raw_rtt_msec ? f->raw_rtt_msec : 1;
  uint32_t wire = f->latest_rtt_msec ? f->latest_rtt_msec : 1;
  if (f->rtt_sample_flags & QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT) {
    if (f->applied_ack_delay_msec != 0 ||
        f->latest_rtt_msec != f->raw_rtt_msec || f->rtt_ack_delay_msec == 0 ||
        f->raw_rtt_msec < f->rtt_ack_delay_msec ||
        (uint64_t)f->raw_rtt_msec >=
            (uint64_t)f->minimum_rtt_msec + f->rtt_ack_delay_msec)
      return false;
    uint32_t cand = f->raw_rtt_msec - f->rtt_ack_delay_msec;
    if (!cand)
      cand = 1;
    wire = cand;
  }
  if (raw < wire)
    raw = wire;
  uint32_t ack_part = raw - wire;
  if (ack_part > s->config.feedback_timeout_msec)
    ack_part = s->config.feedback_timeout_msec;
  *wire_out = wire;
  *raw_out = raw;
  *flight_out = wire + ack_part;
  return true;
}

static bool capacity_sample(const group_mcbbr_t *s, const mcbbr_peer_t *m,
                            const quicly_flexicast_feedback_t *f) {
  uint32_t rtt = f->raw_rtt_msec ? f->raw_rtt_msec
                                 : (m->flight_rtt ? m->flight_rtt : m->raw_rtt);
  uint64_t horizon = s->config.feedback_timeout_msec + 6 * (uint64_t)rtt;
  return (f->delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_VALID) != 0 &&
         !(f->delivery_sample_flags & (QUICLY_FLEXICAST_SAMPLE_APP_LIMITED |
                                       QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED |
                                       QUICLY_FLEXICAST_SAMPLE_MIXED)) &&
         f->delivery_rate_sample_epoch && f->delivery_sample_fanout &&
         f->delivery_sample_bytes &&
         f->delivery_sample_pacing_rate_bytes_per_second &&
         f->delivery_rate_bytes_per_second &&
         f->delivery_sample_sent_at_start >= 0 &&
         f->delivery_sample_sent_at_end >= f->delivery_sample_sent_at_start &&
         f->delivery_sample_acked_at_start >= 0 &&
         f->delivery_sample_acked_at_end > f->delivery_sample_acked_at_start &&
         f->delivery_sample_sent_at_end <= f->delivery_sample_acked_at_end &&
         f->delivery_sample_acked_at_end <= f->now &&
         (uint64_t)(f->now - f->delivery_sample_acked_at_end) <= horizon;
}

/* three-slot windowed min-RTT filter */
static void update_win_min(const group_mcbbr_t *s, mcbbr_peer_t *m,
                           uint32_t rtt, uint32_t flight_rtt, int64_t rtt_at) {
  uint32_t senders = s->hints.active_senders ? s->hints.active_senders : 1;
  uint64_t win_len = 10 * (uint64_t)s->config.feedback_timeout_msec;
  uint64_t span = 8 * (uint64_t)(senders >= 4 ? rtt : flight_rtt);
  uint64_t cap = 26000ULL + 120000ULL / (senders + 3ULL);
  if (senders >= 4 && span > cap)
    span = cap;
  if (win_len < span)
    win_len = span;
  if (win_len < 2000)
    win_len = 2000;
  if (!m->win_min[0].rtt || rtt <= m->win_min[0].rtt ||
      rtt_at < m->win_min[0].at) {
    m->win_min[0] = (delay_point_t){rtt, rtt_at};
    m->win_min[1] = m->win_min[0];
    m->win_min[2] = m->win_min[0];
    return;
  }
  if (rtt <= m->win_min[1].rtt) {
    m->win_min[1] = (delay_point_t){rtt, rtt_at};
    m->win_min[2] = m->win_min[1];
  } else if (rtt <= m->win_min[2].rtt) {
    m->win_min[2] = (delay_point_t){rtt, rtt_at};
  }
  uint64_t dt = (uint64_t)(rtt_at - m->win_min[0].at);
  if (dt > win_len) {
    m->win_min[0] = m->win_min[1];
    m->win_min[1] = m->win_min[2];
    m->win_min[2] = (delay_point_t){rtt, rtt_at};
    if ((uint64_t)(rtt_at - m->win_min[0].at) > win_len) {
      m->win_min[0] = m->win_min[1];
      m->win_min[1] = m->win_min[2];
      if ((uint64_t)(rtt_at - m->win_min[0].at) > win_len)
        m->win_min[0] = m->win_min[1];
    }
    return;
  }
  if (m->win_min[1].at == m->win_min[0].at && dt > win_len / 4) {
    m->win_min[1] = m->win_min[2] = (delay_point_t){rtt, rtt_at};
    return;
  }
  if (m->win_min[2].at == m->win_min[1].at &&
      (uint64_t)(rtt_at - m->win_min[1].at) > win_len / 2) {
    m->win_min[2] = (delay_point_t){rtt, rtt_at};
  }
}

static uint64_t sched_quantum(const group_mcbbr_t *s, uint64_t rtt) {
  uint64_t iv = interval(s);
  return (rtt && iv) ? (rtt * iv) / (rtt + iv) : 0;
}

/* four-sample stability window for baseline RTT adaptation */
static bool observe_window(group_mcbbr_t *s, mcbbr_peer_t *m,
                           uint32_t latest_rtt, uint32_t flight_rtt,
                           int64_t rtt_at, bool growing, bool bloated) {
  if (m->point_count) {
    delay_point_t *last =
        &m->points[(m->point_next + DELAY_POINTS - 1) % DELAY_POINTS];
    uint64_t min_step = (uint64_t)latest_rtt * 2 / 3;
    if (!min_step)
      min_step = 1;
    if ((uint64_t)(rtt_at - last->at) >
        8 * (uint64_t)flight_rtt +
            4 * (uint64_t)s->config.feedback_timeout_msec)
      m->point_count = m->point_next = 0;
    else if ((uint64_t)(rtt_at - last->at) < min_step)
      return bloated;
  }
  m->points[m->point_next] = (delay_point_t){latest_rtt, rtt_at};
  m->point_next = (m->point_next + 1) % DELAY_POINTS;
  if (m->point_count < DELAY_POINTS)
    ++m->point_count;
  if (m->point_count < DELAY_POINTS) {
    m->window_stable = false;
    return bloated;
  }
  uint32_t p[DELAY_POINTS];
  uint32_t low = UINT32_MAX, high = 0;
  for (unsigned i = 0; i < DELAY_POINTS; i++) {
    p[i] = m->points[(m->point_next + i) % DELAY_POINTS].rtt;
    if (p[i] < low)
      low = p[i];
    if (p[i] > high)
      high = p[i];
  }
  uint64_t early = (uint64_t)p[0] + p[1];
  uint64_t late = (uint64_t)p[2] + p[3];
  bool monotonic_up = p[0] < p[1] && p[1] < p[2] && p[2] < p[3];
  uint64_t q = sched_quantum(s, low);
  uint64_t plateau_tol = (uint64_t)low / 5 + 4;
  uint64_t drift_tol = early / 16 + 4;
  if (q > plateau_tol)
    plateau_tol = q;
  if (q * 2U > drift_tol)
    drift_tol = q * 2U;
  bool flat_plateau =
      !growing &&
      (uint64_t)(rtt_at - m->points[m->point_next].at) >= 2 * (uint64_t)low &&
      !monotonic_up && (uint64_t)high <= low + plateau_tol &&
      late <= early + drift_tol;
  /* re-anchor baseline RTT after a propagation-delay step-up */
  bool step_up =
      (s->hints.active_senders > 1 || s->active > 1) && !monotonic_up &&
      (uint64_t)(rtt_at - m->points[m->point_next].at) >= 2 * (uint64_t)low &&
      (uint64_t)high <= (uint64_t)low * 2;
  if ((flat_plateau || step_up) && bloated && m->win_min[0].rtt > 0 &&
      low > m->win_min[0].rtt * 2) {
    m->win_min[0] = m->win_min[1] = m->win_min[2] =
        (delay_point_t){low, rtt_at};
    bloated = false;
  }
  m->window_stable = flat_plateau && !bloated;
  if (m->window_stable)
    m->rising = 0;
  if (m->window_stable && (uint64_t)high + high / 20 < m->reference)
    m->reference = high;
  return bloated;
}

static bool step_up_pending(const mcbbr_peer_t *m, uint32_t latest_rtt) {
  if (!m->win_min[0].rtt || latest_rtt <= m->win_min[0].rtt * 2 || m->degraded)
    return false;
  if (m->point_count < DELAY_POINTS)
    return true;
  for (unsigned i = 0; i < DELAY_POINTS; i++)
    if ((uint64_t)m->points[i].rtt * 2 < latest_rtt)
      return true;
  return false;
}

static uint64_t severe_bloat_slack(const group_mcbbr_t *s, uint32_t base_rtt) {
  uint64_t iv_slack = interval(s) * 2U;
  return base_rtt > iv_slack ? base_rtt : iv_slack;
}

static bool cohort_severe_bloat(const group_mcbbr_t *s, int64_t now) {
  size_t seen = 0, bloated = 0;
  uint64_t iv_lim = interval(s) * 10U;
  for (size_t i = 0; i < s->config.maximum_members; i++) {
    const mcbbr_peer_t *p = &s->peers[i];
    uint64_t fresh_lim = (uint64_t)p->win_min[0].rtt * 8U > iv_lim
                             ? (uint64_t)p->win_min[0].rtt * 8U
                             : iv_lim;
    if (!p->active || p->rtt_at <= 0 || now < p->rtt_at ||
        (uint64_t)(now - p->rtt_at) > fresh_lim || !p->win_min[0].rtt ||
        step_up_pending(p, p->rtt))
      continue;
    ++seen;
    if ((uint64_t)p->rtt >
        (uint64_t)p->win_min[0].rtt + severe_bloat_slack(s, p->win_min[0].rtt))
      ++bloated;
  }
  return seen > 0 &&
         bloated * (s->hints.aggregate_rate_limit_bytes_per_second ? 2U : 3U) >=
             seen;
}

static bool is_slotted_schedule(const group_mcbbr_t *s, const mcbbr_peer_t *m,
                                uint32_t mult) {
  return !s->hints.aggregate_rate_limit_bytes_per_second &&
         m->win_min[0].rtt > 0 &&
         interval(s) > (uint64_t)m->win_min[0].rtt * mult;
}

static bool observe(group_mcbbr_t *s, mcbbr_peer_t *m,
                    const quicly_flexicast_feedback_t *f, int64_t rtt_at,
                    uint32_t latest_rtt, uint32_t raw_rtt, uint32_t flight_rtt,
                    uint64_t rtt_epoch, bool other_up, bool *bloated_out) {
  update_win_min(s, m, latest_rtt, flight_rtt, rtt_at);
  bool post_cut_rtt = !s->cut_seen || rtt_at - (int64_t)raw_rtt >= s->last_cut;
  uint32_t senders = s->hints.active_senders ? s->hints.active_senders : 1;
  bool sample_app_lim =
      (f->delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_APP_LIMITED) != 0;
  bool shared_sched = senders > 1U || sample_app_lim;
  uint64_t q = sched_quantum(s, m->win_min[0].rtt);
  uint32_t margin = shared_sched ? m->reference / 10U : m->reference / 20U;
  if (shared_sched && q > margin)
    margin = (uint32_t)q;
  if (margin < 5)
    margin = 5;
  bool within_slot =
      shared_sched && is_slotted_schedule(s, m, 4U) &&
      (uint64_t)latest_rtt <= (uint64_t)m->win_min[0].rtt + interval(s);
  bool growing = !within_slot && m->reference &&
                 (uint64_t)latest_rtt > (uint64_t)m->reference + margin;
  uint32_t jitter_tol = m->win_min[0].rtt / 4;
  if (shared_sched &&
      (s->hints.aggregate_rate_limit_bytes_per_second ? q > jitter_tol : q > 0))
    jitter_tol = (uint32_t)q;
  bool bloated = m->win_min[0].rtt > 0 &&
                 (uint64_t)latest_rtt >
                     (uint64_t)m->win_min[0].rtt + jitter_tol + interval(s);
  if (!m->reference || (growing && post_cut_rtt)) {
    m->reference = latest_rtt;
    if (growing && m->rising < 2 && post_cut_rtt)
      ++m->rising;
  } else if (!growing && bloated && !step_up_pending(m, latest_rtt) &&
             post_cut_rtt && m->rising < 2) {
    ++m->rising;
  } else if (!bloated && (uint64_t)latest_rtt + margin < m->reference) {
    m->rising = 0;
  }
  bool isolated_outlier =
      s->active > 2 && !other_up && !bloated && !m->degraded;
  if (!growing && !bloated) {
    uint32_t band = m->stable_rtt / 8 + 4;
    if (shared_sched && q > band)
      band = (uint32_t)q;
    if (!m->stable_at ||
        (uint64_t)latest_rtt > (uint64_t)m->stable_rtt + band ||
        (uint64_t)latest_rtt + band < m->stable_rtt) {
      m->stable_at = rtt_at;
      m->stable_rtt = latest_rtt;
    }
  } else if (!isolated_outlier &&
             (!s->hints.aggregate_rate_limit_bytes_per_second || bloated ||
              m->degraded)) {
    m->stable_at = 0;
    uint64_t flight = flight_rtt < interval(s) ? interval(s) : flight_rtt;
    uint64_t wait;
    if (s->hints.aggregate_rate_limit_bytes_per_second > 0) {
      wait = cohort_severe_bloat(s, f->now) ? flight : interval(s);
    } else {
      wait = ((s->active <= 2 && m->rising >= 2) || other_up)
                 ? control_flight(s, f->now)
             : (s->active > 2 && !bloated) ? interval(s)
                                           : flight;
      if ((s->active <= 2 || other_up || bloated) && wait < flight)
        wait = flight;
    }
    int64_t blocked = after(f->now, wait);
    if (blocked > s->blocked_until)
      s->blocked_until = blocked;
  } else if (!m->stable_at) {
    m->stable_at = rtt_at;
    m->stable_rtt = latest_rtt;
  }
  bloated =
      observe_window(s, m, latest_rtt, flight_rtt, rtt_at, growing, bloated);
  if (!growing && !bloated && !m->stable_at) {
    m->stable_at = rtt_at;
    m->stable_rtt = latest_rtt;
  }
  m->rtt = latest_rtt;
  m->raw_rtt = raw_rtt;
  m->flight_rtt = flight_rtt;
  m->minimum_rtt =
      f->minimum_rtt_msec ? f->minimum_rtt_msec : m->win_min[0].rtt;
  m->rtt_at = rtt_at;
  m->rtt_epoch = rtt_epoch;
  m->bloated_last = bloated;
  *bloated_out = bloated;
  return growing;
}

static uint32_t update_drain(group_mcbbr_t *s, const mcbbr_peer_t *m,
                             const quicly_flexicast_feedback_t *f,
                             bool fresh_rtt, bool growing, bool congested_del,
                             uint64_t group_flight) {
  mcbbr_drain_t *d = &s->drain;
  int64_t rtt_at = f->rtt_sample_at ? f->rtt_sample_at : f->now;
  if (d->phase != DRAIN_IDLE && d->member_id == f->member_id && fresh_rtt &&
      rtt_at >= d->started_at && !growing && !f->ecn_ce_count &&
      (d->phase == DRAIN_OBSERVING || f->now >= s->blocked_until))
    return end_drain(s, f->now, TRANSPORT_GROUP_CC_REASON_DRAIN_CLEAR);
  uint64_t d_med = s->hints.median_sender_rate_bytes_per_second;
  bool below_cohort =
      s->hints.active_senders >= 8 && d_med > 0 &&
      s->rate <= scale(d_med, 4, 5);
  bool eligible = m->capacity_eligible && fresh_rtt && growing &&
                  !below_cohort && !f->ecn_ce_count && !external(s) &&
                  (!d->ended_at || rtt_at >= s->last_growth);
  if (!eligible)
    return 0;
  if (d->phase == DRAIN_IDLE && !d->needs_growth && congested_del) {
    d->phase = DRAIN_OBSERVING;
    d->member_id = f->member_id;
    d->ceiling = d->target = 0;
    d->started_at = f->now;
    d->deadline = after(f->now, 2 * group_flight);
  } else if (d->phase == DRAIN_OBSERVING && d->member_id == f->member_id &&
             congested_del && m->ceiling > 0 &&
             f->now >= after(d->started_at, interval(s)) &&
             (!s->cut_seen || f->now >= after(s->last_cut, interval(s)))) {
    uint64_t target = bound(s, scale(m->ceiling, 80, 100));
    if (target < s->rate) {
      d->phase = DRAIN_ACTIVE;
      d->member_id = f->member_id;
      d->ceiling = m->ceiling;
      d->target = target;
      d->started_at = f->now;
      d->deadline = after(f->now, 2 * group_flight);
      return TRANSPORT_GROUP_CC_REASON_DRAIN_ENTER;
    }
  }
  return 0;
}

static void feedback_received(quicly_flexicast_cc_t *cc,
                              const quicly_flexicast_feedback_t *f) {
  group_mcbbr_t *s = (group_mcbbr_t *)cc;
  uint32_t reason = expire_drain(s, f->now);
  mcbbr_peer_t *m = find(s, f->member_id);
  if (!m || !m->active || f->now < 0 || f->now < m->feedback_at ||
      ((f->epoch && f->epoch <= m->feedback_epoch) ||
       (!f->epoch && m->feedback_seen && f->now <= m->feedback_at))) {
    output(s, 0, reason, true);
    return;
  }
  if (f->epoch)
    m->feedback_epoch = f->epoch;
  m->feedback_at = f->now;
  m->feedback_seen = true;
  s->last_timeout = f->now;
  s->unanswered = 0;

  bool explicit_rtt = (f->rtt_sample_flags != 0) || f->rtt_sample_epoch ||
                      f->rtt_sample_at || f->raw_rtt_msec ||
                      f->latest_rtt_msec == 0;
  int64_t rtt_at = explicit_rtt ? f->rtt_sample_at : f->now;
  uint32_t latest_rtt =
      explicit_rtt && !f->latest_rtt_msec ? 1 : f->latest_rtt_msec;
  uint32_t raw_rtt =
      explicit_rtt ? (f->raw_rtt_msec ? f->raw_rtt_msec : 1) : latest_rtt;
  if (raw_rtt < latest_rtt)
    raw_rtt = latest_rtt;
  uint32_t flight_rtt = raw_rtt;
  uint64_t rtt_epoch = explicit_rtt
                           ? f->rtt_sample_epoch
                           : (f->now > 0 ? (uint64_t)f->now : f->epoch);
  bool rtt_valid =
      explicit_rtt ? extract_rtt(s, m, f, &latest_rtt, &raw_rtt, &flight_rtt)
                   : (f->latest_rtt_msec > 0);
  bool fresh_rtt = rtt_valid && rtt_epoch > m->rtt_epoch && rtt_at >= m->rtt_at;
  /* observe only changes this member, which the corroboration scan excludes. */
  bool other_up =
      (fresh_rtt || s->active > 2) && any_other_rising(s, m, f->now);
  bool bloated = false;
  bool growing = fresh_rtt ? observe(s, m, f, rtt_at, latest_rtt, raw_rtt,
                                     flight_rtt, rtt_epoch, other_up, &bloated)
                           : false;
  bool corroborated = s->active <= 2 || other_up;
  bool session_unbloated = s->hints.aggregate_rate_limit_bytes_per_second > 0 &&
                           !bloated && !m->degraded;
  bool isolated_jitter =
      s->active > 2 && !corroborated && !bloated && !m->degraded;
  bool queued = !session_unbloated && !isolated_jitter && (growing || bloated);
  /* Capture the flight after observe has installed the fresh RTT. */
  uint64_t group_flight = control_flight(s, f->now);
  s->next_timeout = after(f->now, group_flight);
  bool rtt_calm = fresh_rtt && !queued && m->stable_at > 0 &&
                  (uint64_t)(rtt_at - m->stable_at) >= latest_rtt &&
                  (!s->cut_seen || rtt_at - (int64_t)raw_rtt >= s->last_cut);
  bool stable = rtt_calm && m->window_stable;

  bool explicit_delivery =
      (f->delivery_sample_flags != 0) || f->delivery_rate_sample_epoch ||
      f->delivery_sample_fanout || f->delivery_sample_bytes ||
      f->delivery_sample_pacing_rate_bytes_per_second ||
      f->delivery_rate_bytes_per_second == 0;
  uint64_t del_epoch = explicit_delivery
                           ? f->delivery_rate_sample_epoch
                           : (f->now > 0 ? (uint64_t)f->now : f->epoch);
  bool fresh_delivery = del_epoch > m->delivery_epoch;
  if (fresh_delivery)
    m->delivery_epoch = del_epoch;

  m->capacity_eligible = m->capacity_post_cut = false;
  m->ceiling = 0;
  bool supports = false, capacity_drop = false,
       usable = fresh_delivery &&
                (explicit_delivery ? capacity_sample(s, m, f)
                                   : f->delivery_rate_bytes_per_second > 0);

  uint64_t total = UINT64_MAX - f->lost_packets < f->acked_packets
                       ? UINT64_MAX
                       : f->lost_packets + f->acked_packets;
  uint32_t current_loss = ratio(f->lost_packets, total);
  uint64_t loss_margin = 20000 + (uint64_t)m->loss_baseline / 3;
  bool new_loss =
      f->lost_packets && (!usable || f->lost_packets >= 2 || total >= 8) &&
      (uint64_t)current_loss > (uint64_t)m->loss_baseline + loss_margin;

  if (usable) {
    uint64_t ref = explicit_delivery
                       ? f->delivery_sample_pacing_rate_bytes_per_second
                       : s->rate;
    uint64_t fan = explicit_delivery ? f->delivery_sample_fanout
                                     : (s->hints.delivery_rate_divisor
                                            ? s->hints.delivery_rate_divisor
                                            : 1);
    uint32_t r =
        f->delivery_rate_bytes_per_second >= ref / fan + (ref % fan != 0)
            ? PPM
            : ratio(f->delivery_rate_bytes_per_second * fan, ref);
    m->capacity_eligible = true;
    m->capacity_post_cut = !s->cut_seen || !explicit_delivery ||
                           f->delivery_sample_sent_at_start >= s->last_cut;
    if (m->clean_ratio || !explicit_delivery) {
      uint32_t clean = m->clean_ratio ? m->clean_ratio : PPM;
      m->ceiling = r < clean ? scale(ref, r, clean) : ref;
    } else if (queued && r < (PPM * 3) / 4) {
      /* startup overload before clean baseline: estimate conservatively */
      m->ceiling = scale(ref, r, (PPM * 85) / 100);
    }
    if (m->capacity_post_cut) {
      supports =
          ref >= s->rate &&
          (m->clean_ratio ? (uint64_t)r + m->clean_ratio / 10 >= m->clean_ratio
                          : r >= (PPM * 9) / 10);
      if (supports && !queued && !f->ecn_ce_count && !new_loss) {
        if (m->supports_streak < 4)
          ++m->supports_streak;
        uint64_t proven = m->ceiling ? m->ceiling : ref;
        if (proven > m->bw_hi)
          m->bw_hi = proven;
        if (proven > s->bw_hi)
          s->bw_hi = proven;
        m->bw_lo = 0;
        s->bw_lo = 0;
      } else {
        m->supports_streak = 0;
      }
      uint32_t senders = s->hints.active_senders ? s->hints.active_senders : 1;
      uint64_t fair_sh = channel_share_rate(s);
      uint64_t med = s->hints.median_sender_rate_bytes_per_second;
      bool cohort_over =
          !is_slotted_schedule(s, m, 8U) &&
          ((senders >= 4 && med > 0 && s->rate > (__uint128_t)med * 7 / 4 &&
            r < (PPM * 3) / 4) ||
           (senders >= 4 && s->rate > fair_sh && r < 250000));
      bool drop_ratio = m->clean_ratio
                            ? (uint64_t)r + m->clean_ratio / 10 < m->clean_ratio
                            : ((queued || cohort_over) && r < (PPM * 3) / 4);
      if (drop_ratio) {
        if (m->degraded < 2)
          ++m->degraded;
        if (!m->ceiling && cohort_over)
          m->ceiling = scale(ref, r, (PPM * 85) / 100);
        capacity_drop = m->degraded >= 2 && m->ceiling && m->ceiling < s->rate;
      } else {
        m->degraded = 0;
      }
      /* BBRv3 startup full-pipe detection after 3 non-growing rounds */
      bool ext_capped =
          (s->hints.aggregate_rate_limit_bytes_per_second &&
           s->rate >= s->hints.aggregate_rate_limit_bytes_per_second) ||
          (f->delivery_sample_flags & (QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED |
                                       QUICLY_FLEXICAST_SAMPLE_APP_LIMITED)) !=
              0;
      if (s->bbr_phase == BBR_STARTUP && s->bw_hi > 0 && !ext_capped) {
        uint64_t r_flight =
            flight_rtt ? flight_rtt : s->config.feedback_timeout_msec;
        if (r_flight < interval(s))
          r_flight = interval(s);
        if (!s->startup_bw_anchor) {
          s->startup_bw_anchor = s->bw_hi;
          s->startup_round_at = f->now;
        } else if (f->now >= after(s->startup_round_at, r_flight)) {
          s->startup_round_at = f->now;
          if (s->bw_hi >= (__uint128_t)s->startup_bw_anchor * 5 / 4) {
            s->startup_bw_anchor = s->bw_hi;
            s->startup_flat_rounds = 0;
          } else if (++s->startup_flat_rounds >= 3) {
            s->bbr_phase = BBR_CRUISE;
            s->phase_at = f->now;
          }
        }
      }
      m->recent_ratio = r;
      m->recent_delivery = f->delivery_rate_bytes_per_second;
      m->expected_delivery = ref / fan;
      bool first_calm =
          fresh_rtt && !queued && m->rising == 0 &&
          (!s->cut_seen || rtt_at - (int64_t)raw_rtt >= s->last_cut);
      if ((stable || ((rtt_calm || first_calm) && !m->clean_ratio) ||
           (!explicit_rtt && !queued)) &&
          !queued && !f->ecn_ce_count && r && (senders < 8 || r >= 350000)) {
        uint32_t delta = m->candidate_ratio > r ? m->candidate_ratio - r
                                                : r - m->candidate_ratio;
        if (!m->candidate_count || delta > m->candidate_ratio / 5 + 25000) {
          m->candidate_ratio = r;
          m->candidate_count = 1;
          if (m->clean_ratio > r)
            m->clean_ratio = (m->clean_ratio * 7 + r) / 8;
        } else if (m->candidate_count < 4) {
          ++m->candidate_count;
        }
        if (m->candidate_count >= 3)
          m->clean_ratio = (m->candidate_ratio + r) / 2;
      }
    } else {
      m->supports_streak = 0;
    }
  } else if (fresh_delivery) {
    m->supports_streak = 0;
  }

  uint64_t flight =
      fresh_rtt ? flight_rtt : (m->flight_rtt ? m->flight_rtt : m->raw_rtt);
  if (flight < group_flight)
    flight = group_flight;
  update_ack_leader(s, m, f->now, group_flight);
  bool due = !s->cut_seen || f->now >= after(s->last_cut, flight);
  bool post_cut =
      fresh_rtt && (!s->cut_seen || rtt_at - (int64_t)raw_rtt >= s->last_cut);

  reason |= update_drain(s, m, f, fresh_rtt, queued,
                         m->degraded > 0 && m->ceiling < s->rate, group_flight);

  uint32_t active_senders =
      s->hints.active_senders ? s->hints.active_senders : 1;
  bool multi_sender = active_senders > 1U;
  uint64_t fair_share = channel_share_rate(s);
  uint64_t cohort_med = s->hints.median_sender_rate_bytes_per_second;
  bool rf_loss_only = fresh_rtt && !queued && !bloated && m->rising == 0 &&
                      !f->ecn_ce_count && current_loss <= (PPM * 3U) / 4U &&
                      (m->loss_baseline > 0 || s->active > 2);
  bool cohort_saturated = !is_slotted_schedule(s, m, 8U) &&
                          ((multi_sender && cohort_med > 0 &&
                            s->rate > (__uint128_t)cohort_med * 7 / 4) ||
                           (multi_sender && s->rate > fair_share && usable &&
                            m->recent_ratio < PPM / 4U));
  if (f->ecn_ce_count) {
    reason |= QUICLY_FLEXICAST_CC_REASON_ECN;
    if (!s->cut_seen || f->now >= after(s->last_cut, interval(s)))
      congestion_cut(s, m->id, scale(s->rate, 85, 100), 0, f->now, flight);
  } else if (s->drain.phase == DRAIN_ACTIVE && s->rate > s->drain.target &&
             ((reason & TRANSPORT_GROUP_CC_REASON_DRAIN_ENTER) ||
              !s->cut_seen || f->now >= after(s->last_cut, group_flight))) {
    uint64_t next = s->drain.target, low = scale(s->rate, 1, 2),
             high = scale(s->rate, 9, 10);
    congestion_cut(s, s->drain.member_id ? s->drain.member_id : m->id,
                   next < low    ? low
                   : next > high ? high
                                 : next,
                   s->drain.ceiling, f->now, flight);
    reason |= TRANSPORT_GROUP_CC_REASON_DRAIN_CUT;
    if (capacity_drop && queued)
      reason |=
          QUICLY_FLEXICAST_CC_REASON_RTT | QUICLY_FLEXICAST_CC_REASON_LOSS;
  } else if (capacity_drop && !rf_loss_only && (queued || cohort_saturated) &&
             due && (corroborated || m->id == s->leader_id || bloated) &&
             !(multi_sender && cohort_med > 0 &&
               s->rate <= scale(cohort_med, 4, 5))) {
    uint64_t next = m->ceiling, low = scale(s->rate, 1, 2),
             high = scale(s->rate, 9, 10);
    if (multi_sender && cohort_med > 0) {
      uint64_t cfloor = scale(cohort_med, 4, 5);
      if (cfloor > low && cfloor < high)
        low = cfloor;
    }
    congestion_cut(s, m->id,
                   next < low    ? low
                   : next > high ? high
                                 : next,
                   m->ceiling, f->now, flight);
    reason |= QUICLY_FLEXICAST_CC_REASON_RTT | QUICLY_FLEXICAST_CC_REASON_LOSS;
  } else if (queued && m->rising >= 2 && post_cut && due &&
             (corroborated || bloated || m->id == s->leader_id) &&
             !((f->delivery_sample_flags &
                QUICLY_FLEXICAST_SAMPLE_APP_LIMITED) &&
               multi_sender && !bloated && !m->degraded) &&
             !(multi_sender && cohort_med > 0 &&
               !cohort_severe_bloat(s, f->now) &&
               s->rate <= scale(cohort_med, 4, 5))) {
    bool app_lim =
        (f->delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_APP_LIMITED) != 0;
    bool harsh = bloated && multi_sender &&
                 (growing || (!usable && !app_lim) || m->degraded);
    uint32_t cut_num =
        harsh ? 80U + (10U * (active_senders - 1U)) / (active_senders + 3U)
              : 90U + (4U * (active_senders - 1U)) / (active_senders + 3U);
    uint64_t next = scale(s->rate, cut_num, 100);
    bool severe_bloat =
        (multi_sender || s->active > 2)
            ? cohort_severe_bloat(s, f->now)
            : (m->win_min[0].rtt > 0 && !step_up_pending(m, m->rtt) &&
               (uint64_t)m->rtt > (uint64_t)m->win_min[0].rtt +
                                      severe_bloat_slack(s, m->win_min[0].rtt));
    if (multi_sender && cohort_med > 0 && !severe_bloat) {
      uint64_t cfloor = scale(cohort_med, 4, 5);
      if (next < cfloor)
        next = cfloor < s->rate ? cfloor : s->rate;
    } else if (multi_sender && !severe_bloat) {
      uint64_t sfloor = scale(fair_share, 3, 4);
      if (next < sfloor)
        next = sfloor < s->rate ? sfloor : s->rate;
    }
    congestion_cut(s, m->id, next, 0, f->now, flight);
    reason |= QUICLY_FLEXICAST_CC_REASON_RTT;
  } else if (f->acked_packets) {
    reason |= QUICLY_FLEXICAST_CC_REASON_ACK;
    bool sev_bloat = multi_sender && cohort_severe_bloat(s, f->now);
    bool eff_loss = new_loss && !rf_loss_only;
    bool clear =
        f->now >= s->blocked_until && !queued && !f->ecn_ce_count && !eff_loss;
    bool clear_catchup =
        f->now >= s->blocked_until && !f->ecn_ce_count && !sev_bloat;
    bool inconsistent_proof =
        explicit_rtt &&
        (f->rtt_sample_flags & QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT) &&
        m->rtt_at == 0 && m->supports_streak >= 2;
    bool rtt_ok =
        !explicit_rtt || inconsistent_proof ||
        (m->rtt_at > 0 && f->now >= m->rtt_at &&
         (uint64_t)(f->now - m->rtt_at) <= group_flight &&
         (!s->cut_seen || m->rtt_at - (int64_t)m->raw_rtt >= s->last_cut));
    bool proof =
        supports && m->capacity_post_cut && rtt_ok &&
        (m->window_stable || inconsistent_proof || (!explicit_rtt && !queued) ||
         (m->clean_ratio && m->stable_at > 0 &&
          (uint64_t)(m->rtt_at - m->stable_at) >= 2 * (uint64_t)m->rtt));
    bool host_limited =
        (f->delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED) != 0;
    bool app_limited =
        (f->delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_APP_LIMITED) != 0;
    uint32_t senders = active_senders;
    uint64_t fair_startup = s->config.startup_rate_bytes_per_second;
    if (s->hints.aggregate_rate_limit_bytes_per_second &&
        fair_startup > s->hints.aggregate_rate_limit_bytes_per_second)
      fair_startup = s->hints.aggregate_rate_limit_bytes_per_second;
    if (multi_sender && (__uint128_t)fair_share * 2 < fair_startup)
      fair_startup = fair_share * 2;
    uint64_t app_cap = s->bw_hi ? scale(s->bw_hi, 85, 100) : 0;
    if (m->recent_delivery > app_cap)
      app_cap = m->recent_delivery;
    if (s->hints.median_sender_rate_bytes_per_second > app_cap)
      app_cap = s->hints.median_sender_rate_bytes_per_second;
    if (multi_sender &&
        (!s->congestion_seen || s->last_cut_was_timeout ||
         (clear && !capacity_drop)) &&
        fair_startup > app_cap)
      app_cap = fair_startup;
    bool no_del_ok = !usable && !host_limited &&
                     (!app_limited || !m->recent_delivery || s->rate < app_cap);
    bool del_ok =
        usable && m->capacity_post_cut &&
        (m->clean_ratio
             ? (uint64_t)m->recent_ratio + m->clean_ratio / 8 >= m->clean_ratio
             : m->recent_ratio >= (PPM * 3) / 4);
    bool post_timeout_recover =
        s->cut_seen &&
        (s->last_cut_was_timeout || !s->congestion_seen ||
         s->rate <= fair_startup / 2 ||
         (multi_sender && clear && !capacity_drop)) &&
        s->rate < fair_startup;
    bool calm_recover = post_timeout_recover && fresh_rtt && !queued &&
                        m->rising == 0 &&
                        (s->last_cut_was_timeout || !s->cut_seen ||
                         rtt_at - (int64_t)raw_rtt >= s->last_cut);
    bool median_catchup = cohort_med > s->rate && rtt_calm;
    bool lagging_cohort =
        multi_sender && cohort_med > 0 && s->rate < scale(cohort_med, 17, 20) &&
        fresh_rtt &&
        ((!queued && m->rising == 0) ||
         (!sev_bloat && (!bloated || s->rate < scale(cohort_med, 3, 5)))) &&
        (!s->cut_seen || rtt_at - (int64_t)raw_rtt >= s->last_cut);
    bool probe =
        !proof && !capacity_drop &&
        s->rate < s->config.startup_rate_bytes_per_second &&
        ((no_del_ok &&
          (stable ||
           (multi_sender && rtt_calm && s->rate < (__uint128_t)fair_startup * 2) ||
           calm_recover || median_catchup) &&
          !eff_loss) ||
         (del_ok && (stable || rtt_calm) && !eff_loss) || lagging_cohort);
    bool startup_probe = s->bbr_phase == BBR_STARTUP && !proof && !probe &&
                         !s->cut_seen && s->startup_probes < 5 && !usable &&
                         !capacity_drop &&
                         (!explicit_delivery ||
                          (f->delivery_rate_sample_epoch == 0 && fresh_rtt));
    uint64_t half_flight = flight / 2 > interval(s) ? flight / 2 : interval(s);
    uint64_t pace =
        (proof || startup_probe || post_timeout_recover || lagging_cohort)
            ? interval(s)
            : (multi_sender && rtt_calm ? half_flight : flight);
    /* BBRv3 ProbeBW cycle transitions: CRUISE -> REFILL -> UP -> CRUISE */
    if (s->bbr_phase == BBR_UP &&
        (queued || (!supports && s->bw_hi &&
                    s->rate >= (__uint128_t)s->bw_hi * 5 / 4 &&
                    f->now >= after(s->phase_at, 2 * group_flight)))) {
      s->bbr_phase = BBR_CRUISE;
      s->phase_at = f->now;
      if (queued && s->congestion_seen && s->bw_hi && s->rate > s->bw_hi)
        s->rate = s->bw_hi;
    }
    if (s->drain.phase == DRAIN_ACTIVE) {
      reason |= TRANSPORT_GROUP_CC_REASON_GROWTH_FROZEN;
    } else if (((clear && (proof || probe || startup_probe)) ||
                (clear_catchup && lagging_cohort &&
                 s->rate < s->config.startup_rate_bytes_per_second)) &&
               (!s->growth_seen || f->now >= after(s->last_growth, pace))) {
      if (external(s)) {
        reason |= TRANSPORT_GROUP_CC_REASON_EXTERNAL_LOAD |
                  TRANSPORT_GROUP_CC_REASON_GROWTH_FROZEN;
      } else {
        uint64_t median = s->hints.median_sender_rate_bytes_per_second;
        uint64_t headroom = s->bw_hi ? scale(s->bw_hi, 85, 100) : 0;
        if (s->bbr_phase == BBR_CRUISE &&
            ((headroom && s->rate >= headroom) ||
             f->now >= after(s->phase_at, 2 * group_flight))) {
          s->bbr_phase = BBR_REFILL;
          s->phase_at = f->now;
        }
        if (s->bbr_phase == BBR_REFILL &&
            ((s->bw_hi && s->rate >= s->bw_hi) ||
             f->now >= after(s->phase_at, flight))) {
          s->bbr_phase = BBR_UP;
          s->phase_at = f->now;
        }
        uint64_t div = 16;
        if (s->bbr_phase == BBR_STARTUP || startup_probe ||
            post_timeout_recover || median > s->rate ||
            (multi_sender && rtt_calm && s->rate < fair_startup)) {
          div = 8;
        } else if (headroom && s->rate < headroom) {
          div = 12;
        } else if (s->bbr_phase == BBR_UP && s->cut_seen) {
          div = 20;
        }
        uint64_t inc =
            (uint64_t)((double)s->rate / (div * sqrt((double)senders)));
        uint64_t mss = s->config.maximum_datagram_size
                           ? s->config.maximum_datagram_size
                           : 1200;
        uint64_t floor_inc = (uint64_t)((double)mss / sqrt((double)senders));
        if (s->rate < 4 * mss && floor_inc < mss / 2)
          floor_inc = mss / 2;
        if (!floor_inc)
          floor_inc = 1;
        if (inc < floor_inc)
          inc = floor_inc;
        if (lagging_cohort) {
          uint64_t target_rate = scale(cohort_med, 17, 20);
          uint64_t catchup = (target_rate - s->rate) / 3;
          if (catchup > inc)
            inc = catchup;
        }
        if (median > s->rate && inc > median - s->rate)
          inc = median - s->rate;
        uint64_t next = UINT64_MAX - s->rate < inc ? UINT64_MAX : s->rate + inc;
        if (!proof && !startup_probe &&
            next > s->config.startup_rate_bytes_per_second)
          next = s->config.startup_rate_bytes_per_second;
        if (next > s->rate) {
          s->rate = next;
          s->last_growth = f->now;
          s->growth_seen = true;
          if (startup_probe)
            ++s->startup_probes;
          if (s->drain.phase == DRAIN_OBSERVING)
            reason |=
                end_drain(s, f->now, TRANSPORT_GROUP_CC_REASON_DRAIN_CLEAR);
          s->drain.needs_growth = false;
        }
      }
    }
  }
  if (f->lost_packets) {
    reason |= QUICLY_FLEXICAST_CC_REASON_LOSS;
    bool loss_calm = fresh_rtt && !queued && m->rising == 0 && post_cut;
    if ((usable || !explicit_delivery ||
         (f->delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_MIXED)) &&
        (stable || rtt_calm || loss_calm) && !queued && !f->ecn_ce_count &&
        current_loss <= (PPM * 3U) / 4U) {
      if (new_loss) {
        m->loss_candidate =
            (uint32_t)(((uint64_t)m->loss_candidate * m->loss_epochs +
                        current_loss) /
                       (m->loss_epochs + 1));
        if (++m->loss_epochs >= 3) {
          m->loss_baseline = m->loss_candidate;
          m->loss_epochs = 0;
        }
      } else {
        m->loss_baseline = (m->loss_baseline * 7 + current_loss) / 8;
        m->loss_epochs = 0;
      }
    }
  } else if (usable && m->loss_baseline) {
    m->loss_baseline = m->loss_baseline * 15 / 16;
  }
  output(s, f->member_id, reason, true);
}

static void timed_out(quicly_flexicast_cc_t *cc, int64_t now) {
  group_mcbbr_t *s = (group_mcbbr_t *)cc;
  uint32_t reason = expire_drain(s, now);
  if (s->active && now >= s->next_timeout && now > s->last_timeout) {
    uint64_t wait = control_flight(s, now);
    s->last_timeout = now;
    reason |= QUICLY_FLEXICAST_CC_REASON_TIMEOUT;
    if (++s->unanswered >= 3) {
      timeout_cut(s, s->rate / 2, now, wait);
      s->unanswered = 0;
    }
    s->next_timeout = after(now, wait);
  }
  output(s, 0, reason, true);
}

quicly_flexicast_cc_type_t transport_group_cc_mcbbr = {
    .name = "mcbbr",
    .on_member_added = added,
    .on_member_removed = removed,
    .on_member_suspended = suspended,
    .on_epoch_reset = epoch_reset,
    .on_feedback = feedback_received,
    .on_timeout = timed_out};

bool transport_group_cc_mcbbr_is(const quicly_flexicast_cc_t *cc) {
  return cc != NULL && cc->type == &transport_group_cc_mcbbr;
}

uint64_t transport_group_cc_mcbbr_burst_bytes(const quicly_flexicast_cc_t *cc) {
  if (!transport_group_cc_mcbbr_is(cc))
    return 0;
  return ((const group_mcbbr_t *)cc)->burst_bytes;
}

quicly_flexicast_cc_t *
transport_group_cc_mcbbr_new(const quicly_flexicast_cc_config_t *config,
                             int64_t now) {
  if (!config)
    return NULL;
  group_mcbbr_t *s = calloc(1, sizeof(*s));
  if (!s)
    return NULL;
  if (quicly_flexicast_cc_init(&s->super, &transport_group_cc_mcbbr, config) !=
      0) {
    free(s);
    return NULL;
  }
  s->config = s->super.config;
  s->peers = calloc(s->config.maximum_members, sizeof(*s->peers));
  if (!s->peers) {
    free(s);
    return NULL;
  }
  s->rate = s->config.startup_rate_bytes_per_second;
  s->next_timeout = after(now, s->config.feedback_timeout_msec);
  output(s, 0, 0, false);
  quicly_flexicast_cc_normalize_output(&s->super);
  return &s->super;
}

void transport_group_cc_mcbbr_free(quicly_flexicast_cc_t *cc) {
  if (!transport_group_cc_mcbbr_is(cc))
    return;
  group_mcbbr_t *s = (group_mcbbr_t *)cc;
  free(s->peers);
  free(s);
}

void transport_group_cc_mcbbr_set_hints(quicly_flexicast_cc_t *cc,
                                        const transport_group_cc_hints_t *h,
                                        int64_t now) {
  if (!transport_group_cc_mcbbr_is(cc) || !h)
    return;
  group_mcbbr_t *s = (group_mcbbr_t *)cc;
  uint32_t reason = TRANSPORT_GROUP_CC_REASON_HINT | expire_drain(s, now);
  bool fresh =
      h->external_load_epoch != 0 && h->external_load_epoch > s->load_epoch;
  transport_group_cc_hints_t prev = s->hints;
  s->hints = *h;
  if ((h->external_load_epoch != 0 && !fresh) ||
      (h->external_load_epoch == 0 && s->load_epoch != 0)) {
    /* ignore stale or unnumbered external-load fields while keeping hints */
    s->hints.external_load_epoch = prev.external_load_epoch;
    s->hints.external_load_queued_bytes = prev.external_load_queued_bytes;
    s->hints.external_load_oldest_age_msec = prev.external_load_oldest_age_msec;
    s->hints.external_load_fraction_ppm = prev.external_load_fraction_ppm;
  }
  if (!s->growth_seen && !s->cut_seen && s->bbr_phase == BBR_STARTUP &&
      h->active_senders >= 2 && !h->aggregate_rate_limit_bytes_per_second &&
      s->config.startup_rate_bytes_per_second > 2000) {
    uint64_t share = channel_share_rate(s);
    if (share < s->rate)
      s->rate = bound_config(s, share);
  }
  s->super.config.minimum_rate_bytes_per_second =
      (h->aggregate_rate_limit_bytes_per_second &&
       h->aggregate_rate_limit_bytes_per_second <
           s->config.minimum_rate_bytes_per_second)
          ? h->aggregate_rate_limit_bytes_per_second
          : s->config.minimum_rate_bytes_per_second;
  if (h->aggregate_rate_limit_bytes_per_second &&
      s->rate > h->aggregate_rate_limit_bytes_per_second) {
    reason |= TRANSPORT_GROUP_CC_REASON_RATE_LIMIT;
  }
  bool overloaded = h->external_load_queued_bytes ||
                    h->external_load_oldest_age_msec ||
                    h->external_load_fraction_ppm > 100000;
  if (fresh) {
    s->load_epoch = h->external_load_epoch;
    if (overloaded) {
      s->load_seen = true;
      s->clear_load_epochs = 0;
    } else if (s->load_seen && ++s->clear_load_epochs >= 3) {
      s->load_seen = false;
      s->clear_load_epochs = 0;
    }
  } else if (h->external_load_epoch == 0 && s->load_epoch == 0 && overloaded) {
    s->load_seen = true;
    s->clear_load_epochs = 0;
  }
  if (external(s))
    reason |= TRANSPORT_GROUP_CC_REASON_EXTERNAL_LOAD;
  output(s, 0, reason, true);
  quicly_flexicast_cc_normalize_output(&s->super);
}

bool transport_group_cc_mcbbr_get_stats(const quicly_flexicast_cc_t *cc,
                                        transport_group_cc_stats_t *stats) {
  if (!transport_group_cc_mcbbr_is(cc) || !stats)
    return false;
  const group_mcbbr_t *s = (const group_mcbbr_t *)cc;
  *stats = s->stats;
  return true;
}

bool transport_group_cc_mcbbr_get_trace_state(
    const quicly_flexicast_cc_t *cc, uint64_t id, int64_t now,
    transport_group_cc_trace_state_t *t) {
  if (!transport_group_cc_mcbbr_is(cc) || !t)
    return false;
  const group_mcbbr_t *s = (const group_mcbbr_t *)cc;
  memset(t, 0, sizeof(*t));
  t->available = 1;
  t->control_epoch = now < 0 ? 0 : (uint64_t)now / interval(s) + 1;
  t->last_reduction_at = s->last_cut;
  t->last_growth_at = s->last_growth;
  t->last_reduction_epoch =
      s->cut_seen ? (uint64_t)s->last_cut / interval(s) + 1 : 0;
  t->last_growth_epoch =
      s->growth_seen ? (uint64_t)s->last_growth / interval(s) + 1 : 0;
  t->growth_blocked_until = s->blocked_until;
  t->next_timeout = s->next_timeout;
  t->unanswered_probes = s->unanswered;
  t->external_load = external(s);
  t->control_interval_msec = interval(s);
  t->drain_phase = s->drain.phase;
  t->drain_member_id = s->drain.member_id;
  t->drain_ceiling_bytes_per_second = s->drain.ceiling;
  t->drain_target_bytes_per_second = s->drain.target;
  t->drain_started_at = s->drain.started_at;
  t->drain_deadline = s->drain.deadline;
  t->drain_ended_at = s->drain.ended_at;
  if (!id)
    return true;
  for (size_t i = 0; i < s->config.maximum_members; i++)
    if (s->peers[i].id == id) {
      const mcbbr_peer_t *m = &s->peers[i];
      t->member_present = 1;
      t->last_feedback_epoch = m->feedback_epoch;
      t->last_rtt_sample_epoch = m->rtt_epoch;
      t->last_delivery_sample_epoch = m->delivery_epoch;
      t->previous_rtt = m->rtt;
      t->previous_rtt_at = m->rtt_at;
      t->minimum_rtt = m->minimum_rtt;
      t->rising_delay_epochs = m->rising;
      t->baseline_delivery_ratio_ppm = m->clean_ratio;
      t->recent_delivery_ratio_ppm = t->delivery_sample_ratio_ppm =
          m->recent_ratio;
      t->recent_delivery_rate = m->recent_delivery;
      t->expected_delivery_rate = m->expected_delivery;
      t->degraded_delivery_epochs = m->degraded;
      t->baseline_loss_ppm = m->loss_baseline;
      t->delivery_ceiling_bytes_per_second = m->ceiling;
      t->delivery_ceiling_eligible = m->capacity_eligible;
      t->delivery_sample_post_cut = m->capacity_post_cut;
      break;
    }
  return true;
}
