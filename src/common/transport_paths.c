#include "transport_paths.h"

#include <math.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

static path_t estimate_with_rtt(float rtt_ms, const quicly_path_stats_t *stats,
                                size_t queued_datagrams, size_t egress_bytes,
                                size_t symbol_size, fp_t relative_owd) {
  path_t sample = {.b = FP_FROM_INT(100),
                   .l = FP_FROM_FLOAT(0.050f),
                   .p = FP_FROM_FLOAT(0.01f)};
  if (stats) {
    if (isfinite(rtt_ms) && rtt_ms > 0) {
      fp_t latency = FP_FROM_FLOAT(rtt_ms / 2000.0f);
      sample.l = latency > 0 ? latency : 1;
      if (stats->cwnd > 0 && symbol_size > 0) {
        /* preserve fractional symbols and sub-symbol rates */
        double rate =
            (double)stats->cwnd * 1000.0 / ((double)symbol_size * rtt_ms);
        sample.b = rate >= FP_SAFE_WHOLE
                       ? FP_FROM_INT(FP_SAFE_WHOLE)
                       : (rate * FP_ONE >= 1 ? (fp_t)(rate * FP_ONE) : 1);
      }
    }
    if (stats->sent > 0) {
      uint64_t lost = stats->lost < stats->sent ? stats->lost : stats->sent;
      sample.p = (fp_t)((fp_wide_t)lost * FP_ONE / stats->sent);
    }
  }
  if (relative_owd > 0)
    sample.l = FP_ADD(sample.l, relative_owd);

  /* Quicly's frames are one FEC symbol each (small control frames count
   * conservatively as one). Egress contains serialized UDP payload bytes.
   * The two queues are disjoint; bytes in flight are deliberately excluded. */
  size_t egress_symbols =
      symbol_size == 0
          ? 0
          : egress_bytes / symbol_size + (egress_bytes % symbol_size != 0);
  sample.q =
      queued_datagrams > FP_SAFE_WHOLE ? FP_SAFE_WHOLE : queued_datagrams;
  sample.q += egress_symbols > FP_SAFE_WHOLE - sample.q
                  ? FP_SAFE_WHOLE - sample.q
                  : egress_symbols;
  return sample;
}

path_t transport_path_estimate(const quicly_path_stats_t *stats,
                               size_t queued_datagrams, size_t egress_bytes,
                               size_t symbol_size, fp_t relative_owd) {
  return estimate_with_rtt(stats ? stats->rtt_smoothed : 0, stats,
                           queued_datagrams, egress_bytes, symbol_size,
                           relative_owd);
}

path_t transport_path_estimate_on_path(quicly_conn_t *quic, size_t path_index,
                                       const quicly_path_stats_t *stats,
                                       size_t queued_datagrams,
                                       size_t egress_bytes, size_t symbol_size,
                                       fp_t relative_owd) {
  float rtt_ms = stats ? stats->rtt_smoothed : 0;
  quicly_path_health_t health;
  if (quic && quicly_get_path_health(quic, path_index, &health) == 0 &&
      health.rtt_is_sampled && isfinite(health.rtt_smoothed) &&
      health.rtt_smoothed > 0)
    rtt_ms = health.rtt_smoothed;
  return estimate_with_rtt(rtt_ms, stats, queued_datagrams, egress_bytes,
                           symbol_size, relative_owd);
}

void transport_path_update_state(path_state_t *state, const path_t *sample,
                                 bool periodic) {
  if (!state->initialized || periodic)
    pathflow_update_state(state, sample->b, sample->l, sample->p, sample->q,
                          FP_FROM_FLOAT(0.1f));
  /* An integer EWMA can hide small queues indefinitely and retain a phantom
   * backlog after draining. Keep the existing field name for pathflow. */
  state->q_ewma = sample->q;
}

bool transport_address_equal(const struct sockaddr *a,
                             const struct sockaddr *b) {
  if (!a || !b || a->sa_family != b->sa_family)
    return false;
  if (a->sa_family == AF_INET)
    return ((const struct sockaddr_in *)a)->sin_addr.s_addr ==
           ((const struct sockaddr_in *)b)->sin_addr.s_addr;
  if (a->sa_family == AF_INET6) {
    const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
    const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
    return a6->sin6_scope_id == b6->sin6_scope_id &&
           memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) == 0;
  }
  return false;
}

bool transport_endpoint_equal(const struct sockaddr *a,
                              const struct sockaddr *b) {
  if (!transport_address_equal(a, b))
    return false;
  if (a->sa_family == AF_INET)
    return ((const struct sockaddr_in *)a)->sin_port ==
           ((const struct sockaddr_in *)b)->sin_port;
  return ((const struct sockaddr_in6 *)a)->sin6_port ==
         ((const struct sockaddr_in6 *)b)->sin6_port;
}

bool transport_path_measure(transport_path_measurement_t *m,
                            const quicly_path_stats_t *stats, size_t quic_path,
                            size_t queued_datagrams, uint64_t now_ms) {
  if (!m || !stats)
    return false;
  bool busy = queued_datagrams != 0 ||
              (stats->cwnd != 0 && stats->bytes_in_flight >= stats->cwnd / 2);
  bool reset =
      !m->initialized || m->quic_path != quic_path || now_ms < m->started_ms ||
      stats->acked < m->baseline.acked ||
      stats->bytes_acked < m->baseline.bytes_acked ||
      stats->sent < m->baseline.sent || stats->lost < m->baseline.lost ||
      !transport_endpoint_equal(&stats->local.sa, &m->baseline.local.sa) ||
      !transport_endpoint_equal(&stats->remote.sa, &m->baseline.remote.sa);
  if (reset) {
    memset(m, 0, sizeof(*m));
    m->baseline = *stats;
    m->quic_path = quic_path;
    m->started_ms = now_ms;
    m->minimum_rtt = stats->rtt_smoothed;
    m->busy = busy;
    m->initialized = true;
    return true;
  }
  if (stats->rtt_smoothed &&
      (!m->minimum_rtt || stats->rtt_smoothed < m->minimum_rtt))
    m->minimum_rtt = stats->rtt_smoothed;
  m->busy = m->busy && busy;
  uint64_t window_ms = (uint64_t)stats->rtt_smoothed * 2;
  if (window_ms < 100)
    window_ms = 100;
  if (window_ms > 1000)
    window_ms = 1000;
  uint64_t elapsed = now_ms - m->started_ms;
  if (elapsed < window_ms)
    return false;
  uint64_t sent = stats->sent - m->baseline.sent;
  uint64_t lost = stats->lost - m->baseline.lost;
  if (sent != 0) {
    if (lost > sent)
      lost = sent;
    m->recent_loss = (fp_t)((fp_wide_t)lost * FP_ONE / sent);
    m->loss_sampled = true;
  }
  uint64_t delivered = stats->bytes_acked - m->baseline.bytes_acked;
  fp_wide_t rate = (fp_wide_t)delivered * 1000 / elapsed;
  uint64_t observed = rate > UINT64_MAX ? UINT64_MAX : (uint64_t)rate;
  m->probe_rates[m->probe_cursor] = observed;
  m->probe_times[m->probe_cursor] = now_ms;
  m->probe_cursor = (m->probe_cursor + 1U) % 4U;
  m->baseline = *stats;
  m->started_ms = now_ms;
  m->busy = busy;
  return false;
}

fp_t transport_path_recent_loss(const transport_path_measurement_t *m) {
  return m && m->loss_sampled ? m->recent_loss : FP_FROM_FLOAT(0.01f);
}

fp_t transport_path_probe_cap(const transport_path_measurement_t *m,
                              const quicly_path_stats_t *stats,
                              size_t symbol_size, uint64_t now_ms) {
  fp_t ceiling = FP_FROM_INT(FP_SAFE_WHOLE);
  if (!m || !stats || !m->initialized || !symbol_size || now_ms < m->started_ms)
    return ceiling;
  uint64_t lifetime = (uint64_t)stats->rtt_smoothed * 8;
  if (lifetime < 500)
    lifetime = 500;
  uint64_t peak = 0;
  for (size_t i = 0; i < 4; i++)
    if (now_ms >= m->probe_times[i] && now_ms - m->probe_times[i] <= lifetime &&
        m->probe_rates[i] > peak)
      peak = m->probe_rates[i];
  if (peak == 0)
    return ceiling;
  uint64_t slack = m->minimum_rtt / 8;
  if (slack < 5)
    slack = 5;
  /* Delivery rate is demand-limited on an underused path.  It becomes a
   * capacity ceiling only when the same busy path shows a sustained RTT
   * increase; otherwise preserve the cwnd / RTT estimate so the scheduler can
   * continue probing independent links. */
  if (!m->busy || !m->minimum_rtt ||
      (uint64_t)stats->rtt_smoothed <= m->minimum_rtt + slack)
    return ceiling;
  fp_wide_t cap = (fp_wide_t)peak * FP_ONE / ((fp_wide_t)symbol_size + 80U);
  return cap > ceiling ? ceiling : (cap > 0 ? (fp_t)cap : 1);
}

size_t transport_path_budget_burst(fp_t rate) {
  fp_wide_t symbols =
      ((fp_wide_t)(rate > 0 ? rate : FP_ONE) + 20 * FP_ONE - 1) / (20 * FP_ONE);
  size_t burst = symbols > SIZE_MAX ? SIZE_MAX : (size_t)symbols;
  if (burst < 8)
    burst = 8;
  if (burst > TRANSPORT_PATH_BURST_MAX)
    burst = TRANSPORT_PATH_BURST_MAX;
  return burst;
}

size_t transport_path_budget_update(transport_path_budget_t *budget, fp_t rate,
                                    uint64_t now_ns) {
  if (!budget)
    return SIZE_MAX;
  if (now_ns < budget->at_ns)
    budget->debt = 0;
  fp_wide_t drained = (fp_wide_t)budget->rate *
                      (now_ns >= budget->at_ns ? now_ns - budget->at_ns : 0) /
                      1000000000U;
  budget->debt = drained >= budget->debt ? 0 : budget->debt - (fp_t)drained;
  budget->at_ns = now_ns;
  budget->rate = rate > 0 ? rate : 1;
  return (size_t)((budget->debt + FP_ONE - 1) / FP_ONE);
}

void transport_path_budget_charge(transport_path_budget_t *budget) {
  if (budget)
    budget->debt += FP_ONE;
}

uint64_t transport_path_budget_wait(const transport_path_budget_t *budget,
                                    size_t burst, size_t symbols) {
  if (!budget || symbols > burst)
    return UINT64_MAX;
  fp_t required = FP_FROM_INT(burst - symbols);
  if (budget->debt <= required)
    return 0;
  if (budget->rate <= 0)
    return UINT64_MAX;
  fp_wide_t needed = budget->debt - required;
  fp_wide_t ns = (needed * 1000000000U + budget->rate - 1) / budget->rate;
  return ns > UINT64_MAX ? UINT64_MAX : (uint64_t)ns;
}

bool transport_path_matches_local(const quicly_path_stats_t *stats,
                                  const struct sockaddr_storage *local) {
  return stats && local &&
         transport_address_equal(&stats->local.sa,
                                 (const struct sockaddr *)local);
}

size_t transport_path_find_by_addresses(quicly_conn_t *quic,
                                        const struct sockaddr *local,
                                        const struct sockaddr *remote) {
  if (!quic || !local || !remote)
    return SIZE_MAX;
  for (size_t p = 0; p < TRANSPORT_MAX_QUIC_PATHS; p++) {
    quicly_path_stats_t stats;
    if (quicly_get_path_stats(quic, p, &stats) == 0 &&
        transport_endpoint_equal(&stats.local.sa, local) &&
        transport_endpoint_equal(&stats.remote.sa, remote))
      return p;
  }
  return SIZE_MAX;
}

size_t transport_path_find_by_local(quicly_conn_t *quic,
                                    const struct sockaddr_storage *local) {
  quicly_path_stats_t stats;
  return transport_path_get_stats_by_local(quic, local, &stats);
}

size_t transport_path_get_stats_by_local(quicly_conn_t *quic,
                                         const struct sockaddr_storage *local,
                                         quicly_path_stats_t *stats) {
  if (!quic || !local || !stats)
    return SIZE_MAX;
  for (size_t p = 0; p < TRANSPORT_MAX_QUIC_PATHS; p++) {
    if (quicly_get_path_stats(quic, p, stats) == 0 &&
        transport_path_matches_local(stats, local))
      return p;
  }
  return SIZE_MAX;
}

size_t transport_path_select_physical(const path_t *paths, size_t num_paths,
                                      size_t packet_index) {
  if (!paths || num_paths == 0)
    return SIZE_MAX;
  for (size_t i = 0; i < num_paths; i++) {
    if (packet_index < paths[i].x)
      return i;
    packet_index -= paths[i].x;
  }
  return SIZE_MAX;
}

size_t
transport_path_get_eligible_by_local(quicly_conn_t *quic,
                                     const struct sockaddr_storage *local,
                                     quicly_path_stats_t *stats) {
  if (!quic || !local || !stats)
    return SIZE_MAX;
  for (size_t path = 0; path < TRANSPORT_MAX_QUIC_PATHS; path++) {
    quicly_path_health_t health;
    if (quicly_get_path_stats(quic, path, stats) == 0 &&
        transport_path_matches_local(stats, local) &&
        quicly_is_path_available(quic, path) &&
        (quicly_get_path_health(quic, path, &health) != 0 ||
         health.state != QUICLY_PATH_SUSPECT))
      return path;
  }
  return SIZE_MAX;
}
