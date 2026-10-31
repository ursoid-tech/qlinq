#ifndef QLINQ_TRANSPORT_PATHS_H
#define QLINQ_TRANSPORT_PATHS_H

#include "pathflow.h"

#include "quicly.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define TRANSPORT_MAX_QUIC_PATHS 64U
#ifndef TRANSPORT_PATH_BURST_MAX
#define TRANSPORT_PATH_BURST_MAX 64U
#endif

/* Counter windows belong to one QUIC path, rather than its physical socket.
 * They provide recent loss and a per-path ACK-rate lower bound for probing. */
typedef struct {
  quicly_path_stats_t baseline;
  uint64_t started_ms;
  size_t quic_path;
  uint64_t probe_rates[4], probe_times[4];
  size_t probe_cursor;
  uint32_t minimum_rtt;
  fp_t recent_loss;
  bool initialized, busy, loss_sampled;
} transport_path_measurement_t;

bool transport_path_measure(transport_path_measurement_t *measurement,
                            const quicly_path_stats_t *stats, size_t quic_path,
                            size_t queued_datagrams, uint64_t now_ms);
/* cold-start rtt is not a measured propagation baseline */
bool transport_path_measure_on_path(transport_path_measurement_t *measurement,
                                    quicly_conn_t *quic,
                                    const quicly_path_stats_t *stats,
                                    size_t quic_path, size_t queued_datagrams,
                                    uint64_t now_ms);
/* A recent ACK rate is demand-limited on an underused path. It caps the
 * cwnd/RTT estimate only while a busy path has RTT inflation; an absent,
 * stale, or clean-RTT sample deliberately leaves that estimate alone. */
fp_t transport_path_recent_loss(
    const transport_path_measurement_t *measurement);
fp_t transport_path_probe_cap(const transport_path_measurement_t *measurement,
                              const quicly_path_stats_t *stats,
                              size_t symbol_size, uint64_t now_ms);

typedef struct {
  fp_t debt, rate;
  uint64_t at_ns;
} transport_path_budget_t;

/* Limit a path to about 50 ms of scheduler-visible work, while retaining a
 * small cold-start burst and never exceeding the QUIC path queue boundary. */
size_t transport_path_budget_burst(fp_t rate);
/* provide headroom for native paced sender up to measured ceiling */
fp_t transport_path_admission_rate(fp_t estimate, fp_t ceiling);
size_t transport_path_budget_update(transport_path_budget_t *budget, fp_t rate,
                                    uint64_t now_ns);
void transport_path_budget_charge(transport_path_budget_t *budget);
uint64_t transport_path_budget_wait(const transport_path_budget_t *budget,
                                    size_t burst, size_t symbols);

/* Rates are symbol-equivalents/second, latency is seconds, and q counts
 * unsent symbol-equivalents. Missing measurements use independent defaults.
 * The physical egress backlog is shared by all peers using that socket. */
path_t transport_path_estimate(const quicly_path_stats_t *stats,
                               size_t queued_datagrams, size_t egress_bytes,
                               size_t symbol_size, fp_t relative_owd);
/* estimate path using fractional RTT if sampled */
path_t transport_path_estimate_on_path(quicly_conn_t *quic, size_t path_index,
                                       const quicly_path_stats_t *stats,
                                       size_t queued_datagrams,
                                       size_t egress_bytes, size_t symbol_size,
                                       fp_t relative_owd);
/* Smooth rate, latency and loss only on periodic samples. Queue occupancy is
 * always current, including between ticks when another object is published. */
void transport_path_update_state(path_state_t *state, const path_t *sample,
                                 bool periodic);

/* Address identity includes IPv6 scope. Endpoint identity also includes the
 * UDP port; ports do not identify a physical link. */
bool transport_address_equal(const struct sockaddr *a,
                             const struct sockaddr *b);
bool transport_endpoint_equal(const struct sockaddr *a,
                              const struct sockaddr *b);
bool transport_address_is_wildcard(const struct sockaddr *sa);

/* Match the same interface identity as link lookup (IPv6 scope included;
 * transport ports do not identify a physical link). */
bool transport_path_matches_local(const quicly_path_stats_t *stats,
                                  const struct sockaddr_storage *local);

/* Both lookup helpers return SIZE_MAX when no QUIC path matches. */
size_t transport_path_find_by_addresses(quicly_conn_t *quic,
                                        const struct sockaddr *local,
                                        const struct sockaddr *remote);
size_t transport_path_find_by_local(quicly_conn_t *quic,
                                    const struct sockaddr_storage *local);
/* Return the matching path and the statistics already read during lookup.
 * Statistics are valid only when the return value is not SIZE_MAX. */
size_t transport_path_get_stats_by_local(quicly_conn_t *quic,
                                         const struct sockaddr_storage *local,
                                         quicly_path_stats_t *stats);
/* Snapshot an available, non-suspect path belonging to this local address.
 * Returns SIZE_MAX when it is ineligible for new application traffic. */
size_t
transport_path_get_eligible_by_local(quicly_conn_t *quic,
                                     const struct sockaddr_storage *local,
                                     quicly_path_stats_t *stats);

/* SIZE_MAX means the symbol has no allocation; never fall back to path zero. */
size_t transport_path_select_physical(const path_t *paths, size_t num_paths,
                                      size_t packet_index);

#endif
