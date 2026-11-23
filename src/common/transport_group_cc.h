#ifndef QLINQ_TRANSPORT_GROUP_CC_H
#define QLINQ_TRANSPORT_GROUP_CC_H

#include "quicly/flexicast_cc.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TRANSPORT_GROUP_CC_REASON_HINT 0x0020U
#define TRANSPORT_GROUP_CC_REASON_RATE_LIMIT 0x0040U
#define TRANSPORT_GROUP_CC_REASON_EXTERNAL_LOAD 0x0080U
#define TRANSPORT_GROUP_CC_REASON_GROWTH_FROZEN 0x0100U
#define TRANSPORT_GROUP_CC_REASON_DRAIN_ENTER 0x0200U
#define TRANSPORT_GROUP_CC_REASON_DRAIN_CUT 0x0400U
#define TRANSPORT_GROUP_CC_REASON_DRAIN_CLEAR 0x0800U
#define TRANSPORT_GROUP_CC_REASON_DRAIN_EXPIRE 0x1000U

typedef struct {
  uint32_t active_senders;
  uint32_t delivery_rate_divisor;
  uint64_t aggregate_rate_limit_bytes_per_second;
  uint64_t median_sender_rate_bytes_per_second;
  uint64_t external_load_epoch;
  uint64_t external_load_queued_bytes;
  uint64_t external_load_oldest_age_msec;
  uint32_t external_load_fraction_ppm;
} transport_group_cc_hints_t;

typedef struct {
  uint64_t rate_increase_events;
  uint64_t rate_reduction_events;
  uint64_t floor_entry_events;
  uint64_t floor_exit_events;
  uint64_t ack_growth_events;
  uint64_t other_growth_events;
  uint64_t loss_reduction_events;
  uint64_t rtt_reduction_events;
  uint64_t ecn_reduction_events;
  uint64_t timeout_reduction_events;
  uint64_t rate_limit_reduction_events;
  uint64_t other_reduction_events;
  uint64_t external_load_growth_freeze_events;
} transport_group_cc_stats_t;

typedef struct {
  int available;
  uint64_t control_epoch;
  int64_t last_reduction_at;
  int64_t last_growth_at;
  uint64_t last_reduction_epoch;
  uint64_t last_growth_epoch;
  int64_t growth_blocked_until;
  int64_t next_timeout;
  uint32_t unanswered_probes;
  int external_load;
  uint64_t control_interval_msec;
  uint32_t drain_phase;
  uint64_t drain_member_id;
  uint64_t drain_ceiling_bytes_per_second;
  uint64_t drain_target_bytes_per_second;
  int64_t drain_started_at;
  int64_t drain_deadline;
  int64_t drain_ended_at;
  int member_present;
  uint64_t last_feedback_epoch;
  uint64_t last_rtt_sample_epoch;
  uint64_t last_delivery_sample_epoch;
  uint32_t previous_rtt;
  int64_t previous_rtt_at;
  uint32_t minimum_rtt;
  uint32_t rising_delay_epochs;
  uint32_t baseline_delivery_ratio_ppm;
  uint32_t recent_delivery_ratio_ppm;
  uint32_t delivery_sample_ratio_ppm;
  uint64_t recent_delivery_rate;
  uint64_t expected_delivery_rate;
  uint32_t degraded_delivery_epochs;
  uint32_t baseline_loss_ppm;
  uint64_t delivery_ceiling_bytes_per_second;
  int delivery_ceiling_eligible;
  int delivery_sample_post_cut;
} transport_group_cc_trace_state_t;

extern quicly_flexicast_cc_type_t transport_group_cc_mcbbr;

quicly_flexicast_cc_t *
transport_group_cc_mcbbr_new(const quicly_flexicast_cc_config_t *config,
                             int64_t now);
void transport_group_cc_mcbbr_free(quicly_flexicast_cc_t *cc);
bool transport_group_cc_mcbbr_is(const quicly_flexicast_cc_t *cc);
uint64_t transport_group_cc_mcbbr_burst_bytes(const quicly_flexicast_cc_t *cc);
void transport_group_cc_mcbbr_set_hints(quicly_flexicast_cc_t *cc,
                                        const transport_group_cc_hints_t *hints,
                                        int64_t now);
bool transport_group_cc_mcbbr_get_stats(const quicly_flexicast_cc_t *cc,
                                        transport_group_cc_stats_t *stats);
bool transport_group_cc_mcbbr_get_trace_state(
    const quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now,
    transport_group_cc_trace_state_t *state);

#ifdef __cplusplus
}
#endif

#endif
