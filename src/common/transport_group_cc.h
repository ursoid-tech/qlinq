#ifndef QLINQ_TRANSPORT_GROUP_CC_H
#define QLINQ_TRANSPORT_GROUP_CC_H

#include "quicly/flexicast_cc.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint32_t active_senders;
  uint64_t aggregate_rate_limit_bytes_per_second;
  uint64_t median_sender_rate_bytes_per_second;
} transport_group_cc_hints_t;

typedef struct {
  int64_t growth_blocked_until;
  int member_present;
  uint64_t last_rtt_sample_epoch;
  uint64_t last_delivery_sample_epoch;
  uint32_t previous_rtt;
  uint32_t minimum_rtt;
  uint32_t baseline_delivery_ratio_ppm;
  uint32_t recent_delivery_ratio_ppm;
} transport_group_cc_trace_state_t;

extern quicly_flexicast_cc_type_t transport_group_cc_mcbbr;

quicly_flexicast_cc_t *
transport_group_cc_mcbbr_new(const quicly_flexicast_cc_config_t *config,
                             int64_t now);
void transport_group_cc_mcbbr_free(quicly_flexicast_cc_t *cc);
bool transport_group_cc_mcbbr_is(const quicly_flexicast_cc_t *cc);
uint64_t transport_group_cc_mcbbr_burst_bytes(const quicly_flexicast_cc_t *cc);
/* notify controller when physical submission creates or clears delivery debt */
void transport_group_cc_mcbbr_on_submitted(quicly_flexicast_cc_t *cc,
                                           int64_t now);
void transport_group_cc_mcbbr_on_delivery_clear(quicly_flexicast_cc_t *cc);
void transport_group_cc_mcbbr_set_hints(quicly_flexicast_cc_t *cc,
                                        const transport_group_cc_hints_t *hints,
                                        int64_t now);
bool transport_group_cc_mcbbr_get_trace_state(
    const quicly_flexicast_cc_t *cc, uint64_t member_id,
    transport_group_cc_trace_state_t *state);

#ifdef __cplusplus
}
#endif

#endif
