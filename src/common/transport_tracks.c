#include "transport_tracks.h"

#include <string.h>

bool transport_track_type_valid(uint8_t type) {
  return type == MOQ_TRACK_VIDEO || type == MOQ_TRACK_AUDIO ||
         type == MOQ_TRACK_INPUT || type == MOQ_TRACK_TEXT ||
         type == MOQ_TRACK_DATA || type == MOQ_TRACK_TELEMETRY;
}

transport_track_profile_t
transport_track_profile_resolve(const moq_track_id_t *track,
                                const qlinq_effective_repair_policy_t *policy) {
  if (!track)
    return (transport_track_profile_t){0};
  bool reliable = (track->flags & MOQ_TRACK_FLAG_RELIABLE) != 0;
  bool fec_enabled = (track->flags & MOQ_TRACK_FLAG_FEC_ENABLED) != 0;
  bool fec_rateless = (track->flags & MOQ_TRACK_FLAG_FEC_RATELESS) != 0;
  bool any_fec = !reliable && (fec_enabled || fec_rateless);
  transport_track_profile_t profile = {
      .reliable = reliable,
      .fec_enabled = fec_enabled,
      .fec_rateless = fec_rateless,
      .proactive_fec = !reliable && fec_enabled && !fec_rateless,
      .reactive_repair = !reliable && fec_rateless,
      .grouped_records = track->type == MOQ_TRACK_DATA && any_fec,
      .checkpoint_recovery =
          track->type == MOQ_TRACK_DATA && !reliable && fec_rateless};
  if (any_fec && policy && policy->enabled) {
    uint32_t present =
        policy->present ? policy->present : QLINQ_REPAIR_ALL_FIELDS;
    if (present & QLINQ_REPAIR_CONFIDENCE)
      profile.proactive_fec = policy->proactive_confidence > 0;
    else if ((present & QLINQ_REPAIR_MIN_INITIAL) &&
             policy->min_initial_parity_symbols > 0)
      profile.proactive_fec = true;
    if (present & QLINQ_REPAIR_REACTIVE)
      profile.reactive_repair = policy->reactive_repair;
    profile.policy.enabled = true;
    profile.policy.present = present;
    profile.policy.proactive_confidence =
        (present & QLINQ_REPAIR_CONFIDENCE)
            ? policy->proactive_confidence
            : (profile.proactive_fec ? QLINQ_REPAIR_DEFAULT_CONFIDENCE : 0U);
    profile.policy.max_object_age_ms =
        (present & QLINQ_REPAIR_MAX_AGE) ? policy->max_object_age_ms : 0U;
    profile.policy.reactive_repair = profile.reactive_repair;
    profile.policy.max_extra_percent = (present & QLINQ_REPAIR_MAX_EXTRA)
                                           ? policy->max_extra_percent
                                           : QLINQ_REPAIR_MAX_PERCENT;
    profile.policy.max_initial_extra_percent =
        (present & QLINQ_REPAIR_MAX_INITIAL_EXTRA)
            ? policy->max_initial_extra_percent
            : profile.policy.max_extra_percent;
    if (profile.policy.max_initial_extra_percent >
        profile.policy.max_extra_percent)
      profile.policy.max_initial_extra_percent =
          profile.policy.max_extra_percent;
    profile.policy.min_initial_parity_symbols =
        (present & QLINQ_REPAIR_MIN_INITIAL) && profile.proactive_fec
            ? policy->min_initial_parity_symbols
            : 0U;
  }
  return profile;
}

transport_track_profile_t transport_track_profile(const moq_track_id_t *track) {
  return transport_track_profile_resolve(track, NULL);
}

bool transport_track_id_valid(const moq_track_id_t *track) {
  if (!track ||
      strnlen(track->name, sizeof(track->name)) == sizeof(track->name))
    return false;
  if (!transport_track_type_valid((uint8_t)track->type))
    return false;
  const uint8_t valid_flags = MOQ_TRACK_FLAG_RELIABLE |
                              MOQ_TRACK_FLAG_FEC_ENABLED |
                              MOQ_TRACK_FLAG_FEC_RATELESS;
  return (track->flags & ~valid_flags) == 0;
}

bool transport_track_id_equal(const moq_track_id_t *a,
                              const moq_track_id_t *b) {
  return a && b && a->type == b->type && a->flags == b->flags &&
         strcmp(a->name, b->name) == 0;
}
