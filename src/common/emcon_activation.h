#ifndef QLINQ_EMCON_ACTIVATION_H
#define QLINQ_EMCON_ACTIVATION_H

#include "emcon_manifest.h"

#include <stdint.h>

typedef struct qlinq_emcon_activation_t qlinq_emcon_activation_t;

typedef enum {
  QLINQ_EMCON_ACTIVATION_OK = 0,
  QLINQ_EMCON_ACTIVATION_INVALID = -1,
  QLINQ_EMCON_ACTIVATION_IO = -2,
  QLINQ_EMCON_ACTIVATION_LOCKED = -3,
  QLINQ_EMCON_ACTIVATION_CORRUPT = -4,
  QLINQ_EMCON_ACTIVATION_IDENTITY_MISMATCH = -5,
  QLINQ_EMCON_ACTIVATION_EXHAUSTED = -6,
  QLINQ_EMCON_ACTIVATION_REUSED = -7
} qlinq_emcon_activation_result_t;

/* opens and exclusively locks one sender activation file until close */
int qlinq_emcon_activation_open(qlinq_emcon_activation_t **activation,
                                const char *state_file,
                                const qlinq_emcon_manifest_t *manifest);

/* derives one canonical sender state filename from the traffic-key epoch */
int qlinq_emcon_activation_open_managed(qlinq_emcon_activation_t **activation,
                                        const char *state_directory,
                                        const qlinq_emcon_manifest_t *manifest);

/* checks for an existing receiver claim without creating state */
int qlinq_emcon_receiver_activation_check_available(
    const char *state_directory, const qlinq_emcon_manifest_t *manifest);

/* permanently claims one receiver key epoch before packet consumption */
int qlinq_emcon_receiver_activation_claim(
    const char *state_directory, const qlinq_emcon_manifest_t *manifest);

/* durably reserves [first_packet_number, reserved_until) within the epoch */
int qlinq_emcon_activation_reserve(qlinq_emcon_activation_t *activation,
                                   uint64_t minimum_packets,
                                   uint64_t preferred_packets,
                                   uint64_t *first_packet_number,
                                   uint64_t *reserved_until);

void qlinq_emcon_activation_close(qlinq_emcon_activation_t *activation);

#endif
