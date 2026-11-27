#ifndef QLINQ_EMCON_ACTIVATION_H
#define QLINQ_EMCON_ACTIVATION_H

#include "emcon_manifest.h"

#include <stdbool.h>
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
  QLINQ_EMCON_ACTIVATION_REUSED = -7,
  QLINQ_EMCON_ACTIVATION_TRANSFER_MISMATCH = -8
} qlinq_emcon_activation_result_t;

typedef struct {
  uint8_t alias;
  uint64_t group_id;
  uint32_t block_size;
  uint64_t input_size;
  uint8_t input_digest[QLINQ_EMCON_MANIFEST_DIGEST_SIZE];
  bool resumable;
} qlinq_emcon_transfer_t;

/* derives one canonical sender state filename from the traffic-key epoch and
 * holds an exclusive lock until close */
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

/* checks whether a stream group can be bound or resumed with transfer */
int qlinq_emcon_activation_check_transfer(
    const qlinq_emcon_activation_t *activation,
    const qlinq_emcon_transfer_t *transfer);

/* durably binds (alias, group_id) to its input identity and record size */
int qlinq_emcon_activation_bind_transfer(
    qlinq_emcon_activation_t *activation,
    const qlinq_emcon_transfer_t *transfer);

void qlinq_emcon_activation_close(qlinq_emcon_activation_t *activation);

#endif
