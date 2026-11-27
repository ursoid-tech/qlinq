#ifndef QLINQ_EMCON_SESSION_H
#define QLINQ_EMCON_SESSION_H

#include "emcon_manifest.h"
#include "emcon_rateless.h"
#include "emcon_send_socket.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct qlinq_emcon_session_t qlinq_emcon_session_t;

typedef enum {
  QLINQ_EMCON_SESSION_OK = 0,
  QLINQ_EMCON_SESSION_INCOMPLETE = 1,
  QLINQ_EMCON_SESSION_DUPLICATE = 2,
  QLINQ_EMCON_SESSION_WOULD_BLOCK = 3,
  QLINQ_EMCON_SESSION_DISCARDED = 4,
  QLINQ_EMCON_SESSION_INVALID = -1,
  QLINQ_EMCON_SESSION_NO_MEMORY = -2,
  QLINQ_EMCON_SESSION_CRYPTO = -3,
  QLINQ_EMCON_SESSION_IO = -4,
  QLINQ_EMCON_SESSION_UNKNOWN_ALIAS = -5,
  QLINQ_EMCON_SESSION_EXPIRED = -6,
  QLINQ_EMCON_SESSION_ACTIVATION = -7,
  QLINQ_EMCON_SESSION_ACTIVATION_LOCKED = -8,
  QLINQ_EMCON_SESSION_PACKET_NUMBER_EXHAUSTED = -9,
  QLINQ_EMCON_SESSION_ACTIVATION_REUSED = -10,
  QLINQ_EMCON_SESSION_INTERRUPTED = -11
} qlinq_emcon_session_result_t;

typedef struct {
  uint64_t packets_received;
  uint64_t bytes_received;
  uint64_t authentication_failures;
  uint64_t replay_rejections;
  uint64_t unknown_aliases;
  uint64_t records_completed;
  uint64_t metadata_received;
  uint64_t metadata_sent;
  uint64_t next_packet_number;
  uint64_t reserved_until;
  bool persistent_activation;
  qlinq_emcon_send_stats_t send;
} qlinq_emcon_session_stats_t;

const char *qlinq_emcon_session_strerror(int error);

/* production sender with durable nonce reservations and exclusive lock */
int qlinq_emcon_session_create_sender_persistent(
    qlinq_emcon_session_t **session, const qlinq_emcon_manifest_t *manifest,
    const uint8_t *traffic_secret, size_t traffic_secret_size, uint64_t now_ms,
    const char *state_directory, uint64_t reservation_packets);
/* prepares receiver socket before committing the one-shot epoch claim */
int qlinq_emcon_session_prepare_receiver(
    qlinq_emcon_session_t **session, const qlinq_emcon_manifest_t *manifest,
    const uint8_t *traffic_secret, size_t traffic_secret_size, uint64_t now_ms,
    const char *state_directory, unsigned int interface_index, bool join_group);
int qlinq_emcon_session_claim_receiver(qlinq_emcon_session_t *session);
void qlinq_emcon_session_set_cancel(qlinq_emcon_session_t *session,
                                    qlinq_emcon_cancel_fn should_cancel,
                                    void *cancel_data);
void qlinq_emcon_session_free(qlinq_emcon_session_t *session);

int qlinq_emcon_session_send_object(qlinq_emcon_session_t *session,
                                    uint8_t alias, uint64_t group_id,
                                    uint64_t object_id, bool keyframe,
                                    uint8_t priority, const void *data,
                                    size_t size);
int qlinq_emcon_session_send_end(qlinq_emcon_session_t *session, uint8_t alias,
                                 uint64_t group_id, uint64_t final_object_id);

int qlinq_emcon_session_receive(qlinq_emcon_session_t *session,
                                qlinq_emcon_event_t *event, bool nonblocking);
qlinq_emcon_session_stats_t
qlinq_emcon_session_stats(const qlinq_emcon_session_t *session);

#endif
