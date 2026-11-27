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
  QLINQ_EMCON_SESSION_INVALID = -1,
  QLINQ_EMCON_SESSION_NO_MEMORY = -2,
  QLINQ_EMCON_SESSION_CRYPTO = -3,
  QLINQ_EMCON_SESSION_IO = -4,
  QLINQ_EMCON_SESSION_UNKNOWN_ALIAS = -5,
  QLINQ_EMCON_SESSION_EXPIRED = -6,
  QLINQ_EMCON_SESSION_ACTIVATION = -7,
  QLINQ_EMCON_SESSION_ACTIVATION_LOCKED = -8,
  QLINQ_EMCON_SESSION_PACKET_NUMBER_EXHAUSTED = -9,
  QLINQ_EMCON_SESSION_ACTIVATION_REUSED = -10
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

int qlinq_emcon_session_create_sender(qlinq_emcon_session_t **session,
                                      const qlinq_emcon_manifest_t *manifest,
                                      const uint8_t *traffic_secret,
                                      size_t traffic_secret_size,
                                      uint64_t now_ms);
/* Production sender constructor. It durably reserves packet-number ranges and
 * holds an exclusive activation lock for the session lifetime. The state
 * filename is derived inside state_directory from the traffic-key epoch. */
int qlinq_emcon_session_create_sender_persistent(
    qlinq_emcon_session_t **session, const qlinq_emcon_manifest_t *manifest,
    const uint8_t *traffic_secret, size_t traffic_secret_size, uint64_t now_ms,
    const char *state_directory, uint64_t reservation_packets);
int qlinq_emcon_session_create_receiver(qlinq_emcon_session_t **session,
                                        const qlinq_emcon_manifest_t *manifest,
                                        const uint8_t *traffic_secret,
                                        size_t traffic_secret_size,
                                        uint64_t now_ms);
/* Claims the receiver key epoch exactly once before opening its socket.
 * Restart requires a newly provisioned key epoch. */
int qlinq_emcon_session_create_receiver_claimed(
    qlinq_emcon_session_t **session, const qlinq_emcon_manifest_t *manifest,
    const uint8_t *traffic_secret, size_t traffic_secret_size, uint64_t now_ms,
    const char *state_directory);
void qlinq_emcon_session_free(qlinq_emcon_session_t *session);

int qlinq_emcon_session_send_object(qlinq_emcon_session_t *session,
                                    uint8_t alias, uint64_t group_id,
                                    uint64_t object_id, bool keyframe,
                                    uint8_t priority, const void *data,
                                    size_t size);
int qlinq_emcon_session_send_window(
    qlinq_emcon_session_t *session,
    const qlinq_emcon_window_metadata_t *window);
int qlinq_emcon_session_send_end(qlinq_emcon_session_t *session,
                                 const qlinq_emcon_end_metadata_t *end);
int qlinq_emcon_session_send_abort(
    qlinq_emcon_session_t *session,
    const qlinq_emcon_abort_metadata_t *abort_metadata);

int qlinq_emcon_session_receive(qlinq_emcon_session_t *session,
                                qlinq_emcon_event_t *event, bool nonblocking);
qlinq_emcon_session_stats_t
qlinq_emcon_session_stats(const qlinq_emcon_session_t *session);

#endif
