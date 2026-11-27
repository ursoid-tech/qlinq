#ifndef QLINQ_EMCON_SESSION_H
#define QLINQ_EMCON_SESSION_H

#include "emcon_activation.h"
#include "emcon_manifest.h"
#include "emcon_rateless.h"
#include "emcon_socket.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct qlinq_emcon_session_t qlinq_emcon_session_t;

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

/* creates persistent sender; optional transfer binds (alias, group_id) first */
int qlinq_emcon_session_create_sender(
    qlinq_emcon_session_t **session, const qlinq_emcon_manifest_t *manifest,
    const uint8_t *traffic_secret, size_t traffic_secret_size, uint64_t now_ms,
    const char *state_directory, uint64_t reservation_packets,
    const qlinq_emcon_transfer_t *transfer);

/* prepares receiver socket before committing the one-shot epoch claim */
int qlinq_emcon_session_prepare_receiver(
    qlinq_emcon_session_t **session, const qlinq_emcon_manifest_t *manifest,
    const uint8_t *traffic_secret, size_t traffic_secret_size, uint64_t now_ms,
    const char *state_directory, unsigned int interface_index, bool join_group);
int qlinq_emcon_session_claim_receiver(qlinq_emcon_session_t *session);
int qlinq_emcon_session_set_receive_filter(qlinq_emcon_session_t *session,
                                           uint8_t alias, uint64_t group_id);
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
