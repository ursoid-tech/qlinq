#ifndef QLINQ_EMCON_RATELESS_H
#define QLINQ_EMCON_RATELESS_H

#include "emcon_manifest.h"
#include "transport_wire.h"

#include "quicly/flexicast.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct qlinq_emcon_ingress_t qlinq_emcon_ingress_t;
typedef struct qlinq_emcon_receiver_t qlinq_emcon_receiver_t;
typedef struct qlinq_emcon_sender_t qlinq_emcon_sender_t;

#define QLINQ_EMCON_MAX_ACTIVE_OBJECTS 16U
#define QLINQ_EMCON_COMPLETED_OBJECTS 64U
#define QLINQ_EMCON_MAX_PACKET_SIZE QUICLY_FLEXICAST_MAX_PACKET_SIZE

typedef bool (*qlinq_emcon_emit_packet_cb)(void *user_data,
                                           uint16_t symbol_index,
                                           const uint8_t *packet,
                                           size_t packet_size);

typedef struct {
  uint8_t alias;
  uint64_t group_id;
  uint64_t object_id;
  bool keyframe;
  uint8_t priority;
  uint8_t *data;
  size_t size;
} qlinq_emcon_record_t;

typedef enum {
  QLINQ_EMCON_EVENT_NONE = 0,
  QLINQ_EMCON_EVENT_RECORD,
  QLINQ_EMCON_EVENT_END
} qlinq_emcon_event_type_t;

typedef struct {
  qlinq_emcon_event_type_t type;
  union {
    qlinq_emcon_record_t record;
    qlinq_wire_track_end_t end;
  } value;
} qlinq_emcon_event_t;

/* sender owns egress keys and a pre-sized FEC slab bound to manifest limits */
int qlinq_emcon_sender_create(
    qlinq_emcon_sender_t **sender, uint64_t flow_id, uint32_t key_epoch,
    const uint8_t manifest_digest[QLINQ_EMCON_MANIFEST_DIGEST_SIZE],
    uint64_t next_packet_number, uint16_t symbol_size, uint16_t repair_symbols,
    uint32_t max_record_size, const uint8_t *traffic_secret,
    size_t traffic_secret_size);
void qlinq_emcon_sender_free(qlinq_emcon_sender_t *sender);
uint64_t
qlinq_emcon_sender_next_packet_number(const qlinq_emcon_sender_t *sender);
bool qlinq_emcon_sender_has_capacity(const qlinq_emcon_sender_t *sender,
                                     uint64_t packets);

/* creates manifest-bound epoch ingress protection backed by quicly flexicast */
int qlinq_emcon_ingress_create(
    qlinq_emcon_ingress_t **ingress, uint64_t flow_id, uint32_t key_epoch,
    const uint8_t manifest_digest[QLINQ_EMCON_MANIFEST_DIGEST_SIZE],
    uint64_t max_authentication_failures, const uint8_t *traffic_secret,
    size_t traffic_secret_size);
void qlinq_emcon_ingress_free(qlinq_emcon_ingress_t *ingress);
uint64_t qlinq_emcon_ingress_authentication_failures(
    const qlinq_emcon_ingress_t *ingress);

int qlinq_emcon_flexicast_seal(qlinq_emcon_sender_t *sender,
                               ptls_iovec_t payload, uint8_t *packet,
                               size_t capacity, size_t *packet_size,
                               uint64_t *packet_number);
int qlinq_emcon_seal_end(qlinq_emcon_sender_t *sender, uint8_t alias,
                         uint64_t group_id, uint64_t final_object_id,
                         uint8_t *packet, size_t capacity, size_t *packet_size,
                         uint64_t *packet_number);
int qlinq_emcon_flexicast_open(qlinq_emcon_ingress_t *ingress, uint8_t *packet,
                               size_t packet_size, ptls_iovec_t *datagram,
                               uint64_t *packet_number);

/* emits one flexicast protected packet per source or repair symbol */
int qlinq_emcon_send_object(qlinq_emcon_sender_t *sender, uint8_t alias,
                            uint64_t group_id, uint64_t object_id,
                            bool keyframe, uint8_t priority, const void *data,
                            size_t size, qlinq_emcon_emit_packet_cb emit,
                            void *user_data);

qlinq_emcon_receiver_t *qlinq_emcon_receiver_create(uint8_t alias,
                                                    uint16_t symbol_size,
                                                    uint16_t repair_symbols,
                                                    uint32_t max_record_size);
void qlinq_emcon_receiver_free(qlinq_emcon_receiver_t *receiver);

int qlinq_emcon_datagram_target(ptls_iovec_t datagram, uint8_t *alias,
                                uint64_t *group_id);
int qlinq_emcon_receiver_ingest(qlinq_emcon_receiver_t *receiver,
                                uint64_t packet_number, ptls_iovec_t datagram,
                                qlinq_emcon_event_t *event);
void qlinq_emcon_record_release(qlinq_emcon_record_t *record);
void qlinq_emcon_event_release(qlinq_emcon_event_t *event);

#endif
