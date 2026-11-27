#ifndef QLINQ_EMCON_RATELESS_H
#define QLINQ_EMCON_RATELESS_H

#include "emcon_metadata.h"

#include "quicly/flexicast.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct qlinq_emcon_receiver_t qlinq_emcon_receiver_t;
typedef struct qlinq_emcon_sender_t qlinq_emcon_sender_t;

#define QLINQ_EMCON_MAX_ACTIVE_OBJECTS 16U
#define QLINQ_EMCON_COMPLETED_OBJECTS 64U
#define QLINQ_EMCON_MAX_PACKET_SIZE QUICLY_FLEXICAST_MAX_PACKET_SIZE

typedef enum {
  QLINQ_EMCON_RECORD_DATA = 1,
  QLINQ_EMCON_RECORD_SESSION = 2,
  QLINQ_EMCON_RECORD_WINDOW = 3,
  QLINQ_EMCON_RECORD_END = 4,
  QLINQ_EMCON_RECORD_ABORT = 5
} qlinq_emcon_record_type_t;

typedef struct {
  qlinq_emcon_record_type_t type;
  uint64_t packet_number;
  ptls_iovec_t payload; /* borrows mutable packet passed to open */
} qlinq_emcon_message_t;

/* sender owns egress keys and epoch packet-number range */
int qlinq_emcon_sender_create(qlinq_emcon_sender_t **sender, uint64_t flow_id,
                              uint32_t key_epoch,
                              uint64_t initial_packet_number,
                              uint64_t next_packet_number,
                              const uint8_t *traffic_secret,
                              size_t traffic_secret_size);
void qlinq_emcon_sender_free(qlinq_emcon_sender_t *sender);
uint64_t
qlinq_emcon_sender_next_packet_number(const qlinq_emcon_sender_t *sender);
bool qlinq_emcon_sender_has_capacity(const qlinq_emcon_sender_t *sender,
                                     uint64_t packets);
/* creates an epoch-scoped flexicast flow for silent reception */
int qlinq_emcon_flexicast_create(quicly_flexicast_flow_t **flow,
                                 uint64_t flow_id, uint32_t key_epoch,
                                 uint64_t first_packet_number,
                                 const uint8_t *traffic_secret,
                                 size_t traffic_secret_size);
int qlinq_emcon_flexicast_seal(qlinq_emcon_sender_t *sender,
                               qlinq_emcon_record_type_t type,
                               ptls_iovec_t payload, uint8_t *packet,
                               size_t capacity, size_t *packet_size,
                               uint64_t *packet_number);
int qlinq_emcon_flexicast_open(quicly_flexicast_flow_t *flow, uint8_t *packet,
                               size_t packet_size,
                               qlinq_emcon_message_t *message);

typedef enum {
  QLINQ_EMCON_OK = 0,
  QLINQ_EMCON_INCOMPLETE = 1,
  QLINQ_EMCON_DUPLICATE = 2,
  QLINQ_EMCON_DISCARDED = 3,
  QLINQ_EMCON_INVALID = -1,
  QLINQ_EMCON_NO_MEMORY = -2,
  QLINQ_EMCON_CRYPTO = -3,
  QLINQ_EMCON_CODEC = -4,
  QLINQ_EMCON_EMIT_FAILED = -6,
  QLINQ_EMCON_PACKET_NUMBER_EXHAUSTED = -7
} qlinq_emcon_result_t;

typedef struct {
  uint8_t alias;
  uint16_t symbol_size;
  uint16_t repair_symbols;
} qlinq_emcon_rateless_config_t;

typedef bool (*qlinq_emcon_emit_packet_cb)(void *user_data,
                                           uint16_t symbol_index,
                                           const uint8_t *packet,
                                           size_t packet_size);

/* emits one flexicast protected packet per source or repair symbol */
int qlinq_emcon_send_object(qlinq_emcon_sender_t *sender,
                            const qlinq_emcon_rateless_config_t *config,
                            uint64_t group_id, uint64_t object_id,
                            bool keyframe, uint8_t priority, const void *data,
                            size_t size, qlinq_emcon_emit_packet_cb emit,
                            void *user_data);

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
  QLINQ_EMCON_EVENT_SESSION,
  QLINQ_EMCON_EVENT_WINDOW,
  QLINQ_EMCON_EVENT_END,
  QLINQ_EMCON_EVENT_ABORT
} qlinq_emcon_event_type_t;

typedef struct {
  qlinq_emcon_event_type_t type;
  union {
    qlinq_emcon_record_t record;
    qlinq_emcon_session_metadata_t session;
    qlinq_emcon_window_metadata_t window;
    qlinq_emcon_end_metadata_t end;
    qlinq_emcon_abort_metadata_t abort;
  } value;
} qlinq_emcon_event_t;

/* creates an alias assembler bounded by the stream's maximum record size */
qlinq_emcon_receiver_t *qlinq_emcon_receiver_create(uint8_t alias,
                                                    uint32_t max_record_size);
void qlinq_emcon_receiver_free(qlinq_emcon_receiver_t *receiver);

int qlinq_emcon_receiver_ingest_message(qlinq_emcon_receiver_t *receiver,
                                        const qlinq_emcon_message_t *message,
                                        qlinq_emcon_event_t *event);
void qlinq_emcon_record_release(qlinq_emcon_record_t *record);
void qlinq_emcon_event_release(qlinq_emcon_event_t *event);

#endif
