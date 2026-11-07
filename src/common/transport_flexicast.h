#ifndef QLINQ_TRANSPORT_FLEXICAST_H
#define QLINQ_TRANSPORT_FLEXICAST_H

#include "transport.h"
#include "transport_tracks.h"
#include "transport_wire.h"

#include "quicly/flexicast.h"

#define TRANSPORT_FLEXICAST_MAX_FLOWS 256U
#define TRANSPORT_FLEXICAST_SECRET_SIZE 32U
#define TRANSPORT_FLEXICAST_MISSED_FEEDBACK_WINDOWS 3U
#define TRANSPORT_FLEXICAST_QUEUE_CAPACITY 256U
#define TRANSPORT_FLEXICAST_MEMBER_TRANSITIONS_PER_SECOND 16U
#define TRANSPORT_FLEXICAST_REKEY_HOLDOFF_MS 250

typedef struct transport_flexicast_io {
  uint32_t (*interface_index)(int family, const void *address);
  int (*open)(uint8_t version, uint16_t port);
  int (*membership)(transport_t *, int, uint8_t, const uint8_t *,
                    const uint8_t *, uint32_t, bool);
  void (*close)(int);
  ssize_t (*receive)(transport_t *, size_t, uint8_t *, size_t,
                     transport_conn_t **, ptls_iovec_t *);
} transport_flexicast_io_t;

typedef struct transport_flexicast_member_t {
  transport_conn_t *conn;
  bool joined;
  bool listening;
  bool offer_pending;
  bool reoffer_pending;
  bool rejoining;
  bool offer_bind_sent;
  uint8_t alias; /* subscriber-local alias used in binding */
  uint32_t offer_epoch;
  uint32_t join_epoch_floor; /* rejects controls predating demotion/reoffer */
  quicly_flexicast_announce_frame_t offer_announce;
  bool key_pending; /* retry FC_KEY when control stream is backpressured */
  bool recovery_baseline_pending;
  uint32_t join_sequence; /* epoch carried by active JOIN */
  int64_t transition_window_started_ms;
  uint16_t transitions_in_window;
  uint64_t acknowledged_delivery_epoch;
  int64_t first_unacknowledged_ms; /* zero when no active delivery debt */
  uint64_t payload_delivery_id;
  int64_t ready_deadline_ms;
} transport_flexicast_member_t;

typedef struct transport_flexicast_member_map_entry_t {
  const transport_conn_t *conn;
  size_t slot;
  uint8_t state;
} transport_flexicast_member_map_entry_t;

typedef struct transport_flexicast_queued_payload_t {
  uint8_t *data;
  size_t size;
  /* retain plaintext so unfinished fanout can resume after rekeying */
  uint8_t *packet;
  size_t packet_capacity;
  size_t packet_size;
  uint64_t packet_number;
  uint32_t packet_epoch;
  uint64_t delivery_id;
  size_t next_member;
  bool packet_ready;
  bool replicated;
  bool counted;
} transport_flexicast_queued_payload_t;

typedef struct transport_flexicast_queue_t {
  transport_flexicast_queued_payload_t *entries;
  size_t capacity;
  size_t head;
  size_t count;
  size_t bytes;
} transport_flexicast_queue_t;

typedef struct transport_flexicast_flow_t {
  bool active;
  bool source;
  bool native_multicast;
  bool binding_received;
  bool announcement_received;
  bool join_sent;
  bool multicast_unavailable;
  bool membership_acquired;
  uint8_t ip_version;
  uint8_t alias;
  uint32_t key_epoch;
  uint64_t flow_id;
  moq_track_id_t track_id;
  uint8_t secret[TRANSPORT_FLEXICAST_SECRET_SIZE];
  quicly_flexicast_flow_t *crypto;
  transport_conn_t *control_conn;
  uint8_t source_ip[16];
  uint8_t group_ip[16];
  uint16_t udp_port;
  uint32_t ack_delay_msec;
  uint32_t interface_index;
  transport_flexicast_queue_t data_queue;
  uint64_t pacing_rate_bytes_per_second;
  /* exact rate is numerator / divisor */
  uint64_t pacing_rate_numerator;
  uint32_t pacing_rate_divisor;
  uint64_t pacing_tokens;
  uint64_t pacing_burst_bytes;
  uint64_t pacing_remainder;
  int64_t pacing_last_refill_ms;
  int64_t dispatch_retry_at_ms;
  uint64_t next_payload_delivery_id;
  int64_t last_payload_sent_ms;
  quicly_flexicast_cc_config_t cc_config;
  transport_flexicast_member_t *members;
  transport_flexicast_member_map_entry_t *member_map;
  size_t member_count;
  size_t listening_count;
  size_t feedback_outstanding_count;
  size_t member_capacity;
  size_t member_map_capacity;
  bool rekey_pending;
  int64_t rekey_ready_at_ms;
  uint64_t delivery_epoch;
  struct transport_flexicast_flow_t *hash_next;
} transport_flexicast_flow_t;

typedef struct transport_flexicast_membership_t {
  bool active;
  uint8_t ip_version;
  uint8_t source_ip[16];
  uint8_t group_ip[16];
  uint16_t udp_port;
  uint32_t interface_index;
  size_t references;
} transport_flexicast_membership_t;

typedef struct transport_flexicast_registry_t {
  transport_flexicast_flow_t *flows;
  transport_flexicast_flow_t *flow_buckets[TRANSPORT_FLEXICAST_MAX_FLOWS];
  transport_flexicast_membership_t *memberships;
  size_t capacity;
  size_t active_count;
  size_t member_capacity;
  uint64_t pacing_tokens;
  uint64_t pacing_rate;
  uint64_t pacing_burst;
  uint64_t pacing_remainder;
  int64_t pacing_last_refill_ms;
} transport_flexicast_registry_t;

bool transport_flexicast_registry_init(transport_flexicast_registry_t *registry,
                                       size_t capacity, size_t member_capacity);
void transport_flexicast_dispose(transport_t *t);
bool transport_flexicast_configure(transport_t *t, const char *group,
                                   uint16_t port, const char *interface);

bool transport_flexicast_offer(transport_t *t, transport_conn_t *conn,
                               const moq_track_id_t *track, uint8_t alias);
void transport_flexicast_remove_member(transport_t *t, transport_conn_t *conn,
                                       const moq_track_id_t *track);
void transport_flexicast_unsubscribe(transport_t *t, transport_conn_t *conn,
                                     const moq_track_id_t *track);
void transport_flexicast_remove_connection(transport_t *t,
                                           transport_conn_t *conn);
void transport_flexicast_interface_removed(transport_t *t, uint8_t ip_version,
                                           const uint8_t *address,
                                           uint32_t interface_index);
void transport_flexicast_interface_added(transport_t *t, uint8_t ip_version,
                                         const uint8_t *address,
                                         uint32_t interface_index);

bool transport_flexicast_receive_bind(transport_t *t, transport_conn_t *conn,
                                      const qlinq_wire_flexicast_bind_t *bind);
bool transport_flexicast_receive_path_ack(transport_t *t,
                                          transport_conn_t *conn,
                                          uint64_t flow_id,
                                          const quicly_ack_frame_t *ack);
bool transport_flexicast_receive_quic_frame(
    transport_t *t, transport_conn_t *conn,
    const quicly_flexicast_frame_t *frame);

/* kernel-provided native ingress metadata */
typedef struct {
  uint8_t ip_version;
  uint8_t source_ip[16], group_ip[16];
  uint16_t destination_port;
  uint32_t interface_index;
  bool truncated;
} transport_flexicast_ingress_t;

bool transport_flexicast_native_packet_valid(
    transport_t *, const uint8_t *, size_t,
    const transport_flexicast_ingress_t *);
ssize_t transport_flexicast_receive_native(transport_t *, size_t, uint8_t *,
                                           size_t, transport_conn_t **,
                                           ptls_iovec_t *);
bool transport_flexicast_receive_unicast_ecn(transport_t *, uint8_t *, size_t,
                                             const struct sockaddr *,
                                             transport_conn_t **,
                                             ptls_iovec_t *, uint8_t);
bool transport_flexicast_receive_packet_ecn(transport_t *, uint8_t *, size_t,
                                            transport_conn_t **, ptls_iovec_t *,
                                            uint8_t);

transport_flexicast_flow_t *
transport_flexicast_find_source(transport_t *t, const moq_track_id_t *track);
size_t
transport_flexicast_listening_members(const transport_flexicast_flow_t *flow);
bool transport_flexicast_member_is_listening(
    const transport_flexicast_flow_t *flow, const transport_conn_t *conn);
bool transport_flexicast_can_queue(const transport_t *t,
                                   const transport_flexicast_flow_t *flow,
                                   size_t packets, size_t bytes);
void transport_flexicast_tick(transport_t *t);
int64_t transport_flexicast_get_first_timeout(transport_t *t);
bool transport_flexicast_track_ready(transport_t *t,
                                     const moq_track_id_t *track);
void transport_flexicast_close_socket(transport_t *, int);

void tf_record_delivery_submission(transport_t *, transport_flexicast_flow_t *,
                                   transport_flexicast_member_t *,
                                   bool first_submission);
int64_t tf_member_feedback_deadline(const transport_flexicast_flow_t *,
                                    const transport_flexicast_member_t *);
size_t tf_clear_flow_queue(transport_flexicast_flow_t *flow);
void tf_queue_dispose(transport_flexicast_queue_t *queue);
bool tf_enqueue_payload(transport_t *, transport_flexicast_flow_t *,
                        ptls_iovec_t);
void tf_drain_paced_payloads(transport_t *t, transport_flexicast_flow_t *flow);

#endif
