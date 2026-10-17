#ifndef QLINQ_TRANSPORT_INTERNAL_H
#define QLINQ_TRANSPORT_INTERNAL_H

#include "ifmon.h"
#include "pathflow.h"
#include "transport.h"
#include "transport_egress.h"
#include "transport_fec_state.h"
#include "transport_memory.h"
#include "transport_paths.h"
#include "transport_repair.h"
#include "transport_subscriptions.h"

#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"

#include <pthread.h>
#include <stdatomic.h>

#define QLINQ_FEC_ASSEMBLER_TIMEOUT_MS 2000
#define QLINQ_FEC_NACK_DELAY_MS 25
#define QLINQ_FEC_COMPLETION_RETRY_MS 500
#define QLINQ_CONNECTION_CACHE_SLOTS 256U
/* Quicly's per-path queue, not its legacy connection-wide 256-frame queue.
 * The publication boundary test verifies this against the linked backend. */
#define QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY 64U
#define QLINQ_COMPLETED_OBJECTS (2U * TRANSPORT_HARD_MAX_ASSEMBLERS)
#define QLINQ_ASSEMBLER_BUCKETS 2048U
#define QLINQ_MIN_ASSEMBLER_WINDOW 8U

typedef struct {
  moq_track_id_t track_id;
  uint64_t next_object_id;
  bool active;
  bool has_objects;
  bool checkpoint_initialized;
  uint64_t checkpoint_group_id;
  uint64_t last_checkpoint_object_id;
} transport_fec_track_state_t;

typedef struct {
  uint8_t *data;
  size_t size, capacity;
  uint64_t started_at_ms;
  moq_track_id_t track_id;
  uint32_t record_count;
  uint8_t priority;
  bool pending; /* Attempted bytes and identity stay fixed until completion. */
} transport_pending_group_t;

/* Physical sockets are shared by all peers. Connection path records use the
 * same socket slot; QUIC path IDs are resolved separately and may differ. */
typedef struct {
  int fd;
  struct sockaddr_storage local_addr;
  socklen_t local_addr_len;
  uint32_t interface_index;
  char interface_name[64];
  uint64_t bytes_received;
  transport_egress_t egress;
  size_t remote_index;
  bool open_pending;
  uint64_t open_retry_at_ms;
} transport_socket_t;

typedef struct {
  path_state_t state;
  transport_path_measurement_t measurement;
  transport_path_budget_t budget;
  int64_t min_owd_ns;
  bool owd_initialized;
  size_t telemetry_path;
  fp_t latest_owd_fp;
  uint64_t last_telemetry_s_ns;
  bool state_overridden;
} transport_conn_path_t;

struct transport_t {
  transport_callback_t callback;
  void *user_data;
  transport_log_callback_t log_callback;
  void *log_user_data;
  bool is_server;
  bool shutting_down;
  bool reconnect_enabled;
  bool reconnect_in_progress;
  uint32_t reconnect_initial_delay_ms;
  uint32_t reconnect_max_delay_ms;
  uint32_t reconnect_current_delay_ms;
  int64_t reconnect_at_ms;
  char server_name[256];
  transport_socket_t sockets[TRANSPORT_MAX_PATHS];
  size_t socket_count;
  uint16_t bind_port; /* Stable while all local interfaces are unavailable. */
  char path_interface_names[TRANSPORT_MAX_PATHS][64];
  size_t num_path_interface_names;
  transport_limits_t limits;
  transport_stats_t stats;
  atomic_uint_fast64_t cross_thread_violations;
  pthread_t owner_thread;
  bool tick_active;
  bool log_callback_active;
  size_t receive_cursor;
  size_t callback_depth;

  struct sockaddr_storage remote_addrs[TRANSPORT_MAX_PATHS];
  size_t num_remote_addrs;
  quicly_context_t quic_ctx;
  ptls_context_t tls_ctx;
  ptls_openssl_sign_certificate_t sign_cert;
  quicly_cid_plaintext_t next_cid;

  uint64_t last_pathflow_update;
  transport_conn_t **conns;
  size_t conn_count;
  uint32_t next_conn_id;
  transport_conn_t *client_conn;
  transport_conn_t *connection_cache[QLINQ_CONNECTION_CACHE_SLOTS];

  quicly_stream_open_t stream_open;
  ptls_openssl_verify_certificate_t verifier;
  bool verifier_initialized;
  quicly_receive_datagram_frame_t receive_datagram;

  transport_sent_cache_t sent_cache;
  transport_repair_mode_t repair_mode;
  transport_repair_limiter_t aggregate_repair_limiter;
  transport_repair_limiter_t aggregate_nack_limiter;
  int64_t aggregate_nack_retry_at_ms;
  size_t recovery_conn_cursor;
  uint32_t fec_assembler_timeout_ms;
  uint8_t simulated_loss_rate;
  arena_t arena;

  transport_pending_group_t pending_group;
  transport_fec_track_state_t fec_tracks[TRANSPORT_HARD_MAX_SUBSCRIPTIONS];

  ifmon_watcher_t ifmon_w;
  int ifmon_pipe[2];
  transport_fec_cache_t fec_cache;
  size_t assembler_memory_bytes;
};

struct transport_conn_t {
  transport_t *transport;
  quicly_conn_t *quic;
  uint32_t id;
  transport_subscription_table_t send_subscriptions;
  transport_subscription_table_t receive_subscriptions;
  bool quic_ready;
  bool hello_sent;
  bool hello_received;
  bool protocol_ready;
  bool connected_emitted;
  bool authenticated;
  bool fec_group_delivered; /* This peer accepted the current grouped object. */
  uint32_t peer_capabilities;
  transport_limits_t negotiated_limits;
  uint64_t stream_frames_received;
  uint64_t datagrams_received;
  uint64_t malformed_datagrams;

  quicly_stream_t *stream;
  frame_assembler_t assemblers[TRANSPORT_HARD_MAX_ASSEMBLERS];
  size_t assembler_index;
  size_t assembler_limit;
  size_t assembler_count;
  uint64_t assembler_rx_rate;
  uint64_t assembler_rx_window_started_ms;
  size_t assembler_rx_window_bytes;
  uint64_t active_assemblers[(TRANSPORT_HARD_MAX_ASSEMBLERS + 63U) / 64U];
  uint16_t assembler_buckets[QLINQ_ASSEMBLER_BUCKETS];
  struct {
    uint64_t generation, group_id, object_id;
    uint8_t alias;
    bool active;
    uint16_t hash_next;
  } completed_objects[QLINQ_COMPLETED_OBJECTS];
  size_t completed_cursor;
  uint16_t completed_buckets[QLINQ_ASSEMBLER_BUCKETS];
  transport_conn_path_t paths[TRANSPORT_MAX_PATHS];
  uint64_t admission_retry_at_ns;
  pathflow_context_t scheduler_context;
  size_t round_robin_path;
  size_t feedback_path;
  /* Owned QUIC slots refreshed once per service pass, not per packet batch. */
  uint64_t scheduler_paths;
  uint8_t scheduler_sockets[TRANSPORT_MAX_QUIC_PATHS];
  transport_repair_limiter_t repair_request_limiter;
  transport_repair_limiter_t nack_request_limiter;
};

static inline size_t transport_connection_count(const transport_t *t) {
  return t->is_server ? t->conn_count : (t->client_conn ? 1U : 0U);
}

static inline transport_conn_t *transport_connection_at(const transport_t *t,
                                                        size_t index) {
  return t->is_server ? t->conns[index] : t->client_conn;
}

/* Master identity is stable across path changes and CID rotation. A cache hit
 * is only a routing hint: the caller must still call quicly_is_destination and
 * quicly_receive. Never use these unauthenticated fields as peer identity. */
static inline transport_conn_t *
transport_connection_cache_find(transport_t *t,
                                const quicly_cid_plaintext_t *cid) {
  transport_conn_t *conn =
      t->connection_cache[cid->master_id % QLINQ_CONNECTION_CACHE_SLOTS];
  if (!conn)
    return NULL;
  const quicly_cid_plaintext_t *master = quicly_get_master_id(conn->quic);
  return master->master_id == cid->master_id &&
                 master->thread_id == cid->thread_id &&
                 master->node_id == cid->node_id
             ? conn
             : NULL;
}

static inline void transport_connection_cache_remember(transport_t *t,
                                                       transport_conn_t *conn) {
  const quicly_cid_plaintext_t *cid = quicly_get_master_id(conn->quic);
  t->connection_cache[cid->master_id % QLINQ_CONNECTION_CACHE_SLOTS] = conn;
}

static inline void transport_connection_cache_forget(transport_t *t,
                                                     transport_conn_t *conn) {
  const quicly_cid_plaintext_t *cid = quicly_get_master_id(conn->quic);
  size_t slot = cid->master_id % QLINQ_CONNECTION_CACHE_SLOTS;
  if (t->connection_cache[slot] == conn)
    t->connection_cache[slot] = NULL;
}

/* State exists only while its alias has a negotiated subscription. Callers
 * must resolve the alias before accessing it; unknown wire aliases are rejected
 * by the protocol parser and never cause an allocation. */
static inline transport_object_gap_state_t *
transport_object_gap(const transport_conn_t *conn, uint8_t alias) {
  transport_subscription_state_t *state =
      transport_subscriptions_get_state(&conn->receive_subscriptions, alias);
  return state ? &state->object_gap : NULL;
}

static inline transport_checkpoint_ack_state_t *
transport_checkpoint_ack(const transport_conn_t *conn, uint8_t alias) {
  transport_subscription_state_t *state =
      transport_subscriptions_get_state(&conn->send_subscriptions, alias);
  return state ? &state->checkpoint_ack : NULL;
}

uint64_t transport_get_time_ns(void);
uint64_t transport_get_monotonic_ns(void);
bool transport_owner_ok(transport_t *t);
void transport_emit_event(transport_t *t, const transport_event_t *event);
void transport_log(transport_t *t, transport_log_level_t level,
                   const char *component, uint32_t connection_id,
                   size_t path_index, const char *format, ...);
size_t transport_next_assembler(const transport_conn_t *conn, size_t first);
size_t transport_receive_bucket(uint8_t alias, uint64_t group, uint64_t object);
frame_assembler_t *transport_find_assembler(transport_conn_t *conn,
                                            uint8_t alias, uint64_t group_id,
                                            uint64_t object_id);
void transport_index_assembler(transport_conn_t *conn, frame_assembler_t *a);
void transport_unindex_assembler(frame_assembler_t *a);
size_t transport_assembler_window(transport_conn_t *conn,
                                  uint16_t total_symbols, uint16_t symbol_size);
void transport_assembler_observe_receive(transport_conn_t *conn,
                                         size_t payload_bytes);
void transport_release_assembler(transport_t *t, frame_assembler_t *assembler);
bool transport_grow_assembler(transport_t *t, frame_assembler_t *assembler,
                              uint16_t symbols, uint16_t symbol_size);
bool transport_queue_datagram(transport_conn_t *conn, size_t path_index,
                              ptls_iovec_t datagram);

#endif
