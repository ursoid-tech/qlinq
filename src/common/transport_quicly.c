/* transport_quicly.c */

#include "fec.h"
#include "ifmon.h"
#include "pathflow.h"
#include "portable_sockets.h"
#include "transport.h"
#include "transport_config.h"
#include "transport_egress.h"
#include "transport_fec_state.h"
#include "transport_internal.h"
#include "transport_memory.h"
#include "transport_paths.h"
#include "transport_protocol.h"
#include "transport_recovery.h"
#include "transport_publish.h"
#include "transport_repair.h"
#include "transport_scheduler.h"
#include "transport_stream.h"
#include "transport_subscriptions.h"
#include "transport_tls.h"
#include "transport_tracks.h"
#include "transport_udp.h"
#include "transport_wire.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <net/if.h>
#endif
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/sendstate.h"
#include "quicly/streambuf.h"

#define QLINQ_STREAM_MULTIPATH_SEND_BATCH 32U
#define QLINQ_STREAM_MULTIPATH_GSO_SEGMENTS 6U
#define QLINQ_PATHFLOW_UPDATE_MS 25U
#define QLINQ_GROUP_FLUSH_MS 3U
#define QLINQ_GROUP_FLUSH_RETRY_MS 1U

uint64_t transport_get_time_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

uint64_t transport_get_monotonic_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void monotonic_now_cb(quicly_now_t *self, double *now) {
  (void)self;
  *now = (double)transport_get_monotonic_ns() / 1000000.0;
}
static quicly_now_t transport_monotonic_now = {monotonic_now_cb};

/* Exact identities share hash buckets; collisions never replace live objects.
 * Slot references are offset by one so calloc initializes empty indexes. */
size_t transport_receive_bucket(uint8_t alias, uint64_t group,
                                uint64_t object) {
  uint64_t key =
      object ^ (group * UINT64_C(0x9e3779b97f4a7c15)) ^ ((uint64_t)alias << 56);
  key ^= key >> 30;
  key *= UINT64_C(0xbf58476d1ce4e5b9);
  key ^= key >> 27;
  return (size_t)key & (QLINQ_ASSEMBLER_BUCKETS - 1U);
}

size_t transport_next_assembler(const transport_conn_t *conn, size_t first) {
  if (conn->assembler_count == 0 || first >= TRANSPORT_HARD_MAX_ASSEMBLERS)
    return TRANSPORT_HARD_MAX_ASSEMBLERS;
  size_t word = first / 64U;
  uint64_t bits = conn->active_assemblers[word] & (UINT64_MAX << (first % 64U));
  for (;;) {
    if (bits != 0)
      return word * 64U + (size_t)__builtin_ctzll(bits);
    if (++word ==
        sizeof(conn->active_assemblers) / sizeof(conn->active_assemblers[0]))
      return TRANSPORT_HARD_MAX_ASSEMBLERS;
    bits = conn->active_assemblers[word];
  }
}

frame_assembler_t *transport_find_assembler(transport_conn_t *conn,
                                            uint8_t alias, uint64_t group_id,
                                            uint64_t object_id) {
  size_t bucket = transport_receive_bucket(alias, group_id, object_id);
  for (uint16_t ref = conn->assembler_buckets[bucket]; ref != 0;) {
    frame_assembler_t *a = &conn->assemblers[ref - 1U];
    if (a->track_id == alias && a->group_id == group_id &&
        a->object_id == object_id)
      return a;
    ref = a->hash_next;
  }
  return NULL;
}

void transport_unindex_assembler(frame_assembler_t *a) {
  transport_conn_t *conn = a->owner;
  if (!conn)
    return;
  size_t bucket =
      transport_receive_bucket(a->track_id, a->group_id, a->object_id);
  uint16_t ref = (uint16_t)(a - conn->assemblers + 1U);
  uint16_t *link = &conn->assembler_buckets[bucket];
  while (*link != ref && *link != 0)
    link = &conn->assemblers[*link - 1U].hash_next;
  if (*link == ref) {
    *link = a->hash_next;
    conn->assembler_count--;
    size_t slot = ref - 1U;
    conn->active_assemblers[slot / 64U] &= ~(UINT64_C(1) << (slot % 64U));
  }
  a->owner = NULL;
  a->hash_next = 0;
}

void transport_index_assembler(transport_conn_t *conn, frame_assembler_t *a) {
  size_t bucket =
      transport_receive_bucket(a->track_id, a->group_id, a->object_id);
  a->owner = conn;
  a->hash_next = conn->assembler_buckets[bucket];
  conn->assembler_buckets[bucket] = (uint16_t)(a - conn->assemblers + 1U);
  conn->assembler_count++;
  size_t slot = (size_t)(a - conn->assemblers);
  conn->active_assemblers[slot / 64U] |= UINT64_C(1) << (slot % 64U);
}

/* A receiver observes payload arrival, not the sender's congestion window.
 * Estimate a receive BDP from that rate and its observed path RTTs.  Keep two
 * BDPs plus a small reorder floor, and retain the high-water mark for this
 * connection; reducing the pool while objects are live would induce evictions.
 */
size_t transport_assembler_window(transport_conn_t *conn,
                                  uint16_t total_symbols,
                                  uint16_t symbol_size) {
  if (!conn || !conn->transport || total_symbols == 0 || symbol_size == 0)
    return QLINQ_MIN_ASSEMBLER_WINDOW;
  transport_t *t = conn->transport;
  size_t cap = t->limits.max_assemblers_per_connection;
  size_t minimum =
      cap < QLINQ_MIN_ASSEMBLER_WINDOW ? cap : QLINQ_MIN_ASSEMBLER_WINDOW;
  size_t object_bytes = (size_t)total_symbols * symbol_size;
  uint32_t rtt_ms = 25;
  if (conn->quic) {
    for (size_t i = 0; i < TRANSPORT_MAX_QUIC_PATHS; i++) {
      quicly_path_stats_t stats;
      if (quicly_get_path_stats(conn->quic, i, &stats) == 0 &&
          stats.rtt_smoothed > rtt_ms)
        rtt_ms = stats.rtt_smoothed;
    }
  }
  uint64_t bdp_bytes = conn->assembler_rx_rate > UINT64_MAX / rtt_ms
                           ? UINT64_MAX
                           : conn->assembler_rx_rate * rtt_ms / 1000U;
  uint64_t target = minimum;
  if (bdp_bytes != 0) {
    uint64_t double_bdp =
        bdp_bytes > UINT64_MAX / 2U ? UINT64_MAX : bdp_bytes * 2U;
    target += (double_bdp + object_bytes - 1U) / object_bytes;
  }
  if (target > cap)
    target = cap;
  if (conn->assembler_limit < target)
    conn->assembler_limit = (size_t)target;
  if (conn->assembler_limit < minimum)
    conn->assembler_limit = minimum;
  return conn->assembler_limit;
}

void transport_assembler_observe_receive(transport_conn_t *conn,
                                         size_t payload_bytes) {
  if (!conn || payload_bytes == 0)
    return;
  uint64_t now_ms = (uint64_t)transport_get_time_ms();
  if (conn->assembler_rx_window_started_ms == 0 ||
      now_ms < conn->assembler_rx_window_started_ms) {
    conn->assembler_rx_window_started_ms = now_ms;
    conn->assembler_rx_window_bytes = payload_bytes;
    return;
  }
  if (payload_bytes > SIZE_MAX - conn->assembler_rx_window_bytes)
    conn->assembler_rx_window_bytes = SIZE_MAX;
  else
    conn->assembler_rx_window_bytes += payload_bytes;
  uint64_t elapsed = now_ms - conn->assembler_rx_window_started_ms;
  if (elapsed == 0)
    return;
  uint64_t rate = conn->assembler_rx_window_bytes > UINT64_MAX / 1000U
                      ? UINT64_MAX
                      : conn->assembler_rx_window_bytes * 1000U / elapsed;
  if (rate > conn->assembler_rx_rate)
    conn->assembler_rx_rate = rate;
  /* Bound the observation interval so a later sparse packet cannot dilute
   * the startup delivery measurement that sizes this connection's window. */
  if (elapsed >= 25U) {
    conn->assembler_rx_window_started_ms = now_ms;
    conn->assembler_rx_window_bytes = 0;
  }
}

void transport_release_assembler(transport_t *t, frame_assembler_t *assembler) {
  if (!t || !assembler)
    return;
  transport_unindex_assembler(assembler);
  size_t bytes = transport_assembler_capacity_bytes(assembler);
  if (bytes <= t->assembler_memory_bytes)
    t->assembler_memory_bytes -= bytes;
  else
    t->assembler_memory_bytes = 0;
  transport_assembler_release(assembler);
}

bool transport_grow_assembler(transport_t *t, frame_assembler_t *assembler,
                              uint16_t symbols, uint16_t symbol_size) {
  if (!t || !assembler)
    return false;
  size_t old_bytes = transport_assembler_capacity_bytes(assembler);
  size_t new_bytes = transport_assembler_required_bytes(symbols, symbol_size);
  if (assembler->capacity_symbols > symbols ||
      assembler->capacity_symbol_size > symbol_size) {
    uint16_t actual_symbols = assembler->capacity_symbols > symbols
                                  ? assembler->capacity_symbols
                                  : symbols;
    uint16_t actual_symbol_size = assembler->capacity_symbol_size > symbol_size
                                      ? assembler->capacity_symbol_size
                                      : symbol_size;
    new_bytes =
        transport_assembler_required_bytes(actual_symbols, actual_symbol_size);
  }
  size_t used_without_old = old_bytes <= t->assembler_memory_bytes
                                ? t->assembler_memory_bytes - old_bytes
                                : t->assembler_memory_bytes;
  /* Growth allocates replacement buffers before copying and freeing the old
   * ones. Reserve that transient allocation too; rejecting growth must leave
   * an incomplete object's symbols intact. Reusing capacity allocates nothing.
   */
  bool needs_allocation = !assembler->buffers ||
                          assembler->capacity_symbols < symbols ||
                          assembler->capacity_symbol_size < symbol_size;
  size_t additional_bytes = needs_allocation ? new_bytes : 0;
  if (t->assembler_memory_bytes > t->limits.max_assembler_memory_bytes ||
      additional_bytes >
          t->limits.max_assembler_memory_bytes - t->assembler_memory_bytes) {
    t->stats.resource_limit_errors++;
    return false;
  }
  if (!transport_assembler_grow(assembler, symbols, symbol_size))
    return false;
  t->assembler_memory_bytes =
      used_without_old + transport_assembler_capacity_bytes(assembler);
  return true;
}

bool transport_owner_ok(transport_t *t) {
  if (!t)
    return false;
  if (pthread_equal(t->owner_thread, pthread_self()))
    return !t->log_callback_active;
  atomic_fetch_add_explicit(&t->cross_thread_violations, 1,
                            memory_order_relaxed);
  return false;
}

void transport_emit_event(transport_t *t, const transport_event_t *event) {
  if (!t || !event)
    return;
  t->callback_depth++;
  t->stats.events_emitted++;
  t->callback(t->user_data, event);
  t->callback_depth--;
}

void transport_log(transport_t *t, transport_log_level_t level,
                   const char *component, uint32_t connection_id,
                   size_t path_index, const char *format, ...) {
  if (!t || !component || !format)
    return;
  char message[512];
  va_list args;
  va_start(args, format);
  (void)vsnprintf(message, sizeof(message), format, args);
  va_end(args);
  transport_log_event_t event = {.level = level,
                                 .component = component,
                                 .connection_id = connection_id,
                                 .path_index = path_index,
                                 .message = message};
  if (t->log_callback) {
    t->log_callback_active = true;
    t->log_callback(t->log_user_data, &event);
    t->log_callback_active = false;
  } else if (level >= TRANSPORT_LOG_WARNING) {
    const char *name = level == TRANSPORT_LOG_ERROR ? "error" : "warning";
    if (connection_id != 0 && path_index != SIZE_MAX)
      fprintf(stderr, "qlinq[%s] %s conn=%" PRIu32 " path=%zu: %s\n", component,
              name, connection_id, path_index, message);
    else if (connection_id != 0)
      fprintf(stderr, "qlinq[%s] %s conn=%" PRIu32 ": %s\n", component, name,
              connection_id, message);
    else if (path_index != SIZE_MAX)
      fprintf(stderr, "qlinq[%s] %s path=%zu: %s\n", component, name,
              path_index, message);
    else
      fprintf(stderr, "qlinq[%s] %s: %s\n", component, name, message);
  }
}

static bool transport_has_connection(const transport_t *t,
                                     const transport_conn_t *conn);

static void accumulate_egress_stats(transport_stats_t *stats,
                                    const transport_egress_t *egress,
                                    bool dropping_pending) {
  stats->udp_packets_sent += egress->packets_sent;
  stats->udp_bytes_sent += egress->bytes_sent;
  stats->udp_would_block += egress->would_block;
  stats->udp_send_errors += egress->send_errors;
  stats->egress_packets_queued += egress->packets_queued;
  stats->egress_bytes_queued += egress->bytes_queued;
  stats->egress_packets_dropped +=
      egress->packets_dropped + (dropping_pending ? egress->count : 0U);
  if (egress->peak_count > stats->egress_peak_packets)
    stats->egress_peak_packets = egress->peak_count;
  if (egress->peak_bytes > stats->egress_peak_bytes)
    stats->egress_peak_bytes = egress->peak_bytes;
}

/* Resolve local ownership independently of peer wire IDs. Prefer an empty
 * queue, then the lower RTT; reselect for every repair symbol in a batch. */
size_t transport_select_datagram_path(transport_conn_t *conn) {
  size_t best = SIZE_MAX, best_queued = SIZE_MAX;
  uint32_t best_rtt = UINT32_MAX;
  transport_t *t = conn->transport;
  for (size_t path = 0; path < TRANSPORT_MAX_QUIC_PATHS; path++) {
    quicly_path_stats_t stats;
    quicly_path_health_t health;
    if (!quicly_is_path_available(conn->quic, path) ||
        quicly_get_path_stats(conn->quic, path, &stats) != 0 ||
        (quicly_get_path_health(conn->quic, path, &health) == 0 &&
         health.state == QUICLY_PATH_SUSPECT))
      continue;
    bool owned = false;
    for (size_t physical = 0; physical < t->socket_count; physical++)
      owned |= transport_path_matches_local(&stats,
                                            &t->sockets[physical].local_addr);
    if (!owned)
      continue;
    size_t queued = quicly_get_num_datagram_frames_path(conn->quic, path);
    if (queued < QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY &&
        (queued < best_queued ||
         (queued == best_queued && stats.rtt_smoothed < best_rtt))) {
      best = path;
      best_queued = queued;
      best_rtt = stats.rtt_smoothed;
    }
  }
  return best;
}

bool transport_queue_datagram(transport_conn_t *conn, size_t path_index,
                              ptls_iovec_t datagram) {
  quicly_path_stats_t path_stats;
  if (!conn || !conn->quic || path_index >= TRANSPORT_MAX_QUIC_PATHS ||
      quicly_get_path_stats(conn->quic, path_index, &path_stats) != 0 ||
      quicly_get_num_datagram_frames_path(conn->quic, path_index) >=
          QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY)
    return false;
  size_t before = quicly_get_num_datagram_frames_path(conn->quic, path_index);
  quicly_send_datagram_frames_path(conn->quic, path_index, &datagram, 1);
  size_t after = quicly_get_num_datagram_frames_path(conn->quic, path_index);
  return after == before + 1U;
}

typedef struct {
  uint32_t index;
  char name[64];
  struct sockaddr_storage addr;
  socklen_t addr_len;
  int is_added;
} ifmon_pipe_msg_t;

static void copy_interface_name(char destination[64], const char *name) {
  if (!destination || !name)
    return;
  strncpy(destination, name, 63);
  destination[63] = '\0';
}

static int qlinq_path_is_eligible(quicly_path_scheduler_t *scheduler,
                                  quicly_conn_t *quic, size_t path_index) {
  (void)scheduler;
  transport_conn_t *conn = *(transport_conn_t **)quicly_get_data(quic);
  quicly_tuple_t tuple;
  if (!conn || !conn->transport ||
      quicly_get_path_tuple(quic, path_index, &tuple) != 0)
    return 0;
  transport_t *t = conn->transport;
  for (size_t i = 0; i < t->socket_count; i++)
    if (transport_address_equal(
            (const struct sockaddr *)&t->sockets[i].local_addr,
            &tuple.address.local.sa))
      return 1;
  return 0;
}

static void abandon_removed_paths(transport_conn_t *conn) {
  /* closing a socket must retire its QUIC paths and notify peer */
  for (size_t path = 0; path < TRANSPORT_MAX_QUIC_PATHS; path++) {
    quicly_path_health_t health;
    if (quicly_get_path_health(conn->quic, path, &health) != 0 ||
        health.abandoned || qlinq_path_is_eligible(NULL, conn->quic, path))
      continue;
    (void)quicly_abandon_path(conn->quic, health.path_id,
                              QUICLY_PATH_ABANDON_ERROR_APPLICATION);
  }
}

static void refresh_scheduler_paths(transport_conn_t *conn) {
  transport_t *t = conn->transport;
  conn->scheduler_paths = 0;
  /* The pinned QUIC API has no path iterator. Snapshot slot ownership once
   * before a service pass; each send batch refreshes only these paths' live
   * congestion and health state. Multiple remote paths may share one socket. */
  for (size_t path = 0; path < TRANSPORT_MAX_QUIC_PATHS; path++) {
    quicly_path_stats_t stats;
    if (quicly_get_path_stats(conn->quic, path, &stats) != 0 ||
        !quicly_is_path_available(conn->quic, path))
      continue;
    for (size_t physical = 0; physical < t->socket_count; physical++)
      if (transport_path_matches_local(&stats,
                                       &t->sockets[physical].local_addr)) {
        conn->scheduler_paths |= UINT64_C(1) << path;
        conn->scheduler_sockets[path] = (uint8_t)physical;
        break;
      }
  }
}

static quicly_error_t
qlinq_path_scheduler_send(quicly_path_scheduler_t *scheduler,
                          quicly_conn_t *quic,
                          quicly_send_context_t *send_context) {
  (void)scheduler;
  transport_conn_t *conn = *(transport_conn_t **)quicly_get_data(quic);
  if (!conn || !conn->transport)
    return 0;
  transport_t *t = conn->transport;

  /* Datagram publication has already assigned a QUIC path. Several remote
   * paths can share one local socket. In particular, a listener's telemetry on
   * its second remote path must not remain runnable but permanently unsent. */
  if (quicly_has_datagram_frames(quic)) {
    size_t first = conn->feedback_path % TRANSPORT_MAX_QUIC_PATHS;
    for (size_t offset = 0; offset < TRANSPORT_MAX_QUIC_PATHS; offset++) {
      size_t path = (first + offset) % TRANSPORT_MAX_QUIC_PATHS;
      if ((conn->scheduler_paths & (UINT64_C(1) << path)) == 0 ||
          quicly_get_num_datagram_frames_path(quic, path) == 0 ||
          !quicly_is_path_available(quic, path))
        continue;
      quicly_path_stats_t stats;
      quicly_path_health_t health;
      if (quicly_get_path_stats(quic, path, &stats) != 0 ||
          (quicly_get_path_health(quic, path, &health) == 0 &&
           health.state == QUICLY_PATH_SUSPECT))
        continue;
      size_t packets_sent = 0;
      quicly_error_t ret =
          quicly_send_on_path(quic, send_context, path, &packets_sent);
      if (ret != 0)
        return ret;
      if (packets_sent != 0) {
        conn->feedback_path = (path + 1U) % TRANSPORT_MAX_QUIC_PATHS;
        return 0;
      }
    }
  }

  size_t quic_paths[TRANSPORT_MAX_QUIC_PATHS];
  path_t paths[TRANSPORT_MAX_QUIC_PATHS];
  size_t count = 0;
  bool has_datagrams = quicly_has_datagram_frames(quic);
  bool feedback_only = !quicly_has_pending_stream_data(quic) && !has_datagrams;
  size_t symbol_size = 0;
  if (!feedback_only) {
    symbol_size = transport_get_datagram_symbol_size(t);
    if (symbol_size == 0)
      symbol_size = 1200;
  }

  uint64_t remaining = conn->scheduler_paths;
  while (remaining != 0) {
    size_t path = (size_t)__builtin_ctzll(remaining);
    remaining &= remaining - 1U;
    size_t physical = conn->scheduler_sockets[path];
    quicly_path_health_t health;
    if (!quicly_is_path_available(quic, path) ||
        (quicly_get_path_health(quic, path, &health) == 0 &&
         health.state == QUICLY_PATH_SUSPECT))
      continue;
    /* Feedback uses round-robin selection, so congestion-derived scores do
     * not influence its ordering. Keep the same owned, available, healthy
     * candidates without copying path statistics or calculating estimates. */
    if (feedback_only) {
      quic_paths[count++] = path;
      continue;
    }
    quicly_path_stats_t stats;
    if (quicly_get_path_stats(quic, path, &stats) != 0)
      continue;
    const transport_conn_path_t *physical_path = &conn->paths[physical];
    fp_t relative_owd =
        physical_path->owd_initialized && physical_path->telemetry_path == path
            ? physical_path->latest_owd_fp
            : 0;
    path_t sample = transport_path_estimate_on_path(
        quic, path, &stats, quicly_get_num_datagram_frames_path(quic, path),
        t->sockets[physical].egress.bytes, symbol_size, relative_owd);
    sample.p = transport_path_recent_loss(&physical_path->measurement);
    const path_state_t *state = &physical_path->state;
    if (state->initialized &&
        (physical_path->state_overridden ||
         (physical_path->measurement.initialized &&
          physical_path->measurement.quic_path == path))) {
      /* Delivery-rate EWMA is demand-limited when this path has been
       * underused. Keep the live cwnd / RTT rate for stream scheduling, while
       * retaining conservative history for latency, loss, and queued work. */
      if (state->l_ewma > sample.l)
        sample.l = state->l_ewma;
      if (state->p_ewma > sample.p)
        sample.p = state->p_ewma;
      if (state->q_ewma > sample.q)
        sample.q = state->q_ewma;
    }
    /* Estimate forward-flight pressure using the same symmetric RTT/2
     * assumption as latency; unacknowledged bytes also span the ACK return
     * trip. Quicly still enforces the full congestion window. */
    size_t in_flight = stats.bytes_in_flight / (2 * symbol_size) +
                       (stats.bytes_in_flight % (2 * symbol_size) != 0);
    sample.q = in_flight > FP_SAFE_WHOLE - sample.q ? FP_SAFE_WHOLE
                                                    : sample.q + in_flight;
    /* Quicly emits at most one path per send call.  A stream call can consume
     * a small packet batch, so account for that whole batch when comparing
     * completion times; otherwise each decision charges one packet then sends
     * several and flattens heterogeneous-link scheduling. */
    size_t batch = has_datagrams ? 1U : QLINQ_STREAM_MULTIPATH_SEND_BATCH;
    if (batch > 1U) {
      size_t additional = batch - 1U;
      sample.q = additional > FP_SAFE_WHOLE - sample.q ? FP_SAFE_WHOLE
                                                       : sample.q + additional;
    }
    quic_paths[count] = path;
    paths[count++] = sample;
  }
  if (count == 0)
    return 0;

  /* Reliable streams recover with QUIC retransmission. A one-packet FEC
   * plan can reserve a fictitious parity packet even for tiny loss rates.
   * Use expected transmission cost for both the first choice and fallbacks;
   * Quicly still enforces congestion, pacing, and stream eligibility. */
  size_t feedback_start = conn->feedback_path % count;
  uint64_t attempted_paths = 0;
  for (size_t attempt = 0; attempt < count; attempt++) {
    size_t index =
        feedback_only
            ? (feedback_start + attempt) % count
            : transport_stream_select_path(paths, count, attempted_paths);
    if (index == SIZE_MAX)
      break;
    attempted_paths |= UINT64_C(1)
                       << index; /* do not retry an empty send path */
    size_t packets_sent = 0;
    quicly_error_t ret = quicly_send_on_path(quic, send_context,
                                             quic_paths[index], &packets_sent);
    if (ret != 0)
      return ret;
    if (packets_sent != 0) {
      if (feedback_only)
        conn->feedback_path = (index + 1U) % count;
      break;
    }
  }
  return 0;
}

static quicly_path_scheduler_t qlinq_path_scheduler = {
    .do_send = qlinq_path_scheduler_send,
    .is_path_eligible = qlinq_path_is_eligible};

static socklen_t ifmon_socket_address(struct sockaddr_storage *out,
                                      const ifmon_addr_t *address,
                                      uint32_t interface_index) {
  memset(out, 0, sizeof(*out));
  if (address->family == AF_INET) {
    struct sockaddr_in *v4 = (struct sockaddr_in *)out;
    v4->sin_family = AF_INET;
    v4->sin_addr = address->ip.v4;
    return sizeof(*v4);
  }
  struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)out;
  v6->sin6_family = AF_INET6;
  v6->sin6_addr = address->ip.v6;
  if (IN6_IS_ADDR_LINKLOCAL(&v6->sin6_addr))
    v6->sin6_scope_id = interface_index;
  return sizeof(*v6);
}

static void resolve_configured_interfaces(transport_t *t) {
  ifmon_list_t interfaces = {0};
  uint8_t scratchpad[IFMON_SCRATCHPAD_SIZE];
  if (!t || ifmon_list_get(&interfaces, scratchpad, sizeof(scratchpad)) != 0)
    return;
  for (size_t path = 0; path < t->socket_count; path++) {
    for (int i = 0; i < interfaces.count; i++) {
      const ifmon_iface_t *iface = &interfaces.ifaces[i];
      for (int a = 0; a < iface->addr_count; a++) {
        struct sockaddr_storage address;
        ifmon_socket_address(&address, &iface->addrs[a], iface->index);
        if (!transport_address_equal(
                (const struct sockaddr *)&address,
                (const struct sockaddr *)&t->sockets[path].local_addr))
          continue;
        t->sockets[path].interface_index = iface->index;
        copy_interface_name(t->sockets[path].interface_name, iface->name);
        break;
      }
      if (t->sockets[path].interface_index != 0)
        break;
    }
  }
}

static void bind_to_device(int fd, uint32_t index) {
  if (index == 0)
    return;
#if defined(__linux__)
  char ifname[IF_NAMESIZE];
  if (if_indextoname(index, ifname)) {
    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
  }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
#ifndef IP_BOUND_IF
#define IP_BOUND_IF 25
#endif
#ifndef IPV6_BOUND_IF
#define IPV6_BOUND_IF 125
#endif
  unsigned int idx = index;
  setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx));
  setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx));
#elif defined(_WIN32)
  DWORD idx = index;
  setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, (const char *)&idx, sizeof(idx));
  setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, (const char *)&idx,
             sizeof(idx));
#endif
}

static void on_ifmon_update(const ifmon_update_t *update, void *userdata) {
  transport_t *t = userdata;

  if (update->is_initial) {
    /* For now, ignore initial snapshot since we bind via config->bind_hosts */
    return;
  }

  for (int i = 0; i < update->added_count; i++) {
    uint32_t idx = update->added[i];
    for (int j = 0; j < update->interfaces->count; j++) {
      if (update->interfaces->ifaces[j].index == idx) {
        const ifmon_iface_t *iface = &update->interfaces->ifaces[j];
        for (int k = 0; k < iface->addr_count; k++) {
          const ifmon_addr_t *a = &iface->addrs[k];
          ifmon_pipe_msg_t msg = {0};
          msg.index = idx;
          copy_interface_name(msg.name, iface->name);
          msg.is_added = 1;
          msg.addr_len = ifmon_socket_address(&msg.addr, a, msg.index);
          ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
          (void)w;
        }
        break;
      }
    }
  }

  for (int i = 0; i < update->removed_count; i++) {
    ifmon_pipe_msg_t msg = {0};
    msg.index = update->removed[i];
    msg.is_added = 0;
    msg.addr.ss_family = AF_UNSPEC;
    ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
    (void)w;
  }

  for (int i = 0; i < update->modified_count; i++) {
    const ifmon_iface_diff_t *diff = &update->modified[i];

    if (diff->link_state_changed) {
      for (int k = 0; k < update->interfaces->count; k++) {
        const ifmon_iface_t *iface = &update->interfaces->ifaces[k];
        if (iface->index == diff->index) {
          for (int a_idx = 0; a_idx < iface->addr_count; a_idx++) {
            const ifmon_addr_t *a = &iface->addrs[a_idx];
            ifmon_pipe_msg_t msg = {0};
            msg.index = diff->index;
            copy_interface_name(msg.name, iface->name);
            msg.is_added = diff->is_up ? 1 : 0;
            msg.addr_len = ifmon_socket_address(&msg.addr, a, msg.index);
            ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
            (void)w;
          }
          break;
        }
      }
    }

    for (int j = 0; j < diff->addrs_added_count; j++) {
      const ifmon_addr_t *a = &diff->addrs_added[j];
      ifmon_pipe_msg_t msg = {0};
      msg.index = diff->index;
      msg.is_added = 1;
      for (int k = 0; k < update->interfaces->count; k++) {
        if (update->interfaces->ifaces[k].index == diff->index) {
          copy_interface_name(msg.name, update->interfaces->ifaces[k].name);
          break;
        }
      }
      msg.addr_len = ifmon_socket_address(&msg.addr, a, msg.index);
      ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
      (void)w;
    }

    for (int j = 0; j < diff->addrs_removed_count; j++) {
      const ifmon_addr_t *a = &diff->addrs_removed[j];
      ifmon_pipe_msg_t msg = {0};
      msg.index = diff->index;
      msg.is_added = 0;
      for (int k = 0; k < update->interfaces->count; k++) {
        if (update->interfaces->ifaces[k].index == diff->index) {
          copy_interface_name(msg.name, update->interfaces->ifaces[k].name);
          break;
        }
      }
      msg.addr_len = ifmon_socket_address(&msg.addr, a, msg.index);
      ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
      (void)w;
    }
  }
}

static bool set_fd_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static int open_unicast_socket(int family) {
  int fd = socket(family, SOCK_DGRAM, 0);
  if (fd >= 0 && family == AF_INET6) {
    /* A wildcard IPv6 path must not claim a separately configured IPv4 path's
     * port. Each physical socket and its address matching stay family-specific.
     */
    int v6_only = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof(v6_only)) !=
        0) {
      CLOSE_SOCKET(fd);
      return -1;
    }
  }
  if (fd >= 0)
    (void)transport_udp_enable_recv_ecn(fd, family);
  return fd;
}

static void configure_socket_buffers(transport_t *t, int fd) {
  int buf_size = 2 * 1024 * 1024; /* 2mb buffer size */
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) != 0)
    transport_log(t, TRANSPORT_LOG_WARNING, "udp", 0, SIZE_MAX,
                  "unable to enlarge send buffer: %s", strerror(errno));
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) != 0)
    transport_log(t, TRANSPORT_LOG_WARNING, "udp", 0, SIZE_MAX,
                  "unable to enlarge receive buffer: %s", strerror(errno));
}

static void set_address_port(struct sockaddr_storage *address, uint16_t port) {
  if (address->ss_family == AF_INET)
    ((struct sockaddr_in *)address)->sin_port = htons(port);
  else
    ((struct sockaddr_in6 *)address)->sin6_port = htons(port);
}

static bool parse_address(const char *host, uint16_t port,
                          struct sockaddr_storage *address, socklen_t *length) {
  memset(address, 0, sizeof(*address));
  void *ip;
  if (strchr(host, ':')) {
    address->ss_family = AF_INET6;
    ip = &((struct sockaddr_in6 *)address)->sin6_addr;
    *length = sizeof(struct sockaddr_in6);
  } else {
    address->ss_family = AF_INET;
    ip = &((struct sockaddr_in *)address)->sin_addr;
    *length = sizeof(struct sockaddr_in);
  }
  set_address_port(address, port);
  return inet_pton(address->ss_family, host, ip) == 1;
}

static void destroy_socket(transport_socket_t *socket) {
  transport_udp_gro_destroy(socket->gro);
  if (socket->fd >= 0)
    CLOSE_SOCKET(socket->fd);
  transport_egress_destroy(&socket->egress);
  *socket = (transport_socket_t){.fd = -1, .remote_index = SIZE_MAX};
}

/* Install a socket only when its descriptor and egress queue are both ready.
 * Unicast tuples stay exclusive: SO_REUSEADDR can let a later endpoint steal
 * an earlier endpoint's QUIC replies, even for bind(port=0) on Linux. */
static const char *open_local_socket(transport_t *t,
                                     transport_socket_t *socket) {
  const char *error = "socket creation failed";
  int saved_errno;
  socket->fd = open_unicast_socket(socket->local_addr.ss_family);
  if (socket->fd < 0)
    goto Fail;
  error = "socket bind failed";
  if (bind(socket->fd, (struct sockaddr *)&socket->local_addr,
           socket->local_addr_len) != 0)
    goto Fail;
  configure_socket_buffers(t, socket->fd);
  error = "failed to make socket nonblocking";
  if (!set_fd_nonblocking(socket->fd))
    goto Fail;
  error = "failed to allocate socket egress queue";
  if (!transport_egress_init(&socket->egress,
                             t->limits.max_egress_packets_per_socket,
                             t->limits.max_egress_bytes_per_socket))
    goto Fail;
  /* Optional per-socket storage is allocated before enabling UDP_GRO. An
   * unsupported socket or allocation failure retains the stateless path. */
  socket->gro = transport_udp_gro_create(socket->fd);
  return NULL;

Fail:
  saved_errno = errno;
  destroy_socket(socket);
  errno = saved_errno;
  return error;
}

#define QLINQ_PATH_OPEN_RETRY_MS 100U

static bool path_endpoint_families_match(const transport_t *t,
                                         size_t local_index,
                                         size_t remote_index) {
  return local_index < t->socket_count && remote_index < t->num_remote_addrs &&
         t->sockets[local_index].local_addr.ss_family ==
             t->remote_addrs[remote_index].ss_family;
}

static bool path_interface_allowed(const transport_t *t, const char *name) {
  if (t->num_path_interface_names == 0)
    return true;
  for (size_t i = 0; i < t->num_path_interface_names; i++) {
    if (strcmp(t->path_interface_names[i], name) == 0)
      return true;
  }
  return false;
}

static void remove_connection_physical_slot(transport_t *t,
                                            size_t removed_index) {
  size_t count = transport_connection_count(t);
  for (size_t c = 0; c < count; c++) {
    transport_conn_t *conn = transport_connection_at(t, c);
    if (!conn)
      continue;
    for (size_t i = removed_index; i + 1 < t->socket_count; i++)
      conn->paths[i] = conn->paths[i + 1];
    conn->paths[t->socket_count - 1U] = (transport_conn_path_t){0};
    conn->admission_retry_at_ns = 0;
  }
}

static size_t select_remote_for_added_local(const transport_t *t,
                                            size_t local_index) {
  if (t->num_remote_addrs == 0)
    return SIZE_MAX;
  if (t->num_remote_addrs == 1)
    return path_endpoint_families_match(t, local_index, 0) ? 0 : SIZE_MAX;

  for (size_t remote_index = 0; remote_index < t->num_remote_addrs;
       remote_index++) {
    if (!path_endpoint_families_match(t, local_index, remote_index))
      continue;
    bool assigned = false;
    for (size_t i = 0; i < t->socket_count; i++) {
      if (i != local_index && t->sockets[i].remote_index == remote_index) {
        assigned = true;
        break;
      }
    }
    if (!assigned)
      return remote_index;
  }
  return SIZE_MAX;
}

static void try_open_pending_paths(transport_t *t, transport_conn_t *conn,
                                   uint64_t now) {
  if (!t || !conn || t->is_server || !conn->quic_ready)
    return;

  bool handshake_confirmed = false;
  for (size_t local_index = 0; local_index < t->socket_count; local_index++) {
    if (!t->sockets[local_index].open_pending ||
        now < t->sockets[local_index].open_retry_at_ms)
      continue;
    if (!handshake_confirmed) {
      /* Application keys can exist before the peer receives ClientFinished.
       * An early secondary probe can then be discarded without the primary
       * path's reordered-handshake buffering, charging setup loss to its CC.
       * Query only while a path is pending; established sends need no stats. */
      quicly_stats_t stats;
      if (quicly_get_stats(conn->quic, &stats) != 0 ||
          stats.handshake_confirmed_msec == UINT64_MAX)
        return;
      handshake_confirmed = true;
    }
    size_t remote_index = t->sockets[local_index].remote_index;
    if (!path_endpoint_families_match(t, local_index, remote_index)) {
      t->sockets[local_index].open_pending = false;
      continue;
    }

    struct sockaddr *local =
        (struct sockaddr *)&t->sockets[local_index].local_addr;
    struct sockaddr *remote = (struct sockaddr *)&t->remote_addrs[remote_index];
    if (transport_path_find_by_addresses(conn->quic, local, remote) !=
        SIZE_MAX) {
      t->sockets[local_index].open_pending = false;
      continue;
    }

    quicly_error_t ret = quicly_open_path(conn->quic, remote, local);
    if (ret == 0) {
      t->sockets[local_index].open_pending = false;
    } else if (ret == QUICLY_ERROR_PACKET_IGNORED) {
      /* The peer may not have supplied a path ID or CID yet. */
      t->sockets[local_index].open_retry_at_ms = now + QLINQ_PATH_OPEN_RETRY_MS;
    } else {
      transport_log(t, TRANSPORT_LOG_ERROR, "path", conn->id, local_index,
                    "unable to open QUIC path: %" PRId64, (int64_t)ret);
      t->sockets[local_index].open_pending = false;
    }
  }
}

static void destroy_connection_subscriptions(transport_conn_t *conn) {
  transport_subscriptions_destroy(&conn->send_subscriptions);
  transport_subscriptions_destroy(&conn->receive_subscriptions);
}

static bool init_connection_subscriptions(transport_conn_t *conn,
                                          size_t capacity) {
  if (transport_subscriptions_init(&conn->send_subscriptions, capacity) &&
      transport_subscriptions_init(&conn->receive_subscriptions, capacity))
    return true;
  destroy_connection_subscriptions(conn);
  return false;
}

static bool start_client_connection(transport_t *t) {
  if (!t || t->is_server || t->num_remote_addrs == 0 || t->socket_count == 0 ||
      t->client_conn)
    return false;

  transport_conn_t *conn = calloc(1, sizeof(*conn));
  if (!conn)
    return false;
  conn->transport = t;
  conn->id = t->next_conn_id++;
  if (!init_connection_subscriptions(
          conn, t->limits.max_subscriptions_per_connection)) {
    free(conn);
    return false;
  }

  int ret =
      quicly_connect(&conn->quic, &t->quic_ctx, t->server_name,
                     (struct sockaddr *)&t->remote_addrs[0],
                     (struct sockaddr *)&t->sockets[0].local_addr, &t->next_cid,
                     ptls_iovec_init(NULL, 0), NULL, NULL, NULL);
  if (ret != 0 || !conn->quic) {
    destroy_connection_subscriptions(conn);
    free(conn);
    return false;
  }
  /* Never reuse the client master CID. Reuse would let delayed packets from a
   * prior session authenticate against a replacement connection after a peer
   * restart. */
  t->next_cid.master_id++;
  *quicly_get_data(conn->quic) = conn;
  if (quicly_open_stream(conn->quic, &conn->stream, 0) != 0 || !conn->stream) {
    quicly_free(conn->quic);
    destroy_connection_subscriptions(conn);
    free(conn);
    return false;
  }

  t->client_conn = conn;
  for (size_t i = 1; i < t->socket_count; i++) {
    t->sockets[i].open_pending = true;
    t->sockets[i].open_retry_at_ms = 0;
  }
  return true;
}

static void schedule_client_reconnect(transport_t *t, int64_t now_ms) {
  if (!t || t->is_server || !t->reconnect_enabled || t->shutting_down)
    return;
  t->reconnect_at_ms = now_ms + t->reconnect_current_delay_ms;
  if (t->reconnect_current_delay_ms < t->reconnect_max_delay_ms) {
    uint64_t next = (uint64_t)t->reconnect_current_delay_ms * 2U;
    t->reconnect_current_delay_ms = next > t->reconnect_max_delay_ms
                                        ? t->reconnect_max_delay_ms
                                        : (uint32_t)next;
  }
}

transport_t *transport_create(const transport_config_t *config) {
  if (config &&
      config->initial_cwnd_packets > TRANSPORT_MAX_INITIAL_CWND_PACKETS)
    return NULL;
  if (!config || !config->callback || config->port == 0 ||
      config->num_bind_hosts == 0 ||
      config->num_bind_hosts > TRANSPORT_MAX_PATHS ||
      config->num_path_interface_names > TRANSPORT_MAX_PATHS ||
      config->num_remote_hosts > TRANSPORT_MAX_PATHS ||
      config->simulated_loss_rate > 100 ||
      config->congestion_control > TRANSPORT_CC_CUBIC ||
      config->pacing > TRANSPORT_PACING_ENABLED ||
      (config->num_remote_hosts != 0 &&
       (config->reconnect_initial_delay_ms != 0
            ? config->reconnect_initial_delay_ms
            : TRANSPORT_DEFAULT_RECONNECT_INITIAL_DELAY_MS) >
           (config->reconnect_max_delay_ms != 0
                ? config->reconnect_max_delay_ms
                : TRANSPORT_DEFAULT_RECONNECT_MAX_DELAY_MS)) ||
      config->simulated_flexicast_feedback_loss_rate > 100 ||
      (!config->verify_peer && !config->allow_insecure_peer)) {
    if (config && config->callback && config->port != 0 &&
        config->num_bind_hosts > 0 &&
        config->num_bind_hosts <= TRANSPORT_MAX_PATHS &&
        config->num_path_interface_names <= TRANSPORT_MAX_PATHS &&
        config->num_remote_hosts <= TRANSPORT_MAX_PATHS &&
        config->simulated_loss_rate <= 100 &&
        config->simulated_flexicast_feedback_loss_rate <= 100)
      fprintf(stderr,
              "transport: peer verification requires verify_peer or explicit "
              "allow_insecure_peer\n");
    return NULL;
  }
  for (size_t i = 0; i < config->num_bind_hosts; i++) {
    if (!config->bind_hosts[i])
      return NULL;
  }
  for (size_t i = 0; i < config->num_path_interface_names; i++) {
    if (!config->path_interface_names[i] ||
        strlen(config->path_interface_names[i]) >=
            sizeof(((transport_t *)0)->path_interface_names[0]))
      return NULL;
  }
  for (size_t i = 0; i < config->num_remote_hosts; i++) {
    if (!config->remote_hosts[i])
      return NULL;
  }

  transport_limits_t limits;
  char limits_error[160];
  if (!transport_limits_resolve(&config->limits, &limits, limits_error,
                                sizeof(limits_error))) {
    fprintf(stderr, "transport: invalid limits: %s\n", limits_error);
    return NULL;
  }

  transport_t *t = calloc(1, sizeof(transport_t));
  if (!t) {
    fprintf(stderr, "transport: failed to allocate transport state\n");
    return NULL;
  }

  for (size_t i = 0; i < TRANSPORT_MAX_PATHS; i++) {
    t->sockets[i].fd = -1;
    t->sockets[i].remote_index = SIZE_MAX;
  }
  for (size_t i = 0; i < 2; i++)
    t->flexicast_fds[i] = -1;
  t->owner_thread = pthread_self();
  atomic_init(&t->cross_thread_violations, 0);
  t->limits = limits;
  t->ifmon_pipe[0] = -1;
  t->ifmon_pipe[1] = -1;
  size_t recovery_object_bytes =
      limits.max_fec_object_size < TRANSPORT_MAX_FEC_GROUP_SIZE
          ? limits.max_fec_object_size
          : TRANSPORT_MAX_FEC_GROUP_SIZE;
  if (!transport_sent_cache_init(&t->sent_cache,
                                 limits.max_recovery_cache_bytes,
                                 recovery_object_bytes))
    goto Fail;

  t->flexicast_enabled = config->enable_flexicast;
  if (config->repair_mode != TRANSPORT_REPAIR_MODE_AUTO &&
      config->repair_mode != TRANSPORT_REPAIR_MODE_INDEXED &&
      config->repair_mode != TRANSPORT_REPAIR_MODE_RATELESS)
    goto Fail;
  t->repair_mode = config->repair_mode;
  if (config->flexicast_cc_mode != TRANSPORT_FLEXICAST_CC_MULTICAST &&
      config->flexicast_cc_mode != TRANSPORT_FLEXICAST_CC_ADAPTIVE) {
    free(t);
    return NULL;
  }
  if (config->flexicast_repair_route != TRANSPORT_FLEXICAST_REPAIR_SHARED &&
      config->flexicast_repair_route != TRANSPORT_FLEXICAST_REPAIR_UNICAST) {
    free(t);
    return NULL;
  }
  if ((config->flexicast_cc_minimum_rate != 0 &&
       config->flexicast_cc_maximum_rate != 0 &&
       config->flexicast_cc_minimum_rate > config->flexicast_cc_maximum_rate) ||
      (config->flexicast_cc_startup_rate != 0 &&
       config->flexicast_cc_minimum_rate != 0 &&
       config->flexicast_cc_startup_rate < config->flexicast_cc_minimum_rate) ||
      (config->flexicast_cc_startup_rate != 0 &&
       config->flexicast_cc_maximum_rate != 0 &&
       config->flexicast_cc_startup_rate > config->flexicast_cc_maximum_rate)) {
    fprintf(stderr, "transport: invalid Flexicast congestion-control rates\n");
    free(t);
    return NULL;
  }
  t->flexicast_cc_mode = config->flexicast_cc_mode;
  t->flexicast_cc_startup_rate = config->flexicast_cc_startup_rate;
  t->flexicast_cc_minimum_rate = config->flexicast_cc_minimum_rate;
  t->flexicast_cc_maximum_rate = config->flexicast_cc_maximum_rate;
  t->flexicast_cc_aggregate_rate_limit =
      config->flexicast_cc_aggregate_rate_limit;
  t->flexicast_cc_feedback_timeout_ms =
      config->flexicast_cc_feedback_timeout_ms;
  t->flexicast_repair_route = config->flexicast_repair_route;
  t->repair_feedback_nonce = config->repair_feedback_seed;
  if (t->repair_feedback_nonce == 0)
    ptls_openssl_random_bytes(&t->repair_feedback_nonce,
                              sizeof(t->repair_feedback_nonce));
  if (t->repair_feedback_nonce == 0)
    t->repair_feedback_nonce = UINT64_C(0x9e3779b97f4a7c15);
  t->repair_shadow_deadline_ms =
      config->repair_shadow_deadline_ms != 0
          ? config->repair_shadow_deadline_ms
          : TRANSPORT_REPAIR_PLANNER_DEFAULT_DEADLINE_MS;
  if (config->repair_shadow_log_file) {
    t->repair_shadow_log = fopen(config->repair_shadow_log_file, "ab");
    if (!t->repair_shadow_log) {
      fprintf(stderr, "transport: unable to open repair shadow log '%s': %s\n",
              config->repair_shadow_log_file, strerror(errno));
      free(t);
      return NULL;
    }
    setvbuf(t->repair_shadow_log, NULL, _IOLBF, 0);
  }
  t->next_conn_id = 1;

  t->conns = calloc(t->limits.max_connections, sizeof(*t->conns));
  if (!t->conns)
    goto Fail;
  if (t->flexicast_enabled && !transport_flexicast_registry_init(
                                  &t->flexicast, TRANSPORT_FLEXICAST_MAX_FLOWS,
                                  t->limits.max_connections))
    goto Fail;
  if (!transport_arena_init(&t->arena, 16U * 1024U * 1024U)) {
    transport_log(t, TRANSPORT_LOG_ERROR, "memory", 0, SIZE_MAX,
                  "failed to allocate packet arena");
    goto Fail;
  }

  t->callback = config->callback;
  t->user_data = config->user_data;
  t->log_callback = config->log_callback;
  t->log_user_data = config->log_user_data;
  t->is_server = (config->num_remote_hosts == 0);
  t->bind_port = t->is_server ? config->port : 0;
  t->reconnect_enabled = !t->is_server && config->reconnect_enabled;
  t->reconnect_initial_delay_ms =
      config->reconnect_initial_delay_ms != 0
          ? config->reconnect_initial_delay_ms
          : TRANSPORT_DEFAULT_RECONNECT_INITIAL_DELAY_MS;
  t->reconnect_max_delay_ms = config->reconnect_max_delay_ms != 0
                                  ? config->reconnect_max_delay_ms
                                  : TRANSPORT_DEFAULT_RECONNECT_MAX_DELAY_MS;
  t->reconnect_current_delay_ms = t->reconnect_initial_delay_ms;
  t->fec_assembler_timeout_ms = config->fec_assembler_timeout_ms != 0
                                    ? config->fec_assembler_timeout_ms
                                    : QLINQ_FEC_ASSEMBLER_TIMEOUT_MS;
  t->simulated_loss_rate = config->simulated_loss_rate;
  t->num_path_interface_names = config->num_path_interface_names;
  for (size_t i = 0; i < t->num_path_interface_names; i++)
    copy_interface_name(t->path_interface_names[i],
                        config->path_interface_names[i]);
  if (config->allow_insecure_peer)
    transport_log(t, TRANSPORT_LOG_WARNING, "tls", 0, SIZE_MAX,
                  "peer certificate verification is disabled");
  if (config->simulated_loss_rate != 0)
    transport_log(t, TRANSPORT_LOG_WARNING, "simulation", 0, SIZE_MAX,
                  "simulated packet loss is enabled");
  t->simulated_flexicast_feedback_loss_rate =
      config->simulated_flexicast_feedback_loss_rate;

  t->last_pathflow_update = transport_get_time_ms();

  if (pipe(t->ifmon_pipe) == 0) {
    if (set_fd_nonblocking(t->ifmon_pipe[0]) &&
        set_fd_nonblocking(t->ifmon_pipe[1])) {
      (void)ifmon_watch_start(&t->ifmon_w, on_ifmon_update, t);
    } else {
      CLOSE_SOCKET(t->ifmon_pipe[0]);
      CLOSE_SOCKET(t->ifmon_pipe[1]);
      t->ifmon_pipe[0] = -1;
      t->ifmon_pipe[1] = -1;
    }
  } else {
    t->ifmon_pipe[0] = -1;
    t->ifmon_pipe[1] = -1;
  }

  /* setup cryptographic context */
  t->tls_ctx.random_bytes = ptls_openssl_random_bytes;
  t->tls_ctx.get_time = &ptls_get_time;
  t->tls_ctx.key_exchanges = ptls_openssl_key_exchanges;
  if (!transport_tls_configure_crypto_backend(t))
    goto Fail;

  transport_protocol_setup(t);
  t->verifier_initialized = false;

  t->quic_ctx = quicly_spec_context;
  t->quic_ctx.now = &transport_monotonic_now;
  /* Use Quicly's native adaptive requester and its supported receive delay. */
  t->quic_ctx.transport_params.min_ack_delay_usec =
      QUICLY_LOCAL_MAX_ACK_DELAY * 1000u;
  t->quic_ctx.ack_frequency = 128;
  if (config->congestion_control == TRANSPORT_CC_RENO)
    t->quic_ctx.egress[0].cc.init_cc = &quicly_cc_reno_init;
  else if (config->congestion_control == TRANSPORT_CC_PICO)
    t->quic_ctx.egress[0].cc.init_cc = &quicly_cc_pico_init;
  else if (config->congestion_control == TRANSPORT_CC_CUBIC)
    t->quic_ctx.egress[0].cc.init_cc = &quicly_cc_cubic_init;
  if (config->pacing != TRANSPORT_PACING_DEFAULT)
    t->quic_ctx.egress[0].pacing = config->pacing == TRANSPORT_PACING_ENABLED;
  if (config->initial_rtt_ms != 0)
    t->quic_ctx.egress[0].loss.default_initial_rtt = config->initial_rtt_ms;
  if (config->handshake_timeout_rtt_multiplier != 0)
    t->quic_ctx.handshake_timeout_rtt_multiplier =
        config->handshake_timeout_rtt_multiplier;

  /* Setup CID encryptor to support active connection migration */
  char cid_key[16];
  ptls_openssl_random_bytes(cid_key, sizeof(cid_key));
  t->quic_ctx.cid_encryptor = transport_tls_new_cid_encryptor(
      t, ptls_iovec_init(cid_key, sizeof(cid_key)));
  ptls_clear_memory(cid_key, sizeof(cid_key));
  if (!t->quic_ctx.cid_encryptor)
    goto Fail;

  t->quic_ctx.tls = &t->tls_ctx;
  quicly_amend_ptls_context(t->quic_ctx.tls);
  t->quic_ctx.stream_open = &t->stream_open;
  t->quic_ctx.receive_datagram_frame = &t->receive_datagram;
  t->quic_ctx.receive_flexicast_frame = &t->receive_flexicast;
  t->quic_ctx.receive_flexicast_ack = &t->receive_flexicast_ack;

  /* Never select a validated QUIC path after its owning physical socket has
   * been removed. Datagram scheduling applies the same invariant. */
  t->quic_ctx.path_scheduler = &qlinq_path_scheduler;
  /* QLINQ selects the failover policy; Quicly owns the sent ranges, PTOs and
   * fresh-ACK recovery. Zero remains the native library's opt-out default. */
  t->quic_ctx.multipath_failover_pto_threshold = 2;

  t->quic_ctx.egress[0].cc.initcwnd_packets =
      config->initial_cwnd_packets != 0 ? config->initial_cwnd_packets : 100;
  t->quic_ctx.initial_egress_max_udp_payload_size =
      t->limits.max_udp_payload_size;
  t->quic_ctx.transport_params.max_datagram_frame_size =
      t->limits.max_udp_payload_size;
  if (config->quic_idle_timeout_ms != 0)
    t->quic_ctx.transport_params.max_idle_timeout =
        config->quic_idle_timeout_ms;
  /* Reliable tracks are long-lived unidirectional streams. Advertising only
   * one maximum object as their flow-control window caps a 40 ms path near
   * 200 Mbps. The configured stream budget is already a bounded per-stream
   * receive commitment, so use it as the window while retaining the object
   * minimum for configurations with a smaller budget. */
  uint64_t reliable_stream_window = t->limits.max_stream_egress_bytes;
  uint64_t reliable_object_window =
      (uint64_t)t->limits.max_reliable_object_size +
      QLINQ_WIRE_FRAME_HEADER_SIZE + QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE;
  if (reliable_stream_window < reliable_object_window)
    reliable_stream_window = reliable_object_window;
  t->quic_ctx.transport_params.max_stream_data.uni = reliable_stream_window;
  if (t->quic_ctx.transport_params.max_stream_data.bidi_local <
      reliable_stream_window)
    t->quic_ctx.transport_params.max_stream_data.bidi_local =
        reliable_stream_window;
  if (t->quic_ctx.transport_params.max_data <
      t->limits.max_total_stream_egress_bytes)
    t->quic_ctx.transport_params.max_data =
        t->limits.max_total_stream_egress_bytes;
  t->quic_ctx.transport_params.max_streams_uni = 100;
  t->quic_ctx.transport_params.max_streams_bidi = 100;

  t->quic_ctx.transport_params.active_connection_id_limit = 8;
  t->quic_ctx.transport_params.initial_max_path_id = TRANSPORT_MAX_PATHS;
  t->quic_ctx.transport_params.flexicast_support.ipv4 = t->flexicast_enabled;
  t->quic_ctx.transport_params.flexicast_support.ipv6 = t->flexicast_enabled;

  t->num_remote_addrs = config->num_remote_hosts;
  for (size_t i = 0; i < config->num_bind_hosts; i++) {
    transport_socket_t *socket = &t->sockets[i];
    if (!parse_address(config->bind_hosts[i], t->bind_port, &socket->local_addr,
                       &socket->local_addr_len)) {
      transport_log(t, TRANSPORT_LOG_ERROR, "config", 0, i,
                    "invalid IPv%d bind address: %s",
                    socket->local_addr.ss_family == AF_INET6 ? 6 : 4,
                    config->bind_hosts[i]);
      goto Fail;
    }
    const char *error = open_local_socket(t, socket);
    if (error) {
      transport_log(t, TRANSPORT_LOG_ERROR, "udp", 0, i, "%s for %s:%u: %s",
                    error, config->bind_hosts[i], config->port,
                    strerror(errno));
      goto Fail;
    }
    t->socket_count++;
  }
  resolve_configured_interfaces(t);

  if (!transport_flexicast_configure(t, config->flexicast_group,
                                     config->flexicast_group_port,
                                     config->flexicast_interface)) {
    transport_destroy(t);
    return NULL;
  }

  if (t->is_server || (config->cert_file && config->key_file)) {
    if (transport_tls_load_certificate_and_key(&t->tls_ctx, &t->sign_cert,
                                               config->cert_file,
                                               config->key_file) != 0) {
      transport_log(t, TRANSPORT_LOG_ERROR, "tls", 0, SIZE_MAX,
                    "failed to load TLS identity");
      goto Fail;
    }
  }

  if (config->verify_peer) {
    X509_STORE *store = NULL;
    if (config->ca_file) {
      store = X509_STORE_new();
      if (X509_STORE_load_locations(store, config->ca_file, NULL) != 1) {
        transport_log(t, TRANSPORT_LOG_ERROR, "tls", 0, SIZE_MAX,
                      "failed to load CA certificates from %s",
                      config->ca_file);
        X509_STORE_free(store);
        goto Fail;
      }
    }

    /* ptls_openssl_init_verify_certificate will take its own reference to store
     * (if provided), or load the system default certificates if store is NULL
     */
    if (ptls_openssl_init_verify_certificate(&t->verifier, store) != 0) {
      transport_log(t, TRANSPORT_LOG_ERROR, "tls", 0, SIZE_MAX,
                    "failed to initialize certificate verifier");
      if (store) {
        X509_STORE_free(store);
      }
      goto Fail;
    }
    if (store) {
      X509_STORE_free(store); /* drop our local reference */
    }

    t->tls_ctx.verify_certificate = &t->verifier.super;
    t->verifier_initialized = true;

    if (t->is_server) {
      t->tls_ctx.require_client_authentication = 1;
    }
  } else {
    transport_tls_init_insecure_verifier(&t->verifier);
    t->tls_ctx.verify_certificate = &t->verifier.super;
    t->verifier_initialized = false;
  }

  if (!t->is_server) {
    if (strlen(config->remote_hosts[0]) >= sizeof(t->server_name)) {
      transport_log(t, TRANSPORT_LOG_ERROR, "config", 0, SIZE_MAX,
                    "remote host name exceeds implementation limit");
      goto Fail;
    }
    strcpy(t->server_name, config->remote_hosts[0]);
    for (size_t i = 0; i < t->num_remote_addrs; i++) {
      socklen_t length;
      if (!parse_address(config->remote_hosts[i], config->port,
                         &t->remote_addrs[i], &length)) {
        transport_log(t, TRANSPORT_LOG_ERROR, "config", 0, i,
                      "invalid IPv%d remote address: %s",
                      t->remote_addrs[i].ss_family == AF_INET6 ? 6 : 4,
                      config->remote_hosts[i]);
        goto Fail;
      }
    }

    if (t->num_remote_addrs > 1 && t->socket_count > t->num_remote_addrs) {
      transport_log(t, TRANSPORT_LOG_ERROR, "config", 0, SIZE_MAX,
                    "multiple remote hosts require at least one remote for "
                    "each configured bind host");
      goto Fail;
    }
    for (size_t i = 0; i < t->socket_count; i++) {
      size_t remote_index = t->num_remote_addrs == 1 ? 0 : i;
      if (!path_endpoint_families_match(t, i, remote_index)) {
        transport_log(t, TRANSPORT_LOG_ERROR, "config", 0, i,
                      "remote host %zu uses a different address family",
                      remote_index);
        goto Fail;
      }
      t->sockets[i].remote_index = remote_index;
    }

    if (!start_client_connection(t)) {
      transport_log(t, TRANSPORT_LOG_ERROR, "connection", 0, SIZE_MAX,
                    "failed to create initial client connection");
      goto Fail;
    }
  }

  return t;

Fail:
  transport_destroy(t);
  return NULL;
}

static void destroy_connection(transport_conn_t *conn) {
  transport_t *t = conn->transport;
  quicly_free(conn->quic);
  for (size_t i = 0; i < t->limits.max_assemblers_per_connection; i++)
    transport_release_assembler(t, &conn->assemblers[i]);
  destroy_connection_subscriptions(conn);
  free(conn);
}

static void dispose_tls_identity(ptls_context_t *tls,
                                 ptls_openssl_sign_certificate_t *signer) {
  if (!tls || !signer)
    return;
  if (tls->sign_certificate)
    ptls_openssl_dispose_sign_certificate(signer);
  for (size_t i = 0; i < tls->certificates.count; i++)
    free(tls->certificates.list[i].base);
  free(tls->certificates.list);
  tls->certificates.list = NULL;
  tls->certificates.count = 0;
  tls->sign_certificate = NULL;
}

void transport_destroy(transport_t *t) {
  if (!t)
    return;
  if (!transport_owner_ok(t))
    return;
  if (t->callback_depth != 0) {
    t->stats.callback_destroy_rejections++;
    return;
  }

  if (t->ifmon_pipe[0] >= 0) {
    ifmon_watch_stop(&t->ifmon_w);
  }
  if (t->ifmon_pipe[0] >= 0) {
    CLOSE_SOCKET(t->ifmon_pipe[0]);
    CLOSE_SOCKET(t->ifmon_pipe[1]);
  }

  transport_flexicast_dispose(t);
  for (size_t i = 0; i < 2; i++)
    if (t->flexicast_fds[i] >= 0)
      CLOSE_SOCKET(t->flexicast_fds[i]);
  for (size_t i = 0; i < TRANSPORT_MAX_PATHS; i++)
    destroy_socket(&t->sockets[i]);

  for (size_t i = 0; i < transport_connection_count(t); i++)
    destroy_connection(transport_connection_at(t, i));

  transport_sent_cache_destroy(&t->sent_cache);
  transport_fec_cache_destroy(&t->fec_cache);

  transport_arena_destroy(&t->arena);

  if (t->quic_ctx.cid_encryptor != NULL) {
    transport_tls_free_cid_encryptor(t->quic_ctx.cid_encryptor);
  }

  if (t->pending_group.data) {
    free(t->pending_group.data);
  }

  if (t->verifier_initialized) {
    ptls_openssl_dispose_verify_certificate(&t->verifier);
  }

  dispose_tls_identity(&t->tls_ctx, &t->sign_cert);

  free(t->conns);
  if (t->repair_shadow_log)
    fclose(t->repair_shadow_log);
  free(t);
}

static uint64_t mix_repair_feedback(uint64_t value) {
  value ^= value >> 30;
  value *= UINT64_C(0xbf58476d1ce4e5b9);
  value ^= value >> 27;
  value *= UINT64_C(0x94d049bb133111eb);
  return value ^ (value >> 31);
}

/* Flexicast receivers cannot overhear one another's encrypted control streams.
 * Spread their requests long enough for the first shared repair datagram to
 * suppress most of the cohort, while keeping ordinary unicast recovery at the
 * original prompt delay. */
static int64_t repair_feedback_delay_ms(const transport_conn_t *conn,
                                        bool shared_delivery, uint8_t alias,
                                        uint64_t group_id, uint64_t object_id,
                                        uint16_t attempt) {
  if (!shared_delivery)
    return QLINQ_FEC_NACK_DELAY_MS;
  uint64_t value = conn->transport->repair_feedback_nonce;
  value ^= group_id + UINT64_C(0x9e3779b97f4a7c15);
  value ^= object_id * UINT64_C(0xd6e8feb86659fd93);
  value ^= (uint64_t)alias << 48;
  value ^= (uint64_t)attempt * UINT64_C(0xa0761d6478bd642f);
  uint64_t span =
      QLINQ_FEC_MULTICAST_NACK_BACKOFF_MAX_MS - QLINQ_FEC_NACK_DELAY_MS + 1U;
  return QLINQ_FEC_NACK_DELAY_MS + (int64_t)(mix_repair_feedback(value) % span);
}

static void add_interface(transport_t *t, const ifmon_pipe_msg_t *msg) {
  if (!path_interface_allowed(t, msg->name) ||
      t->socket_count >= TRANSPORT_MAX_PATHS)
    return;
  for (size_t i = 0; i < t->socket_count; i++)
    if (transport_address_equal(
            (const struct sockaddr *)&t->sockets[i].local_addr,
            (const struct sockaddr *)&msg->addr))
      return;

  size_t local_index = t->socket_count;
  transport_socket_t *socket = &t->sockets[local_index];
  socket->local_addr = msg->addr;
  socket->local_addr_len = msg->addr_len;
  socket->interface_index = msg->index;
  copy_interface_name(socket->interface_name, msg->name);
  set_address_port(&socket->local_addr, t->bind_port);
  if (open_local_socket(t, socket))
    return;
  bind_to_device(socket->fd, msg->index);
  t->socket_count++;

  if (!t->is_server) {
    socket->remote_index = select_remote_for_added_local(t, local_index);
    if (socket->remote_index == SIZE_MAX) {
      destroy_socket(socket);
      t->socket_count--;
      return;
    }
    socket->open_pending = true;
  }

  char ip_str[64];
  const void *address =
      msg->addr.ss_family == AF_INET
          ? (const void *)&((const struct sockaddr_in *)&msg->addr)->sin_addr
          : (const void *)&((const struct sockaddr_in6 *)&msg->addr)->sin6_addr;
  inet_ntop(msg->addr.ss_family, address, ip_str, sizeof(ip_str));
  transport_log(t, TRANSPORT_LOG_INFO, "ifmon", 0, local_index,
                "opened socket for local IP %s", ip_str);
}

static void remove_interface(transport_t *t, const ifmon_pipe_msg_t *msg) {
  for (size_t i = 0; i < t->socket_count; i++) {
    bool match = msg->addr.ss_family == AF_UNSPEC
                     ? t->sockets[i].interface_index == msg->index
                     : transport_address_equal(
                           (const struct sockaddr *)&t->sockets[i].local_addr,
                           (const struct sockaddr *)&msg->addr);
    if (!match)
      continue;
    accumulate_egress_stats(&t->stats, &t->sockets[i].egress, true);
    destroy_socket(&t->sockets[i]);
    remove_connection_physical_slot(t, i);
    for (size_t j = i; j + 1 < t->socket_count; j++)
      t->sockets[j] = t->sockets[j + 1];
    t->sockets[--t->socket_count] =
        (transport_socket_t){.fd = -1, .remote_index = SIZE_MAX};
    transport_log(t, TRANSPORT_LOG_INFO, "ifmon", 0, i,
                  "removed socket for local IP");
    break;
  }
}

static bool service_interfaces(transport_t *t) {
  if (t->ifmon_pipe[0] < 0)
    return false;
  bool consumed = false;
  ifmon_pipe_msg_t msg;
  while (read(t->ifmon_pipe[0], &msg, sizeof(msg)) == sizeof(msg)) {
    consumed = true;
    if (msg.is_added)
      add_interface(t, &msg);
    else
      remove_interface(t, &msg);
  }
  return consumed;
}

/* discard connection without CONNECTION_CLOSE on fatal error */
static void discard_connection(transport_conn_t *conn, quicly_error_t error,
                               const char *failure_reason) {
  transport_t *t = conn->transport;
  size_t index = 0;
  if (t->is_server) {
    while (index < t->conn_count && t->conns[index] != conn)
      index++;
    assert(index < t->conn_count);
  }
  uint64_t offending_frame_type = UINT64_MAX;
  const char *reason = "";
  int is_remote = 0;
  quicly_error_t close_error = error;
  if (error == QUICLY_ERROR_FREE_CONNECTION)
    close_error = quicly_get_close_reason(conn->quic, &offending_frame_type,
                                          &reason, &is_remote);
  else
    reason = failure_reason;
  bool application_error = QUICLY_ERROR_IS_QUIC_APPLICATION(close_error);
  uint64_t error_code = QUICLY_ERROR_IS_QUIC(close_error)
                            ? QUICLY_ERROR_GET_ERROR_CODE(close_error)
                            : (uint64_t)close_error;
  if (!reason)
    reason = "";
  transport_log(
      t, TRANSPORT_LOG_INFO, "connection", conn->id, SIZE_MAX,
      "closed origin=%s class=%s error=%" PRIu64 " raw=%" PRId64 " reason=%s",
      is_remote ? "remote" : "local",
      application_error
          ? "application"
          : (QUICLY_ERROR_IS_QUIC(close_error) ? "transport" : "internal"),
      error_code, (int64_t)close_error, reason[0] ? reason : "none");
  transport_event_t ev = {
      .type = TRANSPORT_EVENT_DISCONNECTED,
      .conn = conn,
      .disconnect = {.error_code = error_code,
                     .raw_error = (int64_t)close_error,
                     .application_error = application_error,
                     .offending_frame_type = offending_frame_type,
                     .remote = is_remote != 0,
                     .reason = reason}};
  transport_emit_event(t, &ev);
  t->stats.connections_closed++;

  transport_flexicast_remove_connection(t, conn);
  transport_publish_checkpoint_connection_removed(t, conn);
  transport_connection_cache_forget(t, conn);
  destroy_connection(conn);

  if (t->is_server) {
    memmove(t->conns + index, t->conns + index + 1,
            sizeof(t->conns[0]) * (t->conn_count - index - 1));
    t->conns[--t->conn_count] = NULL;
  } else {
    t->client_conn = NULL;
    schedule_client_reconnect(t, transport_get_time_ms());
  }
}

static void transport_receive_datagram(transport_t *t, size_t fd_idx,
                                       const uint8_t *buf, size_t len,
                                       struct sockaddr_storage *source,
                                       uint8_t ecn) {
  t->sockets[fd_idx].bytes_received += len;

  struct sockaddr *psa = (struct sockaddr *)source;

  quicly_decoded_packet_t decoded;
  size_t off = 0;
  while (off < len) {
    if (quicly_decode_packet(&t->quic_ctx, &decoded, buf, len, &off) ==
        SIZE_MAX)
      break;

    decoded.ecn = ecn;
    transport_conn_t *target = NULL;
    if (t->is_server) {
      /* Ordinary short-header traffic carries our stable master CID.
       * Avoid testing every earlier peer's reset tokens for each packet.
       * Initials, unknown CIDs and cache collisions retain the full path.
       */
      if (t->quic_ctx.cid_encryptor != NULL &&
          !QUICLY_PACKET_IS_LONG_HEADER(decoded.octets.base[0])) {
        transport_conn_t *hint =
            transport_connection_cache_find(t, &decoded.cid.dest.plaintext);
        if (hint &&
            quicly_is_destination(
                hint->quic, (struct sockaddr *)&t->sockets[fd_idx].local_addr,
                psa, &decoded))
          target = hint;
      }
      for (size_t i = 0; !target && i < t->conn_count; ++i) {
        if (quicly_is_destination(
                t->conns[i]->quic,
                (struct sockaddr *)&t->sockets[fd_idx].local_addr, psa,
                &decoded)) {
          target = t->conns[i];
          transport_connection_cache_remember(t, target);
          break;
        }
      }
      if (!target && !t->shutting_down &&
          t->conn_count < t->limits.max_connections) {
        quicly_conn_t *new_quic = NULL;
        quicly_cid_plaintext_t connection_cid = t->next_cid;
        int accept_res =
            quicly_accept(&new_quic, &t->quic_ctx,
                          (struct sockaddr *)&t->sockets[fd_idx].local_addr,
                          psa, &decoded, NULL, &connection_cid, NULL, NULL);
        if (accept_res == 0 && new_quic) {
          t->next_cid.master_id++;
          target = calloc(1, sizeof(transport_conn_t));
          if (!target) {
            quicly_free(new_quic);
            t->stats.connections_rejected++;
            continue;
          }
          target->transport = t;
          target->quic = new_quic;
          target->id = t->next_conn_id++;
          if (!init_connection_subscriptions(
                  target, t->limits.max_subscriptions_per_connection)) {
            quicly_free(new_quic);
            free(target);
            target = NULL;
            t->stats.connections_rejected++;
            continue;
          }
          *quicly_get_data(new_quic) = target;
          t->conns[t->conn_count++] = target;
          transport_connection_cache_remember(t, target);
          t->stats.connections_accepted++;
        }
      } else if (!target && !t->shutting_down) {
        t->stats.connections_rejected++;
      }
    } else {
      target = t->client_conn;
    }

    if (target && target->authenticated && t->simulated_loss_rate > 0 &&
        (rand() % 100) < t->simulated_loss_rate) {
      continue; /* simulate packet loss on wire after connection is
                   established */
    }

    if (target) {
      quicly_error_t ret = quicly_receive(
          target->quic, (struct sockaddr *)&t->sockets[fd_idx].local_addr, psa,
          &decoded);
      if (ret != 0 && ret != QUICLY_ERROR_PACKET_IGNORED &&
          (ret != QUICLY_ERROR_STATE_EXHAUSTION ||
           quicly_close(target->quic, ret, "receive failure") != 0)) {
        discard_connection(target, ret, "receive failure");
        break;
      }
    }
  }
}

static bool socket_receive_ready(int fd, const struct pollfd *fds,
                                 size_t count) {
  if (!fds)
    return true;
  for (size_t i = 0; i < count; i++)
    if (fds[i].fd == fd &&
        (fds[i].revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0)
      return true;
  return false;
}

static void receive_packets(transport_t *t, const struct pollfd *fds,
                            size_t count) {
  size_t receive_budget = t->limits.max_packets_per_tick;
  size_t flexicast_receive_budget = (receive_budget + 1U) / 2U;
  for (size_t slot = 0; slot < 2 && flexicast_receive_budget > 0; slot++) {
    while (t->flexicast_fds[slot] >= 0 && flexicast_receive_budget > 0) {
      uint8_t buf[2048];
      struct sockaddr_storage sa;
      socklen_t sa_len = sizeof(sa);
      ssize_t rret = recvfrom(t->flexicast_fds[slot], buf, sizeof(buf), 0,
                              (struct sockaddr *)&sa, &sa_len);
      if (rret == -1) {
        if (SOCKET_ERROR_CODE == SOCKET_EAGAIN ||
            SOCKET_ERROR_CODE == SOCKET_EWOULDBLOCK)
          break;
        continue;
      }
      receive_budget--;
      flexicast_receive_budget--;
      t->stats.flexicast_multicast_datagrams_received++;
      transport_conn_t *flexicast_source = NULL;
      ptls_iovec_t flexicast_payload = ptls_iovec_init(NULL, 0);
      if (transport_flexicast_receive_packet(
              t, buf, (size_t)rret, &flexicast_source, &flexicast_payload) &&
          flexicast_source && flexicast_payload.base) {
        if (flexicast_source->authenticated && t->simulated_loss_rate > 0 &&
            (rand() % 100) < t->simulated_loss_rate)
          continue;
        transport_protocol_receive_datagram(flexicast_source, flexicast_payload,
                                            false);
      } else
        t->stats.flexicast_multicast_datagrams_rejected++;
    }
  }
  size_t receive_start =
      t->socket_count ? t->receive_cursor % t->socket_count : 0;
  t->receive_cursor =
      t->socket_count ? (receive_start + 1U) % t->socket_count : 0;
  size_t quantum = t->socket_count ? (receive_budget + t->socket_count - 1U) /
                                         t->socket_count
                                   : 0;
  for (size_t visited = 0; visited < t->socket_count; visited++) {
    size_t fd_idx = (receive_start + visited) % t->socket_count;
    transport_socket_t *socket = &t->sockets[fd_idx];
    if (!transport_udp_gro_pending(socket->gro) &&
        !socket_receive_ready(socket->fd, fds, count))
      continue;
    if (receive_budget == 0) {
      /* The earlier sockets consumed this tick's budget. Remember every
       * remaining ready socket even when the last serviced socket drained. */
      socket->receive_backlog = true;
      continue;
    }
    size_t serviced = 0;
    while (receive_budget > 0 && serviced < quantum) {
      size_t batch = quantum - serviced;
      if (batch > receive_budget)
        batch = receive_budget;
      if (batch > TRANSPORT_UDP_RECEIVE_BATCH)
        batch = TRANSPORT_UDP_RECEIVE_BATCH;
      ssize_t received;
      bool more;
      if (socket->gro) {
        transport_udp_view_t views[TRANSPORT_UDP_RECEIVE_BATCH];
        received = transport_udp_gro_receive(socket->gro, socket->fd, views,
                                             batch, &more);
        for (ssize_t i = 0; i < received; i++)
          if (!views[i].dropped)
            transport_receive_datagram(t, fd_idx, views[i].data, views[i].size,
                                       &views[i].source, views[i].ecn);
      } else {
        transport_udp_datagram_t datagrams[TRANSPORT_UDP_RECEIVE_BATCH];
        received = transport_udp_receive_batch(socket->fd, datagrams, batch);
        for (ssize_t i = 0; i < received; i++) {
          /* Preserve recvfrom/recvmmsg's original copied-prefix dispatch. The
           * decoder validates each complete QUIC packet in that prefix. */
          transport_receive_datagram(t, fd_idx, datagrams[i].data,
                                     datagrams[i].size, &datagrams[i].source,
                                     datagrams[i].ecn);
        }
        more = received == (ssize_t)batch;
      }
      if (received <= 0) {
        /* Only an actual empty read proves this socket drained. A timer-only
         * tick or a receive error must not erase an earlier exhausted budget.
         */
        if (received == 0)
          socket->receive_backlog = false;
        break; /* Empty or persistently failing sockets cannot spin the owner.
                */
      }
      receive_budget -= (size_t)received;
      serviced += (size_t)received;
      if (!more)
        socket->receive_backlog = false;
      else if (receive_budget == 0 || serviced >= quantum)
        socket->receive_backlog = true;
      /* GRO may fill its raw batch yet return fewer logical views than asked
       * for. Its explicit continuation flag preserves the packet quantum and
       * avoids stranding input after a short logical batch. */
      if (!more)
        break;
    }
  }
}

static void update_path_measurements(transport_t *t, uint64_t now) {
  if (now - t->last_pathflow_update >= QLINQ_PATHFLOW_UPDATE_MS) {
    t->last_pathflow_update = now;
    /* Peer limits are unchanged throughout this synchronous update. Resolve
     * their common symbol size once, instead of scanning the cohort again
     * for each connection. */
    size_t symbol_size = transport_get_datagram_symbol_size(t);

    size_t update_count = transport_connection_count(t);
    for (size_t c = 0; c < update_count; c++) {
      transport_conn_t *target = transport_connection_at(t, c);
      if (!target || !target->quic)
        continue;
      for (size_t i = 0; i < t->socket_count; i++) {
        if (target->paths[i].state_overridden)
          continue;
        quicly_path_stats_t stats;
        size_t mapped = transport_path_get_eligible_by_local(
            target->quic, &t->sockets[i].local_addr, &stats);
        if (mapped == SIZE_MAX ||
            !quicly_is_path_available(target->quic, mapped)) {
          /* A newly available path must start from its own measurements. */
          memset(&target->paths[i].state, 0, sizeof(target->paths[i].state));
          memset(&target->paths[i].measurement, 0,
                 sizeof(target->paths[i].measurement));
          memset(&target->paths[i].budget, 0, sizeof(target->paths[i].budget));
          continue;
        }
        size_t queued =
            quicly_get_num_datagram_frames_path(target->quic, mapped);
        if (transport_path_measure(&target->paths[i].measurement, &stats,
                                   mapped, queued, now)) {
          memset(&target->paths[i].state, 0, sizeof(target->paths[i].state));
          memset(&target->paths[i].budget, 0, sizeof(target->paths[i].budget));
        }
        fp_t relative_owd = target->paths[i].owd_initialized &&
                                    target->paths[i].telemetry_path == mapped
                                ? target->paths[i].latest_owd_fp
                                : 0;
        path_t sample = transport_path_estimate_on_path(
            target->quic, mapped, &stats, queued, t->sockets[i].egress.bytes,
            symbol_size, relative_owd);
        sample.p = transport_path_recent_loss(&target->paths[i].measurement);
        fp_t cap = transport_path_probe_cap(&target->paths[i].measurement,
                                            &stats, symbol_size, now);
        if (sample.b > cap)
          sample.b = cap;
        transport_path_update_state(&target->paths[i].state, &sample, true);
      }
    }
  }
}

static void service_connections(transport_t *t, uint64_t now) {
  size_t active_count = transport_connection_count(t);
  for (size_t i = 0; i < active_count; ++i) {
    transport_conn_t *conn = transport_connection_at(t, i);
    if (!conn)
      continue;

    if (!conn->quic_ready && quicly_connection_is_ready(conn->quic)) {
      conn->quic_ready = true;
    }
    abandon_removed_paths(conn);
    try_open_pending_paths(t, conn, now);
    if (conn->quic_ready)
      (void)transport_protocol_send_hello(conn);
    transport_protocol_maybe_emit_connected(conn);
    refresh_scheduler_paths(conn);

    while (1) {
      bool egress_has_room = true;
      for (size_t p = 0; p < t->socket_count; p++) {
        if (!transport_egress_can_accept(&t->sockets[p].egress, 64U,
                                         64U * 1500U)) {
          egress_has_room = false;
          break;
        }
      }
      if (!egress_has_room)
        break;

      quicly_address_t dest, src;
      struct iovec dgrams[64];
      size_t num_dgrams = 64;
      /* qlinq_path_scheduler_send chooses one path for each native batch.
       * Quicly may consume the whole output batch on that path, so bound
       * stream-only multipath batches to keep a single decision from steering
       * 64 packets. Datagram publication retains its 64-packet queue batch. */
      bool stream_only_multipath =
          (conn->scheduler_paths & (conn->scheduler_paths - 1U)) != 0 &&
          !quicly_has_datagram_frames(conn->quic);
      if (stream_only_multipath)
        num_dgrams = QLINQ_STREAM_MULTIPATH_SEND_BATCH;
      /* Save this classification: quicly_send may drain queued DATAGRAMs.
       * Stream-only output uses smaller UDP aggregates independently of the
       * native batch size; retained egress must carry the same limit. */
      quicly_error_t send_res =
          quicly_send(conn->quic, &dest, &src, dgrams, &num_dgrams,
                      t->send_buffer, sizeof(t->send_buffer));
      if (send_res == 0) {
        if (num_dgrams == 0)
          break;

        size_t out_fd_index = SIZE_MAX;
        for (size_t k = 0; k < t->socket_count; k++) {
          if (transport_address_equal(
                  (const struct sockaddr *)&t->sockets[k].local_addr,
                  &src.sa)) {
            out_fd_index = k;
            break;
          }
        }

        if (out_fd_index == SIZE_MAX) {
          t->stats.udp_send_errors += num_dgrams;
          transport_log(t, TRANSPORT_LOG_ERROR, "udp", conn->id, SIZE_MAX,
                        "no socket matches QUIC source address");
          continue;
        }

        if (!transport_egress_submit_ecn(
                &t->sockets[out_fd_index].egress, t->sockets[out_fd_index].fd,
                &dest.sa, quicly_get_socklen(&dest.sa), dgrams, num_dgrams,
                stream_only_multipath ? QLINQ_STREAM_MULTIPATH_GSO_SEGMENTS : 0,
                quicly_send_get_ecn_bits(conn->quic)))
          transport_log(t, TRANSPORT_LOG_WARNING, "udp", conn->id, out_fd_index,
                        "egress queue exhausted");
      } else if (send_res == QUICLY_ERROR_FREE_CONNECTION) {
        discard_connection(conn, send_res, NULL);
        if (t->is_server)
          i--;
        active_count = transport_connection_count(t);
        break;
      } else {
        if (send_res != QUICLY_ERROR_STATE_EXHAUSTION ||
            quicly_close(conn->quic, send_res, "send failure") != 0) {
          discard_connection(conn, send_res, "send failure");
          if (t->is_server)
            i--;
          active_count = transport_connection_count(t);
        }
        break;
      }
    }
  }
}

static int64_t group_flush_deadline(const transport_t *t) {
  const transport_pending_group_t *group = &t->pending_group;
  if (group->size == 0 ||
      group->started_at_ms > INT64_MAX - QLINQ_GROUP_FLUSH_MS)
    return INT64_MAX;
  int64_t deadline = (int64_t)group->started_at_ms + QLINQ_GROUP_FLUSH_MS;
  /* a checkpoint ACK can make room before the retry timer; only actual cache
   * releases bypass backoff, not repeated readiness or timeout queries */
  if (group->flush_retry_cache_releases == t->stats.recovery_cache_releases &&
      group->flush_retry_at_ms > deadline)
    deadline = group->flush_retry_at_ms;
  return deadline;
}

static void flush_group_on_timer(transport_t *t) {
  int64_t deadline = group_flush_deadline(t);
  if (deadline == INT64_MAX)
    return;
  int64_t now = transport_get_time_ms();
  if (now < deadline || transport_publish_flush_grouped(t))
    return;
  /* preserve the group's original age and frozen identity after failure;
   * explicit publish/flush/finish calls do not consult this timer deadline */
  now = transport_get_time_ms();
  t->pending_group.flush_retry_at_ms =
      now > INT64_MAX - QLINQ_GROUP_FLUSH_RETRY_MS
          ? INT64_MAX
          : now + QLINQ_GROUP_FLUSH_RETRY_MS;
  t->pending_group.flush_retry_cache_releases =
      t->stats.recovery_cache_releases;
}

void transport_tick_ready(transport_t *t, const struct pollfd *fds,
                          size_t count) {
  if (!transport_owner_ok(t))
    return;
  if (t->tick_active) {
    t->stats.recursive_tick_rejections++;
    return;
  }
  t->tick_active = true;

  for (size_t i = 0; i < t->socket_count; i++)
    (void)transport_egress_flush(&t->sockets[i].egress, t->sockets[i].fd);

  int64_t now_nack_ms = transport_get_time_ms();
  if (!t->is_server && !t->client_conn && t->reconnect_enabled &&
      !t->shutting_down && now_nack_ms >= t->reconnect_at_ms) {
    t->stats.reconnect_attempts++;
    t->reconnect_in_progress = true;
    if (!start_client_connection(t)) {
      t->stats.reconnect_failed++;
      t->reconnect_in_progress = false;
      schedule_client_reconnect(t, now_nack_ms);
      transport_log(t, TRANSPORT_LOG_WARNING, "connection", 0, SIZE_MAX,
                    "reconnect attempt failed; retry scheduled");
    }
  }

  transport_recovery_tick(t, now_nack_ms);

  flush_group_on_timer(t);

  /* Messages arriving after the snapshot remain readable for the next poll.
   * Consumed updates can compact slots and recycle descriptors; even a no-op
   * update invalidates UDP readiness. Direct ticks retain the full scan. */
  if (socket_receive_ready(t->ifmon_pipe[0], fds, count) &&
      service_interfaces(t))
    fds = NULL;
  receive_packets(t, fds, count);
  if (t->pending_group.size != 0 && t->pending_group.flush_retry_at_ms != 0 &&
      t->pending_group.flush_retry_cache_releases !=
          t->stats.recovery_cache_releases)
    flush_group_on_timer(t);
  uint64_t now = transport_get_time_ms();
  update_path_measurements(t, now);
  service_connections(t, now);
  transport_protocol_poll_lifecycle(t);
  transport_publish_poll_lifecycle(t);
  t->tick_active = false;
}

void transport_tick(transport_t *t) {
  transport_tick_ready(t, NULL, 0);
}

static bool subscribe_connection(transport_conn_t *conn,
                                 const moq_track_id_t *track_id) {
  if (!conn || !conn->protocol_ready || !conn->authenticated || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;

  const track_subscription_t *existing = transport_subscriptions_find_const(
      &conn->receive_subscriptions, track_id);
  if (existing && existing->track_id.flags != track_id->flags)
    return false;
  bool newly_added = false;
  uint8_t alias = existing ? existing->alias : 0;
  if (!existing) {
    if (transport_subscriptions_count(&conn->receive_subscriptions) >=
        conn->negotiated_limits.max_subscriptions_per_connection)
      return false;
    if (track_id->name[0] == '\0') {
      alias = (uint8_t)track_id->type;
    } else {
      int next_alias =
          transport_subscriptions_next_alias(&conn->receive_subscriptions, 8);
      if (next_alias < 0)
        return false;
      alias = (uint8_t)next_alias;
    }
    if (!transport_subscriptions_add(&conn->receive_subscriptions,
                                     track_id->type, track_id->flags,
                                     track_id->name, alias))
      return false;
    newly_added = true;
  }

  if (!transport_stream_write_track_frame(conn->stream, QLINQ_WIRE_SUBSCRIBE,
                                          alias, track_id)) {
    if (!existing)
      transport_subscriptions_remove(&conn->receive_subscriptions,
                                     track_id->type, track_id->name);
    return false;
  if (newly_added)
    memset(&conn->object_gaps[alias], 0, sizeof(conn->object_gaps[alias]));
  transport_publish_checkpoint_member_added(conn->transport, conn, track_id,
                                            alias);
  return true;
}

bool transport_subscribe_conn(transport_t *t, transport_conn_t *conn,
                              moq_track_id_t track_id) {
  if (!transport_owner_ok(t) || !transport_track_id_valid(&track_id) ||
      !transport_has_connection(t, conn))
    return false;
  return subscribe_connection(conn, &track_id);
}

bool transport_subscribe(transport_t *t, moq_track_id_t track_id) {
  if (!transport_owner_ok(t) || !transport_track_id_valid(&track_id))
    return false;
  if (!t->is_server)
    return t->client_conn && subscribe_connection(t->client_conn, &track_id);

  bool found = false;
  bool succeeded = true;
  for (size_t i = 0; i < t->conn_count; i++) {
    transport_conn_t *conn = t->conns[i];
    if (!conn || !conn->protocol_ready || !conn->authenticated)
      continue;
    found = true;
    if (!subscribe_connection(conn, &track_id))
      succeeded = false;
  }
  return !found || succeeded;
}

static bool unsubscribe_connection(transport_t *t, transport_conn_t *conn,
                                   const moq_track_id_t *track_id) {
  if (!conn || !conn->protocol_ready || !conn->authenticated || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;

  const track_subscription_t *subscription = transport_subscriptions_find_const(
      &conn->receive_subscriptions, track_id);
  if (!subscription)
    return false;
  moq_track_id_t subscribed_track = subscription->track_id;
  uint8_t alias = subscription->alias;
  if (!transport_stream_write_track_frame(conn->stream, QLINQ_WIRE_UNSUBSCRIBE,
                                          alias, &subscribed_track))
    return false;

  transport_publish_checkpoint_member_removed(t, conn, &subscribed_track,
                                              alias);
  transport_flexicast_unsubscribe(t, conn, &subscribed_track);
  for (size_t i = 0; i < t->limits.max_assemblers_per_connection; i++)
    if (conn->assemblers[i].total_symbols &&
        conn->assemblers[i].track_id == alias)
      transport_release_assembler(t, &conn->assemblers[i]);
  transport_subscriptions_remove(&conn->receive_subscriptions,
                                 subscribed_track.type, subscribed_track.name);
  return true;
}

bool transport_unsubscribe(transport_t *t, moq_track_id_t track_id) {
  if (!transport_owner_ok(t) || !transport_track_id_valid(&track_id))
    return false;

  if (!t->is_server)
    return t->client_conn &&
           unsubscribe_connection(t, t->client_conn, &track_id);

  bool found = false;
  bool succeeded = true;
  for (size_t i = 0; i < t->conn_count; i++) {
    transport_conn_t *conn = t->conns[i];
    if (!conn || !transport_subscriptions_contains(&conn->receive_subscriptions,
                                                   &track_id))
      continue;
    found = true;
    if (!unsubscribe_connection(t, conn, &track_id))
      succeeded = false;
  }
  return !found || succeeded;
}

bool transport_request_keyframe(transport_t *t, moq_track_id_t track_id) {
  if (!transport_owner_ok(t) || !transport_track_id_valid(&track_id) ||
      t->is_server || !t->client_conn || !t->client_conn->protocol_ready ||
      !t->client_conn->authenticated || !t->client_conn->stream ||
      !quicly_sendstate_is_open(&t->client_conn->stream->sendstate))
    return false;

  return transport_stream_write_track_frame(
      t->client_conn->stream, QLINQ_WIRE_KEYFRAME_REQUEST, 0, &track_id);
}

bool transport_send_unicast(transport_t *t, transport_conn_t *conn,
                            const void *data, size_t size) {
  if (!transport_owner_ok(t) || size > t->limits.max_reliable_object_size ||
      (size > 0 && !data))
    return false;
  if (!transport_has_connection(t, conn) || !conn->protocol_ready ||
      !conn->stream || !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;

  return transport_stream_write_frame(conn->stream, QLINQ_WIRE_UNICAST, data,
                                      size);
}

void transport_close_conn(transport_t *t, transport_conn_t *conn) {
  transport_close_conn_with_error(t, conn, 0, "application close");
}

void transport_close_conn_with_error(transport_t *t, transport_conn_t *conn,
                                     int64_t error, const char *reason) {
  if (!transport_owner_ok(t))
    return;
  if (error != 0 && !QUICLY_ERROR_IS_QUIC_APPLICATION(error))
    return;
  if (transport_has_connection(t, conn) && conn->quic &&
      quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING) {
    if (error == TRANSPORT_APP_ERROR_RESOURCE_LIMIT)
      t->stats.resource_limit_errors++;
    quicly_close(conn->quic, error, reason ? reason : "application close");
  }
}

void transport_shutdown(transport_t *t, const char *reason) {
  if (!transport_owner_ok(t))
    return;
  t->shutting_down = true;
  t->reconnect_in_progress = false;
  const char *phrase = reason && reason[0] ? reason : "application shutdown";
  size_t count = transport_connection_count(t);
  for (size_t i = 0; i < count; i++) {
    transport_conn_t *conn = transport_connection_at(t, i);
    if (conn && conn->quic &&
        quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING)
      (void)quicly_close(conn->quic, 0, phrase);
  }
}

bool transport_is_drained(transport_t *t) {
  if (!transport_owner_ok(t))
    return false;
  if (t->is_server ? t->conn_count != 0 : t->client_conn != NULL)
    return false;
  for (size_t i = 0; i < t->socket_count; i++) {
    if (t->sockets[i].egress.count != 0)
      return false;
  }
  return true;
}

bool transport_reload_credentials(transport_t *t, const char *cert_file,
                                  const char *key_file) {
  if (!transport_owner_ok(t) || !cert_file || !key_file)
    return false;
  ptls_context_t candidate = {0};
  ptls_openssl_sign_certificate_t candidate_signer = {0};
  if (transport_tls_load_certificate_and_key(&candidate, &candidate_signer,
                                             cert_file, key_file) != 0) {
    dispose_tls_identity(&candidate, &candidate_signer);
    transport_log(t, TRANSPORT_LOG_ERROR, "tls", 0, SIZE_MAX,
                  "credential reload failed; retaining current identity");
    return false;
  }

  dispose_tls_identity(&t->tls_ctx, &t->sign_cert);
  t->sign_cert = candidate_signer;
  t->tls_ctx.certificates = candidate.certificates;
  t->tls_ctx.sign_certificate = &t->sign_cert.super;
  transport_log(t, TRANSPORT_LOG_INFO, "tls", 0, SIZE_MAX,
                "credentials reloaded for future handshakes");
  return true;
}

bool transport_send_auth(transport_t *t, transport_conn_t *conn,
                         const uint8_t *token, size_t token_len) {
  if (!transport_owner_ok(t))
    return false;
  if (!transport_has_connection(t, conn) || !conn->protocol_ready ||
      !conn->stream || !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;
  if (token_len > 65535 || (token_len > 0 && !token))
    return false;

  return transport_stream_write_frame(conn->stream, QLINQ_WIRE_AUTH_REQUEST,
                                      token, token_len);
}

bool transport_respond_auth(transport_t *t, transport_conn_t *conn,
                            bool success) {
  if (!transport_owner_ok(t))
    return false;
  if (!transport_has_connection(t, conn) || !conn->protocol_ready ||
      !conn->stream || !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;

  uint8_t status = success ? 1 : 0;
  if (!transport_stream_write_frame(conn->stream, QLINQ_WIRE_AUTH_RESPONSE,
                                    &status, sizeof(status)))
    return false;

  if (success) {
    conn->authenticated = true;
  } else {
    quicly_close(conn->quic, TRANSPORT_APP_ERROR_AUTHENTICATION,
                 "authentication failed");
  }
  return true;
}

uint64_t transport_get_estimated_bandwidth(transport_t *t) {
  if (!transport_owner_ok(t))
    return 0;
  transport_conn_t *conn =
      t->is_server ? (t->conn_count > 0 ? t->conns[0] : NULL) : t->client_conn;
  if (!conn || !conn->quic) {
    return 0;
  }
  quicly_stats_t stats;
  uint64_t rate = 0;
  if (quicly_get_stats(conn->quic, &stats) == 0) {
    rate = stats.delivery_rate.latest;
  }
  return rate;
}

static bool transport_has_connection(const transport_t *t,
                                     const transport_conn_t *conn) {
  if (!t || !conn)
    return false;
  if (!t->is_server)
    return t->client_conn == conn;
  for (size_t i = 0; i < t->conn_count; i++) {
    if (t->conns[i] == conn)
      return true;
  }
  return false;
}

bool transport_get_stats(transport_t *t, transport_stats_t *stats) {
  if (!transport_owner_ok(t) || !stats)
    return false;
  *stats = t->stats;
  stats->recovery_cache_payload_bytes = t->sent_cache.payload_bytes;
  stats->recovery_cache_peak_payload_bytes = t->sent_cache.peak_payload_bytes;
  stats->recovery_cache_entries = t->sent_cache.count;
  stats->recovery_cache_peak_entries = t->sent_cache.peak_count;
  stats->api_thread_violations +=
      atomic_load_explicit(&t->cross_thread_violations, memory_order_relaxed);
  stats->active_connections = transport_connection_count(t);
  stats->assembler_memory_bytes = t->assembler_memory_bytes;
  stats->flexicast_cc_mode = t->flexicast_cc_mode;
  stats->flexicast_active_flows = 0;
  stats->flexicast_active_members = 0;
  int64_t now_ms = transport_get_time_ms();
  size_t active_count = transport_connection_count(t);
  for (size_t i = 0; i < active_count; i++) {
    const transport_conn_t *conn = transport_connection_at(t, i);
    if (!conn)
      continue;
    for (size_t slot = 0; slot < conn->send_subscriptions.capacity; slot++) {
      const track_subscription_t *sub = &conn->send_subscriptions.entries[slot];
      if (!sub->active)
        continue;
      uint8_t alias = sub->alias;
      const transport_checkpoint_ack_state_t *ack =
          transport_checkpoint_ack(conn, alias);
      if (!ack || !ack->participating || !ack->sent_initialized ||
          (ack->acked_initialized &&
           ack->acked_group_id == ack->sent_group_id &&
           ack->acked_object_id >= ack->sent_object_id))
        continue;
      stats->recovery_checkpoints_pending++;
      if (ack->oldest_unacked_sent_at_ms > 0 &&
          now_ms > ack->oldest_unacked_sent_at_ms &&
          (uint64_t)(now_ms - ack->oldest_unacked_sent_at_ms) >
              stats->recovery_oldest_checkpoint_age_ms)
        stats->recovery_oldest_checkpoint_age_ms =
            (uint64_t)(now_ms - ack->oldest_unacked_sent_at_ms);
    }
  }
  for (size_t f = 0; f < t->flexicast.capacity; f++) {
    const transport_flexicast_flow_t *flow = &t->flexicast.flows[f];
    if (!flow->active)
      continue;
    stats->flexicast_active_flows++;
    if (flow->source)
      stats->flexicast_active_members +=
          transport_flexicast_listening_members(flow);
    stats->flexicast_queued_packets +=
        flow->data_queue.count + flow->repair_queue.count;
    stats->flexicast_queued_bytes +=
        flow->data_queue.bytes + flow->repair_queue.bytes;
    stats->repair_queued_packets += flow->repair_queue.count;
    stats->repair_queued_bytes += flow->repair_queue.bytes;
    stats->repair_pending_objects += flow->pending_repair_count;
    for (size_t i = 0; i < flow->repair_queue.count; i++) {
      size_t slot = (flow->repair_queue.head + i) % flow->repair_queue.capacity;
      int64_t enqueued = flow->repair_queue.entries[slot].enqueued_at_ms;
      if (enqueued > 0 && now_ms > enqueued &&
          (uint64_t)(now_ms - enqueued) > stats->repair_oldest_age_ms)
        stats->repair_oldest_age_ms = (uint64_t)(now_ms - enqueued);
    }
    for (size_t i = 0; i < TRANSPORT_FLEXICAST_PENDING_REPAIRS; i++) {
      int64_t requested = flow->pending_repairs[i].first_request_ms;
      if (flow->pending_repairs[i].active && requested > 0 &&
          now_ms > requested &&
          (uint64_t)(now_ms - requested) > stats->repair_oldest_age_ms)
        stats->repair_oldest_age_ms = (uint64_t)(now_ms - requested);
    }
    if (flow->pacing_rate_bytes_per_second != 0 &&
        (stats->flexicast_pacing_rate_bytes_per_second == 0 ||
         flow->pacing_rate_bytes_per_second <
             stats->flexicast_pacing_rate_bytes_per_second)) {
      stats->flexicast_pacing_rate_bytes_per_second =
          flow->pacing_rate_bytes_per_second;
      if (flow->source && flow->crypto) {
        quicly_flexicast_cc_output_t output;
        quicly_flexicast_cc_get_flow_output(flow->crypto, &output);
        stats->flexicast_cc_rate_bytes_per_second =
            output.rate_bytes_per_second;
        stats->flexicast_cc_burst_bytes = output.burst_bytes;
        stats->flexicast_cc_limiting_member = output.limiting_member_id;
      }
    }
    if (flow->source && flow->crypto) {
      quicly_flexicast_cc_output_t output;
      quicly_flexicast_cc_get_flow_output(flow->crypto, &output);
      stats->flexicast_cc_rate_increase_events += output.rate_increase_events;
      stats->flexicast_cc_rate_reduction_events += output.rate_reduction_events;
      stats->flexicast_cc_floor_entry_events += output.floor_entry_events;
      stats->flexicast_cc_floor_exit_events += output.floor_exit_events;
      stats->flexicast_cc_ack_growth_events += output.ack_growth_events;
      stats->flexicast_cc_other_growth_events += output.other_growth_events;
      stats->flexicast_cc_loss_reduction_events += output.loss_reduction_events;
      stats->flexicast_cc_rtt_reduction_events += output.rtt_reduction_events;
      stats->flexicast_cc_ecn_reduction_events += output.ecn_reduction_events;
      stats->flexicast_cc_timeout_reduction_events +=
          output.timeout_reduction_events;
      stats->flexicast_cc_rate_limit_reduction_events +=
          output.rate_limit_reduction_events;
      stats->flexicast_cc_other_reduction_events +=
          output.other_reduction_events;
      stats->flexicast_cc_external_load_growth_freeze_events +=
          output.external_load_growth_freeze_events;
    }
  }
  for (size_t m = 0; m < t->flexicast.capacity; m++)
    stats->flexicast_active_memberships += t->flexicast.memberships[m].active;
  for (size_t i = 0; i < t->socket_count; i++) {
    const transport_egress_t *egress = &t->sockets[i].egress;
    accumulate_egress_stats(stats, egress, false);
    stats->egress_current_packets += egress->count;
    stats->egress_current_bytes += egress->bytes;
  }
  return true;
}

bool transport_get_conn_stats(transport_t *t, transport_conn_t *conn,
                              transport_conn_stats_t *stats) {
  if (!transport_owner_ok(t) || !stats || !transport_has_connection(t, conn))
    return false;
  memset(stats, 0, sizeof(*stats));
  stats->id = conn->id;
  stats->quic_ready = conn->quic_ready;
  stats->protocol_ready = conn->protocol_ready;
  stats->authenticated = conn->authenticated;
  stats->subscriptions =
      transport_subscriptions_count(&conn->receive_subscriptions) +
      transport_subscriptions_count(&conn->send_subscriptions);
  stats->peer_capabilities = conn->peer_capabilities;
  stats->negotiated_limits = conn->negotiated_limits;
  stats->stream_frames_received = conn->stream_frames_received;
  stats->datagrams_received = conn->datagrams_received;
  stats->malformed_datagrams = conn->malformed_datagrams;
  quicly_stats_t quic_stats;
  if (quicly_get_stats(conn->quic, &quic_stats) == 0) {
    stats->quic_paths_created = quic_stats.num_paths.created;
    stats->quic_paths_validated = quic_stats.num_paths.validated;
    stats->quic_paths_validation_failed =
        quic_stats.num_paths.validation_failed;
  }
  return true;
}

uint32_t transport_get_conn_id(transport_t *t, transport_conn_t *conn) {
  return transport_owner_ok(t) && transport_has_connection(t, conn) ? conn->id
                                                                    : 0;
}

transport_repair_mode_t
transport_get_effective_repair_mode(transport_t *t, transport_conn_t *conn,
                                    const moq_track_id_t *track_id) {
  if (!transport_owner_ok(t) || !transport_has_connection(t, conn) ||
      !transport_track_id_valid(track_id))
    return TRANSPORT_REPAIR_MODE_INDEXED;
  return t->repair_mode != TRANSPORT_REPAIR_MODE_INDEXED &&
                 (track_id->flags & MOQ_TRACK_FLAG_FEC_RATELESS) != 0 &&
                 (conn->peer_capabilities & QLINQ_WIRE_CAP_RATELESS_REPAIR) != 0
             ? TRANSPORT_REPAIR_MODE_RATELESS
             : TRANSPORT_REPAIR_MODE_INDEXED;
}

int transport_enable_qlog(const char *socket_path) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    CLOSE_SOCKET(fd);
    return -1;
  }

  /* Set non-blocking to prevent logging from hanging the main transport thread
   */
  if (!set_fd_nonblocking(fd)) {
    CLOSE_SOCKET(fd);
    return -1;
  }

  /* enable picotls and quicly tracing, sample ratio 1.0 (all logs), write to fd
   */
  ptls_log_add_fd(fd, 1.0, NULL, NULL, NULL, 0);
  ptls_log_add_fd(fd, 1.0, NULL, NULL, NULL, 1);
  return 0;
}

bool transport_get_path_stats(transport_t *t, size_t path_idx,
                              transport_path_stats_t *stats) {
  if (!transport_owner_ok(t) || !stats || path_idx >= t->socket_count)
    return false;

  memset(stats, 0, sizeof(*stats));
  stats->interface_index = t->sockets[path_idx].interface_index;
  copy_interface_name(stats->interface_name,
                      t->sockets[path_idx].interface_name);
  const void *address = NULL;
  if (t->sockets[path_idx].local_addr.ss_family == AF_INET)
    address = &((const struct sockaddr_in *)&t->sockets[path_idx].local_addr)
                   ->sin_addr;
  else if (t->sockets[path_idx].local_addr.ss_family == AF_INET6)
    address = &((const struct sockaddr_in6 *)&t->sockets[path_idx].local_addr)
                   ->sin6_addr;
  if (address)
    (void)inet_ntop(t->sockets[path_idx].local_addr.ss_family, address,
                    stats->local_address, sizeof(stats->local_address));
  if (!stats->interface_name[0])
    copy_interface_name(stats->interface_name, stats->local_address);
  stats->bytes_sent = t->sockets[path_idx].egress.bytes_sent;
  stats->bytes_received = t->sockets[path_idx].bytes_received;

  transport_conn_t *target =
      t->is_server ? (t->conn_count > 0 ? t->conns[0] : NULL) : t->client_conn;
  stats->lifecycle = t->shutting_down
                         ? TRANSPORT_PATH_DRAINING
                         : (target ? TRANSPORT_PATH_DISCOVERED
                                   : (t->is_server ? TRANSPORT_PATH_DISCOVERED
                                                   : TRANSPORT_PATH_FAILED));
  if (target && target->quic) {
    quicly_path_stats_t path_stats;
    size_t mapped_path_idx = transport_path_get_stats_by_local(
        target->quic, &t->sockets[path_idx].local_addr, &path_stats);
    if (quicly_get_state(target->quic) >= QUICLY_STATE_CLOSING) {
      stats->lifecycle = TRANSPORT_PATH_DRAINING;
    } else if (mapped_path_idx >= TRANSPORT_MAX_QUIC_PATHS) {
      stats->lifecycle = t->sockets[path_idx].open_pending
                             ? TRANSPORT_PATH_OPENING
                             : TRANSPORT_PATH_DISCOVERED;
    } else if (!quicly_is_path_available(target->quic, mapped_path_idx)) {
      stats->lifecycle = TRANSPORT_PATH_VALIDATING;
    } else {
      stats->lifecycle = TRANSPORT_PATH_ACTIVE;
      stats->sent = path_stats.sent;
      stats->acked = path_stats.acked;
      stats->bytes_acked = path_stats.bytes_acked;
      stats->cwnd = path_stats.cwnd;
      stats->bytes_in_flight = path_stats.bytes_in_flight;
      stats->lost = path_stats.lost;
      stats->rtt = path_stats.rtt_smoothed;
    }
  }

  stats->relative_owd =
      target
          ? (double)FP_TO_FLOAT(target->paths[path_idx].latest_owd_fp) * 1000.0
          : 0.0;
  stats->ewma_latency =
      target
          ? (double)FP_TO_FLOAT(target->paths[path_idx].state.l_ewma) * 1000.0
          : 0.0;

  return true;
}

static void transport_mock_iface_change(transport_t *t, const char *ip_addr,
                                        bool added) {
  if (!transport_owner_ok(t) || t->ifmon_pipe[1] < 0)
    return;

  ifmon_pipe_msg_t msg = {0};
  msg.is_added = added ? 1 : 0;
  msg.index = 1; /* loopback interface index */
  struct sockaddr_in *sin = (struct sockaddr_in *)&msg.addr;
  sin->sin_family = AF_INET;
  if (!ip_addr || inet_pton(AF_INET, ip_addr, &sin->sin_addr) != 1)
    return;
  msg.addr_len = sizeof(*sin);

  ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
  (void)w;
}

/* deterministic interface changes for integration tests */
void transport_mock_iface_add(transport_t *t, const char *ip_addr) {
  transport_mock_iface_change(t, ip_addr, true);
}

void transport_mock_iface_remove(transport_t *t, const char *ip_addr) {
  transport_mock_iface_change(t, ip_addr, false);
}

bool transport_mock_path_state(transport_t *t, size_t path_idx,
                               uint32_t packets_per_second, double latency_ms,
                               double loss_rate) {
  if (!transport_owner_ok(t) || path_idx >= t->socket_count ||
      packets_per_second == 0 || latency_ms < 0.0 || loss_rate < 0.0 ||
      loss_rate > 1.0)
    return false;
  size_t active_count = transport_connection_count(t);
  if (active_count == 0)
    return false;
  for (size_t i = 0; i < active_count; i++) {
    transport_conn_t *conn = transport_connection_at(t, i);
    if (!conn)
      continue;
    path_state_t *state = &conn->paths[path_idx].state;
    state->initialized = 1;
    state->b_ewma = FP_FROM_INT(packets_per_second);
    state->l_ewma = FP_FROM_FLOAT((float)(latency_ms / 1000.0));
    state->p_ewma = FP_FROM_FLOAT((float)loss_rate);
    state->q_ewma = 0;
    conn->paths[path_idx].state_overridden = true;
    memset(&conn->paths[path_idx].budget, 0,
           sizeof(conn->paths[path_idx].budget));
    conn->admission_retry_at_ns = 0;
  }
  return true;
}

size_t transport_get_datagram_symbol_size(const transport_t *t) {
  if (!t || !transport_owner_ok((transport_t *)t))
    return 0;
  size_t udp_payload_size = t->limits.max_udp_payload_size;
  size_t active_count = transport_connection_count(t);
  for (size_t i = 0; i < active_count; i++) {
    const transport_conn_t *conn = transport_connection_at(t, i);
    if (conn && conn->protocol_ready &&
        conn->negotiated_limits.max_udp_payload_size < udp_payload_size)
      udp_payload_size = conn->negotiated_limits.max_udp_payload_size;
  }
  size_t symbol_size = udp_payload_size > 80U ? udp_payload_size - 80U : 0U;
  return symbol_size < 1000 ? 1000 : symbol_size;
}

bool transport_is_track_ready(transport_t *t, const moq_track_id_t *track_id) {
  if (!transport_owner_ok(t) || !transport_track_id_valid(track_id))
    return false;

  if (!transport_publish_recovery_ready(t, track_id))
    return false;

  for (size_t i = 0; i < t->socket_count; i++) {
    const transport_egress_t *egress = &t->sockets[i].egress;
    if (egress->count >= egress->capacity * 3U / 4U ||
        egress->bytes >= egress->max_bytes * 3U / 4U)
      return false;
  }

  transport_track_profile_t profile = transport_track_profile(track_id);

  if (!profile.reliable && t->is_server && t->flexicast_enabled &&
      !transport_flexicast_track_ready(t, track_id))
    return false;

  size_t active_count = transport_connection_count(t);
  if (active_count == 0)
    return true; /* no peers means data is dropped anyway, so it's "ready" */

  for (size_t c = 0; c < active_count; c++) {
    transport_conn_t *conn = transport_connection_at(t, c);
    if (!conn || !conn->quic ||
        quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
      continue;

    if (!t->is_server && (!conn->authenticated || !conn->protocol_ready))
      return false;
    if (!transport_publish_recipient_eligible(t, conn, track_id))
      continue;
    const track_subscription_t *subscription =
        transport_subscriptions_find_const(&conn->send_subscriptions, track_id);
    if (subscription && subscription->track_id.flags != track_id->flags)
      return false;

    if (profile.reliable) {
      quicly_stream_t *stream = subscription ? subscription->stream : NULL;
      if (stream &&
          !transport_stream_can_accept(stream,
                                       QLINQ_WIRE_FRAME_HEADER_SIZE +
                                           QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE,
                                       true))
        return false;
    } else {
      if (conn->admission_retry_at_ns > transport_get_monotonic_ns())
        return false;
      bool ready = false;
      for (size_t path = 0; path < TRANSPORT_MAX_QUIC_PATHS; path++) {
        quicly_path_stats_t stats;
        quicly_path_health_t health;
        if (!quicly_is_path_available(conn->quic, path) ||
            quicly_get_path_stats(conn->quic, path, &stats) != 0 ||
            (quicly_get_path_health(conn->quic, path, &health) == 0 &&
             health.state == QUICLY_PATH_SUSPECT))
          continue;
        bool owned = false;
        for (size_t physical = 0; physical < t->socket_count; physical++)
          owned |= transport_path_matches_local(
              &stats, &t->sockets[physical].local_addr);
        if (owned &&
            quicly_get_num_datagram_frames_path(conn->quic, path) <
                QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY * 3 / 4 &&
            stats.cwnd != 0 && stats.bytes_in_flight / 2 < stats.cwnd) {
          ready = true;
          break;
        }
      }
      if (!ready)
        return false;
    }
  }

  return true;
}

int64_t transport_get_time_ms(void) {
  return (int64_t)(transport_get_monotonic_ns() / 1000000U);
}

int64_t transport_get_first_timeout(transport_t *t) {
  if (!transport_owner_ok(t))
    return INT64_MAX;

  /* A GRO read can empty the kernel socket while leaving logical datagrams
   * in userspace. Poll readiness alone cannot schedule the remaining work. */
  for (size_t i = 0; i < t->socket_count; i++)
    if (transport_udp_gro_pending(t->sockets[i].gro))
      return 0;

  int64_t first_timeout = t->aggregate_nack_retry_at_ms > 0
                              ? t->aggregate_nack_retry_at_ms
                              : INT64_MAX;
  size_t active_conns = transport_connection_count(t);
  for (size_t c = 0; c < active_conns; c++) {
    transport_conn_t *conn = transport_connection_at(t, c);
    if (!conn || !conn->quic ||
        quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
      continue;
    if (conn->admission_retry_at_ns) {
      uint64_t monotonic_now = transport_get_monotonic_ns();
      if (conn->admission_retry_at_ns <= monotonic_now) {
        conn->admission_retry_at_ns = 0;
      } else {
        uint64_t delta = conn->admission_retry_at_ns - monotonic_now;
        uint64_t delay_ms = delta / 1000000U + (delta % 1000000U != 0);
        int64_t timer_now = transport_get_time_ms();
        int64_t retry_at = delay_ms > (uint64_t)(INT64_MAX - timer_now)
                               ? INT64_MAX
                               : timer_now + (int64_t)delay_ms;
        if (retry_at < first_timeout)
          first_timeout = retry_at;
      }
    }
    int64_t recovery_at = transport_recovery_deadline(conn);
    if (recovery_at < first_timeout)
      first_timeout = recovery_at;
  }

  if (active_conns != 0 &&
      t->last_pathflow_update <= INT64_MAX - QLINQ_PATHFLOW_UPDATE_MS &&
      (int64_t)t->last_pathflow_update + QLINQ_PATHFLOW_UPDATE_MS <
          first_timeout)
    first_timeout = (int64_t)t->last_pathflow_update + QLINQ_PATHFLOW_UPDATE_MS;
  int64_t group_at = group_flush_deadline(t);
  if (group_at < first_timeout)
    first_timeout = group_at;

  if (!t->is_server && !t->client_conn && t->reconnect_enabled &&
      !t->shutting_down && t->reconnect_at_ms < first_timeout)
    first_timeout = t->reconnect_at_ms;

  for (size_t i = 0; i < active_conns; i++) {
    transport_conn_t *conn = transport_connection_at(t, i);
    if (conn && conn->quic) {
      int64_t deadline = quicly_get_first_timeout(conn->quic);
      if (deadline < first_timeout)
        first_timeout = deadline;
    }
  }

  int64_t flexicast_timeout = transport_flexicast_get_first_timeout(t);
  if (flexicast_timeout < first_timeout)
    first_timeout = flexicast_timeout;

  return first_timeout;
}

size_t transport_get_poll_fds(transport_t *t, struct pollfd *fds,
                              size_t max_fds) {
  if (!transport_owner_ok(t) || !fds)
    return 0;

  size_t count = 0;
  for (size_t i = 0; i < t->socket_count && count < max_fds; i++) {
    if (t->sockets[i].fd >= 0) {
      fds[count].fd = t->sockets[i].fd;
      fds[count].events = POLLIN;
      if (t->sockets[i].egress.count > 0)
        fds[count].events |= POLLOUT;
      fds[count].revents = 0;
      count++;
    }
  }
  for (size_t i = 0; i < 2 && count < max_fds; i++)
    if (t->flexicast_fds[i] >= 0) {
      fds[count].fd = t->flexicast_fds[i];
      fds[count].events = POLLIN;
      fds[count].revents = 0;
      count++;
    }
  return count;
}

bool transport_rx_cadence_mask(transport_t *t, struct pollfd *fds,
                               size_t count) {
  if (!transport_owner_ok(t) || !fds || t->tick_active || t->shutting_down ||
      t->reconnect_in_progress || t->pending_group.size ||
      t->socket_count == 0 || transport_connection_count(t) != 1)
    return false;
  transport_conn_t *conn = transport_connection_at(t, 0);
  if (!conn || !conn->quic || !conn->authenticated || !conn->protocol_ready ||
      !conn->quic_ready || !quicly_connection_is_ready(conn->quic) ||
      quicly_has_pending_stream_data(conn->quic) ||
      quicly_has_datagram_frames(conn->quic) ||
      quicly_get_state(conn->quic) != QUICLY_STATE_CONNECTED ||
      transport_subscriptions_count(&conn->send_subscriptions) != 0 ||
      transport_subscriptions_count(&conn->receive_subscriptions) == 0)
    return false;

  if (!conn->rx_cadence_handshake_confirmed) {
    quicly_stats_t stats;
    if (quicly_get_stats(conn->quic, &stats) != 0 ||
        stats.handshake_confirmed_msec == UINT64_MAX)
      return false;
    conn->rx_cadence_handshake_confirmed = true;
  }

  /* Validate before mutating any mask. This also rejects stale/recycled fd
   * snapshots and leaves egress and interface wakeups on the ordinary path. */
  size_t slot = 0;
  for (size_t i = 0; i < t->socket_count; i++) {
    transport_socket_t *socket = &t->sockets[i];
    if (socket->egress.count || socket->open_pending ||
        socket->receive_backlog || transport_udp_gro_pending(socket->gro))
      return false;
    if (socket->fd < 0)
      continue;
    if (slot >= count || fds[slot].fd != socket->fd ||
        fds[slot].events != POLLIN || fds[slot].revents != 0)
      return false;
    slot++;
  }
  size_t udp_count = slot;
  if (t->ifmon_pipe[0] >= 0) {
    if (slot >= count || fds[slot].fd != t->ifmon_pipe[0] ||
        fds[slot].events != POLLIN || fds[slot].revents != 0)
      return false;
    slot++;
  }
  if (!udp_count || slot != count)
    return false;
  for (size_t i = 0; i < udp_count; i++)
    fds[i].events &= (short)~POLLIN;
  return true;
}

bool transport_get_track_stats(transport_t *t, const moq_track_id_t *track,
                               transport_track_stats_t *stats) {
  if (!transport_owner_ok(t) || !transport_track_id_valid(track) || !stats)
    return false;
  *stats = (transport_track_stats_t){0};
  size_t count = transport_connection_count(t);
  for (size_t i = 0; i < count; i++) {
    transport_conn_t *conn = transport_connection_at(t, i);
    uint8_t alias;
    if (conn && conn->authenticated && conn->quic &&
        quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING &&
        transport_subscriptions_find_alias(&conn->send_subscriptions, track,
                                           &alias) == 0)
      stats->subscribers++;
  }
  return true;
}
