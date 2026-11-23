#include "transport_flexicast.h"

#include "portable_sockets.h"
#include "transport_group_cc.h"
#include "transport_internal.h"
#include "transport_publish.h"

#include "quicly/defaults.h"

#include <stdlib.h>
#include <string.h>

static transport_flexicast_queued_payload_t *
queue_front(transport_flexicast_queue_t *queue) {
  if (!queue || queue->count == 0 || !queue->entries)
    return NULL;
  return &queue->entries[queue->head % queue->capacity];
}

bool tf_reserve_queue_slots(transport_flexicast_flow_t *flow, size_t count,
                            size_t slot_bytes) {
  if (!flow || slot_bytes == 0)
    return false;
  transport_flexicast_queue_t *queue = &flow->data_queue;
  if (queue->capacity == 0 || queue->count > queue->capacity ||
      count > queue->capacity - queue->count)
    return false;
  if (!queue->entries) {
    if (queue->capacity > SIZE_MAX / sizeof(*queue->entries))
      return false;
    queue->entries = calloc(queue->capacity, sizeof(*queue->entries));
    if (!queue->entries)
      return false;
  }
  for (size_t i = 0; i < count; i++) {
    size_t idx = (queue->head + queue->count + i) % queue->capacity;
    transport_flexicast_queued_payload_t *slot = &queue->entries[idx];
    if (slot->storage_capacity < slot_bytes) {
      uint8_t *grown = realloc(slot->storage, slot_bytes);
      if (!grown)
        return false;
      slot->storage = grown;
      slot->storage_capacity = slot_bytes;
    }
  }
  return true;
}

static bool
queue_push_slot(transport_flexicast_flow_t *flow, ptls_iovec_t payload,
                size_t packet_capacity,
                const transport_flexicast_queued_payload_t *partial) {
  if (!flow || !payload.base || payload.len > SIZE_MAX - packet_capacity)
    return false;
  size_t needed = payload.len + packet_capacity;
  transport_flexicast_queue_t *queue = &flow->data_queue;
  if (queue->count >= queue->capacity ||
      payload.len > SIZE_MAX - queue->bytes ||
      !tf_reserve_queue_slots(flow, 1, needed))
    return false;
  size_t tail = (queue->head + queue->count) % queue->capacity;
  transport_flexicast_queued_payload_t *slot = &queue->entries[tail];
  uint8_t *storage = slot->storage;
  size_t storage_capacity = slot->storage_capacity;
  if (partial)
    *slot = *partial;
  else
    memset(slot, 0, sizeof(*slot));
  slot->storage = storage;
  slot->storage_capacity = storage_capacity;
  memcpy(storage, payload.base, payload.len);
  slot->data = storage;
  slot->size = payload.len;
  slot->packet = storage + payload.len;
  slot->packet_capacity = packet_capacity;
  if (partial && partial->packet_ready && partial->packet &&
      partial->packet_size > 0 && partial->packet_size <= packet_capacity)
    memcpy(slot->packet, partial->packet, partial->packet_size);
  queue->count++;
  queue->bytes += payload.len;
  return true;
}

static void queue_pop(transport_flexicast_queue_t *queue) {
  transport_flexicast_queued_payload_t *payload = queue_front(queue);
  if (!payload)
    return;
  queue->bytes =
      payload->size <= queue->bytes ? queue->bytes - payload->size : 0;
  uint8_t *storage = payload->storage;
  size_t storage_capacity = payload->storage_capacity;
  memset(payload, 0, sizeof(*payload));
  payload->storage = storage;
  payload->storage_capacity = storage_capacity;
  queue->head = (queue->head + 1U) % queue->capacity;
  queue->count--;
}

size_t tf_clear_flow_queue(transport_flexicast_flow_t *flow) {
  if (!flow)
    return 0;
  size_t cleared = flow->data_queue.count;
  while (flow->data_queue.count != 0)
    queue_pop(&flow->data_queue);
  flow->data_queue.head = 0;
  return cleared;
}

void tf_queue_dispose(transport_flexicast_queue_t *queue) {
  if (!queue)
    return;
  if (queue->entries) {
    for (size_t i = 0; i < queue->capacity; i++)
      free(queue->entries[i].storage);
    free(queue->entries);
  }
  memset(queue, 0, sizeof(*queue));
}

static struct sockaddr_storage multicast_source_address(const transport_t *t) {
  struct sockaddr_storage source = {0};
  source.ss_family = t->flexicast_group_addr.ss_family;
  if (source.ss_family == AF_INET) {
    ((struct sockaddr_in *)&source)->sin_addr = t->flexicast_interface_v4;
  } else if (source.ss_family == AF_INET6) {
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&source;
    v6->sin6_addr = t->flexicast_interface_v6;
    if (IN6_IS_ADDR_LINKLOCAL(&v6->sin6_addr))
      v6->sin6_scope_id = t->flexicast_interface_index;
  }
  return source;
}

static uint64_t member_delivery_rate(const transport_flexicast_member_t *member,
                                     size_t packet_size) {
  if (!member || !member->conn || !member->conn->quic)
    return 0;
  quicly_stats_t stats;
  if (quicly_get_stats(member->conn->quic, &stats) != 0)
    return 0;
  uint64_t rate = stats.delivery_rate.smoothed != 0
                      ? stats.delivery_rate.smoothed
                      : stats.delivery_rate.latest;
  if (rate == 0) {
    uint64_t rtt = stats.rtt.smoothed != 0 ? stats.rtt.smoothed : 100;
    uint64_t cwnd = stats.cc.cwnd >= packet_size ? stats.cc.cwnd : packet_size;
    rate = cwnd > UINT64_MAX / 1000U ? UINT64_MAX : cwnd * 1000U / rtt;
  }
  return rate;
}

static bool active_sender(const transport_flexicast_flow_t *flow, int64_t now,
                          int64_t window) {
  return flow->data_queue.count != 0 ||
         (flow->last_payload_sent_ms != 0 &&
          now - flow->last_payload_sent_ms <= window);
}

static int compare_rates(const void *lhs, const void *rhs) {
  uint64_t a = *(const uint64_t *)lhs, b = *(const uint64_t *)rhs;
  return (a > b) - (a < b);
}

/* rates and activity can change during a pacing tick; only reuse snapshot
 * for active senders since an idle sender's hypothetical share is private */
static size_t update_controller_hints(transport_t *t,
                                      transport_flexicast_flow_t *flow,
                                      int64_t now) {
  bool mcbbr = transport_group_cc_mcbbr_is(flow->cc);
  uint64_t aggregate = t->flexicast_cc_aggregate_rate_limit;
  if (!mcbbr && aggregate == 0)
    return 1;
  transport_flexicast_registry_t *registry = &t->flexicast;
  int64_t active_window =
      2 * (int64_t)(t->flexicast_cc_feedback_timeout_ms != 0
                        ? t->flexicast_cc_feedback_timeout_ms
                        : 1000U);
  bool active = active_sender(flow, now, active_window);
  size_t count = registry->cohort_count;
  if (!active || count == 0 || registry->cohort_at_ms != now) {
    uint64_t rates[TRANSPORT_FLEXICAST_MAX_FLOWS];
    count = 0;
    for (size_t i = 0; i < registry->capacity; i++) {
      const transport_flexicast_flow_t *candidate = &registry->flows[i];
      if (!candidate->active || !candidate->source || !candidate->cc ||
          candidate->listening_count == 0 ||
          (candidate != flow && !active_sender(candidate, now, active_window)))
        continue;
      if (mcbbr)
        rates[count] = candidate->cc->output.rate_bytes_per_second;
      ++count;
    }
    if (count == 0)
      return 1;
    if (mcbbr) {
      qsort(rates, count, sizeof(*rates), compare_rates);
      registry->cohort_median_rate = rates[count / 2];
    }
    registry->cohort_count = active ? count : 0;
    registry->cohort_at_ms = now;
  }
  if (!mcbbr)
    return count;
  transport_group_cc_hints_t hints = {
      .active_senders = (uint32_t)count,
      .aggregate_rate_limit_bytes_per_second =
          aggregate / count + (aggregate % count != 0),
      .median_sender_rate_bytes_per_second = registry->cohort_median_rate};
  uint64_t previous = flow->cc->output.rate_bytes_per_second;
  transport_group_cc_mcbbr_set_hints(flow->cc, &hints, now);
  if (flow->cc->output.rate_bytes_per_second != previous)
    registry->cohort_count = 0;
  return count;
}

/* credit elapsed interval at previous rate using wide intermediate math */
static void refill_tokens(uint64_t *tokens, uint64_t *remainder,
                          int64_t *last_refill, uint64_t numerator,
                          uint32_t divisor, uint64_t burst, int64_t now) {
  if (*last_refill == 0 || now <= *last_refill || burst == 0)
    return;
  uint64_t elapsed = (uint64_t)(now - *last_refill);
  *last_refill = now;
  uint64_t denominator = (uint64_t)(divisor != 0 ? divisor : 1) * 1000U;
  uint64_t room = *tokens < burst ? burst - *tokens : 0;
  __extension__ typedef unsigned __int128 wide_t;
  wide_t credit = (wide_t)numerator * elapsed + *remainder;
  wide_t added = credit / denominator;
  if (added >= room) {
    *tokens = burst;
    *remainder = 0;
  } else {
    *tokens += (uint64_t)added;
    *remainder = (uint64_t)(credit % denominator);
  }
}

static uint64_t pacing_burst(const transport_t *t, uint64_t rate,
                             uint64_t suggested, bool mcbbr) {
  uint64_t minimum = t->limits.max_udp_payload_size * (mcbbr ? 2U : 4U);
  uint64_t burst = suggested < minimum ? minimum : suggested;
  uint64_t traditional_maximum = t->limits.max_udp_payload_size * 10U;
  if (burst > traditional_maximum)
    burst = traditional_maximum;
  uint64_t millisecond = rate / 1000U + (rate % 1000U != 0);
  if (burst < millisecond)
    burst = millisecond;
  uint64_t maximum = t->limits.max_egress_bytes_per_socket;
  if (maximum < t->limits.max_udp_payload_size)
    maximum = t->limits.max_udp_payload_size;
  return burst > maximum ? maximum : burst;
}

static void refresh_pacer_at(transport_t *t, transport_flexicast_flow_t *flow,
                             int64_t now) {
  refill_tokens(&flow->pacing_tokens, &flow->pacing_remainder,
                &flow->pacing_last_refill_ms, flow->pacing_rate_numerator,
                flow->pacing_rate_divisor, flow->pacing_burst_bytes, now);
  transport_flexicast_registry_t *registry = &t->flexicast;
  refill_tokens(&registry->pacing_tokens, &registry->pacing_remainder,
                &registry->pacing_last_refill_ms, registry->pacing_rate, 1,
                registry->pacing_burst, now);
  size_t active = update_controller_hints(t, flow, now);
  uint64_t aggregate = t->flexicast_cc_aggregate_rate_limit;
  quicly_flexicast_cc_output_t cc_output;
  quicly_flexicast_cc_get_flow_output(flow->crypto, &cc_output);
  if (flow->listening_count == 0)
    return;
  uint64_t rate = cc_output.rate_bytes_per_second;
  if (rate == 0) {
    uint64_t slowest = UINT64_MAX;
    for (size_t i = 0; i < flow->member_count; i++) {
      transport_flexicast_member_t *member = &flow->members[i];
      if (!member->conn || !member->listening)
        continue;
      uint64_t member_rate =
          member_delivery_rate(member, t->limits.max_udp_payload_size);
      if (member_rate != 0 && member_rate < slowest)
        slowest = member_rate;
    }
    if (slowest == UINT64_MAX)
      slowest = 64U * 1024U;
    rate = slowest / 5U * 4U;
  }
  uint64_t numerator = rate;
  uint32_t divisor = 1;
  if (aggregate != 0 && rate > aggregate / active) {
    numerator = aggregate;
    divisor = (uint32_t)active;
    rate = numerator / divisor + (numerator % divisor != 0);
  }
  uint64_t mcbbr_burst = transport_group_cc_mcbbr_burst_bytes(flow->cc);
  uint64_t burst = pacing_burst(
      t, rate, mcbbr_burst != 0 ? mcbbr_burst : cc_output.burst_bytes,
      mcbbr_burst != 0);
  if (flow->pacing_last_refill_ms == 0) {
    flow->pacing_tokens = burst;
    flow->pacing_last_refill_ms = now;
  }
  if (flow->pacing_rate_divisor != divisor)
    flow->pacing_remainder = 0;
  flow->pacing_rate_numerator = numerator;
  flow->pacing_rate_divisor = divisor;
  flow->pacing_rate_bytes_per_second = rate;
  flow->pacing_burst_bytes = burst;
  if (flow->pacing_tokens > burst)
    flow->pacing_tokens = burst;
  if (aggregate != 0) {
    uint64_t aggregate_burst = pacing_burst(t, aggregate, 0, false);
    if (registry->pacing_last_refill_ms == 0) {
      registry->pacing_tokens = aggregate_burst;
      registry->pacing_last_refill_ms = now;
    }
    registry->pacing_rate = aggregate;
    registry->pacing_burst = aggregate_burst;
    if (registry->pacing_tokens > aggregate_burst)
      registry->pacing_tokens = aggregate_burst;
  }
}

static uint64_t pacing_available(const transport_t *t,
                                 const transport_flexicast_flow_t *flow) {
  uint64_t available = flow->pacing_tokens;
  if (t->flexicast_cc_aggregate_rate_limit != 0 &&
      available > t->flexicast.pacing_tokens)
    available = t->flexicast.pacing_tokens;
  return available;
}

/* fractional credit is expressed in units of 1 / (1000 * divisor) byte */
static uint64_t token_wait_ms(uint64_t deficit, uint64_t remainder,
                              uint32_t divisor, uint64_t rate) {
  if (!deficit)
    return 0;
  uint64_t needed = deficit * 1000U * divisor - remainder;
  return needed / rate + (needed % rate != 0);
}

static int64_t pacing_ready_at(const transport_t *t,
                               const transport_flexicast_flow_t *flow,
                               size_t cost, int64_t now) {
  if (flow->pacing_last_refill_ms == 0)
    return now;
  uint64_t tokens = flow->pacing_tokens, remainder = flow->pacing_remainder;
  int64_t refill = flow->pacing_last_refill_ms;
  refill_tokens(&tokens, &remainder, &refill, flow->pacing_rate_numerator,
                flow->pacing_rate_divisor, flow->pacing_burst_bytes, now);
  uint64_t shared = t->flexicast.pacing_tokens;
  uint64_t shared_remainder = t->flexicast.pacing_remainder;
  refill = t->flexicast.pacing_last_refill_ms;
  refill_tokens(&shared, &shared_remainder, &refill, t->flexicast.pacing_rate,
                1, t->flexicast.pacing_burst, now);
  uint64_t delay = 0;
  if (cost > tokens ||
      (t->flexicast_cc_aggregate_rate_limit != 0 && cost > shared)) {
    if (flow->pacing_rate_numerator == 0)
      return INT64_MAX;
    uint64_t deficit = cost > tokens ? cost - tokens : 0;
    delay = token_wait_ms(deficit, remainder, flow->pacing_rate_divisor,
                          flow->pacing_rate_numerator);
    if (t->flexicast_cc_aggregate_rate_limit != 0 && cost > shared) {
      uint64_t shared_delay =
          token_wait_ms(cost - shared, shared_remainder, 1,
                        t->flexicast_cc_aggregate_rate_limit);
      if (delay < shared_delay)
        delay = shared_delay;
    }
    if (delay == 0)
      delay = 1;
  }
  int64_t ready =
      delay > (uint64_t)(INT64_MAX - now) ? INT64_MAX : now + (int64_t)delay;
  return ready < flow->dispatch_retry_at_ms ? flow->dispatch_retry_at_ms
                                            : ready;
}

/* empty queue is app-limited only after leaving send credit unused;
 * remember when another full-size datagram could have been sent */
static void record_mcbbr_idle(const transport_t *t,
                              transport_flexicast_flow_t *flow, int64_t now) {
  flow->cc_idle_ready_at_ms =
      pacing_ready_at(t, flow, t->limits.max_udp_payload_size, now);
}

static size_t pacing_cost(const transport_flexicast_flow_t *flow,
                          size_t payload_size) {
  return quicly_flexicast_datagram_size(flow->crypto, payload_size);
}

typedef enum {
  FLEXICAST_DISPATCH_OK,
  FLEXICAST_DISPATCH_BLOCKED,
  FLEXICAST_DISPATCH_FAILED,
} flexicast_dispatch_result_t;

static uint8_t flow_ecn_mark(const transport_t *t,
                             const transport_conn_t *conn) {
  uint8_t mode = t->quic_ctx.egress[0].ecn;
  if (mode == QUICLY_ECN_MODE_OFF)
    return 0;
  if (conn) {
    quicly_stats_t qstats;
    if (!conn->quic || quicly_get_stats(conn->quic, &qstats) != 0 ||
        qstats.num_paths.ecn_validated == 0 || qstats.num_paths.ecn_failed != 0)
      return 0;
  }
  return mode == QUICLY_ECN_MODE_L4S ? 1U : 2U;
}

static int submit_protected_packet(
    transport_t *t, size_t socket_index, const struct sockaddr *destination,
    const struct sockaddr *source, bool native_multicast, uint8_t ecn,
    const transport_flexicast_queued_payload_t *queued) {
  if (socket_index == SIZE_MAX || socket_index >= t->socket_count ||
      t->sockets[socket_index].egress_id < 0)
    return -1;
  transport_egress_t *egress = &t->sockets[socket_index].egress;
  if (egress->count != 0)
    return 0;
  struct iovec vec = {.iov_base = queued->packet,
                      .iov_len = queued->packet_size};
  transport_drive_path_t path =
      transport_local_path_info(&t->sockets[socket_index]);
  socklen_t destination_len = destination->sa_family == AF_INET
                                  ? sizeof(struct sockaddr_in)
                                  : sizeof(struct sockaddr_in6);
  uint32_t ifindex = native_multicast && t->flexicast_interface_index
                         ? t->flexicast_interface_index
                         : path.interface_index;
  t->host_callback_active = true;
  ssize_t sent = t->drive_host.send(
      t->drive_host.context, &path,
      source ? source : (const struct sockaddr *)&path.local, destination,
      destination_len, ifindex, ecn, 0, &vec, 1);
  t->host_callback_active = false;
  if (sent > 0) {
    egress->packets_sent++;
    egress->bytes_sent += queued->packet_size;
    return 1;
  }
  if (sent == 0) {
    egress->would_block++;
    return 0;
  }
  egress->send_errors++;
  return -1;
}

static void
account_protected_packet(transport_t *t, transport_flexicast_flow_t *flow,
                         transport_flexicast_queued_payload_t *queued,
                         transport_flexicast_member_t *recipient,
                         uint32_t physical_fanout, bool app_limited) {
  int64_t now = transport_now_ms(t);
  bool mcbbr = transport_group_cc_mcbbr_is(flow->cc);
  uint32_t flags = QUICLY_FLEXICAST_SAMPLE_VALID;
  if (mcbbr) {
    flags |= queued->cc_sample_flags;
    if ((flags & QUICLY_FLEXICAST_SAMPLE_MIXED) != 0)
      flags &= ~QUICLY_FLEXICAST_SAMPLE_VALID;
  } else if (app_limited) {
    flags |= QUICLY_FLEXICAST_SAMPLE_APP_LIMITED;
  }
  quicly_flexicast_send_context_t ctx = {
      .pacing_rate_bytes_per_second = flow->pacing_rate_bytes_per_second,
      .physical_fanout = physical_fanout != 0 ? physical_fanout : 1U,
      .flags = flags};
  (void)quicly_flexicast_mark_submitted(flow->crypto,
                                        recipient ? recipient->conn->id : 0,
                                        queued->packet_number, now, &ctx);
  tf_record_delivery_submission(t, flow, recipient, !queued->counted);
  if (mcbbr || !queued->counted) {
    flow->pacing_tokens = queued->packet_size <= flow->pacing_tokens
                              ? flow->pacing_tokens - queued->packet_size
                              : 0;
    if (t->flexicast_cc_aggregate_rate_limit != 0) {
      transport_flexicast_registry_t *registry = &t->flexicast;
      registry->pacing_tokens =
          queued->packet_size <= registry->pacing_tokens
              ? registry->pacing_tokens - queued->packet_size
              : 0;
      size_t size = t->limits.max_udp_payload_size;
      if (mcbbr && registry->pacing_tokens < size) {
        /* other flows can use spare credit during an idle interval; only
         * postpone readiness when less than a full datagram remains */
        uint64_t wait = token_wait_ms(size - registry->pacing_tokens,
                                      registry->pacing_remainder, 1,
                                      t->flexicast_cc_aggregate_rate_limit);
        int64_t base = registry->pacing_last_refill_ms;
        registry->shared_credit_ready_at_ms =
            wait > (uint64_t)(INT64_MAX - base) ? INT64_MAX
                                                : base + (int64_t)wait;
      }
    }
  }
  if (!queued->counted) {
    t->stats.flexicast_packets_sent++;
    t->stats.flexicast_paced_packets++;
    queued->counted = true;
  }
  if (!recipient)
    t->stats.flexicast_native_packets_sent++;
  flow->last_payload_sent_ms = now;
}

/* queue head keeps the same slot across retries and key rotations;
 * bits follow subscribers when entries are moved by member_remove */
static void snapshot_recipients(transport_t *t,
                                transport_flexicast_flow_t *flow,
                                transport_flexicast_queued_payload_t *queued) {
  size_t slot = (flow->data_queue.head + flow->data_queue.count) %
                flow->data_queue.capacity;
  uint64_t bit = UINT64_C(1) << (slot % 64);
  queued->recipient_epoch = flow->cc_membership_epoch;
  for (size_t i = 0; i < flow->member_count; ++i) {
    transport_flexicast_member_t *member = &flow->members[i];
    uint64_t *pending = &member->pending_payloads[slot / 64];
    if (member->listening && transport_publish_recipient_eligible(
                                 t, member->conn, &flow->track_id)) {
      *pending |= bit;
      queued->recipient_count++;
    } else {
      *pending &= ~bit;
      if (member->joined)
        queued->replicated = true;
    }
  }
}

static void exclude_recipient(transport_flexicast_flow_t *flow,
                              transport_flexicast_queued_payload_t *queued,
                              transport_flexicast_member_t *member) {
  size_t slot = flow->data_queue.head;
  member->pending_payloads[slot / 64] &= ~(UINT64_C(1) << (slot % 64));
  queued->cc_sample_flags |= QUICLY_FLEXICAST_SAMPLE_MIXED;
  queued->replicated = true;
  if (queued->packet_ready) {
    int complete;
    (void)quicly_flexicast_abandon_datagram(flow->crypto, member->conn->id,
                                            queued->packet_number, &complete);
  }
}

static flexicast_dispatch_result_t
recheck_queued_recipients(transport_t *t, transport_flexicast_flow_t *flow,
                          transport_flexicast_queued_payload_t *queued,
                          size_t word, uint64_t bit) {
  bool has_recipient = false;
  queued->waiting_for_members = false;
  for (size_t i = 0; i < flow->member_count; ++i) {
    transport_flexicast_member_t *member = &flow->members[i];
    if (!(member->pending_payloads[word] & bit)) {
      /* joiner may already hold key before LISTEN arrives */
      if (member->joined)
        queued->replicated = true;
      continue;
    }
    if (!transport_publish_recipient_eligible(t, member->conn,
                                              &flow->track_id)) {
      exclude_recipient(flow, queued, member);
      continue;
    }
    /* quicly captures ACK obligations when it encrypts */
    queued->waiting_for_members |= !member->listening;
    has_recipient = true;
  }
  if (!has_recipient)
    return FLEXICAST_DISPATCH_OK;
  return queued->waiting_for_members ? FLEXICAST_DISPATCH_BLOCKED
                                     : FLEXICAST_DISPATCH_FAILED;
}

static flexicast_dispatch_result_t
prepare_protected_packet(transport_t *t, transport_flexicast_flow_t *flow,
                         transport_flexicast_queued_payload_t *queued,
                         size_t word, uint64_t bit, int64_t now) {
  size_t size = pacing_cost(flow, queued->size);
  if (size == 0 || size > t->limits.max_udp_payload_size ||
      size > queued->packet_capacity)
    return FLEXICAST_DISPATCH_FAILED;
  if (size > pacing_available(t, flow))
    return FLEXICAST_DISPATCH_BLOCKED;
  int result = quicly_flexicast_send_datagram(
      flow->crypto, ptls_iovec_init(queued->data, queued->size), queued->packet,
      size, &queued->packet_size, &queued->packet_number, now);
  if (result != QUICLY_FLEXICAST_OK) {
    if (result == QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED)
      return tf_rotate_source_flow(t, flow) ? FLEXICAST_DISPATCH_BLOCKED
                                            : FLEXICAST_DISPATCH_FAILED;
    if (result == QUICLY_FLEXICAST_ERROR_SEND_WINDOW ||
        result == QUICLY_FLEXICAST_ERROR_NO_MEMBERS) {
      flow->dispatch_retry_at_ms = now + 10;
      return FLEXICAST_DISPATCH_BLOCKED;
    }
    return FLEXICAST_DISPATCH_FAILED;
  }
  queued->packet_ready = true;
  queued->packet_epoch = flow->key_epoch;
  for (size_t i = 0; i < flow->member_count; i++) {
    transport_flexicast_member_t *member = &flow->members[i];
    if (!(member->pending_payloads[word] & bit)) {
      int complete;
      (void)quicly_flexicast_abandon_datagram(flow->crypto, member->conn->id,
                                              queued->packet_number, &complete);
    }
  }
  return FLEXICAST_DISPATCH_OK;
}

static flexicast_dispatch_result_t
dispatch_payload(transport_t *t, transport_flexicast_flow_t *flow,
                 transport_flexicast_queued_payload_t *queued,
                 bool app_limited) {
  if (flow->listening_count == 0)
    return FLEXICAST_DISPATCH_BLOCKED;
  bool mcbbr = transport_group_cc_mcbbr_is(flow->cc);
  int64_t now = transport_now_ms(t);
  if (now < flow->dispatch_retry_at_ms)
    return FLEXICAST_DISPATCH_BLOCKED;
  if (queued->recipient_count == 0)
    return FLEXICAST_DISPATCH_OK;
  if (queued->packet_ready && queued->packet_epoch != flow->key_epoch) {
    queued->packet_ready = false;
    queued->packet_size = 0;
    queued->next_member = 0;
    queued->counted = false;
    queued->cc_sample_flags |= QUICLY_FLEXICAST_SAMPLE_MIXED;
  }
  size_t word = flow->data_queue.head / 64;
  uint64_t bit = UINT64_C(1) << (flow->data_queue.head % 64);
  bool membership_changed =
      queued->recipient_epoch != flow->cc_membership_epoch;
  if (membership_changed) {
    queued->cc_sample_flags |= QUICLY_FLEXICAST_SAMPLE_MIXED;
    if (queued->packet_ready)
      queued->replicated = true;
    queued->recipient_epoch = flow->cc_membership_epoch;
  }
  /* direct sends just took a snapshot; on queued retry QUIC may have closed
   * without LISTEN/LEAVE, so recheck recipients before first send */
  bool resuming_replicas = queued->counted && !membership_changed;
  if (flow->data_queue.count != 0 && !resuming_replicas) {
    flexicast_dispatch_result_t check =
        recheck_queued_recipients(t, flow, queued, word, bit);
    if (check != FLEXICAST_DISPATCH_FAILED)
      return check;
  }
  if (!queued->packet_ready) {
    flexicast_dispatch_result_t prep =
        prepare_protected_packet(t, flow, queued, word, bit, now);
    if (prep != FLEXICAST_DISPATCH_OK)
      return prep;
  }

  /* snapshot local addresses for live socket lookup */
  struct sockaddr_storage local_addrs[TRANSPORT_MAX_PATHS];
  for (size_t i = 0; i < t->socket_count; i++)
    local_addrs[i] = t->sockets[i].local_addr;
  if (!queued->replicated && flow->native_multicast &&
      t->flexicast_native_source && !t->flexicast_interface_down) {
    struct sockaddr *group = (struct sockaddr *)&t->flexicast_group_addr;
    struct sockaddr_storage source = multicast_source_address(t);
    size_t fd_index = transport_path_socket_for_source(
        local_addrs, t->socket_count, (struct sockaddr *)&source);
    int result =
        submit_protected_packet(t, fd_index, group, (struct sockaddr *)&source,
                                true, flow_ecn_mark(t, NULL), queued);
    if (result > 0) {
      account_protected_packet(t, flow, queued, NULL, 1U, app_limited);
      return FLEXICAST_DISPATCH_OK;
    }
    if (result == 0) {
      if (mcbbr)
        queued->cc_sample_flags |= QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED;
      flow->dispatch_retry_at_ms = now + 10;
      return FLEXICAST_DISPATCH_BLOCKED;
    }
    t->stats.flexicast_fallbacks++;
  }
  queued->replicated = true;
  while (queued->next_member < flow->member_count) {
    transport_flexicast_member_t *member = &flow->members[queued->next_member];
    if (!(member->pending_payloads[word] & bit)) {
      queued->next_member++;
      continue;
    }
    if (resuming_replicas && !transport_publish_recipient_eligible(
                                 t, member->conn, &flow->track_id)) {
      exclude_recipient(flow, queued, member);
      queued->next_member++;
      continue;
    }
    if (mcbbr && queued->packet_size > pacing_available(t, flow))
      return FLEXICAST_DISPATCH_BLOCKED;
    struct sockaddr_storage destination, peer_source;
    size_t fd_index = transport_path_select_peer_egress(
        member->conn->quic, local_addrs, t->socket_count, &destination,
        &peer_source);
    int result = submit_protected_packet(
        t, fd_index, (const struct sockaddr *)&destination,
        (const struct sockaddr *)&peer_source, false,
        flow_ecn_mark(t, member->conn), queued);
    if (result == 0) {
      if (mcbbr)
        queued->cc_sample_flags |= QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED;
      flow->dispatch_retry_at_ms = now + 10;
      return FLEXICAST_DISPATCH_BLOCKED;
    }
    if (result > 0) {
      account_protected_packet(t, flow, queued, member, queued->recipient_count,
                               app_limited);
    } else {
      if (mcbbr)
        queued->cc_sample_flags |= QUICLY_FLEXICAST_SAMPLE_MIXED;
      int complete;
      (void)quicly_flexicast_abandon_datagram(flow->crypto, member->conn->id,
                                              queued->packet_number, &complete);
      t->stats.flexicast_fallbacks++;
      t->stats.flexicast_pacing_dropped++;
    }
    member->pending_payloads[word] &= ~bit;
    queued->next_member++;
  }
  /* rescan once in case member removal swapped a survivor into an earlier slot
   */
  for (size_t i = 0; i < flow->member_count; i++) {
    transport_flexicast_member_t *member = &flow->members[i];
    if (member->pending_payloads[word] & bit) {
      queued->next_member = i;
      return FLEXICAST_DISPATCH_BLOCKED;
    }
  }
  return FLEXICAST_DISPATCH_OK;
}

bool transport_flexicast_can_queue(const transport_t *t,
                                   const transport_flexicast_flow_t *flow,
                                   size_t packets, size_t bytes) {
  if (!t || !flow || packets > TRANSPORT_FLEXICAST_QUEUE_CAPACITY ||
      flow->data_queue.count > TRANSPORT_FLEXICAST_QUEUE_CAPACITY ||
      packets > TRANSPORT_FLEXICAST_QUEUE_CAPACITY - flow->data_queue.count ||
      bytes > t->limits.max_egress_bytes_per_socket ||
      flow->data_queue.bytes > t->limits.max_egress_bytes_per_socket ||
      bytes > t->limits.max_egress_bytes_per_socket - flow->data_queue.bytes)
    return false;
  return true;
}

bool tf_enqueue_payload(transport_t *t, transport_flexicast_flow_t *flow,
                        ptls_iovec_t payload) {
  if (!t || !flow || !flow->source || !flow->crypto || !payload.base ||
      flow->listening_count == 0)
    return false;
  size_t cost = pacing_cost(flow, payload.len);
  if (cost == 0 || cost > t->limits.max_udp_payload_size)
    return false;
  bool mcbbr = transport_group_cc_mcbbr_is(flow->cc);
  int64_t now = transport_now_ms(t);
  transport_flexicast_queued_payload_t direct = {0};
  if (flow->data_queue.capacity == 0 || payload.len > SIZE_MAX - cost ||
      !transport_flexicast_can_queue(t, flow, 1, payload.len)) {
    t->stats.flexicast_pacing_backpressure++;
    return false;
  }
  snapshot_recipients(t, flow, &direct);
  if (mcbbr && flow->data_queue.count == 0) {
    if (flow->cc_idle_ready_at_ms > 0 && flow->cc_idle_ready_at_ms < now &&
        t->flexicast.shared_credit_ready_at_ms < now)
      direct.cc_sample_flags = QUICLY_FLEXICAST_SAMPLE_APP_LIMITED;
    flow->cc_idle_ready_at_ms = 0;
  }
  if (flow->data_queue.count == 0 && cost <= sizeof(t->send_buffer) &&
      tf_reserve_queue_slots(flow, 1, payload.len + cost)) {
    refresh_pacer_at(t, flow, now);
    if (cost <= pacing_available(t, flow)) {
      direct.data = payload.base;
      direct.size = payload.len;
      direct.packet = t->send_buffer;
      direct.packet_capacity = sizeof(t->send_buffer);
      flexicast_dispatch_result_t result =
          dispatch_payload(t, flow, &direct, true);
      if (result == FLEXICAST_DISPATCH_OK) {
        if (mcbbr)
          record_mcbbr_idle(t, flow, transport_now_ms(t));
        return true;
      }
      if (result == FLEXICAST_DISPATCH_FAILED) {
        t->stats.flexicast_pacing_dropped++;
        return false;
      }
      return queue_push_slot(flow, payload, cost, &direct);
    }
  }
  if (flow->data_queue.count == 0)
    t->flexicast.cohort_count = 0;
  return queue_push_slot(flow, payload, cost, &direct);
}

void tf_drain_paced_payloads(transport_t *t, transport_flexicast_flow_t *flow) {
  if (flow->data_queue.count == 0)
    return;
  if (transport_flexicast_listening_members(flow) == 0) {
    bool awaiting_rekey_ready = false;
    for (size_t i = 0; i < flow->member_count; i++)
      awaiting_rekey_ready |= flow->members[i].conn && flow->members[i].joined;
    if (!awaiting_rekey_ready)
      t->stats.flexicast_pacing_dropped += tf_clear_flow_queue(flow);
    return;
  }
  refresh_pacer_at(t, flow, transport_now_ms(t));
  while (flow->data_queue.count != 0) {
    transport_flexicast_queued_payload_t *queued =
        queue_front(&flow->data_queue);
    if (!queued || !queued->data)
      break;
    size_t cost = pacing_cost(flow, queued->size);
    if (!queued->counted && cost > pacing_available(t, flow))
      break;
    flexicast_dispatch_result_t result =
        dispatch_payload(t, flow, queued, flow->data_queue.count <= 1);
    if (result == FLEXICAST_DISPATCH_BLOCKED)
      break;
    if (result == FLEXICAST_DISPATCH_FAILED)
      t->stats.flexicast_pacing_dropped++;
    queue_pop(&flow->data_queue);
    if (result != FLEXICAST_DISPATCH_OK)
      break;
  }
  if (flow->data_queue.count == 0 && transport_group_cc_mcbbr_is(flow->cc))
    record_mcbbr_idle(t, flow, transport_now_ms(t));
}

bool transport_flexicast_track_ready(transport_t *t,
                                     const moq_track_id_t *track) {
  if (!t || !track)
    return false;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active || !flow->source ||
        !transport_track_id_equal(&flow->track_id, track) ||
        transport_flexicast_listening_members(flow) == 0)
      continue;
    refresh_pacer_at(t, flow, transport_now_ms(t));
    if (flow->data_queue.count >=
            TRANSPORT_FLEXICAST_QUEUE_CAPACITY * 3U / 4U ||
        flow->data_queue.bytes >=
            t->limits.max_egress_bytes_per_socket * 3U / 4U ||
        (flow->data_queue.count != 0 &&
         pacing_available(t, flow) < t->limits.max_udp_payload_size))
      return false;
  }
  return true;
}

int64_t transport_flexicast_get_first_timeout(transport_t *t) {
  if (!t || !t->flexicast_enabled)
    return INT64_MAX;
  int64_t now = transport_now_ms(t);
  int64_t first_timeout = INT64_MAX;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active || flow->source)
      continue;
    if ((flow->ready_pending && flow->crypto) ||
        (flow->binding_received && flow->announcement_received &&
         !flow->join_sent && !flow->multicast_unavailable)) {
      int64_t retry = now > INT64_MAX - 10 ? INT64_MAX : now + 10;
      if (retry < first_timeout)
        first_timeout = retry;
    }
    if (!flow->crypto)
      continue;
    int64_t deadline = quicly_flexicast_get_ack_deadline(flow->crypto);
    if (deadline < first_timeout)
      first_timeout = deadline;
  }
  if (!t->is_server)
    return first_timeout;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active || !flow->source || !flow->crypto)
      continue;
    if (flow->rekey_pending && flow->rekey_ready_at_ms < first_timeout)
      first_timeout = flow->rekey_ready_at_ms;
    for (size_t member_index = 0; member_index < flow->member_count;
         member_index++) {
      const transport_flexicast_member_t *member = &flow->members[member_index];
      int64_t feedback_deadline = tf_member_feedback_deadline(flow, member);
      if (feedback_deadline < first_timeout)
        first_timeout = feedback_deadline;
      if (member->joined && !member->listening &&
          member->ready_deadline_ms > 0 &&
          member->ready_deadline_ms < first_timeout)
        first_timeout = member->ready_deadline_ms;
    }
    int64_t cc_deadline = tf_cc_deadline(flow);
    if (cc_deadline < first_timeout)
      first_timeout = cc_deadline;
    if (flow->data_queue.count == 0 ||
        transport_flexicast_listening_members(flow) == 0)
      continue;
    transport_flexicast_queued_payload_t *payload =
        queue_front(&flow->data_queue);
    if (!payload || payload->waiting_for_members)
      continue;
    int64_t timeout =
        pacing_ready_at(t, flow, pacing_cost(flow, payload->size), now);
    if (timeout < first_timeout)
      first_timeout = timeout;
  }
  return first_timeout;
}
