#include "transport_flexicast.h"

#include "portable_sockets.h"
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

static bool queue_push(transport_flexicast_queue_t *queue,
                       const transport_flexicast_queued_payload_t *payload) {
  if (!queue || !payload || !payload->data || queue->count >= queue->capacity ||
      payload->size > SIZE_MAX - queue->bytes)
    return false;
  if (!queue->entries) {
    if (queue->capacity > SIZE_MAX / sizeof(*queue->entries))
      return false;
    queue->entries = calloc(queue->capacity, sizeof(*queue->entries));
    if (!queue->entries)
      return false;
  }
  size_t tail = (queue->head + queue->count) % queue->capacity;
  queue->entries[tail] = *payload;
  queue->count++;
  queue->bytes += payload->size;
  return true;
}

static void queue_pop(transport_flexicast_queue_t *queue) {
  transport_flexicast_queued_payload_t *payload = queue_front(queue);
  if (!payload)
    return;
  queue->bytes =
      payload->size <= queue->bytes ? queue->bytes - payload->size : 0;
  free(payload->data);
  free(payload->packet);
  memset(payload, 0, sizeof(*payload));
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
  while (queue->count != 0)
    queue_pop(queue);
  free(queue->entries);
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

static size_t active_sender_count(const transport_t *t,
                                  const transport_flexicast_flow_t *flow,
                                  int64_t now) {
  size_t count = 0;
  int64_t active_window =
      2 * (int64_t)(t->flexicast_cc_feedback_timeout_ms != 0
                        ? t->flexicast_cc_feedback_timeout_ms
                        : 1000U);
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    const transport_flexicast_flow_t *candidate = &t->flexicast.flows[i];
    if (!candidate->active || !candidate->source || !candidate->crypto ||
        transport_flexicast_listening_members(candidate) == 0 ||
        (candidate != flow && candidate->data_queue.count == 0 &&
         (candidate->last_payload_sent_ms == 0 ||
          now - candidate->last_payload_sent_ms > active_window)))
      continue;
    count++;
  }
  return count != 0 ? count : 1;
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
                             uint64_t suggested) {
  uint64_t minimum = t->limits.max_udp_payload_size * 4U;
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
  size_t active = active_sender_count(t, flow, now);
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
  uint64_t aggregate = t->flexicast_cc_aggregate_rate_limit;
  if (aggregate != 0 && rate > aggregate / active) {
    numerator = aggregate;
    divisor = (uint32_t)active;
    rate = numerator / divisor + (numerator % divisor != 0);
  }
  uint64_t burst = pacing_burst(t, rate, cc_output.burst_bytes);
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
    uint64_t aggregate_burst = pacing_burst(t, aggregate, 0);
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
  remainder = t->flexicast.pacing_remainder;
  refill = t->flexicast.pacing_last_refill_ms;
  refill_tokens(&shared, &remainder, &refill, t->flexicast.pacing_rate, 1,
                t->flexicast.pacing_burst, now);
  uint64_t delay = 0;
  if (cost > tokens ||
      (t->flexicast_cc_aggregate_rate_limit != 0 && cost > shared)) {
    if (flow->pacing_rate_numerator == 0)
      return INT64_MAX;
    uint64_t deficit = cost > tokens ? cost - tokens : 0;
    uint64_t needed = deficit * 1000U * flow->pacing_rate_divisor;
    delay = needed / flow->pacing_rate_numerator +
            (needed % flow->pacing_rate_numerator != 0);
    if (t->flexicast_cc_aggregate_rate_limit != 0 && cost > shared) {
      needed = (cost - shared) * 1000U;
      uint64_t shared_delay =
          needed / t->flexicast_cc_aggregate_rate_limit +
          (needed % t->flexicast_cc_aggregate_rate_limit != 0);
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

static size_t pacing_cost(const transport_flexicast_flow_t *flow,
                          size_t payload_size) {
  return quicly_flexicast_datagram_size(flow->crypto, payload_size);
}

typedef enum {
  FLEXICAST_DISPATCH_OK,
  FLEXICAST_DISPATCH_BLOCKED,
  FLEXICAST_DISPATCH_FAILED,
} flexicast_dispatch_result_t;

static int
submit_protected_packet(transport_t *t, size_t socket_index,
                        const struct sockaddr *destination,
                        const struct sockaddr *source,
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
  t->host_callback_active = true;
  ssize_t sent = t->drive_host.send(
      t->drive_host.context, &path,
      source ? source : (const struct sockaddr *)&path.local, destination,
      destination_len,
      t->flexicast_interface_index ? t->flexicast_interface_index
                                   : path.interface_index,
      2, 0, &vec, 1);
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
                         transport_flexicast_member_t *recipient) {
  int64_t now = transport_now_ms(t);
  (void)quicly_flexicast_mark_submitted(flow->crypto,
                                        recipient ? recipient->conn->id : 0,
                                        queued->packet_number, now);
  tf_record_delivery_submission(t, flow, recipient, !queued->counted);
  if (!queued->counted) {
    t->stats.flexicast_packets_sent++;
    t->stats.flexicast_paced_packets++;
    queued->counted = true;
  }
  if (!recipient)
    t->stats.flexicast_native_packets_sent++;
  flow->last_payload_sent_ms = now;
  flow->pacing_tokens -= queued->packet_size;
  if (t->flexicast_cc_aggregate_rate_limit != 0)
    t->flexicast.pacing_tokens -= queued->packet_size;
}

static flexicast_dispatch_result_t
dispatch_payload(transport_t *t, transport_flexicast_flow_t *flow,
                 transport_flexicast_queued_payload_t *queued) {
  if (flow->rekey_pending)
    return FLEXICAST_DISPATCH_BLOCKED;
  int64_t now = transport_now_ms(t);
  if (now < flow->dispatch_retry_at_ms)
    return FLEXICAST_DISPATCH_BLOCKED;
  if (queued->packet && queued->packet_epoch != flow->key_epoch) {
    free(queued->packet);
    queued->packet = NULL;
    queued->next_member = 0;
    queued->counted = false;
    /* keep interrupted replicated packet replicated across key rotation */
    queued->replicated = true;
  }
  if (!queued->packet) {
    for (size_t i = 0; i < flow->member_count; i++) {
      if (flow->members[i].joined && !flow->members[i].listening) {
        flow->dispatch_retry_at_ms = now + 10;
        return FLEXICAST_DISPATCH_BLOCKED;
      }
    }
    size_t size = pacing_cost(flow, queued->size);
    if (size == 0 || size > t->limits.max_udp_payload_size)
      return FLEXICAST_DISPATCH_FAILED;
    if (size > pacing_available(t, flow))
      return FLEXICAST_DISPATCH_BLOCKED;
    queued->packet = malloc(size);
    if (!queued->packet)
      return FLEXICAST_DISPATCH_FAILED;
    int result = quicly_flexicast_send_datagram_at(
        flow->crypto, ptls_iovec_init(queued->data, queued->size),
        queued->packet, size, &queued->packet_size, &queued->packet_number,
        now);
    if (result != QUICLY_FLEXICAST_OK) {
      free(queued->packet);
      queued->packet = NULL;
      if (result == QUICLY_FLEXICAST_ERROR_SEND_WINDOW) {
        flow->dispatch_retry_at_ms = now + 10;
        return FLEXICAST_DISPATCH_BLOCKED;
      }
      return FLEXICAST_DISPATCH_FAILED;
    }
    queued->packet_epoch = flow->key_epoch;
    if (queued->delivery_id == 0) {
      if (++flow->next_payload_delivery_id == 0) {
        flow->next_payload_delivery_id = 1;
        for (size_t i = 0; i < flow->member_count; i++)
          flow->members[i].payload_delivery_id = 0;
      }
      queued->delivery_id = flow->next_payload_delivery_id;
    }
    for (size_t i = 0; i < flow->member_count; i++) {
      transport_flexicast_member_t *member = &flow->members[i];
      if (member->payload_delivery_id == queued->delivery_id ||
          !transport_publish_recipient_eligible(t, member->conn,
                                                &flow->track_id)) {
        int complete;
        (void)quicly_flexicast_abandon_datagram(
            flow->crypto, member->conn->id, queued->packet_number, &complete);
      }
    }
  }

  /* snapshot local addresses for live socket lookup */
  struct sockaddr_storage local_addrs[TRANSPORT_MAX_PATHS];
  for (size_t i = 0; i < t->socket_count; i++)
    local_addrs[i] = t->sockets[i].local_addr;
  if (!queued->replicated && flow->native_multicast &&
      t->flexicast_native_source) {
    struct sockaddr *group = (struct sockaddr *)&t->flexicast_group_addr;
    struct sockaddr_storage source = multicast_source_address(t);
    size_t fd_index = transport_path_socket_for_source(
        local_addrs, t->socket_count, (struct sockaddr *)&source);
    int result = submit_protected_packet(t, fd_index, group,
                                         (struct sockaddr *)&source, queued);
    if (result > 0) {
      account_protected_packet(t, flow, queued, NULL);
      return FLEXICAST_DISPATCH_OK;
    }
    if (result == 0) {
      flow->dispatch_retry_at_ms = now + 10;
      return FLEXICAST_DISPATCH_BLOCKED;
    }
    t->stats.flexicast_fallbacks++;
  }
  queued->replicated = true;
  while (queued->next_member < flow->member_count) {
    transport_flexicast_member_t *member = &flow->members[queued->next_member];
    if (!member->listening ||
        member->payload_delivery_id == queued->delivery_id ||
        !transport_publish_recipient_eligible(t, member->conn,
                                              &flow->track_id)) {
      queued->next_member++;
      continue;
    }
    if (queued->packet_size > pacing_available(t, flow))
      return FLEXICAST_DISPATCH_BLOCKED;
    struct sockaddr_storage destination;
    size_t fd_index = transport_path_socket_for_peer(
        member->conn->quic, local_addrs, t->socket_count, &destination);
    int result = submit_protected_packet(
        t, fd_index, (struct sockaddr *)&destination, NULL, queued);
    if (result == 0) {
      flow->dispatch_retry_at_ms = now + 10;
      return FLEXICAST_DISPATCH_BLOCKED;
    }
    if (result > 0) {
      account_protected_packet(t, flow, queued, member);
    } else {
      int complete;
      (void)quicly_flexicast_abandon_datagram(flow->crypto, member->conn->id,
                                              queued->packet_number, &complete);
      t->stats.flexicast_fallbacks++;
      t->stats.flexicast_pacing_dropped++;
    }
    member->payload_delivery_id = queued->delivery_id;
    queued->next_member++;
  }
  /* rescan once in case member removal swapped a survivor into an earlier slot
   */
  for (size_t i = 0; i < flow->member_count; i++) {
    transport_flexicast_member_t *member = &flow->members[i];
    if (member->listening &&
        member->payload_delivery_id != queued->delivery_id &&
        transport_publish_recipient_eligible(t, member->conn,
                                             &flow->track_id)) {
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

static bool queue_payload(transport_t *t, transport_flexicast_flow_t *flow,
                          ptls_iovec_t payload) {
  if (payload.len > SIZE_MAX - 128U ||
      !transport_flexicast_can_queue(t, flow, 1, payload.len)) {
    t->stats.flexicast_pacing_backpressure++;
    return false;
  }
  uint8_t *copy = malloc(payload.len);
  if (!copy)
    return false;
  memcpy(copy, payload.base, payload.len);
  transport_flexicast_queued_payload_t queued = {.data = copy,
                                                 .size = payload.len};
  if (!queue_push(&flow->data_queue, &queued)) {
    free(copy);
    return false;
  }
  return true;
}

bool tf_enqueue_payload(transport_t *t, transport_flexicast_flow_t *flow,
                        ptls_iovec_t payload) {
  if (!t || !flow || !flow->source || !flow->crypto || !payload.base)
    return false;
  size_t cost = pacing_cost(flow, payload.len);
  return cost != 0 && cost <= t->limits.max_udp_payload_size &&
         flow->listening_count != 0 && queue_payload(t, flow, payload);
}

void tf_drain_paced_payloads(transport_t *t, transport_flexicast_flow_t *flow) {
  if (flow->data_queue.count == 0 || flow->rekey_pending)
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
    if (cost > pacing_available(t, flow))
      break;
    flexicast_dispatch_result_t result = dispatch_payload(t, flow, queued);
    if (result == FLEXICAST_DISPATCH_BLOCKED)
      break;
    if (result == FLEXICAST_DISPATCH_FAILED)
      t->stats.flexicast_pacing_dropped++;
    queue_pop(&flow->data_queue);
    if (result != FLEXICAST_DISPATCH_OK)
      break;
  }
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
    if (!flow->active || flow->source || !flow->crypto)
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
    if (flow->rekey_pending) {
      if (flow->rekey_ready_at_ms < first_timeout)
        first_timeout = flow->rekey_ready_at_ms;
      continue;
    }
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
    if (flow->feedback_outstanding_count != 0) {
      quicly_flexicast_cc_output_t output;
      quicly_flexicast_cc_get_flow_output(flow->crypto, &output);
      if (output.next_timeout < first_timeout)
        first_timeout = output.next_timeout;
    }
    if (flow->data_queue.count == 0 ||
        transport_flexicast_listening_members(flow) == 0)
      continue;
    transport_flexicast_queued_payload_t *payload =
        queue_front(&flow->data_queue);
    if (!payload)
      continue;
    int64_t timeout =
        pacing_ready_at(t, flow, pacing_cost(flow, payload->size), now);
    if (timeout < first_timeout)
      first_timeout = timeout;
  }
  return first_timeout;
}
