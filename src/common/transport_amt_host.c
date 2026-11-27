/* classic AMT gateway I/O belongs to the polling host, not the engine */
#include "transport_amt_host.h"
#include "transport_poll_host.h"
#include "transport_protocol.h"
#include "nanoamt/openssl.h"
#include "nanoamt/posix.h"
#include <stdlib.h>
#include <string.h>

#define AMT_SETUP_MS 15000
#define AMT_RECEIVE_BUDGET 128U

typedef struct {
  nanoamt_posix *io;
  uint8_t ip_version, source[16], group[16];
  uint16_t port;
  size_t references;
  int64_t setup_deadline;
  bool joined;
} amt_membership_t;
struct transport_amt_host {
  nanoamt_endpoint relay;
  amt_membership_t memberships[TRANSPORT_MAX_AMT_MEMBERSHIPS];
  size_t cursor;
  bool backlog;
};
static struct transport_amt_host *amt_host(transport_t *t) {
  transport_poll_host_t *host = t ? t->drive_host.context : NULL;
  return host ? host->amt : NULL;
}
struct transport_amt_host *transport_amt_host_new(const transport_config_t *c) {
  if (!c || !c->enable_flexicast || !c->flexicast_relay_address ||
      c->flexicast_group || c->flexicast_group_port || c->flexicast_interface)
    return NULL;
  struct transport_amt_host *host = calloc(1, sizeof(*host));
  if (!host)
    return NULL;
  if (inet_pton(AF_INET, c->flexicast_relay_address, host->relay.ip) == 1)
    host->relay.ip_version = 4;
  else if (inet_pton(AF_INET6, c->flexicast_relay_address, host->relay.ip) == 1)
    host->relay.ip_version = 6;
  else {
    free(host);
    return NULL;
  }
  host->relay.port =
      c->flexicast_relay_port ? c->flexicast_relay_port : NANOAMT_PORT;
  return host;
}
void transport_amt_host_free(struct transport_amt_host *host) {
  if (!host)
    return;
  for (size_t i = 0; i < TRANSPORT_MAX_AMT_MEMBERSHIPS; ++i)
    nanoamt_posix_close(host->memberships[i].io);
  free(host);
}
static amt_membership_t *membership(struct transport_amt_host *host,
                                    const transport_flexicast_flow_t *flow) {
  if (host)
    for (size_t i = 0; i < TRANSPORT_MAX_AMT_MEMBERSHIPS; ++i)
      if (host->memberships[i].io &&
          host->memberships[i].ip_version == flow->ip_version &&
          host->memberships[i].port == flow->udp_port &&
          !memcmp(host->memberships[i].source, flow->source_ip,
                  flow->ip_version == 4 ? 4U : 16U) &&
          !memcmp(host->memberships[i].group, flow->group_ip,
                  flow->ip_version == 4 ? 4U : 16U))
        return &host->memberships[i];
  return NULL;
}
bool transport_amt_host_join(transport_t *t, transport_flexicast_flow_t *flow) {
  struct transport_amt_host *host = amt_host(t);
  if (!host || !flow)
    return false;
  amt_membership_t *existing = membership(host, flow);
  if (existing) {
    existing->references++;
    return true;
  }
  for (size_t i = 0; i < TRANSPORT_MAX_AMT_MEMBERSHIPS; ++i) {
    amt_membership_t *m = &host->memberships[i];
    if (m->io)
      continue;
    nanoamt_config config = {.discovery = host->relay,
                             .ip_version = flow->ip_version,
                             .port = flow->udp_port,
                             .random_bytes = nanoamt_openssl_random};
    memcpy(config.source, flow->source_ip, 16);
    memcpy(config.group, flow->group_ip, 16);
    int64_t now = transport_now_ms(t);
    m->io = nanoamt_posix_open(&config, now);
    if (!m->io)
      return false;
    m->ip_version = flow->ip_version;
    memcpy(m->source, flow->source_ip, 16);
    memcpy(m->group, flow->group_ip, 16);
    m->port = flow->udp_port;
    m->references = 1;
    m->setup_deadline =
        now > INT64_MAX - AMT_SETUP_MS ? INT64_MAX : now + AMT_SETUP_MS;
    return true;
  }
  return false;
}
void transport_amt_host_leave(transport_t *t,
                              transport_flexicast_flow_t *flow) {
  amt_membership_t *m = membership(amt_host(t), flow);
  if (!m || --m->references)
    return;
  int64_t now = transport_now_ms(t);
  (void)nanoamt_posix_leave(m->io, now);
  (void)nanoamt_posix_send(m->io, now);
  nanoamt_posix_close(m->io);
  *m = (amt_membership_t){0};
}
bool transport_amt_host_ready(transport_t *t,
                              const transport_flexicast_flow_t *flow) {
  amt_membership_t *m = membership(amt_host(t), flow);
  return m && nanoamt_posix_is_joined(m->io);
}
size_t transport_amt_host_memberships(transport_t *t) {
  struct transport_amt_host *host = amt_host(t);
  size_t count = 0;
  if (host)
    for (size_t i = 0; i < TRANSPORT_MAX_AMT_MEMBERSHIPS; ++i)
      count += host->memberships[i].io != NULL;
  return count;
}
int64_t transport_amt_host_timeout(transport_t *t) {
  struct transport_amt_host *host = amt_host(t);
  int64_t next = INT64_MAX;
  if (!host)
    return next;
  if (host->backlog)
    return transport_now_ms(t);
  for (size_t i = 0; i < TRANSPORT_MAX_AMT_MEMBERSHIPS; ++i) {
    amt_membership_t *m = &host->memberships[i];
    if (!m->io)
      continue;
    int64_t at = nanoamt_posix_next_timeout(m->io);
    if (!m->joined && m->setup_deadline < at)
      at = m->setup_deadline;
    if (at < next)
      next = at;
  }
  return next;
}
size_t transport_amt_host_poll(transport_t *t, struct pollfd *fds,
                               size_t capacity) {
  struct transport_amt_host *host = amt_host(t);
  size_t count = 0;
  if (host)
    for (size_t i = 0; i < TRANSPORT_MAX_AMT_MEMBERSHIPS && count < capacity;
         ++i) {
      nanoamt_posix *io = host->memberships[i].io;
      if (io)
        fds[count++] = (struct pollfd){
            .fd = nanoamt_posix_fd(io),
            .events = POLLIN | (nanoamt_posix_wants_write(io) ? POLLOUT : 0)};
    }
  return count;
}
static bool readable(int fd, const struct pollfd *fds, size_t count) {
  if (!fds)
    return true;
  for (size_t i = 0; i < count; ++i)
    if (fds[i].fd == fd)
      return (fds[i].revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0;
  return false;
}
/* validate membership, tuple, and flow ID before decrypting the borrowed packet
 */
static void deliver(transport_t *t, amt_membership_t *m,
                    nanoamt_packet *packet) {
  transport_flexicast_flow_t *flow = NULL;
  size_t address_size = m->ip_version == 4 ? 4U : 16U;
  uint64_t id = 0;
  if (packet->data && packet->size >= 9)
    for (size_t i = 1; i < 9; ++i)
      id = (id << 8) | packet->data[i];
  for (size_t i = 0; i < t->flexicast.capacity; ++i)
    if (t->flexicast.flows[i].active && !t->flexicast.flows[i].source &&
        t->flexicast.flows[i].flow_id == id) {
      flow = &t->flexicast.flows[i];
      break;
    }
  if (!flow || membership(amt_host(t), flow) != m || !packet->data ||
      packet->size < 9 || (packet->data[0] & 0xc0U) != 0x40U ||
      id != flow->flow_id || !flow->active || !flow->amt_tunnel ||
      !flow->membership_acquired || !flow->join_sent ||
      flow->multicast_unavailable || !flow->crypto || !flow->control_conn ||
      packet->protocol != 17 || packet->source.ip_version != flow->ip_version ||
      packet->destination.ip_version != flow->ip_version ||
      packet->destination.port != flow->udp_port ||
      memcmp(packet->source.ip, flow->source_ip, address_size) ||
      memcmp(packet->destination.ip, flow->group_ip, address_size)) {
    t->stats.flexicast_amt_packets_rejected++;
    return;
  }
  transport_conn_t *source = NULL;
  ptls_iovec_t payload = ptls_iovec_init(NULL, 0);
  if (!transport_flexicast_receive_packet_ecn(
          t, packet->data, packet->size, &source, &payload, packet->tos & 3U) ||
      source != flow->control_conn || !payload.base) {
    t->stats.flexicast_amt_packets_rejected++;
    return;
  }
  t->stats.flexicast_amt_packets_received++;
  if (!source->authenticated ||
      !transport_simulated_loss(t, t->simulated_loss_rate))
    transport_protocol_receive_datagram(source, payload, false);
}
static void failed(transport_t *t, amt_membership_t *m) {
  for (size_t i = 0; m->io && i < t->flexicast.capacity; ++i) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (flow->active && flow->amt_tunnel && membership(amt_host(t), flow) == m)
      transport_flexicast_tunnel_failed(t, flow);
  }
}
void transport_amt_host_service(transport_t *t, const struct pollfd *fds,
                                size_t count) {
  struct transport_amt_host *host = amt_host(t);
  if (!host)
    return;
  int64_t now = transport_now_ms(t);
  size_t budget = AMT_RECEIVE_BUDGET;
  bool scan = host->backlog || !fds;
  host->backlog = false;
  size_t start = host->cursor;
  host->cursor = (start + 1U) % TRANSPORT_MAX_AMT_MEMBERSHIPS;
  for (size_t n = 0; n < TRANSPORT_MAX_AMT_MEMBERSHIPS; ++n) {
    amt_membership_t *m =
        &host->memberships[(start + n) % TRANSPORT_MAX_AMT_MEMBERSHIPS];
    if (!m->io)
      continue;
    int rc = nanoamt_posix_send(m->io, now);
    if (rc < 0 || (!m->joined && now >= m->setup_deadline)) {
      failed(t, m);
      continue;
    }
    if (budget && (scan || readable(nanoamt_posix_fd(m->io), fds, count))) {
      while (m->io && budget) {
        nanoamt_packet packet;
        rc = nanoamt_posix_receive(m->io, now, &packet);
        if (rc == NANOAMT_AGAIN)
          break;
        --budget;
        if (rc < 0) {
          failed(t, m);
          break;
        }
        if (rc == NANOAMT_PACKET)
          deliver(t, m, &packet);
      }
      if (!budget)
        host->backlog = true;
    }
    if (m->io) {
      m->joined = nanoamt_posix_is_joined(m->io);
      if (nanoamt_posix_get_state(m->io) == NANOAMT_STATE_FAILED)
        failed(t, m);
    }
  }
}
