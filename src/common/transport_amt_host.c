/* AMT and AMTQ gateway I/O belongs to the polling host, not the engine */
#include "transport_amt_host.h"
#include "amtq_posix.h"
#include "nanoamt/openssl.h"
#include "nanoamt/posix.h"
#include "transport_poll_host.h"
#include "transport_protocol.h"
#include <stdlib.h>
#include <string.h>

#define AMT_SETUP_MS 15000
#define AMT_RECEIVE_BUDGET 128U
#define AMTQ_PENDING_PACKETS 64U
#define AMTQ_PENDING_BYTES (1024U * 1024U)

typedef struct {
  nanoamt_posix *io;
  transport_group_backend_t backend;
  uint8_t ip_version, source[16], group[16];
  uint16_t port;
  size_t references;
  uint64_t generation;
  int64_t setup_deadline;
  bool joined, failed;
} amt_membership_t;

typedef struct {
  transport_t *transport;
  uint8_t family;
  amtq_posix *amtq;
  struct {
    nanoamt_packet packet;
    uint64_t generation;
    uint16_t slot;
  } pending[AMTQ_PENDING_PACKETS];
  size_t pending_head, pending_count, pending_bytes;
} amtq_channel_t;

struct transport_amt_host {
  transport_group_backend_t backend;
  nanoamt_endpoint relay;
  uint16_t amtq_port;
  bool amtq_reliable;
  bool allow_insecure_peer;
  char *server_name, *ca_file, *cert_file, *key_file;
  uint64_t generation;
  int64_t mtu_check_at;
  uint32_t path_mtu;
  amt_membership_t memberships[TRANSPORT_MAX_AMT_MEMBERSHIPS];
  amtq_channel_t channels[2];
  size_t cursor;
  bool backlog;
};

bool transport_amt_host_mtu_usable(uint8_t outer_family, uint8_t inner_family,
                                   size_t udp_payload, uint32_t mtu) {
  if ((outer_family != 4 && outer_family != 6) ||
      (inner_family != 4 && inner_family != 6))
    return false;
  if (!mtu || inner_family == 4)
    return true;
  /* outer IP + UDP + two-byte AMT header + inner IPv6 + UDP */
  size_t overhead = (outer_family == 4 ? 20U : 40U) + 8U + 2U + 40U + 8U;
  return mtu > overhead && udp_payload <= mtu - overhead;
}

static uint32_t query_path_mtu(const nanoamt_endpoint *endpoint) {
#ifdef __linux__
  int family = endpoint->ip_version == 4 ? AF_INET : AF_INET6;
  int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return 0;
  struct sockaddr_storage peer = {0};
  socklen_t size;
  if (family == AF_INET) {
    struct sockaddr_in *v4 = (struct sockaddr_in *)&peer;
    v4->sin_family = AF_INET;
    v4->sin_port = htons(endpoint->port);
    memcpy(&v4->sin_addr, endpoint->ip, 4);
    size = sizeof(*v4);
  } else {
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&peer;
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htons(endpoint->port);
    v6->sin6_scope_id = endpoint->scope_id;
    memcpy(&v6->sin6_addr, endpoint->ip, 16);
    size = sizeof(*v6);
  }
  int mtu = 0;
  socklen_t mtu_size = sizeof(mtu);
  if (connect(fd, (struct sockaddr *)&peer, size) ||
      getsockopt(fd, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
                 family == AF_INET ? IP_MTU : IPV6_MTU, &mtu, &mtu_size))
    mtu = 0;
  CLOSE_SOCKET(fd);
  return mtu > 0 ? (uint32_t)mtu : 0;
#else
  (void)endpoint;
  return 0;
#endif
}

static struct transport_amt_host *amt_host(transport_t *t) {
  transport_poll_host_t *host = t ? t->drive_host.context : NULL;
  return host ? host->amt : NULL;
}

static void clear_channel(amtq_channel_t *channel) {
  while (channel->pending_count) {
    nanoamt_packet *packet = &channel->pending[channel->pending_head].packet;
    free(packet->data);
    memset(&channel->pending[channel->pending_head], 0,
           sizeof(channel->pending[channel->pending_head]));
    channel->pending_head = (channel->pending_head + 1U) % AMTQ_PENDING_PACKETS;
    --channel->pending_count;
  }
  channel->pending_bytes = 0;
}

static char *dup_or_null(const char *s, bool *ok) {
  if (!s)
    return NULL;
  char *copy = strdup(s);
  if (!copy)
    *ok = false;
  return copy;
}

struct transport_amt_host *transport_amt_host_new(const transport_config_t *c) {
  if (!c || !c->enable_flexicast || !c->flexicast_relay_address ||
      c->flexicast_group || c->flexicast_group_port ||
      (c->flexicast_interface &&
       c->flexicast_receiver_backend != TRANSPORT_GROUP_AUTO) ||
      (c->flexicast_receiver_backend != TRANSPORT_GROUP_AMT &&
       c->flexicast_receiver_backend != TRANSPORT_GROUP_AMTQ &&
       c->flexicast_receiver_backend != TRANSPORT_GROUP_AUTO) ||
      (c->flexicast_receiver_backend == TRANSPORT_GROUP_AMT &&
       (c->flexicast_relay_amtq_port || c->flexicast_relay_server_name ||
        c->flexicast_relay_ca_file || c->flexicast_amtq_reliable)))
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
  host->backend = c->flexicast_receiver_backend;
  host->amtq_reliable = c->flexicast_amtq_reliable;
  host->allow_insecure_peer = c->allow_insecure_peer && !c->verify_peer;
  host->relay.port =
      c->flexicast_relay_port
          ? c->flexicast_relay_port
          : (host->backend == TRANSPORT_GROUP_AMTQ ? AMTQ_DEFAULT_PORT
                                                   : NANOAMT_PORT);
  host->amtq_port =
      host->backend == TRANSPORT_GROUP_AMTQ
          ? host->relay.port
          : (c->flexicast_relay_amtq_port ? c->flexicast_relay_amtq_port
                                          : AMTQ_DEFAULT_PORT);
  const char *sni = c->flexicast_relay_server_name
                        ? c->flexicast_relay_server_name
                        : c->flexicast_relay_address;
  const char *ca =
      c->flexicast_relay_ca_file ? c->flexicast_relay_ca_file : c->ca_file;
  bool have_client_identity = c->cert_file && c->key_file;
  bool ok = true;
  host->server_name = dup_or_null(sni, &ok);
  host->ca_file = dup_or_null(ca, &ok);
  if (have_client_identity) {
    host->cert_file = dup_or_null(c->cert_file, &ok);
    host->key_file = dup_or_null(c->key_file, &ok);
  }
  if (!ok) {
    transport_amt_host_free(host);
    return NULL;
  }
  host->channels[0].family = 4;
  host->channels[1].family = 6;
  return host;
}

void transport_amt_host_free(struct transport_amt_host *host) {
  if (!host)
    return;
  for (size_t i = 0; i < TRANSPORT_MAX_AMT_MEMBERSHIPS; ++i)
    nanoamt_posix_close(host->memberships[i].io);
  for (size_t i = 0; i < 2; ++i) {
    if (host->channels[i].amtq) {
      int64_t now = host->channels[i].transport
                        ? transport_now_ms(host->channels[i].transport)
                        : 0;
      if (now > 0) {
        (void)amtq_posix_shutdown(host->channels[i].amtq, now);
        (void)amtq_posix_send(host->channels[i].amtq, now);
      }
      amtq_posix_close(host->channels[i].amtq);
    }
    clear_channel(&host->channels[i]);
  }
  free(host->server_name);
  free(host->ca_file);
  free(host->cert_file);
  free(host->key_file);
  free(host);
}

static amt_membership_t *flow_membership(struct transport_amt_host *host,
                                         const transport_flexicast_flow_t *f) {
  if (!host || !f || !f->relay_slot ||
      f->relay_slot > TRANSPORT_MAX_AMT_MEMBERSHIPS)
    return NULL;
  amt_membership_t *m = &host->memberships[f->relay_slot - 1U];
  return m->references && m->generation == f->relay_generation ? m : NULL;
}

static bool tuple_matches(const amt_membership_t *m,
                          const nanoamt_packet *packet) {
  size_t size = m->ip_version == 4 ? 4U : 16U;
  return packet->protocol == 17 && packet->source.ip_version == m->ip_version &&
         packet->destination.ip_version == m->ip_version &&
         packet->destination.port == m->port &&
         !memcmp(packet->source.ip, m->source, size) &&
         !memcmp(packet->destination.ip, m->group, size);
}

static void deliver(transport_t *t, amt_membership_t *m,
                    nanoamt_packet *packet);

static void quic_packet(void *context, uint64_t connection_id,
                        nanoamt_packet *p) {
  (void)connection_id;
  amtq_channel_t *channel = context;
  transport_t *t = channel->transport;
  struct transport_amt_host *host = amt_host(t);
  /* queue delivered packets so application callbacks never reenter AMTQ */
  if (!host || !p->data || p->size < 9 || p->size > 65535 ||
      channel->pending_count == AMTQ_PENDING_PACKETS ||
      p->size > AMTQ_PENDING_BYTES - channel->pending_bytes) {
    if (t)
      t->stats.flexicast_amt_packets_rejected++;
    return;
  }
  uint64_t id = 0;
  for (size_t i = 1; i < 9; ++i)
    id = (id << 8) | p->data[i];
  amt_membership_t *origin = NULL;
  for (size_t i = 0; i < t->flexicast.capacity; ++i) {
    transport_flexicast_flow_t *f = &t->flexicast.flows[i];
    if (!f->active || f->source || !f->amt_tunnel || !f->membership_acquired ||
        !f->join_sent || f->multicast_unavailable || f->flow_id != id ||
        !f->crypto || !f->control_conn)
      continue;
    origin = flow_membership(host, f);
    break;
  }
  if (!origin || origin->failed || origin->ip_version != channel->family ||
      origin->backend != TRANSPORT_GROUP_AMTQ || !tuple_matches(origin, p)) {
    t->stats.flexicast_amt_packets_rejected++;
    return;
  }
  uint8_t *payload = malloc(p->size);
  if (!payload) {
    t->stats.flexicast_amt_packets_rejected++;
    return;
  }
  memcpy(payload, p->data, p->size);
  size_t tail =
      (channel->pending_head + channel->pending_count) % AMTQ_PENDING_PACKETS;
  channel->pending[tail].packet = *p;
  channel->pending[tail].packet.data = payload;
  channel->pending[tail].packet.ip_data = NULL;
  channel->pending[tail].packet.ip_size = 0;
  channel->pending[tail].generation = origin->generation;
  channel->pending[tail].slot = (uint16_t)(origin - host->memberships);
  ++channel->pending_count;
  channel->pending_bytes += p->size;
}

static void drain_channel(amtq_channel_t *channel) {
  while (channel->pending_count) {
    nanoamt_packet packet = channel->pending[channel->pending_head].packet;
    uint64_t generation = channel->pending[channel->pending_head].generation;
    uint16_t slot = channel->pending[channel->pending_head].slot;
    memset(&channel->pending[channel->pending_head], 0,
           sizeof(channel->pending[channel->pending_head]));
    channel->pending_head = (channel->pending_head + 1U) % AMTQ_PENDING_PACKETS;
    --channel->pending_count;
    channel->pending_bytes -= packet.size;
    transport_t *t = channel->transport;
    struct transport_amt_host *host = amt_host(t);
    amt_membership_t *origin = host && slot < TRANSPORT_MAX_AMT_MEMBERSHIPS
                                   ? &host->memberships[slot]
                                   : NULL;
    if (origin && origin->references && origin->generation == generation &&
        !origin->failed)
      deliver(t, origin, &packet);
    else if (t)
      t->stats.flexicast_amt_packets_rejected++;
    free(packet.data);
  }
}

static int update_channel(transport_t *t, struct transport_amt_host *host,
                          size_t index) {
  amtq_channel_t *c = &host->channels[index];
  c->transport = t;
  nanoamtq_membership desired[TRANSPORT_MAX_AMT_MEMBERSHIPS];
  size_t count = 0;
  for (size_t i = 0; i < TRANSPORT_MAX_AMT_MEMBERSHIPS; ++i) {
    amt_membership_t *m = &host->memberships[i];
    if (!m->references || m->backend != TRANSPORT_GROUP_AMTQ ||
        m->ip_version != c->family || m->failed)
      continue;
    desired[count] = (nanoamtq_membership){.port = m->port};
    memcpy(desired[count].source, m->source, m->ip_version == 4 ? 4U : 16U);
    memcpy(desired[count].group, m->group, m->ip_version == 4 ? 4U : 16U);
    ++count;
  }
  if (!count)
    return c->amtq ? amtq_posix_set_memberships(c->amtq, NULL, 0) : 0;
  if (!c->amtq) {
    amtq_posix_config config = {0};
    config.listen.ip_version = host->relay.ip_version;
    config.peer = host->relay;
    config.peer.port = host->amtq_port;
    config.server_name = host->server_name;
    config.ca_file = host->ca_file;
    config.certificate = host->cert_file;
    config.private_key = host->key_file;
    config.allow_insecure_peer = host->allow_insecure_peer;
    config.session.gateway.ip_version = c->family;
    if (host->amtq_reliable) {
      config.session.gateway.data_modes = 3;
      config.session.gateway.preferred_mode = 1;
    }
    config.session.packet = quic_packet;
    config.session.packet_context = c;
    config.send_budget = 16;
    int64_t now = transport_now_ms(t);
    if (now <= 0)
      now = 1;
    c->amtq = amtq_posix_open(&config, now);
    if (!c->amtq)
      return -1;
  }
  return amtq_posix_set_memberships(c->amtq, desired, count);
}

bool transport_amt_host_join(transport_t *t, transport_flexicast_flow_t *flow) {
  struct transport_amt_host *host = amt_host(t);
  if (!host || !flow)
    return false;
  transport_group_backend_t backend =
      host->backend == TRANSPORT_GROUP_AUTO
          ? (flow->relay_auto_stage == 1 ? TRANSPORT_GROUP_AMT
                                         : TRANSPORT_GROUP_AMTQ)
          : host->backend;
  int64_t now = transport_now_ms(t);
  if (backend == TRANSPORT_GROUP_AMT) {
    host->path_mtu = query_path_mtu(&host->relay);
    host->mtu_check_at = now > INT64_MAX - 1000 ? INT64_MAX : now + 1000;
    size_t budget =
        t->limits.max_udp_payload_size ? t->limits.max_udp_payload_size : 1280U;
    if (!transport_amt_host_mtu_usable(host->relay.ip_version, flow->ip_version,
                                       budget, host->path_mtu)) {
      transport_log(t, TRANSPORT_LOG_INFO, "flexicast", 0, SIZE_MAX,
                    "classic AMT IPv6 packet budget exceeds known path MTU; "
                    "using fallback");
      return false;
    }
  }
  size_t addr_len = flow->ip_version == 4 ? 4U : 16U;
  size_t free_slot = TRANSPORT_MAX_AMT_MEMBERSHIPS;
  for (size_t i = 0; i < TRANSPORT_MAX_AMT_MEMBERSHIPS; ++i) {
    amt_membership_t *m = &host->memberships[i];
    if (!m->references) {
      if (free_slot == TRANSPORT_MAX_AMT_MEMBERSHIPS)
        free_slot = i;
      continue;
    }
    if (!m->failed && m->backend == backend &&
        m->ip_version == flow->ip_version && m->port == flow->udp_port &&
        !memcmp(m->source, flow->source_ip, addr_len) &&
        !memcmp(m->group, flow->group_ip, addr_len)) {
      m->references++;
      flow->relay_slot = (uint16_t)(i + 1U);
      flow->relay_generation = m->generation;
      return true;
    }
  }
  if (free_slot == TRANSPORT_MAX_AMT_MEMBERSHIPS ||
      host->generation == UINT64_MAX)
    return false;
  amt_membership_t *m = &host->memberships[free_slot];
  *m = (amt_membership_t){.backend = backend,
                          .ip_version = flow->ip_version,
                          .port = flow->udp_port,
                          .references = 1,
                          .generation = ++host->generation,
                          .setup_deadline = now > INT64_MAX - AMT_SETUP_MS
                                                ? INT64_MAX
                                                : now + AMT_SETUP_MS};
  memcpy(m->source, flow->source_ip, addr_len);
  memcpy(m->group, flow->group_ip, addr_len);
  if (backend == TRANSPORT_GROUP_AMT) {
    nanoamt_config config = {.discovery = host->relay,
                             .ip_version = flow->ip_version,
                             .port = flow->udp_port,
                             .ecn = 1,
                             .random_bytes = nanoamt_openssl_random};
    memcpy(config.source, flow->source_ip, addr_len);
    memcpy(config.group, flow->group_ip, addr_len);
    m->io = nanoamt_posix_open(&config, now);
    if (!m->io) {
      *m = (amt_membership_t){0};
      return false;
    }
  } else if (update_channel(t, host, flow->ip_version == 4 ? 0U : 1U) != 0) {
    *m = (amt_membership_t){0};
    return false;
  }
  flow->relay_slot = (uint16_t)(free_slot + 1U);
  flow->relay_generation = m->generation;
  return true;
}

void transport_amt_host_leave(transport_t *t,
                              transport_flexicast_flow_t *flow) {
  struct transport_amt_host *host = amt_host(t);
  amt_membership_t *m = flow_membership(host, flow);
  if (flow) {
    flow->relay_slot = 0;
    flow->relay_generation = 0;
  }
  if (!m || --m->references)
    return;
  uint8_t ip_version = m->ip_version;
  transport_group_backend_t backend = m->backend;
  if (m->io) {
    int64_t now = transport_now_ms(t);
    (void)nanoamt_posix_leave(m->io, now);
    (void)nanoamt_posix_send(m->io, now);
    nanoamt_posix_close(m->io);
  }
  *m = (amt_membership_t){0};
  if (backend == TRANSPORT_GROUP_AMTQ)
    (void)update_channel(t, host, ip_version == 4 ? 0U : 1U);
}

bool transport_amt_host_ready(transport_t *t,
                              const transport_flexicast_flow_t *flow) {
  struct transport_amt_host *host = amt_host(t);
  amt_membership_t *m = flow_membership(host, flow);
  if (!m || m->failed)
    return false;
  if (m->backend == TRANSPORT_GROUP_AMT)
    return m->io && nanoamt_posix_is_joined(m->io);
  amtq_posix *q = host->channels[m->ip_version == 4 ? 0U : 1U].amtq;
  return q && amtq_posix_is_ready(q) && amtq_posix_memberships_submitted(q);
}

size_t transport_amt_host_memberships(transport_t *t) {
  struct transport_amt_host *host = amt_host(t);
  size_t count = 0;
  if (host)
    for (size_t i = 0; i < TRANSPORT_MAX_AMT_MEMBERSHIPS; ++i)
      count +=
          host->memberships[i].references != 0 && !host->memberships[i].failed;
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
    if (!m->references || m->failed)
      continue;
    int64_t at = m->io ? nanoamt_posix_next_timeout(m->io) : INT64_MAX;
    if (m->io && host->mtu_check_at < at)
      at = host->mtu_check_at;
    if (!m->joined && m->setup_deadline < at)
      at = m->setup_deadline;
    if (at < next)
      next = at;
  }
  for (size_t i = 0; i < 2; ++i)
    if (host->channels[i].amtq) {
      int64_t at = amtq_posix_next_timeout(host->channels[i].amtq);
      if (at < next)
        next = at;
    }
  return next;
}

size_t transport_amt_host_poll(transport_t *t, struct pollfd *fds,
                               size_t capacity) {
  struct transport_amt_host *host = amt_host(t);
  size_t count = 0;
  if (!host)
    return 0;
  for (size_t i = 0; i < TRANSPORT_MAX_AMT_MEMBERSHIPS && count < capacity;
       ++i) {
    nanoamt_posix *io = host->memberships[i].io;
    if (io && !host->memberships[i].failed)
      fds[count++] = (struct pollfd){
          .fd = nanoamt_posix_fd(io),
          .events = POLLIN | (nanoamt_posix_wants_write(io) ? POLLOUT : 0)};
  }
  for (size_t i = 0; i < 2 && count < capacity; ++i) {
    amtq_posix *q = host->channels[i].amtq;
    if (q)
      fds[count++] = (struct pollfd){
          .fd = amtq_posix_fd(q),
          .events = POLLIN | (amtq_posix_wants_write(q) ? POLLOUT : 0)};
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

/* validate membership, tuple, and flow ID before decrypting borrowed packet */
static void deliver(transport_t *t, amt_membership_t *m,
                    nanoamt_packet *packet) {
  struct transport_amt_host *host = amt_host(t);
  transport_flexicast_flow_t *flow = NULL;
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
  if (!flow || flow_membership(host, flow) != m || !packet->data ||
      packet->size < 9 || (packet->data[0] & 0xc0U) != 0x40U ||
      id != flow->flow_id || !flow->active || !flow->amt_tunnel ||
      !flow->membership_acquired || !flow->join_sent ||
      flow->multicast_unavailable || !flow->crypto || !flow->control_conn ||
      !tuple_matches(m, packet)) {
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
  struct transport_amt_host *host = amt_host(t);
  m->failed = true;
  for (size_t i = 0; m->references && i < t->flexicast.capacity; ++i) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (flow->active && flow->amt_tunnel && flow_membership(host, flow) == m)
      transport_flexicast_tunnel_failed(t, flow);
  }
}

void transport_amt_host_service(transport_t *t, const struct pollfd *fds,
                                size_t count) {
  struct transport_amt_host *host = amt_host(t);
  if (!host)
    return;
  int64_t now = transport_now_ms(t);
  if (now >= host->mtu_check_at) {
    host->path_mtu = query_path_mtu(&host->relay);
    host->mtu_check_at = now > INT64_MAX - 1000 ? INT64_MAX : now + 1000;
  }
  size_t budget = AMT_RECEIVE_BUDGET;
  bool scan = host->backlog || !fds;
  host->backlog = false;
  size_t start = host->cursor;
  host->cursor = (start + 1U) % TRANSPORT_MAX_AMT_MEMBERSHIPS;
  size_t udp_budget =
      t->limits.max_udp_payload_size ? t->limits.max_udp_payload_size : 1280U;
  for (size_t n = 0; n < TRANSPORT_MAX_AMT_MEMBERSHIPS; ++n) {
    amt_membership_t *m =
        &host->memberships[(start + n) % TRANSPORT_MAX_AMT_MEMBERSHIPS];
    if (!m->references || m->failed)
      continue;
    if (m->io) {
      if (!transport_amt_host_mtu_usable(host->relay.ip_version, m->ip_version,
                                         udp_budget, host->path_mtu)) {
        failed(t, m);
        continue;
      }
      int rc = nanoamt_posix_send(m->io, now);
      if (rc < 0 || (!m->joined && now >= m->setup_deadline)) {
        failed(t, m);
        continue;
      }
      if (budget && (scan || readable(nanoamt_posix_fd(m->io), fds, count))) {
        while (m->io && !m->failed && budget) {
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
      if (m->io && !m->failed) {
        m->joined = nanoamt_posix_is_joined(m->io);
        if (nanoamt_posix_get_state(m->io) == NANOAMT_STATE_FAILED)
          failed(t, m);
      }
    } else if (!m->joined) {
      amtq_posix *q = host->channels[m->ip_version == 4 ? 0U : 1U].amtq;
      if (q && amtq_posix_is_ready(q) && amtq_posix_memberships_submitted(q))
        m->joined = true;
      else if (now >= m->setup_deadline)
        failed(t, m);
    }
  }
  for (size_t i = 0; i < 2; ++i) {
    amtq_channel_t *c = &host->channels[i];
    if (!c->amtq)
      continue;
    c->transport = t;
    if (budget && (scan || readable(amtq_posix_fd(c->amtq), fds, count))) {
      while (c->amtq && budget) {
        int rc = amtq_posix_receive(c->amtq, now);
        drain_channel(c);
        if (rc <= 0)
          break;
        --budget;
      }
      if (!budget)
        host->backlog = true;
    }
    if (c->amtq) {
      if (amtq_posix_send(c->amtq, now) < 0 || amtq_posix_error(c->amtq)) {
        amtq_posix_close(c->amtq);
        c->amtq = NULL;
        clear_channel(c);
        for (size_t j = 0; j < TRANSPORT_MAX_AMT_MEMBERSHIPS; ++j)
          if (host->memberships[j].references && !host->memberships[j].failed &&
              host->memberships[j].backend == TRANSPORT_GROUP_AMTQ &&
              host->memberships[j].ip_version == c->family)
            failed(t, &host->memberships[j]);
      } else {
        drain_channel(c);
        for (size_t j = 0; j < TRANSPORT_MAX_AMT_MEMBERSHIPS; ++j) {
          amt_membership_t *m = &host->memberships[j];
          if (m->references && !m->failed && !m->joined &&
              m->backend == TRANSPORT_GROUP_AMTQ &&
              m->ip_version == c->family && amtq_posix_is_ready(c->amtq) &&
              amtq_posix_memberships_submitted(c->amtq))
            m->joined = true;
        }
      }
    }
  }
}
