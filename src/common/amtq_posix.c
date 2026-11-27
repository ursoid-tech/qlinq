#include "amtq_posix.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include "../../deps/nanoamt/lib/internal.h"
#include "nanoamt/posix.h"
#include "nanoamt/relay.h"
#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "transport_tls.h"
#include <arpa/inet.h>
#include <limits.h>
#include <openssl/x509.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct quic_input {
  struct quic_input *next;
  size_t size;
  int64_t at;
  uint8_t bytes[];
} quic_input;

typedef struct quic_peer {
  amtq_quicly *session;
  nanoamt_endpoint initial_peer, local;
  uint64_t id, input_generation, input_revision;
  int64_t close_at;
  uint8_t blocked, needs_send;
  quic_input *head, *tail;
  size_t input_count, input_bytes;
} quic_peer;

struct amtq_posix {
  amtq_posix_config config;
  ptls_context_t tls;
  ptls_openssl_sign_certificate_t signer;
  ptls_openssl_verify_certificate_t verifier;
  quicly_context_t context;
  quicly_now_t clock;
  ptls_handshake_properties_t handshake;
  ptls_iovec_t alpn;
  int signer_ready, verifier_ready, fd, dirty, client_error, stopping, opened;
  nanoamt_endpoint bound;
  quic_peer *peers;
  size_t count, send_next;
  int64_t now, rate_at, policy_at;
  uint64_t credit;
  uint8_t input[65536];
  amtq_posix_stats stats;
};

static uint64_t next_handle;

static socklen_t udp_address(const nanoamt_endpoint *ep,
                             struct sockaddr_storage *out) {
  memset(out, 0, sizeof(*out));
  if (ip_version(ep->ip_version) == 6) {
    struct sockaddr_in6 *a = (struct sockaddr_in6 *)out;
    a->sin6_family = AF_INET6;
    a->sin6_port = htons(ep->port);
    a->sin6_scope_id = ep->scope_id;
    memcpy(&a->sin6_addr, ep->ip, 16);
    return sizeof(*a);
  }
  struct sockaddr_in *a = (struct sockaddr_in *)out;
  a->sin_family = AF_INET;
  a->sin_port = htons(ep->port);
  memcpy(&a->sin_addr, ep->ip, 4);
  return sizeof(*a);
}

static void udp_endpoint(const struct sockaddr_storage *address,
                         nanoamt_endpoint *ep) {
  memset(ep, 0, sizeof(*ep));
  if (address->ss_family == AF_INET6) {
    const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)address;
    ep->ip_version = 6;
    ep->port = ntohs(a->sin6_port);
    ep->scope_id = a->sin6_scope_id;
    memcpy(ep->ip, &a->sin6_addr, 16);
  } else {
    const struct sockaddr_in *a = (const struct sockaddr_in *)address;
    ep->ip_version = 4;
    ep->port = ntohs(a->sin_port);
    memcpy(ep->ip, &a->sin_addr, 4);
  }
}

static int udp_open(nanoamt_endpoint *bound) {
  int v6 = ip_version(bound->ip_version) == 6;
  int fd = socket(v6 ? AF_INET6 : AF_INET,
                  SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;
  int one = 1, pmtu = IP_PMTUDISC_DO;
  if (v6) {
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one)) ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &one, sizeof(one)) ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_RECVERR, &one, sizeof(one)) ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &one, sizeof(one)))
      goto fail;
  } else if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one)) ||
             setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &one, sizeof(one)) ||
             setsockopt(fd, IPPROTO_IP, IP_RECVERR, &one, sizeof(one)) ||
             setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu))) {
    goto fail;
  }
  struct sockaddr_storage address;
  socklen_t length = udp_address(bound, &address);
  if (bind(fd, (struct sockaddr *)&address, length) ||
      getsockname(fd, (struct sockaddr *)&address, &length))
    goto fail;
  udp_endpoint(&address, bound);
  return fd;
fail: {
  int error = errno;
  close(fd);
  errno = error;
  return -1;
}
}

static int udp_errors(int fd) {
  int count = 0;
  for (unsigned i = 0; i < 32; ++i) {
    uint8_t byte;
    struct iovec vec = {&byte, 1};
    struct msghdr msg = {.msg_iov = &vec, .msg_iovlen = 1};
    ssize_t size;
    do {
      size = recvmsg(fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
    } while (size < 0 && errno == EINTR);
    if (size < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        break;
      return -1;
    }
    ++count;
  }
  int error = 0;
  socklen_t size = sizeof(error);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size))
    return -1;
  return count;
}

static int udp_receive(int fd, const nanoamt_endpoint *bound, uint8_t *bytes,
                       size_t capacity, size_t *size, nanoamt_endpoint *peer,
                       nanoamt_endpoint *local, int *ecn) {
  struct sockaddr_storage address = {0};
  struct iovec vec = {bytes, capacity};
  union {
    struct cmsghdr align;
    uint8_t
        bytes[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))];
  } ancillary;
  struct msghdr msg = {.msg_name = &address,
                       .msg_namelen = sizeof(address),
                       .msg_iov = &vec,
                       .msg_iovlen = 1,
                       .msg_control = ancillary.bytes,
                       .msg_controllen = sizeof(ancillary.bytes)};
  ssize_t n;
  do {
    n = recvmsg(fd, &msg, 0);
  } while (n < 0 && errno == EINTR);
  if (n < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
  if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
      (address.ss_family != AF_INET && address.ss_family != AF_INET6))
    return 2;
  udp_endpoint(&address, peer);
  *local = *bound;
  *ecn = -1;
  int found = 0;
  for (struct cmsghdr *h = CMSG_FIRSTHDR(&msg); h; h = CMSG_NXTHDR(&msg, h)) {
    if (h->cmsg_level == IPPROTO_IP && h->cmsg_type == IP_PKTINFO &&
        h->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo))) {
      struct in_pktinfo info;
      memcpy(&info, CMSG_DATA(h), sizeof(info));
      memcpy(local->ip, &info.ipi_addr, 4);
      local->scope_id = (uint32_t)info.ipi_ifindex;
      found = 1;
    } else if (h->cmsg_level == IPPROTO_IPV6 && h->cmsg_type == IPV6_PKTINFO &&
               h->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
      struct in6_pktinfo info;
      memcpy(&info, CMSG_DATA(h), sizeof(info));
      memcpy(local->ip, &info.ipi6_addr, 16);
      local->scope_id = info.ipi6_ifindex;
      found = 1;
    } else if (h->cmsg_level == IPPROTO_IP && h->cmsg_type == IP_TOS &&
               h->cmsg_len >= CMSG_LEN(1)) {
      *ecn = *(const uint8_t *)CMSG_DATA(h) & 3;
    } else if (h->cmsg_level == IPPROTO_IPV6 && h->cmsg_type == IPV6_TCLASS &&
               h->cmsg_len >= CMSG_LEN(sizeof(int))) {
      int traffic;
      memcpy(&traffic, CMSG_DATA(h), sizeof(traffic));
      *ecn = traffic & 3;
    }
  }
  if (!found || !peer->port || !address_unicast(peer->ip, peer->ip_version) ||
      !address_unicast(local->ip, local->ip_version))
    return 2;
  *size = (size_t)n;
  return 1;
}

static int udp_send(int fd, const nanoamt_endpoint *source,
                    const nanoamt_endpoint *destination, const uint8_t *bytes,
                    size_t size, uint8_t tos) {
  struct sockaddr_storage address;
  struct iovec vec = {(void *)bytes, size};
  union {
    struct cmsghdr align;
    uint8_t
        bytes[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))];
  } ancillary;
  memset(&ancillary, 0, sizeof(ancillary));
  struct msghdr msg = {.msg_name = &address,
                       .msg_namelen = udp_address(destination, &address),
                       .msg_iov = &vec,
                       .msg_iovlen = 1};
  int v6 = ip_version(destination->ip_version) == 6;
  size_t info_size =
      v6 ? sizeof(struct in6_pktinfo) : sizeof(struct in_pktinfo);
  msg.msg_control = ancillary.bytes;
  msg.msg_controllen = CMSG_SPACE(info_size) + CMSG_SPACE(sizeof(int));
  struct cmsghdr *h = CMSG_FIRSTHDR(&msg);
  h->cmsg_level = v6 ? IPPROTO_IPV6 : IPPROTO_IP;
  h->cmsg_type = v6 ? IPV6_PKTINFO : IP_PKTINFO;
  h->cmsg_len = CMSG_LEN(info_size);
  if (v6) {
    struct in6_pktinfo info = {0};
    memcpy(&info.ipi6_addr, source->ip, 16);
    info.ipi6_ifindex = source->scope_id;
    memcpy(CMSG_DATA(h), &info, sizeof(info));
  } else {
    struct in_pktinfo info = {0};
    memcpy(&info.ipi_spec_dst, source->ip, 4);
    info.ipi_ifindex = (int)source->scope_id;
    memcpy(CMSG_DATA(h), &info, sizeof(info));
  }
  h = CMSG_NXTHDR(&msg, h);
  h->cmsg_level = v6 ? IPPROTO_IPV6 : IPPROTO_IP;
  h->cmsg_type = v6 ? IPV6_TCLASS : IP_TOS;
  h->cmsg_len = CMSG_LEN(sizeof(int));
  int traffic = tos;
  memcpy(CMSG_DATA(h), &traffic, sizeof(traffic));
  ssize_t n;
  do {
    n = sendmsg(fd, &msg, 0);
  } while (n < 0 && errno == EINTR);
  return n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? 0
         : n >= 0 && (size_t)n == size                      ? 1
                                                            : -1;
}

static void input_remove(amtq_posix *io, quic_peer *p, quic_input **link,
                         quic_input *previous) {
  quic_input *input = *link;
  *link = input->next;
  if (p->tail == input)
    p->tail = previous;
  --p->input_count;
  p->input_bytes -= input->size;
  --io->stats.buffered_input_packets;
  io->stats.buffered_input_bytes -= input->size;
  free(input);
}

static void input_pop(amtq_posix *io, quic_peer *p) {
  input_remove(io, p, &p->head, NULL);
}

static void input_clear(amtq_posix *io, quic_peer *p) {
  while (p->head)
    input_pop(io, p);
}

static int input_push(amtq_posix *io, quic_peer *p, const uint8_t *ip,
                      size_t size) {
  if (!amtq_quicly_accepts_ip(p->session, io->now, ip, size))
    return 0;
  if (p->input_count == io->config.data_queue_packets ||
      size > io->config.data_queue_bytes - p->input_bytes ||
      size > io->config.aggregate_data_queue_bytes -
                 io->stats.buffered_input_bytes) {
    ++io->stats.input_dropped;
    return 0;
  }
  quic_input *input = malloc(sizeof(*input) + size);
  if (!input)
    return NANOAMTQ_ERROR_MEMORY;
  *input = (quic_input){.size = size, .at = io->now};
  memcpy(input->bytes, ip, size);
  if (p->tail)
    p->tail->next = input;
  else
    p->head = input;
  p->tail = input;
  ++p->input_count;
  p->input_bytes += size;
  ++io->stats.buffered_input_packets;
  io->stats.buffered_input_bytes += size;
  p->needs_send = 1;
  return 1;
}

static int input_current(amtq_posix *io, quic_peer *p,
                         const quic_input *input) {
  return !p->close_at && !io->stopping &&
         (uint64_t)(io->now - input->at) < io->config.session.data_age_ms &&
         amtq_quicly_accepts_ip(p->session, io->now, input->bytes, input->size);
}

static void input_revalidate(amtq_posix *io, quic_peer *p) {
  nanoamtq_relay *r = amtq_quicly_relay(p->session);
  uint64_t generation = nanoamtq_relay_generation(r);
  uint64_t revision = nanoamtq_relay_authorization_revision(r);
  if (generation != p->input_generation || revision != p->input_revision) {
    /* revalidate entire queue so withdrawn groups cannot revive behind it */
    quic_input **link = &p->head, *previous = NULL;
    while (*link) {
      if (!input_current(io, p, *link)) {
        input_remove(io, p, link, previous);
        ++io->stats.input_dropped;
      } else {
        previous = *link;
        link = &previous->next;
      }
    }
    p->input_generation = generation;
    p->input_revision = revision;
  }
  while (p->head && !input_current(io, p, p->head)) {
    input_pop(io, p);
    ++io->stats.input_dropped;
  }
}

static socklen_t quic_address(const nanoamt_endpoint *endpoint,
                              struct sockaddr_storage *address) {
  socklen_t size = udp_address(endpoint, address);
  if (address->ss_family == AF_INET6 &&
      !(endpoint->ip[0] == 0xfe && (endpoint->ip[1] & 0xc0u) == 0x80u))
    ((struct sockaddr_in6 *)address)->sin6_scope_id = 0;
  return size;
}

static uint64_t handle(void) {
  uint64_t old = __atomic_load_n(&next_handle, __ATOMIC_RELAXED);
  do {
    if (old >= UINT32_MAX)
      return 0;
  } while (!__atomic_compare_exchange_n(&next_handle, &old, old + 1, 0,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED));
  return old + 1;
}

static void clock_now(quicly_now_t *self, double *value) {
  amtq_posix *io =
      (amtq_posix *)((uint8_t *)self - offsetof(amtq_posix, clock));
  *value = (double)io->now;
}

static int hello(ptls_on_client_hello_t *self, ptls_t *tls,
                 ptls_on_client_hello_parameters_t *parameters) {
  (void)self;
  for (size_t i = 0; i < parameters->negotiated_protocols.count; ++i) {
    ptls_iovec_t p = parameters->negotiated_protocols.list[i];
    if (p.len == strlen(NANOAMTQ_ALPN) && !memcmp(p.base, NANOAMTQ_ALPN, p.len))
      return ptls_set_negotiated_protocol(tls, NANOAMTQ_ALPN, 0);
  }
  return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}

static ptls_on_client_hello_t hello_callback = {hello};

static int tls_setup(amtq_posix *io) {
  io->tls.random_bytes = ptls_openssl_random_bytes;
  io->tls.get_time = &ptls_get_time;
  io->tls.key_exchanges = ptls_openssl_key_exchanges;
  io->tls.cipher_suites = ptls_openssl_cipher_suites;
  if (io->config.certificate) {
    if (transport_tls_load_certificate_and_key(&io->tls, &io->signer,
                                               io->config.certificate,
                                               io->config.private_key))
      return -1;
    io->signer_ready = 1;
  }
  if (io->config.server)
    io->tls.on_client_hello = &hello_callback;
  if (!io->config.server && io->config.allow_insecure_peer) {
    transport_tls_init_insecure_verifier(&io->verifier);
    io->tls.verify_certificate = &io->verifier.super;
  } else if (!io->config.server || io->config.require_client_certificate) {
    X509_STORE *store = X509_STORE_new();
    if (!store)
      return -1;
    int loaded =
        io->config.ca_file
            ? X509_STORE_load_locations(store, io->config.ca_file, NULL)
            : X509_STORE_set_default_paths(store);
    int rc = loaded == 1
                 ? ptls_openssl_init_verify_certificate(&io->verifier, store)
                 : -1;
    X509_STORE_free(store);
    if (rc)
      return -1;
    io->verifier_ready = 1;
    io->tls.verify_certificate = &io->verifier.super;
    if (io->config.server)
      io->tls.require_client_authentication = 1;
  }
  io->context = quicly_spec_context;
  io->context.tls = &io->tls;
  io->clock.cb = clock_now;
  io->context.now = &io->clock;
  io->context.initial_egress_max_udp_payload_size = 1200;
  uint8_t secret[16];
  ptls_openssl_random_bytes(secret, sizeof(secret));
  io->context.cid_encryptor = quicly_new_default_cid_encryptor(
      &ptls_openssl_quiclb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256,
      ptls_iovec_init(secret, sizeof(secret)));
  ptls_clear_memory(secret, sizeof(secret));
  if (!io->context.cid_encryptor)
    return -1;
  amtq_quicly_configure(&io->context);
  return 0;
}

static int add_state(nanoamt_memberships **state,
                     const nanoamt_memberships *input, int64_t now) {
  nanoamt_memberships *copy = nanoamt_memberships_clone(input), *merged = NULL;
  if (!copy)
    return NANOAMT_RELAY_ERROR_MEMORY;
  int rc = nanoamt_memberships_tick(copy, now);
  if (!rc)
    rc = nanoamt_memberships_union(*state, copy, &merged);
  nanoamt_memberships_free(copy);
  if (!rc) {
    nanoamt_memberships_free(*state);
    *state = merged;
  }
  return rc;
}

static int aggregate(amtq_posix *io, uint64_t replacement,
                     const nanoamt_memberships *candidate, int extra,
                     nanoamt_memberships **output) {
  *output = nanoamt_memberships_new(&io->config.aggregate, io->now);
  if (!*output)
    return NANOAMT_RELAY_ERROR_MEMORY;
  int rc = candidate ? add_state(output, candidate, io->now) : 0;
  for (size_t i = 0; !rc && i < io->config.max_connections; ++i) {
    quic_peer *peer = &io->peers[i];
    if (!peer->session || peer->id == replacement ||
        amtq_quicly_error(peer->session))
      continue;
    nanoamtq_relay *relay = amtq_quicly_relay(peer->session);
    if (relay)
      rc = add_state(output, nanoamtq_relay_authorized(relay), io->now);
  }
  if (!rc && extra && io->config.extra_snapshot) {
    nanoamt_memberships *other = NULL;
    rc = io->config.extra_snapshot(io->config.extra_context, io->now, &other);
    if (!rc && other)
      rc = add_state(output, other, io->now);
    nanoamt_memberships_free(other);
  }
  if (rc) {
    nanoamt_memberships_free(*output);
    *output = NULL;
  }
  return rc;
}

static int authorize(void *context, uint64_t id,
                     const nanoamt_memberships *candidate) {
  amtq_posix *io = context;
  for (size_t i = 0; i < io->config.max_connections; ++i)
    if (io->peers[i].session && io->peers[i].id == id) {
      input_revalidate(io, &io->peers[i]);
      break;
    }
  nanoamt_memberships *state = NULL;
  int rc = aggregate(io, id, candidate, 1, &state);
  if (!rc && io->config.authorize)
    rc = io->config.authorize(io->config.authorize_context, state);
  nanoamt_memberships_free(state);
  io->dirty = 1;
  if (rc)
    ++io->stats.policy_errors;
  return rc;
}

static void reconcile(amtq_posix *io) {
  if (!io->config.server) {
    io->dirty = 0;
    return;
  }
  if (!io->dirty || io->now < io->policy_at)
    return;
  nanoamt_memberships *state = NULL;
  int rc = aggregate(io, 0, NULL, 1, &state);
  if (!rc && io->config.authorize)
    rc = io->config.authorize(io->config.authorize_context, state);
  nanoamt_memberships_free(state);
  if (rc) {
    ++io->stats.policy_errors;
    io->policy_at = io->now > INT64_MAX - 1000 ? INT64_MAX : io->now + 1000;
  } else {
    io->dirty = 0;
    io->policy_at = 0;
  }
}

static amtq_quicly *new_session(amtq_posix *io, uint64_t id) {
  amtq_quicly_config c = io->config.session;
  c.server = io->config.server;
  c.connection_id = id;
  c.authorize = authorize;
  c.authorize_context = io;
  return amtq_quicly_new(&io->context, &c, io->now);
}

amtq_posix *amtq_posix_open(const amtq_posix_config *config, int64_t now) {
  if (!config || now <= 0 || now == INT64_MAX ||
      (config->listen.ip_version && config->listen.ip_version != 4 &&
       config->listen.ip_version != 6) ||
      (!!config->certificate != !!config->private_key) ||
      (config->server &&
       (!config->certificate || config->allow_insecure_peer)) ||
      (!config->server &&
       ((!config->allow_insecure_peer &&
         (!config->server_name || !*config->server_name)) ||
        !config->peer.port ||
        !address_unicast(config->peer.ip, config->peer.ip_version) ||
        ip_version(config->peer.ip_version) !=
            ip_version(config->listen.ip_version)))) {
    errno = EINVAL;
    return NULL;
  }
  amtq_posix *io = calloc(1, sizeof(*io));
  if (!io)
    return NULL;
  io->fd = -1;
  io->now = io->rate_at = now;
  io->config = *config;
  io->bound = config->listen;
  amtq_posix_config *c = &io->config;
  if (!c->server)
    c->max_connections = 1;
  else if (!c->max_connections)
    c->max_connections = 64;
  if (!c->max_connections_per_ip)
    c->max_connections_per_ip =
        c->max_connections < 16 ? c->max_connections : 16;
  if (!c->admission_rate)
    c->admission_rate = 20;
  if (!c->admission_burst)
    c->admission_burst = 32;
  if (!c->send_budget)
    c->send_budget = 64;
  if (!c->data_queue_packets)
    c->data_queue_packets = 128;
  if (!c->data_queue_bytes)
    c->data_queue_bytes = 262144;
  if (!c->aggregate_data_queue_bytes)
    c->aggregate_data_queue_bytes = 16777216;
  if (!c->session.data_age_ms)
    c->session.data_age_ms = 1000;
  if (c->data_queue_packets > 1024 || c->data_queue_bytes > 16777216 ||
      c->aggregate_data_queue_bytes > 67108864) {
    errno = EINVAL;
    goto fail;
  }
  if (!c->close_grace_ms)
    c->close_grace_ms = 3000;
  if (!c->session.gateway.refresh_cap_ms)
    c->session.gateway.refresh_cap_ms = 10000; /* keep 30s QUIC idle alive */
  c->aggregate.mode = NANOAMT_MEMBERSHIP_ENDPOINT;
  if (!c->aggregate.max_groups)
    c->aggregate.max_groups = 1024;
  if (!c->aggregate.max_sources)
    c->aggregate.max_sources = 4096;
  if (!c->aggregate.max_sources_per_group)
    c->aggregate.max_sources_per_group =
        c->aggregate.max_sources < 1024 ? c->aggregate.max_sources : 1024;
  if (c->max_connections > 1024 ||
      c->max_connections_per_ip > c->max_connections || c->send_budget > 4096) {
    errno = EINVAL;
    goto fail;
  }
  io->credit = (uint64_t)c->admission_burst * 1000;
  io->peers = calloc(c->max_connections, sizeof(*io->peers));
  if (!io->peers)
    goto fail;
  nanoamt_memberships *empty = nanoamt_memberships_new(&c->aggregate, now);
  if (!empty) {
    errno = EINVAL;
    goto fail;
  }
  nanoamt_memberships_free(empty);
  if (tls_setup(io)) {
    errno = EINVAL;
    goto fail;
  }
  io->fd = udp_open(&io->bound);
  if (io->fd < 0)
    goto fail;
  if (!c->server) {
    struct sockaddr_storage destination;
    socklen_t len = udp_address(&c->peer, &destination);
    if (zero(io->bound.ip, ip_address_size(io->bound.ip_version))) {
      int probe =
          socket(ip_version(c->peer.ip_version) == 6 ? AF_INET6 : AF_INET,
                 SOCK_DGRAM, 0);
      if (probe < 0)
        goto fail;
      struct sockaddr_storage source;
      socklen_t source_size = sizeof(source);
      int rc = connect(probe, (struct sockaddr *)&destination, len) ||
               getsockname(probe, (struct sockaddr *)&source, &source_size);
      int error = errno;
      close(probe);
      errno = error;
      if (rc)
        goto fail;
      uint16_t port = io->bound.port;
      udp_endpoint(&source, &io->bound);
      io->bound.port = port;
    }
    quic_peer *peer = &io->peers[0];
    peer->id = handle();
    peer->initial_peer = c->peer;
    if (!peer->id) {
      errno = EOVERFLOW;
      goto fail;
    }
    if (!(peer->session = new_session(io, peer->id))) {
      errno = ENOMEM;
      goto fail;
    }
    io->alpn = ptls_iovec_init(NANOAMTQ_ALPN, strlen(NANOAMTQ_ALPN));
    io->handshake.client.negotiated_protocols.list = &io->alpn;
    io->handshake.client.negotiated_protocols.count = 1;
    struct sockaddr_storage source;
    udp_address(&io->bound, &source);
    quicly_cid_plaintext_t cid = {0};
    cid.master_id = (uint32_t)peer->id;
    quicly_conn_t *connection = NULL;
    const char *sni =
        c->server_name && *c->server_name ? c->server_name : "localhost";
    quicly_error_t rc = quicly_connect(
        &connection, &io->context, sni, (struct sockaddr *)&destination,
        (struct sockaddr *)&source, &cid, ptls_iovec_init(NULL, 0),
        &io->handshake, NULL, peer->session);
    if (rc || amtq_quicly_bind(peer->session, connection)) {
      if (connection)
        quicly_free(connection);
      errno = EINVAL;
      goto fail;
    }
    io->count = 1;
    peer->needs_send = 1;
  }
  io->opened = 1;
  return io;
fail: {
  int error = errno;
  amtq_posix_close(io);
  errno = error;
  return NULL;
}
}

void amtq_posix_close(amtq_posix *io) {
  if (!io)
    return;
  if (io->fd >= 0)
    close(io->fd);
  if (io->peers) {
    for (size_t i = 0; i < io->config.max_connections; ++i) {
      input_clear(io, &io->peers[i]);
      amtq_quicly_free(io->peers[i].session);
      io->peers[i].session = NULL;
    }
    io->count = 0;
    io->dirty = 1;
    io->policy_at = 0;
    if (io->opened)
      reconcile(io);
  }
  free(io->peers);
  if (io->context.cid_encryptor)
    quicly_free_default_cid_encryptor(io->context.cid_encryptor);
  if (io->signer_ready)
    ptls_openssl_dispose_sign_certificate(&io->signer);
  if (io->verifier_ready)
    ptls_openssl_dispose_verify_certificate(&io->verifier);
  for (size_t i = 0; i < io->tls.certificates.count; ++i)
    free(io->tls.certificates.list[i].base);
  free(io->tls.certificates.list);
  free(io);
}

int amtq_posix_fd(const amtq_posix *io) {
  return io ? io->fd : -1;
}

void amtq_posix_bound(const amtq_posix *io, nanoamt_endpoint *ep) {
  if (io && ep)
    *ep = io->bound;
}

int amtq_posix_tick(amtq_posix *io, int64_t now) {
  if (!io || now < io->now || now == INT64_MAX)
    return NANOAMTQ_ERROR_ARGUMENT;
  io->now = now;
  for (size_t i = 0; i < io->config.max_connections; ++i) {
    quic_peer *peer = &io->peers[i];
    if (!peer->session)
      continue;
    int rc = amtq_quicly_tick(peer->session, now);
    if (rc && !peer->close_at) {
      peer->close_at = now > INT64_MAX - io->config.close_grace_ms
                           ? INT64_MAX
                           : now + io->config.close_grace_ms;
      ++io->stats.session_errors;
      io->dirty = 1;
      if (!io->config.server)
        io->client_error = rc;
    }
    input_revalidate(io, peer);
    if (peer->close_at && now >= peer->close_at) {
      amtq_quicly_stats stats;
      amtq_quicly_get_stats(peer->session, &stats);
      io->stats.datagrams += stats.datagrams;
      io->stats.reliable_blocks += stats.reliable_blocks;
      amtq_quicly_free(peer->session);
      memset(peer, 0, sizeof(*peer));
      --io->count;
    }
  }
  reconcile(io);
  return NANOAMTQ_OK;
}

static int admission(amtq_posix *io, const nanoamt_endpoint *from) {
  uint64_t cap = (uint64_t)io->config.admission_burst * 1000;
  uint64_t room = cap - io->credit;
  uint64_t elapsed = (uint64_t)(io->now - io->rate_at);
  io->credit += elapsed >= (room + io->config.admission_rate - 1) /
                               io->config.admission_rate
                    ? room
                    : elapsed * io->config.admission_rate;
  io->rate_at = io->now;
  if (io->credit < 1000 || io->count == io->config.max_connections)
    return 0;
  io->credit -= 1000;
  unsigned count = 0;
  for (size_t i = 0; i < io->config.max_connections; ++i) {
    quic_peer *p = &io->peers[i];
    if (p->session &&
        ip_version(p->initial_peer.ip_version) ==
            ip_version(from->ip_version) &&
        !memcmp(p->initial_peer.ip, from->ip,
                ip_address_size(from->ip_version)))
      ++count;
  }
  return count < io->config.max_connections_per_ip;
}

int amtq_posix_receive(amtq_posix *io, int64_t now) {
  int rc = amtq_posix_tick(io, now);
  if (rc)
    return rc;
  rc = udp_errors(io->fd);
  if (rc < 0)
    return AMTQ_ERROR_IO;
  io->stats.send_errors += (unsigned)rc;
  size_t size = 0;
  nanoamt_endpoint from, local;
  int ecn;
  rc = udp_receive(io->fd, &io->bound, io->input, sizeof(io->input), &size,
                   &from, &local, &ecn);
  if (rc < 0)
    return AMTQ_ERROR_IO;
  if (!rc)
    return NANOAMTQ_OK;
  ++io->stats.received;
  if (rc == 2) {
    ++io->stats.ignored;
    return NANOAMTQ_IGNORED;
  }
  struct sockaddr_storage destination, source;
  quic_address(&local, &destination);
  quic_address(&from, &source);
  quicly_decoded_packet_t packet;
  size_t offset = 0;
  if (quicly_decode_packet(&io->context, &packet, io->input, size, &offset) ==
      SIZE_MAX) {
    ++io->stats.ignored;
    return NANOAMTQ_IGNORED;
  }
  for (size_t i = 0; i < io->config.max_connections; ++i) {
    quic_peer *p = &io->peers[i];
    if (p->session &&
        quicly_is_destination(amtq_quicly_connection(p->session),
                              (struct sockaddr *)&destination,
                              (struct sockaddr *)&source, &packet)) {
      p->local = local;
      p->needs_send = 1;
      (void)amtq_quicly_receive_ecn(p->session, now, &from, &local, io->input,
                                    size, ecn);
      amtq_posix_tick(io, now);
      return NANOAMTQ_PACKET;
    }
  }
  if (!io->config.server || io->stopping || size < 1200 ||
      !QUICLY_PACKET_IS_INITIAL(packet.octets.base[0])) {
    ++io->stats.ignored;
    return NANOAMTQ_IGNORED;
  }
  if (!admission(io, &from)) {
    ++io->stats.admission_dropped;
    return NANOAMTQ_IGNORED;
  }
  quic_peer *slot = NULL;
  for (size_t i = 0; i < io->config.max_connections; ++i)
    if (!io->peers[i].session) {
      slot = &io->peers[i];
      break;
    }
  uint64_t id = handle();
  if (!id) {
    ++io->stats.admission_dropped;
    return NANOAMTQ_IGNORED;
  }
  amtq_quicly *session = new_session(io, id);
  if (!session)
    return NANOAMTQ_ERROR_MEMORY;
  quicly_cid_plaintext_t cid = {0};
  cid.master_id = (uint32_t)id;
  quicly_conn_t *connection = NULL;
  packet.ecn = (unsigned)(ecn < 0 ? 0 : ecn) & 3u;
  quicly_error_t accepted = quicly_accept(
      &connection, &io->context, (struct sockaddr *)&destination,
      (struct sockaddr *)&source, &packet, NULL, &cid, NULL, session);
  if (accepted || amtq_quicly_bind(session, connection)) {
    if (connection)
      quicly_free(connection);
    amtq_quicly_free(session);
    ++io->stats.ignored;
    return NANOAMTQ_IGNORED;
  }
  slot->session = session;
  slot->id = id;
  slot->initial_peer = from;
  slot->local = local;
  slot->needs_send = 1;
  ++io->count;
  ++io->stats.admitted;
  /* process any coalesced packet suffix after initial accept */
  while (offset < size) {
    if (quicly_decode_packet(&io->context, &packet, io->input, size, &offset) ==
        SIZE_MAX)
      break;
    packet.ecn = (unsigned)(ecn < 0 ? 0 : ecn) & 3u;
    (void)amtq_quicly_receive_decoded(session, now, &from, &local, &packet);
  }
  amtq_posix_tick(io, now);
  return NANOAMTQ_PACKET;
}

int amtq_posix_send(amtq_posix *io, int64_t now) {
  int rc = amtq_posix_tick(io, now), sent = 0;
  if (rc)
    return rc;
  rc = udp_errors(io->fd);
  if (rc < 0)
    return AMTQ_ERROR_IO;
  io->stats.send_errors += (unsigned)rc;
  size_t empty = 0;
  for (unsigned attempt = 0;
       attempt < io->config.send_budget && empty < io->config.max_connections;
       ++attempt) {
    quic_peer *peer = &io->peers[io->send_next];
    io->send_next = (io->send_next + 1) % io->config.max_connections;
    if (!peer->session) {
      ++empty;
      continue;
    }
    amtq_quicly_output output;
    peer->needs_send = 0;
    if (peer->head) {
      rc = amtq_quicly_forward_queued(peer->session, now, peer->head->at,
                                      peer->head->bytes, peer->head->size);
      if (rc != NANOAMTQ_ERROR_LIMIT) {
        input_pop(io, peer);
        if (rc)
          ++io->stats.input_dropped;
      }
    }
    rc = amtq_quicly_send(peer->session, now, &output);
    if (rc != NANOAMTQ_PACKET) {
      peer->blocked = 0;
      ++empty;
      continue;
    }
    empty = 0;
    if (!amtq_quicly_output_valid(peer->session, now, &output))
      continue;
    nanoamt_endpoint source = output.source;
    if (peer->local.port && endpoint_equal(&source, &peer->local))
      source.scope_id = peer->local.scope_id;
    rc = udp_send(io->fd, &source, &output.destination, output.bytes,
                  output.size, output.tos);
    peer->blocked = !rc;
    if (!rc) {
      ++io->stats.backpressure;
      continue;
    }
    if (rc < 0)
      ++io->stats.send_errors;
    else {
      ++io->stats.sent;
      sent = 1;
    }
    amtq_quicly_consume(peer->session);
    peer->needs_send = 1;
  }
  amtq_posix_tick(io, now);
  return sent ? NANOAMTQ_PACKET : NANOAMTQ_OK;
}

int amtq_posix_wants_write(const amtq_posix *io) {
  if (io)
    for (size_t i = 0; i < io->config.max_connections; ++i)
      if (io->peers[i].blocked)
        return 1;
  return 0;
}

int amtq_posix_shutdown(amtq_posix *io, int64_t now) {
  int rc = amtq_posix_tick(io, now);
  if (rc)
    return rc;
  io->stopping = 1;
  for (size_t i = 0; i < io->config.max_connections; ++i)
    if (io->peers[i].session) {
      quicly_conn_t *connection = amtq_quicly_connection(io->peers[i].session);
      if (quicly_get_state(connection) < QUICLY_STATE_CLOSING)
        quicly_close(connection, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0),
                     "AMTQ shutdown");
      io->peers[i].needs_send = 1;
    }
  return amtq_posix_tick(io, now);
}

int64_t amtq_posix_next_timeout(amtq_posix *io) {
  if (!io)
    return INT64_MAX;
  int64_t next = io->dirty ? io->policy_at : INT64_MAX;
  for (size_t i = 0; i < io->config.max_connections; ++i) {
    quic_peer *p = &io->peers[i];
    if (!p->session)
      continue;
    if (p->needs_send && !p->blocked)
      return io->now;
    int64_t deadline = amtq_quicly_next_timeout(p->session);
    if (deadline < next)
      next = deadline;
    if (p->head) {
      int64_t expiry = p->head->at > INT64_MAX - io->config.session.data_age_ms
                           ? INT64_MAX
                           : p->head->at + io->config.session.data_age_ms;
      if (expiry < next)
        next = expiry;
    }
    if (p->close_at && p->close_at < next)
      next = p->close_at;
  }
  return next;
}

int amtq_posix_set_memberships(amtq_posix *io,
                               const nanoamtq_membership *memberships,
                               size_t count) {
  if (!io || io->config.server || !io->peers[0].session)
    return NANOAMTQ_ERROR_ARGUMENT;
  int rc =
      amtq_quicly_set_memberships(io->peers[0].session, memberships, count);
  if (!rc)
    io->peers[0].needs_send = 1;
  return rc;
}

int amtq_posix_memberships_submitted(const amtq_posix *io) {
  return io && !io->config.server && io->peers[0].session &&
         amtq_quicly_memberships_submitted(io->peers[0].session);
}

int amtq_posix_is_ready(const amtq_posix *io) {
  return io && !io->config.server && io->peers[0].session &&
         amtq_quicly_is_ready(io->peers[0].session);
}

int amtq_posix_error(const amtq_posix *io) {
  return io ? io->client_error : NANOAMTQ_ERROR_ARGUMENT;
}

int amtq_posix_forward(amtq_posix *io, int64_t now, const uint8_t *ip,
                       size_t size) {
  int rc = amtq_posix_tick(io, now);
  if (rc)
    return rc;
  if (!io->config.server || !ip || !size || size > 65575)
    return NANOAMTQ_ERROR_ARGUMENT;
  int accepted = 0;
  for (size_t i = 0; i < io->config.max_connections; ++i) {
    quic_peer *p = &io->peers[i];
    if (!p->session || !amtq_quicly_is_ready(p->session))
      continue;
    rc = p->head ? NANOAMTQ_ERROR_LIMIT
                 : amtq_quicly_forward(p->session, now, ip, size);
    if (rc == NANOAMTQ_OK) {
      ++accepted;
      p->needs_send = 1;
    } else if (rc == NANOAMTQ_ERROR_LIMIT) {
      int queued = input_push(io, p, ip, size);
      if (queued < 0)
        return queued;
      if (queued)
        ++accepted;
    } else if (rc < 0) {
      return rc;
    }
  }
  return accepted ? NANOAMTQ_OK : NANOAMTQ_IGNORED;
}

int amtq_posix_snapshot(amtq_posix *io, int64_t now,
                        nanoamt_memberships **snapshot) {
  if (!snapshot)
    return NANOAMTQ_ERROR_ARGUMENT;
  *snapshot = NULL;
  if (!io || now < io->now || now == INT64_MAX)
    return NANOAMTQ_ERROR_ARGUMENT;
  /* avoid ticking sessions inside another transport's authorization callback */
  int64_t previous = io->now;
  io->now = now;
  int rc = aggregate(io, 0, NULL, 0, snapshot);
  io->now = previous;
  return rc == NANOAMT_RELAY_ERROR_MEMORY  ? NANOAMTQ_ERROR_MEMORY
         : rc == NANOAMT_RELAY_ERROR_LIMIT ? NANOAMTQ_ERROR_LIMIT
                                           : rc;
}

void amtq_posix_get_stats(const amtq_posix *io, amtq_posix_stats *stats) {
  if (io && stats) {
    *stats = io->stats;
    stats->connections = io->count;
    for (size_t i = 0; i < io->config.max_connections; ++i) {
      if (!io->peers[i].session)
        continue;
      amtq_quicly_stats peer;
      amtq_quicly_get_stats(io->peers[i].session, &peer);
      stats->datagrams += peer.datagrams;
      stats->reliable_blocks += peer.reliable_blocks;
    }
  }
}

#else

amtq_posix *amtq_posix_open(const amtq_posix_config *config, int64_t now_ms) {
  (void)config;
  (void)now_ms;
  errno = ENOTSUP;
  return NULL;
}
void amtq_posix_close(amtq_posix *io) {
  (void)io;
}
int amtq_posix_fd(const amtq_posix *io) {
  (void)io;
  return -1;
}
void amtq_posix_bound(const amtq_posix *io, nanoamt_endpoint *endpoint) {
  (void)io;
  if (endpoint)
    memset(endpoint, 0, sizeof(*endpoint));
}
int amtq_posix_receive(amtq_posix *io, int64_t now_ms) {
  (void)io;
  (void)now_ms;
  return AMTQ_ERROR_IO;
}
int amtq_posix_send(amtq_posix *io, int64_t now_ms) {
  (void)io;
  (void)now_ms;
  return AMTQ_ERROR_IO;
}
int amtq_posix_tick(amtq_posix *io, int64_t now_ms) {
  (void)io;
  (void)now_ms;
  return AMTQ_ERROR_IO;
}
int amtq_posix_shutdown(amtq_posix *io, int64_t now_ms) {
  (void)io;
  (void)now_ms;
  return AMTQ_ERROR_IO;
}
int64_t amtq_posix_next_timeout(amtq_posix *io) {
  (void)io;
  return INT64_MAX;
}
int amtq_posix_wants_write(const amtq_posix *io) {
  (void)io;
  return 0;
}
int amtq_posix_set_memberships(amtq_posix *io,
                               const nanoamtq_membership *memberships,
                               size_t count) {
  (void)io;
  (void)memberships;
  (void)count;
  return AMTQ_ERROR_IO;
}
int amtq_posix_memberships_submitted(const amtq_posix *io) {
  (void)io;
  return 0;
}
int amtq_posix_is_ready(const amtq_posix *io) {
  (void)io;
  return 0;
}
int amtq_posix_error(const amtq_posix *io) {
  (void)io;
  return AMTQ_ERROR_IO;
}
int amtq_posix_forward(amtq_posix *io, int64_t now_ms, const uint8_t *ip,
                       size_t size) {
  (void)io;
  (void)now_ms;
  (void)ip;
  (void)size;
  return AMTQ_ERROR_IO;
}
int amtq_posix_snapshot(amtq_posix *io, int64_t now_ms,
                        nanoamt_memberships **snapshot) {
  (void)io;
  (void)now_ms;
  if (snapshot)
    *snapshot = NULL;
  return AMTQ_ERROR_IO;
}
void amtq_posix_get_stats(const amtq_posix *io, amtq_posix_stats *stats) {
  (void)io;
  if (stats)
    memset(stats, 0, sizeof(*stats));
}

#endif
