#include "qlinq_relay.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#include "amtq_posix.h"
#include "nanoamt/native.h"
#include "nanoamt/openssl.h"
#include "nanoamt/relay_posix.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <poll.h>
#include <time.h>

struct qlinq_relay {
  nanoamt_native *native;
  nanoamt_relay_posix *io;
  amtq_posix *amtq;
  int64_t now;
  int64_t reconcile_at;
  uint64_t upstream_errors;
};

static int64_t clock_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts))
    return -1;
  int64_t ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
  return ms > 0 ? ms : 1;
}

static int classic_authorize(void *context, const nanoamt_endpoint *peer,
                             const nanoamt_memberships *requested,
                             const nanoamt_memberships *aggregate) {
  struct qlinq_relay *relay = context;
  if (!relay->amtq)
    return nanoamt_native_authorize(relay->native, peer, requested, aggregate);
  nanoamt_memberships *quic = NULL, *merged = NULL;
  int rc = amtq_posix_snapshot(relay->amtq, relay->now, &quic);
  if (!rc)
    rc = nanoamt_memberships_union(aggregate, quic, &merged);
  if (!rc)
    rc = nanoamt_native_authorize(relay->native, peer, requested, merged);
  nanoamt_memberships_free(quic);
  nanoamt_memberships_free(merged);
  return rc;
}

static int classic_snapshot(void *context, int64_t now,
                            nanoamt_memberships **snapshot) {
  struct qlinq_relay *relay = context;
  if (!relay->io) {
    *snapshot = NULL;
    return 0;
  }
  return nanoamt_relay_snapshot(nanoamt_relay_posix_core(relay->io), now,
                                snapshot);
}

static int quic_authorize(void *context, const nanoamt_memberships *aggregate) {
  struct qlinq_relay *relay = context;
  return nanoamt_native_reconcile(relay->native, aggregate);
}

void qlinq_relay_close(qlinq_relay_t *relay) {
  if (!relay)
    return;
  if (relay->amtq) {
    int64_t now = clock_ms();
    if (now > 0) {
      if (now < relay->now)
        now = relay->now;
      (void)amtq_posix_shutdown(relay->amtq, now);
      (void)amtq_posix_send(relay->amtq, now);
    }
    amtq_posix_close(relay->amtq);
    relay->amtq = NULL;
  }
  nanoamt_relay_posix_close(relay->io);
  relay->io = NULL;
  nanoamt_native_close(relay->native);
  free(relay);
}

qlinq_relay_t *qlinq_relay_open(const qlinq_relay_config_t *config) {
  bool want_classic = config && !config->disable_classic_amt;
  bool want_amtq =
      config &&
      (config->disable_classic_amt || config->amtq_port != 0 ||
       config->amtq_cert_file != NULL || config->amtq_key_file != NULL ||
       config->amtq_ca_file != NULL || config->amtq_disable_reliable);
  if (!config || !config->upstream_interface || (!want_classic && !want_amtq) ||
      (config->disable_classic_amt &&
       (config->port != 0 || config->linux_gateway_family != 0)) ||
      (config->linux_gateway_family && config->linux_gateway_family != 4 &&
       config->linux_gateway_family != 6) ||
      (config->path_mtu && config->path_mtu < 576) ||
      config->path_mtu > 65535 || config->max_clients > 1024 ||
      config->max_groups > 4096 || config->max_sources > 65536) {
    errno = EINVAL;
    return NULL;
  }
  uint16_t classic_port = config->port ? config->port : NANOAMT_PORT;
  uint16_t amtq_port =
      config->amtq_port ? config->amtq_port
                        : (config->disable_classic_amt ? AMTQ_DEFAULT_PORT : 0);
  if (want_amtq &&
      (!amtq_port || !config->amtq_cert_file || !config->amtq_key_file ||
       (want_classic && amtq_port == classic_port))) {
    errno = EINVAL;
    return NULL;
  }
  nanoamt_native_config native_config = {
      .interface_index = if_nametoindex(config->upstream_interface),
      .max_groups = config->max_groups,
      .max_sources = config->max_sources};
  if (!native_config.interface_index) {
    errno = ENODEV;
    return NULL;
  }
  nanoamt_endpoint listen = {0};
  const char *address = config->bind_address ? config->bind_address : "0.0.0.0";
  if (inet_pton(AF_INET, address, listen.ip) == 1)
    listen.ip_version = 4;
  else if (inet_pton(AF_INET6, address, listen.ip) == 1)
    listen.ip_version = 6;
  else {
    errno = EINVAL;
    return NULL;
  }
  qlinq_relay_t *relay = calloc(1, sizeof(*relay));
  if (!relay)
    return NULL;
  relay->native = nanoamt_native_open(&native_config);
  if (!relay->native)
    goto fail;
  int64_t now = clock_ms();
  if (now < 0)
    goto fail;
  relay->now = now;
  if (want_classic) {
    nanoamt_relay_posix_config io_config = {0};
    io_config.listen = listen;
    io_config.listen.port = classic_port;
    io_config.relay.random_bytes = nanoamt_openssl_random;
    io_config.relay.response_mac = nanoamt_openssl_response_mac;
    io_config.relay.path_mtu = config->path_mtu;
    io_config.relay.max_clients = config->max_clients;
    io_config.relay.aggregate.max_groups = config->max_groups;
    io_config.relay.aggregate.max_sources = config->max_sources;
    io_config.relay.linux_gateway_family = config->linux_gateway_family;
    io_config.relay.authorize = classic_authorize;
    io_config.relay.authorize_context = relay;
    io_config.mtu_feedback = nanoamt_native_mtu_feedback;
    io_config.feedback_context = relay->native;
    relay->io = nanoamt_relay_posix_open(&io_config, now);
    if (!relay->io)
      goto fail;
  }
  if (want_amtq) {
    amtq_posix_config quic_config = {0};
    quic_config.server = 1;
    quic_config.listen = listen;
    quic_config.listen.port = amtq_port;
    quic_config.certificate = config->amtq_cert_file;
    quic_config.private_key = config->amtq_key_file;
    if (config->amtq_ca_file) {
      quic_config.ca_file = config->amtq_ca_file;
      quic_config.require_client_certificate = 1;
    }
    quic_config.max_connections = config->max_clients;
    quic_config.aggregate.max_groups = config->max_groups;
    quic_config.aggregate.max_sources = config->max_sources;
    quic_config.session.relay.data_modes =
        config->amtq_disable_reliable ? 1u : 3u;
    quic_config.authorize = quic_authorize;
    quic_config.authorize_context = relay;
    if (want_classic) {
      quic_config.extra_snapshot = classic_snapshot;
      quic_config.extra_context = relay;
    }
    relay->amtq = amtq_posix_open(&quic_config, now);
    if (!relay->amtq)
      goto fail;
  }
  return relay;
fail: {
  int saved = errno;
  qlinq_relay_close(relay);
  errno = saved;
  return NULL;
}
}

static int reconcile(qlinq_relay_t *relay, int64_t now) {
  nanoamt_memberships *aggregate = NULL;
  int rc = 0;
  if (relay->io)
    rc = nanoamt_relay_snapshot(nanoamt_relay_posix_core(relay->io), now,
                                &aggregate);
  if (!rc && relay->amtq) {
    nanoamt_memberships *quic = NULL;
    rc = amtq_posix_snapshot(relay->amtq, now, &quic);
    if (!rc) {
      if (!aggregate) {
        aggregate = quic;
        quic = NULL;
      } else {
        nanoamt_memberships *merged = NULL;
        rc = nanoamt_memberships_union(aggregate, quic, &merged);
        if (!rc) {
          nanoamt_memberships_free(aggregate);
          aggregate = merged;
        }
      }
    }
    nanoamt_memberships_free(quic);
  }
  if (!rc && aggregate)
    rc = nanoamt_native_reconcile(relay->native, aggregate);
  nanoamt_memberships_free(aggregate);
  return rc;
}

int qlinq_relay_service(qlinq_relay_t *relay, int timeout_ms) {
  if (!relay || timeout_ms < 0) {
    errno = EINVAL;
    return -1;
  }
  int64_t now = clock_ms();
  if (now < 0)
    return -1;
  if (now < relay->now)
    now = relay->now;
  relay->now = now;
  if (relay->amtq && amtq_posix_send(relay->amtq, now) < 0)
    return -1;
  if (relay->io && nanoamt_relay_posix_send(relay->io, now) < 0)
    return -1;
  /* reconcile after membership withdrawal/expiry even when no data arrives */
  if (now >= relay->reconcile_at) {
    if (reconcile(relay, now))
      relay->upstream_errors++;
    relay->reconcile_at = now + 1000;
  }
  int64_t next = relay->reconcile_at;
  if (relay->io) {
    int64_t io_next = nanoamt_relay_posix_next_timeout(relay->io);
    if (io_next < next)
      next = io_next;
  }
  if (relay->amtq) {
    int64_t quic_next = amtq_posix_next_timeout(relay->amtq);
    if (quic_next < next)
      next = quic_next;
  }
  int64_t delay = next > now ? next - now : 0;
  if (delay > timeout_ms)
    delay = timeout_ms;
  struct pollfd fds[3] = {
      {.fd = relay->io ? nanoamt_relay_posix_fd(relay->io) : -1,
       .events = POLLIN},
      {.fd = nanoamt_native_fd(relay->native), .events = POLLIN},
      {.fd = relay->amtq ? amtq_posix_fd(relay->amtq) : -1, .events = POLLIN}};
  if (relay->io && nanoamt_relay_posix_wants_write(relay->io))
    fds[0].events |= POLLOUT;
  if (relay->amtq && amtq_posix_wants_write(relay->amtq))
    fds[2].events |= POLLOUT;
  int rc = poll(fds, 3, (int)delay);
  if (rc < 0)
    return errno == EINTR ? 0 : -1;
  if (((relay->io ? fds[0].revents : 0) | fds[1].revents |
       (relay->amtq ? fds[2].revents : 0)) &
      (POLLNVAL | POLLHUP)) {
    errno = EIO;
    return -1;
  }
  now = clock_ms();
  if (now < 0)
    return -1;
  if (now < relay->now)
    now = relay->now;
  relay->now = now;
  if (relay->io && (fds[0].revents & POLLIN))
    for (unsigned i = 0; i < 64; ++i) {
      rc = nanoamt_relay_posix_receive(relay->io, now);
      if (rc == NANOAMT_AGAIN)
        break;
      if (rc < 0)
        return -1;
      relay->reconcile_at = 0;
    }
  if (relay->amtq && (fds[2].revents & POLLIN))
    for (unsigned i = 0; i < 64; ++i) {
      amtq_posix_stats before, after;
      amtq_posix_get_stats(relay->amtq, &before);
      rc = amtq_posix_receive(relay->amtq, now);
      amtq_posix_get_stats(relay->amtq, &after);
      if (rc < 0)
        return -1;
      relay->reconcile_at = 0;
      if (before.received == after.received)
        break;
    }
  unsigned native_budget = relay->amtq ? 4U : 64U;
  if (fds[1].revents & POLLIN)
    for (unsigned i = 0; i < native_budget; ++i) {
      nanoamt_native_packet packet;
      rc = nanoamt_native_receive(relay->native, &packet);
      if (rc == NANOAMT_AGAIN)
        break;
      if (rc < 0)
        return -1;
      if (rc == NANOAMT_PACKET) {
        if (relay->amtq) {
          if (amtq_posix_forward(relay->amtq, now, packet.ip, packet.size) <
                  0 ||
              amtq_posix_send(relay->amtq, now) < 0)
            return -1;
        }
        if (relay->io) {
          rc = nanoamt_relay_posix_forward(relay->io, now, packet.ip,
                                           packet.size);
          if (rc < 0 && rc != NANOAMT_RELAY_ERROR_LIMIT)
            return -1;
        }
      }
    }
  if (relay->amtq && amtq_posix_send(relay->amtq, now) < 0)
    return -1;
  if (relay->io && nanoamt_relay_posix_send(relay->io, now) < 0)
    return -1;
  return 0;
}

void qlinq_relay_get_stats(const qlinq_relay_t *relay,
                           qlinq_relay_stats_t *stats) {
  if (!stats)
    return;
  *stats = (qlinq_relay_stats_t){0};
  if (!relay)
    return;
  nanoamt_relay_posix_stats io = {0};
  nanoamt_relay_stats core = {0};
  nanoamt_native_stats native = {0};
  amtq_posix_stats quic = {0};
  if (relay->io) {
    nanoamt_relay_posix_get_stats(relay->io, &io);
    nanoamt_relay_get_stats(nanoamt_relay_posix_core(relay->io), &core);
  }
  if (relay->amtq)
    amtq_posix_get_stats(relay->amtq, &quic);
  nanoamt_native_get_stats(relay->native, &native);
  *stats = (qlinq_relay_stats_t){
      .packets_sent = io.sent,
      .input_drops = io.input_dropped,
      .send_errors = io.send_errors,
      .mtu_drops = core.mtu_drops,
      .captured = native.captured,
      .filtered = native.filtered,
      .upstream_errors = relay->upstream_errors,
      .amtq_packets_sent = quic.sent,
      .amtq_datagrams = quic.datagrams,
      .amtq_reliable_blocks = quic.reliable_blocks,
      .amtq_input_drops = quic.input_dropped,
      .amtq_send_errors = quic.send_errors,
      .amtq_backpressure = quic.backpressure,
      .amtq_session_errors = quic.session_errors,
      .amtq_policy_errors = quic.policy_errors,
      .clients = core.clients,
      .amtq_clients = quic.connections,
      .groups = native.groups,
      .sources = native.sources,
      .queued_inputs = io.queued_inputs,
      .amtq_buffered_packets = quic.buffered_input_packets,
      .amtq_buffered_bytes = quic.buffered_input_bytes};
}
#else
qlinq_relay_t *qlinq_relay_open(const qlinq_relay_config_t *config) {
  (void)config;
  errno = ENOTSUP;
  return NULL;
}
int qlinq_relay_service(qlinq_relay_t *relay, int timeout_ms) {
  (void)relay;
  (void)timeout_ms;
  errno = ENOTSUP;
  return -1;
}
void qlinq_relay_get_stats(const qlinq_relay_t *relay,
                           qlinq_relay_stats_t *stats) {
  (void)relay;
  if (stats)
    *stats = (qlinq_relay_stats_t){0};
}
void qlinq_relay_close(qlinq_relay_t *relay) {
  (void)relay;
}
#endif
