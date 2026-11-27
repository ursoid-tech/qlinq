#include "qlinq_relay.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
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
  int64_t reconcile_at;
  uint64_t upstream_errors;
};
static int64_t clock_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts))
    return -1;
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
void qlinq_relay_close(qlinq_relay_t *relay) {
  if (!relay)
    return;
  nanoamt_relay_posix_close(relay->io);
  nanoamt_native_close(relay->native);
  free(relay);
}
qlinq_relay_t *qlinq_relay_open(const qlinq_relay_config_t *config) {
  if (!config || !config->upstream_interface ||
      (config->linux_gateway_family && config->linux_gateway_family != 4 &&
       config->linux_gateway_family != 6) ||
      (config->path_mtu && config->path_mtu < 576) ||
      config->path_mtu > 65535 || config->max_clients > 1024 ||
      config->max_groups > 4096 || config->max_sources > 65536) {
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
  nanoamt_relay_posix_config io_config = {0};
  const char *address = config->bind_address ? config->bind_address : "0.0.0.0";
  if (inet_pton(AF_INET, address, io_config.listen.ip) == 1)
    io_config.listen.ip_version = 4;
  else if (inet_pton(AF_INET6, address, io_config.listen.ip) == 1)
    io_config.listen.ip_version = 6;
  else {
    errno = EINVAL;
    return NULL;
  }
  io_config.listen.port = config->port ? config->port : NANOAMT_PORT;
  io_config.relay.random_bytes = nanoamt_openssl_random;
  io_config.relay.response_mac = nanoamt_openssl_response_mac;
  io_config.relay.path_mtu = config->path_mtu;
  io_config.relay.max_clients = config->max_clients;
  io_config.relay.aggregate.max_groups = config->max_groups;
  io_config.relay.aggregate.max_sources = config->max_sources;
  io_config.relay.linux_gateway_family = config->linux_gateway_family;
  qlinq_relay_t *relay = calloc(1, sizeof(*relay));
  if (!relay)
    return NULL;
  relay->native = nanoamt_native_open(&native_config);
  if (!relay->native)
    goto fail;
  io_config.relay.authorize = nanoamt_native_authorize;
  io_config.relay.authorize_context = relay->native;
  io_config.mtu_feedback = nanoamt_native_mtu_feedback;
  io_config.feedback_context = relay->native;
  int64_t now = clock_ms();
  if (now < 0)
    goto fail;
  relay->io = nanoamt_relay_posix_open(&io_config, now);
  if (!relay->io)
    goto fail;
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
  int rc = nanoamt_relay_snapshot(nanoamt_relay_posix_core(relay->io), now,
                                  &aggregate);
  if (!rc)
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
  if (now < 0 || nanoamt_relay_posix_send(relay->io, now) < 0)
    return -1;
  /* reconcile after membership withdrawal/expiry even when no data arrives;
   * failure preserves previous native joins; retry on the next service turn */
  if (now >= relay->reconcile_at) {
    if (reconcile(relay, now))
      relay->upstream_errors++;
    relay->reconcile_at = now + 1000;
  }
  int64_t next = nanoamt_relay_posix_next_timeout(relay->io);
  if (relay->reconcile_at < next)
    next = relay->reconcile_at;
  int64_t delay = next > now ? next - now : 0;
  if (delay > timeout_ms)
    delay = timeout_ms;
  struct pollfd fds[2] = {
      {.fd = nanoamt_relay_posix_fd(relay->io), .events = POLLIN},
      {.fd = nanoamt_native_fd(relay->native), .events = POLLIN}};
  if (nanoamt_relay_posix_wants_write(relay->io))
    fds[0].events |= POLLOUT;
  int rc = poll(fds, 2, (int)delay);
  if (rc < 0)
    return errno == EINTR ? 0 : -1;
  if ((fds[0].revents | fds[1].revents) & (POLLNVAL | POLLHUP)) {
    errno = EIO;
    return -1;
  }
  now = clock_ms();
  if (now < 0)
    return -1;
  if (fds[0].revents & POLLIN)
    for (unsigned i = 0; i < 64; ++i) {
      rc = nanoamt_relay_posix_receive(relay->io, now);
      if (rc == NANOAMT_AGAIN)
        break;
      if (rc < 0)
        return -1;
      /* subscription installation is transactional through authorize;
       * prune removed upstream memberships after this batch as well */
      relay->reconcile_at = 0;
    }
  if (fds[1].revents & POLLIN)
    for (unsigned i = 0; i < 64; ++i) {
      nanoamt_native_packet packet;
      rc = nanoamt_native_receive(relay->native, &packet);
      if (rc == NANOAMT_AGAIN)
        break;
      if (rc < 0)
        return -1;
      if (rc == NANOAMT_PACKET) {
        rc =
            nanoamt_relay_posix_forward(relay->io, now, packet.ip, packet.size);
        if (rc < 0 && rc != NANOAMT_RELAY_ERROR_LIMIT)
          return -1;
      }
    }
  if (nanoamt_relay_posix_send(relay->io, now) < 0)
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
  nanoamt_relay_posix_stats io;
  nanoamt_relay_stats core;
  nanoamt_native_stats native;
  nanoamt_relay_posix_get_stats(relay->io, &io);
  nanoamt_relay_get_stats(nanoamt_relay_posix_core(relay->io), &core);
  nanoamt_native_get_stats(relay->native, &native);
  *stats = (qlinq_relay_stats_t){.packets_sent = io.sent,
                                 .input_drops = io.input_dropped,
                                 .send_errors = io.send_errors,
                                 .mtu_drops = core.mtu_drops,
                                 .captured = native.captured,
                                 .filtered = native.filtered,
                                 .upstream_errors = relay->upstream_errors,
                                 .clients = core.clients,
                                 .groups = native.groups,
                                 .sources = native.sources,
                                 .queued_inputs = io.queued_inputs};
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
