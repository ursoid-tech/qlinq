#include "emcon_send_socket.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct qlinq_emcon_send_socket_t {
  int fd;
  struct sockaddr_storage destination;
  socklen_t destination_len;
  uint64_t rate_bytes_per_second;
  size_t burst_bytes;
  uint64_t burst_ns;
  uint64_t expires_at_ms;
  uint64_t virtual_finish_ns;
  qlinq_emcon_cancel_fn should_cancel;
  void *cancel_data;
  qlinq_emcon_send_stats_t stats;
};

static uint64_t monotonic_ns(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    return 0;
  return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static uint64_t duration_ns(size_t bytes, uint64_t rate) {
  __uint128_t scaled = (__uint128_t)bytes * UINT64_C(1000000000) + rate - 1;
  scaled /= rate;
  return scaled > UINT64_MAX ? UINT64_MAX : (uint64_t)scaled;
}

static int configure_multicast_destination(int fd,
                                           const struct sockaddr *destination) {
  if (destination->sa_family == AF_INET) {
    const struct sockaddr_in *v4 = (const struct sockaddr_in *)destination;
    if (IN_MULTICAST(ntohl(v4->sin_addr.s_addr))) {
      struct sockaddr_in local = {0};
      socklen_t local_len = sizeof(local);
      unsigned char loop = 1, ttl = 1;
      if (getsockname(fd, (struct sockaddr *)&local, &local_len) != 0 ||
          setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &local.sin_addr,
                     sizeof(local.sin_addr)) != 0 ||
          setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) !=
              0 ||
          setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) != 0)
        return -1;
    }
  } else if (destination->sa_family == AF_INET6) {
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)destination;
    if (IN6_IS_ADDR_MULTICAST(&v6->sin6_addr)) {
      unsigned int loop = 1;
      int hops = 1;
      if (v6->sin6_scope_id != 0) {
        unsigned int ifindex = v6->sin6_scope_id;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex,
                       sizeof(ifindex)) != 0)
          return -1;
      }
      if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop,
                     sizeof(loop)) != 0 ||
          setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
                     sizeof(hops)) != 0)
        return -1;
    }
  }
  return 0;
}

int qlinq_emcon_send_socket_create(qlinq_emcon_send_socket_t **sender,
                                   const struct sockaddr *local_address,
                                   socklen_t local_address_len,
                                   const struct sockaddr *destination,
                                   socklen_t destination_len,
                                   uint64_t rate_bytes_per_second,
                                   size_t burst_bytes, uint64_t expires_at_ms) {
  qlinq_emcon_send_socket_t *created;
  int fd;
  if (!sender ||
      !qlinq_emcon_sockaddr_valid(local_address, local_address_len) ||
      !qlinq_emcon_sockaddr_valid(destination, destination_len) ||
      destination->sa_family != local_address->sa_family ||
      destination_len > sizeof(created->destination) ||
      rate_bytes_per_second == 0 || burst_bytes == 0) {
    errno = EINVAL;
    return -1;
  }
  *sender = NULL;
#ifdef SOCK_CLOEXEC
  fd = socket(local_address->sa_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
#else
  fd = socket(local_address->sa_family, SOCK_DGRAM, 0);
#endif
  if (fd < 0)
    return -1;
#ifndef SOCK_CLOEXEC
  if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0)
    goto Error;
#endif
  if (bind(fd, local_address, local_address_len) != 0 ||
      configure_multicast_destination(fd, destination) != 0)
    goto Error;
  created = calloc(1, sizeof(*created));
  if (!created)
    goto Error;
  created->fd = fd;
  memcpy(&created->destination, destination, destination_len);
  created->destination_len = destination_len;
  created->rate_bytes_per_second = rate_bytes_per_second;
  created->burst_bytes = burst_bytes;
  created->burst_ns = duration_ns(burst_bytes, rate_bytes_per_second);
  created->expires_at_ms = expires_at_ms;
  *sender = created;
  return 0;

Error: {
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  return -1;
}
}

void qlinq_emcon_send_socket_free(qlinq_emcon_send_socket_t *sender) {
  if (!sender)
    return;
  close(sender->fd);
  sender->fd = -1;
  memset(&sender->destination, 0, sizeof(sender->destination));
  free(sender);
}

void qlinq_emcon_send_socket_set_cancel(qlinq_emcon_send_socket_t *sender,
                                        qlinq_emcon_cancel_fn should_cancel,
                                        void *cancel_data) {
  if (!sender)
    return;
  sender->should_cancel = should_cancel;
  sender->cancel_data = cancel_data;
}

static int wait_for_pacer(qlinq_emcon_send_socket_t *sender,
                          uint64_t packet_ns) {
  if (sender->should_cancel && sender->should_cancel(sender->cancel_data))
    return QLINQ_EMCON_SOCKET_INTERRUPTED;
  uint64_t now = monotonic_ns();
  if (!now)
    return QLINQ_EMCON_SOCKET_SYSTEM;
  uint64_t credit_ns = sender->burst_ns - packet_ns;
  uint64_t earliest = sender->virtual_finish_ns > credit_ns
                          ? sender->virtual_finish_ns - credit_ns
                          : 0;
  if (earliest <= now)
    return QLINQ_EMCON_SOCKET_OK;

  uint64_t total_delay = 0;
  for (;;) {
    if (sender->should_cancel && sender->should_cancel(sender->cancel_data))
      return QLINQ_EMCON_SOCKET_INTERRUPTED;
    now = monotonic_ns();
    if (!now)
      return QLINQ_EMCON_SOCKET_SYSTEM;
    if (earliest <= now)
      break;

    struct timespec wall;
    if (clock_gettime(CLOCK_REALTIME, &wall) != 0)
      return QLINQ_EMCON_SOCKET_SYSTEM;
    uint64_t wall_ms =
        (uint64_t)wall.tv_sec * 1000U + (uint64_t)wall.tv_nsec / 1000000U;
    if (!wall_ms)
      return QLINQ_EMCON_SOCKET_SYSTEM;
    if (wall_ms >= sender->expires_at_ms) {
      if (total_delay > 0) {
        sender->stats.pacing_delays++;
        sender->stats.pacing_delay_ns += total_delay;
      }
      return QLINQ_EMCON_SOCKET_EXPIRED;
    }
    uint64_t step_ns = earliest - now;
    uint64_t slice_ns = (uint64_t)QLINQ_EMCON_WAIT_SLICE_MS * UINT64_C(1000000);
    if (sender->should_cancel && step_ns > slice_ns)
      step_ns = slice_ns;
    uint64_t remaining_ms = sender->expires_at_ms - wall_ms;
    if (remaining_ms <= UINT64_MAX / UINT64_C(1000000)) {
      uint64_t sub_ms_ns = (uint64_t)(wall.tv_nsec % 1000000L);
      uint64_t expiry_ns = remaining_ms * UINT64_C(1000000) - sub_ms_ns;
      if (step_ns > expiry_ns)
        step_ns = expiry_ns;
    }
    struct timespec duration = {
        .tv_sec = (time_t)(step_ns / UINT64_C(1000000000)),
        .tv_nsec = (long)(step_ns % UINT64_C(1000000000))};
    if (nanosleep(&duration, NULL) != 0) {
      if (errno == EINTR) {
        if (sender->should_cancel && sender->should_cancel(sender->cancel_data))
          return QLINQ_EMCON_SOCKET_INTERRUPTED;
        continue;
      }
      return QLINQ_EMCON_SOCKET_SYSTEM;
    }
    total_delay += step_ns;
  }
  sender->stats.pacing_delays++;
  sender->stats.pacing_delay_ns += total_delay;
  return QLINQ_EMCON_SOCKET_OK;
}

int qlinq_emcon_send_socket_send(qlinq_emcon_send_socket_t *sender,
                                 const uint8_t *packet, size_t packet_size) {
  if (!sender || sender->fd < 0 || !packet || packet_size == 0) {
    errno = EINVAL;
    return QLINQ_EMCON_SOCKET_INVALID;
  }
  if (packet_size > sender->burst_bytes) {
    errno = EMSGSIZE;
    return QLINQ_EMCON_SOCKET_INVALID;
  }
  uint64_t packet_ns = duration_ns(packet_size, sender->rate_bytes_per_second);
  int ret = wait_for_pacer(sender, packet_ns);
  if (ret != QLINQ_EMCON_SOCKET_OK)
    return ret;
  for (;;) {
    if (sender->should_cancel && sender->should_cancel(sender->cancel_data))
      return QLINQ_EMCON_SOCKET_INTERRUPTED;
    uint64_t now = qlinq_emcon_realtime_ms();
    if (!now)
      return QLINQ_EMCON_SOCKET_SYSTEM;
    if (now >= sender->expires_at_ms)
      return QLINQ_EMCON_SOCKET_EXPIRED;
    ssize_t sent = sendto(sender->fd, packet, packet_size, MSG_DONTWAIT,
                          (struct sockaddr *)&sender->destination,
                          sender->destination_len);
    if (sent == (ssize_t)packet_size)
      break;
    if (sent < 0 && errno == EINTR) {
      if (sender->should_cancel && sender->should_cancel(sender->cancel_data))
        return QLINQ_EMCON_SOCKET_INTERRUPTED;
      continue;
    }
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      ret = qlinq_emcon_socket_wait(sender->fd, POLLOUT, sender->expires_at_ms,
                                    sender->should_cancel, sender->cancel_data);
      if (ret != QLINQ_EMCON_SOCKET_OK)
        return ret;
      continue;
    }
    sender->stats.hard_send_errors++;
    if (sent >= 0)
      errno = EIO;
    return QLINQ_EMCON_SOCKET_SYSTEM;
  }
  uint64_t base = monotonic_ns();
  if (base < sender->virtual_finish_ns)
    base = sender->virtual_finish_ns;
  sender->virtual_finish_ns =
      packet_ns > UINT64_MAX - base ? UINT64_MAX : base + packet_ns;
  sender->stats.packets_sent++;
  sender->stats.bytes_sent += packet_size;
  return QLINQ_EMCON_SOCKET_OK;
}

qlinq_emcon_send_stats_t
qlinq_emcon_send_socket_stats(const qlinq_emcon_send_socket_t *sender) {
  return sender ? sender->stats : (qlinq_emcon_send_stats_t){0};
}
