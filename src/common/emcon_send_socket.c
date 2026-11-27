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
  int family;
  struct sockaddr_storage destination;
  socklen_t destination_len;
  bool destination_set;
  uint64_t rate_bytes_per_second;
  size_t burst_bytes;
  uint64_t burst_ns;
  uint64_t expires_at_ms;
  uint64_t virtual_finish_ns;
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

int qlinq_emcon_send_socket_create(qlinq_emcon_send_socket_t **sender,
                                   const struct sockaddr *local_address,
                                   socklen_t local_address_len,
                                   uint64_t rate_bytes_per_second,
                                   size_t burst_bytes, uint64_t expires_at_ms) {
  qlinq_emcon_send_socket_t *created;
  int fd;
  if (!sender ||
      !qlinq_emcon_sockaddr_valid(local_address, local_address_len) ||
      rate_bytes_per_second == 0 || burst_bytes == 0)
    return -1;
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
  if (bind(fd, local_address, local_address_len) != 0)
    goto Error;
  created = calloc(1, sizeof(*created));
  if (!created)
    goto Error;
  created->fd = fd;
  created->family = local_address->sa_family;
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

int qlinq_emcon_send_socket_local_address(
    const qlinq_emcon_send_socket_t *sender, struct sockaddr *address,
    socklen_t *address_len) {
  if (!sender || sender->fd < 0 || !address || !address_len) {
    errno = EINVAL;
    return -1;
  }
  return getsockname(sender->fd, address, address_len);
}

int qlinq_emcon_send_socket_set_destination(qlinq_emcon_send_socket_t *sender,
                                            const struct sockaddr *destination,
                                            socklen_t destination_len) {
  if (!sender || sender->fd < 0 ||
      !qlinq_emcon_sockaddr_valid(destination, destination_len) ||
      destination->sa_family != sender->family ||
      destination_len > sizeof(sender->destination)) {
    errno = EINVAL;
    return -1;
  }
  if (destination->sa_family == AF_INET) {
    const struct sockaddr_in *v4 = (const struct sockaddr_in *)destination;
    if (IN_MULTICAST(ntohl(v4->sin_addr.s_addr))) {
      struct sockaddr_in local = {0};
      socklen_t local_len = sizeof(local);
      unsigned char loop = 1, ttl = 1;
      if (getsockname(sender->fd, (struct sockaddr *)&local, &local_len) != 0 ||
          setsockopt(sender->fd, IPPROTO_IP, IP_MULTICAST_IF, &local.sin_addr,
                     sizeof(local.sin_addr)) != 0 ||
          setsockopt(sender->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop,
                     sizeof(loop)) != 0 ||
          setsockopt(sender->fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,
                     sizeof(ttl)) != 0)
        return -1;
    }
  } else if (destination->sa_family == AF_INET6) {
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)destination;
    if (IN6_IS_ADDR_MULTICAST(&v6->sin6_addr)) {
      unsigned int loop = 1;
      int hops = 1;
      if (v6->sin6_scope_id != 0) {
        unsigned int ifindex = v6->sin6_scope_id;
        if (setsockopt(sender->fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex,
                       sizeof(ifindex)) != 0)
          return -1;
      }
      if (setsockopt(sender->fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop,
                     sizeof(loop)) != 0 ||
          setsockopt(sender->fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
                     sizeof(hops)) != 0)
        return -1;
    }
  }
  memset(&sender->destination, 0, sizeof(sender->destination));
  memcpy(&sender->destination, destination, destination_len);
  sender->destination_len = destination_len;
  sender->destination_set = true;
  return 0;
}

static int wait_for_pacer(qlinq_emcon_send_socket_t *sender,
                          uint64_t packet_ns) {
  uint64_t now = monotonic_ns();
  if (!now)
    return QLINQ_EMCON_SOCKET_SYSTEM;
  uint64_t credit_ns = sender->burst_ns - packet_ns;
  uint64_t earliest = sender->virtual_finish_ns > credit_ns
                          ? sender->virtual_finish_ns - credit_ns
                          : 0;
  if (earliest <= now)
    return QLINQ_EMCON_SOCKET_OK;

  uint64_t wall_ms = qlinq_emcon_realtime_ms();
  if (!wall_ms)
    return QLINQ_EMCON_SOCKET_SYSTEM;
  if (wall_ms >= sender->expires_at_ms)
    return QLINQ_EMCON_SOCKET_EXPIRED;
  uint64_t delay = earliest - now;
  uint64_t remaining_ms = sender->expires_at_ms - wall_ms;
  clockid_t clock = CLOCK_MONOTONIC;
  struct timespec deadline = {
      .tv_sec = (time_t)(earliest / UINT64_C(1000000000)),
      .tv_nsec = (long)(earliest % UINT64_C(1000000000))};
  if (delay / 1000000 >= remaining_ms) {
    clock = CLOCK_REALTIME;
    deadline.tv_sec = (time_t)(sender->expires_at_ms / 1000);
    deadline.tv_nsec = (long)(sender->expires_at_ms % 1000) * 1000000;
    delay = remaining_ms * 1000000;
  }
  int ret;
  do {
    ret = clock_nanosleep(clock, TIMER_ABSTIME, &deadline, NULL);
  } while (ret == EINTR);
  if (ret != 0) {
    errno = ret;
    return QLINQ_EMCON_SOCKET_SYSTEM;
  }
  sender->stats.pacing_delays++;
  sender->stats.pacing_delay_ns += delay;
  return clock == CLOCK_REALTIME ? QLINQ_EMCON_SOCKET_EXPIRED
                                 : QLINQ_EMCON_SOCKET_OK;
}

int qlinq_emcon_send_socket_send(qlinq_emcon_send_socket_t *sender,
                                 const uint8_t *packet, size_t packet_size) {
  if (!sender || sender->fd < 0 || !sender->destination_set || !packet ||
      packet_size == 0) {
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
    if (sent < 0 && errno == EINTR)
      continue;
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      ret = qlinq_emcon_socket_wait(sender->fd, POLLOUT, sender->expires_at_ms);
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
