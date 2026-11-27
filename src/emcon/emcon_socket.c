#include "emcon_socket.h"

#include "fs_util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define WAIT_SLICE_NS (UINT64_C(50) * UINT64_C(1000000))

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

struct qlinq_emcon_receive_socket_t {
  int fd;
  qlinq_emcon_cancel_fn should_cancel;
  void *cancel_data;
};

static bool sockaddr_valid(const struct sockaddr *addr, socklen_t len) {
  if (!addr)
    return false;
  if (addr->sa_family == AF_INET)
    return len >= sizeof(struct sockaddr_in);
  if (addr->sa_family == AF_INET6)
    return len >= sizeof(struct sockaddr_in6);
  return false;
}

static bool sockaddr_is_multicast(const struct sockaddr *addr) {
  if (addr->sa_family == AF_INET)
    return qlinq_ip_is_multicast(
        4, (const uint8_t *)&((const struct sockaddr_in *)addr)->sin_addr);
  if (addr->sa_family == AF_INET6)
    return qlinq_ip_is_multicast(
        6, ((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr);
  return false;
}

static int open_udp_cloexec(sa_family_t family) {
#ifdef SOCK_CLOEXEC
  return socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
#else
  int fd = socket(family, SOCK_DGRAM, 0);
  if (fd >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
    int saved = errno;
    close(fd);
    errno = saved;
    return -1;
  }
  return fd;
#endif
}

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

/* shared deadline/cancel wait for socket readiness (fd >= 0) or pacer (fd < 0)
 */
static int wait_until(int fd, short events, uint64_t mono_deadline_ns,
                      uint64_t expires_at_ms,
                      qlinq_emcon_cancel_fn should_cancel, void *cancel_data,
                      uint64_t *slept_ns) {
  for (;;) {
    if (should_cancel && should_cancel(cancel_data))
      return QLINQ_EMCON_ERR_INTERRUPTED;
    struct timespec wall;
    if (clock_gettime(CLOCK_REALTIME, &wall) != 0)
      return QLINQ_EMCON_ERR_IO;
    uint64_t wall_ms =
        (uint64_t)wall.tv_sec * 1000U + (uint64_t)wall.tv_nsec / 1000000U;
    if (!wall_ms)
      return QLINQ_EMCON_ERR_IO;
    if (wall_ms >= expires_at_ms)
      return QLINQ_EMCON_ERR_EXPIRED;
    uint64_t rem_ms = expires_at_ms - wall_ms;
    uint64_t step_ns =
        rem_ms <= UINT64_MAX / UINT64_C(1000000)
            ? rem_ms * UINT64_C(1000000) - (uint64_t)(wall.tv_nsec % 1000000L)
            : UINT64_MAX;
    if (fd < 0) {
      uint64_t mono = monotonic_ns();
      if (!mono)
        return QLINQ_EMCON_ERR_IO;
      if (mono >= mono_deadline_ns)
        return QLINQ_EMCON_OK;
      if (mono_deadline_ns - mono < step_ns)
        step_ns = mono_deadline_ns - mono;
    }
    if (should_cancel && step_ns > WAIT_SLICE_NS)
      step_ns = WAIT_SLICE_NS;
    if (fd >= 0) {
      struct pollfd pfd = {.fd = fd, .events = events};
      uint64_t ms = (step_ns + 999999ULL) / 1000000ULL;
      int ret = poll(&pfd, 1, ms > (uint64_t)INT_MAX ? INT_MAX : (int)ms);
      if (ret > 0)
        return (should_cancel && should_cancel(cancel_data))
                   ? QLINQ_EMCON_ERR_INTERRUPTED
                   : QLINQ_EMCON_OK;
      if (ret < 0 && errno != EINTR)
        return QLINQ_EMCON_ERR_IO;
    } else {
      struct timespec req = {.tv_sec = (time_t)(step_ns / UINT64_C(1000000000)),
                             .tv_nsec = (long)(step_ns % UINT64_C(1000000000))};
      if (nanosleep(&req, NULL) != 0 && errno != EINTR)
        return QLINQ_EMCON_ERR_IO;
      if (slept_ns)
        *slept_ns += step_ns;
    }
  }
}

static int configure_multicast_destination(int fd,
                                           const struct sockaddr *destination) {
  if (!sockaddr_is_multicast(destination))
    return 0;
  if (destination->sa_family == AF_INET) {
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
  } else {
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)destination;
    unsigned int loop = 1, ifindex = v6->sin6_scope_id;
    int hops = 1;
    if ((ifindex != 0 && setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                                    &ifindex, sizeof(ifindex)) != 0) ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop,
                   sizeof(loop)) != 0 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
                   sizeof(hops)) != 0)
      return -1;
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
  if (!sender || !sockaddr_valid(local_address, local_address_len) ||
      !sockaddr_valid(destination, destination_len) ||
      destination->sa_family != local_address->sa_family ||
      destination_len > sizeof(struct sockaddr_storage) ||
      rate_bytes_per_second == 0 || burst_bytes == 0) {
    errno = EINVAL;
    return QLINQ_EMCON_ERR_INVALID;
  }
  *sender = NULL;
  int fd = open_udp_cloexec(local_address->sa_family);
  if (fd < 0)
    return QLINQ_EMCON_ERR_IO;
  qlinq_emcon_send_socket_t *created = NULL;
  if (bind(fd, local_address, local_address_len) != 0 ||
      configure_multicast_destination(fd, destination) != 0 ||
      !(created = calloc(1, sizeof(*created)))) {
    int saved = errno;
    close(fd);
    errno = saved;
    return QLINQ_EMCON_ERR_IO;
  }
  created->fd = fd;
  memcpy(&created->destination, destination, destination_len);
  created->destination_len = destination_len;
  created->rate_bytes_per_second = rate_bytes_per_second;
  created->burst_bytes = burst_bytes;
  created->burst_ns = duration_ns(burst_bytes, rate_bytes_per_second);
  created->expires_at_ms = expires_at_ms;
  *sender = created;
  return QLINQ_EMCON_OK;
}

void qlinq_emcon_send_socket_free(qlinq_emcon_send_socket_t *sender) {
  if (!sender)
    return;
  close(sender->fd);
  memset(sender, 0, sizeof(*sender));
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

int qlinq_emcon_send_socket_send(qlinq_emcon_send_socket_t *sender,
                                 const uint8_t *packet, size_t packet_size) {
  if (!sender || sender->fd < 0 || !packet || packet_size == 0 ||
      packet_size > sender->burst_bytes) {
    errno =
        packet_size > (sender ? sender->burst_bytes : 0) ? EMSGSIZE : EINVAL;
    return QLINQ_EMCON_ERR_INVALID;
  }
  uint64_t packet_ns = duration_ns(packet_size, sender->rate_bytes_per_second);
  uint64_t now = monotonic_ns();
  if (!now)
    return QLINQ_EMCON_ERR_IO;
  uint64_t credit_ns = sender->burst_ns - packet_ns;
  uint64_t earliest = sender->virtual_finish_ns > credit_ns
                          ? sender->virtual_finish_ns - credit_ns
                          : 0;
  if (earliest > now) {
    uint64_t slept = 0;
    int ret = wait_until(-1, 0, earliest, sender->expires_at_ms,
                         sender->should_cancel, sender->cancel_data, &slept);
    if (slept > 0 &&
        (ret == QLINQ_EMCON_OK || ret == QLINQ_EMCON_ERR_EXPIRED)) {
      sender->stats.pacing_delays++;
      sender->stats.pacing_delay_ns += slept;
    }
    if (ret != QLINQ_EMCON_OK)
      return ret;
  } else if (sender->should_cancel &&
             sender->should_cancel(sender->cancel_data)) {
    return QLINQ_EMCON_ERR_INTERRUPTED;
  }

  for (;;) {
    if (sender->should_cancel && sender->should_cancel(sender->cancel_data))
      return QLINQ_EMCON_ERR_INTERRUPTED;
    uint64_t wall_ms = qlinq_emcon_realtime_ms();
    if (!wall_ms)
      return QLINQ_EMCON_ERR_IO;
    if (wall_ms >= sender->expires_at_ms)
      return QLINQ_EMCON_ERR_EXPIRED;
    ssize_t sent = sendto(sender->fd, packet, packet_size, MSG_DONTWAIT,
                          (struct sockaddr *)&sender->destination,
                          sender->destination_len);
    if (sent == (ssize_t)packet_size)
      break;
    if (sent < 0 && errno == EINTR)
      continue;
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      int ret = wait_until(sender->fd, POLLOUT, 0, sender->expires_at_ms,
                           sender->should_cancel, sender->cancel_data, NULL);
      if (ret != QLINQ_EMCON_OK)
        return ret;
      continue;
    }
    sender->stats.hard_send_errors++;
    if (sent >= 0)
      errno = EIO;
    return QLINQ_EMCON_ERR_IO;
  }
  uint64_t base = monotonic_ns();
  if (base < sender->virtual_finish_ns)
    base = sender->virtual_finish_ns;
  sender->virtual_finish_ns =
      packet_ns > UINT64_MAX - base ? UINT64_MAX : base + packet_ns;
  sender->stats.packets_sent++;
  sender->stats.bytes_sent += packet_size;
  return QLINQ_EMCON_OK;
}

qlinq_emcon_send_stats_t
qlinq_emcon_send_socket_stats(const qlinq_emcon_send_socket_t *sender) {
  return sender ? sender->stats : (qlinq_emcon_send_stats_t){0};
}

static int bind_socket_to_interface(int fd, sa_family_t family,
                                    uint32_t interface_index, bool multicast,
                                    bool join_group) {
#if defined(SO_BINDTODEVICE)
  (void)family;
  (void)multicast;
  (void)join_group;
  char name[IF_NAMESIZE];
  if (!if_indextoname(interface_index, name))
    return -1;
  return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name,
                    (socklen_t)(strlen(name) + 1));
#elif defined(IP_BOUND_IF) && defined(IPV6_BOUND_IF)
  (void)multicast;
  (void)join_group;
  char name[IF_NAMESIZE];
  if (!if_indextoname(interface_index, name))
    return -1;
  unsigned int bound = interface_index;
  if (family == AF_INET)
    return setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &bound, sizeof(bound));
  if (family == AF_INET6)
    return setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &bound, sizeof(bound));
  errno = EAFNOSUPPORT;
  return -1;
#else
  (void)fd;
  (void)family;
  (void)interface_index;
  if (multicast && join_group)
    return 0;
  errno = ENOTSUP;
  return -1;
#endif
}

int qlinq_emcon_receive_socket_create_multicast(
    qlinq_emcon_receive_socket_t **receiver,
    const struct sockaddr *local_address, socklen_t local_address_len,
    const struct sockaddr *source_address, socklen_t source_address_len,
    uint32_t interface_index, bool join_group) {
  if (!receiver || !sockaddr_valid(local_address, local_address_len) ||
      !sockaddr_valid(source_address, source_address_len) ||
      local_address->sa_family != source_address->sa_family)
    return QLINQ_EMCON_ERR_INVALID;
  *receiver = NULL;
  bool multicast = sockaddr_is_multicast(local_address);
  if (multicast && !join_group && interface_index == 0)
    return QLINQ_EMCON_ERR_INVALID;
  int fd = open_udp_cloexec(local_address->sa_family);
  if (fd < 0)
    return QLINQ_EMCON_ERR_IO;
  if (interface_index != 0 &&
      bind_socket_to_interface(fd, local_address->sa_family, interface_index,
                               multicast, join_group) != 0)
    goto Error;
  if (multicast) {
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0)
      goto Error;
#ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) != 0)
      goto Error;
#endif
  }
  int rcvbuf = 1024 * 1024;
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
  if (bind(fd, local_address, local_address_len) != 0)
    goto Error;
  if (multicast && join_group) {
    if (local_address->sa_family == AF_INET) {
      struct ip_mreqn mreq = {
          .imr_multiaddr =
              ((const struct sockaddr_in *)local_address)->sin_addr,
          .imr_ifindex = (int)interface_index};
      if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) !=
          0)
        goto Error;
    } else {
      const struct sockaddr_in6 *v6 =
          (const struct sockaddr_in6 *)local_address;
      struct ipv6_mreq mreq = {.ipv6mr_multiaddr = v6->sin6_addr,
                               .ipv6mr_interface = interface_index != 0
                                                       ? interface_index
                                                       : v6->sin6_scope_id};
      if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) !=
          0)
        goto Error;
    }
  }
  if (connect(fd, source_address, source_address_len) != 0 ||
      shutdown(fd, SHUT_WR) != 0)
    goto Error;
  qlinq_emcon_receive_socket_t *created = calloc(1, sizeof(*created));
  if (!created)
    goto Error;
  created->fd = fd;
  *receiver = created;
  return QLINQ_EMCON_OK;

Error: {
  int saved = errno;
  close(fd);
  errno = saved;
  return QLINQ_EMCON_ERR_IO;
}
}

void qlinq_emcon_receive_socket_free(qlinq_emcon_receive_socket_t *receiver) {
  if (!receiver)
    return;
  close(receiver->fd);
  free(receiver);
}

void qlinq_emcon_receive_socket_set_cancel(
    qlinq_emcon_receive_socket_t *receiver, qlinq_emcon_cancel_fn should_cancel,
    void *cancel_data) {
  if (!receiver)
    return;
  receiver->should_cancel = should_cancel;
  receiver->cancel_data = cancel_data;
}

int qlinq_emcon_receive_socket_receive(qlinq_emcon_receive_socket_t *receiver,
                                       uint8_t *packet, size_t capacity,
                                       size_t *packet_size, bool nonblocking,
                                       uint64_t expires_at_ms) {
  if (!receiver || receiver->fd < 0 || !packet || capacity == 0 || !packet_size)
    return QLINQ_EMCON_ERR_INVALID;
  for (;;) {
    if (receiver->should_cancel &&
        receiver->should_cancel(receiver->cancel_data))
      return QLINQ_EMCON_ERR_INTERRUPTED;
    struct iovec iov = {.iov_base = packet, .iov_len = capacity};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    ssize_t received = recvmsg(receiver->fd, &msg, MSG_DONTWAIT);
    int error = errno;
    uint64_t now = qlinq_emcon_realtime_ms();
    if (!now)
      return QLINQ_EMCON_ERR_IO;
    if (now >= expires_at_ms)
      return QLINQ_EMCON_ERR_EXPIRED;
    if (received >= 0) {
      if ((msg.msg_flags & MSG_TRUNC) != 0 || (size_t)received > capacity)
        return QLINQ_EMCON_ERR_TOO_LARGE;
      *packet_size = (size_t)received;
      return QLINQ_EMCON_OK;
    }
    if (error == EINTR)
      continue;
    if (error != EAGAIN && error != EWOULDBLOCK)
      return QLINQ_EMCON_ERR_IO;
    if (nonblocking)
      return QLINQ_EMCON_WOULD_BLOCK;
    int ret = wait_until(receiver->fd, POLLIN, 0, expires_at_ms,
                         receiver->should_cancel, receiver->cancel_data, NULL);
    if (ret != QLINQ_EMCON_OK)
      return ret;
  }
}
