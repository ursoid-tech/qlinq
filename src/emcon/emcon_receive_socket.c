#include "emcon_receive_socket.h"

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct qlinq_emcon_receive_socket_t {
  int fd;
  qlinq_emcon_cancel_fn should_cancel;
  void *cancel_data;
};

static bool address_is_multicast(const struct sockaddr *address) {
  if (address->sa_family == AF_INET) {
    const struct sockaddr_in *v4 = (const struct sockaddr_in *)address;
    return IN_MULTICAST(ntohl(v4->sin_addr.s_addr));
  }
  if (address->sa_family == AF_INET6) {
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)address;
    return IN6_IS_ADDR_MULTICAST(&v6->sin6_addr) != 0;
  }
  return false;
}

static int bind_socket_to_interface(int fd, sa_family_t family,
                                    uint32_t interface_index, bool multicast,
                                    bool join_group) {
#if defined(SO_BINDTODEVICE)
  (void)family;
  (void)multicast;
  (void)join_group;
  char interface_name[IF_NAMESIZE];
  if (!if_indextoname(interface_index, interface_name))
    return -1;
  return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface_name,
                    (socklen_t)(strlen(interface_name) + 1));
#elif defined(IP_BOUND_IF) && defined(IPV6_BOUND_IF)
  (void)multicast;
  (void)join_group;
  char interface_name[IF_NAMESIZE];
  if (!if_indextoname(interface_index, interface_name))
    return -1;
  unsigned int bound_index = interface_index;
  if (family == AF_INET)
    return setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &bound_index,
                      sizeof(bound_index));
  if (family == AF_INET6)
    return setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &bound_index,
                      sizeof(bound_index));
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
  qlinq_emcon_receive_socket_t *created;
  int fd;
  bool multicast;

  if (!receiver ||
      !qlinq_emcon_sockaddr_valid(local_address, local_address_len) ||
      !qlinq_emcon_sockaddr_valid(source_address, source_address_len) ||
      local_address->sa_family != source_address->sa_family)
    return QLINQ_EMCON_SOCKET_INVALID;
  *receiver = NULL;
  multicast = address_is_multicast(local_address);
  if (multicast && !join_group && interface_index == 0)
    return QLINQ_EMCON_SOCKET_INVALID;
#ifdef SOCK_CLOEXEC
  fd = socket(local_address->sa_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
#else
  fd = socket(local_address->sa_family, SOCK_DGRAM, 0);
#endif
  if (fd < 0)
    return QLINQ_EMCON_SOCKET_SYSTEM;
#ifndef SOCK_CLOEXEC
  if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0)
    goto SystemError;
#endif
  if (interface_index != 0 &&
      bind_socket_to_interface(fd, local_address->sa_family, interface_index,
                               multicast, join_group) != 0)
    goto SystemError;
  if (multicast) {
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0)
      goto SystemError;
#ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) != 0)
      goto SystemError;
#endif
  }
  {
    /* best-effort receive buffer sizing for unacknowledged EMCON bursts */
    int rcvbuf = 1024 * 1024;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
  }
  if (bind(fd, local_address, local_address_len) != 0)
    goto SystemError;
  if (multicast && join_group) {
    if (local_address->sa_family == AF_INET) {
      const struct sockaddr_in *v4 = (const struct sockaddr_in *)local_address;
      struct ip_mreqn mreq = {0};
      mreq.imr_multiaddr = v4->sin_addr;
      mreq.imr_ifindex = (int)interface_index;
      if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) !=
          0)
        goto SystemError;
    } else if (local_address->sa_family == AF_INET6) {
      const struct sockaddr_in6 *v6 =
          (const struct sockaddr_in6 *)local_address;
      struct ipv6_mreq mreq = {0};
      mreq.ipv6mr_multiaddr = v6->sin6_addr;
      mreq.ipv6mr_interface =
          interface_index != 0 ? interface_index : v6->sin6_scope_id;
      if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) !=
          0)
        goto SystemError;
    }
  }
  if (connect(fd, source_address, source_address_len) != 0 ||
      shutdown(fd, SHUT_WR) != 0)
    goto SystemError;
  created = calloc(1, sizeof(*created));
  if (!created) {
    close(fd);
    return QLINQ_EMCON_SOCKET_SYSTEM;
  }
  created->fd = fd;
  *receiver = created;
  return QLINQ_EMCON_SOCKET_OK;

SystemError: {
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  return QLINQ_EMCON_SOCKET_SYSTEM;
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
    return QLINQ_EMCON_SOCKET_INVALID;
  for (;;) {
    if (receiver->should_cancel &&
        receiver->should_cancel(receiver->cancel_data))
      return QLINQ_EMCON_SOCKET_INTERRUPTED;
    ssize_t received =
        recv(receiver->fd, packet, capacity, MSG_TRUNC | MSG_DONTWAIT);
    int error = errno;
    uint64_t now = qlinq_emcon_realtime_ms();
    if (!now)
      return QLINQ_EMCON_SOCKET_SYSTEM;
    if (now >= expires_at_ms)
      return QLINQ_EMCON_SOCKET_EXPIRED;
    if (received >= 0) {
      if ((size_t)received > capacity)
        return QLINQ_EMCON_SOCKET_TOO_LARGE;
      *packet_size = (size_t)received;
      return QLINQ_EMCON_SOCKET_OK;
    }
    if (error == EINTR) {
      if (receiver->should_cancel &&
          receiver->should_cancel(receiver->cancel_data))
        return QLINQ_EMCON_SOCKET_INTERRUPTED;
      continue;
    }
    if (error != EAGAIN && error != EWOULDBLOCK)
      return QLINQ_EMCON_SOCKET_SYSTEM;
    if (nonblocking)
      return QLINQ_EMCON_SOCKET_WOULD_BLOCK;
    int ret =
        qlinq_emcon_socket_wait(receiver->fd, POLLIN, expires_at_ms,
                                receiver->should_cancel, receiver->cancel_data);
    if (ret != QLINQ_EMCON_SOCKET_OK)
      return ret;
  }
}
