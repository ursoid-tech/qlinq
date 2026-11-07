/* native multicast I/O is composed only into the polling host */
#include "transport_poll_host.h"
#include "transport_flexicast.h"
#include "portable_sockets.h"
#ifndef _WIN32
#include <ifaddrs.h>
#include <net/if.h>
#endif
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
static bool set_multicast_fd_nonblocking(int fd) {
#ifdef _WIN32
  u_long enabled = 1;
  return ioctlsocket(fd, FIONBIO, &enabled) == 0;
#else
  int flags = fcntl(fd, F_GETFL, 0);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

static uint32_t find_interface_index(int family, const void *address) {
  if (!address)
    return 0;
#ifndef _WIN32
  struct ifaddrs *addresses = NULL;
  if (getifaddrs(&addresses) != 0)
    return 0;
  uint32_t result = 0;
  for (const struct ifaddrs *item = addresses; item; item = item->ifa_next) {
    if (!item->ifa_addr || item->ifa_addr->sa_family != family)
      continue;
    const void *candidate =
        family == AF_INET
            ? (const void *)&((const struct sockaddr_in *)item->ifa_addr)
                  ->sin_addr
            : (const void *)&((const struct sockaddr_in6 *)item->ifa_addr)
                  ->sin6_addr;
    size_t size =
        family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);
    if (memcmp(candidate, address, size) == 0) {
      result = if_nametoindex(item->ifa_name);
      break;
    }
  }
  freeifaddrs(addresses);
  return result;
#else
  ifmon_list_t interfaces;
  uint8_t scratchpad[IFMON_SCRATCHPAD_SIZE];
  if (ifmon_list_get(&interfaces, scratchpad, sizeof(scratchpad)) != 0)
    return 0;
  for (int i = 0; i < interfaces.count; i++) {
    for (int a = 0; a < interfaces.ifaces[i].addr_count; a++) {
      const ifmon_addr_t *candidate = &interfaces.ifaces[i].addrs[a];
      if (candidate->family != family)
        continue;
      const void *candidate_address = family == AF_INET
                                          ? (const void *)&candidate->ip.v4
                                          : (const void *)&candidate->ip.v6;
      size_t size =
          family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);
      if (memcmp(candidate_address, address, size) == 0)
        return interfaces.ifaces[i].index;
    }
  }
  return 0;
#endif
}

static int change_source_group(transport_t *t, int fd, uint8_t ip_version,
                               const uint8_t *source_ip,
                               const uint8_t *group_ip,
                               uint32_t interface_index, bool join) {
  if (ip_version == 4) {
    struct ip_mreq_source request = {0};
    memcpy(&request.imr_multiaddr, group_ip, 4);
    memcpy(&request.imr_sourceaddr, source_ip, 4);
    request.imr_interface.s_addr =
        t->flexicast_interface_set && t->flexicast_interface_family == AF_INET
            ? t->flexicast_interface_v4.s_addr
            : htonl(INADDR_ANY);
    return setsockopt(fd, IPPROTO_IP,
                      join ? IP_ADD_SOURCE_MEMBERSHIP
                           : IP_DROP_SOURCE_MEMBERSHIP,
                      &request, sizeof(request));
  }
  if (ip_version != 6)
    return -1;
#if defined(MCAST_JOIN_SOURCE_GROUP) || defined(MCAST_LEAVE_SOURCE_GROUP)
  int option;
  if (join) {
#if defined(MCAST_JOIN_SOURCE_GROUP)
    option = MCAST_JOIN_SOURCE_GROUP;
#else
    return -1;
#endif
  } else {
#if defined(MCAST_LEAVE_SOURCE_GROUP)
    option = MCAST_LEAVE_SOURCE_GROUP;
#else
    return -1;
#endif
  }
  struct group_source_req request = {0};
  request.gsr_interface = interface_index;
  struct sockaddr_in6 *group = (struct sockaddr_in6 *)&request.gsr_group;
  struct sockaddr_in6 *source = (struct sockaddr_in6 *)&request.gsr_source;
  group->sin6_family = AF_INET6;
  source->sin6_family = AF_INET6;
  memcpy(&group->sin6_addr, group_ip, 16);
  memcpy(&source->sin6_addr, source_ip, 16);
  return setsockopt(fd, IPPROTO_IPV6, option, &request, sizeof(request));
#else
  (void)t;
  (void)fd;
  (void)source_ip;
  (void)group_ip;
  (void)interface_index;
  (void)join;
  return -1;
#endif
}

static int open_receive_socket(uint8_t ip_version, uint16_t port) {
  int family = ip_version == 4 ? AF_INET : AF_INET6;
  int fd = socket(family, SOCK_DGRAM, 0);
  if (fd < 0)
    return -1;
  /* ECN is optional; missing socket support must not disable delivery */
  (void)transport_udp_enable_recv_ecn(fd, family);
  int reuse = 1;
  int receive_buffer = 2 * 1024 * 1024;
  int v6_only = 1;
  bool configured =
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0 &&
      setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer,
                 sizeof(receive_buffer)) == 0;
#ifdef __linux__
  if (configured)
    configured = setsockopt(fd, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
                            family == AF_INET ? IP_PKTINFO : IPV6_RECVPKTINFO,
                            &reuse, sizeof(reuse)) == 0;
#else
  /* native delivery requires ancillary source/destination/interface metadata */
  configured = false;
#endif
  if (configured && family == AF_INET6)
    configured = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only,
                            sizeof(v6_only)) == 0;
  if (configured && family == AF_INET) {
    struct sockaddr_in bind_address = {.sin_family = AF_INET,
                                       .sin_port = htons(port),
                                       .sin_addr.s_addr = htonl(INADDR_ANY)};
    configured =
        bind(fd, (struct sockaddr *)&bind_address, sizeof(bind_address)) == 0;
  } else if (configured) {
    struct sockaddr_in6 bind_address = {.sin6_family = AF_INET6,
                                        .sin6_port = htons(port),
                                        .sin6_addr = IN6ADDR_ANY_INIT};
    configured =
        bind(fd, (struct sockaddr *)&bind_address, sizeof(bind_address)) == 0;
  }
  if (!configured || !set_multicast_fd_nonblocking(fd)) {
    fprintf(stderr, "transport: unable to open Flexicast receive socket: %s\n",
            strerror(SOCKET_ERROR_CODE));
    CLOSE_SOCKET(fd);
    return -1;
  }
  return fd;
}

static ssize_t receive_native(transport_t *t, size_t slot, uint8_t *packet,
                              size_t capacity, transport_conn_t **source,
                              ptls_iovec_t *payload) {
  if (!t || slot >= 2 || !source || !payload) {
    errno = EINVAL;
    return -1;
  }
  *source = NULL;
  *payload = ptls_iovec_init(NULL, 0);
#ifdef __linux__
  struct sockaddr_storage peer = {0};
  struct iovec vector = {.iov_base = packet, .iov_len = capacity};
  union {
    struct cmsghdr align;
    uint8_t bytes[CMSG_SPACE(sizeof(struct in_pktinfo)) +
                  CMSG_SPACE(sizeof(struct in6_pktinfo)) +
                  CMSG_SPACE(sizeof(int)) * 2];
  } control = {0};
  struct msghdr message = {.msg_name = &peer,
                           .msg_namelen = sizeof(peer),
                           .msg_iov = &vector,
                           .msg_iovlen = 1,
                           .msg_control = control.bytes,
                           .msg_controllen = sizeof(control.bytes)};
  ssize_t received = recvmsg(t->flexicast_fds[slot], &message, 0);
  if (received < 0)
    return received;
  transport_flexicast_ingress_t ingress = {
      .ip_version = slot == 0 ? 4 : 6,
      .destination_port = t->flexicast_receive_ports[slot],
      .truncated = (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0};
  bool source_valid = false, destination_valid = false;
  if (slot == 0 && peer.ss_family == AF_INET &&
      message.msg_namelen >= sizeof(struct sockaddr_in)) {
    memcpy(ingress.source_ip, &((struct sockaddr_in *)&peer)->sin_addr, 4);
    source_valid = true;
  } else if (slot == 1 && peer.ss_family == AF_INET6 &&
             message.msg_namelen >= sizeof(struct sockaddr_in6)) {
    memcpy(ingress.source_ip, &((struct sockaddr_in6 *)&peer)->sin6_addr, 16);
    source_valid = true;
  }
  for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header;
       header = CMSG_NXTHDR(&message, header)) {
    if (slot == 0 && header->cmsg_level == IPPROTO_IP &&
        header->cmsg_type == IP_PKTINFO &&
        header->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo))) {
      struct in_pktinfo info;
      memcpy(&info, CMSG_DATA(header), sizeof(info));
      memcpy(ingress.group_ip, &info.ipi_addr, 4);
      ingress.interface_index = (uint32_t)info.ipi_ifindex;
      destination_valid = true;
    } else if (slot == 1 && header->cmsg_level == IPPROTO_IPV6 &&
               header->cmsg_type == IPV6_PKTINFO &&
               header->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
      struct in6_pktinfo info;
      memcpy(&info, CMSG_DATA(header), sizeof(info));
      memcpy(ingress.group_ip, &info.ipi6_addr, 16);
      ingress.interface_index = info.ipi6_ifindex;
      destination_valid = true;
    }
  }
  if (source_valid && destination_valid &&
      transport_flexicast_native_packet_valid(t, packet, (size_t)received,
                                              &ingress)) {
    (void)transport_flexicast_receive_packet_ecn(
        t, packet, (size_t)received, source, payload,
        transport_udp_message_ecn(&message));
  }
  return received;
#else
  (void)packet;
  (void)capacity;
  errno = ENOTSUP;
  return -1;
#endif
}

static void close_multicast(int fd) {
  CLOSE_SOCKET(fd);
}
const transport_flexicast_io_t transport_poll_flexicast_io = {
    .interface_index = find_interface_index,
    .open = open_receive_socket,
    .membership = change_source_group,
    .close = close_multicast,
    .receive = receive_native};
