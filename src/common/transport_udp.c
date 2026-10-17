#include "transport_udp.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define TRANSPORT_UDP_MAX_BATCH 64U
#define TRANSPORT_UDP_GSO_BUFFER_SIZE 65507U /* IPv4 UDP payload ceiling. */

#ifdef __linux__
#include <netinet/udp.h>

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif

/* Select complete datagrams that fit one UDP_SEGMENT message. A short
 * final segment ends the group; an empty datagram needs an ordinary send. */
static size_t gso_prefix(const struct iovec *datagrams, size_t count) {
  size_t segment_size = datagrams[0].iov_len, bytes = 0, prefix = 0;
  if (segment_size == 0 || segment_size > TRANSPORT_UDP_GSO_BUFFER_SIZE)
    return 0;
  while (prefix < count) {
    size_t len = datagrams[prefix].iov_len;
    if (len == 0 || len > segment_size ||
        len > TRANSPORT_UDP_GSO_BUFFER_SIZE - bytes)
      break;
    bytes += len;
    prefix++;
    if (len != segment_size)
      break;
  }
  return prefix;
}

static bool try_gso(int fd, const struct sockaddr *destination,
                    socklen_t destination_len, const struct iovec *datagrams,
                    size_t count) {
  if (count < 2 || datagrams[0].iov_len == 0 ||
      datagrams[0].iov_len > UINT16_MAX)
    return false;
  size_t segment_size = datagrams[0].iov_len;
  size_t total_size = 0;
  bool contiguous = true;
  for (size_t i = 0; i < count; i++) {
    /* GSO cannot preserve an empty datagram or a tail larger than its segment
     * size. Use sendmmsg for those batches rather than splitting or dropping
     * an application datagram. */
    if (datagrams[i].iov_len == 0 || datagrams[i].iov_len > segment_size ||
        (i + 1U < count && datagrams[i].iov_len != segment_size) ||
        datagrams[i].iov_len > SIZE_MAX - total_size)
      return false;
    if (i != 0 && (const uint8_t *)datagrams[i - 1U].iov_base +
                          datagrams[i - 1U].iov_len !=
                      datagrams[i].iov_base)
      contiguous = false;
    total_size += datagrams[i].iov_len;
  }
  if (total_size > TRANSPORT_UDP_GSO_BUFFER_SIZE)
    return false;
  uint8_t buffer[TRANSPORT_UDP_GSO_BUFFER_SIZE];
  struct iovec iov = {.iov_base = datagrams[0].iov_base, .iov_len = total_size};
  /* reuse contiguous span when available; fallback to packed buffer */
  if (!contiguous) {
    size_t offset = 0;
    for (size_t i = 0; i < count; i++) {
      memcpy(buffer + offset, datagrams[i].iov_base, datagrams[i].iov_len);
      offset += datagrams[i].iov_len;
    }
    iov.iov_base = buffer;
  }

  uint8_t control[CMSG_SPACE(sizeof(uint16_t))] = {0};
  struct msghdr message = {.msg_name = (void *)destination,
                           .msg_namelen = destination_len,
                           .msg_iov = &iov,
                           .msg_iovlen = 1,
                           .msg_control = control,
                           .msg_controllen = sizeof(control)};
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
  cmsg->cmsg_level = SOL_UDP;
  cmsg->cmsg_type = UDP_SEGMENT;
  cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
  uint16_t value = (uint16_t)segment_size;
  memcpy(CMSG_DATA(cmsg), &value, sizeof(value));

  ssize_t sent;
  do {
    sent = sendmsg(fd, &message, 0);
  } while (sent < 0 && errno == EINTR);
  return sent == (ssize_t)total_size;
}
#endif

ssize_t transport_udp_send_batch(int fd, const struct sockaddr *destination,
                                 socklen_t destination_len,
                                 const struct iovec *datagrams, size_t count) {
  if (fd < 0 || !destination || (!datagrams && count > 0)) {
    errno = EINVAL;
    return -1;
  }
  if (count == 0)
    return 0;
  if (count > TRANSPORT_UDP_MAX_BATCH) {
    errno = E2BIG;
    return -1;
  }

#ifdef __linux__
  size_t sent_count = 0;
  while (sent_count < count) {
    size_t group = gso_prefix(datagrams + sent_count, count - sent_count);
    if (group < 2 || !try_gso(fd, destination, destination_len,
                              datagrams + sent_count, group))
      break;
    sent_count += group;
  }
  if (sent_count == count)
    return (ssize_t)sent_count;

  struct mmsghdr messages[TRANSPORT_UDP_MAX_BATCH];
  struct iovec iovs[TRANSPORT_UDP_MAX_BATCH];
  memset(messages, 0, sizeof(messages));
  for (size_t i = 0; i < count; i++) {
    iovs[i] = datagrams[i];
    messages[i].msg_hdr.msg_name = (void *)destination;
    messages[i].msg_hdr.msg_namelen = destination_len;
    messages[i].msg_hdr.msg_iov = &iovs[i];
    messages[i].msg_hdr.msg_iovlen = 1;
  }
  while (sent_count < count) {
    int sent = sendmmsg(fd, messages + sent_count,
                        (unsigned int)(count - sent_count), 0);
    if (sent > 0) {
      sent_count += (size_t)sent;
      continue;
    }
    if (sent < 0 && errno == EINTR)
      continue;
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      return (ssize_t)sent_count;
    return sent_count > 0 ? (ssize_t)sent_count : -1;
  }
  return (ssize_t)sent_count;
#else
  size_t sent_count = 0;
  for (size_t i = 0; i < count; i++) {
    ssize_t sent;
    do {
      sent = sendto(fd, datagrams[i].iov_base, datagrams[i].iov_len, 0,
                    destination, destination_len);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return (ssize_t)sent_count;
      return sent_count > 0 ? (ssize_t)sent_count : -1;
    }
    if ((size_t)sent != datagrams[i].iov_len) {
      errno = EIO;
      return sent_count > 0 ? (ssize_t)sent_count : -1;
    }
    sent_count++;
  }
  return (ssize_t)sent_count;
#endif
}

ssize_t transport_udp_receive_batch(int fd, transport_udp_datagram_t *datagrams,
                                    size_t count) {
  if (fd < 0 || (!datagrams && count != 0)) {
    errno = EINVAL;
    return -1;
  }
  if (count == 0)
    return 0;
  if (count > TRANSPORT_UDP_RECEIVE_BATCH) {
    errno = E2BIG;
    return -1;
  }
#if defined(__linux__) && !defined(QLINQ_UDP_RECEIVE_PORTABLE)
  struct mmsghdr messages[TRANSPORT_UDP_RECEIVE_BATCH] = {0};
  struct iovec iovs[TRANSPORT_UDP_RECEIVE_BATCH];
  for (size_t i = 0; i < count; i++) {
    iovs[i] = (struct iovec){.iov_base = datagrams[i].data,
                             .iov_len = sizeof(datagrams[i].data)};
    messages[i].msg_hdr.msg_name = &datagrams[i].source;
    messages[i].msg_hdr.msg_namelen = sizeof(datagrams[i].source);
    messages[i].msg_hdr.msg_iov = &iovs[i];
    messages[i].msg_hdr.msg_iovlen = 1;
  }
  int received;
  do {
    received = recvmmsg(fd, messages, (unsigned)count, MSG_DONTWAIT, NULL);
  } while (received < 0 && errno == EINTR);
  if (received < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
  for (int i = 0; i < received; i++) {
    datagrams[i].size = messages[i].msg_len;
    datagrams[i].truncated = (messages[i].msg_hdr.msg_flags & MSG_TRUNC) != 0;
  }
  return received;
#else
  size_t received = 0;
  while (received < count) {
    transport_udp_datagram_t *datagram = &datagrams[received];
    struct iovec iov = {.iov_base = datagram->data,
                        .iov_len = sizeof(datagram->data)};
    struct msghdr message = {.msg_name = &datagram->source,
                             .msg_namelen = sizeof(datagram->source),
                             .msg_iov = &iov,
                             .msg_iovlen = 1};
    ssize_t size;
    do {
      size = recvmsg(fd, &message, MSG_DONTWAIT);
    } while (size < 0 && errno == EINTR);
    if (size < 0) {
      if (received || errno == EAGAIN || errno == EWOULDBLOCK)
        return (ssize_t)received;
      return -1;
    }
    datagram->size = (size_t)size;
    datagram->truncated = (message.msg_flags & MSG_TRUNC) != 0;
    received++;
  }
  return (ssize_t)received;
#endif
}
