#include "transport_udp.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TRANSPORT_UDP_MAX_BATCH 64U
#define TRANSPORT_UDP_GSO_BUFFER_SIZE 65507U /* IPv4 UDP payload ceiling. */

ssize_t transport_udp_send_from(int fd, const struct sockaddr *destination,
                                const struct sockaddr *source,
                                unsigned interface_index,
                                const struct iovec *datagram) {
#ifdef __linux__
  if (!destination || !source || !datagram ||
      destination->sa_family != source->sa_family) {
    errno = EINVAL;
    return -1;
  }
  union {
    struct cmsghdr align;
    unsigned char bytes[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
                        CMSG_SPACE(sizeof(struct in_pktinfo))];
  } control = {0};
  struct msghdr message = {.msg_name = (void *)destination,
                           .msg_iov = (struct iovec *)datagram,
                           .msg_iovlen = 1,
                           .msg_control = control.bytes};
  if (source->sa_family == AF_INET) {
    message.msg_namelen = sizeof(struct sockaddr_in);
    message.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = IPPROTO_IP;
    header->cmsg_type = IP_PKTINFO;
    header->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    struct in_pktinfo info = {
        .ipi_ifindex = (int)interface_index,
        .ipi_spec_dst = ((const struct sockaddr_in *)source)->sin_addr};
    memcpy(CMSG_DATA(header), &info, sizeof(info));
  } else if (source->sa_family == AF_INET6) {
    message.msg_namelen = sizeof(struct sockaddr_in6);
    message.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = IPPROTO_IPV6;
    header->cmsg_type = IPV6_PKTINFO;
    header->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    struct in6_pktinfo info = {
        .ipi6_ifindex = interface_index,
        .ipi6_addr = ((const struct sockaddr_in6 *)source)->sin6_addr};
    memcpy(CMSG_DATA(header), &info, sizeof(info));
  } else {
    errno = EAFNOSUPPORT;
    return -1;
  }
  ssize_t sent;
  do {
    sent = sendmsg(fd, &message, 0);
  } while (sent < 0 && errno == EINTR);
  if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    return 0;
  return sent == (ssize_t)datagram->iov_len ? 1 : -1;
#else
  (void)fd;
  (void)destination;
  (void)source;
  (void)interface_index;
  (void)datagram;
  errno = EOPNOTSUPP;
  return -1;
#endif
}

#ifdef __linux__
#include <netinet/udp.h>

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
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

/* sendmmsg accepts scatter/gather GSO payloads, so multiple groups need no
 * temporary packed buffers. Keep the contiguous fast path at one iovec. */
static void prepare_gso(struct msghdr *message, struct iovec *iovs,
                        const struct iovec *datagrams, size_t count,
                        void *control, size_t control_size) {
  size_t total_size = 0;
  bool contiguous = true;
  for (size_t i = 0; i < count; i++) {
    iovs[i] = datagrams[i];
    if (i != 0 && (const uint8_t *)datagrams[i - 1U].iov_base +
                          datagrams[i - 1U].iov_len !=
                      datagrams[i].iov_base)
      contiguous = false;
    total_size += datagrams[i].iov_len;
  }
  if (contiguous)
    iovs[0].iov_len = total_size;
  message->msg_iov = iovs;
  message->msg_iovlen = contiguous ? 1 : count;
  memset(control, 0, control_size);
  message->msg_control = control;
  message->msg_controllen = control_size;
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(message);
  cmsg->cmsg_level = SOL_UDP;
  cmsg->cmsg_type = UDP_SEGMENT;
  cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
  uint16_t segment_size = (uint16_t)datagrams[0].iov_len;
  memcpy(CMSG_DATA(cmsg), &segment_size, sizeof(segment_size));
}
#endif

ssize_t transport_udp_send_batch(int fd, const struct sockaddr *destination,
                                 socklen_t destination_len,
                                 const struct iovec *datagrams, size_t count,
                                 size_t max_gso_segments) {
  if (fd < 0 || !destination || (!datagrams && count > 0) ||
      max_gso_segments > TRANSPORT_UDP_MAX_BATCH) {
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
  struct mmsghdr messages[TRANSPORT_UDP_MAX_BATCH];
  struct iovec iovs[TRANSPORT_UDP_MAX_BATCH];
  union {
    struct cmsghdr alignment;
    uint8_t bytes[CMSG_SPACE(sizeof(uint16_t))];
  } control[TRANSPORT_UDP_MAX_BATCH];
  size_t logical_end[TRANSPORT_UDP_MAX_BATCH];
  size_t sent_count = 0;
  bool use_gso = true;
  while (sent_count < count) {
    size_t message_count = 0;
    for (size_t first = sent_count; first < count;) {
      size_t available = count - first;
      if (max_gso_segments && available > max_gso_segments)
        available = max_gso_segments;
      size_t group = use_gso ? gso_prefix(datagrams + first, available) : 0;
      if (group < 2) {
        /* Preserve the ordinary suffix after the first non-GSO prefix. */
        use_gso = false;
        group = 1;
      }
      struct mmsghdr *message = &messages[message_count];
      *message = (struct mmsghdr){0};
      message->msg_hdr.msg_name = (void *)destination;
      message->msg_hdr.msg_namelen = destination_len;
      if (group > 1) {
        prepare_gso(&message->msg_hdr, iovs + first, datagrams + first, group,
                    control[message_count].bytes,
                    sizeof(control[message_count].bytes));
      } else {
        iovs[first] = datagrams[first];
        message->msg_hdr.msg_iov = &iovs[first];
        message->msg_hdr.msg_iovlen = 1;
      }
      first += group;
      logical_end[message_count++] = first;
    }
    size_t next = 0;
    while (next < message_count) {
      int sent = sendmmsg(fd, messages + next,
                          (unsigned int)(message_count - next), 0);
      if (sent > 0) {
        next += (size_t)sent;
        /* One accepted GSO message can represent many logical datagrams. */
        sent_count = logical_end[next - 1U];
        continue;
      }
      if (sent < 0 && errno == EINTR)
        continue;
      if (sent < 0 && messages[next].msg_hdr.msg_controllen != 0) {
        /* As before, retry GSO failures with ordinary UDP. Rebuild only the
         * unsent suffix: sendmmsg may have accepted earlier GSO groups before
         * reporting an error on this one. Even aggregate EAGAIN can permit
         * smaller ordinary datagrams; a genuine socket error also fails the
         * ordinary attempt below. */
        use_gso = false;
        break;
      }
      if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return (ssize_t)sent_count;
      if (sent == 0)
        errno = EIO; /* A zero-progress syscall must not spin. */
      return sent_count > 0 ? (ssize_t)sent_count : -1;
    }
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

#define TRANSPORT_UDP_GRO_BATCH 4U
#define TRANSPORT_UDP_GRO_SIZE 65536U

typedef struct {
  struct sockaddr_storage source;
  size_t size;
  size_t segment_size;
  bool dropped;
  uint8_t data[TRANSPORT_UDP_GRO_SIZE];
} transport_udp_gro_message_t;

struct transport_udp_gro {
  int fd;
  size_t count;
  size_t index;
  size_t offset;
  bool full;
  transport_udp_gro_message_t messages[TRANSPORT_UDP_GRO_BATCH];
};

transport_udp_gro_t *transport_udp_gro_create(int fd) {
  if (fd < 0) {
    errno = EINVAL;
    return NULL;
  }
#if defined(__linux__) && !defined(QLINQ_UDP_RECEIVE_PORTABLE)
  transport_udp_gro_t *state = calloc(1, sizeof(*state));
  if (!state)
    return NULL;
  int enabled = 1;
  if (setsockopt(fd, SOL_UDP, UDP_GRO, &enabled, sizeof(enabled)) != 0) {
    int error = errno;
    free(state);
    errno = error;
    return NULL;
  }
  state->fd = fd;
  return state;
#else
  errno = ENOTSUP;
  return NULL;
#endif
}

void transport_udp_gro_destroy(transport_udp_gro_t *state) {
  free(state);
}

bool transport_udp_gro_pending(const transport_udp_gro_t *state) {
  return state && state->index < state->count;
}

#if defined(__linux__) && !defined(QLINQ_UDP_RECEIVE_PORTABLE)
/* GRO uses an int receive cmsg, unlike UDP_SEGMENT's uint16_t send cmsg.
 * Reject incomplete/ambiguous metadata rather than decode merged UDP payloads.
 */
static bool gro_segment_size(const struct msghdr *message, size_t payload_size,
                             size_t *segment_size) {
  *segment_size = 0;
  if ((message->msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)
    return false;
  size_t offset = 0;
  bool found = false;
  while (offset < message->msg_controllen) {
    if (message->msg_controllen - offset < sizeof(struct cmsghdr))
      return false;
    const struct cmsghdr *cmsg =
        (const struct cmsghdr *)((const uint8_t *)message->msg_control +
                                 offset);
    if (cmsg->cmsg_len < CMSG_LEN(0) ||
        cmsg->cmsg_len > message->msg_controllen - offset)
      return false;
    if (cmsg->cmsg_level == SOL_UDP && cmsg->cmsg_type == UDP_GRO) {
      int value;
      if (found || cmsg->cmsg_len != CMSG_LEN(sizeof(value)))
        return false;
      memcpy(&value, CMSG_DATA(cmsg), sizeof(value));
      if (value <= 0 || value > UINT16_MAX || (size_t)value > payload_size)
        return false;
      *segment_size = (size_t)value;
      found = true;
    }
    size_t step = CMSG_ALIGN(cmsg->cmsg_len);
    if (step >= message->msg_controllen - offset)
      break; /* The last cmsg need not include its alignment padding. */
    offset += step;
  }
  return true;
}

static ssize_t gro_refill(transport_udp_gro_t *state, int fd) {
  struct mmsghdr messages[TRANSPORT_UDP_GRO_BATCH] = {0};
  struct iovec iovs[TRANSPORT_UDP_GRO_BATCH];
  union {
    struct cmsghdr alignment;
    uint8_t bytes[CMSG_SPACE(sizeof(int))];
  } control[TRANSPORT_UDP_GRO_BATCH];
  for (size_t i = 0; i < TRANSPORT_UDP_GRO_BATCH; i++) {
    transport_udp_gro_message_t *raw = &state->messages[i];
    raw->source = (struct sockaddr_storage){0};
    iovs[i] = (struct iovec){raw->data, sizeof(raw->data)};
    messages[i].msg_hdr =
        (struct msghdr){.msg_name = &raw->source,
                        .msg_namelen = sizeof(raw->source),
                        .msg_iov = &iovs[i],
                        .msg_iovlen = 1,
                        .msg_control = control[i].bytes,
                        .msg_controllen = sizeof(control[i].bytes)};
  }
  int received;
  do {
    received =
        recvmmsg(fd, messages, TRANSPORT_UDP_GRO_BATCH, MSG_DONTWAIT, NULL);
  } while (received < 0 && errno == EINTR);
  state->index = state->count = state->offset = 0;
  state->full = false;
  if (received < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
  state->count = (size_t)received;
  state->full = state->count == TRANSPORT_UDP_GRO_BATCH;
  for (size_t i = 0; i < state->count; i++) {
    transport_udp_gro_message_t *raw = &state->messages[i];
    raw->size = messages[i].msg_len;
    raw->dropped =
        raw->size > sizeof(raw->data) ||
        messages[i].msg_hdr.msg_controllen > sizeof(control[i].bytes) ||
        !gro_segment_size(&messages[i].msg_hdr, raw->size, &raw->segment_size);
  }
  return received;
}
#endif

ssize_t transport_udp_gro_receive(transport_udp_gro_t *state, int fd,
                                  transport_udp_view_t *views, size_t count,
                                  bool *more) {
  if (more)
    *more = false;
  if (!state || fd < 0 || state->fd != fd || !more || (!views && count)) {
    errno = EINVAL;
    return -1;
  }
  if (count > TRANSPORT_UDP_RECEIVE_BATCH) {
    errno = E2BIG;
    return -1;
  }
  if (!count) {
    *more = transport_udp_gro_pending(state) || state->full;
    return 0;
  }
#if defined(__linux__) && !defined(QLINQ_UDP_RECEIVE_PORTABLE)
  if (!transport_udp_gro_pending(state)) {
    ssize_t received = gro_refill(state, fd);
    if (received <= 0)
      return received;
  }
  size_t received = 0;
  while (received < count && state->index < state->count) {
    transport_udp_gro_message_t *raw = &state->messages[state->index];
    transport_udp_view_t *view = &views[received++];
    *view = (transport_udp_view_t){.source = raw->source,
                                   .data = raw->data + state->offset,
                                   .dropped = raw->dropped};
    if (raw->dropped) {
      /* One invalid raw message is one bounded work unit, with no payload. */
      view->data = NULL;
      state->index++;
      state->offset = 0;
      continue;
    }
    size_t size = raw->size - state->offset;
    if (raw->segment_size && size > raw->segment_size)
      size = raw->segment_size;
    /* Preserve the stateless path's copied-prefix decoder limit per original
     * datagram, without copying or ever joining adjacent UDP segments. */
    view->size =
        size < TRANSPORT_UDP_RECEIVE_SIZE ? size : TRANSPORT_UDP_RECEIVE_SIZE;
    view->truncated = view->size != size;
    state->offset += size;
    if (state->offset == raw->size) {
      state->index++;
      state->offset = 0;
    }
  }
  *more = transport_udp_gro_pending(state) || state->full;
  return (ssize_t)received;
#else
  errno = ENOTSUP;
  return -1;
#endif
}
