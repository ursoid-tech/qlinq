/* Real Linux UDP_GRO boundaries plus deterministic malformed-metadata and
 * syscall-failure coverage. No production test hooks are needed. */
#include "transport_udp.h"
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
static int injected_recvmmsg(int, struct mmsghdr *, unsigned int, int,
                             struct timespec *);
static int injected_setsockopt(int, int, int, const void *, socklen_t);
static void *injected_calloc(size_t, size_t);
static void injected_free(void *);
#define recvmmsg injected_recvmmsg
#define setsockopt injected_setsockopt
#define calloc injected_calloc
#define free injected_free
#include "../../src/common/transport_udp.c"
#undef recvmmsg
#undef setsockopt
#undef calloc
#undef free

static bool fake, allocation_failure, option_failure;
static unsigned option_calls, allocations, frees, receive_calls, interruptions;
static int receive_error;
typedef struct {
  size_t size;
  int segment_size;
  int flags;
  unsigned id;
} queued_message_t;
static queued_message_t queued[16];
static size_t queued_count, queued_next;

static void *injected_calloc(size_t count, size_t size) {
  if (fake) {
    if (allocation_failure) {
      errno = ENOMEM;
      return NULL;
    }
    allocations++;
  }
  return calloc(count, size);
}

static void injected_free(void *pointer) {
  if (fake && pointer)
    frees++;
  free(pointer);
}

static int injected_setsockopt(int fd, int level, int option, const void *value,
                               socklen_t length) {
  if (!fake)
    return setsockopt(fd, level, option, value, length);
  assert(fd == 7 && level == SOL_UDP && option == UDP_GRO);
  assert(length == sizeof(int) && *(const int *)value == 1);
  option_calls++;
  if (option_failure) {
    errno = ENOPROTOOPT;
    return -1;
  }
  return 0;
}

static uint8_t byte_at(unsigned id, size_t position) {
  return (uint8_t)(id * 17U + position);
}

static int injected_recvmmsg(int fd, struct mmsghdr *messages,
                             unsigned int count, int flags,
                             struct timespec *timeout) {
  if (!fake)
    return recvmmsg(fd, messages, count, flags, timeout);
  assert(fd == 7 && count == 4 && flags == MSG_DONTWAIT && !timeout);
  receive_calls++;
  if (interruptions || receive_error || queued_next == queued_count) {
    errno = interruptions ? EINTR : receive_error ? receive_error : EAGAIN;
    if (interruptions)
      interruptions--;
    return -1;
  }
  unsigned received = 0;
  while (received < count && queued_next < queued_count) {
    queued_message_t *raw = &queued[queued_next++];
    struct mmsghdr *message = &messages[received++];
    assert(message->msg_hdr.msg_iovlen == 1);
    struct iovec *iov = message->msg_hdr.msg_iov;
    size_t copied = raw->size < iov->iov_len ? raw->size : iov->iov_len;
    for (size_t i = 0; i < copied; i++)
      ((uint8_t *)iov->iov_base)[i] = byte_at(raw->id, i);
    struct sockaddr_in source = {.sin_family = AF_INET,
                                 .sin_port = htons((uint16_t)(4000 + raw->id)),
                                 .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    memcpy(message->msg_hdr.msg_name, &source, sizeof(source));
    message->msg_hdr.msg_namelen = sizeof(source);
    message->msg_len = (unsigned)raw->size;
    message->msg_hdr.msg_flags = raw->flags;
    if (raw->segment_size) {
      struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message->msg_hdr);
      assert(cmsg);
      cmsg->cmsg_level = SOL_UDP;
      cmsg->cmsg_type = UDP_GRO;
      cmsg->cmsg_len = CMSG_LEN(sizeof(int));
      memcpy(CMSG_DATA(cmsg), &raw->segment_size, sizeof(int));
      message->msg_hdr.msg_controllen = CMSG_SPACE(sizeof(int));
    } else {
      message->msg_hdr.msg_controllen = 0;
    }
  }
  return (int)received;
}

static void reset_queue(void) {
  queued_next = queued_count = 0;
  interruptions = receive_calls = 0;
  receive_error = 0;
}

static void enqueue(size_t size, int segment_size, int flags, unsigned id) {
  assert(queued_count < sizeof(queued) / sizeof(queued[0]));
  queued[queued_count++] = (queued_message_t){size, segment_size, flags, id};
}

static void check_view(const transport_udp_view_t *view, unsigned id,
                       size_t offset, size_t size) {
  assert(!view->dropped && view->size == size);
  const struct sockaddr_in *source = (const struct sockaddr_in *)&view->source;
  assert(source->sin_family == AF_INET && ntohs(source->sin_port) == 4000 + id);
  for (size_t i = 0; i < size; i++)
    assert(view->data[i] == byte_at(id, offset + i));
}

static void metadata(void) {
  union {
    struct cmsghdr alignment;
    uint8_t bytes[2 * CMSG_SPACE(sizeof(int))];
  } control = {0};
  struct msghdr message = {.msg_control = control.bytes};
  size_t segment = 999;
  assert(gro_segment_size(&message, 0, &segment) && segment == 0);
  message.msg_controllen = CMSG_SPACE(sizeof(int));
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
  *cmsg = (struct cmsghdr){.cmsg_level = SOL_UDP,
                           .cmsg_type = UDP_GRO,
                           .cmsg_len = CMSG_LEN(sizeof(int))};
  int value = 1280;
  memcpy(CMSG_DATA(cmsg), &value, sizeof(value));
  assert(gro_segment_size(&message, 1280 * 5 + 43, &segment) &&
         segment == 1280);
  assert(!gro_segment_size(&message, 1279, &segment));
  assert(!gro_segment_size(&message, 0, &segment));
  value = -1;
  memcpy(CMSG_DATA(cmsg), &value, sizeof(value));
  assert(!gro_segment_size(&message, 7680, &segment));
  value = 0;
  memcpy(CMSG_DATA(cmsg), &value, sizeof(value));
  assert(!gro_segment_size(&message, 7680, &segment));
  value = 65536;
  memcpy(CMSG_DATA(cmsg), &value, sizeof(value));
  assert(!gro_segment_size(&message, 65536, &segment));
  value = 1280;
  memcpy(CMSG_DATA(cmsg), &value, sizeof(value));
  cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
  assert(!gro_segment_size(&message, 7680, &segment));
  cmsg->cmsg_len = sizeof(struct cmsghdr) - 1;
  assert(!gro_segment_size(&message, 7680, &segment));
  cmsg->cmsg_len = sizeof(control) + 1;
  assert(!gro_segment_size(&message, 7680, &segment));
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  message.msg_flags = MSG_CTRUNC;
  assert(!gro_segment_size(&message, 7680, &segment));
  message.msg_flags = MSG_TRUNC;
  assert(!gro_segment_size(&message, 7680, &segment));
  message.msg_flags = 0;
  memcpy(control.bytes + CMSG_SPACE(sizeof(int)), control.bytes,
         CMSG_SPACE(sizeof(int)));
  message.msg_controllen = sizeof(control);
  assert(!gro_segment_size(&message, 7680, &segment));
  message.msg_controllen = CMSG_SPACE(sizeof(int)) + 1;
  assert(!gro_segment_size(&message, 7680, &segment));
  message.msg_controllen = CMSG_LEN(sizeof(int));
  assert(gro_segment_size(&message, 7680, &segment));
  cmsg->cmsg_type = UDP_SEGMENT; /* unrelated, structurally valid metadata */
  assert(gro_segment_size(&message, 7680, &segment) && segment == 0);
}

static void deterministic(void) {
  fake = true;
  allocation_failure = true;
  assert(!transport_udp_gro_create(7) && errno == ENOMEM && option_calls == 0);
  allocation_failure = false;
  option_failure = true;
  assert(!transport_udp_gro_create(7) && errno == ENOPROTOOPT);
  assert(allocations == frees);
  option_failure = false;
  assert(!transport_udp_gro_create(-1) && errno == EINVAL);
  transport_udp_gro_t *state = transport_udp_gro_create(7);
  assert(state && !transport_udp_gro_pending(state));
  transport_udp_view_t views[32];
  bool more = true;
  reset_queue();
  assert(transport_udp_gro_receive(state, 7, views, 32, &more) == 0 && !more);
  assert(transport_udp_gro_receive(state, 8, views, 1, &more) == -1 &&
         errno == EINVAL);
  assert(transport_udp_gro_receive(state, 7, NULL, 1, &more) == -1 &&
         errno == EINVAL);
  assert(transport_udp_gro_receive(state, 7, views, 33, &more) == -1 &&
         errno == E2BIG);
  reset_queue();
  for (unsigned id = 1; id <= 5; id++)
    enqueue(6 * 1280, 1280, 0, id);
  interruptions = 1;
  assert(transport_udp_gro_receive(state, 7, views, 1, &more) == 1 && more);
  check_view(&views[0], 1, 0, 1280);
  assert(transport_udp_gro_pending(state) && receive_calls == 2);
  assert(transport_udp_gro_receive(state, 7, views, 7, &more) == 7 && more);
  for (size_t i = 0; i < 7; i++)
    check_view(&views[i], (unsigned)((i + 1) / 6) + 1, ((i + 1) % 6) * 1280,
               1280);
  assert(transport_udp_gro_receive(state, 7, views, 32, &more) == 16 && more);
  for (size_t i = 0; i < 16; i++)
    check_view(&views[i], (unsigned)((i + 8) / 6) + 1, ((i + 8) % 6) * 1280,
               1280);
  assert(!transport_udp_gro_pending(state) && receive_calls == 2);
  assert(transport_udp_gro_receive(state, 7, views, 32, &more) == 6 && !more);
  for (size_t i = 0; i < 6; i++)
    check_view(&views[i], 5, i * 1280, 1280);
  assert(!transport_udp_gro_pending(state));
  reset_queue();
  enqueue(2 * 1280 + 43, 1280, 0, 6);
  enqueue(0, 0, 0, 7);
  enqueue(2049, 0, 0, 8);
  assert(transport_udp_gro_receive(state, 7, views, 32, &more) == 5 && !more);
  check_view(&views[0], 6, 0, 1280);
  check_view(&views[1], 6, 1280, 1280);
  check_view(&views[2], 6, 2560, 43);
  check_view(&views[3], 7, 0, 0);
  check_view(&views[4], 8, 0, 2048);
  assert(views[4].truncated && !views[3].truncated);
  reset_queue();
  enqueue(6 * 1280, 1280, MSG_TRUNC, 1);
  enqueue(6 * 1280, 1280, MSG_CTRUNC, 2);
  enqueue(6 * 1280, -1, 0, 3);
  enqueue(10, 1280, 0, 4);
  enqueue(65537, 1280, 0, 5);
  enqueue(11, 0, 0, 6);
  for (unsigned i = 0; i < 5; i++) {
    assert(transport_udp_gro_receive(state, 7, views, 1, &more) == 1 && more);
    assert(views[0].dropped && views[0].size == 0 && views[0].data == NULL);
  }
  assert(transport_udp_gro_receive(state, 7, views, 1, &more) == 1 && !more);
  check_view(&views[0], 6, 0, 11);
  assert(!transport_udp_gro_pending(state));
  reset_queue();
  enqueue(65536, 1024, 0, 9);
  for (unsigned half = 0; half < 2; half++) {
    assert(transport_udp_gro_receive(state, 7, views, 32, &more) == 32);
    assert(more == (half == 0));
    for (size_t i = 0; i < 32; i++)
      check_view(&views[i], 9, (half * 32 + i) * 1024, 1024);
  }
  reset_queue();
  enqueue(2 * 2049 + 13, 2049, 0, 10);
  assert(transport_udp_gro_receive(state, 7, views, 32, &more) == 3 && !more);
  check_view(&views[0], 10, 0, 2048);
  check_view(&views[1], 10, 2049, 2048);
  check_view(&views[2], 10, 4098, 13);
  assert(views[0].truncated && views[1].truncated && !views[2].truncated);
  receive_error = EIO;
  assert(transport_udp_gro_receive(state, 7, views, 32, &more) == -1 && !more);
  assert(!transport_udp_gro_pending(state));
  transport_udp_gro_destroy(state);
  transport_udp_gro_destroy(NULL);
  assert(allocations == frees);
  fake = false;
}

static void check_real_source(const transport_udp_view_t *view, int family,
                              const struct sockaddr_storage *sender) {
  assert(view->source.ss_family == family);
  if (family == AF_INET) {
    const struct sockaddr_in *actual =
        (const struct sockaddr_in *)&view->source;
    const struct sockaddr_in *local = (const struct sockaddr_in *)sender;
    assert(actual->sin_port == local->sin_port);
    assert(actual->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
  } else {
    const struct sockaddr_in6 *actual =
        (const struct sockaddr_in6 *)&view->source;
    const struct sockaddr_in6 *local = (const struct sockaddr_in6 *)sender;
    assert(actual->sin6_port == local->sin6_port);
    assert(memcmp(&actual->sin6_addr, &in6addr_loopback,
                  sizeof(in6addr_loopback)) == 0);
  }
}

static void real_socket(int family) {
  int sender = socket(family, SOCK_DGRAM, 0);
  int sink = socket(family, SOCK_DGRAM, 0);
  assert(sender >= 0 && sink >= 0);
  struct sockaddr_storage destination = {0};
  socklen_t length;
  if (family == AF_INET) {
    struct sockaddr_in *address = (struct sockaddr_in *)&destination;
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    length = sizeof(*address);
  } else {
    struct sockaddr_in6 *address = (struct sockaddr_in6 *)&destination;
    address->sin6_family = AF_INET6;
    address->sin6_addr = in6addr_loopback;
    length = sizeof(*address);
  }
  assert(bind(sink, (struct sockaddr *)&destination, length) == 0);
  assert(getsockname(sink, (struct sockaddr *)&destination, &length) == 0);
  transport_udp_gro_t *state = transport_udp_gro_create(sink);
  if (!state) {
    assert(errno == ENOPROTOOPT || errno == EOPNOTSUPP || errno == EINVAL);
    puts("UDP_GRO unavailable: real-socket case skipped");
    close(sender);
    close(sink);
    return;
  }
  uint8_t payload[5 * 1280 + 43];
  for (size_t i = 0; i < sizeof(payload); i++)
    payload[i] = byte_at(11, i);
  union {
    struct cmsghdr alignment;
    uint8_t bytes[CMSG_SPACE(sizeof(uint16_t))];
  } control = {0};
  struct iovec iov = {payload, sizeof(payload)};
  struct msghdr message = {.msg_name = &destination,
                           .msg_namelen = length,
                           .msg_iov = &iov,
                           .msg_iovlen = 1,
                           .msg_control = control.bytes,
                           .msg_controllen = sizeof(control)};
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
  *cmsg = (struct cmsghdr){.cmsg_level = SOL_UDP,
                           .cmsg_type = UDP_SEGMENT,
                           .cmsg_len = CMSG_LEN(sizeof(uint16_t))};
  uint16_t segment_size = 1280;
  memcpy(CMSG_DATA(cmsg), &segment_size, sizeof(segment_size));
  ssize_t sent = sendmsg(sender, &message, 0);
  if (sent < 0) {
    assert(errno == ENOPROTOOPT || errno == EOPNOTSUPP || errno == EINVAL);
    puts("UDP_SEGMENT unavailable: real-socket case skipped");
  } else {
    assert(sent == sizeof(payload));
    struct sockaddr_storage sender_address;
    socklen_t sender_length = sizeof(sender_address);
    assert(getsockname(sender, (struct sockaddr *)&sender_address,
                       &sender_length) == 0);
    transport_udp_view_t views[32];
    bool more;
    assert(transport_udp_gro_receive(state, sink, views, 1, &more) == 1);
    assert(more && transport_udp_gro_pending(state));
    assert(!views[0].dropped && views[0].size == 1280);
    check_real_source(&views[0], family, &sender_address);
    assert(memcmp(views[0].data, payload, 1280) == 0);
    struct pollfd pfd = {.fd = sink, .events = POLLIN};
    assert(poll(&pfd, 1, 0) ==
           0); /* remaining segments exist only in userspace */
    assert(transport_udp_gro_receive(state, sink, views, 32, &more) == 5 &&
           !more);
    for (size_t i = 0; i < 5; i++) {
      assert(!views[i].dropped && views[i].source.ss_family == family);
      check_real_source(&views[i], family, &sender_address);
      size_t size = i == 4 ? 43 : 1280;
      assert(views[i].size == size && !views[i].truncated);
      assert(memcmp(views[i].data, payload + (i + 1) * 1280, size) == 0);
    }
    assert(!transport_udp_gro_pending(state));
    assert(transport_udp_gro_receive(state, sink, views, 32, &more) == 0 &&
           !more);
    assert(sendto(sender, "", 0, 0, (struct sockaddr *)&destination, length) ==
           0);
    assert(sendto(sender, payload, 2049, 0, (struct sockaddr *)&destination,
                  length) == 2049);
    assert(transport_udp_gro_receive(state, sink, views, 32, &more) == 2 &&
           !more);
    assert(!views[0].dropped && views[0].size == 0 && !views[0].truncated);
    assert(!views[1].dropped && views[1].size == 2048 && views[1].truncated);
    assert(memcmp(views[1].data, payload, 2048) == 0);
  }
  transport_udp_gro_destroy(state);
  close(sink);
  close(sender);
}

int main(void) {
  metadata();
  deterministic();
  real_socket(AF_INET);
  real_socket(AF_INET6);
  puts("===UDP GRO OK===");
  return 0;
}
#else
int main(void) {
  return 0;
}
#endif
