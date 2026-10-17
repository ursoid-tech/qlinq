#include "transport_udp.h"
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Compile the portable receive path with one injected EINTR, alongside the
 * linked Linux batch implementation. Production send semantics are unchanged.
 */
static unsigned interruptions;
static ssize_t interrupted_recvmsg(int fd, struct msghdr *message, int flags) {
  if (interruptions) {
    interruptions--;
    errno = EINTR;
    return -1;
  }
  return recvmsg(fd, message, flags);
}
#define QLINQ_UDP_RECEIVE_PORTABLE 1
#define recvmsg interrupted_recvmsg
#define transport_udp_receive_batch portable_receive_batch
#define transport_udp_send_batch portable_send_batch
#define transport_udp_gro_create portable_gro_create
#define transport_udp_gro_destroy portable_gro_destroy
#define transport_udp_gro_pending portable_gro_pending
#define transport_udp_gro_receive portable_gro_receive
#include "../../src/common/transport_udp.c"
#undef transport_udp_gro_create
#undef transport_udp_gro_destroy
#undef transport_udp_gro_pending
#undef transport_udp_gro_receive
#undef transport_udp_receive_batch
#undef transport_udp_send_batch
#undef recvmsg

typedef ssize_t (*receive_fn)(int, transport_udp_datagram_t *, size_t);

static void run(int family, receive_fn receive) {
  int sender = socket(family, SOCK_DGRAM, 0);
  int sink = socket(family, SOCK_DGRAM, 0);
  assert(sender >= 0 && sink >= 0);
  struct sockaddr_storage address = {0};
  socklen_t length;
  if (family == AF_INET) {
    struct sockaddr_in *v4 = (struct sockaddr_in *)&address;
    v4->sin_family = AF_INET;
    v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    length = sizeof(*v4);
  } else {
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&address;
    v6->sin6_family = AF_INET6;
    v6->sin6_addr = in6addr_loopback;
    length = sizeof(*v6);
  }
  assert(bind(sink, (struct sockaddr *)&address, length) == 0);
  assert(getsockname(sink, (struct sockaddr *)&address, &length) == 0);
  transport_udp_datagram_t packets[TRANSPORT_UDP_RECEIVE_BATCH];
  assert(receive(sink, packets, 32) == 0);
  for (unsigned i = 0; i < 65; i++) {
    unsigned value = i;
    assert(sendto(sender, &value, sizeof(value), 0, (struct sockaddr *)&address,
                  length) == sizeof(value));
  }
  unsigned total = 0;
  interruptions = 1;
  for (size_t expected = 32; total < 65; expected = total == 64 ? 1 : 32) {
    ssize_t count = receive(sink, packets, 32);
    assert(count == (ssize_t)expected);
    for (ssize_t i = 0; i < count; i++) {
      unsigned value;
      assert(packets[i].size == sizeof(value) && !packets[i].truncated);
      assert(packets[i].source.ss_family == family);
      memcpy(&value, packets[i].data, sizeof(value));
      assert(value == total++);
    }
  }
  assert(receive(sink, packets, 32) == 0);
  assert(sendto(sender, "", 0, 0, (struct sockaddr *)&address, length) == 0);
  uint8_t oversized[TRANSPORT_UDP_RECEIVE_SIZE + 1];
  for (size_t i = 0; i < sizeof(oversized); i++)
    oversized[i] = (uint8_t)i;
  assert(sendto(sender, oversized, sizeof(oversized), 0,
                (struct sockaddr *)&address, length) == sizeof(oversized));
  assert(receive(sink, packets, 32) == 2);
  assert(packets[0].size == 0 && !packets[0].truncated);
  assert(packets[1].size == TRANSPORT_UDP_RECEIVE_SIZE && packets[1].truncated);
  assert(memcmp(packets[1].data, oversized, TRANSPORT_UDP_RECEIVE_SIZE) == 0);
  assert(receive(sink, NULL, 0) == 0);
  assert(receive(sink, NULL, 1) == -1 && errno == EINVAL);
  assert(receive(-1, packets, 1) == -1 && errno == EINVAL);
  assert(receive(sink, packets, 33) == -1 && errno == E2BIG);
  close(sink);
  assert(receive(sink, packets, 1) == -1 && errno == EBADF);
  close(sender);
}

int main(void) {
  assert(!portable_gro_create(7) && errno == ENOTSUP);
  run(AF_INET, transport_udp_receive_batch);
  run(AF_INET6, transport_udp_receive_batch);
  run(AF_INET, portable_receive_batch);
  run(AF_INET6, portable_receive_batch);
  puts("===UDP RECEIVE OK===");
  return 0;
}
