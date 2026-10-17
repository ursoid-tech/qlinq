/* Deterministic syscall fault injection: no live socket or kernel GSO needed.
 */
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>

#ifdef __linux__
static ssize_t mock_sendmsg(int, const struct msghdr *, int);
static int mock_sendmmsg(int, struct mmsghdr *, unsigned int, int);
#define sendmsg mock_sendmsg
#define sendmmsg mock_sendmmsg
#include "../../src/common/transport_udp.c"
#undef sendmsg
#undef sendmmsg

enum fault {
  NONE,
  SECOND_BLOCK,
  SECOND_HARD,
  FIRST_BLOCK,
  FIRST_HARD,
  UNSUPPORTED,
  INTERRUPTED,
  INTERRUPTED_BLOCK,
  PARTIAL_BLOCK
};
static enum fault fault;
static struct iovec expected[64];
static uint8_t payload[64][1500];
static uint8_t contiguous_payload[64 * 1500];
static bool contiguous_layout;
static size_t accepted, expected_count, gso_calls, ordinary_calls;
static size_t direct_calls, packed_calls;
static size_t groups[64], group_count;

static void accept_datagram(const void *data, size_t len) {
  assert(accepted < expected_count);
  assert(len == expected[accepted].iov_len);
  assert(memcmp(data, expected[accepted].iov_base, len) == 0);
  accepted++;
}

static ssize_t mock_sendmsg(int fd, const struct msghdr *msg, int flags) {
  assert(fd == 7 && flags == 0 && msg->msg_iovlen == 1);
  gso_calls++;
  if (msg->msg_iov[0].iov_base == expected[accepted].iov_base)
    direct_calls++;
  else
    packed_calls++;
  if (fault == INTERRUPTED_BLOCK) {
    errno = gso_calls == 1 ? EINTR : EAGAIN;
    return -1;
  }
  if ((fault == INTERRUPTED && gso_calls == 1) || (fault == UNSUPPORTED) ||
      (fault == FIRST_HARD) || (fault == FIRST_BLOCK) ||
      ((fault == SECOND_BLOCK || fault == SECOND_HARD ||
        fault == PARTIAL_BLOCK) &&
       gso_calls == 2)) {
    errno = fault == INTERRUPTED   ? EINTR
            : fault == FIRST_BLOCK ? EAGAIN
                                   : EOPNOTSUPP;
    return -1;
  }
  struct cmsghdr *c = CMSG_FIRSTHDR((struct msghdr *)msg);
  assert(c && c->cmsg_level == SOL_UDP && c->cmsg_type == UDP_SEGMENT);
  uint16_t segment;
  memcpy(&segment, CMSG_DATA(c), sizeof(segment));
  assert(segment > 0 && msg->msg_iov[0].iov_len <= 65507);
  size_t before = accepted, offset = 0;
  while (offset < msg->msg_iov[0].iov_len) {
    size_t len = msg->msg_iov[0].iov_len - offset;
    if (len > segment)
      len = segment;
    accept_datagram((uint8_t *)msg->msg_iov[0].iov_base + offset, len);
    offset += len;
  }
  groups[group_count++] = accepted - before;
  return (ssize_t)offset;
}

static int mock_sendmmsg(int fd, struct mmsghdr *messages, unsigned int count,
                         int flags) {
  assert(fd == 7 && flags == 0 && count == expected_count - accepted);
  ordinary_calls++;
  if (fault == INTERRUPTED_BLOCK) {
    errno = ordinary_calls == 1 ? EINTR : EAGAIN;
    return -1;
  }
  if ((fault == SECOND_BLOCK) || (fault == SECOND_HARD) ||
      (fault == FIRST_HARD) || (fault == FIRST_BLOCK) ||
      (fault == PARTIAL_BLOCK && ordinary_calls == 2) ||
      (fault == INTERRUPTED && ordinary_calls == 1)) {
    errno = fault == INTERRUPTED ? EINTR
            : (fault == SECOND_BLOCK || fault == FIRST_BLOCK ||
               fault == PARTIAL_BLOCK)
                ? EAGAIN
                : EIO;
    return -1;
  }
  unsigned int sent = fault == PARTIAL_BLOCK && ordinary_calls == 1 ? 5 : count;
  assert(sent <= count);
  for (unsigned int i = 0; i < sent; i++) {
    assert(messages[i].msg_hdr.msg_iovlen == 1);
    struct iovec v = messages[i].msg_hdr.msg_iov[0];
    accept_datagram(v.iov_base, v.iov_len);
    messages[i].msg_len = (unsigned int)v.iov_len;
  }
  return (int)sent;
}

static void setup(size_t count, size_t size, enum fault which) {
  fault = which;
  accepted = gso_calls = ordinary_calls = group_count = 0;
  direct_calls = packed_calls = 0;
  expected_count = count;
  for (size_t i = 0; i < count; i++) {
    memset(payload[i], (int)i + 1, sizeof(payload[i]));
    expected[i] = (struct iovec){payload[i], size};
    if (contiguous_layout) {
      expected[i].iov_base = contiguous_payload + i * size;
      memcpy(expected[i].iov_base, payload[i], size);
    }
  }
}

static ssize_t send_suffix(void) {
  struct sockaddr_in address = {.sin_family = AF_INET};
  return transport_udp_send_batch(7, (struct sockaddr *)&address,
                                  sizeof(address), expected + accepted,
                                  expected_count - accepted);
}

static void run_layout(void) {
  setup(64, 1280, NONE);
  assert(send_suffix() == 64 && accepted == 64);
  assert(gso_calls == 2 && ordinary_calls == 0 && groups[0] == 51 &&
         groups[1] == 13);
  assert(direct_calls == (contiguous_layout ? 2 : 0) &&
         packed_calls == (contiguous_layout ? 0 : 2));
  setup(64, 1500, NONE);
  assert(send_suffix() == 64 && groups[0] == 43 && groups[1] == 21);
  assert(direct_calls == 2 && packed_calls == 0);
  setup(64, 1280, NONE);
  expected[20].iov_len = 13;
  assert(send_suffix() == 64 && group_count == 2 && groups[0] == 21);
  setup(64, 1280, NONE);
  expected[20].iov_len = 0;
  assert(send_suffix() == 64 && groups[0] == 20 && ordinary_calls == 1);
  setup(64, 1280, NONE);
  expected[20].iov_len = 1500;
  assert(send_suffix() == 64 && accepted == 64);
  setup(64, 1280, UNSUPPORTED);
  assert(send_suffix() == 64 && gso_calls == 1 && ordinary_calls == 1);
  assert(direct_calls == (contiguous_layout ? 1 : 0));
  setup(64, 1280, SECOND_BLOCK);
  assert(send_suffix() == 51 && accepted == 51);
  fault = NONE;
  assert(send_suffix() == 13 && accepted == 64);
  setup(64, 1280, SECOND_HARD);
  assert(send_suffix() == 51 && errno == EIO && accepted == 51);
  fault = NONE;
  assert(send_suffix() == 13 && accepted == 64);
  setup(64, 1280, FIRST_HARD);
  assert(send_suffix() == -1 && errno == EIO && accepted == 0);
  setup(64, 1280, FIRST_BLOCK);
  assert(send_suffix() == 0 && accepted == 0 && gso_calls == 1 &&
         ordinary_calls == 1);
  fault = NONE;
  assert(send_suffix() == 64 && accepted == 64);
  setup(64, 1280, INTERRUPTED_BLOCK);
  assert(send_suffix() == 0 && accepted == 0 && gso_calls == 2 &&
         ordinary_calls == 2);
  fault = NONE;
  assert(send_suffix() == 64 && accepted == 64);
  setup(64, 1280, PARTIAL_BLOCK);
  assert(send_suffix() == 56 && accepted == 56);
  fault = NONE;
  assert(send_suffix() == 8 && accepted == 64);
  setup(64, 1280, INTERRUPTED);
  assert(send_suffix() == 64 && accepted == 64 && gso_calls == 3);
  setup(2, 1280, INTERRUPTED);
  expected[0].iov_len = 0;
  assert(send_suffix() == 2 && ordinary_calls == 2);
}

int main(void) {
  /* exercise contiguous and separately retained layouts */
  contiguous_layout = false;
  run_layout();
  contiguous_layout = true;
  run_layout();
  /* gap in contiguous group must use packed path */
  setup(6, 1280, NONE);
  expected[4].iov_base = payload[4];
  assert(send_suffix() == 6 && accepted == 6 && direct_calls == 0 &&
         packed_calls == 1 && ordinary_calls == 0);
  puts("UDP GSO grouping and partial-send fault injection passed");
  return 0;
}
#else
int main(void) {
  return 0;
}
#endif
