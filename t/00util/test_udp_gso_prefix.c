/* Deterministic syscall fault injection. The separate transport-components
 * real-socket cases cover the same GSO boundaries against the kernel. */
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>

#ifdef __linux__
static int mock_sendmmsg(int, struct mmsghdr *, unsigned int, int);
#define sendmmsg mock_sendmmsg
#include "../../src/common/transport_udp.c"
#undef sendmmsg

typedef struct {
  int result, error;
  unsigned messages;
  bool first_is_gso;
} send_step_t;
static send_step_t steps[8];
static size_t step_count, send_calls;
static struct iovec expected[64];
static uint8_t payload[64][1500];
static uint8_t contiguous_payload[64 * 1500];
static bool contiguous_layout;
static uint8_t expected_ecn;
static size_t max_gso_segments;
static size_t accepted, expected_count, ordinary_accepted, gso_accepted;
static size_t direct_accepted, scatter_accepted;
static size_t groups[64], group_count;

/* Validate bytes and logical boundaries even for an offered but unaccepted
 * message. A partial syscall must never offer a previously accepted prefix. */
static size_t check_message(const struct msghdr *message, size_t first,
                            bool record) {
  const struct sockaddr_in *address = message->msg_name;
  assert(address && message->msg_namelen == sizeof(*address));
  assert(address->sin_family == AF_INET && address->sin_port == htons(4433));
  assert(message->msg_iovlen > 0 && message->msg_iovlen <= 64);
  uint8_t bytes[65507];
  size_t total = 0;
  for (size_t i = 0; i < message->msg_iovlen; i++) {
    assert(message->msg_iov[i].iov_len <= sizeof(bytes) - total);
    memcpy(bytes + total, message->msg_iov[i].iov_base,
           message->msg_iov[i].iov_len);
    total += message->msg_iov[i].iov_len;
  }
  size_t logical = 0;
  struct cmsghdr *first_control = CMSG_FIRSTHDR((struct msghdr *)message);
  bool is_gso = first_control && first_control->cmsg_level == SOL_UDP &&
                first_control->cmsg_type == UDP_SEGMENT;
  struct cmsghdr *mark =
      is_gso ? CMSG_NXTHDR((struct msghdr *)message, first_control)
             : first_control;
  if (expected_ecn) {
    assert(mark && mark->cmsg_level == IPPROTO_IP && mark->cmsg_type == IP_TOS);
    assert(mark->cmsg_len == CMSG_LEN(sizeof(int)));
    int value;
    memcpy(&value, CMSG_DATA(mark), sizeof(value));
    assert(value == expected_ecn);
    assert(!CMSG_NXTHDR((struct msghdr *)message, mark));
  } else {
    assert(!mark);
  }
  if (is_gso) {
    struct cmsghdr *cmsg = CMSG_FIRSTHDR((struct msghdr *)message);
    assert(cmsg && cmsg->cmsg_level == SOL_UDP &&
           cmsg->cmsg_type == UDP_SEGMENT &&
           cmsg->cmsg_len == CMSG_LEN(sizeof(uint16_t)));
    assert((CMSG_NXTHDR((struct msghdr *)message, cmsg) != NULL) ==
           (expected_ecn != 0));
    uint16_t segment;
    memcpy(&segment, CMSG_DATA(cmsg), sizeof(segment));
    assert(segment > 0 && total > segment);
    for (size_t offset = 0; offset < total;) {
      size_t len = total - offset;
      if (len > segment)
        len = segment;
      assert(first + logical < expected_count);
      assert(len == expected[first + logical].iov_len);
      assert(memcmp(bytes + offset, expected[first + logical].iov_base, len) ==
             0);
      offset += len;
      logical++;
    }
    assert(logical >= 2);
    assert(!max_gso_segments || logical <= max_gso_segments);
    if (record) {
      gso_accepted++;
      groups[group_count++] = logical;
      if (message->msg_iovlen == 1) {
        assert(message->msg_iov[0].iov_base == expected[first].iov_base);
        direct_accepted++;
      } else {
        assert(message->msg_iovlen == logical);
        for (size_t i = 0; i < logical; i++) {
          assert(message->msg_iov[i].iov_base == expected[first + i].iov_base);
          assert(message->msg_iov[i].iov_len == expected[first + i].iov_len);
        }
        scatter_accepted++;
      }
    }
  } else {
    assert((expected_ecn || !message->msg_control) && message->msg_iovlen == 1);
    assert(first < expected_count && total == expected[first].iov_len);
    assert(memcmp(bytes, expected[first].iov_base, total) == 0);
    logical = 1;
    if (record)
      ordinary_accepted++;
  }
  return logical;
}

static int mock_sendmmsg(int fd, struct mmsghdr *messages, unsigned int count,
                         int flags) {
  assert(fd == 7 && flags == 0 && count > 0 && count <= 64);
  size_t offered = accepted;
  for (unsigned i = 0; i < count; i++)
    offered += check_message(&messages[i].msg_hdr, offered, false);
  assert(offered == expected_count);
  send_step_t step = {.result = (int)count};
  if (send_calls < step_count) {
    step = steps[send_calls];
    assert(count == step.messages);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&messages[0].msg_hdr);
    assert((cmsg && cmsg->cmsg_level == SOL_UDP &&
            cmsg->cmsg_type == UDP_SEGMENT) == step.first_is_gso);
  }
  send_calls++;
  if (step.result < 0) {
    errno = step.error;
    return -1;
  }
  assert((unsigned)step.result <= count);
  for (int i = 0; i < step.result; i++) {
    accepted += check_message(&messages[i].msg_hdr, accepted, true);
    size_t bytes = 0;
    for (size_t j = 0; j < messages[i].msg_hdr.msg_iovlen; j++)
      bytes += messages[i].msg_hdr.msg_iov[j].iov_len;
    messages[i].msg_len = (unsigned)bytes;
  }
  return step.result;
}

static void setup(size_t count, size_t size) {
  accepted = send_calls = step_count = group_count = 0;
  max_gso_segments = 0;
  gso_accepted = ordinary_accepted = direct_accepted = scatter_accepted = 0;
  expected_count = count;
  for (size_t i = 0; i < count; i++) {
    for (size_t j = 0; j < sizeof(payload[i]); j++)
      payload[i][j] = (uint8_t)(i * 23U + j);
    expected[i] = (struct iovec){payload[i], size};
    if (contiguous_layout) {
      expected[i].iov_base = contiguous_payload + i * size;
      memcpy(expected[i].iov_base, payload[i], size);
    }
  }
}

static void step(int result, int error, unsigned messages, bool gso) {
  assert(step_count < sizeof(steps) / sizeof(steps[0]));
  steps[step_count++] = (send_step_t){result, error, messages, gso};
}

static ssize_t send_suffix(void) {
  struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(4433)};
  return transport_udp_send_batch_ecn(
      7, (struct sockaddr *)&address, sizeof(address), expected + accepted,
      expected_count - accepted, max_gso_segments, expected_ecn);
}

static void run_limited_layout(void) {
  setup(16, 1280);
  max_gso_segments = 6;
  assert(send_suffix() == 16 && accepted == 16 && send_calls == 1 &&
         group_count == 3 && groups[0] == 6 && groups[1] == 6 &&
         groups[2] == 4);
  assert(direct_accepted == (contiguous_layout ? 3 : 0) &&
         scatter_accepted == (contiguous_layout ? 0 : 3));
  setup(64, 1280);
  max_gso_segments = 6;
  assert(send_suffix() == 64 && accepted == 64 && send_calls == 1 &&
         group_count == 11 && groups[10] == 4);
  for (size_t i = 0; i < 10; i++)
    assert(groups[i] == 6);
  setup(64, 1280);
  max_gso_segments = 64;
  assert(send_suffix() == 64 && send_calls == 1 && groups[0] == 51 &&
         groups[1] == 13); /* Byte ceiling still applies. */
  setup(16, 1280);
  max_gso_segments = 1;
  assert(send_suffix() == 16 && send_calls == 1 && gso_accepted == 0 &&
         ordinary_accepted == 16);
  setup(16, 1280);
  max_gso_segments = 6;
  expected[3].iov_len = 13;
  assert(send_suffix() == 16 && send_calls == 1 && group_count == 3 &&
         groups[0] == 4 && groups[1] == 6 && groups[2] == 6);
  setup(16, 1280);
  max_gso_segments = 6;
  expected[6].iov_len = 0;
  assert(send_suffix() == 16 && send_calls == 1 && groups[0] == 6 &&
         gso_accepted == 1 && ordinary_accepted == 10);
  setup(13, 1280);
  max_gso_segments = 6;
  assert(send_suffix() == 13 && send_calls == 1 && group_count == 2 &&
         groups[0] == 6 && groups[1] == 6 && ordinary_accepted == 1);

  /* Two accepted groups mean twelve datagrams, then smaller flats advance. */
  setup(16, 1280);
  max_gso_segments = 6;
  step(2, 0, 3, true);
  step(-1, EINTR, 1, true);
  step(-1, EAGAIN, 1, true);
  step(2, 0, 4, false);
  step(-1, EAGAIN, 2, false);
  assert(send_suffix() == 14 && accepted == 14 && send_calls == 5);
  assert(send_suffix() == 2 && accepted == 16);
  const int fallback_errors[] = {EOPNOTSUPP, EMSGSIZE, EAGAIN};
  for (size_t i = 0; i < sizeof(fallback_errors) / sizeof(fallback_errors[0]);
       i++) {
    setup(16, 1280);
    max_gso_segments = 6;
    step(1, 0, 3, true);
    step(-1, fallback_errors[i], 2, true);
    step(10, 0, 10, false);
    assert(send_suffix() == 16 && accepted == 16 && gso_accepted == 1 &&
           ordinary_accepted == 10);
  }
  setup(16, 1280);
  max_gso_segments = 6;
  step(-1, EAGAIN, 3, true);
  step(5, 0, 16, false);
  step(-1, EAGAIN, 11, false);
  assert(send_suffix() == 5 && accepted == 5 && send_calls == 3);
  assert(send_suffix() == 11 && accepted == 16);
  setup(16, 1280);
  max_gso_segments = 6;
  step(1, 0, 3, true);
  step(-1, EIO, 2, true);
  step(-1, EIO, 10, false);
  assert(send_suffix() == 6 && accepted == 6 && errno == EIO);
  assert(send_suffix() == 10 && accepted == 16);

  /* A final singleton is already ordinary: no aggregate fallback/replay. */
  setup(13, 1280);
  max_gso_segments = 6;
  step(2, 0, 3, true);
  step(-1, EAGAIN, 1, false);
  assert(send_suffix() == 12 && accepted == 12 && send_calls == 2);
  assert(send_suffix() == 1 && accepted == 13 && ordinary_accepted == 1);
  setup(16, 1280);
  max_gso_segments = 65;
  assert(send_suffix() == -1 && errno == EINVAL && send_calls == 0);
  max_gso_segments = SIZE_MAX;
  assert(send_suffix() == -1 && errno == EINVAL && send_calls == 0);
  setup(0, 1280);
  max_gso_segments = 65;
  assert(send_suffix() == -1 && errno == EINVAL && send_calls == 0);
}

static void run_layout(void) {
  setup(64, 1280);
  assert(send_suffix() == 64 && accepted == 64 && send_calls == 1);
  assert(gso_accepted == 2 && ordinary_accepted == 0 && groups[0] == 51 &&
         groups[1] == 13);
  assert(direct_accepted == (contiguous_layout ? 2 : 0) &&
         scatter_accepted == (contiguous_layout ? 0 : 2));
  setup(64, 1500);
  assert(send_suffix() == 64 && send_calls == 1 && groups[0] == 43 &&
         groups[1] == 21);
  assert(direct_accepted == 2 && scatter_accepted == 0);
  setup(64, 1280);
  expected[20].iov_len = 13;
  assert(send_suffix() == 64 && send_calls == 1 && group_count == 2 &&
         groups[0] == 21 && groups[1] == 43);
  setup(64, 1280);
  expected[20].iov_len = 0;
  assert(send_suffix() == 64 && send_calls == 1 && groups[0] == 20 &&
         gso_accepted == 1 && ordinary_accepted == 44);
  setup(64, 1280);
  expected[20].iov_len = 1500;
  assert(send_suffix() == 64 && send_calls == 1 && group_count == 3 &&
         groups[0] == 20 && groups[1] == 2 && groups[2] == 42);

  /* Kernel acceptance counts messages, not logical segments. */
  setup(64, 1280);
  step(1, 0, 2, true);
  step(-1, EAGAIN, 1, true);
  step(-1, EAGAIN, 13, false);
  assert(send_suffix() == 51 && accepted == 51 && send_calls == 3);
  assert(send_suffix() == 13 && accepted == 64);
  setup(64, 1280);
  step(1, 0, 2, true);
  step(-1, EIO, 1, true);
  step(-1, EIO, 13, false);
  assert(send_suffix() == 51 && accepted == 51 && errno == EIO);
  assert(send_suffix() == 13 && accepted == 64);

  /* GSO failures must still allow smaller ordinary sends to make progress. */
  const int gso_errors[] = {EOPNOTSUPP, ENOPROTOOPT, EINVAL, EMSGSIZE, EAGAIN};
  for (size_t i = 0; i < sizeof(gso_errors) / sizeof(gso_errors[0]); i++) {
    setup(64, 1280);
    step(-1, gso_errors[i], 2, true);
    step(64, 0, 64, false);
    assert(send_suffix() == 64 && accepted == 64 && send_calls == 2 &&
           gso_accepted == 0 && ordinary_accepted == 64);
  }
  setup(64, 1280);
  step(1, 0, 2, true);
  step(-1, EOPNOTSUPP, 1, true);
  step(13, 0, 13, false);
  assert(send_suffix() == 64 && accepted == 64 && gso_accepted == 1 &&
         ordinary_accepted == 13);
  setup(64, 1280);
  step(1, 0, 2, true);
  step(-1, EAGAIN, 1, true);
  step(5, 0, 13, false);
  step(-1, EAGAIN, 8, false);
  assert(send_suffix() == 56 && accepted == 56 && send_calls == 4);
  assert(send_suffix() == 8 && accepted == 64);

  setup(64, 1280);
  step(-1, EIO, 2, true);
  step(-1, EIO, 64, false);
  assert(send_suffix() == -1 && accepted == 0 && errno == EIO);
  setup(64, 1280);
  step(-1, EAGAIN, 2, true);
  step(-1, EAGAIN, 64, false);
  assert(send_suffix() == 0 && accepted == 0 && send_calls == 2);
  assert(send_suffix() == 64 && accepted == 64);
  setup(64, 1280);
  step(-1, EINTR, 2, true);
  step(-1, EAGAIN, 2, true);
  step(-1, EINTR, 64, false);
  step(-1, EAGAIN, 64, false);
  assert(send_suffix() == 0 && accepted == 0 && send_calls == 4);
  assert(send_suffix() == 64 && accepted == 64);
  setup(64, 1280);
  step(1, 0, 2, true);
  step(-1, EINTR, 1, true);
  step(1, 0, 1, true);
  assert(send_suffix() == 64 && accepted == 64 && send_calls == 3);

  /* Accepted GSO + an empty ordinary datagram precede a blocked flat suffix. */
  setup(64, 1280);
  expected[20].iov_len = 0;
  step(2, 0, 45, true);
  step(-1, EAGAIN, 43, false);
  assert(send_suffix() == 21 && accepted == 21 && send_calls == 2);
  assert(send_suffix() == 43 && accepted == 64);
  setup(2, 1280);
  expected[0].iov_len = 0;
  step(-1, EINTR, 2, false);
  step(1, 0, 2, false);
  step(-1, EIO, 1, false);
  assert(send_suffix() == 1 && accepted == 1 && errno == EIO);
  assert(send_suffix() == 1 && accepted == 2);
  setup(2, 1280);
  expected[0].iov_len = 40;
  assert(send_suffix() == 2 && ordinary_accepted == 2 && gso_accepted == 0);
  setup(64, 1280);
  step(0, 0, 2, true);
  assert(send_suffix() == -1 && accepted == 0 && errno == EIO &&
         send_calls == 1);
}

int main(void) {
  contiguous_layout = false;
  run_layout();
  run_limited_layout();
  contiguous_layout = true;
  run_layout();
  run_limited_layout();
  /* One displaced datagram must remain scatter/gather with exact bytes. */
  setup(6, 1280);
  expected[4].iov_base = payload[4];
  assert(send_suffix() == 6 && accepted == 6 && direct_accepted == 0 &&
         scatter_accepted == 1 && send_calls == 1);
  expected_ecn = 2;
  contiguous_layout = false;
  run_layout();
  run_limited_layout();
  contiguous_layout = true;
  run_layout();
  run_limited_layout();
  puts("UDP GSO grouping and partial-send fault injection passed");
  return 0;
}
#else
int main(void) {
  return 0;
}
#endif
