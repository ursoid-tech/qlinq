#include "transport_egress.h"
#include "transport_udp.h"
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

static int failure;
static size_t calls;
static bool inspect_payloads;
static size_t send_allowance, next_sequence, expected_size;
static struct {
  size_t count, limit, sequence;
  ssize_t result;
  int error;
} policy_steps[16];
static size_t policy_step_count, policy_next_step;
static bool inspect_policy;

/* The UDP adapter returns zero for blocked sends and retries EINTR itself. */
ssize_t transport_udp_send_batch(int fd, const struct sockaddr *destination,
                                 socklen_t destination_len,
                                 const struct iovec *datagrams, size_t count,
                                 size_t max_gso_segments) {
  (void)fd;
  (void)destination_len;
  calls++;
  if (inspect_policy) {
    assert(policy_next_step < policy_step_count);
    size_t step = policy_next_step++;
    assert(count == policy_steps[step].count &&
           max_gso_segments == policy_steps[step].limit);
    for (size_t i = 0; i < count; i++) {
      assert(datagrams[i].iov_len == 32);
      const uint8_t *bytes = datagrams[i].iov_base;
      for (size_t j = 0; j < 32; j++)
        assert(bytes[j] == (uint8_t)(policy_steps[step].sequence + i + j * 13));
    }
    if (policy_steps[step].result < 0)
      errno = policy_steps[step].error;
    return policy_steps[step].result;
  }
  assert(max_gso_segments == 0);
  if (failure == EAGAIN)
    return 0;
  if (failure == ENETUNREACH &&
      ((const struct sockaddr_in *)destination)->sin_port == htons(1)) {
    errno = failure;
    return -1;
  }
  if (inspect_payloads) {
    if (count > send_allowance)
      count = send_allowance;
    for (size_t i = 0; i < count; ++i) {
      assert(datagrams[i].iov_len == expected_size);
      const uint8_t *bytes = datagrams[i].iov_base;
      for (size_t j = 0; j < expected_size; ++j)
        assert(bytes[j] == (uint8_t)(next_sequence + j * 13));
      next_sequence++;
    }
    send_allowance -= count;
  }
  return (ssize_t)count;
}

static void submit_sequence(transport_egress_t *egress,
                            const struct sockaddr_in *destination,
                            size_t sequence, size_t size) {
  uint8_t bytes[64];
  assert(size <= sizeof(bytes));
  for (size_t i = 0; i < size; ++i)
    bytes[i] = (uint8_t)(sequence + i * 13);
  struct iovec vec = {.iov_base = bytes, .iov_len = size};
  assert(transport_egress_submit(egress, 1,
                                 (const struct sockaddr *)destination,
                                 sizeof(*destination), &vec, 1, 0));
  /* Queuing must copy the caller's storage. The stub checks original bytes
   * when the queued payload eventually reaches the socket boundary. */
  memset(bytes, 0, sizeof(bytes));
}

static void test_queue_pressure(bool byte_pressure) {
  transport_egress_t egress;
  const size_t capacity = 128;
  const size_t size = byte_pressure ? 64 : 32;
  const size_t accepted = byte_pressure ? 64 : capacity;
  const size_t byte_limit = byte_pressure ? 4096 : 8192;
  struct sockaddr_in destination = {.sin_family = AF_INET,
                                    .sin_port = htons(2)};
  assert(transport_egress_init(&egress, capacity, byte_limit));
  failure = EAGAIN;
  inspect_payloads = false;
  for (size_t i = 0; i < accepted; ++i)
    submit_sequence(&egress, &destination, i, size);
  assert(egress.count == accepted && egress.bytes == accepted * size);
  uint8_t extra[64] = {0};
  struct iovec vec = {.iov_base = extra, .iov_len = size};
  assert(!transport_egress_submit(&egress, 1, (struct sockaddr *)&destination,
                                  sizeof(destination), &vec, 1, 0));
  assert(egress.packets_dropped == 1 && egress.count == accepted &&
         egress.bytes == accepted * size && egress.peak_count == accepted &&
         egress.peak_bytes == accepted * size);
  uint8_t *originals[128];
  for (size_t i = 0; i < accepted; ++i)
    originals[i] = egress.packets[i].data;
  for (size_t retry = 0; retry < 32; ++retry) {
    assert(transport_egress_flush(&egress, 1));
    assert(egress.count == accepted && egress.bytes == accepted * size);
    for (size_t i = 0; i < accepted; ++i)
      assert(egress.packets[i].data == originals[i]);
  }
  failure = 0;
  inspect_payloads = true;
  expected_size = size;
  next_sequence = 0;
  send_allowance = 3;
  assert(transport_egress_flush(&egress, 1));
  assert(next_sequence == 3 && egress.count == accepted - 3 &&
         egress.bytes == (accepted - 3) * size && egress.head == 3);
  for (size_t i = accepted; i < accepted + 3; ++i)
    submit_sequence(&egress, &destination, i, size);
  assert(egress.count == accepted && egress.bytes == accepted * size);
  send_allowance = SIZE_MAX;
  while (egress.count)
    assert(transport_egress_flush(&egress, 1));
  assert(next_sequence == accepted + 3 && !egress.bytes &&
         egress.packets_sent == accepted + 3 && egress.packets_dropped == 1 &&
         egress.peak_count == accepted && egress.peak_bytes == accepted * size);
  for (size_t i = 0; i < egress.capacity; ++i)
    assert(!egress.packets[i].data);
  /* Refill at the wrapped head, then abandon every retained payload. */
  failure = EAGAIN;
  inspect_payloads = false;
  for (size_t i = 0; i < accepted; ++i)
    submit_sequence(&egress, &destination, i, size);
  printf("egress pressure: limit=%s entries=%zu payload_bytes=%zu "
         "array_bytes=%zu blocked_retries=32 exact_sent=%zu\n",
         byte_pressure ? "bytes" : "count", egress.peak_count,
         egress.peak_bytes, egress.capacity * sizeof(*egress.packets),
         next_sequence);
  transport_egress_destroy(&egress);
  assert(!egress.packets && !egress.count && !egress.bytes && !egress.capacity);
}

static void policy_step(size_t count, size_t limit, size_t sequence,
                        ssize_t result, int error) {
  assert(policy_step_count < sizeof(policy_steps) / sizeof(policy_steps[0]));
  size_t step = policy_step_count++;
  policy_steps[step].count = count;
  policy_steps[step].limit = limit;
  policy_steps[step].sequence = sequence;
  policy_steps[step].result = result;
  policy_steps[step].error = error;
}

static void submit_policy_batch(transport_egress_t *egress,
                                const struct sockaddr_in *destination,
                                size_t sequence, size_t limit) {
  uint8_t bytes[4][32];
  struct iovec datagrams[4];
  for (size_t i = 0; i < 4; i++) {
    for (size_t j = 0; j < sizeof(bytes[i]); j++)
      bytes[i][j] = (uint8_t)(sequence + i + j * 13);
    datagrams[i] = (struct iovec){bytes[i], sizeof(bytes[i])};
  }
  assert(transport_egress_submit(egress, 1,
                                 (const struct sockaddr *)destination,
                                 sizeof(*destination), datagrams, 4, limit));
  memset(bytes, 0, sizeof(bytes));
}

static void test_retained_grouping_policy(void) {
  transport_egress_t egress;
  struct sockaddr_in destination = {.sin_family = AF_INET,
                                    .sin_port = htons(2)};
  assert(transport_egress_init(&egress, 12, 12 * 32));
  failure = EAGAIN;
  inspect_payloads = inspect_policy = false;
  for (size_t sequence = 0; sequence < 5; sequence++)
    submit_sequence(&egress, &destination, sequence, 32);
  failure = 0;
  inspect_policy = true;
  policy_step_count = policy_next_step = 0;
  policy_step(5, 0, 0, 5, 0);
  assert(transport_egress_flush(&egress, 1));
  assert(egress.head == 5 && egress.count == 0);

  /* Partial ordinary fallback need not end on a six-packet boundary. The two
   * retained packets keep their limit; later 0/6 policies wrap around the ring
   * and must not merge despite sharing exactly the same destination. */
  policy_step(4, 6, 5, 2, 0);
  submit_policy_batch(&egress, &destination, 5, 6);
  submit_policy_batch(&egress, &destination, 9, 0);
  submit_policy_batch(&egress, &destination, 13, 6);
  assert(policy_next_step == 2 && egress.head == 5 && egress.count == 10 &&
         egress.bytes == 320 && egress.packets_sent == 7);
  assert(egress.packets[11].max_gso_segments == 6 &&
         egress.packets[0].max_gso_segments == 6);

  uint8_t byte = 1;
  struct iovec invalid = {&byte, 1};
  const size_t invalid_limits[] = {65, 256, SIZE_MAX};
  size_t prior_calls = calls;
  for (size_t i = 0; i < sizeof(invalid_limits) / sizeof(invalid_limits[0]);
       i++)
    assert(!transport_egress_submit(
        &egress, 1, (const struct sockaddr *)&destination, sizeof(destination),
        &invalid, 1, invalid_limits[i]));
  assert(calls == prior_calls && egress.count == 10 && egress.bytes == 320 &&
         egress.packets_dropped == 0 && egress.send_errors == 0);

  policy_step(2, 6, 7, 1, 0);
  assert(transport_egress_flush(&egress, 1));
  assert(egress.head == 6 && egress.count == 9 && egress.bytes == 288);
  uint8_t *retained = egress.packets[egress.head].data;
  policy_step(1, 6, 8, 0, 0);
  assert(transport_egress_flush(&egress, 1));
  assert(egress.packets[egress.head].data == retained && egress.count == 9 &&
         egress.packets[egress.head].max_gso_segments == 6);
  policy_step(1, 6, 8, -1, EIO);
  policy_step(4, 0, 9, 2, 0);
  assert(!transport_egress_flush(&egress, 1));
  assert(egress.count == 6 && egress.bytes == 192 && egress.head == 9 &&
         egress.packets_dropped == 1 && egress.send_errors == 1);
  policy_step(2, 0, 11, 2, 0);
  policy_step(4, 6, 13, 4, 0);
  assert(transport_egress_flush(&egress, 1));
  assert(policy_next_step == policy_step_count && egress.count == 0 &&
         egress.bytes == 0 && egress.head == 3 && egress.packets_sent == 16 &&
         egress.bytes_sent == 16 * 32 && egress.packets_queued == 15 &&
         egress.bytes_queued == 15 * 32 && egress.peak_count == 10 &&
         egress.peak_bytes == 320);
  for (size_t i = 0; i < egress.capacity; i++)
    assert(!egress.packets[i].data && !egress.packets[i].max_gso_segments);
  prior_calls = calls;
  assert(!transport_egress_submit(&egress, 1,
                                  (const struct sockaddr *)&destination,
                                  sizeof(destination), NULL, 0, 256));
  assert(calls == prior_calls && egress.count == 0 && egress.send_errors == 1);
  inspect_policy = false;
  transport_egress_destroy(&egress);
}

int main(void) {
  test_queue_pressure(false);
  test_queue_pressure(true);
  test_retained_grouping_policy();
  transport_egress_t egress;
  assert(transport_egress_init(&egress, 128, 4096));
  struct sockaddr_in bad = {.sin_family = AF_INET, .sin_port = htons(1)};
  struct sockaddr_in good = {.sin_family = AF_INET, .sin_port = htons(2)};
  char bytes[] = "packet";
  struct iovec vec = {.iov_base = bytes, .iov_len = sizeof(bytes)};
  failure = EAGAIN;
  assert(transport_egress_submit(&egress, 1, (struct sockaddr *)&bad,
                                 sizeof(bad), &vec, 1, 0));
  assert(transport_egress_submit(&egress, 1, (struct sockaddr *)&good,
                                 sizeof(good), &vec, 1, 0));
  assert(egress.count == 2);
  assert(transport_egress_flush(&egress, 1));
  assert(egress.count == 2 && egress.packets_dropped == 0 &&
         egress.send_errors == 0 && egress.would_block == 2);
  failure = ENETUNREACH;
  assert(!transport_egress_flush(&egress, 1));
  assert(egress.count == 0 && egress.bytes == 0);
  assert(egress.packets_dropped == 1 && egress.packets_sent == 1);
  assert(egress.send_errors == 1 && egress.bytes_sent == sizeof(bytes));
  failure = EAGAIN;
  for (size_t i = 0; i < 100; i++)
    assert(transport_egress_submit(&egress, 1, (struct sockaddr *)&bad,
                                   sizeof(bad), &vec, 1, 0));
  failure = ENETUNREACH;
  calls = 0;
  assert(!transport_egress_flush(&egress, 1));
  assert(calls == 64 && egress.count == 36);
  assert(!transport_egress_flush(&egress, 1));
  assert(egress.count == 0 && egress.packets_dropped == 101);
  transport_egress_destroy(&egress);
  puts("===EGRESS ERRORS OK===");
  return 0;
}
