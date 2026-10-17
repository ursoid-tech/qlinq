/* Linux UDP baseline for multipath_transit_demo. It deliberately bypasses qlinq
 * to calibrate the routed fixture and packet generator independently. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define PATHS 4
#define BATCH 64
#define PACKET_MAX 1400
#define SEEN (1U << 18)
#define MAGIC UINT64_C(0x716c696e71756470)

static uint64_t now_ns(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec * 1000000000U + t.tv_nsec;
}
static double number(const char *s, double lo, double hi) {
  char *end;
  errno = 0;
  double n = strtod(s, &end);
  if (errno || *end || end == s || !isfinite(n) || n < lo || n > hi)
    exit(2);
  return n;
}
static struct sockaddr_in address(const char *ip) {
  struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(19871)};
  if (inet_pton(AF_INET, ip, &a.sin_addr) != 1)
    exit(2);
  return a;
}
static void report(const char *event, const char *role, uint64_t start,
                   uint64_t offered, uint64_t sent, uint64_t received,
                   size_t bytes, uint64_t duplicates, uint64_t corrupt,
                   uint64_t stale) {
  struct rusage u;
  getrusage(RUSAGE_SELF, &u);
  double elapsed = (now_ns() - start) / 1e9;
  double cpu = u.ru_utime.tv_sec + u.ru_utime.tv_usec / 1e6 +
               u.ru_stime.tv_sec + u.ru_stime.tv_usec / 1e6;
  printf("{\"event\":\"%s\",\"role\":\"%s\",\"time\":%.6f,"
         "\"offered\":%" PRIu64 ",\"admitted\":%" PRIu64 ","
         "\"backpressured\":%" PRIu64 ",\"received\":%" PRIu64 ","
         "\"received_bytes\":%" PRIu64 ",\"duplicates\":%" PRIu64 ","
         "\"corrupt\":%" PRIu64 ",\"outside_reorder_window\":%" PRIu64 ","
         "\"cpu_seconds\":%.6f,\"max_rss_kib\":%ld}\n",
         event, role, elapsed, offered, sent, offered - sent, received,
         received * bytes, duplicates, corrupt, stale, cpu, u.ru_maxrss);
}
int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  const char *role = NULL, *start_file = NULL, *binds[PATHS], *remotes[PATHS];
  size_t paths = 0, remote_count = 0, bytes = 1250;
  double seconds = 20, drain = 5, mbps = 4000;
  for (int i = 1; i < argc; i++) {
    if (i + 1 == argc)
      return 2;
    const char *key = argv[i], *value = argv[++i];
    if (!strcmp(key, "--role"))
      role = value;
    else if (!strcmp(key, "--start-file"))
      start_file = value;
    else if (!strcmp(key, "--seconds"))
      seconds = number(value, 1, 3600);
    else if (!strcmp(key, "--drain"))
      drain = number(value, .1, 60);
    else if (!strcmp(key, "--mbps"))
      mbps = number(value, .001, 100000);
    else if (!strcmp(key, "--record-bytes")) {
      double n = number(value, 32, PACKET_MAX);
      if (n != floor(n))
        return 2;
      bytes = n;
    } else if (!strcmp(key, "--bind") && paths < PATHS)
      binds[paths++] = value;
    else if (!strcmp(key, "--remote") && remote_count < PATHS)
      remotes[remote_count++] = value;
    else if (strcmp(key, "--mode") && strcmp(key, "--receive-objects"))
      return 2;
  }
  if (!role || !start_file || !paths ||
      (strcmp(role, "send") && strcmp(role, "receive")))
    return 2;
  bool sending = !strcmp(role, "send");
  if (!sending && remote_count != paths)
    return 2;
  int fds[PATHS];
  bool ready[PATHS] = {false};
  struct pollfd polls[PATHS];
  for (size_t i = 0; i < paths; i++) {
    fds[i] = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in local = address(binds[i]);
    int buffer = 2 * 1024 * 1024;
    if (fds[i] < 0 || bind(fds[i], (void *)&local, sizeof(local)))
      return 1;
    if (setsockopt(fds[i], SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer)) ||
        setsockopt(fds[i], SOL_SOCKET, SO_SNDBUF, &buffer, sizeof(buffer)))
      return 1;
    polls[i] = (struct pollfd){.fd = fds[i], .events = POLLIN};
  }
  uint64_t opened = now_ns(), start = 0, hello_at = 0;
  bool announced = false;
  while (!start) {
    uint64_t now = now_ns();
    if (now - opened > UINT64_C(30000000000))
      return 1;
    for (size_t i = 0; i < paths; i++) {
      if (!sending && now >= hello_at) {
        struct sockaddr_in remote = address(remotes[i]);
        (void)sendto(fds[i], "QLINQ-UDP-HELLO", 15, 0, (void *)&remote,
                     sizeof(remote));
      }
      char hello[64];
      struct sockaddr_in remote;
      socklen_t len = sizeof(remote);
      ssize_t n =
          recvfrom(fds[i], hello, sizeof(hello), 0, (void *)&remote, &len);
      if (n == 15 && !memcmp(hello, "QLINQ-UDP-HELLO", 15)) {
        if (sending) {
          if (connect(fds[i], (void *)&remote, len))
            return 1;
          (void)send(fds[i], hello, 15, 0);
        }
        ready[i] = true;
      }
    }
    if (now >= hello_at)
      hello_at = now + 100000000U;
    bool all = true;
    for (size_t i = 0; i < paths; i++)
      all &= ready[i];
    if (all && !announced) {
      printf("{\"event\":\"ready\",\"role\":\"%s\",\"paths\":%zu}\n", role,
             paths);
      announced = true;
    }
    if (announced) {
      FILE *f = fopen(start_file, "r");
      if (f) {
        if (fscanf(f, "%" SCNu64, &start) != 1 || start <= now)
          return 1;
        fclose(f);
      }
    }
    if (!start)
      poll(polls, paths, 10);
  }
  uint8_t payload[BATCH][PACKET_MAX], expected[PACKET_MAX];
  memset(expected, 0xa5, sizeof(expected));
  struct iovec iov[BATCH];
  struct mmsghdr messages[BATCH];
  memset(payload, 0xa5, sizeof(payload));
  memset(messages, 0, sizeof(messages));
  for (size_t i = 0; i < BATCH; i++) {
    iov[i] = (struct iovec){.iov_base = payload[i], .iov_len = bytes};
    messages[i].msg_hdr.msg_iov = &iov[i];
    messages[i].msg_hdr.msg_iovlen = 1;
  }
  uint64_t *seen = calloc(SEEN, sizeof(*seen));
  if (!seen)
    return 1;
  uint64_t offered = 0, sent = 0, received = 0, duplicates = 0, corrupt = 0,
           stale = 0;
  uint64_t next_report = start + 1000000000U;
  size_t cursor = 0;
  while (now_ns() < start + (uint64_t)((seconds + drain) * 1e9)) {
    uint64_t now = now_ns();
    if (now < start) {
      poll(NULL, 0, 1);
      continue;
    }
    bool work = false;
    if (sending && now < start + (uint64_t)(seconds * 1e9)) {
      uint64_t target = (uint64_t)((now - start) * mbps / (8000.0 * bytes));
      if (target > offered) {
        size_t count = target - offered > BATCH ? BATCH : target - offered;
        for (size_t j = 0; j < count; j++) {
          uint64_t words[2] = {MAGIC, ++offered};
          memcpy(payload[j], words, sizeof(words));
        }
        int n = sendmmsg(fds[cursor++ % paths], messages, count, 0);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
          return 1;
        if (n > 0)
          sent += n;
        work = true;
      }
    } else if (!sending) {
      for (size_t i = 0; i < paths; i++) {
        for (size_t j = 0; j < BATCH; j++)
          messages[j].msg_hdr.msg_flags = 0;
        int n = recvmmsg(fds[(cursor + i) % paths], messages, BATCH,
                         MSG_DONTWAIT, NULL);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
          return 1;
        if (n > 0)
          work = true;
        for (int j = 0; j < n; j++) {
          if (messages[j].msg_len == 15 &&
              !memcmp(payload[j], "QLINQ-UDP-HELLO", 15))
            continue;
          uint64_t words[2];
          memcpy(words, payload[j], sizeof(words));
          uint64_t id = words[1];
          if (messages[j].msg_len != bytes ||
              (messages[j].msg_hdr.msg_flags & MSG_TRUNC) ||
              words[0] != MAGIC || !id ||
              memcmp(payload[j] + 16, expected, bytes - 16))
            corrupt++;
          else if (seen[id % SEEN] == id)
            duplicates++;
          else if (seen[id % SEEN] > id)
            stale++;
          else {
            seen[id % SEEN] = id;
            received++;
          }
        }
      }
      cursor++;
    }
    if (now >= next_report) {
      report("sample", role, start, offered, sent, received, bytes, duplicates,
             corrupt, stale);
      next_report = now + 1000000000U;
    }
    if (!work && (!sending || now >= start + (uint64_t)(seconds * 1e9)))
      poll(sending ? NULL : polls, sending ? 0 : paths, 1);
  }
  report("summary", role, start, offered, sent, received, bytes, duplicates,
         corrupt, stale);
  for (size_t i = 0; i < paths; i++)
    close(fds[i]);
  free(seen);
  return 0;
}
