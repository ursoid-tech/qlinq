/* isolated real-kernel RX integrity and latency diagnostic */
#include "../../src/host/linux/tun_direct.c"
#include <arpa/inet.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include "tun_tcp_fixture.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#define PAYLOAD payload_bytes
static size_t payload_bytes = 4U * 1024U * 1024U;
static size_t record_size = 1300, records;
static _Atomic size_t delivered;
static pthread_mutex_t delivery_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t delivery_ready = PTHREAD_COND_INITIALIZER;
static _Atomic uint64_t *submitted;
static uint64_t *latencies;
static uint64_t nanos(void) {
  struct timespec t;
  assert(!clock_gettime(CLOCK_MONOTONIC, &t));
  return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static int compare_latency(const void *a, const void *b) {
  uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return (x > y) - (x < y);
}
static bool offload_active;
static int family, version;
static unsigned char local[16], remote[16];
static const char *local_text, *remote_text;
static unsigned word(const unsigned char *p) {
  return (unsigned)p[0] * 256 + p[1];
}
static unsigned long number(const unsigned char *p) {
  return (unsigned long)word(p) * 65536 + word(p + 2);
}
static void put16(unsigned char *p, unsigned n) {
  p[0] = n >> 8;
  p[1] = n;
}
static void put32(unsigned char *p, unsigned long n) {
  put16(p, n >> 16);
  put16(p + 2, n);
}
static unsigned sum(const unsigned char *p, size_t n) {
  unsigned s = 0;
  for (size_t i = 0; i < n; i++)
    s += (unsigned)p[i] << (i & 1 ? 0 : 8);
  return s;
}
static unsigned fold(unsigned s) {
  while (s >> 16)
    s = (s & 65535) + (s >> 16);
  return s;
}
static unsigned pseudo(size_t n) {
  return sum(local, version == 4 ? 4 : 16) +
         sum(remote, version == 4 ? 4 : 16) + 6 + (unsigned)n;
}
static uint64_t now(void) {
  struct timespec t;
  assert(!clock_gettime(CLOCK_MONOTONIC, &t));
  return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void ip(char *const argv[]) {
  pid_t p = fork();
  assert(p >= 0);
  if (!p) {
    execvp("ip", argv);
    _exit(127);
  }
  int s;
  assert(waitpid(p, &s, 0) == p && WIFEXITED(s) && WEXITSTATUS(s) == 0);
}
static void reply(int fd, unsigned long seq, unsigned long ack, unsigned flags,
                  bool syn) {
  unsigned char packet[64] = {0}, vnet[10] = {0};
  size_t iplen = version == 4 ? 20 : 40, tcp = syn ? 24 : 20;
  if (version == 4) {
    packet[0] = 0x45;
    put16(packet + 2, iplen + tcp);
    put16(packet + 6, 0x4000);
    packet[8] = 64;
    packet[9] = 6;
    memcpy(packet + 12, remote, 4);
    memcpy(packet + 16, local, 4);
    put16(packet + 10, ~fold(sum(packet, 20)));
  } else {
    packet[0] = 0x60;
    put16(packet + 4, tcp);
    packet[6] = 6;
    packet[7] = 64;
    memcpy(packet + 8, remote, 16);
    memcpy(packet + 24, local, 16);
  }
  unsigned char *t = packet + iplen;
  put16(t, 30101);
  put16(t + 2, 30100);
  put32(t + 4, seq);
  put32(t + 8, ack);
  t[12] = (tcp / 4) << 4;
  t[13] = flags;
  put16(t + 14, 65535);
  if (syn) {
    t[20] = 2;
    t[21] = 4;
    put16(t + 22, 1360);
  }
  put16(t + 16, ~fold(pseudo(tcp) + sum(t, tcp)));
  (void)vnet;
  assert((offload_active
              ? tun_write_vnet(fd, packet, iplen + tcp)
              : tun_write(fd, packet, iplen + tcp)) == (ssize_t)(iplen + tcp));
}
static void *client(void *unused) {
  (void)unused;
  int fd = socket(family, SOCK_STREAM, 0);
  assert(fd >= 0);
  struct timeval timeout = {3, 0};
  assert(!setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)));
  if (version == 4) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(30100)},
                       b = {.sin_family = AF_INET, .sin_port = htons(30101)};
    memcpy(&a.sin_addr, local, 4);
    memcpy(&b.sin_addr, remote, 4);
    assert(!bind(fd, (void *)&a, sizeof(a)));
    assert(!connect(fd, (void *)&b, sizeof(b)));
  } else {
    struct sockaddr_in6 a = {.sin6_family = AF_INET6,
                             .sin6_port = htons(30100)},
                        b = {.sin6_family = AF_INET6,
                             .sin6_port = htons(30101)};
    memcpy(&a.sin6_addr, local, 16);
    memcpy(&b.sin6_addr, remote, 16);
    assert(!bind(fd, (void *)&a, sizeof(a)));
    assert(!connect(fd, (void *)&b, sizeof(b)));
  }
  unsigned char data[1400];
  for (size_t i = 0; i < records; i++) {
    size_t got = 0;
    while (got < record_size) {
      ssize_t n = recv(fd, data + got, record_size - got, 0);
      assert(n > 0);
      got += n;
    }
    for (size_t j = 0; j < record_size; j++)
      assert(data[j] == (uint8_t)(778 + i * record_size + j));
    latencies[i] =
        nanos() - atomic_load_explicit(&submitted[i], memory_order_acquire);
    atomic_store_explicit(&delivered, i + 1, memory_order_release);
    if ((i + 1) % 32 == 0 || i + 1 == records) {
      assert(!pthread_mutex_lock(&delivery_lock));
      assert(!pthread_cond_signal(&delivery_ready));
      assert(!pthread_mutex_unlock(&delivery_lock));
    }
  }
  close(fd);
  return NULL;
}
int main(int argc, char **argv) {
  struct stat self, initial;
  assert(!stat("/proc/self/ns/net", &self) &&
         !stat("/proc/1/ns/net", &initial));
  assert(self.st_ino != initial.st_ino || self.st_dev != initial.st_dev);
  assert(argc == 3 || argc == 4);
  version = atoi(argv[1]);
  assert(version == 4 || version == 6);
  family = version == 4 ? AF_INET : AF_INET6;
  bool enabled = !strcmp(argv[2], "on");
  assert(enabled || !strcmp(argv[2], "off"));
  if (argc == 4)
    record_size = strtoul(argv[3], NULL, 10);
  assert(record_size >= 64 && record_size <= 1300);
  records = payload_bytes / record_size;
  payload_bytes = records * record_size;
  submitted = calloc(records, sizeof(*submitted));
  latencies = calloc(records, sizeof(*latencies));
  assert(submitted && latencies);
  struct rlimit limit = {0, 0};
  assert(!setrlimit(RLIMIT_CORE, &limit));
  alarm(20);
  local_text = version == 4 ? "10.91.0.1" : "fd91::1";
  remote_text = version == 4 ? "10.91.0.2" : "fd91::2";
  assert(inet_pton(family, local_text, local) == 1 &&
         inet_pton(family, remote_text, remote) == 1);
  char device[16] = "qgrorx0";
  int fd = enabled ? tun_alloc_vnet(device, false, &offload_active)
                   : tun_alloc(device);
  assert(fd >= 0 && offload_active == enabled);
  assert(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0);
  char *lo[] = {"ip", "link", "set", "lo", "up", NULL};
  ip(lo);
  char *v4[] = {"ip", "addr", "add", "10.91.0.1/30", "dev", device, NULL};
  char *v6[] = {"ip",  "-6",   "addr",  "add", "fd91::1/64",
                "dev", device, "nodad", NULL};
  ip(version == 4 ? v4 : v6);
  char *up[] = {"ip", "link", "set", device, "mtu", "1400", "up", NULL};
  ip(up);
  pthread_t thread;
  assert(!pthread_create(&thread, NULL, client, NULL));
  uint8_t frame[2048];
  tun_offload_t metadata;
  uint64_t deadline = now() + 5000;
  bool connected = false;
  uint32_t ack = 0;
  while (!connected) {
    ssize_t n = enabled ? tun_read_vnet(fd, frame, sizeof(frame), &metadata)
                        : tun_read(fd, frame, sizeof(frame));
    if (n < 0) {
      assert(errno == EAGAIN || errno == EINTR);
      assert(now() < deadline);
      struct pollfd p = {fd, POLLIN, 0};
      assert(poll(&p, 1, 10) >= 0);
      continue;
    }
    size_t iplen = version == 4 ? 20 : 40;
    if (n < (ssize_t)(iplen + 20) || (version == 6 && frame[6] != 6) ||
        (version == 4 && frame[9] != 6))
      continue;
    uint8_t *tcp = frame + iplen;
    if (tcp[13] & 2) {
      ack = (uint32_t)number(tcp + 4) + 1;
      reply(fd, 777, ack, 0x12, true);
    } else if ((tcp[13] & 0x10) && number(tcp + 8) == 778)
      connected = true;
  }
  tun_rx_batch_t queue;
  tun_rx_limits_t limits = {64, 64 * 1400, 100, 1};
  assert(tun_rx_batch_init(&queue, &limits));
  tunnel_receiver_t rx = {.queue = &queue,
                          .fd = fd,
                          .mtu = 1400,
                          .vnet = enabled,
                          .coalesce = enabled};
  struct rusage before, after;
  assert(!getrusage(RUSAGE_SELF, &before));
  uint64_t start = nanos();
  size_t sent = 0;
  while (sent < records) {
    size_t end = sent + 32;
    if (end > records)
      end = records;
    begin_receive_batch(&rx);
    for (size_t i = sent; i < end; i++) {
      size_t n = fixture_packet(
          frame, version, record_size, 778 + i * record_size, i & 65535,
          i + 1 == records ? 0x19 : (i + 1 == end ? 0x18 : 0x10), false);
      size_t iplen = version == 4 ? 20 : 40;
      memcpy(frame + (version == 4 ? 12 : 8), remote, version == 4 ? 4 : 16);
      memcpy(frame + (version == 4 ? 16 : 24), local, version == 4 ? 4 : 16);
      fixture_num(frame + iplen + 8, ack);
      fixture_checksum(frame, n);
      atomic_store_explicit(&submitted[i], nanos(), memory_order_release);
      qlinq_event_t event = {.record = {.data = frame, .size = n}};
      assert(receive_packet(&rx, &event));
      memset(frame, 0xcc, n); /* no retained borrowed callback storage */
    }
    assert(end_receive_batch(&rx, now()));
    assert(!queue.dropped && !rx.failed);
    while (atomic_load_explicit(&delivered, memory_order_acquire) < end ||
           queue.count) {
      assert(now() < deadline);
      struct pollfd p = {fd, POLLIN | (queue.count ? POLLOUT : 0), 0};
      if (queue.count)
        assert(poll(&p, 1, 1) >= 0);
      else {
        assert(!pthread_mutex_lock(&delivery_lock));
        while (atomic_load_explicit(&delivered, memory_order_acquire) < end) {
          struct timespec until;
          assert(!clock_gettime(CLOCK_REALTIME, &until));
          until.tv_sec++;
          assert(
              !pthread_cond_timedwait(&delivery_ready, &delivery_lock, &until));
        }
        assert(!pthread_mutex_unlock(&delivery_lock));
      }
      if (queue.count) {
        begin_receive_batch(&rx);
        assert(flush_packets(&rx, now()));
        assert(end_receive_batch(&rx, now()));
      }
      /* drain real ACKs and potential IPv6 control traffic */
      while ((enabled ? tun_read_vnet(fd, frame, sizeof(frame), &metadata)
                      : tun_read(fd, frame, sizeof(frame))) > 0) {
      }
    }
    sent = end;
  }
  assert(!pthread_join(thread, NULL));
  uint64_t elapsed = nanos() - start;
  assert(!getrusage(RUSAGE_SELF, &after));
  qsort(latencies, records, sizeof(*latencies), compare_latency);
  uint64_t p99 = latencies[(records * 99) / 100];
  /* chosen local acceptance budget: 5 ms callback-to-application p99 */
  assert(p99 < 5000000ULL);
  assert(rx.written_packets == records && !queue.count && !queue.dropped);
  if (enabled)
    assert(rx.aggregates && rx.write_calls * 4 < records);
  else
    assert(rx.write_calls == records);
  double user = after.ru_utime.tv_sec - before.ru_utime.tv_sec +
                (after.ru_utime.tv_usec - before.ru_utime.tv_usec) / 1e6;
  double system = after.ru_stime.tv_sec - before.ru_stime.tv_sec +
                  (after.ru_stime.tv_usec - before.ru_stime.tv_usec) / 1e6;
  printf(
      "{\"passed\":true,\"version\":%d,\"enabled\":%s,\"bytes\":%zu,"
      "\"packets\":%zu,"
      "\"write_calls\":%llu,\"aggregates\":%llu,\"aggregate_copy_bytes\":%llu,"
      "\"arena_copy_bytes\":%zu,\"wall_ns\":%llu,\"p99_ns\":%llu,\"user_s\":%."
      "6f,\"system_s\":%.6f}\n",
      version, enabled ? "true" : "false", payload_bytes, records,
      (unsigned long long)rx.write_calls, (unsigned long long)rx.aggregates,
      (unsigned long long)rx.copied_bytes,
      enabled ? payload_bytes + records * (version == 4 ? 40 : 60) : 0,
      (unsigned long long)elapsed, (unsigned long long)p99, user, system);
  close(fd);
  free(submitted);
  free(latencies);
  return 0;
}
