/* privileged isolated kernel capability regression */
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
static size_t payload_bytes = 512U * 1024U;
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
  unsigned char *data = malloc(PAYLOAD);
  assert(data);
  for (unsigned i = 0; i < PAYLOAD; i++)
    data[i] = (unsigned char)i;
  size_t sent = 0;
  while (sent < PAYLOAD) {
    ssize_t n = send(fd, data + sent, PAYLOAD - sent, MSG_NOSIGNAL);
    assert(n > 0);
    sent += (size_t)n;
  }
  free(data);
  close(fd);
  return NULL;
}
int main(int argc, char **argv) {
  struct stat self, initial;
  assert(!stat("/proc/self/ns/net", &self) &&
         !stat("/proc/1/ns/net", &initial));
  if (self.st_dev == initial.st_dev && self.st_ino == initial.st_ino) {
    fputs("Run this test with unshare --net\n", stderr);
    return 64;
  }
  assert(argc == 3 || argc == 4);
  version = atoi(argv[1]);
  assert(version == 4 || version == 6);
  family = version == 4 ? AF_INET : AF_INET6;
  bool requested = !strcmp(argv[2], "on");
  assert(requested || !strcmp(argv[2], "off"));
  if (argc == 4) {
    payload_bytes = strtoul(argv[3], NULL, 10);
    assert(payload_bytes >= 512U * 1024U &&
           payload_bytes <= 64U * 1024U * 1024U);
  }
  struct rlimit limit = {0, 0};
  assert(!setrlimit(RLIMIT_CORE, &limit));
  alarm(15);
  local_text = version == 4 ? "10.91.0.1" : "fd91::1";
  remote_text = version == 4 ? "10.91.0.2" : "fd91::2";
  assert(inet_pton(family, local_text, local) == 1 &&
         inet_pton(family, remote_text, remote) == 1);
  char device[16] = "qgsotx0";
  int fd = requested ? tun_alloc_tx_offload(device, &offload_active)
                     : tun_alloc(device);
  assert(fd >= 0 && offload_active == requested);
  assert(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0);
  char *lo[] = {"ip", "link", "set", "lo", "up", NULL};
  ip(lo);
  char *v4[] = {"ip", "address", "add", "10.91.0.1/30", "dev", device, NULL};
  char *v6[] = {"ip",  "-6",   "address", "add", "fd91::1/64",
                "dev", device, "nodad",   NULL};
  ip(version == 4 ? v4 : v6);
  char *up[] = {"ip", "link", "set", device, "mtu", "1400", "up", NULL};
  ip(up);
  tunnel_transmitter_t tx = {.vnet = offload_active, .offload = offload_active};
  uint8_t frame[TUN_TX_FRAME_CAPACITY + 1];
  packet_t ordinary;
  tun_packet_config_t config = {.mtu = 1400, .max_packet_size = 2048};
  tun_packet_output_t output;
  struct rusage before, after;
  assert(!getrusage(RUSAGE_SELF, &before));
  uint64_t started = now();
  size_t normalized = 0, copied = 0;
  pthread_t thread;
  assert(!pthread_create(&thread, NULL, client, NULL));
  size_t received = 0;
  unsigned long expected = 0;
  bool connected = false;
  uint64_t deadline = now() + 10000;
  while (received < PAYLOAD) {
    ssize_t n =
        read_transmit(&tx, fd, frame, &ordinary, &output, &config, now());
    unsigned char *packet = ordinary.bytes;
    if (n < 0) {
      if (errno != EAGAIN && errno != EINTR) {
        perror("read_transmit");
        return 2;
      }
      assert(now() < deadline);
      struct pollfd p = {fd, POLLIN, 0};
      assert(poll(&p, 1, 10) >= 0);
      continue;
    }
    assert(n > 0 && n <= 1400);
    normalized++;
    if (offload_active)
      copied += (size_t)n;
    size_t iplen;
    if (version == 4) {
      if (n < 40 || packet[0] >> 4 != 4 || packet[9] != 6)
        continue;
      iplen = (packet[0] & 15) * 4;
      assert(word(packet + 2) == (unsigned)n &&
             fold(sum(packet, iplen)) == 65535);
      assert(!memcmp(packet + 12, local, 4) && !memcmp(packet + 16, remote, 4));
    } else {
      if (n < 60 || packet[0] >> 4 != 6 || packet[6] != 6)
        continue;
      iplen = 40;
      assert(word(packet + 4) + 40 == (unsigned)n);
      assert(!memcmp(packet + 8, local, 16) &&
             !memcmp(packet + 24, remote, 16));
    }
    unsigned char *tcp = packet + iplen;
    size_t tcp_size = (size_t)n - iplen, header = (tcp[12] >> 4) * 4;
    assert(header >= 20 && header <= tcp_size && word(tcp) == 30100 &&
           word(tcp + 2) == 30101);
    assert(fold(pseudo(tcp_size) + sum(tcp, tcp_size)) == 65535);
    if (tcp[13] & 2) {
      assert(!connected);
      expected = (number(tcp + 4) + 1) & 0xffffffffUL;
      reply(fd, 777, expected, 0x12, true);
      connected = true;
      continue;
    }
    size_t data = tcp_size - header;
    if (!data)
      continue;
    assert(connected && number(tcp + 4) == expected &&
           received + data <= PAYLOAD);
    for (size_t i = 0; i < data; i++)
      assert(tcp[header + i] == (unsigned char)(received + i));
    received += data;
    expected = (expected + data) & 0xffffffffUL;
    reply(fd, 778, expected, 0x10, false);
  }
  assert(!pthread_join(thread, NULL));
  uint64_t elapsed = now() - started;
  assert(!getrusage(RUSAGE_SELF, &after));
  assert(!tx.dropped && !tun_segment_remaining(&tx.plan));
  if (offload_active)
    assert(tx.gso_reads > 0 && tx.gso_packets > tx.gso_reads);
  else
    assert(tx.gso_reads == 0 && tx.gso_packets == 0);
  double user = after.ru_utime.tv_sec - before.ru_utime.tv_sec +
                (after.ru_utime.tv_usec - before.ru_utime.tv_usec) / 1e6;
  double system = after.ru_stime.tv_sec - before.ru_stime.tv_sec +
                  (after.ru_stime.tv_usec - before.ru_stime.tv_usec) / 1e6;
  printf(
      "{\"passed\":true,\"ip_version\":%d,\"offload\":%s,\"application_bytes\":"
      "%zu,"
      "\"read_calls\":%llu,\"tun_frames\":%llu,\"gso_reads\":%llu,\"gso_"
      "packets\":%llu,"
      "\"normalized_packets\":%zu,\"normalization_copy_bytes\":%zu,\"checksum_"
      "packets\":%llu,"
      "\"user_seconds\":%.6f,\"system_seconds\":%.6f,\"wall_ms\":%llu,"
      "\"scope\":\"Kernel TUN TX, exact TCP payload, normalized MTU/checksums; "
      "local diagnostic, not physical throughput qualification.\"}\n",
      version, offload_active ? "true" : "false", received,
      (unsigned long long)tx.read_calls, (unsigned long long)tx.frames,
      (unsigned long long)tx.gso_reads, (unsigned long long)tx.gso_packets,
      normalized, copied, (unsigned long long)tx.checksums, user, system,
      (unsigned long long)elapsed);
  close(fd);
  return 0;
}
