#include "cli_parse.h"
#include "qlinq.h"
#include "tun_control.h"
#include "tun_device.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <net/if.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#define DEFAULT_TUN_MTU 1400U
#define PACKET_CAPACITY 2048U
#define RECEIVE_QUEUE_CAPACITY 64U

typedef struct {
  uint8_t bytes[PACKET_CAPACITY];
  size_t size;
  uint64_t queued_ms;
} packet_t;

typedef struct {
  bool listen;
  bool mock;
  bool insecure;
  const char *bind;
  const char *interface_name;
  const char *ip;
  const char *track;
  const char *token;
  const char *cert;
  const char *key;
  const char *ca;
  const char *run_as;
  const char *peer_ip;
  const char *binds[QLINQ_MAX_PATHS];
  size_t bind_count;
  const char *uplinks[QLINQ_MAX_PATHS];
  size_t uplink_count;
  const char *routes[16];
  size_t route_count;
  uint64_t mtu;
  uint64_t stats_ms;
  uint64_t queue_ms;
  uint64_t parent_pid;
  char peer[256];
  uint16_t port;
  uint64_t run_ms;
  qlinq_delivery_t delivery;
} options_t;

typedef struct {
  packet_t packets[RECEIVE_QUEUE_CAPACITY];
  size_t head;
  size_t count;
  uint64_t dropped;
} receive_queue_t;

static volatile sig_atomic_t stopping;

static void stop_on_signal(int signal_number) {
  (void)signal_number;
  stopping = 1;
}

static uint64_t monotonic_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    return 0;
  return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static void usage(FILE *out, const char *program) {
  fprintf(
      out,
      "Usage: %s (--listen PORT | --peer HOST[:PORT]) --auth-token TOKEN "
      "[options]\n"
      "  --bind ADDRESS          Local IP (default: 0.0.0.0 or ::)\n"
      "  --interface NAME        TUN name (default: tun0)\n"
      "  --ip CIDR               TUN address (default: 10.8.0.1/24)\n"
      "  --peer-ip ADDRESS       Explicit IPv4 tunnel peer (--ip is a bare "
      "IP)\n"
      "  --mtu N                 Tunnel MTU, 1280..2000 (default: 1400)\n"
      "  --route CIDR            Add a subnet route (repeatable, no default)\n"
      "  --uplink NAME           Allow discovered paths on this interface\n"
      "  --stats-ms N            Emit JSON health snapshots periodically\n"
      "  --queue-ms N            Local queue age limit (default: 100 ms)\n"
      "  --track NAME            Packet stream (default: tund/tun0)\n"
      "  --mode MODE             fixed-fec/fec (default), rateless, reliable, "
      "datagram\n"
      "  --cert FILE --key FILE  TLS identity (required on listener)\n"
      "  --ca FILE               Trust store for verified peers\n"
      "  --insecure-no-verify    Disable certificate verification (tests "
      "only)\n"
      "  --run-as USER           Drop root privileges after TUN setup\n"
      "  --mock                  Generate/receive packets without a TUN\n"
      "  --run-ms N              Stop mock mode after N milliseconds\n",
      program);
}

static bool parse_options(int argc, char **argv, options_t *options) {
  *options = (options_t){.interface_name = "tun0",
                         .ip = "10.8.0.1/24",
                         .track = "tund/tun0",
                         .port = 8888,
                         .mtu = DEFAULT_TUN_MTU,
                         .queue_ms = 100,
                         .delivery = QLINQ_DELIVERY_FIXED_FEC};
  bool have_role = false;
  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];
    if (strcmp(arg, "--help") == 0) {
      usage(stdout, argv[0]);
      exit(0);
    }
    if (strcmp(arg, "--mock") == 0) {
      options->mock = true;
    } else if (strcmp(arg, "--insecure-no-verify") == 0) {
      options->insecure = true;
    } else {
      if (++i >= argc)
        return false;
      const char *value = argv[i];
      if (strcmp(arg, "--listen") == 0) {
        uint64_t port;
        if (have_role || !cli_parse_u64(value, UINT16_MAX, &port) || port == 0)
          return false;
        options->listen = have_role = true;
        options->port = (uint16_t)port;
      } else if (strcmp(arg, "--peer") == 0) {
        if (have_role ||
            !cli_parse_endpoint(value, options->peer, sizeof(options->peer),
                                &options->port, NULL))
          return false;
        have_role = true;
      } else if (strcmp(arg, "--bind") == 0) {
        if (options->bind_count == QLINQ_MAX_PATHS)
          return false;
        options->bind = value;
        options->binds[options->bind_count++] = value;
      } else if (strcmp(arg, "--uplink") == 0) {
        if (options->uplink_count == QLINQ_MAX_PATHS || !value[0] ||
            strlen(value) >= IFNAMSIZ)
          return false;
        options->uplinks[options->uplink_count++] = value;
      } else if (strcmp(arg, "--peer-ip") == 0) {
        options->peer_ip = value;
      } else if (strcmp(arg, "--route") == 0) {
        if (options->route_count == 16)
          return false;
        options->routes[options->route_count++] = value;
      } else if (strcmp(arg, "--mtu") == 0) {
        if (!cli_parse_u64(value, 2000, &options->mtu) || options->mtu < 1280)
          return false;
      } else if (strcmp(arg, "--stats-ms") == 0) {
        if (!cli_parse_u64(value, UINT32_MAX, &options->stats_ms) ||
            options->stats_ms < 50)
          return false;
      } else if (strcmp(arg, "--queue-ms") == 0) {
        if (!cli_parse_u64(value, 60000, &options->queue_ms) ||
            options->queue_ms == 0)
          return false;
      } else if (strcmp(arg, "--parent-pid") == 0) {
        if (!cli_parse_u64(value, INT32_MAX, &options->parent_pid) ||
            options->parent_pid == 0)
          return false;
      } else if (strcmp(arg, "--interface") == 0) {
        options->interface_name = value;
      } else if (strcmp(arg, "--ip") == 0) {
        options->ip = value;
      } else if (strcmp(arg, "--track") == 0) {
        options->track = value;
      } else if (strcmp(arg, "--auth-token") == 0) {
        options->token = value;
      } else if (strcmp(arg, "--cert") == 0) {
        options->cert = value;
      } else if (strcmp(arg, "--key") == 0) {
        options->key = value;
      } else if (strcmp(arg, "--ca") == 0) {
        options->ca = value;
      } else if (strcmp(arg, "--run-as") == 0) {
        options->run_as = value;
      } else if (strcmp(arg, "--run-ms") == 0) {
        if (!cli_parse_u64(value, UINT32_MAX, &options->run_ms) ||
            options->run_ms == 0)
          return false;
      } else if (strcmp(arg, "--mode") == 0) {
        if (!cli_parse_delivery(value, &options->delivery))
          return false;
      } else {
        return false;
      }
    }
  }
  if (!options->token)
    options->token = getenv("QLINQ_AUTH_TOKEN");
  if (options->peer_ip) {
    struct in_addr local, peer;
    if (inet_pton(AF_INET, options->ip, &local) != 1 ||
        inet_pton(AF_INET, options->peer_ip, &peer) != 1 ||
        local.s_addr == peer.s_addr)
      return false;
  }
  for (size_t i = 0; i < options->route_count; i++) {
    char cidr[64];
    if (!options->peer_ip || strlen(options->routes[i]) >= sizeof(cidr))
      return false;
    strcpy(cidr, options->routes[i]);
    char *slash = strchr(cidr, '/');
    uint64_t prefix;
    struct in_addr network, remote;
    if (!slash)
      return false;
    *slash++ = 0;
    if (!cli_parse_u64(slash, 32, &prefix) || prefix == 0 ||
        inet_pton(AF_INET, cidr, &network) != 1)
      return false;
    uint32_t mask = UINT32_MAX << (32U - prefix);
    if ((ntohl(network.s_addr) & ~mask) != 0)
      return false;
    if (!options->listen && inet_pton(AF_INET, options->peer, &remote) == 1 &&
        (ntohl(remote.s_addr) & mask) == ntohl(network.s_addr)) {
      fprintf(stderr, "route would capture the transport peer\n");
      return false;
    }
  }
  return have_role && options->token && options->token[0] &&
         strlen(options->token) <= UINT16_MAX &&
         strlen(options->interface_name) < IFNAMSIZ &&
         strlen(options->track) > 0 &&
         strlen(options->track) < QLINQ_STREAM_NAME_CAPACITY &&
         (options->cert != NULL) == (options->key != NULL) &&
         (!options->listen || options->cert != NULL) &&
         (options->insecure || options->cert != NULL) &&
         (!options->run_ms || options->mock);
}

static bool drop_privileges(const char *name) {
  struct passwd *account = getpwnam(name);
  if (!account) {
    fprintf(stderr, "unknown user: %s\n", name);
    return false;
  }
  if (account->pw_uid == 0) {
    fprintf(stderr, "--run-as must name an unprivileged user\n");
    return false;
  }
  if (setgroups(0, NULL) != 0 || setgid(account->pw_gid) != 0 ||
      setuid(account->pw_uid) != 0) {
    perror("dropping privileges");
    return false;
  }
  return true;
}

static bool set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool valid_packet(const void *data, size_t size) {
  if (!data || size == 0 || size > PACKET_CAPACITY)
    return false;
  const uint8_t *bytes = data;
  const uint8_t version = bytes[0] >> 4;
  if (version == 4 && size >= 20) {
    size_t header_size = (size_t)(bytes[0] & 15U) * 4U;
    size_t total_size = ((size_t)bytes[2] << 8) | bytes[3];
    return header_size >= 20 && header_size <= size && total_size == size;
  }
  if (version == 6 && size >= 40) {
    size_t payload_size = ((size_t)bytes[4] << 8) | bytes[5];
    return payload_size + 40U == size;
  }
  return false;
}

static void enqueue_packet(receive_queue_t *queue, const void *data,
                           size_t size) {
  if (!valid_packet(data, size) || queue->count == RECEIVE_QUEUE_CAPACITY) {
    queue->dropped++;
    return;
  }
  size_t tail = (queue->head + queue->count) % RECEIVE_QUEUE_CAPACITY;
  memcpy(queue->packets[tail].bytes, data, size);
  queue->packets[tail].size = size;
  queue->packets[tail].queued_ms = monotonic_ms();
  queue->count++;
}

static bool flush_packets(receive_queue_t *queue, int tun_fd,
                          uint64_t max_age) {
  while (queue->count > 0) {
    packet_t *packet = &queue->packets[queue->head];
    if (monotonic_ms() - packet->queued_ms >= max_age) {
      queue->head = (queue->head + 1) % RECEIVE_QUEUE_CAPACITY;
      queue->count--;
      queue->dropped++;
      continue;
    }
    ssize_t written = tun_write(tun_fd, packet->bytes, packet->size);
    if (written < 0 && errno == EINTR)
      continue;
    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      return true;
    if (written != (ssize_t)packet->size) {
      if (written < 0)
        perror("writing TUN packet");
      else
        fprintf(stderr, "short TUN packet write\n");
      return false;
    }
    queue->head = (queue->head + 1) % RECEIVE_QUEUE_CAPACITY;
    queue->count--;
  }
  return true;
}

static void make_mock_packet(packet_t *packet, uint64_t sequence) {
  packet->size = 64;
  memset(packet->bytes, 0, packet->size);
  packet->bytes[0] = 0x45;
  packet->bytes[2] = 0;
  packet->bytes[3] = (uint8_t)packet->size;
  packet->bytes[8] = 64;
  packet->bytes[9] = 17;
  memcpy(packet->bytes + 20, &sequence, sizeof(sequence));
}

static void json_string(const char *value) {
  putchar('"');
  for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
    if (*p < 32 || *p == '"' || *p == '\\')
      printf("\\u%04x", *p);
    else
      putchar(*p);
  }
  putchar('"');
}

static void print_stats(qlinq_endpoint_t *endpoint, const char *state,
                        uint64_t sent, uint64_t received, uint64_t tx_bytes,
                        uint64_t rx_bytes, uint64_t dropped) {
  qlinq_endpoint_stats_t stats = {0};
  qlinq_endpoint_get_stats(endpoint, &stats);
  bool have_active_path = false;
  for (size_t i = 0; i < QLINQ_MAX_PATHS; i++) {
    qlinq_path_stats_t path;
    if (qlinq_endpoint_get_path_stats(endpoint, i, &path) && path.active)
      have_active_path = true;
  }
  if (strcmp(state, "connected") == 0 && !have_active_path)
    state = "degraded";
  printf("QLINQ_STATUS {\"state\":\"%s\",\"sent\":%llu,\"received\":%llu,"
         "\"tx_bytes\":%llu,\"rx_bytes\":%llu,\"dropped\":%llu,"
         "\"fec_recovered\":%llu,\"fec_decoded\":%llu,\"fec_lost\":%llu,"
         "\"reconnects\":%llu,"
         "\"queued_bytes\":%zu,\"paths\":[",
         state, (unsigned long long)sent, (unsigned long long)received,
         (unsigned long long)tx_bytes, (unsigned long long)rx_bytes,
         (unsigned long long)dropped,
         (unsigned long long)stats.fec_objects_recovered,
         (unsigned long long)stats.fec_objects_decoded,
         (unsigned long long)stats.fec_objects_lost,
         (unsigned long long)stats.reconnect_attempts, stats.queued_bytes);
  bool first = true;
  for (size_t i = 0; i < QLINQ_MAX_PATHS; i++) {
    qlinq_path_stats_t path;
    if (!qlinq_endpoint_get_path_stats(endpoint, i, &path))
      continue;
    char interface_name[64];
    tun_resolve_interface_name(path.local_address, path.interface_name,
                               interface_name);
    printf("%s{\"interface\":", first ? "" : ",");
    json_string(interface_name);
    printf(",\"address\":");
    json_string(path.local_address);
    printf(",\"active\":%s,\"tx_bytes\":%llu,\"rx_bytes\":%llu,\"rtt_ms\":%u,"
           "\"packets_lost\":%llu}",
           path.active ? "true" : "false", (unsigned long long)path.bytes_sent,
           (unsigned long long)path.bytes_received, path.rtt_ms,
           (unsigned long long)path.packets_lost);
    first = false;
  }
  puts("]}");
}

static int run_tunnel(const options_t *options) {
  int tun_fd = -1;
  char interface_name[IFNAMSIZ];
  snprintf(interface_name, sizeof(interface_name), "%s",
           options->interface_name);
  if (!options->mock) {
    if (if_nametoindex(interface_name) != 0) {
      fprintf(stderr, "interface %s already exists; refusing to modify it\n",
              interface_name);
      return 1;
    }
    if (geteuid() == 0 && !options->run_as) {
      fprintf(stderr, "root execution requires --run-as USER\n");
      return 1;
    }
    if (geteuid() != 0 && options->run_as) {
      fprintf(stderr, "--run-as requires root for initial TUN setup\n");
      return 1;
    }
    tun_fd = tun_alloc(interface_name);
    if (tun_fd < 0)
      return 1;
    int configured =
        options->peer_ip
            ? tun_configure_peer(interface_name, options->ip, options->peer_ip)
            : configure_ip_and_up(interface_name, options->ip);
    if (configured != 0 || tun_set_mtu(interface_name, options->mtu) != 0 ||
        !set_nonblocking(tun_fd)) {
      fprintf(stderr, "failed to configure TUN interface %s\n", interface_name);
      close(tun_fd);
      return 1;
    }
    for (size_t i = 0; i < options->route_count; i++) {
      if (tun_add_route(interface_name, options->routes[i]) != 0) {
        fprintf(stderr, "failed to add route %s\n", options->routes[i]);
        close(tun_fd);
        return 1;
      }
    }
  }

  qlinq_context_t *context = qlinq_context_create(NULL);
  if (!context) {
    fprintf(stderr, "failed to create qlinq context\n");
    if (tun_fd >= 0)
      close(tun_fd);
    return 1;
  }
  const char *bind = options->bind ? options->bind
                     : (!options->listen && strchr(options->peer, ':'))
                         ? "::"
                         : "0.0.0.0";
  qlinq_endpoint_config_t config = {
      .bind_addresses = {bind},
      .bind_address_count = 1,
      .port = options->port,
      .reconnect_enabled = !options->listen,
      .idle_timeout_ms = 10000,
      .limits = {.max_connections = 1},
      .security = {.shared_secret = options->token,
                   .shared_secret_size = strlen(options->token),
                   .certificate_file = options->cert,
                   .private_key_file = options->key,
                   .trust_store_file = options->ca,
                   .verify_peer = !options->insecure,
                   .allow_insecure_peer = options->insecure}};
  if (options->bind_count) {
    config.bind_address_count = options->bind_count;
    for (size_t i = 0; i < options->bind_count; i++)
      config.bind_addresses[i] = options->binds[i];
  }
  config.path_interface_count = options->uplink_count;
  for (size_t i = 0; i < options->uplink_count; i++)
    config.path_interface_names[i] = options->uplinks[i];
  if (!options->listen) {
    config.remote_addresses[0] = options->peer;
    config.remote_address_count = 1;
  }
  qlinq_endpoint_t *endpoint = options->listen
                                   ? qlinq_listen(context, &config)
                                   : qlinq_connect(context, &config);
  qlinq_stream_config_t stream_config = {.content_type = QLINQ_CONTENT_DATA,
                                         .delivery = options->delivery,
                                         .name = options->track};
  qlinq_stream_t *publisher =
      endpoint ? qlinq_publish(endpoint, &stream_config) : NULL;
  qlinq_stream_t *subscriber =
      endpoint ? qlinq_subscribe(endpoint, &stream_config) : NULL;
  if (!endpoint || !publisher || !subscriber) {
    fprintf(stderr, "failed to open direct packet stream (status=%d)\n",
            qlinq_context_last_status(context));
    qlinq_context_destroy(context);
    if (tun_fd >= 0)
      close(tun_fd);
    return 1;
  }
  /* load root-owned identity files and bind sockets before dropping uid;
   * no peer packets are serviced until privilege drop succeeds */
  if (!options->mock && geteuid() == 0 && !drop_privileges(options->run_as)) {
    qlinq_context_destroy(context);
    close(tun_fd);
    return 1;
  }
#ifdef __linux__
  /* setuid clears parent-death signal, arm it after dropping uid;
   * checking the original parent closes the setup-time race */
  if (options->parent_pid && (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 ||
                              (uint64_t)getppid() != options->parent_pid)) {
    fprintf(stderr, "tunnel supervisor disappeared during startup\n");
    qlinq_context_destroy(context);
    if (tun_fd >= 0)
      close(tun_fd);
    return 1;
  }
#endif
  printf("direct TUN %s, track=%s, mode=%d, interface=%s%s\n",
         options->listen ? "listening" : "connecting", options->track,
         options->delivery, interface_name, options->mock ? " (mock)" : "");

  receive_queue_t queue = {0};
  packet_t pending = {0};
  uint64_t sent = 0, received = 0, partial = 0;
  uint64_t tx_bytes = 0, rx_bytes = 0, tx_dropped = 0, last_stats = 0;
  const char *state = options->listen ? "listening" : "connecting";
  uint64_t started = monotonic_ms(), last_mock = 0;
  int result = 0;
  while (!stopping &&
         (!options->run_ms || monotonic_ms() - started < options->run_ms)) {
    short ready_events = 0;
    qlinq_status_t status =
        qlinq_service_fd(context, options->mock ? 10 : 50, tun_fd,
                         POLLIN | (queue.count ? POLLOUT : 0), &ready_events);
    if (status < QLINQ_STATUS_OK) {
      fprintf(stderr, "qlinq service failed: %d\n", status);
      result = 1;
      break;
    }
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_RECORD && event.stream == subscriber) {
        if (valid_packet(event.record.data, event.record.size) &&
            event.record.size <= options->mtu) {
          received++;
          rx_bytes += event.record.size;
          if (!options->mock)
            enqueue_packet(&queue, event.record.data, event.record.size);
        } else {
          queue.dropped++;
        }
      } else if (event.type == QLINQ_EVENT_PEER_READY) {
        state = "connected";
        fprintf(stderr, "peer %u ready\n", event.peer_id);
      } else if (event.type == QLINQ_EVENT_PEER_DISCONNECTED ||
                 event.type == QLINQ_EVENT_SUBSCRIBER_LEFT) {
        /* do not replay an old IP packet after reconnect */
        pending.size = 0;
        queue.dropped += queue.count;
        queue.count = 0;
        state = options->listen ? "listening" : "reconnecting";
      } else if (event.type == QLINQ_EVENT_PEER_REJECTED ||
                 event.type == QLINQ_EVENT_ERROR) {
        state = "error";
        fprintf(stderr, "peer error: %s (status=%d)\n",
                event.message ? event.message : "unknown", event.status);
      }
      qlinq_event_release(&event);
    }
    uint64_t now_ms = monotonic_ms();
    if (options->stats_ms && now_ms - last_stats >= options->stats_ms) {
      print_stats(endpoint, state, sent, received, tx_bytes, rx_bytes,
                  queue.dropped + tx_dropped);
      last_stats = now_ms;
    }
    if (pending.size && now_ms - pending.queued_ms >= options->queue_ms) {
      pending.size = 0;
      tx_dropped++;
    }
    if (tun_fd >= 0 && !flush_packets(&queue, tun_fd, options->queue_ms)) {
      result = 1;
      break;
    }
    for (size_t batch = 0; batch < 32; batch++) {
      if (pending.size == 0) {
        if (options->mock) {
          uint64_t now = monotonic_ms();
          if (now - last_mock < 100)
            break;
          make_mock_packet(&pending, sent + 1);
          last_mock = now;
        } else {
          ssize_t count =
              tun_read(tun_fd, pending.bytes, sizeof(pending.bytes));
          if (count < 0 && errno == EINTR)
            continue;
          if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
          if (count <= 0) {
            perror("reading TUN packet");
            result = 1;
            stopping = 1;
            break;
          }
          pending.size = (size_t)count;
          if (!valid_packet(pending.bytes, pending.size) ||
              pending.size > options->mtu) {
            pending.size = 0;
            tx_dropped++;
            continue;
          }
        }
        pending.queued_ms = monotonic_ms();
      }
      if (!qlinq_stream_is_writable(publisher)) {
        /* drain kernel packets while disconnected instead of replaying a
         * stale burst when connectivity returns */
        pending.size = 0;
        tx_dropped++;
        if (options->mock)
          break;
        continue;
      }
      qlinq_record_t record = {.data = pending.bytes,
                               .size = pending.size,
                               .sequence = sent + 1,
                               .priority = 1};
      qlinq_send_result_t send_result = qlinq_stream_send(publisher, &record);
      if (send_result == QLINQ_SEND_WOULD_BLOCK)
        break;
      if (send_result == QLINQ_SEND_NO_SUBSCRIBERS)
        break;
      if (send_result == QLINQ_SEND_INVALID ||
          send_result == QLINQ_SEND_FAILED) {
        fprintf(stderr, "packet send failed: %d\n", send_result);
        result = 1;
        stopping = 1;
        break;
      }
      if (send_result == QLINQ_SEND_PARTIAL)
        partial++;
      sent++;
      tx_bytes += pending.size;
      pending.size = 0;
      if (options->mock)
        break;
    }
  }
  if (options->stats_ms)
    print_stats(endpoint, "stopped", sent, received, tx_bytes, rx_bytes,
                queue.dropped + tx_dropped);
  printf("direct TUN summary: sent=%llu received=%llu partial=%llu "
         "dropped=%llu\n",
         (unsigned long long)sent, (unsigned long long)received,
         (unsigned long long)partial, (unsigned long long)queue.dropped);
  if (options->mock && options->run_ms && (!sent || !received))
    result = 1;
  qlinq_endpoint_shutdown(endpoint, "tunnel stopped");
  uint64_t drain_until = monotonic_ms() + 250;
  while (!qlinq_endpoint_is_drained(endpoint) && monotonic_ms() < drain_until) {
    if (qlinq_service(context, 10) < QLINQ_STATUS_OK)
      break;
    qlinq_event_t event;
    while (qlinq_next_event(context, &event))
      qlinq_event_release(&event);
  }
  qlinq_context_destroy(context);
  if (tun_fd >= 0)
    close(tun_fd);
  return result;
}

int tun_worker_main(int argc, char **argv) {
  options_t options;
  setvbuf(stdout, NULL, _IONBF, 0);
  if (!parse_options(argc, argv, &options)) {
    fprintf(stderr, "invalid command line\n");
    usage(stderr, argv[0]);
    return 1;
  }
  signal(SIGINT, stop_on_signal);
  signal(SIGTERM, stop_on_signal);
  return run_tunnel(&options);
}
