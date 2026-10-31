#include "cli_parse.h"
#include "qlinq.h"
#include "tun_control.h"
#include "tun_device.h"
#include "tun_packet.h"
#include "tun_receive_batch.h"
#include "tun_coalesce.h"

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
#define PACKET_CAPACITY TUN_RX_PACKET_CAPACITY
#define RECEIVE_WRITE_BUDGET 2048U

typedef struct {
  uint8_t bytes[PACKET_CAPACITY];
  size_t size;
  uint64_t queued_ms;
} packet_t;

typedef struct {
  bool listen;
  bool mock;
  bool tx_gso, rx_gro;
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
      "  --mode MODE             fixedrate/fec (default), rateless, reliable, "
      "datagram\n"
      "  --cert FILE --key FILE  TLS identity (required on listener)\n"
      "  --ca FILE               Trust store for verified peers\n"
      "  --insecure-no-verify    Disable certificate verification (tests "
      "only)\n"
      "  --run-as USER           Drop root privileges after TUN setup\n"
      "  --rx-gro                Try Linux TCP receive coalescing (default: "
      "off)\n"
      "  --tx-gso                Try Linux TCP transmit offloads (default: "
      "off)\n"
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
                         .delivery = QLINQ_DELIVERY_FIXEDRATE};
  bool have_role = false;
  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];
    if (strcmp(arg, "--help") == 0) {
      usage(stdout, argv[0]);
      exit(0);
    }
    if (strcmp(arg, "--rx-gro") == 0) {
      options->rx_gro = true;
    } else if (strcmp(arg, "--tx-gso") == 0) {
      options->tx_gso = true;
    } else if (strcmp(arg, "--mock") == 0) {
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

typedef struct {
  tun_rx_batch_t *queue;
  qlinq_stream_t *subscriber;
  int fd;
  size_t mtu, write_budget;
  uint64_t received, bytes;
  bool write_blocked, stopped, failed, vnet, coalesce;
  uint8_t aggregate[TUN_RX_AGGREGATE_CAPACITY];
  uint64_t write_calls, written_packets, aggregates, coalesced_packets,
      copied_bytes;
} tunnel_receiver_t;

static ssize_t write_receive_packet(tunnel_receiver_t *receiver,
                                    const void *data, size_t size) {
  receiver->write_calls++;
  return receiver->vnet ? tun_write_vnet(receiver->fd, data, size)
                        : tun_write(receiver->fd, data, size);
}

static void begin_receive_batch(tunnel_receiver_t *receiver) {
  (void)tun_rx_batch_begin(receiver->queue);
  receiver->write_budget = RECEIVE_WRITE_BUDGET;
  receiver->write_blocked = false;
}

/* consume owned storage only after whole-packet writes; bound syscalls */
static bool flush_packets(tunnel_receiver_t *receiver, uint64_t now_ms) {
  if (receiver->failed)
    return false;
  if (!receiver->queue->count)
    return true;
  tun_rx_batch_expire(receiver->queue, now_ms);
  tun_rx_view_t view;
  while (receiver->queue->count && !receiver->write_blocked &&
         receiver->write_budget &&
         tun_rx_batch_peek(receiver->queue, now_ms, &view)) {
    receiver->write_budget--;
    tun_coalesce_output_t output = {.packet = view.packet, .count = 1};
    if (receiver->coalesce) {
      tun_packet_view_t packets[TUN_RX_BATCH_CAPACITY];
      size_t count = 0;
      while (count < receiver->queue->count) {
        const tun_rx_slot_t *slot =
            &receiver->queue->slots[(receiver->queue->head + count) %
                                    TUN_RX_BATCH_CAPACITY];
        if (slot->batch_id != view.batch_id)
          break;
        packets[count++] = (tun_packet_view_t){.data = slot->bytes,
                                               .size = slot->size,
                                               .header_size = slot->header_size,
                                               .version = slot->version};
        if (slot->end_of_batch)
          break;
      }
      (void)tun_coalesce(packets, count, receiver->aggregate,
                         sizeof(receiver->aggregate), &output);
    }
    ssize_t written;
    if (output.count > 1) {
      receiver->write_calls++;
      receiver->copied_bytes += output.packet.size;
      written = tun_write_offload(receiver->fd, output.packet.data,
                                  output.packet.size, &output.offload);
    } else
      written = write_receive_packet(receiver, output.packet.data,
                                     output.packet.size);
    if (written < 0 && errno == EINTR)
      continue;
    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      receiver->write_blocked = true;
      return true;
    }
    if (written != (ssize_t)output.packet.size) {
      fprintf(stderr, "queued TUN packet write failed: %s\n",
              written < 0 ? strerror(errno) : "short write");
      receiver->failed = true;
      return false;
    }
    receiver->written_packets += output.count;
    if (output.count > 1) {
      receiver->aggregates++;
      receiver->coalesced_packets += output.count;
    }
    for (size_t i = 0; i < output.count; i++)
      tun_rx_batch_consume(receiver->queue);
  }
  return true;
}

static bool end_receive_batch(tunnel_receiver_t *receiver, uint64_t now_ms) {
  tun_rx_batch_end(receiver->queue);
  return receiver->fd < 0 || flush_packets(receiver, now_ms);
}

/* use earliest batch expiry for poll wakeups to avoid EAGAIN spinning */
static int receive_poll_timeout(tunnel_receiver_t *receiver, int timeout_ms,
                                uint64_t now_ms) {
  uint64_t deadline;
  if (tun_rx_batch_deadline(receiver->queue, &deadline)) {
    uint64_t remaining = deadline > now_ms ? deadline - now_ms : 0;
    if (remaining < (uint64_t)timeout_ms)
      timeout_ms = (int)remaining;
  }
  return timeout_ms;
}

/* borrow immediate records when queue is empty; copy retained packets */
static bool receive_packet(void *data, const qlinq_event_t *event) {
  tunnel_receiver_t *receiver = data;
  if (receiver->stopped || event->stream != receiver->subscriber)
    return true;
  if (receiver->failed)
    return false;
  tun_packet_config_t config = {.mtu = receiver->mtu,
                                .max_packet_size = PACKET_CAPACITY};
  tun_packet_input_t input = {.data = event->record.data,
                              .size = event->record.size,
                              .origin = TUN_PACKET_FROM_PEER};
  tun_packet_output_t output;
  tun_packet_result_t processed =
      tun_packet_process(&config, &input, &output, 1);
  if (processed.status != TUN_PACKET_OK) {
    receiver->queue->dropped++;
    return true;
  }
  const tun_packet_view_t *packet = &output.packet;
  receiver->received++;
  receiver->bytes += packet->size;
  if (receiver->fd < 0)
    return true;
  uint64_t now_ms = monotonic_ms();
  if (receiver->coalesce &&
      (receiver->queue->count || tun_coalesce_candidate(packet))) {
    /* copy before callback returns; flush on pressure or incompatible prefix */
    if (receiver->queue->count && !flush_packets(receiver, now_ms))
      return false;
    bool incompatible = false;
    if (receiver->queue->count) {
      const tun_rx_slot_t *tail =
          &receiver->queue
               ->slots[(receiver->queue->head + receiver->queue->count - 1) %
                       TUN_RX_BATCH_CAPACITY];
      tun_packet_view_t previous = {.data = tail->bytes, .size = tail->size};
      incompatible = !tun_coalesce_pair(&previous, packet);
    }
    if (incompatible ||
        receiver->queue->count == receiver->queue->limits.packets ||
        packet->size > receiver->queue->limits.bytes - receiver->queue->bytes) {
      tun_rx_batch_end(receiver->queue);
      if (!flush_packets(receiver, now_ms))
        return false;
      (void)tun_rx_batch_begin(receiver->queue);
    }
    (void)tun_rx_batch_push(receiver->queue, packet, now_ms);
    return flush_packets(receiver, now_ms);
  }
  if (!flush_packets(receiver, now_ms))
    return false;
  if (receiver->queue->count || receiver->write_blocked ||
      !receiver->write_budget) {
    (void)tun_rx_batch_push(receiver->queue, packet, now_ms);
    return true;
  }
  ssize_t written = -1;
  while (receiver->write_budget) {
    receiver->write_budget--;
    written = write_receive_packet(receiver, packet->data, packet->size);
    if (written >= 0 || errno != EINTR)
      break;
  }
  if (written < 0 &&
      (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
    receiver->write_blocked = errno != EINTR;
    (void)tun_rx_batch_push(receiver->queue, packet, now_ms);
    return true;
  }
  if (written != (ssize_t)packet->size) {
    fprintf(stderr, "direct TUN packet write failed: %s\n",
            written < 0 ? strerror(errno) : "short write");
    receiver->failed = true;
    return false;
  }
  receiver->written_packets++;
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

typedef struct {
  tun_segment_t plan;
  uint64_t queued_ms, read_calls, frames, gso_reads, gso_packets, checksums,
      dropped;
  bool vnet, offload;
} tunnel_transmitter_t;

static void expire_transmit(tunnel_transmitter_t *tx, uint64_t now,
                            uint64_t max_age) {
  if (tx->plan.pending && now - tx->queued_ms >= max_age)
    tx->dropped += tun_segment_cancel(&tx->plan);
}

/* read and segment TUN transmit frames */
static ssize_t read_transmit(tunnel_transmitter_t *tx, int fd, uint8_t *frame,
                             packet_t *packet, tun_packet_output_t *output,
                             const tun_packet_config_t *config, uint64_t now) {
  if (!tx->offload) {
    tx->read_calls++;
    tun_offload_t metadata = {0};
    ssize_t n = tx->vnet ? tun_read_vnet(fd, packet->bytes,
                                         sizeof(packet->bytes), &metadata)
                         : tun_read(fd, packet->bytes, sizeof(packet->bytes));
    if (n > 0 && tx->vnet &&
        (metadata.flags || metadata.gso_type || metadata.gso_size)) {
      tx->dropped++;
      errno = EBADMSG;
      return -1;
    }
    if (n > 0)
      tx->frames++;
    packet->queued_ms = now;
    return n;
  }
  if (!tx->plan.pending) {
    tun_offload_t metadata;
    tx->read_calls++;
    ssize_t n = tun_read_vnet(fd, frame, TUN_TX_FRAME_CAPACITY + 1, &metadata);
    if (n <= 0) {
      if (n < 0 && errno == EBADMSG)
        tx->dropped++;
      return n;
    }
    tx->frames++;
    tun_packet_input_t input = {
        .data = frame, .size = (size_t)n, .origin = TUN_PACKET_FROM_DEVICE};
    if (!tun_segment_prepare(&tx->plan, config, &input, &metadata)) {
      tx->dropped++;
      errno = EBADMSG;
      return -1;
    }
    tx->queued_ms = now;
    if (tx->plan.segmented)
      tx->gso_reads++;
  }
  tun_packet_result_t result =
      tun_segment_next(&tx->plan, packet->bytes, sizeof(packet->bytes), output);
  if (result.status != TUN_PACKET_OK) {
    tx->dropped += tun_segment_cancel(&tx->plan);
    errno = EBADMSG;
    return -1;
  }
  if (tx->plan.segmented)
    tx->gso_packets++;
  if (tx->plan.partial)
    tx->checksums++;
  packet->queued_ms = tx->queued_ms;
  return (ssize_t)output->packet.size;
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
                        uint64_t rx_bytes, uint64_t dropped,
                        const tunnel_transmitter_t *tx,
                        const tunnel_receiver_t *rx) {
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
         "\"queued_bytes\":%zu,\"tx_gso_active\":%s,"
         "\"rx_gro_active\":%s,\"rx_tun_writes\":%llu,"
         "\"rx_written_packets\":%llu,\"rx_aggregates\":%llu,"
         "\"rx_coalesced_packets\":%llu,\"rx_aggregate_copy_bytes\":%llu,"
         "\"tx_tun_reads\":%llu,\"tx_tun_frames\":%llu,"
         "\"tx_gso_reads\":%llu,\"tx_gso_packets\":%llu,"
         "\"tx_csum_packets\":%llu,\"tx_gso_pending_packets\":%zu,\"paths\":[",
         state, (unsigned long long)sent, (unsigned long long)received,
         (unsigned long long)tx_bytes, (unsigned long long)rx_bytes,
         (unsigned long long)dropped,
         (unsigned long long)stats.fec_objects_recovered,
         (unsigned long long)stats.fec_objects_decoded,
         (unsigned long long)stats.fec_objects_lost,
         (unsigned long long)stats.reconnect_attempts, stats.queued_bytes,
         tx->offload ? "true" : "false", rx->coalesce ? "true" : "false",
         (unsigned long long)rx->write_calls,
         (unsigned long long)rx->written_packets,
         (unsigned long long)rx->aggregates,
         (unsigned long long)rx->coalesced_packets,
         (unsigned long long)rx->copied_bytes,
         (unsigned long long)tx->read_calls, (unsigned long long)tx->frames,
         (unsigned long long)tx->gso_reads, (unsigned long long)tx->gso_packets,
         (unsigned long long)tx->checksums, tun_segment_remaining(&tx->plan));
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
  tunnel_transmitter_t tx = {0};
  uint8_t tx_frame[TUN_TX_FRAME_CAPACITY + 1];
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
    tun_fd = options->tx_gso || options->rx_gro
                 ? tun_alloc_vnet(interface_name, options->tx_gso, &tx.vnet)
                 : tun_alloc(interface_name);
    if (tun_fd < 0)
      return 1;
    if ((options->tx_gso || options->rx_gro) && !tx.vnet)
      fprintf(stderr, "TUN offloads unavailable; using ordinary TUN I/O\n");
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

  tx.offload = tx.vnet && options->tx_gso;
  tun_rx_batch_t queue;
  tun_rx_limits_t receive_limits = {.packets = TUN_RX_BATCH_CAPACITY,
                                    .bytes =
                                        TUN_RX_BATCH_CAPACITY * options->mtu,
                                    .max_age_ms = options->queue_ms,
                                    .flush_delay_ms = 1};
  if (!tun_rx_batch_init(&queue, &receive_limits)) {
    if (tun_fd >= 0)
      close(tun_fd);
    return 1;
  }
  tunnel_receiver_t receiver = {.queue = &queue,
                                .fd = tun_fd,
                                .mtu = options->mtu,
                                .vnet = tx.vnet,
                                .coalesce = options->rx_gro && tx.vnet};
  qlinq_context_config_t context_config = {.record_callback = receive_packet,
                                           .record_user_data = &receiver};
  qlinq_context_t *context = qlinq_context_create(&context_config);
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
  receiver.subscriber = subscriber;
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

  packet_t pending = {0};
  /* pending_output borrows pending.bytes until sent, expired, or cancelled */
  tun_packet_output_t pending_output = {0};
  tun_packet_config_t packet_config = {.mtu = options->mtu,
                                       .max_packet_size = PACKET_CAPACITY};
  uint64_t sent = 0, partial = 0;
  uint64_t tx_bytes = 0, tx_dropped = 0, last_stats = 0;
  const char *state = options->listen ? "listening" : "connecting";
  uint64_t started = monotonic_ms(), last_mock = 0;
  int result = 0;
  while (!stopping &&
         (!options->run_ms || monotonic_ms() - started < options->run_ms)) {
    short ready_events = 0;
    uint64_t turn_now = monotonic_ms();
    expire_transmit(&tx, turn_now, options->queue_ms);
    int timeout_ms = receive_poll_timeout(&receiver, options->mock ? 10 : 50,
                                          monotonic_ms());
    /* handle disconnect events before closing or flushing the receive batch */
    if (!pending.size && tx.plan.pending)
      timeout_ms = 0; /* buffered segments need service without fd readiness */
    if (pending.size) {
      uint64_t age = turn_now - pending.queued_ms;
      uint64_t left = age < options->queue_ms ? options->queue_ms - age : 0;
      if (left < (uint64_t)timeout_ms)
        timeout_ms = (int)left;
    }
    begin_receive_batch(&receiver);
    qlinq_status_t status =
        qlinq_service_fd(context, timeout_ms, tun_fd,
                         (pending.size || tx.plan.pending ? 0 : POLLIN) |
                             (queue.count ? POLLOUT : 0),
                         &ready_events);
    if (status < QLINQ_STATUS_OK) {
      fprintf(stderr, "qlinq service failed: %d\n", status);
      tun_rx_batch_cancel(&queue);
      result = 1;
      break;
    }
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_PEER_READY) {
        state = "connected";
        fprintf(stderr, "peer %u ready\n", event.peer_id);
      } else if (event.type == QLINQ_EVENT_PEER_DISCONNECTED ||
                 event.type == QLINQ_EVENT_SUBSCRIBER_LEFT) {
        /* do not replay an old IP packet after reconnect */
        if (pending.size)
          tx_dropped++;
        pending.size = 0;
        tx.dropped += tun_segment_cancel(&tx.plan);
        tun_rx_batch_cancel(&queue);
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
      print_stats(endpoint, state, sent, receiver.received, tx_bytes,
                  receiver.bytes, queue.dropped + tx_dropped + tx.dropped, &tx,
                  &receiver);
      last_stats = now_ms;
    }
    if (pending.size && now_ms - pending.queued_ms >= options->queue_ms) {
      pending.size = 0;
      tx_dropped++;
    }
    if (!end_receive_batch(&receiver, now_ms)) {
      result = 1;
      break;
    }
    for (size_t batch = 0; batch < 32; batch++) {
      uint64_t packet_now = monotonic_ms();
      expire_transmit(&tx, packet_now, options->queue_ms);
      if (pending.size == 0) {
        if (options->mock) {
          uint64_t now = packet_now;
          if (now - last_mock < 100)
            break;
          make_mock_packet(&pending, sent + 1);
          pending.queued_ms = now;
          last_mock = now;
        } else {
          ssize_t count =
              read_transmit(&tx, tun_fd, tx_frame, &pending, &pending_output,
                            &packet_config, packet_now);
          if (count < 0 && errno == EBADMSG)
            continue;
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
        }
        if (!tx.offload) {
          tun_packet_input_t input = {.data = pending.bytes,
                                      .size = pending.size,
                                      .origin = TUN_PACKET_FROM_DEVICE};
          tun_packet_result_t processed =
              tun_packet_process(&packet_config, &input, &pending_output, 1);
          if (processed.status != TUN_PACKET_OK) {
            pending.size = 0;
            tx_dropped++;
            continue;
          }
        }
      }
      if (monotonic_ms() - pending.queued_ms >= options->queue_ms) {
        pending.size = 0;
        tx_dropped++;
        continue;
      }
      if (strcmp(state, "connected") != 0) {
        /* drain kernel packets while disconnected instead of replaying a
         * stale burst when connectivity returns */
        pending.size = 0;
        tx_dropped++;
        tx.dropped += tun_segment_cancel(&tx.plan);
        if (options->mock)
          break;
        continue;
      }
      if (!qlinq_stream_is_writable(publisher))
        break; /* preserve pending until the configured queue age expires */
      qlinq_record_t record = {.data = pending_output.packet.data,
                               .size = pending_output.packet.size,
                               .sequence = sent + 1,
                               .priority = 1};
      qlinq_send_result_t send_result = qlinq_stream_send(publisher, &record);
      if (send_result == QLINQ_SEND_WOULD_BLOCK)
        break;
      if (send_result == QLINQ_SEND_NO_SUBSCRIBERS) {
        /* drop packet and segment tail when peer has no subscribers */
        pending.size = 0;
        tx_dropped++;
        tx.dropped += tun_segment_cancel(&tx.plan);
        break;
      }
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
      tx_bytes += pending_output.packet.size;
      pending.size = 0;
      if (options->mock)
        break;
    }
  }
  if (pending.size) {
    tx_dropped++;
    pending.size = 0;
  }
  tx.dropped += tun_segment_cancel(&tx.plan);
  receiver.stopped = true;
  tun_rx_batch_cancel(&queue);
  if (options->stats_ms)
    print_stats(endpoint, "stopped", sent, receiver.received, tx_bytes,
                receiver.bytes, queue.dropped + tx_dropped + tx.dropped, &tx,
                &receiver);
  printf("direct TUN summary: sent=%llu received=%llu partial=%llu "
         "dropped=%llu\n",
         (unsigned long long)sent, (unsigned long long)receiver.received,
         (unsigned long long)partial,
         (unsigned long long)(queue.dropped + tx_dropped + tx.dropped));
  printf("TUN RX: coalescing=%u write_calls=%llu packets=%llu aggregates=%llu "
         "coalesced_packets=%llu aggregate_copy_bytes=%llu\n",
         receiver.coalesce, (unsigned long long)receiver.write_calls,
         (unsigned long long)receiver.written_packets,
         (unsigned long long)receiver.aggregates,
         (unsigned long long)receiver.coalesced_packets,
         (unsigned long long)receiver.copied_bytes);
  printf("TUN TX: offload=%u read_calls=%llu frames=%llu gso_reads=%llu "
         "gso_packets=%llu checksum_packets=%llu\n",
         tx.offload, (unsigned long long)tx.read_calls,
         (unsigned long long)tx.frames, (unsigned long long)tx.gso_reads,
         (unsigned long long)tx.gso_packets, (unsigned long long)tx.checksums);
  if (options->mock && options->run_ms && (!sent || !receiver.received))
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
