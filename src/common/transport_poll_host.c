/* default socket host for the explicit transport engine boundary */
#include "transport_poll_host.h"
#include "portable_sockets.h"
#include "quicly/sendstate.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifndef _WIN32
#include <net/if.h>
#endif

static void copy_interface_name(char out[64], const char *name) {
  snprintf(out, 64, "%s", name);
}
static void host_log(transport_poll_host_t *host, transport_log_level_t level,
                     const char *component, uint32_t conn, size_t path,
                     const char *format, ...) {
  char message[512];
  va_list args;
  va_start(args, format);
  vsnprintf(message, sizeof(message), format, args);
  va_end(args);
  if (host->transport)
    transport_log(host->transport, level, component, conn, path, "%s", message);
  else if (host->log_callback) {
    transport_log_event_t event = {.level = level,
                                   .component = component,
                                   .connection_id = conn,
                                   .path_index = path,
                                   .message = message};
    host->log_callback(host->log_user_data, &event);
  } else if (level >= TRANSPORT_LOG_WARNING)
    fprintf(stderr, "qlinq[%s] %s: %s\n", component,
            level == TRANSPORT_LOG_ERROR ? "error" : "warning", message);
}
static socklen_t ifmon_socket_address(struct sockaddr_storage *out,
                                      const ifmon_addr_t *address,
                                      uint32_t interface_index) {
  memset(out, 0, sizeof(*out));
  if (address->family == AF_INET) {
    struct sockaddr_in *v4 = (struct sockaddr_in *)out;
    v4->sin_family = AF_INET;
    v4->sin_addr = address->ip.v4;
    return sizeof(*v4);
  }
  struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)out;
  v6->sin6_family = AF_INET6;
  v6->sin6_addr = address->ip.v6;
  if (IN6_IS_ADDR_LINKLOCAL(&v6->sin6_addr))
    v6->sin6_scope_id = interface_index;
  return sizeof(*v6);
}
static void bind_to_device(int fd, uint32_t index) {
  if (index == 0)
    return;
#if defined(__linux__)
  char ifname[IF_NAMESIZE];
  if (if_indextoname(index, ifname)) {
    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
  }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
#ifndef IP_BOUND_IF
#define IP_BOUND_IF 25
#endif
#ifndef IPV6_BOUND_IF
#define IPV6_BOUND_IF 125
#endif
  unsigned int idx = index;
  setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx));
  setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx));
#elif defined(_WIN32)
  DWORD idx = index;
  setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, (const char *)&idx, sizeof(idx));
  setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, (const char *)&idx,
             sizeof(idx));
#endif
}
static void on_ifmon_update(const ifmon_update_t *update, void *userdata) {
  transport_poll_host_t *t = userdata;

  if (update->is_initial) {
    if (!t->multihome)
      return;
    for (int j = 0; j < update->interfaces->count; j++) {
      const ifmon_iface_t *iface = &update->interfaces->ifaces[j];
      if (!iface->is_up)
        continue;
      if (strncmp(iface->name, "lo", 2) == 0 && update->interfaces->count > 1)
        continue;
      for (int k = 0; k < iface->addr_count; k++) {
        const ifmon_addr_t *a = &iface->addrs[k];
        transport_interface_event_t msg = {0};
        msg.index = iface->index;
        copy_interface_name(msg.name, iface->name);
        msg.is_added = 1;
        msg.addr_len = ifmon_socket_address(&msg.addr, a, msg.index);
        ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
        (void)w;
      }
    }
    return;
  }

  for (int i = 0; i < update->added_count; i++) {
    uint32_t idx = update->added[i];
    for (int j = 0; j < update->interfaces->count; j++) {
      if (update->interfaces->ifaces[j].index == idx) {
        const ifmon_iface_t *iface = &update->interfaces->ifaces[j];
        for (int k = 0; k < iface->addr_count; k++) {
          const ifmon_addr_t *a = &iface->addrs[k];
          transport_interface_event_t msg = {0};
          msg.index = idx;
          copy_interface_name(msg.name, iface->name);
          msg.is_added = 1;
          msg.addr_len = ifmon_socket_address(&msg.addr, a, msg.index);
          ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
          (void)w;
        }
        break;
      }
    }
  }

  for (int i = 0; i < update->removed_count; i++) {
    transport_interface_event_t msg = {0};
    msg.index = update->removed[i];
    msg.is_added = 0;
    msg.addr.ss_family = AF_UNSPEC;
    ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
    (void)w;
  }

  for (int i = 0; i < update->modified_count; i++) {
    const ifmon_iface_diff_t *diff = &update->modified[i];

    if (diff->link_state_changed) {
      for (int k = 0; k < update->interfaces->count; k++) {
        const ifmon_iface_t *iface = &update->interfaces->ifaces[k];
        if (iface->index == diff->index) {
          for (int a_idx = 0; a_idx < iface->addr_count; a_idx++) {
            const ifmon_addr_t *a = &iface->addrs[a_idx];
            transport_interface_event_t msg = {0};
            msg.index = diff->index;
            copy_interface_name(msg.name, iface->name);
            msg.is_added = diff->is_up ? 1 : 0;
            msg.addr_len = ifmon_socket_address(&msg.addr, a, msg.index);
            ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
            (void)w;
          }
          break;
        }
      }
    }

    for (int j = 0; j < diff->addrs_added_count; j++) {
      const ifmon_addr_t *a = &diff->addrs_added[j];
      transport_interface_event_t msg = {0};
      msg.index = diff->index;
      msg.is_added = 1;
      for (int k = 0; k < update->interfaces->count; k++) {
        if (update->interfaces->ifaces[k].index == diff->index) {
          copy_interface_name(msg.name, update->interfaces->ifaces[k].name);
          break;
        }
      }
      msg.addr_len = ifmon_socket_address(&msg.addr, a, msg.index);
      ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
      (void)w;
    }

    for (int j = 0; j < diff->addrs_removed_count; j++) {
      const ifmon_addr_t *a = &diff->addrs_removed[j];
      transport_interface_event_t msg = {0};
      msg.index = diff->index;
      msg.is_added = 0;
      for (int k = 0; k < update->interfaces->count; k++) {
        if (update->interfaces->ifaces[k].index == diff->index) {
          copy_interface_name(msg.name, update->interfaces->ifaces[k].name);
          break;
        }
      }
      msg.addr_len = ifmon_socket_address(&msg.addr, a, msg.index);
      ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
      (void)w;
    }
  }
}
static bool set_fd_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}
static int open_unicast_socket(int family) {
  int fd = socket(family, SOCK_DGRAM, 0);
  if (fd >= 0 && family == AF_INET6) {
    /* wildcard IPv6 path must not claim a separately configured IPv4 port */
    int v6_only = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof(v6_only)) !=
        0) {
      CLOSE_SOCKET(fd);
      return -1;
    }
  }
  if (fd >= 0) {
    (void)transport_udp_enable_recv_ecn(fd, family);
    (void)transport_udp_enable_recv_pktinfo(fd, family);
  }
  return fd;
}
static void configure_socket_buffers(transport_poll_host_t *t, int fd) {
  int buf_size = 32 * 1024 * 1024; /* 32mb buffer size for multi-gigabit bdp */
#ifdef SO_SNDBUFFORCE
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &buf_size, sizeof(buf_size)) !=
          0 &&
      setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) != 0)
#else
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) != 0)
#endif
    host_log(t, TRANSPORT_LOG_WARNING, "udp", 0, SIZE_MAX,
             "unable to enlarge send buffer: %s", strerror(errno));
#ifdef SO_RCVBUFFORCE
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &buf_size, sizeof(buf_size)) !=
          0 &&
      setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) != 0)
#else
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) != 0)
#endif
    host_log(t, TRANSPORT_LOG_WARNING, "udp", 0, SIZE_MAX,
             "unable to enlarge receive buffer: %s", strerror(errno));
  int send_size = 0, receive_size = 0;
  socklen_t size_len = sizeof(send_size);
  bool sizes_known =
      getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_size, &size_len) == 0;
  size_len = sizeof(receive_size);
  sizes_known =
      getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_size, &size_len) == 0 &&
      sizes_known;
  if (sizes_known) {
    int expected_size = buf_size;
#ifdef __linux__
    /* linux reports twice the requested value, including kernel overhead */
    expected_size *= 2;
#endif
    bool clamped = send_size < expected_size || receive_size < expected_size;
    host_log(t, clamped ? TRANSPORT_LOG_WARNING : TRANSPORT_LOG_INFO, "udp", 0,
             SIZE_MAX,
             "socket buffers requested=%d send=%d receive=%d expected=%d%s",
             buf_size, send_size, receive_size, expected_size,
             clamped ? "; clamped by host socket buffer limits" : "");
  }
}

static void resolve_interface(transport_drive_path_t *path) {
  if (path->interface_index)
    return;
  ifmon_list_t list = {0};
  uint8_t scratch[IFMON_SCRATCHPAD_SIZE];
  if (ifmon_list_get(&list, scratch, sizeof(scratch)))
    return;
  for (int i = 0; i < list.count; i++)
    for (int a = 0; a < list.ifaces[i].addr_count; a++) {
      struct sockaddr_storage address;
      ifmon_socket_address(&address, &list.ifaces[i].addrs[a],
                           list.ifaces[i].index);
      if (transport_address_equal((struct sockaddr *)&address,
                                  (struct sockaddr *)&path->local)) {
        path->interface_index = list.ifaces[i].index;
        copy_interface_name(path->interface_name, list.ifaces[i].name);
        return;
      }
    }
}
/* keep unicast tuples exclusive; SO_REUSEADDR can steal QUIC replies */
static bool host_open(void *context, transport_drive_path_t *path) {
  transport_poll_host_t *host = context;
  if (host->socket_count == TRANSPORT_MAX_PATHS)
    return false;
  int fd = open_unicast_socket(path->local.ss_family);
  if (fd < 0)
    return false;
  if (bind(fd, (struct sockaddr *)&path->local, path->local_len))
    goto Fail;
  socklen_t len = sizeof(path->local);
  if (getsockname(fd, (struct sockaddr *)&path->local, &len) == 0)
    path->local_len = len;
  configure_socket_buffers(host, fd);
  if (!set_fd_nonblocking(fd))
    goto Fail;
  /* hot-added addresses carry an interface index */
  if (path->interface_index)
    bind_to_device(fd, path->interface_index);
  resolve_interface(path);
  transport_poll_socket_t *socket = &host->sockets[host->socket_count++];
  *socket = (transport_poll_socket_t){
      .path = *path, .fd = fd, .gro = transport_udp_gro_create(fd)};
  return true;
Fail: {
  int error = errno;
  CLOSE_SOCKET(fd);
  errno = error;
  return false;
}
}
static void host_close(void *context, const transport_drive_path_t *path) {
  transport_poll_host_t *host = context;
  for (size_t i = 0; i < host->socket_count; i++)
    if (host->sockets[i].path.id == path->id) {
      transport_udp_gro_destroy(host->sockets[i].gro);
      CLOSE_SOCKET(host->sockets[i].fd);
      memmove(host->sockets + i, host->sockets + i + 1,
              (host->socket_count - i - 1) * sizeof(host->sockets[0]));
      --host->socket_count;
      return;
    }
}
static void assert_socket_alignment(const transport_t *t,
                                    const transport_poll_host_t *host) {
#ifndef NDEBUG
  assert(host->socket_count == t->socket_count);
  for (size_t i = 0; i < t->socket_count; i++)
    assert(host->sockets[i].path.id == t->sockets[i].drive_id);
#else
  (void)t;
  (void)host;
#endif
}
static ssize_t host_send(void *context, const transport_drive_path_t *path,
                         const struct sockaddr *source,
                         const struct sockaddr *destination, socklen_t len,
                         uint32_t ifindex, uint8_t ecn, size_t gso,
                         const struct iovec *datagrams, size_t count) {
  transport_poll_host_t *host = context;
  for (size_t i = 0; i < host->socket_count; i++)
    if (host->sockets[i].path.id == path->id) {
      int fd = host->sockets[i].fd;
      if (transport_address_is_wildcard((struct sockaddr *)&path->local) &&
          source && source->sa_family != AF_UNSPEC)
        return transport_udp_send_batch_pktinfo(
            fd, destination, len, source, ifindex, datagrams, count, gso, ecn);
      return transport_udp_send_batch_ecn(fd, destination, len, datagrams,
                                          count, gso, ecn);
    }
  return -1;
}
static uint64_t host_now(void *context) {
  (void)context;
  return transport_get_monotonic_ns();
}
static bool host_input_pending(void *context) {
  transport_poll_host_t *host = context;
  for (size_t i = 0; i < host->socket_count; i++)
    if (transport_udp_gro_pending(host->sockets[i].gro))
      return true;
  return false;
}
static void host_dispose(void *context) {
  transport_poll_host_t *host = context;
  if (host->ifmon_pipe[0] >= 0) {
    ifmon_watch_stop(&host->ifmon_w);
    CLOSE_SOCKET(host->ifmon_pipe[0]);
    CLOSE_SOCKET(host->ifmon_pipe[1]);
  }
  free(host);
}
transport_drive_host_t
transport_poll_host_adapter(transport_poll_host_t *host) {
  return (transport_drive_host_t){.context = host,
                                  .initial_time_ns = host_now(host),
                                  .open = host_open,
                                  .close = host_close,
                                  .send = host_send,
                                  .monotonic_ns = host_now,
                                  .input_pending = host_input_pending};
}
transport_t *transport_create(const transport_config_t *config) {
  if (!config)
    return NULL;
  if (config->drive_host)
    return transport_drive_create(config);
  transport_poll_host_t *host = calloc(1, sizeof(*host));
  if (!host)
    return NULL;
  host->ifmon_pipe[0] = host->ifmon_pipe[1] = -1;
  host->multihome = config->multihome;
  host->log_callback = config->log_callback;
  host->log_user_data = config->log_user_data;
  /* capture interface changes during TLS and path construction */
  if (pipe(host->ifmon_pipe) == 0) {
    if (set_fd_nonblocking(host->ifmon_pipe[0]) &&
        set_fd_nonblocking(host->ifmon_pipe[1]))
      (void)ifmon_watch_start(&host->ifmon_w, on_ifmon_update, host);
    else {
      CLOSE_SOCKET(host->ifmon_pipe[0]);
      CLOSE_SOCKET(host->ifmon_pipe[1]);
      host->ifmon_pipe[0] = host->ifmon_pipe[1] = -1;
    }
  }
  transport_drive_host_t adapter = transport_poll_host_adapter(host);
  transport_config_t driven = *config;
  driven.drive_host = &adapter;
  transport_t *t = transport_drive_create(&driven);
  if (!t) {
    host_dispose(host);
    return NULL;
  }
  host->transport = t;
  t->host_context = host;
  t->host_dispose = host_dispose;
  return t;
}
static bool socket_receive_ready(int fd, const struct pollfd *fds,
                                 size_t count) {
  if (!fds)
    return true;
  for (size_t i = 0; i < count; i++)
    if (fds[i].fd == fd &&
        (fds[i].revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0)
      return true;
  return false;
}
static void receive_packets(transport_t *t, const struct pollfd *fds,
                            size_t count) {
  transport_poll_host_t *host = transport_poll_host(t);
  assert_socket_alignment(t, host);
  size_t receive_budget = t->limits.max_packets_per_tick;
  size_t receive_start =
      t->socket_count ? host->receive_cursor % t->socket_count : 0;
  host->receive_cursor =
      t->socket_count ? (receive_start + 1U) % t->socket_count : 0;
  size_t quantum = t->socket_count ? (receive_budget + t->socket_count - 1U) /
                                         t->socket_count
                                   : 0;
  for (size_t visited = 0; visited < t->socket_count; visited++) {
    size_t fd_idx = (receive_start + visited) % t->socket_count;
    transport_poll_socket_t *socket = &host->sockets[fd_idx];
    if (!transport_udp_gro_pending(socket->gro) &&
        !socket_receive_ready(socket->fd, fds, count))
      continue;
    if (receive_budget == 0) {
      /* earlier sockets consumed this tick's budget; mark remaining ready
       * sockets */
      socket->receive_backlog = true;
      continue;
    }
    size_t serviced = 0;
    while (receive_budget > 0 && serviced < quantum) {
      size_t batch = quantum - serviced;
      if (batch > receive_budget)
        batch = receive_budget;
      if (batch > TRANSPORT_UDP_RECEIVE_BATCH)
        batch = TRANSPORT_UDP_RECEIVE_BATCH;
      ssize_t received;
      bool more;
      if (socket->gro) {
        transport_udp_view_t views[TRANSPORT_UDP_RECEIVE_BATCH];
        received = transport_udp_gro_receive(socket->gro, socket->fd, views,
                                             batch, &more);
        for (ssize_t i = 0; i < received; i++) {
          if (views[i].destination.ss_family == AF_UNSPEC)
            views[i].destination = socket->path.local;
          if (!views[i].dropped)
            transport_drive_receive(t, socket->path.id, views[i].data,
                                    views[i].size, &views[i].source,
                                    &views[i].destination, views[i].ifindex,
                                    views[i].ecn);
        }
      } else {
        transport_udp_datagram_t datagrams[TRANSPORT_UDP_RECEIVE_BATCH];
        received = transport_udp_receive_batch(socket->fd, datagrams, batch);
        for (ssize_t i = 0; i < received; i++) {
          if (datagrams[i].destination.ss_family == AF_UNSPEC)
            datagrams[i].destination = socket->path.local;
          /* preserve recvfrom/recvmmsg copied-prefix dispatch */
          transport_drive_receive(t, socket->path.id, datagrams[i].data,
                                  datagrams[i].size, &datagrams[i].source,
                                  &datagrams[i].destination,
                                  datagrams[i].ifindex, datagrams[i].ecn);
        }
        more = received == (ssize_t)batch;
      }
      if (received <= 0) {
        /* only an actual empty read proves this socket drained */
        if (received == 0)
          socket->receive_backlog = false;
        break; /* empty or persistently failing sockets cannot spin the owner */
      }
      receive_budget -= (size_t)received;
      serviced += (size_t)received;
      if (!more)
        socket->receive_backlog = false;
      else if (receive_budget == 0 || serviced >= quantum)
        socket->receive_backlog = true;
      /* GRO continuation preserves packet quantum after a short logical batch
       */
      if (!more)
        break;
    }
  }
}
static bool service_interfaces(transport_t *t) {
  transport_poll_host_t *host = transport_poll_host(t);
  if (host->ifmon_pipe[0] < 0)
    return false;
  bool consumed = false;
  transport_interface_event_t msg;
  while (read(host->ifmon_pipe[0], &msg, sizeof(msg)) == sizeof(msg)) {
    consumed = true;
    (void)transport_drive_interface(t, msg.is_added, &msg.addr, msg.index,
                                    msg.name);
  }
  return consumed;
}

void transport_tick_ready(transport_t *t, const struct pollfd *fds,
                          size_t count) {
  if (!transport_owner_ok(t))
    return;
  if (t->tick_active || t->turn_active || t->callback_depth) {
    t->stats.recursive_tick_rejections++;
    return;
  }
  transport_poll_host_t *host = transport_poll_host(t);
  if (!host) {
    (void)transport_drive_tick(t, t->drive_now_ns);
    return;
  }
  if (!transport_drive_time(t, host_now(host)) ||
      !transport_engine_begin_turn(t))
    return;
  if (socket_receive_ready(host->ifmon_pipe[0], fds, count) &&
      service_interfaces(t))
    fds = NULL;
  receive_packets(t, fds, count);
  transport_engine_end_turn(t);
}
void transport_tick(transport_t *t) {
  transport_tick_ready(t, NULL, 0);
}
int transport_enable_qlog(const char *socket_path) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    CLOSE_SOCKET(fd);
    return -1;
  }

  /* set non-blocking to prevent logging from hanging the main transport thread
   */
  if (!set_fd_nonblocking(fd)) {
    CLOSE_SOCKET(fd);
    return -1;
  }

  /* enable picotls and quicly tracing, sample ratio 1.0 (all logs), write to fd
   */
  ptls_log_add_fd(fd, 1.0, NULL, NULL, NULL, 0);
  ptls_log_add_fd(fd, 1.0, NULL, NULL, NULL, 1);
  return 0;
}
size_t transport_get_poll_fds(transport_t *t, struct pollfd *fds,
                              size_t max_fds) {
  transport_poll_host_t *host = transport_poll_host(t);
  if (!transport_owner_ok(t) || !fds || !host)
    return 0;
  assert_socket_alignment(t, host);

  size_t count = 0;
  for (size_t i = 0; i < t->socket_count && count < max_fds; i++) {
    if (host->sockets[i].fd >= 0) {
      fds[count].fd = host->sockets[i].fd;
      fds[count].events = POLLIN;
      if (t->sockets[i].egress.count > 0)
        fds[count].events |= POLLOUT;
      fds[count].revents = 0;
      count++;
    }
  }
  if (host->ifmon_pipe[0] >= 0 && count < max_fds) {
    fds[count++] = (struct pollfd){.fd = host->ifmon_pipe[0], .events = POLLIN};
  }
  return count;
}
bool transport_rx_cadence_mask(transport_t *t, struct pollfd *fds,
                               size_t count) {
  transport_poll_host_t *host = transport_poll_host(t);
  if (!host || !transport_owner_ok(t) || t->turn_active || !fds ||
      t->tick_active || t->shutting_down || t->reconnect_in_progress ||
      t->pending_group.size || t->socket_count == 0 ||
      transport_connection_count(t) != 1)
    return false;
  assert_socket_alignment(t, host);
  transport_conn_t *conn = transport_connection_at(t, 0);
  if (!conn || !conn->quic || !conn->authenticated || !conn->protocol_ready ||
      !conn->quic_ready || !quicly_connection_is_ready(conn->quic) ||
      quicly_has_pending_stream_data(conn->quic) ||
      quicly_has_datagram_frames(conn->quic) ||
      quicly_get_state(conn->quic) != QUICLY_STATE_CONNECTED ||
      transport_subscriptions_count(&conn->send_subscriptions) != 0 ||
      transport_subscriptions_count(&conn->receive_subscriptions) == 0)
    return false;

  if (!conn->rx_cadence_handshake_confirmed) {
    quicly_stats_t stats;
    if (quicly_get_stats(conn->quic, &stats) != 0 ||
        stats.handshake_confirmed_msec == UINT64_MAX)
      return false;
    conn->rx_cadence_handshake_confirmed = true;
  }

  /* validate before mutating any mask; reject stale or recycled fd snapshots */
  size_t slot = 0;
  for (size_t i = 0; i < t->socket_count; i++) {
    transport_local_path_t *path = &t->sockets[i];
    transport_poll_socket_t *socket = &host->sockets[i];
    if (path->egress.count || path->open_pending || socket->receive_backlog ||
        transport_udp_gro_pending(socket->gro))
      return false;
    if (socket->fd < 0)
      continue;
    if (slot >= count || fds[slot].fd != socket->fd ||
        fds[slot].events != POLLIN || fds[slot].revents != 0)
      return false;
    slot++;
  }
  size_t udp_count = slot;
  if (host->ifmon_pipe[0] >= 0) {
    if (slot >= count || fds[slot].fd != host->ifmon_pipe[0] ||
        fds[slot].events != POLLIN || fds[slot].revents != 0)
      return false;
    slot++;
  }
  if (!udp_count || slot != count)
    return false;
  for (size_t i = 0; i < udp_count; i++)
    fds[i].events &= (short)~POLLIN;
  return true;
}
static void transport_mock_iface_change(transport_t *t, const char *ip_addr,
                                        bool added) {
  transport_poll_host_t *host = transport_poll_host(t);
  if (!transport_owner_ok(t) || !host || host->ifmon_pipe[1] < 0)
    return;

  transport_interface_event_t msg = {0};
  msg.is_added = added ? 1 : 0;
  msg.index = 1; /* loopback interface index */
  struct sockaddr_in *sin = (struct sockaddr_in *)&msg.addr;
  sin->sin_family = AF_INET;
  if (!ip_addr || inet_pton(AF_INET, ip_addr, &sin->sin_addr) != 1)
    return;
  msg.addr_len = sizeof(*sin);

  ssize_t w = write(host->ifmon_pipe[1], &msg, sizeof(msg));
  (void)w;
}
void transport_mock_iface_add(transport_t *t, const char *ip_addr) {
  transport_mock_iface_change(t, ip_addr, true);
}
void transport_mock_iface_remove(transport_t *t, const char *ip_addr) {
  transport_mock_iface_change(t, ip_addr, false);
}
