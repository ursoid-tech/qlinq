/* default socket host for the explicit transport engine boundary */
#include "transport_poll_host.h"
#include "transport_flexicast.h"
#include "transport_protocol.h"
extern const transport_flexicast_io_t transport_poll_flexicast_io;
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
static bool host_iface_allowed(const transport_poll_host_t *t,
                               const char *name) {
  return t->custom_iface_filter || ifmon_is_default_iface(name);
}

/* the pipe only wakes the owner. snapshot-sized batches avoid losing later
 * candidates when discovery produces more events than the pipe can hold. */
struct transport_interface_batch {
  transport_interface_batch_t *next;
  size_t count, capacity;
  bool filter_discovery;
  transport_interface_event_t events[];
};

static bool append_interface_event(transport_interface_batch_t **batch,
                                   const transport_interface_event_t *event) {
  if (!*batch || (*batch)->count == (*batch)->capacity) {
    bool initial = *batch == NULL;
    size_t capacity = *batch ? (*batch)->capacity : 8;
    if (capacity > (SIZE_MAX - sizeof(**batch)) / 2 / sizeof(*event))
      return false;
    capacity *= 2;
    transport_interface_batch_t *grown =
        realloc(*batch, sizeof(**batch) + capacity * sizeof(*event));
    if (!grown)
      return false;
    if (initial)
      *grown = (transport_interface_batch_t){0};
    grown->capacity = capacity;
    *batch = grown;
  }
  (*batch)->events[(*batch)->count++] = *event;
  return true;
}

static void queue_interface_batch(transport_poll_host_t *host,
                                  transport_interface_batch_t *batch) {
  if (!batch)
    return;
  transport_interface_batch_t *head =
      atomic_load_explicit(&host->interface_updates, memory_order_relaxed);
  do {
    batch->next = head;
  } while (!atomic_compare_exchange_weak_explicit(
      &host->interface_updates, &head, batch, memory_order_release,
      memory_order_relaxed));
  if (!head) {
    char wake = 1;
    ssize_t written;
    do {
      written = write(host->ifmon_pipe[1], &wake, sizeof(wake));
    } while (written < 0 && errno == EINTR);
    /* EAGAIN means an existing wake already makes the descriptor readable */
  }
}

static bool append_interface_address(transport_interface_batch_t **batch,
                                     const ifmon_iface_t *iface,
                                     const ifmon_addr_t *address, bool added) {
  transport_interface_event_t msg = {.index = iface->index, .is_added = added};
  copy_interface_name(msg.name, iface->name);
  msg.addr_len = ifmon_socket_address(&msg.addr, address, msg.index);
  return append_interface_event(batch, &msg);
}

static void on_ifmon_update(const ifmon_update_t *update, void *userdata) {
  transport_poll_host_t *host = userdata;
  transport_interface_batch_t *batch = NULL;

  if (update->is_initial) {
    if (!host->multihome)
      return;
    for (int j = 0; j < update->interfaces->count; j++) {
      const ifmon_iface_t *iface = &update->interfaces->ifaces[j];
      if (!iface->is_up)
        continue;
      for (int k = 0; k < iface->addr_count; k++)
        if (!append_interface_address(&batch, iface, &iface->addrs[k], true))
          goto Fail;
    }
    goto Queue;
  }

  /* retire old addresses before additions so replacements can reuse slots */
  for (int i = 0; i < update->removed_count; i++) {
    transport_interface_event_t msg = {.index = update->removed[i]};
    msg.addr.ss_family = AF_UNSPEC;
    if (!append_interface_event(&batch, &msg))
      goto Fail;
  }
  for (int i = 0; i < update->modified_count; i++) {
    const ifmon_iface_diff_t *diff = &update->modified[i];
    ifmon_iface_t iface = {.index = diff->index};
    for (int j = 0; j < update->interfaces->count; j++)
      if (update->interfaces->ifaces[j].index == diff->index) {
        iface = update->interfaces->ifaces[j];
        break;
      }
    if (diff->link_state_changed && !diff->is_up) {
      transport_interface_event_t msg = {.index = diff->index};
      msg.addr.ss_family = AF_UNSPEC;
      if (!append_interface_event(&batch, &msg))
        goto Fail;
    }
    for (int j = 0; j < diff->addrs_removed_count; j++)
      if (!append_interface_address(&batch, &iface, &diff->addrs_removed[j],
                                    false))
        goto Fail;
  }

  for (int i = 0; i < update->added_count; i++) {
    for (int j = 0; j < update->interfaces->count; j++) {
      const ifmon_iface_t *iface = &update->interfaces->ifaces[j];
      if (iface->index != update->added[i] || !iface->is_up)
        continue;
      for (int k = 0; k < iface->addr_count; k++)
        if (!append_interface_address(&batch, iface, &iface->addrs[k], true))
          goto Fail;
      break;
    }
  }
  for (int i = 0; i < update->modified_count; i++) {
    const ifmon_iface_diff_t *diff = &update->modified[i];
    for (int j = 0; j < update->interfaces->count; j++) {
      const ifmon_iface_t *iface = &update->interfaces->ifaces[j];
      if (iface->index != diff->index || !iface->is_up)
        continue;
      const ifmon_addr_t *addrs =
          diff->link_state_changed ? iface->addrs : diff->addrs_added;
      int count = diff->link_state_changed ? iface->addr_count
                                           : diff->addrs_added_count;
      for (int k = 0; k < count; k++)
        if (!append_interface_address(&batch, iface, &addrs[k], true))
          goto Fail;
      break;
    }
  }
Queue:
  if (batch) {
    batch->filter_discovery = true;
    queue_interface_batch(host, batch);
  }
  return;
Fail:
  free(batch);
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
  if (ifmon_list_get(&list, scratch, sizeof(scratch))) {
    ifmon_list_dispose(&list);
    return;
  }
  for (int i = 0; i < list.count; i++)
    for (int a = 0; a < list.ifaces[i].addr_count; a++) {
      struct sockaddr_storage address;
      ifmon_socket_address(&address, &list.ifaces[i].addrs[a],
                           list.ifaces[i].index);
      if (transport_address_equal((struct sockaddr *)&address,
                                  (struct sockaddr *)&path->local)) {
        path->interface_index = list.ifaces[i].index;
        copy_interface_name(path->interface_name, list.ifaces[i].name);
        ifmon_list_dispose(&list);
        return;
      }
    }
  ifmon_list_dispose(&list);
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
  transport_interface_batch_t *batch =
      atomic_load_explicit(&host->interface_updates, memory_order_relaxed);
  while (batch) {
    transport_interface_batch_t *next = batch->next;
    free(batch);
    batch = next;
  }
  free(host);
}
transport_drive_host_t
transport_poll_host_adapter(transport_poll_host_t *host) {
  return (transport_drive_host_t){.context = host,
                                  .flexicast_io = &transport_poll_flexicast_io,
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
  atomic_init(&host->interface_updates, NULL);
  host->multihome = config->multihome;
  host->custom_iface_filter = config->interface_callback != NULL ||
                              config->num_path_interface_names > 0;
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
  size_t multicast_budget = (receive_budget + 1U) / 2U;
  for (size_t slot = 0; t->flexicast_enabled && slot < 2 && multicast_budget;
       slot++) {
    if (t->flexicast_fds[slot] < 0 ||
        !socket_receive_ready(t->flexicast_fds[slot], fds, count))
      continue;
    while (t->flexicast_fds[slot] >= 0 && multicast_budget) {
      uint8_t packet[2048];
      transport_conn_t *source = NULL;
      ptls_iovec_t payload = ptls_iovec_init(NULL, 0);
      ssize_t received = transport_flexicast_receive_native(
          t, slot, packet, sizeof(packet), &source, &payload);
      if (received < 0) {
        if (errno == EINTR)
          continue;
        break;
      }
      --receive_budget;
      --multicast_budget;
      if (source && payload.base) {
        if (source->authenticated &&
            transport_simulated_loss(t, t->simulated_loss_rate))
          continue;
        transport_protocol_receive_datagram(source, payload, false);
      }
    }
  }

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
  char wake[64];
  ssize_t received;
  do {
    received = read(host->ifmon_pipe[0], wake, sizeof(wake));
  } while (received > 0 || (received < 0 && errno == EINTR));
  transport_interface_batch_t *pending = atomic_exchange_explicit(
      &host->interface_updates, NULL, memory_order_acquire);
  bool consumed = pending != NULL;
  transport_interface_batch_t *ordered = NULL;
  while (pending) {
    transport_interface_batch_t *next = pending->next;
    pending->next = ordered;
    ordered = pending;
    pending = next;
  }
  while (ordered) {
    transport_interface_batch_t *next = ordered->next;
    for (size_t i = 0; i < ordered->count; i++) {
      const transport_interface_event_t *msg = &ordered->events[i];
      if (msg->is_added && ordered->filter_discovery &&
          !host_iface_allowed(host, msg->name) &&
          !transport_is_configured_address(t, &msg->addr))
        continue;
      (void)transport_drive_interface(t, msg->is_added, &msg->addr, msg->index,
                                      msg->name);
    }
    free(ordered);
    ordered = next;
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
  struct sockaddr_un addr;
  if (!socket_path || strlen(socket_path) >= sizeof(addr.sun_path))
    return -1;

  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  memcpy(addr.sun_path, socket_path, strlen(socket_path) + 1);

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

  int quicly_fd = dup(fd);
  if (quicly_fd < 0 || !set_fd_nonblocking(quicly_fd)) {
    if (quicly_fd >= 0)
      CLOSE_SOCKET(quicly_fd);
    CLOSE_SOCKET(fd);
    return -1;
  }

  /* enable picotls and quicly tracing, sample ratio 1.0 (all logs), write to fd
   */
  if (ptls_log_add_fd(fd, 1.0, NULL, NULL, NULL, 0) != 0) {
    CLOSE_SOCKET(quicly_fd);
    CLOSE_SOCKET(fd);
    return -1;
  }
  if (ptls_log_add_fd(quicly_fd, 1.0, NULL, NULL, NULL, 1) != 0) {
    CLOSE_SOCKET(quicly_fd);
    return -1;
  }
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
  for (size_t i = 0; t->flexicast_enabled && i < 2 && count < max_fds; i++)
    if (t->flexicast_fds[i] >= 0)
      fds[count++] =
          (struct pollfd){.fd = t->flexicast_fds[i], .events = POLLIN};
  if (host->ifmon_pipe[0] >= 0 && count < max_fds) {
    fds[count++] = (struct pollfd){.fd = host->ifmon_pipe[0], .events = POLLIN};
  }
  return count;
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

  transport_interface_batch_t *batch = NULL;
  if (append_interface_event(&batch, &msg))
    queue_interface_batch(host, batch);
  else
    free(batch);
}
void transport_mock_iface_add(transport_t *t, const char *ip_addr) {
  transport_mock_iface_change(t, ip_addr, true);
}
void transport_mock_iface_remove(transport_t *t, const char *ip_addr) {
  transport_mock_iface_change(t, ip_addr, false);
}
