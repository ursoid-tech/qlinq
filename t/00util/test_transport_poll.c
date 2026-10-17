#include "transport_internal.h"
#include "portable_sockets.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Exercise real nonblocking UDP queues through the production tick. A one-byte
 * truncated QUIC header is sufficient to observe receipt without a peer or
 * timers for handshake completion. No production operation is intercepted. */
typedef struct {
  transport_t transport;
  int sender;
  bool inject_added_socket;
  size_t added_socket_injections;
} fixture_t;

static void enqueue(fixture_t *f, size_t socket_index, size_t count) {
  struct sockaddr_storage address;
  socklen_t length = sizeof(address);
  assert(getsockname(f->transport.sockets[socket_index].fd,
                     (struct sockaddr *)&address, &length) == 0);
  const uint8_t truncated_header = 0xc0;
  for (size_t i = 0; i < count; i++)
    assert(sendto(f->sender, &truncated_header, sizeof(truncated_header), 0,
                  (struct sockaddr *)&address, length) == 1);
}

static void log_event(void *data, const transport_log_event_t *event) {
  fixture_t *f = data;
  if (f->inject_added_socket && strcmp(event->component, "ifmon") == 0 &&
      strncmp(event->message, "opened socket", 13) == 0) {
    /* Send from the external fixture socket after the real replacement bind,
     * before the same tick receives. The log callback calls no transport API.
     */
    enqueue(f, event->path_index, 1);
    f->added_socket_injections++;
  }
}

static void init_fixture(fixture_t *f) {
  memset(f, 0, sizeof(*f));
  transport_t *t = &f->transport;
  t->owner_thread = pthread_self();
  t->is_server = true;
  t->shutting_down = true; /* Invalid input must not create a QUIC peer. */
  t->limits.max_packets_per_tick = 8;
  t->limits.max_egress_packets_per_socket = 64;
  t->limits.max_egress_bytes_per_socket = 65536;
  t->limits.max_aggregate_nack_requests_per_second = 16;
  t->log_callback = log_event;
  t->log_user_data = f;
  f->sender = socket(AF_INET, SOCK_DGRAM, 0);
  assert(f->sender >= 0);
  for (size_t i = 0; i < 2; i++) {
    transport_socket_t *bound = &t->sockets[i];
    bound->fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(bound->fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET};
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(bound->fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    bound->local_addr_len = sizeof(bound->local_addr);
    assert(getsockname(bound->fd, (struct sockaddr *)&bound->local_addr,
                       &bound->local_addr_len) == 0);
    int flags = fcntl(bound->fd, F_GETFL, 0);
    assert(flags >= 0 && fcntl(bound->fd, F_SETFL, flags | O_NONBLOCK) == 0);
    assert(transport_egress_init(&bound->egress, 64, 65536));
    t->socket_count++;
  }
  assert(pipe(t->ifmon_pipe) == 0);
  int flags = fcntl(t->ifmon_pipe[0], F_GETFL, 0);
  assert(flags >= 0 &&
         fcntl(t->ifmon_pipe[0], F_SETFL, flags | O_NONBLOCK) == 0);
}

static void destroy_fixture(fixture_t *f) {
  for (size_t i = 0; i < f->transport.socket_count; i++) {
    transport_udp_gro_destroy(f->transport.sockets[i].gro);
    close(f->transport.sockets[i].fd);
    transport_egress_destroy(&f->transport.sockets[i].egress);
  }
  close(f->transport.ifmon_pipe[0]);
  close(f->transport.ifmon_pipe[1]);
  close(f->sender);
}

static void ready_filter(void) {
  fixture_t f;
  init_fixture(&f);
  transport_t *t = &f.transport;
  struct pollfd fds[TRANSPORT_MAX_POLL_FDS];
  size_t count = transport_get_poll_fds(t, fds, TRANSPORT_MAX_POLL_FDS);
  assert(count == 3);
  enqueue(&f, 0, 1);
  enqueue(&f, 1, 1);
  size_t cursor = t->receive_cursor;
  transport_tick_ready(t, fds, count); /* A timeout snapshot has no revents. */
  assert(t->sockets[0].bytes_received == 0 &&
         t->sockets[1].bytes_received == 0);
  assert(t->receive_cursor == (cursor + 1U) % t->socket_count);
  assert(t->last_pathflow_update != 0); /* Maintenance still ran. */

  fds[0].revents = POLLIN;
  fds[1].revents = POLLOUT; /* Send readiness must not imply input. */
  transport_tick_ready(t, fds, count);
  assert(t->sockets[0].bytes_received == 1 &&
         t->sockets[1].bytes_received == 0);
  count = transport_get_poll_fds(t, fds, TRANSPORT_MAX_POLL_FDS);
  assert(poll(fds, count, 0) == 1 && (fds[1].revents & POLLIN));
  transport_tick_ready(t, fds, count); /* Level polling finds deferred input. */
  assert(t->sockets[0].bytes_received == 1 &&
         t->sockets[1].bytes_received == 1);

  enqueue(&f, 0, 1);
  enqueue(&f, 1, 1);
  transport_tick(t); /* Direct callers retain a full scan. */
  assert(t->sockets[0].bytes_received == 2 &&
         t->sockets[1].bytes_received == 2);

  /* Filtering does not give a lone ready socket another socket's quantum. */
  t->limits.max_packets_per_tick = 2;
  enqueue(&f, 0, 3);
  count = transport_get_poll_fds(t, fds, TRANSPORT_MAX_POLL_FDS);
  assert(poll(fds, count, 0) == 1);
  transport_tick_ready(t, fds, count);
  assert(t->sockets[0].bytes_received == 3);
  enqueue(&f, 1, 2);
  count = transport_get_poll_fds(t, fds, TRANSPORT_MAX_POLL_FDS);
  assert(poll(fds, count, 0) == 2);
  transport_tick_ready(t, fds, count);
  assert(t->sockets[0].bytes_received == 4 &&
         t->sockets[1].bytes_received == 3);
  transport_tick(t);
  assert(t->sockets[0].bytes_received == 5 &&
         t->sockets[1].bytes_received == 4);
  const short errors[] = {POLLERR, POLLHUP, POLLNVAL};
  for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
    enqueue(&f, 0, 1);
    count = transport_get_poll_fds(t, fds, TRANSPORT_MAX_POLL_FDS);
    fds[0].revents = errors[i];
    transport_tick_ready(t, fds, count);
    assert(t->sockets[0].bytes_received == 6 + i);
  }
  destroy_fixture(&f);
}

#ifdef __linux__
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif

static bool enable_gro(fixture_t *f) {
  for (size_t i = 0; i < f->transport.socket_count; i++) {
    transport_socket_t *socket = &f->transport.sockets[i];
    socket->gro = transport_udp_gro_create(socket->fd);
    if (!socket->gro) {
      puts("UDP_GRO unavailable; buffered receive integration skipped");
      return false;
    }
  }
  return true;
}

static void enqueue_gso(fixture_t *f, size_t socket_index) {
  uint8_t payload[6 * 1280];
  memset(payload, 0xc0, sizeof(payload));
  struct iovec iov = {.iov_base = payload, .iov_len = sizeof(payload)};
  union {
    struct cmsghdr alignment;
    uint8_t bytes[CMSG_SPACE(sizeof(uint16_t))];
  } control = {0};
  transport_socket_t *socket = &f->transport.sockets[socket_index];
  struct msghdr message = {.msg_name = &socket->local_addr,
                           .msg_namelen = socket->local_addr_len,
                           .msg_iov = &iov,
                           .msg_iovlen = 1,
                           .msg_control = control.bytes,
                           .msg_controllen = sizeof(control.bytes)};
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
  cmsg->cmsg_level = IPPROTO_UDP;
  cmsg->cmsg_type = UDP_SEGMENT;
  cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
  uint16_t segment_size = 1280;
  memcpy(CMSG_DATA(cmsg), &segment_size, sizeof(segment_size));
  assert(sendmsg(f->sender, &message, 0) == (ssize_t)sizeof(payload));
}

static void gro_buffered_input(void) {
  fixture_t f;
  init_fixture(&f);
  if (!enable_gro(&f)) {
    destroy_fixture(&f);
    return;
  }
  transport_t *t = &f.transport;
  t->limits.max_packets_per_tick = 2; /* One logical datagram per socket. */
  enqueue_gso(&f, 0);
  enqueue_gso(&f, 1);
  transport_tick(t);
  assert(t->sockets[0].bytes_received == 1280 &&
         t->sockets[1].bytes_received == 1280);
  assert(transport_udp_gro_pending(t->sockets[0].gro) &&
         transport_udp_gro_pending(t->sockets[1].gro));
  assert(transport_get_first_timeout(t) == 0);
  struct pollfd fds[TRANSPORT_MAX_POLL_FDS];
  size_t count = transport_get_poll_fds(t, fds, TRANSPORT_MAX_POLL_FDS);
  assert(poll(fds, count, 0) == 0); /* Input now lives only in userspace. */

  /* A one-packet total budget rotates fairly over both buffered sockets,
   * despite a poll snapshot with no readable descriptors. */
  t->limits.max_packets_per_tick = 1;
  transport_tick_ready(t, fds, count);
  assert(t->sockets[0].bytes_received == 1280 &&
         t->sockets[1].bytes_received == 2560);
  transport_tick_ready(t, fds, count);
  assert(t->sockets[0].bytes_received == 2560 &&
         t->sockets[1].bytes_received == 2560);
  t->limits.max_packets_per_tick = 2;
  transport_tick(t); /* Direct full scans consume the same logical quantum. */
  for (size_t i = 0; i < 3; i++) {
    assert(transport_get_first_timeout(t) == 0);
    transport_tick_ready(t, fds, count);
  }
  assert(t->sockets[0].bytes_received == 6 * 1280 &&
         t->sockets[1].bytes_received == 6 * 1280);
  assert(!transport_udp_gro_pending(t->sockets[0].gro) &&
         !transport_udp_gro_pending(t->sockets[1].gro));
  assert(transport_get_first_timeout(t) == INT64_MAX);

  /* Four ordinary messages fill the raw receive batch but are fewer than
   * this socket's quantum. The fifth must be consumed in the same tick. */
  t->limits.max_packets_per_tick = 32;
  enqueue(&f, 0, 5);
  transport_tick(t);
  assert(t->sockets[0].bytes_received == 6 * 1280 + 5);
  count = transport_get_poll_fds(t, fds, TRANSPORT_MAX_POLL_FDS);
  assert(poll(fds, count, 0) == 0);
  destroy_fixture(&f);
}

static void gro_interface_compaction(void) {
  fixture_t f;
  init_fixture(&f);
  if (!enable_gro(&f)) {
    destroy_fixture(&f);
    return;
  }
  transport_t *t = &f.transport;
  t->limits.max_packets_per_tick = 2;
  enqueue_gso(&f, 0);
  enqueue_gso(&f, 1);
  transport_tick(t);
  transport_udp_gro_t *retained = t->sockets[1].gro;
  int retained_fd = t->sockets[1].fd;
  int removed_fd = t->sockets[0].fd;
  struct pollfd stale[TRANSPORT_MAX_POLL_FDS];
  size_t count = transport_get_poll_fds(t, stale, TRANSPORT_MAX_POLL_FDS);
  assert(poll(stale, count, 0) == 0);
  transport_mock_iface_remove(t, "127.0.0.1");
  transport_mock_iface_add(t, "127.0.0.3");
  f.inject_added_socket = true;
  stale[count - 1].revents = POLLOUT; /* Unrelated readiness must not read. */
  transport_tick_ready(t, stale, count);
  /* The new pipe input was absent from this snapshot. Buffered GRO remains
   * serviceable on both original sockets while interface handling waits. */
  assert(t->socket_count == 2 && t->sockets[0].fd == removed_fd &&
         t->sockets[1].fd == retained_fd && t->sockets[1].gro == retained);
  assert(t->sockets[0].bytes_received == 2 * 1280 &&
         t->sockets[1].bytes_received == 2 * 1280 &&
         f.added_socket_injections == 0);
  count = transport_get_poll_fds(t, stale, TRANSPORT_MAX_POLL_FDS);
  assert(poll(stale, count, 0) == 1 && (stale[count - 1].revents & POLLIN));
  transport_tick_ready(t, stale, count);
  assert(t->socket_count == 2 && t->sockets[0].fd == retained_fd &&
         t->sockets[0].gro == retained && t->sockets[1].fd == removed_fd);
  assert(t->sockets[0].bytes_received == 3 * 1280 &&
         t->sockets[1].bytes_received == 1 && f.added_socket_injections == 1);
  t->limits.max_packets_per_tick = 32;
  transport_tick(t);
  assert(t->sockets[0].bytes_received == 6 * 1280 &&
         t->sockets[1].bytes_received == 1);
  assert(!transport_udp_gro_pending(t->sockets[0].gro));
  destroy_fixture(&f);
}

/* Linux treats the whole 127/8 range as loopback and allocates the lowest free
 * descriptor. Other platforms still exercise filtering/fairness above. */
static void interface_invalidation(void) {
  fixture_t f;
  init_fixture(&f);
  transport_t *t = &f.transport;
  struct pollfd stale[TRANSPORT_MAX_POLL_FDS];
  size_t count = transport_get_poll_fds(t, stale, TRANSPORT_MAX_POLL_FDS);
  int removed_fd = t->sockets[0].fd;
  int retained_fd = t->sockets[1].fd;
  enqueue(&f, 1, 1);
  /* These messages arrive after the poll snapshot. Removal compacts slots;
   * the new socket can reuse the old descriptor, whose snapshot is not ready.
   */
  transport_mock_iface_remove(t, "127.0.0.1");
  transport_mock_iface_add(t, "127.0.0.3");
  f.inject_added_socket = true;
  transport_tick_ready(t, stale, count);
  assert(t->socket_count == 2 && t->sockets[0].fd == removed_fd &&
         t->sockets[1].fd == retained_fd && f.added_socket_injections == 0);
  assert(t->sockets[0].bytes_received == 0 &&
         t->sockets[1].bytes_received == 0);
  count = transport_get_poll_fds(t, stale, TRANSPORT_MAX_POLL_FDS);
  assert(poll(stale, count, 0) == 2 && (stale[count - 1].revents & POLLIN));
  transport_tick_ready(t, stale, count);
  assert(t->socket_count == 2 && t->sockets[0].fd == retained_fd);
  assert(f.added_socket_injections == 1 && t->sockets[0].bytes_received == 1 &&
         t->sockets[1].bytes_received == 1);
  assert(t->sockets[1].fd == removed_fd);
  /* A deferred no-op message also remains pollable. Once consumed, it forces
   * a full scan that finds UDP input arriving after that second snapshot. */
  count = transport_get_poll_fds(t, stale, TRANSPORT_MAX_POLL_FDS);
  transport_mock_iface_add(t, "127.0.0.3");
  transport_tick_ready(t, stale, count);
  assert(f.added_socket_injections == 1 && t->sockets[0].bytes_received == 1);
  count = transport_get_poll_fds(t, stale, TRANSPORT_MAX_POLL_FDS);
  assert(poll(stale, count, 0) == 1 && (stale[count - 1].revents & POLLIN));
  enqueue(&f, 0, 1);
  transport_tick_ready(t, stale, count);
  assert(f.added_socket_injections == 1 && t->sockets[0].bytes_received == 2);

  /* NULL/direct ticks continue to consume interface and UDP input immediately.
   */
  transport_mock_iface_remove(t, "127.0.0.3");
  transport_mock_iface_add(t, "127.0.0.4");
  enqueue(&f, 0, 1);
  transport_tick(t);
  assert(t->socket_count == 2 && f.added_socket_injections == 2 &&
         t->sockets[0].fd == retained_fd && t->sockets[1].fd == removed_fd);
  assert(t->sockets[0].bytes_received == 3 &&
         t->sockets[1].bytes_received == 1);

  /* Pipe error/hangup readiness uses the same read attempt as POLLIN. */
  const short errors[] = {POLLERR, POLLHUP, POLLNVAL};
  for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
    count = transport_get_poll_fds(t, stale, TRANSPORT_MAX_POLL_FDS);
    transport_mock_iface_add(t, "127.0.0.4"); /* Consumed no-op. */
    stale[count - 1].revents = errors[i];
    enqueue(&f, 0, 1);
    transport_tick_ready(t, stale, count);
    assert(t->sockets[0].bytes_received == 4 + i);
    count = transport_get_poll_fds(t, stale, TRANSPORT_MAX_POLL_FDS);
    assert(poll(stale, count, 0) == 0);
  }
  destroy_fixture(&f);
}
#endif

int main(void) {
  ready_filter();
#ifdef __linux__
  gro_buffered_input();
  gro_interface_compaction();
  interface_invalidation();
#endif
  puts("===TRANSPORT POLL OK===");
  return 0;
}
