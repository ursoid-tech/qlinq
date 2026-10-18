/* Reuse the established real-socket fixture, not a model of receive_packets.
 * The renamed main is not run; the tests below add backlog lifetime assertions.
 */
#define main existing_transport_poll_main
#include "test_transport_poll.c"
#undef main

static size_t snapshot(fixture_t *f, struct pollfd *fds, bool ready) {
  size_t count =
      transport_get_poll_fds(&f->transport, fds, TRANSPORT_MAX_POLL_FDS);
  if (ready)
    assert(poll(fds, count, 0) >= 0);
  return count;
}

static void quantum_and_native_only(void) {
  fixture_t f;
  init_fixture(&f);
  transport_t *t = &f.transport;
  struct pollfd fds[TRANSPORT_MAX_POLL_FDS];
  enqueue(&f, 0, 5); /* Socket quantum is four. */
  enqueue(&f, 1, 2);
  size_t count = snapshot(&f, fds, true);
  transport_tick_ready(t, fds, count);
  assert(t->sockets[0].bytes_received == 4 && t->sockets[0].receive_backlog);
  assert(t->sockets[1].bytes_received == 2 && !t->sockets[1].receive_backlog);

  count = snapshot(&f, fds, false);
  transport_tick_ready(t, fds, count); /* No actual read: retain the flag. */
  assert(t->sockets[0].bytes_received == 4 && t->sockets[0].receive_backlog);
  enqueue(&f, 1, 1);
  fds[1].revents = POLLIN;
  transport_tick_ready(t, fds,
                       count); /* Draining another socket is insufficient. */
  assert(t->sockets[0].receive_backlog && t->sockets[1].bytes_received == 3);
  fds[1].revents = 0;
  fds[0].revents = POLLIN;
  transport_tick_ready(t, fds, count);
  assert(t->sockets[0].bytes_received == 5 && !t->sockets[0].receive_backlog);

  /* An exact quantum has no drain proof, even when the kernel queue is empty.
   * A subsequent native-only tick must not invent that proof. */
  enqueue(&f, 0, 4);
  transport_tick_ready(t, fds, count);
  assert(t->sockets[0].receive_backlog);
  count = snapshot(&f, fds, true);
  assert(fds[0].revents == 0);
  transport_tick_ready(t, fds, count);
  assert(t->sockets[0].receive_backlog);
  transport_tick(t); /* Actual nonblocking empty read clears it. */
  assert(!t->sockets[0].receive_backlog);
  destroy_fixture(&f);
}

static void global_budget_fairness(void) {
  fixture_t f;
  init_fixture(&f);
  transport_t *t = &f.transport;
  t->limits.max_packets_per_tick = 1;
  enqueue(&f, 0, 2);
  enqueue(&f, 1, 2);
  for (unsigned turn = 0; turn < 4; turn++) {
    struct pollfd fds[TRANSPORT_MAX_POLL_FDS];
    size_t count = snapshot(&f, fds, true);
    transport_tick_ready(t, fds, count);
    assert(t->sockets[0].bytes_received == (turn + 2U) / 2U);
    assert(t->sockets[1].bytes_received == (turn + 1U) / 2U);
    assert(t->sockets[turn % 2U].receive_backlog);
  }
  t->limits.max_packets_per_tick = 8;
  transport_tick(t);
  assert(!t->sockets[0].receive_backlog && !t->sockets[1].receive_backlog);
  destroy_fixture(&f);
}

#ifdef __linux__
static void gro_budget_skipped_socket(void) {
  fixture_t f;
  init_fixture(&f);
  transport_t *t = &f.transport;
  assert(enable_gro(&f));
  t->limits.max_packets_per_tick = 1;
  /* Each raw refill contains one complete ordinary datagram, so consuming
   * socket zero returns !more despite using the entire global budget. */
  enqueue(&f, 0, 1);
  enqueue(&f, 1, 1);
  struct pollfd fds[TRANSPORT_MAX_POLL_FDS];
  size_t count = snapshot(&f, fds, true);
  assert((fds[0].revents & POLLIN) && (fds[1].revents & POLLIN));
  transport_tick_ready(t, fds, count);
  assert(t->sockets[0].bytes_received == 1 && !t->sockets[0].receive_backlog);
  assert(!transport_udp_gro_pending(t->sockets[0].gro));
  assert(t->sockets[1].bytes_received == 0 && t->sockets[1].receive_backlog);

  count = snapshot(&f, fds, false);
  transport_tick_ready(t, fds,
                       count); /* Native-only service cannot clear it. */
  assert(t->sockets[1].bytes_received == 0 && t->sockets[1].receive_backlog);
  count = snapshot(&f, fds, true);
  assert(fds[1].revents & POLLIN);
  transport_tick_ready(t, fds, count);
  assert(t->sockets[1].bytes_received == 1 && !t->sockets[1].receive_backlog);
  assert(!t->sockets[0].receive_backlog);
  destroy_fixture(&f);
}

static void gro_and_socket_lifetime(void) {
  fixture_t f;
  init_fixture(&f);
  transport_t *t = &f.transport;
  /* This Linux correctness target requires GRO support. A missing capability
   * is a test failure, not a silently successful coverage claim. */
  assert(enable_gro(&f));
  t->limits.max_packets_per_tick = 2;
  enqueue_gso(&f, 0);
  enqueue_gso(&f, 1);
  transport_tick(t);
  assert(t->sockets[0].receive_backlog && t->sockets[1].receive_backlog);
  assert(transport_udp_gro_pending(t->sockets[0].gro) &&
         transport_udp_gro_pending(t->sockets[1].gro));
  struct pollfd fds[TRANSPORT_MAX_POLL_FDS];
  size_t count = snapshot(&f, fds, true);
  assert(fds[0].revents == 0 && fds[1].revents == 0);
  transport_tick_ready(t, fds,
                       count); /* Pending userspace input remains runnable. */
  assert(t->sockets[0].bytes_received == 2 * 1280 &&
         t->sockets[1].bytes_received == 2 * 1280);
  assert(t->sockets[0].receive_backlog && t->sockets[1].receive_backlog);

  int old_fd = t->sockets[0].fd, retained_fd = t->sockets[1].fd;
  transport_udp_gro_t *retained_gro = t->sockets[1].gro;
  transport_mock_iface_remove(t, "127.0.0.1");
  transport_mock_iface_add(t, "127.0.0.3");
  count = snapshot(&f, fds, true);
  assert(fds[count - 1].revents & POLLIN);
  transport_tick_ready(t, fds, count);
  assert(t->socket_count == 2 && t->sockets[0].fd == retained_fd &&
         t->sockets[0].gro == retained_gro && t->sockets[0].receive_backlog);
  assert(t->sockets[1].fd == old_fd && !t->sockets[1].receive_backlog);
  assert(t->sockets[1].bytes_received == 0); /* Recycled fd has fresh state. */
  t->limits.max_packets_per_tick = 32;
  transport_tick(t);
  assert(!transport_udp_gro_pending(t->sockets[0].gro) &&
         !t->sockets[0].receive_backlog && !t->sockets[1].receive_backlog);
  destroy_fixture(&f);
}
#endif

int main(void) {
  quantum_and_native_only();
  global_budget_fairness();
#ifdef __linux__
  gro_budget_skipped_socket();
  gro_and_socket_lifetime();
#endif
  puts("===RX CADENCE BACKLOG OK===");
  return 0;
}
