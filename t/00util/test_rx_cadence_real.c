/* Separate contexts exercise the eligible public API, including actual QUIC
 * recovery. A test-only egress wrapper reorders and loses one data burst. */
#include "qlinq.h"
#include "portable_sockets.h"
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#ifdef __linux__
static int observed_ppoll(struct pollfd *, nfds_t, const struct timespec *,
                          const sigset_t *);
#define ppoll observed_ppoll
#endif
#include "../../src/common/qlinq.c"
#ifdef __linux__
#undef ppoll
#endif
#include "transport_internal.h"

#define RECORDS 64U
#define BYTES 8192U
static unsigned received, injected_bursts;
static bool callback_mode, inject_loss;
static int impaired_fd = -1;
static qlinq_stream_t *subscriber;
static qlinq_context_t *closing_tx;
static qlinq_endpoint_t *closing_server;
static bool close_in_masked_wait;

ssize_t test_cadence_udp_send_batch(int fd, const struct sockaddr *destination,
                                    socklen_t destination_len,
                                    const struct iovec *datagrams, size_t count,
                                    size_t max_gso_segments) {
  if (fd != impaired_fd || !inject_loss || count < 3)
    return transport_udp_send_batch(fd, destination, destination_len, datagrams,
                                    count, max_gso_segments);
  inject_loss = false;
  injected_bursts++;
  /* This isolated-loopback test requires these small writes to succeed. The
   * native sender observes a completed burst; the wire loses its second packet
   * and delivers the others in reverse order. No production loss hook is used.
   */
  for (size_t i = count; i != 0; i--)
    if (i != 2)
      assert(transport_udp_send_batch(fd, destination, destination_len,
                                      datagrams + i - 1, 1, 1) == 1);
  return (ssize_t)count;
}

#ifdef __linux__
static int observed_ppoll(struct pollfd *fds, nfds_t count,
                          const struct timespec *timeout,
                          const sigset_t *signals) {
  if (closing_tx && !close_in_masked_wait && count && fds[0].events == 0) {
    /* Inject the peer's close only after the live receive context has passed
     * every eligibility guard and masked UDP. Its subscription is still open.
     */
    assert(subscriber->state == QLINQ_STREAM_OPEN && timeout->tv_nsec > 0);
    close_in_masked_wait = true;
    assert(qlinq_endpoint_shutdown(closing_server, "cadence close") ==
           QLINQ_STATUS_OK);
    assert(qlinq_service(closing_tx, 0) == QLINQ_STATUS_OK);
  }
  return ppoll(fds, count, timeout, signals);
}
#endif

static void check_record(const qlinq_event_t *event) {
  assert(event->stream == subscriber && event->record.sequence == received &&
         event->record.size == BYTES);
  const uint8_t *p = event->record.data;
  for (size_t i = 0; i < BYTES; i++)
    assert(p[i] == (uint8_t)(received + i));
  received++;
}
static bool callback(void *unused, const qlinq_event_t *event) {
  (void)unused;
  check_record(event);
  return true;
}
static unsigned drain(qlinq_context_t *context, qlinq_event_type_t type) {
  unsigned found = 0;
  qlinq_event_t event;
  while (qlinq_next_event(context, &event)) {
    if (event.type == QLINQ_EVENT_RECORD) {
      assert(!callback_mode);
      check_record(&event);
    }
    assert(event.type != QLINQ_EVENT_ERROR);
    found += event.type == type;
    qlinq_event_release(&event);
  }
  return found;
}
static bool eligible(qlinq_endpoint_t *endpoint) {
  struct pollfd fds[TRANSPORT_MAX_POLL_FDS];
  size_t count =
      transport_get_poll_fds(endpoint->transport, fds, TRANSPORT_MAX_POLL_FDS);
  return transport_rx_cadence_mask(endpoint->transport, fds, count);
}

static void eligibility_guards(qlinq_endpoint_t *endpoint) {
  transport_t *t = endpoint->transport;
  transport_conn_t *conn = transport_connection_at(t, 0);
  struct pollfd fds[TRANSPORT_MAX_POLL_FDS], saved[TRANSPORT_MAX_POLL_FDS];
  size_t count = transport_get_poll_fds(t, saved, TRANSPORT_MAX_POLL_FDS);
  assert(eligible(endpoint));
#define REJECT(set, restore)                                                   \
  do {                                                                         \
    memcpy(fds, saved, count * sizeof(*fds));                                  \
    set;                                                                       \
    assert(!transport_rx_cadence_mask(t, fds, count));                         \
    assert(memcmp(fds, saved, count * sizeof(*fds)) == 0);                     \
    restore;                                                                   \
  } while (0)
  REJECT(t->sockets[0].receive_backlog = true,
         t->sockets[0].receive_backlog = false);
  REJECT(t->shutting_down = true, t->shutting_down = false);
  REJECT(t->reconnect_in_progress = true, t->reconnect_in_progress = false);
  REJECT(conn->authenticated = false, conn->authenticated = true);
  REJECT(conn->protocol_ready = false, conn->protocol_ready = true);
  REJECT(conn->quic_ready = false, conn->quic_ready = true);
  REJECT(t->sockets[0].egress.count = 1, t->sockets[0].egress.count = 0);
  REJECT(t->sockets[0].open_pending = true, t->sockets[0].open_pending = false);
  REJECT(t->pending_group.size = 1, t->pending_group.size = 0);
  /* This fixture's client has one real peer. The early count guard must reject
   * a multi-peer endpoint before touching an array of connection pointers. */
  REJECT(t->is_server = true; t->conn_count = 2, t->is_server = false;
         t->conn_count = 0);
#undef REJECT
  memcpy(fds, saved, count * sizeof(*fds));
  fds[0].fd += 10000;
  assert(!transport_rx_cadence_mask(t, fds, count));
  memcpy(fds, saved, count * sizeof(*fds));
  fds[0].events |= POLLOUT;
  assert(!transport_rx_cadence_mask(t, fds, count));
  memcpy(fds, saved, count * sizeof(*fds));
  fds[0].revents = POLLERR;
  assert(!transport_rx_cadence_mask(t, fds, count));
}

static void run(bool use_callback, bool enabled) {
  assert(setenv("QLINQ_EXPERIMENT_RX_CADENCE_USEC", enabled ? "1000" : "0",
                1) == 0);
  callback_mode = use_callback;
  received = injected_bursts = 0;
  closing_tx = NULL;
  closing_server = NULL;
  close_in_masked_wait = false;
  qlinq_context_t *tx = qlinq_context_create(NULL);
  qlinq_context_config_t cc = {.record_callback =
                                   use_callback ? callback : NULL};
  qlinq_context_t *rx = qlinq_context_create(&cc);
  assert(tx && rx);
  qlinq_endpoint_config_t config = {
      .bind_addresses = {"127.0.0.1"},
      .bind_address_count = 1,
      .port = (uint16_t)(19871 + 2U * enabled + use_callback),
      .idle_timeout_ms = 5000,
      .security = {.shared_secret = "cadence",
                   .shared_secret_size = 7,
                   .certificate_file = "t/assets/server.crt",
                   .private_key_file = "t/assets/server.key",
                   .allow_insecure_peer = true}};
  qlinq_endpoint_t *server = qlinq_listen(tx, &config);
  assert(server);
  config.remote_addresses[0] = "127.0.0.1";
  config.remote_address_count = 1;
  qlinq_endpoint_t *client = qlinq_connect(rx, &config);
  assert(client);
  qlinq_stream_config_t stream = {.content_type = QLINQ_CONTENT_DATA,
                                  .delivery = QLINQ_DELIVERY_RELIABLE,
                                  .name = "cadence"};
  qlinq_stream_t *publisher = qlinq_publish(server, &stream);
  subscriber = qlinq_subscribe(client, &stream);
  assert(publisher && subscriber);
  bool joined = false;
  int64_t until = transport_get_time_ms() + 10000;
  while (transport_get_time_ms() < until && !(joined && eligible(client))) {
    assert(qlinq_service(tx, 0) == QLINQ_STATUS_OK);
    joined |= drain(tx, QLINQ_EVENT_SUBSCRIBER_JOINED) != 0;
    assert(qlinq_service(rx, 1) == QLINQ_STATUS_OK);
    drain(rx, QLINQ_EVENT_PEER_READY);
  }
  assert(joined && eligible(client));
  eligibility_guards(client);
  impaired_fd = server->transport->sockets[0].fd;
  inject_loss = true;
  uint8_t payload[BYTES];
  unsigned sent = 0;
  until = transport_get_time_ms() + 10000;
  while (transport_get_time_ms() < until && received < RECORDS) {
    if (sent < RECORDS) {
      for (size_t i = 0; i < BYTES; i++)
        payload[i] = (uint8_t)(sent + i);
      qlinq_record_t record = {
          .data = payload, .size = BYTES, .sequence = sent, .group_id = 1};
      qlinq_send_result_t result = qlinq_stream_send(publisher, &record);
      assert(result == QLINQ_SEND_SENT || result == QLINQ_SEND_BUFFERED ||
             result == QLINQ_SEND_WOULD_BLOCK);
      sent += result != QLINQ_SEND_WOULD_BLOCK;
    }
    assert(qlinq_service(tx, 0) == QLINQ_STATUS_OK);
    drain(tx, QLINQ_EVENT_SUBSCRIBER_JOINED);
    assert(qlinq_service(rx, 1) == QLINQ_STATUS_OK);
    drain(rx, QLINQ_EVENT_PEER_READY);
  }
  assert(sent == RECORDS && received == RECORDS && injected_bursts == 1);
  quicly_stats_t stats;
  assert(quicly_get_stats(transport_connection_at(server->transport, 0)->quic,
                          &stats) == 0);
  assert(stats.num_bytes.stream_data_resent > 0);
  if (enabled)
    assert(rx->rx_cadence_waits > 0 && tx->rx_cadence_waits == 0 &&
           !rx->rx_cadence_errors);
  else
    assert(!rx->rx_cadence_waits && !tx->rx_cadence_waits);

  if (!use_callback) {
    /* Local control is immediate API work. Keep this unsubscribe scenario
     * separate from the incoming close with an active subscription below. */
    uint64_t waits = rx->rx_cadence_waits;
    qlinq_stream_close(subscriber);
    assert(client->service_pending && qlinq_service(rx, 1) == QLINQ_STATUS_OK);
    assert(rx->rx_cadence_waits == waits);
    unsigned left = 0;
    until = transport_get_time_ms() + 5000;
    while (!left && transport_get_time_ms() < until) {
      assert(qlinq_service(tx, 0) == QLINQ_STATUS_OK);
      left += drain(tx, QLINQ_EVENT_SUBSCRIBER_LEFT);
      assert(qlinq_service(rx, 1) == QLINQ_STATUS_OK);
      drain(rx, QLINQ_EVENT_PEER_READY);
    }
    assert(left == 1);
  }

  if (use_callback && enabled) {
    closing_tx = tx;
    closing_server = server;
  } else {
    assert(qlinq_endpoint_shutdown(server, "cadence close") == QLINQ_STATUS_OK);
  }
  unsigned disconnected = 0;
  until = transport_get_time_ms() + 5000;
  while (!disconnected && transport_get_time_ms() < until) {
    assert(qlinq_service(tx, 0) == QLINQ_STATUS_OK);
    drain(tx, QLINQ_EVENT_PEER_DISCONNECTED);
    assert(qlinq_service(rx, 1) == QLINQ_STATUS_OK);
    disconnected += drain(rx, QLINQ_EVENT_PEER_DISCONNECTED);
    /* Ensure another actual service start if no packet follows the last data
     * burst. This is test input, not a synthetic anchor assignment. */
    if (closing_tx && !close_in_masked_wait && eligible(client)) {
      int fd = socket(AF_INET, SOCK_DGRAM, 0);
      assert(fd >= 0);
      struct sockaddr_storage address;
      socklen_t length = sizeof(address);
      assert(getsockname(client->transport->sockets[0].fd,
                         (struct sockaddr *)&address, &length) == 0);
      const uint8_t invalid = 0xc0;
      assert(sendto(fd, &invalid, 1, 0, (struct sockaddr *)&address, length) ==
             1);
      close(fd);
      assert(qlinq_service(rx, 0) == QLINQ_STATUS_OK);
      drain(rx, QLINQ_EVENT_PEER_READY);
    }
  }
  assert(disconnected == 1);
  if (use_callback && enabled)
    assert(close_in_masked_wait);
  fprintf(stderr,
          "cadence-real enabled=%d callback=%d records=%u waits=%" PRIu64
          " resent=%" PRIu64 " active_close=%d\n",
          enabled, use_callback, received, rx->rx_cadence_waits,
          stats.num_bytes.stream_data_resent, close_in_masked_wait);
  closing_tx = NULL;
  impaired_fd = -1;
  qlinq_context_destroy(rx);
  qlinq_context_destroy(tx);
}

int main(void) {
  run(false, false);
  run(true, false);
#ifdef __linux__
  run(false, true);
  run(true, true);
#endif
  unsetenv("QLINQ_EXPERIMENT_RX_CADENCE_USEC");
  puts("===RX CADENCE REAL OK===");
  return 0;
}
