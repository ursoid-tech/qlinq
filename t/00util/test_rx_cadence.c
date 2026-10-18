/* The public service implementation is real. Only clocks, readiness and the
 * transport boundary are replaced, so no test depends on scheduler timing. */
#include "transport.h"
#include "portable_sockets.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#ifdef __linux__
static int fake_clock(clockid_t, struct timespec *);
static int fake_poll(struct pollfd *, nfds_t, int);
static int fake_ppoll(struct pollfd *, nfds_t, const struct timespec *,
                      const sigset_t *);
static size_t fake_fds(transport_t *, struct pollfd *, size_t);
static int64_t fake_deadline(transport_t *);
static int64_t fake_ms(void);
static void fake_tick(transport_t *, const struct pollfd *, size_t);
static bool fake_mask(transport_t *, struct pollfd *, size_t);
static bool fake_writable(transport_t *, const moq_track_id_t *);
#define clock_gettime fake_clock
#define poll fake_poll
#define ppoll fake_ppoll
#define transport_get_poll_fds fake_fds
#define transport_get_first_timeout fake_deadline
#define transport_get_time_ms fake_ms
#define transport_tick_ready fake_tick
#define transport_rx_cadence_mask fake_mask
#define transport_is_track_ready fake_writable
#include "../../src/common/qlinq.c"
#undef clock_gettime
#undef poll
#undef ppoll

static uint64_t mono, wall, clock_step, mask_cost, requested, tick_cost;
static int64_t deadline, rechecked_deadline;
static unsigned polls, waits, masked_waits, ticks, masks, queries;
static int poll_timeout, wait_result, wait_error, poll_error;
static short udp_ready, monitor_ready, wait_udp, wait_monitor;
static short seen_udp, seen_monitor;
static bool can_mask, writable;
static qlinq_context_t context;
static qlinq_endpoint_t endpoint, second;
static qlinq_stream_t subscription, publication;

static int fake_clock(clockid_t clock, struct timespec *ts) {
  uint64_t n = clock == CLOCK_MONOTONIC ? mono : wall;
  *ts = (struct timespec){.tv_sec = (time_t)(n / 1000000000U),
                          .tv_nsec = (long)(n % 1000000000U)};
  mono += clock_step;
  return 0;
}
static int64_t fake_ms(void) {
  return (int64_t)(wall / 1000000U);
}
static size_t fake_fds(transport_t *t, struct pollfd *fds, size_t cap) {
  (void)t;
  assert(cap >= 2);
  fds[0] = (struct pollfd){.fd = 31, .events = POLLIN};
  fds[1] = (struct pollfd){.fd = 32, .events = POLLIN};
  return 2;
}
static int64_t fake_deadline(transport_t *t) {
  (void)t;
  return ++queries == 1 ? deadline : rechecked_deadline;
}
static bool fake_writable(transport_t *t, const moq_track_id_t *track) {
  (void)t;
  (void)track;
  return writable;
}
static bool fake_mask(transport_t *t, struct pollfd *fds, size_t count) {
  (void)t;
  assert(count == 2);
  masks++;
  mono += mask_cost;
  if (!can_mask)
    return false;
  assert(fds[0].events == POLLIN && fds[1].events == POLLIN);
  fds[0].events = 0;
  return true;
}
static int fake_ppoll(struct pollfd *fds, nfds_t n, const struct timespec *ts,
                      const sigset_t *signals) {
  (void)signals;
  assert(n == 2 && ts && ts->tv_sec == 0 && ts->tv_nsec >= 0 &&
         ts->tv_nsec <= 1000000 && fds[1].events == POLLIN);
  bool masked = fds[0].events == 0;
  assert(masked || fds[0].events == POLLIN);
  waits++;
  masked_waits += masked;
  requested = (uint64_t)ts->tv_nsec;
  fds[0].revents = wait_udp;
  fds[1].revents = wait_monitor;
  if (wait_result < 0) {
    errno = wait_error;
    return -1;
  }
  if (!masked && udp_ready) {
    fds[0].revents |= udp_ready;
    return 1;
  }
  if (!wait_result) {
    mono += requested;
    wall += requested;
  }
  return wait_result;
}
static int fake_poll(struct pollfd *fds, nfds_t n, int timeout) {
  polls++;
  poll_timeout = timeout;
  for (size_t i = 0; i < n; i++)
    fds[i].revents = 0;
  assert(fds[0].events == POLLIN && fds[1].events == POLLIN);
  if (poll_error) {
    errno = poll_error;
    return -1;
  }
  fds[0].revents = udp_ready;
  fds[1].revents = monitor_ready;
  if (n > 2 && n % 2)
    fds[n - 1].revents = POLLIN;
  return (udp_ready != 0) + (monitor_ready != 0) + (n > 2 && n % 2);
}
static void fake_tick(transport_t *t, const struct pollfd *fds, size_t count) {
  (void)t;
  assert(count == 2);
  ticks++;
  seen_udp = fds[0].revents;
  seen_monitor = fds[1].revents;
  /* Processing time must be subtracted from the next service interval. */
  mono += tick_cost;
  wall += tick_cost;
}
static void clean(void) {
  while (context.event_head) {
    qlinq_event_t event;
    assert(qlinq_next_event(&context, &event));
    qlinq_event_release(&event);
  }
  free(context.poll_fds);
  free(context.endpoint_polls);
}
static void reset(void) {
  clean();
  memset(&context, 0, sizeof(context));
  memset(&endpoint, 0, sizeof(endpoint));
  memset(&second, 0, sizeof(second));
  memset(&subscription, 0, sizeof(subscription));
  memset(&publication, 0, sizeof(publication));
  mono = 100000000U;
  wall = 10000000000U;
  clock_step = mask_cost = requested = tick_cost = 0;
  deadline = rechecked_deadline = INT64_MAX;
  polls = waits = masked_waits = ticks = masks = queries = 0;
  poll_timeout = -99;
  wait_result = wait_error = poll_error = 0;
  udp_ready = POLLIN;
  monitor_ready = wait_udp = wait_monitor = seen_udp = seen_monitor = 0;
  can_mask = true;
  writable = false;
  context.owner_thread = pthread_self();
  context.rx_cadence_enabled = true;
  context.endpoints = &endpoint;
  context.max_queued_events = 10;
  context.max_queued_event_bytes = 65536;
  endpoint.context = &context;
  endpoint.active = true;
  endpoint.transport = (transport_t *)&endpoint;
  endpoint.rx_service_started_ns = mono - 250000U;
  endpoint.streams = &subscription;
  subscription.endpoint = &endpoint;
  subscription.state = QLINQ_STREAM_OPEN;
  subscription.direction = QLINQ_STREAM_SUBSCRIBE;
}
static void service_ok(int timeout) {
  assert(qlinq_service(&context, timeout) == QLINQ_STATUS_OK);
}

static void timing_and_idle(void) {
  reset();
  service_ok(1);
  assert(masked_waits == 1 && requested == 750000 && polls == 1 &&
         poll_timeout == 0 && ticks == 1);
  reset();
  mask_cost = 600000;
  service_ok(1);
  assert(masked_waits == 1 && requested == 150000);
  reset();
  mask_cost = 800000;
  service_ok(1);
  assert(!masked_waits && waits == 1 && requested == 200000 && !polls &&
         ticks == 1);
  reset();
  mask_cost = 1200000;
  service_ok(1);
  assert(!masked_waits && waits == 1 && requested == 0);
  reset();
  endpoint.rx_service_started_ns = mono - 1000000;
  service_ok(1);
  assert(!masked_waits && requested == 1000000);
  reset();
  endpoint.rx_service_started_ns = 0;
  service_ok(1);
  assert(!masked_waits && requested == 1000000);
  reset();
  tick_cost = 1200000;
  service_ok(1);
  uint64_t start = endpoint.rx_service_started_ns;
  assert(start + tick_cost == mono);
  service_ok(1);
  assert(masked_waits == 1); /* No new delay after long processing. */
  reset();
  udp_ready = 0;
  uint64_t old_start = endpoint.rx_service_started_ns;
  service_ok(1);
  assert(masked_waits == 1 && !ticks &&
         endpoint.rx_service_started_ns == old_start);
  reset();
  context.rx_cadence_enabled = false;
  udp_ready = 0;
  service_ok(1);
  assert(polls == 1 && !waits &&
         ticks == 1); /* Preserve main's idle maintenance tick. */
  reset();
  rechecked_deadline = fake_ms();
  service_ok(1);
  assert(waits == 1 && !masked_waits && requested == 0 && ticks == 1);
  reset();
  wall += 800000;
  deadline = rechecked_deadline = fake_ms() + 1;
  service_ok(1);
  assert(masked_waits == 1 && requested == 200000);
  reset();
  deadline = rechecked_deadline = fake_ms();
  service_ok(1);
  assert(!waits && poll_timeout == 0 && ticks == 1);

  uint64_t ordinary;
  reset();
  clock_step = 10000;
  assert(rx_cadence_remaining(mono - 100000, mono, 1, INT64_MAX, &ordinary) ==
         880000);
  assert(ordinary == 980000);
  reset();
  assert(rx_cadence_remaining(mono, mono - 900000, 1, INT64_MAX, &ordinary) ==
         100000);
  reset();
  assert(rx_cadence_remaining(UINT64_MAX - 10, mono, 1, INT64_MAX, &ordinary) ==
         0);
  reset();
  assert(rx_cadence_remaining(mono + 1, mono, 1, INT64_MAX, &ordinary) == 0);
  reset();
  assert(rx_cadence_remaining(mono, mono + 1, 1, INT64_MAX, &ordinary) == 0 &&
         !ordinary);
  reset();
  assert(rx_cadence_remaining(mono, UINT64_MAX - 10, 1, INT64_MAX, &ordinary) ==
             0 &&
         !ordinary);
  reset();
  assert(rx_cadence_remaining(mono - 250000, mono, 1, -1, &ordinary) == 750000);
  reset();
  assert(rx_cadence_remaining(mono - 250000, mono, 1, 0, &ordinary) == 0 &&
         !ordinary);
  reset();
  assert(rx_cadence_remaining(mono - 250000, mono, 1, INT64_MAX - 1,
                              &ordinary) == 750000);
  reset();
  deadline = fake_ms() + 1;
  wall += 2000000;
  assert(rx_cadence_remaining(mono - 250000, mono, 1, deadline, &ordinary) ==
         0);
  reset();
  deadline = fake_ms() + 1;
  wall -= 2000000;
  assert(rx_cadence_remaining(mono - 250000, mono, 1, deadline, &ordinary) ==
         750000);
}

static void bypasses(void) {
  reset();
  endpoint.service_pending = true;
  service_ok(1);
  assert(!waits && poll_timeout == 0 && !endpoint.service_pending);
  reset();
  context.rx_cadence_enabled = false;
  service_ok(1);
  assert(!waits && !masks);
  reset();
  service_ok(0);
  assert(!waits && poll_timeout == 0);
  reset();
  service_ok(-1);
  assert(!waits && poll_timeout == INT_MAX);
  reset();
  deadline = rechecked_deadline = -1;
  service_ok(-1);
  assert(!waits && poll_timeout == -1);
  reset();
  short revents = 0;
  assert(qlinq_service_fd(&context, 1, 42, POLLIN, &revents) ==
         QLINQ_STATUS_OK);
  assert(!waits && revents == POLLIN);
  reset();
  second = endpoint;
  endpoint.next = &second;
  service_ok(1);
  assert(!waits);
  reset();
  subscription.state = QLINQ_STREAM_CLOSED;
  service_ok(1);
  assert(!waits);
  reset();
  publication = subscription;
  publication.direction = QLINQ_STREAM_PUBLISH;
  subscription.next = &publication;
  service_ok(1);
  assert(!waits);
  reset();
  subscription.direction = QLINQ_STREAM_PUBLISH;
  writable = true;
  service_ok(1);
  assert(!waits && poll_timeout == 0 && context.event_head);
  reset();
  qlinq_event_t event = {.type = QLINQ_EVENT_PEER_READY};
  assert(queue_event(&context, &event, NULL, 0, NULL));
  service_ok(1);
  assert(!polls && !waits && !ticks);
  reset();
  can_mask = false;
  service_ok(1);
  assert(!waits && polls == 1 && ticks == 1);
}

static void wake_and_errors(void) {
  reset();
  wait_result = 1;
  wait_monitor = POLLIN;
  udp_ready = 0;
  service_ok(1);
  assert(seen_monitor == POLLIN && ticks == 1 && context.rx_cadence_wakes == 1);
  reset();
  wait_result = 1;
  wait_udp = POLLERR | POLLHUP | POLLNVAL;
  udp_ready = 0;
  service_ok(1);
  assert(seen_udp == wait_udp && ticks == 1);
  const int errors[] = {EINTR, EIO};
  for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); i++) {
    qlinq_status_t expected =
        errors[i] == EINTR ? QLINQ_STATUS_AGAIN : QLINQ_STATUS_IO;
    reset();
    wait_result = -1;
    wait_error = errors[i];
    assert(qlinq_service(&context, 1) == expected);
    assert(!polls && !ticks && context.poll_fds[0].events == POLLIN);
    reset();
    poll_error = errors[i];
    assert(qlinq_service(&context, 1) == expected);
    assert(waits == 1 && !ticks && context.poll_fds[0].events == POLLIN);
    reset();
    context.rx_cadence_enabled = false;
    poll_error = errors[i];
    assert(qlinq_service(&context, 1) == expected && !ticks && !waits);
  }
}

int main(void) {
  timing_and_idle();
  bypasses();
  wake_and_errors();
  clean();
  const char *values[] = {"",      "0",     "100",  "1000 ",
                          "+1000", "01000", "2000", "1000"};
  for (size_t i = 0; i < sizeof(values) / sizeof(*values); i++) {
    assert(setenv("QLINQ_EXPERIMENT_RX_CADENCE_USEC", values[i], 1) == 0);
    qlinq_context_t *c = qlinq_context_create(NULL);
    assert(c && c->rx_cadence_enabled == (i == 7));
    qlinq_context_destroy(c);
  }
  unsetenv("QLINQ_EXPERIMENT_RX_CADENCE_USEC");
  qlinq_context_t *c = qlinq_context_create(NULL);
  assert(c && !c->rx_cadence_enabled);
  qlinq_context_destroy(c);
  puts("===RX CADENCE SCHEDULE OK===");
  return 0;
}
#else
#include <stdio.h>
int main(void) {
  puts("===RX CADENCE SCHEDULE OK=== (Linux-only opt-in)");
  return 0;
}
#endif
