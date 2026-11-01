#include "transport_fixture.h"
#include "transport_sim_host.h"
#include "transport_wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <poll.h>

/* application object parity with the polling fixture without socket/clock I/O
 */
static bool prohibit_io;
#ifndef TRANSPORT_ENGINE_ONLY
int __real_socket(int, int, int);
int __wrap_socket(int a, int b, int c) {
  assert(!prohibit_io);
  return __real_socket(a, b, c);
}
int __real_pipe(int[2]);
int __wrap_pipe(int p[2]) {
  assert(!prohibit_io);
  return __real_pipe(p);
}
#endif
int __real_clock_gettime(clockid_t, struct timespec *);
int __wrap_clock_gettime(clockid_t id, struct timespec *ts) {
  assert(!prohibit_io);
  return __real_clock_gettime(id, ts);
}

typedef struct {
  fixture_endpoint_t base;
  size_t records, closed;
  bool seen[64];
} driven_endpoint_t;
static void verify_record(driven_endpoint_t *e, const uint8_t *p, size_t size,
                          bool ordered) {
  assert(size == 512 && p[0] < 10 && !e->seen[p[0]]);
  unsigned sequence = p[0];
  if (ordered)
    assert(sequence == e->records);
  e->seen[sequence] = true;
  e->records++;
  for (size_t i = 0; i < size; i++)
    assert(p[i] == (uint8_t)(i + sequence));
}
static void driven_event(void *context, const transport_event_t *event) {
  driven_endpoint_t *endpoint = context;
  if (event->type == TRANSPORT_EVENT_DISCONNECTED) {
    endpoint->closed++;
    endpoint->base.conn = NULL;
    endpoint->base.authenticated = false;
    return;
  }
  if (event->type == TRANSPORT_EVENT_OBJECT) {
    if (event->track_id.flags &
        (MOQ_TRACK_FLAG_FEC_ENABLED | MOQ_TRACK_FLAG_FEC_RATELESS)) {
      qlinq_wire_cursor_t cursor = {event->object.data, event->object.size};
      const uint8_t *p;
      size_t size;
      while (qlinq_wire_next_record(&cursor, &p, &size))
        verify_record(endpoint, p, size, false);
      assert(!cursor.remaining);
    } else
      verify_record(endpoint, event->object.data, event->object.size,
                    (event->track_id.flags & MOQ_TRACK_FLAG_RELIABLE) != 0);
  }
  fixture_event(&endpoint->base, event);
}
typedef struct {
  bool driven;
  sim_network_t network;
  sim_node_t server_host, client_host;
  driven_endpoint_t server, client;
} driven_fixture_t;
static void step(driven_fixture_t *f) {
  if (f->driven)
    sim_advance(&f->network, 1000000U);
  else {
#ifndef TRANSPORT_ENGINE_ONLY
    transport_tick(f->server.base.transport);
    transport_tick(f->client.base.transport);
    usleep(1000);
#else
    abort();
#endif
  }
  assert(!f->server.base.failed && !f->client.base.failed);
}
static void entropy(void *, size_t);
static void create_family(driven_fixture_t *f, bool loss, bool driven,
                          uint64_t initial_ns, int family) {
  memset(f, 0, sizeof(*f));
  f->network.now_ns = initial_ns;
  f->driven = driven;
  prohibit_io = driven;
  f->server.base.server = true;
  transport_drive_host_t server = driven
                                      ? sim_host(&f->server_host, &f->network)
                                      : (transport_drive_host_t){0};
  transport_drive_host_t client = driven
                                      ? sim_host(&f->client_host, &f->network)
                                      : (transport_drive_host_t){0};
  if (driven) {
    server.random_bytes = entropy;
    client.random_bytes = entropy;
  }
  transport_config_t config = {
      .bind_hosts = {family == AF_INET6 ? "::1" : "127.0.0.1"},
      .num_bind_hosts = 1,
      .port = 19928,
      .callback = driven_event,
      .user_data = &f->server,
      .allow_insecure_peer = true,
      .cert_file = "t/assets/server.crt",
      .key_file = "t/assets/server.key",
      .drive_host = driven ? &server : NULL,
      .reconnect_enabled = driven};
#ifdef TRANSPORT_ENGINE_ONLY
  assert(driven);
#define test_create transport_drive_create
#else
#define test_create transport_create
#endif
  f->server.base.transport = test_create(&config);
  assert(f->server.base.transport);
  f->server_host.transport = f->server.base.transport;
  config.bind_hosts[0] =
      family == AF_INET6 ? (driven ? "::2" : "::1") : "127.0.0.2";
  config.remote_hosts[0] = family == AF_INET6 ? "::1" : "127.0.0.1";
  config.num_remote_hosts = 1;
  config.user_data = &f->client;
  config.drive_host = driven ? &client : NULL;
  f->client.base.transport = test_create(&config);
  assert(f->client.base.transport);
  f->client_host.transport = f->client.base.transport;
  if (loss) {
    f->network.drop_every = 13;
    f->network.reorder = true;
  }
  for (unsigned i = 0; i < 5000 && !f->client.base.authenticated; i++)
    step(f);
  assert(f->client.base.authenticated && f->server.base.authenticated);
  if (driven) {
    assert(f->server.base.conn->local_ifindex_cache[0].ifindex == 100);
    assert(f->client.base.conn->local_ifindex_cache[0].ifindex == 100);
  }
  if (driven) {
#ifndef TRANSPORT_ENGINE_ONLY
    struct pollfd fds[8];
    assert(!transport_get_poll_fds(f->server.base.transport, fds, 8));
    assert(!transport_get_poll_fds(f->client.base.transport, fds, 8));
#endif
  }
}
static void create_at(driven_fixture_t *f, bool loss, bool driven,
                      uint64_t initial_ns) {
  create_family(f, loss, driven, initial_ns, AF_INET);
}
static void create(driven_fixture_t *f, bool loss, bool driven) {
  create_at(f, loss, driven, 1000000000U);
}
static void destroy(driven_fixture_t *f) {
  transport_destroy(f->client.base.transport);
  f->client_host.transport = NULL;
  transport_destroy(f->server.base.transport);
  f->server_host.transport = NULL;
  assert(f->server_host.opens == f->server_host.closes);
  assert(f->client_host.opens == f->client_host.closes);
}
static void transfer_ip(bool loss, uint8_t flags, bool driven, bool ipv6) {
  driven_fixture_t *f = calloc(1, sizeof(*f));
  assert(f);
  create_family(f, loss, driven, 1000000000U, ipv6 ? AF_INET6 : AF_INET);
  moq_track_id_t track = {
      .type = MOQ_TRACK_DATA, .flags = flags, .name = "drive-parity"};
  assert(transport_subscribe(f->client.base.transport, track));
  for (unsigned i = 0; i < 5000 && !f->server.base.subscriptions; i++)
    step(f);
  assert(f->server.base.subscriptions == 1);
  uint8_t payload[512];
  for (size_t i = 0; i < sizeof(payload); i++)
    payload[i] = (uint8_t)i;
  moq_object_t obj = {
      .track_id = track, .data = payload, .size = sizeof(payload)};
  f->server_host.max_accept = 1;
  for (unsigned i = 0; i < 10; i++) {
    obj.object_id = i;
    for (size_t j = 0; j < sizeof(payload); j++)
      payload[j] = (uint8_t)(j + i);
    transport_publish_result_t result =
        transport_publish_ex(f->server.base.transport, &obj);
    assert(result == TRANSPORT_PUBLISH_DELIVERED ||
           result == TRANSPORT_PUBLISH_BUFFERED);
  }
  assert(transport_publish_flush(f->server.base.transport));
  if (loss)
    f->server_host.drop_next = 1; /* force loss after application publication */
  for (unsigned i = 0; i < 10000 && f->client.records < 10; i++)
    step(f);
  fprintf(
      stderr,
      "drive flags=%u loss=%u objects=%zu sent=%zu dropped=%zu partial=%zu\n",
      flags, loss, f->client.base.objects, f->network.accepted,
      f->network.dropped, f->network.partial);
  assert(f->client.records == 10);
  assert(f->client.base.last_track.flags == flags &&
         !strcmp(f->client.base.last_track.name, track.name));
  assert(f->network.peak_count <= SIM_PACKETS &&
         f->network.peak_bytes <= SIM_PACKETS * SIM_PACKET_SIZE);
  if (driven) {
    assert(f->network.partial > 0);
    if (loss)
      assert(f->network.dropped > 0 && !f->server_host.drop_next);
    assert(transport_now_ns(f->server.base.transport) == f->network.now_ns);
    assert(
        !transport_drive_time(f->server.base.transport, f->network.now_ns - 1));
  }
  destroy(f);
  free(f);
}
static void transfer(bool loss, uint8_t flags, bool driven) {
  transfer_ip(loss, flags, driven, false);
}
static size_t entropy_calls;
static void entropy(void *data, size_t size) {
  entropy_calls++;
  ptls_openssl_random_bytes(data, size);
}
static void deadlines_and_paths(void) {
  driven_fixture_t *f = calloc(1, sizeof(*f));
  assert(f);
  create(f, false, true);
  transport_t *t = f->server.base.transport;
  assert(t->tls_ctx.get_time->cb(t->tls_ctx.get_time) ==
         sim_wall(&f->server_host));
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                          .name = "clock"};
  assert(transport_subscribe(f->client.base.transport, track));
  for (unsigned i = 0; i < 1000 && !f->server.base.subscriptions; i++)
    step(f);
  uint8_t payload[512];
  for (size_t i = 0; i < sizeof(payload); i++)
    payload[i] = (uint8_t)i;
  moq_object_t obj = {
      .track_id = track, .data = payload, .size = sizeof(payload)};
  assert(transport_publish_ex(t, &obj) == TRANSPORT_PUBLISH_BUFFERED);
  assert(t->pending_group.started_at_ms == f->network.now_ns / 1000000U);
  int64_t now = transport_now_ms(t), deadline = transport_get_first_timeout(t);
  assert(deadline <= now + 3);
  step(f);
  step(f);
  assert(t->pending_group.size && !f->client.records);
  step(f);
  assert(!t->pending_group.size);
  for (unsigned i = 0; i < 1000 && !f->client.records; i++)
    step(f);
  assert(f->client.records == 1);
  /* verify both cache accounting and timestamp providers use virtual time */
  assert(transport_fec_cache_get(&t->fec_cache, FEC_REED_SOLOMON, 4, 2, 512));
  bool saw_codec = false;
  for (size_t i = 0; i < TRANSPORT_FEC_CACHE_SIZE; i++)
    if (t->fec_cache.entries[i].fec) {
      saw_codec = true;
      assert(t->fec_cache.entries[i].last_used_ns <= f->network.now_ns);
      assert(t->fec_cache.entries[i].last_used_ns >= 1000000000U);
    }
  assert(saw_codec);
  transport_t *client = f->client.base.transport;
  transport_drive_path_t paths[TRANSPORT_MAX_PATHS];
  assert(transport_drive_paths(client, paths, TRANSPORT_MAX_PATHS) == 1);
  uint64_t old = paths[0].id;
  struct sockaddr_storage first = paths[0].local, second = first;
  ((struct sockaddr_in *)&second)->sin_addr.s_addr = htonl(0x7f000003U);
  assert(transport_drive_interface(client, true, &second, 7, "sim7"));
  assert(transport_drive_paths(client, paths, TRANSPORT_MAX_PATHS) == 2);
  assert(strcmp(paths[1].interface_name, "sim7") == 0);
  uint64_t survivor = paths[1].id;
  assert(survivor != old);
  assert(transport_drive_interface(client, false, &first, 0, "sim0"));
  assert(transport_drive_paths(client, paths, TRANSPORT_MAX_PATHS) == 1 &&
         paths[0].id == survivor);
  uint8_t invalid[8] = {0};
  assert(!transport_drive_receive(client, old, invalid, sizeof(invalid),
                                  &second, &first, 0, 0));
  assert(!transport_drive_receive(client, survivor, invalid, sizeof(invalid),
                                  &second, &first, 0, 4));
  assert(transport_drive_receive(client, survivor, invalid, sizeof(invalid),
                                 &first, &second, 7, 3));
  /* removing a blocked interface cancels its owned output */
  f->client_host.blocked = true;
  transport_egress_t *q = &client->sockets[0].egress;
  struct iovec vector = {invalid, sizeof(invalid)};
  assert(
      transport_egress_submit(q, client->sockets[0].egress_id,
                              (struct sockaddr *)&f->server_host.paths[0].local,
                              sizeof(struct sockaddr_in), &vector, 1, 1));
  assert(q->count == 1);
  size_t closes = f->client_host.closes;
  assert(transport_drive_interface(client, false, &second, 7, "sim7"));
  assert(!client->socket_count && f->client_host.closes == closes + 1);
  assert(transport_drive_interface(client, true, &first, 0, "sim0"));
  assert(transport_drive_paths(client, paths, TRANSPORT_MAX_PATHS) == 1 &&
         paths[0].id > survivor);
  assert(!transport_drive_receive(client, survivor, invalid, sizeof(invalid),
                                  &first, &second, 0, 0));
  f->client_host.blocked = false;
  destroy(f);
  free(f);
}
static void simulated_loss_provider(void) {
  driven_fixture_t *f = calloc(1, sizeof(*f));
  assert(f);
  create(f, false, true);
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_RELIABLE,
                          .name = "entropy"};
  assert(transport_subscribe(f->client.base.transport, track));
  for (unsigned i = 0; i < 1000 && !f->server.base.subscriptions; i++)
    step(f);
  f->client.base.transport->simulated_loss_rate = 100;
  uint8_t data[512];
  for (size_t i = 0; i < sizeof(data); i++)
    data[i] = (uint8_t)i;
  moq_object_t object = {.track_id = track, .data = data, .size = sizeof(data)};
  size_t before = entropy_calls;
  assert(transport_publish_ex(f->server.base.transport, &object) ==
         TRANSPORT_PUBLISH_DELIVERED);
  for (unsigned i = 0; i < 100; i++)
    step(f);
  assert(!f->client.records && entropy_calls > before);
  f->client.base.transport->simulated_loss_rate = 0;
  for (unsigned i = 0; i < 5000 && !f->client.records; i++)
    step(f);
  assert(f->client.records == 1);
  destroy(f);
  free(f);
}
static void lifecycle(void) {
  driven_fixture_t *f = calloc(1, sizeof(*f));
  assert(f);
  create(f, false, true);
  uint32_t old = f->client.base.conn->id;
  transport_close_conn(f->server.base.transport, f->server.base.conn);
  for (unsigned i = 0; i < 10000; i++) {
    step(f);
    if (f->client.closed && f->client.base.authenticated &&
        f->client.base.conn && f->client.base.conn->id != old)
      break;
  }
  assert(f->client.closed && f->client.base.authenticated);
  assert(f->client.base.conn && f->client.base.conn->id != old);
  assert(f->client.base.transport->stats.reconnect_attempts > 0);
  transport_shutdown(f->server.base.transport, "drive shutdown");
  transport_shutdown(f->client.base.transport, "drive shutdown");
  for (unsigned i = 0;
       i < 10000 && (!transport_is_drained(f->server.base.transport) ||
                     !transport_is_drained(f->client.base.transport));
       i++)
    step(f);
  assert(transport_is_drained(f->server.base.transport));
  assert(transport_is_drained(f->client.base.transport));
  destroy(f);
  free(f);
}
typedef struct {
  size_t accepted, calls, limit;
  bool blocked, invalid;
  uint8_t expected;
} sink_t;
static ssize_t sink(void *context, int fd, const struct sockaddr *dest,
                    socklen_t len, const struct sockaddr *source,
                    uint32_t ifindex, const struct iovec *v, size_t count,
                    size_t gso, uint8_t ecn) {
  sink_t *s = context;
  (void)fd;
  s->calls++;
  assert(dest->sa_family == AF_INET && len == sizeof(struct sockaddr_in));
  assert(source && source->sa_family == AF_INET && ifindex == 17 && ecn == 3 &&
         gso == 2);
  if (s->invalid)
    return count + 1;
  if (s->blocked)
    return 0;
  size_t n = count < s->limit ? count : s->limit;
  for (size_t i = 0; i < n; i++) {
    assert(v[i].iov_len == 8);
    for (size_t j = 0; j < 8; j++)
      assert(((uint8_t *)v[i].iov_base)[j] == s->expected);
    s->expected++;
    s->accepted++;
  }
  return n;
}
static void ownership(void) {
  transport_egress_t q;
  assert(transport_egress_init(&q, 4, 32));
  sink_t s = {.limit = 1};
  q.sender = sink;
  q.sender_context = &s;
  uint8_t bytes[3][8];
  struct iovec vectors[3];
  for (unsigned i = 0; i < 3; i++) {
    memset(bytes[i], i, 8);
    vectors[i] = (struct iovec){bytes[i], 8};
  }
  struct sockaddr_in dest = {.sin_family = AF_INET, .sin_port = htons(9999)},
                     source = dest;
  assert(transport_egress_submit_pktinfo(
      &q, 123, (struct sockaddr *)&dest, sizeof(dest),
      (struct sockaddr *)&source, 17, vectors, 3, 2, 3));
  assert(s.accepted == 1 && q.count == 2 && q.bytes == 16);
  memset(bytes, 0xee,
         sizeof(bytes)); /* reuse the producer's whole send arena */
  s.blocked = true;
  assert(transport_egress_flush(&q, 123));
  assert(q.count == 2);
  s.blocked = false;
  assert(transport_egress_flush(&q, 123));
  assert(q.count == 1);
  assert(transport_egress_flush(&q, 123));
  assert(!q.count && s.accepted == 3);
  transport_egress_destroy(&q);
  assert(transport_egress_init(&q, 2, 16));
  s.blocked = true;
  q.sender = sink;
  q.sender_context = &s;
  assert(!transport_egress_submit_pktinfo(
      &q, 123, (struct sockaddr *)&dest, sizeof(dest),
      (struct sockaddr *)&source, 17, vectors, 3, 2, 3));
  assert(!q.count && !q.bytes && q.packets_dropped == 3);
  s.invalid = true;
  assert(!transport_egress_submit_pktinfo(
      &q, 123, (struct sockaddr *)&dest, sizeof(dest),
      (struct sockaddr *)&source, 17, vectors, 1, 2, 3));
  assert(!q.count && q.send_errors == 1);
  transport_egress_destroy(&q);
}
static void phase_guards(void) {
  driven_fixture_t *f = calloc(1, sizeof(*f));
  assert(f);
  create(f, false, true);
  transport_t *t = f->server.base.transport;
  uint64_t now = t->drive_now_ns;
  assert(transport_engine_begin_turn(t));
  assert(t->turn_active && !t->tick_active);
  assert(!transport_drive_tick(t, now + 1000000U));
  assert(t->drive_now_ns == now);
  uint64_t rejected = t->stats.callback_destroy_rejections;
  transport_destroy(t);
  assert(t->stats.callback_destroy_rejections == rejected + 1);
  assert(!transport_engine_begin_turn(t));
#ifndef TRANSPORT_ENGINE_ONLY
  rejected = t->stats.recursive_tick_rejections;
  transport_tick(t);
  assert(t->stats.recursive_tick_rejections == rejected + 1);
#endif
  transport_engine_end_turn(t);
  assert(!t->turn_active && !t->tick_active);
  destroy(f);
  free(f);
}

int main(int argc, char **argv) {
  (void)argv;
  transport_drive_host_t invalid_host = {
      .open = sim_open, .close = sim_close, .send = sim_send};
  transport_config_t invalid_config = {.bind_hosts = {"127.0.0.1"},
                                       .num_bind_hosts = 1,
                                       .port = 19928,
                                       .callback = fixture_event,
                                       .allow_insecure_peer = true,
                                       .drive_host = &invalid_host};
  assert(!test_create(&invalid_config));
  driven_fixture_t *zero = calloc(1, sizeof(*zero));
  assert(zero);
  create_at(zero, false, true, 1000000U);
  destroy(zero);
  free(zero);
  ownership();
  phase_guards();
  deadlines_and_paths();
  lifecycle();
  simulated_loss_provider();
  transfer(false, MOQ_TRACK_FLAG_RELIABLE, true);
  transfer(true, MOQ_TRACK_FLAG_RELIABLE, true);
  transfer(false, 0, true);
  transfer(false, MOQ_TRACK_FLAG_FEC_ENABLED, true);
  transfer(true, MOQ_TRACK_FLAG_FEC_RATELESS, true);
  transfer_ip(true, MOQ_TRACK_FLAG_RELIABLE, true, true);
  transfer_ip(false, 0, true, true);
#ifndef TRANSPORT_ENGINE_ONLY
  if (argc == 1) {
    transfer(false, MOQ_TRACK_FLAG_RELIABLE, false);
    transfer(false, 0, false);
    transfer(false, MOQ_TRACK_FLAG_FEC_ENABLED, false);
    transfer(false, MOQ_TRACK_FLAG_FEC_RATELESS, false);
    transfer_ip(false, MOQ_TRACK_FLAG_RELIABLE, false, true);
    transfer_ip(false, 0, false, true);
  }
#else
  (void)argc;
#endif
  assert(entropy_calls > 2);
  prohibit_io = false;
  puts("===TRANSPORT DRIVE OK===");
}
