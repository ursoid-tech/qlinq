/* end-to-end recovery latency under explicit virtual time without native I/O */
#include "transport_fixture.h"
#include "transport_sim_host.h"
#include "transport_wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define RECORDS 64U
#define MAX_BYTES 1372U
#define MS 1000000ULL

int __real_clock_gettime(clockid_t, struct timespec *);
int __wrap_clock_gettime(clockid_t id, struct timespec *ts) {
  (void)id;
  (void)ts;
  assert(!"engine recovery consulted a platform clock");
  return -1;
}
typedef struct latency_fixture latency_fixture_t;
typedef struct {
  fixture_endpoint_t base;
  latency_fixture_t *fixture;
  size_t received, lost, disconnected;
} endpoint_t;
struct latency_fixture {
  sim_network_t net;
  sim_node_t host[2];
  endpoint_t endpoint[2];
  unsigned sender, receiver, first_record;
  bool ipv6;
  uint32_t seed;
  size_t turns;
  moq_track_id_t track;
  bool seen[RECORDS], attempted[RECORDS], planned_disconnect;
  size_t size[RECORDS], blocked;
  uint64_t submitted[RECORDS], admitted[RECORDS], delivered[RECORDS];
};
static void record(endpoint_t *endpoint, const uint8_t *data, size_t size) {
  latency_fixture_t *f = endpoint->fixture;
  assert(endpoint == &f->endpoint[f->receiver] && size >= 8);
  unsigned id = (unsigned)data[0] << 24 | (unsigned)data[1] << 16 |
                (unsigned)data[2] << 8 | data[3];
  assert(id < RECORDS && f->attempted[id] && size == f->size[id] &&
         !f->seen[id]);
  for (size_t i = 4; i < size; i++)
    assert(data[i] == (uint8_t)(i + id * 17U));
  if (f->track.flags & MOQ_TRACK_FLAG_RELIABLE)
    assert(id == f->first_record + endpoint->received);
  f->seen[id] = true;
  f->delivered[id] = f->net.now_ns;
  endpoint->received++;
}
static void event(void *context, const transport_event_t *ev) {
  endpoint_t *endpoint = context;
  latency_fixture_t *f = endpoint->fixture;
  if (ev->type == TRANSPORT_EVENT_OBJECT) {
    if (ev->track_id.flags &
        (MOQ_TRACK_FLAG_FEC_ENABLED | MOQ_TRACK_FLAG_FEC_RATELESS)) {
      qlinq_wire_cursor_t cursor = {ev->object.data, ev->object.size};
      const uint8_t *data;
      size_t size;
      while (qlinq_wire_next_record(&cursor, &data, &size))
        record(endpoint, data, size);
      assert(!cursor.remaining);
    } else
      record(endpoint, ev->object.data, ev->object.size);
    return;
  }
  if (ev->type == TRANSPORT_EVENT_OBJECT_LOST) {
    endpoint->lost++;
    return;
  }
  if (ev->type == TRANSPORT_EVENT_DISCONNECTED) {
    assert(f->planned_disconnect);
    endpoint->disconnected++;
    endpoint->base.conn = NULL;
    endpoint->base.authenticated = false;
    endpoint->base.subscriptions = 0;
    return;
  }
  fixture_event(&endpoint->base, ev);
}
/* advance to the next engine deadline or simulated input */
static void progress(latency_fixture_t *f, uint64_t horizon) {
  assert(horizon > f->net.now_ns);
  uint64_t next = horizon;
  for (size_t i = 0; i < SIM_PACKETS; i++)
    if (f->net.packets[i].active) {
      uint64_t due = f->net.packets[i].due_ns;
      if (due <= f->net.now_ns)
        due = f->net.now_ns + MS;
      if (due < next)
        next = due;
    }
  for (unsigned i = 0; i < 2; i++) {
    int64_t deadline = transport_get_first_timeout(f->host[i].transport);
    uint64_t due = deadline == INT64_MAX ? UINT64_MAX : (uint64_t)deadline * MS;
    if (!deadline || due <= f->net.now_ns)
      due = f->net.now_ns + MS;
    if (due < next)
      next = due;
  }
  assert(next > f->net.now_ns && ++f->turns < 200000);
  sim_advance(&f->net, next - f->net.now_ns);
  assert(!f->endpoint[0].base.failed && !f->endpoint[1].base.failed);
  assert(f->net.count <= SIM_PACKETS &&
         f->net.bytes <= SIM_PACKETS * SIM_PACKET_SIZE);
}
static void advance(latency_fixture_t *f, unsigned ms) {
  uint64_t until = f->net.now_ns + ms * MS;
  while (f->net.now_ns < until)
    progress(f, until);
}
static void await_records(latency_fixture_t *f, unsigned count,
                          uint64_t until) {
  while (f->endpoint[f->receiver].received < count && f->net.now_ns < until)
    progress(f, until);
}
static latency_fixture_t *create(uint8_t flags, bool ipv6, bool client_source) {
  latency_fixture_t *f = calloc(1, sizeof(*f));
  assert(f);
  f->net.now_ns = 1000 * MS;
  f->ipv6 = ipv6;
  f->sender = client_source ? 1 : 0;
  f->receiver = 1 - f->sender;
  f->track = (moq_track_id_t){
      .type = MOQ_TRACK_DATA, .flags = flags, .name = "latency"};
  for (unsigned i = 0; i < 2; i++)
    f->endpoint[i].fixture = f;
  f->endpoint[0].base.server = true;
  transport_drive_host_t adapters[2] = {sim_host(&f->host[0], &f->net),
                                        sim_host(&f->host[1], &f->net)};
  transport_config_t cfg = {.bind_hosts = {ipv6 ? "::1" : "127.0.0.1"},
                            .num_bind_hosts = 1,
                            .port = 19929,
                            .callback = event,
                            .user_data = &f->endpoint[0],
                            .allow_insecure_peer = true,
                            .cert_file = "t/assets/server.crt",
                            .key_file = "t/assets/server.key",
                            .drive_host = &adapters[0],
                            .reconnect_enabled = true,
                            .reconnect_initial_delay_ms = 20,
                            .reconnect_max_delay_ms = 80};
  f->host[0].transport = f->endpoint[0].base.transport =
      transport_drive_create(&cfg);
  assert(f->host[0].transport);
  cfg.bind_hosts[0] = ipv6 ? "::2" : "127.0.0.2";
  cfg.remote_hosts[0] = ipv6 ? "::1" : "127.0.0.1";
  cfg.num_remote_hosts = 1;
  cfg.user_data = &f->endpoint[1];
  cfg.drive_host = &adapters[1];
  f->host[1].transport = f->endpoint[1].base.transport =
      transport_drive_create(&cfg);
  assert(f->host[1].transport);
  for (unsigned i = 0; i < 2000 && !f->endpoint[1].base.authenticated; i++)
    advance(f, 1);
  assert(f->endpoint[0].base.authenticated &&
         f->endpoint[1].base.authenticated);
  assert(transport_subscribe(f->host[f->receiver].transport, f->track));
  for (unsigned i = 0; i < 2000 && !f->endpoint[f->sender].base.subscriptions;
       i++)
    advance(f, 1);
  assert(f->endpoint[f->sender].base.subscriptions == 1);
  /* settle handshake and ACK traffic before faulting the first data flight */
  for (unsigned i = 0; i < 100; i++)
    advance(f, 1);
  return f;
}
static bool send_record(latency_fixture_t *f, unsigned id, size_t size) {
  assert(id < RECORDS && size <= MAX_BYTES);
  if (!f->attempted[id]) {
    f->attempted[id] = true;
    f->submitted[id] = f->net.now_ns;
    f->size[id] = size;
  }
  uint8_t data[MAX_BYTES];
  for (size_t i = 0; i < size; i++)
    data[i] = (uint8_t)(i + id * 17U);
  data[0] = (uint8_t)(id >> 24);
  data[1] = (uint8_t)(id >> 16);
  data[2] = (uint8_t)(id >> 8);
  data[3] = (uint8_t)id;
  moq_object_t obj = {.track_id = f->track,
                      .group_id = 1,
                      .object_id = id,
                      .data = data,
                      .size = size};
  transport_publish_result_t result =
      transport_publish_ex(f->host[f->sender].transport, &obj);
  if (result == TRANSPORT_PUBLISH_BACKPRESSURE) {
    f->blocked++;
    return false;
  }
  assert(result == TRANSPORT_PUBLISH_DELIVERED ||
         result == TRANSPORT_PUBLISH_BUFFERED);
  f->admitted[id] = f->net.now_ns;
  memset(data, 0, sizeof(data));
  return true;
}
static void flush(latency_fixture_t *f) {
  for (unsigned i = 0; i < 1000; i++) {
    if (transport_publish_flush(f->host[f->sender].transport))
      return;
    advance(f, 1);
  }
  assert(!"publication flush stalled");
}
static void destroy(latency_fixture_t *f) {
  for (unsigned i = 0; i < 2; i++) {
    transport_destroy(f->host[i].transport);
    f->host[i].transport = NULL;
    assert(f->host[i].opens == f->host[i].closes);
  }
  assert(!f->net.count && !f->net.bytes);
  free(f);
}
static void report(latency_fixture_t *f, const char *name, unsigned count,
                   unsigned budget_ms) {
  double worst = 0, latency_values[RECORDS];
  for (unsigned i = 0; i < count; i++) {
    assert(f->seen[i] && f->delivered[i] >= f->admitted[i]);
    double latency = (f->delivered[i] - f->submitted[i]) / (double)MS;
    latency_values[i] = latency;
    if (latency > worst)
      worst = latency;
  }
  assert(worst <= budget_ms);
  assert(!f->endpoint[f->receiver].lost);
  for (unsigned i = 1; i < count; i++) {
    double value = latency_values[i];
    unsigned j = i;
    while (j && latency_values[j - 1] > value) {
      latency_values[j] = latency_values[j - 1];
      j--;
    }
    latency_values[j] = value;
  }
  printf("{\"case\":\"%s\",\"flags\":%u,\"ip\":%u,\"seed\":%u,\"records\":%u,"
         "\"one_way_ms\":%.3f,"
         "\"p50_ms\":%.3f,\"p95_ms\":%.3f,\"p99_ms\":%.3f,\"max_ms\":%.3f,"
         "\"budget_ms\":%u,"
         "\"drops\":%zu,\"partial\":%zu,\"peak_packets\":%zu,\"peak_bytes\":%"
         "zu,\"turns\":%zu}\n",
         name, f->track.flags, f->ipv6 ? 6 : 4, f->seed, count,
         f->net.delay_ns / (double)MS,
         latency_values[(count * 50 + 99) / 100 - 1],
         latency_values[(count * 95 + 99) / 100 - 1],
         latency_values[(count * 99 + 99) / 100 - 1], worst, budget_ms,
         f->net.dropped, f->net.partial, f->net.peak_count, f->net.peak_bytes,
         f->turns);
  for (unsigned i = 0; i < 100; i++)
    advance(f, 1);
  assert(f->endpoint[f->receiver].received == count);
}
static void tail(uint8_t flags, bool loss, bool ipv6, unsigned delay_ms) {
  latency_fixture_t *f = create(flags, ipv6, false);
  f->net.delay_ns = delay_ms * MS;
  if (loss)
    f->host[0].drop_until_ns = f->net.now_ns + 20 * MS;
  assert(send_record(f, 0, MAX_BYTES));
  flush(f);
  unsigned limit = flags == 0 && loss ? 900 : 1000;
  await_records(f, 1, f->submitted[0] + limit * MS);
  if (loss)
    assert(f->net.dropped);
  if (!flags && loss) {
    assert(!f->seen[0]);
    puts("{\"case\":\"unreliable-loss-control\",\"records\":0}");
  } else {
    unsigned budget =
        loss ? (flags == MOQ_TRACK_FLAG_RELIABLE ? (delay_ms == 1 ? 150 : 300)
                                                 : (delay_ms == 1 ? 750 : 1000))
             : 10;
    report(f, loss ? "tail-loss" : "baseline", 1, budget);
    if (loss) {
      assert(f->delivered[0] - f->submitted[0] >= 20 * MS);
      if (flags & MOQ_TRACK_FLAG_FEC_RATELESS) {
        transport_stats_t stats;
        assert(transport_get_stats(f->host[1].transport, &stats));
        assert(stats.repair_whole_object_requests_sent);
      }
    }
  }
  destroy(f);
}
static void burst(uint8_t flags, uint32_t seed, bool ipv6) {
  latency_fixture_t *f = create(flags, ipv6, false);
  f->net.delay_ns = 5 * MS;
  f->net.jitter_ns = 3 * MS;
  f->net.rng = seed;
  f->seed = seed;
  f->net.loss_per_mille = 10;
  f->net.reorder = 1;
  f->host[0].drop_until_ns = f->net.now_ns + 8 * MS;
  f->host[0].max_accept = 1;
  unsigned sent = 0;
  for (unsigned i = 0; i < 2000 && sent < RECORDS; i++) {
    if (send_record(f, sent, sent % 2 ? MAX_BYTES : 512))
      sent++;
    advance(f, 1);
  }
  assert(sent == RECORDS);
  flush(f);
  await_records(f, RECORDS, f->net.now_ns + 2000 * MS);
  assert(f->net.dropped && f->net.partial);
  report(f, "seeded-burst", RECORDS,
         flags == MOQ_TRACK_FLAG_RELIABLE ? 300 : 1250);
  destroy(f);
}
static void blocked_output(void) {
  latency_fixture_t *f = create(MOQ_TRACK_FLAG_RELIABLE, false, false);
  f->host[0].blocked = true;
  assert(send_record(f, 0, 512));
  for (unsigned i = 0; i < 40; i++)
    advance(f, 1);
  assert(!f->seen[0] && f->host[0].transport->sockets[0].egress.count);
  f->host[0].blocked = false;
  for (unsigned i = 0; i < 100 && !f->seen[0]; i++)
    advance(f, 1);
  assert(f->delivered[0] - f->submitted[0] >= 40 * MS);
  report(f, "blocked-output", 1, 100);
  destroy(f);
}
static void fixed_repair(void) {
  latency_fixture_t *f = create(MOQ_TRACK_FLAG_FEC_ENABLED, true, false);
  for (unsigned i = 0; i < 4; i++)
    assert(send_record(f, i, 512));
  flush(f);
  f->host[0].drop_next = 1;
  f->host[0].max_accept = 1;
  await_records(f, 4, f->net.now_ns + 100 * MS);
  assert(f->net.dropped);
  transport_stats_t stats;
  assert(transport_get_stats(f->host[1].transport, &stats));
  assert(stats.fec_objects_decoded);
  report(f, "fixed-parity-repair", 4, 100);
  destroy(f);
}
static void reconnect(void) {
  latency_fixture_t *f = create(MOQ_TRACK_FLAG_RELIABLE, false, true);
  transport_t *client = f->host[1].transport;
  transport_drive_path_t path;
  assert(transport_drive_paths(client, &path, 1) == 1);
  uint32_t old_connection =
      transport_get_conn_id(client, f->endpoint[1].base.conn);
  f->host[1].blocked = true;
  assert(send_record(f, 0, 512));
  advance(f, 1);
  assert(client->sockets[0].egress.count && !f->seen[0]);
  f->planned_disconnect = true;
  assert(transport_drive_interface(client, false, &path.local,
                                   path.interface_index, "sim"));
  assert(f->endpoint[1].disconnected == 1 && !client->socket_count);
  assert(transport_drive_interface(client, true, &path.local,
                                   path.interface_index, "sim"));
  transport_drive_path_t returned;
  assert(transport_drive_paths(client, &returned, 1) == 1 &&
         returned.id != path.id);
  f->host[1].blocked = false;
  uint64_t started = f->net.now_ns, until = started + 300 * MS;
  while (!f->endpoint[1].base.authenticated && f->net.now_ns < until)
    progress(f, until);
  assert(f->endpoint[1].base.authenticated);
  assert(transport_get_conn_id(client, f->endpoint[1].base.conn) !=
         old_connection);
  assert(transport_subscribe_conn(f->host[0].transport,
                                  f->endpoint[0].base.conn, f->track));
  while (!f->endpoint[1].base.subscriptions && f->net.now_ns < until)
    progress(f, until);
  assert(f->endpoint[1].base.subscriptions && !f->seen[0]);
  f->first_record = 1;
  assert(send_record(f, 1, 512));
  await_records(f, 1, until);
  assert(f->seen[1] && !f->seen[0] && f->delivered[1] - started <= 300 * MS);
  printf("{\"case\":\"reconnect-no-replay\",\"return_to_record_ms\":%.3f,"
         "\"budget_ms\":300}\n",
         (f->delivered[1] - started) / (double)MS);
  advance(f, 100);
  assert(f->endpoint[0].received == 1 && !f->seen[0]);
  destroy(f);
}

int main(void) {
  tail(0, false, false, 1);
  tail(MOQ_TRACK_FLAG_RELIABLE, false, false, 1);
  tail(MOQ_TRACK_FLAG_FEC_RATELESS, false, true, 1);
  tail(0, true, false, 1);
  tail(MOQ_TRACK_FLAG_RELIABLE, true, false, 1);
  tail(MOQ_TRACK_FLAG_FEC_RATELESS, true, false, 1);
  tail(MOQ_TRACK_FLAG_RELIABLE, true, false, 5);
  tail(MOQ_TRACK_FLAG_FEC_RATELESS, true, false, 5);
  tail(MOQ_TRACK_FLAG_RELIABLE, true, false, 25);
  tail(MOQ_TRACK_FLAG_FEC_RATELESS, true, false, 25);
  blocked_output();
  fixed_repair();
  reconnect();
  for (uint32_t seed = 1; seed <= 3; seed++) {
    burst(MOQ_TRACK_FLAG_RELIABLE, seed, seed == 3);
    burst(MOQ_TRACK_FLAG_FEC_RATELESS, seed, seed == 3);
  }
  puts("===RECOVERY LATENCY OK===");
}
