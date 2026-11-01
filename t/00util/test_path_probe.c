#include "transport_fixture.h"
#include "transport_probe.h"
#include "transport_sim_host.h"
#include <stdio.h>
#include <stdlib.h>

/* Controlled native snapshots exercise states that cannot be held stable by
 * a real peer, without altering the production library or native dependency. */
static struct {
  quicly_path_health_t health;
  quicly_path_stats_t stats;
  bool exists, available, eligible;
  unsigned requests;
} samples[TRANSPORT_MAX_QUIC_PATHS];
static bool confirmed;
static int request_result;
static int sample_stats(quicly_conn_t *quic, quicly_stats_t *stats) {
  (void)quic;
  *stats =
      (quicly_stats_t){.handshake_confirmed_msec = confirmed ? 0 : UINT64_MAX};
  return 0;
}
static int sample_health(quicly_conn_t *quic, size_t path,
                         quicly_path_health_t *health) {
  (void)quic;
  *health = samples[path].health;
  return samples[path].exists ? 0 : -1;
}
static int sample_path_stats(quicly_conn_t *quic, size_t path,
                             quicly_path_stats_t *stats) {
  (void)quic;
  *stats = samples[path].stats;
  return samples[path].exists ? 0 : -1;
}
static int sample_available(quicly_conn_t *quic, size_t path) {
  (void)quic;
  return samples[path].available;
}
static int sample_eligible(quicly_path_scheduler_t *scheduler,
                           quicly_conn_t *quic, size_t path) {
  (void)scheduler;
  (void)quic;
  return samples[path].eligible;
}
static int sample_request(quicly_conn_t *quic, size_t path) {
  (void)quic;
  samples[path].requests++;
  return request_result;
}
#define quicly_get_stats sample_stats
#define quicly_get_path_health sample_health
#define quicly_get_path_stats sample_path_stats
#define quicly_is_path_available sample_available
#define quicly_request_path_probe sample_request
#define transport_probe_tick sample_probe_tick
#define transport_probe_deadline sample_probe_deadline
#include "../../src/common/transport_probe.c"
#undef transport_probe_deadline
#undef transport_probe_tick
#undef quicly_request_path_probe
#undef quicly_is_path_available
#undef quicly_get_path_stats
#undef quicly_get_path_health
#undef quicly_get_stats

static void test_probe_policy(void) {
  transport_t *t = calloc(1, sizeof(*t));
  transport_conn_t *conn = calloc(1, sizeof(*conn));
  assert(t && conn);
  struct _st_quicly_conn_public_t quic = {.state = QUICLY_STATE_CONNECTED};
  quicly_path_scheduler_t scheduler = {.is_path_eligible = sample_eligible};
  t->quic_ctx.path_scheduler = &scheduler;
  conn->transport = t;
  conn->quic = (quicly_conn_t *)&quic;
  conn->quic_ready = true;
  samples[0].exists = samples[0].available = samples[0].eligible = true;
  samples[0].health.validated = true;
  samples[0].stats.local.sin.sin_family = AF_INET;
  samples[0].stats.remote.sin.sin_family = AF_INET;

  assert(sample_probe_deadline(conn, 0) == INT64_MAX);
  sample_probe_tick(conn, 100);
  assert(samples[0].requests == 0);
  t->path_probe_interval_ms = 100;
  assert(sample_probe_deadline(conn, 0) == INT64_MAX);
  confirmed = true;
  assert(sample_probe_deadline(conn, 0) == 100);

  /* ACK-only sends and incoming packets must not postpone our liveness. */
  samples[0].stats.sent = samples[0].stats.received = 20;
  assert(sample_probe_deadline(conn, 75) == 100);
  sample_probe_tick(conn, 99);
  assert(samples[0].requests == 0);
  sample_probe_tick(conn, 100);
  sample_probe_tick(conn, 100);
  assert(samples[0].requests == 1);
  assert(sample_probe_deadline(conn, 100) == 200);
  request_result = -1;
  sample_probe_tick(conn, 200);
  assert(samples[0].requests == 2);
  assert(sample_probe_deadline(conn, 201) == 300);
  request_result = 0;

  /* Existing ACK-eliciting flight and ordinary PTOs own recovery. A leftover
   * negative speculative count cannot suppress probes after flight drains. */
  samples[0].stats.bytes_in_flight = 1000;
  sample_probe_tick(conn, 300);
  assert(sample_probe_deadline(conn, 300) == INT64_MAX);
  samples[0].stats.bytes_in_flight = 0;
  samples[0].health.pto_count = 2;
  assert(sample_probe_deadline(conn, 350) == INT64_MAX);
  samples[0].health.pto_count = -1;
  sample_probe_tick(conn, 400);
  assert(sample_probe_deadline(conn, 400) == 450);
  assert(samples[0].requests == 2);
  samples[0].health.pto_count = 0;
  samples[0].stats.bytes_acked = 1000;
  assert(sample_probe_deadline(conn, 450) == 550);
  sample_probe_tick(conn, 549);
  assert(samples[0].requests == 2);
  sample_probe_tick(conn, 550);
  assert(samples[0].requests == 3);

  /* An independently idle path is not postponed by traffic on path zero. */
  samples[1] = samples[0];
  samples[1].health.path_id = 1;
  samples[1].requests = 0;
  assert(sample_probe_deadline(conn, 600) == 650);
  samples[0].stats.bytes_in_flight = 100;
  sample_probe_tick(conn, 700);
  assert(samples[0].requests == 3 && samples[1].requests == 1);
  samples[1].exists = false;
  assert(sample_probe_deadline(conn, 700) == INT64_MAX);
  samples[0].stats.bytes_in_flight = 0;

  /* Slot reuse and migration both discard the previous path's timer. */
  samples[0].health.path_id++;
  assert(sample_probe_deadline(conn, 900) == 1000);
  samples[0].stats.remote.sin.sin_port = htons(1234);
  assert(sample_probe_deadline(conn, 950) == 1050);
  samples[0].exists = false;
  assert(sample_probe_deadline(conn, 1000) == INT64_MAX);
  samples[0].exists = true;
  assert(sample_probe_deadline(conn, 1100) == 1200);

  samples[0].health.state = QUICLY_PATH_SUSPECT;
  sample_probe_tick(conn, 1200);
  assert(sample_probe_deadline(conn, 1200) == INT64_MAX);
  samples[0].health.state = QUICLY_PATH_RECOVERING;
  assert(sample_probe_deadline(conn, 1200) == INT64_MAX);
  samples[0].health.state = QUICLY_PATH_USABLE;
  assert(sample_probe_deadline(conn, 1300) == 1400);
  samples[0].eligible = false;
  assert(sample_probe_deadline(conn, 1400) == INT64_MAX);
  samples[0].eligible = true;
  samples[0].available = false;
  assert(sample_probe_deadline(conn, 1400) == INT64_MAX);
  samples[0].available = true;
  samples[0].health.abandoned = true;
  assert(sample_probe_deadline(conn, 1400) == INT64_MAX);
  samples[0].health.abandoned = false;
  samples[0].health.probe_only = true;
  assert(sample_probe_deadline(conn, 1400) == INT64_MAX);
  samples[0].health.probe_only = false;
  samples[0].health.validated = false;
  assert(sample_probe_deadline(conn, 1400) == INT64_MAX);
  samples[0].health.validated = true;
  assert(sample_probe_deadline(conn, INT64_MAX - 20) == INT64_MAX);
  sample_probe_tick(conn, INT64_MAX);
  assert(samples[0].requests == 3);
  conn->path_probes[0].active = false;
  assert(sample_probe_deadline(conn, 1500) == 1600);
  t->socket_count = 1;
  /* A full local output queue cannot leave an unsendable native probe due. */
  sample_probe_tick(conn, 1600);
  assert(samples[0].requests == 3);
  assert(sample_probe_deadline(conn, 1600) == 1700);
  t->socket_count = 0;
  t->shutting_down = true;
  assert(sample_probe_deadline(conn, 1500) == INT64_MAX);
  free(conn);
  free(t);
}

typedef struct {
  sim_network_t network;
  sim_node_t hosts[2];
  fixture_endpoint_t endpoints[2];
} probe_fixture_t;

static void advance(probe_fixture_t *f, unsigned duration) {
  for (unsigned ms = 0; ms < duration; ms++) {
    for (size_t i = 0; i < 2; i++) {
      int64_t deadline = transport_get_first_timeout(f->hosts[i].transport);
      assert(transport_get_first_timeout(f->hosts[i].transport) == deadline);
    }
    sim_advance(&f->network, 1000000U);
    assert(!f->endpoints[0].failed && !f->endpoints[1].failed);
  }
}

static void test_native_probes(bool enabled, bool multipath) {
  probe_fixture_t *f = calloc(1, sizeof(*f));
  assert(f);
  f->network.now_ns = UINT64_C(1000000000);
  f->endpoints[0].server = true;
  transport_drive_host_t hosts[2] = {sim_host(&f->hosts[0], &f->network),
                                     sim_host(&f->hosts[1], &f->network)};
  transport_config_t config = {.bind_hosts = {"127.90.1.1"},
                               .num_bind_hosts = 1,
                               .port = 19846,
                               .quic_idle_timeout_ms = enabled ? 300 : 30000,
                               .allow_insecure_peer = true,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .callback = fixture_event,
                               .user_data = &f->endpoints[0],
                               .drive_host = &hosts[0]};
  f->hosts[0].transport = f->endpoints[0].transport =
      transport_drive_create(&config);
  assert(f->hosts[0].transport);
  config.bind_hosts[0] = "127.90.1.2";
  config.bind_hosts[1] = "127.90.2.2";
  config.num_bind_hosts = multipath ? 2 : 1;
  config.remote_hosts[0] = "127.90.1.1";
  config.num_remote_hosts = 1;
  config.user_data = &f->endpoints[1];
  config.drive_host = &hosts[1];
  config.path_probe_interval_ms = enabled ? 100 : 0;
  f->hosts[1].transport = f->endpoints[1].transport =
      transport_drive_create(&config);
  assert(f->hosts[1].transport);
  /* PMTUD emits its own PINGs. Isolate liveness cadence from that independent
   * policy so the disabled case and per-path probe counts remain meaningful. */
  f->hosts[0].transport->quic_ctx.egress[0].enable_pmtud = 0;
  f->hosts[1].transport->quic_ctx.egress[0].enable_pmtud = 0;
  advance(f, 500);
  assert(f->endpoints[0].authenticated && f->endpoints[1].authenticated);
  transport_conn_t *conn = f->endpoints[1].conn;
  quicly_stats_t before, after;
  assert(quicly_get_stats(conn->quic, &before) == 0);
  size_t indices[2], count = multipath ? 2 : 1;
  uint64_t acked[2];
  for (size_t i = 0; i < count; i++) {
    quicly_path_stats_t stats;
    indices[i] = transport_path_get_stats_by_local(
        conn->quic, &f->hosts[1].paths[i].local, &stats);
    assert(indices[i] != SIZE_MAX);
    acked[i] = stats.acked;
  }
  /* Both timeout reads and sends use the supplied monotonic clock. Enabled
   * probes also keep the session alive beyond its 300 ms idle timeout. */
  advance(f, 1000);
  assert(quicly_get_stats(conn->quic, &after) == 0);
  uint64_t probes =
      after.num_frames_sent.ping + after.num_frames_sent.immediate_ack -
      before.num_frames_sent.ping - before.num_frames_sent.immediate_ack;
  assert(enabled ? probes >= count && probes <= count * 12 : probes == 0);
  for (size_t i = 0; i < count; i++) {
    quicly_path_stats_t stats;
    assert(quicly_get_path_stats(conn->quic, indices[i], &stats) == 0);
    assert(enabled ? stats.acked > acked[i] : stats.acked == acked[i]);
  }
  transport_destroy(f->hosts[1].transport);
  transport_destroy(f->hosts[0].transport);
  free(f);
}

int main(void) {
  test_probe_policy();
  test_native_probes(false, false);
  test_native_probes(true, false);
  test_native_probes(true, true);
  puts("===PATH PROBE OK===");
  return 0;
}
