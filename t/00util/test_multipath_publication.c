#include "transport_fixture.h"
#include "transport_paths.h"

#include <stdio.h>

static void create_shared_socket(transport_fixture_t *f, size_t paths[2]) {
  memset(f, 0, sizeof(*f));
  f->server.server = true;
  transport_config_t config = {.bind_hosts = {"127.84.1.1"},
                               .num_bind_hosts = 1,
                               .port = 19876,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .allow_insecure_peer = true,
                               .callback = fixture_event,
                               .user_data = &f->server};
  f->server.transport = transport_create(&config);
  assert(f->server.transport);
  config.bind_hosts[0] = "127.84.1.2";
  config.bind_hosts[1] = "127.84.2.2";
  config.num_bind_hosts = 2;
  config.remote_hosts[0] = "127.84.1.1";
  config.num_remote_hosts = 1;
  config.user_data = &f->client;
  f->client.transport = transport_create(&config);
  assert(f->client.transport);

  size_t count = 0;
  for (size_t attempt = 0; attempt < 2000; attempt++) {
    fixture_tick(f);
    count = 0;
    if (f->server.authenticated && f->client.authenticated)
      for (size_t path = 0; path < TRANSPORT_MAX_QUIC_PATHS && count < 2;
           path++) {
        quicly_path_health_t health;
        if (quicly_get_path_health(f->server.conn->quic, path, &health) == 0 &&
            health.validated && !health.abandoned && !health.probe_only &&
            health.state == QUICLY_PATH_USABLE)
          paths[count++] = path;
      }
    if (count == 2)
      break;
  }
  assert(f->server.transport->socket_count == 1 && count == 2);
}

static void update_measurements(transport_fixture_t *f) {
  f->server.transport->last_pathflow_update = 0;
  transport_tick(f->server.transport);
}

int main(void) {
  transport_fixture_t f;
  size_t paths[2];
  create_shared_socket(&f, paths);
  moq_track_id_t track = {.type = MOQ_TRACK_VIDEO,
                          .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                          .name = "native-path-history"};
  fixture_subscribe(&f, &f.client, track);
  for (size_t i = 0; i < 100; i++)
    fixture_tick(&f);

  transport_conn_path_t *physical = &f.server.conn->paths[0];
  quicly_path_stats_t stats;
  assert(transport_path_get_eligible_by_local(
             f.server.conn->quic, &f.server.transport->sockets[0].local_addr,
             &stats) == paths[0]);

  /* A reply from a second remote path must not become the first path's OWD
   * through their shared physical EWMA. The matching-path control still uses
   * the same two-second queue-delay observation. */
  physical->state = (path_state_t){0};
  physical->owd_initialized = true;
  physical->telemetry_path = paths[1];
  physical->latest_owd_fp = FP_FROM_INT(2);
  update_measurements(&f);
  assert(physical->measurement.quic_path == paths[0]);
  assert(physical->state.l_ewma < FP_ONE);
  physical->state = (path_state_t){0};
  physical->telemetry_path = paths[0];
  update_measurements(&f);
  assert(physical->state.l_ewma >= FP_FROM_INT(2));
  physical->owd_initialized = false;

  /* When native measurement ownership changes, old loss and latency history
   * must reset along with its counters rather than survive in the new EWMA. */
  physical->measurement.quic_path = paths[1];
  physical->state = (path_state_t){.b_ewma = FP_ONE,
                                   .l_ewma = FP_FROM_INT(5),
                                   .p_ewma = FP_ONE,
                                   .initialized = true};
  update_measurements(&f);
  assert(physical->measurement.quic_path == paths[0]);
  assert(physical->state.p_ewma < FP_ONE / 2);
  assert(physical->state.l_ewma < FP_ONE);

  /* Publish immediately after the first native path retires, before periodic
   * measurement can switch ownership. Its 100% loss history must not prevent
   * admission of a coded object on the independently healthy alternate. */
  physical->state = (path_state_t){.b_ewma = FP_ONE,
                                   .l_ewma = FP_FROM_INT(5),
                                   .p_ewma = FP_ONE,
                                   .initialized = true};
  physical->budget = (transport_path_budget_t){0};
  physical->owd_initialized = true;
  physical->telemetry_path = paths[0];
  physical->latest_owd_fp = FP_FROM_INT(2);
  quicly_path_health_t health;
  assert(quicly_get_path_health(f.server.conn->quic, paths[0], &health) == 0);
  assert(quicly_abandon_path(f.server.conn->quic, health.path_id, 0) == 0);
  assert(transport_path_get_eligible_by_local(
             f.server.conn->quic, &f.server.transport->sockets[0].local_addr,
             &stats) == paths[1]);
  uint8_t payload[2000];
  memset(payload, 0x5a, sizeof(payload));
  moq_object_t object = {.track_id = track,
                         .group_id = 1,
                         .object_id = 0,
                         .data = payload,
                         .size = sizeof(payload)};
  /* An explicit physical override still governs its alternate native path.
   * Only automatic measurements must be kept separate. */
  physical->state_overridden = true;
  update_measurements(&f);
  assert(physical->state.p_ewma == FP_ONE &&
         physical->measurement.quic_path == paths[0]);
  assert(transport_publish_ex(f.server.transport, &object) !=
         TRANSPORT_PUBLISH_DELIVERED);
  physical->state_overridden = false;
  assert(transport_publish_ex(f.server.transport, &object) ==
         TRANSPORT_PUBLISH_DELIVERED);
  assert(quicly_get_num_datagram_frames_path(f.server.conn->quic, paths[1]) >
         0);
  assert(physical->budget.rate > FP_ONE);
  update_measurements(&f);
  assert(physical->measurement.initialized &&
         physical->measurement.quic_path == paths[1]);
  assert(physical->state.p_ewma < FP_ONE / 2);
  assert(physical->state.l_ewma < FP_ONE);
  fixture_receive(&f, &f.client, 1);
  assert(f.client.payload_size == sizeof(payload) &&
         memcmp(f.client.payload, payload, sizeof(payload)) == 0);
  fixture_destroy(&f);
  puts("===MULTIPATH PUBLICATION OK===");
  return 0;
}
