#include "transport_fixture.h"
#include "transport_publish.h"
#include "transport_sim_host.h"
#include "transport_stream.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct {
  fixture_endpoint_t endpoint;
  size_t lost;
  uint64_t lost_object_id;
  bool unsubscribe_on_loss;
} deadline_endpoint_t;

typedef struct {
  sim_network_t net;
  sim_node_t nodes[3];
  deadline_endpoint_t endpoints[3];
  size_t count;
} deadline_fixture_t;

static void deadline_event(void *data, const transport_event_t *event) {
  deadline_endpoint_t *endpoint = data;
  if (event->type == TRANSPORT_EVENT_OBJECT_LOST) {
    endpoint->lost++;
    endpoint->lost_object_id = event->object.object_id;
    if (endpoint->unsubscribe_on_loss)
      assert(
          transport_unsubscribe(endpoint->endpoint.transport, event->track_id));
  }
  fixture_event(&endpoint->endpoint, event);
}

static void advance(deadline_fixture_t *f, unsigned milliseconds) {
  for (unsigned i = 0; i < milliseconds; i++)
    sim_advance(&f->net, 1000000);
  for (size_t i = 0; i < f->count; i++)
    assert(!f->endpoints[i].endpoint.failed);
}

static deadline_fixture_t *create_fixture(size_t count) {
  deadline_fixture_t *f = calloc(1, sizeof(*f));
  assert(f && count <= 3);
  f->count = count;
  f->net.now_ns = 1000000000;
  const char *addresses[] = {"127.0.0.1", "127.0.0.2", "127.0.0.3"};
  for (size_t i = 0; i < count; i++) {
    transport_drive_host_t host = sim_host(&f->nodes[i], &f->net);
    f->endpoints[i].endpoint.server = i == 0;
    transport_config_t config = {.bind_hosts = {addresses[i]},
                                 .num_bind_hosts = 1,
                                 .port = 19938,
                                 .callback = deadline_event,
                                 .user_data = &f->endpoints[i],
                                 .allow_insecure_peer = true,
                                 .cert_file = "t/assets/server.crt",
                                 .key_file = "t/assets/server.key",
                                 .drive_host = &host};
    if (i) {
      config.remote_hosts[0] = addresses[0];
      config.num_remote_hosts = 1;
    }
    f->nodes[i].transport = f->endpoints[i].endpoint.transport =
        transport_drive_create(&config);
    assert(f->nodes[i].transport);
  }
  advance(f, 1000);
  for (size_t i = 0; i < count; i++)
    assert(f->endpoints[i].endpoint.authenticated);
  return f;
}

static void destroy_fixture(deadline_fixture_t *f) {
  for (size_t i = f->count; i > 0; i--)
    transport_destroy(f->nodes[i - 1].transport);
  free(f);
}

static void subscribe(deadline_fixture_t *f, moq_track_id_t track) {
  for (size_t i = 1; i < f->count; i++)
    assert(transport_subscribe(f->nodes[i].transport, track));
  advance(f, 100);
}

static void set_age(transport_t *t, const moq_track_id_t *track, uint32_t age,
                    bool reactive) {
  qlinq_repair_policy_t policy = {.present = QLINQ_REPAIR_MAX_AGE |
                                             QLINQ_REPAIR_REACTIVE,
                                  .max_object_age_ms = age,
                                  .reactive_repair = reactive};
  assert(transport_set_track_repair_policy(t, track, &policy));
}

/* Advance deadlines without running a timer that would flush the group. */
static void age_group(deadline_fixture_t *f, unsigned milliseconds) {
  f->net.now_ns += (uint64_t)milliseconds * 1000000;
  for (size_t i = 0; i < f->count; i++)
    assert(transport_drive_time(f->nodes[i].transport, f->net.now_ns));
}

static void test_unsent_expiry(bool attempted, bool receiver_pressure) {
  deadline_fixture_t *f = create_fixture(2);
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                          .name = "unsent-expiry"};
  subscribe(f, track);
  transport_t *sender = f->nodes[0].transport;
  transport_t *receiver = f->nodes[1].transport;
  set_age(sender, &track, 25, true);
  assert(transport_mock_path_state(sender, 0, 100000, 2000, 0));
  uint8_t bytes[100] = {42};
  moq_object_t object = {
      .track_id = track, .data = bytes, .size = sizeof(bytes)};
  assert(transport_publish_ex(sender, &object) == TRANSPORT_PUBLISH_BUFFERED);
  assert(!sender->pending_group.pending);
  if (attempted)
    assert(!transport_publish_flush_grouped(sender));
  assert(sender->sent_cache.count == 0);
  age_group(f, 100);
  assert(transport_mock_path_state(sender, 0, 100000, 5, 0));

  size_t sender_limit = sender->limits.max_stream_egress_bytes;
  sender->limits.max_stream_egress_bytes = 1;
  assert(!transport_publish_flush_grouped(sender));
  assert(sender->pending_group.retiring && sender->pending_group.size != 0);
  /* Once retirement begins, relaxing the policy cannot resend those bytes. */
  set_age(sender, &track, 0, true);
  sender->limits.max_stream_egress_bytes = sender_limit;
  size_t receiver_limit = receiver->limits.max_stream_egress_bytes;
  if (receiver_pressure)
    receiver->limits.max_stream_egress_bytes = 1;
  assert(transport_publish_flush_grouped(sender));
  assert(sender->pending_group.size == 0 && sender->sent_cache.count == 0);
  assert(sender->stats.publish_delivered == 0);
  advance(f, 100);
  if (receiver_pressure) {
    assert(f->endpoints[1].lost == 0);
    receiver->limits.max_stream_egress_bytes = receiver_limit;
    advance(f, 500);
  }
  assert(f->endpoints[1].lost == 1 && f->endpoints[1].lost_object_id == 0 &&
         f->endpoints[1].endpoint.objects == 0);
  assert(sender->stats.recovery_checkpoint_acks_received != 0);
  set_age(sender, &track, 25, true);
  assert(transport_publish_ex(sender, &object) == TRANSPORT_PUBLISH_BUFFERED);
  assert(transport_publish_flush(sender));
  advance(f, 100);
  assert(f->endpoints[1].endpoint.objects == 1 && f->endpoints[1].lost == 1);
  assert(sender->sent_cache.count == 0);
  destroy_fixture(f);
}

static void test_partial_expiry(void) {
  deadline_fixture_t *f = create_fixture(3);
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                          .name = "partial-expiry"};
  subscribe(f, track);
  transport_t *sender = f->nodes[0].transport;
  set_age(sender, &track, 25, true);
  assert(transport_mock_path_state(sender, 0, 100000, 2000, 0));
  sender->conns[0]->paths[0].state.l_ewma = FP_FROM_FLOAT(0.005f);
  uint8_t bytes[100] = {7};
  moq_object_t object = {
      .track_id = track, .data = bytes, .size = sizeof(bytes)};
  assert(transport_publish_ex(sender, &object) == TRANSPORT_PUBLISH_BUFFERED);
  assert(!transport_publish_flush_grouped(sender));
  assert(sender->conns[0]->fec_group_delivered &&
         !sender->conns[1]->fec_group_delivered &&
         sender->sent_cache.count == 1);
  advance(f, 10);
  assert(f->endpoints[1].endpoint.objects + f->endpoints[2].endpoint.objects ==
         1);
  /* A retained object's original deadline survives subsequent policy edits. */
  set_age(sender, &track, 0, true);
  age_group(f, 100);
  assert(transport_mock_path_state(sender, 0, 100000, 5, 0));
  size_t limit = sender->limits.max_stream_egress_bytes;
  sender->limits.max_stream_egress_bytes = 1;
  assert(!transport_publish_flush_grouped(sender));
  assert(sender->pending_group.retiring && sender->sent_cache.count == 1);
  sender->limits.max_stream_egress_bytes = limit;
  assert(transport_publish_flush_grouped(sender));
  assert(sender->pending_group.size == 0 && sender->sent_cache.count == 1);
  assert(sender->stats.publish_delivered == 0);
  advance(f, 100);
  assert(sender->sent_cache.count == 0);
  for (size_t i = 1; i < f->count; i++)
    assert(f->endpoints[i].endpoint.objects + f->endpoints[i].lost == 1);
  assert(f->endpoints[1].lost + f->endpoints[2].lost == 1);
  assert(transport_publish_ex(sender, &object) == TRANSPORT_PUBLISH_BUFFERED);
  assert(transport_publish_flush(sender));
  advance(f, 100);
  assert(f->endpoints[1].endpoint.objects + f->endpoints[2].endpoint.objects ==
         3);
  destroy_fixture(f);
}

static void test_fixed_expiry(bool reactive) {
  deadline_fixture_t *f = create_fixture(2);
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                          .name = "fixed-expiry"};
  subscribe(f, track);
  transport_t *sender = f->nodes[0].transport;
  set_age(sender, &track, 25, reactive);
  uint8_t bytes[100] = {9};
  moq_object_t object = {
      .track_id = track, .data = bytes, .size = sizeof(bytes)};
  assert(transport_mock_path_state(sender, 0, 100000, 5, 0));
  assert(transport_publish_ex(sender, &object) == TRANSPORT_PUBLISH_BUFFERED);
  assert(transport_publish_flush_grouped(sender));
  advance(f, 10);
  assert(f->endpoints[1].endpoint.objects == 1);
  assert(sender->sent_cache.count == (reactive ? 1U : 0U));
  assert(transport_mock_path_state(sender, 0, 100000, 2000, 0));
  assert(transport_publish_ex(sender, &object) == TRANSPORT_PUBLISH_BUFFERED);
  assert(!transport_publish_flush_grouped(sender));
  assert(sender->sent_cache.count == (reactive ? 2U : 0U));
  age_group(f, 100);
  assert(transport_publish_flush_grouped(sender));
  assert(!sender->pending_group.size);
  assert(sender->sent_cache.count == (reactive ? 1U : 0U));
  if (reactive)
    assert(transport_sent_cache_find(&sender->sent_cache, &track, 0, 0));
  assert(!transport_sent_cache_find(&sender->sent_cache, &track, 0, 1));
  assert(transport_mock_path_state(sender, 0, 100000, 5, 0));
  assert(transport_publish_ex(sender, &object) == TRANSPORT_PUBLISH_BUFFERED);
  assert(transport_publish_flush_grouped(sender));
  advance(f, 100);
  assert(f->endpoints[1].endpoint.objects == 2);
  destroy_fixture(f);
}

static void test_unrelated_publication(void) {
  deadline_fixture_t *f = create_fixture(2);
  moq_track_id_t data = {.type = MOQ_TRACK_DATA,
                         .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                         .name = "older-data"};
  moq_track_id_t video = {.type = MOQ_TRACK_VIDEO,
                          .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                          .name = "fresh-video"};
  subscribe(f, data);
  subscribe(f, video);
  transport_t *sender = f->nodes[0].transport;
  set_age(sender, &data, 1000, true);
  set_age(sender, &video, 25, false);
  assert(transport_mock_path_state(sender, 0, 100000, 2000, 0));
  uint8_t bytes[100] = {11};
  moq_object_t object = {
      .track_id = data, .data = bytes, .size = sizeof(bytes)};
  assert(transport_publish_ex(sender, &object) == TRANSPORT_PUBLISH_BUFFERED);
  assert(!transport_publish_flush_grouped(sender));
  age_group(f, 100);
  assert(transport_mock_path_state(sender, 0, 100000, 5, 0));
  object.track_id = video;
  assert(transport_publish_ex(sender, &object) == TRANSPORT_PUBLISH_DELIVERED);
  assert(sender->pending_group.size != 0);
  assert(transport_publish_flush(sender));
  advance(f, 100);
  assert(f->endpoints[1].endpoint.objects == 2 && f->endpoints[1].lost == 0);
  destroy_fixture(f);
}

static void test_expired_before_append(void) {
  deadline_fixture_t *f = create_fixture(2);
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                          .name = "expired-before-append"};
  subscribe(f, track);
  transport_t *sender = f->nodes[0].transport;
  set_age(sender, &track, 25, true);
  assert(transport_mock_path_state(sender, 0, 100000, 5, 0));
  uint8_t bytes[100] = {13};
  moq_object_t object = {
      .track_id = track, .data = bytes, .size = sizeof(bytes)};
  assert(transport_publish_ex(sender, &object) == TRANSPORT_PUBLISH_BUFFERED);
  age_group(f, 100);
  assert(!sender->pending_group.pending);
  assert(transport_publish_ex(sender, &object) == TRANSPORT_PUBLISH_BUFFERED);
  assert(sender->pending_group.record_count == 1 &&
         sender->pending_group.size == sizeof(bytes) + 2);
  for (unsigned i = 0; i < 20 && sender->pending_group.size != 0; i++) {
    (void)transport_publish_flush(sender);
    advance(f, 1);
  }
  assert(sender->pending_group.size == 0);
  advance(f, 100);
  assert(f->endpoints[1].lost == 1 && f->endpoints[1].endpoint.objects == 1);
  destroy_fixture(f);
}

static void test_unsubscribe_on_expiry(void) {
  deadline_fixture_t *f = create_fixture(2);
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                          .name = "unsubscribe-on-expiry"};
  subscribe(f, track);
  transport_t *sender = f->nodes[0].transport;
  set_age(sender, &track, 25, true);
  f->endpoints[1].unsubscribe_on_loss = true;
  uint8_t bytes[100] = {15};
  moq_object_t object = {
      .track_id = track, .data = bytes, .size = sizeof(bytes)};
  assert(transport_publish_ex(sender, &object) == TRANSPORT_PUBLISH_BUFFERED);
  age_group(f, 100);
  assert(transport_publish_flush(sender));
  advance(f, 100);
  assert(f->endpoints[1].lost == 1 && f->endpoints[1].endpoint.objects == 0);
  assert(sender->sent_cache.count == 0);
  destroy_fixture(f);
}

/* Exercise a stored zero timestamp directly, without treating it as an
 * absent deadline. The drive API itself currently requires a nonzero clock. */
static void test_zero_start(void) {
  sim_network_t *net = calloc(1, sizeof(*net));
  assert(net);
  net->now_ns = 1000000;
  sim_node_t node = {0};
  transport_drive_host_t host = sim_host(&node, net);
  fixture_endpoint_t endpoint = {.server = true};
  transport_config_t config = {.bind_hosts = {"127.0.0.1"},
                               .num_bind_hosts = 1,
                               .port = 19938,
                               .callback = fixture_event,
                               .user_data = &endpoint,
                               .allow_insecure_peer = true,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .drive_host = &host};
  transport_t *sender = node.transport = transport_drive_create(&config);
  endpoint.transport = sender;
  assert(sender && transport_now_ms(sender) == 1);
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                          .name = "zero-start"};
  set_age(sender, &track, 25, true);
  sender->pending_group.data = calloc(1, 3);
  assert(sender->pending_group.data);
  sender->pending_group.data[1] = 1;
  sender->pending_group.size = sender->pending_group.capacity = 3;
  sender->pending_group.track_id = track;
  sender->pending_group.record_count = 1;
  assert(transport_drive_time(sender, 100000000));
  assert(transport_publish_flush_grouped(sender));
  assert(sender->fec_tracks[0].next_object_id == 1 &&
         sender->fec_tracks[0].checkpoint_initialized &&
         sender->stats.publish_delivered == 0 && !sender->pending_group.size);
  transport_destroy(sender);
  free(net);
}

int main(void) {
  test_unsent_expiry(false, false);
  test_unsent_expiry(true, true);
  test_partial_expiry();
  test_fixed_expiry(false);
  test_fixed_expiry(true);
  test_unrelated_publication();
  test_expired_before_append();
  test_unsubscribe_on_expiry();
  test_zero_start();
  puts("===PUBLICATION DEADLINES OK===");
  return 0;
}
