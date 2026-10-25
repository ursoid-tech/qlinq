#include "qlinq.h"

#include "transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  qlinq_context_t *context;
  qlinq_endpoint_t *endpoint;
  qlinq_stream_t *stream;
  const uint8_t *payload;
  size_t payload_size;
  qlinq_delivery_t delivery;
  qlinq_content_type_t content;
  size_t received;
  bool valid;
} callback_state_t;

static bool receive_callback(void *user_data, const qlinq_event_t *event) {
  callback_state_t *state = user_data;
  state->valid &=
      event && event->type == QLINQ_EVENT_RECORD &&
      event->stream == state->stream && event->delivery == state->delivery &&
      event->content_type == state->content &&
      event->record.size == state->payload_size &&
      memcmp(event->record.data, state->payload, state->payload_size) == 0;
  /* The borrowed event is delivered with this context's API guarded. */
  state->valid &= qlinq_service(state->context, 0) == QLINQ_STATUS_STATE;
  qlinq_endpoint_stats_t stats;
  state->valid &= !qlinq_endpoint_get_stats(state->endpoint, &stats);
  state->received++;
  return true;
}

/* Exercise the public event boundary: transport-only tests cannot detect a
 * received object's descriptor no longer matching its application stream. */
static int run_delivery(qlinq_delivery_t delivery, qlinq_content_type_t content,
                        bool callback_delivery) {
  callback_state_t callback = {
      .delivery = delivery, .content = content, .valid = true};
  qlinq_context_config_t context_config = {
      .record_callback = callback_delivery ? receive_callback : NULL,
      .record_user_data = callback_delivery ? &callback : NULL};
  qlinq_context_t *context =
      qlinq_context_create(callback_delivery ? &context_config : NULL);
  if (!context)
    return 1;
  int failed = 1;
  qlinq_endpoint_config_t source = {
      .bind_addresses = {"127.0.0.1"},
      .bind_address_count = 1,
      .port = 19762,
      .security = {.shared_secret = "delivery",
                   .shared_secret_size = 8,
                   .certificate_file = "t/assets/server.crt",
                   .private_key_file = "t/assets/server.key",
                   .allow_insecure_peer = true}};
  qlinq_endpoint_config_t receiver = {
      .bind_addresses = {"127.0.0.1"},
      .bind_address_count = 1,
      .remote_addresses = {"127.0.0.1"},
      .remote_address_count = 1,
      .port = 19762,
      .security = {.shared_secret = "delivery",
                   .shared_secret_size = 8,
                   .allow_insecure_peer = true}};
  qlinq_endpoint_t *listener = qlinq_listen(context, &source);
  qlinq_endpoint_t *client = qlinq_connect(context, &receiver);
  if (!listener || !client)
    goto Exit;
  qlinq_endpoint_stats_t initial;
  memset(&initial, 0xa5, sizeof(initial));
  if (!qlinq_endpoint_get_stats(listener, &initial) ||
      initial.publish_delivered != 0 || initial.publish_buffered != 0 ||
      initial.publish_no_recipients != 0 || initial.fec_objects_decoded != 0 ||
      initial.repair_cache_misses != 0 || initial.repair_build_failures != 0 ||
      initial.repair_queue_failures != 0 ||
      initial.recovery_checkpoints_pending != 0 ||
      initial.recovery_oldest_checkpoint_age_ms != 0 ||
      initial.assembler_memory_bytes != 0)
    goto Exit;
  qlinq_stream_config_t config = {
      .content_type = content, .delivery = delivery, .name = "delivery"};
  qlinq_stream_t *publisher = qlinq_publish(listener, &config);
  qlinq_stream_t *subscriber = qlinq_subscribe(client, &config);
  if (!publisher || !subscriber)
    goto Exit;
  qlinq_stream_config_t conflicting = config;
  conflicting.delivery = delivery == QLINQ_DELIVERY_RELIABLE
                             ? QLINQ_DELIVERY_DATAGRAM
                             : QLINQ_DELIVERY_RELIABLE;
  if (qlinq_publish(listener, &conflicting) ||
      qlinq_subscribe(client, &conflicting))
    goto Exit;
  bool joined = false, ready = false;
  for (size_t attempt = 0; attempt < 500; attempt++) {
    if (qlinq_service(context, 10) < QLINQ_STATUS_OK)
      goto Exit;
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_SUBSCRIBER_JOINED)
        joined = true;
      qlinq_event_release(&event);
    }
    qlinq_endpoint_stats_t stats;
    if (joined && qlinq_endpoint_get_stats(listener, &stats) &&
        stats.active_connections == 1) {
      ready = true;
      break;
    }
  }
  if (!ready)
    goto Exit;
  uint8_t payload[1400];
  for (size_t i = 0; i < sizeof(payload); i++)
    payload[i] = (uint8_t)i;
  qlinq_record_t record = {.data = payload,
                           .size = sizeof(payload),
                           .group_id = 17,
                           .sequence = 23,
                           .priority = 1};
  qlinq_stream_config_t unmatched_config = {.content_type = QLINQ_CONTENT_DATA,
                                            .delivery = QLINQ_DELIVERY_DATAGRAM,
                                            .name = "no-subscribers"};
  qlinq_stream_t *unmatched = qlinq_publish(listener, &unmatched_config);
  if (!unmatched ||
      qlinq_stream_send(unmatched, &record) != QLINQ_SEND_NO_SUBSCRIBERS)
    goto Exit;
  qlinq_endpoint_stats_t before_receive;
  if (!qlinq_endpoint_get_stats(client, &before_receive))
    goto Exit;
  qlinq_send_result_t sent = qlinq_stream_send(publisher, &record);
  if (sent != QLINQ_SEND_SENT && sent != QLINQ_SEND_BUFFERED)
    goto Exit;
  qlinq_endpoint_stats_t published;
  if (!qlinq_endpoint_get_stats(listener, &published) ||
      published.publish_delivered != (sent == QLINQ_SEND_SENT) ||
      published.publish_buffered != (sent == QLINQ_SEND_BUFFERED) ||
      published.publish_no_recipients != 1 || published.publish_partial != 0 ||
      published.publish_backpressure != 0 || published.publish_invalid != 0 ||
      published.publish_errors != 0 ||
      published.egress_peak_packets < published.queued_packets ||
      published.egress_peak_bytes < published.queued_bytes)
    goto Exit;
  bool finite =
      content == QLINQ_CONTENT_DATA && (delivery == QLINQ_DELIVERY_FIXEDRATE ||
                                        delivery == QLINQ_DELIVERY_RATELESS);
  callback.context = context;
  callback.endpoint = client;
  callback.stream = subscriber;
  callback.payload = payload;
  callback.payload_size = sizeof(payload);
  bool received = false, saw_queued_record = false;
  for (size_t attempt = 0; attempt < 500 && !received; attempt++) {
    if (qlinq_service(context, -1) < QLINQ_STATUS_OK)
      goto Exit;
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      bool valid = true;
      if (event.type == QLINQ_EVENT_RECORD) {
        saw_queued_record = true;
        valid = !callback_delivery && event.stream == subscriber &&
                event.delivery == delivery && event.content_type == content &&
                (finite || (event.record.sequence == 23 &&
                            event.record.group_id == 17)) &&
                event.record.size == sizeof(payload) &&
                memcmp(event.record.data, payload, sizeof(payload)) == 0;
        received |= valid;
      }
      qlinq_event_release(&event);
      if (!valid)
        goto Exit;
    }
    if (callback_delivery && callback.received != 0)
      received = callback.valid;
  }
  qlinq_endpoint_stats_t stats;
  if (!qlinq_endpoint_get_stats(client, &stats))
    goto Exit;
  /* Ordered loopback delivery completes datagram objects using their original
   * symbols; completion alone must not report a successful FEC decode. */
  if (stats.fec_objects_recovered != (delivery != QLINQ_DELIVERY_RELIABLE) ||
      stats.fec_objects_decoded != 0 || stats.assembler_memory_bytes != 0 ||
      stats.malformed_datagrams != 0 || stats.resource_limit_errors != 0)
    goto Exit;
  if (delivery == QLINQ_DELIVERY_RELIABLE) {
    if (stats.stream_frames_received <= before_receive.stream_frames_received)
      goto Exit;
  } else if (stats.datagrams_received <= before_receive.datagrams_received) {
    goto Exit;
  }
  /* Reading a snapshot must not consume the counters or turn a buffered
   * publication into an additional publication when its group is flushed. */
  qlinq_endpoint_stats_t repeated, after_publish;
  if (!qlinq_endpoint_get_stats(client, &repeated) ||
      !qlinq_endpoint_get_stats(listener, &after_publish) ||
      repeated.datagrams_received != stats.datagrams_received ||
      repeated.stream_frames_received != stats.stream_frames_received ||
      repeated.fec_objects_recovered != stats.fec_objects_recovered ||
      after_publish.publish_delivered != published.publish_delivered ||
      after_publish.publish_buffered != published.publish_buffered ||
      after_publish.publish_no_recipients != published.publish_no_recipients)
    goto Exit;
  if (callback_delivery)
    failed = !received || saw_queued_record || !callback.valid ||
             stats.records_received != callback.received ||
             stats.record_events_queued != 0 ||
             stats.record_payload_bytes_copied != 0 ||
             stats.record_callbacks_accepted != callback.received ||
             stats.record_callbacks_rejected != 0;
  else
    failed = !received || stats.record_events_queued != 1 ||
             stats.record_payload_bytes_copied != sizeof(payload) ||
             stats.record_callbacks_accepted != 0 ||
             stats.record_callbacks_rejected != 0;
Exit:
  qlinq_context_destroy(context);
  if (failed)
    fprintf(stderr, "delivery failed: mode=%d content=%d callback=%d\n",
            delivery, content, callback_delivery);
  return failed;
}

static int run_reliable_boundaries(void) {
  qlinq_context_t *context = qlinq_context_create(NULL);
  if (!context)
    return 1;
  qlinq_endpoint_config_t config = {
      .bind_addresses = {"127.0.0.1"},
      .bind_address_count = 1,
      .port = 19763,
      .security = {.certificate_file = "t/assets/server.crt",
                   .private_key_file = "t/assets/server.key",
                   .allow_insecure_peer = true}};
  qlinq_endpoint_t *server = qlinq_listen(context, &config);
  config.remote_addresses[0] = "127.0.0.1";
  config.remote_address_count = 1;
  qlinq_endpoint_t *client = qlinq_connect(context, &config);
  qlinq_stream_config_t track = {.name = "maximum",
                                 .content_type = QLINQ_CONTENT_DATA,
                                 .delivery = QLINQ_DELIVERY_RELIABLE};
  qlinq_stream_t *publishers[2] = {qlinq_publish(server, &track),
                                   qlinq_publish(client, &track)};
  qlinq_stream_t *subscribers[2] = {qlinq_subscribe(client, &track),
                                    qlinq_subscribe(server, &track)};
  int failed = 1;
  uint8_t *payload = malloc(TRANSPORT_MAX_RELIABLE_OBJECT_SIZE + 1U);
  if (!server || !client || !publishers[0] || !publishers[1] ||
      !subscribers[0] || !subscribers[1] || !payload)
    goto Exit;
  for (size_t i = 0; i <= TRANSPORT_MAX_RELIABLE_OBJECT_SIZE; i++)
    payload[i] = (uint8_t)(i * 37U);
  unsigned joined = 0;
  for (size_t attempt = 0; attempt < 2000 && joined < 2; attempt++) {
    if (qlinq_service(context, 5) < QLINQ_STATUS_OK)
      goto Exit;
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      joined += event.type == QLINQ_EVENT_SUBSCRIBER_JOINED;
      qlinq_event_release(&event);
    }
  }
  if (joined != 2)
    goto Exit;
  for (size_t direction = 0; direction < 2; direction++) {
    uint64_t blocked = 0;
    qlinq_record_t record = {.data = payload,
                             .size = TRANSPORT_MAX_RELIABLE_OBJECT_SIZE + 1U};
    if (qlinq_stream_send(publishers[direction], &record) != QLINQ_SEND_INVALID)
      goto Exit;
    for (unsigned iteration = 0; iteration < 3; iteration++) {
      record.sequence = iteration;
      record.size = TRANSPORT_MAX_RELIABLE_OBJECT_SIZE - (iteration == 0);
      bool sent = false, received = false;
      for (size_t attempt = 0; attempt < 2000 && !received; attempt++) {
        if (!sent) {
          qlinq_send_result_t result =
              qlinq_stream_send(publishers[direction], &record);
          sent = result == QLINQ_SEND_SENT;
          if (!sent && result != QLINQ_SEND_WOULD_BLOCK)
            goto Exit;
          blocked += result == QLINQ_SEND_WOULD_BLOCK;
        }
        if (qlinq_service(context, 5) < QLINQ_STATUS_OK)
          goto Exit;
        qlinq_event_t event;
        while (qlinq_next_event(context, &event)) {
          bool valid = true;
          if (event.type == QLINQ_EVENT_RECORD) {
            valid = event.stream == subscribers[direction] &&
                    event.record.sequence == record.sequence &&
                    event.record.size == record.size &&
                    memcmp(event.record.data, payload, record.size) == 0;
            received = valid;
          }
          qlinq_event_release(&event);
          if (!valid)
            goto Exit;
        }
      }
      if (!received)
        goto Exit;
    }
    qlinq_endpoint_stats_t stats;
    if (!qlinq_endpoint_get_stats(direction == 0 ? server : client, &stats) ||
        stats.publish_delivered != 3 || stats.publish_invalid != 1 ||
        stats.publish_backpressure != blocked || stats.publish_buffered != 0 ||
        stats.publish_partial != 0 || stats.publish_errors != 0)
      goto Exit;
  }
  failed = 0;
Exit:
  free(payload);
  qlinq_context_destroy(context);
  if (failed)
    fputs("reliable maximum-record boundary failed\n", stderr);
  return failed;
}

int main(void) {
  if (run_reliable_boundaries())
    return 1;
  const qlinq_delivery_t modes[] = {
      QLINQ_DELIVERY_DATAGRAM, QLINQ_DELIVERY_FIXEDRATE,
      QLINQ_DELIVERY_RATELESS, QLINQ_DELIVERY_RELIABLE};
  const qlinq_content_type_t content[] = {QLINQ_CONTENT_DATA,
                                          QLINQ_CONTENT_VIDEO};
  for (size_t c = 0; c < sizeof(content) / sizeof(content[0]); c++)
    for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); m++)
      for (size_t callback = 0; callback < 2; callback++)
        if (run_delivery(modes[m], content[c], callback != 0))
          return 1;
  puts("===QLINQ DELIVERY MATRIX OK===");
  return 0;
}
