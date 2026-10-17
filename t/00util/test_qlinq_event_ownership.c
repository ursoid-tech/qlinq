/* Exercise the real queue and public ownership operations without socket I/O.
 * Including the implementation exposes allocation charges for this audit. */
#include "../../src/common/qlinq.c"
#include "transport_internal.h"

#include <stdio.h>

#define CHECK(test)                                                            \
  do {                                                                         \
    if (!(test)) {                                                             \
      fprintf(stderr, "event ownership line %d: %s\n", __LINE__, #test);       \
      failed = 1;                                                              \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

static bool enqueue_record(qlinq_context_t *context, uint64_t sequence) {
  uint8_t payload[64];
  memset(payload, 0x5a, sizeof(payload));
  payload[0] = (uint8_t)sequence;
  qlinq_event_t source = {
      .type = QLINQ_EVENT_RECORD,
      .record = {.sequence = sequence, .size = sizeof(payload)}};
  return queue_event(context, &source, payload, sizeof(payload), NULL);
}

static int count_and_ownership(void) {
  int failed = 0;
  qlinq_event_t held[3] = {0};
  qlinq_context_config_t config = {.max_queued_events = 2,
                                   .max_queued_event_bytes = 65536};
  qlinq_context_t *context = qlinq_context_create(&config);
  CHECK(context);
  CHECK(enqueue_record(context, 1) && enqueue_record(context, 2));
  CHECK(!enqueue_record(context, 3));
  CHECK(qlinq_context_last_status(context) == QLINQ_STATUS_RESOURCE_LIMIT);
  size_t allocation = sizeof(qlinq_event_node_t) + 64;
  CHECK(context->queued_events == 2 &&
        context->queued_event_bytes == 2 * allocation);
  CHECK(context->queued_event_bytes < config.max_queued_event_bytes);
  /* Handing events to the caller releases queue capacity. These three held
   * allocations have separate ownership from the two events still queued. */
  for (size_t i = 0; i < 3; ++i) {
    CHECK(qlinq_next_event(context, &held[i]));
    CHECK(held[i].record.sequence == i + 1);
    CHECK(context->queued_events == 1 &&
          context->queued_event_bytes == allocation);
    CHECK(enqueue_record(context, i + 3));
  }
  CHECK(context->queued_events == 2 &&
        context->queued_event_bytes == 2 * allocation);
  qlinq_context_destroy(context); /* Releases the two events still queued. */
  context = NULL;
  for (size_t i = 0; i < 3; ++i) {
    CHECK(held[i].record.size == 64 && held[i]._private != NULL);
    const uint8_t *payload = held[i].record.data;
    CHECK(payload != NULL && payload[0] == i + 1);
    for (size_t j = 1; j < 64; ++j)
      CHECK(payload[j] == 0x5a);
    qlinq_event_release(&held[i]);
    CHECK(held[i]._private == NULL && held[i].record.data == NULL);
  }
cleanup:
  qlinq_context_destroy(context);
  for (size_t i = 0; i < 3; ++i)
    qlinq_event_release(&held[i]);
  return failed;
}

static int bytes_and_message(void) {
  int failed = 0;
  char reason[81];
  memset(reason, 'r', sizeof(reason) - 1);
  reason[sizeof(reason) - 1] = '\0';
  size_t allocation = sizeof(qlinq_event_node_t) + sizeof(reason);
  qlinq_context_config_t config = {
      .max_queued_events = 8, .max_queued_event_bytes = 2 * allocation - 1};
  qlinq_context_t *context = qlinq_context_create(&config);
  qlinq_event_t source = {.type = QLINQ_EVENT_PEER_DISCONNECTED,
                          .disconnect = {.was_ready = true, .outgoing = true}},
                held = {0};
  CHECK(context);
  CHECK(queue_event(context, &source, NULL, 0, reason));
  CHECK(context->queued_event_bytes == allocation);
  CHECK(!queue_event(context, &source, NULL, 0, reason));
  CHECK(context->queued_events == 1 &&
        context->queued_events < config.max_queued_events);
  CHECK(qlinq_context_last_status(context) == QLINQ_STATUS_RESOURCE_LIMIT);
  CHECK(qlinq_next_event(context, &held));
  CHECK(context->queued_events == 0 && context->queued_event_bytes == 0);
  CHECK(queue_event(context, &source, NULL, 0, reason));
  CHECK(!queue_event(context, &source, reason, SIZE_MAX, NULL));
  CHECK(qlinq_context_last_status(context) == QLINQ_STATUS_INVALID);
  CHECK(context->queued_events == 1 &&
        context->queued_event_bytes == allocation);
  memset(reason, 'x', sizeof(reason));
  qlinq_context_destroy(context);
  context = NULL;
  CHECK(held.message != NULL && held.message == held.disconnect.reason);
  CHECK(held.disconnect.was_ready && held.disconnect.outgoing);
  CHECK(strlen(held.message) == 80);
  for (size_t i = 0; i < 80; ++i)
    CHECK(held.message[i] == 'r');
cleanup:
  qlinq_context_destroy(context);
  qlinq_event_release(&held);
  return failed;
}

/* Exercise real readiness and send admission with bounded in-memory transport
 * queues. No sockets or peer timing are needed to test notification edges. */
static int writable_notifications(void) {
  int failed = 0;
  qlinq_event_t event = {0};
  qlinq_context_config_t config = {.max_queued_events = 1};
  qlinq_context_t *context = qlinq_context_create(&config);
  transport_t transport = {.owner_thread = pthread_self(),
                           .socket_count = 1,
                           .limits = {.max_fec_object_size = 1024},
                           .sent_cache = {.max_payload_bytes = 1}};
  transport.sockets[0].egress.capacity = 4;
  transport.sockets[0].egress.max_bytes = 1024;
  qlinq_endpoint_t endpoint = {
      .context = context, .transport = &transport, .active = true};
  qlinq_stream_t stream = {.endpoint = &endpoint,
                           .track = {.type = MOQ_TRACK_DATA,
                                     .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                                     .name = "writable"},
                           .direction = QLINQ_STREAM_PUBLISH,
                           .state = QLINQ_STREAM_OPEN};
  CHECK(context);
  context->endpoints = &endpoint;
  endpoint.streams = &stream;
  refresh_writable_events(context);
  refresh_writable_events(context);
  CHECK(qlinq_next_event(context, &event));
  CHECK(event.type == QLINQ_EVENT_STREAM_WRITABLE && event.stream == &stream);
  qlinq_event_release(&event);
  refresh_writable_events(context);
  CHECK(!qlinq_next_event(context, &event));

  /* Losing readiness resets the edge. A full event queue must not consume it.
   */
  transport.sockets[0].egress.count = 3;
  refresh_writable_events(context);
  CHECK(!qlinq_next_event(context, &event));
  CHECK(enqueue_record(context, 1));
  transport.sockets[0].egress.count = 0;
  refresh_writable_events(context);
  CHECK(qlinq_context_last_status(context) == QLINQ_STATUS_RESOURCE_LIMIT);
  CHECK(qlinq_next_event(context, &event) && event.type == QLINQ_EVENT_RECORD);
  qlinq_event_release(&event);
  refresh_writable_events(context);
  CHECK(qlinq_next_event(context, &event));
  CHECK(event.type == QLINQ_EVENT_STREAM_WRITABLE && event.stream == &stream);
  qlinq_event_release(&event);
  refresh_writable_events(context);
  CHECK(!qlinq_next_event(context, &event));

  /* A record can exceed the cache budget while the general readiness query
   * still allows smaller records. Failed send admission must rearm the edge. */
  qlinq_record_t record = {.data = "ab", .size = 2};
  CHECK(qlinq_stream_is_writable(&stream));
  CHECK(qlinq_stream_send(&stream, &record) == QLINQ_SEND_WOULD_BLOCK);
  CHECK(qlinq_stream_is_writable(&stream));
  refresh_writable_events(context);
  CHECK(qlinq_next_event(context, &event));
  CHECK(event.type == QLINQ_EVENT_STREAM_WRITABLE && event.stream == &stream);
  qlinq_event_release(&event);
  refresh_writable_events(context);
  CHECK(!qlinq_next_event(context, &event));
cleanup:
  if (context)
    context->endpoints =
        NULL; /* The endpoint and transport are stack fixtures. */
  qlinq_context_destroy(context);
  qlinq_event_release(&event);
  return failed;
}

static bool interrupt_service_poll;

#if defined(__GLIBC__)
int __poll(struct pollfd *fds, nfds_t nfds, int timeout);
int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
  if (interrupt_service_poll) {
    interrupt_service_poll = false;
    errno = EINTR;
    return -1;
  }
  return __poll(fds, nfds, timeout);
}
#endif

typedef struct {
  uint8_t payload[8192];
  qlinq_context_t *contexts[2];
  qlinq_endpoint_t *endpoints[2];
  qlinq_stream_t *publishers[2];
  qlinq_stream_t *subscribers[2];
  unsigned received[2];
  unsigned writable[2];
} service_fixture_t;

static bool service_drain(service_fixture_t *fixture, size_t index) {
  qlinq_event_t event;
  while (qlinq_next_event(fixture->contexts[index], &event)) {
    if (event.type == QLINQ_EVENT_RECORD)
      fixture->received[index]++;
    else if (event.type == QLINQ_EVENT_STREAM_WRITABLE)
      fixture->writable[index]++;
    qlinq_event_release(&event);
  }
  return true;
}

static size_t service_retained(qlinq_stream_t *stream) {
  return stream && stream->endpoint && stream->endpoint->transport
             ? stream->endpoint->transport->stats.stream_egress_bytes
             : 0;
}

static int service_progress(void) {
  int failed = 0;
  qlinq_event_t event = {0};
  int application_pipe[2] = {-1, -1};
  service_fixture_t fixture = {0};
  memset(fixture.payload, 0x3c, sizeof(fixture.payload));
  qlinq_endpoint_config_t config = {
      .bind_addresses = {"127.0.0.1"},
      .bind_address_count = 1,
      .port = 19945,
      .security = {.shared_secret = "service-progress",
                   .shared_secret_size = 16,
                   .certificate_file = "t/assets/server.crt",
                   .private_key_file = "t/assets/server.key",
                   .allow_insecure_peer = true},
      /* The legal minimum for this record size admits several full records,
       * then leaves enough room for general readiness but not another record.
       */
      .limits = {.max_reliable_record_bytes = sizeof(fixture.payload),
                 .max_stream_egress_bytes =
                     sizeof(fixture.payload) + 64U * 1024U + 1024U}};
  qlinq_stream_config_t stream = {.name = "service-progress",
                                  .content_type = QLINQ_CONTENT_DATA,
                                  .delivery = QLINQ_DELIVERY_RELIABLE};
  for (size_t i = 0; i < 2; i++) {
    fixture.contexts[i] = qlinq_context_create(NULL);
    CHECK(fixture.contexts[i]);
    if (i != 0) {
      config.remote_addresses[0] = "127.0.0.1";
      config.remote_address_count = 1;
    }
    fixture.endpoints[i] = i == 0 ? qlinq_listen(fixture.contexts[i], &config)
                                  : qlinq_connect(fixture.contexts[i], &config);
    CHECK(fixture.endpoints[i]);
    fixture.publishers[i] = qlinq_publish(fixture.endpoints[i], &stream);
    fixture.subscribers[i] = qlinq_subscribe(fixture.endpoints[i], &stream);
    CHECK(fixture.publishers[i] && fixture.subscribers[i]);
  }
  CHECK(pipe(application_pipe) == 0 && write(application_pipe[1], "x", 1) == 1);
  int64_t deadline = transport_get_time_ms() + 10000;
  bool ready = false;
  while (!ready && transport_get_time_ms() < deadline) {
    ready = true;
    for (size_t i = 0; i < 2; i++) {
      short revents = 0;
      CHECK(qlinq_service_fd(fixture.contexts[i], -1, application_pipe[0],
                             POLLIN, &revents) >= QLINQ_STATUS_OK);
      CHECK(service_drain(&fixture, i));
      qlinq_stream_stats_t stats;
      CHECK(qlinq_stream_get_stats(fixture.publishers[i], &stats));
      ready &= stats.subscribers == 1 && stats.writable;
    }
    if (!ready)
      usleep(1000);
  }
  CHECK(ready);

  qlinq_record_t record = {
      .data = fixture.payload, .size = sizeof(fixture.payload), .group_id = 1};
  unsigned admitted = 0;
  qlinq_send_result_t sent;
  do {
    record.sequence = admitted + 1;
    sent = qlinq_stream_send(fixture.publishers[0], &record);
    CHECK(sent == QLINQ_SEND_SENT || sent == QLINQ_SEND_BUFFERED ||
          sent == QLINQ_SEND_WOULD_BLOCK);
    if (sent == QLINQ_SEND_SENT || sent == QLINQ_SEND_BUFFERED)
      admitted++;
  } while (admitted < 64 && sent != QLINQ_SEND_WOULD_BLOCK);
  CHECK(admitted > 1 && admitted < 64 && sent == QLINQ_SEND_WOULD_BLOCK);
  CHECK(service_retained(fixture.publishers[0]) > record.size &&
        qlinq_stream_is_writable(fixture.publishers[0]));

  /* An interrupted poll must leave the submitted output pending. A later
   * service(-1) must send it even while an unrelated app fd stays readable. */
  interrupt_service_poll = true;
  CHECK(qlinq_service(fixture.contexts[0], -1) == QLINQ_STATUS_AGAIN);
  CHECK(!interrupt_service_poll && fixture.endpoints[0]->service_pending);

  /* Retry the same large record after each writable notification. ACK input
   * must release retained frames, so admission and exact delivery both finish
   * despite readiness for smaller records remaining true throughout. */
  deadline = transport_get_time_ms() + 10000;
  bool final_admitted = false;
  unsigned writable_observed = fixture.writable[0];
  while (transport_get_time_ms() < deadline &&
         (!final_admitted || fixture.received[1] != admitted + 1 ||
          service_retained(fixture.publishers[0]) != 0)) {
    for (size_t i = 0; i < 2; i++) {
      short revents = 0;
      CHECK(qlinq_service_fd(fixture.contexts[i], -1, application_pipe[0],
                             POLLIN, &revents) >= QLINQ_STATUS_OK);
      CHECK(service_drain(&fixture, i));
    }
    if (!final_admitted && fixture.writable[0] != writable_observed) {
      writable_observed = fixture.writable[0];
      sent = qlinq_stream_send(fixture.publishers[0], &record);
      CHECK(sent == QLINQ_SEND_SENT || sent == QLINQ_SEND_BUFFERED ||
            sent == QLINQ_SEND_WOULD_BLOCK);
      final_admitted = sent != QLINQ_SEND_WOULD_BLOCK;
    }
    usleep(1000);
  }
  CHECK(final_admitted && fixture.received[1] == admitted + 1 &&
        service_retained(fixture.publishers[0]) == 0);

  /* Fill the forward stream again without servicing it. Its failed large
   * admission rearms writable while a reverse record is already queued at
   * the socket. Input must win the context's sole available event slot. */
  record.sequence = admitted + 2;
  for (unsigned i = 0; i < 64; i++, record.sequence++) {
    sent = qlinq_stream_send(fixture.publishers[0], &record);
    if (sent == QLINQ_SEND_WOULD_BLOCK)
      break;
    CHECK(sent == QLINQ_SEND_SENT || sent == QLINQ_SEND_BUFFERED);
  }
  CHECK(sent == QLINQ_SEND_WOULD_BLOCK &&
        qlinq_stream_is_writable(fixture.publishers[0]));
  qlinq_record_t reverse = {
      .data = fixture.payload, .size = 64, .group_id = 1, .sequence = 1};
  sent = qlinq_stream_send(fixture.publishers[1], &reverse);
  CHECK(sent == QLINQ_SEND_SENT || sent == QLINQ_SEND_BUFFERED);
  transport_conn_t *reverse_conn =
      transport_connection_at(fixture.endpoints[1]->transport, 0);
  CHECK(reverse_conn);
  deadline = transport_get_time_ms() + 1000;
  do {
    transport_tick(fixture.endpoints[1]->transport);
    if (!quicly_has_pending_stream_data(reverse_conn->quic))
      break;
    usleep(1000);
  } while (transport_get_time_ms() < deadline);
  CHECK(!quicly_has_pending_stream_data(reverse_conn->quic));
  struct pollfd input = {.fd = fixture.endpoints[0]->transport->sockets[0].fd,
                         .events = POLLIN};
  CHECK(poll(&input, 1, 1000) == 1 && (input.revents & POLLIN));
  fixture.contexts[0]->max_queued_events = 1;
  CHECK(qlinq_service(fixture.contexts[0], -1) == QLINQ_STATUS_RESOURCE_LIMIT);
  CHECK(!fixture.publishers[0]->writable_announced &&
        fixture.contexts[0]->queued_events == 1);
  /* Existing queued events retain the public API's priority over more work. */
  CHECK(qlinq_stream_send(fixture.publishers[0], &record) ==
        QLINQ_SEND_WOULD_BLOCK);
  CHECK(qlinq_service(fixture.contexts[0], -1) == QLINQ_STATUS_RESOURCE_LIMIT &&
        fixture.endpoints[0]->service_pending);
  CHECK(qlinq_next_event(fixture.contexts[0], &event) &&
        event.type == QLINQ_EVENT_RECORD &&
        event.stream == fixture.subscribers[0] && event.record.sequence == 1 &&
        event.record.size == 64 &&
        memcmp(event.record.data, fixture.payload, 64) == 0);
  qlinq_event_release(&event);
  transport_conn_t *conn =
      transport_connection_at(fixture.endpoints[0]->transport, 0);
  CHECK(conn && quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING);
  CHECK(qlinq_service(fixture.contexts[0], 0) == QLINQ_STATUS_OK);
  CHECK(qlinq_next_event(fixture.contexts[0], &event) &&
        event.type == QLINQ_EVENT_STREAM_WRITABLE &&
        event.stream == fixture.publishers[0]);
  qlinq_event_release(&event);
cleanup:
  interrupt_service_poll = false;
  qlinq_event_release(&event);
  for (size_t i = 0; i < 2; i++) {
    qlinq_context_destroy(fixture.contexts[i]);
    if (application_pipe[i] >= 0)
      close(application_pipe[i]);
  }
  return failed;
}

typedef struct {
  qlinq_context_t *context;
  const uint8_t *payload;
  size_t size;
  uint64_t group_id, sequence;
  size_t calls;
  bool accept, valid;
} callback_audit_t;

static bool audit_record_callback(void *user_data, const qlinq_event_t *event) {
  callback_audit_t *audit = user_data;
  audit->valid &= event && event->type == QLINQ_EVENT_RECORD &&
                  event->record.data == audit->payload &&
                  event->record.size == audit->size &&
                  event->record.group_id == audit->group_id &&
                  event->record.sequence == audit->sequence &&
                  event->_private == NULL;
  /* The delivering context is unavailable while the borrowed event is live. */
  audit->valid &=
      qlinq_service(audit->context, 0) == QLINQ_STATUS_STATE &&
      qlinq_context_last_status(audit->context) == QLINQ_STATUS_INVALID;
  audit->calls++;
  return audit->accept;
}

static int borrowed_callback_bridge(void) {
  int failed = 0;
  uint8_t payload[] = {1, 2, 3, 4};
  moq_track_id_t track = {.type = MOQ_TRACK_DATA, .name = "callback"};
  transport_conn_t *connection = (transport_conn_t *)(uintptr_t)1;
  callback_audit_t audit = {.payload = payload,
                            .size = sizeof(payload),
                            .group_id = 7,
                            .sequence = 9,
                            .accept = true,
                            .valid = true};
  qlinq_context_config_t config = {.record_callback = audit_record_callback,
                                   .record_user_data = &audit};
  qlinq_context_t *context = qlinq_context_create(&config);
  qlinq_endpoint_t endpoint = {.context = context};
  qlinq_stream_t stream = {.endpoint = &endpoint,
                           .track = track,
                           .direction = QLINQ_STREAM_SUBSCRIBE,
                           .state = QLINQ_STREAM_OPEN};
  qlinq_peer_state_t peer = {.connection = connection, .id = 11};
  moq_object_t object = {.group_id = audit.group_id,
                         .object_id = audit.sequence,
                         .data = payload,
                         .size = sizeof(payload)};
  CHECK(context);
  audit.context = context;
  endpoint.streams = &stream;
  endpoint.peers = &peer;
  CHECK(deliver_record(&endpoint, connection, &track, &object, payload,
                       sizeof(payload)));
  CHECK(audit.valid && audit.calls == 1 && endpoint.records_received == 1 &&
        stream.records_received == 1 && endpoint.record_events_queued == 0 &&
        endpoint.record_payload_bytes_copied == 0 &&
        endpoint.record_callbacks_accepted == 1 &&
        endpoint.record_callbacks_rejected == 0 && context->event_head == NULL);

  audit.accept = false;
  transport_event_t source = {.type = TRANSPORT_EVENT_OBJECT,
                              .conn = connection,
                              .track_id = track,
                              .object = object};
  queue_received_object(&endpoint, &source);
  CHECK(audit.valid && audit.calls == 2 && endpoint.records_received == 1 &&
        endpoint.record_callbacks_accepted == 1 &&
        endpoint.record_callbacks_rejected == 1 &&
        qlinq_context_last_status(context) == QLINQ_STATUS_RESOURCE_LIMIT);
  qlinq_event_t error = {0};
  CHECK(qlinq_next_event(context, &error));
  CHECK(error.type == QLINQ_EVENT_ERROR &&
        error.status == QLINQ_STATUS_RESOURCE_LIMIT);
  qlinq_event_release(&error);
cleanup:
  qlinq_context_destroy(context);
  return failed;
}

int main(void) {
  for (size_t i = 0; i < 100; ++i)
    if (count_and_ownership() || bytes_and_message() ||
        writable_notifications() || borrowed_callback_bridge())
      return 1;
  if (service_progress())
    return 1;
  puts("===QLINQ EVENT OWNERSHIP OK===");
  return 0;
}
