/* Verified real handshakes plus explicit synthetic callback/barrier faults.
 * Link wrappers affect only this test, never production provider/TLS policy. */
#include "transport_internal.h"
#include "transport_tls.h"
#include "transport_protocol.h"
#include "transport_stream.h"
#include "transport_wire.h"
#include "quicly/defaults.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static ptls_t *fake_tls;
static int fake_complete, fake_psk;
static uint16_t fake_group;
static bool injecting;
static quicly_stream_t *inject_stream;
static const uint8_t *inject_data;
static size_t inject_size;
static unsigned auth_writes, completion_logs, fusion_endpoints, hello_retries,
    oversized_key_shares, fallback_endpoints;
int __real_ptls_handshake_is_complete(ptls_t *);
int __real_ptls_is_psk_handshake(ptls_t *);
uint16_t __real_ptls_get_negotiated_group(ptls_t *);
int __wrap_ptls_handshake_is_complete(ptls_t *tls) {
  return tls == fake_tls ? fake_complete
                         : __real_ptls_handshake_is_complete(tls);
}
int __wrap_ptls_is_psk_handshake(ptls_t *tls) {
  return tls == fake_tls ? fake_psk : __real_ptls_is_psk_handshake(tls);
}
uint16_t __wrap_ptls_get_negotiated_group(ptls_t *tls) {
  return tls == fake_tls ? fake_group : __real_ptls_get_negotiated_group(tls);
}
/* The supported extension callback sees HRR's two-byte key_share selected
 * group (standard TLS extension 51), distinct from a final public key share. */
static int observe_key_share(ptls_on_extension_t *self, ptls_t *tls,
                             uint8_t handshake_type, uint16_t extension,
                             ptls_iovec_t data) {
  (void)self;
  if (handshake_type == PTLS_HANDSHAKE_TYPE_SERVER_HELLO && extension == 51 &&
      data.len == 2) {
    assert(data.base[0] == 0 && data.base[1] == PTLS_GROUP_SECP256R1);
    assert(!__real_ptls_handshake_is_complete(tls));
    assert(__real_ptls_get_negotiated_group(tls) == 0);
    hello_retries++;
  }
  if (extension == 51 && data.len > 1200)
    oversized_key_shares++;
  return 0;
}
static ptls_on_extension_t count_retry = {observe_key_share};

bool __real_transport_stream_write_frame(quicly_stream_t *, uint8_t,
                                         const void *, size_t);
bool __wrap_transport_stream_write_frame(quicly_stream_t *s, uint8_t type,
                                         const void *data, size_t len) {
  bool result = __real_transport_stream_write_frame(s, type, data, len);
  if (result && type == QLINQ_WIRE_AUTH_REQUEST)
    auth_writes++;
  return result;
}
quicly_error_t __real_quicly_receive(quicly_conn_t *, struct sockaddr *,
                                     struct sockaddr *,
                                     quicly_decoded_packet_t *);
quicly_error_t __wrap_quicly_receive(quicly_conn_t *q, struct sockaddr *dst,
                                     struct sockaddr *src,
                                     quicly_decoded_packet_t *packet) {
  if (!inject_stream)
    return __real_quicly_receive(q, dst, src, packet);
  injecting = true;
  size_t count = inject_size;
  uint64_t off = inject_stream->recvstate.data_off +
                 transport_stream_ingress_get(inject_stream).len;
  assert(quicly_recvstate_update(
             &inject_stream->recvstate, off, &count, 0,
             inject_stream->_send_aux.max_stream_data_sender.committed) == 0);
  assert(count == inject_size);
  inject_stream->callbacks->on_receive(inject_stream,
                                       off - inject_stream->recvstate.data_off,
                                       inject_data, inject_size);
  injecting = false;
  inject_stream = NULL;
  return QUICLY_ERROR_PACKET_IGNORED;
}

typedef struct {
  transport_t *t;
  bool server, manual, reject_auth, add_receive_track;
  unsigned connected, auth, ready, objects, subscribed, disconnected;
  qlinq_tls_info_t last;
} state_t;
static void log_event(void *data, const transport_log_event_t *ev) {
  (void)data;
  if (!strcmp(ev->component, "crypto") &&
      strstr(ev->message, "backend=fusion requested=fusion fallback=none"))
    fusion_endpoints++;
  if (!strcmp(ev->component, "crypto") &&
      strstr(ev->message, "backend=openssl requested=fusion fallback="))
    fallback_endpoints++;
  if (!strcmp(ev->component, "tls") && strstr(ev->message, "tls_complete="))
    completion_logs++;
}
static void event(void *data, const transport_event_t *ev) {
  state_t *s = data;
  transport_conn_stats_t stats;
  assert(transport_get_conn_stats(s->t, ev->conn, &stats));
  s->last = stats.tls;
  if (ev->type != TRANSPORT_EVENT_DISCONNECTED &&
      s->t->tls_group_policy != QLINQ_TLS_GROUP_CLASSICAL) {
    assert(stats.tls.complete && stats.tls.policy_accepted);
    assert(stats.tls.handshake == QLINQ_TLS_HANDSHAKE_FULL);
  }
  switch (ev->type) {
  case TRANSPORT_EVENT_CONNECTED:
    s->connected++;
    if (!s->server && !s->manual)
      assert(transport_send_auth(s->t, ev->conn, (const uint8_t *)"test", 4));
    break;
  case TRANSPORT_EVENT_AUTH:
    assert(!injecting); /* pending input may not dispatch during receive */
    s->auth++;
    assert(ev->auth.token_len == 4 && !memcmp(ev->auth.token, "test", 4));
    assert(transport_respond_auth(s->t, ev->conn, !s->reject_auth));
    if (!s->reject_auth) {
      s->ready++;
      if (s->add_receive_track)
        assert(transport_subscriptions_add(
            &ev->conn->receive_subscriptions, MOQ_TRACK_DATA,
            MOQ_TRACK_FLAG_RELIABLE, "deferred", 8));
    }
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    if (ev->auth.success)
      s->ready++;
    break;
  case TRANSPORT_EVENT_SUBSCRIBE:
    s->subscribed++;
    break;
  case TRANSPORT_EVENT_OBJECT:
    assert(ev->object.size == 7 && !memcmp(ev->object.data, "payload", 7));
    s->objects++;
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    s->disconnected++;
    break;
  default:
    break;
  }
}
static transport_t *create(state_t *s, unsigned policy, uint16_t port,
                           const char *identity, bool reconnect) {
  transport_config_t c = {.bind_hosts = {"127.0.0.1"},
                          .num_bind_hosts = 1,
                          .port = port,
                          .limits.max_udp_payload_size = 1200,
                          .tls_group_policy = policy,
                          .cert_file = identity ? "t/assets/untrusted.crt"
                                                : "t/assets/verified.crt",
                          .key_file = identity ? "t/assets/untrusted.key"
                                               : "t/assets/verified.key",
                          .ca_file = "t/assets/verified.crt",
                          .verify_peer = true,
                          .callback = event,
                          .user_data = s,
                          .log_callback = log_event,
                          .reconnect_enabled = reconnect,
                          .reconnect_initial_delay_ms = 10,
                          .reconnect_max_delay_ms = 20};
  if (!s->server) {
    c.remote_hosts[0] = "127.0.0.1";
    c.num_remote_hosts = 1;
  }
  s->t = transport_create(&c);
  if (s->t) {
    assert(s->t->quic_ctx.pre_validation_amplification_limit ==
           quicly_spec_context.pre_validation_amplification_limit);
    assert(s->t->quic_ctx.max_crypto_bytes ==
           quicly_spec_context.max_crypto_bytes);
    assert(s->t->quic_ctx.max_initial_handshake_packets ==
           quicly_spec_context.max_initial_handshake_packets);
    assert(s->t->quic_ctx.handshake_timeout_rtt_multiplier ==
           quicly_spec_context.handshake_timeout_rtt_multiplier);
    assert(s->t->tls_ctx.ticket_lifetime == 0);
    assert(s->t->tls_ctx.max_early_data_size == 0);
    assert(!s->t->tls_ctx.encrypt_ticket && !s->t->tls_ctx.save_ticket);
  }
  return s->t;
}
static void tick_pair(state_t *server, state_t *client, unsigned count) {
  while (count--) {
    transport_tick(client->t);
    transport_tick(server->t);
    usleep(1000);
  }
}
static void real_pair(unsigned cp, unsigned sp, const char *bad_server,
                      const char *bad_client, bool reject_auth,
                      bool reconnect) {
  static uint16_t port = 20100;
  state_t server = {.server = true, .reject_auth = reject_auth}, client = {0};
  assert(create(&server, sp, port, bad_server, false));
  assert(create(&client, cp, port++, bad_client, reconnect));
  assert(client.t->tls_ctx.on_extension == NULL);
  client.t->tls_ctx.on_extension = &count_retry;
  server.t->tls_ctx.on_extension = &count_retry;
  unsigned retries_before = hello_retries;
  transport_conn_t *initial = client.t->client_conn;
  assert(__real_ptls_get_negotiated_group(quicly_get_tls(initial->quic)) == 0);
  transport_conn_stats_t pending;
  assert(transport_get_conn_stats(client.t, initial, &pending));
  assert(!pending.tls.complete && !pending.tls.policy_accepted &&
         !pending.tls.selected_group);
  assert(pending.tls.exchange == QLINQ_TLS_EXCHANGE_PENDING);
  bool success = !bad_server && !bad_client && !reject_auth &&
                 !((cp == 0 && sp == 2) || (cp == 2 && sp == 0));
  unsigned before = auth_writes;
  for (unsigned i = 0; i < 3000; i++) {
    tick_pair(&server, &client, 1);
    if ((server.ready && client.ready) || client.disconnected ||
        server.disconnected)
      break;
  }
  if (success) {
    assert(server.ready == 1 && client.ready == 1);
    if (cp == QLINQ_TLS_GROUP_PREFER_HYBRID && sp == QLINQ_TLS_GROUP_CLASSICAL)
      assert(hello_retries == retries_before + 1);
    uint16_t expected =
        cp && sp ? PTLS_GROUP_X25519MLKEM768 : PTLS_GROUP_SECP256R1;
    assert(server.last.selected_group == expected &&
           client.last.selected_group == expected);
    assert(!strcmp(server.last.selected_group_name,
                   expected == PTLS_GROUP_X25519MLKEM768 ? "X25519MLKEM768"
                                                         : "secp256r1"));
    assert(server.last.configured_policy == (qlinq_tls_group_policy_t)sp);
    assert(client.last.configured_policy == (qlinq_tls_group_policy_t)cp);
    assert(server.last.complete && client.last.complete);
    assert(server.last.policy_accepted && client.last.policy_accepted);
    assert(server.last.verify_peer && client.last.verify_peer);
    assert(server.last.handshake == QLINQ_TLS_HANDSHAKE_FULL &&
           client.last.handshake == QLINQ_TLS_HANDSHAKE_FULL);
    assert(
        transport_send_unicast(client.t, client.t->client_conn, "payload", 7));
    for (unsigned i = 0; i < 1000 && !server.objects; i++)
      tick_pair(&server, &client, 1);
    assert(server.objects == 1);
    quicly_stats_t wire_stats;
    assert(quicly_get_stats(client.t->client_conn->quic, &wire_stats) == 0);
    assert(!wire_stats.num_packets.zero_rtt_sent &&
           !wire_stats.num_packets.zero_rtt_received);
    assert(quicly_get_stats(server.t->conns[0]->quic, &wire_stats) == 0);
    assert(!wire_stats.num_packets.zero_rtt_sent &&
           !wire_stats.num_packets.zero_rtt_received);
    if (reconnect) {
      uint32_t old_id = client.t->client_conn->id;
      transport_close_conn(server.t, server.t->conns[0]);
      bool saw_pending = false;
      for (unsigned i = 0; i < 5000 && client.ready < 2; i++) {
        tick_pair(&server, &client, 1);
        transport_conn_t *conn = client.t->client_conn;
        if (conn && conn->id != old_id && !conn->tls.complete) {
          assert(!conn->tls.policy_accepted && !conn->tls.selected_group);
          saw_pending = true;
        }
      }
      assert(saw_pending && client.ready == 2 && server.ready == 2);
      assert(client.last.selected_group == PTLS_GROUP_X25519MLKEM768);
      assert(client.last.configured_policy == QLINQ_TLS_GROUP_REQUIRE_HYBRID);
      assert(client.last.handshake == QLINQ_TLS_HANDSHAKE_FULL);
    }
  } else {
    assert(!server.ready && !client.ready && !server.objects &&
           !client.objects);
    if (!reject_auth) {
      assert(!server.auth && auth_writes == before);
      assert(!server.connected && !client.connected);
    }
    assert(server.disconnected || client.disconnected);
  }
  printf("pair client=%u server=%u bad_server=%d bad_client=%d reject_auth=%d "
         "reconnect=%d outcome=%s groups=%u/%u hrr=%u\n",
         cp, sp, bad_server != NULL, bad_client != NULL, reject_auth, reconnect,
         success ? "authenticated-transfer" : "rejected",
         client.last.selected_group, server.last.selected_group,
         hello_retries - retries_before);
  transport_destroy(client.t);
  transport_destroy(server.t);
}

static size_t frame(uint8_t *out, uint8_t type, const void *payload,
                    size_t size) {
  assert(qlinq_wire_encode_frame_header(out, 4096, type, size,
                                        TRANSPORT_WIRE_MAX_STREAM_PAYLOAD) ==
         QLINQ_WIRE_OK);
  memcpy(out + QLINQ_WIRE_FRAME_HEADER_SIZE, payload, size);
  return QLINQ_WIRE_FRAME_HEADER_SIZE + size;
}
static size_t controls(uint8_t *out) {
  qlinq_wire_hello_t hello = {.role = QLINQ_WIRE_ROLE_CLIENT,
                              .max_paths = 1,
                              .capabilities = QLINQ_WIRE_CAP_RELIABLE |
                                              QLINQ_WIRE_CAP_DATAGRAM,
                              .max_reliable_object_size = 1024,
                              .max_fec_object_size = 1024,
                              .max_subscriptions = 8,
                              .max_datagram_size = 1200};
  uint8_t payload[256];
  assert(qlinq_wire_encode_hello(payload, sizeof(payload), &hello) ==
         QLINQ_WIRE_OK);
  size_t n = frame(out, QLINQ_WIRE_HELLO, payload, QLINQ_WIRE_HELLO_SIZE);
  n += frame(out + n, QLINQ_WIRE_AUTH_REQUEST, "test", 4);
  qlinq_wire_track_t track = {.alias = 8, .track_type = MOQ_TRACK_DATA};
  strcpy(track.name, "test");
  size_t len = 0;
  assert(qlinq_wire_encode_track(payload, sizeof(payload), &track, &len) ==
         QLINQ_WIRE_OK);
  n += frame(out + n, QLINQ_WIRE_SUBSCRIBE, payload, len);
  n += frame(out + n, QLINQ_WIRE_UNICAST, "payload", 7);
  return n;
}
static void synthetic(unsigned failure, bool split) {
  state_t s = {.manual = true, .add_receive_track = true};
  assert(create(&s, QLINQ_TLS_GROUP_REQUIRE_HYBRID, 20200, NULL, false));
  transport_conn_t *conn = s.t->client_conn;
  /* Convert only the transport fixture's role; no TLS private layout changes.
   */
  s.t->is_server = s.server = true;
  s.t->client_conn = NULL;
  s.t->conns[s.t->conn_count++] = conn;
  conn->quic_ready = true;
  fake_tls = quicly_get_tls(conn->quic);
  fake_complete = fake_psk = 0;
  fake_group = PTLS_GROUP_X25519MLKEM768;
  unsigned before = auth_writes, logged = completion_logs;
  conn->protocol_ready = true; /* direct API attempts must still be blocked */
  assert(!transport_send_auth(s.t, conn, (const uint8_t *)"test", 4));
  assert(!transport_respond_auth(s.t, conn, true));
  assert(!conn->authenticated && auth_writes == before);
  conn->authenticated = true;
  moq_track_id_t blocked_track = {.type = MOQ_TRACK_DATA, .name = "blocked"};
  assert(!transport_subscribe_conn(s.t, conn, blocked_track));
  assert(!transport_send_unicast(s.t, conn, "payload", 7));
  assert(transport_subscriptions_count(&conn->receive_subscriptions) == 0);
  conn->authenticated = false;
  conn->protocol_ready = false;
  uint8_t bytes[4096];
  size_t size = controls(bytes);
  inject_stream = conn->stream;
  inject_data = bytes;
  inject_size = split ? 3 : size;
  (void)quicly_receive(conn->quic, NULL, NULL, NULL);
  if (split) {
    inject_stream = conn->stream;
    inject_data = bytes + 3;
    inject_size = size - 3;
    (void)quicly_receive(conn->quic, NULL, NULL, NULL);
  }
  quicly_stream_t *track = NULL;
  assert(quicly_get_or_open_stream(conn->quic, 3, &track) == 0);
  uint8_t object[QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE + 7], wire[4096];
  qlinq_wire_track_object_t header = {.alias = 8};
  assert(qlinq_wire_encode_track_object(object, sizeof(object), &header) ==
         QLINQ_WIRE_OK);
  memcpy(object + QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE, "payload", 7);
  size_t track_size =
      frame(wire, QLINQ_WIRE_TRACK_OBJECT, object, sizeof(object));
  inject_stream = track;
  inject_data = wire;
  inject_size = track_size;
  (void)quicly_receive(conn->quic, NULL, NULL, NULL);
  assert(conn->tls_deferred && conn->tls_deferred_bytes == size + track_size);
  assert(!s.connected && !s.auth && !s.ready && !s.objects && !s.subscribed);
  assert(!conn->tls.complete && !conn->tls.selected_group &&
         !conn->tls.policy_accepted);
  assert(!conn->protocol_ready && !conn->authenticated);
  assert(transport_subscriptions_count(&conn->send_subscriptions) == 0);
  /* Datagrams and event delivery cannot exploit an authenticated bit either. */
  conn->authenticated = true;
  s.t->receive_datagram.cb(&s.t->receive_datagram, conn->quic,
                           ptls_iovec_init(bytes, size));
  transport_event_t blocked = {.type = TRANSPORT_EVENT_OBJECT, .conn = conn};
  transport_emit_event(s.t, &blocked);
  assert(!s.objects);
  conn->authenticated = false;
  fake_complete = 1;
  if (failure == 1)
    fake_group = 0;
  if (failure == 2)
    fake_group = PTLS_GROUP_SECP256R1;
  if (failure == 3)
    fake_psk = 1;
  if (failure == 4)
    quicly_close(conn->quic, 0, "injected TLS failure");
  transport_tls_observe(conn);
  transport_protocol_resume_deferred(conn);
  if (!failure) {
    assert(s.connected == 1 && s.auth == 1 && s.ready == 1 && s.objects == 2 &&
           s.subscribed == 1);
    assert(conn->tls_deferred_bytes == 0);
    assert(transport_stream_ingress_get(conn->stream).len == 0);
    assert(conn->tls.policy_accepted && conn->tls.selected_group == 4588);
    transport_protocol_resume_deferred(conn);
    assert(s.auth == 1 && s.objects == 2 && s.subscribed == 1);
  } else {
    assert(conn->tls.exchange == QLINQ_TLS_EXCHANGE_REJECTED);
    assert(!conn->tls.policy_accepted && !s.auth && !s.ready && !s.connected &&
           !s.objects && !s.subscribed);
    assert(quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING);
    assert(!transport_send_auth(s.t, conn, (const uint8_t *)"test", 4));
    assert(!transport_respond_auth(s.t, conn, true));
    if (failure <= 3) {
      uint64_t offending;
      const char *reason;
      int remote;
      assert(
          quicly_get_close_reason(conn->quic, &offending, &reason, &remote) ==
          TRANSPORT_APP_ERROR_TLS_POLICY);
      assert(!remote && reason && !strcmp(reason, conn->tls.rejection_reason));
    }
  }
  transport_tls_observe(conn);
  assert(completion_logs == logged + 1);
  printf("synthetic failure=%u split=%d connected=%u auth=%u ready=%u "
         "objects=%u subscriptions=%u reason=%s\n",
         failure, split, s.connected, s.auth, s.ready, s.objects, s.subscribed,
         conn->tls.rejection_reason[0] ? conn->tls.rejection_reason
                                       : "accepted");
  fake_tls = NULL;
  transport_destroy(s.t);
}
static void pending_bounds(bool connection_bound) {
  state_t s = {.manual = true};
  assert(create(&s, QLINQ_TLS_GROUP_REQUIRE_HYBRID, 20202, NULL, false));
  transport_conn_t *conn = s.t->client_conn;
  fake_tls = quicly_get_tls(conn->quic);
  fake_complete = fake_psk = 0;
  uint8_t *bytes = calloc(1, 65536);
  assert(bytes);
  if (connection_bound) {
    for (unsigned i = 0; i < 5; i++) {
      quicly_stream_t *stream;
      assert(quicly_get_or_open_stream(conn->quic, 3 + 4 * i, &stream) == 0);
      stream->callbacks->on_receive(stream, 0, bytes, 65536);
      if (i < 4)
        assert(quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING);
    }
    assert(conn->tls_deferred_bytes == 256 * 1024);
  } else {
    conn->stream->callbacks->on_receive(conn->stream, 65536, bytes, 1);
  }
  assert(quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING);
  assert(s.t->stats.resource_limit_errors == 1);
  assert(!s.auth && !s.ready && !s.objects);
  printf("pending-bound=%s rejected-before-application\n",
         connection_bound ? "connection" : "stream");
  fake_tls = NULL;
  free(bytes);
  transport_destroy(s.t);
}

int main(void) {
  transport_t *capability = calloc(1, sizeof(*capability));
  assert(capability);
  capability->log_callback = log_event;
  bool available = transport_tls_configure_groups(
      capability, QLINQ_TLS_GROUP_REQUIRE_HYBRID);
  if (!available) {
    assert(!strcmp(capability->tls_hybrid_reason, "not-built") ||
           strstr(capability->tls_hybrid_reason, "-unavailable"));
    assert(!getenv("QLINQ_TEST_REQUIRE_HYBRID"));
    free(capability);
    puts("===TLS BARRIER SKIP: hybrid unavailable===");
    return 0;
  }
  free(capability);
  for (unsigned cp = 0; cp < 3; cp++)
    for (unsigned sp = 0; sp < 3; sp++)
      real_pair(cp, sp, NULL, NULL, false, false);
  real_pair(2, 2, "untrusted", NULL, false, false);
  real_pair(2, 2, NULL, "untrusted", false, false);
  real_pair(2, 2, NULL, NULL, true, false);
  real_pair(2, 2, NULL, NULL, false, true);
  for (unsigned failure = 0; failure <= 4; failure++)
    synthetic(failure, false);
  synthetic(0, true);
  pending_bounds(false);
  pending_bounds(true);
  assert(oversized_key_shares >
         0); /* reassembled extension exceeds any UDP payload */
  printf("split-crypto oversized_key_shares=%u udp_payload=1200\n",
         oversized_key_shares);
  if (getenv("QLINQ_TEST_REQUIRE_FUSION"))
    assert(fusion_endpoints > 0);
  if (getenv("QLINQ_TEST_REQUIRE_FALLBACK"))
    assert(fallback_endpoints > 0 && fusion_endpoints == 0);
  printf("fusion_endpoints=%u fallback_endpoints=%u\n", fusion_endpoints,
         fallback_endpoints);
  puts("===TLS BARRIER OK===");
  return 0;
}
