#include "amtq_quicly.h"
#include "../../deps/nanoamt/lib/internal.h"
#include "quicly/sendstate.h"
#include "quicly/streambuf.h"
#include <arpa/inet.h>
#include <limits.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

#define AMTQ_FLIGHT_DEFAULT 1500U
#define AMTQ_RELIABLE_MAX_RECORDS 16U
#define AMTQ_RELIABLE_MAX_BYTES 32768U

typedef struct reliable_tuple {
  uint8_t ip_version, source[16], group[16];
} reliable_tuple;

typedef struct reliable_stream {
  quicly_streambuf_t buffer; /* streambuf requires this first */
  quicly_stream_t *stream;
  uint64_t context_id, block_id;
  size_t pending, written;
  unsigned records, tuple_count;
  reliable_tuple tuples[AMTQ_RELIABLE_MAX_RECORDS];
  int sealed, ended;
} reliable_stream;

struct amtq_quicly {
  quicly_context_t *context;
  quicly_conn_t *connection;
  quicly_stream_t *stream;
  amtq_quicly_config config;
  nanoamtq *gateway;
  nanoamtq_relay *relay;
  nanoamtq_membership memberships[64];
  size_t membership_count, control_bytes, reliable_bytes;
  reliable_stream *reliable[NANOAMTQ_MAX_CONTEXTS];
  reliable_stream *open_reliable;
  nanoamtq_control control;
  nanoamtq_relay_cursor cursor;
  nanoamtq_relay_datagram_output datagram;
  uint8_t *ip, *frame, *flight;
  size_t frame_capacity, flight_capacity;
  amtq_quicly_output output;
  int error, bound, freeing, context_open, queued, flight_data;
  int64_t now, started, input_at, frame_at;
  uint64_t serial;
  amtq_quicly_stats stats;
};

static int secure_random(void *context, void *bytes, size_t size) {
  (void)context;
  return size <= INT_MAX && RAND_bytes(bytes, (int)size) == 1 ? 0 : -1;
}

static int fail(amtq_quicly *s, int error, uint64_t close_code) {
  if (!s->error) {
    s->error = error;
    if (s->connection && quicly_get_state(s->connection) < QUICLY_STATE_CLOSING)
      quicly_close(s->connection,
                   QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(close_code),
                   "AMTQ session failure");
  }
  return s->error;
}

static int activate(amtq_quicly *s) {
  if (s->gateway || s->relay || s->error)
    return s->error;
  if (!s->connection || !quicly_connection_is_ready(s->connection) ||
      !ptls_handshake_is_complete(quicly_get_tls(s->connection)))
    return NANOAMTQ_INCOMPLETE;
  const char *alpn =
      ptls_get_negotiated_protocol(quicly_get_tls(s->connection));
  if (!alpn || strcmp(alpn, NANOAMTQ_ALPN) ||
      quicly_is_client(s->connection) == !!s->config.server)
    return fail(s, NANOAMTQ_ERROR_PROTOCOL, NANOAMTQ_CLOSE_PROTOCOL);
  const quicly_transport_parameters_t *remote =
      quicly_get_remote_transport_parameters(s->connection);
  /* AMTQ data is relay-to-gateway only; a relay need not receive DATAGRAMs */
  if ((s->config.server && !remote->max_datagram_frame_size) ||
      (!s->config.server && !remote->max_streams_bidi))
    return fail(s, NANOAMTQ_ERROR_PROTOCOL, NANOAMTQ_CLOSE_SETTINGS);
  if (s->config.server) {
    nanoamtq_relay_config c = s->config.relay;
    c.connection_id = s->config.connection_id;
    c.peer_max_uni_streams = remote->max_streams_uni;
    s->relay = nanoamtq_relay_new(&c, s->now);
    if (!s->relay)
      return fail(s, NANOAMTQ_ERROR_MEMORY, NANOAMTQ_CLOSE_INTERNAL);
  } else {
    nanoamtq_config c = s->config.gateway;
    s->gateway = nanoamtq_new(&c, s->now);
    if (!s->gateway)
      return fail(s, NANOAMTQ_ERROR_MEMORY, NANOAMTQ_CLOSE_INTERNAL);
    int rc = nanoamtq_set_memberships(s->gateway, s->memberships,
                                      s->membership_count);
    if (rc)
      return fail(s, rc, NANOAMTQ_CLOSE_INTERNAL);
    quicly_stream_t *stream = NULL;
    if (quicly_open_stream(s->connection, &stream, 0) || !stream ||
        stream != s->stream || stream->stream_id != 0)
      return fail(s, NANOAMTQ_ERROR_PROTOCOL, NANOAMTQ_CLOSE_CONTROL_STREAM);
  }
  return NANOAMTQ_OK;
}

static int authorize(amtq_quicly *s) {
  uint64_t generation = nanoamtq_relay_generation(s->relay);
  const nanoamt_memberships *candidate = nanoamtq_relay_requested(s->relay);
  nanoamtq_authorization *token = NULL;
  int rc = nanoamtq_relay_prepare_authorization(s->relay, s->now, generation,
                                                candidate, &token);
  if (rc)
    return fail(s, rc, NANOAMTQ_CLOSE_INTERNAL);
  int denied = s->config.authorize &&
               s->config.authorize(s->config.authorize_context,
                                   s->config.connection_id, candidate);
  if (denied)
    rc = nanoamtq_relay_deny(s->relay, s->now, generation);
  else
    rc = nanoamtq_relay_commit_authorization(s->relay, s->now, token);
  nanoamtq_relay_authorization_free(token);
  if (rc)
    return fail(s, rc, NANOAMTQ_CLOSE_INTERNAL);
  if (!s->context_open &&
      nanoamt_memberships_count(nanoamtq_relay_authorized(s->relay))) {
    rc = nanoamtq_relay_open_context_mode(
        s->relay, s->now, 0, (unsigned)nanoamtq_relay_preferred_mode(s->relay));
    if (rc)
      return fail(s, rc, NANOAMTQ_CLOSE_CONTEXT);
    s->context_open = 1;
  }
  return NANOAMTQ_OK;
}

static void revoke(amtq_quicly *s);

static int seal_reliable(amtq_quicly *s);

static void drain_control(amtq_quicly *s) {
  int rc = activate(s);
  if (rc || !s->stream)
    return;
  for (;;) {
    ptls_iovec_t input = quicly_streambuf_ingress_get(s->stream);
    int fin = quicly_recvstate_transfer_complete(&s->stream->recvstate);
    if (!input.len && !fin)
      break;
    size_t consumed = input.len;
    if (s->config.server) {
      rc = nanoamtq_relay_receive_control(s->relay, s->now, 0, input.base,
                                          input.len, fin, &consumed);
      if (consumed)
        quicly_streambuf_ingress_shift(s->stream, consumed);
      if (rc == NANOAMTQ_MEMBERSHIP) {
        if (seal_reliable(s))
          return;
        /* revoke retained data before a later update can reauthorize it */
        revoke(s);
        if (authorize(s))
          return;
        revoke(s);
        continue;
      }
    } else {
      rc = nanoamtq_receive_control(s->gateway, s->now, 0, input.base,
                                    input.len, fin);
      if (consumed)
        quicly_streambuf_ingress_shift(s->stream, consumed);
    }
    if (rc < 0) {
      fail(s, rc,
           s->relay ? nanoamtq_relay_close_error(s->relay)
                    : nanoamtq_close_error(s->gateway));
      return;
    }
    if (!consumed || !input.len)
      break;
  }
}

static amtq_quicly *owner(quicly_conn_t *connection) {
  return *quicly_get_data(connection);
}

static void drain_reliable(amtq_quicly *s, reliable_stream *data) {
  if (s->config.server || !s->gateway || s->error || data->ended)
    return;
  for (;;) {
    ptls_iovec_t input = quicly_streambuf_ingress_get(data->stream);
    int fin = quicly_recvstate_transfer_complete(&data->stream->recvstate);
    if (!input.len && !fin)
      return;
    size_t consumed = 0;
    nanoamt_packet packet;
    int rc = nanoamtq_receive_stream(
        s->gateway, s->now, (uint64_t)data->stream->stream_id, input.base,
        input.len, fin ? NANOAMTQ_STREAM_FIN : NANOAMTQ_STREAM_DATA, &consumed,
        &packet);
    if (consumed)
      quicly_streambuf_ingress_shift(data->stream, consumed);
    if (rc < 0) {
      fail(s, rc, nanoamtq_close_error(s->gateway));
      return;
    }
    if (rc == NANOAMTQ_PACKET) {
      ++s->stats.packets;
      if (s->config.packet)
        s->config.packet(s->config.packet_context, s->config.connection_id,
                         &packet);
    }
    if (fin && consumed == input.len) {
      data->ended = 1;
      return;
    }
    if (!consumed)
      return;
  }
}

static void check_reliable_cancel(amtq_quicly *s, reliable_stream *data) {
  if (!s || !s->config.server || !data || data->ended || !data->stream)
    return;
  if (quicly_sendstate_eos_type(&data->stream->sendstate) ==
      QUICLY_SENDSTATE_EOS_TYPE_RESET) {
    if (s->open_reliable == data)
      s->open_reliable = NULL;
    data->ended = 1;
    if (s->relay)
      (void)nanoamtq_relay_reliable_abort(s->relay, s->now, data->context_id,
                                          data->block_id);
    fail(s, NANOAMTQ_ERROR_PROTOCOL, NANOAMTQ_CLOSE_CONTEXT);
  }
}

static void stream_destroy(quicly_stream_t *stream, quicly_error_t error) {
  amtq_quicly *s = owner(stream->conn);
  if (s && s->stream == stream) {
    s->stream = NULL;
    if (!s->freeing)
      fail(s, NANOAMTQ_ERROR_PROTOCOL, NANOAMTQ_CLOSE_CONTROL_STREAM);
    if (!s->bound)
      s->connection = NULL;
  }
  if (s && stream->stream_id != 0 && stream->data) {
    reliable_stream *data = stream->data;
    if (s->open_reliable == data)
      s->open_reliable = NULL;
    for (unsigned i = 0; i < NANOAMTQ_MAX_CONTEXTS; ++i)
      if (s->reliable[i] == data)
        s->reliable[i] = NULL;
    s->reliable_bytes -=
        data->pending <= s->reliable_bytes ? data->pending : s->reliable_bytes;
    data->pending = 0;
  }
  if (stream->data)
    quicly_streambuf_destroy(stream, error);
}

static void stream_shift(quicly_stream_t *stream, size_t size) {
  amtq_quicly *s = owner(stream->conn);
  quicly_streambuf_egress_shift(stream, size);
  if (stream->stream_id != 0) {
    reliable_stream *data = stream->data;
    if (size > data->pending) {
      fail(s, NANOAMTQ_ERROR_PROTOCOL, NANOAMTQ_CLOSE_INTERNAL);
    } else {
      data->pending -= size;
      s->reliable_bytes -= size <= s->reliable_bytes ? size : s->reliable_bytes;
    }
    /* STOP_SENDING after local FIN resets the stream and shifts unacked bytes
     */
    check_reliable_cancel(s, data);
    return;
  }
  if (size > s->control_bytes)
    fail(s, NANOAMTQ_ERROR_PROTOCOL, NANOAMTQ_CLOSE_INTERNAL);
  else
    s->control_bytes -= size;
}

static void stream_stop(quicly_stream_t *stream, quicly_error_t error) {
  (void)error;
  amtq_quicly *s = owner(stream->conn);
  if (stream->stream_id == 0) {
    fail(s, NANOAMTQ_ERROR_PROTOCOL, NANOAMTQ_CLOSE_CONTROL_STREAM);
  } else if (s->config.server) {
    reliable_stream *data = stream->data;
    if (s->open_reliable == data)
      s->open_reliable = NULL;
    data->ended = 1;
    nanoamtq_relay_reliable_abort(s->relay, s->now, data->context_id,
                                  data->block_id);
    fail(s, NANOAMTQ_ERROR_PROTOCOL, NANOAMTQ_CLOSE_CONTEXT);
  } else if (!activate(s)) {
    nanoamt_packet packet;
    size_t consumed;
    int rc = nanoamtq_receive_stream(s->gateway, s->now,
                                     (uint64_t)stream->stream_id, NULL, 0,
                                     NANOAMTQ_STREAM_RESET, &consumed, &packet);
    if (rc < 0)
      fail(s, rc, nanoamtq_close_error(s->gateway));
    ((reliable_stream *)stream->data)->ended = 1;
  } else {
    fail(s, NANOAMTQ_ERROR_PROTOCOL, NANOAMTQ_CLOSE_CONTEXT);
  }
}

static void stream_receive(quicly_stream_t *stream, size_t offset,
                           const void *bytes, size_t size) {
  amtq_quicly *s = owner(stream->conn);
  if (offset > 65536 || size > 65536 - offset) {
    fail(s, NANOAMTQ_ERROR_LIMIT, NANOAMTQ_CLOSE_EXCESSIVE_LOAD);
    return;
  }
  if (quicly_streambuf_ingress_receive(stream, offset, bytes, size)) {
    fail(s, NANOAMTQ_ERROR_MEMORY, NANOAMTQ_CLOSE_INTERNAL);
    return;
  }
  /* hold bounded 1-RTT stream bytes until TLS finished completes */
  if (!ptls_handshake_is_complete(quicly_get_tls(stream->conn))) {
    if (stream->stream_id != 0 &&
        quicly_recvstate_transfer_complete(&stream->recvstate))
      fail(s, NANOAMTQ_ERROR_PROTOCOL, NANOAMTQ_CLOSE_CONTEXT);
    return;
  }
  if (stream->stream_id == 0)
    drain_control(s);
  else if (!activate(s))
    drain_reliable(s, stream->data);
  else if (quicly_recvstate_transfer_complete(&stream->recvstate))
    fail(s, NANOAMTQ_ERROR_PROTOCOL, NANOAMTQ_CLOSE_CONTEXT);
}

static const quicly_stream_callbacks_t stream_callbacks = {
    stream_destroy, stream_shift,   quicly_streambuf_egress_emit,
    stream_stop,    stream_receive, stream_stop};

static quicly_error_t stream_open(quicly_stream_open_t *self,
                                  quicly_stream_t *stream) {
  (void)self;
  amtq_quicly *s = owner(stream->conn);
  if (!s)
    return QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(NANOAMTQ_CLOSE_INTERNAL);
  stream->callbacks = &stream_callbacks;
  if (stream->stream_id == 0) {
    if (s->stream)
      return QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(
          NANOAMTQ_CLOSE_CONTROL_STREAM);
    if (quicly_streambuf_create(stream, sizeof(quicly_streambuf_t)))
      return QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(NANOAMTQ_CLOSE_INTERNAL);
    s->stream = stream;
  } else {
    if ((stream->stream_id & 3) != 3)
      return QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(NANOAMTQ_CLOSE_PROTOCOL);
    unsigned i = 0;
    while (i < NANOAMTQ_MAX_CONTEXTS && s->reliable[i])
      ++i;
    if (i == NANOAMTQ_MAX_CONTEXTS)
      return QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(
          NANOAMTQ_CLOSE_EXCESSIVE_LOAD);
    if (quicly_streambuf_create(stream, sizeof(reliable_stream)))
      return QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(NANOAMTQ_CLOSE_INTERNAL);
    reliable_stream *data = stream->data;
    data->stream = stream;
    s->reliable[i] = data;
  }
  s->connection = stream->conn;
  return 0;
}

static void receive_datagram(quicly_receive_datagram_frame_t *self,
                             quicly_conn_t *connection, ptls_iovec_t payload) {
  (void)self;
  amtq_quicly *s = owner(connection);
  if (!s || activate(s))
    return;
  if (s->config.server) {
    int rc = nanoamtq_relay_receive_datagram(s->relay, s->now, payload.base,
                                             payload.len);
    if (rc < 0)
      fail(s, rc, nanoamtq_relay_close_error(s->relay));
  } else {
    nanoamt_packet packet;
    int rc = nanoamtq_receive_datagram(s->gateway, s->now, payload.base,
                                       payload.len, &packet);
    if (rc < 0)
      fail(s, rc, nanoamtq_close_error(s->gateway));
    else if (rc == NANOAMTQ_PACKET) {
      ++s->stats.packets;
      if (s->config.packet)
        s->config.packet(s->config.packet_context, s->config.connection_id,
                         &packet);
    }
  }
}

static quicly_stream_open_t open_callback = {stream_open};
static quicly_receive_datagram_frame_t datagram_callback = {receive_datagram};

void amtq_quicly_configure(quicly_context_t *context) {
  context->stream_open = &open_callback;
  context->receive_datagram_frame = &datagram_callback;
  context->transport_params.max_datagram_frame_size = 65535;
  context->transport_params.max_streams_bidi = 1;
  context->transport_params.max_streams_uni = NANOAMTQ_MAX_CONTEXTS;
  context->transport_params.max_stream_data.uni = 131072;
  context->transport_params.max_stream_data.bidi_local = 65536;
  context->transport_params.max_stream_data.bidi_remote = 65536;
  context->transport_params.max_data = 524288;
  context->allow_variable_datagram_sizes = 1;
  context->egress[0].enable_pmtud = 1;
  if (!context->egress[0].max_udp_payload_size)
    context->egress[0].max_udp_payload_size = 1472;
  if (context->tls) {
    context->tls->max_early_data_size = 0;
    quicly_amend_ptls_context(context->tls);
  }
}

amtq_quicly *amtq_quicly_new(quicly_context_t *context,
                             const amtq_quicly_config *config, int64_t now) {
  if (!context || !context->tls || !config || !config->connection_id ||
      now <= 0 || now == INT64_MAX || context->stream_open != &open_callback ||
      context->receive_datagram_frame != &datagram_callback ||
      context->tls->max_early_data_size ||
      (!config->server && !context->tls->verify_certificate) ||
      (config->server &&
       (!context->tls->certificates.count || !context->tls->sign_certificate)))
    return NULL;
  if (!config->server && (config->gateway.data_modes & 2u) &&
      context->transport_params.max_streams_uni <
          (config->gateway.max_reliable_streams
               ? config->gateway.max_reliable_streams
               : NANOAMTQ_MAX_CONTEXTS))
    return NULL;
  amtq_quicly *s = calloc(1, sizeof(*s));
  if (!s)
    return NULL;
  s->context = context;
  s->config = *config;
  if (!s->config.gateway.random_bytes)
    s->config.gateway.random_bytes = secure_random;
  if (!s->config.handshake_timeout_ms)
    s->config.handshake_timeout_ms = 10000;
  if (!s->config.data_age_ms)
    s->config.data_age_ms = 1000;
  if (!s->config.control_buffer_bytes)
    s->config.control_buffer_bytes = 32768;
  if (!s->config.reliable_buffer_bytes)
    s->config.reliable_buffer_bytes = 256 * 1024;
  if (s->config.reliable_buffer_bytes < 65599 ||
      s->config.reliable_buffer_bytes > 16 * 1024 * 1024 ||
      s->config.control_buffer_bytes < 8192 ||
      s->config.control_buffer_bytes > 1048576) {
    free(s);
    return NULL;
  }
  s->flight_capacity =
      context->egress[0].max_udp_payload_size >= AMTQ_FLIGHT_DEFAULT
          ? context->egress[0].max_udp_payload_size
          : AMTQ_FLIGHT_DEFAULT;
  s->flight = malloc(s->flight_capacity);
  if (!s->flight) {
    free(s);
    return NULL;
  }
  s->now = s->started = now;
  return s;
}

int amtq_quicly_bind(amtq_quicly *s, quicly_conn_t *connection) {
  if (!s || !connection || s->bound ||
      (s->connection && s->connection != connection) ||
      owner(connection) != s || quicly_get_context(connection) != s->context)
    return NANOAMTQ_ERROR_ARGUMENT;
  s->connection = connection;
  s->bound = 1;
  return NANOAMTQ_OK;
}

void amtq_quicly_free(amtq_quicly *s) {
  if (!s)
    return;
  s->freeing = 1;
  if (s->bound)
    quicly_free(s->connection);
  nanoamtq_free(s->gateway);
  nanoamtq_relay_free(s->relay);
  free(s->ip);
  free(s->frame);
  free(s->flight);
  free(s);
}

quicly_conn_t *amtq_quicly_connection(amtq_quicly *s) {
  return s ? s->connection : NULL;
}

nanoamtq_relay *amtq_quicly_relay(amtq_quicly *s) {
  return s ? s->relay : NULL;
}

int amtq_quicly_set_memberships(amtq_quicly *s,
                                const nanoamtq_membership *memberships,
                                size_t count) {
  if (!s || s->config.server || count > 64 || (!memberships && count))
    return NANOAMTQ_ERROR_ARGUMENT;
  nanoamtq *gateway =
      s->gateway ? s->gateway : nanoamtq_new(&s->config.gateway, s->now);
  if (!gateway)
    return NANOAMTQ_ERROR_MEMORY;
  int rc = nanoamtq_set_memberships(gateway, memberships, count);
  if (!s->gateway)
    nanoamtq_free(gateway);
  if (!rc) {
    if (count)
      memcpy(s->memberships, memberships, count * sizeof(*memberships));
    s->membership_count = count;
  }
  return rc;
}

int amtq_quicly_memberships_submitted(const amtq_quicly *s) {
  return s && !s->error && !s->control.size && s->gateway &&
         nanoamtq_memberships_submitted(s->gateway);
}

int amtq_quicly_is_ready(const amtq_quicly *s) {
  return s && !s->error &&
         (s->relay ? nanoamtq_relay_is_ready(s->relay)
                   : s->gateway && nanoamtq_is_ready(s->gateway));
}

int amtq_quicly_error(const amtq_quicly *s) {
  return s ? s->error : NANOAMTQ_ERROR_ARGUMENT;
}

static int input_allowed(amtq_quicly *s, const uint8_t *bytes, size_t size) {
  ip_packet ip;
  return s->relay && !s->error && nanoamtq_relay_is_ready(s->relay) &&
         !nanoamtq_relay_pending(s->relay) &&
         nanoamt_ip_forward_decode(bytes, size, &ip) && ip.size == size &&
         ip.ttl && address_unicast(ip.source, ip.version) &&
         multicast(ip.destination, ip.version) &&
         (ip.version == 4 ? !(ip.destination[0] == 224 && !ip.destination[1] &&
                              !ip.destination[2])
                          : (ip.destination[1] & 15u) > 2) &&
         nanoamt_memberships_allows(nanoamtq_relay_requested(s->relay),
                                    ip.version, ip.destination, ip.source) &&
         nanoamt_memberships_allows(nanoamtq_relay_authorized(s->relay),
                                    ip.version, ip.destination, ip.source);
}

int amtq_quicly_accepts_ip(amtq_quicly *s, int64_t now, const uint8_t *ip,
                           size_t size) {
  /* safe during synchronous membership authorization without stream reentry */
  if (!s || s->error || now < s->now || !s->relay)
    return 0;
  if (nanoamtq_relay_context_mode(s->relay, 0) == 1)
    return input_allowed(s, ip, size);
  nanoamtq_relay_cursor cursor;
  return !nanoamtq_relay_datagram_begin(s->relay, now, 0, ip, size, &cursor);
}

static int frame_valid(amtq_quicly *s) {
  return s->relay && !s->error && s->frame &&
         s->datagram.size <= s->frame_capacity &&
         (uint64_t)(s->now - s->frame_at) < s->config.data_age_ms &&
         nanoamtq_relay_datagram_valid(s->relay, s->now, &s->datagram, s->frame,
                                       s->datagram.size);
}

static int reliable_policy_revoked(amtq_quicly *s,
                                   const reliable_stream *data) {
  if (s->error || !s->relay)
    return 1;
  const nanoamt_memberships *req = nanoamtq_relay_requested(s->relay);
  const nanoamt_memberships *auth = nanoamtq_relay_authorized(s->relay);
  for (unsigned k = 0; k < data->tuple_count; ++k) {
    const reliable_tuple *t = &data->tuples[k];
    /* abort only when policy revokes a group still requested by the client;
     * client-initiated withdrawals drain FIN and are filtered on delivery */
    if (nanoamt_memberships_allows(req, t->ip_version, t->group, t->source) &&
        !nanoamt_memberships_allows(auth, t->ip_version, t->group, t->source))
      return 1;
  }
  return 0;
}

static void revoke(amtq_quicly *s) {
  if (s->ip) {
    nanoamtq_relay_cursor cursor;
    int valid = nanoamtq_relay_context_mode(s->relay, s->cursor.context_id) == 1
                    ? input_allowed(s, s->ip, s->cursor.size)
                    : !nanoamtq_relay_datagram_begin(
                          s->relay, s->now, s->cursor.context_id, s->ip,
                          s->cursor.size, &cursor);
    if (s->error || !valid) {
      free(s->ip);
      s->ip = NULL;
      ++s->stats.revoked;
    }
  }
  for (unsigned i = 0; i < NANOAMTQ_MAX_CONTEXTS; ++i) {
    reliable_stream *data = s->reliable[i];
    if (data && data->tuple_count && !data->ended && data->pending &&
        reliable_policy_revoked(s, data)) {
      if (s->open_reliable == data)
        s->open_reliable = NULL;
      data->ended = 1;
      if (quicly_sendstate_eos_type(&data->stream->sendstate) !=
              QUICLY_SENDSTATE_EOS_TYPE_RESET &&
          !quicly_sendstate_transfer_complete(&data->stream->sendstate))
        quicly_reset_stream(
            data->stream,
            QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(NANOAMTQ_CLOSE_CONTEXT));
      s->output.size = 0;
      ++s->stats.revoked;
      fail(s, NANOAMTQ_ERROR_PROTOCOL, NANOAMTQ_CLOSE_CONTEXT);
    }
  }
  if (s->queued && !frame_valid(s)) {
    quicly_discard_datagram_frames(s->connection, 0);
    s->queued = 0;
    ++s->stats.revoked;
  }
  if (s->output.size && s->flight_data && !frame_valid(s)) {
    s->output.size = 0;
    s->flight_data = 0;
    ++s->stats.revoked;
  }
}

int amtq_quicly_tick(amtq_quicly *s, int64_t now) {
  if (!s || !s->bound || now < s->now || now == INT64_MAX)
    return NANOAMTQ_ERROR_ARGUMENT;
  s->now = now;
  if (quicly_get_state(s->connection) >= QUICLY_STATE_CLOSING)
    s->error = s->error ? s->error : NANOAMTQ_ERROR_PROTOCOL;
  if (!s->gateway && !s->relay && !s->error &&
      (uint64_t)(now - s->started) >= s->config.handshake_timeout_ms)
    fail(s, NANOAMTQ_ERROR_TIMEOUT, 0);
  int rc = activate(s);
  if (rc < 0) {
    revoke(s);
    return rc;
  }
  if (s->ip && (uint64_t)(now - s->input_at) >= s->config.data_age_ms) {
    free(s->ip);
    s->ip = NULL;
    ++s->stats.expired;
  }
  if (s->relay)
    rc = nanoamtq_relay_tick(s->relay, now);
  else if (s->gateway)
    rc = nanoamtq_receive_control(s->gateway, now, 0, NULL, 0, 0);
  if (rc < 0)
    fail(s, rc,
         s->relay ? nanoamtq_relay_close_error(s->relay)
                  : nanoamtq_close_error(s->gateway));
  if (!s->error) {
    drain_control(s);
    for (unsigned i = 0; i < NANOAMTQ_MAX_CONTEXTS; ++i)
      if (s->reliable[i]) {
        if (s->config.server)
          check_reliable_cancel(s, s->reliable[i]);
        else
          drain_reliable(s, s->reliable[i]);
      }
  }
  revoke(s);
  return s->error;
}

static void endpoint(const quicly_address_t *address, nanoamt_endpoint *out) {
  memset(out, 0, sizeof(*out));
  if (address->sa.sa_family == AF_INET6) {
    out->ip_version = 6;
    out->scope_id = address->sin6.sin6_scope_id;
    out->port = ntohs(address->sin6.sin6_port);
    memcpy(out->ip, &address->sin6.sin6_addr, 16);
  } else if (address->sa.sa_family == AF_INET) {
    out->ip_version = 4;
    out->port = ntohs(address->sin.sin_port);
    memcpy(out->ip, &address->sin.sin_addr, 4);
  }
}

static void sockaddr_endpoint(const nanoamt_endpoint *ep,
                              quicly_address_t *address) {
  memset(address, 0, sizeof(*address));
  if (ep->ip_version == 6) {
    address->sin6.sin6_family = AF_INET6;
    address->sin6.sin6_port = htons(ep->port);
    address->sin6.sin6_scope_id =
        ep->ip[0] == 0xfe && (ep->ip[1] & 0xc0u) == 0x80u ? ep->scope_id : 0;
    memcpy(&address->sin6.sin6_addr, ep->ip, 16);
  } else {
    address->sin.sin_family = AF_INET;
    address->sin.sin_port = htons(ep->port);
    memcpy(&address->sin.sin_addr, ep->ip, 4);
  }
}

int amtq_quicly_receive_ecn(amtq_quicly *s, int64_t now,
                            const nanoamt_endpoint *peer,
                            const nanoamt_endpoint *local, uint8_t *bytes,
                            size_t size, int outer_ecn) {
  if (outer_ecn < -1 || outer_ecn > 3)
    return NANOAMTQ_ERROR_ARGUMENT;
  if (!peer || !local || !bytes ||
      amtq_quicly_tick(s, now) == NANOAMTQ_ERROR_ARGUMENT)
    return NANOAMTQ_ERROR_ARGUMENT;
  quicly_address_t from, to;
  sockaddr_endpoint(peer, &from);
  sockaddr_endpoint(local, &to);
  size_t offset = 0;
  while (offset < size) {
    quicly_decoded_packet_t packet;
    if (quicly_decode_packet(s->context, &packet, bytes, size, &offset) ==
        SIZE_MAX)
      break;
    packet.ecn = (unsigned)(outer_ecn < 0 ? 0 : outer_ecn) & 3u;
    quicly_error_t rc =
        quicly_receive(s->connection, &to.sa, &from.sa, &packet);
    if (rc && rc != QUICLY_ERROR_PACKET_IGNORED)
      fail(s, NANOAMTQ_ERROR_PROTOCOL, NANOAMTQ_CLOSE_PROTOCOL);
  }
  return amtq_quicly_tick(s, now);
}

int amtq_quicly_receive_decoded(amtq_quicly *s, int64_t now,
                                const nanoamt_endpoint *peer,
                                const nanoamt_endpoint *local,
                                quicly_decoded_packet_t *packet) {
  if (!peer || !local || !packet ||
      amtq_quicly_tick(s, now) == NANOAMTQ_ERROR_ARGUMENT)
    return NANOAMTQ_ERROR_ARGUMENT;
  quicly_address_t from, to;
  sockaddr_endpoint(peer, &from);
  sockaddr_endpoint(local, &to);
  quicly_error_t rc = quicly_receive(s->connection, &to.sa, &from.sa, packet);
  if (rc && rc != QUICLY_ERROR_PACKET_IGNORED)
    fail(s, NANOAMTQ_ERROR_PROTOCOL, NANOAMTQ_CLOSE_PROTOCOL);
  return amtq_quicly_tick(s, now);
}

static int ensure_frame(amtq_quicly *s, size_t needed) {
  if (s->frame_capacity >= needed)
    return 0;
  size_t cap = s->frame_capacity ? s->frame_capacity : 1536U;
  while (cap < needed)
    cap = cap > 32768U ? 65587U : cap * 2U;
  if (cap < needed)
    cap = needed;
  uint8_t *buf = realloc(s->frame, cap);
  if (!buf)
    return -1;
  s->frame = buf;
  s->frame_capacity = cap;
  return 0;
}

static int seal_reliable(amtq_quicly *s) {
  reliable_stream *data = s->open_reliable;
  if (!data)
    return NANOAMTQ_OK;
  s->open_reliable = NULL;
  if (data->ended || data->sealed)
    return NANOAMTQ_OK;
  if (quicly_streambuf_egress_shutdown(data->stream))
    return fail(s, NANOAMTQ_ERROR_MEMORY, NANOAMTQ_CLOSE_INTERNAL);
  data->sealed = 1;
  int rc = nanoamtq_relay_reliable_finish(s->relay, s->now, data->context_id,
                                          data->block_id);
  if (rc)
    return fail(s, rc, NANOAMTQ_CLOSE_CONTEXT);
  return NANOAMTQ_OK;
}

static void record_reliable_tuple(reliable_stream *data,
                                  const nanoamtq_relay_datagram_output *meta) {
  size_t addr_len = ip_address_size(meta->ip_version);
  for (unsigned i = 0; i < data->tuple_count; ++i) {
    if (data->tuples[i].ip_version == meta->ip_version &&
        !memcmp(data->tuples[i].source, meta->source, addr_len) &&
        !memcmp(data->tuples[i].group, meta->group, addr_len))
      return;
  }
  if (data->tuple_count < AMTQ_RELIABLE_MAX_RECORDS) {
    reliable_tuple *t = &data->tuples[data->tuple_count++];
    memset(t, 0, sizeof(*t));
    t->ip_version = meta->ip_version;
    memcpy(t->source, meta->source, addr_len);
    memcpy(t->group, meta->group, addr_len);
  }
}

static int append_reliable(amtq_quicly *s, int64_t now, const uint8_t *ip,
                           size_t size) {
  if (!input_allowed(s, ip, size))
    return NANOAMTQ_IGNORED;
  size_t max_rec = size + 10; /* max varint prefix plus AMT header */
  if (s->open_reliable &&
      (s->open_reliable->records >= AMTQ_RELIABLE_MAX_RECORDS ||
       (s->open_reliable->records > 0 &&
        s->open_reliable->written + max_rec > AMTQ_RELIABLE_MAX_BYTES))) {
    int rc = seal_reliable(s);
    if (rc)
      return rc;
  }
  size_t needed = max_rec + (s->open_reliable ? 0U : 24U);
  if (needed > s->config.reliable_buffer_bytes - s->reliable_bytes)
    return NANOAMTQ_ERROR_LIMIT;
  if (ensure_frame(s, max_rec))
    return fail(s, NANOAMTQ_ERROR_MEMORY, NANOAMTQ_CLOSE_INTERNAL);
  if (!s->open_reliable) {
    unsigned slot = 0;
    while (slot < NANOAMTQ_MAX_CONTEXTS && s->reliable[slot])
      ++slot;
    if (slot == NANOAMTQ_MAX_CONTEXTS)
      return NANOAMTQ_ERROR_LIMIT;
    uint64_t block = 0;
    uint8_t header[24];
    size_t header_size = 0;
    int rc = nanoamtq_relay_reliable_begin(s->relay, now, 0, &block, header,
                                           sizeof(header), &header_size);
    if (rc == NANOAMTQ_ERROR_LIMIT)
      return NANOAMTQ_ERROR_LIMIT;
    if (rc != NANOAMTQ_PACKET)
      return fail(s, rc, NANOAMTQ_CLOSE_CONTEXT);
    quicly_stream_t *stream = NULL;
    if (quicly_open_stream(s->connection, &stream, 1) ||
        quicly_streambuf_egress_write(stream, header, header_size))
      return fail(s, NANOAMTQ_ERROR_MEMORY, NANOAMTQ_CLOSE_INTERNAL);
    reliable_stream *data = stream->data;
    data->context_id = 0;
    data->block_id = block;
    data->pending += header_size;
    data->written += header_size;
    s->reliable_bytes += header_size;
    s->open_reliable = data;
    ++s->stats.reliable_blocks;
  }
  reliable_stream *data = s->open_reliable;
  nanoamtq_relay_datagram_output metadata;
  int rc = nanoamtq_relay_reliable_record(s->relay, now, data->context_id,
                                          data->block_id, ip, size, s->frame,
                                          s->frame_capacity, &metadata);
  if (rc != NANOAMTQ_PACKET)
    return fail(s, rc < 0 ? rc : NANOAMTQ_ERROR_PROTOCOL,
                NANOAMTQ_CLOSE_CONTEXT);
  if (quicly_streambuf_egress_write(data->stream, s->frame, metadata.size))
    return fail(s, NANOAMTQ_ERROR_MEMORY, NANOAMTQ_CLOSE_INTERNAL);
  data->pending += metadata.size;
  data->written += metadata.size;
  s->reliable_bytes += metadata.size;
  ++data->records;
  record_reliable_tuple(data, &metadata);
  if (data->records >= AMTQ_RELIABLE_MAX_RECORDS ||
      data->written >= AMTQ_RELIABLE_MAX_BYTES)
    return seal_reliable(s);
  return NANOAMTQ_OK;
}

int amtq_quicly_forward_queued(amtq_quicly *s, int64_t now, int64_t at,
                               const uint8_t *ip, size_t size) {
  int rc = amtq_quicly_tick(s, now);
  if (rc)
    return rc;
  if (!s->relay || !ip || !size || size > 65575 || at <= 0 || at > now)
    return NANOAMTQ_ERROR_ARGUMENT;
  if ((uint64_t)(now - at) >= s->config.data_age_ms)
    return NANOAMTQ_IGNORED;
  if (nanoamtq_relay_context_mode(s->relay, 0) == 1)
    return append_reliable(s, now, ip, size);
  nanoamtq_relay_cursor cursor = {0};
  rc = nanoamtq_relay_datagram_begin(s->relay, now, 0, ip, size, &cursor);
  if (rc)
    return rc;
  if (s->ip || s->queued || s->flight_data)
    return NANOAMTQ_ERROR_LIMIT;
  s->ip = malloc(size);
  if (!s->ip)
    return NANOAMTQ_ERROR_MEMORY;
  memcpy(s->ip, ip, size);
  s->cursor = cursor;
  s->cursor.ip = s->ip;
  s->input_at = at;
  return NANOAMTQ_OK;
}

int amtq_quicly_forward(amtq_quicly *s, int64_t now, const uint8_t *ip,
                        size_t size) {
  return amtq_quicly_forward_queued(s, now, now, ip, size);
}

static int pump(amtq_quicly *s) {
  if (!s->stream || s->error)
    return s->error;
  for (unsigned i = 0; i < 8; ++i) {
    if (!s->control.size) {
      if (s->config.control_buffer_bytes - s->control_bytes <
          NANOAMTQ_CONTROL_CAPACITY)
        break;
      int rc = s->relay ? nanoamtq_relay_send(s->relay, s->now, &s->control)
                        : nanoamtq_send(s->gateway, s->now, &s->control);
      if (rc < 0)
        return fail(s, rc,
                    s->relay ? nanoamtq_relay_close_error(s->relay)
                             : nanoamtq_close_error(s->gateway));
      if (rc != NANOAMTQ_PACKET)
        break;
    }
    if (quicly_streambuf_egress_write(s->stream, s->control.bytes,
                                      s->control.size))
      return fail(s, NANOAMTQ_ERROR_MEMORY, NANOAMTQ_CLOSE_INTERNAL);
    s->control_bytes += s->control.size;
    s->control.size = 0;
    ++s->stats.controls;
  }
  if (s->open_reliable) {
    int rc = seal_reliable(s);
    if (rc)
      return rc;
  }
  if (s->relay && s->ip && !s->queued && !s->flight_data) {
    size_t limit = quicly_get_datagram_payload_limit(s->connection, 0);
    if (!limit)
      return NANOAMTQ_OK;
    if (ensure_frame(s, limit < 65577U ? limit : 65577U))
      return fail(s, NANOAMTQ_ERROR_MEMORY, NANOAMTQ_CLOSE_INTERNAL);
    int rc =
        nanoamtq_relay_datagram_next(s->relay, s->now, &s->cursor, limit,
                                     s->frame, s->frame_capacity, &s->datagram);
    if (rc == NANOAMTQ_ERROR_BUFFER && s->datagram.size > limit)
      return NANOAMTQ_OK; /* retain cursor until budget grows or age expires */
    if (rc == NANOAMTQ_OK || rc == NANOAMTQ_IGNORED) {
      free(s->ip);
      s->ip = NULL;
      return NANOAMTQ_OK;
    }
    if (rc < 0)
      return fail(s, rc, NANOAMTQ_CLOSE_INTERNAL);
    s->frame_at = s->input_at;
    ptls_iovec_t frame = ptls_iovec_init(s->frame, s->datagram.size);
    quicly_send_datagram_frames_path(s->connection, 0, &frame, 1);
    if (quicly_get_num_datagram_frames_path(s->connection, 0) != 1)
      return fail(s, NANOAMTQ_ERROR_MEMORY, NANOAMTQ_CLOSE_INTERNAL);
    s->queued = 1;
    ++s->stats.datagrams;
  }
  return NANOAMTQ_OK;
}

int amtq_quicly_send(amtq_quicly *s, int64_t now, amtq_quicly_output *output) {
  if (!output)
    return NANOAMTQ_ERROR_ARGUMENT;
  memset(output, 0, sizeof(*output));
  int rc = amtq_quicly_tick(s, now);
  if (rc == NANOAMTQ_ERROR_ARGUMENT)
    return rc;
  if (s->output.size) {
    *output = s->output;
    return NANOAMTQ_PACKET;
  }
  if (!s->error)
    pump(s);
  struct iovec packet;
  size_t count = 1;
  quicly_address_t destination, source;
  quicly_error_t result =
      quicly_send(s->connection, &destination, &source, &packet, &count,
                  s->flight, s->flight_capacity);
  if (result)
    return fail(s, NANOAMTQ_ERROR_PROTOCOL, NANOAMTQ_CLOSE_PROTOCOL);
  if (!count)
    return s->error ? s->error : NANOAMTQ_OK;
  s->flight_data =
      s->queued && !quicly_get_num_datagram_frames_path(s->connection, 0);
  if (s->flight_data)
    s->queued = 0;
  endpoint(&source, &s->output.source);
  endpoint(&destination, &s->output.destination);
  s->output.bytes = packet.iov_base;
  s->output.size = packet.iov_len;
  if (s->serial == UINT64_MAX)
    return fail(s, NANOAMTQ_ERROR_LIMIT, NANOAMTQ_CLOSE_INTERNAL);
  s->output.serial = ++s->serial;
  s->output.tos = quicly_send_get_ecn_bits(s->connection);
  *output = s->output;
  return NANOAMTQ_PACKET;
}

int amtq_quicly_output_valid(amtq_quicly *s, int64_t now,
                             const amtq_quicly_output *output) {
  if (!output || amtq_quicly_tick(s, now) == NANOAMTQ_ERROR_ARGUMENT)
    return 0;
  return s->output.size && output->serial == s->output.serial &&
         output->size == s->output.size && output->bytes == s->output.bytes &&
         endpoint_equal(&output->source, &s->output.source) &&
         endpoint_equal(&output->destination, &s->output.destination) &&
         output->tos == s->output.tos;
}

void amtq_quicly_consume(amtq_quicly *s) {
  if (!s)
    return;
  s->output.size = 0;
  /* release native input immediately once the final frame is consumed */
  if (s->flight_data && s->ip && s->cursor.offset == s->cursor.size + 2) {
    free(s->ip);
    s->ip = NULL;
  }
  s->flight_data = 0;
}

int64_t amtq_quicly_next_timeout(amtq_quicly *s) {
  if (!s || !s->bound)
    return INT64_MAX;
  int64_t next = quicly_get_first_timeout(s->connection);
  int64_t core = s->relay ? nanoamtq_relay_next_timeout(s->relay)
                 : s->gateway
                     ? nanoamtq_next_timeout(s->gateway)
                     : (s->started > INT64_MAX - s->config.handshake_timeout_ms
                            ? INT64_MAX
                            : s->started + s->config.handshake_timeout_ms);
  if (!s->error && core < next)
    next = core;
  if (s->ip) {
    int64_t expiry = s->input_at > INT64_MAX - s->config.data_age_ms
                         ? INT64_MAX
                         : s->input_at + s->config.data_age_ms;
    if (expiry < next)
      next = expiry;
  }
  return next;
}

void amtq_quicly_get_stats(const amtq_quicly *s, amtq_quicly_stats *stats) {
  if (!s || !stats)
    return;
  *stats = s->stats;
  stats->buffered_control_bytes = s->control_bytes;
  stats->buffered_reliable_bytes = s->reliable_bytes;
}
