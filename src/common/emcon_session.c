#include "emcon_session.h"

#include "emcon_activation.h"
#include "emcon_receive_socket.h"
#include "emcon_send_socket.h"
#include "transport_wire.h"

#include "picotls/openssl.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct qlinq_emcon_session_t {
  qlinq_emcon_manifest_t manifest;
  qlinq_emcon_sender_t *send_crypto;
  quicly_flexicast_flow_t *receive_flow;
  qlinq_emcon_send_socket_t *sender;
  qlinq_emcon_receive_socket_t *receiver;
  qlinq_emcon_activation_t *activation;
  char *receiver_claim_directory;
  qlinq_emcon_receiver_t *aliases[QLINQ_EMCON_MANIFEST_MAX_STREAMS];
  uint64_t reservation_packets;
  uint64_t reserved_until;
  bool session_announced;
  uint64_t last_session_metadata_ms;
  qlinq_emcon_session_stats_t stats;
};

static uint64_t realtime_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_REALTIME, &now) != 0)
    return 0;
  return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static int endpoint_sockaddr(const qlinq_emcon_manifest_endpoint_t *endpoint,
                             struct sockaddr_storage *address,
                             socklen_t *address_len) {
  memset(address, 0, sizeof(*address));
  if (endpoint->family == 4) {
    struct sockaddr_in *v4 = (struct sockaddr_in *)address;
    v4->sin_family = AF_INET;
    v4->sin_port = htons(endpoint->port);
    memcpy(&v4->sin_addr, endpoint->address, 4);
    *address_len = sizeof(*v4);
    return 0;
  }
  if (endpoint->family == 6) {
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)address;
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htons(endpoint->port);
    memcpy(&v6->sin6_addr, endpoint->address, 16);
    *address_len = sizeof(*v6);
    return 0;
  }
  return -1;
}

static bool find_stream(const qlinq_emcon_session_t *session, uint8_t alias,
                        size_t *manifest_index) {
  for (size_t i = 0; i < session->manifest.stream_count; i++) {
    if (session->manifest.streams[i].alias == alias) {
      if (manifest_index)
        *manifest_index = i;
      return true;
    }
  }
  return false;
}

static qlinq_emcon_receiver_t *find_alias(qlinq_emcon_session_t *session,
                                          uint8_t alias) {
  size_t index;
  return find_stream(session, alias, &index) ? session->aliases[index] : NULL;
}

static int create_common(qlinq_emcon_session_t **session,
                         const qlinq_emcon_manifest_t *manifest,
                         const uint8_t *traffic_secret,
                         size_t traffic_secret_size, uint64_t now_ms,
                         bool send_mode, uint64_t first_packet_number) {
  if (!session || !manifest || !traffic_secret ||
      traffic_secret_size != ptls_openssl_aes128gcmsha256.hash->digest_size)
    return QLINQ_EMCON_SESSION_INVALID;
  *session = NULL;
  int validated = qlinq_emcon_manifest_validate(manifest, now_ms);
  if (validated == QLINQ_EMCON_MANIFEST_EXPIRED ||
      validated == QLINQ_EMCON_MANIFEST_NOT_YET_VALID)
    return QLINQ_EMCON_SESSION_EXPIRED;
  if (validated != QLINQ_EMCON_MANIFEST_OK ||
      qlinq_emcon_manifest_check_traffic_key(manifest, traffic_secret,
                                             traffic_secret_size) !=
          QLINQ_EMCON_MANIFEST_OK)
    return QLINQ_EMCON_SESSION_INVALID;

  qlinq_emcon_session_t *created = calloc(1, sizeof(*created));
  if (!created)
    return QLINQ_EMCON_SESSION_NO_MEMORY;
  created->manifest = *manifest;
  int ret = send_mode
                ? qlinq_emcon_sender_create(
                      &created->send_crypto, manifest->flow_id,
                      manifest->key_epoch, manifest->initial_packet_number,
                      first_packet_number, traffic_secret, traffic_secret_size)
                : qlinq_emcon_flexicast_create(
                      &created->receive_flow, manifest->flow_id,
                      manifest->key_epoch, manifest->initial_packet_number,
                      traffic_secret, traffic_secret_size);
  if (ret != QLINQ_EMCON_OK) {
    qlinq_emcon_session_free(created);
    if (ret == QLINQ_EMCON_NO_MEMORY)
      return QLINQ_EMCON_SESSION_NO_MEMORY;
    if (ret == QLINQ_EMCON_PACKET_NUMBER_EXHAUSTED)
      return QLINQ_EMCON_SESSION_PACKET_NUMBER_EXHAUSTED;
    return QLINQ_EMCON_SESSION_CRYPTO;
  }
  for (size_t i = 0; !send_mode && i < manifest->stream_count; i++) {
    created->aliases[i] =
        qlinq_emcon_receiver_create_for_messages(manifest->streams[i].alias);
    if (!created->aliases[i]) {
      qlinq_emcon_session_free(created);
      return QLINQ_EMCON_SESSION_NO_MEMORY;
    }
  }
  *session = created;
  return QLINQ_EMCON_SESSION_OK;
}

static int create_sender_socket(qlinq_emcon_send_socket_t **sender,
                                const qlinq_emcon_manifest_t *manifest) {
  struct sockaddr_storage source, destination;
  socklen_t source_len, destination_len;
  if (endpoint_sockaddr(&manifest->source, &source, &source_len) != 0 ||
      endpoint_sockaddr(&manifest->destination, &destination,
                        &destination_len) != 0)
    return QLINQ_EMCON_SESSION_IO;
  if (manifest->source.family == 6) {
    ((struct sockaddr_in6 *)&source)->sin6_scope_id = manifest->interface_index;
    ((struct sockaddr_in6 *)&destination)->sin6_scope_id =
        manifest->interface_index;
  }
  if (qlinq_emcon_send_socket_create(
          sender, (struct sockaddr *)&source, source_len,
          manifest->rate_bytes_per_second, manifest->burst_bytes) != 0)
    return QLINQ_EMCON_SESSION_IO;
  if (qlinq_emcon_send_socket_set_destination(
          *sender, (struct sockaddr *)&destination, destination_len) != 0) {
    qlinq_emcon_send_socket_free(*sender);
    *sender = NULL;
    return QLINQ_EMCON_SESSION_IO;
  }
  return QLINQ_EMCON_SESSION_OK;
}

int qlinq_emcon_session_create_sender(qlinq_emcon_session_t **session,
                                      const qlinq_emcon_manifest_t *manifest,
                                      const uint8_t *traffic_secret,
                                      size_t traffic_secret_size,
                                      uint64_t now_ms) {
  int ret = create_common(session, manifest, traffic_secret,
                          traffic_secret_size, now_ms, true,
                          manifest ? manifest->initial_packet_number : 0);
  if (ret != QLINQ_EMCON_SESSION_OK)
    return ret;
  ret = create_sender_socket(&(*session)->sender, manifest);
  if (ret != QLINQ_EMCON_SESSION_OK) {
    qlinq_emcon_session_free(*session);
    *session = NULL;
    return ret;
  }
  return QLINQ_EMCON_SESSION_OK;
}

int qlinq_emcon_session_create_sender_persistent(
    qlinq_emcon_session_t **session, const qlinq_emcon_manifest_t *manifest,
    const uint8_t *traffic_secret, size_t traffic_secret_size, uint64_t now_ms,
    const char *state_directory, uint64_t reservation_packets) {
  if (!session || !manifest || !traffic_secret || !state_directory ||
      traffic_secret_size != ptls_openssl_aes128gcmsha256.hash->digest_size ||
      reservation_packets == 0)
    return QLINQ_EMCON_SESSION_INVALID;
  *session = NULL;
  int validated = qlinq_emcon_manifest_validate(manifest, now_ms);
  if (validated == QLINQ_EMCON_MANIFEST_EXPIRED ||
      validated == QLINQ_EMCON_MANIFEST_NOT_YET_VALID)
    return QLINQ_EMCON_SESSION_EXPIRED;
  if (validated != QLINQ_EMCON_MANIFEST_OK ||
      qlinq_emcon_manifest_check_traffic_key(manifest, traffic_secret,
                                             traffic_secret_size) !=
          QLINQ_EMCON_MANIFEST_OK)
    return QLINQ_EMCON_SESSION_INVALID;

  qlinq_emcon_activation_t *activation = NULL;
  int activated = qlinq_emcon_activation_open_managed(
      &activation, state_directory, manifest);
  if (activated == QLINQ_EMCON_ACTIVATION_LOCKED)
    return QLINQ_EMCON_SESSION_ACTIVATION_LOCKED;
  if (activated != QLINQ_EMCON_ACTIVATION_OK)
    return QLINQ_EMCON_SESSION_ACTIVATION;
  qlinq_emcon_send_socket_t *sender = NULL;
  int ret = create_sender_socket(&sender, manifest);
  if (ret != QLINQ_EMCON_SESSION_OK) {
    qlinq_emcon_activation_close(activation);
    return ret;
  }
  uint64_t first_packet_number, reserved_until;
  activated =
      qlinq_emcon_activation_reserve(activation, 1, reservation_packets,
                                     &first_packet_number, &reserved_until);
  if (activated != QLINQ_EMCON_ACTIVATION_OK) {
    qlinq_emcon_send_socket_free(sender);
    qlinq_emcon_activation_close(activation);
    return activated == QLINQ_EMCON_ACTIVATION_EXHAUSTED
               ? QLINQ_EMCON_SESSION_PACKET_NUMBER_EXHAUSTED
               : QLINQ_EMCON_SESSION_ACTIVATION;
  }
  ret = create_common(session, manifest, traffic_secret, traffic_secret_size,
                      now_ms, true, first_packet_number);
  if (ret != QLINQ_EMCON_SESSION_OK) {
    qlinq_emcon_send_socket_free(sender);
    qlinq_emcon_activation_close(activation);
    return ret;
  }
  (*session)->activation = activation;
  (*session)->reservation_packets = reservation_packets;
  (*session)->reserved_until = reserved_until;
  (*session)->sender = sender;
  return QLINQ_EMCON_SESSION_OK;
}

static int create_receiver_socket(qlinq_emcon_session_t *session,
                                  unsigned int interface_index,
                                  bool join_group) {
  const qlinq_emcon_manifest_t *manifest = &session->manifest;
  struct sockaddr_storage source, destination;
  socklen_t source_len, destination_len;
  if (endpoint_sockaddr(&manifest->source, &source, &source_len) != 0 ||
      endpoint_sockaddr(&manifest->destination, &destination,
                        &destination_len) != 0)
    return QLINQ_EMCON_SESSION_IO;
  unsigned int scope_index =
      interface_index ? interface_index : manifest->interface_index;
  if (manifest->source.family == 6) {
    ((struct sockaddr_in6 *)&source)->sin6_scope_id = scope_index;
    ((struct sockaddr_in6 *)&destination)->sin6_scope_id = scope_index;
  }
  if (qlinq_emcon_receive_socket_create_multicast(
          &session->receiver, (struct sockaddr *)&destination, destination_len,
          (struct sockaddr *)&source, source_len,
          join_group ? scope_index : interface_index,
          join_group) != QLINQ_EMCON_SOCKET_OK)
    return QLINQ_EMCON_SESSION_IO;
  return QLINQ_EMCON_SESSION_OK;
}

int qlinq_emcon_session_create_receiver(qlinq_emcon_session_t **session,
                                        const qlinq_emcon_manifest_t *manifest,
                                        const uint8_t *traffic_secret,
                                        size_t traffic_secret_size,
                                        uint64_t now_ms) {
  int ret = create_common(session, manifest, traffic_secret,
                          traffic_secret_size, now_ms, false,
                          manifest ? manifest->initial_packet_number : 0);
  if (ret != QLINQ_EMCON_SESSION_OK)
    return ret;
  ret = create_receiver_socket(*session, 0, true);
  if (ret != QLINQ_EMCON_SESSION_OK) {
    qlinq_emcon_session_free(*session);
    *session = NULL;
  }
  return ret;
}

int qlinq_emcon_session_prepare_receiver(
    qlinq_emcon_session_t **session, const qlinq_emcon_manifest_t *manifest,
    const uint8_t *traffic_secret, size_t traffic_secret_size, uint64_t now_ms,
    const char *state_directory, unsigned int interface_index,
    bool join_group) {
  if (!session || !state_directory)
    return QLINQ_EMCON_SESSION_INVALID;
  *session = NULL;
  int ret = create_common(session, manifest, traffic_secret,
                          traffic_secret_size, now_ms, false,
                          manifest ? manifest->initial_packet_number : 0);
  if (ret != QLINQ_EMCON_SESSION_OK)
    return ret;

  int available = qlinq_emcon_receiver_activation_check_available(
      state_directory, manifest);
  if (available == QLINQ_EMCON_ACTIVATION_OK) {
    (*session)->receiver_claim_directory = strdup(state_directory);
    ret = (*session)->receiver_claim_directory
              ? create_receiver_socket(*session, interface_index, join_group)
              : QLINQ_EMCON_SESSION_NO_MEMORY;
  } else {
    ret = available == QLINQ_EMCON_ACTIVATION_REUSED
              ? QLINQ_EMCON_SESSION_ACTIVATION_REUSED
              : QLINQ_EMCON_SESSION_ACTIVATION;
  }
  if (ret != QLINQ_EMCON_SESSION_OK) {
    qlinq_emcon_session_free(*session);
    *session = NULL;
  }
  return ret;
}

int qlinq_emcon_session_claim_receiver(qlinq_emcon_session_t *session) {
  if (!session || !session->receiver_claim_directory)
    return QLINQ_EMCON_SESSION_INVALID;
  int claimed = qlinq_emcon_receiver_activation_claim(
      session->receiver_claim_directory, &session->manifest);
  if (claimed == QLINQ_EMCON_ACTIVATION_REUSED)
    return QLINQ_EMCON_SESSION_ACTIVATION_REUSED;
  if (claimed != QLINQ_EMCON_ACTIVATION_OK)
    return QLINQ_EMCON_SESSION_ACTIVATION;
  free(session->receiver_claim_directory);
  session->receiver_claim_directory = NULL;
  return QLINQ_EMCON_SESSION_OK;
}

int qlinq_emcon_session_create_receiver_claimed(
    qlinq_emcon_session_t **session, const qlinq_emcon_manifest_t *manifest,
    const uint8_t *traffic_secret, size_t traffic_secret_size, uint64_t now_ms,
    const char *state_directory) {
  int ret = qlinq_emcon_session_prepare_receiver(
      session, manifest, traffic_secret, traffic_secret_size, now_ms,
      state_directory, 0, true);
  if (ret != QLINQ_EMCON_SESSION_OK)
    return ret;
  ret = qlinq_emcon_session_claim_receiver(*session);
  if (ret != QLINQ_EMCON_SESSION_OK) {
    qlinq_emcon_session_free(*session);
    *session = NULL;
  }
  return ret;
}

void qlinq_emcon_session_free(qlinq_emcon_session_t *session) {
  if (!session)
    return;
  for (size_t i = 0; i < QLINQ_EMCON_MANIFEST_MAX_STREAMS; i++)
    qlinq_emcon_receiver_free(session->aliases[i]);
  qlinq_emcon_receive_socket_free(session->receiver);
  qlinq_emcon_send_socket_free(session->sender);
  qlinq_emcon_sender_free(session->send_crypto);
  quicly_flexicast_flow_free(session->receive_flow);
  qlinq_emcon_activation_close(session->activation);
  free(session->receiver_claim_directory);
  memset(session, 0, sizeof(*session));
  free(session);
}

static int ensure_packet_capacity(qlinq_emcon_session_t *session,
                                  uint64_t packets) {
  if (!qlinq_emcon_sender_has_capacity(session->send_crypto, packets))
    return QLINQ_EMCON_SESSION_PACKET_NUMBER_EXHAUSTED;
  if (!session->activation)
    return QLINQ_EMCON_SESSION_OK;
  uint64_t next = qlinq_emcon_sender_next_packet_number(session->send_crypto);
  if (next > session->reserved_until)
    return QLINQ_EMCON_SESSION_ACTIVATION;
  uint64_t available = session->reserved_until - next;
  if (available >= packets)
    return QLINQ_EMCON_SESSION_OK;
  uint64_t additional = packets - available;
  uint64_t reserve = session->reservation_packets > additional
                         ? session->reservation_packets
                         : additional;
  uint64_t first, limit;
  int ret = qlinq_emcon_activation_reserve(session->activation, additional,
                                           reserve, &first, &limit);
  if (ret == QLINQ_EMCON_ACTIVATION_EXHAUSTED)
    return QLINQ_EMCON_SESSION_PACKET_NUMBER_EXHAUSTED;
  if (ret != QLINQ_EMCON_ACTIVATION_OK || first != session->reserved_until ||
      limit <= first)
    return QLINQ_EMCON_SESSION_ACTIVATION;
  session->reserved_until = limit;
  return QLINQ_EMCON_SESSION_OK;
}

static int send_metadata(qlinq_emcon_session_t *session,
                         qlinq_emcon_record_type_t type, const uint8_t *payload,
                         size_t payload_size) {
  uint8_t packet[QLINQ_EMCON_FLEXICAST_OVERHEAD +
                 QLINQ_EMCON_SESSION_WIRE_SIZE + 32];
  size_t packet_size;
  uint64_t packet_number;
  if (qlinq_emcon_flexicast_seal(session->send_crypto, type,
                                 ptls_iovec_init(payload, payload_size), packet,
                                 sizeof(packet), &packet_size,
                                 &packet_number) != QLINQ_EMCON_OK)
    return QLINQ_EMCON_SESSION_CRYPTO;
  (void)packet_number;
  if (qlinq_emcon_send_socket_send(session->sender, packet, packet_size) != 0)
    return QLINQ_EMCON_SESSION_IO;
  session->stats.metadata_sent++;
  return QLINQ_EMCON_SESSION_OK;
}

static int send_session_metadata(qlinq_emcon_session_t *session,
                                 uint64_t now_ms) {
  uint8_t encoded[QLINQ_EMCON_SESSION_WIRE_SIZE];
  qlinq_emcon_session_metadata_t metadata = {.source_time_ms = now_ms,
                                             .stream_table_revision = 1};
  memcpy(metadata.session_id, session->manifest.session_id,
         sizeof(metadata.session_id));
  if (qlinq_emcon_manifest_digest(&session->manifest,
                                  metadata.manifest_digest) !=
          QLINQ_EMCON_MANIFEST_OK ||
      qlinq_emcon_encode_session(encoded, sizeof(encoded), &metadata) !=
          QLINQ_EMCON_METADATA_OK)
    return QLINQ_EMCON_SESSION_INVALID;
  int ret = send_metadata(session, QLINQ_EMCON_RECORD_SESSION, encoded,
                          sizeof(encoded));
  if (ret == QLINQ_EMCON_SESSION_OK) {
    session->session_announced = true;
    session->last_session_metadata_ms = now_ms;
  }
  return ret;
}

static int prepare_send(qlinq_emcon_session_t *session, uint64_t packets) {
  if (!session->send_crypto || !session->sender)
    return QLINQ_EMCON_SESSION_INVALID;
  uint64_t now = realtime_ms();
  if (now == 0 || now >= session->manifest.expires_at_ms)
    return QLINQ_EMCON_SESSION_EXPIRED;
  bool announce = !session->session_announced ||
                  now - session->last_session_metadata_ms >=
                      session->manifest.metadata_repeat_interval_ms;
  int ret = ensure_packet_capacity(session, packets + announce);
  return ret == QLINQ_EMCON_SESSION_OK && announce
             ? send_session_metadata(session, now)
             : ret;
}

int qlinq_emcon_session_send_object(qlinq_emcon_session_t *session,
                                    uint8_t alias, uint64_t group_id,
                                    uint64_t object_id, bool keyframe,
                                    uint8_t priority, const void *data,
                                    size_t size) {
  size_t index;
  if (!session || !session->send_crypto || !data)
    return QLINQ_EMCON_SESSION_INVALID;
  if (!find_stream(session, alias, &index))
    return QLINQ_EMCON_SESSION_UNKNOWN_ALIAS;
  if (size == 0 || size > session->manifest.streams[index].maximum_record_size)
    return QLINQ_EMCON_SESSION_INVALID;
  uint64_t data_symbols = (size + session->manifest.symbol_size - 1) /
                          session->manifest.symbol_size;
  int ret =
      prepare_send(session, data_symbols + session->manifest.repair_symbols);
  if (ret != QLINQ_EMCON_SESSION_OK)
    return ret;
  qlinq_emcon_rateless_config_t config = {
      .alias = alias,
      .symbol_size = session->manifest.symbol_size,
      .repair_symbols = session->manifest.repair_symbols,
  };
  int sent = qlinq_emcon_send_object(
      session->send_crypto, &config, group_id, object_id, keyframe, priority,
      data, size, qlinq_emcon_send_socket_emit, session->sender);
  return sent == QLINQ_EMCON_OK ? QLINQ_EMCON_SESSION_OK
                                : QLINQ_EMCON_SESSION_IO;
}

int qlinq_emcon_session_send_window(
    qlinq_emcon_session_t *session,
    const qlinq_emcon_window_metadata_t *window) {
  uint8_t encoded[QLINQ_EMCON_WINDOW_WIRE_SIZE];
  if (!session || !window || !find_stream(session, window->alias, NULL) ||
      qlinq_emcon_encode_window(encoded, sizeof(encoded), window) !=
          QLINQ_EMCON_METADATA_OK)
    return QLINQ_EMCON_SESSION_INVALID;
  int ret = prepare_send(session, 1);
  return ret == QLINQ_EMCON_SESSION_OK
             ? send_metadata(session, QLINQ_EMCON_RECORD_WINDOW, encoded,
                             sizeof(encoded))
             : ret;
}

int qlinq_emcon_session_send_end(qlinq_emcon_session_t *session,
                                 const qlinq_emcon_end_metadata_t *end) {
  uint8_t encoded[QLINQ_EMCON_END_WIRE_SIZE];
  if (!session || !end || !find_stream(session, end->alias, NULL) ||
      qlinq_emcon_encode_end(encoded, sizeof(encoded), end) !=
          QLINQ_EMCON_METADATA_OK)
    return QLINQ_EMCON_SESSION_INVALID;
  int ret = prepare_send(session, session->manifest.terminal_repeat_count);
  for (size_t i = 0; ret == QLINQ_EMCON_SESSION_OK &&
                     i < session->manifest.terminal_repeat_count;
       i++)
    ret = send_metadata(session, QLINQ_EMCON_RECORD_END, encoded,
                        sizeof(encoded));
  return ret;
}

int qlinq_emcon_session_send_abort(
    qlinq_emcon_session_t *session,
    const qlinq_emcon_abort_metadata_t *abort_metadata) {
  uint8_t encoded[QLINQ_EMCON_ABORT_WIRE_SIZE];
  if (!session || !abort_metadata ||
      qlinq_emcon_encode_abort(encoded, sizeof(encoded), abort_metadata) !=
          QLINQ_EMCON_METADATA_OK)
    return QLINQ_EMCON_SESSION_INVALID;
  int ret = prepare_send(session, 1);
  return ret == QLINQ_EMCON_SESSION_OK
             ? send_metadata(session, QLINQ_EMCON_RECORD_ABORT, encoded,
                             sizeof(encoded))
             : ret;
}

static int alias_from_message(const qlinq_emcon_message_t *message,
                              uint8_t *alias) {
  if (message->type == QLINQ_EMCON_RECORD_DATA) {
    qlinq_wire_fec_header_t header;
    if (qlinq_wire_decode_fec_header(message->payload.base,
                                     message->payload.len,
                                     &header) != QLINQ_WIRE_OK)
      return -1;
    *alias = header.alias;
    return 1;
  }
  if (message->type == QLINQ_EMCON_RECORD_WINDOW) {
    qlinq_emcon_window_metadata_t window;
    if (qlinq_emcon_decode_window(message->payload.base, message->payload.len,
                                  &window) != QLINQ_EMCON_METADATA_OK)
      return -1;
    *alias = window.alias;
    return 1;
  }
  if (message->type == QLINQ_EMCON_RECORD_END) {
    qlinq_emcon_end_metadata_t end;
    if (qlinq_emcon_decode_end(message->payload.base, message->payload.len,
                               &end) != QLINQ_EMCON_METADATA_OK)
      return -1;
    *alias = end.alias;
    return 1;
  }
  return 0;
}

int qlinq_emcon_session_receive(qlinq_emcon_session_t *session,
                                qlinq_emcon_event_t *event, bool nonblocking) {
  uint8_t packet[QLINQ_EMCON_MAX_PACKET_SIZE];
  size_t packet_size;
  if (!session || !session->receive_flow || !session->receiver || !event)
    return QLINQ_EMCON_SESSION_INVALID;
  if (session->receiver_claim_directory)
    return QLINQ_EMCON_SESSION_ACTIVATION;
  uint64_t now = realtime_ms();
  if (now == 0 || now >= session->manifest.expires_at_ms)
    return QLINQ_EMCON_SESSION_EXPIRED;
  int received = qlinq_emcon_receive_socket_receive(
      session->receiver, packet, sizeof(packet), &packet_size, nonblocking);
  if (received == QLINQ_EMCON_SOCKET_WOULD_BLOCK)
    return QLINQ_EMCON_SESSION_WOULD_BLOCK;
  if (received != QLINQ_EMCON_SOCKET_OK)
    return QLINQ_EMCON_SESSION_IO;
  session->stats.packets_received++;
  session->stats.bytes_received += packet_size;

  qlinq_emcon_message_t message;
  int opened = qlinq_emcon_flexicast_open(session->receive_flow, packet,
                                          packet_size, &message);
  if (opened == QLINQ_EMCON_DUPLICATE) {
    session->stats.replay_rejections++;
    return QLINQ_EMCON_SESSION_DUPLICATE;
  }
  if (opened != QLINQ_EMCON_OK) {
    session->stats.authentication_failures++;
    return QLINQ_EMCON_SESSION_CRYPTO;
  }
  uint8_t alias = 0;
  int has_alias = alias_from_message(&message, &alias);
  if (has_alias < 0)
    return QLINQ_EMCON_SESSION_INVALID;
  qlinq_emcon_receiver_t *receiver =
      has_alias ? find_alias(session, alias) : session->aliases[0];
  if (!receiver) {
    session->stats.unknown_aliases++;
    return QLINQ_EMCON_SESSION_UNKNOWN_ALIAS;
  }
  int ingested = qlinq_emcon_receiver_ingest_message(receiver, &message, event);
  if (ingested == QLINQ_EMCON_INCOMPLETE)
    return QLINQ_EMCON_SESSION_INCOMPLETE;
  if (ingested == QLINQ_EMCON_DUPLICATE)
    return QLINQ_EMCON_SESSION_DUPLICATE;
  if (ingested != QLINQ_EMCON_OK)
    return QLINQ_EMCON_SESSION_INVALID;

  if (event->type == QLINQ_EMCON_EVENT_SESSION) {
    uint8_t digest[32];
    if (memcmp(event->value.session.session_id, session->manifest.session_id,
               sizeof(session->manifest.session_id)) != 0 ||
        qlinq_emcon_manifest_digest(&session->manifest, digest) !=
            QLINQ_EMCON_MANIFEST_OK ||
        memcmp(event->value.session.manifest_digest, digest, sizeof(digest)) !=
            0) {
      qlinq_emcon_event_release(event);
      return QLINQ_EMCON_SESSION_INVALID;
    }
  }
  if (event->type == QLINQ_EMCON_EVENT_RECORD)
    session->stats.records_completed++;
  else
    session->stats.metadata_received++;
  return QLINQ_EMCON_SESSION_OK;
}

qlinq_emcon_session_stats_t
qlinq_emcon_session_stats(const qlinq_emcon_session_t *session) {
  qlinq_emcon_session_stats_t stats =
      session ? session->stats : (qlinq_emcon_session_stats_t){0};
  if (session && session->sender)
    stats.send = qlinq_emcon_send_socket_stats(session->sender);
  if (session) {
    stats.next_packet_number =
        session->send_crypto
            ? qlinq_emcon_sender_next_packet_number(session->send_crypto)
            : session->manifest.initial_packet_number;
    stats.reserved_until = session->reserved_until;
    stats.persistent_activation = session->activation != NULL;
  }
  return stats;
}
