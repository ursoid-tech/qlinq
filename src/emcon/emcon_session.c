#include "emcon_session.h"

#include "fs_util.h"
#include "picotls/openssl.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

struct qlinq_emcon_session_t {
  qlinq_emcon_manifest_t manifest;
  qlinq_emcon_sender_t *send_crypto;
  qlinq_emcon_ingress_t *receive_crypto;
  qlinq_emcon_send_socket_t *sender;
  qlinq_emcon_receive_socket_t *receiver;
  qlinq_emcon_activation_t *activation;
  char *receiver_claim_directory;
  qlinq_emcon_receiver_t *aliases[QLINQ_EMCON_MANIFEST_MAX_STREAMS];
  uint64_t reservation_packets;
  uint64_t reserved_until;
  uint64_t filter_group_id;
  uint8_t filter_alias;
  bool filter_active;
  qlinq_emcon_cancel_fn should_cancel;
  void *cancel_data;
  qlinq_emcon_session_stats_t stats;
};

static int endpoint_sockaddr(const qlinq_emcon_manifest_endpoint_t *ep,
                             uint32_t scope_id, struct sockaddr_storage *addr,
                             socklen_t *addr_len) {
  memset(addr, 0, sizeof(*addr));
  if (ep->family == 4) {
    struct sockaddr_in *v4 = (struct sockaddr_in *)addr;
    v4->sin_family = AF_INET;
    v4->sin_port = htons(ep->port);
    memcpy(&v4->sin_addr, ep->address, 4);
    *addr_len = sizeof(*v4);
    return 0;
  }
  if (ep->family == 6) {
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)addr;
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htons(ep->port);
    v6->sin6_scope_id = scope_id;
    memcpy(&v6->sin6_addr, ep->address, 16);
    *addr_len = sizeof(*v6);
    return 0;
  }
  return -1;
}

static bool find_manifest_stream(const qlinq_emcon_manifest_t *manifest,
                                 uint8_t alias, size_t *index) {
  for (size_t i = 0; i < manifest->stream_count; i++) {
    if (manifest->streams[i].alias == alias) {
      if (index)
        *index = i;
      return true;
    }
  }
  return false;
}

static uint32_t max_manifest_record_size(const qlinq_emcon_manifest_t *m) {
  uint32_t max_rec = 0;
  for (size_t i = 0; i < m->stream_count; i++)
    if (m->streams[i].maximum_record_size > max_rec)
      max_rec = m->streams[i].maximum_record_size;
  return max_rec;
}

static int validate_session_manifest(const qlinq_emcon_manifest_t *manifest,
                                     const uint8_t *traffic_secret,
                                     size_t traffic_secret_size,
                                     uint64_t now_ms) {
  if (!manifest || !traffic_secret ||
      traffic_secret_size != ptls_openssl_aes128gcmsha256.hash->digest_size)
    return QLINQ_EMCON_ERR_INVALID;
  int ret = qlinq_emcon_manifest_validate(manifest, now_ms);
  if (ret == QLINQ_EMCON_ERR_NOT_YET_VALID)
    return QLINQ_EMCON_ERR_EXPIRED;
  if (ret != QLINQ_EMCON_OK)
    return ret;
  return qlinq_emcon_manifest_check_traffic_key(
             manifest, traffic_secret, traffic_secret_size) == QLINQ_EMCON_OK
             ? QLINQ_EMCON_OK
             : QLINQ_EMCON_ERR_INVALID;
}

static int create_common(qlinq_emcon_session_t **session,
                         const qlinq_emcon_manifest_t *manifest,
                         const uint8_t *traffic_secret,
                         size_t traffic_secret_size, bool send_mode,
                         uint64_t first_packet_number) {
  uint8_t digest[QLINQ_EMCON_MANIFEST_DIGEST_SIZE];
  if (qlinq_emcon_manifest_digest(manifest, digest) != QLINQ_EMCON_OK)
    return QLINQ_EMCON_ERR_INVALID;
  qlinq_emcon_session_t *created = calloc(1, sizeof(*created));
  if (!created)
    return QLINQ_EMCON_ERR_NO_MEMORY;
  created->manifest = *manifest;
  int ret =
      send_mode
          ? qlinq_emcon_sender_create(
                &created->send_crypto, manifest->flow_id, manifest->key_epoch,
                digest, first_packet_number, manifest->symbol_size,
                manifest->repair_symbols, max_manifest_record_size(manifest),
                traffic_secret, traffic_secret_size)
          : qlinq_emcon_ingress_create(&created->receive_crypto,
                                       manifest->flow_id, manifest->key_epoch,
                                       digest, 0, traffic_secret,
                                       traffic_secret_size);
  if (ret != QLINQ_EMCON_OK) {
    qlinq_emcon_session_free(created);
    return ret;
  }
  for (size_t i = 0; !send_mode && i < manifest->stream_count; i++) {
    created->aliases[i] = qlinq_emcon_receiver_create(
        manifest->streams[i].alias, manifest->symbol_size,
        manifest->repair_symbols, manifest->streams[i].maximum_record_size);
    if (!created->aliases[i]) {
      qlinq_emcon_session_free(created);
      return QLINQ_EMCON_ERR_NO_MEMORY;
    }
  }
  *session = created;
  return QLINQ_EMCON_OK;
}

int qlinq_emcon_session_create_sender(
    qlinq_emcon_session_t **session, const qlinq_emcon_manifest_t *manifest,
    const uint8_t *traffic_secret, size_t traffic_secret_size, uint64_t now_ms,
    const char *state_directory, uint64_t reservation_packets,
    const qlinq_emcon_transfer_t *transfer) {
  if (!session || !state_directory || reservation_packets == 0)
    return QLINQ_EMCON_ERR_INVALID;
  *session = NULL;
  int ret = validate_session_manifest(manifest, traffic_secret,
                                      traffic_secret_size, now_ms);
  if (ret != QLINQ_EMCON_OK)
    return ret;
  if (transfer) {
    size_t idx;
    if (!find_manifest_stream(manifest, transfer->alias, &idx))
      return QLINQ_EMCON_ERR_UNKNOWN_ALIAS;
    if (transfer->block_size == 0 ||
        transfer->block_size > manifest->streams[idx].maximum_record_size)
      return QLINQ_EMCON_ERR_INVALID;
  }

  qlinq_emcon_activation_t *activation = NULL;
  ret = qlinq_emcon_activation_open_managed(&activation, state_directory,
                                            manifest);
  if (ret != QLINQ_EMCON_OK)
    return ret == QLINQ_EMCON_ERR_LOCKED ? ret : QLINQ_EMCON_ERR_ACTIVATION;
  if (transfer && (ret = qlinq_emcon_activation_check_transfer(
                       activation, transfer)) != QLINQ_EMCON_OK) {
    qlinq_emcon_activation_close(activation);
    return (ret == QLINQ_EMCON_ERR_TRANSFER_MISMATCH ||
            ret == QLINQ_EMCON_ERR_INVALID)
               ? ret
               : QLINQ_EMCON_ERR_ACTIVATION;
  }

  struct sockaddr_storage source, destination;
  socklen_t source_len, destination_len;
  qlinq_emcon_send_socket_t *sender = NULL;
  if (endpoint_sockaddr(&manifest->source, manifest->interface_index, &source,
                        &source_len) != 0 ||
      endpoint_sockaddr(&manifest->destination, manifest->interface_index,
                        &destination, &destination_len) != 0 ||
      qlinq_emcon_send_socket_create(
          &sender, (struct sockaddr *)&source, source_len,
          (struct sockaddr *)&destination, destination_len,
          manifest->rate_bytes_per_second, manifest->burst_bytes,
          manifest->expires_at_ms) != QLINQ_EMCON_OK) {
    qlinq_emcon_activation_close(activation);
    return QLINQ_EMCON_ERR_IO;
  }
  if (transfer && (ret = qlinq_emcon_activation_bind_transfer(
                       activation, transfer)) != QLINQ_EMCON_OK) {
    qlinq_emcon_send_socket_free(sender);
    qlinq_emcon_activation_close(activation);
    return ret == QLINQ_EMCON_ERR_TRANSFER_MISMATCH
               ? ret
               : QLINQ_EMCON_ERR_ACTIVATION;
  }
  uint64_t first_pn, reserved_until;
  ret = qlinq_emcon_activation_reserve(activation, 1, reservation_packets,
                                       &first_pn, &reserved_until);
  if (ret != QLINQ_EMCON_OK) {
    qlinq_emcon_send_socket_free(sender);
    qlinq_emcon_activation_close(activation);
    return ret == QLINQ_EMCON_ERR_EXHAUSTED ? ret : QLINQ_EMCON_ERR_ACTIVATION;
  }
  ret = create_common(session, manifest, traffic_secret, traffic_secret_size,
                      true, first_pn);
  if (ret != QLINQ_EMCON_OK) {
    qlinq_emcon_send_socket_free(sender);
    qlinq_emcon_activation_close(activation);
    return ret;
  }
  (*session)->activation = activation;
  (*session)->reservation_packets = reservation_packets;
  (*session)->reserved_until = reserved_until;
  (*session)->sender = sender;
  return QLINQ_EMCON_OK;
}

int qlinq_emcon_session_prepare_receiver(
    qlinq_emcon_session_t **session, const qlinq_emcon_manifest_t *manifest,
    const uint8_t *traffic_secret, size_t traffic_secret_size, uint64_t now_ms,
    const char *state_directory, unsigned int interface_index,
    bool join_group) {
  if (!session || !state_directory)
    return QLINQ_EMCON_ERR_INVALID;
  *session = NULL;
  int ret = validate_session_manifest(manifest, traffic_secret,
                                      traffic_secret_size, now_ms);
  if (ret == QLINQ_EMCON_OK)
    ret = create_common(session, manifest, traffic_secret, traffic_secret_size,
                        false, 0);
  if (ret != QLINQ_EMCON_OK)
    return ret;

  int avail = qlinq_emcon_receiver_activation_check_available(state_directory,
                                                              manifest);
  if (avail != QLINQ_EMCON_OK) {
    ret = avail == QLINQ_EMCON_ERR_REUSED ? avail : QLINQ_EMCON_ERR_ACTIVATION;
  } else if (!((*session)->receiver_claim_directory =
                   strdup(state_directory))) {
    ret = QLINQ_EMCON_ERR_NO_MEMORY;
  } else {
    bool eff_join = qlinq_ip_is_multicast(manifest->destination.family,
                                          manifest->destination.address) &&
                    join_group;
    unsigned int sock_if = interface_index
                               ? interface_index
                               : (eff_join ? manifest->interface_index : 0);
    struct sockaddr_storage source, destination;
    socklen_t source_len, destination_len;
    if (endpoint_sockaddr(&manifest->source, sock_if, &source, &source_len) !=
            0 ||
        endpoint_sockaddr(&manifest->destination, sock_if, &destination,
                          &destination_len) != 0 ||
        qlinq_emcon_receive_socket_create_multicast(
            &(*session)->receiver, (struct sockaddr *)&destination,
            destination_len, (struct sockaddr *)&source, source_len, sock_if,
            eff_join) != QLINQ_EMCON_OK)
      ret = QLINQ_EMCON_ERR_IO;
  }
  if (ret != QLINQ_EMCON_OK) {
    qlinq_emcon_session_free(*session);
    *session = NULL;
  }
  return ret;
}

int qlinq_emcon_session_claim_receiver(qlinq_emcon_session_t *session) {
  if (!session || !session->receiver_claim_directory)
    return QLINQ_EMCON_ERR_INVALID;
  int ret = qlinq_emcon_receiver_activation_claim(
      session->receiver_claim_directory, &session->manifest);
  if (ret != QLINQ_EMCON_OK)
    return ret == QLINQ_EMCON_ERR_REUSED ? ret : QLINQ_EMCON_ERR_ACTIVATION;
  free(session->receiver_claim_directory);
  session->receiver_claim_directory = NULL;
  return QLINQ_EMCON_OK;
}

int qlinq_emcon_session_set_receive_filter(qlinq_emcon_session_t *session,
                                           uint8_t alias, uint64_t group_id) {
  if (!session || !session->receive_crypto)
    return QLINQ_EMCON_ERR_INVALID;
  if (!find_manifest_stream(&session->manifest, alias, NULL))
    return QLINQ_EMCON_ERR_UNKNOWN_ALIAS;
  session->filter_active = true;
  session->filter_alias = alias;
  session->filter_group_id = group_id;
  return QLINQ_EMCON_OK;
}

void qlinq_emcon_session_set_cancel(qlinq_emcon_session_t *session,
                                    qlinq_emcon_cancel_fn should_cancel,
                                    void *cancel_data) {
  if (!session)
    return;
  session->should_cancel = should_cancel;
  session->cancel_data = cancel_data;
  if (session->sender)
    qlinq_emcon_send_socket_set_cancel(session->sender, should_cancel,
                                       cancel_data);
  if (session->receiver)
    qlinq_emcon_receive_socket_set_cancel(session->receiver, should_cancel,
                                          cancel_data);
}

void qlinq_emcon_session_free(qlinq_emcon_session_t *session) {
  if (!session)
    return;
  for (size_t i = 0; i < QLINQ_EMCON_MANIFEST_MAX_STREAMS; i++)
    qlinq_emcon_receiver_free(session->aliases[i]);
  qlinq_emcon_receive_socket_free(session->receiver);
  qlinq_emcon_send_socket_free(session->sender);
  qlinq_emcon_sender_free(session->send_crypto);
  qlinq_emcon_ingress_free(session->receive_crypto);
  qlinq_emcon_activation_close(session->activation);
  free(session->receiver_claim_directory);
  memset(session, 0, sizeof(*session));
  free(session);
}

static int prepare_send(qlinq_emcon_session_t *session, uint64_t packets) {
  if (!session->send_crypto || !session->sender)
    return QLINQ_EMCON_ERR_INVALID;
  if (session->should_cancel && session->should_cancel(session->cancel_data))
    return QLINQ_EMCON_ERR_INTERRUPTED;
  uint64_t now = qlinq_emcon_realtime_ms();
  if (!now || now >= session->manifest.expires_at_ms)
    return QLINQ_EMCON_ERR_EXPIRED;
  if (!qlinq_emcon_sender_has_capacity(session->send_crypto, packets))
    return QLINQ_EMCON_ERR_EXHAUSTED;
  if (!session->activation)
    return QLINQ_EMCON_OK;
  uint64_t next = qlinq_emcon_sender_next_packet_number(session->send_crypto);
  if (next > session->reserved_until)
    return QLINQ_EMCON_ERR_ACTIVATION;
  uint64_t avail = session->reserved_until - next;
  if (avail >= packets)
    return QLINQ_EMCON_OK;
  uint64_t add = packets - avail;
  uint64_t pref =
      session->reservation_packets > add ? session->reservation_packets : add;
  uint64_t first, limit;
  int ret = qlinq_emcon_activation_reserve(session->activation, add, pref,
                                           &first, &limit);
  if (ret == QLINQ_EMCON_ERR_EXHAUSTED)
    return ret;
  if (ret != QLINQ_EMCON_OK || first != session->reserved_until ||
      limit <= first)
    return QLINQ_EMCON_ERR_ACTIVATION;
  session->reserved_until = limit;
  return QLINQ_EMCON_OK;
}

static int send_packet(qlinq_emcon_send_socket_t *sender, const uint8_t *packet,
                       size_t packet_size) {
  int ret = qlinq_emcon_send_socket_send(sender, packet, packet_size);
  return (ret == QLINQ_EMCON_OK || ret == QLINQ_EMCON_ERR_INTERRUPTED ||
          ret == QLINQ_EMCON_ERR_EXPIRED)
             ? ret
             : QLINQ_EMCON_ERR_IO;
}

struct emcon_object_emitter {
  qlinq_emcon_send_socket_t *sender;
  int result;
};

static bool emit_symbol(void *user_data, uint16_t symbol_index,
                        const uint8_t *packet, size_t packet_size) {
  (void)symbol_index;
  struct emcon_object_emitter *em = user_data;
  em->result = send_packet(em->sender, packet, packet_size);
  return em->result == QLINQ_EMCON_OK;
}

int qlinq_emcon_session_send_object(qlinq_emcon_session_t *session,
                                    uint8_t alias, uint64_t group_id,
                                    uint64_t object_id, bool keyframe,
                                    uint8_t priority, const void *data,
                                    size_t size) {
  size_t index;
  if (!session || !session->send_crypto || !data)
    return QLINQ_EMCON_ERR_INVALID;
  if (!find_manifest_stream(&session->manifest, alias, &index))
    return QLINQ_EMCON_ERR_UNKNOWN_ALIAS;
  if (size == 0 || size > session->manifest.streams[index].maximum_record_size)
    return QLINQ_EMCON_ERR_INVALID;
  uint64_t data_symbols = (size + session->manifest.symbol_size - 1U) /
                          session->manifest.symbol_size;
  int ret =
      prepare_send(session, data_symbols + session->manifest.repair_symbols);
  if (ret != QLINQ_EMCON_OK)
    return ret;
  struct emcon_object_emitter emitter = {.sender = session->sender};
  int sent = qlinq_emcon_send_object(session->send_crypto, alias, group_id,
                                     object_id, keyframe, priority, data, size,
                                     emit_symbol, &emitter);
  if (sent == QLINQ_EMCON_ERR_EMIT_FAILED)
    return emitter.result;
  return sent == QLINQ_EMCON_OK ? QLINQ_EMCON_OK : QLINQ_EMCON_ERR_IO;
}

int qlinq_emcon_session_send_end(qlinq_emcon_session_t *session, uint8_t alias,
                                 uint64_t group_id, uint64_t final_object_id) {
  if (!session || !find_manifest_stream(&session->manifest, alias, NULL))
    return QLINQ_EMCON_ERR_INVALID;
  int ret = prepare_send(session, session->manifest.terminal_repeat_count);
  for (size_t i = 0;
       ret == QLINQ_EMCON_OK && i < session->manifest.terminal_repeat_count;
       i++) {
    if (session->should_cancel && session->should_cancel(session->cancel_data))
      return QLINQ_EMCON_ERR_INTERRUPTED;
    uint8_t packet[QLINQ_EMCON_FLEXICAST_OVERHEAD +
                   QLINQ_WIRE_FRAME_HEADER_SIZE + QLINQ_WIRE_TRACK_END_SIZE];
    size_t packet_size;
    if (qlinq_emcon_seal_end(session->send_crypto, alias, group_id,
                             final_object_id, packet, sizeof(packet),
                             &packet_size, NULL) != QLINQ_EMCON_OK)
      return QLINQ_EMCON_ERR_CRYPTO;
    ret = send_packet(session->sender, packet, packet_size);
    if (ret == QLINQ_EMCON_OK)
      session->stats.metadata_sent++;
  }
  return ret;
}

int qlinq_emcon_session_receive(qlinq_emcon_session_t *session,
                                qlinq_emcon_event_t *event, bool nonblocking) {
  uint8_t packet[QLINQ_EMCON_MAX_PACKET_SIZE];
  size_t packet_size;
  if (!session || !session->receive_crypto || !session->receiver || !event)
    return QLINQ_EMCON_ERR_INVALID;
  if (session->receiver_claim_directory)
    return QLINQ_EMCON_ERR_ACTIVATION;
  int ret = qlinq_emcon_receive_socket_receive(
      session->receiver, packet, sizeof(packet), &packet_size, nonblocking,
      session->manifest.expires_at_ms);
  if (ret == QLINQ_EMCON_ERR_TOO_LARGE)
    return QLINQ_EMCON_DISCARDED;
  if (ret != QLINQ_EMCON_OK)
    return ret;
  session->stats.packets_received++;
  session->stats.bytes_received += packet_size;

  ptls_iovec_t datagram;
  uint64_t pn;
  ret = qlinq_emcon_flexicast_open(session->receive_crypto, packet, packet_size,
                                   &datagram, &pn);
  if (ret == QLINQ_EMCON_DUPLICATE)
    session->stats.replay_rejections++;
  if (ret != QLINQ_EMCON_OK)
    return ret;

  uint8_t alias;
  uint64_t group_id;
  ret = qlinq_emcon_datagram_target(datagram, &alias, &group_id);
  if (ret != QLINQ_EMCON_OK)
    return ret;
  size_t stream_idx;
  if (!find_manifest_stream(&session->manifest, alias, &stream_idx)) {
    session->stats.unknown_aliases++;
    return QLINQ_EMCON_ERR_UNKNOWN_ALIAS;
  }
  if (session->filter_active &&
      (alias != session->filter_alias || group_id != session->filter_group_id))
    return QLINQ_EMCON_DISCARDED;
  ret = qlinq_emcon_receiver_ingest(session->aliases[stream_idx], pn, datagram,
                                    event);
  if (ret == QLINQ_EMCON_OK) {
    if (event->type == QLINQ_EMCON_EVENT_RECORD)
      session->stats.records_completed++;
    else
      session->stats.metadata_received++;
  }
  return ret;
}

qlinq_emcon_session_stats_t
qlinq_emcon_session_stats(const qlinq_emcon_session_t *session) {
  qlinq_emcon_session_stats_t stats =
      session ? session->stats : (qlinq_emcon_session_stats_t){0};
  if (!session)
    return stats;
  if (session->sender)
    stats.send = qlinq_emcon_send_socket_stats(session->sender);
  if (session->receive_crypto)
    stats.authentication_failures =
        qlinq_emcon_ingress_authentication_failures(session->receive_crypto);
  stats.next_packet_number =
      session->send_crypto
          ? qlinq_emcon_sender_next_packet_number(session->send_crypto)
          : 0;
  stats.reserved_until = session->reserved_until;
  stats.persistent_activation = session->activation != NULL;
  return stats;
}
