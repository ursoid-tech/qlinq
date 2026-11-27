#include "../../src/emcon/emcon_session.h"
#include "../../src/emcon/emcon_activation.h"
#include "transport_wire.h"

#include "picotls/openssl.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "EMCON session test failed: %s\n", message);             \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static uint64_t now_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static uint16_t free_port(void) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in address = {.sin_family = AF_INET,
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  socklen_t size = sizeof(address);
  if (fd < 0 || bind(fd, (struct sockaddr *)&address, size) != 0 ||
      getsockname(fd, (struct sockaddr *)&address, &size) != 0) {
    if (fd >= 0)
      close(fd);
    return 0;
  }
  close(fd);
  return ntohs(address.sin_port);
}

static int remove_state_directory(const char *path) {
  DIR *directory = opendir(path);
  if (!directory)
    return -1;
  int directory_fd = dirfd(directory);
  int ret = 0;
  struct dirent *entry;
  while ((entry = readdir(directory)) != NULL) {
    if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0 &&
        unlinkat(directory_fd, entry->d_name, 0) != 0)
      ret = -1;
  }
  closedir(directory);
  return ret == 0 ? rmdir(path) : -1;
}

static int open_claimed_receiver(qlinq_emcon_session_t **session,
                                 const qlinq_emcon_manifest_t *manifest,
                                 const uint8_t *secret, size_t secret_size,
                                 uint64_t now, const char *state_directory) {
  int ret = qlinq_emcon_session_prepare_receiver(
      session, manifest, secret, secret_size, now, state_directory, 0, true);
  if (ret != QLINQ_EMCON_OK)
    return ret;
  ret = qlinq_emcon_session_claim_receiver(*session);
  if (ret != QLINQ_EMCON_OK) {
    qlinq_emcon_session_free(*session);
    *session = NULL;
  }
  return ret;
}

static qlinq_emcon_manifest_t fixture(const uint8_t *secret, uint64_t now) {
  qlinq_emcon_manifest_t manifest = {
      .flow_id = 900,
      .key_epoch = 11,
      .valid_from_ms = now - 1000,
      .expires_at_ms = now + 60000,
      .source = {.family = 4},
      .destination = {.family = 4},
      .rate_bytes_per_second = 10000000,
      .burst_bytes = 4096,
      .terminal_repeat_count = 2,
      .symbol_size = 256,
      .repair_symbols = 2,
      .stream_count = 6,
  };
  qlinq_emcon_traffic_key_id(secret, 32, manifest.traffic_key_id);
  inet_pton(AF_INET, "127.0.0.1", manifest.source.address);
  inet_pton(AF_INET, "127.0.0.1", manifest.destination.address);
  manifest.source.port = free_port();
  do {
    manifest.destination.port = free_port();
  } while (manifest.destination.port == manifest.source.port);
  for (size_t i = 0; i < manifest.stream_count; i++) {
    manifest.streams[i].alias = (uint8_t)(20 + i);
    manifest.streams[i].content_type = 0;
    manifest.streams[i].maximum_record_size = 4096;
    snprintf(manifest.streams[i].name, sizeof(manifest.streams[i].name),
             "video-%zu", i + 1);
  }
  return manifest;
}

static int inject_fec_packet(const qlinq_emcon_manifest_t *manifest,
                             const uint8_t *secret, uint64_t pn,
                             const qlinq_wire_fec_header_t *header,
                             size_t symbol_bytes) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in source = {.sin_family = AF_INET,
                               .sin_port = htons(manifest->source.port)};
  struct sockaddr_in destination = {
      .sin_family = AF_INET, .sin_port = htons(manifest->destination.port)};
  memcpy(&source.sin_addr, manifest->source.address, 4);
  memcpy(&destination.sin_addr, manifest->destination.address, 4);
  if (fd < 0 || bind(fd, (struct sockaddr *)&source, sizeof(source)) != 0) {
    if (fd >= 0)
      close(fd);
    return -1;
  }
  qlinq_emcon_sender_t *sender = NULL;
  uint8_t digest[QLINQ_EMCON_MANIFEST_DIGEST_SIZE];
  uint8_t payload[QLINQ_WIRE_FEC_HEADER_SIZE + 512] = {0}, packet[640];
  size_t payload_size = QLINQ_WIRE_FEC_HEADER_SIZE + symbol_bytes;
  size_t packet_size = 0;
  int ok =
      payload_size <= sizeof(payload) &&
      qlinq_emcon_manifest_digest(manifest, digest) == QLINQ_EMCON_OK &&
      qlinq_emcon_sender_create(&sender, manifest->flow_id, manifest->key_epoch,
                                digest, pn, manifest->symbol_size,
                                manifest->repair_symbols, 4096, secret,
                                32) == QLINQ_EMCON_OK &&
      qlinq_wire_encode_fec_header(payload, payload_size, header) ==
          QLINQ_WIRE_OK &&
      qlinq_emcon_flexicast_seal(sender, ptls_iovec_init(payload, payload_size),
                                 packet, sizeof(packet), &packet_size,
                                 NULL) == QLINQ_EMCON_OK &&
      sendto(fd, packet, packet_size, 0, (struct sockaddr *)&destination,
             sizeof(destination)) == (ssize_t)packet_size;
  qlinq_emcon_sender_free(sender);
  close(fd);
  return ok ? 0 : -1;
}

static int inject_unknown_alias(const qlinq_emcon_manifest_t *manifest,
                                const uint8_t *secret) {
  qlinq_wire_fec_header_t header = {
      .alias = 99,
      .group_id = 1,
      .object_id = 1,
      .total_symbols = 2,
      .data_symbols = 1,
      .symbol_size = 1,
      .original_size = 1,
  };
  return inject_fec_packet(manifest, secret, 50, &header, 1);
}

static int check_session_object(qlinq_emcon_session_t *receiver,
                                uint64_t object_id, const void *data,
                                size_t size) {
  qlinq_emcon_event_t event;
  bool completed = false;
  for (size_t packet = 0; packet < 6; packet++) {
    int ret = qlinq_emcon_session_receive(receiver, &event, true);
    CHECK(ret == QLINQ_EMCON_OK || ret == QLINQ_EMCON_INCOMPLETE ||
              ret == QLINQ_EMCON_DUPLICATE,
          "authenticate a source or repair packet");
    if (ret != QLINQ_EMCON_OK)
      continue;
    CHECK(event.type == QLINQ_EMCON_EVENT_RECORD &&
              event.value.record.object_id == object_id &&
              event.value.record.size == size &&
              memcmp(event.value.record.data, data, size) == 0,
          "receive exact object bytes");
    completed = true;
    qlinq_emcon_event_release(&event);
  }
  CHECK(completed, "assemble the object");
  return 0;
}

typedef struct {
  const qlinq_emcon_session_t *session;
  uint64_t stop_after_packets;
} cancel_after_packets_t;

static bool cancel_after_packets(void *user_data) {
  const cancel_after_packets_t *ctx = user_data;
  return qlinq_emcon_session_stats(ctx->session).send.packets_sent >=
         ctx->stop_after_packets;
}

static int check_io_limits(const uint8_t secret[32], const char *state_dir) {
  uint64_t now = now_ms();
  qlinq_emcon_manifest_t manifest = fixture(secret, now);
  manifest.key_epoch += 100;
  manifest.expires_at_ms = now + 200;
  qlinq_emcon_session_t *receiver = NULL, *sender = NULL;
  qlinq_emcon_event_t event;
  CHECK(open_claimed_receiver(&receiver, &manifest, secret, 32, now,
                              state_dir) == QLINQ_EMCON_OK,
        "open receiver with finite wait");
  alarm(5);
  CHECK(qlinq_emcon_session_receive(receiver, &event, false) ==
                QLINQ_EMCON_ERR_EXPIRED &&
            strcmp(qlinq_emcon_strerror(QLINQ_EMCON_ERR_EXPIRED),
                   "manifest validity window expired") == 0 &&
            now_ms() >= manifest.expires_at_ms,
        "idle blocking receive returns at manifest expiry");
  alarm(0);
  qlinq_emcon_session_free(receiver);

  now = now_ms();
  manifest.key_epoch++;
  manifest.expires_at_ms = now + 400;
  manifest.burst_bytes = 600;
  manifest.rate_bytes_per_second = 100;
  CHECK(qlinq_emcon_session_create_sender(&sender, &manifest, secret, 32, now,
                                          state_dir, 64,
                                          NULL) == QLINQ_EMCON_OK,
        "open paced sender");
  uint8_t record[1024] = {0};
  CHECK(qlinq_emcon_session_send_object(sender, 20, 0, 0, false, 0, record,
                                        sizeof(record)) ==
                QLINQ_EMCON_ERR_EXPIRED &&
            qlinq_emcon_session_stats(sender).send.packets_sent == 1,
        "only the first symbol fits before expiry");
  qlinq_emcon_session_free(sender);

  now = now_ms();
  manifest.key_epoch++;
  manifest.expires_at_ms = now + 400;
  manifest.terminal_repeat_count = 32;
  CHECK(qlinq_emcon_session_create_sender(&sender, &manifest, secret, 32, now,
                                          state_dir, 64,
                                          NULL) == QLINQ_EMCON_OK,
        "open terminal metadata sender");
  CHECK(qlinq_emcon_session_send_end(sender, 20, 0, 0) ==
            QLINQ_EMCON_ERR_EXPIRED,
        "terminal repetition stops at expiry");
  qlinq_emcon_session_stats_t stats = qlinq_emcon_session_stats(sender);
  CHECK(stats.metadata_sent > 1 &&
            stats.metadata_sent < manifest.terminal_repeat_count,
        "transmit only the terminal repeats that fit");
  qlinq_emcon_session_free(sender);

  now = now_ms();
  manifest.key_epoch++;
  manifest.expires_at_ms = now + 60000;
  CHECK(qlinq_emcon_session_create_sender(&sender, &manifest, secret, 32, now,
                                          state_dir, 64,
                                          NULL) == QLINQ_EMCON_OK,
        "open cancellable object sender");
  cancel_after_packets_t cancel_ctx = {.session = sender,
                                       .stop_after_packets = 1};
  qlinq_emcon_session_set_cancel(sender, cancel_after_packets, &cancel_ctx);
  uint64_t start_cancel = now_ms();
  CHECK(qlinq_emcon_session_send_object(sender, 20, 0, 0, false, 0, record,
                                        sizeof(record)) ==
                QLINQ_EMCON_ERR_INTERRUPTED &&
            qlinq_emcon_session_stats(sender).send.packets_sent == 1 &&
            now_ms() - start_cancel < 1000,
        "cancel stops mid-object without waiting for remaining symbols");
  qlinq_emcon_session_free(sender);

  now = now_ms();
  manifest.key_epoch++;
  CHECK(qlinq_emcon_session_create_sender(&sender, &manifest, secret, 32, now,
                                          state_dir, 64,
                                          NULL) == QLINQ_EMCON_OK,
        "open cancellable END sender");
  cancel_ctx =
      (cancel_after_packets_t){.session = sender, .stop_after_packets = 3};
  qlinq_emcon_session_set_cancel(sender, cancel_after_packets, &cancel_ctx);
  start_cancel = now_ms();
  CHECK(qlinq_emcon_session_send_end(sender, 20, 0, 0) ==
                QLINQ_EMCON_ERR_INTERRUPTED &&
            qlinq_emcon_session_stats(sender).send.packets_sent == 3 &&
            now_ms() - start_cancel < 1000,
        "cancel stops END-repeat loop immediately");
  qlinq_emcon_session_free(sender);

  uint8_t packet[128] = {0};
  struct sockaddr_in local = {.sin_family = AF_INET,
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  struct sockaddr_in destination = local;
  destination.sin_port = htons(manifest.destination.port);
  qlinq_emcon_send_socket_t *socket_sender;
  CHECK(qlinq_emcon_send_socket_create(
            &socket_sender, (struct sockaddr *)&local, sizeof(local),
            (struct sockaddr *)&destination, sizeof(destination),
            sizeof(packet) * 10, sizeof(packet), UINT64_MAX) == QLINQ_EMCON_OK,
        "create one-packet burst sender");
  now = now_ms();
  CHECK(qlinq_emcon_send_socket_send(socket_sender, packet, sizeof(packet)) ==
                QLINQ_EMCON_OK &&
            qlinq_emcon_send_socket_send(socket_sender, packet,
                                         sizeof(packet)) == QLINQ_EMCON_OK &&
            now_ms() >= now + 99,
        "two full packets require at least one packet interval");
  qlinq_emcon_send_socket_free(socket_sender);
  return 0;
}

int main(void) {
  uint8_t secret[32];
  memset(secret, 0xb7, sizeof(secret));
  char activation_directory[] = "/tmp/qlinq-emcon-session-XXXXXX";
  CHECK(mkdtemp(activation_directory), "create session state directory");
  CHECK(check_io_limits(secret, activation_directory) == 0,
        "enforce signed I/O limits");

  uint64_t now = now_ms();
  qlinq_emcon_manifest_t manifest = fixture(secret, now);
  manifest.interface_index = UINT32_MAX;
  CHECK(manifest.source.port && manifest.destination.port,
        "allocate local ports");
  qlinq_emcon_session_t *receiver = NULL, *sender = NULL;
  CHECK(qlinq_emcon_session_prepare_receiver(
            &receiver, &manifest, secret, sizeof(secret), now,
            activation_directory, UINT32_MAX, true) == QLINQ_EMCON_ERR_IO &&
            receiver == NULL,
        "reject invalid explicit receiver interface on unicast");
  CHECK(open_claimed_receiver(&receiver, &manifest, secret, sizeof(secret), now,
                              activation_directory) == QLINQ_EMCON_OK,
        "create multi-alias receiver ignoring sender interface on unicast");
  qlinq_emcon_event_t unknown_event;
  qlinq_emcon_manifest_t other = manifest;
  other.flow_id++;
  other.key_epoch++;
  CHECK(inject_unknown_alias(&other, secret) == 0 &&
            qlinq_emcon_session_receive(receiver, &unknown_event, true) ==
                QLINQ_EMCON_DISCARDED &&
            qlinq_emcon_session_stats(receiver).authentication_failures == 0,
        "discard an unrelated flow before authenticating");
  other = manifest;
  other.key_epoch--;
  CHECK(inject_unknown_alias(&other, secret) == 0 &&
            qlinq_emcon_session_receive(receiver, &unknown_event, true) ==
                QLINQ_EMCON_DISCARDED &&
            qlinq_emcon_session_stats(receiver).authentication_failures == 1,
        "discard a packet from the previous epoch and count its failed "
        "authentication");
  other = manifest;
  other.symbol_size = 512;
  CHECK(inject_unknown_alias(&other, secret) == 0 &&
            qlinq_emcon_session_receive(receiver, &unknown_event, true) ==
                QLINQ_EMCON_DISCARDED &&
            qlinq_emcon_session_stats(receiver).authentication_failures == 2,
        "discard a packet sealed under a modified manifest in the same epoch");
  CHECK(inject_unknown_alias(&manifest, secret) == 0,
        "inject authenticated unknown alias");
  CHECK(qlinq_emcon_session_receive(receiver, &unknown_event, false) ==
                QLINQ_EMCON_ERR_UNKNOWN_ALIAS &&
            qlinq_emcon_session_stats(receiver).unknown_aliases == 1,
        "reject authenticated unknown alias");

  qlinq_wire_fec_header_t oversize_header = {
      .alias = 20,
      .group_id = 2,
      .object_id = 1,
      .symbol_index = 0,
      .data_symbols = 17,
      .total_symbols = 19,
      .symbol_size = 256,
      .original_size = 4097,
  };
  CHECK(inject_fec_packet(&manifest, secret, 51, &oversize_header, 256) == 0 &&
            qlinq_emcon_session_receive(receiver, &unknown_event, false) ==
                QLINQ_EMCON_ERR_INVALID,
        "reject authenticated symbol exceeding signed maximum_record_size");

  qlinq_wire_fec_header_t wrong_symbol_header = {
      .alias = 20,
      .group_id = 2,
      .object_id = 2,
      .symbol_index = 0,
      .data_symbols = 1,
      .total_symbols = 3,
      .symbol_size = 512,
      .original_size = 512,
  };
  CHECK(inject_fec_packet(&manifest, secret, 52, &wrong_symbol_header, 512) ==
                0 &&
            qlinq_emcon_session_receive(receiver, &unknown_event, false) ==
                QLINQ_EMCON_ERR_INVALID,
        "reject authenticated symbol with unauthorized symbol_size");

  qlinq_wire_fec_header_t wrong_repair_header = {
      .alias = 20,
      .group_id = 2,
      .object_id = 3,
      .symbol_index = 0,
      .data_symbols = 1,
      .total_symbols = 10,
      .symbol_size = 256,
      .original_size = 256,
  };
  CHECK(inject_fec_packet(&manifest, secret, 53, &wrong_repair_header, 256) ==
                0 &&
            qlinq_emcon_session_receive(receiver, &unknown_event, false) ==
                QLINQ_EMCON_ERR_INVALID,
        "reject authenticated symbol with unauthorized repair_symbols");

  qlinq_emcon_activation_t *skip = NULL;
  uint64_t skip_first, skip_limit;
  CHECK(qlinq_emcon_activation_open_managed(&skip, activation_directory,
                                            &manifest) == QLINQ_EMCON_OK &&
            qlinq_emcon_activation_reserve(skip, 64, 64, &skip_first,
                                           &skip_limit) == QLINQ_EMCON_OK,
        "advance sender reservation past injected test packets");
  qlinq_emcon_activation_close(skip);

  CHECK(qlinq_emcon_session_create_sender(
            &sender, &manifest, secret, sizeof(secret), now,
            activation_directory, 65536, NULL) == QLINQ_EMCON_OK,
        "create manifest sender");
  uint8_t wrong_secret[32] = {0};
  qlinq_emcon_session_t *invalid = NULL;
  CHECK(qlinq_emcon_session_create_sender(
            &invalid, &manifest, wrong_secret, sizeof(wrong_secret), now,
            activation_directory, 65536, NULL) == QLINQ_EMCON_ERR_INVALID,
        "reject wrong traffic key");
  uint8_t data[6][1024];
  for (size_t stream = 0; stream < 6; stream++) {
    for (size_t i = 0; i < sizeof(data[stream]); i++)
      data[stream][i] = (uint8_t)(stream * 19U + i * 7U);
    CHECK(qlinq_emcon_session_send_object(
              sender, (uint8_t)(20 + stream), 4, 100 + stream, stream == 0,
              (uint8_t)stream, data[stream],
              sizeof(data[stream])) == QLINQ_EMCON_OK,
          "send manifested stream object");
    CHECK(qlinq_emcon_session_send_end(sender, (uint8_t)(20 + stream), 4,
                                       100 + stream) == QLINQ_EMCON_OK,
          "repeat terminal metadata");
  }
  CHECK(qlinq_emcon_session_send_object(sender, 99, 4, 1, false, 0, data[0],
                                        sizeof(data[0])) ==
            QLINQ_EMCON_ERR_UNKNOWN_ALIAS,
        "reject unprovisioned alias");

  bool completed[6] = {0};
  size_t end_count = 0;
  for (size_t packet = 0; packet < 48; packet++) {
    qlinq_emcon_event_t event;
    int ret = qlinq_emcon_session_receive(receiver, &event, false);
    CHECK(ret == QLINQ_EMCON_OK || ret == QLINQ_EMCON_INCOMPLETE ||
              ret == QLINQ_EMCON_DUPLICATE,
          "receive session packet");
    if (ret != QLINQ_EMCON_OK)
      continue;
    if (event.type == QLINQ_EMCON_EVENT_RECORD) {
      size_t stream = event.value.record.alias - 20;
      CHECK(stream < 6 && event.value.record.group_id == 4 &&
                event.value.record.object_id == 100 + stream &&
                event.value.record.size == sizeof(data[stream]) &&
                memcmp(event.value.record.data, data[stream],
                       sizeof(data[stream])) == 0,
            "exact multi-stream record");
      completed[stream] = true;
    } else if (event.type == QLINQ_EMCON_EVENT_END) {
      end_count++;
    }
    qlinq_emcon_event_release(&event);
  }
  for (size_t i = 0; i < 6; i++)
    CHECK(completed[i], "all six aliases completed");
  CHECK(end_count == 12, "repeated terminal metadata");
  qlinq_emcon_session_stats_t sender_stats = qlinq_emcon_session_stats(sender);
  qlinq_emcon_session_stats_t receiver_stats =
      qlinq_emcon_session_stats(receiver);
  CHECK(sender_stats.send.packets_sent == 48 &&
            sender_stats.metadata_sent == 12 &&
            receiver_stats.packets_received == 55 &&
            receiver_stats.records_completed == 6 &&
            receiver_stats.metadata_received == 12 &&
            receiver_stats.authentication_failures == 2 &&
            receiver_stats.unknown_aliases == 1,
        "session counters");

  qlinq_emcon_session_free(sender);
  qlinq_emcon_session_free(receiver);

  manifest.key_epoch++;
  qlinq_emcon_session_t *persistent = NULL, *competing = NULL;
  qlinq_emcon_session_t *persistent_receiver = NULL, *reused_receiver = NULL;
  int port_holder = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in occupied_rx = {.sin_family = AF_INET,
                                    .sin_port =
                                        htons(manifest.destination.port),
                                    .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  CHECK(port_holder >= 0 && bind(port_holder, (struct sockaddr *)&occupied_rx,
                                 sizeof(occupied_rx)) == 0,
        "occupy receiver port");
  CHECK(open_claimed_receiver(&persistent_receiver, &manifest, secret,
                              sizeof(secret), now,
                              activation_directory) == QLINQ_EMCON_ERR_IO &&
            persistent_receiver == NULL,
        "receiver socket failure leaves epoch available");
  close(port_holder);
  CHECK(qlinq_emcon_session_prepare_receiver(
            &persistent_receiver, &manifest, secret, sizeof(secret), now,
            activation_directory, 0, true) == QLINQ_EMCON_OK,
        "retry one-shot receiver startup");
  CHECK(inject_unknown_alias(&manifest, secret) == 0,
        "queue packet before receiver claim");
  qlinq_emcon_event_t pending_event;
  CHECK(
      qlinq_emcon_session_receive(persistent_receiver, &pending_event, true) ==
              QLINQ_EMCON_ERR_ACTIVATION &&
          qlinq_emcon_session_stats(persistent_receiver).packets_received == 0,
      "prepared receiver cannot consume packets before the claim");
  CHECK(qlinq_emcon_session_claim_receiver(persistent_receiver) ==
            QLINQ_EMCON_OK,
        "claim prepared receiver epoch");
  CHECK(qlinq_emcon_session_receive(persistent_receiver, &pending_event,
                                    true) == QLINQ_EMCON_ERR_UNKNOWN_ALIAS,
        "receiver can consume queued packet after the claim");
  CHECK(open_claimed_receiver(&reused_receiver, &manifest, secret,
                              sizeof(secret), now,
                              activation_directory) == QLINQ_EMCON_ERR_REUSED,
        "reject receiver restart in the same key epoch");

  int sender_holder = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in occupied_tx = {.sin_family = AF_INET,
                                    .sin_port = htons(manifest.source.port),
                                    .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  CHECK(sender_holder >= 0 &&
            bind(sender_holder, (struct sockaddr *)&occupied_tx,
                 sizeof(occupied_tx)) == 0,
        "hold the sender port open");
  CHECK(qlinq_emcon_session_create_sender(
            &persistent, &manifest, secret, sizeof(secret), now,
            activation_directory, 65536, NULL) == QLINQ_EMCON_ERR_IO &&
            persistent == NULL,
        "sender bind failure leaves the packet range available");
  close(sender_holder);

  /* skip past injected PN 50 before starting persistent sender */
  CHECK(qlinq_emcon_activation_open_managed(&skip, activation_directory,
                                            &manifest) == QLINQ_EMCON_OK &&
            qlinq_emcon_activation_reserve(skip, 60, 60, &skip_first,
                                           &skip_limit) == QLINQ_EMCON_OK,
        "advance epoch activation past injected PN 50");
  qlinq_emcon_activation_close(skip);

  CHECK(qlinq_emcon_session_create_sender(
            &persistent, &manifest, secret, sizeof(secret), now,
            activation_directory, 4, NULL) == QLINQ_EMCON_OK,
        "create persistent sender");
  qlinq_emcon_session_stats_t persistent_stats =
      qlinq_emcon_session_stats(persistent);
  CHECK(persistent_stats.persistent_activation &&
            persistent_stats.next_packet_number == 60 &&
            persistent_stats.reserved_until == 64,
        "initial packet-number reservation");
  CHECK(qlinq_emcon_session_create_sender(
            &competing, &manifest, secret, sizeof(secret), now,
            activation_directory, 4, NULL) == QLINQ_EMCON_ERR_LOCKED,
        "persistent sender holds exclusive activation lock");
  CHECK(qlinq_emcon_session_send_object(persistent, 20, 8, 1, false, 0, data[0],
                                        sizeof(data[0])) == QLINQ_EMCON_OK,
        "extend reservation before multi-packet send");
  CHECK(check_session_object(persistent_receiver, 1, data[0],
                             sizeof(data[0])) == 0,
        "running receiver recovers the object");
  persistent_stats = qlinq_emcon_session_stats(persistent);
  CHECK(persistent_stats.next_packet_number == 66 &&
            persistent_stats.reserved_until == 68,
        "use only durably reserved packet numbers");
  qlinq_emcon_session_free(persistent);
  persistent = NULL;
  CHECK(qlinq_emcon_session_create_sender(
            &persistent, &manifest, secret, sizeof(secret), now,
            activation_directory, 65536, NULL) == QLINQ_EMCON_OK,
        "restart persistent sender");
  persistent_stats = qlinq_emcon_session_stats(persistent);
  CHECK(persistent_stats.next_packet_number == 68 &&
            persistent_stats.reserved_until == 68 + 65536,
        "restart skips unused packet numbers");
  qlinq_emcon_session_free(persistent);
  CHECK(qlinq_emcon_session_create_sender(
            &persistent, &manifest, secret, sizeof(secret), now,
            activation_directory, 65536, NULL) == QLINQ_EMCON_OK &&
            qlinq_emcon_session_stats(persistent).next_packet_number ==
                68 + 65536 &&
            qlinq_emcon_session_send_object(persistent, 20, 8, 2, false, 0,
                                            data[0],
                                            sizeof(data[0])) == QLINQ_EMCON_OK,
        "send across a skipped default reservation");
  CHECK(check_session_object(persistent_receiver, 2, data[0],
                             sizeof(data[0])) == 0,
        "running receiver recovers restarted sender object");
  qlinq_emcon_session_free(persistent_receiver);
  qlinq_emcon_session_free(persistent);

  char late_directory[] = "/tmp/qlinq-emcon-late-XXXXXX";
  CHECK(mkdtemp(late_directory), "create late receiver state directory");
  qlinq_emcon_session_t *late_receiver = NULL;
  CHECK(open_claimed_receiver(&late_receiver, &manifest, secret, sizeof(secret),
                              now, late_directory) == QLINQ_EMCON_OK,
        "open a fresh listener");
  CHECK(qlinq_emcon_session_create_sender(
            &persistent, &manifest, secret, sizeof(secret), now,
            activation_directory, 4, NULL) == QLINQ_EMCON_OK &&
            qlinq_emcon_session_stats(persistent).next_packet_number ==
                68 + 2 * 65536 &&
            qlinq_emcon_session_send_object(persistent, 20, 8, 3, false, 0,
                                            data[0],
                                            sizeof(data[0])) == QLINQ_EMCON_OK,
        "send to a late listener after restart");
  CHECK(check_session_object(late_receiver, 3, data[0], sizeof(data[0])) == 0,
        "late listener reconstructs full packet numbers");
  qlinq_emcon_session_free(late_receiver);
  qlinq_emcon_session_free(persistent);
  CHECK(remove_state_directory(late_directory) == 0,
        "remove late receiver state directory");

  manifest.key_epoch++;
  qlinq_emcon_activation_t *budget = NULL;
  uint64_t budget_first, budget_reserved;
  const uint64_t key_limit = QLINQ_EMCON_MAX_PACKETS_PER_KEY;
  CHECK(qlinq_emcon_activation_open_managed(&budget, activation_directory,
                                            &manifest) == QLINQ_EMCON_OK &&
            qlinq_emcon_activation_reserve(budget, key_limit - 6, key_limit - 6,
                                           &budget_first, &budget_reserved) ==
                QLINQ_EMCON_OK &&
            budget_reserved == key_limit - 6,
        "leave six packet numbers in a fresh epoch");
  qlinq_emcon_activation_close(budget);
  CHECK(open_claimed_receiver(&persistent_receiver, &manifest, secret,
                              sizeof(secret), now,
                              activation_directory) == QLINQ_EMCON_OK,
        "open a receiver near the key packet limit");
  CHECK(qlinq_emcon_session_create_sender(
            &persistent, &manifest, secret, sizeof(secret), now,
            activation_directory, 4, NULL) == QLINQ_EMCON_OK &&
            qlinq_emcon_session_stats(persistent).reserved_until ==
                key_limit - 2,
        "start sender near key packet limit");
  CHECK(qlinq_emcon_session_send_object(persistent, 20, 8, 3, false, 0, data[0],
                                        sizeof(data[0])) == QLINQ_EMCON_OK &&
            qlinq_emcon_session_stats(persistent).next_packet_number ==
                key_limit &&
            qlinq_emcon_session_stats(persistent).reserved_until == key_limit,
        "extend with final partial block and use last packet number");
  CHECK(check_session_object(persistent_receiver, 3, data[0],
                             sizeof(data[0])) == 0,
        "receiver recovers FEC at the key packet limit");
  qlinq_emcon_session_free(persistent_receiver);
  CHECK(qlinq_emcon_session_send_object(persistent, 20, 8, 4, false, 0, data[0],
                                        sizeof(data[0])) ==
            QLINQ_EMCON_ERR_EXHAUSTED,
        "refuse encryption beyond key packet limit");
  qlinq_emcon_session_free(persistent);
  CHECK(qlinq_emcon_session_create_sender(
            &persistent, &manifest, secret, sizeof(secret), now,
            activation_directory, 65536, NULL) == QLINQ_EMCON_ERR_EXHAUSTED &&
            persistent == NULL,
        "report exhaustion after restarting the sender");

  /* verify receive filter and bound sender group protection */
  manifest.key_epoch++;
  qlinq_emcon_session_t *filtered_rx = NULL, *bound_tx = NULL;
  CHECK(qlinq_emcon_session_prepare_receiver(
            &filtered_rx, &manifest, secret, sizeof(secret), now,
            activation_directory, 0, true) == QLINQ_EMCON_OK &&
            qlinq_emcon_session_set_receive_filter(filtered_rx, 99, 7) ==
                QLINQ_EMCON_ERR_UNKNOWN_ALIAS &&
            qlinq_emcon_session_set_receive_filter(filtered_rx, 20, 7) ==
                QLINQ_EMCON_OK &&
            qlinq_emcon_session_claim_receiver(filtered_rx) == QLINQ_EMCON_OK,
        "configure receive filter on provisioned alias and group");
  qlinq_emcon_transfer_t tx_binding = {
      .alias = 20,
      .group_id = 7,
      .block_size = 1024,
      .input_size = sizeof(data[0]),
      .resumable = true,
  };
  memset(tx_binding.input_digest, 0x3c, sizeof(tx_binding.input_digest));
  CHECK(qlinq_emcon_session_create_sender(
            &bound_tx, &manifest, secret, sizeof(secret), now,
            activation_directory, 16, &tx_binding) == QLINQ_EMCON_OK,
        "create bound persistent sender");
  CHECK(qlinq_emcon_session_send_object(bound_tx, 21, 7, 0, false, 0, data[1],
                                        sizeof(data[1])) == QLINQ_EMCON_OK &&
            qlinq_emcon_session_send_object(bound_tx, 20, 99, 0, false, 0,
                                            data[2],
                                            sizeof(data[2])) == QLINQ_EMCON_OK,
        "emit unselected alias and unselected group packets");
  for (size_t i = 0; i < 12; i++) {
    qlinq_emcon_event_t filtered_ev;
    CHECK(qlinq_emcon_session_receive(filtered_rx, &filtered_ev, false) ==
              QLINQ_EMCON_DISCARDED,
          "discard unselected alias and group before FEC assembly");
  }
  CHECK(qlinq_emcon_session_stats(filtered_rx).records_completed == 0,
        "filtered traffic completes no records");
  qlinq_emcon_session_free(bound_tx);

  qlinq_emcon_transfer_t incompatible = tx_binding;
  incompatible.block_size = 512;
  CHECK(qlinq_emcon_session_create_sender(
            &bound_tx, &manifest, secret, sizeof(secret), now,
            activation_directory, 65536,
            &incompatible) == QLINQ_EMCON_ERR_TRANSFER_MISMATCH &&
            bound_tx == NULL,
        "reject incompatible group restart before reserving packet numbers");
  CHECK(qlinq_emcon_session_create_sender(
            &bound_tx, &manifest, secret, sizeof(secret), now,
            activation_directory, 16, &tx_binding) == QLINQ_EMCON_OK &&
            qlinq_emcon_session_stats(bound_tx).next_packet_number == 16 &&
            qlinq_emcon_session_send_object(bound_tx, 20, 7, 0, false, 0,
                                            data[0], sizeof(data[0])) ==
                QLINQ_EMCON_OK &&
            check_session_object(filtered_rx, 0, data[0], sizeof(data[0])) == 0,
        "compatible group restart preserves unreserved packet numbers");
  qlinq_emcon_session_free(bound_tx);
  qlinq_emcon_session_free(filtered_rx);
  CHECK(remove_state_directory(activation_directory) == 0,
        "remove session state directory");
  puts("===EMCON SESSION OK===");
  return 0;
}
