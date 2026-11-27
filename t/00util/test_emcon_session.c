#include "emcon_session.h"
#include "emcon_activation.h"
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

static qlinq_emcon_manifest_t fixture(const uint8_t *secret, uint64_t now) {
  qlinq_emcon_manifest_t manifest = {
      .flow_id = 900,
      .key_epoch = 11,
      .cipher_suite = QLINQ_EMCON_CIPHER_AES_128_GCM_SHA256,
      .initial_packet_number = 700,
      .valid_from_ms = now - 1000,
      .expires_at_ms = now + 60000,
      .source = {.family = 4},
      .destination = {.family = 4},
      .replay_window_packets = QLINQ_EMCON_REPLAY_WINDOW_PACKETS,
      .rate_bytes_per_second = 10000000,
      .burst_bytes = 4096,
      .metadata_repeat_interval_ms = 30000,
      .terminal_repeat_count = 2,
      .symbol_size = 256,
      .repair_symbols = 2,
      .stream_count = 6,
  };
  memset(manifest.session_id, 0x15, sizeof(manifest.session_id));
  memset(manifest.sender_id, 0x27, sizeof(manifest.sender_id));
  qlinq_emcon_traffic_key_id(secret, 32, manifest.traffic_key_id);
  inet_pton(AF_INET, "127.0.0.1", manifest.source.address);
  inet_pton(AF_INET, "127.0.0.1", manifest.destination.address);
  manifest.source.port = free_port();
  do {
    manifest.destination.port = free_port();
  } while (manifest.destination.port == manifest.source.port);
  for (size_t i = 0; i < manifest.stream_count; i++) {
    manifest.streams[i].alias = (uint8_t)(20 + i);
    manifest.streams[i].delivery = QLINQ_EMCON_DELIVERY_RATELESS;
    manifest.streams[i].content_type = 0;
    manifest.streams[i].maximum_record_size = 4096;
    snprintf(manifest.streams[i].name, sizeof(manifest.streams[i].name),
             "video-%zu", i + 1);
  }
  return manifest;
}

static int inject_unknown_alias(const qlinq_emcon_manifest_t *manifest,
                                const uint8_t *secret) {
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
  qlinq_wire_fec_header_t header = {
      .alias = 99,
      .group_id = 1,
      .object_id = 1,
      .total_symbols = 1,
      .data_symbols = 1,
      .symbol_size = 1,
      .original_size = 1,
  };
  uint8_t payload[QLINQ_WIRE_FEC_HEADER_SIZE], packet[128];
  size_t packet_size = 0;
  uint64_t packet_number;
  int ok =
      qlinq_emcon_sender_create(&sender, manifest->flow_id, manifest->key_epoch,
                                manifest->initial_packet_number,
                                manifest->initial_packet_number + 50, secret,
                                32) == QLINQ_EMCON_OK &&
      qlinq_wire_encode_fec_header(payload, sizeof(payload), &header) ==
          QLINQ_WIRE_OK &&
      qlinq_emcon_flexicast_seal(sender, QLINQ_EMCON_RECORD_DATA,
                                 ptls_iovec_init(payload, sizeof(payload)),
                                 packet, sizeof(packet), &packet_size,
                                 &packet_number) == QLINQ_EMCON_OK &&
      sendto(fd, packet, packet_size, 0, (struct sockaddr *)&destination,
             sizeof(destination)) == (ssize_t)packet_size;
  (void)packet_number;
  qlinq_emcon_sender_free(sender);
  close(fd);
  return ok ? 0 : -1;
}

static int check_session_object(qlinq_emcon_session_t *receiver,
                                uint64_t object_id, const void *data,
                                size_t size) {
  qlinq_emcon_event_t event;
  CHECK(qlinq_emcon_session_receive(receiver, &event, true) ==
                QLINQ_EMCON_SESSION_OK &&
            event.type == QLINQ_EMCON_EVENT_SESSION,
        "authenticate sender session metadata");
  qlinq_emcon_event_release(&event);
  bool completed = false;
  for (size_t packet = 0; packet < 6; packet++) {
    int ret = qlinq_emcon_session_receive(receiver, &event, true);
    CHECK(ret == QLINQ_EMCON_SESSION_OK ||
              ret == QLINQ_EMCON_SESSION_INCOMPLETE ||
              ret == QLINQ_EMCON_SESSION_DUPLICATE,
          "authenticate a source or repair packet");
    if (ret != QLINQ_EMCON_SESSION_OK)
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

static int check_io_limits(const uint8_t secret[32]) {
  uint64_t now = now_ms();
  qlinq_emcon_manifest_t manifest = fixture(secret, now);
  manifest.key_epoch += 100;
  manifest.expires_at_ms = now + 200;
  qlinq_emcon_session_t *receiver = NULL, *sender = NULL;
  qlinq_emcon_event_t event;
  CHECK(qlinq_emcon_session_create_receiver(&receiver, &manifest, secret, 32,
                                            now) == QLINQ_EMCON_SESSION_OK,
        "open receiver with finite wait");
  alarm(5);
  CHECK(qlinq_emcon_session_receive(receiver, &event, false) ==
                QLINQ_EMCON_SESSION_EXPIRED &&
            now_ms() >= manifest.expires_at_ms,
        "idle blocking receive returns at manifest expiry");
  alarm(0);
  qlinq_emcon_session_free(receiver);

  now = now_ms();
  manifest.key_epoch++;
  manifest.expires_at_ms = now + 400;
  manifest.burst_bytes = 600;
  manifest.rate_bytes_per_second = 100;
  CHECK(qlinq_emcon_session_create_sender(&sender, &manifest, secret, 32,
                                          now) == QLINQ_EMCON_SESSION_OK,
        "open paced sender");
  uint8_t record[1024] = {0};
  CHECK(qlinq_emcon_session_send_object(sender, 20, 0, 0, false, 0, record,
                                        sizeof(record)) ==
                QLINQ_EMCON_SESSION_EXPIRED &&
            qlinq_emcon_session_stats(sender).send.packets_sent == 2,
        "only metadata and the first symbol fit before expiry");
  qlinq_emcon_session_free(sender);

  now = now_ms();
  manifest.key_epoch++;
  manifest.expires_at_ms = now + 400;
  manifest.terminal_repeat_count = 32;
  CHECK(qlinq_emcon_session_create_sender(&sender, &manifest, secret, 32,
                                          now) == QLINQ_EMCON_SESSION_OK,
        "open terminal metadata sender");
  qlinq_emcon_end_metadata_t end = {.alias = 20};
  memset(end.transmission_nonce, 1, sizeof(end.transmission_nonce));
  CHECK(qlinq_emcon_session_send_end(sender, &end) ==
            QLINQ_EMCON_SESSION_EXPIRED,
        "terminal repetition stops at expiry");
  qlinq_emcon_session_stats_t stats = qlinq_emcon_session_stats(sender);
  CHECK(stats.metadata_sent > 1 &&
            stats.metadata_sent < manifest.terminal_repeat_count,
        "transmit only the terminal repeats that fit");
  qlinq_emcon_session_free(sender);

  uint8_t packet[128] = {0};
  struct sockaddr_in local = {.sin_family = AF_INET,
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  struct sockaddr_in destination = local;
  destination.sin_port = htons(manifest.destination.port);
  qlinq_emcon_send_socket_t *socket_sender;
  CHECK(qlinq_emcon_send_socket_create(
            &socket_sender, (struct sockaddr *)&local, sizeof(local),
            sizeof(packet) * 10, sizeof(packet), UINT64_MAX) == 0 &&
            qlinq_emcon_send_socket_set_destination(
                socket_sender, (struct sockaddr *)&destination,
                sizeof(destination)) == 0,
        "create one-packet burst sender");
  now = now_ms();
  CHECK(qlinq_emcon_send_socket_send(socket_sender, packet, sizeof(packet)) ==
                0 &&
            qlinq_emcon_send_socket_send(socket_sender, packet,
                                         sizeof(packet)) == 0 &&
            now_ms() >= now + 99,
        "two full packets require at least one packet interval");
  qlinq_emcon_send_socket_free(socket_sender);
  return 0;
}

int main(void) {
  uint8_t secret[32];
  memset(secret, 0xb7, sizeof(secret));
  CHECK(check_io_limits(secret) == 0, "enforce signed I/O limits");
  uint64_t now = now_ms();
  qlinq_emcon_manifest_t manifest = fixture(secret, now);
  CHECK(manifest.source.port && manifest.destination.port,
        "allocate local ports");
  qlinq_emcon_session_t *receiver = NULL, *sender = NULL;
  CHECK(qlinq_emcon_session_create_receiver(&receiver, &manifest, secret,
                                            sizeof(secret),
                                            now) == QLINQ_EMCON_SESSION_OK,
        "create multi-alias receiver");
  qlinq_emcon_event_t unknown_event;
  qlinq_emcon_manifest_t other = manifest;
  other.flow_id++;
  other.key_epoch++;
  CHECK(inject_unknown_alias(&other, secret) == 0 &&
            qlinq_emcon_session_receive(receiver, &unknown_event, true) ==
                QLINQ_EMCON_SESSION_DISCARDED &&
            qlinq_emcon_session_stats(receiver).authentication_failures == 0,
        "discard an unrelated flow before authenticating");
  other = manifest;
  other.key_epoch--;
  CHECK(inject_unknown_alias(&other, secret) == 0 &&
            qlinq_emcon_session_receive(receiver, &unknown_event, true) ==
                QLINQ_EMCON_SESSION_DISCARDED &&
            qlinq_emcon_session_stats(receiver).authentication_failures == 1,
        "discard a packet from the previous epoch and count its failed "
        "authentication");
  CHECK(inject_unknown_alias(&manifest, secret) == 0,
        "inject authenticated unknown alias");
  CHECK(qlinq_emcon_session_receive(receiver, &unknown_event, false) ==
                QLINQ_EMCON_SESSION_UNKNOWN_ALIAS &&
            qlinq_emcon_session_stats(receiver).unknown_aliases == 1,
        "reject authenticated unknown alias");
  CHECK(qlinq_emcon_session_create_sender(&sender, &manifest, secret,
                                          sizeof(secret),
                                          now) == QLINQ_EMCON_SESSION_OK,
        "create manifest sender");
  uint8_t wrong_secret[32] = {0};
  qlinq_emcon_session_t *invalid = NULL;
  CHECK(qlinq_emcon_session_create_sender(&invalid, &manifest, wrong_secret,
                                          sizeof(wrong_secret),
                                          now) == QLINQ_EMCON_SESSION_INVALID,
        "reject wrong traffic key");
  uint8_t data[6][1024];
  for (size_t stream = 0; stream < 6; stream++) {
    for (size_t i = 0; i < sizeof(data[stream]); i++)
      data[stream][i] = (uint8_t)(stream * 19U + i * 7U);
    CHECK(qlinq_emcon_session_send_object(
              sender, (uint8_t)(20 + stream), 4, 100 + stream, stream == 0,
              (uint8_t)stream, data[stream],
              sizeof(data[stream])) == QLINQ_EMCON_SESSION_OK,
          "send manifested stream object");
    qlinq_emcon_end_metadata_t end = {.alias = (uint8_t)(20 + stream),
                                      .group_id = 4,
                                      .final_object_id = 100 + stream};
    memset(end.transmission_nonce, (int)(0x40 + stream),
           sizeof(end.transmission_nonce));
    CHECK(qlinq_emcon_session_send_end(sender, &end) == QLINQ_EMCON_SESSION_OK,
          "repeat terminal metadata");
  }
  CHECK(qlinq_emcon_session_send_object(sender, 99, 4, 1, false, 0, data[0],
                                        sizeof(data[0])) ==
            QLINQ_EMCON_SESSION_UNKNOWN_ALIAS,
        "reject unprovisioned alias");

  bool completed[6] = {0};
  size_t end_count = 0, session_count = 0;
  for (size_t packet = 0; packet < 49; packet++) {
    qlinq_emcon_event_t event;
    int ret = qlinq_emcon_session_receive(receiver, &event, false);
    CHECK(ret == QLINQ_EMCON_SESSION_OK ||
              ret == QLINQ_EMCON_SESSION_INCOMPLETE ||
              ret == QLINQ_EMCON_SESSION_DUPLICATE,
          "receive session packet");
    if (ret != QLINQ_EMCON_SESSION_OK)
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
    } else if (event.type == QLINQ_EMCON_EVENT_SESSION) {
      session_count++;
    }
    qlinq_emcon_event_release(&event);
  }
  for (size_t i = 0; i < 6; i++)
    CHECK(completed[i], "all six aliases completed");
  CHECK(end_count == 12 && session_count == 1,
        "session and repeated terminal metadata");
  qlinq_emcon_session_stats_t sender_stats = qlinq_emcon_session_stats(sender);
  qlinq_emcon_session_stats_t receiver_stats =
      qlinq_emcon_session_stats(receiver);
  CHECK(sender_stats.send.packets_sent == 49 &&
            sender_stats.metadata_sent == 13 &&
            receiver_stats.packets_received == 52 &&
            receiver_stats.records_completed == 6 &&
            receiver_stats.metadata_received == 13 &&
            receiver_stats.authentication_failures == 1 &&
            receiver_stats.unknown_aliases == 1,
        "session counters");

  qlinq_emcon_session_free(sender);
  qlinq_emcon_session_free(receiver);

  manifest.key_epoch++;
  const uint64_t before_wrap = UINT32_MAX - 100;
  manifest.initial_packet_number = before_wrap;
  char activation_directory[] = "/tmp/qlinq-emcon-session-XXXXXX";
  CHECK(mkdtemp(activation_directory), "create session state directory");
  qlinq_emcon_session_t *persistent = NULL, *competing = NULL;
  qlinq_emcon_session_t *persistent_receiver = NULL, *reused_receiver = NULL;
  qlinq_emcon_session_t *port_holder = NULL;
  CHECK(qlinq_emcon_session_create_receiver(&port_holder, &manifest, secret,
                                            sizeof(secret),
                                            now) == QLINQ_EMCON_SESSION_OK,
        "occupy receiver port");
  CHECK(qlinq_emcon_session_create_receiver_claimed(
            &persistent_receiver, &manifest, secret, sizeof(secret), now,
            activation_directory) == QLINQ_EMCON_SESSION_IO &&
            persistent_receiver == NULL,
        "receiver socket failure leaves epoch available");
  qlinq_emcon_session_free(port_holder);
  CHECK(qlinq_emcon_session_prepare_receiver(
            &persistent_receiver, &manifest, secret, sizeof(secret), now,
            activation_directory, 0, true) == QLINQ_EMCON_SESSION_OK,
        "retry one-shot receiver startup");
  CHECK(inject_unknown_alias(&manifest, secret) == 0,
        "queue packet before receiver claim");
  qlinq_emcon_event_t pending_event;
  CHECK(
      qlinq_emcon_session_receive(persistent_receiver, &pending_event, true) ==
              QLINQ_EMCON_SESSION_ACTIVATION &&
          qlinq_emcon_session_stats(persistent_receiver).packets_received == 0,
      "prepared receiver cannot consume packets before the claim");
  CHECK(qlinq_emcon_session_claim_receiver(persistent_receiver) ==
            QLINQ_EMCON_SESSION_OK,
        "claim prepared receiver epoch");
  CHECK(qlinq_emcon_session_receive(persistent_receiver, &pending_event,
                                    true) == QLINQ_EMCON_SESSION_UNKNOWN_ALIAS,
        "receiver can consume queued packet after the claim");
  CHECK(qlinq_emcon_session_create_receiver_claimed(
            &reused_receiver, &manifest, secret, sizeof(secret), now,
            activation_directory) == QLINQ_EMCON_SESSION_ACTIVATION_REUSED,
        "reject receiver restart in the same key epoch");
  CHECK(qlinq_emcon_session_create_sender(&sender, &manifest, secret,
                                          sizeof(secret),
                                          now) == QLINQ_EMCON_SESSION_OK,
        "hold the sender port open");
  CHECK(qlinq_emcon_session_create_sender_persistent(
            &persistent, &manifest, secret, sizeof(secret), now,
            activation_directory, 65536) == QLINQ_EMCON_SESSION_IO &&
            persistent == NULL,
        "sender bind failure leaves the packet range available");
  qlinq_emcon_session_free(sender);
  CHECK(qlinq_emcon_session_create_sender_persistent(
            &persistent, &manifest, secret, sizeof(secret), now,
            activation_directory, 4) == QLINQ_EMCON_SESSION_OK,
        "create persistent sender");
  qlinq_emcon_session_stats_t persistent_stats =
      qlinq_emcon_session_stats(persistent);
  CHECK(persistent_stats.persistent_activation &&
            persistent_stats.next_packet_number == before_wrap &&
            persistent_stats.reserved_until == before_wrap + 4,
        "initial packet-number reservation");
  CHECK(qlinq_emcon_session_create_sender_persistent(
            &competing, &manifest, secret, sizeof(secret), now,
            activation_directory, 4) == QLINQ_EMCON_SESSION_ACTIVATION_LOCKED,
        "persistent sender holds exclusive activation lock");
  CHECK(qlinq_emcon_session_send_object(persistent, 20, 8, 1, false, 0, data[0],
                                        sizeof(data[0])) ==
            QLINQ_EMCON_SESSION_OK,
        "extend reservation before multi-packet send");
  CHECK(check_session_object(persistent_receiver, 1, data[0],
                             sizeof(data[0])) == 0,
        "running receiver recovers the object before wire rollover");
  persistent_stats = qlinq_emcon_session_stats(persistent);
  CHECK(persistent_stats.next_packet_number == before_wrap + 7 &&
            persistent_stats.reserved_until == before_wrap + 8,
        "use only durably reserved packet numbers");
  qlinq_emcon_session_free(persistent);
  persistent = NULL;
  CHECK(qlinq_emcon_session_create_sender_persistent(
            &persistent, &manifest, secret, sizeof(secret), now,
            activation_directory, 65536) == QLINQ_EMCON_SESSION_OK,
        "restart persistent sender");
  persistent_stats = qlinq_emcon_session_stats(persistent);
  const uint64_t after_wrap = before_wrap + 8 + 65536;
  CHECK(persistent_stats.next_packet_number == before_wrap + 8 &&
            persistent_stats.reserved_until == after_wrap,
        "restart skips unused packet numbers");
  qlinq_emcon_session_free(persistent);
  CHECK(qlinq_emcon_session_create_sender_persistent(
            &persistent, &manifest, secret, sizeof(secret), now,
            activation_directory, 65536) == QLINQ_EMCON_SESSION_OK &&
            qlinq_emcon_session_stats(persistent).next_packet_number ==
                after_wrap &&
            qlinq_emcon_session_send_object(persistent, 20, 8, 2, false, 0,
                                            data[0], sizeof(data[0])) ==
                QLINQ_EMCON_SESSION_OK,
        "send across a skipped default reservation");
  CHECK(check_session_object(persistent_receiver, 2, data[0],
                             sizeof(data[0])) == 0,
        "running receiver recovers the restarted sender's object after wire "
        "rollover");
  qlinq_emcon_session_free(persistent_receiver);
  qlinq_emcon_session_free(persistent);

  qlinq_emcon_session_t *late_receiver = NULL;
  CHECK(qlinq_emcon_session_create_receiver(&late_receiver, &manifest, secret,
                                            sizeof(secret),
                                            now) == QLINQ_EMCON_SESSION_OK,
        "open a fresh listener provisioned with the original packet number");
  CHECK(qlinq_emcon_session_create_sender_persistent(
            &persistent, &manifest, secret, sizeof(secret), now,
            activation_directory, 4) == QLINQ_EMCON_SESSION_OK &&
            qlinq_emcon_session_stats(persistent).next_packet_number ==
                after_wrap + 65536 &&
            qlinq_emcon_session_send_object(persistent, 20, 8, 3, false, 0,
                                            data[0], sizeof(data[0])) ==
                QLINQ_EMCON_SESSION_OK,
        "send to a late listener after restart");
  CHECK(
      check_session_object(late_receiver, 3, data[0], sizeof(data[0])) == 0,
      "late listener reconstructs the full packet numbers after wire rollover");
  qlinq_emcon_session_free(late_receiver);
  qlinq_emcon_session_free(persistent);

  manifest.key_epoch++;
  manifest.initial_packet_number = QLINQ_EMCON_MAX_PACKET_NUMBER - 10;
  qlinq_emcon_activation_t *budget = NULL;
  uint64_t budget_first, budget_reserved;
  const uint64_t key_limit = QLINQ_EMCON_MAX_PACKET_NUMBER + UINT64_C(1);
  CHECK(qlinq_emcon_activation_open_managed(&budget, activation_directory,
                                            &manifest) ==
                QLINQ_EMCON_ACTIVATION_OK &&
            qlinq_emcon_activation_reserve(budget, 4, 4, &budget_first,
                                           &budget_reserved) ==
                QLINQ_EMCON_ACTIVATION_OK &&
            budget_reserved == key_limit - 7,
        "leave seven packet numbers in a fresh epoch");
  qlinq_emcon_activation_close(budget);
  CHECK(qlinq_emcon_session_create_receiver(&persistent_receiver, &manifest,
                                            secret, sizeof(secret),
                                            now) == QLINQ_EMCON_SESSION_OK,
        "open a receiver near the 62-bit ceiling");
  CHECK(qlinq_emcon_session_create_sender_persistent(
            &persistent, &manifest, secret, sizeof(secret), now,
            activation_directory, 4) == QLINQ_EMCON_SESSION_OK &&
            qlinq_emcon_session_stats(persistent).reserved_until ==
                key_limit - 3,
        "start sender near the 62-bit ceiling");
  CHECK(qlinq_emcon_session_send_object(persistent, 20, 8, 3, false, 0, data[0],
                                        sizeof(data[0])) ==
                QLINQ_EMCON_SESSION_OK &&
            qlinq_emcon_session_stats(persistent).next_packet_number ==
                key_limit &&
            qlinq_emcon_session_stats(persistent).reserved_until == key_limit,
        "extend with the final partial block and use the last packet number");
  CHECK(check_session_object(persistent_receiver, 3, data[0],
                             sizeof(data[0])) == 0,
        "receiver recovers metadata and FEC at the 62-bit ceiling");
  qlinq_emcon_session_free(persistent_receiver);
  CHECK(qlinq_emcon_session_send_object(persistent, 20, 8, 4, false, 0, data[0],
                                        sizeof(data[0])) ==
            QLINQ_EMCON_SESSION_PACKET_NUMBER_EXHAUSTED,
        "refuse encryption beyond the 62-bit ceiling");
  qlinq_emcon_session_free(persistent);
  CHECK(qlinq_emcon_session_create_sender_persistent(
            &persistent, &manifest, secret, sizeof(secret), now,
            activation_directory,
            65536) == QLINQ_EMCON_SESSION_PACKET_NUMBER_EXHAUSTED &&
            persistent == NULL,
        "report exhaustion after restarting the sender");
  CHECK(remove_state_directory(activation_directory) == 0,
        "remove session state directory");
  puts("===EMCON SESSION OK===");
  return 0;
}
