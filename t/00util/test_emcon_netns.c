#include "emcon_session.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define SOURCE_PORT 12070U
#define RECEIVER_PORT 12071U

static uint64_t now_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_REALTIME, &now) != 0)
    return 0;
  return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static void fill_payload(uint8_t *payload, size_t size) {
  for (size_t i = 0; i < size; i++)
    payload[i] = (uint8_t)(i * 43U + 9U);
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

static int make_manifest(qlinq_emcon_manifest_t *manifest,
                         const uint8_t *secret, const char *source,
                         const char *destination, uint64_t now) {
  uint64_t validity_hour = now - now % (60U * 60U * 1000U);
  *manifest = (qlinq_emcon_manifest_t){
      .flow_id = 808,
      .key_epoch = 2,
      .cipher_suite = QLINQ_EMCON_CIPHER_AES_128_GCM_SHA256,
      .initial_packet_number = 900,
      .valid_from_ms = validity_hour,
      .expires_at_ms = validity_hour + 2U * 60U * 60U * 1000U,
      .source = {.family = 4, .port = SOURCE_PORT},
      .destination = {.family = 4, .port = RECEIVER_PORT},
      .replay_window_packets = 4096,
      .rate_bytes_per_second = 1000000,
      .burst_bytes = 1024,
      .metadata_repeat_interval_ms = 10000,
      .terminal_repeat_count = 2,
      .symbol_size = 256,
      .repair_symbols = 4,
      .stream_count = 1,
  };
  memset(manifest->session_id, 0x41, sizeof(manifest->session_id));
  memset(manifest->sender_id, 0x52, sizeof(manifest->sender_id));
  manifest->streams[0] = (qlinq_emcon_manifest_stream_t){
      .alias = 4,
      .delivery = QLINQ_EMCON_DELIVERY_RATELESS,
      .content_type = 0,
      .maximum_record_size = 4096,
  };
  memcpy(manifest->streams[0].name, "netns-video", sizeof("netns-video"));
  return inet_pton(AF_INET, source, manifest->source.address) == 1 &&
                 inet_pton(AF_INET, destination,
                           manifest->destination.address) == 1 &&
                 qlinq_emcon_traffic_key_id(secret, 32,
                                            manifest->traffic_key_id) ==
                     QLINQ_EMCON_MANIFEST_OK
             ? 0
             : -1;
}

static int run_source(const char *source, const char *destination) {
  uint8_t secret[32], payload[2048];
  memset(secret, 0x83, sizeof(secret));
  fill_payload(payload, sizeof(payload));
  uint64_t now = now_ms();
  qlinq_emcon_manifest_t manifest;
  qlinq_emcon_session_t *session = NULL;
  char activation_directory[] = "/tmp/qlinq-emcon-netns-source-XXXXXX";
  if (!mkdtemp(activation_directory))
    return 1;
  if (now == 0 || make_manifest(&manifest, secret, source, destination, now) ||
      qlinq_emcon_session_create_sender_persistent(
          &session, &manifest, secret, sizeof(secret), now,
          activation_directory, 8) != QLINQ_EMCON_SESSION_OK ||
      qlinq_emcon_session_send_object(session, 4, 6, 10, false, 1, payload,
                                      sizeof(payload)) !=
          QLINQ_EMCON_SESSION_OK) {
    remove_state_directory(activation_directory);
    return 1;
  }
  qlinq_emcon_end_metadata_t end = {
      .alias = 4, .group_id = 6, .final_object_id = 10};
  memset(end.transmission_nonce, 0x2a, sizeof(end.transmission_nonce));
  if (qlinq_emcon_session_send_end(session, &end) != QLINQ_EMCON_SESSION_OK) {
    qlinq_emcon_session_free(session);
    remove_state_directory(activation_directory);
    return 1;
  }
  qlinq_emcon_session_stats_t stats = qlinq_emcon_session_stats(session);
  qlinq_emcon_session_free(session);
  if (remove_state_directory(activation_directory) != 0)
    return 1;
  if (stats.send.packets_sent != 15 || stats.metadata_sent != 3 ||
      stats.send.hard_send_errors != 0 || !stats.persistent_activation ||
      stats.next_packet_number != 915 || stats.reserved_until != 916)
    return 1;
  puts("===EMCON NETNS SOURCE OK===");
  return 0;
}

static int run_receiver(const char *destination, const char *source) {
  uint8_t secret[32];
  memset(secret, 0x83, sizeof(secret));
  uint64_t now = now_ms();
  qlinq_emcon_manifest_t manifest;
  qlinq_emcon_session_t *session = NULL;
  char activation_directory[] = "/tmp/qlinq-emcon-netns-receiver-XXXXXX";
  if (!mkdtemp(activation_directory))
    return 1;
  if (now == 0 || make_manifest(&manifest, secret, source, destination, now) ||
      qlinq_emcon_session_create_receiver_claimed(
          &session, &manifest, secret, sizeof(secret), now,
          activation_directory) != QLINQ_EMCON_SESSION_OK) {
    fprintf(stderr, "receiver setup failed\n");
    remove_state_directory(activation_directory);
    return 1;
  }
  bool got_record = false;
  size_t end_count = 0, session_count = 0;
  for (size_t i = 0; i < 15; i++) {
    qlinq_emcon_event_t event;
    int ret = qlinq_emcon_session_receive(session, &event, false);
    if (ret == QLINQ_EMCON_SESSION_DUPLICATE ||
        ret == QLINQ_EMCON_SESSION_INCOMPLETE)
      continue;
    if (ret != QLINQ_EMCON_SESSION_OK) {
      fprintf(stderr, "receiver packet %zu failed: %d\n", i, ret);
      qlinq_emcon_session_free(session);
      remove_state_directory(activation_directory);
      return 1;
    }
    if (event.type == QLINQ_EMCON_EVENT_RECORD) {
      uint8_t expected[2048];
      fill_payload(expected, sizeof(expected));
      got_record =
          event.value.record.group_id == 6 &&
          event.value.record.object_id == 10 &&
          event.value.record.size == sizeof(expected) &&
          memcmp(event.value.record.data, expected, sizeof(expected)) == 0;
    } else if (event.type == QLINQ_EMCON_EVENT_END) {
      end_count++;
    } else if (event.type == QLINQ_EMCON_EVENT_SESSION) {
      session_count++;
    }
    qlinq_emcon_event_release(&event);
  }
  qlinq_emcon_session_stats_t stats = qlinq_emcon_session_stats(session);
  qlinq_emcon_session_free(session);
  if (remove_state_directory(activation_directory) != 0)
    return 1;
  if (!got_record || end_count != 2 || session_count != 1 ||
      stats.packets_received != 15 || stats.authentication_failures != 0) {
    fprintf(stderr,
            "receiver result record=%d end=%zu session=%zu packets=%llu "
            "auth=%llu\n",
            got_record, end_count, session_count,
            (unsigned long long)stats.packets_received,
            (unsigned long long)stats.authentication_failures);
    return 1;
  }
  puts("===EMCON NETNS RECEIVER OK===");
  return 0;
}

/* pre-provision multicast membership before the silent interval begins */
static int run_hold_group(const char *group, const char *ifname) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    return 1;
  struct ip_mreqn mreq = {0};
  if (inet_pton(AF_INET, group, &mreq.imr_multiaddr) != 1) {
    close(fd);
    return 1;
  }
  mreq.imr_ifindex = (int)if_nametoindex(ifname);
  if (mreq.imr_ifindex == 0 ||
      setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) != 0) {
    close(fd);
    return 1;
  }
  for (;;)
    pause();
}

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s --source|--receiver|--hold-group ARG1 ARG2\n",
            argv[0]);
    return 2;
  }
  if (strcmp(argv[1], "--source") == 0)
    return run_source(argv[2], argv[3]);
  if (strcmp(argv[1], "--receiver") == 0)
    return run_receiver(argv[2], argv[3]);
  if (strcmp(argv[1], "--hold-group") == 0)
    return run_hold_group(argv[2], argv[3]);
  return 2;
}
