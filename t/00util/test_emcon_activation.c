#include "emcon_activation.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "EMCON activation test failed: %s\n", message);          \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static qlinq_emcon_manifest_t fixture(const uint8_t *secret) {
  qlinq_emcon_manifest_t manifest = {
      .flow_id = 1200,
      .key_epoch = 4,
      .cipher_suite = QLINQ_EMCON_CIPHER_AES_128_GCM_SHA256,
      .initial_packet_number = 100,
      .valid_from_ms = 1000,
      .expires_at_ms = 9000,
      .source = {.family = 4, .port = 15000},
      .destination = {.family = 4, .port = 15001},
      .replay_window_packets = QLINQ_EMCON_REPLAY_WINDOW_PACKETS,
      .rate_bytes_per_second = 1000000,
      .burst_bytes = 2048,
      .metadata_repeat_interval_ms = 1000,
      .terminal_repeat_count = 2,
      .symbol_size = 256,
      .repair_symbols = 4,
      .stream_count = 1,
  };
  memset(manifest.session_id, 0x21, sizeof(manifest.session_id));
  memset(manifest.sender_id, 0x32, sizeof(manifest.sender_id));
  inet_pton(AF_INET, "192.0.2.10", manifest.source.address);
  inet_pton(AF_INET, "192.0.2.11", manifest.destination.address);
  qlinq_emcon_traffic_key_id(secret, 32, manifest.traffic_key_id);
  manifest.streams[0] = (qlinq_emcon_manifest_stream_t){
      .alias = 8,
      .delivery = QLINQ_EMCON_DELIVERY_RATELESS,
      .maximum_record_size = 4096,
  };
  memcpy(manifest.streams[0].name, "activation-test",
         sizeof("activation-test"));
  return manifest;
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

int main(void) {
  uint8_t secret[32];
  memset(secret, 0x5a, sizeof(secret));
  qlinq_emcon_manifest_t manifest = fixture(secret);
  char directory_template[] = "/tmp/qlinq-emcon-activation-XXXXXX";
  char *directory = mkdtemp(directory_template);
  CHECK(directory, "create state directory");
  char state_path[256], link_path[256], directory_link[256];
  char mismatch_path[256], corrupt_path[256];
  snprintf(state_path, sizeof(state_path), "%s/sender.state", directory);
  snprintf(link_path, sizeof(link_path), "%s/sender.link", directory);
  snprintf(directory_link, sizeof(directory_link), "%s-link", directory);
  snprintf(mismatch_path, sizeof(mismatch_path), "%s/mismatch.state",
           directory);
  snprintf(corrupt_path, sizeof(corrupt_path), "%s/corrupt.state", directory);

  qlinq_emcon_activation_t *first = NULL, *concurrent = NULL;
  CHECK(qlinq_emcon_activation_open(&first, state_path, &manifest) ==
            QLINQ_EMCON_ACTIVATION_OK,
        "open new activation");
  uint64_t start, limit;
  CHECK(qlinq_emcon_activation_reserve(first, 8, 8, &start, &limit) ==
                QLINQ_EMCON_ACTIVATION_OK &&
            start == 100 && limit == 108,
        "reserve initial durable range");
  CHECK(qlinq_emcon_activation_open(&concurrent, state_path, &manifest) ==
            QLINQ_EMCON_ACTIVATION_LOCKED,
        "reject concurrent activation");
  qlinq_emcon_activation_close(first);

  qlinq_emcon_activation_t *restarted = NULL;
  CHECK(qlinq_emcon_activation_open(&restarted, state_path, &manifest) ==
            QLINQ_EMCON_ACTIVATION_OK,
        "reopen activation after restart");
  CHECK(qlinq_emcon_activation_reserve(restarted, 8, 8, &start, &limit) ==
                QLINQ_EMCON_ACTIVATION_OK &&
            start == 108 && limit == 116,
        "restart skips previously reserved range");
  qlinq_emcon_activation_close(restarted);

  pid_t child = fork();
  CHECK(child >= 0, "fork crash simulation");
  if (child == 0) {
    qlinq_emcon_activation_t *crashing = NULL;
    uint64_t child_start, child_limit;
    int ok = qlinq_emcon_activation_open(&crashing, state_path, &manifest) ==
                 QLINQ_EMCON_ACTIVATION_OK &&
             qlinq_emcon_activation_reserve(crashing, 8, 8, &child_start,
                                            &child_limit) ==
                 QLINQ_EMCON_ACTIVATION_OK &&
             child_start == 116 && child_limit == 124;
    _exit(ok ? 0 : 1);
  }
  int child_status;
  CHECK(waitpid(child, &child_status, 0) == child && WIFEXITED(child_status) &&
            WEXITSTATUS(child_status) == 0,
        "child reserves range before abrupt exit");
  qlinq_emcon_activation_t *after_crash = NULL;
  CHECK(qlinq_emcon_activation_open(&after_crash, state_path, &manifest) ==
            QLINQ_EMCON_ACTIVATION_OK,
        "release activation lock on process exit");
  CHECK(qlinq_emcon_activation_reserve(after_crash, 8, 8, &start, &limit) ==
                QLINQ_EMCON_ACTIVATION_OK &&
            start == 124 && limit == 132,
        "crash restart skips child reservation");
  qlinq_emcon_activation_close(after_crash);

  qlinq_emcon_activation_t *managed = NULL;
  CHECK(qlinq_emcon_activation_open_managed(&managed, directory, &manifest) ==
            QLINQ_EMCON_ACTIVATION_OK,
        "open canonical sender activation");
  CHECK(qlinq_emcon_activation_reserve(managed, 4, 4, &start, &limit) ==
                QLINQ_EMCON_ACTIVATION_OK &&
            start == 100 && limit == 104,
        "reserve canonical sender range");
  qlinq_emcon_activation_close(managed);
  managed = NULL;
  qlinq_emcon_manifest_t same_domain = manifest;
  same_domain.destination.port++;
  CHECK(
      qlinq_emcon_activation_open_managed(&managed, directory, &same_domain) ==
          QLINQ_EMCON_ACTIVATION_IDENTITY_MISMATCH,
      "alternate manifest cannot bypass nonce-domain state");
  CHECK(qlinq_emcon_receiver_activation_claim(directory, &manifest) ==
                QLINQ_EMCON_ACTIVATION_OK &&
            qlinq_emcon_receiver_activation_claim(directory, &manifest) ==
                QLINQ_EMCON_ACTIVATION_REUSED &&
            qlinq_emcon_receiver_activation_claim(directory, &same_domain) ==
                QLINQ_EMCON_ACTIVATION_REUSED,
        "receiver key epoch is claimed exactly once");

  qlinq_emcon_manifest_t next_epoch = manifest;
  next_epoch.key_epoch++;
  CHECK(qlinq_emcon_activation_open_managed(&managed, directory, &next_epoch) ==
            QLINQ_EMCON_ACTIVATION_OK,
        "fresh epoch receives distinct sender state");
  qlinq_emcon_activation_close(managed);
  CHECK(qlinq_emcon_receiver_activation_claim(directory, &next_epoch) ==
            QLINQ_EMCON_ACTIVATION_OK,
        "fresh epoch receives distinct receiver claim");
  CHECK(chmod(directory, 0755) == 0 &&
            qlinq_emcon_activation_open_managed(&managed, directory,
                                                &next_epoch) ==
                QLINQ_EMCON_ACTIVATION_IO &&
            chmod(directory, 0700) == 0,
        "reject exposed state directory");
  CHECK(symlink(directory, directory_link) == 0 &&
            qlinq_emcon_activation_open_managed(&managed, directory_link,
                                                &next_epoch) ==
                QLINQ_EMCON_ACTIVATION_IO,
        "reject state-directory symlink");

  qlinq_emcon_activation_t *mismatch = NULL;
  qlinq_emcon_manifest_t changed = manifest;
  changed.destination.port++;
  CHECK(qlinq_emcon_activation_open(&mismatch, state_path, &changed) ==
            QLINQ_EMCON_ACTIVATION_IDENTITY_MISMATCH,
        "reject state reused by another manifest");
  CHECK(chmod(state_path, 0644) == 0 &&
            qlinq_emcon_activation_open(&mismatch, state_path, &manifest) ==
                QLINQ_EMCON_ACTIVATION_IO &&
            chmod(state_path, 0600) == 0,
        "reject exposed state file");
  CHECK(symlink(state_path, link_path) == 0 &&
            qlinq_emcon_activation_open(&mismatch, link_path, &manifest) ==
                QLINQ_EMCON_ACTIVATION_IO,
        "reject state-file symlink");

  qlinq_emcon_activation_t *corrupt = NULL;
  CHECK(qlinq_emcon_activation_open(&corrupt, corrupt_path, &manifest) ==
            QLINQ_EMCON_ACTIVATION_OK,
        "open corruption fixture");
  CHECK(qlinq_emcon_activation_reserve(corrupt, 4, 4, &start, &limit) ==
            QLINQ_EMCON_ACTIVATION_OK,
        "write corruption fixture");
  qlinq_emcon_activation_close(corrupt);
  int corrupt_fd = open(corrupt_path, O_WRONLY | O_CLOEXEC);
  uint8_t damaged = 0xff;
  CHECK(corrupt_fd >= 0 && pwrite(corrupt_fd, &damaged, 1, 20) == 1 &&
            fsync(corrupt_fd) == 0 && close(corrupt_fd) == 0,
        "damage activation checksum");
  CHECK(qlinq_emcon_activation_open(&corrupt, corrupt_path, &manifest) ==
            QLINQ_EMCON_ACTIVATION_CORRUPT,
        "corrupt state fails closed");

  qlinq_emcon_activation_t *budget = NULL;
  CHECK(qlinq_emcon_activation_open(&budget, mismatch_path, &manifest) ==
            QLINQ_EMCON_ACTIVATION_OK,
        "open key budget fixture");
  uint64_t key_limit =
      manifest.initial_packet_number + QLINQ_EMCON_MAX_PACKETS_PER_KEY;
  CHECK(qlinq_emcon_activation_reserve(
            budget, 1, QLINQ_EMCON_MAX_PACKETS_PER_KEY - 3, &start, &limit) ==
                QLINQ_EMCON_ACTIVATION_OK &&
            limit == key_limit - 3,
        "charge all reserved numbers to the key budget");
  qlinq_emcon_activation_close(budget);
  CHECK(qlinq_emcon_activation_open(&budget, mismatch_path, &manifest) ==
            QLINQ_EMCON_ACTIVATION_OK,
        "reopen key budget fixture");
  CHECK(qlinq_emcon_activation_reserve(budget, 4, 65536, &start, &limit) ==
                QLINQ_EMCON_ACTIVATION_EXHAUSTED &&
            qlinq_emcon_activation_reserve(budget, 1, 65536, &start, &limit) ==
                QLINQ_EMCON_ACTIVATION_OK &&
            start == key_limit - 3 && limit == key_limit,
        "reserve a final partial block after restart");
  qlinq_emcon_activation_close(budget);
  CHECK(qlinq_emcon_activation_open(&budget, mismatch_path, &manifest) ==
                QLINQ_EMCON_ACTIVATION_OK &&
            qlinq_emcon_activation_reserve(budget, 1, 1, &start, &limit) ==
                QLINQ_EMCON_ACTIVATION_EXHAUSTED,
        "restarting an exhausted key fails closed");
  qlinq_emcon_activation_close(budget);

  const uint64_t wire_limit = UINT64_C(1) << 32;
  char legacy_path[256];
  snprintf(legacy_path, sizeof(legacy_path), "%s/legacy.state", directory);
  qlinq_emcon_manifest_t near_ceiling = manifest;
  near_ceiling.initial_packet_number = UINT32_MAX - 2;
  CHECK(qlinq_emcon_activation_open(&budget, legacy_path, &near_ceiling) ==
                QLINQ_EMCON_ACTIVATION_OK &&
            qlinq_emcon_activation_reserve(budget, 1, 65536, &start, &limit) ==
                QLINQ_EMCON_ACTIVATION_OK &&
            start == near_ceiling.initial_packet_number && limit == wire_limit,
        "clip durable reservations to the 32-bit ceiling");
  qlinq_emcon_activation_close(budget);

  /* Simulate a valid slot written before the 32-bit ceiling was enforced. */
  enum { SLOT_SIZE = 160, NEXT_PACKET_OFFSET = 104, CHECKSUM_OFFSET = 128 };
  uint8_t slot[SLOT_SIZE];
  int legacy_fd = open(legacy_path, O_RDWR | O_CLOEXEC);
  CHECK(legacy_fd >= 0 && pread(legacy_fd, slot, sizeof(slot), 0) == SLOT_SIZE,
        "read sender activation slot");
  for (size_t i = 0; i < sizeof(uint64_t); i++)
    slot[NEXT_PACKET_OFFSET + i] =
        (uint8_t)((wire_limit + 1) >> (56U - 8U * i));
  SHA256(slot, CHECKSUM_OFFSET, slot + CHECKSUM_OFFSET);
  CHECK(pwrite(legacy_fd, slot, SLOT_SIZE, 0) == SLOT_SIZE &&
            fsync(legacy_fd) == 0 && close(legacy_fd) == 0,
        "persist a legacy reservation above the 32-bit ceiling");
  CHECK(qlinq_emcon_activation_open(&budget, legacy_path, &near_ceiling) ==
                QLINQ_EMCON_ACTIVATION_OK &&
            qlinq_emcon_activation_reserve(budget, 1, 1, &start, &limit) ==
                QLINQ_EMCON_ACTIVATION_EXHAUSTED,
        "treat a legacy reservation above the ceiling as exhausted");
  qlinq_emcon_activation_close(budget);

  unlink(directory_link);
  CHECK(remove_state_directory(directory) == 0,
        "remove activation state directory");
  puts("===EMCON ACTIVATION OK===");
  return 0;
}
