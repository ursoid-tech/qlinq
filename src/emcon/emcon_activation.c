#include "emcon_activation.h"

#include "fs_util.h"
#include "wire_endian.h"

#include <openssl/crypto.h>
#include <openssl/sha.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define RECORD_VERSION 1U
#define RECORD_BODY_OFFSET 40U
#define ACTIVATION_SLOT_SIZE QLINQ_EMCON_ACTIVATION_SLOT_SIZE
#define ACTIVATION_SLOT_COUNT 2U
#define ACTIVATION_FILE_SIZE (ACTIVATION_SLOT_SIZE * ACTIVATION_SLOT_COUNT)
#define TRANSFER_RECORD_SIZE 128U
#define FILENAME_CAP 82U

struct qlinq_emcon_activation_t {
  int fd;
  int directory_fd;
  qlinq_emcon_manifest_t manifest;
  uint8_t manifest_digest[32];
  uint64_t next_packet_number;
  uint64_t generation;
  bool needs_directory_sync;
};

static bool all_zero(const uint8_t *value, size_t size) {
  uint8_t combined = 0;
  for (size_t i = 0; i < size; i++)
    combined |= value[i];
  return combined == 0;
}

static int domain_filename(char out[FILENAME_CAP], const char *role,
                           const char *suffix, const char *label,
                           const qlinq_emcon_manifest_t *manifest,
                           const void *extra, size_t extra_len) {
  uint8_t input[96], digest[32];
  size_t label_len = strlen(label), off = 0;
  if (label_len + sizeof(manifest->traffic_key_id) + 4 + extra_len >
      sizeof(input))
    return -1;
  memcpy(input + off, label, label_len);
  off += label_len;
  memcpy(input + off, manifest->traffic_key_id,
         sizeof(manifest->traffic_key_id));
  off += sizeof(manifest->traffic_key_id);
  qlinq_write_u32(input + off, manifest->key_epoch);
  off += 4;
  if (extra_len) {
    memcpy(input + off, extra, extra_len);
    off += extra_len;
  }
  bool ok = SHA256(input, off, digest) != NULL;
  OPENSSL_cleanse(input, sizeof(input));
  if (!ok)
    return -1;
  char hex[65];
  qlinq_hex_encode(digest, sizeof(digest), hex);
  OPENSSL_cleanse(digest, sizeof(digest));
  int n = snprintf(out, FILENAME_CAP, "%s-%s.%s", role, hex, suffix);
  return n > 0 && (size_t)n < FILENAME_CAP ? 0 : -1;
}

static int activation_filename(char out[FILENAME_CAP], const char *role,
                               const char *suffix,
                               const qlinq_emcon_manifest_t *manifest) {
  return domain_filename(out, role, suffix, "qlinq emcon nonce domain v1",
                         manifest, NULL, 0);
}

static int transfer_filename(char out[FILENAME_CAP],
                             const qlinq_emcon_manifest_t *manifest,
                             uint8_t alias, uint64_t group_id) {
  uint8_t extra[9];
  extra[0] = alias;
  qlinq_write_u64(extra + 1, group_id);
  return domain_filename(out, "transfer", "state",
                         "qlinq emcon transfer domain v1", manifest, extra,
                         sizeof(extra));
}

static bool seal_record(uint8_t *rec, size_t rec_size, const char magic[4],
                        const uint8_t manifest_digest[32]) {
  memcpy(rec, magic, 4);
  qlinq_write_u16(rec + 4, RECORD_VERSION);
  qlinq_write_u16(rec + 6, (uint16_t)rec_size);
  memcpy(rec + 8, manifest_digest, 32);
  return SHA256(rec, rec_size - 32, rec + rec_size - 32) != NULL;
}

static int open_record(const uint8_t *rec, size_t rec_size, const char magic[4],
                       const uint8_t manifest_digest[32]) {
  uint8_t checksum[32];
  if (memcmp(rec, magic, 4) != 0 || qlinq_read_u16(rec + 4) != RECORD_VERSION ||
      qlinq_read_u16(rec + 6) != rec_size ||
      !SHA256(rec, rec_size - 32, checksum) ||
      CRYPTO_memcmp(checksum, rec + rec_size - 32, sizeof(checksum)) != 0 ||
      CRYPTO_memcmp(rec + 8, manifest_digest, 32) != 0)
    return QLINQ_EMCON_ERR_ACTIVATION;
  return QLINQ_EMCON_OK;
}

static int decode_slot(const uint8_t slot[ACTIVATION_SLOT_SIZE],
                       uint64_t *next_pn, uint64_t *generation,
                       const uint8_t manifest_digest[32]) {
  int ret = open_record(slot, ACTIVATION_SLOT_SIZE, "QEMA", manifest_digest);
  if (ret != QLINQ_EMCON_OK)
    return ret;
  *next_pn = qlinq_read_u64(slot + RECORD_BODY_OFFSET);
  *generation = qlinq_read_u64(slot + RECORD_BODY_OFFSET + 8);
  if (*next_pn == 0 || *next_pn > QLINQ_EMCON_MAX_PACKETS_PER_KEY ||
      *generation == 0)
    return QLINQ_EMCON_ERR_ACTIVATION;
  return QLINQ_EMCON_OK;
}

static bool encode_slot(uint8_t slot[ACTIVATION_SLOT_SIZE],
                        const qlinq_emcon_activation_t *act, uint64_t next_pn,
                        uint64_t generation) {
  memset(slot, 0, ACTIVATION_SLOT_SIZE);
  qlinq_write_u64(slot + RECORD_BODY_OFFSET, next_pn);
  qlinq_write_u64(slot + RECORD_BODY_OFFSET + 8, generation);
  return seal_record(slot, ACTIVATION_SLOT_SIZE, "QEMA", act->manifest_digest);
}

int qlinq_emcon_activation_open_managed(
    qlinq_emcon_activation_t **activation, const char *state_directory,
    const qlinq_emcon_manifest_t *manifest) {
  if (!activation || !manifest ||
      qlinq_emcon_manifest_validate(manifest, 0) != QLINQ_EMCON_OK)
    return QLINQ_EMCON_ERR_INVALID;
  *activation = NULL;
  int dir_fd = qlinq_open_restricted_dir(state_directory);
  if (dir_fd < 0)
    return QLINQ_EMCON_ERR_IO;
  char filename[FILENAME_CAP];
  int fd = -1;
  if (activation_filename(filename, "sender", "state", manifest) == 0)
    fd = openat(dir_fd, filename, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_CREAT,
                0600);
  off_t file_size = 0;
  if (fd < 0 || !qlinq_stat_restricted_regular(fd, true, true, &file_size)) {
    if (fd >= 0)
      close(fd);
    close(dir_fd);
    return QLINQ_EMCON_ERR_IO;
  }
  if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
    int ret = (errno == EWOULDBLOCK || errno == EAGAIN) ? QLINQ_EMCON_ERR_LOCKED
                                                        : QLINQ_EMCON_ERR_IO;
    close(fd);
    close(dir_fd);
    return ret;
  }
  if (file_size != 0 && file_size != ACTIVATION_SLOT_SIZE &&
      file_size != ACTIVATION_FILE_SIZE) {
    close(fd);
    close(dir_fd);
    return QLINQ_EMCON_ERR_ACTIVATION;
  }

  qlinq_emcon_activation_t *opened = calloc(1, sizeof(*opened));
  if (!opened) {
    close(fd);
    close(dir_fd);
    return QLINQ_EMCON_ERR_IO;
  }
  opened->fd = fd;
  opened->directory_fd = dir_fd;
  opened->manifest = *manifest;
  opened->needs_directory_sync = true;
  if (qlinq_emcon_manifest_digest(manifest, opened->manifest_digest) !=
      QLINQ_EMCON_OK) {
    qlinq_emcon_activation_close(opened);
    return QLINQ_EMCON_ERR_IO;
  }

  uint8_t state[ACTIVATION_FILE_SIZE];
  if (file_size > 0 &&
      qlinq_pread_exact(fd, state, (size_t)file_size, 0) != 0) {
    qlinq_emcon_activation_close(opened);
    return QLINQ_EMCON_ERR_IO;
  }
  size_t slot_count = (size_t)file_size / ACTIVATION_SLOT_SIZE;
  uint64_t slot_next[ACTIVATION_SLOT_COUNT] = {0};
  uint64_t slot_gen[ACTIVATION_SLOT_COUNT] = {0};
  for (size_t i = 0; i < slot_count; i++) {
    int ret = decode_slot(state + i * ACTIVATION_SLOT_SIZE, &slot_next[i],
                          &slot_gen[i], opened->manifest_digest);
    if (ret != QLINQ_EMCON_OK ||
        (slot_gen[i] - 1) % ACTIVATION_SLOT_COUNT != i) {
      qlinq_emcon_activation_close(opened);
      return QLINQ_EMCON_ERR_ACTIVATION;
    }
  }
  if (slot_count == ACTIVATION_SLOT_COUNT) {
    size_t newer = slot_gen[1] > slot_gen[0] ? 1 : 0;
    size_t older = 1 - newer;
    if (slot_gen[newer] - slot_gen[older] != 1 ||
        slot_next[newer] <= slot_next[older]) {
      qlinq_emcon_activation_close(opened);
      return QLINQ_EMCON_ERR_ACTIVATION;
    }
    opened->next_packet_number = slot_next[newer];
    opened->generation = slot_gen[newer];
  } else if (slot_count == 1) {
    if (slot_gen[0] != 1) {
      qlinq_emcon_activation_close(opened);
      return QLINQ_EMCON_ERR_ACTIVATION;
    }
    opened->next_packet_number = slot_next[0];
    opened->generation = slot_gen[0];
  }
  *activation = opened;
  return QLINQ_EMCON_OK;
}

int qlinq_emcon_receiver_activation_check_available(
    const char *state_directory, const qlinq_emcon_manifest_t *manifest) {
  char filename[FILENAME_CAP];
  if (!manifest ||
      activation_filename(filename, "receiver", "claim", manifest) != 0)
    return QLINQ_EMCON_ERR_INVALID;
  int dir_fd = qlinq_open_restricted_dir(state_directory);
  if (dir_fd < 0)
    return QLINQ_EMCON_ERR_IO;
  struct stat info;
  int ret = QLINQ_EMCON_ERR_REUSED;
  if (fstatat(dir_fd, filename, &info, AT_SYMLINK_NOFOLLOW) != 0)
    ret = errno == ENOENT ? QLINQ_EMCON_OK : QLINQ_EMCON_ERR_IO;
  close(dir_fd);
  return ret;
}

int qlinq_emcon_receiver_activation_claim(
    const char *state_directory, const qlinq_emcon_manifest_t *manifest) {
  if (!manifest || qlinq_emcon_manifest_validate(manifest, 0) != QLINQ_EMCON_OK)
    return QLINQ_EMCON_ERR_INVALID;
  int dir_fd = qlinq_open_restricted_dir(state_directory);
  if (dir_fd < 0)
    return QLINQ_EMCON_ERR_IO;
  char filename[FILENAME_CAP];
  if (activation_filename(filename, "receiver", "claim", manifest) != 0) {
    close(dir_fd);
    return QLINQ_EMCON_ERR_IO;
  }
  int fd = openat(dir_fd, filename,
                  O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    int ret = errno == EEXIST ? QLINQ_EMCON_ERR_REUSED : QLINQ_EMCON_ERR_IO;
    close(dir_fd);
    return ret;
  }
  int ret = qlinq_stat_restricted_regular(fd, true, true, NULL) &&
                    qlinq_sync_file_data(fd) == 0 && fsync(dir_fd) == 0
                ? QLINQ_EMCON_OK
                : QLINQ_EMCON_ERR_IO;
  if (ret != QLINQ_EMCON_OK)
    (void)unlinkat(dir_fd, filename, 0);
  close(fd);
  close(dir_fd);
  return ret;
}

static bool transfer_valid(const qlinq_emcon_transfer_t *t) {
  if (!t || t->block_size == 0)
    return false;
  return t->resumable ? t->input_size != 0
                      : (t->input_size == 0 &&
                         all_zero(t->input_digest, sizeof(t->input_digest)));
}

int qlinq_emcon_activation_check_transfer(
    const qlinq_emcon_activation_t *activation,
    const qlinq_emcon_transfer_t *transfer) {
  if (!activation || !transfer_valid(transfer))
    return QLINQ_EMCON_ERR_INVALID;
  char filename[FILENAME_CAP];
  if (transfer_filename(filename, &activation->manifest, transfer->alias,
                        transfer->group_id) != 0)
    return QLINQ_EMCON_ERR_IO;
  int fd = openat(activation->directory_fd, filename,
                  O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return errno == ENOENT ? QLINQ_EMCON_OK : QLINQ_EMCON_ERR_IO;
  off_t size = 0;
  uint8_t rec[TRANSFER_RECORD_SIZE];
  bool io_ok = qlinq_stat_restricted_regular(fd, true, true, &size);
  int read_ok = (io_ok && size == TRANSFER_RECORD_SIZE)
                    ? qlinq_pread_exact(fd, rec, sizeof(rec), 0)
                    : -1;
  close(fd);
  if (!io_ok)
    return QLINQ_EMCON_ERR_IO;
  if (size != TRANSFER_RECORD_SIZE)
    return QLINQ_EMCON_ERR_ACTIVATION;
  if (read_ok != 0)
    return QLINQ_EMCON_ERR_IO;
  if (open_record(rec, sizeof(rec), "QEMT", activation->manifest_digest) !=
          QLINQ_EMCON_OK ||
      rec[41] > 1U || rec[42] != 0 || rec[43] != 0)
    return QLINQ_EMCON_ERR_ACTIVATION;
  qlinq_emcon_transfer_t stored = {
      .alias = rec[40],
      .resumable = rec[41] != 0,
      .block_size = qlinq_read_u32(rec + 44),
      .group_id = qlinq_read_u64(rec + 48),
      .input_size = qlinq_read_u64(rec + 56),
  };
  memcpy(stored.input_digest, rec + 64, sizeof(stored.input_digest));
  if (!transfer_valid(&stored) || stored.alias != transfer->alias ||
      stored.group_id != transfer->group_id)
    return QLINQ_EMCON_ERR_ACTIVATION;
  if (!stored.resumable || !transfer->resumable ||
      stored.block_size != transfer->block_size ||
      stored.input_size != transfer->input_size ||
      CRYPTO_memcmp(stored.input_digest, transfer->input_digest,
                    sizeof(stored.input_digest)) != 0)
    return QLINQ_EMCON_ERR_TRANSFER_MISMATCH;
  return QLINQ_EMCON_OK;
}

int qlinq_emcon_activation_bind_transfer(
    qlinq_emcon_activation_t *activation,
    const qlinq_emcon_transfer_t *transfer) {
  if (!activation || !transfer_valid(transfer))
    return QLINQ_EMCON_ERR_INVALID;
  char filename[FILENAME_CAP];
  if (transfer_filename(filename, &activation->manifest, transfer->alias,
                        transfer->group_id) != 0)
    return QLINQ_EMCON_ERR_IO;
  int fd = openat(activation->directory_fd, filename,
                  O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL, 0600);
  if (fd < 0)
    return errno == EEXIST
               ? qlinq_emcon_activation_check_transfer(activation, transfer)
               : QLINQ_EMCON_ERR_IO;
  uint8_t rec[TRANSFER_RECORD_SIZE] = {0};
  rec[40] = transfer->alias;
  rec[41] = transfer->resumable ? 1U : 0U;
  qlinq_write_u32(rec + 44, transfer->block_size);
  qlinq_write_u64(rec + 48, transfer->group_id);
  qlinq_write_u64(rec + 56, transfer->input_size);
  memcpy(rec + 64, transfer->input_digest, sizeof(transfer->input_digest));
  int ret = qlinq_stat_restricted_regular(fd, true, true, NULL) &&
                    seal_record(rec, sizeof(rec), "QEMT",
                                activation->manifest_digest) &&
                    qlinq_pwrite_exact(fd, rec, sizeof(rec), 0) == 0 &&
                    qlinq_sync_file_data(fd) == 0 &&
                    fsync(activation->directory_fd) == 0
                ? QLINQ_EMCON_OK
                : QLINQ_EMCON_ERR_IO;
  if (ret != QLINQ_EMCON_OK)
    (void)unlinkat(activation->directory_fd, filename, 0);
  close(fd);
  return ret;
}

int qlinq_emcon_activation_reserve(qlinq_emcon_activation_t *activation,
                                   uint64_t minimum_packets,
                                   uint64_t preferred_packets,
                                   uint64_t *first_packet_number,
                                   uint64_t *reserved_until) {
  if (!activation || minimum_packets == 0 ||
      preferred_packets < minimum_packets || !first_packet_number ||
      !reserved_until)
    return QLINQ_EMCON_ERR_INVALID;
  const uint64_t limit = QLINQ_EMCON_MAX_PACKETS_PER_KEY;
  if (activation->generation == UINT64_MAX ||
      activation->next_packet_number >= limit ||
      minimum_packets > limit - activation->next_packet_number)
    return QLINQ_EMCON_ERR_EXHAUSTED;
  uint64_t remaining = limit - activation->next_packet_number;
  uint64_t count =
      preferred_packets < remaining ? preferred_packets : remaining;
  uint64_t next = activation->next_packet_number + count;
  uint64_t gen = activation->generation + 1;
  size_t slot_idx = (size_t)((gen - 1) % ACTIVATION_SLOT_COUNT);
  uint8_t slot[ACTIVATION_SLOT_SIZE];
  if (!encode_slot(slot, activation, next, gen) ||
      qlinq_pwrite_exact(activation->fd, slot, sizeof(slot),
                         (off_t)(slot_idx * ACTIVATION_SLOT_SIZE)) != 0 ||
      qlinq_sync_file_data(activation->fd) != 0 ||
      (activation->needs_directory_sync &&
       fsync(activation->directory_fd) != 0))
    return QLINQ_EMCON_ERR_IO;
  activation->needs_directory_sync = false;
  *first_packet_number = activation->next_packet_number;
  *reserved_until = next;
  activation->next_packet_number = next;
  activation->generation = gen;
  return QLINQ_EMCON_OK;
}

void qlinq_emcon_activation_close(qlinq_emcon_activation_t *activation) {
  if (!activation)
    return;
  if (activation->fd >= 0)
    close(activation->fd);
  if (activation->directory_fd >= 0)
    close(activation->directory_fd);
  OPENSSL_cleanse(activation, sizeof(*activation));
  free(activation);
}
