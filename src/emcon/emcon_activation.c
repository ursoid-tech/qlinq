#include "emcon_activation.h"

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

#define ACTIVATION_MAGIC_0 'Q'
#define ACTIVATION_MAGIC_1 'E'
#define ACTIVATION_MAGIC_2 'M'
#define ACTIVATION_MAGIC_3 'A'
#define ACTIVATION_VERSION 1U
#define ACTIVATION_SLOT_SIZE 160U
#define ACTIVATION_SLOT_COUNT 2U
#define ACTIVATION_FILE_SIZE (ACTIVATION_SLOT_SIZE * ACTIVATION_SLOT_COUNT)
#define ACTIVATION_CHECKSUM_OFFSET 128U
#define ACTIVATION_FILENAME_SIZE 82U

#define TRANSFER_MAGIC_0 'Q'
#define TRANSFER_MAGIC_1 'E'
#define TRANSFER_MAGIC_2 'M'
#define TRANSFER_MAGIC_3 'T'
#define TRANSFER_VERSION 1U
#define TRANSFER_RECORD_SIZE 128U
#define TRANSFER_CHECKSUM_OFFSET 96U

static int sync_file_data(int fd) {
#if defined(__APPLE__)
  return fsync(fd);
#else
  return fdatasync(fd);
#endif
}

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

static int read_state(int fd, uint8_t state[ACTIVATION_FILE_SIZE],
                      size_t *state_size) {
  struct stat info;
  if (fstat(fd, &info) != 0)
    return QLINQ_EMCON_ACTIVATION_IO;
  /* opener may close before first reservation; covered slots must be valid */
  if (info.st_size != 0 && info.st_size != ACTIVATION_SLOT_SIZE &&
      info.st_size != ACTIVATION_FILE_SIZE)
    return QLINQ_EMCON_ACTIVATION_CORRUPT;
  size_t required = (size_t)info.st_size;
  size_t offset = 0;
  while (offset < required) {
    ssize_t got = pread(fd, state + offset, required - offset, (off_t)offset);
    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0)
      return QLINQ_EMCON_ACTIVATION_IO;
    offset += (size_t)got;
  }
  *state_size = required;
  return QLINQ_EMCON_ACTIVATION_OK;
}

static int decode_slot(const uint8_t slot[ACTIVATION_SLOT_SIZE],
                       uint64_t *next_packet_number, uint64_t *generation,
                       const qlinq_emcon_manifest_t *manifest,
                       const uint8_t manifest_digest[32]) {
  uint8_t checksum[32];
  if (slot[0] != ACTIVATION_MAGIC_0 || slot[1] != ACTIVATION_MAGIC_1 ||
      slot[2] != ACTIVATION_MAGIC_2 || slot[3] != ACTIVATION_MAGIC_3 ||
      qlinq_read_u16(slot + 4) != ACTIVATION_VERSION ||
      qlinq_read_u16(slot + 6) != ACTIVATION_SLOT_SIZE ||
      !all_zero(slot + 120, 8) ||
      !SHA256(slot, ACTIVATION_CHECKSUM_OFFSET, checksum) ||
      CRYPTO_memcmp(checksum, slot + ACTIVATION_CHECKSUM_OFFSET,
                    sizeof(checksum)) != 0)
    return QLINQ_EMCON_ACTIVATION_CORRUPT;
  if (CRYPTO_memcmp(slot + 8, manifest->session_id,
                    sizeof(manifest->session_id)) != 0 ||
      CRYPTO_memcmp(slot + 24, manifest->sender_id,
                    sizeof(manifest->sender_id)) != 0 ||
      CRYPTO_memcmp(slot + 40, manifest->traffic_key_id,
                    sizeof(manifest->traffic_key_id)) != 0 ||
      CRYPTO_memcmp(slot + 72, manifest_digest, 32) != 0)
    return QLINQ_EMCON_ACTIVATION_IDENTITY_MISMATCH;
  *next_packet_number = qlinq_read_u64(slot + 104);
  *generation = qlinq_read_u64(slot + 112);
  if (*next_packet_number <= manifest->initial_packet_number ||
      *next_packet_number >
          qlinq_emcon_packet_number_limit(manifest->initial_packet_number) ||
      *generation == 0)
    return QLINQ_EMCON_ACTIVATION_CORRUPT;
  return QLINQ_EMCON_ACTIVATION_OK;
}

static bool encode_slot(uint8_t slot[ACTIVATION_SLOT_SIZE],
                        const qlinq_emcon_activation_t *activation,
                        uint64_t next_packet_number, uint64_t generation) {
  memset(slot, 0, ACTIVATION_SLOT_SIZE);
  slot[0] = ACTIVATION_MAGIC_0;
  slot[1] = ACTIVATION_MAGIC_1;
  slot[2] = ACTIVATION_MAGIC_2;
  slot[3] = ACTIVATION_MAGIC_3;
  qlinq_write_u16(slot + 4, ACTIVATION_VERSION);
  qlinq_write_u16(slot + 6, ACTIVATION_SLOT_SIZE);
  memcpy(slot + 8, activation->manifest.session_id,
         sizeof(activation->manifest.session_id));
  memcpy(slot + 24, activation->manifest.sender_id,
         sizeof(activation->manifest.sender_id));
  memcpy(slot + 40, activation->manifest.traffic_key_id,
         sizeof(activation->manifest.traffic_key_id));
  memcpy(slot + 72, activation->manifest_digest,
         sizeof(activation->manifest_digest));
  qlinq_write_u64(slot + 104, next_packet_number);
  qlinq_write_u64(slot + 112, generation);
  return SHA256(slot, ACTIVATION_CHECKSUM_OFFSET,
                slot + ACTIVATION_CHECKSUM_OFFSET) != NULL;
}

static int write_exact_at(int fd, const uint8_t *data, size_t size,
                          off_t file_offset) {
  size_t written = 0;
  while (written < size) {
    ssize_t result = pwrite(fd, data + written, size - written,
                            file_offset + (off_t)written);
    if (result < 0 && errno == EINTR)
      continue;
    if (result <= 0)
      return -1;
    written += (size_t)result;
  }
  return 0;
}

static int open_state_directory(const char *path) {
  if (!path || !path[0])
    return -1;
  int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  struct stat info;
  if (fd < 0 || fstat(fd, &info) != 0 || !S_ISDIR(info.st_mode) ||
      info.st_uid != geteuid() || (info.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    if (fd >= 0)
      close(fd);
    return -1;
  }
  return fd;
}

static int activation_filename(char filename[ACTIVATION_FILENAME_SIZE],
                               const char *role, const char *suffix,
                               const qlinq_emcon_manifest_t *manifest) {
  static const uint8_t label[] = "qlinq emcon nonce domain v1";
  uint8_t input[sizeof(label) - 1 + QLINQ_EMCON_MANIFEST_KEY_ID_SIZE + 6];
  size_t offset = 0;
  memcpy(input + offset, label, sizeof(label) - 1);
  offset += sizeof(label) - 1;
  memcpy(input + offset, manifest->traffic_key_id,
         sizeof(manifest->traffic_key_id));
  offset += sizeof(manifest->traffic_key_id);
  qlinq_write_u32(input + offset, manifest->key_epoch);
  offset += 4;
  qlinq_write_u16(input + offset, manifest->cipher_suite);
  uint8_t digest[32];
  if (!SHA256(input, sizeof(input), digest))
    return -1;
  static const char hex[] = "0123456789abcdef";
  char encoded[65];
  for (size_t i = 0; i < sizeof(digest); i++) {
    encoded[i * 2] = hex[digest[i] >> 4];
    encoded[i * 2 + 1] = hex[digest[i] & 0x0f];
  }
  encoded[64] = '\0';
  int written = snprintf(filename, ACTIVATION_FILENAME_SIZE, "%s-%s.%s", role,
                         encoded, suffix);
  OPENSSL_cleanse(input, sizeof(input));
  OPENSSL_cleanse(digest, sizeof(digest));
  return written > 0 && (size_t)written < ACTIVATION_FILENAME_SIZE ? 0 : -1;
}

static int finish_activation_open(qlinq_emcon_activation_t **activation, int fd,
                                  int directory_fd,
                                  const qlinq_emcon_manifest_t *manifest) {
  struct stat info;
  if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
      info.st_uid != geteuid() || info.st_nlink != 1 ||
      (info.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    close(fd);
    close(directory_fd);
    return QLINQ_EMCON_ACTIVATION_IO;
  }
  if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
    int ret = errno == EWOULDBLOCK || errno == EAGAIN
                  ? QLINQ_EMCON_ACTIVATION_LOCKED
                  : QLINQ_EMCON_ACTIVATION_IO;
    close(fd);
    close(directory_fd);
    return ret;
  }

  qlinq_emcon_activation_t *opened = calloc(1, sizeof(*opened));
  if (!opened) {
    close(fd);
    close(directory_fd);
    return QLINQ_EMCON_ACTIVATION_IO;
  }
  opened->fd = fd;
  opened->directory_fd = directory_fd;
  opened->manifest = *manifest;
  opened->next_packet_number = manifest->initial_packet_number;
  /* earlier opener may have written first slot without syncing directory */
  opened->needs_directory_sync = true;
  if (qlinq_emcon_manifest_digest(manifest, opened->manifest_digest) !=
      QLINQ_EMCON_MANIFEST_OK) {
    qlinq_emcon_activation_close(opened);
    return QLINQ_EMCON_ACTIVATION_IO;
  }

  uint8_t state[ACTIVATION_FILE_SIZE];
  size_t state_size;
  int ret = read_state(fd, state, &state_size);
  if (ret != QLINQ_EMCON_ACTIVATION_OK) {
    qlinq_emcon_activation_close(opened);
    return ret;
  }
  size_t slot_count = state_size / ACTIVATION_SLOT_SIZE;
  uint64_t slot_next[ACTIVATION_SLOT_COUNT] = {0};
  uint64_t slot_generation[ACTIVATION_SLOT_COUNT] = {0};
  for (size_t i = 0; i < slot_count; i++) {
    int decoded =
        decode_slot(state + i * ACTIVATION_SLOT_SIZE, &slot_next[i],
                    &slot_generation[i], manifest, opened->manifest_digest);
    if (decoded != QLINQ_EMCON_ACTIVATION_OK) {
      qlinq_emcon_activation_close(opened);
      return decoded;
    }
    if ((slot_generation[i] - 1) % ACTIVATION_SLOT_COUNT != i) {
      qlinq_emcon_activation_close(opened);
      return QLINQ_EMCON_ACTIVATION_CORRUPT;
    }
  }
  if (slot_count == ACTIVATION_SLOT_COUNT) {
    size_t newer = slot_generation[1] > slot_generation[0] ? 1 : 0;
    size_t older = 1 - newer;
    if (slot_generation[newer] - slot_generation[older] != 1 ||
        slot_next[newer] <= slot_next[older]) {
      qlinq_emcon_activation_close(opened);
      return QLINQ_EMCON_ACTIVATION_CORRUPT;
    }
    opened->next_packet_number = slot_next[newer];
    opened->generation = slot_generation[newer];
  } else if (slot_count == 1) {
    if (slot_generation[0] != 1) {
      qlinq_emcon_activation_close(opened);
      return QLINQ_EMCON_ACTIVATION_CORRUPT;
    }
    opened->next_packet_number = slot_next[0];
    opened->generation = slot_generation[0];
  }
  *activation = opened;
  return QLINQ_EMCON_ACTIVATION_OK;
}

int qlinq_emcon_activation_open_managed(
    qlinq_emcon_activation_t **activation, const char *state_directory,
    const qlinq_emcon_manifest_t *manifest) {
  if (!activation || !manifest ||
      qlinq_emcon_manifest_validate(manifest, 0) != QLINQ_EMCON_MANIFEST_OK)
    return QLINQ_EMCON_ACTIVATION_INVALID;
  *activation = NULL;
  int directory_fd = open_state_directory(state_directory);
  if (directory_fd < 0)
    return QLINQ_EMCON_ACTIVATION_IO;
  char filename[ACTIVATION_FILENAME_SIZE];
  if (activation_filename(filename, "sender", "state", manifest) != 0) {
    close(directory_fd);
    return QLINQ_EMCON_ACTIVATION_IO;
  }
  int fd = openat(directory_fd, filename,
                  O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_CREAT, 0600);
  if (fd < 0) {
    close(directory_fd);
    return QLINQ_EMCON_ACTIVATION_IO;
  }
  return finish_activation_open(activation, fd, directory_fd, manifest);
}

int qlinq_emcon_receiver_activation_check_available(
    const char *state_directory, const qlinq_emcon_manifest_t *manifest) {
  char filename[ACTIVATION_FILENAME_SIZE];
  if (!manifest ||
      activation_filename(filename, "receiver", "claim", manifest) != 0)
    return QLINQ_EMCON_ACTIVATION_INVALID;
  int directory_fd = open_state_directory(state_directory);
  if (directory_fd < 0)
    return QLINQ_EMCON_ACTIVATION_IO;
  struct stat info;
  int ret = QLINQ_EMCON_ACTIVATION_REUSED;
  if (fstatat(directory_fd, filename, &info, AT_SYMLINK_NOFOLLOW) != 0)
    ret =
        errno == ENOENT ? QLINQ_EMCON_ACTIVATION_OK : QLINQ_EMCON_ACTIVATION_IO;
  close(directory_fd);
  return ret;
}

int qlinq_emcon_receiver_activation_claim(
    const char *state_directory, const qlinq_emcon_manifest_t *manifest) {
  if (!manifest ||
      qlinq_emcon_manifest_validate(manifest, 0) != QLINQ_EMCON_MANIFEST_OK)
    return QLINQ_EMCON_ACTIVATION_INVALID;
  int directory_fd = open_state_directory(state_directory);
  if (directory_fd < 0)
    return QLINQ_EMCON_ACTIVATION_IO;
  char filename[ACTIVATION_FILENAME_SIZE];
  if (activation_filename(filename, "receiver", "claim", manifest) != 0) {
    close(directory_fd);
    return QLINQ_EMCON_ACTIVATION_IO;
  }
  int fd = openat(directory_fd, filename,
                  O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    int ret = errno == EEXIST ? QLINQ_EMCON_ACTIVATION_REUSED
                              : QLINQ_EMCON_ACTIVATION_IO;
    close(directory_fd);
    return ret;
  }
  struct stat info;
  int ret = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
                    info.st_uid == geteuid() && info.st_nlink == 1 &&
                    (info.st_mode & (S_IRWXG | S_IRWXO)) == 0 &&
                    sync_file_data(fd) == 0 && fsync(directory_fd) == 0
                ? QLINQ_EMCON_ACTIVATION_OK
                : QLINQ_EMCON_ACTIVATION_IO;
  if (ret != QLINQ_EMCON_ACTIVATION_OK)
    (void)unlinkat(directory_fd, filename, 0);
  close(fd);
  close(directory_fd);
  return ret;
}

static bool transfer_valid(const qlinq_emcon_transfer_t *transfer) {
  if (!transfer || transfer->block_size == 0)
    return false;
  if (transfer->resumable)
    return transfer->input_size != 0;
  return transfer->input_size == 0 &&
         all_zero(transfer->input_digest, sizeof(transfer->input_digest));
}

static int transfer_filename(char filename[ACTIVATION_FILENAME_SIZE],
                             const qlinq_emcon_manifest_t *manifest,
                             uint8_t alias, uint64_t group_id) {
  static const uint8_t label[] = "qlinq emcon transfer domain v1";
  uint8_t input[sizeof(label) - 1 + QLINQ_EMCON_MANIFEST_KEY_ID_SIZE + 15];
  size_t offset = 0;
  memcpy(input + offset, label, sizeof(label) - 1);
  offset += sizeof(label) - 1;
  memcpy(input + offset, manifest->traffic_key_id,
         sizeof(manifest->traffic_key_id));
  offset += sizeof(manifest->traffic_key_id);
  qlinq_write_u32(input + offset, manifest->key_epoch);
  offset += 4;
  qlinq_write_u16(input + offset, manifest->cipher_suite);
  offset += 2;
  input[offset++] = alias;
  qlinq_write_u64(input + offset, group_id);
  uint8_t digest[32];
  if (!SHA256(input, sizeof(input), digest))
    return -1;
  static const char hex[] = "0123456789abcdef";
  char encoded[65];
  for (size_t i = 0; i < sizeof(digest); i++) {
    encoded[i * 2] = hex[digest[i] >> 4];
    encoded[i * 2 + 1] = hex[digest[i] & 0x0f];
  }
  encoded[64] = '\0';
  int written = snprintf(filename, ACTIVATION_FILENAME_SIZE,
                         "transfer-%s.state", encoded);
  OPENSSL_cleanse(input, sizeof(input));
  OPENSSL_cleanse(digest, sizeof(digest));
  return written > 0 && (size_t)written < ACTIVATION_FILENAME_SIZE ? 0 : -1;
}

static bool encode_transfer_record(uint8_t record[TRANSFER_RECORD_SIZE],
                                   const qlinq_emcon_activation_t *activation,
                                   const qlinq_emcon_transfer_t *transfer) {
  memset(record, 0, TRANSFER_RECORD_SIZE);
  record[0] = TRANSFER_MAGIC_0;
  record[1] = TRANSFER_MAGIC_1;
  record[2] = TRANSFER_MAGIC_2;
  record[3] = TRANSFER_MAGIC_3;
  qlinq_write_u16(record + 4, TRANSFER_VERSION);
  qlinq_write_u16(record + 6, TRANSFER_RECORD_SIZE);
  memcpy(record + 8, activation->manifest_digest,
         sizeof(activation->manifest_digest));
  record[40] = transfer->alias;
  record[41] = transfer->resumable ? 1U : 0U;
  qlinq_write_u32(record + 44, transfer->block_size);
  qlinq_write_u64(record + 48, transfer->group_id);
  qlinq_write_u64(record + 56, transfer->input_size);
  memcpy(record + 64, transfer->input_digest, sizeof(transfer->input_digest));
  return SHA256(record, TRANSFER_CHECKSUM_OFFSET,
                record + TRANSFER_CHECKSUM_OFFSET) != NULL;
}

static int verify_existing_transfer(int fd,
                                    const qlinq_emcon_activation_t *activation,
                                    const qlinq_emcon_transfer_t *transfer) {
  struct stat info;
  if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
      info.st_uid != geteuid() || info.st_nlink != 1 ||
      (info.st_mode & (S_IRWXG | S_IRWXO)) != 0)
    return QLINQ_EMCON_ACTIVATION_IO;
  if (info.st_size != TRANSFER_RECORD_SIZE)
    return QLINQ_EMCON_ACTIVATION_CORRUPT;
  uint8_t record[TRANSFER_RECORD_SIZE];
  size_t offset = 0;
  while (offset < sizeof(record)) {
    ssize_t got =
        pread(fd, record + offset, sizeof(record) - offset, (off_t)offset);
    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0)
      return QLINQ_EMCON_ACTIVATION_IO;
    offset += (size_t)got;
  }
  uint8_t checksum[32];
  if (record[0] != TRANSFER_MAGIC_0 || record[1] != TRANSFER_MAGIC_1 ||
      record[2] != TRANSFER_MAGIC_2 || record[3] != TRANSFER_MAGIC_3 ||
      qlinq_read_u16(record + 4) != TRANSFER_VERSION ||
      qlinq_read_u16(record + 6) != TRANSFER_RECORD_SIZE || record[41] > 1U ||
      record[42] != 0 || record[43] != 0 ||
      !SHA256(record, TRANSFER_CHECKSUM_OFFSET, checksum) ||
      CRYPTO_memcmp(checksum, record + TRANSFER_CHECKSUM_OFFSET,
                    sizeof(checksum)) != 0)
    return QLINQ_EMCON_ACTIVATION_CORRUPT;
  if (CRYPTO_memcmp(record + 8, activation->manifest_digest,
                    sizeof(activation->manifest_digest)) != 0)
    return QLINQ_EMCON_ACTIVATION_IDENTITY_MISMATCH;
  qlinq_emcon_transfer_t stored = {
      .alias = record[40],
      .resumable = record[41] != 0,
      .block_size = qlinq_read_u32(record + 44),
      .group_id = qlinq_read_u64(record + 48),
      .input_size = qlinq_read_u64(record + 56),
  };
  memcpy(stored.input_digest, record + 64, sizeof(stored.input_digest));
  if (!transfer_valid(&stored) || stored.alias != transfer->alias ||
      stored.group_id != transfer->group_id)
    return QLINQ_EMCON_ACTIVATION_CORRUPT;
  if (!stored.resumable || !transfer->resumable ||
      stored.block_size != transfer->block_size ||
      stored.input_size != transfer->input_size ||
      CRYPTO_memcmp(stored.input_digest, transfer->input_digest,
                    sizeof(stored.input_digest)) != 0)
    return QLINQ_EMCON_ACTIVATION_TRANSFER_MISMATCH;
  return QLINQ_EMCON_ACTIVATION_OK;
}

int qlinq_emcon_activation_check_transfer(
    const qlinq_emcon_activation_t *activation,
    const qlinq_emcon_transfer_t *transfer) {
  if (!activation || !transfer_valid(transfer))
    return QLINQ_EMCON_ACTIVATION_INVALID;
  char filename[ACTIVATION_FILENAME_SIZE];
  if (transfer_filename(filename, &activation->manifest, transfer->alias,
                        transfer->group_id) != 0)
    return QLINQ_EMCON_ACTIVATION_IO;
  int fd = openat(activation->directory_fd, filename,
                  O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return errno == ENOENT ? QLINQ_EMCON_ACTIVATION_OK
                           : QLINQ_EMCON_ACTIVATION_IO;
  int ret = verify_existing_transfer(fd, activation, transfer);
  close(fd);
  return ret;
}

int qlinq_emcon_activation_bind_transfer(
    qlinq_emcon_activation_t *activation,
    const qlinq_emcon_transfer_t *transfer) {
  if (!activation || !transfer_valid(transfer))
    return QLINQ_EMCON_ACTIVATION_INVALID;
  char filename[ACTIVATION_FILENAME_SIZE];
  if (transfer_filename(filename, &activation->manifest, transfer->alias,
                        transfer->group_id) != 0)
    return QLINQ_EMCON_ACTIVATION_IO;
  int fd = openat(activation->directory_fd, filename,
                  O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    if (errno == EEXIST)
      return qlinq_emcon_activation_check_transfer(activation, transfer);
    return QLINQ_EMCON_ACTIVATION_IO;
  }
  struct stat info;
  uint8_t record[TRANSFER_RECORD_SIZE];
  int ret = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
                    info.st_uid == geteuid() && info.st_nlink == 1 &&
                    (info.st_mode & (S_IRWXG | S_IRWXO)) == 0 &&
                    encode_transfer_record(record, activation, transfer) &&
                    write_exact_at(fd, record, sizeof(record), 0) == 0 &&
                    sync_file_data(fd) == 0 &&
                    fsync(activation->directory_fd) == 0
                ? QLINQ_EMCON_ACTIVATION_OK
                : QLINQ_EMCON_ACTIVATION_IO;
  if (ret != QLINQ_EMCON_ACTIVATION_OK)
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
    return QLINQ_EMCON_ACTIVATION_INVALID;
  uint64_t limit = qlinq_emcon_packet_number_limit(
      activation->manifest.initial_packet_number);
  if (activation->generation == UINT64_MAX ||
      activation->next_packet_number >= limit ||
      minimum_packets > limit - activation->next_packet_number)
    return QLINQ_EMCON_ACTIVATION_EXHAUSTED;
  uint64_t remaining = limit - activation->next_packet_number;
  uint64_t packet_count =
      preferred_packets < remaining ? preferred_packets : remaining;
  uint64_t next = activation->next_packet_number + packet_count;
  uint64_t generation = activation->generation + 1;
  size_t slot_index = (size_t)((generation - 1) % ACTIVATION_SLOT_COUNT);
  uint8_t slot[ACTIVATION_SLOT_SIZE];
  if (!encode_slot(slot, activation, next, generation) ||
      write_exact_at(activation->fd, slot, sizeof(slot),
                     (off_t)(slot_index * ACTIVATION_SLOT_SIZE)) != 0 ||
      sync_file_data(activation->fd) != 0 ||
      (activation->needs_directory_sync &&
       fsync(activation->directory_fd) != 0))
    return QLINQ_EMCON_ACTIVATION_IO;
  activation->needs_directory_sync = false;
  *first_packet_number = activation->next_packet_number;
  *reserved_until = next;
  activation->next_packet_number = next;
  activation->generation = generation;
  return QLINQ_EMCON_ACTIVATION_OK;
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
