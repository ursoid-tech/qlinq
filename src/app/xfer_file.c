/* durable sequential single-file storage for transfer protocol */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "xfer_file.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define META_SIZE 120
#define META_DIGEST_OFFSET 88
#define HASH_BUFFER_SIZE (64 * 1024)

struct xfer_file {
  int fd;
  int dirfd;
  int lockfd;
  char *name;
  char *part;
  char *meta;
  uint64_t size;
  uint64_t written;
  uint64_t durable;
  uint8_t hash[XFER_FILE_HASH_SIZE];
  EVP_MD_CTX *digest;
  xfer_file_progress_cb progress;
  void *progress_context;
  struct stat source_stat;
  bool source;
  bool committed;
};

static bool fail(char *error, size_t cap, const char *format, ...) {
  if (error != NULL && cap != 0) {
    va_list args;
    va_start(args, format);
    vsnprintf(error, cap, format, args);
    va_end(args);
  }
  return false;
}

static bool syserr(char *error, size_t cap, const char *operation) {
  return fail(error, cap, "%s: %s", operation, strerror(errno));
}

static bool report_progress(xfer_file_t *file, size_t bytes, char *error,
                            size_t cap) {
  return file == NULL || file->progress == NULL ||
         file->progress(file->progress_context, bytes) ||
         fail(error, cap, "transfer cancelled");
}

static xfer_file_t *allocate_file(char *error, size_t cap) {
  xfer_file_t *file = calloc(1, sizeof(*file));
  if (file == NULL) {
    fail(error, cap, "allocating transfer file");
    return NULL;
  }
  file->fd = file->dirfd = file->lockfd = -1;
  return file;
}

static bool regular_fd(int fd, struct stat *st, char *error, size_t cap) {
  if (fstat(fd, st) != 0)
    return syserr(error, cap, "stat transfer file");
  if (!S_ISREG(st->st_mode) || st->st_size < 0)
    return fail(error, cap, "transfer paths must name regular files");
  return true;
}

static bool read_exact(int fd, xfer_file_t *progress_file, uint64_t offset,
                       void *buffer, size_t size, char *error, size_t cap) {
  uint8_t *cursor = buffer;
  while (size != 0) {
    size_t count = size < HASH_BUFFER_SIZE ? size : HASH_BUFFER_SIZE;
    ssize_t got = pread(fd, cursor, count, (off_t)offset);
    if (got < 0 && errno == EINTR)
      continue;
    if (got < 0)
      return syserr(error, cap, "read transfer file");
    if (got == 0)
      return fail(error, cap, "transfer file was truncated");
    cursor += got;
    offset += (uint64_t)got;
    size -= (size_t)got;
    if (!report_progress(progress_file, (size_t)got, error, cap))
      return false;
  }
  return true;
}

static bool digest_value(const EVP_MD_CTX *ctx, uint8_t out[32], char *error,
                         size_t cap) {
  EVP_MD_CTX *copy = EVP_MD_CTX_new();
  unsigned length = 0;
  bool ok = copy != NULL && EVP_MD_CTX_copy_ex(copy, ctx) == 1 &&
            EVP_DigestFinal_ex(copy, out, &length) == 1 && length == 32;
  EVP_MD_CTX_free(copy);
  return ok || fail(error, cap, "SHA-256 failed");
}

/* hash prefix and optionally retain digest context */
static bool hash_prefix(xfer_file_t *file, uint64_t length, uint8_t out[32],
                        EVP_MD_CTX **retained, char *error, size_t cap) {
  uint8_t buffer[HASH_BUFFER_SIZE];
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  bool ok = false;
  if (ctx == NULL || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
    fail(error, cap, "initializing SHA-256");
    goto done;
  }
  for (uint64_t offset = 0; offset < length;) {
    size_t count = length - offset < sizeof(buffer) ? (size_t)(length - offset)
                                                    : sizeof(buffer);
    if (!read_exact(file->fd, NULL, offset, buffer, count, error, cap))
      goto done;
    if (EVP_DigestUpdate(ctx, buffer, count) != 1) {
      fail(error, cap, "updating SHA-256");
      goto done;
    }
    offset += count;
    if (!report_progress(file, count, error, cap))
      goto done;
  }
  ok = digest_value(ctx, out, error, cap);
  if (ok && retained != NULL) {
    *retained = ctx;
    ctx = NULL;
  }
done:
  EVP_MD_CTX_free(ctx);
  return ok;
}

static bool source_unchanged(xfer_file_t *file, char *error, size_t cap) {
  struct stat st;
  if (!file->source)
    return true;
  if (!regular_fd(file->fd, &st, error, cap))
    return false;
#if defined(__APPLE__)
#define ST_MTIME(st) ((st).st_mtimespec)
#define ST_CTIME(st) ((st).st_ctimespec)
#else
#define ST_MTIME(st) ((st).st_mtim)
#define ST_CTIME(st) ((st).st_ctim)
#endif
  if (st.st_size != file->source_stat.st_size ||
      ST_MTIME(st).tv_sec != ST_MTIME(file->source_stat).tv_sec ||
      ST_MTIME(st).tv_nsec != ST_MTIME(file->source_stat).tv_nsec ||
      ST_CTIME(st).tv_sec != ST_CTIME(file->source_stat).tv_sec ||
      ST_CTIME(st).tv_nsec != ST_CTIME(file->source_stat).tv_nsec)
    return fail(error, cap, "source file changed during transfer");
  return true;
}

xfer_file_t *xfer_file_source_open(const char *path,
                                   xfer_file_progress_cb progress,
                                   void *context, char *error, size_t cap) {
  xfer_file_t *file = allocate_file(error, cap);
  if (file == NULL)
    return NULL;
  file->progress = progress;
  file->progress_context = context;
  file->source = true;
  file->fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (file->fd < 0) {
    syserr(error, cap, "open source");
    goto failed;
  }
  if (!regular_fd(file->fd, &file->source_stat, error, cap))
    goto failed;
  file->size = (uint64_t)file->source_stat.st_size;
  if (!hash_prefix(file, file->size, file->hash, NULL, error, cap) ||
      !source_unchanged(file, error, cap))
    goto failed;
  return file;
failed:
  xfer_file_close(file);
  return NULL;
}

static char *suffix(const char *name, const char *extension) {
  size_t a = strlen(name), b = strlen(extension);
  char *result = malloc(a + b + 1);
  if (result != NULL) {
    memcpy(result, name, a);
    memcpy(result + a, extension, b + 1);
  }
  return result;
}

static bool open_destination_dir(xfer_file_t *file, const char *path,
                                 char *error, size_t cap) {
  char *copy = strdup(path);
  if (copy == NULL)
    return fail(error, cap, "allocating destination path");
  char *slash = strrchr(copy, '/');
  const char *parent = ".";
  const char *name = copy;
  if (slash != NULL) {
    name = slash + 1;
    if (slash == copy) {
      parent = "/";
    } else {
      *slash = '\0';
      parent = copy;
    }
  }
  if (*name == '\0' || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
    free(copy);
    return fail(error, cap, "invalid destination filename");
  }
  file->name = strdup(name);
  file->part = suffix(name, ".qlinq-part");
  file->meta = suffix(name, ".qlinq-meta");
  file->dirfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  free(copy);
  if (!file->name || !file->part || !file->meta)
    return fail(error, cap, "allocating destination path");
  if (file->dirfd < 0)
    return syserr(error, cap, "open destination directory");
  char *lock = suffix(file->name, ".qlinq-lock");
  if (lock == NULL)
    return fail(error, cap, "allocating lock path");
  file->lockfd =
      openat(file->dirfd, lock,
             O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
  free(lock);
  if (file->lockfd < 0)
    return syserr(error, cap, "open destination lock");
  struct stat st;
  if (!regular_fd(file->lockfd, &st, error, cap))
    return false;
  if (flock(file->lockfd, LOCK_EX | LOCK_NB) != 0)
    return syserr(error, cap, "destination is locked");
  return true;
}

static void put64(uint8_t *out, uint64_t value) {
  for (unsigned i = 0; i != 8; ++i)
    out[i] = (uint8_t)(value >> (56 - 8 * i));
}

static uint64_t get64(const uint8_t *in) {
  uint64_t value = 0;
  for (unsigned i = 0; i != 8; ++i)
    value = (value << 8) | in[i];
  return value;
}

static bool metadata_digest(const uint8_t *data, uint8_t out[32]) {
  unsigned size = 0;
  return EVP_Digest(data, META_DIGEST_OFFSET, out, &size, EVP_sha256(), NULL) ==
             1 &&
         size == 32;
}

static bool load_metadata(xfer_file_t *file, uint8_t prefix[32], bool *exists,
                          char *error, size_t cap) {
  *exists = false;
  int fd = openat(file->dirfd, file->meta,
                  O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) {
    if (errno == ENOENT)
      return true;
    return syserr(error, cap, "open resume metadata");
  }
  *exists = true;
  uint8_t data[META_SIZE], checksum[32];
  struct stat st;
  bool ok = regular_fd(fd, &st, error, cap);
  if (ok && st.st_size != META_SIZE)
    ok = fail(error, cap, "invalid resume metadata size");
  if (ok)
    ok = read_exact(fd, NULL, 0, data, sizeof(data), error, cap);
  close(fd);
  if (!ok)
    return false;
  if (memcmp(data, "QLXFER1\n", 8) != 0 || !metadata_digest(data, checksum) ||
      CRYPTO_memcmp(checksum, data + META_DIGEST_OFFSET, 32) != 0)
    return fail(error, cap, "corrupt resume metadata");
  if (get64(data + 8) != file->size ||
      CRYPTO_memcmp(data + 24, file->hash, 32) != 0)
    return fail(error, cap, "resume metadata belongs to another source file");
  file->durable = get64(data + 16);
  if (file->durable > file->size)
    return fail(error, cap, "invalid resume offset");
  memcpy(prefix, data + 56, 32);
  return true;
}

static bool sync_data(int fd, char *error, size_t cap) {
#if defined(__APPLE__)
  int result = fsync(fd);
#else
  int result = fdatasync(fd);
#endif
  return result == 0 || syserr(error, cap, "sync transfer data");
}

static bool save_metadata(xfer_file_t *file, char *error, size_t cap) {
  uint8_t data[META_SIZE];
  memcpy(data, "QLXFER1\n", 8);
  put64(data + 8, file->size);
  put64(data + 16, file->written);
  memcpy(data + 24, file->hash, 32);
  if (!digest_value(file->digest, data + 56, error, cap) ||
      !metadata_digest(data, data + META_DIGEST_OFFSET))
    return fail(error, cap, "hashing resume metadata");
  size_t length = strlen(file->meta) + 64;
  char *temporary = malloc(length);
  if (temporary == NULL)
    return fail(error, cap, "allocating metadata path");
  int fd = -1;
  for (unsigned attempt = 0; attempt != 100; ++attempt) {
    snprintf(temporary, length, "%s.tmp.%ld.%u", file->meta, (long)getpid(),
             attempt);
    fd = openat(file->dirfd, temporary,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd >= 0 || errno != EEXIST)
      break;
  }
  if (fd < 0) {
    free(temporary);
    return syserr(error, cap, "create resume metadata");
  }
  bool ok = true;
  size_t offset = 0;
  while (offset < sizeof(data)) {
    ssize_t count = write(fd, data + offset, sizeof(data) - offset);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0) {
      ok = syserr(error, cap, "write resume metadata");
      break;
    }
    offset += (size_t)count;
  }
  if (ok && fsync(fd) != 0)
    ok = syserr(error, cap, "sync resume metadata");
  if (close(fd) != 0 && ok)
    ok = syserr(error, cap, "close resume metadata");
  if (ok && renameat(file->dirfd, temporary, file->dirfd, file->meta) != 0)
    ok = syserr(error, cap, "replace resume metadata");
  if (ok && fsync(file->dirfd) != 0)
    ok = syserr(error, cap, "sync resume directory");
  if (!ok)
    unlinkat(file->dirfd, temporary, 0);
  free(temporary);
  if (ok)
    file->durable = file->written;
  return ok;
}

xfer_file_t *xfer_file_sink_open(const char *path, uint64_t size,
                                 const uint8_t hash[32],
                                 xfer_file_progress_cb progress, void *context,
                                 char *error, size_t cap) {
  if (size > INT64_MAX || sizeof(off_t) < sizeof(int64_t)) {
    fail(error, cap, "transfer file exceeds supported file offset range");
    return NULL;
  }
  xfer_file_t *file = allocate_file(error, cap);
  if (file == NULL)
    return NULL;
  file->progress = progress;
  file->progress_context = context;
  file->size = size;
  memcpy(file->hash, hash, 32);
  if (!open_destination_dir(file, path, error, cap))
    goto failed;

  /* check if destination is already complete */
  file->fd = openat(file->dirfd, file->name,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  struct stat st;
  uint8_t actual[32];
  if (file->fd >= 0) {
    if (!regular_fd(file->fd, &st, error, cap))
      goto failed;
    if ((uint64_t)st.st_size != size) {
      fail(error, cap, "destination already exists with different contents");
      goto failed;
    }
    if (!hash_prefix(file, size, actual, NULL, error, cap))
      goto failed;
    if (CRYPTO_memcmp(actual, hash, 32) != 0) {
      fail(error, cap, "destination already exists with different contents");
      goto failed;
    }
    file->written = file->durable = size;
    file->committed = true;
    return file;
  }
  if (errno != ENOENT) {
    syserr(error, cap, "open destination");
    goto failed;
  }
  uint8_t prefix[32];
  bool metadata_exists;
  if (!load_metadata(file, prefix, &metadata_exists, error, cap))
    goto failed;
  file->fd = openat(file->dirfd, file->part,
                    O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (file->fd < 0 && errno == ENOENT && !metadata_exists) {
    file->fd = openat(file->dirfd, file->part,
                      O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  }
  if (file->fd < 0) {
    syserr(error, cap, "open staging file");
    goto failed;
  }
  if (!regular_fd(file->fd, &st, error, cap))
    goto failed;
  if (st.st_nlink != 1) {
    fail(error, cap, "staging file must not have additional hard links");
    goto failed;
  }
  /* adopt empty orphan staging file */
  if (!metadata_exists && st.st_size != 0) {
    fail(error, cap, "nonempty staging file has no resume metadata");
    goto failed;
  }
  if ((uint64_t)st.st_size < file->durable) {
    fail(error, cap, "staging file is shorter than its durable resume offset");
    goto failed;
  }
  if (!hash_prefix(file, file->durable, actual, &file->digest, error, cap))
    goto failed;
  if (metadata_exists && CRYPTO_memcmp(actual, prefix, 32) != 0) {
    fail(error, cap,
         "staging file's durable prefix failed SHA-256 verification");
    goto failed;
  }
  if (ftruncate(file->fd, (off_t)file->durable) != 0) {
    syserr(error, cap, "truncate uncheckpointed staging bytes");
    goto failed;
  }
  file->written = file->durable;
  if (!metadata_exists) {
    /* ensure staging file is directory durable */
    if (fsync(file->dirfd) != 0) {
      syserr(error, cap, "sync new staging pathname");
      goto failed;
    }
    if (!xfer_file_checkpoint(file, error, cap))
      goto failed;
  }
  return file;
failed:
  xfer_file_close(file);
  return NULL;
}

uint64_t xfer_file_size(const xfer_file_t *file) {
  return file->size;
}
const uint8_t *xfer_file_hash(const xfer_file_t *file) {
  return file->hash;
}
uint64_t xfer_file_offset(const xfer_file_t *file) {
  return file->durable;
}
bool xfer_file_is_committed(const xfer_file_t *file) {
  return file->committed;
}

bool xfer_file_prefix_hash(xfer_file_t *file, uint64_t offset, uint8_t out[32],
                           char *error, size_t cap) {
  if (offset > file->size || (!file->source && offset > file->written))
    return fail(error, cap, "prefix hash exceeds available file data");
  return source_unchanged(file, error, cap) &&
         hash_prefix(file, offset, out, NULL, error, cap) &&
         source_unchanged(file, error, cap);
}

bool xfer_file_read(xfer_file_t *file, uint64_t offset, void *buffer,
                    size_t size, char *error, size_t cap) {
  if (!file->source || offset > file->size || size > file->size - offset)
    return fail(error, cap, "source read exceeds file size");
  return source_unchanged(file, error, cap) &&
         read_exact(file->fd, file, offset, buffer, size, error, cap) &&
         source_unchanged(file, error, cap);
}

bool xfer_file_write(xfer_file_t *file, uint64_t offset, const void *data,
                     size_t size, char *error, size_t cap) {
  if (file->source || file->committed || offset != file->written ||
      offset > file->size || size > file->size - offset)
    return fail(error, cap, "invalid sequential transfer write");
  const uint8_t *bytes = data;
  size_t remaining = size;
  while (remaining != 0) {
    size_t count = remaining < HASH_BUFFER_SIZE ? remaining : HASH_BUFFER_SIZE;
    ssize_t written = pwrite(file->fd, bytes, count, (off_t)offset);
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      return syserr(error, cap, "write staging file");
    bytes += written;
    offset += (uint64_t)written;
    remaining -= (size_t)written;
    if (!report_progress(file, (size_t)written, error, cap))
      return false;
  }
  if (size != 0 && EVP_DigestUpdate(file->digest, data, size) != 1)
    return fail(error, cap, "updating staging SHA-256");
  file->written += size;
  return true;
}

bool xfer_file_checkpoint(xfer_file_t *file, char *error, size_t cap) {
  if (file->source)
    return fail(error, cap, "cannot checkpoint a source file");
  if (file->committed)
    return true;
  return sync_data(file->fd, error, cap) && save_metadata(file, error, cap);
}

/* clean up recognized sidecars after commit */
static bool cleanup_completed(xfer_file_t *file, const struct stat *final,
                              char *error, size_t cap) {
  struct stat staged;
  bool has_part =
      fstatat(file->dirfd, file->part, &staged, AT_SYMLINK_NOFOLLOW) == 0;
  if (!has_part && errno != ENOENT)
    return syserr(error, cap, "stat completed staging file");
  if (has_part && (!S_ISREG(staged.st_mode) || staged.st_dev != final->st_dev ||
                   staged.st_ino != final->st_ino))
    return true;
  uint8_t prefix[32];
  bool has_meta;
  uint64_t durable = file->durable;
  char ignored[256];
  bool matches =
      load_metadata(file, prefix, &has_meta, ignored, sizeof(ignored));
  file->durable = durable;
  if (!matches)
    return true;
  if (has_part && unlinkat(file->dirfd, file->part, 0) != 0)
    return syserr(error, cap, "remove completed staging file");
  if (has_meta && unlinkat(file->dirfd, file->meta, 0) != 0)
    return syserr(error, cap, "remove completed resume metadata");
  return true;
}

bool xfer_file_commit(xfer_file_t *file, char *error, size_t cap) {
  if (file->source || file->written != file->size)
    return fail(error, cap, "cannot commit an incomplete file");
  uint8_t actual[32];
  struct stat st;
  if (!regular_fd(file->fd, &st, error, cap))
    return false;
  if ((uint64_t)st.st_size != file->size)
    return fail(error, cap, "completed file has an unexpected size");
  if (!hash_prefix(file, file->size, actual, NULL, error, cap))
    return false;
  if (CRYPTO_memcmp(actual, file->hash, 32) != 0)
    return fail(error, cap, "completed file failed SHA-256 verification");
  if (!sync_data(file->fd, error, cap))
    return false;
  if (!file->committed) {
    struct stat named;
    if (fstatat(file->dirfd, file->part, &named, AT_SYMLINK_NOFOLLOW) != 0)
      return syserr(error, cap, "stat staging pathname");
    if (!S_ISREG(named.st_mode) || named.st_dev != st.st_dev ||
        named.st_ino != st.st_ino)
      return fail(error, cap, "staging pathname changed during transfer");
    /* atomic install without replacement */
    if (linkat(file->dirfd, file->part, file->dirfd, file->name, 0) != 0)
      return syserr(error, cap, "install destination without replacement");
  }
  struct stat installed;
  if (fstatat(file->dirfd, file->name, &installed, AT_SYMLINK_NOFOLLOW) != 0)
    return syserr(error, cap, "stat installed destination");
  if (!S_ISREG(installed.st_mode) || installed.st_dev != st.st_dev ||
      installed.st_ino != st.st_ino)
    return fail(error, cap, "destination pathname changed during transfer");
  if (fsync(file->dirfd) != 0)
    return syserr(error, cap, "sync installed destination");
  file->committed = true;
  file->durable = file->size;
  if (!cleanup_completed(file, &st, error, cap))
    return false;
  return fsync(file->dirfd) == 0 ||
         syserr(error, cap, "sync destination directory");
}

void xfer_file_close(xfer_file_t *file) {
  if (file == NULL)
    return;
  if (file->fd >= 0)
    close(file->fd);
  if (file->lockfd >= 0)
    close(file->lockfd);
  if (file->dirfd >= 0)
    close(file->dirfd);
  EVP_MD_CTX_free(file->digest);
  free(file->name);
  free(file->part);
  free(file->meta);
  free(file);
}
