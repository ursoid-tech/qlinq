/* storage verification tests */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../../src/app/xfer_file.h"

#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char directory[] = "/tmp/qlinq-xfer-file-XXXXXX";
static char error[256];
static uint8_t bytes[8192];

#define CHECK(expr)                                                            \
  do {                                                                         \
    if (!(expr)) {                                                             \
      fprintf(stderr, "line %d: %s: %s\n", __LINE__, #expr, error);            \
      abort();                                                                 \
    }                                                                          \
  } while (0)

static void path(char out[512], const char *name) {
  int size = snprintf(out, 512, "%s/%s", directory, name);
  CHECK(size > 0 && size < 512);
}

static void write_path(const char *name, const void *data, size_t size) {
  char filename[512];
  path(filename, name);
  int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  CHECK(fd >= 0);
  CHECK(write(fd, data, size) == (ssize_t)size);
  CHECK(close(fd) == 0);
}

static void mutate(const char *name, off_t offset) {
  char filename[512];
  path(filename, name);
  int fd = open(filename, O_RDWR);
  uint8_t byte;
  CHECK(fd >= 0);
  CHECK(pread(fd, &byte, 1, offset) == 1);
  byte ^= 0x5a;
  CHECK(pwrite(fd, &byte, 1, offset) == 1);
  CHECK(close(fd) == 0);
}

static xfer_file_t *sink(const char *name, const xfer_file_t *source) {
  char filename[512];
  path(filename, name);
  return xfer_file_sink_open(filename, xfer_file_size(source),
                             xfer_file_hash(source), NULL, NULL, error,
                             sizeof(error));
}

static xfer_file_t *source(const char *name) {
  char filename[512];
  path(filename, name);
  return xfer_file_source_open(filename, NULL, NULL, error, sizeof(error));
}

static void check_resume(xfer_file_t *src) {
  xfer_file_t *dst = sink("resume", src);
  CHECK(dst != NULL);
  CHECK(sink("resume", src) == NULL); /* reject concurrent writers */
  CHECK(xfer_file_offset(dst) == 0);
  CHECK(!xfer_file_write(dst, 1, bytes, 512, error, sizeof(error)));
  CHECK(!xfer_file_commit(dst, error, sizeof(error)));
  CHECK(xfer_file_write(dst, 0, bytes, 4096, error, sizeof(error)));
  CHECK(xfer_file_offset(dst) == 0);
  CHECK(xfer_file_checkpoint(dst, error, sizeof(error)));
  CHECK(xfer_file_offset(dst) == 4096);
  CHECK(xfer_file_write(dst, 4096, bytes + 4096, 1024, error, sizeof(error)));
  xfer_file_close(dst);

  dst = sink("resume", src);
  CHECK(dst != NULL && xfer_file_offset(dst) == 4096);
  char filename[512];
  path(filename, "resume.qlinq-part");
  struct stat st;
  CHECK(stat(filename, &st) == 0 && st.st_size == 4096);
  uint8_t expected[32], actual[32];
  CHECK(xfer_file_prefix_hash(src, 4096, expected, error, sizeof(error)));
  CHECK(xfer_file_prefix_hash(dst, 4096, actual, error, sizeof(error)));
  CHECK(memcmp(actual, expected, sizeof(actual)) == 0);
  CHECK(xfer_file_write(dst, 4096, bytes + 4096, 4096, error, sizeof(error)));
  path(filename, "resume");
  CHECK(access(filename, F_OK) != 0); /* no partial destination exposed */
  CHECK(xfer_file_commit(dst, error, sizeof(error)));
  CHECK(xfer_file_is_committed(dst));
  CHECK(xfer_file_offset(dst) == sizeof(bytes));
  xfer_file_close(dst);
  path(filename, "resume.qlinq-part");
  CHECK(access(filename, F_OK) != 0);
  path(filename, "resume.qlinq-meta");
  CHECK(access(filename, F_OK) != 0);

  dst = sink("resume", src); /* idempotent completed destination */
  CHECK(dst != NULL && xfer_file_is_committed(dst));
  CHECK(xfer_file_offset(dst) == sizeof(bytes));
  CHECK(xfer_file_commit(dst, error, sizeof(error)));
  xfer_file_close(dst);
  dst = source("resume");
  CHECK(dst != NULL);
  uint8_t contents[sizeof(bytes)];
  CHECK(
      xfer_file_read(dst, 0, contents, sizeof(contents), error, sizeof(error)));
  CHECK(memcmp(contents, bytes, sizeof(bytes)) == 0);
  xfer_file_close(dst);
}

static void check_corruption(xfer_file_t *src) {
  xfer_file_t *dst = sink("corrupt", src);
  CHECK(dst != NULL);
  CHECK(xfer_file_write(dst, 0, bytes, 1024, error, sizeof(error)));
  CHECK(xfer_file_checkpoint(dst, error, sizeof(error)));
  xfer_file_close(dst);
  mutate("corrupt.qlinq-part", 10);
  CHECK(sink("corrupt", src) == NULL);

  dst = sink("metadata", src);
  CHECK(dst != NULL);
  xfer_file_close(dst);
  mutate("metadata.qlinq-meta", 16);
  CHECK(sink("metadata", src) == NULL);

  dst = sink("identity", src);
  CHECK(dst != NULL);
  xfer_file_close(dst);
  char filename[512];
  path(filename, "identity");
  uint8_t other_hash[32];
  memcpy(other_hash, xfer_file_hash(src), sizeof(other_hash));
  other_hash[0] ^= 1;
  CHECK(xfer_file_sink_open(filename, sizeof(bytes), other_hash, NULL, NULL,
                            error, sizeof(error)) == NULL);
  CHECK(xfer_file_sink_open(filename, sizeof(bytes) - 1, xfer_file_hash(src),
                            NULL, NULL, error, sizeof(error)) == NULL);

  dst = sink("wrong-data", src);
  CHECK(dst != NULL);
  uint8_t wrong[sizeof(bytes)];
  memset(wrong, 0, sizeof(wrong));
  CHECK(xfer_file_write(dst, 0, wrong, sizeof(wrong), error, sizeof(error)));
  CHECK(!xfer_file_commit(dst, error, sizeof(error)));
  xfer_file_close(dst);
  path(filename, "wrong-data");
  CHECK(access(filename, F_OK) != 0);
}

static void check_path_safety(xfer_file_t *src) {
  write_path("occupied", "unrelated", 9);
  CHECK(sink("occupied", src) == NULL);
  char filename[512], target[512];
  path(target, "occupied");
  const char *names[] = {"sym", "stage.qlinq-part", "meta.qlinq-meta",
                         "lock.qlinq-lock"};
  const char *sinks[] = {"sym", "stage", "meta", "lock"};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    path(filename, names[i]);
    CHECK(symlink(target, filename) == 0);
    CHECK(sink(sinks[i], src) == NULL);
  }
  CHECK(source("sym") == NULL);
  path(filename, "fifo");
  CHECK(mkfifo(filename, 0600) == 0);
  CHECK(source("fifo") == NULL);
  CHECK(sink("fifo", src) == NULL);
  path(filename, "hardlink.qlinq-part");
  CHECK(link(target, filename) == 0);
  CHECK(sink("hardlink", src) == NULL);
  int fd = open(target, O_RDONLY);
  char contents[9];
  CHECK(fd >= 0 && read(fd, contents, sizeof(contents)) == sizeof(contents));
  CHECK(memcmp(contents, "unrelated", sizeof(contents)) == 0);
  close(fd);

  /* preserve destination on conflict */
  xfer_file_t *dst = sink("race", src);
  CHECK(dst != NULL);
  CHECK(xfer_file_write(dst, 0, bytes, sizeof(bytes), error, sizeof(error)));
  write_path("race", "unrelated", 9);
  CHECK(!xfer_file_commit(dst, error, sizeof(error)));
  xfer_file_close(dst);
}

static void check_interrupted_install(xfer_file_t *src) {
  /* crash after hard-link install */
  xfer_file_t *dst = sink("interrupted", src);
  CHECK(dst != NULL);
  CHECK(xfer_file_write(dst, 0, bytes, sizeof(bytes), error, sizeof(error)));
  CHECK(xfer_file_checkpoint(dst, error, sizeof(error)));
  char part[512], final[512], meta[512];
  path(part, "interrupted.qlinq-part");
  path(meta, "interrupted.qlinq-meta");
  path(final, "interrupted");
  CHECK(link(part, final) == 0);
  xfer_file_close(dst);
  dst = sink("interrupted", src);
  CHECK(dst != NULL && xfer_file_is_committed(dst));
  CHECK(xfer_file_commit(dst, error, sizeof(error)));
  CHECK(access(part, F_OK) != 0 && access(meta, F_OK) != 0);
  xfer_file_close(dst);

  /* preserve unrelated sidecars */
  write_path("interrupted.qlinq-part", "unrelated", 9);
  write_path("interrupted.qlinq-meta", "unrelated", 9);
  dst = sink("interrupted", src);
  CHECK(dst != NULL && xfer_file_commit(dst, error, sizeof(error)));
  xfer_file_close(dst);
  struct stat st;
  CHECK(stat(part, &st) == 0 && st.st_size == 9);
  CHECK(stat(meta, &st) == 0 && st.st_size == 9);
}

static void check_empty_and_orphan(void) {
  write_path("empty", "", 0);
  xfer_file_t *src = source("empty");
  CHECK(src != NULL && xfer_file_size(src) == 0);
  /* adopt empty staging file after crash */
  write_path("empty-out.qlinq-part", "", 0);
  xfer_file_t *dst = sink("empty-out", src);
  CHECK(dst != NULL);
  CHECK(xfer_file_checkpoint(dst, error, sizeof(error)));
  CHECK(xfer_file_commit(dst, error, sizeof(error)));
  xfer_file_close(dst);
  dst = sink("empty-out", src);
  CHECK(dst != NULL && xfer_file_is_committed(dst));
  CHECK(xfer_file_commit(dst, error, sizeof(error)));
  xfer_file_close(dst);
  write_path("orphan.qlinq-part", "unrelated", 9);
  CHECK(sink("orphan", src) == NULL);
  xfer_file_close(src);
}

static bool observe_progress(void *context, size_t count) {
  uint64_t *bytes_done = context;
  CHECK(count > 0);
  *bytes_done += count;
  return true;
}

static bool cancel_progress(void *context, size_t count) {
  uint64_t *bytes_done = context;
  CHECK(count > 0);
  *bytes_done += count;
  return false;
}

static void check_progress(void) {
  char filename[512];
  path(filename, "source");
  uint64_t progress = 0;
  xfer_file_t *src = xfer_file_source_open(filename, observe_progress,
                                           &progress, error, sizeof(error));
  CHECK(src != NULL && progress == sizeof(bytes));
  uint8_t digest[32];
  CHECK(xfer_file_prefix_hash(src, 1024, digest, error, sizeof(error)));
  CHECK(progress == sizeof(bytes) + 1024);
  uint8_t contents[sizeof(bytes)];
  CHECK(
      xfer_file_read(src, 0, contents, sizeof(contents), error, sizeof(error)));
  CHECK(progress == 2 * sizeof(bytes) + 1024);
  path(filename, "progress");
  xfer_file_t *dst =
      xfer_file_sink_open(filename, sizeof(bytes), xfer_file_hash(src),
                          observe_progress, &progress, error, sizeof(error));
  CHECK(dst != NULL);
  uint64_t before_write = progress;
  CHECK(xfer_file_write(dst, 0, bytes, sizeof(bytes), error, sizeof(error)));
  CHECK(progress == before_write + sizeof(bytes));
  CHECK(xfer_file_checkpoint(dst, error, sizeof(error)));
  xfer_file_close(dst);
  uint64_t before_resume = progress;
  dst = xfer_file_sink_open(filename, sizeof(bytes), xfer_file_hash(src),
                            observe_progress, &progress, error, sizeof(error));
  CHECK(dst != NULL && progress == before_resume + sizeof(bytes));
  uint64_t before_commit = progress;
  CHECK(xfer_file_commit(dst, error, sizeof(error)));
  CHECK(progress == before_commit + sizeof(bytes));
  xfer_file_close(dst);

  /* cancel unwinds immediately */
  uint8_t *large = calloc(1, 128 * 1024);
  CHECK(large != NULL);
  write_path("large-source", large, 128 * 1024);
  free(large);
  path(filename, "large-source");
  progress = 0;
  CHECK(xfer_file_source_open(filename, cancel_progress, &progress, error,
                              sizeof(error)) == NULL);
  CHECK(progress == 64 * 1024 && strstr(error, "transfer cancelled") != NULL);
  path(filename, "progress");
  CHECK(xfer_file_sink_open(filename, sizeof(bytes), xfer_file_hash(src),
                            cancel_progress, &progress, error,
                            sizeof(error)) == NULL);
  CHECK(strstr(error, "transfer cancelled") != NULL);
  path(filename, "cancel");
  dst = xfer_file_sink_open(filename, sizeof(bytes), xfer_file_hash(src),
                            cancel_progress, &progress, error, sizeof(error));
  CHECK(dst != NULL);
  CHECK(!xfer_file_write(dst, 0, bytes, sizeof(bytes), error, sizeof(error)));
  CHECK(strstr(error, "transfer cancelled") != NULL);
  CHECK(xfer_file_offset(dst) == 0);
  xfer_file_close(dst);
  dst = sink("cancel", src);
  CHECK(dst != NULL && xfer_file_offset(dst) == 0);
  CHECK(xfer_file_write(dst, 0, bytes, sizeof(bytes), error, sizeof(error)));
  CHECK(xfer_file_commit(dst, error, sizeof(error)));
  xfer_file_close(dst);
  xfer_file_close(src);
}

int main(void) {
  CHECK(mkdtemp(directory) != NULL);
  for (size_t i = 0; i < sizeof(bytes); ++i)
    bytes[i] = (uint8_t)(i * 37 + 11);
  write_path("source", bytes, sizeof(bytes));
  xfer_file_t *src = source("source");
  CHECK(src != NULL && xfer_file_size(src) == sizeof(bytes));
  check_resume(src);
  check_corruption(src);
  check_path_safety(src);
  check_interrupted_install(src);
  check_empty_and_orphan();
  check_progress();
  mutate("source", 0);
  uint8_t out;
  CHECK(!xfer_file_read(src, 0, &out, 1, error, sizeof(error)));
  xfer_file_close(src);

  DIR *dir = opendir(directory);
  CHECK(dir != NULL);
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    char filename[512];
    path(filename, entry->d_name);
    CHECK(unlink(filename) == 0);
  }
  closedir(dir);
  CHECK(rmdir(directory) == 0);
  puts("===QLINQ XFER FILE OK===");
  return 0;
}
