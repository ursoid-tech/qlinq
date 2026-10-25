/* protocol error handling tests */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../../src/app/xfer.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define HEADER 16U
#define PAYLOAD_MAX (16U * 1024U)

enum { OFFER = 1, ACCEPT = 2, DATA = 3, COMMITTED = 6, PROGRESS = 9 };

static char directory[] = "/tmp/qlinq-xfer-protocol-XXXXXX";
static const char *test_case;
static app_xfer_t *active;
static const unsigned char contents[] = {0x00, 0xff, 0x11, 0x80};
static unsigned char content_hash[32], empty_hash[32];

static void fail(int line, const char *expression) {
  app_xfer_status_t status = {0};
  if (active)
    app_xfer_status(active, &status);
  fprintf(stderr, "%s: line %d: %s (protocol error: %s)\n", test_case, line,
          expression, status.error);
  exit(1);
}
#define CHECK(expression)                                                      \
  do {                                                                         \
    if (!(expression))                                                         \
      fail(__LINE__, #expression);                                             \
  } while (0)

static void cleanup(void) {
  app_xfer_destroy(active);
  active = NULL;
  DIR *dir = opendir(directory);
  if (!dir)
    return;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
      unlinkat(dirfd(dir), entry->d_name, 0);
  }
  closedir(dir);
  rmdir(directory);
}

static void path(char out[512], const char *name) {
  int length = snprintf(out, 512, "%s/%s", directory, name);
  CHECK(length > 0 && length < 512);
}

static uint64_t now_ms(void) {
  struct timespec ts;
  CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
  return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

static size_t frame(unsigned char *out, unsigned type, uint64_t offset,
                    const void *payload, size_t size) {
  memcpy(out, "QXF1", 4);
  out[4] = (unsigned char)type;
  memset(out + 5, 0, 3);
  for (unsigned i = 0; i < 8; ++i)
    out[8 + i] = (unsigned char)(offset >> (56U - 8U * i));
  if (size)
    memcpy(out + HEADER, payload, size);
  return HEADER + size;
}

static void start(const char *name, bool sender) {
  char filename[512];
  test_case = name;
  path(filename, sender ? "source" : name);
  active = app_xfer_create(sender ? filename : NULL, sender ? NULL : filename);
  CHECK(active != NULL);
  app_xfer_link(active, true);
}

static void stop(void) {
  app_xfer_destroy(active);
  active = NULL;
}

static void wait_failure(void) {
  uint64_t deadline = now_ms() + 5000;
  for (;;) {
    app_xfer_status_t status;
    app_xfer_status(active, &status);
    CHECK(!status.done);
    if (status.failed) {
      CHECK(status.error[0] != '\0');
      return;
    }
    CHECK(now_ms() < deadline);
    usleep(1000);
  }
}

static void wait_message(unsigned type) {
  uint64_t deadline = now_ms() + 5000;
  for (;;) {
    const void *data;
    size_t size;
    bool is_data;
    if (app_xfer_peek(active, &data, &size, &is_data)) {
      const unsigned char *bytes = data;
      CHECK(size >= HEADER && memcmp(bytes, "QXF1", 4) == 0);
      unsigned actual_type = bytes[4];
      CHECK(actual_type == type || actual_type == PROGRESS);
      if (actual_type == ACCEPT) {
        CHECK(size == HEADER + sizeof(empty_hash));
        CHECK(memcmp(bytes + HEADER, empty_hash, sizeof(empty_hash)) == 0);
        static const unsigned char zero_offset[8] = {0};
        CHECK(memcmp(bytes + 8, zero_offset, sizeof(zero_offset)) == 0);
      }
      app_xfer_consume(active);
      if (actual_type == type)
        return;
      continue;
    }
    app_xfer_status_t status;
    app_xfer_status(active, &status);
    CHECK(!status.failed && !status.done);
    CHECK(now_ms() < deadline);
    /* Worker output must wake an owner sleeping without a transport timer. */
    struct pollfd ready = {.fd = app_xfer_get_fd(active), .events = POLLIN};
    CHECK(poll(&ready, 1, 1000) == 1);
    CHECK(ready.revents == POLLIN);
    app_xfer_drain(active);
  }
}

static void no_destination(void) {
  char filename[512];
  path(filename, test_case);
  struct stat st;
  CHECK(lstat(filename, &st) != 0 && errno == ENOENT);
}

static void offer_to_receiver(void) {
  unsigned char record[HEADER + sizeof(content_hash)];
  size_t size = frame(record, OFFER, sizeof(contents), content_hash,
                      sizeof(content_hash));
  CHECK(app_xfer_receive(active, record, size));
  wait_message(ACCEPT);
}

static void check_malformed(void) {
  static const char *names[] = {"truncated", "bad-magic", "reserved"};
  for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    start(names[i], false);
    unsigned char record[HEADER];
    size_t size = frame(record, OFFER, 0, NULL, 0);
    if (i == 0)
      size = HEADER - 1;
    else if (i == 1)
      record[0] ^= 1;
    else
      record[5] = 1;
    CHECK(!app_xfer_receive(active, record, size));
    wait_failure();
    no_destination();
    stop();
  }
}

static void check_bad_data(void) {
  static const char *names[] = {"wrong-offset", "past-end"};
  for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    start(names[i], false);
    offer_to_receiver();
    unsigned char record[HEADER + sizeof(contents) + 1];
    const unsigned char oversized[] = {0, 0xff, 0x11, 0x80, 0x55};
    size_t size = i == 0 ? frame(record, DATA, 1, contents, 1)
                         : frame(record, DATA, 0, oversized, sizeof(oversized));
    CHECK(app_xfer_receive(active, record, size));
    wait_failure();
    no_destination();
    char name[128], filename[512];
    CHECK(snprintf(name, sizeof(name), "%s.qlinq-part", test_case) > 0);
    path(filename, name);
    struct stat st;
    CHECK(stat(filename, &st) == 0 && st.st_size == 0);
    stop();
  }
}

static void check_bad_resume(void) {
  start("invalid-resume-hash", true);
  wait_message(OFFER);
  unsigned char record[HEADER + 32], invalid_hash[32];
  memcpy(invalid_hash, empty_hash, sizeof(invalid_hash));
  invalid_hash[0] ^= 1;
  size_t size = frame(record, ACCEPT, 0, invalid_hash, sizeof(invalid_hash));
  CHECK(app_xfer_receive(active, record, size));
  wait_failure();
  const void *data;
  bool is_data;
  while (app_xfer_peek(active, &data, &size, &is_data)) {
    CHECK(!is_data);
    app_xfer_consume(active);
  }
  stop();
}

static void check_early_commit(void) {
  start("premature-committed", true);
  wait_message(OFFER);
  unsigned char record[HEADER + 32];
  size_t size = frame(record, COMMITTED, sizeof(contents), content_hash,
                      sizeof(content_hash));
  CHECK(app_xfer_receive(active, record, size));
  wait_failure();
  stop();
}

static void check_oversized_record(void) {
  start("oversized-record", false);
  unsigned char record[HEADER + PAYLOAD_MAX + 1] = {0};
  frame(record, DATA, 0, NULL, 0);
  CHECK(!app_xfer_receive(active, record, sizeof(record)));
  wait_failure();
  no_destination();
  stop();
}

static void check_streaming_finish(void) {
  for (unsigned variant = 0; variant < 3; variant++) {
    const char *names[] = {"streaming-missing-hash", "streaming-false-hash",
                           "streaming-early-finish"};
    start(names[variant], false);
    unsigned char record[HEADER + 32];
    size_t size = frame(record, 10, sizeof(contents), content_hash, 32);
    CHECK(app_xfer_receive(active, record, size));
    wait_message(ACCEPT);
    if (variant != 2) {
      size = frame(record, DATA, 0, contents, sizeof(contents));
      CHECK(app_xfer_receive(active, record, size));
    }
    unsigned char wrong[32] = {0};
    size = variant == 0 ? frame(record, 5, sizeof(contents), NULL, 0)
                        : frame(record, 11, sizeof(contents), wrong, 32);
    CHECK(app_xfer_receive(active, record, size));
    wait_failure();
    no_destination();
    stop();
  }
}

int main(void) {
  test_case = "setup";
  CHECK(mkdtemp(directory) != NULL);
  CHECK(atexit(cleanup) == 0);
  char filename[512];
  path(filename, "source");
  int fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0600);
  CHECK(fd >= 0);
  CHECK(write(fd, contents, sizeof(contents)) == (ssize_t)sizeof(contents));
  CHECK(close(fd) == 0);
  unsigned length = 0;
  CHECK(EVP_Digest(contents, sizeof(contents), content_hash, &length,
                   EVP_sha256(), NULL) == 1 &&
        length == 32);
  CHECK(EVP_Digest("", 0, empty_hash, &length, EVP_sha256(), NULL) == 1 &&
        length == 32);
  check_malformed();
  check_bad_data();
  check_bad_resume();
  check_early_commit();
  check_oversized_record();
  check_streaming_finish();
  puts("===QLINQ XFER PROTOCOL OK===");
  return 0;
}
