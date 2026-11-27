#ifndef QLINQ_FS_UTIL_H
#define QLINQ_FS_UTIL_H

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

static inline int qlinq_sync_file_data(int fd) {
#if defined(__APPLE__)
  return fsync(fd);
#else
  return fdatasync(fd);
#endif
}

static inline int qlinq_pread_exact(int fd, void *buf, size_t size,
                                    off_t offset) {
  uint8_t *dst = buf;
  size_t done = 0;
  while (done < size) {
    ssize_t got = pread(fd, dst + done, size - done, offset + (off_t)done);
    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0)
      return -1;
    done += (size_t)got;
  }
  return 0;
}

static inline int qlinq_pwrite_exact(int fd, const void *buf, size_t size,
                                     off_t offset) {
  const uint8_t *src = buf;
  size_t done = 0;
  while (done < size) {
    ssize_t put = pwrite(fd, src + done, size - done, offset + (off_t)done);
    if (put < 0 && errno == EINTR)
      continue;
    if (put <= 0)
      return -1;
    done += (size_t)put;
  }
  return 0;
}

static inline int qlinq_write_exact(int fd, const void *buf, size_t size) {
  const uint8_t *src = buf;
  size_t done = 0;
  while (done < size) {
    ssize_t put = write(fd, src + done, size - done);
    if (put < 0 && errno == EINTR)
      continue;
    if (put <= 0)
      return -1;
    done += (size_t)put;
  }
  return 0;
}

static inline bool qlinq_stat_restricted_regular(int fd, bool check_owner,
                                                 bool check_nlink,
                                                 off_t *out_size) {
  struct stat info;
  if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
      (info.st_mode & (S_IRWXG | S_IRWXO)) != 0 ||
      (check_owner && info.st_uid != geteuid()) ||
      (check_nlink && info.st_nlink != 1))
    return false;
  if (out_size)
    *out_size = info.st_size;
  return true;
}

static inline int qlinq_open_restricted_file(const char *path,
                                             bool check_owner) {
  if (!path || !path[0])
    return -1;
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd >= 0 && !qlinq_stat_restricted_regular(fd, check_owner, false, NULL)) {
    close(fd);
    return -1;
  }
  return fd;
}

static inline int qlinq_open_restricted_dir(const char *path) {
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

static inline void qlinq_hex_encode(const uint8_t *src, size_t len, char *dst) {
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    dst[i * 2] = hex[src[i] >> 4];
    dst[i * 2 + 1] = hex[src[i] & 0x0f];
  }
  dst[len * 2] = '\0';
}

static inline bool qlinq_ip_is_multicast(uint8_t family, const uint8_t *addr) {
  if (!addr)
    return false;
  return family == 4 ? (addr[0] & 0xf0U) == 0xe0U
                     : (family == 6 && addr[0] == 0xffU);
}

#endif
