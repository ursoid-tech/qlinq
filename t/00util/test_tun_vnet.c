#include "../../src/host/linux/tun_device.h"
#include <assert.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

static unsigned opened, closed, mode, offload_calls;
static bool framing, receive_only;
static tun_offload_t expected_metadata;
static int read_mode, write_mode;

int __wrap_open(const char *path, int flags, ...) {
  (void)flags;
  assert(!strcmp(path, "/dev/net/tun"));
  return 100 + ++opened;
}
int __wrap_close(int fd) {
  assert(fd > 100);
  closed++;
  return 0;
}
int __wrap_ioctl(int fd, unsigned long request, ...) {
  assert(fd > 100);
  va_list args;
  va_start(args, request);
  if (request == TUNSETOFFLOAD) {
    unsigned flags = va_arg(args, unsigned);
    assert(receive_only ? flags == 0
                        : (flags & (TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6)) ==
                              (TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6));
    offload_calls++;
    va_end(args);
    if (mode == 2 || (mode == 3 && offload_calls == 1)) {
      errno = EOPNOTSUPP;
      return -1;
    }
    return 0;
  }
  void *value = va_arg(args, void *);
  va_end(args);
  if (request == TUNGETFEATURES) {
    *(unsigned *)value = mode == 1 ? 0 : IFF_VNET_HDR;
    return 0;
  }
  if (request == TUNSETIFF) {
    struct ifreq *ifr = value;
    framing = (ifr->ifr_flags & IFF_VNET_HDR) != 0;
    assert((ifr->ifr_flags & (IFF_TUN | IFF_NO_PI)) == (IFF_TUN | IFF_NO_PI));
    strcpy(ifr->ifr_name, "testtun0");
    return 0;
  }
  if (request == TUNSETVNETLE) {
    assert(*(int *)value == 1);
    return 0;
  }
  assert(request == TUNSETVNETHDRSZ && *(int *)value == 10);
  if (mode == 4) {
    errno = EINVAL;
    return -1;
  }
  return 0;
}
ssize_t __wrap_readv(int fd, const struct iovec *v, int count) {
  (void)fd;
  assert(count == 2 && v[0].iov_len == 10);
  uint8_t header[10] = {1, 1, 40, 0, 0x40, 5, 20, 0, 16, 0};
  memcpy(v[0].iov_base, header, 10);
  if (read_mode == 1)
    return 9;
  if (read_mode == 2) {
    errno = EAGAIN;
    return -1;
  }
  memset(v[1].iov_base, 0x45, v[1].iov_len);
  return 10 + v[1].iov_len;
}
ssize_t __wrap_writev(int fd, const struct iovec *v, int count) {
  (void)fd;
  assert(count == 2 && v[0].iov_len == 10);
  const uint8_t *header = v[0].iov_base;
  assert(header[0] == expected_metadata.flags &&
         header[1] == expected_metadata.gso_type);
  const uint16_t fields[] = {
      expected_metadata.header_length, expected_metadata.gso_size,
      expected_metadata.checksum_start, expected_metadata.checksum_offset};
  for (unsigned i = 0; i < 4; i++) {
    assert(header[2 + 2 * i] == (fields[i] & 255));
    assert(header[3 + 2 * i] == (fields[i] >> 8));
  }
  if (write_mode == 1)
    return 5;
  if (write_mode == 2) {
    errno = EAGAIN;
    return -1;
  }
  return 10 + v[1].iov_len;
}
int main(void) {
  for (mode = 0; mode <= 4; mode++) {
    opened = closed = offload_calls = 0;
    char name[16] = "testtun0";
    bool active = false;
    int fd = tun_alloc_tx_offload(name, &active);
    assert(fd > 100 && !strcmp(name, "testtun0"));
    bool supported = mode == 0 || mode == 3;
    assert(active == supported && framing == supported);
    assert(opened == (supported ? 1U : 2U) && closed == opened - 1);
    if (mode == 3)
      assert(offload_calls == 2);
    __wrap_close(fd);
    assert(opened == closed);
  }
  receive_only = true;
  mode = 0;
  char name[16] = "testtun0";
  bool active;
  int fd = tun_alloc_vnet(name, false, &active);
  assert(fd > 100 && active && framing);
  __wrap_close(fd);
  uint8_t bytes[64];
  tun_offload_t metadata;
  assert(tun_read_vnet(7, bytes, sizeof(bytes), &metadata) == 64);
  assert(metadata.flags == 1 && metadata.gso_type == 1 &&
         metadata.header_length == 40);
  assert(metadata.gso_size == 1344 && metadata.checksum_start == 20 &&
         metadata.checksum_offset == 16);
  read_mode = 1;
  assert(tun_read_vnet(7, bytes, sizeof(bytes), &metadata) == -1 &&
         errno == EBADMSG);
  read_mode = 2;
  assert(tun_read_vnet(7, bytes, sizeof(bytes), &metadata) == -1 &&
         errno == EAGAIN);
  assert(tun_write_vnet(7, bytes, sizeof(bytes)) == 64);
  expected_metadata = (tun_offload_t){.flags = 1,
                                      .gso_type = 4,
                                      .header_length = 72,
                                      .gso_size = 1344,
                                      .checksum_start = 40,
                                      .checksum_offset = 16};
  assert(tun_write_offload(7, bytes, sizeof(bytes), &expected_metadata) == 64);
  expected_metadata = (tun_offload_t){0};
  write_mode = 1;
  assert(tun_write_vnet(7, bytes, sizeof(bytes)) == 0);
  write_mode = 2;
  assert(tun_write_vnet(7, bytes, sizeof(bytes)) == -1 && errno == EAGAIN);
  puts("===TUN VNET OK===");
}
