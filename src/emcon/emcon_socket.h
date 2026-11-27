#ifndef QLINQ_EMCON_SOCKET_H
#define QLINQ_EMCON_SOCKET_H

#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

typedef enum {
  QLINQ_EMCON_SOCKET_OK = 0,
  QLINQ_EMCON_SOCKET_WOULD_BLOCK = 1,
  QLINQ_EMCON_SOCKET_INVALID = -1,
  QLINQ_EMCON_SOCKET_SYSTEM = -2,
  QLINQ_EMCON_SOCKET_TOO_LARGE = -3,
  QLINQ_EMCON_SOCKET_EXPIRED = -4,
  QLINQ_EMCON_SOCKET_INTERRUPTED = -5
} qlinq_emcon_socket_result_t;

typedef bool (*qlinq_emcon_cancel_fn)(void *user_data);

#define QLINQ_EMCON_WAIT_SLICE_MS 50

static inline bool qlinq_emcon_sockaddr_valid(const struct sockaddr *address,
                                              socklen_t length) {
  if (!address)
    return false;
  if (address->sa_family == AF_INET)
    return length >= sizeof(struct sockaddr_in);
  if (address->sa_family == AF_INET6)
    return length >= sizeof(struct sockaddr_in6);
  return false;
}

static inline uint64_t qlinq_emcon_realtime_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_REALTIME, &now) != 0)
    return 0;
  return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static inline int qlinq_emcon_socket_wait(int fd, short events,
                                          uint64_t expires_at_ms,
                                          qlinq_emcon_cancel_fn should_cancel,
                                          void *cancel_data) {
  struct pollfd descriptor = {.fd = fd, .events = events};
  for (;;) {
    if (should_cancel && should_cancel(cancel_data))
      return QLINQ_EMCON_SOCKET_INTERRUPTED;
    uint64_t now = qlinq_emcon_realtime_ms();
    if (!now)
      return QLINQ_EMCON_SOCKET_SYSTEM;
    if (now >= expires_at_ms)
      return QLINQ_EMCON_SOCKET_EXPIRED;
    uint64_t remaining = expires_at_ms - now;
    int timeout_ms = remaining > INT_MAX ? INT_MAX : (int)remaining;
    if (should_cancel && timeout_ms > QLINQ_EMCON_WAIT_SLICE_MS)
      timeout_ms = QLINQ_EMCON_WAIT_SLICE_MS;
    int ret = poll(&descriptor, 1, timeout_ms);
    if (ret > 0) {
      if (should_cancel && should_cancel(cancel_data))
        return QLINQ_EMCON_SOCKET_INTERRUPTED;
      return QLINQ_EMCON_SOCKET_OK;
    }
    if (ret < 0) {
      if (errno == EINTR) {
        if (should_cancel && should_cancel(cancel_data))
          return QLINQ_EMCON_SOCKET_INTERRUPTED;
        continue;
      }
      return QLINQ_EMCON_SOCKET_SYSTEM;
    }
  }
}

#endif
