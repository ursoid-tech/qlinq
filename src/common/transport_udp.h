#ifndef QLINQ_TRANSPORT_UDP_H
#define QLINQ_TRANSPORT_UDP_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/uio.h>

/* Returns the number of complete datagrams sent. On a short result, retry
 * only the unsent suffix; an error can occur after partial progress. Returns -1
 * only when no datagram was sent and a hard socket error occurred. */
ssize_t transport_udp_send_batch(int fd, const struct sockaddr *destination,
                                 socklen_t destination_len,
                                 const struct iovec *datagrams, size_t count);

#define TRANSPORT_UDP_RECEIVE_BATCH 32U
#define TRANSPORT_UDP_RECEIVE_SIZE 2048U

typedef struct {
  struct sockaddr_storage source;
  size_t size;
  bool truncated;
  uint8_t data[TRANSPORT_UDP_RECEIVE_SIZE];
} transport_udp_datagram_t;

/* Nonblocking receive of at most 32 datagrams. Empty/truncated datagrams count
 * as progress. EINTR is retried; return 0 for an empty socket and -1 for a hard
 * error. size counts copied bytes; truncated marks a clipped payload. */
ssize_t transport_udp_receive_batch(int fd, transport_udp_datagram_t *datagrams,
                                    size_t count);

#endif
