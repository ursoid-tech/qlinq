#ifndef QLINQ_TRANSPORT_UDP_H
#define QLINQ_TRANSPORT_UDP_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/uio.h>

/* Returns the number of complete datagrams sent. On a short result, retry
 * only the unsent suffix; an error can occur after partial progress. Returns -1
 * only when no datagram was sent and a hard socket error occurred.
 * max_gso_segments is 0 for the default byte-limited grouping, or 1..64 to
 * bound logical datagrams per GSO message (1 uses ordinary UDP). Larger values
 * fail with EINVAL before any send. Non-GSO platforms keep ordinary sends. */
ssize_t transport_udp_send_batch(int fd, const struct sockaddr *destination,
                                 socklen_t destination_len,
                                 const struct iovec *datagrams, size_t count,
                                 size_t max_gso_segments);

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

/* Optional Linux socket GRO receive state. Creation allocates four 64 KiB raw
 * buffers before enabling UDP_GRO on a fresh socket; failure leaves the option
 * unchanged so callers can keep using the stateless receive path. Destruction
 * frees the state, not the socket, which must then be closed by its owner. */
typedef struct transport_udp_gro transport_udp_gro_t;
transport_udp_gro_t *transport_udp_gro_create(int fd);
void transport_udp_gro_destroy(transport_udp_gro_t *state);
bool transport_udp_gro_pending(const transport_udp_gro_t *state);

typedef struct {
  struct sockaddr_storage source;
  uint8_t *data;
  size_t size;
  bool truncated;
  bool dropped;
} transport_udp_view_t;

/* Return at most count (0..32) logical datagrams or dropped-message work units.
 * Each result consumes one receive-budget unit; dropped results must not reach
 * the decoder. Views are mutable and valid until the next call on this state.
 * No refill occurs after returning any views, so short results do not mean the
 * socket is drained: more is true when buffered data remains OR the preceding
 * raw batch filled all four buffers. pending reports only actual buffered work.
 * Empty/truncated control or payload messages cannot cause an unbounded retry.
 * Empty sockets return zero; hard errors return -1, as in receive_batch. */
ssize_t transport_udp_gro_receive(transport_udp_gro_t *state, int fd,
                                  transport_udp_view_t *views, size_t count,
                                  bool *more);

#endif
