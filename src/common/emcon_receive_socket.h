#ifndef QLINQ_EMCON_RECEIVE_SOCKET_H
#define QLINQ_EMCON_RECEIVE_SOCKET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

typedef struct qlinq_emcon_receive_socket_t qlinq_emcon_receive_socket_t;

typedef enum {
  QLINQ_EMCON_SOCKET_OK = 0,
  QLINQ_EMCON_SOCKET_WOULD_BLOCK = 1,
  QLINQ_EMCON_SOCKET_INVALID = -1,
  QLINQ_EMCON_SOCKET_SYSTEM = -2,
  QLINQ_EMCON_SOCKET_TOO_LARGE = -3
} qlinq_emcon_socket_result_t;

/* creates a receive socket restricted to one provisioned source with its write
 * half shut down; multicast destinations reuse address/port and optionally join
 * the group */
int qlinq_emcon_receive_socket_create_multicast(
    qlinq_emcon_receive_socket_t **receiver,
    const struct sockaddr *local_address, socklen_t local_address_len,
    const struct sockaddr *source_address, socklen_t source_address_len,
    uint32_t interface_index, bool join_group);
int qlinq_emcon_receive_socket_create(qlinq_emcon_receive_socket_t **receiver,
                                      const struct sockaddr *local_address,
                                      socklen_t local_address_len,
                                      const struct sockaddr *source_address,
                                      socklen_t source_address_len);
void qlinq_emcon_receive_socket_free(qlinq_emcon_receive_socket_t *receiver);

int qlinq_emcon_receive_socket_local_address(
    const qlinq_emcon_receive_socket_t *receiver, struct sockaddr *address,
    socklen_t *address_len);
bool qlinq_emcon_receive_socket_egress_disabled(
    const qlinq_emcon_receive_socket_t *receiver);

int qlinq_emcon_receive_socket_receive(qlinq_emcon_receive_socket_t *receiver,
                                       uint8_t *packet, size_t capacity,
                                       size_t *packet_size, bool nonblocking);

#endif
