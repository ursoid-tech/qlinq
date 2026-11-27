#ifndef QLINQ_EMCON_RECEIVE_SOCKET_H
#define QLINQ_EMCON_RECEIVE_SOCKET_H

#include "emcon_socket.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

typedef struct qlinq_emcon_receive_socket_t qlinq_emcon_receive_socket_t;

/* restricts UDP reception to source and optional local interface;
 * join_group=false requires an explicit interface and preprovisioned group */
int qlinq_emcon_receive_socket_create_multicast(
    qlinq_emcon_receive_socket_t **receiver,
    const struct sockaddr *local_address, socklen_t local_address_len,
    const struct sockaddr *source_address, socklen_t source_address_len,
    uint32_t interface_index, bool join_group);
void qlinq_emcon_receive_socket_free(qlinq_emcon_receive_socket_t *receiver);

void qlinq_emcon_receive_socket_set_cancel(
    qlinq_emcon_receive_socket_t *receiver, qlinq_emcon_cancel_fn should_cancel,
    void *cancel_data);
int qlinq_emcon_receive_socket_receive(qlinq_emcon_receive_socket_t *receiver,
                                       uint8_t *packet, size_t capacity,
                                       size_t *packet_size, bool nonblocking,
                                       uint64_t expires_at_ms);

#endif
