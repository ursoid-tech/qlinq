#ifndef QLINQ_EMCON_SEND_SOCKET_H
#define QLINQ_EMCON_SEND_SOCKET_H

#include "emcon_socket.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

typedef struct qlinq_emcon_send_socket_t qlinq_emcon_send_socket_t;

typedef struct {
  uint64_t packets_sent;
  uint64_t bytes_sent;
  uint64_t pacing_delays;
  uint64_t pacing_delay_ns;
  uint64_t hard_send_errors;
} qlinq_emcon_send_stats_t;

int qlinq_emcon_send_socket_create(qlinq_emcon_send_socket_t **sender,
                                   const struct sockaddr *local_address,
                                   socklen_t local_address_len,
                                   uint64_t rate_bytes_per_second,
                                   size_t burst_bytes, uint64_t expires_at_ms);
void qlinq_emcon_send_socket_free(qlinq_emcon_send_socket_t *sender);

int qlinq_emcon_send_socket_local_address(
    const qlinq_emcon_send_socket_t *sender, struct sockaddr *address,
    socklen_t *address_len);
int qlinq_emcon_send_socket_set_destination(qlinq_emcon_send_socket_t *sender,
                                            const struct sockaddr *destination,
                                            socklen_t destination_len);

int qlinq_emcon_send_socket_send(qlinq_emcon_send_socket_t *sender,
                                 const uint8_t *packet, size_t packet_size);
qlinq_emcon_send_stats_t
qlinq_emcon_send_socket_stats(const qlinq_emcon_send_socket_t *sender);

#endif
