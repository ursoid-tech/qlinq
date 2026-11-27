#ifndef QLINQ_EMCON_SOCKET_H
#define QLINQ_EMCON_SOCKET_H

#include "emcon_manifest.h"

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

typedef bool (*qlinq_emcon_cancel_fn)(void *user_data);

typedef struct qlinq_emcon_send_socket_t qlinq_emcon_send_socket_t;
typedef struct qlinq_emcon_receive_socket_t qlinq_emcon_receive_socket_t;

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
                                   const struct sockaddr *destination,
                                   socklen_t destination_len,
                                   uint64_t rate_bytes_per_second,
                                   size_t burst_bytes, uint64_t expires_at_ms);
void qlinq_emcon_send_socket_free(qlinq_emcon_send_socket_t *sender);
void qlinq_emcon_send_socket_set_cancel(qlinq_emcon_send_socket_t *sender,
                                        qlinq_emcon_cancel_fn should_cancel,
                                        void *cancel_data);
int qlinq_emcon_send_socket_send(qlinq_emcon_send_socket_t *sender,
                                 const uint8_t *packet, size_t packet_size);
qlinq_emcon_send_stats_t
qlinq_emcon_send_socket_stats(const qlinq_emcon_send_socket_t *sender);

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
