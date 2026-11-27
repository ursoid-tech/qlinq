#ifndef QLINQ_AMTQ_QUICLY_H
#define QLINQ_AMTQ_QUICLY_H

#include "nanoamt/amtq_relay.h"
#include "quicly.h"

typedef struct amtq_quicly amtq_quicly;

typedef struct amtq_quicly_config {
  uint8_t server;
  uint64_t connection_id;
  nanoamtq_config gateway;
  nanoamtq_relay_config relay;
  uint32_t handshake_timeout_ms; /* 0: 10000 */
  uint32_t data_age_ms;          /* 0: 1000 */
  size_t control_buffer_bytes;   /* 0: 32768, range 8192..1048576 */
  size_t reliable_buffer_bytes;  /* 0: 256 KiB, range 65599..16 MiB */
  /* synchronous policy: install aggregate native joins before returning zero */
  int (*authorize)(void *context, uint64_t connection_id,
                   const nanoamt_memberships *candidate);
  void *authorize_context;
  void (*packet)(void *context, uint64_t connection_id, nanoamt_packet *packet);
  void *packet_context; /* packet storage is borrowed only for the callback */
} amtq_quicly_config;

typedef struct amtq_quicly_output {
  nanoamt_endpoint source, destination;
  const uint8_t *bytes; /* borrowed until consume, revocation, or free */
  size_t size;
  uint64_t serial;
  uint8_t tos; /* outer QUIC ECN marking */
} amtq_quicly_output;

typedef struct amtq_quicly_stats {
  uint64_t controls, datagrams, packets, revoked, expired, reliable_blocks;
  size_t buffered_control_bytes, buffered_reliable_bytes;
} amtq_quicly_stats;

void amtq_quicly_configure(quicly_context_t *context);
amtq_quicly *amtq_quicly_new(quicly_context_t *context,
                             const amtq_quicly_config *config, int64_t now_ms);
int amtq_quicly_bind(amtq_quicly *session, quicly_conn_t *connection);
void amtq_quicly_free(amtq_quicly *session);
quicly_conn_t *amtq_quicly_connection(amtq_quicly *session);
int amtq_quicly_set_memberships(amtq_quicly *session,
                                const nanoamtq_membership *memberships,
                                size_t count);
nanoamtq_relay *amtq_quicly_relay(amtq_quicly *session);
int amtq_quicly_memberships_submitted(const amtq_quicly *session);
int amtq_quicly_is_ready(const amtq_quicly *session);
int amtq_quicly_error(const amtq_quicly *session);
int64_t amtq_quicly_next_timeout(amtq_quicly *session);
int amtq_quicly_tick(amtq_quicly *session, int64_t now_ms);
int amtq_quicly_receive(amtq_quicly *session, int64_t now_ms,
                        const nanoamt_endpoint *peer,
                        const nanoamt_endpoint *local, uint8_t *bytes,
                        size_t size);
int amtq_quicly_receive_ecn(amtq_quicly *session, int64_t now_ms,
                            const nanoamt_endpoint *peer,
                            const nanoamt_endpoint *local, uint8_t *bytes,
                            size_t size, int outer_ecn);
int amtq_quicly_receive_decoded(amtq_quicly *session, int64_t now_ms,
                                const nanoamt_endpoint *peer,
                                const nanoamt_endpoint *local,
                                quicly_decoded_packet_t *packet);
int amtq_quicly_accepts_ip(amtq_quicly *session, int64_t now_ms,
                           const uint8_t *ip, size_t size);
int amtq_quicly_forward(amtq_quicly *session, int64_t now_ms, const uint8_t *ip,
                        size_t size);
int amtq_quicly_forward_queued(amtq_quicly *session, int64_t now_ms,
                               int64_t enqueued_at_ms, const uint8_t *ip,
                               size_t size);
int amtq_quicly_send(amtq_quicly *session, int64_t now_ms,
                     amtq_quicly_output *output);
int amtq_quicly_output_valid(amtq_quicly *session, int64_t now_ms,
                             const amtq_quicly_output *output);
void amtq_quicly_consume(amtq_quicly *session);
void amtq_quicly_get_stats(const amtq_quicly *session,
                           amtq_quicly_stats *stats);

#endif
