#ifndef QLINQ_AMTQ_POSIX_H
#define QLINQ_AMTQ_POSIX_H

#include "amtq_quicly.h"

#define AMTQ_DEFAULT_PORT 2269U

typedef struct amtq_posix amtq_posix;

enum { AMTQ_ERROR_IO = -10 };

typedef struct amtq_posix_config {
  uint8_t server;
  nanoamt_endpoint listen, peer;
  const char *certificate, *private_key, *ca_file, *server_name;
  uint8_t require_client_certificate;
  uint8_t allow_insecure_peer;       /* test-only client certificate bypass */
  unsigned max_connections;          /* server 0: 64, max 1024; client 1 */
  unsigned max_connections_per_ip;   /* 0: min(16, max_connections) */
  unsigned admission_rate;           /* new handshakes/sec; 0: 20 */
  unsigned admission_burst;          /* 0: 32 */
  unsigned send_budget;              /* 0: 64, max 4096 */
  unsigned data_queue_packets;       /* per peer, 0: 128, max 1024 */
  size_t data_queue_bytes;           /* per peer, 0: 256 KiB, max 16 MiB */
  size_t aggregate_data_queue_bytes; /* total, 0: 16 MiB, max 64 MiB */
  uint32_t close_grace_ms;           /* 0: 3000 */
  amtq_quicly_config session;
  nanoamt_membership_config aggregate;
  int (*extra_snapshot)(void *context, int64_t now_ms,
                        nanoamt_memberships **snapshot);
  void *extra_context;
  int (*authorize)(void *context, const nanoamt_memberships *aggregate);
  void *authorize_context;
} amtq_posix_config;

typedef struct amtq_posix_stats {
  uint64_t received, ignored, admitted, admission_dropped, session_errors;
  uint64_t sent, send_errors, backpressure, input_dropped, policy_errors;
  uint64_t datagrams, reliable_blocks;
  size_t connections, buffered_input_packets, buffered_input_bytes;
} amtq_posix_stats;

amtq_posix *amtq_posix_open(const amtq_posix_config *config, int64_t now_ms);
void amtq_posix_close(amtq_posix *io);
int amtq_posix_fd(const amtq_posix *io);
void amtq_posix_bound(const amtq_posix *io, nanoamt_endpoint *endpoint);
int amtq_posix_receive(amtq_posix *io, int64_t now_ms);
int amtq_posix_send(amtq_posix *io, int64_t now_ms);
int amtq_posix_tick(amtq_posix *io, int64_t now_ms);
int amtq_posix_shutdown(amtq_posix *io, int64_t now_ms);
int64_t amtq_posix_next_timeout(amtq_posix *io);
int amtq_posix_wants_write(const amtq_posix *io);
int amtq_posix_set_memberships(amtq_posix *io,
                               const nanoamtq_membership *memberships,
                               size_t count);
int amtq_posix_memberships_submitted(const amtq_posix *io);
int amtq_posix_is_ready(const amtq_posix *io);
int amtq_posix_error(const amtq_posix *io);
int amtq_posix_forward(amtq_posix *io, int64_t now_ms, const uint8_t *ip,
                       size_t size);
int amtq_posix_snapshot(amtq_posix *io, int64_t now_ms,
                        nanoamt_memberships **snapshot);
void amtq_posix_get_stats(const amtq_posix *io, amtq_posix_stats *stats);

#endif
