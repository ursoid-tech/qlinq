#ifndef QLINQ_TRANSPORT_PROBE_H
#define QLINQ_TRANSPORT_PROBE_H

#include "transport.h"
#include "quicly.h"

typedef struct {
  quicly_address_t local, remote;
  uint64_t bytes_acked;
  int64_t next_at_ms;
  uint32_t path_id;
  bool active;
} transport_probe_state_t;

void transport_probe_tick(transport_conn_t *conn, int64_t now_ms);
int64_t transport_probe_deadline(transport_conn_t *conn, int64_t now_ms);

#endif
