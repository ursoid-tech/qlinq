#ifndef QLINQ_TRANSPORT_PROTOCOL_H
#define QLINQ_TRANSPORT_PROTOCOL_H

#include "transport_internal.h"

void transport_protocol_setup(transport_t *t);
void transport_protocol_receive_datagram(transport_conn_t *conn,
                                         ptls_iovec_t payload,
                                         bool allow_telemetry);
bool transport_protocol_send_hello(transport_conn_t *conn);
void transport_protocol_maybe_emit_connected(transport_conn_t *conn);

#endif
