#ifndef QLINQ_TRANSPORT_PROTOCOL_H
#define QLINQ_TRANSPORT_PROTOCOL_H

#include "transport_internal.h"

void transport_protocol_setup(transport_t *t);
bool transport_protocol_send_hello(transport_conn_t *conn);
void transport_protocol_maybe_emit_connected(transport_conn_t *conn);

#endif
