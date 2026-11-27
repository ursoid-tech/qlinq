#ifndef QLINQ_TRANSPORT_AMT_HOST_H
#define QLINQ_TRANSPORT_AMT_HOST_H
#include "transport_flexicast.h"
#include "portable_sockets.h"
struct transport_amt_host;
struct transport_amt_host *transport_amt_host_new(const transport_config_t *);
void transport_amt_host_free(struct transport_amt_host *);
bool transport_amt_host_join(transport_t *, transport_flexicast_flow_t *);
void transport_amt_host_leave(transport_t *, transport_flexicast_flow_t *);
bool transport_amt_host_ready(transport_t *,
                              const transport_flexicast_flow_t *);
size_t transport_amt_host_memberships(transport_t *);
int64_t transport_amt_host_timeout(transport_t *);
size_t transport_amt_host_poll(transport_t *, struct pollfd *, size_t);
void transport_amt_host_service(transport_t *, const struct pollfd *, size_t);
#endif
