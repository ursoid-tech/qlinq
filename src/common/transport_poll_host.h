#ifndef QLINQ_TRANSPORT_POLL_HOST_H
#define QLINQ_TRANSPORT_POLL_HOST_H
/* private polling-host state; never included by the protocol engine */
#include "transport_internal.h"
#include "transport_udp.h"
#include "ifmon.h"
typedef struct {
  transport_drive_path_t path;
  int fd;
  transport_udp_gro_t *gro;
  bool receive_backlog;
} transport_poll_socket_t;
typedef struct {
  transport_t *transport;
  transport_poll_socket_t sockets[TRANSPORT_MAX_PATHS];
  size_t socket_count, receive_cursor;
  ifmon_watcher_t ifmon_w;
  int ifmon_pipe[2];
  bool multihome;
  transport_log_callback_t log_callback;
  void *log_user_data;
} transport_poll_host_t;
transport_drive_host_t transport_poll_host_adapter(transport_poll_host_t *host);
static inline transport_poll_host_t *transport_poll_host(transport_t *t) {
  return t ? t->host_context : NULL;
}
/* tests observing native descriptors use this host-only view */
static inline int transport_poll_fd(transport_t *t, size_t slot) {
  transport_poll_host_t *host = transport_poll_host(t);
  return host && slot < host->socket_count ? host->sockets[slot].fd : -1;
}
#endif
