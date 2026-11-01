#ifndef QLINQ_TRANSPORT_DRIVE_H
#define QLINQ_TRANSPORT_DRIVE_H

#include "transport.h"
#include <sys/socket.h>
#include <sys/uio.h>

/* owner-thread, synchronous host boundary; path IDs are incarnations */
typedef struct {
  uint64_t id;
  struct sockaddr_storage local;
  socklen_t local_len;
  uint32_t interface_index;
  char interface_name[64];
} transport_drive_path_t;

typedef struct transport_drive_host {
  void *context;
  /* quicly reserves 0 ms for an unlocked clock; start >= 1 ms */
  uint64_t initial_time_ns;
  /* open may assign ephemeral port and ifindex while preserving identity/family
   */
  bool (*open)(void *context, transport_drive_path_t *path);
  void (*close)(void *context, const transport_drive_path_t *path);
  /* each iovec is a UDP datagram; group equal-size runs for GSO or send
   * individually, returning accepted prefix length (0=would block, -1=error) */
  ssize_t (*send)(void *context, const transport_drive_path_t *path,
                  const struct sockaddr *source,
                  const struct sockaddr *destination, socklen_t destination_len,
                  uint32_t interface_index, uint8_t ecn,
                  size_t max_gso_segments, const struct iovec *datagrams,
                  size_t count);
  /* host-buffered input (such as UDP GRO slices) needs an immediate turn */
  bool (*input_pending)(void *context);
  /* optional monotonic clock for compatibility APIs between turns */
  uint64_t (*monotonic_ns)(void *context);
  /* optional TLS wall clock and entropy callbacks */
  uint64_t (*wall_time_ms)(void *context);
  void (*random_bytes)(void *buffer, size_t size);
} transport_drive_host_t;

/* requires config.drive_host; time advances explicitly without rollback */
transport_t *transport_drive_create(const transport_config_t *config);
bool transport_drive_time(transport_t *t, uint64_t monotonic_ns);
bool transport_drive_tick(transport_t *t, uint64_t monotonic_ns);
/* feed one mutable datagram; native QUIC decrypts in place */
bool transport_drive_receive(transport_t *t, uint64_t path_id, void *bytes,
                             size_t size, const struct sockaddr_storage *source,
                             const struct sockaddr_storage *destination,
                             uint32_t interface_index, uint8_t ecn);
/* apply interface add/remove event to open or retire logical path */
bool transport_drive_interface(transport_t *t, bool added,
                               const struct sockaddr_storage *address,
                               uint32_t interface_index, const char *name);
size_t transport_drive_paths(transport_t *t, transport_drive_path_t *paths,
                             size_t capacity);
#endif
