#ifndef QLINQ_TUN_DEVICE_H
#define QLINQ_TUN_DEVICE_H

#include <stddef.h>
#include <sys/types.h>
#include "tun_segment.h"

/* display name for a local numeric address: "lo" for loopback, the transport's
 * known interface name, or device name for a unique local match; uses
 * "fallback" if unavailable or ambiguous; buffer must hold >= 64 bytes */
void tun_resolve_interface_name(const char *address, const char *interface,
                                char name[64]);

int tun_alloc(char *dev);
/* negotiate linux VNET/CSUM/TCP4/TCP6 offloads with fallback to ordinary TUN */
int tun_alloc_vnet(char *dev, bool transmit, bool *active);
ssize_t tun_write_offload(int fd, const void *data, size_t size,
                          const tun_offload_t *metadata);
ssize_t tun_read_vnet(int fd, void *data, size_t capacity,
                      tun_offload_t *metadata);
ssize_t tun_write_vnet(int fd, const void *data, size_t size);
int tun_set_mtu(const char *if_name, int mtu);
int configure_ip_and_up(const char *if_name, const char *ip_cidr);
/* linux point-to-point setup with explicit peer; routes disappear with the
 * non-persistent TUN device */
int tun_configure_peer(const char *if_name, const char *local_ip,
                       const char *peer_ip);
int tun_add_route(const char *if_name, const char *cidr);
ssize_t tun_read(int fd, void *data, size_t size);
ssize_t tun_write(int fd, const void *data, size_t size);

#endif
