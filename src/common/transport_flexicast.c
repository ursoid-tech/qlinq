#include "transport_flexicast.h"

#include "portable_sockets.h"
#include "transport_internal.h"
#include "transport_publish.h"
#include "transport_stream.h"

#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "quicly/sendstate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t find_interface_index(transport_t *t, int family,
                                     const void *address) {
  const transport_flexicast_io_t *io = t->drive_host.flexicast_io;
  if (!io || !io->interface_index)
    return 0;
  bool active = t->host_callback_active;
  t->host_callback_active = true;
  uint32_t index = io->interface_index(family, address);
  t->host_callback_active = active;
  return index;
}

static int change_source_group(transport_t *t, int fd, uint8_t version,
                               const uint8_t *source, const uint8_t *group,
                               uint32_t index, bool join) {
  const transport_flexicast_io_t *io = t->drive_host.flexicast_io;
  if (!io || !io->membership)
    return -1;
  bool active = t->host_callback_active;
  t->host_callback_active = true;
  int result = io->membership(t, fd, version, source, group, index, join);
  t->host_callback_active = active;
  return result;
}

static int open_receive_socket(transport_t *t, uint8_t version, uint16_t port) {
  const transport_flexicast_io_t *io = t->drive_host.flexicast_io;
  if (!io || !io->open)
    return -1;
  bool active = t->host_callback_active;
  t->host_callback_active = true;
  int fd = io->open(version, port);
  t->host_callback_active = active;
  return fd;
}

void transport_flexicast_close_socket(transport_t *t, int fd) {
  const transport_flexicast_io_t *io = t->drive_host.flexicast_io;
  if (fd >= 0 && io && io->close) {
    bool active = t->host_callback_active;
    t->host_callback_active = true;
    io->close(fd);
    t->host_callback_active = active;
  }
}

ssize_t transport_flexicast_receive_native(transport_t *t, size_t slot,
                                           uint8_t *packet, size_t capacity,
                                           transport_conn_t **source,
                                           ptls_iovec_t *payload) {
  if (!t || !t->drive_host.flexicast_io ||
      !t->drive_host.flexicast_io->receive) {
    errno = ENOTSUP;
    return -1;
  }
  bool active = t->host_callback_active;
  t->host_callback_active = true;
  ssize_t received = t->drive_host.flexicast_io->receive(
      t, slot, packet, capacity, source, payload);
  t->host_callback_active = active;
  return received;
}

static bool admit_member_transition(transport_t *, transport_flexicast_flow_t *,
                                    transport_flexicast_member_t *, int64_t);

static bool ipv4_is_multicast(const uint8_t *address) {
  uint32_t value;
  memcpy(&value, address, sizeof(value));
  return IN_MULTICAST(ntohl(value));
}

static bool ipv6_is_ssm(const uint8_t *address) {
  uint8_t scope = address[1] & 0x0fU;
  return address[0] == 0xffU && (address[1] & 0xf0U) == 0x30U &&
         address[2] == 0 && address[3] == 0 &&
         (scope == 1 || scope == 2 || scope == 3 || scope == 4 || scope == 5 ||
          scope == 8 || scope == 14);
}

static bool ipv6_is_multicast(const uint8_t *address) {
  struct in6_addr value;
  memcpy(&value, address, sizeof(value));
  return IN6_IS_ADDR_MULTICAST(&value);
}

static bool ipv6_is_unicast_source(const uint8_t *address) {
  struct in6_addr value;
  memcpy(&value, address, sizeof(value));
  return !IN6_IS_ADDR_UNSPECIFIED(&value) && !IN6_IS_ADDR_MULTICAST(&value);
}

static size_t ip_address_size(uint8_t ip_version) {
  return ip_version == 4 ? 4U : ip_version == 6 ? 16U : 0U;
}

static size_t ip_version_slot(uint8_t ip_version) {
  return ip_version == 4 ? 0U : ip_version == 6 ? 1U : SIZE_MAX;
}

static transport_flexicast_flow_t *find_flow(transport_t *t, uint64_t flow_id) {
  if (!t || flow_id == 0)
    return NULL;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (flow->active && flow->flow_id == flow_id)
      return flow;
  }
  return NULL;
}

static transport_flexicast_flow_t *alloc_flow(transport_t *t) {
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active) {
      memset(flow, 0, sizeof(*flow));
      flow->active = true;
      flow->member_capacity = t->flexicast.member_capacity;
      flow->data_queue.capacity = TRANSPORT_FLEXICAST_QUEUE_CAPACITY;
      return flow;
    }
  }
  return NULL;
}

static bool retired_flow_epoch(const transport_t *t, uint64_t flow_id,
                               uint32_t *epoch) {
  for (size_t i = 0; i < t->flexicast_retired_flow_count; i++) {
    if (t->flexicast_retired_flow_ids[i] == flow_id) {
      if (epoch)
        *epoch = t->flexicast_retired_flow_epochs[i];
      return true;
    }
  }
  return false;
}

static void retire_flow_id(transport_t *t, uint64_t flow_id, uint32_t epoch) {
  if (!t)
    return;
  for (size_t i = 0; i < t->flexicast_retired_flow_count; i++) {
    if (t->flexicast_retired_flow_ids[i] != flow_id)
      continue;
    if (epoch > t->flexicast_retired_flow_epochs[i])
      t->flexicast_retired_flow_epochs[i] = epoch;
    return;
  }
  size_t slot = t->flexicast_retired_flow_next;
  t->flexicast_retired_flow_ids[slot] = flow_id;
  t->flexicast_retired_flow_epochs[slot] = epoch;
  t->flexicast_retired_flow_next = (slot + 1U) % TRANSPORT_FLEXICAST_MAX_FLOWS;
  if (t->flexicast_retired_flow_count < TRANSPORT_FLEXICAST_MAX_FLOWS)
    t->flexicast_retired_flow_count++;
}

static void dispose_flow(transport_flexicast_flow_t *flow) {
  if (!flow)
    return;
  (void)tf_clear_flow_queue(flow);
  tf_queue_dispose(&flow->data_queue);
  quicly_flexicast_flow_free(flow->crypto);
  free(flow->members);
  free(flow->member_map);
  ptls_clear_memory(flow->secret, sizeof(flow->secret));
  memset(flow, 0, sizeof(*flow));
}

static bool create_crypto_with_secret(transport_t *t,
                                      transport_flexicast_flow_t *flow,
                                      const uint8_t *secret,
                                      uint64_t first_packet_number,
                                      quicly_flexicast_flow_t **crypto) {
  quicly_flexicast_config_t config = {
      .flow_id = flow->flow_id,
      .max_packet_size = flow->cc_config.maximum_datagram_size != 0
                             ? flow->cc_config.maximum_datagram_size
                             : QUICLY_FLEXICAST_MAX_PACKET_SIZE,
      .first_packet_number = first_packet_number,
      .cipher_suite = &ptls_openssl_aes128gcmsha256,
      .crypto_engine = &quicly_default_crypto_engine,
      .crypto_conn = NULL,
      .traffic_secret =
          ptls_iovec_init(secret, TRANSPORT_FLEXICAST_SECRET_SIZE),
      .max_members = flow->source ? flow->member_capacity : 1,
      .cc_type = flow->source ? &quicly_flexicast_cc_type_multicast : NULL,
      .cc_config = flow->cc_config,
      .ack_delay_msec = flow->ack_delay_msec != 0
                            ? flow->ack_delay_msec
                            : QUICLY_DEFAULT_MAX_ACK_DELAY,
      .now = transport_now_ms(t)};
  return quicly_flexicast_flow_create(crypto, &config) == QUICLY_FLEXICAST_OK;
}

static bool create_crypto(transport_t *t, transport_flexicast_flow_t *flow,
                          uint64_t first_packet_number) {
  return create_crypto_with_secret(t, flow, flow->secret, first_packet_number,
                                   &flow->crypto);
}

bool transport_flexicast_registry_init(transport_flexicast_registry_t *registry,
                                       size_t capacity,
                                       size_t member_capacity) {
  if (!registry || capacity == 0 || capacity > TRANSPORT_FLEXICAST_MAX_FLOWS ||
      member_capacity == 0 ||
      member_capacity > QUICLY_FLEXICAST_HARD_MAX_MEMBERS)
    return false;
  memset(registry, 0, sizeof(*registry));
  registry->flows = calloc(capacity, sizeof(*registry->flows));
  registry->memberships = calloc(capacity, sizeof(*registry->memberships));
  if (!registry->flows || !registry->memberships) {
    free(registry->flows);
    free(registry->memberships);
    memset(registry, 0, sizeof(*registry));
    return false;
  }
  registry->capacity = capacity;
  registry->member_capacity = member_capacity;
  return true;
}

static void registry_destroy(transport_flexicast_registry_t *registry) {
  if (!registry)
    return;
  for (size_t i = 0; i < registry->capacity; i++)
    dispose_flow(&registry->flows[i]);
  free(registry->flows);
  free(registry->memberships);
  memset(registry, 0, sizeof(*registry));
}

bool transport_flexicast_configure(transport_t *t, const char *group,
                                   uint16_t port, const char *interface) {
  if (!t)
    return false;
  if (!t->flexicast_enabled)
    return !group && port == 0 && !interface;

  if (interface) {
    if (inet_pton(AF_INET, interface, &t->flexicast_interface_v4) == 1) {
      t->flexicast_interface_family = AF_INET;
      t->flexicast_interface_index =
          find_interface_index(t, AF_INET, &t->flexicast_interface_v4);
    } else if (inet_pton(AF_INET6, interface, &t->flexicast_interface_v6) ==
               1) {
      t->flexicast_interface_family = AF_INET6;
      t->flexicast_interface_index =
          find_interface_index(t, AF_INET6, &t->flexicast_interface_v6);
    } else {
      fprintf(stderr, "transport: invalid Flexicast interface address: %s\n",
              interface);
      return false;
    }
    t->flexicast_interface_set = true;
  }

  if (!group && port == 0)
    return true;
  if (!t->is_server || !group || port == 0 || !interface) {
    fprintf(stderr,
            "transport: native Flexicast sources require group, port, and "
            "interface\n");
    return false;
  }

  int family;
  if (strchr(group, ':')) {
    struct sockaddr_in6 *destination =
        (struct sockaddr_in6 *)&t->flexicast_group_addr;
    destination->sin6_family = AF_INET6;
    destination->sin6_port = htons(port);
    if (inet_pton(AF_INET6, group, &destination->sin6_addr) != 1 ||
        !ipv6_is_ssm(destination->sin6_addr.s6_addr)) {
      fprintf(stderr, "transport: invalid IPv6 SSM group: %s\n", group);
      return false;
    }
    destination->sin6_scope_id = t->flexicast_interface_index;
    family = AF_INET6;
  } else {
    struct sockaddr_in *destination =
        (struct sockaddr_in *)&t->flexicast_group_addr;
    destination->sin_family = AF_INET;
    destination->sin_port = htons(port);
    if (inet_pton(AF_INET, group, &destination->sin_addr) != 1 ||
        (ntohl(destination->sin_addr.s_addr) & 0xff000000U) != 0xe8000000U) {
      fprintf(stderr, "transport: invalid IPv4 SSM group: %s\n", group);
      return false;
    }
    family = AF_INET;
  }
  if (family != t->flexicast_interface_family ||
      (family == AF_INET &&
       t->flexicast_interface_v4.s_addr == htonl(INADDR_ANY)) ||
      (family == AF_INET6 &&
       (IN6_IS_ADDR_UNSPECIFIED(&t->flexicast_interface_v6) ||
        IN6_IS_ADDR_MULTICAST(&t->flexicast_interface_v6) ||
        t->flexicast_interface_index == 0))) {
    fprintf(stderr,
            "transport: a native Flexicast source needs a concrete local "
            "interface address matching the group family\n");
    return false;
  }
  bool usable_socket = false;
  for (size_t i = 0; i < t->socket_count; i++) {
    if (t->sockets[i].local_addr.ss_family != family)
      continue;
    bool matches;
    if (family == AF_INET) {
      const struct sockaddr_in *local =
          (const struct sockaddr_in *)&t->sockets[i].local_addr;
      matches = local->sin_addr.s_addr == htonl(INADDR_ANY) ||
                local->sin_addr.s_addr == t->flexicast_interface_v4.s_addr;
    } else {
      const struct sockaddr_in6 *local =
          (const struct sockaddr_in6 *)&t->sockets[i].local_addr;
      matches = IN6_IS_ADDR_UNSPECIFIED(&local->sin6_addr) ||
                memcmp(&local->sin6_addr, &t->flexicast_interface_v6,
                       sizeof(local->sin6_addr)) == 0;
    }
    if (matches) {
      usable_socket = true;
      /* concrete bind matching multicast interface shares physical index */
      bool concrete =
          family == AF_INET
              ? ((const struct sockaddr_in *)&t->sockets[i].local_addr)
                        ->sin_addr.s_addr != htonl(INADDR_ANY)
              : !IN6_IS_ADDR_UNSPECIFIED(
                    &((const struct sockaddr_in6 *)&t->sockets[i].local_addr)
                         ->sin6_addr);
      if (concrete && t->flexicast_interface_index != 0)
        t->sockets[i].interface_index = t->flexicast_interface_index;
      break;
    }
  }
  if (!usable_socket) {
    fprintf(stderr,
            "transport: no UDP socket matching the Flexicast address family "
            "can use the configured interface\n");
    return false;
  }
  t->flexicast_native_source = true;
  return true;
}

static transport_flexicast_membership_t *
find_membership(transport_t *t, uint8_t ip_version, const uint8_t *source,
                const uint8_t *group, uint16_t port, uint32_t interface_index) {
  size_t address_len = ip_address_size(ip_version);
  if (address_len == 0)
    return NULL;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_membership_t *membership = &t->flexicast.memberships[i];
    if (membership->active && membership->ip_version == ip_version &&
        membership->udp_port == port &&
        membership->interface_index == interface_index &&
        memcmp(membership->source_ip, source, address_len) == 0 &&
        memcmp(membership->group_ip, group, address_len) == 0)
      return membership;
  }
  return NULL;
}

static transport_flexicast_membership_t *
allocate_membership(transport_t *t, const uint8_t *source, const uint8_t *group,
                    uint8_t ip_version, uint16_t port,
                    uint32_t interface_index) {
  size_t address_len = ip_address_size(ip_version);
  if (address_len == 0)
    return NULL;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_membership_t *membership = &t->flexicast.memberships[i];
    if (!membership->active) {
      membership->active = true;
      membership->ip_version = ip_version;
      memcpy(membership->source_ip, source, address_len);
      memcpy(membership->group_ip, group, address_len);
      membership->udp_port = port;
      membership->interface_index = interface_index;
      membership->references = 1;
      return membership;
    }
  }
  return NULL;
}

static bool any_memberships(const transport_t *t, uint8_t ip_version) {
  for (size_t i = 0; i < t->flexicast.capacity; i++)
    if (t->flexicast.memberships[i].active &&
        t->flexicast.memberships[i].ip_version == ip_version)
      return true;
  return false;
}

static void release_membership(transport_t *t,
                               transport_flexicast_flow_t *flow) {
  if (!t || !flow || !flow->membership_acquired)
    return;
  transport_flexicast_membership_t *membership =
      find_membership(t, flow->ip_version, flow->source_ip, flow->group_ip,
                      flow->udp_port, flow->interface_index);
  flow->membership_acquired = false;
  if (!membership || membership->references == 0)
    return;
  if (--membership->references != 0)
    return;

  size_t slot = ip_version_slot(membership->ip_version);
  int fd = slot != SIZE_MAX ? t->flexicast_fds[slot] : -1;
  int result =
      fd >= 0 ? change_source_group(t, fd, membership->ip_version,
                                    membership->source_ip, membership->group_ip,
                                    membership->interface_index, false)
              : -1;
  if (fd >= 0) {
    if (result != 0)
      fprintf(stderr, "transport: unable to leave Flexicast group: %s\n",
              strerror(SOCKET_ERROR_CODE));
    else
      t->stats.flexicast_membership_leaves++;
  }
  uint8_t ip_version = membership->ip_version;
  memset(membership, 0, sizeof(*membership));
  if (slot != SIZE_MAX && t->flexicast_fds[slot] >= 0 &&
      !any_memberships(t, ip_version)) {
    transport_flexicast_close_socket(t, t->flexicast_fds[slot]);
    t->flexicast_fds[slot] = -1;
    t->flexicast_receive_ports[slot] = 0;
  }
}

static void release_flow(transport_t *t, transport_flexicast_flow_t *flow) {
  release_membership(t, flow);
  dispose_flow(flow);
}

void transport_flexicast_dispose(transport_t *t) {
  if (!t)
    return;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (flow->active)
      release_flow(t, flow);
  }
  registry_destroy(&t->flexicast);
}

static bool
join_announced_group(transport_t *t, transport_flexicast_flow_t *flow,
                     const quicly_flexicast_announce_frame_t *announce) {
  size_t address_len = ip_address_size(announce->ip_version);
  if (address_len == 0 || announce->udp_port == 0)
    return false;
  uint32_t interface_index =
      t->flexicast_interface_set &&
              ((announce->ip_version == 4 &&
                t->flexicast_interface_family == AF_INET) ||
               (announce->ip_version == 6 &&
                t->flexicast_interface_family == AF_INET6))
          ? t->flexicast_interface_index
          : 0;
  if (flow->membership_acquired && flow->ip_version == announce->ip_version &&
      flow->udp_port == announce->udp_port &&
      flow->interface_index == interface_index &&
      memcmp(flow->source_ip, announce->source_ip, address_len) == 0 &&
      memcmp(flow->group_ip, announce->group_ip, address_len) == 0)
    return true;
  release_membership(t, flow);
  flow->ip_version = announce->ip_version;
  flow->interface_index = interface_index;
  memcpy(flow->source_ip, announce->source_ip, address_len);
  memcpy(flow->group_ip, announce->group_ip, address_len);
  flow->udp_port = announce->udp_port;

  bool multicast = announce->ip_version == 4
                       ? ipv4_is_multicast(announce->group_ip)
                       : ipv6_is_multicast(announce->group_ip);
  if (!multicast)
    return true; /* replicated-unicast profile */
  if ((announce->ip_version == 4 && (announce->source_ip[0] == 0 ||
                                     ipv4_is_multicast(announce->source_ip))) ||
      (announce->ip_version == 6 &&
       !ipv6_is_unicast_source(announce->source_ip))) {
    fprintf(stderr, "transport: announced Flexicast source is not unicast\n");
    return false;
  }
  if ((announce->ip_version == 4 && announce->group_ip[0] != 232U) ||
      (announce->ip_version == 6 && !ipv6_is_ssm(announce->group_ip))) {
    fprintf(stderr, "transport: announced group is outside the SSM range\n");
    return false;
  }

  /* reject when configured interface is missing or family-mismatched */
  if (t->flexicast_interface_set &&
      (interface_index == 0 ||
       t->flexicast_interface_family !=
           (announce->ip_version == 4 ? AF_INET : AF_INET6)))
    return false;
  size_t slot = ip_version_slot(announce->ip_version);
  if (slot >= 2)
    return false;
  bool created = false;
  if (t->flexicast_fds[slot] < 0) {
    int fd = open_receive_socket(t, announce->ip_version, announce->udp_port);
    if (fd < 0)
      return false;
    t->flexicast_fds[slot] = fd;
    t->flexicast_receive_ports[slot] = announce->udp_port;
    created = true;
  } else if (t->flexicast_receive_ports[slot] != announce->udp_port) {
    fprintf(stderr,
            "transport: one address family cannot join Flexicast groups on "
            "different UDP ports\n");
    return false;
  }

  transport_flexicast_membership_t *existing =
      find_membership(t, announce->ip_version, announce->source_ip,
                      announce->group_ip, announce->udp_port, interface_index);
  if (!existing) {
    if (change_source_group(t, t->flexicast_fds[slot], announce->ip_version,
                            announce->source_ip, announce->group_ip,
                            interface_index, true) != 0) {
      fprintf(stderr, "transport: unable to join Flexicast group: %s\n",
              strerror(SOCKET_ERROR_CODE));
      if (created) {
        transport_flexicast_close_socket(t, t->flexicast_fds[slot]);
        t->flexicast_fds[slot] = -1;
        t->flexicast_receive_ports[slot] = 0;
      }
      return false;
    }
    t->stats.flexicast_membership_joins++;
    if (!allocate_membership(t, announce->source_ip, announce->group_ip,
                             announce->ip_version, announce->udp_port,
                             interface_index)) {
      (void)change_source_group(t, t->flexicast_fds[slot], announce->ip_version,
                                announce->source_ip, announce->group_ip,
                                interface_index, false);
      return false;
    }
  } else {
    existing->references++;
  }
  flow->membership_acquired = true;
  flow->native_multicast = true;
  return true;
}

#define FLEXICAST_MEMBER_MAP_EMPTY 0U
#define FLEXICAST_MEMBER_MAP_OCCUPIED 1U

static uintptr_t member_pointer_hash(const transport_conn_t *conn) {
  uintptr_t value = (uintptr_t)conn;
  value ^= value >> 17;
  value *= (uintptr_t)UINT64_C(0xed5ad4bb);
  return value ^ (value >> 11);
}

static bool member_table_init(transport_flexicast_flow_t *flow) {
  if (flow->members)
    return true;
  if (flow->member_capacity == 0 || flow->member_capacity > SIZE_MAX / 2U)
    return false;
  size_t map_capacity = 2;
  size_t required_capacity = flow->member_capacity * 2U;
  while (map_capacity < required_capacity) {
    if (map_capacity > SIZE_MAX / 2U)
      return false;
    map_capacity *= 2U;
  }
  flow->members = calloc(flow->member_capacity, sizeof(*flow->members));
  flow->member_map = calloc(map_capacity, sizeof(*flow->member_map));
  if (!flow->members || !flow->member_map) {
    free(flow->members);
    free(flow->member_map);
    flow->members = NULL;
    flow->member_map = NULL;
    return false;
  }
  flow->member_map_capacity = map_capacity;
  return true;
}

static bool member_map_find(const transport_flexicast_flow_t *flow,
                            const transport_conn_t *conn, size_t *slot) {
  if (!flow->member_map)
    return false;
  size_t index = member_pointer_hash(conn) & (flow->member_map_capacity - 1U);
  for (size_t probe = 0; probe < flow->member_map_capacity; probe++) {
    const transport_flexicast_member_map_entry_t *entry =
        &flow->member_map[index];
    if (entry->state == FLEXICAST_MEMBER_MAP_EMPTY)
      return false;
    if (entry->state == FLEXICAST_MEMBER_MAP_OCCUPIED && entry->conn == conn) {
      *slot = entry->slot;
      return true;
    }
    index = (index + 1U) & (flow->member_map_capacity - 1U);
  }
  return false;
}

static bool member_map_insert(transport_flexicast_flow_t *flow,
                              const transport_conn_t *conn, size_t slot) {
  size_t mask = flow->member_map_capacity - 1U;
  size_t index = member_pointer_hash(conn) & mask;
  for (size_t probe = 0; probe < flow->member_map_capacity; probe++) {
    transport_flexicast_member_map_entry_t *entry = &flow->member_map[index];
    if (entry->state == FLEXICAST_MEMBER_MAP_EMPTY) {
      *entry = (transport_flexicast_member_map_entry_t){
          .conn = conn, .slot = slot, .state = FLEXICAST_MEMBER_MAP_OCCUPIED};
      return true;
    }
    if (entry->conn == conn)
      return false;
    index = (index + 1U) & mask;
  }
  return false;
}

static void member_map_remove(transport_flexicast_flow_t *flow,
                              const transport_conn_t *conn) {
  size_t mask = flow->member_map_capacity - 1U;
  size_t hole = member_pointer_hash(conn) & mask;
  for (size_t probe = 0; probe < flow->member_map_capacity; probe++) {
    if (flow->member_map[hole].state == FLEXICAST_MEMBER_MAP_EMPTY)
      return;
    if (flow->member_map[hole].conn == conn) {
      /* close probe chain without leaving tombstones */
      size_t index = (hole + 1U) & mask;
      for (size_t moved = 0; moved + 1U < flow->member_map_capacity; moved++) {
        if (flow->member_map[index].state == FLEXICAST_MEMBER_MAP_EMPTY)
          break;
        size_t home = member_pointer_hash(flow->member_map[index].conn) & mask;
        if (((hole - home) & mask) < ((index - home) & mask)) {
          flow->member_map[hole] = flow->member_map[index];
          hole = index;
        }
        index = (index + 1U) & mask;
      }
      flow->member_map[hole] = (transport_flexicast_member_map_entry_t){0};
      return;
    }
    hole = (hole + 1U) & mask;
  }
}

static void member_map_update(transport_flexicast_flow_t *flow,
                              const transport_conn_t *conn, size_t slot) {
  size_t mask = flow->member_map_capacity - 1U;
  size_t index = member_pointer_hash(conn) & mask;
  for (size_t probe = 0; probe < flow->member_map_capacity; probe++) {
    transport_flexicast_member_map_entry_t *entry = &flow->member_map[index];
    if (entry->state == FLEXICAST_MEMBER_MAP_EMPTY)
      return;
    if (entry->conn == conn) {
      entry->slot = slot;
      return;
    }
    index = (index + 1U) & mask;
  }
}

static transport_flexicast_member_t *
member_find(transport_flexicast_flow_t *flow, const transport_conn_t *conn) {
  size_t slot;
  return flow && conn && member_map_find(flow, conn, &slot)
             ? &flow->members[slot]
             : NULL;
}

static transport_flexicast_member_t *
member_add(transport_flexicast_flow_t *flow, transport_conn_t *conn) {
  transport_flexicast_member_t *member = member_find(flow, conn);
  if (member)
    return member;
  if (!flow || !conn || flow->member_count == flow->member_capacity ||
      !member_table_init(flow) ||
      !member_map_insert(flow, conn, flow->member_count))
    return NULL;
  member = &flow->members[flow->member_count++];
  member->conn = conn;
  return member;
}

static void recount_member_feedback(transport_flexicast_flow_t *flow) {
  flow->listening_count = 0;
  flow->feedback_outstanding_count = 0;
  for (size_t i = 0; i < flow->member_count; i++) {
    const transport_flexicast_member_t *member = &flow->members[i];
    if (!member->listening)
      continue;
    flow->listening_count++;
    if (member->acknowledged_delivery_epoch < flow->delivery_epoch)
      flow->feedback_outstanding_count++;
  }
}

static void set_member_listening(transport_flexicast_flow_t *flow,
                                 transport_flexicast_member_t *member,
                                 bool listening) {
  if (member->listening == listening)
    return;
  bool inconsistent = false;
  if (listening) {
    flow->listening_count++;
    member->acknowledged_delivery_epoch = flow->delivery_epoch;
    member->first_unacknowledged_ms = 0;
  } else {
    if (flow->listening_count == 0)
      inconsistent = true;
    else
      flow->listening_count--;
    if (member->acknowledged_delivery_epoch < flow->delivery_epoch) {
      if (flow->feedback_outstanding_count == 0)
        inconsistent = true;
      else
        flow->feedback_outstanding_count--;
    }
    member->acknowledged_delivery_epoch = flow->delivery_epoch;
    member->first_unacknowledged_ms = 0;
  }
  member->listening = listening;
  if (inconsistent)
    recount_member_feedback(flow);
}

static void record_member_submission(transport_flexicast_flow_t *flow,
                                     transport_flexicast_member_t *member,
                                     int64_t now) {
  if (!member->listening)
    return;
  if (member->acknowledged_delivery_epoch == flow->delivery_epoch) {
    member->acknowledged_delivery_epoch = flow->delivery_epoch - 1U;
    member->first_unacknowledged_ms = now;
    flow->feedback_outstanding_count++;
  }
}

void tf_record_delivery_submission(transport_t *t,
                                   transport_flexicast_flow_t *flow,
                                   transport_flexicast_member_t *recipient,
                                   bool first_submission) {
  if (first_submission) {
    uint64_t previous = flow->delivery_epoch;
    flow->delivery_epoch = previous == UINT64_MAX ? 1 : previous + 1U;
    for (size_t i = 0; i < flow->member_count; ++i) {
      transport_flexicast_member_t *member = &flow->members[i];
      if (!member->listening)
        continue;
      /* preserve older delivery debt for replicas awaiting submission */
      if (member->acknowledged_delivery_epoch == previous)
        member->acknowledged_delivery_epoch = flow->delivery_epoch;
      else if (previous == UINT64_MAX)
        member->acknowledged_delivery_epoch = 0;
    }
  }
  int64_t now = transport_now_ms(t);
  if (recipient) {
    record_member_submission(flow, recipient, now);
  } else {
    for (size_t i = 0; i < flow->member_count; ++i)
      record_member_submission(flow, &flow->members[i], now);
  }
}

static uint64_t
member_delivery_debt(const transport_flexicast_flow_t *flow,
                     const transport_flexicast_member_t *member) {
  return member->listening &&
                 member->acknowledged_delivery_epoch <= flow->delivery_epoch
             ? flow->delivery_epoch - member->acknowledged_delivery_epoch
             : 0;
}

static uint64_t
feedback_demotion_timeout_ms(const transport_flexicast_flow_t *flow) {
  uint64_t feedback_interval = flow->cc_config.feedback_timeout_msec != 0
                                   ? flow->cc_config.feedback_timeout_msec
                                   : 1000U;
  uint64_t ack_interval = flow->ack_delay_msec != 0
                              ? flow->ack_delay_msec
                              : QUICLY_DEFAULT_MAX_ACK_DELAY;
  uint64_t interval =
      feedback_interval > ack_interval ? feedback_interval : ack_interval;
  return interval * TRANSPORT_FLEXICAST_MISSED_FEEDBACK_WINDOWS;
}

int64_t
tf_member_feedback_deadline(const transport_flexicast_flow_t *flow,
                            const transport_flexicast_member_t *member) {
  if (!member_delivery_debt(flow, member) ||
      member->first_unacknowledged_ms <= 0)
    return INT64_MAX;
  uint64_t interval = feedback_demotion_timeout_ms(flow);
  return interval > (uint64_t)(INT64_MAX - member->first_unacknowledged_ms)
             ? INT64_MAX
             : member->first_unacknowledged_ms + (int64_t)interval;
}

static bool member_remove(transport_flexicast_flow_t *flow,
                          transport_flexicast_member_t *member) {
  if (!flow || !flow->members || !member || flow->member_count == 0)
    return false;
  size_t slot = (size_t)(member - flow->members);
  if (slot >= flow->member_count)
    return false;
  size_t last = flow->member_count - 1U;
  bool inconsistent = false;
  if (member->listening) {
    if (flow->listening_count == 0)
      inconsistent = true;
    else
      flow->listening_count--;
    if (member->acknowledged_delivery_epoch < flow->delivery_epoch) {
      if (flow->feedback_outstanding_count == 0)
        inconsistent = true;
      else
        flow->feedback_outstanding_count--;
    }
  }
  member_map_remove(flow, member->conn);
  if (slot != last) {
    flow->members[slot] = flow->members[last];
    member_map_update(flow, flow->members[slot].conn, slot);
  }
  memset(&flow->members[last], 0, sizeof(flow->members[last]));
  flow->member_count--;
  if (inconsistent)
    recount_member_feedback(flow);
  return true;
}

static bool send_control(transport_conn_t *conn, uint8_t type,
                         const uint8_t *payload, size_t payload_len) {
  return conn && conn->stream &&
         quicly_sendstate_is_open(&conn->stream->sendstate) &&
         transport_stream_write_frame(conn->stream, type, payload, payload_len);
}

static quicly_flexicast_flow_id_t flexicast_wire_id(uint64_t flow_id) {
  quicly_flexicast_flow_id_t wire = {.len = QUICLY_FLEXICAST_FLOW_ID_SIZE};
  quicly_encode64(wire.bytes, flow_id);
  return wire;
}

static bool flexicast_host_id(const quicly_flexicast_flow_id_t *wire,
                              uint64_t *flow_id) {
  if (!wire || !flow_id || wire->len != QUICLY_FLEXICAST_FLOW_ID_SIZE)
    return false;
  const uint8_t *src = wire->bytes;
  *flow_id = quicly_decode64(&src);
  return *flow_id > TRANSPORT_MAX_PATHS && *flow_id <= PTLS_QUICINT_MAX;
}

static bool send_state(transport_conn_t *conn, uint64_t flow_id,
                       uint64_t sequence, uint64_t action) {
  quicly_flexicast_state_frame_t frame = {
      .flow_id = flexicast_wire_id(flow_id),
      .sequence = sequence,
      .action = action,
  };
  return quicly_flexicast_send_state(conn->quic, &frame) == QUICLY_FLEXICAST_OK;
}

static bool send_current_key(transport_flexicast_flow_t *flow,
                             transport_flexicast_member_t *member) {
  if (!flow || !member || !member->conn || !member->conn->quic)
    return false;
  quicly_flexicast_key_frame_t key = {
      .flow_id = flexicast_wire_id(flow->flow_id),
      .sequence = flow->key_epoch,
      .first_packet_number =
          quicly_flexicast_get_next_packet_number(flow->crypto),
      .key = ptls_iovec_init(flow->secret, sizeof(flow->secret)),
      .algorithm = PTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
  };
  return quicly_flexicast_send_key(member->conn->quic, &key) ==
         QUICLY_FLEXICAST_OK;
}

static bool send_pending_offer(transport_flexicast_flow_t *flow,
                               transport_flexicast_member_t *member) {
  if (!flow || !member || !member->conn || !member->offer_pending)
    return flow && member && !member->offer_pending;
  if (!member->offer_bind_sent) {
    qlinq_wire_flexicast_bind_t bind = {.alias = member->alias,
                                        .flow_id = flow->flow_id,
                                        .key_epoch = member->offer_epoch};
    uint8_t bind_buf[QLINQ_WIRE_FLEXICAST_BIND_SIZE];
    if (qlinq_wire_encode_flexicast_bind(bind_buf, sizeof(bind_buf), &bind) !=
            QLINQ_WIRE_OK ||
        !send_control(member->conn, QLINQ_WIRE_FLEXICAST_BIND, bind_buf,
                      sizeof(bind_buf)))
      return false;
    member->offer_bind_sent = true;
  }
  if (quicly_flexicast_send_announce(
          member->conn->quic, &member->offer_announce) != QUICLY_FLEXICAST_OK)
    return false;
  member->offer_pending = false;
  return true;
}

/* prepare or retry an offer without changing membership */
static bool prepare_source_offer(transport_t *t,
                                 transport_flexicast_flow_t *flow,
                                 transport_flexicast_member_t *member) {
  transport_conn_t *conn = member->conn;
  if (!conn || !conn->quic)
    return false;
  struct sockaddr *peer = quicly_get_peername(conn->quic);
  struct sockaddr *local = quicly_get_sockname(conn->quic);
  if (!peer || !local ||
      (!t->flexicast_native_source && peer->sa_family != local->sa_family))
    return false;

  quicly_flexicast_announce_frame_t fc_announce = {
      .flow_id = flexicast_wire_id(flow->flow_id),
      .sequence = flow->key_epoch,
      .ack_delay_msec = QUICLY_DEFAULT_MAX_ACK_DELAY,
  };
  if (t->flexicast_native_source) {
    if (t->flexicast_group_addr.ss_family == AF_INET) {
      const struct sockaddr_in *group =
          (const struct sockaddr_in *)&t->flexicast_group_addr;
      fc_announce.ip_version = 4;
      memcpy(fc_announce.source_ip, &t->flexicast_interface_v4, 4);
      memcpy(fc_announce.group_ip, &group->sin_addr, 4);
      fc_announce.udp_port = ntohs(group->sin_port);
    } else {
      const struct sockaddr_in6 *group =
          (const struct sockaddr_in6 *)&t->flexicast_group_addr;
      fc_announce.ip_version = 6;
      memcpy(fc_announce.source_ip, &t->flexicast_interface_v6, 16);
      memcpy(fc_announce.group_ip, &group->sin6_addr, 16);
      fc_announce.udp_port = ntohs(group->sin6_port);
    }
    flow->native_multicast = true;
    flow->ip_version = fc_announce.ip_version;
    flow->interface_index = t->flexicast_interface_index;
    size_t address_len = ip_address_size(fc_announce.ip_version);
    memcpy(flow->source_ip, fc_announce.source_ip, address_len);
    memcpy(flow->group_ip, fc_announce.group_ip, address_len);
    flow->udp_port = fc_announce.udp_port;
  } else if (peer->sa_family == AF_INET) {
    const struct sockaddr_in *source = (const struct sockaddr_in *)local;
    const struct sockaddr_in *group = (const struct sockaddr_in *)peer;
    fc_announce.ip_version = 4;
    memcpy(fc_announce.source_ip, &source->sin_addr, 4);
    memcpy(fc_announce.group_ip, &group->sin_addr, 4);
    fc_announce.udp_port = ntohs(group->sin_port);
  } else {
    const struct sockaddr_in6 *source = (const struct sockaddr_in6 *)local;
    const struct sockaddr_in6 *group = (const struct sockaddr_in6 *)peer;
    fc_announce.ip_version = 6;
    memcpy(fc_announce.source_ip, &source->sin6_addr, 16);
    memcpy(fc_announce.group_ip, &group->sin6_addr, 16);
    fc_announce.udp_port = ntohs(group->sin6_port);
  }
  member->offer_bind_sent = false;
  if (member->join_epoch_floor < flow->key_epoch)
    member->join_epoch_floor = flow->key_epoch;
  member->offer_pending = true;
  member->offer_epoch = flow->key_epoch;
  member->offer_announce = fc_announce;
  (void)send_pending_offer(flow, member);
  return true;
}

static bool rekey_source_flow(transport_t *t,
                              transport_flexicast_flow_t *flow) {
  if (!t || !flow || !flow->source || !flow->crypto ||
      flow->key_epoch == UINT32_MAX)
    return false;

  uint8_t next_secret[TRANSPORT_FLEXICAST_SECRET_SIZE];
  ptls_openssl_random_bytes(next_secret, sizeof(next_secret));
  uint64_t first_packet_number =
      quicly_flexicast_get_next_packet_number(flow->crypto);
  if (quicly_flexicast_flow_rekey(
          flow->crypto, ptls_iovec_init(next_secret, sizeof(next_secret)),
          first_packet_number, transport_now_ms(t)) != QUICLY_FLEXICAST_OK) {
    ptls_clear_memory(next_secret, sizeof(next_secret));
    return false;
  }

  memcpy(flow->secret, next_secret, sizeof(flow->secret));
  ptls_clear_memory(next_secret, sizeof(next_secret));
  flow->key_epoch++;

  for (size_t i = 0; i < flow->member_count; i++) {
    transport_flexicast_member_t *member = &flow->members[i];
    if (member->reoffer_pending && member->conn) {
      if (prepare_source_offer(t, flow, member))
        member->reoffer_pending = false;
    }
    if (!member->conn || !member->joined)
      continue;
    set_member_listening(flow, member, false);
    member->ready_deadline_ms =
        transport_now_ms(t) +
        3 * (int64_t)flow->cc_config.feedback_timeout_msec;
    member->key_pending = !send_current_key(flow, member);
  }
  t->stats.flexicast_rekeys++;
  return true;
}

static void fallback_source_flow(transport_t *t,
                                 transport_flexicast_flow_t *flow) {
  if (!t || !flow || !flow->source)
    return;
  t->stats.flexicast_pacing_dropped += tf_clear_flow_queue(flow);
  for (size_t i = 0; i < flow->member_count; i++) {
    transport_flexicast_member_t *member = &flow->members[i];
    if (!member->conn || (!member->joined && !member->listening))
      continue;
    (void)send_state(member->conn, flow->flow_id, flow->key_epoch,
                     QUICLY_FLEXICAST_STATE_LEAVE);
    (void)quicly_flexicast_detach_at(flow->crypto, member->conn->id,
                                     transport_now_ms(t));
    member->join_epoch_floor =
        flow->key_epoch == UINT32_MAX ? UINT32_MAX : flow->key_epoch + 1U;
    member->joined = false;
    member->key_pending = false;
    set_member_listening(flow, member, false);
    t->stats.flexicast_fallbacks++;
  }
}

static void schedule_source_rekey(transport_t *t,
                                  transport_flexicast_flow_t *flow,
                                  int64_t now) {
  if (!t || !flow || !flow->active || !flow->source)
    return;
  /* anchor rekey batch to first membership change */
  if (!flow->rekey_pending)
    flow->rekey_ready_at_ms =
        now > INT64_MAX - TRANSPORT_FLEXICAST_REKEY_HOLDOFF_MS
            ? INT64_MAX
            : now + TRANSPORT_FLEXICAST_REKEY_HOLDOFF_MS;
  flow->rekey_pending = true;
}

static bool maybe_send_join(transport_flexicast_flow_t *flow) {
  if (!flow)
    return false;
  /* withhold JOIN on local group-join failure to stay on unicast */
  if (flow->multicast_unavailable)
    return true;
  if (flow->source || flow->join_sent || !flow->binding_received ||
      !flow->announcement_received || !flow->control_conn)
    return flow->join_sent;
  if (!send_state(flow->control_conn, flow->flow_id, flow->key_epoch,
                  QUICLY_FLEXICAST_STATE_JOIN))
    return true; /* retry on local backpressure */
  flow->join_sent = true;
  return true;
}

static bool configured_interface_matches(const transport_t *t,
                                         uint8_t ip_version,
                                         const uint8_t *address,
                                         uint32_t interface_index) {
  int family = ip_version == 4 ? AF_INET : ip_version == 6 ? AF_INET6 : 0;
  if (!t || !address || family == 0 || t->flexicast_interface_family != family)
    return false;
  size_t address_size = ip_version == 4 ? 4U : 16U;
  const void *configured = ip_version == 4
                               ? (const void *)&t->flexicast_interface_v4
                               : (const void *)&t->flexicast_interface_v6;
  if (memcmp(configured, address, address_size) != 0)
    return false;
  return interface_index == 0 || t->flexicast_interface_index == 0 ||
         interface_index == t->flexicast_interface_index;
}

void transport_flexicast_interface_removed(transport_t *t, uint8_t ip_version,
                                           const uint8_t *address,
                                           uint32_t interface_index) {
  bool whole_interface = t && ip_version == 0 && !address &&
                         interface_index != 0 &&
                         t->flexicast_interface_index == interface_index;
  if (!whole_interface &&
      !configured_interface_matches(t, ip_version, address, interface_index))
    return;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active || (!whole_interface && flow->ip_version != ip_version))
      continue;
    if (flow->source) {
      if (flow->native_multicast) {
        flow->native_multicast = false;
        t->stats.flexicast_interface_fallbacks++;
      }
      continue;
    }
    if (flow->interface_index != interface_index && interface_index != 0)
      continue;
    if (flow->membership_acquired)
      release_membership(t, flow);
    flow->native_multicast = false;
    flow->multicast_unavailable = true;
    if (flow->join_sent && flow->control_conn) {
      (void)send_state(flow->control_conn, flow->flow_id, flow->key_epoch,
                       QUICLY_FLEXICAST_STATE_LEAVE);
      flow->join_sent = false;
    }
    t->stats.flexicast_interface_fallbacks++;
  }
}

void transport_flexicast_interface_added(transport_t *t, uint8_t ip_version,
                                         const uint8_t *address,
                                         uint32_t interface_index) {
  if (!configured_interface_matches(t, ip_version, address, 0))
    return;
  t->flexicast_interface_index = interface_index;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active || flow->ip_version != ip_version)
      continue;
    if (flow->source) {
      if (!flow->native_multicast) {
        flow->native_multicast = true;
        t->stats.flexicast_interface_rejoins++;
      }
      continue;
    }
    if (!flow->announcement_received || flow->membership_acquired)
      continue;
    quicly_flexicast_announce_frame_t announce = {
        .flow_id = flexicast_wire_id(flow->flow_id),
        .sequence = flow->key_epoch,
        .ip_version = flow->ip_version,
        .udp_port = flow->udp_port,
        .ack_delay_msec = flow->ack_delay_msec};
    size_t address_size = ip_version == 4 ? 4U : 16U;
    memcpy(announce.source_ip, flow->source_ip, address_size);
    memcpy(announce.group_ip, flow->group_ip, address_size);
    flow->multicast_unavailable = false;
    if (join_announced_group(t, flow, &announce) && maybe_send_join(flow)) {
      t->stats.flexicast_interface_rejoins++;
    } else {
      flow->multicast_unavailable = true;
    }
  }
}

static transport_flexicast_flow_t *
find_source_cohort(transport_t *t, const moq_track_id_t *track) {
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (flow->active && flow->source &&
        transport_track_id_equal(&flow->track_id, track))
      return flow;
  }
  return NULL;
}

bool transport_flexicast_offer(transport_t *t, transport_conn_t *conn,
                               const moq_track_id_t *track, uint8_t alias) {
  if (!t || !conn || !track || !t->flexicast_enabled || !t->is_server ||
      (conn->peer_capabilities & QLINQ_WIRE_CAP_FLEXICAST_DATAGRAM) == 0 ||
      !quicly_flexicast_is_negotiated(conn->quic) ||
      (track->flags & MOQ_TRACK_FLAG_RELIABLE) != 0)
    return false;

  transport_flexicast_flow_t *flow = find_source_cohort(t, track);
  if (!flow) {
    flow = alloc_flow(t);
    if (!flow)
      return false;
    flow->source = true;
    flow->alias = alias;
    flow->key_epoch = 1;
    flow->track_id = *track;
    flow->cc_config.startup_rate_bytes_per_second =
        t->flexicast_cc_startup_rate != 0 ? t->flexicast_cc_startup_rate
                                          : 64U * 1024U;
    flow->cc_config.minimum_rate_bytes_per_second =
        t->flexicast_cc_minimum_rate != 0 ? t->flexicast_cc_minimum_rate
                                          : 2U * 1024U;
    flow->cc_config.maximum_rate_bytes_per_second =
        t->flexicast_cc_maximum_rate != 0 ? t->flexicast_cc_maximum_rate
                                          : 1024U * 1024U * 1024U;
    flow->cc_config.maximum_datagram_size =
        (uint32_t)t->limits.max_udp_payload_size;
    flow->cc_config.feedback_timeout_msec =
        t->flexicast_cc_feedback_timeout_ms != 0
            ? t->flexicast_cc_feedback_timeout_ms
            : 1000U;
    flow->cc_config.packet_reordering_threshold = 3;
    do {
      ptls_openssl_random_bytes(&flow->flow_id, sizeof(flow->flow_id));
      flow->flow_id &= PTLS_QUICINT_MAX;
    } while (flow->flow_id <= TRANSPORT_MAX_PATHS ||
             find_flow(t, flow->flow_id) != flow);
    ptls_openssl_random_bytes(flow->secret, sizeof(flow->secret));
    if (!create_crypto(t, flow, 0)) {
      release_flow(t, flow);
      return false;
    }
  }
  transport_flexicast_member_t *member = member_add(flow, conn);
  if (!member)
    return false;
  member->alias = alias;
  if (member->offer_epoch != 0) {
    /* repeated SUBSCRIBE requests a fresh offer at a higher key epoch */
    if (member->reoffer_pending ||
        !admit_member_transition(t, flow, member, transport_now_ms(t)))
      return true;
    (void)quicly_flexicast_detach_at(flow->crypto, conn->id,
                                     transport_now_ms(t));
    member->join_epoch_floor =
        flow->key_epoch == UINT32_MAX ? UINT32_MAX : flow->key_epoch + 1U;
    member->joined = false;
    member->key_pending = false;
    member->offer_pending = false;
    member->reoffer_pending = true;
    member->rejoining = member->join_sequence != 0;
    set_member_listening(flow, member, false);
    schedule_source_rekey(t, flow, transport_now_ms(t));
    return true;
  }

  if (!prepare_source_offer(t, flow, member)) {
    transport_flexicast_remove_member(t, conn, track);
    return false;
  }
  return true;
}

static void remove_source_member(transport_t *t,
                                 transport_flexicast_flow_t *flow,
                                 transport_conn_t *conn) {
  transport_flexicast_member_t *member = member_find(flow, conn);
  if (!member)
    return;
  bool needs_rekey = member->joined || member->listening;
  (void)quicly_flexicast_detach_at(flow->crypto, conn->id, transport_now_ms(t));
  (void)member_remove(flow, member);
  if (flow->member_count == 0) {
    retire_flow_id(t, flow->flow_id, flow->key_epoch);
    release_flow(t, flow);
  } else if (needs_rekey) {
    schedule_source_rekey(t, flow, transport_now_ms(t));
  }
}

void transport_flexicast_remove_member(transport_t *t, transport_conn_t *conn,
                                       const moq_track_id_t *track) {
  if (!t || !conn)
    return;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active || !flow->source ||
        (track && !transport_track_id_equal(&flow->track_id, track)))
      continue;
    remove_source_member(t, flow, conn);
  }
}

void transport_flexicast_unsubscribe(transport_t *t, transport_conn_t *conn,
                                     const moq_track_id_t *track) {
  if (!t || !conn || !track)
    return;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active || flow->source || flow->control_conn != conn ||
        !transport_track_id_equal(&flow->track_id, track))
      continue;
    if (flow->join_sent)
      (void)send_state(conn, flow->flow_id, flow->key_epoch,
                       QUICLY_FLEXICAST_STATE_LEAVE);
    retire_flow_id(t, flow->flow_id, flow->key_epoch);
    release_flow(t, flow);
  }
}

void transport_flexicast_remove_connection(transport_t *t,
                                           transport_conn_t *conn) {
  if (!t || !conn)
    return;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active)
      continue;
    if (flow->source) {
      remove_source_member(t, flow, conn);
    } else if (flow->control_conn == conn) {
      release_flow(t, flow);
    }
  }
}

/* reset receiver handshake state when a higher-epoch offer arrives */
static void restart_receiver_offer(transport_t *t,
                                   transport_flexicast_flow_t *flow) {
  if (flow->crypto) {
    (void)quicly_flexicast_send_pending_ack(
        flow->crypto, flow->control_conn->quic, transport_now_ms(t), true);
    quicly_flexicast_flow_free(flow->crypto);
    flow->crypto = NULL;
  }
  ptls_clear_memory(flow->secret, sizeof(flow->secret));
  flow->join_sent = false;
  flow->announcement_received = false;
}

bool transport_flexicast_receive_bind(transport_t *t, transport_conn_t *conn,
                                      const qlinq_wire_flexicast_bind_t *bind) {
  if (!t || !conn || !bind || !t->flexicast_enabled || t->is_server)
    return false;
  uint32_t retired_epoch;
  if (retired_flow_epoch(t, bind->flow_id, &retired_epoch) &&
      bind->key_epoch <= retired_epoch)
    return true;
  moq_track_id_t track;
  if (transport_subscriptions_find_by_alias(&conn->receive_subscriptions,
                                            bind->alias, &track) != 0 ||
      (track.flags & MOQ_TRACK_FLAG_RELIABLE) != 0)
    return false;
  transport_flexicast_flow_t *flow = find_flow(t, bind->flow_id);
  if (!flow) {
    flow = alloc_flow(t);
    if (!flow)
      return false;
    flow->source = false;
    flow->flow_id = bind->flow_id;
    flow->control_conn = conn;
  } else if (flow->source || flow->control_conn != conn) {
    return false;
  }
  if (flow->binding_received) {
    if (bind->key_epoch < flow->key_epoch)
      return true;
    if (flow->alias != bind->alias)
      return false;
    if (bind->key_epoch > flow->key_epoch)
      restart_receiver_offer(t, flow);
  }
  flow->alias = bind->alias;
  flow->key_epoch = bind->key_epoch;
  flow->track_id = track;
  flow->binding_received = true;
  return !flow->announcement_received || maybe_send_join(flow);
}

bool transport_flexicast_receive_path_ack(transport_t *t,
                                          transport_conn_t *conn,
                                          uint64_t flow_id,
                                          const quicly_ack_frame_t *ack) {
  if (!t || !conn || !ack || !t->is_server)
    return false;
  transport_flexicast_flow_t *flow = find_flow(t, flow_id);
  /* ignore stale feedback for abandoned or demoted flows */
  if (!flow)
    return true;
  if (!flow->source)
    return false;
  transport_flexicast_member_t *member = member_find(flow, conn);
  if (!member || !member->listening)
    return true;
  size_t num_acked = 0, num_completed = 0, num_lost = 0;
  int ret = quicly_flexicast_ack_frame_at(flow->crypto, conn->id, ack,
                                          &num_acked, &num_lost, &num_completed,
                                          transport_now_ms(t));
  (void)num_lost;
  (void)num_completed;
  if (ret != QUICLY_FLEXICAST_OK)
    return false;
  t->stats.flexicast_acks_received += num_acked;
  if (num_acked > 0) {
    bool recount = false;
    if (member_delivery_debt(flow, member) != 0) {
      if (flow->feedback_outstanding_count != 0)
        flow->feedback_outstanding_count--;
      else
        recount = true;
    }
    member->acknowledged_delivery_epoch = flow->delivery_epoch;
    member->first_unacknowledged_ms = 0;
    if (recount || flow->feedback_outstanding_count > flow->listening_count)
      recount_member_feedback(flow);
  }
  return true;
}

static bool
receive_quic_announce(transport_t *t, transport_conn_t *conn,
                      const quicly_flexicast_announce_frame_t *announce) {
  uint64_t flow_id;
  if (!t || !conn || !announce || t->is_server ||
      !flexicast_host_id(&announce->flow_id, &flow_id) ||
      announce->sequence > UINT32_MAX)
    return false;
  uint32_t retired_epoch = 0;
  if (retired_flow_epoch(t, flow_id, &retired_epoch) &&
      announce->sequence <= retired_epoch)
    return true;
  transport_flexicast_flow_t *flow = find_flow(t, flow_id);
  if (!flow) {
    flow = alloc_flow(t);
    if (!flow)
      return false;
    flow->source = false;
    flow->flow_id = flow_id;
    flow->key_epoch = (uint32_t)announce->sequence;
    flow->control_conn = conn;
  } else if (flow->source || flow->control_conn != conn) {
    return false;
  }
  if ((flow->announcement_received && announce->sequence <= flow->key_epoch) ||
      announce->sequence < flow->key_epoch)
    return true;
  if (flow->binding_received && announce->sequence > flow->key_epoch)
    restart_receiver_offer(t, flow);
  if (!join_announced_group(t, flow, announce)) {
    flow->multicast_unavailable = true;
    t->stats.flexicast_fallbacks++;
  }
  flow->key_epoch = (uint32_t)announce->sequence;
  flow->ack_delay_msec = announce->ack_delay_msec > UINT32_MAX
                             ? UINT32_MAX
                             : (uint32_t)announce->ack_delay_msec;
  flow->announcement_received = true;
  return !flow->binding_received || maybe_send_join(flow);
}

static bool admit_member_transition(transport_t *t,
                                    transport_flexicast_flow_t *flow,
                                    transport_flexicast_member_t *member,
                                    int64_t now) {
  if (member->transition_window_started_ms == 0 ||
      now < member->transition_window_started_ms ||
      now - member->transition_window_started_ms >= 1000) {
    member->transition_window_started_ms = now;
    member->transitions_in_window = 0;
  }
  if (member->transitions_in_window <
      TRANSPORT_FLEXICAST_MEMBER_TRANSITIONS_PER_SECOND) {
    member->transitions_in_window++;
    return true;
  }

  t->stats.flexicast_control_frames_throttled++;
  if (member->joined || member->listening) {
    (void)quicly_flexicast_detach_at(flow->crypto, member->conn->id, now);
    member->join_epoch_floor =
        flow->key_epoch == UINT32_MAX ? UINT32_MAX : flow->key_epoch + 1U;
    member->joined = false;
    member->key_pending = false;
    member->recovery_baseline_pending = false;
    set_member_listening(flow, member, false);
    schedule_source_rekey(t, flow, now);
  }
  return false;
}

static bool receive_quic_state(transport_t *t, transport_conn_t *conn,
                               const quicly_flexicast_state_frame_t *state) {
  uint64_t flow_id;
  if (!t || !conn || !state || !flexicast_host_id(&state->flow_id, &flow_id) ||
      state->sequence > UINT32_MAX)
    return false;
  transport_flexicast_flow_t *flow = find_flow(t, flow_id);
  if (!flow) {
    /* ignore late LEAVE after UNSUBSCRIBE retired the flow */
    uint32_t retired_epoch;
    return (retired_flow_epoch(t, flow_id, &retired_epoch) &&
            state->sequence <= retired_epoch) ||
           (t->is_server && state->action == QUICLY_FLEXICAST_STATE_LEAVE);
  }
  if (state->sequence < flow->key_epoch) {
    /* allow source JOIN and LEAVE across concurrent rekeys; READY must match
     * current key_epoch */
    if (!t->is_server || !flow->source ||
        (state->action != QUICLY_FLEXICAST_STATE_JOIN &&
         state->action != QUICLY_FLEXICAST_STATE_LEAVE))
      return true;
  }
  if (state->sequence > flow->key_epoch)
    return false;
  if (!t->is_server) {
    if (state->action != QUICLY_FLEXICAST_STATE_LEAVE || flow->source ||
        flow->control_conn != conn)
      return false;
    retire_flow_id(t, flow_id, flow->key_epoch);
    release_flow(t, flow);
    return true;
  }
  if (!flow->source)
    return false;
  transport_flexicast_member_t *member = member_find(flow, conn);
  if (!member)
    return state->action == QUICLY_FLEXICAST_STATE_READY ||
           state->action == QUICLY_FLEXICAST_STATE_LEAVE;
  if (state->action == QUICLY_FLEXICAST_STATE_JOIN) {
    if (state->sequence < member->join_epoch_floor) {
      /* require fresh offer when JOIN predates demotion */
      member->reoffer_pending = true;
      if (!flow->rekey_pending && flow->key_epoch >= member->join_epoch_floor &&
          prepare_source_offer(t, flow, member))
        member->reoffer_pending = false;
      return true;
    }
    if (member->joined) {
      if (state->sequence > member->join_sequence)
        member->join_sequence = (uint32_t)state->sequence;
      return true;
    }
    if (!admit_member_transition(t, flow, member, transport_now_ms(t)))
      return true;
    member->joined = true;
    member->key_pending = false;
    member->join_sequence = (uint32_t)state->sequence;
    member->recovery_baseline_pending = !member->rejoining;
    schedule_source_rekey(t, flow, transport_now_ms(t));
  } else if (state->action == QUICLY_FLEXICAST_STATE_READY) {
    uint8_t alias = 0;
    if (!member->joined)
      return member->join_sequence != 0;
    if (flow->rekey_pending || member->key_pending)
      return true;
    member->key_pending = false;
    if (!member->listening &&
        quicly_flexicast_attach_at(flow->crypto, conn->id,
                                   transport_now_ms(t)) != QUICLY_FLEXICAST_OK)
      return false;
    set_member_listening(flow, member, true);
    member->ready_deadline_ms = 0;
    member->rejoining = false;
    if (member->recovery_baseline_pending) {
      if (transport_subscriptions_find_alias(&conn->send_subscriptions,
                                             &flow->track_id, &alias) != 0)
        return false;
      if (!transport_checkpoint_ack(conn, alias)->participating)
        transport_publish_checkpoint_member_added(t, conn, &flow->track_id,
                                                  alias);
      member->recovery_baseline_pending = false;
    }
  } else if (state->action == QUICLY_FLEXICAST_STATE_LEAVE) {
    if (state->sequence < member->join_sequence)
      return true;
    bool needs_rekey = member->joined || member->listening;
    if (needs_rekey &&
        !admit_member_transition(t, flow, member, transport_now_ms(t)))
      return true;
    (void)quicly_flexicast_detach_at(flow->crypto, conn->id,
                                     transport_now_ms(t));
    member->join_epoch_floor =
        flow->key_epoch == UINT32_MAX ? UINT32_MAX : flow->key_epoch + 1U;
    member->joined = false;
    member->key_pending = false;
    member->recovery_baseline_pending = false;
    set_member_listening(flow, member, false);
    if (needs_rekey)
      schedule_source_rekey(t, flow, transport_now_ms(t));
  } else {
    return false;
  }
  return true;
}

static bool receive_quic_key(transport_t *t, transport_conn_t *conn,
                             const quicly_flexicast_key_frame_t *key) {
  uint64_t flow_id;
  if (!t || !conn || !key || t->is_server ||
      !flexicast_host_id(&key->flow_id, &flow_id) ||
      key->sequence > UINT32_MAX ||
      key->algorithm != PTLS_CIPHER_SUITE_AES_128_GCM_SHA256 ||
      key->key.len != TRANSPORT_FLEXICAST_SECRET_SIZE)
    return false;
  transport_flexicast_flow_t *flow = find_flow(t, flow_id);
  if (!flow)
    return retired_flow_epoch(t, flow_id, NULL);
  uint32_t retired_epoch;
  if (retired_flow_epoch(t, flow_id, &retired_epoch) &&
      key->sequence <= retired_epoch)
    return true;
  if (flow->source || flow->control_conn != conn || !flow->join_sent)
    return false;
  if (key->sequence < flow->key_epoch)
    return true;
  if (key->sequence == flow->key_epoch && flow->crypto) {
    if (memcmp(flow->secret, key->key.base, sizeof(flow->secret)) != 0)
      return false;
  } else {
    if (flow->crypto) {
      (void)quicly_flexicast_send_pending_ack(
          flow->crypto, flow->control_conn->quic, transport_now_ms(t), true);
      if (quicly_flexicast_flow_rekey(
              flow->crypto, key->key, key->first_packet_number,
              transport_now_ms(t)) != QUICLY_FLEXICAST_OK)
        return false;
    } else if (!create_crypto_with_secret(t, flow, key->key.base,
                                          key->first_packet_number,
                                          &flow->crypto)) {
      return false;
    }
    memcpy(flow->secret, key->key.base, sizeof(flow->secret));
    flow->key_epoch = (uint32_t)key->sequence;
  }
  return send_state(conn, flow->flow_id, flow->key_epoch,
                    QUICLY_FLEXICAST_STATE_READY);
}

bool transport_flexicast_receive_quic_frame(
    transport_t *t, transport_conn_t *conn,
    const quicly_flexicast_frame_t *frame) {
  if (!t || !conn || !frame || !t->flexicast_enabled ||
      !quicly_flexicast_is_negotiated(conn->quic))
    return false;
  switch (frame->type) {
  case QUICLY_FRAME_TYPE_FC_ANNOUNCE:
    return receive_quic_announce(t, conn, &frame->data.announce);
  case QUICLY_FRAME_TYPE_FC_STATE:
    return receive_quic_state(t, conn, &frame->data.state);
  case QUICLY_FRAME_TYPE_FC_KEY:
    return receive_quic_key(t, conn, &frame->data.key);
  default:
    return false;
  }
}

bool transport_flexicast_native_packet_valid(
    transport_t *t, const uint8_t *packet, size_t size,
    const transport_flexicast_ingress_t *ingress) {
  if (!t || !packet || size < 9 || !ingress || ingress->truncated ||
      !ingress->interface_index || !t->flexicast_enabled)
    return false;
  const uint8_t *at = packet + 1;
  transport_flexicast_flow_t *flow = find_flow(t, quicly_decode64(&at));
  size_t address_size = ip_address_size(ingress->ip_version);
  return address_size && flow && !flow->source && flow->native_multicast &&
         flow->membership_acquired && flow->join_sent &&
         !flow->multicast_unavailable && flow->crypto && flow->control_conn &&
         flow->ip_version == ingress->ip_version &&
         flow->udp_port == ingress->destination_port &&
         (!flow->interface_index ||
          flow->interface_index == ingress->interface_index) &&
         !memcmp(flow->source_ip, ingress->source_ip, address_size) &&
         !memcmp(flow->group_ip, ingress->group_ip, address_size);
}

/* accept replicated ciphertext only from validated control-connection paths */
bool transport_flexicast_receive_unicast_ecn(
    transport_t *t, uint8_t *packet, size_t size, const struct sockaddr *peer,
    transport_conn_t **source, ptls_iovec_t *payload, uint8_t ecn) {
  if (!t || !packet || size < 9 || !source || !payload || !t->flexicast_enabled)
    return false;
  const uint8_t *at = packet + 1;
  transport_flexicast_flow_t *flow = find_flow(t, quicly_decode64(&at));
  if (!flow || flow->source || !flow->crypto)
    return false;
  *source = NULL;
  *payload = ptls_iovec_init(NULL, 0);
  bool allowed = false;
  if (peer && flow->join_sent && !flow->multicast_unavailable &&
      flow->control_conn && flow->control_conn->quic) {
    for (size_t i = 0; i < TRANSPORT_MAX_QUIC_PATHS; i++) {
      quicly_path_stats_t path;
      quicly_path_health_t health;
      if (quicly_get_path_stats(flow->control_conn->quic, i, &path) != 0 ||
          quicly_get_path_health(flow->control_conn->quic, i, &health) != 0 ||
          health.abandoned || !health.validated ||
          peer->sa_family != path.remote.sa.sa_family)
        continue;
      if (peer->sa_family == AF_INET) {
        const struct sockaddr_in *remote = (const struct sockaddr_in *)peer;
        allowed = remote->sin_port == path.remote.sin.sin_port &&
                  remote->sin_addr.s_addr == path.remote.sin.sin_addr.s_addr;
      } else if (peer->sa_family == AF_INET6) {
        const struct sockaddr_in6 *remote = (const struct sockaddr_in6 *)peer;
        allowed =
            remote->sin6_port == path.remote.sin6.sin6_port &&
            !memcmp(&remote->sin6_addr, &path.remote.sin6.sin6_addr, 16) &&
            remote->sin6_scope_id == path.remote.sin6.sin6_scope_id;
      }
      if (allowed)
        break;
    }
  }
  if (!allowed)
    return true;
  return transport_flexicast_receive_packet_ecn(t, packet, size, source,
                                                payload, ecn);
}

bool transport_flexicast_receive_packet_ecn(transport_t *t, uint8_t *packet,
                                            size_t packet_size,
                                            transport_conn_t **source_conn,
                                            ptls_iovec_t *payload,
                                            uint8_t ecn) {
  if (!t || !packet || !source_conn || !payload || packet_size < 9 ||
      !t->flexicast_enabled)
    return false;
  const uint8_t *flow_at = packet + 1;
  uint64_t flow_id = quicly_decode64(&flow_at);
  transport_flexicast_flow_t *flow = find_flow(t, flow_id);
  if (!flow || flow->source || !flow->crypto)
    return false;
  *source_conn = flow->control_conn;
  *payload = ptls_iovec_init(NULL, 0);
  uint64_t packet_number = 0;
  int64_t now = transport_now_ms(t);
  if (quicly_flexicast_receive_datagram_ecn_at(
          flow->crypto, packet, packet_size, payload, &packet_number, now,
          ecn) == QUICLY_FLEXICAST_OK) {
    /* rewrite header alias to subscriber-local alias */
    qlinq_wire_fec_header_t header;
    if (qlinq_wire_decode_fec_header(payload->base, payload->len, &header) ==
        QLINQ_WIRE_OK) {
      header.alias = flow->alias;
      if (qlinq_wire_encode_fec_header(payload->base, payload->len, &header) !=
          QLINQ_WIRE_OK)
        *payload = ptls_iovec_init(NULL, 0);
    }
    t->stats.flexicast_packets_received++;
    if (quicly_flexicast_ack_is_due(flow->crypto, now) &&
        !(t->simulated_flexicast_feedback_loss_rate > 0 &&
          (rand() % 100) < t->simulated_flexicast_feedback_loss_rate))
      (void)quicly_flexicast_send_pending_ack(
          flow->crypto, flow->control_conn->quic, now, false);
  }
  return true;
}

transport_flexicast_flow_t *
transport_flexicast_find_source(transport_t *t, const moq_track_id_t *track) {
  if (!t || !track)
    return NULL;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (flow->active && flow->source &&
        transport_track_id_equal(&flow->track_id, track) &&
        transport_flexicast_listening_members(flow) != 0)
      return flow;
  }
  return NULL;
}

size_t
transport_flexicast_listening_members(const transport_flexicast_flow_t *flow) {
  return flow ? flow->listening_count : 0;
}

bool transport_flexicast_member_is_listening(
    const transport_flexicast_flow_t *flow, const transport_conn_t *conn) {
  if (!flow || !conn)
    return false;
  size_t slot;
  return member_map_find(flow, conn, &slot) && flow->members[slot].listening;
}

void transport_flexicast_tick(transport_t *t) {
  if (!t || !t->flexicast_enabled)
    return;
  int64_t now = transport_now_ms(t);
  for (size_t f = 0; f < t->flexicast.capacity; f++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[f];
    if (!flow->active || flow->source || !flow->crypto || !flow->control_conn ||
        !flow->control_conn->quic ||
        !quicly_flexicast_ack_is_due(flow->crypto, now) ||
        (t->simulated_flexicast_feedback_loss_rate > 0 &&
         (rand() % 100) < t->simulated_flexicast_feedback_loss_rate))
      continue;
    (void)quicly_flexicast_send_pending_ack(
        flow->crypto, flow->control_conn->quic, now, false);
  }
  if (!t->is_server)
    return;
  for (size_t f = 0; f < t->flexicast.capacity; f++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[f];
    if (!flow->active || !flow->source || !flow->crypto)
      continue;
    for (size_t i = 0; i < flow->member_count; i++) {
      transport_flexicast_member_t *member = &flow->members[i];
      if (member->reoffer_pending && !flow->rekey_pending &&
          prepare_source_offer(t, flow, member))
        member->reoffer_pending = false;
      if (member->offer_pending)
        (void)send_pending_offer(flow, member);
    }
    if (flow->rekey_pending) {
      if (now < flow->rekey_ready_at_ms)
        continue;
      flow->rekey_pending = false;
      flow->rekey_ready_at_ms = 0;
      if (!rekey_source_flow(t, flow))
        fallback_source_flow(t, flow);
      continue;
    }
    for (size_t i = 0; i < flow->member_count; i++) {
      transport_flexicast_member_t *member = &flow->members[i];
      if (member->conn && member->joined && member->key_pending &&
          send_current_key(flow, member))
        member->key_pending = false;
    }
    if (flow->feedback_outstanding_count != 0) {
      quicly_flexicast_cc_output_t output;
      quicly_flexicast_cc_get_flow_output(flow->crypto, &output);
      if (output.next_timeout != INT64_MAX && now >= output.next_timeout)
        quicly_flexicast_cc_on_flow_timeout(flow->crypto, now);
    }
    bool removed = false;
    for (size_t i = 0; i < flow->member_count; i++) {
      transport_flexicast_member_t *member = &flow->members[i];
      bool readiness_expired = member->joined && !member->listening &&
                               member->ready_deadline_ms > 0 &&
                               now >= member->ready_deadline_ms;
      bool feedback_expired = member_delivery_debt(flow, member) > 0 &&
                              now >= tf_member_feedback_deadline(flow, member);
      if (!member->conn || (!readiness_expired && !feedback_expired))
        continue;
      (void)send_state(member->conn, flow->flow_id, flow->key_epoch,
                       QUICLY_FLEXICAST_STATE_LEAVE);
      (void)quicly_flexicast_detach_at(flow->crypto, member->conn->id, now);
      member->join_epoch_floor =
          flow->key_epoch == UINT32_MAX ? UINT32_MAX : flow->key_epoch + 1U;
      member->joined = false;
      member->key_pending = false;
      set_member_listening(flow, member, false);
      t->stats.flexicast_fallbacks++;
      t->stats.flexicast_feedback_fallbacks++;
      removed = true;
    }
    if (removed)
      schedule_source_rekey(t, flow, now);
    tf_drain_paced_payloads(t, flow);
  }
}
