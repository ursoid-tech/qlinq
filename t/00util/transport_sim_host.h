#ifndef TEST_TRANSPORT_SIM_HOST_H
#define TEST_TRANSPORT_SIM_HOST_H
#include "transport_drive.h"
#include "transport_paths.h"
#include <assert.h>
#include <string.h>

#define SIM_PACKETS 256U
#define SIM_PACKET_SIZE 2048U
#define SIM_NODES 4U

typedef struct sim_node sim_node_t;
typedef struct {
  uint8_t data[SIM_PACKET_SIZE];
  size_t size;
  sim_node_t *target;
  uint64_t path_id, due_ns, sequence;
  struct sockaddr_storage source, destination;
  uint32_t interface_index;
  uint8_t ecn;
  bool active;
} sim_packet_t;
typedef struct {
  sim_packet_t packets[SIM_PACKETS];
  sim_node_t *nodes[SIM_NODES];
  size_t nodes_count, count, bytes, peak_count, peak_bytes;
  size_t accepted, dropped, delivered, partial;
  uint64_t now_ns, sequence;
  unsigned drop_every, reorder, loss_per_mille;
  uint32_t rng;
  uint64_t delay_ns, jitter_ns;
} sim_network_t;
struct sim_node {
  sim_network_t *network;
  transport_t *transport;
  transport_drive_path_t paths[TRANSPORT_MAX_PATHS];
  size_t path_count, opens, closes, sends, max_accept, drop_next;
  bool blocked, hard_error;
  uint64_t drop_until_ns;
};
/* scheduling randomness is independent of TLS randomness */
static inline uint32_t sim_random(sim_network_t *net) {
  uint32_t x = net->rng ? net->rng : 0x6d2b79f5U;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  return net->rng = x;
}
static inline bool sim_open(void *context, transport_drive_path_t *path) {
  sim_node_t *node = context;
  assert(node->path_count < TRANSPORT_MAX_PATHS);
  uint16_t *port = path->local.ss_family == AF_INET
                       ? &((struct sockaddr_in *)&path->local)->sin_port
                       : &((struct sockaddr_in6 *)&path->local)->sin6_port;
  if (!*port)
    *port = htons(40000 + (unsigned)node->opens);
  if (!path->interface_index)
    path->interface_index = 100;
  node->paths[node->path_count++] = *path;
  node->opens++;
  return true;
}
static inline void sim_close(void *context,
                             const transport_drive_path_t *path) {
  sim_node_t *node = context;
  for (size_t i = 0; i < node->path_count; i++)
    if (node->paths[i].id == path->id) {
      memmove(node->paths + i, node->paths + i + 1,
              (node->path_count - i - 1) * sizeof(*path));
      node->path_count--;
      node->closes++;
      /* closed input incarnation must not be delivered to a replacement */
      sim_network_t *net = node->network;
      for (size_t p = 0; p < SIM_PACKETS; p++)
        if (net->packets[p].active && net->packets[p].target == node &&
            net->packets[p].path_id == path->id) {
          net->count--;
          net->bytes -= net->packets[p].size;
          net->dropped++;
          memset(&net->packets[p], 0, sizeof(net->packets[p]));
        }
      return;
    }
  assert(!"closing unknown path");
}
static inline ssize_t
sim_send(void *context, const transport_drive_path_t *path,
         const struct sockaddr *source, const struct sockaddr *destination,
         socklen_t len, uint32_t ifindex, uint8_t ecn, size_t gso,
         const struct iovec *datagrams, size_t count) {
  sim_node_t *node = context;
  sim_network_t *net = node->network;
  (void)ifindex;
  node->sends++;
  bool known = false;
  for (size_t i = 0; i < node->path_count; i++)
    known |=
        node->paths[i].id == path->id &&
        transport_endpoint_equal((const struct sockaddr *)&node->paths[i].local,
                                 (const struct sockaddr *)&path->local);
  assert(known);
  assert(ecn < 4 && gso <= 64 && len <= sizeof(struct sockaddr_storage));
  assert(source->sa_family == path->local.ss_family);
  /* host callback cannot recursively mutate its own protocol owner */
  if (node->transport)
    assert(!transport_drive_time(node->transport, net->now_ns));
  if (node->hard_error)
    return -1;
  if (node->blocked)
    return 0;
  size_t accepted = 0;
  for (size_t i = 0;
       i < count && (!node->max_accept || accepted < node->max_accept); i++) {
    assert(datagrams[i].iov_len <= SIM_PACKET_SIZE);
    if (net->count == SIM_PACKETS)
      break;
    uint64_t sequence = ++net->sequence;
    sim_node_t *target = NULL;
    uint64_t target_path = 0;
    uint32_t target_interface = 0;
    for (size_t n = 0; n < net->nodes_count; n++) {
      sim_node_t *peer = net->nodes[n];
      for (size_t p = 0; p < peer->path_count; p++)
        if (transport_endpoint_equal(
                destination, (struct sockaddr *)&peer->paths[p].local)) {
          target = peer;
          target_path = peer->paths[p].id;
          target_interface = peer->paths[p].interface_index;
        }
    }
    net->accepted++;
    accepted++;
    bool random_drop =
        net->loss_per_mille && sim_random(net) % 1000U < net->loss_per_mille;
    if (node->drop_next || net->now_ns < node->drop_until_ns || random_drop ||
        !target || (net->drop_every && sequence % net->drop_every == 0)) {
      if (node->drop_next)
        node->drop_next--;
      net->dropped++;
      continue;
    }
    size_t slot = 0;
    while (net->packets[slot].active)
      slot++;
    sim_packet_t *packet = &net->packets[slot];
    *packet = (sim_packet_t){
        .active = true,
        .size = datagrams[i].iov_len,
        .target = target,
        .path_id = target_path,
        .due_ns = net->now_ns + (net->delay_ns ? net->delay_ns : 1000000U) +
                  (net->jitter_ns ? sim_random(net) % net->jitter_ns : 0),
        .sequence = sequence,
        .interface_index = target_interface,
        .ecn = ecn};
    memcpy(&packet->destination, destination, len);
    memcpy(&packet->source, source,
           source->sa_family == AF_INET ? sizeof(struct sockaddr_in)
                                        : sizeof(struct sockaddr_in6));
    memcpy(packet->data, datagrams[i].iov_base, packet->size);
    net->count++;
    net->bytes += packet->size;
    if (net->count > net->peak_count)
      net->peak_count = net->count;
    if (net->bytes > net->peak_bytes)
      net->peak_bytes = net->bytes;
  }
  if (accepted < count)
    net->partial++;
  return accepted;
}
static inline uint64_t sim_wall(void *context) {
  sim_node_t *node = context;
  return 1793412966000ULL + node->network->now_ns / 1000000U;
}
static inline transport_drive_host_t sim_host(sim_node_t *node,
                                              sim_network_t *net) {
  node->network = net;
  assert(net->nodes_count < SIM_NODES);
  net->nodes[net->nodes_count++] = node;
  return (transport_drive_host_t){.context = node,
                                  .initial_time_ns = net->now_ns,
                                  .open = sim_open,
                                  .close = sim_close,
                                  .send = sim_send,
                                  .wall_time_ms = sim_wall};
}
static inline void sim_advance(sim_network_t *net, uint64_t delta) {
  net->now_ns += delta;
  for (size_t n = 0; n < net->nodes_count; n++)
    if (net->nodes[n]->transport)
      assert(transport_drive_time(net->nodes[n]->transport, net->now_ns));
  /* bounded input service; reorder eligible packets without changing contents
   */
  for (size_t serviced = 0; serviced < SIM_PACKETS; serviced++) {
    size_t slot = SIM_PACKETS;
    uint64_t order = net->reorder ? 0 : UINT64_MAX;
    for (size_t i = 0; i < SIM_PACKETS; i++)
      if (net->packets[i].active && net->packets[i].due_ns <= net->now_ns) {
        uint64_t seq = net->packets[i].sequence;
        if ((net->reorder && seq > order) || (!net->reorder && seq < order)) {
          slot = i;
          order = seq;
        }
      }
    if (slot == SIM_PACKETS)
      break;
    sim_packet_t *p = &net->packets[slot];
    bool accepted =
        p->target->transport &&
        transport_drive_receive(p->target->transport, p->path_id, p->data,
                                p->size, &p->source, &p->destination,
                                p->interface_index, p->ecn);
    if (accepted)
      net->delivered++;
    else
      net->dropped++;
    net->count--;
    net->bytes -= p->size;
    memset(p, 0, sizeof(*p));
  }
  for (size_t n = 0; n < net->nodes_count; n++)
    if (net->nodes[n]->transport)
      assert(transport_drive_tick(net->nodes[n]->transport, net->now_ns));
}
#endif
