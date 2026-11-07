#include "transport_internal.h"
#include <stddef.h>
#include <string.h>

uint64_t transport_now_ns(const transport_t *t) {
  if (!t)
    return 0;
  if (t->turn_active || !t->drive_host.monotonic_ns)
    return t->drive_now_ns;
  transport_t *mutable = (transport_t *)t;
  bool active = mutable->host_callback_active;
  mutable->host_callback_active = true;
  uint64_t now = t->drive_host.monotonic_ns(t->drive_host.context);
  mutable->host_callback_active = active;
  return now;
}
int64_t transport_now_ms(const transport_t *t) {
  return (int64_t)(transport_now_ns(t) / 1000000U);
}
static void quic_now(quicly_now_t *self, double *now) {
  transport_t *t =
      (transport_t *)((char *)self - offsetof(transport_t, driver_quic_now));
  *now = (double)transport_now_ns(t) / 1000000.0;
}
static uint64_t tls_now(ptls_get_time_t *self) {
  transport_t *t =
      (transport_t *)((char *)self - offsetof(transport_t, driver_tls_now));
  t->host_callback_active = true;
  uint64_t now = t->drive_host.wall_time_ms(t->drive_host.context);
  t->host_callback_active = false;
  return now;
}
static uint64_t cache_now(void *context) {
  return transport_now_ns(context);
}
void transport_drive_setup_clocks(transport_t *t) {
  t->driver_quic_now.cb = quic_now;
  t->quic_ctx.now = &t->driver_quic_now;
  t->fec_cache.now_ns = cache_now;
  t->fec_cache.clock_context = t;
  if (t->drive_host.wall_time_ms) {
    t->driver_tls_now.cb = tls_now;
    t->tls_ctx.get_time = &t->driver_tls_now;
  }
  if (t->drive_host.random_bytes)
    t->tls_ctx.random_bytes = t->drive_host.random_bytes;
}
static bool ready(transport_t *t) {
  return transport_owner_ok(t) && !t->tick_active && !t->callback_depth;
}
bool transport_drive_time(transport_t *t, uint64_t time) {
  if (!ready(t) || time < t->drive_now_ns)
    return false;
  t->drive_now_ns = time;
  return true;
}
bool transport_drive_tick(transport_t *t, uint64_t time) {
  if (!t || t->turn_active || !transport_drive_time(t, time))
    return false;
  if (!transport_engine_begin_turn(t))
    return false;
  transport_engine_end_turn(t);
  return true;
}
size_t transport_drive_paths(transport_t *t, transport_drive_path_t *paths,
                             size_t capacity) {
  if (!transport_owner_ok(t) || (!paths && capacity))
    return 0;
  size_t n = t->socket_count < capacity ? t->socket_count : capacity;
  for (size_t i = 0; i < n; i++)
    paths[i] = transport_local_path_info(&t->sockets[i]);
  return n;
}
/* implemented beside the common protocol dispatcher and interface lifecycle */
void transport_drive_dispatch(transport_t *, size_t, uint8_t *, size_t,
                              struct sockaddr_storage *,
                              const struct sockaddr_storage *, uint32_t,
                              uint8_t);
void transport_drive_interface_event(transport_t *, bool,
                                     const struct sockaddr_storage *, uint32_t,
                                     const char *);

bool transport_drive_receive(transport_t *t, uint64_t id, void *bytes,
                             size_t size, const struct sockaddr_storage *source,
                             const struct sockaddr_storage *destination,
                             uint32_t interface_index, uint8_t ecn) {
  if (!ready(t) || (!bytes && size) || size > 65535 || !source ||
      !destination || ecn > 3 ||
      (source->ss_family != AF_INET && source->ss_family != AF_INET6) ||
      source->ss_family != destination->ss_family)
    return false;
  for (size_t i = 0; i < t->socket_count; i++)
    if (t->sockets[i].drive_id == id) {
      const struct sockaddr *local =
          (const struct sockaddr *)&t->sockets[i].local_addr;
      if (destination->ss_family != local->sa_family ||
          (!transport_address_is_wildcard(local) &&
           !transport_address_equal(local,
                                    (const struct sockaddr *)destination)))
        return false;
      struct sockaddr_storage mutable_source = *source;
      t->tick_active = true;
      transport_drive_dispatch(t, i, bytes, size, &mutable_source, destination,
                               interface_index, ecn);
      t->tick_active = false;
      return true;
    }
  return false;
}
bool transport_drive_interface(transport_t *t, bool added,
                               const struct sockaddr_storage *address,
                               uint32_t index, const char *name) {
  if (!ready(t) || !address || !name || strlen(name) >= 64 ||
      (address->ss_family != AF_INET && address->ss_family != AF_INET6 &&
       !(address->ss_family == AF_UNSPEC && !added)))
    return false;
  t->tick_active = true;
  transport_drive_interface_event(t, added, address, index, name);
  t->tick_active = false;
  return true;
}

bool transport_drive_input_pending(transport_t *t) {
  if (!t->drive_host.input_pending)
    return false;
  t->host_callback_active = true;
  bool pending = t->drive_host.input_pending(t->drive_host.context);
  t->host_callback_active = false;
  return pending;
}
