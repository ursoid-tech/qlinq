#include "transport_config.h"
#include "transport_egress.h"
#include "transport_fec_state.h"
#include "transport_internal.h"
#include "transport_memory.h"
#include "transport_paths.h"
#include "transport_repair.h"
#include "transport_scheduler.h"
#include "transport_subscriptions.h"
#include "transport_wire.h"

#include "transport_udp.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "transport component test failed: %s\n", message);       \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int test_recovery_cache_protection(void) {
  transport_sent_cache_t cache = {0};
  uint8_t payload[] = {1, 2, 3};
  moq_object_t object = {
      .track_id = {.type = MOQ_TRACK_DATA, .name = "protected"},
      .data = payload,
      .size = sizeof(payload)};
  CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, false),
        "retain required recovery object");
  for (size_t i = 1; i < TRANSPORT_SENT_CACHE_SIZE; i++) {
    object.object_id = i;
    CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, true),
          "fill best-effort cache entries");
  }
  object.object_id = TRANSPORT_SENT_CACHE_SIZE;
  CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, true),
        "best-effort replacement can skip protected entry");
  CHECK(transport_sent_cache_find(&cache, &object.track_id, 0, 0) != NULL &&
            transport_sent_cache_find(&cache, &object.track_id, 0, 1) == NULL,
        "evict best-effort entry instead of recovery obligation");
  /* Promote existing entries, then ensure best-effort retries cannot revoke
   * the recovery protection. */
  for (size_t i = 2; i <= TRANSPORT_SENT_CACHE_SIZE; i++) {
    object.object_id = i;
    CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, false) &&
              transport_sent_cache_store(&cache, &object, 2, 1, 3, true),
          "retry preserves promoted recovery protection");
  }
  object.object_id++;
  CHECK(!transport_sent_cache_store(&cache, &object, 2, 1, 3, true),
        "reject best-effort admission when every entry is protected");
  CHECK(transport_sent_cache_release_through(&cache, &object.track_id, 0, 0) ==
            1,
        "checkpoint releases protected entry");
  CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, true),
        "released entry admits new publication");
  object.object_id++;
  CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, true),
        "reused entry no longer inherits old protection");
  CHECK(transport_sent_cache_release_track(&cache, &object.track_id) ==
            TRANSPORT_SENT_CACHE_SIZE,
        "track release retires protected and best-effort entries");
  transport_sent_cache_destroy(&cache);
  return 0;
}

static int check_cache_lookups(transport_sent_cache_t *cache,
                               const moq_track_id_t tracks[2]) {
  size_t count = 0, bytes = 0;
  for (size_t i = 0; i < cache->capacity; i++) {
    count += cache->entries[i].data != NULL;
    if (cache->entries[i].data)
      bytes += cache->entries[i].size;
  }
  CHECK(cache->count == count && cache->payload_bytes == bytes,
        "cache live count and byte accounting match occupied entries");
  for (size_t track = 0; track < 2; track++)
    for (uint64_t group = 0; group < 3; group++)
      for (uint64_t object = 0; object < 8; object++) {
        sent_object_cache_t *expected = NULL;
        for (size_t i = 0; i < cache->capacity; i++) {
          sent_object_cache_t *entry = &cache->entries[i];
          if (entry->data && entry->group_id == group &&
              entry->object_id == object &&
              entry->track_id.type == tracks[track].type &&
              entry->track_id.flags == tracks[track].flags &&
              strcmp(entry->track_id.name, tracks[track].name) == 0) {
            expected = entry;
            break;
          }
        }
        CHECK(transport_sent_cache_find(cache, &tracks[track], group, object) ==
                  expected,
              "wrapped sparse cache lookup matches full linear reference");
      }
  return 0;
}

static int test_recovery_cache_lookup(void) {
  /* A small ring makes wraparound, protected old entries and release holes
   * explicit while exercising the ordinary store/release implementation. */
  transport_sent_cache_t cache = {.capacity = 16, .max_payload_bytes = 64};
  cache.entries = calloc(cache.capacity, sizeof(*cache.entries));
  CHECK(cache.entries, "lookup cache allocation");
  const moq_track_id_t tracks[2] = {{.type = MOQ_TRACK_DATA,
                                     .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                                     .name = "lookup"},
                                    {.type = MOQ_TRACK_DATA,
                                     .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                                     .name = "lookup"}};
  uint8_t payload = 7;
  moq_object_t object = {.data = &payload, .size = 1};
  for (size_t i = 0; i < 23; i++) {
    object.track_id = tracks[i % 2];
    object.group_id = i % 3;
    object.object_id = i / 6;
    CHECK(transport_sent_cache_store(&cache, &object, 1, 1, 1, i != 0),
          "fill and wrap cache around protected oldest entry");
  }
  CHECK(cache.count == 16 && cache.next_entry == 8 &&
            check_cache_lookups(&cache, tracks) == 0,
        "full wrapped lookup retains protected old identity");
  CHECK(transport_sent_cache_release_track(&cache, &tracks[0]) > 0 &&
            transport_sent_cache_release_through(&cache, &tracks[1], 1, 3) >
                0 &&
            check_cache_lookups(&cache, tracks) == 0,
        "lookup skips holes from track and checkpoint releases");
  for (size_t i = 23; i < 39; i++) {
    object.track_id = tracks[i % 2];
    object.group_id = i % 3;
    object.object_id = i / 6;
    CHECK(transport_sent_cache_store(&cache, &object, 1, 1, 1, true),
          "refill released holes and wrap again");
  }
  CHECK(check_cache_lookups(&cache, tracks) == 0,
        "lookup agrees after hole reuse and eviction");
  transport_sent_cache_release_track(&cache, &tracks[0]);
  transport_sent_cache_release_track(&cache, &tracks[1]);
  CHECK(cache.count == 0 && check_cache_lookups(&cache, tracks) == 0,
        "empty cache lookups preserve a nonzero insertion cursor");
  transport_sent_cache_destroy(&cache);
  return 0;
}

static int test_recovery_cache_nonmonotonic_ids(void) {
  transport_sent_cache_t cache = {.capacity = 4, .max_payload_bytes = 16};
  cache.entries = calloc(cache.capacity, sizeof(*cache.entries));
  CHECK(cache.entries, "nonmonotonic cache allocation");
  const moq_track_id_t tracks[2] = {{.type = MOQ_TRACK_DATA,
                                     .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                                     .name = "nonmonotonic"},
                                    {.type = MOQ_TRACK_DATA,
                                     .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                                     .name = "nonmonotonic"}};
  uint8_t payload[] = {1, 2, 3};
  moq_object_t object = {.track_id = tracks[0],
                         .group_id = 9,
                         .object_id = UINT64_MAX,
                         .data = payload,
                         .size = sizeof(payload)};
  CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, false),
        "retain largest possible object ID without overflow");
  object.group_id = 2;
  object.object_id = 7;
  CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, false),
        "retain lower object ID after larger ID");
  sent_object_cache_t *original =
      transport_sent_cache_find(&cache, &tracks[0], 2, 7);
  CHECK(original, "find lower object ID");
  original->next_repair_symbol = 12;
  object.track_id = tracks[1];
  CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, false),
        "same numeric ID on another track remains distinct");
  object.track_id = tracks[0];
  object.group_id = 3;
  CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, false),
        "same numeric ID in another group remains distinct");
  object.group_id = 2;
  CHECK(transport_sent_cache_store(&cache, &object, 3, 1, 3, true) &&
            cache.count == 4 && original->next_repair_symbol == 12 &&
            original->recovery_protected,
        "retry of lower ID preserves repair progress and protection");
  payload[0] = 9;
  CHECK(!transport_sent_cache_store(&cache, &object, 3, 1, 3, true) &&
            original->data[0] == 1,
        "conflicting lower-ID retry still validates retained contents");
  payload[0] = 1;
  CHECK(transport_sent_cache_release_through(&cache, &tracks[0], 9,
                                             UINT64_MAX) == 1 &&
            transport_sent_cache_find(&cache, &tracks[0], 2, 7) == original,
        "release of greatest ID preserves lower IDs and other groups");
  object.group_id = 4;
  object.object_id = 8;
  CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, false) &&
            transport_sent_cache_find(&cache, &tracks[0], 4, 8),
        "reuse release hole with a nonmonotonic ID");
  CHECK(transport_sent_cache_release_track(&cache, &tracks[0]) == 3 &&
            cache.count == 1 &&
            transport_sent_cache_find(&cache, &tracks[1], 2, 7),
        "release skips holes and preserves a different track");
  CHECK(transport_sent_cache_release_track(&cache, &tracks[1]) == 1 &&
            cache.count == 0,
        "release last live entry clears cache");
  object.group_id = 0;
  for (uint64_t id = 0; id < 8; id++) {
    object.object_id = id;
    CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, true),
          "small increasing IDs work after clear and through eviction");
  }
  for (uint64_t id = 0; id <= 8; id++)
    CHECK((transport_sent_cache_find(&cache, &tracks[0], 0, id) != NULL) ==
              (id >= 4 && id < 8),
          "lookup remains exact after clear, wrap and replacement");
  object.object_id = 8;
  CHECK(!transport_sent_cache_can_store(&cache, &object, false) &&
            !transport_sent_cache_store(&cache, &object, 2, 1, 3, false) &&
            cache.count == 4 && cache.payload_bytes == 12,
        "newer protected object is rejected without changing a full cache");
  object.object_id = 7;
  CHECK(transport_sent_cache_can_store(&cache, &object, false) &&
            transport_sent_cache_store(&cache, &object, 2, 1, 3, false),
        "retained retry remains admissible in full protected cache");
  CHECK(transport_sent_cache_release_through(&cache, &tracks[0], 0, 5) == 2,
        "leave only a retained suffix");
  cache.max_payload_bytes = 6;
  object.object_id = 8;
  CHECK(!transport_sent_cache_can_store(&cache, &object, false) &&
            !transport_sent_cache_store(&cache, &object, 2, 1, 3, false) &&
            cache.count == 2 && cache.payload_bytes == 6,
        "newer protected object observes byte cap while slots remain");
  object.object_id = 7;
  CHECK(transport_sent_cache_can_store(&cache, &object, false),
        "existing identical retry remains valid at byte cap");
  payload[0] = 9;
  CHECK(!transport_sent_cache_can_store(&cache, &object, false),
        "byte-pressure retry still rejects conflicting contents");
  transport_sent_cache_destroy(&cache);
  CHECK(cache.count == 0 && cache.object_id_upper_bound == 0,
        "destroy clears cache lookup bound");
  return 0;
}

static int test_udp_batch_boundaries(int family) {
  static const struct {
    size_t count;
    size_t lengths[3];
    size_t uniform_length;
    size_t override_index, override_length;
    size_t max_gso_segments;
  } cases[] = {{3, {40, 40, 40}, 0, 0, 0, 0}, {3, {80, 80, 40}, 0, 0, 0, 0},
               {2, {40, 80}, 0, 0, 0, 0},     {3, {80, 40, 80}, 0, 0, 0, 0},
               {2, {40, 0}, 0, 0, 0, 0},      {2, {0, 40}, 0, 0, 0, 0},
               {3, {80, 0, 40}, 0, 0, 0, 0},  {64, {0}, 1280, 64, 0, 0},
               {64, {0}, 1500, 64, 0, 0},     {64, {0}, 1280, 63, 13, 0},
               {64, {0}, 1280, 31, 0, 0},     {16, {0}, 1280, 16, 0, 6},
               {32, {0}, 1280, 32, 0, 6},     {64, {0}, 1280, 64, 0, 6}};
  int version = family == AF_INET ? 4 : 6;
  /* Match the UDP receive/GRO fixtures: both address families are required.
   * A missing IPv6 stack or loopback address is a visible setup failure. */
  int sender = socket(family, SOCK_DGRAM, 0);
  if (sender < 0) {
    fprintf(stderr, "UDP batch IPv%d sender socket: %s\n", version,
            strerror(errno));
    return 1;
  }
  int receiver = socket(family, SOCK_DGRAM, 0);
  if (receiver < 0) {
    fprintf(stderr, "UDP batch IPv%d receiver socket: %s\n", version,
            strerror(errno));
    close(sender);
    return 1;
  }
  struct sockaddr_storage address = {0};
  socklen_t address_len;
  if (family == AF_INET) {
    struct sockaddr_in *v4 = (struct sockaddr_in *)&address;
    v4->sin_family = AF_INET;
    v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address_len = sizeof(*v4);
  } else {
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&address;
    v6->sin6_family = AF_INET6;
    v6->sin6_addr = in6addr_loopback;
    address_len = sizeof(*v6);
  }
  if (bind(receiver, (struct sockaddr *)&address, address_len) != 0 ||
      getsockname(receiver, (struct sockaddr *)&address, &address_len) != 0) {
    fprintf(stderr, "UDP batch IPv%d receiver address: %s\n", version,
            strerror(errno));
    close(receiver);
    close(sender);
    return 1;
  }
  struct timeval timeout = {.tv_sec = 1};
  CHECK(setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) == 0,
        "UDP batch receive deadline");
  int receive_bytes = 1024 * 1024;
  CHECK(setsockopt(receiver, SOL_SOCKET, SO_RCVBUF, &receive_bytes,
                   sizeof(receive_bytes)) == 0,
        "large batch receive buffer");
  uint8_t payloads[64][1500], received[1600];
  for (size_t i = 0; i < 64; i++)
    for (size_t j = 0; j < sizeof(payloads[i]); j++)
      payloads[i][j] = (uint8_t)(i * 23 + j);
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    struct iovec datagrams[64];
    for (size_t i = 0; i < cases[c].count; i++)
      datagrams[i] = (struct iovec){.iov_base = payloads[i],
                                    .iov_len = cases[c].uniform_length
                                                   ? cases[c].uniform_length
                                                   : cases[c].lengths[i]};
    if (cases[c].uniform_length && cases[c].override_index < cases[c].count)
      datagrams[cases[c].override_index].iov_len = cases[c].override_length;
    CHECK(transport_udp_send_batch(sender, (struct sockaddr *)&address,
                                   address_len, datagrams, cases[c].count,
                                   cases[c].max_gso_segments) ==
              (ssize_t)cases[c].count,
          "UDP batch reports complete datagrams");
    for (size_t i = 0; i < cases[c].count; i++) {
      ssize_t size = recv(receiver, received, sizeof(received), MSG_TRUNC);
      if (size != (ssize_t)datagrams[i].iov_len)
        fprintf(stderr,
                "UDP batch IPv%d case %zu datagram %zu: received %zd, "
                "expected %zu\n",
                version, c, i, size, datagrams[i].iov_len);
      CHECK(size == (ssize_t)datagrams[i].iov_len &&
                memcmp(received, datagrams[i].iov_base, datagrams[i].iov_len) ==
                    0,
            "UDP batch preserves each datagram's length and contents");
    }
    CHECK(recv(receiver, received, sizeof(received), MSG_DONTWAIT) < 0 &&
              (errno == EAGAIN || errno == EWOULDBLOCK),
          "UDP batch does not create extra datagrams");
  }
  close(sender);
  close(receiver);
  printf("UDP batch IPv%d: %zu boundary cases passed\n", version,
         sizeof(cases) / sizeof(cases[0]));
  return 0;
}

static int test_assembler_growth_budget(void) {
  transport_t *transport = calloc(1, sizeof(*transport));
  frame_assembler_t assembler = {0}, other = {0};
  const uint16_t symbol_size = 64;
  size_t small = transport_assembler_required_bytes(8, symbol_size);
  size_t large = transport_assembler_required_bytes(16, symbol_size);
  CHECK(transport, "assembler budget fixture");
  transport->limits.max_assembler_memory_bytes = small + large;
  CHECK(transport_grow_assembler(transport, &assembler, 8, symbol_size) &&
            transport_grow_assembler(transport, &other, 8, symbol_size),
        "two assemblers share one allocation budget");
  assembler.total_symbols = 8;
  assembler.symbol_size = symbol_size;
  assembler.received_count = 2;
  assembler.received_mask[0] = assembler.received_mask[7] = true;
  memset(assembler.buffers[0], 13, symbol_size);
  memset(assembler.buffers[7], 29, symbol_size);
  uint8_t *old_storage = assembler.buffer_storage;
  uint8_t **old_pointers = assembler.buffers;
  /* Replacement fits after freeing the old buffers, but exceeds the shared
   * cap while both old and new buffers are live. */
  CHECK(
      !transport_grow_assembler(transport, &assembler, 16, symbol_size),
      "assembler growth reserves new allocation before crediting old storage");
  CHECK(transport->stats.resource_limit_errors == 1 &&
            transport->assembler_memory_bytes == 2 * small &&
            assembler.buffer_storage == old_storage &&
            assembler.buffers == old_pointers &&
            assembler.capacity_symbols == 8 && assembler.received_count == 2 &&
            assembler.received_mask[0] && assembler.received_mask[7] &&
            assembler.buffers[0][symbol_size - 1] == 13 &&
            assembler.buffers[7][symbol_size - 1] == 29,
        "rejected growth preserves incomplete data, allocation and charge");
  CHECK(transport_grow_assembler(transport, &assembler, 8, symbol_size) &&
            transport->stats.resource_limit_errors == 1,
        "capacity reuse needs no duplicate allocation allowance");
  transport_release_assembler(transport, &other);
  CHECK(transport->assembler_memory_bytes == small &&
            transport_grow_assembler(transport, &assembler, 16, symbol_size),
        "released peer allocation makes exact transient headroom available");
  CHECK(transport->assembler_memory_bytes == large &&
            assembler.capacity_symbols == 16 && assembler.received_count == 2 &&
            assembler.received_mask[0] && assembler.received_mask[7] &&
            assembler.buffers[0][symbol_size - 1] == 13 &&
            assembler.buffers[7][symbol_size - 1] == 29,
        "successful growth retains partial data and retires old charge");
  transport_release_assembler(transport, &assembler);
  CHECK(!transport->assembler_memory_bytes && !assembler.buffers &&
            !assembler.buffer_storage && !assembler.capacity_symbols,
        "terminal assembler release restores the shared budget");
  fprintf(stderr,
          "assembler growth budget: old=%zu new=%zu limit=%zu "
          "rejected_with_peer=1 recovery_preserved=1 final_bytes=0\n",
          small, large, small + large);
  free(transport);
  return 0;
}

static int test_subscription_state_lifetime(void) {
  transport_subscription_table_t table = {0};
  CHECK(transport_subscriptions_init(&table, 2), "sparse subscription fixture");
  for (size_t alias = 0; alias <= UINT8_MAX; alias++)
    CHECK(!transport_subscriptions_get_state(&table, alias),
          "inactive aliases allocate no recovery state");
  CHECK(transport_subscriptions_add(&table, MOQ_TRACK_DATA,
                                    MOQ_TRACK_FLAG_FEC_RATELESS, "one", 8),
        "allocate active state");
  transport_subscription_state_t *state =
      transport_subscriptions_get_state(&table, 8);
  CHECK(state != NULL, "active state exists");
  CHECK(transport_subscriptions_next_alias(&table, 8) == 9,
        "active alias is unavailable");
  state->object_gap.pending_mask = 3;
  CHECK(!transport_subscriptions_add(&table, MOQ_TRACK_DATA, 0, "other", 8) &&
            transport_subscriptions_get_state(&table, 8) == state &&
            state->object_gap.pending_mask == 3,
        "alias collision preserves incumbent recovery state");
  CHECK(transport_subscriptions_add(&table, MOQ_TRACK_DATA,
                                    MOQ_TRACK_FLAG_FEC_RATELESS, "one", 9) &&
            !transport_subscriptions_get_state(&table, 8) &&
            transport_subscriptions_get_state(&table, 9)
                    ->object_gap.pending_mask == 0,
        "alias remap retires obsolete recovery state");
  CHECK(transport_subscriptions_next_alias(&table, 8) == 8 &&
            transport_subscriptions_next_alias(&table, 9) == 10,
        "alias remap releases the old alias and reserves the new one");
  moq_track_id_t by_alias;
  CHECK(transport_subscriptions_find_by_alias(&table, 8, &by_alias) != 0 &&
            transport_subscriptions_find_by_alias(&table, 9, &by_alias) == 0 &&
            strcmp(by_alias.name, "one") == 0,
        "alias index migrates with subscription");
  transport_subscriptions_remove(&table, MOQ_TRACK_DATA, "one");
  CHECK(transport_subscriptions_find_by_alias(&table, 9, &by_alias) != 0,
        "removed alias cannot resolve stale track");
  CHECK(!transport_subscriptions_get_state(&table, 9) &&
            transport_subscriptions_next_alias(&table, 9) == 9,
        "unsubscribe releases recovery state");
  CHECK(transport_subscriptions_add(&table, MOQ_TRACK_DATA, 0, "two", 9) &&
            transport_subscriptions_get_state(&table, 9)
                    ->object_gap.pending_mask == 0,
        "reused alias starts without obsolete gaps");
  CHECK(transport_subscriptions_init(&table, 1) &&
            !transport_subscriptions_get_state(&table, 9),
        "reinitialization releases prior active state");
  CHECK(transport_subscriptions_add(&table, MOQ_TRACK_DATA, 0, "last",
                                    UINT8_MAX) &&
            transport_subscriptions_next_alias(&table, UINT8_MAX) == -1,
        "last occupied alias has no successor");
  transport_subscriptions_remove(&table, MOQ_TRACK_DATA, "last");
  CHECK(transport_subscriptions_next_alias(&table, UINT8_MAX) == UINT8_MAX,
        "last alias can be reused");
  transport_subscriptions_destroy(&table);
  return 0;
}

static int test_path_pacing_inputs(void) {
  transport_limits_t configured = {0}, resolved;
  char error[128];
  CHECK(
      transport_limits_resolve(&configured, &resolved, error, sizeof(error)) &&
          resolved.max_assemblers_per_connection == 1024,
      "default FEC receive-object cap supports high-BDP paths");
  configured.max_assemblers_per_connection = 1025;
  CHECK(!transport_limits_resolve(&configured, &resolved, error, sizeof(error)),
        "FEC receive-object cap remains bounded");
  configured.max_assemblers_per_connection = 64;
  CHECK(
      transport_limits_resolve(&configured, &resolved, error, sizeof(error)) &&
          resolved.max_assemblers_per_connection == 64,
      "application can set a lower receive-object cap");
  transport_t receiver = {.limits = resolved};
  transport_conn_t receiver_conn = {.transport = &receiver,
                                    .assembler_rx_rate = 100000000};
  CHECK(transport_assembler_window(&receiver_conn, 8, 1000) == 64,
        "derived BDP receive window is clamped by configured cap");
  receiver.limits.max_assemblers_per_connection = 1024;
  receiver_conn.assembler_limit = 0;
  CHECK(transport_assembler_window(&receiver_conn, 8, 1000) == 633,
        "derived receive window keeps two BDPs plus reorder floor");

  receiver_conn.assembler_limit = 0;
  receiver_conn.assembler_rx_rate = UINT64_MAX;
  CHECK(
      transport_assembler_window(&receiver_conn, 1, 1) == 1024,
      "saturated receive BDP clamps to cap without wrapping the reorder floor");

  transport_path_measurement_t measurement = {0};
  quicly_path_stats_t stats = {.cwnd = 1000000, .rtt_smoothed = 40};
  stats.local.sa.sa_family = stats.remote.sa.sa_family = AF_INET;
  CHECK(transport_path_measure(&measurement, &stats, 0, 1, 1000),
        "initialize path measurement");
  stats.acked = stats.sent = 90;
  stats.bytes_acked = 90000;
  CHECK(!transport_path_measure(&measurement, &stats, 0, 1, 1100),
        "complete ACK measurement window");
  CHECK(transport_path_probe_cap(&measurement, &stats, 1120, 1100) ==
            FP_FROM_INT(FP_SAFE_WHOLE),
        "clean RTT leaves an underused path's capacity estimate unbounded");
  stats.rtt_smoothed = 46;
  CHECK(transport_path_probe_cap(&measurement, &stats, 1120, 1100) ==
            FP_FROM_INT(750),
        "queue-induced RTT growth removes probe gain");
  CHECK(transport_path_probe_cap(&measurement, &stats, 1120, 1601) ==
            FP_FROM_INT(FP_SAFE_WHOLE),
        "stale ACK observations do not cap a recovered path");

  /* A long clean lifetime must not dilute a new loss burst. */
  stats.sent = 1000000;
  stats.acked = 1000000;
  stats.lost = 0;
  memset(&measurement, 0, sizeof(measurement));
  CHECK(transport_path_measure(&measurement, &stats, 0, 0, 2000),
        "initialize loss baseline after long clean lifetime");
  stats.sent += 100;
  stats.lost += 50;
  transport_path_measure(&measurement, &stats, 0, 0, 2100);
  CHECK(transport_path_recent_loss(&measurement) == FP_ONE / 2,
        "recent loss reflects burst independently of lifetime");
  stats.sent += 100;
  transport_path_measure(&measurement, &stats, 0, 0, 2200);
  CHECK(transport_path_recent_loss(&measurement) == 0,
        "clean window clears recent loss");
  stats.lost = 0;
  CHECK(transport_path_measure(&measurement, &stats, 0, 0, 2300) &&
            !measurement.loss_sampled,
        "loss counter reset starts fresh measurement");

  transport_path_budget_t budget = {0};
  CHECK(transport_path_budget_burst(FP_FROM_INT(100)) == 8 &&
            transport_path_budget_burst(FP_FROM_INT(2000)) == 64,
        "burst scales from low-rate latency budget to QUIC queue bound");
  CHECK(transport_path_budget_update(&budget, FP_FROM_INT(100), 1000000000) ==
            0,
        "empty path starts without reserved work");
  for (size_t i = 0; i < 8; i++)
    transport_path_budget_charge(&budget);
  CHECK(transport_path_budget_wait(&budget, 8, 3) == 30000000,
        "complete allocation waits for its serialized symbols");
  CHECK(transport_path_budget_update(&budget, FP_FROM_INT(100), 1010000000) ==
            7,
        "paced budget releases work at the measured rate");
  return 0;
}

static int test_stream_path_selection(void) {
  /* Six-packet batch, equal latency: 1000 packets/s at 1% loss still beats
   * 900 packets/s without loss. The one-symbol FEC optimizer picks path 1
   * because it charges path 0 for a whole additional parity packet. */
  path_t paths[3] = {
      {.b = FP_FROM_INT(1000),
       .p = FP_FROM_FLOAT(0.01f),
       .l = FP_FROM_FLOAT(0.05f),
       .q = 5},
      {.b = FP_FROM_INT(900), .l = FP_FROM_FLOAT(0.05f), .q = 5},
      {.b = FP_FROM_INT(2000), .l = FP_FROM_FLOAT(0.05f), .q = 5}};
  CHECK(transport_stream_select_path(paths, 2, 0) == 0,
        "small loss does not charge reliable streams for FEC parity");
  CHECK(transport_stream_select_path(paths, 3, 0) == 2 &&
            transport_stream_select_path(paths, 3, 1U << 2) == 0 &&
            transport_stream_select_path(paths, 3, (1U << 2) | 1U) == 1 &&
            transport_stream_select_path(paths, 3, 7U) == SIZE_MAX,
        "empty-send fallbacks retain completion ordering without retries");

  paths[0].p = FP_ONE / 2;
  CHECK(transport_stream_select_path(paths, 2, 0) == 1 &&
            transport_stream_select_path(paths, 3, 1U << 2) == 1,
        "substantial retransmission cost affects first choice and fallback");
  paths[0].p = 0;
  paths[0].q = 100;
  CHECK(transport_stream_select_path(paths, 2, 0) == 1,
        "queued and in-flight work can outweigh a faster stream path");
  paths[0].q = 5;
  paths[0].l = FP_FROM_FLOAT(0.06f);
  CHECK(transport_stream_select_path(paths, 2, 0) == 1,
        "propagation latency participates in stream selection");

  paths[0] = paths[1];
  CHECK(transport_stream_select_path(paths, 2, 0) == 0,
        "equal completion times preserve stable path order");
  paths[0].p = FP_ONE;
  CHECK(transport_stream_select_path(paths, 2, 0) == 1,
        "total-loss paths are ineligible");
  paths[1].b = 0;
  CHECK(transport_stream_select_path(paths, 2, 0) == SIZE_MAX,
        "no positive delivery rate means no selected path");
  paths[0].b = 1;
  paths[0].p = FP_ONE / 2;
  CHECK(transport_stream_select_path(paths, 2, 0) == SIZE_MAX,
        "rounded-to-zero effective rate cannot cause division by zero");
  paths[0].b = FP_ONE / 2;
  paths[0].p = 0;
  CHECK(transport_stream_select_path(paths, 2, 0) == 0,
        "positive fractional rates remain usable");
  paths[0].q = FP_SAFE_WHOLE;
  paths[1].b = FP_FROM_INT(1);
  CHECK(transport_stream_select_path(paths, 2, 0) == 1,
        "maximum bounded queue does not wrap into an early completion");
  CHECK(transport_stream_select_path(paths, 0, 0) == SIZE_MAX,
        "empty path list has no selection");
  path_t many[TRANSPORT_MAX_QUIC_PATHS] = {0};
  many[0].b = FP_ONE;
  many[63].b = 2 * FP_ONE;
  CHECK(transport_stream_select_path(many, TRANSPORT_MAX_QUIC_PATHS, 0) == 63 &&
            transport_stream_select_path(many, TRANSPORT_MAX_QUIC_PATHS,
                                         UINT64_C(1) << 63) == 0 &&
            transport_stream_select_path(many, TRANSPORT_MAX_QUIC_PATHS,
                                         UINT64_MAX) == SIZE_MAX,
        "all QUIC path slots participate in selection and exclusion");
  CHECK(transport_stream_select_path(many, TRANSPORT_MAX_QUIC_PATHS + 1U, 0) ==
            SIZE_MAX,
        "out-of-range path count cannot overflow the exclusion mask");
  return 0;
}

static int test_datagram_schedule(void) {
  path_state_t states[3] = {
      {.b_ewma = FP_FROM_INT(100), .q_ewma = 5, .initialized = true},
      {.b_ewma = FP_FROM_INT(200), .q_ewma = 10, .initialized = true},
      {.b_ewma = FP_FROM_INT(400), .q_ewma = 20, .initialized = true}};
  pathflow_context_t context = {0};
  transport_schedule_t schedule;
  size_t round_robin = 0;
  CHECK(transport_schedule_build(&context, states, 3, 7, 1200, false, 1,
                                 &round_robin, &schedule) &&
            schedule.paths[0].x == 1 && schedule.paths[1].x == 2 &&
            schedule.paths[2].x == 4 && schedule.parity_symbols == 0,
        "datagrams distribute every symbol by capacity without parity");
  for (size_t i = 0; i < 3; i++) {
    CHECK(schedule.paths[i].b == states[i].b_ewma &&
              schedule.paths[i].l == states[i].l_ewma &&
              schedule.paths[i].p == states[i].p_ewma &&
              schedule.paths[i].q == states[i].q_ewma &&
              schedule.paths[i].m == 0,
          "planned datagram work does not alter path samples");
  }
  CHECK(round_robin == 0, "datagrams preserve the FEC round-robin cursor");

  states[0].p_ewma = states[1].p_ewma = FP_ONE;
  CHECK(transport_schedule_build(&context, states, 3, 7, 1200, false, 1,
                                 &round_robin, &schedule) &&
            schedule.paths[0].x == 0 && schedule.paths[1].x == 0 &&
            schedule.paths[2].x == 7 && schedule.parity_symbols == 0,
        "datagrams skip paths without an effective delivery rate");
  states[2].p_ewma = FP_ONE;
  CHECK(!transport_schedule_build(&context, states, 3, 7, 1200, false, 1,
                                  &round_robin, &schedule) &&
            schedule.paths[0].x == 0 && schedule.paths[1].x == 0 &&
            schedule.paths[2].x == 0 && schedule.parity_symbols == 0,
        "datagram scheduling fails when no path can deliver");
  return 0;
}

static int test_address_identity(void) {
  struct sockaddr_in6 a = {
      .sin6_family = AF_INET6, .sin6_port = htons(443), .sin6_scope_id = 4};
  a.sin6_addr.s6_addr[0] = 0xfe;
  a.sin6_addr.s6_addr[1] = 0x80;
  a.sin6_addr.s6_addr[15] = 1;
  struct sockaddr_in6 b = a;
  const struct sockaddr *sa = (const struct sockaddr *)&a;
  const struct sockaddr *sb = (const struct sockaddr *)&b;
  CHECK(transport_address_equal(sa, sb) && transport_endpoint_equal(sa, sb),
        "identical scoped IPv6 endpoints match");
  b.sin6_scope_id++;
  CHECK(!transport_address_equal(sa, sb) && !transport_endpoint_equal(sa, sb),
        "same link-local IP on distinct interfaces identifies distinct paths");
  b.sin6_scope_id = a.sin6_scope_id;
  b.sin6_port = htons(444);
  CHECK(transport_address_equal(sa, sb) && !transport_endpoint_equal(sa, sb),
        "ports distinguish QUIC endpoints but not physical sockets");
  struct sockaddr_storage local = {0};
  memcpy(&local, &b, sizeof(b));
  quicly_path_stats_t stats = {0};
  memcpy(&stats.local, &a, sizeof(a));
  ((struct sockaddr_in6 *)&local)->sin6_port = 0;
  CHECK(transport_path_matches_local(&stats, &local),
        "path lookup uses the same scoped address identity");
  ((struct sockaddr_in6 *)&local)->sin6_port = htons(443);
  CHECK(transport_path_matches_local(&stats, &local),
        "path lookup matches exact endpoint when port is bound");
  ((struct sockaddr_in6 *)&local)->sin6_port = htons(444);
  CHECK(!transport_path_matches_local(&stats, &local),
        "path lookup rejects distinct port when port is bound");
  ((struct sockaddr_in6 *)&local)->sin6_port = 0;
  ((struct sockaddr_in6 *)&local)->sin6_scope_id++;
  CHECK(!transport_path_matches_local(&stats, &local),
        "path lookup rejects another interface with the same link-local IP");
  struct sockaddr_in any4 = {.sin_family = AF_INET,
                             .sin_addr.s_addr = INADDR_ANY};
  CHECK(transport_address_is_wildcard((const struct sockaddr *)&any4),
        "0.0.0.0 is identified as wildcard");
  struct sockaddr_in6 any6 = {.sin6_family = AF_INET6,
                              .sin6_addr = IN6ADDR_ANY_INIT};
  CHECK(transport_address_is_wildcard((const struct sockaddr *)&any6),
        ":: is identified as wildcard");
  CHECK(!transport_address_is_wildcard(sa),
        "link-local address is not wildcard");
  CHECK(!transport_address_equal(sa, NULL) &&
            !transport_endpoint_equal(NULL, sb),
        "absent addresses cannot identify a path");
  return 0;
}

static int test_path_estimates(void) {
  quicly_path_stats_t fast = {
      .cwnd = 100000, .rtt_smoothed = 100, .sent = 100, .lost = 0};
  quicly_path_stats_t slow = fast;
  slow.cwnd = 10000;
  path_t samples[2] = {transport_path_estimate(&fast, 0, 0, 1000, 0),
                       transport_path_estimate(&slow, 0, 0, 1000, 0)};
  CHECK(samples[0].b == FP_FROM_INT(1000) && samples[1].b == FP_FROM_INT(100) &&
            samples[0].l == samples[1].l,
        "equal RTT paths retain their own ten-to-one window rates");
  path_state_t states[2] = {0};
  for (size_t i = 0; i < 2; i++)
    transport_path_update_state(&states[i], &samples[i], false);
  pathflow_context_t context = {0};
  transport_schedule_t schedule;
  size_t round_robin = 0;
  CHECK(transport_schedule_build(&context, states, 2, 100, 1000, true, 1,
                                 &round_robin, &schedule) &&
            schedule.paths[0].m >= 90 && schedule.paths[1].m <= 10,
        "measured window asymmetry changes FEC allocation");

  samples[0] = transport_path_estimate(&fast, 1000, 0, 1000, 0);
  transport_path_update_state(&states[0], &samples[0], false);
  CHECK(transport_schedule_build(&context, states, 2, 50, 1000, true, 1,
                                 &round_robin, &schedule) &&
            schedule.paths[0].m == 0 && schedule.paths[1].m == 50,
        "a queued fast path yields to an empty slow path before another tick");
  CHECK(schedule.parity_symbols == 1 && schedule.paths[0].x == 0 &&
            schedule.paths[1].x == 51 &&
            transport_path_select_physical(schedule.paths, 2, 50) == 1 &&
            transport_path_select_physical(schedule.paths, 2, 51) == SIZE_MAX,
        "minimum parity has an explicit allocation away from the queued path");
  samples[0].q = 0;
  transport_path_update_state(&states[0], &samples[0], false);
  CHECK(states[0].q_ewma == 0 &&
            transport_schedule_build(&context, states, 2, 100, 1000, true, 1,
                                     &round_robin, &schedule) &&
            schedule.paths[0].m >= 90,
        "drained queue immediately restores fast-path allocation");
  samples[0].b = FP_FROM_INT(200);
  samples[0].q = 1;
  transport_path_update_state(&states[0], &samples[0], false);
  CHECK(states[0].q_ewma == 1 && states[0].b_ewma == FP_FROM_INT(1000),
        "publication refresh sees a one-packet queue without resampling rate");
  transport_path_update_state(&states[0], &samples[0], true);
  CHECK(states[0].b_ewma > FP_FROM_INT(900) &&
            states[0].b_ewma < FP_FROM_INT(1000) && states[0].q_ewma == 1,
        "periodic samples smooth rate but preserve current queue occupancy");

  fast.bytes_in_flight = UINT32_MAX;
  path_t queued = transport_path_estimate(&fast, 3, 1501, 1000, 0);
  CHECK(queued.q == 5,
        "combine QUIC frames and rounded socket bytes without bytes in flight");
  queued = transport_path_estimate(&slow, 0, 1501, 1000, 0);
  CHECK(queued.q == 2, "shared socket backlog applies to another peer");
  queued = transport_path_estimate(&fast, SIZE_MAX, SIZE_MAX, 1, 0);
  CHECK(queued.q == FP_SAFE_WHOLE,
        "large queue inputs saturate without overflow");

  quicly_path_stats_t fractional = {.cwnd = 1500,
                                    .rtt_smoothed = 3000,
                                    .sent = UINT64_MAX,
                                    .lost = UINT64_MAX / 2};
  path_t sample = transport_path_estimate(&fractional, 0, 0, 1000, 0);
  CHECK(sample.b == FP_ONE / 2 && sample.p > FP_ONE / 2 - 2 &&
            sample.p <= FP_ONE / 2,
        "fractional rates and large lifetime loss counters retain precision");
  fractional.lost = UINT64_MAX;
  fractional.sent = 1;
  sample = transport_path_estimate(&fractional, 0, 0, 1000, 0);
  CHECK(sample.p == FP_ONE, "loss probability is bounded");
  fractional.cwnd = UINT32_MAX;
  fractional.rtt_smoothed = 1;
  sample = transport_path_estimate(&fractional, 0, 0, 1, 0);
  CHECK(sample.b == FP_FROM_INT(FP_SAFE_WHOLE), "large rates are bounded");
  fractional.cwnd = 1;
  fractional.rtt_smoothed = UINT32_MAX;
  sample = transport_path_estimate(&fractional, 0, 0, SIZE_MAX, 0);
  CHECK(sample.b > 0, "very slow paths retain positive optimizer throughput");
  fractional.rtt_smoothed = 0;
  sample = transport_path_estimate(&fractional, 0, 0, 1000, 0);
  CHECK(sample.b == FP_FROM_INT(100) && sample.l == FP_FROM_FLOAT(0.050f),
        "unmeasured RTT uses independent defaults rather than a fictitious "
        "millisecond");
  sample = transport_path_estimate(NULL, 0, 0, 1000, FP_ONE / 100);
  CHECK(sample.b == FP_FROM_INT(100) &&
            sample.l == FP_FROM_FLOAT(0.050f) + FP_ONE / 100,
        "missing path defaults and relative delay use consistent units");
  memset(states, 0, sizeof(states));
  CHECK(transport_schedule_build(&context, states, 2, 10, 1000, true, 1,
                                 &round_robin, &schedule) &&
            schedule.paths[0].b == FP_FROM_INT(100) &&
            schedule.paths[1].l == FP_FROM_FLOAT(0.050f),
        "scheduler cold start uses the same independent defaults");
  states[0] = (path_state_t){
      .initialized = true, .b_ewma = FP_FROM_INT(1000), .p_ewma = FP_ONE};
  states[1] = (path_state_t){.initialized = true,
                             .b_ewma = FP_FROM_INT(100),
                             .l_ewma = FP_FROM_FLOAT(0.05f)};
  CHECK(transport_schedule_build(&context, states, 2, 4, 1000, true, 2,
                                 &round_robin, &schedule) &&
            schedule.paths[0].m == 0 && schedule.paths[0].x == 0 &&
            schedule.paths[1].x == 5,
        "minimum parity does not revive a fast path rejected for total loss");
  return 0;
}

static int test_pktinfo_preservation(void) {
  int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
  CHECK(server_fd >= 0, "server socket creation");
  CHECK(transport_udp_enable_recv_pktinfo(server_fd, AF_INET),
        "enable IP_PKTINFO on server socket");

  struct sockaddr_in bind_addr = {
      .sin_family = AF_INET,
      .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
      .sin_port = 0,
  };
  CHECK(bind(server_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) == 0,
        "bind server socket");
  socklen_t addr_len = sizeof(bind_addr);
  CHECK(getsockname(server_fd, (struct sockaddr *)&bind_addr, &addr_len) == 0,
        "get server bound port");

  int client_fd = socket(AF_INET, SOCK_DGRAM, 0);
  CHECK(client_fd >= 0, "client socket creation");

  uint8_t ping_data[16] = "ping";
  struct iovec iov = {.iov_base = ping_data, .iov_len = sizeof(ping_data)};
  CHECK(transport_udp_send_batch_pktinfo(
            client_fd, (const struct sockaddr *)&bind_addr, sizeof(bind_addr),
            NULL, 0, &iov, 1, 0, 0) == 1,
        "client send to server");

  transport_udp_datagram_t dgram = {0};
  ssize_t received = transport_udp_receive_batch(server_fd, &dgram, 1);
  CHECK(received == 1, "server receive datagram");
  CHECK(dgram.destination.ss_family == AF_INET,
        "destination family is AF_INET");
  const struct sockaddr_in *dst =
      (const struct sockaddr_in *)&dgram.destination;
  CHECK(dst->sin_addr.s_addr == htonl(INADDR_LOOPBACK),
        "pktinfo captured local arrival address 127.0.0.1");

  /* test egress source address preservation */
  uint8_t pong_data[16] = "pong";
  struct iovec reply_iov = {.iov_base = pong_data,
                            .iov_len = sizeof(pong_data)};
  CHECK(transport_udp_send_batch_pktinfo(
            server_fd, (const struct sockaddr *)&dgram.source,
            sizeof(dgram.source), (const struct sockaddr *)&dgram.destination,
            dgram.ifindex, &reply_iov, 1, 0, 0) == 1,
        "server send reply with preserved destination as source");

  close(client_fd);
  close(server_fd);
  return 0;
}

int main(void) {
  CHECK(test_address_identity() == 0, "scoped address and endpoint identity");
  CHECK(test_pktinfo_preservation() == 0,
        "IP_PKTINFO destination capture and egress preservation");
  CHECK(test_stream_path_selection() == 0,
        "reliable stream path selection without FEC parity");
  CHECK(test_datagram_schedule() == 0,
        "capacity-aware datagram scheduling without FEC parity");
  CHECK(test_path_pacing_inputs() == 0, "per-path ACK probing and pacing");
  CHECK(test_path_estimates() == 0,
        "heterogeneous path inputs and allocations");
  CHECK(test_subscription_state_lifetime() == 0,
        "sparse recovery state lifetime");
  CHECK(test_assembler_growth_budget() == 0,
        "assembler transient allocation budget");
  CHECK(test_udp_batch_boundaries(AF_INET) == 0, "IPv4 UDP batch boundaries");
  CHECK(test_udp_batch_boundaries(AF_INET6) == 0, "IPv6 UDP batch boundaries");
  CHECK(test_recovery_cache_protection() == 0, "recovery cache protection");
  CHECK(test_recovery_cache_lookup() == 0, "sparse wrapped cache lookup");
  CHECK(test_recovery_cache_nonmonotonic_ids() == 0,
        "nonmonotonic recovery cache identities");
  transport_limits_t configured = {0};
  transport_limits_t resolved_limits;
  char limit_error[128];
  CHECK(transport_limits_resolve(&configured, &resolved_limits, limit_error,
                                 sizeof(limit_error)),
        "default limit resolution");
  CHECK(resolved_limits.max_connections == TRANSPORT_DEFAULT_MAX_CONNECTIONS &&
            resolved_limits.max_subscriptions_per_connection ==
                TRANSPORT_DEFAULT_MAX_SUBSCRIPTIONS &&
            resolved_limits.max_aggregate_repair_requests_per_second ==
                TRANSPORT_DEFAULT_MAX_AGGREGATE_REPAIR_REQUESTS_PER_SECOND &&
            resolved_limits.max_udp_payload_size == 1280,
        "default limits");
  transport_sent_cache_t derived_cache = {0};
  CHECK(transport_sent_cache_init(&derived_cache, 128U * 1024U * 1024U,
                                  TRANSPORT_MAX_FEC_GROUP_SIZE) &&
            derived_cache.capacity > TRANSPORT_SENT_CACHE_SIZE &&
            derived_cache.capacity <= TRANSPORT_SENT_CACHE_MAX_SIZE,
        "recovery cache slots scale with configured byte budget");
  transport_sent_cache_destroy(&derived_cache);
  configured.max_aggregate_repair_requests_per_second = UINT16_MAX + 1U;
  CHECK(!transport_limits_resolve(&configured, &resolved_limits, limit_error,
                                  sizeof(limit_error)),
        "aggregate repair hard limit rejection");
  configured.max_aggregate_repair_requests_per_second = 0;
  configured.max_egress_packets_per_socket = 63;
  CHECK(!transport_limits_resolve(&configured, &resolved_limits, limit_error,
                                  sizeof(limit_error)),
        "unsafe egress limit rejection");

  transport_egress_t egress;
  CHECK(transport_egress_init(&egress, 64, 64U * 1500U), "egress init");
  CHECK(transport_egress_can_accept(&egress, 64, 64U * 1500U) &&
            !transport_egress_can_accept(&egress, 65, 64U * 1500U),
        "egress reservation bounds");
  transport_egress_destroy(&egress);

  arena_t arena;
  CHECK(transport_arena_init(&arena, 64), "arena init");
  CHECK(transport_arena_alloc(&arena, 16) != NULL, "arena allocation");
  CHECK(transport_arena_alloc(&arena, 128) != NULL, "arena fallback");
  CHECK(arena.fallback_count == 1, "arena fallback ownership");
  transport_arena_reset(&arena);
  CHECK(arena.offset == 0 && arena.fallback_count == 0, "arena reset");
  transport_arena_destroy(&arena);

  frame_assembler_t assembler = {0};
  CHECK(transport_assembler_grow(&assembler, 2, 8), "assembler allocation");
  CHECK(transport_assembler_capacity_bytes(&assembler) ==
            transport_assembler_required_bytes(2, 8),
        "assembler memory accounting");
  memset(assembler.buffers[0], 0x5a, 8);
  assembler.received_mask[0] = true;
  assembler.total_symbols = 2;
  assembler.symbol_size = 8;
  CHECK(transport_assembler_grow(&assembler, 4, 16), "assembler growth");
  CHECK(assembler.buffers[0][0] == 0x5a && assembler.received_mask[0],
        "assembler growth preserves state");
  transport_assembler_release(&assembler);
  CHECK(assembler.buffers == NULL, "assembler release");

  transport_subscription_table_t subscriptions = {0};
  moq_track_id_t track = {
      .type = MOQ_TRACK_DATA, .flags = MOQ_TRACK_FLAG_RELIABLE, .name = "data"};
  CHECK(transport_subscriptions_add(&subscriptions, track.type, track.flags,
                                    track.name, 8),
        "subscription add");
  uint8_t alias = 0;
  CHECK(transport_subscriptions_find_alias(&subscriptions, &track, &alias) ==
                0 &&
            alias == 8,
        "subscription alias lookup");
  moq_track_id_t resolved;
  CHECK(transport_subscriptions_find_by_alias(&subscriptions, 8, &resolved) ==
                0 &&
            strcmp(resolved.name, track.name) == 0,
        "subscription track lookup");
  quicly_stream_t *fake_stream = (quicly_stream_t *)(uintptr_t)1;
  CHECK(transport_subscriptions_bind_stream(&subscriptions, 8, fake_stream),
        "subscription stream binding");
  transport_subscriptions_clear_stream(&subscriptions, fake_stream);
  CHECK(transport_subscriptions_find(&subscriptions, &track)->stream == NULL &&
            transport_subscriptions_find(&subscriptions, &track)
                    ->ingress_stream == NULL,
        "subscription stream clearing");
  CHECK(transport_subscriptions_next_alias(&subscriptions, 8) == 9,
        "subscription next alias");
  transport_subscriptions_remove(&subscriptions, track.type, track.name);
  CHECK(!transport_subscriptions_contains(&subscriptions, &track),
        "subscription removal");
  transport_subscriptions_destroy(&subscriptions);

  transport_subscription_table_t bounded_subscriptions = {0};
  CHECK(transport_subscriptions_init(&bounded_subscriptions, 1),
        "bounded subscription init");
  CHECK(transport_subscriptions_add(&bounded_subscriptions, MOQ_TRACK_DATA, 0,
                                    "one", 8) &&
            !transport_subscriptions_add(&bounded_subscriptions, MOQ_TRACK_DATA,
                                         0, "alias-collision", 8) &&
            !transport_subscriptions_add(&bounded_subscriptions, MOQ_TRACK_DATA,
                                         0, "two", 9),
        "subscription capacity");
  transport_subscriptions_destroy(&bounded_subscriptions);

  path_t paths[3] = {{.x = 2}, {.x = 1}, {.x = 3}};
  CHECK(transport_path_select_physical(paths, 3, 0) == 0 &&
            transport_path_select_physical(paths, 3, 2) == 1 &&
            transport_path_select_physical(paths, 3, 5) == 2,
        "physical path selection");
  CHECK(transport_path_select_physical(paths, 3, 6) == SIZE_MAX &&
            transport_path_select_physical(NULL, 0, 0) == SIZE_MAX,
        "unallocated symbols cannot silently fall back to the first path");

  path_state_t path_states[2] = {
      {.b_ewma = FP_FROM_INT(100), .l_ewma = FP_FROM_FLOAT(0.01f)},
      {.b_ewma = FP_FROM_INT(50), .l_ewma = FP_FROM_FLOAT(0.02f)}};
  pathflow_context_t scheduler_context = {0};
  size_t round_robin = 0;
  transport_schedule_t schedule;
  CHECK(transport_schedule_build(&scheduler_context, path_states, 2, 5, 1100,
                                 false, 1, &round_robin, &schedule) &&
            schedule.paths[0].x == 4 && schedule.paths[1].x == 1 &&
            schedule.parity_symbols == 0,
        "non-FEC schedule follows estimated completion time");
  CHECK(transport_schedule_build(&scheduler_context, path_states, 2, 1, 1100,
                                 true, 1, &round_robin, &schedule) &&
            schedule.paths[0].x == 1 && round_robin == 1,
        "single-symbol round robin schedule");

  const uint8_t object_data[] = {1, 2, 3, 4};
  moq_object_t object = {.track_id = track,
                         .group_id = 10,
                         .object_id = 20,
                         .data = object_data,
                         .size = sizeof(object_data),
                         .priority = 2};
  transport_sent_cache_t sent_cache = {0};
  CHECK(transport_sent_cache_store(&sent_cache, &object, 3, 2, 2, true),
        "sent-object cache store");
  sent_object_cache_t *cached =
      transport_sent_cache_find(&sent_cache, &track, 10, 20);
  CHECK(cached && cached->size == sizeof(object_data) && cached->data[3] == 4,
        "sent-object cache roundtrip");
  size_t next_cache_entry = sent_cache.next_entry;
  CHECK(transport_sent_cache_store(&sent_cache, &object, 4, 2, 2, true) &&
            sent_cache.next_entry == next_cache_entry &&
            cached->total_symbols == 4,
        "publication retry reuses sent-object cache identity");
  const uint8_t conflicting_data[] = {4, 3, 2, 1};
  object.data = conflicting_data;
  CHECK(!transport_sent_cache_store(&sent_cache, &object, 4, 2, 2, true),
        "conflicting sent-object identity rejected");
  object.data = object_data;
  moq_track_id_t different_profile = track;
  different_profile.flags ^= MOQ_TRACK_FLAG_FEC_RATELESS;
  CHECK(transport_sent_cache_find(&sent_cache, &different_profile, 10, 20) ==
            NULL,
        "sent-object cache includes track flags in identity");

  uint16_t missing_symbol = 1;
  transport_repair_batch_t repair;
  transport_fec_cache_t repair_fec_cache = {0};
  CHECK(transport_repair_build(&repair_fec_cache, cached, false,
                               &missing_symbol, 1, &repair),
        "repair batch build");
  CHECK(repair.count == 1 && repair.indices[0] == 1 &&
            repair.symbols[0] == object_data[2],
        "repair returns requested data symbol");
  transport_repair_batch_destroy(&repair);
  uint16_t parity_symbol = 2;
  CHECK(transport_repair_build(&repair_fec_cache, cached, false, &parity_symbol,
                               1, &repair) &&
            repair.total_symbols == cached->total_symbols,
        "repair preserves original FEC dimensions");
  transport_repair_batch_destroy(&repair);

  uint16_t outside_geometry = cached->total_symbols;
  CHECK(!transport_repair_build(&repair_fec_cache, cached, false,
                                &outside_geometry, 1, &repair),
        "fixed repair rejects requests that would change encoding geometry");

  moq_track_id_t rateless_track = {.type = MOQ_TRACK_DATA,
                                   .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                                   .name = "rateless-data"};
  moq_object_t rateless_object = object;
  rateless_object.track_id = rateless_track;
  transport_sent_cache_t rateless_cache = {0};
  CHECK(transport_sent_cache_store(&rateless_cache, &rateless_object, 2, 2, 2,
                                   true),
        "rateless sent-object cache store");
  sent_object_cache_t *rateless_cached = transport_sent_cache_find(
      &rateless_cache, &rateless_track, object.group_id, object.object_id);
  CHECK(rateless_cached && rateless_cached->next_repair_symbol == 2 &&
            transport_repair_build_rateless(&repair_fec_cache, rateless_cached,
                                            2, &repair) &&
            repair.count == 2 && repair.indices[0] == 2 &&
            repair.indices[1] == 3 && repair.total_symbols == 4 &&
            rateless_cached->next_repair_symbol == 2,
        "rateless repair reserves fresh ESIs transactionally");
  uint8_t decode_data_0[2] = {1, 2};
  uint8_t decode_data_1[2] = {0};
  uint8_t decode_repair_0[2];
  uint8_t decode_repair_1[2];
  memcpy(decode_repair_0, repair.symbols, 2);
  memcpy(decode_repair_1, repair.symbols + 2, 2);
  uint8_t *decode_blocks[] = {decode_data_0, decode_data_1, decode_repair_0,
                              decode_repair_1};
  bool decode_missing[] = {false, true, false, false};
  fec_t *rateless_decoder =
      transport_fec_cache_get(&repair_fec_cache, FEC_RAPTORQ, 2, 2, 2);
  CHECK(rateless_decoder &&
            fec_decode(rateless_decoder, decode_blocks, decode_missing) &&
            decode_data_1[0] == 3 && decode_data_1[1] == 4,
        "fresh rateless repair recovers a missing source symbol");
  CHECK(transport_repair_commit_rateless(rateless_cached, &repair, 2) &&
            rateless_cached->next_repair_symbol == 4,
        "rateless repair consumes only admitted ESIs");
  transport_repair_batch_destroy(&repair);
  CHECK(transport_repair_build_rateless(&repair_fec_cache, rateless_cached, 3,
                                        &repair) &&
            repair.indices[0] == 4 && repair.indices[2] == 6 &&
            transport_repair_commit_rateless(rateless_cached, &repair, 1) &&
            rateless_cached->next_repair_symbol == 5,
        "partial admission leaves unused rateless ESIs available");
  transport_repair_batch_destroy(&repair);
  rateless_cached->next_repair_symbol = QLINQ_FEC_MAX_TOTAL_SYMBOLS;
  CHECK(transport_repair_build_systematic_fallback(
            &repair_fec_cache, rateless_cached, 4, &repair) &&
            repair.count == 2 && repair.indices[0] == 0 &&
            repair.indices[1] == 1 &&
            transport_repair_commit_systematic_fallback(rateless_cached,
                                                        &repair, 1) &&
            rateless_cached->next_systematic_repair_symbol == 1,
        "ESI exhaustion falls back to systematic source symbols");
  transport_repair_batch_destroy(&repair);

  transport_t negotiation_transport = {0};
  transport_conn_t negotiation_conn = {.transport = &negotiation_transport};
  negotiation_transport.owner_thread = pthread_self();
  negotiation_transport.client_conn = &negotiation_conn;
  negotiation_transport.repair_mode = TRANSPORT_REPAIR_MODE_AUTO;
  negotiation_conn.peer_capabilities = QLINQ_WIRE_CAP_FEC_RATELESS;
  CHECK(transport_get_effective_repair_mode(
            &negotiation_transport, &negotiation_conn, &rateless_track) ==
            TRANSPORT_REPAIR_MODE_INDEXED,
        "legacy rateless peer falls back to indexed repair");
  negotiation_conn.peer_capabilities |= QLINQ_WIRE_CAP_RATELESS_REPAIR;
  CHECK(transport_get_effective_repair_mode(
            &negotiation_transport, &negotiation_conn, &rateless_track) ==
            TRANSPORT_REPAIR_MODE_RATELESS,
        "rateless capability enables degree-of-freedom repair");
  negotiation_transport.repair_mode = TRANSPORT_REPAIR_MODE_INDEXED;
  CHECK(transport_get_effective_repair_mode(
            &negotiation_transport, &negotiation_conn, &rateless_track) ==
            TRANSPORT_REPAIR_MODE_INDEXED,
        "indexed preference overrides rateless capability");

  transport_repair_limiter_t limiter = {0};
  CHECK(transport_repair_limiter_take(&limiter, 4, 100) &&
            transport_repair_limiter_take(&limiter, 4, 100) &&
            transport_repair_limiter_take(&limiter, 4, 100) &&
            transport_repair_limiter_take(&limiter, 4, 100) &&
            !transport_repair_limiter_take(&limiter, 4, 100) &&
            transport_repair_limiter_take(&limiter, 4, 350),
        "repair limiter burst and smooth refill");
  CHECK(
      !transport_repair_limiter_take(&limiter, 4, 349) &&
          limiter.last_refill_ms == 350 && !limiter.tokens_milli &&
          transport_repair_limiter_wait_ms(&limiter, 4, 349) == 251 &&
          !transport_repair_limiter_take(&limiter, 4, 599) &&
          transport_repair_limiter_take(&limiter, 4, 600),
      "stale tick timestamps cannot refill feedback tokens or schedule early");
  limiter = (transport_repair_limiter_t){0};
  CHECK(
      transport_repair_limiter_take(&limiter, 1, 0) &&
          !transport_repair_limiter_take(&limiter, 1, 0) &&
          transport_repair_limiter_wait_ms(&limiter, 1, -1) == 1001 &&
          transport_repair_limiter_take(&limiter, 1, 1000),
      "zero-time initialization and backwards clock preserve the burst bound");
  limiter = (transport_repair_limiter_t){.last_refill_ms = INT64_MIN,
                                         .initialized = true};
  CHECK(transport_repair_limiter_take(&limiter, 1, INT64_MAX),
        "forward refill arithmetic cannot overflow signed clock range");
  limiter.tokens_milli = 0;
  CHECK(transport_repair_limiter_wait_ms(&limiter, 1, INT64_MIN) ==
                UINT64_MAX &&
            !transport_repair_limiter_take(&limiter, 1, INT64_MIN),
        "unrepresentable backwards-clock wait saturates instead of refilling");
  uint16_t unordered_request[] = {7, 1, 7};
  CHECK(transport_repair_normalize_indices(unordered_request, 3) == 2 &&
            unordered_request[0] == 1 && unordered_request[1] == 7,
        "repair request normalization sorts and deduplicates");
  CHECK(transport_repair_build(&repair_fec_cache, cached, true, NULL, 0,
                               &repair) &&
            repair.count == cached->data_symbols,
        "whole-object repair is bounded data retransmission");
  transport_repair_batch_destroy(&repair);
  transport_fec_cache_destroy(&repair_fec_cache);
  transport_sent_cache_destroy(&rateless_cache);
  transport_sent_cache_destroy(&sent_cache);

  transport_sent_cache_t bounded_cache = {0};
  for (uint64_t object_id = 0; object_id < TRANSPORT_SENT_CACHE_SIZE;
       object_id++) {
    object.object_id = object_id;
    CHECK(transport_sent_cache_store(&bounded_cache, &object, 3, 2, 2, false),
          "bounded sent-object cache fill");
  }
  object.object_id = TRANSPORT_SENT_CACHE_SIZE;
  CHECK(
      !transport_sent_cache_has_space(&bounded_cache) &&
          !transport_sent_cache_store(&bounded_cache, &object, 3, 2, 2, false),
      "unacknowledged cache refuses overwrite");
  CHECK(transport_sent_cache_release_through(&bounded_cache, &track, 10, 127) ==
                128 &&
            transport_sent_cache_has_space(&bounded_cache) &&
            transport_sent_cache_store(&bounded_cache, &object, 3, 2, 2, false),
        "checkpoint release restores bounded cache capacity");
  transport_sent_cache_destroy(&bounded_cache);

  /* Entry limits alone admit 256 MiB of retained source payload. Exercise
   * byte pressure well before the entry limit, preserving required repairs. */
  uint8_t *large_payload = malloc(1024U * 1024U);
  CHECK(large_payload != NULL, "source-cache byte-budget fixture allocation");
  memset(large_payload, 0x5a, 1024U * 1024U);
  moq_object_t large_object = object;
  large_object.data = large_payload;
  large_object.size = 1024U * 1024U;
  for (size_t i = 0; i < 16; i++) {
    large_object.object_id = i;
    CHECK(transport_sent_cache_store(&bounded_cache, &large_object, 1024, 1024,
                                     1024, false),
          "source-cache byte-budget fill");
  }
  CHECK(bounded_cache.payload_bytes == TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES &&
            bounded_cache.peak_payload_bytes ==
                TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES &&
            bounded_cache.count == 16 && bounded_cache.peak_count == 16,
        "source-cache allocation counters include the full retained payload");
  large_object.object_id = 0;
  sent_object_cache_t *full_retry =
      transport_sent_cache_find(&bounded_cache, &large_object.track_id,
                                large_object.group_id, large_object.object_id);
  CHECK(transport_sent_cache_can_store(&bounded_cache, &large_object, false) &&
            transport_sent_cache_store(&bounded_cache, &large_object, 1024,
                                       1024, 1024, false) &&
            transport_sent_cache_find(&bounded_cache, &large_object.track_id,
                                      large_object.group_id, 0) == full_retry &&
            bounded_cache.payload_bytes ==
                TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES &&
            bounded_cache.count == 16,
        "a retry at the byte limit reuses its retained allocation");
  large_payload[0] ^= 1;
  CHECK(!transport_sent_cache_can_store(&bounded_cache, &large_object, false) &&
            !transport_sent_cache_store(&bounded_cache, &large_object, 1024,
                                        1024, 1024, false),
        "conflicting identity cannot replace a protected source object");
  large_payload[0] ^= 1;
  large_object.object_id = 16;
  CHECK(!transport_sent_cache_store(&bounded_cache, &large_object, 1024, 1024,
                                    1024, false),
        "source cache must backpressure at 16 MiB before its entry limit");
  CHECK(!transport_sent_cache_store(&bounded_cache, &large_object, 1024, 1024,
                                    1024, true),
        "byte pressure cannot evict protected source objects");
  CHECK(transport_sent_cache_release_through(&bounded_cache,
                                             &large_object.track_id,
                                             large_object.group_id, 0) == 1 &&
            transport_sent_cache_store(&bounded_cache, &large_object, 1024,
                                       1024, 1024, false),
        "checkpoint release restores source-cache byte admission");
  transport_sent_cache_destroy(&bounded_cache);
  CHECK(bounded_cache.payload_bytes == 0 && bounded_cache.count == 0,
        "source-cache destruction clears retained allocation accounting");

  for (size_t i = 0; i < 15; i++) {
    large_object.object_id = i;
    CHECK(transport_sent_cache_store(&bounded_cache, &large_object, 1024, 1024,
                                     1024, false),
          "mixed source-cache protected fill");
  }
  large_object.size = 256U * 1024U;
  for (size_t i = 15; i < 19; i++) {
    large_object.object_id = i;
    CHECK(transport_sent_cache_store(&bounded_cache, &large_object, 256, 256,
                                     1024, true),
          "mixed source-cache best-effort fill");
  }
  large_object.object_id = 19;
  large_object.size = 1024U * 1024U;
  CHECK(
      !transport_sent_cache_can_store(&bounded_cache, &large_object, false) &&
          transport_sent_cache_can_store(&bounded_cache, &large_object, true) &&
          transport_sent_cache_store(&bounded_cache, &large_object, 1024, 1024,
                                     1024, true) &&
          bounded_cache.payload_bytes ==
              TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES &&
          bounded_cache.peak_payload_bytes ==
              TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES &&
          bounded_cache.count == 16 && bounded_cache.peak_count == 19,
      "best-effort replacement reclaims multiple payloads within the byte cap");
  for (size_t i = 0; i < 19; i++)
    CHECK((transport_sent_cache_find(&bounded_cache, &large_object.track_id,
                                     large_object.group_id, i) != NULL) ==
              (i < 15),
          "byte reclamation preserves every protected recovery object");
  large_object.data =
      transport_sent_cache_find(&bounded_cache, &large_object.track_id,
                                large_object.group_id, 19)
          ->data;
  large_object.object_id = 20;
  CHECK(!transport_sent_cache_can_store(&bounded_cache, &large_object, true) &&
            !transport_sent_cache_store(&bounded_cache, &large_object, 1024,
                                        1024, 1024, true) &&
            large_object.data[0] == 0x5a && bounded_cache.count == 16,
        "replacement cannot reclaim its own borrowed source allocation");
  large_object.data = large_payload;
  CHECK(transport_sent_cache_release_track(&bounded_cache,
                                           &large_object.track_id) == 16 &&
            bounded_cache.payload_bytes == 0 && bounded_cache.count == 0 &&
            bounded_cache.peak_payload_bytes ==
                TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES,
        "track release clears current usage and preserves its high-water mark");
  large_object.object_id = 20;
  large_object.size = (size_t)TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES + 1;
  CHECK(!transport_sent_cache_can_store(&bounded_cache, &large_object, true) &&
            !transport_sent_cache_store(&bounded_cache, &large_object, 1, 1, 1,
                                        true),
        "oversized cache payload fails before reading or allocating its data");
  transport_sent_cache_destroy(&bounded_cache);
  free(large_payload);

  bounded_cache.max_payload_bytes = 6;
  object.size = 4;
  object.object_id = 1000;
  CHECK(transport_sent_cache_store(&bounded_cache, &object, 2, 2, 2, false),
        "custom cache budget");
  object.object_id++;
  CHECK(!transport_sent_cache_store(&bounded_cache, &object, 2, 2, 2, false),
        "custom byte cap enforced");
  transport_sent_cache_destroy(&bounded_cache);

  configured = (transport_limits_t){.max_fec_object_size = 32,
                                    .max_recovery_cache_bytes = 32};
  CHECK(!transport_limits_resolve(&configured, &resolved_limits, limit_error,
                                  sizeof(limit_error)),
        "cache limit cannot prevent reaching one rolling checkpoint");
  configured.max_recovery_cache_bytes = 32 * TRANSPORT_RECOVERY_WINDOW_OBJECTS;
  CHECK(transport_limits_resolve(&configured, &resolved_limits, limit_error,
                                 sizeof(limit_error)) &&
            resolved_limits.max_recovery_cache_bytes ==
                configured.max_recovery_cache_bytes,
        "custom recovery byte limit resolves");
  transport_fec_cache_t fec_cache = {0};
  fec_t *fec = transport_fec_cache_get(&fec_cache, FEC_REED_SOLOMON, 2, 1, 8);
  CHECK(fec != NULL, "FEC cache creation");
  CHECK(transport_fec_cache_get(&fec_cache, FEC_REED_SOLOMON, 2, 1, 8) == fec,
        "FEC cache reuse");
  transport_fec_cache_destroy(&fec_cache);

  configured.max_codec_memory_bytes = 1;
  CHECK(!transport_limits_resolve(&configured, &resolved_limits, limit_error,
                                  sizeof(limit_error)),
        "reject tiny codec byte budget");
  configured.max_codec_memory_bytes = 2U * 1024U * 1024U;
  CHECK(transport_limits_resolve(&configured, &resolved_limits, limit_error,
                                 sizeof(limit_error)) &&
            resolved_limits.max_codec_memory_bytes ==
                configured.max_codec_memory_bytes,
        "resolve endpoint codec budget");
  fec = transport_fec_cache_get(&fec_cache, FEC_REED_SOLOMON, 2, 1, 8);
  CHECK(fec, "bounded codec seed");
  size_t codec_base = fec_memory_usage(fec);
  fec_cache.memory.limit = codec_base * 2;
  CHECK(transport_fec_cache_get(&fec_cache, FEC_REED_SOLOMON, 2, 1, 9) &&
            transport_fec_cache_get(&fec_cache, FEC_REED_SOLOMON, 2, 1, 10),
        "idle codecs reclaimed under aggregate byte pressure");
  size_t codecs = 0;
  for (size_t i = 0; i < TRANSPORT_FEC_CACHE_SIZE; i++)
    codecs += fec_cache.entries[i].fec != NULL;
  CHECK(codecs == 2 && fec_cache.memory.current == codec_base * 2 &&
            fec_cache.memory.peak <= fec_cache.memory.limit,
        "byte pressure bounds retained codec entries");
  fec_cache.memory.limit = codec_base - 1;
  CHECK(!transport_fec_cache_get(&fec_cache, FEC_REED_SOLOMON, 2, 1, 11) &&
            !fec_cache.memory.current && fec_cache.memory.refusals,
        "overlarge codec refused after idle reclamation");
  transport_fec_cache_destroy(&fec_cache);
  fec_cache.memory.limit = 16U * 1024U * 1024U;
  fec = transport_fec_cache_get(&fec_cache, FEC_RAPTORQ, 32, 8, 100);
  CHECK(fec && transport_fec_cache_get(&fec_cache, FEC_REED_SOLOMON, 2, 1, 8),
        "shared encode/decode cache metadata");
  fec_cache.memory.limit = fec_cache.memory.current;
  uint8_t codec_data[32][100], codec_output[100];
  const uint8_t *codec_sources[32];
  for (size_t i = 0; i < 32; i++) {
    memset(codec_data[i], (int)i, 100);
    codec_sources[i] = codec_data[i];
  }
  uint8_t *codec_outputs[] = {codec_output};
  uint32_t codec_id = 32;
  CHECK(
      !fec_encode_symbols(fec, codec_sources, &codec_id, 1, codec_outputs) &&
          fec_cache.memory.current == fec_memory_usage(fec) &&
          transport_fec_cache_get(&fec_cache, FEC_RAPTORQ, 32, 8, 100) == fec,
      "workspace pressure reclaims idle codecs but preserves the active codec");
  fec_cache.memory.limit = 16U * 1024U * 1024U;
  CHECK(fec_encode_symbols(fec, codec_sources, &codec_id, 1, codec_outputs) &&
            fec_cache.memory.current == fec_memory_usage(fec) &&
            fec_cache.memory.peak <= fec_cache.memory.limit,
        "codec can retry after a refused workspace allocation");
  transport_fec_cache_destroy(&fec_cache);
  CHECK(!fec_cache.memory.current, "all retained codec bytes released");

  printf("===TRANSPORT COMPONENTS OK===\n");
  return 0;
}
