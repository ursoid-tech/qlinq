#include "transport_fec_state.h"
#include "transport_tracks.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

uint64_t transport_get_monotonic_ns(void);

uint16_t transport_sent_recipient_total(const sent_object_cache_t *object,
                                        uint32_t connection_id) {
  if (object)
    for (size_t i = 0; i < object->recipient_count; i++)
      if (object->recipients[i].connection_id == connection_id)
        return object->recipients[i].total_symbols;
  return 0;
}

bool transport_sent_recipient_reserve(sent_object_cache_t *object,
                                      size_t capacity) {
  if (!object || !object->data || capacity > TRANSPORT_HARD_MAX_CONNECTIONS)
    return false;
  if (capacity <= object->recipient_capacity)
    return true;
  size_t grown =
      object->recipient_capacity ? object->recipient_capacity * 2U : 4U;
  if (grown < capacity)
    grown = capacity;
  if (grown > TRANSPORT_HARD_MAX_CONNECTIONS)
    grown = TRANSPORT_HARD_MAX_CONNECTIONS;
  transport_sent_recipient_t *recipients =
      realloc(object->recipients, grown * sizeof(*recipients));
  if (!recipients)
    return false;
  object->recipients = recipients;
  object->recipient_capacity = (uint16_t)grown;
  return true;
}

bool transport_sent_recipient_store(sent_object_cache_t *object,
                                    uint32_t connection_id,
                                    uint16_t total_symbols) {
  if (!object || !object->data || connection_id == 0 ||
      total_symbols < object->data_symbols ||
      total_symbols > QLINQ_FEC_MAX_TOTAL_SYMBOLS)
    return false;
  uint16_t existing = transport_sent_recipient_total(object, connection_id);
  if (existing)
    return existing == total_symbols;
  if (!transport_sent_recipient_reserve(object, object->recipient_count + 1U))
    return false;
  object->recipients[object->recipient_count++] =
      (transport_sent_recipient_t){connection_id, total_symbols};
  return true;
}

static size_t cache_capacity(const transport_sent_cache_t *cache) {
  return cache && cache->capacity ? cache->capacity : TRANSPORT_SENT_CACHE_SIZE;
}

#define SENT_CACHE_TOMBSTONE UINT32_MAX

static uint64_t sent_cache_hash(const moq_track_id_t *track, uint64_t group_id,
                                uint64_t object_id) {
  uint64_t h = 1469598103934665603ULL;
  h ^= (uint64_t)track->type;
  h *= 1099511628211ULL;
  h ^= (uint64_t)track->flags;
  h *= 1099511628211ULL;
  for (const unsigned char *p = (const unsigned char *)track->name; *p; p++) {
    h ^= *p;
    h *= 1099511628211ULL;
  }
  h ^= group_id;
  h *= 1099511628211ULL;
  h ^= object_id;
  h *= 1099511628211ULL;
  h ^= h >> 33;
  h *= 0xff51afd7ed558ccdULL;
  h ^= h >> 33;
  return h;
}

static void sent_cache_hash_insert(transport_sent_cache_t *cache,
                                   size_t entry_index) {
  if (!cache->hash_slots || cache->hash_capacity == 0)
    return;
  const sent_object_cache_t *entry = &cache->entries[entry_index];
  size_t mask = cache->hash_capacity - 1U;
  size_t slot = (size_t)sent_cache_hash(&entry->track_id, entry->group_id,
                                        entry->object_id) &
                mask;
  for (size_t step = 0; step < cache->hash_capacity; step++) {
    uint32_t value = cache->hash_slots[slot];
    if (value == 0 || value == SENT_CACHE_TOMBSTONE) {
      if (value == SENT_CACHE_TOMBSTONE)
        cache->hash_tombstones--;
      cache->hash_slots[slot] = (uint32_t)(entry_index + 1U);
      return;
    }
    slot = (slot + 1U) & mask;
  }
  assert(false);
}

static void sent_cache_hash_rebuild(transport_sent_cache_t *cache) {
  if (!cache->hash_slots || cache->hash_capacity == 0)
    return;
  memset(cache->hash_slots, 0,
         cache->hash_capacity * sizeof(*cache->hash_slots));
  cache->hash_tombstones = 0;
  if (cache->count == 0)
    return;
  size_t cap = cache_capacity(cache);
  for (size_t i = 0; i < cap; i++) {
    if (cache->entries[i].data)
      sent_cache_hash_insert(cache, i);
  }
}

static void sent_cache_hash_remove(transport_sent_cache_t *cache,
                                   size_t entry_index) {
  if (!cache->hash_slots || cache->hash_capacity == 0)
    return;
  const sent_object_cache_t *entry = &cache->entries[entry_index];
  size_t mask = cache->hash_capacity - 1U;
  size_t slot = (size_t)sent_cache_hash(&entry->track_id, entry->group_id,
                                        entry->object_id) &
                mask;
  uint32_t target = (uint32_t)(entry_index + 1U);
  for (size_t step = 0; step < cache->hash_capacity; step++) {
    uint32_t value = cache->hash_slots[slot];
    if (value == 0)
      return;
    if (value == target) {
      size_t next = (slot + 1U) & mask;
      if (cache->hash_slots[next] == 0) {
        cache->hash_slots[slot] = 0;
      } else {
        cache->hash_slots[slot] = SENT_CACHE_TOMBSTONE;
        cache->hash_tombstones++;
      }
      return;
    }
    slot = (slot + 1U) & mask;
  }
}

bool transport_sent_cache_init(transport_sent_cache_t *cache,
                               size_t max_payload_bytes,
                               size_t max_object_bytes) {
  if (!cache || cache->entries)
    return cache != NULL && cache->entries != NULL;
  size_t byte_limit = max_payload_bytes
                          ? max_payload_bytes
                          : TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES;
  size_t object_limit =
      max_object_bytes ? max_object_bytes : TRANSPORT_MAX_FEC_OBJECT_SIZE;
  size_t capacity = byte_limit / object_limit;
  if (byte_limit % object_limit != 0)
    capacity++;
  if (capacity < TRANSPORT_SENT_CACHE_SIZE)
    capacity = TRANSPORT_SENT_CACHE_SIZE;
  if (capacity > TRANSPORT_SENT_CACHE_MAX_SIZE)
    capacity = TRANSPORT_SENT_CACHE_MAX_SIZE;
  if (capacity > SIZE_MAX / sizeof(*cache->entries) ||
      capacity > (SIZE_MAX / 2U) / sizeof(*cache->hash_slots))
    return false;
  size_t hash_capacity = 1U;
  while (hash_capacity < capacity * 2U)
    hash_capacity <<= 1U;
  cache->entries = calloc(capacity, sizeof(*cache->entries));
  cache->hash_slots = calloc(hash_capacity, sizeof(*cache->hash_slots));
  if (!cache->entries || !cache->hash_slots) {
    free(cache->entries);
    free(cache->hash_slots);
    cache->entries = NULL;
    cache->hash_slots = NULL;
    return false;
  }
  cache->capacity = capacity;
  cache->hash_capacity = hash_capacity;
  cache->hash_tombstones = 0;
  cache->max_payload_bytes = byte_limit;
  cache->object_id_upper_bound = 0;
  return true;
}

sent_object_cache_t *transport_sent_cache_find(transport_sent_cache_t *cache,
                                               const moq_track_id_t *track,
                                               uint64_t group_id,
                                               uint64_t object_id) {
  if (!cache || !track || !cache->entries || cache->count == 0)
    return NULL;
  if (object_id > cache->object_id_upper_bound)
    return NULL;
  if (cache->hash_slots && cache->hash_capacity != 0) {
    size_t mask = cache->hash_capacity - 1U;
    size_t slot = (size_t)sent_cache_hash(track, group_id, object_id) & mask;
    for (size_t step = 0; step < cache->hash_capacity; step++) {
      uint32_t value = cache->hash_slots[slot];
      if (value == 0)
        return NULL;
      if (value != SENT_CACHE_TOMBSTONE) {
        sent_object_cache_t *entry = &cache->entries[value - 1U];
        if (entry->data && entry->group_id == group_id &&
            entry->object_id == object_id &&
            transport_track_id_equal(&entry->track_id, track))
          return entry;
      }
      slot = (slot + 1U) & mask;
    }
    return NULL;
  }
  size_t capacity = cache_capacity(cache), remaining = cache->count;
  size_t index = cache->next_entry;
  assert(remaining <= capacity && index < capacity);
  for (size_t scanned = 0; remaining != 0 && scanned < capacity; scanned++) {
    index = index != 0 ? index - 1U : capacity - 1U;
    sent_object_cache_t *entry = &cache->entries[index];
    if (!entry->data)
      continue;
    remaining--;
    if (entry->group_id == group_id && entry->object_id == object_id &&
        transport_track_id_equal(&entry->track_id, track))
      return entry;
  }
  assert(remaining == 0);
  return NULL;
}

static bool source_overlaps_entry(const moq_object_t *object,
                                  const sent_object_cache_t *entry) {
  uintptr_t source = (uintptr_t)object->data;
  uintptr_t retained = (uintptr_t)entry->data;
  return source >= retained ? source - retained < entry->size
                            : retained - source < object->size;
}

bool transport_sent_cache_can_store(const transport_sent_cache_t *cache,
                                    const moq_object_t *object,
                                    bool allow_evict) {
  if (!cache || !object || !object->data || object->size == 0 ||
      object->size > transport_sent_cache_byte_limit(cache) ||
      cache->payload_bytes > transport_sent_cache_byte_limit(cache))
    return false;
  size_t available =
      transport_sent_cache_byte_limit(cache) - cache->payload_bytes;
  bool slot_available = false;
  if (!cache->entries)
    return cache->count == 0 && object->size <= available;
  /* The common admission path needs neither replacement nor identity lookup:
   * a free entry and sufficient byte budget make the object storable. Exact
   * identity validation remains in store(), while the slower scan below is
   * reserved for a full cache, byte pressure, retries, or eviction. */
  if (cache->count < cache_capacity(cache) && object->size <= available)
    return true;
  const sent_object_cache_t *existing = transport_sent_cache_find(
      (transport_sent_cache_t *)cache, &object->track_id, object->group_id,
      object->object_id);
  if (existing) {
    return existing->size == object->size &&
           memcmp(existing->data, object->data, object->size) == 0;
  }
  if (!allow_evict)
    return false;
  for (size_t i = 0; i < cache_capacity(cache); i++) {
    const sent_object_cache_t *entry = &cache->entries[i];
    if (!entry->data) {
      slot_available = true;
    } else if (!entry->recovery_protected &&
               !source_overlaps_entry(object, entry)) {
      available += entry->size;
      slot_available = true;
      if (object->size <= available)
        return true;
    }
  }
  return slot_available && object->size <= available;
}

static void release_entry(transport_sent_cache_t *cache,
                          sent_object_cache_t *entry) {
  free(entry->recipients);
  if (entry->data) {
    size_t entry_index = (size_t)(entry - cache->entries);
    sent_cache_hash_remove(cache, entry_index);
    cache->payload_bytes -= entry->size;
    cache->count--;
    if (cache->count == 0) {
      cache->object_id_upper_bound = 0;
      if (cache->hash_slots && cache->hash_tombstones != 0) {
        memset(cache->hash_slots, 0,
               cache->hash_capacity * sizeof(*cache->hash_slots));
        cache->hash_tombstones = 0;
      }
    } else if (cache->hash_tombstones > cache->hash_capacity / 4U) {
      sent_cache_hash_rebuild(cache);
    }
    free(entry->data);
  }
  memset(entry, 0, sizeof(*entry));
}

bool transport_sent_cache_store(transport_sent_cache_t *cache,
                                const moq_object_t *object,
                                uint16_t total_symbols, uint16_t data_symbols,
                                uint16_t symbol_size, bool allow_evict) {
  if (!cache || !object || !object->data || object->size == 0)
    return false;
  if (!cache->entries &&
      !transport_sent_cache_init(cache, cache->max_payload_bytes,
                                 TRANSPORT_MAX_FEC_OBJECT_SIZE))
    return false;
  sent_object_cache_t *existing = transport_sent_cache_find(
      cache, &object->track_id, object->group_id, object->object_id);
  if (existing) {
    /* A partially queued publication is retried with the same object
     * identity. Keep one recovery entry and preserve any rateless ESI already
     * allocated from it. Conflicting reuse of an identity is invalid. */
    if (existing->size != object->size ||
        memcmp(existing->data, object->data, object->size) != 0)
      return false;
    if (total_symbols > existing->total_symbols)
      existing->total_symbols = total_symbols;
    if (existing->next_repair_symbol < existing->total_symbols)
      existing->next_repair_symbol = existing->total_symbols;
    existing->data_symbols = data_symbols;
    existing->symbol_size = symbol_size;
    existing->priority = object->priority;
    existing->is_keyframe = object->is_keyframe;
    existing->recovery_protected |= !allow_evict;
    return true;
  }
  if (!transport_sent_cache_can_store(cache, object, allow_evict))
    return false;

  /* Reclaim only evictable best-effort payloads, before allocating the new
   * copy, so the byte cap also holds during replacement. Required recovery
   * objects survive pressure. Allocation failure may retire best-effort cache
   * entries, but cannot destroy a protected obligation. */
  for (size_t offset = 0;
       object->size >
           transport_sent_cache_byte_limit(cache) - cache->payload_bytes ||
       cache->count == cache_capacity(cache);
       offset++) {
    if (!allow_evict || offset == cache_capacity(cache))
      return false;
    size_t index = (cache->next_entry + offset) % cache_capacity(cache);
    if (cache->entries[index].data &&
        !cache->entries[index].recovery_protected &&
        !source_overlaps_entry(object, &cache->entries[index]))
      release_entry(cache, &cache->entries[index]);
  }
  sent_object_cache_t *entry = NULL;
  size_t next_entry = cache->next_entry;
  for (size_t offset = 0; offset < cache_capacity(cache); offset++) {
    size_t index = (cache->next_entry + offset) % cache_capacity(cache);
    if (!cache->entries[index].data) {
      entry = &cache->entries[index];
      next_entry = (index + 1U) % cache_capacity(cache);
      break;
    }
  }
  if (!entry)
    return false;
  uint8_t *copy = malloc(object->size);
  if (!copy)
    return false;
  memcpy(copy, object->data, object->size);

  cache->next_entry = next_entry;
  entry->track_id = object->track_id;
  entry->group_id = object->group_id;
  entry->object_id = object->object_id;
  entry->size = object->size;
  entry->priority = object->priority;
  entry->is_keyframe = object->is_keyframe;
  entry->total_symbols = total_symbols;
  entry->data_symbols = data_symbols;
  entry->symbol_size = symbol_size;
  entry->next_repair_symbol = total_symbols;
  entry->next_systematic_repair_symbol = 0;
  entry->remaining_repair_symbols = UINT32_MAX;
  entry->expires_at_ms = 0;
  entry->policy_initialized = false;
  entry->recovery_protected = !allow_evict;
  entry->data = copy;
  sent_cache_hash_insert(cache, (size_t)(entry - cache->entries));
  if (object->object_id > cache->object_id_upper_bound)
    cache->object_id_upper_bound = object->object_id;
  cache->payload_bytes += object->size;
  cache->count++;
  if (cache->payload_bytes > cache->peak_payload_bytes)
    cache->peak_payload_bytes = cache->payload_bytes;
  if (cache->count > cache->peak_count)
    cache->peak_count = cache->count;
  return true;
}

bool transport_sent_cache_release_object(transport_sent_cache_t *cache,
                                         const moq_track_id_t *track,
                                         uint64_t group_id,
                                         uint64_t object_id) {
  sent_object_cache_t *entry =
      transport_sent_cache_find(cache, track, group_id, object_id);
  if (!entry)
    return false;
  release_entry(cache, entry);
  return true;
}

size_t transport_sent_cache_release_through(transport_sent_cache_t *cache,
                                            const moq_track_id_t *track,
                                            uint64_t group_id,
                                            uint64_t object_id) {
  if (!cache || !track)
    return 0;
  size_t released = 0;
  if (!cache->entries)
    return 0;
  size_t capacity = cache_capacity(cache), remaining = cache->count;
  size_t index = cache->next_entry;
  for (size_t scanned = 0; remaining != 0 && scanned < capacity; scanned++) {
    index = index != 0 ? index - 1U : capacity - 1U;
    sent_object_cache_t *entry = &cache->entries[index];
    if (!entry->data)
      continue;
    remaining--;
    if (entry->group_id == group_id && entry->object_id <= object_id &&
        transport_track_id_equal(&entry->track_id, track)) {
      release_entry(cache, entry);
      released++;
    }
  }
  assert(remaining == 0);
  return released;
}

size_t transport_sent_cache_release_track(transport_sent_cache_t *cache,
                                          const moq_track_id_t *track) {
  if (!cache || !track)
    return 0;
  size_t released = 0;
  if (!cache->entries)
    return 0;
  size_t capacity = cache_capacity(cache), remaining = cache->count;
  size_t index = cache->next_entry;
  for (size_t scanned = 0; remaining != 0 && scanned < capacity; scanned++) {
    index = index != 0 ? index - 1U : capacity - 1U;
    sent_object_cache_t *entry = &cache->entries[index];
    if (!entry->data)
      continue;
    remaining--;
    if (transport_track_id_equal(&entry->track_id, track)) {
      release_entry(cache, entry);
      released++;
    }
  }
  assert(remaining == 0);
  return released;
}

void transport_sent_cache_destroy(transport_sent_cache_t *cache) {
  if (!cache)
    return;
  for (size_t i = 0; cache->entries && i < cache_capacity(cache); i++) {
    free(cache->entries[i].data);
    free(cache->entries[i].recipients);
  }
  free(cache->entries);
  free(cache->hash_slots);
  memset(cache, 0, sizeof(*cache));
}

static bool reclaim_codecs(void *context, size_t bytes, const fec_t *active) {
  transport_fec_cache_t *cache = context;
  while (cache->memory.current > cache->memory.limit ||
         bytes > cache->memory.limit - cache->memory.current) {
    transport_fec_cache_entry_t *oldest = NULL;
    for (size_t i = 0; i < TRANSPORT_FEC_CACHE_SIZE; i++) {
      transport_fec_cache_entry_t *entry = &cache->entries[i];
      if (entry->fec && entry->fec != active &&
          (!oldest || entry->last_used_ns < oldest->last_used_ns))
        oldest = entry;
    }
    if (!oldest)
      return false;
    fec_destroy(oldest->fec);
    memset(oldest, 0, sizeof(*oldest));
  }
  return true;
}

fec_t *transport_fec_cache_get(transport_fec_cache_t *cache, fec_type_t type,
                               size_t data_symbols, size_t parity_symbols,
                               size_t symbol_size) {
  if (!cache || data_symbols == 0 || symbol_size == 0)
    return NULL;
  cache->memory.reclaim = reclaim_codecs;
  cache->memory.context = cache;
  uint64_t now = cache->now_ns ? cache->now_ns(cache->clock_context)
                               : transport_get_monotonic_ns();
  size_t lru_index = 0;
  uint64_t oldest = UINT64_MAX;

  for (size_t i = 0; i < TRANSPORT_FEC_CACHE_SIZE; i++) {
    transport_fec_cache_entry_t *entry = &cache->entries[i];
    if (entry->fec && entry->type == type &&
        entry->data_symbols == data_symbols &&
        entry->symbol_size == symbol_size &&
        (entry->parity_symbols == parity_symbols ||
         (type == FEC_RAPTORQ &&
          fec_set_parity_symbols(entry->fec, parity_symbols)))) {
      entry->parity_symbols = parity_symbols;
      entry->last_used_ns = now;
      return entry->fec;
    }
    if (entry->last_used_ns < oldest) {
      oldest = entry->last_used_ns;
      lru_index = i;
    }
  }

  transport_fec_cache_entry_t *entry = &cache->entries[lru_index];
  /* release the victim before allocating its replacement. active callers
   * never retain a cache pointer across a second get/encode/decode call. */
  fec_destroy(entry->fec);
  memset(entry, 0, sizeof(*entry));
  fec_t *replacement = fec_create_bounded(type, data_symbols, parity_symbols,
                                          symbol_size, &cache->memory);
  if (!replacement)
    return NULL;
  entry->type = type;
  entry->data_symbols = data_symbols;
  entry->parity_symbols = parity_symbols;
  entry->symbol_size = symbol_size;
  entry->fec = replacement;
  entry->last_used_ns = now;
  return replacement;
}

void transport_fec_cache_destroy(transport_fec_cache_t *cache) {
  if (!cache)
    return;
  for (size_t i = 0; i < TRANSPORT_FEC_CACHE_SIZE; i++)
    fec_destroy(cache->entries[i].fec);
  memset(cache, 0, sizeof(*cache));
}
