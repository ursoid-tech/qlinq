#include "transport_repair.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static bool refill_limiter(transport_repair_limiter_t *limiter,
                           size_t requests_per_second, int64_t now_ms) {
  if (!limiter || requests_per_second == 0 ||
      requests_per_second > UINT64_MAX / 1000U)
    return false;

  uint64_t capacity = (uint64_t)requests_per_second * 1000U;
  if (!limiter->initialized) {
    limiter->initialized = true;
    if (limiter->last_refill_ms == 0) {
      limiter->tokens_milli = capacity;
      limiter->last_refill_ms = now_ms;
    }
  }
  if (limiter->tokens_milli > capacity)
    limiter->tokens_milli = capacity;
  /* a caller's saved tick timestamp can precede a later admission timestamp.
   * neither stale inspection nor wall-clock rollback may mint a fresh burst. */
  if (now_ms > limiter->last_refill_ms) {
    uint64_t elapsed = (uint64_t)now_ms - (uint64_t)limiter->last_refill_ms;
    uint64_t added = 0;
    if (elapsed > UINT64_MAX / requests_per_second) {
      added = capacity;
    } else {
      added = elapsed * (uint64_t)requests_per_second;
    }
    limiter->tokens_milli = added >= capacity - limiter->tokens_milli
                                ? capacity
                                : limiter->tokens_milli + added;
    limiter->last_refill_ms = now_ms;
  }

  return true;
}

uint64_t transport_repair_limiter_wait_ms(transport_repair_limiter_t *limiter,
                                          size_t requests_per_second,
                                          int64_t now_ms) {
  if (!refill_limiter(limiter, requests_per_second, now_ms))
    return UINT64_MAX;
  if (limiter->tokens_milli >= 1000U)
    return 0;
  uint64_t missing = 1000U - limiter->tokens_milli;
  uint64_t wait = (missing + requests_per_second - 1U) / requests_per_second;
  uint64_t lag = now_ms < limiter->last_refill_ms
                     ? (uint64_t)limiter->last_refill_ms - (uint64_t)now_ms
                     : 0;
  return wait > UINT64_MAX - lag ? UINT64_MAX : lag + wait;
}

bool transport_repair_limiter_take(transport_repair_limiter_t *limiter,
                                   size_t requests_per_second, int64_t now_ms) {
  if (!refill_limiter(limiter, requests_per_second, now_ms))
    return false;

  if (limiter->tokens_milli < 1000U)
    return false;
  limiter->tokens_milli -= 1000U;
  return true;
}

size_t transport_repair_normalize_indices(uint16_t *indices, size_t count) {
  if (!indices)
    return 0;
  for (size_t i = 1; i < count; i++) {
    uint16_t value = indices[i];
    size_t position = i;
    while (position > 0 && indices[position - 1U] > value) {
      indices[position] = indices[position - 1U];
      position--;
    }
    indices[position] = value;
  }
  size_t unique = 0;
  for (size_t i = 0; i < count; i++)
    if (unique == 0 || indices[i] != indices[unique - 1U])
      indices[unique++] = indices[i];
  return unique;
}

void transport_repair_batch_destroy(transport_repair_batch_t *batch) {
  if (!batch)
    return;
  free(batch->symbols);
  memset(batch, 0, sizeof(*batch));
}

static bool append_unique(transport_repair_batch_t *batch, uint16_t index) {
  for (size_t i = 0; i < batch->count; i++) {
    if (batch->indices[i] == index)
      return true;
  }
  if (batch->count >= TRANSPORT_REPAIR_MAX_SYMBOLS)
    return false;
  batch->indices[batch->count++] = index;
  return true;
}

bool transport_repair_build(transport_fec_cache_t *fec_cache,
                            const sent_object_cache_t *object,
                            bool whole_object, const uint16_t *missing,
                            size_t missing_count,
                            transport_repair_batch_t *batch) {
  if (!fec_cache || !object || !object->data || object->size == 0 || !batch ||
      object->data_symbols == 0 || object->symbol_size == 0 ||
      (!whole_object && (!missing || missing_count == 0)))
    return false;
  memset(batch, 0, sizeof(*batch));
  batch->symbol_size = object->symbol_size;

  if (whole_object) {
    size_t count = object->data_symbols;
    if (count > TRANSPORT_REPAIR_MAX_SYMBOLS)
      count = TRANSPORT_REPAIR_MAX_SYMBOLS;
    for (size_t i = 0; i < count; i++)
      batch->indices[batch->count++] = (uint16_t)i;
  } else {
    size_t count = missing_count;
    if (count > TRANSPORT_REPAIR_MAX_SYMBOLS)
      count = TRANSPORT_REPAIR_MAX_SYMBOLS;
    for (size_t i = 0; i < count; i++) {
      if (missing[i] >= QLINQ_FEC_MAX_TOTAL_SYMBOLS ||
          !append_unique(batch, missing[i]))
        return false;
    }
  }
  if (batch->count == 0)
    return false;

  bool rateless = (object->track_id.flags & MOQ_TRACK_FLAG_FEC_RATELESS) != 0;
  size_t total_symbols = object->total_symbols;
  if (total_symbols < object->data_symbols ||
      total_symbols > QLINQ_FEC_MAX_TOTAL_SYMBOLS ||
      object->data_symbols > QLINQ_FEC_MAX_TOTAL_SYMBOLS ||
      object->symbol_size > QLINQ_FEC_MAX_SYMBOL_SIZE ||
      object->size > (size_t)object->data_symbols * object->symbol_size)
    return false;
  for (size_t i = 0; i < batch->count; i++) {
    size_t extent = (size_t)batch->indices[i] + 1U;
    if (extent > total_symbols) {
      if (!rateless)
        return false; /* fixed geometry must never grow during repair */
      total_symbols = extent;
    }
  }
  batch->symbols = calloc(batch->count, object->symbol_size);
  if (!batch->symbols)
    return false;

  bool encoded = false;
  const uint8_t **data_blocks =
      calloc(object->data_symbols, sizeof(*data_blocks));
  uint8_t *tail = NULL;
  uint32_t parity_ids[TRANSPORT_REPAIR_MAX_SYMBOLS];
  uint8_t *parity_outputs[TRANSPORT_REPAIR_MAX_SYMBOLS];
  size_t parity_count = 0;
  if (!data_blocks)
    goto cleanup;
  for (size_t i = 0; i < object->data_symbols; i++) {
    size_t offset = i * object->symbol_size;
    size_t chunk = offset < object->size ? object->size - offset : 0;
    if (chunk >= object->symbol_size) {
      data_blocks[i] = object->data + offset;
    } else {
      /* valid geometry needs at most one padded tail, never a source copy */
      if (i + 1U != object->data_symbols)
        goto cleanup;
      tail = calloc(1, object->symbol_size);
      if (!tail)
        goto cleanup;
      if (chunk != 0)
        memcpy(tail, object->data + offset, chunk);
      data_blocks[i] = tail;
    }
  }
  for (size_t i = 0; i < batch->count; i++) {
    uint16_t index = batch->indices[i];
    uint8_t *output = batch->symbols + i * object->symbol_size;
    if (index < object->data_symbols) {
      memcpy(output, data_blocks[index], object->symbol_size);
    } else {
      parity_ids[parity_count] = index;
      parity_outputs[parity_count++] = output;
    }
  }
  encoded = true;
  if (parity_count > 0) {
    fec_type_t type = fec_select_type(rateless, total_symbols);
    fec_t *fec = transport_fec_cache_get(fec_cache, type, object->data_symbols,
                                         total_symbols - object->data_symbols,
                                         object->symbol_size);
    encoded = fec && fec_encode_symbols(fec, data_blocks, parity_ids,
                                        parity_count, parity_outputs);
  }
cleanup:
  free(data_blocks);
  free(tail);
  if (!encoded) {
    transport_repair_batch_destroy(batch);
    return false;
  }
  batch->total_symbols = (uint16_t)total_symbols;
  return true;
}

bool transport_repair_build_rateless(transport_fec_cache_t *fec_cache,
                                     sent_object_cache_t *object,
                                     size_t requested,
                                     transport_repair_batch_t *batch) {
  if (!fec_cache || !object || !batch ||
      (object->track_id.flags & MOQ_TRACK_FLAG_FEC_RATELESS) == 0 ||
      requested == 0 || object->next_repair_symbol < object->data_symbols ||
      object->next_repair_symbol >= QLINQ_FEC_MAX_TOTAL_SYMBOLS)
    return false;
  size_t available = QLINQ_FEC_MAX_TOTAL_SYMBOLS - object->next_repair_symbol;
  size_t count = requested;
  if (count > TRANSPORT_REPAIR_MAX_SYMBOLS)
    count = TRANSPORT_REPAIR_MAX_SYMBOLS;
  if (count > available)
    count = available;
  if (count == 0)
    return false;
  uint16_t indices[TRANSPORT_REPAIR_MAX_SYMBOLS];
  for (size_t i = 0; i < count; i++)
    indices[i] = (uint16_t)(object->next_repair_symbol + i);
  return transport_repair_build(fec_cache, object, false, indices, count,
                                batch);
}

bool transport_repair_commit_rateless(sent_object_cache_t *object,
                                      const transport_repair_batch_t *batch,
                                      size_t admitted) {
  if (!object || !batch || admitted == 0 || admitted > batch->count ||
      object->next_repair_symbol >= QLINQ_FEC_MAX_TOTAL_SYMBOLS ||
      admitted > QLINQ_FEC_MAX_TOTAL_SYMBOLS - object->next_repair_symbol)
    return false;
  for (size_t i = 0; i < admitted; i++)
    if (batch->indices[i] != object->next_repair_symbol + i)
      return false;
  object->next_repair_symbol =
      (uint16_t)(object->next_repair_symbol + admitted);
  return true;
}

bool transport_repair_build_systematic_fallback(
    transport_fec_cache_t *fec_cache, sent_object_cache_t *object,
    size_t requested, transport_repair_batch_t *batch) {
  if (!fec_cache || !object || !batch || requested == 0 ||
      (object->track_id.flags & MOQ_TRACK_FLAG_FEC_RATELESS) == 0 ||
      object->next_repair_symbol < QLINQ_FEC_MAX_TOTAL_SYMBOLS ||
      object->data_symbols == 0 ||
      object->next_systematic_repair_symbol >= object->data_symbols)
    return false;
  size_t count = requested;
  if (count > TRANSPORT_REPAIR_MAX_SYMBOLS)
    count = TRANSPORT_REPAIR_MAX_SYMBOLS;
  if (count > object->data_symbols)
    count = object->data_symbols;
  uint16_t indices[TRANSPORT_REPAIR_MAX_SYMBOLS];
  for (size_t i = 0; i < count; i++)
    indices[i] = (uint16_t)((object->next_systematic_repair_symbol + i) %
                            object->data_symbols);
  return transport_repair_build(fec_cache, object, false, indices, count,
                                batch);
}

bool transport_repair_commit_systematic_fallback(
    sent_object_cache_t *object, const transport_repair_batch_t *batch,
    size_t admitted) {
  if (!object || !batch || admitted == 0 || admitted > batch->count ||
      object->data_symbols == 0 ||
      object->next_systematic_repair_symbol >= object->data_symbols)
    return false;
  for (size_t i = 0; i < admitted; i++)
    if (batch->indices[i] !=
        (object->next_systematic_repair_symbol + i) % object->data_symbols)
      return false;
  object->next_systematic_repair_symbol =
      (uint16_t)((object->next_systematic_repair_symbol + admitted) %
                 object->data_symbols);
  return true;
}
