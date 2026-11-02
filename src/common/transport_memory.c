#include "transport_memory.h"

#include <stdlib.h>
#include <string.h>

bool transport_arena_init(arena_t *arena, size_t capacity) {
  if (!arena || capacity == 0)
    return false;
  memset(arena, 0, sizeof(*arena));
  arena->buffer = malloc(capacity);
  if (!arena->buffer)
    return false;
  arena->capacity = capacity;
  return true;
}

void transport_arena_destroy(arena_t *arena) {
  if (!arena)
    return;
  transport_arena_reset(arena);
  free(arena->buffer);
  memset(arena, 0, sizeof(*arena));
}

void *transport_arena_alloc(arena_t *arena, size_t size) {
  if (!arena || !arena->buffer || size > SIZE_MAX - 7U)
    return NULL;
  size = (size + 7U) & ~(size_t)7U;
  if (arena->offset > arena->capacity ||
      size > arena->capacity - arena->offset) {
    if (arena->fallback_count >= TRANSPORT_ARENA_MAX_FALLBACKS)
      return NULL;
    void *ptr = calloc(1, size);
    if (ptr)
      arena->fallbacks[arena->fallback_count++] = ptr;
    return ptr;
  }
  void *ptr = arena->buffer + arena->offset;
  arena->offset += size;
  memset(ptr, 0, size);
  return ptr;
}

void transport_arena_reset(arena_t *arena) {
  if (!arena)
    return;
  arena->offset = 0;
  for (size_t i = 0; i < arena->fallback_count; i++)
    free(arena->fallbacks[i]);
  arena->fallback_count = 0;
}

void transport_assembler_release(frame_assembler_t *assembler) {
  if (!assembler)
    return;
  free(assembler->buffers);
  free(assembler->buffer_storage);
  memset(assembler, 0, sizeof(*assembler));
}

bool transport_assembler_grow(frame_assembler_t *assembler, uint16_t symbols,
                              uint16_t symbol_size) {
  if (!assembler || symbols == 0 || symbol_size == 0)
    return false;
  if (assembler->buffers && assembler->capacity_symbols >= symbols &&
      assembler->capacity_symbol_size >= symbol_size)
    return true;

  uint16_t new_symbols = assembler->capacity_symbols > symbols
                             ? assembler->capacity_symbols
                             : symbols;
  uint16_t new_symbol_size = assembler->capacity_symbol_size > symbol_size
                                 ? assembler->capacity_symbol_size
                                 : symbol_size;
  size_t meta_bytes =
      (size_t)new_symbols *
      (sizeof(uint8_t *) + sizeof(uint16_t) + 2U * sizeof(bool));
  uint8_t **buffers = calloc(1, meta_bytes);
  uint8_t *storage = malloc((size_t)new_symbols * new_symbol_size);
  if (!buffers || !storage)
    goto Fail;
  uint16_t *indices = (uint16_t *)(buffers + new_symbols);
  bool *received = (bool *)(indices + new_symbols);
  bool *missing = received + new_symbols;
  for (size_t i = 0; i < new_symbols; i++)
    buffers[i] = storage + i * new_symbol_size;
  if (assembler->buffers && assembler->total_symbols > 0) {
    if (!assembler->received_mask || assembler->total_symbols > new_symbols ||
        assembler->symbol_size > new_symbol_size)
      goto Fail;
    for (size_t i = 0; i < assembler->total_symbols; i++) {
      if (!assembler->buffers[i])
        goto Fail;
      if (assembler->received_mask[i]) {
        memcpy(buffers[i], assembler->buffers[i], assembler->symbol_size);
        received[i] = true;
      }
    }
  }

  free(assembler->buffers);
  free(assembler->buffer_storage);
  assembler->buffers = buffers;
  assembler->buffer_storage = storage;
  assembler->received_mask = received;
  assembler->missing_mask = missing;
  assembler->missing_indices = indices;
  assembler->capacity_symbols = new_symbols;
  assembler->capacity_symbol_size = new_symbol_size;
  return true;

Fail:
  free(buffers);
  free(storage);
  return false;
}

size_t transport_assembler_required_bytes(uint16_t symbols,
                                          uint16_t symbol_size) {
  if (symbols == 0 || symbol_size == 0)
    return 0;
  return (size_t)symbols * (sizeof(uint8_t *) + (size_t)symbol_size +
                            2U * sizeof(bool) + sizeof(uint16_t));
}

size_t transport_assembler_capacity_bytes(const frame_assembler_t *assembler) {
  if (!assembler)
    return 0;
  return transport_assembler_required_bytes(assembler->capacity_symbols,
                                            assembler->capacity_symbol_size);
}
