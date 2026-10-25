/* fec.h
 *
 * design philosophy:
 * this interface abstracts forward error correction (fec) algorithms,
 * allowing us to swap between reed-solomon (nanors) and raptorq (nanorq)
 * depending on packet block sizes, network loss patterns, and target
 * resolutions.
 */

#ifndef FEC_H
#define FEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct fec_t fec_t;

/* A fec_t instance is reusable but must be confined to one thread at a time. */

typedef enum { FEC_REED_SOLOMON, FEC_RAPTORQ } fec_type_t;

/* rateless objects and blocks larger than RS permits use RaptorQ. */
fec_type_t fec_select_type(bool rateless, size_t total_symbols);

/* shared endpoint allocation budget, confined with its codecs to one owner
 * thread. a zero limit is unlimited for standalone callers. reclaim may
 * discard idle codecs, but must preserve active. */
typedef struct fec_memory_budget_t {
  size_t limit, current, peak;
  uint64_t refusals;
  bool (*reclaim)(void *context, size_t bytes, const fec_t *active);
  void *context;
} fec_memory_budget_t;

fec_t *fec_create_bounded(fec_type_t type, size_t data_symbols,
                          size_t parity_symbols, size_t symbol_size,
                          fec_memory_budget_t *budget);
size_t fec_memory_usage(const fec_t *fec);

/* create a forward error correction instance */
fec_t *fec_create_ex(fec_type_t type, size_t data_symbols,
                     size_t parity_symbols, size_t symbol_size);
fec_t *fec_create(size_t data_symbols, size_t parity_symbols,
                  size_t symbol_size);
void fec_destroy(fec_t *f);

/* encode data symbols and output parity symbols */
bool fec_encode(fec_t *f, const uint8_t *const *data_blocks,
                uint8_t *const *parity_blocks);

/* generate only the requested global parity symbol IDs using the immutable
 * geometry passed to fec_create_ex(). no preceding parity payloads are needed.
 * output buffers must be distinct and must not alias source buffers. a zero
 * count is a no-op and does not prepare RaptorQ. */
bool fec_encode_symbols(fec_t *f, const uint8_t *const *data_blocks,
                        const uint32_t *symbol_ids, size_t count,
                        uint8_t *const *outputs);

/* decode received symbols. missing source symbols need writable destinations;
 * missing parity buffers may be NULL. missing_mask identifies lost blocks. */
bool fec_decode(fec_t *f, uint8_t *const *blocks, const bool *missing_mask);

#endif /* FEC_H */
