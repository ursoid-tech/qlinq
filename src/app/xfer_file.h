#ifndef QLINQ_XFER_FILE_H
#define QLINQ_XFER_FILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define XFER_FILE_HASH_SIZE 32

typedef struct xfer_file xfer_file_t;
/* progress callback invoked synchronously on caller thread */
typedef bool (*xfer_file_progress_cb)(void *context, size_t bytes);

/* synchronous file operations for storage worker thread */
xfer_file_t *xfer_file_source_open(const char *path,
                                   xfer_file_progress_cb progress,
                                   void *context, char *error, size_t cap);
xfer_file_t *xfer_file_sink_open(const char *path, uint64_t size,
                                 const uint8_t hash[XFER_FILE_HASH_SIZE],
                                 xfer_file_progress_cb progress, void *context,
                                 char *error, size_t cap);
uint64_t xfer_file_size(const xfer_file_t *file);
const uint8_t *xfer_file_hash(const xfer_file_t *file);
uint64_t xfer_file_offset(const xfer_file_t *file);
bool xfer_file_is_committed(const xfer_file_t *file);
bool xfer_file_prefix_hash(xfer_file_t *file, uint64_t offset,
                           uint8_t out[XFER_FILE_HASH_SIZE], char *error,
                           size_t cap);
bool xfer_file_read(xfer_file_t *file, uint64_t offset, void *buffer,
                    size_t size, char *error, size_t cap);
bool xfer_file_write(xfer_file_t *file, uint64_t offset, const void *data,
                     size_t size, char *error, size_t cap);
bool xfer_file_checkpoint(xfer_file_t *file, char *error, size_t cap);
bool xfer_file_commit(xfer_file_t *file, char *error, size_t cap);
void xfer_file_close(xfer_file_t *file);

#endif
