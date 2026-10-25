/* file transfer worker protocol; disk work runs on worker thread */
#ifndef QLINQ_APP_XFER_H
#define QLINQ_APP_XFER_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct app_xfer app_xfer_t;
typedef struct {
  bool failed;
  bool done;
  bool output_pending;
  uint64_t disk_bytes;
  uint64_t source_prepare_ms, commit_ms, credit_wait_ms;
  size_t input_queue_bytes, output_queue_bytes;
  char error[256];
} app_xfer_status_t;

app_xfer_t *app_xfer_create(const char *input, const char *output);
/* Opt-in streaming-source protocol; receiver accepts both protocols. */
app_xfer_t *app_xfer_create_streaming(const char *input, const char *output);
void app_xfer_destroy(app_xfer_t *xfer);
void app_xfer_link(app_xfer_t *xfer, bool connected);
bool app_xfer_receive(app_xfer_t *xfer, const void *data, size_t size);
/* borrowed until consume, link, or destroy */
bool app_xfer_peek(app_xfer_t *xfer, const void **data, size_t *size,
                   bool *is_data);
void app_xfer_consume(app_xfer_t *xfer);
/* queue disk progress update */
void app_xfer_progress(app_xfer_t *xfer);
/* Worker readiness for the owner's poll loop. Drain before servicing output. */
int app_xfer_get_fd(const app_xfer_t *xfer);
void app_xfer_drain(app_xfer_t *xfer);
void app_xfer_status(app_xfer_t *xfer, app_xfer_status_t *status);
#endif
