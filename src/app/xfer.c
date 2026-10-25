#include "xfer.h"
#include "xfer_file.h"

#include <openssl/crypto.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ordered reliable track with SHA-256 verified prefix resume */
#define X_HEADER 16U
#define X_PAYLOAD (16U * 1024U)
/* Keep a striped connection supplied across retransmission holes and delayed
 * durable checkpoints. Queue storage remains bounded independently below. */
#define X_WINDOW (128U * 1024U * 1024U)
#define X_CHECKPOINT (1024U * 1024U)
#define X_QUEUE_BYTES (64U * 1024U * 1024U)
#define X_QUEUE_RECORDS 8192U

enum {
  X_OFFER = 1,
  X_ACCEPT,
  X_DATA,
  X_CREDIT,
  X_FINISH,
  X_COMMITTED,
  X_DONE,
  X_ERROR,
  X_PROGRESS,
  X_OFFER_STREAMING,
  X_FINISH_STREAMING
};
enum { X_WAIT, X_SENDING, X_WAIT_COMMIT, X_RECEIVING, X_WAIT_DONE };

typedef struct message {
  struct message *next;
  size_t size;
  unsigned char bytes[];
} message_t;
typedef struct {
  message_t *head, *tail;
  size_t bytes, count;
} queue_t;

struct app_xfer {
  pthread_t thread;
  pthread_mutex_t mutex;
  pthread_cond_t changed;
  int ready[2];
  char *path;
  bool sender, stopping, connected, failed, done, committed;
  bool streaming_source_hash;
  uint64_t disk_bytes, advertised_bytes;
  uint64_t source_prepare_ns, commit_ns, credit_wait_ns;
  uint64_t epoch;
  char error[256];
  queue_t input, output;
};

/* A full nonblocking pipe already represents pending work. Keep output
 * notifications coalesced so backpressure cannot turn poll into a busy loop. */
static void notify_owner(app_xfer_t *x) {
  unsigned char byte = 1;
  ssize_t rc;
  do {
    rc = write(x->ready[1], &byte, sizeof(byte));
  } while (rc < 0 && errno == EINTR);
}

static uint64_t monotonic_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    return 0;
  return (uint64_t)ts.tv_sec * 1000000000U + (uint64_t)ts.tv_nsec;
}

static void put64(unsigned char *p, uint64_t v) {
  for (unsigned i = 0; i < 8; i++)
    p[i] = (unsigned char)(v >> (56U - i * 8U));
}
static uint64_t get64(const unsigned char *p) {
  uint64_t v = 0;
  for (unsigned i = 0; i < 8; i++)
    v = (v << 8U) | p[i];
  return v;
}
static void append(queue_t *q, message_t *m) {
  m->next = NULL;
  if (q->tail)
    q->tail->next = m;
  else
    q->head = m;
  q->tail = m;
  q->bytes += m->size;
  q->count++;
}
static message_t *pop(queue_t *q) {
  message_t *m = q->head;
  if (m) {
    q->head = m->next;
    if (!q->head)
      q->tail = NULL;
    q->bytes -= m->size;
    q->count--;
  }
  return m;
}
static void clear(queue_t *q) {
  message_t *m;
  while ((m = pop(q)) != NULL)
    free(m);
}
static message_t *packet(unsigned type, uint64_t offset, const void *payload,
                         size_t size) {
  message_t *m = malloc(sizeof(*m) + X_HEADER + size);
  if (!m)
    return NULL;
  m->size = X_HEADER + size;
  memcpy(m->bytes, "QXF1", 4);
  m->bytes[4] = (unsigned char)type;
  memset(m->bytes + 5, 0, 3);
  put64(m->bytes + 8, offset);
  if (size)
    memcpy(m->bytes + X_HEADER, payload, size);
  return m;
}
/* called with mutex locked */
static void fail_locked(app_xfer_t *x, const char *error) {
  if (!x->failed) {
    x->failed = true;
    snprintf(x->error, sizeof(x->error), "%s", error);
    /* best-effort diagnostic packet */
    if (x->connected &&
        X_HEADER + strlen(x->error) <= X_QUEUE_BYTES - x->output.bytes &&
        x->output.count < X_QUEUE_RECORDS) {
      message_t *m = packet(X_ERROR, 0, x->error, strlen(x->error));
      if (m)
        append(&x->output, m);
    }
  }
  notify_owner(x);
  pthread_cond_broadcast(&x->changed);
}
static void fail(app_xfer_t *x, uint64_t epoch, const char *error) {
  pthread_mutex_lock(&x->mutex);
  if (!x->stopping && x->epoch == epoch)
    fail_locked(x, error);
  pthread_mutex_unlock(&x->mutex);
}
/* drop packets if epoch changed or disconnected */
static bool send_packet(app_xfer_t *x, uint64_t epoch, unsigned type,
                        uint64_t offset, const void *payload, size_t size) {
  message_t *m = packet(type, offset, payload, size);
  if (!m) {
    fail(x, epoch, "out of memory");
    return false;
  }
  pthread_mutex_lock(&x->mutex);
  while (!x->stopping && !x->failed && x->epoch == epoch && x->connected &&
         (m->size > X_QUEUE_BYTES - x->output.bytes ||
          x->output.count >= X_QUEUE_RECORDS))
    pthread_cond_wait(&x->changed, &x->mutex);
  bool ok = !x->stopping && !x->failed && x->epoch == epoch && x->connected;
  if (ok) {
    bool empty = x->output.head == NULL;
    append(&x->output, m);
    if (empty)
      notify_owner(x);
  } else
    free(m);
  pthread_mutex_unlock(&x->mutex);
  return ok;
}
static void mark_done(app_xfer_t *x, uint64_t epoch) {
  pthread_mutex_lock(&x->mutex);
  if (x->epoch == epoch) {
    x->done = true;
    notify_owner(x);
  }
  pthread_mutex_unlock(&x->mutex);
}

static bool disk_progress(void *context, size_t bytes) {
  app_xfer_t *x = context;
  pthread_mutex_lock(&x->mutex);
  bool ok = !x->stopping;
  if (ok && bytes <= UINT64_MAX - x->disk_bytes)
    x->disk_bytes += bytes;
  pthread_mutex_unlock(&x->mutex);
  return ok;
}

static void *worker(void *arg) {
  app_xfer_t *x = arg;
  xfer_file_t *file = NULL;
  char error[256] = {0};
  unsigned char digest[32], data[X_PAYLOAD];
  uint64_t epoch = 0, offset = 0, durable = 0, size = 0;
  unsigned state = X_WAIT;
  bool offered = false;
  bool streaming = x->sender && x->streaming_source_hash;
  if (x->sender) {
    uint64_t started = monotonic_ns();
    fprintf(stderr, "qlinq-app: transfer source_hash=%s\n",
            streaming ? "streaming" : "preflight");
    file = streaming ? xfer_file_source_open_streaming(x->path, disk_progress,
                                                       x, error, sizeof(error))
                     : xfer_file_source_open(x->path, disk_progress, x, error,
                                             sizeof(error));
    pthread_mutex_lock(&x->mutex);
    x->source_prepare_ns = monotonic_ns() - started;
    if (!file)
      fail_locked(x, error);
    pthread_mutex_unlock(&x->mutex);
    if (!file)
      return NULL;
  }
  for (;;) {
    pthread_mutex_lock(&x->mutex);
    if (x->stopping || x->failed || x->done) {
      pthread_mutex_unlock(&x->mutex);
      break;
    }
    if (epoch != x->epoch) {
      if (x->committed) {
        x->done = true;
        pthread_mutex_unlock(&x->mutex);
        break;
      }
      epoch = x->epoch;
      state = X_WAIT;
      offered = false;
      offset = durable = 0;
      pthread_mutex_unlock(&x->mutex);
      if (!x->sender) {
        streaming = false;
        xfer_file_close(file);
        file = NULL;
      }
      continue;
    }
    if (!x->connected) {
      if (x->committed) {
        x->done = true;
        pthread_mutex_unlock(&x->mutex);
        break;
      }
      pthread_cond_wait(&x->changed, &x->mutex);
      pthread_mutex_unlock(&x->mutex);
      continue;
    }
    message_t *m = pop(&x->input);
    if (m)
      pthread_cond_signal(&x->changed);
    bool produce = x->sender && state == X_SENDING &&
                   (offset == size || offset - durable < X_WINDOW) &&
                   x->output.count < X_QUEUE_RECORDS / 2 &&
                   x->output.bytes < X_QUEUE_BYTES / 2;
    bool offer = x->sender && !offered;
    if (!m && !produce && !offer) {
      bool credit_wait = x->sender && state == X_SENDING && offset < size &&
                         offset - durable >= X_WINDOW;
      uint64_t started = credit_wait ? monotonic_ns() : 0;
      pthread_cond_wait(&x->changed, &x->mutex);
      if (credit_wait)
        x->credit_wait_ns += monotonic_ns() - started;
      pthread_mutex_unlock(&x->mutex);
      continue;
    }
    pthread_mutex_unlock(&x->mutex);

    if (offer) {
      size = xfer_file_size(file);
      offered = send_packet(x, epoch, streaming ? X_OFFER_STREAMING : X_OFFER,
                            size, xfer_file_identity(file), 32);
    }
    if (m) {
      const unsigned char *p = m->bytes;
      unsigned type = p[4];
      uint64_t position = get64(p + 8);
      const unsigned char *payload = p + X_HEADER;
      size_t length = m->size - X_HEADER;
      bool ok = true;
      snprintf(error, sizeof(error), "unexpected transfer message");
      if (type == X_ERROR) {
        snprintf(error, sizeof(error), "remote: %.*s", (int)length,
                 (const char *)payload);
        ok = false;
      } else if (x->sender) {
        if (type == X_ACCEPT && state == X_WAIT && offered && length == 32 &&
            position <= size) {
          ok = xfer_file_source_resume(file, position, digest, error,
                                       sizeof(error));
          if (ok && CRYPTO_memcmp(digest, payload, 32) != 0) {
            snprintf(error, sizeof(error),
                     "resume prefix does not match source");
            ok = false;
          }
          if (ok) {
            offset = durable = position;
            state = X_SENDING;
            fprintf(stderr, "qlinq-app: transfer resume offset=%" PRIu64 "\n",
                    position);
          }
        } else if (type == X_CREDIT && length == 0 &&
                   (state == X_SENDING || state == X_WAIT_COMMIT) &&
                   position >= durable && position <= offset) {
          durable = position;
        } else if (type == X_COMMITTED && state == X_WAIT_COMMIT &&
                   length == 32 && position == size &&
                   CRYPTO_memcmp(payload, xfer_file_hash(file), 32) == 0) {
          if (send_packet(x, epoch, X_DONE, size, NULL, 0))
            mark_done(x, epoch);
        } else {
          ok = false;
        }
      } else if ((type == X_OFFER || type == X_OFFER_STREAMING) &&
                 state == X_WAIT && length == 32) {
        streaming = type == X_OFFER_STREAMING;
        fprintf(stderr, "qlinq-app: transfer protocol=%s\n",
                streaming ? "streaming-v2" : "preflight-v1");
        file =
            streaming
                ? xfer_file_sink_open_streaming(x->path, position, payload,
                                                disk_progress, x, error,
                                                sizeof(error))
                : xfer_file_sink_open(x->path, position, payload, disk_progress,
                                      x, error, sizeof(error));
        ok = file != NULL;
        if (ok) {
          size = position;
          offset = durable = xfer_file_offset(file);
          ok =
              xfer_file_prefix_hash(file, offset, digest, error, sizeof(error));
          if (ok && send_packet(x, epoch, X_ACCEPT, offset, digest, 32))
            state = X_RECEIVING;
        }
      } else if (type == X_DATA && state == X_RECEIVING && length > 0 &&
                 position == offset && length <= size - offset &&
                 length <= X_WINDOW - (offset - durable)) {
        ok = xfer_file_write(file, offset, payload, length, error,
                             sizeof(error));
        if (ok) {
          offset += length;
          if (offset - durable >= X_CHECKPOINT || offset == size) {
            ok = xfer_file_checkpoint(file, error, sizeof(error));
            if (ok) {
              durable = offset;
              (void)send_packet(x, epoch, X_CREDIT, durable, NULL, 0);
            }
          }
        }
      } else if (state == X_RECEIVING && position == size && offset == size &&
                 ((!streaming && type == X_FINISH && length == 0) ||
                  (streaming && type == X_FINISH_STREAMING && length == 32))) {
        uint64_t started = monotonic_ns();
        ok = (!streaming || xfer_file_set_expected_hash(file, payload, error,
                                                        sizeof(error))) &&
             xfer_file_commit(file, error, sizeof(error));
        fprintf(stderr, "qlinq-app: transfer readback_reader=%s\n",
                xfer_file_used_read_ahead(file) ? "read-ahead" : "serial");
        pthread_mutex_lock(&x->mutex);
        x->commit_ns += monotonic_ns() - started;
        pthread_mutex_unlock(&x->mutex);
        if (ok) {
          pthread_mutex_lock(&x->mutex);
          x->committed = true;
          pthread_mutex_unlock(&x->mutex);
          if (send_packet(x, epoch, X_COMMITTED, size, xfer_file_hash(file),
                          32))
            state = X_WAIT_DONE;
        }
      } else if (type == X_DONE && state == X_WAIT_DONE && length == 0 &&
                 position == size) {
        mark_done(x, epoch);
      } else {
        ok = false;
      }
      free(m);
      if (!ok)
        fail(x, epoch, error);
      continue;
    }
    if (produce) {
      if (offset == size) {
        if (!xfer_file_source_finish(file, error, sizeof(error)))
          fail(x, epoch, error);
        else if (send_packet(x, epoch,
                             streaming ? X_FINISH_STREAMING : X_FINISH, size,
                             streaming ? xfer_file_hash(file) : NULL,
                             streaming ? 32 : 0))
          state = X_WAIT_COMMIT;
      } else {
        size_t count = size - offset < sizeof(data) ? (size_t)(size - offset)
                                                    : sizeof(data);
        if (count > X_WINDOW - (offset - durable))
          count = (size_t)(X_WINDOW - (offset - durable));
        if (!xfer_file_read(file, offset, data, count, error, sizeof(error)))
          fail(x, epoch, error);
        else if (send_packet(x, epoch, X_DATA, offset, data, count))
          offset += count;
      }
    }
  }
  xfer_file_close(file);
  return NULL;
}

static app_xfer_t *create(const char *input, const char *output,
                          bool streaming) {
  app_xfer_t *x = calloc(1, sizeof(*x));
  if (!x)
    return NULL;
  x->ready[0] = x->ready[1] = -1;
  x->sender = input != NULL;
  x->streaming_source_hash = streaming;
  x->path = strdup(input ? input : output);
  if (!x->path)
    goto fail_alloc;
  if (pthread_mutex_init(&x->mutex, NULL) != 0)
    goto fail_alloc;
  if (pthread_cond_init(&x->changed, NULL) != 0)
    goto fail_mutex;
  if (pipe(x->ready) != 0)
    goto fail_cond;
  for (size_t i = 0; i < 2; i++) {
    if (fcntl(x->ready[i], F_SETFD, FD_CLOEXEC) < 0 ||
        fcntl(x->ready[i], F_SETFL, O_NONBLOCK) < 0)
      goto fail_pipe;
  }
  if (pthread_create(&x->thread, NULL, worker, x) != 0)
    goto fail_pipe;
  return x;
fail_pipe:
  close(x->ready[0]);
  close(x->ready[1]);
fail_cond:
  pthread_cond_destroy(&x->changed);
fail_mutex:
  pthread_mutex_destroy(&x->mutex);
fail_alloc:
  free(x->path);
  free(x);
  return NULL;
}
app_xfer_t *app_xfer_create(const char *input, const char *output) {
  return create(input, output, false);
}
app_xfer_t *app_xfer_create_streaming(const char *input, const char *output) {
  return create(input, output, true);
}
void app_xfer_destroy(app_xfer_t *x) {
  if (!x)
    return;
  pthread_mutex_lock(&x->mutex);
  x->stopping = true;
  pthread_cond_broadcast(&x->changed);
  pthread_mutex_unlock(&x->mutex);
  pthread_join(x->thread, NULL);
  close(x->ready[0]);
  close(x->ready[1]);
  clear(&x->input);
  clear(&x->output);
  pthread_cond_destroy(&x->changed);
  pthread_mutex_destroy(&x->mutex);
  free(x->path);
  free(x);
}
void app_xfer_link(app_xfer_t *x, bool connected) {
  pthread_mutex_lock(&x->mutex);
  if (x->connected != connected) {
    x->connected = connected;
    if (x->committed) {
      x->done = true;
    } else if (!x->done) {
      x->epoch++;
      x->advertised_bytes = 0;
      clear(&x->input);
      clear(&x->output);
    }
    pthread_cond_broadcast(&x->changed);
  }
  pthread_mutex_unlock(&x->mutex);
}
bool app_xfer_receive(app_xfer_t *x, const void *data, size_t size) {
  const unsigned char *p = data;
  pthread_mutex_lock(&x->mutex);
  if (x->done) {
    pthread_mutex_unlock(&x->mutex);
    return true;
  }
  while (x->connected && !x->failed && !x->done &&
         (size > X_QUEUE_BYTES - x->input.bytes ||
          x->input.count >= X_QUEUE_RECORDS))
    pthread_cond_wait(&x->changed, &x->mutex);

  bool ok = x->connected && !x->failed && size >= X_HEADER &&
            size <= X_HEADER + X_PAYLOAD && memcmp(p, "QXF1", 4) == 0 &&
            p[5] == 0 && p[6] == 0 && p[7] == 0 &&
            size <= X_QUEUE_BYTES - x->input.bytes &&
            x->input.count < X_QUEUE_RECORDS;
  /* bypass queue for progress updates during large file hashing */
  if (ok && p[4] == X_PROGRESS && size == X_HEADER) {
    pthread_mutex_unlock(&x->mutex);
    return true;
  }
  if (ok) {
    message_t *m = malloc(sizeof(*m) + size);
    if (m) {
      m->size = size;
      memcpy(m->bytes, data, size);
      append(&x->input, m);
      pthread_cond_signal(&x->changed);
    } else {
      ok = false;
    }
  }
  if (!ok) {
    fail_locked(x, "invalid transfer record or receive queue exhausted");
  }
  pthread_mutex_unlock(&x->mutex);
  return ok;
}
bool app_xfer_peek(app_xfer_t *x, const void **data, size_t *size,
                   bool *is_data) {
  pthread_mutex_lock(&x->mutex);
  message_t *m = x->output.head;
  if (m) {
    *data = m->bytes;
    *size = m->size;
    *is_data = m->bytes[4] == X_DATA;
  }
  pthread_mutex_unlock(&x->mutex);
  return m != NULL;
}
void app_xfer_consume(app_xfer_t *x) {
  pthread_mutex_lock(&x->mutex);
  free(pop(&x->output));
  pthread_cond_signal(&x->changed);
  pthread_mutex_unlock(&x->mutex);
}
void app_xfer_progress(app_xfer_t *x) {
  pthread_mutex_lock(&x->mutex);
  if (x->connected && !x->failed && !x->done &&
      x->disk_bytes != x->advertised_bytes &&
      x->output.count < X_QUEUE_RECORDS &&
      X_HEADER <= X_QUEUE_BYTES - x->output.bytes) {
    message_t *m = packet(X_PROGRESS, x->disk_bytes, NULL, 0);
    if (m) {
      append(&x->output, m);
      x->advertised_bytes = x->disk_bytes;
    }
  }
  pthread_mutex_unlock(&x->mutex);
}

void app_xfer_status(app_xfer_t *x, app_xfer_status_t *status) {
  pthread_mutex_lock(&x->mutex);
  *status = (app_xfer_status_t){.failed = x->failed,
                                .done = x->done,
                                .output_pending = x->output.head != NULL,
                                .disk_bytes = x->disk_bytes};
  status->source_prepare_ms = x->source_prepare_ns / 1000000U;
  status->commit_ms = x->commit_ns / 1000000U;
  status->credit_wait_ms = x->credit_wait_ns / 1000000U;
  status->input_queue_bytes = x->input.bytes;
  status->output_queue_bytes = x->output.bytes;
  memcpy(status->error, x->error, sizeof(status->error));
  pthread_mutex_unlock(&x->mutex);
}

int app_xfer_get_fd(const app_xfer_t *x) {
  return x->ready[0];
}

void app_xfer_drain(app_xfer_t *x) {
  unsigned char bytes[64];
  ssize_t rc;
  do {
    rc = read(x->ready[0], bytes, sizeof(bytes));
  } while (rc > 0 || (rc < 0 && errno == EINTR));
}
