/* qlinq-emcon: minimal cold-start file/stdin sender and receiver. */

#include "emcon_manifest.h"
#include "emcon_session.h"
#include "manifest_create.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define EMCON_DEFAULT_BLOCK_SIZE 16384U
#define EMCON_DEFAULT_RESERVATION_PACKETS 65536U
#define EMCON_REORDER_SLOTS QLINQ_EMCON_MAX_ACTIVE_OBJECTS

typedef enum { EMCON_SEND, EMCON_RECEIVE } emcon_command_t;

typedef struct {
  emcon_command_t command;
  const char *manifest_file;
  const char *signature_file;
  const char *public_key_file;
  const char *traffic_key_file;
  const char *state_directory;
  const char *data_file;
  uint64_t group_id;
  uint64_t reservation_packets;
  size_t block_size;
  unsigned int receiver_interface;
  uint8_t alias;
  bool alias_set;
  bool block_size_set;
  bool preprovisioned;
  bool join_group;
} emcon_options_t;

typedef struct {
  uint64_t object_id;
  uint8_t *data;
  size_t size;
  bool active;
} emcon_pending_t;

static volatile sig_atomic_t emcon_running = 1;

static void handle_signal(int signal_number) {
  (void)signal_number;
  emcon_running = 0;
}

static void show_help(FILE *output, const char *program) {
  fprintf(output,
          "usage: %s send [options] INPUT|-\n"
          "       %s receive [options] OUTPUT|-\n"
          "       %s manifest create CONFIG [options]\n\n"
          "Required options:\n"
          "  --manifest FILE              canonical EMCON manifest\n"
          "  --signature FILE             detached Ed25519 signature\n"
          "  --public-key FILE            Ed25519 verification key (PEM)\n"
          "  --traffic-key FILE           binary traffic secret (mode 0600)\n"
          "  --state-dir DIRECTORY        stable activation directory (mode "
          "0700)\n\n"
          "Stream options:\n"
          "  --alias N                    manifest alias (default first)\n"
          "  --group N                    group identifier (default 0)\n"
          "  --block-size BYTES           sender record size (default 16384, "
          "bounded by manifest)\n"
          "  --reservation-packets N      sender durable nonce block "
          "(default 65536)\n\n"
          "Multicast receiver options (choose one mode):\n"
          "  --interface NAME             receiver-local interface\n"
          "  --preprovisioned             use existing host group membership;\n"
          "                               requires --interface and a "
          "receive-only link\n"
          "  --join-group                 lab mode; kernel sends IGMP/MLD\n\n"
          "The receiver activation is one-shot. Restart it only with a fresh "
          "traffic secret and incremented epoch.\n",
          program, program, program);
}

static bool parse_u64(const char *text, uint64_t *value) {
  if (!text || !text[0] || text[0] == '-')
    return false;
  errno = 0;
  char *end = NULL;
  unsigned long long parsed = strtoull(text, &end, 10);
  if (errno != 0 || !end || *end != '\0')
    return false;
  *value = (uint64_t)parsed;
  return true;
}

static bool option_value(int argc, char **argv, int *index,
                         const char **value) {
  if (*index + 1 >= argc)
    return false;
  *value = argv[++*index];
  return true;
}

static bool parse_options(int argc, char **argv, emcon_options_t *options) {
  memset(options, 0, sizeof(*options));
  options->reservation_packets = EMCON_DEFAULT_RESERVATION_PACKETS;
  if (argc < 2)
    return false;
  if (strcmp(argv[1], "send") == 0)
    options->command = EMCON_SEND;
  else if (strcmp(argv[1], "receive") == 0)
    options->command = EMCON_RECEIVE;
  else
    return false;

  for (int i = 2; i < argc; i++) {
    const char *value = NULL;
    if (strcmp(argv[i], "--manifest") == 0 &&
        option_value(argc, argv, &i, &value))
      options->manifest_file = value;
    else if (strcmp(argv[i], "--signature") == 0 &&
             option_value(argc, argv, &i, &value))
      options->signature_file = value;
    else if (strcmp(argv[i], "--public-key") == 0 &&
             option_value(argc, argv, &i, &value))
      options->public_key_file = value;
    else if (strcmp(argv[i], "--traffic-key") == 0 &&
             option_value(argc, argv, &i, &value))
      options->traffic_key_file = value;
    else if (strcmp(argv[i], "--state-dir") == 0 &&
             option_value(argc, argv, &i, &value))
      options->state_directory = value;
    else if (strcmp(argv[i], "--alias") == 0 &&
             option_value(argc, argv, &i, &value)) {
      uint64_t alias;
      if (!parse_u64(value, &alias) || alias > UINT8_MAX)
        return false;
      options->alias = (uint8_t)alias;
      options->alias_set = true;
    } else if (strcmp(argv[i], "--group") == 0 &&
               option_value(argc, argv, &i, &value)) {
      if (!parse_u64(value, &options->group_id))
        return false;
    } else if (strcmp(argv[i], "--block-size") == 0 &&
               option_value(argc, argv, &i, &value)) {
      uint64_t block_size;
      if (!parse_u64(value, &block_size) || block_size == 0 ||
          block_size > SIZE_MAX)
        return false;
      options->block_size = (size_t)block_size;
      options->block_size_set = true;
    } else if (strcmp(argv[i], "--reservation-packets") == 0 &&
               option_value(argc, argv, &i, &value)) {
      if (!parse_u64(value, &options->reservation_packets) ||
          options->reservation_packets == 0)
        return false;
    } else if (strcmp(argv[i], "--interface") == 0 &&
               option_value(argc, argv, &i, &value)) {
      options->receiver_interface = if_nametoindex(value);
      if (options->receiver_interface == 0) {
        fprintf(stderr, "qlinq-emcon: unknown receiver interface: %s\n", value);
        return false;
      }
    } else if (strcmp(argv[i], "--preprovisioned") == 0) {
      options->preprovisioned = true;
    } else if (strcmp(argv[i], "--join-group") == 0) {
      options->join_group = true;
    } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      return false;
    } else if (argv[i][0] == '-' && strcmp(argv[i], "-") != 0) {
      return false;
    } else if (!options->data_file) {
      options->data_file = argv[i];
    } else {
      return false;
    }
  }
  if ((options->preprovisioned &&
       (!options->receiver_interface || options->join_group)) ||
      (options->command == EMCON_SEND &&
       (options->receiver_interface || options->preprovisioned ||
        options->join_group)))
    return false;
  return options->manifest_file && options->signature_file &&
         options->public_key_file && options->traffic_key_file &&
         options->state_directory && options->data_file;
}

static const qlinq_emcon_manifest_stream_t *
select_stream(const qlinq_emcon_manifest_t *manifest,
              emcon_options_t *options) {
  if (!options->alias_set)
    options->alias = manifest->streams[0].alias;
  for (size_t i = 0; i < manifest->stream_count; i++)
    if (manifest->streams[i].alias == options->alias)
      return &manifest->streams[i];
  return NULL;
}

static FILE *open_data_file(const char *path, const char *mode,
                            FILE *standard_stream) {
  return strcmp(path, "-") == 0 ? standard_stream : fopen(path, mode);
}

static int run_sender(const emcon_options_t *options,
                      const qlinq_emcon_manifest_t *manifest,
                      const qlinq_emcon_manifest_stream_t *stream,
                      const uint8_t *traffic_secret,
                      size_t traffic_secret_size) {
  qlinq_emcon_session_t *session = NULL;
  FILE *input = open_data_file(options->data_file, "rb", stdin);
  if (!input) {
    fprintf(stderr, "qlinq-emcon: cannot open input: %s\n", strerror(errno));
    return 1;
  }
  size_t block_size =
      options->block_size_set ? options->block_size : EMCON_DEFAULT_BLOCK_SIZE;
  if (block_size > stream->maximum_record_size)
    block_size = stream->maximum_record_size;
  uint8_t *block = malloc(block_size);
  if (!block) {
    fprintf(stderr, "qlinq-emcon: cannot allocate input block\n");
    if (input != stdin)
      fclose(input);
    return 1;
  }

  uint64_t object_id = 0;
  uint64_t bytes = 0;
  bool failed = false;
  while (emcon_running) {
    size_t size = fread(block, 1, block_size, input);
    if (ferror(input)) {
      fprintf(stderr, "qlinq-emcon: input read failed\n");
      failed = true;
      break;
    }
    if (size == 0 || !emcon_running)
      break;
    int ret;
    if (!session) {
      uint64_t now_ms = qlinq_emcon_realtime_ms();
      ret = now_ms ? qlinq_emcon_session_create_sender_persistent(
                         &session, manifest, traffic_secret,
                         traffic_secret_size, now_ms, options->state_directory,
                         options->reservation_packets)
                   : QLINQ_EMCON_SESSION_IO;
      if (ret != QLINQ_EMCON_SESSION_OK) {
        fprintf(stderr, "qlinq-emcon: sender activation failed: %d\n", ret);
        failed = true;
        break;
      }
    }
    ret = qlinq_emcon_session_send_object(session, options->alias,
                                          options->group_id, object_id, false,
                                          0, block, size);
    if (ret != QLINQ_EMCON_SESSION_OK) {
      fprintf(stderr, "qlinq-emcon: send object failed: %d\n", ret);
      failed = true;
      break;
    }
    bytes += size;
    if (object_id == UINT64_MAX) {
      fprintf(stderr, "qlinq-emcon: object identifier exhausted\n");
      failed = true;
      break;
    }
    object_id++;
    if (size != block_size)
      break;
  }
  if (!emcon_running) {
    fprintf(stderr, "qlinq-emcon: interrupted\n");
    failed = true;
  }
  if (!failed && object_id == 0) {
    fprintf(stderr, "qlinq-emcon: empty input has no finite object range\n");
    failed = true;
  }
  if (!failed) {
    qlinq_emcon_end_metadata_t end = {
        .alias = options->alias,
        .group_id = options->group_id,
        .final_object_id = object_id - 1,
    };
    if (RAND_bytes(end.transmission_nonce, sizeof(end.transmission_nonce)) !=
            1 ||
        qlinq_emcon_session_send_end(session, &end) != QLINQ_EMCON_SESSION_OK) {
      fprintf(stderr, "qlinq-emcon: terminal metadata failed\n");
      failed = true;
    }
  }
  qlinq_emcon_session_stats_t stats = qlinq_emcon_session_stats(session);
  OPENSSL_cleanse(block, block_size);
  free(block);
  if (input != stdin && fclose(input) != 0)
    failed = true;
  qlinq_emcon_session_free(session);
  if (!failed)
    fprintf(stderr,
            "qlinq-emcon: transmission complete: objects=%" PRIu64
            " bytes=%" PRIu64 " packets=%" PRIu64 "\n",
            object_id, bytes, stats.send.packets_sent);
  return failed ? 1 : 0;
}

static bool write_record(FILE *output, const uint8_t *data, size_t size) {
  return fwrite(data, 1, size, output) == size;
}

static int store_pending(emcon_pending_t pending[EMCON_REORDER_SLOTS],
                         qlinq_emcon_record_t *record) {
  for (size_t i = 0; i < EMCON_REORDER_SLOTS; i++) {
    if (pending[i].active && pending[i].object_id == record->object_id)
      return 0;
    if (!pending[i].active) {
      pending[i].object_id = record->object_id;
      pending[i].data = record->data;
      pending[i].size = record->size;
      pending[i].active = true;
      record->data = NULL;
      record->size = 0;
      return 0;
    }
  }
  return -1;
}

static int flush_pending(FILE *output,
                         emcon_pending_t pending[EMCON_REORDER_SLOTS],
                         uint64_t *next_object, uint64_t *bytes) {
  bool found;
  do {
    found = false;
    for (size_t i = 0; i < EMCON_REORDER_SLOTS; i++) {
      if (!pending[i].active || pending[i].object_id != *next_object)
        continue;
      if (!write_record(output, pending[i].data, pending[i].size))
        return -1;
      *bytes += pending[i].size;
      free(pending[i].data);
      memset(&pending[i], 0, sizeof(pending[i]));
      (*next_object)++;
      found = true;
      break;
    }
  } while (found);
  return 0;
}

static void free_pending(emcon_pending_t pending[EMCON_REORDER_SLOTS]) {
  for (size_t i = 0; i < EMCON_REORDER_SLOTS; i++)
    free(pending[i].data);
}

static FILE *open_receiver_output(const char *path, bool *truncate_output) {
  *truncate_output = false;
  if (strcmp(path, "-") == 0) {
    int flags = fcntl(fileno(stdout), F_GETFL);
    if (flags < 0)
      return NULL;
    if ((flags & O_ACCMODE) == O_RDONLY) {
      errno = EBADF;
      return NULL;
    }
    return stdout;
  }

  /* keep existing output intact until durable claim succeeds */
  int fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0666);
  if (fd < 0)
    return NULL;
  struct stat info;
  FILE *output = fstat(fd, &info) == 0 ? fdopen(fd, "wb") : NULL;
  if (!output) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return NULL;
  }
  *truncate_output = S_ISREG(info.st_mode);
  return output;
}

static int run_receiver(const emcon_options_t *options,
                        const qlinq_emcon_manifest_t *manifest,
                        const uint8_t *traffic_secret,
                        size_t traffic_secret_size, uint64_t now_ms) {
  qlinq_emcon_session_t *session = NULL;
  int ret = qlinq_emcon_session_prepare_receiver(
      &session, manifest, traffic_secret, traffic_secret_size, now_ms,
      options->state_directory, options->receiver_interface,
      !options->preprovisioned);
  if (ret != QLINQ_EMCON_SESSION_OK) {
    fprintf(stderr, "qlinq-emcon: receiver activation failed: %d\n", ret);
    return 1;
  }
  bool truncate_output;
  FILE *output = open_receiver_output(options->data_file, &truncate_output);
  if (!output) {
    fprintf(stderr, "qlinq-emcon: cannot open output: %s\n", strerror(errno));
    qlinq_emcon_session_free(session);
    return 1;
  }
  if (!emcon_running) {
    fprintf(stderr, "qlinq-emcon: interrupted\n");
  } else {
    ret = qlinq_emcon_session_claim_receiver(session);
    if (ret != QLINQ_EMCON_SESSION_OK)
      fprintf(stderr, "qlinq-emcon: receiver activation failed: %d\n", ret);
    else if (truncate_output && ftruncate(fileno(output), 0) != 0) {
      fprintf(stderr, "qlinq-emcon: cannot truncate output: %s\n",
              strerror(errno));
      ret = QLINQ_EMCON_SESSION_IO;
    }
  }
  if (!emcon_running || ret != QLINQ_EMCON_SESSION_OK) {
    if (output != stdout)
      fclose(output);
    qlinq_emcon_session_free(session);
    return 1;
  }

  emcon_pending_t pending[EMCON_REORDER_SLOTS] = {{0}};
  uint64_t next_object = 0, bytes = 0, final_object = 0;
  bool end_seen = false, failed = false;
  while (emcon_running && (!end_seen || next_object <= final_object)) {
    qlinq_emcon_event_t event;
    ret = qlinq_emcon_session_receive(session, &event, true);
    if (ret == QLINQ_EMCON_SESSION_WOULD_BLOCK) {
      usleep(1000);
      continue;
    }
    if (ret == QLINQ_EMCON_SESSION_INCOMPLETE ||
        ret == QLINQ_EMCON_SESSION_DUPLICATE ||
        ret == QLINQ_EMCON_SESSION_DISCARDED)
      continue;
    if (ret != QLINQ_EMCON_SESSION_OK) {
      fprintf(stderr, "qlinq-emcon: receive failed: %d\n", ret);
      failed = true;
      break;
    }
    if (event.type == QLINQ_EMCON_EVENT_RECORD &&
        event.value.record.alias == options->alias &&
        event.value.record.group_id == options->group_id) {
      if (event.value.record.object_id >= next_object &&
          store_pending(pending, &event.value.record) != 0) {
        fprintf(stderr,
                "qlinq-emcon: reorder capacity exceeded before object %" PRIu64
                "\n",
                next_object);
        failed = true;
      } else if (flush_pending(output, pending, &next_object, &bytes) != 0) {
        fprintf(stderr, "qlinq-emcon: output write failed\n");
        failed = true;
      }
    } else if (event.type == QLINQ_EMCON_EVENT_END &&
               event.value.end.alias == options->alias &&
               event.value.end.group_id == options->group_id) {
      if (event.value.end.final_object_id == UINT64_MAX ||
          (end_seen && final_object != event.value.end.final_object_id) ||
          next_object > event.value.end.final_object_id + 1) {
        fprintf(stderr, "qlinq-emcon: inconsistent terminal object range\n");
        failed = true;
      } else {
        final_object = event.value.end.final_object_id;
        end_seen = true;
      }
    } else if (event.type == QLINQ_EMCON_EVENT_ABORT) {
      fprintf(stderr, "qlinq-emcon: sender aborted the session: reason=%u\n",
              event.value.abort.reason);
      failed = true;
    }
    qlinq_emcon_event_release(&event);
    if (failed)
      break;
  }
  if (!emcon_running) {
    fprintf(stderr, "qlinq-emcon: interrupted\n");
    failed = true;
  }
  if (!failed && fflush(output) != 0)
    failed = true;
  free_pending(pending);
  if (output != stdout && fclose(output) != 0)
    failed = true;
  qlinq_emcon_session_stats_t stats = qlinq_emcon_session_stats(session);
  qlinq_emcon_session_free(session);
  if (!failed)
    fprintf(stderr,
            "qlinq-emcon: receive complete: objects=%" PRIu64 " bytes=%" PRIu64
            " packets=%" PRIu64 "\n",
            next_object, bytes, stats.packets_received);
  return failed ? 1 : 0;
}

int main(int argc, char **argv) {
  if (argc > 1 && strcmp(argv[1], "manifest") == 0)
    return qlinq_emcon_manifest_command(argc, argv);
  bool help_requested = false;
  for (int i = 1; i < argc; i++)
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
      help_requested = true;
  if (help_requested) {
    show_help(stdout, argv[0]);
    return 0;
  }
  emcon_options_t options;
  if (!parse_options(argc, argv, &options)) {
    show_help(stderr, argv[0]);
    return 2;
  }
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  uint64_t now_ms = qlinq_emcon_realtime_ms();
  qlinq_emcon_manifest_t manifest;
  int loaded = qlinq_emcon_manifest_load_signed(
      &manifest, options.manifest_file, options.signature_file,
      options.public_key_file, now_ms);
  if (now_ms == 0 || loaded != QLINQ_EMCON_MANIFEST_OK) {
    fprintf(stderr, "qlinq-emcon: signed manifest load failed: %d\n", loaded);
    return 1;
  }
  if (options.command == EMCON_RECEIVE) {
    const qlinq_emcon_manifest_endpoint_t *destination = &manifest.destination;
    bool multicast = destination->family == 4
                         ? (destination->address[0] & 0xf0U) == 0xe0U
                         : destination->address[0] == 0xffU;
    if (multicast && !options.preprovisioned && !options.join_group) {
      fprintf(stderr,
              "qlinq-emcon: multicast receive requires --preprovisioned or "
              "--join-group\n");
      return 2;
    }
    if (!multicast && (options.preprovisioned || options.join_group)) {
      fprintf(stderr,
              "qlinq-emcon: --preprovisioned and --join-group require a "
              "multicast destination\n");
      return 2;
    }
  }
  const qlinq_emcon_manifest_stream_t *stream =
      select_stream(&manifest, &options);
  if (!stream) {
    fprintf(stderr, "qlinq-emcon: alias is not provisioned by the manifest\n");
    return 1;
  }
  if (options.command == EMCON_RECEIVE && options.block_size_set) {
    fprintf(stderr, "qlinq-emcon: --block-size is sender-only\n");
    return 2;
  }
  if (options.command == EMCON_SEND && options.block_size_set &&
      options.block_size > stream->maximum_record_size) {
    fprintf(stderr,
            "qlinq-emcon: block size exceeds manifest record limit %u\n",
            stream->maximum_record_size);
    return 1;
  }

  uint8_t traffic_secret[64];
  size_t traffic_secret_size = 0;
  loaded = qlinq_emcon_traffic_key_load(options.traffic_key_file,
                                        traffic_secret, sizeof(traffic_secret),
                                        &traffic_secret_size);
  if (loaded != QLINQ_EMCON_MANIFEST_OK ||
      qlinq_emcon_manifest_check_traffic_key(&manifest, traffic_secret,
                                             traffic_secret_size) !=
          QLINQ_EMCON_MANIFEST_OK) {
    fprintf(stderr, "qlinq-emcon: traffic key load or identity check failed\n");
    OPENSSL_cleanse(traffic_secret, sizeof(traffic_secret));
    return 1;
  }
  int ret = options.command == EMCON_SEND
                ? run_sender(&options, &manifest, stream, traffic_secret,
                             traffic_secret_size)
                : run_receiver(&options, &manifest, traffic_secret,
                               traffic_secret_size, now_ms);
  OPENSSL_cleanse(traffic_secret, sizeof(traffic_secret));
  return ret;
}
