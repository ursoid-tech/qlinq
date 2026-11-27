/* qlinq-emcon: minimal cold-start file/stdin sender, receiver, and provisioner
 */

#include "cli_parse.h"
#include "emcon_manifest.h"
#include "emcon_session.h"
#include "fs_util.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
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
#include <unistd.h>

#define EMCON_DEFAULT_BLOCK_SIZE 16384U
#define EMCON_DEFAULT_RESERVATION_PACKETS 65536U
#define EMCON_FILE_REORDER_SLOTS QLINQ_EMCON_REPLAY_WINDOW_PACKETS
#define EMCON_FILE_REORDER_MAX_BYTES (32U * 1024U * 1024U)
#define GENERATED_TRAFFIC_KEY_SIZE 32U

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
  const char *config_file;
  const char *signing_key_file;
  const char *manifest_file;
  const char *signature_file;
  const char *traffic_key_file;
  const char *generated_traffic_key_file;
  const char *public_key_file;
} create_options_t;

typedef struct {
  uint64_t object_id;
  uint8_t *data;
  size_t size;
  bool active;
} emcon_pending_t;

typedef uint8_t emcon_digest_t[QLINQ_EMCON_MANIFEST_DIGEST_SIZE];

static volatile sig_atomic_t emcon_running = 1;

static void handle_signal(int signal_number) {
  (void)signal_number;
  emcon_running = 0;
}

static bool is_cancelled(void *user_data) {
  (void)user_data;
  return !emcon_running;
}

static bool has_help_flag(int argc, char **argv, int start) {
  for (int i = start; i < argc; i++)
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
      return true;
  return false;
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
          "  --block-size BYTES           sender record size (default 16384)\n"
          "  --reservation-packets N      sender durable nonce block "
          "(default 65536)\n\n"
          "Multicast receiver options (choose one mode):\n"
          "  --interface NAME             receiver-local interface\n"
          "  --preprovisioned             use existing host group membership\n"
          "  --join-group                 lab mode; kernel sends IGMP/MLD\n",
          program, program, program);
}

static void show_create_help(FILE *output, const char *program) {
  fprintf(output,
          "usage: %s manifest create CONFIG [options]\n\n"
          "Required options:\n"
          "  --signing-key FILE           protected Ed25519 private key\n"
          "  --output FILE                new canonical manifest file\n"
          "  --signature FILE             new detached signature file\n"
          "  --traffic-key FILE           use an existing mode 0600 key\n"
          "  --generate-traffic-key FILE  create a new mode 0600 key\n"
          "Optional:\n"
          "  --public-key-output FILE     optionally export the public key\n",
          program);
}

static int sync_parent_directory(const char *path) {
  char *copy = strdup(path);
  if (!copy)
    return -1;
  char *slash = strrchr(copy, '/');
  const char *directory = ".";
  if (slash) {
    slash[slash == copy ? 1 : 0] = '\0';
    directory = copy;
  }
  int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  int ret = fd >= 0 && fsync(fd) == 0 ? 0 : -1;
  if (fd >= 0)
    close(fd);
  free(copy);
  return ret;
}

static int create_durable_file(const char *path, const void *data, size_t size,
                               mode_t mode) {
  int fd =
      open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
  if (fd < 0)
    return -1;
  int ret =
      qlinq_write_exact(fd, data, size) == 0 && qlinq_sync_file_data(fd) == 0
          ? 0
          : -1;
  if (close(fd) != 0 || (ret == 0 && sync_parent_directory(path) != 0))
    ret = -1;
  if (ret != 0)
    unlink(path);
  return ret;
}

static int create_public_key_file(const char *path, EVP_PKEY *key) {
  BIO *mem = BIO_new(BIO_s_mem());
  char *pem_data = NULL;
  long pem_len = 0;
  int ret = -1;
  if (mem && PEM_write_bio_PUBKEY(mem, key) == 1 &&
      (pem_len = BIO_get_mem_data(mem, &pem_data)) > 0)
    ret = create_durable_file(path, pem_data, (size_t)pem_len, 0644);
  BIO_free(mem);
  return ret;
}

static EVP_PKEY *load_signing_key(const char *path) {
  int fd = qlinq_open_restricted_file(path, true);
  FILE *file = fd >= 0 ? fdopen(fd, "r") : NULL;
  if (!file) {
    if (fd >= 0)
      close(fd);
    return NULL;
  }
  EVP_PKEY *key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
  fclose(file);
  if (key && EVP_PKEY_get_id(key) != EVP_PKEY_ED25519) {
    EVP_PKEY_free(key);
    return NULL;
  }
  return key;
}

static bool parse_create_options(int argc, char **argv, create_options_t *opt) {
  memset(opt, 0, sizeof(*opt));
  if (argc < 3 || strcmp(argv[1], "manifest") != 0 ||
      strcmp(argv[2], "create") != 0)
    return false;
  for (int i = 3; i < argc; i++) {
    const char *v = NULL;
    if (strcmp(argv[i], "--signing-key") == 0 &&
        cli_option_value(argc, argv, &i, &v))
      opt->signing_key_file = v;
    else if (strcmp(argv[i], "--output") == 0 &&
             cli_option_value(argc, argv, &i, &v))
      opt->manifest_file = v;
    else if (strcmp(argv[i], "--signature") == 0 &&
             cli_option_value(argc, argv, &i, &v))
      opt->signature_file = v;
    else if (strcmp(argv[i], "--traffic-key") == 0 &&
             cli_option_value(argc, argv, &i, &v))
      opt->traffic_key_file = v;
    else if (strcmp(argv[i], "--generate-traffic-key") == 0 &&
             cli_option_value(argc, argv, &i, &v))
      opt->generated_traffic_key_file = v;
    else if (strcmp(argv[i], "--public-key-output") == 0 &&
             cli_option_value(argc, argv, &i, &v))
      opt->public_key_file = v;
    else if (argv[i][0] != '-' && !opt->config_file)
      opt->config_file = argv[i];
    else
      return false;
  }
  return opt->config_file && opt->signing_key_file && opt->manifest_file &&
         opt->signature_file &&
         (!!opt->traffic_key_file != !!opt->generated_traffic_key_file);
}

static int run_manifest_command(int argc, char **argv) {
  bool help = has_help_flag(argc, argv, 2);
  create_options_t opt;
  if (help || !parse_create_options(argc, argv, &opt)) {
    show_create_help(help ? stdout : stderr, argv[0]);
    return help ? 0 : 2;
  }
  qlinq_emcon_manifest_t manifest;
  if (qlinq_emcon_manifest_parse_conf(opt.config_file, &manifest) !=
      QLINQ_EMCON_OK)
    return 1;
  EVP_PKEY *signing_key = load_signing_key(opt.signing_key_file);
  if (!signing_key) {
    fprintf(
        stderr,
        "qlinq-emcon: signing key must be a protected Ed25519 private key\n");
    return 1;
  }

  uint8_t traffic_key[64];
  size_t traffic_key_size = 0;
  bool gen = opt.generated_traffic_key_file != NULL, gen_created = false;
  const char *key_path =
      gen ? opt.generated_traffic_key_file : opt.traffic_key_file;
  int ret;
  if (gen) {
    traffic_key_size = GENERATED_TRAFFIC_KEY_SIZE;
    ret = RAND_bytes(traffic_key, (int)traffic_key_size) == 1 &&
                  create_durable_file(key_path, traffic_key, traffic_key_size,
                                      0600) == 0
              ? 0
              : -1;
    gen_created = ret == 0;
  } else {
    ret =
        qlinq_emcon_traffic_key_load(key_path, traffic_key, sizeof(traffic_key),
                                     &traffic_key_size) == QLINQ_EMCON_OK
            ? 0
            : -1;
  }
  if (ret != 0 || traffic_key_size != GENERATED_TRAFFIC_KEY_SIZE ||
      qlinq_emcon_traffic_key_id(traffic_key, traffic_key_size,
                                 manifest.traffic_key_id) != QLINQ_EMCON_OK) {
    fprintf(stderr, "qlinq-emcon: traffic key creation or loading failed\n");
    if (gen_created)
      unlink(key_path);
    OPENSSL_cleanse(traffic_key, sizeof(traffic_key));
    EVP_PKEY_free(signing_key);
    return 1;
  }

  uint8_t encoded[QLINQ_EMCON_MANIFEST_MAX_SIZE];
  uint8_t signature[QLINQ_EMCON_MANIFEST_SIGNATURE_SIZE];
  size_t encoded_size = 0;
  ret = qlinq_emcon_manifest_encode(&manifest, encoded, sizeof(encoded),
                                    &encoded_size) == QLINQ_EMCON_OK &&
                qlinq_emcon_manifest_sign(&manifest, signing_key, signature) ==
                    QLINQ_EMCON_OK
            ? 0
            : -1;
  bool mf_created = false, sig_created = false, pub_created = false;
  if (ret == 0)
    mf_created = (ret = create_durable_file(opt.manifest_file, encoded,
                                            encoded_size, 0644)) == 0;
  if (ret == 0)
    sig_created = (ret = create_durable_file(opt.signature_file, signature,
                                             sizeof(signature), 0644)) == 0;
  if (ret == 0 && opt.public_key_file)
    pub_created =
        (ret = create_public_key_file(opt.public_key_file, signing_key)) == 0;
  if (ret != 0) {
    fprintf(stderr, "qlinq-emcon: cannot create provisioning output files\n");
    if (mf_created)
      unlink(opt.manifest_file);
    if (sig_created)
      unlink(opt.signature_file);
    if (pub_created)
      unlink(opt.public_key_file);
    if (gen_created)
      unlink(key_path);
  } else {
    fprintf(stderr,
            "qlinq-emcon: created manifest %s (flow_id=%" PRIu64
            " epoch=%u streams=%u)\n",
            opt.manifest_file, manifest.flow_id, manifest.key_epoch,
            manifest.stream_count);
  }
  OPENSSL_cleanse(traffic_key, sizeof(traffic_key));
  OPENSSL_cleanse(signature, sizeof(signature));
  EVP_PKEY_free(signing_key);
  return ret == 0 ? 0 : 1;
}

static bool parse_options(int argc, char **argv, emcon_options_t *opt) {
  memset(opt, 0, sizeof(*opt));
  opt->reservation_packets = EMCON_DEFAULT_RESERVATION_PACKETS;
  if (argc < 2)
    return false;
  if (strcmp(argv[1], "send") == 0)
    opt->command = EMCON_SEND;
  else if (strcmp(argv[1], "receive") == 0)
    opt->command = EMCON_RECEIVE;
  else
    return false;

  for (int i = 2; i < argc; i++) {
    const char *v = NULL;
    uint64_t parsed;
    if (strcmp(argv[i], "--manifest") == 0 &&
        cli_option_value(argc, argv, &i, &v))
      opt->manifest_file = v;
    else if (strcmp(argv[i], "--signature") == 0 &&
             cli_option_value(argc, argv, &i, &v))
      opt->signature_file = v;
    else if (strcmp(argv[i], "--public-key") == 0 &&
             cli_option_value(argc, argv, &i, &v))
      opt->public_key_file = v;
    else if (strcmp(argv[i], "--traffic-key") == 0 &&
             cli_option_value(argc, argv, &i, &v))
      opt->traffic_key_file = v;
    else if (strcmp(argv[i], "--state-dir") == 0 &&
             cli_option_value(argc, argv, &i, &v))
      opt->state_directory = v;
    else if (strcmp(argv[i], "--alias") == 0 &&
             cli_option_value(argc, argv, &i, &v)) {
      if (!cli_parse_u64(v, UINT8_MAX, &parsed))
        return false;
      opt->alias = (uint8_t)parsed;
      opt->alias_set = true;
    } else if (strcmp(argv[i], "--group") == 0 &&
               cli_option_value(argc, argv, &i, &v)) {
      if (!cli_parse_u64(v, UINT64_MAX, &opt->group_id))
        return false;
    } else if (strcmp(argv[i], "--block-size") == 0 &&
               cli_option_value(argc, argv, &i, &v)) {
      if (!cli_parse_u64(v, SIZE_MAX, &parsed) || parsed == 0)
        return false;
      opt->block_size = (size_t)parsed;
      opt->block_size_set = true;
    } else if (strcmp(argv[i], "--reservation-packets") == 0 &&
               cli_option_value(argc, argv, &i, &v)) {
      if (!cli_parse_u64(v, UINT64_MAX, &opt->reservation_packets) ||
          opt->reservation_packets == 0)
        return false;
    } else if (strcmp(argv[i], "--interface") == 0 &&
               cli_option_value(argc, argv, &i, &v)) {
      opt->receiver_interface = if_nametoindex(v);
      if (opt->receiver_interface == 0) {
        fprintf(stderr, "qlinq-emcon: unknown receiver interface: %s\n", v);
        return false;
      }
    } else if (strcmp(argv[i], "--preprovisioned") == 0) {
      opt->preprovisioned = true;
    } else if (strcmp(argv[i], "--join-group") == 0) {
      opt->join_group = true;
    } else if ((argv[i][0] != '-' || strcmp(argv[i], "-") == 0) &&
               !opt->data_file) {
      opt->data_file = argv[i];
    } else {
      return false;
    }
  }
  if ((opt->preprovisioned && (!opt->receiver_interface || opt->join_group)) ||
      (opt->command == EMCON_SEND &&
       (opt->receiver_interface || opt->preprovisioned || opt->join_group)))
    return false;
  return opt->manifest_file && opt->signature_file && opt->public_key_file &&
         opt->traffic_key_file && opt->state_directory && opt->data_file;
}

static const qlinq_emcon_manifest_stream_t *
select_stream(const qlinq_emcon_manifest_t *manifest, emcon_options_t *opt) {
  if (!opt->alias_set)
    opt->alias = manifest->streams[0].alias;
  for (size_t i = 0; i < manifest->stream_count; i++)
    if (manifest->streams[i].alias == opt->alias)
      return &manifest->streams[i];
  return NULL;
}

static bool sha256_bytes(const uint8_t *data, size_t size,
                         emcon_digest_t digest) {
  unsigned int len = 0;
  return EVP_Digest(data, size, digest, &len, EVP_sha256(), NULL) == 1 &&
         len == sizeof(emcon_digest_t);
}

static bool pread_full(int fd, uint8_t *buffer, size_t capacity,
                       uint64_t offset, size_t *bytes_read) {
  const uint64_t max_off =
      sizeof(off_t) >= sizeof(int64_t) ? (uint64_t)INT64_MAX : INT32_MAX;
  size_t total = 0;
  while (total < capacity && emcon_running) {
    if (offset > max_off || total > max_off - offset)
      return false;
    ssize_t got =
        pread(fd, buffer + total, capacity - total, (off_t)(offset + total));
    if (got < 0 && errno == EINTR)
      continue;
    if (got < 0)
      return false;
    if (got == 0)
      break;
    total += (size_t)got;
  }
  *bytes_read = total;
  return emcon_running != 0;
}

static void free_record_digests(emcon_digest_t *digests, size_t capacity) {
  if (!digests)
    return;
  OPENSSL_cleanse(digests, capacity * sizeof(*digests));
  free(digests);
}

static bool hash_regular_file(int fd, uint8_t *scratch, size_t block_size,
                              uint64_t *total_bytes, emcon_digest_t digest,
                              emcon_digest_t **record_digests,
                              size_t *record_count, size_t *record_capacity) {
  *record_digests = NULL;
  *record_count = *record_capacity = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
  emcon_digest_t *digests = NULL;
  size_t count = 0, cap = 0;
  uint64_t offset = 0;
  while (ok && emcon_running) {
    size_t got = 0;
    if (!(ok = pread_full(fd, scratch, block_size, offset, &got)) || got == 0)
      break;
    if (count == cap) {
      size_t next = cap ? cap * 2U : 64U;
      emcon_digest_t *grown =
          (next > cap && next <= SIZE_MAX / sizeof(*digests))
              ? realloc(digests, next * sizeof(*digests))
              : NULL;
      if (!grown) {
        ok = false;
        break;
      }
      digests = grown;
      cap = next;
    }
    ok = sha256_bytes(scratch, got, digests[count]) &&
         EVP_DigestUpdate(ctx, scratch, got) == 1;
    count++;
    offset += got;
    if (got < block_size)
      break;
  }
  unsigned int dlen = 0;
  ok = ok && emcon_running && EVP_DigestFinal_ex(ctx, digest, &dlen) == 1 &&
       dlen == sizeof(emcon_digest_t);
  EVP_MD_CTX_free(ctx);
  if (!ok) {
    free_record_digests(digests, cap);
    return false;
  }
  *total_bytes = offset;
  *record_digests = digests;
  *record_count = count;
  *record_capacity = cap;
  return true;
}

static int run_sender(const emcon_options_t *opt,
                      const qlinq_emcon_manifest_t *manifest,
                      const qlinq_emcon_manifest_stream_t *stream,
                      const uint8_t *traffic_secret,
                      size_t traffic_secret_size) {
  qlinq_emcon_session_t *session = NULL;
  emcon_digest_t *record_digests = NULL;
  size_t record_count = 0, record_cap = 0;
  size_t block_size =
      opt->block_size_set ? opt->block_size : EMCON_DEFAULT_BLOCK_SIZE;
  if (block_size > stream->maximum_record_size)
    block_size = stream->maximum_record_size;
  FILE *input =
      strcmp(opt->data_file, "-") == 0 ? stdin : fopen(opt->data_file, "rb");
  if (!input) {
    fprintf(stderr, "qlinq-emcon: cannot open input: %s\n", strerror(errno));
    return 1;
  }
  uint8_t *block = malloc(block_size);
  bool failed = true;
  uint64_t object_id = 0, bytes = 0;
  struct stat st;
  if (!block || fstat(fileno(input), &st) != 0) {
    fprintf(stderr, "qlinq-emcon: cannot prepare input\n");
    goto done;
  }
  bool regular = S_ISREG(st.st_mode) &&
                 (input != stdin || lseek(fileno(input), 0, SEEK_CUR) == 0);
  qlinq_emcon_transfer_t transfer = {.alias = opt->alias,
                                     .group_id = opt->group_id,
                                     .block_size = (uint32_t)block_size,
                                     .resumable = regular};
  if (regular) {
    if (!hash_regular_file(fileno(input), block, block_size,
                           &transfer.input_size, transfer.input_digest,
                           &record_digests, &record_count, &record_cap)) {
      fprintf(stderr, emcon_running ? "qlinq-emcon: input read failed\n"
                                    : "qlinq-emcon: interrupted\n");
      goto done;
    }
    if (transfer.input_size == 0) {
      fprintf(stderr, "qlinq-emcon: empty input has no finite object range\n");
      goto done;
    }
  }

  failed = false;
  while (emcon_running) {
    size_t size = 0;
    if (regular) {
      if (object_id >= record_count)
        break;
      uint64_t rem = transfer.input_size - bytes;
      size_t expected = rem > block_size ? block_size : (size_t)rem;
      if (!pread_full(fileno(input), block, expected, bytes, &size)) {
        if (emcon_running)
          fprintf(stderr, "qlinq-emcon: input read failed\n");
        failed = true;
        break;
      }
      emcon_digest_t rec_digest;
      uint8_t extra = 0;
      size_t extra_sz = 0;
      bool tail_ok =
          object_id + 1 < record_count ||
          pread_full(fileno(input), &extra, 1, transfer.input_size, &extra_sz);
      if (!tail_ok) {
        if (emcon_running)
          fprintf(stderr, "qlinq-emcon: input read failed\n");
        failed = true;
        break;
      }
      bool same = size == expected && extra_sz == 0 &&
                  sha256_bytes(block, size, rec_digest) &&
                  CRYPTO_memcmp(rec_digest, record_digests[object_id],
                                sizeof(rec_digest)) == 0;
      OPENSSL_cleanse(rec_digest, sizeof(rec_digest));
      if (!same) {
        fprintf(stderr, "qlinq-emcon: input changed during transmission\n");
        failed = true;
        break;
      }
    } else {
      size = fread(block, 1, block_size, input);
      if (ferror(input)) {
        if (emcon_running)
          fprintf(stderr, "qlinq-emcon: input read failed\n");
        failed = true;
        break;
      }
      if (size == 0 || !emcon_running)
        break;
    }

    int ret;
    if (!session) {
      uint64_t now_ms = qlinq_emcon_realtime_ms();
      ret = now_ms ? qlinq_emcon_session_create_sender(
                         &session, manifest, traffic_secret,
                         traffic_secret_size, now_ms, opt->state_directory,
                         opt->reservation_packets, &transfer)
                   : QLINQ_EMCON_ERR_IO;
      if (ret != QLINQ_EMCON_OK) {
        fprintf(stderr, "qlinq-emcon: sender activation failed: %s\n",
                qlinq_emcon_strerror(ret));
        failed = true;
        break;
      }
      qlinq_emcon_session_set_cancel(session, is_cancelled, NULL);
    }
    ret = qlinq_emcon_session_send_object(session, opt->alias, opt->group_id,
                                          object_id, false, 0, block, size);
    if (ret != QLINQ_EMCON_OK) {
      if (ret != QLINQ_EMCON_ERR_INTERRUPTED)
        fprintf(stderr, "qlinq-emcon: send object failed: %s\n",
                qlinq_emcon_strerror(ret));
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
    if (!regular && size != block_size)
      break;
  }

  if (!emcon_running) {
    fprintf(stderr, "qlinq-emcon: interrupted\n");
    failed = true;
  } else if (!failed && object_id == 0) {
    fprintf(stderr, "qlinq-emcon: empty input has no finite object range\n");
    failed = true;
  } else if (!failed && regular) {
    struct stat fin;
    if (fstat(fileno(input), &fin) != 0) {
      fprintf(stderr, "qlinq-emcon: input read failed\n");
      failed = true;
    } else if (!S_ISREG(fin.st_mode) || fin.st_size < 0 ||
               (uint64_t)fin.st_size != transfer.input_size ||
               bytes != transfer.input_size) {
      fprintf(stderr, "qlinq-emcon: input changed during transmission\n");
      failed = true;
    }
  }
  if (!failed) {
    int end_ret = qlinq_emcon_session_send_end(session, opt->alias,
                                               opt->group_id, object_id - 1);
    if (end_ret != QLINQ_EMCON_OK) {
      fprintf(stderr,
              end_ret == QLINQ_EMCON_ERR_INTERRUPTED
                  ? "qlinq-emcon: interrupted\n"
                  : "qlinq-emcon: terminal metadata failed: %s\n",
              qlinq_emcon_strerror(end_ret));
      failed = true;
    }
  }

done:
  free_record_digests(record_digests, record_cap);
  qlinq_emcon_session_stats_t stats = qlinq_emcon_session_stats(session);
  if (block) {
    OPENSSL_cleanse(block, block_size);
    free(block);
  }
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

static bool
pending_exceeds_final(const emcon_pending_t pending[EMCON_FILE_REORDER_SLOTS],
                      uint64_t final_object) {
  for (size_t i = 0; i < EMCON_FILE_REORDER_SLOTS; i++)
    if (pending[i].active && pending[i].object_id > final_object)
      return true;
  return false;
}

static int store_pending(emcon_pending_t pending[EMCON_FILE_REORDER_SLOTS],
                         size_t *pending_bytes, qlinq_emcon_record_t *record) {
  emcon_pending_t *free_slot = NULL;
  for (size_t i = 0; i < EMCON_FILE_REORDER_SLOTS; i++) {
    if (pending[i].active && pending[i].object_id == record->object_id)
      return 0;
    if (!pending[i].active && !free_slot)
      free_slot = &pending[i];
  }
  if (!free_slot ||
      record->size > EMCON_FILE_REORDER_MAX_BYTES - *pending_bytes)
    return -1;
  *free_slot = (emcon_pending_t){.object_id = record->object_id,
                                 .data = record->data,
                                 .size = record->size,
                                 .active = true};
  *pending_bytes += record->size;
  record->data = NULL;
  record->size = 0;
  return 0;
}

static int flush_pending(FILE *output,
                         emcon_pending_t pending[EMCON_FILE_REORDER_SLOTS],
                         size_t *pending_bytes, uint64_t *next_object,
                         bool end_seen, uint64_t final_object,
                         uint64_t *bytes) {
  for (bool found = true; found;) {
    found = false;
    for (size_t i = 0; i < EMCON_FILE_REORDER_SLOTS; i++) {
      if (!pending[i].active || pending[i].object_id != *next_object)
        continue;
      if ((end_seen && pending[i].object_id > final_object) ||
          fwrite(pending[i].data, 1, pending[i].size, output) !=
              pending[i].size)
        return -1;
      *bytes += pending[i].size;
      *pending_bytes -= pending[i].size;
      free(pending[i].data);
      memset(&pending[i], 0, sizeof(pending[i]));
      (*next_object)++;
      found = true;
      break;
    }
  }
  return 0;
}

static FILE *open_receiver_output(const char *path, bool *truncate_output) {
  *truncate_output = false;
  if (strcmp(path, "-") == 0) {
    int flags = fcntl(fileno(stdout), F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) == O_RDONLY) {
      if (flags >= 0)
        errno = EBADF;
      return NULL;
    }
    return stdout;
  }
  /* keep existing output intact until durable claim succeeds */
  int fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0666);
  struct stat info;
  FILE *output = (fd >= 0 && fstat(fd, &info) == 0) ? fdopen(fd, "wb") : NULL;
  if (!output) {
    int saved = errno;
    if (fd >= 0)
      close(fd);
    errno = saved;
    return NULL;
  }
  *truncate_output = S_ISREG(info.st_mode);
  return output;
}

static int run_receiver(const emcon_options_t *opt,
                        const qlinq_emcon_manifest_t *manifest,
                        const uint8_t *traffic_secret,
                        size_t traffic_secret_size, uint64_t now_ms) {
  qlinq_emcon_session_t *session = NULL;
  FILE *output = NULL;
  emcon_pending_t pending[EMCON_FILE_REORDER_SLOTS] = {{0}};
  bool failed = true;
  uint64_t next_object = 0, bytes = 0, final_object = 0;

  int ret = qlinq_emcon_session_prepare_receiver(
      &session, manifest, traffic_secret, traffic_secret_size, now_ms,
      opt->state_directory, opt->receiver_interface, !opt->preprovisioned);
  if (ret == QLINQ_EMCON_OK)
    ret = qlinq_emcon_session_set_receive_filter(session, opt->alias,
                                                 opt->group_id);
  if (ret != QLINQ_EMCON_OK) {
    fprintf(stderr, "qlinq-emcon: receiver activation failed: %s\n",
            qlinq_emcon_strerror(ret));
    goto done;
  }
  bool truncate_output;
  output = open_receiver_output(opt->data_file, &truncate_output);
  if (!output) {
    fprintf(stderr, "qlinq-emcon: cannot open output: %s\n", strerror(errno));
    goto done;
  }
  if (!emcon_running) {
    fprintf(stderr, "qlinq-emcon: interrupted\n");
    goto done;
  }
  ret = qlinq_emcon_session_claim_receiver(session);
  if (ret != QLINQ_EMCON_OK) {
    fprintf(stderr, "qlinq-emcon: receiver activation failed: %s\n",
            qlinq_emcon_strerror(ret));
    goto done;
  }
  if (truncate_output && ftruncate(fileno(output), 0) != 0) {
    fprintf(stderr, "qlinq-emcon: cannot truncate output: %s\n",
            strerror(errno));
    goto done;
  }

  qlinq_emcon_session_set_cancel(session, is_cancelled, NULL);
  size_t pending_bytes = 0;
  bool end_seen = false;
  failed = false;
  while (emcon_running && (!end_seen || next_object <= final_object)) {
    qlinq_emcon_event_t event;
    ret = qlinq_emcon_session_receive(session, &event, false);
    if (ret == QLINQ_EMCON_ERR_INTERRUPTED)
      break;
    if (ret == QLINQ_EMCON_INCOMPLETE || ret == QLINQ_EMCON_DUPLICATE ||
        ret == QLINQ_EMCON_DISCARDED)
      continue;
    if (ret != QLINQ_EMCON_OK) {
      fprintf(stderr, "qlinq-emcon: receive failed: %s\n",
              qlinq_emcon_strerror(ret));
      failed = true;
      break;
    }
    if (event.type == QLINQ_EMCON_EVENT_RECORD &&
        event.value.record.alias == opt->alias &&
        event.value.record.group_id == opt->group_id) {
      qlinq_emcon_record_t *rec = &event.value.record;
      if (end_seen && rec->object_id > final_object) {
        fprintf(stderr, "qlinq-emcon: inconsistent terminal object range\n");
        failed = true;
      } else if (rec->object_id == next_object) {
        if (fwrite(rec->data, 1, rec->size, output) != rec->size) {
          fprintf(stderr, "qlinq-emcon: output write failed\n");
          failed = true;
        } else {
          bytes += rec->size;
          next_object++;
          if (flush_pending(output, pending, &pending_bytes, &next_object,
                            end_seen, final_object, &bytes) != 0) {
            fprintf(stderr, "qlinq-emcon: output write failed\n");
            failed = true;
          }
        }
      } else if (rec->object_id > next_object &&
                 store_pending(pending, &pending_bytes, rec) != 0) {
        fprintf(stderr,
                "qlinq-emcon: reorder capacity exceeded before object %" PRIu64
                "\n",
                next_object);
        failed = true;
      }
    } else if (event.type == QLINQ_EMCON_EVENT_END &&
               event.value.end.alias == opt->alias &&
               event.value.end.group_id == opt->group_id) {
      uint64_t end_id = event.value.end.final_object_id;
      if (end_id == UINT64_MAX || (end_seen && final_object != end_id) ||
          next_object > end_id + 1 || pending_exceeds_final(pending, end_id)) {
        fprintf(stderr, "qlinq-emcon: inconsistent terminal object range\n");
        failed = true;
      } else {
        final_object = end_id;
        end_seen = true;
      }
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

done:
  for (size_t i = 0; i < EMCON_FILE_REORDER_SLOTS; i++)
    free(pending[i].data);
  if (output && output != stdout && fclose(output) != 0)
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
    return run_manifest_command(argc, argv);
  if (has_help_flag(argc, argv, 1)) {
    show_help(stdout, argv[0]);
    return 0;
  }
  emcon_options_t opt;
  if (!parse_options(argc, argv, &opt)) {
    show_help(stderr, argv[0]);
    return 2;
  }
  struct sigaction action = {.sa_handler = handle_signal};
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGINT, &action, NULL) != 0 ||
      sigaction(SIGTERM, &action, NULL) != 0) {
    fprintf(stderr, "qlinq-emcon: signal handler setup failed\n");
    return 1;
  }

  uint64_t now_ms = qlinq_emcon_realtime_ms();
  qlinq_emcon_manifest_t manifest;
  int loaded = now_ms ? qlinq_emcon_manifest_load_signed(
                            &manifest, opt.manifest_file, opt.signature_file,
                            opt.public_key_file, now_ms)
                      : QLINQ_EMCON_ERR_IO;
  if (loaded != QLINQ_EMCON_OK) {
    fprintf(stderr, "qlinq-emcon: signed manifest load failed: %s\n",
            qlinq_emcon_strerror(loaded));
    return 1;
  }
  if (opt.command == EMCON_RECEIVE) {
    bool multicast = qlinq_ip_is_multicast(manifest.destination.family,
                                           manifest.destination.address);
    if (multicast && !opt.preprovisioned && !opt.join_group) {
      fprintf(stderr,
              "qlinq-emcon: multicast receive requires --preprovisioned or "
              "--join-group\n");
      return 2;
    }
    if (!multicast && (opt.preprovisioned || opt.join_group)) {
      fprintf(stderr,
              "qlinq-emcon: --preprovisioned and --join-group require a "
              "multicast destination\n");
      return 2;
    }
  }
  const qlinq_emcon_manifest_stream_t *stream = select_stream(&manifest, &opt);
  if (!stream) {
    fprintf(stderr, "qlinq-emcon: alias is not provisioned by the manifest\n");
    return 1;
  }
  if (opt.command == EMCON_RECEIVE && opt.block_size_set) {
    fprintf(stderr, "qlinq-emcon: --block-size is sender-only\n");
    return 2;
  }
  if (opt.command == EMCON_SEND && opt.block_size_set &&
      opt.block_size > stream->maximum_record_size) {
    fprintf(stderr,
            "qlinq-emcon: block size exceeds manifest record limit %u\n",
            stream->maximum_record_size);
    return 1;
  }

  uint8_t traffic_secret[64];
  size_t traffic_secret_size = 0;
  loaded = qlinq_emcon_traffic_key_load(opt.traffic_key_file, traffic_secret,
                                        sizeof(traffic_secret),
                                        &traffic_secret_size);
  if (loaded != QLINQ_EMCON_OK ||
      qlinq_emcon_manifest_check_traffic_key(
          &manifest, traffic_secret, traffic_secret_size) != QLINQ_EMCON_OK) {
    fprintf(stderr, "qlinq-emcon: traffic key load or identity check failed\n");
    OPENSSL_cleanse(traffic_secret, sizeof(traffic_secret));
    return 1;
  }
  int ret = opt.command == EMCON_SEND
                ? run_sender(&opt, &manifest, stream, traffic_secret,
                             traffic_secret_size)
                : run_receiver(&opt, &manifest, traffic_secret,
                               traffic_secret_size, now_ms);
  OPENSSL_cleanse(traffic_secret, sizeof(traffic_secret));
  return ret;
}
