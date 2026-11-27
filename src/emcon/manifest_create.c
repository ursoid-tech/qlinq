#include "manifest_create.h"

#include "emcon_manifest.h"

#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define GENERATED_TRAFFIC_KEY_SIZE 32U
#define CONFIG_LINE_LIMIT 1024U
#define DEFAULT_REPLAY_WINDOW_PACKETS 4096U

enum config_field {
  FIELD_SESSION_ID = 1U << 0,
  FIELD_SENDER_ID = 1U << 1,
  FIELD_FLOW_ID = 1U << 2,
  FIELD_KEY_EPOCH = 1U << 3,
  FIELD_INITIAL_PACKET_NUMBER = 1U << 4,
  FIELD_VALID_FROM = 1U << 5,
  FIELD_EXPIRES_AT = 1U << 6,
  FIELD_VALID_FOR = 1U << 7,
  FIELD_SOURCE = 1U << 8,
  FIELD_DESTINATION = 1U << 9,
  FIELD_INTERFACE_INDEX = 1U << 10,
  FIELD_REPLAY_WINDOW = 1U << 11,
  FIELD_RATE = 1U << 12,
  FIELD_BURST = 1U << 13,
  FIELD_METADATA_REPEAT = 1U << 14,
  FIELD_TERMINAL_REPEAT = 1U << 15,
  FIELD_SYMBOL_SIZE = 1U << 16,
  FIELD_REPAIR_SYMBOLS = 1U << 17,
};

#define REQUIRED_FIELDS                                                        \
  (FIELD_KEY_EPOCH | FIELD_SOURCE | FIELD_DESTINATION | FIELD_RATE |           \
   FIELD_BURST | FIELD_METADATA_REPEAT | FIELD_TERMINAL_REPEAT |               \
   FIELD_SYMBOL_SIZE | FIELD_REPAIR_SYMBOLS)

typedef struct {
  const char *config_file;
  const char *signing_key_file;
  const char *manifest_file;
  const char *signature_file;
  const char *traffic_key_file;
  const char *generated_traffic_key_file;
  const char *public_key_file;
} create_options_t;

static void show_create_help(FILE *output, const char *program) {
  fprintf(output,
          "usage: %s manifest create CONFIG [options]\n\n"
          "Required options:\n"
          "  --signing-key FILE           protected Ed25519 private key\n"
          "  --output FILE                new canonical manifest file\n"
          "  --signature FILE             new detached signature file\n"
          "  --traffic-key FILE           use an existing mode 0600 key\n"
          "  --generate-traffic-key FILE  create a new mode 0600 key\n"
          "                               (choose exactly one key option)\n\n"
          "Optional:\n"
          "  --public-key-output FILE     optionally export the public key\n\n"
          "The signing key must be an Ed25519 private key in PEM format with "
          "mode 0600.\n"
          "Generated traffic keys are 32 random bytes written to a new mode "
          "0600 file.\n",
          program);
}

static bool parse_u64(const char *text, uint64_t maximum, uint64_t *value) {
  if (!text || !text[0] || text[0] == '-')
    return false;
  errno = 0;
  char *end = NULL;
  unsigned long long parsed = strtoull(text, &end, 0);
  if (errno != 0 || !end || *end != '\0' || parsed > maximum)
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

static bool parse_create_options(int argc, char **argv,
                                 create_options_t *options) {
  memset(options, 0, sizeof(*options));
  if (argc < 3 || strcmp(argv[1], "manifest") != 0 ||
      strcmp(argv[2], "create") != 0)
    return false;
  for (int i = 3; i < argc; i++) {
    const char *value = NULL;
    if (strcmp(argv[i], "--signing-key") == 0 &&
        option_value(argc, argv, &i, &value))
      options->signing_key_file = value;
    else if (strcmp(argv[i], "--output") == 0 &&
             option_value(argc, argv, &i, &value))
      options->manifest_file = value;
    else if (strcmp(argv[i], "--signature") == 0 &&
             option_value(argc, argv, &i, &value))
      options->signature_file = value;
    else if (strcmp(argv[i], "--traffic-key") == 0 &&
             option_value(argc, argv, &i, &value))
      options->traffic_key_file = value;
    else if (strcmp(argv[i], "--generate-traffic-key") == 0 &&
             option_value(argc, argv, &i, &value))
      options->generated_traffic_key_file = value;
    else if (strcmp(argv[i], "--public-key-output") == 0 &&
             option_value(argc, argv, &i, &value))
      options->public_key_file = value;
    else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
      return false;
    else if (argv[i][0] != '-' && !options->config_file)
      options->config_file = argv[i];
    else
      return false;
  }
  return options->config_file && options->signing_key_file &&
         options->manifest_file && options->signature_file &&
         (!!options->traffic_key_file != !!options->generated_traffic_key_file);
}

static char *trim(char *text) {
  while (isspace((unsigned char)*text))
    text++;
  char *end = text + strlen(text);
  while (end > text && isspace((unsigned char)end[-1]))
    *--end = '\0';
  return text;
}

static int hex_nibble(char value) {
  if (value >= '0' && value <= '9')
    return value - '0';
  if (value >= 'a' && value <= 'f')
    return value - 'a' + 10;
  if (value >= 'A' && value <= 'F')
    return value - 'A' + 10;
  return -1;
}

static int decode_hex_id(const char *text, uint8_t *output, size_t size) {
  if (strcmp(text, "random") == 0)
    return RAND_bytes(output, (int)size) == 1 ? 0 : -1;
  if (strlen(text) != size * 2)
    return -1;
  for (size_t i = 0; i < size; i++) {
    int high = hex_nibble(text[i * 2]);
    int low = hex_nibble(text[i * 2 + 1]);
    if (high < 0 || low < 0)
      return -1;
    output[i] = (uint8_t)((high << 4) | low);
  }
  return 0;
}

static int parse_endpoint(const char *text,
                          qlinq_emcon_manifest_endpoint_t *endpoint) {
  char address[INET6_ADDRSTRLEN];
  const char *port_text;
  size_t address_size;
  if (text[0] == '[') {
    const char *close = strchr(text + 1, ']');
    if (!close || close[1] != ':' || close == text + 1)
      return -1;
    address_size = (size_t)(close - text - 1);
    port_text = close + 2;
    endpoint->family = 6;
    if (address_size >= sizeof(address))
      return -1;
    memcpy(address, text + 1, address_size);
  } else {
    const char *colon = strrchr(text, ':');
    if (!colon || colon == text || strchr(text, ':') != colon)
      return -1;
    address_size = (size_t)(colon - text);
    port_text = colon + 1;
    endpoint->family = 4;
    if (address_size >= sizeof(address))
      return -1;
    memcpy(address, text, address_size);
  }
  address[address_size] = '\0';
  uint64_t port;
  memset(endpoint->address, 0, sizeof(endpoint->address));
  int family = endpoint->family == 4 ? AF_INET : AF_INET6;
  return parse_u64(port_text, UINT16_MAX, &port) && port != 0 &&
                 inet_pton(family, address, endpoint->address) == 1
             ? (endpoint->port = (uint16_t)port, 0)
             : -1;
}

static int content_type(const char *text, uint8_t *value) {
  static const struct {
    const char *name;
    uint8_t value;
  } types[] = {{"video", 0}, {"audio", 1}, {"input", 2},
               {"text", 3},  {"data", 4},  {"telemetry", 6}};
  for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++)
    if (strcmp(text, types[i].name) == 0) {
      *value = types[i].value;
      return 0;
    }
  uint64_t numeric;
  if (!parse_u64(text, UINT8_MAX, &numeric))
    return -1;
  *value = (uint8_t)numeric;
  return 0;
}

static int parse_stream(char *value, qlinq_emcon_manifest_t *manifest) {
  if (manifest->stream_count >= QLINQ_EMCON_MANIFEST_MAX_STREAMS)
    return -1;
  char *parts[4], *save = NULL;
  for (size_t i = 0; i < 4; i++) {
    parts[i] = strtok_r(i == 0 ? value : NULL, ",", &save);
    if (!parts[i])
      return -1;
    parts[i] = trim(parts[i]);
  }
  if (strtok_r(NULL, ",", &save) != NULL || !parts[3][0] ||
      strlen(parts[3]) >= QLINQ_EMCON_MANIFEST_STREAM_NAME_SIZE)
    return -1;
  uint64_t alias, maximum_record_size;
  qlinq_emcon_manifest_stream_t *stream =
      &manifest->streams[manifest->stream_count];
  if (!parse_u64(parts[0], UINT8_MAX, &alias) ||
      content_type(parts[1], &stream->content_type) != 0 ||
      !parse_u64(parts[2], UINT32_MAX, &maximum_record_size) ||
      maximum_record_size == 0)
    return -1;
  stream->alias = (uint8_t)alias;
  stream->delivery = QLINQ_EMCON_DELIVERY_RATELESS;
  stream->maximum_record_size = (uint32_t)maximum_record_size;
  memcpy(stream->name, parts[3], strlen(parts[3]) + 1);
  manifest->stream_count++;
  return 0;
}

static int assign_number(const char *value, uint64_t maximum, uint32_t field,
                         uint32_t *seen, uint64_t *destination) {
  uint64_t parsed;
  if ((*seen & field) != 0 || !parse_u64(value, maximum, &parsed))
    return -1;
  *seen |= field;
  *destination = parsed;
  return 0;
}

static int parse_config_value(char *key, char *value,
                              qlinq_emcon_manifest_t *manifest, uint32_t *seen,
                              uint64_t *valid_for_seconds) {
  uint64_t number;
  if (strcmp(key, "session_id") == 0) {
    if ((*seen & FIELD_SESSION_ID) != 0 ||
        decode_hex_id(value, manifest->session_id,
                      sizeof(manifest->session_id)) != 0)
      return -1;
    *seen |= FIELD_SESSION_ID;
  } else if (strcmp(key, "sender_id") == 0) {
    if ((*seen & FIELD_SENDER_ID) != 0 ||
        decode_hex_id(value, manifest->sender_id,
                      sizeof(manifest->sender_id)) != 0)
      return -1;
    *seen |= FIELD_SENDER_ID;
  } else if (strcmp(key, "flow_id") == 0) {
    if ((*seen & FIELD_FLOW_ID) != 0)
      return -1;
    if (strcmp(value, "random") == 0) {
      do {
        if (RAND_bytes((uint8_t *)&manifest->flow_id,
                       sizeof(manifest->flow_id)) != 1)
          return -1;
      } while (manifest->flow_id == 0);
    } else if (!parse_u64(value, UINT64_MAX, &manifest->flow_id)) {
      return -1;
    }
    *seen |= FIELD_FLOW_ID;
  } else if (strcmp(key, "key_epoch") == 0) {
    if (assign_number(value, UINT32_MAX, FIELD_KEY_EPOCH, seen, &number) != 0)
      return -1;
    manifest->key_epoch = (uint32_t)number;
  } else if (strcmp(key, "initial_packet_number") == 0) {
    if (assign_number(value, UINT64_MAX, FIELD_INITIAL_PACKET_NUMBER, seen,
                      &manifest->initial_packet_number) != 0)
      return -1;
  } else if (strcmp(key, "valid_from_ms") == 0) {
    if (assign_number(value, UINT64_MAX, FIELD_VALID_FROM, seen,
                      &manifest->valid_from_ms) != 0)
      return -1;
  } else if (strcmp(key, "expires_at_ms") == 0) {
    if (assign_number(value, UINT64_MAX, FIELD_EXPIRES_AT, seen,
                      &manifest->expires_at_ms) != 0)
      return -1;
  } else if (strcmp(key, "valid_for_seconds") == 0) {
    if (assign_number(value, UINT64_MAX / 1000U, FIELD_VALID_FOR, seen,
                      valid_for_seconds) != 0 ||
        *valid_for_seconds == 0)
      return -1;
  } else if (strcmp(key, "source") == 0) {
    if ((*seen & FIELD_SOURCE) != 0 ||
        parse_endpoint(value, &manifest->source) != 0)
      return -1;
    *seen |= FIELD_SOURCE;
  } else if (strcmp(key, "destination") == 0) {
    if ((*seen & FIELD_DESTINATION) != 0 ||
        parse_endpoint(value, &manifest->destination) != 0)
      return -1;
    *seen |= FIELD_DESTINATION;
  } else if (strcmp(key, "interface_index") == 0) {
    if (assign_number(value, UINT32_MAX, FIELD_INTERFACE_INDEX, seen,
                      &number) != 0)
      return -1;
    manifest->interface_index = (uint32_t)number;
  } else if (strcmp(key, "replay_window_packets") == 0) {
    if (assign_number(value, UINT32_MAX, FIELD_REPLAY_WINDOW, seen, &number) !=
        0)
      return -1;
    manifest->replay_window_packets = (uint32_t)number;
  } else if (strcmp(key, "rate_bytes_per_second") == 0) {
    if (assign_number(value, UINT64_MAX, FIELD_RATE, seen,
                      &manifest->rate_bytes_per_second) != 0)
      return -1;
  } else if (strcmp(key, "burst_bytes") == 0) {
    if (assign_number(value, UINT32_MAX, FIELD_BURST, seen, &number) != 0)
      return -1;
    manifest->burst_bytes = (uint32_t)number;
  } else if (strcmp(key, "metadata_repeat_interval_ms") == 0) {
    if (assign_number(value, UINT32_MAX, FIELD_METADATA_REPEAT, seen,
                      &number) != 0)
      return -1;
    manifest->metadata_repeat_interval_ms = (uint32_t)number;
  } else if (strcmp(key, "terminal_repeat_count") == 0) {
    if (assign_number(value, UINT16_MAX, FIELD_TERMINAL_REPEAT, seen,
                      &number) != 0)
      return -1;
    manifest->terminal_repeat_count = (uint16_t)number;
  } else if (strcmp(key, "symbol_size") == 0) {
    if (assign_number(value, UINT16_MAX, FIELD_SYMBOL_SIZE, seen, &number) != 0)
      return -1;
    manifest->symbol_size = (uint16_t)number;
  } else if (strcmp(key, "repair_symbols") == 0) {
    if (assign_number(value, UINT16_MAX, FIELD_REPAIR_SYMBOLS, seen, &number) !=
        0)
      return -1;
    manifest->repair_symbols = (uint16_t)number;
  } else if (strcmp(key, "stream") == 0) {
    return parse_stream(value, manifest);
  } else {
    return -1;
  }
  return 0;
}

static uint64_t realtime_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_REALTIME, &now) != 0)
    return 0;
  return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static int read_config(const char *path, qlinq_emcon_manifest_t *manifest) {
  FILE *file = fopen(path, "r");
  if (!file)
    return -1;
  memset(manifest, 0, sizeof(*manifest));
  manifest->cipher_suite = QLINQ_EMCON_CIPHER_AES_128_GCM_SHA256;
  manifest->replay_window_packets = DEFAULT_REPLAY_WINDOW_PACKETS;
  if (RAND_bytes(manifest->session_id, sizeof(manifest->session_id)) != 1 ||
      RAND_bytes(manifest->sender_id, sizeof(manifest->sender_id)) != 1) {
    fclose(file);
    return -1;
  }
  do {
    if (RAND_bytes((uint8_t *)&manifest->flow_id, sizeof(manifest->flow_id)) !=
        1) {
      fclose(file);
      return -1;
    }
  } while (manifest->flow_id == 0);

  uint32_t seen = 0;
  uint64_t valid_for_seconds = 0;
  char *line = NULL;
  size_t capacity = 0, line_number = 0;
  int ret = 0;
  while (getline(&line, &capacity, file) >= 0) {
    line_number++;
    if (strlen(line) > CONFIG_LINE_LIMIT) {
      ret = -1;
      break;
    }
    char *content = trim(line);
    if (!content[0] || content[0] == '#')
      continue;
    char *equals = strchr(content, '=');
    if (!equals) {
      ret = -1;
      break;
    }
    *equals = '\0';
    char *key = trim(content), *value = trim(equals + 1);
    if (!key[0] || !value[0] ||
        parse_config_value(key, value, manifest, &seen, &valid_for_seconds) !=
            0) {
      ret = -1;
      break;
    }
  }
  if (ferror(file))
    ret = -1;
  if (ret != 0)
    fprintf(stderr, "qlinq-emcon: invalid manifest config at line %zu\n",
            line_number);
  free(line);
  fclose(file);
  if (ret != 0 || (seen & REQUIRED_FIELDS) != REQUIRED_FIELDS ||
      manifest->stream_count == 0) {
    if (ret == 0)
      fprintf(stderr,
              "qlinq-emcon: manifest config is missing required fields\n");
    return -1;
  }
  bool duration = (seen & FIELD_VALID_FOR) != 0;
  bool explicit_window = (seen & (FIELD_VALID_FROM | FIELD_EXPIRES_AT)) ==
                         (FIELD_VALID_FROM | FIELD_EXPIRES_AT);
  if (duration == explicit_window) {
    fprintf(
        stderr,
        "qlinq-emcon: use valid_for_seconds or both explicit time fields\n");
    return -1;
  }
  if (duration) {
    uint64_t now = realtime_ms();
    if (now == 0 || valid_for_seconds > (UINT64_MAX - now) / 1000U)
      return -1;
    manifest->valid_from_ms = now;
    manifest->expires_at_ms = now + valid_for_seconds * 1000U;
  }
  return 0;
}

static int open_restricted_regular(const char *path) {
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  struct stat info;
  if (fd < 0 || fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
      info.st_uid != geteuid() || (info.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    if (fd >= 0)
      close(fd);
    return -1;
  }
  return fd;
}

static EVP_PKEY *load_signing_key(const char *path) {
  int fd = open_restricted_regular(path);
  if (fd < 0)
    return NULL;
  FILE *file = fdopen(fd, "r");
  if (!file) {
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

static int write_all(int fd, const uint8_t *data, size_t size) {
  size_t offset = 0;
  while (offset < size) {
    ssize_t written = write(fd, data + offset, size - offset);
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      return -1;
    offset += (size_t)written;
  }
  return 0;
}

static int sync_parent_directory(const char *path) {
  char *copy = strdup(path);
  if (!copy)
    return -1;
  char *slash = strrchr(copy, '/');
  const char *directory = ".";
  if (slash) {
    if (slash == copy)
      slash[1] = '\0';
    else
      *slash = '\0';
    directory = copy;
  }
  int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  int ret = fd >= 0 && fsync(fd) == 0 ? 0 : -1;
  if (fd >= 0)
    close(fd);
  free(copy);
  return ret;
}

static int create_file(const char *path, const uint8_t *data, size_t size,
                       mode_t mode) {
  int fd =
      open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
  if (fd < 0)
    return -1;
  int ret = write_all(fd, data, size) == 0 && fdatasync(fd) == 0 ? 0 : -1;
  int saved_errno = errno;
  if (close(fd) != 0)
    ret = -1;
  errno = saved_errno;
  if (ret == 0 && sync_parent_directory(path) != 0)
    ret = -1;
  if (ret != 0)
    unlink(path);
  return ret;
}

static int create_public_key_file(const char *path, EVP_PKEY *key) {
  int fd =
      open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644);
  if (fd < 0)
    return -1;
  FILE *file = fdopen(fd, "w");
  if (!file) {
    close(fd);
    unlink(path);
    return -1;
  }
  int ret = PEM_write_PUBKEY(file, key) == 1 && fflush(file) == 0 &&
                    fdatasync(fd) == 0
                ? 0
                : -1;
  if (fclose(file) != 0)
    ret = -1;
  if (ret == 0 && sync_parent_directory(path) != 0)
    ret = -1;
  if (ret != 0)
    unlink(path);
  return ret;
}

static void print_hex(FILE *output, const uint8_t *value, size_t size) {
  for (size_t i = 0; i < size; i++)
    fprintf(output, "%02x", value[i]);
}

int qlinq_emcon_manifest_command(int argc, char **argv) {
  bool help = false;
  for (int i = 2; i < argc; i++)
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
      help = true;
  create_options_t options;
  if (help || !parse_create_options(argc, argv, &options)) {
    show_create_help(help ? stdout : stderr, argv[0]);
    return help ? 0 : 2;
  }

  qlinq_emcon_manifest_t manifest;
  if (read_config(options.config_file, &manifest) != 0)
    return 1;
  EVP_PKEY *signing_key = load_signing_key(options.signing_key_file);
  if (!signing_key) {
    fprintf(
        stderr,
        "qlinq-emcon: signing key must be a protected Ed25519 private key\n");
    return 1;
  }

  uint8_t traffic_key[64];
  size_t traffic_key_size = 0;
  bool generated_key = options.generated_traffic_key_file != NULL;
  bool generated_key_created = false;
  const char *traffic_key_path = generated_key
                                     ? options.generated_traffic_key_file
                                     : options.traffic_key_file;
  int ret;
  if (generated_key) {
    traffic_key_size = GENERATED_TRAFFIC_KEY_SIZE;
    ret = RAND_bytes(traffic_key, (int)traffic_key_size) == 1 ? 0 : -1;
    if (ret == 0) {
      ret = create_file(traffic_key_path, traffic_key, traffic_key_size, 0600);
      generated_key_created = ret == 0;
    }
  } else {
    ret = qlinq_emcon_traffic_key_load(
              traffic_key_path, traffic_key, sizeof(traffic_key),
              &traffic_key_size) == QLINQ_EMCON_MANIFEST_OK
              ? 0
              : -1;
  }
  if (ret != 0 || traffic_key_size != GENERATED_TRAFFIC_KEY_SIZE ||
      qlinq_emcon_traffic_key_id(traffic_key, traffic_key_size,
                                 manifest.traffic_key_id) !=
          QLINQ_EMCON_MANIFEST_OK) {
    fprintf(stderr, "qlinq-emcon: traffic key creation or loading failed\n");
    if (generated_key_created)
      unlink(traffic_key_path);
    OPENSSL_cleanse(traffic_key, sizeof(traffic_key));
    EVP_PKEY_free(signing_key);
    return 1;
  }

  uint8_t encoded[QLINQ_EMCON_MANIFEST_MAX_SIZE];
  uint8_t signature[QLINQ_EMCON_MANIFEST_SIGNATURE_SIZE];
  size_t encoded_size = 0;
  ret = qlinq_emcon_manifest_encode(&manifest, encoded, sizeof(encoded),
                                    &encoded_size) == QLINQ_EMCON_MANIFEST_OK &&
                qlinq_emcon_manifest_sign(&manifest, signing_key, signature) ==
                    QLINQ_EMCON_MANIFEST_OK
            ? 0
            : -1;
  bool manifest_created = false, signature_created = false,
       public_created = false;
  if (ret == 0) {
    ret = create_file(options.manifest_file, encoded, encoded_size, 0644);
    manifest_created = ret == 0;
  }
  if (ret == 0) {
    ret =
        create_file(options.signature_file, signature, sizeof(signature), 0644);
    signature_created = ret == 0;
  }
  if (ret == 0 && options.public_key_file) {
    ret = create_public_key_file(options.public_key_file, signing_key);
    public_created = ret == 0;
  }
  if (ret != 0) {
    fprintf(stderr, "qlinq-emcon: cannot create provisioning output files\n");
    if (manifest_created)
      unlink(options.manifest_file);
    if (signature_created)
      unlink(options.signature_file);
    if (public_created)
      unlink(options.public_key_file);
    if (generated_key_created)
      unlink(traffic_key_path);
  } else {
    fprintf(stderr, "qlinq-emcon: created manifest %s\n  session_id=",
            options.manifest_file);
    print_hex(stderr, manifest.session_id, sizeof(manifest.session_id));
    fprintf(stderr, "\n  sender_id=");
    print_hex(stderr, manifest.sender_id, sizeof(manifest.sender_id));
    fprintf(stderr, "\n  flow_id=%" PRIu64 " epoch=%u streams=%u\n",
            manifest.flow_id, manifest.key_epoch, manifest.stream_count);
  }
  OPENSSL_cleanse(traffic_key, sizeof(traffic_key));
  OPENSSL_cleanse(signature, sizeof(signature));
  EVP_PKEY_free(signing_key);
  return ret == 0 ? 0 : 1;
}
