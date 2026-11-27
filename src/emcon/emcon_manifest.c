#include "emcon_manifest.h"

#include "cli_parse.h"
#include "fs_util.h"
#include "transport_fec_state.h"
#include "transport_wire.h"

#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <ctype.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MANIFEST_HEADER "QEMCON1\n"
#define CONFIG_LINE_LIMIT 1024U

static bool nonzero(const uint8_t *value, size_t size) {
  uint8_t combined = 0;
  for (size_t i = 0; i < size; i++)
    combined |= value[i];
  return combined != 0;
}

static bool endpoint_valid(const qlinq_emcon_manifest_endpoint_t *ep) {
  if (ep->port == 0 || (ep->family != 4 && ep->family != 6))
    return false;
  if (ep->family == 4 && nonzero(ep->address + 4, 12))
    return false;
  return nonzero(ep->address, ep->family == 4 ? 4 : 16);
}

static bool stream_name_valid(const char *name, size_t cap) {
  const char *end = memchr(name, '\0', cap);
  if (!end || end == name || isspace((unsigned char)name[0]) ||
      isspace((unsigned char)end[-1]))
    return false;
  for (const char *p = name; p < end; p++) {
    unsigned char ch = (unsigned char)*p;
    if (ch < 0x20U || ch == 0x7fU || ch == ',')
      return false;
  }
  return true;
}

const char *qlinq_emcon_strerror(int error) {
  static const struct {
    int code;
    const char *msg;
  } table[] = {
      {QLINQ_EMCON_OK, "ok"},
      {QLINQ_EMCON_INCOMPLETE, "incomplete object"},
      {QLINQ_EMCON_DUPLICATE, "duplicate packet"},
      {QLINQ_EMCON_WOULD_BLOCK, "would block"},
      {QLINQ_EMCON_DISCARDED, "packet discarded"},
      {QLINQ_EMCON_ERR_INVALID, "invalid input"},
      {QLINQ_EMCON_ERR_NO_MEMORY, "out of memory"},
      {QLINQ_EMCON_ERR_IO, "socket or file I/O failed"},
      {QLINQ_EMCON_ERR_CRYPTO, "cryptographic failure"},
      {QLINQ_EMCON_ERR_SIGNATURE, "invalid manifest signature"},
      {QLINQ_EMCON_ERR_KEY_MISMATCH, "traffic key mismatch"},
      {QLINQ_EMCON_ERR_NOT_YET_VALID, "manifest not yet valid"},
      {QLINQ_EMCON_ERR_EXPIRED, "manifest validity window expired"},
      {QLINQ_EMCON_ERR_TOO_LARGE, "buffer or datagram too large"},
      {QLINQ_EMCON_ERR_UNKNOWN_ALIAS, "unknown stream alias"},
      {QLINQ_EMCON_ERR_ACTIVATION, "activation state error"},
      {QLINQ_EMCON_ERR_LOCKED, "sender activation already locked"},
      {QLINQ_EMCON_ERR_REUSED, "receiver key epoch already claimed"},
      {QLINQ_EMCON_ERR_EXHAUSTED, "epoch packet numbers exhausted"},
      {QLINQ_EMCON_ERR_TRANSFER_MISMATCH,
       "group already bound to an incompatible transfer"},
      {QLINQ_EMCON_ERR_INTERRUPTED, "interrupted"},
  };
  for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++)
    if (table[i].code == error)
      return table[i].msg;
  return "unknown EMCON error";
}

int qlinq_emcon_manifest_validate(const qlinq_emcon_manifest_t *manifest,
                                  uint64_t now_ms) {
  if (!manifest ||
      !nonzero(manifest->traffic_key_id, sizeof(manifest->traffic_key_id)) ||
      manifest->flow_id == 0 || manifest->key_epoch == 0 ||
      manifest->valid_from_ms >= manifest->expires_at_ms ||
      !endpoint_valid(&manifest->source) ||
      !endpoint_valid(&manifest->destination) ||
      manifest->source.family != manifest->destination.family ||
      manifest->rate_bytes_per_second == 0 || manifest->burst_bytes == 0 ||
      manifest->terminal_repeat_count == 0 ||
      manifest->terminal_repeat_count > 64 || manifest->symbol_size == 0 ||
      manifest->symbol_size > QLINQ_FEC_MAX_SYMBOL_SIZE ||
      manifest->repair_symbols == 0 ||
      manifest->repair_symbols >= QLINQ_FEC_MAX_TOTAL_SYMBOLS ||
      manifest->stream_count == 0 ||
      manifest->stream_count > QLINQ_EMCON_MANIFEST_MAX_STREAMS)
    return QLINQ_EMCON_ERR_INVALID;

  size_t max_data_symbols =
      QLINQ_FEC_MAX_TOTAL_SYMBOLS - manifest->repair_symbols;
  size_t max_record_size = max_data_symbols * manifest->symbol_size;
  size_t max_packet_size = QLINQ_EMCON_FLEXICAST_OVERHEAD +
                           QLINQ_WIRE_FEC_HEADER_SIZE + manifest->symbol_size;
  if (manifest->burst_bytes < max_packet_size)
    return QLINQ_EMCON_ERR_INVALID;
  for (size_t i = 0; i < manifest->stream_count; i++) {
    const qlinq_emcon_manifest_stream_t *s = &manifest->streams[i];
    if (s->maximum_record_size == 0 ||
        s->maximum_record_size > max_record_size ||
        !stream_name_valid(s->name, sizeof(s->name)))
      return QLINQ_EMCON_ERR_INVALID;
    for (size_t j = 0; j < i; j++)
      if (manifest->streams[j].alias == s->alias)
        return QLINQ_EMCON_ERR_INVALID;
  }
  if (now_ms != 0 && now_ms < manifest->valid_from_ms)
    return QLINQ_EMCON_ERR_NOT_YET_VALID;
  if (now_ms != 0 && now_ms >= manifest->expires_at_ms)
    return QLINQ_EMCON_ERR_EXPIRED;
  return QLINQ_EMCON_OK;
}

static bool format_endpoint(const qlinq_emcon_manifest_endpoint_t *ep,
                            char *out, size_t cap) {
  char addr[INET6_ADDRSTRLEN];
  if (!inet_ntop(ep->family == 4 ? AF_INET : AF_INET6, ep->address, addr,
                 sizeof(addr)))
    return false;
  int n = snprintf(out, cap, ep->family == 6 ? "[%s]:%u" : "%s:%u", addr,
                   (unsigned)ep->port);
  return n > 0 && (size_t)n < cap;
}

int qlinq_emcon_manifest_encode(const qlinq_emcon_manifest_t *manifest,
                                uint8_t *output, size_t capacity,
                                size_t *output_size) {
  int valid = qlinq_emcon_manifest_validate(manifest, 0);
  if (valid != QLINQ_EMCON_OK || !output || !output_size)
    return valid == QLINQ_EMCON_OK ? QLINQ_EMCON_ERR_INVALID : valid;
  char key_hex[QLINQ_EMCON_MANIFEST_KEY_ID_SIZE * 2 + 1];
  char src_ep[INET6_ADDRSTRLEN + 16], dst_ep[INET6_ADDRSTRLEN + 16];
  if (!format_endpoint(&manifest->source, src_ep, sizeof(src_ep)) ||
      !format_endpoint(&manifest->destination, dst_ep, sizeof(dst_ep)))
    return QLINQ_EMCON_ERR_INVALID;
  qlinq_hex_encode(manifest->traffic_key_id, sizeof(manifest->traffic_key_id),
                   key_hex);

  char scratch[QLINQ_EMCON_MANIFEST_MAX_SIZE];
  int pos = snprintf(
      scratch, sizeof(scratch),
      MANIFEST_HEADER "traffic_key_id=%s\nflow_id=%" PRIu64 "\nkey_epoch=%u\n"
                      "valid_from_ms=%" PRIu64 "\nexpires_at_ms=%" PRIu64 "\n"
                      "source=%s\ndestination=%s\ninterface_index=%u\n"
                      "rate_bytes_per_second=%" PRIu64 "\nburst_bytes=%u\n"
                      "terminal_repeat_count=%u\nsymbol_size=%u\n"
                      "repair_symbols=%u\n",
      key_hex, manifest->flow_id, manifest->key_epoch, manifest->valid_from_ms,
      manifest->expires_at_ms, src_ep, dst_ep, manifest->interface_index,
      manifest->rate_bytes_per_second, manifest->burst_bytes,
      manifest->terminal_repeat_count, manifest->symbol_size,
      manifest->repair_symbols);
  if (pos <= 0 || (size_t)pos >= sizeof(scratch))
    return QLINQ_EMCON_ERR_TOO_LARGE;
  size_t used = (size_t)pos;
  for (size_t i = 0; i < manifest->stream_count; i++) {
    const qlinq_emcon_manifest_stream_t *s = &manifest->streams[i];
    int n =
        snprintf(scratch + used, sizeof(scratch) - used, "stream=%u,%u,%u,%s\n",
                 s->alias, s->content_type, s->maximum_record_size, s->name);
    if (n <= 0 || (size_t)n >= sizeof(scratch) - used)
      return QLINQ_EMCON_ERR_TOO_LARGE;
    used += (size_t)n;
  }
  if (capacity < used)
    return QLINQ_EMCON_ERR_TOO_LARGE;
  memcpy(output, scratch, used);
  *output_size = used;
  return QLINQ_EMCON_OK;
}

enum {
  F_KEY_ID = 1U << 0,
  F_FLOW_ID = 1U << 1,
  F_KEY_EPOCH = 1U << 2,
  F_VALID_FROM = 1U << 3,
  F_EXPIRES_AT = 1U << 4,
  F_VALID_FOR = 1U << 5,
  F_SOURCE = 1U << 6,
  F_DEST = 1U << 7,
  F_IFINDEX = 1U << 8,
  F_RATE = 1U << 9,
  F_BURST = 1U << 10,
  F_REPEAT = 1U << 11,
  F_SYM_SIZE = 1U << 12,
  F_REPAIR = 1U << 13,
};

#define CONF_REQUIRED_FIELDS                                                   \
  (F_KEY_EPOCH | F_SOURCE | F_DEST | F_RATE | F_BURST | F_REPEAT |             \
   F_SYM_SIZE | F_REPAIR)
#define CANONICAL_REQUIRED_FIELDS                                              \
  (CONF_REQUIRED_FIELDS | F_KEY_ID | F_FLOW_ID | F_VALID_FROM | F_EXPIRES_AT | \
   F_IFINDEX)

typedef enum { V_U16, V_U32, V_U64, V_KEY_ID, V_EP } field_kind_t;

typedef struct {
  const char *key;
  uint32_t bit;
  field_kind_t kind;
  size_t offset;
  uint64_t max_val;
} field_desc_t;

static const field_desc_t field_table[] = {
    {"traffic_key_id", F_KEY_ID, V_KEY_ID,
     offsetof(qlinq_emcon_manifest_t, traffic_key_id), 0},
    {"flow_id", F_FLOW_ID, V_U64, offsetof(qlinq_emcon_manifest_t, flow_id),
     UINT64_MAX},
    {"key_epoch", F_KEY_EPOCH, V_U32,
     offsetof(qlinq_emcon_manifest_t, key_epoch), UINT32_MAX},
    {"valid_from_ms", F_VALID_FROM, V_U64,
     offsetof(qlinq_emcon_manifest_t, valid_from_ms), UINT64_MAX},
    {"expires_at_ms", F_EXPIRES_AT, V_U64,
     offsetof(qlinq_emcon_manifest_t, expires_at_ms), UINT64_MAX},
    {"source", F_SOURCE, V_EP, offsetof(qlinq_emcon_manifest_t, source), 0},
    {"destination", F_DEST, V_EP, offsetof(qlinq_emcon_manifest_t, destination),
     0},
    {"interface_index", F_IFINDEX, V_U32,
     offsetof(qlinq_emcon_manifest_t, interface_index), UINT32_MAX},
    {"rate_bytes_per_second", F_RATE, V_U64,
     offsetof(qlinq_emcon_manifest_t, rate_bytes_per_second), UINT64_MAX},
    {"burst_bytes", F_BURST, V_U32,
     offsetof(qlinq_emcon_manifest_t, burst_bytes), UINT32_MAX},
    {"terminal_repeat_count", F_REPEAT, V_U16,
     offsetof(qlinq_emcon_manifest_t, terminal_repeat_count), UINT16_MAX},
    {"symbol_size", F_SYM_SIZE, V_U16,
     offsetof(qlinq_emcon_manifest_t, symbol_size), UINT16_MAX},
    {"repair_symbols", F_REPAIR, V_U16,
     offsetof(qlinq_emcon_manifest_t, repair_symbols), UINT16_MAX},
};

static char *trim_ws(char *s) {
  while (isspace((unsigned char)*s))
    s++;
  char *end = s + strlen(s);
  while (end > s && isspace((unsigned char)end[-1]))
    *--end = '\0';
  return s;
}

static bool random_nonzero_u64(uint64_t *out) {
  do {
    if (RAND_bytes((uint8_t *)out, sizeof(*out)) != 1)
      return false;
  } while (*out == 0);
  return true;
}

static bool decode_lower_hex(const char *text, uint8_t *out, size_t size) {
  if (strlen(text) != size * 2)
    return false;
  for (size_t i = 0; i < size * 2; i++) {
    char c = text[i];
    int nib = (c >= '0' && c <= '9')   ? c - '0'
              : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                                       : -1;
    if (nib < 0)
      return false;
    out[i / 2] = (i & 1) ? (uint8_t)(out[i / 2] | nib) : (uint8_t)(nib << 4);
  }
  return true;
}

static bool parse_content_type(const char *text, int base, uint8_t *out) {
  static const struct {
    const char *name;
    uint8_t val;
  } names[] = {{"video", 0}, {"audio", 1}, {"input", 2},
               {"text", 3},  {"data", 4},  {"telemetry", 6}};
  if (base == 0) {
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
      if (strcmp(text, names[i].name) == 0) {
        *out = names[i].val;
        return true;
      }
  }
  uint64_t numeric;
  if (!cli_parse_u64_base(text, UINT8_MAX, base, &numeric))
    return false;
  *out = (uint8_t)numeric;
  return true;
}

static bool parse_stream_entry(char *value, bool conf_mode,
                               qlinq_emcon_manifest_t *manifest) {
  if (manifest->stream_count >= QLINQ_EMCON_MANIFEST_MAX_STREAMS)
    return false;
  int base = conf_mode ? 0 : 10;
  char *parts[4], *cursor = value;
  for (size_t i = 0; i < 3; i++) {
    char *comma = strchr(cursor, ',');
    if (!comma)
      return false;
    *comma = '\0';
    parts[i] = conf_mode ? trim_ws(cursor) : cursor;
    cursor = comma + 1;
  }
  parts[3] = conf_mode ? trim_ws(cursor) : cursor;
  if (strchr(parts[3], ',') || strlen(parts[3]) == 0 ||
      strlen(parts[3]) >= QLINQ_EMCON_MANIFEST_STREAM_NAME_SIZE)
    return false;
  uint64_t alias, max_rec;
  qlinq_emcon_manifest_stream_t *s = &manifest->streams[manifest->stream_count];
  if (!cli_parse_u64_base(parts[0], UINT8_MAX, base, &alias) ||
      !parse_content_type(parts[1], base, &s->content_type) ||
      !cli_parse_u64_base(parts[2], UINT32_MAX, base, &max_rec) || max_rec == 0)
    return false;
  s->alias = (uint8_t)alias;
  s->maximum_record_size = (uint32_t)max_rec;
  memcpy(s->name, parts[3], strlen(parts[3]) + 1);
  manifest->stream_count++;
  return true;
}

static bool parse_kv_pair(const char *key, char *value, bool conf_mode,
                          qlinq_emcon_manifest_t *manifest, uint32_t *seen,
                          uint64_t *valid_for_seconds) {
  int base = conf_mode ? 0 : 10;
  if (strcmp(key, "stream") == 0)
    return parse_stream_entry(value, conf_mode, manifest);
  if (conf_mode && strcmp(key, "valid_for_seconds") == 0) {
    if ((*seen & F_VALID_FOR) != 0 ||
        !cli_parse_u64_base(value, UINT64_MAX / 1000U, 0, valid_for_seconds) ||
        *valid_for_seconds == 0)
      return false;
    *seen |= F_VALID_FOR;
    return true;
  }
  for (size_t i = 0; i < sizeof(field_table) / sizeof(field_table[0]); i++) {
    const field_desc_t *d = &field_table[i];
    if (strcmp(key, d->key) != 0)
      continue;
    if ((conf_mode && d->bit == F_KEY_ID) || (*seen & d->bit) != 0)
      return false;
    uint8_t *dst = (uint8_t *)manifest + d->offset;
    if (conf_mode && d->bit == F_FLOW_ID && strcmp(value, "random") == 0) {
      if (!random_nonzero_u64(&manifest->flow_id))
        return false;
    } else if (d->kind == V_KEY_ID) {
      if (!decode_lower_hex(value, dst, QLINQ_EMCON_MANIFEST_KEY_ID_SIZE))
        return false;
    } else if (d->kind == V_EP) {
      qlinq_emcon_manifest_endpoint_t *ep =
          (qlinq_emcon_manifest_endpoint_t *)dst;
      if (!cli_parse_ip_endpoint(value, base, &ep->family, ep->address,
                                 &ep->port))
        return false;
    } else {
      uint64_t parsed;
      if (!cli_parse_u64_base(value, d->max_val, base, &parsed))
        return false;
      if (d->kind == V_U16)
        *(uint16_t *)dst = (uint16_t)parsed;
      else if (d->kind == V_U32)
        *(uint32_t *)dst = (uint32_t)parsed;
      else
        *(uint64_t *)dst = parsed;
    }
    *seen |= d->bit;
    return true;
  }
  return false;
}

int qlinq_emcon_manifest_decode(qlinq_emcon_manifest_t *manifest,
                                const uint8_t *input, size_t input_size,
                                uint64_t now_ms) {
  const size_t hdr_len = sizeof(MANIFEST_HEADER) - 1U;
  if (!manifest || !input || input_size <= hdr_len ||
      input_size > QLINQ_EMCON_MANIFEST_MAX_SIZE ||
      input[input_size - 1] != '\n' ||
      memcmp(input, MANIFEST_HEADER, hdr_len) != 0 ||
      memchr(input, '\0', input_size) != NULL)
    return QLINQ_EMCON_ERR_INVALID;

  char copy[QLINQ_EMCON_MANIFEST_MAX_SIZE + 1];
  memcpy(copy, input + hdr_len, input_size - hdr_len);
  copy[input_size - hdr_len] = '\0';

  qlinq_emcon_manifest_t parsed = {0};
  uint32_t seen = 0;
  uint64_t unused_dur = 0;
  char *cursor = copy;
  while (*cursor) {
    char *nl = strchr(cursor, '\n');
    if (!nl)
      return QLINQ_EMCON_ERR_INVALID;
    *nl = '\0';
    char *eq = strchr(cursor, '=');
    if (!eq || eq == cursor || !eq[1])
      return QLINQ_EMCON_ERR_INVALID;
    *eq = '\0';
    if (!parse_kv_pair(cursor, eq + 1, false, &parsed, &seen, &unused_dur))
      return QLINQ_EMCON_ERR_INVALID;
    cursor = nl + 1;
  }
  if (seen != CANONICAL_REQUIRED_FIELDS)
    return QLINQ_EMCON_ERR_INVALID;
  uint8_t reencoded[QLINQ_EMCON_MANIFEST_MAX_SIZE];
  size_t reencoded_size = 0;
  int ret = qlinq_emcon_manifest_encode(&parsed, reencoded, sizeof(reencoded),
                                        &reencoded_size);
  if (ret != QLINQ_EMCON_OK)
    return ret;
  if (reencoded_size != input_size || memcmp(reencoded, input, input_size) != 0)
    return QLINQ_EMCON_ERR_INVALID;
  ret = qlinq_emcon_manifest_validate(&parsed, now_ms);
  if (ret == QLINQ_EMCON_OK)
    *manifest = parsed;
  return ret;
}

int qlinq_emcon_manifest_parse_conf(const char *path,
                                    qlinq_emcon_manifest_t *manifest) {
  FILE *file = path ? fopen(path, "r") : NULL;
  if (!file || !manifest) {
    if (file)
      fclose(file);
    return QLINQ_EMCON_ERR_IO;
  }
  memset(manifest, 0, sizeof(*manifest));
  if (!random_nonzero_u64(&manifest->flow_id)) {
    fclose(file);
    return QLINQ_EMCON_ERR_CRYPTO;
  }

  uint32_t seen = 0;
  uint64_t valid_for_seconds = 0;
  char *line = NULL;
  size_t cap = 0, line_no = 0;
  bool ok = true;
  while (getline(&line, &cap, file) >= 0) {
    line_no++;
    if (strlen(line) > CONFIG_LINE_LIMIT) {
      ok = false;
      break;
    }
    char *content = trim_ws(line);
    if (!content[0] || content[0] == '#')
      continue;
    char *eq = strchr(content, '=');
    if (!eq) {
      ok = false;
      break;
    }
    *eq = '\0';
    char *key = trim_ws(content), *val = trim_ws(eq + 1);
    if (!key[0] || !val[0] ||
        !parse_kv_pair(key, val, true, manifest, &seen, &valid_for_seconds)) {
      ok = false;
      break;
    }
  }
  if (ferror(file))
    ok = false;
  free(line);
  fclose(file);
  if (!ok) {
    fprintf(stderr, "qlinq-emcon: invalid manifest config at line %zu\n",
            line_no);
    return QLINQ_EMCON_ERR_INVALID;
  }
  if ((seen & CONF_REQUIRED_FIELDS) != CONF_REQUIRED_FIELDS ||
      manifest->stream_count == 0) {
    fprintf(stderr,
            "qlinq-emcon: manifest config is missing required fields\n");
    return QLINQ_EMCON_ERR_INVALID;
  }
  bool dur = (seen & F_VALID_FOR) != 0;
  bool any_exp = (seen & (F_VALID_FROM | F_EXPIRES_AT)) != 0;
  bool both_exp =
      (seen & (F_VALID_FROM | F_EXPIRES_AT)) == (F_VALID_FROM | F_EXPIRES_AT);
  if ((dur && any_exp) || (!dur && !both_exp)) {
    fprintf(
        stderr,
        "qlinq-emcon: use valid_for_seconds or both explicit time fields\n");
    return QLINQ_EMCON_ERR_INVALID;
  }
  if (dur) {
    uint64_t now = qlinq_emcon_realtime_ms();
    if (!now || valid_for_seconds > (UINT64_MAX - now) / 1000U)
      return QLINQ_EMCON_ERR_INVALID;
    manifest->valid_from_ms = now;
    manifest->expires_at_ms = now + valid_for_seconds * 1000U;
  }
  return QLINQ_EMCON_OK;
}

int qlinq_emcon_manifest_digest(const qlinq_emcon_manifest_t *manifest,
                                uint8_t digest[32]) {
  uint8_t encoded[QLINQ_EMCON_MANIFEST_MAX_SIZE];
  size_t encoded_size;
  if (!digest || qlinq_emcon_manifest_encode(manifest, encoded, sizeof(encoded),
                                             &encoded_size) != QLINQ_EMCON_OK)
    return QLINQ_EMCON_ERR_INVALID;
  return SHA256(encoded, encoded_size, digest) ? QLINQ_EMCON_OK
                                               : QLINQ_EMCON_ERR_INVALID;
}

static int manifest_signature(const qlinq_emcon_manifest_t *manifest,
                              EVP_PKEY *key, uint8_t *signature, bool verify) {
  uint8_t encoded[QLINQ_EMCON_MANIFEST_MAX_SIZE];
  size_t encoded_size, sig_size = QLINQ_EMCON_MANIFEST_SIGNATURE_SIZE;
  if (!key || !signature || EVP_PKEY_get_id(key) != EVP_PKEY_ED25519 ||
      qlinq_emcon_manifest_encode(manifest, encoded, sizeof(encoded),
                                  &encoded_size) != QLINQ_EMCON_OK)
    return QLINQ_EMCON_ERR_INVALID;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    return QLINQ_EMCON_ERR_SIGNATURE;
  bool ok = verify ? (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
                      EVP_DigestVerify(ctx, signature, sig_size, encoded,
                                       encoded_size) == 1)
                   : (EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
                      EVP_DigestSign(ctx, signature, &sig_size, encoded,
                                     encoded_size) == 1 &&
                      sig_size == QLINQ_EMCON_MANIFEST_SIGNATURE_SIZE);
  EVP_MD_CTX_free(ctx);
  return ok ? QLINQ_EMCON_OK : QLINQ_EMCON_ERR_SIGNATURE;
}

int qlinq_emcon_manifest_sign(
    const qlinq_emcon_manifest_t *manifest, EVP_PKEY *private_key,
    uint8_t signature[QLINQ_EMCON_MANIFEST_SIGNATURE_SIZE]) {
  return manifest_signature(manifest, private_key, signature, false);
}

int qlinq_emcon_manifest_verify(
    const qlinq_emcon_manifest_t *manifest, EVP_PKEY *public_key,
    const uint8_t signature[QLINQ_EMCON_MANIFEST_SIGNATURE_SIZE]) {
  return manifest_signature(manifest, public_key, (uint8_t *)signature, true);
}

static int read_exact_stream(FILE *file, uint8_t *buffer, size_t capacity,
                             size_t *size) {
  size_t got = fread(buffer, 1, capacity, file);
  if (ferror(file) || fgetc(file) != EOF) {
    OPENSSL_cleanse(buffer, capacity);
    return QLINQ_EMCON_ERR_IO;
  }
  *size = got;
  return QLINQ_EMCON_OK;
}

static int read_exact_file(const char *path, uint8_t *buffer, size_t capacity,
                           size_t *size) {
  FILE *file = path ? fopen(path, "rb") : NULL;
  if (!file)
    return QLINQ_EMCON_ERR_IO;
  int ret = read_exact_stream(file, buffer, capacity, size);
  fclose(file);
  return ret;
}

int qlinq_emcon_manifest_load_signed(qlinq_emcon_manifest_t *manifest,
                                     const char *manifest_file,
                                     const char *signature_file,
                                     const char *public_key_file,
                                     uint64_t now_ms) {
  uint8_t encoded[QLINQ_EMCON_MANIFEST_MAX_SIZE], signature[64];
  size_t encoded_size = 0, sig_size = 0;
  int ret =
      read_exact_file(manifest_file, encoded, sizeof(encoded), &encoded_size);
  if (ret == QLINQ_EMCON_OK)
    ret = read_exact_file(signature_file, signature, sizeof(signature),
                          &sig_size);
  if (ret != QLINQ_EMCON_OK || sig_size != QLINQ_EMCON_MANIFEST_SIGNATURE_SIZE)
    return ret == QLINQ_EMCON_OK ? QLINQ_EMCON_ERR_SIGNATURE : ret;
  qlinq_emcon_manifest_t decoded;
  if ((ret = qlinq_emcon_manifest_decode(&decoded, encoded, encoded_size,
                                         now_ms)) != QLINQ_EMCON_OK)
    return ret;
  FILE *key_file = public_key_file ? fopen(public_key_file, "r") : NULL;
  if (!key_file)
    return QLINQ_EMCON_ERR_IO;
  EVP_PKEY *public_key = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
  fclose(key_file);
  if (!public_key)
    return QLINQ_EMCON_ERR_SIGNATURE;
  ret = qlinq_emcon_manifest_verify(&decoded, public_key, signature);
  EVP_PKEY_free(public_key);
  if (ret == QLINQ_EMCON_OK)
    *manifest = decoded;
  return ret;
}

int qlinq_emcon_traffic_key_id(
    const uint8_t *secret, size_t secret_size,
    uint8_t key_id[QLINQ_EMCON_MANIFEST_KEY_ID_SIZE]) {
  if (!secret || secret_size == 0 || !key_id)
    return QLINQ_EMCON_ERR_INVALID;
  return SHA256(secret, secret_size, key_id) ? QLINQ_EMCON_OK
                                             : QLINQ_EMCON_ERR_INVALID;
}

int qlinq_emcon_traffic_key_load(const char *key_file, uint8_t *secret,
                                 size_t capacity, size_t *secret_size) {
  if (secret_size)
    *secret_size = 0;
  if (!secret || capacity == 0 || !secret_size)
    return QLINQ_EMCON_ERR_IO;
  int fd = qlinq_open_restricted_file(key_file, false);
  if (fd < 0)
    return QLINQ_EMCON_ERR_IO;
  FILE *file = fdopen(fd, "rb");
  if (!file) {
    close(fd);
    return QLINQ_EMCON_ERR_IO;
  }
  size_t loaded = 0;
  int ret = read_exact_stream(file, secret, capacity, &loaded);
  fclose(file);
  if (ret != QLINQ_EMCON_OK || loaded == 0) {
    OPENSSL_cleanse(secret, capacity);
    return ret == QLINQ_EMCON_OK ? QLINQ_EMCON_ERR_IO : ret;
  }
  *secret_size = loaded;
  return QLINQ_EMCON_OK;
}

int qlinq_emcon_manifest_check_traffic_key(
    const qlinq_emcon_manifest_t *manifest, const uint8_t *secret,
    size_t secret_size) {
  uint8_t key_id[QLINQ_EMCON_MANIFEST_KEY_ID_SIZE];
  if (!manifest ||
      qlinq_emcon_traffic_key_id(secret, secret_size, key_id) != QLINQ_EMCON_OK)
    return QLINQ_EMCON_ERR_INVALID;
  int ret = CRYPTO_memcmp(manifest->traffic_key_id, key_id, sizeof(key_id)) == 0
                ? QLINQ_EMCON_OK
                : QLINQ_EMCON_ERR_KEY_MISMATCH;
  OPENSSL_cleanse(key_id, sizeof(key_id));
  return ret;
}
