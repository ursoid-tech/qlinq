#include "emcon_manifest.h"

#include "transport_fec_state.h"
#include "transport_wire.h"

#include <openssl/pem.h>
#include <openssl/sha.h>

#include <stdbool.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MANIFEST_MAGIC_0 'Q'
#define MANIFEST_MAGIC_1 'E'
#define MANIFEST_MAGIC_2 'M'
#define MANIFEST_MAGIC_3 'F'
#define MANIFEST_AEAD_TAG_SIZE 16U

static void write_u16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value >> 8);
  dst[1] = (uint8_t)value;
}

static void write_u32(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)(value >> 24);
  dst[1] = (uint8_t)(value >> 16);
  dst[2] = (uint8_t)(value >> 8);
  dst[3] = (uint8_t)value;
}

static void write_u64(uint8_t *dst, uint64_t value) {
  for (size_t i = 0; i < 8; i++)
    dst[i] = (uint8_t)(value >> (56U - 8U * i));
}

static uint16_t read_u16(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8) | src[1]);
}

static uint32_t read_u32(const uint8_t *src) {
  return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
         ((uint32_t)src[2] << 8) | src[3];
}

static uint64_t read_u64(const uint8_t *src) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; i++)
    value = (value << 8) | src[i];
  return value;
}

static bool nonzero(const uint8_t *value, size_t size) {
  uint8_t combined = 0;
  for (size_t i = 0; i < size; i++)
    combined |= value[i];
  return combined != 0;
}

static bool endpoint_valid(const qlinq_emcon_manifest_endpoint_t *endpoint) {
  size_t address_size = endpoint->family == 4 ? 4 : 16;
  return (endpoint->family == 4 || endpoint->family == 6) &&
         endpoint->port != 0 && nonzero(endpoint->address, address_size);
}

uint64_t qlinq_emcon_packet_number_limit(uint64_t initial_packet_number) {
  uint64_t limit = initial_packet_number + QLINQ_EMCON_MAX_PACKETS_PER_KEY;
  uint64_t wire_limit = UINT64_C(1) + QLINQ_EMCON_MAX_PACKET_NUMBER;
  return limit < wire_limit ? limit : wire_limit;
}

int qlinq_emcon_manifest_validate(const qlinq_emcon_manifest_t *manifest,
                                  uint64_t now_ms) {
  if (!manifest ||
      !nonzero(manifest->session_id, sizeof(manifest->session_id)) ||
      !nonzero(manifest->sender_id, sizeof(manifest->sender_id)) ||
      !nonzero(manifest->traffic_key_id, sizeof(manifest->traffic_key_id)) ||
      manifest->flow_id == 0 || manifest->key_epoch == 0 ||
      manifest->cipher_suite != QLINQ_EMCON_CIPHER_AES_128_GCM_SHA256 ||
      manifest->initial_packet_number > QLINQ_EMCON_MAX_PACKET_NUMBER ||
      manifest->valid_from_ms >= manifest->expires_at_ms ||
      !endpoint_valid(&manifest->source) ||
      !endpoint_valid(&manifest->destination) ||
      manifest->source.family != manifest->destination.family ||
      manifest->replay_window_packets != QLINQ_EMCON_REPLAY_WINDOW_PACKETS ||
      manifest->rate_bytes_per_second == 0 || manifest->burst_bytes == 0 ||
      manifest->metadata_repeat_interval_ms == 0 ||
      manifest->terminal_repeat_count == 0 ||
      manifest->terminal_repeat_count > 64 || manifest->symbol_size == 0 ||
      manifest->symbol_size > QLINQ_FEC_MAX_SYMBOL_SIZE ||
      manifest->repair_symbols == 0 ||
      manifest->repair_symbols >= QLINQ_FEC_MAX_TOTAL_SYMBOLS ||
      manifest->stream_count == 0 ||
      manifest->stream_count > QLINQ_EMCON_MANIFEST_MAX_STREAMS)
    return QLINQ_EMCON_MANIFEST_INVALID;

  size_t maximum_data_symbols =
      QLINQ_FEC_MAX_TOTAL_SYMBOLS - manifest->repair_symbols;
  size_t maximum_record_size = maximum_data_symbols * manifest->symbol_size;
  size_t maximum_packet_size = QLINQ_EMCON_FLEXICAST_OVERHEAD +
                               QLINQ_WIRE_FEC_HEADER_SIZE +
                               manifest->symbol_size;
  if (manifest->burst_bytes < maximum_packet_size)
    return QLINQ_EMCON_MANIFEST_INVALID;
  for (size_t i = 0; i < manifest->stream_count; i++) {
    const qlinq_emcon_manifest_stream_t *stream = &manifest->streams[i];
    if (stream->delivery != QLINQ_EMCON_DELIVERY_RATELESS ||
        stream->maximum_record_size == 0 ||
        stream->maximum_record_size > maximum_record_size ||
        !memchr(stream->name, '\0', sizeof(stream->name)) ||
        stream->name[0] == '\0')
      return QLINQ_EMCON_MANIFEST_INVALID;
    for (size_t j = 0; j < i; j++)
      if (manifest->streams[j].alias == stream->alias)
        return QLINQ_EMCON_MANIFEST_INVALID;
  }
  if (now_ms != 0 && now_ms < manifest->valid_from_ms)
    return QLINQ_EMCON_MANIFEST_NOT_YET_VALID;
  if (now_ms != 0 && now_ms >= manifest->expires_at_ms)
    return QLINQ_EMCON_MANIFEST_EXPIRED;
  return QLINQ_EMCON_MANIFEST_OK;
}

int qlinq_emcon_manifest_encode(const qlinq_emcon_manifest_t *manifest,
                                uint8_t *output, size_t capacity,
                                size_t *output_size) {
  int valid = qlinq_emcon_manifest_validate(manifest, 0);
  if (valid != QLINQ_EMCON_MANIFEST_OK || !output || !output_size)
    return valid == QLINQ_EMCON_MANIFEST_OK ? QLINQ_EMCON_MANIFEST_INVALID
                                            : valid;
  size_t required = QLINQ_EMCON_MANIFEST_HEADER_SIZE +
                    manifest->stream_count * QLINQ_EMCON_MANIFEST_STREAM_SIZE;
  if (capacity < required)
    return QLINQ_EMCON_MANIFEST_BUFFER_TOO_SMALL;
  memset(output, 0, required);
  output[0] = MANIFEST_MAGIC_0;
  output[1] = MANIFEST_MAGIC_1;
  output[2] = MANIFEST_MAGIC_2;
  output[3] = MANIFEST_MAGIC_3;
  write_u16(output + 4, QLINQ_EMCON_MANIFEST_VERSION);
  write_u16(output + 6, QLINQ_EMCON_MANIFEST_HEADER_SIZE);
  write_u32(output + 8, (uint32_t)required);
  memcpy(output + 16, manifest->session_id, sizeof(manifest->session_id));
  memcpy(output + 32, manifest->sender_id, sizeof(manifest->sender_id));
  memcpy(output + 48, manifest->traffic_key_id,
         sizeof(manifest->traffic_key_id));
  write_u64(output + 80, manifest->flow_id);
  write_u32(output + 88, manifest->key_epoch);
  write_u16(output + 92, manifest->cipher_suite);
  write_u16(output + 94, manifest->stream_count);
  write_u64(output + 96, manifest->initial_packet_number);
  write_u64(output + 104, manifest->valid_from_ms);
  write_u64(output + 112, manifest->expires_at_ms);
  output[120] = manifest->source.family;
  write_u16(output + 122, manifest->source.port);
  memcpy(output + 124, manifest->source.address,
         sizeof(manifest->source.address));
  output[140] = manifest->destination.family;
  write_u16(output + 142, manifest->destination.port);
  memcpy(output + 144, manifest->destination.address,
         sizeof(manifest->destination.address));
  write_u32(output + 160, manifest->interface_index);
  write_u32(output + 164, manifest->replay_window_packets);
  write_u64(output + 168, manifest->rate_bytes_per_second);
  write_u32(output + 176, manifest->burst_bytes);
  write_u32(output + 180, manifest->metadata_repeat_interval_ms);
  write_u16(output + 184, manifest->terminal_repeat_count);
  write_u16(output + 186, manifest->symbol_size);
  write_u16(output + 188, manifest->repair_symbols);
  for (size_t i = 0; i < manifest->stream_count; i++) {
    const qlinq_emcon_manifest_stream_t *stream = &manifest->streams[i];
    uint8_t *encoded = output + QLINQ_EMCON_MANIFEST_HEADER_SIZE +
                       i * QLINQ_EMCON_MANIFEST_STREAM_SIZE;
    encoded[0] = stream->alias;
    encoded[1] = stream->delivery;
    encoded[2] = stream->content_type;
    write_u32(encoded + 4, stream->maximum_record_size);
    size_t name_size = strnlen(stream->name, sizeof(stream->name));
    memcpy(encoded + 8, stream->name, name_size);
  }
  *output_size = required;
  return QLINQ_EMCON_MANIFEST_OK;
}

int qlinq_emcon_manifest_decode(qlinq_emcon_manifest_t *manifest,
                                const uint8_t *input, size_t input_size,
                                uint64_t now_ms) {
  if (!manifest || !input || input_size < QLINQ_EMCON_MANIFEST_HEADER_SIZE)
    return QLINQ_EMCON_MANIFEST_INVALID;
  if (input[0] != MANIFEST_MAGIC_0 || input[1] != MANIFEST_MAGIC_1 ||
      input[2] != MANIFEST_MAGIC_2 || input[3] != MANIFEST_MAGIC_3)
    return QLINQ_EMCON_MANIFEST_INVALID;
  if (read_u16(input + 4) != QLINQ_EMCON_MANIFEST_VERSION)
    return QLINQ_EMCON_MANIFEST_UNSUPPORTED;
  uint16_t header_size = read_u16(input + 6);
  uint32_t total_size = read_u32(input + 8);
  uint16_t stream_count = read_u16(input + 94);
  if (header_size != QLINQ_EMCON_MANIFEST_HEADER_SIZE || stream_count == 0 ||
      stream_count > QLINQ_EMCON_MANIFEST_MAX_STREAMS ||
      total_size != input_size ||
      total_size != QLINQ_EMCON_MANIFEST_HEADER_SIZE +
                        stream_count * QLINQ_EMCON_MANIFEST_STREAM_SIZE)
    return QLINQ_EMCON_MANIFEST_INVALID;
  for (size_t i = 12; i < 16; i++)
    if (input[i] != 0)
      return QLINQ_EMCON_MANIFEST_INVALID;
  if (input[121] != 0 || input[141] != 0)
    return QLINQ_EMCON_MANIFEST_INVALID;
  for (size_t i = 190; i < QLINQ_EMCON_MANIFEST_HEADER_SIZE; i++)
    if (input[i] != 0)
      return QLINQ_EMCON_MANIFEST_INVALID;

  memset(manifest, 0, sizeof(*manifest));
  memcpy(manifest->session_id, input + 16, sizeof(manifest->session_id));
  memcpy(manifest->sender_id, input + 32, sizeof(manifest->sender_id));
  memcpy(manifest->traffic_key_id, input + 48,
         sizeof(manifest->traffic_key_id));
  manifest->flow_id = read_u64(input + 80);
  manifest->key_epoch = read_u32(input + 88);
  manifest->cipher_suite = read_u16(input + 92);
  manifest->stream_count = stream_count;
  manifest->initial_packet_number = read_u64(input + 96);
  manifest->valid_from_ms = read_u64(input + 104);
  manifest->expires_at_ms = read_u64(input + 112);
  manifest->source.family = input[120];
  manifest->source.port = read_u16(input + 122);
  memcpy(manifest->source.address, input + 124,
         sizeof(manifest->source.address));
  manifest->destination.family = input[140];
  manifest->destination.port = read_u16(input + 142);
  memcpy(manifest->destination.address, input + 144,
         sizeof(manifest->destination.address));
  if ((manifest->source.family == 4 &&
       nonzero(manifest->source.address + 4, 12)) ||
      (manifest->destination.family == 4 &&
       nonzero(manifest->destination.address + 4, 12)))
    return QLINQ_EMCON_MANIFEST_INVALID;
  manifest->interface_index = read_u32(input + 160);
  manifest->replay_window_packets = read_u32(input + 164);
  manifest->rate_bytes_per_second = read_u64(input + 168);
  manifest->burst_bytes = read_u32(input + 176);
  manifest->metadata_repeat_interval_ms = read_u32(input + 180);
  manifest->terminal_repeat_count = read_u16(input + 184);
  manifest->symbol_size = read_u16(input + 186);
  manifest->repair_symbols = read_u16(input + 188);
  for (size_t i = 0; i < stream_count; i++) {
    const uint8_t *encoded = input + QLINQ_EMCON_MANIFEST_HEADER_SIZE +
                             i * QLINQ_EMCON_MANIFEST_STREAM_SIZE;
    const uint8_t *name_end = memchr(encoded + 8, '\0', 64);
    if (encoded[3] != 0 || !name_end ||
        nonzero(name_end + 1,
                (size_t)(encoded + QLINQ_EMCON_MANIFEST_STREAM_SIZE -
                         (name_end + 1))))
      return QLINQ_EMCON_MANIFEST_INVALID;
    manifest->streams[i].alias = encoded[0];
    manifest->streams[i].delivery = encoded[1];
    manifest->streams[i].content_type = encoded[2];
    manifest->streams[i].maximum_record_size = read_u32(encoded + 4);
    memcpy(manifest->streams[i].name, encoded + 8,
           sizeof(manifest->streams[i].name));
  }
  return qlinq_emcon_manifest_validate(manifest, now_ms);
}

int qlinq_emcon_manifest_digest(const qlinq_emcon_manifest_t *manifest,
                                uint8_t digest[32]) {
  uint8_t encoded[QLINQ_EMCON_MANIFEST_MAX_SIZE];
  size_t encoded_size;
  if (!digest ||
      qlinq_emcon_manifest_encode(manifest, encoded, sizeof(encoded),
                                  &encoded_size) != QLINQ_EMCON_MANIFEST_OK)
    return QLINQ_EMCON_MANIFEST_INVALID;
  return SHA256(encoded, encoded_size, digest) ? QLINQ_EMCON_MANIFEST_OK
                                               : QLINQ_EMCON_MANIFEST_INVALID;
}

static int manifest_signature(const qlinq_emcon_manifest_t *manifest,
                              EVP_PKEY *key, uint8_t *signature, bool verify) {
  uint8_t encoded[QLINQ_EMCON_MANIFEST_MAX_SIZE];
  size_t encoded_size, signature_size = QLINQ_EMCON_MANIFEST_SIGNATURE_SIZE;
  if (!key || !signature || EVP_PKEY_get_id(key) != EVP_PKEY_ED25519 ||
      qlinq_emcon_manifest_encode(manifest, encoded, sizeof(encoded),
                                  &encoded_size) != QLINQ_EMCON_MANIFEST_OK)
    return QLINQ_EMCON_MANIFEST_INVALID;
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  if (!context)
    return QLINQ_EMCON_MANIFEST_SIGNATURE;
  int ok;
  if (verify) {
    ok = EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) == 1 &&
         EVP_DigestVerify(context, signature,
                          QLINQ_EMCON_MANIFEST_SIGNATURE_SIZE, encoded,
                          encoded_size) == 1;
  } else {
    ok = EVP_DigestSignInit(context, NULL, NULL, NULL, key) == 1 &&
         EVP_DigestSign(context, signature, &signature_size, encoded,
                        encoded_size) == 1 &&
         signature_size == QLINQ_EMCON_MANIFEST_SIGNATURE_SIZE;
  }
  EVP_MD_CTX_free(context);
  return ok ? QLINQ_EMCON_MANIFEST_OK : QLINQ_EMCON_MANIFEST_SIGNATURE;
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
  int extra = fgetc(file);
  int error = ferror(file);
  if (error || extra != EOF) {
    memset(buffer, 0, capacity);
    return QLINQ_EMCON_MANIFEST_IO;
  }
  *size = got;
  return QLINQ_EMCON_MANIFEST_OK;
}

static int read_exact_file(const char *path, uint8_t *buffer, size_t capacity,
                           size_t *size) {
  FILE *file = path ? fopen(path, "rb") : NULL;
  if (!file)
    return QLINQ_EMCON_MANIFEST_IO;
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
  size_t encoded_size = 0, signature_size = 0;
  int ret =
      read_exact_file(manifest_file, encoded, sizeof(encoded), &encoded_size);
  if (ret == QLINQ_EMCON_MANIFEST_OK)
    ret = read_exact_file(signature_file, signature, sizeof(signature),
                          &signature_size);
  if (ret != QLINQ_EMCON_MANIFEST_OK ||
      signature_size != QLINQ_EMCON_MANIFEST_SIGNATURE_SIZE)
    return ret == QLINQ_EMCON_MANIFEST_OK ? QLINQ_EMCON_MANIFEST_SIGNATURE
                                          : ret;
  qlinq_emcon_manifest_t decoded;
  if ((ret = qlinq_emcon_manifest_decode(&decoded, encoded, encoded_size,
                                         now_ms)) != QLINQ_EMCON_MANIFEST_OK)
    return ret;
  FILE *key_file = public_key_file ? fopen(public_key_file, "r") : NULL;
  if (!key_file)
    return QLINQ_EMCON_MANIFEST_IO;
  EVP_PKEY *public_key = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
  fclose(key_file);
  if (!public_key)
    return QLINQ_EMCON_MANIFEST_SIGNATURE;
  ret = qlinq_emcon_manifest_verify(&decoded, public_key, signature);
  EVP_PKEY_free(public_key);
  if (ret == QLINQ_EMCON_MANIFEST_OK)
    *manifest = decoded;
  return ret;
}

int qlinq_emcon_traffic_key_id(
    const uint8_t *secret, size_t secret_size,
    uint8_t key_id[QLINQ_EMCON_MANIFEST_KEY_ID_SIZE]) {
  if (!secret || secret_size == 0 || !key_id)
    return QLINQ_EMCON_MANIFEST_INVALID;
  return SHA256(secret, secret_size, key_id) ? QLINQ_EMCON_MANIFEST_OK
                                             : QLINQ_EMCON_MANIFEST_INVALID;
}

int qlinq_emcon_traffic_key_load(const char *key_file, uint8_t *secret,
                                 size_t capacity, size_t *secret_size) {
  if (secret_size)
    *secret_size = 0;
  if (!key_file || !secret || capacity == 0 || !secret_size)
    return QLINQ_EMCON_MANIFEST_IO;
  int fd = open(key_file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  struct stat info;
  if (fd < 0 || fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
      (info.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    if (fd >= 0)
      close(fd);
    return QLINQ_EMCON_MANIFEST_IO;
  }
  FILE *file = fdopen(fd, "rb");
  if (!file) {
    close(fd);
    return QLINQ_EMCON_MANIFEST_IO;
  }
  size_t loaded = 0;
  int ret = read_exact_stream(file, secret, capacity, &loaded);
  fclose(file);
  if (ret != QLINQ_EMCON_MANIFEST_OK || loaded == 0) {
    OPENSSL_cleanse(secret, capacity);
    return ret == QLINQ_EMCON_MANIFEST_OK ? QLINQ_EMCON_MANIFEST_IO : ret;
  }
  *secret_size = loaded;
  return QLINQ_EMCON_MANIFEST_OK;
}

int qlinq_emcon_manifest_check_traffic_key(
    const qlinq_emcon_manifest_t *manifest, const uint8_t *secret,
    size_t secret_size) {
  uint8_t key_id[QLINQ_EMCON_MANIFEST_KEY_ID_SIZE];
  if (!manifest || qlinq_emcon_traffic_key_id(secret, secret_size, key_id) !=
                       QLINQ_EMCON_MANIFEST_OK)
    return QLINQ_EMCON_MANIFEST_INVALID;
  int ret = CRYPTO_memcmp(manifest->traffic_key_id, key_id, sizeof(key_id)) == 0
                ? QLINQ_EMCON_MANIFEST_OK
                : QLINQ_EMCON_MANIFEST_KEY_MISMATCH;
  OPENSSL_cleanse(key_id, sizeof(key_id));
  return ret;
}
