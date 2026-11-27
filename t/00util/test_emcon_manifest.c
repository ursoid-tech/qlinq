#include "../../src/emcon/emcon_manifest.h"

#include <arpa/inet.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "EMCON manifest test failed: %s\n", message);            \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static qlinq_emcon_manifest_t fixture(const uint8_t *secret) {
  qlinq_emcon_manifest_t manifest = {
      .flow_id = 500,
      .key_epoch = 7,
      .valid_from_ms = 1000,
      .expires_at_ms = 5000,
      .source = {.family = 4, .port = 12070},
      .destination = {.family = 4, .port = 12071},
      .rate_bytes_per_second = 1000000,
      .burst_bytes = 2048,
      .terminal_repeat_count = 3,
      .symbol_size = 256,
      .repair_symbols = 8,
      .stream_count = 6,
  };
  inet_pton(AF_INET, "10.2.0.1", manifest.source.address);
  inet_pton(AF_INET, "10.2.0.2", manifest.destination.address);
  qlinq_emcon_traffic_key_id(secret, 32, manifest.traffic_key_id);
  for (size_t i = 0; i < manifest.stream_count; i++) {
    manifest.streams[i].alias = (uint8_t)(10 + i);
    manifest.streams[i].content_type = 0;
    manifest.streams[i].maximum_record_size = 4096;
    snprintf(manifest.streams[i].name, sizeof(manifest.streams[i].name),
             "camera-%zu", i + 1);
  }
  return manifest;
}

int main(void) {
  uint8_t secret[32], other_secret[32];
  memset(secret, 0x31, sizeof(secret));
  memset(other_secret, 0x52, sizeof(other_secret));
  qlinq_emcon_manifest_t manifest = fixture(secret), decoded;
  CHECK(qlinq_emcon_manifest_validate(&manifest, 2000) == QLINQ_EMCON_OK,
        "valid rateless manifest");
  CHECK(qlinq_emcon_manifest_validate(&manifest, 999) ==
            QLINQ_EMCON_ERR_NOT_YET_VALID,
        "not-yet-valid rejection");
  CHECK(qlinq_emcon_manifest_validate(&manifest, 5000) ==
                QLINQ_EMCON_ERR_EXPIRED &&
            strcmp(qlinq_emcon_strerror(QLINQ_EMCON_ERR_EXPIRED),
                   "manifest validity window expired") == 0,
        "expiry rejection");
  CHECK(qlinq_emcon_manifest_check_traffic_key(
            &manifest, secret, sizeof(secret)) == QLINQ_EMCON_OK,
        "traffic key reference");
  CHECK(qlinq_emcon_manifest_check_traffic_key(&manifest, other_secret,
                                               sizeof(other_secret)) ==
            QLINQ_EMCON_ERR_KEY_MISMATCH,
        "wrong traffic key rejected");

  qlinq_emcon_manifest_t invalid = manifest;
  strcpy(invalid.streams[0].name, "bad,name");
  CHECK(qlinq_emcon_manifest_validate(&invalid, 2000) ==
            QLINQ_EMCON_ERR_INVALID,
        "reject comma in stream name");

  uint8_t encoded[QLINQ_EMCON_MANIFEST_MAX_SIZE], reencoded[sizeof(encoded)];
  size_t encoded_size, reencoded_size;
  CHECK(qlinq_emcon_manifest_encode(&manifest, encoded, sizeof(encoded),
                                    &encoded_size) == QLINQ_EMCON_OK &&
            qlinq_emcon_manifest_decode(&decoded, encoded, encoded_size,
                                        2000) == QLINQ_EMCON_OK &&
            qlinq_emcon_manifest_encode(&decoded, reencoded, sizeof(reencoded),
                                        &reencoded_size) == QLINQ_EMCON_OK &&
            encoded_size == reencoded_size &&
            memcmp(encoded, reencoded, encoded_size) == 0,
        "canonical text roundtrip");

  /* non-canonical trailing newline or modified formatting must fail decode */
  encoded[encoded_size] = '\n';
  CHECK(qlinq_emcon_manifest_decode(&decoded, encoded, encoded_size + 1,
                                    2000) == QLINQ_EMCON_ERR_INVALID,
        "non-canonical trailing newline rejected");

  EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
  EVP_PKEY *wrong_key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
  uint8_t signature[QLINQ_EMCON_MANIFEST_SIGNATURE_SIZE];
  CHECK(key && qlinq_emcon_manifest_sign(&invalid, key, signature) ==
                   QLINQ_EMCON_ERR_INVALID,
        "refuse to sign invalid manifest");
  CHECK(key && wrong_key &&
            qlinq_emcon_manifest_sign(&manifest, key, signature) ==
                QLINQ_EMCON_OK &&
            qlinq_emcon_manifest_verify(&manifest, key, signature) ==
                QLINQ_EMCON_OK &&
            qlinq_emcon_manifest_verify(&manifest, wrong_key, signature) ==
                QLINQ_EMCON_ERR_SIGNATURE,
        "Ed25519 sign and verify");
  manifest.streams[0].maximum_record_size++;
  CHECK(qlinq_emcon_manifest_verify(&manifest, key, signature) ==
            QLINQ_EMCON_ERR_SIGNATURE,
        "signed field tamper rejected");
  manifest.streams[0].maximum_record_size--;

  char manifest_path[128], signature_path[128], public_path[128];
  snprintf(manifest_path, sizeof(manifest_path),
           "/tmp/qlinq-emcon-manifest-%ld.txt", (long)getpid());
  snprintf(signature_path, sizeof(signature_path),
           "/tmp/qlinq-emcon-manifest-%ld.sig", (long)getpid());
  snprintf(public_path, sizeof(public_path),
           "/tmp/qlinq-emcon-manifest-%ld.pub", (long)getpid());
  FILE *manifest_file = fopen(manifest_path, "wb");
  FILE *signature_file = fopen(signature_path, "wb");
  FILE *public_file = fopen(public_path, "w");
  CHECK(manifest_file && signature_file && public_file, "manifest test files");
  CHECK(fwrite(encoded, 1, encoded_size, manifest_file) == encoded_size &&
            fwrite(signature, 1, sizeof(signature), signature_file) ==
                sizeof(signature) &&
            PEM_write_PUBKEY(public_file, key) == 1,
        "write signed manifest files");
  fclose(manifest_file);
  fclose(signature_file);
  fclose(public_file);
  CHECK(qlinq_emcon_manifest_load_signed(&decoded, manifest_path,
                                         signature_path, public_path,
                                         2000) == QLINQ_EMCON_OK,
        "load signed manifest");

  char traffic_key_path[128], traffic_key_link[128];
  snprintf(traffic_key_path, sizeof(traffic_key_path),
           "/tmp/qlinq-emcon-traffic-%ld.key", (long)getpid());
  snprintf(traffic_key_link, sizeof(traffic_key_link),
           "/tmp/qlinq-emcon-traffic-%ld.link", (long)getpid());
  FILE *traffic_key_file = fopen(traffic_key_path, "wb");
  CHECK(traffic_key_file &&
            fwrite(secret, 1, sizeof(secret), traffic_key_file) ==
                sizeof(secret) &&
            fclose(traffic_key_file) == 0 && chmod(traffic_key_path, 0600) == 0,
        "write protected traffic key");
  uint8_t loaded_secret[64];
  size_t loaded_secret_size = 0;
  CHECK(qlinq_emcon_traffic_key_load(traffic_key_path, loaded_secret,
                                     sizeof(loaded_secret),
                                     &loaded_secret_size) == QLINQ_EMCON_OK &&
            loaded_secret_size == sizeof(secret) &&
            memcmp(loaded_secret, secret, sizeof(secret)) == 0,
        "load protected traffic key");
  CHECK(symlink(traffic_key_path, traffic_key_link) == 0 &&
            qlinq_emcon_traffic_key_load(
                traffic_key_link, loaded_secret, sizeof(loaded_secret),
                &loaded_secret_size) == QLINQ_EMCON_ERR_IO,
        "reject traffic key symlink");
  CHECK(chmod(traffic_key_path, 0644) == 0 &&
            qlinq_emcon_traffic_key_load(
                traffic_key_path, loaded_secret, sizeof(loaded_secret),
                &loaded_secret_size) == QLINQ_EMCON_ERR_IO,
        "reject exposed traffic key");
  unlink(manifest_path);
  unlink(signature_path);
  unlink(public_path);
  unlink(traffic_key_link);
  unlink(traffic_key_path);
  EVP_PKEY_free(wrong_key);
  EVP_PKEY_free(key);
  puts("===EMCON MANIFEST OK===");
  return 0;
}
