/* backend selection and QUIC packet-protection interoperability */
#include "transport_internal.h"
#include "transport_tls.h"
#include "picotls/openssl.h"
#include "quicly/defaults.h"
#if QLINQ_WITH_FUSION
#include "picotls/fusion.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "crypto backend test failed at line %d: %s\n", __LINE__, \
              #condition);                                                     \
      return 1;                                                                \
    }                                                                          \
  } while (0)

/* Compile the real TLS helpers under private names for allocation-failure and
 * cache-hit observation. No production runtime controls are introduced. */
static bool fail_cache_allocation, fail_native_constructor;

static void *test_tls_malloc(size_t size) {
  return fail_cache_allocation ? NULL : malloc(size);
}

static quicly_cid_encryptor_t *
test_default_cid_constructor(ptls_cipher_algorithm_t *cid_cipher,
                             ptls_cipher_algorithm_t *reset_cipher,
                             ptls_hash_algorithm_t *hash, ptls_iovec_t key) {
  return fail_native_constructor ? NULL
                                 : quicly_new_default_cid_encryptor(
                                       cid_cipher, reset_cipher, hash, key);
}

/* Force an unsupported CPU through the real TLS policy. */
#if QLINQ_WITH_FUSION
#define __builtin_cpu_supports(feature) 0
#endif
#define malloc test_tls_malloc
#define quicly_new_default_cid_encryptor test_default_cid_constructor
#define transport_tls_configure_crypto_backend configure_unsupported_cpu
#define transport_tls_cid_cipher unsupported_cpu_cid_cipher
#define transport_tls_new_cid_encryptor test_new_cid_encryptor
#define transport_tls_free_cid_encryptor test_free_cid_encryptor
#define transport_tls_load_certificate_and_key unused_load_certificate
#define transport_tls_init_insecure_verifier unused_init_verifier
#include "../../src/common/transport_tls.c"
#undef transport_tls_init_insecure_verifier
#undef transport_tls_load_certificate_and_key
#undef transport_tls_configure_crypto_backend
#undef transport_tls_cid_cipher
#undef transport_tls_new_cid_encryptor
#undef transport_tls_free_cid_encryptor
#undef quicly_new_default_cid_encryptor
#undef malloc
#if QLINQ_WITH_FUSION
#undef __builtin_cpu_supports
#endif

static char crypto_log[512];

static void ignore_event(void *data, const transport_event_t *event) {
  (void)data;
  (void)event;
}

static void capture_log(void *data, const transport_log_event_t *event) {
  (void)data;
  if (strcmp(event->component, "crypto") == 0)
    snprintf(crypto_log, sizeof(crypto_log), "%s", event->message);
}

static transport_t *create_endpoint(void) {
  transport_config_t config = {.bind_hosts = {"127.0.0.1"},
                               .num_bind_hosts = 1,
                               .port = 19868,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .allow_insecure_peer = true,
                               .callback = ignore_event,
                               .log_callback = capture_log};
  crypto_log[0] = '\0';
  return transport_create(&config);
}

static int check_cid_protection(transport_t *transport) {
  ptls_cipher_algorithm_t *candidate = transport_tls_cid_cipher(transport);
  ptls_cipher_algorithm_t *reference = &ptls_openssl_quiclb;
  CHECK(candidate->key_size == reference->key_size &&
        candidate->block_size == reference->block_size &&
        candidate->iv_size == reference->iv_size);
  uint8_t key[PTLS_QUICLB_KEY_SIZE], plain[PTLS_QUICLB_MAX_BLOCK_SIZE],
      encrypted[2][PTLS_QUICLB_MAX_BLOCK_SIZE],
      recovered[PTLS_QUICLB_MAX_BLOCK_SIZE];
  for (size_t seed = 0; seed < 3; seed++) {
    for (size_t i = 0; i < sizeof(key); i++)
      key[i] = (uint8_t)(i * 17 + seed * 83);
    for (size_t i = 0; i < sizeof(plain); i++)
      plain[i] = (uint8_t)(i * 29 + seed * 71);
    ptls_cipher_context_t *enc[2] = {ptls_cipher_new(candidate, 1, key),
                                     ptls_cipher_new(reference, 1, key)};
    ptls_cipher_context_t *dec[2] = {ptls_cipher_new(candidate, 0, key),
                                     ptls_cipher_new(reference, 0, key)};
    CHECK(enc[0] && enc[1] && dec[0] && dec[1]);
    for (size_t length = PTLS_QUICLB_MIN_BLOCK_SIZE;
         length <= PTLS_QUICLB_MAX_BLOCK_SIZE; length++) {
      for (size_t i = 0; i < 2; i++)
        ptls_cipher_encrypt(enc[i], encrypted[i], plain, length);
      CHECK(memcmp(encrypted[0], encrypted[1], length) == 0);
      for (size_t i = 0; i < 2; i++) {
        /* Cross-backend decode, including the in-place operation. */
        memcpy(recovered, encrypted[1 - i], length);
        ptls_cipher_encrypt(dec[i], recovered, recovered, length);
        CHECK(memcmp(recovered, plain, length) == 0);
      }
    }
    for (size_t i = 0; i < 2; i++) {
      ptls_cipher_free(enc[i]);
      ptls_cipher_free(dec[i]);
    }

    quicly_cid_encryptor_t *cid[2] = {
        transport_tls_new_cid_encryptor(transport,
                                        ptls_iovec_init(key, sizeof(key))),
        quicly_new_default_cid_encryptor(reference, &ptls_openssl_aes128ecb,
                                         &ptls_openssl_sha256,
                                         ptls_iovec_init(key, sizeof(key)))};
    CHECK(cid[0] && cid[1]);
    for (size_t path = 0; path <= 255; path += 17) {
      quicly_cid_plaintext_t original = {.master_id = 0x12340000u + path,
                                         .path_id = path,
                                         .sequence = 255 - path,
                                         .thread_id = 0xa531,
                                         .node_id = 0};
      quicly_cid_t encoded[2];
      uint8_t tokens[2][QUICLY_STATELESS_RESET_TOKEN_LEN],
          token[QUICLY_STATELESS_RESET_TOKEN_LEN];
      for (size_t i = 0; i < 2; i++)
        cid[i]->encrypt_cid(cid[i], &encoded[i], tokens[i], &original);
      CHECK(encoded[0].len == 8 && encoded[1].len == 8);
      CHECK(memcmp(encoded[0].cid, encoded[1].cid, 8) == 0);
      CHECK(memcmp(tokens[0], tokens[1], sizeof(token)) == 0);
      for (size_t i = 0; i < 2; i++) {
        for (size_t length = 0; length <= 8; length += 8) {
          quicly_cid_plaintext_t decoded;
          CHECK(cid[i]->decrypt_cid(cid[i], &decoded, encoded[1 - i].cid,
                                    length) == 8);
          CHECK(decoded.master_id == original.master_id &&
                decoded.path_id == original.path_id &&
                decoded.sequence == original.sequence &&
                decoded.thread_id == original.thread_id &&
                decoded.node_id == original.node_id);
        }
        CHECK(cid[i]->generate_stateless_reset_token(cid[i], token,
                                                     encoded[1 - i].cid));
        CHECK(memcmp(token, tokens[1 - i], sizeof(token)) == 0);
        quicly_cid_plaintext_t ignored;
        CHECK(cid[i]->decrypt_cid(cid[i], &ignored, encoded[1 - i].cid, 7) ==
              SIZE_MAX);
      }
    }
    transport_tls_free_cid_encryptor(cid[0]);
    quicly_free_default_cid_encryptor(cid[1]);
  }
  return 0;
}

static bool same_cid_plaintext(const quicly_cid_plaintext_t *a,
                               const quicly_cid_plaintext_t *b) {
  return a->master_id == b->master_id && a->path_id == b->path_id &&
         a->sequence == b->sequence && a->thread_id == b->thread_id &&
         a->node_id == b->node_id;
}

static quicly_cid_encryptor_t *counted_cid_delegate;
static size_t (*original_cid_decrypt)(quicly_cid_encryptor_t *,
                                      quicly_cid_plaintext_t *, const void *,
                                      size_t);
static size_t cid_decrypt_calls;
static bool cid_delegate_failed, cid_delegate_wrong_self;

static size_t count_cid_decrypt(quicly_cid_encryptor_t *self,
                                quicly_cid_plaintext_t *plaintext,
                                const void *encrypted, size_t len) {
  cid_decrypt_calls++;
  if (self != counted_cid_delegate) {
    cid_delegate_wrong_self = true;
    return SIZE_MAX;
  }
  if (cid_delegate_failed)
    return SIZE_MAX;
  return original_cid_decrypt(self, plaintext, encrypted, len);
}

static int check_cid_cache(void) {
  transport_t policy = {0}; /* OpenSSL policy, independent of environment. */
  uint8_t key[16] = {0}, other_key[16] = {1};
  quicly_cid_encryptor_t *cid =
      test_new_cid_encryptor(&policy, ptls_iovec_init(key, sizeof(key)));
  quicly_cid_encryptor_t *reference = quicly_new_default_cid_encryptor(
      &ptls_openssl_quiclb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256,
      ptls_iovec_init(key, sizeof(key)));
  CHECK(cid && reference && cid->decrypt_cid == cached_decrypt_cid);
  cached_cid_encryptor_t *cache = (cached_cid_encryptor_t *)cid;
  counted_cid_delegate = cache->delegate;
  original_cid_decrypt = counted_cid_delegate->decrypt_cid;
  counted_cid_delegate->decrypt_cid = count_cid_decrypt;
  cid_decrypt_calls = 0;
  cid_delegate_failed = cid_delegate_wrong_self = false;
  quicly_cid_plaintext_t original[10];
  quicly_cid_t encoded[10];
  uint8_t tokens[10][QUICLY_STATELESS_RESET_TOKEN_LEN];
  for (size_t i = 0; i < 10; i++) {
    original[i] = (quicly_cid_plaintext_t){.master_id = 0x739a0000u + i,
                                           .path_id = i,
                                           .sequence = 255 - i,
                                           .thread_id = 0xa531};
    quicly_cid_t expected;
    uint8_t token[QUICLY_STATELESS_RESET_TOKEN_LEN];
    cid->encrypt_cid(cid, &encoded[i], tokens[i], &original[i]);
    reference->encrypt_cid(reference, &expected, token, &original[i]);
    CHECK(encoded[i].len == 8 && expected.len == 8);
    CHECK(memcmp(encoded[i].cid, expected.cid, 8) == 0);
    CHECK(memcmp(tokens[i], token, sizeof(token)) == 0);
  }
  CHECK(cid_decrypt_calls == 0); /* Encryption does not populate the cache. */
  quicly_cid_plaintext_t cold_rejected = original[9];
  CHECK(cid->decrypt_cid(cid, &cold_rejected, NULL, 7) == SIZE_MAX);
  CHECK(same_cid_plaintext(&cold_rejected, &original[9]) &&
        cid_decrypt_calls == 0);
  for (size_t i = 0; i < 8; i++) {
    quicly_cid_plaintext_t decoded;
    CHECK(cid->decrypt_cid(cid, &decoded, encoded[i].cid, i % 2 ? 8 : 0) == 8);
    CHECK(same_cid_plaintext(&decoded, &original[i]));
    CHECK(cid_decrypt_calls == i + 1);
  }
  for (size_t i = 0; i < 8; i++) {
    quicly_cid_plaintext_t decoded;
    CHECK(cid->decrypt_cid(cid, &decoded, encoded[i].cid, i % 2 ? 0 : 8) == 8);
    CHECK(same_cid_plaintext(&decoded, &original[i]));
  }
  CHECK(cid_decrypt_calls == 8 && cache->count == 8);
  quicly_cid_plaintext_t decoded = original[9];
  const size_t invalid_lengths[] = {1, 7, 9, 16, SIZE_MAX};
  for (size_t i = 0; i < sizeof(invalid_lengths) / sizeof(invalid_lengths[0]);
       i++) {
    CHECK(cid->decrypt_cid(cid, &decoded, encoded[0].cid, invalid_lengths[i]) ==
          SIZE_MAX);
    CHECK(same_cid_plaintext(&decoded, &original[9]));
    /* Invalid lengths must be rejected before even reading the input. */
    CHECK(cid->decrypt_cid(cid, &decoded, NULL, invalid_lengths[i]) ==
          SIZE_MAX);
  }
  CHECK(cid_decrypt_calls == 8);
  CHECK(cid->decrypt_cid(cid, &decoded, encoded[8].cid, 0) == 8);
  CHECK(same_cid_plaintext(&decoded, &original[8]) && cid_decrypt_calls == 9);
  CHECK(cid->decrypt_cid(cid, &decoded, encoded[1].cid, 8) == 8);
  CHECK(same_cid_plaintext(&decoded, &original[1]) && cid_decrypt_calls == 9);
  CHECK(cid->decrypt_cid(cid, &decoded, encoded[0].cid, 8) == 8);
  CHECK(same_cid_plaintext(&decoded, &original[0]) && cid_decrypt_calls == 10);
  CHECK(cache->count == 8); /* Nine distinct CIDs evict, never grow storage. */

  uint8_t changed[8];
  memcpy(changed, encoded[0].cid, sizeof(changed));
  changed[7] ^= 1; /* A common seven-byte prefix is not a cache match. */
  quicly_cid_plaintext_t expected;
  CHECK(reference->decrypt_cid(reference, &expected, changed, 8) == 8);
  CHECK(cid->decrypt_cid(cid, &decoded, changed, 8) == 8);
  CHECK(same_cid_plaintext(&decoded, &expected) && cid_decrypt_calls == 11);
  decoded = original[0]; /* Modifying the output cannot mutate the cache. */
  CHECK(cid->decrypt_cid(cid, &decoded, changed, 0) == 8);
  CHECK(same_cid_plaintext(&decoded, &expected) && cid_decrypt_calls == 11);

  cid_delegate_failed = true;
  decoded = original[0];
  for (size_t i = 0; i < 2; i++) {
    CHECK(cid->decrypt_cid(cid, &decoded, encoded[9].cid, 8) == SIZE_MAX);
    CHECK(same_cid_plaintext(&decoded, &original[0]));
  }
  CHECK(cid_decrypt_calls == 13); /* Failed decryptions are never cached. */
  cid_delegate_failed = false;
  CHECK(cid->decrypt_cid(cid, &decoded, encoded[9].cid, 0) == 8);
  CHECK(same_cid_plaintext(&decoded, &original[9]) && cid_decrypt_calls == 14);
  CHECK(!cid_delegate_wrong_self);
  for (size_t i = 0; i < 10; i++) {
    uint8_t token[QUICLY_STATELESS_RESET_TOKEN_LEN];
    CHECK(cid->generate_stateless_reset_token(cid, token, encoded[i].cid));
    CHECK(memcmp(token, tokens[i], sizeof(token)) == 0);
    quicly_cid_t without_token;
    cid->encrypt_cid(cid, &without_token, NULL, &original[i]);
    CHECK(without_token.len == 8 &&
          memcmp(without_token.cid, encoded[i].cid, 8) == 0);
  }

  /* Concurrent endpoints and a newly created lifetime cannot reuse plaintext
   * derived using another key, even for identical ciphertext. */
  for (size_t lifetime = 0; lifetime < 2; lifetime++) {
    quicly_cid_encryptor_t *other = test_new_cid_encryptor(
        &policy, ptls_iovec_init(other_key, sizeof(other_key)));
    quicly_cid_encryptor_t *other_reference = quicly_new_default_cid_encryptor(
        &ptls_openssl_quiclb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256,
        ptls_iovec_init(other_key, sizeof(other_key)));
    CHECK(other && other_reference);
    CHECK(other_reference->decrypt_cid(other_reference, &expected,
                                       encoded[9].cid, 8) == 8);
    CHECK(!same_cid_plaintext(&expected, &original[9]));
    CHECK(other->decrypt_cid(other, &decoded, encoded[9].cid, 0) == 8);
    CHECK(same_cid_plaintext(&decoded, &expected));
    CHECK(cid->decrypt_cid(cid, &decoded, encoded[9].cid, 8) == 8);
    CHECK(same_cid_plaintext(&decoded, &original[9]) &&
          cid_decrypt_calls == 14);
    test_free_cid_encryptor(other);
    quicly_free_default_cid_encryptor(other_reference);
    other_key[0]++;
  }
  union {
    quicly_cid_plaintext_t plaintext;
    uint8_t ciphertext[16];
  } overlapping;
  memcpy(overlapping.ciphertext, encoded[1].cid, 8);
  CHECK(cid->decrypt_cid(cid, &overlapping.plaintext, overlapping.ciphertext,
                         8) == 8);
  CHECK(same_cid_plaintext(&overlapping.plaintext, &original[1]));
  CHECK(cid_decrypt_calls == 15);
  CHECK(cid->decrypt_cid(cid, &decoded, encoded[1].cid, 0) == 8);
  CHECK(same_cid_plaintext(&decoded, &original[1]) && cid_decrypt_calls == 15);
  counted_cid_delegate->decrypt_cid = original_cid_decrypt;
  test_free_cid_encryptor(cid);
  quicly_free_default_cid_encryptor(reference);

  fail_cache_allocation = true;
  cid = test_new_cid_encryptor(&policy, ptls_iovec_init(key, sizeof(key)));
  fail_cache_allocation = false;
  CHECK(cid && cid->decrypt_cid != cached_decrypt_cid);
  CHECK(cid->decrypt_cid(cid, &decoded, encoded[9].cid, 0) == 8);
  CHECK(same_cid_plaintext(&decoded, &original[9]));
  test_free_cid_encryptor(cid); /* The paired destructor also owns fallback. */
  fail_native_constructor = true;
  CHECK(test_new_cid_encryptor(&policy, ptls_iovec_init(key, sizeof(key))) ==
        NULL);
  fail_native_constructor = false;
  test_free_cid_encryptor(NULL);
  return 0;
}

static int check_cid_credential_reload(transport_t *t) {
  quicly_cid_encryptor_t *cid = t->quic_ctx.cid_encryptor;
  quicly_cid_plaintext_t original = {.master_id = 0x983ba52c,
                                     .path_id = 3,
                                     .sequence = 27,
                                     .thread_id = 0xffff},
                         decoded;
  quicly_cid_t encoded;
  uint8_t token[QUICLY_STATELESS_RESET_TOKEN_LEN],
      after[QUICLY_STATELESS_RESET_TOKEN_LEN];
  cid->encrypt_cid(cid, &encoded, token, &original);
  CHECK(cid->decrypt_cid(cid, &decoded, encoded.cid, 0) == 8);
  CHECK(same_cid_plaintext(&decoded, &original));
  CHECK(transport_reload_credentials(t, "t/assets/server.crt",
                                     "t/assets/server.key"));
  CHECK(t->quic_ctx.cid_encryptor == cid);
  CHECK(cid->decrypt_cid(cid, &decoded, encoded.cid, 8) == 8);
  CHECK(same_cid_plaintext(&decoded, &original));
  CHECK(cid->generate_stateless_reset_token(cid, after, encoded.cid));
  CHECK(memcmp(token, after, sizeof(token)) == 0);
  return 0;
}

static int check_packet_protection(ptls_cipher_suite_t *candidate,
                                   ptls_cipher_suite_t *reference) {
  uint8_t key[32], iv[12], aad[21], plain[4096], encrypted[2][4112],
      recovered[4096];
  memset(key, 0x81, sizeof(key));
  memset(iv, 0x19, sizeof(iv));
  memset(aad, 0x5a, sizeof(aad));
  for (size_t i = 0; i < sizeof(plain); i++)
    plain[i] = (uint8_t)i;
  ptls_aead_context_t *enc[2] = {
      ptls_aead_new_direct(candidate->aead, 1, key, iv),
      ptls_aead_new_direct(reference->aead, 1, key, iv)};
  ptls_aead_context_t *dec[2] = {
      ptls_aead_new_direct(candidate->aead, 0, key, iv),
      ptls_aead_new_direct(reference->aead, 0, key, iv)};
  ptls_cipher_context_t *hp[2] = {
      ptls_cipher_new(candidate->aead->ctr_cipher, 1, key),
      ptls_cipher_new(reference->aead->ctr_cipher, 1, key)};
  CHECK(enc[0] && enc[1] && dec[0] && dec[1] && hp[0] && hp[1]);
  const size_t lengths[] = {0, 1, 16, 17, 1436, 4096};
  for (size_t n = 0; n < sizeof(lengths) / sizeof(lengths[0]); n++) {
    size_t length = lengths[n], ciphertext_length = length + 16;
    /* Multipath QUIC temporarily permutes the IV for each native path. */
    uint8_t packet_iv[sizeof(iv)], observed_iv[sizeof(iv)];
    memcpy(packet_iv, iv, sizeof(iv));
    packet_iv[0] ^= (uint8_t)n;
    for (size_t i = 0; i < 2; i++) {
      ptls_aead_set_iv(enc[i], packet_iv);
      ptls_aead_set_iv(dec[i], packet_iv);
      ptls_aead_get_iv(enc[i], observed_iv);
      CHECK(memcmp(observed_iv, packet_iv, sizeof(packet_iv)) == 0);
    }
    ptls_aead_supplementary_encryption_t supp[2] = {
        {.ctx = hp[0], .input = encrypted[0]},
        {.ctx = hp[1], .input = encrypted[1]}};
    for (size_t i = 0; i < 2; i++)
      ptls_aead_encrypt_s(enc[i], encrypted[i], plain, length, 0x1234 + n, aad,
                          sizeof(aad), &supp[i]);
    CHECK(memcmp(encrypted[0], encrypted[1], ciphertext_length) == 0);
    CHECK(memcmp(supp[0].output, supp[1].output, sizeof(supp[0].output)) == 0);
    for (size_t i = 0; i < 2; i++) {
      CHECK(ptls_aead_decrypt(dec[i], recovered, encrypted[1 - i],
                              ciphertext_length, 0x1234 + n, aad,
                              sizeof(aad)) == length);
      CHECK(memcmp(recovered, plain, length) == 0);
      encrypted[1 - i][ciphertext_length - 1] ^= 1;
      CHECK(ptls_aead_decrypt(dec[i], recovered, encrypted[1 - i],
                              ciphertext_length, 0x1234 + n, aad,
                              sizeof(aad)) == SIZE_MAX);
      encrypted[1 - i][ciphertext_length - 1] ^= 1;
      aad[0] ^= 1;
      CHECK(ptls_aead_decrypt(dec[i], recovered, encrypted[1 - i],
                              ciphertext_length, 0x1234 + n, aad,
                              sizeof(aad)) == SIZE_MAX);
      aad[0] ^= 1;
      CHECK(ptls_aead_decrypt(dec[i], recovered, encrypted[1 - i],
                              ciphertext_length - 1, 0x1234 + n, aad,
                              sizeof(aad)) == SIZE_MAX);
    }
  }
  for (size_t i = 0; i < 2; i++) {
    ptls_aead_free(enc[i]);
    ptls_aead_free(dec[i]);
    ptls_cipher_free(hp[i]);
  }
  return 0;
}

typedef struct {
  quicly_crypto_engine_t super;
  quicly_crypto_engine_t *delegate;
  size_t encrypt_updates, decrypt_updates;
} counted_crypto_t;

static int
counted_setup_cipher(quicly_crypto_engine_t *engine, quicly_conn_t *conn,
                     size_t epoch, int is_enc, ptls_cipher_context_t **header,
                     ptls_aead_context_t **packet, ptls_aead_algorithm_t *aead,
                     ptls_hash_algorithm_t *hash, const void *secret) {
  counted_crypto_t *counted = (counted_crypto_t *)engine;
  int result =
      counted->delegate->setup_cipher(counted->delegate, conn, epoch, is_enc,
                                      header, packet, aead, hash, secret);
  if (result == 0 && epoch == QUICLY_EPOCH_1RTT && header == NULL) {
    if (is_enc)
      counted->encrypt_updates++;
    else
      counted->decrypt_updates++;
  }
  return result;
}

static void counted_encrypt_packet(quicly_crypto_engine_t *engine,
                                   quicly_conn_t *conn,
                                   ptls_cipher_context_t *header,
                                   ptls_aead_context_t *packet,
                                   ptls_iovec_t datagram, size_t first_byte,
                                   size_t payload, uint64_t packet_number,
                                   int coalesced) {
  counted_crypto_t *counted = (counted_crypto_t *)engine;
  counted->delegate->encrypt_packet(counted->delegate, conn, header, packet,
                                    datagram, first_byte, payload,
                                    packet_number, coalesced);
}

typedef struct {
  transport_t *transport;
  transport_conn_t *conn;
  counted_crypto_t crypto;
  bool server, authenticated, subscribed, failed;
  size_t offered, received;
} crypto_peer_t;

static void mixed_peer_event(void *data, const transport_event_t *event) {
  crypto_peer_t *peer = data;
  peer->conn = event->conn;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    if (!peer->server)
      peer->failed |= !transport_send_auth(peer->transport, event->conn,
                                           (const uint8_t *)"crypto", 6);
    break;
  case TRANSPORT_EVENT_AUTH:
    peer->failed |= !transport_respond_auth(peer->transport, event->conn, true);
    peer->authenticated = !peer->failed;
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    peer->authenticated = event->auth.success;
    peer->failed |= !event->auth.success;
    break;
  case TRANSPORT_EVENT_SUBSCRIBE:
    peer->subscribed = true;
    break;
  case TRANSPORT_EVENT_OBJECT:
    peer->failed |=
        event->object.object_id != peer->received || event->object.size != 2048;
    for (size_t i = 0; i < event->object.size; i++)
      peer->failed |= event->object.data[i] != (uint8_t)peer->received;
    peer->received++;
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    peer->failed = true;
    break;
  default:
    break;
  }
}

static int create_mixed_peer(crypto_peer_t *peer, const char *backend) {
  CHECK(setenv("QLINQ_CRYPTO_BACKEND", backend, 1) == 0);
  transport_config_t config = {.bind_hosts = {"127.0.0.1"},
                               .num_bind_hosts = 1,
                               .port = 19867,
                               .cert_file = "t/assets/verified.crt",
                               .key_file = "t/assets/verified.key",
                               .ca_file = "t/assets/verified.crt",
                               .verify_peer = true,
                               .callback = mixed_peer_event,
                               .user_data = peer};
  if (!peer->server) {
    config.remote_hosts[0] = "127.0.0.1";
    config.num_remote_hosts = 1;
  }
  peer->transport = transport_create(&config);
  CHECK(peer->transport);
  peer->crypto.super =
      (quicly_crypto_engine_t){counted_setup_cipher, counted_encrypt_packet};
  peer->crypto.delegate = peer->transport->quic_ctx.crypto_engine;
  peer->transport->quic_ctx.crypto_engine = &peer->crypto.super;
  peer->transport->quic_ctx.max_packets_per_key = 4;
  return 0;
}

static void mixed_tick(crypto_peer_t *server, crypto_peer_t *client) {
  transport_tick(server->transport);
  transport_tick(client->transport);
  usleep(1000);
}

static void mixed_publish(crypto_peer_t *peer, moq_track_id_t track) {
  uint8_t payload[2048];
  memset(payload, (uint8_t)peer->offered, sizeof(payload));
  moq_object_t object = {.track_id = track,
                         .group_id = 1,
                         .object_id = peer->offered,
                         .data = payload,
                         .size = sizeof(payload)};
  if (transport_publish(peer->transport, &object))
    peer->offered++;
}

static int check_mixed_peers_and_key_updates(void) {
  crypto_peer_t server = {.server = true}, client = {0};
  CHECK(create_mixed_peer(&server, "fusion") == 0);
  CHECK(create_mixed_peer(&client, "openssl") == 0);
  for (size_t attempt = 0;
       attempt < 2000 && (!server.authenticated || !client.authenticated);
       attempt++) {
    mixed_tick(&server, &client);
    CHECK(!server.failed && !client.failed);
  }
  CHECK(server.authenticated && client.authenticated);
  ptls_cipher_suite_t *server_cipher =
      ptls_get_cipher(quicly_get_tls(server.conn->quic));
  ptls_cipher_suite_t *client_cipher =
      ptls_get_cipher(quicly_get_tls(client.conn->quic));
  CHECK(server_cipher->id == PTLS_CIPHER_SUITE_AES_256_GCM_SHA384 &&
        client_cipher->id == PTLS_CIPHER_SUITE_AES_256_GCM_SHA384);
  CHECK(server_cipher->aead ==
            server.transport->tls_ctx.cipher_suites[0]->aead &&
        client_cipher->aead == &ptls_openssl_aes256gcm);
  CHECK(transport_tls_cid_cipher(client.transport) == &ptls_openssl_quiclb);
#if QLINQ_WITH_FUSION
  CHECK((transport_tls_cid_cipher(server.transport) == &ptls_fusion_quiclb) ==
        (server_cipher->aead == &ptls_fusion_aes256gcm));
#endif
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_RELIABLE,
                          .name = "mixed-backend-key-update"};
  CHECK(transport_subscribe_conn(server.transport, server.conn, track));
  CHECK(transport_subscribe_conn(client.transport, client.conn, track));
  for (size_t attempt = 0;
       attempt < 2000 && (!server.subscribed || !client.subscribed);
       attempt++) {
    mixed_tick(&server, &client);
    CHECK(!server.failed && !client.failed);
  }
  CHECK(server.subscribed && client.subscribed);
  /* The wrapper observes actual key replacement and delegates packet crypto
   * unchanged. Keep traffic active through QUIC's key-update delay. */
  for (size_t attempt = 0;
       attempt < 3000 && (server.offered < 32 || client.offered < 32 ||
                          server.crypto.encrypt_updates == 0 ||
                          client.crypto.encrypt_updates == 0);
       attempt++) {
    mixed_publish(&server, track);
    mixed_publish(&client, track);
    mixed_tick(&server, &client);
    CHECK(!server.failed && !client.failed);
  }
  for (size_t attempt = 0;
       attempt < 2000 && (server.received != client.offered ||
                          client.received != server.offered ||
                          server.crypto.decrypt_updates == 0 ||
                          client.crypto.decrypt_updates == 0);
       attempt++) {
    mixed_tick(&server, &client);
    CHECK(!server.failed && !client.failed);
  }
  CHECK(server.offered >= 32 && client.offered >= 32);
  CHECK(server.received == client.offered && client.received == server.offered);
  CHECK(server.crypto.encrypt_updates && server.crypto.decrypt_updates &&
        client.crypto.encrypt_updates && client.crypto.decrypt_updates);
  printf("mixed peers delivered %zu/%zu records; key updates send=%zu/%zu "
         "receive=%zu/%zu\n",
         server.received, client.received, server.crypto.encrypt_updates,
         client.crypto.encrypt_updates, server.crypto.decrypt_updates,
         client.crypto.decrypt_updates);
  transport_destroy(client.transport);
  transport_destroy(server.transport);
  CHECK(unsetenv("QLINQ_CRYPTO_BACKEND") == 0);
  return 0;
}

int main(void) {
  CHECK(check_cid_cache() == 0);
  CHECK(unsetenv("QLINQ_CRYPTO_BACKEND") == 0);
  transport_t *t = create_endpoint();
  CHECK(t && t->tls_ctx.cipher_suites == ptls_openssl_cipher_suites);
  CHECK(transport_tls_cid_cipher(t) == &ptls_openssl_quiclb);
  CHECK(strstr(crypto_log, "backend=openssl requested=openssl fallback=none"));
  CHECK(check_cid_protection(t) == 0);
  CHECK(check_cid_credential_reload(t) == 0);
  transport_destroy(t);

  CHECK(setenv("QLINQ_CRYPTO_BACKEND", "openssl", 1) == 0);
  t = create_endpoint();
  CHECK(t && t->tls_ctx.cipher_suites == ptls_openssl_cipher_suites);
  CHECK(transport_tls_cid_cipher(t) == &ptls_openssl_quiclb);
  transport_destroy(t);

  CHECK(setenv("QLINQ_CRYPTO_BACKEND", "invalid", 1) == 0);
  CHECK(create_endpoint() == NULL);
  CHECK(strstr(crypto_log, "invalid QLINQ_CRYPTO_BACKEND"));

  CHECK(setenv("QLINQ_CRYPTO_BACKEND", "fusion", 1) == 0);
  t = create_endpoint();
  CHECK(t);
#if QLINQ_WITH_FUSION
  bool capable =
      __builtin_cpu_supports("avx2") && __builtin_cpu_supports("aes") &&
      __builtin_cpu_supports("pclmul") && __builtin_cpu_supports("vaes") &&
      __builtin_cpu_supports("vpclmulqdq") && ptls_fusion_is_supported_by_cpu();
  CHECK((t->tls_ctx.cipher_suites != ptls_openssl_cipher_suites) == capable);
  CHECK((transport_tls_cid_cipher(t) == &ptls_fusion_quiclb) == capable);
#else
  CHECK(t->tls_ctx.cipher_suites == ptls_openssl_cipher_suites);
  CHECK(transport_tls_cid_cipher(t) == &ptls_openssl_quiclb);
  CHECK(strstr(crypto_log, "fallback=not-built"));
#endif
  if (t->tls_ctx.cipher_suites == ptls_openssl_cipher_suites) {
    CHECK(strstr(crypto_log, "backend=openssl requested=fusion fallback="));
    CHECK(!strstr(crypto_log, "fallback=none"));
  } else {
    CHECK(strstr(crypto_log, "backend=fusion requested=fusion fallback=none"));
  }
  CHECK(check_cid_protection(t) == 0);
  /* verify suite attributes match reference */
  for (size_t i = 0;; i++) {
    ptls_cipher_suite_t *suite = t->tls_ctx.cipher_suites[i];
    ptls_cipher_suite_t *reference = ptls_openssl_cipher_suites[i];
    CHECK((suite != NULL) == (reference != NULL));
    if (!suite)
      break;
    CHECK(suite->id == reference->id && suite->hash == reference->hash);
    CHECK(strcmp(suite->name, reference->name) == 0);
    CHECK(suite->aead->key_size == reference->aead->key_size &&
          suite->aead->iv_size == reference->aead->iv_size &&
          suite->aead->tag_size == reference->aead->tag_size &&
          suite->aead->confidentiality_limit ==
              reference->aead->confidentiality_limit &&
          suite->aead->integrity_limit == reference->aead->integrity_limit);
#if QLINQ_WITH_FUSION
    if (capable && suite->id == PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)
      CHECK(suite->aead == &ptls_fusion_aes128gcm);
    if (capable && suite->id == PTLS_CIPHER_SUITE_AES_256_GCM_SHA384)
      CHECK(suite->aead == &ptls_fusion_aes256gcm);
#endif
    if (suite->id == PTLS_CIPHER_SUITE_AES_128_GCM_SHA256 ||
        suite->id == PTLS_CIPHER_SUITE_AES_256_GCM_SHA384)
      CHECK(check_packet_protection(suite, reference) == 0);
  }
  printf("%s\n", crypto_log);
#if QLINQ_WITH_FUSION
  CHECK(configure_unsupported_cpu(t));
  CHECK(t->tls_ctx.cipher_suites == ptls_openssl_cipher_suites);
  CHECK(transport_tls_cid_cipher(t) == &ptls_openssl_quiclb);
  CHECK(unsupported_cpu_cid_cipher(t) == &ptls_openssl_quiclb);
  CHECK(strstr(crypto_log,
               "backend=openssl requested=fusion fallback=cpu-unsupported"));
#endif
  transport_destroy(t);
  CHECK(check_mixed_peers_and_key_updates() == 0);
  puts("===CRYPTO BACKENDS OK===");
  return 0;
}
