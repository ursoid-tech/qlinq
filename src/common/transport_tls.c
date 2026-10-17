#include "transport_tls.h"
#include "transport_internal.h"
#include "quicly/defaults.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#if QLINQ_WITH_FUSION
#include "picotls/fusion.h"
#endif

#include <openssl/pem.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#ifndef _WIN32
#include <sys/stat.h>
#endif

#if QLINQ_WITH_FUSION
static pthread_once_t fusion_cpu_once = PTHREAD_ONCE_INIT;
static bool fusion_cpu_supported;

static void detect_fusion_cpu(void) {
  /* This generic translation unit guards every ISA enabled for fusion.o.
   * The AVX2 builtin also checks OS support for saving the vector state. */
  if (__builtin_cpu_supports("avx2") && __builtin_cpu_supports("aes") &&
      __builtin_cpu_supports("pclmul") && __builtin_cpu_supports("vaes") &&
      __builtin_cpu_supports("vpclmulqdq"))
    fusion_cpu_supported = ptls_fusion_is_supported_by_cpu() != 0;
}

static ptls_cipher_suite_t fusion_aes128 = {
    .id = PTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
    .aead = &ptls_fusion_aes128gcm,
    .hash = &ptls_openssl_sha256,
    .name = PTLS_CIPHER_SUITE_NAME_AES_128_GCM_SHA256};
static ptls_cipher_suite_t fusion_aes256 = {
    .id = PTLS_CIPHER_SUITE_AES_256_GCM_SHA384,
    .aead = &ptls_fusion_aes256gcm,
    .hash = &ptls_openssl_sha384,
    .name = PTLS_CIPHER_SUITE_NAME_AES_256_GCM_SHA384};
/* Preserve the pinned OpenSSL cipher order. These Fusion engines implement
 * QUIC packet AEAD, not incremental TLS record encryption. */
static ptls_cipher_suite_t *fusion_cipher_suites[] = {
    &fusion_aes256, &fusion_aes128,
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
    &ptls_openssl_chacha20poly1305sha256,
#endif
    NULL};
#endif

bool transport_tls_configure_crypto_backend(transport_t *t) {
  const char *requested = getenv("QLINQ_CRYPTO_BACKEND");
  const char *selected = "openssl";
  const char *fallback = NULL;
  t->tls_ctx.cipher_suites = ptls_openssl_cipher_suites;
  if (!requested || !*requested)
    requested = "openssl";
  if (strcmp(requested, "fusion") == 0) {
#if QLINQ_WITH_FUSION
    pthread_once(&fusion_cpu_once, detect_fusion_cpu);
    if (fusion_cpu_supported) {
      t->tls_ctx.cipher_suites = fusion_cipher_suites;
      selected = "fusion";
    } else {
      fallback = "cpu-unsupported";
    }
#else
    fallback = "not-built";
#endif
  } else if (strcmp(requested, "openssl") != 0) {
    transport_log(
        t, TRANSPORT_LOG_ERROR, "crypto", 0, SIZE_MAX,
        "invalid QLINQ_CRYPTO_BACKEND=%s (expected openssl or fusion)",
        requested);
    return false;
  }
  transport_log(
      t, fallback ? TRANSPORT_LOG_WARNING : TRANSPORT_LOG_INFO, "crypto", 0,
      SIZE_MAX,
      "backend=%s requested=%s fallback=%s aes_preference=AES-256-GCM",
      selected, requested, fallback ? fallback : "none");
  /* Report an explicit selection even without a structured log consumer. */
  if (!t->log_callback && !fallback && getenv("QLINQ_CRYPTO_BACKEND"))
    fprintf(stderr,
            "qlinq[crypto] backend=%s requested=%s fallback=none "
            "aes_preference=AES-256-GCM\n",
            selected, requested);
  return true;
}

ptls_cipher_algorithm_t *transport_tls_cid_cipher(const transport_t *t) {
#if QLINQ_WITH_FUSION
  /* Use the configured choice, which already passed the runtime CPU guard.
   * Later environment changes must not alter an existing endpoint's policy. */
  if (t->tls_ctx.cipher_suites == fusion_cipher_suites)
    return &ptls_fusion_quiclb;
#endif
  (void)t;
  return &ptls_openssl_quiclb;
}

enum { CID_CACHE_ENTRIES = 8, CID_CACHE_MAX_SIZE = 16 };

typedef struct {
  quicly_cid_encryptor_t super;
  quicly_cid_encryptor_t *delegate;
  size_t cid_size, count, next;
  struct {
    uint8_t encrypted[CID_CACHE_MAX_SIZE];
    quicly_cid_plaintext_t plaintext;
  } entries[CID_CACHE_ENTRIES];
} cached_cid_encryptor_t;

static void cached_encrypt_cid(quicly_cid_encryptor_t *self,
                               quicly_cid_t *encrypted, void *reset_token,
                               const quicly_cid_plaintext_t *plaintext) {
  cached_cid_encryptor_t *cache = (cached_cid_encryptor_t *)self;
  cache->delegate->encrypt_cid(cache->delegate, encrypted, reset_token,
                               plaintext);
}

static size_t cached_decrypt_cid(quicly_cid_encryptor_t *self,
                                 quicly_cid_plaintext_t *plaintext,
                                 const void *encrypted, size_t len) {
  cached_cid_encryptor_t *cache = (cached_cid_encryptor_t *)self;
  /* Match the native long-header check before reading any ciphertext. Short
   * headers pass zero and use this endpoint's immutable cipher block size. */
  if (len != 0 && len != cache->cid_size)
    return SIZE_MAX;
  for (size_t i = 0; i < cache->count; i++) {
    if (memcmp(cache->entries[i].encrypted, encrypted, cache->cid_size) == 0) {
      *plaintext = cache->entries[i].plaintext;
      return cache->cid_size;
    }
  }
  /* The native decoder permits the input to overlap the output. Preserve the
   * ciphertext before delegation overwrites any such shared storage. */
  uint8_t cache_key[CID_CACHE_MAX_SIZE];
  memcpy(cache_key, encrypted, cache->cid_size);
  size_t result =
      cache->delegate->decrypt_cid(cache->delegate, plaintext, encrypted, len);
  if (result == cache->cid_size) {
    memcpy(cache->entries[cache->next].encrypted, cache_key, cache->cid_size);
    cache->entries[cache->next].plaintext = *plaintext;
    cache->next = (cache->next + 1) % CID_CACHE_ENTRIES;
    if (cache->count < CID_CACHE_ENTRIES)
      cache->count++;
  }
  return result;
}

static int cached_generate_reset_token(quicly_cid_encryptor_t *self,
                                       void *token, const void *cid) {
  cached_cid_encryptor_t *cache = (cached_cid_encryptor_t *)self;
  return cache->delegate->generate_stateless_reset_token(cache->delegate, token,
                                                         cid);
}

quicly_cid_encryptor_t *transport_tls_new_cid_encryptor(const transport_t *t,
                                                        ptls_iovec_t key) {
  ptls_cipher_algorithm_t *cipher = transport_tls_cid_cipher(t);
  quicly_cid_encryptor_t *delegate = quicly_new_default_cid_encryptor(
      cipher, &ptls_openssl_aes128ecb, &ptls_openssl_sha256, key);
  if (!delegate)
    return NULL;
  cached_cid_encryptor_t *cache = malloc(sizeof(*cache));
  if (!cache)
    return delegate;
  cache->super = (quicly_cid_encryptor_t){
      cached_encrypt_cid, cached_decrypt_cid, cached_generate_reset_token};
  cache->delegate = delegate;
  cache->cid_size = cipher->block_size;
  cache->count = cache->next = 0;
  /* The cache belongs to this endpoint/key, just like the native contexts.
   * It caches only the deterministic CID transform: hits still undergo normal
   * destination checks and packet authentication in quicly_receive. */
  return &cache->super;
}

void transport_tls_free_cid_encryptor(quicly_cid_encryptor_t *encryptor) {
  if (!encryptor)
    return;
  if (encryptor->decrypt_cid == cached_decrypt_cid) {
    cached_cid_encryptor_t *cache = (cached_cid_encryptor_t *)encryptor;
    quicly_free_default_cid_encryptor(cache->delegate);
    ptls_clear_memory(cache, sizeof(*cache));
    free(cache);
  } else {
    /* Wrapper allocation failed; the original native ownership is intact. */
    quicly_free_default_cid_encryptor(encryptor);
  }
}

static const uint16_t insecure_verify_algorithms[] = {
    PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256, PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
    PTLS_SIGNATURE_RSA_PKCS1_SHA256, UINT16_MAX};

static int verify_any_certificate(
    ptls_verify_certificate_t *self, ptls_t *tls, const char *server_name,
    int (**verify_sign)(void *verify_ctx, uint16_t algorithm, ptls_iovec_t data,
                        ptls_iovec_t signature),
    void **verify_data, ptls_iovec_t *certificates, size_t certificate_count) {
  (void)self;
  (void)tls;
  (void)server_name;
  (void)verify_sign;
  (void)verify_data;
  (void)certificates;
  (void)certificate_count;
  return 0;
}

int transport_tls_load_certificate_and_key(
    ptls_context_t *tls, ptls_openssl_sign_certificate_t *signer,
    const char *certificate_file, const char *key_file) {
  if (!tls || !signer || !certificate_file || !key_file) {
    fprintf(stderr, "certificate file and key file are required\n");
    return -1;
  }
#ifndef _WIN32
  struct stat key_stat;
  if (stat(key_file, &key_stat) != 0) {
    fprintf(stderr, "failed to inspect private key file\n");
    return -1;
  }
  if ((key_stat.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) != 0) {
    fprintf(stderr,
            "private key permissions are unsafe; remove group write/execute "
            "and all access for other users\n");
    return -1;
  }
#endif
  if (ptls_load_certificates(tls, (char *)certificate_file) != 0) {
    fprintf(stderr, "failed to load certificates\n");
    return -1;
  }

  FILE *file = fopen(key_file, "r");
  if (!file) {
    fprintf(stderr, "failed to open private key file\n");
    return -1;
  }
  EVP_PKEY *key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
  fclose(file);
  if (!key) {
    fprintf(stderr, "failed to load private key\n");
    return -1;
  }
  const unsigned char *der =
      tls->certificates.count != 0 ? tls->certificates.list[0].base : NULL;
  X509 *leaf = der ? d2i_X509(NULL, &der, tls->certificates.list[0].len) : NULL;
  bool matches = leaf && X509_check_private_key(leaf, key) == 1;
  X509_free(leaf);
  if (!matches) {
    EVP_PKEY_free(key);
    fprintf(stderr, "certificate and private key do not match\n");
    return -1;
  }
  if (ptls_openssl_init_sign_certificate(signer, key) != 0) {
    EVP_PKEY_free(key);
    fprintf(stderr, "failed to initialize certificate signer\n");
    return -1;
  }
  EVP_PKEY_free(key);
  tls->sign_certificate = &signer->super;
  return 0;
}

void transport_tls_init_insecure_verifier(
    ptls_openssl_verify_certificate_t *verifier) {
  if (!verifier)
    return;
  verifier->super.cb = verify_any_certificate;
  verifier->super.algos = insecure_verify_algorithms;
}
