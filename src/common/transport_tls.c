#include "transport_tls.h"
#include "transport_internal.h"
#include "quicly/defaults.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#if QLINQ_WITH_FUSION
#include "picotls/fusion.h"
#endif

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
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
#if PTLS_OPENSSL_HAVE_ED25519
    PTLS_SIGNATURE_ED25519,
#endif
    PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
#ifdef NID_secp384r1
    PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384,
#endif
#ifdef NID_secp521r1
    PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512,
#endif
    PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
    PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
    PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512,
    PTLS_SIGNATURE_RSA_PKCS1_SHA256,
    UINT16_MAX};

static int verify_peer_signature(void *verify_ctx, uint16_t algo,
                                 ptls_iovec_t data, ptls_iovec_t signature) {
  EVP_PKEY *key = verify_ctx;
  EVP_MD_CTX *ctx = NULL;
  EVP_PKEY_CTX *pkey_ctx = NULL;
  int ret = 0;

  if (!data.base)
    goto Exit;

  const ptls_openssl_signature_scheme_t *scheme =
      ptls_openssl_lookup_signature_schemes(key);
  if (!scheme) {
    ret = PTLS_ERROR_LIBRARY;
    goto Exit;
  }
  for (; scheme->scheme_id != UINT16_MAX; ++scheme) {
    if (scheme->scheme_id == algo)
      break;
  }
  if (scheme->scheme_id == UINT16_MAX) {
    ret = PTLS_ALERT_ILLEGAL_PARAMETER;
    goto Exit;
  }
  ctx = EVP_MD_CTX_create();
  if (!ctx) {
    ret = PTLS_ERROR_NO_MEMORY;
    goto Exit;
  }
#if PTLS_OPENSSL_HAVE_ED25519
  if (EVP_PKEY_id(key) == EVP_PKEY_ED25519) {
    if (EVP_DigestVerifyInit(ctx, &pkey_ctx, NULL, NULL, key) != 1 ||
        EVP_DigestVerify(ctx, signature.base, signature.len, data.base,
                         data.len) != 1) {
      ret = PTLS_ALERT_DECRYPT_ERROR;
      goto Exit;
    }
  } else
#endif
  {
    if (EVP_DigestVerifyInit(ctx, &pkey_ctx, scheme->scheme_md(), NULL, key) !=
        1) {
      ret = PTLS_ERROR_LIBRARY;
      goto Exit;
    }
    if (EVP_PKEY_id(key) == EVP_PKEY_RSA) {
      if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1 ||
          EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) != 1 ||
          EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, scheme->scheme_md()) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
      }
    }
    if (EVP_DigestVerifyUpdate(ctx, data.base, data.len) != 1) {
      ret = PTLS_ERROR_LIBRARY;
      goto Exit;
    }
    if (EVP_DigestVerifyFinal(ctx, signature.base, signature.len) != 1) {
      ret = PTLS_ALERT_DECRYPT_ERROR;
      goto Exit;
    }
  }

Exit:
  if (ret != 0)
    ERR_clear_error();
  if (ctx)
    EVP_MD_CTX_destroy(ctx);
  EVP_PKEY_free(key);
  return ret;
}

/* verify proof-of-possession on presented certificates without CA trust */
static int verify_any_certificate(
    ptls_verify_certificate_t *self, ptls_t *tls, const char *server_name,
    int (**verify_sign)(void *verify_ctx, uint16_t algorithm, ptls_iovec_t data,
                        ptls_iovec_t signature),
    void **verify_data, ptls_iovec_t *certificates, size_t certificate_count) {
  (void)self;
  (void)server_name;
  if (certificate_count == 0)
    return ptls_is_server(tls) ? 0 : PTLS_ALERT_CERTIFICATE_REQUIRED;
  const unsigned char *der = certificates[0].base;
  X509 *cert = d2i_X509(NULL, &der, (long)certificates[0].len);
  if (!cert || der != certificates[0].base + certificates[0].len) {
    X509_free(cert);
    ERR_clear_error();
    return PTLS_ALERT_BAD_CERTIFICATE;
  }
  EVP_PKEY *pubkey = X509_get_pubkey(cert);
  X509_free(cert);
  if (!pubkey) {
    ERR_clear_error();
    return PTLS_ALERT_BAD_CERTIFICATE;
  }
  *verify_data = pubkey;
  *verify_sign = verify_peer_signature;
  return 0;
}

static void free_loaded_certificates(ptls_context_t *tls) {
  for (size_t i = 0; i < tls->certificates.count; i++)
    free(tls->certificates.list[i].base);
  free(tls->certificates.list);
  tls->certificates.list = NULL;
  tls->certificates.count = 0;
}

static FILE *open_credential_file(const char *path, bool private_key) {
#ifndef _WIN32
  int flags = O_RDONLY | O_CLOEXEC | O_NONBLOCK;
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
  int fd = open(path, flags);
  if (fd < 0)
    return NULL;
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
      (private_key && (st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) != 0)) {
    close(fd);
    return NULL;
  }
  FILE *fp = fdopen(fd, "r");
  if (!fp)
    close(fd);
  return fp;
#else
  (void)private_key;
  return fopen(path, "rb");
#endif
}

static int load_certificate_chain_fp(ptls_context_t *tls, FILE *fp) {
  X509 *leaf = PEM_read_X509(fp, NULL, NULL, NULL);
  if (!leaf) {
    ERR_clear_error();
    return -1;
  }
  STACK_OF(X509) *chain = sk_X509_new_null();
  if (!chain) {
    X509_free(leaf);
    return -1;
  }
  X509 *cert = NULL;
  while ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
    if (!sk_X509_push(chain, cert)) {
      X509_free(cert);
      sk_X509_pop_free(chain, X509_free);
      X509_free(leaf);
      return -1;
    }
  }
  ERR_clear_error();
  int rc = ptls_openssl_load_certificates(tls, leaf, chain);
  sk_X509_pop_free(chain, X509_free);
  X509_free(leaf);
  return rc == 0 ? 0 : -1;
}

int transport_tls_load_certificate_and_key(
    ptls_context_t *tls, ptls_openssl_sign_certificate_t *signer,
    const char *certificate_file, const char *key_file) {
  if (!tls || !signer || !certificate_file || !key_file)
    return -1;

  FILE *cert_fp = open_credential_file(certificate_file, false);
  if (!cert_fp)
    return -1;
  int cert_rc = load_certificate_chain_fp(tls, cert_fp);
  fclose(cert_fp);
  if (cert_rc != 0)
    return -1;

  FILE *key_fp = open_credential_file(key_file, true);
  if (!key_fp) {
    free_loaded_certificates(tls);
    return -1;
  }
  EVP_PKEY *key = PEM_read_PrivateKey(key_fp, NULL, NULL, NULL);
  fclose(key_fp);
  if (!key) {
    ERR_clear_error();
    free_loaded_certificates(tls);
    return -1;
  }
  const unsigned char *der =
      tls->certificates.count != 0 ? tls->certificates.list[0].base : NULL;
  X509 *leaf = der ? d2i_X509(NULL, &der, tls->certificates.list[0].len) : NULL;
  bool matches = leaf && X509_check_private_key(leaf, key) == 1;
  X509_free(leaf);
  if (!matches) {
    ERR_clear_error();
    EVP_PKEY_free(key);
    free_loaded_certificates(tls);
    return -1;
  }
  if (ptls_openssl_init_sign_certificate(signer, key) != 0) {
    ERR_clear_error();
    EVP_PKEY_free(key);
    free_loaded_certificates(tls);
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
