#include "transport_tls.h"
#include "transport_internal.h"

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
