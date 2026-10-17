#ifndef QLINQ_TRANSPORT_TLS_H
#define QLINQ_TRANSPORT_TLS_H

#include "transport.h"
#include "picotls.h"
#include "picotls/openssl.h"

/* OpenSSL by default; explicit Fusion selection has build/CPU fallback. */
bool transport_tls_configure_crypto_backend(transport_t *transport);

int transport_tls_load_certificate_and_key(
    ptls_context_t *tls, ptls_openssl_sign_certificate_t *signer,
    const char *certificate_file, const char *key_file);
void transport_tls_init_insecure_verifier(
    ptls_openssl_verify_certificate_t *verifier);

#endif
