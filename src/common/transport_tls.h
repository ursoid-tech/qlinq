#ifndef QLINQ_TRANSPORT_TLS_H
#define QLINQ_TRANSPORT_TLS_H

#include "transport.h"
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly/cid.h"

/* OpenSSL by default; explicit Fusion selection has build/CPU fallback. */
bool transport_tls_configure_crypto_backend(transport_t *transport);
/* Call after backend configuration; inherits its explicit selection/CPU guard.
 */
ptls_cipher_algorithm_t *transport_tls_cid_cipher(const transport_t *transport);
/* Owns the native encryptor and an optional bounded decryption cache. Always
 * release with the paired helper, including allocation-fallback results. */
quicly_cid_encryptor_t *
transport_tls_new_cid_encryptor(const transport_t *transport, ptls_iovec_t key);
void transport_tls_free_cid_encryptor(quicly_cid_encryptor_t *encryptor);

int transport_tls_load_certificate_and_key(
    ptls_context_t *tls, ptls_openssl_sign_certificate_t *signer,
    const char *certificate_file, const char *key_file);
void transport_tls_init_insecure_verifier(
    ptls_openssl_verify_certificate_t *verifier);

#endif
