/* Endpoint TLS group policy. Cryptography remains in Picotls/OpenSSL. */
#include "transport_tls.h"
#include "transport_internal.h"

#include <openssl/err.h>
#include <openssl/evperr.h>
#include <stdlib.h>
#include <string.h>

const char *qlinq_tls_group_policy_name(qlinq_tls_group_policy_t policy) {
  switch (policy) {
  case QLINQ_TLS_GROUP_CLASSICAL:
    return "classical";
  case QLINQ_TLS_GROUP_PREFER_HYBRID:
    return "prefer-hybrid";
  case QLINQ_TLS_GROUP_REQUIRE_HYBRID:
    return "require-hybrid";
  default:
    return NULL;
  }
}

bool qlinq_tls_group_policy_parse(const char *text,
                                  qlinq_tls_group_policy_t *policy) {
  if (!text || !policy)
    return false;
  for (unsigned i = 0; i <= QLINQ_TLS_GROUP_REQUIRE_HYBRID; i++) {
    if (strcmp(text, qlinq_tls_group_policy_name(i)) == 0) {
      *policy = (qlinq_tls_group_policy_t)i;
      return true;
    }
  }
  return false;
}

typedef enum {
  HYBRID_AVAILABLE,
  HYBRID_UNAVAILABLE,
  HYBRID_ERROR
} hybrid_probe_t;

#if PTLS_OPENSSL_HAVE_X25519MLKEM768 && !defined(OPENSSL_IS_BORINGSSL)
/* A failed fetch is positive evidence of unavailability only if every error
 * explicitly says unsupported. Allocation/provider/empty-stack failures are
 * ambiguous and must fail closed. No provider or property policy is changed. */
static hybrid_probe_t classify_fetch_failure(void) {
  bool unsupported = false;
  unsigned long error;
  while ((error = ERR_get_error()) != 0) {
    if (ERR_GET_LIB(error) != ERR_LIB_EVP ||
        (ERR_GET_REASON(error) != ERR_R_UNSUPPORTED &&
         ERR_GET_REASON(error) != EVP_R_UNSUPPORTED_ALGORITHM)) {
      ERR_clear_error();
      return HYBRID_ERROR;
    }
    unsupported = true;
  }
  return unsupported ? HYBRID_UNAVAILABLE : HYBRID_ERROR;
}
#endif

static hybrid_probe_t probe_hybrid(const char **reason) {
#if PTLS_OPENSSL_HAVE_X25519MLKEM768
#ifndef OPENSSL_IS_BORINGSSL
  /* Use the exact provider name and default library context/property query
   * used by the pinned Picotls implementation. Discovery alone is not enough:
   * the actual Picotls create/release path below must also succeed. */
  ERR_clear_error();
  EVP_KEYMGMT *keymgmt =
      EVP_KEYMGMT_fetch(NULL, PTLS_GROUP_NAME_X25519MLKEM768, NULL);
  if (!keymgmt) {
    hybrid_probe_t result = classify_fetch_failure();
    *reason = result == HYBRID_UNAVAILABLE ? "provider-keymgmt-unavailable"
                                           : "provider-keymgmt-error";
    return result;
  }
  EVP_KEYMGMT_free(keymgmt);
  EVP_KEM *kem = EVP_KEM_fetch(NULL, PTLS_GROUP_NAME_X25519MLKEM768, NULL);
  if (!kem) {
    hybrid_probe_t result = classify_fetch_failure();
    *reason = result == HYBRID_UNAVAILABLE ? "provider-kem-unavailable"
                                           : "provider-kem-error";
    return result;
  }
  EVP_KEM_free(kem);
#endif
  ptls_key_exchange_context_t *ctx = NULL;
  int ret =
      ptls_openssl_x25519mlkem768.create(&ptls_openssl_x25519mlkem768, &ctx);
  if (ret == 0 && ctx) {
    /* Picotls owns and clears the ephemeral private key on release. */
    ret = ctx->on_exchange(&ctx, 1, NULL, ptls_iovec_init(NULL, 0));
  } else if (ret == 0) {
    ret = PTLS_ERROR_LIBRARY;
  }
  ERR_clear_error();
  if (ret != 0) {
    *reason = ret == PTLS_ERROR_NO_MEMORY ? "probe-allocation-failed"
                                          : "picotls-probe-failed";
    return HYBRID_ERROR;
  }
  *reason = "available";
  return HYBRID_AVAILABLE;
#else
  *reason = "not-built";
  return HYBRID_UNAVAILABLE;
#endif
}

bool transport_tls_configure_groups(transport_t *t,
                                    qlinq_tls_group_policy_t policy) {
  const char *name = qlinq_tls_group_policy_name(policy);
  if (!t || !name)
    return false;
  t->tls_group_policy = policy;
  t->tls_hybrid_available = false;
  t->tls_hybrid_reason = "not-probed-classical";
  memset(t->tls_key_exchanges, 0, sizeof(t->tls_key_exchanges));
  t->tls_key_exchanges[0] = &ptls_openssl_secp256r1;
  t->tls_ctx.key_exchanges = t->tls_key_exchanges;
  if (policy == QLINQ_TLS_GROUP_CLASSICAL)
    return true;

  hybrid_probe_t result = probe_hybrid(&t->tls_hybrid_reason);
  if (result == HYBRID_ERROR || (result == HYBRID_UNAVAILABLE &&
                                 policy == QLINQ_TLS_GROUP_REQUIRE_HYBRID)) {
    transport_log(t, TRANSPORT_LOG_ERROR, "tls-groups", 0, SIZE_MAX,
                  "policy=%s reason=%s; usable X25519MLKEM768 requires a "
                  "hybrid-capable Picotls/OpenSSL build and permitted provider",
                  name, t->tls_hybrid_reason);
    return false;
  }
  if (result == HYBRID_UNAVAILABLE) {
    transport_log(
        t, TRANSPORT_LOG_WARNING, "tls-groups", 0, SIZE_MAX,
        "policy=%s local-hybrid-unavailable reason=%s fallback=secp256r1", name,
        t->tls_hybrid_reason);
    return true;
  }
#if PTLS_OPENSSL_HAVE_X25519MLKEM768
  t->tls_hybrid_available = true;
  t->tls_key_exchanges[0] = &ptls_openssl_x25519mlkem768;
  if (policy == QLINQ_TLS_GROUP_PREFER_HYBRID)
    t->tls_key_exchanges[1] = &ptls_openssl_secp256r1;
#endif
  transport_log(t, TRANSPORT_LOG_INFO, "tls-groups", 0, SIZE_MAX,
                "policy=%s local-hybrid=available", name);
  return true;
}
