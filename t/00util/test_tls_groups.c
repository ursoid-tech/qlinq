/* Endpoint policy, provider classification and compile-time absence fixtures.
 */
#include "transport_internal.h"
#include "transport_tls.h"
#include <assert.h>
#include <openssl/err.h>
#include <openssl/evperr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Private copy of production policy code: inject provider and creation errors
 * without introducing any production environment override. */
#if PTLS_OPENSSL_HAVE_X25519MLKEM768 && !defined(OPENSSL_IS_BORINGSSL)
static int fault;
static EVP_KEYMGMT *test_keymgmt_fetch(OSSL_LIB_CTX *ctx, const char *name,
                                       const char *properties) {
  if (fault == 1) {
    ERR_raise(ERR_LIB_EVP, ERR_R_UNSUPPORTED);
    return NULL;
  }
  if (fault == 2) {
    ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  if (fault == 3)
    return NULL; /* ambiguous */
  if (fault == 4) {
    ERR_raise(ERR_LIB_EVP, ERR_R_UNSUPPORTED);
    ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  return EVP_KEYMGMT_fetch(ctx, name, properties);
}
static int test_create(ptls_key_exchange_algorithm_t *algo,
                       ptls_key_exchange_context_t **ctx) {
  (void)algo;
  if (fault == 5)
    return PTLS_ERROR_NO_MEMORY;
  if (fault == 6)
    return PTLS_ERROR_LIBRARY;
  return ptls_openssl_x25519mlkem768.create(&ptls_openssl_x25519mlkem768, ctx);
}
static const struct st_ptls_key_exchange_algorithm_t test_hybrid = {
    .id = PTLS_GROUP_X25519MLKEM768, .create = test_create};
#define EVP_KEYMGMT_fetch test_keymgmt_fetch
#define ptls_openssl_x25519mlkem768 test_hybrid
#endif
#define qlinq_tls_group_policy_name fixture_policy_name
#define qlinq_tls_group_policy_parse fixture_policy_parse
#define transport_tls_configure_groups fixture_configure_groups
#include "../../src/common/transport_tls_groups.c"
#undef transport_tls_configure_groups
#undef qlinq_tls_group_policy_parse
#undef qlinq_tls_group_policy_name
#if PTLS_OPENSSL_HAVE_X25519MLKEM768 && !defined(OPENSSL_IS_BORINGSSL)
#undef ptls_openssl_x25519mlkem768
#undef EVP_KEYMGMT_fetch
#endif

bool legacy_configure_groups(transport_t *, qlinq_tls_group_policy_t);
static char last_log[512];
static void capture(void *data, const transport_log_event_t *event) {
  (void)data;
  snprintf(last_log, sizeof(last_log), "%s", event->message);
}
static void ignore(void *data, const transport_event_t *event) {
  (void)data;
  (void)event;
}

int main(void) {
  printf("compiled=%s loaded=%s\n", OPENSSL_VERSION_TEXT,
         OpenSSL_version(OPENSSL_VERSION));
  for (int i = 0; i <= QLINQ_TLS_GROUP_REQUIRE_HYBRID; i++) {
    qlinq_tls_group_policy_t value = -1;
    assert(
        qlinq_tls_group_policy_parse(qlinq_tls_group_policy_name(i), &value));
    assert(value == (qlinq_tls_group_policy_t)i);
  }
  const char *invalid[] = {
      NULL, "", "hybrid", "CLASSICAL", " classical", "require-hybrid ", "1"};
  for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
    qlinq_tls_group_policy_t value = QLINQ_TLS_GROUP_REQUIRE_HYBRID;
    assert(!qlinq_tls_group_policy_parse(invalid[i], &value));
    assert(value == QLINQ_TLS_GROUP_REQUIRE_HYBRID);
  }
  assert(!qlinq_tls_group_policy_parse("classical", NULL));
  assert(!qlinq_tls_group_policy_name(-1));
  assert(!qlinq_tls_group_policy_name(3));
  transport_t *t = calloc(1, sizeof(*t));
  assert(t);
  t->log_callback = capture;
  assert(!transport_tls_configure_groups(t, -1));
  assert(!transport_tls_configure_groups(t, 3));
  assert(transport_tls_configure_groups(t, 0));
  assert(t->tls_ctx.key_exchanges == t->tls_key_exchanges);
  assert(t->tls_key_exchanges[0] == &ptls_openssl_secp256r1);
  assert(!t->tls_key_exchanges[1]);
  assert(transport_tls_configure_groups(t, QLINQ_TLS_GROUP_PREFER_HYBRID));
  bool available = t->tls_hybrid_available;
  printf("hybrid=%s reason=%s\n", available ? "available" : "unavailable",
         t->tls_hybrid_reason);
  if (getenv("QLINQ_TEST_REQUIRE_HYBRID"))
    assert(available);
  if (getenv("QLINQ_TEST_REQUIRE_LEGACY")) {
    assert(!available);
    assert(!strcmp(t->tls_hybrid_reason, "not-built"));
  }
  if (available) {
    assert(t->tls_key_exchanges[0]->id == PTLS_GROUP_X25519MLKEM768);
    assert(t->tls_key_exchanges[1] == &ptls_openssl_secp256r1);
    assert(!t->tls_key_exchanges[2]);
    assert(transport_tls_configure_groups(t, QLINQ_TLS_GROUP_REQUIRE_HYBRID));
    assert(t->tls_key_exchanges[0]->id == PTLS_GROUP_X25519MLKEM768);
    assert(!t->tls_key_exchanges[1]);
  } else {
    assert(!transport_tls_configure_groups(t, QLINQ_TLS_GROUP_REQUIRE_HYBRID));
  }
  /* Compile-time absence exercises the production source with the dependency
   * capability macro disabled; the object has no hybrid symbol references. */
  assert(legacy_configure_groups(t, QLINQ_TLS_GROUP_CLASSICAL));
  assert(legacy_configure_groups(t, QLINQ_TLS_GROUP_PREFER_HYBRID));
  assert(strstr(last_log, "local-hybrid-unavailable reason=not-built"));
  assert(t->tls_key_exchanges[0] == &ptls_openssl_secp256r1);
  assert(!t->tls_key_exchanges[1]);
  assert(!legacy_configure_groups(t, QLINQ_TLS_GROUP_REQUIRE_HYBRID));
#if PTLS_OPENSSL_HAVE_X25519MLKEM768 && !defined(OPENSSL_IS_BORINGSSL)
  /* Real provider property exclusion, without changing provider policy in
   * production. Only this single-threaded fixture changes default properties.
   */
  assert(EVP_set_default_properties(NULL, "provider=qlinq-test-missing") == 1);
  assert(transport_tls_configure_groups(t, QLINQ_TLS_GROUP_PREFER_HYBRID));
  assert(!t->tls_hybrid_available);
  assert(strstr(last_log, "local-hybrid-unavailable"));
  assert(!transport_tls_configure_groups(t, QLINQ_TLS_GROUP_REQUIRE_HYBRID));
  assert(transport_tls_configure_groups(t, QLINQ_TLS_GROUP_CLASSICAL));
  assert(EVP_set_default_properties(NULL, NULL) == 1);
  for (fault = 1; fault <= 6; fault++) {
    if (fault >= 5 && !available)
      continue;
    bool ok = fixture_configure_groups(t, QLINQ_TLS_GROUP_PREFER_HYBRID);
    assert(ok == (fault == 1));
    if (ok)
      assert(strstr(last_log, "local-hybrid-unavailable"));
    assert(!fixture_configure_groups(t, QLINQ_TLS_GROUP_REQUIRE_HYBRID));
    assert(fixture_configure_groups(t, QLINQ_TLS_GROUP_CLASSICAL));
  }
  fault = 0;
#endif
  free(t);

  /* Real endpoint creation, independent arrays, config ownership and reload. */
  transport_config_t config = {.bind_hosts = {"127.0.0.1"},
                               .num_bind_hosts = 1,
                               .port = 19949,
                               .cert_file = "t/assets/verified.crt",
                               .key_file = "t/assets/verified.key",
                               .ca_file = "t/assets/verified.crt",
                               .verify_peer = true,
                               .callback = ignore,
                               .log_callback = capture};
  transport_t *classical = transport_create(&config);
  assert(classical);
  config.port++;
  config.tls_group_policy = QLINQ_TLS_GROUP_PREFER_HYBRID;
  transport_t *preferred = transport_create(&config);
  assert(preferred);
  config.port++;
  config.tls_group_policy = QLINQ_TLS_GROUP_REQUIRE_HYBRID;
  transport_t *required = transport_create(&config);
  assert((required != NULL) == available);
  config.tls_group_policy = -1;
  assert(!transport_create(&config));
  config.tls_group_policy = 3;
  assert(!transport_create(&config));
  assert(classical->tls_group_policy == QLINQ_TLS_GROUP_CLASSICAL);
  assert(preferred->tls_group_policy == QLINQ_TLS_GROUP_PREFER_HYBRID);
  assert(classical->tls_ctx.key_exchanges != preferred->tls_ctx.key_exchanges);
  assert(classical->tls_key_exchanges[0] == &ptls_openssl_secp256r1);
  assert(ptls_openssl_key_exchanges[0] == &ptls_openssl_secp256r1);
  assert(!ptls_openssl_key_exchanges[1]);
  assert(transport_reload_credentials(preferred, "t/assets/verified.crt",
                                      "t/assets/verified.key"));
  assert(preferred->tls_group_policy == QLINQ_TLS_GROUP_PREFER_HYBRID);
  assert(preferred->tls_hybrid_available == available);
  if (available)
    assert(preferred->tls_key_exchanges[0]->id == PTLS_GROUP_X25519MLKEM768);
  transport_destroy(required);
  transport_destroy(preferred);
  transport_destroy(classical);
  puts("===TLS GROUPS OK===");
  return 0;
}
