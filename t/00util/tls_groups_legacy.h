/* Controlled compile-time absence fixture; no production override. */
#include "transport_tls.h"
#undef PTLS_OPENSSL_HAVE_X25519MLKEM768
#define PTLS_OPENSSL_HAVE_X25519MLKEM768 0
#define qlinq_tls_group_policy_name legacy_policy_name
#define qlinq_tls_group_policy_parse legacy_policy_parse
#define transport_tls_configure_groups legacy_configure_groups
