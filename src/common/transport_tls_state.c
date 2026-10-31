/* Actual negotiation observations and the pre-application TLS policy barrier.
 */
#include "transport_tls.h"
#include "transport_internal.h"
#include <stdio.h>
#include <string.h>

static void log_result(transport_conn_t *conn) {
  if (conn->tls_logged)
    return;
  conn->tls_logged = true;
  transport_t *t = conn->transport;
  qlinq_tls_info_t *s = &conn->tls;
  const char *result = s->exchange == QLINQ_TLS_EXCHANGE_HYBRID ? "hybrid"
                       : s->exchange == QLINQ_TLS_EXCHANGE_CLASSICAL
                           ? "classical-negotiated"
                           : "rejected";
  transport_log(t,
                s->policy_accepted ? TRANSPORT_LOG_INFO : TRANSPORT_LOG_WARNING,
                "tls", conn->id, SIZE_MAX,
                "policy=%s tls_complete=%d group=%u result=%s accepted=%d "
                "handshake=%s verify_peer=%d reason=%s",
                qlinq_tls_group_policy_name(t->tls_group_policy), s->complete,
                s->selected_group, result, s->policy_accepted,
                s->handshake == QLINQ_TLS_HANDSHAKE_FULL  ? "full"
                : s->handshake == QLINQ_TLS_HANDSHAKE_PSK ? "psk"
                                                          : "pending",
                t->verifier_initialized,
                s->rejection_reason[0] ? s->rejection_reason : "none");
  if (!t->log_callback && s->policy_accepted)
    fprintf(stderr,
            "qlinq[tls] conn=%u policy=%s group=%u result=%s handshake=%s "
            "verify_peer=%d\n",
            conn->id, qlinq_tls_group_policy_name(t->tls_group_policy),
            s->selected_group, result,
            s->handshake == QLINQ_TLS_HANDSHAKE_FULL ? "full" : "psk",
            t->verifier_initialized);
}

void transport_tls_observe(transport_conn_t *conn) {
  if (!conn || !conn->quic || conn->tls.exchange != QLINQ_TLS_EXCHANGE_PENDING)
    return;
  qlinq_tls_info_t *s = &conn->tls;
  if (quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING) {
    s->exchange = QLINQ_TLS_EXCHANGE_REJECTED;
    snprintf(s->rejection_reason, sizeof(s->rejection_reason),
             "handshake-closed");
    log_result(conn);
    return; /* preserve the original certificate/transport failure */
  }
  ptls_t *tls = quicly_get_tls(conn->quic);
  if (!ptls_handshake_is_complete(tls))
    return;
  s->complete = true;
  s->selected_group = ptls_get_negotiated_group(tls);
  s->handshake = ptls_is_psk_handshake(tls) ? QLINQ_TLS_HANDSHAKE_PSK
                                            : QLINQ_TLS_HANDSHAKE_FULL;
  qlinq_tls_group_policy_t policy = conn->transport->tls_group_policy;
  bool classical = s->selected_group == PTLS_GROUP_SECP256R1;
  bool hybrid = s->selected_group == PTLS_GROUP_X25519MLKEM768;
  const char *reason = NULL;
  if (!s->selected_group)
    reason = "selected-group-unknown";
  else if ((policy == QLINQ_TLS_GROUP_CLASSICAL && !classical) ||
           (policy == QLINQ_TLS_GROUP_REQUIRE_HYBRID && !hybrid) ||
           (!classical && !hybrid))
    reason = "selected-group-forbidden";
  else if (policy != QLINQ_TLS_GROUP_CLASSICAL &&
           s->handshake != QLINQ_TLS_HANDSHAKE_FULL)
    reason = "fresh-full-handshake-required";
  if (reason) {
    s->exchange = QLINQ_TLS_EXCHANGE_REJECTED;
    snprintf(s->rejection_reason, sizeof(s->rejection_reason), "%s", reason);
    (void)quicly_close(conn->quic, TRANSPORT_APP_ERROR_TLS_POLICY, reason);
  } else {
    s->policy_accepted = true;
    s->exchange =
        hybrid ? QLINQ_TLS_EXCHANGE_HYBRID : QLINQ_TLS_EXCHANGE_CLASSICAL;
  }
  log_result(conn);
}

void transport_tls_note_failure(transport_conn_t *conn) {
  if (conn->tls.exchange == QLINQ_TLS_EXCHANGE_PENDING) {
    conn->tls.exchange = QLINQ_TLS_EXCHANGE_REJECTED;
    snprintf(conn->tls.rejection_reason, sizeof(conn->tls.rejection_reason),
             "handshake-failed");
    log_result(conn);
  }
}

bool transport_tls_application_allowed(transport_conn_t *conn) {
  if (!conn)
    return false;
  /* Preserve classical application timing. Its telemetry still waits for TLS.
   */
  if (conn->transport->tls_group_policy == QLINQ_TLS_GROUP_CLASSICAL)
    return conn->tls.exchange != QLINQ_TLS_EXCHANGE_REJECTED;
  transport_tls_observe(conn);
  return conn->tls.policy_accepted &&
         quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING;
}

void transport_tls_get_info(const transport_conn_t *conn,
                            qlinq_tls_info_t *info) {
  *info = conn->tls;
  const transport_t *t = conn->transport;
  info->configured_policy = t->tls_group_policy;
  info->local_hybrid_capability =
      t->tls_group_policy == QLINQ_TLS_GROUP_CLASSICAL
          ? QLINQ_TLS_HYBRID_NOT_PROBED
      : t->tls_hybrid_available ? QLINQ_TLS_HYBRID_AVAILABLE
                                : QLINQ_TLS_HYBRID_UNAVAILABLE;
  snprintf(info->local_hybrid_reason, sizeof(info->local_hybrid_reason), "%s",
           t->tls_hybrid_reason ? t->tls_hybrid_reason : "not-probed");
  info->verify_peer = t->verifier_initialized;
  const char *name = info->selected_group == PTLS_GROUP_SECP256R1 ? "secp256r1"
                     : info->selected_group == PTLS_GROUP_X25519MLKEM768
                         ? "X25519MLKEM768"
                     : info->selected_group ? "unrecognized"
                                            : "unknown";
  snprintf(info->selected_group_name, sizeof(info->selected_group_name), "%s",
           name);
}
