/* backend selection and QUIC packet-protection interoperability */
#include "transport_internal.h"
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

/* Force an unsupported CPU through the real TLS policy without changing
 * production detection or introducing a runtime override. */
#if QLINQ_WITH_FUSION
#define __builtin_cpu_supports(feature) 0
#define transport_tls_configure_crypto_backend configure_unsupported_cpu
#define transport_tls_load_certificate_and_key unused_load_certificate
#define transport_tls_init_insecure_verifier unused_init_verifier
#include "../../src/common/transport_tls.c"
#undef transport_tls_init_insecure_verifier
#undef transport_tls_load_certificate_and_key
#undef transport_tls_configure_crypto_backend
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
  CHECK(unsetenv("QLINQ_CRYPTO_BACKEND") == 0);
  transport_t *t = create_endpoint();
  CHECK(t && t->tls_ctx.cipher_suites == ptls_openssl_cipher_suites);
  CHECK(strstr(crypto_log, "backend=openssl requested=openssl fallback=none"));
  transport_destroy(t);

  CHECK(setenv("QLINQ_CRYPTO_BACKEND", "openssl", 1) == 0);
  t = create_endpoint();
  CHECK(t && t->tls_ctx.cipher_suites == ptls_openssl_cipher_suites);
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
#else
  CHECK(t->tls_ctx.cipher_suites == ptls_openssl_cipher_suites);
  CHECK(strstr(crypto_log, "fallback=not-built"));
#endif
  if (t->tls_ctx.cipher_suites == ptls_openssl_cipher_suites) {
    CHECK(strstr(crypto_log, "backend=openssl requested=fusion fallback="));
    CHECK(!strstr(crypto_log, "fallback=none"));
  } else {
    CHECK(strstr(crypto_log, "backend=fusion requested=fusion fallback=none"));
  }
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
  CHECK(strstr(crypto_log,
               "backend=openssl requested=fusion fallback=cpu-unsupported"));
#endif
  transport_destroy(t);
  CHECK(check_mixed_peers_and_key_updates() == 0);
  puts("===CRYPTO BACKENDS OK===");
  return 0;
}
