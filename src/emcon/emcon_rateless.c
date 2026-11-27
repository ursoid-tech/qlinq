#include "emcon_rateless.h"

#include "fec.h"
#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "transport_fec_state.h"
#include "transport_memory.h"

#include <stdlib.h>
#include <string.h>

_Static_assert(QLINQ_EMCON_REPLAY_WINDOW_PACKETS ==
                   QUICLY_FLEXICAST_REPLAY_WINDOW,
               "the manifest replay window must match flexicast");
_Static_assert(
    QLINQ_EMCON_MAX_PACKETS_PER_KEY < (UINT64_C(1) << 31),
    "the entire epoch must fit the packet number reconstruction window");

#define EMCON_PACKET_NUMBER_LENGTH 4U

struct qlinq_emcon_ingress_t {
  quicly_flexicast_flow_t *flow;
};

struct qlinq_emcon_sender_t {
  quicly_flexicast_egress_t egress;
  quicly_flexicast_flow_id_t flow_id;
  uint64_t next_packet_number;
  uint16_t symbol_size;
  uint16_t repair_symbols;
  uint32_t max_record_size;
  fec_t *fec;
  size_t fec_data_symbols;
  uint8_t *slab;
  size_t slab_size;
  const uint8_t **data_blocks;
  uint8_t **repair_blocks;
  uint8_t *tail_symbol;
  uint8_t *wire;
  uint8_t *packet;
  size_t packet_capacity;
};

typedef struct {
  bool active;
  bool keyframe;
  uint64_t latest_symbol_pn;
  uint16_t data_received_count;
  frame_assembler_t assembler;
} qlinq_emcon_receive_object_t;

struct qlinq_emcon_receiver_t {
  uint8_t alias;
  uint16_t symbol_size;
  uint16_t repair_symbols;
  uint32_t max_record_size;
  fec_t *fec;
  size_t fec_data_symbols;
  qlinq_emcon_receive_object_t objects[QLINQ_EMCON_MAX_ACTIVE_OBJECTS];
  struct {
    bool active;
    uint64_t group_id;
    uint64_t object_id;
  } completed[QLINQ_EMCON_COMPLETED_OBJECTS];
  size_t completed_index;
};

static size_t align_up(size_t n) {
  return (n + 7U) & ~(size_t)7U;
}

static bool geometry_valid(uint16_t symbol_size, uint16_t repair_symbols,
                           uint32_t max_record_size) {
  return symbol_size > 0 && symbol_size <= QLINQ_FEC_MAX_SYMBOL_SIZE &&
         repair_symbols > 0 && repair_symbols < QLINQ_FEC_MAX_TOTAL_SYMBOLS &&
         max_record_size > 0 &&
         max_record_size <=
             (size_t)(QLINQ_FEC_MAX_TOTAL_SYMBOLS - repair_symbols) *
                 symbol_size;
}

static quicly_flexicast_flow_id_t encode_flow_id(uint64_t flow_id) {
  uint8_t encoded[8];
  quicly_encode64(encoded, flow_id);
  return quicly_flexicast_flow_id_init(encoded, sizeof(encoded));
}

static int derive_epoch_secret(
    uint8_t *derived, ptls_hash_algorithm_t *hash, uint32_t key_epoch,
    const uint8_t manifest_digest[QLINQ_EMCON_MANIFEST_DIGEST_SIZE],
    const uint8_t *traffic_secret) {
  uint8_t context[4 + QLINQ_EMCON_MANIFEST_DIGEST_SIZE];
  quicly_encode32(context, key_epoch);
  memcpy(context + 4, manifest_digest, QLINQ_EMCON_MANIFEST_DIGEST_SIZE);
  int ret = ptls_hkdf_expand_label(
      hash, derived, hash->digest_size,
      ptls_iovec_init(traffic_secret, hash->digest_size), "qlinq emcon epoch",
      ptls_iovec_init(context, sizeof(context)), NULL);
  ptls_clear_memory(context, sizeof(context));
  return ret;
}

static fec_t *ensure_raptorq(fec_t **fec, size_t *cached_k, size_t data_symbols,
                             size_t repair_symbols, size_t symbol_size) {
  if (*fec && *cached_k == data_symbols &&
      fec_set_parity_symbols(*fec, repair_symbols))
    return *fec;
  fec_destroy(*fec);
  *fec = fec_create_ex(FEC_RAPTORQ, data_symbols, repair_symbols, symbol_size);
  *cached_k = *fec ? data_symbols : 0;
  return *fec;
}

int qlinq_emcon_sender_create(
    qlinq_emcon_sender_t **sender, uint64_t flow_id, uint32_t key_epoch,
    const uint8_t manifest_digest[QLINQ_EMCON_MANIFEST_DIGEST_SIZE],
    uint64_t next_packet_number, uint16_t symbol_size, uint16_t repair_symbols,
    uint32_t max_record_size, const uint8_t *traffic_secret,
    size_t traffic_secret_size) {
  ptls_cipher_suite_t *suite = &ptls_openssl_aes128gcmsha256;
  uint8_t derived[PTLS_MAX_DIGEST_SIZE];
  if (!sender)
    return QLINQ_EMCON_ERR_INVALID;
  *sender = NULL;
  if (flow_id == 0 || key_epoch == 0 || !manifest_digest || !traffic_secret ||
      traffic_secret_size != suite->hash->digest_size ||
      !geometry_valid(symbol_size, repair_symbols, max_record_size))
    return QLINQ_EMCON_ERR_INVALID;
  if (next_packet_number >= QLINQ_EMCON_MAX_PACKETS_PER_KEY)
    return QLINQ_EMCON_ERR_EXHAUSTED;

  qlinq_emcon_sender_t *created = calloc(1, sizeof(*created));
  if (!created)
    return QLINQ_EMCON_ERR_NO_MEMORY;
  created->flow_id = encode_flow_id(flow_id);
  created->next_packet_number = next_packet_number;
  created->symbol_size = symbol_size;
  created->repair_symbols = repair_symbols;
  created->max_record_size = max_record_size;
  created->egress.crypto_engine = &quicly_default_crypto_engine;
  int ret = derive_epoch_secret(derived, suite->hash, key_epoch,
                                manifest_digest, traffic_secret);
  if (ret == 0)
    ret = created->egress.crypto_engine->setup_cipher(
        created->egress.crypto_engine, NULL, QUICLY_EPOCH_1RTT, 1,
        &created->egress.header_protection, &created->egress.aead, suite->aead,
        suite->hash, derived);
  ptls_clear_memory(derived, sizeof(derived));
  if (ret != 0) {
    qlinq_emcon_sender_free(created);
    return QLINQ_EMCON_ERR_CRYPTO;
  }

  size_t max_k = (max_record_size + symbol_size - 1U) / symbol_size;
  size_t wire_cap = QLINQ_WIRE_FEC_HEADER_SIZE + symbol_size;
  size_t pkt_cap = quicly_flexicast_datagram_packet_size(
      &created->egress, &created->flow_id, EMCON_PACKET_NUMBER_LENGTH,
      wire_cap);
  if (pkt_cap == 0) {
    qlinq_emcon_sender_free(created);
    return QLINQ_EMCON_ERR_CRYPTO;
  }
  size_t off_data = 0;
  size_t off_rep_ptrs = off_data + align_up(max_k * sizeof(const uint8_t *));
  size_t off_rep_buf =
      off_rep_ptrs + align_up(repair_symbols * sizeof(uint8_t *));
  size_t off_tail =
      off_rep_buf + align_up((size_t)repair_symbols * symbol_size);
  size_t off_wire = off_tail + align_up(symbol_size);
  size_t off_pkt = off_wire + align_up(wire_cap);
  size_t total_slab = off_pkt + align_up(pkt_cap);
  created->slab = calloc(1, total_slab);
  if (!created->slab) {
    qlinq_emcon_sender_free(created);
    return QLINQ_EMCON_ERR_NO_MEMORY;
  }
  created->slab_size = total_slab;
  created->data_blocks = (const uint8_t **)(created->slab + off_data);
  created->repair_blocks = (uint8_t **)(created->slab + off_rep_ptrs);
  uint8_t *rep_storage = created->slab + off_rep_buf;
  for (size_t i = 0; i < repair_symbols; i++)
    created->repair_blocks[i] = rep_storage + i * symbol_size;
  created->tail_symbol = created->slab + off_tail;
  created->wire = created->slab + off_wire;
  created->packet = created->slab + off_pkt;
  created->packet_capacity = pkt_cap;
  *sender = created;
  return QLINQ_EMCON_OK;
}

void qlinq_emcon_sender_free(qlinq_emcon_sender_t *sender) {
  if (!sender)
    return;
  if (sender->egress.header_protection)
    ptls_cipher_free(sender->egress.header_protection);
  if (sender->egress.aead)
    ptls_aead_free(sender->egress.aead);
  fec_destroy(sender->fec);
  if (sender->slab) {
    ptls_clear_memory(sender->slab, sender->slab_size);
    free(sender->slab);
  }
  free(sender);
}

uint64_t
qlinq_emcon_sender_next_packet_number(const qlinq_emcon_sender_t *sender) {
  return sender ? sender->next_packet_number : 0;
}

bool qlinq_emcon_sender_has_capacity(const qlinq_emcon_sender_t *sender,
                                     uint64_t packets) {
  return sender && packets <= QLINQ_EMCON_MAX_PACKETS_PER_KEY -
                                  sender->next_packet_number;
}

int qlinq_emcon_ingress_create(
    qlinq_emcon_ingress_t **ingress, uint64_t flow_id, uint32_t key_epoch,
    const uint8_t manifest_digest[QLINQ_EMCON_MANIFEST_DIGEST_SIZE],
    uint64_t max_authentication_failures, const uint8_t *traffic_secret,
    size_t traffic_secret_size) {
  ptls_cipher_suite_t *suite = &ptls_openssl_aes128gcmsha256;
  uint8_t derived[PTLS_MAX_DIGEST_SIZE];
  if (!ingress)
    return QLINQ_EMCON_ERR_INVALID;
  *ingress = NULL;
  if (flow_id == 0 || key_epoch == 0 || !manifest_digest || !traffic_secret ||
      traffic_secret_size != suite->hash->digest_size)
    return QLINQ_EMCON_ERR_INVALID;

  qlinq_emcon_ingress_t *created = calloc(1, sizeof(*created));
  if (!created)
    return QLINQ_EMCON_ERR_NO_MEMORY;
  int ret = derive_epoch_secret(derived, suite->hash, key_epoch,
                                manifest_digest, traffic_secret);
  if (ret == 0) {
    quicly_flexicast_config_t cfg = {
        .flow_id = encode_flow_id(flow_id),
        .first_packet_number = 0,
        .cipher_suite = suite,
        .crypto_engine = &quicly_default_crypto_engine,
        .traffic_secret = ptls_iovec_init(derived, suite->hash->digest_size),
        .max_members = 1,
        .max_packets_per_key = QLINQ_EMCON_MAX_PACKETS_PER_KEY,
        .max_authentication_failures = max_authentication_failures,
        .max_packet_size = QUICLY_FLEXICAST_MAX_PACKET_SIZE,
    };
    ret = quicly_flexicast_flow_create(&created->flow, &cfg);
  } else {
    ret = QUICLY_FLEXICAST_ERROR_CRYPTO;
  }
  ptls_clear_memory(derived, sizeof(derived));
  if (ret != QUICLY_FLEXICAST_OK) {
    qlinq_emcon_ingress_free(created);
    return ret == QUICLY_FLEXICAST_ERROR_NO_MEMORY
               ? QLINQ_EMCON_ERR_NO_MEMORY
               : (ret == QUICLY_FLEXICAST_ERROR_INVALID
                      ? QLINQ_EMCON_ERR_INVALID
                      : QLINQ_EMCON_ERR_CRYPTO);
  }
  *ingress = created;
  return QLINQ_EMCON_OK;
}

void qlinq_emcon_ingress_free(qlinq_emcon_ingress_t *ingress) {
  if (!ingress)
    return;
  quicly_flexicast_flow_free(ingress->flow);
  free(ingress);
}

uint64_t qlinq_emcon_ingress_authentication_failures(
    const qlinq_emcon_ingress_t *ingress) {
  quicly_flexicast_crypto_usage_t usage;
  if (!ingress || quicly_flexicast_get_crypto_usage(ingress->flow, &usage) !=
                      QUICLY_FLEXICAST_OK)
    return 0;
  return usage.authentication_failures;
}

int qlinq_emcon_flexicast_seal(qlinq_emcon_sender_t *sender,
                               ptls_iovec_t payload, uint8_t *packet,
                               size_t capacity, size_t *packet_size,
                               uint64_t *packet_number) {
  if (!sender || !packet || !packet_size ||
      (payload.len != 0 && !payload.base) ||
      payload.len > QUICLY_FLEXICAST_MAX_DATAGRAM_SIZE)
    return QLINQ_EMCON_ERR_INVALID;
  if (!qlinq_emcon_sender_has_capacity(sender, 1))
    return QLINQ_EMCON_ERR_EXHAUSTED;
  uint64_t pn = sender->next_packet_number;
  if (quicly_flexicast_encode_datagram_packet(
          &sender->egress, &sender->flow_id, pn, EMCON_PACKET_NUMBER_LENGTH,
          payload, packet, capacity, packet_size) != QUICLY_FLEXICAST_OK)
    return QLINQ_EMCON_ERR_CRYPTO;
  /* consume packet number on protection, before emission */
  sender->next_packet_number = pn + 1;
  if (packet_number)
    *packet_number = pn;
  return QLINQ_EMCON_OK;
}

int qlinq_emcon_seal_end(qlinq_emcon_sender_t *sender, uint8_t alias,
                         uint64_t group_id, uint64_t final_object_id,
                         uint8_t *packet, size_t capacity, size_t *packet_size,
                         uint64_t *packet_number) {
  uint8_t body[QLINQ_WIRE_TRACK_END_SIZE];
  uint8_t frame[QLINQ_WIRE_FRAME_HEADER_SIZE + QLINQ_WIRE_TRACK_END_SIZE];
  size_t frame_len = 0;
  qlinq_wire_track_end_t end = {
      .alias = alias, .group_id = group_id, .final_object_id = final_object_id};
  if (qlinq_wire_encode_track_end(body, sizeof(body), &end) != QLINQ_WIRE_OK ||
      qlinq_wire_encode_frame(frame, sizeof(frame), QLINQ_WIRE_TRACK_END, body,
                              sizeof(body), sizeof(body),
                              &frame_len) != QLINQ_WIRE_OK)
    return QLINQ_EMCON_ERR_INVALID;
  return qlinq_emcon_flexicast_seal(sender, ptls_iovec_init(frame, frame_len),
                                    packet, capacity, packet_size,
                                    packet_number);
}

int qlinq_emcon_flexicast_open(qlinq_emcon_ingress_t *ingress, uint8_t *packet,
                               size_t packet_size, ptls_iovec_t *datagram,
                               uint64_t *packet_number) {
  if (!ingress || !packet || !datagram || !packet_number)
    return QLINQ_EMCON_ERR_INVALID;
  *datagram = ptls_iovec_init(NULL, 0);
  *packet_number = 0;
  size_t count = 1;
  uint64_t pn = 0;
  int ret = quicly_flexicast_receive_datagrams(
      ingress->flow, packet, packet_size, datagram, &count, &pn, 0, 0);
  switch (ret) {
  case QUICLY_FLEXICAST_OK:
    if (count != 1 || pn >= QLINQ_EMCON_MAX_PACKETS_PER_KEY)
      return QLINQ_EMCON_ERR_INVALID;
    *packet_number = pn;
    return QLINQ_EMCON_OK;
  case QUICLY_FLEXICAST_ERROR_REPLAY:
    return QLINQ_EMCON_DUPLICATE;
  case QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED:
    return QLINQ_EMCON_ERR_CRYPTO;
  case QUICLY_FLEXICAST_ERROR_NO_MEMORY:
    return QLINQ_EMCON_ERR_NO_MEMORY;
  case QUICLY_FLEXICAST_ERROR_WRONG_FLOW:
  case QUICLY_FLEXICAST_ERROR_CRYPTO:
  case QUICLY_FLEXICAST_ERROR_INVALID:
    return QLINQ_EMCON_DISCARDED;
  default:
    return QLINQ_EMCON_ERR_INVALID;
  }
}

int qlinq_emcon_send_object(qlinq_emcon_sender_t *sender, uint8_t alias,
                            uint64_t group_id, uint64_t object_id,
                            bool keyframe, uint8_t priority, const void *data,
                            size_t size, qlinq_emcon_emit_packet_cb emit,
                            void *user_data) {
  if (!sender || !data || !emit || size == 0 || size > sender->max_record_size)
    return QLINQ_EMCON_ERR_INVALID;
  size_t sym_size = sender->symbol_size;
  size_t data_symbols = (size + sym_size - 1U) / sym_size;
  size_t total_symbols = data_symbols + sender->repair_symbols;
  if (!qlinq_emcon_sender_has_capacity(sender, total_symbols))
    return QLINQ_EMCON_ERR_EXHAUSTED;

  const uint8_t *bytes = data;
  for (size_t i = 0; i + 1 < data_symbols; i++)
    sender->data_blocks[i] = bytes + i * sym_size;
  size_t tail_off = (data_symbols - 1U) * sym_size;
  size_t tail_len = size - tail_off;
  if (tail_len == sym_size) {
    sender->data_blocks[data_symbols - 1U] = bytes + tail_off;
  } else {
    memcpy(sender->tail_symbol, bytes + tail_off, tail_len);
    memset(sender->tail_symbol + tail_len, 0, sym_size - tail_len);
    sender->data_blocks[data_symbols - 1U] = sender->tail_symbol;
  }

  fec_t *fec = ensure_raptorq(&sender->fec, &sender->fec_data_symbols,
                              data_symbols, sender->repair_symbols, sym_size);
  if (!fec || !fec_encode(fec, sender->data_blocks, sender->repair_blocks))
    return QLINQ_EMCON_ERR_CRYPTO;

  for (size_t emitted = 0; emitted < total_symbols; emitted++) {
    uint16_t symbol_index = (uint16_t)emitted;
    qlinq_wire_fec_header_t header = {
        .alias = alias,
        .is_keyframe = keyframe,
        .priority = priority,
        .group_id = group_id,
        .object_id = object_id,
        .symbol_index = symbol_index,
        .total_symbols = (uint16_t)total_symbols,
        .data_symbols = (uint16_t)data_symbols,
        .symbol_size = sender->symbol_size,
        .original_size = (uint32_t)size,
    };
    size_t sym_payload = qlinq_wire_fec_payload_size(&header);
    size_t wire_len = QLINQ_WIRE_FEC_HEADER_SIZE + sym_payload;
    if (sym_payload == 0 ||
        qlinq_wire_encode_fec_header(sender->wire, wire_len, &header) !=
            QLINQ_WIRE_OK)
      return QLINQ_EMCON_ERR_INVALID;
    const uint8_t *sym =
        emitted < data_symbols
            ? sender->data_blocks[symbol_index]
            : sender->repair_blocks[symbol_index - data_symbols];
    memcpy(sender->wire + QLINQ_WIRE_FEC_HEADER_SIZE, sym, sym_payload);
    size_t packet_size;
    int ret = qlinq_emcon_flexicast_seal(
        sender, ptls_iovec_init(sender->wire, wire_len), sender->packet,
        sender->packet_capacity, &packet_size, NULL);
    if (ret != QLINQ_EMCON_OK)
      return ret;
    if (!emit(user_data, symbol_index, sender->packet, packet_size))
      return QLINQ_EMCON_ERR_EMIT_FAILED;
  }
  return QLINQ_EMCON_OK;
}

qlinq_emcon_receiver_t *qlinq_emcon_receiver_create(uint8_t alias,
                                                    uint16_t symbol_size,
                                                    uint16_t repair_symbols,
                                                    uint32_t max_record_size) {
  if (!geometry_valid(symbol_size, repair_symbols, max_record_size))
    return NULL;
  qlinq_emcon_receiver_t *rx = calloc(1, sizeof(*rx));
  if (!rx)
    return NULL;
  rx->alias = alias;
  rx->symbol_size = symbol_size;
  rx->repair_symbols = repair_symbols;
  rx->max_record_size = max_record_size;
  return rx;
}

void qlinq_emcon_receiver_free(qlinq_emcon_receiver_t *receiver) {
  if (!receiver)
    return;
  for (size_t i = 0; i < QLINQ_EMCON_MAX_ACTIVE_OBJECTS; i++)
    transport_assembler_release(&receiver->objects[i].assembler);
  fec_destroy(receiver->fec);
  free(receiver);
}

typedef struct {
  bool is_end;
  qlinq_wire_fec_header_t fec;
  const uint8_t *symbol;
  size_t symbol_size;
  qlinq_wire_track_end_t end;
} parsed_datagram_t;

static int parse_datagram(ptls_iovec_t datagram, parsed_datagram_t *out) {
  uint8_t type = 0;
  if (!datagram.base || datagram.len < 4)
    return QLINQ_EMCON_ERR_INVALID;
  if (qlinq_wire_decode_datagram_type(datagram.base, datagram.len, &type) ==
          QLINQ_WIRE_OK &&
      type == QLINQ_WIRE_DATAGRAM_FEC) {
    if (qlinq_wire_decode_fec_header(datagram.base, datagram.len, &out->fec) !=
        QLINQ_WIRE_OK)
      return QLINQ_EMCON_ERR_INVALID;
    size_t sym_len = qlinq_wire_fec_payload_size(&out->fec);
    if (sym_len == 0 || datagram.len != QLINQ_WIRE_FEC_HEADER_SIZE + sym_len)
      return QLINQ_EMCON_ERR_INVALID;
    out->is_end = false;
    out->symbol = datagram.base + QLINQ_WIRE_FEC_HEADER_SIZE;
    out->symbol_size = sym_len;
    return QLINQ_EMCON_OK;
  }
  qlinq_wire_frame_t frame;
  if (qlinq_wire_decode_frame(datagram.base, datagram.len,
                              QLINQ_WIRE_TRACK_END_SIZE,
                              &frame) == QLINQ_WIRE_OK &&
      frame.consumed == datagram.len && frame.type == QLINQ_WIRE_TRACK_END &&
      qlinq_wire_decode_track_end(frame.payload, frame.payload_len,
                                  &out->end) == QLINQ_WIRE_OK) {
    out->is_end = true;
    return QLINQ_EMCON_OK;
  }
  return QLINQ_EMCON_ERR_INVALID;
}

int qlinq_emcon_datagram_target(ptls_iovec_t datagram, uint8_t *alias,
                                uint64_t *group_id) {
  parsed_datagram_t parsed;
  if (!alias || !group_id)
    return QLINQ_EMCON_ERR_INVALID;
  int ret = parse_datagram(datagram, &parsed);
  if (ret != QLINQ_EMCON_OK)
    return ret;
  *alias = parsed.is_end ? parsed.end.alias : parsed.fec.alias;
  *group_id = parsed.is_end ? parsed.end.group_id : parsed.fec.group_id;
  return QLINQ_EMCON_OK;
}

static int receiver_start_object(qlinq_emcon_receive_object_t *obj,
                                 const qlinq_emcon_receiver_t *rx,
                                 const qlinq_wire_fec_header_t *hdr) {
  if (hdr->alias != rx->alias || hdr->symbol_size != rx->symbol_size ||
      hdr->data_symbols == 0 || hdr->total_symbols <= hdr->data_symbols ||
      hdr->total_symbols - hdr->data_symbols != rx->repair_symbols ||
      hdr->total_symbols > QLINQ_FEC_MAX_TOTAL_SYMBOLS ||
      hdr->original_size == 0 || hdr->original_size > rx->max_record_size)
    return QLINQ_EMCON_ERR_INVALID;
  obj->active = false;
  obj->assembler.total_symbols = 0;
  if (!transport_assembler_grow(&obj->assembler, hdr->total_symbols,
                                hdr->symbol_size))
    return QLINQ_EMCON_ERR_NO_MEMORY;
  for (size_t i = 0; i < hdr->total_symbols; i++) {
    obj->assembler.buffers[i] =
        obj->assembler.buffer_storage + i * hdr->symbol_size;
    obj->assembler.received_mask[i] = false;
  }
  obj->active = true;
  obj->keyframe = hdr->is_keyframe;
  obj->latest_symbol_pn = 0;
  obj->data_received_count = 0;
  obj->assembler.group_id = hdr->group_id;
  obj->assembler.object_id = hdr->object_id;
  obj->assembler.priority = hdr->priority;
  obj->assembler.total_symbols = hdr->total_symbols;
  obj->assembler.data_symbols = hdr->data_symbols;
  obj->assembler.symbol_size = hdr->symbol_size;
  obj->assembler.original_size = hdr->original_size;
  obj->assembler.received_count = 0;
  return QLINQ_EMCON_OK;
}

int qlinq_emcon_receiver_ingest(qlinq_emcon_receiver_t *receiver,
                                uint64_t packet_number, ptls_iovec_t datagram,
                                qlinq_emcon_event_t *event) {
  parsed_datagram_t parsed;
  if (!receiver || !event)
    return QLINQ_EMCON_ERR_INVALID;
  memset(event, 0, sizeof(*event));
  int ret = parse_datagram(datagram, &parsed);
  if (ret != QLINQ_EMCON_OK)
    return ret;
  if (parsed.is_end) {
    if (parsed.end.alias != receiver->alias)
      return QLINQ_EMCON_ERR_INVALID;
    event->type = QLINQ_EMCON_EVENT_END;
    event->value.end = parsed.end;
    return QLINQ_EMCON_OK;
  }

  const qlinq_wire_fec_header_t *hdr = &parsed.fec;
  for (size_t i = 0; i < QLINQ_EMCON_COMPLETED_OBJECTS; i++)
    if (receiver->completed[i].active &&
        receiver->completed[i].group_id == hdr->group_id &&
        receiver->completed[i].object_id == hdr->object_id)
      return QLINQ_EMCON_DUPLICATE;

  qlinq_emcon_receive_object_t *obj = NULL, *slot = NULL;
  for (size_t i = 0; i < QLINQ_EMCON_MAX_ACTIVE_OBJECTS; i++) {
    qlinq_emcon_receive_object_t *cand = &receiver->objects[i];
    if (cand->active && cand->assembler.group_id == hdr->group_id &&
        cand->assembler.object_id == hdr->object_id) {
      obj = cand;
      break;
    }
    if (!slot || !cand->active ||
        (slot->active && cand->latest_symbol_pn < slot->latest_symbol_pn))
      slot = cand;
  }
  if (!obj) {
    if (slot->active && packet_number <= slot->latest_symbol_pn)
      return QLINQ_EMCON_INCOMPLETE;
    obj = slot;
    ret = receiver_start_object(obj, receiver, hdr);
    if (ret != QLINQ_EMCON_OK)
      return ret;
  } else if (obj->assembler.total_symbols != hdr->total_symbols ||
             obj->assembler.data_symbols != hdr->data_symbols ||
             obj->assembler.symbol_size != hdr->symbol_size ||
             obj->assembler.original_size != hdr->original_size ||
             obj->keyframe != hdr->is_keyframe ||
             obj->assembler.priority != hdr->priority ||
             hdr->alias != receiver->alias) {
    return QLINQ_EMCON_ERR_INVALID;
  }

  frame_assembler_t *a = &obj->assembler;
  if (!a->received_mask[hdr->symbol_index]) {
    memcpy(a->buffers[hdr->symbol_index], parsed.symbol, parsed.symbol_size);
    memset(a->buffers[hdr->symbol_index] + parsed.symbol_size, 0,
           a->symbol_size - parsed.symbol_size);
    a->received_mask[hdr->symbol_index] = true;
    a->received_count++;
    if (hdr->symbol_index < a->data_symbols)
      obj->data_received_count++;
    if (packet_number > obj->latest_symbol_pn)
      obj->latest_symbol_pn = packet_number;
  }
  if (a->received_count < a->data_symbols)
    return QLINQ_EMCON_INCOMPLETE;

  bool decoded = obj->data_received_count == a->data_symbols;
  if (!decoded) {
    for (size_t i = 0; i < a->total_symbols; i++)
      a->missing_mask[i] = !a->received_mask[i];
    fec_t *fec = ensure_raptorq(&receiver->fec, &receiver->fec_data_symbols,
                                a->data_symbols, receiver->repair_symbols,
                                a->symbol_size);
    decoded = fec && fec_decode(fec, a->buffers, a->missing_mask);
  }
  if (!decoded)
    return QLINQ_EMCON_INCOMPLETE;

  uint8_t *data = malloc(a->original_size);
  if (!data)
    return QLINQ_EMCON_ERR_NO_MEMORY;
  memcpy(data, a->buffer_storage, a->original_size);
  event->type = QLINQ_EMCON_EVENT_RECORD;
  event->value.record = (qlinq_emcon_record_t){
      .alias = receiver->alias,
      .group_id = a->group_id,
      .object_id = a->object_id,
      .keyframe = obj->keyframe,
      .priority = a->priority,
      .data = data,
      .size = a->original_size,
  };
  size_t done = receiver->completed_index++ % QLINQ_EMCON_COMPLETED_OBJECTS;
  receiver->completed[done].active = true;
  receiver->completed[done].group_id = a->group_id;
  receiver->completed[done].object_id = a->object_id;
  obj->active = false;
  return QLINQ_EMCON_OK;
}

void qlinq_emcon_record_release(qlinq_emcon_record_t *record) {
  if (!record)
    return;
  free(record->data);
  memset(record, 0, sizeof(*record));
}

void qlinq_emcon_event_release(qlinq_emcon_event_t *event) {
  if (!event)
    return;
  if (event->type == QLINQ_EMCON_EVENT_RECORD)
    qlinq_emcon_record_release(&event->value.record);
  memset(event, 0, sizeof(*event));
}
