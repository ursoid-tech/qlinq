#include "emcon_rateless.h"

#include "emcon_manifest.h"
#include "fec.h"
#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "transport_fec_state.h"
#include "transport_wire.h"

#include <stdlib.h>
#include <string.h>

_Static_assert(QLINQ_EMCON_REPLAY_WINDOW_PACKETS ==
                   QUICLY_FLEXICAST_REPLAY_WINDOW,
               "the manifest replay window must match flexicast");
_Static_assert(
    QLINQ_EMCON_MAX_PACKETS_PER_KEY < (UINT64_C(1) << 31),
    "the entire epoch must fit the packet number reconstruction window");

#define EMCON_PACKET_NUMBER_LENGTH 4U

struct qlinq_emcon_sender_t {
  quicly_flexicast_egress_t egress;
  quicly_flexicast_flow_id_t flow_id;
  uint64_t next_packet_number;
  uint64_t packet_number_limit;
  fec_t *fec;
  size_t fec_data_symbols;
  size_t fec_symbol_size;
  const uint8_t **data_blocks;
  size_t data_blocks_capacity;
  uint8_t **repair_blocks;
  size_t repair_blocks_capacity;
  uint8_t *repair_storage;
  size_t repair_storage_capacity;
  uint8_t *tail_symbol;
  size_t tail_symbol_capacity;
  uint8_t *wire;
  size_t wire_capacity;
  uint8_t *packet;
  size_t packet_capacity;
};

static quicly_flexicast_flow_id_t encode_flow_id(uint64_t flow_id) {
  uint8_t encoded[8];
  quicly_encode64(encoded, flow_id);
  return quicly_flexicast_flow_id_init(encoded, sizeof(encoded));
}

static int derive_epoch_secret(uint8_t *derived, ptls_hash_algorithm_t *hash,
                               uint32_t key_epoch,
                               const uint8_t *traffic_secret) {
  uint8_t epoch_be[4];
  quicly_encode32(epoch_be, key_epoch);
  return ptls_hkdf_expand_label(
      hash, derived, hash->digest_size,
      ptls_iovec_init(traffic_secret, hash->digest_size), "qlinq emcon epoch",
      ptls_iovec_init(epoch_be, sizeof(epoch_be)), NULL);
}

int qlinq_emcon_sender_create(qlinq_emcon_sender_t **sender, uint64_t flow_id,
                              uint32_t key_epoch,
                              uint64_t initial_packet_number,
                              uint64_t next_packet_number,
                              const uint8_t *traffic_secret,
                              size_t traffic_secret_size) {
  ptls_cipher_suite_t *suite = &ptls_openssl_aes128gcmsha256;
  uint8_t derived[PTLS_MAX_DIGEST_SIZE];
  if (!sender)
    return QLINQ_EMCON_INVALID;
  *sender = NULL;
  if (flow_id == 0 || key_epoch == 0 || !traffic_secret ||
      traffic_secret_size != suite->hash->digest_size ||
      initial_packet_number > QLINQ_EMCON_MAX_PACKET_NUMBER ||
      next_packet_number < initial_packet_number)
    return QLINQ_EMCON_INVALID;
  uint64_t limit = qlinq_emcon_packet_number_limit(initial_packet_number);
  if (next_packet_number >= limit)
    return QLINQ_EMCON_PACKET_NUMBER_EXHAUSTED;

  qlinq_emcon_sender_t *created = calloc(1, sizeof(*created));
  if (!created)
    return QLINQ_EMCON_NO_MEMORY;
  created->flow_id = encode_flow_id(flow_id);
  created->next_packet_number = next_packet_number;
  created->packet_number_limit = limit;
  created->egress.crypto_engine = &quicly_default_crypto_engine;
  int ret =
      derive_epoch_secret(derived, suite->hash, key_epoch, traffic_secret);
  if (ret == 0)
    ret = created->egress.crypto_engine->setup_cipher(
        created->egress.crypto_engine, NULL, QUICLY_EPOCH_1RTT, 1,
        &created->egress.header_protection, &created->egress.aead, suite->aead,
        suite->hash, derived);
  ptls_clear_memory(derived, sizeof(derived));
  if (ret != 0) {
    qlinq_emcon_sender_free(created);
    return QLINQ_EMCON_CRYPTO;
  }
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
  if (sender->repair_storage) {
    ptls_clear_memory(sender->repair_storage, sender->repair_storage_capacity);
    free(sender->repair_storage);
  }
  if (sender->tail_symbol) {
    ptls_clear_memory(sender->tail_symbol, sender->tail_symbol_capacity);
    free(sender->tail_symbol);
  }
  if (sender->wire) {
    ptls_clear_memory(sender->wire, sender->wire_capacity);
    free(sender->wire);
  }
  if (sender->packet) {
    ptls_clear_memory(sender->packet, sender->packet_capacity);
    free(sender->packet);
  }
  free(sender->data_blocks);
  free(sender->repair_blocks);
  free(sender);
}

uint64_t
qlinq_emcon_sender_next_packet_number(const qlinq_emcon_sender_t *sender) {
  return sender ? sender->next_packet_number : 0;
}

bool qlinq_emcon_sender_has_capacity(const qlinq_emcon_sender_t *sender,
                                     uint64_t packets) {
  return sender &&
         packets <= sender->packet_number_limit - sender->next_packet_number;
}

int qlinq_emcon_flexicast_create(quicly_flexicast_flow_t **flow,
                                 uint64_t flow_id, uint32_t key_epoch,
                                 uint64_t first_packet_number,
                                 const uint8_t *traffic_secret,
                                 size_t traffic_secret_size) {
  ptls_cipher_suite_t *suite = &ptls_openssl_aes128gcmsha256;
  uint8_t derived[PTLS_MAX_DIGEST_SIZE];
  if (!flow)
    return QLINQ_EMCON_INVALID;
  *flow = NULL;
  if (flow_id == 0 || key_epoch == 0 || !traffic_secret ||
      first_packet_number > QLINQ_EMCON_MAX_PACKET_NUMBER ||
      traffic_secret_size != suite->hash->digest_size)
    return QLINQ_EMCON_INVALID;
  if (derive_epoch_secret(derived, suite->hash, key_epoch, traffic_secret) !=
      0) {
    ptls_clear_memory(derived, sizeof(derived));
    return QLINQ_EMCON_CRYPTO;
  }
  quicly_flexicast_config_t cfg = {
      .flow_id = encode_flow_id(flow_id),
      .first_packet_number = first_packet_number,
      .cipher_suite = suite,
      .crypto_engine = &quicly_default_crypto_engine,
      .traffic_secret = ptls_iovec_init(derived, traffic_secret_size),
      .max_packets_per_key = QLINQ_EMCON_MAX_PACKETS_PER_KEY,
      .max_packet_size = QUICLY_FLEXICAST_MAX_PACKET_SIZE,
  };
  int ret = quicly_flexicast_flow_create(flow, &cfg);
  ptls_clear_memory(derived, sizeof(derived));
  return ret == QUICLY_FLEXICAST_OK ? QLINQ_EMCON_OK : QLINQ_EMCON_CRYPTO;
}

static int seal_framed(qlinq_emcon_sender_t *sender, ptls_iovec_t framed,
                       uint8_t *packet, size_t capacity, size_t *packet_size,
                       uint64_t *packet_number) {
  if (!qlinq_emcon_sender_has_capacity(sender, 1))
    return QLINQ_EMCON_PACKET_NUMBER_EXHAUSTED;
  uint64_t pn = sender->next_packet_number;
  if (quicly_flexicast_encode_datagram_packet(
          &sender->egress, &sender->flow_id, pn, EMCON_PACKET_NUMBER_LENGTH,
          framed, packet, capacity, packet_size) != QUICLY_FLEXICAST_OK)
    return QLINQ_EMCON_CRYPTO;
  /* consume packet number on protection, before emission */
  sender->next_packet_number = pn + 1;
  if (packet_number)
    *packet_number = pn;
  return QLINQ_EMCON_OK;
}

int qlinq_emcon_flexicast_seal(qlinq_emcon_sender_t *sender,
                               qlinq_emcon_record_type_t type,
                               ptls_iovec_t payload, uint8_t *packet,
                               size_t capacity, size_t *packet_size,
                               uint64_t *packet_number) {
  uint8_t stack_buf[256];
  uint8_t *framed = stack_buf;
  if (!sender || !packet || !packet_size || !packet_number ||
      (payload.len != 0 && !payload.base) || type < QLINQ_EMCON_RECORD_DATA ||
      type > QLINQ_EMCON_RECORD_ABORT ||
      payload.len > QUICLY_FLEXICAST_MAX_DATAGRAM_SIZE - 1U)
    return QLINQ_EMCON_INVALID;
  size_t framed_len = 1U + payload.len;
  if (framed_len > sizeof(stack_buf)) {
    framed = malloc(framed_len);
    if (!framed)
      return QLINQ_EMCON_NO_MEMORY;
  }
  framed[0] = (uint8_t)type;
  if (payload.len != 0)
    memcpy(framed + 1, payload.base, payload.len);
  int ret = seal_framed(sender, ptls_iovec_init(framed, framed_len), packet,
                        capacity, packet_size, packet_number);
  if (framed != stack_buf)
    free(framed);
  return ret;
}

int qlinq_emcon_flexicast_open(quicly_flexicast_flow_t *flow, uint8_t *packet,
                               size_t packet_size,
                               qlinq_emcon_message_t *message) {
  ptls_iovec_t datagram = {0};
  uint64_t pn = 0;
  if (!flow || !packet || !message)
    return QLINQ_EMCON_INVALID;
  memset(message, 0, sizeof(*message));
  int ret = quicly_flexicast_receive_datagram(flow, packet, packet_size,
                                              &datagram, &pn, 0, 0);
  if (ret == QUICLY_FLEXICAST_ERROR_REPLAY)
    return QLINQ_EMCON_DUPLICATE;
  if (ret == QUICLY_FLEXICAST_ERROR_WRONG_FLOW ||
      ret == QUICLY_FLEXICAST_ERROR_INVALID ||
      ret == QUICLY_FLEXICAST_ERROR_CRYPTO)
    return QLINQ_EMCON_DISCARDED;
  if (ret == QUICLY_FLEXICAST_ERROR_NO_MEMORY)
    return QLINQ_EMCON_NO_MEMORY;
  if (ret != QUICLY_FLEXICAST_OK)
    return QLINQ_EMCON_CRYPTO;
  uint64_t epoch_start = quicly_flexicast_get_next_packet_number(flow);
  uint64_t epoch_limit = qlinq_emcon_packet_number_limit(epoch_start);
  if (((packet[0] & 0x3U) + 1U) != EMCON_PACKET_NUMBER_LENGTH ||
      pn < epoch_start || pn >= epoch_limit)
    return QLINQ_EMCON_INVALID;
  if (datagram.len < 1U || datagram.base[0] < QLINQ_EMCON_RECORD_DATA ||
      datagram.base[0] > QLINQ_EMCON_RECORD_ABORT)
    return QLINQ_EMCON_INVALID;
  message->type = (qlinq_emcon_record_type_t)datagram.base[0];
  message->packet_number = pn;
  message->payload = ptls_iovec_init(datagram.base + 1, datagram.len - 1U);
  return QLINQ_EMCON_OK;
}

typedef struct {
  bool active;
  uint64_t group_id;
  uint64_t object_id;
  bool keyframe;
  uint8_t priority;
  uint16_t total_symbols;
  uint16_t data_symbols;
  uint16_t symbol_size;
  uint32_t original_size;
  uint64_t latest_symbol_pn;
  size_t received_count;
  uint8_t *storage;
  uint8_t **blocks;
  bool *received;
  bool *missing;
} qlinq_emcon_receive_object_t;

struct qlinq_emcon_receiver_t {
  uint8_t alias;
  uint32_t max_record_size;
  qlinq_emcon_receive_object_t objects[QLINQ_EMCON_MAX_ACTIVE_OBJECTS];
  struct {
    bool active;
    uint64_t group_id;
    uint64_t object_id;
  } completed[QLINQ_EMCON_COMPLETED_OBJECTS];
  size_t completed_index;
};

static void receiver_clear_object(qlinq_emcon_receive_object_t *object) {
  free(object->storage);
  free(object->blocks);
  free(object->received);
  free(object->missing);
  memset(object, 0, sizeof(*object));
}

static bool sender_config_valid(const qlinq_emcon_rateless_config_t *config,
                                size_t size, size_t *data_symbols) {
  if (!config || config->symbol_size == 0 ||
      config->symbol_size > QLINQ_FEC_MAX_SYMBOL_SIZE ||
      config->repair_symbols == 0 || size == 0 || size > UINT32_MAX)
    return false;
  *data_symbols = (size + config->symbol_size - 1) / config->symbol_size;
  return *data_symbols > 0 &&
         *data_symbols + config->repair_symbols <= QLINQ_FEC_MAX_TOTAL_SYMBOLS;
}

static bool ensure_sender_buffer(void **buffer, size_t *capacity,
                                 size_t required) {
  if (*capacity >= required)
    return true;
  if (*buffer) {
    ptls_clear_memory(*buffer, *capacity);
    free(*buffer);
    *buffer = NULL;
    *capacity = 0;
  }
  void *allocated = malloc(required);
  if (!allocated)
    return false;
  *buffer = allocated;
  *capacity = required;
  return true;
}

static bool ensure_sender_pointers(void **array, size_t *capacity,
                                   size_t count) {
  if (*capacity >= count)
    return true;
  if (count > SIZE_MAX / sizeof(void *))
    return false;
  void *grown = realloc(*array, count * sizeof(void *));
  if (!grown)
    return false;
  *array = grown;
  *capacity = count;
  return true;
}

static fec_t *ensure_sender_fec(qlinq_emcon_sender_t *sender,
                                size_t data_symbols, size_t repair_symbols,
                                size_t symbol_size) {
  if (sender->fec && sender->fec_data_symbols == data_symbols &&
      sender->fec_symbol_size == symbol_size &&
      fec_set_parity_symbols(sender->fec, repair_symbols))
    return sender->fec;
  fec_destroy(sender->fec);
  sender->fec = NULL;
  sender->fec_data_symbols = 0;
  sender->fec_symbol_size = 0;
  sender->fec =
      fec_create_ex(FEC_RAPTORQ, data_symbols, repair_symbols, symbol_size);
  if (sender->fec) {
    sender->fec_data_symbols = data_symbols;
    sender->fec_symbol_size = symbol_size;
  }
  return sender->fec;
}

int qlinq_emcon_send_object(qlinq_emcon_sender_t *sender,
                            const qlinq_emcon_rateless_config_t *config,
                            uint64_t group_id, uint64_t object_id,
                            bool keyframe, uint8_t priority, const void *data,
                            size_t size, qlinq_emcon_emit_packet_cb emit,
                            void *user_data) {
  size_t data_symbols, total_symbols, data_index = 0, repair_index = 0;

  if (!sender || !data || !emit ||
      !sender_config_valid(config, size, &data_symbols))
    return QLINQ_EMCON_INVALID;
  total_symbols = data_symbols + config->repair_symbols;
  if (!qlinq_emcon_sender_has_capacity(sender, total_symbols))
    return QLINQ_EMCON_PACKET_NUMBER_EXHAUSTED;

  size_t max_framed_size =
      1U + QLINQ_WIRE_FEC_HEADER_SIZE + config->symbol_size;
  size_t protected_capacity = quicly_flexicast_datagram_packet_size(
      &sender->egress, &sender->flow_id, EMCON_PACKET_NUMBER_LENGTH,
      max_framed_size);
  if (protected_capacity == 0)
    return QLINQ_EMCON_CRYPTO;
  if (!ensure_sender_pointers((void **)&sender->data_blocks,
                              &sender->data_blocks_capacity, data_symbols) ||
      !ensure_sender_pointers((void **)&sender->repair_blocks,
                              &sender->repair_blocks_capacity,
                              config->repair_symbols) ||
      !ensure_sender_buffer(
          (void **)&sender->repair_storage, &sender->repair_storage_capacity,
          (size_t)config->repair_symbols * config->symbol_size) ||
      !ensure_sender_buffer((void **)&sender->tail_symbol,
                            &sender->tail_symbol_capacity,
                            config->symbol_size) ||
      !ensure_sender_buffer((void **)&sender->wire, &sender->wire_capacity,
                            max_framed_size) ||
      !ensure_sender_buffer((void **)&sender->packet, &sender->packet_capacity,
                            protected_capacity))
    return QLINQ_EMCON_NO_MEMORY;

  const uint8_t *bytes = data;
  for (size_t i = 0; i + 1 < data_symbols; i++)
    sender->data_blocks[i] = bytes + i * config->symbol_size;
  size_t tail_offset = (data_symbols - 1) * config->symbol_size;
  size_t tail_size = size - tail_offset;
  if (tail_size == config->symbol_size) {
    sender->data_blocks[data_symbols - 1] = bytes + tail_offset;
  } else {
    memcpy(sender->tail_symbol, bytes + tail_offset, tail_size);
    memset(sender->tail_symbol + tail_size, 0, config->symbol_size - tail_size);
    sender->data_blocks[data_symbols - 1] = sender->tail_symbol;
  }
  for (size_t i = 0; i < config->repair_symbols; i++)
    sender->repair_blocks[i] = sender->repair_storage + i * config->symbol_size;

  fec_t *fec = ensure_sender_fec(sender, data_symbols, config->repair_symbols,
                                 config->symbol_size);
  if (!fec || !fec_encode(fec, sender->data_blocks, sender->repair_blocks))
    return QLINQ_EMCON_CODEC;

  for (size_t emitted = 0; emitted < total_symbols; emitted++) {
    bool use_data;
    if (data_index == data_symbols) {
      use_data = false;
    } else if (repair_index == config->repair_symbols) {
      use_data = true;
    } else {
      /* pick class with less normalized progress */
      use_data = (data_index + 1) * (size_t)config->repair_symbols <=
                 (repair_index + 1) * data_symbols;
    }
    uint16_t symbol_index = use_data
                                ? (uint16_t)data_index++
                                : (uint16_t)(data_symbols + repair_index++);
    qlinq_wire_fec_header_t header = {
        .alias = config->alias,
        .is_keyframe = keyframe,
        .priority = priority,
        .path_id = 0,
        .group_id = group_id,
        .object_id = object_id,
        .symbol_index = symbol_index,
        .total_symbols = (uint16_t)total_symbols,
        .data_symbols = (uint16_t)data_symbols,
        .symbol_size = config->symbol_size,
        .original_size = (uint32_t)size,
        .send_time_ns = 0,
    };
    size_t symbol_payload_size = qlinq_wire_fec_payload_size(&header);
    if (symbol_payload_size == 0)
      return QLINQ_EMCON_INVALID;
    size_t framed_size = 1U + QLINQ_WIRE_FEC_HEADER_SIZE + symbol_payload_size;
    sender->wire[0] = (uint8_t)QLINQ_EMCON_RECORD_DATA;
    if (qlinq_wire_encode_fec_header(
            sender->wire + 1, QLINQ_WIRE_FEC_HEADER_SIZE + symbol_payload_size,
            &header) != QLINQ_WIRE_OK)
      return QLINQ_EMCON_INVALID;
    const uint8_t *symbol =
        use_data ? sender->data_blocks[symbol_index]
                 : sender->repair_blocks[symbol_index - data_symbols];
    memcpy(sender->wire + 1 + QLINQ_WIRE_FEC_HEADER_SIZE, symbol,
           symbol_payload_size);
    size_t packet_size;
    int result = seal_framed(sender, ptls_iovec_init(sender->wire, framed_size),
                             sender->packet, sender->packet_capacity,
                             &packet_size, NULL);
    if (result != QLINQ_EMCON_OK)
      return result;
    if (!emit(user_data, symbol_index, sender->packet, packet_size))
      return QLINQ_EMCON_EMIT_FAILED;
  }
  return QLINQ_EMCON_OK;
}

qlinq_emcon_receiver_t *qlinq_emcon_receiver_create(uint8_t alias,
                                                    uint32_t max_record_size) {
  if (max_record_size == 0)
    return NULL;
  qlinq_emcon_receiver_t *receiver = calloc(1, sizeof(*receiver));
  if (!receiver)
    return NULL;
  receiver->alias = alias;
  receiver->max_record_size = max_record_size;
  return receiver;
}

void qlinq_emcon_receiver_free(qlinq_emcon_receiver_t *receiver) {
  if (!receiver)
    return;
  for (size_t i = 0; i < QLINQ_EMCON_MAX_ACTIVE_OBJECTS; i++)
    receiver_clear_object(&receiver->objects[i]);
  free(receiver);
}

static int receiver_start_object(qlinq_emcon_receive_object_t *object,
                                 const qlinq_emcon_receiver_t *receiver,
                                 const qlinq_wire_fec_header_t *header) {
  size_t bytes;
  if (header->alias != receiver->alias || header->total_symbols == 0 ||
      header->total_symbols > QLINQ_FEC_MAX_TOTAL_SYMBOLS ||
      header->data_symbols == 0 ||
      header->data_symbols >= header->total_symbols ||
      header->symbol_size == 0 ||
      header->symbol_size > QLINQ_FEC_MAX_SYMBOL_SIZE ||
      header->original_size == 0 ||
      header->original_size > receiver->max_record_size ||
      qlinq_wire_fec_payload_size(header) == 0)
    return QLINQ_EMCON_INVALID;
  bytes = (size_t)header->total_symbols * header->symbol_size;
  if (object->active)
    receiver_clear_object(object);
  object->storage = calloc(1, bytes);
  object->blocks =
      malloc((size_t)header->total_symbols * sizeof(*object->blocks));
  object->received = calloc(header->total_symbols, sizeof(*object->received));
  object->missing =
      malloc((size_t)header->total_symbols * sizeof(*object->missing));
  if (!object->storage || !object->blocks || !object->received ||
      !object->missing) {
    receiver_clear_object(object);
    return QLINQ_EMCON_NO_MEMORY;
  }
  for (size_t i = 0; i < header->total_symbols; i++)
    object->blocks[i] = object->storage + i * header->symbol_size;
  object->active = true;
  object->group_id = header->group_id;
  object->object_id = header->object_id;
  object->keyframe = header->is_keyframe;
  object->priority = header->priority;
  object->total_symbols = header->total_symbols;
  object->data_symbols = header->data_symbols;
  object->symbol_size = header->symbol_size;
  object->original_size = header->original_size;
  return QLINQ_EMCON_OK;
}

static int receiver_complete(qlinq_emcon_receiver_t *receiver,
                             qlinq_emcon_receive_object_t *object,
                             qlinq_emcon_record_t *record) {
  bool all_data = true, decoded = false;
  fec_t *fec = NULL;
  for (size_t i = 0; i < object->data_symbols; i++)
    all_data &= object->received[i];
  if (all_data) {
    decoded = true;
  } else {
    for (size_t i = 0; i < object->total_symbols; i++)
      object->missing[i] = !object->received[i];
    fec = fec_create_ex(FEC_RAPTORQ, object->data_symbols,
                        object->total_symbols - object->data_symbols,
                        object->symbol_size);
    decoded = fec && fec_decode(fec, object->blocks, object->missing);
  }
  fec_destroy(fec);
  if (!decoded)
    return QLINQ_EMCON_INCOMPLETE;

  uint8_t *data = malloc(object->original_size);
  if (!data)
    return QLINQ_EMCON_NO_MEMORY;
  size_t remaining = object->original_size;
  for (size_t i = 0; i < object->data_symbols && remaining; i++) {
    size_t chunk =
        remaining < object->symbol_size ? remaining : object->symbol_size;
    memcpy(data + i * object->symbol_size, object->blocks[i], chunk);
    remaining -= chunk;
  }
  *record = (qlinq_emcon_record_t){
      .alias = receiver->alias,
      .group_id = object->group_id,
      .object_id = object->object_id,
      .keyframe = object->keyframe,
      .priority = object->priority,
      .data = data,
      .size = object->original_size,
  };
  size_t completed =
      receiver->completed_index++ % QLINQ_EMCON_COMPLETED_OBJECTS;
  receiver->completed[completed].active = true;
  receiver->completed[completed].group_id = object->group_id;
  receiver->completed[completed].object_id = object->object_id;
  receiver_clear_object(object);
  return QLINQ_EMCON_OK;
}

static int receiver_ingest_data(qlinq_emcon_receiver_t *receiver,
                                const qlinq_emcon_message_t *message,
                                qlinq_emcon_record_t *record) {
  qlinq_wire_fec_header_t header;
  qlinq_emcon_receive_object_t *object = NULL, *slot = NULL;
  size_t payload_size;
  if (message->payload.len < QLINQ_WIRE_FEC_HEADER_SIZE ||
      qlinq_wire_decode_fec_header(message->payload.base, message->payload.len,
                                   &header) != QLINQ_WIRE_OK ||
      (payload_size = qlinq_wire_fec_payload_size(&header)) == 0 ||
      message->payload.len != QLINQ_WIRE_FEC_HEADER_SIZE + payload_size)
    return QLINQ_EMCON_INVALID;

  for (size_t i = 0; i < QLINQ_EMCON_COMPLETED_OBJECTS; i++)
    if (receiver->completed[i].active &&
        receiver->completed[i].group_id == header.group_id &&
        receiver->completed[i].object_id == header.object_id)
      return QLINQ_EMCON_DUPLICATE;
  for (size_t i = 0; i < QLINQ_EMCON_MAX_ACTIVE_OBJECTS; i++) {
    qlinq_emcon_receive_object_t *candidate = &receiver->objects[i];
    if (candidate->active && candidate->group_id == header.group_id &&
        candidate->object_id == header.object_id) {
      object = candidate;
      break;
    }
    if (!slot || !candidate->active ||
        (slot->active && candidate->latest_symbol_pn < slot->latest_symbol_pn))
      slot = candidate;
  }
  if (!object) {
    /* under pressure, keep objects with the most recent useful symbols */
    if (slot->active && message->packet_number <= slot->latest_symbol_pn)
      return QLINQ_EMCON_INCOMPLETE;
    object = slot;
    int started = receiver_start_object(object, receiver, &header);
    if (started != QLINQ_EMCON_OK)
      return started;
  } else if (object->total_symbols != header.total_symbols ||
             object->data_symbols != header.data_symbols ||
             object->symbol_size != header.symbol_size ||
             object->original_size != header.original_size ||
             object->keyframe != header.is_keyframe ||
             object->priority != header.priority ||
             header.alias != receiver->alias) {
    return QLINQ_EMCON_INVALID;
  }

  if (!object->received[header.symbol_index]) {
    memcpy(object->blocks[header.symbol_index],
           message->payload.base + QLINQ_WIRE_FEC_HEADER_SIZE, payload_size);
    memset(object->blocks[header.symbol_index] + payload_size, 0,
           object->symbol_size - payload_size);
    object->received[header.symbol_index] = true;
    object->received_count++;
    if (message->packet_number > object->latest_symbol_pn)
      object->latest_symbol_pn = message->packet_number;
  }
  if (object->received_count < object->data_symbols)
    return QLINQ_EMCON_INCOMPLETE;
  return receiver_complete(receiver, object, record);
}

int qlinq_emcon_receiver_ingest_message(qlinq_emcon_receiver_t *receiver,
                                        const qlinq_emcon_message_t *message,
                                        qlinq_emcon_event_t *event) {
  int decoded;
  if (!receiver || !message || !event)
    return QLINQ_EMCON_INVALID;
  memset(event, 0, sizeof(*event));
  switch (message->type) {
  case QLINQ_EMCON_RECORD_DATA:
    decoded = receiver_ingest_data(receiver, message, &event->value.record);
    if (decoded == QLINQ_EMCON_OK)
      event->type = QLINQ_EMCON_EVENT_RECORD;
    return decoded;
  case QLINQ_EMCON_RECORD_SESSION:
    decoded = qlinq_emcon_decode_session(
        message->payload.base, message->payload.len, &event->value.session);
    event->type = decoded == QLINQ_EMCON_METADATA_OK ? QLINQ_EMCON_EVENT_SESSION
                                                     : QLINQ_EMCON_EVENT_NONE;
    break;
  case QLINQ_EMCON_RECORD_WINDOW:
    decoded = qlinq_emcon_decode_window(
        message->payload.base, message->payload.len, &event->value.window);
    if (decoded == QLINQ_EMCON_METADATA_OK &&
        event->value.window.alias != receiver->alias)
      decoded = QLINQ_EMCON_METADATA_INVALID;
    event->type = decoded == QLINQ_EMCON_METADATA_OK ? QLINQ_EMCON_EVENT_WINDOW
                                                     : QLINQ_EMCON_EVENT_NONE;
    break;
  case QLINQ_EMCON_RECORD_END:
    decoded = qlinq_emcon_decode_end(message->payload.base,
                                     message->payload.len, &event->value.end);
    if (decoded == QLINQ_EMCON_METADATA_OK &&
        event->value.end.alias != receiver->alias)
      decoded = QLINQ_EMCON_METADATA_INVALID;
    event->type = decoded == QLINQ_EMCON_METADATA_OK ? QLINQ_EMCON_EVENT_END
                                                     : QLINQ_EMCON_EVENT_NONE;
    break;
  case QLINQ_EMCON_RECORD_ABORT:
    decoded = qlinq_emcon_decode_abort(
        message->payload.base, message->payload.len, &event->value.abort);
    event->type = decoded == QLINQ_EMCON_METADATA_OK ? QLINQ_EMCON_EVENT_ABORT
                                                     : QLINQ_EMCON_EVENT_NONE;
    break;
  default:
    return QLINQ_EMCON_INVALID;
  }
  return decoded == QLINQ_EMCON_METADATA_OK ? QLINQ_EMCON_OK
                                            : QLINQ_EMCON_INVALID;
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
