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

int qlinq_emcon_flexicast_create(quicly_flexicast_flow_t **flow,
                                 uint64_t flow_id, uint32_t key_epoch,
                                 uint64_t first_packet_number,
                                 const uint8_t *traffic_secret,
                                 size_t traffic_secret_size,
                                 bool allow_untracked_send) {
  ptls_cipher_suite_t *suite = &ptls_openssl_aes128gcmsha256;
  uint8_t epoch_be[4];
  uint8_t derived[PTLS_MAX_DIGEST_SIZE];
  uint8_t flow_id_bytes[8];
  if (!flow || flow_id == 0 || key_epoch == 0 || !traffic_secret ||
      traffic_secret_size != suite->hash->digest_size)
    return QLINQ_EMCON_INVALID;
  *flow = NULL;
  epoch_be[0] = (uint8_t)(key_epoch >> 24);
  epoch_be[1] = (uint8_t)(key_epoch >> 16);
  epoch_be[2] = (uint8_t)(key_epoch >> 8);
  epoch_be[3] = (uint8_t)key_epoch;
  if (ptls_hkdf_expand_label(
          suite->hash, derived, traffic_secret_size,
          ptls_iovec_init(traffic_secret, traffic_secret_size),
          "qlinq emcon epoch", ptls_iovec_init(epoch_be, sizeof(epoch_be)),
          NULL) != 0)
    return QLINQ_EMCON_CRYPTO;
  quicly_encode64(flow_id_bytes, flow_id);
  quicly_flexicast_config_t cfg = {
      .flow_id =
          quicly_flexicast_flow_id_init(flow_id_bytes, sizeof(flow_id_bytes)),
      .first_packet_number = first_packet_number,
      .cipher_suite = suite,
      .crypto_engine = &quicly_default_crypto_engine,
      .traffic_secret = ptls_iovec_init(derived, traffic_secret_size),
      .max_packets_per_key = QLINQ_EMCON_MAX_PACKETS_PER_KEY,
      .max_packet_size = QUICLY_FLEXICAST_MAX_PACKET_SIZE,
      .allow_untracked_send = allow_untracked_send ? 1 : 0,
      .send_packet_number_length = 4,
  };
  int ret = quicly_flexicast_flow_create(flow, &cfg);
  ptls_clear_memory(derived, sizeof(derived));
  return ret == QUICLY_FLEXICAST_OK ? QLINQ_EMCON_OK : QLINQ_EMCON_CRYPTO;
}

int qlinq_emcon_flexicast_seal(quicly_flexicast_flow_t *flow,
                               qlinq_emcon_record_type_t type,
                               ptls_iovec_t payload, uint8_t *packet,
                               size_t capacity, size_t *packet_size,
                               uint64_t *packet_number) {
  uint8_t stack_buf[256];
  uint8_t *framed = stack_buf;
  if (!flow || !packet || !packet_size || !packet_number ||
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
  int ret = quicly_flexicast_send_datagram(
      flow, ptls_iovec_init(framed, framed_len), packet, capacity, packet_size,
      packet_number, 0);
  if (framed != stack_buf)
    free(framed);
  return ret == QUICLY_FLEXICAST_OK ? QLINQ_EMCON_OK : QLINQ_EMCON_CRYPTO;
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
  if (ret != QUICLY_FLEXICAST_OK)
    return QLINQ_EMCON_CRYPTO;
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
  size_t received_count;
  uint8_t *storage;
  uint8_t **blocks;
  bool *received;
  bool *missing;
} qlinq_emcon_receive_object_t;

struct qlinq_emcon_receiver_t {
  quicly_flexicast_flow_t *flow; /* borrowed */
  uint8_t alias;
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

int qlinq_emcon_send_object(quicly_flexicast_flow_t *flow,
                            const qlinq_emcon_rateless_config_t *config,
                            uint64_t group_id, uint64_t object_id,
                            bool keyframe, uint8_t priority, const void *data,
                            size_t size, qlinq_emcon_emit_packet_cb emit,
                            void *user_data) {
  size_t data_symbols, total_symbols, data_index = 0, repair_index = 0;
  uint8_t *data_storage = NULL, *repair_storage = NULL, *wire = NULL,
          *packet = NULL;
  uint8_t **data_blocks = NULL, **repair_blocks = NULL;
  fec_t *fec = NULL;
  int result = QLINQ_EMCON_NO_MEMORY;

  if (!flow || !data || !emit ||
      !sender_config_valid(config, size, &data_symbols))
    return QLINQ_EMCON_INVALID;
  total_symbols = data_symbols + config->repair_symbols;

  data_storage = calloc(data_symbols, config->symbol_size);
  repair_storage = malloc((size_t)config->repair_symbols * config->symbol_size);
  data_blocks = malloc(data_symbols * sizeof(*data_blocks));
  repair_blocks =
      malloc((size_t)config->repair_symbols * sizeof(*repair_blocks));
  size_t framed_size = 1U + QLINQ_WIRE_FEC_HEADER_SIZE + config->symbol_size;
  wire = malloc(framed_size);
  size_t protected_capacity = quicly_flexicast_datagram_size(flow, framed_size);
  packet = protected_capacity != 0 ? malloc(protected_capacity) : NULL;
  if (!data_storage || !repair_storage || !data_blocks || !repair_blocks ||
      !wire || !packet)
    goto Exit;

  memcpy(data_storage, data, size);
  for (size_t i = 0; i < data_symbols; i++)
    data_blocks[i] = data_storage + i * config->symbol_size;
  for (size_t i = 0; i < config->repair_symbols; i++)
    repair_blocks[i] = repair_storage + i * config->symbol_size;

  fec = fec_create_ex(FEC_RAPTORQ, data_symbols, config->repair_symbols,
                      config->symbol_size);
  if (!fec ||
      !fec_encode(fec, (const uint8_t *const *)data_blocks, repair_blocks)) {
    result = QLINQ_EMCON_CODEC;
    goto Exit;
  }

  for (size_t emitted = 0; emitted < total_symbols; emitted++) {
    bool use_data;
    if (data_index == data_symbols) {
      use_data = false;
    } else if (repair_index == config->repair_symbols) {
      use_data = true;
    } else {
      /* Pick the class with less normalized progress. */
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
    wire[0] = (uint8_t)QLINQ_EMCON_RECORD_DATA;
    if (qlinq_wire_encode_fec_header(
            wire + 1, QLINQ_WIRE_FEC_HEADER_SIZE + config->symbol_size,
            &header) != QLINQ_WIRE_OK) {
      result = QLINQ_EMCON_INVALID;
      goto Exit;
    }
    const uint8_t *symbol = use_data
                                ? data_blocks[symbol_index]
                                : repair_blocks[symbol_index - data_symbols];
    memcpy(wire + 1 + QLINQ_WIRE_FEC_HEADER_SIZE, symbol, config->symbol_size);
    size_t packet_size;
    uint64_t packet_number;
    if (quicly_flexicast_send_datagram(flow, ptls_iovec_init(wire, framed_size),
                                       packet, protected_capacity, &packet_size,
                                       &packet_number,
                                       0) != QUICLY_FLEXICAST_OK) {
      result = QLINQ_EMCON_CRYPTO;
      goto Exit;
    }
    (void)packet_number;
    if (!emit(user_data, symbol_index, packet, packet_size)) {
      result = QLINQ_EMCON_EMIT_FAILED;
      goto Exit;
    }
  }
  result = QLINQ_EMCON_OK;

Exit:
  fec_destroy(fec);
  free(packet);
  free(wire);
  free(repair_blocks);
  free(data_blocks);
  free(repair_storage);
  free(data_storage);
  return result;
}

qlinq_emcon_receiver_t *
qlinq_emcon_receiver_create(quicly_flexicast_flow_t *flow, uint8_t alias) {
  if (!flow)
    return NULL;
  qlinq_emcon_receiver_t *receiver = calloc(1, sizeof(*receiver));
  if (!receiver)
    return NULL;
  receiver->flow = flow;
  receiver->alias = alias;
  return receiver;
}

qlinq_emcon_receiver_t *
qlinq_emcon_receiver_create_for_messages(uint8_t alias) {
  qlinq_emcon_receiver_t *receiver = calloc(1, sizeof(*receiver));
  if (receiver)
    receiver->alias = alias;
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
                                 uint8_t expected_alias,
                                 const qlinq_wire_fec_header_t *header) {
  size_t bytes;
  if (header->alias != expected_alias || header->total_symbols == 0 ||
      header->total_symbols > QLINQ_FEC_MAX_TOTAL_SYMBOLS ||
      header->data_symbols == 0 ||
      header->data_symbols >= header->total_symbols ||
      header->symbol_size == 0 ||
      header->symbol_size > QLINQ_FEC_MAX_SYMBOL_SIZE ||
      header->original_size == 0 ||
      header->original_size >
          (uint32_t)header->data_symbols * header->symbol_size)
    return QLINQ_EMCON_INVALID;
  bytes = (size_t)header->total_symbols * header->symbol_size;
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
  qlinq_emcon_receive_object_t *object = NULL, *empty = NULL;
  if (message->payload.len < QLINQ_WIRE_FEC_HEADER_SIZE ||
      qlinq_wire_decode_fec_header(message->payload.base, message->payload.len,
                                   &header) != QLINQ_WIRE_OK ||
      header.symbol_index >= header.total_symbols ||
      message->payload.len != QLINQ_WIRE_FEC_HEADER_SIZE + header.symbol_size)
    return QLINQ_EMCON_INVALID;

  for (size_t i = 0; i < QLINQ_EMCON_COMPLETED_OBJECTS; i++)
    if (receiver->completed[i].active &&
        receiver->completed[i].group_id == header.group_id &&
        receiver->completed[i].object_id == header.object_id)
      return QLINQ_EMCON_DUPLICATE;
  for (size_t i = 0; i < QLINQ_EMCON_MAX_ACTIVE_OBJECTS; i++) {
    if (receiver->objects[i].active &&
        receiver->objects[i].group_id == header.group_id &&
        receiver->objects[i].object_id == header.object_id) {
      object = &receiver->objects[i];
      break;
    }
    if (!receiver->objects[i].active && !empty)
      empty = &receiver->objects[i];
  }
  if (!object) {
    if (!empty)
      return QLINQ_EMCON_BUSY;
    object = empty;
    int started = receiver_start_object(object, receiver->alias, &header);
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
           message->payload.base + QLINQ_WIRE_FEC_HEADER_SIZE,
           object->symbol_size);
    object->received[header.symbol_index] = true;
    object->received_count++;
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

int qlinq_emcon_receiver_ingest_packet(qlinq_emcon_receiver_t *receiver,
                                       uint8_t *packet, size_t packet_size,
                                       qlinq_emcon_event_t *event) {
  qlinq_emcon_message_t message;
  if (!receiver || !receiver->flow || !packet || !event)
    return QLINQ_EMCON_INVALID;
  int opened =
      qlinq_emcon_flexicast_open(receiver->flow, packet, packet_size, &message);
  if (opened != QLINQ_EMCON_OK)
    return opened;
  return qlinq_emcon_receiver_ingest_message(receiver, &message, event);
}

int qlinq_emcon_receiver_ingest(qlinq_emcon_receiver_t *receiver,
                                uint8_t *packet, size_t packet_size,
                                qlinq_emcon_record_t *record) {
  qlinq_emcon_event_t event;
  int ret;
  if (!record)
    return QLINQ_EMCON_INVALID;
  memset(record, 0, sizeof(*record));
  ret =
      qlinq_emcon_receiver_ingest_packet(receiver, packet, packet_size, &event);
  if (ret != QLINQ_EMCON_OK)
    return ret;
  if (event.type != QLINQ_EMCON_EVENT_RECORD)
    return QLINQ_EMCON_INVALID;
  *record = event.value.record;
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
