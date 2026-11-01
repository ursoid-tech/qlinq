#ifndef QLINQ_TUN_PACKET_H
#define QLINQ_TUN_PACKET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* one ordinary IP packet; storage is borrowed and must outlive view use */
typedef struct {
  const uint8_t *data;
  size_t size;
  size_t header_size; /* IPv4 header with options, or IPv6 base header */
  uint8_t version;
} tun_packet_view_t;

typedef enum {
  TUN_PACKET_FROM_DEVICE,
  TUN_PACKET_FROM_PEER
} tun_packet_origin_t;

typedef enum {
  TUN_PACKET_TO_TRANSPORT,
  TUN_PACKET_TO_DEVICE
} tun_packet_destination_t;

/* explicit host MTU and storage limits for each emitted ordinary IP packet */
typedef struct {
  size_t mtu;
  size_t max_packet_size;
} tun_packet_config_t;

typedef struct {
  const void *data;
  size_t size;
  tun_packet_origin_t origin;
} tun_packet_input_t;

typedef struct {
  tun_packet_view_t packet;
  tun_packet_destination_t destination;
} tun_packet_output_t;

typedef enum {
  TUN_PACKET_OK,
  TUN_PACKET_INVALID,
  TUN_PACKET_OUTPUT_FULL
} tun_packet_status_t;

typedef struct {
  tun_packet_status_t status;
  size_t count;
} tun_packet_result_t;

/* pure ordinary-packet pipeline; validates structure, MTU, and capacity */
tun_packet_result_t tun_packet_process(const tun_packet_config_t *config,
                                       const tun_packet_input_t *input,
                                       tun_packet_output_t *outputs,
                                       size_t output_capacity);

/* validate ordinary IP packet structure and length against max_size */
bool tun_packet_parse(const void *data, size_t size, size_t max_size,
                      tun_packet_view_t *view);

#endif
