#include "cli_parse.h"
#include "transport.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

bool cli_parse_delivery(const char *text, qlinq_delivery_t *delivery) {
  if (!text || !delivery)
    return false;
  if (strcmp(text, "datagram") == 0)
    *delivery = QLINQ_DELIVERY_DATAGRAM;
  else if (strcmp(text, "reliable") == 0)
    *delivery = QLINQ_DELIVERY_RELIABLE;
  else if (strcmp(text, "fixedrate") == 0 || strcmp(text, "fec") == 0)
    *delivery = QLINQ_DELIVERY_FIXEDRATE;
  else if (strcmp(text, "rateless") == 0)
    *delivery = QLINQ_DELIVERY_RATELESS;
  else
    return false;
  return true;
}

bool cli_parse_track_mode(const char *text, uint8_t *flags) {
  qlinq_delivery_t delivery;
  if (!flags || !cli_parse_delivery(text, &delivery))
    return false;
  switch (delivery) {
  case QLINQ_DELIVERY_DATAGRAM:
    *flags = 0;
    break;
  case QLINQ_DELIVERY_RELIABLE:
    *flags = MOQ_TRACK_FLAG_RELIABLE;
    break;
  case QLINQ_DELIVERY_FIXEDRATE:
    *flags = MOQ_TRACK_FLAG_FEC_ENABLED;
    break;
  case QLINQ_DELIVERY_RATELESS:
    *flags = MOQ_TRACK_FLAG_FEC_RATELESS;
    break;
  }
  return true;
}

bool cli_parse_congestion_control(const char *text,
                                  qlinq_congestion_control_t *controller) {
  if (!text || !controller)
    return false;
  if (strcmp(text, "default") == 0)
    *controller = QLINQ_CC_DEFAULT;
  else if (strcmp(text, "reno") == 0)
    *controller = QLINQ_CC_RENO;
  else if (strcmp(text, "pico") == 0)
    *controller = QLINQ_CC_PICO;
  else if (strcmp(text, "cubic") == 0)
    *controller = QLINQ_CC_CUBIC;
  else if (strcmp(text, "bbr") == 0)
    *controller = QLINQ_CC_BBR;
  else
    return false;
  return true;
}

bool cli_parse_u64_base(const char *text, uint64_t maximum, int base,
                        uint64_t *value) {
  char *end = NULL;
  if (!text || !text[0] || text[0] < '0' || text[0] > '9' || !value)
    return false;
  errno = 0;
  unsigned long long parsed = strtoull(text, &end, base);
  if (errno != 0 || !end || *end != '\0' || parsed > maximum)
    return false;
  *value = (uint64_t)parsed;
  return true;
}

bool cli_parse_u64(const char *text, uint64_t maximum, uint64_t *value) {
  return cli_parse_u64_base(text, maximum, 10, value);
}

static bool split_endpoint_host_port(const char *text, char *host,
                                     size_t host_capacity,
                                     const char **port_out, bool *bracketed) {
  if (!text || !text[0] || !host || host_capacity == 0)
    return false;
  const char *start = text, *port_text = NULL;
  size_t host_size = strlen(text);
  if (bracketed)
    *bracketed = text[0] == '[';
  if (text[0] == '[') {
    const char *closing = strchr(text + 1, ']');
    if (!closing || (closing[1] != '\0' && closing[1] != ':'))
      return false;
    start = text + 1;
    host_size = (size_t)(closing - start);
    if (closing[1] == ':')
      port_text = closing + 2;
  } else {
    const char *first_colon = strchr(text, ':');
    if (first_colon && first_colon == strrchr(text, ':')) {
      host_size = (size_t)(first_colon - text);
      port_text = first_colon + 1;
    }
  }
  if (host_size == 0 || host_size >= host_capacity)
    return false;
  memcpy(host, start, host_size);
  host[host_size] = '\0';
  *port_out = port_text;
  return true;
}

bool cli_parse_endpoint(const char *text, char *host, size_t host_capacity,
                        uint16_t *port, bool *has_port) {
  const char *port_text = NULL;
  if (!port ||
      !split_endpoint_host_port(text, host, host_capacity, &port_text, NULL))
    return false;
  if (has_port)
    *has_port = port_text != NULL;
  if (port_text) {
    uint64_t parsed;
    if (!cli_parse_u64(port_text, UINT16_MAX, &parsed) || parsed == 0)
      return false;
    *port = (uint16_t)parsed;
  }
  return true;
}

bool cli_parse_ip_endpoint(const char *text, int port_base, uint8_t *family,
                           uint8_t address[16], uint16_t *port) {
  char host[INET6_ADDRSTRLEN];
  const char *port_text = NULL;
  bool bracketed = false;
  uint64_t parsed_port = 0;
  if (!family || !address || !port ||
      !split_endpoint_host_port(text, host, sizeof(host), &port_text,
                                &bracketed) ||
      !port_text ||
      !cli_parse_u64_base(port_text, UINT16_MAX, port_base, &parsed_port) ||
      parsed_port == 0)
    return false;
  memset(address, 0, 16);
  if (inet_pton(bracketed ? AF_INET6 : AF_INET, host, address) != 1)
    return false;
  *family = bracketed ? 6U : 4U;
  *port = (uint16_t)parsed_port;
  return true;
}
