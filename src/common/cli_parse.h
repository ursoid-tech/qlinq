#ifndef QLINQ_CLI_PARSE_H
#define QLINQ_CLI_PARSE_H

#include "qlinq.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* fixedrate and fec name the same delivery mode. */
bool cli_parse_delivery(const char *text, qlinq_delivery_t *delivery);
bool cli_parse_track_mode(const char *text, uint8_t *flags);
bool cli_parse_congestion_control(const char *text,
                                  qlinq_congestion_control_t *controller);

static inline bool cli_option_value(int argc, char **argv, int *index,
                                    const char **value) {
  if (*index + 1 >= argc)
    return false;
  *value = argv[++*index];
  return true;
}

bool cli_parse_u64(const char *text, uint64_t maximum, uint64_t *value);
bool cli_parse_u64_base(const char *text, uint64_t maximum, int base,
                        uint64_t *value);

/* Parses HOST, HOST:PORT, [IPv6], or [IPv6]:PORT. The caller supplies the
 * default port; has_port may be NULL when that distinction is unimportant. */
bool cli_parse_endpoint(const char *text, char *host, size_t host_capacity,
                        uint16_t *port, bool *has_port);
bool cli_parse_ip_endpoint(const char *text, int port_base, uint8_t *family,
                           uint8_t address[16], uint16_t *port);

#endif
