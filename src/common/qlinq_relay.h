#ifndef QLINQ_RELAY_H
#define QLINQ_RELAY_H
#include <stddef.h>
#include <stdint.h>

/* transparent classic AMT host; no qlinq sessions, group keys, or FEC state;
 * single service thread; linux native capture requires CAP_NET_RAW */
typedef struct qlinq_relay qlinq_relay_t;
typedef struct {
  const char *bind_address;       /* numeric IP; NULL: 0.0.0.0 */
  uint16_t port;                  /* 0: 2268 */
  const char *upstream_interface; /* linux interface name, required */
  uint32_t path_mtu;              /* 0: 1500; native PMTU feedback enabled */
  unsigned max_clients;           /* 0: 64; maximum 1024 */
  unsigned max_groups;            /* 0: 1024; maximum 4096 */
  unsigned max_sources;           /* 0: 4096; maximum 65536 */
  unsigned linux_gateway_family;  /* 0: RFC 7450, or linux compatibility 4/6 */
} qlinq_relay_config_t;
typedef struct {
  uint64_t packets_sent, input_drops, send_errors, mtu_drops;
  uint64_t captured, filtered, upstream_errors;
  size_t clients, groups, sources, queued_inputs;
} qlinq_relay_stats_t;
qlinq_relay_t *qlinq_relay_open(const qlinq_relay_config_t *);
/* service at most 64 control and 64 native packets, then flush bounded fanout;
 * timeout_ms is the maximum poll wait (>=0); returns 0, or -1 with errno */
int qlinq_relay_service(qlinq_relay_t *, int timeout_ms);
void qlinq_relay_get_stats(const qlinq_relay_t *, qlinq_relay_stats_t *);
void qlinq_relay_close(qlinq_relay_t *);
#endif
