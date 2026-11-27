#ifndef QLINQ_RELAY_H
#define QLINQ_RELAY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* transparent AMT and AMTQ relay host; no qlinq sessions, group keys, or FEC
 * state; single service thread; linux native capture requires CAP_NET_RAW */
typedef struct qlinq_relay qlinq_relay_t;
typedef struct {
  const char *bind_address; /* numeric IP; NULL: 0.0.0.0 */
  uint16_t port;            /* classic AMT UDP port; 0: 2268 */
  bool disable_classic_amt; /* true: serve AMTQ only (no UDP 2268) */
  uint16_t amtq_port; /* AMTQ UDP port; >0 enables AMTQ (0: 2269 if classic
                         disabled) */
  const char *amtq_cert_file;     /* required when AMTQ is enabled */
  const char *amtq_key_file;      /* required when AMTQ is enabled */
  const char *amtq_ca_file;       /* optional client CA; enables client mTLS */
  bool amtq_disable_reliable;     /* true: offer AMTQ datagram mode only */
  const char *upstream_interface; /* linux interface name, required */
  uint32_t path_mtu;              /* 0: 1500; native PMTU feedback enabled */
  unsigned max_clients;           /* 0: 64; maximum 1024 */
  unsigned max_groups;            /* 0: 1024; maximum 4096 */
  unsigned max_sources;           /* 0: 4096; maximum 65535 */
  unsigned linux_gateway_family;  /* 0: RFC 7450, or linux compatibility 4/6 */
} qlinq_relay_config_t;
typedef struct {
  uint64_t packets_sent, input_drops, send_errors, mtu_drops;
  uint64_t captured, filtered, upstream_errors;
  uint64_t amtq_packets_sent, amtq_datagrams, amtq_reliable_blocks;
  uint64_t amtq_input_drops, amtq_send_errors, amtq_backpressure;
  uint64_t amtq_session_errors, amtq_policy_errors;
  size_t clients, amtq_clients, groups, sources, queued_inputs;
  size_t amtq_buffered_packets, amtq_buffered_bytes;
} qlinq_relay_stats_t;
qlinq_relay_t *qlinq_relay_open(const qlinq_relay_config_t *);
/* service control and native packets, then flush bounded fanout;
 * timeout_ms is the maximum poll wait (>=0); returns 0, or -1 with errno */
int qlinq_relay_service(qlinq_relay_t *, int timeout_ms);
void qlinq_relay_get_stats(const qlinq_relay_t *, qlinq_relay_stats_t *);
void qlinq_relay_close(qlinq_relay_t *);
#endif
