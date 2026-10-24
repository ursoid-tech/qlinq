#ifndef QLINQ_TUN_CONTROL_H
#define QLINQ_TUN_CONTROL_H

#include "tun_json.h"
#include <limits.h>
#include <stddef.h>

typedef struct {
  char id[33], role[8], endpoint[16], local_ip[16], peer_ip[16];
  char interface[16], uplinks[4][16], routes[16][32], mode[16], run_as[33];
  char token[65];
  unsigned port, mtu, queue_ms, uplink_count, route_count;
} tc_config;

typedef struct {
  const char *root, *action, *name, *identity, *invite, *listen;
  const char *interface, *local_ip, *peer_ip, *run_as, *metrics_output;
  const char *uplinks[4], *routes[16];
  unsigned uplink_count, route_count, metrics_interval;
  bool mock, json;
} tc_args;

typedef struct {
  char errors[32][192], warnings[8][192];
  unsigned error_count, warning_count;
} tc_report;

bool tc_error(const char *format, ...);
bool tc_path(char out[PATH_MAX], const char *dir, const char *name);
bool tc_secure_dir(const char *path, bool create);
bool tc_profile_dir(const tc_args *args, char directory[PATH_MAX],
                    bool create_root);
bool tc_validate(const tc_config *c);
bool tc_decode(const tj_doc *doc, const tj_node *obj, tc_config *config);
bool tc_load(const char *directory, tc_config *config);
void tc_write(FILE *out, const tc_config *config, bool redacted);
int tc_init(const tc_args *args, const char *directory);
int tc_pair(const tc_args *args, const char *directory,
            const tc_config *config);
unsigned tc_addresses(const tc_config *config, char addresses[4][16],
                      bool found[4]);
void tc_check(const char *directory, const tc_config *config, bool mock,
              bool running, tc_report *report);
uint64_t tc_now_ms(void);
int tun_worker_main(int argc, char **argv);
int tun_control_main(int argc, char **argv);

#endif
