/* Test snapshot changes without depending on host interfaces or watcher timing.
 */
#include "../../src/common/ifmon.c"

#include <assert.h>

static ifmon_addr_t address(int family, const char *text, uint8_t prefix) {
  ifmon_addr_t addr = {.family = family, .prefix_len = prefix};
  assert(inet_pton(family, text, &addr.ip) == 1);
  return addr;
}

static void snapshot_changes(void) {
  ifmon_list_t prev = {.count = 2};
  prev.ifaces[0] = (ifmon_iface_t){.index = 7, .is_up = 1, .addr_count = 3};
  prev.ifaces[0].addrs[0] = address(AF_INET, "192.0.2.1", 24);
  prev.ifaces[0].addrs[1] = address(AF_INET6, "2001:db8::1", 64);
  prev.ifaces[0].addrs[2] = address(AF_INET, "192.0.2.2", 24);
  prev.ifaces[1].index = 9;
  ifmon_list_t curr = prev;
  ifmon_update_t update;
  generate_update(NULL, &curr, 1, &update);
  assert(update.is_initial && update.interfaces == &curr);
  assert(!update.added_count && !update.removed_count &&
         !update.modified_count);

  /* Enumeration order is irrelevant; emitted changes retain snapshot order. */
  curr.ifaces[0] = prev.ifaces[1];
  curr.ifaces[1] = prev.ifaces[0];
  curr.ifaces[1].addrs[0] = prev.ifaces[0].addrs[2];
  curr.ifaces[1].addrs[2] = prev.ifaces[0].addrs[0];
  generate_update(&prev, &curr, 0, &update);
  assert(!update.added_count && !update.removed_count &&
         !update.modified_count);

  curr.ifaces[0].index = 11;
  curr.ifaces[1].is_up = 0;
  strcpy(curr.ifaces[1].hw_addr, "AA:BB:CC:DD:EE:FF");
  curr.ifaces[1].addrs[0].prefix_len = 25;
  curr.ifaces[1].addrs[1] = address(AF_INET6, "2001:db8::2", 64);
  generate_update(&prev, &curr, 0, &update);
  assert(!update.is_initial && update.interfaces == &curr);
  assert(update.added_count == 1 && update.added[0] == 11);
  assert(update.removed_count == 1 && update.removed[0] == 9);
  assert(update.modified_count == 1);
  const ifmon_iface_diff_t *diff = &update.modified[0];
  assert(diff->index == 7 && diff->hw_addr_changed && diff->link_state_changed);
  assert(!diff->is_up && diff->addrs_added_count == 2 &&
         diff->addrs_removed_count == 2);
  assert(memcmp(diff->addrs_added, curr.ifaces[1].addrs,
                2 * sizeof(ifmon_addr_t)) == 0);
  assert(memcmp(diff->addrs_removed, &prev.ifaces[0].addrs[1],
                2 * sizeof(ifmon_addr_t)) == 0);

  prev = (ifmon_list_t){.count = IFMON_MAX_INTERFACES};
  curr = prev;
  for (int i = 0; i < IFMON_MAX_INTERFACES; i++) {
    prev.ifaces[i].index = curr.ifaces[i].index = (uint32_t)i + 1;
    prev.ifaces[i].addr_count = curr.ifaces[i].addr_count =
        IFMON_MAX_IPS_PER_IFACE;
    for (int j = 0; j < IFMON_MAX_IPS_PER_IFACE; j++) {
      prev.ifaces[i].addrs[j] = address(AF_INET, "192.0.2.1", 24);
      curr.ifaces[i].addrs[j] = address(AF_INET6, "2001:db8::1", 64);
    }
  }
  generate_update(&prev, &curr, 0, &update);
  assert(update.modified_count == IFMON_MAX_INTERFACES);
  for (int i = 0; i < update.modified_count; i++) {
    assert(update.modified[i].index == (uint32_t)i + 1);
    assert(update.modified[i].addrs_added_count == IFMON_MAX_IPS_PER_IFACE);
    assert(update.modified[i].addrs_removed_count == IFMON_MAX_IPS_PER_IFACE);
  }
}

#ifndef _WIN32
static void missing_prefixes(void) {
  ifmon_list_t list = {.count = 2};
  ifmon_iface_t *iface = &list.ifaces[0];
  iface->addr_count = 6;
  iface->addrs[0] = address(AF_INET, "192.0.2.1", 0);
  iface->addrs[1] = address(AF_INET6, "2001:db8::1", 0);
  iface->addrs[2] = address(AF_INET, "192.0.2.2", 25);
  iface->addrs[3] = address(AF_INET6, "2001:db8::2", 56);
  iface->addrs[4] = address(AF_INET, "192.0.2.3", 26);
  iface->addrs[5] = address(AF_INET6, "2001:db8::3", 48);
  list.ifaces[1].addr_count = 3;
  list.ifaces[1].addrs[0] = iface->addrs[0];
  list.ifaces[1].addrs[1] = iface->addrs[1];
  list.ifaces[1].addrs[2].family = AF_UNSPEC;
  fill_missing_prefixes(&list);
  assert(iface->addrs[0].prefix_len == 25 && iface->addrs[1].prefix_len == 56);
  assert(iface->addrs[2].prefix_len == 25 && iface->addrs[3].prefix_len == 56);
  assert(iface->addrs[4].prefix_len == 26 && iface->addrs[5].prefix_len == 48);
  assert(list.ifaces[1].addrs[0].prefix_len == 24);
  assert(list.ifaces[1].addrs[1].prefix_len == 64);
  assert(list.ifaces[1].addrs[2].prefix_len == 0);
}
#endif

int main(void) {
  snapshot_changes();
#ifndef _WIN32
  missing_prefixes();
#endif
  puts("===IFMON SNAPSHOTS OK===");
  return 0;
}
