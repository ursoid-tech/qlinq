/* test real dump parsing and snapshot changes without host interface changes.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <stdlib.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <unistd.h>
#endif

static int allocation_budget = -1;

static int allow_allocation(void) {
  if (allocation_budget < 0)
    return 1;
  if (!allocation_budget)
    return 0;
  allocation_budget--;
  return 1;
}

#ifndef __linux__
static void *test_malloc(size_t size) {
  return allow_allocation() ? malloc(size) : NULL;
}
#endif

static void *test_calloc(size_t count, size_t size) {
  return allow_allocation() ? calloc(count, size) : NULL;
}

static void *test_realloc(void *ptr, size_t size) {
  return allow_allocation() ? realloc(ptr, size) : NULL;
}

#ifdef __linux__
static int dump_fd = -1;

static int test_socket(int domain, int type, int protocol) {
  if (dump_fd >= 0 && domain == AF_NETLINK)
    return dup(dump_fd);
  return socket(domain, type, protocol);
}

static ssize_t test_send(int fd, const void *buffer, size_t size, int flags) {
  return dump_fd >= 0 ? (ssize_t)size : send(fd, buffer, size, flags);
}
#define socket test_socket
#define send test_send
#endif
#define malloc test_malloc
#define calloc test_calloc
#define realloc test_realloc
#include "../../src/common/ifmon.c"
#undef malloc
#undef calloc
#undef realloc
#ifdef __linux__
#undef socket
#undef send
#endif

static ifmon_list_t snapshot(int count) {
  ifmon_list_t list = {0};
  for (int i = 0; i < count; i++)
    assert(append_iface(&list));
  return list;
}

static ifmon_addr_t address(int family, const char *text, uint8_t prefix) {
  ifmon_addr_t addr = {.family = family, .prefix_len = prefix};
  assert(inet_pton(family, text, &addr.ip) == 1);
  return addr;
}

static void snapshot_changes(void) {
  ifmon_list_t prev = snapshot(2);
  prev.ifaces[0] = (ifmon_iface_t){.index = 7, .is_up = 1, .addr_count = 3};
  prev.ifaces[0].addrs[0] = address(AF_INET, "192.0.2.1", 24);
  prev.ifaces[0].addrs[1] = address(AF_INET6, "2001:db8::1", 64);
  prev.ifaces[0].addrs[2] = address(AF_INET, "192.0.2.2", 24);
  prev.ifaces[1].index = 9;
  ifmon_list_t curr = snapshot(prev.count);
  memcpy(curr.ifaces, prev.ifaces, (size_t)prev.count * sizeof(*prev.ifaces));
  ifmon_update_t update = {0};
  assert(generate_update(NULL, &curr, 1, &update) == 0);
  assert(update.is_initial && update.interfaces == &curr);
  assert(!update.added_count && !update.removed_count &&
         !update.modified_count);

  /* enumeration order is irrelevant; emitted changes retain snapshot order */
  curr.ifaces[0] = prev.ifaces[1];
  curr.ifaces[1] = prev.ifaces[0];
  curr.ifaces[1].addrs[0] = prev.ifaces[0].addrs[2];
  curr.ifaces[1].addrs[2] = prev.ifaces[0].addrs[0];
  assert(generate_update(&prev, &curr, 0, &update) == 0);
  assert(!update.added_count && !update.removed_count &&
         !update.modified_count);

  curr.ifaces[0].index = 11;
  curr.ifaces[1].is_up = 0;
  strcpy(curr.ifaces[1].hw_addr, "AA:BB:CC:DD:EE:FF");
  curr.ifaces[1].addrs[0].prefix_len = 25;
  curr.ifaces[1].addrs[1] = address(AF_INET6, "2001:db8::2", 64);
  assert(generate_update(&prev, &curr, 0, &update) == 0);
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

  ifmon_list_dispose(&prev);
  ifmon_list_dispose(&curr);
  enum { interface_count = 40 };
  prev = snapshot(interface_count);
  curr = snapshot(interface_count);
  for (int i = 0; i < interface_count; i++) {
    prev.ifaces[i].index = curr.ifaces[i].index = (uint32_t)i + 1;
    prev.ifaces[i].addr_count = curr.ifaces[i].addr_count =
        IFMON_MAX_IPS_PER_IFACE;
    for (int j = 0; j < IFMON_MAX_IPS_PER_IFACE; j++) {
      prev.ifaces[i].addrs[j] = address(AF_INET, "192.0.2.1", 24);
      curr.ifaces[i].addrs[j] = address(AF_INET6, "2001:db8::1", 64);
    }
  }
  assert(generate_update(&prev, &curr, 0, &update) == 0);
  assert(update.modified_count == interface_count);
  for (int i = 0; i < update.modified_count; i++) {
    assert(update.modified[i].index == (uint32_t)i + 1);
    assert(update.modified[i].addrs_added_count == IFMON_MAX_IPS_PER_IFACE);
    assert(update.modified[i].addrs_removed_count == IFMON_MAX_IPS_PER_IFACE);
  }

  for (int i = 0; i < curr.count; i++)
    curr.ifaces[i].index += interface_count;
  assert(generate_update(&prev, &curr, 0, &update) == 0);
  assert(update.added_count == interface_count);
  assert(update.removed_count == interface_count);
  assert(!update.modified_count);
  for (int i = 0; i < interface_count; i++) {
    assert(update.added[i] == (uint32_t)(i + 1 + interface_count));
    assert(update.removed[i] == (uint32_t)(i + 1));
  }
  allocation_budget = 0;
  assert(generate_update(&prev, &curr, 0, &update) == -1);
  assert(!update.added && !update.removed && !update.modified);
  allocation_budget = -1;
  assert(generate_update(&prev, &curr, 0, &update) == 0);
  ifmon_update_dispose(&update);
  ifmon_list_dispose(&prev);
  ifmon_list_dispose(&curr);
}

static void snapshot_renames(void) {
  ifmon_list_t prev = snapshot(3);
  for (int i = 0; i < prev.count; i++) {
    prev.ifaces[i].index = (uint32_t)i + 1;
    prev.ifaces[i].is_up = 1;
    prev.ifaces[i].addr_count = 1;
    prev.ifaces[i].addrs[0] = address(AF_INET, "192.0.2.1", 24);
  }
  strcpy(prev.ifaces[0].name, "tun0");
  strcpy(prev.ifaces[1].name, "eth1");
  strcpy(prev.ifaces[2].name, "eth2");

  ifmon_list_t curr = snapshot(3);
  curr.ifaces[0] = prev.ifaces[1];
  curr.ifaces[1] = prev.ifaces[0];
  curr.ifaces[2] = prev.ifaces[2];
  strcpy(curr.ifaces[0].name, "tun1");
  strcpy(curr.ifaces[1].name, "eth0");
  curr.ifaces[2].index = 4;
  strcpy(curr.ifaces[2].name, "eth3");

  /* coalesced down/rename/up events leave only the names changed. both
   * filter directions must retire the old name and discover the new one. */
  ifmon_update_t update = {0};
  assert(generate_update(&prev, &curr, 0, &update) == 0);
  assert(update.added_count == 3 && update.removed_count == 3);
  assert(update.added[0] == 2 && update.added[1] == 1 && update.added[2] == 4);
  assert(update.removed[0] == 1 && update.removed[1] == 2 &&
         update.removed[2] == 3);
  assert(!update.modified_count);

  /* a renamed interface's current snapshot carries simultaneous changes;
   * a second modified event would duplicate part of that transition. */
  curr.ifaces[1].is_up = 0;
  curr.ifaces[1].addrs[0] = address(AF_INET, "192.0.2.2", 25);
  strcpy(curr.ifaces[1].hw_addr, "AA:BB:CC:DD:EE:FF");
  assert(generate_update(&prev, &curr, 0, &update) == 0);
  assert(update.added_count == 3 && update.removed_count == 3);
  assert(!update.modified_count);

  /* without a rename, the same state changes remain ordinary diffs */
  strcpy(curr.ifaces[0].name, prev.ifaces[1].name);
  strcpy(curr.ifaces[1].name, prev.ifaces[0].name);
  assert(generate_update(&prev, &curr, 0, &update) == 0);
  assert(update.added_count == 1 && update.added[0] == 4);
  assert(update.removed_count == 1 && update.removed[0] == 3);
  assert(update.modified_count == 1 && update.modified[0].index == 1);
  assert(update.modified[0].link_state_changed &&
         update.modified[0].hw_addr_changed);
  assert(update.modified[0].addrs_added_count == 1 &&
         update.modified[0].addrs_removed_count == 1);

  ifmon_update_dispose(&update);
  ifmon_list_dispose(&prev);
  ifmon_list_dispose(&curr);
}

#ifndef _WIN32
static void missing_prefixes(void) {
  ifmon_list_t list = snapshot(2);
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
  ifmon_list_dispose(&list);
}
#endif

#ifdef __linux__
static void netlink_addresses(void) {
  struct {
    struct rtattr peer;
    struct in_addr peer_ip;
    struct rtattr local;
    struct in_addr local_ip;
  } attrs = {.peer = {.rta_type = IFA_ADDRESS, .rta_len = RTA_LENGTH(4)},
             .local = {.rta_type = IFA_LOCAL, .rta_len = RTA_LENGTH(4)}};
  inet_pton(AF_INET, "192.0.2.1", &attrs.peer_ip);
  inet_pton(AF_INET, "192.0.2.2", &attrs.local_ip);
  ifmon_addr_t addr = {.family = AF_INET};
  assert(parse_address_attributes(&addr, &attrs.peer, sizeof(attrs)));
  assert(addr.ip.v4.s_addr == attrs.local_ip.s_addr);
  assert(parse_address_attributes(&addr, &attrs.peer, RTA_LENGTH(4)));
  assert(addr.ip.v4.s_addr == attrs.peer_ip.s_addr);
  attrs.peer.rta_len = RTA_LENGTH(0);
  assert(!parse_address_attributes(&addr, &attrs.peer, RTA_LENGTH(0)));
  addr.family = AF_INET6;
  attrs.peer.rta_len = RTA_LENGTH(4);
  assert(!parse_address_attributes(&addr, &attrs.peer, RTA_LENGTH(4)));
}

static void send_links(int fd, int count) {
  uint64_t storage[1024] = {0};
  uint8_t *buffer = (uint8_t *)storage;
  size_t length = 0;
  for (int i = 0; i < count; i++) {
    char name[64];
    if (i == 0)
      strcpy(name, "lo");
    else if (i == count - 2)
      strcpy(name, "eth0");
    else if (i == count - 1)
      strcpy(name, "tun0");
    else
      snprintf(name, sizeof(name), "br-%d", i);
    size_t namesize = strlen(name) + 1;
    size_t msgsize = NLMSG_LENGTH(sizeof(struct ifinfomsg)) +
                     RTA_ALIGN(RTA_LENGTH(namesize));
    assert(length + msgsize <= sizeof(storage));
    struct nlmsghdr *nlh = (struct nlmsghdr *)(buffer + length);
    nlh->nlmsg_len = msgsize;
    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_seq = 1;
    struct ifinfomsg *ifi = NLMSG_DATA(nlh);
    ifi->ifi_index = i + 1;
    ifi->ifi_flags = IFF_UP | IFF_RUNNING;
    struct rtattr *attr = IFLA_RTA(ifi);
    attr->rta_type = IFLA_IFNAME;
    attr->rta_len = RTA_LENGTH(namesize);
    memcpy(RTA_DATA(attr), name, namesize);
    length += NLMSG_ALIGN(msgsize);
  }
  ssize_t sent = send(fd, buffer, length, 0);
  if (sent < 0)
    perror("synthetic dump send");
  assert(sent == (ssize_t)length);
}

static void send_addresses(int fd, int count) {
  uint64_t storage[1024] = {0};
  uint8_t *buffer = (uint8_t *)storage;
  size_t length = 0;
  for (int i = 0; i < count; i++) {
    size_t msgsize = NLMSG_LENGTH(sizeof(struct ifaddrmsg)) + RTA_LENGTH(4);
    assert(length + msgsize <= sizeof(storage));
    struct nlmsghdr *nlh = (struct nlmsghdr *)(buffer + length);
    nlh->nlmsg_len = msgsize;
    nlh->nlmsg_type = RTM_NEWADDR;
    nlh->nlmsg_seq = 2;
    struct ifaddrmsg *ifa = NLMSG_DATA(nlh);
    ifa->ifa_index = i + 1;
    ifa->ifa_family = AF_INET;
    ifa->ifa_prefixlen = 24;
    struct rtattr *attr = IFA_RTA(ifa);
    attr->rta_type = IFA_LOCAL;
    attr->rta_len = RTA_LENGTH(4);
    struct in_addr ip = {.s_addr = htonl(0xc0000201u + (unsigned)i)};
    memcpy(RTA_DATA(attr), &ip, sizeof(ip));
    length += NLMSG_ALIGN(msgsize);
  }
  ssize_t sent = send(fd, buffer, length, 0);
  if (sent < 0)
    perror("synthetic dump send");
  assert(sent == (ssize_t)length);
}

/* replace only the dump socket; production enumeration parses real datagrams.
 */
static int synthetic_dump(int count, int failure) {
  int pair[2];
  assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0);
  assert(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0);
  dump_fd = pair[0];
  send_links(pair[1], count);
  struct nlmsghdr done = {
      .nlmsg_len = NLMSG_LENGTH(0), .nlmsg_type = NLMSG_DONE, .nlmsg_seq = 1};
  if (failure == 1)
    return pair[1]; /* missing NLMSG_DONE must not publish a partial snapshot
                     */
  if (failure == 2)
    done.nlmsg_type = NLMSG_ERROR;
  if (failure == 3)
    done.nlmsg_flags = NLM_F_DUMP_INTR;
  assert(send(pair[1], &done, sizeof(done), 0) == sizeof(done));
  send_addresses(pair[1], count);
  done.nlmsg_seq = 2;
  if (failure == 4)
    done.nlmsg_flags = NLM_F_DUMP_INTR;
  assert(send(pair[1], &done, sizeof(done), 0) == sizeof(done));
  return pair[1];
}

static void close_dump(int peer) {
  close(dump_fd);
  close(peer);
  dump_fd = -1;
}

static void count_update(const ifmon_update_t *update, void *userdata) {
  int *count = userdata;
  assert(update->interfaces->count > 16);
  if (update->is_initial)
    assert(!update->added_count && !update->removed_count &&
           !update->modified_count);
  (*count)++;
}

static void netlink_enumeration(void) {
  uint8_t scratchpad[32];
  ifmon_list_t list = snapshot(1);
  list.ifaces[0].index = 99;
  int peer = synthetic_dump(40, 0);
  assert(ifmon_list_get(&list, scratchpad, sizeof(scratchpad)) == 0);
  close_dump(peer);
  assert(list.count == 40);
  assert(strcmp(list.ifaces[38].name, "eth0") == 0);
  assert(strcmp(list.ifaces[39].name, "tun0") == 0);
  int default_candidates = 0;
  for (int i = 0; i < list.count; i++) {
    assert(list.ifaces[i].index == (uint32_t)i + 1);
    assert(list.ifaces[i].is_up && list.ifaces[i].addr_count == 1);
    assert(list.ifaces[i].addrs[0].ip.v4.s_addr ==
           htonl(0xc0000201u + (unsigned)i));
    default_candidates += ifmon_is_default_iface(list.ifaces[i].name);
  }
  assert(default_candidates == 1);

  ifmon_iface_t *original = list.ifaces;
  for (int failure = 1; failure <= 4; failure++) {
    peer = synthetic_dump(41, failure);
    assert(ifmon_list_get(&list, scratchpad, sizeof(scratchpad)) == -1);
    assert(list.ifaces == original && list.count == 40);
    close_dump(peer);
  }

  /* fail each allocation, including growth after interfaces were appended */
  for (int budget = 0; budget < 5; budget++) {
    peer = synthetic_dump(40, 0);
    allocation_budget = budget;
    int result = ifmon_list_get(&list, scratchpad, sizeof(scratchpad));
    allocation_budget = -1;
    if (result == -1)
      assert(list.ifaces == original && list.count == 40);
    else
      original = list.ifaces;
    close_dump(peer);
  }

  int callbacks = 0;
  ifmon_watcher_t watcher = {
      .prev_list = list, .cb = count_update, .userdata = &callbacks};
  list = (ifmon_list_t){0}; /* transfer owned storage to the watcher */
  original = watcher.prev_list.ifaces;
  peer = synthetic_dump(41, 4);
  watcher_refresh(&watcher);
  close_dump(peer);
  assert(!callbacks && watcher.prev_list.ifaces == original);

  /* the read succeeds but allocating a diff fails; preserve the old state */
  peer = synthetic_dump(41, 0);
  allocation_budget = 3;
  watcher_refresh(&watcher);
  allocation_budget = -1;
  close_dump(peer);
  assert(!callbacks && watcher.prev_list.ifaces == original &&
         !watcher.curr_list.ifaces);

  peer = synthetic_dump(41, 0);
  watcher_refresh(&watcher);
  close_dump(peer);
  assert(callbacks == 1 && watcher.prev_list.count == 41);
  assert(!watcher.curr_list.ifaces && !watcher.update.added);
  original = watcher.prev_list.ifaces;
  peer = synthetic_dump(41, 0);
  watcher_refresh(&watcher);
  close_dump(peer);
  assert(callbacks == 1 && watcher.prev_list.count == 41);
  assert(!watcher.curr_list.ifaces && !watcher.update.modified);
  watcher_dispose(&watcher);
  assert(!watcher.prev_list.ifaces);

  /* if the startup dump was interrupted, the first refresh is initial */
  watcher.initial_pending = 1;
  peer = synthetic_dump(41, 0);
  watcher_refresh(&watcher);
  close_dump(peer);
  assert(callbacks == 2 && !watcher.initial_pending &&
         watcher.prev_list.count == 41);
  watcher_dispose(&watcher);
}

#endif

int main(void) {
  assert(!ifmon_is_default_iface("lo") && !ifmon_is_default_iface("lo:1"));
  assert(!ifmon_is_default_iface("lo0") && !ifmon_is_default_iface("lo1"));
  assert(!ifmon_is_default_iface("tun0") && !ifmon_is_default_iface("docker0"));
  assert(ifmon_is_default_iface("lon0") && ifmon_is_default_iface("local0"));
  snapshot_renames();
#ifdef __linux__
  netlink_addresses();
  netlink_enumeration();
#endif
  snapshot_changes();
#ifndef _WIN32
  missing_prefixes();
#endif
  puts("===IFMON SNAPSHOTS OK===");
  return 0;
}
