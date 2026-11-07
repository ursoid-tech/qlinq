/* exercise the watcher callback, owner-thread queue and real path lifecycle
 * together. a simulated socket host keeps discovery tests independent of the
 * machine's interfaces, privileges and UDP binding behavior. */
#include "../../src/common/transport_poll_host.c"

#include <assert.h>

typedef struct {
  transport_poll_host_t host;
  transport_t *transport;
  size_t opens, closes, callbacks, loopback_callbacks;
  bool accept_candidates;
  const char *allowed_name;
} ifmon_fixture_t;

static bool fixture_open(void *context, transport_drive_path_t *path) {
  ifmon_fixture_t *f = context;
  f->opens++;
  if (!path->interface_index &&
      !transport_address_is_wildcard((struct sockaddr *)&path->local))
    path->interface_index = 7;
  return true;
}

static void fixture_close(void *context, const transport_drive_path_t *path) {
  (void)path;
  ((ifmon_fixture_t *)context)->closes++;
}

static ssize_t fixture_send(void *context, const transport_drive_path_t *path,
                            const struct sockaddr *source,
                            const struct sockaddr *destination,
                            socklen_t destination_len, uint32_t interface_index,
                            uint8_t ecn, size_t max_gso_segments,
                            const struct iovec *datagrams, size_t count) {
  (void)context;
  (void)path;
  (void)source;
  (void)destination;
  (void)destination_len;
  (void)interface_index;
  (void)ecn;
  (void)max_gso_segments;
  (void)datagrams;
  return (ssize_t)count;
}

static void fixture_event(void *context, const transport_event_t *event) {
  (void)context;
  (void)event;
}

static void fixture_log(void *context, const transport_log_event_t *event) {
  (void)context;
  (void)event;
}

static bool fixture_candidate(void *context,
                              const transport_interface_info_t *info) {
  ifmon_fixture_t *f = context;
  f->callbacks++;
  if (strcmp(info->interface_name, "lo") == 0)
    f->loopback_callbacks++;
  assert(pthread_equal(f->transport->owner_thread, pthread_self()));
  return f->accept_candidates &&
         (!f->allowed_name ||
          strcmp(info->interface_name, f->allowed_name) == 0);
}

static void fixture_init_addresses(ifmon_fixture_t *f, const char *bind_address,
                                   const char *second_address, bool multihome,
                                   bool callback, const char *allow_name,
                                   const char *const *remote_addresses,
                                   bool reconnect) {
  memset(f, 0, sizeof(*f));
  atomic_init(&f->host.interface_updates, NULL);
  f->host.multihome = multihome;
  f->host.custom_iface_filter = callback || allow_name != NULL;
  f->accept_candidates = true;
  assert(pipe(f->host.ifmon_pipe) == 0);
  assert(set_fd_nonblocking(f->host.ifmon_pipe[0]));
  assert(set_fd_nonblocking(f->host.ifmon_pipe[1]));
  transport_drive_host_t adapter = {.context = f,
                                    .initial_time_ns = 1000000000U,
                                    .open = fixture_open,
                                    .close = fixture_close,
                                    .send = fixture_send};
  transport_config_t config = {.bind_hosts = {bind_address},
                               .num_bind_hosts = 1,
                               .port = 19867,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .allow_insecure_peer = true,
                               .reconnect_enabled = reconnect,
                               .callback = fixture_event,
                               .log_callback = fixture_log,
                               .drive_host = &adapter,
                               .interface_callback =
                                   callback ? fixture_candidate : NULL,
                               .interface_user_data = f};
  if (second_address) {
    config.bind_hosts[1] = second_address;
    config.num_bind_hosts = 2;
  }
  if (remote_addresses) {
    config.remote_hosts[0] = remote_addresses[0];
    config.remote_hosts[1] = remote_addresses[1];
    config.num_remote_hosts = remote_addresses[1] ? 2 : 1;
  }
  if (allow_name) {
    config.path_interface_names[0] = allow_name;
    config.num_path_interface_names = 1;
  }
  f->transport = transport_drive_create(&config);
  assert(f->transport && f->transport->socket_count == config.num_bind_hosts);
  f->host.transport = f->transport;
  /* service_interfaces uses the polling wrapper's queue while path opening
   * and closing continue through the independent simulated drive host */
  f->transport->host_context = &f->host;
}

static void fixture_init(ifmon_fixture_t *f, const char *bind_address,
                         bool multihome, bool callback,
                         const char *allow_name) {
  fixture_init_addresses(f, bind_address, NULL, multihome, callback, allow_name,
                         NULL, false);
}

static void fixture_dispose(ifmon_fixture_t *f) {
  assert(!atomic_load(&f->host.interface_updates));
  transport_destroy(f->transport);
  assert(f->opens == f->closes);
  close(f->host.ifmon_pipe[0]);
  close(f->host.ifmon_pipe[1]);
}

static ifmon_addr_t fixture_address(const char *text) {
  ifmon_addr_t address = {.family = strchr(text, ':') ? AF_INET6 : AF_INET,
                          .prefix_len = strchr(text, ':') ? 64 : 24};
  assert(inet_pton(address.family, text, &address.ip) == 1);
  return address;
}

static ifmon_iface_t fixture_iface(uint32_t index, const char *name,
                                   const char *address) {
  ifmon_iface_t iface = {.index = index, .is_up = 1, .addr_count = 1};
  snprintf(iface.name, sizeof(iface.name), "%s", name);
  iface.addrs[0] = fixture_address(address);
  return iface;
}

static void fixture_apply(ifmon_fixture_t *f, const ifmon_update_t *update) {
  on_ifmon_update(update, &f->host);
  (void)service_interfaces(f->transport);
}

static void assert_only_address(ifmon_fixture_t *f, const char *text,
                                uint32_t index) {
  assert(f->transport->socket_count == 1);
  transport_local_path_t *path = &f->transport->sockets[0];
  ifmon_addr_t expected = fixture_address(text);
  struct sockaddr_storage address;
  ifmon_socket_address(&address, &expected, index);
  assert(transport_address_equal((struct sockaddr *)&path->local_addr,
                                 (struct sockaddr *)&address));
  assert(path->interface_index == index);
  unsigned port =
      address.ss_family == AF_INET
          ? ntohs(((struct sockaddr_in *)&path->local_addr)->sin_port)
          : ntohs(((struct sockaddr_in6 *)&path->local_addr)->sin6_port);
  assert(port == 19867);
}

typedef struct {
  const ifmon_update_t *update;
  transport_poll_host_t *host;
} fixture_submission_t;

static void *fixture_submit(void *context) {
  fixture_submission_t *submission = context;
  on_ifmon_update(submission->update, submission->host);
  return NULL;
}

static void initial_loopback_policy(void) {
  for (int policy = 0; policy < 3; policy++) {
    ifmon_fixture_t f;
    fixture_init(&f, "0.0.0.0", true, policy == 1, policy == 2 ? "lo" : NULL);
    ifmon_iface_t interfaces[] = {fixture_iface(1, "lo", "127.0.0.1"),
                                  fixture_iface(2, "eth0", "192.0.2.1")};
    ifmon_list_t list = {.ifaces = interfaces, .count = 2};
    ifmon_update_t update = {.is_initial = 1, .interfaces = &list};
    fixture_submission_t submission = {.update = &update, .host = &f.host};
    pthread_t producer;
    assert(pthread_create(&producer, NULL, fixture_submit, &submission) == 0);
    assert(pthread_join(producer, NULL) == 0);
    assert(f.callbacks == 0); /* policy runs only when the owner drains */
    assert(service_interfaces(f.transport));
    assert(f.transport->socket_count == (policy == 1 ? 3U : 2U));
    assert(f.loopback_callbacks == (policy == 1 ? 1U : 0U));
    assert(f.callbacks == (policy == 1 ? 2U : 0U));
    assert(f.transport->sockets[1].interface_index == (policy == 0 ? 2U : 1U));
    fixture_dispose(&f);
  }
}

static void renamed_interface_policy(void) {
  for (int policy = 0; policy < 3; policy++) {
    ifmon_fixture_t f;
    fixture_init(&f, "0.0.0.0", true, policy == 1, policy == 2 ? "eth9" : NULL);
    f.allowed_name = "eth9";
    ifmon_iface_t iface = fixture_iface(9, "tun9", "192.0.2.9");
    ifmon_list_t list = {.ifaces = &iface, .count = 1};
    ifmon_update_t update = {.is_initial = 1, .interfaces = &list};
    fixture_apply(&f, &update);
    assert(f.transport->socket_count == 1);

    /* a rename is delivered as removal plus addition of the same index.
     * default policy, callbacks and name allowlists must all see the new name.
     */
    uint32_t index = iface.index;
    copy_interface_name(iface.name, "eth9");
    update = (ifmon_update_t){.interfaces = &list,
                              .removed = &index,
                              .removed_count = 1,
                              .added = &index,
                              .added_count = 1};
    fixture_apply(&f, &update);
    assert(f.transport->socket_count == 2);
    assert(f.transport->sockets[1].interface_index == index);
    assert(strcmp(f.transport->sockets[1].interface_name, "eth9") == 0);

    copy_interface_name(iface.name, "tun9");
    fixture_apply(&f, &update);
    assert(f.transport->socket_count == 1);
    assert(f.opens == 2 && f.closes == 1);
    assert(f.callbacks == (policy == 1 ? 3U : 0U));
    fixture_dispose(&f);
  }
}

static void explicit_dual_stack_recovery(void) {
  ifmon_fixture_t f;
  fixture_init_addresses(&f, "192.0.2.7", "2001:db8::7", false, false, NULL,
                         NULL, false);
  ifmon_iface_t iface = fixture_iface(7, "tun0", "192.0.2.7");
  iface.addrs[1] = fixture_address("2001:db8::7");
  iface.addr_count = 2;
  ifmon_list_t list = {.ifaces = &iface, .count = 1};
  uint32_t index = 7;
  ifmon_update_t update = {
      .interfaces = &list, .removed = &index, .removed_count = 1};
  fixture_apply(&f, &update);
  assert(f.transport->socket_count == 0 && f.closes == 2);
  iface.index = index = 38;
  update =
      (ifmon_update_t){.interfaces = &list, .added = &index, .added_count = 1};
  fixture_apply(&f, &update);
  assert(f.transport->socket_count == 2 && f.opens == 4);
  assert(f.transport->sockets[0].local_addr.ss_family == AF_INET);
  assert(f.transport->sockets[1].local_addr.ss_family == AF_INET6);
  assert(f.transport->sockets[0].interface_index == 38 &&
         f.transport->sockets[1].interface_index == 38);
  fixture_dispose(&f);
}

static void explicit_client_remote_pairing(bool reconnect, bool dual_stack) {
  ifmon_fixture_t f;
  const char *second_address = dual_stack ? "2001:db8::8" : "192.0.2.8";
  const char *remotes[] = {"192.0.2.100",
                           dual_stack ? "2001:db8::101" : "192.0.2.101"};
  fixture_init_addresses(&f, "192.0.2.7", second_address, false, true, NULL,
                         remotes, reconnect);
  f.accept_candidates = false;
  assert(!f.transport->is_server && f.transport->client_conn);
  assert(f.transport->sockets[0].remote_index == 0 &&
         f.transport->sockets[1].remote_index == 1);
  ifmon_iface_t interfaces[] = {fixture_iface(38, "tun1", second_address),
                                fixture_iface(39, "tun0", "192.0.2.7"),
                                fixture_iface(40, "eth2", "192.0.2.9")};
  ifmon_list_t list = {.ifaces = interfaces, .count = 3};
  uint32_t original_index = 7;
  ifmon_update_t update = {
      .interfaces = &list, .removed = &original_index, .removed_count = 1};
  fixture_apply(&f, &update);
  assert(f.transport->socket_count == 0);
  assert((f.transport->client_conn == NULL) == reconnect);
  f.accept_candidates = true;
  uint32_t candidate_index = 40;
  update = (ifmon_update_t){
      .interfaces = &list, .added = &candidate_index, .added_count = 1};
  fixture_apply(&f, &update);
  assert(f.transport->socket_count == 0 && f.callbacks == 1);
  f.accept_candidates = false;
  uint32_t restored_indices[] = {38, 39};
  update = (ifmon_update_t){
      .interfaces = &list, .added = restored_indices, .added_count = 2};
  fixture_apply(&f, &update);
  assert(f.transport->socket_count == 2 && f.callbacks == 1);
  for (size_t i = 0; i < 2; i++) {
    transport_local_path_t *path = &f.transport->sockets[i];
    struct sockaddr_storage expected;
    ifmon_socket_address(&expected, &interfaces[i].addrs[0],
                         interfaces[i].index);
    assert(transport_address_equal((struct sockaddr *)&path->local_addr,
                                   (struct sockaddr *)&expected));
    assert(path->interface_index == restored_indices[i]);
    assert(path->remote_index == 1U - i && path->open_pending);
  }
  if (reconnect) {
    uint64_t reconnect_time =
        (uint64_t)(f.transport->reconnect_at_ms + 1) * 1000000U;
    assert(transport_drive_tick(f.transport, reconnect_time));
    assert(f.transport->client_conn);
    /* the QUIC primary path must use the restored socket's peer, including
     * when the first recovered socket has a different address family */
    assert(transport_endpoint_equal(
        quicly_get_peername(f.transport->client_conn->quic),
        (const struct sockaddr *)&f.transport->remote_addrs[1]));
    assert(!f.transport->sockets[0].open_pending);
    assert(f.transport->sockets[1].open_pending);
  }
  fixture_dispose(&f);
}

static void explicit_recovery(const char *bound, const char *alias) {
  for (int policy = 0; policy < 4; policy++) {
    ifmon_fixture_t f;
    fixture_init(&f, bound, false, (policy & 1) != 0,
                 (policy & 2) != 0 ? "eth0" : NULL);
    f.accept_candidates = false;
    assert(f.callbacks == 0);
    ifmon_iface_t iface = fixture_iface(7, "tun0", bound);
    ifmon_list_t list = {.ifaces = &iface, .count = 1};
    ifmon_iface_diff_t diff = {.index = 7, .link_state_changed = 1};
    ifmon_update_t update = {
        .interfaces = &list, .modified = &diff, .modified_count = 1};

    iface.is_up = 0;
    fixture_apply(&f, &update);
    assert(f.transport->socket_count == 0);

    iface.is_up = diff.is_up = 1;
    iface.addrs[1] = fixture_address(alias);
    iface.addr_count = 2;
    fixture_apply(&f, &update);
    assert_only_address(&f, bound, 7);
    assert(f.callbacks == (policy == 1 ? 1U : 0U));

    /* remove the entire interface and restore its configured address under a
     * new index, without admitting another address on the excluded device */
    uint32_t index = 7;
    update = (ifmon_update_t){
        .interfaces = &list, .removed = &index, .removed_count = 1};
    fixture_apply(&f, &update);
    assert(f.transport->socket_count == 0);
    iface.index = index = 38;
    update = (ifmon_update_t){
        .interfaces = &list, .added = &index, .added_count = 1};
    fixture_apply(&f, &update);
    assert_only_address(&f, bound, 38);

    /* renaming an explicitly bound interface must also preserve its exception
     * to the callback and name allowlist */
    copy_interface_name(iface.name, "tun-renamed");
    update.removed = &index;
    update.removed_count = 1;
    fixture_apply(&f, &update);
    assert_only_address(&f, bound, 38);
    assert(strcmp(f.transport->sockets[0].interface_name, "tun-renamed") == 0);

    /* address disappearance has to retire an explicit path even when the
     * now-empty interface would fail the discovery policy */
    diff = (ifmon_iface_diff_t){.index = 38, .addrs_removed_count = 1};
    diff.addrs_removed[0] = fixture_address(bound);
    iface.addr_count = 0;
    update = (ifmon_update_t){
        .interfaces = &list, .modified = &diff, .modified_count = 1};
    fixture_apply(&f, &update);
    assert(f.transport->socket_count == 0);
    diff.addrs_removed_count = 0;
    diff.addrs_added_count = 1;
    diff.addrs_added[0] = fixture_address(bound);
    iface.addr_count = 1;
    fixture_apply(&f, &update);
    assert_only_address(&f, bound, 38);
    fixture_dispose(&f);
  }
}

static void wildcard_is_not_an_exception(const char *bound,
                                         const char *candidate) {
  ifmon_fixture_t f;
  fixture_init(&f, bound, false, false, NULL);
  ifmon_iface_t iface = fixture_iface(7, "tun0", candidate);
  ifmon_list_t list = {.ifaces = &iface, .count = 1};
  uint32_t index = iface.index;
  ifmon_update_t update = {
      .interfaces = &list, .added = &index, .added_count = 1};
  fixture_apply(&f, &update);
  assert(f.transport->socket_count == 1 && f.opens == 1);
  assert(transport_address_is_wildcard(
      (struct sockaddr *)&f.transport->sockets[0].local_addr));
  fixture_dispose(&f);
}

static void large_snapshot_and_queued_updates(void) {
  ifmon_fixture_t f;
  fixture_init(&f, "0.0.0.0", true, false, NULL);
  enum { EXCLUDED_INTERFACES = 40 };
  ifmon_iface_t *interfaces =
      calloc(EXCLUDED_INTERFACES + 1, sizeof(*interfaces));
  assert(interfaces);
  for (size_t i = 0; i < EXCLUDED_INTERFACES; i++) {
    interfaces[i] = fixture_iface((uint32_t)i + 10, "br-test", "192.0.2.1");
    interfaces[i].addr_count = IFMON_MAX_IPS_PER_IFACE;
    for (int j = 0; j < IFMON_MAX_IPS_PER_IFACE; j++) {
      char address[32];
      snprintf(address, sizeof(address), "10.%zu.%d.1", i, j);
      interfaces[i].addrs[j] = fixture_address(address);
    }
  }
  interfaces[EXCLUDED_INTERFACES] = fixture_iface(90, "eth0", "192.0.2.90");
  ifmon_list_t list = {.ifaces = interfaces, .count = EXCLUDED_INTERFACES + 1};
  ifmon_update_t update = {.is_initial = 1, .interfaces = &list};
  fixture_apply(&f, &update);
  assert(f.transport->socket_count == 2);
  assert(f.transport->sockets[1].interface_index == 90);
  free(interfaces);

  /* a full wakeup pipe must not discard queued changes. multiple snapshots
   * are borrowed only during callbacks and must be replayed in FIFO order. */
  uint8_t padding[512] = {0};
  while (write(f.host.ifmon_pipe[1], padding, sizeof(padding)) > 0)
    ;
  assert(errno == EAGAIN || errno == EWOULDBLOCK);
  ifmon_iface_t iface = fixture_iface(91, "eth1", "192.0.2.91");
  list = (ifmon_list_t){.ifaces = &iface, .count = 1};
  uint32_t index = 91;
  update =
      (ifmon_update_t){.interfaces = &list, .added = &index, .added_count = 1};
  on_ifmon_update(&update, &f.host);
  update = (ifmon_update_t){
      .interfaces = &list, .removed = &index, .removed_count = 1};
  on_ifmon_update(&update, &f.host);
  iface.index = index = 92;
  update =
      (ifmon_update_t){.interfaces = &list, .added = &index, .added_count = 1};
  on_ifmon_update(&update, &f.host);
  memset(&iface, 0, sizeof(iface));
  assert(service_interfaces(f.transport));
  assert(f.transport->socket_count == 3);
  assert(f.transport->sockets[2].interface_index == 92);
  assert(f.opens == 4 && f.closes == 1);
  fixture_dispose(&f);
}

int main(void) {
  initial_loopback_policy();
  renamed_interface_policy();
  explicit_recovery("192.0.2.7", "192.0.2.8");
  explicit_recovery("2001:db8::7", "2001:db8::8");
  explicit_dual_stack_recovery();
  explicit_client_remote_pairing(false, false);
  explicit_client_remote_pairing(false, true);
  explicit_client_remote_pairing(true, false);
  explicit_client_remote_pairing(true, true);
  wildcard_is_not_an_exception("0.0.0.0", "192.0.2.7");
  wildcard_is_not_an_exception("::", "2001:db8::7");
  large_snapshot_and_queued_updates();
  puts("===TRANSPORT IFMON OK===");
  return 0;
}
