#include "tun_control.h"
#include "cli_parse.h"
#include "tun_metrics.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested;
static void stop_handler(int number) {
  (void)number;
  stop_requested = 1;
}

static void help(void) {
  puts("Usage: qlinq-tun [--config-dir DIR] COMMAND NAME [options]\n"
       "  init NAME --listen IPV4[:PORT] --uplink IFACE [--uplink IFACE ...]\n"
       "  init NAME --invite FILE --uplink IFACE [--uplink IFACE ...]\n"
       "    [--interface NAME] [--local-ip IP] [--peer-ip IP]\n"
       "    [--run-as USER] [--route CIDR ...]\n"
       "  pair NAME PEER.json       Trust the client's public identity\n"
       "  up NAME [--mock]          Start in the background\n"
       "  run NAME [--mock]         Run in foreground (for systemd)\n"
       "  down NAME                 Stop the tunnel\n"
       "  status NAME [--json]      Show live health\n"
       "  metrics NAME [--output /PATH/FILE.prom] [--interval SECONDS]\n"
       "                            Export Prometheus text (interval requires "
       "output)\n"
       "  diag NAME [--json] [--mock] Check configuration and prerequisites\n"
       "  diagnose NAME             Print a redacted JSON diagnostic report\n"
       "Default config directory: /etc/qlinq/tunnels\n"
       "Advanced transport flags remain supported: qlinq-tun --peer ... or "
       "--listen ...");
}

static bool parse(int argc, char **argv, tc_args *a) {
  *a = (tc_args){.root = "/etc/qlinq/tunnels",
                 .local_ip = "10.88.0.1",
                 .peer_ip = "10.88.0.2",
                 .run_as = "qlinq"};
  int i = 1;
  if (i < argc && !strcmp(argv[i], "--config-dir")) {
    if (++i == argc)
      return false;
    a->root = argv[i++];
  }
  if (i == argc)
    return false;
  a->action = argv[i++];
  const char *actions[] = {"init",   "pair", "up",       "run",    "down",
                           "status", "diag", "diagnose", "metrics"};
  bool known = false;
  for (unsigned j = 0; j < sizeof(actions) / sizeof(actions[0]); j++)
    if (!strcmp(a->action, actions[j]))
      known = true;
  if (!known || i == argc)
    return false;
  a->name = argv[i++];
  bool init = !strcmp(a->action, "init");
  bool runtime = !strcmp(a->action, "up") || !strcmp(a->action, "run");
  bool diag = !strcmp(a->action, "diag");
  if (!strcmp(a->action, "pair")) {
    if (i == argc)
      return false;
    a->identity = argv[i++];
  }
  for (; i < argc; i++) {
    const char *option = argv[i];
    if (!strcmp(option, "--mock") && (runtime || diag)) {
      a->mock = true;
      continue;
    }
    if (!strcmp(option, "--json") && (diag || !strcmp(a->action, "status"))) {
      a->json = true;
      continue;
    }
    if (!strcmp(a->action, "metrics")) {
      if (++i == argc)
        return false;
      if (!strcmp(option, "--output") && !a->metrics_output) {
        const char *path = argv[i];
        size_t length = strlen(path);
        if (path[0] != '/' || length < 6 || length >= PATH_MAX - 7 ||
            strcmp(path + length - 5, ".prom"))
          return false;
        a->metrics_output = path;
      } else if (!strcmp(option, "--interval") && !a->metrics_interval) {
        uint64_t seconds;
        if (!cli_parse_u64(argv[i], 3600, &seconds) || seconds == 0)
          return false;
        a->metrics_interval = (unsigned)seconds;
      } else
        return false;
      continue;
    }
    if (!init || ++i == argc)
      return false;
    const char *v = argv[i];
    if (!strcmp(option, "--listen") && !a->listen)
      a->listen = v;
    else if (!strcmp(option, "--invite") && !a->invite)
      a->invite = v;
    else if (!strcmp(option, "--interface") && !a->interface)
      a->interface = v;
    else if (!strcmp(option, "--local-ip"))
      a->local_ip = v;
    else if (!strcmp(option, "--peer-ip"))
      a->peer_ip = v;
    else if (!strcmp(option, "--run-as"))
      a->run_as = v;
    else if (!strcmp(option, "--uplink") && a->uplink_count < 4)
      a->uplinks[a->uplink_count++] = v;
    else if (!strcmp(option, "--route") && a->route_count < 16)
      a->routes[a->route_count++] = v;
    else
      return false;
  }
  if (a->metrics_interval && !a->metrics_output)
    return false;
  return !init || ((!!a->listen != !!a->invite) && a->uplink_count);
}

static bool socket_address(const char *dir, struct sockaddr_un *addr) {
  memset(addr, 0, sizeof(*addr));
  addr->sun_family = AF_UNIX;
  int n = snprintf(addr->sun_path, sizeof(addr->sun_path),
                   "%s/run/control.sock", dir);
  return n > 0 && (size_t)n < sizeof(addr->sun_path);
}

static bool send_all(int fd, const char *data, size_t size) {
  while (size) {
    ssize_t n = send(fd, data, size, MSG_NOSIGNAL);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return false;
    data += n;
    size -= n;
  }
  return true;
}

/* 0: stopped, 1: reply, -1: real control error (never mistake it for stopped)
 */
static int control(const char *dir, const char *request,
                   char reply[TJ_MAX_BYTES + 1]) {
  struct sockaddr_un addr;
  if (!socket_address(dir, &addr)) {
    tc_error("profile path is too long for a control socket");
    return -1;
  }
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;
  struct timeval timeout = {.tv_sec = 2};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
    int error = errno;
    close(fd);
    if (error == ENOENT || error == ECONNREFUSED)
      return 0;
    tc_error("control connection failed: %s", strerror(error));
    return -1;
  }
  char message[128];
  int length = snprintf(message, sizeof(message), "%s\n", request);
  if (length <= 0 || (size_t)length >= sizeof(message) ||
      !send_all(fd, message, (size_t)length)) {
    int error = errno;
    close(fd);
    tc_error("control request failed: %s", strerror(error));
    return -1;
  }
  size_t used = 0;
  for (;;) {
    ssize_t n = recv(fd, reply + used, TJ_MAX_BYTES - used, 0);
    if (n < 0 && errno == EINTR)
      continue;
    if (n < 0 || used == TJ_MAX_BYTES) {
      close(fd);
      tc_error("control reply failed or too large");
      return -1;
    }
    if (!n)
      break;
    used += n;
  }
  close(fd);
  reply[used] = 0;
  tj_doc *doc = calloc(1, sizeof(*doc));
  bool ok = doc && tj_parse(doc, reply) && doc->nodes[0].type == TJ_OBJECT;
  free(doc);
  if (!ok) {
    tc_error("invalid control reply");
    return -1;
  }
  return 1;
}

/* separate foreground exporter reports stopped tunnels without touching
 * transport state */
static int export_metrics(const tc_args *a, const char *dir, char *reply) {
  signal(SIGTERM, stop_handler);
  signal(SIGINT, stop_handler);
  do {
    int status = control(dir, "status", reply);
    if (stop_requested)
      return 0;
    if (status < 0)
      return 1;
    if (!status)
      strcpy(reply, "{\"state\":\"stopped\"}");
    size_t size = 0;
    char *text = tm_format(a->name, reply, &size);
    if (!text) {
      tc_error("cannot format metrics from tunnel status");
      return 1;
    }
    bool ok = a->metrics_output
                  ? tm_write_file(a->metrics_output, text, size)
                  : fwrite(text, 1, size, stdout) == size && !fflush(stdout);
    free(text);
    if (!ok) {
      tc_error("metrics export failed: %s", strerror(errno));
      return 1;
    }
    if (!a->metrics_interval)
      break;
    uint64_t until = tc_now_ms() + (uint64_t)a->metrics_interval * 1000;
    while (!stop_requested) {
      uint64_t now = tc_now_ms();
      if (now >= until)
        break;
      uint64_t remaining = until - now;
      poll(NULL, 0, (int)(remaining > 200 ? 200 : remaining));
    }
  } while (!stop_requested);
  return 0;
}

static int open_log(const char *dir, const char *name, int flags) {
  char path[PATH_MAX];
  if (!tc_path(path, dir, name))
    return -1;
  return open(path, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW | flags, 0600);
}

static void log_line(const char *runtime, const char *line, const char *token) {
  char path[PATH_MAX], one[PATH_MAX], two[PATH_MAX];
  tc_path(path, runtime, "tunnel.log");
  tc_path(one, runtime, "tunnel.log.1");
  tc_path(two, runtime, "tunnel.log.2");
  struct stat st;
  if (!lstat(path, &st) && st.st_size >= 1024 * 1024) {
    rename(one, two);
    rename(path, one);
  }
  int fd = open_log(runtime, "tunnel.log", O_APPEND);
  if (fd < 0)
    return;
  FILE *f = fdopen(fd, "a");
  if (!f) {
    close(fd);
    return;
  }
  const char *match;
  while (token && token[0] && (match = strstr(line, token))) {
    fwrite(line, 1, match - line, f);
    fputs("[redacted]", f);
    line = match + strlen(token);
  }
  fprintf(f, "%s\n", line);
  fclose(f);
}

static int worker(const tc_args *a, const char *dir, const tc_config *c,
                  pid_t parent) {
  char cert[PATH_MAX], key[PATH_MAX], ca[PATH_MAX], remote[48], port[16],
      mtu[16], queue[16], parent_text[32], track[64];
  tc_path(cert, dir, "identity.crt");
  tc_path(key, dir, "identity.key");
  tc_path(ca, dir, "peer.crt");
  snprintf(remote, sizeof(remote), "%s:%u", c->endpoint, c->port);
  snprintf(port, sizeof(port), "%u", c->port);
  snprintf(mtu, sizeof(mtu), "%u", c->mtu);
  snprintf(queue, sizeof(queue), "%u", c->queue_ms);
  snprintf(parent_text, sizeof(parent_text), "%ld", (long)parent);
  snprintf(track, sizeof(track), "tun/%s", c->id);
  char *argv[128];
  int argc = 0;
#define ARG(v) argv[argc++] = (char *)(v)
#define OPT(k, v)                                                              \
  do {                                                                         \
    ARG(k);                                                                    \
    ARG(v);                                                                    \
  } while (0)
  ARG("qlinq-tun");
  if (!strcmp(c->role, "listen"))
    OPT("--listen", port);
  else
    OPT("--peer", remote);
  OPT("--interface", c->interface);
  OPT("--ip", c->local_ip);
  OPT("--peer-ip", c->peer_ip);
  OPT("--track", track);
  OPT("--mode", c->mode);
  OPT("--mtu", mtu);
  OPT("--queue-ms", queue);
  OPT("--stats-ms", "500");
  OPT("--cert", cert);
  OPT("--key", key);
  OPT("--ca", ca);
  OPT("--parent-pid", parent_text);
  char addresses[4][16];
  bool found[4];
  if (a->mock) {
    ARG("--mock");
    OPT("--bind", "127.0.0.1");
    OPT("--uplink", "lo");
  } else {
    unsigned count = tc_addresses(c, addresses, found);
    if (!count) {
      tc_error("all selected uplinks disappeared during startup");
      return 1;
    }
    for (unsigned i = 0; i < count; i++)
      OPT("--bind", addresses[i]);
    for (unsigned i = 0; i < c->uplink_count; i++)
      OPT("--uplink", c->uplinks[i]);
    for (unsigned i = 0; i < c->route_count; i++)
      OPT("--route", c->routes[i]);
    OPT("--run-as", c->run_as);
  }
  argv[argc] = NULL;
  if (setenv("QLINQ_AUTH_TOKEN", c->token, 1))
    return 1;
  return tun_worker_main(argc, argv);
#undef ARG
#undef OPT
}

static uint64_t counter(const tj_doc *d, const char *name) {
  uint64_t v = 0;
  tj_u64(tj_get(d, &d->nodes[0], name), &v);
  return v;
}

static int serve(const tc_args *a, const char *dir, const tc_config *c) {
  int lock = -1, server = -1, output = -1, child_status = 0, result = 1;
  pid_t child = -1;
  bool bound = false, reaped = false;
  char runtime[PATH_MAX], path[PATH_MAX];
  struct sockaddr_un address;
  tj_doc *doc = NULL;
  if (!tc_path(runtime, dir, "run") || !tc_secure_dir(runtime, true) ||
      !socket_address(dir, &address)) {
    tc_error("cannot prepare runtime directory/control socket");
    return 1;
  }
  tc_path(path, runtime, "lock");
  lock = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB)) {
    tc_error("tunnel is already running or lock is inaccessible");
    goto done;
  }
  tc_report report;
  tc_check(dir, c, a->mock, false, &report);
  if (report.error_count) {
    for (unsigned i = 0; i < report.error_count; i++)
      tc_error("%s", report.errors[i]);
    goto done;
  }
  unlink(address.sun_path);
  server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (server < 0 || bind(server, (struct sockaddr *)&address, sizeof(address)))
    goto done;
  bound = true;
  if (chmod(address.sun_path, 0600) || listen(server, 8))
    goto done;
  doc = calloc(1, sizeof(*doc));
  if (!doc)
    goto done;
  int pipes[2];
  if (pipe(pipes))
    goto done;
  fflush(NULL);
  pid_t supervisor = getpid();
  child = fork();
  if (child < 0) {
    close(pipes[0]);
    close(pipes[1]);
    goto done;
  }
  if (child == 0) {
    close(server);
    close(lock);
    close(pipes[0]);
    if (dup2(pipes[1], STDOUT_FILENO) < 0 || dup2(pipes[1], STDERR_FILENO) < 0)
      _exit(1);
    close(pipes[1]);
    free(doc);
    int code = worker(a, dir, c, supervisor);
    fflush(NULL);
    _exit(code);
  }
  close(pipes[1]);
  output = pipes[0];
  if (fcntl(output, F_SETFL, O_NONBLOCK) < 0)
    goto done;
  signal(SIGTERM, stop_handler);
  signal(SIGINT, stop_handler);
  signal(SIGPIPE, SIG_IGN);
  bool signalled = false;
  uint64_t stopped_at = 0, updated = tc_now_ms(), tx = 0, rx = 0;
  double tx_rate = 0, rx_rate = 0;
  char snapshot[16384] = "{\"state\":\"starting\",\"paths\":[]}";
  char pending[65536];
  size_t used = 0;
  for (;;) {
    pid_t waited = waitpid(child, &child_status, WNOHANG);
    if (waited == child) {
      reaped = true;
      break;
    }
    if (waited < 0 && errno != EINTR)
      goto done;
    if (stop_requested && !signalled) {
      kill(child, SIGTERM);
      signalled = true;
      stopped_at = tc_now_ms();
    }
    if (signalled && tc_now_ms() - stopped_at > 5000)
      kill(child, SIGKILL);
    struct pollfd fds[2] = {{.fd = server, .events = POLLIN},
                            {.fd = output, .events = POLLIN}};
    int ready = poll(fds, 2, 200);
    if (ready < 0 && errno != EINTR)
      goto done;
    if (ready <= 0)
      continue;
    if (fds[1].revents & (POLLIN | POLLHUP)) {
      ssize_t n = read(output, pending + used, sizeof(pending) - 1 - used);
      if (n > 0) {
        used += n;
        pending[used] = 0;
        char *line = pending, *end;
        while ((end = strchr(line, '\n'))) {
          *end = 0;
          if (!strncmp(line, "QLINQ_STATUS ", 13)) {
            const char *text = line + 13;
            if (strlen(text) < sizeof(snapshot) && tj_parse(doc, text) &&
                doc->nodes[0].type == TJ_OBJECT &&
                tj_string(doc, &doc->nodes[0], "state")) {
              uint64_t now = tc_now_ms(), next_tx = counter(doc, "tx_bytes"),
                       next_rx = counter(doc, "rx_bytes");
              double elapsed = now > updated ? (double)(now - updated) : 1.0;
              tx_rate = next_tx >= tx ? (next_tx - tx) * 0.008 / elapsed : 0;
              rx_rate = next_rx >= rx ? (next_rx - rx) * 0.008 / elapsed : 0;
              tx = next_tx;
              rx = next_rx;
              updated = now;
              strcpy(snapshot, text);
            }
          } else
            log_line(runtime, line, c->token);
          line = end + 1;
        }
        used -= (size_t)(line - pending);
        memmove(pending, line, used);
        if (used == sizeof(pending) - 1)
          used = 0;
      }
    }
    if (fds[0].revents & POLLIN) {
      int fd = accept(server, NULL, NULL);
      if (fd < 0)
        continue;
      struct timeval timeout = {.tv_sec = 2};
      setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
      char request[128];
      ssize_t length = recv(fd, request, sizeof(request) - 1, 0);
      if (length > 0) {
        request[length] = 0;
        request[strcspn(request, "\r\n")] = 0;
        if (!strcmp(request, "down")) {
          stop_requested = 1;
          send_all(fd, "{\"state\":\"stopping\"}", 20);
        } else if (!strcmp(request, "status")) {
          char *reply = NULL;
          size_t size;
          FILE *f = open_memstream(&reply, &size);
          if (f) {
            fputs("{\"name\":", f);
            tj_quote(f, a->name);
            fputs(",\"interface\":", f);
            tj_quote(f, c->interface);
            fprintf(
                f,
                ",\"supervisor_pid\":%ld,\"mock\":%s,\"snapshot_age_ms\":%llu,"
                "\"tx_mbps\":%.3f,\"rx_mbps\":%.3f,%s",
                (long)getpid(), a->mock ? "true" : "false",
                (unsigned long long)(tc_now_ms() - updated), tx_rate, rx_rate,
                snapshot + 1);
            fclose(f);
            send_all(fd, reply, size);
            free(reply);
          }
        } else
          send_all(fd, "{\"error\":\"unknown command\"}", 27);
      }
      close(fd);
    }
  }
  result = stop_requested ||
                   (WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0)
               ? 0
               : 1;
  if (result)
    tc_error("transport exited; see %s/tunnel.log", runtime);
done:
  if (child > 0 && !reaped) {
    kill(child, SIGTERM);
    uint64_t until = tc_now_ms() + 5000;
    while (waitpid(child, &child_status, WNOHANG) == 0) {
      if (tc_now_ms() >= until)
        kill(child, SIGKILL);
      usleep(10000);
    }
  }
  if (output >= 0)
    close(output);
  if (server >= 0)
    close(server);
  if (bound)
    unlink(address.sun_path);
  if (lock >= 0)
    close(lock);
  free(doc);
  return result;
}

static int start(const tc_args *a, const char *dir, const tc_config *c,
                 char *reply) {
  int existing = control(dir, "status", reply);
  if (existing < 0)
    return 1;
  if (existing) {
    printf("%s: already running\n", a->name);
    return 0;
  }
  char runtime[PATH_MAX];
  if (!tc_path(runtime, dir, "run") || !tc_secure_dir(runtime, true))
    return 1;
  int log = open_log(runtime, "startup.log", O_TRUNC);
  if (log < 0)
    return 1;
  fflush(NULL);
  pid_t child = fork();
  if (child < 0) {
    close(log);
    return 1;
  }
  if (!child) {
    if (setsid() < 0)
      _exit(1);
    int null = open("/dev/null", O_RDONLY);
    if (null >= 0) {
      dup2(null, STDIN_FILENO);
      close(null);
    }
    dup2(log, STDOUT_FILENO);
    dup2(log, STDERR_FILENO);
    close(log);
    int code = serve(a, dir, c);
    fflush(NULL);
    _exit(code);
  }
  close(log);
  tj_doc *d = calloc(1, sizeof(*d));
  int status;
  for (unsigned i = 0; d && i < 100; i++) {
    if (waitpid(child, &status, WNOHANG) == child) {
      tc_error("startup failed; see %s/startup.log and tunnel.log", runtime);
      free(d);
      return 1;
    }
    if (control(dir, "status", reply) == 1 && tj_parse(d, reply)) {
      const char *state = tj_string(d, &d->nodes[0], "state");
      if (state && strcmp(state, "starting")) {
        printf("%s: %s; use status to check peer connectivity\n", a->name,
               state);
        free(d);
        return 0;
      }
    }
    usleep(50000);
  }
  kill(child, SIGTERM);
  uint64_t until = tc_now_ms() + 7000;
  while (waitpid(child, &status, WNOHANG) == 0) {
    if (tc_now_ms() >= until)
      kill(child, SIGKILL);
    usleep(10000);
  }
  free(d);
  tc_error("startup timed out; see %s/tunnel.log", runtime);
  return 1;
}

static void print_status(const char *name, const char *reply) {
  tj_doc *d = calloc(1, sizeof(*d));
  if (!d || !tj_parse(d, reply)) {
    free(d);
    return;
  }
  const char *state = tj_string(d, &d->nodes[0], "state");
  printf("%s: %s\n", name, state ? state : "unknown");
  if (counter(d, "snapshot_age_ms") > 3000)
    puts("WARNING: transport health snapshot is stale");
  const tj_node *tx = tj_get(d, &d->nodes[0], "tx_mbps"),
                *rx = tj_get(d, &d->nodes[0], "rx_mbps");
  if (tx && rx)
    printf("TX %s Mbps / RX %s Mbps; recovered %llu FEC objects; dropped %llu "
           "packets\n",
           tx->text, rx->text, (unsigned long long)counter(d, "fec_recovered"),
           (unsigned long long)counter(d, "dropped"));
  const tj_node *paths = tj_get(d, &d->nodes[0], "paths");
  if (paths && paths->type == TJ_ARRAY) {
    for (int i = paths->child; i >= 0; i = d->nodes[i].next) {
      const tj_node *p = &d->nodes[i], *active = tj_get(d, p, "active");
      const char *iface = tj_string(d, p, "interface"),
                 *address = tj_string(d, p, "address");
      uint64_t rtt = 0, sent = 0, received = 0;
      tj_u64(tj_get(d, p, "rtt_ms"), &rtt);
      tj_u64(tj_get(d, p, "tx_bytes"), &sent);
      tj_u64(tj_get(d, p, "rx_bytes"), &received);
      printf("  %s %s (%s): RTT %llu ms, wire TX %llu / RX %llu bytes\n",
             iface ? iface : "?", address ? address : "?",
             active && active->text && !strcmp(active->text, "true")
                 ? "active"
                 : "not validated",
             (unsigned long long)rtt, (unsigned long long)sent,
             (unsigned long long)received);
    }
  }
  free(d);
}

int tun_control_main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  umask(077);
  for (int i = 1; i < argc; i++)
    if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
      help();
      return 0;
    }
  tc_args a;
  if (!parse(argc, argv, &a)) {
    help();
    return 1;
  }
  char dir[PATH_MAX];
  bool init = !strcmp(a.action, "init");
  if (!tc_profile_dir(&a, dir, init))
    return 1;
  if (init)
    return tc_init(&a, dir);
  tc_config config;
  if (!tc_load(dir, &config))
    return 1;
  char *reply = calloc(TJ_MAX_BYTES + 1, 1);
  if (!reply)
    return 1;
  int result = 0;
  if (!strcmp(a.action, "metrics"))
    result = export_metrics(&a, dir, reply);
  else if (!strcmp(a.action, "run"))
    result = serve(&a, dir, &config);
  else if (!strcmp(a.action, "up"))
    result = start(&a, dir, &config, reply);
  else {
    int status =
        control(dir, !strcmp(a.action, "down") ? "down" : "status", reply);
    if (status < 0) {
      free(reply);
      return 1;
    }
    if (!status)
      strcpy(reply, "{\"state\":\"stopped\"}");
    if (!strcmp(a.action, "pair")) {
      if (status) {
        tc_error("stop the tunnel before changing its trusted peer");
        result = 1;
      } else
        result = tc_pair(&a, dir, &config);
    } else if (!strcmp(a.action, "down")) {
      for (unsigned i = 0; status && i < 150; i++) {
        usleep(50000);
        status = control(dir, "status", reply);
      }
      if (status) {
        tc_error("shutdown failed or is taking too long");
        result = 1;
      } else
        printf("%s: stopped\n", a.name);
    } else if (!strcmp(a.action, "status")) {
      if (a.json)
        puts(reply);
      else
        print_status(a.name, reply);
    } else if (!strcmp(a.action, "diagnose")) {
      fputs("{\"config\":", stdout);
      tc_write(stdout, &config, true);
      printf(",\"status\":%s}\n", reply);
    } else if (!strcmp(a.action, "diag")) {
      tc_report report;
      tc_check(dir, &config, a.mock, status == 1, &report);
      result = report.error_count ? 1 : 0;
      if (a.json) {
        printf("{\"ok\":%s,\"errors\":[", result ? "false" : "true");
        for (unsigned i = 0; i < report.error_count; i++) {
          if (i)
            putchar(',');
          tj_quote(stdout, report.errors[i]);
        }
        fputs("],\"warnings\":[", stdout);
        for (unsigned i = 0; i < report.warning_count; i++) {
          if (i)
            putchar(',');
          tj_quote(stdout, report.warnings[i]);
        }
        printf("],\"status\":%s}\n", reply);
      } else {
        for (unsigned i = 0; i < report.error_count; i++)
          printf("ERROR: %s\n", report.errors[i]);
        for (unsigned i = 0; i < report.warning_count; i++)
          printf("WARNING: %s\n", report.warnings[i]);
        if (!result)
          puts("Local checks passed. Peer reachability is confirmed only by "
               "connected status.");
      }
    }
  }
  free(reply);
  return result;
}

int main(int argc, char **argv) {
  if (argc > 1 && argv[1][0] == '-' && strcmp(argv[1], "--config-dir") &&
      strcmp(argv[1], "--help") && strcmp(argv[1], "-h"))
    return tun_worker_main(argc, argv);
  return tun_control_main(argc, argv);
}
