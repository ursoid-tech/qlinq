#include "cli_parse.h"
#include "tun_control.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

bool tc_error(const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  fputs("qlinq-tun: ", stderr);
  vfprintf(stderr, format, ap);
  fputc('\n', stderr);
  va_end(ap);
  return false;
}

uint64_t tc_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

bool tc_path(char out[PATH_MAX], const char *dir, const char *name) {
  int n = snprintf(out, PATH_MAX, "%s/%s", dir, name);
  return n > 0 && n < PATH_MAX;
}

static bool name_ok(const char *s, size_t max) {
  if (!s || !*s || strlen(s) > max || !isalnum((unsigned char)*s))
    return false;
  for (; *s; s++)
    if (!isalnum((unsigned char)*s) && !strchr("_.-", *s))
      return false;
  return true;
}

static bool mkdir_parents(const char *path) {
  char buffer[PATH_MAX];
  if (strlen(path) >= sizeof(buffer))
    return false;
  strcpy(buffer, path);
  for (char *p = buffer + 1;; p++) {
    if (*p == '/' || !*p) {
      char saved = *p;
      *p = 0;
      if (mkdir(buffer, 0700) != 0 && errno != EEXIST)
        return false;
      *p = saved;
      if (!saved)
        break;
    }
  }
  return true;
}

bool tc_secure_dir(const char *path, bool create) {
  struct stat st;
  if (create && !mkdir_parents(path))
    return tc_error("cannot create %s: %s", path, strerror(errno));
  if (lstat(path, &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
      (st.st_mode & 077))
    return tc_error(
        "%s must be a private directory owned by the current user (mode 700)",
        path);
  return true;
}

bool tc_profile_dir(const tc_args *a, char dir[PATH_MAX], bool create_root) {
  char root[PATH_MAX];
  if (!name_ok(a->name, 32))
    return tc_error(
        "invalid tunnel name (use 1..32 letters, digits, '.', '_' or '-')");
  if (!tc_secure_dir(a->root, create_root) || !realpath(a->root, root) ||
      !tc_path(dir, root, a->name))
    return false;
  return create_root || tc_secure_dir(dir, false);
}

static bool ipv4(const char *s, uint32_t *out) {
  struct in_addr address;
  if (inet_pton(AF_INET, s, &address) != 1)
    return false;
  *out = ntohl(address.s_addr);
  return *out != 0 && (*out & 0xf0000000U) != 0xe0000000U;
}

static bool network(const char *s, uint32_t *ip, uint32_t *mask) {
  char copy[32];
  if (strlen(s) >= sizeof(copy))
    return false;
  strcpy(copy, s);
  char *slash = strchr(copy, '/');
  uint64_t bits;
  struct in_addr address;
  if (!slash)
    return false;
  *slash++ = 0;
  if (!cli_parse_u64(slash, 32, &bits) || bits == 0 ||
      inet_pton(AF_INET, copy, &address) != 1)
    return false;
  *ip = ntohl(address.s_addr);
  *mask = UINT32_MAX << (32 - bits);
  return (*ip & ~*mask) == 0;
}

static bool hex_string(const char *s, size_t n) {
  return strlen(s) == n && strspn(s, "0123456789abcdef") == n;
}

bool tc_validate(const tc_config *c) {
  uint32_t endpoint, local, peer;
  if (!hex_string(c->id, 32) || !hex_string(c->token, 64) ||
      (strcmp(c->role, "listen") && strcmp(c->role, "connect")) ||
      !ipv4(c->endpoint, &endpoint) || !ipv4(c->local_ip, &local) ||
      !ipv4(c->peer_ip, &peer) || local == peer || endpoint == local ||
      endpoint == peer)
    return tc_error("invalid tunnel identity or endpoint addresses");
  if (!c->port || c->port > 65535 || c->mtu < 1280 || c->mtu > 2000 ||
      !c->queue_ms || c->queue_ms > 60000 || !name_ok(c->interface, 15) ||
      !name_ok(c->run_as, 32) || !c->uplink_count || c->uplink_count > 4 ||
      c->route_count > 16)
    return tc_error(
        "invalid port, MTU, queue limit, interface or service account");
  if (strcmp(c->mode, "fixedrate") && strcmp(c->mode, "rateless") &&
      strcmp(c->mode, "datagram") && strcmp(c->mode, "reliable"))
    return tc_error("invalid delivery mode");
  for (unsigned i = 0; i < c->uplink_count; i++) {
    if (!name_ok(c->uplinks[i], 15) || !strcmp(c->uplinks[i], c->interface))
      return tc_error("invalid uplink or tunnel included in uplinks");
    for (unsigned j = 0; j < i; j++)
      if (!strcmp(c->uplinks[i], c->uplinks[j]))
        return tc_error("duplicate uplink");
  }
  for (unsigned i = 0; i < c->route_count; i++) {
    uint32_t ip, mask;
    if (!network(c->routes[i], &ip, &mask) || (endpoint & mask) == ip ||
        (local & mask) == ip || (peer & mask) == ip)
      return tc_error("invalid/default route or route overlaps an endpoint");
    for (unsigned j = 0; j < i; j++) {
      uint32_t other, other_mask;
      if (!network(c->routes[j], &other, &other_mask) ||
          (ip & other_mask) == other || (other & mask) == ip)
        return tc_error("configured routes overlap");
    }
  }
  return true;
}

static bool copy_string(char *out, size_t size, const char *s) {
  if (!s || strlen(s) >= size)
    return false;
  strcpy(out, s);
  return true;
}

bool tc_decode(const tj_doc *d, const tj_node *obj, tc_config *c) {
  if (!obj || obj->type != TJ_OBJECT)
    return tc_error("expected a configuration object");
  memset(c, 0, sizeof(*c));
  unsigned fields = 0;
  for (int i = obj->child; i >= 0; i = d->nodes[d->nodes[i].next].next)
    fields++;
  uint64_t v;
  if (fields != 15 || !tj_u64(tj_get(d, obj, "schema"), &v) || v != 1)
    return tc_error("unsupported or incomplete profile schema");
#define FIELD(key)                                                             \
  if (!copy_string(c->key, sizeof(c->key), tj_string(d, obj, #key)))           \
  return tc_error("invalid field: " #key)
  FIELD(id);
  FIELD(role);
  FIELD(endpoint);
  FIELD(local_ip);
  FIELD(peer_ip);
  FIELD(interface);
  FIELD(mode);
  FIELD(run_as);
  FIELD(token);
#undef FIELD
#define NUMBER(key)                                                            \
  if (!tj_u64(tj_get(d, obj, #key), &v) || v > UINT32_MAX)                     \
    return tc_error("invalid integer: " #key);                                 \
  c->key = (unsigned)v
  NUMBER(port);
  NUMBER(mtu);
  NUMBER(queue_ms);
#undef NUMBER
  const tj_node *array = tj_get(d, obj, "uplinks");
  if (!array || array->type != TJ_ARRAY)
    return tc_error("uplinks must be an array");
  for (int i = array->child; i >= 0; i = d->nodes[i].next) {
    if (c->uplink_count == 4 || d->nodes[i].type != TJ_STRING ||
        !copy_string(c->uplinks[c->uplink_count++], 16, d->nodes[i].text))
      return tc_error("invalid uplink list");
  }
  array = tj_get(d, obj, "routes");
  if (!array || array->type != TJ_ARRAY)
    return tc_error("routes must be an array");
  for (int i = array->child; i >= 0; i = d->nodes[i].next) {
    if (c->route_count == 16 || d->nodes[i].type != TJ_STRING ||
        !copy_string(c->routes[c->route_count++], 32, d->nodes[i].text))
      return tc_error("invalid route list");
  }
  return tc_validate(c);
}

bool tc_load(const char *directory, tc_config *config) {
  char path[PATH_MAX];
  tj_doc *d = calloc(1, sizeof(*d));
  bool ok = d && tc_path(path, directory, "config.json") && tj_load(d, path);
  if (!ok)
    tc_error("cannot read a valid config.json");
  else
    ok = tc_decode(d, &d->nodes[0], config);
  free(d);
  return ok;
}

void tc_write(FILE *f, const tc_config *c, bool redacted) {
  fprintf(f, "{\"schema\":1,\"port\":%u,\"mtu\":%u,\"queue_ms\":%u", c->port,
          c->mtu, c->queue_ms);
#define FIELD(key)                                                             \
  fputs(",\"" #key "\":", f);                                                  \
  tj_quote(f, c->key)
  FIELD(role);
  FIELD(endpoint);
  FIELD(local_ip);
  FIELD(peer_ip);
  FIELD(interface);
  FIELD(mode);
  if (!redacted) {
    FIELD(id);
    FIELD(run_as);
    FIELD(token);
  }
#undef FIELD
  fputs(",\"uplinks\":[", f);
  for (unsigned i = 0; i < c->uplink_count; i++) {
    if (i)
      fputc(',', f);
    tj_quote(f, c->uplinks[i]);
  }
  fputs("],\"routes\":[", f);
  for (unsigned i = 0; i < c->route_count; i++) {
    if (i)
      fputc(',', f);
    tj_quote(f, c->routes[i]);
  }
  fputs("]}", f);
}

static FILE *new_file(const char *dir, const char *name) {
  char path[PATH_MAX];
  if (!tc_path(path, dir, name))
    return NULL;
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0)
    return NULL;
  FILE *f = fdopen(fd, "w");
  if (!f)
    close(fd);
  return f;
}

static bool finish(FILE *f) {
  bool ok = !ferror(f);
  return fclose(f) == 0 && ok;
}

static X509 *parse_cert(const char *text) {
  if (!text || strlen(text) > 16384)
    return NULL;
  BIO *b = BIO_new_mem_buf(text, -1);
  X509 *x = b ? PEM_read_bio_X509(b, NULL, NULL, NULL) : NULL;
  BIO_free(b);
  if (x && (X509_cmp_current_time(X509_get0_notAfter(x)) != 1 ||
            X509_cmp_current_time(X509_get0_notBefore(x)) != -1)) {
    X509_free(x);
    x = NULL;
  }
  return x;
}

static void fingerprint(X509 *x) {
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned n;
  if (X509_digest(x, EVP_sha256(), digest, &n) != 1)
    return;
  fputs("SHA256 Fingerprint=", stdout);
  for (unsigned i = 0; i < n; i++)
    printf("%s%02X", i ? ":" : "", digest[i]);
  putchar('\n');
}

static bool random_hex(char *out, unsigned bytes) {
  unsigned char buffer[32];
  if (bytes > sizeof(buffer) || RAND_bytes(buffer, bytes) != 1)
    return false;
  for (unsigned i = 0; i < bytes; i++)
    sprintf(out + i * 2, "%02x", buffer[i]);
  return true;
}

static bool extension(X509 *x, int nid, const char *value) {
  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
  X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
  bool ok = ext && X509_add_ext(x, ext, -1) == 1;
  X509_EXTENSION_free(ext);
  return ok;
}

static char *new_identity(const char *dir, const tc_config *c) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  EVP_PKEY *key = NULL;
  X509 *x = X509_new();
  BIO *pem = NULL;
  char *result = NULL, cn[64], san[64];
  unsigned char serial[16];
  BIGNUM *bn = NULL;
  if (!ctx || !x || EVP_PKEY_keygen_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0 ||
      EVP_PKEY_keygen(ctx, &key) <= 0 ||
      RAND_bytes(serial, sizeof(serial)) != 1)
    goto done;
  bn = BN_bin2bn(serial, sizeof(serial), NULL);
  if (!bn || !BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x)) ||
      !X509_set_version(x, 2) || !X509_set_pubkey(x, key) ||
      !X509_gmtime_adj(X509_getm_notBefore(x), -60) ||
      !X509_gmtime_adj(X509_getm_notAfter(x), 365L * 86400))
    goto done;
  snprintf(cn, sizeof(cn), "qlinq-%s", c->id);
  snprintf(san, sizeof(san), "IP:%s", c->endpoint);
  X509_NAME *name = X509_get_subject_name(x);
  if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)cn,
                                  -1, -1, 0) ||
      !X509_set_issuer_name(x, name) ||
      !extension(x, NID_subject_alt_name, san) ||
      !extension(x, NID_basic_constraints, "critical,CA:TRUE") ||
      !extension(x, NID_key_usage, "critical,digitalSignature,keyCertSign") ||
      !extension(x, NID_ext_key_usage, "serverAuth,clientAuth") ||
      !X509_sign(x, key, EVP_sha256()))
    goto done;
  FILE *f = new_file(dir, "identity.key");
  if (!f)
    goto done;
  bool written = PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL) == 1;
  if (!finish(f) || !written)
    goto done;
  f = new_file(dir, "identity.crt");
  if (!f)
    goto done;
  written = PEM_write_X509(f, x) == 1;
  if (!finish(f) || !written)
    goto done;
  pem = BIO_new(BIO_s_mem());
  if (pem && PEM_write_bio_X509(pem, x) == 1) {
    char *data;
    long size = BIO_get_mem_data(pem, &data);
    result = strndup(data, size);
  }
done:
  BIO_free(pem);
  BN_free(bn);
  X509_free(x);
  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(ctx);
  return result;
}

int tc_init(const tc_args *a, const char *dir) {
  tc_config c = {.port = 8888, .mtu = 1400, .queue_ms = 100};
  tj_doc *invite = NULL;
  X509 *peer = NULL, *own = NULL;
  char *own_pem = NULL;
  const char *peer_pem = NULL;
  bool created = false;
  int result = 1;
  if (a->invite) {
    invite = calloc(1, sizeof(*invite));
    uint64_t schema;
    if (!invite || !tj_load(invite, a->invite) ||
        !tj_u64(tj_get(invite, &invite->nodes[0], "schema"), &schema) ||
        schema != 1 || !tj_string(invite, &invite->nodes[0], "kind") ||
        strcmp(tj_string(invite, &invite->nodes[0], "kind"), "qlinq-invite") ||
        !tc_decode(invite, tj_get(invite, &invite->nodes[0], "config"), &c) ||
        strcmp(c.role, "listen")) {
      tc_error("invalid invitation");
      goto done;
    }
    peer_pem = tj_string(invite, &invite->nodes[0], "certificate");
    peer = parse_cert(peer_pem);
    if (!peer) {
      tc_error("invalid or expired listener certificate");
      goto done;
    }
    strcpy(c.role, "connect");
    char swap[16];
    strcpy(swap, c.peer_ip);
    strcpy(c.peer_ip, c.local_ip);
    strcpy(c.local_ip, swap);
  } else {
    uint16_t port = 8888;
    if (!cli_parse_endpoint(a->listen, c.endpoint, sizeof(c.endpoint), &port,
                            NULL) ||
        !random_hex(c.id, 16) || !random_hex(c.token, 32)) {
      tc_error("invalid listener address or random generator failure");
      goto done;
    }
    c.port = port;
    strcpy(c.role, "listen");
    strcpy(c.mode, "fixedrate");
    if (!copy_string(c.local_ip, sizeof(c.local_ip), a->local_ip) ||
        !copy_string(c.peer_ip, sizeof(c.peer_ip), a->peer_ip))
      goto invalid;
  }
  if (a->interface) {
    if (!copy_string(c.interface, sizeof(c.interface), a->interface))
      goto invalid;
  } else {
    unsigned char digest[32];
    unsigned length;
    if (!EVP_Digest(a->name, strlen(a->name), digest, &length, EVP_sha256(),
                    NULL))
      goto invalid;
    strcpy(c.interface, "ql");
    for (unsigned i = 0; i < 5; i++)
      sprintf(c.interface + 2 + i * 2, "%02x", digest[i]);
  }
  if (!copy_string(c.run_as, sizeof(c.run_as), a->run_as))
    goto invalid;
  c.uplink_count = a->uplink_count;
  c.route_count = a->route_count;
  for (unsigned i = 0; i < c.uplink_count; i++)
    if (!copy_string(c.uplinks[i], sizeof(c.uplinks[i]), a->uplinks[i]))
      goto invalid;
  for (unsigned i = 0; i < c.route_count; i++)
    if (!copy_string(c.routes[i], sizeof(c.routes[i]), a->routes[i]))
      goto invalid;
  if (!tc_validate(&c))
    goto done;
  if (mkdir(dir, 0700)) {
    tc_error("cannot create profile (already exists or inaccessible)");
    goto done;
  }
  created = true;
  own_pem = new_identity(dir, &c);
  if (!own_pem)
    goto io_failure;
  FILE *f = new_file(dir, "config.json");
  if (!f)
    goto io_failure;
  tc_write(f, &c, false);
  if (!finish(f))
    goto io_failure;
  if (peer_pem) {
    f = new_file(dir, "peer.crt");
    if (!f)
      goto io_failure;
    fputs(peer_pem, f);
    if (!finish(f))
      goto io_failure;
  }
  f = new_file(dir, peer_pem ? "peer.json" : "invite.json");
  if (!f)
    goto io_failure;
  if (peer_pem) {
    fprintf(f, "{\"schema\":1,\"kind\":\"qlinq-peer\",\"id\":\"%s\",", c.id);
  } else {
    fputs("{\"schema\":1,\"kind\":\"qlinq-invite\",\"config\":", f);
    tc_write(f, &c, false);
    fputc(',', f);
  }
  fputs("\"certificate\":", f);
  tj_quote(f, own_pem);
  fputs("}\n", f);
  if (!finish(f))
    goto io_failure;
  printf("Created %s. %s %s/%s to the %s.\n", a->name,
         peer_pem ? "Send" : "Securely transfer", dir,
         peer_pem ? "peer.json" : "invite.json",
         peer_pem ? "listener" : "client");
  if (!peer_pem)
    puts("The invitation contains a secret; private identity keys stay on this "
         "machine.");
  if (peer) {
    fputs("Listener ", stdout);
    fingerprint(peer);
  }
  own = parse_cert(own_pem);
  if (own) {
    fputs("Local ", stdout);
    fingerprint(own);
  }
  result = 0;
  goto done;
invalid:
  tc_error("invalid configuration argument");
  goto done;
io_failure:
  tc_error("failed to create identity/profile: %s", strerror(errno));
done:
  if (created && result) {
    const char *files[] = {"identity.key", "identity.crt", "config.json",
                           "peer.crt",     "peer.json",    "invite.json"};
    char path[PATH_MAX];
    for (unsigned i = 0; i < sizeof(files) / sizeof(files[0]); i++)
      if (tc_path(path, dir, files[i]))
        unlink(path);
    rmdir(dir);
  }
  X509_free(own);
  X509_free(peer);
  free(own_pem);
  free(invite);
  return result;
}

int tc_pair(const tc_args *a, const char *dir, const tc_config *c) {
  tj_doc *d = calloc(1, sizeof(*d));
  X509 *x = NULL;
  int result = 1;
  uint64_t schema;
  if (strcmp(c->role, "listen") || !d || !tj_load(d, a->identity) ||
      !tj_u64(tj_get(d, &d->nodes[0], "schema"), &schema) || schema != 1 ||
      !tj_string(d, &d->nodes[0], "kind") ||
      strcmp(tj_string(d, &d->nodes[0], "kind"), "qlinq-peer") ||
      !tj_string(d, &d->nodes[0], "id") ||
      strcmp(tj_string(d, &d->nodes[0], "id"), c->id)) {
    tc_error("peer identity does not belong to this listener invitation");
    goto done;
  }
  const char *cert = tj_string(d, &d->nodes[0], "certificate");
  x = parse_cert(cert);
  if (!x) {
    tc_error("invalid or expired peer certificate");
    goto done;
  }
  FILE *f = new_file(dir, "peer.crt");
  if (!f) {
    char path[PATH_MAX];
    tc_path(path, dir, "peer.crt");
    BIO *b = BIO_new_file(path, "r");
    X509 *old = b ? PEM_read_bio_X509(b, NULL, NULL, NULL) : NULL;
    if (old && X509_cmp(old, x) == 0) {
      puts("This peer is already paired.");
      result = 0;
    } else
      tc_error(
          "a different peer is already paired or peer.crt cannot be created");
    X509_free(old);
    BIO_free(b);
    goto done;
  }
  fputs(cert, f);
  if (!finish(f)) {
    tc_error("failed writing peer.crt");
    goto done;
  }
  puts("Paired. Verify this fingerprint with the client over your trusted "
       "channel:");
  fingerprint(x);
  result = 0;
done:
  X509_free(x);
  free(d);
  return result;
}

unsigned tc_addresses(const tc_config *c, char addresses[4][16],
                      bool found[4]) {
  struct ifaddrs *list;
  memset(found, 0, 4 * sizeof(bool));
  unsigned count = 0;
  if (getifaddrs(&list))
    return 0;
  for (unsigned i = 0; i < c->uplink_count; i++) {
    for (struct ifaddrs *p = list; p; p = p->ifa_next) {
      if (p->ifa_addr && p->ifa_addr->sa_family == AF_INET &&
          (p->ifa_flags & IFF_UP) && !strcmp(p->ifa_name, c->uplinks[i])) {
        struct sockaddr_in *sin = (struct sockaddr_in *)p->ifa_addr;
        inet_ntop(AF_INET, &sin->sin_addr, addresses[count++], 16);
        found[i] = true;
        break;
      }
    }
  }
  freeifaddrs(list);
  return count;
}

static int no_password(char *buffer, int size, int rwflag, void *ctx) {
  (void)buffer;
  (void)size;
  (void)rwflag;
  (void)ctx;
  return 0;
}

static bool route_check(const tc_config *c) {
  int pipes[2];
  if (pipe(pipes))
    return false;
  pid_t pid = fork();
  if (pid < 0) {
    close(pipes[0]);
    close(pipes[1]);
    return false;
  }
  if (!pid) {
    close(pipes[0]);
    dup2(pipes[1], STDOUT_FILENO);
    dup2(pipes[1], STDERR_FILENO);
    close(pipes[1]);
    execlp("ip", "ip", "-j", "route", "get", c->endpoint, (char *)NULL);
    _exit(127);
  }
  close(pipes[1]);
  char buffer[4096];
  size_t used = 0;
  int status = 0;
  uint64_t until = tc_now_ms() + 2000;
  while (used < sizeof(buffer) - 1 && tc_now_ms() < until) {
    struct pollfd p = {.fd = pipes[0], .events = POLLIN};
    if (poll(&p, 1, 100) > 0) {
      ssize_t n = read(pipes[0], buffer + used, sizeof(buffer) - 1 - used);
      if (n <= 0)
        break;
      used += n;
    }
  }
  close(pipes[0]);
  if (waitpid(pid, &status, WNOHANG) == 0) {
    /* bounded wait even when an external ip executable misbehaves */
    for (unsigned i = 0; i < 20; i++) {
      if (waitpid(pid, &status, WNOHANG) == pid)
        goto collected;
      usleep(10000);
    }
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    return false;
  }
collected:
  buffer[used] = 0;
  tj_doc *d = calloc(1, sizeof(*d));
  bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0 && d &&
            tj_parse(d, buffer) && d->nodes[0].type == TJ_ARRAY &&
            d->nodes[0].child >= 0;
  if (ok) {
    const char *dev = tj_string(d, &d->nodes[d->nodes[0].child], "dev");
    ok = dev && strcmp(dev, c->interface);
  }
  free(d);
  return ok;
}

void tc_check(const char *dir, const tc_config *c, bool mock, bool running,
              tc_report *r) {
  memset(r, 0, sizeof(*r));
#define ERROR(...)                                                             \
  do {                                                                         \
    if (r->error_count < 32)                                                   \
      snprintf(r->errors[r->error_count++], 192, __VA_ARGS__);                 \
  } while (0)
#define WARN(...)                                                              \
  do {                                                                         \
    if (r->warning_count < 8)                                                  \
      snprintf(r->warnings[r->warning_count++], 192, __VA_ARGS__);             \
  } while (0)
  char path[PATH_MAX];
  X509 *identity = NULL;
  const char *names[] = {"identity.crt", "peer.crt"};
  for (unsigned i = 0; i < 2; i++) {
    tc_path(path, dir, names[i]);
    BIO *b = BIO_new_file(path, "r");
    X509 *x = b ? PEM_read_bio_X509(b, NULL, NULL, NULL) : NULL;
    BIO_free(b);
    if (!x || X509_cmp_current_time(X509_get0_notAfter(x)) != 1 ||
        X509_cmp_current_time(X509_get0_notBefore(x)) != -1)
      ERROR("missing, invalid or expired %s; complete init/pair first",
            names[i]);
    if (i == 0)
      identity = x;
    else
      X509_free(x);
  }
  tc_path(path, dir, "identity.key");
  struct stat st;
  if (lstat(path, &st) || !S_ISREG(st.st_mode) || (st.st_mode & 077))
    ERROR("identity.key must be a regular private file (mode 600)");
  BIO *b = BIO_new_file(path, "r");
  EVP_PKEY *key =
      b ? PEM_read_bio_PrivateKey(b, NULL, no_password, NULL) : NULL;
  if (!key || !identity || X509_check_private_key(identity, key) != 1)
    ERROR(
        "identity certificate and private key are unreadable or do not match");
  BIO_free(b);
  EVP_PKEY_free(key);
  X509_free(identity);
  if (mock)
    return;
  if (geteuid())
    ERROR("real TUN setup requires root; use sudo");
  if (access("/dev/net/tun", F_OK))
    ERROR("/dev/net/tun missing; enable the Linux tun driver");
  struct passwd *account = getpwnam(c->run_as);
  if (!account || account->pw_uid == 0)
    ERROR("run_as must name an existing unprivileged account");
  char addresses[4][16];
  bool found[4];
  unsigned count = tc_addresses(c, addresses, found);
  if (!count)
    ERROR("no selected uplink has an active IPv4 address");
  for (unsigned i = 0; i < c->uplink_count; i++)
    if (!found[i])
      WARN("unavailable uplink: %s", c->uplinks[i]);
  if (!running && if_nametoindex(c->interface))
    ERROR("tunnel interface already exists; refusing to modify it");
  for (unsigned i = 0; i < count; i++) {
    uint32_t address;
    if (!ipv4(addresses[i], &address)) {
      ERROR("invalid uplink IPv4 address");
      continue;
    }
    for (unsigned j = 0; j < c->route_count; j++) {
      uint32_t ip, mask;
      if (network(c->routes[j], &ip, &mask) && (address & mask) == ip)
        ERROR("route %s overlaps an uplink address", c->routes[j]);
    }
  }
  if (!strcmp(c->role, "connect") && !route_check(c))
    ERROR("no route to transport endpoint, or endpoint routes into the tunnel");
#undef ERROR
#undef WARN
}
