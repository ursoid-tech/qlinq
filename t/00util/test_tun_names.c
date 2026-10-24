/* deterministic interface-name resolution without changing host networking */
#define getifaddrs test_getifaddrs
#define freeifaddrs test_freeifaddrs
#include "../../src/host/linux/tun_device.c"
#undef getifaddrs
#undef freeifaddrs

#include <assert.h>

static struct ifaddrs interfaces[5];
static struct sockaddr_in ipv4;
static struct sockaddr_in6 ipv6;
static int lookup_error, lookups, frees;

int test_getifaddrs(struct ifaddrs **result) {
  lookups++;
  if (lookup_error) {
    errno = EIO;
    return -1;
  }
  *result = interfaces;
  return 0;
}

void test_freeifaddrs(struct ifaddrs *list) {
  assert(list == interfaces);
  frees++;
}

static void check_interface(const char *address, const char *interface,
                            const char *expected) {
  char name[64];
  memset(name, 0xa5, sizeof(name));
  tun_resolve_interface_name(address, interface, name);
  assert(strcmp(name, expected) == 0);
}

static void check(const char *address, const char *expected) {
  check_interface(address, NULL, expected);
}

int main(void) {
  /* loopback detection is independent of enumeration and link state */
  lookup_error = 1;
  check("127.0.0.1", "lo");
  check("127.1.2.3", "lo");
  check("127.255.255.255", "lo");
  check("::1", "lo");
  check("0:0:0:0:0:0:0:1", "lo");
  check("::ffff:127.2.3.4", "lo");
  check("::ffff:7f00:1", "lo");
  assert(lookups == 0 && frees == 0);
  check("192.0.2.1", "fallback");
  assert(lookups == 1 && frees == 0);
  check(NULL, "fallback");
  check("", "fallback");
  check("invalid", "fallback");
  check("127.0.0.1junk", "fallback");
  /* transport identities survive failed lookups; special addresses retain
   * normalization */
  check_interface("192.0.2.1", "eth-known", "eth-known");
  check_interface("127.0.0.1", "eth-known", "lo");
  check_interface("::ffff:127.2.3.4", "eth-known", "lo");
  check_interface("invalid", "eth-known", "fallback");
  check_interface("0.0.0.0", "eth-known", "fallback");
  check_interface("::", "eth-known", "fallback");
  assert(lookups == 1);

  lookup_error = 0;
  ipv4.sin_family = AF_INET;
  ipv6.sin6_family = AF_INET6;
  assert(inet_pton(AF_INET, "192.0.2.1", &ipv4.sin_addr) == 1);
  assert(inet_pton(AF_INET6, "2001:db8::1", &ipv6.sin6_addr) == 1);
  /* null addresses and unnamed entries must not interfere with a match */
  interfaces[0].ifa_next = &interfaces[1];
  interfaces[1].ifa_addr = (struct sockaddr *)&ipv4;
  interfaces[1].ifa_next = &interfaces[2];
  interfaces[2].ifa_addr = (struct sockaddr *)&ipv4;
  interfaces[2].ifa_name = "eth-test";
  interfaces[2].ifa_next = &interfaces[3];
  interfaces[3].ifa_addr = (struct sockaddr *)&ipv6;
  interfaces[3].ifa_name = "wwan-test";
  check("192.0.2.1", "eth-test");
  check("::ffff:192.0.2.1", "eth-test");
  check("2001:db8::1", "wwan-test");
  check("192.0.2.2", "fallback");
  check("126.255.255.255", "fallback");
  check("128.0.0.1", "fallback");
  check("2001:db8::2", "fallback");
  check("0.0.0.0", "fallback");
  check("::", "fallback");
  check_interface("192.0.2.2", "eth-known", "eth-known");
  /* address used as a placeholder is not a transport device identity */
  check_interface("192.0.2.1", "192.0.2.1", "eth-test");
  check_interface("192.0.2.1", "", "eth-test");
  check_interface("192.0.2.2", "192.0.2.2", "fallback");
  assert(lookups == frees + 1);

  /* duplicate entries on one device are fine; different devices are ambiguous
   */
  interfaces[3].ifa_next = &interfaces[4];
  interfaces[4].ifa_addr = (struct sockaddr *)&ipv4;
  interfaces[4].ifa_name = "eth-test";
  check("192.0.2.1", "eth-test");
  interfaces[4].ifa_name = "other-test";
  check("192.0.2.1", "fallback");
  interfaces[4].ifa_addr = (struct sockaddr *)&ipv6;
  check("2001:db8::1", "fallback");
  interfaces[4].ifa_name = "";
  check("2001:db8::1", "wwan-test");
  /* link-local addresses need transport device identity to distinguish paths */
  assert(inet_pton(AF_INET6, "fe80::1", &ipv6.sin6_addr) == 1);
  interfaces[4].ifa_name = "other-test";
  check("fe80::1", "fallback");
  int before = lookups;
  check_interface("fe80::1", "wwan-test", "wwan-test");
  check_interface("fe80::1", "other-test", "other-test");
  assert(lookups == before);
  char oversized_name[65];
  memset(oversized_name, 'x', sizeof(oversized_name) - 1);
  oversized_name[sizeof(oversized_name) - 1] = 0;
  interfaces[2].ifa_name = oversized_name;
  check("192.0.2.1", "fallback");
  check_interface("192.0.2.1", oversized_name, "fallback");
  assert(lookups == frees + 1);
  puts("=== TUN INTERFACE NAMES OK ===");
  return 0;
}
