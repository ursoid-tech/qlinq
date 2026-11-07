/* ifmon.c - network interface monitor C library */

#ifndef _WIN32
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
#include <net/if_dl.h>
#include <net/route.h>
#include <sys/sysctl.h>
#endif

#else
#include <iphlpapi.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "ifmon.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ifmon_list_dispose(ifmon_list_t *list) {
  if (!list)
    return;
  free(list->ifaces);
  memset(list, 0, sizeof(*list));
}

void ifmon_update_dispose(ifmon_update_t *update) {
  if (!update)
    return;
  free(update->added);
  free(update->removed);
  free(update->modified);
  memset(update, 0, sizeof(*update));
}

static ifmon_iface_t *append_iface(ifmon_list_t *list) {
  if (list->count == list->capacity) {
    if (list->capacity > INT_MAX / 2)
      return NULL;
    int capacity = list->capacity ? list->capacity * 2 : 16;
    if ((size_t)capacity > SIZE_MAX / sizeof(*list->ifaces))
      return NULL;
    ifmon_iface_t *ifaces =
        realloc(list->ifaces, (size_t)capacity * sizeof(*ifaces));
    if (!ifaces)
      return NULL;
    list->ifaces = ifaces;
    list->capacity = capacity;
  }
  ifmon_iface_t *iface = &list->ifaces[list->count++];
  memset(iface, 0, sizeof(*iface));
  return iface;
}

static void format_mac(const uint8_t *bytes, size_t len, char *out) {
  if (len > 6) {
    len = 6;
  }
  if (len == 0) {
    strncpy(out, "00:00:00:00:00:00", 18);
    return;
  }
  char *p = out;
  for (size_t i = 0; i < len; i++) {
    p += sprintf(p, i == 0 ? "%02X" : ":%02X", bytes[i]);
  }
  for (size_t i = len; i < 6; i++) {
    p += sprintf(p, ":00");
  }
}

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||      \
    defined(__NetBSD__)
static uint8_t count_bits_v4(struct in_addr addr) {
  uint32_t val = ntohl(addr.s_addr);
  uint8_t count = 0;
  while (val & 0x80000000) {
    count++;
    val <<= 1;
  }
  return count;
}

static uint8_t count_bits_v6(struct in6_addr addr) {
  uint8_t count = 0;
  for (int i = 0; i < 16; i++) {
    uint8_t byte = addr.s6_addr[i];
    while (byte & 0x80) {
      count++;
      byte <<= 1;
    }
    if (byte != 0) {
      break;
    }
  }
  return count;
}
#endif

int ifmon_is_default_iface(const char *name) {
  if (!name || name[0] == '\0')
    return 0;

  /* Linux / Generic */
  if (strcmp(name, "lo") == 0 || strncmp(name, "lo:", 3) == 0 ||
      (strncmp(name, "lo", 2) == 0 && name[2] >= '0' && name[2] <= '9'))
    return 0;
  if (strncmp(name, "tun", 3) == 0 || strncmp(name, "ql", 2) == 0)
    return 0;
  if (strncmp(name, "tap", 3) == 0)
    return 0;
  if (strncmp(name, "docker", 6) == 0)
    return 0;
  if (strncmp(name, "br-", 3) == 0)
    return 0;

  /* macOS specific */
  if (strncmp(name, "utun", 4) == 0)
    return 0;
  if (strncmp(name, "llw", 3) == 0)
    return 0; /* Apple low latency wifi */
  if (strncmp(name, "awdl", 4) == 0)
    return 0; /* Apple Wireless Direct Link */

  /* Windows specific */
  if (strstr(name, "Loopback") != NULL)
    return 0;
  if (strstr(name, "vEthernet") != NULL)
    return 0;
  if (strstr(name, "Wintun") != NULL)
    return 0;

  return 1;
}

static const ifmon_iface_t *find_iface(const ifmon_list_t *list,
                                       uint32_t index) {
  for (int i = 0; i < list->count; i++)
    if (list->ifaces[i].index == index)
      return &list->ifaces[i];
  return NULL;
}

static int missing_addresses(const ifmon_iface_t *from,
                             const ifmon_iface_t *other, ifmon_addr_t *out) {
  int count = 0;
  for (int i = 0; i < from->addr_count; i++) {
    const ifmon_addr_t *addr = &from->addrs[i];
    int found = 0;
    for (int j = 0; j < other->addr_count; j++) {
      const ifmon_addr_t *candidate = &other->addrs[j];
      if (addr->family != candidate->family ||
          addr->prefix_len != candidate->prefix_len)
        continue;
      found =
          (addr->family == AF_INET &&
           addr->ip.v4.s_addr == candidate->ip.v4.s_addr) ||
          (addr->family == AF_INET6 &&
           memcmp(&addr->ip.v6, &candidate->ip.v6, sizeof(addr->ip.v6)) == 0);
      if (found)
        break;
    }
    if (!found && count < IFMON_MAX_IPS_PER_IFACE)
      out[count++] = *addr;
  }
  return count;
}

static int generate_update(const ifmon_list_t *prev, const ifmon_list_t *curr,
                           int is_initial, ifmon_update_t *up) {
  ifmon_update_dispose(up);
  up->is_initial = is_initial;
  up->interfaces = curr;
  if (is_initial)
    return 0;

  if (curr->count) {
    up->added = calloc((size_t)curr->count, sizeof(*up->added));
    up->modified = calloc((size_t)curr->count, sizeof(*up->modified));
    if (!up->added || !up->modified)
      goto fail;
  }
  if (prev->count) {
    up->removed = calloc((size_t)prev->count, sizeof(*up->removed));
    if (!up->removed)
      goto fail;
  }

  for (int i = 0; i < curr->count; i++) {
    const ifmon_iface_t *curr_if = &curr->ifaces[i];
    const ifmon_iface_t *prev_if = find_iface(prev, curr_if->index);
    /* admission can depend on the name. treat a rename as replacement so
     * consumers retire the old name and evaluate the current snapshot. */
    if (!prev_if || strcmp(prev_if->name, curr_if->name) != 0) {
      up->added[up->added_count++] = curr_if->index;
      continue;
    }
    ifmon_iface_diff_t diff = {
        .index = curr_if->index,
        .hw_addr_changed = strcmp(prev_if->hw_addr, curr_if->hw_addr) != 0,
        .link_state_changed = prev_if->is_up != curr_if->is_up,
        .is_up = curr_if->is_up};
    diff.addrs_added_count =
        missing_addresses(curr_if, prev_if, diff.addrs_added);
    diff.addrs_removed_count =
        missing_addresses(prev_if, curr_if, diff.addrs_removed);
    if (diff.hw_addr_changed || diff.link_state_changed ||
        diff.addrs_added_count || diff.addrs_removed_count)
      up->modified[up->modified_count++] = diff;
  }
  for (int i = 0; i < prev->count; i++) {
    const ifmon_iface_t *prev_if = &prev->ifaces[i];
    const ifmon_iface_t *curr_if = find_iface(curr, prev_if->index);
    if (!curr_if || strcmp(prev_if->name, curr_if->name) != 0)
      up->removed[up->removed_count++] = prev_if->index;
  }
  return 0;

fail:
  ifmon_update_dispose(up);
  return -1;
}

#ifndef _WIN32
static void fill_missing_prefixes(ifmon_list_t *list) {
  for (int i = 0; i < list->count; i++) {
    ifmon_iface_t *iface = &list->ifaces[i];
    uint8_t v4 = 0, v6 = 0;
    for (int j = 0; j < iface->addr_count; j++) {
      const ifmon_addr_t *addr = &iface->addrs[j];
      if (addr->family == AF_INET && v4 == 0)
        v4 = addr->prefix_len;
      if (addr->family == AF_INET6 && v6 == 0)
        v6 = addr->prefix_len;
    }
    for (int j = 0; j < iface->addr_count; j++) {
      ifmon_addr_t *addr = &iface->addrs[j];
      if (addr->prefix_len == 0) {
        if (addr->family == AF_INET)
          addr->prefix_len = v4 ? v4 : 24;
        else if (addr->family == AF_INET6)
          addr->prefix_len = v6 ? v6 : 64;
      }
    }
  }
}
#endif

#if defined(__linux__)
static bool parse_address_attributes(ifmon_addr_t *addr, struct rtattr *rta,
                                     int rta_len) {
  const void *local = NULL, *peer = NULL;
  size_t size = addr->family == AF_INET ? sizeof(struct in_addr)
                                        : sizeof(struct in6_addr);
  for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
    if (RTA_PAYLOAD(rta) < size)
      continue;
    if (rta->rta_type == IFA_LOCAL)
      local = RTA_DATA(rta);
    else if (rta->rta_type == IFA_ADDRESS)
      peer = RTA_DATA(rta);
  }
  if (!local && !peer)
    return false;
  memcpy(&addr->ip, local ? local : peer, size);
  return true;
}

static int parse_netlink_link(ifmon_list_t *list, struct nlmsghdr *nlh) {
  if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg)))
    return -1;
  struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
  if (!(ifi->ifi_flags & IFF_UP))
    return 0;

  ifmon_iface_t *iface = append_iface(list);
  if (!iface)
    return -1;
  iface->index = ifi->ifi_index;
  iface->is_up =
      (ifi->ifi_flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING);
  strcpy(iface->hw_addr, "00:00:00:00:00:00");
  struct rtattr *rta = IFLA_RTA(ifi);
  int rta_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
  for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
    if (rta->rta_type == IFLA_IFNAME) {
      size_t length = RTA_PAYLOAD(rta);
      if (length > sizeof(iface->name) - 1)
        length = sizeof(iface->name) - 1;
      memcpy(iface->name, RTA_DATA(rta), length);
    } else if (rta->rta_type == IFLA_ADDRESS) {
      format_mac((uint8_t *)RTA_DATA(rta), RTA_PAYLOAD(rta), iface->hw_addr);
    } else if (rta->rta_type == IFLA_OPERSTATE &&
               RTA_PAYLOAD(rta) >= sizeof(uint8_t)) {
      uint8_t operstate = *(uint8_t *)RTA_DATA(rta);
      if (operstate != 6 /* IF_OPER_UP */ &&
          operstate != 0 /* IF_OPER_UNKNOWN */)
        iface->is_up = 0;
    }
  }
  if (rta_len != 0)
    return -1;
  if (iface->name[0] == '\0')
    list->count--;
  return 0;
}

static int parse_netlink_address(ifmon_list_t *list, struct nlmsghdr *nlh) {
  if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifaddrmsg)))
    return -1;
  struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
  ifmon_iface_t *iface = NULL;
  for (int i = 0; i < list->count; i++) {
    if (list->ifaces[i].index == ifa->ifa_index) {
      iface = &list->ifaces[i];
      break;
    }
  }
  if (!iface || iface->addr_count == IFMON_MAX_IPS_PER_IFACE ||
      (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6))
    return 0;
  ifmon_addr_t *addr = &iface->addrs[iface->addr_count];
  addr->family = ifa->ifa_family;
  addr->prefix_len = ifa->ifa_prefixlen;
  int rta_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa));
  if (parse_address_attributes(addr, IFA_RTA(ifa), rta_len))
    iface->addr_count++;
  return 0;
}

/* a dump may span any number of datagrams, each larger than the scratchpad.
 * only a complete, uninterrupted dump may replace the watcher's snapshot. */
static int read_netlink_dump(int fd, ifmon_list_t *list, uint32_t sequence,
                             uint8_t *scratchpad, size_t scratchpad_size) {
  uint8_t *buffer = scratchpad;
  size_t capacity = scratchpad_size;
  int result = -1;
  for (;;) {
    ssize_t needed;
    do {
      needed = recv(fd, scratchpad, scratchpad_size, MSG_PEEK | MSG_TRUNC);
    } while (needed < 0 && errno == EINTR);
    if (needed <= 0 || needed > INT_MAX)
      break;
    if ((size_t)needed > capacity) {
      uint8_t *larger =
          realloc(buffer == scratchpad ? NULL : buffer, (size_t)needed);
      if (!larger)
        break;
      buffer = larger;
      capacity = (size_t)needed;
    }
    ssize_t len;
    do {
      len = recv(fd, buffer, capacity, MSG_TRUNC);
    } while (len < 0 && errno == EINTR);
    if (len != needed)
      break;
    struct nlmsghdr *nlh;
    for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, (size_t)len);
         nlh = NLMSG_NEXT(nlh, len)) {
      if (nlh->nlmsg_seq != sequence)
        continue;
      if ((nlh->nlmsg_flags & NLM_F_DUMP_INTR) ||
          nlh->nlmsg_type == NLMSG_ERROR || nlh->nlmsg_type == NLMSG_OVERRUN)
        goto done;
      if (nlh->nlmsg_type == NLMSG_DONE) {
        int status = 0;
        if (NLMSG_PAYLOAD(nlh, 0) >= sizeof(status))
          memcpy(&status, NLMSG_DATA(nlh), sizeof(status));
        if (status == 0)
          result = 0;
        goto done;
      }
      if ((nlh->nlmsg_type == RTM_NEWLINK &&
           parse_netlink_link(list, nlh) != 0) ||
          (nlh->nlmsg_type == RTM_NEWADDR &&
           parse_netlink_address(list, nlh) != 0))
        goto done;
    }
    if (len != 0)
      break;
  }
done:
  if (buffer != scratchpad)
    free(buffer);
  return result;
}

static int list_get_into(ifmon_list_t *list, uint8_t *scratchpad,
                         size_t scratchpad_size) {
  if (!scratchpad || scratchpad_size < sizeof(struct nlmsghdr))
    return -1;
  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (fd < 0)
    return -1;
  int result = -1;
  struct {
    struct nlmsghdr nlh;
    struct ifinfomsg ifi;
  } req_link = {0};
  req_link.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req_link.ifi));
  req_link.nlh.nlmsg_type = RTM_GETLINK;
  req_link.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req_link.nlh.nlmsg_seq = 1;
  req_link.ifi.ifi_family = AF_UNSPEC;
  if (send(fd, &req_link, req_link.nlh.nlmsg_len, 0) < 0 ||
      read_netlink_dump(fd, list, 1, scratchpad, scratchpad_size) != 0)
    goto done;

  struct {
    struct nlmsghdr nlh;
    struct ifaddrmsg ifa;
  } req_addr = {0};
  req_addr.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req_addr.ifa));
  req_addr.nlh.nlmsg_type = RTM_GETADDR;
  req_addr.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req_addr.nlh.nlmsg_seq = 2;
  req_addr.ifa.ifa_family = AF_UNSPEC;
  if (send(fd, &req_addr, req_addr.nlh.nlmsg_len, 0) < 0 ||
      read_netlink_dump(fd, list, 2, scratchpad, scratchpad_size) != 0)
    goto done;
  fill_missing_prefixes(list);
  result = 0;
done:
  close(fd);
  return result;
}

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)

#define ROUNDUP(a)                                                             \
  ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

static int list_get_into(ifmon_list_t *list, uint8_t *scratchpad,
                         size_t scratchpad_size) {
  if (!list || !scratchpad || scratchpad_size < sizeof(struct rt_msghdr))
    return -1;
  int mib[6];
  mib[0] = CTL_NET;
  mib[1] = AF_ROUTE;
  mib[2] = 0;
  mib[3] = 0;
  mib[4] = NET_RT_IFLIST;
  mib[5] = 0;

  size_t len = 0;
  if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
    return -1;

  uint8_t *buffer = scratchpad;
  int result = -1;
  if (len > scratchpad_size) {
    buffer = malloc(len);
    if (!buffer)
      return -1;
  }
  if (sysctl(mib, 6, buffer, &len, NULL, 0) < 0)
    goto done;

  uint8_t *next = buffer;
  uint8_t *end = buffer + len;

  while (next < end) {
    size_t header_size = offsetof(struct rt_msghdr, rtm_type) +
                         sizeof(((struct rt_msghdr *)0)->rtm_type);
    if ((size_t)(end - next) < header_size)
      goto done;
    struct rt_msghdr *rtm = (struct rt_msghdr *)next;
    if (rtm->rtm_msglen < header_size || rtm->rtm_msglen > (size_t)(end - next))
      goto done;

    if (rtm->rtm_type == RTM_IFINFO) {
      if (rtm->rtm_msglen <
          sizeof(struct if_msghdr) + offsetof(struct sockaddr_dl, sdl_data))
        goto done;
      struct if_msghdr *ifm = (struct if_msghdr *)rtm;
      if (!(ifm->ifm_flags & IFF_UP)) {
        next += rtm->rtm_msglen;
        continue;
      }
      {
        ifmon_iface_t *iface = append_iface(list);
        if (!iface)
          goto done;
        iface->index = ifm->ifm_index;
        iface->is_up =
            (ifm->ifm_flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING);
        strncpy(iface->hw_addr, "00:00:00:00:00:00", sizeof(iface->hw_addr));

        struct sockaddr_dl *sdl = (struct sockaddr_dl *)(ifm + 1);
        size_t sdl_size = rtm->rtm_msglen - sizeof(*ifm);
        if (sdl->sdl_len > sdl_size ||
            sdl->sdl_len < offsetof(struct sockaddr_dl, sdl_data) ||
            (size_t)sdl->sdl_nlen + sdl->sdl_alen >
                sdl->sdl_len - offsetof(struct sockaddr_dl, sdl_data))
          goto done;
        if (sdl->sdl_family == AF_LINK) {
          int nlen = sdl->sdl_nlen;
          if (nlen >= (int)sizeof(iface->name))
            nlen = sizeof(iface->name) - 1;
          memcpy(iface->name, sdl->sdl_data, nlen);
          iface->name[nlen] = '\0';
          format_mac((uint8_t *)LLADDR(sdl), sdl->sdl_alen, iface->hw_addr);
        }
        if (iface->name[0] == '\0') {
          list->count--;
          goto next_iface;
        }
      }
    } else if (rtm->rtm_type == RTM_NEWADDR) {
      if (rtm->rtm_msglen < sizeof(struct ifa_msghdr))
        goto done;
      struct ifa_msghdr *ifam = (struct ifa_msghdr *)rtm;
      ifmon_iface_t *iface = NULL;
      for (int i = 0; i < list->count; i++) {
        if (list->ifaces[i].index == ifam->ifam_index) {
          iface = &list->ifaces[i];
          break;
        }
      }

      if (iface && iface->addr_count < IFMON_MAX_IPS_PER_IFACE) {
        struct sockaddr *sa = (struct sockaddr *)(ifam + 1);
        struct sockaddr *addrs[RTAX_MAX];
        int addrs_present = ifam->ifam_addrs;
        for (int i = 0; i < RTAX_MAX; i++) {
          if (addrs_present & (1 << i)) {
            addrs[i] = sa;
            sa = (struct sockaddr *)((uint8_t *)sa + ROUNDUP(sa->sa_len));
          } else {
            addrs[i] = NULL;
          }
        }

        struct sockaddr *addr = addrs[RTAX_IFA];
        struct sockaddr *netmask = addrs[RTAX_NETMASK];
        if (addr &&
            (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) {
          ifmon_addr_t *a = &iface->addrs[iface->addr_count];
          a->family = addr->sa_family;

          if (addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)addr;
            a->ip.v4 = sin->sin_addr;
            if (netmask) {
              struct sockaddr_in *msin = (struct sockaddr_in *)netmask;
              a->prefix_len = count_bits_v4(msin->sin_addr);
            }
          } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
            a->ip.v6 = sin6->sin6_addr;
            if (netmask) {
              struct sockaddr_in6 *msin6 = (struct sockaddr_in6 *)netmask;
              a->prefix_len = count_bits_v6(msin6->sin6_addr);
            }
          }
          iface->addr_count++;
        }
      }
    }
  next_iface:
    next += rtm->rtm_msglen;
  }

  fill_missing_prefixes(list);
  result = 0;
done:
  if (buffer != scratchpad)
    free(buffer);
  return result;
}

#else
static int list_get_into(ifmon_list_t *list, uint8_t *scratchpad,
                         size_t scratchpad_size) {
  if (!list || !scratchpad || scratchpad_size < sizeof(IP_ADAPTER_ADDRESSES))
    return -1;
  ULONG size = (ULONG)scratchpad_size;

  IP_ADAPTER_ADDRESSES *addrs = (IP_ADAPTER_ADDRESSES *)scratchpad;

  int result = -1;
  ULONG res = ERROR_BUFFER_OVERFLOW;
  for (int attempt = 0; attempt < 3; attempt++) {
    res = GetAdaptersAddresses(AF_UNSPEC,
                               GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                               NULL, addrs, &size);
    if (res != ERROR_BUFFER_OVERFLOW)
      break;
    IP_ADAPTER_ADDRESSES *larger =
        realloc((uint8_t *)addrs == scratchpad ? NULL : addrs, size);
    if (!larger)
      goto done;
    addrs = larger;
  }
  if (res != ERROR_SUCCESS)
    goto done;

  for (IP_ADAPTER_ADDRESSES *curr = addrs; curr != NULL; curr = curr->Next) {
    if (curr->OperStatus != IfOperStatusUp)
      continue;

    uint32_t index = curr->IfIndex;
    if (index == 0)
      index = curr->Ipv6IfIndex;
    if (index == 0)
      continue;

    {
      ifmon_iface_t *iface = append_iface(list);
      if (!iface)
        goto done;
      iface->index = index;
      iface->is_up = 1;

      int name_len =
          WideCharToMultiByte(CP_UTF8, 0, curr->FriendlyName, -1, iface->name,
                              sizeof(iface->name) - 1, NULL, NULL);
      if (name_len > 0) {
        iface->name[name_len] = '\0';
      } else {
        strncpy(iface->name, "", sizeof(iface->name));
      }

      format_mac(curr->PhysicalAddress, curr->PhysicalAddressLength,
                 iface->hw_addr);

      if (iface->name[0] == '\0') {
        list->count--;
        continue;
      }

      for (IP_ADAPTER_UNICAST_ADDRESS *unicast = curr->FirstUnicastAddress;
           unicast != NULL; unicast = unicast->Next) {
        if (!unicast->Address.lpSockaddr)
          continue;
        int family = unicast->Address.lpSockaddr->sa_family;
        if (family != AF_INET && family != AF_INET6)
          continue;

        if (iface->addr_count < IFMON_MAX_IPS_PER_IFACE) {
          ifmon_addr_t *addr = &iface->addrs[iface->addr_count];
          addr->family = family;
          addr->prefix_len = unicast->OnLinkPrefixLength;
          if (family == AF_INET) {
            struct sockaddr_in *sin =
                (struct sockaddr_in *)unicast->Address.lpSockaddr;
            addr->ip.v4 = sin->sin_addr;
          } else {
            struct sockaddr_in6 *sin6 =
                (struct sockaddr_in6 *)unicast->Address.lpSockaddr;
            addr->ip.v6 = sin6->sin6_addr;
          }
          iface->addr_count++;
        }
      }
    }
  }
  result = 0;
done:
  if ((uint8_t *)addrs != scratchpad)
    free(addrs);
  return result;
}
#endif

int ifmon_list_get(ifmon_list_t *list, uint8_t *scratchpad,
                   size_t scratchpad_size) {
  if (!list)
    return -1;
  ifmon_list_t next = {0};
  if (list_get_into(&next, scratchpad, scratchpad_size) != 0) {
    ifmon_list_dispose(&next);
    return -1;
  }
  ifmon_list_dispose(list);
  *list = next;
  return 0;
}

static void watcher_dispose(ifmon_watcher_t *w) {
  ifmon_update_dispose(&w->update);
  ifmon_list_dispose(&w->prev_list);
  ifmon_list_dispose(&w->curr_list);
}

static void watcher_refresh(ifmon_watcher_t *w) {
  if (ifmon_list_get(&w->curr_list, w->scratchpad, sizeof(w->scratchpad)) != 0)
    return;
  if (generate_update(&w->prev_list, &w->curr_list, w->initial_pending,
                      &w->update) != 0) {
    ifmon_list_dispose(&w->curr_list);
    return;
  }
  if (w->update.is_initial || w->update.added_count ||
      w->update.removed_count || w->update.modified_count)
    w->cb(&w->update, w->userdata);
  w->initial_pending = 0;
  ifmon_update_dispose(&w->update);
  ifmon_list_dispose(&w->prev_list);
  w->prev_list = w->curr_list;
  w->curr_list = (ifmon_list_t){0};
}

#ifndef _WIN32
static int open_event_socket(void) {
  int fd = -1;
#if defined(__linux__)
  fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (fd >= 0) {
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
      close(fd);
      return -1;
    }
  }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
  fd = socket(AF_ROUTE, SOCK_RAW, 0);
#endif

  if (fd >= 0) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
      fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
  }
  return fd;
}

static void drain_socket(int fd) {
  char buf[4096];
  for (int iter = 0; iter < 1000; iter++) {
    ssize_t r;
    do {
      r = recv(fd, buf, sizeof(buf), 0);
    } while (r < 0 && errno == EINTR);
    if (r <= 0)
      break;
  }
}

static void *watcher_thread_func(void *arg) {
  ifmon_watcher_t *w = (ifmon_watcher_t *)arg;
  struct pollfd fds[2];
  fds[0].fd = w->event_fd;
  fds[0].events = POLLIN;
  fds[1].fd = w->stop_pipe[0];
  fds[1].events = POLLIN;

  while (atomic_load_explicit(&w->running, memory_order_acquire)) {
    int ret;
    do {
      ret = poll(fds, 2, -1);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0)
      continue;
    if (fds[1].revents & POLLIN)
      break;
    if (fds[0].revents & POLLIN) {
      drain_socket(w->event_fd);
      watcher_refresh(w);
    }
  }
  return NULL;
}

int ifmon_watch_start(ifmon_watcher_t *w, ifmon_callback_t cb, void *userdata) {
  if (!w || !cb)
    return -1;
  memset(w, 0, sizeof(ifmon_watcher_t));
  w->cb = cb;
  w->userdata = userdata;
  w->initial_pending = 1;
  w->event_fd = -1;
  w->stop_pipe[0] = -1;
  w->stop_pipe[1] = -1;

  if (ifmon_list_get(&w->prev_list, w->scratchpad, sizeof(w->scratchpad)) ==
      0) {
    w->initial_pending = 0;
    generate_update(NULL, &w->prev_list, 1, &w->update);
    cb(&w->update, userdata);
    ifmon_update_dispose(&w->update);
  }

  if (pipe(w->stop_pipe) < 0)
    goto fail;

  w->event_fd = open_event_socket();
  if (w->event_fd < 0) {
    close(w->stop_pipe[0]);
    close(w->stop_pipe[1]);
    goto fail;
  }

  atomic_store_explicit(&w->running, 1, memory_order_release);
  if (pthread_create(&w->thread, NULL, watcher_thread_func, w) != 0) {
    atomic_store_explicit(&w->running, 0, memory_order_release);
    close(w->event_fd);
    close(w->stop_pipe[0]);
    close(w->stop_pipe[1]);
    goto fail;
  }
  return 0;
fail:
  watcher_dispose(w);
  return -1;
}

void ifmon_watch_stop(ifmon_watcher_t *w) {
  if (!w || !atomic_load_explicit(&w->running, memory_order_acquire))
    return;
  atomic_store_explicit(&w->running, 0, memory_order_release);
  char c = 1;
  ssize_t rc = write(w->stop_pipe[1], &c, 1);
  (void)rc;
  pthread_join(w->thread, NULL);
  close(w->stop_pipe[0]);
  close(w->stop_pipe[1]);
  if (w->event_fd >= 0) {
    close(w->event_fd);
  }
  watcher_dispose(w);
}

#else

static VOID
    NETIOAPI_API_ windows_callback(PVOID CallerContext,
                                   PMIB_UNICASTIPADDRESS_ROW Row,
                                   MIB_NOTIFICATION_TYPE NotificationType) {
  ifmon_watcher_t *w = (ifmon_watcher_t *)CallerContext;
  EnterCriticalSection(&w->lock);
  watcher_refresh(w);
  LeaveCriticalSection(&w->lock);
}

int ifmon_watch_start(ifmon_watcher_t *w, ifmon_callback_t cb, void *userdata) {
  if (!w || !cb)
    return -1;
  memset(w, 0, sizeof(ifmon_watcher_t));
  w->cb = cb;
  w->userdata = userdata;
  w->initial_pending = 1;
  w->notify_handle = INVALID_HANDLE_VALUE;
  InitializeCriticalSection(&w->lock);
  w->lock_initialized = 1;

  if (ifmon_list_get(&w->prev_list, w->scratchpad, sizeof(w->scratchpad)) ==
      0) {
    w->initial_pending = 0;
    generate_update(NULL, &w->prev_list, 1, &w->update);
    cb(&w->update, userdata);
    ifmon_update_dispose(&w->update);
  }

  DWORD res = NotifyUnicastIpAddressChange(AF_UNSPEC, windows_callback, w,
                                           FALSE, &w->notify_handle);
  if (res != NO_ERROR)
    goto fail;
  return 0;
fail:
  DeleteCriticalSection(&w->lock);
  w->lock_initialized = 0;
  watcher_dispose(w);
  return -1;
}

void ifmon_watch_stop(ifmon_watcher_t *w) {
  if (!w || !w->lock_initialized)
    return;
  if (w->notify_handle != INVALID_HANDLE_VALUE) {
    CancelMibChangeNotify2(w->notify_handle);
  }
  DeleteCriticalSection(&w->lock);
  w->lock_initialized = 0;
  watcher_dispose(w);
}
#endif
