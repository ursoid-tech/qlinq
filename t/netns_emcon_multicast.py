"""Multicast membership and router queries for the EMCON namespace test."""

import signal
import socket
import struct
import sys
from pathlib import Path


def checksum(packet):
    if len(packet) % 2:
        packet += b"\0"
    value = sum(struct.unpack(f"!{len(packet) // 2}H", packet))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return (~value) & 0xFFFF


def hold_group(interface, group, ready):
    index = socket.if_nametoindex(interface)
    if ":" in group:
        receiver = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        request = socket.inet_pton(socket.AF_INET6, group) + struct.pack("=I", index)
        receiver.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, request)
    else:
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        request = socket.inet_aton(group) + bytes(4) + struct.pack("=i", index)
        receiver.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, request)
    Path(ready).touch()
    while True:
        signal.pause()


def check_membership(interface, group):
    """The provisioning socket should be the only membership owner."""
    if ":" in group:
        address = socket.inet_pton(socket.AF_INET6, group).hex()
        for line in Path("/proc/net/igmp6").read_text().splitlines():
            _, device, entry, users, *_ = line.split()
            if device == interface and entry == address and int(users) == 1:
                return
    else:
        address = socket.inet_aton(group)
        device = None
        for line in Path("/proc/net/igmp").read_text().splitlines()[1:]:
            if line[0].isspace():
                entry, users, *_ = line.split()
                if (device == interface and struct.pack("=I", int(entry, 16)) == address
                        and int(users) == 1):
                    return
            else:
                device = line.split()[1]
    sys.exit(f"expected one membership owner for {group} on {interface}")


def router_query(interface, source, group):
    # A group-specific query with a 100 ms response interval and Router Alert.
    if ":" in group:
        src = socket.inet_pton(socket.AF_INET6, source)
        dst = socket.inet_pton(socket.AF_INET6, group)
        query = struct.pack("!BBHHH16s", 130, 0, 0, 100, 0, dst)
        pseudoheader = struct.pack("!16s16sI3xB", src, dst, len(query), 58)
        query = query[:2] + struct.pack("!H", checksum(pseudoheader + query)) + query[4:]
        hop_options = bytes.fromhex("3a 00 05 02 00 00 01 00")
        ip_header = struct.pack("!IHBB16s16s", 6 << 28, len(hop_options + query),
                                0, 1, src, dst)
        ethernet_destination = bytes.fromhex("33 33") + dst[-4:]
        ethertype = b"\x86\xdd"
    else:
        src = socket.inet_aton(source)
        dst = socket.inet_aton(group)
        query = struct.pack("!BBH4s", 0x11, 1, 0, dst)
        query = query[:2] + struct.pack("!H", checksum(query)) + query[4:]
        ip_header = struct.pack("!BBHHHBBH4s4s4s", 0x46, 0, 24 + len(query), 0,
                                0, 1, 2, 0, src, dst, b"\x94\x04\0\0")
        ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]
        hop_options = b""
        ethernet_destination = bytes.fromhex("01 00 5e") + bytes([dst[1] & 0x7F]) + dst[2:]
        ethertype = b"\x08\x00"

    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sender:
        sender.bind((interface, 0))
        ethernet_source = sender.getsockname()[4]
        sender.send(ethernet_destination + ethernet_source + ethertype +
                    ip_header + hop_options + query)


if sys.argv[1] == "hold":
    hold_group(*sys.argv[2:])
elif sys.argv[1] == "check-membership":
    check_membership(*sys.argv[2:])
elif sys.argv[1] == "query":
    router_query(*sys.argv[2:])
else:
    sys.exit("expected hold, check-membership, or query")
