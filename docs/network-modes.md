# Network modes

`qlinq-app --network-mode p2p|multicast-fanout|amt-relay|amtq-relay` selects the
deployment role. `--mode datagram|fixedrate|rateless|reliable` still selects the
record delivery policy. The default network mode is `p2p`, preserving existing
command lines. `multicast` is an alias for `multicast-fanout`.

Build all modes with the pinned nanoamt submodule:

```sh
git submodule update --init --recursive
make
```

Nanoamt is compiled into `libqlinq.a`; no external relay executable, sibling
checkout, or second QUIC/TLS stack is required. Classic AMT is RFC 7450 over
UDP (normally port 2268), and AMTQ (`amtq-00`, normally port 2269) runs over
`qlinq`'s linked `quicly` stack with TLS/mTLS, congestion control, and both
Datagram and Reliable Block delivery modes.

## P2P

Direct QUIC transport retains multipath, authentication, FEC and repair:

```sh
./qlinq-app --network-mode p2p --listen 8888 --bind SOURCE_IP \
  --cert source.crt --key source.key --ca mesh-ca.crt \
  --auth-token SECRET --input payload.bin --mode rateless --one-shot

./qlinq-app --network-mode p2p --peer SOURCE_IP:8888 \
  --cert receiver.crt --key receiver.key --ca mesh-ca.crt \
  --auth-token SECRET --output received.bin --mode rateless
```

The placeholders are deployment addresses and credentials. The listener needs
an input or output file in P2P and multicast modes. Receivers can use
`--receive-count N` to stop after a known number of records.

## Multicast fanout

The source listens for authenticated QUIC control connections and sends shared,
encrypted Flexicast datagrams to an IPv4 or IPv6 SSM group. The source's
`--bind` must make its concrete `--group-interface` address available. Multicast
fanout supports datagram, fixedrate and rateless records; reliable streams and
`--transfer` use P2P.

```sh
./qlinq-app --network-mode multicast-fanout \
  --listen 8888 --bind SOURCE_IP \
  --group 232.42.42.1 --group-port 9001 --group-interface SOURCE_IP \
  --cert source.crt --key source.key --ca mesh-ca.crt \
  --auth-token SECRET --input payload.bin --mode rateless \
  --message-size 1024 --wait-subscribers 2 --one-shot

./qlinq-app --network-mode multicast-fanout --peer SOURCE_IP:8888 \
  --group-interface RECEIVER_INTERFACE_IP \
  --cert receiver.crt --key receiver.key --ca mesh-ca.crt \
  --auth-token SECRET --output received.bin --mode rateless
```

Receivers learn the source/group/port through the authenticated source connection.
IPv4 groups must be in `232.0.0.0/8`; IPv6 groups must be SSM addresses. A native
receiver can omit `--group-interface` to use routing defaults. The interface
option takes a local **address**, rather than an interface name.

Each receiver keeps its QUIC control and repair connection to the source.
Delivery continues over unicast while group setup is pending or unavailable.
`--wait-subscribers` counts subscriptions, not completed multicast joins.

## Transparent AMT and AMTQ relay

Run a relay on a Linux host with upstream multicast connectivity. This role uses
`--relay-interface`, which takes an interface **name**. Native packet capture
requires root or `CAP_NET_RAW`.

Classic AMT only (RFC 7450 over UDP, default port 2268):

```sh
sudo ./qlinq-app --network-mode amt-relay \
  --bind RELAY_IP --listen 2268 --relay-interface eth0 --stats-ms 1000
```

AMTQ only (`amtq-00` over QUIC, default port 2269; requires `--cert` and `--key`,
with optional `--ca` to require client mTLS certificates):

```sh
sudo ./qlinq-app --network-mode amtq-relay \
  --bind RELAY_IP --listen 2269 --relay-interface eth0 \
  --cert relay.crt --key relay.key --ca clients-ca.crt --stats-ms 1000
```

Dual-stack classic AMT + AMTQ sharing a single upstream native capture and
membership set:

```sh
sudo ./qlinq-app --network-mode amt-relay \
  --bind RELAY_IP --listen 2268 --amtq-port 2269 --relay-interface eth0 \
  --cert relay.crt --key relay.key --stats-ms 1000
```

`--no-classic-amt` disables the classic AMT listener under `--network-mode
amt-relay`. `--amtq-datagram-only` restricts AMTQ sessions to QUIC Datagram Mode
and disables Reliable Block Mode.

The relay embeds nanoamt's classic AMT and AMTQ cores, membership aggregation,
transactional upstream subscriptions, native IP capture, bounded fanout queues
and PMTU handling. It forwards the inner multicast IP packets without
interpreting the qlinq payload. It does not create qlinq publication sessions,
receive group keys, decode FEC, or republish streams; authentication tokens and
input/output files are therefore not relay options.

A receiver without native multicast access connects to the original source for
control and selects the relay for multicast delivery:

```sh
# Classic AMT tunnel
./qlinq-app --network-mode multicast-fanout --peer SOURCE_IP:8888 \
  --amt-relay RELAY_IP --amt-port 2268 \
  --cert receiver.crt --key receiver.key --ca mesh-ca.crt \
  --auth-token SECRET --output received.bin --mode rateless

# AMTQ tunnel (add --amtq-reliable to prefer Reliable Block Mode)
./qlinq-app --network-mode multicast-fanout --peer SOURCE_IP:8888 \
  --group-backend amtq --amt-relay RELAY_IP --amtq-port 2269 \
  --amtq-server-name relay.example.net --amtq-ca relay-ca.crt \
  --cert receiver.crt --key receiver.key --ca mesh-ca.crt \
  --auth-token SECRET --output received.bin --mode rateless

# Staged automatic backend selection: native -> classic AMT -> AMTQ -> unicast
./qlinq-app --network-mode multicast-fanout --peer SOURCE_IP:8888 \
  --group-backend auto --group-interface RECEIVER_INTERFACE_IP \
  --amt-relay RELAY_IP --amt-port 2268 --amtq-port 2269 \
  --amtq-server-name relay.example.net --amtq-ca relay-ca.crt \
  --cert receiver.crt --key receiver.key --ca mesh-ca.crt \
  --auth-token SECRET --output received.bin --mode rateless
```

`--amt-relay` accepts a numeric IPv4 or IPv6 address. `--group-backend
native|amt|amtq|auto` selects the receiver group backend (`--amt-relay` defaults
to `amt` when `--group-backend` is omitted). When the receiver configures `--cert`
and `--key`, AMTQ automatically presents that client certificate if the relay
requests mTLS. `--amtq-ca` overrides `--ca` when the relay uses a separate PKI
from the publication source, and `--insecure` skips relay certificate
verification in test environments. Native, classic AMT, and AMTQ receivers can
subscribe to the same publication concurrently. In `auto` mode, each flow tries
native multicast first (when a local group interface is usable), then classic
AMT (skipping classic AMT when known path MTU cannot carry unfragmented IPv6
multicast), then AMTQ, while keeping unicast control and repair active throughout.

The gateway waits for AMT or AMTQ context readiness before announcing Flexicast
readiness. Setup is bounded to 15 seconds per stage; failure advances `auto` to
the next backend or leaves unicast delivery available. Up to 64 distinct
source/group/port memberships are supported per endpoint; classic AMT flows
sharing a tuple share a gateway, and AMTQ multiplexes all IPv4 or IPv6
memberships per address family over a single QUIC connection.

Relay defaults and limits:

| Option | Default | Maximum |
| --- | --- | --- |
| `--relay-clients` | 64 | 1024 |
| `--relay-groups` | 1024 | 4096 |
| `--relay-sources` | 4096 | 65536 |
| `--relay-mtu` | 1500 | 65535 |

The minimum configured relay MTU is 576. Classic AMT accounts for encapsulation,
fragments IPv4 when permitted, and supplies PMTU feedback for packets that cannot
fit. AMTQ fragments oversized multicast packets across QUIC `DATAGRAM` frames or
delivers each packet in a server-initiated unidirectional Reliable Block stream.
`--linux-gateway-family 4|6` enables nanoamt's compatibility mode for Linux
kernel classic AMT gateways.

`--stats-ms` emits relay JSON to stderr, including classic AMT and AMTQ clients,
upstream groups and sources, emitted packets, AMTQ datagrams and reliable blocks,
queue drops, backpressure, send/session/policy errors, MTU drops and upstream
reconciliation errors. SIGINT/SIGTERM stop the relay and release sockets and
native subscriptions. Native capture is Linux-only; other platforms report
`ENOTSUP` when opening a relay.

## Embedding

`transport_config_t` exposes `flexicast_receiver_backend`,
`flexicast_relay_address`, `flexicast_relay_port`, `flexicast_relay_amtq_port`,
`flexicast_relay_server_name`, `flexicast_relay_ca_file`, and
`flexicast_amtq_reliable`. The native `qlinq.h` API exposes the corresponding
`group_delivery` fields using `QLINQ_GROUP_NATIVE`, `QLINQ_GROUP_AMT`,
`QLINQ_GROUP_AMTQ`, or `QLINQ_GROUP_AUTO`.

The standalone transparent host is exposed by `qlinq_relay.h`, supporting
classic AMT, AMTQ-only (`disable_classic_amt = true`), and dual-stack
(`amtq_port` alongside classic AMT) configurations:

```c
qlinq_relay_config_t config = {
    .bind_address = "192.0.2.10",
    .port = 2268,
    .amtq_port = 2269,
    .amtq_cert_file = "relay.crt",
    .amtq_key_file = "relay.key",
    .upstream_interface = "eth0",
};
qlinq_relay_t *relay = qlinq_relay_open(&config);
if (relay) {
    /* Call on one service thread; each call bounds its packet work and wait. */
    while (keep_running && qlinq_relay_service(relay, 100) == 0) {
        /* Application work. */
    }
    qlinq_relay_close(relay);
}
```

AMT and AMTQ sockets live in the default polling host. A custom driven transport
host must supply the tunnel membership callbacks to select tunnel backends; the
protocol engine itself remains independent of socket I/O.
