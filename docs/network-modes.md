# Network modes

`qlinq-app --network-mode p2p|multicast-fanout|amt-relay` selects the deployment
role. `--mode datagram|fixedrate|rateless|reliable` still selects the record
delivery policy. The default network mode is `p2p`, preserving existing command
lines. `multicast` is an alias for `multicast-fanout`.

Build all modes with the pinned nanoamt submodule:

```sh
git submodule update --init --recursive
make
```

Nanoamt is compiled into `libqlinq.a`; no external relay executable, sibling
checkout, or second QUIC/TLS stack is required. Classic AMT is RFC 7450 over
UDP, normally port 2268. AMTQ is not enabled by these modes.

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

## Transparent AMT relay

Run a relay on a Linux host with upstream multicast connectivity. This role uses
`--relay-interface`, which takes an interface **name**. Native packet capture
requires root or `CAP_NET_RAW`.

```sh
sudo ./qlinq-app --network-mode amt-relay \
  --bind RELAY_IP --listen 2268 --relay-interface eth0 --stats-ms 1000
```

The relay embeds nanoamt's listener, membership aggregation, transactional
upstream subscriptions, native IP capture, bounded fanout queues and PMTU
handling. It forwards the inner multicast IP packets without interpreting the
qlinq payload. It does not create qlinq sessions, receive group keys, decode
FEC, or republish streams. TLS identity files, authentication tokens and
input/output files are therefore not relay options.

A receiver without native multicast access connects to the original source for
control and selects the relay for multicast delivery:

```sh
./qlinq-app --network-mode multicast-fanout --peer SOURCE_IP:8888 \
  --amt-relay RELAY_IP --amt-port 2268 \
  --cert receiver.crt --key receiver.key --ca mesh-ca.crt \
  --auth-token SECRET --output received.bin --mode rateless
```

`--amt-relay` accepts a numeric IPv4 or IPv6 address. It replaces the receiver's
native multicast interface selection. Native and AMT receivers can subscribe
to the same publication concurrently. The relay must be able to join the
source's multicast distribution network, and the receiver must separately be
able to reach the source's QUIC listener. Hosting a relay does not proxy that
control connection.

The gateway waits for AMT membership before announcing Flexicast readiness.
Setup is bounded to 15 seconds; failure releases membership and leaves unicast
delivery available. Up to 64 distinct source/group/port memberships are supported
per endpoint; flows sharing a tuple share a gateway. Leaving the final flow
sends a best-effort AMT withdrawal and closes its socket. Relay membership timers
also retire abandoned gateways.

Relay defaults and limits:

| Option | Default | Maximum |
| --- | --- | --- |
| `--relay-clients` | 64 | 1024 |
| `--relay-groups` | 1024 | 4096 |
| `--relay-sources` | 4096 | 65536 |
| `--relay-mtu` | 1500 | 65535 |

The minimum configured relay MTU is 576. Nanoamt accounts for encapsulation,
fragments IPv4 when permitted, and supplies PMTU feedback for packets that cannot
fit. IPv6 inner packets require an adequate unfragmented path budget; choose the
source's UDP payload budget for the full encapsulated path. `--linux-gateway-family
4|6` enables nanoamt's compatibility mode for Linux kernel AMT gateways; qlinq's
gateway uses the RFC wire format by default.

`--stats-ms` emits relay JSON to stderr, including clients, upstream groups and
sources, emitted packets, queue drops, send errors, MTU drops and upstream
reconciliation errors. SIGINT/SIGTERM stop the relay and release sockets and
native subscriptions. Native capture is Linux-only; other platforms report
`ENOTSUP` when opening a relay.

## Embedding

`transport_config_t` exposes `flexicast_receiver_backend`,
`flexicast_relay_address` and `flexicast_relay_port`. The native `qlinq.h` API
exposes the corresponding `group_delivery.receiver_backend`, `relay_address`
and `relay_port` fields, using `QLINQ_GROUP_NATIVE` or `QLINQ_GROUP_AMT`.

The standalone transparent host is exposed by `qlinq_relay.h`:

```c
qlinq_relay_config_t config = {
    .bind_address = "192.0.2.10",
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

AMT sockets live in the default polling host. A custom driven transport host
must supply the tunnel membership callbacks to select the AMT backend; the
protocol engine itself remains independent of socket I/O.
