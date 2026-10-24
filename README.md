# qlinq

[![CI](https://github.com/sleepybishop/qlinq/actions/workflows/ci.yml/badge.svg)](https://github.com/sleepybishop/qlinq/actions/workflows/ci.yml)

`qlinq` ("clink") is a resilient data transport over QUIC with multipath scheduling and fixed-block or rateless forward error correction.

## Features

- **QUIC-native Tunneling**: Low-latency, connection-migrating packet tunnels.
- **Multipath Link Aggregation**: Dynamic path discovery, performance scheduling, and failover across multiple interfaces (Wi-Fi, Ethernet, Satcom, Cellular).
- **Forward Error Correction**: Recover lost packets on high-loss links without retransmission latency.
- **mTLS Authentication**: Full mutual TLS authentication support using custom or system trusted root authorities.
- **Finite Fanout**: `qlinq-cast` streams files or pipelines to a confirmed
  receiver cohort with ordered recovery and explicit completion.
- **Experimental Flexicast Fanout**: One encrypted unreliable-track packet can
  reach many authenticated subscribers with shared replay protection and
  aggregate acknowledgements. Enable it on every participating daemon with
  `--flexicast`; without a multicast policy qlinq replicates the protected
  packet over unicast. A source sends one native IPv4 or IPv6 SSM datagram by
  also setting `--flexicast-group 232.1.2.3 --flexicast-port 9000
  --flexicast-interface 192.0.2.10`, or an IPv6 `ff3x::/32` group with its
  numeric local IPv6 interface address. Receivers learn the group dynamically
  and may select their membership interface with `--flexicast-interface`.
  IPv6 peer endpoints use bracket notation such as `--peer [2001:db8::2]:8888`.
  Shared keys rotate as membership changes, and receivers with sustained missing
  PATH_ACK feedback fall back to their authenticated unicast path. The default
  `multicast` congestion controller follows the limiting receiver. Select the
  radio-oriented controller with `--flexicast-cc adaptive`; optional
  `--flexicast-cc-startup-rate`, `--flexicast-cc-min-rate`,
  `--flexicast-cc-max-rate`, `--flexicast-cc-aggregate-rate`, and
  `--flexicast-cc-feedback-timeout` values tune it in bytes per second and
  milliseconds. Multicast bursts remain bounded, and queue pressure is exposed
  through the publication API. Member state is dynamically sized and tested
  with 1,000-member cohorts; use `--max-connections N` on a listener to raise
  its default 32-connection/Flexicast-member capacity (hard limit 16,384).

## Building

To compile all targets, run:

```bash
git submodule update --init --recursive
make
```

The default build uses native CPU targeting for nanorq and its shared OBL
kernels. Use `make CODEC_TARGET=portable` for binaries intended for other CPUs.
Changes to compiler, flags, codec targeting or `WITH_FUSION` rebuild objects
through a configuration stamp; `libqlinq.a` is recreated when its members change.

The optional Fusion AES-GCM implementation is built when supported by the
compiler (`WITH_FUSION=0` disables it). Select it at runtime with
`QLINQ_CRYPTO_BACKEND=fusion`; unsupported CPUs or builds fall back to OpenSSL.
OpenSSL remains the runtime default. `make check-reports` runs both benchmark
report validators without creating network namespaces.
This produces the following tools and an embeddable transport library:

- `qlinqd`: The background peer-to-peer network daemon.
- `qlinq-app`: A direct `transport.h` send/receive and mesh test tool; it does
  not use the daemon's Unix data socket.
- `qlinq-cast`: A finite file/stdin fan-out tool built on the native streams api.
- `qlinq-tund`: The lightweight virtual TUN/TAP interface controller.
- `qlinq-tun`: Single native executable for Linux tunnel management and the
  direct `qlinq.h` packet worker: local identities, pairing, saved profiles,
  up/down, status, diagnostics and Prometheus text metrics. No Python runtime or
  companion engine is required. Existing `--peer ...` and `--listen ...`
  invocations remain supported.
- `libqlinq.a`: The in-process `transport.h` API used by `qlinq-app`, plus the
  [native application API](docs/application-api.md) in `qlinq.h` for named
  streams, owned events and endpoint management.

For example, start a rateless Flexicast sender using the adaptive controller:

```bash
./qlinq-app --listen 8888 --bind 192.0.2.10 \
  --auth-token "$QLINQ_AUTH_TOKEN" --cert peer.crt --key peer.key \
  --input payload.bin --one-shot --mode rateless --flexicast \
  --flexicast-group 232.1.2.3 --flexicast-port 9000 \
  --flexicast-interface 192.0.2.10 --flexicast-cc adaptive \
  --max-repair-requests 16 --max-aggregate-repairs 256
```

A receiver connects directly to the transport API and writes recovered records:

```bash
./qlinq-app --peer 192.0.2.10:8888 --auth-token "$QLINQ_AUTH_TOKEN" \
  --ca mesh-ca.crt --cert peer.crt --key peer.key \
  --output received.bin --mode rateless --flexicast \
  --flexicast-interface 192.0.2.20 --flexicast-cc adaptive
```

The app also supports reliable, plain datagram, fixed-FEC, and rateless modes,
IPv6 bracketed peer endpoints, negotiated repair selection, an explicit QUIC
idle timeout, machine-readable counter snapshots, and `--pv` for pv-style wire
throughput per physical interface. Run `qlinq-app --help` for the complete
interface.

Delivery mode names are shared by `qlinq-app`, `qlinqd`, and `qlinq-tun`:
`datagram`, `reliable`, `fixed-fec` (also accepted as `fec`), and `rateless`.
The daemon also retains its `--reliable` and `--rateless` aliases. Each tool
keeps its existing default mode.

## Managed packet tunnel

See the [two-machine quickstart](docs/tun-tool.md) for installation, secure
pairing, uplink selection, subnet routes and systemd operation. The pilot is a
Linux point-to-point IPv4 tunnel with one reachable server; no cloud account is
required. The core tunnel commands are:

```bash
sudo qlinq-tun up office
sudo qlinq-tun status office
sudo qlinq-tun diag office
sudo qlinq-tun down office
```

## Direct packet tunnel (advanced)

`qlinq-tun` maps each IP packet to one `QLINQ_CONTENT_DATA` record and
publishes/subscribes to the same named stream in opposite directions. Both
peers must choose the same `--track` and `--mode` (default `fixed-fec`). The
listener is limited to one peer; the connecting side reconnects automatically.
For a real interface, configure the TUN as root and use `--run-as USER` to drop
privileges before servicing peer traffic. TLS identities and sockets are
initialized before the drop; private keys can remain root-owned. Create a
dedicated unprivileged `qlinq` account. For example,
with identities issued by a shared CA:

```bash
sudo ./qlinq-tun --listen 8888 --bind 0.0.0.0 --interface tun0 \
  --ip 10.8.0.1/24 --track vpn/demo --mode fixed-fec \
  --cert server.crt --key server.key --ca mesh-ca.crt \
  --auth-token 'replace-with-a-secret' --run-as qlinq

sudo ./qlinq-tun --peer SERVER_IP:8888 --interface tun0 \
  --ip 10.8.0.2/24 --track vpn/demo --mode fixed-fec \
  --cert client.crt --key client.key --ca mesh-ca.crt \
  --auth-token 'replace-with-a-secret' --run-as qlinq
```

The helper defaults to MTU 1400 (`--mtu` overrides it), bounds its receive queue,
and never retries a partially accepted record as a new packet. TUN readiness
wakes the transport poller. Repeat `--bind` and `--uplink` to select paths;
`--peer-ip` enables explicit point-to-point IPv4 addressing and `--route` adds
subnet routes. `--stats-ms` emits JSON health snapshots. The managed workflow
supplies these options from a saved profile. Retain `qlinqd` plus `qlinq-tund`
for legacy mesh deployments.
`--mock --run-ms N` exercises the direct stream without a privileged TUN.

Rateless-coded tracks use negotiated degree-of-freedom repair by default and
fall back to indexed missing-symbol requests with legacy peers. Use
`--repair-mode indexed` to force exact missing-ESI repair for comparison, or
`--repair-mode rateless` to express the rateless preference explicitly (it
still falls back safely when the peer lacks support).

## Security

`qlinqd` requires an application authentication token and verifies peer
certificates by default. Supply the token through `QLINQ_AUTH_TOKEN` or
`--auth-token`, and use `--ca` when peers are signed by a private CA. For local
testing only, certificate verification can be disabled explicitly with
`--insecure-no-verify`.

```bash
QLINQ_AUTH_TOKEN='replace-with-a-secret' \
  ./qlinqd --listen 8888 --cert peer.crt --key peer.key --ca mesh-ca.crt
```

## Testing

To run the test suite:

```bash
make check
```

Run `make indent` to format first-party C sources and headers using the
repository's `.clang-format` configuration.

The private peer protocol is documented in
[docs/wire-protocol.md](docs/wire-protocol.md). Protocol version 1 is required
on both peers; incompatible versions are rejected instead of being guessed.
The implementation boundaries and ownership rules are described in
[docs/transport-architecture.md](docs/transport-architecture.md).
