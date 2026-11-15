# qlinq

[![CI](https://github.com/sleepybishop/qlinq/actions/workflows/ci.yml/badge.svg)](https://github.com/sleepybishop/qlinq/actions/workflows/ci.yml)

`qlinq` ("clink") is a resilient data transport over QUIC with multipath scheduling and fixed-block or rateless forward error correction.

## Features

- **QUIC-native Tunneling**: Low-latency, connection-migrating packet tunnels.
- **Multipath Link Aggregation**: Dynamic path discovery, performance scheduling, and failover across multiple interfaces (Wi-Fi, Ethernet, Satcom, Cellular).
- **Forward Error Correction**: Recover lost packets on high-loss links without retransmission latency.
- **mTLS Authentication**: Full mutual TLS authentication support using custom or system trusted root authorities.

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

- `qlinq-app`: Direct file/stream sender and receiver supporting unicast,
  multipath, FEC, and Flexicast group delivery.
- `qlinq-tun`: Single native executable for Linux tunnel management and the
  direct `qlinq.h` packet worker: local identities, pairing, saved profiles,
  up/down, status, diagnostics, optional TX GSO / RX GRO offloads, and
  Prometheus text metrics. No Python runtime or companion engine is required.
  Existing `--peer ...` and `--listen ...` invocations remain supported.
- `libqlinq.a`: The in-process `transport.h` API used by `qlinq-app`, plus the
  [native application API](docs/application-api.md) in `qlinq.h` for named
  streams, owned events and endpoint management.

For example, send one 512-byte rateless-protected record:

```bash
./qlinq-app --listen 8888 --bind 127.0.0.1 \
  --cert t/assets/server.crt --key t/assets/server.key \
  --auth-token test --insecure-no-verify --input payload.bin \
  --message-size 512 --count 1 --wait-subscribers 1 --one-shot
```

Receive it with:

```bash
./qlinq-app --peer 127.0.0.1:8888 --auth-token test \
  --insecure-no-verify --output received.bin --receive-count 1
```

The app also supports reliable, plain datagram, fixedrate, and rateless modes,
IPv6 bracketed peer endpoints, negotiated repair selection, congestion-control
selection (`--cc reno|cubic|bbr`), TLS hybrid group policy (`--tls-group-policy`),
an explicit QUIC idle timeout, machine-readable counter snapshots, and `--pv`
for pv-style wire throughput per physical interface. Run `qlinq-app --help` for
the complete interface.

Delivery mode names are shared by `qlinq-app` and `qlinq-tun`:
`datagram`, `reliable`, `fixedrate` (also accepted as `fec`), and `rateless`.
Each tool keeps its existing default mode.

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
peers must choose the same `--track` and `--mode` (default `fixedrate`). The
listener is limited to one peer; the connecting side reconnects automatically.
For a real interface, configure the TUN as root and use `--run-as USER` to drop
privileges before servicing peer traffic. TLS identities and sockets are
initialized before the drop; private keys can remain root-owned. Create a
dedicated unprivileged `qlinq` account. For example,
with identities issued by a shared CA:

```bash
sudo ./qlinq-tun --listen 8888 --bind 0.0.0.0 --interface tun0 \
  --ip 10.8.0.1/24 --track vpn/demo --mode fixedrate \
  --cert server.crt --key server.key --ca mesh-ca.crt \
  --auth-token 'replace-with-a-secret' --run-as qlinq

sudo ./qlinq-tun --peer SERVER_IP:8888 --interface tun0 \
  --ip 10.8.0.2/24 --track vpn/demo --mode fixedrate \
  --cert client.crt --key client.key --ca mesh-ca.crt \
  --auth-token 'replace-with-a-secret' --run-as qlinq
```

The helper defaults to MTU 1400 (`--mtu` overrides it), bounds its receive queue,
and never retries a partially accepted record as a new packet. TUN readiness
wakes the transport poller. Repeat `--bind` and `--uplink` to select paths;
`--peer-ip` enables explicit point-to-point IPv4 addressing and `--route` adds
subnet routes. `--tx-gso` and `--rx-gro` enable optional Linux `IFF_VNET_HDR`
TCP segmentation/coalescing offloads, and `--stats-ms` emits JSON health
snapshots. The managed workflow supplies these options from a saved profile.
`--mock --run-ms N` exercises the direct stream without a privileged TUN.

## Security

`qlinq-app` and `qlinq-tun` verify peer certificates by default and support an
application authentication token. Supply the token through `QLINQ_AUTH_TOKEN`
or `--auth-token`, use `--ca` when peers are signed by a private CA, and use
`--tls-group-policy` (`classical`, `prefer-hybrid`, or `require-hybrid`) to
control hybrid post-quantum TLS key exchange. For local testing only,
certificate verification can be disabled explicitly with `--insecure-no-verify`.

```bash
QLINQ_AUTH_TOKEN='replace-with-a-secret' \
  ./qlinq-app --listen 8888 --bind 0.0.0.0 \
  --cert peer.crt --key peer.key --ca mesh-ca.crt
```

## Testing

To run the test suite:

```bash
make check
```

Run `make indent` to format first-party C sources and headers using the
repository's `.clang-format` configuration.
