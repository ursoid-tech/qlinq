# Linux TUN tool

The supported pilot connects two Linux machines, with one reachable IPv4 UDP
listener. It carries ordinary IP applications through an encrypted, authenticated
QUIC transport with optional FEC. Each endpoint can select up to four uplinks.
There is no registration server or hosted control plane.

## Install

Runtime requirements: OpenSSL libraries, iproute2, Linux TUN, and an unprivileged
`qlinq` service account. `qlinq-tun` is a single native executable; neither Python
nor the OpenSSL CLI is required on the target. Identity generation and validation
use the linked OpenSSL library. Source builds need a C compiler and OpenSSL
development headers. Python 3 is used only by development tests and packaging;
the test certificate fixtures also use the OpenSSL CLI.

```sh
make -j4
sudo make install-tun
sudo systemd-sysusers /usr/local/lib/sysusers.d/qlinq.conf
sudo systemctl daemon-reload
```

`make package-tun` produces a Linux tar archive containing the single executable,
service template, sysusers definition and this guide. It is built for the build
host's architecture and library ABI; test on the target distribution before
deployment. This is an unsigned pilot artifact, not a cross-distribution binary.
The install target supports `DESTDIR` and `PREFIX` for packaging.

To install the archive on a matching target, extract its `usr/local` tree at
the filesystem root, then run the `systemd-sysusers` and `daemon-reload` commands
above. Existing JSON profiles and pairing bundles from the earlier Python
launcher are compatible; no conversion or re-pairing is needed. The obsolete
`qlinq-tun-engine` file from an earlier installation is no longer used or shipped.

Without systemd, create a dedicated non-login `qlinq` account using the host's
account tools and use `up`/`down` or a foreground `run` under your supervisor.

## Pair two machines

On the listener, substitute its publicly reachable IP and actual interface:

```sh
sudo qlinq-tun init office --listen 203.0.113.10:8888 --uplink eth0
```

This generates a private identity and
`/etc/qlinq/tunnels/office/invite.json`. Transfer that invitation to the client
over an authenticated channel such as SSH. It contains a pairing secret; do not
publish it. The private identity key never leaves the machine. Allow UDP port
8888 in the listener's firewall (and port forwarding if it is behind NAT).

On the client, after transferring the invitation:

```sh
sudo qlinq-tun init office --invite ./invite.json --uplink eth0 --uplink wwan0
```

The client generates its own private key and a public identity bundle at
`/etc/qlinq/tunnels/office/peer.json`. Transfer that bundle back over the same
trusted channel, then on the listener:

```sh
sudo qlinq-tun pair office ./peer.json
```

Compare the printed SHA-256 fingerprints over your trusted channel. Pairing
trusts exactly the supplied self-signed identity as a trust anchor; invitations
are not an online enrollment service. A listener accepts one paired client.
Certificates expire after 365 days. For this pilot, re-pair using a new tunnel
profile to rotate or revoke credentials; automated renewal is not implemented.

On both machines:

```sh
sudo qlinq-tun diag office
sudo qlinq-tun up office
sudo qlinq-tun status office
```

On the client:

```sh
ping 10.88.0.1
```

The default listener/client tunnel addresses are `10.88.0.1` and `10.88.0.2`.
Choose another pair during listener initialization using `--local-ip` and
`--peer-ip`. Each is configured as an explicit point-to-point endpoint. Use
`--interface` to choose the device name; otherwise a stable name is derived from
the profile name. Existing interfaces are never commandeered.

`up` means the local process started; `status` must say `connected` to confirm
authentication. A local `diag` success alone does not prove the remote peer is
reachable. `--mock` is a developer-only loopback mode, explicitly marked in status.

## Configuration and routes

The complete profile lives in `/etc/qlinq/tunnels/office/config.json`, mode 600
inside a mode 700 directory. Stop the tunnel before editing it, run `diag`,
then start again. Unknown keys are rejected. Both peers must use the same
delivery mode and compatible MTUs. Names, secrets and track IDs are generated
by the pairing workflow rather than entered independently.

Important fields:

| Field | Meaning |
| --- | --- |
| `uplinks` | Exact Linux interface names; one IPv4 address per available interface at startup |
| `mode` | `fixedrate` (default), `rateless`, `datagram`, or `reliable` |
| `mtu` | Inner IP MTU, 1280–2000, default 1400; configure the same value on both peers |
| `routes` | Explicit remote IPv4 subnets, e.g. `["192.168.50.0/24"]` |
| `queue_ms` | Maximum age of packets in the helper's userspace queues, default 100 ms |
| `run_as` | Unprivileged transport user, default `qlinq` |

The queue limit is **not an end-to-end delivery deadline**. FEC assembly,
transport queues, the network and the application have separate timing behavior.
Measure application latency before choosing a real-time deployment profile.
Reliable mode can add head-of-line delay to inner TCP; benchmark the default FEC
datagram mode first for general packet tunneling.

`--route SUBNET` can also be supplied at initialization. The helper adds routes
without replacing existing ones. They disappear when the non-persistent TUN
closes, including on worker failure. Default routes and routes containing known
tunnel/transport endpoints are rejected. Existing route conflicts fail startup.
For routed LANs you must separately arrange IP forwarding, firewall rules and
return routes on the gateways; qlinq does not change those global settings.

Each selected uplink must already be able to reach the remote endpoint through
the host's routing policy. Selecting interfaces does not configure modem dialing,
DHCP, carrier gateways, NAT or source-policy routing. An absent uplink is reported
as a warning when another selected uplink is available. Interface changes are
forwarded to the transport's path discovery/reconnect machinery. Check the
`active` path state and increasing per-path wire counters to verify actual use.

## Service and diagnostics

For an automatically restarted boot service, stop a manually started instance
before enabling systemd:

```sh
sudo qlinq-tun down office
sudo systemctl enable --now qlinq-tun@office
sudo qlinq-tun status office --json
```

Use `systemctl stop qlinq-tun@office` to stop a systemd-managed instance. Manual
`up` runs independently of your terminal but does not restart a crashed worker;
systemd supplies that supervision. `run office` remains in the foreground for
other service managers. The native root supervisor owns the local control socket
and forks the packet worker from the same executable; the worker drops privileges
before processing peer traffic. Systemd supplies persistent crash/boot supervision.

```sh
sudo qlinq-tun diag office --json
sudo qlinq-tun diagnose office > office-diagnostics.json
sudo qlinq-tun down office
```

`diagnose` prints an allowlisted JSON report with configuration and current
statistics. It excludes secrets, certificate contents, private keys and logs.
It does include interface names, addresses and routes; review before sharing.
Runtime logs are in the profile's `run/` directory and rotate at 1 MiB, retaining
two backups. The control socket is private to the profile owner. A stale status
snapshot is reported explicitly. On Linux, a worker exits if its supervisor dies;
the next startup can reclaim the stale control socket under an exclusive lock.

## Prometheus metrics

Export a profile's current statistics in the Prometheus text format:

```sh
sudo qlinq-tun metrics office
```

For Node Exporter's textfile collector, create a directory readable by its
service account, enable `--collector.textfile.directory` on Node Exporter, and
write an absolute `.prom` path in that directory:

```sh
sudo install -d -m 755 /var/lib/node_exporter/textfile_collector
sudo qlinq-tun metrics office \
  --output /var/lib/node_exporter/textfile_collector/qlinq-office.prom
```

Add `--interval 5` to refresh the file every five seconds in the foreground.
The interval accepts whole seconds from 1 through 3600 and requires `--output`.
Run this command under your service manager, or invoke the one-shot command
from a timer. Use a distinct output file for each tunnel and run only one writer
per file. The existing `qlinq-tun@` service manages the tunnel itself; metrics
collection runs separately so it can report stopped tunnels. The exporter needs
the profile owner's access to the private control socket (normally root).
Node Exporter only needs read access to the exported file and its directory.

Each update atomically replaces the file with mode 644, so readers cannot see
partial updates. Temporary files do not match `*.prom`. The output contains only
allowlisted health/statistics fields, tunnel names and uplink interface/address
labels. It includes no pairing secrets or identity contents. A failed read,
invalid status or failed write exits nonzero and retains the previous file.
SIGINT/SIGTERM stops periodic collection successfully and also retains the file.
No HTTP server or additional runtime dependency is added to qlinq; Prometheus
scrapes Node Exporter's HTTP endpoint.

Every sample has a `tunnel` label. Per-path samples also have `interface` and
`address` labels, rather than unstable path slot numbers. Interface labels use
`lo` for IPv4 loopback (`127.0.0.0/8`), IPv6 loopback (`::1`), and mapped IPv4
loopback addresses. Other paths retain the device name known to the transport,
so identical IPv6 link-local addresses on different uplinks remain distinct.
When the device is unknown, addresses resolve against the local interface list;
unassigned, invalid or ambiguous addresses, or lookup failures, use the literal
label `fallback`. JSON status uses the same names. This lookup does not change
which interfaces the transport discovers or uses.

The initial metrics are:

| Metric | Meaning |
| --- | --- |
| `qlinq_tun_running` | A supervisor answered the local control socket |
| `qlinq_tun_connected` | A fresh snapshot reports an authenticated connection with an active path |
| `qlinq_tun_snapshot_fresh` | A worker snapshot exists and is at most three seconds old |
| `qlinq_tun_snapshot_age_seconds` | Cached snapshot age; absent when stopped |
| `qlinq_tun_metrics_export_time_seconds` | Unix time of the last successful export |
| `qlinq_tun_state{state="..."}` | Last reported state, with sample value 1 |
| `qlinq_tun_tx_packets_total`, `qlinq_tun_tx_bytes_total` | Inner packets/bytes accepted for transport sending |
| `qlinq_tun_rx_packets_total`, `qlinq_tun_rx_bytes_total` | Valid inner packets/bytes received before TUN writes |
| `qlinq_tun_dropped_packets_total` | Combined transmit/receive TUN worker drops |
| `qlinq_tun_fec_completed_objects_total` | Completed datagram objects, including those requiring no FEC decoding |
| `qlinq_tun_fec_decoded_objects_total` | Completed objects that required FEC decoding |
| `qlinq_tun_fec_lost_objects_total` | Datagram objects counted lost by the assembler |
| `qlinq_tun_reconnect_attempts_total` | Worker reconnect attempts |
| `qlinq_tun_transport_queued_bytes` | Current datagram egress queue occupancy |
| `qlinq_tun_path_active` | Path was active/validated in the last snapshot |
| `qlinq_tun_path_tx_bytes_total`, `qlinq_tun_path_rx_bytes_total` | Physical socket wire byte counters |
| `qlinq_tun_path_packets_lost` | Current QUIC path connection loss count, exposed as a gauge |
| `qlinq_tun_path_rtt_seconds` | RTT for active paths with a nonzero measurement |

Worker counters reset when the worker restarts. Wire byte counters reset when
physical sockets are replaced. QUIC path loss counts reset on reconnect, which
is why they are gauges. Use `rate()` on byte/packet counters for throughput;
accepted sends are not remote delivery confirmations. Path labels disappear
when their paths are removed. The last counters/path values remain available
while a worker snapshot is stale, alongside `snapshot_fresh=0` and
`connected=0`. Stopped tunnels emit health/state/export-time samples and omit
traffic/path values rather than inventing zero counters.

Monitor freshness of both the worker and the exporter. For example:

```promql
qlinq_tun_connected == 0
time() - qlinq_tun_metrics_export_time_seconds > 30
rate(qlinq_tun_tx_bytes_total[5m]) * 8
```

Choose the exporter age threshold to exceed its refresh interval and your scrape
interval. If the exporter is killed, its retained file can otherwise appear
healthy indefinitely. Node Exporter's `node_textfile_mtime_seconds` also exposes
file age; monitoring `qlinq_tun_snapshot_fresh` alone does not detect a stopped
exporter. Remove the `.prom` file when permanently removing a tunnel/exporter.

## Verification and pilot boundaries

```sh
make check                    # existing suite plus management acceptance
make check-tun-tool           # focused loopback management tests
sudo make check-tun-real      # isolated real TUN/network namespace acceptance
```

The real test covers authenticated endpoints, ICMP including full-MTU packets,
TCP file integrity, UDP record boundaries, a routed subnet, endpoint restart,
hot-added multipath, traffic during a primary-path blackhole, path removal,
total uplink loss/return and cleanup. It creates its network state inside namespaces,
not on the host's physical interfaces.

In the development namespace test, total uplink loss recovered in approximately
22 seconds after the link returned. A remaining working path avoids that total
outage case. Faster recovery after *all* sockets disappear remains a follow-up;
do not promise subsecond recovery from complete disconnection. `degraded` status
means the authenticated session currently has no validated physical path.

Before an external pilot, run a sustained test on the actual target hardware and
carrier mix, publish throughput/CPU/latency/FEC-overhead results, and test service
startup after boot. The repository tests are not a substitute for that field
validation.

This release does not yet provide a browser dashboard, fleet management, NAT
hole punching, DNS endpoint resolution, default-route VPN, IPv6 tunnel address
setup, multi-peer routing, automatic credential renewal, or a transport-wide
packet expiry deadline. It preserves the advanced transport flag interface and
the separate legacy daemon/TUN controller.
