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
| `mode` | `fixed-fec` (default), `rateless`, `datagram`, or `reliable` |
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
