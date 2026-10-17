# Paced records: MPTCP/TLS and qlinq reliable

Copy the **contents** of this directory into `qlinq/examples/mtcp/`. The examples
are intended to ship with qlinq; readers then need only its GitHub checkout.
`mtcp` is the requested directory name; the protocol is MPTCP.

This compares the same paced 8 KiB records using native qlinq reliable delivery
and a native Linux MPTCP socket protected with TLS 1.3. It does not use a TUN
interface, iperf, Python, or a separately downloaded reproduction archive.

## Build

Use Linux with MPTCP enabled, sudo access and network namespace support. Install
Git, a C compiler, Make, OpenSSL development headers, Bash, jq, iproute2 (`ip`,
`tc`, `ss`), ethtool, iputils (`ping`), procps (`sysctl`), util-linux (`flock`,
`lscpu`), coreutils and awk. Follow qlinq's build prerequisites for its library.
A restricted container may not allow network namespaces.

From a fresh recursive clone of qlinq:

```sh
git clone --recurse-submodules https://github.com/ursoid-tech/qlinq.git
cd qlinq/examples/mtcp
./build.sh
```

Build without sudo. The default source root is `../..`; while this directory
is staged outside qlinq, use `./build.sh /absolute/path/to/qlinq` instead.
The build uses that checkout's current source and committed dependency versions;
it does not fetch or select a historical benchmark revision. Update the checkout
and submodules yourself when desired, then rebuild. The build records HEAD,
submodule identities, dirty state, compiler, OpenSSL, source/binary/library hashes
and a build log in `.build/`. Do not edit the source during a comparison.

## One comparison

```sh
sudo ./lab.sh up mptcp equal
sudo ./run.sh records 180M 60
sudo ./lab.sh down

sudo ./lab.sh up qlinq equal
sudo ./run.sh records 180M 60
sudo ./lab.sh down
```

`180M` means 180 decimal Mbit/s of offered application payload. A trial takes
about 75 seconds: five seconds for connection setup, 60 seconds of offered work,
and a ten-second drain. Nothing is discarded as warmup. `run.sh` leaves the lab
in place, including after a failed trial; `lab.sh down` removes it and is safe to
repeat. Stop a trial with Ctrl-C and then run teardown.

For the unequal-path cases substitute `unequal` in both setup commands and use
`100M` or `120M` in both runs. Run comparisons sequentially on an otherwise idle
machine. A fresh connection is created for every invocation of `run.sh`.

| Profile | Path 1 | Path 2 | Offered load used in the article |
| --- | --- | --- | --- |
| `equal` | 100 Mbit/s, 20 ms nominal RTT | 100 Mbit/s, 20 ms nominal RTT | 180 Mbit/s |
| `unequal` | 100 Mbit/s, 20 ms nominal RTT | 40 Mbit/s, 80 ms nominal RTT | 100 and 120 Mbit/s |

The router shapes each direction with HTB plus netem delay, a queue limit of
nominal one-way BDP / 1500 bytes rounded up plus 32 packets, and 16 KiB HTB bursts.
GSO/GRO/TSO are disabled on the veths. No random loss is injected; finite queues
can drop packets. Both connections use short-lived local test certificates.
The shared test identity and qlinq test secret are for this isolated example.

## Inspect the setup

```sh
sudo ./lab.sh status
sudo ./lab.sh client ip route show table all
sudo ./lab.sh client ip mptcp endpoint show
sudo ./lab.sh client ss -Mtin
sudo ./lab.sh server ip -br address
```

`lab.sh` is the complete setup/teardown source. It creates `qm-client`,
`qm-server`, and `qm-router` network namespaces. Both endpoints have two virtual
interfaces. Source routing makes the second client address use the second path,
even when connecting to the server's first address. MPTCP setup adds a second
subflow endpoint; qlinq binds the same two client interfaces directly. Host
routes and host sysctls are untouched. Existing lab state/namespaces are refused
rather than reused. Only one lab and one trial may run at a time.

The test process runs as root in its network namespace; use this development
example with the source you trust. No daemon, tunnel device or installed service
is needed. Teardown removes the namespaces and their processes, plus credentials
under `/run/qlinq-mtcp-examples`; results stay in this directory.

## What the result means

Every record carries its original scheduled generation timestamp and sequence.
Latency includes waiting for admission and delivery. Once the offering interval
ends, unsent records are counted as rejected; an in-progress TLS write may finish
during the drain, as in the original driver. Backpressure does not reset the
schedule or make old records look new.

The summary reports offering-window useful payload Mbit/s, received-record p50,
p95 and p99, offered/admitted/received counts, offered delivery percentage,
admitted records still missing after the drain, and summed endpoint process CPU
seconds during the offering interval. The CPU metric excludes some kernel/router
work. P99 includes received records arriving in the drain and excludes records
that never arrive. An admission deficit is **not accepted-data loss**.

This is a same-host test: all three namespaces share `CLOCK_MONOTONIC`.
Do not run the endpoints on different machines with these timestamps.
MPTCP uses the host's default scheduler/controller; qlinq uses its library
configuration. Controllers, startup windows and memory accounting are not
normalized. This compares complete configurations, not an isolated scheduler.

## Results and verification

Each trial creates a new `results/` directory, or use an explicit new directory:

```sh
sudo ./run.sh records 100M 60 results/unequal-100-mptcp-01
./verify.sh results/unequal-100-mptcp-01
```

Raw endpoint CSVs, endpoint JSON, connection logs, socket snapshots, interface
counters, queue counters, unloaded path pings, environment, source identity and
copies of the executed binary/scripts are retained. The pings calibrate the
paths; they are not the application's latency measurement. Private keys are
never copied into results. Failed trials keep diagnostics and a nonzero
`exit-code`; do not silently discard them.

`verify.sh` independently reconstructs record schedules, ordering, delivery
counts and latency percentiles from raw receive samples, then compares them
with the driver's JSON. It checks input hashes, traffic on both interfaces,
MPTCP's two negotiated subflows and verified TLS, or qlinq's per-path payload
counters. Missing admitted records are reported as an outcome, not hidden by
verification. Successful structural verification is not a reliability guarantee.
Run it without sudo after a trial; result ownership is restored to the invoking
sudo user.

Use three trials per backend for unequal/100M, five for unequal/120M and five
for equal/180M to match the article's counts. Alternate backend order, retain
all attempts, and compare medians and ranges rather than selecting the best run.
The article's published numbers belong to its recorded build and original
collector, not automatically to every run of these examples or a future HEAD.

## Files

- `records.c`: the original matched workload, with a `--start` monotonic clock
  helper and argument checks; delivery, pacing and measurement logic preserved.
- `build.sh`: build the library and driver, record source identity.
- `lab.sh`: configure/remove the isolated two-path network and credentials.
- `run.sh`: launch both endpoints, collect diagnostics and print a summary.
- `verify.sh`: independently check raw samples and two-path evidence.
