# Transport architecture

The low-level public transport API remains in `transport.h`. The application
wrapper in `qlinq.h` adds owned events and named streams; see
[Native application API](application-api.md). The Quicly implementation is
split into internal modules for connection lifecycle, publication, receive
recovery, path scheduling, and bounded storage.

Specialized integrations may use `transport.h` directly. `qlinq-app` is the
reference low-level consumer: it drives `transport_tick`, integrates
`transport_get_poll_fds` and `transport_get_first_timeout`, publishes with
`transport_publish_ex`, and consumes callbacks without a Unix-socket hop. The
`data_uds` interface remains a daemon adapter for out-of-process packet devices
such as `qlinq-tund`, not the primary application API.

| Module | Responsibility |
| --- | --- |
| `qlinq.c` | Native context, endpoint, named-stream, and owned-event facade |
| `transport_quicly.c` | Connection lifecycle, socket event loop, and public control/query API |
| `transport_internal.h` | Private shared transport and connection state |
| `cli_parse.c` | Shared bounded numeric and endpoint parsing for app and daemon |
| `transport_config.c` | Default resolution and validation of resource limits |
| `transport_protocol.c` | HELLO negotiation, stream dispatch, datagram receive, and FEC decoding |
| `transport_publish.c` | Reliable/datagram publication, FEC generation, and grouped data flushes |
| `transport_recovery.c` | Receive gaps, checkpoint acknowledgements, recovery requests, and assembler expiration |
| `transport_tracks.c` | Small delivery-class validation and profile derivation |
| `transport_wire.c` | Versioned, bounded byte-level encoding and decoding |
| `transport_stream.c` | Bounded retained stream frames and QUIC acknowledgement accounting |
| `transport_subscriptions.c` | Track/alias lookup, allocation, and stream binding |
| `transport_memory.c` | Packet arena and FEC assembler allocation ownership |
| `transport_fec_state.c` | Reusable FEC contexts and sent-object repair cache |
| `fec.c` | Codec selection and Reed-Solomon/RaptorQ encode/decode operations |
| `transport_flexicast.c` | Cohort binding, reference-counted IPv4/IPv6 SSM membership, epoch transitions, and fallback |
| `transport_flexicast_dispatch.c` | Plaintext queues, resumable replication, source-path selection, pacing, and physical accounting |
| `transport_flexicast_repair.c` | Repair intents, requester observations, suppression, and materialization |
| `transport_flexicast_internal.h` | Shared ownership rules and the internal module boundary |
| `transport_paths.c` | QUIC-path mapping and physical-path selection |
| `transport_repair.c` | Bounded NACK symbol reconstruction |
| `transport_scheduler.c` | Per-connection path and redundancy planning |
| `transport_tls.c` | Certificate loading and verifier initialization |
| `transport_egress.c` | Owned, bounded queues for packets awaiting socket writability |
| `transport_udp.c` | Portable UDP batch system calls and Linux GSO acceleration |

The protocol and publication engines operate on private state but do not own the
socket event loop. `transport_quicly.c` coordinates lifecycle and polling while
each module owns its invariants. The public header continues to expose opaque
handles.

The event loop services recovery, grouped publication, interface changes,
received packets, path measurements, and connections in that order. Receive
recovery transitions and expiration deadlines live together; protocol parsing
validates wire records before applying those transitions. The control-stream
parser dispatches one complete frame at a time and consumes it only after its
handler succeeds. Protocol-error closes share accounting; authentication and
resource-limit failures retain their separate classifications. Publication routes
a record into grouping or object delivery once. A group flush calls object
delivery directly and retains its bytes and identity across partial retries.
Recipients are evaluated on every retry, including new subscriptions, while
peers that already accepted the group are skipped.

Physical socket records own addresses, interface identity, egress queues, and
path-open retries. Each connection keeps separate path measurements, telemetry,
and admission budgets indexed by that socket slot. QUIC path IDs are resolved
separately. Removing an interface moves complete records together.
Several remote QUIC paths may share one local socket. The send loop snapshots
their socket ownership once per connection service pass, then scores every
owned QUIC path using live congestion and health information. Physical-path
history is applied only to the QUIC path that produced it. Path-bound datagrams
are serviced across all eligible QUIC paths, so a listener's feedback cannot
remain queued behind a different path sharing its socket. Reliable multipath
batches remain bounded even when all remote paths share one local socket.
Configured and discovered sockets use the same setup and teardown routines.
Transport creation has one failure cleanup path, including partially initialized
connections, sockets, and caches.

## Timing and connection control

`transport_config_t.fec_assembler_timeout_ms` sets the inactivity timeout for
partial FEC objects; zero preserves the 2000 ms default. Expiration releases
assembler memory and reports `TRANSPORT_EVENT_OBJECT_LOST`, including while
outbound NACKs are rate limited. Poll deadlines include assembler expiration
and deferred aggregate-budget retries.

`initial_rtt_ms` sets Quicly's initial RTT estimate, and
`handshake_timeout_rtt_multiplier` sets its handshake timeout in RTT multiples.
Zero preserves each Quicly default. Neither changes the configured QUIC idle
timeout.

Qlinq enables multipath suspicion after two probe timeouts when a healthy
alternative exists. Suspect paths are excluded from new application placement;
Quicly retains retransmission ownership and recovery probes and requires fresh
acknowledgment progress before normal reuse. Congestion control and pacing can
be selected explicitly through the transport and application configuration.
Zero-valued options retain the pinned Quicly defaults.

`transport_close_conn_with_error` accepts zero or a tagged
`QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE` value and an optional reason.
It preserves an existing close reason, ignores unknown connections and invalid
error types, and counts a resource-limit close once. `transport_close_conn`
continues to request an ordinary application close.

Server packet routing uses a bounded 256-slot connection cache keyed by the
stable master CID. Hits still pass Quicly's destination check; collisions and
unknown CIDs fall back to the full scan. Entries are invalidated before their
connections are freed. Path scheduling reuses path-stat snapshots and resolves
the common datagram symbol size once per update. IPv6 link matching includes
the scope ID.

## Ownership rules

- `transport_memory` initializes and destroys arenas and frame assemblers.
- `transport_subscriptions` is the only code that allocates aliases or changes
  subscription entries. Send and receive directions have independent alias
  namespaces and subscription limits, so unsubscribing from incoming data does
  not stop publication to a peer. Gap and checkpoint state is allocated only
  for active subscriptions and released on removal or disconnect.
- `transport_fec_state` owns cached FEC instances and copies of rateless DATA
  objects. Cache slots derive from the configured byte and object limits, up
  to 4,096 objects, matching the receiver's 128 recovery windows of 32 objects.
  An unresolved recovery prefix therefore backpressures publication before
  the sender can exceed the receiver's checkpoint history.
- `transport_stream` emits complete frames in one Quicly egress operation.
  Retained allocations include frame payloads, ownership headers, and vector
  capacity. Partial ACKs keep the entire frame charged until QUIC releases it;
  unused vector capacity is compacted as frames drain. A vector cursor avoids
  rescanning queued output for each packet. Receive
  consumption returns QUIC credit immediately and defers physical compaction
  until the consumed prefix reaches the remaining span. Larger reliable
  windows increase receive memory: used storage can approach twice a stream
  window, with rounded allocation capacity retained until the stream closes.
- `transport_egress` copies any QUIC packets not accepted immediately by the
  kernel. Quicly is not asked for another batch unless every possible output
  socket has room for one complete batch.
- `transport_wire` owns versioned frame encoding/decoding and grouped-record
  decoding.
- Quicly owns Flexicast negotiation and frames, packet protection, the shared
  packet-number/replay spaces, ACK aggregation, per-receiver delivery state,
  loss retirement, and the pluggable multicast congestion-controller API.
  qlinq binds Flow IDs to authenticated subscriptions and owns FEC, endpoint
  choice, membership lifetime, controller selection, physical-send cost,
  bounded pacing queues, and fallback.
- Flexicast membership is capacity-driven rather than machine-word-driven.
  Quicly keeps a hash-indexed dynamic slot table, a multiword active-member
  bitmap, and one contiguous pending-ACK bitmap slab for the sent window. qlinq
  mirrors the authenticated connection cohort with a dense, hash-indexed table
  sized from `limits.max_connections`. Both built-in controllers allocate to
  the same flow capacity. The supported hard ceiling is 16,384 members, and
  the test gate exercises 1,000 members including safe slot reuse while a
  packet is outstanding. The conservative controller uses indexed rate and
  feedback-deadline heaps, so feedback and churn update the limiting receiver
  in `O(log N)`. Native multicast sends use cached listener counts and one
  delivery epoch for feedback accounting; receiver ACKs clear epoch debt
  individually. Dispatch validates cohort readiness and recipient eligibility
  before protecting a new packet. Replication maintains a cursor and per-member
  completion markers so a logical packet can span many bounded pacing bursts.
- Path measurements and scheduler state belong to a connection; one client's
  RTT, loss, or telemetry must never determine another client's schedule.
  Each available path uses its own congestion-window/RTT rate proxy, expressed
  in full-sized FEC symbol equivalents per second. Missing window/RTT samples
  use 100 symbols/s and missing RTT uses 50 ms one-way latency; another path's
  estimate is never substituted. Rate, RTT/2 plus relative one-way delay, and
  cumulative loss are smoothed every 25 ms. The rate is a sending-rate proxy,
  not a measured link capacity.
  QUIC path ranking also uses half of unacknowledged flight as a load-pressure
  estimate, following the same symmetric RTT/2 assumption. This is a heuristic:
  asymmetric ACK routes and bursts need not split flight equally. Quicly still
  enforces the full congestion window.
  At publication, uninitialized paths are sampled immediately and unsent queue
  inputs are refreshed even between ticks: the path's QUIC DATAGRAM frame count
  plus `ceil(socket_egress_bytes / full_symbol_size)`. The socket backlog is
  shared across peers and is included once for each candidate path's completion
  estimate. Publication also includes outstanding bytes in flight. Kernel and
  network queues are excluded. Admission normally permits 50 ms of work (8–64
  symbols); one complete allocation may exceed that allowance after all prior
  debt drains, within the actual 64-frame path queue. Every transmitted symbol
  is charged, so subsequent allocations wait for debt repayment. Rateless DATA
  preflight counts only systematic source symbols, not speculative parity.
  Queue occupancy is not smoothed, so small queues and completed drains take
  effect immediately. Small single-symbol objects do not change the units of
  the stored rate estimate.
  Debug log events from component `scheduler` include connection and physical
  path identity, object identity, symbol size, raw and used bandwidth/latency/
  loss/queue inputs, and planned data/total symbol allocation. `source` identifies
  `cwnd_rtt`, a cold-start `default`, or a test `override`; `mode` distinguishes
  pathflow, non-FEC earliest-completion placement, and single-symbol FEC
  round-robin placement. These events
  describe scheduling decisions, including plans subsequently backpressured.
- Incoming FEC assemblers share a 64 MiB transport-wide memory budget. Each
  connection starts with a small receive window, with an eight-object floor
  when the configured cap permits it, and grows according to observed receive
  rate and RTT up to its configured cap (1,024 objects by default). Growth must
  fit both the old buffers and their replacements within that budget until
  copying completes.
  Rejected growth preserves partial data; reusing existing capacity requires
  no additional allocation allowance.
- NACK handling sends at most 64 requested symbols per repair and accepts at
  most 16 repair requests per connection per second. An exact NACK is coalesced
  while its reliable frame remains retained, including partial ACKs and later
  ACKed ranges behind a missing prefix. Once released, a lost repair response
  can trigger another request. Queue pressure defers NACKs without spending
  rate tokens or consuming essential-control reserves. Outbound requests also
  share `max_aggregate_nack_requests_per_second` across all peers (default 16,
  maximum 65535). This token bucket permits a one-second burst, then refills
  continuously; zero configuration selects the default. Recovery rotates its
  starting peer after an admitted or coalesced request, and pauses request
  scans until the aggregate budget refills. Assembler expiration continues
  during that pause. These limits are local policy, not wire negotiation.
- A NACK from an active Flexicast member produces repair symbols on its shared
  Flexicast flow, not on the requester's data socket. Those symbols therefore
  use the existing protected packet-number space, pacer, physical-airtime
  accounting, and pluggable congestion controller. Exact feedback is
  suppressed for 250 milliseconds in a bounded 64-entry fingerprint cache.
  Accepted feedback then enters a separate 64-object repair-intent table:
  requests for the same object are unioned during a fixed 25 ms holdoff aligned
  with the minimum randomized NACK backoff, so complementary receiver losses
  become one bounded repair batch rather than repeated batches. Symbols already
  materialized in the repair queue remain
  part of the suppression state until physically sent. Once the entire
  checkpoint cohort acknowledges an object range, qlinq cancels pending and
  queued repairs for that range while releasing the matching source cache.
- Rateless-coded tracks negotiate a separate rateless-repair capability.
  `auto` selects constant-size degree-of-freedom feedback when that capability
  is present and falls back to indexed missing-ESI feedback for legacy peers;
  callers can force indexed repair with `transport_config_t.repair_mode`.
  Indexed aggregation takes the bounded union of ESIs. Rateless aggregation
  takes the maximum receiver deficit and allocates fresh monotonic RaptorQ ESIs
  from the maximum initially emitted symbol. Mixed-capability members may use
  both repair modes on one protected flow without conflating their intents.
- Materialized repairs use a dedicated 128-packet queue while ordinary data
  retains its 256-packet queue. Both queues share the configured per-socket
  byte budget. A repair receives priority after 250 ms without repair service;
  while both queues remain backlogged, subsequent repairs require three bytes
  of data airtime credit per byte of repair airtime (a 25% repair share). The
  repair queue drains without that ratio when no new data is waiting, ensuring
  finite transfers can complete.
- Flexicast receivers spread initial and repeated feedback over a deterministic
  25--250 ms window seeded independently per process. The first shared repair
  cancels pending whole-object feedback and narrows later symbol NACKs. Ordinary
  unicast recovery retains the 25 ms delay. This adapts multicast backoff,
  suppression, aggregation, and failsafe-budget concepts without exposing
  another protocol's wire semantics through Quicly.
- Production transports seed that feedback window from the operating system.
  Reproducible scenario harnesses may provide an explicit local seed; the seed
  is neither sent on the wire nor used for packet protection.
- Event payload pointers are borrowed and valid only during the callback.
- The creating thread owns a transport. Callbacks run synchronously on that
  thread and may call non-driving APIs; recursive ticks, callback destruction,
  and cross-thread operations are rejected.
- HELLO negotiation completes before `TRANSPORT_EVENT_CONNECTED`, so capability
  and effective-limit snapshots are valid inside the connected callback.

Both immediate and deferred group sends enter the same plaintext queue and
use the same dispatcher. A pending membership rekey blocks every data and
repair send; the first membership change anchors the 250 ms holdoff. Queue
entries retain their plaintext until each replica has been submitted or abandoned
after a hard socket error.
On rotation, unsent ciphertext is discarded and protected again under the new
epoch. Members already served are skipped, preventing duplicate delivery after
an interrupted fanout. A joined member that never confirms its new key is
demoted after three configured feedback intervals, allowing survivors to resume.
Group ciphertext never enters the generic UDP egress queue.

Each successful kernel submission consumes its exact protected UDP payload
size from the token bucket. The bucket remains bounded independently of cohort
size. High-rate buckets hold at least one millisecond of rate credit, up to the
configured egress byte budget, so the millisecond refill clock does not impose
the previous ten-datagram-per-millisecond ceiling. A smaller byte budget can
limit the achievable rate. Elapsed credit is earned at the previous rate,
before a feedback update changes it. An aggregate bucket also charges every
physical copy; fractional per-flow shares remain finite below one byte/second.
Native submission uses the configured source address and interface via
Linux packet-info ancillary data, including with wildcard binds; replication
selects an available connection path and its matching local socket. A permanent
native submission failure switches the remaining packet to replicated delivery.

RTT samples use the actual kernel submission time, excluding local pacing and
socket waits. Native multicast needs one timestamp; differing replica times
use bounded sparse storage. If that storage is exhausted, the affected RTT
sample is omitted rather than attributing local queue time to the network.
Delivery-rate sampling aggregates all ACK frames in a completed millisecond
bucket and ignores duplicate ACKs, so batching cannot discard delivered bytes
or reset the sampling clock. ECN ancillary data is read on native and replicated
ingress, while per-packet send marking leaves ordinary QUIC socket traffic
unchanged.
Platforms without explicit source selection fall back to replication. Temporary
socket pressure retains the packet for retry. Generic QUIC egress drops a hard
failure at its head and continues, with at most 64 packets processed per flush.

Encoded object admission respects the smallest negotiated limit among eligible
recipients. Oversized publications are rejected before shared transmission;
grouped DATA records also reserve their two-byte framing overhead. Application
events preserve the negotiated track descriptor regardless of symbol encoding.

`transport_publish_ex` distinguishes delivery, buffering, no recipients,
partial delivery, backpressure, invalid input, and internal failure. The legacy
boolean wrapper returns false for partial delivery and all failures. DELIVERED
means accepted by transport queues; it is not a network-delivery confirmation.
Finite-stream checkpoint and completion ACKs provide that stronger guarantee.

Finite fixed-FEC and rateless publishers call `transport_finish_track` after
their final application record. Publication assigns internal FEC object IDs,
freezes the current receiver cohort, flushes the last partial group, emits a
rolling checkpoint every 32 objects, and sends a reliable completion watermark.
Receivers retain at most 128 missing-window bitmaps. Missing-object requests are
pipelined within per-tick, token, and control-queue budgets, with admission
rotating across peers, aliases, and whole/partial-object recovery. Multicast
feedback uses randomized backoff and shared-repair suppression.

Cumulative ACKs release source repair-cache entries. Publication reports
backpressure when protected source entries exhaust the cache's entry or byte
budget. The source cache has a configurable `max_recovery_cache_bytes` payload
budget, defaulting to 16 MiB, and admits objects only when both limits can be met
without evicting protected objects. Configuration must hold a maximum FEC object
and one 32-object recovery window at the grouped publication size. Completed
checkpoints and repeated final watermarks retire obsolete receiver gaps and
partial objects through the acknowledged object ID, preserving other groups,
tracks, and later objects. Receiver completion and publisher cohort settlement
produce separate lifecycle events; aborts release pending recovery state.

This recovery lifecycle belongs in qlinq because it describes application-track
and FEC object lifetime. Quicly owns delivery and protection of reliable control
bytes.

`transport_get_stats` reports protocol errors, handshake and reconnect counts,
publication outcomes, FEC outcomes, thread-contract violations, UDP
would-block/errors, current/peak egress occupancy, Flexicast queue/rate
pressure, selected congestion controller and its current rate/burst/limiting
receiver, repair requests, suppressed, merged, or source-throttled feedback,
repair batches, repair queue pressure and age, shared repair symbols and
physical repair airtime, indexed-versus-rateless request counts, rateless
symbols, ESI exhaustion, completed-object replay suppression, and kernel
membership joins/leaves. `flexicast_payloads_accepted` and
`flexicast_plaintext_bytes_accepted` count encoded payload admission, including
repair payloads. `flexicast_packets_sent` counts distinct protected packet
numbers with at least one successful submission; `flexicast_physical_packets_sent`
and `flexicast_physical_bytes_sent` count actual submissions and their UDP
payload bytes, including each replica. They exclude IP/link headers and do not
prove network delivery. `flexicast_protected_packets_queued` and
`flexicast_protected_bytes_queued` report ciphertext still owned by the dispatcher;
plaintext queue gauges remain separate. At most one active logical packet per
flow retains an extra protected buffer of at most `max_udp_payload_size` bytes.
The public API exposes these counters with the `group_` prefix. Quicly RTT
samples use successful physical submission times; physical byte accounting
does not depend on those timing estimates.
Completion watermark, rolling checkpoint, ACK, cache-release, and cache-
backpressure counts are also reported so finite-flow experiments can
distinguish recovery-window behavior from ordinary gap repair.
Controller output telemetry also reports rate increases and reductions, floor
entries and exits, ACK and other growth, loss/RTT/ECN/timeout/rate-limit/other
reductions, and growth freezes caused by external load. Quicly attributes these
transport-generic controller decisions; qlinq aggregates them with transfer,
recovery-tail, repair-debt, and physical-send measurements without teaching
Quicly about objects or NACK semantics.
`transport_get_conn_stats` adds stable connection IDs, negotiated limits,
authentication state, subscriptions, and receive counters.

Component-level tests cover these ownership and lookup boundaries. A dedicated
member-index gate inserts, removes, and replaces a 1,000-member qlinq cohort
within a 2 MiB index-storage and two-second CPU budget. End-to-end tests cover
connection establishment, authentication, reliable streams, datagrams,
FEC/NACK recovery, IPv4/IPv6 mutual TLS, reconnect and Flexicast rejoin after a
peer restart, address and whole-interface removal, multipath behavior,
protected Flexicast fanout, multicast pacing, abusive membership churn, and
shared kernel-membership teardown. Every multicast correctness scenario runs
against both the standard multicast and adaptive controllers; adaptive remains
an explicit selection rather than the default. A further regression matrix uses
unaltered production rates for sustained fanout to 1, 5, and 12 receivers, alias
cohorts, partial-fanout rekeying, retained old keys, full control queues, egress
backlog, source bind ordering, wildcard binds, incompatible limits, and fixed-FEC
and rateless leading/interior object loss. Cache-capacity admission is tested
with a full 256-object unconfirmed prefix. The public API matrix covers four
delivery modes, DATA and VIDEO, over ordinary QUIC and Flexicast.

`make check` includes the standalone Quicly Flexicast unit suite. CI runs it and
the transport suites under ASan/UBSan via `make check-sanitize`.
`make fuzz-flexicast-state` adds 10,000 stateful model-based cases for membership,
feedback, replay, rekeying, and recovery-cache admission/release to the existing
frame-codec fuzzing. The integration matrix separately permutes authenticated
JOIN/READY/LEAVE transitions across rekey and unsubscribe boundaries.

`transport_unsubscribe` queues the reliable qlinq unsubscribe, immediately
releases the receiver flow and its reference-counted kernel SSM membership,
and permits a later subscribe to negotiate a fresh flow. The source rekeys any
subscribers that remain in the cohort. `make check-flexicast-netns` is an
optional Linux integration test that uses root/CAP_NET_ADMIN or unprivileged
user namespaces to create isolated network namespaces and a bridge. It
validates native IPv4 and IPv6 fan-out plus kernel rejection of multicast
traffic from the wrong source.

`make check-multipath-demo` runs the dynamically discovered Cellular, Wi-Fi,
Satcom and Ethernet profiles in an isolated user/network namespace. It shapes
delay and loss, not bandwidth. The benchmark reports a shared server-traffic
window after all four paths have been active for 500 ms, and fails if the
window is shorter than one second or Ethernet carries no more than half of
the server's UDP payload bytes. This avoids comparing lifetime totals from
paths that joined at different times. Rates include protocol traffic and are
not capacity measurements. Reported QUIC RTT can include an ACK returned on
another link, so it need not equal the configured same-link round-trip delay.

`./examples/multipath_bw_demo --all-modes` (or `make check-multipath-bw-demo`)
runs a separate bandwidth experiment for each delivery mode. All three paths
are validated before sending; each has a 20 ms one-way delay and independent
forward/reverse HTB caps of 500, 1,000 and 2,000 Mbps. The veth MTU is 1,500 bytes;
the benchmark's UDP payload ceiling is 1,452 bytes, leaving room for IPv6 and
UDP headers within that MTU. Shaping is applied to loopback by destination
address. There is no injected loss, though overflowing a bounded kernel queue
can still drop packets. The workload ramps from 250 to 2,000 Mbps over four
seconds, followed by eight seconds at 2,000 Mbps and a three-second drain.
`--offered-mbps`, `--initial-mbps`, and `--single-path` vary the workload.
Publication backpressure is counted as undelivered offered traffic.

All four public delivery modes use 8,000-byte DATA records: `--datagram`
corresponds to `QLINQ_DELIVERY_DATAGRAM`, `--fixed-fec` to
`QLINQ_DELIVERY_FIXED_FEC`, `--rateless` to `QLINQ_DELIVERY_RATELESS`, and
`--reliable` to `QLINQ_DELIVERY_RELIABLE`. Without a delivery flag the demo runs
rateless only. `--all-modes` builds once and runs the four modes sequentially,
each in a fresh user/network namespace, continuing after a failed mode.

Default builds use `-O2`. Run `make clean` before rebuilding after changing
compiler flags, because Make does not track flag changes as dependencies.
The benchmark explicitly configures bounded retained stream budgets of
32 MiB per stream and 64 MiB per transport. The UDP ceiling and stream budgets
are benchmark settings, reported or configured explicitly for this profile.
The producer services both endpoints after at most four records (32 KB),
and during pacing waits; path statistics are sampled at most once per ms.

The demo records actual kernel dequeue rates, UDP send shares, sampled kernel
queue occupancy and growth, queue drops, application goodput, delivery, and
mean/p95/p99 completion latency. Goodput counts records completed during the
measurement window; delivery/latency cover records offered in that window,
including completions during the drain. Kernel queue milliseconds include the
configured propagation delay and do not include QUIC or application queues.
The kernel samples omit an additional half-second at the start and quarter-
second at the end of the steady window to allow for sampler timing.

The explicit checks require cap compliance within 5%, increasing dequeue rates
with increasing caps among paths carrying material traffic, goodput of at least
99% of the configured offer (1,980 Mbps at the default target), at least 99%
delivery of offered records, p99 latency at most 250 ms, no steady
queue drops, and late median kernel queues at most 100 ms with growth at most
50 ms. A failing check returns nonzero and preserves `benchmark.log`,
`queues.json`, and `report.json` in a printed temporary directory. Use
`--output-dir PATH` to choose it, or `--benchmark PATH` to compare a compatible
benchmark built with another transport version. Run the report-validator tests
with `python3 examples/test_multipath_bw_demo.py`.

With `--all-modes`, each mode keeps those files in `PATH/<mode>/`; the parent
`PATH/report.json` records each exit status and report path. The overall command
returns nonzero if any mode fails. A successful all-mode qualification requires
all four per-mode reports to pass.

This is a diagnostic target, not part of `release-check`. The benchmark is
intended to expose capacity-estimation and backpressure behavior.
