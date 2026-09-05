# Transport architecture

The native application API is in `qlinq.h`. It provides contexts, authenticated
endpoints, named publishing and subscribed streams, and an owned event queue.
It is implemented as a façade over the lower-level `transport.h` API. The
Quicly implementation is split into small internal modules with one-way
dependencies toward shared data types and the wire codec.

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
| `transport_protocol.c` | HELLO negotiation, stream dispatch, datagram receive, and FEC assembly |
| `transport_publish.c` | Reliable/datagram publication, FEC generation, and grouped data flushes |
| `transport_tracks.c` | Small delivery-class validation and profile derivation |
| `transport_wire.c` | Versioned, bounded byte-level encoding and decoding |
| `transport_stream.c` | Bounded retained stream frames and QUIC acknowledgement accounting |
| `transport_subscriptions.c` | Track/alias lookup, allocation, and stream binding |
| `transport_memory.c` | Packet arena and FEC assembler allocation ownership |
| `transport_fec_state.c` | Reusable FEC contexts and sent-object repair cache |
| `transport_flexicast.c` | Cohort binding, reference-counted IPv4/IPv6 SSM membership, native multicast or packet replication, physical-send accounting, token-bucket execution, and fallback |
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
  unused vector capacity is compacted as frames drain.
- `transport_egress` copies any QUIC packets not accepted immediately by the
  kernel. Quicly is not asked for another batch unless every possible output
  socket has room for one complete batch.
- `transport_wire` is the only code that reads or writes multibyte wire fields.
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
  delivery epoch instead of walking the cohort; receiver ACKs clear epoch debt
  individually.
- Path measurements and scheduler state belong to a connection; one client's
  RTT, loss, or telemetry must never determine another client's schedule.
  Each available path uses its own congestion-window/RTT rate proxy, expressed
  in full-sized FEC symbol equivalents per second. Missing window/RTT samples
  use 100 symbols/s and missing RTT uses 50 ms one-way latency; another path's
  estimate is never substituted. Rate, RTT/2 plus relative one-way delay, and
  cumulative loss are smoothed every 25 ms. The rate is a sending-rate proxy,
  not a measured link capacity.
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
  pathflow from the non-FEC and single-symbol round-robin cases. These events
  describe scheduling decisions, including plans subsequently backpressured.
- Incoming FEC assemblers share a 64 MiB transport-wide memory budget and each
  connection has eight active assembler slots.
- NACK handling sends at most 64 requested symbols per repair. Smooth token
  buckets accept at most 16 requests per connection per second by default and
  at most 256 requests per source transport per second, independent of cohort
  size. `max_repair_requests_per_second` and
  `max_aggregate_repair_requests_per_second` configure those failsafes.
- Outbound NACKs use the same per-connection request ceiling. Missing objects
  remain pending until repair data arrives, so either a local or source-wide
  ceiling can defer work without creating an unrecoverable hole.
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

`transport_publish_ex` distinguishes delivery, buffering, no recipients,
partial delivery, backpressure, invalid input, and internal failure. The legacy
boolean wrapper returns false for partial delivery and all failures.
Reliable publication reports backpressure when retained storage is full.
`max_stream_egress_bytes` defaults to 2 MiB per stream and
`max_total_stream_egress_bytes` to 16 MiB per transport. Hard bounds also limit
retained frames to 256 per stream and vector capacity to 8,192 per transport.
Application data and retryable NACKs leave 64 KiB and 16 frames available on a
control stream, plus 2 MiB and 256 vector slots across the transport, for
essential control. Exhausting essential-control capacity closes the connection
with a resource-limit error. Configuration must accommodate one maximum-sized
reliable object plus control space.

Datagram publication checks the smallest negotiated FEC object limit among
eligible receivers before accepting a record into a group or emitting data.
Grouped records include their two-byte length prefixes in this limit. Short
objects use smaller FEC symbols instead of padding every symbol to the maximum
UDP payload. Received objects preserve the subscribed track flags; applications
recognize grouped FEC data when either FEC flag is present.

Finite fixed-FEC and rateless publishers call `transport_finish_track` after
their final application record. Publication owns per-track internal FEC object
numbering; the finish call freezes the current receiver cohort, flushes a
partial group, and queues a reliable completion watermark on every eligible
control stream. A negotiated rolling checkpoint is also queued every 32 FEC
objects. Receive-side protocol state retains up to eight missing-window bitmaps
and retries one absent object at a time rather than injecting an entire repair
window into a constrained radio queue. Reliable completion ACKs let an
all-capable receiver cohort release cached source objects and produce drained
statistics; eight unacknowledged windows instead produce publication
backpressure. `transport_abort_track` drops retained recovery state and sends a
terminal abort to the current subscribers.
This recovery lifecycle belongs in qlinq because it describes
application-track/FEC object lifetime, while Quicly continues to own delivery
and protection of the reliable control bytes.

`transport_get_stats` reports protocol errors, handshake and reconnect counts,
publication outcomes, FEC outcomes, thread-contract violations, UDP
would-block/errors, current/peak egress occupancy, Flexicast queue/rate
pressure, selected congestion controller and its current rate/burst/limiting
receiver, repair requests, suppressed, merged, or source-throttled feedback,
repair batches, repair queue pressure and age, shared repair symbols and
physical repair airtime, indexed-versus-rateless request counts, rateless
symbols, ESI exhaustion, completed-object replay suppression, and kernel
membership joins/leaves.
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

Component-level tests cover these ownership and lookup boundaries. End-to-end
tests cover connection establishment, authentication, reliable streams,
datagrams, FEC/NACK recovery, IPv4/IPv6 mutual TLS, reconnect after peer
restart, live interface removal, multipath behavior, protected Flexicast fanout,
multicast pacing, and shared kernel-membership teardown.

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

`./examples/multipath_bw_demo` (or `make check-multipath-bw-demo`) is a separate
bandwidth experiment. All four paths are validated before sending; each has a
20 ms one-way delay and independent forward/reverse HTB caps of 1, 2, 4 and
8 Mbps. There is no injected loss, though overflowing a bounded kernel queue
can still drop packets. Offered application traffic ramps from 2 to 12 Mbps
over four seconds, followed by eight seconds at 12 Mbps and a three-second
drain. Publication backpressure is counted as undelivered offered traffic.

The demo records actual kernel dequeue rates, UDP send shares, sampled kernel
queue occupancy and growth, queue drops, application goodput, delivery, and
mean/p95/p99 completion latency. Goodput counts records completed during the
measurement window; delivery/latency cover records offered in that window,
including completions during the drain. Kernel queue milliseconds include the
configured propagation delay and do not include QUIC or application queues.
The kernel samples omit an additional half-second at the start and quarter-
second at the end of the steady window to allow for sampler timing.

The explicit checks require cap compliance within 5%, increasing dequeue rates
with increasing caps, goodput above the fastest individual link's 8 Mbps cap,
at least 99% delivery of offered records, p99 latency at most 250 ms, no steady
queue drops, and late median kernel queues at most 100 ms with growth at most
50 ms. A failing check returns nonzero and preserves `benchmark.log`,
`queues.json`, and `report.json` in a printed temporary directory. Use
`--output-dir PATH` to choose it, or `--benchmark PATH` to compare a compatible
benchmark built with another transport version. Run the report-validator tests
with `python3 examples/test_multipath_bw_demo.py`.

This is a diagnostic target, not part of `release-check`. The benchmark is
intended to expose capacity-estimation and backpressure behavior.
