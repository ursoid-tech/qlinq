# Native application API

Include `qlinq.h` from `src/common` and link `libqlinq.a` with the same system
libraries as `qlinq-app`. The header exposes no Quicly or internal transport
types and is usable from C and C++. The existing `transport.h` API remains
available, and the two APIs exchange the same wire records.

## Contexts, endpoints and streams

Create a context with `qlinq_context_create`, then create listening endpoints
with `qlinq_listen` or connecting endpoints with `qlinq_connect`. A listener
has no remote addresses; a connecting endpoint has at least one. Both require
a port and one or more local bind addresses. A listener accepts multiple
peers; a connecting endpoint represents one peer, optionally over multiple
paths. Configure certificate verification and an application shared secret
through `qlinq_security_config_t`. Secrets are copied; address and file-name
strings need only remain valid during endpoint creation.

`path_interface_names` / `path_interface_count` restrict hot-added paths to
selected interfaces. Match initial bind addresses to the same interfaces;
the allowlist does not configure OS routing.

`qlinq_publish` and `qlinq_subscribe` return named stream handles. Each stream
selects content type and datagram, reliable, fixed-FEC or rateless delivery.
Subscriptions created before authentication activate when peers become ready,
and reactivate after a configured client reconnect. Send and receive streams
with the same name are independent. Stream names are nonempty and at most
63 bytes. `qlinq_stream_close` stops use of the handle and unsubscribes receive
streams; it does not define a finite-transfer completion protocol.

Drive progress with `qlinq_service(context, timeout_ms)` and drain events with
`qlinq_next_event`. Zero timeout polls; -1 waits for network or timer activity.
Pending events return immediately. Internal deadlines also service FEC group
flushes and periodic recovery/path measurements. `QLINQ_EVENT_PEER_READY` means
application authentication completed. Subscriber join/leave events and
`QLINQ_EVENT_STREAM_WRITABLE` let publishers discover recipients and resume
sending. The writable event describes a transition to writable, not a promise
that every future record will fit; always check `qlinq_stream_send`'s result.

`qlinq_service_fd(context, timeout_ms, fd, events, &revents)` additionally polls
one borrowed application descriptor using `poll(2)` event bits. It reports
readiness without consuming bytes and follows the same event/deadline semantics.
Pass `fd=-1` to omit it. This lets a TUN wake the network loop without periodic
busy polling.

```c
qlinq_stream_config_t stream_config = {
    .content_type = QLINQ_CONTENT_DATA,
    .delivery = QLINQ_DELIVERY_RELIABLE,
    .name = "telemetry"
};
qlinq_stream_t *publisher = qlinq_publish(endpoint, &stream_config);
/* Check publisher for NULL and service authentication/subscription events. */
qlinq_record_t record = {
    .sequence = 42, .data = "sample", .size = 6
};
qlinq_send_result_t result = qlinq_stream_send(publisher, &record);
/* WOULD_BLOCK is retryable; SENT/BUFFERED/PARTIAL must not be blindly resent. */

qlinq_status_t status = qlinq_service(context, 10);
/* Handle negative status even when the event queue is full. */
qlinq_event_t event;
while (qlinq_next_event(context, &event)) {
    if (event.type == QLINQ_EVENT_RECORD) {
        /* Consume event.record.data and event.record.size. */
    }
    qlinq_event_release(&event);
}
```

`qlinq_endpoint_get_stats`, `qlinq_endpoint_get_peer`, and
`qlinq_stream_get_stats` expose connection state, recovery/queue counters,
subscriber counts and stream readiness. `qlinq_context_last_status` reports
operation errors, including failures that could not be queued as events.

`qlinq_endpoint_get_stats` copies a snapshot into a caller-owned
`qlinq_endpoint_stats_t` without resetting counters. Read it on the context's
creating thread before closing the endpoint; a synchronized copy can then be
consumed by an application's metrics exporter. The library requires no metrics
backend or serialization. Rebuild callers when updating the public stats
structure.

The endpoint snapshot includes:

- Repair requests by indexed/rateless mode, whole-object requests, coalescing,
  deferral, per-peer/aggregate throttling, source-cache misses, generation
  failures, queue failures and rateless parity exhaustion.
- Recovery checkpoint and ACK totals, cache releases/backpressure, pending
  connection/track states and their maximum age without ACK progress.
- UDP send pressure/errors, dropped queued packets, socket queue peaks, and
  publication outcomes, including buffering, partial acceptance and backpressure.
- Receive assembler memory, resource-limit errors, malformed datagrams, received
  datagrams/stream frames and FEC-assisted completions.

Counters accumulate for the endpoint's lifetime. Occupancy, pending counts and
ages are gauges; peak fields are high-water marks. `egress_peak_packets` and
`egress_peak_bytes` are the maximum individual socket queue peaks, rather than
simultaneous totals across sockets. Field comments in `qlinq.h` define the
individual units and scopes. In particular:

- `repair_symbols_sent` and `repair_rateless_symbols_sent` count symbols admitted
  to the QUIC datagram queue. They do not confirm UDP transmission or delivery.
  `repair_queue_failures` counts requests whose response could not be fully
  queued, including partial responses. `repair_build_failures` includes invalid
  symbol selections and failure after attempting systematic fallback.
- Received indexed/rateless request counts exclude requests rejected by the
  per-peer limiter or without a known subscription, so their sum need not equal
  `repair_requests_received`. `repair_rateless_exhausted` counts attempts that
  exhaust fresh parity IDs; systematic source-symbol fallback may still succeed.
  Coalesced/deferred counts describe request attempts, not unique lost objects.
- `recovery_checkpoints_pending` counts connection/track states awaiting ACK
  progress, not individual checkpoint frames. Partial ACK progress resets the
  pending state's age, so `recovery_oldest_checkpoint_age_ms` is a stall
  indicator rather than a repair-latency measurement. Cache releases also include
  objects released when subscribers leave.
- `fec_objects_recovered` retains its existing meaning: all completed datagram
  objects, including those assembled entirely from original data symbols.
  `fec_objects_decoded` is the subset that required successful FEC decoding.
- `publish_*` fields count calls reaching transport publication. Public API
  prevalidation failures, such as a null record or closed stream, are excluded;
  later group flushes do not count as additional publications.
  `publish_delivered` means accepted for sending to eligible recipients, not
  remote application delivery.

`qlinq_endpoint_get_path_stats` exposes active/validated state, interface/address,
wire byte counters, packet-loss counters and RTT in milliseconds for each path.
Slots can move when interfaces disappear; use interface/address as identity.
`qlinq_endpoint_get_path` adds lifecycle, ACK counts, congestion window,
bytes in flight and delay estimates. Both queries read the same underlying
snapshot. Wire byte counters belong to the physical socket; on listeners,
connection fields describe the first connected peer. Congestion window and
in-flight values count QUIC packet bytes; timing fields use milliseconds.

`congestion_control` selects the default, Reno, Pico or Cubic controller;
`pacing` selects the default, disabled or enabled policy. Zero-initialized
configuration retains the transport defaults (Reno with pacing disabled).
These endpoint settings are fixed at creation and need not match the peer.
To use the explicit CUBIC and pacing configuration measured in the
[MPTCP comparison](mtcp-performance-progress.md), set these fields on the
endpoint configuration before calling `qlinq_listen` or `qlinq_connect`:

```c
config.congestion_control = QLINQ_CC_CUBIC;
config.pacing = QLINQ_PACING_ENABLED;
/* Leave initial_cwnd_packets at zero to retain the 100-packet default. */
```

`initial_cwnd_packets` sets the initial congestion window independently for each
QUIC path. Zero preserves QLINQ's existing **100-packet default**; explicit
values from 1 through `QLINQ_MAX_INITIAL_CWND_PACKETS` (65,535) are accepted.
Quicly applies a two-packet minimum, so a request of 1 produces an effective
two-packet window. The bounded packet count keeps the initial byte-window
calculation within 32 bits. Values outside that range are rejected with
`QLINQ_STATUS_INVALID`; parse signed external input before assigning this
unsigned field. This setting is fixed at endpoint creation and may differ
between peers. It permits controlled configuration experiments; it does not
change the default controller, pacing or window.

Multipath endpoints stop assigning new traffic to a path after two ordinary
probe timeouts when another path has recent progress. QUIC retransmits retained
reliable data on the remaining eligible paths and probes for recovery.
The pinned QUIC implementation also uses `initial_cwnd_packets` as the temporary
flight cap for a recovering path. Reducing it therefore affects both startup
and recovery; evaluate outage behavior as well as initial transfer latency.

## Record compatibility and ownership

Send payloads are borrowed during `qlinq_stream_send`; callers may reuse the
buffer after it returns. Receive payloads and disconnect reasons are copied
into owned events. Pop each event once and release it exactly once with
`qlinq_event_release`. Do not release multiple copies of the same event.

The queue defaults to 1024 events and 64 MiB, including event metadata and
copied payload/string storage. Popping releases queue capacity; popped events
are separately owned by the application and remain valid until release, even
after context destruction. Endpoint and stream pointers in those events cease
to be valid when the context is destroyed. The application must bound its own
collection of retained, popped events.

Event overflow returns a resource-limit status. If a reliable or FEC record
cannot be retained, the affected connection closes with a resource-limit error;
plain datagram delivery can drop under pressure. A full queue may have no room
for an error event, so applications must inspect service status as well.

`qlinq_context_config_t.record_callback` is an experimental, opt-in receive
mode for single-threaded consumers that can process each record from inside
`qlinq_service`. When it is NULL, the owned queued-event behavior above is
unchanged. When non-NULL, `QLINQ_EVENT_RECORD` is delivered synchronously to
the callback and is absent from `qlinq_next_event`; peer, control, writable,
loss, and error events remain queued.

The callback event, record payload, and strings are borrowed and valid only
during that callback. Do not retain their pointers, call `qlinq_event_release`,
or call QLINQ through the delivering context while it runs. Copy data needed
after return. A true callback result accepts the record. A false result drops a
datagram record; reliable and FEC delivery closes the affected connection with
the existing resource-limit error. Existing queue users retain their owned
payloads until release, including after context destruction.

Endpoint statistics separately expose successful queued record events and
their copied payload bytes, accepted callbacks, and rejected callbacks. These
are cumulative receive-bridge counts, not transport/FEC copy counts.

FEC DATA publication uses the transport's existing grouped-record format.
The API splits recovered groups into individual payload events without adding
or interpreting a private record envelope. Consequently, received group and
sequence IDs for FEC DATA identify the transport's coding object, and several
records can share them; per-record application IDs must be carried in the
payload when needed. Other modes expose the transport's object metadata.
Existing payload bytes, including bytes resembling an envelope marker, remain
unchanged. Limits on FEC objects include the transport's grouped-record length
prefixes; no extra wrapper-header allowance is needed.

## Timing, lifecycle and threading

Endpoint timing configuration includes `receive_object_timeout_ms`,
`initial_rtt_ms`, and `handshake_timeout_rtt_multiplier`. The first defaults
to 2000 ms; zero for the other fields keeps the underlying default.

`qlinq_endpoint_shutdown` begins an orderly connection shutdown and stops
reconnect. Continue servicing until `qlinq_endpoint_is_drained`, subject to an
application deadline. `qlinq_endpoint_close` releases the transport immediately.
`qlinq_endpoint_reload_credentials` atomically replaces the identity for future
handshakes. Closing an endpoint closes its stream handles. Closed handles remain
allocated until `qlinq_context_destroy`, which releases endpoints, streams and
unpopped events.

All context, endpoint and stream operations use the creating thread. QLINQ does
not create worker threads or perform multi-core receive processing. Logging and
experimental record callbacks execute synchronously on that creating thread.
Cross-thread access and calls through the delivering context from either
callback are rejected. An independently owned, popped event can be transferred
to another thread for consumption and release.

This interface covers unicast use. It does not expose multicast configuration,
listener-initiated mesh connections, or finite-transfer finish/drain/abort
stream states. The separate Quicly keepalive patches remain separate work.
