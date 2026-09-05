# Native application API

`qlinq.h` is the recommended interface for applications. It presents qlinq as
a collection of named streams carried by authenticated endpoints. The lower
level `transport.h` interface remains available for the daemon and specialized
integrations.

## Model

- A **context** owns endpoints and a bounded event queue.
- An **endpoint** listens for peers or connects to a peer over one or more
  paths.
- A **publishing stream** accepts application records.
- A **subscribed stream** produces owned record events.

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

## Minimal publisher

`qlinq_service_fd(context, timeout_ms, fd, events, &revents)` additionally polls
one borrowed application descriptor using `poll(2)` event bits. It reports
readiness without consuming bytes and follows the same event/deadline semantics.
Pass `fd=-1` to omit it. This lets a TUN wake the network loop without periodic
busy polling.

```c
#include "qlinq.h"

static const char secret[] = "replace-this-secret";

qlinq_context_t *context = qlinq_context_create(NULL);

qlinq_endpoint_config_t endpoint_config = {
    .bind_addresses = {"192.0.2.10"},
    .bind_address_count = 1,
    .port = 8888,
    .security = {
        .shared_secret = secret,
        .shared_secret_size = sizeof(secret) - 1,
        .certificate_file = "peer.crt",
        .private_key_file = "peer.key",
        .trust_store_file = "mesh-ca.crt",
    },
    .group_delivery = {
        .enabled = true,
        .group_address = "232.1.2.3",
        .port = 9000,
        .interface_address = "192.0.2.10",
        .congestion_control = QLINQ_GROUP_CC_ADAPTIVE,
    },
};

qlinq_endpoint_t *endpoint = qlinq_listen(context, &endpoint_config);
qlinq_stream_t *stream = qlinq_publish(
    endpoint,
    &(qlinq_stream_config_t){.content_type = QLINQ_CONTENT_DATA,
                             .delivery = QLINQ_DELIVERY_RATELESS,
                             .name = "telemetry/position"});

const char payload[] = "record bytes";
qlinq_send_result_t sent = qlinq_stream_send(
    stream, &(qlinq_record_t){.group_id = 7,
                              .sequence = 42,
                              .data = payload,
                              .size = sizeof(payload) - 1,
                              .priority = 1});
```

`QLINQ_SEND_SENT` means the record was accepted by the active transport path;
it does not claim that every subscriber has received it. Finite fixed-FEC and
rateless streams call `qlinq_stream_finish()` after their final record so a
partial coding group is flushed and the completion watermark is sent.

## Minimal subscriber

```c
qlinq_endpoint_config_t endpoint_config = {
    .bind_addresses = {"0.0.0.0"},
    .bind_address_count = 1,
    .remote_addresses = {"192.0.2.10"},
    .remote_address_count = 1,
    .port = 8888,
    .security = {
        .shared_secret = secret,
        .shared_secret_size = sizeof(secret) - 1,
        .trust_store_file = "mesh-ca.crt",
    },
    .group_delivery = {
        .enabled = true,
        .interface_address = "192.0.2.20",
        .congestion_control = QLINQ_GROUP_CC_ADAPTIVE,
    },
};

qlinq_endpoint_t *endpoint = qlinq_connect(context, &endpoint_config);
qlinq_stream_t *stream = qlinq_subscribe(
    endpoint,
    &(qlinq_stream_config_t){.content_type = QLINQ_CONTENT_DATA,
                             .delivery = QLINQ_DELIVERY_RATELESS,
                             .name = "telemetry/position"});

for (;;) {
  if (qlinq_service(context, -1) < 0)
    break;

  qlinq_event_t event;
  while (qlinq_next_event(context, &event)) {
    if (event.type == QLINQ_EVENT_RECORD && event.stream == stream) {
      consume(event.record.data, event.record.size);
    }
    qlinq_event_release(&event);
  }
}
```

A subscription may be created before the connection completes. It is retained
and activated after peer authentication. Event record bytes are copied into
the context's bounded queue and remain valid until `qlinq_event_release()`.
For FEC-backed data streams, the façade preserves each record's group,
sequence, keyframe, and priority metadata inside the grouped transport payload;
receivers using the same API recover the original record boundaries and
metadata.

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

The thread that creates a context owns that context, its endpoints, and its
streams. `qlinq_service()` drives socket and timer progress and never invokes
application code from a background thread. A context defaults to 1,024 queued
events and 64 MiB of queued event storage; both bounds are configurable.

Closing a stream or endpoint is immediate from the application's perspective.
Handles remain safe to compare with already queued events until the context is
destroyed. Applications must release popped events before destroying their
context.

## Stream lifecycle

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
A publishing stream starts in `QLINQ_STREAM_OPEN`. `qlinq_stream_send()` may
return `QLINQ_SEND_WOULD_BLOCK` when bounded recovery or egress state is full;
`QLINQ_EVENT_STREAM_WRITABLE` is edge-triggered and reports when the stream can
accept records again. `qlinq_stream_is_writable()` provides the current level.

`qlinq_stream_finish()` starts asynchronous completion for a fixed-FEC or
rateless data stream and changes the publisher to `QLINQ_STREAM_FINISHING`.
It snapshots the currently subscribed receivers, flushes the final coding
group, and rejects further sends. A receiver gets
`QLINQ_EVENT_STREAM_FINISHED` only after every object through the terminal
watermark has either arrived or been recovered. The publisher gets
`QLINQ_EVENT_STREAM_DRAINED` after every receiver in the snapshot has
confirmed completion or departed. Its `completion` fields distinguish the
confirmed and failed/departed counts. A transfer with no current subscribers
drains with all three counts equal to zero. A subscriber arriving after the
snapshot receives `QLINQ_EVENT_STREAM_ABORTED`; applications should use a new
stream name for a new finite transfer.

`qlinq_stream_abort()` immediately makes a publishing stream terminal, drops
its queued recovery state, and queues a reliable notification to its current
subscribers.
Both sides observe `QLINQ_EVENT_STREAM_ABORTED`. `qlinq_stream_get_stats()`
reports the current state, accepted and received record counts, subscriber and
group-member counts, completion confirmations, and writability.

## Current boundary

All context, endpoint and stream operations use the creating thread. QLINQ does
not create worker threads or perform multi-core receive processing. Logging and
experimental record callbacks execute synchronously on that creating thread.
Cross-thread access and calls through the delivering context from either
callback are rejected. An independently owned, popped event can be transferred
to another thread for consumption and release.
The API operates on bounded records. It does not itself provide a continuous
byte stream, receiver-confirmed per-record delivery token, or automatic peer
discovery. The `qlinq-cast` tool demonstrates how ordered file and pipeline
transfer can be built above the context, endpoint, lifecycle, and named-stream
model without changing existing callers.

A connected receiver is not silent: QUIC still requires handshake, packet
acknowledgement, path validation, and liveness traffic even when application
recovery uses proactive rateless symbols. A genuinely one-way receiver mode
would therefore use QUIC only for an optional authenticated bootstrap, then a
separate protected datagram data plane. Receivers that must be silent from the
first packet would need pre-provisioned keys and transfer metadata instead of a
QUIC connection. That mode is intentionally outside this lifecycle API.
