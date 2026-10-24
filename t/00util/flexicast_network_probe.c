/* Actual transport endpoint for scripts/flexicast_network_measure.py.
 * This is a measurement tool, not a pass/fail performance assertion. All
 * processes share CLOCK_MONOTONIC in Linux network namespaces. */
#include "transport_internal.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#define NS_PER_MS UINT64_C(1000000)
#define NS_PER_SEC UINT64_C(1000000000)
#define LATENCY_BINS 20002
#define MAX_OBJECTS 8000000
#define PAYLOAD_MAGIC UINT64_C(0x514c4e514d454153)
#define ARRIVAL_BUCKET_NS (100 * NS_PER_MS)
/* Maximum 300s production + 20s drain + 0.5s receiver tail, rounded up. */
#define ARRIVAL_BUCKETS 3210

typedef struct {
  uint64_t bins[LATENCY_BINS], count, bytes, max_ns;
} latency_t;

typedef struct {
  uint64_t count, over_100ms, max_ns;
} arrival_latency_t;

typedef struct {
  transport_t *transport;
  moq_track_id_t track;
  bool source, connected, subscribed;
  uint64_t start_ns, duration_ns, phase_ns, transient_ns,
      phase_boundaries_ns[4];
  uint64_t offered_objects, offered_bytes, admitted_objects, admitted_bytes;
  uint64_t overload_objects, received_objects, received_bytes, duplicates;
  uint64_t malformed, trace_read, trace_written, trace_omitted, overwritten;
  uint64_t producer_late_max_ns, loop_pause_max_ns;
  uint64_t max_queued_packets, queued_observations, observations;
  uint8_t seen[MAX_OBJECTS / 8];
  latency_t latency[3][3];
  arrival_latency_t arrival_latency[ARRIVAL_BUCKETS];
  uint64_t arrival_bucket_overflow;
  FILE *metrics, *trace;
} probe_t;

static uint64_t mono_ns(void) {
  return transport_get_monotonic_ns();
}

static bool configure_schedule(probe_t *p, uint64_t phase_ms, uint64_t low_ms,
                               uint64_t transient_ms) {
  /* Low may extend the original observation window, never shorten it. Bound
   * the integer schedule before multiplying so the arrival array stays safe. */
  if (!phase_ms || phase_ms > 100000 || low_ms < phase_ms ||
      low_ms > 300000 - 2 * phase_ms || !transient_ms ||
      transient_ms >= phase_ms)
    return false;
  p->phase_ns = phase_ms * NS_PER_MS;
  p->transient_ns = transient_ms * NS_PER_MS;
  p->phase_boundaries_ns[0] = 0;
  p->phase_boundaries_ns[1] = p->phase_ns;
  p->phase_boundaries_ns[2] = (phase_ms + low_ms) * NS_PER_MS;
  p->phase_boundaries_ns[3] = (2 * phase_ms + low_ms) * NS_PER_MS;
  p->duration_ns = p->phase_boundaries_ns[3];
  return true;
}

static latency_t *emission_latency(probe_t *p, uint64_t emitted) {
  if (emitted >= p->duration_ns)
    return NULL;
  size_t phase = emitted < p->phase_boundaries_ns[1]   ? 0
                 : emitted < p->phase_boundaries_ns[2] ? 1
                                                       : 2;
  uint64_t offset = emitted - p->phase_boundaries_ns[phase];
  size_t segment =
      phase == 1 && offset >= p->phase_ns ? 2 : offset >= p->transient_ns;
  return &p->latency[phase][segment];
}

static double cpu_seconds(void) {
  struct rusage usage;
  getrusage(RUSAGE_SELF, &usage);
  return usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6 +
         usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6;
}

static void on_event(void *data, const transport_event_t *event) {
  probe_t *p = data;
  if (p->source) {
    if (event->type == TRANSPORT_EVENT_AUTH)
      (void)transport_respond_auth(p->transport, event->conn, true);
    return;
  }
  if (event->type == TRANSPORT_EVENT_CONNECTED)
    (void)transport_send_auth(p->transport, event->conn, (uint8_t *)"measure",
                              7);
  if (event->type == TRANSPORT_EVENT_AUTH_COMPLETE && event->auth.success)
    p->connected = true;
  if (event->type != TRANSPORT_EVENT_OBJECT)
    return;
  uint64_t header[3], now = mono_ns();
  if (event->object.size < sizeof(header)) {
    p->malformed++;
    return;
  }
  /* These native-endian payloads are local measurement data, not a wire API. */
  memcpy(header, event->object.data, sizeof(header));
  if (header[0] != PAYLOAD_MAGIC || header[1] >= MAX_OBJECTS || !p->start_ns ||
      header[2] < p->start_ns || header[2] > now) {
    p->malformed++;
    return;
  }
  uint64_t id = header[1];
  if (p->seen[id / 8] & (1U << (id % 8))) {
    p->duplicates++;
    return;
  }
  p->seen[id / 8] |= 1U << (id % 8);
  p->received_objects++;
  p->received_bytes += event->object.size;
  uint64_t delay = now - header[2];
  size_t arrival_index = (now - p->start_ns) / ARRIVAL_BUCKET_NS;
  if (arrival_index < ARRIVAL_BUCKETS) {
    arrival_latency_t *arrival = &p->arrival_latency[arrival_index];
    arrival->count++;
    arrival->over_100ms += delay > 100 * NS_PER_MS;
    if (delay > arrival->max_ns)
      arrival->max_ns = delay;
  } else {
    p->arrival_bucket_overflow++;
  }
  uint64_t emitted = header[2] - p->start_ns;
  latency_t *latency = emission_latency(p, emitted);
  if (!latency)
    return;
  size_t bin = (delay + NS_PER_MS - 1) / NS_PER_MS;
  if (bin >= LATENCY_BINS)
    bin = LATENCY_BINS - 1;
  latency->bins[bin]++;
  latency->count++;
  latency->bytes += event->object.size;
  if (delay > latency->max_ns)
    latency->max_ns = delay;
}

static void print_state(FILE *out, const quicly_flexicast_cc_trace_state_t *s) {
  fprintf(
      out,
      "{\"available\":%u,\"control_epoch\":%" PRIu64
      ",\"control_interval_ms\":%" PRIu64 ",\"growth_blocked_until\":%" PRId64
      ",\"last_growth_epoch\":%" PRIu64 ",\"last_reduction_epoch\":%" PRIu64
      ",\"recent_delivery_Bps\":%" PRIu64 ",\"expected_delivery_Bps\":%" PRIu64
      ",\"last_delivery_sample_epoch\":%" PRIu64
      ",\"baseline_delivery_ratio_ppm\":%u,\"recent_delivery_ratio_ppm\":%u"
      ",\"baseline_loss_ppm\":%u,\"rising_delay_epochs\":%u"
      ",\"minimum_rtt_ms\":%u,\"previous_rtt_ms\":%u"
      ",\"unanswered_probes\":%u,\"startup_probes\":%u,\"external_load\":%u"
      ",\"next_timeout\":%" PRId64 ",\"last_feedback_epoch\":%" PRIu64
      ",\"degraded_delivery_epochs\":%u,\"flat_loss_epochs\":%u",
      s->available, s->control_epoch, s->control_interval_msec,
      s->growth_blocked_until, s->last_growth_epoch, s->last_reduction_epoch,
      s->recent_delivery_rate, s->expected_delivery_rate,
      s->last_delivery_sample_epoch, s->baseline_delivery_ratio_ppm,
      s->recent_delivery_ratio_ppm, s->baseline_loss_ppm,
      s->rising_delay_epochs, s->minimum_rtt, s->previous_rtt,
      s->unanswered_probes, s->startup_probes, s->external_load,
      s->next_timeout, s->last_feedback_epoch, s->degraded_delivery_epochs,
      s->flat_loss_epochs);
#ifdef QUICLY_FLEXICAST_SAMPLE_PRESENT
  fprintf(out,
          ",\"last_growth_at_ms\":%" PRId64 ",\"last_reduction_at_ms\":%" PRId64
          ",\"last_rtt_sample_epoch\":%" PRIu64
          ",\"previous_rtt_at_ms\":%" PRId64,
          s->last_growth_at, s->last_reduction_at, s->last_rtt_sample_epoch,
          s->previous_rtt_at);
#endif
#ifdef QUICLY_FLEXICAST_CC_TRACE_DELIVERY_CEILING
  fprintf(out,
          ",\"delivery_ceiling_Bps\":%" PRIu64
          ",\"delivery_ceiling_eligible\":%u,\"delivery_sample_post_cut\":%u"
          ",\"delivery_sample_ratio_ppm\":%u",
          s->delivery_ceiling_bytes_per_second, s->delivery_ceiling_eligible,
          s->delivery_sample_post_cut, s->delivery_sample_ratio_ppm);
#endif
#ifdef QUICLY_FLEXICAST_CC_TRACE_DRAIN
  fprintf(out,
          ",\"drain_phase\":%u,\"drain_member_id\":%" PRIu64
          ",\"drain_ceiling_Bps\":%" PRIu64 ",\"drain_target_Bps\":%" PRIu64
          ",\"drain_started_at_ms\":%" PRId64 ",\"drain_deadline_ms\":%" PRId64
          ",\"drain_ended_at_ms\":%" PRId64,
          s->drain_phase, s->drain_member_id, s->drain_ceiling_bytes_per_second,
          s->drain_target_bytes_per_second, s->drain_started_at,
          s->drain_deadline, s->drain_ended_at);
#endif
  fputc('}', out);
}

static void drain_trace(probe_t *p, transport_flexicast_flow_t *flow) {
  if (!p->trace || !flow)
    return;
  quicly_flexicast_cc_trace_event_t events[128];
  size_t count;
  while ((count = quicly_flexicast_cc_read_flow_trace(flow->crypto, events, 128,
                                                      &p->overwritten))) {
    p->trace_read += count;
    for (size_t i = 0; i < count; i++) {
      quicly_flexicast_cc_trace_event_t *e = &events[i];
      /* Hints happen on most ticks. Retain every rate-changing hint and every
       * feedback/timeout, but explicitly account for the omitted records. */
      if (e->type == QUICLY_FLEXICAST_CC_TRACE_HINTS &&
          e->rate_before == e->rate_after &&
          memcmp(&e->state_before, &e->state_after, sizeof(e->state_before)) ==
              0) {
        p->trace_omitted++;
        continue;
      }
      p->trace_written++;
      const quicly_flexicast_feedback_t *f = &e->feedback;
      fprintf(
          p->trace,
          "{\"sequence\":%" PRIu64 ",\"drained_mono_ns\":%" PRIu64
          ",\"now_wall_ms\":%" PRId64 ",\"type\":%u,\"member\":%" PRIu64
          ",\"rate_before_Bps\":%" PRIu64 ",\"rate_after_Bps\":%" PRIu64
          ",\"reason\":%u,\"feedback\":{\"epoch\":%" PRIu64
          ",\"largest_acknowledged\":%" PRIu64 ",\"acked_packets\":%" PRIu64
          ",\"acked_bytes\":%" PRIu64 ",\"lost_packets\":%" PRIu64
          ",\"lost_bytes\":%" PRIu64 ",\"delivered_bytes\":%" PRIu64
          ",\"delivery_Bps\":%" PRIu64 ",\"delivery_epoch\":%" PRIu64
          ",\"ecn_ce_count\":%" PRIu64
          ",\"latest_rtt_ms\":%u,\"minimum_rtt_ms\":%u,\"smoothed_rtt_ms\":%u"
          ",\"ack_delay_ms\":%u},\"hints\":{\"active_senders\":%u"
          ",\"delivery_divisor\":%u,\"median_sender_Bps\":%" PRIu64
          ",\"aggregate_limit_Bps\":%" PRIu64
          ",\"external_load_epoch\":%" PRIu64
          ",\"external_queued_bytes\":%" PRIu64
          ",\"external_oldest_ms\":%" PRIu64 ",\"external_fraction_ppm\":%u}",
          e->sequence, mono_ns(), e->now, e->type, e->member_id, e->rate_before,
          e->rate_after, e->reason, f->epoch, f->largest_acknowledged,
          f->acked_packets, f->acked_bytes, f->lost_packets, f->lost_bytes,
          f->delivered_bytes, f->delivery_rate_bytes_per_second,
          f->delivery_rate_sample_epoch, f->ecn_ce_count, f->latest_rtt_msec,
          f->minimum_rtt_msec, f->smoothed_rtt_msec, f->ack_delay_msec,
          e->hints.active_senders, e->hints.delivery_rate_divisor,
          e->hints.median_sender_rate_bytes_per_second,
          e->hints.aggregate_rate_limit_bytes_per_second,
          e->hints.external_load_epoch, e->hints.external_load_queued_bytes,
          e->hints.external_load_oldest_age_msec,
          e->hints.external_load_fraction_ppm);
#ifdef QUICLY_FLEXICAST_SAMPLE_PRESENT
      fprintf(
          p->trace,
          ",\"sample_context\":{\"flags\":%u,\"fanout\":%u,\"bytes\":%" PRIu64
          ",\"pacing_Bps\":%" PRIu64 ",\"sent_start_ms\":%" PRId64
          ",\"sent_end_ms\":%" PRId64 ",\"acked_start_ms\":%" PRId64
          ",\"acked_end_ms\":%" PRId64 ",\"rtt_epoch\":%" PRIu64
          ",\"rtt_at_ms\":%" PRId64 ",\"raw_rtt_ms\":%u"
          ",\"rtt_ack_delay_ms\":%u,\"applied_ack_delay_ms\":%u,\"rtt_flags\":%"
          "u}",
          f->delivery_sample_flags, f->delivery_sample_fanout,
          f->delivery_sample_bytes,
          f->delivery_sample_pacing_rate_bytes_per_second,
          f->delivery_sample_sent_at_start, f->delivery_sample_sent_at_end,
          f->delivery_sample_acked_at_start, f->delivery_sample_acked_at_end,
          f->rtt_sample_epoch, f->rtt_sample_at, f->raw_rtt_msec,
          f->rtt_ack_delay_msec, f->applied_ack_delay_msec,
          f->rtt_sample_flags);
#endif
      fputs(",\"before\":", p->trace);
      print_state(p->trace, &e->state_before);
      fputs(",\"after\":", p->trace);
      print_state(p->trace, &e->state_after);
      fputs("}\n", p->trace);
    }
  }
}

static void sample(probe_t *p, uint64_t now, double cpu_start,
                   transport_flexicast_flow_t *flow) {
  transport_stats_t stats;
  transport_get_stats(p->transport, &stats);
  quicly_flexicast_cc_output_t cc = {0};
  if (flow)
    quicly_flexicast_cc_get_flow_output(flow->crypto, &cc);
  fprintf(p->metrics,
          "{\"kind\":\"sample\",\"elapsed_s\":%.9f,\"cpu_s\":%.9f"
          ",\"offered_objects\":%" PRIu64 ",\"offered_bytes\":%" PRIu64
          ",\"admitted_objects\":%" PRIu64 ",\"admitted_bytes\":%" PRIu64
          ",\"application_overload_objects\":%" PRIu64
          ",\"received_objects\":%" PRIu64 ",\"received_bytes\":%" PRIu64
          ",\"physical_bytes\":%" PRIu64 ",\"physical_packets\":%" PRIu64
          ",\"native_packets\":%" PRIu64 ",\"fallbacks\":%" PRIu64
          ",\"ack_frames\":%" PRIu64 ",\"controller_Bps\":%" PRIu64
          ",\"pacer_Bps\":%" PRIu64 ",\"queued_packets\":%zu"
          ",\"rate_increases\":%" PRIu64 ",\"rate_reductions\":%" PRIu64
          ",\"trace_read\":%" PRIu64 ",\"trace_written\":%" PRIu64
          ",\"trace_omitted_unchanged_hints\":%" PRIu64
          ",\"trace_overwritten\":%" PRIu64 "}\n",
          (double)(now - p->start_ns) / NS_PER_SEC, cpu_seconds() - cpu_start,
          p->offered_objects, p->offered_bytes, p->admitted_objects,
          p->admitted_bytes, p->overload_objects, p->received_objects,
          p->received_bytes, stats.flexicast_physical_bytes_sent,
          stats.flexicast_physical_packets_sent,
          stats.flexicast_native_packets_sent, stats.flexicast_fallbacks,
          stats.flexicast_acks_received, cc.rate_bytes_per_second,
          flow ? flow->pacing_rate_bytes_per_second : 0,
          flow ? flow->data_queue.count : 0, cc.rate_increase_events,
          cc.rate_reduction_events, p->trace_read, p->trace_written,
          p->trace_omitted, p->overwritten);
  fflush(p->metrics);
}

static size_t percentile(const latency_t *latency, unsigned percent) {
  uint64_t target = (latency->count * percent + 99) / 100, count = 0;
  for (size_t i = 0; i < LATENCY_BINS; i++) {
    count += latency->bins[i];
    if (count >= target)
      return i;
  }
  return LATENCY_BINS - 1;
}

int main(int argc, char **argv) {
  if (argc != 17 && argc != 18) {
    fprintf(stderr,
            "usage: %s source|client bind source native|replica phase_ms "
            "transient_ms drain_ms offer_Bps startup_Bps minimum_Bps "
            "maximum_Bps backlog object_size start_file metrics_file "
            "trace_file|off [low_phase_ms]\n",
            argv[0]);
    return 2;
  }
  probe_t *p = calloc(1, sizeof(*p));
  if (!p)
    return 2;
  p->source = strcmp(argv[1], "source") == 0;
  bool native = strcmp(argv[4], "native") == 0;
  uint64_t phase_ms = strtoull(argv[5], NULL, 10);
  uint64_t low_ms = argc == 18 ? strtoull(argv[17], NULL, 10) : phase_ms;
  uint64_t transient_ms = strtoull(argv[6], NULL, 10);
  uint64_t drain_ms = strtoull(argv[7], NULL, 10);
  uint64_t offer_rate = strtoull(argv[8], NULL, 10);
  size_t backlog = strtoull(argv[12], NULL, 10);
  size_t object_size = strtoull(argv[13], NULL, 10);
  if (!configure_schedule(p, phase_ms, low_ms, transient_ms) ||
      drain_ms > 20000 || !offer_rate || offer_rate > 10000000 || !backlog ||
      backlog > 128 || object_size < 24 || object_size > 1100 ||
      offer_rate * (p->duration_ns / NS_PER_SEC + 1) / object_size >=
          MAX_OBJECTS)
    return 2;
  uint64_t drain_ns = drain_ms * NS_PER_MS;
  p->metrics = fopen(argv[15], "w");
  if (!p->metrics)
    return 2;
  if (p->source && strcmp(argv[16], "off") != 0) {
    p->trace = fopen(argv[16], "w");
    if (!p->trace)
      return 2;
    setvbuf(p->trace, NULL, _IOFBF, 256 * 1024);
  }
  p->track = (moq_track_id_t){.type = MOQ_TRACK_VIDEO, .name = "measure/video"};
  transport_config_t config = {
      .bind_hosts = {argv[2]},
      .num_bind_hosts = 1,
      .port = 19891,
      .allow_insecure_peer = true,
      .enable_flexicast = true,
      .flexicast_interface = argv[2],
      .callback = on_event,
      .user_data = p,
      .flexicast_cc_mode = TRANSPORT_FLEXICAST_CC_ADAPTIVE,
      .flexicast_cc_startup_rate = strtoull(argv[9], NULL, 10),
      .flexicast_cc_minimum_rate = strtoull(argv[10], NULL, 10),
      .flexicast_cc_maximum_rate = strtoull(argv[11], NULL, 10)};
  if (p->source) {
    config.cert_file = "t/assets/server.crt";
    config.key_file = "t/assets/server.key";
    if (native) {
      config.flexicast_group = "232.42.42.71";
      config.flexicast_group_port = 19892;
    }
  } else {
    config.remote_hosts[0] = argv[3];
    config.num_remote_hosts = 1;
  }
  p->transport = transport_create(&config);
  if (!p->transport)
    return 1;
  transport_flexicast_flow_t *flow = NULL;
  uint64_t deadline = mono_ns() + 20 * NS_PER_SEC;
  bool ready = false;
  while (!p->start_ns && mono_ns() < deadline) {
    transport_tick(p->transport);
    if (!p->source && p->connected && !p->subscribed)
      p->subscribed = transport_subscribe(p->transport, p->track);
    if (p->source) {
      flow = transport_flexicast_find_source(p->transport, &p->track);
      if (!ready && flow && flow->listening_count == 2) {
        if (p->trace &&
            quicly_flexicast_cc_enable_flow_trace(flow->crypto, 8192) != 0)
          return 1;
        fprintf(p->metrics,
                "{\"kind\":\"ready\",\"members\":2,\"native\":%s}\n",
                flow->native_multicast ? "true" : "false");
        fflush(p->metrics);
        ready = true;
      }
    }
    FILE *start = fopen(argv[14], "r");
    if (start) {
      if (fscanf(start, "%" SCNu64, &p->start_ns) != 1)
        p->start_ns = 0;
      fclose(start);
    }
    drain_trace(p, flow);
    usleep(1000);
  }
  if (!p->start_ns || (p->source && !ready)) {
    fprintf(stderr, "measurement readiness/start timeout\n");
    return 1;
  }
  while (mono_ns() < p->start_ns) {
    transport_tick(p->transport);
    drain_trace(p, flow);
    usleep(1000);
  }
  uint8_t payload[1100] = {0};
  uint64_t next_offer = p->start_ns, next_sample = p->start_ns;
  uint64_t interval = object_size * NS_PER_SEC / offer_rate;
  if (!interval)
    interval = 1;
  uint64_t last_loop = mono_ns();
  double cpu_start = cpu_seconds();
  uint64_t finish = p->start_ns + p->duration_ns + drain_ns +
                    (p->source ? 0 : NS_PER_SEC / 2);
  fprintf(
      p->metrics,
      "{\"kind\":\"start\",\"mono_ns\":%" PRIu64 ",\"wall_ms\":%" PRId64
      ",\"duration_s\":%.3f,\"phase_s\":%.3f"
      ",\"low_phase_s\":%.3f,\"phase_boundaries_s\":[0,%.3f,%.3f,%.3f]"
      ",\"transient_s\":%.3f,\"object_size\":%zu,\"backlog_limit_packets\":%zu"
      ",\"configured_offer_Bps\":%" PRIu64 ",\"trace_enabled\":%s}\n",
      p->start_ns, transport_get_time_ms(), p->duration_ns / 1e9,
      p->phase_ns / 1e9, low_ms / 1000.0, p->phase_boundaries_ns[1] / 1e9,
      p->phase_boundaries_ns[2] / 1e9, p->phase_boundaries_ns[3] / 1e9,
      p->transient_ns / 1e9, object_size, backlog, offer_rate,
      p->trace ? "true" : "false");
  while (mono_ns() < finish) {
    uint64_t now = mono_ns();
    if (now - last_loop > p->loop_pause_max_ns)
      p->loop_pause_max_ns = now - last_loop;
    last_loop = now;
    transport_tick(p->transport);
    if (p->source && now < p->start_ns + p->duration_ns) {
      /* The offered schedule is independent of the controller. CPU stalls do
       * not silently lower the offered rate: overdue work is counted/dropped.
       * At most one bounded batch is admitted on each scheduling turn. */
      unsigned attempts = 0;
      while (next_offer <= now && next_offer < p->start_ns + p->duration_ns) {
        uint64_t id = p->offered_objects++;
        p->offered_bytes += object_size;
        uint64_t lateness = now - next_offer;
        if (lateness > p->producer_late_max_ns)
          p->producer_late_max_ns = lateness;
        next_offer += interval;
        if (++attempts > 64 || !flow || flow->data_queue.count >= backlog) {
          p->overload_objects++;
          continue;
        }
        uint64_t header[3] = {PAYLOAD_MAGIC, id, mono_ns()};
        memcpy(payload, header, sizeof(header));
        moq_object_t object = {.track_id = p->track,
                               .group_id = 1,
                               .object_id = p->admitted_objects,
                               .data = payload,
                               .size = object_size,
                               .priority = 1};
        if (transport_publish_ex(p->transport, &object) ==
            TRANSPORT_PUBLISH_DELIVERED) {
          p->admitted_objects++;
          p->admitted_bytes += object_size;
        } else {
          p->overload_objects++;
        }
      }
      p->observations++;
      p->queued_observations += flow && flow->data_queue.count > 0;
      if (flow && flow->data_queue.count > p->max_queued_packets)
        p->max_queued_packets = flow->data_queue.count;
    }
    drain_trace(p, flow);
    if (now >= next_sample) {
      sample(p, now, cpu_start, flow);
      next_sample += NS_PER_SEC;
    }
    usleep(1000);
  }
  uint64_t observation_end_ns = mono_ns();
  drain_trace(p, flow);
  sample(p, mono_ns(), cpu_start, flow);
  if (!p->source) {
    /* Do not turn post-measurement output time into observed receive time. */
    uint64_t observed_until = observation_end_ns - p->start_ns;
    size_t buckets =
        (observed_until + ARRIVAL_BUCKET_NS - 1) / ARRIVAL_BUCKET_NS;
    if (buckets > ARRIVAL_BUCKETS)
      buckets = ARRIVAL_BUCKETS;
    for (size_t i = 0; i < buckets; i++) {
      arrival_latency_t *bucket = &p->arrival_latency[i];
      fprintf(
          p->metrics,
          "{\"kind\":\"arrival_latency_bucket\",\"begin_s\":%.3f,\"end_s\":%.3f"
          ",\"complete\":%s,\"objects\":%" PRIu64 ",\"over_100ms\":%" PRIu64
          ",\"max_latency_ms\":%.6f}\n",
          (double)(i * ARRIVAL_BUCKET_NS) / NS_PER_SEC,
          (double)((i + 1) * ARRIVAL_BUCKET_NS) / NS_PER_SEC,
          (i + 1) * ARRIVAL_BUCKET_NS <= observed_until ? "true" : "false",
          bucket->count, bucket->over_100ms, bucket->max_ns / 1e6);
    }
  }
  /* Keep the original six entries in their original order. The extended low
   * interval is a separate seventh entry, including every latency miss. */
  size_t windows = low_ms > phase_ms ? 7 : 6;
  for (size_t i = 0; i < windows; i++) {
    size_t phase = i < 6 ? i / 2 : 1;
    size_t segment = i < 6 ? i % 2 : 2;
    latency_t *l = &p->latency[phase][segment];
    fprintf(p->metrics,
            "{\"kind\":\"latency\",\"emission_phase\":%zu,\"segment\":\"%s\""
            ",\"objects\":%" PRIu64 ",\"bytes\":%" PRIu64
            ",\"p50_upper_ms\":%zu,\"p99_upper_ms\":%zu,\"max_ms\":%.6f"
            ",\"overflow_over_20000ms\":%" PRIu64 "}\n",
            phase,
            segment == 2 ? "late"
            : segment    ? "steady"
                         : "transient",
            l->count, l->bytes, l->count ? percentile(l, 50) : 0,
            l->count ? percentile(l, 99) : 0, l->max_ns / 1e6,
            l->bins[LATENCY_BINS - 1]);
  }
  fprintf(p->metrics,
          "{\"kind\":\"health\",\"duplicates\":%" PRIu64
          ",\"malformed\":%" PRIu64 ",\"max_queued_packets\":%" PRIu64
          ",\"queued_observations\":%" PRIu64 ",\"observations\":%" PRIu64
          ",\"producer_lateness_max_ms\":%.6f,\"loop_pause_max_ms\":%.6f"
          ",\"arrival_bucket_overflow\":%" PRIu64 "}\n",
          p->duplicates, p->malformed, p->max_queued_packets,
          p->queued_observations, p->observations,
          p->producer_late_max_ns / 1e6, p->loop_pause_max_ns / 1e6,
          p->arrival_bucket_overflow);
  fclose(p->metrics);
  if (p->trace)
    fclose(p->trace);
  transport_destroy(p->transport);
  free(p);
  return 0;
}
