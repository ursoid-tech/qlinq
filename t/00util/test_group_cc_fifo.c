#include "transport_group_cc.h"
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

enum {
  WRITERS = 50,
  RECEIVERS = 49,
  PACKET_BYTES = 1100,
  HOST_BYTES_PER_SEC = 24000,
  FIFO_PACKETS = 480000 / PACKET_BYTES,
  STEP_MS = 250,
  START = 100000,
  RTT_STEP = START + 20000,
  WARMUP_END = START + 150000,
  END = START + 270000,
  HISTORY = HOST_BYTES_PER_SEC * ((END - START) / 1000) / PACKET_BYTES + 2,
  MAX_BURST = (HOST_BYTES_PER_SEC * STEP_MS / 1000) / PACKET_BYTES + 1,
};

typedef struct {
  double submitted, departed;
  uint64_t received_mask, pacing_rate;
} packet_t;

typedef struct {
  uint64_t epoch, bytes, rate, pacing_rate;
  int64_t sent_start, sent_end, ack_start, ack_end;
  uint32_t flags;
} delivery_bucket_t;

typedef struct {
  size_t ack_cursor;
  int64_t last_ack;
  uint64_t feedback_epoch;
  uint32_t min_raw_rtt, smoothed_rtt;
  bool in_bad_state;
  delivery_bucket_t bucket;
} receiver_t;

typedef struct {
  quicly_flexicast_cc_t *cc;
  double credit;
  size_t count, next_receiver;
  uint64_t delivered_copies, copies_at_last_second;
  unsigned low_ms, longest_low_ms;
  receiver_t receivers[RECEIVERS];
  packet_t packets[HISTORY];
} writer_t;

typedef struct {
  unsigned writer;
  double at;
} arrival_t;
typedef struct {
  packet_t *packet;
  unsigned writer, copies;
} entry_t;

typedef struct {
  writer_t writers[WRITERS];
  entry_t queue[FIFO_PACKETS];
  size_t head, queued, max_queued;
  unsigned capacity;
  uint64_t offered, overflow, departed, measured_departures;
  uint64_t channel_rng, report_rng;
  double tail_at, last_event, byte_msec;
} simulation_t;

typedef struct {
  double service, goodput, jain, min_over_mean, median_bits_per_second,
      mean_queue;
  uint64_t overflow;
  size_t max_queued;
  unsigned healthy_writers, longest_low_ms;
} result_t;

static unsigned draw(uint64_t *state) {
  *state =
      *state * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
  return (uint32_t)(*state >> 32);
}

static int compare_arrivals(const void *a, const void *b) {
  const arrival_t *x = a, *y = b;
  if (x->at == y->at)
    return (x->writer > y->writer) - (x->writer < y->writer);
  return (x->at > y->at) - (x->at < y->at);
}

static int compare_rates(const void *a, const void *b) {
  uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return (x > y) - (x < y);
}

static void advance_clock(simulation_t *s, double now) {
  if (now > WARMUP_END)
    s->byte_msec +=
        s->queued * PACKET_BYTES * (now - fmax(WARMUP_END, s->last_event));
  s->last_event = now;
}

static void drain_until(simulation_t *s, double now) {
  while (s->queued) {
    entry_t *e = &s->queue[s->head];
    if (e->packet->departed > now)
      break;
    advance_clock(s, e->packet->departed);
    if (e->packet->departed > WARMUP_END) {
      ++s->measured_departures;
      s->writers[e->writer].delivered_copies += e->copies;
    }
    ++s->departed;
    --s->queued;
    s->head = (s->head + 1) % FIFO_PACKETS;
  }
  advance_clock(s, now);
}

/* native tx occupies FIFO once; gilbert-elliott loss applies per copy */
static void send_packet(simulation_t *s, arrival_t a) {
  drain_until(s, a.at);
  writer_t *w = &s->writers[a.writer];
  assert(w->count < HISTORY);
  if (!w->count)
    transport_group_cc_mcbbr_on_submitted(w->cc, lround(a.at));
  packet_t *p = &w->packets[w->count++];
  p->submitted = a.at;
  p->pacing_rate = w->cc->output.rate_bytes_per_second;
  ++s->offered;
  if (s->queued == FIFO_PACKETS) {
    ++s->overflow;
    p->departed = s->tail_at;
    return;
  }
  p->departed = s->tail_at =
      fmax(s->tail_at, a.at) + PACKET_BYTES * 1000.0 / s->capacity;
  entry_t *e = &s->queue[(s->head + s->queued++) % FIFO_PACKETS];
  if (s->queued > s->max_queued)
    s->max_queued = s->queued;
  *e = (entry_t){.packet = p, .writer = a.writer};
  for (unsigned r = 0; r < RECEIVERS; ++r) {
    if (p->departed >= RTT_STEP) {
      receiver_t *rx = &w->receivers[r];
      unsigned change = draw(&s->channel_rng) % 100;
      rx->in_bad_state = rx->in_bad_state ? change >= 2 : change < 1;
      unsigned loss = rx->in_bad_state ? 50 : 1;
      if (draw(&s->channel_rng) % 100 < loss)
        continue;
    }
    ++e->copies;
    p->received_mask |= UINT64_C(1) << r;
  }
}

static void transmit_step(simulation_t *s, bool shared, int64_t now) {
  uint64_t rates[WRITERS];
  for (unsigned i = 0; i < WRITERS; ++i)
    rates[i] = s->writers[i].cc->output.rate_bytes_per_second;
  if (shared)
    qsort(rates, WRITERS, sizeof(*rates), compare_rates);
  arrival_t arrivals[WRITERS * MAX_BURST];
  size_t count = 0;
  for (unsigned i = 0; i < WRITERS; ++i) {
    writer_t *w = &s->writers[i];
    transport_group_cc_hints_t hints = {.active_senders = shared ? WRITERS : 1,
                                        .median_sender_rate_bytes_per_second =
                                            shared ? rates[WRITERS / 2]
                                                   : rates[i]};
    transport_group_cc_mcbbr_set_hints(w->cc, &hints, now - STEP_MS);
    double rate = fmin(w->cc->output.rate_bytes_per_second, HOST_BYTES_PER_SEC);
    double credit = w->credit + rate * STEP_MS / 1000;
    unsigned packets = (unsigned)(credit / PACKET_BYTES);
    assert(packets <= MAX_BURST);
    for (unsigned k = 1; k <= packets; ++k)
      arrivals[count++] = (arrival_t){
          .writer = i,
          .at = now - STEP_MS + (k * PACKET_BYTES - w->credit) * 1000 / rate};
    w->credit = credit - packets * PACKET_BYTES;
  }
  qsort(arrivals, count, sizeof(*arrivals), compare_arrivals);
  for (size_t i = 0; i < count; ++i)
    send_packet(s, arrivals[i]);
  drain_until(s, now);
  assert(s->offered == s->overflow + s->departed + s->queued);
}

static void export_previous_bucket(const delivery_bucket_t *b,
                                   quicly_flexicast_feedback_t *f) {
  f->delivery_rate_sample_epoch = b->epoch;
  f->delivery_sample_bytes = b->bytes;
  f->delivery_rate_bytes_per_second = b->rate;
  f->delivery_sample_pacing_rate_bytes_per_second = b->pacing_rate;
  f->delivery_sample_flags = b->flags;
  f->delivery_sample_fanout = 1;
  f->delivery_sample_sent_at_start = b->sent_start;
  f->delivery_sample_sent_at_end = b->sent_end;
  f->delivery_sample_acked_at_start = b->ack_start;
  f->delivery_sample_acked_at_end = b->ack_end;
}

/* DRR selects reporting receivers; ACK prefix visible after propagation and
 * coalescing; FIFO never reorders so holes before largest PN are real loss */
static void report(simulation_t *s, writer_t *w, unsigned member, int64_t now) {
  receiver_t *rx = &w->receivers[member];
  unsigned propagation = now < RTT_STEP ? 40 : 2040;
  propagation += draw(&s->report_rng) % (now < RTT_STEP ? 16 : 180);
  unsigned coalescing = 450 + draw(&s->report_rng) % 6000;
  double visible = (double)now - propagation - coalescing;
  uint64_t bit = UINT64_C(1) << member;
  size_t begin = rx->ack_cursor, end = begin, acknowledged = 0;
  uint64_t reference = 0;
  bool mixed = false, host_limited = false;
  for (size_t i = begin; i < w->count && w->packets[i].departed <= visible;
       ++i) {
    const packet_t *p = &w->packets[i];
    if (!(p->received_mask & bit))
      continue;
    mixed |= acknowledged != 0 && reference != p->pacing_rate;
    host_limited |= p->pacing_rate > HOST_BYTES_PER_SEC;
    reference = p->pacing_rate;
    ++acknowledged;
    end = i + 1;
  }
  if (!acknowledged)
    return;
  const packet_t *last = &w->packets[end - 1];
  uint32_t raw = (uint32_t)(now - lround(last->submitted));
  uint32_t delay = (uint32_t)(now - propagation - lround(last->departed));
  if (!rx->min_raw_rtt || raw < rx->min_raw_rtt)
    rx->min_raw_rtt = raw;
  uint32_t applied = raw >= (uint64_t)rx->min_raw_rtt + delay ? delay : 0;
  uint32_t rtt = raw - applied;
  rx->smoothed_rtt = rx->smoothed_rtt ? (7 * rx->smoothed_rtt + rtt) / 8 : rtt;
  quicly_flexicast_feedback_t f = {.member_id = member + 1,
                                   .epoch = ++rx->feedback_epoch,
                                   .now = now,
                                   .largest_acknowledged = end - 1,
                                   .acked_packets = acknowledged,
                                   .lost_packets = end - begin - acknowledged,
                                   .acked_bytes = acknowledged * PACKET_BYTES,
                                   .raw_rtt_msec = raw,
                                   .latest_rtt_msec = rtt,
                                   .minimum_rtt_msec = rx->min_raw_rtt,
                                   .smoothed_rtt_msec = rx->smoothed_rtt,
                                   .rtt_sample_at = now,
                                   .rtt_sample_epoch = rx->feedback_epoch,
                                   .rtt_ack_delay_msec = delay,
                                   .applied_ack_delay_msec = applied,
                                   .rtt_sample_flags =
                                       QUICLY_FLEXICAST_RTT_VALID};
  if (delay && !applied)
    f.rtt_sample_flags |= QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT;
  export_previous_bucket(&rx->bucket, &f);
  if (rx->last_ack) {
    int64_t start = lround(w->packets[begin - 1].submitted);
    int64_t finish = lround(last->submitted);
    int64_t span = finish - start > now - rx->last_ack ? finish - start
                                                       : now - rx->last_ack;
    rx->bucket = (delivery_bucket_t){
        .epoch = rx->feedback_epoch,
        .bytes = f.acked_bytes,
        .rate = f.acked_bytes * 1000 / span,
        .pacing_rate = reference,
        .sent_start = start,
        .sent_end = finish,
        .ack_start = rx->last_ack,
        .ack_end = now,
        .flags = (mixed ? QUICLY_FLEXICAST_SAMPLE_MIXED
                        : QUICLY_FLEXICAST_SAMPLE_VALID) |
                 (host_limited ? QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED : 0)};
  }
  rx->ack_cursor = end;
  rx->last_ack = now;
  quicly_flexicast_cc_on_feedback(w->cc, &f);
}

static result_t run_fifo(bool shared, unsigned capacity, uint64_t seed) {
  simulation_t *s = calloc(1, sizeof(*s));
  assert(s);
  s->capacity = capacity;
  s->channel_rng = seed;
  s->report_rng = seed ^ UINT64_C(0xc42fc09e6da52d19);
  quicly_flexicast_cc_config_t cfg = {.maximum_members = RECEIVERS,
                                      .startup_rate_bytes_per_second = 32000,
                                      .minimum_rate_bytes_per_second = 250,
                                      .maximum_datagram_size = 1200,
                                      .feedback_timeout_msec = 1000};
  for (unsigned i = 0; i < WRITERS; ++i) {
    writer_t *w = &s->writers[i];
    w->cc = transport_group_cc_mcbbr_new(&cfg, START);
    assert(w->cc);
    w->credit = PACKET_BYTES * (draw(&s->channel_rng) / (double)UINT32_MAX);
    w->next_receiver = i;
    for (unsigned r = 0; r < RECEIVERS; ++r)
      assert(quicly_flexicast_cc_on_member_added(w->cc, r + 1, START) == 0);
  }
  for (int64_t now = START + STEP_MS; now <= END; now += STEP_MS) {
    transmit_step(s, shared, now);
    for (unsigned i = 0; i < WRITERS; ++i) {
      writer_t *w = &s->writers[i];
      if (now > WARMUP_END && (now - WARMUP_END) % 1000 == 0) {
        uint64_t copies = w->delivered_copies - w->copies_at_last_second;
        w->copies_at_last_second = w->delivered_copies;
        w->low_ms =
            copies * PACKET_BYTES <= 3750 * RECEIVERS ? w->low_ms + 1000 : 0;
        if (w->low_ms > w->longest_low_ms)
          w->longest_low_ms = w->low_ms;
      }
      quicly_flexicast_cc_on_timeout(w->cc, now);
      for (unsigned r = 0; r < (now < RTT_STEP ? 6U : 2U); ++r) {
        unsigned member = w->next_receiver++ % RECEIVERS;
        if (now < RTT_STEP || draw(&s->report_rng) % 100 >= 10)
          report(s, w, member, now);
      }
    }
  }
  double seconds = (END - WARMUP_END) / 1000.0;
  result_t result = {.service = s->measured_departures * PACKET_BYTES / seconds,
                     .mean_queue = s->byte_msec / (END - WARMUP_END),
                     .overflow = s->overflow,
                     .max_queued = s->max_queued};
  uint64_t copies[WRITERS];
  double sum_sq = 0, minimum = capacity;
  for (unsigned i = 0; i < WRITERS; ++i) {
    writer_t *w = &s->writers[i];
    double rate = w->delivered_copies * PACKET_BYTES / (RECEIVERS * seconds);
    copies[i] = w->delivered_copies;
    result.goodput += rate;
    result.healthy_writers += rate * 8 >= 33000;
    if (w->longest_low_ms > result.longest_low_ms)
      result.longest_low_ms = w->longest_low_ms;
    sum_sq += rate * rate;
    minimum = fmin(minimum, rate);
    transport_group_cc_mcbbr_free(w->cc);
  }
  free(s);
  assert(result.goodput > 0 && result.goodput <= result.service + 0.001);
  assert(result.service <= capacity + PACKET_BYTES / seconds);
  result.jain = result.goodput * result.goodput / (WRITERS * sum_sq);
  result.min_over_mean = minimum * WRITERS / result.goodput;
  qsort(copies, WRITERS, sizeof(*copies), compare_rates);
  result.median_bits_per_second =
      4.0 * PACKET_BYTES * (copies[WRITERS / 2 - 1] + copies[WRITERS / 2]) /
      (RECEIVERS * seconds);
  return result;
}

void test_fifty_writer_fifo(void) {
  uint64_t seed = UINT64_C(0x17553461);
  const char *seed_text = getenv("QLINQ_TEST_FIFO_SEED");
  if (seed_text) {
    char *end;
    errno = 0;
    seed = strtoull(seed_text, &end, 0);
    assert(end != seed_text && *end == '\0' && *seed_text != '-' && !errno);
  }
  for (unsigned shared = 0; shared <= 1; ++shared) {
    for (unsigned rf_only = 0; rf_only <= 1; ++rf_only) {
      unsigned capacity = rf_only ? 2500000 : 620000;
      result_t r = run_fifo(shared != 0, capacity, seed);
      printf(
          "50 writers (%s, %s) goodput %.0f B/s, link service %.0f B/s, "
          "Jain %.3f, minimum/mean %.3f, median %.0f bit/s, mean queue %.0f B, "
          "healthy %u, longest low %u ms\n",
          shared ? "shared endpoint" : "independent endpoints",
          rf_only ? "RF loss only" : "bottleneck and RF loss", r.goodput,
          r.service, r.jain, r.min_over_mean, r.median_bits_per_second,
          r.mean_queue, r.healthy_writers, r.longest_low_ms);
      fflush(stdout);
      if (rf_only) {
        /* even synchronized writers drain before their next packet */
        assert(r.overflow == 0 && r.max_queued <= WRITERS);
        double radio_survival = (2 * 0.99 + 0.50) / 3;
        assert(r.goodput >=
               WRITERS * HOST_BYTES_PER_SEC * radio_survival * 0.85);
      } else {
        assert(r.goodput >= capacity * 0.5);
        assert(r.median_bits_per_second >= 55000 &&
               r.median_bits_per_second <= 125000);
      }
      assert(r.jain >= 0.85 && r.min_over_mean >= 0.50);
      assert(r.healthy_writers == WRITERS && r.longest_low_ms < 22500);
      assert(r.mean_queue < FIFO_PACKETS * PACKET_BYTES / 2);
    }
  }
}
