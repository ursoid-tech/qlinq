/*
 * Deterministic fluid-queue model, not a transport latency benchmark.
 *
 * Both controller versions receive the same model: a 50 ms feedback clock,
 * 20 ms base RTT, and a one-second bottleneck buffer. Capacity falls from
 * 100,000 to 20,000 bytes/second at 5 seconds and recovers at 30 seconds.
 * The runner compiles this file against each version and checks its CSV.
 */
#include "quicly/flexicast_cc.h"

#include <assert.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>

#define MODEL_STEP_MSEC 50
#define MODEL_STEPS 1200
#define MODEL_BASE_RTT_MSEC 20
#define MODEL_CAPACITY_HIGH 100000
#define MODEL_CAPACITY_LOW 20000

static uint64_t model_rate(quicly_flexicast_cc_t *controller) {
  quicly_flexicast_cc_output_t output;
  quicly_flexicast_cc_get_output(controller, &output);
  return output.rate_bytes_per_second;
}

static void run_scenario(const char *name, size_t members, double radio_loss,
                         bool heterogeneous, bool repair_pressure) {
  const quicly_flexicast_cc_config_t config = {
      .maximum_members = 64,
      .startup_rate_bytes_per_second = MODEL_CAPACITY_HIGH,
      .minimum_rate_bytes_per_second = 2000,
      .maximum_rate_bytes_per_second = 1000000,
      .maximum_datagram_size = 1200,
      .feedback_timeout_msec = 1000,
  };
  quicly_flexicast_cc_t *controller = NULL;
  int ret = quicly_flexicast_cc_create(
      &controller, &quicly_flexicast_cc_type_adaptive, &config, 0);
  assert(ret == 0);
  for (size_t member = 1; member <= members; ++member)
    quicly_flexicast_cc_on_member_added(controller, member, 0);

  const double step_seconds = MODEL_STEP_MSEC / 1000.0;
  double queued_bytes = 0;
  for (int step = 1; step <= MODEL_STEPS; ++step) {
    int64_t now = step * MODEL_STEP_MSEC;
    double capacity =
        now > 5000 && now <= 30000 ? MODEL_CAPACITY_LOW : MODEL_CAPACITY_HIGH;
    quicly_flexicast_cc_hints_t hints = {0};
    if (heterogeneous) {
      hints.active_senders = 2;
      hints.median_sender_rate_bytes_per_second = 200000;
    }
    if (repair_pressure) {
      hints.external_load_epoch = (uint64_t)now / 1000 + 1;
      hints.external_load_queued_bytes = now > 5000 && now <= 15000 ? 4800 : 0;
    }
    quicly_flexicast_cc_set_hints(controller, &hints, now);

    uint64_t offered_rate = model_rate(controller);
    double incoming_bytes = offered_rate * step_seconds;
    double available_bytes = queued_bytes + incoming_bytes;
    double served_bytes = fmin(capacity * step_seconds, available_bytes);
    double buffer_bytes = capacity; /* one second at current capacity */
    queued_bytes = available_bytes - served_bytes;
    double dropped_bytes = fmax(0, queued_bytes - buffer_bytes);
    queued_bytes = fmin(queued_bytes, buffer_bytes);
    double delivered_bytes = served_bytes * (1 - radio_loss);
    double rtt = MODEL_BASE_RTT_MSEC + 1000 * queued_bytes / capacity;
    double network_loss =
        incoming_bytes != 0 ? fmin(1, dropped_bytes / incoming_bytes) : 0;
    double loss = network_loss + (1 - network_loss) * radio_loss;

    for (size_t member = 1; member <= members; ++member) {
      quicly_flexicast_feedback_t feedback = {
          .member_id = member,
          .epoch = (uint64_t)step,
          .acked_packets = (uint64_t)(1000 * (1 - loss)),
          .lost_packets = (uint64_t)(1000 * loss),
          .delivery_rate_bytes_per_second =
              (uint64_t)(delivered_bytes / step_seconds),
          .minimum_rtt_msec = MODEL_BASE_RTT_MSEC,
          .latest_rtt_msec = (uint32_t)rtt,
          .now = now,
      };
      if (heterogeneous && member > 1) {
        /* This receiver has no bottleneck; it must not undo the
         * slower receiver's congestion response. */
        feedback.acked_packets = 1000;
        feedback.lost_packets = 0;
        feedback.delivery_rate_bytes_per_second = offered_rate;
        feedback.latest_rtt_msec = MODEL_BASE_RTT_MSEC;
      }
      quicly_flexicast_cc_on_feedback(controller, &feedback);
    }
    printf("%s,%" PRId64 ",%.0f,%" PRIu64 ",%" PRIu64 ",%.3f,%.3f,%.3f,%.3f\n",
           name, now, capacity, offered_rate, model_rate(controller),
           delivered_bytes / step_seconds, rtt, dropped_bytes, incoming_bytes);
  }
  quicly_flexicast_cc_free(controller);
}

int main(void) {
  puts("scenario,time_ms,capacity_Bps,offered_Bps,next_rate_Bps,goodput_Bps,"
       "rtt_ms,dropped_B,offered_B");
  run_scenario("single", 1, 0, false, false);
  run_scenario("group32", 32, 0, false, false);
  run_scenario("radio20", 1, 0.2, false, false);
  run_scenario("heterogeneous", 2, 0, true, false);
  run_scenario("repair", 1, 0, false, true);
  return 0;
}
