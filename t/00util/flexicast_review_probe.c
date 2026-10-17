/* Reproducible loopback probes; build with scripts/flexicast_review_probe.py.
 */
#include "transport_internal.h"

#include <stdbool.h>
#include <string.h>

static bool probe_fixed_rate;

static transport_t *probe_transport_create(const transport_config_t *config) {
  transport_config_t adjusted = *config;
  adjusted.port = probe_fixed_rate ? 19871 : 19861;
  if (probe_fixed_rate && adjusted.cert_file != NULL) {
    adjusted.flexicast_cc_startup_rate = 50000000;
    adjusted.flexicast_cc_minimum_rate = 50000000;
    adjusted.flexicast_cc_maximum_rate = 50000000;
  }
  return transport_create(&adjusted);
}

/* Reuse authentication, subscription and delivery checks from the fixture in
 * the tree being measured. The build helper resolves this include explicitly
 * so the same probe can also be compiled against the pre-fix tree. */
#define transport_create probe_transport_create
#define main fixture_regressions_main
#include "test_flexicast_regressions.c"
#undef main
#undef transport_create

int main(int argc, char **argv) {
  if (argc != 2 ||
      (strcmp(argv[1], "rate") != 0 && strcmp(argv[1], "natural") != 0)) {
    fprintf(stderr, "usage: %s rate|natural\n", argv[0]);
    return 2;
  }
  probe_fixed_rate = strcmp(argv[1], "rate") == 0;
  fixture_t fixture;
  create_fixture(&fixture, probe_fixed_rate ? 1 : 2, true, "pacing");
  transport_t *source = fixture.source.transport;
  transport_flexicast_flow_t *flow = fixture.flow;
  uint8_t bytes[1024] = {42};
  moq_object_t object = object_for(&fixture, bytes, sizeof(bytes));
  if (probe_fixed_rate) {
    int64_t start = transport_get_time_ms();
    uint64_t before = source->stats.flexicast_physical_bytes_sent;
    while (transport_get_time_ms() < start + 300) {
      for (size_t i = 0; i < 16; i++)
        if (transport_publish_ex(source, &object) ==
            TRANSPORT_PUBLISH_DELIVERED)
          object.object_id++;
      transport_tick(source);
      transport_tick(fixture.clients[0].transport);
    }
    int64_t elapsed = transport_get_time_ms() - start;
    uint64_t sent = source->stats.flexicast_physical_bytes_sent - before;
    quicly_flexicast_cc_output_t cc;
    quicly_flexicast_cc_get_flow_output(flow->crypto, &cc);
    printf("{\"probe\":\"rate\",\"elapsed_ms\":%" PRId64
           ",\"configured_Bps\":%" PRIu64 ",\"controller_Bps\":%" PRIu64
           ",\"pacer_Bps\":%" PRIu64 ",\"burst_bytes\":%" PRIu64
           ",\"sent_bytes\":%" PRIu64 ",\"physical_Bps\":%" PRIu64
           ",\"queued_packets\":%zu}\n",
           elapsed, flow->cc_config.startup_rate_bytes_per_second,
           cc.rate_bytes_per_second, flow->pacing_rate_bytes_per_second,
           flow->pacing_burst_bytes, sent,
           elapsed > 0 ? sent * 1000 / elapsed : 0, flow->data_queue.count);
  } else {
    for (size_t round = 0; round < 12; round++) {
      object.object_id = round;
      CHECK(transport_publish_ex(source, &object) ==
            TRANSPORT_PUBLISH_DELIVERED);
      check_delivery(&fixture, round + 1, 2);
      pump(&fixture, 30);
      quicly_flexicast_cc_output_t cc;
      quicly_flexicast_cc_get_flow_output(flow->crypto, &cc);
      printf("{\"probe\":\"natural\",\"round\":%zu,\"controller_Bps\":%" PRIu64
             ",\"members\":[",
             round, cc.rate_bytes_per_second);
      for (size_t i = 0; i < flow->member_count; i++) {
        quicly_flexicast_member_stats_t stats;
        CHECK(quicly_flexicast_get_member_stats(flow->crypto,
                                                flow->members[i].conn->id,
                                                &stats) == QUICLY_FLEXICAST_OK);
        printf("%s{\"minimum_rtt_ms\":%u,\"latest_rtt_ms\":%u,\"delivery_Bps\":"
               "%" PRIu64 "}",
               i ? "," : "", stats.minimum_rtt_msec, stats.latest_rtt_msec,
               stats.delivery_rate_bytes_per_second);
      }
      puts("]}");
      fflush(stdout);
    }
  }
  destroy_fixture(&fixture);
  return 0;
}
