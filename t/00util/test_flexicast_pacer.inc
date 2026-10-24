/* Deterministic accounting checks supplement the live socket scenarios. */
/* Delayed service and empty supply must not be confused with normal pacing. */
static void test_supply_context(fixture_t *fixture) {
  transport_t *source = fixture->source.transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  transport_flexicast_queued_payload_t packet = {0};
  uint64_t aggregate = source->flexicast_cc_aggregate_rate_limit;
  source->flexicast_cc_aggregate_rate_limit = 0;
  flow->pacing_rate_numerator = 1000000;
  flow->pacing_rate_divisor = 1;
  flow->pacing_tokens = flow->pacing_remainder = 0;
  flow->pacing_burst_bytes = 4000;
  flow->pacing_last_refill_ms = 1000;
  flow->cc_supply_empty_since_ms = 1000;
  tf_sample_supply_at(source, flow, &packet, 1000, 1001);
  CHECK(packet.cc_sample_flags == 0); /* credit only just became available */
  flow->cc_supply_empty_since_ms = 1000;
  tf_sample_supply_at(source, flow, &packet, 1000, 1002);
  CHECK(packet.cc_sample_flags == QUICLY_FLEXICAST_SAMPLE_APP_LIMITED);
  CHECK(flow->pacing_tokens == 0 && flow->pacing_last_refill_ms == 1000);

  packet.cc_sample_flags = 0;
  flow->pacing_rate_numerator = 1000;
  flow->cc_supply_empty_since_ms = 1000;
  tf_sample_supply_at(source, flow, &packet, 1000, 1100);
  CHECK(packet.cc_sample_flags ==
        0);                   /* waiting for pacing is not app limitation */
  flow->pacing_tokens = 1000; /* the service deadline must still be eligible */
  flow->cc_supply_ready_at_ms = 1100;
  tf_sample_supply_at(source, flow, &packet, 1000, 1102);
  CHECK(packet.cc_sample_flags == 0);
  flow->cc_supply_ready_at_ms = 1100;
  tf_sample_supply_at(source, flow, &packet, 1000, 1103);
  CHECK(packet.cc_sample_flags == QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED);

  packet.cc_sample_flags = 0;
  source->flexicast_cc_aggregate_rate_limit = 1000;
  source->flexicast.pacing_tokens = source->flexicast.pacing_remainder = 0;
  source->flexicast.pacing_rate = 1000;
  source->flexicast.pacing_burst = 4000;
  source->flexicast.pacing_last_refill_ms = 1000;
  flow->pacing_rate_numerator = 1000000;
  flow->cc_supply_empty_since_ms = 1000;
  tf_sample_supply_at(source, flow, &packet, 1000, 1100);
  CHECK(packet.cc_sample_flags == 0); /* shared-budget pacing also counts */
  flow->cc_supply_ready_at_ms = 1100;
  flow->cc_supply_credit_epoch = source->flexicast.pacing_credit_epoch;
  tf_sample_supply_at(source, flow, &packet, 1000, 1103);
  CHECK(packet.cc_sample_flags == 0); /* another flow consumed shared credit */

  source->flexicast.pacing_tokens = 1000;
  source->flexicast.pacing_credit_epoch++;
  flow->cc_supply_ready_at_ms = 1100;
  tf_sample_supply_at(source, flow, &packet, 1000, 1103);
  CHECK(packet.cc_sample_flags ==
        0); /* stale eligibility even after credit returns */
  flow->cc_supply_credit_epoch = source->flexicast.pacing_credit_epoch;
  flow->cc_supply_ready_at_ms = 1100;
  tf_sample_supply_at(source, flow, &packet, 1000, 1103);
  CHECK(packet.cc_sample_flags == QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED);

  packet.cc_sample_flags = 0;
  source->flexicast_cc_aggregate_rate_limit = 0;
  flow->pacing_tokens = 4000;
  flow->pacing_last_refill_ms = 1103;
  flow->cc_supply_empty_since_ms = 1000;
  tf_sample_supply_at(source, flow, &packet, 1000, 1103);
  CHECK(packet.cc_sample_flags ==
        0); /* cannot project a future balance backwards */

  flow->cc_supply_ready_at_ms = 1100;
  flow->pacing_rate_numerator = 1; /* force a rate/share change on refresh */
  tf_refresh_pacer_at(source, flow, transport_get_time_ms());
  CHECK(flow->cc_supply_ready_at_ms == 0 &&
        flow->cc_supply_empty_since_ms == 0);
  int64_t published_at = transport_get_time_ms();
  flow->cc_supply_empty_since_ms = published_at - 20;
  flow->cc_supply_idle_ready_at_ms = published_at - 10;
  flow->cc_supply_credit_epoch = source->flexicast.pacing_credit_epoch;
  /* The application's readiness query settles credit at the publication
   * time, but must not erase an already proven empty-queue opportunity. */
  tf_refresh_pacer_at(source, flow, published_at);
  tf_sample_supply_at(source, flow, &packet, 1000, published_at);
  CHECK(packet.cc_sample_flags == QUICLY_FLEXICAST_SAMPLE_APP_LIMITED);
  source->flexicast_cc_aggregate_rate_limit = aggregate;
}

static void test_continuation_context(fixture_t *fixture) {
  transport_t *source = fixture->source.transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  CHECK(flow->listening_count >= 2);
  transport_egress_t *egress = &source->sockets[0].egress;
  CHECK(egress->count == 0);
  transport_egress_packet_t *blocked = &egress->packets[egress->head];
  blocked->data = malloc(1);
  CHECK(blocked->data);
  blocked->size = 1;
  egress->count = egress->bytes = 1;
  /* Reprotected continuation: one still-listening member already received
   * this plaintext before the key change, so it is not another physical copy.
   */
  flow->members[0].payload_delivery_id = flow->next_payload_delivery_id + 1;
  uint8_t bytes[32] = {42};
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  CHECK(transport_publish_ex(source, &object) == TRANSPORT_PUBLISH_DELIVERED);
  CHECK(flow->data_queue.count == 1);
  transport_flexicast_queued_payload_t *queued =
      &flow->data_queue.entries[flow->data_queue.head];
  CHECK(queued->packet != NULL);
  CHECK(queued->cc_packet_fanout == flow->listening_count - 1);
  CHECK(queued->cc_packet_membership_epoch == flow->cc_membership_epoch);
  free(blocked->data);
  memset(blocked, 0, sizeof(*blocked));
  egress->count = egress->bytes = 0;
  flow->dispatch_retry_at_ms = 0;
  tf_drain_paced_payloads(source, flow);
  CHECK(flow->data_queue.count == 0);
}

static void test_high_rate_pacer(fixture_t *fixture) {
  transport_t *source = fixture->source.transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  int64_t now = transport_get_time_ms();
  tf_refresh_pacer_at(source, flow, now);
  uint64_t rate = flow->cc_config.startup_rate_bytes_per_second;
  CHECK(flow->pacing_rate_bytes_per_second == rate);
  CHECK(flow->pacing_burst_bytes >= rate / 1000U);
  flow->pacing_tokens = 0;
  flow->pacing_remainder = 0;
  tf_refresh_pacer_at(source, flow, now + 1);
  CHECK(flow->pacing_tokens == rate / 1000U);
  /* Queries in the same clock interval must not manufacture more credit. */
  uint64_t tokens = flow->pacing_tokens;
  tf_refresh_pacer_at(source, flow, now + 1);
  CHECK(flow->pacing_tokens == tokens);
  test_supply_context(fixture);
  if (fixture->count >= 2)
    test_continuation_context(fixture);
}

static void test_aggregate_pacer(fixture_t *fixture) {
  transport_t *source = fixture->source.transport;
  transport_flexicast_flow_t *flows[2] = {0};
  size_t count = 0;
  for (size_t i = 0; i < source->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &source->flexicast.flows[i];
    if (flow->active && flow->source && flow->listening_count != 0 &&
        transport_track_id_equal(&flow->track_id, &fixture->track)) {
      CHECK(count < 2);
      flows[count++] = flow;
      /* Keep both independent alias cohorts active during the virtual clock. */
      flow->last_payload_sent_ms = INT64_MAX;
    }
  }
  CHECK(count == 2);
  int64_t now = transport_get_time_ms();
  source->flexicast_cc_aggregate_rate_limit = 100;
  for (size_t i = 0; i < count; i++) {
    tf_refresh_pacer_at(source, flows[i], now);
    flows[i]->pacing_tokens = 0;
    flows[i]->pacing_remainder = 0;
    CHECK(flows[i]->pacing_rate_bytes_per_second == 50);
  }
  source->flexicast.pacing_tokens = 0;
  source->flexicast.pacing_remainder = 0;
  for (size_t i = 0; i < count; i++) {
    tf_refresh_pacer_at(source, flows[i], now + 1000);
    CHECK(flows[i]->pacing_tokens == 50);
  }
  CHECK(source->flexicast.pacing_tokens == 100);

  /* Raising the cap cannot credit the previous interval at its new rate. */
  source->flexicast_cc_aggregate_rate_limit = 10000;
  for (size_t i = 0; i < count; i++) {
    flows[i]->pacing_tokens = 0;
    tf_refresh_pacer_at(source, flows[i], now + 2000);
    CHECK(flows[i]->pacing_tokens == 50);
  }
  CHECK(source->flexicast.pacing_tokens == 200);

  /* A one-byte budget split across two cohorts is 1/2 B/s each, not zero
   * (unlimited) and not the controller's positive minimum rate. */
  source->flexicast_cc_aggregate_rate_limit = 1;
  for (size_t i = 0; i < count; i++) {
    tf_refresh_pacer_at(source, flows[i], now + 2000);
    flows[i]->pacing_tokens = 0;
    flows[i]->pacing_remainder = 0;
    CHECK(flows[i]->pacing_rate_numerator == 1);
    CHECK(flows[i]->pacing_rate_divisor == 2);
  }
  source->flexicast.pacing_tokens = 0;
  source->flexicast.pacing_remainder = 0;
  for (size_t i = 0; i < count; i++) {
    tf_refresh_pacer_at(source, flows[i], now + 3000);
    CHECK(flows[i]->pacing_tokens == 0);
    tf_refresh_pacer_at(source, flows[i], now + 4000);
    CHECK(flows[i]->pacing_tokens == 1);
  }
  CHECK(source->flexicast.pacing_tokens == 2);

  uint8_t bytes[32] = {42};
  size_t cost = quicly_flexicast_datagram_size(
      flows[0]->crypto, QLINQ_WIRE_FEC_HEADER_SIZE + sizeof(bytes));
  int64_t ready_at = now + 2000 + (int64_t)(cost * 2000U);
  for (size_t i = 0; i < count; i++) {
    tf_refresh_pacer_at(source, flows[i], ready_at);
    CHECK(flows[i]->pacing_tokens == cost);
  }
  CHECK(source->flexicast.pacing_tokens == cost * 2U);
  uint64_t sent = source->stats.flexicast_physical_packets_sent;
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  CHECK(transport_publish_ex(source, &object) == TRANSPORT_PUBLISH_DELIVERED);
  CHECK(source->stats.flexicast_physical_packets_sent == sent + 2);
  CHECK(source->flexicast.pacing_tokens == 0);
  CHECK(flows[0]->pacing_tokens == 0 && flows[1]->pacing_tokens == 0);
}

static void test_submitted_rtt(fixture_t *fixture) {
  transport_t *source = fixture->source.transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  CHECK(fixture->count == 2);
  uint8_t bytes[32] = {42};
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  size_t cost = quicly_flexicast_datagram_size(
      flow->crypto, QLINQ_WIRE_FEC_HEADER_SIZE + sizeof(bytes));
  flow->pacing_tokens = cost;
  flow->pacing_last_refill_ms = INT64_MAX;
  CHECK(transport_publish_ex(source, &object) == TRANSPORT_PUBLISH_DELIVERED);
  CHECK(flow->data_queue.count == 1);
  pump(fixture, 250);
  flow->pacing_tokens = cost;
  int64_t submitted_at = transport_get_time_ms();
  tf_drain_paced_payloads(source, flow);
  CHECK(flow->data_queue.count == 0);
  check_delivery(fixture, 1, fixture->count);
  pump(fixture, 30);
  quicly_flexicast_member_stats_t stats;
  CHECK(quicly_flexicast_get_member_stats(flow->crypto,
                                          flow->members[1].conn->id,
                                          &stats) == QUICLY_FLEXICAST_OK);
  CHECK(stats.delivered_packets == 1);
  /* Scheduler noise is allowed, but time spent waiting for local credit must
   * be absent: the RTT cannot predate the successful UDP submission. */
  CHECK(stats.latest_rtt_msec <=
        (uint64_t)(transport_get_time_ms() - submitted_at));
}

static void test_native_fallback_pacing(fixture_t *fixture) {
  transport_t *source = fixture->source.transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  CHECK(flow->native_multicast && fixture->count == 2);
  struct sockaddr_in *group =
      (struct sockaddr_in *)&source->flexicast_group_addr;
  uint16_t port = group->sin_port;
  uint8_t bytes[32] = {42};
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  CHECK(quicly_flexicast_cc_enable_flow_trace(flow->crypto, 2048) == 0);
  bool saw_native = false, saw_replicated = false;
  for (size_t round = 0; round < 4; round++) {
    /* Port zero fails only the native send; the established unicast sockets
     * and the receiver's authenticated multicast announcement remain valid. */
    group->sin_port = round < 2 ? 0 : port;
    object.object_id = round;
    uint64_t physical = source->stats.flexicast_physical_packets_sent;
    CHECK(transport_publish_ex(source, &object) == TRANSPORT_PUBLISH_DELIVERED);
    check_delivery(fixture, round + 1, fixture->count);
    CHECK(source->stats.flexicast_physical_packets_sent - physical ==
          (round < 2 ? fixture->count : 1));
    CHECK(flow->last_submission_replicated == (round < 2));
    CHECK(flow->native_multicast);
    pump(fixture, 35);
    quicly_flexicast_cc_trace_event_t events[16];
    size_t count;
    while ((count = quicly_flexicast_cc_read_flow_trace(flow->crypto, events,
                                                        16, NULL)) != 0) {
      for (size_t i = 0; i < count; ++i) {
        const quicly_flexicast_feedback_t *feedback = &events[i].feedback;
        if (events[i].type != QUICLY_FLEXICAST_CC_TRACE_FEEDBACK ||
            feedback->delivery_rate_sample_epoch == 0)
          continue;
        saw_native |= feedback->delivery_sample_fanout == 1;
        saw_replicated |= feedback->delivery_sample_fanout == fixture->count;
      }
    }
  }
  CHECK(saw_native && saw_replicated);
  quicly_flexicast_cc_disable_flow_trace(flow->crypto);
}
