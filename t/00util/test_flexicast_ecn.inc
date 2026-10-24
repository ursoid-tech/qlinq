/* Included by the transport regression fixture. Use actual UDP ancillary
 * data and authenticated PATH_ACK feedback, including replay suppression. */
#include "transport_paths.h"

static void test_ecn(fixture_t *fixture, bool native) {
#ifdef __linux__
  transport_t *source = fixture->source.transport;
  transport_t *receiver = fixture->clients[0].transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  transport_flexicast_member_t *member = &flow->members[0];
  uint8_t body[32] = {42}, ciphertext[256], received[256];
  size_t size;
  uint64_t packet_number;
  CHECK(quicly_flexicast_send_datagram_at(
            flow->crypto, ptls_iovec_init(body, sizeof(body)), ciphertext,
            sizeof(ciphertext), &size, &packet_number,
            transport_get_time_ms()) == QUICLY_FLEXICAST_OK);
  struct sockaddr_storage local_addrs[TRANSPORT_MAX_PATHS];
  for (size_t i = 0; i < source->socket_count; i++)
    local_addrs[i] = source->sockets[i].local_addr;
  struct sockaddr_storage destination;
  size_t fd_index = transport_path_socket_for_peer(
      member->conn->quic, local_addrs, source->socket_count, &destination);
  CHECK(fd_index != SIZE_MAX);
  struct sockaddr_storage source_address = {0};
  struct sockaddr *from = NULL;
  if (native) {
    destination = source->flexicast_group_addr;
    struct sockaddr_in *v4 = (struct sockaddr_in *)&source_address;
    v4->sin_family = AF_INET;
    v4->sin_addr = source->flexicast_interface_v4;
    from = (struct sockaddr *)&source_address;
    fd_index = transport_path_socket_for_source(local_addrs,
                                                source->socket_count, from);
    CHECK(fd_index != SIZE_MAX);
  }
  struct iovec vector = {.iov_base = ciphertext, .iov_len = size};
  for (unsigned replay = 0; replay < 2; replay++) {
    CHECK(transport_udp_send_ecn(
              source->sockets[fd_index].fd, (struct sockaddr *)&destination,
              from, source->flexicast_interface_index, &vector, 3) == 1);
    if (replay == 0)
      CHECK(quicly_flexicast_mark_submitted(
                flow->crypto, native ? 0 : member->conn->id, packet_number,
                transport_get_time_ms()) == QUICLY_FLEXICAST_OK);
    transport_conn_t *owner = NULL;
    ptls_iovec_t payload = {0};
    if (native) {
      CHECK(transport_flexicast_receive_native(receiver, 0, received,
                                               sizeof(received), &owner,
                                               &payload) == (ssize_t)size);
    } else {
      struct sockaddr_storage peer;
      socklen_t peer_length = sizeof(peer);
      uint8_t ecn;
      CHECK(transport_udp_receive_ecn(receiver->sockets[0].fd, received,
                                      sizeof(received), &peer, &peer_length,
                                      &ecn) == (ssize_t)size);
      CHECK(ecn == 3);
      CHECK(transport_flexicast_receive_unicast_ecn(receiver, received, size,
                                                    (struct sockaddr *)&peer,
                                                    &owner, &payload, ecn));
    }
    if (replay == 0)
      CHECK(owner && payload.len == sizeof(body) &&
            !memcmp(payload.base, body, sizeof(body)));
    else
      CHECK(!payload.base);
    pump(fixture, 40);
    quicly_flexicast_member_stats_t stats;
    CHECK(quicly_flexicast_get_member_stats(flow->crypto, member->conn->id,
                                            &stats) == QUICLY_FLEXICAST_OK);
    CHECK(stats.ecn_ce_count == 1);
  }
#else
  (void)fixture;
  (void)native;
#endif
}
