#include "../../src/emcon/emcon_receive_socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "EMCON receive socket test failed: %s\n", message);      \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static uint16_t free_port(void) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in address = {.sin_family = AF_INET,
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  socklen_t size = sizeof(address);
  if (fd < 0 || bind(fd, (struct sockaddr *)&address, size) != 0 ||
      getsockname(fd, (struct sockaddr *)&address, &size) != 0) {
    if (fd >= 0)
      close(fd);
    return 0;
  }
  close(fd);
  return address.sin_port;
}

static bool cancel_immediately(void *user_data) {
  bool *cancelled = user_data;
  return *cancelled;
}

int main(void) {
  int sender = socket(AF_INET, SOCK_DGRAM, 0);
  CHECK(sender >= 0, "sender socket");
  struct sockaddr_in sender_address = {
      .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  socklen_t sender_address_len = sizeof(sender_address);
  CHECK(bind(sender, (struct sockaddr *)&sender_address, sender_address_len) ==
                0 &&
            getsockname(sender, (struct sockaddr *)&sender_address,
                        &sender_address_len) == 0,
        "sender bind");

  struct sockaddr_in multicast_address = {.sin_family = AF_INET,
                                          .sin_port = htons(15001)};
  inet_pton(AF_INET, "239.0.0.1", &multicast_address.sin_addr);
  qlinq_emcon_receive_socket_t *receiver = NULL;
  CHECK(qlinq_emcon_receive_socket_create_multicast(
            &receiver, (struct sockaddr *)&multicast_address,
            sizeof(multicast_address), (struct sockaddr *)&sender_address,
            sizeof(sender_address), 0, false) == QLINQ_EMCON_SOCKET_INVALID,
        "preprovisioned multicast requires an interface");

  struct sockaddr_in receiver_address = {.sin_family = AF_INET,
                                         .sin_port = free_port(),
                                         .sin_addr.s_addr =
                                             htonl(INADDR_LOOPBACK)};
  CHECK(receiver_address.sin_port != 0 &&
            qlinq_emcon_receive_socket_create_multicast(
                &receiver, (struct sockaddr *)&receiver_address,
                sizeof(receiver_address), (struct sockaddr *)&sender_address,
                sizeof(sender_address), UINT32_MAX,
                true) == QLINQ_EMCON_SOCKET_SYSTEM,
        "unicast receive honors an explicit interface index");
  CHECK(qlinq_emcon_receive_socket_create_multicast(
            &receiver, (struct sockaddr *)&receiver_address,
            sizeof(receiver_address), (struct sockaddr *)&sender_address,
            sizeof(sender_address), 0, true) == QLINQ_EMCON_SOCKET_OK,
        "create UDP receive socket");

  const uint8_t payload[] = "protected symbol";
  CHECK(sendto(sender, payload, sizeof(payload), 0,
               (struct sockaddr *)&receiver_address,
               sizeof(receiver_address)) == (ssize_t)sizeof(payload),
        "send from provisioned source");
  uint8_t packet[64];
  size_t packet_size = 0;
  CHECK(qlinq_emcon_receive_socket_receive(receiver, packet, sizeof(packet),
                                           &packet_size, false, UINT64_MAX) ==
                QLINQ_EMCON_SOCKET_OK &&
            packet_size == sizeof(payload) &&
            memcmp(packet, payload, sizeof(payload)) == 0,
        "receive datagram");
  CHECK(qlinq_emcon_receive_socket_receive(receiver, packet, sizeof(packet),
                                           &packet_size, true, UINT64_MAX) ==
            QLINQ_EMCON_SOCKET_WOULD_BLOCK,
        "no receiver feedback datagram");
  CHECK(recv(sender, packet, sizeof(packet), MSG_DONTWAIT) < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK),
        "sender observes no feedback");

  bool cancelled = true;
  qlinq_emcon_receive_socket_set_cancel(receiver, cancel_immediately,
                                        &cancelled);
  CHECK(qlinq_emcon_receive_socket_receive(receiver, packet, sizeof(packet),
                                           &packet_size, false, UINT64_MAX) ==
            QLINQ_EMCON_SOCKET_INTERRUPTED,
        "blocking receive wakes on cancellation");
  cancelled = false;

  CHECK(sendto(sender, payload, sizeof(payload), 0,
               (struct sockaddr *)&receiver_address,
               sizeof(receiver_address)) == (ssize_t)sizeof(payload),
        "queue a datagram at expiry");
  packet_size = 0;
  CHECK(qlinq_emcon_receive_socket_receive(
            receiver, packet, sizeof(packet), &packet_size, false,
            qlinq_emcon_realtime_ms()) == QLINQ_EMCON_SOCKET_EXPIRED &&
            packet_size == 0,
        "never accept queued data after expiry");

  qlinq_emcon_receive_socket_free(receiver);
  close(sender);
  puts("===EMCON RECEIVE SOCKET OK===");
  return 0;
}
