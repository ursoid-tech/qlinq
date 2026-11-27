#include "emcon_receive_socket.h"

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

  struct sockaddr_in receiver_address = {
      .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  qlinq_emcon_receive_socket_t *receiver = NULL;
  CHECK(qlinq_emcon_receive_socket_create(
            &receiver, (struct sockaddr *)&receiver_address,
            sizeof(receiver_address), (struct sockaddr *)&sender_address,
            sizeof(sender_address)) == QLINQ_EMCON_SOCKET_OK,
        "create UDP receive socket");
  sender_address_len = sizeof(receiver_address);
  CHECK(qlinq_emcon_receive_socket_local_address(
            receiver, (struct sockaddr *)&receiver_address,
            &sender_address_len) == QLINQ_EMCON_SOCKET_OK,
        "receiver local address");

  const uint8_t payload[] = "protected symbol";
  CHECK(sendto(sender, payload, sizeof(payload), 0,
               (struct sockaddr *)&receiver_address,
               sizeof(receiver_address)) == (ssize_t)sizeof(payload),
        "send from provisioned source");
  uint8_t packet[64];
  size_t packet_size = 0;
  CHECK(qlinq_emcon_receive_socket_receive(receiver, packet, sizeof(packet),
                                           &packet_size,
                                           false) == QLINQ_EMCON_SOCKET_OK &&
            packet_size == sizeof(payload) &&
            memcmp(packet, payload, sizeof(payload)) == 0,
        "receive datagram");
  CHECK(qlinq_emcon_receive_socket_receive(receiver, packet, sizeof(packet),
                                           &packet_size, true) ==
            QLINQ_EMCON_SOCKET_WOULD_BLOCK,
        "no receiver feedback datagram");
  CHECK(recv(sender, packet, sizeof(packet), MSG_DONTWAIT) < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK),
        "sender observes no feedback");

  qlinq_emcon_receive_socket_free(receiver);
  close(sender);
  puts("===EMCON RECEIVE SOCKET OK===");
  return 0;
}
