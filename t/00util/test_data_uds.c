#include "data_uds.h"
#include "portable_sockets.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
  int calls;
  uint8_t payload[64];
  size_t size;
  uint8_t priority;
} test_state_t;

static void on_packet(void *user_data, const moq_track_id_t *track_id,
                      const uint8_t *buf, size_t size, uint8_t priority) {
  test_state_t *state = user_data;
  if (track_id->type != MOQ_TRACK_DATA ||
      strcmp(track_id->name, "partial") != 0 || size > sizeof(state->payload))
    return;
  memcpy(state->payload, buf, size);
  state->size = size;
  state->priority = priority;
  state->calls++;
}

static int write_bytewise(int fd, data_uds_t *uds, const uint8_t *buf,
                          size_t size) {
  for (size_t i = 0; i < size; i++) {
    if (write(fd, buf + i, 1) != 1)
      return -1;
    data_uds_tick(uds);
  }
  return 0;
}

static int read_exact(int fd, void *buf, size_t size) {
  size_t done = 0;
  while (done < size) {
    ssize_t ret = read(fd, (uint8_t *)buf + done, size - done);
    if (ret < 0 && errno == EINTR)
      continue;
    if (ret <= 0)
      return -1;
    done += (size_t)ret;
  }
  return 0;
}

typedef struct {
  bool ready, retry;
  unsigned calls, accepted[2], ready_calls;
  uint64_t first_id;
} retry_state_t;

static bool ready(void *arg, const moq_track_id_t *track) {
  (void)track;
  retry_state_t *state = arg;
  state->ready_calls++;
  return state->ready;
}

static data_uds_result_t retry_packet(void *arg, data_uds_record_t *record) {
  retry_state_t *state = arg;
  assert(record->size == 1 && record->data[0] == 42);
  if (state->calls++ == 0)
    state->first_id = record->id;
  if (state->retry || record->progress)
    assert(record->id == state->first_id);
  if (!(record->progress & 1)) {
    state->accepted[0]++;
    record->progress |= 1;
  }
  if (state->retry)
    return DATA_UDS_RETRY;
  state->accepted[1]++;
  state->ready = false; /* The next complete frame must stay unread. */
  return DATA_UDS_ACCEPTED;
}

static void retry_and_ownership(void) {
  const char *name = "qlinq-data-uds-retry-test";
  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/%s.sock", name);
  retry_state_t state = {.ready = true, .retry = true};
  data_uds_t *uds = data_uds_create_ex(name, retry_packet, ready, &state);
  assert(uds);
  assert(data_uds_create_ex(name, retry_packet, ready, &state) == NULL);
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  assert(fd >= 0 && connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
  data_uds_tick(uds);
  struct pollfd fds[2];
  assert(data_uds_get_poll_fds(uds, fds, 2) == 2);
  assert(fds[1].events == POLLIN && state.ready_calls == 0);
  uint8_t registration[] = {MOQ_TRACK_DATA, MOQ_TRACK_FLAG_RELIABLE, 1, 'r'};
  assert(write(fd, registration, sizeof(registration)) == sizeof(registration));
  uint8_t frames[12] = {0};
  uint32_t size = 1;
  memcpy(frames, &size, 4);
  frames[5] = 42;
  memcpy(frames + 6, frames, 6);
  assert(write(fd, frames, sizeof(frames)) == sizeof(frames));
  data_uds_tick(uds);
  assert(state.accepted[0] == 1 && state.accepted[1] == 0);
  unsigned ready_calls = state.ready_calls;
  assert(data_uds_get_poll_fds(uds, fds, 2) == 1);
  assert(state.ready_calls ==
         ready_calls); /* Pending records suppress POLLIN. */
  data_uds_tick(uds);  /* Retry without another socket write. */
  assert(state.calls == 2 && state.accepted[0] == 1);
  assert(state.ready_calls == ready_calls + 1);
  state.retry = false;
  data_uds_tick(uds);
  assert(state.accepted[0] == 1 && state.accepted[1] == 1);
  data_uds_tick(uds);
  assert(state.calls == 3); /* Readiness is checked between records. */
  assert(data_uds_get_poll_fds(uds, fds, 2) == 1);

  /* Output remains pollable while input is paused for backpressure. */
  int send_buffer = 1024;
  assert(setsockopt(fds[1].fd, SOL_SOCKET, SO_SNDBUF, &send_buffer,
                    sizeof(send_buffer)) == 0);
  uint8_t output[65536] = {0};
  moq_track_id_t track = {.type = MOQ_TRACK_DATA, .name = "r"};
  assert(data_uds_send(uds, &track, output, sizeof(output), 1));
  assert(data_uds_get_poll_fds(uds, fds, 2) == 2 && fds[1].events == POLLOUT);
  uint8_t chunk[4096];
  size_t remaining = sizeof(output) + 5;
  while (remaining != 0) {
    ssize_t count =
        read(fd, chunk, remaining < sizeof(chunk) ? remaining : sizeof(chunk));
    assert(count > 0);
    remaining -= (size_t)count;
    data_uds_tick(uds);
    assert(state.calls == 3);
  }
  assert(data_uds_get_poll_fds(uds, fds, 2) == 1);
  state.ready = true;
  assert(data_uds_get_poll_fds(uds, fds, 2) == 2 && fds[1].events == POLLIN);
  data_uds_tick(uds);
  assert(state.accepted[0] == 2 && state.accepted[1] == 2);
  close(fd);

  /* A replaced pathname belongs to its new inode, even before old teardown. */
  assert(unlink(addr.sun_path) == 0);
  int replacement = socket(AF_UNIX, SOCK_STREAM, 0);
  assert(replacement >= 0 &&
         bind(replacement, (struct sockaddr *)&addr, sizeof(addr)) == 0);
  struct stat before, after;
  assert(lstat(addr.sun_path, &before) == 0);
  data_uds_destroy(uds);
  assert(lstat(addr.sun_path, &after) == 0 && before.st_ino == after.st_ino);
  close(
      replacement); /* Leave a stale socket for the next instance to recover. */
  uds = data_uds_create_ex(name, retry_packet, ready, &state);
  assert(uds);
  data_uds_destroy(uds);
  assert(lstat(addr.sun_path, &after) != 0 && errno == ENOENT);
}

/* Exact names outrank earlier DATA fallbacks; duplicate names retain the first
 * registration. Accepting on descriptor zero exercises client lifetime state.
 */
static void routing_and_zero_descriptor(void) {
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    test_state_t state = {0};
    data_uds_t *uds =
        data_uds_create("qlinq-data-uds-routing-test", on_packet, NULL, &state);
    assert(uds);
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strcpy(addr.sun_path, "/tmp/qlinq-data-uds-routing-test.sock");
    const uint8_t types[] = {MOQ_TRACK_DATA, MOQ_TRACK_DATA, MOQ_TRACK_DATA,
                             MOQ_TRACK_VIDEO};
    const char names[] = {'a', 'b', 'b', 'v'};
    int clients[4];
    for (size_t i = 0; i < 4; i++) {
      clients[i] = socket(AF_UNIX, SOCK_STREAM, 0);
      assert(clients[i] >= 0);
      assert(connect(clients[i], (struct sockaddr *)&addr, sizeof(addr)) == 0);
      if (i == 0)
        close(STDIN_FILENO);
      data_uds_tick(uds);
      uint8_t registration[] = {types[i], 0, 1, (uint8_t)names[i]};
      assert(write_bytewise(clients[i], uds, registration,
                            sizeof(registration)) == 0);
    }
    struct pollfd fds[5];
    assert(data_uds_get_poll_fds(uds, fds, 5) == 5 && fds[1].fd == 0);
    assert(data_uds_get_poll_fds(uds, fds, 1) == 1);
    assert(data_uds_get_poll_fds(uds, fds, 0) == 0);
    const struct {
      uint8_t type;
      char name;
      int destination;
    } cases[] = {{MOQ_TRACK_DATA, 'b', 1},
                 {MOQ_TRACK_DATA, 'x', 0},
                 {MOQ_TRACK_VIDEO, 'v', 3},
                 {MOQ_TRACK_VIDEO, 'x', -1},
                 {MOQ_TRACK_INPUT, 'a', -1}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      moq_track_id_t track = {.type = cases[i].type,
                              .name = {cases[i].name, '\0'}};
      assert(data_uds_send(uds, &track, (const uint8_t *)"z", 1, 2) ==
             (cases[i].destination >= 0));
      for (int j = 0; j < 4; j++) {
        struct pollfd incoming = {.fd = clients[j], .events = POLLIN};
        assert(poll(&incoming, 1, 0) == (j == cases[i].destination));
      }
      if (cases[i].destination >= 0) {
        uint8_t frame[6];
        uint32_t size;
        assert(read_exact(clients[cases[i].destination], frame,
                          sizeof(frame)) == 0);
        memcpy(&size, frame, sizeof(size));
        assert(size == 1 && frame[4] == 2 && frame[5] == 'z');
      }
    }
    data_uds_destroy(uds);
    assert(fcntl(STDIN_FILENO, F_GETFD) == -1 && errno == EBADF);
    for (size_t i = 0; i < 4; i++)
      close(clients[i]);
    _exit(0);
  }
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void broken_pipe(void) {
  int pair[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
  close(pair[1]);
  pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    signal(SIGPIPE, SIG_DFL);
    ssize_t sent = socket_write(pair[0], "x", 1);
    _exit(sent == -1 && errno == EPIPE ? 0 : 1);
  }
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  close(pair[0]);
}

int main(void) {
  retry_and_ownership();
  routing_and_zero_descriptor();
  broken_pipe();
  if (data_uds_create("../invalid", on_packet, NULL, NULL) != NULL) {
    fprintf(stderr, "unsafe socket name was accepted\n");
    return 1;
  }

  test_state_t state = {0};
  data_uds_t *uds =
      data_uds_create("qlinq-data-uds-test", on_packet, NULL, &state);
  if (!uds)
    return 1;

  const char *socket_path = "/tmp/qlinq-data-uds-test.sock";
  struct stat st;
  if (stat(socket_path, &st) != 0 || (st.st_mode & 0777) != 0600) {
    fprintf(stderr, "UDS permissions are not private\n");
    data_uds_destroy(uds);
    return 1;
  }

  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
  if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    data_uds_destroy(uds);
    return 1;
  }
  data_uds_tick(uds);

  const char *name = "partial";
  uint8_t registration[3 + 7] = {MOQ_TRACK_DATA, MOQ_TRACK_FLAG_FEC_ENABLED, 7};
  memcpy(registration + 3, name, 7);
  if (write_bytewise(fd, uds, registration, sizeof(registration)) != 0) {
    close(fd);
    data_uds_destroy(uds);
    return 1;
  }

  const uint8_t payload[] = "framed-payload";
  uint32_t payload_size = sizeof(payload);
  uint8_t frame[5 + sizeof(payload)];
  memcpy(frame, &payload_size, 4);
  frame[4] = 2;
  memcpy(frame + 5, payload, sizeof(payload));
  if (write_bytewise(fd, uds, frame, sizeof(frame)) != 0 || state.calls != 1 ||
      state.size != sizeof(payload) || state.priority != 2 ||
      memcmp(state.payload, payload, sizeof(payload)) != 0) {
    fprintf(stderr, "partial input framing failed\n");
    close(fd);
    data_uds_destroy(uds);
    return 1;
  }

  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                          .name = "partial"};
  const uint8_t reply[] = "queued-reply";
  if (!data_uds_send(uds, &track, reply, sizeof(reply), 1)) {
    close(fd);
    data_uds_destroy(uds);
    return 1;
  }
  uint32_t reply_size;
  uint8_t reply_priority;
  uint8_t reply_buf[sizeof(reply)];
  if (read_exact(fd, &reply_size, sizeof(reply_size)) != 0 ||
      read_exact(fd, &reply_priority, sizeof(reply_priority)) != 0 ||
      reply_size != sizeof(reply) || reply_priority != 1 ||
      read_exact(fd, reply_buf, sizeof(reply_buf)) != 0 ||
      memcmp(reply_buf, reply, sizeof(reply)) != 0) {
    fprintf(stderr, "queued output framing failed\n");
    close(fd);
    data_uds_destroy(uds);
    return 1;
  }

  close(fd);
  data_uds_destroy(uds);
  printf("===DATA UDS OK===\n");
  return 0;
}
