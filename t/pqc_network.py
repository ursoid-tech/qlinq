"""Bounded deterministic UDP impairment proxy; no privileged host changes.

This is a correctness fixture, not a latency or throughput benchmark. Datagram
contents are opaque and unmodified. Only the public QUIC long-header type is
inspected to select handshake-flight faults.
"""
import heapq
import select
import socket
import threading
import time


class FaultProxy:
    def __init__(self, server_port, blackhole=False):
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind(("127.0.0.1", 0))
        self.back.bind(("127.0.0.1", 0))
        self.port = self.front.getsockname()[1]
        self.server = ("127.0.0.1", server_port)
        self.blackhole = blackhole
        self.stop = threading.Event()
        self.counts = {"c2s": 0, "s2c": 0, "dropped_initial_c2s": 0,
                       "dropped_initial_s2c": 0, "delayed": 0, "payload_delayed": 0, "reordered": 0, "duplicated": 0,
                       "handshake_datagrams": 0, "blackholed": 0, "max_udp": 0}
        self.error = None
        self.thread = threading.Thread(target=self.run)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop.set()
        self.thread.join(timeout=2)
        self.front.close()
        self.back.close()
        if self.thread.is_alive():
            raise AssertionError("proxy did not stop")
        if self.error:
            raise self.error

    def run(self):
        try:
            client = None
            queue = []
            serial = 0
            last_forwarded = {"c2s": 0, "s2c": 0}
            while not self.stop.is_set():
                ready, _, _ = select.select([self.front, self.back], [], [], 0.002)
                for sock in ready:
                    data, address = sock.recvfrom(65536)
                    direction = "c2s" if sock is self.front else "s2c"
                    self.counts[direction] += 1
                    self.counts["max_udp"] = max(self.counts["max_udp"], len(data))
                    if direction == "c2s":
                        client = address
                        outgoing, destination = self.back, self.server
                    else:
                        outgoing, destination = self.front, client
                    if self.blackhole and direction == "s2c":
                        self.counts["blackholed"] += 1
                        continue
                    # QUIC v1: Initial=0 and Handshake=2. No TLS decryption.
                    initial = data[0] & 128 and (data[0] >> 4) & 3 == 0
                    handshake = data[0] & 128 and (data[0] >> 4) & 3 == 2
                    if handshake:
                        self.counts["handshake_datagrams"] += 1
                    key = "dropped_initial_" + direction
                    if initial and not self.counts[key]:
                        self.counts[key] += 1
                        continue
                    delay = 0.003
                    if handshake and not self.counts["delayed"]:
                        delay = 0.06
                        self.counts["delayed"] += 1
                    # Full-size 1-RTT payload packets provide a deterministic
                    # reorder opportunity even for a small classical handshake.
                    if (direction == "c2s" and not data[0] & 128 and len(data) == 1200
                            and not self.counts["payload_delayed"]):
                        delay = 0.06
                        self.counts["payload_delayed"] += 1
                    serial += 1
                    heapq.heappush(queue, (time.monotonic() + delay, serial, direction, outgoing, destination, data))
                    if handshake and not self.counts["duplicated"]:
                        self.counts["duplicated"] += 1
                        serial += 1
                        heapq.heappush(queue, (time.monotonic() + 0.08, serial, direction, outgoing, destination, data))
                while queue and queue[0][0] <= time.monotonic():
                    _, sequence, direction, outgoing, destination, data = heapq.heappop(queue)
                    if sequence < last_forwarded[direction]:
                        self.counts["reordered"] += 1
                    last_forwarded[direction] = max(last_forwarded[direction], sequence)
                    if destination:
                        outgoing.sendto(data, destination)
        except BaseException as error:
            self.error = error
