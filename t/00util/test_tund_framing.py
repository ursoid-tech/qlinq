#!/usr/bin/env python3
"""Exercise tund's local framing without a TUN device or QUIC connection."""

import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid


LENGTH = struct.Struct("!I")
TIMEOUT = 3
TRACK = b"framing-test"


def read_exact(peer, size):
    data = bytearray()
    deadline = time.monotonic() + TIMEOUT
    while len(data) < size:
        remaining = deadline - time.monotonic()
        assert remaining > 0, "tund did not complete a frame"
        peer.settimeout(remaining)
        chunk = peer.recv(size - len(data))
        if not chunk:
            raise AssertionError("tund disconnected before completing a frame")
        data.extend(chunk)
    return bytes(data)


def accept_peer(listener):
    peer, _ = listener.accept()
    peer.settimeout(TIMEOUT)
    try:
        assert read_exact(peer, 3) == bytes((4, 2, len(TRACK)))
        assert read_exact(peer, len(TRACK)) == TRACK
    except BaseException:
        peer.close()
        raise
    return peer


def frame(payload, priority):
    return LENGTH.pack(len(payload)) + bytes((priority,)) + payload


def wait_for_log(process, log_path, marker):
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        assert process.poll() is None, "tund exited unexpectedly"
        output = log_path.read_text()
        if marker in output:
            return output
        time.sleep(0.01)
    raise AssertionError(f"tund did not log {marker!r}")


def expect_disconnect(peer):
    deadline = time.monotonic() + TIMEOUT
    while True:
        remaining = deadline - time.monotonic()
        assert remaining > 0, "oversized length did not disconnect tund"
        peer.settimeout(remaining)
        try:
            if not peer.recv(4096):
                return
        except ConnectionResetError:
            return


def stop_process(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def main():
    binary = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "./qlinq-tund")
    name = "qlinq-tund-framing-" + uuid.uuid4().hex[:16]
    socket_path = pathlib.Path("/tmp") / (name + ".sock")
    with tempfile.TemporaryDirectory(prefix="qlinq-tund-framing-") as directory:
        log_path = pathlib.Path(directory) / "tund.log"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.settimeout(TIMEOUT)
            listener.bind(str(socket_path))
            try:
                listener.listen(2)
                with log_path.open("wb") as log:
                    process = subprocess.Popen(
                        [str(binary.resolve()), "--mock", "--socket", name,
                         "--track", TRACK.decode(), "--priority", "high"],
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )
                    try:
                        with accept_peer(listener) as peer:
                            # All short frames are consumed, without reading
                            # sequence bytes beyond their payloads.
                            marker = "starting with 0x45 seq=4660 size=6 priority=2"
                            packets = b"".join(frame(b"x" * size, 0)
                                               for size in range(6))
                            packets += frame(b"\x45\x00\x00\x06\x34\x12", 2)
                            peer.sendall(packets)
                            output = wait_for_log(process, log_path, marker)
                            assert output.count("MOCK: received packet") == 1

                            # No priority or body follows this impossible size.
                            peer.sendall(LENGTH.pack(2049))
                            expect_disconnect(peer)

                        with accept_peer(listener) as peer:
                            length_bytes = read_exact(peer, LENGTH.size)
                            assert length_bytes == b"\x00\x00\x00\x40"
                            size = LENGTH.unpack(length_bytes)[0]
                            priority = read_exact(peer, 1)[0]
                            assert size == 64 and priority == 2
                            payload = read_exact(peer, size)
                            assert payload[:4] == b"\x45\x00\x00\x40"
                            sequence = payload[4] | (payload[5] << 8)
                            peer.sendall(frame(payload, priority))
                            marker = f"seq={sequence} size=64 priority=2"
                            output = wait_for_log(process, log_path, marker)
                            assert output.count("MOCK: received packet") == 2
                    except BaseException:
                        print(log_path.read_text(), file=sys.stderr)
                        raise
                    finally:
                        stop_process(process)
            finally:
                socket_path.unlink(missing_ok=True)
    print("===TUND FRAMING OK===")


if __name__ == "__main__":
    main()
