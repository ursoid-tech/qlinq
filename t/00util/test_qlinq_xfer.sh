#!/bin/sh
set -eu

# Python handles ephemeral ports, bounded waits, and child cleanup so a failing
# transfer cannot leave a listener running or hang the rest of make check.
exec python3 - "${QLINQ_APP_BIN:-./qlinq-app}" <<'PY'
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

app = os.path.abspath(sys.argv[1])
children = []
logs = []
case = "setup"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def launch(name, args):
    path = root / (name + ".log")
    with path.open("wb") as log:
        proc = subprocess.Popen(
            [app, "--transfer", "--auth-token", "xfer-test",
             "--insecure-no-verify", "--idle-timeout-ms", "60000"] + args,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
    children.append(proc)
    logs.append(path)
    return proc


def pair(name, source, destination, reverse=False, extra=None, shared=None, endpoint=None):
    endpoint = port() if endpoint is None else endpoint
    listener = ["--listen", str(endpoint), "--bind", "127.0.0.1",
                "--cert", "t/assets/server.crt", "--key", "t/assets/server.key"]
    connector = ["--peer", "127.0.0.1:" + str(endpoint)]
    listener += shared or []
    connector += shared or []
    sender = ["--input", str(source)] + (extra or [])
    receiver = ["--output", str(destination)]
    if reverse:
        send = launch(name + "-send", listener + sender)
        recv = launch(name + "-recv", connector + receiver)
    else:
        recv = launch(name + "-recv", listener + receiver)
        send = launch(name + "-send", connector + sender)
    return send, recv


def wait_pair(processes, success=True):
    deadline = time.monotonic() + 30
    codes = [proc.wait(timeout=max(0.1, deadline - time.monotonic()))
             for proc in processes]
    if success:
        require(codes == [0, 0], "expected both peers to succeed: " + str(codes))
    else:
        require(all(code != 0 for code in codes),
                "failure must not report success at either peer: " + str(codes))


def wait_partial(processes, destination):
    part = Path(str(destination) + ".qlinq-part")
    deadline = time.monotonic() + 15
    while True:
        require(all(proc.poll() is None for proc in processes),
                "peer exited before transfer interruption")
        # Checkpoints occur every MiB. Leave ample room before EOF, then
        # verify the next sender's negotiated resume offset below.
        if part.exists() and part.stat().st_size >= 2 * 1024 * 1024:
            return
        require(time.monotonic() < deadline, "no partial file before timeout")
        time.sleep(0.01)


def verify(source, destination):
    require(source.read_bytes() == destination.read_bytes(), "file contents differ")
    require(not Path(str(destination) + ".qlinq-part").exists(),
            "completed transfer left its staging file")
    require(not Path(str(destination) + ".qlinq-meta").exists(),
            "completed transfer left its resume metadata")


with tempfile.TemporaryDirectory(prefix="qlinq-xfer-test.") as tmp:
    root = Path(tmp)
    try:
        # Larger than the application credit window: catches stalls when only
        # the initial window works and durable acknowledgments do not advance it.
        large = root / "large.bin"
        with large.open("wb") as stream:
            block = bytes(range(256)) * 128
            for index in range(12 * 1024 * 1024 // len(block)):
                stream.write(index.to_bytes(8, "big") + block[8:])
            stream.write(b"tail")
        small = root / "small.bin"
        small.write_bytes(b"qlinq transfer\x00\xff\n" * 151)
        empty = root / "empty.bin"
        empty.touch()

        case = "large file"
        output = root / "large.out"
        wait_pair(pair("large", large, output))
        verify(large, output)

        case = "empty file"
        output = root / "empty.out"
        wait_pair(pair("empty", empty, output))
        verify(empty, output)

        case = "listener sends, connector receives"
        output = root / "reverse.out"
        wait_pair(pair("reverse", small, output, reverse=True,
                       extra=["--mode", "reliable"]))
        verify(small, output)

        case = "completed retry"
        before = output.stat()
        wait_pair(pair("retry", small, output))
        verify(small, output)
        after = output.stat()
        require((before.st_ino, before.st_mtime_ns) ==
                (after.st_ino, after.st_mtime_ns),
                "identical completed destination should be recognized in place")

        case = "restart resumes a durable prefix"
        output = root / "resume.out"
        processes = pair("interrupt", large, output,
                         extra=["--interval-ms", "5"])
        wait_partial(processes, output)
        require(not output.exists(), "destination became visible before commit")
        for proc in processes:
            proc.kill()
        for proc in processes:
            require(proc.wait(timeout=3) != 0, "interrupted peer reported success")
        require(not output.exists(), "interrupted transfer published its destination")
        require(Path(str(output) + ".qlinq-meta").exists(), "missing resume state")
        wait_pair(pair("resume", large, output))
        verify(large, output)
        offsets = re.findall(r"transfer resume offset=(\d+)",
                             (root / "resume-send.log").read_text())
        require(any(0 < int(value) < large.stat().st_size for value in offsets),
                "restart did not negotiate a nonzero partial resume offset")

        case = "live sender reconnects after receiver restart"
        output = root / "reconnect.out"
        endpoint = port()
        shared = ["--idle-timeout-ms", "1000", "--transfer-timeout-ms", "10000"]
        send, recv = pair("reconnect", large, output,
                          extra=["--interval-ms", "5"], shared=shared,
                          endpoint=endpoint)
        wait_partial((send, recv), output)
        recv.kill()
        require(recv.wait(timeout=3) != 0, "killed receiver reported success")
        require(not output.exists(), "restarting receiver published incomplete data")
        resumed = launch("reconnected-recv", [
            "--listen", str(endpoint), "--bind", "127.0.0.1",
            "--cert", "t/assets/server.crt", "--key", "t/assets/server.key",
            "--output", str(output)] + shared)
        wait_pair((send, resumed))
        verify(large, output)
        offsets = re.findall(r"transfer resume offset=(\d+)",
                             (root / "reconnect-send.log").read_text())
        require(any(0 < int(value) < large.stat().st_size for value in offsets),
                "running sender did not resume after reconnect")

        case = "existing destination is preserved on conflict"
        output = root / "conflict.out"
        original = b"existing destination must survive\n"
        output.write_bytes(original)
        wait_pair(pair("conflict", small, output,
                       shared=["--transfer-timeout-ms", "3000"]), success=False)
        require(output.read_bytes() == original, "conflicting destination was modified")
        require("remote: destination already exists with different contents" in
                (root / "conflict-send.log").read_text(),
                "sender did not receive the destination conflict diagnostic")

        case = "wrong authentication token cannot publish a destination"
        output = root / "unauthenticated.out"
        wait_pair(pair("wrong-token", small, output,
                       extra=["--auth-token", "wrong-token"],
                       shared=["--transfer-timeout-ms", "3000"]), success=False)
        require(not output.exists(), "unauthenticated sender published a destination")
        require(not Path(str(output) + ".qlinq-part").exists(),
                "unauthenticated sender created a staging file")

        case = "invalid transfer options"
        options = [
            ["--input", "-"],
            ["--output", "-"],
            ["--input", str(small), "--output", str(root / "both.out")],
            ["--input", str(small), "--mode", "rateless"],
            ["--input", str(small), "--count", "1"],
            ["--output", str(root / "count.out"), "--receive-count", "1"],
            ["--input", str(small), "--message-size", "1024"],
            ["--input", str(small), "--max-connections", "2"],
        ]
        for index, args in enumerate(options):
            proc = launch("invalid-" + str(index),
                          ["--peer", "127.0.0.1:" + str(port())] + args)
            require(proc.wait(timeout=3) != 0, "invalid options were accepted: " + str(args))

        case = "termination before completion reports failure"
        proc = launch("terminated", ["--peer", "127.0.0.1:" + str(port()),
                                     "--input", str(small)])
        time.sleep(0.1)
        proc.terminate()
        require(proc.wait(timeout=3) != 0, "incomplete transfer reported success on SIGTERM")
    except BaseException:
        print("qlinq transfer test failed: " + case, file=sys.stderr)
        for path in logs:
            print("--- " + path.name + " ---", file=sys.stderr)
            print(path.read_text(errors="replace")[-12000:], file=sys.stderr)
        raise
    finally:
        for proc in children:
            if proc.poll() is None:
                proc.kill()
        for proc in children:
            proc.wait(timeout=3)

print("===QLINQ APP TRANSFER OK===")
PY
