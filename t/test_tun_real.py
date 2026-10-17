#!/usr/bin/env python3
"""Real TUN acceptance. Requires root; all networking is namespace-isolated."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "qlinq-tun"


def run(*args, prefix=(), **kwargs):
    result = subprocess.run([*prefix, *map(str, args)], text=True,
                            capture_output=True, timeout=25, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{' '.join(map(str, args))}: {result.stdout}\n{result.stderr}")
    return result.stdout


def main():
    if os.geteuid() != 0:
        raise RuntimeError("run as root; this test creates isolated network namespaces")
    if "--isolated" not in sys.argv:
        os.execvp("unshare", ["unshare", "--net", sys.executable, __file__, "--isolated"])
    run("ip", "link", "set", "lo", "up")
    peer = subprocess.Popen(["unshare", "--net", "sleep", "300"])
    processes = []
    try:
        for _ in range(100):
            if os.readlink(f"/proc/{peer.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                break
            time.sleep(0.02)
        ns = ["nsenter", "-t", str(peer.pid), "-n"]
        run("ip", "link", "add", "veth_a", "type", "veth", "peer", "name", "veth_b")
        run("ip", "link", "set", "veth_b", "netns", peer.pid)
        run("ip", "addr", "add", "172.30.77.1/24", "dev", "veth_a")
        run("ip", "link", "set", "veth_a", "up")
        run("ip", "link", "set", "lo", "up", prefix=ns)
        run("ip", "addr", "add", "172.30.77.2/24", "dev", "veth_b", prefix=ns)
        run("ip", "link", "set", "veth_b", "up", prefix=ns)
        with tempfile.TemporaryDirectory(prefix="qr-") as temporary:
            directory = Path(temporary)

            def cli(*args, client=False):
                return run(CLI, "--config-dir", directory, *args, prefix=ns if client else ())

            def wait_connected(name, client=False):
                for _ in range(100):
                    status = json.loads(cli("status", name, "--json", client=client))
                    if status["state"] == "connected":
                        return status
                    time.sleep(0.1)
                raise RuntimeError(f"{name}: no authenticated connection: {status}")

            def wait_traffic(label):
                # A remaining path may still be recovering from the earlier
                # blackhole. Allow its backed-off PTO probes (or idle timeout
                # and reconnect) to restore traffic within a bounded window.
                started = time.monotonic()
                for _ in range(20):
                    probe = subprocess.run([*ns, "ping", "-c", "1", "-W", "1",
                                            "10.88.0.1"], capture_output=True,
                                           text=True, timeout=2)
                    if probe.returncode == 0:
                        print(f"{label} recovered in {time.monotonic() - started:.2f}s")
                        return
                    time.sleep(0.2)
                raise AssertionError(f"traffic did not recover after {label}: "
                                     f"{probe.stdout}\n{probe.stderr}")

            cli("init", "server", "--listen", "172.30.77.1:19888", "--uplink", "veth_a",
                "--interface", "qt_a", "--run-as", "nobody")
            cli("init", "client", "--invite", directory / "server/invite.json",
                "--uplink", "veth_b", "--uplink", "veth_c",
                "--interface", "qt_b", "--run-as", "nobody",
                "--route", "10.99.0.0/24", client=True)
            cli("pair", "server", directory / "client/peer.json")
            try:
                cli("up", "server")
                cli("up", "client", client=True)
                wait_connected("server")
                wait_connected("client", True)
                run("ping", "-c", "3", "-W", "2", "10.88.0.1", prefix=ns)
                # Full MTU packet: IPv4 + ICMP headers consume 28 bytes.
                run("ping", "-c", "2", "-W", "2", "-M", "do", "-s", "1372",
                    "10.88.0.1", prefix=ns)
                run("ip", "addr", "add", "10.99.0.1/32", "dev", "lo")
                run("ping", "-c", "2", "-W", "2", "10.99.0.1", prefix=ns)
                payload = os.urandom(256 * 1024)
                (directory / "payload.bin").write_bytes(payload)
                http = subprocess.Popen([sys.executable, "-m", "http.server", "18088",
                                         "--bind", "10.88.0.1", "--directory", temporary],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                processes.append(http)
                time.sleep(0.2)
                code = ("import urllib.request,hashlib; "
                        "print(hashlib.sha256(urllib.request.urlopen("
                        "'http://10.88.0.1:18088/payload.bin',timeout=15).read()).hexdigest())")
                actual = run(sys.executable, "-c", code, prefix=ns).strip()
                assert actual == hashlib.sha256(payload).hexdigest(), "TCP payload corrupted"
                # UDP echo verifies record boundaries with ordinary application sockets.
                udp_code = ("import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                            "s.bind(('10.88.0.1',18089)); "
                            "exec('while True:\\n d,a=s.recvfrom(2048); s.sendto(d,a)')")
                udp = subprocess.Popen([sys.executable, "-c", udp_code])
                processes.append(udp)
                time.sleep(0.1)
                probe = ("import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                         "s.settimeout(3); "
                         "exec('for i in range(30):\\n d=bytes([i])*512; "
                         "s.sendto(d,(\"10.88.0.1\",18089)); assert s.recv(2048)==d')")
                run(sys.executable, "-c", probe, prefix=ns)
                cli("down", "server")
                cli("up", "server")
                wait_connected("server")
                wait_connected("client", True)
                run("ping", "-c", "2", "-W", "2", "10.88.0.1", prefix=ns)
                # Hot-add an independent routed uplink to the same endpoint.
                # Source-policy routing represents what carrier managers set
                # up on real gateways. All sysctls are namespace-local.
                run("ip", "link", "add", "veth_d", "type", "veth", "peer", "name", "veth_c")
                run("ip", "link", "set", "veth_c", "netns", peer.pid)
                run("ip", "addr", "add", "172.31.77.1/24", "dev", "veth_d")
                run("ip", "link", "set", "veth_d", "up")
                run("ip", "addr", "add", "172.31.77.2/24", "dev", "veth_c", prefix=ns)
                run("ip", "link", "set", "veth_c", "up", prefix=ns)
                run("ip", "rule", "add", "from", "172.31.77.2", "table", "200", prefix=ns)
                run("ip", "route", "add", "172.31.77.0/24", "dev", "veth_c", "table", "200", prefix=ns)
                run("ip", "route", "add", "172.30.77.1/32", "via", "172.31.77.1",
                    "dev", "veth_c", "table", "200", prefix=ns)
                run("sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0", prefix=ns)
                run("sysctl", "-qw", "net.ipv4.conf.veth_c.rp_filter=0", prefix=ns)
                for _ in range(100):
                    paths = json.loads(cli("status", "client", "--json", client=True))["paths"]
                    if sum(p["active"] for p in paths) >= 2:
                        break
                    time.sleep(0.1)
                assert sum(p["active"] for p in paths) == 2, f"second path did not validate: {paths}"
                run("tc", "qdisc", "add", "dev", "veth_b", "root", "netem", "loss", "100%", prefix=ns)
                try:
                    run("ping", "-c", "8", "-W", "2", "10.88.0.1", prefix=ns)
                    paths = json.loads(cli("status", "client", "--json", client=True))["paths"]
                    assert any(p["interface"] == "veth_c" and p["tx_bytes"] > 0 and
                               p["rx_bytes"] > 0 for p in paths), paths
                finally:
                    run("tc", "qdisc", "del", "dev", "veth_b", "root", prefix=ns)
                run("ip", "link", "del", "veth_d")
                wait_traffic("Secondary uplink removal")
                # Uplink outage and return must recover without restarting the app.
                run("ip", "link", "set", "veth_b", "down", prefix=ns)
                time.sleep(1)
                run("ip", "link", "set", "veth_b", "up", prefix=ns)
                # A total-path outage may require the 10-second QUIC idle
                # timeout followed by reconnect. Verify traffic, not a stale
                # authenticated-state snapshot from the old connection.
                wait_traffic("Total uplink outage")
            finally:
                for name, is_client in (("server", False), ("client", True)):
                    try:
                        cli("down", name, client=is_client)
                    except Exception:
                        pass
                for name in ("server", "client"):
                    log = directory / name / "run/tunnel.log"
                    if log.exists() and sys.exc_info()[0]:
                        print(log.read_text()[-8000:], file=sys.stderr)
            assert "qt_a" not in {r["ifname"] for r in json.loads(run("ip", "-j", "link"))}
            assert "qt_b" not in {r["ifname"] for r in json.loads(run("ip", "-j", "link", prefix=ns))}
            assert not any(r.get("dst") == "10.99.0.0/24" for r in
                           json.loads(run("ip", "-j", "route", prefix=ns)))
            print("REAL TUN OK: mTLS, ping/MTU, subnet route, TCP integrity, UDP, restart, multipath hot-add/failover/removal, uplink recovery, cleanup")
    finally:
        for process in processes:
            process.terminate()
            process.wait(timeout=5)
        peer.terminate()
        peer.wait(timeout=5)


if __name__ == "__main__":
    main()
