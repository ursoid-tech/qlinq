#!/usr/bin/env python3
"""Authenticated, bounded process tests for the PQC MVP CLI/profile surface."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import tempfile
import time
import unittest

from pqc_network import FaultProxy

ROOT = Path(__file__).resolve().parent.parent
POLICIES = ("classical", "prefer-hybrid", "require-hybrid")
IDENTITY = ["--cert", "t/assets/verified.crt", "--key", "t/assets/verified.key",
            "--ca", "t/assets/verified.crt"]


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class PqcCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run([str(ROOT / "t/00util/test_tls_groups")], cwd=ROOT,
                                capture_output=True, text=True, timeout=8)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        cls.hybrid = "hybrid=available reason=available" in result.stdout
        if os.getenv("QLINQ_TEST_REQUIRE_HYBRID") and not cls.hybrid:
            raise AssertionError("required hybrid coverage is unavailable")
        print(f"CLI capability: hybrid={cls.hybrid}", flush=True)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pqc-cli-")
        self.path = Path(self.tmp.name)
        self.children = []
        self.profiles = []
        self.serial = 0

    def tearDown(self):
        for profile in self.profiles:
            self.manage("down", profile, expected=None)
        for proc, _ in reversed(self.children):
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        self.tmp.cleanup()

    def launch(self, executable, arguments, label):
        self.serial += 1
        path = self.path / f"{self.serial}-{label}.log"
        with path.open("wb") as log:
            proc = subprocess.Popen([str(ROOT / executable), *arguments], cwd=ROOT,
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        self.children.append((proc, path))
        return proc, path

    def wait_for(self, condition, message, timeout=12):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = condition()
            if value:
                return value
            time.sleep(0.025)
        logs = "\n".join(path.read_text(errors="replace")[-4000:]
                         for _, path in self.children)
        self.fail(message + "\n" + logs)

    def logged(self, path, text):
        return text in path.read_text(errors="replace")

    def stop(self, proc):
        if proc.poll() is None:
            proc.terminate()
        self.assertEqual(proc.wait(timeout=5), 0)

    def manage(self, *arguments, expected=0):
        result = subprocess.run([str(ROOT / "qlinq-tun"), "--config-dir", str(self.path),
                                 *arguments], cwd=ROOT, capture_output=True, text=True, timeout=18)
        if expected is not None:
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def status(self, name):
        return json.loads(self.manage("status", name, "--json").stdout)

    def connected(self, name, group):
        def ready():
            value = self.status(name)
            if value["state"] != "connected" or not value.get("received"):
                return None
            self.assertEqual(value["tls"]["selected_group"], group)
            self.assertTrue(value["tls"]["complete"])
            self.assertTrue(value["tls"]["policy_accepted"])
            self.assertTrue(value["tls"]["verify_peer"])
            self.assertEqual(value["tls"]["handshake"], "full")
            return value
        return self.wait_for(ready, f"{name} did not authenticate", timeout=15)

    def test_strict_cli_parsing(self):
        for executable in ("qlinq-app", "qlinqd", "qlinq-tun"):
            for invalid in ("", "hybrid", "CLASSICAL", " prefer-hybrid", "require-hybrid "):
                result = subprocess.run([str(ROOT / executable), "--tls-group-policy", invalid,
                                         "--help"], cwd=ROOT, capture_output=True, timeout=4)
                self.assertNotEqual(result.returncode, 0, (executable, invalid))
            result = subprocess.run([str(ROOT / executable), "--tls-group-policy"],
                                    cwd=ROOT, capture_output=True, timeout=4)
            self.assertNotEqual(result.returncode, 0)
            for policy in POLICIES:
                result = subprocess.run([str(ROOT / executable), "--tls-group-policy", policy,
                                         "--help"], cwd=ROOT, capture_output=True, timeout=4)
                self.assertEqual(result.returncode, 0, (executable, policy, result.stderr))
                self.assertIn(b"--tls-group-policy", result.stdout)

    def test_verified_app_matrix_and_reload(self):
        source = self.path / "source.bin"
        payload = bytes(range(256)) * 257 + b"verified-pqc-tail\x00\xff"
        source.write_bytes(payload)
        for client_policy in POLICIES:
            for server_policy in POLICIES:
                with self.subTest(client=client_policy, server=server_policy):
                    destination = self.path / f"{client_policy}-{server_policy}.bin"
                    port = free_port()
                    common = ["--transfer", *IDENTITY, "--auth-token", "pqc-test", "--drain-ms", "50",
                              "--transfer-timeout-ms", "2000", "--verbose"]
                    server, server_log = self.launch("qlinq-app", [*common, "--listen", str(port),
                        "--bind", "127.0.0.1", "--tls-group-policy", server_policy,
                        "--output", str(destination)], "app-server")
                    expected_success = not ((client_policy == "classical" and server_policy == "require-hybrid") or
                                            (server_policy == "classical" and client_policy == "require-hybrid") or
                                            (not self.hybrid and "require-hybrid" in (client_policy, server_policy)))
                    if self.hybrid and client_policy == server_policy == "require-hybrid":
                        self.wait_for(lambda: self.logged(server_log, "tls-group-policy=require-hybrid"),
                                      "app did not initialize policy")
                        os.kill(server.pid, signal.SIGHUP)
                        self.wait_for(lambda: self.logged(server_log, "TLS credentials reloaded"),
                                      "app did not reload identity")
                    client, client_log = self.launch("qlinq-app", [*common, "--peer", f"127.0.0.1:{port}",
                        "--tls-group-policy", client_policy, "--input", str(source)], "app-client")
                    codes = [client.wait(timeout=10), server.wait(timeout=10)]
                    texts = [path.read_text(errors="replace") for path in (client_log, server_log)]
                    if expected_success:
                        self.assertEqual(codes, [0, 0], "\n".join(texts))
                        self.assertEqual(destination.read_bytes(), payload)
                        self.assertEqual(hashlib.sha256(destination.read_bytes()).digest(),
                                         hashlib.sha256(payload).digest())
                        group = 4588 if self.hybrid and "classical" not in (client_policy, server_policy) else 23
                        for text, policy in zip(texts, (client_policy, server_policy)):
                            self.assertRegex(text, rf"policy={policy} group={group} result=.*handshake=full verify_peer=1")
                        print(f"app client={client_policy} server={server_policy} group={group} sha256={hashlib.sha256(payload).hexdigest()}", flush=True)
                    else:
                        self.assertTrue(all(code != 0 for code in codes), (codes, texts))
                        self.assertFalse(destination.exists())
                        for text in texts:
                            self.assertNotIn("peer connected", text)
                            self.assertNotIn("transfer committed", text)
                        print(f"app client={client_policy} server={server_policy} rejected", flush=True)

    def test_verified_network_faults(self):
        cases = [("prefer-hybrid", "classical", False),
                 ("prefer-hybrid", "prefer-hybrid", False)]
        if self.hybrid:
            cases += [("require-hybrid", "require-hybrid", False),
                      ("require-hybrid", "classical", False),
                      ("require-hybrid", "require-hybrid", True)]
        payload = bytes(range(256)) * 257 + b"fault-test-tail"
        source = self.path / "fault-source.bin"
        source.write_bytes(payload)
        for cp, sp, blackhole in cases:
            with self.subTest(client=cp, server=sp, blackhole=blackhole):
                port = free_port()
                destination = self.path / f"fault-{cp}-{sp}-{blackhole}.bin"
                common = ["--transfer", *IDENTITY, "--auth-token", "pqc-test",
                          "--drain-ms", "100", "--transfer-timeout-ms", "4000",
                          "--udp-payload", "1200", "--verbose"]
                server, server_log = self.launch("qlinq-app", [*common,
                    "--listen", str(port), "--bind", "127.0.0.1",
                    "--tls-group-policy", sp, "--output", str(destination)], "fault-server")
                self.wait_for(lambda: self.logged(server_log, f"tls-group-policy={sp}"),
                              "fault listener did not start")
                with FaultProxy(port, blackhole) as proxy:
                    client, client_log = self.launch("qlinq-app", [*common,
                        "--peer", f"127.0.0.1:{proxy.port}", "--tls-group-policy", cp,
                        "--input", str(source)], "fault-client")
                    codes = [client.wait(timeout=12), server.wait(timeout=12)]
                texts = [p.read_text(errors="replace") for p in (client_log, server_log)]
                success = not blackhole and not (cp == "require-hybrid" and sp == "classical")
                self.assertLessEqual(proxy.counts["max_udp"], 1200)
                self.assertEqual(proxy.counts["dropped_initial_c2s"], 1)
                if success:
                    self.assertEqual(codes, [0, 0], "\n".join(texts))
                    self.assertEqual(destination.read_bytes(), payload)
                    self.assertEqual(proxy.counts["dropped_initial_s2c"], 1)
                    self.assertGreater(proxy.counts["handshake_datagrams"], 1)
                    self.assertEqual(proxy.counts["payload_delayed"], 1)
                    self.assertGreater(proxy.counts["reordered"], 0)
                    self.assertEqual(proxy.counts["duplicated"], 1)
                    group = 4588 if self.hybrid and sp != "classical" else 23
                    for text, policy in zip(texts, (cp, sp)):
                        self.assertRegex(text, rf"policy={policy} group={group} result=.*handshake=full verify_peer=1")
                else:
                    self.assertTrue(all(code != 0 for code in codes), (codes, texts))
                    self.assertFalse(destination.exists())
                    for text in texts:
                        self.assertNotIn("peer connected", text)
                        self.assertNotIn("transfer committed", text)
                        self.assertNotIn("group=23 result=classical", text)
                    if blackhole:
                        self.assertGreater(proxy.counts["blackholed"], 0)
                        self.assertIn("timed out", "\n".join(texts).lower())
                print(f"fault client={cp} server={sp} blackhole={blackhole} success={success} "
                      f"counts={proxy.counts} sha256={hashlib.sha256(payload).hexdigest() if success else 'none'}",
                      flush=True)

    def test_verified_app_authentication_rejections(self):
        if not self.hybrid:
            self.skipTest("required hybrid unavailable")
        source = self.path / "rejected-source.bin"
        source.write_bytes(b"must-never-be-delivered")
        for failure in ("client-certificate", "server-certificate", "application-token"):
            with self.subTest(failure=failure):
                port = free_port()
                output = self.path / (failure + ".bin")
                common = ["--transfer", *IDENTITY, "--tls-group-policy", "require-hybrid",
                          "--auth-token", "pqc-test", "--drain-ms", "50", "--transfer-timeout-ms", "1500"]
                server_extra, client_extra = [], []
                untrusted = ["--cert", "t/assets/untrusted.crt", "--key", "t/assets/untrusted.key"]
                if failure == "client-certificate":
                    client_extra = untrusted
                elif failure == "server-certificate":
                    server_extra = untrusted
                else:
                    client_extra = ["--auth-token", "wrong-token"]
                server, server_log = self.launch("qlinq-app", [*common, "--listen", str(port),
                    "--bind", "127.0.0.1", "--output", str(output), *server_extra], "reject-server")
                client, client_log = self.launch("qlinq-app", [*common, "--peer", f"127.0.0.1:{port}",
                    "--input", str(source), *client_extra], "reject-client")
                codes = [client.wait(timeout=8), server.wait(timeout=8)]
                texts = [log.read_text() for log in (server_log, client_log)]
                self.assertTrue(all(code != 0 for code in codes), texts)
                self.assertFalse(output.exists())
                self.assertTrue(all("transfer committed" not in text for text in texts))
                if failure == "application-token":
                    for text in texts:
                        self.assertIn("group=4588 result=hybrid handshake=full verify_peer=1", text)
                print(f"app authentication rejection: {failure}; no committed payload", flush=True)

    def test_profile_roundtrip_legacy_and_invalid(self):
        for number, policy in enumerate(POLICIES):
            name = f"server{number}"
            client = f"client{number}"
            self.manage("init", name, "--listen", f"127.0.0.1:{free_port()}", "--uplink", "lo",
                        "--tls-group-policy", policy)
            config = json.loads((self.path / name / "config.json").read_text())
            invite = json.loads((self.path / name / "invite.json").read_text())
            self.assertEqual(config["tls_group_policy"], policy)
            self.assertEqual(invite["config"]["tls_group_policy"], policy)
            self.manage("init", client, "--invite", str(self.path / name / "invite.json"), "--uplink", "lo")
            self.assertEqual(json.loads((self.path / client / "config.json").read_text())["tls_group_policy"], policy)
            diagnosis = json.loads(self.manage("diagnose", name).stdout)
            self.assertEqual(diagnosis["config"]["tls_group_policy"], policy)
            self.assertEqual(self.status(name)["tls_group_policy"], policy)
        for invalid in ("invalid", "", "CLASSICAL"):
            self.manage("init", "invalid", "--listen", "127.0.0.1", "--uplink", "lo",
                        "--tls-group-policy", invalid, expected=1)
            self.assertFalse((self.path / "invalid").exists())
        self.manage("init", "override", "--invite", str(self.path / "server2/invite.json"),
                    "--uplink", "lo", "--tls-group-policy", "classical")
        self.assertEqual(json.loads((self.path / "override/config.json").read_text())["tls_group_policy"], "classical")
        config_path = self.path / "server0/config.json"
        original = json.loads(config_path.read_text())
        for invalid in ("", "invalid", "CLASSICAL", " prefer-hybrid", 1, None, [], {}):
            config_path.write_text(json.dumps(dict(original, tls_group_policy=invalid)))
            self.manage("diag", "server0", "--mock", expected=1)
            self.manage("up", "server0", "--mock", expected=1)
        config_path.write_text(json.dumps(original))
        # Missing field in both former profiles and invitations means classical.
        legacy = dict(original)
        del legacy["tls_group_policy"]
        config_path.write_text(json.dumps(legacy))
        self.assertEqual(self.status("server0")["tls_group_policy"], "classical")
        invitation = json.loads((self.path / "server0/invite.json").read_text())
        del invitation["config"]["tls_group_policy"]
        legacy_invite = self.path / "legacy-invite.json"
        legacy_invite.write_text(json.dumps(invitation))
        self.manage("init", "legacy", "--invite", str(legacy_invite), "--uplink", "lo")
        self.assertEqual(json.loads((self.path / "legacy/config.json").read_text())["tls_group_policy"], "classical")
        self.manage("pair", "server0", str(self.path / "legacy/peer.json"))
        self.profiles.extend(("server0", "legacy"))
        self.manage("up", "server0", "--mock")
        self.manage("up", "legacy", "--mock")
        self.connected("server0", 23)
        self.connected("legacy", 23)
        print("profiles: all policies roundtrip; legacy omission classical; invalid stored values rejected", flush=True)

    def test_managed_hybrid_worker_restart(self):
        if not self.hybrid:
            self.skipTest("required hybrid unavailable; fallback/creation behavior covered by CLI matrix")
        self.manage("init", "server", "--listen", f"127.0.0.1:{free_port()}", "--uplink", "lo",
                    "--tls-group-policy", "require-hybrid")
        self.manage("init", "client", "--invite", str(self.path / "server/invite.json"), "--uplink", "lo")
        self.manage("pair", "server", str(self.path / "client/peer.json"))
        self.profiles.extend(("server", "client"))
        self.manage("up", "server", "--mock")
        self.manage("up", "client", "--mock")
        first = {name: self.connected(name, 4588) for name in self.profiles}
        for name in self.profiles:
            self.assertEqual(first[name]["tls_group_policy"], "require-hybrid")
        self.manage("down", "server")
        self.wait_for(lambda: self.status("client").get("tls") is None,
                      "client retained a previous connection's hybrid observation")
        self.assertEqual(self.status("server")["tls_group_policy"], "require-hybrid")
        self.manage("up", "server", "--mock")
        restarted = self.connected("server", 4588)
        self.connected("client", 4588)
        self.assertNotEqual(restarted["supervisor_pid"], first["server"]["supervisor_pid"])
        self.manage("down", "client")
        self.manage("up", "client", "--mock")
        self.connected("server", 4588)
        final = self.connected("client", 4588)
        self.assertNotEqual(final["supervisor_pid"], first["client"]["supervisor_pid"])
        self.assertEqual(final["tls_group_policy"], "require-hybrid")
        for name in self.profiles:
            self.assertEqual(json.loads((self.path / name / "config.json").read_text())["tls_group_policy"], "require-hybrid")
        print("managed restart: required policy preserved, pending status reset, verified full group=4588 on both workers", flush=True)

    def test_daemon_bidirectional_reload(self):
        policy = "require-hybrid" if self.hybrid else "prefer-hybrid"
        group = 4588 if self.hybrid else 23
        port = free_port()
        stem = f"pqc-{os.getpid()}-{self.path.name}"
        server_name, client_name = stem + "-s", stem + "-c"
        common = [*IDENTITY, "--auth-token", "pqc-test", "--tls-group-policy", policy,
                  "--track", "pqc", "--mode", "reliable"]
        server, server_log = self.launch("qlinqd", [*common, "--listen", str(port),
            "--bind", "127.0.0.1", "--socket", server_name], "daemon-server")
        client, client_log = self.launch("qlinqd", [*common, "--peer", f"127.0.0.1:{port}",
            "--socket", client_name], "daemon-client")
        self.wait_for(lambda: self.logged(server_log, "peer authentication successful") and
                      self.logged(client_log, "authentication to peer successful"), "daemons did not authenticate")
        sockets = []
        def connect_uds(name):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(8)
            sock.connect(f"/tmp/{name}.sock")
            sock.sendall(bytes((4, 1, 3)) + b"pqc")
            sockets.append(sock)
            return sock
        def read_exact(sock, size):
            result = bytearray()
            while len(result) < size:
                chunk = sock.recv(size - len(result))
                self.assertTrue(chunk)
                result.extend(chunk)
            return bytes(result)
        def exchange(sender, receiver, payload):
            sender.sendall(struct.pack("!IB", len(payload), 2) + payload)
            size, priority = struct.unpack("!IB", read_exact(receiver, 5))
            self.assertEqual(priority, 2)
            self.assertEqual(read_exact(receiver, size), payload)
        try:
            left, right = connect_uds(client_name), connect_uds(server_name)
            self.wait_for(lambda: self.logged(server_log, "peer subscribed") and self.logged(client_log, "peer subscribed"),
                          "daemon tracks were not subscribed")
            time.sleep(0.05)  # allow the bounded UDS registration to be consumed
            exchange(left, right, bytes(range(256)) * 31)
            exchange(right, left, b"verified-reverse-daemon\x00\xff")
            for proc in (server, client):
                os.kill(proc.pid, signal.SIGHUP)
            self.wait_for(lambda: self.logged(server_log, "TLS credential reload complete") and
                          self.logged(client_log, "TLS credential reload complete"), "daemon identity reload failed")
            left.close()
            self.stop(client)
            new_name = client_name + "2"
            new_client, new_log = self.launch("qlinqd", [*common, "--peer", f"127.0.0.1:{port}",
                "--socket", new_name], "daemon-client-reloaded")
            self.wait_for(lambda: self.logged(new_log, "authentication to peer successful") and
                          server_log.read_text().count("peer authentication successful") == 2,
                          "fresh daemon connection after reload did not authenticate")
            new_socket = connect_uds(new_name)
            time.sleep(0.05)
            exchange(new_socket, right, b"verified-after-reload")
            for log in (server_log, client_log, new_log):
                self.assertRegex(log.read_text(), rf"policy={policy} group={group} result=.*handshake=full verify_peer=1")
            self.assertEqual(server_log.read_text().count(f"group={group} result="), 2)
            print(f"daemon: verified bidirectional exact payloads, reload and fresh connection policy={policy} group={group}", flush=True)
        finally:
            for sock in sockets:
                sock.close()


if __name__ == "__main__":
    program = unittest.main(verbosity=2, exit=False)
    if program.result.wasSuccessful():
        print("===PQC CLI OK===", flush=True)
    raise SystemExit(0 if program.result.wasSuccessful() else 1)
