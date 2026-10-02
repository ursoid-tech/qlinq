#!/usr/bin/env python3
"""Unprivileged management and authenticated loopback acceptance tests."""
import json
import os
from pathlib import Path
import socket
import signal
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "qlinq-tun"


class TunnelTool(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="qt-")
        self.directory = Path(self.tmp.name)
        # Exercise an isolated installation with just one executable. No
        # Python, openssl CLI, or companion engine is available in PATH.
        install = self.directory / "bin"
        install.mkdir()
        self.cli = install / "qlinq-tun"
        shutil.copy2(CLI, self.cli)
        self.env = dict(os.environ, PATH=str(install))
        self.assertEqual(self.cli.read_bytes()[:4], b"\x7fELF")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.call("init", "server", "--listen", f"127.0.0.1:{self.port}", "--uplink", "lo")
        self.call("init", "client", "--invite", str(self.directory / "server/invite.json"),
                  "--uplink", "lo")
        self.call("pair", "server", str(self.directory / "client/peer.json"))

    def tearDown(self):
        for name in ("server", "client"):
            self.call("down", name, expected=None)
        self.tmp.cleanup()

    def call(self, *args, expected=0):
        result = subprocess.run([str(self.cli), "--config-dir", str(self.directory), *args],
                                text=True, capture_output=True, timeout=20, env=self.env)
        if expected is not None:
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def status(self, name):
        return json.loads(self.call("status", name, "--json").stdout)

    def connected(self, name):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            status = self.status(name)
            if status["state"] == "connected" and status.get("received", 0) > 0:
                return status
            time.sleep(0.1)
        self.fail(f"{name} did not connect: {status}; " +
                  (self.directory / name / "run/tunnel.log").read_text())

    def test_identity_and_validation(self):
        server_key = (self.directory / "server/identity.key").read_text()
        client_key = (self.directory / "client/identity.key").read_text()
        self.assertNotEqual(server_key, client_key)
        self.assertNotIn("PRIVATE KEY", (self.directory / "server/invite.json").read_text())
        self.assertNotIn("PRIVATE KEY", (self.directory / "client/peer.json").read_text())
        self.assertEqual((self.directory / "server/identity.key").stat().st_mode & 0o777, 0o600)
        self.call("init", "server", "--listen", "127.0.0.1", "--uplink", "lo", expected=1)
        self.assertEqual(server_key, (self.directory / "server/identity.key").read_text())
        self.call("diag", "server", "--mock")
        config_path = self.directory / "server/config.json"
        config = json.loads(config_path.read_text())
        for bad in ({"mtu": 9000}, {"routes": ["0.0.0.0/0"]},
                    {"routes": ["127.0.0.0/8"]},
                    {"routes": ["10.90.0.0/16", "10.90.1.0/24"]},
                    {"uplinks": [config["interface"]]}, {"schema": 999}):
            changed = dict(config, **bad)
            config_path.write_text(json.dumps(changed))
            self.call("diag", "server", "--mock", expected=1)
        config_path.write_text(json.dumps(config))
        self.call("init", "../escape", "--listen", "127.0.0.1", "--uplink", "lo", expected=1)

    def test_lifecycle_reconnect_and_redaction(self):
        self.call("up", "server", "--mock")
        self.call("up", "client", "--mock")
        for name in ("server", "client"):
            snapshot = self.connected(name)
            self.assertGreater(snapshot["sent"], 0)
            self.assertTrue(snapshot["paths"])
        self.assertIn("already", self.call("up", "server", "--mock").stdout)
        self.call("run", "server", "--mock", expected=1)
        token = json.loads((self.directory / "server/config.json").read_text())["token"]
        report = self.call("diagnose", "server").stdout
        self.assertNotIn(token, report)
        self.assertNotIn("PRIVATE KEY", report)
        self.call("down", "server")
        self.assertEqual(self.status("server")["state"], "stopped")
        self.call("up", "server", "--mock")
        self.connected("server")
        self.connected("client")
        for name in ("server", "client"):
            self.call("down", name)
            self.call("down", name)
            self.assertFalse((self.directory / name / "run/control.sock").exists())

    def test_missing_peer_and_unknown_identity(self):
        (self.directory / "server/peer.crt").unlink()
        self.call("diag", "server", "--mock", expected=1)
        self.call("up", "server", "--mock", expected=1)
        peer = json.loads((self.directory / "client/peer.json").read_text())
        peer["id"] = "0" * 32
        wrong = self.directory / "wrong.json"
        wrong.write_text(json.dumps(peer))
        self.call("pair", "server", str(wrong), expected=1)
        self.assertFalse((self.directory / "server/peer.crt").exists())

    def test_supervisor_crash_and_stale_socket(self):
        self.call("up", "server", "--mock")
        status = self.status("server")
        os.kill(status["supervisor_pid"], signal.SIGKILL)
        # The worker's parent-death handler must release its UDP port before
        # the new supervisor starts. No arbitrary stored PID is signalled by
        # the CLI: all normal lifecycle requests use the private control socket.
        time.sleep(1)
        self.assertEqual(self.status("server")["state"], "stopped")
        self.call("up", "server", "--mock")
        self.call("up", "client", "--mock")
        self.connected("server")

    def test_engine_rejects_bad_network_options(self):
        for options in (["--mtu", "500"], ["--mtu", "9000"],
                        ["--ip", "10.88.0.1", "--peer-ip", "10.88.0.1"],
                        ["--ip", "10.88.0.1", "--peer-ip", "10.88.0.2", "--route", "0.0.0.0/0"]):
            result = subprocess.run([str(CLI), "--peer", "127.0.0.1", "--auth-token",
                                     "test", "--insecure-no-verify", "--mock", *options],
                                    capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)

    def test_json_rejection_and_legacy_whitespace(self):
        path = self.directory / "server/config.json"
        config = json.loads(path.read_text())
        for bad in ('{"schema":1,"schema":1}', '{"a":}', '{"a":01}',
                    '{"a":"\\u0000"}', '{"a":"\\ud800"}', '{"a":true,}',
                    '[' * 40 + '0' + ']' * 40, 'x' * 65537,
                    json.dumps(config) + ' trailing', json.dumps(config) + '\x00'):
            path.write_text(bad)
            self.call("diag", "server", "--mock", expected=1)
        # Profiles emitted by the former Python launcher used indentation and
        # Python's JSON escape conventions; those remain accepted unchanged.
        legacy = json.dumps(config, indent=2).replace('"listen"', '"li\\u0073ten"')
        path.write_text(legacy + '\n')
        self.call("diag", "server", "--mock", "--json")


if __name__ == "__main__":
    unittest.main(verbosity=2)
