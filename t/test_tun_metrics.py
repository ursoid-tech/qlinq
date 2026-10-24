#!/usr/bin/env python3
"""Prometheus exposition, freshness, and atomic textfile acceptance tests."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "qlinq-tun"


class TunnelMetrics(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="qm-")
        self.directory = Path(self.tmp.name)
        self.output = self.directory / "office.prom"
        self.exporter = None
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.call("init", "office", "--listen", f"127.0.0.1:{self.port}",
                  "--uplink", "lo")

    def tearDown(self):
        if self.exporter is not None and self.exporter.poll() is None:
            self.exporter.terminate()
            self.exporter.communicate(timeout=5)
        for name in ("office", "client"):
            self.call("down", name, expected=None)
        self.tmp.cleanup()

    def command(self, *args):
        return [str(CLI), "--config-dir", str(self.directory), *args]

    def call(self, *args, expected=0):
        result = subprocess.run(self.command(*args), text=True,
                                capture_output=True, timeout=20)
        if expected is not None:
            self.assertEqual(result.returncode, expected,
                             result.stdout + result.stderr)
        return result

    @contextmanager
    def snapshot(self, value):
        """Supply deterministic status over the actual control protocol."""
        runtime = self.directory / "office/run"
        runtime.mkdir(mode=0o700, exist_ok=True)
        path = runtime / "control.sock"
        errors = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
            server.listen(1)
            server.settimeout(5)

            def respond():
                try:
                    with server.accept()[0] as client:
                        client.settimeout(5)
                        request = b""
                        while b"\n" not in request:
                            request += client.recv(128)
                        self.assertEqual(request, b"status\n")
                        client.sendall(json.dumps(value).encode())
                except Exception as error:
                    errors.append(error)

            thread = threading.Thread(target=respond, daemon=True)
            thread.start()
            try:
                yield
            finally:
                thread.join(timeout=6)
                path.unlink(missing_ok=True)
                self.assertFalse(thread.is_alive())
                if errors:
                    raise errors[0]

    def exported(self, snapshot):
        with self.snapshot(snapshot):
            return self.call("metrics", "office").stdout

    def value(self, text, metric):
        prefix = f'qlinq_tun_{metric}{{tunnel="office"}} '
        return float(next(line[len(prefix):] for line in text.splitlines()
                          if line.startswith(prefix)))

    def wait_for(self, predicate):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if predicate():
                return
            if self.exporter is not None and self.exporter.poll() is not None:
                self.fail(f"exporter exited: {self.exporter.communicate()}")
            time.sleep(0.05)
        self.fail("timed out waiting for metrics")

    def test_stopped_tunnel(self):
        text = self.call("metrics", "office").stdout
        for metric in ("running", "connected", "snapshot_fresh"):
            self.assertEqual(self.value(text, metric), 0)
        self.assertIn('state="stopped"} 1\n', text)
        self.assertNotIn("tx_bytes_total", text)
        self.assertNotIn("snapshot_age_seconds", text)
        self.assertLess(abs(self.value(text, "metrics_export_time_seconds") - time.time()), 5)

    def test_format_units_labels_types_and_allowlist(self):
        snapshot = {
            "state": "connected", "snapshot_age_ms": 1234,
            "sent": 12, "received": 13, "tx_bytes": 2**64 - 1,
            "rx_bytes": 1024, "dropped": 2, "queued_bytes": 123,
            "fec_recovered": 9, "fec_decoded": 3, "fec_lost": 1,
            "reconnects": 2, "token": "never-export-this-secret",
            "paths": [{"interface": 'eth"\\\n0', "address": "192.0.2.1",
                       "active": True, "rtt_ms": 42, "tx_bytes": 333,
                       "rx_bytes": 444, "packets_lost": 5},
                      {"interface": "wwan0", "address": "192.0.2.2",
                       "active": False, "rtt_ms": 99},
                      {"interface": "eth2", "address": "192.0.2.3",
                       "active": True, "rtt_ms": 0}]
        }
        text = self.exported(snapshot)
        self.assertEqual(self.value(text, "connected"), 1)
        self.assertEqual(self.value(text, "snapshot_age_seconds"), 1.234)
        self.assertIn('qlinq_tun_tx_bytes_total{tunnel="office"} 18446744073709551615\n', text)
        self.assertEqual(self.value(text, "fec_completed_objects_total"), 9)
        self.assertEqual(self.value(text, "fec_decoded_objects_total"), 3)
        self.assertIn('interface="eth\\"\\\\\\n0",address="192.0.2.1"} 0.042\n', text)
        self.assertNotIn("never-export-this-secret", text)
        self.assertNotIn("token", text)
        rtt_samples = [line for line in text.splitlines()
                       if line.startswith("qlinq_tun_path_rtt_seconds{")]
        self.assertEqual(len(rtt_samples), 1)
        types = [line.split()[2] for line in text.splitlines()
                 if line.startswith("# TYPE ")]
        self.assertEqual(len(types), len(set(types)))
        self.assertIn("# TYPE qlinq_tun_path_packets_lost gauge\n", text)
        self.assertIn("# TYPE qlinq_tun_tx_bytes_total counter\n", text)
        self.assertIn("# TYPE qlinq_tun_transport_queued_bytes gauge\n", text)
        sample_keys = [line.rsplit(" ", 1)[0] for line in text.splitlines()
                       if not line.startswith("#")]
        self.assertEqual(len(sample_keys), len(set(sample_keys)))
        seen, current = set(), None
        for line in text.splitlines():
            if line.startswith("#"):
                continue
            family = line.split("{", 1)[0]
            if family != current:
                self.assertNotIn(family, seen)
                seen.add(family)
                current = family
            self.assertIn(f"# TYPE {family} ", text[:text.index(line)])
        self.assertTrue(text.endswith("\n"))

    def test_same_address_on_distinct_interfaces(self):
        paths = [{"interface": interface, "address": "fe80::1",
                  "active": True, "tx_bytes": count}
                 for count, interface in enumerate(("eth0", "eth1"), 1)]
        text = self.exported({"state": "connected", "snapshot_age_ms": 0,
                              "paths": paths})
        for path in paths:
            labels = (f'tunnel="office",interface="{path["interface"]}",'
                      'address="fe80::1"')
            self.assertEqual(text.count(
                f'qlinq_tun_path_active{{{labels}}} 1\n'), 1)
            self.assertEqual(text.count(
                f'qlinq_tun_path_tx_bytes_total{{{labels}}} '
                f'{path["tx_bytes"]}\n'), 1)

    def test_freshness_and_connection_state(self):
        for state, age, fresh, connected in (
                ("connected", 3000, 1, 1), ("connected", 3001, 0, 0),
                ("degraded", 100, 1, 0), ("reconnecting", 100, 1, 0),
                ("starting", 100, 0, 0), ("connected", None, 0, 0)):
            with self.subTest(state=state, age=age):
                snapshot = {"state": state, "sent": 5}
                if age is not None:
                    snapshot["snapshot_age_ms"] = age
                text = self.exported(snapshot)
                self.assertEqual(self.value(text, "running"), 1)
                self.assertEqual(self.value(text, "snapshot_fresh"), fresh)
                self.assertEqual(self.value(text, "connected"), connected)
                # A stale snapshot retains actual totals, accompanied by freshness.
                self.assertEqual(self.value(text, "tx_packets_total"), 5)

    def test_malformed_snapshot_does_not_replace_file(self):
        path = {"interface": "lo", "address": "127.0.0.1", "active": True}
        for snapshot in ({"state": "unknown"}, {"state": "connected", "sent": -1},
                         {"state": "connected", "sent": 2**64},
                         {"state": "connected", "snapshot_age_ms": "1"},
                         {"state": "connected", "paths": {}},
                         {"state": "connected", "paths": [dict(path, active=1)]},
                         {"state": "connected", "paths": [path, path]}):
            with self.subTest(snapshot=snapshot):
                self.output.write_text("previous complete file\n")
                with self.snapshot(snapshot):
                    result = self.call("metrics", "office", "--output", str(self.output), expected=1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(self.output.read_text(), "previous complete file\n")
                self.assertFalse(list(self.directory.glob("office.prom.*")))

    def test_atomic_output_and_failures(self):
        victim = self.directory / "victim"
        victim.write_text("untouched")
        self.output.symlink_to(victim)
        self.call("metrics", "office", "--output", str(self.output))
        self.assertFalse(self.output.is_symlink())
        self.assertEqual(victim.read_text(), "untouched")
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o644)
        old_inode = self.output.stat().st_ino
        self.call("metrics", "office", "--output", str(self.output))
        self.assertNotEqual(self.output.stat().st_ino, old_inode)
        self.assertFalse(list(self.directory.glob("office.prom.*")))
        self.output.unlink()
        self.output.mkdir()
        self.call("metrics", "office", "--output", str(self.output), expected=1)
        self.assertTrue(self.output.is_dir())
        self.assertFalse(list(self.directory.glob("office.prom.*")))
        self.call("metrics", "office", "--output",
                  str(self.directory / "missing/out.prom"), expected=1)

    def test_invalid_options(self):
        for args in (("--interval", "1"), ("--output", "relative.prom"),
                     ("--output", str(self.directory / "config.json")),
                     ("--output",), ("--json",), ("--mock",),
                     ("--output", str(self.output), "--interval", "0"),
                     ("--output", str(self.output), "--interval", "3601"),
                     ("--output", str(self.output), "--interval", "1.5"),
                     ("--output", str(self.output), "--interval", "-1"),
                     ("--output", str(self.output), "--output", str(self.output))):
            with self.subTest(args=args):
                self.call("metrics", "office", *args, expected=1)
        self.call("metrics", "missing", expected=1)
        self.assertFalse(self.output.exists())

    def test_periodic_export_tracks_stop_and_restart(self):
        self.call("init", "client", "--invite", str(self.directory / "office/invite.json"),
                  "--uplink", "lo")
        self.call("pair", "office", str(self.directory / "client/peer.json"))
        self.call("up", "office", "--mock")
        self.call("up", "client", "--mock")
        self.exporter = subprocess.Popen(
            self.command("metrics", "office", "--output", str(self.output), "--interval", "1"),
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        def connected():
            return (self.output.exists() and
                    self.value(self.output.read_text(), "connected") == 1)

        self.wait_for(connected)
        text = self.output.read_text()
        self.assertGreater(self.value(text, "tx_bytes_total"), 0)
        self.assertIn("qlinq_tun_fec_decoded_objects_total", text)
        self.assertIn('qlinq_tun_path_active{tunnel="office",interface="lo",address="127.0.0.1"} 1\n', text)
        status = json.loads(self.call("status", "office", "--json").stdout)
        self.assertTrue(status["paths"])
        self.assertTrue(all(path["interface"] == "lo" for path in status["paths"]))
        self.call("down", "office")
        self.wait_for(lambda: self.value(self.output.read_text(), "running") == 0)
        self.assertNotIn("tx_bytes_total", self.output.read_text())
        # Restart both packet workers; this exercises exporter continuity
        # without making this test depend on transport reconnect backoff.
        self.call("down", "client")
        self.call("up", "office", "--mock")
        self.call("up", "client", "--mock")
        self.wait_for(connected)
        before = self.output.stat().st_mtime_ns
        self.wait_for(lambda: self.output.stat().st_mtime_ns > before)
        self.exporter.send_signal(signal.SIGTERM)
        stdout, stderr = self.exporter.communicate(timeout=2)
        self.assertEqual(self.exporter.returncode, 0, stderr)
        self.assertEqual(stdout, "")
        # Retained on exporter shutdown so an mtime/timestamp alert can detect it.
        self.assertTrue(self.output.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
