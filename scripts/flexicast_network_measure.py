#!/usr/bin/env python3
"""Measure actual Flexicast traffic through an isolated Linux shaped network.

Build in a clean tree: make -j8 CFLAGS=-O2 t/00util/flexicast_network_probe gencerts
Run: python3 scripts/flexicast_network_measure.py --mode native --output /tmp/fc-native
The output directory must not exist. No performance threshold is a test assertion.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import time


def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=("native", "replica"), required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--phase-seconds", type=float, default=8)
    p.add_argument("--low-phase-seconds", type=float,
                   help="Low plateau duration, at least --phase-seconds; defaults to the same duration")
    p.add_argument("--transient-seconds", type=float, default=2)
    p.add_argument("--drain-seconds", type=float, default=2)
    p.add_argument("--high-kbit", type=int, default=4000)
    p.add_argument("--low-kbit", type=int, default=1000)
    p.add_argument("--delay-ms", type=float, default=10)
    p.add_argument("--queue-packets", type=int, default=64)
    p.add_argument("--offer-Bps", type=int, default=2000000)
    p.add_argument("--startup-Bps", type=int, default=500000)
    p.add_argument("--minimum-Bps", type=int, default=250)
    p.add_argument("--maximum-Bps", type=int, default=2000000)
    p.add_argument("--backlog-packets", type=int, default=2)
    p.add_argument("--object-size", type=int, default=1024)
    p.add_argument("--receiver2-delay-ms", type=float, default=0)
    p.add_argument("--receiver2-loss-percent", type=float, default=0)
    p.add_argument("--receiver2-rate-kbit", type=int, default=0)
    p.add_argument("--ce-percent", type=float, default=0,
                   help="Random netem loss+ECN marking at shared egress; this is not AQM")
    p.add_argument("--trace", choices=("on", "off"), default="on")
    p.add_argument("--label", default="unspecified-source-revision")
    p.add_argument("--build-flags", default="-O2", help="Recorded build flags; clean/rebuild separately")
    p.add_argument("--in-namespace", action="store_true", help=argparse.SUPPRESS)
    a = p.parse_args()
    if a.low_phase_seconds is None:
        a.low_phase_seconds = a.phase_seconds
    if not (0 < a.transient_seconds < a.phase_seconds <= 100 and
            a.phase_seconds <= a.low_phase_seconds <= 300 - 2 * a.phase_seconds and
            0 <= a.drain_seconds <= 20 and a.high_kbit > 0 and a.low_kbit > 0 and
            0 <= a.delay_ms <= 1000 and 1 <= a.queue_packets <= 10000 and
            1 <= a.backlog_packets <= 128 and 24 <= a.object_size <= 1100 and
            0 < a.minimum_Bps <= a.startup_Bps <= a.maximum_Bps and
            0 < a.offer_Bps <= 10000000 and
            a.offer_Bps * (2 * a.phase_seconds + a.low_phase_seconds + 1) / a.object_size < 8000000 and
            0 <= a.receiver2_loss_percent <= 100 and 0 <= a.ce_percent <= 100 and
            0 <= a.receiver2_delay_ms <= 1000 and a.receiver2_rate_kbit >= 0 and
            0 < round(a.transient_seconds * 1000) < round(a.phase_seconds * 1000)):
        p.error("invalid measurement bounds")
    # C takes integer milliseconds; schedule precisely those same durations.
    a.phase_seconds = round(a.phase_seconds * 1000) / 1000
    a.low_phase_seconds = round(a.low_phase_seconds * 1000) / 1000
    a.transient_seconds = round(a.transient_seconds * 1000) / 1000
    a.drain_seconds = round(a.drain_seconds * 1000) / 1000
    if round((2 * a.phase_seconds + a.low_phase_seconds) * 1000) > 300000:
        p.error("rounded production duration exceeds 300 seconds")
    return a


def phase_boundaries(args):
    """Integer-millisecond nominal schedule shared with the C endpoint."""
    phase_ms = round(args.phase_seconds * 1000)
    low_ms = round(args.low_phase_seconds * 1000)
    return [0, phase_ms / 1000, (phase_ms + low_ms) / 1000,
            (2 * phase_ms + low_ms) / 1000]


def measurement_windows(args):
    boundaries_ms = [round(value * 1000) for value in phase_boundaries(args)]
    phase_ms = round(args.phase_seconds * 1000)
    transient_ms = round(args.transient_seconds * 1000)
    windows = []
    for phase in range(3):
        begin_ms = boundaries_ms[phase]
        windows.extend(((phase, "transient", begin_ms / 1000, (begin_ms + transient_ms) / 1000),
                        (phase, "steady", (begin_ms + transient_ms) / 1000, (begin_ms + phase_ms) / 1000)))
    if args.low_phase_seconds > args.phase_seconds:
        windows.append((1, "late", (boundaries_ms[1] + phase_ms) / 1000, boundaries_ms[2] / 1000))
    return windows


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def interpolate(samples, when, field):
    if when <= samples[0]["elapsed_s"]:
        return samples[0][field]
    for left, right in zip(samples, samples[1:]):
        if when <= right["elapsed_s"]:
            fraction = (when - left["elapsed_s"]) / (right["elapsed_s"] - left["elapsed_s"])
            return left[field] + (right[field] - left[field]) * fraction
    return samples[-1][field]


def summarize(output, args):
    result = {"schema": 1, "mode": args.mode, "label": args.label,
              "trace": args.trace, "phase_seconds": args.phase_seconds,
              "low_phase_seconds": args.low_phase_seconds,
              "phase_boundaries_s": phase_boundaries(args),
              "latency_definition": "admission-attempt to unique application delivery, grouped by emission phase; 1ms ceiling bins",
              "rate_definition": "cumulative counters linearly interpolated at phase boundaries from approximately 1s samples; physical is protected UDP payload submitted to kernel, qdisc counters include actual egress",
              "phase_definition": "nominal emission schedule; actual tc change timestamps and drift are in manifest.phase_changes",
              "window_definition": "each phase preserves transient 0..transient_seconds and steady transient_seconds..phase_seconds; any extended low interval is a separate appended late window",
              "latency_excludes_application_overload_drops": True,
              "admission_policy": "fixed offered schedule; admit through publish_ex while the explicit packet backlog is below its bound; rejected offers are counted, never retried",
              "latency_target_ms": 100, "roles": {}}
    for role in ("source", "receiver1", "receiver2"):
        rows = records(output / (role + ".jsonl"))
        samples = [r for r in rows if r["kind"] == "sample"]
        phases = []
        fields = ("offered_bytes", "admitted_bytes", "received_bytes", "physical_bytes", "cpu_s", "application_overload_objects")
        for phase, segment, begin, end in measurement_windows(args):
            deltas = {f: interpolate(samples, end, f) - interpolate(samples, begin, f) for f in fields}
            entry = {"phase": phase, "segment": segment, "duration_s": end - begin,
                     "begin_s": begin, "end_s": end,
                     "capacity_kbit": args.low_kbit if phase == 1 else args.high_kbit,
                     "offered_Bps": deltas["offered_bytes"] / (end - begin),
                     "admitted_Bps": deltas["admitted_bytes"] / (end - begin),
                     "goodput_Bps": deltas["received_bytes"] / (end - begin),
                     "physical_submitted_Bps": deltas["physical_bytes"] / (end - begin),
                     "cpu_core_fraction": deltas["cpu_s"] / (end - begin),
                     "application_overload_objects": deltas["application_overload_objects"]}
            latency = next(r for r in rows if r["kind"] == "latency" and
                           r["emission_phase"] == phase and r["segment"] == segment)
            entry["delivered_latency"] = latency
            entry["p99_meets_100ms"] = latency["p99_upper_ms"] <= 100 if latency["objects"] else None
            phases.append(entry)
        result["roles"][role] = {"phases": phases, "last_sample": samples[-1],
                                 "health": next(r for r in rows if r["kind"] == "health")}
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    failures = []
    for role in ("receiver1", "receiver2"):
        if result["roles"][role]["health"]["malformed"]:
            failures.append(role + " delivered malformed measurement payload")
        if not result["roles"][role]["last_sample"]["received_objects"]:
            failures.append(role + " delivered no measurement objects")
    if args.mode == "native" and not result["roles"]["source"]["last_sample"]["native_packets"]:
        failures.append("native mode did not submit any native multicast packets")
    if failures:
        raise RuntimeError("; ".join(failures))
    return result


def main():
    args = parse_args()
    root = Path(__file__).resolve().parent.parent
    args.output = args.output.resolve()
    for command in ("ip", "tc", "nsenter", "unshare"):
        if not shutil.which(command):
            raise SystemExit(f"required executable missing: {command}")
    if not args.in_namespace:
        # Even a root caller gets a private outer network namespace. No host
        # interface, global named namespace, or unrelated process is modified.
        os.execvp("unshare", ["unshare", "--user", "--map-root-user", "--net",
                             sys.executable, str(Path(__file__).resolve()),
                             *sys.argv[1:], "--in-namespace"])
    binary = root / "t/00util/flexicast_network_probe"
    if not binary.is_file():
        raise SystemExit("build t/00util/flexicast_network_probe first")
    args.output.mkdir(parents=True, exist_ok=False)
    children, holders, log_handles, command_log = [], [], [], []
    manifest = {"schema": 1, "label": args.label, "arguments": vars(args).copy(),
                "phase_boundaries_s": phase_boundaries(args),
                "kernel": platform.uname()._asdict(), "commands": command_log,
                "clock": "CLOCK_MONOTONIC shared across local network namespaces",
                "declared_build_flags": args.build_flags,
                "queue": "source eth0 HTB class -> netem bounded packet queue; shared before bridge replication",
                "physical_accounting": "transport successful UDP submission, not confirmed NIC egress; use tc statistics for egress and drops",
                "ce_model": "random netem loss+ecn marking (not AQM)",
                "trace_filter": "all feedback/timeouts and rate/state transitions, unchanged hints omitted and counted; ring overwrite cumulative",
                "source_hashes": {}}
    manifest["arguments"]["output"] = str(args.output)
    for base in (root / "src", root / "deps"):
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix in (".c", ".h"):
                manifest["source_hashes"][str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    for path in (binary, root / "Makefile", Path(__file__).resolve(), root / "t/00util/flexicast_network_probe.c"):
        manifest["source_hashes"][str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest["compiler"] = subprocess.check_output(["gcc", "--version"], text=True).splitlines()[0]

    def save_manifest():
        (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    def command(cmd, ns=None, capture=False):
        full = (["nsenter", "-t", str(ns.pid), "-n", "--"] if ns else []) + [str(v) for v in cmd]
        command_log.append({"mono_ns": time.monotonic_ns(), "argv": full})
        return subprocess.run(full, check=True, text=True, stdout=subprocess.PIPE if capture else None,
                              stderr=subprocess.PIPE if capture else None, cwd=root)

    def start_holder():
        holder = subprocess.Popen(["unshare", "--net", "--", "sleep", "infinity"])
        holders.append(holder)
        return holder

    def cleanup():
        for process in children + holders:
            if process.poll() is None:
                process.terminate()
        for process in children + holders:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for stream in log_handles:
            stream.close()

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    qdisc_stream = None
    try:
        switch, source, a, b = [start_holder() for _ in range(4)]
        time.sleep(.1)
        for holder in holders:
            if holder.poll() is not None:
                raise RuntimeError("network namespace holder failed")
            command(["ip", "link", "set", "lo", "up"], holder)
        command(["ip", "link", "add", "br0", "type", "bridge"], switch)
        command(["ip", "link", "set", "br0", "type", "bridge", "mcast_snooping", "0"], switch)
        command(["ip", "link", "set", "br0", "up"], switch)
        for i, endpoint in enumerate((source, a, b)):
            first, second = f"fm{i}a", f"fm{i}b"
            command(["ip", "link", "add", first, "type", "veth", "peer", "name", second])
            command(["ip", "link", "set", first, "netns", endpoint.pid])
            command(["ip", "link", "set", second, "netns", switch.pid])
            command(["ip", "link", "set", first, "name", "eth0"], endpoint)
            command(["ip", "link", "set", "eth0", "up"], endpoint)
            command(["ip", "address", "add", f"10.242.0.{i + 1}/24", "dev", "eth0"], endpoint)
            command(["ip", "route", "add", "224.0.0.0/4", "dev", "eth0"], endpoint)
            command(["ip", "link", "set", second, "name", f"port{i}"], switch)
            command(["ip", "link", "set", f"port{i}", "master", "br0"], switch)
            command(["ip", "link", "set", f"port{i}", "up"], switch)
        command(["tc", "qdisc", "add", "dev", "eth0", "root", "handle", "1:", "htb", "default", "10"], source)

        def set_capacity(rate, verb="change"):
            command(["tc", "class", verb, "dev", "eth0", "parent", "1:", "classid", "1:10",
                     "htb", "rate", f"{rate}kbit", "ceil", f"{rate}kbit", "burst", "8kb", "cburst", "8kb"], source)

        set_capacity(args.high_kbit, "add")
        netem = ["tc", "qdisc", "add", "dev", "eth0", "parent", "1:10", "handle", "10:",
                 "netem", "delay", f"{args.delay_ms}ms", "limit", args.queue_packets]
        if args.ce_percent:
            netem += ["loss", "random", f"{args.ce_percent}%", "ecn"]
        command(netem, source)
        if args.receiver2_delay_ms or args.receiver2_loss_percent or args.receiver2_rate_kbit:
            netem = ["tc", "qdisc", "add", "dev", "port2", "root", "netem", "limit", args.queue_packets]
            if args.receiver2_delay_ms:
                netem += ["delay", f"{args.receiver2_delay_ms}ms"]
            if args.receiver2_loss_percent:
                netem += ["loss", "random", f"{args.receiver2_loss_percent}%"]
            if args.receiver2_rate_kbit:
                netem += ["rate", f"{args.receiver2_rate_kbit}kbit"]
            command(netem, switch)
        common = [args.mode, round(args.phase_seconds * 1000), round(args.transient_seconds * 1000),
                  round(args.drain_seconds * 1000), args.offer_Bps, args.startup_Bps, args.minimum_Bps,
                  args.maximum_Bps, args.backlog_packets, args.object_size, args.output / "start.ns"]
        for role, endpoint, ip in (("source", source, "10.242.0.1"), ("receiver1", a, "10.242.0.2"),
                                    ("receiver2", b, "10.242.0.3")):
            trace = args.output / "trace.jsonl" if role == "source" and args.trace == "on" else "off"
            cmd = ["nsenter", "-t", str(endpoint.pid), "-n", "--", str(binary),
                   "source" if role == "source" else "client", ip, "10.242.0.1",
                   *map(str, common), str(args.output / (role + ".jsonl")), str(trace),
                   str(round(args.low_phase_seconds * 1000))]
            command_log.append({"mono_ns": time.monotonic_ns(), "argv": cmd})
            stream = (args.output / (role + ".log")).open("w")
            log_handles.append(stream)
            children.append(subprocess.Popen(cmd, cwd=root, stdout=stream, stderr=subprocess.STDOUT))
        ready_path = args.output / "source.jsonl"
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if any(p.poll() is not None for p in children):
                raise RuntimeError("endpoint exited during readiness; inspect endpoint logs")
            if ready_path.exists() and '"kind":"ready"' in ready_path.read_text():
                break
            time.sleep(.02)
        else:
            raise RuntimeError("source readiness timed out")
        start_ns = time.monotonic_ns() + 200000000
        manifest["start_mono_ns"] = start_ns
        temporary = args.output / "start.tmp"
        temporary.write_text(str(start_ns) + "\n")
        temporary.rename(args.output / "start.ns")
        qdisc_stream = (args.output / "qdisc.jsonl").open("w")

        def snapshot(label):
            row = {"elapsed_s": (time.monotonic_ns() - start_ns) / 1e9, "label": label,
                   "source_qdisc": json.loads(command(["tc", "-s", "-j", "qdisc", "show", "dev", "eth0"], source, True).stdout),
                   "source_class": json.loads(command(["tc", "-s", "-j", "class", "show", "dev", "eth0"], source, True).stdout),
                   "receiver2_qdisc": json.loads(command(["tc", "-s", "-j", "qdisc", "show", "dev", "port2"], switch, True).stdout)}
            qdisc_stream.write(json.dumps(row) + "\n")
            qdisc_stream.flush()

        snapshot("ready")
        phase, next_snapshot = 0, start_ns
        boundaries = phase_boundaries(args)
        end_ns = start_ns + round((boundaries[-1] + args.drain_seconds + 2) * 1e9)
        while time.monotonic_ns() < end_ns and any(p.poll() is None for p in children):
            now = time.monotonic_ns()
            if phase < 2 and now >= start_ns + round(boundaries[phase + 1] * 1e9):
                snapshot("before_capacity_change")
                phase += 1
                set_capacity(args.low_kbit if phase == 1 else args.high_kbit)
                changed_ns = time.monotonic_ns()
                manifest.setdefault("phase_changes", []).append({"phase": phase, "mono_ns": changed_ns,
                    "nominal_elapsed_s": boundaries[phase],
                    "actual_elapsed_s": (changed_ns - start_ns) / 1e9,
                    "drift_ms": (changed_ns - start_ns - round(boundaries[phase] * 1e9)) / 1e6})
                snapshot("after_capacity_change")
            if now >= next_snapshot:
                snapshot("periodic")
                next_snapshot += 1000000000
            time.sleep(.01)
        snapshot("finished")
        manifest["returncodes"] = [p.poll() for p in children]
        if any(code != 0 for code in manifest["returncodes"]):
            raise RuntimeError(f"measurement endpoint failure: {manifest['returncodes']}")
        result = summarize(args.output, args)
        manifest["completed"] = True
        print(json.dumps({"output": str(args.output), "mode": args.mode,
                          "source_final_controller_Bps": result["roles"]["source"]["last_sample"]["controller_Bps"],
                          "source_cpu_s": result["roles"]["source"]["last_sample"]["cpu_s"],
                          "receiver_objects": [result["roles"][r]["last_sample"]["received_objects"] for r in ("receiver1", "receiver2")],
                          "trace_overwritten": result["roles"]["source"]["last_sample"]["trace_overwritten"]}))
    except BaseException as error:
        manifest["completed"] = False
        manifest["error"] = repr(error)
        raise
    finally:
        try:
            save_manifest()
            if qdisc_stream:
                qdisc_stream.close()
        finally:
            cleanup()


if __name__ == "__main__":
    main()
