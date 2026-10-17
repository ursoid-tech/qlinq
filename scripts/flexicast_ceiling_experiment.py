#!/usr/bin/env python3
"""Run, collect, and analyze repeated shaped-network Flexicast comparisons.

Examples:
  python3 scripts/flexicast_ceiling_experiment.py plan --baseline-tree BASE --candidate-tree CAND
  python3 scripts/flexicast_ceiling_experiment.py run --baseline-tree BASE --candidate-tree CAND
  python3 scripts/flexicast_ceiling_experiment.py collect --input /tmp --output docs/evidence/flexicast-ceiling
  python3 scripts/flexicast_ceiling_experiment.py analyze --input docs/evidence/flexicast-ceiling --output comparison.json

The runner is serial. The caller must freeze source/builds and pause other test
work first. Empty observation buckets never count as successful delay recovery.
"""
import argparse
from collections import Counter
import gzip
import json
import math
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import time

RUN_NAME = re.compile(r"(?:flexicast-ceiling-)?(baseline|candidate)-(native|replica)-(\d+)")
WIDTH = 0.1
WINDOW = 10


def rows(path):
    if path.suffix == ".gz":
        with gzip.open(path, "rt") as stream:
            return [json.loads(line) for line in stream if line.strip()]
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def run_paths(directory):
    for path in sorted(directory.iterdir()):
        match = RUN_NAME.fullmatch(path.name)
        if path.is_dir() and match and (path / "summary.json").exists():
            yield path, match.group(1), match.group(2), int(match.group(3))


def sequence(args):
    for repetition in range(1, args.repetitions + 1):
        versions = ("baseline", "candidate") if repetition % 2 else ("candidate", "baseline")
        modes = ("native", "replica") if repetition % 2 else ("replica", "native")
        for mode in modes:
            for version in versions:
                tree = getattr(args, version + "_tree").resolve()
                output = args.input.resolve() / f"flexicast-ceiling-{version}-{mode}-{repetition}"
                yield {"version": version, "mode": mode, "repetition": repetition,
                       "tree": str(tree), "output": str(output),
                       "argv": ["python3", "scripts/flexicast_network_measure.py", "--mode", mode,
                                "--output", str(output), "--label", f"ceiling-{version}-{mode}-{repetition}"]}


def run(args):
    planned = list(sequence(args))
    if args.command == "plan":
        print(json.dumps(planned, indent=2))
        return
    log_path = args.input / "flexicast-ceiling-sequence.json"
    if log_path.exists() or any(Path(item["output"]).exists() for item in planned):
        raise SystemExit("output or sequence already exists; use a new input directory, never silently replace a run")
    args.input.mkdir(parents=True, exist_ok=True)
    state = {"schema": 1, "order": planned, "completed": []}
    log_path.write_text(json.dumps(state, indent=2) + "\n")
    for index, item in enumerate(planned, 1):
        print(json.dumps({"event": "starting", "index": index, "total": len(planned), **item}), flush=True)
        began = time.monotonic_ns()
        result = subprocess.run(item["argv"], cwd=item["tree"])
        state["completed"].append({"index": index, "version": item["version"], "mode": item["mode"],
                                   "repetition": item["repetition"], "returncode": result.returncode,
                                   "started_mono_ns": began, "finished_mono_ns": time.monotonic_ns()})
        log_path.write_text(json.dumps(state, indent=2) + "\n")
        if result.returncode:
            raise SystemExit(result.returncode)


def collect(args):
    args.output.mkdir(parents=True, exist_ok=True)
    copied = []
    for path, version, mode, repetition in run_paths(args.input):
        dest = args.output / f"{version}-{mode}-{repetition}"
        dest.mkdir(exist_ok=True)
        for name in ("summary.json", "manifest.json", "source.jsonl", "receiver1.jsonl", "receiver2.jsonl",
                     "qdisc.jsonl", "source.log", "receiver1.log", "receiver2.log"):
            if (path / name).exists():
                shutil.copyfile(path / name, dest / name)
        trace = path / "trace.jsonl"
        if trace.exists():
            (dest / "trace.jsonl.gz").write_bytes(gzip.compress(trace.read_bytes(), mtime=0))
        elif (path / "trace.jsonl.gz").exists():
            shutil.copyfile(path / "trace.jsonl.gz", dest / "trace.jsonl.gz")
        copied.append(dest.name)
    sequence_path = args.input / "flexicast-ceiling-sequence.json"
    if sequence_path.exists():
        shutil.copyfile(sequence_path, args.output / "sequence.json")
    print(json.dumps({"collected": copied, "output": str(args.output)}))


def sustained(buckets, drop, recovery):
    """Ten populated full 100 ms buckets with zero threshold violations.

    Return both retrospective window start and the time it can be confirmed.
    Keep recurrence after the first passing window separate from first drain.
    Buckets are dictionaries indexed on the shared measurement clock.
    """
    first = math.ceil((drop - 1e-9) / WIDTH)
    stop = math.floor((recovery + 1e-9) / WIDTH)
    good = lambda i: i in buckets and buckets[i]["complete"] and buckets[i]["count"] > 0 and buckets[i]["bad"] == 0
    start = next((i for i in range(first, stop - WINDOW + 1)
                  if all(good(j) for j in range(i, i + WINDOW))), None)
    bad = [i for i in range(first, stop) if buckets.get(i, {}).get("bad", 0)]
    missing = [i for i in range(first, stop) if i not in buckets or not buckets[i]["complete"] or not buckets[i]["count"]]
    following = [i for i in bad if start is not None and i >= start + WINDOW]
    final = next((i for i in range(first, stop - WINDOW + 1)
                  if all(good(j) for j in range(i, stop))), None)
    return {"first_1s_window_start_delay_s": round(start * WIDTH - drop, 6) if start is not None else None,
            "first_1s_window_confirmed_delay_s": round((start + WINDOW) * WIDTH - drop, 6) if start is not None else None,
            "no_1s_window_before_recovery": start is None,
            "threshold_violations_before_recovery": sum(buckets[i]["bad"] for i in bad),
            "buckets_with_violations_before_recovery": len(bad),
            "missing_or_empty_buckets_before_recovery": len(missing),
            "violation_buckets_after_first_window": len(following),
            "first_recurrence_delay_s": round(following[0] * WIDTH - drop, 6) if following else None,
            "last_violation_bucket_end_delay_s": round((bad[-1] + 1) * WIDTH - drop, 6) if bad else None,
            "fully_observed_final_drained_interval_start_delay_s": round(final * WIDTH - drop, 6) if final is not None else None}


def analyze_run(path, version, mode, repetition):
    summary = json.loads((path / "summary.json").read_text())
    manifest = json.loads((path / "manifest.json").read_text())
    source = rows(path / "source.jsonl")
    start = next(row for row in source if row["kind"] == "start")
    start_ns = manifest["start_mono_ns"]
    changes = {item["phase"]: (item["mono_ns"] - start_ns) / 1e9 for item in manifest["phase_changes"]}
    drop, recovery = changes[1], changes[2]
    capacity = manifest["arguments"]["low_kbit"] * 1000 // 8
    trace_path = path / "trace.jsonl.gz"
    if not trace_path.exists():
        trace_path = path / "trace.jsonl"
    events = rows(trace_path)
    event_time = lambda event: (event["drained_mono_ns"] - start_ns) / 1e9
    low = [event for event in events if drop <= event_time(event) < recovery]
    first_under = next((event for event in low if event["rate_after_Bps"] <= capacity), None)
    before_drop = [event for event in events if event_time(event) < drop]
    if before_drop and before_drop[-1]["rate_after_Bps"] <= capacity:
        first_rate_delay = 0.0
    else:
        first_rate_delay = round(event_time(first_under) - drop, 6) if first_under else None
    member_buckets, last_epoch = {}, {}
    for event in events:
        if event["type"] != 4 or "sample_context" not in event:
            continue
        context, member = event["sample_context"], event["member"]
        epoch = context["rtt_epoch"]
        fresh = epoch > last_epoch.get(member, 0)
        last_epoch[member] = max(epoch, last_epoch.get(member, 0))
        sample_at = context["rtt_at_ms"]
        if (not fresh or context["rtt_flags"] & 3 != 3 or context["rtt_flags"] & 4 or
                sample_at <= 0 or sample_at > event["now_wall_ms"] or
                event["now_wall_ms"] - sample_at > 1000 or event["feedback"]["latest_rtt_ms"] <= 0):
            continue
        index = (event["drained_mono_ns"] - start_ns) // 100000000
        bucket = member_buckets.setdefault(member, {}).setdefault(index, {"count": 0, "bad": 0, "complete": True})
        bucket["count"] += 1
        bucket["bad"] += event["feedback"]["latest_rtt_ms"] > 100
    expected_members = sorted(member_buckets)
    group_buckets = {}
    for index in range(math.ceil(drop / WIDTH), math.floor(recovery / WIDTH)):
        available = [member_buckets[member].get(index) for member in expected_members]
        if len(available) == 2 and all(item and item["count"] for item in available):
            group_buckets[index] = {"count": sum(item["count"] for item in available),
                                    "bad": sum(item["bad"] for item in available), "complete": True}
        else:
            # Preserve known violations even when another member lacks data.
            group_buckets[index] = {"count": 0, "bad": sum(item["bad"] for item in available if item), "complete": False}
    qdisc = rows(path / "qdisc.jsonl")
    leaf = lambda row: next(q for q in row["source_qdisc"] if q["kind"] == "netem")
    source_summary = summary["roles"]["source"]
    last = source_summary["last_sample"]
    result = {"version": version, "mode": mode, "repetition": repetition, "path": str(path),
              "completed": manifest["completed"], "actual_drop_s": drop, "actual_recovery_s": recovery,
              "low_capacity_Bps": capacity, "first_rate_at_or_below_capacity_delay_s": first_rate_delay,
              "fresh_valid_rtt_group_drain": sustained(group_buckets, drop, recovery),
              "fresh_valid_rtt_members": {str(member): sustained(buckets, drop, recovery) for member, buckets in member_buckets.items()},
              "source_process_cpu_s": last["cpu_s"], "source_physical_bytes": last["physical_bytes"],
              "source_admitted_objects": last["admitted_objects"], "source_offered_objects": last["offered_objects"],
              "application_overload_objects": last["application_overload_objects"],
              "source_final_queued_packets": last["queued_packets"], "source_qdisc_drops": leaf(qdisc[-1])["drops"] - leaf(qdisc[0])["drops"],
              "source_native_packets": last["native_packets"], "fallbacks": last["fallbacks"],
              "trace_overwritten": last["trace_overwritten"], "source_health": source_summary["health"],
              "ceiling_eligible_feedback": sum(e["type"] == 4 and bool(e["after"].get("delivery_ceiling_eligible")) for e in low),
              "ceiling_eligible_pre_cut_feedback": sum(e["type"] == 4 and bool(e["after"].get("delivery_ceiling_eligible")) and not e["after"].get("delivery_sample_post_cut") for e in low),
              "feedback_reduction_reasons": dict(Counter(e["reason"] for e in low if e["type"] == 4 and e["rate_after_Bps"] < e["rate_before_Bps"])),
              "receivers": {}, "phases": [], "source_hashes": manifest["source_hashes"]}
    for receiver in ("receiver1", "receiver2"):
        receiver_rows = rows(path / (receiver + ".jsonl"))
        buckets = {round(row["begin_s"] / WIDTH): {"count": row["objects"], "bad": row["over_100ms"], "complete": row["complete"]}
                   for row in receiver_rows if row["kind"] == "arrival_latency_bucket"}
        info = summary["roles"][receiver]
        delivered = info["last_sample"]["received_objects"]
        result["receivers"][receiver] = {"delivered_objects": delivered,
            "undelivered_admitted_objects_after_drain": last["admitted_objects"] - delivered,
            "undelivered_admitted_fraction_after_drain": 1 - delivered / last["admitted_objects"] if last["admitted_objects"] else None,
            "process_cpu_s": info["last_sample"]["cpu_s"], "health": info["health"],
            "arrival_max_based_drain": sustained(buckets, drop, recovery) if buckets else None}
    for index, phase in enumerate(source_summary["phases"]):
        result["phases"].append({"phase": phase["phase"], "segment": phase["segment"],
            "physical_Bps": phase["physical_submitted_Bps"], "offered_Bps": phase["offered_Bps"],
            "admitted_Bps": phase["admitted_Bps"], "source_cpu_core_fraction": phase["cpu_core_fraction"],
            "receivers": {receiver: {"goodput_Bps": summary["roles"][receiver]["phases"][index]["goodput_Bps"],
                "delivered_latency": summary["roles"][receiver]["phases"][index]["delivered_latency"]}
                for receiver in ("receiver1", "receiver2")}})
    return result


def spread(values):
    present = [value for value in values if value is not None]
    return {"observed": len(present), "missing_or_censored": len(values) - len(present),
            "min": min(present) if present else None, "median": statistics.median(present) if present else None,
            "max": max(present) if present else None}


def aggregate(runs):
    groups, identity = {}, {}
    for version in ("baseline", "candidate"):
        version_runs = [run for run in runs if run["version"] == version]
        if not version_runs:
            continue
        first = version_runs[0]["source_hashes"]
        identity[version] = {"all_recorded_source_binary_hashes_identical": all(run["source_hashes"] == first for run in version_runs),
                             "binary_sha256": first["t/00util/flexicast_network_probe"],
                             "probe_sha256": first["t/00util/flexicast_network_probe.c"],
                             "script_sha256": first["scripts/flexicast_network_measure.py"]}
        for mode in ("native", "replica"):
            matched = [run for run in version_runs if run["mode"] == mode]
            if not matched:
                continue
            groups[version + "-" + mode] = {"n": len(matched),
                "rate_response_delay_s": spread([r["first_rate_at_or_below_capacity_delay_s"] for r in matched]),
                "rtt_group_drain_start_delay_s": spread([r["fresh_valid_rtt_group_drain"]["first_1s_window_start_delay_s"] for r in matched]),
                "source_qdisc_drops": spread([r["source_qdisc_drops"] for r in matched]),
                "source_process_cpu_s": spread([r["source_process_cpu_s"] for r in matched]),
                "arrival_drain_start_delay_s": {receiver: spread([r["receivers"][receiver]["arrival_max_based_drain"]["first_1s_window_start_delay_s"]
                    if r["receivers"][receiver]["arrival_max_based_drain"] else None for r in matched]) for receiver in ("receiver1", "receiver2")},
                "phases": [{"phase": index // 2, "segment": "steady" if index % 2 else "transient",
                    "physical_Bps": spread([r["phases"][index]["physical_Bps"] for r in matched]),
                    "receivers": {receiver: {
                        "goodput_Bps": spread([r["phases"][index]["receivers"][receiver]["goodput_Bps"] for r in matched]),
                        "p99_ms": spread([r["phases"][index]["receivers"][receiver]["delivered_latency"]["p99_upper_ms"] for r in matched])}
                        for receiver in ("receiver1", "receiver2")}} for index in range(6)]}
    if all(version in identity for version in ("baseline", "candidate")):
        identity["cross_revision_harness_identical"] = all(identity["baseline"][key] == identity["candidate"][key] for key in ("probe_sha256", "script_sha256"))
    paired = []
    for mode in ("native", "replica"):
        for repetition in sorted({run["repetition"] for run in runs}):
            pair = {run["version"]: run for run in runs if run["mode"] == mode and run["repetition"] == repetition}
            if len(pair) != 2:
                continue
            b, c = pair["baseline"], pair["candidate"]
            diff = lambda key: c[key] - b[key] if c[key] is not None and b[key] is not None else None
            paired.append({"mode": mode, "repetition": repetition,
                           "candidate_minus_baseline_rate_delay_s": diff("first_rate_at_or_below_capacity_delay_s"),
                           "candidate_minus_baseline_qdisc_drops": diff("source_qdisc_drops"),
                           "candidate_minus_baseline_source_cpu_s": diff("source_process_cpu_s")})
    return groups, identity, paired


def analyze(args):
    runs = [analyze_run(*item) for item in run_paths(args.input)]
    groups, identity, paired = aggregate(runs)
    for run in runs:
        del run["source_hashes"]
    result = {"schema": 1, "definitions": {
        "rate_response": "First observed controller output at or below the configured low-link capacity, relative to actual tc class-change completion. Observations use trace drain monotonic timestamps.",
        "rtt_drain": "First 1 s window of ten full 100 ms buckets, each containing a fresh VALID RTT sample from each of 2 members, with no eligible sample over 100 ms. Both retrospective window start and confirmation time are reported.",
        "application_drain": "Strict observed maximum-based proxy, not p99: first 1 s window of ten populated complete 100 ms arrival buckets with zero delivered object latencies over 100 ms, per receiver. Lost/unreceived objects are excluded.",
        "recurrence": "Violations after the first passing 1 s window are counted separately until actual link recovery; final uninterrupted observed drain is also reported.",
        "time_resolution": "Only complete 100 ms buckets entirely between actual drop and recovery are eligible; up to 100 ms at each boundary is excluded. Phase p50/p99 remain grouped by nominal emission phase and transient/steady segment.",
        "rate_and_cpu": "Phase rates interpolate cumulative 1 s samples; physical means kernel UDP submission. CPU is getrusage user+system process time including instrumentation/drain, not an isolated CPU optimization claim.",
        "repetitions": "Report all serial matched runs, medians and ranges; no statistical significance claim."},
        "groups": groups, "paired_differences": paired, "hash_identity": identity, "runs": runs}
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")
    if args.output:
        print(json.dumps({"runs": len(runs), "output": str(args.output), "groups": {name: {
            "n": group["n"], "rate_delay": group["rate_response_delay_s"], "drops": group["source_qdisc_drops"]}
            for name, group in groups.items()}}))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("plan", "run", "collect", "analyze"))
    parser.add_argument("--input", type=Path, default=Path("/tmp"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--baseline-tree", type=Path)
    parser.add_argument("--candidate-tree", type=Path)
    parser.add_argument("--repetitions", type=int, default=5)
    args = parser.parse_args()
    if args.command in ("plan", "run"):
        if not args.baseline_tree or not args.candidate_tree or not 1 <= args.repetitions <= 100:
            parser.error("run/plan requires both source trees and 1..100 repetitions")
        run(args)
    elif args.command == "collect":
        if not args.output:
            parser.error("collect requires --output directory")
        collect(args)
    else:
        analyze(args)


if __name__ == "__main__":
    main()
