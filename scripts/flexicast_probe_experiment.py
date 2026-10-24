#!/usr/bin/env python3
"""Serial matched probe or drain experiment with an extended low-capacity plateau.

The immutable six original emission windows are retained; low 8--30 s is a
separate seventh window. Measurements may start only after the caller freezes
both builds. Analysis reuses the committed ceiling experiment's raw readers and
initial drain calculation without changing that historical evidence.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import time

import flexicast_ceiling_experiment as common

RUN_NAME = re.compile(r"(?:flexicast-(probe|drain)-)?(baseline|candidate)-(native|replica)-(\d+)")
HIGH_SECONDS = 8.0
LOW_SECONDS = 30.0
TRANSIENT_SECONDS = 2.0
RECOVERY_THRESHOLD_BPS = 450000
FROZEN_FILES = (
    "deps/quicly/include/quicly/flexicast_cc.h",
    "deps/quicly/lib/flexicast_cc_adaptive.c",
    "deps/quicly/t/flexicast-adaptive-context.inc",
    "t/00util/flexicast_network_probe.c",
    "t/00util/flexicast_network_probe",
    "scripts/flexicast_network_measure.py",
    "scripts/flexicast_ceiling_experiment.py",
    "scripts/flexicast_probe_experiment.py",
)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def hashes(tree):
    return {name: hashlib.sha256((tree / name).read_bytes()).hexdigest() for name in FROZEN_FILES}


def sequence_path(directory, experiment):
    """Select one experiment's raw or collected record, never mix series."""
    raw = directory / f"flexicast-{experiment}-sequence.json"
    other = "drain" if experiment == "probe" else "probe"
    if (directory / f"flexicast-{other}-sequence.json").exists():
        raise SystemExit("input contains a different experiment sequence; select --experiment " + other)
    collected = directory / "sequence.json"
    if raw.exists() and collected.exists():
        raise SystemExit("input contains both raw and collected sequence records")
    path = collected if collected.exists() else raw
    if path.exists():
        state = json.loads(path.read_text())
        # Historical collected records predate this field and are probe runs.
        declared = state.get("experiment", "probe" if path == collected else experiment)
        if declared != experiment:
            raise SystemExit("sequence experiment does not match --experiment " + experiment)
    return path


def run_paths(directory, experiment="probe"):
    sequence_path(directory, experiment)
    for path in sorted(directory.iterdir()):
        match = RUN_NAME.fullmatch(path.name)
        if path.is_dir() and match:
            if match.group(1) is not None and match.group(1) != experiment:
                raise SystemExit("input contains mixed or different experiment runs; select --experiment " + match.group(1))
            if (path / "summary.json").exists():
                yield path, match.group(2), match.group(3), int(match.group(4))


def sequence(args):
    for repetition in range(1, args.repetitions + 1):
        versions = ("baseline", "candidate") if repetition % 2 else ("candidate", "baseline")
        modes = ("native", "replica") if repetition % 2 else ("replica", "native")
        for mode in modes:
            for version in versions:
                tree = getattr(args, version + "_tree").resolve()
                output = args.input.resolve() / f"flexicast-{args.experiment}-{version}-{mode}-{repetition}"
                yield {"version": version, "mode": mode, "repetition": repetition,
                       "tree": str(tree), "output": str(output),
                       "argv": ["python3", "scripts/flexicast_network_measure.py", "--mode", mode,
                                "--phase-seconds", "8", "--low-phase-seconds", "30",
                                "--transient-seconds", "2", "--output", str(output),
                                "--label", f"{args.experiment}-{version}-{mode}-{repetition}"]}


def run(args):
    planned = list(sequence(args))
    if args.command == "plan":
        print(json.dumps(planned, indent=2))
        return
    log_path = sequence_path(args.input, args.experiment)
    existing_runs = args.input.exists() and any(path.is_dir() and RUN_NAME.fullmatch(path.name) for path in args.input.iterdir())
    if log_path.exists() or existing_runs or any(Path(item["output"]).exists() for item in planned):
        raise SystemExit("output or sequence exists; use a new directory rather than replacing a run")
    args.input.mkdir(parents=True, exist_ok=True)
    frozen = {version: hashes(getattr(args, version + "_tree").resolve()) for version in ("baseline", "candidate")}
    harness = [name for name in FROZEN_FILES if name.startswith("scripts/") or name.endswith("flexicast_network_probe.c")]
    if any(frozen["baseline"][name] != frozen["candidate"][name] for name in harness):
        raise SystemExit("baseline and candidate observational harness sources differ")
    state = {"schema": 1, "experiment": args.experiment, "phase_seconds": [8, 30, 8], "order": planned,
             "frozen_source_binary_hashes": frozen, "completed": []}
    write_json(log_path, state)
    for index, item in enumerate(planned, 1):
        tree = Path(item["tree"])
        if hashes(tree) != frozen[item["version"]]:
            raise SystemExit("frozen source/binary changed before run " + str(index))
        print(json.dumps({"event": "starting", "index": index, "total": len(planned), **item}), flush=True)
        began = time.monotonic_ns()
        result = subprocess.run(item["argv"], cwd=tree)
        unchanged = hashes(tree) == frozen[item["version"]]
        state["completed"].append({"index": index, "version": item["version"], "mode": item["mode"],
                                   "repetition": item["repetition"], "returncode": result.returncode,
                                   "started_mono_ns": began, "finished_mono_ns": time.monotonic_ns(),
                                   "frozen_source_binary_unchanged": unchanged})
        write_json(log_path, state)
        print(json.dumps({"event": "completed", "index": index, "total": len(planned),
                          "version": item["version"], "mode": item["mode"], "repetition": item["repetition"],
                          "returncode": result.returncode, "frozen_source_binary_unchanged": unchanged}), flush=True)
        if result.returncode or not unchanged:
            raise SystemExit(result.returncode or 1)


def collect(args):
    # Preserve documentation/freeze metadata while refusing to replace runs.
    sources = list(run_paths(args.input, args.experiment))
    if args.output.exists() and (any(RUN_NAME.fullmatch(item.name) for item in args.output.iterdir()) or
                                 (args.output / "sequence.json").exists()):
        raise SystemExit("collection destination already contains experiment runs or a sequence")
    args.output.mkdir(parents=True, exist_ok=True)
    copied = []
    for path, version, mode, repetition in sources:
        dest = args.output / f"{version}-{mode}-{repetition}"
        dest.mkdir()
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
    record = sequence_path(args.input, args.experiment)
    if record.exists():
        shutil.copyfile(record, args.output / "sequence.json")
    print(json.dumps({"collected": copied, "output": str(args.output)}))


def controller_recovery(events, start_ns, recovery, production_end, threshold=RECOVERY_THRESHOLD_BPS):
    """Observe a >=1 s state interval, requiring trace coverage to confirm it.

    Controller output persists until the next recorded output. Use monotonic
    trace-drain observations, not fictitious exact wire or decision timestamps.
    A post-production trace event can confirm state through production_end but
    cannot extend the eligible window beyond production_end.
    """
    active_start = None
    prior_rate = None
    last_observed = None
    answer = {"threshold_Bps": threshold, "required_interval_s": 1.0,
              "production_end_s": production_end, "start_delay_s": None,
              "confirmed_delay_s": None, "confirmation_observed_delay_s": None,
              "missing_or_censored": True, "status": "unconfirmed_before_production_end",
              "trace_observed_through_delay_s": None}
    for event in events:
        at = (event["drained_mono_ns"] - start_ns) / 1e9
        if last_observed is not None and at < last_observed:
            raise ValueError("trace observation timestamps moved backwards")
        last_observed = at
        if at < recovery:
            prior_rate = event["rate_after_Bps"]
            continue
        if prior_rate is not None and active_start is None and prior_rate >= threshold:
            active_start = recovery
        boundary = min(at, production_end)
        if active_start is not None and boundary - active_start >= 1.0:
            answer.update(start_delay_s=round(active_start - recovery, 6),
                          confirmed_delay_s=round(active_start + 1.0 - recovery, 6),
                          confirmation_observed_delay_s=round(at - recovery, 6), missing_or_censored=False, status="confirmed")
            break
        if at >= production_end:
            break
        prior_rate = None  # the pre-recovery state must never reinitialize a later window
        if event["rate_after_Bps"] < threshold:
            active_start = None
        elif active_start is None:
            active_start = at
    if last_observed is not None:
        answer["trace_observed_through_delay_s"] = round(min(last_observed, production_end) - recovery, 6)
    return answer


def delivered_intervals(samples, recovery, production_end):
    """Non-overlapping full intervals >=1 s, bounded by actual counter samples.

    Do not interpolate a subsecond sample to invent a full observation. If the
    next sample is just short of one second, extend to the following sample.
    Durations are recorded; two qualifying intervals need not be exactly 2 s.
    """
    observed = [sample for sample in samples if recovery <= sample["elapsed_s"] <= production_end]
    result, begin = [], 0
    for end in range(1, len(observed)):
        left, right = observed[begin], observed[end]
        duration = right["elapsed_s"] - left["elapsed_s"]
        if duration < 1.0:
            continue
        delta = right["received_bytes"] - left["received_bytes"]
        if delta < 0:
            raise ValueError("delivered byte counter moved backwards")
        result.append({"start_delay_s": round(left["elapsed_s"] - recovery, 9),
                       "end_delay_s": round(right["elapsed_s"] - recovery, 9),
                       "duration_s": duration, "delivered_bytes": delta,
                       "delivered_Bps": delta / duration})
        begin = end
    return result


def delivered_recovery(intervals, reference):
    threshold = reference * 0.9
    answer = {"paired_baseline_initial_steady_Bps": reference, "threshold_Bps": threshold,
              "required_consecutive_intervals": 2, "minimum_each_interval_s": 1.0,
              "start_delay_s": None, "confirmed_delay_s": None, "observed_duration_s": None,
              "qualifying_interval_durations_s": None, "missing_or_censored": True,
              "status": "unconfirmed_before_production_end", "intervals": intervals}
    for left, right in zip(intervals, intervals[1:]):
        if reference > 0 and left["delivered_Bps"] >= threshold and right["delivered_Bps"] >= threshold:
            answer.update(start_delay_s=left["start_delay_s"], confirmed_delay_s=right["end_delay_s"],
                          observed_duration_s=left["duration_s"] + right["duration_s"],
                          qualifying_interval_durations_s=[left["duration_s"], right["duration_s"]],
                          missing_or_censored=False, status="confirmed")
            break
    return answer


def region_counts(buckets, begin, end):
    first = math.ceil((begin - 1e-9) / common.WIDTH)
    stop = math.floor((end + 1e-9) / common.WIDTH)
    selected = [buckets.get(index) for index in range(first, stop)]
    complete = [bucket for bucket in selected if bucket and bucket["complete"]]
    count = sum(bucket["count"] for bucket in complete)
    bad = sum(bucket["bad"] for bucket in complete)
    return {"begin_s": begin, "end_s": end, "full_buckets": len(selected),
            "complete_populated_buckets": sum(bucket["count"] > 0 for bucket in complete),
            "missing_incomplete_or_empty_buckets": sum(not bucket or not bucket["complete"] or not bucket["count"] for bucket in selected),
            "delivered_objects": count, "objects_over_100ms": bad,
            "fraction_over_100ms": bad / count if count else None,
            "buckets_over_100ms": sum(bucket["bad"] > 0 for bucket in complete),
            "maximum_delivered_latency_ms": max((bucket["max_ms"] for bucket in complete if bucket["count"]), default=None)}


def analyze_run(path, version, mode, repetition):
    result = common.analyze_run(path, version, mode, repetition)
    manifest = json.loads((path / "manifest.json").read_text())
    summary = json.loads((path / "summary.json").read_text())
    arguments = manifest["arguments"]
    high = arguments["phase_seconds"]
    low = arguments.get("low_phase_seconds", high)
    if (high, low, arguments["transient_seconds"]) != (HIGH_SECONDS, LOW_SECONDS, TRANSIENT_SECONDS):
        raise ValueError("unexpected experiment windows: " + str(path))
    expected_phases = [(0, "transient"), (0, "steady"), (1, "transient"), (1, "steady"),
                       (2, "transient"), (2, "steady"), (1, "late")]
    if [(item["phase"], item["segment"]) for item in result["phases"]] != expected_phases:
        raise ValueError("original six windows or seventh late window changed: " + str(path))
    expected_windows = [(0, 2), (2, 8), (8, 10), (10, 16), (38, 40), (40, 46), (16, 38)]
    for role in ("source", "receiver1", "receiver2"):
        for index, (begin, end) in enumerate(expected_windows):
            phase = summary["roles"][role]["phases"][index]
            if (phase["begin_s"], phase["end_s"], phase["duration_s"]) != (begin, end, end - begin):
                raise ValueError("measurement-window bounds changed: " + str(path))
    for phase, (begin, end) in zip(result["phases"], expected_windows):
        phase.update(begin_s=begin, end_s=end, duration_s=end - begin)
    start_ns = manifest["start_mono_ns"]
    drop, recovery = result["actual_drop_s"], result["actual_recovery_s"]
    production_end = high * 2 + low
    result["production_end_s"] = production_end
    trace_path = path / "trace.jsonl.gz"
    events = common.rows(trace_path if trace_path.exists() else path / "trace.jsonl")
    result["controller_recovery"] = controller_recovery(events, start_ns, recovery, production_end)
    result["manifest_returncodes"] = manifest["returncodes"]
    result["arrival_bucket_counts_match"] = {}
    for receiver in ("receiver1", "receiver2"):
        raw = common.rows(path / (receiver + ".jsonl"))
        arrivals = [item for item in raw if item["kind"] == "arrival_latency_bucket"]
        buckets = {round(item["begin_s"] / common.WIDTH):
                   {"count": item["objects"], "bad": item["over_100ms"], "complete": item["complete"],
                    "max_ms": item["max_latency_ms"]} for item in arrivals}
        info = result["receivers"][receiver]
        info["initial_8s_arrival_drain"] = common.sustained(buckets, drop, min(drop + high, recovery))
        info["late_arrival"] = region_counts(buckets, drop + high, recovery)
        info["late_arrival_drain"] = common.sustained(buckets, drop + high, recovery)
        info["recovery_intervals"] = delivered_intervals([item for item in raw if item["kind"] == "sample"],
                                                        recovery, production_end)
        result["arrival_bucket_counts_match"][receiver] = sum(item["objects"] for item in arrivals) == info["delivered_objects"]
    qdisc = common.rows(path / "qdisc.jsonl")
    snapshots = [item for item in qdisc if drop + high <= item["elapsed_s"] < recovery]
    leaf_drops = lambda item: next(entry["drops"] for entry in item["source_qdisc"] if entry["kind"] == "netem")
    result["late_qdisc_observations"] = {"first_snapshot_s": snapshots[0]["elapsed_s"] if snapshots else None,
        "last_snapshot_s": snapshots[-1]["elapsed_s"] if snapshots else None,
        "leaf_drop_delta": leaf_drops(snapshots[-1]) - leaf_drops(snapshots[0]) if len(snapshots) >= 2 else None,
        "missing_or_censored": len(snapshots) < 2}
    return result


def phase_key(phase):
    return phase["phase"], phase["segment"]


def aggregate(runs):
    # The inherited identity/paired analysis is unchanged; replace only its
    # six-window group summaries with explicit keys, including the seventh.
    groups, identity, paired = common.aggregate(runs)
    by_key = {(run["version"], run["mode"], run["repetition"]): run for run in runs}
    for run in runs:
        baseline = by_key.get(("baseline", run["mode"], run["repetition"]))
        for receiver, info in run["receivers"].items():
            reference = next(phase for phase in baseline["phases"] if phase_key(phase) == (0, "steady"))["receivers"][receiver]["goodput_Bps"] if baseline else 0
            info["delivered_recovery"] = delivered_recovery(info.pop("recovery_intervals"), reference)
            info["delivered_recovery"]["paired_baseline_missing"] = baseline is None
    for name, group in groups.items():
        matched = sorted([run for run in runs if run["version"] + "-" + run["mode"] == name], key=lambda r: r["repetition"])
        group["controller_recovery_start_delay_s"] = common.spread([r["controller_recovery"]["start_delay_s"] for r in matched])
        group["controller_recovery_confirmed_delay_s"] = common.spread([r["controller_recovery"]["confirmed_delay_s"] for r in matched])
        group["late_qdisc_observed_drop_delta"] = common.spread([r["late_qdisc_observations"]["leaf_drop_delta"] for r in matched])
        group["any_receiver_late_violation_runs"] = sum(any(info["late_arrival"]["objects_over_100ms"] for info in r["receivers"].values()) for r in matched)
        group["any_receiver_recurrence_runs"] = sum(any(info["arrival_max_based_drain"]["violation_buckets_after_first_window"] for info in r["receivers"].values()) for r in matched)
        group["source_admitted_objects"] = common.spread([r["source_admitted_objects"] for r in matched])
        group["application_overload_objects"] = common.spread([r["application_overload_objects"] for r in matched])
        group["worst_receiver_unreceived_fraction"] = common.spread([max(info["undelivered_admitted_fraction_after_drain"] for info in r["receivers"].values()) for r in matched])
        group["phases"] = []
        for key in map(phase_key, matched[0]["phases"]):
            phases = [next(phase for phase in run["phases"] if phase_key(phase) == key) for run in matched]
            p99 = [max(info["delivered_latency"]["p99_upper_ms"] for info in phase["receivers"].values()) for phase in phases]
            goodput = [statistics.mean(info["goodput_Bps"] for info in phase["receivers"].values()) for phase in phases]
            group["phases"].append({"phase": key[0], "segment": key[1],
                "worst_receiver_p99_ms": common.spread(p99), "worst_receiver_p99_by_repetition_ms": p99,
                "mean_receiver_goodput_Bps": common.spread(goodput), "mean_receiver_goodput_by_repetition_Bps": goodput,
                "physical_Bps": common.spread([phase["physical_Bps"] for phase in phases])})
        group["receivers"] = {}
        for receiver in ("receiver1", "receiver2"):
            group["receivers"][receiver] = {
                "delivered_recovery_start_delay_s": common.spread([r["receivers"][receiver]["delivered_recovery"]["start_delay_s"] for r in matched]),
                "delivered_recovery_confirmed_delay_s": common.spread([r["receivers"][receiver]["delivered_recovery"]["confirmed_delay_s"] for r in matched]),
                "late_objects_over_100ms": common.spread([r["receivers"][receiver]["late_arrival"]["objects_over_100ms"] for r in matched]),
                "late_fraction_over_100ms": common.spread([r["receivers"][receiver]["late_arrival"]["fraction_over_100ms"] for r in matched]),
                "late_buckets_over_100ms": common.spread([r["receivers"][receiver]["late_arrival"]["buckets_over_100ms"] for r in matched])}
    for pair in paired:
        baseline = by_key[("baseline", pair["mode"], pair["repetition"])]
        candidate = by_key[("candidate", pair["mode"], pair["repetition"])]
        diff = lambda key: candidate["controller_recovery"][key] - baseline["controller_recovery"][key] if candidate["controller_recovery"][key] is not None and baseline["controller_recovery"][key] is not None else None
        pair["candidate_minus_baseline_controller_recovery_start_s"] = diff("start_delay_s")
        pair["controller_recovery_censored"] = {r["version"]: r["controller_recovery"]["missing_or_censored"] for r in (baseline, candidate)}
    return groups, identity, paired


def health_audit(runs, identity, sequence_state, repetitions):
    failures, detail = [], []
    expect = {(version, mode, i) for version in ("baseline", "candidate") for mode in ("native", "replica") for i in range(1, repetitions + 1)}
    actual = {(r["version"], r["mode"], r["repetition"]) for r in runs}
    if actual != expect or len(runs) != len(expect):
        failures.append("missing, duplicate or unexpected runs")
    for version in ("baseline", "candidate"):
        if not identity.get(version, {}).get("all_recorded_source_binary_hashes_identical"):
            failures.append(version + " source/binary hashes changed")
    if not identity.get("cross_revision_harness_identical"):
        failures.append("probe/wrapper sources differ between versions")
    for r in runs:
        name = f'{r["version"]}-{r["mode"]}-{r["repetition"]}'
        issues = []
        if not r["completed"] or any(r["manifest_returncodes"]): issues.append("incomplete or endpoint failure")
        if r["fallbacks"] or r["trace_overwritten"] or r["source_final_queued_packets"]: issues.append("fallback/trace loss/undrained transport")
        if r["source_health"]["max_queued_packets"] > 2: issues.append("transport backlog exceeded two packets")
        if any(r["source_health"].get(key, 0) for key in ("duplicates", "malformed", "arrival_bucket_overflow")):
            issues.append("source health failure")
        if (r["mode"] == "native") != bool(r["source_native_packets"]): issues.append("native/replicated path mismatch")
        for receiver, info in r["receivers"].items():
            if any(info["health"].get(key, 0) for key in ("duplicates", "malformed", "arrival_bucket_overflow")):
                issues.append(receiver + " health failure")
            if not r["arrival_bucket_counts_match"][receiver]: issues.append(receiver + " arrival counts differ")
            for phase in r["phases"]:
                latency = phase["receivers"][receiver]["delivered_latency"]
                if latency["objects"] <= 0:
                    issues.append(f"{receiver} empty delivered latency cohort: phase {phase['phase']} {phase['segment']}")
                if latency["overflow_over_20000ms"]:
                    issues.append(receiver + " latency histogram overflow")
        failures.extend(name + ": " + issue for issue in issues)
        detail.append({"run": name, "completed": r["completed"], "issues": issues})
    if sequence_state is None:
        failures.append("sequence record missing")
    else:
        completed = sequence_state["completed"]
        if len(completed) != len(expect) or any(item["returncode"] or not item["frozen_source_binary_unchanged"] for item in completed):
            failures.append("sequence incomplete, failed or frozen hashes changed")
        if any(left["finished_mono_ns"] > right["started_mono_ns"] for left, right in zip(completed, completed[1:])):
            failures.append("runs overlapped")
    return {"all_pass": not failures, "failures": failures, "runs": len(runs), "per_run": detail,
            "recorded_hash_identity": identity}


def analyze(args):
    runs = [analyze_run(*item) for item in run_paths(args.input, args.experiment)]
    groups, identity, paired = aggregate(runs)
    record = sequence_path(args.input, args.experiment)
    sequence_state = json.loads(record.read_text()) if record.exists() else None
    audit = health_audit(runs, identity, sequence_state, args.repetitions)
    for run in runs:
        del run["source_hashes"]
    result = {"schema": 1, "experiment": args.experiment, "definitions": {
        "phases": "Nominal emission windows: original high0-2/high2-8, low0-2/low2-8, recovery0-2/recovery2-8 unchanged; low8-30 is a separate seventh late window.",
        "phase_rates": "Rates interpolate cumulative approximately1s samples at nominal window boundaries; latency follows emission cohorts, not arrival windows. Worst-receiver p99 and mean-receiver goodput are aggregated per run before five-run medians/ranges.",
        "initial_drain": "Same strict maximum-based proxy as ceiling experiment:10 populated full100ms arrival buckets with no delivered object over100ms; first8s drain retained separately from whole30s plateau. Not rolling p99; missing/empty buckets never imply clearance.",
        "late_arrival": "Full100ms arrival buckets from actual drop+8s to actual recovery; distinct from nominal-emission low8-30 latency. All later violations and recurrence after first clear window remain counted.",
        "late_qdisc": "Netem leaf drop delta between first and last captured snapshots wholly inside late arrival interval; exact snapshot times retained. Whole-run drops remain primary.",
        "controller_recovery": "Fixed450000B/s threshold (90% of nominal4Mbit/s), independent of candidate initial throughput. First uninterrupted>=1s trace-observed output-state interval after actual recovery, with trace coverage through confirmation and before nominal production end. Drain timestamps are observation times, not exact send times.",
        "delivered_recovery": "Each version uses90% of the same matched baseline receiver's initial2-8s goodput. Requires two consecutive nonoverlapping intervals, each>=1s, from actual cumulative delivery observations wholly after actual recovery and before production end. These are interval-average rates, not continuous recovery; actual durations/confirmation recorded. Subsecond intervals extend to the next observation. Missing qualifying intervals remain censored. Original recovery0-2/2-8 goodput is primary.",
        "accounting": "Latency excludes application overload and admitted objects never received; both remain counted. Process CPU includes instrumentation and drain and is not a5Gbps CPU result.",
        "repetitions": "Five serial matched repetitions per mode/version with alternating order. All observations and medians/ranges retained; no significance claim."},
        "groups": groups, "paired_differences": paired, "hash_identity": identity, "health_audit": audit, "runs": runs}
    if args.output:
        write_json(args.output, result)
        write_json(args.output.with_name("health-hash-audit.json"), audit)
        print(json.dumps({"runs": len(runs), "all_pass": audit["all_pass"], "failures": audit["failures"], "output": str(args.output)}))
    else:
        print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "run", "collect", "analyze"))
    parser.add_argument("--experiment", choices=("probe", "drain"), default="probe")
    parser.add_argument("--input", type=Path, default=Path("/tmp/flexicast-probe-runs-20261014"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--baseline-tree", type=Path)
    parser.add_argument("--candidate-tree", type=Path)
    parser.add_argument("--repetitions", type=int, default=5)
    args = parser.parse_args()
    if not 1 <= args.repetitions <= 100:
        parser.error("repetitions must be1..100")
    if args.command in ("plan", "run"):
        if not args.baseline_tree or not args.candidate_tree:
            parser.error("run/plan requires both trees")
        run(args)
    elif args.command == "collect":
        if not args.output:
            parser.error("collect requires output directory")
        collect(args)
    else:
        analyze(args)


if __name__ == "__main__":
    main()
