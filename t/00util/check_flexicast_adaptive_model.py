#!/usr/bin/env python3
"""Compile the same fluid model against pinned and current adaptive controllers.

All binaries and raw CSV files live in a temporary directory. The optional
--summary argument saves only the compact, checked JSON evidence.
"""

import argparse
import csv
import json
import math
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

BASELINE_COMMIT = "564c6d5d20903104144d4351f88c9c1b68dea0ad"
CONTROLLER_FILES = (
    "include/quicly/flexicast_cc.h",
    "lib/flexicast_cc.c",
    "lib/flexicast_cc_adaptive.c",
    "lib/flexicast_cc_internal.h",
    "lib/flexicast_member_map.h",
)
REPOSITORY = Path(__file__).resolve().parents[2]


def baseline_source(explicit_path, work):
    if explicit_path is not None:
        source = explicit_path.resolve()
        if (source / "deps/quicly/lib/flexicast_cc.c").is_file():
            source /= "deps/quicly"
        for name in CONTROLLER_FILES:
            if not (source / name).is_file():
                raise RuntimeError(f"missing baseline file: {source / name}")
        return source

    source = work / "baseline-source"
    for name in CONTROLLER_FILES:
        result = subprocess.run(
            ["git", "-C", str(REPOSITORY / "deps/quicly"), "show",
             f"{BASELINE_COMMIT}:{name}"],
            capture_output=True, check=False, timeout=30,
        )
        if result.returncode:
            raise RuntimeError(
                f"cannot read baseline {BASELINE_COMMIT} from deps/quicly; "
                "use --baseline /path/to/exported/quicly (or its qlinq root)"
            )
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(result.stdout)
    return source


def run_model(compiler, controller, version, work):
    executable = work / f"adaptive-model-{version}"
    subprocess.run(
        compiler + [
            "-std=c11", "-O2", "-Wall", "-Wextra",
            "-I", str(controller / "include"),
            str(REPOSITORY / "t/00util/test_flexicast_adaptive_model.c"),
            str(controller / "lib/flexicast_cc.c"),
            str(controller / "lib/flexicast_cc_adaptive.c"),
            "-lm", "-o", str(executable),
        ],
        check=True, timeout=60,
    )
    raw_csv = work / f"adaptive-model-{version}.csv"
    with raw_csv.open("w") as output:
        subprocess.run([str(executable)], stdout=output, check=True, timeout=30)

    groups = {}
    with raw_csv.open(newline="") as stream:
        for row in csv.DictReader(stream):
            name = row.pop("scenario")
            groups.setdefault(name, []).append(
                {key: float(value) for key, value in row.items()}
            )
    expected = {"single", "group32", "radio20", "heterogeneous", "repair"}
    if set(groups) != expected or any(len(rows) != 1200 for rows in groups.values()):
        raise RuntimeError(f"incomplete {version} model output")
    return {name: summarize(rows) for name, rows in groups.items()}


def p99_rtt(rows):
    values = sorted(row["rtt_ms"] for row in rows)
    return round(values[math.ceil(0.99 * len(values)) - 1], 2)


def settling_time(rows, start_ms, capacity):
    """First rate in [80%, 115%] of capacity sustained for 20 feedback steps."""
    after = [row for row in rows if row["time_ms"] > start_ms]
    for index, row in enumerate(after):
        sample = after[index:index + 20]
        if len(sample) == 20 and all(
            0.8 * capacity <= point["next_rate_Bps"] <= 1.15 * capacity
            for point in sample
        ):
            return round((row["time_ms"] - start_ms) / 1000, 2)
    return None


def summarize(rows):
    low = [row for row in rows if 5000 < row["time_ms"] <= 30000]
    transient = [row for row in rows if 5000 < row["time_ms"] <= 10000]
    steady = [row for row in rows if 25000 < row["time_ms"] <= 30000]
    recovered = [row for row in rows if 55000 < row["time_ms"] <= 60000]
    return {
        "drop_settling_s": settling_time(
            [row for row in rows if row["time_ms"] <= 30000], 5000, 20000
        ),
        "recovery_settling_s": settling_time(rows, 30000, 100000),
        "drop_transient_rtt_p99_ms": p99_rtt(transient),
        "drop_steady_rtt_p99_ms": p99_rtt(steady),
        "recovered_rtt_p99_ms": p99_rtt(recovered),
        "drop_goodput_Bps": round(sum(row["goodput_Bps"] for row in low) / len(low)),
        "recovered_goodput_Bps": round(
            sum(row["goodput_Bps"] for row in recovered) / len(recovered)
        ),
        "drop_network_loss_pct": round(
            100 * sum(row["dropped_B"] for row in low)
            / sum(row["offered_B"] for row in low), 2
        ),
        "last_low_rate_Bps": round(low[-1]["next_rate_Bps"]),
    }


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def check_results(results):
    fixed = results["fixed"]
    for name, metrics in fixed.items():
        drop = metrics["drop_settling_s"]
        recovery = metrics["recovery_settling_s"]
        require(drop is not None and drop < 3, f"{name}: drop did not settle within 3 s: {metrics}")
        require(recovery is not None and recovery < 8,
                f"{name}: recovery did not settle within 8 s: {metrics}")
        expected_goodput = 16000 if name == "radio20" else 20000
        require(metrics["drop_goodput_Bps"] > 0.8 * expected_goodput,
                f"{name}: useful throughput fell below 80%: {metrics}")
        require(metrics["drop_network_loss_pct"] < 15,
                f"{name}: network loss exceeded 15%: {metrics}")
    require(fixed["single"] == fixed["group32"],
            "correlated group feedback changed model metrics")
    baseline = results["baseline"]["single"]
    require(baseline["drop_settling_s"] is None,
            "the supplied baseline no longer reproduces persistent overload")
    require(fixed["single"]["drop_steady_rtt_p99_ms"] < baseline["drop_steady_rtt_p99_ms"],
            "fixed controller did not reduce steady queue delay")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path,
                        help="exported baseline quicly directory, or its qlinq root")
    parser.add_argument("--summary", type=Path,
                        help="save compact JSON here; raw CSV/binaries stay temporary")
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"),
                        help="C compiler command (default: CC environment variable or cc)")
    args = parser.parse_args()
    compiler = shlex.split(args.cc)
    require(bool(compiler), "empty compiler command")
    with tempfile.TemporaryDirectory(prefix="qlinq-adaptive-model-") as temporary:
        work = Path(temporary)
        baseline = baseline_source(args.baseline, work)
        results = {
            "baseline": run_model(compiler, baseline, "baseline", work),
            "fixed": run_model(compiler, REPOSITORY / "deps/quicly", "fixed", work),
        }
    check_results(results)
    evidence = {
        "schema_version": 1,
        "baseline_quicly_commit": BASELINE_COMMIT,
        "model": {
            "duration_ms": 60000, "feedback_interval_ms": 50,
            "base_rtt_ms": 20, "buffer_capacity_seconds": 1,
            "capacity_Bps": [100000, 20000, 100000],
            "capacity_change_ms": [5000, 30000],
            "controller_feedback_timeout_ms": 1000,
            "settling_rate_fraction": [0.8, 1.15],
            "settling_consecutive_samples": 20,
            "transient_window_ms": [5000, 10000],
            "low_capacity_steady_window_ms": [25000, 30000],
            "recovered_steady_window_ms": [55000, 60000],
        },
        "validation": "passed",
        "limitation": "Fluid model, not a transport benchmark; transient p99 is not constrained to 100 ms.",
        "results": results,
    }
    encoded = json.dumps(evidence, indent=2) + "\n"
    if args.summary is not None:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(encoded)
        print(f"Adaptive model checks passed; summary: {args.summary}")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
