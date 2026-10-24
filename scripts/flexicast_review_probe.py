#!/usr/bin/env python3
"""Build the Flexicast review probe without modifying the measured tree.

Compile all sources with -O2 in a separate directory so baseline and candidate
use identical optimization. Run the resulting binary with `rate` or `natural`.
The tree must have all pinned submodules populated. No network namespace or
traffic-control changes are performed; the probe uses loopback UDP sockets.
"""
import argparse
import concurrent.futures
import json
from pathlib import Path
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    tree = args.tree.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    overlay = output / "settings.mk"
    overlay.write_text("\n".join([
        ".PHONY: probe-settings", "probe-settings:", "\t@:",
        "$(info PROBE_CC=$(CC))",
        "$(info PROBE_FLAGS=$(CFLAGS_COMMON) $(INCLUDES) -O2)",
        "$(info PROBE_OBJECTS=$(COMMON_OBJS))",
        "$(info PROBE_LIBS=$(LDFLAGS))", ""]))
    raw = subprocess.check_output(
        ["make", "-s", "-f", "Makefile", "-f", str(overlay), "probe-settings"],
        cwd=tree, text=True)
    settings = dict(line.split("=", 1) for line in raw.splitlines()
                    if line.startswith("PROBE_"))
    compiler = shlex.split(settings["PROBE_CC"])
    flags = shlex.split(settings["PROBE_FLAGS"])
    objects = shlex.split(settings["PROBE_OBJECTS"])
    libraries = shlex.split(settings["PROBE_LIBS"])
    commands = []

    def compile_object(relative):
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        command = compiler + flags + ["-w", "-c", str(Path(relative).with_suffix(".c")),
                                      "-o", str(destination)]
        subprocess.run(command, cwd=tree, check=True)
        return str(destination), command

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        built = list(pool.map(compile_object, objects))
    commands.extend(command for _, command in built)
    template = Path(__file__).resolve().parent.parent / "t/00util/flexicast_review_probe.c"
    source = output / "flexicast_review_probe.c"
    fixture = tree / "t/00util/test_flexicast_regressions.c"
    source.write_text(template.read_text().replace(
        '#include "test_flexicast_regressions.c"', '#include ' + json.dumps(str(fixture))))
    binary = output / "flexicast_review_probe"
    command = compiler + flags + [str(source)] + [path for path, _ in built] + libraries + ["-o", str(binary)]
    subprocess.run(command, cwd=tree, check=True)
    commands.append(command)
    (output / "build-commands.json").write_text(json.dumps({
        "working_directory": str(tree), "commands": commands}, indent=2) + "\n")
    print(binary)


if __name__ == "__main__":
    main()
