#!/usr/bin/env python3
"""Apply the tracked variable-size datagram patch to the pinned Quicly checkout.

Fail on any other tracked dependency edits; never reset or discard them.
--check accepts either a pristine pin or exactly our recorded patch.
Nested dependency patches are checked separately by their own preparation scripts.
"""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
dep = root / "deps/quicly"
patch = root / "patches/quicly-gso.patch"
actual = subprocess.check_output(
    ["git", "diff", "HEAD", "--binary", "--abbrev=8", "--ignore-submodules=all"], cwd=dep)
expected = patch.read_bytes()
if actual and actual != expected:
    sys.exit("Quicly has unexpected tracked edits; refusing to modify them")
if not actual and "--check" not in sys.argv:
    subprocess.run(["git", "apply", "--check", str(patch)], cwd=dep, check=True)
    subprocess.run(["git", "apply", str(patch)], cwd=dep, check=True)
