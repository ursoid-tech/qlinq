#!/usr/bin/env python3
"""Apply the tracked accessor and KEM context-cleanup patch to the pinned Picotls checkout.

Fail on any other tracked dependency edits; never reset or discard them.
--check accepts either a pristine pin or exactly our recorded patch.
"""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
dep = root / "deps/quicly/deps/picotls"
patch = root / "patches/picotls-negotiated-group.patch"
actual = subprocess.check_output(["git", "diff", "HEAD", "--binary"], cwd=dep)
expected = patch.read_bytes()
if actual and actual != expected:
    sys.exit("Picotls has unexpected tracked edits; refusing to modify them")
if not actual and "--check" not in sys.argv:
    subprocess.run(["git", "apply", "--check", str(patch)], cwd=dep, check=True)
    subprocess.run(["git", "apply", str(patch)], cwd=dep, check=True)
