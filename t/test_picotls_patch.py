#!/usr/bin/env python3
"""Exercise dependency preparation against a temporary pristine Git checkout."""
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
original = root / "deps/quicly/deps/picotls"

def run(args, cwd, **kwargs):
    return subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, **kwargs)

with tempfile.TemporaryDirectory(prefix="qlinq-picotls-patch-") as temporary:
    fixture = Path(temporary)
    dep = fixture / "deps/quicly/deps/picotls"
    dep.mkdir(parents=True)
    for name in ("include/picotls.h", "lib/picotls.c", "lib/openssl.c"):
        contents = subprocess.check_output(["git", "show", "HEAD:" + name], cwd=original)
        target = dep / name
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(contents)
    run(["git", "init", "--quiet", "--template="], dep, check=True)
    run(["git", "add", "."], dep, check=True)
    run(["git", "-c", "user.name=qlinq test", "-c", "user.email=test@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
         "commit", "--quiet", "-m", "fixture baseline"], dep, check=True)
    for name in ("scripts/prepare_picotls.py", "patches/picotls-negotiated-group.patch"):
        target = fixture / name
        target.parent.mkdir(exist_ok=True)
        shutil.copyfile(root / name, target)
    prepare = ["python3", str(fixture / "scripts/prepare_picotls.py")]
    run(prepare + ["--check"], fixture, check=True)
    run(prepare, fixture, check=True)
    expected = (fixture / "patches/picotls-negotiated-group.patch").read_bytes()
    assert run(["git", "diff", "HEAD", "--binary"], dep, check=True).stdout == expected
    run(prepare, fixture, check=True)
    run(prepare + ["--check"], fixture, check=True)
    header = dep / "include/picotls.h"
    unexpected = header.read_bytes() + b"\n/* preserve unrelated edit */\n"
    header.write_bytes(unexpected)
    for arguments in (prepare, prepare + ["--check"]):
        result = run(arguments, fixture)
        assert result.returncode != 0 and b"unexpected tracked edits" in result.stderr
        assert header.read_bytes() == unexpected
print("===PICOTLS PATCH OK===")
