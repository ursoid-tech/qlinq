#!/usr/bin/env python3
"""Build a local pilot install bundle without installing on the host."""
import argparse
import platform
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("dist"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / f"qlinq-tun-tool-linux-{platform.machine()}.tar.gz"
    with tempfile.TemporaryDirectory(prefix="qlinq-package-") as temporary:
        stage = Path(temporary)
        subprocess.run(["make", "install-tun", f"DESTDIR={stage}", "PREFIX=/usr/local"],
                       cwd=root, check=True)
        docs = stage / "usr/local/share/doc/qlinq-tun"
        docs.mkdir(parents=True)
        shutil.copy2(root / "docs/tun-tool.md", docs / "README.md")
        with tarfile.open(archive, "w:gz") as bundle:
            for path in sorted(stage.rglob("*")):
                if not path.is_file():
                    continue
                arcname = str(path.relative_to(stage))
                info = bundle.gettarinfo(str(path), arcname=arcname)
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mode = 0o755 if arcname == "usr/local/bin/qlinq-tun" else 0o644
                with path.open("rb") as source:
                    bundle.addfile(info, source)
    print(archive.resolve())


if __name__ == "__main__":
    main()
