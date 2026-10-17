#!/usr/bin/env bash
# Build against this checkout, including its pinned dependencies.
set -Eeuo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(realpath -e "${1:-$HERE/../..}")
[[ -f $ROOT/src/common/qlinq.h ]] || { echo 'Usage: ./build.sh [qlinq checkout]' >&2; exit 1; }
[[ $EUID != 0 ]] || { echo 'Build as your ordinary user, without sudo.' >&2; exit 1; }
mkdir -p "$HERE/.build"
make -C "$ROOT" -j"${JOBS:-4}" libqlinq.a > "$HERE/.build/build.log" 2>&1 || {
    tail -n 30 "$HERE/.build/build.log" >&2; exit 1;
}
cc -O2 -Wall -Wextra -I "$ROOT/src/common" "$HERE/records.c" "$ROOT/libqlinq.a" \
    -o "$HERE/.build/records" -lpthread -lrt -ldl -lm -lcrypto -lssl
{
    git -C "$ROOT" rev-parse HEAD
    git -C "$ROOT" status --short
    git -C "$ROOT" submodule status --recursive
    cc --version | head -n 1
    openssl version
} > "$HERE/.build/source.txt"
sha256sum "$ROOT/libqlinq.a" > "$HERE/.build/library.sha256"
(cd "$HERE" && sha256sum records.c .build/records > .build/driver.sha256)
echo 'Built .build/records; source identity and build log are in .build/.'
