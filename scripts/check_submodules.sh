#!/bin/sh

set -eu

if [ ! -f .gitmodules ]; then
  exit 0
fi

bad_status=0
git submodule status --recursive | while IFS= read -r line; do
  case "$line" in
    -*) echo "uninitialized submodule: $line" >&2; exit 1 ;;
    +*) echo "submodule is not at the recorded commit: $line" >&2; exit 1 ;;
    U*) echo "submodule has unresolved conflicts: $line" >&2; exit 1 ;;
  esac
done || bad_status=1
[ "$bad_status" -eq 0 ] || exit 1

python3 scripts/prepare_picotls.py --check
export QLINQ_PICOTLS_PATCH="$(pwd)/patches/picotls-negotiated-group.patch"
git submodule foreach --quiet --recursive \
  'if ! git diff --quiet --ignore-submodules=all; then if [ "$displaypath" = "deps/quicly/deps/picotls" ] && git diff HEAD --binary | cmp -s - "$QLINQ_PICOTLS_PATCH"; then exit 0; fi; echo "tracked changes in submodule: $displaypath" >&2; exit 1; fi'

echo "submodule revisions are pinned and tracked contents match pins plus the recorded Picotls patch"
