#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

for scheme in mldsa falcon; do
  echo "== $scheme =="
  ( cd "$ROOT/$scheme" && cargo-build-sbf 2>&1 ) \
    | grep -iE 'frame size|stack offset|Finished' \
    | sort -u
  echo
done

echo "Any 'Stack offset ... exceeded max offset of 4096' line means the verifier"
echo "cannot run safely on-chain as compiled: its frame is larger than the SBF"
echo "4096-byte stack limit."
