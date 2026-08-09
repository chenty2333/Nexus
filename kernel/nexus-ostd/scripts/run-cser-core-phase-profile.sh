#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Emit the portable, no-persistence CSER transition-phase profile as JSONL.
# This is a development measurement: it is intentionally not a pass/fail
# performance gate, and it excludes journal I/O/readback/flush, TPM anchor
# work, OSTD mutex queue/hold time, endpoint time, and QEMU execution.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
output=${1:-"$repo_root/artifacts/cser-core-phase-profile.jsonl"}

mkdir -p "$(dirname "$output")"
cd "$repo_root"

# `--nocapture` emits a stable CSER_CORE_STATE_PROFILE prefix. Keep only the
# JSON payload so the result is directly consumable as JSONL even when Cargo
# changes its diagnostic formatting.
cargo test --locked -p cser-core --release --features std --lib \
    portable_core_state_work_profile -- --ignored --nocapture \
    | sed -n 's/^CSER_CORE_STATE_PROFILE //p' >"$output"

test -s "$output"
printf 'CSER core phase profile written: %s\n' "$output"
