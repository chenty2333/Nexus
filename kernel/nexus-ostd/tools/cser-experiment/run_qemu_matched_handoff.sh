#!/usr/bin/env bash
# Run both real-QEMU logical-handoff arms and emit one strict matched summary.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
output=
base_media_dir=
trials=1
timeout=90
recovery_timeout=150
only_cutpoint=

usage() {
  echo "usage: $0 --output DIR --base-media-dir DIR [--trials N] [--only-cutpoint NAME]" >&2
}

while (($#)); do
  case "$1" in
    --output) output=${2:?}; shift 2;;
    --base-media-dir) base_media_dir=${2:?}; shift 2;;
    --trials) trials=${2:?}; shift 2;;
    --timeout-seconds) timeout=${2:?}; shift 2;;
    --recovery-timeout-seconds) recovery_timeout=${2:?}; shift 2;;
    --only-cutpoint) only_cutpoint=${2:?}; shift 2;;
    -h|--help) usage; exit 0;;
    *) usage; exit 2;;
  esac
done

[[ -n $output && -n $base_media_dir && ! -e $output ]] || { usage; exit 2; }
mkdir -p "$output"

for variant in cser baseline; do
  args=(
    --variant "$variant"
    --output "$output/$variant"
    --base-media-dir "$base_media_dir"
    --trials "$trials"
    --timeout-seconds "$timeout"
    --recovery-timeout-seconds "$recovery_timeout"
  )
  [[ -z $only_cutpoint ]] || args+=(--only-cutpoint "$only_cutpoint")
  "$root/run_qemu_handoff_matrix.sh" "${args[@]}"
done

summary_args=(
  --input "$output/cser/metrics.jsonl"
  --input "$output/baseline/metrics.jsonl"
  --output "$output/summary.json"
)
[[ -z $only_cutpoint ]] || summary_args+=(--allow-partial)
python3 "$root/summarize_handoff_metrics.py" "${summary_args[@]}"
