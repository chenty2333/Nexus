#!/usr/bin/env bash
# Run the matched CSER3 logical-handoff crash cuts without changing Tool+DMA.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
variant= output= trials=1 timeout=90 recovery_timeout=150 media=() only_cutpoint= real_qemu=false
usage() { echo "usage: $0 --variant {cser,baseline} --output DIR --base-media FILE [--trials N] [--only-cutpoint NAME] -- GUEST" >&2; }
while (($#)); do case "$1" in
  --variant) variant=${2:?}; shift 2;; --output) output=${2:?}; shift 2;; --base-media) media+=("${2:?}"); shift 2;; --trials) trials=${2:?}; shift 2;; --timeout-seconds) timeout=${2:?}; shift 2;; --recovery-timeout-seconds) recovery_timeout=${2:?}; shift 2;; --only-cutpoint) only_cutpoint=${2:?}; shift 2;; --real-qemu) real_qemu=true; shift;; --) shift; break;; -h|--help) usage; exit 0;; *) usage; exit 2;; esac; done
[[ $variant == cser || $variant == baseline ]] && [[ -n $output && ${#media[@]} -gt 0 && $# -gt 0 ]] || { usage; exit 2; }
[[ $trials =~ ^[1-9][0-9]*$ && $timeout =~ ^[1-9][0-9]*$ && $recovery_timeout =~ ^[1-9][0-9]*$ ]] || { echo 'invalid numeric option' >&2; exit 2; }
[[ ! -e $output ]] || { echo "output already exists: $output" >&2; exit 2; }
cuts=(descriptor_discovered parent_ack_or_descriptor_durable child_installed handoff_committed child_first_observed)
if [[ -n $only_cutpoint ]]; then case "$only_cutpoint" in descriptor_discovered|parent_ack_or_descriptor_durable|child_installed|handoff_committed|child_first_observed) cuts=("$only_cutpoint");; *) echo 'invalid --only-cutpoint' >&2; exit 2;; esac; fi
project_root=$(cd "$root/../.." && pwd -P)
catalog_digest=$(cargo run --quiet --locked --manifest-path "$project_root/../../Cargo.toml" -p cser-core --features std --bin cser-catalog-digest -- tool-dma)
[[ $catalog_digest =~ ^[0-9a-f]{64}$ ]] || { echo 'tool-dma catalog digest command returned invalid output' >&2; exit 1; }
mkdir -p "$output"; metrics="$output/metrics.jsonl"
for ((trial=1; trial<=trials; trial++)); do for cut in "${cuts[@]}"; do
  run_id=$(python3 -c 'import secrets; print(secrets.token_hex(16))'); authority=$(python3 -c 'import secrets; print(secrets.token_hex(16))'); effect=$(python3 -c 'import secrets; print(secrets.token_hex(16))'); namespace="handoff-${run_id}"
  case "$cut" in descriptor_discovered) id=21;; parent_ack_or_descriptor_durable) id=22;; child_installed) id=23;; handoff_committed) id=24;; child_first_observed) id=25;; esac
  trial_dir="$output/${variant}-t${trial}-${cut}-${run_id}"; barrier="$trial_dir/com3-crash.sock"
  if [[ $real_qemu == true ]]; then barrier="$project_root/artifacts/tool-handoff-${variant}/com3-crash.sock"; fi
  args=(python3 "$root/handoff_matrix_controller.py" --variant "$variant" --run-id "$run_id" --catalog-digest "$catalog_digest" --namespace-id "$namespace" --authority-id "$authority" --effect-id "$effect" --trial "$trial" --cutpoint "$cut" --cutpoint-id "$id" --barrier-socket "$barrier" --trial-dir "$trial_dir" --metrics-jsonl "$metrics" --timeout-seconds "$timeout" --recovery-timeout-seconds "$recovery_timeout" --recovery-guest "$root/qemu_boot.sh")
  for item in "${media[@]}"; do args+=(--media "$item"); done
  [[ $real_qemu == true ]] && args+=(--real-qemu)
  args+=(-- "$@")
  "${args[@]}"
done; done
python3 "$root/summarize_handoff_metrics.py" --allow-partial --input "$metrics" --output "$output/summary.json"
