#!/usr/bin/env bash
# Dedicated real-QEMU entrypoint for the separate logical handoff lane.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
variant= output= trials=1 timeout=90 recovery_timeout=150 only_cutpoint= base_media_dir= media=()
usage() { echo "usage: $0 --variant {cser,baseline} --output DIR (--base-media FILE ... | --base-media-dir DIR) [--trials N] [--only-cutpoint NAME]" >&2; }
while (($#)); do case "$1" in --variant) variant=${2:?}; shift 2;; --output) output=${2:?}; shift 2;; --base-media) media+=("${2:?}"); shift 2;; --base-media-dir) base_media_dir=${2:?}; shift 2;; --trials) trials=${2:?}; shift 2;; --timeout-seconds) timeout=${2:?}; shift 2;; --recovery-timeout-seconds) recovery_timeout=${2:?}; shift 2;; --only-cutpoint) only_cutpoint=${2:?}; shift 2;; -h|--help) usage; exit 0;; *) usage; exit 2;; esac; done
[[ ( $variant == cser || $variant == baseline ) && -n $output ]] || { usage; exit 2; }; [[ -z $base_media_dir || ${#media[@]} -eq 0 ]] || { echo 'choose one media source' >&2; exit 2; }
(( recovery_timeout > 130 )) || { echo 'real-QEMU recovery timeout must exceed 130 seconds' >&2; exit 2; }
if [[ -n $base_media_dir ]]; then "$root/prepare_base_media.sh" "$base_media_dir"; media=("$base_media_dir/journal.raw" "$base_media_dir/outbox.raw" "$base_media_dir/ram.raw"); fi
[[ ${#media[@]} -gt 0 ]] || { usage; exit 2; }
exec 9>"/tmp/nexus-handoff-${variant}.lock"; flock --exclusive --nonblock 9 || { echo "another handoff campaign owns this variant" >&2; exit 1; }
args=(--variant "$variant" --output "$output" --trials "$trials" --timeout-seconds "$timeout" --recovery-timeout-seconds "$recovery_timeout" --real-qemu)
[[ -z $only_cutpoint ]] || args+=(--only-cutpoint "$only_cutpoint")
for item in "${media[@]}"; do args+=(--base-media "$item"); done
"$root/run_handoff_matrix.sh" "${args[@]}" -- "$root/qemu_boot.sh"
