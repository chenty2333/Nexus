#!/usr/bin/env bash
# Dedicated real-QEMU entrypoint. Fake guest helpers are intentionally not
# expressible here; unit tests continue to use run_matrix.sh directly.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
variant=
output=
trials=1
timeout=90
# qemu_boot's OSDK envelope is 90 seconds. Keep the controller outside it so
# the recovered VM can terminate and its serial receipt can be collected.
recovery_timeout=120
only_cutpoint=
media=()
base_media_dir=
usage() {
  echo "usage: $0 --variant {cser,baseline} --output DIR (--base-media FILE ... | --base-media-dir DIR) [--trials N] [--timeout-seconds N] [--recovery-timeout-seconds N] [--only-cutpoint NAME]" >&2
}
while (($#)); do
  case "$1" in
    --variant) variant=${2:?}; shift 2 ;;
    --output) output=${2:?}; shift 2 ;;
    --base-media) media+=("${2:?}"); shift 2 ;;
    --base-media-dir) base_media_dir=${2:?}; shift 2 ;;
    --trials) trials=${2:?}; shift 2 ;;
    --timeout-seconds) timeout=${2:?}; shift 2 ;;
    --recovery-timeout-seconds) recovery_timeout=${2:?}; shift 2 ;;
    --only-cutpoint) only_cutpoint=${2:?}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
[[ $variant == cser || $variant == baseline ]] || { usage; exit 2; }
[[ -n $output ]] || { usage; exit 2; }
[[ $trials =~ ^[1-9][0-9]*$ && $timeout =~ ^[1-9][0-9]*$ && $recovery_timeout =~ ^[1-9][0-9]*$ ]] || { usage; exit 2; }
(( recovery_timeout > 90 )) || {
  echo "real-QEMU recovery timeout must exceed the qemu_boot internal 90s timeout" >&2
  exit 2
}
[[ -z $base_media_dir || ${#media[@]} -eq 0 ]] || { echo "choose either --base-media or --base-media-dir" >&2; exit 2; }

# Each OSDK scheme has one fixed artifact directory, TPM state, and COM2/COM3
# socket pair. Serialize the whole initial+recovery campaign for one variant so
# independent runner processes cannot cross-contaminate those authorities.
lock_path="/tmp/nexus-tool-dma-${variant}.lock"
exec {matrix_lock_fd}>"$lock_path"
flock --exclusive --nonblock "$matrix_lock_fd" || {
  echo "another real-QEMU $variant matrix owns $lock_path" >&2
  exit 1
}
if [[ -n $base_media_dir ]]; then
  "$root/prepare_base_media.sh" "$base_media_dir"
  media=("$base_media_dir/journal.raw" "$base_media_dir/outbox.raw" "$base_media_dir/ram.raw")
fi
for medium in "${media[@]}"; do [[ -f $medium ]] || { echo "not a regular base medium: $medium" >&2; exit 2; }; done
[[ ${#media[@]} -gt 0 ]] || { usage; exit 2; }

# qemu_boot receives this identity through the controller environment.  The
# original generic runner remains useful for isolated protocol tests; this
# entrypoint is the research campaign and therefore forces real-QEMU mode.
args=(--variant "$variant" --output "$output" --trials "$trials" --timeout-seconds "$timeout" --recovery-timeout-seconds "$recovery_timeout" \
  --real-qemu --recovery-output-metrics --recovery-guest "$root/qemu_boot.sh" \
  --kill-mode container)
[[ -z $only_cutpoint ]] || args+=(--only-cutpoint "$only_cutpoint")
for medium in "${media[@]}"; do args+=(--base-media "$medium"); done
args+=(--container-kill-command /usr/bin/docker kill -- "$root/qemu_boot.sh")
"$root/run_matrix.sh" "${args[@]}"
