#!/usr/bin/env bash
# Run the identical host-controlled crash matrix for the CSER and baseline arms.
set -euo pipefail
usage() { cat >&2 <<'EOF'
usage: run_matrix.sh --variant {cser,baseline} --output DIR --base-media PATH [options] -- GUEST [ARGS...]
options: --trials N (default 1), --timeout-seconds N (default 30),
         --only-cutpoint NAME,
         --kill-mode {pid,container}, --container-kill-command CMD [ARGS...],
         --recovery-guest EXECUTABLE, --recovery-output-metrics, --real-qemu
EOF
}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); variant=; output=; trials=1; timeout=30; only_cutpoint=; kill_mode=pid; recovery_guest=; recovery_output_metrics=false; real_qemu=false; container_kill=(); base_media=()
while (($#)); do case "$1" in
  --variant) variant=${2:?}; shift 2;; --output) output=${2:?}; shift 2;; --base-media) base_media+=("${2:?}"); shift 2;; --trials) trials=${2:?}; shift 2;; --timeout-seconds) timeout=${2:?}; shift 2;; --only-cutpoint) only_cutpoint=${2:?}; shift 2;; --kill-mode) kill_mode=${2:?}; shift 2;;
  --container-kill-command) shift; while (($#)) && [[ $1 != -- ]]; do container_kill+=("$1"); shift; done;; --recovery-guest) recovery_guest=${2:?}; shift 2;; --recovery-output-metrics) recovery_output_metrics=true; shift;; --real-qemu) real_qemu=true; shift;; --) shift; break;; -h|--help) usage; exit 0;; *) usage; exit 2;; esac; done
[[ $variant == cser || $variant == baseline ]] || { echo 'invalid --variant' >&2; exit 2; }; [[ -n $output && ${#base_media[@]} -gt 0 && $# -gt 0 ]] || { usage; exit 2; }; [[ $trials =~ ^[1-9][0-9]*$ ]] || { echo 'invalid --trials' >&2; exit 2; }; [[ $kill_mode == pid || $kill_mode == container ]] || { echo 'invalid --kill-mode' >&2; exit 2; }; [[ $kill_mode == pid || ${#container_kill[@]} -gt 0 ]] || { echo 'container kill requires --container-kill-command' >&2; exit 2; }
cutpoints=(pre_escape post_register post_endpoint_apply post_effect_fact post_quiescence pre_discharge post_discharge)
[[ ! -e $output ]] || { echo "output already exists: $output" >&2; exit 2; }
mkdir -p "$output"; metrics="$output/metrics.jsonl"; touch "$metrics"
if [[ -n $only_cutpoint ]]; then
  valid=false
  for candidate in "${cutpoints[@]}"; do [[ $candidate == "$only_cutpoint" ]] && valid=true; done
  [[ $valid == true ]] || { echo 'invalid --only-cutpoint' >&2; exit 2; }
  selected_cutpoints=("$only_cutpoint")
else
  selected_cutpoints=("${cutpoints[@]}")
fi
for ((trial=1; trial<=trials; trial++)); do for cutpoint in "${selected_cutpoints[@]}"; do
  if [[ $real_qemu == true ]]; then
    # See matrix_controller._CURRENT_GUEST_RUN_ID: this is not a global test
    # identity, because every row gets independently copied durable media.
    run_id=42424242424242424242424242424242
  else
    run_id=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
  fi
  trial_dir="$output/${variant}-t${trial}-${cutpoint}-${run_id}"; mkdir -p "$trial_dir/media"; media_args=()
  for source in "${base_media[@]}"; do [[ -f $source ]] || { echo "base media is not a regular file: $source" >&2; exit 2; }; destination="$trial_dir/media/$(basename "$source")"; cp --reflink=auto --preserve=mode,timestamps "$source" "$destination"; media_args+=(--media "$destination"); done
  cutpoint_id=0; for index in "${!cutpoints[@]}"; do [[ ${cutpoints[$index]} == "$cutpoint" ]] && cutpoint_id=$((index + 1)); done
  barrier_socket="$trial_dir/com3-crash.sock"
  if [[ $real_qemu == true ]]; then
    # The reviewed OSDK schemes expose COM3 at a fixed, short artifact path.
    # Do not mirror the socket beneath the descriptive row directory: its
    # absolute pathname can exceed Linux's 108-byte AF_UNIX limit before QEMU
    # has a chance to create it. Rows are intentionally sequential, so this
    # shared transport path does not mix trial state.
    project_root=$(cd "$root/../.." && pwd -P)
    barrier_socket="$project_root/artifacts/tool-dma-$variant/com3-crash.sock"
  fi
  command=(python3 "$root/matrix_controller.py" --variant "$variant" --run-id "$run_id" --trial "$trial" --cutpoint "$cutpoint" --cutpoint-id "$cutpoint_id" --barrier-socket "$barrier_socket" --trial-dir "$trial_dir" --prepared-trial-dir --metrics-jsonl "$metrics" --timeout-seconds "$timeout" --kill-mode "$kill_mode"); command+=("${media_args[@]}"); [[ -z $recovery_guest ]] || command+=(--recovery-guest "$recovery_guest"); [[ $recovery_output_metrics == false ]] || command+=(--recovery-output-metrics); [[ $real_qemu == false ]] || command+=(--real-qemu); if [[ $kill_mode == container ]]; then command+=(--container-kill-command "${container_kill[@]}"); fi; command+=(-- "$@"); "${command[@]}"
done; done
python3 "$root/summarize_metrics.py" --input "$metrics" --output "$output/summary.json"
