#!/usr/bin/env bash
# Launch exactly one real QEMU boot for the tool-plus-DMA crash matrix.
#
# This is deliberately the only launcher accepted by matrix_controller's
# --real-qemu mode.  It stages an isolated trial into the static OSDK scheme
# location, starts the independent durable tool endpoint and COM2 bridge, and
# delegates VM lifecycle to kernel/nexus-ostd/x.  It never writes a recovery
# success result: recovery acceptance is based solely on a terminal marker
# emitted by the guest over QEMU serial.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
variant=${CSER_EXPERIMENT_VARIANT:?missing CSER_EXPERIMENT_VARIANT}
trial_dir=${CSER_EXPERIMENT_TRIAL_DIR:?missing CSER_EXPERIMENT_TRIAL_DIR}
run_id=${CSER_EXPERIMENT_RUN_ID:?missing CSER_EXPERIMENT_RUN_ID}
catalog_digest=${CSER_EXPERIMENT_CATALOG_DIGEST:?missing CSER_EXPERIMENT_CATALOG_DIGEST}
namespace=${CSER_EXPERIMENT_NAMESPACE_ID:?missing CSER_EXPERIMENT_NAMESPACE_ID}
authority_id=${CSER_EXPERIMENT_AUTHORITY_ID:?missing CSER_EXPERIMENT_AUTHORITY_ID}
effect_id=${CSER_EXPERIMENT_EFFECT_ID:?missing CSER_EXPERIMENT_EFFECT_ID}
phase=${CSER_EXPERIMENT_PHASE:-initial}

case "$variant" in
  cser) scheme=tool-dma-cser; artifact_dir="$root/artifacts/tool-dma-cser" ;;
  baseline) scheme=tool-dma-baseline; artifact_dir="$root/artifacts/tool-dma-baseline" ;;
  *) echo "qemu_boot: invalid variant: $variant" >&2; exit 2 ;;
esac
case "$phase" in initial|recovery) ;; *) echo "qemu_boot: invalid phase: $phase" >&2; exit 2 ;; esac
[[ $run_id =~ ^[0-9a-f]{32}$ ]] || { echo "qemu_boot: invalid run id" >&2; exit 2; }
[[ $catalog_digest =~ ^[0-9a-f]{64}$ ]] || { echo "qemu_boot: invalid catalog digest" >&2; exit 2; }
[[ $namespace =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] || { echo "qemu_boot: invalid namespace" >&2; exit 2; }
[[ $authority_id =~ ^[0-9a-f]{32}$ ]] || { echo "qemu_boot: invalid authority" >&2; exit 2; }
[[ $effect_id =~ ^[0-9a-f]{32}$ ]] || { echo "qemu_boot: invalid effect" >&2; exit 2; }
[[ -d $trial_dir/media ]] || { echo "qemu_boot: trial media is missing" >&2; exit 2; }

require_medium() {
  local name=$1 expected_bytes=$2 path="$trial_dir/media/$1"
  [[ -f $path ]] || { echo "qemu_boot: required trial medium missing: $path" >&2; exit 2; }
  [[ $(stat -c %s -- "$path") == "$expected_bytes" ]] || {
    echo "qemu_boot: trial medium has wrong size: $path" >&2
    exit 2
  }
}
require_medium journal.raw $((4 * 1024 * 1024))
require_medium outbox.raw $((4 * 1024 * 1024))
require_medium ram.raw $((1024 * 1024 * 1024))

tool_catalog_digest() {
  local digest
  digest=$(cargo run --quiet --locked --manifest-path "$root/../../Cargo.toml" \
    -p cser-core --features std --bin cser-catalog-digest -- tool-dma)
  [[ $digest =~ ^[0-9a-f]{64}$ ]] || {
    echo "qemu_boot: tool catalog digest command returned invalid output" >&2
    exit 1
  }
  printf '%s\n' "$digest"
}

# OSDK's reviewed schemes use fixed in-repository artifact paths.  Trials are
# sequential, so copying an isolated media snapshot into that fixed envelope
# before boot preserves each crash cut's independent initial state.
if [[ $phase == initial ]]; then
  mkdir -p "$artifact_dir"
  for name in journal.raw outbox.raw ram.raw; do
    source="$trial_dir/media/$name"
    [[ -f $source ]] || { echo "qemu_boot: required trial medium missing: $source" >&2; exit 2; }
    cp --reflink=auto --preserve=mode,timestamps "$source" "$artifact_dir/$name"
  done
  # TPM state is part of a row's durable custody state even though it is a
  # directory rather than one of run_matrix's file media. Reset exactly this
  # reviewed per-scheme directory before the first boot; recovery reuses it.
  rm -rf -- "$artifact_dir/tpmstate"
  mkdir -p -- "$artifact_dir/tpmstate"
  if [[ $variant == cser ]]; then
    # The CSER boot envelope calls `inspect` before it can quarantine the
    # device. Provision a registry/binding-1 genesis tip whose catalog is
    # computed from the same workspace source used to build the guest.
    "$root/scripts/provision-cser-tpm-nv.sh" \
      "$artifact_dir/tpmstate" "$(tool_catalog_digest)" 0 "$(printf '%064d' 0)"
  else
    # The independent baseline owns only a revision/digest selector. Its
    # guest-side ExperimentNvAnchor initializes the selected blank slot, but
    # it still needs an authenticated empty NV layout before quarantine.
    "$root/scripts/provision-cser-tpm-nv.sh" --experiment-blank "$artifact_dir/tpmstate"
  fi
  rm -f "$artifact_dir/com2-tool.sock" "$artifact_dir/com3-crash.sock" "$artifact_dir/swtpm-qemu.sock"
fi

database="$trial_dir/tool-endpoint.sqlite"
port_file="$trial_dir/tool-endpoint.port"
endpoint_log="$trial_dir/endpoint.stderr.log"
bridge_ready="$trial_dir/bridge.startup-ready.json"
bridge_status="$trial_dir/bridge.status.json"
bridge_log="$trial_dir/bridge.stderr.log"
sink_ready="$trial_dir/recovery-sink.startup-ready.json"
sink_status="$trial_dir/recovery-sink.status.json"
sink_log="$trial_dir/recovery-sink.stderr.log"
rm -f -- "$port_file" "$bridge_ready" "$bridge_status" "$sink_ready" "$sink_status"
endpoint_pid=
bridge_pid=
crash_sink_pid=

stage_fail() {
  local stage=$1; shift
  echo "qemu_boot: stage=$stage: $*" >&2
  exit 1
}

signal_detail() {
  local signal_file=$1
  [[ -s $signal_file ]] || return 0
  python3 - "$signal_file" <<'PY'
import json, sys
try:
    value = json.load(open(sys.argv[1], encoding="utf-8"))
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
except (OSError, ValueError) as error:
    print(f"unreadable-signal:{error}")
PY
}

wait_for_startup_ready() {
  local stage=$1 pid=$2 signal_file=$3
  for _ in {1..100}; do
    if [[ -s $signal_file ]]; then
      if grep -Fq '"state": "ready"' "$signal_file"; then
        return 0
      fi
      stage_fail "$stage" "invalid startup signal $(signal_detail "$signal_file")"
    fi
    kill -0 "$pid" 2>/dev/null || stage_fail "$stage" "helper exited; see its stderr log"
    sleep .05
  done
  stage_fail "$stage" "startup readiness timed out"
}

wait_for_terminal_helper() {
  local stage=$1 pid=$2 signal_file=$3 expected=$4
  for _ in {1..100}; do
    local matched=false
    if [[ -s $signal_file ]]; then
      if grep -Fq "\"state\": \"$expected\"" "$signal_file"; then
        matched=true
      elif [[ $expected == served-or-unused ]] \
        && { grep -Fq '"state": "served"' "$signal_file" \
          || grep -Fq '"state": "unused"' "$signal_file"; }; then
        matched=true
      fi
    fi
    if [[ $matched == true ]]; then
      wait "$pid" || stage_fail "$stage" "helper exited nonzero after $expected: $(signal_detail "$signal_file")"
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" || true
      stage_fail "$stage" "helper exited before $expected: $(signal_detail "$signal_file")"
    fi
    sleep .05
  done
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  stage_fail "$stage" "helper did not reach $expected: $(signal_detail "$signal_file")"
}

cleanup() {
  [[ -z ${crash_sink_pid:-} ]] || kill "$crash_sink_pid" 2>/dev/null || true
  [[ -z ${bridge_pid:-} ]] || kill "$bridge_pid" 2>/dev/null || true
  [[ -z ${endpoint_pid:-} ]] || kill "$endpoint_pid" 2>/dev/null || true
  wait "${crash_sink_pid:-}" 2>/dev/null || true
  wait "${bridge_pid:-}" 2>/dev/null || true
  wait "${endpoint_pid:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

python3 "$root/tools/cser-experiment/tool_endpoint.py" \
  --database "$database" --namespace "$namespace" --authority-id "$authority_id" --effect-id "$effect_id" --catalog-digest "$catalog_digest" \
  --port 0 --port-file "$port_file" 2>>"$endpoint_log" &
endpoint_pid=$!
for _ in {1..100}; do
  if [[ -s $port_file ]]; then break; fi
  kill -0 "$endpoint_pid" 2>/dev/null || stage_fail endpoint-connect "endpoint exited before publishing a port; see $endpoint_log"
  sleep .05
done
[[ -s $port_file ]] || stage_fail endpoint-connect "endpoint did not publish its port; see $endpoint_log"
port=$(<"$port_file")
[[ $port =~ ^[1-9][0-9]*$ && $port -le 65535 ]] || stage_fail endpoint-connect "endpoint published invalid port"
endpoint_ready=false
for _ in {1..100}; do
  if python3 - "$port" <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=.1)
s.close()
PY
  then endpoint_ready=true; break; fi
  sleep .05
done
kill -0 "$endpoint_pid" 2>/dev/null || stage_fail endpoint-connect "endpoint exited before accepting TCP; see $endpoint_log"
[[ $endpoint_ready == true ]] || stage_fail endpoint-connect "endpoint did not accept TCP before deadline; see $endpoint_log"

bridge_args=(
  --socket "$artifact_dir/com2-tool.sock" --run-id "$run_id" --endpoint-port "$port" --cser2
  --namespace-id "$namespace" --authority-id "$authority_id" --effect-id "$effect_id" --catalog-digest "$catalog_digest"
  --connect-timeout 90 --request-timeout 90 --startup-ready-file "$bridge_ready"
  --status-file "$bridge_status"
)
[[ $phase != recovery ]] || bridge_args+=(--allow-no-request)
python3 "$root/tools/cser-experiment/uart_http_bridge.py" \
  "${bridge_args[@]}" 2>>"$bridge_log" &
bridge_pid=$!
wait_for_startup_ready bridge-ready "$bridge_pid" "$bridge_ready"

# COM3 uses wait=on so no initial crash barrier can be lost before the matrix
# controller connects. Recovery deliberately has no crash cutpoints, but QEMU
# still requires a peer before boot; this sink holds the channel open and
# fails if the recovered guest unexpectedly emits a barrier.
if [[ $phase == recovery ]]; then
  python3 "$root/tools/cser-experiment/uart_sink.py" \
    --socket "$artifact_dir/com3-crash.sock" --run-id "$run_id" --connect-timeout 90 \
    --catalog-digest "$catalog_digest" \
    --namespace-id "$namespace" --authority-id "$authority_id" --effect-id "$effect_id" \
    --startup-ready-file "$sink_ready" --status-file "$sink_status" 2>>"$sink_log" &
  crash_sink_pid=$!
  wait_for_startup_ready recovery-receipt "$crash_sink_pid" "$sink_ready"
fi

# The x command starts QEMU (and its swtpm peer) in the exact reviewed scheme.
# Its serial output is forwarded unchanged; matrix_controller parses the
# recovery marker from this stream instead of trusting host-created metrics.
if ! "$root/x" run-tool-dma-boot "$scheme"; then
  stage_fail guest-boot "QEMU launcher exited nonzero; bridge=$(signal_detail "$bridge_status") sink=$(signal_detail "$sink_status")"
fi

if [[ $phase == recovery ]]; then
  wait_for_terminal_helper bridge-ready "$bridge_pid" "$bridge_status" served-or-unused
  bridge_pid=
  wait_for_terminal_helper recovery-receipt "$crash_sink_pid" "$sink_status" closed
  crash_sink_pid=
fi

# Preserve the terminal durable files with the row once recovery has finished;
# otherwise the next sequential row would overwrite the fixed OSDK envelope.
if [[ $phase == recovery ]]; then
  for name in journal.raw outbox.raw ram.raw; do
    cp --reflink=auto --preserve=mode,timestamps "$artifact_dir/$name" "$trial_dir/media/$name"
  done
fi
