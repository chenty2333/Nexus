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
provider_delay_ms=${CSER_EXPERIMENT_PROVIDER_DELAY_MS:-0}
worker_count=${CSER_EXPERIMENT_WORKER_COUNT:-1}
background_jobs=${CSER_EXPERIMENT_BACKGROUND_JOBS:-0}
lane=${CSER_EXPERIMENT_LANE:-tool-dma}

case "$lane" in
  tool-dma|handoff) ;;
  *) echo "qemu_boot: invalid experiment lane: $lane" >&2; exit 2 ;;
esac
case "$variant:$lane" in
  cser:tool-dma)
    if [[ ${CSER_EXPERIMENT_JOURNAL_VNEXT:-0} == 1 ]]; then
      scheme=tool-dma-cser-vnext
      artifact_dir="$root/artifacts/tool-dma-cser-vnext"
    else
      scheme=tool-dma-cser
      artifact_dir="$root/artifacts/tool-dma-cser"
    fi
    ;;
  baseline:tool-dma) scheme=tool-dma-baseline; artifact_dir="$root/artifacts/tool-dma-baseline" ;;
  # This lane has deliberately separate artifacts from Tool+DMA. The baseline
  # scheme name is reserved here so the paired arm cannot accidentally inherit
  # the CSER envelope when its guest runtime lands.
  cser:handoff) scheme=tool-handoff-cser; artifact_dir="$root/artifacts/tool-handoff-cser" ;;
  baseline:handoff) scheme=tool-handoff-baseline; artifact_dir="$root/artifacts/tool-handoff-baseline" ;;
  *) echo "qemu_boot: invalid variant: $variant" >&2; exit 2 ;;
esac
[[ $lane != handoff || ${CSER_EXPERIMENT_JOURNAL_VNEXT:-0} != 1 ]] || {
  echo "qemu_boot: handoff lane does not select the vNext journal" >&2
  exit 2
}
case "$phase" in initial|recovery) ;; *) echo "qemu_boot: invalid phase: $phase" >&2; exit 2 ;; esac
[[ $run_id =~ ^[0-9a-f]{32}$ ]] || { echo "qemu_boot: invalid run id" >&2; exit 2; }
[[ $catalog_digest =~ ^[0-9a-f]{64}$ ]] || { echo "qemu_boot: invalid catalog digest" >&2; exit 2; }
[[ $namespace =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] || { echo "qemu_boot: invalid namespace" >&2; exit 2; }
[[ $authority_id =~ ^[0-9a-f]{32}$ ]] || { echo "qemu_boot: invalid authority" >&2; exit 2; }
[[ $effect_id =~ ^[0-9a-f]{32}$ ]] || { echo "qemu_boot: invalid effect" >&2; exit 2; }
[[ -d $trial_dir/media ]] || { echo "qemu_boot: trial media is missing" >&2; exit 2; }
[[ $provider_delay_ms =~ ^[0-9]+$ ]] || { echo "qemu_boot: invalid provider delay" >&2; exit 2; }
[[ $worker_count =~ ^[1-9][0-9]*$ ]] || { echo "qemu_boot: invalid worker count" >&2; exit 2; }
[[ $background_jobs =~ ^[0-9]+$ && $background_jobs -le 4096 ]] || { echo "qemu_boot: invalid background job count" >&2; exit 2; }

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
fi

# A crash-killed QEMU leaves its Unix socket path behind. Remove those stale
# inodes before every boot so recovery helpers cannot race or attach to the
# prior boot's transport endpoint. The new QEMU instance remains the sole
# publisher of both wait=on sockets.
rm -f "$artifact_dir/com2-tool.sock" "$artifact_dir/com3-crash.sock" "$artifact_dir/swtpm-qemu.sock"

database="$trial_dir/tool-endpoint.sqlite"
provider_database=
port_file="$trial_dir/tool-endpoint.port"
endpoint_log="$trial_dir/endpoint.stderr.log"
child_database=
child_provider_database=
child_port_file=
child_endpoint_log=
child_effect_id=
bridge_ready="$trial_dir/bridge.startup-ready.json"
bridge_status="$trial_dir/bridge.status.json"
bridge_log="$trial_dir/bridge.stderr.log"
sink_ready="$trial_dir/recovery-sink.startup-ready.json"
sink_status="$trial_dir/recovery-sink.status.json"
sink_log="$trial_dir/recovery-sink.stderr.log"
rm -f -- "$port_file" "$bridge_ready" "$bridge_status" "$sink_ready" "$sink_status"
endpoint_pid=
child_endpoint_pid=
bridge_pid=
crash_sink_pid=
background_pid=

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
      elif [[ $expected == served-or-unused-or-deferred ]] \
        && { grep -Fq '"state": "served"' "$signal_file" \
          || grep -Fq '"state": "unused"' "$signal_file" \
          || grep -Fq '"state": "deferred"' "$signal_file"; }; then
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
  [[ -z ${child_endpoint_pid:-} ]] || kill "$child_endpoint_pid" 2>/dev/null || true
  [[ -z ${background_pid:-} ]] || kill "$background_pid" 2>/dev/null || true
  wait "${crash_sink_pid:-}" 2>/dev/null || true
  wait "${bridge_pid:-}" 2>/dev/null || true
  wait "${endpoint_pid:-}" 2>/dev/null || true
  wait "${child_endpoint_pid:-}" 2>/dev/null || true
  wait "${background_pid:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

start_endpoint() {
  local stage=$1 database_path=$2 provider_database_path=$3 effect=$4 endpoint_port_file=$5 endpoint_stderr_log=$6
  local endpoint_args=(
    --database "$database_path"
    --namespace "$namespace" --authority-id "$authority_id" --effect-id "$effect" --catalog-digest "$catalog_digest"
    --port 0 --port-file "$endpoint_port_file" --provider-delay-ms "$provider_delay_ms" --worker-count "$worker_count"
  )
  [[ -z $provider_database_path ]] || endpoint_args+=(--provider-database "$provider_database_path")
  python3 "$root/tools/cser-experiment/tool_endpoint.py" "${endpoint_args[@]}" 2>>"$endpoint_stderr_log" &
  local pid=$!
  for _ in {1..100}; do
    if [[ -s $endpoint_port_file ]]; then break; fi
    kill -0 "$pid" 2>/dev/null || stage_fail "$stage" "endpoint exited before publishing a port; see $endpoint_stderr_log"
    sleep .05
  done
  [[ -s $endpoint_port_file ]] || stage_fail "$stage" "endpoint did not publish its port; see $endpoint_stderr_log"
  local endpoint_port
  endpoint_port=$(<"$endpoint_port_file")
  [[ $endpoint_port =~ ^[1-9][0-9]*$ && $endpoint_port -le 65535 ]] || stage_fail "$stage" "endpoint published invalid port"
  local endpoint_ready=false
  for _ in {1..100}; do
    if python3 - "$endpoint_port" <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=.1)
s.close()
PY
    then endpoint_ready=true; break; fi
    sleep .05
  done
  kill -0 "$pid" 2>/dev/null || stage_fail "$stage" "endpoint exited before accepting TCP; see $endpoint_stderr_log"
  [[ $endpoint_ready == true ]] || stage_fail "$stage" "endpoint did not accept TCP before deadline; see $endpoint_stderr_log"
  started_endpoint_pid=$pid
  started_endpoint_port=$endpoint_port
}

if [[ $lane == handoff ]]; then
  # Keep the two v3 stores and their provider ledgers physically distinct. The
  # child identity is a transport identity, not an alias of the parent effect.
  child_effect_id=$(PYTHONPATH="$root/tools/cser-experiment${PYTHONPATH:+:$PYTHONPATH}" python3 - "$namespace" "$authority_id" "$effect_id" "$run_id" "$catalog_digest" <<'PY'
import sys
from handoff_identity import child_transport_effect_id
print(child_transport_effect_id(*sys.argv[1:]))
PY
)
  [[ $child_effect_id =~ ^[0-9a-f]{32}$ ]] || stage_fail handoff-identity "derived invalid child effect id"
  database="$trial_dir/handoff-parent-endpoint.sqlite"
  provider_database="$trial_dir/handoff-parent-provider.sqlite"
  port_file="$trial_dir/handoff-parent-endpoint.port"
  endpoint_log="$trial_dir/handoff-parent-endpoint.stderr.log"
  child_database="$trial_dir/handoff-child-endpoint.sqlite"
  child_provider_database="$trial_dir/handoff-child-provider.sqlite"
  child_port_file="$trial_dir/handoff-child-endpoint.port"
  child_endpoint_log="$trial_dir/handoff-child-endpoint.stderr.log"
fi
rm -f -- "$port_file" "${child_port_file:-}"
start_endpoint endpoint-connect "$database" "$provider_database" "$effect_id" "$port_file" "$endpoint_log"
endpoint_pid=$started_endpoint_pid
port=$started_endpoint_port
if [[ $lane == handoff ]]; then
  start_endpoint child-endpoint-connect "$child_database" "$child_provider_database" "$child_effect_id" "$child_port_file" "$child_endpoint_log"
  child_endpoint_pid=$started_endpoint_pid
  child_port=$started_endpoint_port
fi

# The performance lane can submit bounded, distinct host-local provider jobs
# before boot. These are deliberately not guest effects or CSER claims. They
# merely keep the endpoint worker queue occupied so the primary guest request
# has an auditable concurrency overlap in the durable endpoint database.
if [[ $phase == initial && $background_jobs != 0 ]]; then
  python3 - "$port" "$namespace" "$authority_id" "$effect_id" "$run_id" "$catalog_digest" "$background_jobs" <<'PY' 2>>"$endpoint_log" &
import base64, hashlib, http.client, json, sys
port, namespace, authority, effect, run_id, catalog, count = sys.argv[1:]
payload = b"perf-background-v1"
encoded = base64.b64encode(payload).decode("ascii")
for index in range(int(count)):
    body = json.dumps({"contract_version": "3", "namespace_id": namespace,
        "authority_id": authority, "effect_id": effect, "run_id": run_id,
        "operation_key": f"perf-bg-{index}", "input_digest": hashlib.sha256(payload).hexdigest(),
        "catalog_digest": catalog, "payload_b64": encoded}, separators=(",", ":")).encode("utf-8")
    connection = http.client.HTTPConnection("127.0.0.1", int(port), timeout=5)
    try:
        connection.request("POST", "/v3/operations", body, {"Content-Type": "application/json"})
        if connection.getresponse().status != 202:
            raise SystemExit("background endpoint job was not accepted")
    finally:
        connection.close()
PY
  background_pid=$!
fi

bridge_args=(
  --socket "$artifact_dir/com2-tool.sock" --run-id "$run_id" --endpoint-port "$port"
  --namespace-id "$namespace" --authority-id "$authority_id" --effect-id "$effect_id" --catalog-digest "$catalog_digest"
  --connect-timeout 90 --request-timeout 90 --startup-ready-file "$bridge_ready"
  --status-file "$bridge_status"
)
if [[ $lane == handoff ]]; then
  bridge_args+=(--handoff-cser3 --child-endpoint-port "$child_port"
    --handoff-parent-root 0x48414e44 --handoff-parent-sequence 1 --handoff-parent-component 6)
else
  bridge_args+=(--cser2)
  [[ $phase != recovery ]] || bridge_args+=(--allow-no-request)
fi
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
  wait_for_terminal_helper bridge-ready "$bridge_pid" "$bridge_status" served-or-unused-or-deferred
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
