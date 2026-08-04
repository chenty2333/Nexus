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
phase=${CSER_EXPERIMENT_PHASE:-initial}

case "$variant" in
  cser) scheme=tool-dma-cser; artifact_dir="$root/artifacts/tool-dma-cser" ;;
  baseline) scheme=tool-dma-baseline; artifact_dir="$root/artifacts/tool-dma-baseline" ;;
  *) echo "qemu_boot: invalid variant: $variant" >&2; exit 2 ;;
esac
case "$phase" in initial|recovery) ;; *) echo "qemu_boot: invalid phase: $phase" >&2; exit 2 ;; esac
[[ $run_id =~ ^[0-9a-f]{32}$ ]] || { echo "qemu_boot: invalid run id" >&2; exit 2; }
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
rm -f -- "$port_file"
endpoint_pid=
bridge_pid=
crash_sink_pid=
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
  --database "$database" --port 0 --port-file "$port_file" &
endpoint_pid=$!
for _ in {1..100}; do
  if [[ -s $port_file ]]; then break; fi
  kill -0 "$endpoint_pid" 2>/dev/null || { echo "qemu_boot: endpoint failed to start" >&2; exit 1; }
  sleep .05
done
[[ -s $port_file ]] || { echo "qemu_boot: endpoint did not publish its port" >&2; exit 1; }
port=$(<"$port_file")
[[ $port =~ ^[1-9][0-9]*$ && $port -le 65535 ]] || { echo "qemu_boot: endpoint published invalid port" >&2; exit 1; }
for _ in {1..100}; do
  if python3 - "$port" <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=.1)
s.close()
PY
  then break; fi
  sleep .05
done
kill -0 "$endpoint_pid" 2>/dev/null || { echo "qemu_boot: endpoint failed to start" >&2; exit 1; }

python3 "$root/tools/cser-experiment/uart_http_bridge.py" \
  --socket "$artifact_dir/com2-tool.sock" --run-id "$run_id" --endpoint-port "$port" \
  --connect-timeout 90 --request-timeout 90 &
bridge_pid=$!

# COM3 uses wait=on so no initial crash barrier can be lost before the matrix
# controller connects. Recovery deliberately has no crash cutpoints, but QEMU
# still requires a peer before boot; this sink holds the channel open and
# fails if the recovered guest unexpectedly emits a barrier.
if [[ $phase == recovery ]]; then
  python3 "$root/tools/cser-experiment/uart_sink.py" \
    --socket "$artifact_dir/com3-crash.sock" --run-id "$run_id" --connect-timeout 90 &
  crash_sink_pid=$!
fi

# The x command starts QEMU (and its swtpm peer) in the exact reviewed scheme.
# Its serial output is forwarded unchanged; matrix_controller parses the
# recovery marker from this stream instead of trusting host-created metrics.
"$root/x" run-tool-dma-boot "$scheme"

if [[ $phase == recovery ]]; then
  wait "$crash_sink_pid"
  crash_sink_pid=
fi

# Preserve the terminal durable files with the row once recovery has finished;
# otherwise the next sequential row would overwrite the fixed OSDK envelope.
if [[ $phase == recovery ]]; then
  for name in journal.raw outbox.raw ram.raw; do
    cp --reflink=auto --preserve=mode,timestamps "$artifact_dir/$name" "$trial_dir/media/$name"
  done
fi
