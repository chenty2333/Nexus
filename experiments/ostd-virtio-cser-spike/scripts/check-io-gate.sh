#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
experiment_root=$(cd "$script_dir/.." && pwd)
repo_root=$(cd "$experiment_root/../.." && pwd)
source_file=${1:-$repo_root/crates/nexus-ostd-virtio/src/portal.rs}
entry_file=${2:-$experiment_root/src/lib.rs}

require_literal() {
    local literal=$1
    if ! grep -Fq "$literal" "$source_file"; then
        echo "Stage 7B I/O adapter lacks required transition: $literal" >&2
        exit 1
    fi
}

for literal in \
    'pub type EffectAuthority = IoIdentity;' \
    'fn portal_instance_id(device_function: DeviceFunction) -> u64 {' \
    'device_function.valid(),' \
    '"invalid PCI device function namespace"' \
    '(u64::from(device_function.bus) << 24)' \
    '(u64::from(device_function.device) << 19)' \
    '(u64::from(device_function.function) << 16)' \
    'u64::from(QUEUE_INDEX)' \
    'let instance_id = portal_instance_id(device_function);' \
    'IoGate::new(instance_id)' \
    'device_function: DeviceFunction,' \
    'fn bind_session_authority(' \
    'authority.instance_id() != self.gate.instance_id()' \
    'portal_instance_id(self.device_function) != self.gate.instance_id()' \
    'pub fn open_session(' \
    'let binding = self.bind_session_authority(authority)?;' \
    'Ok(Session::open_bound(root, binding))' \
    'fn open_bound(root: &mut Root, binding: SessionBinding)' \
    'pub fn assert_session_namespace_isolation() -> SessionNamespaceIsolationReceipt {' \
    'pub struct SessionNamespaceIsolationReceipt {' \
    'pub const fn into_marker(self) -> &'"'"'static str {' \
    'SessionNamespaceIsolationReceipt {' \
    'marker: "IO Namespace foreign_bdf_rejected=true bidirectional=true portal_state_unchanged=true pre_pci_dma=true",' \
    'left.bind_session_authority(right_authority)' \
    'right.bind_session_authority(left_authority)' \
    'assert_eq!(left.state_projection(), left_before);' \
    'assert_eq!(right.state_projection(), right_before);' \
    'gate: IoGate<4>,' \
    '.commit_with(authority' \
    '.can_complete_device(authority)' \
    '.begin_closing()' \
    '.begin_reset(close)' \
    '.apply_reset(receipt)' \
    '.begin_iotlb::<3>(outcome)' \
    '.mark_quiesced(closure.gate)' \
    '.rebind_after_quiescence()' \
    'gate_attempt: Option<GateResetAttempt>,' \
    'gate_tombstone: Option<GateResetTombstone>,' \
    'gate: GateIotlbTombstone<3>,' \
    'gate_closure_progress(' \
    'dma::begin_closure(reset.closure_authority, inject_one_pending)'; do
    require_literal "$literal"
done

if grep -Eq '^[[:space:]]+(authority_epoch|binding_epoch|device_generation|next_request_id): u64,' \
    "$source_file"; then
    echo 'Stage 5B Portal regained a shadow authority/binding/device epoch' >&2
    exit 1
fi
if grep -Eq 'struct EffectRecord|enum PortalPhase|effects: \[Option<EffectRecord>' \
    "$source_file"; then
    echo 'Stage 5B Portal regained a shadow commit/terminal effect ledger' >&2
    exit 1
fi
if grep -Fq 'let mut probe = self.gate' "$source_file"; then
    echo 'Stage 7B I/O adapter copied the unique IoGate owner' >&2
    exit 1
fi
if grep -Fq 'pub fn open(' "$source_file"; then
    echo 'Stage 7B I/O adapter exposed an unbound raw Session constructor' >&2
    exit 1
fi

negative_call='let namespace_isolation = assert_session_namespace_isolation();'
negative_marker='println!("{}", namespace_isolation.into_marker());'
raw_marker='IO Namespace foreign_bdf_rejected=true bidirectional=true portal_state_unchanged=true pre_pci_dma=true'
discovery_call='let mut root = match discover_and_own_bars() {'
discovery_failure='Err(error) => {'
discovery_failure_action='poweroff(ExitCode::Failure)'
for literal in "$negative_call" "$negative_marker" "$discovery_call" "$discovery_failure" "$discovery_failure_action"; do
    if [[ $(grep -Fc "$literal" "$entry_file") -ne 1 ]]; then
        echo "Stage 7B I/O entrypoint must contain one exact namespace-negative step: $literal" >&2
        exit 1
    fi
done
negative_line=$(grep -nF "$negative_call" "$entry_file" | cut -d: -f1)
marker_line=$(grep -nF "$negative_marker" "$entry_file" | cut -d: -f1)
discovery_line=$(grep -nF "$discovery_call" "$entry_file" | cut -d: -f1)
if ! ((negative_line < marker_line && marker_line < discovery_line)); then
    echo 'Stage 7B I/O namespace negative must execute before its marker and before PCI/DMA discovery' >&2
    exit 1
fi
if grep -Fq 'if false {' "$entry_file"; then
    echo 'Stage 7B I/O entrypoint conditionally suppressed a required namespace negative' >&2
    exit 1
fi
if grep -Fq "$raw_marker" "$entry_file"; then
    echo 'Stage 7B I/O entrypoint fabricated the namespace marker without its typed receipt' >&2
    exit 1
fi

echo 'Stage 7B I/O gate adapter: PASS authority_identity=delegated session_device_instance=bound pre_pci_dma_negative=executed commit_gate=shared reset_typestate=shared iotlb_typestate=shared shadow_ledger=false'
