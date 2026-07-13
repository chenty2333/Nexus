#!/usr/bin/env bash
set -euo pipefail

source_file=${1:-src/portal.rs}

require_literal() {
    local literal=$1
    if ! grep -Fq "$literal" "$source_file"; then
        echo "Stage 7B I/O adapter lacks required transition: $literal" >&2
        exit 1
    fi
}

for literal in \
    'pub type EffectAuthority = IoIdentity;' \
    'gate: IoGate<4>,' \
    '.commit_with(authority' \
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

echo 'Stage 7B I/O gate adapter: PASS authority_identity=delegated commit_gate=shared reset_typestate=shared iotlb_typestate=shared shadow_ledger=false'
