#!/usr/bin/env bash
set -euo pipefail

log=${1:?usage: assert-serial.sh SERIAL_LOG}

patterns=(
    "CSER Register authority_epoch=41 binding_epoch=1 effect=scheduler_policy"
    "CSER Prepare authority_epoch=41 binding_epoch=1 proposal_task=100"
    "CSER Commit authority_epoch=41 binding_epoch=1 proposal_task=100 state=Committed"
    "OSTD_PROBE UserMode return=UserSyscall VmSpace=active authority_epoch=41"
    "CSER Prepare authority_epoch=41 binding_epoch=1 proposal_task=200"
    "OSTD_PROBE UserMode return=UserException exception=PageFault addr=0x800000 authority_epoch=41"
    "CSER Crash authority_epoch=41 previous_binding_epoch=1 binding_epoch=2"
    "OSTD_PROBE PASS api=UserMode+VmSpace syscall=true page_fault=true authority_epoch=41"
    "CSER FallbackPick authority_epoch=41 binding_epoch=2 task=200"
    "OSTD_PROBE PASS fallback_latency_ticks="
    "CSER REJECT_NO_SUPERVISOR action=Prepare authority_epoch=41 binding_epoch=2 proposal_task=100"
    "CSER Rebind authority_epoch=41 binding_epoch=2"
    "CSER REJECT_STALE action=Prepare authority_epoch=41 proposal_binding_epoch=1 current_binding_epoch=2 proposal_task=100"
    "OSTD_PROBE PASS wrappers=wait+timer carry_effect_token=true authority_epoch=41"
    "IOMMU_PROBE PASS result=FAIL_CLOSED reason=IOTLB_INVALIDATION_UNAVAILABLE ostd=0.18.0 authority_epoch=41"
    "SPIKE_RESULT PASS"
)

previous=0
for pattern in "${patterns[@]}"; do
    line=$(grep -nF -m1 "$pattern" "$log" | cut -d: -f1)
    if [[ -z "$line" ]]; then
        echo "missing serial assertion: $pattern" >&2
        exit 1
    fi
    if (( line < previous )); then
        echo "out-of-order serial assertion: $pattern" >&2
        exit 1
    fi
    previous=$line
done

if ! grep -Eq 'OSTD_PROBE PASS fallback_latency_ticks=[01] bound_ticks=1 authority_epoch=41 binding_epoch=2' "$log"; then
    echo "fallback latency exceeded the one-tick bound" >&2
    exit 1
fi

echo "serial assertions: PASS"
