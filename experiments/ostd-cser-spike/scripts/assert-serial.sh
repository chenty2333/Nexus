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
    "OSTD_PROBE PASS wrappers=wait+timer carry_effect_token=true authority_epoch=41"
    "PAGER_SCENARIO BEGIN scenario=recover scope=20 fault=1 scheduler_mode=kernel_fifo_fallback"
    "PAGER Register scenario=recover scope=20 fault=1 authority_epoch=71 binding_epoch=1 as=1 as_generation=1 thread=300 addr=0x401000 access_bits=0x4 rip=0x400005"
    "PAGER PrepareZero scenario=recover fault=1 binding_epoch=1 owner=kernel credit=Held"
    "PAGER Crash scenario=recover supervisor=301 previous_binding_epoch=1 binding_epoch=2"
    "PAGER REJECT_STALE scenario=recover stage=post_crash action=Commit proposal_binding_epoch=1 current_binding_epoch=2 vm_mutation=false"
    "PAGER Fallback scenario=recover binding_epoch=2 action=close_reply_gate+retain+watchdog"
    "PAGER FreshSpawn scenario=recover task=303 vm=fresh user_mode=constructed_in_task binding_epoch=2"
    "PAGER RecoverySnapshot scenario=recover replacement=303 binding_epoch=2 fault=1 phase=Prepared prepared=true"
    "PAGER Ready scenario=recover replacement=303 binding_epoch=2"
    "PAGER REJECT_NO_SUPERVISOR scenario=recover stage=pre_rebind action=Commit proposal_binding_epoch=2 vm_mutation=false"
    "PAGER Rebind scenario=recover replacement=303 binding_epoch=2 epoch_advanced=false pager_fallback=Standby"
    "PAGER REJECT_STALE scenario=recover stage=post_rebind action=Commit proposal_binding_epoch=1 current_binding_epoch=2 vm_mutation=false"
    "PAGER RecoverNext scenario=recover replacement=303 fault=1 old_binding_epoch=1 phase=Prepared"
    "PAGER Adopt scenario=recover replacement=303 fault=1 old_binding_epoch=1 binding_epoch=2 explicit=true"
    "PAGER Commit scenario=recover replacement=303 fault=1 binding_epoch=2 pte_published=true credit=Spent"
    "PAGER TlbSync scenario=recover fault=1 issue=true dispatch=true synchronize=true cpu=local"
    "PAGER Complete scenario=recover fault=1 terminal=Completed wake=one-shot"
    "PAGER ClientResume scenario=recover fault=1 same_rip=true value=0 terminal=Resolved"
    "PAGER_SCENARIO PASS scenario=recover terminalizations=1"
    "PAGER_SCENARIO BEGIN scenario=timeout scope=21 fault=2 scheduler_mode=kernel_fifo_fallback"
    "PAGER Register scenario=timeout scope=21 fault=2 authority_epoch=71 binding_epoch=1 as=1 as_generation=1 thread=310 addr=0x401000 access_bits=0x4 rip=0x400005"
    "PAGER PrepareZero scenario=timeout fault=2 binding_epoch=1 owner=kernel credit=Held"
    "PAGER Crash scenario=timeout supervisor=311 previous_binding_epoch=1 binding_epoch=2"
    "PAGER REJECT_STALE scenario=timeout stage=post_crash action=Commit proposal_binding_epoch=1 current_binding_epoch=2 vm_mutation=false"
    "PAGER WatchdogArm scenario=timeout binding_epoch=2"
    "PAGER RevokeBegin scenario=timeout scope=21 old_authority_epoch=71 authority_epoch=72 reason=watchdog_timeout scope_phase=Closing reply_gate=closed cleanup_inflight=true wake_pending=true credit=Held"
    "PAGER CleanupDrop scenario=timeout fault=2 prepared_dropped=true outside_lock=true cleanup_inflight=true wake_pending=true credit=Held"
    "PAGER Abort scenario=timeout fault=2 terminal=Aborted prepared_dropped=true credit=Held cleanup_inflight=true wake_pending=true wake_published=true waker_dropped=true"
    "PAGER RevokeComplete scenario=timeout scope=21 authority_epoch=72 live_effects=0 retained_frames=0 cleanup_inflight=false wake_pending=false wake_published=true waker_dropped=true credit=Returned pager_fallback=Standby"
    "PAGER ClientExit scenario=timeout fault=2 terminal=Aborted cooperative=true"
    "PAGER_SCENARIO PASS scenario=timeout terminalizations=1"
    "PAGER_SLICE PASS scenarios=recover+timeout single_cpu=true zero_page=true single_client=true task_kill=false"
    "CSER Rebind authority_epoch=41 binding_epoch=2"
    "CSER REJECT_STALE action=Prepare authority_epoch=41 proposal_binding_epoch=1 current_binding_epoch=2 proposal_task=100"
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

if [[ $(grep -cF 'PAGER Complete scenario=recover fault=1 terminal=Completed' "$log") -ne 1 ]]; then
    echo "recover fault did not complete exactly once" >&2
    exit 1
fi

if [[ $(grep -cF 'PAGER REJECT_NO_SUPERVISOR scenario=recover stage=pre_rebind action=Commit' "$log") -ne 1 ]]; then
    echo "recover path did not reject exactly one pre-rebind reply" >&2
    exit 1
fi

if [[ $(grep -cF 'PAGER REJECT_STALE scenario=recover stage=post_rebind action=Commit' "$log") -ne 1 ]]; then
    echo "recover path did not reject exactly one post-rebind stale reply" >&2
    exit 1
fi

if [[ $(grep -cF 'PAGER Abort scenario=timeout fault=2 terminal=Aborted' "$log") -ne 1 ]]; then
    echo "timeout fault did not abort exactly once" >&2
    exit 1
fi

if [[ $(grep -cF 'PAGER RevokeBegin scenario=timeout scope=21' "$log") -ne 1 ]]; then
    echo "timeout scope did not publish RevokeBegin exactly once" >&2
    exit 1
fi

if [[ $(grep -cF 'PAGER RevokeComplete scenario=timeout scope=21' "$log") -ne 1 ]]; then
    echo "timeout scope did not publish RevokeComplete exactly once" >&2
    exit 1
fi

if [[ $(grep -cF 'PAGER ClientResume scenario=recover fault=1' "$log") -ne 1 ]]; then
    echo "recover client did not resume exactly once" >&2
    exit 1
fi

if [[ $(grep -cF 'PAGER CleanupDrop scenario=timeout fault=2 prepared_dropped=true outside_lock=true' "$log") -ne 1 ]]; then
    echo "timeout fault did not clean its retained frame exactly once outside the state lock" >&2
    exit 1
fi

for forbidden in \
    'PAGER Commit scenario=timeout' \
    'PAGER Complete scenario=timeout' \
    'PAGER ClientResume scenario=timeout' \
    'PAGER RevokeComplete scenario=timeout scope=21 authority_epoch=72 live_effects=0 retained_frames=0 cleanup_inflight=true' \
    'PAGER RevokeComplete scenario=timeout scope=21 authority_epoch=72 live_effects=0 retained_frames=0 cleanup_inflight=false wake_pending=true' \
    'CSER Crash authority_epoch=41 previous_binding_epoch=2 binding_epoch=3' \
    'panicked at' \
    'Non-resettable panic!'; do
    if grep -Fq "$forbidden" "$log"; then
        echo "forbidden serial evidence: $forbidden" >&2
        exit 1
    fi
done

echo "serial assertions: PASS"
