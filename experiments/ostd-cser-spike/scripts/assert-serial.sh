#!/usr/bin/env bash
set -euo pipefail

log=${1:?usage: assert-serial.sh SERIAL_LOG}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

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
    "OSTD_PROBE PASS fallback_first_task=200 fallback_first_selection_attempt=1 observed_tick_delta="
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
    "LINUX_ELF MapPlan workload=linux-hello vaddr=0x400000"
    "LINUX_ELF MapPlan workload=linux-hello vaddr=0x401000"
    "publication=lazy-file-backed"
    "LINUX_ELF MapPlan workload=linux-hello vaddr=0x402000"
    "LINUX_ELF InitialStack workload=linux-hello"
    "argc=1 argv=1 envp=0 auxv=9 aligned16=true rw=true executable=false"
    "LINUX_ELF Loaded workload=linux-hello parser=object-0.39.1 format=ELF64 type=ET_EXEC arch=x86_64 static=true"
    "entry_publication=lazy-file-backed"
    "wx=false overlap=false"
    "LINUX_SLICE BEGIN workload=linux-hello format=ELF64 type=ET_EXEC"
    "scheduler_mode=user_policy_then_kernel_fifo_fallback scheduler_binding_epoch=2"
    "LINUX_CODE_PAGER Start workload=linux-hello effect=3 authority_epoch=91 scope=30"
    "CSER Prepare authority_epoch=41 binding_epoch=2 proposal_task=404"
    "CSER Commit authority_epoch=41 binding_epoch=2 proposal_task=404 state=Committed"
    "LINUX_SCHEDULER Register workload=linux-hello policy=404 workload_authority_epoch=91 scope=30 effect=0 scheduler_binding_epoch=2"
    "CSER PrepareScoped service=scheduler scheduler_authority_epoch=41 binding_epoch=2 workload_authority_epoch=91 scope=30 effect=0 proposal_task=400"
    "CSER Crash authority_epoch=41 previous_binding_epoch=2 binding_epoch=3"
    "reason=linux_scheduler_policy_user_page_fault"
    "CSER CrashScoped service=scheduler scheduler_authority_epoch=41 binding_epoch=3 workload_authority_epoch=91 scope=30 effect=0 pending_scoped_cleared=true fallback=kernel_fifo"
    "LINUX_SCHEDULER_POLICY EXIT workload=linux-hello policy=404 reason=real_user_page_fault guest_proposal_committed=false"
    "CSER FallbackPick authority_epoch=41 binding_epoch=3 task=400"
    "LINUX_CODE_PAGER Register workload=linux-hello effect=3 authority_epoch=91 scope=30 binding_epoch=1 thread=400"
    "access_bits=0x14 backing=elf-image"
    "LINUX_CODE_PAGER GuestBlocked workload=linux-hello effect=3 thread=400"
    "LINUX_CODE_PAGER PrepareImage workload=linux-hello effect=3 binding_epoch=1 bytes=4096"
    "owner=kernel pte_published=false"
    "LINUX_CODE_PAGER Crash workload=linux-hello supervisor=410 previous_binding_epoch=1 binding_epoch=2"
    "image_frame_retained=true pte_published=false"
    "LINUX_CODE_PAGER REJECT_STALE workload=linux-hello stage=post_crash action=MapAndWake effect=3"
    "LINUX_CODE_PAGER Fallback workload=linux-hello binding_epoch=2"
    "LINUX_CODE_PAGER FreshSpawn workload=linux-hello task=412 vm=fresh user_mode=constructed_in_task binding_epoch=2"
    "LINUX_CODE_PAGER RecoverySnapshot workload=linux-hello replacement=412 binding_epoch=2 effect=3 phase=Prepared image_frame=true"
    "LINUX_CODE_PAGER Ready workload=linux-hello replacement=412 binding_epoch=2"
    "LINUX_CODE_PAGER REJECT_NO_SUPERVISOR workload=linux-hello stage=pre_rebind action=MapAndWake effect=3"
    "LINUX_CODE_PAGER Rebind workload=linux-hello replacement=412 binding_epoch=2"
    "LINUX_CODE_PAGER REJECT_STALE workload=linux-hello stage=post_rebind action=MapAndWake effect=3"
    "LINUX_CODE_PAGER RecoverNext workload=linux-hello replacement=412 effect=3 old_binding_epoch=1 phase=Prepared"
    "LINUX_CODE_PAGER Adopt workload=linux-hello replacement=412 effect=3 old_binding_epoch=1 binding_epoch=2 explicit=true"
    "LINUX_CODE_PAGER Commit workload=linux-hello replacement=412 effect=3 binding_epoch=2 backing=elf-image"
    "permissions=RX pte_published=true"
    "LINUX_CODE_PAGER TlbSync workload=linux-hello effect=3 issue=true dispatch=true synchronize=true cpu=local single_cpu=true"
    "LINUX_CODE_PAGER Complete workload=linux-hello effect=3 terminal=Completed wake=one-shot pte=RX same_rip=true"
    "LINUX_CODE_PAGER GuestResume workload=linux-hello effect=3 thread=400"
    "same_rip=true resume_returns=1"
    "LINUX_SYSCALL Capture workload=linux-hello effect=1 kind=write nr=1 fd=1"
    "authority_epoch=91 binding_epoch=1"
    "LINUX_PORTAL Deliver workload=linux-hello personality=401 effect=1 binding_epoch=1 immutable_snapshot=true guest_context_writable=false"
    "LINUX_PERSONALITY Dispatch workload=linux-hello personality=401 kind=write nr=1 user_mode=true uapi=linux-raw-sys-0.12.1"
    "LINUX_SYSCALL Prepare workload=linux-hello effect=1 kind=write binding_epoch=1 guest_bytes_copied=23 owner=kernel"
    "LINUX_GUEST stdout=hello from linux-hello"
    "LINUX_SYSCALL BackendCommit workload=linux-hello personality=401 effect=1 kind=write binding_epoch=1 result=Committed output_publications=1 guest_reply_pending=true"
    "LINUX_PORTAL Queue workload=linux-hello sender=401 action=Reply effect=1 authority_epoch=91 scope=30 task=400 operation=1 binding_epoch=1 delivery=after_crash"
    "LINUX_PERSONALITY Crash workload=linux-hello supervisor=401 previous_binding_epoch=1 binding_epoch=2 reason=user_page_fault backend_committed=true guest_reply_pending=true"
    "LINUX_SYSCALL REJECT_STALE workload=linux-hello stage=post_crash action=Reply effect=1"
    "LINUX_PORTAL Projection action=post_crash sender=401 opcode=0x4c520002 authority_epoch=91 scope=30 effect=1 task=400 operation=1 binding_epoch=1 result=StaleBinding mutation=false"
    "LINUX_PERSONALITY Fallback workload=linux-hello binding_epoch=2"
    "LINUX_PERSONALITY FreshSpawn workload=linux-hello task=403 vm=fresh user_mode=constructed_in_task binding_epoch=2"
    "LINUX_PERSONALITY RecoverySnapshot workload=linux-hello replacement=403 binding_epoch=2 effect=1 phase=BackendCommitted output_obligation=retained guest_reply_pending=true"
    "LINUX_PERSONALITY Ready workload=linux-hello replacement=403 binding_epoch=2"
    "LINUX_SYSCALL REJECT_NO_SUPERVISOR workload=linux-hello stage=pre_rebind action=Reply effect=1"
    "LINUX_PERSONALITY Rebind workload=linux-hello replacement=403 binding_epoch=2"
    "LINUX_SYSCALL REJECT_STALE workload=linux-hello stage=post_rebind action=Reply effect=1"
    "LINUX_SYSCALL RecoverNext workload=linux-hello replacement=403 effect=1 old_binding_epoch=1 phase=BackendCommitted"
    "LINUX_PERSONALITY Dispatch workload=linux-hello personality=403 kind=write nr=1 user_mode=true recovered=true uapi=linux-raw-sys-0.12.1"
    "LINUX_SYSCALL Adopt workload=linux-hello replacement=403 effect=1 old_binding_epoch=1 binding_epoch=2 explicit=true"
    "LINUX_SYSCALL BackendCommit workload=linux-hello personality=403 effect=1 kind=write binding_epoch=2 result=AlreadyCommitted output_publications=1 guest_reply_pending=true"
    "LINUX_SYSCALL Reply workload=linux-hello replacement=403 effect=1 kind=write binding_epoch=2 backend_replayed=false guest_resume=one-shot terminal=Completed"
    "LINUX_SYSCALL Capture workload=linux-hello effect=2 kind=exit_group nr=231 status=0 authority_epoch=91 binding_epoch=2"
    "LINUX_PORTAL Deliver workload=linux-hello personality=403 effect=2 binding_epoch=2 immutable_snapshot=true guest_context_writable=false"
    "LINUX_PERSONALITY Dispatch workload=linux-hello personality=403 kind=exit_group nr=231 user_mode=true uapi=linux-raw-sys-0.12.1"
    "LINUX_SYSCALL Commit workload=linux-hello replacement=403 effect=2 kind=exit_group binding_epoch=2 terminal=Completed"
    "LINUX_GUEST Exit workload=linux-hello status=0 resumed_after_exit=false terminal=Exited"
    "LINUX_SCHEDULER PASS workload=linux-hello policy=404 fallback_first_task=400 fallback_first_selection_attempt=1 observed_tick_delta="
    "LINUX_CODE_PAGER PASS workload=linux-hello effect=3 backing=elf-image pager_crash_rebind=true old_binding_rejections=2 terminalizations=1 wake_publications=1 resume_returns=1 permissions=RX same_rip=true single_cpu=true bounded=true"
    "LINUX_SLICE PASS workload=linux-hello write=true exit_group=true personality_crash_rebind=true stale_reply_fenced=true terminalizations=2 output_publications=1"
    "CSER REJECT_STALE action=Prepare authority_epoch=41 proposal_binding_epoch=1 current_binding_epoch=3 proposal_task=100"
    "IOMMU_PROBE PASS result=FAIL_CLOSED reason=IOTLB_INVALIDATION_UNAVAILABLE ostd=0.18.0 authority_epoch=41"
    "SPIKE_RESULT PASS"
)

previous=0
for pattern in "${patterns[@]}"; do
    line=$(grep -nF -m1 "$pattern" "$log" | cut -d: -f1 || true)
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

awk '
    function fail(message) {
        print "fallback trace assertion failed: " message > "/dev/stderr"
        failed = 1
        exit 1
    }
    function field(name,    i, prefix) {
        prefix = name "="
        for (i = 1; i <= NF; i++) {
            if (index($i, prefix) == 1)
                return substr($i, length(prefix) + 1)
        }
        return ""
    }
    {
        sub(/\r$/, "")
    }
    /^CSER Crash authority_epoch=41 previous_binding_epoch=1 binding_epoch=2 / {
        base_crashes++
        if (field("tick") !~ /^[0-9]+$/)
            fail("base crash has a non-numeric tick: " $0)
        base_crash_tick = field("tick") + 0
    }
    /^CSER Crash authority_epoch=41 previous_binding_epoch=2 binding_epoch=3 / {
        linux_crashes++
        if (field("tick") !~ /^[0-9]+$/)
            fail("Linux crash has a non-numeric tick: " $0)
        linux_crash_tick = field("tick") + 0
    }
    /^CSER FallbackPick authority_epoch=41 binding_epoch=2 / {
        base_attempts_seen++
        if (field("tick") !~ /^[0-9]+$/ || field("selection_attempt") != base_attempts_seen)
            fail("base fallback attempts are not dense numeric ordinals: " $0)
        if (field("selection_attempt") == "1")
            base_first_attempts++
        if (!base_pick_seen) {
            base_pick_seen = 1
            if (field("task") != "200" || field("selection_attempt") != "1")
                fail("base first pick was not task 200 on selection attempt 1: " $0)
            base_pick_tick = field("tick") + 0
        }
    }
    /^CSER FallbackPick authority_epoch=41 binding_epoch=3 / {
        linux_attempts_seen++
        if (field("tick") !~ /^[0-9]+$/ || field("selection_attempt") != linux_attempts_seen)
            fail("Linux fallback attempts are not dense numeric ordinals: " $0)
        if (field("selection_attempt") == "1")
            linux_first_attempts++
        if (!linux_pick_seen) {
            linux_pick_seen = 1
            if (field("task") != "400" || field("selection_attempt") != "1")
                fail("Linux first pick was not task 400 on selection attempt 1: " $0)
            linux_pick_tick = field("tick") + 0
        }
    }
    /^OSTD_PROBE PASS fallback_first_task=/ {
        base_passes++
        if ($0 !~ /^OSTD_PROBE PASS fallback_first_task=200 fallback_first_selection_attempt=1 observed_tick_delta=[0-9]+ tick_delta_diagnostic=true authority_epoch=41 binding_epoch=2$/)
            fail("malformed base fallback PASS: " $0)
        base_reported_delta = field("observed_tick_delta") + 0
    }
    /^LINUX_SCHEDULER PASS workload=linux-hello / {
        linux_passes++
        if ($0 !~ /^LINUX_SCHEDULER PASS workload=linux-hello policy=404 fallback_first_task=400 fallback_first_selection_attempt=1 observed_tick_delta=[0-9]+ tick_delta_diagnostic=true scoped_proposal_cleared=true$/)
            fail("malformed Linux fallback PASS: " $0)
        linux_reported_delta = field("observed_tick_delta") + 0
    }
    END {
        if (failed)
            exit 1
        if (base_crashes != 1 || linux_crashes != 1)
            fail("expected one base crash and one Linux crash")
        if (!base_pick_seen || !linux_pick_seen)
            fail("missing first fallback pick")
        if (base_first_attempts != 1 || linux_first_attempts != 1)
            fail("selection attempt 1 must appear exactly once in each binding epoch")
        if (base_passes != 1 || linux_passes != 1)
            fail("expected exactly one base and one Linux fallback PASS")
        if (base_pick_tick < base_crash_tick || base_reported_delta != base_pick_tick - base_crash_tick)
            fail("base fallback tick diagnostic does not match Crash -> first pick")
        if (linux_pick_tick < linux_crash_tick || linux_reported_delta != linux_pick_tick - linux_crash_tick)
            fail("Linux fallback tick diagnostic does not match Crash -> first pick")
    }
' "$log"

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

require_exact_count() {
    local expected=$1
    local pattern=$2
    local description=$3
    local actual
    actual=$(grep -cF "$pattern" "$log" || true)
    if [[ "$actual" -ne "$expected" ]]; then
        echo "$description: expected $expected, observed $actual ($pattern)" >&2
        exit 1
    fi
}

# The Projection oracle is deliberately scenario-aware.  It pairs every
# compressed semantic state with its PortalResult, validates the complete token
# identity and allowed order, and rejects any missing or additional receipt.
awk -f "$script_dir/assert-linux-projections.awk" "$log"

require_exact_count 1 \
    'CSER PrepareScoped service=scheduler scheduler_authority_epoch=41 binding_epoch=2 workload_authority_epoch=91 scope=30 effect=0 proposal_task=400' \
    'linux scheduler scoped proposal count mismatch'
require_exact_count 1 \
    'CSER CrashScoped service=scheduler scheduler_authority_epoch=41 binding_epoch=3 workload_authority_epoch=91 scope=30 effect=0 pending_scoped_cleared=true fallback=kernel_fifo' \
    'linux scheduler scoped crash count mismatch'
require_exact_count 1 \
    'LINUX_SCHEDULER PASS workload=linux-hello' \
    'linux scheduler fallback receipt count mismatch'

for event in Register PrepareImage Crash Commit Complete GuestResume PASS; do
    require_exact_count 1 \
        "LINUX_CODE_PAGER $event workload=linux-hello" \
        "linux code-pager $event count mismatch"
done
require_exact_count 1 \
    'LINUX_CODE_PAGER REJECT_STALE workload=linux-hello stage=post_crash' \
    'linux code-pager post-crash stale rejection count mismatch'
require_exact_count 1 \
    'LINUX_CODE_PAGER REJECT_STALE workload=linux-hello stage=post_rebind' \
    'linux code-pager post-rebind stale rejection count mismatch'
require_exact_count 1 \
    'LINUX_CODE_PAGER REJECT_NO_SUPERVISOR workload=linux-hello stage=pre_rebind' \
    'linux code-pager no-supervisor rejection count mismatch'

require_exact_count 1 \
    'LINUX_GUEST stdout=hello from linux-hello' \
    'linux guest output publication count mismatch'
require_exact_count 1 \
    'LINUX_GUEST stdout=' \
    'unexpected additional linux guest output publication'
require_exact_count 1 \
    'LINUX_SYSCALL BackendCommit workload=linux-hello personality=401 effect=1 kind=write binding_epoch=1 result=Committed' \
    'linuxd-v1 backend commit count mismatch'
require_exact_count 1 \
    'LINUX_PORTAL Queue workload=linux-hello sender=401 action=Reply effect=1 authority_epoch=91 scope=30 task=400 operation=1 binding_epoch=1 delivery=after_crash' \
    'linuxd-v1 delayed full-token packet count mismatch'
require_exact_count 1 \
    'LINUX_PORTAL Queue workload=linux-hello' \
    'unexpected additional Linux portal queued packet'
require_exact_count 1 \
    'LINUX_SYSCALL BackendCommit workload=linux-hello personality=403 effect=1 kind=write binding_epoch=2 result=AlreadyCommitted' \
    'linuxd-v2 duplicate backend fencing count mismatch'
require_exact_count 2 \
    'LINUX_SYSCALL BackendCommit workload=linux-hello' \
    'unexpected additional linux write backend commit attempt'
require_exact_count 1 \
    'LINUX_SYSCALL Reply workload=linux-hello replacement=403 effect=1 kind=write' \
    'linux write reply count mismatch'
require_exact_count 1 \
    'LINUX_PERSONALITY Crash workload=linux-hello supervisor=401' \
    'linux personality crash count mismatch'
require_exact_count 1 \
    'LINUX_SYSCALL REJECT_STALE workload=linux-hello stage=post_crash action=Reply effect=1' \
    'linux personality post-crash stale rejection count mismatch'
require_exact_count 1 \
    'LINUX_SYSCALL REJECT_STALE workload=linux-hello stage=post_rebind action=Reply effect=1' \
    'linux personality post-rebind stale rejection count mismatch'
require_exact_count 1 \
    'LINUX_SYSCALL REJECT_NO_SUPERVISOR workload=linux-hello stage=pre_rebind action=Reply effect=1' \
    'linux personality no-supervisor rejection count mismatch'
require_exact_count 1 \
    'LINUX_SYSCALL Commit workload=linux-hello replacement=403 effect=2 kind=exit_group' \
    'linux exit-group terminalization count mismatch'
require_exact_count 1 \
    'LINUX_GUEST Exit workload=linux-hello status=0 resumed_after_exit=false terminal=Exited' \
    'linux guest exit count mismatch'
require_exact_count 1 \
    'LINUX_SLICE PASS workload=linux-hello' \
    'linux slice receipt count mismatch'
require_exact_count 1 'SPIKE_RESULT PASS' 'overall spike receipt count mismatch'

require_exact_count 1 \
    'LINUX_REVOKE ClosureStep scope=31 effect=5 from=ReplyPrepared to=Aborted backend_commits=0 replies=0 resumes=0 aborts=1 steps=1 waker_taken=true wake_published=true waker_dropped=true' \
    'revoke-before-commit closure receipt count mismatch'
require_exact_count 1 \
    'LINUX_REVOKE RevokeComplete parent_scope=30 scope=31 authority_epoch=92 target_count=1 steps=1 live_effects=0 waker_present=false wake_publications=1 state=Revoked' \
    'revoke-before-commit quiescent completion count mismatch'
require_exact_count 1 \
    'LINUX_REVOKE ClosureStep scope=32 effect=6 from=BackendCommitted to=Completed backend_commits=1 replies=1 resumes=1 aborts=0 steps=1 waker_taken=true wake_published=true waker_dropped=true' \
    'commit-before-revoke closure receipt count mismatch'
require_exact_count 1 \
    'LINUX_REVOKE RevokeComplete parent_scope=30 scope=32 authority_epoch=92 target_count=1 steps=1 live_effects=0 waker_present=false wake_publications=1 state=Revoked' \
    'commit-before-revoke quiescent completion count mismatch'
require_exact_count 2 \
    'LINUX_REVOKE ClosureStep scope=' \
    'unexpected additional or missing revoke closure step'
require_exact_count 2 \
    'LINUX_REVOKE RevokeComplete parent_scope=30 scope=' \
    'unexpected additional or missing quiescent revoke completion'

guest_exit_line=$(grep -nF -m1 \
    'LINUX_GUEST Exit workload=linux-hello status=0 resumed_after_exit=false terminal=Exited' \
    "$log" | cut -d: -f1 || true)
if [[ -z "$guest_exit_line" ]]; then
    echo "missing Linux guest exit terminalization" >&2
    exit 1
fi
if tail -n "+$((guest_exit_line + 1))" "$log" | grep -Eq \
    'LINUX_(SYSCALL (Capture|Prepare|BackendCommit|Reply|Commit) workload=linux-hello|PORTAL Deliver workload=linux-hello|GUEST (Block|Resume|stdout=)|PERSONALITY (Dispatch|Crash|Fallback|FreshSpawn|RecoverySnapshot|Ready|Rebind))'; then
    echo "successful Linux guest/syscall activity observed after guest exit" >&2
    exit 1
fi

for forbidden in \
    'PAGER Commit scenario=timeout' \
    'PAGER Complete scenario=timeout' \
    'PAGER ClientResume scenario=timeout' \
    'PAGER RevokeComplete scenario=timeout scope=21 authority_epoch=72 live_effects=0 retained_frames=0 cleanup_inflight=true' \
    'PAGER RevokeComplete scenario=timeout scope=21 authority_epoch=72 live_effects=0 retained_frames=0 cleanup_inflight=false wake_pending=true' \
    'CSER Commit authority_epoch=41 binding_epoch=2 proposal_task=400' \
    'LINUX_SYSCALL Reply workload=linux-hello replacement=401' \
    'LINUX_SYSCALL Reply workload=linux-hello replacement=403 effect=1 kind=write binding_epoch=1' \
    'LINUX_CODE_PAGER Commit workload=linux-hello replacement=412 effect=3 binding_epoch=1' \
    'backend_replayed=true' \
    'output_publications=2' \
    'wake_publications=2' \
    'resume_returns=2' \
    'entry_publication=eager' \
    'permissions=RWX' \
    'wx=true' \
    'Linux personality rejected an unexpected Linux syscall snapshot' \
    'unknown Linux personality' \
    'unknown Linux code pager' \
    'panicked at' \
    'Non-resettable panic!'; do
    if grep -Fq "$forbidden" "$log"; then
        echo "forbidden serial evidence: $forbidden" >&2
        exit 1
    fi
done

echo "serial assertions: PASS"
