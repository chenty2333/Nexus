#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_file=${1:-$script_root/src/personality/linux_fs.rs}
lib_file=${2:-$script_root/src/lib.rs}
device_flight_file=${3:-$script_root/src/cser/device_flight.rs}
postcommit_file=${4:-$script_root/src/personality/linux_fs_postcommit.rs}
v2_guest=${5:-$script_root/guest/linux-fsd-v2-postcommit.S}
v3_guest=${6:-$script_root/guest/linux-fsd-v3.S}
cargo_file=$script_root/Cargo.toml
osdk_file=$script_root/OSDK.toml
primary_gate=$script_root/scripts/assert-runtime-fs-same-boot-source.sh

fail() {
    echo "runtime filesystem same-boot postcommit source assertion: FAIL: $*" >&2
    exit 1
}

for input in "$source_file" "$lib_file" "$device_flight_file" \
    "$postcommit_file" "$v2_guest" "$v3_guest" "$cargo_file" \
    "$osdk_file" "$primary_gate"; do
    [[ -f $input && ! -L $input ]] ||
        fail "implementation source is not a regular non-symlink file: $input"
done
for command_name in awk bash cmp cp grep mapfile mktemp rm sed; do
    command -v "$command_name" >/dev/null 2>&1 ||
        fail "missing command: $command_name"
done

# The additive postcommit lane inherits the complete positive same-boot
# architecture contract. Its local checks only narrow the crash boundary.
NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 bash "$primary_gate" \
    "$source_file" "$lib_file" "$device_flight_file" >/dev/null

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fixed_count() {
    grep -F -c -- "$2" "$1" || true
}

require_count() {
    local actual
    actual=$(fixed_count "$1" "$2")
    [[ $actual == "$3" ]] ||
        fail "expected $3 occurrence(s) of '$2' in $1, observed $actual"
}

require_at_least() {
    local actual
    actual=$(fixed_count "$1" "$2")
    ((actual >= $3)) ||
        fail "expected at least $3 occurrence(s) of '$2' in $1, observed $actual"
}

reject_fixed() {
    if grep -Fq -- "$2" "$1"; then
        fail "forbidden source token '$2' entered $1"
    fi
}

line_of_unique() {
    local file=$1
    local pattern=$2
    local -a matches=()
    mapfile -t matches < <(grep -nF -- "$pattern" "$file" || true)
    ((${#matches[@]} == 1)) ||
        fail "expected one source anchor '$pattern' in $file, observed ${#matches[@]}"
    printf '%s\n' "${matches[0]%%:*}"
}

extract_between() {
    local file=$1
    local start_pattern=$2
    local end_pattern=$3
    local output=$4
    local start end
    start=$(line_of_unique "$file" "$start_pattern")
    end=$(line_of_unique "$file" "$end_pattern")
    ((start < end)) || fail "invalid source boundary '$start_pattern' -> '$end_pattern'"
    sed -n "${start},$((end - 1))p" "$file" >"$output"
    [[ -s $output ]] || fail "empty source boundary: $start_pattern"
}

require_order() {
    local file=$1
    shift
    local previous=0 pattern line
    for pattern in "$@"; do
        line=$(line_of_unique "$file" "$pattern")
        ((line > previous)) ||
            fail "source transition '$pattern' is out of order in $file"
        previous=$line
    done
}

pending=$work/pending.rs
crash=$work/crash.rs
stale=$work/stale.rs
wake=$work/wake.rs
trigger=$work/trigger.rs
publication=$work/publication.rs
run_slice=$work/run-slice.rs
task_data=$work/task-data.rs

extract_between "$postcommit_file" '    fn require_postcommit_pending(' \
    '    pub(super) fn fsd_crash_postcommit_v2(' "$pending"
extract_between "$postcommit_file" '    pub(super) fn fsd_crash_postcommit_v2(' \
    '    pub(super) fn fsd_postcommit_stale_probe(' "$crash"
extract_between "$postcommit_file" '    pub(super) fn fsd_postcommit_stale_probe(' \
    '    pub(super) fn fsd_trigger_postcommit_publication(' "$stale"
extract_between "$postcommit_file" '    pub(super) fn fsd_trigger_postcommit_publication(' \
    '    pub(super) fn fsd_finish_postcommit_trigger(' "$wake"
extract_between "$postcommit_file" 'fn current_postcommit_trigger(' \
    'impl FsScenario {' "$trigger"
extract_between "$source_file" '    fn publish(&self, outcome: &DispatchOutcome)' \
    '    fn finish(&self)' "$publication"
extract_between "$source_file" \
    'pub(crate) fn run_linux_fs_slice() -> Result<RuntimeFsSliceReceipt, RuntimeFsSliceIsolation>' \
    'fn run_guest(' "$run_slice"
extract_between "$lib_file" \
    '    pub(crate) fn new_postcommit_trigger(' \
    '#[ostd::main]' "$task_data"

# The fault feature is isolated and cannot be combined with the precommit
# witness. The child module and guest images remain feature-gated inputs.
require_count "$cargo_file" \
    'virtio-cser-postcommit-fault = ["virtio-cser-facade"]' 1
require_count "$osdk_file" '[scheme."runtime-fs-same-boot-postcommit-crash"]' 1
require_count "$osdk_file" \
    'build.features = ["virtio-cser-postcommit-fault"]' 1
for required in \
    'feature = "virtio-cser-precommit-fault"' \
    'feature = "virtio-cser-postcommit-fault"' \
    'compile_error!(' \
    '"virtio-cser-precommit-fault and virtio-cser-postcommit-fault are mutually exclusive"'; do
    require_at_least "$lib_file" "$required" 1
done
for required in \
    '#[cfg(feature = "virtio-cser-postcommit-fault")]' \
    '#[path = "linux_fs_postcommit.rs"]' \
    'const FSD_V2_PROGRAM: &[u8] = include_bytes!("../../guest/linux-fsd-v2-postcommit.bin");' \
    'const FSD_V3_PROGRAM: &[u8] = include_bytes!("../../guest/linux-fsd-v3.bin");'; do
    require_at_least "$source_file" "$required" 1
done

# A post-backend crash is accepted only while the exact completed outcome,
# device flight, Registry publication, and opaque causal session all agree.
for required in \
    'service.response_waker.is_none()' \
    'service.reply_wakeups != 0' \
    'service.response_taken' \
    'service.termination.is_some()' \
    'outcome.result != 4' \
    'Publication::FixedGuestBytes { len: 4, .. }' \
    'PublicationAuthority::Production {' \
    'if service_cookie.get() != outcome_cookie' \
    'scope.phase != ScopePhase::Closing' \
    'scope.live_effects != 0' \
    'scope.pending_publications != 1' \
    'runtime.adapter_phase != FsDeviceAdapterPhase::Released' \
    'FsDeviceFlight::AwaitingPublication {' \
    'ticket.effect() == work.effects[0]' \
    'work.result == 4' \
    'work.byte_count == 4' \
    '.verify_causal_session(cookie, root_effect)' \
    '.check_invariants()'; do
    require_at_least "$pending" "$required" 1
done
for forbidden in \
    'EffectRegistry::new()' '.crash_domain(' '.domain_recovery_snapshot(' \
    '.rebind_domain(' '.adopt_domain(' 'commit_or_recover_device_flight_with_apply('; do
    reject_fixed "$pending" "$forbidden"
done

# V2 faults only after completion has become one pending publication; the
# crash itself neither recovers nor republishes anything.
for required in \
    'FsServiceProtocol::require_sender("postcommit_crash", sender, FILESYSTEM_V2)' \
    'self.require_postcommit_pending("postcommit_crash", FsServicePhase::Executed)' \
    'service.postcommit_causal_identity = Some(pending.causal_identity);' \
    'service.phase = FsServicePhase::PostcommitCrashed;' \
    'backend_completion=true phase=Closing live_effects=0 pending_publications=1' \
    'flight=AwaitingPublication' \
    'causal_state=Active' \
    'outcome_present=true reply_wakeups=0 guest_reply=false' \
    'polling=true irq=false smp=1'; do
    require_at_least "$crash" "$required" 1
done
for forbidden in \
    '.crash_domain(' '.domain_recovery_snapshot(' '.rebind_domain(' \
    '.adopt_domain(' '.publish_prepared()' 'lost_ack=true' \
    'prebackend_crash=true' 'outer_ack_failure=true'; do
    reject_fixed "$crash" "$forbidden"
done

# V3 is a Registry-free closure trigger. Its stale V2 authority probe must be
# a real mutating prepare attempt whose failure leaves Registry, flight, and
# causal identity byte-for-byte unchanged.
for required in \
    'data.postcommit_trigger_task.ok_or_else' \
    'data.cser_task.is_some()' \
    'trigger != FILESYSTEM_V3_TRIGGER'; do
    require_at_least "$trigger" "$required" 1
done
for required in \
    'cser_task: None,' \
    'postcommit_trigger_task: Some(task),'; do
    require_at_least "$task_data" "$required" 1
done
for required in \
    'self.require_postcommit_pending("postcommit_probe", FsServicePhase::PostcommitCrashed)' \
    'service.postcommit_causal_identity != Some(pending.causal_identity)' \
    'runtime.registry.failure_atomic_projection()' \
    'runtime.registry.prepare(FILESYSTEM_V2, old_handle)' \
    'Err(RegistryError::StaleAuthority)' \
    'if after != before' \
    '.verify_causal_session(pending.cookie, pending.root_effect)' \
    'FsDeviceFlight::AwaitingPublication { cookie, ticket, work, .. }' \
    'service.phase = FsServicePhase::PostcommitProbed;' \
    'result=StaleAuthority' \
    'registry_projection_unchanged=true' \
    'flight_identity_unchanged=true causal_identity_unchanged=true' \
    'same_causal_session=true recommit=false rebind=false adopt=false' \
    'registry_replacement=false causal_service_task_facade_observed=false causal_fault_matrix_promotion=false'; do
    require_at_least "$stale" "$required" 1
done
for forbidden in '.rebind_domain(' '.adopt_domain(' '.publish_prepared()' \
    'registry_replacement=true' 'causal_service_task_facade_observed=true' \
    'causal_fault_matrix_promotion=true'; do
    reject_fixed "$stale" "$forbidden"
done

# The fresh trigger only wakes the original blocked guest once. All identity
# checks precede taking the waker, and no replacement request is constructed.
for required in \
    'self.require_postcommit_pending("postcommit_wake", FsServicePhase::PostcommitProbed)' \
    'service.postcommit_causal_identity != Some(pending.causal_identity)' \
    '.response_waker' \
    '.take()' \
    'service.reply_wakeups = 1;' \
    'service.phase = FsServicePhase::ReplyReady;' \
    'same_causal_session=true same_flight=true same_ticket=true same_outcome=true' \
    'reply_wakeups=1 exactly_once=true original_guest_publication_pending=true' \
    'registry_replacement=false causal_service_task_facade_observed=false causal_fault_matrix_promotion=false' \
    'waker.wake_up();'; do
    require_at_least "$wake" "$required" 1
done
require_order "$wake" \
    'self.require_postcommit_pending("postcommit_wake", FsServicePhase::PostcommitProbed)' \
    '.response_waker' \
    'service.reply_wakeups = 1;' \
    'same_causal_session=true same_flight=true same_ticket=true same_outcome=true' \
    'waker.wake_up();'
require_count "$wake" 'waker.wake_up();' 1
for forbidden in 'commit_or_recover_device_flight_with_apply(' \
    '.publish_prepared()' 'registry_replacement=true' \
    'causal_service_task_facade_observed=true' \
    'causal_fault_matrix_promotion=true'; do
    reject_fixed "$wake" "$forbidden"
done

# Publication verifies Active, closes the causal session before the outer
# Registry ACK, and clears the closed identity only after that ACK applies.
for required in \
    '.verify_causal_session(causal_cookie, root_effect)' \
    '.close_or_verify_causal_terminal(causal_cookie, root_effect)' \
    '.prepare_terminal_clear(causal_cookie, root_effect)' \
    '.acknowledge_publication_and_revoke_complete_with_apply(' \
    'runtime.causal.apply_terminal_clear(causal_clear);' \
    'before_close=Active after_close=Closed outer_ack_apply=true after_outer_ack=Vacant publication_actor=original_guest' \
    'actor=original_guest trigger=fsd-v3' \
    'registry_ack=true revoke_complete=true causal_state=Vacant'; do
    require_at_least "$publication" "$required" 1
done
require_order "$publication" \
    '.verify_causal_session(causal_cookie, root_effect)' \
    '.close_or_verify_causal_terminal(causal_cookie, root_effect)' \
    '.prepare_terminal_clear(causal_cookie, root_effect)' \
    '.acknowledge_publication_and_revoke_complete_with_apply(' \
    'runtime.causal.apply_terminal_clear(causal_clear);' \
    'before_close=Active after_close=Closed outer_ack_apply=true after_outer_ack=Vacant publication_actor=original_guest'
for forbidden in 'outer_ack_failure=true' 'lost_ack=true'; do
    reject_fixed "$publication" "$forbidden"
done

# The postcommit trigger is created only after V2's real fault waiter and is
# explicitly denied a Registry TaskKey. The final receipt stays within the
# bounded evidence that this runtime actually exercises.
for required in \
    'v2_waiter.wait();' \
    'FsServicePhase::PostcommitCrashed' \
    'let v3_vm = Arc::new(create_vm_space(FSD_V3_PROGRAM));' \
    'TaskData::new_postcommit_trigger(' \
    'assert!(trigger_data.cser_task.is_none());' \
    'closure_trigger_only=true registry_replacement=false registry_task=false' \
    'v3_task.run();' \
    'v3_waiter.wait();' \
    'post_backend_pre_reply_crash=true prebackend_crash=false' \
    'v3_registry_replacement=false v3_registry_task=false' \
    'causal_service_task_facade_observed=false causal_fault_matrix_promotion=false' \
    'causal_publication_transition=Active,Closed,Vacant' \
    'publication_actor=original_guest'; do
    require_at_least "$run_slice" "$required" 1
done
require_order "$run_slice" \
    'v2_waiter.wait();' \
    'FsServicePhase::PostcommitCrashed' \
    'let v3_vm = Arc::new(create_vm_space(FSD_V3_PROGRAM));' \
    'TaskData::new_postcommit_trigger(' \
    'v3_task.run();' \
    'v3_waiter.wait();' \
    'post_backend_pre_reply_crash=true prebackend_crash=false'
for forbidden in 'outer_ack_failure=true' 'lost_ack=true' \
    'causal_service_task_facade_observed=true' \
    'causal_fault_matrix_promotion=true'; do
    reject_fixed "$run_slice" "$forbidden"
done

require_order "$v2_guest" \
    'mov     $FSD_COMMIT, %eax' \
    'movabs  $EXPECTED_FAULT, %rax' \
    'mov     (%rax), %rax'
reject_fixed "$v2_guest" '    mov     $FSD_PUBLISH'
require_order "$v3_guest" \
    'mov     $FSD_POSTCOMMIT_PROBE, %eax' \
    'mov     $FSD_PUBLISH, %eax' \
    'mov     $FSD_DONE, %eax'
for forbidden in FSD_COMMIT FSD_RECOVERY_SNAPSHOT FSD_READY FSD_REBIND \
    FSD_ADOPT_NEXT FSD_REPLAY_OLD; do
    reject_fixed "$v3_guest" "$forbidden"
done

if [[ ${NEXUS_SAME_BOOT_POSTCOMMIT_SOURCE_PRIMARY_ONLY:-0} != 1 ]]; then
    mutations=0

    require_mutation() {
        ((mutations += 1))
        ! cmp -s -- "$1" "$2" || fail "source mutation did not change input: $3"
    }

    require_rejection() {
        local label=$1 source=${2:-$source_file} lib=${3:-$lib_file}
        local postcommit=${4:-$postcommit_file} v2=${5:-$v2_guest} v3=${6:-$v3_guest}
        if NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 \
            NEXUS_SAME_BOOT_POSTCOMMIT_SOURCE_PRIMARY_ONLY=1 \
            bash "$0" "$source" "$lib" "$device_flight_file" \
                "$postcommit" "$v2" "$v3" >/dev/null 2>&1; then
            fail "postcommit source gate accepted mutation: $label"
        fi
    }

    mutate_fixed() {
        local input=$1 before=$2 after=$3 label=$4 kind=${5:-postcommit}
        local output=$work/$label
        sed "0,/$before/s//$after/" "$input" >"$output"
        require_mutation "$input" "$output" "$label"
        case $kind in
            source) require_rejection "$label" "$output" ;;
            lib) require_rejection "$label" "$source_file" "$output" ;;
            postcommit) require_rejection "$label" "$source_file" "$lib_file" "$output" ;;
            v2) require_rejection "$label" "$source_file" "$lib_file" "$postcommit_file" "$output" "$v3_guest" ;;
            v3) require_rejection "$label" "$source_file" "$lib_file" "$postcommit_file" "$v2_guest" "$output" ;;
        esac
    }

    mutate_fixed "$postcommit_file" 'scope.phase != ScopePhase::Closing' \
        'scope.phase != ScopePhase::Active' wrong-scope.rs
    mutate_fixed "$postcommit_file" 'scope.pending_publications != 1' \
        'scope.pending_publications != 0' missing-pending.rs
    mutate_fixed "$postcommit_file" '.verify_causal_session(cookie, root_effect)' \
        '.verify_complete()' missing-causal-verify.rs
    mutate_fixed "$postcommit_file" 'FsDeviceFlight::AwaitingPublication {' \
        'FsDeviceFlight::Published {' wrong-flight.rs
    mutate_fixed "$postcommit_file" 'backend_completion=true' \
        'backend_completion=false' prebackend-crash.rs
    mutate_fixed "$postcommit_file" 'Err(RegistryError::StaleAuthority)' \
        'Err(RegistryError::StaleBinding)' wrong-stale.rs
    mutate_fixed "$postcommit_file" 'if after != before' \
        'if after == before' changed-projection.rs
    mutate_fixed "$postcommit_file" 'causal_identity_unchanged=true' \
        'causal_identity_unchanged=false' changed-causal.rs
    mutate_fixed "$postcommit_file" 'same_ticket=true' \
        'same_ticket=false' changed-ticket.rs
    mutate_fixed "$postcommit_file" 'registry_replacement=false' \
        'registry_replacement=true' replacement-claim.rs
    mutate_fixed "$postcommit_file" 'causal_service_task_facade_observed=false' \
        'causal_service_task_facade_observed=true' facade-claim.rs
    mutate_fixed "$postcommit_file" 'causal_fault_matrix_promotion=false' \
        'causal_fault_matrix_promotion=true' fault-matrix-claim.rs
    mutate_fixed "$source_file" 'before_close=Active after_close=Closed' \
        'before_close=Closed after_close=Closed' close-order.rs source
    mutate_fixed "$source_file" 'prebackend_crash=false' \
        'prebackend_crash=true' prebackend-claim.rs source
    mutate_fixed "$source_file" 'publication_actor=original_guest' \
        'publication_actor=fsd-v3' wrong-publisher.rs source
    mutate_fixed "$lib_file" 'cser_task: None,' \
        'cser_task: Some(task),' registry-bearing-trigger.rs lib

    awk '
        { print }
        !changed && /waker\.wake_up\(\);/ {
            print "        waker.wake_up();"
            changed = 1
        }
        END { if (!changed) exit 2 }
    ' "$postcommit_file" >"$work/duplicate-wakeup.rs"
    require_mutation "$postcommit_file" "$work/duplicate-wakeup.rs" duplicate-wakeup
    require_rejection duplicate-wakeup "$source_file" "$lib_file" \
        "$work/duplicate-wakeup.rs"

    sed '0,/movabs  \$EXPECTED_FAULT, %rax/i\    mov     $FSD_PUBLISH, %eax' \
        "$v2_guest" >"$work/v2-publishes.S"
    require_mutation "$v2_guest" "$work/v2-publishes.S" v2-publishes
    require_rejection v2-publishes "$source_file" "$lib_file" \
        "$postcommit_file" "$work/v2-publishes.S" "$v3_guest"

    sed '0,/\.equ FSD_PUBLISH/a\.equ FSD_COMMIT,             0x4e740003' \
        "$v3_guest" >"$work/v3-recommits.S"
    require_mutation "$v3_guest" "$work/v3-recommits.S" v3-recommits
    require_rejection v3-recommits "$source_file" "$lib_file" \
        "$postcommit_file" "$v2_guest" "$work/v3-recommits.S"

    [[ $mutations == 19 ]] ||
        fail "expected 19 source mutations, observed $mutations"
fi

echo 'runtime filesystem same-boot postcommit source assertions: PASS boundary=post-backend-pre-publication phase=Closing live_effects=0 pending_publications=1 flight=AwaitingPublication causal_state=Active fresh_v3=registry-free-closure-trigger stale_v2=StaleAuthority registry_projection_unchanged=true flight_identity_unchanged=true causal_identity_unchanged=true original_v2_publication=true causal_transition=Active,Closed,Vacant close_before_outer_ack=true clear_after_outer_ack=true runtime_outer_ack_failure=false runtime_fault_matrix=false runtime_service_task_facade=false prebackend_claim=false lost_ack_claim=false polling=true irq=false smp=1 mutations=19'
