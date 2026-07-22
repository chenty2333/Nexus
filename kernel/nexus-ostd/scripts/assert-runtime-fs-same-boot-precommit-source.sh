#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_file=${1:-$script_root/src/personality/linux_fs.rs}
lib_file=${2:-$script_root/src/lib.rs}
facade_file=${3:-$script_root/../../crates/nexus-ostd-virtio/src/production.rs}
device_flight_file=${4:-$script_root/src/cser/device_flight.rs}
primary_gate=$script_root/scripts/assert-runtime-fs-same-boot-source.sh

fail() {
    echo "runtime filesystem same-boot precommit source assertion: FAIL: $*" >&2
    exit 1
}

for input in "$source_file" "$lib_file" "$facade_file" "$device_flight_file" \
    "$primary_gate"; do
    [[ -f $input && ! -L $input ]] ||
        fail "implementation source is not a regular non-symlink file: $input"
done
for command_name in awk bash cmp cp grep mapfile mktemp rm sed; do
    command -v "$command_name" >/dev/null 2>&1 ||
        fail "missing command: $command_name"
done

# The precommit witness is not permitted to weaken the positive architecture
# contract. In particular, it must also use the one accepted Registry/ledger
# and the same runtime-resident hardware flight.
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
    ((start < end)) ||
        fail "invalid source boundary '$start_pattern' -> '$end_pattern'"
    sed -n "${start},$((end - 1))p" "$file" >"$output"
    [[ -s $output ]] || fail "empty extracted source boundary: $start_pattern"
}

extract_until_first_after() {
    local file=$1
    local start_pattern=$2
    local end_pattern=$3
    local output=$4
    local start
    start=$(line_of_unique "$file" "$start_pattern")
    awk -v start="$start" -v end_pattern="$end_pattern" '
        NR >= start {
            if (NR > start && index($0, end_pattern)) {
                found = 1
                exit
            }
            print
        }
        END { if (!found) exit 2 }
    ' "$file" >"$output" ||
        fail "missing end boundary '$end_pattern' after '$start_pattern'"
    [[ -s $output ]] || fail "empty extracted source boundary: $start_pattern"
}

dispatch="$work/same-boot-dispatch.rs"
commit_gate="$work/device-commit-gate.rs"
fault="$work/precommit-fault.rs"
precommit_close="$work/precommit-close.rs"
feature_root="$work/feature-root.rs"
prepared_impl="$work/prepared-request.rs"
cancel_intent_impl="$work/prepared-cancel-intent.rs"

extract_between "$source_file" 'fn execute_recovered_first_pread_same_boot(' \
    'fn dispatch_first_executable_pread(' "$dispatch"
extract_between "$dispatch" '            let commits = [' \
    '        if precommit_close {' "$commit_gate"
extract_between "$commit_gate" \
    '            #[cfg(feature = "virtio-cser-precommit-fault")]' \
    '            #[cfg(not(feature = "virtio-cser-precommit-fault"))]' "$fault"
extract_between "$source_file" 'fn close_precommit_flight(' \
    'fn drive_postcommit_flight(' "$precommit_close"
extract_until_first_after "$lib_file" '    let fs_receipt = match linux_fs::run_linux_fs_slice() {' \
    '    #[cfg(not(feature = "virtio-cser-facade"))]' "$feature_root"
extract_between "$facade_file" 'impl PreparedRequest {' \
    'impl Drop for PreparedRequest {' "$prepared_impl"
extract_between "$facade_file" 'impl PreparedCancelIntent {' \
    'pub enum CompletionFailure {' "$cancel_intent_impl"

# The injected revoke wins before publication. The complete real cohort and
# its concrete prepared owner remain in the runtime slot; closure goes through
# the Registry's failure-atomic precommit semantic wrapper.
for required in \
    'FsDeviceFlight::Building {' \
    'runtime.put_flight('; do
    require_at_least "$fault" "$required" 1
done
require_at_least "$dispatch" \
    'return self.close_precommit_flight("precommit_commit_gate");' 1
for required in \
    'close_enrolled_device_flight_precommit_with_apply(' \
    'FsCloseSemantic::Precommit(' \
    'FsDeviceFlight::Resetting {' \
    'request.preflight_cancel(expected)' \
    'let mut intent_slot = Some(intent);' \
    '.apply_reset(true)'; do
    require_at_least "$precommit_close" "$required" 1
done
reject_fixed "$fault" '.publish_prepared()'
reject_fixed "$fault" 'DeviceFlightCloseOutcome::Applied'
reject_fixed "$fault" 'revoke_begin(SCOPE)'
reject_fixed "$precommit_close" '.publish_prepared()'
reject_fixed "$precommit_close" 'begin_unpublished_device_cancel('
reject_fixed "$precommit_close" 'revoke_begin(SCOPE)'
reject_fixed "$precommit_close" 'SameBootFlight'
reject_fixed "$precommit_close" 'ProductionReadPhase'
reject_fixed "$precommit_close" 'claim_device_replay_reset_and_revoke'

# Cancellation has an explicit prevalidated linear intent. The gate forbids a
# stack-local forget/panic escape after the facade has changed hardware state.
require_count "$prepared_impl" 'pub fn preflight_cancel(' 2
for required in \
    'Result<PreparedCancelIntent, HardwareIntentFailure<PreparedRequest>>' \
    'Ok(PreparedCancelIntent { request: self })'; do
    require_at_least "$prepared_impl" "$required" 1
done
for required in \
    'pub fn apply_reset(self, inject_pending_once: bool) -> ProductionResetTombstone' \
    '.cancel_prepared()' \
    '.begin_reset(inject_pending_once)'; do
    require_at_least "$cancel_intent_impl" "$required" 1
done
reject_fixed "$precommit_close" 'core::mem::forget'
reject_fixed "$precommit_close" 'panic!('

# This witness never makes a descriptor visible and is not an IRQ or SMP
# witness. Polling/interrupt facade tokens cannot upgrade that claim.
reject_fixed "$fault" 'prepare_read_sector0_irq('
reject_fixed "$fault" '.ack_interrupt('
reject_fixed "$fault" '.notify()'
reject_fixed "$source_file" 'polling=false irq=true'
require_at_least "$source_file" 'polling=false irq=false smp=1' 2
require_at_least "$source_file" 'publish_closure_calls=0' 1
require_at_least "$source_file" 'closure=AbortedBeforeCommit' 1

# The feature root consumes the same production receipt and terminates before
# legacy filesystem/network composition. Its public receipt must remain honest
# about zero device publication and the enrolled revoke winner.
for required in \
    '#[cfg(feature = "virtio-cser-precommit-fault")]' \
    'assert_eq!(fs_receipt.production_effects, 6);' \
    'assert!(fs_receipt.preparation_identity_observed);' \
    'assert!(fs_receipt.enrolled_revoke_wins_observed);' \
    'println!("SPIKE_RESULT PASS");' \
    'poweroff(ExitCode::Success);'; do
    require_at_least "$feature_root" "$required" 1
done
reject_fixed "$feature_root" 'linux_net::run_linux_net_slice();'

if [[ ${NEXUS_SAME_BOOT_PRECOMMIT_SOURCE_PRIMARY_ONLY:-0} != 1 ]]; then
    mutations=0

    require_mutation() {
        ((mutations += 1))
        ! cmp -s -- "$1" "$2" || fail "source mutation did not change input: $3"
    }

    require_source_rejection() {
        if NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 \
            NEXUS_SAME_BOOT_PRECOMMIT_SOURCE_PRIMARY_ONLY=1 \
            bash "$0" "$1" "$lib_file" "$facade_file" "$device_flight_file" \
            >/dev/null 2>&1; then
            fail "precommit source gate accepted mutation: $2"
        fi
    }

    require_facade_rejection() {
        if NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 \
            NEXUS_SAME_BOOT_PRECOMMIT_SOURCE_PRIMARY_ONLY=1 \
            bash "$0" "$source_file" "$lib_file" "$1" "$device_flight_file" \
            >/dev/null 2>&1; then
            fail "precommit source gate accepted facade mutation: $2"
        fi
    }

    cp "$source_file" "$work/precommit-publishes.rs"
    awk '
        /#\[cfg\(feature = "virtio-cser-precommit-fault"\)\]/ { fault = 1 }
        fault && !changed && /runtime\.put_flight\(FsDeviceFlight::Building/ {
            print "                let _forbidden = request.publish_prepared();"
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/precommit-publishes.rs"
    require_mutation "$source_file" "$work/precommit-publishes.rs" precommit-publishes
    require_source_rejection "$work/precommit-publishes.rs" precommit-publishes

    awk '
        /#\[cfg\(feature = "virtio-cser-precommit-fault"\)\]/ { fault = 1 }
        fault && !changed && /runtime\.put_flight\(FsDeviceFlight::Building/ {
            print "                let _forbidden = runtime.registry.revoke_begin(SCOPE);"
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/two-step-revoke.rs"
    require_mutation "$source_file" "$work/two-step-revoke.rs" two-step-revoke
    require_source_rejection "$work/two-step-revoke.rs" two-step-revoke

    cp "$source_file" "$work/receipt-only-cancel.rs"
    sed -i \
        '0,/close_enrolled_device_flight_precommit_with_apply(/s//begin_unpublished_device_cancel(/' \
        "$work/receipt-only-cancel.rs"
    require_mutation "$source_file" "$work/receipt-only-cancel.rs" receipt-only-cancel
    require_source_rejection "$work/receipt-only-cancel.rs" receipt-only-cancel

    cp "$source_file" "$work/precommit-irq-claim.rs"
    sed -i '0,/polling=false irq=false smp=1/s//polling=false irq=true smp=1/' \
        "$work/precommit-irq-claim.rs"
    require_mutation "$source_file" "$work/precommit-irq-claim.rs" precommit-irq-claim
    require_source_rejection "$work/precommit-irq-claim.rs" precommit-irq-claim

    cp "$facade_file" "$work/missing-cancel-intent.rs"
    sed -i '0,/pub fn preflight_cancel(/s//pub fn preflight_abandon(/' \
        "$work/missing-cancel-intent.rs"
    require_mutation "$facade_file" "$work/missing-cancel-intent.rs" missing-cancel-intent
    require_facade_rejection "$work/missing-cancel-intent.rs" missing-cancel-intent

    cp "$source_file" "$work/false-service-device-commit.rs"
    sed -i \
        '0,/device_commit_gate_after_rebind=true device_committed_after_rebind=false/s//device_commit_gate_after_rebind=true device_committed_after_rebind=true/' \
        "$work/false-service-device-commit.rs"
    require_mutation "$source_file" "$work/false-service-device-commit.rs" \
        false-service-device-commit
    require_source_rejection "$work/false-service-device-commit.rs" \
        false-service-device-commit

    [[ $mutations == 6 ]] || fail "expected 6 source mutations, observed $mutations"
fi

echo 'runtime filesystem same-boot precommit source assertions: PASS checkpoint=device_flight accepted_registry=one accepted_ledger=one compatibility_syscalls=payload_only_not_cser flight=single_actor_slot_handoff actor_resident=false real_user_service_crash=true fsd_task_key=current-task-bound+951:1->951:2 replacement_construction=post-crash guest_admission=receipt-before-armed crash_before_device=true stale_prepare=queued-v1+failure-atomic old_sender_current_handle=NoSupervisor device_commit_gate_after_rebind=true device_committed_after_rebind=false reply_wakeups=1 publication_calls=0 closure=AbortedBeforeCommit prepared_owner=linear polling=false irq_evidence=false smp=1 rfc0001_full_closure=false mutations=6'
