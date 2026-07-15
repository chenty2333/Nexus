#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_file=${1:-$script_root/src/personality/linux_fs.rs}
lib_file=${2:-$script_root/src/lib.rs}
device_flight_file=${3:-$script_root/src/cser/device_flight.rs}

fail() {
    echo "runtime filesystem same-boot source assertion: FAIL: $*" >&2
    exit 1
}

for input in "$source_file" "$lib_file" "$device_flight_file"; do
    [[ -f $input && ! -L $input ]] ||
        fail "implementation source is not a regular non-symlink file: $input"
done
for command_name in awk bash cmp cp grep mapfile mktemp rm sed; do
    command -v "$command_name" >/dev/null 2>&1 ||
        fail "missing command: $command_name"
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fixed_count() {
    grep -F -c -- "$2" "$1" || true
}

regex_count() {
    grep -E -c -- "$2" "$1" || true
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

require_regex_count() {
    local actual
    actual=$(regex_count "$1" "$2")
    [[ $actual == "$3" ]] ||
        fail "expected $3 match(es) of /$2/ in $1, observed $actual"
}

reject_fixed() {
    if grep -Fq -- "$2" "$1"; then
        fail "forbidden source token '$2' entered $1"
    fi
}

reject_regex() {
    if grep -Eq -- "$2" "$1"; then
        fail "forbidden source pattern /$2/ entered $1"
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

extract_from() {
    local file=$1
    local start_pattern=$2
    local output=$3
    local start
    start=$(line_of_unique "$file" "$start_pattern")
    sed -n "${start},\$p" "$file" >"$output"
    [[ -s $output ]] || fail "empty extracted source suffix: $start_pattern"
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

require_order() {
    local file=$1
    shift
    local previous=0
    local pattern line
    for pattern in "$@"; do
        line=$(line_of_unique "$file" "$pattern")
        ((line > previous)) ||
            fail "source transition '$pattern' is out of order in $file"
        previous=$line
    done
}

require_not_feature_guarded_if_present() {
    local file=$1
    local pattern=$2
    local -a matches=()
    local match line previous
    mapfile -t matches < <(grep -nF -- "$pattern" "$file" || true)
    ((${#matches[@]} <= 1)) ||
        fail "legacy Registry anchor '$pattern' is duplicated in $file"
    ((${#matches[@]} == 0)) && return
    match=${matches[0]}
    line=${match%%:*}
    ((line > 1)) || fail "legacy Registry anchor has no cfg predecessor: $pattern"
    previous=$(sed -n "$((line - 1))p" "$file" |
        sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [[ $previous == '#[cfg(not(feature = "virtio-cser-facade"))]' ]] ||
        fail "legacy Registry anchor '$pattern' is live in the accepted facade build"
}

fs_state="$work/fs-state.rs"
flight="$work/device-flight.rs"
runtime="$work/production-runtime.rs"
runtime_impl="$work/production-runtime-impl.rs"
dispatch="$work/same-boot-dispatch.rs"
closure_driver="$work/closure-driver.rs"
post_terminal="$work/post-terminal.rs"
publication_apply="$work/publication-apply.rs"
publish="$work/publish.rs"
production_publish="$work/production-publish.rs"
publish_commit="$work/publish-commit.rs"
run_slice="$work/run-slice.rs"
generic_dispatch="$work/generic-dispatch.rs"
guest_loop="$work/guest-loop.rs"
feature_root="$work/feature-root.rs"
semantic_close="$work/semantic-close.rs"
prepared_guest_write="$work/prepared-guest-write.rs"

extract_between "$source_file" 'struct FsState {' \
    'struct FsClosureWork {' "$fs_state"
extract_between "$source_file" 'enum FsDeviceFlight {' \
    'struct ProductionReadRuntime {' "$flight"
extract_between "$source_file" 'struct ProductionReadRuntime {' \
    'impl ProductionReadRuntime {' "$runtime"
extract_between "$source_file" 'impl ProductionReadRuntime {' \
    'struct ProductionReadReceipt {' "$runtime_impl"
extract_between "$source_file" 'fn dispatch_first_executable_pread_same_boot(' \
    'fn dispatch_first_executable_pread(' "$dispatch"
extract_between "$source_file" 'fn drive_closure_flight(&self) -> DispatchOutcome {' \
    'fn dispatch_first_executable_pread(' "$closure_driver"
extract_between "$closure_driver" '.stage_device_batch_terminal(' \
    'retained @ FsDeviceFlight::Retained' "$post_terminal"
extract_between "$source_file" 'fn apply_publication(&self, publication: &Publication)' \
    'fn publish(&self, outcome: &DispatchOutcome) -> PublicationResult {' \
    "$publication_apply"
extract_between "$source_file" \
    'fn publish(&self, outcome: &DispatchOutcome) -> PublicationResult {' \
    'fn finish(&self) {' "$publish"
extract_between "$publish" 'PublicationAuthority::Production {' \
    'PublicationAuthority::Retained { flight_cookie } => {' "$production_publish"
extract_between "$production_publish" \
    '.acknowledge_publication_and_revoke_complete_with_apply(' \
    'runtime.put_flight(FsDeviceFlight::Complete { root, device });' \
    "$publish_commit"
extract_between "$source_file" 'pub(crate) fn run_linux_fs_slice() -> RuntimeFsSliceReceipt {' \
    'fn run_guest(' "$run_slice"
extract_between "$source_file" 'fn dispatch(&self, descriptor: SyscallDescriptor)' \
    'fn apply_publication(&self, publication: &Publication)' "$generic_dispatch"
extract_between "$source_file" 'fn run_guest(' \
    'fn syscall_descriptor(' "$guest_loop"
extract_until_first_after "$lib_file" '    let fs_receipt = linux_fs::run_linux_fs_slice();' \
    '    #[cfg(not(feature = "virtio-cser-facade"))]' "$feature_root"
extract_from "$device_flight_file" \
    'pub(crate) fn commit_or_recover_device_flight_with_apply<T>(' \
    "$semantic_close"
extract_between "$source_file" 'struct PreparedGuestWrite {' \
    'fn same_boot_credit' "$prepared_guest_write"

# RFC 0001 accepts one root, one production Registry, and one ledger. The
# legacy in-memory filesystem Registry may remain in the non-facade build, but
# it may not be instantiated in the accepted same-boot build.
require_count "$runtime" 'registry: EffectRegistry,' 1
require_count "$runtime" 'flight: FsDeviceFlight,' 1
require_count "$runtime" 'next_flight_cookie: NonZeroU64,' 1
require_count "$runtime_impl" 'registry: new_same_boot_registry(),' 1
require_not_feature_guarded_if_present "$fs_state" 'effects: EffectRegistry,'
require_not_feature_guarded_if_present "$source_file" \
    'effects: new_production_registry(),'
require_count "$run_slice" \
    'lifecycle_companion::run_filesystem_lifecycle_companion();' 1
require_not_feature_guarded_if_present "$run_slice" \
    'lifecycle_companion::run_filesystem_lifecycle_companion();'
reject_fixed "$source_file" 'registry=request_local_production'
reject_fixed "$source_file" 'registry=request_local_registry'
reject_fixed "$source_file" 'generic_effects=13 device_cohort_effects=6'
reject_fixed "$source_file" 'generic_effects=1 device_cohort_effects=6'
reject_fixed "$source_file" 'clone_non_device_candidate'
require_at_least "$source_file" 'registry=shared_production' 1
require_at_least "$source_file" 'compatibility_syscalls=payload_only_not_cser' 1

# The runtime slot, not a stack-local compatibility flight, owns every linear
# hardware successor. Old phase/dispatch names are forbidden because they
# allowed root/device/selection state to drift apart.
for forbidden in \
    'SameBootFlight' \
    'SameBootRequest' \
    'SameBootDispatch' \
    'ProductionReadPhase' \
    'active_revoke' \
    'validate_device_replay_fence_candidate' \
    'claim_device_replay_reset_and_revoke'; do
    reject_fixed "$source_file" "$forbidden"
done
for state in \
    'Ready {' \
    'Captured {' \
    'Prepared {' \
    'PreparedCancel {' \
    'Building {' \
    'Published {' \
    'PublishedReset {' \
    'CompletionReset {' \
    'Resetting {' \
    'ResetRetained {' \
    'Iotlb {' \
    'IotlbRetained {' \
    'Draining {' \
    'AwaitingPublication {' \
    'Retained {' \
    'Complete {' \
    'Transitioning'; do
    require_at_least "$flight" "$state" 1
done
require_count "$runtime_impl" \
    'core::mem::replace(&mut self.flight, FsDeviceFlight::Transitioning)' 1
require_count "$runtime_impl" 'debug_assert!(matches!(self.flight, FsDeviceFlight::Transitioning));' 1
reject_regex "$runtime_impl" '^[[:space:]]*assert!\(matches!\(self\.flight, FsDeviceFlight::Transitioning\)\);'
reject_fixed "$runtime_impl" 'check_invariants()'
require_at_least "$runtime_impl" 'self.put_flight(' 3
require_at_least "$runtime_impl" 'FsDeviceFlight::Retained {' 1
require_at_least "$source_file" 'owner_runtime_resident=true' 1
reject_fixed "$dispatch" 'core::mem::forget'
reject_fixed "$dispatch" 'EffectRegistry::new()'

# Semantic identity comes only from the production Registry. This module may
# correlate immutable receipts, but it may not own a second Registry or ledger.
for required in \
    'pub(crate) struct DeviceFlightKey {' \
    'operation: DeviceCloseOperationId,' \
    'pub(crate) struct PublishedSemantic {' \
    'pub(crate) struct RetainedSemantic {' \
    'pub(crate) enum DeviceFlightCloseOutcome<T> {' \
    'DeviceCloseOutcome::Applied {' \
    'DeviceCloseOutcome::Recovered {'; do
    require_at_least "$device_flight_file" "$required" 1
done
reject_fixed "$device_flight_file" 'registry: EffectRegistry'
require_count "$semantic_close" \
    'registry.commit_or_recover_device_close_with_apply(' 1
require_count "$semantic_close" 'publish,' 1
require_count "$semantic_close" 'DeviceCloseOutcome::Recovered { receipt, selection }' 1
reject_fixed "$semantic_close" 'publish(&'

# The real workload creates and enrolls the exact six-effect flight before the
# one close operation. Exact recovery never republishes. A published error is
# converted to a retained semantic obligation and the concrete hardware owner
# remains in the runtime slot.
for required in \
    'DeviceFlightCloseOutcome::Applied {' \
    'DeviceFlightCloseOutcome::Recovered {' \
    'DeviceCloseError::Published {' \
    'RetainedSemantic::from_close_error(' \
    'FsDeviceFlight::Retained {'; do
    require_at_least "$dispatch" "$required" 1
done
require_count "$dispatch" 'runtime.registry.register_derived(' 2
require_count "$dispatch" 'runtime.registry.register_device_derived_cohort([' 1
require_count "$dispatch" '.enroll_device_batch(' 1
require_count "$dispatch" \
    'mint_device_flight_key(&runtime.registry, &enrollment, cookie)' 1
require_count "$dispatch" 'commit_or_recover_device_flight_with_apply(' 1
require_count "$dispatch" '.publish_prepared()' 1
require_at_least "$dispatch" 'runtime.put_flight(' 8
require_at_least "$dispatch" 'runtime.retain_current(' 3
reject_fixed "$dispatch" 'begin_unpublished_device_cancel('
reject_fixed "$dispatch" 'revoke_begin(SCOPE).unwrap()'

# Every syscall after the accepted first pread is compatibility payload only.
# Its feature branch may update the bounded guest fixture, but it cannot touch
# the production Registry or mint another causal effect.
require_count "$generic_dispatch" 'state.compatibility_syscalls += 1;' 1
require_count "$generic_dispatch" \
    'authority: PublicationAuthority::CompatibilityPayload,' 1
require_not_feature_guarded_if_present "$generic_dispatch" \
    'let registered = state.capture(descriptor, resources);'
require_not_feature_guarded_if_present "$generic_dispatch" \
    'let commit = state.commit(&registered, result);'
require_count "$generic_dispatch" \
    'let ticket = state.terminalize(&registered, result, commit);' 1
reject_fixed "$generic_dispatch" 'runtime.registry'
reject_fixed "$generic_dispatch" 'EffectRegistry::new()'

# This witness is polling-only. Facade interrupt preparation/tokens are useful
# substrate, but they are not evidence that an OSTD IRQ actor delivered work.
require_count "$source_file" 'prepare_read_sector0(&mut root)' 1
reject_fixed "$dispatch" 'prepare_read_sector0_irq('
reject_fixed "$dispatch" '.ack_interrupt('
reject_fixed "$dispatch" '.complete_after_interrupt('
reject_fixed "$source_file" 'irq=true'
require_at_least "$source_file" 'polling=true irq=false smp=1' 2

# Completion, reset, IOTLB, drain, and guest publication advance through one
# single-actor flight. Each one-step probe returns the linear owner to the slot
# before its transition boundary; a future IRQ/SMP actor still needs an explicit
# slot lease rather than sharing this synchronous stack handoff.
for required in \
    '.probe_completion_once()' \
    '.probe_ack_once(' \
    'record_device_completion_and_begin_reset_with_apply(' \
    'begin_device_reset_with_apply(' \
    'acknowledge_device_reset_with_apply(' \
    'begin_device_iotlb_with_apply(' \
    'acknowledge_device_iotlb_with_apply(' \
    'stage_device_batch_terminal(' \
    'revoke_complete(' \
    'acknowledge_publication(' \
    'FsDeviceFlight::Complete {'; do
    require_at_least "$source_file" "$required" 1
done
reject_fixed "$dispatch" 'poll_completion()'
reject_fixed "$source_file" '.poll_completion'

# Guest publication is the final cross-object transition. The Registry must
# acknowledge the terminal publication and complete the frozen revoke as one
# failure-atomic operation. The flight remains runtime-resident while all
# checks and the external guest write run; an ordinary rejection writes no
# bytes and prevents the guest from resuming.
require_count "$production_publish" \
    '.acknowledge_publication_and_revoke_complete_with_apply(' 1
reject_fixed "$production_publish" '.acknowledge_publication('
reject_fixed "$production_publish" '.revoke_complete('
reject_fixed "$production_publish" 'self.apply_publication(&outcome.publication)'
reject_fixed "$publish_commit" '.unwrap()'
reject_fixed "$production_publish" \
    'runtime.put_flight(FsDeviceFlight::AwaitingPublication {'
require_count "$production_publish" \
    'PreparedGuestWrite::prepare(&mut cursor, *address, *bytes, *len)' 1
require_count "$production_publish" \
    'let _mapping_lock = mapping_cursor.as_ref();' 1
require_count "$production_publish" 'prepared_publication.apply();' 1
require_order "$production_publish" \
    'let preempt_guard = disable_preempt();' \
    'PreparedGuestWrite::prepare(&mut cursor, *address, *bytes, *len)' \
    'let mut runtime = self.production.lock();' \
    'let selection = match &runtime.flight {' \
    '.acknowledge_publication_and_revoke_complete_with_apply(' \
    'let _mapping_lock = mapping_cursor.as_ref();' \
    'prepared_publication.apply();' \
    '.is_err()' \
    'drop(mapping_cursor);' \
    'drop(preempt_guard);' \
    'let flight = runtime.take_flight();' \
    'runtime.put_flight(FsDeviceFlight::Complete { root, device });'

# The production guest write is prepared against one locked, writable RAM
# mapping and owns a frame reference before Registry validation. Its apply path
# uses only the frame's infallible kernel writer and cannot partially fault.
for required in \
    'VmQueriedItem::MappedRam { frame, prop }' \
    'prop.flags.contains(PageFlags::W)' \
    'offset.checked_add(len)? > ostd::mm::PAGE_SIZE' \
    'frame: frame.clone(),' \
    'let mut destination = self.frame.writer();' \
    'destination.skip(self.offset).limit(self.len);' \
    'let _ = destination.write(&mut source);'; do
    require_count "$prepared_guest_write" "$required" 1
done
reject_fixed "$prepared_guest_write" 'write_fallible('
reject_fixed "$prepared_guest_write" '.expect('
reject_fixed "$prepared_guest_write" '.unwrap('
reject_fixed "$prepared_guest_write" 'assert!('
reject_fixed "$prepared_guest_write" 'assert_eq!('

# Terminalization cannot allocate the reply after device ownership has been
# drained. The fixed payload is copied before AwaitingPublication and borrowed
# directly by publish(). Compatibility paths may still allocate their own
# payloads outside this production terminal boundary.
for required in \
    'let guest_bytes = work.bytes;' \
    'Publication::FixedGuestBytes {' \
    'bytes: guest_bytes,'; do
    require_count "$post_terminal" "$required" 1
done
reject_fixed "$post_terminal" '.to_vec()'
reject_fixed "$post_terminal" 'Vec::'
reject_fixed "$post_terminal" '.collect('
reject_fixed "$post_terminal" 'check_invariants()'
require_count "$publish" 'Publication::FixedGuestBytes { len, .. }' 1

# Publication status is consumed before the next user-mode entry. A retained
# owner is an immediate fail-stop in this bounded witness, never a guest-visible
# result followed by compatibility execution.
require_count "$guest_loop" 'let publication = scenario.publish(&outcome);' 1
require_count "$guest_loop" 'assert_eq!(' 1
require_order "$guest_loop" \
    'let outcome = scenario.dispatch(descriptor);' \
    'user_mode.context_mut().set_rax(outcome.result as usize);' \
    'let publication = scenario.publish(&outcome);' \
    'assert_eq!(' \
    'PublicationResult::Complete,' \
    'if outcome.exit {'

# The feature root consumes only the production receipt and terminates before
# any legacy filesystem/network successor can manufacture composition evidence.
for required in \
    'assert_eq!(fs_receipt.production_effects, 6);' \
    'assert!(fs_receipt.preparation_identity_observed);' \
    'println!("SPIKE_RESULT PASS");' \
    'poweroff(ExitCode::Success);'; do
    require_at_least "$feature_root" "$required" 1
done
reject_fixed "$feature_root" 'linux_net::run_linux_net_slice();'

if [[ ${NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY:-0} != 1 ]]; then
    mutations=0

    require_mutation() {
        ((mutations += 1))
        ! cmp -s -- "$1" "$2" || fail "source mutation did not change input: $3"
    }

    require_source_rejection() {
        if NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 bash "$0" "$1" "$lib_file" \
            "$device_flight_file" >/dev/null 2>&1; then
            fail "source gate accepted mutation: $2"
        fi
    }

    require_lib_rejection() {
        if NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 bash "$0" "$source_file" "$1" \
            "$device_flight_file" >/dev/null 2>&1; then
            fail "source gate accepted lib mutation: $2"
        fi
    }

    require_semantic_rejection() {
        if NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 bash "$0" "$source_file" "$lib_file" \
            "$1" >/dev/null 2>&1; then
            fail "source gate accepted semantic mutation: $2"
        fi
    }

    cp "$source_file" "$work/stale-phase.rs"
    sed -i '1i // ProductionReadPhase compatibility is forbidden' "$work/stale-phase.rs"
    require_mutation "$source_file" "$work/stale-phase.rs" stale-phase
    require_source_rejection "$work/stale-phase.rs" stale-phase

    awk '
        NR == 1 { previous = $0; next }
        {
            if ($0 ~ /^[[:space:]]*effects: EffectRegistry,$/ &&
                previous ~ /^[[:space:]]*#\[cfg\(not\(feature = "virtio-cser-facade"\)\)\]$/) {
                print $0
                previous = ""
                changed = 1
                next
            }
            if (previous != "") print previous
            previous = $0
        }
        END {
            if (previous != "") print previous
            if (!changed) exit 2
        }
    ' "$source_file" >"$work/second-registry.rs"
    require_mutation "$source_file" "$work/second-registry.rs" second-registry
    require_source_rejection "$work/second-registry.rs" second-registry

    cp "$source_file" "$work/request-local-registry.rs"
    sed -i '0,/registry=shared_production/s//registry=request_local_production/' \
        "$work/request-local-registry.rs"
    require_mutation "$source_file" "$work/request-local-registry.rs" request-local-registry
    require_source_rejection "$work/request-local-registry.rs" request-local-registry

    cp "$source_file" "$work/irq-claim.rs"
    sed -i '0,/polling=true irq=false smp=1/s//polling=true irq=true smp=1/' \
        "$work/irq-claim.rs"
    require_mutation "$source_file" "$work/irq-claim.rs" irq-claim
    require_source_rejection "$work/irq-claim.rs" irq-claim

    cp "$source_file" "$work/release-assert.rs"
    sed -i '0,/debug_assert!(matches!(self.flight/s//assert!(matches!(self.flight/' \
        "$work/release-assert.rs"
    require_mutation "$source_file" "$work/release-assert.rs" release-assert
    require_source_rejection "$work/release-assert.rs" release-assert

    cp "$source_file" "$work/missing-retained-semantic.rs"
    sed -i '0,/RetainedSemantic::from_close_error(/s//discard_published_obligation(/' \
        "$work/missing-retained-semantic.rs"
    require_mutation "$source_file" "$work/missing-retained-semantic.rs" \
        missing-retained-semantic
    require_source_rejection "$work/missing-retained-semantic.rs" \
        missing-retained-semantic

    cp "$device_flight_file" "$work/recovery-republishes.rs"
    sed -i \
        '0,/DeviceCloseOutcome::Recovered { receipt, selection } => {/s//DeviceCloseOutcome::Recovered { receipt, selection } => { let _ = publish(\&receipt);/' \
        "$work/recovery-republishes.rs"
    require_mutation "$device_flight_file" "$work/recovery-republishes.rs" \
        recovery-republishes
    require_semantic_rejection "$work/recovery-republishes.rs" recovery-republishes

    cp "$lib_file" "$work/feature-legacy-successor.rs"
    awk '
        /assert_eq!\(fs_receipt\.production_effects, 6\);/ { feature = 1 }
        feature && !changed && /println!\("SPIKE_RESULT PASS"\);/ {
            print "        linux_net::run_linux_net_slice();"
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$lib_file" >"$work/feature-legacy-successor.rs"
    require_mutation "$lib_file" "$work/feature-legacy-successor.rs" feature-legacy-successor
    require_lib_rejection "$work/feature-legacy-successor.rs" feature-legacy-successor

    awk '
        !changed && /\.acknowledge_publication_and_revoke_complete_with_apply\(/ {
            print "                    .acknowledge_publication(ticket)"
            print "                    .and_then(|_| runtime.registry.revoke_complete(&selection))"
            changed = 1
            next
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/split-publication-revoke.rs"
    require_mutation "$source_file" "$work/split-publication-revoke.rs" \
        split-publication-revoke
    require_source_rejection "$work/split-publication-revoke.rs" \
        split-publication-revoke

    awk '
        NR == 1 { previous = $0; next }
        {
            if ($0 ~ /^[[:space:]]*lifecycle_companion::run_filesystem_lifecycle_companion\(\);$/ &&
                previous ~ /^[[:space:]]*#\[cfg\(not\(feature = "virtio-cser-facade"\)\)\]$/) {
                print $0
                previous = ""
                changed = 1
                next
            }
            if (previous != "") print previous
            previous = $0
        }
        END {
            if (previous != "") print previous
            if (!changed) exit 2
        }
    ' "$source_file" >"$work/facade-companion.rs"
    require_mutation "$source_file" "$work/facade-companion.rs" facade-companion
    require_source_rejection "$work/facade-companion.rs" facade-companion

    awk '
        { print }
        !changed && /runtime\.registry\.register_derived\(DerivedRegisterRequest/ {
            print "            let _extra = runtime.registry.register_derived(DerivedRegisterRequest {"
            changed = 1
        }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/extra-production-effect.rs"
    require_mutation "$source_file" "$work/extra-production-effect.rs" \
        extra-production-effect
    require_source_rejection "$work/extra-production-effect.rs" \
        extra-production-effect

    awk '
        { print }
        !changed && /assert_eq!\(pending\.pending_publications, 1\);/ {
            print "                    runtime.registry.check_invariants().unwrap();"
            changed = 1
        }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/post-terminal-invariant-allocation.rs"
    require_mutation "$source_file" "$work/post-terminal-invariant-allocation.rs" \
        post-terminal-invariant-allocation
    require_source_rejection "$work/post-terminal-invariant-allocation.rs" \
        post-terminal-invariant-allocation

    awk '
        /let publication = scenario\.publish\(&outcome\);/ { armed = 1 }
        armed && !changed && /assert_eq!\(/ {
            sub(/assert_eq!/, "drop")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/resume-retained-publication.rs"
    require_mutation "$source_file" "$work/resume-retained-publication.rs" \
        resume-retained-publication
    require_source_rejection "$work/resume-retained-publication.rs" \
        resume-retained-publication

    cp "$source_file" "$work/fallible-production-guest-write.rs"
    sed -i \
        '0,/prepared_publication\.apply();/s//self.apply_publication(\&outcome.publication);/' \
        "$work/fallible-production-guest-write.rs"
    require_mutation "$source_file" "$work/fallible-production-guest-write.rs" \
        fallible-production-guest-write
    require_source_rejection "$work/fallible-production-guest-write.rs" \
        fallible-production-guest-write

    [[ $mutations == 14 ]] || fail "expected 14 source mutations, observed $mutations"
fi

echo 'runtime filesystem same-boot source assertions: PASS checkpoint=device_flight accepted_registry=one accepted_ledger=one compatibility_syscalls=payload_only_not_cser flight=single_actor_slot_handoff actor_resident=false semantic_identity=registry_issued published_error=retained ack_revoke=failure_atomic guest_write=prevalidated+infallible_frame_apply fail_stop=before_guest_resume post_terminal_allocation=false facade_companion=false polling=true irq_evidence=false smp=1 legacy_phase=false rfc0001_full_closure=false mutations=14'
