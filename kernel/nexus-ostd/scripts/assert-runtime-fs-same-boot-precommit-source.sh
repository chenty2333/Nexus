#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_file=${1:-$script_root/src/personality/linux_fs.rs}
lib_file=${2:-$script_root/src/lib.rs}
facade_file=${3:-$script_root/../../crates/nexus-ostd-virtio/src/production.rs}

fail() {
    echo "runtime filesystem same-boot precommit source assertion: FAIL: $*" >&2
    exit 1
}

for input in "$source_file" "$lib_file" "$facade_file"; do
    [[ -f $input && ! -L $input ]] ||
        fail "implementation source is not a regular non-symlink file: $input"
done
for command_name in awk bash cmp cp grep mapfile mktemp rm sed wc; do
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

extract_through_first_after() {
    local file=$1
    local start_pattern=$2
    local end_pattern=$3
    local output=$4
    local start
    start=$(line_of_unique "$file" "$start_pattern")
    awk -v start="$start" -v end_pattern="$end_pattern" '
        NR >= start {
            print
            if (NR > start && index($0, end_pattern)) {
                found = 1
                exit
            }
        }
        END { if (!found) exit 2 }
    ' "$file" >"$output" ||
        fail "missing end boundary '$end_pattern' after '$start_pattern'"
    [[ -s $output ]] || fail "empty extracted source boundary: $start_pattern"
}

require_line_count() {
    local actual
    actual=$(wc -l <"$1")
    [[ $actual == "$2" ]] ||
        fail "expected $2 lines in $1, observed $actual"
}

require_cfg_before() {
    local file=$1
    local pattern=$2
    local expected=$3
    local line previous
    line=$(line_of_unique "$file" "$pattern")
    ((line > 1)) || fail "source anchor has no cfg predecessor: $pattern"
    previous=$(sed -n "$((line - 1))p" "$file" |
        sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [[ $previous == "$expected" ]] ||
        fail "source anchor '$pattern' is not directly gated by $expected"
}

require_cfg_near_before() {
    local file=$1
    local pattern=$2
    local expected=$3
    local line start count
    line=$(line_of_unique "$file" "$pattern")
    ((line > 1)) || fail "source anchor has no cfg predecessor: $pattern"
    start=$((line > 4 ? line - 4 : 1))
    count=$(sed -n "${start},$((line - 1))p" "$file" |
        grep -F -c -- "$expected" || true)
    [[ $count == 1 ]] ||
        fail "source anchor '$pattern' is not gated nearby by $expected"
}

require_adjacent_pair_count() {
    local file=$1
    local first=$2
    local second=$3
    local expected=$4
    local actual
    actual=$(awk -v first="$first" -v second="$second" '
        {
            line = $0
            sub(/^[[:space:]]*/, "", line)
            sub(/[[:space:]]*$/, "", line)
            if (previous == first && line == second)
                count++
            previous = line
        }
        END { print count + 0 }
    ' "$file")
    [[ $actual == "$expected" ]] ||
        fail "expected $expected adjacent '$first' -> '$second' pair(s) in $file, observed $actual"
}

receipt="$work/runtime-fs-receipt.rs"
runtime="$work/production-runtime.rs"
helper="$work/precommit-close.rs"
marker_transition="$work/enrolled-witness-marker.rs"
same_boot="$work/same-boot-dispatch.rs"
entry="$work/same-boot-entry.rs"
fault="$work/precommit-branch.rs"
handles="$work/enrollment-handles.rs"
effects="$work/precommit-effects.rs"
leaves="$work/precommit-leaves.rs"
dispatch_route="$work/dispatch-route.rs"
publication="$work/publication.rs"
finish="$work/finish.rs"
run_slice="$work/run-slice.rs"
positive_projection="$work/positive-receipt-projection.rs"
fault_projection="$work/fault-receipt-projection.rs"
receipt_assembly="$work/runtime-fs-receipt-assembly.rs"
run_guest="$work/run-guest.rs"
descriptor_builder="$work/descriptor-builder.rs"
prepared_impl="$work/prepared-request.rs"
cancel_method="$work/cancel-prepared.rs"
cancelled_impl="$work/cancelled-request.rs"
post_fs="$work/post-fs-root.rs"
positive_root="$work/positive-root.rs"
fault_root="$work/precommit-root.rs"
legacy_root="$work/legacy-root.rs"

extract_between "$source_file" \
    'pub(crate) struct RuntimeFsSliceReceipt {' \
    'enum FdKind {' "$receipt"
extract_between "$source_file" \
    'struct ProductionReadRuntime {' \
    'enum SameBootRequest {' "$runtime"
extract_between "$source_file" \
    'fn close_enrolled_precommit_failure(' \
    'fn dispatch_first_executable_pread_same_boot(' "$helper"
extract_through_first_after "$helper" \
    'runtime.phase = ProductionReadPhase::AwaitingPublication(cookie);' \
    'runtime.enrolled_revoke_wins_observed = true;' "$marker_transition"
extract_between "$source_file" \
    'fn dispatch_first_executable_pread_same_boot(' \
    'fn dispatch_first_executable_pread(' "$same_boot"
extract_between "$same_boot" \
    'fn dispatch_first_executable_pread_same_boot(' \
    '// Capture the real UserContext descriptor before fd/inode resolution.' "$entry"
extract_between "$same_boot" \
    '            #[cfg(feature = "virtio-cser-precommit-fault")]' \
    '            #[cfg(not(feature = "virtio-cser-precommit-fault"))]' "$fault"
extract_between "$same_boot" \
    '            let handles = [' '            let enrollment = match runtime' "$handles"
extract_through_first_after "$fault" \
    '                let effects = [' '                ];' "$effects"
extract_through_first_after "$helper" \
    '            let leaf_first = [' '            ];' "$leaves"
extract_between "$source_file" \
    'fn dispatch(&self, descriptor: SyscallDescriptor) -> DispatchOutcome {' \
    'fn publish(&self, outcome: &DispatchOutcome) {' "$dispatch_route"
extract_between "$source_file" \
    'fn publish(&self, outcome: &DispatchOutcome) {' 'fn finish(&self) {' "$publication"
extract_between "$source_file" \
    'fn finish(&self) {' 'enum FsAction {' "$finish"
extract_between "$source_file" \
    'pub(crate) fn run_linux_fs_slice() -> RuntimeFsSliceReceipt {' \
    'fn run_guest(scenario: Arc<FsScenario>' "$run_slice"
extract_through_first_after "$run_slice" \
    'let (production_effects, preparation_identity_observed) = {' \
    '    };' "$positive_projection"
extract_through_first_after "$run_slice" \
    'let (production_effects, preparation_identity_observed, enrolled_revoke_wins_observed) = {' \
    '    };' "$fault_projection"
extract_through_first_after "$run_slice" \
    '    RuntimeFsSliceReceipt {' \
    '    }' "$receipt_assembly"
extract_between "$source_file" \
    'fn run_guest(scenario: Arc<FsScenario>' 'fn syscall_descriptor(' "$run_guest"
extract_between "$source_file" \
    'fn syscall_descriptor(context: &UserContext) -> SyscallDescriptor {' \
    'fn read_guest_bytes(' "$descriptor_builder"
extract_between "$facade_file" \
    'impl PreparedRequest {' 'impl Drop for PreparedRequest {' "$prepared_impl"
extract_between "$prepared_impl" \
    'pub fn cancel_prepared(self) -> CancelledRequest {' \
    '/// Rolls back hardware preparation which could not be installed as a' \
    "$cancel_method"
extract_between "$facade_file" \
    'impl CancelledRequest {' 'impl Drop for CancelledRequest {' "$cancelled_impl"
extract_from "$lib_file" \
    '    let fs_receipt = linux_fs::run_linux_fs_slice();' "$post_fs"
extract_between "$post_fs" \
    '    #[cfg(all(' '    #[cfg(feature = "virtio-cser-precommit-fault")]' "$positive_root"
extract_between "$post_fs" \
    '    #[cfg(feature = "virtio-cser-precommit-fault")]' \
    '    #[cfg(not(feature = "virtio-cser-facade"))]' "$fault_root"
extract_from "$post_fs" \
    '    #[cfg(not(feature = "virtio-cser-facade"))]' "$legacy_root"

require_cfg_near_before "$source_file" 'fn close_enrolled_precommit_failure(' \
    '#[cfg(feature = "virtio-cser-facade")]'
require_cfg_near_before "$source_file" 'fn dispatch_first_executable_pread_same_boot(' \
    '#[cfg(feature = "virtio-cser-facade")]'

# A feature-local provenance bit distinguishes the one enrolled revoke-wins
# witness from handled failures which can honestly report the same 6/true
# effect/preparation projection. It must start false and reach the exported
# receipt only through the sealed fault path below.
require_count "$receipt" 'pub(crate) enrolled_revoke_wins_observed: bool,' 1
require_cfg_before "$receipt" \
    'pub(crate) enrolled_revoke_wins_observed: bool,' \
    '#[cfg(feature = "virtio-cser-precommit-fault")]'
require_count "$runtime" 'enrolled_revoke_wins_observed: bool,' 1
require_cfg_before "$runtime" \
    'enrolled_revoke_wins_observed: bool,' \
    '#[cfg(feature = "virtio-cser-precommit-fault")]'
require_count "$runtime" 'enrolled_revoke_wins_observed: false,' 1
require_cfg_before "$runtime" \
    'enrolled_revoke_wins_observed: false,' \
    '#[cfg(feature = "virtio-cser-precommit-fault")]'

# Seal the canonical entry. An early return, dead wrapper, or helper call cannot
# leave the complete production implementation as unreachable token bait.
require_line_count "$entry" 9
require_order "$entry" \
    'fn dispatch_first_executable_pread_same_boot(' \
    '        assert_eq!(descriptor.number(), __NR_pread64 as usize);' \
    '        assert_eq!(descriptor.argument(0), 3);' \
    '        assert_eq!(descriptor.argument(2), 4);' \
    '        assert_eq!(descriptor.argument(3), 0);'
reject_regex "$entry" '(^|[[:space:]])(return|if|match|loop|while|for)[[:space:]]'
reject_regex "$same_boot" 'if[[:space:]]+(false|true)[[:space:]]*\{'
require_regex_count "$same_boot" '(^|[^[:alnum:]_])return[[:space:]]+' 1
require_order "$same_boot" \
    '            #[cfg(feature = "virtio-cser-precommit-fault")]' \
    'SameBootDispatch::Precommit(self.close_enrolled_precommit_failure(' \
    '            #[cfg(not(feature = "virtio-cser-precommit-fault"))]' \
    'SameBootDispatch::Published(SameBootFlight {' \
    '        let flight = match flight {' \
    'SameBootDispatch::Published(flight) => flight,' \
    'SameBootDispatch::Precommit(outcome) => return outcome,' \
    '        let SameBootFlight {' \
    'let notification = published.notify();'

# Bind the real UserContext descriptor and the production dispatch route.
require_order "$run_guest" \
    'ReturnReason::UserSyscall => {' \
    'let descriptor = syscall_descriptor(user_mode.context());' \
    'let outcome = scenario.dispatch(descriptor);' \
    'user_mode.context_mut().set_rax(outcome.result as usize);' \
    'scenario.publish(&outcome);' \
    'if outcome.exit {' \
    'scenario.finish();' \
    'return;'
require_order "$descriptor_builder" \
    'SyscallDescriptor::new(' 'context.rax(),' 'context.rdi(),' 'context.rsi(),' \
    'context.rdx(),' 'context.r10(),' 'context.r8(),' 'context.r9(),'
require_order "$dispatch_route" \
    'if descriptor.number() == __NR_pread64 as usize && !state.production_read_observed {' \
    '#[cfg(feature = "virtio-cser-facade")]' \
    'drop(state);' \
    'return self.dispatch_first_executable_pread_same_boot(descriptor);'
require_count "$dispatch_route" 'dispatch_first_executable_pread_same_boot(descriptor)' 1
reject_fixed "$dispatch_route" 'SyscallDescriptor::new('

# The exact-six cohort is enrolled and preflighted before the injected revoke.
require_line_count "$handles" 8
for handle in \
    'syscall.handle,' 'adopted_filesystem,' 'block.handle,' \
    'dma_queue_a.handle,' 'dma_queue_b.handle,' 'dma_request.handle,'; do
    require_count "$handles" "$handle" 1
done
require_regex_count "$handles" \
    '^[[:space:]]+(syscall\.handle|adopted_filesystem|block\.handle|dma_queue_a\.handle|dma_queue_b\.handle|dma_request\.handle),$' 6
require_order "$same_boot" \
    '.prepare_read_sector0(&mut root)' \
    '.register_device_derived_cohort([' \
    'for effect in [&block, &dma_queue_a, &dma_queue_b, &dma_request] {' \
    '.kernel_root_authority(SCOPE, ROOT_OWNER)' \
    '            let handles = [' \
    '.enroll_device_batch(authority, &handles, envelope)' \
    '.preflight_publish(expected_hardware_identity)' \
    '            #[cfg(feature = "virtio-cser-precommit-fault")]'
require_count "$same_boot" '.register_device_derived_cohort([' 1
require_count "$same_boot" '.enroll_device_batch(authority, &handles, envelope)' 1
require_count "$same_boot" '.preflight_publish(expected_hardware_identity)' 1

# Revocation wins before commit apply. The publication closure may contain the
# sole publish call, but StaleAuthority must prevent it from being invoked.
require_order "$fault" \
    'LINUX_FS_SAME_BOOT_PRECOMMIT Capture stage=enrolled_preflight' \
    'LINUX_FS_SAME_BOOT_PRECOMMIT DmaOwner kind={}' \
    'let selection = runtime.registry.revoke_begin(SCOPE).unwrap();' \
    'assert_eq!(selection.target_count, 6);' \
    'let mut prepared_slot = Some(prepared_request);' \
    'let mut publish_closure_calls = 0_usize;' \
    'let commit = runtime.registry.commit_device_batch_with_publish(' \
    'publish_closure_calls += 1;' \
    '                            .publish_prepared()' \
    'assert!(matches!(commit, Err(RegistryError::StaleAuthority)));' \
    'assert_eq!(publish_closure_calls, 0);' \
    'assert!(prepared_slot.is_some());' \
    '.begin_unpublished_device_cancel(&enrollment)' \
    'let prepared = prepared_slot' \
    'drop(runtime);' \
    'LINUX_FS_SAME_BOOT_PRECOMMIT CommitRejected error=StaleAuthority' \
    'SameBootDispatch::Precommit(self.close_enrolled_precommit_failure('
require_count "$fault" '.publish_prepared()' 1
require_count "$fault" '.take()' 2
require_count "$fault" '.begin_unpublished_device_cancel(&enrollment)' 1
require_count "$fault" 'runtime.registry.revoke_begin(SCOPE).unwrap();' 1
require_count "$fault" 'commit_device_batch_with_publish(' 1
reject_fixed "$fault" 'prepared_request.publish_prepared()'
for forbidden in 'published.notify()' 'poll_completion()' 'CompletedRequest' \
    'Publication::GuestBytes' 'EffectRegistry::new' 'RUNTIME_FS_ELF'; do
    reject_fixed "$fault" "$forbidden"
done

require_line_count "$effects" 8
for effect in \
    'syscall.identity.effect(),' 'filesystem.identity.effect(),' \
    'block.identity.effect(),' 'dma_queue_a.identity.effect(),' \
    'dma_queue_b.identity.effect(),' 'dma_request.identity.effect(),'; do
    require_count "$effects" "$effect" 1
done

# Cancellation retains the linear owner through reset and IOTLB apply, then
# closes all six effects in the frozen leaf-first order with Aborted(-125).
require_order "$helper" \
    'let reset_tombstone = prepared.cancel_prepared().begin_reset(true);' \
    '.retain_device_reset_timeout(&reset_ticket)' \
    '.retry_device_reset(&tombstone)' \
    'let mut hardware_reset = match reset_tombstone.retry_ack(&mut root) {' \
    '.prepare_generation_advance(&mut hardware_reset)' \
    '.acknowledge_device_reset_with_apply(&retry_ticket, |prepared| {' \
    'generation_plan.apply()' \
    '.begin_device_iotlb(&registry_reset)' \
    'device.begin_iotlb(hardware_reset, true)' \
    '.retain_device_iotlb_timeout(&registry_iotlb)' \
    '.retry_device_iotlb(&registry_reset, &tombstone)' \
    'hardware_iotlb.retry(1024)' \
    '.prepare_quiescence_apply(&mut hardware_closure)' \
    '.acknowledge_device_iotlb_with_apply(&registry_iotlb_retry, |prepared| {' \
    'quiescence_plan.apply()' \
    '            let leaf_first = [' \
    'TerminalRequest::aborted(-125)' \
    'runtime.registry.revoke_next(&selection).unwrap().is_none()' \
    'let publication = publication.expect("precommit root publication ticket");' \
    'runtime.root = Some(root);' \
    'runtime.device = Some(device);' \
    'runtime.active_revoke = Some(selection.clone());' \
    'runtime.phase = ProductionReadPhase::AwaitingPublication(cookie);' \
    'result: -125,' \
    'publication: Publication::None,'
require_count "$helper" 'exit: true,' 1
require_line_count "$leaves" 8
for leaf in \
    '(effects[3], "dma_queue_owner_a"),' \
    '(effects[4], "dma_queue_owner_b"),' \
    '(effects[5], "dma_request_owner"),' \
    '(effects[2], "block_request"),' \
    '(effects[1], "filesystem_read"),' \
    '(effects[0], "filesystem_syscall"),'; do
    require_count "$leaves" "$leaf" 1
done
require_count "$helper" '.revoke_next(&selection)' 2
require_count "$helper" '.stage_device_batch_terminal(' 1
require_count "$helper" 'TerminalRequest::aborted(-125)' 1
require_order "$marker_transition" \
    'runtime.phase = ProductionReadPhase::AwaitingPublication(cookie);' \
    'runtime.registry.check_invariants().unwrap();' \
    '#[cfg(feature = "virtio-cser-precommit-fault")]' \
    'if fault_markers {' \
    'runtime.enrolled_revoke_wins_observed = true;'
require_count "$helper" 'runtime.enrolled_revoke_wins_observed = true;' 1
require_adjacent_pair_count "$helper" \
    'if fault_markers {' \
    'runtime.enrolled_revoke_wins_observed = true;' 1
for forbidden in '.publish_prepared()' '.notify()' '.poll_completion()' \
    'Publication::GuestBytes' 'EffectRegistry::new' 'RUNTIME_FS_ELF'; do
    reject_fixed "$helper" "$forbidden"
done

# Facade cancellation consumes the exact unpublished queue and all three DMA
# shares; no cloneable or implicit Drop path can substitute for it.
require_order "$cancel_method" \
    'pub fn cancel_prepared(self) -> CancelledRequest {' \
    'let prepared = unsafe { ManuallyDrop::take(&mut this.queue) };' \
    'let mut buffers = unsafe { ManuallyDrop::take(&mut this.buffers) };' \
    'let queue = unsafe { prepared.cancel_prepared(&inputs, &mut outputs) };' \
    'dma::request_share_counts(this.identity.device_generation),' \
    'published: false,'
require_count "$cancel_method" 'pub fn cancel_prepared(self) -> CancelledRequest {' 1
require_count "$cancel_method" 'prepared.cancel_prepared(&inputs, &mut outputs)' 1
require_order "$cancelled_impl" \
    'pub fn begin_reset(mut self, inject_pending_once: bool) -> ProductionResetTombstone {' \
    'self.session.take().expect("cancelled request session"),' \
    'inject_pending_once,'
reject_fixed "$cancel_method" '#[derive(Clone'
reject_fixed "$cancelled_impl" '#[derive(Clone'

# Production publication acknowledges the -125 root ticket and completes the
# same revoke selection before the terminal feature receipt.
require_order "$publication" \
    'runtime.registry.acknowledge_publication(ticket).unwrap();' \
    '.active_revoke' \
    'runtime.registry.revoke_complete(&selection).unwrap();' \
    'runtime.phase = ProductionReadPhase::Complete;' \
    'runtime.assert_complete();' \
    '#[cfg(feature = "virtio-cser-precommit-fault")]' \
    'if runtime.enrolled_revoke_wins_observed {' \
    'assert_eq!(outcome.result, -125);' \
    'assert!(matches!(outcome.publication, Publication::None));' \
    'LINUX_FS_SAME_BOOT_PRECOMMIT GuestPublication result=-125 bytes=0' \
    'LINUX_FS_SAME_BOOT_PRECOMMIT PASS scope=95 effects=6 credits_free={}'
require_count "$publication" 'runtime.registry.acknowledge_publication(ticket).unwrap();' 1
require_count "$publication" 'runtime.registry.revoke_complete(&selection).unwrap();' 1
require_count "$publication" 'if runtime.enrolled_revoke_wins_observed {' 1
require_cfg_before "$publication" \
    'if runtime.enrolled_revoke_wins_observed {' \
    '#[cfg(feature = "virtio-cser-precommit-fault")]'

# The fault run terminates after the two-syscall prefix; it may not resume the
# guest's failure branch or execute legacy network/composition successors.
require_order "$positive_projection" \
    'let (production_effects, preparation_identity_observed) = {' \
    'production.registered_effects,' \
    'production.preparation_identity_observed,' \
    '    };'
require_count "$positive_projection" 'production.registered_effects,' 1
require_count "$positive_projection" 'production.preparation_identity_observed,' 1
reject_fixed "$positive_projection" 'enrolled_revoke_wins_observed'
require_cfg_near_before "$run_slice" \
    'let (production_effects, preparation_identity_observed) = {' \
    '#[cfg(all('

require_order "$fault_projection" \
    'let (production_effects, preparation_identity_observed, enrolled_revoke_wins_observed) = {' \
    'production.registered_effects,' \
    'production.preparation_identity_observed,' \
    'production.enrolled_revoke_wins_observed,' \
    '    };'
require_count "$fault_projection" 'production.registered_effects,' 1
require_count "$fault_projection" 'production.preparation_identity_observed,' 1
require_count "$fault_projection" 'production.enrolled_revoke_wins_observed,' 1
require_cfg_before "$run_slice" \
    'let (production_effects, preparation_identity_observed, enrolled_revoke_wins_observed) = {' \
    '#[cfg(feature = "virtio-cser-precommit-fault")]'

require_order "$receipt_assembly" \
    '        production_effects,' \
    '        preparation_identity_observed,' \
    '        #[cfg(feature = "virtio-cser-precommit-fault")]' \
    '        enrolled_revoke_wins_observed,'
require_count "$receipt_assembly" '        production_effects,' 1
require_count "$receipt_assembly" '        preparation_identity_observed,' 1
require_count "$receipt_assembly" '        enrolled_revoke_wins_observed,' 1
require_cfg_before "$receipt_assembly" \
    '        enrolled_revoke_wins_observed,' \
    '#[cfg(feature = "virtio-cser-precommit-fault")]'

require_order "$run_slice" \
    'task.run();' \
    'done_waiter.wait();' \
    'scenario.state.lock().assert_precommit_final();' \
    'let (production_effects, preparation_identity_observed) = {' \
    'let (production_effects, preparation_identity_observed, enrolled_revoke_wins_observed) = {' \
    'let terminalizations = 14;' \
    'let terminalizations = scenario.state.lock().syscall_terminalizations + 1;' \
    'let publication_acks = terminalizations;' \
    '    RuntimeFsSliceReceipt {'
require_count "$run_slice" \
    'let terminalizations = scenario.state.lock().syscall_terminalizations + 1;' 1
require_count "$run_slice" 'let publication_acks = terminalizations;' 1
require_count "$run_slice" 'production.enrolled_revoke_wins_observed,' 1
require_cfg_before "$run_slice" 'scenario.state.lock().assert_precommit_final();' \
    '#[cfg(feature = "virtio-cser-precommit-fault")]'
require_order "$finish" \
    'if enrolled_revoke_wins_observed {' \
    'EFFECT_REGISTRY Quiescent workload=linux-runtime-fs generic_effects=1 device_cohort_effects=6' \
    'LINUX_FS_SLICE PASS workload=linux-runtime-fs-smoke retained=true adapted=false syscalls=2 openat=1 pread64=1' \
    'enrolled_revoke_wins_observed=false'
require_count "$finish" 'if enrolled_revoke_wins_observed {' 1
require_cfg_before "$finish" \
    'if enrolled_revoke_wins_observed {' \
    '#[cfg(feature = "virtio-cser-precommit-fault")]'
require_count "$finish" 'enrolled_revoke_wins_observed=false' 1
reject_regex "$finish" \
    'LINUX_FS_SLICE PASS .*enrolled_revoke_wins_observed=false'
require_count "$finish" 'precommit_fault=true' 1
require_count "$finish" 'state.assert_precommit_final();' 2
require_adjacent_pair_count "$finish" \
    '#[cfg(feature = "virtio-cser-precommit-fault")]' \
    'state.assert_precommit_final();' 1
require_order "$fault_root" \
    '    #[cfg(feature = "virtio-cser-precommit-fault")]' \
    'assert_eq!(fs_receipt.terminalizations, 2);' \
    'assert_eq!(fs_receipt.publication_acks, 2);' \
    'assert_eq!(fs_receipt.production_effects, 6);' \
    'assert_eq!(fs_receipt.production_domains, 3);' \
    'assert!(fs_receipt.enrolled_revoke_wins_observed);' \
    'assert!(fs_receipt.quiescent);' \
    'LINUX_FS_SAME_BOOT_PRECOMMIT Terminal receipt_checked=true' \
    'println!("SPIKE_RESULT PASS");' \
    'poweroff(ExitCode::Success);'
require_count "$fault_root" 'println!("SPIKE_RESULT PASS");' 1
require_count "$fault_root" 'poweroff(ExitCode::Success);' 1
require_count "$fault_root" 'assert!(fs_receipt.enrolled_revoke_wins_observed);' 1
for successor in 'linux_net::run_linux_net_slice' \
    'composition::run_composition_slice' \
    'linux_io_composition::run_linux_io_composition_slice' 'IOMMU_PROBE PASS'; do
    reject_fixed "$fault_root" "$successor"
done

require_count "$positive_root" 'feature = "virtio-cser-facade"' 1
require_count "$positive_root" 'not(feature = "virtio-cser-precommit-fault")' 1
for module_path in \
    '#[path = "cser/composition.rs"]' '#[path = "probes/iommu_probe.rs"]' \
    '#[path = "cser/linux_io_composition.rs"]' '#[path = "personality/linux_net.rs"]'; do
    require_cfg_before "$lib_file" "$module_path" \
        '#[cfg(not(feature = "virtio-cser-facade"))]'
done
require_order "$legacy_root" \
    '    #[cfg(not(feature = "virtio-cser-facade"))]' \
    'linux_net::run_linux_net_slice();' \
    'composition::run_composition_slice(scheduler, pager_receipt);' \
    'linux_io_composition::run_linux_io_composition_slice(' \
    'println!("SPIKE_RESULT PASS");' \
    'poweroff(ExitCode::Success);'

if [[ ${NEXUS_PRECOMMIT_SOURCE_PRIMARY_ONLY:-0} != 1 ]]; then
    mutations=0

    require_mutation() {
        if cmp -s "$1" "$2"; then
            fail "source mutation did not apply: $3"
        fi
    }

    require_source_rejection() {
        local mutated=$1
        local label=$2
        if NEXUS_PRECOMMIT_SOURCE_PRIMARY_ONLY=1 \
            bash "$0" "$mutated" "$lib_file" "$facade_file" >/dev/null 2>&1; then
            fail "precommit source gate accepted mutation: $label"
        fi
        mutations=$((mutations + 1))
    }

    require_lib_rejection() {
        local mutated=$1
        local label=$2
        if NEXUS_PRECOMMIT_SOURCE_PRIMARY_ONLY=1 \
            bash "$0" "$source_file" "$mutated" "$facade_file" >/dev/null 2>&1; then
            fail "precommit source gate accepted kernel-root mutation: $label"
        fi
        mutations=$((mutations + 1))
    }

    require_facade_rejection() {
        local mutated=$1
        local label=$2
        if NEXUS_PRECOMMIT_SOURCE_PRIMARY_ONLY=1 \
            bash "$0" "$source_file" "$lib_file" "$mutated" >/dev/null 2>&1; then
            fail "precommit source gate accepted facade mutation: $label"
        fi
        mutations=$((mutations + 1))
    }

    awk '
        /fn dispatch_first_executable_pread_same_boot\(/ { dispatch = 1 }
        { print }
        dispatch && !changed && /\) -> DispatchOutcome \{/ {
            print "        return self.external_precommit_helper(descriptor);"
            changed = 1
        }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/early-return.rs"
    require_mutation "$source_file" "$work/early-return.rs" early-return
    require_source_rejection "$work/early-return.rs" early-return

    awk '
        /fn dispatch_first_executable_pread_same_boot\(/ { dispatch = 1 }
        { print }
        dispatch && !changed && /\) -> DispatchOutcome \{/ {
            print "        if false { self.external_precommit_helper(descriptor); }"
            changed = 1
        }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/dead-branch.rs"
    require_mutation "$source_file" "$work/dead-branch.rs" dead-branch
    require_source_rejection "$work/dead-branch.rs" dead-branch

    cp "$source_file" "$work/missing-option-slot.rs"
    sed -i \
        's/let mut prepared_slot = Some(prepared_request);/let prepared_slot = prepared_request;/' \
        "$work/missing-option-slot.rs"
    require_mutation "$source_file" "$work/missing-option-slot.rs" missing-option-slot
    require_source_rejection "$work/missing-option-slot.rs" missing-option-slot

    awk '
        /let mut prepared_slot = Some\(prepared_request\);/ { slot = 1 }
        slot && !changed && /\.take\(\)/ {
            sub(/\.take\(\)/, ".as_ref()")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/missing-option-take.rs"
    require_mutation "$source_file" "$work/missing-option-take.rs" missing-option-take
    require_source_rejection "$work/missing-option-take.rs" missing-option-take

    cp "$source_file" "$work/missing-hardware-cancel.rs"
    sed -i \
        's/prepared\.cancel_prepared()\.begin_reset(true)/prepared.publish_prepared().begin_reset(true)/' \
        "$work/missing-hardware-cancel.rs"
    require_mutation "$source_file" "$work/missing-hardware-cancel.rs" missing-hardware-cancel
    require_source_rejection "$work/missing-hardware-cancel.rs" missing-hardware-cancel

    awk '
        /#\[cfg\(feature = "virtio-cser-precommit-fault"\)\]/ { fault = 1 }
        fault && !changed && /let commit = runtime\.registry\.commit_device_batch_with_publish\(/ {
            print "                let _published = prepared_slot.take().unwrap().publish_prepared();"
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/direct-publish.rs"
    require_mutation "$source_file" "$work/direct-publish.rs" direct-publish
    require_source_rejection "$work/direct-publish.rs" direct-publish

    awk '
        /#\[cfg\(feature = "virtio-cser-precommit-fault"\)\]/ { fault = 1 }
        fault && !held && /let selection = runtime\.registry\.revoke_begin\(SCOPE\)\.unwrap\(\);/ {
            selection = $0
            held = 1
            next
        }
        fault && held && !inserted && /assert!\(matches!\(commit, Err\(RegistryError::StaleAuthority\)\)\);/ {
            print
            print selection
            inserted = 1
            next
        }
        { print }
        END { if (!held || !inserted) exit 2 }
    ' "$source_file" >"$work/commit-before-revoke.rs"
    require_mutation "$source_file" "$work/commit-before-revoke.rs" commit-before-revoke
    require_source_rejection "$work/commit-before-revoke.rs" commit-before-revoke

    cp "$source_file" "$work/five-handles.rs"
    sed -i '/^[[:space:]]*dma_request\.handle,$/d' "$work/five-handles.rs"
    require_mutation "$source_file" "$work/five-handles.rs" five-handles
    require_source_rejection "$work/five-handles.rs" five-handles

    cp "$source_file" "$work/missing-registry-cancel.rs"
    sed -i \
        's/begin_unpublished_device_cancel/begin_published_device_cancel/' \
        "$work/missing-registry-cancel.rs"
    require_mutation "$source_file" "$work/missing-registry-cancel.rs" missing-registry-cancel
    require_source_rejection "$work/missing-registry-cancel.rs" missing-registry-cancel

    cp "$source_file" "$work/missing-reset-apply.rs"
    sed -i 's/generation_plan\.apply()/new_generation/' "$work/missing-reset-apply.rs"
    require_mutation "$source_file" "$work/missing-reset-apply.rs" missing-reset-apply
    require_source_rejection "$work/missing-reset-apply.rs" missing-reset-apply

    cp "$source_file" "$work/missing-iotlb-apply.rs"
    sed -i 's/quiescence_plan\.apply()/expected_identity/' "$work/missing-iotlb-apply.rs"
    require_mutation "$source_file" "$work/missing-iotlb-apply.rs" missing-iotlb-apply
    require_source_rejection "$work/missing-iotlb-apply.rs" missing-iotlb-apply

    cp "$source_file" "$work/reordered-leaves.rs"
    sed -i \
        's/(effects\[3\], "dma_queue_owner_a")/(effects[4], "dma_queue_owner_a")/' \
        "$work/reordered-leaves.rs"
    require_mutation "$source_file" "$work/reordered-leaves.rs" reordered-leaves
    require_source_rejection "$work/reordered-leaves.rs" reordered-leaves

    cp "$source_file" "$work/missing-publication-ack.rs"
    sed -i \
        's/runtime\.registry\.acknowledge_publication(ticket)\.unwrap();/runtime.registry.check_invariants().unwrap();/' \
        "$work/missing-publication-ack.rs"
    require_mutation "$source_file" "$work/missing-publication-ack.rs" missing-publication-ack
    require_source_rejection "$work/missing-publication-ack.rs" missing-publication-ack

    awk '
        /fn close_enrolled_precommit_failure\(/ { helper = 1 }
        helper && !changed && /exit: true,/ {
            sub(/exit: true,/, "exit: false,")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/resume-fault-guest.rs"
    require_mutation "$source_file" "$work/resume-fault-guest.rs" resume-fault-guest
    require_source_rejection "$work/resume-fault-guest.rs" resume-fault-guest

    cp "$source_file" "$work/missing-precommit-final.rs"
    sed -i 's/state\.assert_precommit_final();/state.assert_final();/' \
        "$work/missing-precommit-final.rs"
    require_mutation "$source_file" "$work/missing-precommit-final.rs" missing-precommit-final
    require_source_rejection "$work/missing-precommit-final.rs" missing-precommit-final

    cp "$source_file" "$work/witness-marker-default-true.rs"
    sed -i \
        '0,/enrolled_revoke_wins_observed: false,/s//enrolled_revoke_wins_observed: true,/' \
        "$work/witness-marker-default-true.rs"
    require_mutation "$source_file" "$work/witness-marker-default-true.rs" \
        witness-marker-default-true
    require_source_rejection "$work/witness-marker-default-true.rs" \
        witness-marker-default-true

    awk '
        /fn close_enrolled_precommit_failure\(/ { helper = 1 }
        helper && /runtime\.phase = ProductionReadPhase::AwaitingPublication\(cookie\);/ { tail = 1 }
        tail && !changed && /if fault_markers \{/ {
            sub(/if fault_markers \{/, "if true {")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/unconditional-witness-marker.rs"
    require_mutation "$source_file" "$work/unconditional-witness-marker.rs" \
        unconditional-witness-marker
    require_source_rejection "$work/unconditional-witness-marker.rs" \
        unconditional-witness-marker

    cp "$source_file" "$work/unconditional-publication-pass.rs"
    sed -i \
        's/if runtime\.enrolled_revoke_wins_observed {/if true {/' \
        "$work/unconditional-publication-pass.rs"
    require_mutation "$source_file" "$work/unconditional-publication-pass.rs" \
        unconditional-publication-pass
    require_source_rejection "$work/unconditional-publication-pass.rs" \
        unconditional-publication-pass

    cp "$source_file" "$work/unconditional-slice-pass.rs"
    sed -i \
        's/if enrolled_revoke_wins_observed {/if true {/' \
        "$work/unconditional-slice-pass.rs"
    require_mutation "$source_file" "$work/unconditional-slice-pass.rs" \
        unconditional-slice-pass
    require_source_rejection "$work/unconditional-slice-pass.rs" \
        unconditional-slice-pass

    cp "$lib_file" "$work/missing-witness-receipt-check.rs"
    sed -i \
        's/assert!(fs_receipt\.enrolled_revoke_wins_observed);/assert!(true);/' \
        "$work/missing-witness-receipt-check.rs"
    require_mutation "$lib_file" "$work/missing-witness-receipt-check.rs" \
        missing-witness-receipt-check
    require_lib_rejection "$work/missing-witness-receipt-check.rs" \
        missing-witness-receipt-check

    awk '
        /#\[cfg\(feature = "virtio-cser-precommit-fault"\)\]/ { fault = 1 }
        fault && !changed && /assert_eq!\(fs_receipt\.terminalizations, 2\);/ {
            sub(/terminalizations, 2/, "terminalizations, 14")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$lib_file" >"$work/fourteen-fault-terminalizations.rs"
    require_mutation "$lib_file" "$work/fourteen-fault-terminalizations.rs" \
        fourteen-fault-terminalizations
    require_lib_rejection "$work/fourteen-fault-terminalizations.rs" \
        fourteen-fault-terminalizations

    awk '
        /#\[cfg\(feature = "virtio-cser-precommit-fault"\)\]/ { fault = 1 }
        fault && !changed && /println!\("SPIKE_RESULT PASS"\);/ {
            print "        linux_net::run_linux_net_slice();"
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$lib_file" >"$work/feature-legacy-successor.rs"
    require_mutation "$lib_file" "$work/feature-legacy-successor.rs" feature-legacy-successor
    require_lib_rejection "$work/feature-legacy-successor.rs" feature-legacy-successor

    awk '
        /let fs_receipt = linux_fs::run_linux_fs_slice\(\);/ { post_fs = 1 }
        post_fs && !removed && /^[[:space:]]*#\[cfg\(feature = "virtio-cser-precommit-fault"\)\]$/ {
            removed = 1
            next
        }
        { print }
        END { if (!removed) exit 2 }
    ' "$lib_file" >"$work/unfenced-feature-root.rs"
    require_mutation "$lib_file" "$work/unfenced-feature-root.rs" unfenced-feature-root
    require_lib_rejection "$work/unfenced-feature-root.rs" unfenced-feature-root

    cp "$facade_file" "$work/missing-cancel-api.rs"
    sed -i \
        's/pub fn cancel_prepared(self) -> CancelledRequest/pub fn abandon_prepared(self) -> CancelledRequest/' \
        "$work/missing-cancel-api.rs"
    require_mutation "$facade_file" "$work/missing-cancel-api.rs" missing-cancel-api
    require_facade_rejection "$work/missing-cancel-api.rs" missing-cancel-api

    cp "$facade_file" "$work/missing-driver-cancel.rs"
    sed -i \
        's/prepared\.cancel_prepared(&inputs, &mut outputs)/prepared.publish_prepared()/' \
        "$work/missing-driver-cancel.rs"
    require_mutation "$facade_file" "$work/missing-driver-cancel.rs" missing-driver-cancel
    require_facade_rejection "$work/missing-driver-cancel.rs" missing-driver-cancel

    cp "$lib_file" "$work/missing-feature-poweroff.rs"
    awk '
        /#\[cfg\(feature = "virtio-cser-precommit-fault"\)\]/ { fault = 1 }
        fault && !changed && /poweroff\(ExitCode::Success\);/ {
            sub(/poweroff\(ExitCode::Success\);/, "Task::yield_now();")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$lib_file" >"$work/missing-feature-poweroff.rs"
    require_mutation "$lib_file" "$work/missing-feature-poweroff.rs" missing-feature-poweroff
    require_lib_rejection "$work/missing-feature-poweroff.rs" missing-feature-poweroff

    [[ $mutations == 26 ]] ||
        fail "expected 26 source mutations, observed $mutations"
fi

echo 'runtime filesystem same-boot precommit source assertions: PASS canonical_entry_sealed=true user_context_descriptor=true exact_six_enrollment=true revoke_wins_commit=true publish_closure_calls=0 prepared_option_retained=true registry_cancel=true facade_cancel=true reset_apply=true iotlb_apply=true leaf_first=true guest_result=-125 guest_bytes=0 witness_marker=enrolled_revoke_wins production_publication=ack+revoke_complete generic_prefix_syscalls=2 feature_terminal=true legacy_successors=false mutations=26'
