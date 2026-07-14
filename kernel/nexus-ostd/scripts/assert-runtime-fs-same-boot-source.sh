#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_file=${1:-$script_root/src/personality/linux_fs.rs}
lib_file=${2:-$script_root/src/lib.rs}

fail() {
    echo "runtime filesystem same-boot source assertion: FAIL: $*" >&2
    exit 1
}

[[ -f $source_file && ! -L $source_file ]] ||
    fail "implementation source is not a regular non-symlink file: $source_file"
[[ -f $lib_file && ! -L $lib_file ]] ||
    fail "kernel root source is not a regular non-symlink file: $lib_file"

for command_name in awk bash cmp cp cut grep mapfile mktemp rm sed wc; do
    command -v "$command_name" >/dev/null 2>&1 || fail "missing command: $command_name"
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fixed_count() {
    local file=$1
    local pattern=$2
    grep -F -c -- "$pattern" "$file" || true
}

regex_count() {
    local file=$1
    local pattern=$2
    grep -E -c -- "$pattern" "$file" || true
}

require_count() {
    local file=$1
    local pattern=$2
    local expected=$3
    local actual
    actual=$(fixed_count "$file" "$pattern")
    [[ $actual == "$expected" ]] ||
        fail "expected $expected occurrence(s) of '$pattern' in $file, observed $actual"
}

require_regex_count() {
    local file=$1
    local pattern=$2
    local expected=$3
    local actual
    actual=$(regex_count "$file" "$pattern")
    [[ $actual == "$expected" ]] ||
        fail "expected $expected match(es) of /$pattern/ in $file, observed $actual"
}

reject_fixed() {
    local file=$1
    local pattern=$2
    if grep -Fq -- "$pattern" "$file"; then
        fail "forbidden source token '$pattern' entered $file"
    fi
}

reject_regex() {
    local file=$1
    local pattern=$2
    if grep -Eq -- "$pattern" "$file"; then
        fail "forbidden source pattern /$pattern/ entered $file"
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

require_cfg_before() {
    local file=$1
    local pattern=$2
    local line previous
    line=$(line_of_unique "$file" "$pattern")
    ((line > 1)) || fail "source anchor has no cfg predecessor: $pattern"
    previous=$(sed -n "$((line - 1))p" "$file" |
        sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [[ $previous == '#[cfg(feature = "virtio-cser-facade")]' ]] ||
        fail "source anchor is not directly feature gated: $pattern"
}

require_cfg_near_before() {
    local file=$1
    local pattern=$2
    local line start count
    line=$(line_of_unique "$file" "$pattern")
    ((line > 1)) || fail "source anchor has no cfg predecessor: $pattern"
    start=$((line > 4 ? line - 4 : 1))
    count=$(sed -n "${start},$((line - 1))p" "$file" |
        grep -F -c -- '#[cfg(feature = "virtio-cser-facade")]' || true)
    [[ $count == 1 ]] ||
        fail "source anchor is not feature gated nearby: $pattern"
}

require_not_feature_cfg_before() {
    local file=$1
    local pattern=$2
    local line previous
    line=$(line_of_unique "$file" "$pattern")
    ((line > 1)) || fail "source anchor has no cfg predecessor: $pattern"
    previous=$(sed -n "$((line - 1))p" "$file" |
        sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [[ $previous == '#[cfg(not(feature = "virtio-cser-facade"))]' ]] ||
        fail "legacy source anchor is not directly excluded from the feature build: $pattern"
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
    local file=$1
    local expected=$2
    local actual
    actual=$(wc -l <"$file")
    [[ $actual == "$expected" ]] ||
        fail "expected $expected lines in $file, observed $actual"
}

runtime="$work/production-runtime.rs"
flight_struct="$work/same-boot-flight.rs"
registry="$work/production-registry.rs"
credit_helper="$work/credit-helper.rs"
dma_helper="$work/dma-helper.rs"
scenario="$work/scenario.rs"
same_boot="$work/same-boot-dispatch.rs"
positive="$work/same-boot-positive.rs"
applied_arm="$work/same-boot-applied.rs"
replay_arm="$work/same-boot-replay.rs"
error_arm="$work/same-boot-error.rs"
post_match="$work/same-boot-post-match.rs"
replay_tail="$work/same-boot-replay-tail.rs"
ordinary_transition="$work/ordinary-precommit-transition.rs"
prepared_reject="$work/unregistered-precommit-reject.rs"
ordinary_close="$work/ordinary-precommit-close.rs"
unregistered_close="$work/unregistered-precommit-close.rs"
cohort_error="$work/cohort-register-error.rs"
enrolled_transition="$work/enrolled-precommit-transition.rs"
enrolled_reject="$work/enrolled-precommit-reject.rs"
dispatch_route="$work/dispatch-route.rs"
publication="$work/production-publication.rs"
run_guest="$work/run-guest.rs"
descriptor_builder="$work/descriptor-builder.rs"
published_io="$work/lock-free-published-io.rs"
handles="$work/enrollment-handles.rs"
commits="$work/batch-commits.rs"
effect_vector="$work/flight-effects.rs"
post_fs_root="$work/post-fs-root.rs"
feature_root="$work/feature-root.rs"
precommit_root="$work/precommit-root.rs"
legacy_root="$work/legacy-root.rs"

extract_between "$source_file" \
    'struct ProductionReadRuntime {' 'struct SameBootFlight {' "$runtime"
extract_through_first_after "$source_file" \
    'struct SameBootFlight {' '}' "$flight_struct"
extract_between "$source_file" \
    'fn new_same_boot_registry() -> EffectRegistry {' 'impl FsState {' "$registry"
extract_between "$source_file" \
    'fn same_boot_credit(class: CreditClass, units: u64) -> CreditCharge {' \
    'fn same_boot_dma_entry(' "$credit_helper"
extract_between "$source_file" \
    'fn same_boot_dma_entry(' 'fn published_identity(' "$dma_helper"
extract_between "$source_file" \
    'struct FsScenario {' 'impl FsScenario {' "$scenario"
extract_between "$source_file" \
    'fn dispatch_first_executable_pread_same_boot(' \
    'fn dispatch_first_executable_pread(' "$same_boot"
extract_between "$same_boot" \
    '            #[cfg(not(feature = "virtio-cser-precommit-fault"))]' \
    '        let flight = match flight {' "$positive"
extract_between "$positive" \
    '                    Ok(DeviceBatchCommitOutcome::Applied {' \
    '                    Ok(DeviceBatchCommitOutcome::AlreadyCommitted {' "$applied_arm"
extract_between "$positive" \
    '                    Ok(DeviceBatchCommitOutcome::AlreadyCommitted {' \
    '                    Err(error) => {' "$replay_arm"
extract_through_first_after "$positive" \
    '                    Err(error) => {' '                };' "$error_arm"
extract_between "$positive" \
    '                };' \
    '                if matches!(&request, SameBootRequest::Published(_)) {' \
    "$post_match"
extract_between "$same_boot" \
    '                SameBootRequest::ReplayConflict(prepared) => {' \
    '            "LINUX_FS_SAME_BOOT Completion outcome={} result={} used_len={} payload_source={} data_prefix={}",' \
    "$replay_tail"
extract_between "$source_file" \
    'fn begin_ordinary_precommit_close(' \
    'fn begin_pending_device_precommit_close(' "$ordinary_transition"
extract_between "$source_file" \
    'fn reject_prepared_without_device_root(' \
    'fn reject_pending_device_precommit(' "$prepared_reject"
extract_between "$source_file" \
    'fn close_ordinary_precommit_failure(' \
    'fn close_unregistered_precommit_failure(' "$ordinary_close"
extract_between "$source_file" \
    'fn close_unregistered_precommit_failure(' \
    'fn close_enrolled_precommit_failure(' "$unregistered_close"
extract_through_first_after "$same_boot" \
    '            let [block, dma_queue_a, dma_queue_b, dma_request] = match cohort {' \
    '            runtime.registered_effects = 6;' "$cohort_error"
extract_between "$source_file" \
    'fn begin_enrolled_device_precommit_close(' \
    'enum SameBootRequest {' "$enrolled_transition"
extract_between "$source_file" \
    'fn reject_enrolled_device_precommit(' \
    'fn close_ordinary_precommit_failure(' "$enrolled_reject"
extract_between "$source_file" \
    'fn dispatch(&self, descriptor: SyscallDescriptor) -> DispatchOutcome {' \
    'fn publish(&self, outcome: &DispatchOutcome) {' "$dispatch_route"
extract_between "$source_file" \
    'fn publish(&self, outcome: &DispatchOutcome) {' 'fn finish(&self) {' "$publication"
extract_between "$source_file" \
    'fn run_guest(scenario: Arc<FsScenario>' 'fn syscall_descriptor(' "$run_guest"
extract_between "$source_file" \
    'fn syscall_descriptor(context: &UserContext) -> SyscallDescriptor {' \
    'fn read_guest_bytes(' "$descriptor_builder"
extract_through_first_after "$same_boot" \
    '                SameBootRequest::Published(mut published) => {' \
    'let reset_ticket = {' "$published_io"
extract_between "$same_boot" \
    '            let handles = [' '            let enrollment = match runtime' "$handles"
extract_through_first_after "$same_boot" \
    '            let commits = [' '            ];' "$commits"
extract_through_first_after "$same_boot" \
    '                effects: [' '                ],' "$effect_vector"
extract_from "$lib_file" \
    '    let fs_receipt = linux_fs::run_linux_fs_slice();' "$post_fs_root"
extract_between "$post_fs_root" \
    '    #[cfg(all(' \
    '    #[cfg(feature = "virtio-cser-precommit-fault")]' "$feature_root"
extract_between "$post_fs_root" \
    '    #[cfg(feature = "virtio-cser-precommit-fault")]' \
    '    #[cfg(not(feature = "virtio-cser-facade"))]' "$precommit_root"
extract_from "$post_fs_root" \
    '    #[cfg(not(feature = "virtio-cser-facade"))]' "$legacy_root"

for anchor in \
    'struct ProductionReadRuntime {' \
    'fn new_same_boot_registry() -> EffectRegistry {' \
    'fn same_boot_credit(class: CreditClass, units: u64) -> CreditCharge {' \
    'fn same_boot_dma_entry('; do
    require_cfg_before "$source_file" "$anchor"
done
require_cfg_near_before "$source_file" \
    'fn dispatch_first_executable_pread_same_boot('
require_cfg_before "$scenario" 'production: SpinLock<ProductionReadRuntime>,'
require_cfg_before "$publication" 'PublicationAuthority::Production {'

# The feature path owns a request-local registry and linear device owners that
# are separate from the generic filesystem state.
require_count "$runtime" 'registry: EffectRegistry,' 1
require_count "$runtime" 'root: Option<Root>,' 1
require_count "$runtime" 'device: Option<ProductionDevice>,' 1
require_count "$runtime" 'registry: new_same_boot_registry(),' 1
require_count "$runtime" 'credits.capacity, 10' 1
require_count "$runtime" 'credits.free, 10' 1
reject_fixed "$runtime" '#[derive(Clone'
require_count "$scenario" 'state: SpinLock<FsState>,' 1
require_count "$scenario" 'production: SpinLock<ProductionReadRuntime>,' 1

# Six credit classes provide exactly ten units: 1+1+1+3+3+1.
require_count "$registry" 'let mut registry = EffectRegistry::new();' 1
require_count "$registry" 'CreditLimit::new(' 6
for limit in \
    'CreditLimit::new(CONTROL_CREDIT, 1)' \
    'CreditLimit::new(FILESYSTEM_OP_CREDIT, 1)' \
    'CreditLimit::new(QUEUE_SLOT_CREDIT, 1)' \
    'CreditLimit::new(PINNED_PAGE_CREDIT, 3)' \
    'CreditLimit::new(DMA_MAPPING_CREDIT, 3)' \
    'CreditLimit::new(GUEST_REPLY_CREDIT, 1)'; do
    require_count "$registry" "$limit" 1
done
require_count "$registry" 'DomainConfig {' 3
for domain in PERSONALITY_DOMAIN FILESYSTEM_DOMAIN BLOCK_DOMAIN; do
    require_count "$registry" "key: $domain," 1
done
reject_fixed "$registry" 'BLOCK_PREPARATION_CREDIT'

require_count "$credit_helper" 'CreditCharge::new(class, units)' 1
require_count "$dma_helper" 'DeviceDerivedCohortEntry {' 2
require_count "$dma_helper" 'DeviceCohortParent::BatchIndex(0)' 1
require_count "$dma_helper" 'same_boot_credit(PINNED_PAGE_CREDIT, 1)' 1
require_count "$dma_helper" 'same_boot_credit(DMA_MAPPING_CREDIT, 1)' 1
for descriptor_field in \
    'paddr,' \
    'iova,' \
    'ostd::mm::PAGE_SIZE,' \
    'usize::from(identity.queue()),' \
    'usize::from(identity.descriptor_token()),' \
    'generation as usize,'; do
    require_count "$dma_helper" "$descriptor_field" 1
done
reject_regex "$dma_helper" '(EffectRegistry::new|clone_non_device_candidate|fresh_registry)'

# The syscall descriptor is built from the real UserContext and is passed
# unchanged through dispatch into the feature-gated path.
require_order "$run_guest" \
    'ReturnReason::UserSyscall => {' \
    'let descriptor = syscall_descriptor(user_mode.context());' \
    'let outcome = scenario.dispatch(descriptor);' \
    'user_mode.context_mut().set_rax(outcome.result as usize);' \
    'scenario.publish(&outcome);'
require_order "$descriptor_builder" \
    'SyscallDescriptor::new(' \
    'context.rax(),' \
    'context.rdi(),' \
    'context.rsi(),' \
    'context.rdx(),' \
    'context.r10(),' \
    'context.r8(),' \
    'context.r9(),'
require_order "$dispatch_route" \
    'if descriptor.number() == __NR_pread64 as usize && !state.production_read_observed {' \
    '#[cfg(feature = "virtio-cser-facade")]' \
    'drop(state);' \
    'return self.dispatch_first_executable_pread_same_boot(descriptor);'
require_count "$dispatch_route" 'dispatch_first_executable_pread_same_boot(descriptor)' 1
reject_fixed "$dispatch_route" 'SyscallDescriptor::new('

# Bind the shared real workload preparation once. Fault-specific cancellation
# is checked by the precommit gate; this gate owns the non-fault commit split.
require_count "$same_boot" '.register_derived(DerivedRegisterRequest {' 2
require_count "$same_boot" '.register_device_derived_cohort([' 1
require_count "$same_boot" 'same_boot_dma_entry(' 3
require_count "$same_boot" 'owner_address(' 3
require_count "$same_boot" 'for effect in [&block, &dma_queue_a, &dma_queue_b, &dma_request] {' 1
require_count "$same_boot" \
    'if let Err(error) = runtime.registry.prepare(BLOCK_V1, effect.handle) {' 1
require_count "$same_boot" '.kernel_root_authority(SCOPE, ROOT_OWNER)' 1
require_count "$same_boot" '.enroll_device_batch(authority, &handles, envelope)' 1
require_count "$same_boot" '.preflight_publish(expected_hardware_identity)' 1
require_order "$same_boot" \
    'let syscall = {' \
    'runtime.phase = ProductionReadPhase::Captured(syscall.identity.effect());' \
    "// This is the real filesystem personality's fd/inode resolution." \
    'let flight = '\''prepare: {' \
    'let filesystem = runtime' \
    '.crash_domain(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V1)' \
    '.domain_recovery_snapshot(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2)' \
    '.domain_ready(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2, &snapshot)' \
    '.rebind_domain(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2)' \
    '.recover_next_domain(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2)' \
    '.adopt_domain(SCOPE, FILESYSTEM_DOMAIN, FILESYSTEM_V2, filesystem.handle)' \
    '.prepare_read_sector0(&mut root)' \
    '.register_device_derived_cohort([' \
    'for effect in [&block, &dma_queue_a, &dma_queue_b, &dma_request] {' \
    '.kernel_root_authority(SCOPE, ROOT_OWNER)' \
    'let handles = [' \
    '.enroll_device_batch(authority, &handles, envelope)' \
    '.preflight_publish(expected_hardware_identity)' \
    'let commits = [' \
    '            #[cfg(feature = "virtio-cser-precommit-fault")]' \
    '            #[cfg(not(feature = "virtio-cser-precommit-fault"))]'

# A failed cohort registration occurs after real hardware preparation but
# before any device root reaches the live Registry. It must preserve the
# PreparedRequest and route the exact two already-registered ancestors into the
# unregistered cancellation path.
for helper_anchor in \
    'fn begin_ordinary_precommit_close(' \
    'fn reject_prepared_without_device_root(' \
    'fn close_ordinary_precommit_failure(' \
    'fn close_unregistered_precommit_failure('; do
    require_cfg_near_before "$source_file" "$helper_anchor"
done
require_order "$cohort_error" \
    'let [block, dma_queue_a, dma_queue_b, dma_request] = match cohort {' \
    'Ok(cohort) => cohort,' \
    'Err(error) => {' \
    'let effects = [syscall.identity.effect(), filesystem.identity.effect()];' \
    'drop(runtime);' \
    'LINUX_FS_SAME_BOOT PrecommitRejected stage=cohort_register' \
    'break '\''prepare SameBootDispatch::Precommit(' \
    'self.reject_prepared_without_device_root(' \
    'prepared_request,' \
    'root,' \
    'device,' \
    'effects,' \
    '"cohort_register",' \
    'runtime.registered_effects = 6;'
require_count "$cohort_error" \
    'let effects = [syscall.identity.effect(), filesystem.identity.effect()];' 1
require_count "$cohort_error" 'self.reject_prepared_without_device_root(' 1
reject_fixed "$cohort_error" 'reject_preparation_without_hardware_owner'
reject_fixed "$cohort_error" 'close_ordinary_precommit_failure'

# The ordinary transition rejects an installed device root, freezes the scope,
# and moves the request-local runtime to Closing before either the hardware or
# the Registry can be terminalized.
require_order "$ordinary_transition" \
    'fn begin_ordinary_precommit_close(' \
    'if runtime.registry.device_root_installed(SCOPE)? {' \
    'return Err(RegistryError::InvalidState);' \
    'let next_cookie = cookie' \
    '.checked_add(1)' \
    'let selection = runtime.registry.revoke_begin(SCOPE)?;' \
    'runtime.next_flight_cookie = next_cookie;' \
    'runtime.phase = ProductionReadPhase::Closing(cookie);' \
    'runtime.registry.check_invariants()?;' \
    'Ok((cookie, selection))'
require_count "$ordinary_transition" 'device_root_installed(SCOPE)?' 1
reject_fixed "$ordinary_transition" 'begin_unpublished_device_cancel'

require_order "$prepared_reject" \
    'fn reject_prepared_without_device_root(' \
    'prepared: PreparedRequest,' \
    'let transition = begin_ordinary_precommit_close(&mut runtime);' \
    'fail_stop_retain_precommit_owners(stage, error, (prepared, root, device));' \
    'let (cookie, selection) = transition;' \
    'self.close_unregistered_precommit_failure(' \
    'cookie, prepared, root, device, selection, effects, stage,'
require_count "$prepared_reject" 'self.close_unregistered_precommit_failure(' 1
reject_fixed "$prepared_reject" 'close_ordinary_precommit_failure'

# Unregistered cancellation consumes the exact unpublished hardware owner. The
# first reset and IOTLB attempts must remain pending; every later apply is
# explicit, and the IOTLB-begin error arm retains the returned reset owner.
require_order "$unregistered_close" \
    'fn close_unregistered_precommit_failure(' \
    'assert_eq!(runtime.registry.device_root_installed(SCOPE), Ok(false));' \
    'let identity = prepared.identity();' \
    'let cancelled = prepared.cancel_unregistered();' \
    'assert_eq!(cancelled.identity(), identity);' \
    'let (reset_tombstone, mut cancellation) = cancelled.begin_reset(true);' \
    'assert_eq!(cancellation.identity(), identity);' \
    'let reset_tombstone = match reset_tombstone.retry_ack(&mut root) {' \
    '"unregistered_reset_timeout_injection",' \
    'Err(tombstone) => tombstone,' \
    'let mut reset = match reset_tombstone.retry_ack(&mut root) {' \
    'Ok(reset) => reset,' \
    '"unregistered_reset_retry",' \
    'assert!(!reset.was_published());' \
    'assert!(!reset.was_descriptor_popped());' \
    'assert!(!reset.was_completed());' \
    'let generation = match device.apply_unregistered_reset(&mut reset, &mut cancellation) {' \
    '"unregistered_generation_apply",' \
    'assert_eq!(generation, identity.device_generation() + 1);' \
    'let iotlb = match device.begin_unregistered_iotlb(reset, &cancellation, true) {' \
    'Err((error, reset_owner)) => fail_stop_retain_precommit_owners(' \
    '"unregistered_iotlb_begin",' \
    '(reset_owner, cancellation, root, device),' \
    'ProductionClosureProgress::Pending(tombstone) => tombstone,' \
    '"unregistered_iotlb_timeout_injection",' \
    'assert!(!iotlb.failure_retained());' \
    'let mut closure = match iotlb.retry(1024) {' \
    'ProductionClosureProgress::Complete(receipt) => receipt,' \
    '"unregistered_iotlb_retry",' \
    'assert_eq!(closure.completed_pages(), 3);' \
    'let applied = match device.apply_unregistered_quiescence(&mut closure, &mut cancellation) {' \
    '"unregistered_quiescence_apply",' \
    'assert_eq!(applied, identity);' \
    'assert!(cancellation.is_complete());' \
    'LINUX_FS_SAME_BOOT UnregisteredCancel stage={}' \
    'self.close_ordinary_precommit_failure(cookie, root, device, selection, effects, stage)'
require_count "$unregistered_close" 'retry_ack(&mut root)' 2
require_count "$unregistered_close" 'retained_dma_pages(), 3' 2
require_count "$unregistered_close" 'completed_pages(), 3' 1
require_count "$unregistered_close" '(reset_owner, cancellation, root, device),' 1
for forbidden in '.publish_prepared()' '.cancel_prepared()' '.notify()' \
    '.poll_completion()' 'CompletedRequest' 'Publication::GuestBytes' \
    'begin_unpublished_device_cancel' 'stage_device_batch_terminal'; do
    reject_fixed "$unregistered_close" "$forbidden"
done

# Once hardware quiescence is complete, only the filesystem read and syscall
# ancestors remain. They close child-first as ordinary Aborted(-125) effects;
# no device-batch authority or device-visible operation may re-enter here.
require_order "$ordinary_close" \
    'fn close_ordinary_precommit_failure(' \
    'for expected in [effects[1], effects[0]] {' \
    '.expect("ordinary precommit revoke leaf");' \
    'assert_eq!(selected.effect, expected);' \
    'assert_eq!(selected.disposition, RevokeDisposition::Abort);' \
    '.stage_revoke_terminal(&selection, expected, TerminalRequest::aborted(-125))' \
    'assert_eq!(expected, effects[0]);' \
    'assert!(runtime.registry.revoke_next(&selection).unwrap().is_none());' \
    'let publication = publication.expect("ordinary precommit root publication ticket");' \
    'assert_eq!(publication.result(), -125);' \
    'runtime.root = Some(root);' \
    'runtime.device = Some(device);' \
    'runtime.active_revoke = Some(selection.clone());' \
    'runtime.phase = ProductionReadPhase::AwaitingPublication(cookie);' \
    'result: -125,' \
    'publication: Publication::None,' \
    'exit: true,'
require_count "$ordinary_close" '.revoke_next(&selection)' 2
require_count "$ordinary_close" '.stage_revoke_terminal(' 1
require_count "$ordinary_close" 'TerminalRequest::aborted(-125)' 1
for forbidden in '.publish_prepared()' '.notify()' '.poll_completion()' \
    'CompletedRequest' 'Publication::GuestBytes' 'stage_device_batch_terminal'; do
    reject_fixed "$ordinary_close" "$forbidden"
done

# Keep the linear prepared owner outside the publication closure. Only Applied
# may clear the slot and flow into the positive Published flight.
require_count "$positive" 'let mut prepared_slot = Some(prepared_request);' 1
require_count "$positive" 'commit_device_batch_with_publish(' 1
require_count "$positive" '.publish_prepared()' 1
require_count "$positive" '.take()' 3
require_count "$positive" 'SameBootDispatch::Published(SameBootFlight {' 1
require_count "$positive" 'SameBootDispatch::Precommit(' 1
require_count "$positive" 'runtime.registry.revoke_begin(SCOPE).unwrap();' 1
reject_fixed "$positive" '.begin_unpublished_device_cancel(&enrollment)'
reject_regex "$positive" 'AlreadyCommitted[^{]*\{[^}]*\}[[:space:]]*\|[[:space:]]*Err'
require_order "$positive" \
    '            #[cfg(not(feature = "virtio-cser-precommit-fault"))]' \
    'let mut prepared_slot = Some(prepared_request);' \
    'let commit = runtime.registry.commit_device_batch_with_publish(' \
    'same-boot publication retains prepared owner' \
    '                            .publish_prepared()' \
    'let (batch, request) = match commit {' \
    'Ok(DeviceBatchCommitOutcome::Applied {' \
    'Ok(DeviceBatchCommitOutcome::AlreadyCommitted {' \
    'Err(error) => {' \
    '.validate_device_batch_receipt(&batch)' \
    'SameBootDispatch::Published(SameBootFlight {'

require_order "$post_match" \
    '.validate_device_batch_receipt(&batch)' \
    'let selection = runtime.registry.revoke_begin(SCOPE).unwrap();' \
    'assert_eq!(selection.target_count, 6);' \
    'runtime.phase = ProductionReadPhase::Polling(cookie);' \
    'runtime.registry.check_invariants().unwrap();'

require_order "$applied_arm" \
    'Ok(DeviceBatchCommitOutcome::Applied {' \
    'assert!(prepared_slot.is_none());' \
    '(receipt, SameBootRequest::Published(publication))'
for forbidden in 'begin_unpublished_device_cancel' 'revoke_begin(SCOPE)' \
    'close_enrolled_precommit_failure' 'SameBootDispatch::Precommit'; do
    reject_fixed "$applied_arm" "$forbidden"
done

# Replay is not an unpublished request. It retains the prepared owner as an
# explicit post-commit conflict, validates the authoritative receipt, and
# enters Drain/reset/IOTLB rather than borrowing the Err cancellation ticket.
require_count "$replay_arm" 'assert!(prepared_slot.is_some());' 1
require_count "$replay_arm" 'SameBootRequest::ReplayConflict(' 1
require_count "$replay_arm" '.validate_device_replay_fence_candidate(&receipt)' 1
require_count "$replay_arm" '.take()' 1
require_count "$replay_arm" \
    'registry_commit_recorded=true current_publish_calls=0 prepared_was_published=false' 1
for forbidden in 'begin_unpublished_device_cancel' \
    'close_enrolled_precommit_failure' 'SameBootDispatch::Precommit' \
    'AbortedBeforeCommit' 'registry_published=true' 'closure=' \
    'IndeterminateAfterReset' '(receipt, publication)'; do
    reject_fixed "$replay_arm" "$forbidden"
done

require_order "$error_arm" \
    'Err(error) => {' \
    'assert!(prepared_slot.is_some());' \
    'let prepared = prepared_slot' \
    'rejected same-boot commit retains prepared owner' \
    'drop(runtime);' \
    'break '\''prepare SameBootDispatch::Precommit(' \
    'self.reject_enrolled_device_precommit(' \
    '"commit",'
require_count "$error_arm" '.take()' 1
reject_fixed "$error_arm" 'SameBootDispatch::Published'
reject_fixed "$error_arm" '(receipt, publication)'

require_order "$enrolled_transition" \
    'fn begin_enrolled_device_precommit_close(' \
    '.checked_add(1)' \
    'let selection = runtime.registry.revoke_begin(SCOPE)?;' \
    '.begin_unpublished_device_cancel(enrollment)?;' \
    'runtime.next_flight_cookie = next_cookie;' \
    'runtime.phase = ProductionReadPhase::Closing(cookie);' \
    'runtime.registry.check_invariants()?;' \
    'Ok((cookie, selection, reset))'
require_order "$enrolled_reject" \
    'fn reject_enrolled_device_precommit(' \
    'begin_enrolled_device_precommit_close(&mut runtime, &enrollment);' \
    'fail_stop_retain_precommit_owners(' \
    'let (cookie, selection, reset_ticket) = transition;' \
    'self.close_enrolled_precommit_failure(' \
    'false,'

require_order "$replay_tail" \
    'SameBootRequest::ReplayConflict(prepared) => {' \
    'prepared.identity(),' \
    'published_identity(envelope, root.device_bdf())' \
    'runtime.registry.begin_device_reset(&batch).unwrap();' \
    'runtime.phase = ProductionReadPhase::Closing(cookie);' \
    '-5,' \
    'Vec::new(),' \
    'prepared.cancel_prepared().begin_reset(true),' \
    '"ReplayConflict",' \
    '0,'
for forbidden in '.publish_prepared()' '.notify()' '.poll_completion()' \
    'begin_unpublished_device_cancel' 'AbortedBeforeCommit' \
    'Publication::GuestBytes'; do
    reject_fixed "$replay_tail" "$forbidden"
done

# The positive flight remains the only path that can notify, poll, consume
# CompletedRequest bytes, and perform post-commit reset/IOTLB closure.
require_count "$same_boot" 'let notification = published.notify();' 1
require_count "$same_boot" 'match published.poll_completion() {' 1
require_count "$same_boot" '.record_device_completion(&batch, envelope, 4)' 1
require_count "$same_boot" '.prepare_generation_advance(&mut hardware_reset)' 1
require_count "$same_boot" '.acknowledge_device_reset_with_apply(&retry_ticket, |prepared| {' 1
require_count "$same_boot" 'generation_plan.apply()' 1
require_count "$same_boot" '.prepare_quiescence_apply(&mut hardware_closure)' 1
require_count "$same_boot" '.acknowledge_device_iotlb_with_apply(&registry_iotlb_retry, |prepared| {' 1
require_count "$same_boot" 'quiescence_plan.apply()' 1
require_count "$same_boot" '.revoke_next(&selection)' 2
require_count "$same_boot" '.stage_device_batch_terminal(&registry_closure, expected, request)' 1
require_count "$same_boot" 'TerminalRequest::indeterminate_after_reset(-5)' 1
require_count "$same_boot" 'authority: PublicationAuthority::Production {' 1
require_count "$same_boot" 'Publication::GuestBytes {' 1
require_order "$same_boot" \
    '        let flight = match flight {' \
    'SameBootDispatch::Published(flight) => flight,' \
    'SameBootDispatch::Precommit(outcome) => return outcome,' \
    '        let SameBootFlight {' \
    'let notification = published.notify();' \
    'match published.poll_completion() {' \
    'CompletionProgress::Complete(completed) => {' \
    'let bytes = completed.data()[..4].to_vec();' \
    '.record_device_completion(&batch, envelope, 4)' \
    'completed.begin_reset(true)' \
    'let reset_tombstone = match reset_tombstone.retry_ack(&mut root) {' \
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
    'assert_eq!(registry_closure.outcome(), registry_reset.outcome());' \
    'let leaf_first = [' \
    'effects[3], effects[4], effects[5], effects[2], effects[1], effects[0],' \
    'assert!(matches!(selected.disposition, RevokeDisposition::Drain(_)));' \
    'DeviceClosureResult::IndeterminateAfterReset => {' \
    'TerminalRequest::indeterminate_after_reset(-5)' \
    'DeviceClosureResult::AbortedBeforeCommit => unreachable!(),' \
    '.stage_device_batch_terminal(&registry_closure, expected, request)' \
    'let publication = publication.expect("same-boot root publication ticket");' \
    'authority: PublicationAuthority::Production {' \
    'Publication::GuestBytes {'

# Exact arrays bind the six enrolled handles, six commit results, and the
# frozen leaf-first identities to values returned by the registry calls.
require_line_count "$handles" 8
for handle in \
    'syscall.handle,' \
    'adopted_filesystem,' \
    'block.handle,' \
    'dma_queue_a.handle,' \
    'dma_queue_b.handle,' \
    'dma_request.handle,'; do
    require_count "$handles" "$handle" 1
done
require_regex_count "$handles" \
    '^[[:space:]]+(syscall\.handle|adopted_filesystem|block\.handle|dma_queue_a\.handle|dma_queue_b\.handle|dma_request\.handle),$' 6

require_line_count "$commits" 8
for commit in \
    '(syscall.handle, CommitMetadata::new(4, 1)),' \
    '(adopted_filesystem, CommitMetadata::new(4, 1)),' \
    '(block.handle, CommitMetadata::new(512, 1)),' \
    '(dma_queue_a.handle, CommitMetadata::new(1, 1)),' \
    '(dma_queue_b.handle, CommitMetadata::new(1, 1)),' \
    '(dma_request.handle, CommitMetadata::new(1, 1)),'; do
    require_count "$commits" "$commit" 1
done
require_regex_count "$commits" '^[[:space:]]+\(.+CommitMetadata::new\(.+\)\),$' 6

require_line_count "$effect_vector" 8
for effect in \
    'syscall.identity.effect(),' \
    'filesystem.identity.effect(),' \
    'block.identity.effect(),' \
    'dma_queue_a.identity.effect(),' \
    'dma_queue_b.identity.effect(),' \
    'dma_request.identity.effect(),'; do
    require_count "$effect_vector" "$effect" 1
done

# The linear request/device owners leave the production SpinLock before notify
# and polling. Merely counting notify/poll tokens would not establish this.
require_order "$published_io" \
    'SameBootRequest::Published(mut published) => {' \
    'let notification = published.notify();' \
    'match published.poll_completion() {' \
    'CompletionProgress::Complete(completed) => {' \
    'let bytes = completed.data()[..4].to_vec();' \
    'let reset_ticket = {'
reject_fixed "$published_io" 'self.production.lock()'
reject_fixed "$published_io" 'let mut runtime'
require_count "$flight_struct" 'request: SameBootRequest,' 1
require_count "$flight_struct" 'root: Root,' 1
require_count "$flight_struct" 'device: ProductionDevice,' 1
reject_fixed "$flight_struct" '#[derive(Clone'

# Completion data is the only accepted guest payload source. A retained ELF or
# a fresh/synthetic/clone registry inside this function is an explicit bypass.
require_count "$same_boot" 'assert_eq!(fnv1a(completed.data()), SAME_BOOT_SECTOR_FNV1A);' 1
require_count "$same_boot" 'let bytes = completed.data()[..4].to_vec();' 1
reject_fixed "$same_boot" 'RUNTIME_FS_ELF'
reject_fixed "$same_boot" 'EffectRegistry::new'
reject_fixed "$same_boot" 'new_production_registry'
reject_fixed "$same_boot" 'fresh_registry'
reject_fixed "$same_boot" 'clone_non_device_candidate'
reject_fixed "$same_boot" 'state.effects'
reject_fixed "$same_boot" '.register_device_derived('

# Guest bytes are written before the production registry acknowledges the
# publication ticket and only then completes the frozen revoke selection.
require_order "$publication" \
    'Publication::GuestBytes { address, bytes } => {' \
    'write_guest_bytes(&self.vm_space, *address, bytes)' \
    'PublicationAuthority::Production {' \
    'runtime.phase,' \
    'runtime.registry.acknowledge_publication(ticket).unwrap();' \
    '.active_revoke' \
    'runtime.registry.revoke_complete(&selection).unwrap();' \
    'runtime.phase = ProductionReadPhase::Complete;' \
    'runtime.assert_complete();' \
    'LINUX_FS_SAME_BOOT GuestPublication' \
    'LINUX_FS_SAME_BOOT PASS'
require_count "$publication" 'PublicationAuthority::Production {' 1
require_count "$publication" 'runtime.registry.acknowledge_publication(ticket).unwrap();' 1
require_count "$publication" 'runtime.registry.revoke_complete(&selection).unwrap();' 1

# The kernel root makes the feature run terminal immediately after the runtime
# filesystem receipt. Legacy network/composition/IOMMU successors are compiled
# and executed only in the explicit not(feature) branch.
for module_path in \
    '#[path = "cser/composition.rs"]' \
    '#[path = "probes/iommu_probe.rs"]' \
    '#[path = "cser/linux_io_composition.rs"]' \
    '#[path = "personality/linux_net.rs"]'; do
    require_not_feature_cfg_before "$lib_file" "$module_path"
done
require_order "$feature_root" \
    '    #[cfg(all(' \
    'feature = "virtio-cser-facade",' \
    'not(feature = "virtio-cser-precommit-fault")' \
    'assert_eq!(fs_receipt.terminalizations, 14);' \
    'assert_eq!(fs_receipt.publication_acks, 14);' \
    'assert_eq!(fs_receipt.production_effects, 6);' \
    'assert_eq!(fs_receipt.production_domains, 3);' \
    'assert!(fs_receipt.quiescent);' \
    'println!("SPIKE_RESULT PASS");' \
    'poweroff(ExitCode::Success);'
require_count "$feature_root" 'println!("SPIKE_RESULT PASS");' 1
require_count "$feature_root" 'poweroff(ExitCode::Success);' 1
for forbidden_successor in \
    'linux_net::run_linux_net_slice' \
    'composition::run_composition_slice' \
    'linux_io_composition::run_linux_io_composition_slice' \
    'IOMMU_PROBE PASS'; do
    reject_fixed "$feature_root" "$forbidden_successor"
done

require_order "$legacy_root" \
    '    #[cfg(not(feature = "virtio-cser-facade"))]' \
    'linux_net::run_linux_net_slice();' \
    'composition::run_composition_slice(scheduler, pager_receipt);' \
    'linux_io_composition::run_linux_io_composition_slice(' \
    'IOMMU_PROBE PASS result=FAIL_CLOSED' \
    'println!("SPIKE_RESULT PASS");' \
    'poweroff(ExitCode::Success);'
for legacy_token in \
    'linux_net::run_linux_net_slice' \
    'composition::run_composition_slice' \
    'linux_io_composition::run_linux_io_composition_slice'; do
    require_count "$lib_file" "$legacy_token" 1
    require_count "$legacy_root" "$legacy_token" 1
done
require_count "$lib_file" 'println!("SPIKE_RESULT PASS");' 3
require_count "$feature_root" 'assert_eq!(fs_receipt.production_effects, 6);' 1

if [[ ${NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY:-0} != 1 ]]; then
    mutations=0

    require_mutation() {
        local canonical=$1
        local mutated=$2
        local label=$3
        if cmp -s "$canonical" "$mutated"; then
            fail "source mutation did not apply: $label"
        fi
    }

    require_rejection() {
        local mutated=$1
        local label=$2
        if NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 bash "$0" "$mutated" "$lib_file" \
            >/dev/null 2>&1; then
            fail "same-boot source gate accepted mutation: $label"
        fi
        mutations=$((mutations + 1))
    }

    require_lib_rejection() {
        local mutated=$1
        local label=$2
        if NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 bash "$0" "$source_file" "$mutated" \
            >/dev/null 2>&1; then
            fail "same-boot source gate accepted kernel-root mutation: $label"
        fi
        mutations=$((mutations + 1))
    }

    cp "$source_file" "$work/fabricated-descriptor.rs"
    sed -i 's/return self\.dispatch_first_executable_pread_same_boot(descriptor);/return self.dispatch_first_executable_pread_same_boot(SyscallDescriptor::new(0, [0; 6]));/' \
        "$work/fabricated-descriptor.rs"
    require_mutation "$source_file" "$work/fabricated-descriptor.rs" fabricated-descriptor
    require_rejection "$work/fabricated-descriptor.rs" fabricated-descriptor

    cp "$source_file" "$work/direct-device-registration.rs"
    sed -i 's/register_device_derived_cohort/register_device_derived/' \
        "$work/direct-device-registration.rs"
    require_mutation "$source_file" "$work/direct-device-registration.rs" direct-device-registration
    require_rejection "$work/direct-device-registration.rs" direct-device-registration

    cp "$source_file" "$work/five-handles.rs"
    sed -i '/^[[:space:]]*dma_request\.handle,$/d' "$work/five-handles.rs"
    require_mutation "$source_file" "$work/five-handles.rs" five-handles
    require_rejection "$work/five-handles.rs" five-handles

    cp "$source_file" "$work/missing-root-authority.rs"
    sed -i 's/kernel_root_authority(SCOPE, ROOT_OWNER)/validate_kernel_root_authority(SCOPE, ROOT_OWNER)/' \
        "$work/missing-root-authority.rs"
    require_mutation "$source_file" "$work/missing-root-authority.rs" missing-root-authority
    require_rejection "$work/missing-root-authority.rs" missing-root-authority

    awk '
        /stage=cohort_register/ { cohort_error = 1 }
        cohort_error && !changed && /self\.reject_prepared_without_device_root\(/ {
            sub(/reject_prepared_without_device_root/, "reject_preparation_without_hardware_owner")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/cohort-error-missing-unregistered-route.rs"
    require_mutation "$source_file" "$work/cohort-error-missing-unregistered-route.rs" \
        cohort-error-missing-unregistered-route
    require_rejection "$work/cohort-error-missing-unregistered-route.rs" \
        cohort-error-missing-unregistered-route

    cp "$source_file" "$work/unregistered-device-root-present.rs"
    sed -i \
        's/assert_eq!(runtime\.registry\.device_root_installed(SCOPE), Ok(false));/assert_eq!(runtime.registry.device_root_installed(SCOPE), Ok(true));/' \
        "$work/unregistered-device-root-present.rs"
    require_mutation "$source_file" "$work/unregistered-device-root-present.rs" \
        unregistered-device-root-present
    require_rejection "$work/unregistered-device-root-present.rs" \
        unregistered-device-root-present

    cp "$source_file" "$work/unregistered-published-owner.rs"
    sed -i \
        's/let cancelled = prepared\.cancel_unregistered();/let cancelled = prepared.publish_prepared();/' \
        "$work/unregistered-published-owner.rs"
    require_mutation "$source_file" "$work/unregistered-published-owner.rs" \
        unregistered-published-owner
    require_rejection "$work/unregistered-published-owner.rs" unregistered-published-owner

    cp "$source_file" "$work/unregistered-reset-no-timeout.rs"
    sed -i \
        's/let (reset_tombstone, mut cancellation) = cancelled\.begin_reset(true);/let (reset_tombstone, mut cancellation) = cancelled.begin_reset(false);/' \
        "$work/unregistered-reset-no-timeout.rs"
    require_mutation "$source_file" "$work/unregistered-reset-no-timeout.rs" \
        unregistered-reset-no-timeout
    require_rejection "$work/unregistered-reset-no-timeout.rs" unregistered-reset-no-timeout

    cp "$source_file" "$work/unregistered-missing-reset-retry.rs"
    sed -i \
        's/let mut reset = match reset_tombstone\.retry_ack(&mut root) {/let mut reset = match reset_tombstone.skip_retry_ack(\&mut root) {/' \
        "$work/unregistered-missing-reset-retry.rs"
    require_mutation "$source_file" "$work/unregistered-missing-reset-retry.rs" \
        unregistered-missing-reset-retry
    require_rejection "$work/unregistered-missing-reset-retry.rs" \
        unregistered-missing-reset-retry

    cp "$source_file" "$work/unregistered-missing-reset-apply.rs"
    sed -i 's/apply_unregistered_reset/skip_unregistered_reset/' \
        "$work/unregistered-missing-reset-apply.rs"
    require_mutation "$source_file" "$work/unregistered-missing-reset-apply.rs" \
        unregistered-missing-reset-apply
    require_rejection "$work/unregistered-missing-reset-apply.rs" \
        unregistered-missing-reset-apply

    cp "$source_file" "$work/unregistered-iotlb-no-timeout.rs"
    sed -i \
        's/begin_unregistered_iotlb(reset, &cancellation, true)/begin_unregistered_iotlb(reset, \&cancellation, false)/' \
        "$work/unregistered-iotlb-no-timeout.rs"
    require_mutation "$source_file" "$work/unregistered-iotlb-no-timeout.rs" \
        unregistered-iotlb-no-timeout
    require_rejection "$work/unregistered-iotlb-no-timeout.rs" \
        unregistered-iotlb-no-timeout

    cp "$source_file" "$work/unregistered-dropped-reset-owner.rs"
    sed -i \
        's/(reset_owner, cancellation, root, device),/(cancellation, root, device),/' \
        "$work/unregistered-dropped-reset-owner.rs"
    require_mutation "$source_file" "$work/unregistered-dropped-reset-owner.rs" \
        unregistered-dropped-reset-owner
    require_rejection "$work/unregistered-dropped-reset-owner.rs" \
        unregistered-dropped-reset-owner

    awk '
        /fn close_unregistered_precommit_failure\(/ { helper = 1 }
        /fn close_enrolled_precommit_failure\(/ { helper = 0 }
        helper && !changed && /iotlb\.retry\(1024\)/ {
            sub(/retry\(1024\)/, "retry(0)")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/unregistered-zero-iotlb-retry.rs"
    require_mutation "$source_file" "$work/unregistered-zero-iotlb-retry.rs" \
        unregistered-zero-iotlb-retry
    require_rejection "$work/unregistered-zero-iotlb-retry.rs" \
        unregistered-zero-iotlb-retry

    cp "$source_file" "$work/unregistered-missing-quiescence-apply.rs"
    sed -i 's/apply_unregistered_quiescence/skip_unregistered_quiescence/' \
        "$work/unregistered-missing-quiescence-apply.rs"
    require_mutation "$source_file" "$work/unregistered-missing-quiescence-apply.rs" \
        unregistered-missing-quiescence-apply
    require_rejection "$work/unregistered-missing-quiescence-apply.rs" \
        unregistered-missing-quiescence-apply

    cp "$source_file" "$work/unregistered-incomplete-cancellation.rs"
    sed -i \
        's/assert!(cancellation\.is_complete());/assert!(!cancellation.is_complete());/' \
        "$work/unregistered-incomplete-cancellation.rs"
    require_mutation "$source_file" "$work/unregistered-incomplete-cancellation.rs" \
        unregistered-incomplete-cancellation
    require_rejection "$work/unregistered-incomplete-cancellation.rs" \
        unregistered-incomplete-cancellation

    cp "$source_file" "$work/unregistered-reordered-ancestors.rs"
    sed -i \
        's/for expected in \[effects\[1\], effects\[0\]\] {/for expected in [effects[0], effects[1]] {/' \
        "$work/unregistered-reordered-ancestors.rs"
    require_mutation "$source_file" "$work/unregistered-reordered-ancestors.rs" \
        unregistered-reordered-ancestors
    require_rejection "$work/unregistered-reordered-ancestors.rs" \
        unregistered-reordered-ancestors

    awk '
        /fn close_ordinary_precommit_failure\(/ { ordinary = 1 }
        /fn close_unregistered_precommit_failure\(/ { ordinary = 0 }
        ordinary && !changed && /TerminalRequest::aborted\(-125\)/ {
            sub(/TerminalRequest::aborted\(-125\)/,
                "TerminalRequest::indeterminate_after_reset(-5)")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/unregistered-wrong-ancestor-terminal.rs"
    require_mutation "$source_file" "$work/unregistered-wrong-ancestor-terminal.rs" \
        unregistered-wrong-ancestor-terminal
    require_rejection "$work/unregistered-wrong-ancestor-terminal.rs" \
        unregistered-wrong-ancestor-terminal

    awk '
        /fn close_unregistered_precommit_failure\(/ { helper = 1 }
        /fn close_enrolled_precommit_failure\(/ { helper = 0 }
        { print }
        helper && !changed && /assert_eq!\(cancelled\.identity\(\), identity\);/ {
            print "        let _forbidden = cancelled.notify();"
            changed = 1
        }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/unregistered-device-notify.rs"
    require_mutation "$source_file" "$work/unregistered-device-notify.rs" \
        unregistered-device-notify
    require_rejection "$work/unregistered-device-notify.rs" unregistered-device-notify

    awk '
        /fn close_unregistered_precommit_failure\(/ { helper = 1 }
        /fn close_enrolled_precommit_failure\(/ { helper = 0 }
        { print }
        helper && !changed && /assert_eq!\(cancelled\.identity\(\), identity\);/ {
            print "        let _forbidden = cancelled.poll_completion();"
            changed = 1
        }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/unregistered-device-poll.rs"
    require_mutation "$source_file" "$work/unregistered-device-poll.rs" \
        unregistered-device-poll
    require_rejection "$work/unregistered-device-poll.rs" unregistered-device-poll

    awk '
        /^            #\[cfg\(not\(feature = "virtio-cser-precommit-fault"\)\)\]$/ { positive = 1 }
        positive && !changed && /\.publish_prepared\(\)/ {
            sub(/\.publish_prepared\(\)/, ".cancel_prepared()")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/missing-publish-gate.rs"
    require_mutation "$source_file" "$work/missing-publish-gate.rs" missing-publish-gate
    require_rejection "$work/missing-publish-gate.rs" missing-publish-gate

    awk '
        /^            #\[cfg\(not\(feature = "virtio-cser-precommit-fault"\)\)\]$/ { positive = 1 }
        positive && !changed && /let mut prepared_slot = Some\(prepared_request\);/ {
            sub(/Some\(prepared_request\)/, "prepared_request")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/missing-prepared-slot.rs"
    require_mutation "$source_file" "$work/missing-prepared-slot.rs" missing-prepared-slot
    require_rejection "$work/missing-prepared-slot.rs" missing-prepared-slot

    awk '
        /Ok\(DeviceBatchCommitOutcome::Applied \{/ { applied = 1 }
        applied && !changed && /assert!\(prepared_slot\.is_none\(\)\);/ {
            sub(/is_none/, "is_some")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/applied-retains-slot.rs"
    require_mutation "$source_file" "$work/applied-retains-slot.rs" applied-retains-slot
    require_rejection "$work/applied-retains-slot.rs" applied-retains-slot

    awk '
        /^            #\[cfg\(not\(feature = "virtio-cser-precommit-fault"\)\)\]$/ { positive = 1 }
        positive && /Err\(error\) => \{/ { error = 1 }
        error && !changed && /reject_enrolled_device_precommit/ {
            sub(/reject_enrolled_device_precommit/, "skip_enrolled_device_precommit")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/error-missing-cancel.rs"
    require_mutation "$source_file" "$work/error-missing-cancel.rs" error-missing-cancel
    require_rejection "$work/error-missing-cancel.rs" error-missing-cancel

    cp "$source_file" "$work/enrolled-helper-missing-cancel.rs"
    sed -i \
        's/begin_unpublished_device_cancel(enrollment)/skip_unpublished_device_cancel(enrollment)/' \
        "$work/enrolled-helper-missing-cancel.rs"
    require_mutation "$source_file" "$work/enrolled-helper-missing-cancel.rs" \
        enrolled-helper-missing-cancel
    require_rejection "$work/enrolled-helper-missing-cancel.rs" \
        enrolled-helper-missing-cancel

    awk '
        /^            #\[cfg\(not\(feature = "virtio-cser-precommit-fault"\)\)\]$/ { positive = 1 }
        positive && /Err\(error\) => \{/ { error = 1 }
        error && !changed && /\.take\(\)/ {
            sub(/\.take\(\)/, ".as_ref()")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/error-missing-take.rs"
    require_mutation "$source_file" "$work/error-missing-take.rs" error-missing-take
    require_rejection "$work/error-missing-take.rs" error-missing-take

    awk '
        !changed && /Ok\(DeviceBatchCommitOutcome::AlreadyCommitted \{/ {
            sub(/\) => \{/, ") | Err(error) => {")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/replay-merged-with-error.rs"
    require_mutation "$source_file" "$work/replay-merged-with-error.rs" replay-merged-with-error
    require_rejection "$work/replay-merged-with-error.rs" replay-merged-with-error

    awk '
        /Ok\(DeviceBatchCommitOutcome::AlreadyCommitted \{/ { replay = 1 }
        replay && !changed {
            print
            print "                        let _forbidden = runtime.registry.begin_unpublished_device_cancel(&enrollment);"
            changed = 1
            next
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/replay-unpublished-cancel.rs"
    require_mutation "$source_file" "$work/replay-unpublished-cancel.rs" replay-unpublished-cancel
    require_rejection "$work/replay-unpublished-cancel.rs" replay-unpublished-cancel

    awk '
        /Ok\(DeviceBatchCommitOutcome::AlreadyCommitted \{/ { replay = 1 }
        /Err\(error\) => \{/ { replay = 0 }
        replay && !changed && /validate_device_replay_fence_candidate\(&receipt\)/ {
            sub(/validate_device_replay_fence_candidate/, "skip_device_replay_fence_validation")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/replay-missing-validation.rs"
    require_mutation "$source_file" "$work/replay-missing-validation.rs" replay-missing-validation
    require_rejection "$work/replay-missing-validation.rs" replay-missing-validation

    awk '
        /Ok\(DeviceBatchCommitOutcome::AlreadyCommitted \{/ { replay = 1 }
        replay && !changed {
            print
            print "                        let _forbidden = DeviceClosureResult::AbortedBeforeCommit;"
            changed = 1
            next
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/replay-aborted-before-commit.rs"
    require_mutation "$source_file" "$work/replay-aborted-before-commit.rs" replay-aborted-before-commit
    require_rejection "$work/replay-aborted-before-commit.rs" replay-aborted-before-commit

    awk '
        /Ok\(DeviceBatchCommitOutcome::AlreadyCommitted \{/ { replay = 1 }
        /Err\(error\) => \{/ { replay = 0; error = 1 }
        replay && !changed && /assert!\(prepared_slot\.is_some\(\)\);/ {
            sub(/is_some/, "is_none")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/replay-missing-slot.rs"
    require_mutation "$source_file" "$work/replay-missing-slot.rs" replay-missing-slot
    require_rejection "$work/replay-missing-slot.rs" replay-missing-slot

    awk '
        /fn reject_enrolled_device_precommit\(/ { reject = 1 }
        /fn close_ordinary_precommit_failure\(/ { reject = 0 }
        reject && !changed && /^[[:space:]]*false,$/ {
            sub(/false/, "true")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/error-fault-markers.rs"
    require_mutation "$source_file" "$work/error-fault-markers.rs" error-fault-markers
    require_rejection "$work/error-fault-markers.rs" error-fault-markers

    awk '
        /^            #\[cfg\(not\(feature = "virtio-cser-precommit-fault"\)\)\]$/ { positive = 1 }
        positive && !changed && /validate_device_batch_receipt\(&batch\)/ {
            sub(/validate_device_batch_receipt/, "skip_device_batch_receipt_validation")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/missing-positive-batch-validation.rs"
    require_mutation "$source_file" "$work/missing-positive-batch-validation.rs" \
        missing-positive-batch-validation
    require_rejection "$work/missing-positive-batch-validation.rs" \
        missing-positive-batch-validation

    cp "$source_file" "$work/poll-under-lock.rs"
    sed -i '/let notification = published\.notify();/i\        let _forbidden_guard = self.production.lock();' \
        "$work/poll-under-lock.rs"
    require_mutation "$source_file" "$work/poll-under-lock.rs" poll-under-lock
    require_rejection "$work/poll-under-lock.rs" poll-under-lock

    cp "$source_file" "$work/elf-payload.rs"
    sed -i 's/let bytes = completed\.data()\[\.\.4\]\.to_vec();/let bytes = RUNTIME_FS_ELF[..4].to_vec();/' \
        "$work/elf-payload.rs"
    require_mutation "$source_file" "$work/elf-payload.rs" retained-elf-payload
    require_rejection "$work/elf-payload.rs" retained-elf-payload

    cp "$source_file" "$work/missing-generation-apply.rs"
    sed -i 's/generation_plan\.apply()/new_hardware_generation/' \
        "$work/missing-generation-apply.rs"
    require_mutation "$source_file" "$work/missing-generation-apply.rs" missing-generation-apply
    require_rejection "$work/missing-generation-apply.rs" missing-generation-apply

    cp "$source_file" "$work/reordered-leaves.rs"
    sed -i 's/effects\[3\], effects\[4\], effects\[5\], effects\[2\], effects\[1\], effects\[0\]/effects[4], effects[3], effects[5], effects[2], effects[1], effects[0]/' \
        "$work/reordered-leaves.rs"
    require_mutation "$source_file" "$work/reordered-leaves.rs" reordered-leaves
    require_rejection "$work/reordered-leaves.rs" reordered-leaves

    cp "$source_file" "$work/synthetic-registry.rs"
    sed -i '/assert_eq!(descriptor\.number(), __NR_pread64 as usize);/a\        let _synthetic = EffectRegistry::new();' \
        "$work/synthetic-registry.rs"
    require_mutation "$source_file" "$work/synthetic-registry.rs" synthetic-registry
    require_rejection "$work/synthetic-registry.rs" synthetic-registry

    cp "$source_file" "$work/missing-publication-ack.rs"
    sed -i 's/runtime\.registry\.acknowledge_publication(ticket)\.unwrap();/runtime.registry.check_invariants().unwrap();/' \
        "$work/missing-publication-ack.rs"
    require_mutation "$source_file" "$work/missing-publication-ack.rs" missing-publication-ack
    require_rejection "$work/missing-publication-ack.rs" missing-publication-ack

    cp "$lib_file" "$work/sixteen-production-effects.rs"
    sed -i 's/assert_eq!(fs_receipt\.production_effects, 6);/assert_eq!(fs_receipt.production_effects, 16);/' \
        "$work/sixteen-production-effects.rs"
    require_mutation "$lib_file" "$work/sixteen-production-effects.rs" sixteen-production-effects
    require_lib_rejection "$work/sixteen-production-effects.rs" sixteen-production-effects

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

    cp "$lib_file" "$work/missing-feature-poweroff.rs"
    awk '
        /assert_eq!\(fs_receipt\.production_effects, 6\);/ { feature = 1 }
        feature && !changed && /poweroff\(ExitCode::Success\);/ {
            sub(/poweroff\(ExitCode::Success\);/, "Task::yield_now();")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$lib_file" >"$work/missing-feature-poweroff.rs"
    require_mutation "$lib_file" "$work/missing-feature-poweroff.rs" missing-feature-poweroff
    require_lib_rejection "$work/missing-feature-poweroff.rs" missing-feature-poweroff

    cp "$lib_file" "$work/unfenced-legacy-branch.rs"
    awk '
        /let fs_receipt = linux_fs::run_linux_fs_slice\(\);/ { post_fs = 1 }
        post_fs && !removed && /^[[:space:]]*#\[cfg\(not\(feature = "virtio-cser-facade"\)\)\]$/ {
            removed = 1
            next
        }
        { print }
        END { if (!removed) exit 2 }
    ' "$lib_file" >"$work/unfenced-legacy-branch.rs"
    require_mutation "$lib_file" "$work/unfenced-legacy-branch.rs" unfenced-legacy-branch
    require_lib_rejection "$work/unfenced-legacy-branch.rs" unfenced-legacy-branch

    awk '
        /let fs_receipt = linux_fs::run_linux_fs_slice\(\);/ { post_fs = 1 }
        post_fs && !removed && /^[[:space:]]*not\(feature = "virtio-cser-precommit-fault"\)$/ {
            removed = 1
            next
        }
        { print }
        END { if (!removed) exit 2 }
    ' "$lib_file" >"$work/unfenced-positive-branch.rs"
    require_mutation "$lib_file" "$work/unfenced-positive-branch.rs" unfenced-positive-branch
    require_lib_rejection "$work/unfenced-positive-branch.rs" unfenced-positive-branch

    [[ $mutations == 43 ]] || fail "expected 43 source mutations, observed $mutations"
fi

echo 'runtime filesystem same-boot source assertions: PASS user_context_descriptor=true request_local_registry=true effects=6 credits=10 recovery=crash+snapshot+ready+rebind+adopt cohort=failure_atomic cohort_error=unregistered_cancel device_root=false unregistered_reset=pending+retry+apply unregistered_iotlb=owner_preserving_error+pending+retry+apply unregistered_complete=true ordinary_ancestors=filesystem_read+filesystem_syscall device_activity=publish+notify+poll_forbidden prepare_four=true authority=enroll_exact_six commit_gate=preflight+avail_idx_release prepared_slot=true applied_positive_only=true replay=postcommit_conflict error=explicit_unpublished_cancel lock_free_notify_poll=true completion_source=CompletedRequest reset_apply=true iotlb_apply=true leaf_first=true production_publication=ack+revoke_complete feature_terminal=true legacy_successors=not_feature synthetic_registry=false mutations=43'
