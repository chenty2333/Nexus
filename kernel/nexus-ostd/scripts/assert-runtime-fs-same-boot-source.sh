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
dispatch_route="$work/dispatch-route.rs"
publication="$work/production-publication.rs"
run_guest="$work/run-guest.rs"
descriptor_builder="$work/descriptor-builder.rs"
lock_free="$work/lock-free-flight.rs"
handles="$work/enrollment-handles.rs"
commits="$work/batch-commits.rs"
effect_vector="$work/flight-effects.rs"
post_fs_root="$work/post-fs-root.rs"
feature_root="$work/feature-root.rs"
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
extract_between "$same_boot" \
    '        let SameBootFlight {' \
    '        let (result, bytes, reset_tombstone, completion_label, used_len, reset_ticket) =' \
    "$lock_free"
extract_between "$same_boot" \
    '            let handles = [' '            let enrollment = runtime' "$handles"
extract_between "$same_boot" \
    '            let commits = [' '            let (batch, published) = match runtime' "$commits"
extract_through_first_after "$same_boot" \
    '                effects: [' '                ],' "$effect_vector"
extract_from "$lib_file" \
    '    let fs_receipt = linux_fs::run_linux_fs_slice();' "$post_fs_root"
extract_between "$post_fs_root" \
    '    #[cfg(feature = "virtio-cser-facade")]' \
    '    #[cfg(not(feature = "virtio-cser-facade"))]' "$feature_root"
extract_from "$post_fs_root" \
    '    #[cfg(not(feature = "virtio-cser-facade"))]' "$legacy_root"

for anchor in \
    'struct ProductionReadRuntime {' \
    'fn new_same_boot_registry() -> EffectRegistry {' \
    'fn same_boot_credit(class: CreditClass, units: u64) -> CreditCharge {' \
    'fn same_boot_dma_entry(' \
    'fn dispatch_first_executable_pread_same_boot('; do
    require_cfg_before "$source_file" "$anchor"
done
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
    'usize::try_from(generation).unwrap(),'; do
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

# Bind every semantic phase to the same feature function. Counts prevent a
# dead synthetic cohort from being added alongside the production calls.
require_count "$same_boot" '.register_derived(DerivedRegisterRequest {' 2
require_count "$same_boot" '.register_device_derived_cohort([' 1
require_count "$same_boot" 'same_boot_dma_entry(' 3
require_count "$same_boot" 'owner_address(' 3
require_count "$same_boot" 'for effect in [&block, &dma_queue_a, &dma_queue_b, &dma_request] {' 1
require_count "$same_boot" 'runtime.registry.prepare(BLOCK_V1, effect.handle).unwrap();' 1
require_count "$same_boot" '.kernel_root_authority(SCOPE, ROOT_OWNER)' 1
require_count "$same_boot" '.enroll_device_batch(authority, &handles, envelope)' 1
require_count "$same_boot" '.preflight_publish(expected_hardware_identity)' 1
require_count "$same_boot" '.commit_device_batch_with_publish(authority, &enrollment, &commits, move |_| {' 1
require_count "$same_boot" 'prepared_request.publish_prepared()' 1
require_count "$same_boot" 'runtime.registry.revoke_begin(SCOPE).unwrap();' 1
require_count "$same_boot" 'let notification = published.notify();' 1
require_count "$same_boot" 'let progress = published.poll_completion();' 1
require_count "$same_boot" '.record_device_completion(&batch, envelope, 4)' 1
require_count "$same_boot" '.prepare_generation_advance(&mut hardware_reset)' 1
require_count "$same_boot" '.acknowledge_device_reset_with_apply(&retry_ticket, |prepared| {' 1
require_count "$same_boot" 'generation_plan.apply()' 1
require_count "$same_boot" '.prepare_quiescence_apply(&mut hardware_closure)' 1
require_count "$same_boot" '.acknowledge_device_iotlb_with_apply(&registry_iotlb_retry, |prepared| {' 1
require_count "$same_boot" 'quiescence_plan.apply()' 1
require_count "$same_boot" '.revoke_next(&selection)' 2
require_count "$same_boot" '.stage_device_batch_terminal(&registry_closure, expected, request)' 1
require_count "$same_boot" 'authority: PublicationAuthority::Production {' 1
require_count "$same_boot" 'Publication::GuestBytes {' 1

require_order "$same_boot" \
    'let syscall = {' \
    'runtime.phase = ProductionReadPhase::Captured(syscall.identity.effect());' \
    "// This is the real filesystem personality's fd/inode resolution." \
    'let flight = {' \
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
    '.commit_device_batch_with_publish(authority, &enrollment, &commits, move |_| {' \
    'prepared_request.publish_prepared()' \
    '.validate_device_batch_receipt(&batch)' \
    'runtime.registry.revoke_begin(SCOPE).unwrap();' \
    '            SameBootFlight {' \
    '        let SameBootFlight {' \
    'let notification = published.notify();' \
    'let progress = published.poll_completion();' \
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
    'let leaf_first = [' \
    'effects[3], effects[4], effects[5], effects[2], effects[1], effects[0],' \
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
require_order "$lock_free" \
    '        let SameBootFlight {' \
    '        } = flight;' \
    'let notification = published.notify();' \
    'let progress = published.poll_completion();'
reject_fixed "$lock_free" 'self.production.lock()'
reject_fixed "$lock_free" 'let mut runtime'
require_count "$flight_struct" 'published: PublishedRequest,' 1
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
    '    #[cfg(feature = "virtio-cser-facade")]' \
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
require_count "$lib_file" 'println!("SPIKE_RESULT PASS");' 2
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

    cp "$source_file" "$work/missing-publish-gate.rs"
    sed -i 's/prepared_request\.publish_prepared()/prepared_request.cancel_prepared()/' \
        "$work/missing-publish-gate.rs"
    require_mutation "$source_file" "$work/missing-publish-gate.rs" missing-publish-gate
    require_rejection "$work/missing-publish-gate.rs" missing-publish-gate

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

    [[ $mutations == 15 ]] || fail "expected 15 source mutations, observed $mutations"
fi

echo 'runtime filesystem same-boot source assertions: PASS user_context_descriptor=true request_local_registry=true effects=6 credits=10 recovery=crash+snapshot+ready+rebind+adopt cohort=failure_atomic prepare_four=true authority=enroll_exact_six commit_gate=preflight+avail_idx_release lock_free_notify_poll=true completion_source=CompletedRequest reset_apply=true iotlb_apply=true leaf_first=true production_publication=ack+revoke_complete feature_terminal=true legacy_successors=not_feature synthetic_registry=false mutations=15'
