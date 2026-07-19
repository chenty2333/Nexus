#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_file=${1:-$script_root/src/personality/linux_fs.rs}
lib_file=${2:-$script_root/src/lib.rs}
device_flight_file=${3:-$script_root/src/cser/device_flight.rs}
runtime_causal_file=${4:-$script_root/src/cser/effect_registry/runtime_causal.rs}
infrastructure_root_file=${5:-$script_root/src/cser/infrastructure/root.rs}
infrastructure_mod_file=${6:-$script_root/src/cser/infrastructure/mod.rs}
effect_registry_file=${7:-$script_root/src/cser/effect_registry.rs}
adapter_file=${8:-$script_root/src/personality/virtio_cser_adapter.rs}
receipt_bridge_file=${9:-$script_root/src/cser/infrastructure/device_receipt_bridge.rs}
registry_file=$effect_registry_file

fail() {
    echo "runtime filesystem same-boot source assertion: FAIL: $*" >&2
    exit 1
}

for input in \
    "$source_file" \
    "$lib_file" \
    "$device_flight_file" \
    "$runtime_causal_file" \
    "$infrastructure_root_file" \
    "$infrastructure_mod_file" \
    "$effect_registry_file" \
    "$adapter_file" \
    "$receipt_bridge_file"; do
    [[ -f $input && ! -L $input ]] ||
        fail "implementation source is not a regular non-symlink file: $input"
done

# Concrete VirtIO receipt types belong only to the Linux filesystem consumer
# and its feature-gated sibling adapter. The CSER core owns provider-neutral
# views and must remain host-compilable without the OSTD facade dependency.
if grep -R -Fq --include='*.rs' -- 'nexus_ostd_virtio' "$script_root/src/cser"; then
    fail 'concrete nexus_ostd_virtio dependency entered the CSER core'
fi
mapfile -t concrete_virtio_files < <(
    grep -R -lF --include='*.rs' -- 'nexus_ostd_virtio' "$script_root/src" || true
)
[[ ${#concrete_virtio_files[@]} == 2 ]] ||
    fail "expected concrete VirtIO references in exactly linux_fs + sibling adapter, observed ${#concrete_virtio_files[@]} files"
for expected_concrete_file in \
    "$script_root/src/personality/linux_fs.rs" \
    "$script_root/src/personality/virtio_cser_adapter.rs"; do
    found_expected=false
    for concrete_file in "${concrete_virtio_files[@]}"; do
        if [[ $concrete_file == "$expected_concrete_file" ]]; then
            found_expected=true
        fi
    done
    [[ $found_expected == true ]] ||
        fail "missing sole allowed concrete VirtIO dependency edge: $expected_concrete_file"
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
causal_slot="$work/causal-adapter-slot.rs"
runtime="$work/production-runtime.rs"
runtime_impl="$work/production-runtime-impl.rs"
dispatch="$work/same-boot-dispatch.rs"
capture="$work/same-boot-capture.rs"
guest_wait="$work/filesystem-guest-wait.rs"
service_next="$work/filesystem-service-next.rs"
service_prepare="$work/filesystem-service-prepare.rs"
service_queue="$work/filesystem-service-queue.rs"
service_crash="$work/filesystem-service-crash.rs"
service_recovery="$work/filesystem-service-recovery.rs"
service_stale="$work/filesystem-service-stale.rs"
service_execute="$work/filesystem-service-execute.rs"
service_publish="$work/filesystem-service-publish.rs"
fsd_task_identity="$work/filesystem-service-task-identity.rs"
fsd_v1_runner="$work/filesystem-service-v1-runner.rs"
fsd_v2_runner="$work/filesystem-service-v2-runner.rs"
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
causal_session="$work/causal-session.rs"
causal_activation="$work/causal-activation.rs"
causal_limits="$work/causal-limits.rs"
causal_domain_request="$work/causal-domain-request.rs"
causal_domain_prepare="$work/causal-domain-prepare.rs"
causal_domain_activate="$work/causal-domain-activate.rs"
causal_domain_validate="$work/causal-domain-validate.rs"
causal_domain_verify="$work/causal-domain-verify.rs"
causal_domain_close_validate="$work/causal-domain-close-validate.rs"
causal_domain_close="$work/causal-domain-close.rs"
causal_close_intent="$work/causal-close-intent.rs"
causal_close_prepare="$work/causal-close-prepare.rs"
causal_close_validate="$work/causal-close-validate.rs"
causal_close_apply="$work/causal-close-apply.rs"
causal_combined_close="$work/causal-combined-close.rs"
causal_standalone_close="$work/causal-standalone-close.rs"
infrastructure_close_prepare="$work/infrastructure-close-prepare.rs"
infrastructure_close_validate="$work/infrastructure-close-validate.rs"
infrastructure_close_apply="$work/infrastructure-close-apply.rs"
infrastructure_projected_finish="$work/infrastructure-projected-finish.rs"
infrastructure_child_open="$work/infrastructure-child-open.rs"
infrastructure_child_apply="$work/infrastructure-child-apply.rs"
infrastructure_historical_close="$work/infrastructure-historical-close.rs"
registry_revoke_prepare="$work/registry-revoke-prepare.rs"
adapter_phase="$work/device-adapter-phase.rs"

extract_between "$source_file" 'struct FsState {' \
    'struct FsClosureWork {' "$fs_state"
extract_between "$source_file" 'enum FsDeviceFlight {' \
    'struct FsCausalAdapterSlot {' "$flight"
extract_between "$source_file" 'struct FsCausalAdapterSlot {' \
    'struct ProductionReadRuntime {' "$causal_slot"
extract_between "$source_file" 'struct ProductionReadRuntime {' \
    'impl ProductionReadRuntime {' "$runtime"
extract_between "$source_file" 'impl ProductionReadRuntime {' \
    'struct ProductionReadReceipt {' "$runtime_impl"
extract_between "$source_file" 'fn fsd_next_operation(&self, sender: TaskKey)' \
    'fn fsd_prepare_active(&self, sender: TaskKey)' "$service_next"
extract_between "$source_file" 'fn fsd_prepare_active(&self, sender: TaskKey)' \
    'fn fsd_queue_old_prepare(&self, sender: TaskKey)' "$service_prepare"
extract_between "$source_file" 'fn fsd_queue_old_prepare(&self, sender: TaskKey)' \
    'fn crash_fsd_v1(&self, sender: TaskKey)' "$service_queue"
extract_between "$source_file" 'fn crash_fsd_v1(&self, sender: TaskKey)' \
    'fn fsd_recovery_snapshot(&self, sender: TaskKey)' "$service_crash"
extract_between "$source_file" 'fn fsd_recovery_snapshot(&self, sender: TaskKey)' \
    'fn fsd_deliver_old_prepare(&self, delivery_sender: TaskKey)' "$service_recovery"
extract_between "$source_file" 'fn fsd_deliver_old_prepare(&self, delivery_sender: TaskKey)' \
    'fn fsd_execute_recovered(&self)' "$service_stale"
extract_between "$source_file" 'fn fsd_execute_recovered(&self)' \
    'fn fsd_publish_response(&self)' "$service_execute"
extract_between "$source_file" 'fn fsd_publish_response(&self)' \
    '// The single polling actor restores each linear successor' "$service_publish"
extract_between "$source_file" 'fn capture_first_executable_pread_same_boot(' \
    'fn dispatch_first_executable_pread_same_boot(' "$capture"
extract_between "$source_file" 'fn dispatch_first_executable_pread_same_boot(' \
    'fn execute_recovered_first_pread_same_boot(' "$guest_wait"
extract_between "$source_file" 'fn execute_recovered_first_pread_same_boot(' \
    'fn dispatch_first_executable_pread(' "$dispatch"
extract_between "$source_file" 'fn current_fsd_task(' \
    'fn run_fsd_v1(' "$fsd_task_identity"
extract_between "$source_file" 'fn run_fsd_v1(' \
    'fn run_fsd_v2(' "$fsd_v1_runner"
extract_between "$source_file" 'fn run_fsd_v2(' \
    'pub(crate) fn run_linux_fs_slice()' "$fsd_v2_runner"
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
extract_between "$runtime_causal_file" \
    'pub(crate) struct CausalWorkloadSession {' \
    'pub(crate) enum CausalWorkloadError {' "$causal_session"
extract_between "$runtime_causal_file" \
    'pub(crate) struct CausalActivationRequest {' \
    'impl EffectRegistry {' "$causal_activation"
extract_between "$source_file" 'const fn same_boot_causal_limits()' \
    'fn new_same_boot_registry()' "$causal_limits"
extract_between "$runtime_causal_file" \
    'pub(crate) struct CausalDomainWorkloadRequest {' \
    'pub(crate) struct CausalDomainWorkloadActivationFailure {' \
    "$causal_domain_request"
extract_between "$runtime_causal_file" \
    '    pub(crate) fn prepare_causal_domain_workload(' \
    '    pub(crate) fn activate_causal_domain_workload(' \
    "$causal_domain_prepare"
extract_between "$runtime_causal_file" \
    '    pub(crate) fn activate_causal_domain_workload(' \
    '    fn validate_causal_domain_workload_activation(' \
    "$causal_domain_activate"
extract_between "$runtime_causal_file" \
    '    fn validate_causal_domain_workload_activation(' \
    '    pub(crate) fn verify_causal_domain_workload_session(' \
    "$causal_domain_validate"
extract_between "$runtime_causal_file" \
    '    pub(crate) fn verify_causal_domain_workload_session(' \
    '    fn validate_causal_domain_workload_close(' \
    "$causal_domain_verify"
extract_between "$runtime_causal_file" \
    '    fn validate_causal_domain_workload_close(' \
    '    pub(crate) fn close_causal_domain_workload(' \
    "$causal_domain_close_validate"
extract_between "$runtime_causal_file" \
    '    pub(crate) fn close_causal_domain_workload(' \
    '    pub(crate) fn prepare_close_causal_workload(' \
    "$causal_domain_close"
extract_between "$runtime_causal_file" \
    'pub(crate) struct CausalWorkloadCloseIntent {' \
    'impl CausalWorkloadSession {' "$causal_close_intent"
extract_between "$runtime_causal_file" \
    'pub(crate) fn prepare_close_causal_workload(' \
    'fn validate_causal_workload_close_binding(' "$causal_close_prepare"
extract_between "$runtime_causal_file" \
    'fn validate_prepared_causal_workload_close(' \
    'fn apply_close_causal_workload(' "$causal_close_validate"
extract_between "$runtime_causal_file" \
    'fn apply_close_causal_workload(' \
    'pub(crate) fn acknowledge_publication_close_causal_workload_and_revoke_complete_with_apply<' \
    "$causal_close_apply"
extract_between "$runtime_causal_file" \
    'pub(crate) fn acknowledge_publication_close_causal_workload_and_revoke_complete_with_apply<' \
    'pub(crate) fn close_causal_workload(' "$causal_combined_close"
extract_between "$runtime_causal_file" \
    'pub(crate) fn close_causal_workload(' \
    '#[cfg(test)]' "$causal_standalone_close"
extract_between "$infrastructure_root_file" \
    'pub(in super::super) fn prepare_workload_close(' \
    'pub(in super::super) fn prepare_historical_workload_close(' \
    "$infrastructure_close_prepare"
extract_between "$infrastructure_root_file" \
    'pub(in super::super) fn validate_workload_close_intent(' \
    'pub(in super::super) fn apply_workload_close(' \
    "$infrastructure_close_validate"
extract_between "$infrastructure_root_file" \
    'pub(in super::super) fn apply_workload_close(' \
    'pub(in super::super) fn close_workload(' "$infrastructure_close_apply"
extract_between "$infrastructure_root_file" \
    '    pub(in super::super) fn open_child_workload(' \
    '    fn apply_child_workload_open(' "$infrastructure_child_open"
extract_between "$infrastructure_root_file" \
    '    fn apply_child_workload_open(' \
    '    pub(in super::super) fn open_workload(' "$infrastructure_child_apply"
extract_between "$infrastructure_root_file" \
    '    pub(in super::super) fn prepare_historical_workload_close(' \
    '    pub(in super::super) fn validate_workload_close_intent(' \
    "$infrastructure_historical_close"
extract_between "$infrastructure_root_file" \
    'pub(in super::super) fn prepare_closure_finish_after_workload_close(' \
    'pub(in super::super) fn apply_closure_finish(' "$infrastructure_projected_finish"
extract_between "$effect_registry_file" \
    'fn prepare_revoke_complete_apply(' \
    'fn apply_revoke_complete(&mut self, plan: RevokeCompleteApplyPlan)' \
    "$registry_revoke_prepare"
extract_between "$source_file" 'enum FsDeviceAdapterPhase {' \
    'enum FsDeviceAdapterTransitionError {' "$adapter_phase"

# RFC 0001 accepts one root, one production Registry, and one ledger. The
# legacy in-memory filesystem Registry may remain in the non-facade build, but
# it may not be instantiated in the accepted same-boot build.
require_count "$runtime" 'registry: EffectRegistry,' 1
require_count "$runtime" 'causal: FsCausalAdapterSlot,' 1
require_count "$runtime" 'flight: FsDeviceFlight,' 1
require_count "$runtime" 'next_flight_cookie: NonZeroU64,' 1
require_count "$runtime_impl" 'registry: new_same_boot_registry(),' 1
require_count "$runtime_impl" 'causal: FsCausalAdapterSlot::new(),' 1
reject_fixed "$flight" 'CausalWorkloadSession'
require_regex_count "$causal_slot" '^[[:space:]]+Vacant,$' 1
require_regex_count "$causal_slot" \
    '^[[:space:]]+Active\(CausalWorkloadSession\),$' 1
require_regex_count "$causal_slot" \
    '^[[:space:]]+Closed\(CausalWorkloadIdentity\),$' 1
require_count "$causal_slot" 'struct FsCausalActivationReservation' 1
reject_regex "$causal_slot" '(^|[^_])assert!\('
require_count "$causal_session" 'pub(super) context: infrastructure::WorkloadContext,' 2
require_count "$causal_session" \
    'pub(super) const fn infrastructure_context(&self) -> &infrastructure::WorkloadContext {' 1
reject_fixed "$causal_session" \
    'pub(crate) const fn infrastructure_context(&self) -> &infrastructure::WorkloadContext {'
causal_session_line=$(line_of_unique "$runtime_causal_file" \
    'pub(crate) struct CausalWorkloadSession {')
causal_session_derive=$(sed -n "$((causal_session_line - 1))p" \
    "$runtime_causal_file")
[[ $causal_session_derive == \
    '#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]' ]] ||
    fail 'CausalWorkloadSession gained Clone/Copy or lost its frozen derive set'
causal_domain_session_line=$(line_of_unique "$runtime_causal_file" \
    'pub(crate) struct CausalDomainWorkloadSession {')
causal_domain_session_derive=$(sed -n "$((causal_domain_session_line - 1))p" \
    "$runtime_causal_file")
[[ $causal_domain_session_derive == \
    '#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]' ]] ||
    fail 'CausalDomainWorkloadSession gained Clone/Copy or lost its frozen derive set'
require_count "$causal_activation" 'request: CausalActivationRequest,' 1
require_count "$causal_activation" 'into_input(self) -> CausalActivationRequest' 1
require_count "$causal_activation" \
    'into_parts(self) -> (CausalWorkloadError, CausalActivationRequest)' 1
require_count "$causal_limits" \
    'CausalWorkloadLimits::new(8, 2, 8, 2, 2, 8, 4, 4, 4, 12, 12, 128)' 1

# The provider-neutral child-workload foundation is intentionally not wired to
# the filesystem adapter yet. It still freezes the linear authority boundary,
# authoritative binding capture, exact activation fences, parent accounting,
# and cleanup-only historical epoch rule in the production core sources.
require_count "$runtime_causal_file" '    workloads: u32,' 1
require_count "$runtime_causal_file" \
    '    pub(crate) const fn with_workload_capacity(mut self, workloads: u32) -> Self {' 1
for required in \
    'registry_instance: u64,' \
    'registry_scope_revision: u64,' \
    'infrastructure_scope_revision: u64,' \
    'domain_revision: u64,' \
    'parent: CausalWorkloadIdentity,' \
    'domain: DomainKey,' \
    'binding_epoch: u64,' \
    'request_id: u64,' \
    'request_generation: u64,'; do
    require_count "$causal_domain_request" "$required" 1
done
require_count "$causal_domain_prepare" \
    'let parent_identity = self.verify_causal_workload_session(parent)?;' 1
require_count "$causal_domain_prepare" '.domains' 1
require_count "$causal_domain_prepare" '.get(&target_domain)' 1
require_count "$causal_domain_prepare" 'domain_revision: binding.revision,' 1
require_count "$causal_domain_prepare" 'binding_epoch: binding.binding_epoch,' 1
reject_fixed "$causal_domain_prepare" 'binding_epoch: u64'
require_count "$causal_domain_activate" \
    'self.validate_causal_domain_workload_activation(parent, target_domain, &request)' 1
require_count "$causal_domain_activate" \
    'let context = match self.infrastructure.open_child_workload(' 1
require_count "$causal_domain_activate" \
    'return Err(CausalDomainWorkloadActivationFailure {' 2
require_count "$causal_domain_validate" \
    'if request.registry_instance != self.instance_id {' 1
require_count "$causal_domain_validate" \
    'if target_domain != request.domain {' 1
require_count "$causal_domain_validate" \
    'if parent_identity != request.parent {' 1
require_count "$causal_domain_validate" \
    'binding.binding_epoch != request.binding_epoch' 1
require_count "$causal_domain_validate" \
    'binding.revision != request.domain_revision' 1
require_count "$causal_domain_validate" \
    'scope.revision != request.registry_scope_revision' 1
require_count "$causal_domain_validate" \
    'infrastructure.revision != request.infrastructure_scope_revision' 1
require_count "$causal_domain_verify" \
    'if binding.binding_epoch != identity.binding_epoch {' 1
require_count "$causal_domain_verify" \
    '.describe_open_workload(&session.context)' 1
require_count "$causal_domain_close_validate" \
    'if binding.binding_epoch < identity.binding_epoch {' 1
require_count "$causal_domain_close_validate" \
    '.describe_closable_workload(&session.context)' 1
require_count "$causal_domain_close" \
    '.prepare_historical_workload_close(&session.context)' 1
require_count "$causal_domain_close" \
    '.apply_workload_close(intent, &session.context);' 1
require_count "$infrastructure_child_open" 'target_domain: DomainKey,' 1
reject_fixed "$infrastructure_child_open" 'binding_epoch'
require_count "$infrastructure_child_apply" \
    'parent.live_children.checked_add(1)' 1
require_count "$infrastructure_child_apply" \
    'parent.live_children = next_parent_live_children;' 1
require_count "$infrastructure_child_apply" \
    'scope.workloads.install_vacant_prevalidated(record);' 1
require_count "$infrastructure_child_apply" \
    'scope.reverse_indexes.install_vacant_prevalidated(index);' 1
require_count "$infrastructure_mod_file" \
    '    next_parent_live_children: Option<u32>,' 1
require_count "$infrastructure_close_apply" \
    'if let ParentStamp::Request(parent_request) = intent.mint.parent {' 1
require_count "$infrastructure_close_apply" \
    'parent.live_children.checked_sub(1)' 1
require_count "$infrastructure_historical_close" \
    'validate_recovery_context(scope, self.registry_instance, context)?;' 1
reject_fixed "$infrastructure_historical_close" 'validate_context('

# The core Registry now owns an exact two-phase causal close transaction. Both
# close intents are opaque, linear values: preparation is read-only and every
# ordinary combined failure returns the exact intent/session before any
# external callback can run.
causal_close_intent_line=$(line_of_unique "$runtime_causal_file" \
    'pub(crate) struct CausalWorkloadCloseIntent {')
causal_close_intent_derive=$(sed -n "$((causal_close_intent_line - 1))p" \
    "$runtime_causal_file")
[[ $causal_close_intent_derive == \
    '#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]' ]] ||
    fail 'CausalWorkloadCloseIntent gained Clone/Copy or lost its frozen derive set'
combined_close_failure_line=$(line_of_unique "$runtime_causal_file" \
    'pub(crate) struct CausalCombinedCloseFailure {')
combined_close_failure_derive=$(sed -n "$((combined_close_failure_line - 1))p" \
    "$runtime_causal_file")
[[ $combined_close_failure_derive == \
    '#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]' ]] ||
    fail 'CausalCombinedCloseFailure gained Clone/Copy or lost its frozen derive set'
workload_close_intent_line=$(line_of_unique "$infrastructure_mod_file" \
    'pub(super) struct WorkloadCloseIntent {')
workload_close_intent_derive=$(sed -n "$((workload_close_intent_line - 1))p" \
    "$infrastructure_mod_file")
[[ $workload_close_intent_derive == \
    '#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]' ]] ||
    fail 'WorkloadCloseIntent gained Clone/Copy or lost its frozen derive set'
require_count "$causal_close_intent" 'identity: CausalWorkloadIdentity,' 1
require_count "$causal_close_intent" 'root: PortalHandle,' 1
require_count "$causal_close_intent" 'registry_scope_revision: u64,' 1
require_count "$causal_close_intent" \
    'infrastructure: infrastructure::WorkloadCloseIntent,' 1
require_count "$causal_close_prepare" '&self,' 1
reject_fixed "$causal_close_prepare" '&mut self'
require_count "$causal_close_prepare" \
    'Result<(CausalWorkloadCloseIntent, CausalWorkloadSession), CausalWorkloadCloseFailure>' 1
require_count "$causal_close_prepare" \
    'self.validate_causal_workload_close_binding(session.identity)' 1
require_count "$causal_close_prepare" \
    'self.infrastructure.prepare_workload_close(&session.context)' 1
require_count "$causal_close_prepare" \
    'Err(error) => return Err(CausalWorkloadCloseFailure { error, session }),' 1
require_count "$causal_close_prepare" \
    'error: CausalWorkloadError::Infrastructure(error),' 1
require_count "$causal_close_validate" 'if intent.identity != session.identity {' 1
require_count "$causal_close_validate" \
    'if root != intent.root || registry_scope_revision != intent.registry_scope_revision {' 1
require_count "$causal_close_validate" \
    '.validate_workload_close_intent(&intent.infrastructure, Some(&session.context))' 1
require_count "$causal_close_apply" '&mut self,' 1
require_count "$causal_close_apply" ') -> CausalWorkloadIdentity {' 1
reject_fixed "$causal_close_apply" 'Result<'
reject_fixed "$causal_close_apply" 'validate_workload_close_intent'
require_count "$causal_close_apply" \
    '.apply_workload_close(intent.infrastructure, &session.context);' 1

# One and only one failure-only preflight precedes the external boundary. The
# ticket binds the causal root, the selector binds its scope/closed authority,
# and projected root finish consumes the exact infrastructure intent.
for required in \
    'ticket.scope != identity.scope' \
    'ticket.effect != identity.root_effect' \
    'selection.scope != identity.scope' \
    'selection.closed_authority_epoch != identity.authority_epoch' \
    'self.prepare_publication_ack(ticket)' \
    'self.prepare_revoke_complete_apply(' \
    'Some(&intent.infrastructure),' \
    'let applied = apply_external();' \
    'self.apply_publication_ack(publication);' \
    'let identity = self.apply_close_causal_workload(intent, session);' \
    'self.apply_revoke_complete(revoke);'; do
    require_count "$causal_combined_close" "$required" 1
done
require_count "$causal_combined_close" \
    'return Err(CausalCombinedCloseFailure {' 4
require_count "$causal_combined_close" 'apply_external()' 1
require_order "$causal_combined_close" \
    'self.validate_prepared_causal_workload_close(&intent, &session)' \
    'if ticket.scope != identity.scope' \
    'let publication = match self.prepare_publication_ack(ticket)' \
    'let revoke = match self.prepare_revoke_complete_apply(' \
    'let applied = apply_external();' \
    'self.apply_publication_ack(publication);' \
    'let identity = self.apply_close_causal_workload(intent, session);' \
    'self.apply_revoke_complete(revoke);'

# The infrastructure preflight validates the complete live-child/revision
# projection and the apply phase only installs those exact precomputed values.
require_count "$infrastructure_close_prepare" '&self,' 1
reject_fixed "$infrastructure_close_prepare" '&mut self'
for required in \
    'check_scope_invariants(scope)?;' \
    'validate_context(scope, self.registry_instance, context)?;' \
    'if record.live_children != 0 {' \
    'let next_revision = preview_revision(scope)?;' \
    'let next_live_workloads = checked_sub(scope.live.workloads, 1)?;' \
    'base_revision: scope.revision,'; do
    require_count "$infrastructure_close_prepare" "$required" 1
done
for required in \
    'check_scope_invariants(scope)?;' \
    'validate_context(scope, self.registry_instance, context)?;' \
    'scope.revision != intent.base_revision' \
    'preview_revision(scope)? != intent.next_revision' \
    'checked_sub(scope.live.workloads, 1)? != intent.next_live_workloads'; do
    require_count "$infrastructure_close_validate" "$required" 1
done
reject_fixed "$infrastructure_close_apply" 'Result<'
reject_fixed "$infrastructure_close_apply" 'validate_workload_close_intent'
require_order "$infrastructure_close_apply" \
    '.phase = WorkloadPhase::Closed;' \
    'scope.live.workloads = intent.next_live_workloads;' \
    'scope.revision = intent.next_revision;' \
    'InfrastructureEventKind::WorkloadClosed,'
for required in \
    'self.validate_workload_close_intent(close, None)?;' \
    'close.mint.root.scope != selection.scope' \
    'close.mint.root.authority_epoch != selection.authority_epoch' \
    'close.mint.root.root_effect != record.root.root_effect' \
    'live.workloads = close.next_live_workloads;' \
    '.next_revision' \
    '.checked_add(1)' \
    'first_live_obligation_counts(projected_live)'; do
    require_at_least "$infrastructure_projected_finish" "$required" 1
done
for required in \
    'projected_workload_close: Option<&infrastructure::WorkloadCloseIntent>,' \
    'self.validate_revoke_selection(selection)?;' \
    '.next_scope_revision' \
    '.checked_add(1)' \
    'members_checked = members_checked' \
    '.prepare_closure_finish_after_workload_close(' \
    'projected workload close lacks infrastructure closure'; do
    require_at_least "$registry_revoke_prepare" "$required" 1
done
reject_fixed "$registry_revoke_prepare" 'apply_closure_finish('

# The compatibility helper remains workload-only. It cannot install a root
# receipt or advance the business scope out of Closing by itself.
require_count "$causal_standalone_close" \
    'match self.prepare_close_causal_workload(session)' 1
require_count "$causal_standalone_close" \
    'Ok((intent, session)) => Ok(self.apply_close_causal_workload(intent, session)),' 1
reject_fixed "$causal_standalone_close" 'apply_revoke_complete'
reject_fixed "$causal_standalone_close" 'apply_closure_finish'
reject_fixed "$causal_standalone_close" 'apply_publication_ack'
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

# The sibling adapter is the sole production implementation/call edge for the
# provider-neutral receipt vocabulary. Fully qualified inherent calls prevent
# same-name trait methods from accidentally recursing.
for trait_impl in \
    'impl DevicePreparedReceiptView for PreparationReceipt {' \
    'impl DeviceRollbackReceiptView for PreparationRollbackReceipt {' \
    'impl DeviceIndeterminateReceiptView for PreparationIndeterminate {' \
    'impl DeviceClosureReceiptView for ProductionClosureReceipt {'; do
    require_count "$adapter_file" "$trait_impl" 1
done
require_count "$adapter_file" 'PreparationReceipt::' 11
require_count "$adapter_file" 'PreparationRollbackReceipt::' 10
require_count "$adapter_file" 'PreparationIndeterminate::' 5
require_count "$adapter_file" 'ProductionClosureReceipt::' 8
reject_regex "$adapter_file" 'self\.[A-Za-z_][A-Za-z0-9_]*\('
for trait_definition in \
    'pub(crate) trait DevicePreparedReceiptView {' \
    'pub(crate) trait DeviceRollbackReceiptView {' \
    'pub(crate) trait DeviceIndeterminateReceiptView {' \
    'pub(crate) trait DeviceClosureReceiptView {'; do
    require_count "$registry_file" "$trait_definition" 1
done
for concrete_type in \
    nexus_ostd_virtio \
    PreparationReceipt \
    PreparationRollbackReceipt \
    PreparationIndeterminate \
    ProductionClosureReceipt; do
    reject_fixed "$receipt_bridge_file" "$concrete_type"
done
require_count "$adapter_file" \
    'registry.acknowledge_device_prepared_from_view(intent, receipt)' 1
require_count "$adapter_file" \
    'registry.acknowledge_device_rollback_from_view(intent, receipt)' 1
require_count "$adapter_file" \
    'registry.retain_device_indeterminate_from_view(intent, observation)' 1
require_count "$adapter_file" \
    'registry.install_materialized_device_closure_from_view(ticket, registry_closure, closure)' 1
require_count "$source_file" 'crate::virtio_cser_adapter::acknowledge_prepared(' 1
require_count "$source_file" 'crate::virtio_cser_adapter::acknowledge_rollback(' 1
require_count "$source_file" 'crate::virtio_cser_adapter::retain_indeterminate(' 1
require_count "$source_file" 'crate::virtio_cser_adapter::install_materialized_closure(' 1
for core_entry in \
    acknowledge_device_prepared_from_view \
    acknowledge_device_rollback_from_view \
    retain_device_indeterminate_from_view \
    install_materialized_device_closure_from_view; do
    reject_fixed "$source_file" "$core_entry"
done

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
    'Reserved {' \
    'PreparationApplying {' \
    'PreparedPendingAck {' \
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
for phase in \
    Vacant Reserved Applying PreparedPendingAck Prepared MaterializedUnpublished Published \
    Closing ClosureInstalledDrainPending Released IndeterminateRetained; do
    require_regex_count "$adapter_phase" "^[[:space:]]+$phase,$" 1
done
require_count "$runtime" 'adapter_phase: FsDeviceAdapterPhase,' 1
require_count "$runtime" \
    'materialized_authority: MaterializedAuthoritySlot,' 1
require_count "$source_file" 'enum MaterializedAuthoritySlot {' 1
for required in \
    'Active(MaterializedDeviceTicket),' \
    'RetainedConflict {' \
    'fn install(' \
    'fn take(&mut self) -> Result<MaterializedDeviceTicket, MaterializedAuthorityTakeError>' \
    'MaterializedAuthorityInstallError::Saturated(authority)' \
    'FsRuntimeCompletionError::MaterializedAuthorityRetained'; do
    require_at_least "$source_file" "$required" 1
done
require_count "$runtime_impl" \
    'core::mem::replace(&mut self.flight, FsDeviceFlight::Transitioning)' 1
require_count "$runtime_impl" 'debug_assert!(matches!(self.flight, FsDeviceFlight::Transitioning));' 1
reject_regex "$runtime_impl" '^[[:space:]]*assert!\(matches!\(self\.flight, FsDeviceFlight::Transitioning\)\);'
reject_fixed "$runtime_impl" 'check_invariants()'
require_at_least "$runtime_impl" 'self.put_flight(' 3
require_at_least "$runtime_impl" 'FsDeviceFlight::Retained {' 1
require_count "$runtime_impl" \
    'self.adapter_phase = FsDeviceAdapterPhase::IndeterminateRetained;' 3
require_count "$runtime_impl" \
    ') -> Result<(), FsDeviceAdapterTransitionError> {' 3
reject_fixed "$runtime_impl" 'panic!("device adapter cannot enter Closing'
reject_regex "$runtime_impl" '^[[:space:]]*assert(_eq)?!\(self\.adapter_phase'
for forbidden in \
    'unreachable!()' \
    '.expect("prevalidated owner-bound publish intent")' \
    '.expect("recovered close did not consume fresh publish intent")' \
    '.expect("materialized device authority survives until IOTLB closure")' \
    '.expect("prevalidated cancel intent is consumed once")' \
    '.expect("prevalidated completion reset is consumed once")' \
    '.expect("prevalidated failed-completion reset is consumed once")' \
    '.expect("prevalidated published reset is consumed once")'; do
    reject_fixed "$dispatch" "$forbidden"
    reject_fixed "$closure_driver" "$forbidden"
done
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

# The first executable pread is a real cross-task request. Capture installs the
# syscall flight, then the guest drops every Registry/service guard before it
# publishes the blocking receipt.  QueuedUnannounced prevents fsd-v1 from
# consuming the request until that no-lock receipt has been emitted; the sticky
# waiter then preserves a wake between admission and wait().
require_count "$capture" 'runtime.registry.register_derived(' 1
require_count "$capture" 'task: GUEST,' 1
require_count "$capture" 'domain: PERSONALITY_DOMAIN,' 1
require_count "$capture" '.prepare(PERSONALITY_V1, syscall.handle)' 1
require_count "$capture" 'prepare_causal_workload_activation(' 1
require_count "$capture" 'activate_causal_workload(activation)' 1
require_count "$capture" 'reservation.install(session);' 1
require_order "$capture" \
    'runtime.registry.register_derived(' \
    '.prepare(PERSONALITY_V1, syscall.handle)' \
    'prepare_causal_workload_activation(' \
    'activate_causal_workload(activation)' \
    'reservation.install(session);' \
    'syscall: syscall.clone(),'
require_count "$capture" \
    'return Err(DispatchOutcome::retained(identity.request_id()));' 1
reject_fixed "$capture" \
    'stage=causal_slot_not_vacant error={:?}'
require_count "$source_file" 'QueuedUnannounced,' 1
require_count "$source_file" 'self.phase = FsServicePhase::QueuedUnannounced;' 1
require_count "$source_file" 'fn arm_queued(&mut self) {' 1
require_count "$service_next" 'if service.phase != FsServicePhase::Queued {' 1
require_count "$guest_wait" '.enqueue_unannounced(descriptor, cookie, waker);' 1
require_count "$guest_wait" 'self.require_same_boot_causal_session(cookie)' 1
require_count "$guest_wait" 'self.service.lock().arm_queued();' 1
require_count "$guest_wait" 'waiter.wait();' 1
require_count "$guest_wait" 'self.service.lock().take_outcome()' 1
require_order "$guest_wait" \
    'self.require_same_boot_causal_session(cookie)' \
    '.enqueue_unannounced(descriptor, cookie, waker);' \
    'all_locks_released=true reply_wakeups=0' \
    'self.service.lock().arm_queued();' \
    'waiter.wait();' \
    'self.service.lock().take_outcome()'
reject_fixed "$guest_wait" 'self.production.lock()'
reject_fixed "$guest_wait" 'let service = self.service.lock()'
reject_fixed "$guest_wait" 'let mut service = self.service.lock()'

# fsd-v1 owns the Registry supervisor TaskKey. It registers and prepares the
# one filesystem descendant before any block/DMA member exists.
require_count "$service_next" 'assert_eq!(sender, FILESYSTEM_V1);' 1
require_count "$service_next" '.register_derived(DerivedRegisterRequest {' 1
require_count "$service_next" 'task: sender,' 1
require_count "$service_next" 'domain: FILESYSTEM_DOMAIN,' 1
require_count "$service_next" 'parent: Some(syscall.identity.effect()),' 1
require_at_least "$service_next" '.domain_projection(SCOPE, BLOCK_DOMAIN)' 1
require_count "$service_next" '.live_effects,' 1
require_count "$service_next" 'service.phase = FsServicePhase::Registered;' 1
require_count "$service_prepare" 'assert_eq!(sender, FILESYSTEM_V1);' 1
require_count "$service_prepare" '.prepare(sender, filesystem.handle)' 1
require_count "$service_prepare" 'assert_eq!(view.phase, EffectPhase::Prepared);' 1
require_at_least "$service_prepare" '.domain_projection(SCOPE, BLOCK_DOMAIN)' 1
require_count "$service_prepare" 'FsDeviceFlight::Captured { .. }' 1
require_count "$service_prepare" 'self.service.lock().phase = FsServicePhase::Prepared;' 1

# fsd-v1 itself queues the typed delayed command before the fault.  Delivery is
# a later recovery action; it does not manufacture the old sender at that time.
require_count "$service_queue" 'assert_eq!(sender, FILESYSTEM_V1);' 1
require_count "$service_queue" 'DelayedPrepareCommand { sender, handle }' 1
require_count "$service_queue" 'service.delayed_prepare = Some(' 1
require_count "$service_queue" 'delivery=after_rebind' 1
require_count "$fsd_v1_runner" 'scenario.fsd_queue_old_prepare(sender);' 1
require_order "$fsd_v1_runner" \
    'FSD_PREPARE => {' \
    'scenario.fsd_prepare_active(sender);' \
    'FSD_QUEUE_OLD_PREPARE => {' \
    'scenario.fsd_queue_old_prepare(sender);' \
    'Some(CpuException::PageFault(info)) => info,'

# The real user page fault is the only fsd-v1 terminal boundary. Registry crash
# sees exactly the prepared filesystem effect, no device cohort, and no reply.
for required in \
    'assert_eq!(service.phase, FsServicePhase::Prepared);' \
    'assert!(service.outcome.is_none());' \
    'assert_eq!(service.reply_wakeups, 0);' \
    '.domain_projection(SCOPE, BLOCK_DOMAIN)' \
    'FsDeviceFlight::Captured { .. }' \
    '.crash_domain(SCOPE, FILESYSTEM_DOMAIN, sender)' \
    'assert_eq!(crash.cohort.len(), 1);' \
    'assert!(crash.cohort.contains(&filesystem.identity.effect()));' \
    'self.service.lock().phase = FsServicePhase::Crashed;' \
    'device_committed=false guest_reply=false'; do
    require_at_least "$service_crash" "$required" 1
done
require_count "$fsd_v1_runner" 'Some(CpuException::PageFault(info)) => info,' 1
require_count "$fsd_v1_runner" 'assert_eq!(info.addr, EXPECTED_FSD_FAULT);' 1
require_count "$fsd_v1_runner" 'scenario.crash_fsd_v1(sender);' 1
require_count "$fsd_v1_runner" 'task_generation={}' 1
require_order "$fsd_v1_runner" \
    'Some(CpuException::PageFault(info)) => info,' \
    'assert_eq!(info.addr, EXPECTED_FSD_FAULT);' \
    'scenario.crash_fsd_v1(sender);' \
    'reason=real_user_page_fault' \
    'done.wake_up();' \
    'return;'

# fsd-v2 follows the typed Registry recovery protocol and adopts the exact old
# handle before either a stale mutation attempt or device work can proceed.
for required in \
    '.domain_recovery_snapshot(SCOPE, FILESYSTEM_DOMAIN, sender, 1)' \
    '.domain_ready(SCOPE, FILESYSTEM_DOMAIN, sender, &snapshot)' \
    '.rebind_domain(SCOPE, FILESYSTEM_DOMAIN, sender)' \
    '.recover_next_domain(SCOPE, FILESYSTEM_DOMAIN, sender)' \
    '.adopt_domain(SCOPE, FILESYSTEM_DOMAIN, sender, old_handle)' \
    'assert_eq!(snapshot.effects.len(), 1);' \
    'assert_eq!(snapshot.effects[0].phase, EffectPhase::Prepared);' \
    'service.phase = FsServicePhase::Adopted;'; do
    require_at_least "$service_recovery" "$required" 1
done
require_order "$service_recovery" \
    'fn fsd_recovery_snapshot(&self, sender: TaskKey)' \
    'fn fsd_recovery_ready(&self, sender: TaskKey)' \
    'fn fsd_recovery_rebind(&self, sender: TaskKey)' \
    'fn fsd_adopt_next(&self, sender: TaskKey)'

# Delivery presents both halves of the queued v1 identity.  The old handle is
# StaleBinding after adoption; the same old sender paired with the current
# adopted handle is NoSupervisor.  Both mutating attempts preserve the complete
# Registry and service projections.
require_count "$service_stale" 'let mut runtime = self.production.lock();' 1
require_count "$service_stale" 'runtime.registry.failure_atomic_projection();' 3
require_count "$service_stale" \
    'runtime.registry.prepare(command.sender, command.handle),' 1
require_count "$service_stale" \
    'runtime.registry.prepare(command.sender, adopted_handle),' 1
require_count "$service_stale" 'Err(RegistryError::StaleBinding),' 1
require_count "$service_stale" 'Err(RegistryError::NoSupervisor),' 1
require_count "$service_stale" 'assert_eq!(after_old_handle, before_registry);' 1
require_count "$service_stale" 'assert_eq!(after_old_sender, before_registry);' 1
require_count "$service_stale" 'assert_eq!(after_service, before_service);' 1
require_at_least "$service_stale" \
    'queued_generation={} action=Prepare' 1
reject_fixed "$service_stale" 'runtime.registry.descriptor('

# Device execution is admitted only after Adopted plus the stale replay fence.
# fsd-v2 installs one outcome and consumes one response waker outside its lock.
require_count "$service_execute" 'assert_eq!(service.phase, FsServicePhase::Adopted);' 2
require_count "$service_execute" 'assert!(service.stale_replay_observed);' 1
require_count "$service_execute" 'self.execute_recovered_first_pread_same_boot(' 1
require_count "$service_publish" 'assert_eq!(service.phase, FsServicePhase::Executed);' 1
require_count "$service_publish" 'assert_eq!(service.reply_wakeups, 0);' 1
require_count "$service_publish" 'service.phase = FsServicePhase::ReplyReady;' 1
require_count "$service_publish" 'service.reply_wakeups = 1;' 1
require_count "$service_publish" '.response_waker' 2
require_count "$service_publish" '.take()' 1
require_count "$service_publish" 'waker.wake_up();' 1
require_order "$service_publish" \
    'fn fsd_publish_response(&self)' \
    'assert_eq!(service.reply_wakeups, 0);' \
    'service.reply_wakeups = 1;' \
    '.expect("one blocked runtime-fs guest continuation")' \
    'all_locks_released=true' \
    'waker.wake_up();' \
    'fn fsd_service_done(&self)'

# The OSTD runners carry the complete TaskKey in TaskData; their portal sender is
# derived from Task::current(), not filled in by a closure constant.  The v2 VM,
# continuation, and Task are all constructed only after v1's crash receipt.
require_count "$source_file" 'const FILESYSTEM_V1: TaskKey = TaskKey::new(951, 1);' 1
require_count "$source_file" 'const FILESYSTEM_V2: TaskKey = TaskKey::new(951, 2);' 1
require_count "$lib_file" 'pub(crate) cser_task: Option<TaskKey>,' 1
require_count "$lib_file" 'pub(crate) fn new_cser(task: TaskKey, vm_space: Option<Arc<VmSpace>>) -> Self {' 1
require_count "$lib_file" 'cser_task: Some(task),' 1
require_count "$fsd_task_identity" '.cser_task' 1
require_count "$fsd_task_identity" 'assert_eq!(task, expected);' 1
require_count "$fsd_task_identity" 'assert_eq!(data.id, task.id());' 1
require_count "$fsd_task_identity" 'Arc::ptr_eq(active, vm_space)' 1
require_count "$fsd_v1_runner" 'let sender = current_fsd_task(FILESYSTEM_V1, &vm_space);' 1
require_count "$fsd_v2_runner" 'let sender = current_fsd_task(FILESYSTEM_V2, &vm_space);' 1
require_count "$fsd_v2_runner" 'scenario.fsd_deliver_old_prepare(sender);' 1
for required in \
    'assert!(!Arc::ptr_eq(&v1_vm, &v2_vm));' \
    'TaskOptions::new(move || run_fsd_v1(task_scenario, task_vm, v1_waker))' \
    '.data(TaskData::new_cser(FILESYSTEM_V1, Some(data_vm)))' \
    'TaskOptions::new(move || run_fsd_v2(task_scenario, task_vm, v2_waker))' \
    '.data(TaskData::new_cser(FILESYSTEM_V2, Some(data_vm)))' \
    'assert!(!Arc::ptr_eq(&v1_task, &v2_task));' \
    'v1_waiter.wait();' \
    'assert_eq!(scenario.service.lock().phase, FsServicePhase::Crashed);' \
    'v2_task.run();' \
    'v2_waiter.wait();' \
    'scenario.service.lock().assert_complete();' \
    'device_commit_gate_after_rebind=true device_committed_after_rebind=true' \
    'device_commit_gate_after_rebind=true device_committed_after_rebind=false'; do
    require_at_least "$run_slice" "$required" 1
done
require_order "$run_slice" \
    'v1_waiter.wait();' \
    'assert_eq!(scenario.service.lock().phase, FsServicePhase::Crashed);' \
    'let v2_vm = Arc::new(create_vm_space(FSD_V2_PROGRAM));' \
    'let (v2_waiter, v2_waker) = EffectWaiter::new_pair(EffectToken {' \
    'TaskOptions::new(move || run_fsd_v2(task_scenario, task_vm, v2_waker))' \
    '.data(TaskData::new_cser(FILESYSTEM_V2, Some(data_vm)))' \
    'LINUX_FS_SERVICE FreshSpawn' \
    'v2_task.run();' \
    'v2_waiter.wait();'

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
reject_fixed "$dispatch" 'runtime.registry.register_derived('
require_count "$dispatch" \
    'runtime.registry.materialize_device_cohort_from_preparation(' 1
require_count "$dispatch" '.enroll_device_batch(' 1
require_count "$dispatch" \
    'mint_device_flight_key(&runtime.registry, &enrollment, cookie)' 1
require_count "$dispatch" 'commit_or_recover_device_flight_with_apply(' 1
require_count "$dispatch" 'device.preflight_publish(request, expected)' 1
require_count "$dispatch" \
    'request_slot.take().map(|intent| intent.apply())' 1
reject_fixed "$dispatch" '.expect("prevalidated owner-bound publish intent")'
reject_fixed "$dispatch" 'unreachable!()'
require_at_least "$dispatch" '.apply()' 2
reject_fixed "$dispatch" '.publish_prepared()'
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
require_count "$source_file" 'device.preflight_read_sector0(&mut root)' 1
require_count "$dispatch" \
    'runtime.verify_causal_session(cookie, captured.identity.effect())' 1
require_order "$dispatch" \
    'runtime.verify_causal_session(cookie, captured.identity.effect())' \
    'registry.reserve_device_preparation_for_session(session, coordinates)' \
    'device.preflight_read_sector0(&mut root)' \
    'runtime.registry.begin_device_hardware_apply(reservation)' \
    'let request = match permit.apply()'
reject_fixed "$dispatch" 'close_or_verify_causal_terminal'
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
reject_fixed "$source_file" 'DeviceHardwareReceipt {'
reject_fixed "$source_file" 'DeviceRollbackReceipt {'

# The adapter stores every exact hardware/Registry bearer before the next
# fallible cross-component acknowledgement, then materializes one block and
# three DMA effects. Publication consumes only a prevalidated intent after all
# business Prepare/enrollment work. The materialized bearer survives through
# reset and IOTLB and is consumed only by the coupled closure install before
# leaf draining or frame-credit reuse.
for required in \
    'reserve_device_preparation_for_session(session, coordinates)' \
    'cancel_device_preparation(reservation)' \
    'FsDeviceFlight::PreparationApplying {' \
    'device.issue_preparation_receipt(request)' \
    'FsDeviceFlight::PreparedPendingAck {' \
    'crate::virtio_cser_adapter::acknowledge_prepared(' \
    'runtime.registry.materialize_device_cohort_from_preparation(' \
    '.install(materialized.authority)' \
    'device.preflight_publish(request, expected)' \
    'request_slot' \
    'request_slot.take().map(|intent| intent.apply())' \
    '.apply()'; do
    require_at_least "$dispatch" "$required" 1
done
require_count "$dispatch" \
    'runtime.put_flight(FsDeviceFlight::PreparedPendingAck {' 2
require_order "$dispatch" \
    'registry.reserve_device_preparation_for_session(session, coordinates)' \
    'device.preflight_read_sector0(&mut root)' \
    'runtime.registry.begin_device_hardware_apply(reservation)' \
    'let request = match permit.apply()' \
    'runtime.put_flight(FsDeviceFlight::PreparationApplying {' \
    'device.issue_preparation_receipt(request)' \
    'let FsDeviceFlight::PreparedPendingAck {' \
    'crate::virtio_cser_adapter::acknowledge_prepared(' \
    'runtime.registry.materialize_device_cohort_from_preparation(' \
    '.install(materialized.authority)' \
    '.enroll_device_batch(authority, &handles, envelope)' \
    'device.preflight_publish(request, expected)' \
    'commit_or_recover_device_flight_with_apply('
require_count "$closure_driver" \
    '.acknowledge_device_iotlb_with_apply(&registry_retry, |_| {' 1
require_at_least "$closure_driver" '.materialized_authority' 2
require_count "$closure_driver" \
    'let materialized = match runtime.materialized_authority.take() {' 1
reject_fixed "$closure_driver" \
    '.expect("materialized device authority survives until IOTLB closure")'
require_count "$closure_driver" \
    'crate::virtio_cser_adapter::install_materialized_closure(' 1
require_at_least "$closure_driver" \
    'runtime.put_flight(FsDeviceFlight::Draining {' 2
require_at_least "$closure_driver" 'next_ordinal: 0,' 1
require_at_least "$closure_driver" \
    'FsDeviceAdapterPhase::ClosureInstalledDrainPending' 2
require_order "$closure_driver" \
    '.acknowledge_device_iotlb_with_apply(&registry_retry, |_| {' \
    'let materialized = match runtime.materialized_authority.take() {' \
    'crate::virtio_cser_adapter::install_materialized_closure(' \
    'LINUX_FS_SAME_BOOT IotlbAck completed_pages=3' \
    '.stage_device_batch_terminal('

# Guest publication is the final cross-object transition. The Registry must
# acknowledge the terminal publication and complete the frozen revoke as one
# failure-atomic operation. The flight remains runtime-resident while all
# checks and the external guest write run; an ordinary rejection writes no
# bytes and prevents the guest from resuming.
require_count "$production_publish" \
    '.acknowledge_publication_and_revoke_complete_with_apply(' 1
require_count "$production_publish" \
    'runtime.close_or_verify_causal_terminal(causal_cookie, root_effect)' 1
require_count "$production_publish" \
    '.prepare_terminal_clear(causal_cookie, root_effect)' 1
require_count "$production_publish" \
    'runtime.causal.apply_terminal_clear(causal_clear);' 1
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
    'let (selection, root_effect) = match &runtime.flight {' \
    'runtime.close_or_verify_causal_terminal(causal_cookie, root_effect)' \
    '.prepare_terminal_clear(causal_cookie, root_effect)' \
    '.acknowledge_publication_and_revoke_complete_with_apply(' \
    'let _mapping_lock = mapping_cursor.as_ref();' \
    'prepared_publication.apply();' \
    '.is_err()' \
    'drop(mapping_cursor);' \
    'drop(preempt_guard);' \
    'let flight = runtime.take_flight();' \
    'runtime.put_flight(FsDeviceFlight::Complete { root, device });' \
    'runtime.causal.apply_terminal_clear(causal_clear);'

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
            "$device_flight_file" "$runtime_causal_file" >/dev/null 2>&1; then
            fail "source gate accepted mutation: $2"
        fi
    }

    require_lib_rejection() {
        if NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 bash "$0" "$source_file" "$1" \
            "$device_flight_file" "$runtime_causal_file" >/dev/null 2>&1; then
            fail "source gate accepted lib mutation: $2"
        fi
    }

    require_semantic_rejection() {
        if NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 bash "$0" "$source_file" "$lib_file" \
            "$1" "$runtime_causal_file" >/dev/null 2>&1; then
            fail "source gate accepted semantic mutation: $2"
        fi
    }

    require_causal_facade_rejection() {
        if NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 bash "$0" "$source_file" "$lib_file" \
            "$device_flight_file" "$1" >/dev/null 2>&1; then
            fail "source gate accepted causal facade mutation: $2"
        fi
    }

    require_infrastructure_root_rejection() {
        if NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 bash "$0" \
            "$source_file" "$lib_file" "$device_flight_file" \
            "$runtime_causal_file" "$1" "$infrastructure_mod_file" \
            "$effect_registry_file" "$adapter_file" "$receipt_bridge_file" \
            >/dev/null 2>&1; then
            fail "source gate accepted infrastructure root mutation: $2"
        fi
    }

    require_infrastructure_mod_rejection() {
        if NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 bash "$0" \
            "$source_file" "$lib_file" "$device_flight_file" \
            "$runtime_causal_file" "$infrastructure_root_file" "$1" \
            "$effect_registry_file" "$adapter_file" "$receipt_bridge_file" \
            >/dev/null 2>&1; then
            fail "source gate accepted infrastructure type mutation: $2"
        fi
    }

    require_effect_registry_rejection() {
        if NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 bash "$0" \
            "$source_file" "$lib_file" "$device_flight_file" \
            "$runtime_causal_file" "$infrastructure_root_file" \
            "$infrastructure_mod_file" "$1" "$adapter_file" \
            "$receipt_bridge_file" >/dev/null 2>&1; then
            fail "source gate accepted Registry mutation: $2"
        fi
    }

    require_adapter_rejection() {
        if NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 bash "$0" \
            "$source_file" "$lib_file" "$device_flight_file" \
            "$runtime_causal_file" "$infrastructure_root_file" \
            "$infrastructure_mod_file" "$effect_registry_file" "$1" \
            "$receipt_bridge_file" >/dev/null 2>&1; then
            fail "source gate accepted VirtIO adapter mutation: $2"
        fi
    }

    require_receipt_bridge_rejection() {
        if NEXUS_SAME_BOOT_SOURCE_PRIMARY_ONLY=1 bash "$0" \
            "$source_file" "$lib_file" "$device_flight_file" \
            "$runtime_causal_file" "$infrastructure_root_file" \
            "$infrastructure_mod_file" "$effect_registry_file" "$adapter_file" \
            "$1" >/dev/null 2>&1; then
            fail "source gate accepted receipt bridge mutation: $2"
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

    awk '
        !changed && /waiter\.wait\(\);/ {
            print "        let _held = self.production.lock();"
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/wait-under-production-lock.rs"
    require_mutation "$source_file" "$work/wait-under-production-lock.rs" \
        wait-under-production-lock
    require_source_rejection "$work/wait-under-production-lock.rs" \
        wait-under-production-lock

    awk '
        /fn crash_fsd_v1\(&self, sender: TaskKey\)/ { service_crash = 1 }
        service_crash && !changed && /\.crash_domain\(/ {
            sub(/\.crash_domain/, ".crash_scope")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/missing-service-crash-domain.rs"
    require_mutation "$source_file" "$work/missing-service-crash-domain.rs" \
        missing-service-crash-domain
    require_source_rejection "$work/missing-service-crash-domain.rs" \
        missing-service-crash-domain

    cp "$source_file" "$work/shared-fsd-vm.rs"
    sed -i \
        '0,/assert!(!Arc::ptr_eq(\&v1_vm, \&v2_vm));/s//assert!(Arc::ptr_eq(\&v1_vm, \&v2_vm));/' \
        "$work/shared-fsd-vm.rs"
    require_mutation "$source_file" "$work/shared-fsd-vm.rs" shared-fsd-vm
    require_source_rejection "$work/shared-fsd-vm.rs" shared-fsd-vm

    cp "$source_file" "$work/shared-fsd-task.rs"
    sed -i \
        '0,/assert!(!Arc::ptr_eq(\&v1_task, \&v2_task));/s//assert!(Arc::ptr_eq(\&v1_task, \&v2_task));/' \
        "$work/shared-fsd-task.rs"
    require_mutation "$source_file" "$work/shared-fsd-task.rs" shared-fsd-task
    require_source_rejection "$work/shared-fsd-task.rs" shared-fsd-task

    awk '
        { lines[NR] = $0 }
        /v1_waiter\.wait\(\);/ { wait_line = NR }
        /let v2_vm = Arc::new\(create_vm_space\(FSD_V2_PROGRAM\)\);/ { vm_line = NR }
        END {
            if (!wait_line || !vm_line || wait_line >= vm_line) exit 2
            swap = lines[wait_line]
            lines[wait_line] = lines[vm_line]
            lines[vm_line] = swap
            for (line = 1; line <= NR; line++) print lines[line]
        }
    ' "$source_file" >"$work/preconstructed-fsd-v2.rs"
    require_mutation "$source_file" "$work/preconstructed-fsd-v2.rs" \
        preconstructed-fsd-v2
    require_source_rejection "$work/preconstructed-fsd-v2.rs" \
        preconstructed-fsd-v2

    cp "$source_file" "$work/early-service-admission.rs"
    sed -i \
        '0,/self\.phase = FsServicePhase::QueuedUnannounced;/s//self.phase = FsServicePhase::Queued;/' \
        "$work/early-service-admission.rs"
    require_mutation "$source_file" "$work/early-service-admission.rs" \
        early-service-admission
    require_source_rejection "$work/early-service-admission.rs" \
        early-service-admission

    cp "$source_file" "$work/closure-minted-fsd-v2-sender.rs"
    sed -i \
        '0,/let sender = current_fsd_task(FILESYSTEM_V2, \&vm_space);/s//let sender = FILESYSTEM_V2;/' \
        "$work/closure-minted-fsd-v2-sender.rs"
    require_mutation "$source_file" "$work/closure-minted-fsd-v2-sender.rs" \
        closure-minted-fsd-v2-sender
    require_source_rejection "$work/closure-minted-fsd-v2-sender.rs" \
        closure-minted-fsd-v2-sender

    cp "$source_file" "$work/unbound-fsd-v2-task-data.rs"
    sed -i \
        '0,/TaskData::new_cser(FILESYSTEM_V2, Some(data_vm))/s//TaskData::new(FILESYSTEM_V2.id(), Some(data_vm))/' \
        "$work/unbound-fsd-v2-task-data.rs"
    require_mutation "$source_file" "$work/unbound-fsd-v2-task-data.rs" \
        unbound-fsd-v2-task-data
    require_source_rejection "$work/unbound-fsd-v2-task-data.rs" \
        unbound-fsd-v2-task-data

    cp "$source_file" "$work/missing-delayed-old-prepare.rs"
    sed -i \
        '0,/scenario\.fsd_queue_old_prepare(sender);/s//let _missing_delayed_prepare = sender;/' \
        "$work/missing-delayed-old-prepare.rs"
    require_mutation "$source_file" "$work/missing-delayed-old-prepare.rs" \
        missing-delayed-old-prepare
    require_source_rejection "$work/missing-delayed-old-prepare.rs" \
        missing-delayed-old-prepare

    cp "$source_file" "$work/read-only-stale-probe.rs"
    sed -i \
        '0,/runtime\.registry\.prepare(command.sender, command.handle)/s//runtime.registry.descriptor(command.sender, command.handle)/' \
        "$work/read-only-stale-probe.rs"
    require_mutation "$source_file" "$work/read-only-stale-probe.rs" read-only-stale-probe
    require_source_rejection "$work/read-only-stale-probe.rs" read-only-stale-probe

    cp "$source_file" "$work/duplicate-reply-wakeup.rs"
    sed -i \
        '0,/service\.reply_wakeups = 1;/s//service.reply_wakeups = 2;/' \
        "$work/duplicate-reply-wakeup.rs"
    require_mutation "$source_file" "$work/duplicate-reply-wakeup.rs" \
        duplicate-reply-wakeup
    require_source_rejection "$work/duplicate-reply-wakeup.rs" \
        duplicate-reply-wakeup

    cp "$source_file" "$work/stale-fsd-v2-task-key.rs"
    sed -i \
        '0,/const FILESYSTEM_V2: TaskKey = TaskKey::new(951, 2);/s//const FILESYSTEM_V2: TaskKey = TaskKey::new(951, 1);/' \
        "$work/stale-fsd-v2-task-key.rs"
    require_mutation "$source_file" "$work/stale-fsd-v2-task-key.rs" \
        stale-fsd-v2-task-key
    require_source_rejection "$work/stale-fsd-v2-task-key.rs" \
        stale-fsd-v2-task-key

    cp "$source_file" "$work/missing-causal-activation.rs"
    sed -i \
        '0,/registry\.activate_causal_workload(activation)/s//registry.skip_causal_workload_activation(activation)/' \
        "$work/missing-causal-activation.rs"
    require_mutation "$source_file" "$work/missing-causal-activation.rs" \
        missing-causal-activation
    require_source_rejection "$work/missing-causal-activation.rs" \
        missing-causal-activation

    cp "$source_file" "$work/missing-causal-device-check.rs"
    sed -i \
        '0,/runtime\.verify_causal_session(cookie, captured\.identity\.effect())/s//runtime.skip_causal_session_check(cookie, captured.identity.effect())/' \
        "$work/missing-causal-device-check.rs"
    require_mutation "$source_file" "$work/missing-causal-device-check.rs" \
        missing-causal-device-check
    require_source_rejection "$work/missing-causal-device-check.rs" \
        missing-causal-device-check

    awk '
        { print }
        /enum FsDeviceFlight \{/ { flight = 1 }
        flight && !changed && /^[[:space:]]*Captured \{/ {
            print "        causal: CausalWorkloadSession,"
            changed = 1
        }
        END { if (!changed) exit 2 }
    ' "$source_file" >"$work/causal-session-in-device-flight.rs"
    require_mutation "$source_file" "$work/causal-session-in-device-flight.rs" \
        causal-session-in-device-flight
    require_source_rejection "$work/causal-session-in-device-flight.rs" \
        causal-session-in-device-flight

    cp "$source_file" "$work/causal-busy-zero-sentinel.rs"
    sed -i \
        '0,/DispatchOutcome::retained(identity\.request_id())/s//DispatchOutcome::retained(0)/' \
        "$work/causal-busy-zero-sentinel.rs"
    require_mutation "$source_file" "$work/causal-busy-zero-sentinel.rs" \
        causal-busy-zero-sentinel
    require_source_rejection "$work/causal-busy-zero-sentinel.rs" \
        causal-busy-zero-sentinel

    awk '
        /#\[derive\(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq\)\]/ {
            candidate = $0
            getline next_line
            if (!changed && next_line ~ /pub\(crate\) struct CausalWorkloadSession \{/) {
                sub(/\)\]$/, ", __cser_core::clone::Clone)]", candidate)
                print candidate
                print next_line
                changed = 1
                next
            }
            print candidate
            print next_line
            next
        }
        {
            print
        }
        END {
            if (!changed) exit 2
        }
    ' "$runtime_causal_file" >"$work/cloneable-causal-session.rs"
    require_mutation "$runtime_causal_file" "$work/cloneable-causal-session.rs" \
        cloneable-causal-session
    require_causal_facade_rejection "$work/cloneable-causal-session.rs" \
        cloneable-causal-session

    awk '
        /#\[derive\(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq\)\]/ {
            candidate = $0
            getline next_line
            if (!changed && next_line ~ /pub\(crate\) struct CausalWorkloadCloseIntent \{/) {
                sub(/\)\]$/, ", __cser_core::clone::Clone)]", candidate)
                print candidate
                print next_line
                changed = 1
                next
            }
            print candidate
            print next_line
            next
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$runtime_causal_file" >"$work/cloneable-causal-close-intent.rs"
    require_mutation "$runtime_causal_file" "$work/cloneable-causal-close-intent.rs" \
        cloneable-causal-close-intent
    require_causal_facade_rejection "$work/cloneable-causal-close-intent.rs" \
        cloneable-causal-close-intent

    awk '
        /#\[derive\(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq\)\]/ {
            candidate = $0
            getline next_line
            if (!changed && next_line ~ /pub\(super\) struct WorkloadCloseIntent \{/) {
                sub(/\)\]$/, ", __cser_core::clone::Clone)]", candidate)
                print candidate
                print next_line
                changed = 1
                next
            }
            print candidate
            print next_line
            next
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$infrastructure_mod_file" >"$work/cloneable-workload-close-intent.rs"
    require_mutation "$infrastructure_mod_file" "$work/cloneable-workload-close-intent.rs" \
        cloneable-workload-close-intent
    require_infrastructure_mod_rejection "$work/cloneable-workload-close-intent.rs" \
        cloneable-workload-close-intent

    awk '
        !changed && /let publication = match self\.prepare_publication_ack\(ticket\)/ {
            print "        let _early_external = apply_external();"
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$runtime_causal_file" >"$work/external-before-preflight.rs"
    require_mutation "$runtime_causal_file" "$work/external-before-preflight.rs" \
        external-before-preflight
    require_causal_facade_rejection "$work/external-before-preflight.rs" \
        external-before-preflight

    awk '
        { lines[NR] = $0 }
        /let identity = self\.apply_close_causal_workload\(intent, session\);/ {
            close_line = NR
        }
        /self\.apply_revoke_complete\(revoke\);/ { revoke_line = NR }
        END {
            if (!close_line || !revoke_line || close_line >= revoke_line) exit 2
            swap = lines[close_line]
            lines[close_line] = lines[revoke_line]
            lines[revoke_line] = swap
            for (line = 1; line <= NR; line++) print lines[line]
        }
    ' "$runtime_causal_file" >"$work/revoke-before-workload-close.rs"
    require_mutation "$runtime_causal_file" "$work/revoke-before-workload-close.rs" \
        revoke-before-workload-close
    require_causal_facade_rejection "$work/revoke-before-workload-close.rs" \
        revoke-before-workload-close

    cp "$runtime_causal_file" "$work/missing-projected-close.rs"
    sed -i '0,/Some(\&intent\.infrastructure),/s//None,/' \
        "$work/missing-projected-close.rs"
    require_mutation "$runtime_causal_file" "$work/missing-projected-close.rs" \
        missing-projected-close
    require_causal_facade_rejection "$work/missing-projected-close.rs" \
        missing-projected-close

    cp "$runtime_causal_file" "$work/unbound-publication-root.rs"
    sed -i \
        '0,/ticket\.effect != identity\.root_effect/s//ticket.effect == identity.root_effect/' \
        "$work/unbound-publication-root.rs"
    require_mutation "$runtime_causal_file" "$work/unbound-publication-root.rs" \
        unbound-publication-root
    require_causal_facade_rejection "$work/unbound-publication-root.rs" \
        unbound-publication-root

    awk '
        /pub\(in super::super\) fn prepare_workload_close\(/ { prepare = 1 }
        prepare && !changed && /check_scope_invariants\(scope\)\?;/ {
            print "        let _unchecked_scope = scope;"
            changed = 1
            next
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$infrastructure_root_file" >"$work/unchecked-workload-close-scope.rs"
    require_mutation "$infrastructure_root_file" "$work/unchecked-workload-close-scope.rs" \
        unchecked-workload-close-scope
    require_infrastructure_root_rejection "$work/unchecked-workload-close-scope.rs" \
        unchecked-workload-close-scope

    awk '
        /pub\(in super::super\) fn apply_workload_close\(/ { apply = 1 }
        apply && !changed && /^[[:space:]]*\) \{$/ {
            sub(/\) \{/, ") -> Result<(), InfrastructureError> {")
            changed = 1
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$infrastructure_root_file" >"$work/fallible-workload-close-apply.rs"
    require_mutation "$infrastructure_root_file" "$work/fallible-workload-close-apply.rs" \
        fallible-workload-close-apply
    require_infrastructure_root_rejection "$work/fallible-workload-close-apply.rs" \
        fallible-workload-close-apply

    cp "$effect_registry_file" "$work/nonprojected-root-finish.rs"
    sed -i \
        '0,/\.prepare_closure_finish_after_workload_close(/s//.prepare_closure_finish(/' \
        "$work/nonprojected-root-finish.rs"
    require_mutation "$effect_registry_file" "$work/nonprojected-root-finish.rs" \
        nonprojected-root-finish
    require_effect_registry_rejection "$work/nonprojected-root-finish.rs" \
        nonprojected-root-finish

    cp "$adapter_file" "$work/recursive-receipt-view.rs"
    sed -i \
        '0,/PreparationReceipt::attempt(self)/s//self.attempt()/' \
        "$work/recursive-receipt-view.rs"
    require_mutation "$adapter_file" "$work/recursive-receipt-view.rs" \
        recursive-receipt-view
    require_adapter_rejection "$work/recursive-receipt-view.rs" \
        recursive-receipt-view

    cp "$receipt_bridge_file" "$work/concrete-core-receipt.rs"
    sed -i '1i use nexus_ostd_virtio::PreparationReceipt;' \
        "$work/concrete-core-receipt.rs"
    require_mutation "$receipt_bridge_file" "$work/concrete-core-receipt.rs" \
        concrete-core-receipt
    require_receipt_bridge_rejection "$work/concrete-core-receipt.rs" \
        concrete-core-receipt

    cp "$source_file" "$work/phase-mismatch-continues.rs"
    sed -i \
        '0,/self.adapter_phase = FsDeviceAdapterPhase::IndeterminateRetained;/s//self.adapter_phase = next;/' \
        "$work/phase-mismatch-continues.rs"
    require_mutation "$source_file" "$work/phase-mismatch-continues.rs" \
        phase-mismatch-continues
    require_source_rejection "$work/phase-mismatch-continues.rs" phase-mismatch-continues

    cp "$source_file" "$work/publish-owner-expect.rs"
    sed -i \
        '0,/request_slot.take().map(|intent| intent.apply())/s//request_slot.take().expect("prevalidated owner-bound publish intent").apply()/' \
        "$work/publish-owner-expect.rs"
    require_mutation "$source_file" "$work/publish-owner-expect.rs" publish-owner-expect
    require_source_rejection "$work/publish-owner-expect.rs" publish-owner-expect

    [[ $mutations == 44 ]] || fail "expected 44 source mutations, observed $mutations"
fi

echo 'runtime filesystem same-boot source assertions: PASS checkpoint=device_flight accepted_registry=one accepted_ledger=one compatibility_syscalls=payload_only_not_cser causal_bootstrap=workload+two-phase-core causal_slot=vacant+active+closed causal_close=non-clone+failure-atomic+projected-root-finish combined_order=external+ack+workload+root exact_outer_ack_retry=true rfc0003_obligations=not_wired source_mapped=false observed=false adapter_wired=false flight=single_actor_slot_handoff actor_resident=false semantic_identity=registry_issued receipt_boundary=provider-neutral+sibling-adapter-only real_user_service_crash=true fsd_task_key=current-task-bound+951:1->951:2 replacement_construction=post-crash distinct_task_vm=true guest_admission=receipt-before-armed guest_wait_locks=none crash_cohort=filesystem_read_only stale_prepare=queued-v1+failure-atomic old_sender_current_handle=NoSupervisor reply_wakeups=1 published_error=retained ack_revoke=failure_atomic guest_write=prevalidated+infallible_frame_apply fail_stop=before_guest_resume post_terminal_allocation=false facade_companion=false polling=true irq_evidence=false smp=1 legacy_phase=false rfc0001_full_closure=false mutations=44'
