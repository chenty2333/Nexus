#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
default_repo_root=$(cd -- "$script_dir/../../.." && pwd)
repo_root=${1:-$default_repo_root}

fail() {
    echo "CSER core production cutover assertion: FAIL: $*" >&2
    exit 1
}

extract_rust_item() {
    local marker=$1
    local input=$2

    awk -v marker="$marker" '
        !in_item && index($0, marker) {
            in_item = 1
            found = 1
        }
        in_item {
            print
            scan = $0
            opens = gsub(/\{/, "", scan)
            scan = $0
            closes = gsub(/\}/, "", scan)
            depth += opens - closes
            if (opens > 0) opened = 1
            if (opened && depth == 0) {
                complete = 1
                exit
            }
        }
        END {
            if (!found || !complete) exit 1
        }
    ' "$input"
}

require_ordered_tokens() {
    local source=$1
    local contract=$2
    shift 2
    local previous=0
    local token
    local line

    for token in "$@"; do
        line=$(awk -v token="$token" 'index($0, token) { print NR; exit }' <<<"$source")
        [[ -n $line ]] || fail "$contract lacks ordered token: $token"
        (( line > previous )) \
            || fail "$contract has a noncanonical call order at token: $token"
        previous=$line
    done
}

if (( $# > 1 )); then
    fail 'usage: assert-cser-core-production-cutover.sh [REPOSITORY_ROOT]'
fi

[[ -d $repo_root && ! -L $repo_root ]] || fail "repository root is not a directory: $repo_root"
repo_root=$(cd -- "$repo_root" && pwd)

manifest=$repo_root/kernel/nexus-ostd/cser-production-sources.txt
cser_source_root=$repo_root/kernel/nexus-ostd/src/cser
kernel_manifest=$repo_root/kernel/nexus-ostd/Cargo.toml
root_manifest=$repo_root/Cargo.toml
kernel_entry=$repo_root/kernel/nexus-ostd/src/lib.rs
root_workflow=$repo_root/x
kernel_workflow=$repo_root/kernel/nexus-ostd/x
core_lib=$repo_root/crates/cser-core/src/lib.rs
core_engine=$repo_root/crates/cser-core/src/engine.rs
core_journal=$repo_root/crates/cser-core/src/journal.rs
core_profiles=$repo_root/crates/cser-core/src/profiles.rs
production_registry=$cser_source_root/core_production_registry.rs
portal_vnext=$cser_source_root/core_portal_vnext.rs
persistent_runtime=$cser_source_root/core_persistent_runtime.rs
reply_outbox=$cser_source_root/core_reply_outbox.rs
tpm_anchor=$cser_source_root/core_tpm_anchor.rs

for input in \
    "$manifest" \
    "$root_manifest" \
    "$kernel_manifest" \
    "$kernel_entry" \
    "$root_workflow" \
    "$kernel_workflow" \
    "$core_lib" \
    "$core_engine" \
    "$core_journal" \
    "$core_profiles" \
    "$production_registry" \
    "$portal_vnext" \
    "$persistent_runtime" \
    "$reply_outbox" \
    "$tpm_anchor"; do
    [[ -f $input && ! -L $input ]] || fail "required input is not a regular non-symlink file: $input"
done
[[ -d $cser_source_root && ! -L $cser_source_root ]] \
    || fail "CSER source root is not a directory: $cser_source_root"

grep -Fxq 'pub const CSER_CORE_API_PROFILE_VERSION: u16 = 3;' "$core_lib" \
    || fail 'portable core API profile 3 is not frozen at the cutover'
grep -Fxq 'pub const STANDARD_CATALOG_VERSION: u16 = 7;' "$core_lib" \
    || fail 'portable standard catalog v7 is not frozen at the cutover'
grep -Fxq 'pub const PROJECTION_VERSION: u16 = 7;' "$core_lib" \
    || fail 'portable projection v7 is not frozen at the cutover'
grep -Fxq 'pub const RECOVERY_SNAPSHOT_VERSION: u16 = 3;' "$core_lib" \
    || fail 'portable recovery snapshot v3 is not frozen at the cutover'
grep -Fxq 'pub const JOURNAL_MAGIC: [u8; 8] = *b"CSERJR7\0";' "$core_journal" \
    || fail 'portable core journal magic is not bound to schema 7'
grep -Fxq 'pub const JOURNAL_SCHEMA_VERSION: u16 = 7;' "$core_journal" \
    || fail 'portable core journal schema 7 is not frozen at the cutover'
for profile2_engine_guard in \
    'Self::new_with_mode(catalog, limits, freshness, EngineApiMode::ProfileTwo)' \
    'if self.api_mode == EngineApiMode::ProfileTwo && !command.is_profile_two_compatible() {' \
    '&& !record.command().is_profile_two_compatible()'; do
    grep -Fq "$profile2_engine_guard" "$core_engine" \
        || fail "portable profile-2 Engine lacks a fail-closed grammar guard: $profile2_engine_guard"
done
for profile_coordinate in \
    'pub const AGENT_OPERATION_COMPOSITE: CompositeKindId = match CompositeKindId::new(1) {' \
    'pub const AGENT_COMPONENT_REPLY: ComponentId = match ComponentId::new(1) {' \
    'pub const AGENT_COMPONENT_DMA: ComponentId = match ComponentId::new(2) {' \
    'pub const DMA_ARENA_REUSE_COMPOSITE: CompositeKindId = match CompositeKindId::new(2) {'; do
    grep -Fxq "$profile_coordinate" "$core_profiles" \
        || fail "portable profile 2 lacks frozen composite coordinate: $profile_coordinate"
done

declare -a closure_sources=()
declare -A manifest_entries=()
while IFS= read -r entry || [[ -n $entry ]]; do
    [[ -n $entry ]] || fail 'production source manifest contains a blank line'
    [[ $entry != *$'\r'* ]] || fail "production source manifest contains CRLF data: $entry"
    [[ $entry =~ ^core_[a-z0-9_]+\.rs$ ]] \
        || fail "production source is outside the new core/vNext namespace: $entry"
    case "$entry" in
        core_runtime_slice.rs|core_dma_runtime.rs)
            fail "development-only runtime entered the production closure: $entry"
            ;;
    esac
    [[ ! -v "manifest_entries[$entry]" ]] \
        || fail "duplicate production source manifest entry: $entry"
    manifest_entries[$entry]=1

    source=$cser_source_root/$entry
    [[ -f $source && ! -L $source ]] \
        || fail "manifest entry is not a regular non-symlink source: $entry"
    closure_sources+=("$source")
done <"$manifest"

(( ${#closure_sources[@]} > 0 )) || fail 'production source manifest is empty'

required_sources=(
    core_device_quarantine.rs
    core_dma_adapter.rs
    core_dma_arena_allocator.rs
    core_persistent_runtime.rs
    core_pio_journal.rs
    core_portal_vnext.rs
    core_production_registry.rs
    core_qemu_persistent_boot.rs
    core_reboot.rs
    core_reply_adapter.rs
    core_reply_outbox.rs
    core_runtime.rs
    core_supervisor_vnext.rs
    core_tpm_anchor.rs
)
(( ${#closure_sources[@]} == ${#required_sources[@]} )) \
    || fail "production source manifest must contain exactly ${#required_sources[@]} sources; found ${#closure_sources[@]}"
for required in "${required_sources[@]}"; do
    [[ -v "manifest_entries[$required]" ]] \
        || fail "production source manifest lacks required cutover owner: $required"
done

retired_files=(
    kernel/nexus-ostd/src/cser/composition.rs
    kernel/nexus-ostd/src/cser/device_flight.rs
    kernel/nexus-ostd/src/cser/effect.rs
    kernel/nexus-ostd/src/cser/effect_registry.rs
    kernel/nexus-ostd/src/cser/linux_io_composition.rs
    kernel/nexus-ostd/src/cser/portal_v2.rs
    kernel/nexus-ostd/src/cser/supervisor_runtime.rs
    crates/nexus-ostd-virtio/src/portal.rs
)
for relative in "${retired_files[@]}"; do
    [[ ! -e $repo_root/$relative ]] \
        || fail "retired live source remains present: $relative"
done

retired_trees=(
    kernel/nexus-ostd/src/cser/effect_registry
    kernel/nexus-ostd/src/cser/infrastructure
    kernel/nexus-ostd/src/domains
    kernel/nexus-ostd/src/personality
    crates/cser-transition-gates
    crates/nexus-effect-peer
    crates/nexus-portal-abi
    crates/nexus-supervisor
)
for relative in "${retired_trees[@]}"; do
    tree=$repo_root/$relative
    if [[ -d $tree ]] && find "$tree" -type f -print -quit | grep -q .; then
        fail "retired live tree still contains files: $relative"
    fi
done

for entry in "${!manifest_entries[@]}"; do
    path_marker="#[path = \"cser/$entry\"]"
    reference_count=$(grep -Fc "$path_marker" "$kernel_entry" || true)
    (( reference_count == 1 )) \
        || fail "kernel entrypoint must reference manifest source exactly once: $entry (found $reference_count)"
    declaration_prefix=$(awk -v marker="$path_marker" '
        index($0, marker) {
            start = NR - 1
            while (start > 0 && lines[start] !~ /^[[:space:]]*$/) start--
            for (line = start + 1; line < NR; line++) print lines[line]
            found = 1
            exit
        }
        { lines[NR] = $0 }
        END { if (!found) exit 1 }
    ' "$kernel_entry") || fail "cannot isolate kernel feature guard for manifest source: $entry"
    grep -Fq 'feature = "cser-production"' <<<"$declaration_prefix" \
        || fail "manifest source is not selected by cser-production: $entry"
done

forbidden_tokens=(
    EffectRegistry
    effect_registry
    portal_v2
    supervisor_runtime
    nexus-effect-peer
    nexus_effect_peer
    nexus-portal-abi
    nexus_portal_abi
    nexus-supervisor
    nexus_supervisor
    transact_volatile
    new_legacy_compatibility
    recover_legacy_compatibility
)
closure_inputs=("${closure_sources[@]}" "$kernel_entry")
for token in "${forbidden_tokens[@]}"; do
    if matches=$(LC_ALL=C grep -nHF -- "$token" "${closure_inputs[@]}" 2>/dev/null); then
        printf '%s\n' "$matches" >&2
        fail "production source closure contains forbidden legacy/development token: $token"
    fi
done

ingress_identity=$(extract_rust_item \
    'pub(crate) struct ProductionIngressIdentity {' \
    "$production_registry") \
    || fail 'cannot isolate production ingress identity'
ingress_identity_field_count=$(grep -Ec \
    '^    [[:alpha:]_][[:alnum:]_]*:' \
    <<<"$ingress_identity" || true)
(( ingress_identity_field_count == 3 )) \
    || fail 'production ingress identity must bind exact root/incarnation/binding generation'
for field in \
    '    root: cser_core::RootId,' \
    '    incarnation: cser_core::PrincipalIncarnation,' \
    '    binding_generation: u64,'; do
    grep -Fxq "$field" <<<"$ingress_identity" \
        || fail "production ingress identity lacks exact field: $field"
done

task_data=$(extract_rust_item \
    'pub(crate) struct ProductionIngressTaskData<S> {' \
    "$production_registry") \
    || fail 'cannot isolate production ingress task data'
task_data_field_count=$(grep -Ec \
    '^    [[:alpha:]_][[:alnum:]_]*:' \
    <<<"$task_data" || true)
(( task_data_field_count == 3 )) \
    || fail 'production task data must bind exactly ingress identity, owner, and exit observer'
for field in \
    '    identity: ProductionIngressIdentity,' \
    '    owner: Weak<ProductionCoreOwner<S>>,' \
    '    exit_observer: Arc<dyn ProductionIngressExitObserver>,'; do
    grep -Fxq "$field" <<<"$task_data" \
        || fail "production task data lacks exact owner/identity binding: $field"
done

service_identity=$(extract_rust_item \
    'struct ProductionServiceIdentity {' \
    "$persistent_runtime") \
    || fail 'cannot isolate production service identity'
service_identity_field_count=$(grep -Ec \
    '^    [[:alpha:]_][[:alnum:]_]*:' \
    <<<"$service_identity" || true)
(( service_identity_field_count == 3 )) \
    || fail 'production service identity must bind exactly ingress/snapshot/stage'
for field in \
    '    ingress: ProductionIngressIdentity,' \
    '    snapshot: Option<SnapshotId>,' \
    '    stage: ProductionServiceStage,'; do
    grep -Fxq "$field" <<<"$service_identity" \
        || fail "production service identity lacks exact recovery binding: $field"
done

service_builder=$(extract_rust_item \
    'fn build_production_service<S, F>(' \
    "$persistent_runtime") \
    || fail 'cannot isolate production service task builder'
for token in \
    'Arc::new(PersistentServiceExitObserver {' \
    'control: Arc::downgrade(&control),' \
    'inbox: Arc::downgrade(&exits),' \
    'ProductionIngressTaskData::new(owner, identity.ingress, exit_observer)' \
    '.data(task_data)'; do
    grep -Fq "$token" <<<"$service_builder" \
        || fail "production service task builder lacks exact task-bound token: $token"
done
exit_observer_binding=$(awk '
    /Arc::new\(PersistentServiceExitObserver \{/ { capture = 1 }
    capture { print }
    capture && /\}\);[[:space:]]*$/ { complete = 1; exit }
    END { if (!capture || !complete) exit 1 }
' <<<"$service_builder") \
    || fail 'cannot isolate production service exit-observer binding'
for field in \
    '            identity,' \
    '            control: Arc::downgrade(&control),' \
    '            inbox: Arc::downgrade(&exits),'; do
    grep -Fxq "$field" <<<"$exit_observer_binding" \
        || fail "production exit observer does not retain the full staged service identity: $field"
done
require_ordered_tokens "$service_builder" 'production service task builder' \
    'let ingress = ProductionServiceIngress {' \
    'let exit_observer: Arc<dyn ProductionIngressExitObserver>' \
    'let task_data = ProductionIngressTaskData::new(owner, identity.ingress, exit_observer);' \
    'TaskOptions::new(move || {' \
    '.data(task_data)'

exact_exit=$(extract_rust_item \
    'pub(crate) fn observe_exact_exit(&self, task: &Task) {' \
    "$production_registry") \
    || fail 'cannot isolate production exact-exit handler'
require_ordered_tokens "$exact_exit" 'production exact-exit handler' \
    'if !task.is_reaped() {' \
    'let gate_closed = self' \
    '.is_some_and(|owner| owner.close_ingress(self.identity));' \
    'self.exit_observer.observe_exit(self.identity, gate_closed);'

exit_observer=$(extract_rust_item \
    'impl ProductionIngressExitObserver for PersistentServiceExitObserver {' \
    "$persistent_runtime") \
    || fail 'cannot isolate persistent service exit observer'
require_ordered_tokens "$exit_observer" 'persistent service exit observer' \
    'if identity != self.identity.ingress || !gate_closed || !control.close_ingress() {' \
    'inbox.publish(ProductionServiceExit {' \
    'identity: self.identity,'

task_exit_hook=$(extract_rust_item \
    'fn observe_persistent_task_exit(task: &Task) {' \
    "$persistent_runtime") \
    || fail 'cannot isolate persistent production task-exit hook'
for task_owner in PersistentRuntime QuarantinedPersistentCore; do
    grep -Fq "downcast_ref::<ProductionIngressTaskData<$task_owner>>()" \
        <<<"$task_exit_hook" \
        || fail "production task-exit hook lacks exact owner task data: $task_owner"
done
exact_exit_dispatches=$(grep -Fc 'data.observe_exact_exit(task);' <<<"$task_exit_hook" || true)
(( exact_exit_dispatches == 2 )) \
    || fail "production task-exit hook must dispatch both installed owner forms; found $exact_exit_dispatches"

production_launch=$(extract_rust_item \
    'pub(crate) fn launch() -> ! {' \
    "$persistent_runtime") \
    || fail 'cannot isolate persistent production launch'
require_ordered_tokens "$production_launch" 'persistent production launch' \
    'inject_post_task_exit_handler(observe_persistent_task_exit);' \
    'TaskOptions::new(run_persistent_recovery)' \
    'manager.run();'

client_transact=$(extract_rust_item \
    'fn transact(&self, request: CommandRequest)' \
    "$production_registry") \
    || fail 'cannot isolate client-facing production Registry transact'
require_ordered_tokens "$client_transact" 'client-facing production Registry transact' \
    'if !request.is_profile_two_compatible() {' \
    'return Err(ProductionRegistryError::ProfileOneCommandForbidden);' \
    '.authorize_current_ingress()' \
    'if command_ingress_identity(&request) != Some(identity) {' \
    '.installed' \
    '.transact(request.into())'
for component_command in \
    'CommandRequest::CreateCompositeEffect { .. }' \
    'CommandRequest::AddComponentClaim { .. }' \
    'CommandRequest::PrepareCompositeEffect { .. }' \
    'CommandRequest::RecordComponentCommitIntent { .. }' \
    'CommandRequest::RecordCompositeCommitIntents { .. }'; do
    grep -Fq "$component_command" <<<"$client_transact" \
        || fail "client-facing production Registry rejects profile 2 command: $component_command"
done

component_intent_take=$(extract_rust_item \
    'pub(crate) fn take_component_commit_intent(' \
    "$production_registry") \
    || fail 'cannot isolate component-local commit-intent transfer'
for component_coordinate in \
    '        effect: cser_core::EffectId,' \
    '        component: cser_core::ComponentId,' \
    '        self.take_matching_commit_intent(effect, Some(component))'; do
    grep -Fxq "$component_coordinate" <<<"$component_intent_take" \
        || fail "production Registry component bearer lacks exact coordinate: $component_coordinate"
done

composite_intent_take=$(extract_rust_item \
    'pub(crate) fn take_composite_commit_intents(' \
    "$production_registry") \
    || fail 'cannot isolate atomic composite commit-intent transfer'
require_ordered_tokens "$composite_intent_take" 'atomic composite commit-intent transfer' \
    'effect: cser_core::EffectId,' \
    'TransitionOutput::CompositeCommitIntents(intents)' \
    'intents.iter().all(|intent| intent.effect() == effect)' \
    'TransitionOutput::CompositeCommitIntents(intents) => Some(intents)'
if grep -Fq 'TransitionOutput::CommitIntent(intent) => Some(intent)' \
    <<<"$composite_intent_take"; then
    fail 'atomic composite bearer can be partially extracted as a singleton intent'
fi

client_observe=$(extract_rust_item \
    'fn observe(&self, query: CoreQuery)' \
    "$production_registry") \
    || fail 'cannot isolate client-facing production Registry observe'
require_ordered_tokens "$client_observe" 'client-facing production Registry observe' \
    'self.authorize_current_ingress()' \
    'self.installed.observe(|engine| {'

trusted_transact=$(extract_rust_item \
    'pub(crate) fn transact_trusted<C>(' \
    "$production_registry") \
    || fail 'cannot isolate trusted production Registry transact'
require_ordered_tokens "$trusted_transact" 'trusted production Registry transact' \
    'let command = command.into();' \
    'if !command.is_profile_two_compatible() {' \
    'return Err(TxError::Core(CoreError::IncompatibleApiProfile));' \
    'self.installed.transact(command)'
if grep -Fq 'authorize_current_ingress' <<<"$trusted_transact"; then
    fail 'trusted supervisor/domain path is incorrectly coupled to client task ingress'
fi

profile2_install=$(extract_rust_item \
    'pub(crate) fn new(installed: S)' \
    "$production_registry") \
    || fail 'cannot isolate profile-2 production owner installation'
require_ordered_tokens "$profile2_install" 'profile-2 production owner installation' \
    'installed.observe(Engine::profile_one_estate_count) != 0' \
    'return Err((CoreError::IncompatibleApiProfile, installed));' \
    'linear_custody: Mutex::new(Vec::with_capacity(MAX_LINEAR_PORTAL_BEARERS))'

portal_policy=$(extract_rust_item \
    'fn require_client_command(request: &CommandRequest)' \
    "$portal_vnext") \
    || fail 'cannot isolate profile-2 portal policy'
require_ordered_tokens "$portal_policy" 'profile-2 portal policy' \
    'if !request.is_profile_two_compatible() {' \
    'return Err(PortalPolicyError::ProfileOneCommandForbidden);' \
    'CommandRequest::CreateCompositeEffect { .. }' \
    '| CommandRequest::RecordComponentCommitIntent { .. }' \
    '| CommandRequest::RecordCompositeCommitIntents { .. } => return Ok(())'

if grep -Fq 'pub(crate) fn take_commit_intent(' "$production_registry"; then
    fail 'production Registry still exposes a profile-1 commit-intent transfer'
fi
for legacy_query in 'Estate(EffectId)' 'Claims(EffectId)'; do
    if grep -Fq "$legacy_query" "$portal_vnext"; then
        fail "production portal still exposes a profile-1 query: $legacy_query"
    fi
done

runtime_effect_helper_count=$(grep -Ec \
    '^fn [[:alpha:]_][[:alnum:]_]*effect\(\) -> EffectId' \
    "$persistent_runtime" || true)
(( runtime_effect_helper_count == 2 )) \
    || fail "production runtime must define exactly the operation and reuse EffectId helpers; found $runtime_effect_helper_count"
runtime_effect_constructor_count=$(grep -Fc 'EffectId::new(' "$persistent_runtime" || true)
(( runtime_effect_constructor_count == 2 )) \
    || fail "production runtime must construct exactly one operation and one reuse EffectId; found $runtime_effect_constructor_count"

operation_root=$(extract_rust_item \
    'fn operation_root() -> RootId {' \
    "$persistent_runtime") \
    || fail 'cannot isolate production operation root'
grep -Fxq '    root(0xc501)' <<<"$operation_root" \
    || fail 'production operation root is not the frozen shared root'

operation_effect=$(extract_rust_item \
    'fn operation_effect() -> EffectId {' \
    "$persistent_runtime") \
    || fail 'cannot isolate production operation effect'
grep -Fxq \
    '    EffectId::new(operation_root(), 1).expect("agent operation effect is non-zero")' \
    <<<"$operation_effect" \
    || fail 'production operation effect is not derived once from the shared root'

reuse_effect=$(extract_rust_item \
    'fn reuse_effect() -> EffectId {' \
    "$persistent_runtime") \
    || fail 'cannot isolate production DMA reuse effect'
for coordinate in \
    '    EffectId::new(operation_root(), REUSE_EFFECT_SEQUENCE)' \
    '        .expect("DMA reuse effect identity is non-zero")'; do
    grep -Fxq "$coordinate" <<<"$reuse_effect" \
        || fail "production DMA reuse effect lacks exact root/sequence coordinate: $coordinate"
done
grep -Fxq 'const REUSE_EFFECT_SEQUENCE: u64 = 2;' "$persistent_runtime" \
    || fail 'production DMA reuse effect is not the frozen second effect on the agent root'

operation_origin=$(extract_rust_item \
    'fn operation_origin() -> PrincipalIncarnation {' \
    "$persistent_runtime") \
    || fail 'cannot isolate production operation origin'
grep -Fxq '    principal(0xc501, 1)' <<<"$operation_origin" \
    || fail 'production operation origin is not bound to the shared root'

activation_boot=$(extract_rust_item \
    'fn run_activation_boot(boot: PersistentBoot) -> ! {' \
    "$persistent_runtime") \
    || fail 'cannot isolate first-boot production activation'
activation_service_count=$(grep -Fc 'build_production_service(' <<<"$activation_boot" || true)
(( activation_service_count == 1 )) \
    || fail "first-boot operation must run in exactly one production service task; found $activation_service_count"
require_ordered_tokens "$activation_boot" 'first-boot composite production service' \
    'let service_identity = match prepare_production_service(' \
    'operation_root(),' \
    'operation_origin(),' \
    'ProductionServiceStage::InitialCompositePublication,' \
    'let service = match build_production_service(' \
    'let output = publish_first_boot_operation('

composite_prepare=$(extract_rust_item \
    'fn ensure_composite_prepared<S>(' \
    "$persistent_runtime") \
    || fail 'cannot isolate production composite preparation'
create_composite_count=$(grep -Fc 'CommandRequest::CreateCompositeEffect {' \
    <<<"$composite_prepare" || true)
prepare_composite_count=$(grep -Fc 'CommandRequest::PrepareCompositeEffect {' \
    <<<"$composite_prepare" || true)
(( create_composite_count == 1 && prepare_composite_count == 1 )) \
    || fail 'production composite preparation must create and prepare one shared effect'
require_ordered_tokens "$composite_prepare" 'production composite preparation' \
    'let effect = operation_effect();' \
    'CommandRequest::CreateCompositeEffect {' \
    'kind: AGENT_OPERATION_COMPOSITE,' \
    'engine.component(effect, AGENT_COMPONENT_REPLY)' \
    'engine.component(effect, AGENT_COMPONENT_DMA)' \
    'CommandRequest::AddComponentClaim {' \
    'component: AGENT_COMPONENT_REPLY,' \
    'engine.component_claims(effect, AGENT_COMPONENT_DMA)' \
    'dma.enroll_claims()' \
    'CommandRequest::PrepareCompositeEffect {'

reply_commit=$(extract_rust_item \
    'fn ensure_reply_component_committed<S>(' \
    "$persistent_runtime") \
    || fail 'cannot isolate reply component commit'
require_ordered_tokens "$reply_commit" 'reply component commit' \
    'projection.commit == CommitState::Committed' \
    'projection.commit != CommitState::CommitIntentDurable' \
    'let intent = intent.ok_or("reply-atomic-commit-intent-custody")?;' \
    'intent.component() != Some(AGENT_COMPONENT_REPLY)' \
    '.commit(&challenge, REPLY_SEQUENCE, plan.payload_digest())' \
    '.acknowledge(outcome)'
if grep -Fq 'CommandRequest::RecordComponentCommitIntent {' <<<"$reply_commit"; then
    fail 'reply component still arms a singleton commit intent outside the atomic cohort'
fi

initial_commit_arm=$(extract_rust_item \
    'fn arm_initial_component_commits<S>(' \
    "$persistent_runtime") \
    || fail 'cannot isolate atomic initial component commit arm'
require_ordered_tokens "$initial_commit_arm" 'atomic initial component commit arm' \
    'CommandRequest::RecordCompositeCommitIntents {' \
    'effect: operation_effect(),' \
    'operations: vec![' \
    'ComponentCommitOperation::new(AGENT_COMPONENT_REPLY, digest(0xc1))' \
    'ComponentCommitOperation::new(AGENT_COMPONENT_DMA, dma_operation)' \
    '.take_composite_commit_intents(operation_effect())' \
    'intents.len() != 2' \
    'intent.component() == Some(AGENT_COMPONENT_REPLY)' \
    'dma.component() != Some(AGENT_COMPONENT_DMA)'
if grep -Fq 'CommandRequest::RecordComponentCommitIntent {' <<<"$initial_commit_arm"; then
    fail 'initial composite arm falls back to a singleton component intent'
fi

first_publication=$(extract_rust_item \
    'fn publish_first_boot_operation(' \
    "$persistent_runtime") \
    || fail 'cannot isolate first-boot composite publication'
require_ordered_tokens "$first_publication" 'first-boot composite publication' \
    'let cohort = CoreDmaCohort::bind_component(' \
    'operation_effect(),' \
    'AGENT_COMPONENT_DMA,' \
    'ensure_composite_prepared(' \
    'let arena = persistent_dma_arena_layout().ok_or("dma-arena-layout-absent")?;' \
    'let arena_digest = persistent_dma_arena_digest(arena);' \
    'arm_initial_component_commits(portal, owner, actor, binding_generation, arena_digest)?;' \
    'ensure_reply_component_committed(owner, &mut outbox, Some(reply_intent))?;' \
    'component.commit != CommitState::CommitIntentDurable' \
    'bind_queue_commit(engine, dma_intent, cohort)' \
    'publish_real_queue(' \
    'published.verify_commit(engine)'
composite_intent_take_count=$(grep -Fc '.take_composite_commit_intents(' \
    "$persistent_runtime" || true)
(( composite_intent_take_count == 1 )) \
    || fail "production runtime must transfer exactly one atomic reply+DMA intent cohort; found $composite_intent_take_count"
component_intent_take_count=$(grep -Fc '.take_component_commit_intent(' \
    "$persistent_runtime" || true)
(( component_intent_take_count == 0 )) \
    || fail "initial reply/DMA operation still transfers singleton component intents; found $component_intent_take_count"

component_settlement=$(extract_rust_item \
    'fn claim_component_settlement(' \
    "$persistent_runtime") \
    || fail 'cannot isolate component-local settlement claim'
require_ordered_tokens "$component_settlement" 'component-local settlement claim' \
    'self.authorize_ingress()?;' \
    'CoreSupervisorVNext::new(Arc::clone(&self.owner))' \
    '.claim_component_settlement(effect, component, self.identity.ingress.incarnation())'
reply_component_settlement_count=$(grep -Fc \
    'ingress.claim_component_settlement(operation_effect(), AGENT_COMPONENT_REPLY)?;' \
    "$persistent_runtime" || true)
(( reply_component_settlement_count == 2 )) \
    || fail "reply component must be claimed at second-crash arm and recovery; found $reply_component_settlement_count"

for settlement_stage in \
    'fn arm_reply_second_crash(' \
    'fn reconcile_reply_in_service<S>('; do
    stage_contract=$(extract_rust_item "$settlement_stage" "$persistent_runtime") \
        || fail "cannot isolate reply component settlement stage: $settlement_stage"
    grep -Fq \
        'ingress.claim_component_settlement(operation_effect(), AGENT_COMPONENT_REPLY)?;' \
        <<<"$stage_contract" \
        || fail "reply settlement stage lacks shared-effect component claim: $settlement_stage"
done

reply_reconcile=$(extract_rust_item \
    'fn reconcile_reply_in_service<S>(' \
    "$persistent_runtime") \
    || fail 'cannot isolate durable reply reconciliation'
require_ordered_tokens "$reply_reconcile" 'durable APPLY before physical wake' \
    '.record_apply(plan, source)' \
    '.redeliver_durable(plan, apply.semantic_digest())'
reply_completion=${reply_reconcile#*"let acknowledgement = match durable_ack {"}
[[ $reply_completion != "$reply_reconcile" ]] \
    || fail 'cannot isolate durable reply acknowledgement completion'
require_ordered_tokens "$reply_completion" 'receiver acceptance before durable ACK and settlement' \
    'result.wait_take_bounded()' \
    '.record_acknowledgement(plan, apply)' \
    'engine.verify_settlement_ack(' \
    '.settle(verified_ack)' \
    'ingress.transact(settle)' \
    'retire_reply_from_durable_ack('

delivery_append=$(extract_rust_item \
    'fn append_delivery(' \
    "$reply_outbox") \
    || fail 'cannot isolate durable reply delivery append'
require_ordered_tokens "$delivery_append" 'durable reply delivery write protocol' \
    'self.backend.write_sector(lba, &encoded)' \
    'self.backend.flush()' \
    'self.backend.read_sector(lba, &mut readback)' \
    'if readback != encoded' \
    'ReplyDeliveryRecord::decode(&readback)'

arm_second_crash=$(extract_rust_item \
    'fn arm_reply_second_crash(' \
    "$persistent_runtime") \
    || fail 'cannot isolate second-crash arm'
for forbidden_retry in \
    'outbox.commit(' \
    'ensure_reply_component_committed(' \
    '.redeliver_durable(' \
    '.record_acknowledgement('; do
    if grep -Fq "$forbidden_retry" <<<"$arm_second_crash"; then
        fail "second-crash arm may blindly replay an unknown external reply: $forbidden_retry"
    fi
done
grep -Fq '.record_apply_intent(plan.intent_digest())' <<<"$arm_second_crash" \
    || fail 'second-crash arm lacks its durable logical apply intent'

dma_recovery=$(extract_rust_item \
    'fn reconcile_dma_tombstones(' \
    "$persistent_runtime") \
    || fail 'cannot isolate DMA component tombstone recovery'
require_ordered_tokens "$dma_recovery" 'DMA component tombstone recovery' \
    'let layout = persistent_dma_arena_layout().ok_or("dma-arena-layout-absent")?;' \
    'if component.commit_operation != Some(layout_digest) {' \
    '.retained_component_claims()' \
    'claim.effect == effect' \
    'claim.component == AGENT_COMPONENT_DMA' \
    'engine.component_retirement_evidence_accepted(' \
    '.inspect_with_guard(|_, guard| project_replayed_component_claim(guard, claim))' \
    '.verify_component_retirement_evidence('
for component_recovery_token in \
    '&OstdBootClaimVerifier::new_component(claim),' \
    '&OstdBootIrqVerifier::new_component(claim),' \
    'let verifier = QemuArenaIotlbVerifier::new_component(' \
    'report.resource_reuse_authorized = validate_dma_reuse_boundary(owner, effect, expected);'; do
    grep -Fq "$component_recovery_token" <<<"$dma_recovery" \
        || fail "DMA tombstone recovery lacks component-local token: $component_recovery_token"
done

reuse_publication=$(extract_rust_item \
    'fn publish_reused_dma(' \
    "$persistent_runtime") \
    || fail 'cannot isolate generation+1 DMA reuse publication'
require_ordered_tokens "$reuse_publication" 'generation+1 DMA reuse publication' \
    'engine.component_claims(operation_effect(), AGENT_COMPONENT_DMA)' \
    'claims.iter().any(|claim| !claim.retired)' \
    'CommandRequest::CreateCompositeEffect {' \
    'effect: reuse_effect(),' \
    'kind: DMA_ARENA_REUSE_COMPOSITE,' \
    'ensure_uncommitted_composite_actor(' \
    'if let Some(projection) = projections' \
    'engine.reclaim_component_resource_reuse(' \
    'Err(CoreError::StaleReusePermit) => {}' \
    'CommandRequest::ReserveComponentReuse {' \
    'expected_generation: old.generation(),' \
    'CommandRequest::PrepareCompositeEffect {' \
    'let precommit = ingress.observe(validate_reuse_precommit)?;' \
    '.prepare_read_sector0(&mut root)' \
    'CoreDmaCohort::bind_component(' \
    'reused_dma_claims(),' \
    'cohort.record_commit_intent(persistent_dma_arena_digest(arena))' \
    'publish_real_queue(' \
    'published.verify_commit(engine)'
reuse_permit_count=$(grep -Fc 'CommandRequest::ReserveComponentReuse {' \
    <<<"$reuse_publication" || true)
(( reuse_permit_count == 1 )) \
    || fail "generation+1 DMA reuse must use one role-driven permit loop; found $reuse_permit_count"
reuse_activation_count=$(grep -Fc \
    'expect_no_output_checked(ingress.transact(permit.activate())?)?;' \
    <<<"$reuse_publication" || true)
(( reuse_activation_count == 2 )) \
    || fail "generation+1 DMA reuse must activate both reclaimed and new permits; found $reuse_activation_count activation sites"
if grep -Fq 'reuse_effect()' <<<"$reply_commit"; then
    fail 'reply publication is incorrectly coupled to the DMA reuse effect'
fi
for settlement_stage in \
    'fn arm_reply_second_crash(' \
    'fn reconcile_reply_in_service<S>('; do
    stage_contract=$(extract_rust_item "$settlement_stage" "$persistent_runtime") \
        || fail "cannot isolate reply component settlement stage: $settlement_stage"
    if grep -Fq 'reuse_effect()' <<<"$stage_contract"; then
        fail "reply settlement stage is incorrectly coupled to the DMA reuse effect: $settlement_stage"
    fi
done

legacy_runtime_tokens=(
    'CommandRequest::CreateEstate'
    'CommandRequest::AddClaim'
    'CommandRequest::PrepareEffect'
    'CommandRequest::RecordCommitIntent'
    '.take_commit_intent('
    'engine.estate('
    'engine.claims('
    'engine.retained_claims('
    'fn reply_effect('
    'fn dma_effect('
    'fn reply_root('
    'fn dma_root('
    'fn reply_origin('
    'fn dma_origin('
    'reply_service_task=true'
    'dma_service_task=true'
)
for legacy_runtime_token in "${legacy_runtime_tokens[@]}"; do
    if grep -Fq "$legacy_runtime_token" "$persistent_runtime"; then
        fail "production runtime retains legacy estate or split-effect path: $legacy_runtime_token"
    fi
done

service_ready=$(extract_rust_item \
    'fn ready_and_wait_for_rebind(&self)' \
    "$persistent_runtime") \
    || fail 'cannot isolate fresh service Ready/Rebind handshake'
require_ordered_tokens "$service_ready" 'fresh service Ready/Rebind handshake' \
    'self.authorize_task()?;' \
    '.ready(' \
    'self.control.advance(SERVICE_ENTERED, SERVICE_READY)?;' \
    'if !self.control.wait_for(SERVICE_REBOUND) {' \
    'self.authorize_ingress()?;' \
    'Some(RootRecoveryState::Rebound {'

manager_rebind=$(extract_rust_item \
    'fn rebind_production_service<S>(' \
    "$persistent_runtime") \
    || fail 'cannot isolate production manager Rebind handshake'
for coordinate in \
    'run.identity.ingress.root(),' \
    'run.identity.ingress.incarnation(),' \
    'run.identity.ingress.binding_generation(),'; do
    grep -Fq "$coordinate" <<<"$manager_rebind" \
        || fail "production manager Rebind lacks exact ingress coordinate: $coordinate"
done
require_ordered_tokens "$manager_rebind" 'production manager Rebind handshake' \
    'if !run.control.wait_for(SERVICE_READY) {' \
    'Some(RootRecoveryState::Ready {' \
    '.rebind(' \
    '.open_ingress(run.identity.ingress)' \
    'run.control.mark_ingress_open()?;' \
    'run.control.advance(SERVICE_READY, SERVICE_REBOUND)'

for boot in 1 2 3 4; do
    boot_marker=$(awk -v marker="CSER_CORE_PERSISTENT_BOOT$boot PASS" '
        !capture && index($0, marker) {
            capture = 1
            found = 1
        }
        capture { print }
        capture && /",[[:space:]]*$/ {
            complete = 1
            exit
        }
        END {
            if (!found || !complete) exit 1
        }
    ' "$persistent_runtime") \
        || fail "cannot isolate persistent boot$boot production marker"
    case $boot in
        1)
            boot_contract=(
                'profile=2'
                'composite_effect=true'
                'effect_identity=shared'
                'component_ids=reply+dma'
                'service_principal_generation={}'
                'binding_generation={}'
                'production_service_tasks=1'
                'service_death=task-return'
                'exact_reap=true'
                'same_boot_fence=true'
                'ingress_latch=closed'
                'closed_ingress_rejected=true'
                'production_rebind=initial'
            )
            ;;
        2)
            boot_contract=(
                'service_principal_generation={}'
                'binding_generation={}'
                'second_crash=service-exact-reap'
                'fresh_service_task=true'
                'ready_in_fresh_task=true'
                'production_rebind=true'
                'service_death=task-return'
                'exact_reap=true'
                'same_boot_fence=true'
                'ingress_latch=closed'
                'closed_ingress_rejected=true'
            )
            ;;
        3)
            boot_contract=(
                'service_principal_generation={}'
                'binding_generation={}'
                'fresh_service_task=true'
                'ready_in_fresh_task=true'
                'production_rebind=true'
                'service_state=live'
                'ingress_latch=open'
                'prior_service_fence=same-boot-exact-reap'
            )
            ;;
        4)
            boot_contract=(
                'service_principal_generation={}'
                'binding_generation={}'
                'fresh_service_task=true'
                'ready_in_fresh_task=true'
                'production_rebind=true'
                'service_state=live'
                'ingress_latch=open'
                'prior_service_fence=boot-checkpoint'
            )
            ;;
    esac
    for token in "${boot_contract[@]}"; do
        grep -Fq "$token" <<<"$boot_marker" \
            || fail "persistent boot$boot marker lacks production task/rebind semantic: $token"
    done
done

dependencies=$(awk '
    /^\[dependencies\][[:space:]]*$/ { in_table = 1; next }
    /^\[/ { if (in_table) exit }
    in_table { print }
' "$kernel_manifest")
core_dependency_count=$(grep -Ec '^[[:space:]]*cser-core[[:space:]]*=' <<<"$dependencies" || true)
(( core_dependency_count == 1 )) \
    || fail "kernel Cargo.toml must declare exactly one cser-core dependency; found $core_dependency_count"
core_dependency=$(awk '
    /^[[:space:]]*cser-core[[:space:]]*=/ {
        collecting = 1
        found = 1
    }
    collecting {
        print
        copy = $0
        opens += gsub(/\{/, "", copy)
        copy = $0
        closes += gsub(/\}/, "", copy)
        if (opens == 0 || opens == closes) exit
    }
    END { if (!found) exit 1 }
' <<<"$dependencies") || fail 'cannot isolate kernel cser-core dependency declaration'
grep -Fq 'path = "../../crates/cser-core"' <<<"$core_dependency" \
    || fail 'kernel cser-core dependency is not bound to the workspace portable core'
if grep -Eq 'optional[[:space:]]*=[[:space:]]*true' <<<"$core_dependency"; then
    fail 'kernel cser-core dependency remains optional'
fi

for dependency in nexus-effect-peer nexus-portal-abi nexus-supervisor; do
    if grep -Eq "^[[:space:]]*$dependency[[:space:]]*=" <<<"$dependencies"; then
        fail "legacy crate remains a kernel production dependency: $dependency"
    fi
done

features=$(awk '
    /^\[features\][[:space:]]*$/ { in_table = 1; next }
    /^\[/ { if (in_table) exit }
    in_table { print }
' "$kernel_manifest")
default_count=$(grep -Ec '^[[:space:]]*default[[:space:]]*=' <<<"$features" || true)
(( default_count == 1 )) \
    || fail "kernel Cargo.toml must declare exactly one default feature list; found $default_count"
grep -Eq '^[[:space:]]*default[[:space:]]*=[[:space:]]*\[[[:space:]]*"cser-production"[[:space:]]*\][[:space:]]*$' \
    <<<"$features" \
    || fail 'kernel default feature list must be exactly ["cser-production"]'
grep -Eq '^[[:space:]]*cser-production[[:space:]]*=' <<<"$features" \
    || fail 'kernel Cargo.toml lacks the cser-production feature'
if grep -Fq 'dep:cser-core' <<<"$features"; then
    fail 'cser-core is still feature-gated through dep:cser-core instead of being nonoptional'
fi

workspace_members=$(awk '
    /^members[[:space:]]*=[[:space:]]*\[/ { in_list = 1; next }
    in_list && /^[[:space:]]*\]/ { found_end = 1; exit }
    in_list { print }
    END { if (!in_list || !found_end) exit 1 }
' "$root_manifest") || fail 'cannot isolate root production workspace members'
expected_members=(
    crates/cser-core
    crates/cser-model
    crates/cser-trace-conformance
    crates/nexus-effect-peer-wire
)
member_count=$(grep -Ec '^[[:space:]]*"[^"]+",?[[:space:]]*$' <<<"$workspace_members" || true)
(( member_count == ${#expected_members[@]} )) \
    || fail "root production workspace must contain exactly ${#expected_members[@]} members; found $member_count"
for member in "${expected_members[@]}"; do
    count=$(grep -Fxc "    \"$member\"," <<<"$workspace_members" || true)
    (( count == 1 )) || fail "root production workspace lacks exact member: $member"
done
for retired in \
    crates/cser-transition-gates \
    crates/nexus-effect-peer \
    crates/nexus-portal-abi \
    crates/nexus-supervisor; do
    if grep -Fq "\"$retired\"" <<<"$workspace_members"; then
        fail "retired live crate remains a production workspace member: $retired"
    fi
done

root_verify=$(awk '
    /^verify_all\(\)[[:space:]]*\{/ { in_function = 1 }
    in_function { print }
    in_function && /^\}[[:space:]]*$/ { found_end = 1; exit }
    END { if (!in_function || !found_end) exit 1 }
' "$root_workflow") || fail 'cannot isolate root verify_all workflow'
grep -Eq '^[[:space:]]*run_backend[[:space:]]+"\$kernel_backend"[[:space:]]+seal-core-persistent-recovery([[:space:]]|$)' \
    <<<"$root_verify" \
    || fail 'root verify_all does not directly invoke the clean-source sealed recovery backend'

kernel_command_definition_count=$(grep -Ec \
    '^[[:space:]]*(function[[:space:]]+)?run_production_recovery([[:space:]]*\(\))?[[:space:]]*\{' \
    "$kernel_workflow" || true)
(( kernel_command_definition_count == 1 )) \
    || fail "kernel workflow must define run_production_recovery exactly once; found $kernel_command_definition_count"
kernel_command=$(awk '
    /^[[:space:]]*(function[[:space:]]+)?run_production_recovery([[:space:]]*\(\))?[[:space:]]*\{/ {
        if (seen_function) exit 2
        seen_function = 1
        in_function = 1
        next
    }
    in_function && /^[[:space:]]*\}[[:space:]]*$/ {
        in_function = 0
        found_end = 1
        next
    }
    in_function {
        line = $0
        sub(/^[[:space:]]+/, "", line)
        sub(/[[:space:]]+$/, "", line)
        if (line != "") print line
    }
    END {
        if (!seen_function || !found_end || in_function) exit 1
    }
' "$kernel_workflow") || fail 'cannot isolate unique kernel production recovery command'
mapfile -t kernel_calls <<<"$kernel_command"
expected_kernel_calls=(
    'prepare_core_persistent_artifacts'
    'bash "$root/scripts/assert-cser-core-production-cutover.sh" "$repo_root"'
    'capture_core_reply_evidence'
    'capture_core_dma_evidence'
    'capture_core_persistent_run'
)
(( ${#kernel_calls[@]} == ${#expected_kernel_calls[@]} )) \
    || fail "kernel production recovery command must contain exactly ${#expected_kernel_calls[@]} calls; found ${#kernel_calls[@]}"
for index in "${!expected_kernel_calls[@]}"; do
    [[ ${kernel_calls[$index]} == "${expected_kernel_calls[$index]}" ]] \
        || fail "kernel production recovery call $((index + 1)) is not canonical: ${kernel_calls[$index]}"
done

for forbidden in \
    'prepare_guest' \
    'run_same_boot_acceptance' \
    'stage7b' \
    'check-scheduler-attempt' \
    'src/personality' \
    'linux_io_composition'; do
    if grep -Fq "$forbidden" "$kernel_workflow"; then
        fail "kernel production workflow retains legacy route token: $forbidden"
    fi
done

for forbidden in \
    'virtio_backend' \
    'composition_backend' \
    'run_system' \
    'run_same_boot_acceptance' \
    'eval-stage7b'; do
    if grep -Fq "$forbidden" "$root_workflow"; then
        fail "root release workflow retains legacy route token: $forbidden"
    fi
done

osdk_manifest=$repo_root/kernel/nexus-ostd/OSDK.toml
[[ -f $osdk_manifest && ! -L $osdk_manifest ]] \
    || fail 'OSDK manifest is not a regular non-symlink file'
declare -A scheme_header_counts=(
    ['[scheme."cser-production"]']=0
    ['[scheme."cser-core-reply-recovery"]']=0
    ['[scheme."cser-pio-journal-ktest"]']=0
    ['[scheme."cser-baseline-handoff-ktest"]']=0
    ['[scheme."cser-core-dma-recovery"]']=0
    ['[scheme."cser-smp-smoke"]']=0
    ['[scheme."tool-dma-cser"]']=0
    ['[scheme."tool-dma-cser-vnext"]']=0
    ['[scheme."tool-dma-baseline"]']=0
)
while IFS= read -r scheme_header; do
    case "$scheme_header" in
        '[scheme."cser-production"]'|\
        '[scheme."cser-core-reply-recovery"]'|\
        '[scheme."cser-pio-journal-ktest"]'|\
        '[scheme."cser-baseline-handoff-ktest"]'|\
        '[scheme."cser-core-dma-recovery"]'|\
        '[scheme."cser-smp-smoke"]'|\
        '[scheme."tool-dma-cser"]'|\
        '[scheme."tool-dma-cser-vnext"]'|\
        '[scheme."tool-dma-baseline"]')
            ;;
        *)
            fail "OSDK manifest exposes a noncanonical scheme table: $scheme_header"
            ;;
    esac
    scheme_header_counts["$scheme_header"]=$((scheme_header_counts["$scheme_header"] + 1))
done < <(awk '
    {
        line = $0
        sub(/^[[:space:]]+/, "", line)
        sub(/[[:space:]]+$/, "", line)
        if (line ~ /^\[\[?[[:space:]]*(scheme|"scheme"|\047scheme\047)[[:space:]]*(\.|\])/)
            print line
    }
' "$osdk_manifest")
for scheme_header in "${!scheme_header_counts[@]}"; do
    (( scheme_header_counts["$scheme_header"] == 1 )) \
        || fail "OSDK manifest must expose the canonical scheme table exactly once: $scheme_header"
done
if grep -Eq '^\[qemu\][[:space:]]*$' "$osdk_manifest"; then
    fail 'OSDK manifest retains a scheme-less QEMU fallback'
fi
production_scheme=$(awk '
    $0 == "[scheme.\"cser-production\"]" { in_scheme = 1; next }
    in_scheme && /^\[/ { exit }
    in_scheme { print }
' "$osdk_manifest")
grep -Fxq 'build.features = ["cser-production"]' <<<"$production_scheme" \
    || fail 'production OSDK scheme does not select exactly cser-production'
if grep -Fq 'build.no_default_features = true' <<<"$production_scheme"; then
    fail 'production OSDK scheme bypasses the default production feature'
fi
for profile in reply dma; do
    scheme="cser-core-$profile-recovery"
    scheme_block=$(awk -v header="[scheme.\"$scheme\"]" '
        $0 == header { in_scheme = 1; next }
        in_scheme && /^\[/ { exit }
        in_scheme { print }
    ' "$osdk_manifest")
    grep -Fxq 'build.no_default_features = true' <<<"$scheme_block" \
        || fail "evidence scheme does not disable the production default: $scheme"
    grep -Fxq "build.features = [\"$scheme\"]" <<<"$scheme_block" \
        || fail "evidence scheme does not select its exact feature: $scheme"
done
for specification in \
    'tool-dma-cser:cser-tool-dma-experiment' \
    'tool-dma-cser-vnext:cser-tool-dma-experiment-vnext' \
    'tool-dma-baseline:cser-tool-dma-baseline-experiment'; do
    scheme=${specification%%:*}
    feature=${specification#*:}
    scheme_block=$(awk -v header="[scheme.\"$scheme\"]" '
        $0 == header { in_scheme = 1; next }
        in_scheme && /^\[/ { exit }
        in_scheme { print }
    ' "$osdk_manifest")
    grep -Fxq 'build.no_default_features = true' <<<"$scheme_block" \
        || fail "tool-DMA scheme does not disable the production default: $scheme"
    grep -Fxq "build.features = [\"$feature\"]" <<<"$scheme_block" \
        || fail "tool-DMA scheme does not select its exact feature: $scheme"
done

persistent_run=$(awk '
    /^capture_core_persistent_run\(\)[[:space:]]*\{/ { in_function = 1 }
    in_function { print }
    in_function && /^\}[[:space:]]*$/ { found_end = 1; exit }
    END { if (!in_function || !found_end) exit 1 }
' "$kernel_workflow") || fail 'cannot isolate kernel combined persistent recovery runner'
runtime_recovery=$(extract_rust_item \
    'fn run_persistent_recovery() {' \
    "$persistent_runtime") \
    || fail 'cannot isolate production persistent recovery entry'
require_ordered_tokens "$runtime_recovery" 'production trusted-state recovery order' \
    'let mut prepared = match PreparedQemuPersistentBoot::acquire() {' \
    'let selected_tip = prepared.candidate().committed();' \
    'let selected_bytes = match prepared.journal_bytes() {' \
    'if is_legacy_schema5(&selected_bytes) {' \
    'let boot = match prepared.recover(catalog, CoreLimits::bounded_default(), binding) {'
for schema5_fail_closed_token in \
    'if is_legacy_schema5(&selected_bytes)' \
    'selected_tip.revision() == 0 || selected_tip.head().is_zero()' \
    'trusted_tpm_candidate_selected=true' \
    'profile2_binding_authorized=false' \
    'typed_error=migration-required' \
    'semantic_replay=false inferred_pairing=false pre_replay_quarantine=true' \
    'device_guard_retained=true production_registry=false device_activation=false' \
    'fail_closed("schema5-migration-required", prepared)'; do
    grep -Fq "$schema5_fail_closed_token" <<<"$runtime_recovery" \
        || fail "production schema-5 rejection lacks retained authority token: $schema5_fail_closed_token"
done
for anchor_candidate_token in \
    'pub(crate) struct TpmNvAnchorCandidate<T> {' \
    'pub(crate) fn inspect(' \
    'pub(crate) fn bind(' \
    'return Err(Box::new((' \
    'PersistenceProtocolError::BindingMismatch.into(),'; do
    grep -Fq "$anchor_candidate_token" "$tpm_anchor" \
        || fail "TPM anchor lacks linear pre-binding inspection token: $anchor_candidate_token"
done
grep -Fq '"$core_persistent_artifact_dir/production-kernel.iso"' \
    <<<"$persistent_run" \
    || fail 'combined persistent recovery does not archive the production ISO'
kernel_iso_binding=$(awk '
    /production_kernel_iso_sha256=/ {
        if (seen_binding) exit 2
        seen_binding = 1
        in_binding = 1
    }
    in_binding { print }
    in_binding && /\| cut -d/ {
        found_end = 1
        exit
    }
    END {
        if (!seen_binding || !found_end) exit 1
    }
' "$kernel_workflow") || fail 'cannot isolate production ISO receipt binding'
grep -Fq '"$core_persistent_artifact_dir/production-kernel.iso"' \
    <<<"$kernel_iso_binding" \
    || fail 'production receipt is not bound to the archived production ISO'
if grep -Fq 'target/osdk/nexus-kernel/nexus-kernel-osdk-bin.iso' \
    <<<"$kernel_iso_binding"; then
    fail 'production receipt hashes the mutable OSDK output instead of its archive'
fi
for seal_contract in \
    'seal-core-persistent-recovery)' \
    'require_core_persistent_sealable_tree' \
    'nexus.cser.production-proof.v1' \
    ' NONSEALABLE '; do
    grep -Fq "$seal_contract" "$kernel_workflow" \
        || fail "kernel production workflow lacks receipt seal contract: $seal_contract"
done
boot_call_count=$(grep -Ec '^[[:space:]]*capture_core_persistent_boot[[:space:]]+\\[[:space:]]*$' \
    <<<"$persistent_run" || true)
(( boot_call_count == 4 )) \
    || fail "combined persistent recovery must invoke exactly four guest boots; found $boot_call_count"
for marker in \
    'boot1-serial.log' \
    'boot2-serial.log' \
    'boot3-serial.log' \
    'boot4-serial.log' \
    'CSER_CORE_PERSISTENT_BOOT1 PASS' \
    'CSER_CORE_PERSISTENT_BOOT2 PASS' \
    'CSER_CORE_PERSISTENT_BOOT3 PASS' \
    'CSER_CORE_PERSISTENT_BOOT4 PASS' \
    'assert_core_persistent_freshness_progression' \
    'core_persistent_qemu_event_count' \
    'freshness_progression=' \
    'shared_boot_virtio_notify_baseline=' \
    'boot1_runtime_notify_delta=' \
    'boot1_dma_translation_events=' \
    'post_boot1_dma_translation_events=' \
    'production_kernel_iso_sha256='; do
    grep -Fq "$marker" <<<"$persistent_run" \
        || fail "combined persistent recovery runner lacks marker: $marker"
done
if grep -Eq '^[[:space:]]*prepare_core_persistent_artifacts([[:space:]]|$)' \
    <<<"$persistent_run"; then
    fail 'combined runner recreates persistent media between its four guest boots'
fi
for shared_path in \
    'core_persistent_state_dir="$core_persistent_artifact_dir/tpmstate"' \
    'core_persistent_journal="$core_persistent_artifact_dir/journal.raw"' \
    'core_persistent_outbox="$core_persistent_artifact_dir/outbox.raw"'; do
    grep -Fq "$shared_path" "$kernel_workflow" \
        || fail "kernel workflow lacks one shared cross-boot persistence path: $shared_path"
done

container_function=$(awk '
    /^container\(\)[[:space:]]*\{/ { in_function = 1 }
    in_function { print }
    in_function && /^\}[[:space:]]*$/ { found_end = 1; exit }
    END { if (!in_function || !found_end) exit 1 }
' "$kernel_workflow") || fail 'cannot isolate kernel container runner'
persistent_guest=$(awk '
    /^run_core_persistent_guest\(\)[[:space:]]*\{/ { in_function = 1 }
    in_function { print }
    in_function && /^\}[[:space:]]*$/ { found_end = 1; exit }
    END { if (!in_function || !found_end) exit 1 }
' "$kernel_workflow") || fail 'cannot isolate persistent production guest runner'
persistent_capture=$(awk '
    /^capture_core_persistent_boot\(\)[[:space:]]*\(/ { in_function = 1 }
    in_function { print }
    in_function && /^\)[[:space:]]*$/ { found_end = 1; exit }
    END { if (!in_function || !found_end) exit 1 }
' "$kernel_workflow") || fail 'cannot isolate persistent production capture wrapper'
schema5_negative=$(awk '
    /^capture_core_schema5_negative_boot\(\)[[:space:]]*\{/ { in_function = 1 }
    in_function { print }
    in_function && /^\}[[:space:]]*$/ { found_end = 1; exit }
    END { if (!in_function || !found_end) exit 1 }
' "$kernel_workflow") || fail 'cannot isolate schema-5 negative boot cell'
swtpm_start=$(awk '
    /^start_core_persistent_swtpm\(\)[[:space:]]*\{/ { in_function = 1 }
    in_function { print }
    in_function && /^\}[[:space:]]*$/ { found_end = 1; exit }
    END { if (!in_function || !found_end) exit 1 }
' "$kernel_workflow") || fail 'cannot isolate persistent swtpm owner'
if grep -Eq 'capture_qemu_streams.*(\|\||&&)' <<<"$persistent_capture"; then
    fail 'persistent production capture disables helper errexit through a conditional invocation'
fi
require_ordered_tokens "$persistent_capture" 'persistent capture strict-status boundary' \
    "trap 'stop_core_persistent_swtpm || exit 1' EXIT" \
    'start_core_persistent_swtpm' \
    'set +e' \
    'capture_qemu_streams "$serial" "$debug" run_core_persistent_guest' \
    'capture_status=$?' \
    'set -e' \
    '    stop_core_persistent_swtpm'
for swtpm_owner_marker in \
    'core_persistent_pid=$!' \
    'stop_core_persistent_swtpm' \
    'return 1'; do
    grep -Fq "$swtpm_owner_marker" <<<"$swtpm_start" \
        || fail "persistent swtpm owner lacks failure cleanup marker: $swtpm_owner_marker"
done
if grep -Fq -- '--daemon' <<<"$swtpm_start"; then
    fail 'persistent swtpm escaped the runner-owned background process'
fi
grep -Fxq \
    'core_schema5_fixture_catalog=f58ad9f2c973e65532b10d6392f0528838bf95c09668f30395743816a58ddf25' \
    "$kernel_workflow" \
    || fail 'schema-5 negative boot lacks the frozen profile-1 catalog digest'
require_ordered_tokens "$schema5_negative" 'authentic schema-5 negative boot' \
    'build_core_schema5_selected_fixture' \
    'bash "$root/scripts/provision-cser-tpm-nv.sh"' \
    '"$core_schema5_fixture_catalog"' \
    'capture_core_persistent_boot' \
    'cmp "$core_schema5_journal" "$core_persistent_journal"' \
    "'CSER_CORE_SCHEMA5_MIGRATION_REQUIRED PASS'" \
    "'anchor_binding_match=false'" \
    "'device_guard_retained=true'" \
    'assert_core_schema5_post_quarantine_trace'
if grep -Fq '"$catalog_digest" \' <<<"$schema5_negative"; then
    fail 'schema-5 negative boot provisions TPM authority with the profile-2 catalog'
fi
[[ $(grep -Fc 'NEXUS_CONTAINER_HOST_UNIX_SOCKET' <<<"$container_function") == 1 ]] \
    || fail 'container runner must declare the host Unix socket policy once'
[[ $(grep -Fc 'NEXUS_CONTAINER_HOST_UNIX_SOCKET' <<<"$persistent_guest") == 1 ]] \
    || fail 'persistent production capture must select the host Unix socket policy once'
grep -Fq 'NEXUS_CONTAINER_HOST_UNIX_SOCKET=1 container bash -c' \
    <<<"$persistent_guest" \
    || fail 'persistent production guest does not select the host Unix socket policy'
require_ordered_tokens "$container_function" 'TPM fixture container policy' \
    'if [[ ${NEXUS_CONTAINER_HOST_UNIX_SOCKET:-0} == 1 ]]; then' \
    'security_args=(--security-opt label=disable)' \
    'if command "$docker_bin" info --format' \
    "| grep -Fq 'name=apparmor'; then" \
    'security_args+=(--security-opt apparmor=unconfined)' \
    'command "$docker_bin" run --rm' \
    '"${security_args[@]}"' \
    '--network none'
for forbidden_container_option in --privileged --cap-add --device; do
    if grep -Fq -- "$forbidden_container_option" <<<"$container_function"; then
        fail "TPM fixture container policy grants forbidden option: $forbidden_container_option"
    fi
done

echo "CSER_CORE_PRODUCTION_CUTOVER PASS manifest_sources=${#closure_sources[@]} portable_core=nonoptional api_profile=3 catalog_version=7 projection_version=7 snapshot_version=3 journal_schema=7 default=cser-production registry=single operation_effect=shared component_custody=reply+dma production_service_tasks=1 legacy_runtime_estates=false task_bound_ingress=true post_exit_fence=true production_rebind=true vnext_portal=true vnext_supervisor=true volatile_transitions=false evidence_schemes=reply+dma boots=4 shared_media=true tpm_fixture_policy=scoped"
