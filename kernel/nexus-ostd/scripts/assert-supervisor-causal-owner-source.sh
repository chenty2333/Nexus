#!/usr/bin/bash -p
set -euo pipefail

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
readonly PATH
script_root=$(cd "$(/usr/bin/dirname "$0")/.." && pwd)
source_file=${1:-$script_root/src/cser/supervisor_runtime.rs}
lib_file=${2:-$script_root/src/lib.rs}
readme_file=${3:-$script_root/README.md}

fail() {
    echo "supervisor causal owner source assertion failed: $*" >&2
    exit 1
}

for input in "$source_file" "$lib_file" "$readme_file"; do
    [[ -f $input && ! -L $input ]] ||
        fail "source must be a regular non-symlink file: $input"
done

fixed_count() {
    grep -F -c -- "$2" "$1" || true
}

require_count() {
    local observed
    observed=$(fixed_count "$1" "$2")
    [[ $observed == "$3" ]] ||
        fail "expected $3 occurrence(s) of '$2' in $1, observed $observed"
}

require_at_least() {
    local observed
    observed=$(fixed_count "$1" "$2")
    ((observed >= $3)) ||
        fail "expected at least $3 occurrence(s) of '$2' in $1, observed $observed"
}

reject_fixed() {
    ! grep -F -- "$2" "$1" >/dev/null ||
        fail "forbidden source fragment '$2' in $1"
}

line_of_unique() {
    local -a matches=()
    mapfile -t matches < <(grep -nF -- "$2" "$1" || true)
    ((${#matches[@]} == 1)) ||
        fail "expected one source anchor '$2' in $1, observed ${#matches[@]}"
    printf '%s\n' "${matches[0]%%:*}"
}

extract_between() {
    local file=$1 start_pattern=$2 end_pattern=$3 output=$4 start end
    start=$(line_of_unique "$file" "$start_pattern")
    end=$(line_of_unique "$file" "$end_pattern")
    ((start < end)) || fail "invalid source boundary '$start_pattern' -> '$end_pattern'"
    sed -n "${start},$((end - 1))p" "$file" >"$output"
    [[ -s $output ]] || fail "empty source block '$start_pattern'"
}

extract_function() {
    local file=$1 start_pattern=$2 end_pattern=$3 output=$4 start end
    start=$(line_of_unique "$file" "$start_pattern")
    end=$(line_of_unique "$file" "$end_pattern")
    ((start < end)) || fail "invalid function boundary '$start_pattern' -> '$end_pattern'"
    sed -n "${start},$((end - 1))p" "$file" >"$output"
    [[ -s $output ]] || fail "empty function block '$start_pattern'"
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Evidence is deliberately raw observation. Authority coordinates are supplied
# only by the future armed bearer/Registry transition.
extract_between "$source_file" \
    'pub(crate) enum OstdUserFaultEvidence {' \
    'impl OstdUserFaultEvidence {' \
    "$work/user-fault.rs"
require_count "$work/user-fault.rs" 'instruction_pointer:' 2
require_count "$work/user-fault.rs" 'address:' 1
require_count "$work/user-fault.rs" 'access:' 1
require_count "$work/user-fault.rs" 'architecture_error:' 2
require_count "$work/user-fault.rs" 'evidence_digest:' 2
for forbidden in TaskKey vm_generation DomainKey binding_epoch ServiceIdentity ScopeKey; do
    reject_fixed "$work/user-fault.rs" "$forbidden"
done

extract_between "$source_file" \
    'pub(crate) struct OstdServiceExitEvidence {' \
    'impl OstdServiceExitEvidence {' \
    "$work/service-exit.rs"
require_count "$work/service-exit.rs" 'reason:' 1
require_count "$work/service-exit.rs" 'evidence_digest:' 1
for forbidden in TaskKey vm_generation DomainKey binding_epoch ServiceIdentity ScopeKey; do
    reject_fixed "$work/service-exit.rs" "$forbidden"
done
require_count "$source_file" '    UserFault(OstdUserFaultEvidence),' 1
require_count "$source_file" '    ServiceExit(OstdServiceExitEvidence),' 1
require_count "$source_file" 'MissingUserFaultEvidence' 3
require_count "$source_file" 'UnexpectedUserFaultEvidence' 2

extract_between "$source_file" \
    'enum CausalServiceTaskOwnerState<Armed, Committed> {' \
    'impl<Armed, Committed> CausalServiceTaskOwnerState<Armed, Committed> {' \
    "$work/owner-state.rs"
require_count "$work/owner-state.rs" '    Empty,' 1
require_count "$work/owner-state.rs" '    Armed {' 1
require_count "$work/owner-state.rs" '    ArmedWithExit {' 1
require_count "$work/owner-state.rs" '    Reaped {' 1
require_count "$work/owner-state.rs" '    Committed {' 1
require_count "$work/owner-state.rs" '    Retained {' 1
reject_fixed "$work/owner-state.rs" '__cser_core::clone::Clone'
reject_fixed "$work/owner-state.rs" '__cser_core::marker::Copy'

owner_line=$(line_of_unique "$source_file" 'pub(crate) struct CausalServiceTaskOwner<')
owner_prefix=$(sed -n "$((owner_line - 3)),$((owner_line - 1))p" "$source_file")
if grep -Eq '__cser_core::(clone::Clone|marker::Copy)' <<<"$owner_prefix"; then
    fail 'CausalServiceTaskOwner must not implement Clone or Copy'
fi
require_count "$source_file" 'pub(crate) fn install_armed(' 1
require_count "$source_file" 'pub(crate) fn observe_exit(' 1
require_count "$source_file" 'pub(crate) fn observe_reaped(' 1
require_count "$source_file" 'pub(crate) fn resolve_reaped_with<' 1
require_count "$source_file" 'pub(crate) fn retain_committed(' 1
require_count "$source_file" 'bearer: Some(bearer),' 2
require_count "$source_file" 'Err(CausalServiceTaskOwnerTransitionFailure::Transition(error))' 1
require_count "$source_file" 'CausalServiceTaskOwnerPhase::Retained' 3

require_count "$source_file" 'const MAX_RETAINED_SERVICE_TASK_OWNERS: usize = 4;' 1
extract_between "$source_file" \
    'enum CausalRetainedOwnerEntry {' \
    'struct CausalRetainedOwnerTableState {' \
    "$work/retained-entry.rs"
require_count "$work/retained-entry.rs" '    Vacant,' 1
require_count "$work/retained-entry.rs" '    Reserved {' 1
require_count "$work/retained-entry.rs" '    Published {' 1
require_count "$work/retained-entry.rs" '    Retained {' 1
require_count "$work/retained-entry.rs" 'owner: Arc<CausalServiceTaskOwner>' 2
require_count "$source_file" 'owner: Arc::clone(owner),' 2
require_count "$source_file" 'owner.phase() == CausalServiceTaskOwnerPhase::Retained' 1

require_count "$lib_file" 'supervisor_causal_owner: Option<Arc<supervisor_runtime::CausalServiceTaskOwner>>,' 1
require_count "$lib_file" 'supervisor_causal_owner: Arc<supervisor_runtime::CausalServiceTaskOwner>,' 1
require_count "$source_file" 'causal_owner: Option<Arc<CausalServiceTaskOwner>>' 1
require_count "$source_file" 'causal_owner_reservation: Option<CausalRetainedOwnerReservation>' 1
require_at_least "$source_file" 'Arc::new(CausalServiceTaskOwner::new_empty())' 2

extract_function "$source_file" \
    'fn publish_replacement(&mut self, replacement: ServiceIdentity)' \
    'fn request_stop_replacement(' \
    "$work/publish-replacement.rs"
publish_line=$(line_of_unique "$work/publish-replacement.rs" '.publish(&owner)')
run_line=$(line_of_unique "$work/publish-replacement.rs" 'task.run();')
((publish_line < run_line)) || fail 'replacement publication must precede Task::run'
extract_function "$source_file" \
    'fn publish_initial_active(' \
    'fn rollback_initial_active(' \
    "$work/publish-initial.rs"
publish_initial_line=$(line_of_unique "$work/publish-initial.rs" '.publish(&owner)')
active_line=$(line_of_unique "$work/publish-initial.rs" 'slot.phase = ReplacementSlotPhase::Active;')
((publish_initial_line < active_line)) || fail 'initial publication state follows retained-owner publication'

extract_function "$source_file" \
    'fn construct_replacement(&mut self, launch: ReplacementLaunch)' \
    'fn discard_unpublished_replacement(' \
    "$work/construct-replacement.rs"
reserve_line=$(line_of_unique "$work/construct-replacement.rs" 'self.shared.retained_owners.reserve()')
task_options_line=$(line_of_unique "$work/construct-replacement.rs" 'let built = TaskOptions::new')
((reserve_line < task_options_line)) || fail 'retained capacity must be reserved before task construction'

require_count "$source_file" '.crash_domain(self.scope, self.domain, service_task(service))?' 1
reject_fixed "$source_file" 'crash_causal_domain'
require_fixed_readme='gate reports `adapter_wired=false`, `source_mapped=false`, and `observed=false`.'
grep -F -- "$require_fixed_readme" "$readme_file" >/dev/null ||
    fail 'existing OSTD evidence status was promoted by the owner foundation'

if [[ ${NEXUS_SUPERVISOR_CAUSAL_OWNER_PRIMARY_ONLY:-0} != 1 ]]; then
    mutations=0
    require_mutation() {
        ((mutations += 1))
        ! cmp -s -- "$source_file" "$1" || fail "mutation did not change source: $2"
    }
    require_rejection() {
        if NEXUS_SUPERVISOR_CAUSAL_OWNER_PRIMARY_ONLY=1 bash "$0" "$1" "$lib_file" "$readme_file" >/dev/null 2>&1; then
            fail "source gate accepted mutation: $2"
        fi
    }

    cp "$source_file" "$work/cloneable-owner.rs"
    sed -i '/pub(crate) struct CausalServiceTaskOwner</i #[derive(__cser_core::clone::Clone)]' "$work/cloneable-owner.rs"
    require_mutation "$work/cloneable-owner.rs" cloneable-owner
    require_rejection "$work/cloneable-owner.rs" cloneable-owner

    cp "$source_file" "$work/authority-in-evidence.rs"
    sed -i '/pub(crate) enum OstdUserFaultEvidence {/,/impl OstdUserFaultEvidence {/ {
        /instruction_pointer: u64,/a\        binding_epoch: u64,
        /binding_epoch/!b
        :done
    }' "$work/authority-in-evidence.rs"
    require_mutation "$work/authority-in-evidence.rs" authority-in-evidence
    require_rejection "$work/authority-in-evidence.rs" authority-in-evidence

    cp "$source_file" "$work/no-retained-publication.rs"
    sed -i '0,/\.publish(\&owner)/s//.publish_removed(\&owner)/' "$work/no-retained-publication.rs"
    require_mutation "$work/no-retained-publication.rs" no-retained-publication
    require_rejection "$work/no-retained-publication.rs" no-retained-publication

    cp "$source_file" "$work/causal-crash-bypass.rs"
    sed -i '0,/\.crash_domain(self.scope, self.domain, service_task(service))?/s//.crash_causal_domain(self.scope, self.domain, service_task(service))?/' "$work/causal-crash-bypass.rs"
    require_mutation "$work/causal-crash-bypass.rs" causal-crash-bypass
    require_rejection "$work/causal-crash-bypass.rs" causal-crash-bypass

    cp "$lib_file" "$work/no-owner-arc.rs"
    sed -i 's/supervisor_causal_owner: Option<Arc<supervisor_runtime::CausalServiceTaskOwner>>,/supervisor_causal_owner: Option<()>,/' "$work/no-owner-arc.rs"
    require_mutation "$work/no-owner-arc.rs" no-owner-arc
    if NEXUS_SUPERVISOR_CAUSAL_OWNER_PRIMARY_ONLY=1 bash "$0" "$source_file" "$work/no-owner-arc.rs" "$readme_file" >/dev/null 2>&1; then
        fail 'source gate accepted mutation: no-owner-arc'
    fi

    [[ $mutations == 5 ]] || fail "expected 5 mutation checks, observed $mutations"
fi

echo 'supervisor causal owner source assertions: PASS states=6 evidence=typed+authority-free retained_capacity=4 publish_before_run=true reserve_before_construct=true backend_unwired=true evidence_status=unchanged mutations=5'
