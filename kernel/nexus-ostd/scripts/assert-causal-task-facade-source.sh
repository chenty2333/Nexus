#!/usr/bin/bash -p
set -euo pipefail

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
readonly PATH
script_root=$(cd "$(/usr/bin/dirname "$0")/.." && pwd)
source_file=${1:-$script_root/src/cser/effect_registry/runtime_task.rs}

fail() {
    echo "causal task facade source assertion failed: $*" >&2
    exit 1
}

[[ -f $source_file && ! -L $source_file ]] || fail "source must be a regular non-symlink: $source_file"

require_count() {
    local file=$1 needle=$2 expected=$3 observed
    observed=$(grep -F -c -- "$needle" "$file" || true)
    [[ $observed == "$expected" ]] ||
        fail "expected $expected occurrences of '$needle', observed $observed"
}

reject_fixed() {
    local file=$1 needle=$2
    ! grep -F -- "$needle" "$file" >/dev/null || fail "forbidden source fragment: $needle"
}

require_order() {
    local file=$1 first=$2 second=$3 first_line second_line
    first_line=$(grep -F -n -m1 -- "$first" "$file" | cut -d: -f1)
    second_line=$(grep -F -n -m1 -- "$second" "$file" | cut -d: -f1)
    [[ -n $first_line && -n $second_line && $first_line -lt $second_line ]] ||
        fail "required order missing: '$first' before '$second'"
}

bearer_line=$(grep -F -n -m1 'pub(crate) struct CausalTaskBearer {' "$source_file" | cut -d: -f1)
[[ -n $bearer_line ]] || fail 'missing CausalTaskBearer'
bearer_derive=$(sed -n "$((bearer_line - 1))p" "$source_file")
[[ $bearer_derive == '#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]' ]] ||
    fail 'CausalTaskBearer gained Clone/Copy or lost its frozen derive set'

require_count "$source_file" '    workload: CausalWorkloadIdentity,' 1
require_count "$source_file" '    descriptor: CausalTaskDescriptor,' 3
require_count "$source_file" '    authority: CausalTaskAuthority,' 1
require_count "$source_file" '    Admitted(infrastructure::TaskLease),' 1
require_count "$source_file" '    Entered(infrastructure::EnteredTaskLease),' 1
require_count "$source_file" 'pub(crate) fn reserve_causal_task_work(' 1
require_count "$source_file" 'return Err(CausalTaskError::RequiresFaultComposite);' 1
require_count "$source_file" '.admit_task(&session.context, infrastructure_descriptor)' 1
require_order "$source_file" \
    'return Err(CausalTaskError::RequiresFaultComposite);' \
    '.admit_task(&session.context, infrastructure_descriptor)'
require_count "$source_file" 'pub(crate) fn claim_causal_task_entry(' 1
require_count "$source_file" 'if let Err(error) = self.validate_causal_task_bearer(session, selector, &bearer)' 4
require_count "$source_file" 'match self.infrastructure.claim_task_entry(authority)' 1
require_count "$source_file" 'match self.infrastructure.reject_task_construction(authority)' 1
require_count "$source_file" 'match self.infrastructure.isolate_entered_task(authority)' 1
require_count "$source_file" 'match self.infrastructure.reap_task(authority)' 1
require_count "$source_file" 'let (error, authority) = failure.into_parts();' 4
require_count "$source_file" 'pub(crate) fn query_causal_task(' 1
require_count "$source_file" '.query_task(&session.context, selector.work_id, selector.generation)' 2
require_count "$source_file" 'if bearer.workload.registry_instance != self.instance_id {' 1
require_count "$source_file" 'if bearer.workload != identity {' 1
require_count "$source_file" 'if bearer.descriptor.selector != selector {' 1
require_order "$source_file" \
    'let identity = self.validate_causal_task_session(session, TaskSessionAccess::Existing)?;' \
    'if bearer.workload.registry_instance != self.instance_id {'
reject_fixed "$source_file" 'use ostd::'
reject_fixed "$source_file" 'ostd::task'
reject_fixed "$source_file" 'Task::run('

if [[ ${NEXUS_CAUSAL_TASK_SOURCE_PRIMARY_ONLY:-0} != 1 ]]; then
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    mutations=0

    require_mutation() {
        ((mutations += 1))
        ! cmp -s -- "$source_file" "$1" || fail "mutation did not change source: $2"
    }

    require_rejection() {
        if NEXUS_CAUSAL_TASK_SOURCE_PRIMARY_ONLY=1 bash "$0" "$1" >/dev/null 2>&1; then
            fail "source gate accepted mutation: $2"
        fi
    }

    awk '
        /#\[derive\(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq\)\]/ {
            candidate = $0
            getline next_line
            if (!changed && next_line ~ /pub\(crate\) struct CausalTaskBearer \{/) {
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
    ' "$source_file" >"$work/cloneable-bearer.rs"
    require_mutation "$work/cloneable-bearer.rs" cloneable-bearer
    require_rejection "$work/cloneable-bearer.rs" cloneable-bearer

    cp "$source_file" "$work/foreign-registry-bypass.rs"
    sed -i '0,/bearer\.workload\.registry_instance != self\.instance_id/s//bearer.workload.registry_instance == self.instance_id/' \
        "$work/foreign-registry-bypass.rs"
    require_mutation "$work/foreign-registry-bypass.rs" foreign-registry-bypass
    require_rejection "$work/foreign-registry-bypass.rs" foreign-registry-bypass

    cp "$source_file" "$work/session-substitution.rs"
    sed -i '0,/bearer\.workload != identity/s//bearer.workload == identity/' \
        "$work/session-substitution.rs"
    require_mutation "$work/session-substitution.rs" session-substitution
    require_rejection "$work/session-substitution.rs" session-substitution

    cp "$source_file" "$work/no-entry-claim.rs"
    sed -i '0,/claim_task_entry(authority)/s//reject_task_construction(authority)/' \
        "$work/no-entry-claim.rs"
    require_mutation "$work/no-entry-claim.rs" no-entry-claim
    require_rejection "$work/no-entry-claim.rs" no-entry-claim

    cp "$source_file" "$work/admitted-isolation.rs"
    sed -i '0,/isolate_entered_task(authority)/s//isolate_task(authority)/' \
        "$work/admitted-isolation.rs"
    require_mutation "$work/admitted-isolation.rs" admitted-isolation
    require_rejection "$work/admitted-isolation.rs" admitted-isolation

    cp "$source_file" "$work/isolate-instead-of-reap.rs"
    sed -i '0,/reap_task(authority)/s//isolate_entered_task(authority)/' \
        "$work/isolate-instead-of-reap.rs"
    require_mutation "$work/isolate-instead-of-reap.rs" isolate-instead-of-reap
    require_rejection "$work/isolate-instead-of-reap.rs" isolate-instead-of-reap

    cp "$source_file" "$work/scheduler-dependency.rs"
    sed -i '1a use ostd::task::Task;' "$work/scheduler-dependency.rs"
    require_mutation "$work/scheduler-dependency.rs" scheduler-dependency
    require_rejection "$work/scheduler-dependency.rs" scheduler-dependency

    [[ $mutations == 7 ]] || fail "expected 7 mutations, observed $mutations"
fi

echo 'causal task facade source assertions: PASS bearer=opaque+linear admission=before-entry exact_session=true exact_selector=true retry_returns_bearer=true query=read-only scheduler_dependency=false ostd_wired=false evidence_promoted=false mutations=7'
