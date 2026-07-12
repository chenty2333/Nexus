#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
kernel_log=${1:-$root/kernel/nexus-ostd/artifacts/serial.log}
virtio_log=${2:-$root/experiments/ostd-virtio-cser-spike/artifacts/kernel.log}
artifact=${3:-$root/target/verification/linux-io-composition-oracle.log}
kernel_scripts="$root/kernel/nexus-ostd/scripts"
fs_oracle="$kernel_scripts/assert-linux-fs.awk"
net_oracle="$kernel_scripts/assert-linux-net.awk"
linux_io_oracle="$kernel_scripts/assert-linux-io-composition.sh"
stage5b_oracle="$kernel_scripts/assert-composition.sh"

fail() {
    echo "linux I/O composition evidence assertion failed: $*" >&2
    return 1
}

require_exact_once() {
    local path=$1
    local wanted=$2
    local count
    count=$(awk -v wanted="$wanted" '
        { sub(/\r$/, "") }
        $0 == wanted { count++ }
        END { print count + 0 }
    ' "$path")
    [[ $count == 1 ]] || fail "expected one exact receipt, observed $count: $wanted"
}

check_evidence() {
    local observed_kernel=$1
    local observed_virtio=$2

    [[ -s $observed_kernel ]] || {
        fail "missing kernel receipt: $observed_kernel"
        return 1
    }
    [[ -s $observed_virtio ]] || {
        fail "missing Stage 5B receipt: $observed_virtio"
        return 1
    }
    awk -f "$fs_oracle" "$observed_kernel" || return 1
    awk -f "$net_oracle" "$observed_kernel" || return 1
    bash "$linux_io_oracle" "$observed_kernel" || return 1
    bash "$stage5b_oracle" "$observed_kernel" "$observed_virtio" || return 1
    require_exact_once "$observed_virtio" \
        'FIXTURE Hash before=27a4e8fed7b428b42ff04e3f62eadfe2e3f3310dac4e2fe8ecfff04be3cca254 after=27a4e8fed7b428b42ff04e3f62eadfe2e3f3310dac4e2fe8ecfff04be3cca254 readonly=true' || return 1
}

expect_reject() {
    local label=$1
    local observed_kernel=$2
    local observed_virtio=$3

    if check_evidence "$observed_kernel" "$observed_virtio" >/dev/null 2>&1; then
        fail "negative mutation was accepted: $label"
    fi
    echo "linux I/O composition negative assertion: PASS $label=rejected"
}

mutate_once() {
    local source=$1
    local destination=$2
    local pattern=$3
    local replacement=$4
    local prefix=
    if [[ $source == "$kernel_log" ]]; then
        prefix='LINUX_IO_COMPOSITION '
    fi

    awk -v pattern="$pattern" -v replacement="$replacement" -v prefix="$prefix" '
        !changed && (prefix == "" || index($0, prefix) == 1) && index($0, pattern) {
            before = $0
            sub(pattern, replacement)
            changed = ($0 != before)
        }
        { print }
        END { if (!changed) exit 1 }
    ' "$source" >"$destination"
}

main() {
    mkdir -p "$(dirname -- "$artifact")"
    {
        for oracle in "$fs_oracle" "$net_oracle" "$linux_io_oracle" "$stage5b_oracle"; do
            [[ -f $oracle ]] || {
                fail "missing oracle: $oracle"
                exit 1
            }
        done
        check_evidence "$kernel_log" "$virtio_log"

        local mutation_dir
        mutation_dir=$(mktemp -d)
        trap 'rm -rf "$mutation_dir"' EXIT

        cp "$kernel_log" "$mutation_dir/duplicate-pass.log"
        grep -F -m1 'LINUX_IO_COMPOSITION PASS ' "$kernel_log" \
            >>"$mutation_dir/duplicate-pass.log"
        expect_reject duplicate_pass "$mutation_dir/duplicate-pass.log" "$virtio_log"

        local label pattern replacement
        while IFS='|' read -r label pattern replacement; do
            [[ -n $label ]] || continue
            mutate_once \
                "$kernel_log" \
                "$mutation_dir/$label.log" \
                "$pattern" \
                "$replacement"
            expect_reject "$label" "$mutation_dir/$label.log" "$virtio_log"
        done <<'EOF'
wrong_domain_count|domains=7 effects=9|domains=6 effects=9
wrong_effect_count|effects=9 causal_nodes=10|effects=8 causal_nodes=10
wrong_edge_count|causal_edges=9 credit_classes=8|causal_edges=8 credit_classes=8
wrong_parent_edge|kind=BlockReq domain=virtio parent=FsOp|kind=BlockReq domain=virtio parent=FsSyscall
control_capacity|control_capacity=2|control_capacity=1
credit_units|credit_units=9 control_capacity=2|credit_units=8 control_capacity=2
non_atomic_network|atomic_batch=true|atomic_batch=false
buffer_released_early|buffer_visibility=ping buffer_credit=Held|buffer_visibility=ping buffer_credit=Free
wrong_readiness_cause|causal_net_effect=7 causal_net_commit_sequence=3|causal_net_effect=9 causal_net_commit_sequence=4
fabricated_guest_reply|GUEST_REPLIES fs=0 net=0|GUEST_REPLIES fs=0 net=1
mutating_stale_reject|result=StaleAuthority mutation=false|result=StaleAuthority mutation=true
live_child_receipt_escalation|kind=live_child_receipt domain=pager child_domain=scheduler result=LiveDescendant|kind=live_child_receipt domain=pager child_domain=scheduler result=Applied
duplicate_issue_escalation|kind=duplicate_issue domain=scheduler result=DuplicateReceipt|kind=duplicate_issue domain=scheduler result=Applied
tombstone_terminalize_escalation|action=Terminalize effect=6 tombstone=1 result=TombstoneActive|action=Terminalize effect=6 tombstone=1 result=Applied
wrong_virtio_fs_order|domain=virtio effect=6 kind=BlockReq terminal_sequence=3|domain=virtio effect=6 kind=BlockReq terminal_sequence=4
wrong_readiness_network_order|domain=readiness effect=8 kind=ReadinessWait terminal_sequence=5|domain=readiness effect=8 kind=ReadinessWait terminal_sequence=6
truncated_network_cohort|domain=network effects=7,9|domain=network effects=7
truncated_personality_cohort|domain=personality effects=1,2|domain=personality effects=1
wrong_receipt_revision|receipt_sequence=7 receipt_revision=7|receipt_sequence=7 receipt_revision=8
timeout_replay_accepted|kind=stale_timeout_replay|kind=accepted_timeout_replay
wrong_final_credits|credits_free=9 live=0|credits_free=8 live=0
retained_identity_escalation|retained_workload_identity=false|retained_workload_identity=true
retained_cohort_escalation|retained_effects_in_root_cohort=false|retained_effects_in_root_cohort=true
registry_binding_escalation|registry_multi_domain_binding=false|registry_multi_domain_binding=true
stage5b_same_boot_escalation|stage5b_same_boot=false|stage5b_same_boot=true
stage5b_identity_escalation|identity_preserving_stage5b=false|identity_preserving_stage5b=true
real_dma_escalation|real_dma_primary=false|real_dma_primary=true
network_breadth_escalation|smoltcp=false|smoltcp=true
EOF

        grep -Fv 'LINUX_FS_SLICE PASS ' "$kernel_log" \
            >"$mutation_dir/missing-retained-fs-pass.log"
        expect_reject \
            missing_retained_fs_pass \
            "$mutation_dir/missing-retained-fs-pass.log" \
            "$virtio_log"

        grep -Fv 'LINUX_NET_SLICE PASS ' "$kernel_log" \
            >"$mutation_dir/missing-retained-net-pass.log"
        expect_reject \
            missing_retained_net_pass \
            "$mutation_dir/missing-retained-net-pass.log" \
            "$virtio_log"

        mutate_once \
            "$virtio_log" \
            "$mutation_dir/stage5b-generation.log" \
            'RESET Fence old_generation=1 new_generation=2' \
            'RESET Fence old_generation=1 new_generation=3'
        expect_reject \
            wrong_stage5b_generation \
            "$kernel_log" \
            "$mutation_dir/stage5b-generation.log"

        mutate_once \
            "$virtio_log" \
            "$mutation_dir/stage5b-fixture.log" \
            '27a4e8fed7b428b42ff04e3f62eadfe2e3f3310dac4e2fe8ecfff04be3cca254' \
            '17a4e8fed7b428b42ff04e3f62eadfe2e3f3310dac4e2fe8ecfff04be3cca254'
        expect_reject \
            wrong_stage5b_fixture_digest \
            "$kernel_log" \
            "$mutation_dir/stage5b-fixture.log"

        echo 'LINUX_IO_COMPOSITION_EVIDENCE PASS domains=7 effects=9 causal_nodes=10 causal_edges=9 credit_classes=8 credit_units=9 same_root_effects=true same_boot_kernel_adapters=true retained_workloads_same_boot=true retained_workload_identity=false retained_effects_in_root_cohort=false filesystem_recovery=companion network_recovery=companion registry_multi_domain_binding=false stage5b_relation=component_consistency stage5b_same_boot=false identity_preserving_stage5b=false real_dma_primary=false cross_fd_total_order=false bounded=true single_cpu=true'

        rm -rf "$mutation_dir"
        trap - EXIT
    } 2>&1 | tee "$artifact"
}

main "$@"
