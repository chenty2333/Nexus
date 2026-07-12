#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
repo_lock="/tmp/nexus-workflow-${root//\//_}.lock"
if [[ ${NEXUS_ROOT_LOCK_HELD:-0} != 1 ]]; then
    exec {repo_lock_fd}>"$repo_lock"
    flock "$repo_lock_fd"
fi
kernel_root="$root/kernel/nexus-ostd"
kernel_lock="/tmp/nexus-kernel-${kernel_root//\//_}.lock"
io_root="$root/experiments/ostd-virtio-cser-spike"
io_lock_key=$(printf '%s' "$io_root" | sha256sum | cut -c1-16)
io_lock="/tmp/nexus-ostd-virtio-cser-spike-$io_lock_key.lock"
composition_oracle="$root/kernel/nexus-ostd/scripts/assert-composition.sh"
virtio_oracle="$io_root/scripts/assert-serial.sh"

check_evidence() {
    local composition_log=$1
    local virtio_log=$2
    local virtio_debug_log=$3

    # This helper is deliberately an AND-list. Negative gates invoke it from an
    # `if` condition, where Bash suppresses errexit inside called functions.
    # The explicit list preserves the first oracle's nonzero result.
    "$virtio_oracle" "$virtio_log" "$virtio_debug_log" &&
        "$composition_oracle" "$composition_log" "$virtio_log"
}

expect_reject() {
    local label=$1
    local composition_log=$2
    local virtio_log=$3
    local virtio_debug_log=$4

    if check_evidence \
        "$composition_log" "$virtio_log" "$virtio_debug_log" >/dev/null 2>&1; then
        echo "system composition oracle accepted negative mutation: $label" >&2
        return 1
    fi
    echo "system composition negative assertion: PASS $label=rejected"
}

main() {
    local composition_log="$root/kernel/nexus-ostd/artifacts/serial.log"
    local virtio_log="$io_root/artifacts/kernel.log"
    local virtio_debug_log="$io_root/artifacts/qemu-debug.log"
    local artifact="$root/target/verification/system-composition-oracle.log"
    local kernel_lock_fd
    local io_lock_fd

    exec {kernel_lock_fd}>"$kernel_lock"
    flock "$kernel_lock_fd"
    exec {io_lock_fd}>"$io_lock"
    flock "$io_lock_fd"
    mkdir -p "$(dirname -- "$artifact")"
    {
        for executable in "$composition_oracle" "$virtio_oracle"; do
            if [[ ! -x "$executable" ]]; then
                echo "system composition oracle is missing or not executable: $executable" >&2
                exit 1
            fi
        done
        for evidence in "$composition_log" "$virtio_log" "$virtio_debug_log"; do
            if [[ ! -s "$evidence" ]]; then
                echo "system composition evidence is missing or empty: $evidence" >&2
                exit 1
            fi
        done

        check_evidence "$composition_log" "$virtio_log" "$virtio_debug_log"

        local mutation_dir
        mutation_dir=$(mktemp -d)
        trap 'rm -rf "$mutation_dir"' EXIT

        cp "$composition_log" "$mutation_dir/composition-duplicate-pass.log"
        grep -F -m1 'COMPOSITION_SLICE PASS ' "$composition_log" \
            >>"$mutation_dir/composition-duplicate-pass.log"
        expect_reject \
            duplicate_composition_pass \
            "$mutation_dir/composition-duplicate-pass.log" \
            "$virtio_log" \
            "$virtio_debug_log"

        awk '
            !changed && /^COMPOSITION_REJECT / && /kind=stale_receipt/ {
                changed = sub(/mutation=false/, "mutation=true")
            }
            { print }
            END { if (!changed) exit 1 }
        ' "$composition_log" >"$mutation_dir/composition-stale-receipt.log"
        expect_reject \
            mutating_stale_receipt \
            "$mutation_dir/composition-stale-receipt.log" \
            "$virtio_log" \
            "$virtio_debug_log"

        awk '
            !changed && /^COMPOSITION_CLOSURE (Issue|Receipt) / {
                changed = sub(/receipt_sequence=[0-9]+/, "receipt_sequence=999")
            }
            { print }
            END { if (!changed) exit 1 }
        ' "$composition_log" >"$mutation_dir/composition-wrong-sequence.log"
        expect_reject \
            wrong_closure_sequence \
            "$mutation_dir/composition-wrong-sequence.log" \
            "$virtio_log" \
            "$virtio_debug_log"

        awk '
            !changed && /RESET Fence old_generation=2 new_generation=3/ {
                changed = sub(/new_generation=3/, "new_generation=4")
            }
            { print }
            END { if (!changed) exit 1 }
        ' "$virtio_log" >"$mutation_dir/virtio-wrong-generation.log"
        expect_reject \
            wrong_virtio_generation \
            "$composition_log" \
            "$mutation_dir/virtio-wrong-generation.log" \
            "$virtio_debug_log"

        awk '
            !changed && /^vtd_inv_desc_iotlb_global / {
                changed = sub(/vtd_inv_desc_iotlb_global/, "vtd_inv_desc_iotlb_corrupt")
            }
            { print }
            END { if (!changed) exit 1 }
        ' "$virtio_debug_log" >"$mutation_dir/virtio-missing-iotlb.log"
        expect_reject \
            missing_iotlb_trace \
            "$composition_log" \
            "$virtio_log" \
            "$mutation_dir/virtio-missing-iotlb.log"

        rm -rf "$mutation_dir"
        trap - EXIT
    } 2>&1 | tee "$artifact"
    exec {io_lock_fd}>&-
    exec {kernel_lock_fd}>&-
}

main "$@"
