#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
kernel_log=${1:-$root/kernel/nexus-ostd/artifacts/serial.log}
virtio_log=${2:-$root/experiments/ostd-virtio-cser-spike/artifacts/kernel.log}
artifact=${3:-$root/target/verification/runtime-fs-composition-oracle.log}
guest_elf="$root/kernel/nexus-ostd/guest/linux-runtime-fs.elf"
source_file="$root/tests/guest/linux/sources/linux-runtime-fs-smoke/runtime_fs_smoke.S"
sector_asset="$root/experiments/ostd-virtio-cser-spike/assets/sector0.txt"
virtio_dockerfile="$root/experiments/ostd-virtio-cser-spike/Dockerfile"
fs_oracle="$root/kernel/nexus-ostd/scripts/assert-linux-fs.awk"

readonly source_sha=c5a4014d88794ddccd1c5239957a43500a6637a433640c2293e699fea72b870f
readonly elf_sha=0dc5ad40cb05e39592592ef3272ed45be4d71f9b147a534be20b9a5626c17bef
readonly input_sha=a101969acc8dac3209f8be33a5d070e5972fc82f49f5ef85e28db576068024fc
readonly payload_sha=3bdbb4fe8397cd2b842430b39ccff01a8663c751945ef5e9a09e267fb8b1d359
readonly preparation_sha=e3229d4050798eedcd6503e8b44c3e6bad6d1c105f07f79d3f4fbb04925f1f14
readonly sector_sha=9cb83be92a4c9239752718e6e20ac00fe9e32842ea561ae7fedec94b620a05cc
readonly image_sha=27a4e8fed7b428b42ff04e3f62eadfe2e3f3310dac4e2fe8ecfff04be3cca254
readonly sector_fnv=0xc4b4ad9059afd22e

fail() {
    echo "runtime filesystem composition assertion failed: $*" >&2
    return 1
}

require_exact_once() {
    local path=$1
    local line=$2
    local count
    count=$(awk -v wanted="$line" '
        { sub(/\r$/, "") }
        $0 == wanted { count++ }
        END { print count + 0 }
    ' "$path")
    [[ $count == 1 ]] || fail "expected one exact receipt, observed $count: $line"
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
    [[ -f $source_file && ! -L $source_file ]] || {
        fail "retained source is not regular"
        return 1
    }
    [[ -f $guest_elf && ! -L $guest_elf ]] || {
        fail "runtime-fs ELF is not regular"
        return 1
    }
    [[ -f $sector_asset && ! -L $sector_asset ]] || {
        fail "Stage 5B sector source is not regular"
        return 1
    }
    [[ $(sha256sum "$source_file" | cut -d ' ' -f1) == "$source_sha" ]] || {
        fail "retained source digest mismatch"
        return 1
    }
    [[ $(sha256sum "$guest_elf" | cut -d ' ' -f1) == "$elf_sha" ]] || {
        fail "runtime-fs ELF digest mismatch"
        return 1
    }
    [[ $(head -c 4 "$guest_elf" | sha256sum | cut -d ' ' -f1) == "$payload_sha" ]] || {
        fail "first pread payload digest mismatch"
        return 1
    }
    [[ $(printf '%s' 'pread64
fd=3
path=/bin/linux-runtime-fs-smoke
offset=0
length=4
' | sha256sum | cut -d ' ' -f1) == "$input_sha" ]] || {
        fail "first pread input digest mismatch"
        return 1
    }
    [[ $(printf '%s' 'nexus-cser-block-preparation-v1
inode=0x7101:1:1
block=0
offset=0
length=4
queue=0
writable=false
' | sha256sum | cut -d ' ' -f1) == "$preparation_sha" ]] || {
        fail "block preparation digest mismatch"
        return 1
    }
    local sector_asset_bytes
    local reconstructed_sector_sha
    sector_asset_bytes=$(wc -c <"$sector_asset")
    [[ $sector_asset_bytes == 30 ]] || {
        fail "Stage 5B sector source length mismatch"
        return 1
    }
    reconstructed_sector_sha=$(
        {
            head -c "$sector_asset_bytes" "$sector_asset"
            head -c "$((512 - sector_asset_bytes))" /dev/zero
        } | sha256sum | cut -d ' ' -f1
    )
    [[ $reconstructed_sector_sha == "$sector_sha" ]] || {
        fail "reconstructed Stage 5B sector digest mismatch"
        return 1
    }
    grep -Fq "$sector_sha" "$virtio_dockerfile" || {
        fail "Stage 5B Dockerfile lost the sector digest pin"
        return 1
    }
    grep -Fq "$image_sha" "$virtio_dockerfile" || {
        fail "Stage 5B Dockerfile lost the full-image digest pin"
        return 1
    }

    awk -f "$fs_oracle" "$observed_kernel" || return 1
    require_exact_once "$observed_kernel" \
        "LINUX_FS_ARTIFACT source_sha256=$source_sha elf_sha256=$elf_sha first_pread_input_sha256=$input_sha first_pread_payload_sha256=$payload_sha block_preparation_sha256=$preparation_sha sector_sha256=$sector_sha full_image_sha256=$image_sha sector_fnv1a=$sector_fnv relation=component_consistency real_stage5b_required=true same_boot=false identity_preserving_stage5b=false" || return 1
    require_exact_once "$observed_kernel" \
        'LINUX_FS_PRODUCTION_IDENTITY NoSyntheticCohort positive_cohort=normal_workload_path foreign_registry_receipt=CommitConflict foreign_receipt_accepted=false full_projection_unchanged=true negative_only_registry=true' || return 1
    require_exact_once "$observed_kernel" \
        'LINUX_FS_PRODUCTION_IDENTITY BlockPreparation effect=4 phase=Prepared terminal=Aborted terminal_sequence=2 preparation_only=true adapter=bounded_in_memory queue_credit_held=false pinned_page_credit_held=false dma_mapping_credit_held=false device_commit=false avail_idx_release=false returned_payload_source=runtime_fs_elf' || return 1
    require_exact_once "$observed_kernel" \
        'COMPOSITION_SLICE BEGIN root_scope=70 authority_epoch=121 domains=5 bounded=true single_cpu=true runtime_fs=false runtime_net=false virtio_adapter=external_stage5b_consistency' || return 1
    require_exact_once "$observed_virtio" \
        "IO Read magic_ok=true zero_tail=true fnv1a=$sector_fnv" || return 1
    require_exact_once "$observed_virtio" \
        "FIXTURE Hash before=$image_sha after=$image_sha readonly=true" || return 1

    if grep -E '^LINUX_FS.*(same_boot=true|identity_preserving=true|real_dma=true)' \
        "$observed_kernel" >/dev/null; then
        fail "filesystem evidence escalated an unestablished composition boundary"
        return 1
    fi
    return 0
}

expect_reject() {
    local label=$1
    local observed_kernel=$2
    local observed_virtio=$3

    if check_evidence "$observed_kernel" "$observed_virtio" >/dev/null 2>&1; then
        fail "negative mutation was accepted: $label"
    fi
    echo "runtime filesystem composition negative assertion: PASS $label=rejected"
}

main() {
    mkdir -p "$(dirname -- "$artifact")"
    {
        check_evidence "$kernel_log" "$virtio_log"

        local mutation_dir
        mutation_dir=$(mktemp -d)
        trap 'rm -rf "$mutation_dir"' EXIT

        cp "$kernel_log" "$mutation_dir/duplicate-pass.log"
        grep -F -m1 'LINUX_FS_SLICE PASS ' "$kernel_log" \
            >>"$mutation_dir/duplicate-pass.log"
        expect_reject duplicate_fs_pass "$mutation_dir/duplicate-pass.log" "$virtio_log"

        sed 's/elf_sha256=0dc5ad40/elf_sha256=1dc5ad40/' "$kernel_log" \
            >"$mutation_dir/wrong-elf-digest.log"
        expect_reject wrong_elf_digest "$mutation_dir/wrong-elf-digest.log" "$virtio_log"

        sed 's/block_preparation_sha256=e3229d40/block_preparation_sha256=f3229d40/' \
            "$kernel_log" >"$mutation_dir/wrong-preparation-digest.log"
        expect_reject wrong_preparation_digest \
            "$mutation_dir/wrong-preparation-digest.log" "$virtio_log"

        sed 's/foreign_receipt_accepted=false/foreign_receipt_accepted=true/' \
            "$kernel_log" >"$mutation_dir/foreign-receipt-accepted.log"
        expect_reject foreign_receipt_accepted \
            "$mutation_dir/foreign-receipt-accepted.log" "$virtio_log"

        sed 's/device_commit=false avail_idx_release=false/device_commit=true avail_idx_release=true/' \
            "$kernel_log" >"$mutation_dir/device-commit-escalation.log"
        expect_reject device_commit_escalation \
            "$mutation_dir/device-commit-escalation.log" "$virtio_log"

        sed 's/fnv1a=0xc4b4ad9059afd22e/fnv1a=0xc4b4ad9059afd22f/' "$virtio_log" \
            >"$mutation_dir/wrong-sector-fnv.log"
        expect_reject wrong_sector_payload "$kernel_log" "$mutation_dir/wrong-sector-fnv.log"

        sed 's/same_boot=false/same_boot=true/' "$kernel_log" \
            >"$mutation_dir/same-boot-escalation.log"
        expect_reject same_boot_escalation "$mutation_dir/same-boot-escalation.log" "$virtio_log"

        grep -Fv "FIXTURE Hash before=$image_sha" "$virtio_log" \
            >"$mutation_dir/missing-fixture-hash.log"
        expect_reject missing_fixture_hash "$kernel_log" "$mutation_dir/missing-fixture-hash.log"

        echo "RUNTIME_FS_COMPOSITION PASS source_sha256=$source_sha elf_sha256=$elf_sha input_sha256=$input_sha payload_sha256=$payload_sha preparation_sha256=$preparation_sha production_identity_preparation=true no_synthetic_cohort=true block_preparation_only=true device_commit=false sector_sha256=$sector_sha full_image_sha256=$image_sha sector_fnv1a=$sector_fnv relation=component_consistency predecessor_frozen_runtime_fs_false=true runtime_filesystem=true same_boot=false identity_preserving_stage5b=false real_dma_primary=false stage5b_real_virtio=true positive_oracle=true negative_oracles=8"

        rm -rf "$mutation_dir"
        trap - EXIT
    } 2>&1 | tee "$artifact"
}

main "$@"
