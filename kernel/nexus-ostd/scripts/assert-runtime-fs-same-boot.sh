#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

die() {
    echo "runtime filesystem same-boot assertion: FAIL: $*" >&2
    exit 1
}

if (( $# != 2 )); then
    die "usage: $0 SERIAL_LOG QEMU_DEBUG_LOG"
fi

serial_log=$1
debug_log=$2
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
oracle="$script_dir/assert-runtime-fs-same-boot.awk"

for input in "$serial_log" "$debug_log" "$oracle"; do
    [[ -f "$input" && ! -L "$input" ]] || die "not a regular non-symlink input: $input"
done
[[ -s "$serial_log" ]] || die "empty serial input: $serial_log"
[[ -s "$debug_log" ]] || die "empty QEMU debug input: $debug_log"

awk -f "$oracle" "$serial_log" "$debug_log"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mutations=0

require_mutation() {
    if cmp -s "$1" "$2"; then
        die "negative fixture did not mutate $3"
    fi
}

require_rejection() {
    local label=$1
    local candidate_serial=$2
    local candidate_debug=$3
    if awk -f "$oracle" "$candidate_serial" "$candidate_debug" \
        >/dev/null 2>&1; then
        die "oracle accepted $label mutation"
    fi
    mutations=$((mutations + 1))
}

require_acceptance() {
    local label=$1
    local candidate_serial=$2
    local candidate_debug=$3
    if ! awk -f "$oracle" "$candidate_serial" "$candidate_debug" \
        >/dev/null 2>&1; then
        die "oracle rejected $label acceptance-preserving control"
    fi
}

awk '
    !changed && /^LINUX_FS_SAME_BOOT Capture / {
        sub(/real_dma=true/, "real_dma=false")
        changed = 1
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/not-real-dma.log"
require_mutation "$serial_log" "$work/not-real-dma.log" real-dma
require_rejection not-real-dma "$work/not-real-dma.log" "$debug_log"

cp "$serial_log" "$work/duplicate-pass.log"
grep -F -m1 'LINUX_FS_SAME_BOOT PASS ' "$serial_log" \
    >>"$work/duplicate-pass.log"
require_mutation "$serial_log" "$work/duplicate-pass.log" duplicate-PASS
require_rejection duplicate-PASS "$work/duplicate-pass.log" "$debug_log"

awk '
    !changed && /^LINUX_FS_SAME_BOOT DmaOwner / {
        sub(/iova=0x[0-9a-f]+/, "iova=0xdeadbeef")
        changed = 1
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/unbound-owner.log"
require_mutation "$serial_log" "$work/unbound-owner.log" owner-IOVA
require_rejection unbound-owner "$work/unbound-owner.log" "$debug_log"

awk '
    /^virtio_blk_handle_read / {
        removed++
        next
    }
    { print }
    END { if (removed == 0) exit 2 }
' "$debug_log" >"$work/missing-read.log"
require_mutation "$debug_log" "$work/missing-read.log" missing-read
require_rejection missing-read "$serial_log" "$work/missing-read.log"

cp "$debug_log" "$work/write-trace.log"
printf '%s\n' \
    'virtio_blk_handle_write vdev 0x1 req 0x2 sector 0 nsectors 1' \
    >>"$work/write-trace.log"
require_mutation "$debug_log" "$work/write-trace.log" write-trace
require_rejection write-trace "$serial_log" "$work/write-trace.log"

awk '
    { print }
    !changed && /^LINUX_FS_SAME_BOOT PASS / {
        print "LINUX_NET_SLICE BEGIN forbidden_feature_successor=true"
        changed = 1
    }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/legacy-successor.log"
require_mutation "$serial_log" "$work/legacy-successor.log" legacy-successor
require_rejection legacy-successor "$work/legacy-successor.log" "$debug_log"

awk '
    {
        line = $0
        sub(/\r$/, "", line)
    }
    line == "SPIKE_RESULT PASS" {
        removed++
        next
    }
    { print }
    END { if (removed != 1) exit 2 }
' "$serial_log" >"$work/missing-spike-result.log"
require_mutation "$serial_log" "$work/missing-spike-result.log" missing-SPIKE_RESULT
require_rejection missing-SPIKE_RESULT "$work/missing-spike-result.log" "$debug_log"

awk '
    {
        print
        line = $0
        sub(/\r$/, "", line)
        if (line == "SPIKE_RESULT PASS") {
            print
            duplicated++
        }
    }
    END { if (duplicated != 1) exit 2 }
' "$serial_log" >"$work/duplicate-spike-result.log"
require_mutation "$serial_log" "$work/duplicate-spike-result.log" duplicate-SPIKE_RESULT
require_rejection duplicate-SPIKE_RESULT "$work/duplicate-spike-result.log" "$debug_log"

awk '
    /^LINUX_FS_SERVICE Prepare / {
        removed++
        next
    }
    { print }
    END { if (removed != 1) exit 2 }
' "$serial_log" >"$work/missing-service-prepare.log"
require_mutation "$serial_log" "$work/missing-service-prepare.log" missing-service-Prepare
require_rejection missing-service-Prepare \
    "$work/missing-service-prepare.log" "$debug_log"

awk '
    {
        print
        if (/^LINUX_FS_SERVICE Crash /) {
            print
            duplicated++
        }
    }
    END { if (duplicated != 1) exit 2 }
' "$serial_log" >"$work/duplicate-service-crash.log"
require_mutation "$serial_log" "$work/duplicate-service-crash.log" duplicate-service-Crash
require_rejection duplicate-service-Crash \
    "$work/duplicate-service-crash.log" "$debug_log"

awk '
    /^LINUX_FS_SERVICE Snapshot / {
        held = $0
        next
    }
    /^LINUX_FS_SERVICE Ready / && held != "" {
        print
        print held
        held = ""
        swapped++
        next
    }
    { print }
    END { if (swapped != 1 || held != "") exit 2 }
' "$serial_log" >"$work/reordered-service-recovery.log"
require_mutation \
    "$serial_log" "$work/reordered-service-recovery.log" reordered-service-recovery
require_rejection reordered-service-recovery \
    "$work/reordered-service-recovery.log" "$debug_log"

awk '
    !changed && /^FSD_V1 EXIT / {
        sub(/task_generation=1/, "task_generation=2")
        changed = 1
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/wrong-v1-generation.log"
require_mutation "$serial_log" "$work/wrong-v1-generation.log" wrong-v1-generation
require_rejection wrong-v1-generation "$work/wrong-v1-generation.log" "$debug_log"

awk '
    !changed && /^LINUX_FS_SERVICE Crash / {
        sub(/cohort=1/, "cohort=2")
        changed = 1
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/wrong-service-cohort.log"
require_mutation "$serial_log" "$work/wrong-service-cohort.log" wrong-service-cohort
require_rejection wrong-service-cohort "$work/wrong-service-cohort.log" "$debug_log"

awk '
    !changed && /^LINUX_FS_SLICE PASS / {
        sub(/real_user_service_crash=true/, "real_user_service_crash=false")
        changed = 1
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/non-witness-slice-pass.log"
require_mutation "$serial_log" "$work/non-witness-slice-pass.log" non-witness-slice-PASS
require_rejection non-witness-slice-PASS \
    "$work/non-witness-slice-pass.log" "$debug_log"

awk '
    {
        line[NR] = $0
        if ($0 ~ /^FSD_V2 EXIT /) {
            v2 = NR
            v2_count++
        }
        if ($0 ~ /^LINUX_FS_SAME_BOOT GuestPublication /) {
            publication = NR
            publication_count++
        }
        if ($0 ~ /^LINUX_FS_SLICE PASS /) {
            slice = NR
            slice_count++
        }
    }
    END {
        if (v2_count != 1 || publication_count != 1 || slice_count != 1)
            exit 2
        move_after_slice = v2 < publication
        for (i = 1; i <= NR; i++) {
            if (i == v2)
                continue
            if (!move_after_slice && i == publication)
                print line[v2]
            print line[i]
            if (move_after_slice && i == slice)
                print line[v2]
        }
    }
' "$serial_log" >"$work/alternate-v2-schedule.log"
require_mutation "$serial_log" "$work/alternate-v2-schedule.log" alternate-v2-schedule
require_acceptance alternate-v2-schedule \
    "$work/alternate-v2-schedule.log" "$debug_log"

[[ $mutations == 14 ]] || die "internal mutation count drifted: $mutations"
echo 'runtime filesystem same-boot serial/debug assertions: PASS real_user_service_crash=true fsd_task_key=current-task-bound+951:1->951:2 replacement_construction=post-crash distinct_task_vm=true guest_admission=receipt-before-armed crash_cohort=filesystem_read_only delayed_old_prepare=true stale_prepare_failure_atomic=true old_sender_current_handle=NoSupervisor exact_six_effect_cohort=true owner_iommu_binding=true commit_point=avail_idx_release completion_source=CompletedRequest reset_retry=true iotlb_retry=true leaf_first=true reply_wakeups=1 guest_publication_after_closure=true aggregate_slice_pass=true feature_terminal=true legacy_successors=false immutable_fixture=true mutations=14'
