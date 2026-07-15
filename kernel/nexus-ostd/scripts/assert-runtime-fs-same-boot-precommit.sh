#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

die() {
    echo "runtime filesystem same-boot precommit assertion: FAIL: $*" >&2
    exit 1
}

if (( $# != 2 )); then
    die "usage: $0 SERIAL_LOG QEMU_DEBUG_LOG"
fi

serial_log=$1
debug_log=$2
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
oracle="$script_dir/assert-runtime-fs-same-boot-precommit.awk"

for input in "$serial_log" "$debug_log" "$oracle"; do
    [[ -f "$input" && ! -L "$input" ]] ||
        die "not a regular non-symlink input: $input"
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

inject_target_prefix_activity() {
    local input=$1
    local output=$2
    local injection=$3
    awk -v injection="$injection" '
        { line[NR] = $0 }
        END {
            for (i = 1; i + 6 <= NR; i++) {
                if (line[i] ~ /^virtio_set_status .* val 0\r?$/ &&
                    line[i + 1] ~ /^virtio_set_status .* val 0\r?$/ &&
                    line[i + 2] ~ /^virtio_set_status .* val 0\r?$/ &&
                    line[i + 3] ~ /^virtio_set_status .* val 0\r?$/ &&
                    line[i + 4] ~ /^virtio_set_status .* val 3\r?$/ &&
                    line[i + 5] ~ /^virtio_set_status .* val 11\r?$/ &&
                    line[i + 6] ~ /^virtio_set_status .* val 15\r?$/) {
                    target = i
                    matches++
                }
            }
            if (matches != 1)
                exit 2
            for (i = 1; i <= NR; i++) {
                print line[i]
                if (i == target + 1)
                    print injection
            }
        }
    ' "$input" >"$output"
}

remove_first_target_reset_status() {
    local input=$1
    local output=$2
    awk '
        { line[NR] = $0 }
        END {
            for (i = 1; i + 6 <= NR; i++) {
                if (line[i] ~ /^virtio_set_status .* val 0\r?$/ &&
                    line[i + 1] ~ /^virtio_set_status .* val 0\r?$/ &&
                    line[i + 2] ~ /^virtio_set_status .* val 0\r?$/ &&
                    line[i + 3] ~ /^virtio_set_status .* val 0\r?$/ &&
                    line[i + 4] ~ /^virtio_set_status .* val 3\r?$/ &&
                    line[i + 5] ~ /^virtio_set_status .* val 11\r?$/ &&
                    line[i + 6] ~ /^virtio_set_status .* val 15\r?$/) {
                    target = i
                    matches++
                }
            }
            if (matches != 1)
                exit 2
            for (i = target + 7; i <= NR; i++) {
                if (line[i] ~ /^virtio_set_status .* val 0\r?$/) {
                    reset = i
                    break
                }
            }
            if (!reset)
                exit 2
            for (i = 1; i <= NR; i++)
                if (i != reset)
                    print line[i]
        }
    ' "$input" >"$output"
}

awk '
    !changed && /^LINUX_FS_SAME_BOOT_PRECOMMIT CommitGate / {
        sub(/publish_closure_calls=0/, "publish_closure_calls=1")
        changed = 1
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/published-closure.log"
require_mutation "$serial_log" "$work/published-closure.log" published-closure
require_rejection published-closure "$work/published-closure.log" "$debug_log"

awk '
    !removed && /^LINUX_FS_SAME_BOOT_PRECOMMIT Abort / {
        removed = 1
        next
    }
    { print }
    END { if (!removed) exit 2 }
' "$serial_log" >"$work/missing-abort.log"
require_mutation "$serial_log" "$work/missing-abort.log" missing-Abort
require_rejection missing-Abort "$work/missing-abort.log" "$debug_log"

awk '
    /^LINUX_FS_SAME_BOOT_PRECOMMIT Abort / && !held {
        first = $0
        held = 1
        next
    }
    /^LINUX_FS_SAME_BOOT_PRECOMMIT Abort / && held == 1 {
        print
        print first
        held = 2
        next
    }
    { print }
    END { if (held != 2) exit 2 }
' "$serial_log" >"$work/reordered-aborts.log"
require_mutation "$serial_log" "$work/reordered-aborts.log" reordered-Aborts
require_rejection reordered-Aborts "$work/reordered-aborts.log" "$debug_log"

awk '
    !changed && /^LINUX_FS_SAME_BOOT_PRECOMMIT Abort / {
        sub(/result=-125/, "result=-5")
        changed = 1
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/wrong-errno.log"
require_mutation "$serial_log" "$work/wrong-errno.log" abort-errno
require_rejection abort-errno "$work/wrong-errno.log" "$debug_log"

awk '
    !changed && /^LINUX_FS_SAME_BOOT_PRECOMMIT DmaOwner / {
        sub(/effect=/, "effect=0")
        changed = 1
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/non-canonical-effect.log"
require_mutation "$serial_log" "$work/non-canonical-effect.log" non-canonical-effect
require_rejection non-canonical-effect "$work/non-canonical-effect.log" "$debug_log"

awk '
    !changed && /^LINUX_FS_SAME_BOOT_PRECOMMIT DmaOwner / {
        sub(/iova=0x[1-9a-f][0-9a-f]*000/, "&1")
        changed = 1
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/unaligned-owner.log"
require_mutation "$serial_log" "$work/unaligned-owner.log" unaligned-owner
require_rejection unaligned-owner "$work/unaligned-owner.log" "$debug_log"

awk '
    { print }
    !changed && /^LINUX_FS_SAME_BOOT_PRECOMMIT CommitGate / {
        print "LINUX_FS_SAME_BOOT Completion outcome=Completed result=4 used_len=513 payload_source=CompletedRequest data_prefix=7f454c46"
        changed = 1
    }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/positive-completion.log"
require_mutation "$serial_log" "$work/positive-completion.log" positive-Completion
require_rejection positive-Completion "$work/positive-completion.log" "$debug_log"

awk '
    { print }
    !changed && /^LINUX_FS_SAME_BOOT_PRECOMMIT CommitGate / {
        print "PRECOMMIT_FAULT avail_idx_release forbidden=true"
        changed = 1
    }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/avail-release.log"
require_mutation "$serial_log" "$work/avail-release.log" avail-idx-release
require_rejection avail-idx-release "$work/avail-release.log" "$debug_log"

awk '
    !changed && /^LINUX_FS_SAME_BOOT_PRECOMMIT CommitGate / {
        sub(/device_visible=false/, "device_visible=true")
        changed = 1
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/was-published.log"
require_mutation "$serial_log" "$work/was-published.log" was-published
require_rejection was-published "$work/was-published.log" "$debug_log"

awk '
    !changed && /^LINUX_FS_SAME_BOOT_PRECOMMIT GuestPublication / {
        sub(/bytes=0/, "bytes=1")
        changed = 1
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/guest-bytes.log"
require_mutation "$serial_log" "$work/guest-bytes.log" guest-bytes
require_rejection guest-bytes "$work/guest-bytes.log" "$debug_log"

owner_iova=$(awk '
    /^LINUX_FS_SAME_BOOT_PRECOMMIT DmaOwner / {
        for (i = 1; i <= NF; i++)
            if ($i ~ /^iova=0x[0-9a-f]+$/) {
                sub(/^iova=/, "", $i)
                print $i
                exit
            }
    }
' "$serial_log")
owner_paddr=$(awk '
    /^LINUX_FS_SAME_BOOT_PRECOMMIT DmaOwner / {
        for (i = 1; i <= NF; i++)
            if ($i ~ /^paddr=0x[0-9a-f]+$/) {
                sub(/^paddr=/, "", $i)
                print $i
                exit
            }
    }
' "$serial_log")
[[ $owner_iova == 0x* && $owner_paddr == 0x* ]] ||
    die "could not extract a prepared owner IOVA/paddr"

awk -v iova="$owner_paddr" -v paddr="$owner_paddr" '
    BEGIN {
        print "vtd_dmar_translate dev 00:05.00 iova " iova \
            " -> gpa " paddr " mask 0xfff"
    }
    { print }
' "$debug_log" >"$work/firmware-non-owner-translation.log"
require_mutation \
    "$debug_log" "$work/firmware-non-owner-translation.log" firmware-non-owner-translation
require_acceptance firmware-non-owner-translation \
    "$serial_log" "$work/firmware-non-owner-translation.log"

awk '
    BEGIN {
        print "virtio_blk_handle_read vdev 0x1 req 0x2 sector 0 nsectors 1"
    }
    { print }
' "$debug_log" >"$work/firmware-read.log"
require_mutation "$debug_log" "$work/firmware-read.log" firmware-read
require_acceptance firmware-read "$serial_log" "$work/firmware-read.log"

awk -v iova="$owner_iova" -v paddr="$owner_paddr" '
    BEGIN {
        print "vtd_dmar_translate dev 00:05.00 iova " iova \
            " -> gpa " paddr " mask 0xfff"
    }
    { print }
' "$debug_log" >"$work/owned-translation.log"
require_mutation "$debug_log" "$work/owned-translation.log" owned-translation
require_rejection owned-translation "$serial_log" "$work/owned-translation.log"

owner_iova_alias="0x0${owner_iova#0x}"
awk -v iova="$owner_iova_alias" -v paddr="$owner_paddr" '
    BEGIN {
        print "vtd_dmar_translate dev 00:05.00 iova " iova \
            " -> gpa " paddr " mask 0xfff"
    }
    { print }
' "$debug_log" >"$work/owned-translation-alias.log"
require_mutation "$debug_log" "$work/owned-translation-alias.log" owned-translation-alias
require_rejection owned-translation-alias \
    "$serial_log" "$work/owned-translation-alias.log"

awk -v iova="$owner_paddr" -v paddr="$owner_paddr" '
    BEGIN {
        print "vtd_dmar_translate dev 00:05.00 iova " iova \
            " -> gpa " paddr " mask 0xfff trailing"
    }
    { print }
' "$debug_log" >"$work/malformed-translation.log"
require_mutation "$debug_log" "$work/malformed-translation.log" malformed-translation
require_rejection malformed-translation \
    "$serial_log" "$work/malformed-translation.log"

inject_target_prefix_activity \
    "$debug_log" "$work/target-prefix-notify.log" \
    'virtio_pci_notify_write 0x0 = 0x0 (2)'
require_mutation "$debug_log" "$work/target-prefix-notify.log" target-prefix-notify
require_rejection target-prefix-notify \
    "$serial_log" "$work/target-prefix-notify.log"

inject_target_prefix_activity \
    "$debug_log" "$work/target-prefix-read.log" \
    'virtio_blk_handle_read vdev 0x1 req 0x2 sector 0 nsectors 1'
require_mutation "$debug_log" "$work/target-prefix-read.log" target-prefix-read
require_rejection target-prefix-read "$serial_log" "$work/target-prefix-read.log"

cp "$debug_log" "$work/late-notify.log"
printf '%s\n' 'virtio_pci_notify_write 0x0 = 0x0 (2)' \
    >>"$work/late-notify.log"
require_mutation "$debug_log" "$work/late-notify.log" late-notify
require_rejection late-notify "$serial_log" "$work/late-notify.log"

cp "$debug_log" "$work/late-queue.log"
printf '%s\n' 'virtio_queue_notify vdev 0x1 n 0 vq 0x2' \
    >>"$work/late-queue.log"
require_mutation "$debug_log" "$work/late-queue.log" late-queue
require_rejection late-queue "$serial_log" "$work/late-queue.log"

cp "$debug_log" "$work/late-read.log"
printf '%s\n' \
    'virtio_blk_handle_read vdev 0x1 req 0x2 sector 0 nsectors 1' \
    >>"$work/late-read.log"
require_mutation "$debug_log" "$work/late-read.log" late-read
require_rejection late-read "$serial_log" "$work/late-read.log"

remove_first_target_reset_status \
    "$debug_log" "$work/missing-reset-status.log"
require_mutation "$debug_log" "$work/missing-reset-status.log" missing-reset-status
require_rejection missing-reset-status \
    "$serial_log" "$work/missing-reset-status.log"

awk '
    !removed_global && /^vtd_inv_desc_iotlb_global / {
        removed_global = 1
        next
    }
    removed_global && !removed_wait && /^vtd_inv_desc_wait_irq / {
        removed_wait = 1
        next
    }
    { print }
    END { if (!removed_global || !removed_wait) exit 2 }
' "$debug_log" >"$work/missing-iotlb-pair.log"
require_mutation "$debug_log" "$work/missing-iotlb-pair.log" missing-IOTLB-pair
require_rejection missing-IOTLB-pair "$serial_log" "$work/missing-iotlb-pair.log"

awk '
    { print }
    !changed && /^LINUX_FS_SAME_BOOT_PRECOMMIT PASS / {
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
    /^LINUX_FS_SAME_BOOT_PRECOMMIT PASS / {
        removed++
        next
    }
    { print }
    END { if (removed != 1) exit 2 }
' "$serial_log" >"$work/missing-precommit-pass.log"
require_mutation "$serial_log" "$work/missing-precommit-pass.log" missing-precommit-PASS
require_rejection missing-precommit-PASS \
    "$work/missing-precommit-pass.log" "$debug_log"

awk '
    /^LINUX_FS_SAME_BOOT_PRECOMMIT Terminal / {
        removed++
        next
    }
    { print }
    END { if (removed != 1) exit 2 }
' "$serial_log" >"$work/missing-terminal.log"
require_mutation "$serial_log" "$work/missing-terminal.log" missing-Terminal
require_rejection missing-Terminal "$work/missing-terminal.log" "$debug_log"

awk '
    !changed && /^LINUX_FS_SAME_BOOT_PRECOMMIT Terminal / {
        sub(/registry=shared_production/, "registry=detached")
        changed = 1
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/non-quiescent-terminal.log"
require_mutation "$serial_log" "$work/non-quiescent-terminal.log" non-quiescent-Terminal
require_rejection non-quiescent-Terminal \
    "$work/non-quiescent-terminal.log" "$debug_log"

awk '
    !changed && /^RUNTIME_FS_SAME_BOOT_PRECOMMIT_FIXTURE / {
        sub(/before=[0-9a-f]+/, "before=0000000000000000000000000000000000000000000000000000000000000000")
        changed = 1
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/changed-fixture-sha.log"
require_mutation "$serial_log" "$work/changed-fixture-sha.log" fixture-SHA
require_rejection fixture-SHA "$work/changed-fixture-sha.log" "$debug_log"

awk '
    !changed && /^RUNTIME_FS_SAME_BOOT_PRECOMMIT_FIXTURE / {
        sub(/mode=444/, "mode=644")
        changed = 1
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/changed-fixture-mode.log"
require_mutation "$serial_log" "$work/changed-fixture-mode.log" fixture-mode
require_rejection fixture-mode "$work/changed-fixture-mode.log" "$debug_log"

awk '
    {
        print
        if (/^RUNTIME_FS_SAME_BOOT_PRECOMMIT_FIXTURE /) {
            print
            duplicated++
        }
    }
    END { if (duplicated != 1) exit 2 }
' "$serial_log" >"$work/duplicate-fixture.log"
require_mutation "$serial_log" "$work/duplicate-fixture.log" duplicate-fixture
require_rejection duplicate-fixture "$work/duplicate-fixture.log" "$debug_log"

cp "$serial_log" "$work/duplicate-pass.log"
grep -F -m1 'LINUX_FS_SAME_BOOT_PRECOMMIT PASS ' "$serial_log" \
    >>"$work/duplicate-pass.log"
require_mutation "$serial_log" "$work/duplicate-pass.log" duplicate-PASS
require_rejection duplicate-PASS "$work/duplicate-pass.log" "$debug_log"

awk '
    !changed && /^LINUX_FS_SLICE PASS / {
        sub(/precommit_fault=true/, "precommit_fault=false")
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
        print
        if (/^LINUX_FS_SLICE PASS /) {
            print
            duplicated++
        }
    }
    END { if (duplicated != 1) exit 2 }
' "$serial_log" >"$work/duplicate-slice-pass.log"
require_mutation "$serial_log" "$work/duplicate-slice-pass.log" duplicate-slice-PASS
require_rejection duplicate-slice-PASS \
    "$work/duplicate-slice-pass.log" "$debug_log"

[[ $mutations == 32 ]] || die "internal mutation count drifted: $mutations"
echo 'runtime filesystem same-boot precommit serial/debug assertions: PASS prepared_owner_retained=true was_published=false owner_iova_translations=0 target_notify=false target_read=false target_completion=false reset_retry=true iotlb_retry=true leaf_first=true guest_result=-125 guest_bytes=0 aggregate_slice_pass=true feature_terminal=true legacy_successors=false immutable_fixture=true mutations=32'
