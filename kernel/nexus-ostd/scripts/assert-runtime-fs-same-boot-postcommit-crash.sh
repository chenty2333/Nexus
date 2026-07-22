#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

die() {
    echo "runtime filesystem same-boot postcommit assertion: FAIL: $*" >&2
    exit 1
}

if (( $# != 2 )); then
    die "usage: $0 SERIAL_LOG QEMU_DEBUG_LOG"
fi

serial_log=$1
debug_log=$2
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
oracle=$script_dir/assert-runtime-fs-same-boot-postcommit-crash.awk

for input in "$serial_log" "$debug_log" "$oracle"; do
    [[ -f $input && ! -L $input ]] ||
        die "not a regular non-symlink input: $input"
done
for command_name in awk cmp cp grep mktemp rm; do
    command -v "$command_name" >/dev/null 2>&1 ||
        die "missing command: $command_name"
done
[[ -s $serial_log ]] || die "empty serial input: $serial_log"
[[ -s $debug_log ]] || die "empty QEMU debug input: $debug_log"

awk -f "$oracle" "$serial_log" "$debug_log"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mutations=0

require_mutation() {
    ! cmp -s -- "$1" "$2" || die "negative fixture did not mutate $3"
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

mutate_postcommit_field() {
    local event=$1
    local name=$2
    local before=$3
    local after=$4
    local output=$5
    awk -v event="$event" -v name="$name" -v before="$before" -v after="$after" '
        $1 == "LINUX_FS_POSTCOMMIT" && $2 == event && !changed {
            for (i = 3; i <= NF; i++) {
                token = $i
                suffix = ""
                if (sub(/\r$/, "", token))
                    suffix = "\r"
                if (token == name "=" before) {
                    $i = name "=" after suffix
                    changed = 1
                    break
                }
            }
        }
        { print }
        END { if (!changed) exit 2 }
    ' "$serial_log" >"$output"
}

awk '
    /^LINUX_FS_POSTCOMMIT Crash / { removed++; next }
    { print }
    END { if (removed != 1) exit 2 }
' "$serial_log" >"$work/missing-crash.log"
require_mutation "$serial_log" "$work/missing-crash.log" missing-Crash
require_rejection missing-Crash "$work/missing-crash.log" "$debug_log"

cp -- "$serial_log" "$work/duplicate-pass.log"
grep -F -m1 'LINUX_FS_POSTCOMMIT PASS ' "$serial_log" \
    >>"$work/duplicate-pass.log"
require_mutation "$serial_log" "$work/duplicate-pass.log" duplicate-PASS
require_rejection duplicate-PASS "$work/duplicate-pass.log" "$debug_log"

awk '
    /^LINUX_FS_POSTCOMMIT Crash / { held = $0; next }
    /^LINUX_FS_POSTCOMMIT FreshTrigger / && held != "" {
        print
        print held
        held = ""
        moved++
        next
    }
    { print }
    END { if (moved != 1 || held != "") exit 2 }
' "$serial_log" >"$work/reordered-crash.log"
require_mutation "$serial_log" "$work/reordered-crash.log" reordered-Crash
require_rejection reordered-Crash "$work/reordered-crash.log" "$debug_log"

for mutation in \
    'Crash phase Closing Active active-scope' \
    'Crash pending_publications 1 0 missing-publication' \
    'Crash causal_state Active Closed inactive-crash-causal' \
    'Crash guest_reply false true early-reply' \
    'FreshTrigger registry_task false true registry-bearing-trigger' \
    'FreshTrigger registry_replacement false true replacement-claim' \
    'FreshTrigger causal_service_task_facade_observed false true facade-claim' \
    'FreshTrigger causal_fault_matrix_promotion false true fault-matrix-claim' \
    'StaleProbe result StaleAuthority StaleBinding wrong-stale-result' \
    'StaleProbe registry_projection_unchanged true false changed-projection' \
    'StaleProbe flight_identity_unchanged true false changed-flight' \
    'StaleProbe causal_identity_unchanged true false changed-causal' \
    'StaleProbe recommit false true recommit' \
    'WakeTrigger same_ticket true false replaced-ticket' \
    'WakeTrigger reply_wakeups 1 2 duplicate-wakeup' \
    'WakeTrigger original_guest_publication_pending true false lost-original-publication' \
    'CausalPublication before_close Active Closed close-before-active-check' \
    'CausalPublication after_close Closed Active missing-close' \
    'CausalPublication outer_ack_apply true false missing-outer-ack' \
    'CausalPublication after_outer_ack Vacant Closed premature-clear-claim' \
    'CausalPublication publication_actor original_guest fsd-v3 wrong-causal-publisher' \
    'GuestPublication actor original_guest fsd-v3 wrong-guest-publisher' \
    'PASS prebackend_crash false true prebackend-claim' \
    'PASS causal_publication_transition Active,Closed,Vacant Active,Vacant missing-closed-state' \
    'PASS v3_registry_replacement false true pass-replacement-claim'; do
    read -r event name before after label <<<"$mutation"
    output=$work/$label.log
    mutate_postcommit_field "$event" "$name" "$before" "$after" "$output"
    require_mutation "$serial_log" "$output" "$label"
    require_rejection "$label" "$output" "$debug_log"
done

awk '
    $1 == "LINUX_FS_POSTCOMMIT" && $2 == "StaleProbe" && !changed {
        for (i = 3; i <= NF; i++) {
            if ($i ~ /^flight_cookie=[1-9][0-9]*$/) {
                $i = $i "0"
                changed = 1
                break
            }
        }
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial_log" >"$work/changed-flight-cookie.log"
require_mutation "$serial_log" "$work/changed-flight-cookie.log" changed-flight-cookie
require_rejection changed-flight-cookie "$work/changed-flight-cookie.log" "$debug_log"

awk '
    {
        line[NR] = $0
        if ($0 ~ /^LINUX_FS_POSTCOMMIT StaleProbe /) {
            stale = NR
            stale_count++
        }
        if ($0 ~ /^LINUX_FS_POSTCOMMIT WakeTrigger /) {
            wake = NR
            wake_count++
        }
    }
    END {
        if (stale_count != 1 || wake_count != 1 || stale >= wake)
            exit 2
        for (i = 1; i <= NR; i++) {
            if (i == stale)
                continue
            if (i == wake)
                print line[i]
            if (i == wake)
                print line[stale]
            else
                print line[i]
        }
    }
' "$serial_log" >"$work/reordered-stale-wake.log"
require_mutation "$serial_log" "$work/reordered-stale-wake.log" reordered-stale-wake
require_rejection reordered-stale-wake "$work/reordered-stale-wake.log" "$debug_log"

awk '
    {
        line = $0
        sub(/\r$/, "", line)
    }
    line == "SPIKE_RESULT PASS" { removed++; next }
    { print }
    END { if (removed != 1) exit 2 }
' "$serial_log" >"$work/missing-spike.log"
require_mutation "$serial_log" "$work/missing-spike.log" missing-SPIKE_RESULT
require_rejection missing-SPIKE_RESULT "$work/missing-spike.log" "$debug_log"

awk '
    /^RUNTIME_FS_SAME_BOOT_POSTCOMMIT_FIXTURE / { removed++; next }
    { print }
    END { if (removed != 1) exit 2 }
' "$serial_log" >"$work/missing-fixture.log"
require_mutation "$serial_log" "$work/missing-fixture.log" missing-fixture
require_rejection missing-fixture "$work/missing-fixture.log" "$debug_log"

awk '
    {
        line[NR] = $0
        if ($0 ~ /^virtio_blk_rw_complete /)
            completion_line[++completions] = NR
    }
    END {
        if (completions == 0)
            exit 2
        for (i = 1; i <= NR; i++)
            if (i != completion_line[completions])
                print line[i]
    }
' "$debug_log" >"$work/missing-backend-completion.log"
require_mutation "$debug_log" "$work/missing-backend-completion.log" \
    missing-backend-completion
require_rejection missing-backend-completion "$serial_log" \
    "$work/missing-backend-completion.log"

awk '
    {
        line[NR] = $0
        if ($0 ~ /^virtio_blk_handle_read /)
            read_line[++reads] = NR
    }
    END {
        if (reads == 0)
            exit 2
        for (i = 1; i <= NR; i++) {
            print line[i]
            if (i == read_line[reads])
                print line[i]
        }
    }
' "$debug_log" >"$work/duplicate-device-read.log"
require_mutation "$debug_log" "$work/duplicate-device-read.log" duplicate-device-read
require_rejection duplicate-device-read "$serial_log" "$work/duplicate-device-read.log"

cp -- "$debug_log" "$work/device-write.log"
printf '%s\n' \
    'virtio_blk_handle_write vdev 0x1 req 0x2 sector 0 nsectors 1' \
    >>"$work/device-write.log"
require_mutation "$debug_log" "$work/device-write.log" device-write
require_rejection device-write "$serial_log" "$work/device-write.log"

[[ $mutations == 35 ]] ||
    die "internal mutation count drifted: $mutations"
echo 'runtime filesystem same-boot postcommit crash serial/debug assertions: PASS boundary=post-backend-pre-publication causal_state=Active fresh_v3=registry-free-closure-trigger stale_v2=StaleAuthority registry_projection_unchanged=true flight_identity_unchanged=true causal_identity_unchanged=true original_v2_publication=true causal_transition=Active,Closed,Vacant close_before_outer_ack=true clear_after_outer_ack=true runtime_outer_ack_failure=false runtime_fault_matrix=false runtime_service_task_facade=false prebackend_claim=false lost_ack_claim=false real_dma=true polling=true irq=false smp=1 mutations=35'
