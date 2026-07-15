#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
serial=${1:-$root/artifacts/serial.log}
artifact=${2:-$root/../../target/verification/runtime-net-oracle.log}
oracle="$root/scripts/assert-linux-net.awk"

if [[ ! -s $serial ]]; then
    echo "runtime network serial evidence is missing or empty: $serial" >&2
    exit 1
fi
if [[ ! -f $oracle ]]; then
    echo "runtime network serial oracle is missing: $oracle" >&2
    exit 1
fi

tmp=$(mktemp -d)
artifact_tmp=
report="$tmp/report.log"
cleanup() {
    rm -rf "$tmp"
    if [[ -n $artifact_tmp ]]; then
        rm -f "$artifact_tmp"
    fi
}
trap cleanup EXIT

awk -f "$oracle" "$serial"
echo "runtime network serial positive assertion: PASS exact_semantic_transcript=true projection_pair_recomputed=true" | tee -a "$report"

negative_count=0
expect_reject() {
    local label=$1
    local mutated=$2
    if diff -q "$serial" "$mutated" >/dev/null; then
        echo "runtime network negative mutation made no change: $label" >&2
        exit 1
    fi
    if awk -f "$oracle" "$mutated" >/dev/null 2>&1; then
        echo "runtime network oracle accepted negative mutation: $label" >&2
        exit 1
    fi
    negative_count=$((negative_count + 1))
    echo "runtime network serial negative assertion: PASS $label=rejected" | tee -a "$report"
}

swap_first() {
    local first=$1
    local second=$2
    local output=$3
    awk -v first="$first" -v second="$second" '
        { lines[NR] = $0 }
        first_line == 0 && $0 ~ first { first_line = NR }
        second_line == 0 && $0 ~ second { second_line = NR }
        END {
            if (first_line == 0 || second_line == 0 || first_line == second_line)
                exit 2
            swapped = lines[first_line]
            lines[first_line] = lines[second_line]
            lines[second_line] = swapped
            for (line = 1; line <= NR; line++)
                print lines[line]
        }
    ' "$serial" >"$output"
}

sed '0,/syscalls=22/s//syscalls=23/' "$serial" >"$tmp/syscall-count.log"
expect_reject syscall_count "$tmp/syscall-count.log"

cp "$serial" "$tmp/duplicate-pass.log"
grep -m1 '^LINUX_NET_SLICE PASS ' "$serial" >>"$tmp/duplicate-pass.log"
expect_reject duplicate_slice_pass "$tmp/duplicate-pass.log"

sed '0,/elf_sha256=8cdd5864/s//elf_sha256=0cdd5864/' \
    "$serial" >"$tmp/elf-digest.log"
expect_reject elf_digest "$tmp/elf-digest.log"

awk '
    !removed && /^NETWORK_LIFECYCLE NetdCrash / { removed = 1; next }
    { print }
    END { if (!removed) exit 2 }
' "$serial" >"$tmp/missing-crash.log"
expect_reject missing_netd_crash "$tmp/missing-crash.log"

swap_first \
    '^NETWORK_LIFECYCLE Snapshot ' \
    '^NETWORK_LIFECYCLE Ready ' \
    "$tmp/snapshot-ready.log"
expect_reject snapshot_ready_order "$tmp/snapshot-ready.log"

swap_first \
    '^NETWORK_LIFECYCLE Adopt .* kind=accept ' \
    '^NETWORK_LIFECYCLE Adopt .* kind=readiness ' \
    "$tmp/adopt-order.log"
expect_reject adopt_order "$tmp/adopt-order.log"

awk '
    !changed && /^NETWORK_LIFECYCLE StaleReplay / {
        changed = sub(/mutation=false/, "mutation=true")
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial" >"$tmp/stale-mutation.log"
expect_reject stale_replay_mutation "$tmp/stale-mutation.log"

awk '
    !changed && /^NETWORK_LIFECYCLE StaleReplay / {
        for (field = 1; field <= NF; field++) {
            if ($field ~ /^projection_after=[0-9a-f]+$/) {
                digest = substr($field, length("projection_after=") + 1)
                first = substr(digest, 1, 1) == "0" ? "1" : "0"
                replacement = first substr(digest, 2)
                changed = sub("projection_after=" digest,
                              "projection_after=" replacement)
                break
            }
        }
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial" >"$tmp/stale-projection.log"
expect_reject stale_replay_projection_mismatch "$tmp/stale-projection.log"

swap_first \
    '^NETWORK_COMPANION READY_REVOKE Transition case=ready-first .* step=ReadyCommit ' \
    '^NETWORK_COMPANION READY_REVOKE Transition case=ready-first .* step=RevokeBegin ' \
    "$tmp/ready-revoke-order.log"
expect_reject ready_revoke_winner_order "$tmp/ready-revoke-order.log"

sed '0,/send_disposition=Drain/s//send_disposition=Abort/' \
    "$serial" >"$tmp/personality-disposition.log"
expect_reject personality_committed_drain "$tmp/personality-disposition.log"

sed '0,/guest_replies_after=0/s//guest_replies_after=1/' \
    "$serial" >"$tmp/buffer-reply.log"
expect_reject buffer_visible_reply_absent "$tmp/buffer-reply.log"

awk '
    !changed && /^NETWORK_COMPANION STALE_GENERATION PASS kind=socket / {
        changed = sub(/full_projection_unchanged=true/, "full_projection_unchanged=false")
    }
    { print }
    END { if (!changed) exit 2 }
' "$serial" >"$tmp/full-projection.log"
expect_reject stale_full_projection "$tmp/full-projection.log"

sed 's/smoltcp=false/smoltcp=true/g' \
    "$serial" >"$tmp/smoltcp-claim.log"
expect_reject smoltcp_claim_escalation "$tmp/smoltcp-claim.log"

sed 's/bounded_loopback=true/bounded_loopback=false/g' \
    "$serial" >"$tmp/bounded-loopback.log"
expect_reject bounded_loopback_downgrade "$tmp/bounded-loopback.log"

mkdir -p "$(dirname -- "$artifact")"
artifact_tmp="$(dirname -- "$artifact")/.runtime-net-oracle.$$.tmp"
cp "$report" "$artifact_tmp"
printf '%s\n' \
    "RUNTIME_NET_ORACLE PASS serial=kernel/nexus-ostd/artifacts/serial.log positive_oracle=true exact_semantic_transcript=true projection_pair_recomputed=true negative_oracles=$negative_count retained_syscalls=22 bounded_loopback=true single_cpu=true smoltcp=false virtio_net=false external_packets=false tcp_breadth=false" \
    >>"$artifact_tmp"
mv "$artifact_tmp" "$artifact"
artifact_tmp=
echo "runtime network evidence: PASS artifact=$artifact negative_oracles=$negative_count"
