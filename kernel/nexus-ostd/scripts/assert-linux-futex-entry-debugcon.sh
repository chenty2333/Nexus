#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

die() {
    echo "Linux futex entry debugcon assertion: FAIL: $*" >&2
    exit 1
}

if (( $# != 1 )); then
    die "usage: $0 TASK_ENTRY_DEBUGCON_LOG"
fi

log=$1
[[ -f $log && ! -L $log ]] || die "not a regular non-symlink log: $log"

oracle() {
    local bytes
    bytes=$(wc -c <"$1")
    if (( bytes != 16 )); then
        echo "Linux futex entry debugcon oracle: FAIL: expected exactly 16 bytes, found $bytes" >&2
        return 1
    fi
    awk '
        function fail(message) {
            print "Linux futex entry debugcon oracle: FAIL: " message > "/dev/stderr"
            exit 1
        }
        {
            if (NR != 1 || length($0) != 16 || $0 !~ /^[0-9a-f]+$/)
                fail("debugcon stream is not one exact 16-byte hex record")
            for (position = 1; position <= length($0); position++) {
                marker = substr($0, position, 1)
                code = index("0123456789abcdef", marker) - 1
                task = code % 4
                current_rank = int(code / 4) + 1
                if (current_rank != last_rank[task] + 1)
                    fail("task boundary is missing, duplicated, or reordered: " marker)
                last_rank[task] = current_rank
                counts[task]++
                total++
                if (task == 1 && current_rank == 4) waker_complete_position = position
                if (task == 0 && current_rank == 1) waiter_start_position = position
                if (task == 0 && current_rank == 4) waiter_complete_position = position
                if ((task == 2 || task == 3) && current_rank == 1 && effect_start_position == 0)
                    effect_start_position = position
            }
        }
        END {
            if (NR != 1 || total != 16)
                fail("expected exactly 16 first-entry boundary records")
            for (task = 0; task < 4; task++) {
                if (counts[task] != 4 || last_rank[task] != 4)
                    fail("task did not close all four entry boundaries: " task)
            }
            if (!(waker_complete_position < waiter_start_position &&
                  waiter_complete_position < effect_start_position))
                fail("debugcon task admission order disagrees with the staged protocol")
        }
    ' "$1"
}

oracle "$log"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

sed 's/5//' "$log" >"$work/missing-trampoline.log"
if oracle "$work/missing-trampoline.log" >/dev/null 2>&1; then
    die "oracle accepted a missing post-IRQ trampoline boundary"
fi

sed 's/9/X/; s/d/9/; s/X/d/' "$log" >"$work/reordered-identity.log"
if oracle "$work/reordered-identity.log" >/dev/null 2>&1; then
    die "oracle accepted identity validation before closure entry"
fi

sed 's/1/11/' "$log" >"$work/duplicate-boundary.log"
if oracle "$work/duplicate-boundary.log" >/dev/null 2>&1; then
    die "oracle accepted a duplicate first-entry boundary"
fi

sed 's/1/z/' "$log" >"$work/foreign-task.log"
if oracle "$work/foreign-task.log" >/dev/null 2>&1; then
    die "oracle accepted a foreign task identity"
fi

awk '{ moved = $0; sub(/2/, "", moved); sub(/0/, "02", moved); print moved }' \
    "$log" >"$work/effect-before-waiter-complete.log"
if oracle "$work/effect-before-waiter-complete.log" >/dev/null 2>&1; then
    die "oracle accepted an effect task before the waiter entry closed"
fi

cp "$log" "$work/trailing-newline.log"
printf '\n' >>"$work/trailing-newline.log"
if oracle "$work/trailing-newline.log" >/dev/null 2>&1; then
    die "oracle accepted a trailing byte outside the exact debugcon record"
fi

echo 'Linux futex entry debugcon assertions: PASS tasks=510+511+512+513 boundaries=post-vm-pre-irq+post-irq-entry+closure-entered+identity-validated encoding=single-byte-hex bytes=16 records=16 sink=isa-debugcon mutations=6'
