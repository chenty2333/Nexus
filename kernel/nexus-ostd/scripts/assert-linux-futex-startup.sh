#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

die() {
    echo "Linux futex startup assertion: FAIL: $*" >&2
    exit 1
}

if (( $# != 1 )); then
    die "usage: $0 SERIAL_LOG"
fi

serial_log=$1
[[ -f $serial_log && ! -L $serial_log ]] || die "not a regular non-symlink serial log: $serial_log"
[[ -s $serial_log ]] || die "empty serial log: $serial_log"

oracle() {
    awk '
    function fail(message) {
        print "Linux futex startup serial oracle: FAIL: " message > "/dev/stderr"
        failed = 1
        exit 1
    }
    function field(name,    i, prefix) {
        prefix = name "="
        for (i = 1; i <= NF; i++) {
            if (index($i, prefix) == 1)
                return substr($i, length(prefix) + 1)
        }
        return ""
    }
    function decimal(value, label) {
        if (value !~ /^[0-9]+$/)
            fail("malformed " label "=" value)
        return value + 0
    }
    {
        sub(/\r$/, "")
    }
    /^LINUX_FUTEX_SCENARIO BEGIN scenario=expire / {
        begin_count++
        begin_line = NR
    }
    /^LINUX_FUTEX_STARTUP TaskEntry scenario=expire / {
        if (NF != 6 || $2 != "TaskEntry" || $3 != "scenario=expire")
            fail("malformed startup task-entry receipt: " $0)
        stage = field("stage")
        role = field("role")
        task = decimal(field("task"), stage " task")
        if (stage == "waker-ready" && role == "waker" && task == 511) {
            waker_task_entry_count++
            waker_task_entry_line = NR
        } else if (stage == "wait-captured" && role == "waiter" && task == 510) {
            waiter_task_entry_count++
            waiter_task_entry_line = NR
        } else {
            fail("unknown startup task-entry identity: " $0)
        }
    }
    /^LINUX_FUTEX_STARTUP Receipt scenario=expire / {
        if (NF != 14 || $2 != "Receipt" || $3 != "scenario=expire" ||
            $8 != "timing=diagnostic" || $9 != "internal_timeout=false" ||
            $10 != "failure_bound=outer-qemu-timeout" ||
            $11 != "handshake=wait-queue" ||
            $12 != "spawn_preemption=disabled-through-run" ||
            $13 != "publish=release" || $14 != "observe=acquire")
            fail("malformed startup receipt: " $0)
        stage = field("stage")
        start = decimal(field("start_tick"), stage " start_tick")
        observed = decimal(field("observed_tick"), stage " observed_tick")
        waited = decimal(field("waited_ticks"), stage " waited_ticks")
        if (observed < start || observed - start != waited)
            fail("startup timing diagnostic is not monotonic: " $0)
        if (stage == "waker-ready") {
            waker_ready_count++
            waker_ready_line = NR
        } else if (stage == "wait-captured") {
            wait_captured_count++
            wait_captured_line = NR
        } else {
            fail("unknown startup stage: " stage)
        }
    }
    /^LINUX_FUTEX GuestBlock scenario=expire role=waker .* gate=EnableWaker / {
        waker_guest_block_count++
        waker_guest_block_line = NR
    }
    /^LINUX_FUTEX Mismatch scenario=expire / { mismatch_line = NR }
    /^LINUX_FUTEX Capture scenario=expire kind=WAIT / { wait_capture_line = NR }
    /^LINUX_FUTEX GuestBlock scenario=expire role=waiter .* effect=1 / {
        waiter_guest_block_count++
        waiter_guest_block_line = NR
    }
    /^LINUX_FUTEX PortalResult scenario=expire action=WaitRegister .* result=Applied / {
        wait_register_line = NR
    }
    /^LINUX_FUTEX PortalResult scenario=expire action=EnableWaker .* result=Applied / {
        enable_waker_line = NR
    }
    /^LINUX_FUTEX Capture scenario=expire kind=WAKE / { wake_capture_line = NR }
    /^LINUX_FUTEX Crash scenario=expire / { crash_line = NR }
    /^LINUX_FUTEX WatchdogExpire scenario=expire / { watchdog_line = NR }
    END {
        if (failed)
            exit 1
        if (begin_count != 1 || waker_task_entry_count != 1 ||
            waiter_task_entry_count != 1 || waker_ready_count != 1 || wait_captured_count != 1 ||
            waker_guest_block_count != 1 || waiter_guest_block_count != 1)
            fail("expected one Expire begin, task entry, child block, and receipt for each startup stage")
        if (!(begin_line < waker_task_entry_line &&
              waker_task_entry_line < waker_guest_block_line &&
              waker_guest_block_line < waker_ready_line &&
              waker_ready_line < waiter_task_entry_line &&
              waiter_task_entry_line < mismatch_line &&
              mismatch_line < wait_capture_line &&
              wait_capture_line < waiter_guest_block_line &&
              waiter_guest_block_line < wait_captured_line &&
              wait_captured_line < wait_register_line &&
              wait_register_line < enable_waker_line &&
              enable_waker_line < wake_capture_line &&
              wake_capture_line < crash_line &&
              crash_line < watchdog_line))
            fail("startup or publish/recover receipt order is incomplete")
    }
' "$1"
}

oracle "$serial_log"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

awk '
    !removed && /^LINUX_FUTEX_STARTUP Receipt scenario=expire stage=waker-ready / {
        removed = 1
        next
    }
    { print }
    END { if (!removed) exit 2 }
' "$serial_log" >"$work/missing-waker-ready.log"
if oracle "$work/missing-waker-ready.log" >/dev/null 2>&1; then
    die "oracle accepted a missing waker-ready receipt"
fi

awk '
    { lines[NR] = $0 }
    /^LINUX_FUTEX_STARTUP Receipt scenario=expire stage=waker-ready / { waker = NR }
    /^LINUX_FUTEX_STARTUP Receipt scenario=expire stage=wait-captured / { waiter = NR }
    END {
        if (waker == 0 || waiter == 0) exit 2
        swapped = lines[waker]
        lines[waker] = lines[waiter]
        lines[waiter] = swapped
        for (line = 1; line <= NR; line++) print lines[line]
    }
' "$serial_log" >"$work/swapped-receipts.log"
if oracle "$work/swapped-receipts.log" >/dev/null 2>&1; then
    die "oracle accepted swapped startup receipts"
fi

sed '0,/handshake=wait-queue/s//handshake=yield-poll/' \
    "$serial_log" >"$work/yield-poll-receipt.log"
if oracle "$work/yield-poll-receipt.log" >/dev/null 2>&1; then
    die "oracle accepted a yield-poll startup receipt"
fi

awk '
    !removed && /^LINUX_FUTEX GuestBlock scenario=expire role=waker .* gate=EnableWaker / {
        removed = 1
        next
    }
    { print }
    END { if (!removed) exit 2 }
' "$serial_log" >"$work/missing-waker-entry.log"
if oracle "$work/missing-waker-entry.log" >/dev/null 2>&1; then
    die "oracle accepted a readiness receipt without the waker child-entry block"
fi

awk '
    !removed && /^LINUX_FUTEX_STARTUP TaskEntry scenario=expire stage=waker-ready / {
        removed = 1
        next
    }
    { print }
    END { if (!removed) exit 2 }
' "$serial_log" >"$work/missing-waker-task-entry.log"
if oracle "$work/missing-waker-task-entry.log" >/dev/null 2>&1; then
    die "oracle accepted a waker readiness receipt without TaskEntry"
fi

sed '0,/spawn_preemption=disabled-through-run/s//spawn_preemption=unguarded/' \
    "$serial_log" >"$work/unguarded-spawn-receipt.log"
if oracle "$work/unguarded-spawn-receipt.log" >/dev/null 2>&1; then
    die "oracle accepted an unguarded spawn-window receipt"
fi

sed '0,/internal_timeout=false/s//internal_timeout=true/' \
    "$serial_log" >"$work/internal-timeout-overclaim.log"
if oracle "$work/internal-timeout-overclaim.log" >/dev/null 2>&1; then
    die "oracle accepted an unimplemented guest-side startup timeout"
fi

echo "Linux futex staged-start assertions: PASS receipts=2 task_entries=2 child_entry_blocks=2 timing=diagnostic internal_timeout=false handshake=wait-queue spawn_preemption=disabled-through-run failure_bound=outer-qemu-timeout publish_recover_race=preserved mutations=7"
