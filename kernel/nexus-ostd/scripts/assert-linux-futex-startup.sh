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
        if (value !~ /^(0|[1-9][0-9]*)$/)
            fail("malformed " label "=" value)
        if (length(value) > 20 ||
            (length(value) == 20 && decimal_compare(value, "18446744073709551615") > 0))
            fail("out-of-range u64 " label "=" value)
        return value
    }
    function decimal_equal(left, right,    i) {
        if (length(left) != length(right))
            return 0
        for (i = 1; i <= length(left); i++) {
            if (substr(left, i, 1) != substr(right, i, 1))
                return 0
        }
        return 1
    }
    function decimal_compare(left, right,    i, left_digit, right_digit) {
        if (length(left) < length(right))
            return -1
        if (length(left) > length(right))
            return 1
        for (i = 1; i <= length(left); i++) {
            left_digit = substr(left, i, 1) + 0
            right_digit = substr(right, i, 1) + 0
            if (left_digit < right_digit)
                return -1
            if (left_digit > right_digit)
                return 1
        }
        return 0
    }
    function decimal_subtract(left, right,    i, left_digit, right_digit, digit, borrow, result) {
        if (decimal_compare(left, right) < 0)
            fail("decimal subtraction underflow: " left " - " right)
        borrow = 0
        result = ""
        for (i = 0; i < length(left); i++) {
            left_digit = substr(left, length(left) - i, 1) + 0
            if (i < length(right))
                right_digit = substr(right, length(right) - i, 1) + 0
            else
                right_digit = 0
            digit = left_digit - right_digit - borrow
            if (digit < 0) {
                digit += 10
                borrow = 1
            } else {
                borrow = 0
            }
            result = digit result
        }
        sub(/^0+/, "", result)
        if (result == "")
            result = "0"
        return result
    }
    {
        sub(/\r$/, "")
    }
    /^LINUX_FUTEX_SCENARIO BEGIN scenario=expire / {
        begin_count++
        begin_line = NR
    }
    /^CSER FallbackPick authority_epoch=41 binding_epoch=4 / {
        task = decimal(field("task"), "fallback task")
        cause = field("cause")
        if (cause !~ /^(tick|wait-or-exit|yield|best-effort)$/)
            fail("Expire startup used an unknown selection cause: " $0)
        if (begin_count == 1 && decimal_equal(task, "511") &&
            waker_task_entry_count == 0 && waker_pick_count == 0) {
            waker_pick_count++
            waker_pick_line = NR
        } else if (begin_count == 1 && decimal_equal(task, "510") &&
                   waiter_task_entry_count == 0 && waiter_pick_count == 0) {
            waiter_pick_count++
            waiter_pick_line = NR
        } else if (wait_captured_count == 1 && decimal_equal(task, "512") &&
                   v1_task_entry_count == 0 && v1_pick_count == 0) {
            v1_pick_count++
            v1_pick_line = NR
        } else if (wait_captured_count == 1 && decimal_equal(task, "513") &&
                   watchdog_task_entry_count == 0 && watchdog_pick_count == 0) {
            watchdog_pick_count++
            watchdog_pick_line = NR
        }
    }
    /^LINUX_FUTEX_STARTUP (PreSwitch|PostSwitch) scenario=expire / {
        fail("switch-critical path emitted a serial diagnostic: " $0)
    }
    /^LINUX_FUTEX_STARTUP TaskEntry scenario=expire / {
        if (NF != 14 || $2 != "TaskEntry" || $3 != "scenario=expire" ||
            $4 !~ /^stage=(waker-ready|wait-captured|effect-driver|closure-watchdog)$/ ||
            $5 !~ /^role=(waker|waiter|personality-v1|watchdog)$/ || $6 !~ /^task=/ ||
            $7 != "source=ostd-trampoline" || $8 != "post_vm_pre_irq=true" ||
            $9 != "post_irq_entry=true" || $10 != "closure_entered=true" ||
            $11 != "identity_validated=true" || $12 != "debugcon=true" ||
            $13 != "reported_by=parent" ||
            $14 !~ /^observation=(semantic-ready|completion)$/)
            fail("malformed startup task-entry receipt: " $0)
        stage = field("stage")
        role = field("role")
        task = decimal(field("task"), stage " task")
        observation = field("observation")
        if (stage == "waker-ready" && role == "waker" && decimal_equal(task, "511") &&
            observation == "semantic-ready") {
            waker_task_entry_count++
            waker_task_entry_line = NR
        } else if (stage == "wait-captured" && role == "waiter" &&
                   decimal_equal(task, "510") && observation == "semantic-ready") {
            waiter_task_entry_count++
            waiter_task_entry_line = NR
        } else if (stage == "effect-driver" && role == "personality-v1" &&
                   decimal_equal(task, "512") && observation == "completion") {
            v1_task_entry_count++
            v1_task_entry_line = NR
        } else if (stage == "closure-watchdog" && role == "watchdog" &&
                   decimal_equal(task, "513") && observation == "completion") {
            watchdog_task_entry_count++
            watchdog_task_entry_line = NR
        } else {
            fail("unknown startup task-entry identity: " $0)
        }
    }
    /^LINUX_FUTEX_STARTUP Receipt scenario=expire / {
        if (NF != 14 || $2 != "Receipt" || $3 != "scenario=expire" ||
            $4 !~ /^stage=(waker-ready|wait-captured)$/ || $5 !~ /^start_tick=/ ||
            $6 !~ /^observed_tick=/ || $7 !~ /^waited_ticks=/ ||
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
        if (decimal_compare(observed, start) < 0 ||
            !decimal_equal(decimal_subtract(observed, start), waited))
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
        if (begin_count != 1 || waker_pick_count != 1 || waiter_pick_count != 1 ||
            v1_pick_count != 1 || watchdog_pick_count != 1 ||
            waker_task_entry_count != 1 || v1_task_entry_count != 1 ||
            watchdog_task_entry_count != 1 ||
            waiter_task_entry_count != 1 || waker_ready_count != 1 || wait_captured_count != 1 ||
            waker_guest_block_count != 1 || waiter_guest_block_count != 1)
            fail("expected one Expire begin, task entry, child block, and receipt for each startup stage")
        if (!(begin_line < waker_pick_line &&
              waker_pick_line < waker_guest_block_line &&
              waker_guest_block_line < waker_task_entry_line &&
              waker_task_entry_line < waker_ready_line &&
              waker_ready_line < waiter_pick_line &&
              waiter_pick_line < mismatch_line &&
              mismatch_line < wait_capture_line &&
              wait_capture_line < waiter_guest_block_line &&
              waiter_guest_block_line < waiter_task_entry_line &&
              waiter_task_entry_line < wait_captured_line &&
              wait_captured_line < v1_pick_line &&
              wait_captured_line < watchdog_pick_line &&
              v1_pick_line < wait_register_line &&
              watchdog_pick_line < crash_line &&
              wait_register_line < enable_waker_line &&
              enable_waker_line < wake_capture_line &&
              wake_capture_line < crash_line &&
              crash_line < watchdog_line &&
              watchdog_line < v1_task_entry_line &&
              v1_task_entry_line < watchdog_task_entry_line))
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

sed '0,/post_vm_pre_irq=true/s//post_vm_pre_irq=false/' \
    "$serial_log" >"$work/missing-post-vm-boundary.log"
if oracle "$work/missing-post-vm-boundary.log" >/dev/null 2>&1; then
    die "oracle accepted TaskEntry without the post-VM/pre-IRQ boundary"
fi

sed '0,/post_irq_entry=true/s//post_irq_entry=false/' \
    "$serial_log" >"$work/missing-post-irq-boundary.log"
if oracle "$work/missing-post-irq-boundary.log" >/dev/null 2>&1; then
    die "oracle accepted TaskEntry without the post-IRQ trampoline boundary"
fi

awk '
    !mutated && /^CSER FallbackPick authority_epoch=41 binding_epoch=4 task=511 / {
        sub(/cause=[^ ]+/, "cause=unknown")
        mutated = 1
    }
    { print }
    END { if (!mutated) exit 2 }
' "$serial_log" >"$work/unknown-selection.log"
if oracle "$work/unknown-selection.log" >/dev/null 2>&1; then
    die "oracle accepted an unknown startup selection cause"
fi

sed '0,/reported_by=parent/s//reported_by=child/' \
    "$serial_log" >"$work/self-reported-entry.log"
if oracle "$work/self-reported-entry.log" >/dev/null 2>&1; then
    die "oracle accepted a task-body self-reported entry boundary"
fi

awk '
    !mutated && /^LINUX_FUTEX_STARTUP Receipt scenario=expire stage=waker-ready / {
        sub(/start_tick=[^ ]+/, "start_tick=9007199254740992")
        sub(/observed_tick=[^ ]+/, "observed_tick=9007199254740993")
        sub(/waited_ticks=[^ ]+/, "waited_ticks=0")
        mutated = 1
    }
    { print }
    END { if (!mutated) exit 2 }
' "$serial_log" >"$work/inexact-u64-timing.log"
if oracle "$work/inexact-u64-timing.log" >/dev/null 2>&1; then
    die "oracle accepted a u64 timing mismatch hidden by floating-point rounding"
fi

awk '
    !mutated && /^LINUX_FUTEX_STARTUP Receipt scenario=expire stage=waker-ready / {
        sub(/start_tick=[^ ]+/, "start_tick=18446744073709551616")
        sub(/observed_tick=[^ ]+/, "observed_tick=18446744073709551616")
        sub(/waited_ticks=[^ ]+/, "waited_ticks=0")
        mutated = 1
    }
    { print }
    END { if (!mutated) exit 2 }
' "$serial_log" >"$work/u64-overflow-timing.log"
if oracle "$work/u64-overflow-timing.log" >/dev/null 2>&1; then
    die "oracle accepted a startup tick above u64::MAX"
fi

awk '
    !mutated && /^LINUX_FUTEX_STARTUP Receipt scenario=expire stage=waker-ready / {
        sub(/start_tick=[^ ]+/, "start_tick=18446744073709551615")
        sub(/observed_tick=[^ ]+/, "observed_tick=18446744073709551614")
        sub(/waited_ticks=[^ ]+/, "waited_ticks=0")
        mutated = 1
    }
    { print }
    END { if (!mutated) exit 2 }
' "$serial_log" >"$work/descending-u64-timing.log"
if oracle "$work/descending-u64-timing.log" >/dev/null 2>&1; then
    die "oracle accepted a high observed tick below its start tick"
fi

awk '
    !mutated && /^LINUX_FUTEX_STARTUP Receipt scenario=expire stage=waker-ready / {
        sub(/start_tick=[^ ]+/, "start_tick=18446744073709551515")
        sub(/observed_tick=[^ ]+/, "observed_tick=18446744073709551615")
        sub(/waited_ticks=[^ ]+/, "waited_ticks=99")
        mutated = 1
    }
    { print }
    END { if (!mutated) exit 2 }
' "$serial_log" >"$work/high-u64-difference.log"
if oracle "$work/high-u64-difference.log" >/dev/null 2>&1; then
    die "oracle accepted an incorrect high-u64 tick difference"
fi

awk '
    !mutated && /^LINUX_FUTEX_STARTUP TaskEntry scenario=expire stage=waker-ready / {
        sub(/task=511/, "task=0511")
        mutated = 1
    }
    { print }
    END { if (!mutated) exit 2 }
' "$serial_log" >"$work/noncanonical-task-id.log"
if oracle "$work/noncanonical-task-id.log" >/dev/null 2>&1; then
    die "oracle accepted a non-canonical decimal task identity"
fi

awk '
    !mutated && /^LINUX_FUTEX_STARTUP TaskEntry scenario=expire stage=effect-driver / {
        mutated = 1
        next
    }
    { print }
    END { if (!mutated) exit 2 }
' "$serial_log" >"$work/missing-v1-task-entry.log"
if oracle "$work/missing-v1-task-entry.log" >/dev/null 2>&1; then
    die "oracle accepted an effect-driver spawn without TaskEntry"
fi

awk '
    !mutated && /^LINUX_FUTEX_STARTUP TaskEntry scenario=expire stage=closure-watchdog / {
        mutated = 1
        next
    }
    { print }
    END { if (!mutated) exit 2 }
' "$serial_log" >"$work/missing-watchdog-task-entry.log"
if oracle "$work/missing-watchdog-task-entry.log" >/dev/null 2>&1; then
    die "oracle accepted a closure-watchdog spawn without TaskEntry"
fi

awk '
    { print }
    !injected && /^LINUX_FUTEX_STARTUP Receipt scenario=expire stage=wait-captured / {
        print "LINUX_FUTEX_STARTUP PreSwitch scenario=expire physical_task=200 phase=after-grace-before-kstack"
        injected = 1
    }
    END { if (!injected) exit 2 }
' "$serial_log" >"$work/post-window-switch-diagnostic.log"
if oracle "$work/post-window-switch-diagnostic.log" >/dev/null 2>&1; then
    die "oracle accepted a switch diagnostic after the staging window"
fi

awk '
    !mutated && /^LINUX_FUTEX_STARTUP Receipt scenario=expire stage=waker-ready / {
        value = $5
        $5 = $6
        $6 = value
        mutated = 1
    }
    { print }
    END { if (!mutated) exit 2 }
' "$serial_log" >"$work/reordered-timing-fields.log"
if oracle "$work/reordered-timing-fields.log" >/dev/null 2>&1; then
    die "oracle accepted a non-canonical startup receipt field order"
fi

echo "Linux futex staged-start assertions: PASS receipts=2 selections=4 selection_cause=explicit switch_serial=false task_entries=4 entry_source=ostd-trampoline entry_boundaries=post-vm-pre-irq+post-irq-entry+closure-entered+identity-validated entry_reporter=parent child_entry_blocks=2 timing=diagnostic exact_u64_decimal=true internal_timeout=false handshake=wait-queue prerequisite_spawn_preemption=disabled-through-run effect_task_spawns=batched-under-preempt-guard next_explicit_schedule=completion-wait atomic_release_and_park=false effect_entry_order=partial failure_bound=outer-qemu-timeout publish_recover_protocol=retained mutations=20"
