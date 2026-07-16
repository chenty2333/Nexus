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
    /^LINUX_FUTEX_STARTUP Receipt scenario=expire / {
        if (NF != 10 || $2 != "Receipt" || $3 != "scenario=expire" ||
            $9 != "max_wait_ticks=128" || $10 != "bounded=true")
            fail("malformed startup receipt: " $0)
        stage = field("stage")
        start = decimal(field("start_tick"), stage " start_tick")
        observed = decimal(field("observed_tick"), stage " observed_tick")
        deadline = decimal(field("deadline_tick"), stage " deadline_tick")
        waited = decimal(field("waited_ticks"), stage " waited_ticks")
        if (deadline - start != 128 || observed - start != waited || observed > deadline)
            fail("startup receipt violates its checked deadline: " $0)
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
    /^LINUX_FUTEX Mismatch scenario=expire / { mismatch_line = NR }
    /^LINUX_FUTEX Capture scenario=expire kind=WAIT / { wait_capture_line = NR }
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
        if (begin_count != 1 || waker_ready_count != 1 || wait_captured_count != 1)
            fail("expected one Expire begin and one receipt for each startup stage")
        if (!(begin_line < waker_ready_line &&
              waker_ready_line < mismatch_line &&
              mismatch_line < wait_capture_line &&
              wait_capture_line < wait_captured_line &&
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

echo "Linux futex staged-start assertions: PASS receipts=2 max_wait_ticks=128 publish_recover_race=preserved mutations=2"
