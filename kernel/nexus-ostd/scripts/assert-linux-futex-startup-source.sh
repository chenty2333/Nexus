#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

die() {
    echo "Linux futex startup source assertion: FAIL: $*" >&2
    exit 1
}

if (( $# != 1 )); then
    die "usage: $0 LINUX_FUTEX_RS"
fi

source_file=$1
[[ -f $source_file && ! -L $source_file ]] || die "not a regular non-symlink source: $source_file"

oracle() {
    awk '
        function fail(message) {
            print "Linux futex startup source oracle: FAIL: " message > "/dev/stderr"
            exit 1
        }
        $0 == "const EXPIRE_STARTUP_MAX_TICKS: u64 = 128;" {
            deadline_constants++
        }
        $0 == "fn wait_for_expire_startup(scenario: &FutexScenario, stage: ExpireStartupStage) {" {
            helper_lines++
        }
        $0 == "    fn mark_expire_startup_ready(&self, stage: ExpireStartupStage) {" {
            publisher_helpers++
        }
        /compare_exchange\(false, true, Ordering::Release, Ordering::Relaxed\)/ {
            release_publishes++
        }
        /ready\.load\(Ordering::Acquire\)/ {
            acquire_observations++
        }
        $0 == "    scenario.capture_wait(user_mode.context(), waker);" {
            wait_captures++
            wait_capture = NR
        }
        index($0, "\"LINUX_FUTEX GuestBlock scenario={} role=waiter task={}") > 0 {
            waiter_guest_blocks++
            waiter_guest_block = NR
        }
        $0 == "        scenario.mark_expire_startup_ready(ExpireStartupStage::WaitCaptured);" {
            waiter_publishers++
            waiter_publish = NR
        }
        $0 == "    scenario.register_enable_waker(enable_waker);" {
            enable_waker_registrations++
            enable_waker_registration = NR
        }
        index($0, "\"LINUX_FUTEX GuestBlock scenario={} role=waker task={} gate=EnableWaker") > 0 {
            waker_guest_blocks++
            waker_guest_block = NR
        }
        $0 == "        scenario.mark_expire_startup_ready(ExpireStartupStage::WakerReady);" {
            waker_publishers++
            waker_publish = NR
        }
        /checked_add\(EXPIRE_STARTUP_MAX_TICKS\)/ {
            checked_deadlines++
        }
        /observed < deadline,/ {
            strict_deadline_checks++
        }
        $0 == "            waker_task.run();" {
            waker_run = NR
        }
        $0 == "            wait_for_expire_startup(&scenario, ExpireStartupStage::WakerReady);" {
            waker_ready_calls++
            waker_ready = NR
            staged_waker_run = waker_run
        }
        $0 == "            waiter_task.run();" && waker_ready > 0 {
            staged_waiter_run = NR
        }
        $0 == "            wait_for_expire_startup(&scenario, ExpireStartupStage::WaitCaptured);" {
            wait_captured_calls++
            wait_captured = NR
        }
        $0 == "            v1_task.run();" && wait_captured > 0 && v1_run == 0 {
            v1_run = NR
        }
        $0 == "            watchdog_task.run();" && wait_captured > 0 && watchdog_run == 0 {
            watchdog_run = NR
        }
        END {
            if (deadline_constants != 1 || helper_lines != 1 ||
                checked_deadlines != 1 || strict_deadline_checks != 1)
                fail("startup helper is not uniquely deadline-bounded")
            if (publisher_helpers != 1 || release_publishes != 1 ||
                acquire_observations != 1 || waker_publishers != 1 ||
                waiter_publishers != 1)
                fail("startup readiness is not one-shot release/acquire published")
            if (wait_captures != 1 || waiter_guest_blocks != 1 ||
                enable_waker_registrations != 1 || waker_guest_blocks != 1 ||
                !(wait_capture < waiter_guest_block &&
                  waiter_guest_block < waiter_publish &&
                  enable_waker_registration < waker_guest_block &&
                  waker_guest_block < waker_publish))
                fail("startup readiness is published before the guest prerequisite receipt")
            if (waker_ready_calls != 1 || wait_captured_calls != 1)
                fail("startup stages are not each invoked exactly once")
            if (!(staged_waker_run < waker_ready &&
                  waker_ready < staged_waiter_run &&
                  staged_waiter_run < wait_captured &&
                  wait_captured < v1_run &&
                  v1_run < watchdog_run))
                fail("Expire startup order is not waker-ready, waiter-captured, v1, watchdog")
        }
    ' "$1"
}

oracle "$source_file"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

awk '
    !removed && $0 == "            wait_for_expire_startup(&scenario, ExpireStartupStage::WakerReady);" {
        removed = 1
        next
    }
    { print }
    END { if (!removed) exit 2 }
' "$source_file" >"$work/missing-waker-ready.rs"
if oracle "$work/missing-waker-ready.rs" >/dev/null 2>&1; then
    die "oracle accepted a missing waker-ready barrier"
fi

awk '
    $0 == "            wait_for_expire_startup(&scenario, ExpireStartupStage::WakerReady);" {
        sub(/WakerReady/, "Swapping")
    }
    $0 == "            wait_for_expire_startup(&scenario, ExpireStartupStage::WaitCaptured);" {
        sub(/WaitCaptured/, "WakerReady")
    }
    { lines[NR] = $0 }
    END {
        for (line = 1; line <= NR; line++) {
            sub(/Swapping/, "WaitCaptured", lines[line])
            print lines[line]
        }
    }
' "$source_file" >"$work/swapped-stages.rs"
if oracle "$work/swapped-stages.rs" >/dev/null 2>&1; then
    die "oracle accepted swapped startup stages"
fi

sed '0,/const EXPIRE_STARTUP_MAX_TICKS: u64 = 128;/s//const EXPIRE_STARTUP_MAX_TICKS: u64 = 0;/' \
    "$source_file" >"$work/unbounded-deadline.rs"
if oracle "$work/unbounded-deadline.rs" >/dev/null 2>&1; then
    die "oracle accepted a missing startup deadline"
fi

sed '0,/ready\.load(Ordering::Acquire)/s//ready.load(Ordering::Relaxed)/' \
    "$source_file" >"$work/relaxed-readiness.rs"
if oracle "$work/relaxed-readiness.rs" >/dev/null 2>&1; then
    die "oracle accepted a relaxed startup readiness observation"
fi

awk '
    $0 == "    scenario.register_enable_waker(enable_waker);" {
        print "    if scenario.kind == ScenarioKind::Expire {"
        print "        scenario.mark_expire_startup_ready(ExpireStartupStage::WakerReady);"
        print "    }"
        print
        injected = 1
        next
    }
    $0 == "        scenario.mark_expire_startup_ready(ExpireStartupStage::WakerReady);" {
        removed = 1
        next
    }
    { print }
    END { if (!injected || !removed) exit 2 }
' "$source_file" >"$work/early-waker-readiness.rs"
if oracle "$work/early-waker-readiness.rs" >/dev/null 2>&1; then
    die "oracle accepted readiness published before waker registration and GuestBlock"
fi

echo "Linux futex startup source assertions: PASS expire_only=true order=waker-ready+wait-captured+v1+watchdog publication_order=guest-prerequisite-before-ready readiness=release+acquire deadline=checked max_wait_ticks=128 mutations=5"
