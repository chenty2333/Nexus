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
        $0 == "fn wait_for_expire_startup(scenario: &FutexScenario, stage: ExpireStartupStage) {" {
            helper_lines++
        }
        $0 == "    fn mark_expire_startup_ready(&self, stage: ExpireStartupStage) {" {
            publisher_helpers++
        }
        /compare_exchange\(false, true, Ordering::Release, Ordering::Relaxed\)/ {
            release_publishes++
            release_publish = NR
        }
        /ready\.load\(Ordering::Acquire\)/ {
            acquire_observations++
        }
        $0 == "    sync::{SpinLock, WaitQueue}," {
            wait_queue_imports++
        }
        $0 == "    expire_waker_queue: WaitQueue," {
            waker_queue_fields++
        }
        $0 == "    expire_waiter_queue: WaitQueue," {
            waiter_queue_fields++
        }
        /expire_waker_queue: WaitQueue::new\(\),/ {
            waker_queue_constructors++
        }
        /expire_waiter_queue: WaitQueue::new\(\),/ {
            waiter_queue_constructors++
        }
        $0 == "        let _ = queue.wake_one();" {
            queue_wakes++
            queue_wake = NR
        }
        $0 == "    queue.wait_until(|| ready.load(Ordering::Acquire).then_some(()));" {
            blocking_waits++
            blocking_wait = NR
        }
        index($0, "waited_ticks={} timing=diagnostic internal_timeout=false failure_bound=outer-qemu-timeout handshake=wait-queue spawn_preemption=disabled-through-run publish=release observe=acquire") > 0 {
            diagnostic_receipts++
        }
        /EXPIRE_STARTUP_MAX_SUCCESS_TICKS/ || /success_latency_checked=true/ ||
        /max_success_wait_ticks=/ || /observed <= deadline/ ||
        (index($0, "LINUX_FUTEX_STARTUP") > 0 && /bounded=true/) {
            forbidden_latency_claims++
        }
        /\.checked_sub\(start\)/ {
            monotonic_differences++
        }
        index($0, "\"LINUX_FUTEX_STARTUP TaskEntry scenario=expire stage=wait-captured role=waiter task={}") > 0 {
            waiter_task_entries++
            waiter_task_entry = NR
        }
        index($0, "\"LINUX_FUTEX_STARTUP TaskEntry scenario=expire stage=waker-ready role=waker task={}") > 0 {
            waker_task_entries++
            waker_task_entry = NR
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
        helper_lines > 0 && run_scenario_lines == 0 && /Task::yield_now\(\)/ {
            helper_yields++
        }
        $0 == "fn run_expire_startup_task(task: &Arc<Task>, scenario: &FutexScenario, stage: ExpireStartupStage) {" {
            startup_runner_helpers++
        }
        $0 == "    let preempt_guard = disable_preempt();" {
            startup_preempt_guards++
            startup_preempt_guard = NR
        }
        $0 == "    task.run();" {
            startup_task_runs++
            startup_task_run = NR
        }
        $0 == "    drop(preempt_guard);" {
            startup_guard_drops++
            startup_guard_drop = NR
        }
        $0 == "    wait_for_expire_startup(scenario, stage);" {
            startup_blocking_waits++
            startup_blocking_wait = NR
        }
        $0 == "fn run_scenario(" {
            run_scenario_lines++
        }
        $0 == "            run_expire_startup_task(&waker_task, &scenario, ExpireStartupStage::WakerReady);" {
            waker_ready_calls++
            waker_ready = NR
        }
        $0 == "            run_expire_startup_task(&waiter_task, &scenario, ExpireStartupStage::WaitCaptured);" {
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
            if (helper_lines != 1 || diagnostic_receipts != 1 ||
                monotonic_differences != 1 || forbidden_latency_claims != 0)
                fail("startup helper overclaims a guest-side timeout or omits its timing diagnostic")
            if (publisher_helpers != 1 || release_publishes != 1 ||
                acquire_observations != 1 || waker_publishers != 1 ||
                waiter_publishers != 1)
                fail("startup readiness is not one-shot release/acquire published")
            if (wait_queue_imports != 1 || waker_queue_fields != 1 ||
                waiter_queue_fields != 1 || waker_queue_constructors != 1 ||
                waiter_queue_constructors != 1 || queue_wakes != 1 ||
                blocking_waits != 1 ||
                !(release_publish < queue_wake &&
                queue_wake < blocking_wait) || helper_yields != 0)
                fail("startup handshake is not a blocking publish-before-wake wait queue")
            if (startup_runner_helpers != 1 || startup_preempt_guards != 1 ||
                startup_task_runs != 1 || startup_guard_drops != 1 ||
                startup_blocking_waits != 1 ||
                !(startup_preempt_guard < startup_task_run &&
                startup_task_run < startup_guard_drop &&
                startup_guard_drop < startup_blocking_wait) ||
                startup_task_run != startup_preempt_guard + 1 ||
                startup_guard_drop != startup_task_run + 1 ||
                startup_blocking_wait != startup_guard_drop + 1)
                fail("startup task can preempt before the parent reaches its blocking wait")
            if (waiter_task_entries != 1 || waker_task_entries != 1 ||
                wait_captures != 1 || waiter_guest_blocks != 1 ||
                enable_waker_registrations != 1 || waker_guest_blocks != 1 ||
                !(waiter_task_entry < wait_capture &&
                  wait_capture < waiter_guest_block &&
                  waiter_guest_block < waiter_publish &&
                  waker_task_entry < enable_waker_registration &&
                  enable_waker_registration < waker_guest_block &&
                  waker_guest_block < waker_publish))
                fail("startup readiness is published before the guest prerequisite receipt")
            if (waker_ready_calls != 1 || wait_captured_calls != 1)
                fail("startup stages are not each invoked exactly once")
            if (!(waker_ready < wait_captured &&
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
    !removed && $0 == "            run_expire_startup_task(&waker_task, &scenario, ExpireStartupStage::WakerReady);" {
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
    $0 == "            run_expire_startup_task(&waker_task, &scenario, ExpireStartupStage::WakerReady);" {
        sub(/WakerReady/, "Swapping")
    }
    $0 == "            run_expire_startup_task(&waiter_task, &scenario, ExpireStartupStage::WaitCaptured);" {
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

sed '0,/timing=diagnostic/s//timing=bounded/' \
    "$source_file" >"$work/overclaimed-startup-timing.rs"
if oracle "$work/overclaimed-startup-timing.rs" >/dev/null 2>&1; then
    die "oracle accepted an unsupported bounded startup-timing claim"
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

sed '0,/queue\.wait_until(|| ready\.load(Ordering::Acquire)\.then_some(()));/s//while !ready.load(Ordering::Acquire) { Task::yield_now(); }/' \
    "$source_file" >"$work/yield-polling.rs"
if oracle "$work/yield-polling.rs" >/dev/null 2>&1; then
    die "oracle accepted runnable-parent yield polling in place of the blocking handshake"
fi

awk '
    !removed && $0 == "        let _ = queue.wake_one();" {
        removed = 1
        next
    }
    { print }
    END { if (!removed) exit 2 }
' "$source_file" >"$work/missing-queue-wake.rs"
if oracle "$work/missing-queue-wake.rs" >/dev/null 2>&1; then
    die "oracle accepted a Release publication without a wait-queue notification"
fi

awk '
    !injected && $0 == "        ready" {
        print "        let _ = queue.wake_one();"
        print
        injected = 1
        next
    }
    !removed && $0 == "        let _ = queue.wake_one();" {
        removed = 1
        next
    }
    { print }
    END { if (!injected || !removed) exit 2 }
' "$source_file" >"$work/wake-before-release.rs"
if oracle "$work/wake-before-release.rs" >/dev/null 2>&1; then
    die "oracle accepted a wait-queue notification before the Release publication"
fi

sed '0,/failure_bound=outer-qemu-timeout/s//failure_bound=guest-tick-deadline/' \
    "$source_file" >"$work/overclaimed-failure-bound.rs"
if oracle "$work/overclaimed-failure-bound.rs" >/dev/null 2>&1; then
    die "oracle accepted a guest-side failure bound not enforced by WaitQueue"
fi

awk '
    !removed && $0 == "    let preempt_guard = disable_preempt();" {
        removed = 1
        next
    }
    { print }
    END { if (!removed) exit 2 }
' "$source_file" >"$work/missing-spawn-preempt-guard.rs"
if oracle "$work/missing-spawn-preempt-guard.rs" >/dev/null 2>&1; then
    die "oracle accepted an unguarded Task::run spawn window"
fi

awk '
    $0 == "    task.run();" {
        print "    drop(preempt_guard);"
        print
        swapped = 1
        next
    }
    $0 == "    drop(preempt_guard);" {
        removed = 1
        next
    }
    { print }
    END { if (!swapped || !removed) exit 2 }
' "$source_file" >"$work/drop-guard-before-run.rs"
if oracle "$work/drop-guard-before-run.rs" >/dev/null 2>&1; then
    die "oracle accepted dropping the preemption guard before Task::run"
fi

awk '
    $0 == "    drop(preempt_guard);" {
        print
        print "    Task::yield_now();"
        injected = 1
        next
    }
    { print }
    END { if (!injected) exit 2 }
' "$source_file" >"$work/preempt-point-before-wait.rs"
if oracle "$work/preempt-point-before-wait.rs" >/dev/null 2>&1; then
    die "oracle accepted an explicit preemption point between guard drop and blocking wait"
fi

awk '
    !removed && index($0, "\"LINUX_FUTEX_STARTUP TaskEntry scenario=expire stage=waker-ready role=waker task={}") > 0 {
        removed = 1
        next
    }
    { print }
    END { if (!removed) exit 2 }
' "$source_file" >"$work/missing-waker-task-entry.rs"
if oracle "$work/missing-waker-task-entry.rs" >/dev/null 2>&1; then
    die "oracle accepted a missing waker TaskEntry source receipt"
fi

echo "Linux futex startup source assertions: PASS expire_only=true order=waker-ready+wait-captured+v1+watchdog task_entries=2 publication_order=guest-prerequisite-before-ready readiness=release+acquire handshake=blocking-wait-queue spawn_preemption=disabled-through-run timing=diagnostic internal_timeout=false failure_bound=outer-qemu-timeout mutations=13"
