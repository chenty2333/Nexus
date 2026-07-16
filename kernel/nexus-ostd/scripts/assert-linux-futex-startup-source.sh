#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

die() {
    echo "Linux futex startup source assertion: FAIL: $*" >&2
    exit 1
}

if (( $# < 1 || $# > 2 )); then
    die "usage: $0 LINUX_FUTEX_RS [KERNEL_LIB_RS]"
fi

source_file=$1
script_root=$(cd "$(dirname "$0")/.." && pwd)
lib_file=${2:-"$script_root/src/lib.rs"}
[[ -f $source_file && ! -L $source_file ]] || die "not a regular non-symlink source: $source_file"
[[ -f $lib_file && ! -L $lib_file ]] || die "not a regular non-symlink kernel source: $lib_file"

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
        $0 == "        ready" {
            ready_receiver_line = NR
        }
        $0 == "            .compare_exchange(false, true, Ordering::Release, Ordering::Relaxed)" &&
        NR == ready_receiver_line + 1 {
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
        index($0, "\"LINUX_FUTEX_STARTUP TaskEntry scenario=expire stage=effect-driver role=personality-v1 task={}") > 0 {
            v1_task_entries++
            v1_task_entry = NR
        }
        index($0, "\"LINUX_FUTEX_STARTUP TaskEntry scenario=expire stage=closure-watchdog role=watchdog task={}") > 0 {
            watchdog_task_entries++
            watchdog_task_entry = NR
        }
        $0 == "    assert_current_user_task(scenario.kind.waiter_task_id(), &vm_space);" {
            waiter_identity_asserts++
            waiter_identity_assert = NR
        }
        $0 == "    assert_current_user_task(scenario.kind.waker_task_id(), &vm_space);" {
            waker_identity_asserts++
            waker_identity_assert = NR
        }
        $0 == "    assert_current_user_task(scenario.kind.personality_v1_task_id(), &vm_space);" {
            v1_identity_asserts++
            v1_identity_assert = NR
        }
        $0 == "    assert_current_kernel_task(scenario.kind.watchdog_task_id());" {
            watchdog_identity_asserts++
            watchdog_identity_assert = NR
        }
        $0 == "    while !scenario.wait_is_captured() {" {
            v1_first_work = NR
        }
        $0 == "    while !scenario.has_crashed() {" {
            watchdog_first_work = NR
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
        $0 == "fn run_expire_effect_tasks_and_wait(" {
            effect_runner_helpers++
            in_effect_runner = 1
        }
        in_effect_runner && $0 == "    let effect_preempt_guard = disable_preempt();" {
            effect_preempt_guards++
            effect_preempt_guard = NR
        }
        in_effect_runner && $0 == "    v1_task.run();" {
            effect_v1_runs++
            effect_v1_run = NR
        }
        in_effect_runner && $0 == "    watchdog_task.run();" {
            effect_watchdog_runs++
            effect_watchdog_run = NR
        }
        in_effect_runner && $0 == "    drop(effect_preempt_guard);" {
            effect_guard_drops++
            effect_guard_drop = NR
        }
        in_effect_runner && $0 == "    done_waiter.wait();" {
            effect_completion_waits++
            effect_completion_wait = NR
        }
        in_effect_runner && /Task::yield_now\(\)/ {
            effect_runner_yields++
        }
        in_effect_runner && $0 == "}" {
            in_effect_runner = 0
        }
        $0 == "fn run_scenario(" {
            run_scenario_lines++
        }
        $0 == "static EXPIRE_STARTUP_SWITCH_DIAGNOSTICS: AtomicBool = AtomicBool::new(false);" {
            diagnostics_false_initializers++
        }
        /expire_startup_switch_diagnostics_enabled\(\) -> bool/ {
            diagnostics_gate_readers++
        }
        /EXPIRE_STARTUP_SWITCH_DIAGNOSTICS\.load\(Ordering::Acquire\)/ {
            diagnostics_acquire_reads++
        }
        $0 == "        EXPIRE_STARTUP_SWITCH_DIAGNOSTICS" {
            diagnostics_open_receivers++
            diagnostics_open_receiver = NR
        }
        $0 == "            .compare_exchange(false, true, Ordering::Release, Ordering::Relaxed)" &&
        NR == diagnostics_open_receiver + 1 {
            diagnostics_open_cas++
            diagnostics_open = NR
        }
        $0 == "            .expect(\"expire startup switch diagnostics must have one active window\");" &&
        NR == diagnostics_open + 1 {
            diagnostics_open_expects++
        }
        $0 == "            EXPIRE_STARTUP_SWITCH_DIAGNOSTICS" {
            diagnostics_close_receivers++
            diagnostics_close_receiver = NR
        }
        $0 == "                .compare_exchange(true, false, Ordering::Release, Ordering::Relaxed)" &&
        NR == diagnostics_close_receiver + 1 {
            diagnostics_close_cas++
            diagnostics_close = NR
        }
        $0 == "                .expect(\"expire startup switch diagnostics must close once\");" &&
        NR == diagnostics_close + 1 {
            diagnostics_close_expects++
        }
        $0 == "            run_expire_startup_task(&waker_task, &scenario, ExpireStartupStage::WakerReady);" {
            waker_ready_calls++
            waker_ready = NR
        }
        $0 == "            run_expire_startup_task(&waiter_task, &scenario, ExpireStartupStage::WaitCaptured);" {
            wait_captured_calls++
            wait_captured = NR
        }
        $0 == "            run_expire_effect_tasks_and_wait(&v1_task, &watchdog_task, &done_waiter);" {
            effect_runner_calls++
            effect_runner_call = NR
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
                fail("startup admission is not adjacent to its direct blocking wait")
            if (effect_runner_helpers != 1 || effect_preempt_guards != 1 ||
                effect_v1_runs != 1 || effect_watchdog_runs != 1 ||
                effect_guard_drops != 1 || effect_completion_waits != 1 ||
                effect_runner_yields != 0 ||
                !(effect_preempt_guard < effect_v1_run &&
                  effect_v1_run < effect_watchdog_run &&
                  effect_watchdog_run < effect_guard_drop &&
                  effect_guard_drop < effect_completion_wait) ||
                effect_v1_run != effect_preempt_guard + 1 ||
                effect_watchdog_run != effect_v1_run + 1 ||
                effect_guard_drop != effect_watchdog_run + 1 ||
                effect_completion_wait != effect_guard_drop + 1)
                fail("effect admissions are not batched immediately before the completion wait")
            if (waiter_task_entries != 1 || waker_task_entries != 1 ||
                v1_task_entries != 1 || watchdog_task_entries != 1 ||
                waiter_identity_asserts != 1 || waker_identity_asserts != 1 ||
                v1_identity_asserts != 1 || watchdog_identity_asserts != 1 ||
                wait_captures != 1 || waiter_guest_blocks != 1 ||
                enable_waker_registrations != 1 || waker_guest_blocks != 1 ||
                !(waiter_identity_assert < waiter_task_entry &&
                  waiter_task_entry < wait_capture &&
                  wait_capture < waiter_guest_block &&
                  waiter_guest_block < waiter_publish &&
                  waker_identity_assert < waker_task_entry &&
                  waker_task_entry < enable_waker_registration &&
                  enable_waker_registration < waker_guest_block &&
                  waker_guest_block < waker_publish &&
                  v1_identity_assert < v1_task_entry &&
                  v1_task_entry < v1_first_work &&
                  watchdog_identity_assert < watchdog_task_entry &&
                  watchdog_task_entry < watchdog_first_work))
                fail("TaskEntry is not identity-validated before the task first effect")
            if (diagnostics_false_initializers != 1 || diagnostics_gate_readers != 1 ||
                diagnostics_acquire_reads != 1 || diagnostics_open_receivers != 1 ||
                diagnostics_open_cas != 1 || diagnostics_open_expects != 1 ||
                diagnostics_close_receivers != 1 || diagnostics_close_cas != 1 ||
                diagnostics_close_expects != 1)
                fail("expire startup switch diagnostics are not one bounded acquire/release window")
            if (waker_ready_calls != 1 || wait_captured_calls != 1 ||
                effect_runner_calls != 1)
                fail("startup stages are not each invoked exactly once")
            if (!(diagnostics_open < waker_ready &&
                  waker_ready < wait_captured &&
                  wait_captured < diagnostics_close &&
                  diagnostics_close < effect_runner_call))
                fail("Expire startup order is not waker-ready, waiter-captured, v1, watchdog")
        }
    ' "$1"
}

lib_oracle() {
    awk '
        function fail(message) {
            print "Linux futex startup lib oracle: FAIL: " message > "/dev/stderr"
            exit 1
        }
        /inject_pre_schedule_handler\(trace_expire_pre_schedule\);/ {
            pre_injections++
        }
        $0 == "fn trace_expire_pre_schedule(_guard: &DisabledLocalIrqGuard) {" {
            in_pre = 1
            pre_handlers++
        }
        in_pre && $0 == "    if !linux_futex::expire_startup_switch_diagnostics_enabled() {" {
            pre_negative_gate_checks++
            pre_gate_line = NR
        }
        in_pre && $0 == "        return;" && NR == pre_gate_line + 1 {
            pre_gate_returns++
        }
        in_pre && index($0, "LINUX_FUTEX_STARTUP PreSwitch scenario=expire physical_task={}") > 0 {
            pre_receipts++
            pre_receipt_line = NR
            in_pre = 0
        }
        $0 == "fn activate_current_task_vm() {" {
            in_post = 1
            post_handlers++
        }
        in_post && $0 == "    let trace_expire_startup = linux_futex::expire_startup_switch_diagnostics_enabled();" {
            post_gate_assignments++
            post_gate_assignment = NR
        }
        in_post && $0 == "    if trace_expire_startup {" {
            post_receipt_gates++
            if (post_before_gate == 0)
                post_before_gate = NR
            else
                post_after_gate = NR
        }
        in_post && index($0, "LINUX_FUTEX_STARTUP PostSwitch scenario=expire task={} phase=before-vm-activate vm={}") > 0 {
            post_before_receipts++
            post_before_line = NR
        }
        in_post && /vm_space\.lock\(\)\.activate\(\);/ {
            post_activation_calls++
            if (post_first_activation_line == 0) post_first_activation_line = NR
            post_last_activation_line = NR
        }
        in_post && $0 == "        vm_space.activate();" {
            post_activation_calls++
            if (post_first_activation_line == 0) post_first_activation_line = NR
            post_last_activation_line = NR
        }
        in_post && index($0, "LINUX_FUTEX_STARTUP PostSwitch scenario=expire task={} phase=after-vm-activate vm={}") > 0 {
            post_after_receipts++
            post_after_line = NR
            in_post = 0
        }
        END {
            if (pre_injections != 1 || pre_handlers != 1 ||
                pre_negative_gate_checks != 1 || pre_gate_returns != 1 ||
                pre_receipts != 1 ||
                !(pre_gate_line < pre_receipt_line))
                fail("pre-schedule diagnostics are not injected and gated exactly once")
            if (post_handlers != 1 || post_gate_assignments != 1 ||
                post_receipt_gates != 2 ||
                post_before_receipts != 1 || post_after_receipts != 1 ||
                post_activation_calls != 2)
                fail("post-schedule VM diagnostics are incomplete or duplicated")
            if (!(post_gate_assignment < post_before_gate &&
                  post_before_gate < post_before_line &&
                  post_before_line < post_first_activation_line &&
                  post_last_activation_line < post_after_gate &&
                  post_after_gate < post_after_line))
                fail("post-schedule receipts do not bracket VM activation")
        }
    ' "$1"
}

oracle "$source_file"
lib_oracle "$lib_file"

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
    $0 == "    let preempt_guard = disable_preempt();" {
        print "    let preempt_guard = ();"
        mutated = 1
        next
    }
    { print }
    END { if (!mutated) exit 2 }
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

sed '0,/LINUX_FUTEX_STARTUP TaskEntry scenario=expire stage=waker-ready/s//LINUX_FUTEX_STARTUP TaskStarted scenario=expire stage=waker-ready/' \
    "$source_file" >"$work/missing-waker-task-entry.rs"
if oracle "$work/missing-waker-task-entry.rs" >/dev/null 2>&1; then
    die "oracle accepted a missing waker TaskEntry source receipt"
fi

sed '0,/LINUX_FUTEX_STARTUP TaskEntry scenario=expire stage=effect-driver/s//LINUX_FUTEX_STARTUP TaskStarted scenario=expire stage=effect-driver/' \
    "$source_file" >"$work/missing-v1-task-entry.rs"
if oracle "$work/missing-v1-task-entry.rs" >/dev/null 2>&1; then
    die "oracle accepted a missing effect-driver TaskEntry source receipt"
fi

sed '0,/LINUX_FUTEX_STARTUP TaskEntry scenario=expire stage=closure-watchdog/s//LINUX_FUTEX_STARTUP TaskStarted scenario=expire stage=closure-watchdog/' \
    "$source_file" >"$work/missing-watchdog-task-entry.rs"
if oracle "$work/missing-watchdog-task-entry.rs" >/dev/null 2>&1; then
    die "oracle accepted a missing closure-watchdog TaskEntry source receipt"
fi

awk '
    $0 == "    let effect_preempt_guard = disable_preempt();" {
        print "    let effect_preempt_guard = ();"
        mutated = 1
        next
    }
    { print }
    END { if (!mutated) exit 2 }
' "$source_file" >"$work/disabled-effect-preempt-guard.rs"
if oracle "$work/disabled-effect-preempt-guard.rs" >/dev/null 2>&1; then
    die "oracle accepted effect-task spawns without a preemption guard"
fi

awk '
    $0 == "    watchdog_task.run();" {
        print "    drop(effect_preempt_guard);"
        print
        moved = 1
        next
    }
    $0 == "    drop(effect_preempt_guard);" {
        removed = 1
        next
    }
    { print }
    END { if (!moved || !removed) exit 2 }
' "$source_file" >"$work/drop-effect-guard-before-watchdog.rs"
if oracle "$work/drop-effect-guard-before-watchdog.rs" >/dev/null 2>&1; then
    die "oracle accepted a watchdog spawn after the effect preemption guard was dropped"
fi

awk '
    $0 == "    drop(effect_preempt_guard);" {
        print
        print "    Task::yield_now();"
        injected = 1
        next
    }
    { print }
    END { if (!injected) exit 2 }
' "$source_file" >"$work/preempt-point-before-completion-wait.rs"
if oracle "$work/preempt-point-before-completion-wait.rs" >/dev/null 2>&1; then
    die "oracle accepted an explicit preemption point before the completion wait"
fi

awk '
    $0 == "        EXPIRE_STARTUP_SWITCH_DIAGNOSTICS" {
        open_receiver = 1
    }
    !mutated && open_receiver &&
    $0 == "            .compare_exchange(false, true, Ordering::Release, Ordering::Relaxed)" {
        sub(/Ordering::Release/, "Ordering::Relaxed")
        mutated = 1
        open_receiver = 0
    }
    { print }
    END { if (!mutated) exit 2 }
' "$source_file" >"$work/relaxed-diagnostic-open.rs"
if oracle "$work/relaxed-diagnostic-open.rs" >/dev/null 2>&1; then
    die "oracle accepted a diagnostic window opened without Release ordering"
fi

awk '
    $0 == "            EXPIRE_STARTUP_SWITCH_DIAGNOSTICS" {
        close_receiver = 1
    }
    !mutated && close_receiver &&
    $0 == "                .compare_exchange(true, false, Ordering::Release, Ordering::Relaxed)" {
        sub(/true, false/, "false, true")
        mutated = 1
        close_receiver = 0
    }
    { print }
    END { if (!mutated) exit 2 }
' "$source_file" >"$work/reversed-diagnostic-close.rs"
if oracle "$work/reversed-diagnostic-close.rs" >/dev/null 2>&1; then
    die "oracle accepted a diagnostic window close with reversed states"
fi

awk '
    !removed && /inject_pre_schedule_handler\(trace_expire_pre_schedule\);/ {
        removed = 1
        next
    }
    { print }
    END { if (!removed) exit 2 }
' "$lib_file" >"$work/missing-pre-schedule-diagnostic.rs"
if lib_oracle "$work/missing-pre-schedule-diagnostic.rs" >/dev/null 2>&1; then
    die "oracle accepted a missing pre-schedule diagnostic injection"
fi

sed '0,/phase=after-vm-activate/s//phase=before-vm-activate/' \
    "$lib_file" >"$work/missing-post-vm-completion.rs"
if lib_oracle "$work/missing-post-vm-completion.rs" >/dev/null 2>&1; then
    die "oracle accepted a post-schedule receipt that did not bracket VM activation"
fi

sed '0,/if !linux_futex::expire_startup_switch_diagnostics_enabled()/s/if !/if /' \
    "$lib_file" >"$work/inverted-pre-schedule-gate.rs"
if lib_oracle "$work/inverted-pre-schedule-gate.rs" >/dev/null 2>&1; then
    die "oracle accepted an inverted pre-schedule diagnostic gate"
fi

sed '0,/if trace_expire_startup {/s//if true {/' \
    "$lib_file" >"$work/ungated-post-schedule-receipt.rs"
if lib_oracle "$work/ungated-post-schedule-receipt.rs" >/dev/null 2>&1; then
    die "oracle accepted an ungated post-schedule diagnostic receipt"
fi

echo "Linux futex startup source assertions: PASS expire_only=true order=waker-ready+wait-captured+v1+watchdog selection_cause=explicit pre_switch=instrumented child_post_switch_vm=instrumented diagnostic_window=false-to-true-to-false+release task_entries=identity-validated-first-effect publication_order=guest-prerequisite-before-ready readiness=release+acquire handshake=blocking-wait-queue prerequisite_spawn_preemption=disabled-through-run effect_spawns=batched-under-preempt-guard next_explicit_schedule=completion-wait atomic_release_and_park=false timing=diagnostic internal_timeout=false failure_bound=outer-qemu-timeout tcb=ostd-0.18-task-run+park-current mutations=24"
