#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

die() {
    echo "Linux futex startup source assertion: FAIL: $*" >&2
    exit 1
}

if (( $# < 1 || $# > 3 )); then
    die "usage: $0 LINUX_FUTEX_RS [KERNEL_LIB_RS] [OSDK_TOML]"
fi

source_file=$1
script_root=$(cd "$(dirname "$0")/.." && pwd)
lib_file=${2:-"$script_root/src/lib.rs"}
osdk_file=${3:-"$script_root/OSDK.toml"}
[[ -f $source_file && ! -L $source_file ]] || die "not a regular non-symlink source: $source_file"
[[ -f $lib_file && ! -L $lib_file ]] || die "not a regular non-symlink kernel source: $lib_file"
[[ -f $osdk_file && ! -L $osdk_file ]] || die "not a regular non-symlink OSDK config: $osdk_file"

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
        $0 == "pub(crate) fn admit_expire_task_pre_irq(data: &TaskData, _irq_guard: &DisabledLocalIrqGuard) {" {
            admission_functions++
            admission_function_line = NR
            in_admission = 1
        }
        in_admission && $0 == "    let Some(entry) = ExpireTaskEntry::from_task_id(data.id) else {" {
            admission_identity_mappings++
            admission_identity_mapping_line = NR
        }
        in_admission && $0 == "    let bit = entry.bit();" {
            admission_bit_derivations++
            admission_bit_derivation_line = NR
        }
        in_admission && $0 == "    EXPIRE_SWITCH_TAIL_OPEN_BITS.fetch_or(bit, Ordering::Release);" {
            forbidden_retired_switch_tail_state++
        }
        in_admission && $0 == "    emit_expire_debugcon(entry, ExpireEntryBoundary::PreIrqAdmitted);" {
            admission_markers++
            admission_marker_line = NR
        }
        $0 == "pub(crate) fn record_expire_post_irq_entry(task_id: u64) {" {
            if (in_admission) {
                admission_ends++
                admission_end_line = NR
                in_admission = 0
            }
        }
        /^static EXPIRE_POST_VM_READY_BITS: AtomicU8 = AtomicU8::new\(0\);$/ {
            post_vm_masks++
        }
        /^static EXPIRE_PRE_IRQ_ADMITTED_BITS: AtomicU8 = AtomicU8::new\(0\);$/ {
            pre_irq_masks++
        }
        /^static EXPIRE_POST_IRQ_ENTRY_BITS: AtomicU8 = AtomicU8::new\(0\);$/ {
            post_irq_masks++
        }
        /^static EXPIRE_CLOSURE_ENTERED_BITS: AtomicU8 = AtomicU8::new\(0\);$/ {
            closure_masks++
        }
        /^static EXPIRE_IDENTITY_VALIDATED_BITS: AtomicU8 = AtomicU8::new\(0\);$/ {
            identity_masks++
        }
        /EXPIRE_POST_VM_READY_BITS\.fetch_or\(entry\.bit\(\), Ordering::Release\)/ {
            post_vm_release_publishes++
        }
        in_admission && /EXPIRE_PRE_IRQ_ADMITTED_BITS\.fetch_or\(bit, Ordering::Release\)/ {
            pre_irq_release_publishes++
            pre_irq_release_publish = NR
        }
        /EXPIRE_POST_IRQ_ENTRY_BITS\.fetch_or\(entry\.bit\(\), Ordering::Release\)/ {
            post_irq_release_publishes++
        }
        /EXPIRE_CLOSURE_ENTERED_BITS\.fetch_or\(entry\.bit\(\), Ordering::Release\)/ {
            closure_release_publishes++
        }
        /EXPIRE_IDENTITY_VALIDATED_BITS\.fetch_or\(entry\.bit\(\), Ordering::Release\)/ {
            identity_release_publishes++
        }
        /EXPIRE_POST_VM_READY_BITS\.load\(Ordering::Acquire\)/ {
            post_vm_acquire_observations++
            if (in_admission) {
                admission_post_vm_observations++
                admission_post_vm_observe_line = NR
            }
        }
        /EXPIRE_PRE_IRQ_ADMITTED_BITS\.load\(Ordering::Acquire\)/ {
            pre_irq_acquire_observations++
        }
        /EXPIRE_POST_IRQ_ENTRY_BITS\.load\(Ordering::Acquire\)/ {
            post_irq_acquire_observations++
        }
        /EXPIRE_CLOSURE_ENTERED_BITS\.load\(Ordering::Acquire\)/ {
            closure_acquire_observations++
        }
        /EXPIRE_IDENTITY_VALIDATED_BITS\.load\(Ordering::Acquire\)/ {
            identity_acquire_observations++
        }
        /510 => Some\(Self::Waiter\),/ { waiter_mappings++ }
        /511 => Some\(Self::Waker\),/ { waker_mappings++ }
        /512 => Some\(Self::EffectDriver\),/ { v1_mappings++ }
        /513 => Some\(Self::ClosureWatchdog\),/ { watchdog_mappings++ }
        $0 == "static EXPIRE_DEBUGCON: Once<IoPort<u8, WriteOnlyAccess>> = Once::new();" {
            debugcon_once_cells++
        }
        $0 == "const EXPIRE_DEBUGCON_PORT: u16 = 0xe9;" { debugcon_ports++ }
        $0 == "    debugcon.write(byte);" {
            debugcon_writes++
        }
        $0 == "    let code = (boundary as u8) * 4 + entry as u8;" {
            debugcon_single_byte_encoders++
        }
        /x86::io::outb/ { forbidden_raw_debugcon_writes++ }
        /IoPort::acquire\(EXPIRE_DEBUGCON_PORT\)/ {
            debugcon_acquisitions++
        }
        index($0, "\"LINUX_FUTEX_STARTUP TaskEntry scenario=expire stage={} role={} task={} source=ostd-first-switch pre_irq_admitted=true post_irq_entry=true closure_entered=true identity_validated=true debugcon=true reported_by=parent observation={}") > 0 {
            parent_task_entry_reporters++
        }
        in_admission && $0 == "    let expects_vm = entry != ExpireTaskEntry::ClosureWatchdog;" {
            vm_shape_roles++
            vm_shape_role_line = NR
        }
        in_admission && $0 == "        data.vm_space.is_some()," {
            vm_shape_checks++
            vm_shape_check_line = NR
        }
        in_admission && $0 == "        data.dynamic_vm_space.is_none()," {
            dynamic_vm_rejections++
            dynamic_vm_rejection_line = NR
        }
        in_admission && $0 == "        data.cser_task.is_none()," {
            registry_identity_rejections++
            registry_identity_rejection_line = NR
        }
        $0 == "        mark_expire_closure_entered(ExpireTaskEntry::Waiter);" {
            waiter_closure_entries++
            waiter_closure_entry = NR
        }
        $0 == "        mark_expire_closure_entered(ExpireTaskEntry::Waker);" {
            waker_closure_entries++
            waker_closure_entry = NR
        }
        $0 == "        mark_expire_closure_entered(ExpireTaskEntry::EffectDriver);" {
            v1_closure_entries++
            v1_closure_entry = NR
        }
        $0 == "        mark_expire_closure_entered(ExpireTaskEntry::ClosureWatchdog);" {
            watchdog_closure_entries++
            watchdog_closure_entry = NR
        }
        $0 == "        mark_expire_identity_validated(ExpireTaskEntry::Waiter);" {
            waiter_identity_markers++
            waiter_identity_marker = NR
        }
        $0 == "        mark_expire_identity_validated(ExpireTaskEntry::Waker);" {
            waker_identity_markers++
            waker_identity_marker = NR
        }
        $0 == "        mark_expire_identity_validated(ExpireTaskEntry::EffectDriver);" {
            v1_identity_markers++
            v1_identity_marker = NR
        }
        $0 == "        mark_expire_identity_validated(ExpireTaskEntry::ClosureWatchdog);" {
            watchdog_identity_markers++
            watchdog_identity_marker = NR
        }
        $0 == "    report_expire_task_entry(stage.task_entry(), \"semantic-ready\");" {
            semantic_ready_reports++
        }
        $0 == "    report_expire_task_entry(ExpireTaskEntry::EffectDriver, \"completion\");" {
            v1_completion_reports++
        }
        $0 == "    report_expire_task_entry(ExpireTaskEntry::ClosureWatchdog, \"completion\");" {
            watchdog_completion_reports++
        }
        $0 == "    assert_expire_task_entry_receipts_complete();" {
            complete_entry_assertions++
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
                fail("effect task spawns are not batched immediately before the completion wait")
            if (post_vm_masks != 1 || pre_irq_masks != 1 || post_irq_masks != 1 ||
                closure_masks != 1 || identity_masks != 1 ||
                post_vm_release_publishes != 1 ||
                pre_irq_release_publishes != 1 ||
                post_irq_release_publishes != 1 ||
                closure_release_publishes != 1 ||
                identity_release_publishes != 1 ||
                post_vm_acquire_observations < 2 ||
                pre_irq_acquire_observations < 3 ||
                post_irq_acquire_observations < 3 ||
                closure_acquire_observations < 3 ||
                identity_acquire_observations < 2 ||
                waiter_mappings != 1 || waker_mappings != 1 ||
                v1_mappings != 1 || watchdog_mappings != 1 ||
                debugcon_once_cells != 1 || debugcon_ports != 1 ||
                debugcon_writes != 1 || debugcon_single_byte_encoders != 1 ||
                debugcon_acquisitions != 1 ||
                forbidden_raw_debugcon_writes != 0 ||
                parent_task_entry_reporters != 1 ||
                admission_functions != 1 || admission_identity_mappings != 1 ||
                admission_bit_derivations != 1 || admission_post_vm_observations != 1 ||
                admission_ends != 1 || admission_markers != 1 ||
                forbidden_retired_switch_tail_state != 0 || in_admission ||
                vm_shape_roles != 1 || vm_shape_checks != 1 ||
                dynamic_vm_rejections != 1 || registry_identity_rejections != 1 ||
                !(admission_function_line < admission_identity_mapping_line &&
                  admission_identity_mapping_line < admission_bit_derivation_line &&
                  admission_bit_derivation_line < admission_post_vm_observe_line &&
                  admission_post_vm_observe_line < vm_shape_role_line &&
                  vm_shape_role_line < vm_shape_check_line &&
                  vm_shape_check_line < dynamic_vm_rejection_line &&
                  dynamic_vm_rejection_line < registry_identity_rejection_line &&
                  registry_identity_rejection_line < pre_irq_release_publish &&
                  pre_irq_release_publish < admission_marker_line &&
                  admission_marker_line < admission_end_line) ||
                semantic_ready_reports != 1 ||
                v1_completion_reports != 1 || watchdog_completion_reports != 1 ||
                complete_entry_assertions != 1)
                fail("entry boundary storage, ordering, debugcon, or parent receipt is incomplete")
            if (waiter_closure_entries != 1 || waker_closure_entries != 1 ||
                v1_closure_entries != 1 || watchdog_closure_entries != 1 ||
                waiter_identity_markers != 1 || waker_identity_markers != 1 ||
                v1_identity_markers != 1 || watchdog_identity_markers != 1 ||
                waiter_identity_asserts != 1 || waker_identity_asserts != 1 ||
                v1_identity_asserts != 1 || watchdog_identity_asserts != 1 ||
                wait_captures != 1 || waiter_guest_blocks != 1 ||
                enable_waker_registrations != 1 || waker_guest_blocks != 1 ||
                !(waiter_closure_entry < waiter_identity_assert &&
                  waiter_identity_assert < waiter_identity_marker &&
                  waiter_identity_marker < wait_capture &&
                  wait_capture < waiter_guest_block &&
                  waiter_guest_block < waiter_publish &&
                  waker_closure_entry < waker_identity_assert &&
                  waker_identity_assert < waker_identity_marker &&
                  waker_identity_marker < enable_waker_registration &&
                  enable_waker_registration < waker_guest_block &&
                  waker_guest_block < waker_publish &&
                  v1_closure_entry < v1_identity_assert &&
                  v1_identity_assert < v1_identity_marker &&
                  v1_identity_marker < v1_first_work &&
                  watchdog_closure_entry < watchdog_identity_assert &&
                  watchdog_identity_assert < watchdog_identity_marker &&
                  watchdog_identity_marker < watchdog_first_work))
                fail("entry boundaries are not release/acquire bound around identity validation")
            if (waker_ready_calls != 1 || wait_captured_calls != 1 ||
                effect_runner_calls != 1)
                fail("startup stages are not each invoked exactly once")
            if (!(waker_ready < wait_captured &&
                  wait_captured < effect_runner_call))
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
        /inject_post_schedule_handler\(activate_current_task_vm\);/ {
            post_injections++
        }
        /inject_first_task_pre_irq_handler\(admit_current_task_pre_irq\);/ {
            pre_irq_injections++
        }
        /inject_first_task_entry_handler\(record_current_task_post_irq_entry\);/ {
            entry_injections++
        }
        /linux_futex::init_expire_debugcon\(\);/ {
            debugcon_initializers++
            debugcon_initializer_line = NR
        }
        /ostd_scheduler::inject_scheduler\(scheduler\);/ {
            scheduler_injections++
            scheduler_injection_line = NR
        }
        $0 == "fn activate_current_task_vm() {" {
            in_post = 1
            post_handlers++
        }
        in_post && /vm_space\.lock\(\)\.activate\(\);/ {
            post_activation_calls++
            post_last_activation_line = NR
        }
        in_post && $0 == "        vm_space.activate();" {
            post_activation_calls++
            post_last_activation_line = NR
        }
        in_post && $0 == "    linux_futex::record_expire_post_vm_ready(data.id);" {
            post_vm_recorders++
            post_vm_recorder_line = NR
            in_post = 0
        }
        $0 == "fn admit_current_task_pre_irq(irq_guard: &DisabledLocalIrqGuard) {" {
            in_pre_irq = 1
            pre_irq_handlers++
            pre_irq_handler_line = NR
        }
        in_pre_irq && /Task::current\(\)/ {
            pre_irq_current_task_reads++
            pre_irq_current_task_line = NR
        }
        in_pre_irq && /\.downcast_ref::<TaskData>\(\)/ {
            pre_irq_task_data_downcasts++
            pre_irq_task_data_line = NR
        }
        in_pre_irq && $0 == "    linux_futex::admit_expire_task_pre_irq(data, irq_guard);" {
            pre_irq_recorders++
            pre_irq_recorder_line = NR
            in_pre_irq = 0
        }
        $0 == "fn record_current_task_post_irq_entry() {" {
            in_entry = 1
            entry_handlers++
            entry_handler_line = NR
        }
        in_entry && /Task::current\(\)/ {
            current_task_reads++
            current_task_line = NR
        }
        in_entry && /\.downcast_ref::<TaskData>\(\)/ {
            task_data_downcasts++
            task_data_line = NR
        }
        in_entry && $0 == "    linux_futex::record_expire_post_irq_entry(data.id);" {
            entry_recorders++
            entry_recorder_line = NR
            in_entry = 0
        }
        /LINUX_FUTEX_STARTUP (PreSwitch|PostSwitch)/ {
            forbidden_switch_serial++
        }
        END {
            if (post_injections != 1 || pre_irq_injections != 1 ||
                entry_injections != 1 ||
                debugcon_initializers != 1 || scheduler_injections != 1 ||
                !(debugcon_initializer_line < scheduler_injection_line) ||
                post_handlers != 1 || post_activation_calls != 2 ||
                post_vm_recorders != 1 || forbidden_switch_serial != 0 ||
                !(post_last_activation_line < post_vm_recorder_line))
                fail("post-switch VM activation is not atomically recorded without serial output")
            if (pre_irq_handlers != 1 || pre_irq_current_task_reads != 1 ||
                pre_irq_task_data_downcasts != 1 || pre_irq_recorders != 1 ||
                !(pre_irq_handler_line < pre_irq_current_task_line &&
                  pre_irq_current_task_line < pre_irq_task_data_line &&
                  pre_irq_task_data_line < pre_irq_recorder_line))
                fail("pre-IRQ admission does not bind TaskData and the disabled-IRQ guard")
            if (entry_handlers != 1 || current_task_reads != 1 ||
                task_data_downcasts != 1 || entry_recorders != 1 ||
                !(entry_handler_line < current_task_line &&
                  current_task_line < task_data_line &&
                  task_data_line < entry_recorder_line))
                fail("OSTD first-task-entry injection does not identity-bind Nexus TaskData")
        }
    ' "$1"
}

osdk_oracle() {
    awk '
        /-chardev file,id=entry-debugcon,path=\/work\/artifacts\/task-entry-debugcon-scratch\.log/ {
            standard_scratch_paths++
        }
        /-chardev file,id=entry-debugcon,path=\/work\/artifacts\/runtime-fs-same-boot\/task-entry-debugcon\.log/ {
            same_boot_paths++
        }
        /-chardev file,id=entry-debugcon,path=\/work\/artifacts\/runtime-fs-same-boot-precommit\/task-entry-debugcon\.log/ {
            precommit_paths++
        }
        /-chardev file,id=entry-debugcon,path=\/work\/artifacts\/runtime-fs-same-boot-postcommit-crash\/task-entry-debugcon\.log/ {
            postcommit_paths++
        }
        /-device isa-debugcon,iobase=0xe9,chardev=entry-debugcon/ {
            debugcon_devices++
        }
        END {
            if (standard_scratch_paths != 1 || same_boot_paths != 1 ||
                precommit_paths != 1 || postcommit_paths != 1 ||
                debugcon_devices != 4)
                exit 1
        }
    ' "$1"
}

oracle "$source_file"
lib_oracle "$lib_file"
osdk_oracle "$osdk_file" || die "OSDK profiles do not isolate the entry debugcon sink"

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

sed '0,/mark_expire_closure_entered(ExpireTaskEntry::Waker)/s//mark_expire_closure_entered(ExpireTaskEntry::Waiter)/' \
    "$source_file" >"$work/wrong-waker-closure-entry.rs"
if oracle "$work/wrong-waker-closure-entry.rs" >/dev/null 2>&1; then
    die "oracle accepted a waker closure bound to the waiter entry identity"
fi

sed '0,/mark_expire_identity_validated(ExpireTaskEntry::EffectDriver)/s//mark_expire_identity_validated(ExpireTaskEntry::Waiter)/' \
    "$source_file" >"$work/wrong-v1-identity.rs"
if oracle "$work/wrong-v1-identity.rs" >/dev/null 2>&1; then
    die "oracle accepted a missing effect-driver identity boundary"
fi

sed '0,/mark_expire_identity_validated(ExpireTaskEntry::ClosureWatchdog)/s//mark_expire_identity_validated(ExpireTaskEntry::Waiter)/' \
    "$source_file" >"$work/wrong-watchdog-identity.rs"
if oracle "$work/wrong-watchdog-identity.rs" >/dev/null 2>&1; then
    die "oracle accepted a missing closure-watchdog identity boundary"
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

sed '0,/EXPIRE_POST_VM_READY_BITS.fetch_or(entry.bit(), Ordering::Release)/s/Ordering::Release/Ordering::Relaxed/' \
    "$source_file" >"$work/relaxed-post-vm-publication.rs"
if oracle "$work/relaxed-post-vm-publication.rs" >/dev/null 2>&1; then
    die "oracle accepted a relaxed post-VM boundary publication"
fi

sed '0,/EXPIRE_PRE_IRQ_ADMITTED_BITS.fetch_or(bit, Ordering::Release)/s/Ordering::Release/Ordering::Relaxed/' \
    "$source_file" >"$work/relaxed-pre-irq-admission.rs"
if oracle "$work/relaxed-pre-irq-admission.rs" >/dev/null 2>&1; then
    die "oracle accepted a relaxed pre-IRQ admission publication"
fi

awk '
    !removed && $0 == "        mark_expire_closure_entered(ExpireTaskEntry::Waker);" {
        held = $0
        removed = 1
        next
    }
    { print }
    removed && !inserted &&
    $0 == "    assert_current_user_task(scenario.kind.waker_task_id(), &vm_space);" {
        print held
        inserted = 1
    }
    END { if (!removed || !inserted) exit 2 }
' "$source_file" >"$work/late-waker-closure-entry.rs"
if oracle "$work/late-waker-closure-entry.rs" >/dev/null 2>&1; then
    die "oracle accepted a closure-entry marker after identity validation began"
fi

sed '0,/const EXPIRE_DEBUGCON_PORT: u16 = 0xe9;/s/0xe9/0xe8/' \
    "$source_file" >"$work/wrong-debugcon-port.rs"
if oracle "$work/wrong-debugcon-port.rs" >/dev/null 2>&1; then
    die "oracle accepted an entry marker on the wrong debugcon port"
fi

awk '
    !removed && /inject_first_task_entry_handler\(record_current_task_post_irq_entry\);/ {
        removed = 1
        next
    }
    { print }
    END { if (!removed) exit 2 }
' "$lib_file" >"$work/missing-first-entry-injection.rs"
if lib_oracle "$work/missing-first-entry-injection.rs" >/dev/null 2>&1; then
    die "oracle accepted a missing OSTD first-task-entry injection"
fi

awk '
    !removed && /inject_first_task_pre_irq_handler\(admit_current_task_pre_irq\);/ {
        removed = 1
        next
    }
    { print }
    END { if (!removed) exit 2 }
' "$lib_file" >"$work/missing-first-pre-irq-injection.rs"
if lib_oracle "$work/missing-first-pre-irq-injection.rs" >/dev/null 2>&1; then
    die "oracle accepted a missing OSTD first-task pre-IRQ injection"
fi

awk '
    !removed && $0 == "    linux_futex::record_expire_post_vm_ready(data.id);" {
        removed = 1
        next
    }
    { print }
    END { if (!removed) exit 2 }
' "$lib_file" >"$work/missing-post-vm-recorder.rs"
if lib_oracle "$work/missing-post-vm-recorder.rs" >/dev/null 2>&1; then
    die "oracle accepted a post-switch path without its post-VM recorder"
fi

awk '
    !removed && $0 == "    linux_futex::admit_expire_task_pre_irq(data, irq_guard);" {
        removed = 1
        next
    }
    { print }
    END { if (!removed) exit 2 }
' "$lib_file" >"$work/missing-pre-irq-admission-recorder.rs"
if lib_oracle "$work/missing-pre-irq-admission-recorder.rs" >/dev/null 2>&1; then
    die "oracle accepted pre-IRQ admission without TaskData and guard binding"
fi

sed '0,/let expects_vm = entry != ExpireTaskEntry::ClosureWatchdog;/s/!=/==/' \
    "$source_file" >"$work/reversed-pre-irq-vm-shape.rs"
if oracle "$work/reversed-pre-irq-vm-shape.rs" >/dev/null 2>&1; then
    die "oracle accepted reversed role-specific VM shape admission"
fi

sed '0,/ExpireTaskEntry::from_task_id(data\.id)/s/data\.id/510/' \
    "$source_file" >"$work/hardcoded-pre-irq-admission.rs"
if oracle "$work/hardcoded-pre-irq-admission.rs" >/dev/null 2>&1; then
    die "oracle accepted pre-IRQ admission hardcoded to task 510"
fi

awk '
    !removed && $0 == "    linux_futex::record_expire_post_irq_entry(data.id);" {
        removed = 1
        next
    }
    { print }
    END { if (!removed) exit 2 }
' "$lib_file" >"$work/missing-post-irq-recorder.rs"
if lib_oracle "$work/missing-post-irq-recorder.rs" >/dev/null 2>&1; then
    die "oracle accepted an OSTD hook that did not bind Nexus task identity"
fi

awk '
    !removed && /-device isa-debugcon,iobase=0xe9,chardev=entry-debugcon/ {
        removed = 1
        next
    }
    { print }
    END { if (!removed) exit 2 }
' "$osdk_file" >"$work/missing-debugcon-device.toml"
if osdk_oracle "$work/missing-debugcon-device.toml" >/dev/null 2>&1; then
    die "oracle accepted an OSDK profile without its debugcon device"
fi

echo "Linux futex startup source assertions: PASS expire_only=true order=waker-ready+wait-captured+v1+watchdog selection_cause=observed switch_path=irq-off-first-admission pre_irq_admitted=task-data-scoped+guarded post_irq_liveness=true closure_entered_before_identity=true identity_validated_before_effect=true task_entries=parent-reported debugcon=isolated publication_order=guest-prerequisite-before-ready readiness=release+acquire handshake=blocking-wait-queue prerequisite_spawn_preemption=disabled-through-run effect_task_spawns=batched-under-preempt-guard next_explicit_schedule=completion-wait atomic_release_and_park=false timing=diagnostic internal_timeout=false failure_bound=outer-qemu-timeout tcb=ostd-0.18-first-task-pre-irq+first-task-entry+park-current mutations=30"
