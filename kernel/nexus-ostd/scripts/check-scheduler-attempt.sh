#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
source_file=${1:-"$root/src/domains/scheduler.rs"}
gate_source=${2:-"$root/../../crates/cser-transition-gates/src/scheduler.rs"}
futex_source=${3:-"$root/src/personality/linux_futex_core.rs"}

awk '
    /fn install_reserved\(&mut self\)/ { in_install = 1 }
    in_install && /self\.install_current\(next\);/ { install_count++; install_line = NR }
    in_install && /record_liveness_pick_installed\(task_id, self\.cpu_index\);/ {
        record_count++
        record_line = NR
    }
    in_install && /self\.current\.as_ref\(\)/ { return_count++; return_line = NR; in_install = 0 }
    /"CSER PickInstalled / { serial_in_scheduler++ }
    /pub\(crate\) fn consume_liveness_pick_installed/ { consume_count++ }
    END {
        if (install_count != 1 || record_count != 1 || return_count != 1 ||
            consume_count != 1 || serial_in_scheduler != 0 ||
            !(install_line < record_line && record_line < return_line)) {
            print "scheduler liveness source gate: pick receipt escaped install/atomic/lock-free-output contract" > "/dev/stderr"
            exit 1
        }
    }
' "$source_file"

awk '
    /fn recovery_snapshot\(&self\)/ { in_snapshot = 1 }
    in_snapshot && /"LINUX_FUTEX_CORE RecoverySnapshotBegin / {
        begin_count++
        begin_line = NR
    }
    in_snapshot && /let snapshot = self\.runtime\.with_state/ {
        section_count++
        section_line = NR
        in_runtime_section = 1
    }
    in_runtime_section && $0 == "        });" {
        section_close_count++
        section_close_line = NR
        in_runtime_section = 0
    }
    in_snapshot && /"LINUX_FUTEX_CORE RecoveryRuntimeSectionComplete / {
        complete_count++
        complete_line = NR
    }
    in_snapshot && /self\.state\.lock\(\)\.recovery_snapshot = Some/ {
        state_store_count++
        state_store_line = NR
    }
    in_snapshot && /"LINUX_FUTEX_CORE RecoverySnapshot replacement=/ {
        receipt_count++
        receipt_line = NR
        in_snapshot = 0
    }
    /consume_liveness_pick_installed\(V2_TASK\.id\(\)\)/ {
        consume_count++
        consume_line = NR
    }
    /"CSER PickInstalled task=/ {
        pick_log_count++
        pick_log_line = NR
    }
    /"LINUX_FUTEX_CORE RecoveryTaskEntry replacement=\{\} phase=kernel"/ {
        task_entry_count++
        task_entry_line = NR
    }
    /RecoveryRuntimeLockAcquired/ { stale_lock_marker++ }
    END {
        if (begin_count != 1 || section_count != 1 || section_close_count != 1 ||
            complete_count != 1 || state_store_count != 1 || receipt_count != 1 ||
            consume_count != 1 || pick_log_count != 1 || task_entry_count != 1 ||
            stale_lock_marker != 0 ||
            !(begin_line < section_line && section_line < section_close_line &&
              section_close_line < complete_line && complete_line < state_store_line &&
              state_store_line < receipt_line && consume_line < pick_log_line &&
              pick_log_line < task_entry_line)) {
            print "scheduler liveness source gate: serial receipt is not outside scheduler/runtime locks" > "/dev/stderr"
            exit 1
        }
        print "scheduler liveness source gate: PASS pick_record=atomic pick_output=task_context runtime_output=after_lock_release direct_handoff_claim=false performance_claim=false"
    }
' "$futex_source"

awk '
    index($0, ".pop_front()") {
        pop_count++
        pop_line = NR
    }
    index($0, ".note_fallback_pick(") {
        gate_count++
        gate_line = NR
    }
    index($0, "\"CSER FallbackPick authority_epoch=") {
        receipt_count++
        receipt_line = NR
    }
    index($0, "self.reserved = Some(next);") {
        reservation_count++
        if (gate_count > 0 && NR > gate_line && fallback_reservation_line == 0)
            fallback_reservation_line = NR
    }
    /^[[:space:]]*(fallback_selection_attempts|fallback_pick_tick|fallback_pick_task_id|fallback_pick_selection_attempt):/ {
        shadow_count++
    }
    END {
        if (pop_count != 1 || gate_count != 1 || receipt_count != 1 ||
            reservation_count != 2 || fallback_reservation_line == 0) {
            print "scheduler attempt source gate: expected one pop/gate-pick/fallback reservation/receipt" > "/dev/stderr"
            exit 1
        }
        if (!(pop_line < gate_line && gate_line < fallback_reservation_line &&
              fallback_reservation_line < receipt_line)) {
            print "scheduler attempt source gate: fallback selection escaped pop/gate/reserve/receipt ordering" > "/dev/stderr"
            exit 1
        }
        if (shadow_count != 0) {
            print "scheduler attempt source gate: shadow fallback evidence fields remain in production adapter" > "/dev/stderr"
            exit 1
        }
        print "scheduler attempt source gate: PASS pop_before_gate_pick=true reserve_before_receipt=true shadow_fallback_fields=false"
    }
' "$source_file"

awk '
    /^[[:space:]]*fn propose_inner\(/ {
        in_propose = 1
    }
    in_propose && /^[[:space:]]*pub fn crash\(/ {
        in_propose = 0
    }
    in_propose && index($0, "for (target_cpu, queue_lock) in self.queues.iter().enumerate()") {
        scan_count++
        scan_line = NR
    }
    in_propose && index($0, "let queue = queue_lock.disable_irq().lock();") {
        queue_lock_count++
        queue_lock_line = NR
    }
    in_propose && index($0, "queue.runnable_position(task_id)") {
        runnable_count++
        runnable_line = NR
    }
    in_propose && index($0, "queue.runnable_owner_matches(runnable_index)") {
        owner_count++
        owner_line = NR
    }
    in_propose && index($0, "let mut policy = self.policy.disable_irq().lock();") {
        nested_policy_count++
        nested_policy_line = NR
    }
    in_propose && index($0, "Self::prepare_rejection(&policy, binding)") {
        rejection_count++
        if (nested_policy_count > 0 && NR > nested_policy_line && nested_rejection_line == 0)
            nested_rejection_line = NR
    }
    in_propose && index($0, ".prepare(") {
        prepare_count++
        prepare_line = NR
    }
    in_propose && index($0, "let projection = policy.gate.projection();") {
        projection_count++
        projection_line = NR
    }
    in_propose && index($0, "drop(policy);") {
        policy_drop_count++
        policy_drop_line = NR
    }
    in_propose && index($0, "drop(queue);") {
        queue_drop_count++
        queue_drop_line = NR
    }
    in_propose && index($0, "\"CSER LeaseRenew action=Prepare") {
        receipt_log_count++
        receipt_log_line = NR
    }
    index($0, "fn prepare_rejection(") {
        rejection_helper_count++
    }
    index($0, "PrepareRejection::Busy") {
        busy_state_count++
    }
    index($0, "ProposalResult::RejectBusy") {
        busy_result_count++
    }
    index($0, "fn queue_containing_task(") || index($0, "fn contains_task(") {
        legacy_current_lookup_count++
    }
    /^struct CserPolicy \{/ {
        in_policy = 1
    }
    in_policy && /^}/ {
        in_policy = 0
    }
    in_policy && index($0, "gate: SchedulerGate<Proposal>") {
        owned_gate_count++
    }
    /^struct CserRunQueue \{/ {
        in_queue = 1
    }
    in_queue && /^}/ {
        in_queue = 0
    }
    in_queue && index($0, "policy: Arc<SpinLock<CserPolicy>>") {
        shared_policy_count++
    }
    in_queue && index($0, "gate: SchedulerGate<Proposal>") {
        local_gate_count++
    }
    in_queue && /^[[:space:]]*(binding|pending|mode|tick|lease_ticks|lease_deadline_tick|crash_tick|fallback_[a-z_]+):/ {
        shadow_count++
    }
    END {
        if (scan_count != 1 || queue_lock_count != 1 || runnable_count != 1 ||
            owner_count != 1 || nested_policy_count != 1 || rejection_count != 3 ||
            nested_rejection_line == 0 || prepare_count != 1 || projection_count != 1 ||
            policy_drop_count != 2 || queue_drop_count != 2 || receipt_log_count != 1 ||
            rejection_helper_count != 1 || busy_state_count != 2 || busy_result_count != 1 ||
            legacy_current_lookup_count != 0 || owned_gate_count != 1 ||
            shared_policy_count != 1 || local_gate_count != 0) {
            print "scheduler adapter source gate: atomic runnable admission, Busy rejection, or global gate ownership changed" > "/dev/stderr"
            exit 1
        }
        if (!(scan_line < queue_lock_line && queue_lock_line < runnable_line &&
              runnable_line < owner_line && owner_line < nested_policy_line &&
              nested_policy_line < nested_rejection_line && nested_rejection_line < prepare_line &&
              prepare_line < projection_line && projection_line < policy_drop_line &&
              policy_drop_line < queue_drop_line && queue_drop_line < receipt_log_line)) {
            print "scheduler adapter source gate: rq -> policy prepare or lock-free receipt ordering changed" > "/dev/stderr"
            exit 1
        }
        if (shadow_count != 0) {
            print "scheduler adapter source gate: shadow binding/mode/pending/lease/fallback fields remain" > "/dev/stderr"
            exit 1
        }
        print "scheduler adapter source gate: PASS runnable_only=true lock_order=rq_then_policy busy_rejected=true receipt_after_unlock=true shadow_recovery_fields=false"
    }
' "$source_file"

awk '
    index($0, "let cpu_count = num_cpus();") {
        cpu_count_count++
        cpu_count_line = NR
    }
    index($0, "let mut queues = Vec::with_capacity(cpu_count);") {
        capacity_count++
        capacity_line = NR
    }
    index($0, "for cpu_index in 0..cpu_count {") {
        allocation_loop_count++
        allocation_loop_line = NR
    }
    index($0, "fn checked_queue_index(cpu_index: usize, queue_count: usize) -> Option<usize>") {
        checked_helper_count++
    }
    index($0, "(cpu_index < queue_count).then_some(cpu_index)") {
        strict_bound_count++
    }
    index($0, "self.queues.get(index).unwrap_or_else(|| {") {
        checked_get_count++
    }
    index($0, "self.queues[") {
        direct_index_count++
    }
    index($0, "let queue = self.queue(guard.current_cpu()).disable_irq().lock();") {
        immutable_callback_count++
    }
    index($0, "let mut queue = self.queue(guard.current_cpu()).disable_irq().lock();") {
        mutable_callback_count++
    }
    index($0, "let selected_cpu = self.select_cpu();") {
        selected_cpu_count++
        selected_cpu_line = NR
    }
    index($0, "if let Err(owner_cpu) = runnable.schedule_info().cpu.set_if_is_none(selected_cpu)") {
        existing_owner_count++
        existing_owner_line = NR
    }
    index($0, "(true, owner_cpu)") {
        owner_target_count++
        owner_target_line = NR
    }
    index($0, "let mut queue = self.queue(target_cpu).disable_irq().lock();") {
        owner_queue_count++
        owner_queue_line = NR
    }
    index($0, ".set_if_is_none(target_cpu)") {
        second_cas_count++
        second_cas_line = NR
    }
    index($0, "reserved: Option<Arc<Task>>") {
        reserved_field_count++
    }
    index($0, "proposal.target_cpu == self.cpu_index") {
        target_guard_count++
        target_guard_line = NR
    }
    index($0, "proposal.binding,") {
        binding_precondition_count++
        if (target_guard_line > 0 && binding_precondition_line == 0)
            binding_precondition_line = NR
    }
    index($0, ".runnable_position(proposal.task_id)") {
        runnable_precondition_count++
        runnable_precondition_line = NR
    }
    index($0, "self.runnable_owner_matches(runnable_index)") {
        reservation_owner_count++
        reservation_owner_line = NR
    }
    index($0, ".take_bound_proposal()") {
        take_count++
        take_line = NR
    }
    index($0, ".remove(runnable_index)") {
        remove_count++
        remove_line = NR
    }
    index($0, "self.advance_lease_clock(flags);") {
        advance_call_count++
    }
    index($0, "flags != UpdateFlags::Tick || !self.lease_clock_cpu") {
        clock_guard_count++
        clock_guard_line = NR
    }
    index($0, ".tick()") {
        tick_count++
        tick_line = NR
    }
    index($0, "if self.runnable.is_empty()") {
        empty_guard_count++
        empty_guard_line = NR
    }
    index($0, "if !cause.requires_progress(current_absent)") {
        progress_guard_count++
        progress_guard_line = NR
    }
    index($0, "policy.enter_fallback(binding, \"mandatory_progress\")") {
        mandatory_fallback_count++
        mandatory_fallback_line = NR
    }
    index($0, "self.reserve_next(cause)") {
        update_reserve_count++
        update_reserve_line = NR
    }
    index($0, "fn pick_next(&mut self) -> &Arc<Task>") {
        pick_override_count++
        pick_override_line = NR
    }
    index($0, ".expect(\"update_current(true) must leave one local reservation\")") {
        guaranteed_pick_count++
        guaranteed_pick_line = NR
    }
    index($0, "self.reserve_next(SelectionCause::BestEffort)") {
        best_effort_count++
    }
    index($0, "cpu_index == lease_clock_cpu") {
        designated_clock_count++
    }
    index($0, "CpuId::bsp()") {
        bsp_count++
    }
    index($0, "local run queue, then global policy") {
        lock_order_count++
    }
    index($0, "OSTD `SpinLock` acquire/release is the publication boundary") {
        memory_boundary_count++
    }
    index($0, "std::sync") || index($0, "Mutex<") || index($0, "RwLock<") {
        non_ostd_lock_count++
    }
    END {
        if (cpu_count_count != 1 || capacity_count != 1 || allocation_loop_count != 1 ||
            checked_helper_count != 1 || strict_bound_count != 1 || checked_get_count != 1 ||
            direct_index_count != 0 || immutable_callback_count != 1 ||
            mutable_callback_count != 1 || selected_cpu_count != 1 ||
            existing_owner_count != 1 || owner_target_count != 1 || owner_queue_count != 1 ||
            second_cas_count != 1 || reserved_field_count != 1 || target_guard_count != 1 ||
            binding_precondition_count < 1 || runnable_precondition_count != 1 ||
            reservation_owner_count != 1 || take_count != 1 || remove_count != 1 ||
            advance_call_count != 1 || clock_guard_count != 1 || tick_count != 1 ||
            empty_guard_count != 1 || progress_guard_count != 1 || mandatory_fallback_count != 1 ||
            update_reserve_count != 1 || pick_override_count != 1 || guaranteed_pick_count != 1 ||
            best_effort_count != 1 || designated_clock_count != 1 ||
            bsp_count != 1 || lock_order_count < 1 || memory_boundary_count != 1 ||
            non_ostd_lock_count != 0) {
            print "scheduler per-CPU source gate: ownership, reservation, clock, progress, or synchronization contract changed" > "/dev/stderr"
            exit 1
        }
        if (!(cpu_count_line < capacity_line && capacity_line < allocation_loop_line &&
              selected_cpu_line < existing_owner_line && existing_owner_line < owner_target_line &&
              owner_target_line < owner_queue_line && owner_queue_line < second_cas_line &&
              target_guard_line < binding_precondition_line &&
              binding_precondition_line < runnable_precondition_line &&
              runnable_precondition_line < reservation_owner_line &&
              reservation_owner_line < take_line && take_line < remove_line &&
              clock_guard_line < tick_line && empty_guard_line < progress_guard_line &&
              progress_guard_line < mandatory_fallback_line &&
              update_reserve_line < pick_override_line && pick_override_line < guaranteed_pick_line)) {
            print "scheduler per-CPU source gate: owner-CAS, precondition-before-take, or reservation ordering changed" > "/dev/stderr"
            exit 1
        }
        print "scheduler per-CPU source gate: PASS existing_owner_queue=true preconditions_before_take=true local_reservation=true designated_clock=bsp idle_queue_no_fallback=true lock_order=rq_then_policy placement=bsp"
    }
' "$source_file"

awk '
    /^[[:space:]]*pub fn prepare\(/ {
        in_prepare = 1
    }
    in_prepare && /^[[:space:]]*pub fn take_bound_proposal\(/ {
        in_prepare = 0
    }
    in_prepare && index($0, "if presented != self.binding") {
        stale_count++
        stale_line = NR
    }
    in_prepare && index($0, "if self.mode != SchedulerMode::Bound") {
        supervisor_count++
        supervisor_line = NR
    }
    in_prepare && index($0, "if !known_task") {
        task_count++
        task_line = NR
    }
    in_prepare && index($0, "let lease_deadline_tick = self") {
        deadline_count++
        deadline_line = NR
    }
    in_prepare && index($0, "let receipt = PreparedProposal {") {
        build_count++
        build_line = NR
    }
    in_prepare && index($0, "self.pending = Some(proposal);") {
        pending_count++
        pending_line = NR
    }
    in_prepare && index($0, "self.lease_deadline_tick = lease_deadline_tick;") {
        lease_count++
        lease_line = NR
    }
    in_prepare && index($0, "Ok(receipt)") {
        return_count++
        return_line = NR
    }
    END {
        if (stale_count != 1 || supervisor_count != 1 || task_count != 1 ||
            deadline_count != 1 || build_count != 1 || pending_count != 1 ||
            lease_count != 1 || return_count != 1) {
            print "scheduler transition gate: expected three reject gates and one checked deadline/receipt/pending/lease/return" > "/dev/stderr"
            exit 1
        }
        if (!(stale_line < supervisor_line && supervisor_line < task_line &&
              task_line < deadline_line && deadline_line < build_line &&
              build_line < pending_line && pending_line < lease_line &&
              lease_line < return_line)) {
            print "scheduler transition gate: rejection, failure-atomic calculation, or receipt publication ordering changed" > "/dev/stderr"
            exit 1
        }
        print "scheduler transition gate: PASS rejected_proposals_do_not_mutate=true checked_deadline_before_mutation=true receipt_after_pending_and_lease=true"
    }
' "$gate_source"

# Deterministic host oracle for the adapter protocol. This deliberately models
# only the queue/policy hand-off checked above; it is not OSTD SMP evidence.
awk '
    function fail(message) {
        print "scheduler foundation host oracle: " message > "/dev/stderr"
        exit 1
    }
    function reset(    cpu) {
        mode = "Bound"
        binding = 1
        pending = -1
        ticks = 0
        picks = 0
        for (cpu = 0; cpu < 4; cpu++) {
            runnable[cpu] = 0
            reserved[cpu] = 0
            insertions[cpu] = 0
        }
    }
    function prepare(target) {
        if (pending != -1)
            return "Busy"
        pending = target
        return "Prepared"
    }
    function reserve(cpu, cause, current_absent,    force_progress) {
        if (reserved[cpu])
            return 1
        if (runnable[cpu] == 0)
            return 0
        if (mode == "Bound" && (cause != "Tick" || current_absent) && pending == cpu) {
            pending = -1
            runnable[cpu]--
            reserved[cpu] = 1
            return 1
        }
        force_progress = (cause == "Wait" || current_absent)
        if (mode == "Bound" && !force_progress)
            return 0
        if (mode == "Bound") {
            mode = "Fallback"
            binding++
            pending = -1
        }
        runnable[cpu]--
        reserved[cpu] = 1
        picks++
        return 1
    }
    function pick(cpu) {
        if (!reserved[cpu])
            return 0
        reserved[cpu] = 0
        return 1
    }
    function tick(cpu) {
        if (cpu == 0)
            ticks++
    }
    function wake_target(selected, observed_owner) {
        return observed_owner >= 0 ? observed_owner : selected
    }
    function wake(selected, observed_owner, owner_cleared,    target) {
        target = wake_target(selected, observed_owner)
        if (observed_owner >= 0 && !owner_cleared)
            return 0
        insertions[target]++
        return 1
    }
    function runnable_admission(is_runnable, is_current) {
        return is_runnable
    }
    BEGIN {
        # A foreign proposal cannot make q1 return true and then fail pick:
        # mandatory progress atomically falls back and reserves a local task.
        reset()
        runnable[1] = 1
        pending = 0
        if (!reserve(1, "Wait", 0) || mode != "Fallback" || pending != -1 || !reserved[1])
            fail("foreign-target Wait did not produce a stable fallback reservation")
        mode = "Bound"
        pending = 0
        if (!pick(1) || pending != 0)
            fail("rebind or a new foreign proposal invalidated a local reservation")

        # A consumed local proposal remains pickable after another CPU prepares.
        reset()
        runnable[0] = 1
        pending = 0
        if (!reserve(0, "Yield", 0) || prepare(1) != "Prepared" || !pick(0) || pending != 1)
            fail("bound reservation was invalidated by a later prepare")

        # Rebind after fallback selection cannot invalidate the selected Arc.
        reset()
        mode = "Fallback"
        runnable[1] = 1
        if (!reserve(1, "Yield", 0))
            fail("fallback did not reserve a runnable task")
        mode = "Bound"
        if (!pick(1))
            fail("rebind invalidated a fallback reservation")

        # An empty AP queue does not advance the global binding. Once a wake
        # supplies real work, best effort establishes progress exactly once.
        reset()
        if (reserve(1, "Wait", 0) || mode != "Bound" || binding != 1)
            fail("idle AP forced global fallback")
        runnable[1] = 1
        if (!reserve(1, "BestEffort", 1) || !pick(1) || mode != "Fallback")
            fail("a post-idle wake could not make progress")

        # Existing task ownership selects the observed owner queue, never the
        # new placement choice, for both sides of the sleep/wake race.
        reset()
        if (wake_target(0, 1) != 1 || wake(0, 1, 0) != 0 || insertions[0] != 0 || insertions[1] != 0)
            fail("wake target ignored existing owner")
        if (wake(0, 1, 1) != 1 || insertions[0] != 0 || insertions[1] != 1)
            fail("wake-after-dequeue was not inserted once on the observed owner queue")

        # Busy is failure-atomic and a running-only task is not admissible.
        reset()
        pending = 0
        if (prepare(1) != "Busy" || pending != 0)
            fail("Busy prepare replaced the accepted proposal")
        if (runnable_admission(0, 1) != 0 || runnable_admission(1, 0) != 1)
            fail("proposal admission included current instead of runnable")

        # Four per-CPU callbacks represent one lease step because only the
        # designated BSP clock CPU advances the global gate.
        reset()
        tick(0); tick(1); tick(2); tick(3)
        if (ticks != 1)
            fail("per-CPU callbacks multiplied the global lease clock")

        print "scheduler foundation host oracle: PASS foreign_target_wait=reserved prepare_after_update=stable fallback_rebind=stable idle_ap=no_fallback wake_owner=preserved busy=failure_atomic runnable_only=true four_cpu_ticks=1"
    }
'

if [[ ${NEXUS_SCHEDULER_NEGATIVE_SELFTEST:-1} == 1 ]]; then
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    sed '0,/self\.queues\.get(index)/s//self.queues[index]/' \
        "$source_file" >"$tmp/direct-index.rs"
    if NEXUS_SCHEDULER_NEGATIVE_SELFTEST=0 \
        bash "$0" "$tmp/direct-index.rs" "$gate_source" >/dev/null 2>&1; then
        echo "scheduler per-CPU negative gate accepted direct queue indexing" >&2
        exit 1
    fi

    sed '0,/(cpu_index < queue_count)/s//(cpu_index <= queue_count)/' \
        "$source_file" >"$tmp/inclusive-bound.rs"
    if NEXUS_SCHEDULER_NEGATIVE_SELFTEST=0 \
        bash "$0" "$tmp/inclusive-bound.rs" "$gate_source" >/dev/null 2>&1; then
        echo "scheduler per-CPU negative gate accepted inclusive upper bound" >&2
        exit 1
    fi

    sed '0,/let cpu_count = num_cpus();/s//let cpu_count = 1usize;/' \
        "$source_file" >"$tmp/hard-coded-one.rs"
    if NEXUS_SCHEDULER_NEGATIVE_SELFTEST=0 \
        bash "$0" "$tmp/hard-coded-one.rs" "$gate_source" >/dev/null 2>&1; then
        echo "scheduler per-CPU negative gate accepted a hard-coded single queue" >&2
        exit 1
    fi

    sed '0,/(true, owner_cpu)/s//(true, selected_cpu)/' \
        "$source_file" >"$tmp/wrong-owner.rs"
    if NEXUS_SCHEDULER_NEGATIVE_SELFTEST=0 \
        bash "$0" "$tmp/wrong-owner.rs" "$gate_source" >/dev/null 2>&1; then
        echo "scheduler per-CPU negative gate accepted selected CPU in place of existing owner" >&2
        exit 1
    fi

    sed '0,/queue\.runnable_position(task_id)/s//queue.runnable_position(task_id + 1)/' \
        "$source_file" >"$tmp/non-runnable-admission.rs"
    if NEXUS_SCHEDULER_NEGATIVE_SELFTEST=0 \
        bash "$0" "$tmp/non-runnable-admission.rs" "$gate_source" >/dev/null 2>&1; then
        echo "scheduler per-CPU negative gate accepted changed runnable-only admission" >&2
        exit 1
    fi

    sed '0,/ProposalResult::RejectBusy/s//ProposalResult::RejectUnknownTask/' \
        "$source_file" >"$tmp/no-busy.rs"
    if NEXUS_SCHEDULER_NEGATIVE_SELFTEST=0 \
        bash "$0" "$tmp/no-busy.rs" "$gate_source" >/dev/null 2>&1; then
        echo "scheduler per-CPU negative gate accepted missing Busy result" >&2
        exit 1
    fi

    sed '0,/self\.runnable_owner_matches(runnable_index)/s//true/' \
        "$source_file" >"$tmp/no-owner-precondition.rs"
    if NEXUS_SCHEDULER_NEGATIVE_SELFTEST=0 \
        bash "$0" "$tmp/no-owner-precondition.rs" "$gate_source" >/dev/null 2>&1; then
        echo "scheduler per-CPU negative gate accepted missing owner precondition" >&2
        exit 1
    fi

    sed '0,/flags != UpdateFlags::Tick || !self\.lease_clock_cpu/s//flags != UpdateFlags::Tick/' \
        "$source_file" >"$tmp/all-cpu-clock.rs"
    if NEXUS_SCHEDULER_NEGATIVE_SELFTEST=0 \
        bash "$0" "$tmp/all-cpu-clock.rs" "$gate_source" >/dev/null 2>&1; then
        echo "scheduler per-CPU negative gate accepted all-CPU lease advancement" >&2
        exit 1
    fi

    sed '0,/self\.reserve_next(cause)/s//!self.runnable.is_empty()/' \
        "$source_file" >"$tmp/no-update-reservation.rs"
    if NEXUS_SCHEDULER_NEGATIVE_SELFTEST=0 \
        bash "$0" "$tmp/no-update-reservation.rs" "$gate_source" >/dev/null 2>&1; then
        echo "scheduler per-CPU negative gate accepted update without local reservation" >&2
        exit 1
    fi

    sed '0,/if self\.runnable\.is_empty()/s//if false/' \
        "$source_file" >"$tmp/idle-fallback.rs"
    if NEXUS_SCHEDULER_NEGATIVE_SELFTEST=0 \
        bash "$0" "$tmp/idle-fallback.rs" "$gate_source" >/dev/null 2>&1; then
        echo "scheduler per-CPU negative gate accepted removal of idle-queue guard" >&2
        exit 1
    fi

    echo "scheduler per-CPU negative assertions: PASS direct_index=rejected inclusive_bound=rejected hard_coded_one=rejected wrong_owner=rejected non_runnable=rejected no_busy=rejected no_owner_precondition=rejected all_cpu_clock=rejected no_reservation=rejected idle_fallback=rejected"
fi
