// SPDX-License-Identifier: MPL-2.0

//! OSTD scheduler adapter synchronization boundary.
//!
//! The CSER policy state (authority/binding, lease, proposal, and fallback
//! evidence) is global and protected by `policy`. Runnable/current task state
//! is partitioned into one `queues[cpu]` lock per CPU reported by OSTD. If an
//! operation needs both, it must acquire the local run-queue lock before the
//! global policy lock; no path may acquire them in the opposite order. In
//! short, the lock order is local run queue, then global policy.
//!
//! OSTD `SpinLock` acquire/release is the publication boundary for both state
//! classes. The task's OSTD-owned `schedule_info().cpu` transition remains the
//! ownership gate around enqueue/dequeue. A bound proposal is admitted while
//! holding its target run queue and then consumed into a queue-local
//! reservation before `update_current` reports that a pick is mandatory. This
//! layout removes the hard-coded single-queue indexing hazard and closes the
//! adapter's cross-lock time-of-check/time-of-use windows, but it does not
//! itself establish SMP scheduling correctness or change the current BSP
//! placement policy.

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use cser_transition_gates::scheduler::{
    SchedulerCrashReceipt, SchedulerError, SchedulerGate, SchedulerMode,
};
use ostd::{
    cpu::{CpuId, PinCurrentCpu, num_cpus},
    prelude::*,
    sync::SpinLock,
    task::{
        Task, disable_preempt,
        scheduler::{EnqueueFlags, LocalRunQueue, Scheduler, UpdateFlags},
    },
};

use crate::TaskData;
use crate::effect::EffectToken;

pub const FIRST_FALLBACK_SELECTION_ATTEMPT: u64 = 1;

pub use cser_transition_gates::scheduler::{FallbackEvidence, SchedulerBinding as Binding};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalResult {
    Prepared,
    RejectStale,
    RejectNoSupervisor,
    RejectBusy,
    RejectUnknownTask,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Proposal {
    binding: Binding,
    task_id: u64,
    target_cpu: usize,
    causal_token: Option<EffectToken>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrepareRejection {
    Stale { current_binding_epoch: u64 },
    NoSupervisor,
    Busy { pending_task_id: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectionCause {
    Tick,
    WaitOrExit,
    Yield,
    BestEffort,
}

impl SelectionCause {
    const fn may_consume_bound(self, current_absent: bool) -> bool {
        !matches!(self, Self::Tick) || current_absent
    }

    const fn requires_progress(self, current_absent: bool) -> bool {
        matches!(self, Self::WaitOrExit) || current_absent
    }
}

pub struct CserScheduler {
    policy: Arc<SpinLock<CserPolicy>>,
    queues: Vec<SpinLock<CserRunQueue>>,
}

impl CserScheduler {
    pub fn new(authority_epoch: u64, lease_ticks: u64) -> Self {
        let policy = Arc::new(SpinLock::new(CserPolicy::new(authority_epoch, lease_ticks)));
        let cpu_count = num_cpus();
        assert!(cpu_count > 0, "OSTD must report at least one CPU");
        let lease_clock_cpu = Self::cpu_index(Self::bsp_cpu());
        let mut queues = Vec::with_capacity(cpu_count);
        for cpu_index in 0..cpu_count {
            queues.push(SpinLock::new(CserRunQueue::new(
                cpu_index,
                cpu_index == lease_clock_cpu,
                Arc::clone(&policy),
            )));
        }
        Self { policy, queues }
    }

    fn bsp_cpu() -> CpuId {
        CpuId::bsp()
    }

    fn cpu_index(cpu: CpuId) -> usize {
        usize::try_from(u32::from(cpu)).expect("OSTD CPU identifiers fit usize")
    }

    fn checked_queue_index(cpu_index: usize, queue_count: usize) -> Option<usize> {
        (cpu_index < queue_count).then_some(cpu_index)
    }

    fn queue(&self, cpu: CpuId) -> &SpinLock<CserRunQueue> {
        let cpu_index = Self::cpu_index(cpu);
        let index = Self::checked_queue_index(cpu_index, self.queues.len()).unwrap_or_else(|| {
            panic!(
                "OSTD CPU {cpu_index} has no CSER run queue (queue_count={})",
                self.queues.len()
            )
        });
        self.queues.get(index).unwrap_or_else(|| {
            panic!(
                "validated CSER run-queue index {index} is absent (queue_count={})",
                self.queues.len()
            )
        })
    }

    fn select_cpu(&self) -> CpuId {
        // Preserve the v0.1 placement policy. Per-CPU storage is a safety
        // prerequisite, not a load-balancing or SMP-acceptance claim.
        Self::bsp_cpu()
    }

    fn prepare_rejection(policy: &CserPolicy, binding: Binding) -> Option<PrepareRejection> {
        if binding != policy.gate.binding() {
            return Some(PrepareRejection::Stale {
                current_binding_epoch: policy.gate.binding().binding_epoch,
            });
        }
        if policy.gate.mode() != SchedulerMode::Bound {
            return Some(PrepareRejection::NoSupervisor);
        }
        policy
            .gate
            .pending()
            .map(|proposal| PrepareRejection::Busy {
                pending_task_id: proposal.task_id,
            })
    }

    fn log_prepare_rejection(
        binding: Binding,
        task_id: u64,
        rejection: PrepareRejection,
    ) -> ProposalResult {
        match rejection {
            PrepareRejection::Stale {
                current_binding_epoch,
            } => {
                println!(
                    "CSER REJECT_STALE action=Prepare authority_epoch={} proposal_binding_epoch={} current_binding_epoch={} proposal_task={}",
                    binding.authority_epoch, binding.binding_epoch, current_binding_epoch, task_id,
                );
                ProposalResult::RejectStale
            }
            PrepareRejection::NoSupervisor => {
                println!(
                    "CSER REJECT_NO_SUPERVISOR action=Prepare authority_epoch={} binding_epoch={} proposal_task={}",
                    binding.authority_epoch, binding.binding_epoch, task_id,
                );
                ProposalResult::RejectNoSupervisor
            }
            PrepareRejection::Busy { pending_task_id } => {
                println!(
                    "CSER REJECT_BUSY action=Prepare authority_epoch={} binding_epoch={} pending_task={} proposal_task={}",
                    binding.authority_epoch, binding.binding_epoch, pending_task_id, task_id,
                );
                ProposalResult::RejectBusy
            }
        }
    }

    pub fn binding(&self) -> Binding {
        self.policy.disable_irq().lock().gate.binding()
    }

    pub fn propose(&self, binding: Binding, task_id: u64) -> ProposalResult {
        self.propose_inner(binding, task_id, None)
    }

    pub fn propose_scoped(
        &self,
        binding: Binding,
        task_id: u64,
        causal_token: EffectToken,
    ) -> ProposalResult {
        self.propose_inner(binding, task_id, Some(causal_token))
    }

    fn propose_inner(
        &self,
        binding: Binding,
        task_id: u64,
        causal_token: Option<EffectToken>,
    ) -> ProposalResult {
        let initial_rejection = {
            let policy = self.policy.disable_irq().lock();
            Self::prepare_rejection(&policy, binding)
        };
        if let Some(rejection) = initial_rejection {
            return Self::log_prepare_rejection(binding, task_id, rejection);
        }

        for (target_cpu, queue_lock) in self.queues.iter().enumerate() {
            // A positive admission is one rq -> policy critical section. In
            // particular, a currently running task is not a runnable target.
            let queue = queue_lock.disable_irq().lock();
            let Some(runnable_index) = queue.runnable_position(task_id) else {
                continue;
            };
            assert!(
                queue.runnable_owner_matches(runnable_index),
                "runnable task owner must match its CSER run queue"
            );

            let mut policy = self.policy.disable_irq().lock();
            if let Some(rejection) = Self::prepare_rejection(&policy, binding) {
                drop(policy);
                drop(queue);
                return Self::log_prepare_rejection(binding, task_id, rejection);
            }
            let receipt = policy
                .gate
                .prepare(
                    binding,
                    true,
                    Proposal {
                        binding,
                        task_id,
                        target_cpu,
                        causal_token,
                    },
                )
                .unwrap_or_else(|error| {
                    panic!("prevalidated scheduler prepare gate failed: {error:?}")
                });
            let projection = policy.gate.projection();
            drop(policy);
            drop(queue);

            if let Some(token) = causal_token {
                println!(
                    "CSER PrepareScoped service=scheduler scheduler_authority_epoch={} binding_epoch={} workload_authority_epoch={} scope={} effect={} proposal_task={}",
                    binding.authority_epoch,
                    binding.binding_epoch,
                    token.authority_epoch,
                    token.scope_id,
                    token.effect_id,
                    task_id,
                );
            } else {
                println!(
                    "CSER Prepare authority_epoch={} binding_epoch={} proposal_task={}",
                    binding.authority_epoch, binding.binding_epoch, task_id,
                );
            }
            println!(
                "CSER LeaseRenew action=Prepare authority_epoch={} binding_epoch={} proposal_task={} source={} tick={} previous_deadline_tick={} lease_deadline_tick={} lease_ticks={}",
                binding.authority_epoch,
                binding.binding_epoch,
                task_id,
                if causal_token.is_some() {
                    "scoped"
                } else {
                    "unscoped"
                },
                projection.tick,
                receipt.previous_deadline_tick,
                receipt.lease_deadline_tick,
                projection.lease_ticks,
            );
            return ProposalResult::Prepared;
        }

        let final_rejection = {
            let policy = self.policy.disable_irq().lock();
            Self::prepare_rejection(&policy, binding)
        };
        if let Some(rejection) = final_rejection {
            return Self::log_prepare_rejection(binding, task_id, rejection);
        }
        ProposalResult::RejectUnknownTask
    }

    pub fn crash(&self, binding: Binding, reason: &'static str) {
        let mut policy = self.policy.disable_irq().lock();
        assert_eq!(
            binding,
            policy.gate.binding(),
            "only the current binding can crash"
        );
        policy.enter_fallback(binding, reason);
    }

    pub fn crash_scoped(&self, binding: Binding, reason: &'static str, causal_token: EffectToken) {
        let mut policy = self.policy.disable_irq().lock();
        assert_eq!(
            binding,
            policy.gate.binding(),
            "only the current binding can crash"
        );
        assert_eq!(
            policy
                .gate
                .pending()
                .as_ref()
                .and_then(|proposal| proposal.causal_token),
            Some(causal_token),
            "scoped crash must fence its pending workload proposal"
        );
        policy.enter_fallback(binding, reason);
        println!(
            "CSER CrashScoped service=scheduler scheduler_authority_epoch={} binding_epoch={} workload_authority_epoch={} scope={} effect={} pending_scoped_cleared=true fallback=kernel_fifo",
            policy.gate.binding().authority_epoch,
            policy.gate.binding().binding_epoch,
            causal_token.authority_epoch,
            causal_token.scope_id,
            causal_token.effect_id,
        );
    }

    pub fn rebind(&self, authority_epoch: u64) -> Binding {
        let mut policy = self.policy.disable_irq().lock();
        assert_eq!(authority_epoch, policy.gate.binding().authority_epoch);
        assert_eq!(policy.gate.mode(), SchedulerMode::Fallback);
        assert!(
            policy.gate.projection().first_fallback_pick.is_some(),
            "rebind requires the kernel fallback to be running"
        );
        let binding = policy
            .gate
            .rebind(authority_epoch)
            .expect("validated scheduler rebind must succeed");
        println!(
            "CSER Rebind authority_epoch={} binding_epoch={}",
            binding.authority_epoch, binding.binding_epoch,
        );
        binding
    }

    pub fn fallback_evidence(&self) -> Option<FallbackEvidence> {
        self.policy.disable_irq().lock().gate.fallback_evidence()
    }
}

impl Scheduler<Task> for CserScheduler {
    fn enqueue(&self, runnable: Arc<Task>, flags: EnqueueFlags) -> Option<CpuId> {
        let selected_cpu = self.select_cpu();
        let (still_in_queue, target_cpu) =
            if let Err(owner_cpu) = runnable.schedule_info().cpu.set_if_is_none(selected_cpu) {
                debug_assert!(flags != EnqueueFlags::Spawn);
                (true, owner_cpu)
            } else {
                (false, selected_cpu)
            };

        // Match OSTD's wake-up protocol exactly: if the first CAS observed an
        // existing owner, serialize with that owner's queue. The second CAS
        // then distinguishes "still queued/running" from "dequeued while the
        // waker waited" without ever inserting the same task on two CPUs.
        let mut queue = self.queue(target_cpu).disable_irq().lock();
        if still_in_queue
            && runnable
                .schedule_info()
                .cpu
                .set_if_is_none(target_cpu)
                .is_err()
        {
            return None;
        }
        queue.runnable.push_back(runnable);
        None
    }

    fn local_rq_with(&self, f: &mut dyn FnMut(&dyn LocalRunQueue<Task>)) {
        let guard = disable_preempt();
        let queue = self.queue(guard.current_cpu()).disable_irq().lock();
        f(&*queue);
    }

    fn mut_local_rq_with(&self, f: &mut dyn FnMut(&mut dyn LocalRunQueue<Task>)) {
        let guard = disable_preempt();
        let mut queue = self.queue(guard.current_cpu()).disable_irq().lock();
        f(&mut *queue);
    }
}

struct CserPolicy {
    gate: SchedulerGate<Proposal>,
}

impl CserPolicy {
    fn new(authority_epoch: u64, lease_ticks: u64) -> Self {
        Self {
            gate: SchedulerGate::new(authority_epoch, lease_ticks)
                .expect("scheduler authority epoch and lease are nonzero"),
        }
    }

    fn enter_fallback(&mut self, presented: Binding, reason: &'static str) {
        let receipt = match self.gate.enter_fallback(presented) {
            Ok(receipt) => receipt,
            Err(SchedulerError::AlreadyFallback) => return,
            Err(error) => panic!("validated current scheduler fallback failed: {error:?}"),
        };
        self.log_fallback(receipt, reason);
    }

    fn log_fallback(&self, receipt: SchedulerCrashReceipt, reason: &'static str) {
        println!(
            "CSER Crash authority_epoch={} previous_binding_epoch={} binding_epoch={} tick={} reason={}",
            self.gate.binding().authority_epoch,
            receipt.previous_binding_epoch,
            receipt.binding_epoch,
            receipt.crash_tick,
            reason,
        );
    }
}

struct CserRunQueue {
    cpu_index: usize,
    lease_clock_cpu: bool,
    current: Option<Arc<Task>>,
    runnable: VecDeque<Arc<Task>>,
    reserved: Option<Arc<Task>>,
    policy: Arc<SpinLock<CserPolicy>>,
}

impl CserRunQueue {
    fn new(cpu_index: usize, lease_clock_cpu: bool, policy: Arc<SpinLock<CserPolicy>>) -> Self {
        Self {
            cpu_index,
            lease_clock_cpu,
            current: None,
            runnable: VecDeque::new(),
            reserved: None,
            policy,
        }
    }

    fn task_id(task: &Task) -> u64 {
        task.data()
            .downcast_ref::<TaskData>()
            .expect("all prototype tasks carry TaskData")
            .id
    }

    fn cpu_id(&self) -> CpuId {
        self.cpu_index
            .try_into()
            .expect("CSER run queues are created from OSTD CPU identifiers")
    }

    fn runnable_position(&self, task_id: u64) -> Option<usize> {
        self.runnable
            .iter()
            .position(|task| Self::task_id(task) == task_id)
    }

    fn runnable_owner_matches(&self, index: usize) -> bool {
        self.runnable.get(index).is_some_and(|task| {
            task.schedule_info()
                .cpu
                .get()
                .is_some_and(|owner| owner == self.cpu_id())
        })
    }

    fn install_current(&mut self, task: Arc<Task>) {
        if let Some(previous) = self.current.replace(task) {
            self.runnable.push_back(previous);
        }
    }

    fn advance_lease_clock(&mut self, flags: UpdateFlags) {
        if flags != UpdateFlags::Tick || !self.lease_clock_cpu {
            return;
        }
        let policy_handle = Arc::clone(&self.policy);
        let mut policy = policy_handle.disable_irq().lock();
        if let Some(receipt) = policy
            .gate
            .tick()
            .expect("scheduler tick counter overflow defeats recovery")
        {
            policy.log_fallback(receipt, "policy_lease_expired");
        }
    }

    fn reserve_next(&mut self, cause: SelectionCause) -> bool {
        if self.reserved.is_some() {
            return true;
        }
        if self.runnable.is_empty() {
            return false;
        }

        let current_absent = self.current.is_none();
        let policy_handle = Arc::clone(&self.policy);
        let mut policy = policy_handle.disable_irq().lock();

        if policy.gate.mode() == SchedulerMode::Bound
            && cause.may_consume_bound(current_absent)
            && let Some(proposal) = policy.gate.pending()
            && proposal.target_cpu == self.cpu_index
        {
            assert_eq!(
                proposal.binding,
                policy.gate.binding(),
                "a bound proposal must carry the current scheduler binding"
            );
            let runnable_index = self
                .runnable_position(proposal.task_id)
                .expect("an admitted bound proposal must remain runnable until reservation");
            assert!(
                self.runnable_owner_matches(runnable_index),
                "a reserved task must still be owned by its target run queue"
            );

            // All proposal and queue preconditions have been checked while
            // holding rq -> policy. Only now may the global pending slot be
            // consumed and the task leave the runnable collection.
            let consumed = policy
                .gate
                .take_bound_proposal()
                .expect("bound scheduler gate must accept proposal take")
                .expect("the prevalidated bound proposal must still be pending");
            assert_eq!(
                consumed, proposal,
                "scheduler proposal changed under its gate lock"
            );
            let next = self
                .runnable
                .remove(runnable_index)
                .expect("the prevalidated runnable index must remain present");
            drop(policy);
            self.reserved = Some(next);
            println!(
                "CSER Commit authority_epoch={} binding_epoch={} proposal_task={} state=Committed",
                proposal.binding.authority_epoch, proposal.binding.binding_epoch, proposal.task_id,
            );
            return true;
        }

        if policy.gate.mode() == SchedulerMode::Bound {
            if !cause.requires_progress(current_absent) {
                return false;
            }
            // Do not crash the global policy merely because an AP became
            // idle. This path is reached only after a runnable task exists and
            // the bound supervisor supplied no executable local decision.
            let binding = policy.gate.binding();
            policy.enter_fallback(binding, "mandatory_progress");
        }

        debug_assert_eq!(policy.gate.mode(), SchedulerMode::Fallback);
        let next = self
            .runnable
            .pop_front()
            .expect("fallback reservation requires a nonempty run queue");
        let task_id = Self::task_id(&next);
        let pick = policy
            .gate
            .note_fallback_pick(task_id)
            .expect("fallback task selection must be admitted by scheduler gate");
        let binding = policy.gate.binding();
        drop(policy);
        self.reserved = Some(next);
        println!(
            "CSER FallbackPick authority_epoch={} binding_epoch={} task={} tick={} selection_attempt={}",
            binding.authority_epoch,
            binding.binding_epoch,
            task_id,
            pick.tick,
            pick.selection_attempt,
        );
        true
    }

    fn install_reserved(&mut self) -> Option<&Arc<Task>> {
        let next = self.reserved.take()?;
        self.install_current(next);
        self.current.as_ref()
    }
}

impl LocalRunQueue<Task> for CserRunQueue {
    fn current(&self) -> Option<&Arc<Task>> {
        self.current.as_ref()
    }

    fn update_current(&mut self, flags: UpdateFlags) -> bool {
        // OSTD holds this queue lock across update_current(true) and pick_next.
        // Reserve the concrete Arc first, so a concurrent prepare/crash/rebind
        // cannot invalidate the mandatory pick between those two trait calls.
        self.advance_lease_clock(flags);
        let cause = match flags {
            UpdateFlags::Tick => SelectionCause::Tick,
            UpdateFlags::Wait | UpdateFlags::Exit => SelectionCause::WaitOrExit,
            UpdateFlags::Yield => SelectionCause::Yield,
        };
        self.reserve_next(cause)
    }

    fn pick_next(&mut self) -> &Arc<Task> {
        self.install_reserved()
            .expect("update_current(true) must leave one local reservation")
    }

    fn try_pick_next(&mut self) -> Option<&Arc<Task>> {
        if self.reserved.is_none() && !self.reserve_next(SelectionCause::BestEffort) {
            return None;
        }
        self.install_reserved()
    }

    fn dequeue_current(&mut self) -> Option<Arc<Task>> {
        self.current
            .take()
            .inspect(|task| task.schedule_info().cpu.set_to_none())
    }
}
