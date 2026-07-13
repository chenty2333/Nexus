// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};

use cser_transition_gates::scheduler::{
    SchedulerCrashReceipt, SchedulerError, SchedulerGate, SchedulerMode,
};
use ostd::{
    cpu::{CpuId, PinCurrentCpu},
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
    RejectUnknownTask,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Proposal {
    binding: Binding,
    task_id: u64,
    causal_token: Option<EffectToken>,
}

pub struct CserScheduler {
    queues: Vec<SpinLock<CserRunQueue>>,
}

impl CserScheduler {
    pub fn new(authority_epoch: u64, lease_ticks: u64) -> Self {
        Self {
            queues: vec![SpinLock::new(CserRunQueue::new(
                authority_epoch,
                lease_ticks,
            ))],
        }
    }

    pub fn binding(&self) -> Binding {
        let queue = self.queues[0].disable_irq().lock();
        queue.gate.binding()
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
        let mut queue = self.queues[0].disable_irq().lock();
        let known_task = queue.contains_task(task_id);
        let receipt = match queue.gate.prepare(
            binding,
            known_task,
            Proposal {
                binding,
                task_id,
                causal_token,
            },
        ) {
            Ok(receipt) => receipt,
            Err(SchedulerError::StaleBinding) => {
                println!(
                    "CSER REJECT_STALE action=Prepare authority_epoch={} proposal_binding_epoch={} current_binding_epoch={} proposal_task={}",
                    binding.authority_epoch,
                    binding.binding_epoch,
                    queue.gate.binding().binding_epoch,
                    task_id,
                );
                return ProposalResult::RejectStale;
            }
            Err(SchedulerError::NoSupervisor) => {
                println!(
                    "CSER REJECT_NO_SUPERVISOR action=Prepare authority_epoch={} binding_epoch={} proposal_task={}",
                    binding.authority_epoch, binding.binding_epoch, task_id,
                );
                return ProposalResult::RejectNoSupervisor;
            }
            Err(SchedulerError::UnknownTask) => return ProposalResult::RejectUnknownTask,
            Err(error) => panic!("scheduler prepare gate failed unexpectedly: {error:?}"),
        };
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
            queue.gate.projection().tick,
            receipt.previous_deadline_tick,
            receipt.lease_deadline_tick,
            queue.gate.projection().lease_ticks,
        );
        ProposalResult::Prepared
    }

    pub fn crash(&self, binding: Binding, reason: &'static str) {
        let mut queue = self.queues[0].disable_irq().lock();
        assert_eq!(
            binding,
            queue.gate.binding(),
            "only the current binding can crash"
        );
        queue.enter_fallback(binding, reason);
    }

    pub fn crash_scoped(&self, binding: Binding, reason: &'static str, causal_token: EffectToken) {
        let mut queue = self.queues[0].disable_irq().lock();
        assert_eq!(
            binding,
            queue.gate.binding(),
            "only the current binding can crash"
        );
        assert_eq!(
            queue
                .gate
                .pending()
                .as_ref()
                .and_then(|proposal| proposal.causal_token),
            Some(causal_token),
            "scoped crash must fence its pending workload proposal"
        );
        queue.enter_fallback(binding, reason);
        println!(
            "CSER CrashScoped service=scheduler scheduler_authority_epoch={} binding_epoch={} workload_authority_epoch={} scope={} effect={} pending_scoped_cleared=true fallback=kernel_fifo",
            queue.gate.binding().authority_epoch,
            queue.gate.binding().binding_epoch,
            causal_token.authority_epoch,
            causal_token.scope_id,
            causal_token.effect_id,
        );
    }

    pub fn rebind(&self, authority_epoch: u64) -> Binding {
        let mut queue = self.queues[0].disable_irq().lock();
        assert_eq!(authority_epoch, queue.gate.binding().authority_epoch);
        assert_eq!(queue.gate.mode(), SchedulerMode::Fallback);
        assert!(
            queue.gate.projection().first_fallback_pick.is_some(),
            "rebind requires the kernel fallback to be running"
        );
        let binding = queue
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
        let queue = self.queues[0].disable_irq().lock();
        queue.gate.fallback_evidence()
    }
}

impl Scheduler<Task> for CserScheduler {
    fn enqueue(&self, runnable: Arc<Task>, flags: EnqueueFlags) -> Option<CpuId> {
        let target = CpuId::bsp();
        let still_in_queue =
            if let Err(task_cpu) = runnable.schedule_info().cpu.set_if_is_none(target) {
                debug_assert!(flags != EnqueueFlags::Spawn);
                task_cpu == target
            } else {
                false
            };

        let mut queue = self.queues[0].disable_irq().lock();
        if still_in_queue && runnable.schedule_info().cpu.set_if_is_none(target).is_err() {
            return None;
        }
        queue.runnable.push_back(runnable);
        None
    }

    fn local_rq_with(&self, f: &mut dyn FnMut(&dyn LocalRunQueue<Task>)) {
        let guard = disable_preempt();
        let cpu = u32::from(guard.current_cpu()) as usize;
        let queue = self.queues[cpu].disable_irq().lock();
        f(&*queue);
    }

    fn mut_local_rq_with(&self, f: &mut dyn FnMut(&mut dyn LocalRunQueue<Task>)) {
        let guard = disable_preempt();
        let cpu = u32::from(guard.current_cpu()) as usize;
        let mut queue = self.queues[cpu].disable_irq().lock();
        f(&mut *queue);
    }
}

struct CserRunQueue {
    current: Option<Arc<Task>>,
    runnable: VecDeque<Arc<Task>>,
    gate: SchedulerGate<Proposal>,
}

impl CserRunQueue {
    fn new(authority_epoch: u64, lease_ticks: u64) -> Self {
        Self {
            current: None,
            runnable: VecDeque::new(),
            gate: SchedulerGate::new(authority_epoch, lease_ticks)
                .expect("scheduler authority epoch and lease are nonzero"),
        }
    }

    fn task_id(task: &Task) -> u64 {
        task.data()
            .downcast_ref::<TaskData>()
            .expect("all prototype tasks carry TaskData")
            .id
    }

    fn contains_task(&self, task_id: u64) -> bool {
        self.current
            .as_deref()
            .is_some_and(|task| Self::task_id(task) == task_id)
            || self
                .runnable
                .iter()
                .any(|task| Self::task_id(task) == task_id)
    }

    fn remove_task(&mut self, task_id: u64) -> Option<Arc<Task>> {
        let index = self
            .runnable
            .iter()
            .position(|task| Self::task_id(task) == task_id)?;
        self.runnable.remove(index)
    }

    fn install_current(&mut self, task: Arc<Task>) {
        if let Some(previous) = self.current.replace(task) {
            self.runnable.push_back(previous);
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

impl LocalRunQueue<Task> for CserRunQueue {
    fn current(&self) -> Option<&Arc<Task>> {
        self.current.as_ref()
    }

    fn update_current(&mut self, flags: UpdateFlags) -> bool {
        match flags {
            UpdateFlags::Tick => {
                if let Some(receipt) = self
                    .gate
                    .tick()
                    .expect("scheduler tick counter overflow defeats recovery")
                {
                    self.log_fallback(receipt, "policy_lease_expired");
                }
                self.gate.mode() == SchedulerMode::Fallback && !self.runnable.is_empty()
            }
            UpdateFlags::Wait | UpdateFlags::Exit => {
                if self.gate.mode() == SchedulerMode::Bound && self.gate.pending().is_none() {
                    let binding = self.gate.binding();
                    self.enter_fallback(binding, "mandatory_progress");
                }
                !self.runnable.is_empty()
            }
            UpdateFlags::Yield => {
                !self.runnable.is_empty()
                    && (self.gate.mode() == SchedulerMode::Fallback
                        || self.gate.pending().is_some())
            }
        }
    }

    fn try_pick_next(&mut self) -> Option<&Arc<Task>> {
        let next = match self.gate.mode() {
            SchedulerMode::Bound => {
                let proposal = self
                    .gate
                    .take_bound_proposal()
                    .expect("bound scheduler gate must accept proposal take")?;
                if proposal.binding != self.gate.binding() {
                    return None;
                }
                let next = self.remove_task(proposal.task_id)?;
                println!(
                    "CSER Commit authority_epoch={} binding_epoch={} proposal_task={} state=Committed",
                    proposal.binding.authority_epoch,
                    proposal.binding.binding_epoch,
                    proposal.task_id,
                );
                next
            }
            SchedulerMode::Fallback => {
                // A failed empty-queue probe is not a selection attempt: it
                // chooses no task and emits no FallbackPick receipt. Pop
                // first so the diagnostic ordinal remains dense over the
                // successful selections represented by those receipts.
                let next = self.runnable.pop_front()?;
                let pick = self
                    .gate
                    .note_fallback_pick(Self::task_id(&next))
                    .expect("fallback task selection must be admitted by scheduler gate");
                println!(
                    "CSER FallbackPick authority_epoch={} binding_epoch={} task={} tick={} selection_attempt={}",
                    self.gate.binding().authority_epoch,
                    self.gate.binding().binding_epoch,
                    Self::task_id(&next),
                    pick.tick,
                    pick.selection_attempt,
                );
                next
            }
        };
        self.install_current(next);
        self.current.as_ref()
    }

    fn dequeue_current(&mut self) -> Option<Arc<Task>> {
        self.current
            .take()
            .inspect(|task| task.schedule_info().cpu.set_to_none())
    }
}
