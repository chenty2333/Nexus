// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding {
    pub authority_epoch: u64,
    pub binding_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalResult {
    Prepared,
    RejectStale,
    RejectNoSupervisor,
    RejectUnknownTask,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyMode {
    Bound,
    Fallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Proposal {
    binding: Binding,
    task_id: u64,
    causal_token: Option<EffectToken>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FallbackEvidence {
    pub lease_deadline_tick: u64,
    pub crash_tick: u64,
    pub pick_tick: u64,
    pub pick_task_id: u64,
    pub pick_selection_attempt: u64,
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
        queue.binding
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
        if binding != queue.binding {
            println!(
                "CSER REJECT_STALE action=Prepare authority_epoch={} proposal_binding_epoch={} current_binding_epoch={} proposal_task={}",
                binding.authority_epoch,
                binding.binding_epoch,
                queue.binding.binding_epoch,
                task_id,
            );
            return ProposalResult::RejectStale;
        }
        if queue.mode == PolicyMode::Fallback {
            println!(
                "CSER REJECT_NO_SUPERVISOR action=Prepare authority_epoch={} binding_epoch={} proposal_task={}",
                binding.authority_epoch, binding.binding_epoch, task_id,
            );
            return ProposalResult::RejectNoSupervisor;
        }
        if !queue.contains_task(task_id) {
            return ProposalResult::RejectUnknownTask;
        }

        queue.pending = Some(Proposal {
            binding,
            task_id,
            causal_token,
        });
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
        ProposalResult::Prepared
    }

    pub fn crash(&self, binding: Binding, reason: &'static str) {
        let mut queue = self.queues[0].disable_irq().lock();
        assert_eq!(binding, queue.binding, "only the current binding can crash");
        queue.enter_fallback(reason);
    }

    pub fn crash_scoped(&self, binding: Binding, reason: &'static str, causal_token: EffectToken) {
        let mut queue = self.queues[0].disable_irq().lock();
        assert_eq!(binding, queue.binding, "only the current binding can crash");
        assert_eq!(
            queue
                .pending
                .as_ref()
                .and_then(|proposal| proposal.causal_token),
            Some(causal_token),
            "scoped crash must fence its pending workload proposal"
        );
        queue.enter_fallback(reason);
        println!(
            "CSER CrashScoped service=scheduler scheduler_authority_epoch={} binding_epoch={} workload_authority_epoch={} scope={} effect={} pending_scoped_cleared=true fallback=kernel_fifo",
            queue.binding.authority_epoch,
            queue.binding.binding_epoch,
            causal_token.authority_epoch,
            causal_token.scope_id,
            causal_token.effect_id,
        );
    }

    pub fn rebind(&self, authority_epoch: u64) -> Binding {
        let mut queue = self.queues[0].disable_irq().lock();
        assert_eq!(authority_epoch, queue.binding.authority_epoch);
        assert_eq!(queue.mode, PolicyMode::Fallback);
        assert!(
            queue.fallback_pick_tick.is_some(),
            "rebind requires the kernel fallback to be running"
        );
        queue.mode = PolicyMode::Bound;
        queue.pending = None;
        queue.lease_deadline_tick = queue.tick.saturating_add(queue.lease_ticks);
        println!(
            "CSER Rebind authority_epoch={} binding_epoch={}",
            queue.binding.authority_epoch, queue.binding.binding_epoch,
        );
        queue.binding
    }

    pub fn fallback_evidence(&self) -> Option<FallbackEvidence> {
        let queue = self.queues[0].disable_irq().lock();
        Some(FallbackEvidence {
            lease_deadline_tick: queue.lease_deadline_tick,
            crash_tick: queue.crash_tick?,
            pick_tick: queue.fallback_pick_tick?,
            pick_task_id: queue.fallback_pick_task_id?,
            pick_selection_attempt: queue.fallback_pick_selection_attempt?,
        })
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
    binding: Binding,
    pending: Option<Proposal>,
    mode: PolicyMode,
    tick: u64,
    lease_ticks: u64,
    lease_deadline_tick: u64,
    crash_tick: Option<u64>,
    fallback_pick_tick: Option<u64>,
    fallback_pick_task_id: Option<u64>,
    fallback_selection_attempts: u64,
    fallback_pick_selection_attempt: Option<u64>,
}

impl CserRunQueue {
    fn new(authority_epoch: u64, lease_ticks: u64) -> Self {
        Self {
            current: None,
            runnable: VecDeque::new(),
            binding: Binding {
                authority_epoch,
                binding_epoch: 1,
            },
            pending: None,
            mode: PolicyMode::Bound,
            tick: 0,
            lease_ticks,
            lease_deadline_tick: lease_ticks,
            crash_tick: None,
            fallback_pick_tick: None,
            fallback_pick_task_id: None,
            fallback_selection_attempts: 0,
            fallback_pick_selection_attempt: None,
        }
    }

    fn task_id(task: &Task) -> u64 {
        task.data()
            .downcast_ref::<TaskData>()
            .expect("all spike tasks carry TaskData")
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

    fn enter_fallback(&mut self, reason: &'static str) {
        if self.mode == PolicyMode::Fallback {
            return;
        }
        let previous_binding_epoch = self.binding.binding_epoch;
        self.binding.binding_epoch = self
            .binding
            .binding_epoch
            .checked_add(1)
            .expect("binding epoch overflow would defeat stale-reply fencing");
        self.mode = PolicyMode::Fallback;
        self.pending = None;
        self.crash_tick = Some(self.tick);
        self.fallback_pick_tick = None;
        self.fallback_pick_task_id = None;
        self.fallback_selection_attempts = 0;
        self.fallback_pick_selection_attempt = None;
        println!(
            "CSER Crash authority_epoch={} previous_binding_epoch={} binding_epoch={} tick={} reason={}",
            self.binding.authority_epoch,
            previous_binding_epoch,
            self.binding.binding_epoch,
            self.tick,
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
                self.tick = self.tick.saturating_add(1);
                if self.mode == PolicyMode::Bound && self.tick >= self.lease_deadline_tick {
                    self.enter_fallback("policy_lease_expired");
                }
                self.mode == PolicyMode::Fallback && !self.runnable.is_empty()
            }
            UpdateFlags::Wait | UpdateFlags::Exit => {
                if self.mode == PolicyMode::Bound && self.pending.is_none() {
                    self.enter_fallback("mandatory_progress");
                }
                !self.runnable.is_empty()
            }
            UpdateFlags::Yield => {
                !self.runnable.is_empty()
                    && (self.mode == PolicyMode::Fallback || self.pending.is_some())
            }
        }
    }

    fn try_pick_next(&mut self) -> Option<&Arc<Task>> {
        let next = match self.mode {
            PolicyMode::Bound => {
                let proposal = self.pending.take()?;
                if proposal.binding != self.binding {
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
            PolicyMode::Fallback => {
                self.fallback_selection_attempts = self
                    .fallback_selection_attempts
                    .checked_add(1)
                    .expect("fallback selection-attempt counter overflow");
                let selection_attempt = self.fallback_selection_attempts;
                let next = self.runnable.pop_front()?;
                if self.fallback_pick_tick.is_none() {
                    self.fallback_pick_tick = Some(self.tick);
                    self.fallback_pick_task_id = Some(Self::task_id(&next));
                    self.fallback_pick_selection_attempt = Some(selection_attempt);
                }
                println!(
                    "CSER FallbackPick authority_epoch={} binding_epoch={} task={} tick={} selection_attempt={}",
                    self.binding.authority_epoch,
                    self.binding.binding_epoch,
                    Self::task_id(&next),
                    self.tick,
                    selection_attempt,
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
