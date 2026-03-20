use alloc::collections::VecDeque;

use super::*;

#[derive(Debug, Default)]
pub(super) struct CpuSchedulerState {
    run_queue: VecDeque<ThreadId>,
    current_thread_id: Option<ThreadId>,
    reschedule_requested: bool,
    current_runtime_started_ns: Option<i64>,
    slice_deadline_ns: Option<i64>,
    online: bool,
}

impl CpuSchedulerState {
    pub(super) fn bootstrap_current(thread_id: ThreadId, now: i64) -> Self {
        Self {
            run_queue: VecDeque::new(),
            current_thread_id: Some(thread_id),
            reschedule_requested: false,
            current_runtime_started_ns: Some(now),
            slice_deadline_ns: now.checked_add(DEFAULT_TIME_SLICE_NS),
            online: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StartPlacementPolicy {
    PreserveAffinity,
    PreferIdlePeer,
}

const RQ_DEPTH_ENQUEUE_BACK: u16 = 1;
const RQ_DEPTH_ENQUEUE_FRONT: u16 = 2;
const RQ_DEPTH_DEQUEUE_LOCAL: u16 = 3;

impl Kernel {
    fn cpu_scheduler(&self, cpu_id: usize) -> Result<&CpuSchedulerState, zx_status_t> {
        self.cpu_schedulers.get(&cpu_id).ok_or(ZX_ERR_BAD_STATE)
    }

    fn cpu_scheduler_mut(&mut self, cpu_id: usize) -> &mut CpuSchedulerState {
        self.cpu_schedulers.entry(cpu_id).or_default()
    }

    fn current_cpu_scheduler(&self) -> Result<&CpuSchedulerState, zx_status_t> {
        self.cpu_scheduler(self.current_cpu_id())
    }

    fn current_cpu_scheduler_mut(&mut self) -> &mut CpuSchedulerState {
        let cpu_id = self.current_cpu_id();
        self.cpu_scheduler_mut(cpu_id)
    }

    pub(super) fn current_thread_id(&self) -> Result<ThreadId, zx_status_t> {
        self.current_cpu_scheduler()?
            .current_thread_id
            .ok_or(ZX_ERR_BAD_STATE)
    }

    pub(super) fn running_cpu_for_thread(&self, thread_id: ThreadId) -> Option<usize> {
        self.cpu_schedulers.iter().find_map(|(&cpu_id, scheduler)| {
            (scheduler.current_thread_id == Some(thread_id)).then_some(cpu_id)
        })
    }

    fn cpu_is_online(&self, cpu_id: usize) -> bool {
        self.cpu_schedulers
            .get(&cpu_id)
            .is_some_and(|scheduler| scheduler.online)
    }

    fn cpu_is_idle(&self, cpu_id: usize) -> bool {
        self.cpu_schedulers.get(&cpu_id).is_some_and(|scheduler| {
            scheduler.online
                && scheduler.current_thread_id.is_none()
                && scheduler.run_queue.is_empty()
        })
    }

    fn first_idle_cpu_excluding(&self, excluded_cpu_id: usize) -> Option<usize> {
        self.cpu_schedulers.iter().find_map(|(&cpu_id, scheduler)| {
            (cpu_id != excluded_cpu_id
                && scheduler.online
                && scheduler.current_thread_id.is_none()
                && scheduler.run_queue.is_empty())
            .then_some(cpu_id)
        })
    }

    fn note_run_queue_depth(&self, thread_id: ThreadId, cpu_id: usize, op: u16) {
        let depth = self
            .cpu_schedulers
            .get(&cpu_id)
            .map(|scheduler| scheduler.run_queue.len())
            .unwrap_or(0);
        crate::trace::record_run_queue_depth(thread_id, cpu_id, depth, op);
    }

    pub(super) fn maybe_nudge_idle_stealer(&mut self, donor_cpu_id: usize) {
        let _ = donor_cpu_id;
    }

    pub(crate) fn mark_cpu_online(&mut self, cpu_id: usize) {
        self.cpu_scheduler_mut(cpu_id).online = true;
    }

    pub(super) fn request_reschedule_on_cpu(&mut self, cpu_id: usize) {
        self.cpu_scheduler_mut(cpu_id).reschedule_requested = true;
        if cpu_id != self.current_cpu_id() && self.cpu_is_online(cpu_id) {
            crate::arch::ipi::send_reschedule(cpu_id);
        }
    }

    pub(super) fn take_reschedule_requested(&mut self, cpu_id: usize) -> bool {
        core::mem::take(&mut self.cpu_scheduler_mut(cpu_id).reschedule_requested)
    }

    pub(super) fn choose_start_cpu(
        &self,
        thread_id: ThreadId,
        placement: StartPlacementPolicy,
    ) -> usize {
        let preferred_cpu = self.choose_wake_cpu(thread_id);
        if placement == StartPlacementPolicy::PreferIdlePeer
            && preferred_cpu == self.current_cpu_id()
            && self
                .cpu_schedulers
                .get(&preferred_cpu)
                .is_some_and(|scheduler| scheduler.current_thread_id.is_some())
            && let Some(idle_cpu_id) = self.first_idle_cpu_excluding(preferred_cpu)
        {
            return idle_cpu_id;
        }
        preferred_cpu
    }

    pub(super) fn choose_wake_cpu(&self, thread_id: ThreadId) -> usize {
        let current_cpu_id = self.current_cpu_id();
        if let Some(running_cpu_id) = self.running_cpu_for_thread(thread_id) {
            return running_cpu_id;
        }
        let preferred_cpu = self
            .threads
            .get(&thread_id)
            .map(|thread| thread.last_cpu)
            .unwrap_or(current_cpu_id);
        if self.cpu_is_online(preferred_cpu) && self.cpu_is_idle(preferred_cpu) {
            return preferred_cpu;
        }
        if self.cpu_is_online(preferred_cpu) {
            return preferred_cpu;
        }
        if let Some((&idle_cpu_id, _)) = self.cpu_schedulers.iter().find(|(_, scheduler)| {
            scheduler.online
                && scheduler.current_thread_id.is_none()
                && scheduler.run_queue.is_empty()
        }) {
            return idle_cpu_id;
        }
        if self.cpu_is_online(current_cpu_id) {
            return current_cpu_id;
        }
        current_cpu_id
    }

    pub(super) fn arm_current_slice_from(&mut self, now: i64) {
        let scheduler = self.current_cpu_scheduler_mut();
        scheduler.current_runtime_started_ns = Some(now);
        scheduler.slice_deadline_ns = now.checked_add(DEFAULT_TIME_SLICE_NS);
    }

    pub(super) fn clear_current_slice_state(&mut self) {
        let scheduler = self.current_cpu_scheduler_mut();
        scheduler.current_runtime_started_ns = None;
        scheduler.slice_deadline_ns = None;
    }

    pub(super) fn clear_current_thread_slot(&mut self) {
        self.current_cpu_scheduler_mut().current_thread_id = None;
    }

    pub(super) fn account_current_runtime_until(&mut self, now: i64) -> Result<(), zx_status_t> {
        let current_thread_id = self.current_thread_id()?;
        let scheduler = self.current_cpu_scheduler_mut();
        let Some(started_ns) = scheduler.current_runtime_started_ns else {
            scheduler.current_runtime_started_ns = Some(now);
            return Ok(());
        };
        let elapsed_ns = now.saturating_sub(started_ns).max(0) as u64;
        scheduler.current_runtime_started_ns = Some(now);
        let thread = self
            .threads
            .get_mut(&current_thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?;
        thread.runtime_ns = thread.runtime_ns.saturating_add(elapsed_ns);
        Ok(())
    }

    pub(crate) fn note_current_cpu_timer_tick(&mut self, now: i64) -> Result<(), zx_status_t> {
        let scheduler = self.current_cpu_scheduler_mut();
        if scheduler.current_thread_id.is_none() {
            scheduler.current_runtime_started_ns = None;
            scheduler.slice_deadline_ns = None;
            return Ok(());
        }
        let _ = scheduler;
        self.account_current_runtime_until(now)?;
        if self
            .current_cpu_scheduler()?
            .slice_deadline_ns
            .is_some_and(|deadline| now >= deadline)
        {
            self.current_cpu_scheduler_mut().slice_deadline_ns =
                now.checked_add(DEFAULT_TIME_SLICE_NS);
            self.request_reschedule_on_cpu(self.current_cpu_id());
        }
        Ok(())
    }

    pub(crate) fn timer_interrupt_requires_trap_exit(
        &mut self,
        now: i64,
    ) -> Result<bool, zx_status_t> {
        self.note_current_cpu_timer_tick(now)?;
        if self.current_cpu_scheduler()?.reschedule_requested {
            return Ok(true);
        }
        Ok(!matches!(
            self.current_thread()?.state,
            ThreadState::Runnable
        ))
    }

    pub(super) fn enqueue_runnable_thread(
        &mut self,
        thread_id: ThreadId,
    ) -> Result<(), zx_status_t> {
        self.enqueue_runnable_thread_on_cpu(thread_id, self.current_cpu_id())
    }

    pub(super) fn enqueue_runnable_thread_on_cpu(
        &mut self,
        thread_id: ThreadId,
        cpu_id: usize,
    ) -> Result<(), zx_status_t> {
        let current_cpu_id = self.current_cpu_id();
        let enqueue_ns = self.current_cpu_now_ns().max(0) as u64;
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if thread.queued_on_cpu.is_some() || !matches!(thread.state, ThreadState::Runnable) {
            return Ok(());
        }
        thread.queued_on_cpu = Some(cpu_id);
        if cpu_id != current_cpu_id {
            thread.remote_wake_enqueued_ns = Some(enqueue_ns);
            thread.remote_wake_source_cpu = Some(current_cpu_id);
            thread.remote_wake_target_cpu = Some(cpu_id);
        } else {
            thread.remote_wake_enqueued_ns = None;
            thread.remote_wake_source_cpu = None;
            thread.remote_wake_target_cpu = None;
        }
        let _ = thread;
        self.cpu_scheduler_mut(cpu_id)
            .run_queue
            .push_back(thread_id);
        self.note_run_queue_depth(thread_id, cpu_id, RQ_DEPTH_ENQUEUE_BACK);
        Ok(())
    }

    pub(super) fn enqueue_runnable_thread_front(
        &mut self,
        thread_id: ThreadId,
    ) -> Result<(), zx_status_t> {
        self.enqueue_runnable_thread_front_on_cpu(thread_id, self.current_cpu_id())
    }

    pub(super) fn enqueue_runnable_thread_front_on_cpu(
        &mut self,
        thread_id: ThreadId,
        cpu_id: usize,
    ) -> Result<(), zx_status_t> {
        let current_cpu_id = self.current_cpu_id();
        let enqueue_ns = self.current_cpu_now_ns().max(0) as u64;
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if thread.queued_on_cpu.is_some() || !matches!(thread.state, ThreadState::Runnable) {
            return Ok(());
        }
        thread.queued_on_cpu = Some(cpu_id);
        if cpu_id != current_cpu_id {
            thread.remote_wake_enqueued_ns = Some(enqueue_ns);
            thread.remote_wake_source_cpu = Some(current_cpu_id);
            thread.remote_wake_target_cpu = Some(cpu_id);
        } else {
            thread.remote_wake_enqueued_ns = None;
            thread.remote_wake_source_cpu = None;
            thread.remote_wake_target_cpu = None;
        }
        let _ = thread;
        self.cpu_scheduler_mut(cpu_id)
            .run_queue
            .push_front(thread_id);
        self.note_run_queue_depth(thread_id, cpu_id, RQ_DEPTH_ENQUEUE_FRONT);
        crate::trace::record_sched_handoff(
            thread_id,
            cpu_id,
            self.cpu_schedulers
                .get(&cpu_id)
                .map(|scheduler| scheduler.run_queue.len())
                .unwrap_or(0),
        );
        Ok(())
    }

    pub(super) fn requeue_current_thread(&mut self) -> Result<(), zx_status_t> {
        let thread_id = self.current_thread_id()?;
        self.enqueue_runnable_thread_on_cpu(thread_id, self.current_cpu_id())
    }

    pub(super) fn pop_runnable_thread(&mut self) -> Option<ThreadId> {
        let current_cpu_id = self.current_cpu_id();
        loop {
            let thread_id = self
                .cpu_scheduler_mut(current_cpu_id)
                .run_queue
                .pop_front()?;
            self.note_run_queue_depth(thread_id, current_cpu_id, RQ_DEPTH_DEQUEUE_LOCAL);
            let Some(thread) = self.threads.get_mut(&thread_id) else {
                continue;
            };
            if thread.queued_on_cpu != Some(current_cpu_id) {
                continue;
            }
            thread.queued_on_cpu = None;
            if matches!(thread.state, ThreadState::Runnable) {
                return Some(thread_id);
            }
        }
    }

    fn take_next_runnable_thread_for_current_cpu(&mut self) -> Option<ThreadId> {
        self.pop_runnable_thread()
    }

    fn activate_thread_on_current_cpu(
        &mut self,
        thread_id: ThreadId,
    ) -> Result<UserContext, zx_status_t> {
        let current_cpu_id = self.current_cpu_id();
        let activation_now_ns = self.current_cpu_now_ns().max(0) as u64;
        let previous_thread_id = self.current_cpu_scheduler()?.current_thread_id;
        let current_address_space_id = if let Some(current_thread_id) = previous_thread_id {
            let process_id = self
                .threads
                .get(&current_thread_id)
                .ok_or(ZX_ERR_BAD_STATE)?
                .process_id;
            Some(self.process(process_id)?.address_space_id)
        } else {
            None
        };
        let next_process_id = self
            .threads
            .get(&thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .process_id;
        let next_address_space_id = self.process(next_process_id)?.address_space_id;
        let next_page_tables = self.with_vm(|vm| vm.root_page_table(next_address_space_id))?;
        let local_tlb_flush_needed = self
            .with_vm(|vm| vm.current_cpu_needs_tlb_sync(next_address_space_id, current_cpu_id))?;
        let context = self
            .threads
            .get_mut(&thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .context
            .ok_or(ZX_ERR_BAD_STATE)?;
        let address_space_switched = current_address_space_id != Some(next_address_space_id);
        let switch_kind = if address_space_switched || local_tlb_flush_needed {
            next_page_tables
                .activate(local_tlb_flush_needed)
                .map_err(map_page_table_error)?
        } else {
            crate::arch::tlb::AddressSpaceSwitchKind::SameAddressSpaceSkip
        };
        if let Some(current_address_space_id) = current_address_space_id {
            if current_address_space_id != next_address_space_id {
                self.with_vm_mut(|vm| {
                    vm.note_cpu_inactive(current_address_space_id, current_cpu_id)
                });
            }
        }
        if address_space_switched || local_tlb_flush_needed {
            self.observe_cpu_tlb_epoch_for_address_space(next_address_space_id, current_cpu_id);
        }
        self.current_cpu_scheduler_mut().current_thread_id = Some(thread_id);
        self.arm_current_slice_from(self.current_cpu_now_ns());
        crate::trace::record_context_switch(previous_thread_id, thread_id, address_space_switched);
        crate::trace::record_tlb_address_space_switch(
            current_address_space_id.unwrap_or(0),
            next_address_space_id,
            switch_kind,
        );
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if let (Some(enqueued_ns), Some(source_cpu_id), Some(target_cpu_id)) = (
            thread.remote_wake_enqueued_ns,
            thread.remote_wake_source_cpu,
            thread.remote_wake_target_cpu,
        ) {
            if target_cpu_id == current_cpu_id {
                crate::trace::record_remote_wake_latency(
                    thread_id,
                    source_cpu_id,
                    target_cpu_id,
                    activation_now_ns.saturating_sub(enqueued_ns),
                );
            }
        }
        thread.remote_wake_enqueued_ns = None;
        thread.remote_wake_source_cpu = None;
        thread.remote_wake_target_cpu = None;
        thread.last_cpu = current_cpu_id;
        Ok(context)
    }

    pub(crate) fn take_current_cpu_idle_context(
        &mut self,
    ) -> Result<Option<UserContext>, zx_status_t> {
        let current_cpu_id = self.current_cpu_id();
        self.mark_cpu_online(current_cpu_id);
        if self.current_cpu_scheduler()?.current_thread_id.is_some() {
            return Err(ZX_ERR_BAD_STATE);
        }
        let _ = self.take_reschedule_requested(current_cpu_id);
        let Some(thread_id) = self.take_next_runnable_thread_for_current_cpu() else {
            return Ok(None);
        };
        let context = self.activate_thread_on_current_cpu(thread_id)?;
        self.restore_thread_fpu_state(thread_id)?;
        Ok(Some(context))
    }

    pub(super) fn switch_to_thread(
        &mut self,
        thread_id: ThreadId,
        trap: &mut crate::arch::int80::TrapFrame,
        cpu_frame: *mut u64,
    ) -> Result<(), zx_status_t> {
        let context = self.activate_thread_on_current_cpu(thread_id)?;
        self.restore_thread_fpu_state(thread_id)?;
        context.restore(trap, cpu_frame)?;
        Ok(())
    }

    fn restore_thread_fpu_state(&self, thread_id: ThreadId) -> Result<(), zx_status_t> {
        let thread = self.threads.get(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        crate::arch::fpu::restore_current(&thread.fpu_state);
        Ok(())
    }

    fn make_thread_runnable_inner(
        &mut self,
        thread_id: ThreadId,
        status: Option<zx_status_t>,
    ) -> Result<(), zx_status_t> {
        let previous_state = self.threads.get(&thread_id).ok_or(ZX_ERR_BAD_STATE)?.state;
        if matches!(
            previous_state,
            ThreadState::TerminationPending | ThreadState::Terminated
        ) {
            return Ok(());
        }
        let hold_suspended = self.thread_should_be_suspended(thread_id)?;
        let running_cpu_id = self.running_cpu_for_thread(thread_id);
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        let Some(context) = thread.context else {
            return Err(ZX_ERR_BAD_STATE);
        };
        thread.context = Some(match status {
            Some(status) => context.with_status(status),
            None => context,
        });
        thread.state = if hold_suspended {
            ThreadState::Suspended
        } else {
            ThreadState::Runnable
        };
        if hold_suspended {
            thread.queued_on_cpu = None;
        }
        let queued_on_cpu = thread.queued_on_cpu;
        let _ = thread;
        if hold_suspended {
            if let Some(cpu_id) = running_cpu_id {
                self.request_reschedule_on_cpu(cpu_id);
            }
            return Ok(());
        }
        if let Some(cpu_id) = running_cpu_id {
            if cpu_id != self.current_cpu_id() {
                let now_ns = self.current_cpu_now_ns().max(0) as u64;
                let source_cpu_id = self.current_cpu_id();
                let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
                thread.remote_wake_enqueued_ns = Some(now_ns);
                thread.remote_wake_source_cpu = Some(source_cpu_id);
                thread.remote_wake_target_cpu = Some(cpu_id);
                let _ = thread;
                crate::trace::record_remote_wake(thread_id, cpu_id);
                crate::trace::record_sched_handoff(thread_id, cpu_id, 0);
            }
            self.request_reschedule_on_cpu(cpu_id);
            return Ok(());
        }
        if queued_on_cpu.is_none() {
            let target_cpu = self.choose_wake_cpu(thread_id);
            if target_cpu != self.current_cpu_id() {
                crate::trace::record_remote_wake(thread_id, target_cpu);
            }
            if matches!(previous_state, ThreadState::Blocked { .. }) {
                self.enqueue_runnable_thread_front_on_cpu(thread_id, target_cpu)?;
            } else {
                self.enqueue_runnable_thread_on_cpu(thread_id, target_cpu)?;
            }
            self.request_reschedule_on_cpu(target_cpu);
            self.maybe_nudge_idle_stealer(target_cpu);
        } else if let Some(cpu_id) = queued_on_cpu {
            self.request_reschedule_on_cpu(cpu_id);
        }
        Ok(())
    }

    pub(crate) fn wake_thread(
        &mut self,
        thread_id: ThreadId,
        reason: WakeReason,
    ) -> Result<(), zx_status_t> {
        match reason {
            WakeReason::Status(status) => self.make_thread_runnable_inner(thread_id, Some(status)),
            WakeReason::PreserveContext => self.make_thread_runnable_inner(thread_id, None),
        }
    }

    pub(crate) fn request_reschedule(&mut self) {
        self.request_reschedule_on_cpu(self.current_cpu_id());
    }
}
