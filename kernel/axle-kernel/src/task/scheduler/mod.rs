use alloc::collections::VecDeque;

use super::*;

mod policy;
mod runqueue;
mod switch;
mod wake;

pub(crate) use policy::StartPlacementPolicy;

#[derive(Debug, Default)]
pub(super) struct CpuSchedulerState {
    run_queue: VecDeque<ThreadId>,
    current_thread_id: Option<ThreadId>,
    reschedule_requested: bool,
    current_runtime_started_ns: Option<i64>,
    slice_deadline_ns: Option<i64>,
    last_rebalance_ns: Option<i64>,
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
            last_rebalance_ns: Some(now),
            online: true,
        }
    }
}

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

    pub(super) fn maybe_nudge_idle_stealer(&mut self, donor_cpu_id: usize) {
        if self.cpu_runnable_load(donor_cpu_id) <= 1 {
            return;
        }
        let Some(idle_cpu_id) = self.donation_receiver_cpu_excluding(donor_cpu_id) else {
            return;
        };
        if self
            .migrate_one_runnable_thread(donor_cpu_id, idle_cpu_id)
            .is_some()
        {
            self.request_reschedule_on_cpu(idle_cpu_id);
        }
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

    pub(super) fn arm_current_slice_from(&mut self, now: i64) {
        let scheduler = self.current_cpu_scheduler_mut();
        scheduler.current_runtime_started_ns = Some(now);
        scheduler.slice_deadline_ns = now.checked_add(DEFAULT_TIME_SLICE_NS);
    }

    fn maybe_periodic_rebalance(&mut self, now: i64) {
        let current_cpu_id = self.current_cpu_id();
        let should_rebalance = {
            let scheduler = self.cpu_scheduler_mut(current_cpu_id);
            match scheduler.last_rebalance_ns {
                Some(last_ns) if now.saturating_sub(last_ns) < DEFAULT_TIME_SLICE_NS => false,
                _ => {
                    scheduler.last_rebalance_ns = Some(now);
                    true
                }
            }
        };
        if !should_rebalance {
            return;
        }

        let Some((donor_cpu_id, donor_load)) = self.most_loaded_online_cpu() else {
            return;
        };
        let Some((receiver_cpu_id, receiver_load)) = self.least_loaded_online_cpu(None) else {
            return;
        };
        if donor_cpu_id == receiver_cpu_id || donor_load <= receiver_load + 1 {
            return;
        }
        if self
            .migrate_one_runnable_thread(donor_cpu_id, receiver_cpu_id)
            .is_some()
        {
            self.request_reschedule_on_cpu(receiver_cpu_id);
        }
    }

    pub(super) fn clear_current_slice_state(&mut self) {
        let scheduler = self.current_cpu_scheduler_mut();
        scheduler.current_runtime_started_ns = None;
        scheduler.slice_deadline_ns = None;
    }

    pub(super) fn clear_current_thread_slot(&mut self) {
        let scheduler = self.current_cpu_scheduler_mut();
        if let Some(thread_id) = scheduler.current_thread_id.take() {
            if let Some(thread) = self.threads.get_mut(&thread_id) {
                thread.running_on_cpu = None;
            }
        }
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
        self.maybe_periodic_rebalance(now);
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

    pub(crate) fn request_reschedule(&mut self) {
        self.request_reschedule_on_cpu(self.current_cpu_id());
    }
}
