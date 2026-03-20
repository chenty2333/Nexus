use alloc::collections::VecDeque;

use super::*;

mod switch;
mod wake;

pub(crate) use wake::StartPlacementPolicy;

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

    pub(crate) fn request_reschedule(&mut self) {
        self.request_reschedule_on_cpu(self.current_cpu_id());
    }
}
