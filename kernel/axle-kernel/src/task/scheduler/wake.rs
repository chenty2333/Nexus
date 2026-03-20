use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StartPlacementPolicy {
    PreserveAffinity,
    PreferIdlePeer,
}

impl Kernel {
    pub(crate) fn choose_start_cpu(
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

    pub(crate) fn choose_wake_cpu(&self, thread_id: ThreadId) -> usize {
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

    pub(crate) fn enqueue_runnable_thread(
        &mut self,
        thread_id: ThreadId,
    ) -> Result<(), zx_status_t> {
        self.enqueue_runnable_thread_on_cpu(thread_id, self.current_cpu_id())
    }

    pub(crate) fn enqueue_runnable_thread_on_cpu(
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

    pub(crate) fn enqueue_runnable_thread_front(
        &mut self,
        thread_id: ThreadId,
    ) -> Result<(), zx_status_t> {
        self.enqueue_runnable_thread_front_on_cpu(thread_id, self.current_cpu_id())
    }

    pub(crate) fn enqueue_runnable_thread_front_on_cpu(
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

    pub(crate) fn requeue_current_thread(&mut self) -> Result<(), zx_status_t> {
        let thread_id = self.current_thread_id()?;
        self.enqueue_runnable_thread_on_cpu(thread_id, self.current_cpu_id())
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
}
