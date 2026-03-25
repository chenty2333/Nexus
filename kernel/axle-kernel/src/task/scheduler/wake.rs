use super::*;

impl Kernel {
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
        if matches!(previous_state, ThreadState::Runnable) {
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
            let direct_resume = self
                .cpu_schedulers
                .get(&cpu_id)
                .and_then(|scheduler| scheduler.current_thread_id)
                == Some(thread_id);
            if !direct_resume {
                if let Some(thread) = self.threads.get_mut(&thread_id) {
                    thread.running_on_cpu = None;
                }
            }
        }
        if let Some(cpu_id) = running_cpu_id.filter(|cpu_id| {
            self.cpu_schedulers
                .get(cpu_id)
                .and_then(|scheduler| scheduler.current_thread_id)
                == Some(thread_id)
        }) {
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
