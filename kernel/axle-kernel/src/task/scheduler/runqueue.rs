use super::*;

const RQ_DEPTH_ENQUEUE_BACK: u16 = 1;
const RQ_DEPTH_ENQUEUE_FRONT: u16 = 2;
const RQ_DEPTH_DEQUEUE_LOCAL: u16 = 3;
const RQ_DEPTH_DEQUEUE_STEAL: u16 = 4;
const RQ_DEPTH_ENQUEUE_MIGRATE: u16 = 5;

impl Kernel {
    pub(super) fn note_run_queue_depth(&self, thread_id: ThreadId, cpu_id: usize, op: u16) {
        let depth = self
            .cpu_schedulers
            .get(&cpu_id)
            .map(|scheduler| scheduler.run_queue.len())
            .unwrap_or(0);
        crate::trace::record_run_queue_depth(thread_id, cpu_id, depth, op);
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

    pub(crate) fn pop_runnable_thread(&mut self) -> Option<ThreadId> {
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

    pub(super) fn migrate_one_runnable_thread(
        &mut self,
        donor_cpu_id: usize,
        receiver_cpu_id: usize,
    ) -> Option<ThreadId> {
        if donor_cpu_id == receiver_cpu_id
            || !self.cpu_is_online(donor_cpu_id)
            || !self.cpu_is_online(receiver_cpu_id)
        {
            return None;
        }

        loop {
            let thread_id = self.cpu_scheduler_mut(donor_cpu_id).run_queue.pop_back()?;
            self.note_run_queue_depth(thread_id, donor_cpu_id, RQ_DEPTH_DEQUEUE_STEAL);
            let enqueue_ns = self.current_cpu_now_ns().max(0) as u64;
            let Some(thread) = self.threads.get_mut(&thread_id) else {
                continue;
            };
            if thread.queued_on_cpu != Some(donor_cpu_id) {
                continue;
            }
            if !matches!(thread.state, ThreadState::Runnable) {
                thread.queued_on_cpu = None;
                continue;
            }
            thread.queued_on_cpu = Some(receiver_cpu_id);
            thread.remote_wake_enqueued_ns = Some(enqueue_ns);
            thread.remote_wake_source_cpu = Some(donor_cpu_id);
            thread.remote_wake_target_cpu = Some(receiver_cpu_id);
            let _ = thread;

            self.cpu_scheduler_mut(receiver_cpu_id)
                .run_queue
                .push_back(thread_id);
            self.note_run_queue_depth(thread_id, receiver_cpu_id, RQ_DEPTH_ENQUEUE_MIGRATE);
            let donor_depth_after = self
                .cpu_schedulers
                .get(&donor_cpu_id)
                .map(|scheduler| scheduler.run_queue.len())
                .unwrap_or(0);
            crate::trace::record_sched_steal(
                thread_id,
                donor_cpu_id,
                receiver_cpu_id,
                donor_depth_after,
            );
            return Some(thread_id);
        }
    }

    pub(super) fn take_next_runnable_thread_for_current_cpu(&mut self) -> Option<ThreadId> {
        self.pop_runnable_thread()
    }
}
