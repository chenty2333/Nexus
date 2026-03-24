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
        // EEVDF: prepare scheduling parameters before enqueue
        self.prepare_enqueue_eevdf(thread_id, cpu_id);
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
        // EEVDF: prepare scheduling parameters before enqueue
        self.prepare_enqueue_eevdf(thread_id, cpu_id);
        self.cpu_scheduler_mut(cpu_id)
            .run_queue
            .push_back(thread_id);
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
        if let Some(thread) = self.threads.get_mut(&thread_id) {
            thread.queued_on_cpu = None;
            thread.remote_wake_enqueued_ns = None;
            thread.remote_wake_source_cpu = None;
            thread.remote_wake_target_cpu = None;
        }
        self.enqueue_runnable_thread_on_cpu(thread_id, self.current_cpu_id())
    }

    /// EEVDF pick-next: select the eligible thread with the smallest vdeadline.
    ///
    /// A thread is eligible when `eligible_time <= min_vruntime`. If no thread
    /// is eligible (e.g. all newly woken), fall back to the smallest vdeadline
    /// unconditionally to prevent starvation.
    pub(crate) fn pop_runnable_thread(&mut self) -> Option<ThreadId> {
        let current_cpu_id = self.current_cpu_id();
        let min_vruntime = self
            .cpu_schedulers
            .get(&current_cpu_id)
            .map(|sched| sched.min_vruntime)
            .unwrap_or(0);

        // First, purge stale entries from the front (threads that are no longer
        // runnable or queued on a different CPU), same as the old FIFO loop.
        // But for EEVDF we need to scan the whole queue, so we do it inline.

        let run_queue = &self.cpu_scheduler_mut(current_cpu_id).run_queue;
        if run_queue.is_empty() {
            return None;
        }

        // Pass 1: find the best eligible thread (smallest vdeadline where eligible_time <= min_vruntime)
        let mut best_idx: Option<usize> = None;
        let mut best_vdl = i64::MAX;
        let rq = &self.cpu_schedulers.get(&current_cpu_id)?.run_queue;
        for (i, &tid) in rq.iter().enumerate() {
            let Some(thread) = self.threads.get(&tid) else {
                continue;
            };
            if thread.queued_on_cpu != Some(current_cpu_id) {
                continue;
            }
            if !matches!(thread.state, ThreadState::Runnable) {
                continue;
            }
            if thread.eligible_time <= min_vruntime && thread.vdeadline < best_vdl {
                best_vdl = thread.vdeadline;
                best_idx = Some(i);
            }
        }

        // Pass 2: if no eligible thread, pick the smallest vdeadline unconditionally
        // (latency bound — prevents starvation of newly woken threads)
        if best_idx.is_none() {
            best_vdl = i64::MAX;
            let rq = &self.cpu_schedulers.get(&current_cpu_id)?.run_queue;
            for (i, &tid) in rq.iter().enumerate() {
                let Some(thread) = self.threads.get(&tid) else {
                    continue;
                };
                if thread.queued_on_cpu != Some(current_cpu_id) {
                    continue;
                }
                if !matches!(thread.state, ThreadState::Runnable) {
                    continue;
                }
                if thread.vdeadline < best_vdl {
                    best_vdl = thread.vdeadline;
                    best_idx = Some(i);
                }
            }
        }

        let idx = best_idx?;
        let thread_id = self
            .cpu_scheduler_mut(current_cpu_id)
            .run_queue
            .remove(idx)?;
        self.note_run_queue_depth(thread_id, current_cpu_id, RQ_DEPTH_DEQUEUE_LOCAL);

        // Clear queued_on_cpu for the picked thread
        if let Some(thread) = self.threads.get_mut(&thread_id) {
            thread.queued_on_cpu = None;
        }

        // EEVDF: advance min_vruntime after pick
        self.update_min_vruntime_after_pick(thread_id);

        Some(thread_id)
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

            // EEVDF: adjust vruntime relative to destination CPU's min_vruntime
            let dest_min_vruntime = self
                .cpu_schedulers
                .get(&receiver_cpu_id)
                .map(|sched| sched.min_vruntime)
                .unwrap_or(0);
            if thread.vruntime < dest_min_vruntime {
                thread.vruntime = dest_min_vruntime;
            }
            let _ = thread;

            // Prepare EEVDF parameters for the destination CPU
            self.prepare_enqueue_eevdf(thread_id, receiver_cpu_id);

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

    /// Remove a specific thread from its CPU run queue.
    ///
    /// Called when a thread transitions to a non-runnable state (e.g. Suspended)
    /// so the run queue length accurately reflects the number of runnable threads.
    pub(in crate::task) fn remove_thread_from_run_queue(&mut self, thread_id: ThreadId, cpu_id: usize) {
        let scheduler = self.cpu_scheduler_mut(cpu_id);
        scheduler.run_queue.retain(|&id| id != thread_id);
    }
}
