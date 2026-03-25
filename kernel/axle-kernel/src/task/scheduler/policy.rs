use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StartPlacementPolicy {
    PreserveAffinity,
    PreferIdlePeer,
}

impl Kernel {
    fn current_thread_is_runnable_on_cpu(&self, cpu_id: usize) -> bool {
        self.cpu_schedulers
            .get(&cpu_id)
            .and_then(|scheduler| scheduler.current_thread_id)
            .and_then(|thread_id| self.threads.get(&thread_id))
            .is_some_and(|thread| matches!(thread.state, ThreadState::Runnable))
    }

    fn cpu_accepts_foreign_runnable(&self, cpu_id: usize) -> bool {
        self.cpu_schedulers.get(&cpu_id).is_some_and(|scheduler| {
            scheduler.online
                && (scheduler.current_thread_id.is_none()
                    || self.current_thread_is_runnable_on_cpu(cpu_id))
        })
    }

    pub(super) fn cpu_runnable_load(&self, cpu_id: usize) -> usize {
        self.cpu_schedulers
            .get(&cpu_id)
            .filter(|scheduler| scheduler.online)
            .map(|scheduler| {
                scheduler.run_queue.len()
                    + usize::from(self.current_thread_is_runnable_on_cpu(cpu_id))
            })
            .unwrap_or(0)
    }

    pub(crate) fn running_cpu_for_thread(&self, thread_id: ThreadId) -> Option<usize> {
        self.threads
            .get(&thread_id)
            .and_then(|thread| thread.running_on_cpu)
    }

    pub(super) fn cpu_is_online(&self, cpu_id: usize) -> bool {
        self.cpu_schedulers
            .get(&cpu_id)
            .is_some_and(|scheduler| scheduler.online)
    }

    pub(super) fn first_idle_cpu_excluding(&self, excluded_cpu_id: usize) -> Option<usize> {
        self.cpu_schedulers.iter().find_map(|(&cpu_id, scheduler)| {
            (cpu_id != excluded_cpu_id
                && scheduler.online
                && scheduler.current_thread_id.is_none()
                && scheduler.run_queue.is_empty())
            .then_some(cpu_id)
        })
    }

    pub(super) fn donation_receiver_cpu_excluding(&self, excluded_cpu_id: usize) -> Option<usize> {
        self.first_idle_cpu_excluding(excluded_cpu_id)
    }

    pub(super) fn least_loaded_online_cpu(
        &self,
        excluded_cpu_id: Option<usize>,
    ) -> Option<(usize, usize)> {
        self.cpu_schedulers
            .iter()
            .filter(|(cpu_id, scheduler)| {
                scheduler.online
                    && excluded_cpu_id != Some(**cpu_id)
                    && self.cpu_accepts_foreign_runnable(**cpu_id)
            })
            .map(|(&cpu_id, _)| (cpu_id, self.cpu_runnable_load(cpu_id)))
            .min_by_key(|&(cpu_id, load)| (load, cpu_id))
    }

    pub(super) fn most_loaded_online_cpu(&self) -> Option<(usize, usize)> {
        self.cpu_schedulers
            .iter()
            .filter(|(_, scheduler)| scheduler.online)
            .map(|(&cpu_id, _)| (cpu_id, self.cpu_runnable_load(cpu_id)))
            .max_by_key(|&(cpu_id, load)| (load, usize::MAX - cpu_id))
    }

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
                .is_some_and(|scheduler| {
                    scheduler.online && self.current_thread_is_runnable_on_cpu(preferred_cpu)
                })
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
        let least_loaded = self
            .least_loaded_online_cpu(None)
            .unwrap_or((current_cpu_id, self.cpu_runnable_load(current_cpu_id)));
        if self.cpu_is_online(preferred_cpu) {
            let preferred_load = self.cpu_runnable_load(preferred_cpu);
            if preferred_load <= least_loaded.1 + 1 {
                return preferred_cpu;
            }
        }
        if self.cpu_is_online(least_loaded.0) {
            return least_loaded.0;
        }
        current_cpu_id
    }
}
