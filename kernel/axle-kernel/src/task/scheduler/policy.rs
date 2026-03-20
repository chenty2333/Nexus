use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StartPlacementPolicy {
    PreserveAffinity,
    PreferIdlePeer,
}

impl Kernel {
    pub(crate) fn running_cpu_for_thread(&self, thread_id: ThreadId) -> Option<usize> {
        self.cpu_schedulers.iter().find_map(|(&cpu_id, scheduler)| {
            (scheduler.current_thread_id == Some(thread_id)).then_some(cpu_id)
        })
    }

    pub(super) fn cpu_is_online(&self, cpu_id: usize) -> bool {
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
}
