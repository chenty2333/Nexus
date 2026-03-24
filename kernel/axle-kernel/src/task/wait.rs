use alloc::collections::VecDeque;

use axle_types::koid::ZX_KOID_INVALID;

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitRegistration {
    Sleep,
    Futex {
        key: FutexKey,
        owner_koid: zx_koid_t,
    },
    Signal {
        object_key: ObjectKey,
        watched: Signals,
        observed_ptr: u64,
    },
    Port {
        port_object: ObjectKey,
        packet_ptr: u64,
    },
    VmFault {
        key: FaultInFlightKey,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitSourceKey {
    Signals(ObjectKey),
    PortReadable(ObjectKey),
    Futex(FutexKey),
    Fault(FaultInFlightKey),
    None,
}

impl WaitRegistration {
    pub(super) const fn source_key(self) -> WaitSourceKey {
        match self {
            Self::Sleep => WaitSourceKey::None,
            Self::Futex { key, .. } => WaitSourceKey::Futex(key),
            Self::Signal { object_key, .. } => WaitSourceKey::Signals(object_key),
            Self::Port { port_object, .. } => WaitSourceKey::PortReadable(port_object),
            Self::VmFault { key } => WaitSourceKey::Fault(key),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct WaitNode {
    pub(super) seq: u64,
    pub(super) registration: Option<WaitRegistration>,
    pub(super) deadline: Option<i64>,
}

impl WaitNode {
    /// Arm this wait node with a new registration and optional deadline.
    ///
    /// The sequence number is monotonically incremented on each arm; seq == 0
    /// is reserved for the uninitialised/cleared state so that callers can
    /// distinguish "never armed" from any valid armed generation.
    pub(super) fn arm(&mut self, registration: WaitRegistration, deadline: Option<i64>) -> u64 {
        self.seq = self.seq.wrapping_add(1);
        if self.seq == 0 {
            self.seq = 1;
        }
        self.registration = Some(registration);
        self.deadline = deadline;
        self.seq
    }

    pub(super) fn clear(&mut self) {
        self.registration = None;
        self.deadline = None;
    }
}

#[derive(Debug)]
pub(crate) struct Reactor {
    observers: ObserverRegistry,
    signal_waiters: BTreeMap<ObjectKey, VecDeque<ThreadId>>,
    port_waiters: BTreeMap<ObjectKey, VecDeque<ThreadId>>,
    timers: ReactorTimerCore,
}

impl Reactor {
    pub(crate) fn new(cpu_count: usize) -> Self {
        Self {
            observers: ObserverRegistry::new(),
            signal_waiters: BTreeMap::new(),
            port_waiters: BTreeMap::new(),
            timers: ReactorTimerCore::new(cpu_count),
        }
    }

    pub(crate) fn observers(&self) -> &ObserverRegistry {
        &self.observers
    }

    pub(crate) fn observers_mut(&mut self) -> &mut ObserverRegistry {
        &mut self.observers
    }

    pub(crate) fn remove_port(&mut self, port_key: ObjectKey) {
        self.observers.remove_port(port_key);
        let _ = self.port_waiters.remove(&port_key);
    }

    pub(crate) fn remove_waitable(&mut self, waitable_key: ObjectKey) {
        self.observers.remove_waitable(waitable_key);
        let _ = self.signal_waiters.remove(&waitable_key);
    }

    pub(super) fn push_signal_waiter(&mut self, object_key: ObjectKey, thread_id: ThreadId) {
        self.signal_waiters
            .entry(object_key)
            .or_default()
            .push_back(thread_id);
    }

    pub(super) fn remove_signal_waiter(&mut self, object_key: ObjectKey, thread_id: ThreadId) {
        let should_remove = if let Some(waiters) = self.signal_waiters.get_mut(&object_key) {
            waiters.retain(|waiter| *waiter != thread_id);
            waiters.is_empty()
        } else {
            false
        };
        if should_remove {
            let _ = self.signal_waiters.remove(&object_key);
        }
    }

    pub(super) fn push_port_waiter(&mut self, port_object: ObjectKey, thread_id: ThreadId) {
        self.port_waiters
            .entry(port_object)
            .or_default()
            .push_back(thread_id);
    }

    pub(super) fn remove_port_waiter(&mut self, port_object: ObjectKey, thread_id: ThreadId) {
        let should_remove = if let Some(waiters) = self.port_waiters.get_mut(&port_object) {
            waiters.retain(|waiter| *waiter != thread_id);
            waiters.is_empty()
        } else {
            false
        };
        if should_remove {
            let _ = self.port_waiters.remove(&port_object);
        }
    }

    pub(super) fn cancel_wait_deadline(&mut self, thread_id: ThreadId, seq: u64) {
        self.timers
            .cancel_wait_deadline(WaitDeadlineId::new(thread_id, seq));
    }

    pub(super) fn arm_wait_deadline(
        &mut self,
        cpu_id: usize,
        thread_id: ThreadId,
        seq: u64,
        deadline: i64,
    ) {
        self.timers
            .arm_wait_deadline(cpu_id, WaitDeadlineId::new(thread_id, seq), deadline);
    }

    pub(super) fn signal_waiter_thread_ids(&self, object_key: ObjectKey) -> Vec<ThreadId> {
        self.signal_waiters
            .get(&object_key)
            .map(|waiters| waiters.iter().copied().collect())
            .unwrap_or_default()
    }

    pub(super) fn port_waiter_thread_ids(&self, port_object: ObjectKey) -> Vec<ThreadId> {
        self.port_waiters
            .get(&port_object)
            .map(|waiters| waiters.iter().copied().collect())
            .unwrap_or_default()
    }

    pub(crate) fn create_timer_object(&mut self) -> TimerId {
        self.timers.create_timer()
    }

    pub(crate) fn destroy_timer_object(&mut self, timer_id: TimerId) -> Result<(), TimerError> {
        self.timers.remove_timer(timer_id)
    }

    pub(crate) fn set_timer_object(
        &mut self,
        timer_id: TimerId,
        cpu_id: usize,
        deadline: i64,
        now: i64,
    ) -> Result<bool, TimerError> {
        self.timers.set_timer(timer_id, cpu_id, deadline, now)
    }

    pub(crate) fn cancel_timer_object(&mut self, timer_id: TimerId) -> Result<(), TimerError> {
        self.timers.cancel_timer(timer_id)
    }

    pub(crate) fn timer_object_signaled(&self, timer_id: TimerId) -> Result<bool, TimerError> {
        self.timers.is_timer_signaled(timer_id)
    }

    pub(crate) fn poll(&mut self, current_cpu_id: usize, now: i64) -> Vec<ReactorTimerEvent> {
        if crate::arch::timer::ticks_all_cpus() {
            self.timers.poll_slot(current_cpu_id, now)
        } else {
            self.timers.poll_all(now)
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SignalWaiter {
    thread_id: ThreadId,
    seq: u64,
    observed_ptr: u64,
}

impl SignalWaiter {
    pub(crate) const fn thread_id(self) -> ThreadId {
        self.thread_id
    }

    pub(crate) const fn seq(self) -> u64 {
        self.seq
    }

    pub(crate) const fn observed_ptr(self) -> *mut zx_signals_t {
        self.observed_ptr as *mut zx_signals_t
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PortWaiter {
    thread_id: ThreadId,
    seq: u64,
    packet_ptr: u64,
}

impl PortWaiter {
    pub(crate) const fn thread_id(self) -> ThreadId {
        self.thread_id
    }

    pub(crate) const fn seq(self) -> u64 {
        self.seq
    }

    pub(crate) const fn packet_ptr(self) -> *mut zx_port_packet_t {
        self.packet_ptr as *mut zx_port_packet_t
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ExpiredWait {
    thread_id: ThreadId,
    registration: WaitRegistration,
}

impl ExpiredWait {
    pub(crate) const fn thread_id(self) -> ThreadId {
        self.thread_id
    }

    pub(crate) const fn registration(self) -> WaitRegistration {
        self.registration
    }
}

#[derive(Debug, Default)]
pub(crate) struct ReactorPollResult {
    events: Vec<ReactorPollEvent>,
}

impl ReactorPollResult {
    pub(crate) fn into_events(self) -> Vec<ReactorPollEvent> {
        self.events
    }
}

#[derive(Debug)]
pub(crate) enum ReactorPollEvent {
    TimerFired(TimerId),
    WaitExpired(ExpiredWait),
}

impl Kernel {
    pub(super) fn cancel_wait_deadline(&mut self, thread_id: ThreadId, seq: u64) {
        self.reactor.lock().cancel_wait_deadline(thread_id, seq);
    }

    pub(crate) fn create_timer_object(&mut self) -> TimerId {
        self.reactor.lock().create_timer_object()
    }

    pub(crate) fn destroy_timer_object(&mut self, timer_id: TimerId) -> Result<(), TimerError> {
        self.reactor.lock().destroy_timer_object(timer_id)
    }

    pub(crate) fn set_timer_object(
        &mut self,
        timer_id: TimerId,
        deadline: i64,
        now: i64,
    ) -> Result<bool, TimerError> {
        let cpu_id = self.current_cpu_id();
        self.reactor
            .lock()
            .set_timer_object(timer_id, cpu_id, deadline, now)
    }

    pub(crate) fn cancel_timer_object(&mut self, timer_id: TimerId) -> Result<(), TimerError> {
        self.reactor.lock().cancel_timer_object(timer_id)
    }

    pub(crate) fn timer_object_signaled(&self, timer_id: TimerId) -> Result<bool, TimerError> {
        self.reactor.lock().timer_object_signaled(timer_id)
    }

    pub(crate) fn thread_wait_registration(
        &self,
        thread_id: ThreadId,
    ) -> Result<Option<WaitRegistration>, zx_status_t> {
        Ok(self
            .threads
            .get(&thread_id)
            .ok_or(ZX_ERR_BAD_STATE)?
            .wait
            .registration)
    }

    pub(crate) fn thread_wait_seq(&self, thread_id: ThreadId) -> Result<Option<u64>, zx_status_t> {
        let thread = self.threads.get(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        Ok(thread.wait.registration.map(|_| thread.wait.seq))
    }

    pub(super) fn push_signal_waiter(&mut self, object_key: ObjectKey, thread_id: ThreadId) {
        self.reactor
            .lock()
            .push_signal_waiter(object_key, thread_id);
    }

    pub(super) fn remove_signal_waiter(&mut self, object_key: ObjectKey, thread_id: ThreadId) {
        self.reactor
            .lock()
            .remove_signal_waiter(object_key, thread_id);
    }

    pub(super) fn push_port_waiter(&mut self, port_object: ObjectKey, thread_id: ThreadId) {
        self.reactor.lock().push_port_waiter(port_object, thread_id);
    }

    pub(super) fn remove_port_waiter(&mut self, port_object: ObjectKey, thread_id: ThreadId) {
        self.reactor
            .lock()
            .remove_port_waiter(port_object, thread_id);
    }

    pub(super) fn enqueue_wait_source(
        &mut self,
        thread_id: ThreadId,
        registration: WaitRegistration,
    ) {
        match registration {
            WaitRegistration::Sleep => {}
            WaitRegistration::Signal { object_key, .. } => {
                self.push_signal_waiter(object_key, thread_id)
            }
            WaitRegistration::Port { port_object, .. } => {
                self.push_port_waiter(port_object, thread_id)
            }
            WaitRegistration::Futex { key, owner_koid } => {
                self.futexes.enqueue_waiter(key, thread_id, owner_koid);
                // PI: record which futex this thread is blocked on.
                if let Some(thread) = self.threads.get_mut(&thread_id) {
                    thread.pi_blocked_on = Some(key);
                }
                // PI: if the futex has a known owner, boost it if needed.
                let waiter_weight = self
                    .threads
                    .get(&thread_id)
                    .map(|t| t.weight)
                    .unwrap_or(0);
                self.apply_pi_boost(owner_koid, waiter_weight);
            }
            WaitRegistration::VmFault { .. } => {}
        }
    }

    pub(super) fn remove_wait_source_membership(
        &mut self,
        thread_id: ThreadId,
        registration: WaitRegistration,
    ) {
        match registration {
            WaitRegistration::Sleep => {}
            WaitRegistration::Signal { object_key, .. } => {
                self.remove_signal_waiter(object_key, thread_id)
            }
            WaitRegistration::Port { port_object, .. } => {
                self.remove_port_waiter(port_object, thread_id)
            }
            WaitRegistration::Futex { key, .. } => {
                let _ = self.futexes.cancel_waiter(key, thread_id);
                // PI: clear the blocked-on record for the woken/cancelled thread.
                if let Some(thread) = self.threads.get_mut(&thread_id) {
                    thread.pi_blocked_on = None;
                }
            }
            WaitRegistration::VmFault { key } => {
                self.with_faults_mut(|faults| {
                    faults.remove_blocked_waiter(key, thread_id);
                });
            }
        }
    }

    pub(super) fn take_wait_registration_if_seq(
        &mut self,
        thread_id: ThreadId,
        seq: u64,
    ) -> Option<WaitRegistration> {
        let (registration, had_deadline) = {
            let thread = self.threads.get_mut(&thread_id)?;
            if thread.wait.seq != seq {
                return None;
            }
            let registration = thread.wait.registration?;
            let had_deadline = thread.wait.deadline.is_some();
            thread.wait.clear();
            (registration, had_deadline)
        };
        if had_deadline {
            self.cancel_wait_deadline(thread_id, seq);
        }
        Some(registration)
    }

    pub(super) fn take_wait_registration(
        &mut self,
        thread_id: ThreadId,
    ) -> Option<(u64, WaitRegistration)> {
        let (seq, registration, had_deadline) = {
            let thread = self.threads.get_mut(&thread_id)?;
            let registration = thread.wait.registration?;
            let seq = thread.wait.seq;
            let had_deadline = thread.wait.deadline.is_some();
            thread.wait.clear();
            (seq, registration, had_deadline)
        };
        if had_deadline {
            self.cancel_wait_deadline(thread_id, seq);
        }
        Some((seq, registration))
    }

    pub(crate) fn park_current_with_seq(
        &mut self,
        registration: WaitRegistration,
        deadline: Option<i64>,
    ) -> Result<u64, zx_status_t> {
        let thread_id = self.current_thread_id()?;
        let source = registration.source_key();
        let seq = {
            let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
            if !matches!(thread.state, ThreadState::Runnable) {
                return Err(ZX_ERR_BAD_STATE);
            }
            thread.state = ThreadState::Blocked { source };
            thread.wait.arm(registration, deadline)
        };
        self.enqueue_wait_source(thread_id, registration);
        if let Some(deadline) = deadline {
            self.reactor
                .lock()
                .arm_wait_deadline(self.current_cpu_id(), thread_id, seq, deadline);
        }
        Ok(seq)
    }

    pub(crate) fn park_current(
        &mut self,
        registration: WaitRegistration,
        deadline: Option<i64>,
    ) -> Result<(), zx_status_t> {
        let _ = self.park_current_with_seq(registration, deadline)?;
        Ok(())
    }

    pub(crate) fn block_current(
        &mut self,
        registration: WaitRegistration,
    ) -> Result<(), zx_status_t> {
        self.park_current(registration, None)
    }

    pub(crate) fn signal_waiters_ready(
        &self,
        object_key: ObjectKey,
        current: Signals,
    ) -> Vec<SignalWaiter> {
        self.reactor
            .lock()
            .signal_waiter_thread_ids(object_key)
            .iter()
            .filter_map(|thread_id| {
                let thread = self.threads.get(thread_id)?;
                match thread.wait.registration {
                    Some(WaitRegistration::Signal {
                        object_key: wait_object_key,
                        watched,
                        observed_ptr,
                    }) if wait_object_key == object_key && current.intersects(watched) => {
                        Some(SignalWaiter {
                            thread_id: *thread_id,
                            seq: thread.wait.seq,
                            observed_ptr: observed_ptr as u64,
                        })
                    }
                    _ => None,
                }
            })
            .collect()
    }

    pub(crate) fn port_waiters(&self, port_object: ObjectKey) -> Vec<PortWaiter> {
        self.reactor
            .lock()
            .port_waiter_thread_ids(port_object)
            .iter()
            .filter_map(|thread_id| {
                let thread = self.threads.get(thread_id)?;
                match thread.wait.registration {
                    Some(WaitRegistration::Port {
                        port_object: wait_port_object,
                        packet_ptr,
                    }) if wait_port_object == port_object => Some(PortWaiter {
                        thread_id: *thread_id,
                        seq: thread.wait.seq,
                        packet_ptr: packet_ptr as u64,
                    }),
                    _ => None,
                }
            })
            .collect()
    }

    pub(crate) fn complete_waiter(
        &mut self,
        thread_id: ThreadId,
        seq: u64,
        reason: WakeReason,
    ) -> Result<bool, zx_status_t> {
        let Some(registration) = self.take_wait_registration_if_seq(thread_id, seq) else {
            return Ok(false);
        };
        self.remove_wait_source_membership(thread_id, registration);
        self.wake_thread(thread_id, reason)?;
        Ok(true)
    }

    pub(crate) fn cancel_waiter_if_seq(
        &mut self,
        thread_id: ThreadId,
        seq: u64,
    ) -> Result<bool, zx_status_t> {
        let Some(registration) = self.take_wait_registration_if_seq(thread_id, seq) else {
            return Ok(false);
        };
        self.remove_wait_source_membership(thread_id, registration);
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        if matches!(thread.state, ThreadState::Blocked { .. }) {
            thread.state = ThreadState::Runnable;
        }
        Ok(true)
    }

    pub(crate) fn complete_waiter_source_removed(
        &mut self,
        thread_id: ThreadId,
        reason: WakeReason,
    ) -> Result<bool, zx_status_t> {
        let Some((_, registration)) = self.take_wait_registration(thread_id) else {
            return Ok(false);
        };
        self.remove_wait_source_membership(thread_id, registration);
        self.wake_thread(thread_id, reason)?;
        Ok(true)
    }

    pub(crate) fn poll_reactor(&mut self, now: i64) -> ReactorPollResult {
        let mut result = ReactorPollResult::default();
        let due = self.reactor.lock().poll(self.current_cpu_id(), now);

        for event in due {
            match event {
                ReactorTimerEvent::TimerFired(timer_id) => {
                    result.events.push(ReactorPollEvent::TimerFired(timer_id));
                }
                ReactorTimerEvent::WaitExpired(wait_id) => {
                    let Some(thread) = self.threads.get(&wait_id.thread_id()) else {
                        continue;
                    };
                    if thread.wait.seq != wait_id.seq() {
                        continue;
                    }
                    let Some(registration) =
                        self.take_wait_registration_if_seq(wait_id.thread_id(), wait_id.seq())
                    else {
                        continue;
                    };
                    self.remove_wait_source_membership(wait_id.thread_id(), registration);
                    result
                        .events
                        .push(ReactorPollEvent::WaitExpired(ExpiredWait {
                            thread_id: wait_id.thread_id(),
                            registration,
                        }));
                }
            }
        }
        result
    }

    pub(super) fn update_wait_registration(
        &mut self,
        thread_id: ThreadId,
        registration: WaitRegistration,
    ) -> Result<bool, zx_status_t> {
        let thread = self.threads.get_mut(&thread_id).ok_or(ZX_ERR_BAD_STATE)?;
        let Some(current) = thread.wait.registration else {
            return Ok(false);
        };
        if !matches!(current, WaitRegistration::Futex { .. }) {
            return Ok(false);
        }
        thread.wait.registration = Some(registration);
        thread.state = ThreadState::Blocked {
            source: registration.source_key(),
        };
        Ok(true)
    }

    #[allow(dead_code)]
    pub(crate) fn wake_futex_waiters(
        &mut self,
        key: FutexKey,
        wake_count: usize,
        new_owner_koid: zx_koid_t,
        single_owner: bool,
    ) -> Result<usize, zx_status_t> {
        // PI: snapshot the old owner koid before wake changes it.
        let old_owner_koid = self.futexes.owner(key);
        let result = self
            .futexes
            .wake(key, wake_count, new_owner_koid, single_owner);
        for &thread_id in &result.woken {
            // PI: clear blocked-on for each woken thread.
            if let Some(thread) = self.threads.get_mut(&thread_id) {
                thread.pi_blocked_on = None;
            }
            let _ = self.complete_waiter_source_removed(thread_id, WakeReason::Status(ZX_OK))?;
        }
        // PI: recompute old owner's weight based on remaining waiters.
        self.recompute_pi_weight(old_owner_koid, key);
        Ok(result.remaining)
    }

    #[allow(dead_code)]
    pub(crate) fn requeue_futex_waiters(
        &mut self,
        source: FutexKey,
        target: FutexKey,
        wake_count: usize,
        requeue_count: usize,
        target_owner_koid: zx_koid_t,
    ) -> Result<crate::futex::RequeueResult, zx_status_t> {
        // PI: snapshot the old source owner koid before requeue changes it.
        let old_source_owner_koid = self.futexes.owner(source);
        let result =
            self.futexes
                .requeue(source, target, wake_count, requeue_count, target_owner_koid);
        for &thread_id in &result.woken {
            // PI: clear blocked-on for each woken thread.
            if let Some(thread) = self.threads.get_mut(&thread_id) {
                thread.pi_blocked_on = None;
            }
            let _ = self.complete_waiter_source_removed(thread_id, WakeReason::Status(ZX_OK))?;
        }
        for &thread_id in &result.requeued_waiters {
            // PI: update blocked-on to the target futex for requeued threads.
            if let Some(thread) = self.threads.get_mut(&thread_id) {
                thread.pi_blocked_on = Some(target);
            }
            let _ = self.update_wait_registration(
                thread_id,
                WaitRegistration::Futex {
                    key: target,
                    owner_koid: target_owner_koid,
                },
            )?;
        }
        // PI: recompute old source owner's weight (waiters were removed from its queue).
        self.recompute_pi_weight(old_source_owner_koid, source);
        // PI: apply boost to the new target owner from the requeued waiters.
        if target_owner_koid != ZX_KOID_INVALID {
            let max_requeued_weight = result
                .requeued_waiters
                .iter()
                .filter_map(|&tid| self.threads.get(&tid))
                .map(|t| t.weight)
                .max()
                .unwrap_or(0);
            if max_requeued_weight > 0 {
                self.apply_pi_boost(target_owner_koid, max_requeued_weight);
            }
        }
        Ok(result)
    }

    #[allow(dead_code)]
    pub(crate) fn futex_owner(&self, key: FutexKey) -> zx_koid_t {
        self.futexes.owner(key)
    }

    #[allow(dead_code)]
    pub(crate) fn thread_is_waiting_on_futex(&self, thread_id: ThreadId, key: FutexKey) -> bool {
        self.threads
            .get(&thread_id)
            .and_then(|thread| thread.wait.registration)
            .is_some_and(|registration| {
                matches!(registration, WaitRegistration::Futex { key: wait_key, .. } if wait_key == key)
            })
    }

    // ---- Priority Inheritance helpers ----

    /// Find a ThreadId by its koid. Returns `None` if no thread with that koid exists.
    fn thread_id_for_koid(&self, koid: zx_koid_t) -> Option<ThreadId> {
        self.thread_koid_index.get(&koid).copied()
    }

    /// Apply PI boost: if the waiter's effective weight exceeds the owner's effective weight,
    /// boost the owner. Single-level only (no chain propagation beyond depth 1 for now).
    fn apply_pi_boost(&mut self, owner_koid: zx_koid_t, waiter_weight: u32) {
        if owner_koid == ZX_KOID_INVALID {
            return;
        }
        let owner_tid = match self.thread_id_for_koid(owner_koid) {
            Some(tid) => tid,
            None => return,
        };
        let (needs_recompute, cpu_id) = {
            let owner = match self.threads.get_mut(&owner_tid) {
                Some(t) => t,
                None => return,
            };
            if waiter_weight <= owner.weight {
                return;
            }
            owner.weight = waiter_weight;
            // If owner is in a run queue, recompute its EEVDF parameters
            (owner.queued_on_cpu.is_some(), owner.queued_on_cpu)
        };
        if needs_recompute {
            if let Some(cpu_id) = cpu_id {
                self.prepare_enqueue_eevdf(owner_tid, cpu_id);
            }
        }
    }

    /// Recompute the owner's effective weight from base_weight and the maximum weight
    /// among remaining waiters on the given futex key.
    fn recompute_pi_weight(&mut self, owner_koid: zx_koid_t, futex_key: FutexKey) {
        if owner_koid == ZX_KOID_INVALID {
            return;
        }
        let owner_tid = match self.thread_id_for_koid(owner_koid) {
            Some(tid) => tid,
            None => return,
        };
        let remaining_ids = self.futexes.waiter_thread_ids(futex_key);
        let max_waiter_weight = remaining_ids
            .iter()
            .filter_map(|&tid| self.threads.get(&tid))
            .map(|t| t.weight)
            .max()
            .unwrap_or(0);
        let base = self
            .threads
            .get(&owner_tid)
            .map(|t| t.base_weight)
            .unwrap_or(1024);
        let (needs_recompute, cpu_id) = {
            if let Some(owner) = self.threads.get_mut(&owner_tid) {
                let old_weight = owner.weight;
                owner.weight = base.max(max_waiter_weight);
                (owner.weight != old_weight && owner.queued_on_cpu.is_some(), owner.queued_on_cpu)
            } else {
                (false, None)
            }
        };
        if needs_recompute {
            if let Some(cpu_id) = cpu_id {
                self.prepare_enqueue_eevdf(owner_tid, cpu_id);
            }
        }
    }
}
