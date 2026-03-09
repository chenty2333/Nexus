//! Timer: host-testable semantic core for Zircon-like timers.
//!
//! The kernel version will integrate with the scheduler and slack rules.
//! For Phase A host contracts we provide:
//! - `FakeClock` monotonic time
//! - `TimerService` that manages one-shot timers
//!
//! Observable behavior we model:
//! - `set(deadline)` arms (or re-arms) a timer and clears `SIGNALED`.
//! - when `now >= deadline`, the timer becomes `SIGNALED` and disarms.
//! - `cancel()` disarms and clears `SIGNALED`.
//!
//! Integration with `Port`/`wait_async` is done by the caller via the returned
//! list of fired timer ids from `advance_*`.

use alloc::collections::BTreeMap;
use alloc::collections::BinaryHeap;
use alloc::vec::Vec;
use core::cmp::Ordering;

/// A monotonic timestamp in nanoseconds.
///
/// We keep it as `i64` to match Zircon's `zx_time_t` style.
pub type Time = i64;

/// Timer identifier (corresponds to a kernel object id in real system).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimerId(u64);

impl TimerId {
    /// Raw numeric id (for debug).
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// A fake monotonic clock for deterministic tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct FakeClock {
    now: Time,
}

impl FakeClock {
    /// Create a clock starting at time 0.
    pub fn new() -> Self {
        Self { now: 0 }
    }

    /// Current time.
    pub const fn now(&self) -> Time {
        self.now
    }

    /// Advance time by `delta` (must be >= 0).
    pub fn advance_by(&mut self, delta: Time) {
        assert!(delta >= 0);
        self.now = self.now.saturating_add(delta);
    }

    /// Set time to an absolute value (must be monotonic).
    pub fn advance_to(&mut self, t: Time) {
        assert!(t >= self.now);
        self.now = t;
    }
}

#[derive(Clone, Copy, Debug)]
struct TimerState {
    deadline: Option<Time>,
    signaled: bool,
}

#[derive(Clone, Copy, Debug)]
struct HeapEntry {
    deadline: Time,
    id: TimerId,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline && self.id == other.id
    }
}
impl Eq for HeapEntry {}
impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap is max-heap, so reverse ordering for min-heap behavior.
        other
            .deadline
            .cmp(&self.deadline)
            .then_with(|| other.id.cmp(&self.id))
    }
}

/// Errors returned by timer operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerError {
    /// Unknown timer id.
    NotFound,
}

/// A deterministic timer service (one-shot timers).
#[derive(Debug, Default)]
pub struct TimerService {
    next_id: u64,
    timers: BTreeMap<TimerId, TimerState>,
    heap: BinaryHeap<HeapEntry>,
}

impl TimerService {
    /// Create a new service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new timer and return its id.
    pub fn create_timer(&mut self) -> TimerId {
        let id = TimerId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        self.timers.insert(
            id,
            TimerState {
                deadline: None,
                signaled: false,
            },
        );
        id
    }

    /// Arm (or re-arm) the timer at an absolute deadline.
    ///
    /// This clears `signaled`.
    pub fn set(&mut self, id: TimerId, deadline: Time) -> Result<(), TimerError> {
        let Some(st) = self.timers.get_mut(&id) else {
            return Err(TimerError::NotFound);
        };
        st.deadline = Some(deadline);
        st.signaled = false;
        self.heap.push(HeapEntry { deadline, id });
        Ok(())
    }

    /// Cancel the timer (disarm + clear signal).
    pub fn cancel(&mut self, id: TimerId) -> Result<(), TimerError> {
        let Some(st) = self.timers.get_mut(&id) else {
            return Err(TimerError::NotFound);
        };
        st.deadline = None;
        st.signaled = false;
        Ok(())
    }

    /// Whether a timer is currently signaled.
    pub fn is_signaled(&self, id: TimerId) -> Result<bool, TimerError> {
        self.timers
            .get(&id)
            .map(|s| s.signaled)
            .ok_or(TimerError::NotFound)
    }

    /// Earliest armed deadline among all timers, if any.
    ///
    /// This is useful for kernel-style "wait forever" implementations that
    /// still need a wakeup source (e.g. to drive a fake clock in bring-up).
    pub fn next_deadline(&mut self) -> Option<Time> {
        while let Some(top) = self.heap.peek().copied() {
            // Lazy skip: timer might have been re-armed, canceled, or deleted.
            let Some(st) = self.timers.get(&top.id) else {
                let _ = self.heap.pop();
                continue;
            };
            if st.deadline != Some(top.deadline) {
                let _ = self.heap.pop();
                continue;
            }
            return Some(top.deadline);
        }
        None
    }

    /// Advance time and return the list of timer ids that became signaled.
    pub fn advance_clock(
        &mut self,
        clock: &mut FakeClock,
        new_time: Time,
    ) -> alloc::vec::Vec<TimerId> {
        clock.advance_to(new_time);
        self.fire_due(clock.now())
    }

    /// Fire due timers for an externally managed time source.
    ///
    /// This is the kernel-facing API: the kernel owns the monotonic clock and
    /// calls `poll(now)` from a timer interrupt or scheduler tick.
    pub fn poll(&mut self, now: Time) -> alloc::vec::Vec<TimerId> {
        self.fire_due(now)
    }

    /// Fire due timers for current time `now`.
    fn fire_due(&mut self, now: Time) -> alloc::vec::Vec<TimerId> {
        let mut fired = alloc::vec::Vec::new();

        while let Some(top) = self.heap.peek().copied() {
            if top.deadline > now {
                break;
            }
            let _ = self.heap.pop();

            // Lazy skip: timer might have been re-armed or canceled.
            let Some(st) = self.timers.get_mut(&top.id) else {
                continue;
            };
            if st.deadline != Some(top.deadline) {
                continue;
            }

            st.deadline = None;
            st.signaled = true;
            fired.push(top.id);
        }

        fired
    }
}

/// Identifier for one blocked wait deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WaitDeadlineId {
    thread_id: u64,
    seq: u64,
}

impl WaitDeadlineId {
    /// Create one wait-deadline id.
    pub const fn new(thread_id: u64, seq: u64) -> Self {
        Self { thread_id, seq }
    }

    /// Owning thread id.
    pub const fn thread_id(self) -> u64 {
        self.thread_id
    }

    /// Wait-sequence discriminator.
    pub const fn seq(self) -> u64 {
        self.seq
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ReactorEntryKind {
    Timer(TimerId),
    Wait(WaitDeadlineId),
}

#[derive(Clone, Copy, Debug)]
struct ReactorHeapEntry {
    deadline: Time,
    slot: usize,
    kind: ReactorEntryKind,
}

impl PartialEq for ReactorHeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline && self.slot == other.slot && self.kind == other.kind
    }
}

impl Eq for ReactorHeapEntry {}

impl PartialOrd for ReactorHeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ReactorHeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .deadline
            .cmp(&self.deadline)
            .then_with(|| other.slot.cmp(&self.slot))
            .then_with(|| other.kind.cmp(&self.kind))
    }
}

#[derive(Clone, Copy, Debug)]
struct ReactorTimerState {
    deadline: Option<Time>,
    signaled: bool,
    slot: usize,
}

#[derive(Clone, Copy, Debug)]
struct WaitDeadlineState {
    deadline: Time,
    slot: usize,
}

/// One due event returned by the unified reactor timer backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReactorTimerEvent {
    /// One kernel timer object became signaled.
    TimerFired(TimerId),
    /// One blocked wait deadline expired.
    WaitExpired(WaitDeadlineId),
}

/// Lightweight telemetry for the unified timer backend.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReactorTimerStats {
    /// Object timers currently armed.
    pub armed_timers: usize,
    /// Wait deadlines currently armed.
    pub armed_waits: usize,
    /// Peak total armed entries.
    pub peak_armed_total: usize,
    /// Number of timer-object firings produced so far.
    pub timer_fire_count: u64,
    /// Number of wait-deadline expirations produced so far.
    pub wait_expire_count: u64,
    /// Number of explicit cancels processed so far.
    pub cancel_count: u64,
}

/// Unified timer backend for timer objects and wait deadlines.
#[derive(Debug)]
pub struct ReactorTimerCore {
    next_timer_id: u64,
    timers: BTreeMap<TimerId, ReactorTimerState>,
    waits: BTreeMap<WaitDeadlineId, WaitDeadlineState>,
    slots: Vec<BinaryHeap<ReactorHeapEntry>>,
    stats: ReactorTimerStats,
}

impl ReactorTimerCore {
    /// Create a core with `slot_count` deadline heaps.
    pub fn new(slot_count: usize) -> Self {
        assert!(slot_count > 0, "slot_count must be non-zero");
        Self {
            next_timer_id: 0,
            timers: BTreeMap::new(),
            waits: BTreeMap::new(),
            slots: (0..slot_count).map(|_| BinaryHeap::new()).collect(),
            stats: ReactorTimerStats::default(),
        }
    }

    fn slot_for_cpu(&self, cpu_id: usize) -> usize {
        cpu_id.min(self.slots.len().saturating_sub(1))
    }

    fn note_population_change(&mut self) {
        let total = self.stats.armed_timers + self.stats.armed_waits;
        self.stats.peak_armed_total = self.stats.peak_armed_total.max(total);
    }

    /// Create a new timer-object id.
    pub fn create_timer(&mut self) -> TimerId {
        let id = TimerId(self.next_timer_id);
        self.next_timer_id = self.next_timer_id.wrapping_add(1);
        self.timers.insert(
            id,
            ReactorTimerState {
                deadline: None,
                signaled: false,
                slot: 0,
            },
        );
        id
    }

    /// Remove one timer object from the backend.
    pub fn remove_timer(&mut self, id: TimerId) -> Result<(), TimerError> {
        let Some(state) = self.timers.remove(&id) else {
            return Err(TimerError::NotFound);
        };
        if state.deadline.is_some() {
            self.stats.armed_timers = self.stats.armed_timers.saturating_sub(1);
        }
        Ok(())
    }

    /// Arm or re-arm a timer object on the slot owned by `cpu_id`.
    pub fn set_timer(
        &mut self,
        id: TimerId,
        cpu_id: usize,
        deadline: Time,
        now: Time,
    ) -> Result<bool, TimerError> {
        let slot = self.slot_for_cpu(cpu_id);
        let was_armed = self
            .timers
            .get(&id)
            .map(|state| state.deadline.is_some())
            .ok_or(TimerError::NotFound)?;
        if !was_armed {
            self.stats.armed_timers += 1;
            self.note_population_change();
        }
        let Some(state) = self.timers.get_mut(&id) else {
            return Err(TimerError::NotFound);
        };
        state.deadline = Some(deadline);
        state.signaled = false;
        state.slot = slot;
        if deadline <= now {
            state.deadline = None;
            state.signaled = true;
            self.stats.armed_timers = self.stats.armed_timers.saturating_sub(1);
            self.stats.timer_fire_count = self.stats.timer_fire_count.saturating_add(1);
            return Ok(true);
        }
        self.slots[slot].push(ReactorHeapEntry {
            deadline,
            slot,
            kind: ReactorEntryKind::Timer(id),
        });
        Ok(false)
    }

    /// Cancel one timer object.
    pub fn cancel_timer(&mut self, id: TimerId) -> Result<(), TimerError> {
        let Some(state) = self.timers.get_mut(&id) else {
            return Err(TimerError::NotFound);
        };
        if state.deadline.take().is_some() {
            self.stats.armed_timers = self.stats.armed_timers.saturating_sub(1);
            self.stats.cancel_count = self.stats.cancel_count.saturating_add(1);
        }
        state.signaled = false;
        Ok(())
    }

    /// Whether a timer object is currently signaled.
    pub fn is_timer_signaled(&self, id: TimerId) -> Result<bool, TimerError> {
        self.timers
            .get(&id)
            .map(|state| state.signaled)
            .ok_or(TimerError::NotFound)
    }

    /// Arm or re-arm one blocked wait deadline.
    pub fn arm_wait_deadline(&mut self, cpu_id: usize, id: WaitDeadlineId, deadline: Time) {
        let slot = self.slot_for_cpu(cpu_id);
        if self
            .waits
            .insert(id, WaitDeadlineState { deadline, slot })
            .is_none()
        {
            self.stats.armed_waits += 1;
            self.note_population_change();
        }
        self.slots[slot].push(ReactorHeapEntry {
            deadline,
            slot,
            kind: ReactorEntryKind::Wait(id),
        });
    }

    /// Cancel one blocked wait deadline.
    pub fn cancel_wait_deadline(&mut self, id: WaitDeadlineId) {
        if self.waits.remove(&id).is_some() {
            self.stats.armed_waits = self.stats.armed_waits.saturating_sub(1);
            self.stats.cancel_count = self.stats.cancel_count.saturating_add(1);
        }
    }

    /// Poll one CPU slot and return all due events.
    pub fn poll_slot(&mut self, cpu_id: usize, now: Time) -> alloc::vec::Vec<ReactorTimerEvent> {
        let slot = self.slot_for_cpu(cpu_id);
        let mut due = alloc::vec::Vec::new();
        self.poll_slot_inner(slot, now, &mut due);
        due
    }

    /// Poll every slot and return all due events.
    pub fn poll_all(&mut self, now: Time) -> alloc::vec::Vec<ReactorTimerEvent> {
        let mut due = alloc::vec::Vec::new();
        for slot in 0..self.slots.len() {
            self.poll_slot_inner(slot, now, &mut due);
        }
        due
    }

    /// Current telemetry snapshot.
    pub const fn stats(&self) -> ReactorTimerStats {
        self.stats
    }

    fn poll_slot_inner(
        &mut self,
        slot: usize,
        now: Time,
        out: &mut alloc::vec::Vec<ReactorTimerEvent>,
    ) {
        loop {
            let entry = {
                let Some(heap) = self.slots.get_mut(slot) else {
                    return;
                };
                let Some(entry) = heap.peek().copied() else {
                    return;
                };
                if entry.deadline > now {
                    return;
                }
                let _ = heap.pop();
                entry
            };

            match entry.kind {
                ReactorEntryKind::Timer(id) => {
                    let Some(state) = self.timers.get_mut(&id) else {
                        continue;
                    };
                    if state.deadline != Some(entry.deadline) || state.slot != entry.slot {
                        continue;
                    }
                    state.deadline = None;
                    state.signaled = true;
                    self.stats.armed_timers = self.stats.armed_timers.saturating_sub(1);
                    self.stats.timer_fire_count = self.stats.timer_fire_count.saturating_add(1);
                    out.push(ReactorTimerEvent::TimerFired(id));
                }
                ReactorEntryKind::Wait(id) => {
                    let Some(state) = self.waits.get(&id).copied() else {
                        continue;
                    };
                    if state.deadline != entry.deadline || state.slot != entry.slot {
                        continue;
                    }
                    let _ = self.waits.remove(&id);
                    self.stats.armed_waits = self.stats.armed_waits.saturating_sub(1);
                    self.stats.wait_expire_count = self.stats.wait_expire_count.saturating_add(1);
                    out.push(ReactorTimerEvent::WaitExpired(id));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_set_fire_cancel() {
        let mut clock = FakeClock::new();
        let mut svc = TimerService::new();

        let t = svc.create_timer();
        assert!(!svc.is_signaled(t).unwrap());

        svc.set(t, 10).unwrap();

        // advance to 9: no fire
        let fired = svc.advance_clock(&mut clock, 9);
        assert!(fired.is_empty());
        assert!(!svc.is_signaled(t).unwrap());

        // advance to 10: fire
        let fired = svc.advance_clock(&mut clock, 10);
        assert_eq!(fired, alloc::vec![t]);
        assert!(svc.is_signaled(t).unwrap());

        // re-arm clears signaled
        svc.set(t, 20).unwrap();
        assert!(!svc.is_signaled(t).unwrap());

        // cancel clears
        svc.cancel(t).unwrap();
        assert!(!svc.is_signaled(t).unwrap());
        let fired = svc.advance_clock(&mut clock, 100);
        assert!(fired.is_empty());
    }

    #[test]
    fn rearm_uses_latest_deadline() {
        let mut clock = FakeClock::new();
        let mut svc = TimerService::new();

        let t = svc.create_timer();
        svc.set(t, 50).unwrap();
        svc.set(t, 10).unwrap(); // earlier deadline wins

        let fired = svc.advance_clock(&mut clock, 10);
        assert_eq!(fired, alloc::vec![t]);
    }

    #[test]
    fn reactor_timer_core_fires_object_timers() {
        let mut core = ReactorTimerCore::new(2);
        let timer = core.create_timer();
        assert!(!core.set_timer(timer, 1, 10, 0).unwrap());
        assert!(!core.is_timer_signaled(timer).unwrap());
        assert!(core.poll_slot(0, 10).is_empty());
        let due = core.poll_slot(1, 10);
        assert_eq!(due, alloc::vec![ReactorTimerEvent::TimerFired(timer)]);
        assert!(core.is_timer_signaled(timer).unwrap());
    }

    #[test]
    fn reactor_timer_core_cancels_wait_deadlines() {
        let mut core = ReactorTimerCore::new(4);
        let wait = WaitDeadlineId::new(7, 11);
        core.arm_wait_deadline(3, wait, 20);
        core.cancel_wait_deadline(wait);
        assert!(core.poll_slot(3, 20).is_empty());
    }

    #[test]
    fn reactor_timer_core_polls_all_slots() {
        let mut core = ReactorTimerCore::new(2);
        let timer = core.create_timer();
        let wait = WaitDeadlineId::new(9, 2);
        assert!(!core.set_timer(timer, 0, 5, 0).unwrap());
        core.arm_wait_deadline(1, wait, 5);
        let due = core.poll_all(5);
        assert_eq!(due.len(), 2);
        assert!(due.contains(&ReactorTimerEvent::TimerFired(timer)));
        assert!(due.contains(&ReactorTimerEvent::WaitExpired(wait)));
        let stats = core.stats();
        assert_eq!(stats.timer_fire_count, 1);
        assert_eq!(stats.wait_expire_count, 1);
    }

    #[test]
    fn reactor_timer_core_can_fire_timer_immediately() {
        let mut core = ReactorTimerCore::new(1);
        let timer = core.create_timer();
        assert!(core.set_timer(timer, 0, 5, 5).unwrap());
        assert!(core.is_timer_signaled(timer).unwrap());
        assert!(core.poll_all(5).is_empty());
    }

    #[test]
    fn reactor_timer_core_removes_armed_timer() {
        let mut core = ReactorTimerCore::new(1);
        let timer = core.create_timer();
        assert!(!core.set_timer(timer, 0, 10, 0).unwrap());
        core.remove_timer(timer).unwrap();
        assert!(core.poll_all(10).is_empty());
        let stats = core.stats();
        assert_eq!(stats.armed_timers, 0);
    }
}
