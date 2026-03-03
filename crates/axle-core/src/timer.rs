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

    /// Advance time and return the list of timer ids that became signaled.
    pub fn advance_clock(
        &mut self,
        clock: &mut FakeClock,
        new_time: Time,
    ) -> alloc::vec::Vec<TimerId> {
        clock.advance_to(new_time);
        self.fire_due(clock.now())
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
}
