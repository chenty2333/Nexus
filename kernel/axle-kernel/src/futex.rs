//! Internal futex wait-queue state machine.
//!
//! This module is intentionally independent from the syscall layer so the
//! roadmap's `(global VMO identity, offset)` key semantics can be tested before
//! the full `zx_futex_*` ABI lands.

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use axle_mm::FutexKey;
use axle_types::koid::ZX_KOID_INVALID;
use axle_types::zx_koid_t;

/// Result of waking waiters from one futex queue.
#[derive(Debug, Default)]
pub(crate) struct WakeResult {
    /// Waiters woken in FIFO order.
    pub(crate) woken: Vec<u64>,
    /// Number of waiters left queued on the futex after the wake.
    pub(crate) remaining: usize,
}

/// Result of moving waiters between futex queues.
#[derive(Debug, Default)]
pub(crate) struct RequeueResult {
    /// Waiters woken in FIFO order from the source queue.
    pub(crate) woken: Vec<u64>,
    /// Number of waiters moved to the target queue.
    pub(crate) requeued: usize,
    /// Remaining waiter count on the source queue.
    pub(crate) source_remaining: usize,
    /// Remaining waiter count on the target queue.
    pub(crate) target_remaining: usize,
}

#[derive(Debug, Default)]
struct FutexQueue {
    waiters: VecDeque<u64>,
    owner_koid: zx_koid_t,
}

/// Kernel futex table keyed by metadata-derived `FutexKey`.
#[derive(Debug, Default)]
pub(crate) struct FutexTable {
    queues: BTreeMap<FutexKey, FutexQueue>,
}

impl FutexTable {
    /// Create an empty futex table.
    pub(crate) fn new() -> Self {
        Self {
            queues: BTreeMap::new(),
        }
    }

    /// Return the recorded owner koid for one key, or `ZX_KOID_INVALID`.
    pub(crate) fn owner(&self, key: FutexKey) -> zx_koid_t {
        self.queues
            .get(&key)
            .map(|queue| queue.owner_koid)
            .unwrap_or(ZX_KOID_INVALID)
    }

    /// Enqueue one waiter in FIFO order.
    pub(crate) fn enqueue_waiter(&mut self, key: FutexKey, thread_id: u64, owner_koid: zx_koid_t) {
        let queue = self.queues.entry(key).or_default();
        queue.waiters.push_back(thread_id);
        if owner_koid != ZX_KOID_INVALID {
            queue.owner_koid = owner_koid;
        }
    }

    /// Remove one waiter from a queue if it is still present.
    pub(crate) fn cancel_waiter(&mut self, key: FutexKey, thread_id: u64) -> bool {
        let Some(queue) = self.queues.get_mut(&key) else {
            return false;
        };
        let before = queue.waiters.len();
        queue.waiters.retain(|waiter| *waiter != thread_id);
        let removed = queue.waiters.len() != before;
        self.gc_key(key);
        removed
    }

    /// Wake up to `wake_count` waiters from one queue.
    pub(crate) fn wake(
        &mut self,
        key: FutexKey,
        wake_count: usize,
        new_owner_koid: zx_koid_t,
        single_owner: bool,
    ) -> WakeResult {
        let Some(queue) = self.queues.get_mut(&key) else {
            return WakeResult::default();
        };

        let mut result = WakeResult::default();
        for _ in 0..wake_count {
            let Some(thread_id) = queue.waiters.pop_front() else {
                break;
            };
            result.woken.push(thread_id);
        }
        if single_owner {
            queue.owner_koid = new_owner_koid;
        } else if !result.woken.is_empty() {
            queue.owner_koid = ZX_KOID_INVALID;
        }
        result.remaining = queue.waiters.len();
        self.gc_key(key);
        result
    }

    /// Wake some waiters on `source`, then move more to `target`.
    pub(crate) fn requeue(
        &mut self,
        source: FutexKey,
        target: FutexKey,
        wake_count: usize,
        requeue_count: usize,
        target_owner_koid: zx_koid_t,
    ) -> RequeueResult {
        if source == target {
            let wake = self.wake(source, wake_count, target_owner_koid, false);
            return RequeueResult {
                requeued: 0,
                source_remaining: wake.remaining,
                target_remaining: wake.remaining,
                woken: wake.woken,
            };
        }

        let mut result = RequeueResult::default();
        let mut moved = VecDeque::new();

        if let Some(source_queue) = self.queues.get_mut(&source) {
            for _ in 0..wake_count {
                let Some(thread_id) = source_queue.waiters.pop_front() else {
                    break;
                };
                result.woken.push(thread_id);
            }
            for _ in 0..requeue_count {
                let Some(thread_id) = source_queue.waiters.pop_front() else {
                    break;
                };
                moved.push_back(thread_id);
                result.requeued += 1;
            }
            if !result.woken.is_empty() {
                source_queue.owner_koid = ZX_KOID_INVALID;
            }
            result.source_remaining = source_queue.waiters.len();
        }

        if !moved.is_empty() {
            let target_queue = self.queues.entry(target).or_default();
            if target_owner_koid != ZX_KOID_INVALID {
                target_queue.owner_koid = target_owner_koid;
            }
            target_queue.waiters.extend(moved);
            result.target_remaining = target_queue.waiters.len();
        } else {
            result.target_remaining = self
                .queues
                .get(&target)
                .map(|queue| queue.waiters.len())
                .unwrap_or(0);
        }

        self.gc_key(source);
        self.gc_key(target);
        result
    }

    fn gc_key(&mut self, key: FutexKey) {
        let should_remove = self
            .queues
            .get(&key)
            .map(|queue| queue.waiters.is_empty() && queue.owner_koid == ZX_KOID_INVALID)
            .unwrap_or(false);
        if should_remove {
            let _ = self.queues.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FutexTable, RequeueResult, WakeResult};
    use axle_mm::{FutexKey, GlobalVmoId};

    fn shared_key(id: u64, offset: u64) -> FutexKey {
        FutexKey::Shared {
            global_vmo_id: GlobalVmoId::new(id),
            offset,
        }
    }

    #[test]
    fn wake_is_fifo_and_clears_owner() {
        let key = shared_key(1, 0);
        let mut table = FutexTable::new();
        table.enqueue_waiter(key, 11, 500);
        table.enqueue_waiter(key, 12, 500);

        let WakeResult { woken, remaining } = table.wake(key, 1, 0, false);
        assert_eq!(woken, alloc::vec![11]);
        assert_eq!(remaining, 1);
        assert_eq!(table.owner(key), 0);
    }

    #[test]
    fn requeue_moves_tail_waiters_and_sets_target_owner() {
        let source = shared_key(1, 0);
        let target = shared_key(2, 0);
        let mut table = FutexTable::new();
        table.enqueue_waiter(source, 1, 77);
        table.enqueue_waiter(source, 2, 77);
        table.enqueue_waiter(source, 3, 77);

        let RequeueResult {
            woken,
            requeued,
            source_remaining,
            target_remaining,
        } = table.requeue(source, target, 1, 2, 88);

        assert_eq!(woken, alloc::vec![1]);
        assert_eq!(requeued, 2);
        assert_eq!(source_remaining, 0);
        assert_eq!(target_remaining, 2);
        assert_eq!(table.owner(target), 88);
    }

    #[test]
    fn cancel_waiter_removes_one_registration() {
        let key = shared_key(9, 0x40);
        let mut table = FutexTable::new();
        table.enqueue_waiter(key, 1, 0);
        table.enqueue_waiter(key, 2, 0);

        assert!(table.cancel_waiter(key, 1));
        let WakeResult { woken, remaining } = table.wake(key, 2, 0, false);
        assert_eq!(woken, alloc::vec![2]);
        assert_eq!(remaining, 0);
    }
}
