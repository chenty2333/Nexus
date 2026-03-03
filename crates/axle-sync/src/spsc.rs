//! Single-producer / single-consumer ring buffer (lock-free).
//!
//! Intended usage:
//! - Exactly **one producer thread** calls `try_push`.
//! - Exactly **one consumer thread** calls `try_pop`.
//!
//! This primitive is a building block for Axle's data-plane queues (IPC/Port rings), and is
//! designed to be simple enough for Loom testing and auditing.

use core::{array, mem::MaybeUninit};

#[cfg(feature = "loom")]
use loom::cell::UnsafeCell;
#[cfg(feature = "loom")]
use loom::sync::atomic::{AtomicUsize, Ordering};

#[cfg(not(feature = "loom"))]
use core::cell::UnsafeCell;
#[cfg(not(feature = "loom"))]
use core::sync::atomic::{AtomicUsize, Ordering};

/// A lock-free SPSC ring.
///
/// Capacity is `N-1` (one slot is always left empty to distinguish full vs empty).
///
/// ### Why `UnsafeCell<MaybeUninit<T>>` *per slot*?
///
/// In real Rust, disjoint slot accesses are data-race-free under the SPSC discipline.
///
/// In Loom, `UnsafeCell` tracks access at the *cell* granularity. If we used a single
/// `UnsafeCell<[...; N]>`, producer and consumer would appear to concurrently mutably/immutably
/// access the same cell and Loom would (correctly, per its coarse model) panic.
///
/// Per-slot cells let Loom validate that we never concurrently access the *same slot*.
pub struct SpscRing<T: Copy, const N: usize> {
    head: AtomicUsize,
    tail: AtomicUsize,
    buf: [UnsafeCell<MaybeUninit<T>>; N],
}

// SAFETY: T is Copy, so reads/writes do not involve drop glue. The SPSC discipline ensures
// no data races on individual slots (producer writes each slot once before consumer reads it).
unsafe impl<T: Copy + Send, const N: usize> Send for SpscRing<T, N> {}
// SAFETY: Concurrent access is safe under the SPSC discipline (one producer + one consumer).
unsafe impl<T: Copy + Send, const N: usize> Sync for SpscRing<T, N> {}

impl<T: Copy, const N: usize> SpscRing<T, N> {
    /// Create an empty ring.
    pub fn new() -> Self {
        assert!(N >= 2, "ring size must be >= 2");

        // Start with all slots uninitialized.
        let buf = array::from_fn(|_| UnsafeCell::new(MaybeUninit::uninit()));

        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            buf,
        }
    }

    /// Maximum number of elements that can be stored at once (`N-1`).
    pub const fn capacity(&self) -> usize {
        N - 1
    }

    #[inline(always)]
    fn inc(i: usize) -> usize {
        let n = N;
        let j = i + 1;
        if j == n {
            0
        } else {
            j
        }
    }

    /// Try to push a value. Returns `Err(value)` if the ring is full.
    pub fn try_push(&self, value: T) -> Result<(), T> {
        let tail = self.tail.load(Ordering::Relaxed);
        let next = Self::inc(tail);

        // Acquire: we must observe consumer progress before deciding "full".
        let head = self.head.load(Ordering::Acquire);
        if next == head {
            return Err(value);
        }

        // SAFETY: Only the producer writes to `tail` slot; `tail != head` implies slot is free.
        self.write_slot(tail, value);

        // Release: publish the element before making it visible by updating `tail`.
        self.tail.store(next, Ordering::Release);
        Ok(())
    }

    /// Try to pop a value. Returns `None` if the ring is empty.
    pub fn try_pop(&self) -> Option<T> {
        let head = self.head.load(Ordering::Relaxed);

        // Acquire: must observe producer published element before reading from buffer.
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }

        // SAFETY: Only consumer reads from `head` slot; `head != tail` implies initialized.
        let value = self.read_slot(head);

        let next = Self::inc(head);
        // Release: consumer must finish reading the element before advancing `head`.
        self.head.store(next, Ordering::Release);
        Some(value)
    }

    /// Returns `true` if empty (non-linearizable helper, for diagnostics only).
    pub fn is_empty_relaxed(&self) -> bool {
        self.head.load(Ordering::Relaxed) == self.tail.load(Ordering::Relaxed)
    }

    #[inline(always)]
    fn write_slot(&self, idx: usize, value: T) {
        #[cfg(feature = "loom")]
        {
            self.buf[idx].with_mut(|p| unsafe {
                (*p).write(value);
            });
        }

        #[cfg(not(feature = "loom"))]
        unsafe {
            (*self.buf[idx].get()).write(value);
        }
    }

    #[inline(always)]
    fn read_slot(&self, idx: usize) -> T {
        #[cfg(feature = "loom")]
        {
            self.buf[idx].with(|p| unsafe { (*p).as_ptr().read() })
        }

        #[cfg(not(feature = "loom"))]
        unsafe {
            (*self.buf[idx].get()).as_ptr().read()
        }
    }
}

impl<T: Copy, const N: usize> Default for SpscRing<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::SpscRing;

    #[test]
    fn basic_push_pop() {
        // When built with `--features loom`, this crate uses Loom synchronization primitives.
        // Loom primitives must only be accessed from within `loom::model`.
        #[cfg(feature = "loom")]
        loom::model(|| basic_push_pop_body());

        #[cfg(not(feature = "loom"))]
        basic_push_pop_body();
    }

    fn basic_push_pop_body() {
        let q: SpscRing<u32, 4> = SpscRing::new();
        assert_eq!(q.try_pop(), None);

        q.try_push(1).unwrap();
        q.try_push(2).unwrap();
        q.try_push(3).unwrap();
        assert!(q.try_push(4).is_err(), "capacity is N-1");

        assert_eq!(q.try_pop(), Some(1));
        assert_eq!(q.try_pop(), Some(2));
        assert_eq!(q.try_pop(), Some(3));
        assert_eq!(q.try_pop(), None);
    }

    #[cfg(feature = "loom")]
    #[test]
    fn loom_two_thread_in_order() {
        use loom::sync::Arc;
        use loom::sync::Mutex;
        use loom::thread;

        loom::model(|| {
            let q: Arc<SpscRing<u32, 4>> = Arc::new(SpscRing::new());
            let out: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));

            let qp = q.clone();
            let prod = thread::spawn(move || {
                for i in 1..=3u32 {
                    loop {
                        if qp.try_push(i).is_ok() {
                            break;
                        }
                        thread::yield_now();
                    }
                }
            });

            let qc = q.clone();
            let outc = out.clone();
            let cons = thread::spawn(move || {
                while outc.lock().unwrap().len() < 3 {
                    if let Some(v) = qc.try_pop() {
                        outc.lock().unwrap().push(v);
                    } else {
                        thread::yield_now();
                    }
                }
            });

            prod.join().unwrap();
            cons.join().unwrap();

            let got = out.lock().unwrap().clone();
            assert_eq!(got, vec![1, 2, 3]);
        });
    }
}
