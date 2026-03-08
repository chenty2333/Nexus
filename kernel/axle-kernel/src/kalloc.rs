//! Minimal bump allocator for early bring-up.
//!
//! This is intentionally simple and temporary. It enables `alloc` users
//! (CSpace/object tables) before a real PMM-backed allocator is integrated.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

use spin::Mutex;

const HEAP_SIZE: usize = 8 * 1024 * 1024; // 8 MiB bootstrap heap.

static NEXT: Mutex<usize> = Mutex::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOC_FAIL_COUNT: AtomicUsize = AtomicUsize::new(0);

#[repr(align(4096))]
struct AlignedHeap([u8; HEAP_SIZE]);

static mut HEAP: AlignedHeap = AlignedHeap([0; HEAP_SIZE]);

/// Global bootstrap allocator.
pub struct BootstrapAllocator;

#[derive(Clone, Copy, Debug)]
pub(crate) struct BootstrapHeapStats {
    pub(crate) used_bytes: usize,
    pub(crate) peak_bytes: usize,
    pub(crate) alloc_fail_count: usize,
    pub(crate) capacity_bytes: usize,
}

pub(crate) fn bootstrap_heap_stats() -> BootstrapHeapStats {
    let used_bytes = *NEXT.lock();
    BootstrapHeapStats {
        used_bytes,
        peak_bytes: PEAK.load(Ordering::Relaxed),
        alloc_fail_count: ALLOC_FAIL_COUNT.load(Ordering::Relaxed),
        capacity_bytes: HEAP_SIZE,
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: BootstrapAllocator = BootstrapAllocator;

const fn align_up(v: usize, align: usize) -> usize {
    (v + (align - 1)) & !(align - 1)
}

unsafe impl GlobalAlloc for BootstrapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut next = NEXT.lock();
        let heap_base = core::ptr::addr_of_mut!(HEAP) as usize;
        let start_addr = align_up(heap_base.saturating_add(*next), layout.align());
        let end_addr = start_addr.saturating_add(layout.size());
        let heap_end = heap_base.saturating_add(HEAP_SIZE);
        if end_addr > heap_end {
            ALLOC_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
            return null_mut();
        }

        *next = end_addr - heap_base;
        let used_bytes = *next;
        let mut peak = PEAK.load(Ordering::Relaxed);
        while used_bytes > peak {
            match PEAK.compare_exchange_weak(peak, used_bytes, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(observed) => peak = observed,
            }
        }

        // SAFETY: address range was checked against the static heap bounds.
        start_addr as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // no-op for bootstrap bump allocator
    }
}
