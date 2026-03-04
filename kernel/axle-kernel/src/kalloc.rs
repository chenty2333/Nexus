//! Minimal bump allocator for early bring-up.
//!
//! This is intentionally simple and temporary. It enables `alloc` users
//! (CSpace/object tables) before a real PMM-backed allocator is integrated.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;

use spin::Mutex;

const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB bootstrap heap.

static NEXT: Mutex<usize> = Mutex::new(0);
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

/// Global bootstrap allocator.
pub struct BootstrapAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: BootstrapAllocator = BootstrapAllocator;

const fn align_up(v: usize, align: usize) -> usize {
    (v + (align - 1)) & !(align - 1)
}

unsafe impl GlobalAlloc for BootstrapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut next = NEXT.lock();
        let start = align_up(*next, layout.align());
        let end = start.saturating_add(layout.size());
        if end > HEAP_SIZE {
            return null_mut();
        }

        *next = end;

        // SAFETY: `start..end` was range-checked against the static heap bounds.
        unsafe { (core::ptr::addr_of_mut!(HEAP) as *mut u8).add(start) }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // no-op for bootstrap bump allocator
    }
}
