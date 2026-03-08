//! Minimal bump allocator for early bring-up.
//!
//! This is intentionally simple and temporary. It enables `alloc` users
//! (CSpace/object tables) before a real PMM-backed allocator is integrated.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;

use spin::Mutex;

const HEAP_SIZE: usize = 8 * 1024 * 1024; // 8 MiB bootstrap heap.

static NEXT: Mutex<usize> = Mutex::new(0);

#[repr(align(4096))]
struct AlignedHeap([u8; HEAP_SIZE]);

static mut HEAP: AlignedHeap = AlignedHeap([0; HEAP_SIZE]);

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
        let heap_base = core::ptr::addr_of_mut!(HEAP) as usize;
        let start_addr = align_up(heap_base.saturating_add(*next), layout.align());
        let end_addr = start_addr.saturating_add(layout.size());
        let heap_end = heap_base.saturating_add(HEAP_SIZE);
        if end_addr > heap_end {
            return null_mut();
        }

        *next = end_addr - heap_base;

        // SAFETY: address range was checked against the static heap bounds.
        start_addr as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // no-op for bootstrap bump allocator
    }
}
