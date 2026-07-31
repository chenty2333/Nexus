// SPDX-License-Identifier: MPL-2.0

//! Global frame allocator wrapper which reserves the persistent DMA arena.
//!
//! The current production QEMU scheme supplies 1 GiB of guest RAM. The arena
//! sits at 768 MiB, away from the low-memory early allocator and below the
//! guest RAM ceiling. A machine whose usable-memory map does not completely
//! contain this exact range fails closed on its first global allocation.

use core::{
    alloc::Layout,
    ops::Range,
    sync::atomic::{AtomicU8, Ordering},
};

use osdk_frame_allocator::FrameAllocator;
use ostd::mm::{PAGE_SIZE, Paddr, frame::GlobalFrameAllocator};

const DMA_ARENA_BASE: Paddr = 0x3000_0000;
const DMA_ARENA_FRAME_COUNT: usize = 3;
const DMA_ARENA_SIZE: usize = DMA_ARENA_FRAME_COUNT * PAGE_SIZE;
const DMA_ARENA_END: Paddr = DMA_ARENA_BASE + DMA_ARENA_SIZE;
const QEMU_PRODUCTION_RAM_END: Paddr = 0x4000_0000;

const RESERVATION_UNSEEN: u8 = 0;
const RESERVATION_WITHHOLDING: u8 = 1;
const RESERVATION_READY: u8 = 2;
const RESERVATION_FAILED: u8 = 3;

const _: () = {
    assert!(DMA_ARENA_BASE.is_multiple_of(PAGE_SIZE));
    assert!(DMA_ARENA_SIZE == 3 * PAGE_SIZE);
    assert!(DMA_ARENA_END <= QEMU_PRODUCTION_RAM_END);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FreeRange {
    base: Paddr,
    size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddFreeMemoryPlan {
    Forward,
    Withhold {
        left: Option<FreeRange>,
        right: Option<FreeRange>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeallocPlan {
    Forward,
    RetainArena,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RangeError {
    Empty,
    Unaligned,
    Overflow,
    PartialArenaOverlap,
}

struct PersistentDmaArenaFrameAllocator {
    inner: FrameAllocator,
    reservation: AtomicU8,
}

impl PersistentDmaArenaFrameAllocator {
    const fn new() -> Self {
        Self {
            inner: FrameAllocator,
            reservation: AtomicU8::new(RESERVATION_UNSEEN),
        }
    }

    fn fail_closed(&self, reason: &'static str) -> ! {
        self.reservation
            .store(RESERVATION_FAILED, Ordering::Release);
        panic!("CSER persistent DMA arena allocator failed closed: {reason}");
    }

    fn require_ready(&self) {
        if self.reservation.load(Ordering::Acquire) != RESERVATION_READY {
            self.fail_closed("the exact arena was not withheld before frame allocation");
        }
    }
}

#[ostd::global_frame_allocator]
static FRAME_ALLOCATOR: PersistentDmaArenaFrameAllocator = PersistentDmaArenaFrameAllocator::new();

impl GlobalFrameAllocator for PersistentDmaArenaFrameAllocator {
    fn alloc(&self, layout: Layout) -> Option<Paddr> {
        self.require_ready();
        let allocated = self.inner.alloc(layout)?;
        let end = checked_page_end(allocated, layout.size())
            .unwrap_or_else(|_| self.fail_closed("the inner allocator returned an invalid range"));
        if overlaps_arena(allocated, end) {
            self.fail_closed("the inner allocator returned a withheld arena frame");
        }
        Some(allocated)
    }

    fn dealloc(&self, addr: Paddr, size: usize) {
        self.require_ready();
        match plan_dealloc(addr, size) {
            Ok(DeallocPlan::Forward) => self.inner.dealloc(addr, size),
            Ok(DeallocPlan::RetainArena) => {}
            Err(_) => {
                self.fail_closed("an invalid or partially overlapping frame range was deallocated")
            }
        }
    }

    fn add_free_memory(&self, addr: Paddr, size: usize) {
        match self.reservation.load(Ordering::Acquire) {
            RESERVATION_WITHHOLDING | RESERVATION_FAILED => {
                self.fail_closed("free-memory setup overlapped or ran concurrently")
            }
            RESERVATION_UNSEEN | RESERVATION_READY => {}
            _ => self.fail_closed("the reservation state is invalid"),
        }

        let plan = plan_add_free_memory(addr, size)
            .unwrap_or_else(|_| self.fail_closed("the free-memory map is inconsistent"));
        match plan {
            AddFreeMemoryPlan::Forward => self.inner.add_free_memory(addr, size),
            AddFreeMemoryPlan::Withhold { left, right } => {
                if self
                    .reservation
                    .compare_exchange(
                        RESERVATION_UNSEEN,
                        RESERVATION_WITHHOLDING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    self.fail_closed("the exact arena appeared more than once");
                }
                if let Some(range) = left {
                    self.inner.add_free_memory(range.base, range.size);
                }
                if let Some(range) = right {
                    self.inner.add_free_memory(range.base, range.size);
                }
                self.reservation.store(RESERVATION_READY, Ordering::Release);
            }
        }
    }
}

fn checked_page_end(addr: Paddr, size: usize) -> Result<Paddr, RangeError> {
    if size == 0 {
        return Err(RangeError::Empty);
    }
    if !addr.is_multiple_of(PAGE_SIZE) || !size.is_multiple_of(PAGE_SIZE) {
        return Err(RangeError::Unaligned);
    }
    addr.checked_add(size).ok_or(RangeError::Overflow)
}

fn overlaps_arena(start: Paddr, end: Paddr) -> bool {
    start < DMA_ARENA_END && DMA_ARENA_BASE < end
}

fn plan_add_free_memory(addr: Paddr, size: usize) -> Result<AddFreeMemoryPlan, RangeError> {
    let end = checked_page_end(addr, size)?;
    if !overlaps_arena(addr, end) {
        return Ok(AddFreeMemoryPlan::Forward);
    }
    if addr > DMA_ARENA_BASE || end < DMA_ARENA_END {
        return Err(RangeError::PartialArenaOverlap);
    }
    let left = (addr < DMA_ARENA_BASE).then_some(FreeRange {
        base: addr,
        size: DMA_ARENA_BASE - addr,
    });
    let right = (DMA_ARENA_END < end).then_some(FreeRange {
        base: DMA_ARENA_END,
        size: end - DMA_ARENA_END,
    });
    Ok(AddFreeMemoryPlan::Withhold { left, right })
}

fn plan_dealloc(addr: Paddr, size: usize) -> Result<DeallocPlan, RangeError> {
    let end = checked_page_end(addr, size)?;
    if DMA_ARENA_BASE <= addr && end <= DMA_ARENA_END {
        return Ok(DeallocPlan::RetainArena);
    }
    if overlaps_arena(addr, end) {
        return Err(RangeError::PartialArenaOverlap);
    }
    Ok(DeallocPlan::Forward)
}

/// Returns the fixed physical base of the three-frame persistent DMA arena.
#[allow(dead_code)]
pub(crate) const fn persistent_dma_arena_base() -> Paddr {
    DMA_ARENA_BASE
}

/// Returns the exact physical range withheld from the general frame allocator.
#[allow(dead_code)]
pub(crate) fn persistent_dma_arena_range() -> Range<Paddr> {
    DMA_ARENA_BASE..DMA_ARENA_END
}

/// Reports whether the boot memory map supplied the complete arena exactly once.
#[allow(dead_code)]
pub(crate) fn persistent_dma_arena_ready() -> bool {
    FRAME_ALLOCATOR.reservation.load(Ordering::Acquire) == RESERVATION_READY
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn arena_layout_is_exactly_three_contiguous_pages() {
        assert!(persistent_dma_arena_base().is_multiple_of(PAGE_SIZE));
        assert_eq!(
            persistent_dma_arena_range(),
            DMA_ARENA_BASE..DMA_ARENA_BASE + 3 * PAGE_SIZE
        );
    }

    #[ktest]
    fn containing_free_range_is_split_around_the_arena() {
        let base = DMA_ARENA_BASE - 2 * PAGE_SIZE;
        let size = 7 * PAGE_SIZE;
        assert_eq!(
            plan_add_free_memory(base, size),
            Ok(AddFreeMemoryPlan::Withhold {
                left: Some(FreeRange {
                    base,
                    size: 2 * PAGE_SIZE,
                }),
                right: Some(FreeRange {
                    base: DMA_ARENA_END,
                    size: 2 * PAGE_SIZE,
                }),
            })
        );
    }

    #[ktest]
    fn partial_arena_overlap_is_rejected() {
        assert_eq!(
            plan_add_free_memory(DMA_ARENA_BASE - PAGE_SIZE, 2 * PAGE_SIZE),
            Err(RangeError::PartialArenaOverlap)
        );
        assert_eq!(
            plan_add_free_memory(DMA_ARENA_END - PAGE_SIZE, 2 * PAGE_SIZE),
            Err(RangeError::PartialArenaOverlap)
        );
    }

    #[ktest]
    fn arena_segment_drop_is_retained_but_partial_dealloc_is_rejected() {
        for page in 0..DMA_ARENA_FRAME_COUNT {
            assert_eq!(
                plan_dealloc(DMA_ARENA_BASE + page * PAGE_SIZE, PAGE_SIZE),
                Ok(DeallocPlan::RetainArena)
            );
        }
        assert_eq!(
            plan_dealloc(DMA_ARENA_BASE, DMA_ARENA_SIZE),
            Ok(DeallocPlan::RetainArena)
        );
        assert_eq!(
            plan_dealloc(DMA_ARENA_BASE - PAGE_SIZE, PAGE_SIZE),
            Ok(DeallocPlan::Forward)
        );
        assert_eq!(
            plan_dealloc(DMA_ARENA_BASE - PAGE_SIZE, 2 * PAGE_SIZE),
            Err(RangeError::PartialArenaOverlap)
        );
    }
}
