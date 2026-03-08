//! Bootstrap physical-page allocator backed by the PVH memory map.
//!
//! This allocator is intentionally simple:
//! - only manages the identity-mapped low 1 GiB
//! - uses fixed-capacity free-range metadata (no heap)
//! - allocates top-down to stay away from low boot/kernel regions

use core::cmp::{max, min};

use heapless::Vec;
use spin::Mutex;

const PAGE_BYTES: u64 = crate::userspace::USER_PAGE_BYTES;
const IDENTITY_MAPPED_LIMIT: u64 = 1 << 30;
const BOOTSTRAP_RESERVED_FLOOR: u64 = 0x0200_0000; // 32 MiB
const MAX_FREE_RANGES: usize = 128;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PhysRange {
    base: u64,
    len: u64,
}

impl PhysRange {
    const fn end(self) -> u64 {
        self.base + self.len
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BootstrapPageAllocatorStats {
    pub(crate) capacity_bytes: u64,
    pub(crate) free_bytes: u64,
    pub(crate) peak_used_bytes: u64,
    pub(crate) alloc_fail_count: u64,
}

#[derive(Debug)]
struct BootstrapPageAllocator {
    initialized: bool,
    free: Vec<PhysRange, MAX_FREE_RANGES>,
    capacity_bytes: u64,
    free_bytes: u64,
    peak_used_bytes: u64,
    alloc_fail_count: u64,
}

impl BootstrapPageAllocator {
    const fn new() -> Self {
        Self {
            initialized: false,
            free: Vec::new(),
            capacity_bytes: 0,
            free_bytes: 0,
            peak_used_bytes: 0,
            alloc_fail_count: 0,
        }
    }

    fn init(&mut self) {
        if self.initialized {
            return;
        }

        let start = crate::arch::pvh::start_info()
            .expect("pmm: PVH start_info is required for bootstrap page allocation");
        let reserved_floor = bootstrap_reserved_floor(start);

        for entry in crate::arch::pvh::memmap_entries(start) {
            if entry.entry_type != crate::arch::pvh::HVM_MEMMAP_TYPE_RAM || entry.size_bytes == 0 {
                continue;
            }

            let Some(entry_end) = entry
                .addr
                .checked_add(entry.size_bytes)
                .map(|end| min(end, IDENTITY_MAPPED_LIMIT))
            else {
                continue;
            };
            let base = align_up(max(entry.addr, reserved_floor), PAGE_BYTES);
            let end = align_down(entry_end, PAGE_BYTES);
            if end <= base {
                continue;
            }

            self.insert_free_range(PhysRange {
                base,
                len: end - base,
            })
            .expect("pmm: exhausted bootstrap free-range metadata");
        }

        self.capacity_bytes = self.free.iter().map(|range| range.len).sum();
        self.free_bytes = self.capacity_bytes;
        self.peak_used_bytes = 0;
        self.initialized = true;

        assert!(
            self.capacity_bytes != 0,
            "pmm: PVH memmap yielded no usable identity-mapped RAM"
        );
        crate::kprintln!(
            "kernel: pmm capacity={} MiB reserved_floor={:#x}",
            self.capacity_bytes / (1024 * 1024),
            reserved_floor
        );
    }

    fn alloc_pages(&mut self, page_count: usize) -> Option<u64> {
        let bytes = PAGE_BYTES.checked_mul(page_count as u64)?;
        if bytes == 0 {
            return None;
        }

        for index in (0..self.free.len()).rev() {
            let range = self.free[index];
            if range.len < bytes {
                continue;
            }

            let alloc_base = range.end() - bytes;
            if alloc_base == range.base {
                self.free.remove(index);
            } else {
                self.free[index].len -= bytes;
            }
            self.free_bytes -= bytes;
            self.peak_used_bytes = self
                .peak_used_bytes
                .max(self.capacity_bytes - self.free_bytes);
            return Some(alloc_base);
        }

        self.alloc_fail_count = self.alloc_fail_count.saturating_add(1);
        None
    }

    fn free_pages(&mut self, paddr: u64, page_count: usize) {
        if page_count == 0 {
            return;
        }
        let Some(bytes) = PAGE_BYTES.checked_mul(page_count as u64) else {
            return;
        };
        let base = align_down(paddr, PAGE_BYTES);
        let range = PhysRange { base, len: bytes };
        if self.insert_free_range(range).is_ok() {
            self.free_bytes = self
                .free_bytes
                .saturating_add(bytes)
                .min(self.capacity_bytes);
        }
    }

    fn stats(&self) -> BootstrapPageAllocatorStats {
        BootstrapPageAllocatorStats {
            capacity_bytes: self.capacity_bytes,
            free_bytes: self.free_bytes,
            peak_used_bytes: self.peak_used_bytes,
            alloc_fail_count: self.alloc_fail_count,
        }
    }

    fn insert_free_range(&mut self, mut range: PhysRange) -> Result<(), ()> {
        if range.len == 0 {
            return Ok(());
        }

        let mut insert_at = 0;
        while insert_at < self.free.len() && self.free[insert_at].base < range.base {
            insert_at += 1;
        }

        if insert_at > 0 {
            let prev = self.free[insert_at - 1];
            if prev.end() >= range.base {
                range.base = prev.base;
                range.len = max(prev.end(), range.end()) - range.base;
                self.free.remove(insert_at - 1);
                insert_at -= 1;
            }
        }

        while insert_at < self.free.len() {
            let next = self.free[insert_at];
            if next.base > range.end() {
                break;
            }
            range.base = min(range.base, next.base);
            range.len = max(range.end(), next.end()) - range.base;
            self.free.remove(insert_at);
        }

        self.free.insert(insert_at, range).map_err(|_| ())?;
        Ok(())
    }
}

static PMM: Mutex<BootstrapPageAllocator> = Mutex::new(BootstrapPageAllocator::new());

pub(crate) fn init() {
    PMM.lock().init();
}

pub(crate) fn alloc_pages(page_count: usize) -> Option<u64> {
    PMM.lock().alloc_pages(page_count)
}

pub(crate) fn alloc_zeroed_pages(page_count: usize) -> Option<u64> {
    let paddr = alloc_pages(page_count)?;
    let bytes = usize::try_from(PAGE_BYTES.checked_mul(page_count as u64)?).ok()?;
    unsafe {
        // SAFETY: the bootstrap PMM only hands out physical pages below the identity-mapped
        // 1 GiB direct map, so the physical address is directly writable as a kernel pointer.
        core::ptr::write_bytes(paddr as *mut u8, 0, bytes);
    }
    Some(paddr)
}

pub(crate) fn free_pages(paddr: u64, page_count: usize) {
    PMM.lock().free_pages(paddr, page_count);
}

pub(crate) fn stats() -> BootstrapPageAllocatorStats {
    PMM.lock().stats()
}

fn bootstrap_reserved_floor(start: &crate::arch::pvh::HvmStartInfo) -> u64 {
    let mut reserved = BOOTSTRAP_RESERVED_FLOOR;

    let (heap_base, heap_end) = crate::kalloc::bootstrap_heap_region();
    reserved = reserved.max(align_up(heap_end.max(heap_base), PAGE_BYTES));

    let start_info_end = crate::arch::pvh::start_info_paddr()
        .saturating_add(core::mem::size_of::<crate::arch::pvh::HvmStartInfo>() as u64);
    reserved = reserved.max(align_up(start_info_end, PAGE_BYTES));

    if start.nr_modules != 0 {
        let modlist_bytes = (start.nr_modules as u64)
            .saturating_mul(core::mem::size_of::<crate::arch::pvh::HvmModlistEntry>() as u64);
        reserved = reserved.max(align_up(
            start.modlist_paddr.saturating_add(modlist_bytes),
            PAGE_BYTES,
        ));
        for module in crate::arch::pvh::modules(start) {
            reserved = reserved.max(align_up(
                module.paddr.saturating_add(module.size_bytes),
                PAGE_BYTES,
            ));
        }
    }

    if start.memmap_entries != 0 {
        let memmap_bytes = (start.memmap_entries as u64)
            .saturating_mul(core::mem::size_of::<crate::arch::pvh::HvmMemmapEntry>() as u64);
        reserved = reserved.max(align_up(
            start.memmap_paddr.saturating_add(memmap_bytes),
            PAGE_BYTES,
        ));
    }

    min(align_up(reserved, PAGE_BYTES), IDENTITY_MAPPED_LIMIT)
}

const fn align_up(value: u64, align: u64) -> u64 {
    (value + (align - 1)) & !(align - 1)
}

const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}
