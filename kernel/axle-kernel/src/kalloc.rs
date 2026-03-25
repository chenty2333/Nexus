//! Minimal bump allocator for early bring-up.
//!
//! This is intentionally simple and temporary. It enables `alloc` users
//! (CSpace/object tables) before a real PMM-backed allocator is integrated.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use heapless::Vec;
use spin::Mutex;

const HEAP_SIZE: usize = 8 * 1024 * 1024; // 8 MiB bootstrap heap.
const LATE_HEAP_INITIAL_PAGES: usize = 256; // 1 MiB.
const LATE_HEAP_GROW_PAGES: usize = 64; // 256 KiB.
const MAX_LATE_ARENAS: usize = 64;
const MAX_LATE_FREE_RANGES: usize = 1024;

// ── Per-CPU slab allocator constants ────────────────────────────────────────
const SLAB_SIZES: [usize; 5] = [32, 64, 128, 256, 512];
const SLAB_FREE_LIST_CAP: usize = 128;
const SLAB_BACKING_PAGES: usize = 4; // 16 KiB per slab backing allocation

static NEXT: Mutex<usize> = Mutex::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOC_FAIL_COUNT: AtomicUsize = AtomicUsize::new(0);
static LATE_HEAP_ENABLED: AtomicBool = AtomicBool::new(false);

// ── Per-CPU slab cache types ────────────────────────────────────────────────

struct SlabFreeList {
    entries: [usize; SLAB_FREE_LIST_CAP], // pointers stored as usize
    count: usize,
}

impl SlabFreeList {
    const fn new() -> Self {
        Self {
            entries: [0; SLAB_FREE_LIST_CAP],
            count: 0,
        }
    }

    fn pop(&mut self) -> Option<*mut u8> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(self.entries[self.count] as *mut u8)
    }

    fn push(&mut self, ptr: *mut u8) -> bool {
        if self.count >= SLAB_FREE_LIST_CAP {
            return false;
        }
        self.entries[self.count] = ptr as usize;
        self.count += 1;
        true
    }
}

struct PerCpuSlabs {
    caches: [SlabFreeList; 5], // one per SLAB_SIZES entry
}

impl PerCpuSlabs {
    const fn new() -> Self {
        Self {
            caches: [
                SlabFreeList::new(),
                SlabFreeList::new(),
                SlabFreeList::new(),
                SlabFreeList::new(),
                SlabFreeList::new(),
            ],
        }
    }
}

const MAX_CPUS: usize = crate::arch::MAX_CPUS;
static PER_CPU_SLABS: [Mutex<PerCpuSlabs>; MAX_CPUS] =
    [const { Mutex::new(PerCpuSlabs::new()) }; MAX_CPUS];

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

pub(crate) fn bootstrap_heap_region() -> (u64, u64) {
    let base = core::ptr::addr_of!(HEAP) as u64;
    (base, base + HEAP_SIZE as u64)
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LateHeapStats {
    pub(crate) arena_bytes: usize,
    pub(crate) free_bytes: usize,
    pub(crate) peak_used_bytes: usize,
    pub(crate) alloc_fail_count: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct HeapRange {
    base: usize,
    len: usize,
}

impl HeapRange {
    const fn end(self) -> usize {
        self.base + self.len
    }
}

#[derive(Debug)]
struct LateHeap {
    initialized: bool,
    arenas: Vec<HeapRange, MAX_LATE_ARENAS>,
    free: Vec<HeapRange, MAX_LATE_FREE_RANGES>,
    arena_bytes: usize,
    free_bytes: usize,
    peak_used_bytes: usize,
    alloc_fail_count: usize,
}

impl LateHeap {
    const fn new() -> Self {
        Self {
            initialized: false,
            arenas: Vec::new(),
            free: Vec::new(),
            arena_bytes: 0,
            free_bytes: 0,
            peak_used_bytes: 0,
            alloc_fail_count: 0,
        }
    }

    fn init(&mut self, arena_base: usize, arena_len: usize) -> bool {
        if self.initialized {
            return true;
        }
        if !self.add_arena(arena_base, arena_len) {
            self.alloc_fail_count = self.alloc_fail_count.saturating_add(1);
            return false;
        }
        self.initialized = true;
        true
    }

    fn alloc(&mut self, layout: Layout) -> Option<*mut u8> {
        let size = layout.size().max(1);
        for index in 0..self.free.len() {
            let range = self.free[index];
            let start = align_up(range.base, layout.align());
            let end = start.checked_add(size)?;
            if end > range.end() {
                continue;
            }

            let left = start - range.base;
            let right = range.end() - end;
            self.free.remove(index);
            if right != 0 {
                if self
                    .free
                    .insert(
                        index,
                        HeapRange {
                            base: end,
                            len: right,
                        },
                    )
                    .is_err()
                {
                    self.alloc_fail_count = self.alloc_fail_count.saturating_add(1);
                    let _ = self.insert_free_range(range);
                    return None;
                }
            }
            if left != 0 {
                if self
                    .free
                    .insert(
                        index,
                        HeapRange {
                            base: range.base,
                            len: left,
                        },
                    )
                    .is_err()
                {
                    self.alloc_fail_count = self.alloc_fail_count.saturating_add(1);
                    // Remove the already-inserted right fragment before restoring
                    // the original range to avoid overlapping entries.
                    if right != 0 {
                        // The right fragment is at position `index` since we just
                        // failed to insert left before it.
                        self.free.remove(index);
                    }
                    let _ = self.insert_free_range(range);
                    return None;
                }
            }

            self.free_bytes = self.free_bytes.saturating_sub(size);
            self.peak_used_bytes = self.peak_used_bytes.max(self.arena_bytes - self.free_bytes);
            return Some(start as *mut u8);
        }
        self.alloc_fail_count = self.alloc_fail_count.saturating_add(1);
        None
    }

    fn dealloc(&mut self, ptr: *mut u8, layout: Layout) {
        let size = layout.size().max(1);
        let base = ptr as usize;
        let _ = self.insert_free_range(HeapRange { base, len: size });
        self.free_bytes = self.free_bytes.saturating_add(size).min(self.arena_bytes);
    }

    fn add_arena(&mut self, arena_base: usize, arena_len: usize) -> bool {
        let arena = HeapRange {
            base: arena_base,
            len: arena_len,
        };
        if self.arenas.push(arena).is_err() {
            return false;
        }
        if self.insert_free_range(arena).is_err() {
            let _ = self.arenas.pop();
            return false;
        }
        self.arena_bytes = self.arena_bytes.saturating_add(arena_len);
        self.free_bytes = self.free_bytes.saturating_add(arena_len);
        true
    }

    fn contains(&self, ptr: *mut u8) -> bool {
        let addr = ptr as usize;
        self.arenas
            .iter()
            .copied()
            .any(|arena| addr >= arena.base && addr < arena.end())
    }

    fn stats(&self) -> LateHeapStats {
        LateHeapStats {
            arena_bytes: self.arena_bytes,
            free_bytes: self.free_bytes,
            peak_used_bytes: self.peak_used_bytes,
            alloc_fail_count: self.alloc_fail_count,
        }
    }

    fn insert_free_range(&mut self, mut range: HeapRange) -> Result<(), ()> {
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
                range.len = prev.end().max(range.end()) - range.base;
                self.free.remove(insert_at - 1);
                insert_at -= 1;
            }
        }

        while insert_at < self.free.len() {
            let next = self.free[insert_at];
            if next.base > range.end() {
                break;
            }
            range.base = range.base.min(next.base);
            range.len = next.end().max(range.end()) - range.base;
            self.free.remove(insert_at);
        }

        self.free.insert(insert_at, range).map_err(|_| ())
    }
}

static LATE_HEAP: Mutex<LateHeap> = Mutex::new(LateHeap::new());

pub(crate) fn late_heap_stats() -> LateHeapStats {
    LATE_HEAP.lock().stats()
}

pub(crate) fn init_late_heap() {
    if LATE_HEAP_ENABLED.load(Ordering::Acquire) {
        return;
    }

    let arena_base = crate::pmm::alloc_pages(LATE_HEAP_INITIAL_PAGES)
        .expect("kalloc: failed to allocate initial PMM-backed late heap arena");
    let arena_len =
        usize::try_from(crate::userspace::USER_PAGE_BYTES * LATE_HEAP_INITIAL_PAGES as u64)
            .expect("kalloc: late heap arena length overflow");

    let mut heap = LATE_HEAP.lock();
    assert!(
        heap.init(arena_base as usize, arena_len),
        "kalloc: failed to initialize late heap metadata"
    );
    LATE_HEAP_ENABLED.store(true, Ordering::Release);
}

#[global_allocator]
static GLOBAL_ALLOCATOR: BootstrapAllocator = BootstrapAllocator;

const fn align_up(v: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (v + (align - 1)) & !(align - 1)
}

// ── Slab allocator helpers ──────────────────────────────────────────────────

/// Returns the slab class index for a given size, or `None` if too large or
/// alignment exceeds the class size.
fn slab_class_for(size: usize, align: usize) -> Option<usize> {
    for (i, &class_size) in SLAB_SIZES.iter().enumerate() {
        if size <= class_size && align <= class_size {
            return Some(i);
        }
    }
    None
}

/// Slabs depend on the PMM being available for backing pages.
fn slab_enabled() -> bool {
    LATE_HEAP_ENABLED.load(Ordering::Relaxed)
}

fn current_cpu_index() -> usize {
    crate::arch::x86_64::percpu::try_current_cpu_slot().unwrap_or(0) % MAX_CPUS
}

/// Try the per-CPU slab cache first; on a miss allocate a new backing slab
/// from the PMM, carve it into objects, and return the first one.
fn slab_alloc(class_idx: usize) -> Option<*mut u8> {
    let cpu = current_cpu_index();

    // Fast path: pop from per-CPU cache.
    {
        let mut slabs = PER_CPU_SLABS[cpu].lock();
        if let Some(ptr) = slabs.caches[class_idx].pop() {
            return Some(ptr);
        }
    }

    // Cache miss: allocate a new slab backing from PMM and carve it up.
    let class_size = SLAB_SIZES[class_idx];
    let backing_bytes = SLAB_BACKING_PAGES * 4096;
    let paddr = crate::pmm::alloc_pages(SLAB_BACKING_PAGES)?;
    let base = paddr as *mut u8;

    // Zero the backing (security).
    unsafe {
        core::ptr::write_bytes(base, 0, backing_bytes);
    }

    let obj_count = backing_bytes / class_size;

    // Return first object, push the rest into the cache.
    let result = base;
    {
        let mut slabs = PER_CPU_SLABS[cpu].lock();
        for i in 1..obj_count {
            let ptr = unsafe { base.add(i * class_size) };
            if !slabs.caches[class_idx].push(ptr) {
                break; // cache full
            }
        }
    }
    Some(result)
}

/// Return an object to the per-CPU slab cache.  If the cache is full the
/// object is silently dropped (acceptable loss — the backing is still live).
fn slab_dealloc(ptr: *mut u8, class_idx: usize) {
    let cpu = current_cpu_index();
    let mut slabs = PER_CPU_SLABS[cpu].lock();
    let _ = slabs.caches[class_idx].push(ptr);
}

unsafe impl GlobalAlloc for BootstrapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Fast path: per-CPU slab for small, naturally-aligned allocations.
        if slab_enabled() {
            if let Some(class_idx) = slab_class_for(layout.size(), layout.align()) {
                if let Some(ptr) = slab_alloc(class_idx) {
                    return ptr;
                }
            }
        }

        if LATE_HEAP_ENABLED.load(Ordering::Acquire) {
            if let Some(ptr) = alloc_from_late_heap(layout) {
                return ptr;
            }
        }

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

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Fast path: return small objects to the per-CPU slab cache, but only
        // if the pointer did NOT originate from the late heap.  Without this
        // check a late-heap pointer whose size happens to match a slab class
        // would be pushed onto the slab free-list, corrupting both allocators.
        if slab_enabled() {
            if let Some(class_idx) = slab_class_for(layout.size(), layout.align()) {
                let in_late_heap =
                    LATE_HEAP_ENABLED.load(Ordering::Acquire) && LATE_HEAP.lock().contains(ptr);
                if !in_late_heap {
                    slab_dealloc(ptr, class_idx);
                    return;
                }
            }
        }

        if !LATE_HEAP_ENABLED.load(Ordering::Acquire) {
            return;
        }

        let mut heap = LATE_HEAP.lock();
        if heap.contains(ptr) {
            heap.dealloc(ptr, layout);
        }
    }
}

fn alloc_from_late_heap(layout: Layout) -> Option<*mut u8> {
    {
        let mut heap = LATE_HEAP.lock();
        if let Some(ptr) = heap.alloc(layout) {
            return Some(ptr);
        }
    }

    let min_bytes = layout
        .size()
        .max(crate::userspace::USER_PAGE_BYTES as usize * LATE_HEAP_GROW_PAGES);
    let page_bytes = crate::userspace::USER_PAGE_BYTES as usize;
    let grow_pages = (min_bytes + (page_bytes - 1)) / page_bytes;
    let arena_base = crate::pmm::alloc_pages(grow_pages)?;
    let arena_len = page_bytes.checked_mul(grow_pages)?;

    let mut heap = LATE_HEAP.lock();
    if !heap.add_arena(arena_base as usize, arena_len) {
        crate::pmm::free_pages(arena_base, grow_pages);
        heap.alloc_fail_count = heap.alloc_fail_count.saturating_add(1);
        return None;
    }
    heap.alloc(layout)
}
