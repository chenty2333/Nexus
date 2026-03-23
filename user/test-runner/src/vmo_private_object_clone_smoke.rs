use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use axle_arch_x86_64::debug_break;
use libzircon::handle::ZX_HANDLE_INVALID;
use libzircon::rights::{ZX_RIGHT_MAP, ZX_RIGHT_READ, ZX_RIGHT_WRITE};
use libzircon::status::ZX_OK;
use libzircon::vmo::{
    ZX_VMO_BACKING_SCOPE_GLOBAL_SHARED, ZX_VMO_BACKING_SCOPE_LOCAL_PRIVATE, ZX_VMO_KIND_ANONYMOUS,
    ZX_VMO_KIND_PAGER_BACKED, zx_vmo_info_t,
};
use libzircon::{
    ax_vmo_create_private_clone, ax_vmo_get_info, zx_handle_close, zx_handle_t, zx_vmo_read,
    zx_vmo_set_size, zx_vmo_write,
};

const USER_SHARED_BASE: u64 = 0x0000_0001_0100_0000;
const SLOT_OK: usize = 0;
const SLOT_SELF_CODE_VMO_H: usize = 506;

const SLOT_VMO_PRIVATE_OBJECT_PRESENT: usize = 1121;
const SLOT_VMO_PRIVATE_OBJECT_FAILURE_STEP: usize = 1122;
const SLOT_VMO_PRIVATE_OBJECT_SOURCE_INFO: usize = 1123;
const SLOT_VMO_PRIVATE_OBJECT_CLONE_CREATE: usize = 1124;
const SLOT_VMO_PRIVATE_OBJECT_CLONE_INFO: usize = 1125;
const SLOT_VMO_PRIVATE_OBJECT_PREFIX_MATCH: usize = 1126;
const SLOT_VMO_PRIVATE_OBJECT_CLONE_WRITE: usize = 1127;
const SLOT_VMO_PRIVATE_OBJECT_CLONE_READ_AFTER: usize = 1128;
const SLOT_VMO_PRIVATE_OBJECT_SOURCE_UNCHANGED: usize = 1129;
const SLOT_VMO_PRIVATE_OBJECT_CLONE_RESIZE: usize = 1130;
const SLOT_VMO_PRIVATE_OBJECT_CLONE_SIZE_AFTER: usize = 1131;

const STEP_PANIC: u64 = u64::MAX;
const STEP_SOURCE_HANDLE: u64 = 1;
const STEP_SOURCE_INFO: u64 = 2;
const STEP_CLONE_CREATE: u64 = 3;
const STEP_CLONE_INFO: u64 = 4;
const STEP_PREFIX_MATCH: u64 = 5;
const STEP_CLONE_WRITE: u64 = 6;
const STEP_CLONE_READ_AFTER: u64 = 7;
const STEP_SOURCE_UNCHANGED: u64 = 8;
const STEP_CLONE_RESIZE: u64 = 9;

const PAGE_BYTES: u64 = 4096;
const PREFIX_BYTES: usize = 16;
const HEAP_BYTES: usize = 8 * 1024;

#[repr(align(16))]
struct HeapStorage([u8; HEAP_BYTES]);

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);
static mut HEAP: HeapStorage = HeapStorage([0; HEAP_BYTES]);

#[derive(Clone, Copy, Default)]
struct PrivateObjectCloneSummary {
    failure_step: u64,
    source_info_status: i64,
    clone_create_status: i64,
    clone_info_status: i64,
    prefix_match: u64,
    clone_write_status: i64,
    clone_read_after_match: u64,
    source_unchanged: u64,
    clone_resize_status: i64,
    clone_size_after: u64,
}

// SAFETY: this allocator serves one bootstrap test process, returns unique
// non-overlapping aligned ranges from one static buffer, and never reuses
// freed memory.
unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align_mask = layout.align().saturating_sub(1);
        let size = layout.size();
        let mut current = HEAP_NEXT.load(Ordering::Relaxed);

        loop {
            let aligned = (current + align_mask) & !align_mask;
            let Some(next) = aligned.checked_add(size) else {
                return ptr::null_mut();
            };
            if next > HEAP_BYTES {
                return ptr::null_mut();
            }
            match HEAP_NEXT.compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // SAFETY: each successful bump returns a unique region
                    // inside the dedicated static heap for this bootstrap
                    // binary.
                    let base = unsafe { ptr::addr_of_mut!(HEAP.0).cast::<u8>() as usize };
                    return (base + aligned) as *mut u8;
                }
                Err(observed) => current = observed,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_start() -> ! {
    let summary = run_vmo_private_object_clone_smoke();
    write_summary(&summary);
    write_slot(SLOT_OK, 1);
    debug_break()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}

pub fn report_panic() -> ! {
    write_slot(SLOT_VMO_PRIVATE_OBJECT_PRESENT, 1);
    write_slot(SLOT_VMO_PRIVATE_OBJECT_FAILURE_STEP, STEP_PANIC);
    write_slot(SLOT_OK, 1);
    debug_break()
}

fn run_vmo_private_object_clone_smoke() -> PrivateObjectCloneSummary {
    let mut summary = PrivateObjectCloneSummary::default();
    let source = read_slot(SLOT_SELF_CODE_VMO_H) as zx_handle_t;
    if source == ZX_HANDLE_INVALID {
        summary.failure_step = STEP_SOURCE_HANDLE;
        return summary;
    }

    let mut source_info = zx_vmo_info_t::default();
    summary.source_info_status = ax_vmo_get_info(source, &mut source_info) as i64;
    if summary.source_info_status != ZX_OK as i64
        || source_info.kind != ZX_VMO_KIND_PAGER_BACKED
        || source_info.backing_scope != ZX_VMO_BACKING_SCOPE_GLOBAL_SHARED
        || (source_info.rights & ZX_RIGHT_READ) == 0
        || (source_info.rights & ZX_RIGHT_MAP) == 0
        || (source_info.rights & ZX_RIGHT_WRITE) != 0
    {
        summary.failure_step = STEP_SOURCE_INFO;
        return summary;
    }

    let mut clone = ZX_HANDLE_INVALID;
    summary.clone_create_status = ax_vmo_create_private_clone(source, &mut clone) as i64;
    if summary.clone_create_status != ZX_OK as i64 || clone == ZX_HANDLE_INVALID {
        summary.failure_step = STEP_CLONE_CREATE;
        return summary;
    }

    let mut clone_info = zx_vmo_info_t::default();
    summary.clone_info_status = ax_vmo_get_info(clone, &mut clone_info) as i64;
    if summary.clone_info_status != ZX_OK as i64
        || clone_info.kind != ZX_VMO_KIND_ANONYMOUS
        || clone_info.backing_scope != ZX_VMO_BACKING_SCOPE_LOCAL_PRIVATE
        || (clone_info.rights & ZX_RIGHT_READ) == 0
        || (clone_info.rights & ZX_RIGHT_MAP) == 0
        || (clone_info.rights & ZX_RIGHT_WRITE) == 0
    {
        summary.failure_step = STEP_CLONE_INFO;
        let _ = zx_handle_close(clone);
        return summary;
    }

    let mut source_before = [0u8; PREFIX_BYTES];
    let mut clone_before = [0u8; PREFIX_BYTES];
    if zx_vmo_read(source, &mut source_before, 0) != ZX_OK
        || zx_vmo_read(clone, &mut clone_before, 0) != ZX_OK
    {
        summary.failure_step = STEP_PREFIX_MATCH;
        let _ = zx_handle_close(clone);
        return summary;
    }
    summary.prefix_match = u64::from(source_before == clone_before);
    if summary.prefix_match != 1 {
        summary.failure_step = STEP_PREFIX_MATCH;
        let _ = zx_handle_close(clone);
        return summary;
    }

    summary.clone_write_status = zx_vmo_write(clone, b"Z", 0) as i64;
    if summary.clone_write_status != ZX_OK as i64 {
        summary.failure_step = STEP_CLONE_WRITE;
        let _ = zx_handle_close(clone);
        return summary;
    }

    let mut clone_after = [0u8; PREFIX_BYTES];
    if zx_vmo_read(clone, &mut clone_after, 0) != ZX_OK {
        summary.failure_step = STEP_CLONE_READ_AFTER;
        let _ = zx_handle_close(clone);
        return summary;
    }
    summary.clone_read_after_match =
        u64::from(clone_after[0] == b'Z' && clone_after[1..] == clone_before[1..]);
    if summary.clone_read_after_match != 1 {
        summary.failure_step = STEP_CLONE_READ_AFTER;
        let _ = zx_handle_close(clone);
        return summary;
    }

    let mut source_after = [0u8; PREFIX_BYTES];
    if zx_vmo_read(source, &mut source_after, 0) != ZX_OK {
        summary.failure_step = STEP_SOURCE_UNCHANGED;
        let _ = zx_handle_close(clone);
        return summary;
    }
    summary.source_unchanged = u64::from(source_after == source_before);
    if summary.source_unchanged != 1 {
        summary.failure_step = STEP_SOURCE_UNCHANGED;
        let _ = zx_handle_close(clone);
        return summary;
    }

    summary.clone_resize_status =
        zx_vmo_set_size(clone, clone_info.size_bytes.saturating_add(PAGE_BYTES)) as i64;
    let expected_size_after = clone_info.size_bytes.saturating_add(PAGE_BYTES);
    if summary.clone_resize_status != ZX_OK as i64 {
        summary.failure_step = STEP_CLONE_RESIZE;
        let _ = zx_handle_close(clone);
        return summary;
    }
    if ax_vmo_get_info(clone, &mut clone_info) != ZX_OK {
        summary.failure_step = STEP_CLONE_RESIZE;
        let _ = zx_handle_close(clone);
        return summary;
    }
    summary.clone_size_after = clone_info.size_bytes;
    if clone_info.size_bytes != expected_size_after {
        summary.failure_step = STEP_CLONE_RESIZE;
    }

    let _ = zx_handle_close(clone);
    summary
}

fn write_summary(summary: &PrivateObjectCloneSummary) {
    write_slot(SLOT_VMO_PRIVATE_OBJECT_PRESENT, 1);
    write_slot(SLOT_VMO_PRIVATE_OBJECT_FAILURE_STEP, summary.failure_step);
    write_slot(
        SLOT_VMO_PRIVATE_OBJECT_SOURCE_INFO,
        summary.source_info_status as u64,
    );
    write_slot(
        SLOT_VMO_PRIVATE_OBJECT_CLONE_CREATE,
        summary.clone_create_status as u64,
    );
    write_slot(
        SLOT_VMO_PRIVATE_OBJECT_CLONE_INFO,
        summary.clone_info_status as u64,
    );
    write_slot(SLOT_VMO_PRIVATE_OBJECT_PREFIX_MATCH, summary.prefix_match);
    write_slot(
        SLOT_VMO_PRIVATE_OBJECT_CLONE_WRITE,
        summary.clone_write_status as u64,
    );
    write_slot(
        SLOT_VMO_PRIVATE_OBJECT_CLONE_READ_AFTER,
        summary.clone_read_after_match,
    );
    write_slot(
        SLOT_VMO_PRIVATE_OBJECT_SOURCE_UNCHANGED,
        summary.source_unchanged,
    );
    write_slot(
        SLOT_VMO_PRIVATE_OBJECT_CLONE_RESIZE,
        summary.clone_resize_status as u64,
    );
    write_slot(
        SLOT_VMO_PRIVATE_OBJECT_CLONE_SIZE_AFTER,
        summary.clone_size_after,
    );
}

fn read_slot(slot: usize) -> u64 {
    let ptr = (USER_SHARED_BASE as *const u64).wrapping_add(slot);
    unsafe {
        // SAFETY: the kernel maps the bootstrap shared summary window at
        // `USER_SHARED_BASE` for the runner process for the entire lifetime of
        // this smoke binary.
        core::ptr::read_volatile(ptr)
    }
}

fn write_slot(slot: usize, value: u64) {
    let ptr = (USER_SHARED_BASE as *mut u64).wrapping_add(slot);
    unsafe {
        // SAFETY: the kernel maps the bootstrap shared summary window at
        // `USER_SHARED_BASE` for the runner process for the entire lifetime of
        // this smoke binary.
        core::ptr::write_volatile(ptr, value);
    }
}
