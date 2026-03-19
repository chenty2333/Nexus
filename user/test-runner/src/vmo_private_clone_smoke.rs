use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use axle_arch_x86_64::{debug_break, native_syscall, native_syscall8};
use libzircon::handle::ZX_HANDLE_INVALID;
use libzircon::status::ZX_OK;
use libzircon::syscall_numbers::{AXLE_SYS_VMAR_MAP, AXLE_SYS_VMAR_UNMAP};
use libzircon::vm::{ZX_VM_PERM_READ, ZX_VM_PERM_WRITE, ZX_VM_PRIVATE_CLONE};
use libzircon::vmo::{ZX_VMO_BACKING_SCOPE_GLOBAL_SHARED, ZX_VMO_KIND_PAGER_BACKED, zx_vmo_info_t};
use libzircon::{ax_vmo_get_info, zx_handle_close, zx_handle_t, zx_status_t, zx_vmo_read};

const USER_SHARED_BASE: u64 = 0x0000_0001_0100_0000;
const PAGE_BYTES: u64 = 4096;
const HEAP_BYTES: usize = 8 * 1024;
const PREFIX_BYTES: usize = 16;

const SLOT_OK: usize = 0;
const SLOT_ROOT_VMAR_H: usize = 62;
const SLOT_SELF_CODE_VMO_H: usize = 506;
const SLOT_VMO_PRIVATE_CLONE_PRESENT: usize = 1090;
const SLOT_VMO_PRIVATE_CLONE_FAILURE_STEP: usize = 1091;
const SLOT_VMO_PRIVATE_CLONE_INFO_BEFORE: usize = 1092;
const SLOT_VMO_PRIVATE_CLONE_KIND_BEFORE: usize = 1093;
const SLOT_VMO_PRIVATE_CLONE_SCOPE_BEFORE: usize = 1094;
const SLOT_VMO_PRIVATE_CLONE_SOURCE_READ_BEFORE: usize = 1095;
const SLOT_VMO_PRIVATE_CLONE_MAP: usize = 1096;
const SLOT_VMO_PRIVATE_CLONE_PREFIX_MATCH: usize = 1097;
const SLOT_VMO_PRIVATE_CLONE_WRITE_THROUGH_MAPPING: usize = 1098;
const SLOT_VMO_PRIVATE_CLONE_MAPPING_SEES_PRIVATE: usize = 1099;
const SLOT_VMO_PRIVATE_CLONE_SOURCE_READ_AFTER: usize = 1100;
const SLOT_VMO_PRIVATE_CLONE_SOURCE_UNCHANGED: usize = 1101;
const SLOT_VMO_PRIVATE_CLONE_INFO_AFTER: usize = 1102;
const SLOT_VMO_PRIVATE_CLONE_KIND_AFTER: usize = 1103;
const SLOT_VMO_PRIVATE_CLONE_SCOPE_AFTER: usize = 1104;
const SLOT_VMO_PRIVATE_CLONE_UNMAP: usize = 1105;

const STEP_PANIC: u64 = u64::MAX;
const STEP_SOURCE_INFO_BEFORE: u64 = 1;
const STEP_SOURCE_READ_BEFORE: u64 = 2;
const STEP_MAP_PRIVATE_CLONE: u64 = 3;
const STEP_MAPPING_PREFIX: u64 = 4;
const STEP_MAPPING_WRITE: u64 = 5;
const STEP_SOURCE_READ_AFTER: u64 = 6;
const STEP_SOURCE_INFO_AFTER: u64 = 7;
const STEP_UNMAP: u64 = 8;

#[repr(align(16))]
struct HeapStorage([u8; HEAP_BYTES]);

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);
static mut HEAP: HeapStorage = HeapStorage([0; HEAP_BYTES]);

#[derive(Clone, Copy, Default)]
struct PrivateCloneSummary {
    failure_step: u64,
    info_before_status: i64,
    kind_before: u64,
    scope_before: u64,
    source_read_before_status: i64,
    map_status: i64,
    prefix_match: u64,
    write_through_mapping: u64,
    mapping_sees_private: u64,
    source_read_after_status: i64,
    source_unchanged: u64,
    info_after_status: i64,
    kind_after: u64,
    scope_after: u64,
    unmap_status: i64,
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
    let summary = run_vmo_private_clone_smoke();
    write_summary(&summary);
    write_slot(SLOT_OK, 1);
    debug_break()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}

pub fn report_panic() -> ! {
    write_slot(SLOT_VMO_PRIVATE_CLONE_PRESENT, 1);
    write_slot(SLOT_VMO_PRIVATE_CLONE_FAILURE_STEP, STEP_PANIC);
    write_slot(SLOT_OK, 1);
    debug_break()
}

fn run_vmo_private_clone_smoke() -> PrivateCloneSummary {
    let mut summary = PrivateCloneSummary::default();
    let root_vmar = read_slot(SLOT_ROOT_VMAR_H) as zx_handle_t;
    let source_vmo = read_slot(SLOT_SELF_CODE_VMO_H) as zx_handle_t;
    let mut mapped_addr = 0_u64;

    let mut source_info_before = zx_vmo_info_t::default();
    summary.info_before_status = ax_vmo_get_info(source_vmo, &mut source_info_before) as i64;
    summary.kind_before = source_info_before.kind as u64;
    summary.scope_before = source_info_before.backing_scope as u64;
    if summary.info_before_status != ZX_OK as i64
        || source_info_before.kind != ZX_VMO_KIND_PAGER_BACKED
        || source_info_before.backing_scope != ZX_VMO_BACKING_SCOPE_GLOBAL_SHARED
    {
        summary.failure_step = STEP_SOURCE_INFO_BEFORE;
        return summary;
    }

    let mut source_prefix_before = [0u8; PREFIX_BYTES];
    summary.source_read_before_status =
        zx_vmo_read(source_vmo, &mut source_prefix_before, 0) as i64;
    if summary.source_read_before_status != ZX_OK as i64 {
        summary.failure_step = STEP_SOURCE_READ_BEFORE;
        return summary;
    }

    summary.map_status = zx_vmar_map_local(
        root_vmar,
        ZX_VM_PERM_READ | ZX_VM_PERM_WRITE | ZX_VM_PRIVATE_CLONE,
        0,
        source_vmo,
        0,
        PAGE_BYTES,
        &mut mapped_addr,
    ) as i64;
    if summary.map_status != ZX_OK as i64 {
        summary.failure_step = STEP_MAP_PRIVATE_CLONE;
        return summary;
    }

    let mapping_prefix = unsafe {
        // SAFETY: `mapped_addr` is returned by `zx_vmar_map_local` above for a
        // one-page readable user mapping, and this smoke only reads the first
        // `PREFIX_BYTES` from that mapping before unmapping it.
        core::slice::from_raw_parts(mapped_addr as *const u8, PREFIX_BYTES)
    };
    summary.prefix_match = u64::from(mapping_prefix == source_prefix_before);
    if summary.prefix_match != 1 {
        summary.failure_step = STEP_MAPPING_PREFIX;
        let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, PAGE_BYTES);
        return summary;
    }

    let private_byte = source_prefix_before[0].wrapping_add(1);
    unsafe {
        // SAFETY: `mapped_addr` names a writable user mapping returned by
        // `zx_vmar_map_local`, and this smoke writes one byte at the start of
        // that mapped page before unmapping it.
        ptr::write_volatile(mapped_addr as *mut u8, private_byte);
    }
    summary.write_through_mapping = 1;
    let mapping_private_byte = unsafe {
        // SAFETY: same writable/readable mapping as above; this is one
        // immediate readback from the same byte just written.
        ptr::read_volatile(mapped_addr as *const u8)
    };
    summary.mapping_sees_private = u64::from(mapping_private_byte == private_byte);
    if summary.mapping_sees_private != 1 {
        summary.failure_step = STEP_MAPPING_WRITE;
        let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, PAGE_BYTES);
        return summary;
    }

    let mut source_prefix_after = [0u8; PREFIX_BYTES];
    summary.source_read_after_status = zx_vmo_read(source_vmo, &mut source_prefix_after, 0) as i64;
    summary.source_unchanged = u64::from(source_prefix_after == source_prefix_before);
    if summary.source_read_after_status != ZX_OK as i64 || summary.source_unchanged != 1 {
        summary.failure_step = STEP_SOURCE_READ_AFTER;
        let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, PAGE_BYTES);
        return summary;
    }

    let mut source_info_after = zx_vmo_info_t::default();
    summary.info_after_status = ax_vmo_get_info(source_vmo, &mut source_info_after) as i64;
    summary.kind_after = source_info_after.kind as u64;
    summary.scope_after = source_info_after.backing_scope as u64;
    if summary.info_after_status != ZX_OK as i64
        || source_info_after.kind != ZX_VMO_KIND_PAGER_BACKED
        || source_info_after.backing_scope != ZX_VMO_BACKING_SCOPE_GLOBAL_SHARED
    {
        summary.failure_step = STEP_SOURCE_INFO_AFTER;
        let _ = zx_vmar_unmap_local(root_vmar, mapped_addr, PAGE_BYTES);
        return summary;
    }

    summary.unmap_status = zx_vmar_unmap_local(root_vmar, mapped_addr, PAGE_BYTES) as i64;
    if summary.unmap_status != ZX_OK as i64 {
        summary.failure_step = STEP_UNMAP;
    }

    summary
}

fn zx_vmar_map_local(
    vmar: zx_handle_t,
    options: u32,
    vmar_offset: u64,
    vmo: zx_handle_t,
    vmo_offset: u64,
    len: u64,
    mapped_addr: &mut u64,
) -> zx_status_t {
    native_syscall8(
        AXLE_SYS_VMAR_MAP as u64,
        [
            vmar,
            options as u64,
            vmar_offset,
            vmo,
            vmo_offset,
            len,
            mapped_addr as *mut u64 as u64,
            0,
        ],
    )
}

fn zx_vmar_unmap_local(vmar: zx_handle_t, addr: u64, len: u64) -> zx_status_t {
    native_syscall(AXLE_SYS_VMAR_UNMAP as u64, [vmar, addr, len, 0, 0, 0])
}

fn write_summary(summary: &PrivateCloneSummary) {
    write_slot(SLOT_VMO_PRIVATE_CLONE_PRESENT, 1);
    write_slot(SLOT_VMO_PRIVATE_CLONE_FAILURE_STEP, summary.failure_step);
    write_slot(
        SLOT_VMO_PRIVATE_CLONE_INFO_BEFORE,
        summary.info_before_status as u64,
    );
    write_slot(SLOT_VMO_PRIVATE_CLONE_KIND_BEFORE, summary.kind_before);
    write_slot(SLOT_VMO_PRIVATE_CLONE_SCOPE_BEFORE, summary.scope_before);
    write_slot(
        SLOT_VMO_PRIVATE_CLONE_SOURCE_READ_BEFORE,
        summary.source_read_before_status as u64,
    );
    write_slot(SLOT_VMO_PRIVATE_CLONE_MAP, summary.map_status as u64);
    write_slot(SLOT_VMO_PRIVATE_CLONE_PREFIX_MATCH, summary.prefix_match);
    write_slot(
        SLOT_VMO_PRIVATE_CLONE_WRITE_THROUGH_MAPPING,
        summary.write_through_mapping,
    );
    write_slot(
        SLOT_VMO_PRIVATE_CLONE_MAPPING_SEES_PRIVATE,
        summary.mapping_sees_private,
    );
    write_slot(
        SLOT_VMO_PRIVATE_CLONE_SOURCE_READ_AFTER,
        summary.source_read_after_status as u64,
    );
    write_slot(
        SLOT_VMO_PRIVATE_CLONE_SOURCE_UNCHANGED,
        summary.source_unchanged,
    );
    write_slot(
        SLOT_VMO_PRIVATE_CLONE_INFO_AFTER,
        summary.info_after_status as u64,
    );
    write_slot(SLOT_VMO_PRIVATE_CLONE_KIND_AFTER, summary.kind_after);
    write_slot(SLOT_VMO_PRIVATE_CLONE_SCOPE_AFTER, summary.scope_after);
    write_slot(SLOT_VMO_PRIVATE_CLONE_UNMAP, summary.unmap_status as u64);
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
