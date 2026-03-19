use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use axle_arch_x86_64::debug_break;
use libzircon::handle::ZX_HANDLE_INVALID;
use libzircon::status::ZX_OK;
use libzircon::vmo::{
    ZX_VMO_BACKING_SCOPE_GLOBAL_SHARED, ZX_VMO_BACKING_SCOPE_LOCAL_PRIVATE,
    ZX_VMO_INFO_FLAG_COPY_ON_WRITE, ZX_VMO_INFO_FLAG_KERNEL_READ, ZX_VMO_INFO_FLAG_KERNEL_WRITE,
    ZX_VMO_INFO_FLAG_PAGE_LOAN, ZX_VMO_INFO_FLAG_RESIZABLE, ZX_VMO_KIND_ANONYMOUS,
    ZX_VMO_KIND_PAGER_BACKED, zx_vmo_info_t,
};
use libzircon::{ax_vmo_get_info, zx_handle_close, zx_handle_t, zx_vmo_create};

const USER_SHARED_BASE: u64 = 0x0000_0001_0100_0000;

const SLOT_OK: usize = 0;
const SLOT_SELF_CODE_VMO_H: usize = 506;
const SLOT_VMO_INFO: usize = 1034;
const SLOT_VMO_INFO_KIND: usize = 1035;
const SLOT_VMO_INFO_BACKING_SCOPE: usize = 1036;
const SLOT_VMO_INFO_FLAGS: usize = 1037;
const SLOT_VMO_INFO_SIZE: usize = 1038;
const SLOT_VMO_BOOT_CODE_INFO: usize = 1039;
const SLOT_VMO_BOOT_CODE_KIND: usize = 1040;
const SLOT_VMO_BOOT_CODE_BACKING_SCOPE: usize = 1041;
const SLOT_VMO_BOOT_CODE_FLAGS: usize = 1042;
const SLOT_VMO_BOOT_CODE_SIZE_NONZERO: usize = 1043;
const SLOT_VMO_BOOT_CODE_SIZE: usize = 1044;
const SLOT_VMO_PRESENT: usize = 1045;
const SLOT_VMO_FAILURE_STEP: usize = 1046;

const STEP_PANIC: u64 = u64::MAX;
const STEP_VMO_CREATE: u64 = 1;
const STEP_VMO_INFO: u64 = 2;
const STEP_BOOT_CODE_HANDLE: u64 = 3;
const STEP_BOOT_CODE_INFO: u64 = 4;

const ANON_VMO_SIZE: u64 = 4096;
const HEAP_BYTES: usize = 8 * 1024;
const ANON_EXPECTED_FLAGS: u32 = ZX_VMO_INFO_FLAG_KERNEL_READ
    | ZX_VMO_INFO_FLAG_KERNEL_WRITE
    | ZX_VMO_INFO_FLAG_RESIZABLE
    | ZX_VMO_INFO_FLAG_COPY_ON_WRITE
    | ZX_VMO_INFO_FLAG_PAGE_LOAN;
const BOOT_EXPECTED_FLAGS: u32 = ZX_VMO_INFO_FLAG_KERNEL_READ | ZX_VMO_INFO_FLAG_COPY_ON_WRITE;

#[repr(align(16))]
struct HeapStorage([u8; HEAP_BYTES]);

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);
static mut HEAP: HeapStorage = HeapStorage([0; HEAP_BYTES]);

#[derive(Clone, Copy, Default)]
struct VmoInfoSummary {
    failure_step: u64,
    anon_status: i64,
    anon_kind: u64,
    anon_backing_scope: u64,
    anon_flags: u64,
    anon_size: u64,
    boot_status: i64,
    boot_kind: u64,
    boot_backing_scope: u64,
    boot_flags: u64,
    boot_size_nonzero: u64,
    boot_size: u64,
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
    let summary = run_vmo_info_smoke();
    write_summary(&summary);
    write_slot(SLOT_OK, 1);
    debug_break()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}

pub fn report_panic() -> ! {
    write_slot(SLOT_VMO_PRESENT, 1);
    write_slot(SLOT_VMO_FAILURE_STEP, STEP_PANIC);
    write_slot(SLOT_OK, 1);
    debug_break()
}

fn run_vmo_info_smoke() -> VmoInfoSummary {
    let mut summary = VmoInfoSummary::default();
    let mut anon = ZX_HANDLE_INVALID;
    summary.anon_status = zx_vmo_create(ANON_VMO_SIZE, 0, &mut anon) as i64;
    if summary.anon_status != ZX_OK as i64 {
        summary.failure_step = STEP_VMO_CREATE;
        return summary;
    }

    let mut anon_info = zx_vmo_info_t::default();
    summary.anon_status = ax_vmo_get_info(anon, &mut anon_info) as i64;
    summary.anon_kind = anon_info.kind as u64;
    summary.anon_backing_scope = anon_info.backing_scope as u64;
    summary.anon_flags = anon_info.flags as u64;
    summary.anon_size = anon_info.size_bytes;
    if summary.anon_status != ZX_OK as i64
        || anon_info.kind != ZX_VMO_KIND_ANONYMOUS
        || anon_info.backing_scope != ZX_VMO_BACKING_SCOPE_LOCAL_PRIVATE
        || anon_info.flags != ANON_EXPECTED_FLAGS
        || anon_info.size_bytes != ANON_VMO_SIZE
    {
        summary.failure_step = STEP_VMO_INFO;
        let _ = zx_handle_close(anon);
        return summary;
    }

    let boot_code_vmo = read_slot(SLOT_SELF_CODE_VMO_H) as zx_handle_t;
    if boot_code_vmo == ZX_HANDLE_INVALID {
        summary.failure_step = STEP_BOOT_CODE_HANDLE;
        let _ = zx_handle_close(anon);
        return summary;
    }

    let mut boot_info = zx_vmo_info_t::default();
    summary.boot_status = ax_vmo_get_info(boot_code_vmo, &mut boot_info) as i64;
    summary.boot_kind = boot_info.kind as u64;
    summary.boot_backing_scope = boot_info.backing_scope as u64;
    summary.boot_flags = boot_info.flags as u64;
    summary.boot_size = boot_info.size_bytes;
    summary.boot_size_nonzero = u64::from(boot_info.size_bytes != 0);
    if summary.boot_status != ZX_OK as i64
        || boot_info.kind != ZX_VMO_KIND_PAGER_BACKED
        || boot_info.backing_scope != ZX_VMO_BACKING_SCOPE_GLOBAL_SHARED
        || boot_info.flags != BOOT_EXPECTED_FLAGS
        || boot_info.size_bytes == 0
    {
        summary.failure_step = STEP_BOOT_CODE_INFO;
    }

    let _ = zx_handle_close(anon);
    summary
}

fn write_summary(summary: &VmoInfoSummary) {
    write_slot(SLOT_VMO_PRESENT, 1);
    write_slot(SLOT_VMO_FAILURE_STEP, summary.failure_step);
    write_slot(SLOT_VMO_INFO, summary.anon_status as u64);
    write_slot(SLOT_VMO_INFO_KIND, summary.anon_kind);
    write_slot(SLOT_VMO_INFO_BACKING_SCOPE, summary.anon_backing_scope);
    write_slot(SLOT_VMO_INFO_FLAGS, summary.anon_flags);
    write_slot(SLOT_VMO_INFO_SIZE, summary.anon_size);
    write_slot(SLOT_VMO_BOOT_CODE_INFO, summary.boot_status as u64);
    write_slot(SLOT_VMO_BOOT_CODE_KIND, summary.boot_kind);
    write_slot(SLOT_VMO_BOOT_CODE_BACKING_SCOPE, summary.boot_backing_scope);
    write_slot(SLOT_VMO_BOOT_CODE_FLAGS, summary.boot_flags);
    write_slot(SLOT_VMO_BOOT_CODE_SIZE_NONZERO, summary.boot_size_nonzero);
    write_slot(SLOT_VMO_BOOT_CODE_SIZE, summary.boot_size);
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
