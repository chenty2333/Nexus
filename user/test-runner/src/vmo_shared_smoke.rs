use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use axle_arch_x86_64::debug_break;
use libzircon::handle::ZX_HANDLE_INVALID;
use libzircon::status::{ZX_ERR_ACCESS_DENIED, ZX_OK};
use libzircon::{zx_handle_t, zx_vmo_read, zx_vmo_set_size, zx_vmo_write};

const USER_SHARED_BASE: u64 = 0x0000_0001_0100_0000;
const USER_CODE_VA: u64 = 0x0000_0001_0000_0000;
const PAGE_SIZE: u64 = 4096;
const CODE_PREFIX_BYTES: usize = 16;
const HEAP_BYTES: usize = 8 * 1024;

const SLOT_OK: usize = 0;
const SLOT_SELF_CODE_VMO_H: usize = 506;
const SLOT_SELF_CODE_VMO_SIZE: usize = 510;
const SLOT_VMO_SHARED_PRESENT: usize = 1047;
const SLOT_VMO_SHARED_FAILURE_STEP: usize = 1048;
const SLOT_VMO_SHARED_READ: usize = 1049;
const SLOT_VMO_SHARED_READ_MATCH: usize = 1050;
const SLOT_VMO_SHARED_WRITE: usize = 1051;
const SLOT_VMO_SHARED_RESIZE: usize = 1052;

const STEP_PANIC: u64 = u64::MAX;
const STEP_BOOT_CODE_HANDLE: u64 = 1;
const STEP_BOOT_CODE_SIZE: u64 = 2;
const STEP_BOOT_CODE_READ: u64 = 3;
const STEP_BOOT_CODE_WRITE: u64 = 4;
const STEP_BOOT_CODE_RESIZE: u64 = 5;

#[repr(align(16))]
struct HeapStorage([u8; HEAP_BYTES]);

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);
static mut HEAP: HeapStorage = HeapStorage([0; HEAP_BYTES]);

#[derive(Clone, Copy, Default)]
struct SharedVmoSummary {
    failure_step: u64,
    read_status: i64,
    read_match: u64,
    write_status: i64,
    resize_status: i64,
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
    let summary = run_vmo_shared_smoke();
    write_summary(&summary);
    write_slot(SLOT_OK, 1);
    debug_break()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}

pub fn report_panic() -> ! {
    write_slot(SLOT_VMO_SHARED_PRESENT, 1);
    write_slot(SLOT_VMO_SHARED_FAILURE_STEP, STEP_PANIC);
    write_slot(SLOT_OK, 1);
    debug_break()
}

fn run_vmo_shared_smoke() -> SharedVmoSummary {
    let mut summary = SharedVmoSummary::default();
    let boot_code_vmo = read_slot(SLOT_SELF_CODE_VMO_H) as zx_handle_t;
    if boot_code_vmo == ZX_HANDLE_INVALID {
        summary.failure_step = STEP_BOOT_CODE_HANDLE;
        return summary;
    }
    let boot_code_size = read_slot(SLOT_SELF_CODE_VMO_SIZE);
    if boot_code_size == 0 {
        summary.failure_step = STEP_BOOT_CODE_SIZE;
        return summary;
    }

    let mut prefix = [0u8; CODE_PREFIX_BYTES];
    summary.read_status = zx_vmo_read(boot_code_vmo, &mut prefix, 0) as i64;
    let mapped_prefix = unsafe {
        // SAFETY: the bootstrap runner's code image is mapped at the fixed
        // `USER_CODE_VA` window for the lifetime of this process, and this
        // smoke only reads one small prefix from that mapping.
        core::slice::from_raw_parts(USER_CODE_VA as *const u8, CODE_PREFIX_BYTES)
    };
    summary.read_match = u64::from(prefix == mapped_prefix);
    if summary.read_status != ZX_OK as i64 || summary.read_match == 0 {
        summary.failure_step = STEP_BOOT_CODE_READ;
        return summary;
    }

    summary.write_status = zx_vmo_write(boot_code_vmo, &[0], 0) as i64;
    if summary.write_status != ZX_ERR_ACCESS_DENIED as i64 {
        summary.failure_step = STEP_BOOT_CODE_WRITE;
        return summary;
    }

    summary.resize_status = zx_vmo_set_size(boot_code_vmo, boot_code_size + PAGE_SIZE) as i64;
    if summary.resize_status != ZX_ERR_ACCESS_DENIED as i64 {
        summary.failure_step = STEP_BOOT_CODE_RESIZE;
    }

    summary
}

fn write_summary(summary: &SharedVmoSummary) {
    write_slot(SLOT_VMO_SHARED_PRESENT, 1);
    write_slot(SLOT_VMO_SHARED_FAILURE_STEP, summary.failure_step);
    write_slot(SLOT_VMO_SHARED_READ, summary.read_status as u64);
    write_slot(SLOT_VMO_SHARED_READ_MATCH, summary.read_match);
    write_slot(SLOT_VMO_SHARED_WRITE, summary.write_status as u64);
    write_slot(SLOT_VMO_SHARED_RESIZE, summary.resize_status as u64);
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
