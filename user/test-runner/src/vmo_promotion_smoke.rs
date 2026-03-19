use core::alloc::{GlobalAlloc, Layout};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use axle_arch_x86_64::debug_break;
use libzircon::handle::ZX_HANDLE_INVALID;
use libzircon::rights::ZX_RIGHT_SAME_RIGHTS;
use libzircon::signals::{ZX_CHANNEL_PEER_CLOSED, ZX_CHANNEL_READABLE};
use libzircon::status::ZX_OK;
use libzircon::vmo::{
    ZX_VMO_BACKING_SCOPE_GLOBAL_SHARED, ZX_VMO_BACKING_SCOPE_LOCAL_PRIVATE, ZX_VMO_KIND_ANONYMOUS,
    zx_vmo_info_t,
};
use libzircon::{
    ax_process_prepare_start, ax_vmo_get_info, zx_channel_create, zx_channel_read,
    zx_channel_write, zx_handle_close, zx_handle_duplicate, zx_handle_t, zx_object_wait_one,
    zx_process_create, zx_process_start, zx_signals_t, zx_task_kill, zx_thread_create,
    zx_vmo_create,
};

const USER_SHARED_BASE: u64 = 0x0000_0001_0100_0000;
const ANON_VMO_SIZE: u64 = 4096;
const WAIT_TIMEOUT_NS: u64 = 5_000_000_000;
const HEAP_BYTES: usize = 8 * 1024;

const SLOT_OK: usize = 0;
const SLOT_SELF_PROCESS_H: usize = 396;
const SLOT_SELF_CODE_VMO_H: usize = 506;
const SLOT_T0_NS: usize = 511;
const SLOT_VMO_PROMOTION_PRESENT: usize = 1068;
const SLOT_VMO_PROMOTION_FAILURE_STEP: usize = 1069;
const SLOT_VMO_PROMOTION_CREATE: usize = 1070;
const SLOT_VMO_PROMOTION_INFO_BEFORE: usize = 1071;
const SLOT_VMO_PROMOTION_INFO_BEFORE_KIND: usize = 1072;
const SLOT_VMO_PROMOTION_INFO_BEFORE_BACKING_SCOPE: usize = 1073;
const SLOT_VMO_PROMOTION_CHANNEL_CREATE: usize = 1074;
const SLOT_VMO_PROMOTION_PROCESS_CREATE: usize = 1075;
const SLOT_VMO_PROMOTION_THREAD_CREATE: usize = 1076;
const SLOT_VMO_PROMOTION_PREPARE_START: usize = 1077;
const SLOT_VMO_PROMOTION_PROCESS_START: usize = 1078;
const SLOT_VMO_PROMOTION_HANDLE_DUP: usize = 1079;
const SLOT_VMO_PROMOTION_TRANSFER: usize = 1080;
const SLOT_VMO_PROMOTION_WAIT_REPLY: usize = 1081;
const SLOT_VMO_PROMOTION_WAIT_REPLY_OBSERVED: usize = 1082;
const SLOT_VMO_PROMOTION_READ_REPLY: usize = 1083;
const SLOT_VMO_PROMOTION_CHILD_INFO: usize = 1084;
const SLOT_VMO_PROMOTION_CHILD_INFO_KIND: usize = 1085;
const SLOT_VMO_PROMOTION_CHILD_INFO_BACKING_SCOPE: usize = 1086;
const SLOT_VMO_PROMOTION_PARENT_INFO_AFTER: usize = 1087;
const SLOT_VMO_PROMOTION_PARENT_INFO_AFTER_KIND: usize = 1088;
const SLOT_VMO_PROMOTION_PARENT_INFO_AFTER_BACKING_SCOPE: usize = 1089;

const STEP_PANIC: u64 = u64::MAX;
const STEP_VMO_CREATE: u64 = 1;
const STEP_INFO_BEFORE: u64 = 2;
const STEP_CHANNEL_CREATE: u64 = 3;
const STEP_PROCESS_CREATE: u64 = 4;
const STEP_THREAD_CREATE: u64 = 5;
const STEP_PREPARE_START: u64 = 6;
const STEP_PROCESS_START: u64 = 7;
const STEP_HANDLE_DUP: u64 = 8;
const STEP_TRANSFER: u64 = 9;
const STEP_WAIT_REPLY: u64 = 10;
const STEP_READ_REPLY: u64 = 11;
const STEP_CHILD_INFO: u64 = 12;
const STEP_PARENT_INFO_AFTER: u64 = 13;

const CHILD_STATUS_BAD_MESSAGE: i64 = -50;

#[repr(align(16))]
struct HeapStorage([u8; HEAP_BYTES]);

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);
static mut HEAP: HeapStorage = HeapStorage([0; HEAP_BYTES]);

#[derive(Clone, Copy, Default)]
struct VmoPromotionSummary {
    failure_step: u64,
    create_status: i64,
    info_before_status: i64,
    info_before_kind: u64,
    info_before_backing_scope: u64,
    channel_create_status: i64,
    process_create_status: i64,
    thread_create_status: i64,
    prepare_start_status: i64,
    process_start_status: i64,
    handle_dup_status: i64,
    transfer_status: i64,
    wait_reply_status: i64,
    wait_reply_observed: u64,
    read_reply_status: i64,
    child_info_status: i64,
    child_info_kind: u64,
    child_info_backing_scope: u64,
    parent_info_after_status: i64,
    parent_info_after_kind: u64,
    parent_info_after_backing_scope: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ChildReply {
    status: i64,
    kind: u64,
    backing_scope: u64,
}

#[derive(Clone, Copy, Default)]
struct ChildProcess {
    process: zx_handle_t,
    root_vmar: zx_handle_t,
    thread: zx_handle_t,
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
    let summary = run_vmo_promotion_smoke();
    write_summary(&summary);
    write_slot(SLOT_OK, 1);
    debug_break()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}

pub fn report_panic() -> ! {
    write_slot(SLOT_VMO_PROMOTION_PRESENT, 1);
    write_slot(SLOT_VMO_PROMOTION_FAILURE_STEP, STEP_PANIC);
    write_slot(SLOT_OK, 1);
    debug_break()
}

fn run_vmo_promotion_smoke() -> VmoPromotionSummary {
    let mut summary = VmoPromotionSummary::default();
    let self_process = read_slot(SLOT_SELF_PROCESS_H) as zx_handle_t;
    let self_code_vmo = read_slot(SLOT_SELF_CODE_VMO_H) as zx_handle_t;

    let mut anon_vmo = ZX_HANDLE_INVALID;
    let mut parent_channel = ZX_HANDLE_INVALID;
    let mut child_channel = ZX_HANDLE_INVALID;
    let mut child = ChildProcess::default();

    summary.create_status = zx_vmo_create(ANON_VMO_SIZE, 0, &mut anon_vmo) as i64;
    if summary.create_status != ZX_OK as i64 {
        summary.failure_step = STEP_VMO_CREATE;
        return summary;
    }

    let mut info_before = zx_vmo_info_t::default();
    summary.info_before_status = ax_vmo_get_info(anon_vmo, &mut info_before) as i64;
    summary.info_before_kind = info_before.kind as u64;
    summary.info_before_backing_scope = info_before.backing_scope as u64;
    if summary.info_before_status != ZX_OK as i64
        || info_before.kind != ZX_VMO_KIND_ANONYMOUS
        || info_before.backing_scope != ZX_VMO_BACKING_SCOPE_LOCAL_PRIVATE
    {
        summary.failure_step = STEP_INFO_BEFORE;
        close_if_valid(anon_vmo);
        return summary;
    }

    summary.channel_create_status =
        zx_channel_create(0, &mut parent_channel, &mut child_channel) as i64;
    if summary.channel_create_status != ZX_OK as i64 {
        summary.failure_step = STEP_CHANNEL_CREATE;
        close_if_valid(anon_vmo);
        return summary;
    }

    summary.process_create_status =
        zx_process_create(self_process, 0, &mut child.process, &mut child.root_vmar) as i64;
    if summary.process_create_status != ZX_OK as i64 {
        summary.failure_step = STEP_PROCESS_CREATE;
        close_if_valid(parent_channel);
        close_if_valid(child_channel);
        close_if_valid(anon_vmo);
        return summary;
    }

    summary.thread_create_status = zx_thread_create(child.process, 0, &mut child.thread) as i64;
    if summary.thread_create_status != ZX_OK as i64 {
        summary.failure_step = STEP_THREAD_CREATE;
        close_child_process(&child);
        close_if_valid(parent_channel);
        close_if_valid(child_channel);
        close_if_valid(anon_vmo);
        return summary;
    }

    let mut ignored_entry = 0_u64;
    let mut stack = 0_u64;
    summary.prepare_start_status = ax_process_prepare_start(
        child.process,
        self_code_vmo,
        0,
        &mut ignored_entry,
        &mut stack,
    ) as i64;
    if summary.prepare_start_status != ZX_OK as i64 {
        summary.failure_step = STEP_PREPARE_START;
        close_child_process(&child);
        close_if_valid(parent_channel);
        close_if_valid(child_channel);
        close_if_valid(anon_vmo);
        return summary;
    }

    let Some(child_stack) = stack.checked_sub(8) else {
        summary.failure_step = STEP_PREPARE_START;
        summary.prepare_start_status = -40;
        close_child_process(&child);
        close_if_valid(parent_channel);
        close_if_valid(child_channel);
        close_if_valid(anon_vmo);
        return summary;
    };

    summary.process_start_status = zx_process_start(
        child.process,
        child.thread,
        vmo_promotion_child_entry as *const () as usize as u64,
        child_stack,
        child_channel,
        0,
    ) as i64;
    if summary.process_start_status != ZX_OK as i64 {
        summary.failure_step = STEP_PROCESS_START;
        close_child_process(&child);
        close_if_valid(parent_channel);
        close_if_valid(child_channel);
        close_if_valid(anon_vmo);
        return summary;
    }
    child_channel = ZX_HANDLE_INVALID;

    let mut transferred_vmo = ZX_HANDLE_INVALID;
    summary.handle_dup_status =
        zx_handle_duplicate(anon_vmo, ZX_RIGHT_SAME_RIGHTS, &mut transferred_vmo) as i64;
    if summary.handle_dup_status != ZX_OK as i64 {
        summary.failure_step = STEP_HANDLE_DUP;
        let _ = zx_task_kill(child.process);
        close_child_process(&child);
        close_if_valid(parent_channel);
        close_if_valid(anon_vmo);
        return summary;
    }

    summary.transfer_status =
        zx_channel_write(parent_channel, 0, ptr::null(), 0, &transferred_vmo, 1) as i64;
    if summary.transfer_status != ZX_OK as i64 {
        summary.failure_step = STEP_TRANSFER;
        close_if_valid(transferred_vmo);
        let _ = zx_task_kill(child.process);
        close_child_process(&child);
        close_if_valid(parent_channel);
        close_if_valid(anon_vmo);
        return summary;
    }

    let mut observed: zx_signals_t = 0;
    summary.wait_reply_status = zx_object_wait_one(
        parent_channel,
        ZX_CHANNEL_READABLE | ZX_CHANNEL_PEER_CLOSED,
        wait_deadline(),
        &mut observed,
    ) as i64;
    summary.wait_reply_observed = u64::from(observed);
    if summary.wait_reply_status != ZX_OK as i64 || (observed & ZX_CHANNEL_READABLE) == 0 {
        summary.failure_step = STEP_WAIT_REPLY;
        let _ = zx_task_kill(child.process);
        close_child_process(&child);
        close_if_valid(parent_channel);
        close_if_valid(anon_vmo);
        return summary;
    }

    let mut reply = ChildReply::default();
    let mut actual_bytes = 0_u32;
    let mut actual_handles = 0_u32;
    summary.read_reply_status = zx_channel_read(
        parent_channel,
        0,
        (&mut reply as *mut ChildReply).cast::<u8>(),
        ptr::null_mut(),
        size_of::<ChildReply>() as u32,
        0,
        &mut actual_bytes,
        &mut actual_handles,
    ) as i64;
    summary.child_info_status = reply.status;
    summary.child_info_kind = reply.kind;
    summary.child_info_backing_scope = reply.backing_scope;
    if summary.read_reply_status != ZX_OK as i64
        || actual_bytes != size_of::<ChildReply>() as u32
        || actual_handles != 0
    {
        summary.failure_step = STEP_READ_REPLY;
        let _ = zx_task_kill(child.process);
        close_child_process(&child);
        close_if_valid(parent_channel);
        close_if_valid(anon_vmo);
        return summary;
    }
    if summary.child_info_status != ZX_OK as i64
        || summary.child_info_kind != ZX_VMO_KIND_ANONYMOUS as u64
        || summary.child_info_backing_scope != ZX_VMO_BACKING_SCOPE_GLOBAL_SHARED as u64
    {
        summary.failure_step = STEP_CHILD_INFO;
        let _ = zx_task_kill(child.process);
        close_child_process(&child);
        close_if_valid(parent_channel);
        close_if_valid(anon_vmo);
        return summary;
    }

    let mut info_after = zx_vmo_info_t::default();
    summary.parent_info_after_status = ax_vmo_get_info(anon_vmo, &mut info_after) as i64;
    summary.parent_info_after_kind = info_after.kind as u64;
    summary.parent_info_after_backing_scope = info_after.backing_scope as u64;
    if summary.parent_info_after_status != ZX_OK as i64
        || info_after.kind != ZX_VMO_KIND_ANONYMOUS
        || info_after.backing_scope != ZX_VMO_BACKING_SCOPE_GLOBAL_SHARED
    {
        summary.failure_step = STEP_PARENT_INFO_AFTER;
    }

    let _ = zx_task_kill(child.process);
    close_child_process(&child);
    close_if_valid(parent_channel);
    close_if_valid(anon_vmo);
    summary
}

extern "C" fn vmo_promotion_child_entry(channel_handle: u64, _arg1: u64) -> ! {
    let channel = channel_handle as zx_handle_t;
    let reply = run_child(channel);
    let _ = zx_channel_write(
        channel,
        0,
        (&reply as *const ChildReply).cast::<u8>(),
        size_of::<ChildReply>() as u32,
        ptr::null(),
        0,
    );
    close_if_valid(channel);
    loop {
        core::hint::spin_loop();
    }
}

fn run_child(channel: zx_handle_t) -> ChildReply {
    let mut reply = ChildReply::default();
    let mut imported_vmo = ZX_HANDLE_INVALID;
    let mut actual_bytes = 0_u32;
    let mut actual_handles = 0_u32;
    let read_status = zx_channel_read(
        channel,
        0,
        ptr::null_mut(),
        &mut imported_vmo,
        0,
        1,
        &mut actual_bytes,
        &mut actual_handles,
    );
    if read_status != ZX_OK {
        reply.status = read_status as i64;
        return reply;
    }
    if actual_bytes != 0 || actual_handles != 1 {
        reply.status = CHILD_STATUS_BAD_MESSAGE;
        close_if_valid(imported_vmo);
        return reply;
    }

    let mut info = zx_vmo_info_t::default();
    reply.status = ax_vmo_get_info(imported_vmo, &mut info) as i64;
    reply.kind = info.kind as u64;
    reply.backing_scope = info.backing_scope as u64;
    close_if_valid(imported_vmo);
    reply
}

fn write_summary(summary: &VmoPromotionSummary) {
    write_slot(SLOT_VMO_PROMOTION_PRESENT, 1);
    write_slot(SLOT_VMO_PROMOTION_FAILURE_STEP, summary.failure_step);
    write_slot(SLOT_VMO_PROMOTION_CREATE, summary.create_status as u64);
    write_slot(
        SLOT_VMO_PROMOTION_INFO_BEFORE,
        summary.info_before_status as u64,
    );
    write_slot(
        SLOT_VMO_PROMOTION_INFO_BEFORE_KIND,
        summary.info_before_kind,
    );
    write_slot(
        SLOT_VMO_PROMOTION_INFO_BEFORE_BACKING_SCOPE,
        summary.info_before_backing_scope,
    );
    write_slot(
        SLOT_VMO_PROMOTION_CHANNEL_CREATE,
        summary.channel_create_status as u64,
    );
    write_slot(
        SLOT_VMO_PROMOTION_PROCESS_CREATE,
        summary.process_create_status as u64,
    );
    write_slot(
        SLOT_VMO_PROMOTION_THREAD_CREATE,
        summary.thread_create_status as u64,
    );
    write_slot(
        SLOT_VMO_PROMOTION_PREPARE_START,
        summary.prepare_start_status as u64,
    );
    write_slot(
        SLOT_VMO_PROMOTION_PROCESS_START,
        summary.process_start_status as u64,
    );
    write_slot(
        SLOT_VMO_PROMOTION_HANDLE_DUP,
        summary.handle_dup_status as u64,
    );
    write_slot(SLOT_VMO_PROMOTION_TRANSFER, summary.transfer_status as u64);
    write_slot(
        SLOT_VMO_PROMOTION_WAIT_REPLY,
        summary.wait_reply_status as u64,
    );
    write_slot(
        SLOT_VMO_PROMOTION_WAIT_REPLY_OBSERVED,
        summary.wait_reply_observed,
    );
    write_slot(
        SLOT_VMO_PROMOTION_READ_REPLY,
        summary.read_reply_status as u64,
    );
    write_slot(
        SLOT_VMO_PROMOTION_CHILD_INFO,
        summary.child_info_status as u64,
    );
    write_slot(SLOT_VMO_PROMOTION_CHILD_INFO_KIND, summary.child_info_kind);
    write_slot(
        SLOT_VMO_PROMOTION_CHILD_INFO_BACKING_SCOPE,
        summary.child_info_backing_scope,
    );
    write_slot(
        SLOT_VMO_PROMOTION_PARENT_INFO_AFTER,
        summary.parent_info_after_status as u64,
    );
    write_slot(
        SLOT_VMO_PROMOTION_PARENT_INFO_AFTER_KIND,
        summary.parent_info_after_kind,
    );
    write_slot(
        SLOT_VMO_PROMOTION_PARENT_INFO_AFTER_BACKING_SCOPE,
        summary.parent_info_after_backing_scope,
    );
}

fn wait_deadline() -> i64 {
    let deadline = read_slot(SLOT_T0_NS).saturating_add(WAIT_TIMEOUT_NS);
    deadline.min(i64::MAX as u64) as i64
}

fn close_child_process(child: &ChildProcess) {
    close_if_valid(child.thread);
    close_if_valid(child.root_vmar);
    close_if_valid(child.process);
}

fn close_if_valid(handle: zx_handle_t) {
    if handle != ZX_HANDLE_INVALID {
        let _ = zx_handle_close(handle);
    }
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
