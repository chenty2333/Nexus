use core::alloc::{GlobalAlloc, Layout};
use core::fmt;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use axle_arch_x86_64::debug_break;
use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::rights::{
    ZX_RIGHT_DUPLICATE, ZX_RIGHT_INSPECT, ZX_RIGHT_SAME_RIGHTS, ZX_RIGHT_SIGNAL,
    ZX_RIGHT_SIGNAL_PEER, ZX_RIGHT_TRANSFER,
};
use axle_types::signals::{ZX_TASK_TERMINATED, ZX_USER_SIGNAL_0};
use axle_types::status::{ZX_ERR_ACCESS_DENIED, ZX_OK};
use axle_types::{zx_handle_t, zx_job_info_t};
use libzircon::{
    ax_console_write, ax_job_create, ax_job_get_info, ax_job_set_policy, ax_process_get_job,
    zx_eventpair_create, zx_handle_close, zx_handle_duplicate, zx_object_wait_one,
    zx_process_create, zx_task_kill,
};

const USER_SHARED_BASE: u64 = 0x0000_0001_0100_0000;
const SLOT_OK: usize = 0;
const SLOT_SELF_PROCESS_H: usize = 396;
const HEAP_BYTES: usize = 8 * 1024;

const STEP_PANIC: u64 = u64::MAX;
const STEP_ROOT_JOB: u64 = 1;
const STEP_ROOT_INFO: u64 = 2;
const STEP_CHILD_JOB: u64 = 3;
const STEP_CHILD_INFO_BEFORE: u64 = 4;
const STEP_CHILD_PROCESS_CREATE: u64 = 5;
const STEP_CHILD_JOB_FROM_PROCESS: u64 = 6;
const STEP_CHILD_INFO_AFTER: u64 = 7;
const STEP_KILL_JOB: u64 = 8;
const STEP_WAIT_KILLED_PROCESS: u64 = 9;
const STEP_POLICY_SET: u64 = 10;
const STEP_EVENTPAIR_CREATE: u64 = 11;
const STEP_POLICY_DUP: u64 = 12;
const STEP_POLICY_WAIT_DENIED: u64 = 13;

#[derive(Clone, Copy, Default)]
struct JobSummary {
    failure_step: u64,
    root_job: i64,
    root_info: i64,
    root_job_id: u64,
    root_child_jobs_before: u32,
    child_job: i64,
    child_info_before: i64,
    child_job_id: u64,
    child_parent_koid: u64,
    child_process_create: i64,
    child_job_from_process: i64,
    child_job_same: u64,
    child_info_after: i64,
    child_process_count_after: u32,
    kill_job: i64,
    wait_killed_process: i64,
    wait_killed_observed: u32,
    policy_set: i64,
    eventpair_create: i64,
    policy_dup: i64,
    policy_wait_denied: i64,
}

#[repr(align(16))]
struct HeapStorage([u8; HEAP_BYTES]);

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);
static mut HEAP: HeapStorage = HeapStorage([0; HEAP_BYTES]);

struct FixedBuf<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> FixedBuf<N> {
    const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl<const N: usize> fmt::Write for FixedBuf<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        if self.len.saturating_add(bytes.len()) > N {
            return Err(fmt::Error);
        }
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

// SAFETY: this allocator is only used by the bootstrap job smoke. It monotonically carves
// aligned, non-overlapping ranges out of one fixed static heap and never reuses freed memory.
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
                    // SAFETY: each successful bump allocation hands out a unique region within
                    // the dedicated static heap backing this single bootstrap binary.
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
    let summary = run_job_smoke();
    emit_summary(&summary);
    write_slot(SLOT_OK, 1);
    debug_break()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}

pub fn report_panic() -> ! {
    let summary = JobSummary {
        failure_step: STEP_PANIC,
        ..JobSummary::default()
    };
    emit_summary(&summary);
    write_slot(SLOT_OK, 1);
    debug_break()
}

fn run_job_smoke() -> JobSummary {
    let mut summary = JobSummary::default();
    let self_process = read_slot(SLOT_SELF_PROCESS_H) as zx_handle_t;

    let mut root_job = ZX_HANDLE_INVALID;
    summary.root_job = ax_process_get_job(self_process, &mut root_job) as i64;
    if summary.root_job != ZX_OK as i64 {
        summary.failure_step = STEP_ROOT_JOB;
        return summary;
    }

    let mut root_info = zx_job_info_t::default();
    summary.root_info = ax_job_get_info(root_job, &mut root_info) as i64;
    if summary.root_info != ZX_OK as i64 {
        summary.failure_step = STEP_ROOT_INFO;
        close_handles(&[root_job]);
        return summary;
    }
    summary.root_job_id = root_info.job_id;
    summary.root_child_jobs_before = root_info.child_job_count;

    let mut child_job = ZX_HANDLE_INVALID;
    summary.child_job = ax_job_create(root_job, 0, &mut child_job) as i64;
    if summary.child_job != ZX_OK as i64 {
        summary.failure_step = STEP_CHILD_JOB;
        close_handles(&[root_job]);
        return summary;
    }

    let mut child_info = zx_job_info_t::default();
    summary.child_info_before = ax_job_get_info(child_job, &mut child_info) as i64;
    if summary.child_info_before != ZX_OK as i64 {
        summary.failure_step = STEP_CHILD_INFO_BEFORE;
        close_handles(&[root_job, child_job]);
        return summary;
    }
    summary.child_job_id = child_info.job_id;
    summary.child_parent_koid = child_info.parent_koid;

    let mut child_process = ZX_HANDLE_INVALID;
    let mut child_root_vmar = ZX_HANDLE_INVALID;
    summary.child_process_create =
        zx_process_create(child_job, 0, &mut child_process, &mut child_root_vmar) as i64;
    if summary.child_process_create != ZX_OK as i64 {
        summary.failure_step = STEP_CHILD_PROCESS_CREATE;
        close_handles(&[root_job, child_job]);
        return summary;
    }

    let mut child_job_from_process = ZX_HANDLE_INVALID;
    summary.child_job_from_process =
        ax_process_get_job(child_process, &mut child_job_from_process) as i64;
    summary.child_job_same = u64::from(child_job_from_process != ZX_HANDLE_INVALID);
    if summary.child_job_from_process != ZX_OK as i64 {
        summary.failure_step = STEP_CHILD_JOB_FROM_PROCESS;
        close_handles(&[root_job, child_job, child_process, child_root_vmar]);
        return summary;
    }
    let mut child_info_again = zx_job_info_t::default();
    summary.child_info_after =
        ax_job_get_info(child_job_from_process, &mut child_info_again) as i64;
    if summary.child_info_after != ZX_OK as i64 {
        summary.failure_step = STEP_CHILD_INFO_AFTER;
        close_handles(&[
            root_job,
            child_job,
            child_process,
            child_root_vmar,
            child_job_from_process,
        ]);
        return summary;
    }
    summary.child_process_count_after = child_info_again.child_process_count;
    summary.child_job_same = u64::from(child_info_again.job_id == summary.child_job_id);

    summary.kill_job = zx_task_kill(child_job) as i64;
    if summary.kill_job != ZX_OK as i64 {
        summary.failure_step = STEP_KILL_JOB;
        close_handles(&[
            root_job,
            child_job,
            child_process,
            child_root_vmar,
            child_job_from_process,
        ]);
        return summary;
    }

    let mut observed = 0u32;
    summary.wait_killed_process =
        zx_object_wait_one(child_process, ZX_TASK_TERMINATED, 0, &mut observed) as i64;
    summary.wait_killed_observed = observed;
    if summary.wait_killed_process != ZX_OK as i64 {
        summary.failure_step = STEP_WAIT_KILLED_PROCESS;
        close_handles(&[
            root_job,
            child_job,
            child_process,
            child_root_vmar,
            child_job_from_process,
        ]);
        return summary;
    }

    let rights_ceiling = ZX_RIGHT_DUPLICATE
        | ZX_RIGHT_TRANSFER
        | ZX_RIGHT_SIGNAL
        | ZX_RIGHT_SIGNAL_PEER
        | ZX_RIGHT_INSPECT;
    summary.policy_set = ax_job_set_policy(root_job, rights_ceiling) as i64;
    if summary.policy_set != ZX_OK as i64 {
        summary.failure_step = STEP_POLICY_SET;
        close_handles(&[
            root_job,
            child_job,
            child_process,
            child_root_vmar,
            child_job_from_process,
        ]);
        return summary;
    }

    let mut left = ZX_HANDLE_INVALID;
    let mut right = ZX_HANDLE_INVALID;
    summary.eventpair_create = zx_eventpair_create(0, &mut left, &mut right) as i64;
    if summary.eventpair_create != ZX_OK as i64 {
        summary.failure_step = STEP_EVENTPAIR_CREATE;
        close_handles(&[
            root_job,
            child_job,
            child_process,
            child_root_vmar,
            child_job_from_process,
        ]);
        return summary;
    }

    let mut capped = ZX_HANDLE_INVALID;
    summary.policy_dup = zx_handle_duplicate(left, ZX_RIGHT_SAME_RIGHTS, &mut capped) as i64;
    if summary.policy_dup != ZX_OK as i64 {
        summary.failure_step = STEP_POLICY_DUP;
        close_handles(&[
            root_job,
            child_job,
            child_process,
            child_root_vmar,
            child_job_from_process,
            left,
            right,
            capped,
        ]);
        return summary;
    }

    observed = 0;
    summary.policy_wait_denied =
        zx_object_wait_one(capped, ZX_USER_SIGNAL_0, 0, &mut observed) as i64;
    if summary.policy_wait_denied != ZX_ERR_ACCESS_DENIED as i64 {
        summary.failure_step = STEP_POLICY_WAIT_DENIED;
    }

    close_handles(&[
        root_job,
        child_job,
        child_process,
        child_root_vmar,
        child_job_from_process,
        left,
        right,
        capped,
    ]);
    summary
}

fn close_handles(handles: &[zx_handle_t]) {
    for &handle in handles {
        if handle != ZX_HANDLE_INVALID {
            let _ = zx_handle_close(handle);
        }
    }
}

fn emit_summary(summary: &JobSummary) {
    let mut line = FixedBuf::<1024>::new();
    let _ = fmt::write(
        &mut line,
        format_args!(
            "kernel: job smoke (job_present=1, job_failure_step={}, root_job={}, root_info={}, root_job_id={}, root_child_jobs_before={}, child_job={}, child_info_before={}, child_job_id={}, child_parent_koid={}, child_process_create={}, child_job_from_process={}, child_job_same={}, child_info_after={}, child_process_count_after={}, kill_job={}, wait_killed_process={}, wait_killed_observed={}, policy_set={}, eventpair_create={}, policy_dup={}, policy_wait_denied={})\n",
            summary.failure_step,
            summary.root_job,
            summary.root_info,
            summary.root_job_id,
            summary.root_child_jobs_before,
            summary.child_job,
            summary.child_info_before,
            summary.child_job_id,
            summary.child_parent_koid,
            summary.child_process_create,
            summary.child_job_from_process,
            summary.child_job_same,
            summary.child_info_after,
            summary.child_process_count_after,
            summary.kill_job,
            summary.wait_killed_process,
            summary.wait_killed_observed,
            summary.policy_set,
            summary.eventpair_create,
            summary.policy_dup,
            summary.policy_wait_denied,
        ),
    );
    let mut actual = 0usize;
    let _ = ax_console_write(line.as_bytes(), &mut actual);
}

fn read_slot(slot: usize) -> u64 {
    let ptr = (USER_SHARED_BASE as *const u64).wrapping_add(slot);
    // SAFETY: the bootstrap runner ABI reserves the shared summary page range at USER_SHARED_BASE.
    unsafe { ptr::read_volatile(ptr) }
}

fn write_slot(slot: usize, value: u64) {
    let ptr = (USER_SHARED_BASE as *mut u64).wrapping_add(slot);
    // SAFETY: the bootstrap runner ABI reserves the shared summary page range at USER_SHARED_BASE.
    unsafe { ptr::write_volatile(ptr, value) };
}
