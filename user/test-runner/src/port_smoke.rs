use core::alloc::{GlobalAlloc, Layout};
use core::fmt;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use axle_arch_x86_64::debug_break;
use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::packet::{ZX_PKT_TYPE_SIGNAL_ONE, ZX_PKT_TYPE_USER};
use axle_types::signals::ZX_USER_SIGNAL_0;
use axle_types::status::{ZX_ERR_SHOULD_WAIT, ZX_OK};
use axle_types::{zx_handle_t, zx_packet_signal_t, zx_port_info_t};
use libzircon::{
    ax_console_write, ax_port_get_info, zx_eventpair_create, zx_handle_close,
    zx_object_signal_peer, zx_object_wait_async, zx_port_create, zx_port_packet_t, zx_port_queue,
    zx_port_wait,
};

const USER_SHARED_BASE: u64 = 0x0000_0001_0100_0000;
const SLOT_OK: usize = 0;
const HEAP_BYTES: usize = 8 * 1024;

const STEP_PANIC: u64 = u64::MAX;
const STEP_CREATE: u64 = 1;
const STEP_FILL_USER: u64 = 2;
const STEP_USER_FULL: u64 = 3;
const STEP_FILLER_CREATE: u64 = 4;
const STEP_FILLER_ARM: u64 = 5;
const STEP_FILLER_SIGNAL: u64 = 6;
const STEP_TARGET_CREATE: u64 = 7;
const STEP_TARGET_ARM: u64 = 8;
const STEP_TARGET_SIGNAL_FIRST: u64 = 9;
const STEP_TARGET_SIGNAL_SECOND: u64 = 10;
const STEP_INFO_BEFORE: u64 = 11;
const STEP_POP_AND_FLUSH: u64 = 12;
const STEP_INFO_AFTER: u64 = 13;
const STEP_DRAIN: u64 = 14;
const STEP_LAST_PACKET: u64 = 15;

const FILLER_COUNT: usize = 16;
const USER_FILL_COUNT: usize = 48;
const TARGET_KEY: u64 = 0xfeed_cafe;

#[derive(Clone, Copy, Default)]
struct PortSummary {
    failure_step: u64,
    create: i64,
    user_fill_status: i64,
    user_full_wait: i64,
    filler_create: i64,
    filler_arm: i64,
    filler_signal: i64,
    target_create: i64,
    target_arm: i64,
    target_signal_first: i64,
    target_signal_second: i64,
    pop_flush: i64,
    last_packet_ok: u64,
    last_packet_count: u64,
    capacity: u32,
    kernel_reserve: u32,
    peak_depth_before: u32,
    current_depth_before: u32,
    pending_current_before: u32,
    pending_peak_before: u32,
    pending_new_before: u64,
    pending_merge_before: u64,
    pending_flush_before: u64,
    user_queue_count_before: u64,
    user_should_wait_before: u64,
    user_reserve_hits_before: u64,
    kernel_queue_count_after: u64,
    kernel_should_wait_after: u64,
    pending_current_after: u32,
    pending_peak_after: u32,
    pending_new_after: u64,
    pending_merge_after: u64,
    pending_flush_after: u64,
    depth_p50_after: u32,
    depth_p90_after: u32,
    depth_p99_after: u32,
    pop_count_after: u64,
    final_current_depth: u32,
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

// SAFETY: this allocator is only used by the bootstrap port smoke. It monotonically carves
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
    let summary = run_port_smoke();
    emit_summary(&summary);
    write_slot(SLOT_OK, 1);
    debug_break()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}

pub fn report_panic() -> ! {
    let summary = PortSummary {
        failure_step: STEP_PANIC,
        ..PortSummary::default()
    };
    emit_summary(&summary);
    write_slot(SLOT_OK, 1);
    debug_break()
}

fn run_port_smoke() -> PortSummary {
    let mut summary = PortSummary::default();
    let mut port = ZX_HANDLE_INVALID;
    summary.create = zx_port_create(0, &mut port) as i64;
    if summary.create != ZX_OK as i64 {
        summary.failure_step = STEP_CREATE;
        return summary;
    }

    for idx in 0..USER_FILL_COUNT {
        let packet = zx_port_packet_t {
            key: idx as u64,
            type_: ZX_PKT_TYPE_USER,
            status: ZX_OK,
            user: Default::default(),
        };
        summary.user_fill_status = zx_port_queue(port, &packet) as i64;
        if summary.user_fill_status != ZX_OK as i64 {
            summary.failure_step = STEP_FILL_USER;
            let _ = zx_handle_close(port);
            return summary;
        }
    }

    let packet = zx_port_packet_t {
        key: 0xdead_beef,
        type_: ZX_PKT_TYPE_USER,
        status: ZX_OK,
        user: Default::default(),
    };
    summary.user_full_wait = zx_port_queue(port, &packet) as i64;
    if summary.user_full_wait != ZX_ERR_SHOULD_WAIT as i64 {
        summary.failure_step = STEP_USER_FULL;
        let _ = zx_handle_close(port);
        return summary;
    }

    let mut filler_left = [ZX_HANDLE_INVALID; FILLER_COUNT];
    let mut filler_right = [ZX_HANDLE_INVALID; FILLER_COUNT];
    for index in 0..FILLER_COUNT {
        summary.filler_create =
            zx_eventpair_create(0, &mut filler_left[index], &mut filler_right[index]) as i64;
        if summary.filler_create != ZX_OK as i64 {
            summary.failure_step = STEP_FILLER_CREATE;
            close_pairs(&filler_left, &filler_right);
            let _ = zx_handle_close(port);
            return summary;
        }
        summary.filler_arm = zx_object_wait_async(
            filler_left[index],
            port,
            0x1000 + index as u64,
            ZX_USER_SIGNAL_0,
            0,
        ) as i64;
        if summary.filler_arm != ZX_OK as i64 {
            summary.failure_step = STEP_FILLER_ARM;
            close_pairs(&filler_left, &filler_right);
            let _ = zx_handle_close(port);
            return summary;
        }
        summary.filler_signal =
            zx_object_signal_peer(filler_right[index], 0, ZX_USER_SIGNAL_0) as i64;
        if summary.filler_signal != ZX_OK as i64 {
            summary.failure_step = STEP_FILLER_SIGNAL;
            close_pairs(&filler_left, &filler_right);
            let _ = zx_handle_close(port);
            return summary;
        }
    }

    let mut target_left = ZX_HANDLE_INVALID;
    let mut target_right = ZX_HANDLE_INVALID;
    summary.target_create = zx_eventpair_create(0, &mut target_left, &mut target_right) as i64;
    if summary.target_create != ZX_OK as i64 {
        summary.failure_step = STEP_TARGET_CREATE;
        close_pairs(&filler_left, &filler_right);
        let _ = zx_handle_close(port);
        return summary;
    }
    summary.target_arm =
        zx_object_wait_async(target_left, port, TARGET_KEY, ZX_USER_SIGNAL_0, 0) as i64;
    if summary.target_arm != ZX_OK as i64 {
        summary.failure_step = STEP_TARGET_ARM;
        let _ = zx_handle_close(target_left);
        let _ = zx_handle_close(target_right);
        close_pairs(&filler_left, &filler_right);
        let _ = zx_handle_close(port);
        return summary;
    }
    summary.target_signal_first = zx_object_signal_peer(target_right, 0, ZX_USER_SIGNAL_0) as i64;
    if summary.target_signal_first != ZX_OK as i64 {
        summary.failure_step = STEP_TARGET_SIGNAL_FIRST;
        let _ = zx_handle_close(target_left);
        let _ = zx_handle_close(target_right);
        close_pairs(&filler_left, &filler_right);
        let _ = zx_handle_close(port);
        return summary;
    }
    summary.target_signal_second = zx_object_signal_peer(target_right, 0, ZX_USER_SIGNAL_0) as i64;
    if summary.target_signal_second != ZX_OK as i64 {
        summary.failure_step = STEP_TARGET_SIGNAL_SECOND;
        let _ = zx_handle_close(target_left);
        let _ = zx_handle_close(target_right);
        close_pairs(&filler_left, &filler_right);
        let _ = zx_handle_close(port);
        return summary;
    }

    let mut info_before = zx_port_info_t::default();
    let status = ax_port_get_info(port, &mut info_before);
    if status != ZX_OK {
        summary.failure_step = STEP_INFO_BEFORE;
        let _ = zx_handle_close(target_left);
        let _ = zx_handle_close(target_right);
        close_pairs(&filler_left, &filler_right);
        let _ = zx_handle_close(port);
        return summary;
    }
    summary.capacity = info_before.capacity;
    summary.kernel_reserve = info_before.kernel_reserve;
    summary.peak_depth_before = info_before.peak_depth;
    summary.current_depth_before = info_before.current_depth;
    summary.pending_current_before = info_before.pending_current;
    summary.pending_peak_before = info_before.pending_peak;
    summary.pending_new_before = info_before.pending_new_count;
    summary.pending_merge_before = info_before.pending_merge_count;
    summary.pending_flush_before = info_before.pending_flush_delivered_count;
    summary.user_queue_count_before = info_before.user_queue_count;
    summary.user_should_wait_before = info_before.user_should_wait_count;
    summary.user_reserve_hits_before = info_before.user_reserve_hit_count;

    let mut first = zx_port_packet_t::default();
    summary.pop_flush = zx_port_wait(port, 0, &mut first) as i64;
    if summary.pop_flush != ZX_OK as i64 {
        summary.failure_step = STEP_POP_AND_FLUSH;
        let _ = zx_handle_close(target_left);
        let _ = zx_handle_close(target_right);
        close_pairs(&filler_left, &filler_right);
        let _ = zx_handle_close(port);
        return summary;
    }

    let mut info_after = zx_port_info_t::default();
    let status = ax_port_get_info(port, &mut info_after);
    if status != ZX_OK {
        summary.failure_step = STEP_INFO_AFTER;
        let _ = zx_handle_close(target_left);
        let _ = zx_handle_close(target_right);
        close_pairs(&filler_left, &filler_right);
        let _ = zx_handle_close(port);
        return summary;
    }
    summary.kernel_queue_count_after = info_after.kernel_queue_count;
    summary.kernel_should_wait_after = info_after.kernel_should_wait_count;
    summary.pending_current_after = info_after.pending_current;
    summary.pending_peak_after = info_after.pending_peak;
    summary.pending_new_after = info_after.pending_new_count;
    summary.pending_merge_after = info_after.pending_merge_count;
    summary.pending_flush_after = info_after.pending_flush_delivered_count;
    summary.depth_p50_after = info_after.depth_p50;
    summary.depth_p90_after = info_after.depth_p90;
    summary.depth_p99_after = info_after.depth_p99;
    summary.pop_count_after = info_after.pop_count;

    let mut last = zx_port_packet_t::default();
    for _ in 0..64 {
        let status = zx_port_wait(port, 0, &mut last);
        if status != ZX_OK {
            summary.failure_step = STEP_DRAIN;
            let _ = zx_handle_close(target_left);
            let _ = zx_handle_close(target_right);
            close_pairs(&filler_left, &filler_right);
            let _ = zx_handle_close(port);
            return summary;
        }
    }
    if last.type_ == ZX_PKT_TYPE_SIGNAL_ONE && last.key == TARGET_KEY {
        let signal = zx_packet_signal_t::from_user(last.user);
        summary.last_packet_ok = 1;
        summary.last_packet_count = signal.count;
    } else {
        summary.failure_step = STEP_LAST_PACKET;
    }

    let mut final_info = zx_port_info_t::default();
    if ax_port_get_info(port, &mut final_info) == ZX_OK {
        summary.final_current_depth = final_info.current_depth;
    }

    let _ = zx_handle_close(target_left);
    let _ = zx_handle_close(target_right);
    close_pairs(&filler_left, &filler_right);
    let _ = zx_handle_close(port);
    summary
}

fn close_pairs(left: &[zx_handle_t], right: &[zx_handle_t]) {
    for &handle in left {
        if handle != ZX_HANDLE_INVALID {
            let _ = zx_handle_close(handle);
        }
    }
    for &handle in right {
        if handle != ZX_HANDLE_INVALID {
            let _ = zx_handle_close(handle);
        }
    }
}

fn emit_summary(summary: &PortSummary) {
    let mut line = FixedBuf::<1024>::new();
    let _ = fmt::write(
        &mut line,
        format_args!(
            "kernel: port telemetry smoke (port_present=1, port_failure_step={}, create={}, user_fill_status={}, user_full_wait={}, filler_create={}, filler_arm={}, filler_signal={}, target_create={}, target_arm={}, target_signal_first={}, target_signal_second={}, pop_flush={}, last_packet_ok={}, last_packet_count={}, port_capacity={}, port_kernel_reserve={}, peak_depth_before={}, current_depth_before={}, pending_current_before={}, pending_peak_before={}, pending_new_before={}, pending_merge_before={}, pending_flush_before={}, user_queue_count_before={}, user_should_wait_before={}, user_reserve_hits_before={}, kernel_queue_count_after={}, kernel_should_wait_after={}, pending_current_after={}, pending_peak_after={}, pending_new_after={}, pending_merge_after={}, pending_flush_after={}, depth_p50_after={}, depth_p90_after={}, depth_p99_after={}, pop_count_after={}, final_current_depth={})\n",
            summary.failure_step,
            summary.create,
            summary.user_fill_status,
            summary.user_full_wait,
            summary.filler_create,
            summary.filler_arm,
            summary.filler_signal,
            summary.target_create,
            summary.target_arm,
            summary.target_signal_first,
            summary.target_signal_second,
            summary.pop_flush,
            summary.last_packet_ok,
            summary.last_packet_count,
            summary.capacity,
            summary.kernel_reserve,
            summary.peak_depth_before,
            summary.current_depth_before,
            summary.pending_current_before,
            summary.pending_peak_before,
            summary.pending_new_before,
            summary.pending_merge_before,
            summary.pending_flush_before,
            summary.user_queue_count_before,
            summary.user_should_wait_before,
            summary.user_reserve_hits_before,
            summary.kernel_queue_count_after,
            summary.kernel_should_wait_after,
            summary.pending_current_after,
            summary.pending_peak_after,
            summary.pending_new_after,
            summary.pending_merge_after,
            summary.pending_flush_after,
            summary.depth_p50_after,
            summary.depth_p90_after,
            summary.depth_p99_after,
            summary.pop_count_after,
            summary.final_current_depth,
        ),
    );
    let mut actual = 0usize;
    let _ = ax_console_write(line.as_bytes(), &mut actual);
}

fn write_slot(slot: usize, value: u64) {
    let ptr = (USER_SHARED_BASE as *mut u64).wrapping_add(slot);
    // SAFETY: the bootstrap runner ABI reserves the shared summary page range at USER_SHARED_BASE.
    unsafe { ptr::write_volatile(ptr, value) };
}
