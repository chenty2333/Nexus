use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use axle_arch_x86_64::debug_break;
use axle_types::signals::{ZX_SOCKET_PEER_CLOSED, ZX_SOCKET_READABLE, ZX_SOCKET_WRITABLE};
use axle_types::socket::{ZX_SOCKET_DATAGRAM, ZX_SOCKET_PEEK};
use axle_types::status::{ZX_ERR_PEER_CLOSED, ZX_ERR_SHOULD_WAIT, ZX_OK};
use libzircon::handle::ZX_HANDLE_INVALID;
use libzircon::{
    zx_handle_close, zx_handle_t, zx_object_wait_one, zx_signals_t, zx_socket_create,
    zx_socket_read, zx_socket_write,
};

const USER_SHARED_BASE: u64 = 0x0000_0001_0100_0000;
const SLOT_OK: usize = 0;
const SLOT_T0_NS: usize = 511;

const SLOT_DGRAM_PRESENT: usize = 954;
const SLOT_DGRAM_FAILURE_STEP: usize = 955;
const SLOT_DGRAM_CREATE: usize = 956;
const SLOT_DGRAM_WAIT_WRITABLE: usize = 957;
const SLOT_DGRAM_WRITE_FIRST: usize = 958;
const SLOT_DGRAM_WAIT_READABLE: usize = 959;
const SLOT_DGRAM_PEEK: usize = 960;
const SLOT_DGRAM_PEEK_ACTUAL: usize = 961;
const SLOT_DGRAM_PEEK_MATCH: usize = 962;
const SLOT_DGRAM_READ_FIRST: usize = 963;
const SLOT_DGRAM_READ_FIRST_ACTUAL: usize = 964;
const SLOT_DGRAM_READ_FIRST_MATCH: usize = 965;
const SLOT_DGRAM_WRITE_TRUNC: usize = 966;
const SLOT_DGRAM_READ_TRUNC: usize = 967;
const SLOT_DGRAM_READ_TRUNC_ACTUAL: usize = 968;
const SLOT_DGRAM_READ_TRUNC_PREFIX: usize = 969;
const SLOT_DGRAM_READ_AFTER_TRUNC: usize = 970;
const SLOT_DGRAM_FILL_SHOULD_WAIT: usize = 971;
const SLOT_DGRAM_DRAIN_AFTER_FILL: usize = 972;
const SLOT_DGRAM_WRITE_RECOVER: usize = 973;
const SLOT_DGRAM_CLOSE_LEFT: usize = 974;
const SLOT_DGRAM_WAIT_PEER_CLOSED: usize = 975;
const SLOT_DGRAM_WAIT_PEER_CLOSED_OBSERVED: usize = 976;
const SLOT_DGRAM_WRITE_PEER_CLOSED: usize = 977;

const STEP_PANIC: u64 = u64::MAX;
const STEP_CREATE: u64 = 1;
const STEP_WAIT_WRITABLE: u64 = 2;
const STEP_WRITE_FIRST: u64 = 3;
const STEP_WAIT_READABLE: u64 = 4;
const STEP_PEEK: u64 = 5;
const STEP_READ_FIRST: u64 = 6;
const STEP_WRITE_TRUNC: u64 = 7;
const STEP_READ_TRUNC: u64 = 8;
const STEP_READ_AFTER_TRUNC: u64 = 9;
const STEP_FILL: u64 = 10;
const STEP_DRAIN_AFTER_FILL: u64 = 11;
const STEP_WRITE_RECOVER: u64 = 12;
const STEP_CLOSE_LEFT: u64 = 13;
const STEP_WAIT_PEER_CLOSED: u64 = 14;
const STEP_WRITE_PEER_CLOSED: u64 = 15;

const WAIT_TIMEOUT_NS: u64 = 5_000_000_000;
const FIRST_PAYLOAD: &[u8] = b"axle-dgram-first";
const TRUNC_PAYLOAD: &[u8] = b"axle-dgram-truncate-payload";
const FILL_PACKET_BYTES: usize = 1024;
const HEAP_BYTES: usize = 8 * 1024;

#[repr(align(16))]
struct HeapStorage([u8; HEAP_BYTES]);

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);
static mut HEAP: HeapStorage = HeapStorage([0; HEAP_BYTES]);

#[derive(Clone, Copy, Default)]
struct DatagramSummary {
    failure_step: u64,
    create: i64,
    wait_writable: i64,
    write_first: i64,
    wait_readable: i64,
    peek: i64,
    peek_actual: u64,
    peek_match: u64,
    read_first: i64,
    read_first_actual: u64,
    read_first_match: u64,
    write_trunc: i64,
    read_trunc: i64,
    read_trunc_actual: u64,
    read_trunc_prefix: u64,
    read_after_trunc: i64,
    fill_should_wait: i64,
    drain_after_fill: u64,
    write_recover: i64,
    close_left: i64,
    wait_peer_closed: i64,
    wait_peer_closed_observed: u64,
    write_peer_closed: i64,
}

// SAFETY: this allocator is only used by the bootstrap datagram smoke. It monotonically carves
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
    let summary = run_datagram_smoke();
    write_summary(&summary);
    write_slot(SLOT_OK, 1);
    debug_break()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}

pub fn report_panic() -> ! {
    write_slot(SLOT_DGRAM_PRESENT, 1);
    write_slot(SLOT_DGRAM_FAILURE_STEP, STEP_PANIC);
    write_slot(SLOT_OK, 1);
    debug_break()
}

fn run_datagram_smoke() -> DatagramSummary {
    let mut summary = DatagramSummary::default();
    let mut left = ZX_HANDLE_INVALID;
    let mut right = ZX_HANDLE_INVALID;
    let mut observed: zx_signals_t = 0;

    summary.create = zx_socket_create(ZX_SOCKET_DATAGRAM, &mut left, &mut right) as i64;
    if summary.create != ZX_OK as i64 {
        summary.failure_step = STEP_CREATE;
        return summary;
    }

    summary.wait_writable =
        zx_object_wait_one(left, ZX_SOCKET_WRITABLE, wait_deadline(), &mut observed) as i64;
    if summary.wait_writable != ZX_OK as i64 {
        summary.failure_step = STEP_WAIT_WRITABLE;
        close_pair(left, right);
        return summary;
    }

    let mut actual = 0usize;
    summary.write_first = zx_socket_write(
        left,
        0,
        FIRST_PAYLOAD.as_ptr(),
        FIRST_PAYLOAD.len(),
        &mut actual,
    ) as i64;
    if summary.write_first != ZX_OK as i64 || actual != FIRST_PAYLOAD.len() {
        summary.failure_step = STEP_WRITE_FIRST;
        close_pair(left, right);
        return summary;
    }

    observed = 0;
    summary.wait_readable =
        zx_object_wait_one(right, ZX_SOCKET_READABLE, wait_deadline(), &mut observed) as i64;
    if summary.wait_readable != ZX_OK as i64 {
        summary.failure_step = STEP_WAIT_READABLE;
        close_pair(left, right);
        return summary;
    }

    let mut first_buf = [0u8; FIRST_PAYLOAD.len()];
    actual = 0;
    summary.peek = zx_socket_read(
        right,
        ZX_SOCKET_PEEK,
        first_buf.as_mut_ptr(),
        first_buf.len(),
        &mut actual,
    ) as i64;
    summary.peek_actual = actual as u64;
    summary.peek_match = u64::from(actual == FIRST_PAYLOAD.len() && first_buf == FIRST_PAYLOAD);
    if summary.peek != ZX_OK as i64 || summary.peek_match != 1 {
        summary.failure_step = STEP_PEEK;
        close_pair(left, right);
        return summary;
    }

    first_buf.fill(0);
    actual = 0;
    summary.read_first = zx_socket_read(
        right,
        0,
        first_buf.as_mut_ptr(),
        first_buf.len(),
        &mut actual,
    ) as i64;
    summary.read_first_actual = actual as u64;
    summary.read_first_match =
        u64::from(actual == FIRST_PAYLOAD.len() && first_buf == FIRST_PAYLOAD);
    if summary.read_first != ZX_OK as i64 || summary.read_first_match != 1 {
        summary.failure_step = STEP_READ_FIRST;
        close_pair(left, right);
        return summary;
    }

    actual = 0;
    summary.write_trunc = zx_socket_write(
        left,
        0,
        TRUNC_PAYLOAD.as_ptr(),
        TRUNC_PAYLOAD.len(),
        &mut actual,
    ) as i64;
    if summary.write_trunc != ZX_OK as i64 || actual != TRUNC_PAYLOAD.len() {
        summary.failure_step = STEP_WRITE_TRUNC;
        close_pair(left, right);
        return summary;
    }

    let mut small = [0u8; 8];
    actual = 0;
    summary.read_trunc =
        zx_socket_read(right, 0, small.as_mut_ptr(), small.len(), &mut actual) as i64;
    summary.read_trunc_actual = actual as u64;
    summary.read_trunc_prefix =
        u64::from(actual == small.len() && small.as_slice() == &TRUNC_PAYLOAD[..small.len()]);
    if summary.read_trunc != ZX_OK as i64 || summary.read_trunc_prefix != 1 {
        summary.failure_step = STEP_READ_TRUNC;
        close_pair(left, right);
        return summary;
    }

    actual = 0;
    summary.read_after_trunc =
        zx_socket_read(right, 0, small.as_mut_ptr(), small.len(), &mut actual) as i64;
    if summary.read_after_trunc != ZX_ERR_SHOULD_WAIT as i64 {
        summary.failure_step = STEP_READ_AFTER_TRUNC;
        close_pair(left, right);
        return summary;
    }

    let fill_packet = [0x5a_u8; FILL_PACKET_BYTES];
    for _ in 0..4 {
        actual = 0;
        let status = zx_socket_write(
            left,
            0,
            fill_packet.as_ptr(),
            fill_packet.len(),
            &mut actual,
        );
        if status != ZX_OK || actual != fill_packet.len() {
            summary.fill_should_wait = status as i64;
            summary.failure_step = STEP_FILL;
            close_pair(left, right);
            return summary;
        }
    }
    actual = 0;
    summary.fill_should_wait = zx_socket_write(
        left,
        0,
        fill_packet.as_ptr(),
        fill_packet.len(),
        &mut actual,
    ) as i64;
    if summary.fill_should_wait != ZX_ERR_SHOULD_WAIT as i64 {
        summary.failure_step = STEP_FILL;
        close_pair(left, right);
        return summary;
    }

    let mut drain = [0u8; FILL_PACKET_BYTES];
    actual = 0;
    let drain_status = zx_socket_read(right, 0, drain.as_mut_ptr(), drain.len(), &mut actual);
    summary.drain_after_fill = actual as u64;
    if drain_status != ZX_OK || actual != fill_packet.len() || drain != fill_packet {
        summary.failure_step = STEP_DRAIN_AFTER_FILL;
        close_pair(left, right);
        return summary;
    }

    actual = 0;
    summary.write_recover = zx_socket_write(
        left,
        0,
        fill_packet.as_ptr(),
        fill_packet.len(),
        &mut actual,
    ) as i64;
    if summary.write_recover != ZX_OK as i64 || actual != fill_packet.len() {
        summary.failure_step = STEP_WRITE_RECOVER;
        close_pair(left, right);
        return summary;
    }

    summary.close_left = zx_handle_close(left) as i64;
    left = ZX_HANDLE_INVALID;
    if summary.close_left != ZX_OK as i64 {
        summary.failure_step = STEP_CLOSE_LEFT;
        close_pair(left, right);
        return summary;
    }

    observed = 0;
    summary.wait_peer_closed =
        zx_object_wait_one(right, ZX_SOCKET_PEER_CLOSED, wait_deadline(), &mut observed) as i64;
    summary.wait_peer_closed_observed = u64::from(observed);
    if summary.wait_peer_closed != ZX_OK as i64 {
        summary.failure_step = STEP_WAIT_PEER_CLOSED;
        close_pair(left, right);
        return summary;
    }

    actual = 0;
    summary.write_peer_closed = zx_socket_write(
        right,
        0,
        FIRST_PAYLOAD.as_ptr(),
        FIRST_PAYLOAD.len(),
        &mut actual,
    ) as i64;
    if summary.write_peer_closed != ZX_ERR_PEER_CLOSED as i64 {
        summary.failure_step = STEP_WRITE_PEER_CLOSED;
    }

    close_pair(left, right);
    summary
}

fn wait_deadline() -> i64 {
    read_slot(SLOT_T0_NS)
        .saturating_add(WAIT_TIMEOUT_NS)
        .min(i64::MAX as u64) as i64
}

fn close_pair(left: zx_handle_t, right: zx_handle_t) {
    if left != ZX_HANDLE_INVALID {
        let _ = zx_handle_close(left);
    }
    if right != ZX_HANDLE_INVALID {
        let _ = zx_handle_close(right);
    }
}

fn read_slot(slot: usize) -> u64 {
    let slots = USER_SHARED_BASE as *const u64;
    // SAFETY: the kernel maps the bootstrap shared summary pages at `USER_SHARED_BASE`.
    unsafe { slots.add(slot).read_volatile() }
}

fn write_slot(slot: usize, value: u64) {
    let slots = USER_SHARED_BASE as *mut u64;
    // SAFETY: the kernel maps the bootstrap shared summary pages at `USER_SHARED_BASE`.
    unsafe { slots.add(slot).write_volatile(value) }
}

fn write_summary(summary: &DatagramSummary) {
    write_slot(SLOT_DGRAM_PRESENT, 1);
    write_slot(SLOT_DGRAM_FAILURE_STEP, summary.failure_step);
    write_slot(SLOT_DGRAM_CREATE, summary.create as u64);
    write_slot(SLOT_DGRAM_WAIT_WRITABLE, summary.wait_writable as u64);
    write_slot(SLOT_DGRAM_WRITE_FIRST, summary.write_first as u64);
    write_slot(SLOT_DGRAM_WAIT_READABLE, summary.wait_readable as u64);
    write_slot(SLOT_DGRAM_PEEK, summary.peek as u64);
    write_slot(SLOT_DGRAM_PEEK_ACTUAL, summary.peek_actual);
    write_slot(SLOT_DGRAM_PEEK_MATCH, summary.peek_match);
    write_slot(SLOT_DGRAM_READ_FIRST, summary.read_first as u64);
    write_slot(SLOT_DGRAM_READ_FIRST_ACTUAL, summary.read_first_actual);
    write_slot(SLOT_DGRAM_READ_FIRST_MATCH, summary.read_first_match);
    write_slot(SLOT_DGRAM_WRITE_TRUNC, summary.write_trunc as u64);
    write_slot(SLOT_DGRAM_READ_TRUNC, summary.read_trunc as u64);
    write_slot(SLOT_DGRAM_READ_TRUNC_ACTUAL, summary.read_trunc_actual);
    write_slot(SLOT_DGRAM_READ_TRUNC_PREFIX, summary.read_trunc_prefix);
    write_slot(SLOT_DGRAM_READ_AFTER_TRUNC, summary.read_after_trunc as u64);
    write_slot(SLOT_DGRAM_FILL_SHOULD_WAIT, summary.fill_should_wait as u64);
    write_slot(SLOT_DGRAM_DRAIN_AFTER_FILL, summary.drain_after_fill);
    write_slot(SLOT_DGRAM_WRITE_RECOVER, summary.write_recover as u64);
    write_slot(SLOT_DGRAM_CLOSE_LEFT, summary.close_left as u64);
    write_slot(SLOT_DGRAM_WAIT_PEER_CLOSED, summary.wait_peer_closed as u64);
    write_slot(
        SLOT_DGRAM_WAIT_PEER_CLOSED_OBSERVED,
        summary.wait_peer_closed_observed,
    );
    write_slot(
        SLOT_DGRAM_WRITE_PEER_CLOSED,
        summary.write_peer_closed as u64,
    );
}
