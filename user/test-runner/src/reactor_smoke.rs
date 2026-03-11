//! Runtime-grade dispatcher/executor smoke for Phase-3 `libzircon + nexus-rt`.

use alloc::rc::Rc;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::RefCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use libzircon::handle::ZX_HANDLE_INVALID;
use libzircon::signals::{ZX_CHANNEL_READABLE, ZX_SOCKET_READABLE};
use libzircon::socket::ZX_SOCKET_STREAM;
use libzircon::status::{ZX_ERR_INTERNAL, ZX_OK};
use libzircon::{
    zx_channel_create, zx_channel_write, zx_handle_close, zx_handle_t, zx_socket_create,
    zx_socket_read, zx_socket_write, zx_time_t,
};
use nexus_rt::Dispatcher;

const USER_SHARED_BASE: u64 = 0x0000_0001_0010_0000;

const SLOT_OK: usize = 0;
const SLOT_T0_NS: usize = 511;
const SLOT_RUNTIME_FAILURE_STEP: usize = 543;
const SLOT_RUNTIME_DISPATCHER_CREATE: usize = 544;
const SLOT_RUNTIME_REG_CREATE_FIRST: usize = 545;
const SLOT_RUNTIME_REG_CANCEL_FIRST: usize = 546;
const SLOT_RUNTIME_REG_CREATE_SECOND: usize = 547;
const SLOT_RUNTIME_REG_SLOT_REUSED: usize = 548;
const SLOT_RUNTIME_REG_GEN_ADVANCED: usize = 549;
const SLOT_RUNTIME_CHANNEL_CREATE: usize = 550;
const SLOT_RUNTIME_CHANNEL_SEED_WRITE: usize = 551;
const SLOT_RUNTIME_CHANNEL_RECV: usize = 552;
const SLOT_RUNTIME_CHANNEL_RECV_ACTUAL_BYTES: usize = 553;
const SLOT_RUNTIME_CHANNEL_RECV_MATCH: usize = 554;
const SLOT_RUNTIME_SLEEP_CREATE: usize = 555;
const SLOT_RUNTIME_SLEEP_WAIT: usize = 556;
const SLOT_RUNTIME_CHANNEL_CALL_CREATE: usize = 557;
const SLOT_RUNTIME_CHANNEL_CALL_SERVER_SPAWN: usize = 558;
const SLOT_RUNTIME_CHANNEL_CALL_SERVER_RECV: usize = 559;
const SLOT_RUNTIME_CHANNEL_CALL_SERVER_MATCH: usize = 560;
const SLOT_RUNTIME_CHANNEL_CALL_SERVER_REPLY: usize = 561;
const SLOT_RUNTIME_CHANNEL_CALL: usize = 562;
const SLOT_RUNTIME_CHANNEL_CALL_ACTUAL_BYTES: usize = 563;
const SLOT_RUNTIME_CHANNEL_CALL_MATCH: usize = 564;
const SLOT_RUNTIME_SOCKET_CREATE: usize = 565;
const SLOT_RUNTIME_SOCKET_SEED_WRITE: usize = 566;
const SLOT_RUNTIME_SOCKET_WAIT_READABLE: usize = 567;
const SLOT_RUNTIME_SOCKET_WAIT_OBSERVED: usize = 568;
const SLOT_RUNTIME_SOCKET_READ: usize = 569;
const SLOT_RUNTIME_SOCKET_READ_ACTUAL_BYTES: usize = 570;
const SLOT_RUNTIME_SOCKET_READ_MATCH: usize = 571;
const SLOT_RUNTIME_CLOSE_SEED_TX: usize = 572;
const SLOT_RUNTIME_CLOSE_SEED_RX: usize = 573;
const SLOT_RUNTIME_CLOSE_CALL_CLIENT: usize = 574;
const SLOT_RUNTIME_CLOSE_CALL_SERVER: usize = 575;
const SLOT_RUNTIME_CLOSE_SOCKET_TX: usize = 576;
const SLOT_RUNTIME_CLOSE_SOCKET_RX: usize = 577;

const STEP_DISPATCHER_CREATE: u64 = 1;
const STEP_REG_CREATE_FIRST: u64 = 2;
const STEP_REG_CANCEL_FIRST: u64 = 3;
const STEP_REG_CREATE_SECOND: u64 = 4;
const STEP_REG_REUSE: u64 = 5;
const STEP_CHANNEL_CREATE: u64 = 6;
const STEP_CHANNEL_SEED_WRITE: u64 = 7;
const STEP_CHANNEL_RECV: u64 = 8;
const STEP_SLEEP_CREATE: u64 = 9;
const STEP_SLEEP_WAIT: u64 = 10;
const STEP_CHANNEL_CALL_CREATE: u64 = 11;
const STEP_CHANNEL_CALL_SERVER_SPAWN: u64 = 12;
const STEP_CHANNEL_CALL: u64 = 13;
const STEP_SOCKET_CREATE: u64 = 14;
const STEP_SOCKET_SEED_WRITE: u64 = 15;
const STEP_SOCKET_WAIT_READABLE: u64 = 16;
const STEP_SOCKET_READ: u64 = 17;
const STEP_PANIC: u64 = u64::MAX;

const CHANNEL_PAYLOAD: [u8; 5] = *b"ping!";
const CALL_REQUEST: [u8; 4] = *b"ping";
const CALL_REPLY: [u8; 4] = *b"pong";
const SOCKET_PAYLOAD: [u8; 4] = *b"sock";
const SLEEP_DELAY_NS: i64 = 50_000_000;
const HEAP_BYTES: usize = 256 * 1024;

#[repr(align(16))]
struct HeapStorage([u8; HEAP_BYTES]);

static mut HEAP: HeapStorage = HeapStorage([0; HEAP_BYTES]);
static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

// SAFETY: this allocator only serves the single-threaded bootstrap runtime
// smoke. Allocations come from one fixed static buffer, deallocation is a
// no-op, and alignment is honored by monotonic bumping.
unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align_mask = layout.align().saturating_sub(1);
        let size = layout.size();
        let mut current = HEAP_NEXT.load(Ordering::Relaxed);

        loop {
            let aligned = (current + align_mask) & !align_mask;
            let Some(next) = aligned.checked_add(size) else {
                return core::ptr::null_mut();
            };
            if next > HEAP_BYTES {
                return core::ptr::null_mut();
            }
            match HEAP_NEXT.compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // SAFETY: `HEAP` is the dedicated backing storage for this bump allocator.
                    // Allocation is serialized by the atomic bump pointer, and callers only
                    // receive disjoint regions within this static buffer.
                    let base = unsafe { core::ptr::addr_of_mut!(HEAP.0).cast::<u8>() as usize };
                    return (base + aligned) as *mut u8;
                }
                Err(observed) => current = observed,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RuntimeSummary {
    failure_step: u64,
    dispatcher_create: i64,
    reg_create_first: i64,
    reg_cancel_first: i64,
    reg_create_second: i64,
    reg_slot_reused: u64,
    reg_generation_advanced: u64,
    channel_create: i64,
    channel_seed_write: i64,
    channel_recv: i64,
    channel_recv_actual_bytes: u64,
    channel_recv_match: u64,
    sleep_create: i64,
    sleep_wait: i64,
    channel_call_create: i64,
    channel_call_server_spawn: i64,
    channel_call_server_recv: i64,
    channel_call_server_match: u64,
    channel_call_server_reply: i64,
    channel_call: i64,
    channel_call_actual_bytes: u64,
    channel_call_match: u64,
    socket_create: i64,
    socket_seed_write: i64,
    socket_wait_readable: i64,
    socket_wait_observed: u64,
    socket_read: i64,
    socket_read_actual_bytes: u64,
    socket_read_match: u64,
    close_seed_tx: i64,
    close_seed_rx: i64,
    close_call_client: i64,
    close_call_server: i64,
    close_socket_tx: i64,
    close_socket_rx: i64,
}

#[derive(Clone, Copy)]
struct ServerTaskSummary {
    recv: i64,
    match_ok: u64,
    reply: i64,
}

impl Default for ServerTaskSummary {
    fn default() -> Self {
        Self {
            recv: ZX_ERR_INTERNAL as i64,
            match_ok: 0,
            reply: ZX_ERR_INTERNAL as i64,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_start() -> ! {
    let mut summary = RuntimeSummary::default();
    let status = run_runtime_dispatcher_smoke(&mut summary, read_slot(SLOT_T0_NS));
    write_summary(&summary);
    write_slot(SLOT_OK, u64::from(status == 0));
    axle_arch_x86_64::debug_break()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}

pub fn report_panic() -> ! {
    write_slot(SLOT_RUNTIME_FAILURE_STEP, STEP_PANIC);
    write_slot(SLOT_OK, 1);
    axle_arch_x86_64::debug_break()
}

fn run_runtime_dispatcher_smoke(summary: &mut RuntimeSummary, t0_ns: u64) -> i32 {
    *summary = RuntimeSummary::default();

    let dispatcher = match Dispatcher::create() {
        Ok(dispatcher) => {
            summary.dispatcher_create = ZX_OK as i64;
            dispatcher
        }
        Err(status) => {
            summary.dispatcher_create = status as i64;
            summary.failure_step = STEP_DISPATCHER_CREATE;
            return 1;
        }
    };
    let handle = dispatcher.handle();

    let mut seed_tx = ZX_HANDLE_INVALID;
    let mut seed_rx = ZX_HANDLE_INVALID;
    summary.channel_create = zx_channel_create(0, &mut seed_tx, &mut seed_rx) as i64;
    if summary.channel_create != ZX_OK as i64 {
        summary.failure_step = STEP_CHANNEL_CREATE;
        return 1;
    }

    let reg_first = match handle.register_signals(seed_rx, ZX_CHANNEL_READABLE) {
        Ok(registration) => {
            summary.reg_create_first = ZX_OK as i64;
            registration
        }
        Err(status) => {
            summary.reg_create_first = status as i64;
            summary.failure_step = STEP_REG_CREATE_FIRST;
            return 1;
        }
    };
    let first_id = reg_first.id().unwrap_or_else(|| unreachable!());
    summary.reg_cancel_first = match reg_first.cancel() {
        Ok(()) => ZX_OK as i64,
        Err(status) => {
            summary.failure_step = STEP_REG_CANCEL_FIRST;
            status as i64
        }
    };
    if summary.reg_cancel_first != ZX_OK as i64 {
        return 1;
    }
    let reg_second = match handle.register_signals(seed_rx, ZX_CHANNEL_READABLE) {
        Ok(registration) => {
            summary.reg_create_second = ZX_OK as i64;
            registration
        }
        Err(status) => {
            summary.reg_create_second = status as i64;
            summary.failure_step = STEP_REG_CREATE_SECOND;
            return 1;
        }
    };
    let second_id = reg_second.id().unwrap_or_else(|| unreachable!());
    summary.reg_slot_reused = u64::from(first_id.slot() == second_id.slot());
    summary.reg_generation_advanced = u64::from(second_id.generation() != first_id.generation());
    if summary.reg_slot_reused != 1 || summary.reg_generation_advanced != 1 {
        summary.failure_step = STEP_REG_REUSE;
        return 1;
    }
    drop(reg_second);

    summary.channel_seed_write = zx_channel_write(
        seed_tx,
        0,
        CHANNEL_PAYLOAD.as_ptr(),
        CHANNEL_PAYLOAD.len() as u32,
        core::ptr::null(),
        0,
    ) as i64;
    if summary.channel_seed_write != ZX_OK as i64 {
        summary.failure_step = STEP_CHANNEL_SEED_WRITE;
        return 1;
    }

    let mut recv_bytes = [0u8; CHANNEL_PAYLOAD.len()];
    let mut recv_handles: [zx_handle_t; 0] = [];
    match dispatcher.block_on(handle.channel_recv(seed_rx, &mut recv_bytes, &mut recv_handles)) {
        Ok(Ok(result)) => {
            summary.channel_recv = ZX_OK as i64;
            summary.channel_recv_actual_bytes = result.actual_bytes as u64;
            summary.channel_recv_match = u64::from(
                result.actual_bytes as usize == CHANNEL_PAYLOAD.len()
                    && recv_bytes == CHANNEL_PAYLOAD,
            );
        }
        Ok(Err(status)) | Err(status) => {
            summary.channel_recv = status as i64;
            summary.failure_step = STEP_CHANNEL_RECV;
            return 1;
        }
    }
    if summary.channel_recv_match != 1 {
        summary.failure_step = STEP_CHANNEL_RECV;
        return 1;
    }

    let sleep = match handle.sleep_until(deadline_after(t0_ns, SLEEP_DELAY_NS)) {
        Ok(sleep) => {
            summary.sleep_create = ZX_OK as i64;
            sleep
        }
        Err(status) => {
            summary.sleep_create = status as i64;
            summary.failure_step = STEP_SLEEP_CREATE;
            return 1;
        }
    };
    match dispatcher.block_on(sleep) {
        Ok(Ok(())) => summary.sleep_wait = ZX_OK as i64,
        Ok(Err(status)) | Err(status) => {
            summary.sleep_wait = status as i64;
            summary.failure_step = STEP_SLEEP_WAIT;
            return 1;
        }
    }

    let mut call_client = ZX_HANDLE_INVALID;
    let mut call_server = ZX_HANDLE_INVALID;
    summary.channel_call_create = zx_channel_create(0, &mut call_client, &mut call_server) as i64;
    if summary.channel_call_create != ZX_OK as i64 {
        summary.failure_step = STEP_CHANNEL_CALL_CREATE;
        return 1;
    }

    let server_summary = Rc::new(RefCell::new(ServerTaskSummary::default()));
    let server_summary_task = Rc::clone(&server_summary);
    let server_handle = handle.clone();
    match dispatcher.spawn(async move {
        let mut request = [0u8; CALL_REQUEST.len()];
        let mut request_handles: [zx_handle_t; 0] = [];
        let outcome = server_handle
            .channel_recv(call_server, &mut request, &mut request_handles)
            .await;
        let mut server = server_summary_task.borrow_mut();
        match outcome {
            Ok(result) => {
                server.recv = ZX_OK as i64;
                server.match_ok = u64::from(
                    result.actual_bytes as usize == CALL_REQUEST.len() && request == CALL_REQUEST,
                );
                server.reply = zx_channel_write(
                    call_server,
                    0,
                    CALL_REPLY.as_ptr(),
                    CALL_REPLY.len() as u32,
                    core::ptr::null(),
                    0,
                ) as i64;
            }
            Err(status) => {
                server.recv = status as i64;
            }
        }
    }) {
        Ok(_) => summary.channel_call_server_spawn = ZX_OK as i64,
        Err(status) => {
            summary.channel_call_server_spawn = status as i64;
            summary.failure_step = STEP_CHANNEL_CALL_SERVER_SPAWN;
            return 1;
        }
    }

    let mut reply = [0u8; CALL_REPLY.len()];
    let mut reply_handles: [zx_handle_t; 0] = [];
    match dispatcher.block_on(handle.channel_call(
        call_client,
        &CALL_REQUEST,
        &mut reply,
        &mut reply_handles,
    )) {
        Ok(Ok(result)) => {
            summary.channel_call = ZX_OK as i64;
            summary.channel_call_actual_bytes = result.actual_bytes as u64;
            summary.channel_call_match =
                u64::from(result.actual_bytes as usize == CALL_REPLY.len() && reply == CALL_REPLY);
        }
        Ok(Err(status)) | Err(status) => {
            summary.channel_call = status as i64;
            summary.failure_step = STEP_CHANNEL_CALL;
            return 1;
        }
    }

    let server_summary = server_summary.borrow();
    summary.channel_call_server_recv = server_summary.recv;
    summary.channel_call_server_match = server_summary.match_ok;
    summary.channel_call_server_reply = server_summary.reply;
    if summary.channel_call_server_recv != ZX_OK as i64
        || summary.channel_call_server_match != 1
        || summary.channel_call_server_reply != ZX_OK as i64
        || summary.channel_call_match != 1
    {
        summary.failure_step = STEP_CHANNEL_CALL;
        return 1;
    }

    let mut socket_tx = ZX_HANDLE_INVALID;
    let mut socket_rx = ZX_HANDLE_INVALID;
    summary.socket_create =
        zx_socket_create(ZX_SOCKET_STREAM, &mut socket_tx, &mut socket_rx) as i64;
    if summary.socket_create != ZX_OK as i64 {
        summary.failure_step = STEP_SOCKET_CREATE;
        return 1;
    }

    let mut socket_written = 0usize;
    summary.socket_seed_write = zx_socket_write(
        socket_tx,
        0,
        SOCKET_PAYLOAD.as_ptr(),
        SOCKET_PAYLOAD.len(),
        &mut socket_written,
    ) as i64;
    if summary.socket_seed_write != ZX_OK as i64 || socket_written != SOCKET_PAYLOAD.len() {
        summary.failure_step = STEP_SOCKET_SEED_WRITE;
        return 1;
    }

    match dispatcher.block_on(handle.socket_readiness(socket_rx, ZX_SOCKET_READABLE)) {
        Ok(Ok(observed)) => {
            summary.socket_wait_readable = ZX_OK as i64;
            summary.socket_wait_observed = observed as u64;
        }
        Ok(Err(status)) | Err(status) => {
            summary.socket_wait_readable = status as i64;
            summary.failure_step = STEP_SOCKET_WAIT_READABLE;
            return 1;
        }
    }

    let mut socket_buf = [0u8; SOCKET_PAYLOAD.len()];
    let mut socket_actual = 0usize;
    summary.socket_read = zx_socket_read(
        socket_rx,
        0,
        socket_buf.as_mut_ptr(),
        socket_buf.len(),
        &mut socket_actual,
    ) as i64;
    summary.socket_read_actual_bytes = socket_actual as u64;
    summary.socket_read_match =
        u64::from(socket_actual == SOCKET_PAYLOAD.len() && socket_buf == SOCKET_PAYLOAD);
    if summary.socket_read != ZX_OK as i64 || summary.socket_read_match != 1 {
        summary.failure_step = STEP_SOCKET_READ;
        return 1;
    }

    summary.close_seed_tx = zx_handle_close(seed_tx) as i64;
    summary.close_seed_rx = zx_handle_close(seed_rx) as i64;
    summary.close_call_client = zx_handle_close(call_client) as i64;
    summary.close_call_server = zx_handle_close(call_server) as i64;
    summary.close_socket_tx = zx_handle_close(socket_tx) as i64;
    summary.close_socket_rx = zx_handle_close(socket_rx) as i64;

    0
}

fn deadline_after(base: u64, delta_ns: i64) -> zx_time_t {
    (base as i64).saturating_add(delta_ns)
}

fn write_summary(summary: &RuntimeSummary) {
    write_slot(SLOT_RUNTIME_FAILURE_STEP, summary.failure_step);
    write_slot(
        SLOT_RUNTIME_DISPATCHER_CREATE,
        summary.dispatcher_create as u64,
    );
    write_slot(
        SLOT_RUNTIME_REG_CREATE_FIRST,
        summary.reg_create_first as u64,
    );
    write_slot(
        SLOT_RUNTIME_REG_CANCEL_FIRST,
        summary.reg_cancel_first as u64,
    );
    write_slot(
        SLOT_RUNTIME_REG_CREATE_SECOND,
        summary.reg_create_second as u64,
    );
    write_slot(SLOT_RUNTIME_REG_SLOT_REUSED, summary.reg_slot_reused);
    write_slot(
        SLOT_RUNTIME_REG_GEN_ADVANCED,
        summary.reg_generation_advanced,
    );
    write_slot(SLOT_RUNTIME_CHANNEL_CREATE, summary.channel_create as u64);
    write_slot(
        SLOT_RUNTIME_CHANNEL_SEED_WRITE,
        summary.channel_seed_write as u64,
    );
    write_slot(SLOT_RUNTIME_CHANNEL_RECV, summary.channel_recv as u64);
    write_slot(
        SLOT_RUNTIME_CHANNEL_RECV_ACTUAL_BYTES,
        summary.channel_recv_actual_bytes,
    );
    write_slot(SLOT_RUNTIME_CHANNEL_RECV_MATCH, summary.channel_recv_match);
    write_slot(SLOT_RUNTIME_SLEEP_CREATE, summary.sleep_create as u64);
    write_slot(SLOT_RUNTIME_SLEEP_WAIT, summary.sleep_wait as u64);
    write_slot(
        SLOT_RUNTIME_CHANNEL_CALL_CREATE,
        summary.channel_call_create as u64,
    );
    write_slot(
        SLOT_RUNTIME_CHANNEL_CALL_SERVER_SPAWN,
        summary.channel_call_server_spawn as u64,
    );
    write_slot(
        SLOT_RUNTIME_CHANNEL_CALL_SERVER_RECV,
        summary.channel_call_server_recv as u64,
    );
    write_slot(
        SLOT_RUNTIME_CHANNEL_CALL_SERVER_MATCH,
        summary.channel_call_server_match,
    );
    write_slot(
        SLOT_RUNTIME_CHANNEL_CALL_SERVER_REPLY,
        summary.channel_call_server_reply as u64,
    );
    write_slot(SLOT_RUNTIME_CHANNEL_CALL, summary.channel_call as u64);
    write_slot(
        SLOT_RUNTIME_CHANNEL_CALL_ACTUAL_BYTES,
        summary.channel_call_actual_bytes,
    );
    write_slot(SLOT_RUNTIME_CHANNEL_CALL_MATCH, summary.channel_call_match);
    write_slot(SLOT_RUNTIME_SOCKET_CREATE, summary.socket_create as u64);
    write_slot(
        SLOT_RUNTIME_SOCKET_SEED_WRITE,
        summary.socket_seed_write as u64,
    );
    write_slot(
        SLOT_RUNTIME_SOCKET_WAIT_READABLE,
        summary.socket_wait_readable as u64,
    );
    write_slot(
        SLOT_RUNTIME_SOCKET_WAIT_OBSERVED,
        summary.socket_wait_observed,
    );
    write_slot(SLOT_RUNTIME_SOCKET_READ, summary.socket_read as u64);
    write_slot(
        SLOT_RUNTIME_SOCKET_READ_ACTUAL_BYTES,
        summary.socket_read_actual_bytes,
    );
    write_slot(SLOT_RUNTIME_SOCKET_READ_MATCH, summary.socket_read_match);
    write_slot(SLOT_RUNTIME_CLOSE_SEED_TX, summary.close_seed_tx as u64);
    write_slot(SLOT_RUNTIME_CLOSE_SEED_RX, summary.close_seed_rx as u64);
    write_slot(
        SLOT_RUNTIME_CLOSE_CALL_CLIENT,
        summary.close_call_client as u64,
    );
    write_slot(
        SLOT_RUNTIME_CLOSE_CALL_SERVER,
        summary.close_call_server as u64,
    );
    write_slot(SLOT_RUNTIME_CLOSE_SOCKET_TX, summary.close_socket_tx as u64);
    write_slot(SLOT_RUNTIME_CLOSE_SOCKET_RX, summary.close_socket_rx as u64);
}

fn read_slot(index: usize) -> u64 {
    // SAFETY: the kernel maps one shared result page at `USER_SHARED_BASE` for
    // the bootstrap test runner and all slot indices in this file are within
    // that fixed page-sized slot table.
    unsafe { slot_ptr(index).read_volatile() }
}

fn write_slot(index: usize, value: u64) {
    // SAFETY: the kernel-owned shared result page is writable by this
    // userspace test runner for these fixed diagnostic slots.
    unsafe { slot_ptr(index).write_volatile(value) }
}

fn slot_ptr(index: usize) -> *mut u64 {
    (USER_SHARED_BASE as *mut u64).wrapping_add(index)
}
