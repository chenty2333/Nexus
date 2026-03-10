//! Minimal ring3 smoke for Phase-3 `libzircon + reactor`.

use libzircon::clock::ZX_CLOCK_MONOTONIC;
use libzircon::handle::ZX_HANDLE_INVALID;
use libzircon::signals::{ZX_CHANNEL_READABLE, ZX_TIMER_SIGNALED};
use libzircon::status::ZX_OK;
use libzircon::{
    ZX_TIME_INFINITE, zx_channel_create, zx_channel_read, zx_channel_write, zx_handle_close,
    zx_time_t, zx_timer_cancel, zx_timer_create, zx_timer_set,
};
use nexus_rt::{Event, Reactor};

const USER_SHARED_BASE: u64 = 0x0000_0001_0000_8000;

const SLOT_OK: usize = 0;
const SLOT_T0_NS: usize = 511;
const SLOT_RUNTIME_FAILURE_STEP: usize = 543;
const SLOT_RUNTIME_PORT_CREATE: usize = 544;
const SLOT_RUNTIME_CHANNEL_CREATE: usize = 545;
const SLOT_RUNTIME_TIMER_CREATE: usize = 546;
const SLOT_RUNTIME_ARM_CHANNEL: usize = 547;
const SLOT_RUNTIME_CHANNEL_WRITE: usize = 548;
const SLOT_RUNTIME_WAIT_CHANNEL: usize = 549;
const SLOT_RUNTIME_CHANNEL_EVENT_KEY: usize = 550;
const SLOT_RUNTIME_CHANNEL_EVENT_TYPE: usize = 551;
const SLOT_RUNTIME_CHANNEL_EVENT_OBSERVED: usize = 552;
const SLOT_RUNTIME_CHANNEL_READ: usize = 553;
const SLOT_RUNTIME_CHANNEL_ACTUAL_BYTES: usize = 554;
const SLOT_RUNTIME_CHANNEL_MATCH: usize = 555;
const SLOT_RUNTIME_ARM_TIMER: usize = 556;
const SLOT_RUNTIME_TIMER_SET: usize = 557;
const SLOT_RUNTIME_WAIT_TIMER: usize = 558;
const SLOT_RUNTIME_TIMER_EVENT_KEY: usize = 559;
const SLOT_RUNTIME_TIMER_EVENT_TYPE: usize = 560;
const SLOT_RUNTIME_TIMER_EVENT_OBSERVED: usize = 561;
const SLOT_RUNTIME_TIMER_CANCEL: usize = 562;
const SLOT_RUNTIME_CLOSE_TX: usize = 563;
const SLOT_RUNTIME_CLOSE_RX: usize = 564;
const SLOT_RUNTIME_CLOSE_TIMER: usize = 565;
const SLOT_RUNTIME_CLOSE_PORT: usize = 566;

const CHANNEL_EVENT_KEY: u64 = 0x4348_414E_4E45_4C31;
const TIMER_EVENT_KEY: u64 = 0x5449_4D45_5231_0001;
const CHANNEL_PAYLOAD: [u8; 5] = *b"ping!";
const TIMER_DELAY_NS: i64 = 50_000_000;
const WAIT_BUDGET_NS: i64 = 500_000_000;

const STEP_PORT_CREATE: u64 = 1;
const STEP_CHANNEL_CREATE: u64 = 2;
const STEP_TIMER_CREATE: u64 = 3;
const STEP_ARM_CHANNEL: u64 = 4;
const STEP_CHANNEL_WRITE: u64 = 5;
const STEP_WAIT_CHANNEL: u64 = 6;
const STEP_CHANNEL_EVENT: u64 = 7;
const STEP_CHANNEL_READ: u64 = 8;
const STEP_ARM_TIMER: u64 = 9;
const STEP_TIMER_SET: u64 = 10;
const STEP_WAIT_TIMER: u64 = 11;
const STEP_TIMER_EVENT: u64 = 12;
const STEP_TIMER_CANCEL: u64 = 13;
const STEP_CLOSE_TX: u64 = 14;
const STEP_CLOSE_RX: u64 = 15;
const STEP_CLOSE_TIMER: u64 = 16;
const STEP_CLOSE_PORT: u64 = 17;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ReactorSmokeSummary {
    failure_step: u64,
    port_create: i64,
    channel_create: i64,
    timer_create: i64,
    arm_channel: i64,
    channel_write: i64,
    wait_channel: i64,
    channel_event_key: u64,
    channel_event_type: u64,
    channel_event_observed: u64,
    channel_read: i64,
    channel_actual_bytes: u64,
    channel_match: u64,
    arm_timer: i64,
    timer_set: i64,
    wait_timer: i64,
    timer_event_key: u64,
    timer_event_type: u64,
    timer_event_observed: u64,
    timer_cancel: i64,
    close_tx: i64,
    close_rx: i64,
    close_timer: i64,
    close_port: i64,
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_start() -> ! {
    let mut summary = ReactorSmokeSummary::default();
    let status = run_reactor_smoke(&mut summary, read_slot(SLOT_T0_NS));
    write_summary(&summary);
    write_slot(SLOT_OK, u64::from(status == 0));
    axle_arch_x86_64::debug_break()
}

#[unsafe(no_mangle)]
pub extern "C" fn axle_user_prog_end() {}

fn run_reactor_smoke(summary: &mut ReactorSmokeSummary, t0_ns: u64) -> i32 {
    *summary = ReactorSmokeSummary::default();

    let reactor = match Reactor::create() {
        Ok(reactor) => {
            summary.port_create = ZX_OK as i64;
            reactor
        }
        Err(status) => {
            summary.port_create = status as i64;
            summary.failure_step = STEP_PORT_CREATE;
            return 1;
        }
    };

    let mut tx = ZX_HANDLE_INVALID;
    let mut rx = ZX_HANDLE_INVALID;
    summary.channel_create = zx_channel_create(0, &mut tx, &mut rx) as i64;
    if summary.channel_create != ZX_OK as i64 {
        summary.failure_step = STEP_CHANNEL_CREATE;
        return 1;
    }

    let mut timer = ZX_HANDLE_INVALID;
    summary.timer_create = zx_timer_create(0, ZX_CLOCK_MONOTONIC, &mut timer) as i64;
    if summary.timer_create != ZX_OK as i64 {
        summary.failure_step = STEP_TIMER_CREATE;
        return 1;
    }

    summary.arm_channel = match reactor.wait_async(rx, CHANNEL_EVENT_KEY, ZX_CHANNEL_READABLE, 0) {
        Ok(()) => ZX_OK as i64,
        Err(status) => status as i64,
    };
    if summary.arm_channel != ZX_OK as i64 {
        summary.failure_step = STEP_ARM_CHANNEL;
        return 1;
    }

    summary.channel_write = zx_channel_write(
        tx,
        0,
        CHANNEL_PAYLOAD.as_ptr(),
        CHANNEL_PAYLOAD.len() as u32,
        core::ptr::null(),
        0,
    ) as i64;
    if summary.channel_write != ZX_OK as i64 {
        summary.failure_step = STEP_CHANNEL_WRITE;
        return 1;
    }

    let channel_deadline = deadline_after(t0_ns, WAIT_BUDGET_NS);
    let channel_event = match reactor.wait_until(channel_deadline) {
        Ok(event) => {
            summary.wait_channel = ZX_OK as i64;
            event
        }
        Err(status) => {
            summary.wait_channel = status as i64;
            summary.failure_step = STEP_WAIT_CHANNEL;
            return 1;
        }
    };
    if !record_signal_event(
        &channel_event,
        CHANNEL_EVENT_KEY,
        ZX_CHANNEL_READABLE,
        &mut summary.channel_event_key,
        &mut summary.channel_event_type,
        &mut summary.channel_event_observed,
    ) {
        summary.failure_step = STEP_CHANNEL_EVENT;
        return 1;
    }

    let mut rx_bytes = [0u8; CHANNEL_PAYLOAD.len()];
    let mut actual_bytes = 0u32;
    let mut actual_handles = 0u32;
    summary.channel_read = zx_channel_read(
        rx,
        0,
        rx_bytes.as_mut_ptr(),
        core::ptr::null_mut(),
        rx_bytes.len() as u32,
        0,
        &mut actual_bytes,
        &mut actual_handles,
    ) as i64;
    summary.channel_actual_bytes = actual_bytes as u64;
    summary.channel_match = u64::from(
        summary.channel_read == ZX_OK as i64
            && actual_handles == 0
            && actual_bytes as usize == CHANNEL_PAYLOAD.len()
            && rx_bytes == CHANNEL_PAYLOAD,
    );
    if summary.channel_match != 1 {
        summary.failure_step = STEP_CHANNEL_READ;
        return 1;
    }

    summary.arm_timer = match reactor.wait_async(timer, TIMER_EVENT_KEY, ZX_TIMER_SIGNALED, 0) {
        Ok(()) => ZX_OK as i64,
        Err(status) => status as i64,
    };
    if summary.arm_timer != ZX_OK as i64 {
        summary.failure_step = STEP_ARM_TIMER;
        return 1;
    }

    summary.timer_set = zx_timer_set(timer, deadline_after(t0_ns, TIMER_DELAY_NS), 0) as i64;
    if summary.timer_set != ZX_OK as i64 {
        summary.failure_step = STEP_TIMER_SET;
        return 1;
    }

    let timer_event = match reactor.wait_until(ZX_TIME_INFINITE) {
        Ok(event) => {
            summary.wait_timer = ZX_OK as i64;
            event
        }
        Err(status) => {
            summary.wait_timer = status as i64;
            summary.failure_step = STEP_WAIT_TIMER;
            return 1;
        }
    };
    if !record_signal_event(
        &timer_event,
        TIMER_EVENT_KEY,
        ZX_TIMER_SIGNALED,
        &mut summary.timer_event_key,
        &mut summary.timer_event_type,
        &mut summary.timer_event_observed,
    ) {
        summary.failure_step = STEP_TIMER_EVENT;
        return 1;
    }

    summary.timer_cancel = zx_timer_cancel(timer) as i64;
    if summary.timer_cancel != ZX_OK as i64 {
        summary.failure_step = STEP_TIMER_CANCEL;
        return 1;
    }

    summary.close_tx = zx_handle_close(tx) as i64;
    if summary.close_tx != ZX_OK as i64 {
        summary.failure_step = STEP_CLOSE_TX;
        return 1;
    }
    summary.close_rx = zx_handle_close(rx) as i64;
    if summary.close_rx != ZX_OK as i64 {
        summary.failure_step = STEP_CLOSE_RX;
        return 1;
    }
    summary.close_timer = zx_handle_close(timer) as i64;
    if summary.close_timer != ZX_OK as i64 {
        summary.failure_step = STEP_CLOSE_TIMER;
        return 1;
    }
    summary.close_port = zx_handle_close(reactor.port_handle()) as i64;
    if summary.close_port != ZX_OK as i64 {
        summary.failure_step = STEP_CLOSE_PORT;
        return 1;
    }

    0
}

fn write_summary(summary: &ReactorSmokeSummary) {
    write_slot(SLOT_RUNTIME_FAILURE_STEP, summary.failure_step);
    write_slot(SLOT_RUNTIME_PORT_CREATE, summary.port_create as u64);
    write_slot(SLOT_RUNTIME_CHANNEL_CREATE, summary.channel_create as u64);
    write_slot(SLOT_RUNTIME_TIMER_CREATE, summary.timer_create as u64);
    write_slot(SLOT_RUNTIME_ARM_CHANNEL, summary.arm_channel as u64);
    write_slot(SLOT_RUNTIME_CHANNEL_WRITE, summary.channel_write as u64);
    write_slot(SLOT_RUNTIME_WAIT_CHANNEL, summary.wait_channel as u64);
    write_slot(SLOT_RUNTIME_CHANNEL_EVENT_KEY, summary.channel_event_key);
    write_slot(SLOT_RUNTIME_CHANNEL_EVENT_TYPE, summary.channel_event_type);
    write_slot(
        SLOT_RUNTIME_CHANNEL_EVENT_OBSERVED,
        summary.channel_event_observed,
    );
    write_slot(SLOT_RUNTIME_CHANNEL_READ, summary.channel_read as u64);
    write_slot(
        SLOT_RUNTIME_CHANNEL_ACTUAL_BYTES,
        summary.channel_actual_bytes,
    );
    write_slot(SLOT_RUNTIME_CHANNEL_MATCH, summary.channel_match);
    write_slot(SLOT_RUNTIME_ARM_TIMER, summary.arm_timer as u64);
    write_slot(SLOT_RUNTIME_TIMER_SET, summary.timer_set as u64);
    write_slot(SLOT_RUNTIME_WAIT_TIMER, summary.wait_timer as u64);
    write_slot(SLOT_RUNTIME_TIMER_EVENT_KEY, summary.timer_event_key);
    write_slot(SLOT_RUNTIME_TIMER_EVENT_TYPE, summary.timer_event_type);
    write_slot(
        SLOT_RUNTIME_TIMER_EVENT_OBSERVED,
        summary.timer_event_observed,
    );
    write_slot(SLOT_RUNTIME_TIMER_CANCEL, summary.timer_cancel as u64);
    write_slot(SLOT_RUNTIME_CLOSE_TX, summary.close_tx as u64);
    write_slot(SLOT_RUNTIME_CLOSE_RX, summary.close_rx as u64);
    write_slot(SLOT_RUNTIME_CLOSE_TIMER, summary.close_timer as u64);
    write_slot(SLOT_RUNTIME_CLOSE_PORT, summary.close_port as u64);
}

fn deadline_after(base: u64, delta_ns: i64) -> zx_time_t {
    (base as i64).saturating_add(delta_ns)
}

fn record_signal_event(
    event: &Event,
    expected_key: u64,
    expected_signal: u32,
    key_out: &mut u64,
    type_out: &mut u64,
    observed_out: &mut u64,
) -> bool {
    *key_out = event.key();
    *type_out = event.packet_type() as u64;
    *observed_out = event.observed_signals().unwrap_or(0) as u64;

    matches!(
        event,
        Event::Signal(signal)
            if signal.key == expected_key && (signal.observed & expected_signal) != 0
    )
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
