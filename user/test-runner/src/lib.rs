//! Shared conformance checks for the Nexus userspace test runner.
//!
//! This module is `no_std` and can be called from early kernel bring-up as a
//! temporary bridge until real userspace launch is wired.

#![no_std]
#![forbid(unsafe_code)]

use axle_types::clock::ZX_CLOCK_MONOTONIC;
use axle_types::packet::ZX_PKT_TYPE_USER;
use axle_types::status::{ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_SYSCALL, ZX_ERR_SHOULD_WAIT, ZX_OK};
use axle_types::syscall_numbers::{
    AXLE_SYS_HANDLE_CLOSE, AXLE_SYS_PORT_CREATE, AXLE_SYS_PORT_QUEUE, AXLE_SYS_PORT_WAIT,
    AXLE_SYS_TIMER_CANCEL, AXLE_SYS_TIMER_CREATE, AXLE_SYS_TIMER_SET,
};
use axle_types::{zx_handle_t, zx_packet_user_t, zx_port_packet_t, zx_status_t};

/// Aggregate syscall statuses captured during the conformance run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Int80ConformanceSummary {
    pub unknown: zx_status_t,
    pub bad_wait: zx_status_t,
    pub empty_wait: zx_status_t,
    pub queue: zx_status_t,
    pub wait: zx_status_t,
    pub timer_set: zx_status_t,
    pub timer_cancel: zx_status_t,
    pub close: zx_status_t,
    pub close_again: zx_status_t,
    pub port_h: zx_handle_t,
    pub timer_h: zx_handle_t,
}

/// Failure returned by [`run_int80_conformance`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Int80ConformanceFailure {
    pub step: &'static str,
    pub expected: i64,
    pub got: i64,
}

impl Int80ConformanceFailure {
    const fn status(step: &'static str, expected: zx_status_t, got: zx_status_t) -> Self {
        Self {
            step,
            expected: expected as i64,
            got: got as i64,
        }
    }

    const fn value(step: &'static str, expected: i64, got: i64) -> Self {
        Self {
            step,
            expected,
            got,
        }
    }
}

/// Run the bootstrap syscall conformance checks through `int 0x80`.
pub fn run_int80_conformance() -> Result<Int80ConformanceSummary, Int80ConformanceFailure> {
    // Unknown syscall id should fail with BAD_SYSCALL.
    let unknown_status = run_int80(u64::MAX, [0; 6]);
    if unknown_status != ZX_ERR_BAD_SYSCALL {
        return Err(Int80ConformanceFailure::status(
            "unknown_syscall",
            ZX_ERR_BAD_SYSCALL,
            unknown_status,
        ));
    }

    // Port wait with invalid handle must fail with BAD_HANDLE.
    let mut bad_wait_packet = zx_port_packet_t::default();
    let bad_port_wait_status = run_int80(
        AXLE_SYS_PORT_WAIT as u64,
        [
            0,
            0,
            (&mut bad_wait_packet as *mut zx_port_packet_t) as u64,
            0,
            0,
            0,
        ],
    );
    if bad_port_wait_status != ZX_ERR_BAD_HANDLE {
        return Err(Int80ConformanceFailure::status(
            "port_wait_bad_handle",
            ZX_ERR_BAD_HANDLE,
            bad_port_wait_status,
        ));
    }

    // Port create should succeed and return a non-zero handle.
    let mut port_handle: zx_handle_t = 0;
    let port_create_status = run_int80(
        AXLE_SYS_PORT_CREATE as u64,
        [0, (&mut port_handle as *mut zx_handle_t) as u64, 0, 0, 0, 0],
    );
    if port_create_status != ZX_OK {
        return Err(Int80ConformanceFailure::status(
            "port_create_status",
            ZX_OK,
            port_create_status,
        ));
    }
    if port_handle == 0 {
        return Err(Int80ConformanceFailure::value(
            "port_create_handle_nonzero",
            1,
            0,
        ));
    }

    // Empty wait should report SHOULD_WAIT.
    let mut empty_wait_packet = zx_port_packet_t::default();
    let empty_wait_status = run_int80(
        AXLE_SYS_PORT_WAIT as u64,
        [
            port_handle as u64,
            0,
            (&mut empty_wait_packet as *mut zx_port_packet_t) as u64,
            0,
            0,
            0,
        ],
    );
    if empty_wait_status != ZX_ERR_SHOULD_WAIT {
        return Err(Int80ConformanceFailure::status(
            "port_wait_empty",
            ZX_ERR_SHOULD_WAIT,
            empty_wait_status,
        ));
    }

    // Queue a user packet and verify wait roundtrip.
    let tx_packet = zx_port_packet_t {
        key: 0xAA55_AA55_AA55_AA55,
        type_: ZX_PKT_TYPE_USER,
        status: -123,
        user: zx_packet_user_t {
            u64: [0x11, 0x22, 0x33, 0x44],
        },
    };
    let queue_status = run_int80(
        AXLE_SYS_PORT_QUEUE as u64,
        [
            port_handle as u64,
            (&tx_packet as *const zx_port_packet_t) as u64,
            0,
            0,
            0,
            0,
        ],
    );
    if queue_status != ZX_OK {
        return Err(Int80ConformanceFailure::status(
            "port_queue",
            ZX_OK,
            queue_status,
        ));
    }

    let mut rx_packet = zx_port_packet_t::default();
    let wait_status = run_int80(
        AXLE_SYS_PORT_WAIT as u64,
        [
            port_handle as u64,
            0,
            (&mut rx_packet as *mut zx_port_packet_t) as u64,
            0,
            0,
            0,
        ],
    );
    if wait_status != ZX_OK {
        return Err(Int80ConformanceFailure::status(
            "port_wait",
            ZX_OK,
            wait_status,
        ));
    }
    if rx_packet != tx_packet {
        return Err(Int80ConformanceFailure::value(
            "port_roundtrip_packet",
            1,
            0,
        ));
    }

    // Timer create should succeed and return a non-zero handle.
    let mut timer_handle: zx_handle_t = 0;
    let timer_create_status = run_int80(
        AXLE_SYS_TIMER_CREATE as u64,
        [
            0,
            ZX_CLOCK_MONOTONIC as u64,
            (&mut timer_handle as *mut zx_handle_t) as u64,
            0,
            0,
            0,
        ],
    );
    if timer_create_status != ZX_OK {
        return Err(Int80ConformanceFailure::status(
            "timer_create_status",
            ZX_OK,
            timer_create_status,
        ));
    }
    if timer_handle == 0 {
        return Err(Int80ConformanceFailure::value(
            "timer_create_handle_nonzero",
            1,
            0,
        ));
    }

    let timer_set_status = run_int80(
        AXLE_SYS_TIMER_SET as u64,
        [timer_handle as u64, 123_456, 0, 0, 0, 0],
    );
    if timer_set_status != ZX_OK {
        return Err(Int80ConformanceFailure::status(
            "timer_set",
            ZX_OK,
            timer_set_status,
        ));
    }

    let timer_cancel_status = run_int80(
        AXLE_SYS_TIMER_CANCEL as u64,
        [timer_handle as u64, 0, 0, 0, 0, 0],
    );
    if timer_cancel_status != ZX_OK {
        return Err(Int80ConformanceFailure::status(
            "timer_cancel",
            ZX_OK,
            timer_cancel_status,
        ));
    }

    // handle_close should succeed once then fail with BAD_HANDLE when repeated.
    let close_status = run_int80(
        AXLE_SYS_HANDLE_CLOSE as u64,
        [port_handle as u64, 0, 0, 0, 0, 0],
    );
    if close_status != ZX_OK {
        return Err(Int80ConformanceFailure::status(
            "handle_close",
            ZX_OK,
            close_status,
        ));
    }

    let close_again_status = run_int80(
        AXLE_SYS_HANDLE_CLOSE as u64,
        [port_handle as u64, 0, 0, 0, 0, 0],
    );
    if close_again_status != ZX_ERR_BAD_HANDLE {
        return Err(Int80ConformanceFailure::status(
            "handle_close_again",
            ZX_ERR_BAD_HANDLE,
            close_again_status,
        ));
    }

    Ok(Int80ConformanceSummary {
        unknown: unknown_status,
        bad_wait: bad_port_wait_status,
        empty_wait: empty_wait_status,
        queue: queue_status,
        wait: wait_status,
        timer_set: timer_set_status,
        timer_cancel: timer_cancel_status,
        close: close_status,
        close_again: close_again_status,
        port_h: port_handle,
        timer_h: timer_handle,
    })
}

fn run_int80(nr: u64, args: [u64; 6]) -> zx_status_t {
    axle_arch_x86_64::int80_syscall(nr, args)
}
