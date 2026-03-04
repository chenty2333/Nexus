//! Trap/exception/interrupt scaffolding (Phase B).
//!
//! TODO: build IDT, fault handlers, IRQ handlers, IPI.

use axle_types::clock::ZX_CLOCK_MONOTONIC;
use axle_types::packet::ZX_PKT_TYPE_USER;
use axle_types::status::{ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_SYSCALL, ZX_ERR_SHOULD_WAIT};
use axle_types::syscall_numbers::{
    AXLE_SYS_HANDLE_CLOSE, AXLE_SYS_PORT_CREATE, AXLE_SYS_PORT_QUEUE, AXLE_SYS_PORT_WAIT,
    AXLE_SYS_TIMER_CANCEL, AXLE_SYS_TIMER_CREATE, AXLE_SYS_TIMER_SET,
};
use axle_types::{zx_handle_t, zx_packet_user_t, zx_port_packet_t, zx_status_t};

use crate::arch;

pub fn init() {
    arch::idt::init_int80_gate(arch::int80::entry_addr());
    int80_self_test();
}

fn int80_self_test() {
    // Unknown syscall id should fail with BAD_SYSCALL.
    let unknown_status = run_int80(u64::MAX, [0; 6]);
    if unknown_status != ZX_ERR_BAD_SYSCALL {
        panic!(
            "int80 self-test failed: expected {}, got {}",
            ZX_ERR_BAD_SYSCALL, unknown_status
        );
    }

    // Port wait with an invalid handle must fail with BAD_HANDLE.
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
        panic!(
            "int80 self-test failed: expected {}, got {} for bad AXLE_SYS_PORT_WAIT",
            ZX_ERR_BAD_HANDLE, bad_port_wait_status
        );
    }

    // Port create should succeed and return a non-zero handle.
    let mut port_handle: zx_handle_t = 0;
    let port_create_status = run_int80(
        AXLE_SYS_PORT_CREATE as u64,
        [0, (&mut port_handle as *mut zx_handle_t) as u64, 0, 0, 0, 0],
    );
    if port_create_status != axle_types::status::ZX_OK || port_handle == 0 {
        panic!(
            "int80 self-test failed: port_create status={}, handle={}",
            port_create_status, port_handle
        );
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
        panic!(
            "int80 self-test failed: expected {}, got {} for empty AXLE_SYS_PORT_WAIT",
            ZX_ERR_SHOULD_WAIT, empty_wait_status
        );
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
    if queue_status != axle_types::status::ZX_OK {
        panic!(
            "int80 self-test failed: port_queue status={}, handle={}",
            queue_status, port_handle
        );
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
    if wait_status != axle_types::status::ZX_OK {
        panic!(
            "int80 self-test failed: port_wait status={}, handle={}",
            wait_status, port_handle
        );
    }
    if rx_packet != tx_packet {
        panic!("int80 self-test failed: queued packet did not roundtrip");
    }

    // Timer create should also succeed and return a non-zero handle.
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
    if timer_create_status != axle_types::status::ZX_OK || timer_handle == 0 {
        panic!(
            "int80 self-test failed: timer_create status={}, handle={}",
            timer_create_status, timer_handle
        );
    }

    let timer_set_status = run_int80(
        AXLE_SYS_TIMER_SET as u64,
        [timer_handle as u64, 123_456, 0, 0, 0, 0],
    );
    if timer_set_status != axle_types::status::ZX_OK {
        panic!(
            "int80 self-test failed: timer_set status={}, handle={}",
            timer_set_status, timer_handle
        );
    }

    let timer_cancel_status = run_int80(
        AXLE_SYS_TIMER_CANCEL as u64,
        [timer_handle as u64, 0, 0, 0, 0, 0],
    );
    if timer_cancel_status != axle_types::status::ZX_OK {
        panic!(
            "int80 self-test failed: timer_cancel status={}, handle={}",
            timer_cancel_status, timer_handle
        );
    }

    // handle_close should succeed once then fail with BAD_HANDLE when repeated.
    let close_status = run_int80(
        AXLE_SYS_HANDLE_CLOSE as u64,
        [port_handle as u64, 0, 0, 0, 0, 0],
    );
    if close_status != axle_types::status::ZX_OK {
        panic!(
            "int80 self-test failed: handle_close status={}, handle={}",
            close_status, port_handle
        );
    }

    let close_again_status = run_int80(
        AXLE_SYS_HANDLE_CLOSE as u64,
        [port_handle as u64, 0, 0, 0, 0, 0],
    );
    if close_again_status != ZX_ERR_BAD_HANDLE {
        panic!(
            "int80 self-test failed: expected {}, got {} for repeated handle_close",
            ZX_ERR_BAD_HANDLE, close_again_status
        );
    }

    crate::kprintln!(
        "trap: int80 self-test ok (unknown={}, bad_wait={}, empty_wait={}, queue={}, wait={}, timer_set={}, timer_cancel={}, close={}, close_again={}, port_h={}, timer_h={})",
        unknown_status,
        bad_port_wait_status,
        empty_wait_status,
        queue_status,
        wait_status,
        timer_set_status,
        timer_cancel_status,
        close_status,
        close_again_status,
        port_handle,
        timer_handle
    );
}

fn run_int80(nr: u64, args: [u64; 6]) -> zx_status_t {
    let ret_rax: u64;

    // SAFETY: this executes a software interrupt through the installed 0x80 gate
    // in early boot and captures the return status from `rax`.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") nr => ret_rax,
            in("rdi") args[0],
            in("rsi") args[1],
            in("rdx") args[2],
            in("r10") args[3],
            in("r8") args[4],
            in("r9") args[5],
            clobber_abi("sysv64"),
        );
    }

    ret_rax as i32
}
