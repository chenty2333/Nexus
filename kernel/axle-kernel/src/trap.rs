//! Trap/exception/interrupt scaffolding (Phase B).
//!
//! TODO: build IDT, fault handlers, IRQ handlers, IPI.

use axle_types::clock::ZX_CLOCK_MONOTONIC;
use axle_types::status::{ZX_ERR_BAD_SYSCALL, ZX_ERR_NOT_SUPPORTED};
use axle_types::syscall_numbers::{
    AXLE_SYS_HANDLE_CLOSE, AXLE_SYS_PORT_CREATE, AXLE_SYS_PORT_WAIT, AXLE_SYS_TIMER_CREATE,
};
use axle_types::{zx_handle_t, zx_status_t};

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
    let bad_port_wait_status = run_int80(AXLE_SYS_PORT_WAIT as u64, [0, 0, 0, 0, 0, 0]);
    if bad_port_wait_status != axle_types::status::ZX_ERR_BAD_HANDLE {
        panic!(
            "int80 self-test failed: expected {}, got {} for bad AXLE_SYS_PORT_WAIT",
            axle_types::status::ZX_ERR_BAD_HANDLE,
            bad_port_wait_status
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

    // Known syscall id with a valid handle (wired in dispatch but still unimplemented)
    // should currently return NOT_SUPPORTED.
    let known_status = run_int80(
        AXLE_SYS_PORT_WAIT as u64,
        [port_handle as u64, 0, 0, 0, 0, 0],
    );
    if known_status != ZX_ERR_NOT_SUPPORTED {
        panic!(
            "int80 self-test failed: expected {}, got {} for AXLE_SYS_PORT_WAIT(valid handle)",
            ZX_ERR_NOT_SUPPORTED, known_status
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
    if close_again_status != axle_types::status::ZX_ERR_BAD_HANDLE {
        panic!(
            "int80 self-test failed: expected {}, got {} for repeated handle_close",
            axle_types::status::ZX_ERR_BAD_HANDLE,
            close_again_status
        );
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

    crate::kprintln!(
        "trap: int80 self-test ok (unknown={}, bad_wait={}, known_wait={}, close={}, close_again={}, port_h={}, timer_h={})",
        unknown_status,
        bad_port_wait_status,
        known_status,
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
