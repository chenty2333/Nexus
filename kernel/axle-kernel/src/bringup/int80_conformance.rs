//! Minimal syscall conformance checks driven through the `int 0x80` entry path.
//!
//! This is an early bring-up bridge until we can run `user/test-runner` in ring3.

use axle_types::clock::ZX_CLOCK_MONOTONIC;
use axle_types::packet::ZX_PKT_TYPE_USER;
use axle_types::status::{ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_SYSCALL, ZX_ERR_SHOULD_WAIT, ZX_OK};
use axle_types::syscall_numbers::{
    AXLE_SYS_HANDLE_CLOSE, AXLE_SYS_PORT_CREATE, AXLE_SYS_PORT_QUEUE, AXLE_SYS_PORT_WAIT,
    AXLE_SYS_TIMER_CANCEL, AXLE_SYS_TIMER_CREATE, AXLE_SYS_TIMER_SET,
};
use axle_types::{zx_handle_t, zx_packet_user_t, zx_port_packet_t, zx_status_t};

#[derive(Clone, Copy, Debug)]
struct Summary {
    unknown: zx_status_t,
    bad_wait: zx_status_t,
    empty_wait: zx_status_t,
    queue: zx_status_t,
    wait: zx_status_t,
    timer_set: zx_status_t,
    timer_cancel: zx_status_t,
    close: zx_status_t,
    close_again: zx_status_t,
    port_h: zx_handle_t,
    timer_h: zx_handle_t,
}

#[derive(Clone, Copy, Debug)]
struct Failure {
    step: &'static str,
    expected: zx_status_t,
    got: zx_status_t,
}

impl Failure {
    const fn new(step: &'static str, expected: zx_status_t, got: zx_status_t) -> Self {
        Self {
            step,
            expected,
            got,
        }
    }
}

pub fn run() {
    match run_int80_conformance() {
        Ok(s) => crate::kprintln!(
            "kernel: int80 conformance ok (unknown={}, bad_wait={}, empty_wait={}, queue={}, wait={}, timer_set={}, timer_cancel={}, close={}, close_again={}, port_h={}, timer_h={})",
            s.unknown,
            s.bad_wait,
            s.empty_wait,
            s.queue,
            s.wait,
            s.timer_set,
            s.timer_cancel,
            s.close,
            s.close_again,
            s.port_h,
            s.timer_h
        ),
        Err(f) => panic!(
            "kernel: int80 conformance failed (step={}, expected={}, got={})",
            f.step, f.expected, f.got
        ),
    }
}

fn run_int80_conformance() -> Result<Summary, Failure> {
    let unknown = run_int80(u64::MAX, [0; 6]);
    if unknown != ZX_ERR_BAD_SYSCALL {
        return Err(Failure::new("unknown_syscall", ZX_ERR_BAD_SYSCALL, unknown));
    }

    let mut bad_wait_packet = zx_port_packet_t::default();
    let bad_wait = run_int80(
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
    if bad_wait != ZX_ERR_BAD_HANDLE {
        return Err(Failure::new(
            "port_wait_bad_handle",
            ZX_ERR_BAD_HANDLE,
            bad_wait,
        ));
    }

    let mut port_h: zx_handle_t = 0;
    let port_create = run_int80(
        AXLE_SYS_PORT_CREATE as u64,
        [0, (&mut port_h as *mut zx_handle_t) as u64, 0, 0, 0, 0],
    );
    if port_create != ZX_OK {
        return Err(Failure::new("port_create", ZX_OK, port_create));
    }
    if port_h == 0 {
        return Err(Failure::new("port_handle_nonzero", ZX_OK, -1));
    }

    let mut empty_wait_packet = zx_port_packet_t::default();
    let empty_wait = run_int80(
        AXLE_SYS_PORT_WAIT as u64,
        [
            port_h as u64,
            0,
            (&mut empty_wait_packet as *mut zx_port_packet_t) as u64,
            0,
            0,
            0,
        ],
    );
    if empty_wait != ZX_ERR_SHOULD_WAIT {
        return Err(Failure::new(
            "port_wait_empty",
            ZX_ERR_SHOULD_WAIT,
            empty_wait,
        ));
    }

    let tx_packet = zx_port_packet_t {
        key: 0xAA55_AA55_AA55_AA55,
        type_: ZX_PKT_TYPE_USER,
        status: -123,
        user: zx_packet_user_t {
            u64: [0x11, 0x22, 0x33, 0x44],
        },
    };
    let queue = run_int80(
        AXLE_SYS_PORT_QUEUE as u64,
        [
            port_h as u64,
            (&tx_packet as *const zx_port_packet_t) as u64,
            0,
            0,
            0,
            0,
        ],
    );
    if queue != ZX_OK {
        return Err(Failure::new("port_queue", ZX_OK, queue));
    }

    let mut rx_packet = zx_port_packet_t::default();
    let wait = run_int80(
        AXLE_SYS_PORT_WAIT as u64,
        [
            port_h as u64,
            0,
            (&mut rx_packet as *mut zx_port_packet_t) as u64,
            0,
            0,
            0,
        ],
    );
    if wait != ZX_OK {
        return Err(Failure::new("port_wait_roundtrip", ZX_OK, wait));
    }
    if rx_packet != tx_packet {
        return Err(Failure::new("port_packet_mismatch", ZX_OK, -1));
    }

    let mut timer_h: zx_handle_t = 0;
    let timer_create = run_int80(
        AXLE_SYS_TIMER_CREATE as u64,
        [
            0,
            ZX_CLOCK_MONOTONIC as u64,
            (&mut timer_h as *mut zx_handle_t) as u64,
            0,
            0,
            0,
        ],
    );
    if timer_create != ZX_OK {
        return Err(Failure::new("timer_create", ZX_OK, timer_create));
    }
    if timer_h == 0 {
        return Err(Failure::new("timer_handle_nonzero", ZX_OK, -1));
    }

    let timer_set = run_int80(
        AXLE_SYS_TIMER_SET as u64,
        [timer_h as u64, 123_456, 0, 0, 0, 0],
    );
    if timer_set != ZX_OK {
        return Err(Failure::new("timer_set", ZX_OK, timer_set));
    }

    let timer_cancel = run_int80(
        AXLE_SYS_TIMER_CANCEL as u64,
        [timer_h as u64, 0, 0, 0, 0, 0],
    );
    if timer_cancel != ZX_OK {
        return Err(Failure::new("timer_cancel", ZX_OK, timer_cancel));
    }

    let close = run_int80(AXLE_SYS_HANDLE_CLOSE as u64, [port_h as u64, 0, 0, 0, 0, 0]);
    if close != ZX_OK {
        return Err(Failure::new("handle_close", ZX_OK, close));
    }
    let close_again = run_int80(AXLE_SYS_HANDLE_CLOSE as u64, [port_h as u64, 0, 0, 0, 0, 0]);
    if close_again != ZX_ERR_BAD_HANDLE {
        return Err(Failure::new(
            "handle_close_again",
            ZX_ERR_BAD_HANDLE,
            close_again,
        ));
    }

    Ok(Summary {
        unknown,
        bad_wait,
        empty_wait,
        queue,
        wait,
        timer_set,
        timer_cancel,
        close,
        close_again,
        port_h,
        timer_h,
    })
}

fn run_int80(nr: u64, args: [u64; 6]) -> zx_status_t {
    let mut rax = nr;
    let mut rdi = args[0];
    let mut rsi = args[1];
    let mut rdx = args[2];
    let mut r10 = args[3];
    let mut r8 = args[4];
    let mut r9 = args[5];

    // SAFETY: Executes `int 0x80` with the Phase-B calling convention.
    // The handler is expected to preserve callee-saved registers and return
    // a `zx_status_t` in `rax`.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("rax") rax,
            inout("rdi") rdi,
            inout("rsi") rsi,
            inout("rdx") rdx,
            inout("r10") r10,
            inout("r8") r8,
            inout("r9") r9,
            options(nostack),
        );
    }

    rax as zx_status_t
}
