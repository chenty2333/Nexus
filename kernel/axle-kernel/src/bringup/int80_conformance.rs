//! Minimal syscall conformance checks driven through the `int 0x80` entry path.
//!
//! This is an early bring-up bridge until we can run `user/test-runner` in ring3.

use axle_types::clock::ZX_CLOCK_MONOTONIC;
use axle_types::packet::{ZX_PKT_TYPE_SIGNAL_ONE, ZX_PKT_TYPE_USER};
use axle_types::signals::ZX_TIMER_SIGNALED;
use axle_types::status::{
    ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_SYSCALL, ZX_ERR_INVALID_ARGS, ZX_ERR_SHOULD_WAIT,
    ZX_ERR_TIMED_OUT, ZX_ERR_WRONG_TYPE, ZX_OK,
};
use axle_types::syscall_numbers::{
    AXLE_SYS_HANDLE_CLOSE, AXLE_SYS_OBJECT_WAIT_ASYNC, AXLE_SYS_OBJECT_WAIT_ONE, AXLE_SYS_PORT_CREATE,
    AXLE_SYS_PORT_QUEUE, AXLE_SYS_PORT_WAIT, AXLE_SYS_TIMER_CANCEL, AXLE_SYS_TIMER_CREATE,
    AXLE_SYS_TIMER_SET,
};
use axle_types::{zx_handle_t, zx_packet_signal_t, zx_packet_user_t, zx_port_packet_t, zx_signals_t, zx_status_t};

#[derive(Clone, Copy, Debug)]
struct Summary {
    unknown: zx_status_t,
    close_invalid: zx_status_t,
    port_create_bad_opts: zx_status_t,
    port_create_null_out: zx_status_t,
    bad_wait: zx_status_t,
    port_wait_null_out: zx_status_t,
    empty_wait: zx_status_t,
    port_queue_null_pkt: zx_status_t,
    port_queue_bad_type: zx_status_t,
    queue: zx_status_t,
    wait: zx_status_t,
    timer_create_bad_opts: zx_status_t,
    timer_create_bad_clock: zx_status_t,
    timer_create_null_out: zx_status_t,
    port_wait_wrong_type: zx_status_t,
    port_queue_wrong_type: zx_status_t,
    timer_set_wrong_type: zx_status_t,
    timer_cancel_wrong_type: zx_status_t,
    wait_one_unsignaled: zx_status_t,
    wait_one_unsignaled_observed: zx_signals_t,
    wait_async: zx_status_t,
    timer_set_immediate: zx_status_t,
    wait_signal: zx_status_t,
    signal_trigger: zx_signals_t,
    signal_observed: zx_signals_t,
    signal_count: u64,
    wait_one_signaled: zx_status_t,
    wait_one_signaled_observed: zx_signals_t,
    timer_set: zx_status_t,
    timer_cancel: zx_status_t,
    timer_close: zx_status_t,
    timer_close_again: zx_status_t,
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
            "kernel: int80 conformance ok (unknown={}, close_invalid={}, port_create_bad_opts={}, port_create_null_out={}, bad_wait={}, port_wait_null_out={}, empty_wait={}, port_queue_null_pkt={}, port_queue_bad_type={}, queue={}, wait={}, timer_create_bad_opts={}, timer_create_bad_clock={}, timer_create_null_out={}, port_wait_wrong_type={}, port_queue_wrong_type={}, timer_set_wrong_type={}, timer_cancel_wrong_type={}, wait_one_unsignaled={}, wait_one_unsignaled_observed={}, wait_async={}, timer_set_immediate={}, wait_signal={}, signal_trigger={}, signal_observed={}, signal_count={}, wait_one_signaled={}, wait_one_signaled_observed={}, timer_set={}, timer_cancel={}, timer_close={}, timer_close_again={}, close={}, close_again={}, port_h={}, timer_h={})",
            s.unknown,
            s.close_invalid,
            s.port_create_bad_opts,
            s.port_create_null_out,
            s.bad_wait,
            s.port_wait_null_out,
            s.empty_wait,
            s.port_queue_null_pkt,
            s.port_queue_bad_type,
            s.queue,
            s.wait,
            s.timer_create_bad_opts,
            s.timer_create_bad_clock,
            s.timer_create_null_out,
            s.port_wait_wrong_type,
            s.port_queue_wrong_type,
            s.timer_set_wrong_type,
            s.timer_cancel_wrong_type,
            s.wait_one_unsignaled,
            s.wait_one_unsignaled_observed,
            s.wait_async,
            s.timer_set_immediate,
            s.wait_signal,
            s.signal_trigger,
            s.signal_observed,
            s.signal_count,
            s.wait_one_signaled,
            s.wait_one_signaled_observed,
            s.timer_set,
            s.timer_cancel,
            s.timer_close,
            s.timer_close_again,
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

fn expect(step: &'static str, got: zx_status_t, expected: zx_status_t) -> Result<(), Failure> {
    if got == expected {
        Ok(())
    } else {
        Err(Failure::new(step, expected, got))
    }
}

fn run_int80_conformance() -> Result<Summary, Failure> {
    let unknown = run_int80(u64::MAX, [0; 6]);
    expect("unknown_syscall", unknown, ZX_ERR_BAD_SYSCALL)?;

    let close_invalid = run_int80(AXLE_SYS_HANDLE_CLOSE as u64, [0, 0, 0, 0, 0, 0]);
    expect("handle_close_invalid", close_invalid, ZX_ERR_BAD_HANDLE)?;

    let mut ignored_handle: zx_handle_t = 0;
    let port_create_bad_opts = run_int80(
        AXLE_SYS_PORT_CREATE as u64,
        [1, (&mut ignored_handle as *mut zx_handle_t) as u64, 0, 0, 0, 0],
    );
    expect("port_create_bad_opts", port_create_bad_opts, ZX_ERR_INVALID_ARGS)?;

    let port_create_null_out = run_int80(AXLE_SYS_PORT_CREATE as u64, [0, 0, 0, 0, 0, 0]);
    expect("port_create_null_out", port_create_null_out, ZX_ERR_INVALID_ARGS)?;

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
    expect("port_wait_bad_handle", bad_wait, ZX_ERR_BAD_HANDLE)?;

    let mut port_h: zx_handle_t = 0;
    let port_create = run_int80(
        AXLE_SYS_PORT_CREATE as u64,
        [0, (&mut port_h as *mut zx_handle_t) as u64, 0, 0, 0, 0],
    );
    expect("port_create", port_create, ZX_OK)?;
    if port_h == 0 {
        return Err(Failure::new("port_handle_nonzero", ZX_OK, -1));
    }

    let port_wait_null_out = run_int80(AXLE_SYS_PORT_WAIT as u64, [port_h as u64, 0, 0, 0, 0, 0]);
    expect("port_wait_null_out", port_wait_null_out, ZX_ERR_INVALID_ARGS)?;

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
    expect("port_wait_empty", empty_wait, ZX_ERR_SHOULD_WAIT)?;

    let port_queue_null_pkt = run_int80(AXLE_SYS_PORT_QUEUE as u64, [port_h as u64, 0, 0, 0, 0, 0]);
    expect("port_queue_null_pkt", port_queue_null_pkt, ZX_ERR_INVALID_ARGS)?;

    let bad_type_packet = zx_port_packet_t {
        key: 0,
        type_: ZX_PKT_TYPE_USER + 1,
        status: 0,
        user: zx_packet_user_t { u64: [0; 4] },
    };
    let port_queue_bad_type = run_int80(
        AXLE_SYS_PORT_QUEUE as u64,
        [
            port_h as u64,
            (&bad_type_packet as *const zx_port_packet_t) as u64,
            0,
            0,
            0,
            0,
        ],
    );
    expect("port_queue_bad_type", port_queue_bad_type, ZX_ERR_INVALID_ARGS)?;

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
    expect("port_queue", queue, ZX_OK)?;

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
    expect("port_wait_roundtrip", wait, ZX_OK)?;
    if rx_packet != tx_packet {
        return Err(Failure::new("port_packet_mismatch", ZX_OK, -1));
    }

    let mut ignored_timer: zx_handle_t = 0;
    let timer_create_bad_opts = run_int80(
        AXLE_SYS_TIMER_CREATE as u64,
        [
            1,
            ZX_CLOCK_MONOTONIC as u64,
            (&mut ignored_timer as *mut zx_handle_t) as u64,
            0,
            0,
            0,
        ],
    );
    expect("timer_create_bad_opts", timer_create_bad_opts, ZX_ERR_INVALID_ARGS)?;

    let timer_create_bad_clock = run_int80(
        AXLE_SYS_TIMER_CREATE as u64,
        [
            0,
            ZX_CLOCK_MONOTONIC as u64 + 1,
            (&mut ignored_timer as *mut zx_handle_t) as u64,
            0,
            0,
            0,
        ],
    );
    expect(
        "timer_create_bad_clock",
        timer_create_bad_clock,
        ZX_ERR_INVALID_ARGS,
    )?;

    let timer_create_null_out = run_int80(
        AXLE_SYS_TIMER_CREATE as u64,
        [0, ZX_CLOCK_MONOTONIC as u64, 0, 0, 0, 0],
    );
    expect(
        "timer_create_null_out",
        timer_create_null_out,
        ZX_ERR_INVALID_ARGS,
    )?;

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
    expect("timer_create", timer_create, ZX_OK)?;
    if timer_h == 0 {
        return Err(Failure::new("timer_handle_nonzero", ZX_OK, -1));
    }

    let mut wait_one_unsignaled_observed: zx_signals_t = 0;
    let wait_one_unsignaled = run_int80(
        AXLE_SYS_OBJECT_WAIT_ONE as u64,
        [
            timer_h as u64,
            ZX_TIMER_SIGNALED as u64,
            0,
            (&mut wait_one_unsignaled_observed as *mut zx_signals_t) as u64,
            0,
            0,
        ],
    );
    expect("wait_one_unsignaled", wait_one_unsignaled, ZX_ERR_TIMED_OUT)?;
    if wait_one_unsignaled_observed != 0 {
        return Err(Failure::new("wait_one_unsignaled_observed", ZX_OK, -1));
    }

    const SIGNAL_KEY: u64 = 0x1234;
    let wait_async = run_int80(
        AXLE_SYS_OBJECT_WAIT_ASYNC as u64,
        [
            timer_h as u64,
            port_h as u64,
            SIGNAL_KEY,
            ZX_TIMER_SIGNALED as u64,
            0,
            0,
        ],
    );
    expect("wait_async", wait_async, ZX_OK)?;

    // Bring-up: deadline <= 0 fires immediately (fake clock starts at 0).
    let timer_set_immediate = run_int80(
        AXLE_SYS_TIMER_SET as u64,
        [timer_h as u64, 0, 0, 0, 0, 0],
    );
    expect("timer_set_immediate", timer_set_immediate, ZX_OK)?;

    let mut signal_packet = zx_port_packet_t::default();
    let wait_signal = run_int80(
        AXLE_SYS_PORT_WAIT as u64,
        [
            port_h as u64,
            0,
            (&mut signal_packet as *mut zx_port_packet_t) as u64,
            0,
            0,
            0,
        ],
    );
    expect("port_wait_signal", wait_signal, ZX_OK)?;
    if signal_packet.key != SIGNAL_KEY {
        return Err(Failure::new("signal_key", ZX_OK, -1));
    }
    if signal_packet.type_ != ZX_PKT_TYPE_SIGNAL_ONE {
        return Err(Failure::new("signal_type", ZX_OK, -1));
    }

    let sig = zx_packet_signal_t::from_user(signal_packet.user);
    if sig.trigger != ZX_TIMER_SIGNALED {
        return Err(Failure::new("signal_trigger", ZX_OK, -1));
    }
    if (sig.observed & ZX_TIMER_SIGNALED) == 0 {
        return Err(Failure::new("signal_observed", ZX_OK, -1));
    }
    if sig.count < 1 {
        return Err(Failure::new("signal_count", ZX_OK, -1));
    }

    let mut wait_one_signaled_observed: zx_signals_t = 0;
    let wait_one_signaled = run_int80(
        AXLE_SYS_OBJECT_WAIT_ONE as u64,
        [
            timer_h as u64,
            ZX_TIMER_SIGNALED as u64,
            0,
            (&mut wait_one_signaled_observed as *mut zx_signals_t) as u64,
            0,
            0,
        ],
    );
    expect("wait_one_signaled", wait_one_signaled, ZX_OK)?;
    if (wait_one_signaled_observed & ZX_TIMER_SIGNALED) == 0 {
        return Err(Failure::new("wait_one_signaled_observed", ZX_OK, -1));
    }

    let port_wait_wrong_type = run_int80(
        AXLE_SYS_PORT_WAIT as u64,
        [
            timer_h as u64,
            0,
            (&mut bad_wait_packet as *mut zx_port_packet_t) as u64,
            0,
            0,
            0,
        ],
    );
    expect("port_wait_wrong_type", port_wait_wrong_type, ZX_ERR_WRONG_TYPE)?;

    let port_queue_wrong_type = run_int80(
        AXLE_SYS_PORT_QUEUE as u64,
        [
            timer_h as u64,
            (&tx_packet as *const zx_port_packet_t) as u64,
            0,
            0,
            0,
            0,
        ],
    );
    expect(
        "port_queue_wrong_type",
        port_queue_wrong_type,
        ZX_ERR_WRONG_TYPE,
    )?;

    let timer_set_wrong_type = run_int80(
        AXLE_SYS_TIMER_SET as u64,
        [port_h as u64, 123_456, 0, 0, 0, 0],
    );
    expect(
        "timer_set_wrong_type",
        timer_set_wrong_type,
        ZX_ERR_WRONG_TYPE,
    )?;

    let timer_cancel_wrong_type =
        run_int80(AXLE_SYS_TIMER_CANCEL as u64, [port_h as u64, 0, 0, 0, 0, 0]);
    expect(
        "timer_cancel_wrong_type",
        timer_cancel_wrong_type,
        ZX_ERR_WRONG_TYPE,
    )?;

    let timer_set = run_int80(
        AXLE_SYS_TIMER_SET as u64,
        [timer_h as u64, 123_456, 0, 0, 0, 0],
    );
    expect("timer_set", timer_set, ZX_OK)?;

    let timer_cancel = run_int80(
        AXLE_SYS_TIMER_CANCEL as u64,
        [timer_h as u64, 0, 0, 0, 0, 0],
    );
    expect("timer_cancel", timer_cancel, ZX_OK)?;

    let timer_close = run_int80(AXLE_SYS_HANDLE_CLOSE as u64, [timer_h as u64, 0, 0, 0, 0, 0]);
    expect("timer_close", timer_close, ZX_OK)?;
    let timer_close_again =
        run_int80(AXLE_SYS_HANDLE_CLOSE as u64, [timer_h as u64, 0, 0, 0, 0, 0]);
    expect(
        "timer_close_again",
        timer_close_again,
        ZX_ERR_BAD_HANDLE,
    )?;

    let close = run_int80(AXLE_SYS_HANDLE_CLOSE as u64, [port_h as u64, 0, 0, 0, 0, 0]);
    expect("handle_close", close, ZX_OK)?;
    let close_again = run_int80(AXLE_SYS_HANDLE_CLOSE as u64, [port_h as u64, 0, 0, 0, 0, 0]);
    expect("handle_close_again", close_again, ZX_ERR_BAD_HANDLE)?;

    Ok(Summary {
        unknown,
        close_invalid,
        port_create_bad_opts,
        port_create_null_out,
        bad_wait,
        port_wait_null_out,
        empty_wait,
        port_queue_null_pkt,
        port_queue_bad_type,
        queue,
        wait,
        timer_create_bad_opts,
        timer_create_bad_clock,
        timer_create_null_out,
        port_wait_wrong_type,
        port_queue_wrong_type,
        timer_set_wrong_type,
        timer_cancel_wrong_type,
        wait_one_unsignaled,
        wait_one_unsignaled_observed,
        wait_async,
        timer_set_immediate,
        wait_signal,
        signal_trigger: sig.trigger,
        signal_observed: sig.observed,
        signal_count: sig.count,
        wait_one_signaled,
        wait_one_signaled_observed,
        timer_set,
        timer_cancel,
        timer_close,
        timer_close_again,
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
