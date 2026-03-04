//! Syscall entry/dispatch scaffolding (Phase B).
//!
//! In the Zircon model, userspace typically calls into the vDSO stubs,
//! which then enters the kernel with a syscall number and arguments.
//!
//! This module will eventually:
//! - validate arguments
//! - perform handle lookup (CSpace + rights + revocation)
//! - dispatch to object-specific handlers (Channel/Port/Timer/etc)

#![allow(dead_code)]

use axle_types::status::{ZX_ERR_BAD_SYSCALL, ZX_ERR_INVALID_ARGS, ZX_ERR_NOT_SUPPORTED, ZX_OK};
use axle_types::syscall_numbers::{
    AXLE_SYS_HANDLE_CLOSE, AXLE_SYS_OBJECT_WAIT_ASYNC, AXLE_SYS_OBJECT_WAIT_ONE,
    AXLE_SYS_PORT_CREATE, AXLE_SYS_PORT_QUEUE, AXLE_SYS_PORT_WAIT, AXLE_SYS_TIMER_CANCEL,
    AXLE_SYS_TIMER_CREATE, AXLE_SYS_TIMER_SET, SyscallNumber,
};
use axle_types::{
    zx_clock_t, zx_duration_t, zx_handle_t, zx_port_packet_t, zx_signals_t, zx_status_t, zx_time_t,
};

/// Phase-B bootstrap syscall numbers supported by the shared ABI spec.
pub const BOOTSTRAP_SYSCALLS: [SyscallNumber; 9] = [
    AXLE_SYS_HANDLE_CLOSE,
    AXLE_SYS_OBJECT_WAIT_ONE,
    AXLE_SYS_OBJECT_WAIT_ASYNC,
    AXLE_SYS_PORT_CREATE,
    AXLE_SYS_PORT_QUEUE,
    AXLE_SYS_PORT_WAIT,
    AXLE_SYS_TIMER_CREATE,
    AXLE_SYS_TIMER_SET,
    AXLE_SYS_TIMER_CANCEL,
];

// Compile-time witness that kernel syscall layer consumes shared ABI types.
const _ABI_TYPES_WITNESS: Option<(
    zx_handle_t,
    zx_signals_t,
    zx_time_t,
    zx_duration_t,
    zx_clock_t,
    zx_port_packet_t,
    zx_status_t,
)> = None;

pub fn init() {
    crate::object::init();

    // Placeholder.
    //
    // Keep a reference so the compiler proves this module is wired to the shared
    // syscall-number source.
    let _ = BOOTSTRAP_SYSCALLS;
}

/// Dispatch one syscall number + up to 6 arguments.
///
/// Unknown numbers return `ZX_ERR_BAD_SYSCALL`.
/// Known-but-not-yet-implemented syscalls return `ZX_ERR_NOT_SUPPORTED`.
pub fn dispatch_syscall(nr: SyscallNumber, args: [u64; 6]) -> zx_status_t {
    match nr {
        AXLE_SYS_HANDLE_CLOSE => sys_handle_close(args),
        AXLE_SYS_OBJECT_WAIT_ONE => sys_object_wait_one(args),
        AXLE_SYS_OBJECT_WAIT_ASYNC => sys_object_wait_async(args),
        AXLE_SYS_PORT_CREATE => sys_port_create(args),
        AXLE_SYS_PORT_QUEUE => sys_port_queue(args),
        AXLE_SYS_PORT_WAIT => sys_port_wait(args),
        AXLE_SYS_TIMER_CREATE => sys_timer_create(args),
        AXLE_SYS_TIMER_SET => sys_timer_set(args),
        AXLE_SYS_TIMER_CANCEL => sys_timer_cancel(args),
        _ => ZX_ERR_BAD_SYSCALL,
    }
}

/// Dispatch a syscall from the architecture trap frame and write status back.
pub fn invoke_from_trapframe(frame: &mut crate::arch::int80::TrapFrame) {
    let status = match u32::try_from(frame.syscall_nr()) {
        Ok(nr) => dispatch_syscall(nr, frame.args()),
        Err(_) => ZX_ERR_BAD_SYSCALL,
    };
    frame.set_status(status);
}

fn sys_handle_close(args: [u64; 6]) -> zx_status_t {
    let handle = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    match crate::object::close_handle(handle) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_object_wait_one(_args: [u64; 6]) -> zx_status_t {
    ZX_ERR_NOT_SUPPORTED
}

fn sys_object_wait_async(_args: [u64; 6]) -> zx_status_t {
    ZX_ERR_NOT_SUPPORTED
}

fn sys_port_create(args: [u64; 6]) -> zx_status_t {
    let options = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };

    let out_ptr = args[1] as *mut zx_handle_t;
    if out_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    let h = match crate::object::create_port(options) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // SAFETY: for current bring-up we trust the caller-provided pointer; later
    // phases will replace this with strict copyout validation.
    unsafe {
        out_ptr.write(h);
    }
    ZX_OK
}

fn sys_port_queue(args: [u64; 6]) -> zx_status_t {
    let handle = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let packet_ptr = args[1] as *const zx_port_packet_t;
    if packet_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    // SAFETY: for current bring-up we trust the caller-provided pointer; later
    // phases will replace this with strict copyin validation.
    let packet = unsafe { packet_ptr.read() };
    match crate::object::queue_port_packet(handle, packet) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_port_wait(args: [u64; 6]) -> zx_status_t {
    let handle = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let out_ptr = args[2] as *mut zx_port_packet_t;
    if out_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    match crate::object::wait_port_packet(handle) {
        Ok(packet) => {
            // SAFETY: for current bring-up we trust the caller-provided pointer; later
            // phases will replace this with strict copyout validation.
            unsafe {
                out_ptr.write(packet);
            }
            ZX_OK
        }
        Err(e) => e,
    }
}

fn sys_timer_create(args: [u64; 6]) -> zx_status_t {
    let options = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let clock_id = match u32::try_from(args[1]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let out_ptr = args[2] as *mut zx_handle_t;
    if out_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    let h = match crate::object::create_timer(options, clock_id) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // SAFETY: for current bring-up we trust the caller-provided pointer; later
    // phases will replace this with strict copyout validation.
    unsafe {
        out_ptr.write(h);
    }
    ZX_OK
}

fn sys_timer_set(args: [u64; 6]) -> zx_status_t {
    let handle = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let deadline = args[1] as i64;
    let slack = args[2] as i64;
    match crate::object::timer_set(handle, deadline, slack) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_timer_cancel(args: [u64; 6]) -> zx_status_t {
    let handle = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    match crate::object::timer_cancel(handle) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}
