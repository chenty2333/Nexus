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

use axle_core::{WaitAsyncOptions, WaitAsyncTimestamp};
use axle_types::status::{ZX_ERR_BAD_SYSCALL, ZX_ERR_INVALID_ARGS, ZX_ERR_NOT_SUPPORTED, ZX_OK};
use axle_types::syscall_numbers::{
    AXLE_SYS_HANDLE_CLOSE, AXLE_SYS_OBJECT_WAIT_ASYNC, AXLE_SYS_OBJECT_WAIT_ONE,
    AXLE_SYS_PORT_CREATE, AXLE_SYS_PORT_QUEUE, AXLE_SYS_PORT_WAIT, AXLE_SYS_TIMER_CANCEL,
    AXLE_SYS_TIMER_CREATE, AXLE_SYS_TIMER_SET, AXLE_SYS_VMAR_MAP, AXLE_SYS_VMAR_PROTECT,
    AXLE_SYS_VMAR_UNMAP, AXLE_SYS_VMO_CREATE, SyscallNumber,
};
use axle_types::wait_async::{
    ZX_WAIT_ASYNC_BOOT_TIMESTAMP, ZX_WAIT_ASYNC_EDGE, ZX_WAIT_ASYNC_TIMESTAMP,
};
use axle_types::{
    zx_clock_t, zx_duration_t, zx_handle_t, zx_port_packet_t, zx_signals_t, zx_status_t, zx_time_t,
    zx_vaddr_t, zx_vm_option_t,
};
use core::mem::size_of;

/// Phase-B bootstrap syscall numbers supported by the shared ABI spec.
pub const BOOTSTRAP_SYSCALLS: [SyscallNumber; 13] = [
    AXLE_SYS_HANDLE_CLOSE,
    AXLE_SYS_OBJECT_WAIT_ONE,
    AXLE_SYS_OBJECT_WAIT_ASYNC,
    AXLE_SYS_PORT_CREATE,
    AXLE_SYS_PORT_QUEUE,
    AXLE_SYS_PORT_WAIT,
    AXLE_SYS_TIMER_CREATE,
    AXLE_SYS_TIMER_SET,
    AXLE_SYS_TIMER_CANCEL,
    AXLE_SYS_VMO_CREATE,
    AXLE_SYS_VMAR_MAP,
    AXLE_SYS_VMAR_UNMAP,
    AXLE_SYS_VMAR_PROTECT,
];

// Compile-time witness that kernel syscall layer consumes shared ABI types.
const _ABI_TYPES_WITNESS: Option<(
    zx_handle_t,
    zx_signals_t,
    zx_time_t,
    zx_duration_t,
    zx_clock_t,
    zx_port_packet_t,
    zx_vaddr_t,
    zx_vm_option_t,
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
        AXLE_SYS_VMO_CREATE => sys_vmo_create(args),
        AXLE_SYS_VMAR_MAP => ZX_ERR_NOT_SUPPORTED,
        AXLE_SYS_VMAR_UNMAP => sys_vmar_unmap(args),
        AXLE_SYS_VMAR_PROTECT => sys_vmar_protect(args),
        _ => ZX_ERR_BAD_SYSCALL,
    }
}

/// Dispatch a syscall from the architecture trap frame and write status back.
pub fn invoke_from_trapframe(frame: &mut crate::arch::int80::TrapFrame, cpu_frame: *const u64) {
    let status = match u32::try_from(frame.syscall_nr()) {
        Ok(AXLE_SYS_VMAR_MAP) => sys_vmar_map(frame.args(), cpu_frame),
        Ok(nr) => dispatch_syscall(nr, frame.args()),
        Err(_) => ZX_ERR_BAD_SYSCALL,
    };
    frame.set_status(status);
}

fn copyin<T: Copy>(ptr: *const T) -> Result<T, zx_status_t> {
    if ptr.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if !crate::userspace::validate_user_ptr(ptr as u64, size_of::<T>()) {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    // SAFETY: pointer validated to be within a mapped userspace page region.
    unsafe { Ok(core::ptr::read_unaligned(ptr)) }
}

fn copyout<T: Copy>(ptr: *mut T, v: T) -> Result<(), zx_status_t> {
    if ptr.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if !crate::userspace::validate_user_ptr(ptr as u64, size_of::<T>()) {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    // SAFETY: pointer validated to be within a mapped userspace page region.
    unsafe {
        core::ptr::write_unaligned(ptr, v);
    }
    Ok(())
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
    let handle = match u32::try_from(_args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let signals = match u32::try_from(_args[1]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let deadline = _args[2] as i64;
    let observed_ptr = _args[3] as *mut zx_signals_t;
    if observed_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }
    if signals == 0 {
        return ZX_ERR_INVALID_ARGS;
    }

    let (status, observed) = match crate::object::object_wait_one(handle, signals, deadline) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let Err(e) = copyout(observed_ptr, observed) {
        return e;
    }
    status
}

fn sys_object_wait_async(_args: [u64; 6]) -> zx_status_t {
    let handle = match u32::try_from(_args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let port = match u32::try_from(_args[1]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let key = _args[2];
    let signals = match u32::try_from(_args[3]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let options = match u32::try_from(_args[4]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };

    if signals == 0 {
        return ZX_ERR_INVALID_ARGS;
    }

    let allowed = ZX_WAIT_ASYNC_TIMESTAMP | ZX_WAIT_ASYNC_EDGE | ZX_WAIT_ASYNC_BOOT_TIMESTAMP;
    if (options & !allowed) != 0 {
        return ZX_ERR_INVALID_ARGS;
    }
    if (options & ZX_WAIT_ASYNC_TIMESTAMP) != 0 && (options & ZX_WAIT_ASYNC_BOOT_TIMESTAMP) != 0 {
        return ZX_ERR_INVALID_ARGS;
    }

    let timestamp = if (options & ZX_WAIT_ASYNC_BOOT_TIMESTAMP) != 0 {
        WaitAsyncTimestamp::Boot
    } else if (options & ZX_WAIT_ASYNC_TIMESTAMP) != 0 {
        WaitAsyncTimestamp::Monotonic
    } else {
        WaitAsyncTimestamp::None
    };

    let wait_options = WaitAsyncOptions {
        edge_triggered: (options & ZX_WAIT_ASYNC_EDGE) != 0,
        timestamp,
    };
    match crate::object::object_wait_async(handle, port, key, signals, wait_options) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
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

    if let Err(e) = copyout(out_ptr, h) {
        return e;
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

    let packet = match copyin(packet_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
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
    let deadline = args[1] as i64;
    let out_ptr = args[2] as *mut zx_port_packet_t;
    if out_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    match crate::object::port_wait(handle, deadline) {
        Ok(packet) => {
            if let Err(e) = copyout(out_ptr, packet) {
                return e;
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

    if let Err(e) = copyout(out_ptr, h) {
        return e;
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

fn sys_vmo_create(args: [u64; 6]) -> zx_status_t {
    let size = align_up_page(args[0]).unwrap_or(0);
    let options = match u32::try_from(args[1]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let out_ptr = args[2] as *mut zx_handle_t;
    if out_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }
    if size == 0 {
        return ZX_ERR_INVALID_ARGS;
    }

    let handle = match crate::object::create_vmo(size, options) {
        Ok(handle) => handle,
        Err(e) => return e,
    };
    if let Err(e) = copyout(out_ptr, handle) {
        return e;
    }
    ZX_OK
}

fn sys_vmar_map(args: [u64; 6], cpu_frame: *const u64) -> zx_status_t {
    let vmar = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let options = match u32::try_from(args[1]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let vmar_offset = args[2];
    let vmo = match u32::try_from(args[3]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let vmo_offset = args[4];
    let len = match align_up_page(args[5]) {
        Some(len) if len != 0 => len,
        _ => return ZX_ERR_INVALID_ARGS,
    };
    let mapped_addr_ptr = match extra_arg_u64(cpu_frame, 0) {
        Ok(arg) => arg as *mut zx_vaddr_t,
        Err(e) => return e,
    };
    if mapped_addr_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    let mapped_addr =
        match crate::object::vmar_map(vmar, options, vmar_offset, vmo, vmo_offset, len) {
            Ok(addr) => addr,
            Err(e) => return e,
        };
    if let Err(e) = copyout(mapped_addr_ptr, mapped_addr) {
        return e;
    }
    ZX_OK
}

fn sys_vmar_unmap(args: [u64; 6]) -> zx_status_t {
    let vmar = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let addr = args[1];
    let len = match align_up_page(args[2]) {
        Some(len) if len != 0 => len,
        _ => return ZX_ERR_INVALID_ARGS,
    };

    match crate::object::vmar_unmap(vmar, addr, len) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_vmar_protect(args: [u64; 6]) -> zx_status_t {
    let vmar = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let options = match u32::try_from(args[1]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let addr = args[2];
    let len = match align_up_page(args[3]) {
        Some(len) if len != 0 => len,
        _ => return ZX_ERR_INVALID_ARGS,
    };

    match crate::object::vmar_protect(vmar, options, addr, len) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn align_up_page(value: u64) -> Option<u64> {
    const PAGE_SIZE: u64 = 0x1000;
    value
        .checked_add(PAGE_SIZE - 1)
        .map(|v| v & !(PAGE_SIZE - 1))
}

fn extra_arg_u64(cpu_frame: *const u64, index: usize) -> Result<u64, zx_status_t> {
    if cpu_frame.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let user_rsp = unsafe {
        // SAFETY: `cpu_frame` points at the hardware interrupt frame built by the CPU for
        // ring3 -> ring0 `int 0x80`. On privilege transitions the saved user RSP is the
        // fourth u64 slot after RIP/CS/RFLAGS.
        *cpu_frame.add(3)
    };
    let extra_ptr = user_rsp
        .checked_add((index as u64) * 8)
        .ok_or(ZX_ERR_INVALID_ARGS)? as *const u64;
    copyin(extra_ptr)
}
