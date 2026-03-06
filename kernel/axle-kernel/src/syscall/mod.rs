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

extern crate alloc;

use alloc::vec::Vec;
use axle_core::{WaitAsyncOptions, WaitAsyncTimestamp};
use axle_types::status::{
    ZX_ERR_BAD_STATE, ZX_ERR_BAD_SYSCALL, ZX_ERR_INVALID_ARGS, ZX_ERR_NO_MEMORY,
    ZX_ERR_NOT_SUPPORTED, ZX_ERR_OUT_OF_RANGE, ZX_OK,
};
use axle_types::syscall_numbers::{
    AXLE_SYS_CHANNEL_CREATE, AXLE_SYS_CHANNEL_READ, AXLE_SYS_CHANNEL_WRITE,
    AXLE_SYS_EVENTPAIR_CREATE, AXLE_SYS_FUTEX_GET_OWNER, AXLE_SYS_FUTEX_REQUEUE,
    AXLE_SYS_FUTEX_WAIT, AXLE_SYS_FUTEX_WAKE, AXLE_SYS_HANDLE_CLOSE, AXLE_SYS_HANDLE_DUPLICATE,
    AXLE_SYS_HANDLE_REPLACE, AXLE_SYS_OBJECT_SIGNAL, AXLE_SYS_OBJECT_SIGNAL_PEER,
    AXLE_SYS_OBJECT_WAIT_ASYNC, AXLE_SYS_OBJECT_WAIT_ONE, AXLE_SYS_PORT_CREATE,
    AXLE_SYS_PORT_QUEUE, AXLE_SYS_PORT_WAIT, AXLE_SYS_THREAD_CREATE, AXLE_SYS_THREAD_START,
    AXLE_SYS_TIMER_CANCEL, AXLE_SYS_TIMER_CREATE, AXLE_SYS_TIMER_SET, AXLE_SYS_VMAR_MAP,
    AXLE_SYS_VMAR_PROTECT, AXLE_SYS_VMAR_UNMAP, AXLE_SYS_VMO_CREATE, SyscallNumber,
};
use axle_types::wait_async::{
    ZX_WAIT_ASYNC_BOOT_TIMESTAMP, ZX_WAIT_ASYNC_EDGE, ZX_WAIT_ASYNC_TIMESTAMP,
};
use axle_types::{
    zx_clock_t, zx_duration_t, zx_futex_t, zx_handle_t, zx_koid_t, zx_port_packet_t, zx_rights_t,
    zx_signals_t, zx_status_t, zx_time_t, zx_vaddr_t, zx_vm_option_t,
};
use core::mem::size_of;
use core::slice;

/// Phase-B bootstrap syscall numbers supported by the shared ABI spec.
pub const BOOTSTRAP_SYSCALLS: [SyscallNumber; 27] = [
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
    AXLE_SYS_CHANNEL_CREATE,
    AXLE_SYS_CHANNEL_WRITE,
    AXLE_SYS_CHANNEL_READ,
    AXLE_SYS_EVENTPAIR_CREATE,
    AXLE_SYS_OBJECT_SIGNAL_PEER,
    AXLE_SYS_HANDLE_DUPLICATE,
    AXLE_SYS_HANDLE_REPLACE,
    AXLE_SYS_OBJECT_SIGNAL,
    AXLE_SYS_FUTEX_WAIT,
    AXLE_SYS_FUTEX_WAKE,
    AXLE_SYS_FUTEX_REQUEUE,
    AXLE_SYS_FUTEX_GET_OWNER,
    AXLE_SYS_THREAD_CREATE,
    AXLE_SYS_THREAD_START,
];

// Compile-time witness that kernel syscall layer consumes shared ABI types.
const _ABI_TYPES_WITNESS: Option<(
    zx_handle_t,
    zx_rights_t,
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
        AXLE_SYS_CHANNEL_CREATE => sys_channel_create(args),
        AXLE_SYS_CHANNEL_WRITE => sys_channel_write(args),
        AXLE_SYS_CHANNEL_READ => ZX_ERR_NOT_SUPPORTED,
        AXLE_SYS_EVENTPAIR_CREATE => sys_eventpair_create(args),
        AXLE_SYS_OBJECT_SIGNAL_PEER => sys_object_signal_peer(args),
        AXLE_SYS_HANDLE_DUPLICATE => sys_handle_duplicate(args),
        AXLE_SYS_HANDLE_REPLACE => sys_handle_replace(args),
        AXLE_SYS_OBJECT_SIGNAL => sys_object_signal(args),
        AXLE_SYS_FUTEX_WAIT => sys_futex_wait(args),
        AXLE_SYS_FUTEX_WAKE => sys_futex_wake(args),
        AXLE_SYS_FUTEX_REQUEUE => sys_futex_requeue(args),
        AXLE_SYS_FUTEX_GET_OWNER => sys_futex_get_owner(args),
        AXLE_SYS_THREAD_CREATE => sys_thread_create(args),
        AXLE_SYS_THREAD_START => sys_thread_start(args),
        _ => ZX_ERR_BAD_SYSCALL,
    }
}

/// Dispatch a syscall from the architecture trap frame and write status back.
pub fn invoke_from_trapframe(frame: &mut crate::arch::int80::TrapFrame, cpu_frame: *const u64) {
    let _ = crate::object::capture_current_user_context(frame, cpu_frame);
    let status = match u32::try_from(frame.syscall_nr()) {
        Ok(AXLE_SYS_VMAR_MAP) => sys_vmar_map(frame.args(), cpu_frame),
        Ok(AXLE_SYS_CHANNEL_READ) => sys_channel_read(frame.args(), cpu_frame),
        Ok(nr) => dispatch_syscall(nr, frame.args()),
        Err(_) => ZX_ERR_BAD_SYSCALL,
    };
    frame.set_status(status);
    let _ = crate::object::finish_syscall(frame, cpu_frame.cast_mut());
}

fn copyin<T: Copy>(ptr: *const T) -> Result<T, zx_status_t> {
    if ptr.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if !crate::userspace::validate_user_ptr(ptr as u64, size_of::<T>()) {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    crate::userspace::ensure_user_range_resident(ptr as u64, size_of::<T>(), false)?;
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
    crate::userspace::ensure_user_range_resident(ptr as u64, size_of::<T>(), true)?;
    // SAFETY: pointer validated to be within a mapped userspace page region.
    unsafe {
        core::ptr::write_unaligned(ptr, v);
    }
    Ok(())
}

fn copyin_bytes(ptr: *const u8, len: usize) -> Result<Vec<u8>, zx_status_t> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if !crate::userspace::validate_user_ptr(ptr as u64, len) {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    crate::userspace::ensure_user_range_resident(ptr as u64, len, false)?;

    let mut out = Vec::new();
    out.try_reserve_exact(len).map_err(|_| ZX_ERR_NO_MEMORY)?;
    out.resize(len, 0);
    // SAFETY: the userspace range was validated above and `out` was sized to `len`.
    let src = unsafe { slice::from_raw_parts(ptr, len) };
    out.as_mut_slice().copy_from_slice(src);
    Ok(out)
}

fn copyout_bytes(ptr: *mut u8, bytes: &[u8]) -> Result<(), zx_status_t> {
    if bytes.is_empty() {
        return Ok(());
    }
    if ptr.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if !crate::userspace::validate_user_ptr(ptr as u64, bytes.len()) {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    crate::userspace::ensure_user_range_resident(ptr as u64, bytes.len(), true)?;
    // SAFETY: the userspace range was validated above and `bytes` is a valid source slice.
    let dst = unsafe { slice::from_raw_parts_mut(ptr, bytes.len()) };
    dst.copy_from_slice(bytes);
    Ok(())
}

fn copyout_loaned_bytes(
    ptr: *mut u8,
    loaned: &crate::task::LoanedUserPages,
) -> Result<(), zx_status_t> {
    let len = usize::try_from(loaned.len()).map_err(|_| ZX_ERR_OUT_OF_RANGE)?;
    if len == 0 {
        return Ok(());
    }
    if ptr.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if !crate::userspace::validate_user_ptr(ptr as u64, len) {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    crate::userspace::ensure_user_range_resident(ptr as u64, len, true)?;

    let page_size = crate::userspace::USER_PAGE_BYTES as usize;
    let page_count = len / page_size;
    if page_count != loaned.pages().len() {
        return Err(ZX_ERR_BAD_STATE);
    }

    for (page_index, frame_id) in loaned.pages().iter().copied().enumerate() {
        // SAFETY: the destination range was validated above, and bootstrap guest memory is
        // identity mapped so the registered frame physical address is a readable kernel VA.
        unsafe {
            core::ptr::copy_nonoverlapping(
                frame_id.raw() as *const u8,
                ptr.add(page_index * page_size),
                page_size,
            );
        }
    }
    Ok(())
}

fn copyout_optional<T: Copy>(ptr: *mut T, value: T) -> Result<(), zx_status_t> {
    if ptr.is_null() {
        return Ok(());
    }
    copyout(ptr, value)
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

fn sys_handle_duplicate(args: [u64; 6]) -> zx_status_t {
    let handle = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let rights = match u32::try_from(args[1]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let out_ptr = args[2] as *mut zx_handle_t;
    if out_ptr.is_null()
        || !crate::userspace::validate_user_ptr(out_ptr as u64, size_of::<zx_handle_t>())
    {
        return ZX_ERR_INVALID_ARGS;
    }

    let duplicated = match crate::object::duplicate_handle(handle, rights as zx_rights_t) {
        Ok(new_handle) => new_handle,
        Err(e) => return e,
    };
    match copyout(out_ptr, duplicated) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_handle_replace(args: [u64; 6]) -> zx_status_t {
    let handle = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let rights = match u32::try_from(args[1]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let out_ptr = args[2] as *mut zx_handle_t;
    if out_ptr.is_null()
        || !crate::userspace::validate_user_ptr(out_ptr as u64, size_of::<zx_handle_t>())
    {
        return ZX_ERR_INVALID_ARGS;
    }

    let replaced = match crate::object::replace_handle(handle, rights as zx_rights_t) {
        Ok(new_handle) => new_handle,
        Err(e) => return e,
    };
    match copyout(out_ptr, replaced) {
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

    match crate::object::object_wait_one(handle, signals, deadline, observed_ptr) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
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

    match crate::object::port_wait(handle, deadline, out_ptr) {
        Ok(()) => ZX_OK,
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

fn sys_channel_create(args: [u64; 6]) -> zx_status_t {
    let options = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let out0_ptr = args[1] as *mut zx_handle_t;
    let out1_ptr = args[2] as *mut zx_handle_t;
    if out0_ptr.is_null() || out1_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }
    if !crate::userspace::validate_user_ptr(out0_ptr as u64, size_of::<zx_handle_t>())
        || !crate::userspace::validate_user_ptr(out1_ptr as u64, size_of::<zx_handle_t>())
    {
        return ZX_ERR_INVALID_ARGS;
    }

    let (out0, out1) = match crate::object::create_channel(options) {
        Ok(handles) => handles,
        Err(e) => return e,
    };
    if let Err(e) = copyout(out0_ptr, out0) {
        return e;
    }
    if let Err(e) = copyout(out1_ptr, out1) {
        return e;
    }
    ZX_OK
}

fn sys_channel_write(args: [u64; 6]) -> zx_status_t {
    let handle = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let options = match u32::try_from(args[1]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let bytes_ptr = args[2] as *const u8;
    let num_bytes = match usize::try_from(args[3]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let handles_ptr = args[4] as *const zx_handle_t;
    let num_handles = match u32::try_from(args[5]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    if num_bytes != 0 && bytes_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }
    if num_handles != 0 && handles_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    let payload = match crate::object::try_loan_current_user_pages(bytes_ptr as u64, num_bytes) {
        Ok(Some(loaned)) => crate::object::ChannelPayload::Loaned(loaned),
        Ok(None) => match copyin_bytes(bytes_ptr, num_bytes) {
            Ok(bytes) => crate::object::ChannelPayload::Copied(bytes),
            Err(e) => return e,
        },
        Err(e) => return e,
    };
    match crate::object::channel_write(handle, options, payload, num_handles) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_channel_read(args: [u64; 6], cpu_frame: *const u64) -> zx_status_t {
    let handle = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let options = match u32::try_from(args[1]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let bytes_ptr = args[2] as *mut u8;
    let handles_ptr = args[3] as *mut zx_handle_t;
    let num_bytes = match u32::try_from(args[4]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let num_handles = match u32::try_from(args[5]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let actual_bytes_ptr = match extra_arg_u64(cpu_frame, 0) {
        Ok(arg) => arg as *mut u32,
        Err(e) => return e,
    };
    let actual_handles_ptr = match extra_arg_u64(cpu_frame, 1) {
        Ok(arg) => arg as *mut u32,
        Err(e) => return e,
    };
    if num_bytes != 0 && bytes_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }
    if num_handles != 0 && handles_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    let message = match crate::object::channel_read(handle, options, num_bytes, num_handles) {
        Ok(message) => message,
        Err((status, actual_bytes, actual_handles)) => {
            let _ = copyout_optional(actual_bytes_ptr, actual_bytes);
            let _ = copyout_optional(actual_handles_ptr, actual_handles);
            return status;
        }
    };
    let actual_bytes = message.actual_bytes;
    let actual_handles = message.actual_handles;
    let copy_result = match &message.payload {
        crate::object::ChannelPayload::Copied(bytes) => copyout_bytes(bytes_ptr, bytes),
        crate::object::ChannelPayload::Loaned(loaned) => {
            match crate::object::try_remap_loaned_channel_read(bytes_ptr as u64, loaned) {
                Ok(true) => Ok(()),
                Ok(false) => copyout_loaned_bytes(bytes_ptr, loaned),
                Err(e) => Err(e),
            }
        }
    };
    crate::object::release_channel_read_result(message);
    if let Err(e) = copy_result {
        return e;
    }
    if let Err(e) = copyout_optional(actual_bytes_ptr, actual_bytes) {
        return e;
    }
    if let Err(e) = copyout_optional(actual_handles_ptr, actual_handles) {
        return e;
    }
    ZX_OK
}

fn sys_eventpair_create(args: [u64; 6]) -> zx_status_t {
    let options = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let out0_ptr = args[1] as *mut zx_handle_t;
    let out1_ptr = args[2] as *mut zx_handle_t;
    if out0_ptr.is_null() || out1_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }
    if !crate::userspace::validate_user_ptr(out0_ptr as u64, size_of::<zx_handle_t>())
        || !crate::userspace::validate_user_ptr(out1_ptr as u64, size_of::<zx_handle_t>())
    {
        return ZX_ERR_INVALID_ARGS;
    }

    let (out0, out1) = match crate::object::create_eventpair(options) {
        Ok(handles) => handles,
        Err(e) => return e,
    };
    if let Err(e) = copyout(out0_ptr, out0) {
        return e;
    }
    if let Err(e) = copyout(out1_ptr, out1) {
        return e;
    }
    ZX_OK
}

fn sys_object_signal_peer(args: [u64; 6]) -> zx_status_t {
    let handle = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let clear_mask = match u32::try_from(args[1]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let set_mask = match u32::try_from(args[2]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };

    match crate::object::object_signal_peer(handle, clear_mask, set_mask) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_object_signal(args: [u64; 6]) -> zx_status_t {
    let handle = match u32::try_from(args[0]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let clear_mask = match u32::try_from(args[1]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let set_mask = match u32::try_from(args[2]) {
        Ok(v) => v,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };

    match crate::object::object_signal(handle, clear_mask, set_mask) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_futex_wait(args: [u64; 6]) -> zx_status_t {
    let value_ptr = args[0];
    let current_value_raw = match u32::try_from(args[1]) {
        Ok(value) => value,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let current_value = current_value_raw as zx_futex_t;
    let new_futex_owner = match u32::try_from(args[2]) {
        Ok(value) => value,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let deadline = args[3] as zx_time_t;

    match crate::object::futex_wait(value_ptr, current_value, new_futex_owner, deadline) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_futex_wake(args: [u64; 6]) -> zx_status_t {
    let value_ptr = args[0];
    let wake_count = match u32::try_from(args[1]) {
        Ok(value) => value,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };

    match crate::object::futex_wake(value_ptr, wake_count) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_futex_requeue(args: [u64; 6]) -> zx_status_t {
    let value_ptr = args[0];
    let wake_count = match u32::try_from(args[1]) {
        Ok(value) => value,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let current_value_raw = match u32::try_from(args[2]) {
        Ok(value) => value,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let current_value = current_value_raw as zx_futex_t;
    let requeue_ptr = args[3];
    let requeue_count = match u32::try_from(args[4]) {
        Ok(value) => value,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let new_requeue_owner = match u32::try_from(args[5]) {
        Ok(value) => value,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };

    match crate::object::futex_requeue(
        value_ptr,
        wake_count,
        current_value,
        requeue_ptr,
        requeue_count,
        new_requeue_owner,
    ) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_futex_get_owner(args: [u64; 6]) -> zx_status_t {
    let value_ptr = args[0];
    let koid_ptr = args[1] as *mut zx_koid_t;
    if koid_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    let koid = match crate::object::futex_get_owner(value_ptr) {
        Ok(koid) => koid,
        Err(e) => return e,
    };
    match copyout(koid_ptr, koid) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_thread_create(args: [u64; 6]) -> zx_status_t {
    let process = match u32::try_from(args[0]) {
        Ok(value) => value,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let name_ptr = args[1] as *const u8;
    let name_size = match usize::try_from(args[2]) {
        Ok(value) => value,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let options = match u32::try_from(args[3]) {
        Ok(value) => value,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let out_ptr = args[4] as *mut zx_handle_t;
    if out_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }
    if name_size != 0
        && (name_ptr.is_null() || !crate::userspace::validate_user_ptr(name_ptr as u64, name_size))
    {
        return ZX_ERR_INVALID_ARGS;
    }

    let handle = match crate::object::create_thread(process, options) {
        Ok(handle) => handle,
        Err(e) => return e,
    };
    match copyout(out_ptr, handle) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_thread_start(args: [u64; 6]) -> zx_status_t {
    let thread = match u32::try_from(args[0]) {
        Ok(value) => value,
        Err(_) => return ZX_ERR_INVALID_ARGS,
    };
    let entry = args[1];
    let stack = args[2];
    let arg1 = args[3];
    let arg2 = args[4];

    match crate::object::start_thread(thread, entry, stack, arg1, arg2) {
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
