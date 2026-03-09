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
use axle_types::status::{ZX_ERR_BAD_SYSCALL, ZX_ERR_INVALID_ARGS, ZX_ERR_OUT_OF_RANGE, ZX_OK};
use axle_types::syscall_numbers::{
    AXLE_SYS_AX_PROCESS_PREPARE_START, AXLE_SYS_CHANNEL_CREATE, AXLE_SYS_CHANNEL_READ,
    AXLE_SYS_CHANNEL_WRITE, AXLE_SYS_EVENTPAIR_CREATE, AXLE_SYS_FUTEX_GET_OWNER,
    AXLE_SYS_FUTEX_REQUEUE, AXLE_SYS_FUTEX_WAIT, AXLE_SYS_FUTEX_WAKE, AXLE_SYS_HANDLE_CLOSE,
    AXLE_SYS_HANDLE_DUPLICATE, AXLE_SYS_HANDLE_REPLACE, AXLE_SYS_OBJECT_SIGNAL,
    AXLE_SYS_OBJECT_SIGNAL_PEER, AXLE_SYS_OBJECT_WAIT_ASYNC, AXLE_SYS_OBJECT_WAIT_ONE,
    AXLE_SYS_PORT_CREATE, AXLE_SYS_PORT_QUEUE, AXLE_SYS_PORT_WAIT, AXLE_SYS_PROCESS_CREATE,
    AXLE_SYS_PROCESS_START, AXLE_SYS_SOCKET_CREATE, AXLE_SYS_SOCKET_READ, AXLE_SYS_SOCKET_WRITE,
    AXLE_SYS_TASK_KILL, AXLE_SYS_TASK_SUSPEND, AXLE_SYS_THREAD_CREATE, AXLE_SYS_THREAD_START,
    AXLE_SYS_TIMER_CANCEL, AXLE_SYS_TIMER_CREATE, AXLE_SYS_TIMER_SET, AXLE_SYS_VMAR_ALLOCATE,
    AXLE_SYS_VMAR_DESTROY, AXLE_SYS_VMAR_MAP, AXLE_SYS_VMAR_PROTECT, AXLE_SYS_VMAR_UNMAP,
    AXLE_SYS_VMO_CREATE, AXLE_SYS_VMO_READ, AXLE_SYS_VMO_SET_SIZE, AXLE_SYS_VMO_WRITE,
    SyscallNumber,
};
use axle_types::wait_async::{
    ZX_WAIT_ASYNC_BOOT_TIMESTAMP, ZX_WAIT_ASYNC_EDGE, ZX_WAIT_ASYNC_TIMESTAMP,
};
use axle_types::{
    zx_clock_t, zx_duration_t, zx_futex_t, zx_handle_t, zx_koid_t, zx_port_packet_t, zx_rights_t,
    zx_signals_t, zx_status_t, zx_time_t, zx_vaddr_t, zx_vm_option_t,
};

/// Phase-B bootstrap syscall numbers supported by the shared ABI spec.
pub const BOOTSTRAP_SYSCALLS: [SyscallNumber; 40] = [
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
    AXLE_SYS_PROCESS_CREATE,
    AXLE_SYS_PROCESS_START,
    AXLE_SYS_TASK_KILL,
    AXLE_SYS_TASK_SUSPEND,
    AXLE_SYS_VMAR_ALLOCATE,
    AXLE_SYS_VMAR_DESTROY,
    AXLE_SYS_VMO_READ,
    AXLE_SYS_VMO_WRITE,
    AXLE_SYS_VMO_SET_SIZE,
    AXLE_SYS_SOCKET_CREATE,
    AXLE_SYS_SOCKET_WRITE,
    AXLE_SYS_SOCKET_READ,
    AXLE_SYS_AX_PROCESS_PREPARE_START,
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

#[derive(Clone, Copy, Debug)]
enum PostAction {
    FinishTrapExit { cpu_frame: *mut u64 },
}

#[derive(Debug, Default)]
struct SyscallCtx {
    extra_args_user_rsp: Option<u64>,
    post_actions: Vec<PostAction>,
}

impl SyscallCtx {
    fn new() -> Self {
        Self::default()
    }

    fn from_trapframe(frame: &crate::arch::int80::TrapFrame, cpu_frame: *const u64) -> Self {
        let _ = crate::object::capture_current_user_context(frame, cpu_frame);
        let mut ctx = Self {
            extra_args_user_rsp: user_stack_ptr_from_cpu_frame(cpu_frame).ok(),
            post_actions: Vec::new(),
        };
        ctx.push_post_action(PostAction::FinishTrapExit {
            cpu_frame: cpu_frame.cast_mut(),
        });
        ctx
    }

    fn push_post_action(&mut self, action: PostAction) {
        self.post_actions.push(action);
    }

    fn arg_handle(&self, args: [u64; 6], index: usize) -> Result<zx_handle_t, zx_status_t> {
        self.arg_u32(args, index)
    }

    fn arg_u32(&self, args: [u64; 6], index: usize) -> Result<u32, zx_status_t> {
        u32::try_from(args[index]).map_err(|_| ZX_ERR_INVALID_ARGS)
    }

    fn arg_usize(&self, args: [u64; 6], index: usize) -> Result<usize, zx_status_t> {
        usize::try_from(args[index]).map_err(|_| ZX_ERR_INVALID_ARGS)
    }

    fn arg_usize_or(
        &self,
        args: [u64; 6],
        index: usize,
        err: zx_status_t,
    ) -> Result<usize, zx_status_t> {
        usize::try_from(args[index]).map_err(|_| err)
    }

    fn arg_ptr<T>(&self, args: [u64; 6], index: usize) -> *mut T {
        args[index] as *mut T
    }

    fn arg_const_ptr<T>(&self, args: [u64; 6], index: usize) -> *const T {
        args[index] as *const T
    }

    fn extra_arg_u64(&self, index: usize) -> Result<u64, zx_status_t> {
        let user_rsp = self.extra_args_user_rsp.ok_or(ZX_ERR_INVALID_ARGS)?;
        let extra_ptr = user_rsp
            .checked_add((index as u64) * 8)
            .ok_or(ZX_ERR_INVALID_ARGS)? as *const u64;
        self.copyin(extra_ptr)
    }

    fn extra_arg_ptr<T>(&self, index: usize) -> Result<*mut T, zx_status_t> {
        Ok(self.extra_arg_u64(index)? as *mut T)
    }

    fn copyin<T: Copy>(&self, ptr: *const T) -> Result<T, zx_status_t> {
        crate::copy::copyin_value(ptr)
    }

    fn copyout<T: Copy>(&self, ptr: *mut T, value: T) -> Result<(), zx_status_t> {
        crate::copy::copyout_value(ptr, value)
    }

    fn copyout_optional<T: Copy>(&self, ptr: *mut T, value: T) -> Result<(), zx_status_t> {
        if ptr.is_null() {
            return Ok(());
        }
        self.copyout(ptr, value)
    }

    fn copyin_handles(
        &self,
        ptr: *const zx_handle_t,
        len: usize,
    ) -> Result<Vec<zx_handle_t>, zx_status_t> {
        crate::copy::copyin_handles(ptr, len)
    }

    fn copyout_handles(
        &self,
        ptr: *mut zx_handle_t,
        handles: &[zx_handle_t],
    ) -> Result<(), zx_status_t> {
        crate::copy::copyout_handles(ptr, handles)
    }

    fn probe_read_bytes(&self, ptr: *const u8, len: usize) -> Result<(), zx_status_t> {
        crate::copy::probe_read_bytes(ptr, len)
    }

    fn probe_write_value<T>(&self, ptr: *mut T) -> Result<(), zx_status_t> {
        crate::copy::probe_write_value(ptr)
    }

    fn probe_write_handles(&self, ptr: *mut zx_handle_t, len: usize) -> Result<(), zx_status_t> {
        crate::copy::probe_write_handles(ptr, len)
    }

    fn prepare_channel_write_payload(
        &self,
        ptr: *const u8,
        len: usize,
    ) -> Result<crate::object::ChannelPayload, zx_status_t> {
        crate::copy::prepare_channel_write_payload(ptr, len)
    }

    fn write_channel_payload_to_user(
        &self,
        ptr: *mut u8,
        payload: &crate::object::ChannelPayload,
    ) -> Result<(), zx_status_t> {
        crate::copy::write_channel_payload_to_user(ptr, payload)
    }

    fn socket_write_from_user(
        &self,
        handle: zx_handle_t,
        options: u32,
        buffer: *const u8,
        len: usize,
    ) -> Result<usize, zx_status_t> {
        crate::copy::socket_write_from_user(handle, options, buffer, len)
    }

    fn socket_read_to_user(
        &self,
        handle: zx_handle_t,
        options: u32,
        buffer: *mut u8,
        len: usize,
    ) -> Result<usize, zx_status_t> {
        crate::copy::socket_read_to_user(handle, options, buffer, len)
    }

    fn vmo_write_from_user(
        &self,
        handle: zx_handle_t,
        offset: u64,
        buffer: *const u8,
        len: usize,
    ) -> Result<(), zx_status_t> {
        crate::copy::vmo_write_from_user(handle, offset, buffer, len)
    }

    fn vmo_read_to_user(
        &self,
        handle: zx_handle_t,
        offset: u64,
        buffer: *mut u8,
        len: usize,
    ) -> Result<(), zx_status_t> {
        crate::copy::vmo_read_to_user(handle, offset, buffer, len)
    }

    fn finish(self, frame: &mut crate::arch::int80::TrapFrame) {
        for action in self.post_actions {
            match action {
                PostAction::FinishTrapExit { cpu_frame } => {
                    let _ = crate::object::finish_syscall(frame, cpu_frame);
                }
            }
        }
    }
}

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
    let mut ctx = SyscallCtx::new();
    dispatch_syscall_with_ctx(&mut ctx, nr, args)
}

fn dispatch_syscall_with_ctx(
    ctx: &mut SyscallCtx,
    nr: SyscallNumber,
    args: [u64; 6],
) -> zx_status_t {
    match nr {
        AXLE_SYS_HANDLE_CLOSE => sys_handle_close(ctx, args),
        AXLE_SYS_OBJECT_WAIT_ONE => sys_object_wait_one(ctx, args),
        AXLE_SYS_OBJECT_WAIT_ASYNC => sys_object_wait_async(ctx, args),
        AXLE_SYS_PORT_CREATE => sys_port_create(ctx, args),
        AXLE_SYS_PORT_QUEUE => sys_port_queue(ctx, args),
        AXLE_SYS_PORT_WAIT => sys_port_wait(ctx, args),
        AXLE_SYS_TIMER_CREATE => sys_timer_create(ctx, args),
        AXLE_SYS_TIMER_SET => sys_timer_set(ctx, args),
        AXLE_SYS_TIMER_CANCEL => sys_timer_cancel(ctx, args),
        AXLE_SYS_VMO_CREATE => sys_vmo_create(ctx, args),
        AXLE_SYS_VMO_READ => sys_vmo_read(ctx, args),
        AXLE_SYS_VMO_WRITE => sys_vmo_write(ctx, args),
        AXLE_SYS_VMO_SET_SIZE => sys_vmo_set_size(ctx, args),
        AXLE_SYS_VMAR_ALLOCATE => sys_vmar_allocate(ctx, args),
        AXLE_SYS_VMAR_DESTROY => sys_vmar_destroy(ctx, args),
        AXLE_SYS_VMAR_MAP => sys_vmar_map(ctx, args),
        AXLE_SYS_VMAR_UNMAP => sys_vmar_unmap(ctx, args),
        AXLE_SYS_VMAR_PROTECT => sys_vmar_protect(ctx, args),
        AXLE_SYS_CHANNEL_CREATE => sys_channel_create(ctx, args),
        AXLE_SYS_CHANNEL_WRITE => sys_channel_write(ctx, args),
        AXLE_SYS_CHANNEL_READ => sys_channel_read(ctx, args),
        AXLE_SYS_EVENTPAIR_CREATE => sys_eventpair_create(ctx, args),
        AXLE_SYS_OBJECT_SIGNAL_PEER => sys_object_signal_peer(ctx, args),
        AXLE_SYS_HANDLE_DUPLICATE => sys_handle_duplicate(ctx, args),
        AXLE_SYS_HANDLE_REPLACE => sys_handle_replace(ctx, args),
        AXLE_SYS_OBJECT_SIGNAL => sys_object_signal(ctx, args),
        AXLE_SYS_FUTEX_WAIT => sys_futex_wait(ctx, args),
        AXLE_SYS_FUTEX_WAKE => sys_futex_wake(ctx, args),
        AXLE_SYS_FUTEX_REQUEUE => sys_futex_requeue(ctx, args),
        AXLE_SYS_FUTEX_GET_OWNER => sys_futex_get_owner(ctx, args),
        AXLE_SYS_THREAD_CREATE => sys_thread_create(ctx, args),
        AXLE_SYS_THREAD_START => sys_thread_start(ctx, args),
        AXLE_SYS_PROCESS_CREATE => sys_process_create(ctx, args),
        AXLE_SYS_AX_PROCESS_PREPARE_START => sys_ax_process_prepare_start(ctx, args),
        AXLE_SYS_PROCESS_START => sys_process_start(ctx, args),
        AXLE_SYS_TASK_KILL => sys_task_kill(ctx, args),
        AXLE_SYS_TASK_SUSPEND => sys_task_suspend(ctx, args),
        AXLE_SYS_SOCKET_CREATE => sys_socket_create(ctx, args),
        AXLE_SYS_SOCKET_WRITE => sys_socket_write(ctx, args),
        AXLE_SYS_SOCKET_READ => sys_socket_read(ctx, args),
        _ => ZX_ERR_BAD_SYSCALL,
    }
}

/// Dispatch a syscall from the architecture trap frame and write status back.
pub fn invoke_from_trapframe(frame: &mut crate::arch::int80::TrapFrame, cpu_frame: *const u64) {
    let mut ctx = SyscallCtx::from_trapframe(frame, cpu_frame);
    let status = match u32::try_from(frame.syscall_nr()) {
        Ok(nr) => dispatch_syscall_with_ctx(&mut ctx, nr, frame.args()),
        Err(_) => ZX_ERR_BAD_SYSCALL,
    };
    frame.set_status(status);
    ctx.finish(frame);
}

fn user_stack_ptr_from_cpu_frame(cpu_frame: *const u64) -> Result<u64, zx_status_t> {
    if cpu_frame.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(unsafe {
        // SAFETY: `cpu_frame` points at the hardware interrupt frame built by the CPU for
        // ring3 -> ring0 `int 0x80`. On privilege transitions the saved user RSP is the
        // fourth u64 slot after RIP/CS/RFLAGS.
        *cpu_frame.add(3)
    })
}

fn sys_handle_close(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    match crate::object::close_handle(handle) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_handle_duplicate(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let rights = match ctx.arg_u32(args, 1) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let out_ptr = ctx.arg_ptr::<zx_handle_t>(args, 2);
    if let Err(err) = ctx.probe_write_value(out_ptr) {
        return err;
    }

    let duplicated = match crate::object::handle::duplicate_handle(handle, rights as zx_rights_t) {
        Ok(new_handle) => new_handle,
        Err(e) => return e,
    };
    match ctx.copyout(out_ptr, duplicated) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_handle_replace(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let rights = match ctx.arg_u32(args, 1) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let out_ptr = ctx.arg_ptr::<zx_handle_t>(args, 2);
    if let Err(err) = ctx.probe_write_value(out_ptr) {
        return err;
    }

    let replaced = match crate::object::handle::replace_handle(handle, rights as zx_rights_t) {
        Ok(new_handle) => new_handle,
        Err(e) => return e,
    };
    match ctx.copyout(out_ptr, replaced) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_object_wait_one(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let signals = match ctx.arg_u32(args, 1) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let deadline = args[2] as i64;
    let observed_ptr = ctx.arg_ptr::<zx_signals_t>(args, 3);
    if observed_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }
    if signals == 0 {
        return ZX_ERR_INVALID_ARGS;
    }

    match crate::wait::object_wait_one(handle, signals, deadline, observed_ptr) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_object_wait_async(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let port = match ctx.arg_handle(args, 1) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let key = args[2];
    let signals = match ctx.arg_u32(args, 3) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let options = match ctx.arg_u32(args, 4) {
        Ok(v) => v,
        Err(err) => return err,
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
    match crate::wait::object_wait_async(handle, port, key, signals, wait_options) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_port_create(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let options = match ctx.arg_u32(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };

    let out_ptr = ctx.arg_ptr::<zx_handle_t>(args, 1);
    if out_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    let h = match crate::object::create_port(options) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let Err(e) = ctx.copyout(out_ptr, h) {
        return e;
    }
    ZX_OK
}

fn sys_port_queue(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let packet_ptr = ctx.arg_const_ptr::<zx_port_packet_t>(args, 1);
    if packet_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    let packet = match ctx.copyin(packet_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match crate::wait::queue_port_packet(handle, packet) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_port_wait(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let deadline = args[1] as i64;
    let out_ptr = ctx.arg_ptr::<zx_port_packet_t>(args, 2);
    if out_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    match crate::wait::port_wait(handle, deadline, out_ptr) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_timer_create(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let options = match ctx.arg_u32(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let clock_id = match ctx.arg_u32(args, 1) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let out_ptr = ctx.arg_ptr::<zx_handle_t>(args, 2);
    if out_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    let h = match crate::object::create_timer(options, clock_id) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let Err(e) = ctx.copyout(out_ptr, h) {
        return e;
    }
    ZX_OK
}

fn sys_timer_set(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let deadline = args[1] as i64;
    let slack = args[2] as i64;
    match crate::object::timer_set(handle, deadline, slack) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_timer_cancel(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    match crate::object::timer_cancel(handle) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_vmo_create(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let size = align_up_page(args[0]).unwrap_or(0);
    let options = match ctx.arg_u32(args, 1) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let out_ptr = ctx.arg_ptr::<zx_handle_t>(args, 2);
    if out_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }
    if size == 0 {
        return ZX_ERR_INVALID_ARGS;
    }

    let handle = match crate::object::vm::create_vmo(size, options) {
        Ok(handle) => handle,
        Err(e) => return e,
    };
    if let Err(e) = ctx.copyout(out_ptr, handle) {
        return e;
    }
    ZX_OK
}

fn sys_vmo_read(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let buffer = ctx.arg_ptr::<u8>(args, 1);
    let offset = args[2];
    let buffer_size = match ctx.arg_usize_or(args, 3, ZX_ERR_OUT_OF_RANGE) {
        Ok(v) => v,
        Err(err) => return err,
    };

    match ctx.vmo_read_to_user(handle, offset, buffer, buffer_size) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_vmo_write(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let buffer = ctx.arg_const_ptr::<u8>(args, 1);
    let offset = args[2];
    let buffer_size = match ctx.arg_usize_or(args, 3, ZX_ERR_OUT_OF_RANGE) {
        Ok(v) => v,
        Err(err) => return err,
    };

    match ctx.vmo_write_from_user(handle, offset, buffer, buffer_size) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_vmo_set_size(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let size = args[1];
    match crate::object::vm::vmo_set_size(handle, size) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_socket_create(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let options = match ctx.arg_u32(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let out0_ptr = ctx.arg_ptr::<zx_handle_t>(args, 1);
    let out1_ptr = ctx.arg_ptr::<zx_handle_t>(args, 2);
    if let Err(err) = ctx.probe_write_value(out0_ptr) {
        return err;
    }
    if let Err(err) = ctx.probe_write_value(out1_ptr) {
        return err;
    }

    let (out0, out1) = match crate::object::transport::create_socket(options) {
        Ok(handles) => handles,
        Err(e) => return e,
    };
    if let Err(e) = ctx.copyout(out0_ptr, out0) {
        return e;
    }
    if let Err(e) = ctx.copyout(out1_ptr, out1) {
        return e;
    }
    ZX_OK
}

fn sys_socket_write(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let options = match ctx.arg_u32(args, 1) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let buffer = ctx.arg_const_ptr::<u8>(args, 2);
    let buffer_size = match ctx.arg_usize_or(args, 3, ZX_ERR_OUT_OF_RANGE) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let actual_ptr = ctx.arg_ptr::<usize>(args, 4);
    if buffer_size != 0 && buffer.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    if buffer_size == 0 {
        let actual = match ctx.socket_write_from_user(handle, options, buffer, 0) {
            Ok(actual) => actual,
            Err(e) => return e,
        };
        return match ctx.copyout_optional(actual_ptr, actual) {
            Ok(()) => ZX_OK,
            Err(e) => e,
        };
    }

    let actual = match ctx.socket_write_from_user(handle, options, buffer, buffer_size) {
        Ok(actual) => actual,
        Err(e) => return e,
    };
    match ctx.copyout_optional(actual_ptr, actual) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_socket_read(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let options = match ctx.arg_u32(args, 1) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let buffer = ctx.arg_ptr::<u8>(args, 2);
    let buffer_size = match ctx.arg_usize_or(args, 3, ZX_ERR_OUT_OF_RANGE) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let actual_ptr = ctx.arg_ptr::<usize>(args, 4);
    if buffer.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    let actual = match ctx.socket_read_to_user(handle, options, buffer, buffer_size) {
        Ok(actual) => actual,
        Err(e) => return e,
    };
    match ctx.copyout_optional(actual_ptr, actual) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_vmar_allocate(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let parent_vmar = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let options = match ctx.arg_u32(args, 1) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let offset = args[2];
    let size = match align_up_page(args[3]) {
        Some(len) if len != 0 => len,
        _ => return ZX_ERR_INVALID_ARGS,
    };
    let out_child_vmar = ctx.arg_ptr::<zx_handle_t>(args, 4);
    let out_child_addr = ctx.arg_ptr::<zx_vaddr_t>(args, 5);
    if let Err(err) = ctx.probe_write_value(out_child_vmar) {
        return err;
    }
    if let Err(err) = ctx.probe_write_value(out_child_addr) {
        return err;
    }

    let (child_vmar, child_addr) =
        match crate::object::vm::vmar_allocate(parent_vmar, options, offset, size) {
            Ok(v) => v,
            Err(e) => return e,
        };
    if let Err(e) = ctx.copyout(out_child_vmar, child_vmar) {
        return e;
    }
    if let Err(e) = ctx.copyout(out_child_addr, child_addr) {
        return e;
    }
    ZX_OK
}

fn sys_vmar_map(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let vmar = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let options = match ctx.arg_u32(args, 1) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let vmar_offset = args[2];
    let vmo = match ctx.arg_handle(args, 3) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let vmo_offset = args[4];
    let len = match align_up_page(args[5]) {
        Some(len) if len != 0 => len,
        _ => return ZX_ERR_INVALID_ARGS,
    };
    let mapped_addr_ptr = match ctx.extra_arg_ptr::<zx_vaddr_t>(0) {
        Ok(arg) => arg,
        Err(e) => return e,
    };
    if mapped_addr_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    let mapped_addr =
        match crate::object::vm::vmar_map(vmar, options, vmar_offset, vmo, vmo_offset, len) {
            Ok(addr) => addr,
            Err(e) => return e,
        };
    if let Err(e) = ctx.copyout(mapped_addr_ptr, mapped_addr) {
        return e;
    }
    ZX_OK
}

fn sys_vmar_destroy(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let vmar = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    match crate::object::vm::vmar_destroy(vmar) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_vmar_unmap(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let vmar = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let addr = args[1];
    let len = match align_up_page(args[2]) {
        Some(len) if len != 0 => len,
        _ => return ZX_ERR_INVALID_ARGS,
    };

    match crate::object::vm::vmar_unmap(vmar, addr, len) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_vmar_protect(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let vmar = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let options = match ctx.arg_u32(args, 1) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let addr = args[2];
    let len = match align_up_page(args[3]) {
        Some(len) if len != 0 => len,
        _ => return ZX_ERR_INVALID_ARGS,
    };

    match crate::object::vm::vmar_protect(vmar, options, addr, len) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_channel_create(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let options = match ctx.arg_u32(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let out0_ptr = ctx.arg_ptr::<zx_handle_t>(args, 1);
    let out1_ptr = ctx.arg_ptr::<zx_handle_t>(args, 2);
    if let Err(err) = ctx.probe_write_value(out0_ptr) {
        return err;
    }
    if let Err(err) = ctx.probe_write_value(out1_ptr) {
        return err;
    }

    let (out0, out1) = match crate::object::transport::create_channel(options) {
        Ok(handles) => handles,
        Err(e) => return e,
    };
    if let Err(e) = ctx.copyout(out0_ptr, out0) {
        return e;
    }
    if let Err(e) = ctx.copyout(out1_ptr, out1) {
        return e;
    }
    ZX_OK
}

fn sys_channel_write(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let options = match ctx.arg_u32(args, 1) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let bytes_ptr = ctx.arg_const_ptr::<u8>(args, 2);
    let num_bytes = match ctx.arg_usize(args, 3) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let handles_ptr = ctx.arg_const_ptr::<zx_handle_t>(args, 4);
    let num_handles = match ctx.arg_u32(args, 5) {
        Ok(v) => v,
        Err(err) => return err,
    };
    if num_bytes != 0 && bytes_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }
    if num_handles != 0 && handles_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }
    let handles = match ctx.copyin_handles(handles_ptr, num_handles as usize) {
        Ok(handles) => handles,
        Err(e) => return e,
    };

    let payload = match ctx.prepare_channel_write_payload(bytes_ptr, num_bytes) {
        Ok(payload) => payload,
        Err(e) => return e,
    };
    match crate::object::transport::channel_write(handle, options, payload, handles) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_channel_read(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let options = match ctx.arg_u32(args, 1) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let bytes_ptr = ctx.arg_ptr::<u8>(args, 2);
    let handles_ptr = ctx.arg_ptr::<zx_handle_t>(args, 3);
    let num_bytes = match ctx.arg_u32(args, 4) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let num_handles = match ctx.arg_u32(args, 5) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let actual_bytes_ptr = match ctx.extra_arg_ptr::<u32>(0) {
        Ok(arg) => arg,
        Err(e) => return e,
    };
    let actual_handles_ptr = match ctx.extra_arg_ptr::<u32>(1) {
        Ok(arg) => arg,
        Err(e) => return e,
    };
    if num_bytes != 0 && bytes_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }
    if num_handles != 0 && handles_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }
    if let Err(e) = ctx.probe_write_handles(handles_ptr, num_handles as usize) {
        return e;
    }

    let message =
        match crate::object::transport::channel_read(handle, options, num_bytes, num_handles) {
            Ok(message) => message,
            Err((status, actual_bytes, actual_handles)) => {
                let _ = ctx.copyout_optional(actual_bytes_ptr, actual_bytes);
                let _ = ctx.copyout_optional(actual_handles_ptr, actual_handles);
                return status;
            }
        };
    let actual_bytes = message.actual_bytes;
    let actual_handles = message.actual_handles;
    let transferred_handles = message.handles.clone();
    let copy_result = ctx.write_channel_payload_to_user(bytes_ptr, &message.payload);
    crate::object::transport::release_channel_read_result(message);
    if let Err(e) = copy_result {
        return e;
    }
    if let Err(e) = ctx.copyout_handles(handles_ptr, &transferred_handles) {
        return e;
    }
    if let Err(e) = ctx.copyout_optional(actual_bytes_ptr, actual_bytes) {
        return e;
    }
    if let Err(e) = ctx.copyout_optional(actual_handles_ptr, actual_handles) {
        return e;
    }
    ZX_OK
}

fn sys_eventpair_create(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let options = match ctx.arg_u32(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let out0_ptr = ctx.arg_ptr::<zx_handle_t>(args, 1);
    let out1_ptr = ctx.arg_ptr::<zx_handle_t>(args, 2);
    if let Err(err) = ctx.probe_write_value(out0_ptr) {
        return err;
    }
    if let Err(err) = ctx.probe_write_value(out1_ptr) {
        return err;
    }

    let (out0, out1) = match crate::object::create_eventpair(options) {
        Ok(handles) => handles,
        Err(e) => return e,
    };
    if let Err(e) = ctx.copyout(out0_ptr, out0) {
        return e;
    }
    if let Err(e) = ctx.copyout(out1_ptr, out1) {
        return e;
    }
    ZX_OK
}

fn sys_object_signal_peer(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let clear_mask = match ctx.arg_u32(args, 1) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let set_mask = match ctx.arg_u32(args, 2) {
        Ok(v) => v,
        Err(err) => return err,
    };

    match crate::object::object_signal_peer(handle, clear_mask, set_mask) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_object_signal(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let clear_mask = match ctx.arg_u32(args, 1) {
        Ok(v) => v,
        Err(err) => return err,
    };
    let set_mask = match ctx.arg_u32(args, 2) {
        Ok(v) => v,
        Err(err) => return err,
    };

    match crate::object::object_signal(handle, clear_mask, set_mask) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_futex_wait(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let value_ptr = args[0];
    let current_value_raw = match ctx.arg_u32(args, 1) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let current_value = current_value_raw as zx_futex_t;
    let new_futex_owner = match ctx.arg_u32(args, 2) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let deadline = args[3] as zx_time_t;

    match crate::object::futex_wait(value_ptr, current_value, new_futex_owner, deadline) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_futex_wake(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let value_ptr = args[0];
    let wake_count = match ctx.arg_u32(args, 1) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match crate::object::futex_wake(value_ptr, wake_count) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_futex_requeue(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let value_ptr = args[0];
    let wake_count = match ctx.arg_u32(args, 1) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let current_value_raw = match ctx.arg_u32(args, 2) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let current_value = current_value_raw as zx_futex_t;
    let requeue_ptr = args[3];
    let requeue_count = match ctx.arg_u32(args, 4) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let new_requeue_owner = match ctx.arg_u32(args, 5) {
        Ok(value) => value,
        Err(err) => return err,
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

fn sys_futex_get_owner(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let value_ptr = args[0];
    let koid_ptr = ctx.arg_ptr::<zx_koid_t>(args, 1);
    if koid_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    let koid = match crate::object::futex_get_owner(value_ptr) {
        Ok(koid) => koid,
        Err(e) => return e,
    };
    match ctx.copyout(koid_ptr, koid) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_thread_create(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let process = match ctx.arg_handle(args, 0) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let name_ptr = ctx.arg_const_ptr::<u8>(args, 1);
    let name_size = match ctx.arg_usize(args, 2) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let options = match ctx.arg_u32(args, 3) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let out_ptr = ctx.arg_ptr::<zx_handle_t>(args, 4);
    if out_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }
    if let Err(err) = ctx.probe_read_bytes(name_ptr, name_size) {
        return err;
    }

    let handle = match crate::object::process::create_thread(process, options) {
        Ok(handle) => handle,
        Err(e) => return e,
    };
    match ctx.copyout(out_ptr, handle) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_thread_start(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let thread = match ctx.arg_handle(args, 0) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let entry = args[1];
    let stack = args[2];
    let arg1 = args[3];
    let arg2 = args[4];

    match crate::object::process::start_thread(thread, entry, stack, arg1, arg2) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_process_create(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let parent_process = match ctx.arg_handle(args, 0) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let name_ptr = ctx.arg_const_ptr::<u8>(args, 1);
    let name_size = match ctx.arg_usize(args, 2) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let options = match ctx.arg_u32(args, 3) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let out_process_ptr = ctx.arg_ptr::<zx_handle_t>(args, 4);
    let out_vmar_ptr = ctx.arg_ptr::<zx_handle_t>(args, 5);
    if out_process_ptr.is_null() || out_vmar_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }
    if let Err(err) = ctx.probe_read_bytes(name_ptr, name_size) {
        return err;
    }

    let (process_handle, root_vmar_handle) =
        match crate::object::process::create_process(parent_process, options) {
            Ok(handles) => handles,
            Err(e) => return e,
        };
    if let Err(e) = ctx.copyout(out_process_ptr, process_handle) {
        return e;
    }
    match ctx.copyout(out_vmar_ptr, root_vmar_handle) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_process_start(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let process = match ctx.arg_handle(args, 0) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let thread = match ctx.arg_handle(args, 1) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let entry = args[2];
    let stack = args[3];
    let arg_handle = match ctx.arg_handle(args, 4) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let arg2 = args[5];

    match crate::object::process::start_process(process, thread, entry, stack, arg_handle, arg2) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_ax_process_prepare_start(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let process = match ctx.arg_handle(args, 0) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let image_vmo = match ctx.arg_handle(args, 1) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let options = match ctx.arg_u32(args, 2) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let out_entry_ptr = ctx.arg_ptr::<zx_vaddr_t>(args, 3);
    let out_stack_ptr = ctx.arg_ptr::<zx_vaddr_t>(args, 4);
    if out_entry_ptr.is_null() || out_stack_ptr.is_null() {
        return ZX_ERR_INVALID_ARGS;
    }

    let prepared = match crate::object::process::prepare_process_start(process, image_vmo, options)
    {
        Ok(prepared) => prepared,
        Err(err) => return err,
    };
    if let Err(err) = ctx.copyout(out_entry_ptr, prepared.entry()) {
        return err;
    }
    match ctx.copyout(out_stack_ptr, prepared.stack_top()) {
        Ok(()) => ZX_OK,
        Err(err) => err,
    }
}

fn sys_task_kill(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match crate::object::process::task_kill(handle) {
        Ok(()) => ZX_OK,
        Err(e) => e,
    }
}

fn sys_task_suspend(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
    let handle = match ctx.arg_handle(args, 0) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let out_token = ctx.arg_ptr::<zx_handle_t>(args, 1);

    match crate::object::process::task_suspend(handle, out_token) {
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
