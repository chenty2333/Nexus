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
    AXLE_SYS_AX_GUEST_SESSION_CREATE, AXLE_SYS_AX_GUEST_SESSION_READ_MEMORY,
    AXLE_SYS_AX_GUEST_SESSION_RESUME, AXLE_SYS_AX_GUEST_SESSION_WRITE_MEMORY,
    AXLE_SYS_AX_PROCESS_PREPARE_LINUX_EXEC, AXLE_SYS_AX_PROCESS_PREPARE_START,
    AXLE_SYS_AX_PROCESS_START_GUEST, AXLE_SYS_AX_THREAD_GET_GUEST_X64_FS_BASE,
    AXLE_SYS_AX_THREAD_SET_GUEST_X64_FS_BASE, AXLE_SYS_AX_THREAD_START_GUEST,
    AXLE_SYS_CHANNEL_CREATE, AXLE_SYS_CHANNEL_READ, AXLE_SYS_CHANNEL_WRITE,
    AXLE_SYS_EVENTPAIR_CREATE, AXLE_SYS_FUTEX_GET_OWNER, AXLE_SYS_FUTEX_REQUEUE,
    AXLE_SYS_FUTEX_WAIT, AXLE_SYS_FUTEX_WAKE, AXLE_SYS_HANDLE_CLOSE,
    AXLE_SYS_HANDLE_DUPLICATE, AXLE_SYS_HANDLE_REPLACE, AXLE_SYS_OBJECT_SIGNAL,
    AXLE_SYS_OBJECT_SIGNAL_PEER, AXLE_SYS_OBJECT_WAIT_ASYNC, AXLE_SYS_OBJECT_WAIT_ONE,
    AXLE_SYS_PORT_CREATE, AXLE_SYS_PORT_QUEUE, AXLE_SYS_PORT_WAIT, AXLE_SYS_PROCESS_CREATE,
    AXLE_SYS_PROCESS_START, AXLE_SYS_SOCKET_CREATE, AXLE_SYS_SOCKET_READ,
    AXLE_SYS_SOCKET_WRITE, AXLE_SYS_TASK_KILL, AXLE_SYS_TASK_SUSPEND, AXLE_SYS_THREAD_CREATE,
    AXLE_SYS_THREAD_START, AXLE_SYS_TIMER_CANCEL, AXLE_SYS_TIMER_CREATE, AXLE_SYS_TIMER_SET,
    AXLE_SYS_VMAR_ALLOCATE, AXLE_SYS_VMAR_DESTROY, AXLE_SYS_VMAR_MAP, AXLE_SYS_VMAR_PROTECT,
    AXLE_SYS_VMAR_UNMAP, AXLE_SYS_VMO_CREATE, AXLE_SYS_VMO_READ, AXLE_SYS_VMO_SET_SIZE,
    AXLE_SYS_VMO_WRITE, SyscallNumber,
};
use axle_types::wait_async::{
    ZX_WAIT_ASYNC_BOOT_TIMESTAMP, ZX_WAIT_ASYNC_EDGE, ZX_WAIT_ASYNC_TIMESTAMP,
};
use axle_types::{
    ax_guest_x64_regs_t, zx_clock_t, zx_duration_t, zx_futex_t, zx_handle_t, zx_koid_t,
    zx_port_packet_t, zx_rights_t, zx_signals_t, zx_status_t, zx_time_t, zx_vaddr_t,
    zx_vm_option_t,
};

/// Phase-B bootstrap syscall numbers supported by the shared ABI spec.
pub const BOOTSTRAP_SYSCALLS: [SyscallNumber; 49] = [
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
    AXLE_SYS_AX_PROCESS_PREPARE_LINUX_EXEC,
    AXLE_SYS_AX_GUEST_SESSION_CREATE,
    AXLE_SYS_AX_GUEST_SESSION_RESUME,
    AXLE_SYS_AX_GUEST_SESSION_READ_MEMORY,
    AXLE_SYS_AX_GUEST_SESSION_WRITE_MEMORY,
    AXLE_SYS_AX_PROCESS_START_GUEST,
    AXLE_SYS_AX_THREAD_START_GUEST,
    AXLE_SYS_AX_THREAD_SET_GUEST_X64_FS_BASE,
    AXLE_SYS_AX_THREAD_GET_GUEST_X64_FS_BASE,
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

#[derive(Clone, Copy, Debug, Default)]
struct NoWriteback;

#[derive(Debug)]
struct OutValue<T> {
    ptr: *mut T,
}

impl<T> Clone for OutValue<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for OutValue<T> {}

impl<T> OutValue<T> {
    fn new(ptr: *mut T) -> Result<Self, zx_status_t> {
        if ptr.is_null() {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        Ok(Self { ptr })
    }

    const fn ptr(self) -> *mut T {
        self.ptr
    }
}

#[derive(Debug)]
struct OptionalOutValue<T> {
    ptr: *mut T,
}

impl<T> Clone for OptionalOutValue<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for OptionalOutValue<T> {}

impl<T> OptionalOutValue<T> {
    const fn new(ptr: *mut T) -> Self {
        Self { ptr }
    }

    const fn is_null(self) -> bool {
        self.ptr.is_null()
    }

    const fn ptr(self) -> *mut T {
        self.ptr
    }
}

#[derive(Debug)]
struct UserWriteBytes {
    ptr: *mut u8,
    len: usize,
}

impl Clone for UserWriteBytes {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for UserWriteBytes {}

impl UserWriteBytes {
    fn new(ptr: *mut u8, len: usize) -> Result<Self, zx_status_t> {
        if len != 0 && ptr.is_null() {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        Ok(Self { ptr, len })
    }

    const fn ptr(self) -> *mut u8 {
        self.ptr
    }

    const fn len(self) -> usize {
        self.len
    }
}

#[derive(Debug)]
struct OutHandles {
    ptr: *mut zx_handle_t,
    len: usize,
}

impl Clone for OutHandles {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for OutHandles {}

impl OutHandles {
    fn new(ptr: *mut zx_handle_t, len: usize) -> Result<Self, zx_status_t> {
        if len != 0 && ptr.is_null() {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        Ok(Self { ptr, len })
    }

    const fn ptr(self) -> *mut zx_handle_t {
        self.ptr
    }

    const fn len(self) -> usize {
        self.len
    }
}

#[derive(Debug)]
struct DecodedSyscall<Request, Writeback> {
    request: Request,
    writeback: Writeback,
}

impl<Request, Writeback> DecodedSyscall<Request, Writeback> {
    fn new(request: Request, writeback: Writeback) -> Self {
        Self { request, writeback }
    }
}

struct TypedSyscallDesc<Request, Writeback, Response> {
    decode:
        fn(&mut SyscallCtx, [u64; 6]) -> Result<DecodedSyscall<Request, Writeback>, zx_status_t>,
    run: fn(Request) -> Result<Response, zx_status_t>,
    writeback: fn(&mut SyscallCtx, Writeback, Response) -> Result<(), zx_status_t>,
}

impl<Request, Writeback, Response> TypedSyscallDesc<Request, Writeback, Response> {
    const fn new(
        decode: fn(
            &mut SyscallCtx,
            [u64; 6],
        ) -> Result<DecodedSyscall<Request, Writeback>, zx_status_t>,
        run: fn(Request) -> Result<Response, zx_status_t>,
        writeback: fn(&mut SyscallCtx, Writeback, Response) -> Result<(), zx_status_t>,
    ) -> Self {
        Self {
            decode,
            run,
            writeback,
        }
    }

    fn invoke(&self, ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
        let decoded = match (self.decode)(ctx, args) {
            Ok(decoded) => decoded,
            Err(err) => return err,
        };
        let response = match (self.run)(decoded.request) {
            Ok(response) => response,
            Err(err) => return err,
        };
        match (self.writeback)(ctx, decoded.writeback, response) {
            Ok(()) => ZX_OK,
            Err(err) => err,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct SyscallDispatch {
    invoke: fn(&mut SyscallCtx, [u64; 6]) -> zx_status_t,
}

impl SyscallDispatch {
    const fn new(invoke: fn(&mut SyscallCtx, [u64; 6]) -> zx_status_t) -> Self {
        Self { invoke }
    }
}

macro_rules! typed_syscall {
    ($typed_desc:ident, $entry_fn:ident, $request:ty, $writeback:ty, $response:ty, $decode:path, $run:path, $writeback_fn:path) => {
        const $typed_desc: TypedSyscallDesc<$request, $writeback, $response> =
            TypedSyscallDesc::new($decode, $run, $writeback_fn);

        fn $entry_fn(ctx: &mut SyscallCtx, args: [u64; 6]) -> zx_status_t {
            $typed_desc.invoke(ctx, args)
        }
    };
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
        Ok(args[index])
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
        crate::copy::copyin_value(extra_ptr)
    }

    fn extra_arg_ptr<T>(&self, index: usize) -> Result<*mut T, zx_status_t> {
        Ok(self.extra_arg_u64(index)? as *mut T)
    }

    fn decode_out_value<T>(
        &self,
        args: [u64; 6],
        index: usize,
    ) -> Result<OutValue<T>, zx_status_t> {
        let out = OutValue::new(self.arg_ptr(args, index))?;
        probe_out_value(out)?;
        Ok(out)
    }

    fn decode_extra_out_value<T>(&self, index: usize) -> Result<OutValue<T>, zx_status_t> {
        let out = OutValue::new(self.extra_arg_ptr(index)?)?;
        probe_out_value(out)?;
        Ok(out)
    }

    fn decode_optional_out_value<T>(
        &self,
        args: [u64; 6],
        index: usize,
    ) -> Result<OptionalOutValue<T>, zx_status_t> {
        let out = OptionalOutValue::new(self.arg_ptr(args, index));
        probe_optional_out_value(out)?;
        Ok(out)
    }

    fn decode_optional_extra_out_value<T>(
        &self,
        index: usize,
    ) -> Result<OptionalOutValue<T>, zx_status_t> {
        let out = OptionalOutValue::new(self.extra_arg_ptr(index)?);
        probe_optional_out_value(out)?;
        Ok(out)
    }

    fn decode_user_write_bytes(
        &self,
        ptr: *mut u8,
        len: usize,
    ) -> Result<UserWriteBytes, zx_status_t> {
        let out = UserWriteBytes::new(ptr, len)?;
        if out.len() != 0 {
            crate::copy::probe_resident_write_bytes(out.ptr(), out.len())?;
        }
        Ok(out)
    }

    fn decode_out_handles(
        &self,
        ptr: *mut zx_handle_t,
        len: usize,
    ) -> Result<OutHandles, zx_status_t> {
        let out = OutHandles::new(ptr, len)?;
        if out.len() != 0 {
            crate::copy::probe_write_handles(out.ptr(), out.len())?;
        }
        Ok(out)
    }

    fn decode_signals_sink(
        &self,
        args: [u64; 6],
        index: usize,
    ) -> Result<crate::wait::UserSignalsSink, zx_status_t> {
        crate::wait::UserSignalsSink::new(self.decode_out_value::<zx_signals_t>(args, index)?.ptr())
    }

    fn decode_port_packet_sink(
        &self,
        args: [u64; 6],
        index: usize,
    ) -> Result<crate::wait::UserPortPacketSink, zx_status_t> {
        crate::wait::UserPortPacketSink::new(
            self.decode_out_value::<zx_port_packet_t>(args, index)?
                .ptr(),
        )
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
    match syscall_dispatch(nr) {
        Some(dispatch) => (dispatch.invoke)(ctx, args),
        None => ZX_ERR_BAD_SYSCALL,
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

fn probe_out_value<T>(out: OutValue<T>) -> Result<(), zx_status_t> {
    crate::copy::probe_write_value(out.ptr())
}

fn probe_optional_out_value<T>(out: OptionalOutValue<T>) -> Result<(), zx_status_t> {
    if out.is_null() {
        return Ok(());
    }
    crate::copy::probe_write_value(out.ptr())
}

fn decode_input_value<T: Copy>(ptr: *const T) -> Result<T, zx_status_t> {
    crate::copy::copyin_value(ptr)
}

fn decode_input_bytes(ptr: *const u8, len: usize) -> Result<Vec<u8>, zx_status_t> {
    crate::copy::copyin_bytes(ptr, len)
}

fn decode_input_handles(
    ptr: *const zx_handle_t,
    len: usize,
) -> Result<Vec<zx_handle_t>, zx_status_t> {
    crate::copy::copyin_handles(ptr, len)
}

fn probe_input_bytes(ptr: *const u8, len: usize) -> Result<(), zx_status_t> {
    crate::copy::probe_read_bytes(ptr, len)
}

fn prepare_channel_payload(
    ptr: *const u8,
    len: usize,
) -> Result<crate::object::ChannelPayload, zx_status_t> {
    crate::copy::prepare_channel_write_payload(ptr, len)
}

fn write_out_value<T: Copy>(out: OutValue<T>, value: T) -> Result<(), zx_status_t> {
    crate::copy::copyout_value(out.ptr(), value)
}

fn write_optional_out_value<T: Copy>(
    out: OptionalOutValue<T>,
    value: T,
) -> Result<(), zx_status_t> {
    if out.is_null() {
        return Ok(());
    }
    crate::copy::copyout_value(out.ptr(), value)
}

fn write_user_bytes(out: UserWriteBytes, bytes: &[u8]) -> Result<(), zx_status_t> {
    crate::copy::copyout_bytes(out.ptr(), bytes)
}

fn write_out_handles(out: OutHandles, handles: &[zx_handle_t]) -> Result<(), zx_status_t> {
    crate::copy::copyout_handles(out.ptr(), handles)
}

fn write_channel_payload(
    out: UserWriteBytes,
    payload: &crate::object::ChannelPayload,
) -> Result<(), zx_status_t> {
    crate::copy::write_channel_payload_to_user(out.ptr(), payload)
}

fn write_signals_sink(
    sink: crate::wait::UserSignalsSink,
    observed: zx_signals_t,
) -> Result<(), zx_status_t> {
    crate::copy::copyout_value(sink.ptr(), observed)
}

fn write_port_packet_sink(
    sink: crate::wait::UserPortPacketSink,
    packet: zx_port_packet_t,
) -> Result<(), zx_status_t> {
    crate::copy::copyout_value(sink.ptr(), packet)
}

fn writeback_noop(
    _ctx: &mut SyscallCtx,
    _writeback: NoWriteback,
    _response: (),
) -> Result<(), zx_status_t> {
    Ok(())
}

fn writeback_handle(
    _ctx: &mut SyscallCtx,
    out: OutValue<zx_handle_t>,
    handle: zx_handle_t,
) -> Result<(), zx_status_t> {
    write_out_value(out, handle)
}

fn writeback_handle_pair(
    _ctx: &mut SyscallCtx,
    outs: (OutValue<zx_handle_t>, OutValue<zx_handle_t>),
    handles: (zx_handle_t, zx_handle_t),
) -> Result<(), zx_status_t> {
    write_out_value(outs.0, handles.0)?;
    write_out_value(outs.1, handles.1)
}

fn writeback_handle_and_vaddr(
    _ctx: &mut SyscallCtx,
    outs: (OutValue<zx_handle_t>, OutValue<zx_vaddr_t>),
    values: (zx_handle_t, zx_vaddr_t),
) -> Result<(), zx_status_t> {
    write_out_value(outs.0, values.0)?;
    write_out_value(outs.1, values.1)
}

fn writeback_vaddr(
    _ctx: &mut SyscallCtx,
    out: OutValue<zx_vaddr_t>,
    value: zx_vaddr_t,
) -> Result<(), zx_status_t> {
    write_out_value(out, value)
}

fn writeback_vaddr_pair(
    _ctx: &mut SyscallCtx,
    outs: (OutValue<zx_vaddr_t>, OutValue<zx_vaddr_t>),
    values: crate::task::PreparedProcessStart,
) -> Result<(), zx_status_t> {
    write_out_value(outs.0, values.entry())?;
    write_out_value(outs.1, values.stack_top())
}

fn writeback_koid(
    _ctx: &mut SyscallCtx,
    out: OutValue<zx_koid_t>,
    koid: zx_koid_t,
) -> Result<(), zx_status_t> {
    write_out_value(out, koid)
}

fn writeback_u64(
    _ctx: &mut SyscallCtx,
    out: OutValue<u64>,
    value: u64,
) -> Result<(), zx_status_t> {
    write_out_value(out, value)
}

fn writeback_optional_usize(
    _ctx: &mut SyscallCtx,
    out: OptionalOutValue<usize>,
    value: usize,
) -> Result<(), zx_status_t> {
    write_optional_out_value(out, value)
}

#[derive(Clone, Copy, Debug)]
struct WaitOneRequest {
    handle: zx_handle_t,
    signals: zx_signals_t,
    deadline: i64,
    sink: crate::wait::UserSignalsSink,
}

#[derive(Clone, Copy, Debug)]
struct WaitOneWriteback {
    sink: crate::wait::UserSignalsSink,
}

fn decode_handle_close(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<zx_handle_t, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(ctx.arg_handle(args, 0)?, NoWriteback))
}

fn run_handle_close(handle: zx_handle_t) -> Result<(), zx_status_t> {
    crate::object::close_handle(handle)
}

typed_syscall!(
    HANDLE_CLOSE_TYPED,
    handle_close_entry,
    zx_handle_t,
    NoWriteback,
    (),
    decode_handle_close,
    run_handle_close,
    writeback_noop
);
const HANDLE_CLOSE_DISPATCH: SyscallDispatch = SyscallDispatch::new(handle_close_entry);

type HandleWithRightsRequest = (zx_handle_t, zx_rights_t);

fn decode_handle_duplicate(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<HandleWithRightsRequest, OutValue<zx_handle_t>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (
            ctx.arg_handle(args, 0)?,
            ctx.arg_u32(args, 1)? as zx_rights_t,
        ),
        ctx.decode_out_value::<zx_handle_t>(args, 2)?,
    ))
}

fn run_handle_duplicate(req: HandleWithRightsRequest) -> Result<zx_handle_t, zx_status_t> {
    crate::object::handle::duplicate_handle(req.0, req.1)
}

typed_syscall!(
    HANDLE_DUPLICATE_TYPED,
    handle_duplicate_entry,
    HandleWithRightsRequest,
    OutValue<zx_handle_t>,
    zx_handle_t,
    decode_handle_duplicate,
    run_handle_duplicate,
    writeback_handle
);
const HANDLE_DUPLICATE_DISPATCH: SyscallDispatch = SyscallDispatch::new(handle_duplicate_entry);

fn decode_handle_replace(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<HandleWithRightsRequest, OutValue<zx_handle_t>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (
            ctx.arg_handle(args, 0)?,
            ctx.arg_u32(args, 1)? as zx_rights_t,
        ),
        ctx.decode_out_value::<zx_handle_t>(args, 2)?,
    ))
}

fn run_handle_replace(req: HandleWithRightsRequest) -> Result<zx_handle_t, zx_status_t> {
    crate::object::handle::replace_handle(req.0, req.1)
}

typed_syscall!(
    HANDLE_REPLACE_TYPED,
    handle_replace_entry,
    HandleWithRightsRequest,
    OutValue<zx_handle_t>,
    zx_handle_t,
    decode_handle_replace,
    run_handle_replace,
    writeback_handle
);
const HANDLE_REPLACE_DISPATCH: SyscallDispatch = SyscallDispatch::new(handle_replace_entry);

fn decode_object_wait_one(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<WaitOneRequest, WaitOneWriteback>, zx_status_t> {
    let signals = ctx.arg_u32(args, 1)?;
    if signals == 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let sink = ctx.decode_signals_sink(args, 3)?;
    Ok(DecodedSyscall::new(
        WaitOneRequest {
            handle: ctx.arg_handle(args, 0)?,
            signals,
            deadline: args[2] as i64,
            sink,
        },
        WaitOneWriteback { sink },
    ))
}

fn run_object_wait_one(req: WaitOneRequest) -> Result<crate::wait::WaitOneOutcome, zx_status_t> {
    crate::wait::object_wait_one(req.handle, req.signals, req.deadline, req.sink)
}

fn writeback_object_wait_one(
    _ctx: &mut SyscallCtx,
    writeback: WaitOneWriteback,
    response: crate::wait::WaitOneOutcome,
) -> Result<(), zx_status_t> {
    match response {
        crate::wait::WaitOneOutcome::Completed { observed } => {
            write_signals_sink(writeback.sink, observed)
        }
        crate::wait::WaitOneOutcome::Blocked => Ok(()),
    }
}

typed_syscall!(
    OBJECT_WAIT_ONE_TYPED,
    object_wait_one_entry,
    WaitOneRequest,
    WaitOneWriteback,
    crate::wait::WaitOneOutcome,
    decode_object_wait_one,
    run_object_wait_one,
    writeback_object_wait_one
);
const OBJECT_WAIT_ONE_DISPATCH: SyscallDispatch = SyscallDispatch::new(object_wait_one_entry);

#[derive(Clone, Copy, Debug)]
struct WaitAsyncRequest {
    handle: zx_handle_t,
    port: zx_handle_t,
    key: u64,
    signals: zx_signals_t,
    options: WaitAsyncOptions,
}

fn decode_object_wait_async(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<WaitAsyncRequest, NoWriteback>, zx_status_t> {
    let signals = ctx.arg_u32(args, 3)?;
    if signals == 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let options = ctx.arg_u32(args, 4)?;
    let allowed = ZX_WAIT_ASYNC_TIMESTAMP | ZX_WAIT_ASYNC_EDGE | ZX_WAIT_ASYNC_BOOT_TIMESTAMP;
    if (options & !allowed) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if (options & ZX_WAIT_ASYNC_TIMESTAMP) != 0 && (options & ZX_WAIT_ASYNC_BOOT_TIMESTAMP) != 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    let timestamp = if (options & ZX_WAIT_ASYNC_BOOT_TIMESTAMP) != 0 {
        WaitAsyncTimestamp::Boot
    } else if (options & ZX_WAIT_ASYNC_TIMESTAMP) != 0 {
        WaitAsyncTimestamp::Monotonic
    } else {
        WaitAsyncTimestamp::None
    };
    Ok(DecodedSyscall::new(
        WaitAsyncRequest {
            handle: ctx.arg_handle(args, 0)?,
            port: ctx.arg_handle(args, 1)?,
            key: args[2],
            signals,
            options: WaitAsyncOptions {
                edge_triggered: (options & ZX_WAIT_ASYNC_EDGE) != 0,
                timestamp,
            },
        },
        NoWriteback,
    ))
}

fn run_object_wait_async(req: WaitAsyncRequest) -> Result<(), zx_status_t> {
    crate::wait::object_wait_async(req.handle, req.port, req.key, req.signals, req.options)
}

typed_syscall!(
    OBJECT_WAIT_ASYNC_TYPED,
    object_wait_async_entry,
    WaitAsyncRequest,
    NoWriteback,
    (),
    decode_object_wait_async,
    run_object_wait_async,
    writeback_noop
);
const OBJECT_WAIT_ASYNC_DISPATCH: SyscallDispatch = SyscallDispatch::new(object_wait_async_entry);

fn decode_port_create(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<u32, OutValue<zx_handle_t>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        ctx.arg_u32(args, 0)?,
        ctx.decode_out_value::<zx_handle_t>(args, 1)?,
    ))
}

fn run_port_create(options: u32) -> Result<zx_handle_t, zx_status_t> {
    crate::object::create_port(options)
}

typed_syscall!(
    PORT_CREATE_TYPED,
    port_create_entry,
    u32,
    OutValue<zx_handle_t>,
    zx_handle_t,
    decode_port_create,
    run_port_create,
    writeback_handle
);
const PORT_CREATE_DISPATCH: SyscallDispatch = SyscallDispatch::new(port_create_entry);

type PortQueueRequest = (zx_handle_t, zx_port_packet_t);

fn decode_port_queue(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<PortQueueRequest, NoWriteback>, zx_status_t> {
    let packet_ptr = ctx.arg_const_ptr::<zx_port_packet_t>(args, 1);
    if packet_ptr.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, decode_input_value(packet_ptr)?),
        NoWriteback,
    ))
}

fn run_port_queue(req: PortQueueRequest) -> Result<(), zx_status_t> {
    crate::wait::queue_port_packet(req.0, req.1)
}

typed_syscall!(
    PORT_QUEUE_TYPED,
    port_queue_entry,
    PortQueueRequest,
    NoWriteback,
    (),
    decode_port_queue,
    run_port_queue,
    writeback_noop
);
const PORT_QUEUE_DISPATCH: SyscallDispatch = SyscallDispatch::new(port_queue_entry);

#[derive(Clone, Copy, Debug)]
struct PortWaitRequest {
    handle: zx_handle_t,
    deadline: i64,
    sink: crate::wait::UserPortPacketSink,
}

#[derive(Clone, Copy, Debug)]
struct PortWaitWriteback {
    sink: crate::wait::UserPortPacketSink,
}

fn decode_port_wait(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<PortWaitRequest, PortWaitWriteback>, zx_status_t> {
    let sink = ctx.decode_port_packet_sink(args, 2)?;
    Ok(DecodedSyscall::new(
        PortWaitRequest {
            handle: ctx.arg_handle(args, 0)?,
            deadline: args[1] as i64,
            sink,
        },
        PortWaitWriteback { sink },
    ))
}

fn run_port_wait(req: PortWaitRequest) -> Result<crate::wait::PortWaitOutcome, zx_status_t> {
    crate::wait::port_wait(req.handle, req.deadline, req.sink)
}

fn writeback_port_wait(
    _ctx: &mut SyscallCtx,
    writeback: PortWaitWriteback,
    response: crate::wait::PortWaitOutcome,
) -> Result<(), zx_status_t> {
    match response {
        crate::wait::PortWaitOutcome::Completed { packet } => {
            write_port_packet_sink(writeback.sink, packet)
        }
        crate::wait::PortWaitOutcome::Blocked => Ok(()),
    }
}

typed_syscall!(
    PORT_WAIT_TYPED,
    port_wait_entry,
    PortWaitRequest,
    PortWaitWriteback,
    crate::wait::PortWaitOutcome,
    decode_port_wait,
    run_port_wait,
    writeback_port_wait
);
const PORT_WAIT_DISPATCH: SyscallDispatch = SyscallDispatch::new(port_wait_entry);

type TimerCreateRequest = (u32, u32);

fn decode_timer_create(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<TimerCreateRequest, OutValue<zx_handle_t>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (ctx.arg_u32(args, 0)?, ctx.arg_u32(args, 1)?),
        ctx.decode_out_value::<zx_handle_t>(args, 2)?,
    ))
}

fn run_timer_create(req: TimerCreateRequest) -> Result<zx_handle_t, zx_status_t> {
    crate::object::create_timer(req.0, req.1)
}

typed_syscall!(
    TIMER_CREATE_TYPED,
    timer_create_entry,
    TimerCreateRequest,
    OutValue<zx_handle_t>,
    zx_handle_t,
    decode_timer_create,
    run_timer_create,
    writeback_handle
);
const TIMER_CREATE_DISPATCH: SyscallDispatch = SyscallDispatch::new(timer_create_entry);

type TimerSetRequest = (zx_handle_t, i64, i64);

fn decode_timer_set(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<TimerSetRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, args[1] as i64, args[2] as i64),
        NoWriteback,
    ))
}

fn run_timer_set(req: TimerSetRequest) -> Result<(), zx_status_t> {
    crate::object::timer_set(req.0, req.1, req.2)
}

typed_syscall!(
    TIMER_SET_TYPED,
    timer_set_entry,
    TimerSetRequest,
    NoWriteback,
    (),
    decode_timer_set,
    run_timer_set,
    writeback_noop
);
const TIMER_SET_DISPATCH: SyscallDispatch = SyscallDispatch::new(timer_set_entry);

fn decode_timer_cancel(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<zx_handle_t, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(ctx.arg_handle(args, 0)?, NoWriteback))
}

fn run_timer_cancel(handle: zx_handle_t) -> Result<(), zx_status_t> {
    crate::object::timer_cancel(handle)
}

typed_syscall!(
    TIMER_CANCEL_TYPED,
    timer_cancel_entry,
    zx_handle_t,
    NoWriteback,
    (),
    decode_timer_cancel,
    run_timer_cancel,
    writeback_noop
);
const TIMER_CANCEL_DISPATCH: SyscallDispatch = SyscallDispatch::new(timer_cancel_entry);

type VmoCreateRequest = (u64, u32);

fn decode_vmo_create(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<VmoCreateRequest, OutValue<zx_handle_t>>, zx_status_t> {
    let size = align_up_page(args[0]).unwrap_or(0);
    if size == 0 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(DecodedSyscall::new(
        (size, ctx.arg_u32(args, 1)?),
        ctx.decode_out_value::<zx_handle_t>(args, 2)?,
    ))
}

fn run_vmo_create(req: VmoCreateRequest) -> Result<zx_handle_t, zx_status_t> {
    crate::object::vm::create_vmo(req.0, req.1)
}

typed_syscall!(
    VMO_CREATE_TYPED,
    vmo_create_entry,
    VmoCreateRequest,
    OutValue<zx_handle_t>,
    zx_handle_t,
    decode_vmo_create,
    run_vmo_create,
    writeback_handle
);
const VMO_CREATE_DISPATCH: SyscallDispatch = SyscallDispatch::new(vmo_create_entry);

#[derive(Debug)]
struct VmoReadRequest {
    handle: zx_handle_t,
    offset: u64,
    len: usize,
}

fn decode_vmo_read(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<VmoReadRequest, UserWriteBytes>, zx_status_t> {
    let len = ctx.arg_usize_or(args, 3, ZX_ERR_OUT_OF_RANGE)?;
    let out = ctx.decode_user_write_bytes(ctx.arg_ptr::<u8>(args, 1), len)?;
    Ok(DecodedSyscall::new(
        VmoReadRequest {
            handle: ctx.arg_handle(args, 0)?,
            offset: args[2],
            len,
        },
        out,
    ))
}

fn run_vmo_read(req: VmoReadRequest) -> Result<Vec<u8>, zx_status_t> {
    crate::object::vm::vmo_read(req.handle, req.offset, req.len)
}

fn writeback_vmo_read(
    _ctx: &mut SyscallCtx,
    out: UserWriteBytes,
    bytes: Vec<u8>,
) -> Result<(), zx_status_t> {
    write_user_bytes(out, &bytes)
}

typed_syscall!(
    VMO_READ_TYPED,
    vmo_read_entry,
    VmoReadRequest,
    UserWriteBytes,
    Vec<u8>,
    decode_vmo_read,
    run_vmo_read,
    writeback_vmo_read
);
const VMO_READ_DISPATCH: SyscallDispatch = SyscallDispatch::new(vmo_read_entry);

#[derive(Debug)]
struct VmoWriteRequest {
    handle: zx_handle_t,
    offset: u64,
    bytes: Vec<u8>,
}

fn decode_vmo_write(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<VmoWriteRequest, NoWriteback>, zx_status_t> {
    let len = ctx.arg_usize_or(args, 3, ZX_ERR_OUT_OF_RANGE)?;
    let buffer = ctx.arg_const_ptr::<u8>(args, 1);
    if len != 0 && buffer.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(DecodedSyscall::new(
        VmoWriteRequest {
            handle: ctx.arg_handle(args, 0)?,
            offset: args[2],
            bytes: decode_input_bytes(buffer, len)?,
        },
        NoWriteback,
    ))
}

fn run_vmo_write(req: VmoWriteRequest) -> Result<(), zx_status_t> {
    crate::object::vm::vmo_write(req.handle, req.offset, &req.bytes)
}

typed_syscall!(
    VMO_WRITE_TYPED,
    vmo_write_entry,
    VmoWriteRequest,
    NoWriteback,
    (),
    decode_vmo_write,
    run_vmo_write,
    writeback_noop
);
const VMO_WRITE_DISPATCH: SyscallDispatch = SyscallDispatch::new(vmo_write_entry);

type VmoSetSizeRequest = (zx_handle_t, u64);

fn decode_vmo_set_size(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<VmoSetSizeRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, args[1]),
        NoWriteback,
    ))
}

fn run_vmo_set_size(req: VmoSetSizeRequest) -> Result<(), zx_status_t> {
    crate::object::vm::vmo_set_size(req.0, req.1)
}

typed_syscall!(
    VMO_SET_SIZE_TYPED,
    vmo_set_size_entry,
    VmoSetSizeRequest,
    NoWriteback,
    (),
    decode_vmo_set_size,
    run_vmo_set_size,
    writeback_noop
);
const VMO_SET_SIZE_DISPATCH: SyscallDispatch = SyscallDispatch::new(vmo_set_size_entry);

fn decode_socket_create(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<u32, (OutValue<zx_handle_t>, OutValue<zx_handle_t>)>, zx_status_t> {
    Ok(DecodedSyscall::new(
        ctx.arg_u32(args, 0)?,
        (
            ctx.decode_out_value::<zx_handle_t>(args, 1)?,
            ctx.decode_out_value::<zx_handle_t>(args, 2)?,
        ),
    ))
}

fn run_socket_create(options: u32) -> Result<(zx_handle_t, zx_handle_t), zx_status_t> {
    crate::object::transport::create_socket(options)
}

typed_syscall!(
    SOCKET_CREATE_TYPED,
    socket_create_entry,
    u32,
    (OutValue<zx_handle_t>, OutValue<zx_handle_t>),
    (zx_handle_t, zx_handle_t),
    decode_socket_create,
    run_socket_create,
    writeback_handle_pair
);
const SOCKET_CREATE_DISPATCH: SyscallDispatch = SyscallDispatch::new(socket_create_entry);

#[derive(Debug)]
struct SocketWriteRequest {
    handle: zx_handle_t,
    options: u32,
    bytes: Vec<u8>,
}

fn decode_socket_write(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<SocketWriteRequest, OptionalOutValue<usize>>, zx_status_t> {
    let len = ctx.arg_usize_or(args, 3, ZX_ERR_OUT_OF_RANGE)?;
    let buffer = ctx.arg_const_ptr::<u8>(args, 2);
    if len != 0 && buffer.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(DecodedSyscall::new(
        SocketWriteRequest {
            handle: ctx.arg_handle(args, 0)?,
            options: ctx.arg_u32(args, 1)?,
            bytes: decode_input_bytes(buffer, len)?,
        },
        ctx.decode_optional_out_value::<usize>(args, 4)?,
    ))
}

fn run_socket_write(req: SocketWriteRequest) -> Result<usize, zx_status_t> {
    crate::object::transport::socket_write(req.handle, req.options, &req.bytes)
}

typed_syscall!(
    SOCKET_WRITE_TYPED,
    socket_write_entry,
    SocketWriteRequest,
    OptionalOutValue<usize>,
    usize,
    decode_socket_write,
    run_socket_write,
    writeback_optional_usize
);
const SOCKET_WRITE_DISPATCH: SyscallDispatch = SyscallDispatch::new(socket_write_entry);

#[derive(Debug)]
struct SocketReadRequest {
    handle: zx_handle_t,
    options: u32,
    len: usize,
}

#[derive(Clone, Copy, Debug)]
struct SocketReadWriteback {
    buffer: UserWriteBytes,
    actual: OptionalOutValue<usize>,
}

fn decode_socket_read(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<SocketReadRequest, SocketReadWriteback>, zx_status_t> {
    let len = ctx.arg_usize_or(args, 3, ZX_ERR_OUT_OF_RANGE)?;
    let buffer_ptr = ctx.arg_ptr::<u8>(args, 2);
    if buffer_ptr.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(DecodedSyscall::new(
        SocketReadRequest {
            handle: ctx.arg_handle(args, 0)?,
            options: ctx.arg_u32(args, 1)?,
            len,
        },
        SocketReadWriteback {
            buffer: ctx.decode_user_write_bytes(buffer_ptr, len)?,
            actual: ctx.decode_optional_out_value::<usize>(args, 4)?,
        },
    ))
}

fn run_socket_read(req: SocketReadRequest) -> Result<Vec<u8>, zx_status_t> {
    crate::object::transport::socket_read(req.handle, req.options, req.len)
}

fn writeback_socket_read(
    _ctx: &mut SyscallCtx,
    writeback: SocketReadWriteback,
    bytes: Vec<u8>,
) -> Result<(), zx_status_t> {
    write_user_bytes(writeback.buffer, &bytes)?;
    write_optional_out_value(writeback.actual, bytes.len())
}

typed_syscall!(
    SOCKET_READ_TYPED,
    socket_read_entry,
    SocketReadRequest,
    SocketReadWriteback,
    Vec<u8>,
    decode_socket_read,
    run_socket_read,
    writeback_socket_read
);
const SOCKET_READ_DISPATCH: SyscallDispatch = SyscallDispatch::new(socket_read_entry);

#[derive(Clone, Copy, Debug)]
struct VmarAllocateRequest {
    parent_vmar: zx_handle_t,
    options: u32,
    offset: u64,
    size: u64,
}

fn decode_vmar_allocate(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<
    DecodedSyscall<VmarAllocateRequest, (OutValue<zx_handle_t>, OutValue<zx_vaddr_t>)>,
    zx_status_t,
> {
    let size = match align_up_page(args[3]) {
        Some(len) if len != 0 => len,
        _ => return Err(ZX_ERR_INVALID_ARGS),
    };
    Ok(DecodedSyscall::new(
        VmarAllocateRequest {
            parent_vmar: ctx.arg_handle(args, 0)?,
            options: ctx.arg_u32(args, 1)?,
            offset: args[2],
            size,
        },
        (
            ctx.decode_out_value::<zx_handle_t>(args, 4)?,
            ctx.decode_out_value::<zx_vaddr_t>(args, 5)?,
        ),
    ))
}

fn run_vmar_allocate(req: VmarAllocateRequest) -> Result<(zx_handle_t, zx_vaddr_t), zx_status_t> {
    crate::object::vm::vmar_allocate(req.parent_vmar, req.options, req.offset, req.size)
}

typed_syscall!(
    VMAR_ALLOCATE_TYPED,
    vmar_allocate_entry,
    VmarAllocateRequest,
    (OutValue<zx_handle_t>, OutValue<zx_vaddr_t>),
    (zx_handle_t, zx_vaddr_t),
    decode_vmar_allocate,
    run_vmar_allocate,
    writeback_handle_and_vaddr
);
const VMAR_ALLOCATE_DISPATCH: SyscallDispatch = SyscallDispatch::new(vmar_allocate_entry);

#[derive(Clone, Copy, Debug)]
struct VmarMapRequest {
    vmar: zx_handle_t,
    options: u32,
    vmar_offset: u64,
    vmo: zx_handle_t,
    vmo_offset: u64,
    len: u64,
}

fn decode_vmar_map(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<VmarMapRequest, OutValue<zx_vaddr_t>>, zx_status_t> {
    let len = match align_up_page(args[5]) {
        Some(len) if len != 0 => len,
        _ => return Err(ZX_ERR_INVALID_ARGS),
    };
    Ok(DecodedSyscall::new(
        VmarMapRequest {
            vmar: ctx.arg_handle(args, 0)?,
            options: ctx.arg_u32(args, 1)?,
            vmar_offset: args[2],
            vmo: ctx.arg_handle(args, 3)?,
            vmo_offset: args[4],
            len,
        },
        ctx.decode_extra_out_value::<zx_vaddr_t>(0)?,
    ))
}

fn run_vmar_map(req: VmarMapRequest) -> Result<zx_vaddr_t, zx_status_t> {
    crate::object::vm::vmar_map(
        req.vmar,
        req.options,
        req.vmar_offset,
        req.vmo,
        req.vmo_offset,
        req.len,
    )
}

typed_syscall!(
    VMAR_MAP_TYPED,
    vmar_map_entry,
    VmarMapRequest,
    OutValue<zx_vaddr_t>,
    zx_vaddr_t,
    decode_vmar_map,
    run_vmar_map,
    writeback_vaddr
);
const VMAR_MAP_DISPATCH: SyscallDispatch = SyscallDispatch::new(vmar_map_entry);

type VmarDestroyRequest = zx_handle_t;

fn decode_vmar_destroy(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<VmarDestroyRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(ctx.arg_handle(args, 0)?, NoWriteback))
}

fn run_vmar_destroy(handle: zx_handle_t) -> Result<(), zx_status_t> {
    crate::object::vm::vmar_destroy(handle)
}

typed_syscall!(
    VMAR_DESTROY_TYPED,
    vmar_destroy_entry,
    VmarDestroyRequest,
    NoWriteback,
    (),
    decode_vmar_destroy,
    run_vmar_destroy,
    writeback_noop
);
const VMAR_DESTROY_DISPATCH: SyscallDispatch = SyscallDispatch::new(vmar_destroy_entry);

type VmarUnmapRequest = (zx_handle_t, u64, u64);

fn decode_vmar_unmap(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<VmarUnmapRequest, NoWriteback>, zx_status_t> {
    let len = match align_up_page(args[2]) {
        Some(len) if len != 0 => len,
        _ => return Err(ZX_ERR_INVALID_ARGS),
    };
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, args[1], len),
        NoWriteback,
    ))
}

fn run_vmar_unmap(req: VmarUnmapRequest) -> Result<(), zx_status_t> {
    crate::object::vm::vmar_unmap(req.0, req.1, req.2)
}

typed_syscall!(
    VMAR_UNMAP_TYPED,
    vmar_unmap_entry,
    VmarUnmapRequest,
    NoWriteback,
    (),
    decode_vmar_unmap,
    run_vmar_unmap,
    writeback_noop
);
const VMAR_UNMAP_DISPATCH: SyscallDispatch = SyscallDispatch::new(vmar_unmap_entry);

type VmarProtectRequest = (zx_handle_t, u32, u64, u64);

fn decode_vmar_protect(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<VmarProtectRequest, NoWriteback>, zx_status_t> {
    let len = match align_up_page(args[3]) {
        Some(len) if len != 0 => len,
        _ => return Err(ZX_ERR_INVALID_ARGS),
    };
    Ok(DecodedSyscall::new(
        (
            ctx.arg_handle(args, 0)?,
            ctx.arg_u32(args, 1)?,
            args[2],
            len,
        ),
        NoWriteback,
    ))
}

fn run_vmar_protect(req: VmarProtectRequest) -> Result<(), zx_status_t> {
    crate::object::vm::vmar_protect(req.0, req.1, req.2, req.3)
}

typed_syscall!(
    VMAR_PROTECT_TYPED,
    vmar_protect_entry,
    VmarProtectRequest,
    NoWriteback,
    (),
    decode_vmar_protect,
    run_vmar_protect,
    writeback_noop
);
const VMAR_PROTECT_DISPATCH: SyscallDispatch = SyscallDispatch::new(vmar_protect_entry);

fn decode_channel_create(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<u32, (OutValue<zx_handle_t>, OutValue<zx_handle_t>)>, zx_status_t> {
    Ok(DecodedSyscall::new(
        ctx.arg_u32(args, 0)?,
        (
            ctx.decode_out_value::<zx_handle_t>(args, 1)?,
            ctx.decode_out_value::<zx_handle_t>(args, 2)?,
        ),
    ))
}

fn run_channel_create(options: u32) -> Result<(zx_handle_t, zx_handle_t), zx_status_t> {
    crate::object::transport::create_channel(options)
}

typed_syscall!(
    CHANNEL_CREATE_TYPED,
    channel_create_entry,
    u32,
    (OutValue<zx_handle_t>, OutValue<zx_handle_t>),
    (zx_handle_t, zx_handle_t),
    decode_channel_create,
    run_channel_create,
    writeback_handle_pair
);
const CHANNEL_CREATE_DISPATCH: SyscallDispatch = SyscallDispatch::new(channel_create_entry);

#[derive(Debug)]
struct ChannelWriteRequest {
    handle: zx_handle_t,
    options: u32,
    payload: crate::object::ChannelPayload,
    handles: Vec<zx_handle_t>,
}

fn decode_channel_write(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<ChannelWriteRequest, NoWriteback>, zx_status_t> {
    let num_bytes = ctx.arg_usize(args, 3)?;
    let num_handles = ctx.arg_u32(args, 5)? as usize;
    let bytes_ptr = ctx.arg_const_ptr::<u8>(args, 2);
    let handles_ptr = ctx.arg_const_ptr::<zx_handle_t>(args, 4);
    if num_bytes != 0 && bytes_ptr.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if num_handles != 0 && handles_ptr.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(DecodedSyscall::new(
        ChannelWriteRequest {
            handle: ctx.arg_handle(args, 0)?,
            options: ctx.arg_u32(args, 1)?,
            payload: prepare_channel_payload(bytes_ptr, num_bytes)?,
            handles: decode_input_handles(handles_ptr, num_handles)?,
        },
        NoWriteback,
    ))
}

fn run_channel_write(req: ChannelWriteRequest) -> Result<(), zx_status_t> {
    crate::object::transport::channel_write(req.handle, req.options, req.payload, req.handles)
}

typed_syscall!(
    CHANNEL_WRITE_TYPED,
    channel_write_entry,
    ChannelWriteRequest,
    NoWriteback,
    (),
    decode_channel_write,
    run_channel_write,
    writeback_noop
);
const CHANNEL_WRITE_DISPATCH: SyscallDispatch = SyscallDispatch::new(channel_write_entry);

#[derive(Clone, Copy, Debug)]
struct ChannelReadRequest {
    handle: zx_handle_t,
    options: u32,
    num_bytes: u32,
    num_handles: u32,
}

#[derive(Clone, Copy, Debug)]
struct ChannelReadWriteback {
    bytes: UserWriteBytes,
    handles: OutHandles,
    actual_bytes: OptionalOutValue<u32>,
    actual_handles: OptionalOutValue<u32>,
}

#[derive(Clone, Copy, Debug)]
struct ChannelReadFailure {
    status: zx_status_t,
    actual_bytes: u32,
    actual_handles: u32,
}

#[derive(Debug)]
enum ChannelReadResponse {
    Success(crate::object::ChannelReadResult),
    Failure(ChannelReadFailure),
}

#[derive(Debug)]
struct ChannelReadDelivery {
    result: Option<crate::object::ChannelReadResult>,
    handles_delivered: bool,
}

impl ChannelReadDelivery {
    fn new(result: crate::object::ChannelReadResult) -> Self {
        Self {
            result: Some(result),
            handles_delivered: false,
        }
    }

    fn payload(&self) -> &crate::object::ChannelPayload {
        &self
            .result
            .as_ref()
            .expect("channel read result missing")
            .payload
    }

    fn handles(&self) -> &[zx_handle_t] {
        &self
            .result
            .as_ref()
            .expect("channel read result missing")
            .handles
    }

    fn actual_bytes(&self) -> u32 {
        self.result
            .as_ref()
            .expect("channel read result missing")
            .actual_bytes
    }

    fn actual_handles(&self) -> u32 {
        self.result
            .as_ref()
            .expect("channel read result missing")
            .actual_handles
    }

    fn mark_handles_delivered(&mut self) {
        self.handles_delivered = true;
    }

    fn finish(mut self) {
        if let Some(result) = self.result.take() {
            crate::object::transport::release_channel_read_result(result);
        }
    }
}

impl Drop for ChannelReadDelivery {
    fn drop(&mut self) {
        if let Some(result) = self.result.take() {
            if !self.handles_delivered {
                for handle in &result.handles {
                    let _ = crate::object::close_handle(*handle);
                }
            }
            crate::object::transport::release_channel_read_result(result);
        }
    }
}

fn decode_channel_read(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<ChannelReadRequest, ChannelReadWriteback>, zx_status_t> {
    let num_bytes = ctx.arg_u32(args, 4)?;
    let num_handles = ctx.arg_u32(args, 5)?;
    let bytes_ptr = ctx.arg_ptr::<u8>(args, 2);
    let handles_ptr = ctx.arg_ptr::<zx_handle_t>(args, 3);
    if num_bytes != 0 && bytes_ptr.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    if num_handles != 0 && handles_ptr.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(DecodedSyscall::new(
        ChannelReadRequest {
            handle: ctx.arg_handle(args, 0)?,
            options: ctx.arg_u32(args, 1)?,
            num_bytes,
            num_handles,
        },
        ChannelReadWriteback {
            bytes: ctx.decode_user_write_bytes(bytes_ptr, num_bytes as usize)?,
            handles: ctx.decode_out_handles(handles_ptr, num_handles as usize)?,
            actual_bytes: ctx.decode_optional_extra_out_value::<u32>(0)?,
            actual_handles: ctx.decode_optional_extra_out_value::<u32>(1)?,
        },
    ))
}

fn run_channel_read(req: ChannelReadRequest) -> Result<ChannelReadResponse, zx_status_t> {
    Ok(
        match crate::object::transport::channel_read(
            req.handle,
            req.options,
            req.num_bytes,
            req.num_handles,
        ) {
            Ok(message) => ChannelReadResponse::Success(message),
            Err((status, actual_bytes, actual_handles)) => {
                ChannelReadResponse::Failure(ChannelReadFailure {
                    status,
                    actual_bytes,
                    actual_handles,
                })
            }
        },
    )
}

fn writeback_channel_read(
    _ctx: &mut SyscallCtx,
    writeback: ChannelReadWriteback,
    response: ChannelReadResponse,
) -> Result<(), zx_status_t> {
    match response {
        ChannelReadResponse::Failure(failure) => {
            write_optional_out_value(writeback.actual_bytes, failure.actual_bytes)?;
            write_optional_out_value(writeback.actual_handles, failure.actual_handles)?;
            Err(failure.status)
        }
        ChannelReadResponse::Success(message) => {
            let mut delivery = ChannelReadDelivery::new(message);
            write_channel_payload(writeback.bytes, delivery.payload())?;
            write_optional_out_value(writeback.actual_bytes, delivery.actual_bytes())?;
            write_optional_out_value(writeback.actual_handles, delivery.actual_handles())?;
            write_out_handles(writeback.handles, delivery.handles())?;
            delivery.mark_handles_delivered();
            delivery.finish();
            Ok(())
        }
    }
}

typed_syscall!(
    CHANNEL_READ_TYPED,
    channel_read_entry,
    ChannelReadRequest,
    ChannelReadWriteback,
    ChannelReadResponse,
    decode_channel_read,
    run_channel_read,
    writeback_channel_read
);
const CHANNEL_READ_DISPATCH: SyscallDispatch = SyscallDispatch::new(channel_read_entry);

fn decode_eventpair_create(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<u32, (OutValue<zx_handle_t>, OutValue<zx_handle_t>)>, zx_status_t> {
    Ok(DecodedSyscall::new(
        ctx.arg_u32(args, 0)?,
        (
            ctx.decode_out_value::<zx_handle_t>(args, 1)?,
            ctx.decode_out_value::<zx_handle_t>(args, 2)?,
        ),
    ))
}

fn run_eventpair_create(options: u32) -> Result<(zx_handle_t, zx_handle_t), zx_status_t> {
    crate::object::create_eventpair(options)
}

typed_syscall!(
    EVENTPAIR_CREATE_TYPED,
    eventpair_create_entry,
    u32,
    (OutValue<zx_handle_t>, OutValue<zx_handle_t>),
    (zx_handle_t, zx_handle_t),
    decode_eventpair_create,
    run_eventpair_create,
    writeback_handle_pair
);
const EVENTPAIR_CREATE_DISPATCH: SyscallDispatch = SyscallDispatch::new(eventpair_create_entry);

type SignalRequest = (zx_handle_t, u32, u32);

fn decode_object_signal_peer(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<SignalRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (
            ctx.arg_handle(args, 0)?,
            ctx.arg_u32(args, 1)?,
            ctx.arg_u32(args, 2)?,
        ),
        NoWriteback,
    ))
}

fn run_object_signal_peer(req: SignalRequest) -> Result<(), zx_status_t> {
    crate::object::object_signal_peer(req.0, req.1, req.2)
}

typed_syscall!(
    OBJECT_SIGNAL_PEER_TYPED,
    object_signal_peer_entry,
    SignalRequest,
    NoWriteback,
    (),
    decode_object_signal_peer,
    run_object_signal_peer,
    writeback_noop
);
const OBJECT_SIGNAL_PEER_DISPATCH: SyscallDispatch = SyscallDispatch::new(object_signal_peer_entry);

fn decode_object_signal(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<SignalRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (
            ctx.arg_handle(args, 0)?,
            ctx.arg_u32(args, 1)?,
            ctx.arg_u32(args, 2)?,
        ),
        NoWriteback,
    ))
}

fn run_object_signal(req: SignalRequest) -> Result<(), zx_status_t> {
    crate::object::object_signal(req.0, req.1, req.2)
}

typed_syscall!(
    OBJECT_SIGNAL_TYPED,
    object_signal_entry,
    SignalRequest,
    NoWriteback,
    (),
    decode_object_signal,
    run_object_signal,
    writeback_noop
);
const OBJECT_SIGNAL_DISPATCH: SyscallDispatch = SyscallDispatch::new(object_signal_entry);

type FutexWaitRequest = (u64, zx_futex_t, zx_handle_t, zx_time_t);

fn decode_futex_wait(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<FutexWaitRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (
            args[0],
            ctx.arg_u32(args, 1)? as zx_futex_t,
            ctx.arg_handle(args, 2)?,
            args[3] as zx_time_t,
        ),
        NoWriteback,
    ))
}

fn run_futex_wait(req: FutexWaitRequest) -> Result<(), zx_status_t> {
    crate::object::futex_wait(req.0, req.1, req.2, req.3)
}

typed_syscall!(
    FUTEX_WAIT_TYPED,
    futex_wait_entry,
    FutexWaitRequest,
    NoWriteback,
    (),
    decode_futex_wait,
    run_futex_wait,
    writeback_noop
);
const FUTEX_WAIT_DISPATCH: SyscallDispatch = SyscallDispatch::new(futex_wait_entry);

type FutexWakeRequest = (u64, u32);

fn decode_futex_wake(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<FutexWakeRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (args[0], ctx.arg_u32(args, 1)?),
        NoWriteback,
    ))
}

fn run_futex_wake(req: FutexWakeRequest) -> Result<(), zx_status_t> {
    crate::object::futex_wake(req.0, req.1)
}

typed_syscall!(
    FUTEX_WAKE_TYPED,
    futex_wake_entry,
    FutexWakeRequest,
    NoWriteback,
    (),
    decode_futex_wake,
    run_futex_wake,
    writeback_noop
);
const FUTEX_WAKE_DISPATCH: SyscallDispatch = SyscallDispatch::new(futex_wake_entry);

type FutexRequeueRequest = (u64, u32, zx_futex_t, u64, u32, zx_handle_t);

fn decode_futex_requeue(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<FutexRequeueRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (
            args[0],
            ctx.arg_u32(args, 1)?,
            ctx.arg_u32(args, 2)? as zx_futex_t,
            args[3],
            ctx.arg_u32(args, 4)?,
            ctx.arg_handle(args, 5)?,
        ),
        NoWriteback,
    ))
}

fn run_futex_requeue(req: FutexRequeueRequest) -> Result<(), zx_status_t> {
    crate::object::futex_requeue(req.0, req.1, req.2, req.3, req.4, req.5)
}

typed_syscall!(
    FUTEX_REQUEUE_TYPED,
    futex_requeue_entry,
    FutexRequeueRequest,
    NoWriteback,
    (),
    decode_futex_requeue,
    run_futex_requeue,
    writeback_noop
);
const FUTEX_REQUEUE_DISPATCH: SyscallDispatch = SyscallDispatch::new(futex_requeue_entry);

fn decode_futex_get_owner(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<u64, OutValue<zx_koid_t>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        args[0],
        ctx.decode_out_value::<zx_koid_t>(args, 1)?,
    ))
}

fn run_futex_get_owner(value_ptr: u64) -> Result<zx_koid_t, zx_status_t> {
    crate::object::futex_get_owner(value_ptr)
}

typed_syscall!(
    FUTEX_GET_OWNER_TYPED,
    futex_get_owner_entry,
    u64,
    OutValue<zx_koid_t>,
    zx_koid_t,
    decode_futex_get_owner,
    run_futex_get_owner,
    writeback_koid
);
const FUTEX_GET_OWNER_DISPATCH: SyscallDispatch = SyscallDispatch::new(futex_get_owner_entry);

type ThreadCreateRequest = (zx_handle_t, u32);

fn decode_thread_create(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<ThreadCreateRequest, OutValue<zx_handle_t>>, zx_status_t> {
    let name_size = ctx.arg_usize(args, 2)?;
    let name_ptr = ctx.arg_const_ptr::<u8>(args, 1);
    if name_size != 0 && name_ptr.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    probe_input_bytes(name_ptr, name_size)?;
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, ctx.arg_u32(args, 3)?),
        ctx.decode_out_value::<zx_handle_t>(args, 4)?,
    ))
}

fn run_thread_create(req: ThreadCreateRequest) -> Result<zx_handle_t, zx_status_t> {
    crate::object::process::create_thread(req.0, req.1)
}

typed_syscall!(
    THREAD_CREATE_TYPED,
    thread_create_entry,
    ThreadCreateRequest,
    OutValue<zx_handle_t>,
    zx_handle_t,
    decode_thread_create,
    run_thread_create,
    writeback_handle
);
const THREAD_CREATE_DISPATCH: SyscallDispatch = SyscallDispatch::new(thread_create_entry);

type ThreadStartRequest = (zx_handle_t, u64, u64, u64, u64);

fn decode_thread_start(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<ThreadStartRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, args[1], args[2], args[3], args[4]),
        NoWriteback,
    ))
}

fn run_thread_start(req: ThreadStartRequest) -> Result<(), zx_status_t> {
    crate::object::process::start_thread(req.0, req.1, req.2, req.3, req.4)
}

typed_syscall!(
    THREAD_START_TYPED,
    thread_start_entry,
    ThreadStartRequest,
    NoWriteback,
    (),
    decode_thread_start,
    run_thread_start,
    writeback_noop
);
const THREAD_START_DISPATCH: SyscallDispatch = SyscallDispatch::new(thread_start_entry);

type ProcessCreateRequest = (zx_handle_t, u32);

fn decode_process_create(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<
    DecodedSyscall<ProcessCreateRequest, (OutValue<zx_handle_t>, OutValue<zx_handle_t>)>,
    zx_status_t,
> {
    let name_size = ctx.arg_usize(args, 2)?;
    let name_ptr = ctx.arg_const_ptr::<u8>(args, 1);
    if name_size != 0 && name_ptr.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    probe_input_bytes(name_ptr, name_size)?;
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, ctx.arg_u32(args, 3)?),
        (
            ctx.decode_out_value::<zx_handle_t>(args, 4)?,
            ctx.decode_out_value::<zx_handle_t>(args, 5)?,
        ),
    ))
}

fn run_process_create(
    req: ProcessCreateRequest,
) -> Result<(zx_handle_t, zx_handle_t), zx_status_t> {
    crate::object::process::create_process(req.0, req.1)
}

typed_syscall!(
    PROCESS_CREATE_TYPED,
    process_create_entry,
    ProcessCreateRequest,
    (OutValue<zx_handle_t>, OutValue<zx_handle_t>),
    (zx_handle_t, zx_handle_t),
    decode_process_create,
    run_process_create,
    writeback_handle_pair
);
const PROCESS_CREATE_DISPATCH: SyscallDispatch = SyscallDispatch::new(process_create_entry);

type ProcessStartRequest = (zx_handle_t, zx_handle_t, u64, u64, zx_handle_t, u64);

fn decode_process_start(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<ProcessStartRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (
            ctx.arg_handle(args, 0)?,
            ctx.arg_handle(args, 1)?,
            args[2],
            args[3],
            ctx.arg_handle(args, 4)?,
            args[5],
        ),
        NoWriteback,
    ))
}

fn run_process_start(req: ProcessStartRequest) -> Result<(), zx_status_t> {
    crate::object::process::start_process(req.0, req.1, req.2, req.3, req.4, req.5)
}

typed_syscall!(
    PROCESS_START_TYPED,
    process_start_entry,
    ProcessStartRequest,
    NoWriteback,
    (),
    decode_process_start,
    run_process_start,
    writeback_noop
);
const PROCESS_START_DISPATCH: SyscallDispatch = SyscallDispatch::new(process_start_entry);

type PrepareStartRequest = (zx_handle_t, zx_handle_t, u32);

#[derive(Debug)]
struct PrepareLinuxExecRequest {
    process: zx_handle_t,
    image_vmo: zx_handle_t,
    options: u32,
    exec_spec: Vec<u8>,
}

fn decode_ax_process_prepare_start(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<
    DecodedSyscall<PrepareStartRequest, (OutValue<zx_vaddr_t>, OutValue<zx_vaddr_t>)>,
    zx_status_t,
> {
    Ok(DecodedSyscall::new(
        (
            ctx.arg_handle(args, 0)?,
            ctx.arg_handle(args, 1)?,
            ctx.arg_u32(args, 2)?,
        ),
        (
            ctx.decode_out_value::<zx_vaddr_t>(args, 3)?,
            ctx.decode_out_value::<zx_vaddr_t>(args, 4)?,
        ),
    ))
}

fn run_ax_process_prepare_start(
    req: PrepareStartRequest,
) -> Result<crate::task::PreparedProcessStart, zx_status_t> {
    crate::object::process::prepare_process_start(req.0, req.1, req.2)
}

typed_syscall!(
    AX_PROCESS_PREPARE_START_TYPED,
    ax_process_prepare_start_entry,
    PrepareStartRequest,
    (OutValue<zx_vaddr_t>, OutValue<zx_vaddr_t>),
    crate::task::PreparedProcessStart,
    decode_ax_process_prepare_start,
    run_ax_process_prepare_start,
    writeback_vaddr_pair
);
const AX_PROCESS_PREPARE_START_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_process_prepare_start_entry);

fn decode_ax_process_prepare_linux_exec(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<
    DecodedSyscall<PrepareLinuxExecRequest, (OutValue<zx_vaddr_t>, OutValue<zx_vaddr_t>)>,
    zx_status_t,
> {
    let spec_len = ctx.arg_usize_or(args, 4, ZX_ERR_OUT_OF_RANGE)?;
    let spec_bytes = ctx.arg_const_ptr::<u8>(args, 3);
    if spec_len != 0 && spec_bytes.is_null() {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    Ok(DecodedSyscall::new(
        PrepareLinuxExecRequest {
            process: ctx.arg_handle(args, 0)?,
            image_vmo: ctx.arg_handle(args, 1)?,
            options: ctx.arg_u32(args, 2)?,
            exec_spec: decode_input_bytes(spec_bytes, spec_len)?,
        },
        (
            ctx.decode_out_value::<zx_vaddr_t>(args, 5)?,
            ctx.decode_extra_out_value::<zx_vaddr_t>(0)?,
        ),
    ))
}

fn run_ax_process_prepare_linux_exec(
    req: PrepareLinuxExecRequest,
) -> Result<crate::task::PreparedProcessStart, zx_status_t> {
    crate::object::process::prepare_linux_exec(
        req.process,
        req.image_vmo,
        req.options,
        &req.exec_spec,
    )
}

typed_syscall!(
    AX_PROCESS_PREPARE_LINUX_EXEC_TYPED,
    ax_process_prepare_linux_exec_entry,
    PrepareLinuxExecRequest,
    (OutValue<zx_vaddr_t>, OutValue<zx_vaddr_t>),
    crate::task::PreparedProcessStart,
    decode_ax_process_prepare_linux_exec,
    run_ax_process_prepare_linux_exec,
    writeback_vaddr_pair
);
const AX_PROCESS_PREPARE_LINUX_EXEC_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_process_prepare_linux_exec_entry);

#[derive(Clone, Copy, Debug)]
struct GuestSessionCreateRequest {
    thread: zx_handle_t,
    sidecar_vmo: zx_handle_t,
    port: zx_handle_t,
    key: u64,
    options: u32,
}

fn decode_ax_guest_session_create(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<GuestSessionCreateRequest, OutValue<zx_handle_t>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        GuestSessionCreateRequest {
            thread: ctx.arg_handle(args, 0)?,
            sidecar_vmo: ctx.arg_handle(args, 1)?,
            port: ctx.arg_handle(args, 2)?,
            key: args[3],
            options: ctx.arg_u32(args, 4)?,
        },
        ctx.decode_out_value::<zx_handle_t>(args, 5)?,
    ))
}

fn run_ax_guest_session_create(req: GuestSessionCreateRequest) -> Result<zx_handle_t, zx_status_t> {
    crate::object::guest::create_guest_session(
        req.thread,
        req.sidecar_vmo,
        req.port,
        req.key,
        req.options,
    )
}

typed_syscall!(
    AX_GUEST_SESSION_CREATE_TYPED,
    ax_guest_session_create_entry,
    GuestSessionCreateRequest,
    OutValue<zx_handle_t>,
    zx_handle_t,
    decode_ax_guest_session_create,
    run_ax_guest_session_create,
    writeback_handle
);
const AX_GUEST_SESSION_CREATE_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_guest_session_create_entry);

type GuestSessionResumeRequest = (zx_handle_t, u64, u32);

fn decode_ax_guest_session_resume(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<GuestSessionResumeRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, args[1], ctx.arg_u32(args, 2)?),
        NoWriteback,
    ))
}

fn run_ax_guest_session_resume(req: GuestSessionResumeRequest) -> Result<(), zx_status_t> {
    crate::object::guest::resume_guest_session(req.0, req.1, req.2)
}

typed_syscall!(
    AX_GUEST_SESSION_RESUME_TYPED,
    ax_guest_session_resume_entry,
    GuestSessionResumeRequest,
    NoWriteback,
    (),
    decode_ax_guest_session_resume,
    run_ax_guest_session_resume,
    writeback_noop
);
const AX_GUEST_SESSION_RESUME_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_guest_session_resume_entry);

#[derive(Debug)]
struct GuestSessionReadMemoryRequest {
    session: zx_handle_t,
    guest_addr: u64,
    len: usize,
}

fn decode_ax_guest_session_read_memory(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<GuestSessionReadMemoryRequest, UserWriteBytes>, zx_status_t> {
    let len = ctx.arg_usize_or(args, 3, ZX_ERR_OUT_OF_RANGE)?;
    let out = ctx.decode_user_write_bytes(ctx.arg_ptr::<u8>(args, 2), len)?;
    Ok(DecodedSyscall::new(
        GuestSessionReadMemoryRequest {
            session: ctx.arg_handle(args, 0)?,
            guest_addr: args[1],
            len,
        },
        out,
    ))
}

fn run_ax_guest_session_read_memory(
    req: GuestSessionReadMemoryRequest,
) -> Result<Vec<u8>, zx_status_t> {
    crate::object::guest::read_guest_memory(req.session, req.guest_addr, req.len)
}

fn writeback_ax_guest_session_read_memory(
    _ctx: &mut SyscallCtx,
    out: UserWriteBytes,
    bytes: Vec<u8>,
) -> Result<(), zx_status_t> {
    write_user_bytes(out, &bytes)
}

typed_syscall!(
    AX_GUEST_SESSION_READ_MEMORY_TYPED,
    ax_guest_session_read_memory_entry,
    GuestSessionReadMemoryRequest,
    UserWriteBytes,
    Vec<u8>,
    decode_ax_guest_session_read_memory,
    run_ax_guest_session_read_memory,
    writeback_ax_guest_session_read_memory
);
const AX_GUEST_SESSION_READ_MEMORY_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_guest_session_read_memory_entry);

#[derive(Debug)]
struct GuestSessionWriteMemoryRequest {
    session: zx_handle_t,
    guest_addr: u64,
    bytes: Vec<u8>,
}

fn decode_ax_guest_session_write_memory(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<GuestSessionWriteMemoryRequest, NoWriteback>, zx_status_t> {
    let len = ctx.arg_usize_or(args, 3, ZX_ERR_OUT_OF_RANGE)?;
    Ok(DecodedSyscall::new(
        GuestSessionWriteMemoryRequest {
            session: ctx.arg_handle(args, 0)?,
            guest_addr: args[1],
            bytes: decode_input_bytes(ctx.arg_const_ptr::<u8>(args, 2), len)?,
        },
        NoWriteback,
    ))
}

fn run_ax_guest_session_write_memory(
    req: GuestSessionWriteMemoryRequest,
) -> Result<(), zx_status_t> {
    crate::object::guest::write_guest_memory(req.session, req.guest_addr, &req.bytes)
}

typed_syscall!(
    AX_GUEST_SESSION_WRITE_MEMORY_TYPED,
    ax_guest_session_write_memory_entry,
    GuestSessionWriteMemoryRequest,
    NoWriteback,
    (),
    decode_ax_guest_session_write_memory,
    run_ax_guest_session_write_memory,
    writeback_noop
);
const AX_GUEST_SESSION_WRITE_MEMORY_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_guest_session_write_memory_entry);

#[derive(Clone, Copy, Debug)]
struct ProcessStartGuestRequest {
    process: zx_handle_t,
    thread: zx_handle_t,
    regs: ax_guest_x64_regs_t,
    options: u32,
}

fn decode_ax_process_start_guest(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<ProcessStartGuestRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(
        ProcessStartGuestRequest {
            process: ctx.arg_handle(args, 0)?,
            thread: ctx.arg_handle(args, 1)?,
            regs: decode_input_value(ctx.arg_const_ptr::<ax_guest_x64_regs_t>(args, 2))?,
            options: ctx.arg_u32(args, 3)?,
        },
        NoWriteback,
    ))
}

fn run_ax_process_start_guest(req: ProcessStartGuestRequest) -> Result<(), zx_status_t> {
    crate::object::process::start_process_guest(req.process, req.thread, &req.regs, req.options)
}

typed_syscall!(
    AX_PROCESS_START_GUEST_TYPED,
    ax_process_start_guest_entry,
    ProcessStartGuestRequest,
    NoWriteback,
    (),
    decode_ax_process_start_guest,
    run_ax_process_start_guest,
    writeback_noop
);
const AX_PROCESS_START_GUEST_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_process_start_guest_entry);

#[derive(Clone, Copy, Debug)]
struct ThreadStartGuestRequest {
    thread: zx_handle_t,
    regs: ax_guest_x64_regs_t,
    options: u32,
}

fn decode_ax_thread_start_guest(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<ThreadStartGuestRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(
        ThreadStartGuestRequest {
            thread: ctx.arg_handle(args, 0)?,
            regs: decode_input_value(ctx.arg_const_ptr::<ax_guest_x64_regs_t>(args, 1))?,
            options: ctx.arg_u32(args, 2)?,
        },
        NoWriteback,
    ))
}

fn run_ax_thread_start_guest(req: ThreadStartGuestRequest) -> Result<(), zx_status_t> {
    crate::object::process::start_thread_guest(req.thread, &req.regs, req.options)
}

typed_syscall!(
    AX_THREAD_START_GUEST_TYPED,
    ax_thread_start_guest_entry,
    ThreadStartGuestRequest,
    NoWriteback,
    (),
    decode_ax_thread_start_guest,
    run_ax_thread_start_guest,
    writeback_noop
);
const AX_THREAD_START_GUEST_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_thread_start_guest_entry);

#[derive(Clone, Copy, Debug)]
struct ThreadSetGuestFsBaseRequest {
    thread: zx_handle_t,
    fs_base: u64,
    options: u32,
}

fn decode_ax_thread_set_guest_x64_fs_base(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<ThreadSetGuestFsBaseRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(
        ThreadSetGuestFsBaseRequest {
            thread: ctx.arg_handle(args, 0)?,
            fs_base: args[1],
            options: ctx.arg_u32(args, 2)?,
        },
        NoWriteback,
    ))
}

fn run_ax_thread_set_guest_x64_fs_base(
    req: ThreadSetGuestFsBaseRequest,
) -> Result<(), zx_status_t> {
    crate::object::process::set_thread_guest_x64_fs_base(req.thread, req.fs_base, req.options)
}

typed_syscall!(
    AX_THREAD_SET_GUEST_X64_FS_BASE_TYPED,
    ax_thread_set_guest_x64_fs_base_entry,
    ThreadSetGuestFsBaseRequest,
    NoWriteback,
    (),
    decode_ax_thread_set_guest_x64_fs_base,
    run_ax_thread_set_guest_x64_fs_base,
    writeback_noop
);
const AX_THREAD_SET_GUEST_X64_FS_BASE_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_thread_set_guest_x64_fs_base_entry);

#[derive(Clone, Copy, Debug)]
struct ThreadGetGuestFsBaseRequest {
    thread: zx_handle_t,
    options: u32,
}

fn decode_ax_thread_get_guest_x64_fs_base(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<ThreadGetGuestFsBaseRequest, OutValue<u64>>, zx_status_t> {
    let out_fs_base = ctx.decode_out_value::<u64>(args, 2)?;
    Ok(DecodedSyscall::new(
        ThreadGetGuestFsBaseRequest {
            thread: ctx.arg_handle(args, 0)?,
            options: ctx.arg_u32(args, 1)?,
        },
        out_fs_base,
    ))
}

fn run_ax_thread_get_guest_x64_fs_base(
    req: ThreadGetGuestFsBaseRequest,
) -> Result<u64, zx_status_t> {
    crate::object::process::thread_guest_x64_fs_base(req.thread, req.options)
}

typed_syscall!(
    AX_THREAD_GET_GUEST_X64_FS_BASE_TYPED,
    ax_thread_get_guest_x64_fs_base_entry,
    ThreadGetGuestFsBaseRequest,
    OutValue<u64>,
    u64,
    decode_ax_thread_get_guest_x64_fs_base,
    run_ax_thread_get_guest_x64_fs_base,
    writeback_u64
);
const AX_THREAD_GET_GUEST_X64_FS_BASE_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_thread_get_guest_x64_fs_base_entry);

fn decode_task_kill(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<zx_handle_t, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(ctx.arg_handle(args, 0)?, NoWriteback))
}

fn run_task_kill(handle: zx_handle_t) -> Result<(), zx_status_t> {
    crate::object::process::task_kill(handle)
}

typed_syscall!(
    TASK_KILL_TYPED,
    task_kill_entry,
    zx_handle_t,
    NoWriteback,
    (),
    decode_task_kill,
    run_task_kill,
    writeback_noop
);
const TASK_KILL_DISPATCH: SyscallDispatch = SyscallDispatch::new(task_kill_entry);

fn decode_task_suspend(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<zx_handle_t, OutValue<zx_handle_t>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        ctx.arg_handle(args, 0)?,
        ctx.decode_out_value::<zx_handle_t>(args, 1)?,
    ))
}

fn run_task_suspend(handle: zx_handle_t) -> Result<zx_handle_t, zx_status_t> {
    crate::object::process::task_suspend(handle)
}

typed_syscall!(
    TASK_SUSPEND_TYPED,
    task_suspend_entry,
    zx_handle_t,
    OutValue<zx_handle_t>,
    zx_handle_t,
    decode_task_suspend,
    run_task_suspend,
    writeback_handle
);
const TASK_SUSPEND_DISPATCH: SyscallDispatch = SyscallDispatch::new(task_suspend_entry);

fn syscall_dispatch(nr: SyscallNumber) -> Option<&'static SyscallDispatch> {
    match nr {
        AXLE_SYS_HANDLE_CLOSE => Some(&HANDLE_CLOSE_DISPATCH),
        AXLE_SYS_HANDLE_DUPLICATE => Some(&HANDLE_DUPLICATE_DISPATCH),
        AXLE_SYS_HANDLE_REPLACE => Some(&HANDLE_REPLACE_DISPATCH),
        AXLE_SYS_OBJECT_WAIT_ONE => Some(&OBJECT_WAIT_ONE_DISPATCH),
        AXLE_SYS_OBJECT_WAIT_ASYNC => Some(&OBJECT_WAIT_ASYNC_DISPATCH),
        AXLE_SYS_PORT_CREATE => Some(&PORT_CREATE_DISPATCH),
        AXLE_SYS_PORT_QUEUE => Some(&PORT_QUEUE_DISPATCH),
        AXLE_SYS_PORT_WAIT => Some(&PORT_WAIT_DISPATCH),
        AXLE_SYS_TIMER_CREATE => Some(&TIMER_CREATE_DISPATCH),
        AXLE_SYS_TIMER_SET => Some(&TIMER_SET_DISPATCH),
        AXLE_SYS_TIMER_CANCEL => Some(&TIMER_CANCEL_DISPATCH),
        AXLE_SYS_VMO_CREATE => Some(&VMO_CREATE_DISPATCH),
        AXLE_SYS_VMO_READ => Some(&VMO_READ_DISPATCH),
        AXLE_SYS_VMO_WRITE => Some(&VMO_WRITE_DISPATCH),
        AXLE_SYS_VMO_SET_SIZE => Some(&VMO_SET_SIZE_DISPATCH),
        AXLE_SYS_SOCKET_CREATE => Some(&SOCKET_CREATE_DISPATCH),
        AXLE_SYS_SOCKET_WRITE => Some(&SOCKET_WRITE_DISPATCH),
        AXLE_SYS_SOCKET_READ => Some(&SOCKET_READ_DISPATCH),
        AXLE_SYS_VMAR_ALLOCATE => Some(&VMAR_ALLOCATE_DISPATCH),
        AXLE_SYS_VMAR_MAP => Some(&VMAR_MAP_DISPATCH),
        AXLE_SYS_VMAR_DESTROY => Some(&VMAR_DESTROY_DISPATCH),
        AXLE_SYS_VMAR_UNMAP => Some(&VMAR_UNMAP_DISPATCH),
        AXLE_SYS_VMAR_PROTECT => Some(&VMAR_PROTECT_DISPATCH),
        AXLE_SYS_CHANNEL_CREATE => Some(&CHANNEL_CREATE_DISPATCH),
        AXLE_SYS_CHANNEL_WRITE => Some(&CHANNEL_WRITE_DISPATCH),
        AXLE_SYS_CHANNEL_READ => Some(&CHANNEL_READ_DISPATCH),
        AXLE_SYS_EVENTPAIR_CREATE => Some(&EVENTPAIR_CREATE_DISPATCH),
        AXLE_SYS_OBJECT_SIGNAL_PEER => Some(&OBJECT_SIGNAL_PEER_DISPATCH),
        AXLE_SYS_OBJECT_SIGNAL => Some(&OBJECT_SIGNAL_DISPATCH),
        AXLE_SYS_FUTEX_WAIT => Some(&FUTEX_WAIT_DISPATCH),
        AXLE_SYS_FUTEX_WAKE => Some(&FUTEX_WAKE_DISPATCH),
        AXLE_SYS_FUTEX_REQUEUE => Some(&FUTEX_REQUEUE_DISPATCH),
        AXLE_SYS_FUTEX_GET_OWNER => Some(&FUTEX_GET_OWNER_DISPATCH),
        AXLE_SYS_THREAD_CREATE => Some(&THREAD_CREATE_DISPATCH),
        AXLE_SYS_THREAD_START => Some(&THREAD_START_DISPATCH),
        AXLE_SYS_PROCESS_CREATE => Some(&PROCESS_CREATE_DISPATCH),
        AXLE_SYS_PROCESS_START => Some(&PROCESS_START_DISPATCH),
        AXLE_SYS_AX_PROCESS_PREPARE_START => Some(&AX_PROCESS_PREPARE_START_DISPATCH),
        AXLE_SYS_AX_PROCESS_PREPARE_LINUX_EXEC => Some(&AX_PROCESS_PREPARE_LINUX_EXEC_DISPATCH),
        AXLE_SYS_AX_GUEST_SESSION_CREATE => Some(&AX_GUEST_SESSION_CREATE_DISPATCH),
        AXLE_SYS_AX_GUEST_SESSION_RESUME => Some(&AX_GUEST_SESSION_RESUME_DISPATCH),
        AXLE_SYS_AX_GUEST_SESSION_READ_MEMORY => Some(&AX_GUEST_SESSION_READ_MEMORY_DISPATCH),
        AXLE_SYS_AX_GUEST_SESSION_WRITE_MEMORY => Some(&AX_GUEST_SESSION_WRITE_MEMORY_DISPATCH),
        AXLE_SYS_AX_PROCESS_START_GUEST => Some(&AX_PROCESS_START_GUEST_DISPATCH),
        AXLE_SYS_AX_THREAD_START_GUEST => Some(&AX_THREAD_START_GUEST_DISPATCH),
        AXLE_SYS_AX_THREAD_SET_GUEST_X64_FS_BASE => {
            Some(&AX_THREAD_SET_GUEST_X64_FS_BASE_DISPATCH)
        }
        AXLE_SYS_AX_THREAD_GET_GUEST_X64_FS_BASE => {
            Some(&AX_THREAD_GET_GUEST_X64_FS_BASE_DISPATCH)
        }
        AXLE_SYS_TASK_KILL => Some(&TASK_KILL_DISPATCH),
        AXLE_SYS_TASK_SUSPEND => Some(&TASK_SUSPEND_DISPATCH),
        _ => None,
    }
}

fn align_up_page(value: u64) -> Option<u64> {
    const PAGE_SIZE: u64 = 0x1000;
    value
        .checked_add(PAGE_SIZE - 1)
        .map(|v| v & !(PAGE_SIZE - 1))
}
