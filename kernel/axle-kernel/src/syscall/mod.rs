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
use axle_types::dma::{ax_dma_region_info_t, ax_dma_segment_info_t};
use axle_types::interrupt::ax_interrupt_info_t;
use axle_types::pci::{
    ax_pci_bar_info_t, ax_pci_config_info_t, ax_pci_device_info_t, ax_pci_interrupt_info_t,
    ax_pci_interrupt_mode_info_t, ax_pci_resource_info_t,
};
use axle_types::status::{ZX_ERR_BAD_SYSCALL, ZX_ERR_INVALID_ARGS, ZX_ERR_OUT_OF_RANGE, ZX_OK};
use axle_types::syscall_numbers::{
    AXLE_SYS_AX_DMA_REGION_GET_INFO, AXLE_SYS_AX_DMA_REGION_GET_SEGMENT,
    AXLE_SYS_AX_DMA_REGION_LOOKUP_IOVA, AXLE_SYS_AX_DMA_REGION_LOOKUP_PADDR,
    AXLE_SYS_AX_GUEST_SESSION_CREATE, AXLE_SYS_AX_GUEST_SESSION_READ_MEMORY,
    AXLE_SYS_AX_GUEST_SESSION_RESUME, AXLE_SYS_AX_GUEST_SESSION_WRITE_MEMORY,
    AXLE_SYS_AX_INTERRUPT_TRIGGER, AXLE_SYS_AX_PCI_DEVICE_GET_BAR,
    AXLE_SYS_AX_PCI_DEVICE_GET_CONFIG, AXLE_SYS_AX_PCI_DEVICE_GET_INFO,
    AXLE_SYS_AX_PCI_DEVICE_GET_INTERRUPT, AXLE_SYS_AX_PCI_DEVICE_GET_INTERRUPT_MODE,
    AXLE_SYS_AX_PCI_DEVICE_GET_RESOURCE, AXLE_SYS_AX_PCI_DEVICE_GET_RESOURCE_COUNT,
    AXLE_SYS_AX_PCI_DEVICE_SET_INTERRUPT_MODE, AXLE_SYS_AX_PROCESS_PREPARE_LINUX_EXEC,
    AXLE_SYS_AX_PROCESS_PREPARE_START, AXLE_SYS_AX_PROCESS_START_GUEST,
    AXLE_SYS_AX_THREAD_GET_GUEST_X64_FS_BASE, AXLE_SYS_AX_THREAD_SET_GUEST_X64_FS_BASE,
    AXLE_SYS_AX_THREAD_START_GUEST, AXLE_SYS_AX_VMAR_CLONE_MAPPINGS, AXLE_SYS_AX_VMO_GET_INFO,
    AXLE_SYS_AX_VMO_LOOKUP_PADDR, AXLE_SYS_AX_VMO_PIN, AXLE_SYS_AX_VMO_PROMOTE_SHARED,
    AXLE_SYS_CHANNEL_CREATE, AXLE_SYS_CHANNEL_READ, AXLE_SYS_CHANNEL_WRITE,
    AXLE_SYS_EVENTPAIR_CREATE, AXLE_SYS_FUTEX_GET_OWNER, AXLE_SYS_FUTEX_REQUEUE,
    AXLE_SYS_FUTEX_WAIT, AXLE_SYS_FUTEX_WAKE, AXLE_SYS_HANDLE_CLOSE, AXLE_SYS_HANDLE_DUPLICATE,
    AXLE_SYS_HANDLE_REPLACE, AXLE_SYS_INTERRUPT_ACK, AXLE_SYS_INTERRUPT_CREATE,
    AXLE_SYS_INTERRUPT_GET_INFO, AXLE_SYS_INTERRUPT_MASK, AXLE_SYS_INTERRUPT_UNMASK,
    AXLE_SYS_OBJECT_SIGNAL, AXLE_SYS_OBJECT_SIGNAL_PEER, AXLE_SYS_OBJECT_WAIT_ASYNC,
    AXLE_SYS_OBJECT_WAIT_ONE, AXLE_SYS_PORT_CREATE, AXLE_SYS_PORT_QUEUE, AXLE_SYS_PORT_WAIT,
    AXLE_SYS_PROCESS_CREATE, AXLE_SYS_PROCESS_START, AXLE_SYS_SOCKET_CREATE, AXLE_SYS_SOCKET_READ,
    AXLE_SYS_SOCKET_WRITE, AXLE_SYS_TASK_KILL, AXLE_SYS_TASK_SUSPEND, AXLE_SYS_THREAD_CREATE,
    AXLE_SYS_THREAD_START, AXLE_SYS_TIMER_CANCEL, AXLE_SYS_TIMER_CREATE, AXLE_SYS_TIMER_SET,
    AXLE_SYS_VMAR_ALLOCATE, AXLE_SYS_VMAR_DESTROY, AXLE_SYS_VMAR_MAP, AXLE_SYS_VMAR_PROTECT,
    AXLE_SYS_VMAR_UNMAP, AXLE_SYS_VMO_CREATE, AXLE_SYS_VMO_CREATE_CONTIGUOUS,
    AXLE_SYS_VMO_CREATE_PHYSICAL, AXLE_SYS_VMO_READ, AXLE_SYS_VMO_SET_SIZE, AXLE_SYS_VMO_WRITE,
    SyscallNumber,
};
use axle_types::wait_async::{
    ZX_WAIT_ASYNC_BOOT_TIMESTAMP, ZX_WAIT_ASYNC_EDGE, ZX_WAIT_ASYNC_TIMESTAMP,
};
use axle_types::{
    ax_guest_x64_regs_t, ax_vmo_info_t, zx_clock_t, zx_duration_t, zx_futex_t, zx_handle_t,
    zx_koid_t, zx_port_packet_t, zx_rights_t, zx_signals_t, zx_status_t, zx_time_t, zx_vaddr_t,
    zx_vm_option_t,
};

/// Phase-B bootstrap syscall numbers supported by the shared ABI spec.
pub const BOOTSTRAP_SYSCALLS: [SyscallNumber; 74] = [
    AXLE_SYS_HANDLE_CLOSE,
    AXLE_SYS_OBJECT_WAIT_ONE,
    AXLE_SYS_OBJECT_WAIT_ASYNC,
    AXLE_SYS_PORT_CREATE,
    AXLE_SYS_PORT_QUEUE,
    AXLE_SYS_PORT_WAIT,
    AXLE_SYS_TIMER_CREATE,
    AXLE_SYS_TIMER_SET,
    AXLE_SYS_TIMER_CANCEL,
    AXLE_SYS_INTERRUPT_CREATE,
    AXLE_SYS_INTERRUPT_GET_INFO,
    AXLE_SYS_INTERRUPT_ACK,
    AXLE_SYS_INTERRUPT_MASK,
    AXLE_SYS_INTERRUPT_UNMASK,
    AXLE_SYS_AX_INTERRUPT_TRIGGER,
    AXLE_SYS_VMO_CREATE,
    AXLE_SYS_VMO_CREATE_PHYSICAL,
    AXLE_SYS_VMO_CREATE_CONTIGUOUS,
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
    AXLE_SYS_AX_VMAR_CLONE_MAPPINGS,
    AXLE_SYS_AX_VMO_GET_INFO,
    AXLE_SYS_AX_VMO_PROMOTE_SHARED,
    AXLE_SYS_AX_VMO_LOOKUP_PADDR,
    AXLE_SYS_AX_VMO_PIN,
    AXLE_SYS_AX_DMA_REGION_LOOKUP_PADDR,
    AXLE_SYS_AX_DMA_REGION_LOOKUP_IOVA,
    AXLE_SYS_AX_DMA_REGION_GET_INFO,
    AXLE_SYS_AX_DMA_REGION_GET_SEGMENT,
    AXLE_SYS_AX_PCI_DEVICE_GET_INFO,
    AXLE_SYS_AX_PCI_DEVICE_GET_CONFIG,
    AXLE_SYS_AX_PCI_DEVICE_GET_BAR,
    AXLE_SYS_AX_PCI_DEVICE_GET_INTERRUPT,
    AXLE_SYS_AX_PCI_DEVICE_GET_INTERRUPT_MODE,
    AXLE_SYS_AX_PCI_DEVICE_GET_RESOURCE_COUNT,
    AXLE_SYS_AX_PCI_DEVICE_GET_RESOURCE,
    AXLE_SYS_AX_PCI_DEVICE_SET_INTERRUPT_MODE,
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
    FinishTrapExit {
        cpu_frame: *mut u64,
        native_sysret_ok: bool,
    },
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
        Self::from_trapframe_with_mode(frame, cpu_frame, false)
    }

    fn from_native_trapframe(frame: &crate::arch::int80::TrapFrame, cpu_frame: *const u64) -> Self {
        Self::from_trapframe_with_mode(frame, cpu_frame, true)
    }

    fn from_trapframe_with_mode(
        frame: &crate::arch::int80::TrapFrame,
        cpu_frame: *const u64,
        native_sysret_ok: bool,
    ) -> Self {
        let _ = crate::object::capture_current_user_context(frame, cpu_frame);
        let mut ctx = Self {
            extra_args_user_rsp: user_stack_ptr_from_cpu_frame(cpu_frame).ok(),
            post_actions: Vec::new(),
        };
        ctx.push_post_action(PostAction::FinishTrapExit {
            cpu_frame: cpu_frame.cast_mut(),
            native_sysret_ok,
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

    fn finish(self, frame: &mut crate::arch::int80::TrapFrame) -> bool {
        let mut native_sysret = false;
        for action in self.post_actions {
            match action {
                PostAction::FinishTrapExit {
                    cpu_frame,
                    native_sysret_ok,
                } => {
                    let sysret = if native_sysret_ok {
                        crate::object::finish_syscall_native(frame, cpu_frame).unwrap_or(false)
                    } else {
                        let _ = crate::object::finish_syscall(frame, cpu_frame);
                        false
                    };
                    native_sysret |= sysret;
                }
            }
        }
        native_sysret
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
    let _ = invoke_from_frame(frame, cpu_frame, false);
}

fn invoke_from_frame(
    frame: &mut crate::arch::int80::TrapFrame,
    cpu_frame: *const u64,
    native_sysret_ok: bool,
) -> bool {
    let mut ctx = if native_sysret_ok {
        SyscallCtx::from_native_trapframe(frame, cpu_frame)
    } else {
        SyscallCtx::from_trapframe(frame, cpu_frame)
    };
    let syscall_nr = frame.syscall_nr();
    crate::trace::record_sys_enter(syscall_nr);
    let status = match u32::try_from(syscall_nr) {
        Ok(nr) => dispatch_syscall_with_ctx(&mut ctx, nr, frame.args()),
        Err(_) => ZX_ERR_BAD_SYSCALL,
    };
    crate::trace::record_sys_exit(syscall_nr, status);
    frame.set_status(status);
    let native_sysret = ctx.finish(frame);
    if native_sysret {
        crate::trace::record_sys_native_sysret(syscall_nr, status);
    }
    crate::trace::record_sys_retire(syscall_nr, status);
    native_sysret
}

pub fn invoke_from_native_syscall(
    frame: &mut crate::arch::int80::TrapFrame,
    cpu_frame: *const u64,
) -> u64 {
    match crate::object::handle_native_syscall_entry(frame, cpu_frame.cast_mut()) {
        Ok(true) => return 0,
        Ok(false) => {}
        Err(status) => panic!("native guest syscall entry failed: {status}"),
    }
    u64::from(invoke_from_frame(frame, cpu_frame, true))
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

fn writeback_value<T: Copy>(
    _ctx: &mut SyscallCtx,
    out: OutValue<T>,
    value: T,
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

fn writeback_u64(_ctx: &mut SyscallCtx, out: OutValue<u64>, value: u64) -> Result<(), zx_status_t> {
    write_out_value(out, value)
}

fn writeback_vmo_info(
    _ctx: &mut SyscallCtx,
    out: OutValue<ax_vmo_info_t>,
    value: ax_vmo_info_t,
) -> Result<(), zx_status_t> {
    write_out_value(out, value)
}

fn writeback_dma_region_info(
    _ctx: &mut SyscallCtx,
    out: OutValue<ax_dma_region_info_t>,
    value: ax_dma_region_info_t,
) -> Result<(), zx_status_t> {
    write_out_value(out, value)
}

fn writeback_dma_segment_info(
    _ctx: &mut SyscallCtx,
    out: OutValue<ax_dma_segment_info_t>,
    value: ax_dma_segment_info_t,
) -> Result<(), zx_status_t> {
    write_out_value(out, value)
}

fn writeback_pci_device_info(
    _ctx: &mut SyscallCtx,
    out: OutValue<ax_pci_device_info_t>,
    value: ax_pci_device_info_t,
) -> Result<(), zx_status_t> {
    write_out_value(out, value)
}

fn writeback_pci_config_info(
    _ctx: &mut SyscallCtx,
    out: OutValue<ax_pci_config_info_t>,
    value: ax_pci_config_info_t,
) -> Result<(), zx_status_t> {
    write_out_value(out, value)
}

fn writeback_pci_bar_info(
    _ctx: &mut SyscallCtx,
    out: OutValue<ax_pci_bar_info_t>,
    value: ax_pci_bar_info_t,
) -> Result<(), zx_status_t> {
    write_out_value(out, value)
}

fn writeback_pci_interrupt_info(
    _ctx: &mut SyscallCtx,
    out: OutValue<ax_pci_interrupt_info_t>,
    value: ax_pci_interrupt_info_t,
) -> Result<(), zx_status_t> {
    write_out_value(out, value)
}

fn writeback_pci_interrupt_mode_info(
    _ctx: &mut SyscallCtx,
    out: OutValue<ax_pci_interrupt_mode_info_t>,
    value: ax_pci_interrupt_mode_info_t,
) -> Result<(), zx_status_t> {
    write_out_value(out, value)
}

fn writeback_pci_resource_info(
    _ctx: &mut SyscallCtx,
    out: OutValue<ax_pci_resource_info_t>,
    value: ax_pci_resource_info_t,
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

fn decode_interrupt_create(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<u32, OutValue<zx_handle_t>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        ctx.arg_u32(args, 0)?,
        ctx.decode_out_value::<zx_handle_t>(args, 1)?,
    ))
}

fn run_interrupt_create(options: u32) -> Result<zx_handle_t, zx_status_t> {
    crate::object::create_interrupt(options)
}

typed_syscall!(
    INTERRUPT_CREATE_TYPED,
    interrupt_create_entry,
    u32,
    OutValue<zx_handle_t>,
    zx_handle_t,
    decode_interrupt_create,
    run_interrupt_create,
    writeback_handle
);
const INTERRUPT_CREATE_DISPATCH: SyscallDispatch = SyscallDispatch::new(interrupt_create_entry);

fn decode_interrupt_get_info(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<zx_handle_t, OutValue<ax_interrupt_info_t>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        ctx.arg_handle(args, 0)?,
        ctx.decode_out_value::<ax_interrupt_info_t>(args, 1)?,
    ))
}

fn run_interrupt_get_info(handle: zx_handle_t) -> Result<ax_interrupt_info_t, zx_status_t> {
    crate::object::interrupt_get_info(handle)
}

typed_syscall!(
    INTERRUPT_GET_INFO_TYPED,
    interrupt_get_info_entry,
    zx_handle_t,
    OutValue<ax_interrupt_info_t>,
    ax_interrupt_info_t,
    decode_interrupt_get_info,
    run_interrupt_get_info,
    writeback_value
);
const INTERRUPT_GET_INFO_DISPATCH: SyscallDispatch = SyscallDispatch::new(interrupt_get_info_entry);

fn decode_interrupt_ack(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<zx_handle_t, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(ctx.arg_handle(args, 0)?, NoWriteback))
}

fn run_interrupt_ack(handle: zx_handle_t) -> Result<(), zx_status_t> {
    crate::object::interrupt_ack(handle)
}

typed_syscall!(
    INTERRUPT_ACK_TYPED,
    interrupt_ack_entry,
    zx_handle_t,
    NoWriteback,
    (),
    decode_interrupt_ack,
    run_interrupt_ack,
    writeback_noop
);
const INTERRUPT_ACK_DISPATCH: SyscallDispatch = SyscallDispatch::new(interrupt_ack_entry);

fn decode_interrupt_mask(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<zx_handle_t, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(ctx.arg_handle(args, 0)?, NoWriteback))
}

fn run_interrupt_mask(handle: zx_handle_t) -> Result<(), zx_status_t> {
    crate::object::interrupt_mask(handle)
}

typed_syscall!(
    INTERRUPT_MASK_TYPED,
    interrupt_mask_entry,
    zx_handle_t,
    NoWriteback,
    (),
    decode_interrupt_mask,
    run_interrupt_mask,
    writeback_noop
);
const INTERRUPT_MASK_DISPATCH: SyscallDispatch = SyscallDispatch::new(interrupt_mask_entry);

fn decode_interrupt_unmask(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<zx_handle_t, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(ctx.arg_handle(args, 0)?, NoWriteback))
}

fn run_interrupt_unmask(handle: zx_handle_t) -> Result<(), zx_status_t> {
    crate::object::interrupt_unmask(handle)
}

typed_syscall!(
    INTERRUPT_UNMASK_TYPED,
    interrupt_unmask_entry,
    zx_handle_t,
    NoWriteback,
    (),
    decode_interrupt_unmask,
    run_interrupt_unmask,
    writeback_noop
);
const INTERRUPT_UNMASK_DISPATCH: SyscallDispatch = SyscallDispatch::new(interrupt_unmask_entry);

type InterruptTriggerRequest = (zx_handle_t, u64);

fn decode_ax_interrupt_trigger(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<InterruptTriggerRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, args[1]),
        NoWriteback,
    ))
}

fn run_ax_interrupt_trigger(req: InterruptTriggerRequest) -> Result<(), zx_status_t> {
    crate::object::ax_interrupt_trigger(req.0, req.1)
}

typed_syscall!(
    AX_INTERRUPT_TRIGGER_TYPED,
    ax_interrupt_trigger_entry,
    InterruptTriggerRequest,
    NoWriteback,
    (),
    decode_ax_interrupt_trigger,
    run_ax_interrupt_trigger,
    writeback_noop
);
const AX_INTERRUPT_TRIGGER_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_interrupt_trigger_entry);

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

type VmoCreatePhysicalRequest = (u64, u64, u32);

fn decode_vmo_create_physical(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<VmoCreatePhysicalRequest, OutValue<zx_handle_t>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (args[0], args[1], ctx.arg_u32(args, 2)?),
        ctx.decode_out_value::<zx_handle_t>(args, 3)?,
    ))
}

fn run_vmo_create_physical(req: VmoCreatePhysicalRequest) -> Result<zx_handle_t, zx_status_t> {
    crate::object::vm::create_physical_vmo(req.0, req.1, req.2)
}

typed_syscall!(
    VMO_CREATE_PHYSICAL_TYPED,
    vmo_create_physical_entry,
    VmoCreatePhysicalRequest,
    OutValue<zx_handle_t>,
    zx_handle_t,
    decode_vmo_create_physical,
    run_vmo_create_physical,
    writeback_handle
);
const VMO_CREATE_PHYSICAL_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(vmo_create_physical_entry);

type VmoCreateContiguousRequest = (u64, u32);

fn decode_vmo_create_contiguous(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<VmoCreateContiguousRequest, OutValue<zx_handle_t>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (args[0], ctx.arg_u32(args, 1)?),
        ctx.decode_out_value::<zx_handle_t>(args, 2)?,
    ))
}

fn run_vmo_create_contiguous(req: VmoCreateContiguousRequest) -> Result<zx_handle_t, zx_status_t> {
    crate::object::vm::create_contiguous_vmo(req.0, req.1)
}

typed_syscall!(
    VMO_CREATE_CONTIGUOUS_TYPED,
    vmo_create_contiguous_entry,
    VmoCreateContiguousRequest,
    OutValue<zx_handle_t>,
    zx_handle_t,
    decode_vmo_create_contiguous,
    run_vmo_create_contiguous,
    writeback_handle
);
const VMO_CREATE_CONTIGUOUS_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(vmo_create_contiguous_entry);

type VmoLookupPaddrRequest = (zx_handle_t, u64);
type VmarCloneMappingsRequest = (zx_handle_t, zx_handle_t);

fn decode_ax_vmar_clone_mappings(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<VmarCloneMappingsRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, ctx.arg_handle(args, 1)?),
        NoWriteback,
    ))
}

fn run_ax_vmar_clone_mappings(req: VmarCloneMappingsRequest) -> Result<(), zx_status_t> {
    crate::object::vm::vmar_clone_mappings(req.0, req.1)
}

typed_syscall!(
    AX_VMAR_CLONE_MAPPINGS_TYPED,
    ax_vmar_clone_mappings_entry,
    VmarCloneMappingsRequest,
    NoWriteback,
    (),
    decode_ax_vmar_clone_mappings,
    run_ax_vmar_clone_mappings,
    writeback_noop
);
const AX_VMAR_CLONE_MAPPINGS_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_vmar_clone_mappings_entry);

type VmoGetInfoRequest = zx_handle_t;

fn decode_ax_vmo_get_info(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<VmoGetInfoRequest, OutValue<ax_vmo_info_t>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        ctx.arg_handle(args, 0)?,
        ctx.decode_out_value::<ax_vmo_info_t>(args, 1)?,
    ))
}

fn run_ax_vmo_get_info(req: VmoGetInfoRequest) -> Result<ax_vmo_info_t, zx_status_t> {
    crate::object::vm::vmo_get_info(req)
}

typed_syscall!(
    AX_VMO_GET_INFO_TYPED,
    ax_vmo_get_info_entry,
    VmoGetInfoRequest,
    OutValue<ax_vmo_info_t>,
    ax_vmo_info_t,
    decode_ax_vmo_get_info,
    run_ax_vmo_get_info,
    writeback_vmo_info
);
const AX_VMO_GET_INFO_DISPATCH: SyscallDispatch = SyscallDispatch::new(ax_vmo_get_info_entry);

type VmoPromoteSharedRequest = zx_handle_t;

fn decode_ax_vmo_promote_shared(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<VmoPromoteSharedRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(ctx.arg_handle(args, 0)?, NoWriteback))
}

fn run_ax_vmo_promote_shared(req: VmoPromoteSharedRequest) -> Result<(), zx_status_t> {
    crate::object::vm::vmo_promote_shared(req)
}

typed_syscall!(
    AX_VMO_PROMOTE_SHARED_TYPED,
    ax_vmo_promote_shared_entry,
    VmoPromoteSharedRequest,
    NoWriteback,
    (),
    decode_ax_vmo_promote_shared,
    run_ax_vmo_promote_shared,
    writeback_noop
);
const AX_VMO_PROMOTE_SHARED_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_vmo_promote_shared_entry);

fn decode_ax_vmo_lookup_paddr(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<VmoLookupPaddrRequest, OutValue<u64>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, args[1]),
        ctx.decode_out_value::<u64>(args, 2)?,
    ))
}

fn run_ax_vmo_lookup_paddr(req: VmoLookupPaddrRequest) -> Result<u64, zx_status_t> {
    crate::object::vm::lookup_vmo_paddr(req.0, req.1)
}

typed_syscall!(
    AX_VMO_LOOKUP_PADDR_TYPED,
    ax_vmo_lookup_paddr_entry,
    VmoLookupPaddrRequest,
    OutValue<u64>,
    u64,
    decode_ax_vmo_lookup_paddr,
    run_ax_vmo_lookup_paddr,
    writeback_u64
);
const AX_VMO_LOOKUP_PADDR_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_vmo_lookup_paddr_entry);

type VmoPinRequest = (zx_handle_t, u64, u64, u32);

fn decode_ax_vmo_pin(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<VmoPinRequest, OutValue<zx_handle_t>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (
            ctx.arg_handle(args, 0)?,
            args[1],
            args[2],
            ctx.arg_u32(args, 3)?,
        ),
        ctx.decode_out_value::<zx_handle_t>(args, 4)?,
    ))
}

fn run_ax_vmo_pin(req: VmoPinRequest) -> Result<zx_handle_t, zx_status_t> {
    crate::object::vm::pin_vmo(req.0, req.1, req.2, req.3)
}

typed_syscall!(
    AX_VMO_PIN_TYPED,
    ax_vmo_pin_entry,
    VmoPinRequest,
    OutValue<zx_handle_t>,
    zx_handle_t,
    decode_ax_vmo_pin,
    run_ax_vmo_pin,
    writeback_handle
);
const AX_VMO_PIN_DISPATCH: SyscallDispatch = SyscallDispatch::new(ax_vmo_pin_entry);

type DmaRegionLookupPaddrRequest = (zx_handle_t, u64);

fn decode_ax_dma_region_lookup_paddr(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<DmaRegionLookupPaddrRequest, OutValue<u64>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, args[1]),
        ctx.decode_out_value::<u64>(args, 2)?,
    ))
}

fn run_ax_dma_region_lookup_paddr(req: DmaRegionLookupPaddrRequest) -> Result<u64, zx_status_t> {
    crate::object::vm::lookup_dma_region_paddr(req.0, req.1)
}

typed_syscall!(
    AX_DMA_REGION_LOOKUP_PADDR_TYPED,
    ax_dma_region_lookup_paddr_entry,
    DmaRegionLookupPaddrRequest,
    OutValue<u64>,
    u64,
    decode_ax_dma_region_lookup_paddr,
    run_ax_dma_region_lookup_paddr,
    writeback_u64
);
const AX_DMA_REGION_LOOKUP_PADDR_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_dma_region_lookup_paddr_entry);

type DmaRegionLookupIovaRequest = (zx_handle_t, u64);

fn decode_ax_dma_region_lookup_iova(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<DmaRegionLookupIovaRequest, OutValue<u64>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, args[1]),
        ctx.decode_out_value::<u64>(args, 2)?,
    ))
}

fn run_ax_dma_region_lookup_iova(req: DmaRegionLookupIovaRequest) -> Result<u64, zx_status_t> {
    crate::object::vm::lookup_dma_region_iova(req.0, req.1)
}

typed_syscall!(
    AX_DMA_REGION_LOOKUP_IOVA_TYPED,
    ax_dma_region_lookup_iova_entry,
    DmaRegionLookupIovaRequest,
    OutValue<u64>,
    u64,
    decode_ax_dma_region_lookup_iova,
    run_ax_dma_region_lookup_iova,
    writeback_u64
);
const AX_DMA_REGION_LOOKUP_IOVA_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_dma_region_lookup_iova_entry);

type DmaRegionGetInfoRequest = zx_handle_t;

fn decode_ax_dma_region_get_info(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<DmaRegionGetInfoRequest, OutValue<ax_dma_region_info_t>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        ctx.arg_handle(args, 0)?,
        ctx.decode_out_value::<ax_dma_region_info_t>(args, 1)?,
    ))
}

fn run_ax_dma_region_get_info(
    req: DmaRegionGetInfoRequest,
) -> Result<ax_dma_region_info_t, zx_status_t> {
    crate::object::vm::dma_region_get_info(req)
}

typed_syscall!(
    AX_DMA_REGION_GET_INFO_TYPED,
    ax_dma_region_get_info_entry,
    DmaRegionGetInfoRequest,
    OutValue<ax_dma_region_info_t>,
    ax_dma_region_info_t,
    decode_ax_dma_region_get_info,
    run_ax_dma_region_get_info,
    writeback_dma_region_info
);
const AX_DMA_REGION_GET_INFO_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_dma_region_get_info_entry);

type DmaRegionGetSegmentRequest = (zx_handle_t, u32);

fn decode_ax_dma_region_get_segment(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<DmaRegionGetSegmentRequest, OutValue<ax_dma_segment_info_t>>, zx_status_t>
{
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, ctx.arg_u32(args, 1)?),
        ctx.decode_out_value::<ax_dma_segment_info_t>(args, 2)?,
    ))
}

fn run_ax_dma_region_get_segment(
    req: DmaRegionGetSegmentRequest,
) -> Result<ax_dma_segment_info_t, zx_status_t> {
    crate::object::vm::dma_region_get_segment_info(req.0, req.1)
}

typed_syscall!(
    AX_DMA_REGION_GET_SEGMENT_TYPED,
    ax_dma_region_get_segment_entry,
    DmaRegionGetSegmentRequest,
    OutValue<ax_dma_segment_info_t>,
    ax_dma_segment_info_t,
    decode_ax_dma_region_get_segment,
    run_ax_dma_region_get_segment,
    writeback_dma_segment_info
);
const AX_DMA_REGION_GET_SEGMENT_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_dma_region_get_segment_entry);

type PciDeviceGetInfoRequest = zx_handle_t;

fn decode_ax_pci_device_get_info(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<PciDeviceGetInfoRequest, OutValue<ax_pci_device_info_t>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        ctx.arg_handle(args, 0)?,
        ctx.decode_out_value::<ax_pci_device_info_t>(args, 1)?,
    ))
}

fn run_ax_pci_device_get_info(
    req: PciDeviceGetInfoRequest,
) -> Result<ax_pci_device_info_t, zx_status_t> {
    crate::object::device::pci_device_get_info(req)
}

typed_syscall!(
    AX_PCI_DEVICE_GET_INFO_TYPED,
    ax_pci_device_get_info_entry,
    PciDeviceGetInfoRequest,
    OutValue<ax_pci_device_info_t>,
    ax_pci_device_info_t,
    decode_ax_pci_device_get_info,
    run_ax_pci_device_get_info,
    writeback_pci_device_info
);
const AX_PCI_DEVICE_GET_INFO_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_pci_device_get_info_entry);

type PciDeviceGetConfigRequest = zx_handle_t;

fn decode_ax_pci_device_get_config(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<PciDeviceGetConfigRequest, OutValue<ax_pci_config_info_t>>, zx_status_t>
{
    Ok(DecodedSyscall::new(
        ctx.arg_handle(args, 0)?,
        ctx.decode_out_value::<ax_pci_config_info_t>(args, 1)?,
    ))
}

fn run_ax_pci_device_get_config(
    req: PciDeviceGetConfigRequest,
) -> Result<ax_pci_config_info_t, zx_status_t> {
    crate::object::device::pci_device_get_config(req)
}

typed_syscall!(
    AX_PCI_DEVICE_GET_CONFIG_TYPED,
    ax_pci_device_get_config_entry,
    PciDeviceGetConfigRequest,
    OutValue<ax_pci_config_info_t>,
    ax_pci_config_info_t,
    decode_ax_pci_device_get_config,
    run_ax_pci_device_get_config,
    writeback_pci_config_info
);
const AX_PCI_DEVICE_GET_CONFIG_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_pci_device_get_config_entry);

type PciDeviceGetBarRequest = (zx_handle_t, u32);

fn decode_ax_pci_device_get_bar(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<PciDeviceGetBarRequest, OutValue<ax_pci_bar_info_t>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, ctx.arg_u32(args, 1)?),
        ctx.decode_out_value::<ax_pci_bar_info_t>(args, 2)?,
    ))
}

fn run_ax_pci_device_get_bar(
    req: PciDeviceGetBarRequest,
) -> Result<ax_pci_bar_info_t, zx_status_t> {
    crate::object::device::pci_device_get_bar(req.0, req.1)
}

typed_syscall!(
    AX_PCI_DEVICE_GET_BAR_TYPED,
    ax_pci_device_get_bar_entry,
    PciDeviceGetBarRequest,
    OutValue<ax_pci_bar_info_t>,
    ax_pci_bar_info_t,
    decode_ax_pci_device_get_bar,
    run_ax_pci_device_get_bar,
    writeback_pci_bar_info
);
const AX_PCI_DEVICE_GET_BAR_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_pci_device_get_bar_entry);

type PciDeviceGetInterruptRequest = (zx_handle_t, u32, u32);

fn decode_ax_pci_device_get_interrupt(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<
    DecodedSyscall<PciDeviceGetInterruptRequest, OutValue<ax_pci_interrupt_info_t>>,
    zx_status_t,
> {
    Ok(DecodedSyscall::new(
        (
            ctx.arg_handle(args, 0)?,
            ctx.arg_u32(args, 1)?,
            ctx.arg_u32(args, 2)?,
        ),
        ctx.decode_out_value::<ax_pci_interrupt_info_t>(args, 3)?,
    ))
}

fn run_ax_pci_device_get_interrupt(
    req: PciDeviceGetInterruptRequest,
) -> Result<ax_pci_interrupt_info_t, zx_status_t> {
    crate::object::device::pci_device_get_interrupt(req.0, req.1, req.2)
}

typed_syscall!(
    AX_PCI_DEVICE_GET_INTERRUPT_TYPED,
    ax_pci_device_get_interrupt_entry,
    PciDeviceGetInterruptRequest,
    OutValue<ax_pci_interrupt_info_t>,
    ax_pci_interrupt_info_t,
    decode_ax_pci_device_get_interrupt,
    run_ax_pci_device_get_interrupt,
    writeback_pci_interrupt_info
);
const AX_PCI_DEVICE_GET_INTERRUPT_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_pci_device_get_interrupt_entry);

type PciDeviceGetInterruptModeRequest = (zx_handle_t, u32);

fn decode_ax_pci_device_get_interrupt_mode(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<
    DecodedSyscall<PciDeviceGetInterruptModeRequest, OutValue<ax_pci_interrupt_mode_info_t>>,
    zx_status_t,
> {
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, ctx.arg_u32(args, 1)?),
        ctx.decode_out_value::<ax_pci_interrupt_mode_info_t>(args, 2)?,
    ))
}

fn run_ax_pci_device_get_interrupt_mode(
    req: PciDeviceGetInterruptModeRequest,
) -> Result<ax_pci_interrupt_mode_info_t, zx_status_t> {
    crate::object::device::pci_device_get_interrupt_mode(req.0, req.1)
}

typed_syscall!(
    AX_PCI_DEVICE_GET_INTERRUPT_MODE_TYPED,
    ax_pci_device_get_interrupt_mode_entry,
    PciDeviceGetInterruptModeRequest,
    OutValue<ax_pci_interrupt_mode_info_t>,
    ax_pci_interrupt_mode_info_t,
    decode_ax_pci_device_get_interrupt_mode,
    run_ax_pci_device_get_interrupt_mode,
    writeback_pci_interrupt_mode_info
);
const AX_PCI_DEVICE_GET_INTERRUPT_MODE_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_pci_device_get_interrupt_mode_entry);

type PciDeviceGetResourceCountRequest = zx_handle_t;

fn decode_ax_pci_device_get_resource_count(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<PciDeviceGetResourceCountRequest, OutValue<u64>>, zx_status_t> {
    Ok(DecodedSyscall::new(
        ctx.arg_handle(args, 0)?,
        ctx.decode_out_value::<u64>(args, 1)?,
    ))
}

fn run_ax_pci_device_get_resource_count(
    req: PciDeviceGetResourceCountRequest,
) -> Result<u64, zx_status_t> {
    Ok(u64::from(
        crate::object::device::pci_device_get_resource_count(req)?,
    ))
}

typed_syscall!(
    AX_PCI_DEVICE_GET_RESOURCE_COUNT_TYPED,
    ax_pci_device_get_resource_count_entry,
    PciDeviceGetResourceCountRequest,
    OutValue<u64>,
    u64,
    decode_ax_pci_device_get_resource_count,
    run_ax_pci_device_get_resource_count,
    writeback_u64
);
const AX_PCI_DEVICE_GET_RESOURCE_COUNT_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_pci_device_get_resource_count_entry);

type PciDeviceGetResourceRequest = (zx_handle_t, u32);

fn decode_ax_pci_device_get_resource(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<
    DecodedSyscall<PciDeviceGetResourceRequest, OutValue<ax_pci_resource_info_t>>,
    zx_status_t,
> {
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, ctx.arg_u32(args, 1)?),
        ctx.decode_out_value::<ax_pci_resource_info_t>(args, 2)?,
    ))
}

fn run_ax_pci_device_get_resource(
    req: PciDeviceGetResourceRequest,
) -> Result<ax_pci_resource_info_t, zx_status_t> {
    crate::object::device::pci_device_get_resource(req.0, req.1)
}

typed_syscall!(
    AX_PCI_DEVICE_GET_RESOURCE_TYPED,
    ax_pci_device_get_resource_entry,
    PciDeviceGetResourceRequest,
    OutValue<ax_pci_resource_info_t>,
    ax_pci_resource_info_t,
    decode_ax_pci_device_get_resource,
    run_ax_pci_device_get_resource,
    writeback_pci_resource_info
);
const AX_PCI_DEVICE_GET_RESOURCE_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_pci_device_get_resource_entry);

type PciDeviceSetInterruptModeRequest = (zx_handle_t, u32);

fn decode_ax_pci_device_set_interrupt_mode(
    ctx: &mut SyscallCtx,
    args: [u64; 6],
) -> Result<DecodedSyscall<PciDeviceSetInterruptModeRequest, NoWriteback>, zx_status_t> {
    Ok(DecodedSyscall::new(
        (ctx.arg_handle(args, 0)?, ctx.arg_u32(args, 1)?),
        NoWriteback,
    ))
}

fn run_ax_pci_device_set_interrupt_mode(
    req: PciDeviceSetInterruptModeRequest,
) -> Result<(), zx_status_t> {
    crate::object::device::pci_device_set_interrupt_mode(req.0, req.1)
}

typed_syscall!(
    AX_PCI_DEVICE_SET_INTERRUPT_MODE_TYPED,
    ax_pci_device_set_interrupt_mode_entry,
    PciDeviceSetInterruptModeRequest,
    NoWriteback,
    (),
    decode_ax_pci_device_set_interrupt_mode,
    run_ax_pci_device_set_interrupt_mode,
    writeback_noop
);
const AX_PCI_DEVICE_SET_INTERRUPT_MODE_DISPATCH: SyscallDispatch =
    SyscallDispatch::new(ax_pci_device_set_interrupt_mode_entry);

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
        AXLE_SYS_INTERRUPT_CREATE => Some(&INTERRUPT_CREATE_DISPATCH),
        AXLE_SYS_INTERRUPT_GET_INFO => Some(&INTERRUPT_GET_INFO_DISPATCH),
        AXLE_SYS_INTERRUPT_ACK => Some(&INTERRUPT_ACK_DISPATCH),
        AXLE_SYS_INTERRUPT_MASK => Some(&INTERRUPT_MASK_DISPATCH),
        AXLE_SYS_INTERRUPT_UNMASK => Some(&INTERRUPT_UNMASK_DISPATCH),
        AXLE_SYS_AX_INTERRUPT_TRIGGER => Some(&AX_INTERRUPT_TRIGGER_DISPATCH),
        AXLE_SYS_VMO_CREATE => Some(&VMO_CREATE_DISPATCH),
        AXLE_SYS_VMO_CREATE_PHYSICAL => Some(&VMO_CREATE_PHYSICAL_DISPATCH),
        AXLE_SYS_VMO_CREATE_CONTIGUOUS => Some(&VMO_CREATE_CONTIGUOUS_DISPATCH),
        AXLE_SYS_VMO_READ => Some(&VMO_READ_DISPATCH),
        AXLE_SYS_VMO_WRITE => Some(&VMO_WRITE_DISPATCH),
        AXLE_SYS_VMO_SET_SIZE => Some(&VMO_SET_SIZE_DISPATCH),
        AXLE_SYS_AX_VMAR_CLONE_MAPPINGS => Some(&AX_VMAR_CLONE_MAPPINGS_DISPATCH),
        AXLE_SYS_AX_VMO_GET_INFO => Some(&AX_VMO_GET_INFO_DISPATCH),
        AXLE_SYS_AX_VMO_PROMOTE_SHARED => Some(&AX_VMO_PROMOTE_SHARED_DISPATCH),
        AXLE_SYS_AX_VMO_LOOKUP_PADDR => Some(&AX_VMO_LOOKUP_PADDR_DISPATCH),
        AXLE_SYS_AX_VMO_PIN => Some(&AX_VMO_PIN_DISPATCH),
        AXLE_SYS_AX_DMA_REGION_LOOKUP_PADDR => Some(&AX_DMA_REGION_LOOKUP_PADDR_DISPATCH),
        AXLE_SYS_AX_DMA_REGION_LOOKUP_IOVA => Some(&AX_DMA_REGION_LOOKUP_IOVA_DISPATCH),
        AXLE_SYS_AX_DMA_REGION_GET_INFO => Some(&AX_DMA_REGION_GET_INFO_DISPATCH),
        AXLE_SYS_AX_DMA_REGION_GET_SEGMENT => Some(&AX_DMA_REGION_GET_SEGMENT_DISPATCH),
        AXLE_SYS_AX_PCI_DEVICE_GET_INFO => Some(&AX_PCI_DEVICE_GET_INFO_DISPATCH),
        AXLE_SYS_AX_PCI_DEVICE_GET_CONFIG => Some(&AX_PCI_DEVICE_GET_CONFIG_DISPATCH),
        AXLE_SYS_AX_PCI_DEVICE_GET_BAR => Some(&AX_PCI_DEVICE_GET_BAR_DISPATCH),
        AXLE_SYS_AX_PCI_DEVICE_GET_INTERRUPT => Some(&AX_PCI_DEVICE_GET_INTERRUPT_DISPATCH),
        AXLE_SYS_AX_PCI_DEVICE_GET_INTERRUPT_MODE => {
            Some(&AX_PCI_DEVICE_GET_INTERRUPT_MODE_DISPATCH)
        }
        AXLE_SYS_AX_PCI_DEVICE_GET_RESOURCE_COUNT => {
            Some(&AX_PCI_DEVICE_GET_RESOURCE_COUNT_DISPATCH)
        }
        AXLE_SYS_AX_PCI_DEVICE_GET_RESOURCE => Some(&AX_PCI_DEVICE_GET_RESOURCE_DISPATCH),
        AXLE_SYS_AX_PCI_DEVICE_SET_INTERRUPT_MODE => {
            Some(&AX_PCI_DEVICE_SET_INTERRUPT_MODE_DISPATCH)
        }
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
        AXLE_SYS_AX_THREAD_SET_GUEST_X64_FS_BASE => Some(&AX_THREAD_SET_GUEST_X64_FS_BASE_DISPATCH),
        AXLE_SYS_AX_THREAD_GET_GUEST_X64_FS_BASE => Some(&AX_THREAD_GET_GUEST_X64_FS_BASE_DISPATCH),
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
