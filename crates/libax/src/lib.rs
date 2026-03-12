//! Thin native Axle userspace facade.
//!
//! `libax` is the native UAPI personality for new userspace code. During the
//! ABI transition it forwards through the frozen `libzircon` compatibility
//! wrappers while presenting `ax_*` types and names to callers.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::ptr;

pub use libzircon::nexus_component;

pub use axle_types::clock;
pub use axle_types::guest;
pub use axle_types::handle;
pub use axle_types::koid;
pub use axle_types::packet;
pub use axle_types::rights;
pub use axle_types::signals;
pub use axle_types::socket;
pub use axle_types::status;
pub use axle_types::syscall_numbers;
pub use axle_types::vm;
pub use axle_types::wait_async;
pub use axle_types::{
    ax_clock_t, ax_duration_t, ax_futex_t, ax_guest_stop_state_t, ax_guest_x64_regs_t, ax_handle_t,
    ax_koid_t, ax_linux_exec_spec_header_t, ax_packet_signal_t, ax_packet_type_t, ax_packet_user_t,
    ax_port_packet_t, ax_rights_t, ax_signals_t, ax_status_t, ax_time_t, ax_vaddr_t,
    ax_vm_option_t,
};

use axle_types::status::{AX_ERR_NO_MEMORY, AX_ERR_OUT_OF_RANGE, AX_OK};

/// Infinite deadline used by blocking wait syscalls.
pub const AX_TIME_INFINITE: ax_time_t = i64::MAX;

fn narrow_handle(handle: ax_handle_t) -> Result<libzircon::zx_handle_t, ax_status_t> {
    libzircon::zx_handle_t::try_from(handle).map_err(|_| AX_ERR_OUT_OF_RANGE)
}

fn widen_handle(handle: libzircon::zx_handle_t) -> ax_handle_t {
    ax_handle_t::from(handle)
}

fn narrow_handle_slice(
    handles: &[ax_handle_t],
) -> Result<Vec<libzircon::zx_handle_t>, ax_status_t> {
    let mut raw = Vec::new();
    raw.try_reserve_exact(handles.len())
        .map_err(|_| AX_ERR_NO_MEMORY)?;
    for &handle in handles {
        raw.push(narrow_handle(handle)?);
    }
    Ok(raw)
}

/// Convert a raw `ax_status_t` into `Result<(), ax_status_t>`.
pub fn ax_status_result(status: ax_status_t) -> Result<(), ax_status_t> {
    if status == AX_OK { Ok(()) } else { Err(status) }
}

/// Close a handle.
pub fn ax_handle_close(handle: ax_handle_t) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::zx_handle_close(raw),
        Err(status) => status,
    }
}

/// Duplicate a handle into the current process.
pub fn ax_handle_duplicate(
    handle: ax_handle_t,
    rights: ax_rights_t,
    out: &mut ax_handle_t,
) -> ax_status_t {
    let raw_handle = match narrow_handle(handle) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let mut raw_out = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::zx_handle_duplicate(raw_handle, rights, &mut raw_out);
    if status == AX_OK {
        *out = widen_handle(raw_out);
    }
    status
}

/// Wait synchronously for any bit in `signals` to become satisfied.
pub fn ax_object_wait_one(
    handle: ax_handle_t,
    signals: ax_signals_t,
    deadline: ax_time_t,
    observed: &mut ax_signals_t,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::zx_object_wait_one(raw, signals, deadline, observed),
        Err(status) => status,
    }
}

/// Register a one-shot async wait on `port`.
pub fn ax_object_wait_async(
    handle: ax_handle_t,
    port: ax_handle_t,
    key: u64,
    signals: ax_signals_t,
    options: u32,
) -> ax_status_t {
    let raw_handle = match narrow_handle(handle) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let raw_port = match narrow_handle(port) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    libzircon::zx_object_wait_async(raw_handle, raw_port, key, signals, options)
}

/// Create a port handle.
pub fn ax_port_create(options: u32, out: &mut ax_handle_t) -> ax_status_t {
    let mut raw_out = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::zx_port_create(options, &mut raw_out);
    if status == AX_OK {
        *out = widen_handle(raw_out);
    }
    status
}

/// Queue a user packet into a port.
pub fn ax_port_queue(port: ax_handle_t, packet: &ax_port_packet_t) -> ax_status_t {
    match narrow_handle(port) {
        Ok(raw) => libzircon::zx_port_queue(raw, packet),
        Err(status) => status,
    }
}

/// Block on a port until a packet is available or `deadline` expires.
pub fn ax_port_wait(
    port: ax_handle_t,
    deadline: ax_time_t,
    packet: &mut ax_port_packet_t,
) -> ax_status_t {
    match narrow_handle(port) {
        Ok(raw) => libzircon::zx_port_wait(raw, deadline, packet),
        Err(status) => status,
    }
}

/// Create a timer handle.
pub fn ax_timer_create(options: u32, clock_id: ax_clock_t, out: &mut ax_handle_t) -> ax_status_t {
    let mut raw_out = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::zx_timer_create(options, clock_id, &mut raw_out);
    if status == AX_OK {
        *out = widen_handle(raw_out);
    }
    status
}

/// Create a monotonic timer handle.
pub fn ax_timer_create_monotonic(options: u32, out: &mut ax_handle_t) -> ax_status_t {
    let mut raw_out = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::zx_timer_create_monotonic(options, &mut raw_out);
    if status == AX_OK {
        *out = widen_handle(raw_out);
    }
    status
}

/// Arm a timer.
pub fn ax_timer_set(handle: ax_handle_t, deadline: ax_time_t, slack: ax_duration_t) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::zx_timer_set(raw, deadline, slack),
        Err(status) => status,
    }
}

/// Cancel a timer.
pub fn ax_timer_cancel(handle: ax_handle_t) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::zx_timer_cancel(raw),
        Err(status) => status,
    }
}

/// Create a channel pair.
pub fn ax_channel_create(
    options: u32,
    out0: &mut ax_handle_t,
    out1: &mut ax_handle_t,
) -> ax_status_t {
    let mut raw0 = libzircon::handle::ZX_HANDLE_INVALID;
    let mut raw1 = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::zx_channel_create(options, &mut raw0, &mut raw1);
    if status == AX_OK {
        *out0 = widen_handle(raw0);
        *out1 = widen_handle(raw1);
    }
    status
}

/// Write bytes and optional transferred handles into a channel.
pub fn ax_channel_write(
    handle: ax_handle_t,
    options: u32,
    bytes: &[u8],
    handles: &[ax_handle_t],
) -> ax_status_t {
    let raw_handle = match narrow_handle(handle) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let raw_handles = match narrow_handle_slice(handles) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let num_bytes = match u32::try_from(bytes.len()) {
        Ok(len) => len,
        Err(_) => return AX_ERR_OUT_OF_RANGE,
    };
    let num_handles = match u32::try_from(raw_handles.len()) {
        Ok(len) => len,
        Err(_) => return AX_ERR_OUT_OF_RANGE,
    };
    libzircon::zx_channel_write(
        raw_handle,
        options,
        if bytes.is_empty() {
            ptr::null()
        } else {
            bytes.as_ptr()
        },
        num_bytes,
        if raw_handles.is_empty() {
            ptr::null()
        } else {
            raw_handles.as_ptr()
        },
        num_handles,
    )
}

/// Read bytes and optional transferred handles from a channel.
pub fn ax_channel_read(
    handle: ax_handle_t,
    options: u32,
    bytes: &mut [u8],
    handles: &mut [ax_handle_t],
    actual_bytes: &mut u32,
    actual_handles: &mut u32,
) -> ax_status_t {
    let raw_handle = match narrow_handle(handle) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let num_bytes = match u32::try_from(bytes.len()) {
        Ok(len) => len,
        Err(_) => return AX_ERR_OUT_OF_RANGE,
    };
    let num_handles = match u32::try_from(handles.len()) {
        Ok(len) => len,
        Err(_) => return AX_ERR_OUT_OF_RANGE,
    };
    let mut raw_handles = Vec::new();
    if handles.is_empty() {
        raw_handles = Vec::new();
    } else {
        raw_handles.resize(handles.len(), libzircon::handle::ZX_HANDLE_INVALID);
    }
    let status = libzircon::zx_channel_read(
        raw_handle,
        options,
        if bytes.is_empty() {
            ptr::null_mut()
        } else {
            bytes.as_mut_ptr()
        },
        if raw_handles.is_empty() {
            ptr::null_mut()
        } else {
            raw_handles.as_mut_ptr()
        },
        num_bytes,
        num_handles,
        actual_bytes,
        actual_handles,
    );
    if status == AX_OK {
        let copy_len = core::cmp::min(handles.len(), usize::try_from(*actual_handles).unwrap_or(0));
        for (dst, raw) in handles
            .iter_mut()
            .zip(raw_handles.into_iter())
            .take(copy_len)
        {
            *dst = widen_handle(raw);
        }
    }
    status
}

/// Read the next channel message into freshly allocated byte and handle vectors.
pub fn ax_channel_read_alloc(
    handle: ax_handle_t,
    options: u32,
) -> Result<(Vec<u8>, Vec<ax_handle_t>), ax_status_t> {
    let raw_handle = narrow_handle(handle)?;
    let (bytes, raw_handles) = libzircon::zx_channel_read_alloc(raw_handle, options)?;
    let handles = raw_handles.into_iter().map(widen_handle).collect();
    Ok((bytes, handles))
}

/// Create a socket pair.
pub fn ax_socket_create(
    options: u32,
    out0: &mut ax_handle_t,
    out1: &mut ax_handle_t,
) -> ax_status_t {
    let mut raw0 = libzircon::handle::ZX_HANDLE_INVALID;
    let mut raw1 = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::zx_socket_create(options, &mut raw0, &mut raw1);
    if status == AX_OK {
        *out0 = widen_handle(raw0);
        *out1 = widen_handle(raw1);
    }
    status
}

/// Write bytes into a socket.
pub fn ax_socket_write(
    handle: ax_handle_t,
    options: u32,
    bytes: &[u8],
    actual: &mut usize,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::zx_socket_write(raw, options, bytes.as_ptr(), bytes.len(), actual),
        Err(status) => status,
    }
}

/// Read bytes from a socket.
pub fn ax_socket_read(
    handle: ax_handle_t,
    options: u32,
    bytes: &mut [u8],
    actual: &mut usize,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::zx_socket_read(raw, options, bytes.as_mut_ptr(), bytes.len(), actual),
        Err(status) => status,
    }
}

/// Create a VMO.
pub fn ax_vmo_create(size: u64, options: u32, out: &mut ax_handle_t) -> ax_status_t {
    let mut raw_out = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::zx_vmo_create(size, options, &mut raw_out);
    if status == AX_OK {
        *out = widen_handle(raw_out);
    }
    status
}

/// Read bytes from a VMO.
pub fn ax_vmo_read(handle: ax_handle_t, bytes: &mut [u8], offset: u64) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::zx_vmo_read(raw, bytes, offset),
        Err(status) => status,
    }
}

/// Write bytes into a VMO.
pub fn ax_vmo_write(handle: ax_handle_t, bytes: &[u8], offset: u64) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::zx_vmo_write(raw, bytes, offset),
        Err(status) => status,
    }
}

/// Create a process and its root VMAR.
pub fn ax_process_create(
    parent_process: ax_handle_t,
    options: u32,
    out_process: &mut ax_handle_t,
    out_root_vmar: &mut ax_handle_t,
) -> ax_status_t {
    let raw_parent = match narrow_handle(parent_process) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let mut raw_process = libzircon::handle::ZX_HANDLE_INVALID;
    let mut raw_root_vmar = libzircon::handle::ZX_HANDLE_INVALID;
    let status =
        libzircon::zx_process_create(raw_parent, options, &mut raw_process, &mut raw_root_vmar);
    if status == AX_OK {
        *out_process = widen_handle(raw_process);
        *out_root_vmar = widen_handle(raw_root_vmar);
    }
    status
}

/// Create a thread inside an existing process.
pub fn ax_thread_create(
    process: ax_handle_t,
    options: u32,
    out_thread: &mut ax_handle_t,
) -> ax_status_t {
    let raw_process = match narrow_handle(process) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let mut raw_thread = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::zx_thread_create(raw_process, options, &mut raw_thread);
    if status == AX_OK {
        *out_thread = widen_handle(raw_thread);
    }
    status
}

/// Start a process entry thread.
pub fn ax_process_start(
    process: ax_handle_t,
    thread: ax_handle_t,
    entry: u64,
    stack: u64,
    arg_handle: ax_handle_t,
    arg1: u64,
) -> ax_status_t {
    let raw_process = match narrow_handle(process) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let raw_thread = match narrow_handle(thread) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let raw_arg = match narrow_handle(arg_handle) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    libzircon::zx_process_start(raw_process, raw_thread, entry, stack, raw_arg, arg1)
}

/// Start a non-entry thread.
pub fn ax_thread_start(
    thread: ax_handle_t,
    entry: u64,
    stack: u64,
    arg0: u64,
    arg1: u64,
) -> ax_status_t {
    match narrow_handle(thread) {
        Ok(raw) => libzircon::zx_thread_start(raw, entry, stack, arg0, arg1),
        Err(status) => status,
    }
}

/// Prepare a generic child process image.
pub fn ax_process_prepare_start(
    process: ax_handle_t,
    image_vmo: ax_handle_t,
    options: u32,
    out_entry: &mut u64,
    out_stack: &mut u64,
) -> ax_status_t {
    let raw_process = match narrow_handle(process) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let raw_image = match narrow_handle(image_vmo) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    libzircon::ax_process_prepare_start(raw_process, raw_image, options, out_entry, out_stack)
}

/// Prepare a Linux-flavored child process image using an opaque exec-spec blob.
pub fn ax_process_prepare_linux_exec(
    process: ax_handle_t,
    image_vmo: ax_handle_t,
    options: u32,
    exec_spec: &[u8],
    out_entry: &mut u64,
    out_stack: &mut u64,
) -> ax_status_t {
    let raw_process = match narrow_handle(process) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let raw_image = match narrow_handle(image_vmo) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    libzircon::ax_process_prepare_linux_exec(
        raw_process,
        raw_image,
        options,
        exec_spec,
        out_entry,
        out_stack,
    )
}

/// Create one guest session bound to a thread, sidecar VMO, and supervisor port.
pub fn ax_guest_session_create(
    thread: ax_handle_t,
    sidecar_vmo: ax_handle_t,
    port: ax_handle_t,
    key: u64,
    options: u32,
    out_session: &mut ax_handle_t,
) -> ax_status_t {
    let raw_thread = match narrow_handle(thread) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let raw_sidecar = match narrow_handle(sidecar_vmo) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let raw_port = match narrow_handle(port) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let mut raw_out = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::ax_guest_session_create(
        raw_thread,
        raw_sidecar,
        raw_port,
        key,
        options,
        &mut raw_out,
    );
    if status == AX_OK {
        *out_session = widen_handle(raw_out);
    }
    status
}

/// Resume one stopped guest session after the sidecar state was updated.
pub fn ax_guest_session_resume(session: ax_handle_t, stop_seq: u64, options: u32) -> ax_status_t {
    match narrow_handle(session) {
        Ok(raw) => libzircon::ax_guest_session_resume(raw, stop_seq, options),
        Err(status) => status,
    }
}

/// Copy guest userspace bytes out of one supervised guest session.
pub fn ax_guest_session_read_memory(
    session: ax_handle_t,
    guest_addr: u64,
    buffer: &mut [u8],
) -> ax_status_t {
    match narrow_handle(session) {
        Ok(raw) => libzircon::ax_guest_session_read_memory(raw, guest_addr, buffer),
        Err(status) => status,
    }
}

/// Copy kernel-owned bytes into one supervised guest session's userspace memory.
pub fn ax_guest_session_write_memory(
    session: ax_handle_t,
    guest_addr: u64,
    buffer: &[u8],
) -> ax_status_t {
    match narrow_handle(session) {
        Ok(raw) => libzircon::ax_guest_session_write_memory(raw, guest_addr, buffer),
        Err(status) => status,
    }
}

/// Start one newly created process from a full guest x86_64 register snapshot.
pub fn ax_process_start_guest(
    process: ax_handle_t,
    thread: ax_handle_t,
    regs: &ax_guest_x64_regs_t,
    options: u32,
) -> ax_status_t {
    let raw_process = match narrow_handle(process) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let raw_thread = match narrow_handle(thread) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    libzircon::ax_process_start_guest(raw_process, raw_thread, regs, options)
}

/// Start one newly created thread from a full guest x86_64 register snapshot.
pub fn ax_thread_start_guest(
    thread: ax_handle_t,
    regs: &ax_guest_x64_regs_t,
    options: u32,
) -> ax_status_t {
    match narrow_handle(thread) {
        Ok(raw) => libzircon::ax_thread_start_guest(raw, regs, options),
        Err(status) => status,
    }
}

/// Kill a process or thread carrier.
pub fn ax_task_kill(handle: ax_handle_t) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::zx_task_kill(raw),
        Err(status) => status,
    }
}

/// Build one opaque Linux exec-spec blob from the shared fixed header plus caller-provided stack-image bytes.
pub fn ax_linux_exec_spec_blob(
    header: ax_linux_exec_spec_header_t,
    stack_image: &[u8],
) -> Result<Vec<u8>, ax_status_t> {
    libzircon::ax_linux_exec_spec_blob(header, stack_image)
}

/// Read one guest stop-state snapshot from a sidecar VMO.
pub fn ax_guest_stop_state_read(
    sidecar_vmo: ax_handle_t,
) -> Result<ax_guest_stop_state_t, ax_status_t> {
    let raw = narrow_handle(sidecar_vmo)?;
    libzircon::ax_guest_stop_state_read(raw)
}

/// Write one guest stop-state snapshot into a sidecar VMO.
pub fn ax_guest_stop_state_write(
    sidecar_vmo: ax_handle_t,
    stop_state: &ax_guest_stop_state_t,
) -> ax_status_t {
    match narrow_handle(sidecar_vmo) {
        Ok(raw) => libzircon::ax_guest_stop_state_write(raw, stop_state),
        Err(status) => status,
    }
}

/// Bootstrap-channel helpers for component-style process startup.
pub mod bootstrap {
    use super::{ax_handle_t, ax_status_t, narrow_handle, nexus_component};

    /// Read and decode one `ComponentStartInfo` message from a bootstrap channel.
    pub fn read_component_start_info(
        bootstrap_channel: ax_handle_t,
    ) -> Result<nexus_component::ComponentStartInfo, ax_status_t> {
        let raw = narrow_handle(bootstrap_channel)?;
        libzircon::bootstrap::read_component_start_info(raw)
    }
}
