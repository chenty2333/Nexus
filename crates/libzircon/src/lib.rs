//! Thin userspace Zircon compatibility wrappers for Axle/Nexus.
//!
//! This crate intentionally adds very little policy. It re-exports the shared
//! ABI surface from `axle-types` and maps `zx_*` calls onto the current
//! bootstrap `int 0x80` userspace ABI.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::ptr;

pub use nexus_component;

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
    ax_guest_stop_state_t, ax_guest_x64_regs_t, ax_linux_exec_interp_header_t,
    ax_linux_exec_spec_header_t, zx_clock_t, zx_duration_t, zx_futex_t, zx_handle_t, zx_koid_t,
    zx_packet_signal_t, zx_packet_type_t, zx_packet_user_t, zx_port_packet_t, zx_rights_t,
    zx_signals_t, zx_status_t, zx_time_t, zx_vaddr_t, zx_vm_option_t,
};

use axle_types::clock::ZX_CLOCK_MONOTONIC;
use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::status::{ZX_ERR_BUFFER_TOO_SMALL, ZX_ERR_IO_DATA_INTEGRITY, ZX_ERR_NO_MEMORY};
use axle_types::syscall_numbers::{
    AXLE_SYS_AX_GUEST_SESSION_CREATE, AXLE_SYS_AX_GUEST_SESSION_READ_MEMORY,
    AXLE_SYS_AX_GUEST_SESSION_RESUME, AXLE_SYS_AX_GUEST_SESSION_WRITE_MEMORY,
    AXLE_SYS_AX_PROCESS_PREPARE_LINUX_EXEC, AXLE_SYS_AX_PROCESS_PREPARE_START,
    AXLE_SYS_AX_PROCESS_START_GUEST, AXLE_SYS_AX_THREAD_START_GUEST, AXLE_SYS_CHANNEL_CREATE,
    AXLE_SYS_CHANNEL_READ, AXLE_SYS_CHANNEL_WRITE, AXLE_SYS_EVENTPAIR_CREATE,
    AXLE_SYS_HANDLE_CLOSE, AXLE_SYS_HANDLE_DUPLICATE, AXLE_SYS_OBJECT_SIGNAL,
    AXLE_SYS_OBJECT_SIGNAL_PEER, AXLE_SYS_OBJECT_WAIT_ASYNC, AXLE_SYS_OBJECT_WAIT_ONE,
    AXLE_SYS_PORT_CREATE, AXLE_SYS_PORT_QUEUE, AXLE_SYS_PORT_WAIT, AXLE_SYS_PROCESS_CREATE,
    AXLE_SYS_PROCESS_START, AXLE_SYS_SOCKET_CREATE, AXLE_SYS_SOCKET_READ, AXLE_SYS_SOCKET_WRITE,
    AXLE_SYS_TASK_KILL, AXLE_SYS_THREAD_CREATE, AXLE_SYS_THREAD_START, AXLE_SYS_TIMER_CANCEL,
    AXLE_SYS_TIMER_CREATE, AXLE_SYS_TIMER_SET, AXLE_SYS_VMO_CREATE, AXLE_SYS_VMO_READ,
    AXLE_SYS_VMO_WRITE,
};

/// Infinite deadline used by blocking wait syscalls.
pub const ZX_TIME_INFINITE: zx_time_t = i64::MAX;

#[inline(always)]
fn int80_call(nr: u64, args: [u64; 6]) -> zx_status_t {
    axle_arch_x86_64::int80_syscall(nr, args)
}

#[inline(always)]
fn int80_call8(nr: u64, args: [u64; 8]) -> zx_status_t {
    axle_arch_x86_64::int80_syscall8(nr, args)
}

/// Convert a raw `zx_status_t` into `Result<(), zx_status_t>`.
pub fn zx_status_result(status: zx_status_t) -> Result<(), zx_status_t> {
    if status == status::ZX_OK {
        Ok(())
    } else {
        Err(status)
    }
}

/// Close a handle.
pub fn zx_handle_close(handle: zx_handle_t) -> zx_status_t {
    int80_call(AXLE_SYS_HANDLE_CLOSE as u64, [handle, 0, 0, 0, 0, 0])
}

/// Duplicate a handle into the current process.
pub fn zx_handle_duplicate(
    handle: zx_handle_t,
    rights: zx_rights_t,
    out: &mut zx_handle_t,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_HANDLE_DUPLICATE as u64,
        [
            handle,
            rights as u64,
            out as *mut zx_handle_t as u64,
            0,
            0,
            0,
        ],
    )
}

/// Wait synchronously for any bit in `signals` to become satisfied.
pub fn zx_object_wait_one(
    handle: zx_handle_t,
    signals: zx_signals_t,
    deadline: zx_time_t,
    observed: &mut zx_signals_t,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_OBJECT_WAIT_ONE as u64,
        [
            handle,
            signals as u64,
            deadline as u64,
            observed as *mut zx_signals_t as u64,
            0,
            0,
        ],
    )
}

/// Register a one-shot async wait on `port`.
pub fn zx_object_wait_async(
    handle: zx_handle_t,
    port: zx_handle_t,
    key: u64,
    signals: zx_signals_t,
    options: u32,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_OBJECT_WAIT_ASYNC as u64,
        [handle, port, key, signals as u64, options as u64, 0],
    )
}

/// Create an eventpair handle pair.
pub fn zx_eventpair_create(
    options: u32,
    out0: &mut zx_handle_t,
    out1: &mut zx_handle_t,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_EVENTPAIR_CREATE as u64,
        [
            options as u64,
            out0 as *mut zx_handle_t as u64,
            out1 as *mut zx_handle_t as u64,
            0,
            0,
            0,
        ],
    )
}

/// Clear and set user-visible signals on one handle.
pub fn zx_object_signal(
    handle: zx_handle_t,
    clear_mask: zx_signals_t,
    set_mask: zx_signals_t,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_OBJECT_SIGNAL as u64,
        [handle, clear_mask as u64, set_mask as u64, 0, 0, 0],
    )
}

/// Clear and set user-visible signals on the peer of one handle.
pub fn zx_object_signal_peer(
    handle: zx_handle_t,
    clear_mask: zx_signals_t,
    set_mask: zx_signals_t,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_OBJECT_SIGNAL_PEER as u64,
        [handle, clear_mask as u64, set_mask as u64, 0, 0, 0],
    )
}

/// Create a port handle.
pub fn zx_port_create(options: u32, out: &mut zx_handle_t) -> zx_status_t {
    int80_call(
        AXLE_SYS_PORT_CREATE as u64,
        [options as u64, out as *mut zx_handle_t as u64, 0, 0, 0, 0],
    )
}

/// Queue a user packet into a port.
pub fn zx_port_queue(port: zx_handle_t, packet: &zx_port_packet_t) -> zx_status_t {
    int80_call(
        AXLE_SYS_PORT_QUEUE as u64,
        [port, packet as *const zx_port_packet_t as u64, 0, 0, 0, 0],
    )
}

/// Block on a port until a packet is available or `deadline` expires.
pub fn zx_port_wait(
    port: zx_handle_t,
    deadline: zx_time_t,
    packet: &mut zx_port_packet_t,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_PORT_WAIT as u64,
        [
            port,
            deadline as u64,
            packet as *mut zx_port_packet_t as u64,
            0,
            0,
            0,
        ],
    )
}

/// Create a timer handle.
pub fn zx_timer_create(options: u32, clock_id: zx_clock_t, out: &mut zx_handle_t) -> zx_status_t {
    int80_call(
        AXLE_SYS_TIMER_CREATE as u64,
        [
            options as u64,
            clock_id as u64,
            out as *mut zx_handle_t as u64,
            0,
            0,
            0,
        ],
    )
}

/// Create a monotonic timer handle.
pub fn zx_timer_create_monotonic(options: u32, out: &mut zx_handle_t) -> zx_status_t {
    zx_timer_create(options, ZX_CLOCK_MONOTONIC, out)
}

/// Arm a timer.
pub fn zx_timer_set(handle: zx_handle_t, deadline: zx_time_t, slack: zx_duration_t) -> zx_status_t {
    int80_call(
        AXLE_SYS_TIMER_SET as u64,
        [handle, deadline as u64, slack as u64, 0, 0, 0],
    )
}

/// Cancel a timer.
pub fn zx_timer_cancel(handle: zx_handle_t) -> zx_status_t {
    int80_call(AXLE_SYS_TIMER_CANCEL as u64, [handle, 0, 0, 0, 0, 0])
}

/// Create a channel pair.
pub fn zx_channel_create(
    options: u32,
    out0: &mut zx_handle_t,
    out1: &mut zx_handle_t,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_CHANNEL_CREATE as u64,
        [
            options as u64,
            out0 as *mut zx_handle_t as u64,
            out1 as *mut zx_handle_t as u64,
            0,
            0,
            0,
        ],
    )
}

/// Write bytes and optional transferred handles into a channel.
pub fn zx_channel_write(
    handle: zx_handle_t,
    options: u32,
    bytes: *const u8,
    num_bytes: u32,
    handles: *const zx_handle_t,
    num_handles: u32,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_CHANNEL_WRITE as u64,
        [
            handle,
            options as u64,
            bytes as u64,
            num_bytes as u64,
            handles as u64,
            num_handles as u64,
        ],
    )
}

/// Read bytes and optional transferred handles from a channel.
///
/// This syscall uses the current Axle bootstrap ABI for arguments 6 and 7:
/// `actual_bytes` and `actual_handles` are placed on the userspace stack and
/// consumed by the trap handler.
#[allow(clippy::too_many_arguments)]
pub fn zx_channel_read(
    handle: zx_handle_t,
    options: u32,
    bytes: *mut u8,
    handles: *mut zx_handle_t,
    num_bytes: u32,
    num_handles: u32,
    actual_bytes: *mut u32,
    actual_handles: *mut u32,
) -> zx_status_t {
    int80_call8(
        AXLE_SYS_CHANNEL_READ as u64,
        [
            handle,
            options as u64,
            bytes as u64,
            handles as u64,
            num_bytes as u64,
            num_handles as u64,
            actual_bytes as u64,
            actual_handles as u64,
        ],
    )
}

/// Read the next channel message into freshly allocated byte and handle vectors.
pub fn zx_channel_read_alloc(
    handle: zx_handle_t,
    options: u32,
) -> Result<(Vec<u8>, Vec<zx_handle_t>), zx_status_t> {
    loop {
        let mut actual_bytes = 0u32;
        let mut actual_handles = 0u32;
        let probe = zx_channel_read(
            handle,
            options,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            0,
            &mut actual_bytes,
            &mut actual_handles,
        );
        if probe != ZX_ERR_BUFFER_TOO_SMALL && probe != status::ZX_OK {
            return Err(probe);
        }

        let byte_len = usize::try_from(actual_bytes).map_err(|_| status::ZX_ERR_OUT_OF_RANGE)?;
        let handle_len =
            usize::try_from(actual_handles).map_err(|_| status::ZX_ERR_OUT_OF_RANGE)?;

        let mut bytes = vec![0u8; byte_len];
        let mut handles = vec![ZX_HANDLE_INVALID; handle_len];
        let status = zx_channel_read(
            handle,
            options,
            if bytes.is_empty() {
                ptr::null_mut()
            } else {
                bytes.as_mut_ptr()
            },
            if handles.is_empty() {
                ptr::null_mut()
            } else {
                handles.as_mut_ptr()
            },
            actual_bytes,
            actual_handles,
            &mut actual_bytes,
            &mut actual_handles,
        );
        if status == ZX_ERR_BUFFER_TOO_SMALL {
            continue;
        }
        if status != status::ZX_OK {
            return Err(status);
        }
        bytes.truncate(usize::try_from(actual_bytes).map_err(|_| status::ZX_ERR_OUT_OF_RANGE)?);
        handles.truncate(usize::try_from(actual_handles).map_err(|_| status::ZX_ERR_OUT_OF_RANGE)?);
        return Ok((bytes, handles));
    }
}

/// Bootstrap-channel helpers for component-manager style process startup.
pub mod bootstrap {
    use nexus_component::{CodecError, ComponentStartInfo};

    use super::*;

    fn map_codec_error(error: CodecError) -> zx_status_t {
        match error {
            CodecError::UnexpectedEof
            | CodecError::InvalidMagic
            | CodecError::UnsupportedVersion(_)
            | CodecError::InvalidTag { .. }
            | CodecError::InvalidUtf8
            | CodecError::TrailingBytes
            | CodecError::HandleCountMismatch { .. } => ZX_ERR_IO_DATA_INTEGRITY,
            CodecError::LengthOverflow => ZX_ERR_NO_MEMORY,
        }
    }

    /// Read and decode one `ComponentStartInfo` message from a bootstrap channel.
    pub fn read_component_start_info(
        bootstrap_channel: zx_handle_t,
    ) -> Result<ComponentStartInfo, zx_status_t> {
        let (bytes, handles) = zx_channel_read_alloc(bootstrap_channel, 0)?;
        ComponentStartInfo::decode_channel_message(&bytes, &handles).map_err(map_codec_error)
    }
}

/// Create a socket pair.
pub fn zx_socket_create(
    options: u32,
    out0: &mut zx_handle_t,
    out1: &mut zx_handle_t,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_SOCKET_CREATE as u64,
        [
            options as u64,
            out0 as *mut zx_handle_t as u64,
            out1 as *mut zx_handle_t as u64,
            0,
            0,
            0,
        ],
    )
}

/// Write bytes into a socket.
pub fn zx_socket_write(
    handle: zx_handle_t,
    options: u32,
    bytes: *const u8,
    len: usize,
    actual: *mut usize,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_SOCKET_WRITE as u64,
        [
            handle,
            options as u64,
            bytes as u64,
            len as u64,
            actual as u64,
            0,
        ],
    )
}

/// Read bytes from a socket.
pub fn zx_socket_read(
    handle: zx_handle_t,
    options: u32,
    bytes: *mut u8,
    len: usize,
    actual: *mut usize,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_SOCKET_READ as u64,
        [
            handle,
            options as u64,
            bytes as u64,
            len as u64,
            actual as u64,
            0,
        ],
    )
}

/// Create a VMO.
pub fn zx_vmo_create(size: u64, options: u32, out: &mut zx_handle_t) -> zx_status_t {
    int80_call(
        AXLE_SYS_VMO_CREATE as u64,
        [
            size,
            options as u64,
            out as *mut zx_handle_t as u64,
            0,
            0,
            0,
        ],
    )
}

/// Read bytes from a VMO.
pub fn zx_vmo_read(handle: zx_handle_t, bytes: &mut [u8], offset: u64) -> zx_status_t {
    int80_call(
        AXLE_SYS_VMO_READ as u64,
        [
            handle,
            if bytes.is_empty() {
                ptr::null_mut::<u8>() as u64
            } else {
                bytes.as_mut_ptr() as u64
            },
            offset,
            bytes.len() as u64,
            0,
            0,
        ],
    )
}

/// Write bytes into a VMO.
pub fn zx_vmo_write(handle: zx_handle_t, bytes: &[u8], offset: u64) -> zx_status_t {
    int80_call(
        AXLE_SYS_VMO_WRITE as u64,
        [
            handle,
            if bytes.is_empty() {
                ptr::null::<u8>() as u64
            } else {
                bytes.as_ptr() as u64
            },
            offset,
            bytes.len() as u64,
            0,
            0,
        ],
    )
}

/// Create a process and its root VMAR.
pub fn zx_process_create(
    parent_process: zx_handle_t,
    options: u32,
    out_process: &mut zx_handle_t,
    out_root_vmar: &mut zx_handle_t,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_PROCESS_CREATE as u64,
        [
            parent_process,
            0,
            0,
            options as u64,
            out_process as *mut zx_handle_t as u64,
            out_root_vmar as *mut zx_handle_t as u64,
        ],
    )
}

/// Create a thread inside an existing process.
pub fn zx_thread_create(
    process: zx_handle_t,
    options: u32,
    out_thread: &mut zx_handle_t,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_THREAD_CREATE as u64,
        [
            process,
            0,
            0,
            options as u64,
            out_thread as *mut zx_handle_t as u64,
            0,
        ],
    )
}

/// Start a process entry thread.
pub fn zx_process_start(
    process: zx_handle_t,
    thread: zx_handle_t,
    entry: u64,
    stack: u64,
    arg_handle: zx_handle_t,
    arg1: u64,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_PROCESS_START as u64,
        [process, thread, entry, stack, arg_handle, arg1],
    )
}

/// Start a non-entry thread.
pub fn zx_thread_start(
    thread: zx_handle_t,
    entry: u64,
    stack: u64,
    arg0: u64,
    arg1: u64,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_THREAD_START as u64,
        [thread, entry, stack, arg0, arg1, 0],
    )
}

/// Prepare a generic child process image.
pub fn ax_process_prepare_start(
    process: zx_handle_t,
    image_vmo: zx_handle_t,
    options: u32,
    out_entry: &mut u64,
    out_stack: &mut u64,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_AX_PROCESS_PREPARE_START as u64,
        [
            process,
            image_vmo,
            options as u64,
            out_entry as *mut u64 as u64,
            out_stack as *mut u64 as u64,
            0,
        ],
    )
}

/// Prepare a Linux-flavored child process image using an opaque exec-spec blob.
pub fn ax_process_prepare_linux_exec(
    process: zx_handle_t,
    image_vmo: zx_handle_t,
    options: u32,
    exec_spec: &[u8],
    out_entry: &mut u64,
    out_stack: &mut u64,
) -> zx_status_t {
    int80_call8(
        AXLE_SYS_AX_PROCESS_PREPARE_LINUX_EXEC as u64,
        [
            process,
            image_vmo,
            options as u64,
            if exec_spec.is_empty() {
                ptr::null::<u8>() as u64
            } else {
                exec_spec.as_ptr() as u64
            },
            exec_spec.len() as u64,
            out_entry as *mut u64 as u64,
            out_stack as *mut u64 as u64,
            0,
        ],
    )
}

/// Create one guest session bound to a thread, sidecar VMO, and supervisor port.
pub fn ax_guest_session_create(
    thread: zx_handle_t,
    sidecar_vmo: zx_handle_t,
    port: zx_handle_t,
    key: u64,
    options: u32,
    out_session: &mut zx_handle_t,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_AX_GUEST_SESSION_CREATE as u64,
        [
            thread,
            sidecar_vmo,
            port,
            key,
            options as u64,
            out_session as *mut zx_handle_t as u64,
        ],
    )
}

/// Resume one stopped guest session after the sidecar state was updated.
pub fn ax_guest_session_resume(session: zx_handle_t, stop_seq: u64, options: u32) -> zx_status_t {
    int80_call(
        AXLE_SYS_AX_GUEST_SESSION_RESUME as u64,
        [session, stop_seq, options as u64, 0, 0, 0],
    )
}

/// Copy guest userspace bytes out of one supervised guest session.
pub fn ax_guest_session_read_memory(
    session: zx_handle_t,
    guest_addr: u64,
    buffer: &mut [u8],
) -> zx_status_t {
    int80_call(
        AXLE_SYS_AX_GUEST_SESSION_READ_MEMORY as u64,
        [
            session,
            guest_addr,
            if buffer.is_empty() {
                ptr::null_mut::<u8>() as u64
            } else {
                buffer.as_mut_ptr() as u64
            },
            buffer.len() as u64,
            0,
            0,
        ],
    )
}

/// Copy kernel-owned bytes into one supervised guest session's userspace memory.
pub fn ax_guest_session_write_memory(
    session: zx_handle_t,
    guest_addr: u64,
    buffer: &[u8],
) -> zx_status_t {
    int80_call(
        AXLE_SYS_AX_GUEST_SESSION_WRITE_MEMORY as u64,
        [
            session,
            guest_addr,
            if buffer.is_empty() {
                ptr::null::<u8>() as u64
            } else {
                buffer.as_ptr() as u64
            },
            buffer.len() as u64,
            0,
            0,
        ],
    )
}

/// Start one newly created process from a full guest x86_64 register snapshot.
pub fn ax_process_start_guest(
    process: zx_handle_t,
    thread: zx_handle_t,
    regs: &ax_guest_x64_regs_t,
    options: u32,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_AX_PROCESS_START_GUEST as u64,
        [
            process,
            thread,
            regs as *const ax_guest_x64_regs_t as u64,
            options as u64,
            0,
            0,
        ],
    )
}

/// Start one newly created thread from a full guest x86_64 register snapshot.
pub fn ax_thread_start_guest(
    thread: zx_handle_t,
    regs: &ax_guest_x64_regs_t,
    options: u32,
) -> zx_status_t {
    int80_call(
        AXLE_SYS_AX_THREAD_START_GUEST as u64,
        [
            thread,
            regs as *const ax_guest_x64_regs_t as u64,
            options as u64,
            0,
            0,
            0,
        ],
    )
}

/// Kill a process or thread carrier.
pub fn zx_task_kill(handle: zx_handle_t) -> zx_status_t {
    int80_call(AXLE_SYS_TASK_KILL as u64, [handle, 0, 0, 0, 0, 0])
}

/// Build one opaque Linux exec-spec blob from the shared fixed header plus
/// caller-provided stack-image bytes.
pub fn ax_linux_exec_spec_blob(
    header: ax_linux_exec_spec_header_t,
    stack_image: &[u8],
) -> Result<Vec<u8>, zx_status_t> {
    let header_bytes = header.encode();
    let total = header_bytes
        .len()
        .checked_add(stack_image.len())
        .ok_or(status::ZX_ERR_OUT_OF_RANGE)?;
    let mut blob = Vec::new();
    blob.try_reserve_exact(total)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    blob.extend_from_slice(&header_bytes);
    blob.extend_from_slice(stack_image);
    Ok(blob)
}

/// Build one v2 Linux exec-spec blob with an appended interpreter image.
pub fn ax_linux_exec_spec_blob_with_interp(
    header: ax_linux_exec_spec_header_t,
    stack_image: &[u8],
    interp: ax_linux_exec_interp_header_t,
    interp_image: &[u8],
) -> Result<Vec<u8>, zx_status_t> {
    let header_bytes = header.encode();
    let interp_header_bytes = interp.encode();
    let total = header_bytes
        .len()
        .checked_add(stack_image.len())
        .and_then(|size| size.checked_add(interp_header_bytes.len()))
        .and_then(|size| size.checked_add(interp_image.len()))
        .ok_or(status::ZX_ERR_OUT_OF_RANGE)?;
    let mut blob = Vec::new();
    blob.try_reserve_exact(total)
        .map_err(|_| ZX_ERR_NO_MEMORY)?;
    blob.extend_from_slice(&header_bytes);
    blob.extend_from_slice(stack_image);
    blob.extend_from_slice(&interp_header_bytes);
    blob.extend_from_slice(interp_image);
    Ok(blob)
}

/// Read one guest stop-state snapshot from a sidecar VMO.
pub fn ax_guest_stop_state_read(
    sidecar_vmo: zx_handle_t,
) -> Result<ax_guest_stop_state_t, zx_status_t> {
    let mut bytes = [0u8; ax_guest_stop_state_t::BYTE_LEN];
    zx_status_result(zx_vmo_read(sidecar_vmo, &mut bytes, 0))?;
    ax_guest_stop_state_t::decode(&bytes).ok_or(ZX_ERR_IO_DATA_INTEGRITY)
}

/// Write one guest stop-state snapshot into a sidecar VMO.
pub fn ax_guest_stop_state_write(
    sidecar_vmo: zx_handle_t,
    stop_state: &ax_guest_stop_state_t,
) -> zx_status_t {
    let bytes = stop_state.encode();
    zx_vmo_write(sidecar_vmo, &bytes, 0)
}
