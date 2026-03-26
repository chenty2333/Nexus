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
pub use axle_types::dma;
pub use axle_types::guest;
pub use axle_types::handle;
pub use axle_types::interrupt;
pub use axle_types::koid;
pub use axle_types::packet;
pub use axle_types::pci;
pub use axle_types::rights;
pub use axle_types::signals;
pub use axle_types::socket;
pub use axle_types::status;
pub use axle_types::syscall_numbers;
pub use axle_types::vm;
pub use axle_types::vmo;
pub use axle_types::wait_async;
pub use axle_types::{
    ax_clock_t, ax_dma_region_info_t, ax_dma_segment_info_t, ax_duration_t, ax_futex_t,
    ax_guest_stop_state_t, ax_guest_x64_regs_t, ax_handle_t, ax_interrupt_info_t, ax_job_info_t,
    ax_koid_t, ax_linux_exec_interp_header_t, ax_linux_exec_spec_header_t, ax_packet_signal_t,
    ax_packet_type_t, ax_packet_user_t, ax_pci_bar_info_t, ax_pci_config_info_t,
    ax_pci_device_info_t, ax_pci_interrupt_info_t, ax_pci_interrupt_mode_info_t,
    ax_pci_resource_info_t, ax_port_info_t, ax_port_packet_t, ax_revocation_group_info_t,
    ax_rights_t, ax_signals_t, ax_status_t, ax_time_t, ax_vaddr_t, ax_vm_option_t, ax_vmo_info_t,
};

use axle_types::status::{AX_ERR_NO_MEMORY, AX_ERR_OUT_OF_RANGE, AX_OK};

/// Frozen Zircon-compatible facade re-exported behind the native `libax`
/// boundary.
///
/// Native crates should prefer `ax_*` entry points from this crate. This module
/// exists only so legacy `zx_*` call sites can continue compiling while the
/// repository contracts the old compat surface.
pub mod compat {
    pub use libzircon::*;
}

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

/// Write bytes to the bootstrap console.
pub fn ax_console_write(bytes: &[u8], out_actual: &mut usize) -> ax_status_t {
    libzircon::ax_console_write(bytes, out_actual)
}

/// Read bytes from the bootstrap console.
pub fn ax_console_read(buffer: &mut [u8], out_actual: &mut usize) -> ax_status_t {
    libzircon::ax_console_read(buffer, out_actual)
}

/// Query one telemetry snapshot for a port.
pub fn ax_port_get_info(handle: ax_handle_t, out: &mut ax_port_info_t) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_port_get_info(raw, out),
        Err(status) => status,
    }
}

/// Create a revocation-group handle.
pub fn ax_revocation_group_create(options: u32, out: &mut ax_handle_t) -> ax_status_t {
    let mut raw = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::ax_revocation_group_create(options, &mut raw);
    if status == AX_OK {
        *out = widen_handle(raw);
    }
    status
}

/// Query revocation-group metadata.
pub fn ax_revocation_group_get_info(
    handle: ax_handle_t,
    out: &mut ax_revocation_group_info_t,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_revocation_group_get_info(raw, out),
        Err(status) => status,
    }
}

/// Increment one revocation group's epoch.
pub fn ax_revocation_group_revoke(handle: ax_handle_t) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_revocation_group_revoke(raw),
        Err(status) => status,
    }
}

/// Duplicate one handle and bind the duplicate to a revocation group.
pub fn ax_handle_duplicate_revocable(
    handle: ax_handle_t,
    rights: ax_rights_t,
    group: ax_handle_t,
    out: &mut ax_handle_t,
) -> ax_status_t {
    let raw_handle = match narrow_handle(handle) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let raw_group = match narrow_handle(group) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let mut raw_out = libzircon::handle::ZX_HANDLE_INVALID;
    let status =
        libzircon::ax_handle_duplicate_revocable(raw_handle, rights, raw_group, &mut raw_out);
    if status == AX_OK {
        *out = widen_handle(raw_out);
    }
    status
}

/// Return a handle to the job that owns a process.
pub fn ax_process_get_job(process: ax_handle_t, out: &mut ax_handle_t) -> ax_status_t {
    let raw_process = match narrow_handle(process) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let mut raw_out = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::ax_process_get_job(raw_process, &mut raw_out);
    if status == AX_OK {
        *out = widen_handle(raw_out);
    }
    status
}

/// Create a child job.
pub fn ax_job_create(parent_job: ax_handle_t, options: u32, out: &mut ax_handle_t) -> ax_status_t {
    let raw_parent = match narrow_handle(parent_job) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let mut raw_out = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::ax_job_create(raw_parent, options, &mut raw_out);
    if status == AX_OK {
        *out = widen_handle(raw_out);
    }
    status
}

/// Query job metadata.
pub fn ax_job_get_info(handle: ax_handle_t, out: &mut ax_job_info_t) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_job_get_info(raw, out),
        Err(status) => status,
    }
}

/// Reduce the effective handle-rights ceiling for a job subtree.
pub fn ax_job_set_policy(handle: ax_handle_t, rights_ceiling: ax_rights_t) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_job_set_policy(raw, rights_ceiling),
        Err(status) => status,
    }
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

/// Create an eventpair handle pair.
pub fn ax_eventpair_create(
    options: u32,
    out0: &mut ax_handle_t,
    out1: &mut ax_handle_t,
) -> ax_status_t {
    let mut raw0 = libzircon::handle::ZX_HANDLE_INVALID;
    let mut raw1 = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::zx_eventpair_create(options, &mut raw0, &mut raw1);
    if status == AX_OK {
        *out0 = widen_handle(raw0);
        *out1 = widen_handle(raw1);
    }
    status
}

/// Clear and set user-visible signals on one handle.
pub fn ax_object_signal(
    handle: ax_handle_t,
    clear_mask: ax_signals_t,
    set_mask: ax_signals_t,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::zx_object_signal(raw, clear_mask, set_mask),
        Err(status) => status,
    }
}

/// Clear and set user-visible signals on the peer of one handle.
pub fn ax_object_signal_peer(
    handle: ax_handle_t,
    clear_mask: ax_signals_t,
    set_mask: ax_signals_t,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::zx_object_signal_peer(raw, clear_mask, set_mask),
        Err(status) => status,
    }
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

/// Create a virtual interrupt object.
pub fn ax_interrupt_create(options: u32, out: &mut ax_handle_t) -> ax_status_t {
    let mut raw_out = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::zx_interrupt_create(options, &mut raw_out);
    if status == AX_OK {
        *out = widen_handle(raw_out);
    }
    status
}

/// Read one metadata snapshot from an interrupt object.
pub fn ax_interrupt_get_info(
    handle: ax_handle_t,
    out_info: &mut ax_interrupt_info_t,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::zx_interrupt_get_info(raw, out_info),
        Err(status) => status,
    }
}

/// Acknowledge one pending interrupt.
pub fn ax_interrupt_ack(handle: ax_handle_t) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::zx_interrupt_ack(raw),
        Err(status) => status,
    }
}

/// Mask one interrupt object.
pub fn ax_interrupt_mask(handle: ax_handle_t) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::zx_interrupt_mask(raw),
        Err(status) => status,
    }
}

/// Unmask one interrupt object.
pub fn ax_interrupt_unmask(handle: ax_handle_t) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::zx_interrupt_unmask(raw),
        Err(status) => status,
    }
}

/// Software-trigger one virtual interrupt object.
pub fn ax_interrupt_trigger(handle: ax_handle_t, count: u64) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_interrupt_trigger(raw, count),
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
        for (dst, raw) in handles.iter_mut().zip(raw_handles).take(copy_len) {
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

/// Create a physical/MMIO-style VMO over an existing page-aligned span.
///
/// This surface is currently restricted to processes in the root job and
/// returns a DMA-capable handle that explicitly carries pin/layout rights.
pub fn ax_vmo_create_physical(
    base_paddr: u64,
    size: u64,
    options: u32,
    out: &mut ax_handle_t,
) -> ax_status_t {
    let mut raw_out = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::zx_vmo_create_physical(base_paddr, size, options, &mut raw_out);
    if status == AX_OK {
        *out = widen_handle(raw_out);
    }
    status
}

/// Create a contiguous, DMA-capable VMO.
///
/// This surface is currently restricted to processes in the root job and
/// returns a DMA-capable handle that explicitly carries pin/layout rights.
pub fn ax_vmo_create_contiguous(size: u64, options: u32, out: &mut ax_handle_t) -> ax_status_t {
    let mut raw_out = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::zx_vmo_create_contiguous(size, options, &mut raw_out);
    if status == AX_OK {
        *out = widen_handle(raw_out);
    }
    status
}

/// Return the physical address backing one physical/contiguous VMO offset.
///
/// The queried handle must carry `AX_RIGHT_INSPECT_LAYOUT`.
pub fn ax_vmo_lookup_paddr(handle: ax_handle_t, offset: u64, out_paddr: &mut u64) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_vmo_lookup_paddr(raw, offset, out_paddr),
        Err(status) => status,
    }
}

/// Read one narrow public VMO/object-model snapshot.
pub fn ax_vmo_get_info(handle: ax_handle_t, out_info: &mut ax_vmo_info_t) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_vmo_get_info(raw, out_info),
        Err(status) => status,
    }
}

/// Create one object-level private clone from a shared COW-capable source VMO.
pub fn ax_vmo_create_private_clone(handle: ax_handle_t, out: &mut ax_handle_t) -> ax_status_t {
    let raw = match narrow_handle(handle) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let mut raw_out = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::ax_vmo_create_private_clone(raw, &mut raw_out);
    if status == AX_OK {
        *out = widen_handle(raw_out);
    }
    status
}

/// Promote one local-private VMO object to the shared/global backing domain.
pub fn ax_vmo_promote_shared(handle: ax_handle_t) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_vmo_promote_shared(raw),
        Err(status) => status,
    }
}

/// Clone all child-visible source mappings from one VMAR into another.
pub fn ax_vmar_clone_mappings(src_vmar: ax_handle_t, dst_vmar: ax_handle_t) -> ax_status_t {
    let src_raw = match narrow_handle(src_vmar) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let dst_raw = match narrow_handle(dst_vmar) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    libzircon::ax_vmar_clone_mappings(src_raw, dst_raw)
}

/// Reify the current backing VMO of one mapping inside a VMAR.
pub fn ax_vmar_get_mapping_vmo(
    vmar: ax_handle_t,
    addr: u64,
    out_vmo: &mut ax_handle_t,
) -> ax_status_t {
    let raw = match narrow_handle(vmar) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    libzircon::ax_vmar_get_mapping_vmo(raw, addr, out_vmo)
}

/// Pin one physical/contiguous VMO range and return a DMA region handle.
///
/// The queried handle must carry `AX_RIGHT_PIN`.
pub fn ax_vmo_pin(
    handle: ax_handle_t,
    offset: u64,
    len: u64,
    options: u32,
    out: &mut ax_handle_t,
) -> ax_status_t {
    let raw = match narrow_handle(handle) {
        Ok(raw) => raw,
        Err(status) => return status,
    };
    let mut raw_out = libzircon::handle::ZX_HANDLE_INVALID;
    let status = libzircon::ax_vmo_pin(raw, offset, len, options, &mut raw_out);
    if status == AX_OK {
        *out = widen_handle(raw_out);
    }
    status
}

/// Return the physical address backing one offset inside a pinned DMA region.
///
/// The queried handle must carry `AX_RIGHT_INSPECT_LAYOUT`.
pub fn ax_dma_region_lookup_paddr(
    handle: ax_handle_t,
    offset: u64,
    out_paddr: &mut u64,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_dma_region_lookup_paddr(raw, offset, out_paddr),
        Err(status) => status,
    }
}

/// Return the device-visible IOVA backing one offset inside a pinned DMA region.
///
/// The queried handle must carry `AX_RIGHT_INSPECT_LAYOUT`.
pub fn ax_dma_region_lookup_iova(
    handle: ax_handle_t,
    offset: u64,
    out_iova: &mut u64,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_dma_region_lookup_iova(raw, offset, out_iova),
        Err(status) => status,
    }
}

/// Read one metadata snapshot from a DMA-region object.
///
/// The queried handle must carry `AX_RIGHT_INSPECT_LAYOUT`.
pub fn ax_dma_region_get_info(
    handle: ax_handle_t,
    out_info: &mut ax_dma_region_info_t,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_dma_region_get_info(raw, out_info),
        Err(status) => status,
    }
}

/// Read one segment metadata snapshot from a DMA-region object.
///
/// The queried handle must carry `AX_RIGHT_INSPECT_LAYOUT`.
pub fn ax_dma_region_get_segment(
    handle: ax_handle_t,
    segment_index: u32,
    out_info: &mut ax_dma_segment_info_t,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_dma_region_get_segment(raw, segment_index, out_info),
        Err(status) => status,
    }
}

/// Read one narrow PCI/device info snapshot from a device handle.
pub fn ax_pci_device_get_info(
    handle: ax_handle_t,
    out_info: &mut ax_pci_device_info_t,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_pci_device_get_info(raw, out_info),
        Err(status) => status,
    }
}

/// Export one PCI config-space window from a device handle.
pub fn ax_pci_device_get_config(
    handle: ax_handle_t,
    out_info: &mut ax_pci_config_info_t,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => {
            let mut raw_info = libzircon::pci::zx_pci_config_info_t::default();
            let status = libzircon::ax_pci_device_get_config(raw, &mut raw_info);
            if status == AX_OK {
                out_info.handle = widen_handle(raw_info.handle);
                out_info.size = raw_info.size;
                out_info.flags = raw_info.flags;
                out_info.map_options = raw_info.map_options;
            }
            status
        }
        Err(status) => status,
    }
}

/// Export one BAR resource from a PCI/device handle.
pub fn ax_pci_device_get_bar(
    handle: ax_handle_t,
    bar_index: u32,
    out_bar: &mut ax_pci_bar_info_t,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => {
            let mut raw_bar = libzircon::pci::zx_pci_bar_info_t::default();
            let status = libzircon::ax_pci_device_get_bar(raw, bar_index, &mut raw_bar);
            if status == AX_OK {
                out_bar.handle = widen_handle(raw_bar.handle);
                out_bar.size = raw_bar.size;
                out_bar.flags = raw_bar.flags;
                out_bar.map_options = raw_bar.map_options;
            }
            status
        }
        Err(status) => status,
    }
}

/// Export one interrupt resource from a PCI/device handle.
pub fn ax_pci_device_get_interrupt(
    handle: ax_handle_t,
    group: u32,
    queue_pair: u32,
    out_interrupt: &mut ax_pci_interrupt_info_t,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => {
            let mut raw_interrupt = libzircon::pci::zx_pci_interrupt_info_t::default();
            let status =
                libzircon::ax_pci_device_get_interrupt(raw, group, queue_pair, &mut raw_interrupt);
            if status == AX_OK {
                out_interrupt.handle = widen_handle(raw_interrupt.handle);
                out_interrupt.mode = raw_interrupt.mode;
                out_interrupt.vector = raw_interrupt.vector;
            }
            status
        }
        Err(status) => status,
    }
}

/// Query one interrupt delivery mode exported by a PCI/device handle.
pub fn ax_pci_device_get_interrupt_mode(
    handle: ax_handle_t,
    mode: u32,
    out_info: &mut ax_pci_interrupt_mode_info_t,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_pci_device_get_interrupt_mode(raw, mode, out_info),
        Err(status) => status,
    }
}

/// Query the number of generic resource exports from a PCI/device handle.
pub fn ax_pci_device_get_resource_count(handle: ax_handle_t, out_count: &mut u64) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_pci_device_get_resource_count(raw, out_count),
        Err(status) => status,
    }
}

/// Export one generic resource from a PCI/device handle.
pub fn ax_pci_device_get_resource(
    handle: ax_handle_t,
    resource_index: u32,
    out_info: &mut ax_pci_resource_info_t,
) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => {
            let mut raw_info = libzircon::pci::zx_pci_resource_info_t::default();
            let status = libzircon::ax_pci_device_get_resource(raw, resource_index, &mut raw_info);
            if status == AX_OK {
                out_info.handle = widen_handle(raw_info.handle);
                out_info.kind = raw_info.kind;
                out_info.index = raw_info.index;
                out_info.subindex = raw_info.subindex;
                out_info.flags = raw_info.flags;
                out_info.map_options = raw_info.map_options;
                out_info.size = raw_info.size;
                out_info.mode = raw_info.mode;
                out_info.vector = raw_info.vector;
                out_info.reserved0 = raw_info.reserved0;
            }
            status
        }
        Err(status) => status,
    }
}

/// Select one interrupt delivery mode for a PCI/device handle.
pub fn ax_pci_device_set_interrupt_mode(handle: ax_handle_t, mode: u32) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_pci_device_set_interrupt_mode(raw, mode),
        Err(status) => status,
    }
}

/// Update the live PCI command register for a PCI/device handle.
pub fn ax_pci_device_set_command(handle: ax_handle_t, command: u16) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::ax_pci_device_set_command(raw, command),
        Err(status) => status,
    }
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

/// Resize one VMO.
pub fn ax_vmo_set_size(handle: ax_handle_t, size: u64) -> ax_status_t {
    match narrow_handle(handle) {
        Ok(raw) => libzircon::zx_vmo_set_size(raw, size),
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

/// Set the guest x86_64 FS base for one thread carrier.
pub fn ax_thread_set_guest_x64_fs_base(
    thread: ax_handle_t,
    fs_base: u64,
    options: u32,
) -> ax_status_t {
    match narrow_handle(thread) {
        Ok(raw) => libzircon::ax_thread_set_guest_x64_fs_base(raw, fs_base, options),
        Err(status) => status,
    }
}

/// Read the guest x86_64 FS base for one thread carrier.
pub fn ax_thread_get_guest_x64_fs_base(
    thread: ax_handle_t,
    options: u32,
    out_fs_base: &mut u64,
) -> ax_status_t {
    match narrow_handle(thread) {
        Ok(raw) => libzircon::ax_thread_get_guest_x64_fs_base(raw, options, out_fs_base),
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

/// Build one v2 Linux exec-spec blob with an appended interpreter image.
pub fn ax_linux_exec_spec_blob_with_interp(
    header: ax_linux_exec_spec_header_t,
    stack_image: &[u8],
    interp: ax_linux_exec_interp_header_t,
    interp_image: &[u8],
) -> Result<Vec<u8>, ax_status_t> {
    libzircon::ax_linux_exec_spec_blob_with_interp(header, stack_image, interp, interp_image)
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
