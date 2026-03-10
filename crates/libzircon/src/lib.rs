//! Thin userspace Zircon compatibility wrappers for Axle/Nexus.
//!
//! This crate intentionally adds very little policy. It re-exports the shared
//! ABI surface from `axle-types` and maps `zx_*` calls onto the current
//! bootstrap `int 0x80` userspace ABI.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub use axle_types::clock;
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
    zx_clock_t, zx_duration_t, zx_futex_t, zx_handle_t, zx_koid_t, zx_packet_signal_t,
    zx_packet_type_t, zx_packet_user_t, zx_port_packet_t, zx_rights_t, zx_signals_t, zx_status_t,
    zx_time_t, zx_vaddr_t, zx_vm_option_t,
};

use axle_types::clock::ZX_CLOCK_MONOTONIC;
use axle_types::syscall_numbers::{
    AXLE_SYS_CHANNEL_CREATE, AXLE_SYS_CHANNEL_READ, AXLE_SYS_CHANNEL_WRITE, AXLE_SYS_HANDLE_CLOSE,
    AXLE_SYS_OBJECT_WAIT_ASYNC, AXLE_SYS_OBJECT_WAIT_ONE, AXLE_SYS_PORT_CREATE,
    AXLE_SYS_PORT_QUEUE, AXLE_SYS_PORT_WAIT, AXLE_SYS_TIMER_CANCEL, AXLE_SYS_TIMER_CREATE,
    AXLE_SYS_TIMER_SET,
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
    int80_call(AXLE_SYS_HANDLE_CLOSE as u64, [handle as u64, 0, 0, 0, 0, 0])
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
            handle as u64,
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
        [
            handle as u64,
            port as u64,
            key,
            signals as u64,
            options as u64,
            0,
        ],
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
        [
            port as u64,
            packet as *const zx_port_packet_t as u64,
            0,
            0,
            0,
            0,
        ],
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
            port as u64,
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
        [handle as u64, deadline as u64, slack as u64, 0, 0, 0],
    )
}

/// Cancel a timer.
pub fn zx_timer_cancel(handle: zx_handle_t) -> zx_status_t {
    int80_call(AXLE_SYS_TIMER_CANCEL as u64, [handle as u64, 0, 0, 0, 0, 0])
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
            handle as u64,
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
            handle as u64,
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
