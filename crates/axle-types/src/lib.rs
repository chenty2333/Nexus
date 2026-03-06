//! Zircon-compatible public types and constants for Axle/Nexus.
//!
//! This crate is intentionally tiny and `no_std` so it can be shared by:
//! - kernel (`no_std`)
//! - userspace runtime (`no_std`)
//! - host-side conformance tests (`std` via consumers)
//!
//! The numeric values are aligned with Zircon's public headers.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![allow(non_camel_case_types)]

/// Zircon handle type (u32).
pub type zx_handle_t = u32;
/// Zircon status/error type (i32).
pub type zx_status_t = i32;
/// Zircon signals type (u32 bitmask).
pub type zx_signals_t = u32;
/// Zircon rights bitmask type.
pub type zx_rights_t = u32;
/// Zircon kernel object id type.
pub type zx_koid_t = u64;
/// Zircon futex word type.
pub type zx_futex_t = i32;
/// Zircon absolute time / deadline type (monotonic nanoseconds).
pub type zx_time_t = i64;
/// Zircon duration / interval type (nanoseconds).
pub type zx_duration_t = i64;
/// Zircon clock id type.
pub type zx_clock_t = u32;
/// Zircon packet type id.
pub type zx_packet_type_t = u32;
/// Zircon VM option bitmask type.
pub type zx_vm_option_t = u32;
/// Zircon virtual address type.
pub type zx_vaddr_t = u64;

/// Zircon user packet payload (32 bytes).
///
/// We use a 4x u64 layout to keep the payload naturally 8-byte aligned
/// while preserving the exact 32-byte payload size.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct zx_packet_user_t {
    /// User-controlled payload words.
    pub u64: [u64; 4],
}

/// Zircon signal packet payload (32 bytes).
///
/// This corresponds to `zx_packet_signal_t` (used with `ZX_PKT_TYPE_SIGNAL_ONE`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct zx_packet_signal_t {
    /// Watched signal mask that triggered the packet.
    pub trigger: zx_signals_t,
    /// Observed signals at the time of delivery.
    pub observed: zx_signals_t,
    /// Delivery count (merged on overflow in some port implementations).
    pub count: u64,
    /// Monotonic timestamp (when requested via wait-async options).
    pub timestamp: zx_time_t,
    /// Reserved.
    pub reserved1: u64,
}

impl zx_packet_signal_t {
    /// Encode into the raw 32-byte union payload shape (`zx_packet_user_t` view).
    ///
    /// This avoids Rust unions in the public ABI while preserving layout
    /// compatibility with Zircon's `zx_port_packet_t` union.
    pub const fn to_user(self) -> zx_packet_user_t {
        let first = (self.trigger as u64) | ((self.observed as u64) << 32);
        zx_packet_user_t {
            u64: [first, self.count, self.timestamp as u64, self.reserved1],
        }
    }

    /// Decode from the raw 32-byte union payload shape (`zx_packet_user_t` view).
    pub const fn from_user(user: zx_packet_user_t) -> Self {
        let first = user.u64[0];
        Self {
            trigger: first as zx_signals_t,
            observed: (first >> 32) as zx_signals_t,
            count: user.u64[1],
            timestamp: user.u64[2] as zx_time_t,
            reserved1: user.u64[3],
        }
    }
}

/// Zircon port packet (minimal Phase-B ABI shape).
///
/// For bootstrap we model the user-packet path used by `zx_port_queue` and
/// `zx_port_wait`. Additional packet variants can be added later without
/// changing this baseline layout: the `user` payload is the 32-byte union area
/// used by Zircon (user packets, signal packets, etc).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct zx_port_packet_t {
    /// User-defined key.
    pub key: u64,
    /// Packet type (for now `ZX_PKT_TYPE_USER`).
    pub type_: zx_packet_type_t,
    /// Status associated with the packet.
    pub status: zx_status_t,
    /// User payload.
    pub user: zx_packet_user_t,
}

const _: [(); 32] = [(); core::mem::size_of::<zx_packet_user_t>()];
const _: [(); 32] = [(); core::mem::size_of::<zx_packet_signal_t>()];
const _: [(); 48] = [(); core::mem::size_of::<zx_port_packet_t>()];
const _: [(); 8] = [(); core::mem::align_of::<zx_port_packet_t>()];

/// Clock ids.
pub mod clock {
    use super::zx_clock_t;

    /// Monotonic clock.
    pub const ZX_CLOCK_MONOTONIC: zx_clock_t = 0;
    /// UTC clock.
    pub const ZX_CLOCK_UTC: zx_clock_t = 1;
    /// Thread clock.
    pub const ZX_CLOCK_THREAD: zx_clock_t = 2;
}

/// Port packet type ids.
pub mod packet {
    use super::zx_packet_type_t;

    /// User-defined packet (`zx_port_queue`).
    pub const ZX_PKT_TYPE_USER: zx_packet_type_t = 0;
    /// Signal packet delivered by `zx_object_wait_async`.
    pub const ZX_PKT_TYPE_SIGNAL_ONE: zx_packet_type_t = 1;
}

/// Options for `zx_object_wait_async`.
///
/// Values follow Zircon's `zircon/syscalls/port.h`.
pub mod wait_async {
    /// One-shot (default).
    pub const ZX_WAIT_ASYNC_ONCE: u32 = 0;
    /// Request monotonic timestamp in packets.
    pub const ZX_WAIT_ASYNC_TIMESTAMP: u32 = 1;
    /// Edge-triggered: only fire on transition from not-satisfied to satisfied.
    pub const ZX_WAIT_ASYNC_EDGE: u32 = 2;
    /// Request boot timestamp in packets.
    ///
    /// In current bring-up Axle exposes the same underlying monotonic timeline
    /// for both monotonic and boot timestamps because suspend/resume time
    /// accounting has not been introduced yet.
    pub const ZX_WAIT_ASYNC_BOOT_TIMESTAMP: u32 = 4;
}

/// VM mapping and protection options.
///
/// Values follow Zircon's public VM option bits.
pub mod vm {
    use super::zx_vm_option_t;

    /// Mapping/protection grants read access.
    pub const ZX_VM_PERM_READ: zx_vm_option_t = 1 << 0;
    /// Mapping/protection grants write access.
    pub const ZX_VM_PERM_WRITE: zx_vm_option_t = 1 << 1;
    /// Mapping/protection grants execute access.
    pub const ZX_VM_PERM_EXECUTE: zx_vm_option_t = 1 << 2;
    /// Map at an exact address (`vmar_offset` must be honored exactly).
    pub const ZX_VM_SPECIFIC: zx_vm_option_t = 1 << 10;
}

/// Zircon handle rights bit definitions.
pub mod rights {
    use super::zx_rights_t;

    /// Duplicate the handle.
    pub const ZX_RIGHT_DUPLICATE: zx_rights_t = 1u32 << 0;
    /// Transfer the handle to another process.
    pub const ZX_RIGHT_TRANSFER: zx_rights_t = 1u32 << 1;
    /// Read from the object.
    pub const ZX_RIGHT_READ: zx_rights_t = 1u32 << 2;
    /// Write to the object.
    pub const ZX_RIGHT_WRITE: zx_rights_t = 1u32 << 3;
    /// Execute from the object.
    pub const ZX_RIGHT_EXECUTE: zx_rights_t = 1u32 << 4;
    /// Map the object into a VMAR.
    pub const ZX_RIGHT_MAP: zx_rights_t = 1u32 << 5;
    /// Read object properties.
    pub const ZX_RIGHT_GET_PROPERTY: zx_rights_t = 1u32 << 6;
    /// Set object properties.
    pub const ZX_RIGHT_SET_PROPERTY: zx_rights_t = 1u32 << 7;
    /// Enumerate children or related objects.
    pub const ZX_RIGHT_ENUMERATE: zx_rights_t = 1u32 << 8;
    /// Destroy the object.
    pub const ZX_RIGHT_DESTROY: zx_rights_t = 1u32 << 9;
    /// Set policy on the object.
    pub const ZX_RIGHT_SET_POLICY: zx_rights_t = 1u32 << 10;
    /// Get policy from the object.
    pub const ZX_RIGHT_GET_POLICY: zx_rights_t = 1u32 << 11;
    /// Set user signals on the object itself.
    pub const ZX_RIGHT_SIGNAL: zx_rights_t = 1u32 << 12;
    /// Set signals on the peer of a peered object.
    pub const ZX_RIGHT_SIGNAL_PEER: zx_rights_t = 1u32 << 13;
    /// Wait on the object.
    pub const ZX_RIGHT_WAIT: zx_rights_t = 1u32 << 14;
    /// Inspect the object.
    pub const ZX_RIGHT_INSPECT: zx_rights_t = 1u32 << 15;
    /// Manage a job.
    pub const ZX_RIGHT_MANAGE_JOB: zx_rights_t = 1u32 << 16;
    /// Manage a process.
    pub const ZX_RIGHT_MANAGE_PROCESS: zx_rights_t = 1u32 << 17;
    /// Manage a thread.
    pub const ZX_RIGHT_MANAGE_THREAD: zx_rights_t = 1u32 << 18;
    /// Apply a profile.
    pub const ZX_RIGHT_APPLY_PROFILE: zx_rights_t = 1u32 << 19;

    /// Basic transferable/duplicable/waitable rights.
    pub const ZX_RIGHTS_BASIC: zx_rights_t =
        ZX_RIGHT_TRANSFER | ZX_RIGHT_DUPLICATE | ZX_RIGHT_WAIT | ZX_RIGHT_INSPECT;
    /// Read/write I/O rights.
    pub const ZX_RIGHTS_IO: zx_rights_t = ZX_RIGHT_READ | ZX_RIGHT_WRITE;
    /// Keep the same rights as the source handle when duplicating/replacing.
    pub const ZX_RIGHT_SAME_RIGHTS: zx_rights_t = u32::MAX;
    /// Mask of all currently defined right bits.
    pub const ZX_RIGHTS_ALL: zx_rights_t = ZX_RIGHT_DUPLICATE
        | ZX_RIGHT_TRANSFER
        | ZX_RIGHT_READ
        | ZX_RIGHT_WRITE
        | ZX_RIGHT_EXECUTE
        | ZX_RIGHT_MAP
        | ZX_RIGHT_GET_PROPERTY
        | ZX_RIGHT_SET_PROPERTY
        | ZX_RIGHT_ENUMERATE
        | ZX_RIGHT_DESTROY
        | ZX_RIGHT_SET_POLICY
        | ZX_RIGHT_GET_POLICY
        | ZX_RIGHT_SIGNAL
        | ZX_RIGHT_SIGNAL_PEER
        | ZX_RIGHT_WAIT
        | ZX_RIGHT_INSPECT
        | ZX_RIGHT_MANAGE_JOB
        | ZX_RIGHT_MANAGE_PROCESS
        | ZX_RIGHT_MANAGE_THREAD
        | ZX_RIGHT_APPLY_PROFILE;
}

/// Generated syscall numbers (ABI).
///
/// Single source of truth:
/// - `syscalls/spec/syscalls.toml`
/// - generated by `tools/syscalls-gen` into `syscalls/generated`
#[allow(missing_docs)]
#[path = "../../../syscalls/generated/syscall_numbers.rs"]
pub mod syscall_numbers;

/// Handle constants.
pub mod handle {
    use super::zx_handle_t;

    /// Invalid handle value.
    pub const ZX_HANDLE_INVALID: zx_handle_t = 0;

    /// Mask for the two low “fixed bits” of a Zircon handle.
    ///
    /// Zircon guarantees the low 2 bits of a valid handle are always 1, so
    /// applications may use those bits for tagging as long as they restore them
    /// before calling into the kernel.
    pub const ZX_HANDLE_FIXED_BITS_MASK: zx_handle_t = 0x3;
    /// The required value of the low 2 “fixed bits” for a valid handle.
    pub const ZX_HANDLE_FIXED_BITS_VALUE: zx_handle_t = 0x3;
}

/// Kernel object id constants.
pub mod koid {
    use super::zx_koid_t;

    /// Invalid kernel object id.
    pub const ZX_KOID_INVALID: zx_koid_t = 0;
}

/// Status / error codes.
///
/// Values follow Zircon's `zircon/errors.h`.
pub mod status {
    use super::zx_status_t;

    /// Operation successful.
    pub const ZX_OK: zx_status_t = 0;

    /// Internal error.
    pub const ZX_ERR_INTERNAL: zx_status_t = -1;
    /// Not supported.
    pub const ZX_ERR_NOT_SUPPORTED: zx_status_t = -2;
    /// No resources.
    pub const ZX_ERR_NO_RESOURCES: zx_status_t = -3;
    /// No memory.
    pub const ZX_ERR_NO_MEMORY: zx_status_t = -4;

    /// Invalid argument(s).
    pub const ZX_ERR_INVALID_ARGS: zx_status_t = -10;
    /// Bad handle.
    pub const ZX_ERR_BAD_HANDLE: zx_status_t = -11;
    /// Wrong object type.
    pub const ZX_ERR_WRONG_TYPE: zx_status_t = -12;
    /// Bad syscall number.
    pub const ZX_ERR_BAD_SYSCALL: zx_status_t = -13;
    /// Out of range.
    pub const ZX_ERR_OUT_OF_RANGE: zx_status_t = -14;
    /// Buffer too small.
    pub const ZX_ERR_BUFFER_TOO_SMALL: zx_status_t = -15;

    /// Bad state.
    pub const ZX_ERR_BAD_STATE: zx_status_t = -20;
    /// Timed out.
    pub const ZX_ERR_TIMED_OUT: zx_status_t = -21;
    /// Should wait (would block).
    pub const ZX_ERR_SHOULD_WAIT: zx_status_t = -22;
    /// Canceled.
    pub const ZX_ERR_CANCELED: zx_status_t = -23;
    /// Peer closed.
    pub const ZX_ERR_PEER_CLOSED: zx_status_t = -24;
    /// Not found.
    pub const ZX_ERR_NOT_FOUND: zx_status_t = -25;
    /// Already exists.
    pub const ZX_ERR_ALREADY_EXISTS: zx_status_t = -26;
    /// Already bound.
    pub const ZX_ERR_ALREADY_BOUND: zx_status_t = -27;
    /// Unavailable.
    pub const ZX_ERR_UNAVAILABLE: zx_status_t = -28;
    /// Access denied.
    pub const ZX_ERR_ACCESS_DENIED: zx_status_t = -30;

    /// I/O error.
    pub const ZX_ERR_IO: zx_status_t = -40;
    /// Device or peer refused the operation.
    pub const ZX_ERR_IO_REFUSED: zx_status_t = -41;
    /// Data integrity / checksum failure.
    pub const ZX_ERR_IO_DATA_INTEGRITY: zx_status_t = -42;
    /// Data loss.
    pub const ZX_ERR_IO_DATA_LOSS: zx_status_t = -43;
    /// Device not present.
    pub const ZX_ERR_IO_NOT_PRESENT: zx_status_t = -44;
    /// I/O overrun.
    pub const ZX_ERR_IO_OVERRUN: zx_status_t = -45;
    /// Missed I/O deadline.
    pub const ZX_ERR_IO_MISSED_DEADLINE: zx_status_t = -46;
    /// Invalid I/O request or payload.
    pub const ZX_ERR_IO_INVALID: zx_status_t = -47;

    /// Bad or malformed path.
    pub const ZX_ERR_BAD_PATH: zx_status_t = -50;
    /// Not a directory.
    pub const ZX_ERR_NOT_DIR: zx_status_t = -51;
    /// Not a regular file.
    pub const ZX_ERR_NOT_FILE: zx_status_t = -52;
    /// File too large.
    pub const ZX_ERR_FILE_BIG: zx_status_t = -53;
    /// No space left.
    pub const ZX_ERR_NO_SPACE: zx_status_t = -54;
    /// Directory not empty.
    pub const ZX_ERR_NOT_EMPTY: zx_status_t = -55;

    /// Protocol not supported.
    pub const ZX_ERR_PROTOCOL_NOT_SUPPORTED: zx_status_t = -70;
    /// Address unreachable.
    pub const ZX_ERR_ADDRESS_UNREACHABLE: zx_status_t = -71;
    /// Address already in use.
    pub const ZX_ERR_ADDRESS_IN_USE: zx_status_t = -72;
    /// Not connected.
    pub const ZX_ERR_NOT_CONNECTED: zx_status_t = -73;
    /// Connection refused.
    pub const ZX_ERR_CONNECTION_REFUSED: zx_status_t = -74;
    /// Connection reset.
    pub const ZX_ERR_CONNECTION_RESET: zx_status_t = -75;
    /// Connection aborted.
    pub const ZX_ERR_CONNECTION_ABORTED: zx_status_t = -76;
}

/// Signals bitmask constants.
///
/// Values follow Zircon's `zircon/types.h`.
pub mod signals {
    use super::zx_signals_t;

    /// No signals.
    pub const ZX_SIGNAL_NONE: zx_signals_t = 0;

    // Common object signals (implementation details in Zircon header, but stable in practice).
    /// Readable.
    pub const ZX_OBJECT_READABLE: zx_signals_t = 1u32 << 0;
    /// Writable.
    pub const ZX_OBJECT_WRITABLE: zx_signals_t = 1u32 << 1;
    /// Peer closed.
    pub const ZX_OBJECT_PEER_CLOSED: zx_signals_t = 1u32 << 2;
    /// Signaled.
    pub const ZX_OBJECT_SIGNALED: zx_signals_t = 1u32 << 3;

    /// Handle closed (cancellation).
    pub const ZX_SIGNAL_HANDLE_CLOSED: zx_signals_t = 1u32 << 23;

    /// User signals mask (bits 24..31).
    pub const ZX_USER_SIGNAL_ALL: zx_signals_t = 0xff00_0000;

    /// User signal 0.
    pub const ZX_USER_SIGNAL_0: zx_signals_t = 1u32 << 24;
    /// User signal 1.
    pub const ZX_USER_SIGNAL_1: zx_signals_t = 1u32 << 25;
    /// User signal 2.
    pub const ZX_USER_SIGNAL_2: zx_signals_t = 1u32 << 26;
    /// User signal 3.
    pub const ZX_USER_SIGNAL_3: zx_signals_t = 1u32 << 27;
    /// User signal 4.
    pub const ZX_USER_SIGNAL_4: zx_signals_t = 1u32 << 28;
    /// User signal 5.
    pub const ZX_USER_SIGNAL_5: zx_signals_t = 1u32 << 29;
    /// User signal 6.
    pub const ZX_USER_SIGNAL_6: zx_signals_t = 1u32 << 30;
    /// User signal 7.
    pub const ZX_USER_SIGNAL_7: zx_signals_t = 1u32 << 31;

    // Aliases (object-specific names).
    /// Channel readable.
    pub const ZX_CHANNEL_READABLE: zx_signals_t = ZX_OBJECT_READABLE;
    /// Channel writable.
    pub const ZX_CHANNEL_WRITABLE: zx_signals_t = ZX_OBJECT_WRITABLE;
    /// Channel peer closed.
    pub const ZX_CHANNEL_PEER_CLOSED: zx_signals_t = ZX_OBJECT_PEER_CLOSED;

    /// Timer signaled.
    pub const ZX_TIMER_SIGNALED: zx_signals_t = ZX_OBJECT_SIGNALED;
}
