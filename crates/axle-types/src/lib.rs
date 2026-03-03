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
#![allow(non_camel_case_types)]

/// Zircon handle type (u32).
pub type zx_handle_t = u32;
/// Zircon status/error type (i32).
pub type zx_status_t = i32;
/// Zircon signals type (u32 bitmask).
pub type zx_signals_t = u32;

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
