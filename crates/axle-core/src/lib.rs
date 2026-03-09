#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Axle core contracts (host-testable, kernel-reusable).
//!
//! This crate provides **semantic cores** for key Axle/Zircon primitives:
//!
//! - Handle encoding / decoding (Zircon-style low-bit invariants)
//! - CSpace (per-process handle table) with ABA protection + quarantine
//! - Revocation groups (epoch-based bulk invalidation)
//! - Signals + a minimal wait-one decision helper
//! - Port queue semantics (reservation + pending merge)
//! - Timers (fake clock + deterministic service)
//!
//! Design goals:
//! - **Auditable** (no unsafe, no heavy deps)
//! - **Testable on host** (unit tests / proptest)
//! - **Reusable in-kernel** (`default-features = false`)

extern crate alloc;

pub mod capability;
pub mod cspace;
pub mod handle;
pub mod observer;
pub mod port;
pub mod revocation;
pub mod signals;
pub mod timer;

pub use capability::Capability;
pub use cspace::{CSpace, CSpaceError, TransferredCap};
pub use handle::{Handle, HandleError};
pub use observer::{ObserverPortId, ObserverRegistry, WaitAsyncRegistration};
pub use port::{
    Packet, PacketKind, PacketQueue, Port, PortError, PortKey, PortState, VecPortQueue,
    WaitAsyncOptions, WaitAsyncTimestamp, WaitableId,
};
pub use revocation::{RevocationGroupId, RevocationGroupToken, RevocationManager, RevocationRef};
pub use signals::{Signals, WaitOne, wait_one};
pub use timer::{
    FakeClock, ReactorTimerCore, ReactorTimerEvent, ReactorTimerStats, Time, TimerError, TimerId,
    TimerService, WaitDeadlineId,
};

#[cfg(test)]
extern crate std;

#[cfg(all(test, feature = "loom"))]
mod wait_core_loom;
