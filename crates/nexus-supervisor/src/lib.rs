// SPDX-License-Identifier: MPL-2.0

//! Bounded restart and recovery orchestration for Nexus service domains.
//!
//! The manager is intentionally independent from OSTD and the Registry. A
//! kernel adapter implements [`SupervisorBackend`], while this crate owns the
//! ordering, recovery-attempt budget, deadline, epoch-fenced event validation,
//! bounded replay, and recovery loop. The adapter owns one manager; a child
//! service may report its identity and manager-selected binding epoch, but it
//! never receives backend, rebind, or adoption authority.
//!
//! See the crate README for the exact lifecycle and current evidence boundary.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod backend;
mod manager;
mod types;

pub use backend::SupervisorBackend;
pub use manager::SupervisorManager;
pub use types::*;

#[cfg(test)]
mod tests;
