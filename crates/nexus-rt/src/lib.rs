//! Minimal userspace runtime glue for Nexus.
//!
//! This crate stays intentionally small:
//! - `Reactor` exposes the thin port-backed event decode layer.
//! - `Dispatcher` builds a single-thread executor on top of one port, one
//!   dispatcher timer, a ready queue, and generation-safe registration slabs.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

mod dispatcher;
mod reactor;

pub use dispatcher::{
    AsyncChannelCall, AsyncChannelRecv, AsyncSocketReadiness, ChannelReadResult, Dispatcher,
    DispatcherHandle, OnSignals, RegistrationId, SignalRegistration, Sleep, TaskId,
};
pub use reactor::{Event, Reactor, SignalEvent};
