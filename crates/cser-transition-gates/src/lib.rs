// SPDX-License-Identifier: MPL-2.0

//! Dependency-free transition gates shared by the production OSTD adapters,
//! the mediated VirtIO experiment, and bounded host-side concurrency tests.
//!
//! The gates own only semantic phase, generational identity, and one-shot
//! winner state. Tasks, frames, wakers, page tables, queues, and DMA owners
//! remain payloads of their respective production adapters.

#![no_std]
#![forbid(unsafe_code)]

pub mod deadline;
pub mod io;
pub mod oneshot;
pub mod pager;
pub mod scheduler;
