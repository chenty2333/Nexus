// SPDX-License-Identifier: MPL-2.0

extern crate alloc;

mod peer;
mod wire;

pub use peer::{ProductionEffectPeer, serve};
pub use wire::*;
