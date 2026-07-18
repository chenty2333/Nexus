// SPDX-License-Identifier: MPL-2.0

extern crate alloc;

mod peer;

pub use nexus_effect_peer_wire::*;
pub use peer::{ProductionEffectPeer, serve};
