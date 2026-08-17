#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Independent normalized oracles for the current CSER core.
//!
//! The oracles deliberately share no commands, records, codecs, or transition
//! helpers with `cser-core`. Production tests translate public projections into
//! these smaller state machines and compare the resulting behavior.

extern crate alloc;

pub mod composite_effect_oracle;
pub mod core_rebaseline_oracle;
pub mod provider_lifecycle_oracle;
pub mod recovery_artifact_oracle;

/// Stable identifier of a composite effect in the independent oracle.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EffectId(u64);

impl EffectId {
    /// Constructs an effect identifier for an oracle fixture.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the numeric representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}
