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
pub mod identity;
pub mod provider_lifecycle_oracle;
pub mod recovery_artifact_oracle;

pub use identity::{
    ArtifactId, ComponentId, EffectId, ExecutorCoordinate, ExecutorGeneration, ExecutorId,
    OperationId, ProviderCoordinate, ProviderGeneration, ProviderId, WorldId,
};
