//! Canonical typed coordinates used by every independent oracle.
//!
//! These definitions intentionally live in the model crate rather than being
//! copied into each oracle.  The model remains clean-room with respect to
//! `cser-core`, while all of its state machines agree on the same identity
//! grammar: zero is never a valid world, provider, generation, operation,
//! effect sequence, component, artifact, or executor coordinate.

use core::num::{NonZeroU32, NonZeroU64};

/// Stable identity of one authoritative semantic world.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorldId(NonZeroU64);

impl WorldId {
    /// Constructs a non-zero world identity.
    #[must_use]
    pub const fn new(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the stable numeric representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Stable logical identity of one semantic provider.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderId(NonZeroU64);

impl ProviderId {
    /// Constructs a non-zero provider identity.
    #[must_use]
    pub const fn new(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the stable numeric representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Monotonic generation of one semantic provider.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderGeneration(NonZeroU64);

impl ProviderGeneration {
    /// Constructs a non-zero provider generation.
    #[must_use]
    pub const fn new(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the stable numeric representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Exact world/provider/generation coordinate bound to an effect or receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderCoordinate {
    world: WorldId,
    provider: ProviderId,
    generation: ProviderGeneration,
}

impl ProviderCoordinate {
    /// Creates an exact provider coordinate.
    #[must_use]
    pub const fn new(world: WorldId, provider: ProviderId, generation: ProviderGeneration) -> Self {
        Self {
            world,
            provider,
            generation,
        }
    }

    /// Returns the owning world.
    #[must_use]
    pub const fn world(self) -> WorldId {
        self.world
    }

    /// Returns the logical provider identity.
    #[must_use]
    pub const fn provider(self) -> ProviderId {
        self.provider
    }

    /// Returns the provider generation.
    #[must_use]
    pub const fn generation(self) -> ProviderGeneration {
        self.generation
    }
}

/// Stable identity of one causal operation allocated by the embedding.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationId(NonZeroU64);

impl OperationId {
    /// Constructs a non-zero operation identity.
    #[must_use]
    pub const fn new(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the stable numeric representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Stable identity of one effect below a causal operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EffectId {
    operation: OperationId,
    sequence: NonZeroU64,
}

impl EffectId {
    /// Constructs an effect with a non-zero per-operation sequence.
    #[must_use]
    pub const fn new(operation: OperationId, sequence: u64) -> Option<Self> {
        match NonZeroU64::new(sequence) {
            Some(value) => Some(Self {
                operation,
                sequence: value,
            }),
            None => None,
        }
    }

    /// Returns the causal operation.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the per-operation effect sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence.get()
    }
}

/// Stable catalog-defined component identity.
///
/// Components are one-based.  The two named values are the fixed component
/// slots used by the bounded composite oracle; other non-zero values are
/// available to the provider and recovery-artifact profiles.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ComponentId(NonZeroU32);

impl ComponentId {
    /// Reply component in the bounded composite profile.
    #[allow(non_upper_case_globals)]
    pub const Reply: Self = Self(NonZeroU32::new(1).unwrap());

    /// DMA component in the bounded composite profile.
    #[allow(non_upper_case_globals)]
    pub const Dma: Self = Self(NonZeroU32::new(2).unwrap());

    /// Constructs a non-zero component identity.
    #[must_use]
    pub const fn new(raw: u32) -> Option<Self> {
        match NonZeroU32::new(raw) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the stable numeric representation.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Stable identity of one retained recovery-artifact lease.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArtifactId(NonZeroU64);

impl ArtifactId {
    /// Constructs a non-zero artifact identity.
    #[must_use]
    pub const fn new(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the stable numeric representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Stable logical identity of one effect executor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExecutorId(NonZeroU64);

impl ExecutorId {
    /// Constructs a non-zero executor identity.
    #[must_use]
    pub const fn new(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the stable numeric representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Monotonic generation of one effect executor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExecutorGeneration(NonZeroU64);

impl ExecutorGeneration {
    /// Constructs a non-zero executor generation.
    #[must_use]
    pub const fn new(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the stable numeric representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Exact executor identity and generation bound to an authority observation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExecutorCoordinate {
    executor: ExecutorId,
    generation: ExecutorGeneration,
}

impl ExecutorCoordinate {
    /// Constructs an exact executor coordinate.
    #[must_use]
    pub const fn new(executor: ExecutorId, generation: ExecutorGeneration) -> Self {
        Self {
            executor,
            generation,
        }
    }

    /// Returns the logical executor identity.
    #[must_use]
    pub const fn executor(self) -> ExecutorId {
        self.executor
    }

    /// Returns the executor generation.
    #[must_use]
    pub const fn generation(self) -> ExecutorGeneration {
        self.generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_stable_coordinate_rejects_zero() {
        assert!(WorldId::new(0).is_none());
        assert!(ProviderId::new(0).is_none());
        assert!(ProviderGeneration::new(0).is_none());
        assert!(OperationId::new(0).is_none());
        assert!(ComponentId::new(0).is_none());
        assert!(ArtifactId::new(0).is_none());
        assert!(ExecutorId::new(0).is_none());
        assert!(ExecutorGeneration::new(0).is_none());
    }

    #[test]
    fn effect_identity_keeps_operation_and_sequence_typed() {
        let operation = OperationId::new(7).unwrap();
        let effect = EffectId::new(operation, 3).unwrap();
        assert_eq!(effect.operation(), operation);
        assert_eq!(effect.sequence(), 3);
        assert!(EffectId::new(operation, 0).is_none());
    }
}
