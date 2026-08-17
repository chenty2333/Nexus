// SPDX-License-Identifier: MPL-2.0

use core::fmt;

/// Error returned when a stable identity or generation uses zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    /// Zero is reserved for an absent or invalid identity.
    Zero,
}

macro_rules! nonzero_id {
    ($name:ident, $inner:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name($inner);

        impl $name {
            /// Creates a validated non-zero identity.
            pub const fn new(value: $inner) -> Result<Self, IdentityError> {
                if value == 0 {
                    Err(IdentityError::Zero)
                } else {
                    Ok(Self(value))
                }
            }

            /// Returns the stable numeric representation.
            pub const fn get(self) -> $inner {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }
    };
}

nonzero_id!(
    RegistryInstance,
    u64,
    "Durable identity of one authoritative Registry instance."
);
nonzero_id!(
    BootGeneration,
    u64,
    "Monotonic boot generation supplied by the freshness provider."
);
nonzero_id!(
    JournalGeneration,
    u64,
    "Monotonic journal generation supplied by the persistence provider."
);
nonzero_id!(
    DeviceGeneration,
    u64,
    "Generation of the device ownership and reset domain."
);
nonzero_id!(
    DeviceScopeId,
    u64,
    "Stable identity of one independently reset and quarantined device scope."
);
nonzero_id!(
    VerifierId,
    u32,
    "Stable identity of one configured receipt-verifier class."
);
nonzero_id!(
    ReceiptSchemaId,
    u32,
    "Stable identity of one canonical external receipt schema."
);
nonzero_id!(
    CreditClassId,
    u32,
    "Stable identity of one conserved and independently charged resource class."
);
nonzero_id!(
    ChargeAccountId,
    u64,
    "Stable account charged for retained resource units."
);
nonzero_id!(ClaimId, u64, "Stable identity of one resource claim.");
nonzero_id!(ResourceId, u64, "Stable domain-defined resource identity.");
nonzero_id!(
    ResourceGeneration,
    u64,
    "Monotonic allocation generation of one stable resource identity."
);
nonzero_id!(SnapshotId, u64, "Stable identity of one recovery snapshot.");
nonzero_id!(DomainId, u32, "Stable domain schema identity.");
nonzero_id!(
    CompositeKindId,
    u32,
    "Stable catalog-defined class of one composite effect."
);
nonzero_id!(
    ComponentId,
    u32,
    "Stable catalog-defined component identity within a composite effect."
);
nonzero_id!(
    ObligationKindId,
    u32,
    "Stable domain-defined obligation class identity."
);
nonzero_id!(
    ClaimKindId,
    u32,
    "Stable domain-defined resource-claim class identity."
);
nonzero_id!(
    EvidenceKindId,
    u32,
    "Stable domain-defined retirement-evidence class identity."
);
nonzero_id!(
    WorldId,
    u64,
    "Stable identity of one authoritative semantic world."
);
nonzero_id!(
    ProviderId,
    u64,
    "Stable logical identity of one semantic provider."
);
nonzero_id!(
    ProviderGeneration,
    u64,
    "Monotonic generation of one semantic provider."
);
nonzero_id!(
    ExecutorId,
    u64,
    "Stable logical identity of one effect executor."
);
nonzero_id!(
    ExecutorGeneration,
    u64,
    "Monotonic generation of one effect executor."
);
nonzero_id!(
    OperationId,
    u64,
    "Stable identity of one general causal operation allocated by the embedding."
);
nonzero_id!(
    RecoveryArtifactId,
    u64,
    "Stable identity of one recovery-artifact retention lease."
);
nonzero_id!(
    VerifierGeneration,
    u64,
    "Monotonic generation of one receipt verifier."
);

/// Exact world/provider generation coordinate bound to an effect or receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderCoordinate {
    world: WorldId,
    provider: ProviderId,
    generation: ProviderGeneration,
}

impl ProviderCoordinate {
    /// Creates a provider coordinate from its non-zero identity components.
    pub const fn new(world: WorldId, provider: ProviderId, generation: ProviderGeneration) -> Self {
        Self {
            world,
            provider,
            generation,
        }
    }

    /// Returns the authoritative world identity.
    pub const fn world(self) -> WorldId {
        self.world
    }

    /// Returns the logical provider identity.
    pub const fn provider(self) -> ProviderId {
        self.provider
    }

    /// Returns the provider generation.
    pub const fn generation(self) -> ProviderGeneration {
        self.generation
    }
}

/// Exact executor generation coordinate bound to an effect or observation.
///
/// The executor identity is deliberately separate from the provider
/// coordinate. A provider may be invoked by more than one executor, and an
/// executor generation can be retired independently of the provider it uses.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExecutorCoordinate {
    executor: ExecutorId,
    generation: ExecutorGeneration,
}

impl ExecutorCoordinate {
    /// Creates an executor coordinate from its non-zero identity components.
    pub const fn new(executor: ExecutorId, generation: ExecutorGeneration) -> Self {
        Self {
            executor,
            generation,
        }
    }

    /// Returns the logical executor identity.
    pub const fn executor(self) -> ExecutorId {
        self.executor
    }

    /// Returns the executor generation.
    pub const fn generation(self) -> ExecutorGeneration {
        self.generation
    }
}

/// Stable identity of one effect below a causal operation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EffectId {
    operation: OperationId,
    sequence: u64,
}

impl EffectId {
    /// Creates an effect identity with a non-zero per-operation sequence.
    pub const fn new(operation: OperationId, sequence: u64) -> Result<Self, IdentityError> {
        if sequence == 0 {
            Err(IdentityError::Zero)
        } else {
            Ok(Self {
                operation,
                sequence,
            })
        }
    }

    /// Returns the causal operation.
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the per-operation effect sequence.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// Digest used for journal chains, results, evidence, and schema identities.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct Digest([u8; 32]);

impl Digest {
    /// All-zero digest used only as the predecessor of the first record.
    pub const ZERO: Self = Self([0; 32]);

    /// Creates a digest from exact bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes.
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns whether this is the reserved zero digest.
    pub const fn is_zero(self) -> bool {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Digest({:02x}{:02x}{:02x}{:02x}..)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// Freshness coordinates checked at every authority and evidence boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Freshness {
    boot: BootGeneration,
    registry: RegistryInstance,
    device: DeviceGeneration,
    journal: JournalGeneration,
}

impl Freshness {
    /// Creates a complete freshness vector.
    pub const fn new(
        boot: BootGeneration,
        registry: RegistryInstance,
        device: DeviceGeneration,
        journal: JournalGeneration,
    ) -> Self {
        Self {
            boot,
            registry,
            device,
            journal,
        }
    }

    /// Returns the boot generation.
    pub const fn boot(self) -> BootGeneration {
        self.boot
    }

    /// Returns the Registry instance.
    pub const fn registry(self) -> RegistryInstance {
        self.registry
    }

    /// Returns the current device generation.
    pub const fn device(self) -> DeviceGeneration {
        self.device
    }

    /// Returns the journal generation.
    pub const fn journal(self) -> JournalGeneration {
        self.journal
    }

    pub(crate) fn set_boot_and_journal(
        &mut self,
        boot: BootGeneration,
        journal: JournalGeneration,
    ) {
        self.boot = boot;
        self.journal = journal;
    }

    /// Returns the same freshness envelope with one observed device
    /// generation. Acceptance still requires a configured verifier and the
    /// core's exact evidence challenge.
    pub const fn with_device(self, device: DeviceGeneration) -> Self {
        Self { device, ..self }
    }

    pub(crate) fn set_device(&mut self, device: DeviceGeneration) {
        self.device = device;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExecutorCoordinate, ExecutorGeneration, ExecutorId, IdentityError, OperationId,
        ProviderCoordinate, ProviderGeneration, ProviderId, RecoveryArtifactId, VerifierGeneration,
        WorldId,
    };

    #[test]
    fn next_profile_identities_reject_zero() {
        assert_eq!(WorldId::new(0), Err(IdentityError::Zero));
        assert_eq!(ProviderId::new(0), Err(IdentityError::Zero));
        assert_eq!(ProviderGeneration::new(0), Err(IdentityError::Zero));
        assert_eq!(ExecutorId::new(0), Err(IdentityError::Zero));
        assert_eq!(ExecutorGeneration::new(0), Err(IdentityError::Zero));
        assert_eq!(OperationId::new(0), Err(IdentityError::Zero));
        assert_eq!(RecoveryArtifactId::new(0), Err(IdentityError::Zero));
        assert_eq!(VerifierGeneration::new(0), Err(IdentityError::Zero));
    }

    #[test]
    fn provider_coordinate_exposes_exact_components() {
        let world = WorldId::new(11).unwrap();
        let provider = ProviderId::new(22).unwrap();
        let generation = ProviderGeneration::new(33).unwrap();
        let coordinate = ProviderCoordinate::new(world, provider, generation);

        assert_eq!(coordinate.world(), world);
        assert_eq!(coordinate.provider(), provider);
        assert_eq!(coordinate.generation(), generation);
    }

    #[test]
    fn executor_coordinate_exposes_exact_components() {
        let executor = ExecutorId::new(44).unwrap();
        let generation = ExecutorGeneration::new(55).unwrap();
        let coordinate = ExecutorCoordinate::new(executor, generation);

        assert_eq!(coordinate.executor(), executor);
        assert_eq!(coordinate.generation(), generation);
    }
}
