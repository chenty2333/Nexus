// SPDX-License-Identifier: MPL-2.0

//! Dedicated cross-world persistence boundary.

use super::*;

/// Trusted-anchor capability which explicitly authorizes a cross-world CAS.
///
/// Ordinary [`TrustedAnchorBackend::compare_and_advance`] implementations must
/// continue rejecting binding changes. A platform opts into world rollover
/// only by implementing this separate capability and atomically replacing the
/// exact `expected` snapshot with `replacement`. The replacement Registry must
/// be new and every boot, device, and journal generation must strictly advance.
pub trait WorldRolloverAnchorBackend: TrustedAnchorBackend {
    /// Atomically replaces an exact drained-world tip with a new-world root.
    fn compare_and_rebind_world(
        &mut self,
        expected: TrustedAnchorSnapshot,
        replacement: TrustedAnchorSnapshot,
    ) -> Result<(), Self::Error>;
}

/// Dedicated durability boundary for replacing a fully drained semantic
/// world with an empty checkpoint under a fresh recovery binding.
///
/// Production callers cannot implement this trait directly. Custom storage
/// participates through [`StreamingJournalBackend`] and
/// [`WorldRolloverAnchorBackend`] composed by [`CoordinatedPersistence`].
#[cfg(not(feature = "test-support"))]
pub trait WorldRolloverDurability: super::authority_durability_seal::Sealed {
    /// Persistence failure returned to the rollover coordinator.
    type Error;

    /// Stages the canonical empty checkpoint for the successor world without
    /// changing the trusted anchor.
    fn persist_world_rollover(
        &mut self,
        prepared: &crate::PreparedWorldRollover,
    ) -> Result<(), Self::Error>;

    /// Atomically replaces the exact drained source tip with the staged
    /// successor-world root.
    fn anchor_world_rollover(
        &mut self,
        anchor: crate::WorldRolloverAnchor,
    ) -> Result<(), Self::Error>;
}

/// Development durability boundary for world rollover fixtures.
///
/// This form exists only with the explicit `test-support` feature.
#[cfg(feature = "test-support")]
pub trait WorldRolloverDurability {
    /// Persistence failure returned to the rollover coordinator.
    type Error;

    /// Stages the canonical empty checkpoint for the successor world without
    /// changing the trusted anchor.
    fn persist_world_rollover(
        &mut self,
        prepared: &crate::PreparedWorldRollover,
    ) -> Result<(), Self::Error>;

    /// Atomically replaces the exact drained source tip with the staged
    /// successor-world root.
    fn anchor_world_rollover(
        &mut self,
        anchor: crate::WorldRolloverAnchor,
    ) -> Result<(), Self::Error>;
}

impl<J, A> WorldRolloverDurability for CoordinatedPersistence<J, A>
where
    J: StreamingJournalBackend,
    A: WorldRolloverAnchorBackend,
{
    type Error = CoordinatedPersistenceError<J::Error, A::Error>;

    fn persist_world_rollover(
        &mut self,
        prepared: &crate::PreparedWorldRollover,
    ) -> Result<(), Self::Error> {
        if self.recovery_required {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::RecoveryRequired,
            ));
        }
        let source = prepared.source();
        let plan = prepared.checkpoint_plan();
        if !source.matches(self.committed)
            || self.reserved_recovery.is_some()
            || plan.base_revision() != 0
            || !plan.predecessor().is_zero()
            || plan.revision() != 1
            || plan.binding().profile() != RecoveryProfile::current()
            || plan.catalog_digest() != source.binding().catalog_digest()
            || plan.world() == source.binding().world()
            || plan.freshness().registry() == source.binding().registry()
            || plan.freshness().boot().get() <= source.freshness().boot().get()
            || plan.freshness().device().get() <= source.freshness().device().get()
            || plan.freshness().journal().get() <= source.freshness().journal().get()
        {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::BindingMismatch,
            ));
        }

        self.committed_checkpoint = None;
        self.recovery_required = true;
        self.journal
            .stage_checkpoint(plan)
            .map_err(CoordinatedPersistenceError::Journal)
    }

    fn anchor_world_rollover(
        &mut self,
        anchor: crate::WorldRolloverAnchor,
    ) -> Result<(), Self::Error> {
        if !self.recovery_required {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::RecoveryRequired,
            ));
        }
        let source = anchor.source();
        let target = anchor.target();
        if !source.matches(self.committed)
            || self.reserved_recovery.is_some()
            || target.base_revision() != 0
            || !target.predecessor().is_zero()
            || target.revision() != 1
            || target.binding().profile() != RecoveryProfile::current()
            || target.binding().catalog_digest() != source.binding().catalog_digest()
            || target.binding().world() == source.binding().world()
            || target.binding().registry() == source.binding().registry()
            || target.freshness().registry() != target.binding().registry()
            || target.resulting_freshness() != target.freshness()
            || target.freshness().boot().get() <= source.freshness().boot().get()
            || target.freshness().device().get() <= source.freshness().device().get()
            || target.freshness().journal().get() <= source.freshness().journal().get()
        {
            return Err(CoordinatedPersistenceError::Protocol(
                PersistenceProtocolError::BindingMismatch,
            ));
        }
        let replacement = TrustedAnchorSnapshot::from_trusted_backend(
            target.binding(),
            target.resulting_freshness(),
            target.revision(),
            target.digest(),
            target.resulting_projection(),
        )
        .map_err(CoordinatedPersistenceError::Protocol)?;
        self.anchor
            .compare_and_rebind_world(self.committed, replacement)
            .map_err(CoordinatedPersistenceError::Anchor)?;
        self.committed = replacement;
        self.recovery_required = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::{
        BootGeneration, CatalogSet, CoreLimits, DeviceGeneration, Engine, JournalGeneration,
        RegistryInstance, TxError, WorldId, standard_catalog,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestError {
        Stale,
        Stage,
    }

    #[derive(Debug)]
    struct TestJournal {
        staged: Vec<u8>,
        fail: bool,
    }

    impl StreamingJournalBackend for TestJournal {
        type Error = TestError;

        fn stage_checkpoint(&mut self, plan: &CheckpointRecordPlan) -> Result<(), Self::Error> {
            if self.fail {
                return Err(TestError::Stage);
            }
            self.staged.clear();
            plan.write_to(&mut self.staged)
                .map_err(|never| match never {})?;
            Ok(())
        }
    }

    #[derive(Debug)]
    struct TestAnchor {
        committed: TrustedAnchorSnapshot,
        rebinds: usize,
    }

    impl TrustedAnchorBackend for TestAnchor {
        type Error = TestError;

        fn reserve_recovery_epoch(
            &mut self,
            _binding: RecoveryBinding,
            _observed_device: DeviceGeneration,
        ) -> Result<RecoveryLease, Self::Error> {
            Err(TestError::Stale)
        }

        fn compare_and_advance(
            &mut self,
            _expected: TrustedAnchorSnapshot,
            _replacement: TrustedAnchorSnapshot,
        ) -> Result<(), Self::Error> {
            Err(TestError::Stale)
        }
    }

    impl WorldRolloverAnchorBackend for TestAnchor {
        fn compare_and_rebind_world(
            &mut self,
            expected: TrustedAnchorSnapshot,
            replacement: TrustedAnchorSnapshot,
        ) -> Result<(), Self::Error> {
            if expected != self.committed
                || expected.binding().profile() != replacement.binding().profile()
                || expected.binding().catalog_digest() != replacement.binding().catalog_digest()
                || expected.binding().world() == replacement.binding().world()
                || expected.binding().registry() == replacement.binding().registry()
            {
                return Err(TestError::Stale);
            }
            self.committed = replacement;
            self.rebinds += 1;
            Ok(())
        }
    }

    fn freshness(registry: u64) -> Freshness {
        Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(registry).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(1).unwrap(),
        )
    }

    fn freshness_at(registry: u64, generation: u64) -> Freshness {
        Freshness::new(
            BootGeneration::new(generation).unwrap(),
            RegistryInstance::new(registry).unwrap(),
            DeviceGeneration::new(generation).unwrap(),
            JournalGeneration::new(generation).unwrap(),
        )
    }

    fn fixture(
        fail_stage: bool,
        source_freshness: Freshness,
    ) -> (Engine, CoordinatedPersistence<TestJournal, TestAnchor>) {
        let world = WorldId::new(1).unwrap();
        let catalogs = CatalogSet::new(&[standard_catalog()]).unwrap();
        let engine = Engine::new(
            world,
            catalogs.clone(),
            CoreLimits::bounded_default(),
            source_freshness,
        );
        let binding = RecoveryBinding::new(
            RecoveryProfile::current(),
            world,
            catalogs.digest(),
            source_freshness.registry(),
        )
        .unwrap();
        let committed = TrustedAnchorSnapshot::from_trusted_backend(
            binding,
            source_freshness,
            0,
            Digest::ZERO,
            engine.projection_digest(),
        )
        .unwrap();
        (
            engine,
            CoordinatedPersistence {
                journal: TestJournal {
                    staged: Vec::new(),
                    fail: fail_stage,
                },
                anchor: TestAnchor {
                    committed,
                    rebinds: 0,
                },
                committed,
                reserved_recovery: None,
                committed_checkpoint: None,
                recovery_required: false,
            },
        )
    }

    #[test]
    fn rollover_stages_before_exact_cross_world_anchor_cas() {
        let (engine, mut persistence) = fixture(false, freshness_at(1, 3));
        let old_checkpoint = engine.journal_checkpoint(&[]).unwrap();
        let prepared = engine
            .prepare_world_rollover(WorldId::new(2).unwrap(), freshness_at(2, 4))
            .unwrap();
        let durable = prepared.persist(&mut persistence).unwrap();
        assert!(persistence.recovery_required());
        assert!(!persistence.journal.staged.is_empty());
        assert_eq!(persistence.anchor.rebinds, 0);

        let target = durable.publish(&mut persistence).unwrap();
        assert_eq!(target.world(), WorldId::new(2).unwrap());
        assert_eq!(target.pressure().active_operations, 0);
        assert_eq!(target.pressure().active_composites, 0);
        assert_eq!(persistence.anchor.rebinds, 1);
        assert_eq!(persistence.committed.binding().world(), target.world());
        assert!(!persistence.recovery_required());

        let committed = persistence.committed;
        let next = Freshness::new(
            BootGeneration::new(5).unwrap(),
            committed.binding().registry(),
            committed.committed_freshness().device(),
            JournalGeneration::new(5).unwrap(),
        );
        let recovery_anchor = crate::RecoveryAnchor::from_trusted_provider(
            committed.binding(),
            committed.committed_freshness(),
            next,
            committed.revision(),
            committed.head(),
            committed.projection(),
        )
        .unwrap();
        let recovered = Engine::recover(
            CatalogSet::new(&[standard_catalog()]).unwrap(),
            CoreLimits::bounded_default(),
            recovery_anchor,
            &persistence.journal.staged,
        )
        .unwrap()
        .into_engine();
        assert_eq!(recovered.world(), target.world());
        assert_eq!(recovered.pressure().active_operations, 0);

        let new_anchor = crate::RecoveryAnchor::from_trusted_provider(
            committed.binding(),
            committed.committed_freshness(),
            next,
            committed.revision(),
            committed.head(),
            committed.projection(),
        )
        .unwrap();
        assert!(matches!(
            old_checkpoint.recover(
                CatalogSet::new(&[standard_catalog()]).unwrap(),
                CoreLimits::bounded_default(),
                new_anchor,
            ),
            Err(crate::CoreError::RollbackDetected)
        ));
    }

    #[test]
    fn failed_rollover_stage_latches_without_rebinding_anchor() {
        let (engine, mut persistence) = fixture(true, freshness(1));
        let old = persistence.committed;
        let prepared = engine
            .prepare_world_rollover(WorldId::new(2).unwrap(), freshness_at(2, 2))
            .unwrap();
        assert!(matches!(
            prepared.persist(&mut persistence),
            Err(TxError::Persist(CoordinatedPersistenceError::Journal(
                TestError::Stage
            )))
        ));
        assert!(persistence.recovery_required());
        assert_eq!(persistence.committed, old);
        assert_eq!(persistence.anchor.rebinds, 0);
    }
}
