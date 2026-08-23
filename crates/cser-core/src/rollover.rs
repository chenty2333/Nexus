// SPDX-License-Identifier: MPL-2.0

//! Authenticated replacement of a fully drained semantic world.

use super::*;

/// Exact trusted tip which must still authorize the drained source world.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldRolloverSource {
    binding: RecoveryBinding,
    freshness: Freshness,
    revision: u64,
    head: Digest,
    projection: Digest,
}

impl WorldRolloverSource {
    /// Returns the source recovery binding.
    pub const fn binding(self) -> RecoveryBinding {
        self.binding
    }

    /// Returns the source freshness vector.
    pub const fn freshness(self) -> Freshness {
        self.freshness
    }

    /// Returns the source journal revision.
    pub const fn revision(self) -> u64 {
        self.revision
    }

    /// Returns the source journal head.
    pub const fn head(self) -> Digest {
        self.head
    }

    /// Returns the source authenticated projection.
    pub const fn projection(self) -> Digest {
        self.projection
    }

    pub(crate) fn matches(self, snapshot: crate::TrustedAnchorSnapshot) -> bool {
        snapshot.binding() == self.binding
            && snapshot.committed_freshness() == self.freshness
            && snapshot.revision() == self.revision
            && snapshot.head() == self.head
            && snapshot.projection() == self.projection
    }
}

/// Opaque old-tip/new-root pair accepted by the rollover anchor boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldRolloverAnchor {
    source: WorldRolloverSource,
    target: CheckpointAnchor,
}

impl WorldRolloverAnchor {
    /// Returns the exact old trusted tip which must be replaced.
    pub const fn source(self) -> WorldRolloverSource {
        self.source
    }

    /// Returns the new-world checkpoint anchor.
    pub const fn target(self) -> CheckpointAnchor {
        self.target
    }
}

/// Linear rollover plan containing the drained old tip and empty new world.
pub struct PreparedWorldRollover {
    source: WorldRolloverSource,
    target: Engine,
    checkpoint: PreparedCheckpoint,
}

impl PreparedWorldRollover {
    /// Returns the old trusted tip which must still be current during staging.
    pub const fn source(&self) -> WorldRolloverSource {
        self.source
    }

    /// Returns the canonical empty-new-world checkpoint plan.
    pub const fn checkpoint_plan(&self) -> &CheckpointRecordPlan {
        self.checkpoint.plan()
    }

    /// Stages the new root and returns the only token which may rebind the anchor.
    pub fn persist<P>(
        self,
        persistence: &mut P,
    ) -> Result<DurablePreparedWorldRollover, TxError<P::Error>>
    where
        P: crate::WorldRolloverDurability,
    {
        persistence
            .persist_world_rollover(&self)
            .map_err(TxError::Persist)?;
        Ok(DurablePreparedWorldRollover { prepared: self })
    }
}

/// Linear proof that the empty new-world root was staged successfully.
pub struct DurablePreparedWorldRollover {
    prepared: PreparedWorldRollover,
}

impl DurablePreparedWorldRollover {
    /// Atomically rebinds the trusted anchor and publishes the empty new engine.
    pub fn publish<P>(self, persistence: &mut P) -> Result<Engine, TxError<P::Error>>
    where
        P: crate::WorldRolloverDurability,
    {
        let PreparedWorldRollover {
            source,
            mut target,
            checkpoint,
        } = self.prepared;
        if checkpoint.evolved_catalog.is_some() {
            return Err(TxError::Core(CoreError::InvariantViolation));
        }
        let anchor = WorldRolloverAnchor {
            source,
            target: checkpoint.anchor(),
        };
        let PreparedCheckpoint {
            plan,
            delta,
            receipt: _,
            certificate,
            origin,
            evolved_catalog: _,
        } = checkpoint;
        drop(plan);
        drop(origin);
        persistence
            .anchor_world_rollover(anchor)
            .map_err(TxError::Persist)?;
        delta.apply(&mut target.state);
        target.live_certificate = Some(certificate);
        target.persistence_recovery_required = false;
        Ok(target)
    }
}

impl Engine {
    /// Consumes a fully drained world and prepares an empty, independently
    /// bound successor world.
    ///
    /// The embedding must allocate a never-before-used `new_world` and a new
    /// Registry instance. Boot, device, and journal generations must all
    /// strictly advance so the successor cannot reuse a source generation.
    /// Identity allocators whose values are not themselves world-qualified
    /// must not reuse values from the source world.
    pub fn prepare_world_rollover(
        self,
        new_world: WorldId,
        new_freshness: Freshness,
    ) -> Result<PreparedWorldRollover, CoreError> {
        if new_world == self.state.world()
            || new_freshness.registry() == self.state.freshness().registry()
        {
            return Err(CoreError::WorldMismatch);
        }
        let source_freshness = self.state.freshness();
        if new_freshness.boot().get() <= source_freshness.boot().get()
            || new_freshness.device().get() <= source_freshness.device().get()
            || new_freshness.journal().get() <= source_freshness.journal().get()
        {
            return Err(CoreError::FreshnessRollback);
        }
        if self.journal_repair_required.is_some() {
            return Err(CoreError::JournalRepairRequired);
        }
        if self.persistence_recovery_required {
            return Err(CoreError::PersistenceRecoveryRequired);
        }
        if self.state.recovery_target().is_some() {
            return Err(CoreError::RecoveryPending);
        }
        let drained = self.state.scoped_composites().is_empty()
            && self.state.composite_effects().values().all(|effect| {
                effect.custodian == CustodyState::Released
                    && effect.authority == AuthorityState::Revoked
                    && effect.released_provenance.is_some()
                    && effect
                        .components
                        .values()
                        .all(|component| component.retirement == RetirementState::Released)
            })
            && self.state.provider_generations().values().all(|provider| {
                provider.live_component_bindings == 0
                    && matches!(provider.state, ProviderEffectState::Retired { .. })
            })
            && self
                .state
                .artifact_leases()
                .values()
                .all(|lease| matches!(lease, ArtifactLeaseState::Released { .. }))
            && self
                .state
                .resources()
                .values()
                .all(|resource| matches!(resource.phase, ResourcePhase::Retired))
            && self.state.charges().values().all(|units| *units == 0)
            && self
                .state
                .catalog_charges()
                .values()
                .all(|units| *units == 0)
            && self.state.device_quarantine().is_empty();
        if !drained {
            return Err(CoreError::WorldNotDrained);
        }
        self.live_certificate
            .as_ref()
            .ok_or(CoreError::InvariantViolation)?
            .validate(&self.state, self.catalog.digest())?;
        let source = WorldRolloverSource {
            binding: RecoveryBinding::new(
                crate::RecoveryProfile::current(),
                self.state.world(),
                self.catalog.digest(),
                self.state.freshness().registry(),
            )
            .map_err(|_| CoreError::SchemaMismatch)?,
            freshness: self.state.freshness(),
            revision: self.state.revision(),
            head: self.state.head(),
            projection: self.state.projection_cache().digest,
        };
        let mut target = Engine::new(new_world, self.catalog.clone(), self.limits, new_freshness);
        let plan = target.checkpoint_snapshot()?.prepare_plan()?;
        let checkpoint = target.checkpoint_prepare(plan)?;
        Ok(PreparedWorldRollover {
            source,
            target,
            checkpoint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standard_catalog;

    fn freshness(registry: u64) -> Freshness {
        Freshness::new(
            BootGeneration::new(1).unwrap(),
            RegistryInstance::new(registry).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(1).unwrap(),
        )
    }

    #[test]
    fn rollover_requires_a_distinct_world_and_registry() {
        let world = WorldId::new(1).unwrap();
        let catalogs = CatalogSet::new(&[standard_catalog()]).unwrap();
        let engine = Engine::new(
            world,
            catalogs.clone(),
            CoreLimits::bounded_default(),
            freshness(1),
        );
        assert!(matches!(
            engine.prepare_world_rollover(world, freshness(2)),
            Err(CoreError::WorldMismatch)
        ));

        let engine = Engine::new(world, catalogs, CoreLimits::bounded_default(), freshness(1));
        assert!(matches!(
            engine.prepare_world_rollover(WorldId::new(2).unwrap(), freshness(1)),
            Err(CoreError::WorldMismatch)
        ));
    }

    #[test]
    fn rollover_refuses_a_nonempty_quarantine_closure() {
        let mut engine = Engine::new(
            WorldId::new(1).unwrap(),
            CatalogSet::new(&[standard_catalog()]).unwrap(),
            CoreLimits::bounded_default(),
            freshness(1),
        );
        engine
            .state
            .device_quarantine
            .insert_mut(DeviceScopeId::new(9).unwrap());
        assert!(matches!(
            engine.prepare_world_rollover(
                WorldId::new(2).unwrap(),
                Freshness::new(
                    BootGeneration::new(2).unwrap(),
                    RegistryInstance::new(2).unwrap(),
                    DeviceGeneration::new(2).unwrap(),
                    JournalGeneration::new(2).unwrap(),
                ),
            ),
            Err(CoreError::WorldNotDrained)
        ));
    }

    #[test]
    fn rollover_rejects_successor_freshness_below_the_source_high_water() {
        let source = Freshness::new(
            BootGeneration::new(3).unwrap(),
            RegistryInstance::new(1).unwrap(),
            DeviceGeneration::new(3).unwrap(),
            JournalGeneration::new(3).unwrap(),
        );
        let target = Freshness::new(
            BootGeneration::new(3).unwrap(),
            RegistryInstance::new(2).unwrap(),
            DeviceGeneration::new(1).unwrap(),
            JournalGeneration::new(3).unwrap(),
        );
        let engine = Engine::new(
            WorldId::new(1).unwrap(),
            CatalogSet::new(&[standard_catalog()]).unwrap(),
            CoreLimits::bounded_default(),
            source,
        );
        assert!(matches!(
            engine.prepare_world_rollover(WorldId::new(2).unwrap(), target),
            Err(CoreError::FreshnessRollback)
        ));
    }
}
