//! Independent recovery-artifact lifecycle oracle.
//!
//! This is a deliberately small, clean-room state machine.  It models the
//! durable obligation created by a recovery root without importing any
//! production command, record, codec, or transition helper.  A lease is
//! owned by the complete world/provider/operation/effect/component/closure
//! tuple; equal closure digests therefore never make two leases interchangeable.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::{
    ArtifactId, ComponentId, EffectId, OperationId, ProviderGeneration, ProviderId, WorldId,
};

/// Opaque closure identity supplied by the embedding artifact system.
pub type ClosureDigest = [u8; 32];

/// Exact tuple that owns one recovery-artifact lease.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ArtifactOwner {
    /// Owning world.
    pub world: WorldId,
    /// Stable provider identity.
    pub provider: ProviderId,
    /// Exact provider generation.
    pub generation: ProviderGeneration,
    /// Causal operation identity.
    pub operation: OperationId,
    /// Effect identity.
    pub effect: EffectId,
    /// Component identity.
    pub component: ComponentId,
    /// Catalog digest used to interpret the effect.
    pub catalog_digest: ClosureDigest,
    /// Receipt-schema digest required for recovery.
    pub schema_digest: ClosureDigest,
    /// Verifier-set digest required for recovery.
    pub verifier_set_digest: ClosureDigest,
    /// Exact retained artifact closure digest.
    pub closure_digest: ClosureDigest,
}

/// Provider-generation lifecycle phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderPhase {
    /// New effects and commit intents are admitted.
    Active,
    /// New execution is fenced; escaped effects may settle.
    EffectFenced,
    /// Only settlement and release of existing effects are admitted.
    SettlementOnly,
    /// Permanent generation tombstone.
    Retired,
}

impl ProviderPhase {
    const fn admits_execution(self) -> bool {
        matches!(self, Self::Active)
    }

    const fn is_retired(self) -> bool {
        matches!(self, Self::Retired)
    }
}

/// Logical lifecycle of a component obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentPhase {
    /// No commit intent exists.
    Staged,
    /// Commit intent is durable but has not escaped.
    CommitIntent,
    /// Provider execution escaped.
    Executed,
    /// Escaped outcome is durable.
    Outcome,
    /// Logical settlement is durable.
    Settled,
    /// Fence-before-escape abandoned the component.
    Aborted,
    /// Component retention was released.
    Released,
}

impl ComponentPhase {
    const fn is_live(self) -> bool {
        !matches!(self, Self::Released)
    }

    const fn is_escaped(self) -> bool {
        matches!(self, Self::Executed | Self::Outcome | Self::Settled)
    }

    const fn is_logically_terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Aborted)
    }
}

/// Recovery-artifact lease lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactLeaseState {
    /// The artifact root is declared but has not been pinned.
    Declared,
    /// The artifact root is durably pinned before effect commit intent.
    Pinned,
    /// Release was authorized after all logical and physical obligations
    /// became terminal.
    ReleaseAuthorized,
    /// The external artifact system confirmed unpin.
    Released,
}

/// Exact release permit minted by the oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactReleasePermit {
    lease: ArtifactId,
    owner: ArtifactOwner,
    authorization_epoch: u64,
}

impl ArtifactReleasePermit {
    /// Returns the lease authorized by this permit.
    #[must_use]
    pub const fn lease(self) -> ArtifactId {
        self.lease
    }

    /// Returns the exact owner tuple bound by this permit.
    #[must_use]
    pub const fn owner(self) -> ArtifactOwner {
        self.owner
    }

    /// Returns the deterministic authorization epoch.
    #[must_use]
    pub const fn authorization_epoch(self) -> u64 {
        self.authorization_epoch
    }
}

/// Stable projection of one component's logical and physical retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentProjection {
    /// Effect identity.
    pub effect: EffectId,
    /// Component identity.
    pub component: ComponentId,
    /// Logical component phase.
    pub phase: ComponentPhase,
    /// Whether physical retirement has been observed.
    pub physical_retired: bool,
    /// Whether all retained claims have been retired.
    pub claims_retired: bool,
}

/// Stable projection of one recovery-artifact lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactProjection {
    /// Lease identity.
    pub lease: ArtifactId,
    /// Exact lease owner tuple.
    pub owner: ArtifactOwner,
    /// Catalog digest retained by the artifact provenance.
    pub catalog_digest: ClosureDigest,
    /// Receipt-schema digest retained by the artifact provenance.
    pub schema_digest: ClosureDigest,
    /// Verifier-set digest retained by the artifact provenance.
    pub verifier_set_digest: ClosureDigest,
    /// Current lease lifecycle.
    pub state: ArtifactLeaseState,
}

/// Stable projection of one provider generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderProjection {
    /// Provider coordinate.
    pub provider: ProviderId,
    /// Provider generation.
    pub generation: ProviderGeneration,
    /// Current lifecycle phase.
    pub phase: ProviderPhase,
    /// Number of unreleased components.
    pub live_components: u64,
    /// Number of unreleased effects.
    pub live_effects: u64,
}

/// Deterministic normalized projection used by model tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryArtifactProjection {
    /// Oracle-owned world.
    pub world: WorldId,
    /// Number of successful state-changing operations.
    pub revision: u64,
    /// Provider projections in coordinate order.
    pub providers: Vec<ProviderProjection>,
    /// Component projections in effect/component order.
    pub components: Vec<ComponentProjection>,
    /// Artifact projections in lease order.
    pub artifacts: Vec<ArtifactProjection>,
}

/// Recovery-artifact lifecycle rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactError {
    /// An identity was zero or a component was invalid.
    InvalidIdentity,
    /// A command named a world not owned by this oracle.
    WrongWorld,
    /// A generation was not strictly newer than its high-water tombstone.
    GenerationRollback,
    /// The previous generation still has live obligations.
    GenerationStillLive,
    /// A provider coordinate is not registered.
    UnknownProvider,
    /// A provider coordinate is known but is not the current generation.
    NotCurrentGeneration,
    /// A provider phase rejects this transition.
    WrongProviderPhase,
    /// A provider phase transition was attempted out of order.
    InvalidPhaseTransition,
    /// An effect identity is already used.
    EffectAlreadyExists,
    /// An operation identity is already used.
    OperationAlreadyExists,
    /// An effect identity is unknown.
    UnknownEffect,
    /// A component identity is not part of the effect.
    UnknownComponent,
    /// A lease identity is already used.
    LeaseAlreadyExists,
    /// A lease identity is unknown.
    UnknownArtifact,
    /// The complete artifact owner tuple did not match.
    WrongArtifactOwner,
    /// The lease is not in the requested lifecycle phase.
    WrongArtifactState,
    /// A required lease was not pinned before commit intent.
    ArtifactNotPinned,
    /// A release authorization was requested before terminal retirement.
    RetirementNotTerminal,
    /// The component still has an escaped outcome that needs settlement.
    SettlementRequired,
    /// A physical retirement or claim retirement was attempted too early.
    PhysicalRetirementRequired,
    /// A component was already released.
    ComponentAlreadyReleased,
    /// An unescaped component cannot be released without an explicit abort.
    UnescapedComponent,
    /// A permit did not exactly match the authorized lease.
    InvalidReleasePermit,
    /// A provider generation still has live effect/component or artifact
    /// obligations.
    LiveObligationsRemain,
}

#[derive(Clone, Debug)]
struct ProviderRecord {
    provider: ProviderId,
    generation: ProviderGeneration,
    phase: ProviderPhase,
}

#[derive(Clone, Debug)]
struct ComponentRecord {
    effect: EffectId,
    component: ComponentId,
    phase: ComponentPhase,
    physical_retired: bool,
    claims_retired: bool,
    artifacts: Vec<ArtifactId>,
}

#[derive(Clone, Debug)]
struct EffectRecord {
    provider: ProviderId,
    generation: ProviderGeneration,
    components: BTreeMap<ComponentId, ComponentRecord>,
}

#[derive(Clone, Debug)]
struct ArtifactRecord {
    owner: ArtifactOwner,
    state: ArtifactLeaseState,
    permit: Option<ArtifactReleasePermit>,
}

/// Independent recovery-artifact lifecycle oracle.
#[derive(Clone, Debug)]
pub struct RecoveryArtifactOracle {
    world: WorldId,
    revision: u64,
    high_water: BTreeMap<ProviderId, ProviderGeneration>,
    current: BTreeMap<ProviderId, ProviderGeneration>,
    providers: BTreeMap<(ProviderId, ProviderGeneration), ProviderRecord>,
    effects: BTreeMap<EffectId, EffectRecord>,
    operations: BTreeMap<OperationId, EffectId>,
    artifacts: BTreeMap<ArtifactId, ArtifactRecord>,
}

impl RecoveryArtifactOracle {
    /// Creates an empty oracle owned by one non-zero world.
    #[must_use]
    pub const fn new(world: WorldId) -> Self {
        Self {
            world,
            revision: 0,
            high_water: BTreeMap::new(),
            current: BTreeMap::new(),
            providers: BTreeMap::new(),
            effects: BTreeMap::new(),
            operations: BTreeMap::new(),
            artifacts: BTreeMap::new(),
        }
    }

    /// Returns the owning world.
    #[must_use]
    pub const fn world(&self) -> WorldId {
        self.world
    }

    /// Returns the successful transition count.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Registers a strictly newer provider generation.
    pub fn register_provider(
        &mut self,
        provider: ProviderId,
        generation: ProviderGeneration,
    ) -> Result<(), ArtifactError> {
        if self
            .high_water
            .get(&provider)
            .is_some_and(|high| generation <= *high)
        {
            return Err(ArtifactError::GenerationRollback);
        }
        if let Some(old_generation) = self.current.get(&provider).copied()
            && self
                .providers
                .get(&(provider, old_generation))
                .is_none_or(|record| !record.phase.is_retired())
        {
            return Err(ArtifactError::GenerationStillLive);
        }
        self.high_water.insert(provider, generation);
        self.current.insert(provider, generation);
        self.providers.insert(
            (provider, generation),
            ProviderRecord {
                provider,
                generation,
                phase: ProviderPhase::Active,
            },
        );
        self.bump_revision();
        Ok(())
    }

    /// Admits an effect under the active provider generation.
    pub fn admit_effect(
        &mut self,
        effect: EffectId,
        provider: ProviderId,
        generation: ProviderGeneration,
        components: &[ComponentId],
    ) -> Result<(), ArtifactError> {
        if self.effects.contains_key(&effect) {
            return Err(ArtifactError::EffectAlreadyExists);
        }
        let operation = effect.operation();
        if self.operations.contains_key(&operation) {
            return Err(ArtifactError::OperationAlreadyExists);
        }
        if components.is_empty() || components.iter().any(|component| component.get() == 0) {
            return Err(ArtifactError::InvalidIdentity);
        }
        let provider_record = self.provider_record(provider, generation)?;
        if !provider_record.phase.admits_execution() {
            return Err(ArtifactError::WrongProviderPhase);
        }
        let mut component_records = BTreeMap::new();
        for component in components {
            if component_records
                .insert(
                    *component,
                    ComponentRecord {
                        effect,
                        component: *component,
                        phase: ComponentPhase::Staged,
                        physical_retired: false,
                        claims_retired: false,
                        artifacts: Vec::new(),
                    },
                )
                .is_some()
            {
                return Err(ArtifactError::InvalidIdentity);
            }
        }
        self.effects.insert(
            effect,
            EffectRecord {
                provider,
                generation,
                components: component_records,
            },
        );
        self.operations.insert(operation, effect);
        self.bump_revision();
        Ok(())
    }

    /// Declares one required artifact lease for an admitted component.
    pub fn require_artifact(
        &mut self,
        lease: ArtifactId,
        owner: ArtifactOwner,
    ) -> Result<(), ArtifactError> {
        self.check_owner_effect(owner)?;
        if self.artifacts.contains_key(&lease) {
            return Err(ArtifactError::LeaseAlreadyExists);
        }
        let component = self.component_record_mut(owner.effect, owner.component)?;
        if component.phase != ComponentPhase::Staged {
            return Err(ArtifactError::WrongArtifactState);
        }
        component.artifacts.push(lease);
        self.artifacts.insert(
            lease,
            ArtifactRecord {
                owner,
                state: ArtifactLeaseState::Declared,
                permit: None,
            },
        );
        self.bump_revision();
        Ok(())
    }

    /// Pins a declared recovery-artifact lease against its exact owner tuple.
    pub fn pin_artifact(
        &mut self,
        lease: ArtifactId,
        owner: ArtifactOwner,
    ) -> Result<(), ArtifactError> {
        let record = self.artifact_record_mut(lease, owner)?;
        if record.state != ArtifactLeaseState::Declared || record.permit.is_some() {
            return Err(ArtifactError::WrongArtifactState);
        }
        record.state = ArtifactLeaseState::Pinned;
        record.permit = Some(ArtifactReleasePermit {
            lease,
            owner,
            authorization_epoch: 0,
        });
        self.bump_revision();
        Ok(())
    }

    /// Records commit intent only after every required artifact is pinned.
    pub fn commit_intent(
        &mut self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<(), ArtifactError> {
        let (provider, generation) = self.effect_coordinate(effect)?;
        if !self
            .provider_record(provider, generation)?
            .phase
            .admits_execution()
        {
            return Err(ArtifactError::WrongProviderPhase);
        }
        let record = self.component_record(effect, component)?;
        if record.phase != ComponentPhase::Staged {
            return Err(ArtifactError::WrongArtifactState);
        }
        if record.artifacts.iter().any(|lease| {
            self.artifacts
                .get(lease)
                .is_none_or(|artifact| artifact.state != ArtifactLeaseState::Pinned)
        }) {
            return Err(ArtifactError::ArtifactNotPinned);
        }
        self.component_record_mut(effect, component)?.phase = ComponentPhase::CommitIntent;
        self.bump_revision();
        Ok(())
    }

    /// Executes an already durable commit intent.
    pub fn execute(
        &mut self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<(), ArtifactError> {
        let (provider, generation) = self.effect_coordinate(effect)?;
        if !self
            .provider_record(provider, generation)?
            .phase
            .admits_execution()
        {
            return Err(ArtifactError::WrongProviderPhase);
        }
        let record = self.component_record_mut(effect, component)?;
        if record.phase != ComponentPhase::CommitIntent {
            return Err(ArtifactError::WrongArtifactState);
        }
        record.phase = ComponentPhase::Executed;
        self.bump_revision();
        Ok(())
    }

    /// Records an escaped provider outcome.
    pub fn record_outcome(
        &mut self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<(), ArtifactError> {
        let record = self.component_record_mut(effect, component)?;
        if record.phase != ComponentPhase::Executed {
            return Err(ArtifactError::SettlementRequired);
        }
        record.phase = ComponentPhase::Outcome;
        self.bump_revision();
        Ok(())
    }

    /// Settles an escaped outcome.
    pub fn settle(
        &mut self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<(), ArtifactError> {
        let record = self.component_record_mut(effect, component)?;
        if record.phase != ComponentPhase::Outcome {
            return Err(ArtifactError::SettlementRequired);
        }
        record.phase = ComponentPhase::Settled;
        self.bump_revision();
        Ok(())
    }

    /// Aborts a component that did not escape before the provider fence.
    pub fn abort_unescaped(
        &mut self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<(), ArtifactError> {
        let (provider, generation) = self.effect_coordinate(effect)?;
        if self
            .provider_record(provider, generation)?
            .phase
            .admits_execution()
        {
            return Err(ArtifactError::WrongProviderPhase);
        }
        let record = self.component_record_mut(effect, component)?;
        if record.phase != ComponentPhase::Staged && record.phase != ComponentPhase::CommitIntent {
            return Err(if record.phase.is_escaped() {
                ArtifactError::SettlementRequired
            } else {
                ArtifactError::WrongArtifactState
            });
        }
        record.phase = ComponentPhase::Aborted;
        self.bump_revision();
        Ok(())
    }

    /// Records physical retirement after logical settlement or abort.
    pub fn retire_physical(
        &mut self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<(), ArtifactError> {
        let record = self.component_record_mut(effect, component)?;
        if !record.phase.is_logically_terminal() {
            return Err(ArtifactError::SettlementRequired);
        }
        record.physical_retired = true;
        self.bump_revision();
        Ok(())
    }

    /// Records retirement of all retained logical claims.
    pub fn retire_claims(
        &mut self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<(), ArtifactError> {
        let record = self.component_record_mut(effect, component)?;
        if !record.phase.is_logically_terminal() || !record.physical_retired {
            return Err(ArtifactError::PhysicalRetirementRequired);
        }
        record.claims_retired = true;
        self.bump_revision();
        Ok(())
    }

    /// Authorizes artifact release only after logical, physical, and claim
    /// retirement.  Repeating this call returns the exact same permit.
    pub fn authorize_artifact_release(
        &mut self,
        lease: ArtifactId,
        owner: ArtifactOwner,
    ) -> Result<ArtifactReleasePermit, ArtifactError> {
        let component = self.component_record(owner.effect, owner.component)?;
        if !component.phase.is_logically_terminal()
            || !component.physical_retired
            || !component.claims_retired
        {
            return Err(ArtifactError::RetirementNotTerminal);
        }
        let authorization_epoch = next(self.revision);
        let record = self.artifact_record_mut(lease, owner)?;
        match record.state {
            ArtifactLeaseState::Pinned => {
                if record.permit.is_none() {
                    return Err(ArtifactError::ArtifactNotPinned);
                }
                let permit = ArtifactReleasePermit {
                    lease,
                    owner,
                    authorization_epoch,
                };
                record.state = ArtifactLeaseState::ReleaseAuthorized;
                record.permit = Some(permit);
                self.bump_revision();
                Ok(permit)
            }
            ArtifactLeaseState::ReleaseAuthorized => {
                record.permit.ok_or(ArtifactError::InvalidReleasePermit)
            }
            ArtifactLeaseState::Declared | ArtifactLeaseState::Released => {
                Err(ArtifactError::WrongArtifactState)
            }
        }
    }

    /// Reissues the exact persisted release permit after a recovery cut.
    pub fn reissue_release_permit(
        &self,
        lease: ArtifactId,
        owner: ArtifactOwner,
    ) -> Result<ArtifactReleasePermit, ArtifactError> {
        let record = self.artifact_record(lease, owner)?;
        if record.state != ArtifactLeaseState::ReleaseAuthorized {
            return Err(ArtifactError::WrongArtifactState);
        }
        record.permit.ok_or(ArtifactError::InvalidReleasePermit)
    }

    /// Confirms the external artifact system's unpin with an exact permit.
    pub fn confirm_artifact_released(
        &mut self,
        permit: ArtifactReleasePermit,
    ) -> Result<(), ArtifactError> {
        let record = self
            .artifacts
            .get_mut(&permit.lease)
            .ok_or(ArtifactError::UnknownArtifact)?;
        if record.owner != permit.owner
            || record.state != ArtifactLeaseState::ReleaseAuthorized
            || record.permit != Some(permit)
        {
            return Err(ArtifactError::InvalidReleasePermit);
        }
        record.state = ArtifactLeaseState::Released;
        self.bump_revision();
        Ok(())
    }

    /// Releases component retention after every required artifact is released.
    pub fn release_component(
        &mut self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<(), ArtifactError> {
        let record = self.component_record(effect, component)?;
        if record.phase == ComponentPhase::Released {
            return Err(ArtifactError::ComponentAlreadyReleased);
        }
        if !record.phase.is_logically_terminal() {
            return Err(ArtifactError::UnescapedComponent);
        }
        if !record.physical_retired || !record.claims_retired {
            return Err(ArtifactError::PhysicalRetirementRequired);
        }
        if record.artifacts.iter().any(|lease| {
            self.artifacts
                .get(lease)
                .is_none_or(|artifact| artifact.state != ArtifactLeaseState::Released)
        }) {
            return Err(ArtifactError::LiveObligationsRemain);
        }
        self.component_record_mut(effect, component)?.phase = ComponentPhase::Released;
        self.bump_revision();
        Ok(())
    }

    /// Fences new provider effects and commit intents.
    pub fn fence_provider(
        &mut self,
        provider: ProviderId,
        generation: ProviderGeneration,
    ) -> Result<(), ArtifactError> {
        let record = self.provider_record_mut(provider, generation)?;
        if record.phase != ProviderPhase::Active {
            return Err(ArtifactError::InvalidPhaseTransition);
        }
        record.phase = ProviderPhase::EffectFenced;
        self.bump_revision();
        Ok(())
    }

    /// Enters settlement-only mode after all pre-escape components are gone.
    pub fn enter_settlement_only(
        &mut self,
        provider: ProviderId,
        generation: ProviderGeneration,
    ) -> Result<(), ArtifactError> {
        if self.provider_record(provider, generation)?.phase != ProviderPhase::EffectFenced {
            return Err(ArtifactError::InvalidPhaseTransition);
        }
        if self.effects.values().any(|effect| {
            effect.provider == provider
                && effect.generation == generation
                && effect.components.values().any(|component| {
                    matches!(
                        component.phase,
                        ComponentPhase::Staged
                            | ComponentPhase::CommitIntent
                            | ComponentPhase::Executed
                    )
                })
        }) {
            return Err(ArtifactError::LiveObligationsRemain);
        }
        self.provider_record_mut(provider, generation)?.phase = ProviderPhase::SettlementOnly;
        self.bump_revision();
        Ok(())
    }

    /// Retires a provider generation only after effects and artifacts drain.
    pub fn retire_provider(
        &mut self,
        provider: ProviderId,
        generation: ProviderGeneration,
    ) -> Result<(), ArtifactError> {
        if self.provider_record(provider, generation)?.phase != ProviderPhase::SettlementOnly {
            return Err(ArtifactError::InvalidPhaseTransition);
        }
        if self.effects.values().any(|effect| {
            effect.provider == provider
                && effect.generation == generation
                && effect.components.values().any(|component| {
                    component.phase != ComponentPhase::Released
                        || component.artifacts.iter().any(|lease| {
                            self.artifacts.get(lease).is_none_or(|artifact| {
                                artifact.state != ArtifactLeaseState::Released
                            })
                        })
                })
        }) {
            return Err(ArtifactError::LiveObligationsRemain);
        }
        self.provider_record_mut(provider, generation)?.phase = ProviderPhase::Retired;
        self.bump_revision();
        Ok(())
    }

    /// Returns a deterministic normalized projection.
    #[must_use]
    pub fn projection(&self) -> RecoveryArtifactProjection {
        let providers = self
            .providers
            .values()
            .map(|record| {
                let mut live_components = 0;
                let mut live_effects = 0;
                for effect in self.effects.values().filter(|effect| {
                    effect.provider == record.provider && effect.generation == record.generation
                }) {
                    let effect_live = effect
                        .components
                        .values()
                        .filter(|component| component.phase.is_live())
                        .count();
                    live_components += effect_live as u64;
                    if effect_live != 0 {
                        live_effects += 1;
                    }
                }
                ProviderProjection {
                    provider: record.provider,
                    generation: record.generation,
                    phase: record.phase,
                    live_components,
                    live_effects,
                }
            })
            .collect();
        let components = self
            .effects
            .values()
            .flat_map(|effect| effect.components.values())
            .map(|component| ComponentProjection {
                effect: component.effect,
                component: component.component,
                phase: component.phase,
                physical_retired: component.physical_retired,
                claims_retired: component.claims_retired,
            })
            .collect();
        let artifacts = self
            .artifacts
            .iter()
            .map(|(lease, artifact)| ArtifactProjection {
                lease: *lease,
                owner: artifact.owner,
                catalog_digest: artifact.owner.catalog_digest,
                schema_digest: artifact.owner.schema_digest,
                verifier_set_digest: artifact.owner.verifier_set_digest,
                state: artifact.state,
            })
            .collect();
        RecoveryArtifactProjection {
            world: self.world,
            revision: self.revision,
            providers,
            components,
            artifacts,
        }
    }

    /// Checks tuple ownership, lifecycle ordering, permit identity, and
    /// provider retirement conservation.
    #[must_use]
    pub fn check_invariants(&self) -> bool {
        for (key, provider) in &self.providers {
            if provider.provider != key.0
                || provider.generation != key.1
                || self.world.get() == 0
                || provider.phase.is_retired()
                    && self.effects.values().any(|effect| {
                        effect.provider == provider.provider
                            && effect.generation == provider.generation
                            && effect
                                .components
                                .values()
                                .any(|component| component.phase != ComponentPhase::Released)
                    })
            {
                return false;
            }
        }
        for (lease, artifact) in &self.artifacts {
            if artifact.owner.world != self.world {
                return false;
            }
            if artifact.owner.catalog_digest == [0; 32]
                || artifact.owner.schema_digest == [0; 32]
                || artifact.owner.verifier_set_digest == [0; 32]
                || artifact.owner.closure_digest == [0; 32]
            {
                return false;
            }
            let Some(effect) = self.effects.get(&artifact.owner.effect) else {
                return false;
            };
            if artifact.owner.effect.operation() != artifact.owner.operation
                || effect.provider != artifact.owner.provider
                || effect.generation != artifact.owner.generation
                || !effect
                    .components
                    .get(&artifact.owner.component)
                    .is_some_and(|component| component.artifacts.contains(lease))
            {
                return false;
            }
            match (artifact.state, artifact.permit) {
                (ArtifactLeaseState::Declared, None) => {}
                (ArtifactLeaseState::Pinned, Some(permit)) if permit.authorization_epoch == 0 => {
                    if permit.lease != *lease || permit.owner != artifact.owner {
                        return false;
                    }
                }
                (
                    ArtifactLeaseState::ReleaseAuthorized | ArtifactLeaseState::Released,
                    Some(permit),
                ) if permit.authorization_epoch != 0 => {
                    if permit.lease != *lease || permit.owner != artifact.owner {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }

    fn provider_record(
        &self,
        provider: ProviderId,
        generation: ProviderGeneration,
    ) -> Result<&ProviderRecord, ArtifactError> {
        if self.current.get(&provider).copied() != Some(generation) {
            return Err(if self.providers.contains_key(&(provider, generation)) {
                ArtifactError::NotCurrentGeneration
            } else {
                ArtifactError::UnknownProvider
            });
        }
        self.providers
            .get(&(provider, generation))
            .ok_or(ArtifactError::UnknownProvider)
    }

    fn provider_record_mut(
        &mut self,
        provider: ProviderId,
        generation: ProviderGeneration,
    ) -> Result<&mut ProviderRecord, ArtifactError> {
        self.provider_record(provider, generation)?;
        self.providers
            .get_mut(&(provider, generation))
            .ok_or(ArtifactError::UnknownProvider)
    }

    fn effect_coordinate(
        &self,
        effect: EffectId,
    ) -> Result<(ProviderId, ProviderGeneration), ArtifactError> {
        self.effects
            .get(&effect)
            .map(|record| (record.provider, record.generation))
            .ok_or(ArtifactError::UnknownEffect)
    }

    fn check_owner_effect(&self, owner: ArtifactOwner) -> Result<(), ArtifactError> {
        if owner.world != self.world {
            return Err(ArtifactError::WrongWorld);
        }
        if owner.catalog_digest == [0; 32]
            || owner.schema_digest == [0; 32]
            || owner.verifier_set_digest == [0; 32]
            || owner.closure_digest == [0; 32]
        {
            return Err(ArtifactError::InvalidIdentity);
        }
        let effect = self
            .effects
            .get(&owner.effect)
            .ok_or(ArtifactError::UnknownEffect)?;
        if owner.effect.operation() != owner.operation
            || effect.provider != owner.provider
            || effect.generation != owner.generation
        {
            return Err(ArtifactError::WrongArtifactOwner);
        }
        if !effect.components.contains_key(&owner.component) {
            return Err(ArtifactError::UnknownComponent);
        }
        Ok(())
    }

    fn component_record(
        &self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<&ComponentRecord, ArtifactError> {
        self.effects
            .get(&effect)
            .ok_or(ArtifactError::UnknownEffect)?
            .components
            .get(&component)
            .ok_or(ArtifactError::UnknownComponent)
    }

    fn component_record_mut(
        &mut self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<&mut ComponentRecord, ArtifactError> {
        self.effects
            .get_mut(&effect)
            .ok_or(ArtifactError::UnknownEffect)?
            .components
            .get_mut(&component)
            .ok_or(ArtifactError::UnknownComponent)
    }

    fn artifact_record(
        &self,
        lease: ArtifactId,
        owner: ArtifactOwner,
    ) -> Result<&ArtifactRecord, ArtifactError> {
        let record = self
            .artifacts
            .get(&lease)
            .ok_or(ArtifactError::UnknownArtifact)?;
        if record.owner != owner {
            return Err(ArtifactError::WrongArtifactOwner);
        }
        Ok(record)
    }

    fn artifact_record_mut(
        &mut self,
        lease: ArtifactId,
        owner: ArtifactOwner,
    ) -> Result<&mut ArtifactRecord, ArtifactError> {
        let record = self
            .artifacts
            .get_mut(&lease)
            .ok_or(ArtifactError::UnknownArtifact)?;
        if record.owner != owner {
            return Err(ArtifactError::WrongArtifactOwner);
        }
        Ok(record)
    }

    fn bump_revision(&mut self) {
        self.revision = next(self.revision);
    }
}

const fn next(value: u64) -> u64 {
    match value.checked_add(1) {
        Some(next) => next,
        None => panic!("recovery-artifact oracle exhausted"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        world: WorldId,
        provider: ProviderId,
        generation: ProviderGeneration,
        effect: EffectId,
        component: ComponentId,
        lease: ArtifactId,
        owner: ArtifactOwner,
    }

    fn fixture() -> Fixture {
        let world = WorldId::new(1).unwrap();
        let provider = ProviderId::new(7).unwrap();
        let generation = ProviderGeneration::new(3).unwrap();
        let operation = OperationId::new(11).unwrap();
        let effect = EffectId::new(operation, 13).unwrap();
        let component = ComponentId::new(1).unwrap();
        let lease = ArtifactId::new(17).unwrap();
        Fixture {
            world,
            provider,
            generation,
            effect,
            component,
            lease,
            owner: ArtifactOwner {
                world,
                provider,
                generation,
                operation,
                effect,
                component,
                catalog_digest: [0x11; 32],
                schema_digest: [0x22; 32],
                verifier_set_digest: [0x33; 32],
                closure_digest: [0xabu8; 32],
            },
        }
    }

    fn admitted(fixture: &Fixture) -> RecoveryArtifactOracle {
        let mut oracle = RecoveryArtifactOracle::new(fixture.world);
        oracle
            .register_provider(fixture.provider, fixture.generation)
            .unwrap();
        oracle
            .admit_effect(
                fixture.effect,
                fixture.provider,
                fixture.generation,
                &[fixture.component],
            )
            .unwrap();
        oracle
    }

    fn pinned(fixture: &Fixture) -> RecoveryArtifactOracle {
        let mut oracle = admitted(fixture);
        oracle
            .require_artifact(fixture.lease, fixture.owner)
            .unwrap();
        oracle.pin_artifact(fixture.lease, fixture.owner).unwrap();
        oracle
    }

    fn terminal(fixture: &Fixture) -> (RecoveryArtifactOracle, ArtifactReleasePermit) {
        let mut oracle = pinned(fixture);
        oracle
            .commit_intent(fixture.effect, fixture.component)
            .unwrap();
        oracle.execute(fixture.effect, fixture.component).unwrap();
        oracle
            .record_outcome(fixture.effect, fixture.component)
            .unwrap();
        oracle.settle(fixture.effect, fixture.component).unwrap();
        oracle
            .retire_physical(fixture.effect, fixture.component)
            .unwrap();
        oracle
            .retire_claims(fixture.effect, fixture.component)
            .unwrap();
        let permit = oracle
            .authorize_artifact_release(fixture.lease, fixture.owner)
            .unwrap();
        (oracle, permit)
    }

    #[test]
    fn required_artifact_is_pinned_before_commit_intent() {
        let fixture = fixture();
        let mut oracle = admitted(&fixture);
        oracle
            .require_artifact(fixture.lease, fixture.owner)
            .unwrap();
        assert_eq!(
            oracle.projection().artifacts[0].state,
            ArtifactLeaseState::Declared
        );
        assert_eq!(
            oracle.commit_intent(fixture.effect, fixture.component),
            Err(ArtifactError::ArtifactNotPinned)
        );
        assert!(oracle.check_invariants());
        oracle.pin_artifact(fixture.lease, fixture.owner).unwrap();
        assert_eq!(
            oracle.projection().artifacts[0].state,
            ArtifactLeaseState::Pinned
        );
        oracle
            .commit_intent(fixture.effect, fixture.component)
            .unwrap();
        assert!(oracle.check_invariants());
    }

    #[test]
    fn provenance_digest_mismatch_cannot_pin_declared_lease() {
        let fixture = fixture();
        let mut oracle = admitted(&fixture);
        oracle
            .require_artifact(fixture.lease, fixture.owner)
            .unwrap();
        let mut wrong = fixture.owner;
        wrong.verifier_set_digest = [0x44; 32];
        let before = oracle.projection();
        assert_eq!(
            oracle.pin_artifact(fixture.lease, wrong),
            Err(ArtifactError::WrongArtifactOwner)
        );
        assert_eq!(oracle.projection(), before);
        assert!(oracle.check_invariants());
    }

    #[test]
    fn wrong_owner_tuple_is_rejected_without_mutation() {
        let fixture = fixture();
        let mut oracle = admitted(&fixture);
        oracle
            .require_artifact(fixture.lease, fixture.owner)
            .unwrap();
        let mut wrong = fixture.owner;
        wrong.generation = ProviderGeneration::new(4).unwrap();
        let before = oracle.projection();
        assert_eq!(
            oracle.pin_artifact(fixture.lease, wrong),
            Err(ArtifactError::WrongArtifactOwner)
        );
        assert_eq!(oracle.projection(), before);
        assert!(oracle.check_invariants());
    }

    #[test]
    fn crash_cuts_reissue_exact_release_permit() {
        let fixture = fixture();
        let (oracle, permit) = terminal(&fixture);
        let recovered = oracle.clone();
        assert_eq!(
            recovered
                .reissue_release_permit(fixture.lease, fixture.owner)
                .unwrap(),
            permit
        );
        let mut resumed = recovered;
        let repeated = resumed
            .authorize_artifact_release(fixture.lease, fixture.owner)
            .unwrap();
        assert_eq!(repeated, permit);
        resumed.confirm_artifact_released(permit).unwrap();
        assert_eq!(
            resumed.reissue_release_permit(fixture.lease, fixture.owner),
            Err(ArtifactError::WrongArtifactState)
        );
        assert!(resumed.check_invariants());
    }

    #[test]
    fn fence_before_escape_aborts_and_cleans_pinned_lease() {
        let fixture = fixture();
        let mut oracle = pinned(&fixture);
        oracle
            .commit_intent(fixture.effect, fixture.component)
            .unwrap();
        oracle
            .fence_provider(fixture.provider, fixture.generation)
            .unwrap();
        oracle
            .abort_unescaped(fixture.effect, fixture.component)
            .unwrap();
        oracle
            .retire_physical(fixture.effect, fixture.component)
            .unwrap();
        oracle
            .retire_claims(fixture.effect, fixture.component)
            .unwrap();
        let permit = oracle
            .authorize_artifact_release(fixture.lease, fixture.owner)
            .unwrap();
        oracle.confirm_artifact_released(permit).unwrap();
        oracle
            .release_component(fixture.effect, fixture.component)
            .unwrap();
        oracle
            .enter_settlement_only(fixture.provider, fixture.generation)
            .unwrap();
        oracle
            .retire_provider(fixture.provider, fixture.generation)
            .unwrap();
        assert!(oracle.check_invariants());
    }

    #[test]
    fn equal_closure_digests_have_independent_leases() {
        let fixture = fixture();
        let mut oracle = admitted(&fixture);
        let lease_two = ArtifactId::new(18).unwrap();
        oracle
            .require_artifact(fixture.lease, fixture.owner)
            .unwrap();
        oracle.require_artifact(lease_two, fixture.owner).unwrap();
        oracle.pin_artifact(fixture.lease, fixture.owner).unwrap();
        oracle.pin_artifact(lease_two, fixture.owner).unwrap();
        oracle
            .commit_intent(fixture.effect, fixture.component)
            .unwrap();
        oracle.execute(fixture.effect, fixture.component).unwrap();
        oracle
            .record_outcome(fixture.effect, fixture.component)
            .unwrap();
        oracle.settle(fixture.effect, fixture.component).unwrap();
        oracle
            .retire_physical(fixture.effect, fixture.component)
            .unwrap();
        oracle
            .retire_claims(fixture.effect, fixture.component)
            .unwrap();
        let first = oracle
            .authorize_artifact_release(fixture.lease, fixture.owner)
            .unwrap();
        let second = oracle
            .authorize_artifact_release(lease_two, fixture.owner)
            .unwrap();
        oracle.confirm_artifact_released(first).unwrap();
        assert_eq!(
            oracle.release_component(fixture.effect, fixture.component),
            Err(ArtifactError::LiveObligationsRemain)
        );
        oracle.confirm_artifact_released(second).unwrap();
        oracle
            .release_component(fixture.effect, fixture.component)
            .unwrap();
        assert!(oracle.check_invariants());
    }

    #[test]
    fn provider_retirement_waits_for_effect_and_artifact_drain() {
        let fixture = fixture();
        let (mut oracle, permit) = terminal(&fixture);
        oracle
            .fence_provider(fixture.provider, fixture.generation)
            .unwrap();
        oracle
            .enter_settlement_only(fixture.provider, fixture.generation)
            .unwrap();
        assert_eq!(
            oracle.retire_provider(fixture.provider, fixture.generation),
            Err(ArtifactError::LiveObligationsRemain)
        );
        oracle.confirm_artifact_released(permit).unwrap();
        oracle
            .release_component(fixture.effect, fixture.component)
            .unwrap();
        oracle
            .retire_provider(fixture.provider, fixture.generation)
            .unwrap();
        assert!(oracle.check_invariants());
    }
}
