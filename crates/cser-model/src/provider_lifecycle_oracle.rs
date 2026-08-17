//! Independent bounded oracle for provider-generation retirement.
//!
//! This module is intentionally a small, clean-room state machine.  It does
//! not import `cser-core` commands, records, codecs, or transition helpers.
//! A provider generation is retained as a tombstone after retirement, and a
//! scoped effect may only be admitted by the currently active generation.  A
//! fence is the single ordering point between new execution and settlement:
//! intent recorded before the fence may finish outcome, settlement, and
//! release, while intent after the fence is rejected.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::{
    ComponentId, EffectId, OperationId, ProviderCoordinate, ProviderGeneration, ProviderId, WorldId,
};

/// Maximum number of components in this bounded composite profile.
pub const MAX_COMPONENTS: usize = 4;

/// Provider lifecycle phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderPhase {
    /// New effect admission and execution are allowed.
    Active {
        /// Monotonic lifecycle epoch.
        epoch: u64,
    },
    /// New effects/intents/execution are fenced; escaped effects may settle.
    EffectFenced {
        /// Monotonic lifecycle epoch.
        epoch: u64,
    },
    /// Only outcome, settlement, and release of existing effects are allowed.
    SettlementOnly {
        /// Monotonic lifecycle epoch.
        epoch: u64,
    },
    /// The generation is a permanent tombstone.
    Retired {
        /// Monotonic lifecycle epoch.
        epoch: u64,
    },
}

impl ProviderPhase {
    /// Returns the monotonic authority epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        match self {
            Self::Active { epoch }
            | Self::EffectFenced { epoch }
            | Self::SettlementOnly { epoch }
            | Self::Retired { epoch } => epoch,
        }
    }

    /// Returns whether new execution is admitted.
    #[must_use]
    pub const fn admits_execution(self) -> bool {
        matches!(self, Self::Active { .. })
    }

    /// Returns whether the phase is permanently retired.
    #[must_use]
    pub const fn is_retired(self) -> bool {
        matches!(self, Self::Retired { .. })
    }
}

/// Lifecycle of one bounded component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentLifecycle {
    /// No external commit intent exists yet.
    Staged,
    /// Commit intent is durable and the component is escaped.
    CommitIntent,
    /// The provider performed execution before the fence.
    Executed,
    /// An escaped outcome is durable.
    Outcome,
    /// Settlement is durable and release is now permitted.
    Settled,
    /// The component's retained obligation has been released.
    Released,
}

impl ComponentLifecycle {
    const fn is_released(self) -> bool {
        matches!(self, Self::Released)
    }

    const fn is_escaped(self) -> bool {
        !matches!(self, Self::Staged | Self::Released)
    }
}

/// A stable projection of one scoped effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectProjection {
    /// Effect identity.
    pub effect: EffectId,
    /// Provider generation bound at admission.
    pub provider: ProviderCoordinate,
    /// Component identities in stable catalog order.
    pub component_ids: [ComponentId; MAX_COMPONENTS],
    /// Number of active component slots in this effect.
    pub component_count: u8,
    /// Component states in stable bounded slot order.
    pub components: [ComponentLifecycle; MAX_COMPONENTS],
}

/// A stable projection of one provider generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderProjection {
    /// Provider generation coordinate.
    pub coordinate: ProviderCoordinate,
    /// Current lifecycle phase.
    pub phase: ProviderPhase,
    /// Number of effects with at least one unreleased component.
    pub live_effects: u64,
    /// Number of admitted but unreleased components.
    pub live_components: u64,
    /// Number of components admitted by this generation.
    pub admitted_components: u64,
    /// Number of components released by this generation.
    pub released_components: u64,
}

/// Complete normalized projection used by sequence/differential tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleProjection {
    /// World owned by this oracle.
    pub world: WorldId,
    /// Number of successful state-changing operations.
    pub revision: u64,
    /// Provider-generation projections in coordinate order.
    pub providers: Vec<ProviderProjection>,
    /// Effect projections in effect-id order.
    pub effects: Vec<EffectProjection>,
}

/// Rejection emitted by the provider lifecycle oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    /// An identity was zero or a component was outside the fixed bound.
    InvalidIdentity,
    /// A command named a world not owned by this oracle.
    WrongWorld,
    /// A provider generation did not advance beyond its tombstoned high water.
    GenerationRollback,
    /// The current provider generation still has live authority or effects.
    GenerationStillLive,
    /// A coordinate is not registered in this world.
    UnknownProviderGeneration,
    /// A coordinate names a generation other than the current provider.
    NotCurrentGeneration,
    /// The provider phase does not admit this operation.
    WrongProviderPhase,
    /// A provider phase transition was attempted in the wrong order.
    InvalidPhaseTransition,
    /// An effect identity is already permanently recorded.
    EffectAlreadyExists,
    /// An effect identity is not known.
    UnknownEffect,
    /// An operation identity is already used by another effect.
    OperationAlreadyExists,
    /// The requested component is outside this effect's bounded catalog.
    ComponentOutOfBounds,
    /// A component is not in the requested lifecycle stage.
    WrongComponentState,
    /// New execution was attempted after the provider effect fence.
    ExecutionFenced,
    /// An escaped outcome is required before settlement.
    OutcomeRequired,
    /// A component was already settled or released.
    AlreadySettled,
    /// A component was already released.
    AlreadyReleased,
    /// Settlement-only cannot begin while a precommit component remains.
    PrecommitStillLive,
    /// Retirement requires all effect/component obligations to be released.
    LiveEffectsRemain,
}

#[derive(Clone, Debug)]
struct ProviderRecord {
    coordinate: ProviderCoordinate,
    phase: ProviderPhase,
    live_effects: u64,
    live_components: u64,
    admitted_components: u64,
    released_components: u64,
}

#[derive(Clone, Debug)]
struct EffectRecord {
    projection: EffectProjection,
}

/// Independent bounded provider-generation lifecycle oracle.
#[derive(Clone, Debug)]
pub struct ProviderLifecycleOracle {
    world: WorldId,
    revision: u64,
    high_water: BTreeMap<ProviderId, ProviderGeneration>,
    current: BTreeMap<ProviderId, ProviderGeneration>,
    providers: BTreeMap<ProviderCoordinate, ProviderRecord>,
    effects: BTreeMap<EffectId, EffectRecord>,
    operations: BTreeMap<OperationId, EffectId>,
}

impl ProviderLifecycleOracle {
    /// Creates an empty registry owned by one non-zero world.
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
        }
    }

    /// Returns this oracle's world.
    #[must_use]
    pub const fn world(&self) -> WorldId {
        self.world
    }

    /// Returns the successful transition count.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the generation high-water tombstone for one provider.
    #[must_use]
    pub fn high_water(&self, provider: ProviderId) -> Option<ProviderGeneration> {
        self.high_water.get(&provider).copied()
    }

    /// Returns a provider phase when the exact coordinate is registered.
    #[must_use]
    pub fn provider_phase(&self, coordinate: ProviderCoordinate) -> Option<ProviderPhase> {
        self.providers.get(&coordinate).map(|record| record.phase)
    }

    /// Returns a complete deterministic projection.
    #[must_use]
    pub fn projection(&self) -> LifecycleProjection {
        let providers = self
            .providers
            .values()
            .map(|record| ProviderProjection {
                coordinate: record.coordinate,
                phase: record.phase,
                live_effects: record.live_effects,
                live_components: record.live_components,
                admitted_components: record.admitted_components,
                released_components: record.released_components,
            })
            .collect();
        let effects = self
            .effects
            .values()
            .map(|record| record.projection.clone())
            .collect();
        LifecycleProjection {
            world: self.world,
            revision: self.revision,
            providers,
            effects,
        }
    }

    /// Registers a strictly newer provider generation after the predecessor
    /// has become a retired tombstone.
    pub fn register_provider(
        &mut self,
        provider: ProviderId,
        generation: ProviderGeneration,
    ) -> Result<ProviderCoordinate, LifecycleError> {
        let high_water = self.high_water.get(&provider).copied();
        if high_water.is_some_and(|old| generation <= old) {
            return Err(LifecycleError::GenerationRollback);
        }
        if let Some(old_generation) = self.current.get(&provider).copied() {
            let old_coordinate = ProviderCoordinate::new(self.world, provider, old_generation);
            let old = self
                .providers
                .get(&old_coordinate)
                .ok_or(LifecycleError::UnknownProviderGeneration)?;
            if !old.phase.is_retired() {
                return Err(LifecycleError::GenerationStillLive);
            }
        }
        let coordinate = ProviderCoordinate::new(self.world, provider, generation);
        let record = ProviderRecord {
            coordinate,
            phase: ProviderPhase::Active { epoch: 1 },
            live_effects: 0,
            live_components: 0,
            admitted_components: 0,
            released_components: 0,
        };
        self.high_water.insert(provider, generation);
        self.current.insert(provider, generation);
        self.providers.insert(coordinate, record);
        self.bump_revision();
        Ok(coordinate)
    }

    /// Admits one fixed-size scoped effect under an active generation.
    pub fn admit_effect(
        &mut self,
        effect: EffectId,
        coordinate: ProviderCoordinate,
        components: &[ComponentId],
    ) -> Result<(), LifecycleError> {
        if self.effects.contains_key(&effect) {
            return Err(LifecycleError::EffectAlreadyExists);
        }
        let operation = effect.operation();
        if self.operations.contains_key(&operation) {
            return Err(LifecycleError::OperationAlreadyExists);
        }
        if coordinate.world() != self.world {
            return Err(LifecycleError::WrongWorld);
        }
        if components.is_empty() || components.len() > MAX_COMPONENTS {
            return Err(LifecycleError::ComponentOutOfBounds);
        }
        if (0..components.len()).any(|left| {
            components[left + 1..]
                .iter()
                .any(|component| *component == components[left])
        }) {
            return Err(LifecycleError::InvalidIdentity);
        }
        let component_count = components.len() as u8;
        let mut component_ids = [ComponentId::Reply; MAX_COMPONENTS];
        component_ids[..components.len()].copy_from_slice(components);
        let record = self.current_record_mut(coordinate)?;
        if !record.phase.admits_execution() {
            return Err(LifecycleError::WrongProviderPhase);
        }
        let projection = EffectProjection {
            effect,
            provider: coordinate,
            component_ids,
            component_count,
            components: [ComponentLifecycle::Staged; MAX_COMPONENTS],
        };
        record.live_effects = next(record.live_effects);
        record.live_components = record
            .live_components
            .checked_add(u64::from(component_count))
            .ok_or(LifecycleError::InvalidIdentity)?;
        record.admitted_components = record
            .admitted_components
            .checked_add(u64::from(component_count))
            .ok_or(LifecycleError::InvalidIdentity)?;
        self.effects.insert(effect, EffectRecord { projection });
        self.operations.insert(operation, effect);
        self.bump_revision();
        Ok(())
    }

    /// Records the unique commit intent for a staged component.
    pub fn commit_intent(
        &mut self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<(), LifecycleError> {
        let coordinate = self.effect_coordinate(effect)?;
        let phase = self
            .provider_phase(coordinate)
            .ok_or(LifecycleError::UnknownProviderGeneration)?;
        if !phase.admits_execution() {
            return Err(LifecycleError::ExecutionFenced);
        }
        let state = self.component_state(effect, component)?;
        if state != ComponentLifecycle::Staged {
            return Err(LifecycleError::WrongComponentState);
        }
        self.set_component_state(effect, component, ComponentLifecycle::CommitIntent);
        self.bump_revision();
        Ok(())
    }

    /// Performs new provider execution for an already durable commit intent.
    pub fn execute(
        &mut self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<(), LifecycleError> {
        let coordinate = self.effect_coordinate(effect)?;
        let phase = self
            .provider_phase(coordinate)
            .ok_or(LifecycleError::UnknownProviderGeneration)?;
        if !phase.admits_execution() {
            return Err(LifecycleError::ExecutionFenced);
        }
        if self.component_state(effect, component)? != ComponentLifecycle::CommitIntent {
            return Err(LifecycleError::WrongComponentState);
        }
        self.set_component_state(effect, component, ComponentLifecycle::Executed);
        self.bump_revision();
        Ok(())
    }

    /// Records an outcome for an escaped component, including after a fence.
    pub fn record_outcome(
        &mut self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<(), LifecycleError> {
        let coordinate = self.effect_coordinate(effect)?;
        if self.provider_phase(coordinate).is_none() {
            return Err(LifecycleError::UnknownProviderGeneration);
        }
        if !self.component_state(effect, component)?.is_escaped() {
            return Err(LifecycleError::WrongComponentState);
        }
        self.set_component_state(effect, component, ComponentLifecycle::Outcome);
        self.bump_revision();
        Ok(())
    }

    /// Settles an outcome-bearing component.
    pub fn settle(
        &mut self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<(), LifecycleError> {
        let coordinate = self.effect_coordinate(effect)?;
        if self.provider_phase(coordinate).is_none() {
            return Err(LifecycleError::UnknownProviderGeneration);
        }
        if self.component_state(effect, component)? != ComponentLifecycle::Outcome {
            return Err(LifecycleError::OutcomeRequired);
        }
        self.set_component_state(effect, component, ComponentLifecycle::Settled);
        self.bump_revision();
        Ok(())
    }

    /// Releases one component.  A staged component is an abandoned precommit;
    /// every escaped component must first record outcome and settlement.
    pub fn release(
        &mut self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<(), LifecycleError> {
        let coordinate = self.effect_coordinate(effect)?;
        let phase = self
            .provider_phase(coordinate)
            .ok_or(LifecycleError::UnknownProviderGeneration)?;
        let state = self.component_state(effect, component)?;
        if state.is_released() {
            return Err(LifecycleError::AlreadyReleased);
        }
        if matches!(
            state,
            ComponentLifecycle::CommitIntent
                | ComponentLifecycle::Executed
                | ComponentLifecycle::Outcome
        ) {
            return Err(LifecycleError::OutcomeRequired);
        }
        if state == ComponentLifecycle::Settled || state == ComponentLifecycle::Staged {
            if state == ComponentLifecycle::Staged && phase.admits_execution() {
                // Explicit precommit abandonment is safe while authority is
                // still active; after a fence it is the only way to drain it.
            }
            self.set_component_state(effect, component, ComponentLifecycle::Released);
            let effect_fully_released = self.effect_is_fully_released(effect)?;
            let record = self.current_record_mut(coordinate)?;
            record.live_components = record
                .live_components
                .checked_sub(1)
                .ok_or(LifecycleError::InvalidIdentity)?;
            record.released_components = record
                .released_components
                .checked_add(1)
                .ok_or(LifecycleError::InvalidIdentity)?;
            if effect_fully_released {
                record.live_effects = record
                    .live_effects
                    .checked_sub(1)
                    .ok_or(LifecycleError::InvalidIdentity)?;
            }
            self.bump_revision();
            return Ok(());
        }
        Err(LifecycleError::WrongComponentState)
    }

    /// Fences provider execution at one unique authority epoch.
    pub fn fence_provider(&mut self, coordinate: ProviderCoordinate) -> Result<(), LifecycleError> {
        let record = self.current_record_mut(coordinate)?;
        let epoch = record.phase.epoch();
        if !matches!(record.phase, ProviderPhase::Active { .. }) {
            return Err(LifecycleError::InvalidPhaseTransition);
        }
        record.phase = ProviderPhase::EffectFenced { epoch: next(epoch) };
        self.bump_revision();
        Ok(())
    }

    /// Enters settlement-only mode after all precommit components are gone.
    pub fn enter_settlement_only(
        &mut self,
        coordinate: ProviderCoordinate,
    ) -> Result<(), LifecycleError> {
        let phase = self
            .provider_phase(coordinate)
            .ok_or(LifecycleError::UnknownProviderGeneration)?;
        if !matches!(phase, ProviderPhase::EffectFenced { .. }) {
            return Err(LifecycleError::InvalidPhaseTransition);
        }
        if self.effects.values().any(|effect| {
            effect.projection.provider == coordinate
                && effect.projection.components[..effect.projection.component_count as usize]
                    .iter()
                    .any(|state| {
                        matches!(
                            state,
                            ComponentLifecycle::Staged
                                | ComponentLifecycle::CommitIntent
                                | ComponentLifecycle::Executed
                        )
                    })
        }) {
            return Err(LifecycleError::PrecommitStillLive);
        }
        let record = self.current_record_mut(coordinate)?;
        let epoch = record.phase.epoch();
        record.phase = ProviderPhase::SettlementOnly { epoch: next(epoch) };
        self.bump_revision();
        Ok(())
    }

    /// Retires a provider generation after every component is released.
    pub fn retire_provider(
        &mut self,
        coordinate: ProviderCoordinate,
    ) -> Result<(), LifecycleError> {
        let record = self.current_record_mut(coordinate)?;
        if !matches!(record.phase, ProviderPhase::SettlementOnly { .. }) {
            return Err(LifecycleError::InvalidPhaseTransition);
        }
        if record.live_components != 0 || record.live_effects != 0 {
            return Err(LifecycleError::LiveEffectsRemain);
        }
        let epoch = record.phase.epoch();
        record.phase = ProviderPhase::Retired { epoch: next(epoch) };
        self.bump_revision();
        Ok(())
    }

    /// Applies one independent command to the oracle.
    pub fn apply(&mut self, command: LifecycleCommand) -> Result<(), LifecycleError> {
        match command {
            LifecycleCommand::Register {
                provider,
                generation,
            } => self.register_provider(provider, generation).map(|_| ()),
            LifecycleCommand::Admit {
                effect,
                provider,
                generation,
                components,
            } => self.admit_effect(
                effect,
                ProviderCoordinate::new(self.world, provider, generation),
                &components,
            ),
            LifecycleCommand::CommitIntent { effect, component } => {
                self.commit_intent(effect, component)
            }
            LifecycleCommand::Execute { effect, component } => self.execute(effect, component),
            LifecycleCommand::Outcome { effect, component } => {
                self.record_outcome(effect, component)
            }
            LifecycleCommand::Settle { effect, component } => self.settle(effect, component),
            LifecycleCommand::Release { effect, component } => self.release(effect, component),
            LifecycleCommand::Fence {
                provider,
                generation,
            } => self.fence_provider(ProviderCoordinate::new(self.world, provider, generation)),
            LifecycleCommand::SettlementOnly {
                provider,
                generation,
            } => self
                .enter_settlement_only(ProviderCoordinate::new(self.world, provider, generation)),
            LifecycleCommand::Retire {
                provider,
                generation,
            } => self.retire_provider(ProviderCoordinate::new(self.world, provider, generation)),
        }
    }

    /// Checks provider, effect, phase, and release-counter conservation.
    #[must_use]
    pub fn check_invariants(&self) -> bool {
        let mut computed_live_components = BTreeMap::<ProviderCoordinate, u64>::new();
        let mut computed_live_effects = BTreeMap::<ProviderCoordinate, u64>::new();
        let mut computed_released = BTreeMap::<ProviderCoordinate, u64>::new();
        for effect in self.effects.values() {
            let coordinate = effect.projection.provider;
            let active_ids =
                &effect.projection.component_ids[..effect.projection.component_count as usize];
            if active_ids.iter().any(|component| component.get() == 0)
                || (0..active_ids.len()).any(|left| {
                    active_ids[left + 1..]
                        .iter()
                        .any(|component| *component == active_ids[left])
                })
            {
                return false;
            }
            let mut live = 0_u64;
            let mut released = 0_u64;
            for state in effect.projection.components[..effect.projection.component_count as usize]
                .iter()
                .copied()
            {
                if state.is_released() {
                    released += 1;
                } else {
                    live += 1;
                }
            }
            *computed_live_components.entry(coordinate).or_default() += live;
            *computed_released.entry(coordinate).or_default() += released;
            if live != 0 {
                *computed_live_effects.entry(coordinate).or_default() += 1;
            }
            if effect.projection.components[effect.projection.component_count as usize..]
                .iter()
                .any(|state| *state != ComponentLifecycle::Staged)
            {
                return false;
            }
        }
        for (coordinate, record) in &self.providers {
            if record.coordinate != *coordinate
                || record.coordinate.world() != self.world
                || record.phase.epoch() == 0
                || record.live_components
                    != computed_live_components
                        .get(coordinate)
                        .copied()
                        .unwrap_or(0)
                || record.released_components
                    != computed_released.get(coordinate).copied().unwrap_or(0)
                || record.live_effects
                    != computed_live_effects.get(coordinate).copied().unwrap_or(0)
                || record.admitted_components != record.live_components + record.released_components
            {
                return false;
            }
            if record.phase.is_retired() && record.live_components != 0 {
                return false;
            }
        }
        for (provider, high) in &self.high_water {
            let Some(current) = self.current.get(provider) else {
                return false;
            };
            if *high < *current {
                return false;
            }
        }
        self.operations.iter().all(|(operation, effect)| {
            self.effects
                .get(effect)
                .is_some_and(|record| record.projection.effect.operation() == *operation)
        })
    }

    fn current_record_mut(
        &mut self,
        coordinate: ProviderCoordinate,
    ) -> Result<&mut ProviderRecord, LifecycleError> {
        if coordinate.world() != self.world {
            return Err(LifecycleError::WrongWorld);
        }
        let current = self.current.get(&coordinate.provider()).copied();
        if current != Some(coordinate.generation()) {
            return Err(if self.providers.contains_key(&coordinate) {
                LifecycleError::NotCurrentGeneration
            } else {
                LifecycleError::UnknownProviderGeneration
            });
        }
        self.providers
            .get_mut(&coordinate)
            .ok_or(LifecycleError::UnknownProviderGeneration)
    }

    fn effect_coordinate(&self, effect: EffectId) -> Result<ProviderCoordinate, LifecycleError> {
        self.effects
            .get(&effect)
            .map(|record| record.projection.provider)
            .ok_or(LifecycleError::UnknownEffect)
    }

    fn component_state(
        &self,
        effect: EffectId,
        component: ComponentId,
    ) -> Result<ComponentLifecycle, LifecycleError> {
        let record = self
            .effects
            .get(&effect)
            .ok_or(LifecycleError::UnknownEffect)?;
        let index = record.projection.component_ids[..record.projection.component_count as usize]
            .iter()
            .position(|candidate| *candidate == component)
            .ok_or(LifecycleError::ComponentOutOfBounds)?;
        Ok(record.projection.components[index])
    }

    fn set_component_state(
        &mut self,
        effect: EffectId,
        component: ComponentId,
        state: ComponentLifecycle,
    ) {
        if let Some(record) = self.effects.get_mut(&effect)
            && let Some(index) = record.projection.component_ids
                [..record.projection.component_count as usize]
                .iter()
                .position(|candidate| *candidate == component)
        {
            record.projection.components[index] = state;
        }
    }

    fn effect_is_fully_released(&self, effect: EffectId) -> Result<bool, LifecycleError> {
        let record = self
            .effects
            .get(&effect)
            .ok_or(LifecycleError::UnknownEffect)?;
        Ok(
            record.projection.components[..record.projection.component_count as usize]
                .iter()
                .all(|state| state.is_released()),
        )
    }

    fn bump_revision(&mut self) {
        self.revision = next(self.revision);
    }
}

/// Independent command set used by sequence/property tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleCommand {
    /// Register a provider generation.
    Register {
        /// Stable provider identity.
        provider: ProviderId,
        /// Monotonic provider generation.
        generation: ProviderGeneration,
    },
    /// Admit a bounded effect.
    Admit {
        /// Stable effect identity.
        effect: EffectId,
        /// Stable provider identity.
        provider: ProviderId,
        /// Exact provider generation.
        generation: ProviderGeneration,
        /// Explicit component identities in catalog order.
        components: Vec<ComponentId>,
    },
    /// Record commit intent for one component.
    CommitIntent {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact component slot.
        component: ComponentId,
    },
    /// Execute one committed component.
    Execute {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact component slot.
        component: ComponentId,
    },
    /// Record an escaped outcome.
    Outcome {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact component slot.
        component: ComponentId,
    },
    /// Settle one outcome-bearing component.
    Settle {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact component slot.
        component: ComponentId,
    },
    /// Release one staged or settled component.
    Release {
        /// Stable effect identity.
        effect: EffectId,
        /// Exact component slot.
        component: ComponentId,
    },
    /// Fence one provider generation.
    Fence {
        /// Stable provider identity.
        provider: ProviderId,
        /// Exact provider generation.
        generation: ProviderGeneration,
    },
    /// Enter settlement-only mode.
    SettlementOnly {
        /// Stable provider identity.
        provider: ProviderId,
        /// Exact provider generation.
        generation: ProviderGeneration,
    },
    /// Retire one provider generation.
    Retire {
        /// Stable provider identity.
        provider: ProviderId,
        /// Exact provider generation.
        generation: ProviderGeneration,
    },
}

const fn next(value: u64) -> u64 {
    match value.checked_add(1) {
        Some(next) => next,
        None => panic!("provider lifecycle oracle exhausted"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (WorldId, ProviderId, ProviderGeneration, ProviderCoordinate) {
        let world = WorldId::new(1).unwrap();
        let provider = ProviderId::new(7).unwrap();
        let generation = ProviderGeneration::new(1).unwrap();
        (
            world,
            provider,
            generation,
            ProviderCoordinate::new(world, provider, generation),
        )
    }

    #[test]
    fn generation_high_water_requires_retired_predecessor() {
        let (world, provider, generation, coordinate) = ids();
        let mut oracle = ProviderLifecycleOracle::new(world);
        oracle.register_provider(provider, generation).unwrap();
        assert_eq!(
            oracle.register_provider(provider, ProviderGeneration::new(1).unwrap()),
            Err(LifecycleError::GenerationRollback)
        );
        assert_eq!(
            oracle.register_provider(provider, ProviderGeneration::new(2).unwrap()),
            Err(LifecycleError::GenerationStillLive)
        );
        oracle.fence_provider(coordinate).unwrap();
        oracle.enter_settlement_only(coordinate).unwrap();
        oracle.retire_provider(coordinate).unwrap();
        let next = oracle
            .register_provider(provider, ProviderGeneration::new(2).unwrap())
            .unwrap();
        assert_eq!(next.generation().get(), 2);
        assert_eq!(oracle.high_water(provider).unwrap().get(), 2);
        assert!(oracle.check_invariants());
    }

    #[test]
    fn fence_and_intent_have_one_serial_winner() {
        let (world, provider, generation, coordinate) = ids();
        let operation = OperationId::new(20).unwrap();
        let effect = EffectId::new(operation, 1).unwrap();
        let component = ComponentId::new(1).unwrap();

        let mut fence_first = ProviderLifecycleOracle::new(world);
        fence_first.register_provider(provider, generation).unwrap();
        fence_first.fence_provider(coordinate).unwrap();
        fence_first
            .admit_effect(effect, coordinate, &[component])
            .unwrap_err();

        let mut intent_first = ProviderLifecycleOracle::new(world);
        intent_first
            .register_provider(provider, generation)
            .unwrap();
        intent_first
            .admit_effect(effect, coordinate, &[component])
            .unwrap();
        intent_first.commit_intent(effect, component).unwrap();
        intent_first.fence_provider(coordinate).unwrap();
        assert_eq!(
            intent_first.execute(effect, component),
            Err(LifecycleError::ExecutionFenced)
        );
        intent_first.record_outcome(effect, component).unwrap();
        intent_first.settle(effect, component).unwrap();
        intent_first.release(effect, component).unwrap();
        assert!(intent_first.check_invariants());
    }

    #[test]
    fn settlement_only_allows_only_outcome_settle_release() {
        let (world, provider, generation, coordinate) = ids();
        let operation = OperationId::new(40).unwrap();
        let effect = EffectId::new(operation, 1).unwrap();
        let component = ComponentId::new(1).unwrap();
        let mut oracle = ProviderLifecycleOracle::new(world);
        oracle.register_provider(provider, generation).unwrap();
        oracle
            .admit_effect(effect, coordinate, &[component])
            .unwrap();
        oracle.commit_intent(effect, component).unwrap();
        oracle.fence_provider(coordinate).unwrap();
        assert_eq!(
            oracle.enter_settlement_only(coordinate),
            Err(LifecycleError::PrecommitStillLive)
        );
        oracle.record_outcome(effect, component).unwrap();
        oracle.settle(effect, component).unwrap();
        oracle.release(effect, component).unwrap();
        oracle.enter_settlement_only(coordinate).unwrap();
        assert_eq!(
            oracle.commit_intent(effect, component),
            Err(LifecycleError::ExecutionFenced)
        );
        assert_eq!(
            oracle.execute(effect, component),
            Err(LifecycleError::ExecutionFenced)
        );
        oracle.retire_provider(coordinate).unwrap();
        assert!(oracle.check_invariants());
    }

    #[test]
    fn release_counters_conserve_bounded_components() {
        let (world, provider, generation, coordinate) = ids();
        let mut oracle = ProviderLifecycleOracle::new(world);
        oracle.register_provider(provider, generation).unwrap();
        oracle
            .admit_effect(
                EffectId::new(OperationId::new(51).unwrap(), 1).unwrap(),
                coordinate,
                &[ComponentId::new(3).unwrap(), ComponentId::new(7).unwrap()],
            )
            .unwrap();
        let projection = &oracle.projection().effects[0];
        assert_eq!(projection.component_count, 2);
        assert_eq!(projection.component_ids[0].get(), 3);
        assert_eq!(projection.component_ids[1].get(), 7);
        assert_eq!(oracle.projection().providers[0].live_components, 2);
        for raw in [3, 7] {
            oracle
                .release(
                    EffectId::new(OperationId::new(51).unwrap(), 1).unwrap(),
                    ComponentId::new(raw).unwrap(),
                )
                .unwrap();
        }
        let provider_projection = &oracle.projection().providers[0];
        assert_eq!(provider_projection.live_components, 0);
        assert_eq!(
            provider_projection.admitted_components,
            provider_projection.released_components
        );
        assert_eq!(provider_projection.live_effects, 0);
        assert!(oracle.check_invariants());
    }
}
