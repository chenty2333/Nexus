// SPDX-License-Identifier: MPL-2.0

//! Shared Linux-personality runtime shell.
//!
//! The generic registry stays unaware of futex keys and readiness objects.
//! Each domain instantiates a typed resource index here, while one outer OSTD
//! spin lock keeps domain mutations and generic reverse-index mutations in the
//! same critical section.

#![allow(dead_code)]

use alloc::collections::{BTreeMap, BTreeSet};

use ostd::sync::SpinLock;

use crate::effect_registry::{
    CommitMetadata, CommitOutcome, EffectKey, EffectRegistry, PortalHandle, PublicationTicket,
    RegistryError, ResourceKey, ResourceMove, TaskKey,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct TypedResourceRecord {
    identity: ResourceKey,
    effects: BTreeSet<EffectKey>,
}

/// Maps a domain-owned key to an opaque generational resource identity.
///
/// `K` may later be a private-futex `(address-space, generation, uaddr)` key or
/// an epoll/readiness source key.  Neither representation leaks into
/// [`EffectRegistry`].
#[derive(Debug)]
pub(crate) struct TypedResourceIndex<K> {
    namespace: u32,
    next_id: u64,
    records: BTreeMap<K, TypedResourceRecord>,
    reverse: BTreeMap<EffectKey, BTreeSet<K>>,
}

impl<K> TypedResourceIndex<K>
where
    K: Clone + Ord,
{
    pub(crate) fn new(namespace: u32) -> Self {
        Self {
            namespace,
            next_id: 1,
            records: BTreeMap::new(),
            reverse: BTreeMap::new(),
        }
    }

    pub(crate) fn intern(&mut self, key: K) -> Result<ResourceKey, RegistryError> {
        if let Some(record) = self.records.get(&key) {
            return Ok(record.identity);
        }
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let identity = ResourceKey::new(self.namespace, id, 1);
        self.records.insert(
            key,
            TypedResourceRecord {
                identity,
                effects: BTreeSet::new(),
            },
        );
        Ok(identity)
    }

    pub(crate) fn identity(&self, key: &K) -> Option<ResourceKey> {
        self.records.get(key).map(|record| record.identity)
    }

    /// Adds the domain-side edge after the effect has been registered with the
    /// same opaque resource identity in `EffectRegistry`.
    pub(crate) fn attach(
        &mut self,
        registry: &EffectRegistry,
        key: &K,
        effect: EffectKey,
    ) -> Result<(), RegistryError> {
        let record = self
            .records
            .get_mut(key)
            .ok_or(RegistryError::InvalidState)?;
        let view = registry.effect_view(effect)?;
        if !view.current_resources.contains(&record.identity)
            || !registry
                .effects_for_resource(record.identity)
                .contains(&effect)
            || !record.effects.insert(effect)
        {
            return Err(RegistryError::InvalidState);
        }
        self.reverse.entry(effect).or_default().insert(key.clone());
        Ok(())
    }

    /// Removes the domain-side edge in the same outer critical section in
    /// which the registry stages the effect's terminal state.
    pub(crate) fn detach(&mut self, key: &K, effect: EffectKey) -> Result<(), RegistryError> {
        let record = self
            .records
            .get_mut(key)
            .ok_or(RegistryError::InvalidState)?;
        if !record.effects.remove(&effect) {
            return Err(RegistryError::InvalidState);
        }
        let remove_reverse = {
            let keys = self
                .reverse
                .get_mut(&effect)
                .ok_or(RegistryError::InvalidState)?;
            if !keys.remove(key) {
                return Err(RegistryError::InvalidState);
            }
            keys.is_empty()
        };
        if remove_reverse {
            self.reverse.remove(&effect);
        }
        Ok(())
    }

    pub(crate) fn detach_effect(&mut self, effect: EffectKey) -> Result<(), RegistryError> {
        let keys = self.reverse.get(&effect).cloned().unwrap_or_default();
        for key in keys {
            self.detach(&key, effect)?;
        }
        Ok(())
    }

    pub(crate) fn effects(&self, key: &K) -> BTreeSet<EffectKey> {
        self.records
            .get(key)
            .map_or_else(BTreeSet::new, |record| record.effects.clone())
    }

    fn validate_move_before(
        &self,
        registry: &EffectRegistry,
        source: &K,
        target: &K,
        effect: EffectKey,
    ) -> Result<(), RegistryError> {
        if source == target {
            return Err(RegistryError::InvalidState);
        }
        let source_record = self
            .records
            .get(source)
            .ok_or(RegistryError::InvalidState)?;
        let target_record = self
            .records
            .get(target)
            .ok_or(RegistryError::InvalidState)?;
        let view = registry.effect_view(effect)?;
        if !source_record.effects.contains(&effect)
            || target_record.effects.contains(&effect)
            || self
                .reverse
                .get(&effect)
                .is_none_or(|keys| keys.len() != 1 || !keys.contains(source))
            || view.current_resources.len() != 1
            || !view.current_resources.contains(&source_record.identity)
            || view.current_resources.contains(&target_record.identity)
            || !registry
                .effects_for_resource(source_record.identity)
                .contains(&effect)
            || registry
                .effects_for_resource(target_record.identity)
                .contains(&effect)
        {
            return Err(RegistryError::InvalidState);
        }
        Ok(())
    }

    fn move_after_registry(
        &mut self,
        registry: &EffectRegistry,
        source: &K,
        target: &K,
        effect: EffectKey,
    ) -> Result<(), RegistryError> {
        let source_identity = self
            .records
            .get(source)
            .ok_or(RegistryError::InvalidState)?
            .identity;
        let target_identity = self
            .records
            .get(target)
            .ok_or(RegistryError::InvalidState)?
            .identity;
        let view = registry.effect_view(effect)?;
        if view.current_resources.len() != 1
            || !view.current_resources.contains(&target_identity)
            || view.current_resources.contains(&source_identity)
            || registry
                .effects_for_resource(source_identity)
                .contains(&effect)
            || !registry
                .effects_for_resource(target_identity)
                .contains(&effect)
        {
            return Err(RegistryError::InvalidState);
        }

        let source_record = self.records.get_mut(source).unwrap();
        if !source_record.effects.remove(&effect) {
            return Err(RegistryError::InvalidState);
        }
        let target_record = self.records.get_mut(target).unwrap();
        if !target_record.effects.insert(effect) {
            return Err(RegistryError::InvalidState);
        }
        let keys = self
            .reverse
            .get_mut(&effect)
            .ok_or(RegistryError::InvalidState)?;
        if !keys.remove(source) || !keys.insert(target.clone()) || keys.len() != 1 {
            return Err(RegistryError::InvalidState);
        }
        Ok(())
    }

    pub(crate) fn retire(&mut self, key: &K) -> Result<ResourceKey, RegistryError> {
        let record = self.records.get(key).ok_or(RegistryError::InvalidState)?;
        if !record.effects.is_empty() {
            return Err(RegistryError::NotQuiescent);
        }
        Ok(self.records.remove(key).unwrap().identity)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.records.is_empty() && self.reverse.is_empty()
    }

    pub(crate) fn check_invariants(&self, registry: &EffectRegistry) -> Result<(), RegistryError> {
        let mut expected_reverse: BTreeMap<EffectKey, BTreeSet<K>> = BTreeMap::new();
        let mut identities = BTreeSet::new();
        for (key, record) in &self.records {
            if record.identity.namespace() != self.namespace
                || record.identity.generation() == 0
                || !identities.insert(record.identity)
            {
                return Err(RegistryError::Invariant("typed resource identity mismatch"));
            }
            if registry.effects_for_resource(record.identity) != record.effects {
                return Err(RegistryError::Invariant(
                    "typed resource membership mismatch",
                ));
            }
            for effect in &record.effects {
                expected_reverse
                    .entry(*effect)
                    .or_default()
                    .insert(key.clone());
            }
        }
        if expected_reverse != self.reverse {
            return Err(RegistryError::Invariant(
                "typed resource reverse index mismatch",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct LinuxRuntimeState<FutexKey, ReadinessKey>
where
    FutexKey: Clone + Ord,
    ReadinessKey: Clone + Ord,
{
    pub(crate) effects: EffectRegistry,
    pub(crate) futex: TypedResourceIndex<FutexKey>,
    pub(crate) readiness: TypedResourceIndex<ReadinessKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TypedResourceMove<K> {
    pub(crate) source: K,
    pub(crate) target: K,
    pub(crate) handle: PortalHandle,
}

impl<FutexKey, ReadinessKey> LinuxRuntimeState<FutexKey, ReadinessKey>
where
    FutexKey: Clone + Ord,
    ReadinessKey: Clone + Ord,
{
    pub(crate) fn new(futex_namespace: u32, readiness_namespace: u32) -> Self {
        assert_ne!(futex_namespace, readiness_namespace);
        Self {
            effects: EffectRegistry::new(),
            futex: TypedResourceIndex::new(futex_namespace),
            readiness: TypedResourceIndex::new(readiness_namespace),
        }
    }

    pub(crate) fn check_invariants(&self) -> Result<(), RegistryError> {
        self.effects.check_invariants()?;
        self.futex.check_invariants(&self.effects)?;
        self.readiness.check_invariants(&self.effects)?;
        Ok(())
    }

    /// Commits one futex domain transaction and migrates each typed queue edge
    /// under the same outer runtime lock as the generic reverse-index move.
    pub(crate) fn commit_futex_with_moves(
        &mut self,
        sender: TaskKey,
        commits: &[(PortalHandle, CommitMetadata)],
        moves: &[TypedResourceMove<FutexKey>],
    ) -> Result<alloc::vec::Vec<CommitOutcome>, RegistryError> {
        let mut registry_moves = alloc::vec::Vec::with_capacity(moves.len());
        for movement in moves {
            let effect = movement.handle.effect();
            self.futex.validate_move_before(
                &self.effects,
                &movement.source,
                &movement.target,
                effect,
            )?;
            let target = self
                .futex
                .identity(&movement.target)
                .ok_or(RegistryError::InvalidState)?;
            registry_moves.push(ResourceMove {
                handle: movement.handle,
                current_resources: alloc::vec![target],
            });
        }

        let outcomes = self
            .effects
            .commit_with_moves(sender, commits, &registry_moves)?;
        for movement in moves {
            self.futex
                .move_after_registry(
                    &self.effects,
                    &movement.source,
                    &movement.target,
                    movement.handle.effect(),
                )
                .expect("typed move was validated before generic commit");
        }
        Ok(outcomes)
    }
}

/// One lock is intentionally outside the generic registry so a futex requeue
/// or readiness transition can mutate its typed index and the CSER reverse
/// indexes atomically.
#[derive(Debug)]
pub(crate) struct LinuxRuntime<FutexKey, ReadinessKey>
where
    FutexKey: Clone + Ord,
    ReadinessKey: Clone + Ord,
{
    state: SpinLock<LinuxRuntimeState<FutexKey, ReadinessKey>>,
}

impl<FutexKey, ReadinessKey> LinuxRuntime<FutexKey, ReadinessKey>
where
    FutexKey: Clone + Ord,
    ReadinessKey: Clone + Ord,
{
    pub(crate) fn new(futex_namespace: u32, readiness_namespace: u32) -> Self {
        Self {
            state: SpinLock::new(LinuxRuntimeState::new(futex_namespace, readiness_namespace)),
        }
    }

    pub(crate) fn with_state<T>(
        &self,
        operation: impl FnOnce(&mut LinuxRuntimeState<FutexKey, ReadinessKey>) -> T,
    ) -> T {
        operation(&mut self.state.lock())
    }

    pub(crate) fn check_invariants(&self) -> Result<(), RegistryError> {
        self.state.lock().check_invariants()
    }
}

/// Couples the registry's ticket to domain-owned continuation state.  The
/// caller extracts this value under `LinuxRuntime`'s lock, publishes `work`
/// outside the lock, then acknowledges `ticket` in a second critical section.
#[derive(Debug)]
pub(crate) struct PublicationWork<W> {
    ticket: PublicationTicket,
    work: W,
}

impl<W> PublicationWork<W> {
    pub(crate) const fn new(ticket: PublicationTicket, work: W) -> Self {
        Self { ticket, work }
    }

    pub(crate) fn into_parts(self) -> (PublicationTicket, W) {
        (self.ticket, self.work)
    }
}
