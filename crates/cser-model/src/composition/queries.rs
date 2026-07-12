use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::*;

impl CompositionModel {
    /// Returns a read-only root scope projection.
    #[must_use]
    pub fn scope(&self, scope: ScopeId) -> Option<CompositionScopeView> {
        let record = self.scopes.get(&scope)?;
        Some(CompositionScopeView {
            state: record.state,
            authority_epoch: record.authority_epoch,
            initial_credits: record.initial_credits,
            free_credits: record.free_credits,
            domains: record.domains.keys().copied().collect(),
            frozen_domains: record.revocation.as_ref().map_or_else(Vec::new, |revoke| {
                revoke.frozen_domains.iter().copied().collect()
            }),
        })
    }

    /// Returns a read-only domain projection.
    #[must_use]
    pub fn domain(&self, scope: ScopeId, domain: DomainId) -> Option<DomainView> {
        let record = self.scopes.get(&scope)?.domains.get(&domain)?;
        Some(DomainView {
            service: record.service,
            binding_epoch: record.binding_epoch,
            device_generation: record.device_generation,
            fallback: record.fallback,
            live_effects: record.live_effects.iter().copied().collect(),
            leaf_effects: record.leaf_effects.iter().copied().collect(),
            adoption_cohort: record.recovery_cohort.iter().copied().collect(),
            tombstones: record.tombstones.iter().copied().collect(),
            mutation_generation: record.mutation_generation,
            closure_revision: record.closure_revision,
        })
    }

    /// Returns a read-only effect projection.
    #[must_use]
    pub fn effect(&self, effect: EffectId) -> Option<CompositionEffectView> {
        let record = self.effects.get(&effect)?;
        Some(CompositionEffectView {
            token: record.token,
            parent: record.parent,
            live_children: record.live_children.iter().copied().collect(),
            state: record.state,
            held_credits: record.held_credits,
            commit_receipt: record.commit_receipt,
            tombstone: record.tombstone,
            external_quiesced: record.external_quiesced,
            terminalizations: record.terminalizations,
        })
    }

    /// Returns a read-only tombstone projection.
    #[must_use]
    pub fn tombstone(&self, tombstone: TombstoneId) -> Option<TombstoneView> {
        let record = self.tombstones.get(&tombstone)?;
        Some(TombstoneView {
            scope: record.scope,
            domain: record.domain,
            effect: record.effect,
            device_generation: record.device_generation,
            retained_credits: record.retained_credits,
            state: record.state,
            attempts: record.attempts,
        })
    }

    /// Returns bounded closure progress for one frozen domain.
    #[must_use]
    pub fn closure_progress(
        &self,
        scope: ScopeId,
        domain: DomainId,
    ) -> Option<DomainClosureProgress> {
        let scope_record = self.scopes.get(&scope)?;
        let revocation = scope_record.revocation.as_ref()?;
        let progress = revocation.progress.get(&domain)?;
        let remaining = scope_record.domains.get(&domain)?.live_effects.len();
        Some(DomainClosureProgress {
            target_count: progress.target_count,
            terminalized: progress.terminalized,
            index_selections: progress.index_selections,
            remaining,
            receipt_accepted: revocation.accepted.contains_key(&domain),
        })
    }

    /// Returns the number of global effect records, for negative scan tests.
    #[must_use]
    pub fn global_effect_count(&self) -> usize {
        self.effects.len()
    }

    /// Audits graph identity, local indexes, credits, recovery, and closure.
    pub fn check_invariants(&self) -> Result<(), CompositionInvariantViolation> {
        for (scope_id, scope) in &self.scopes {
            let mut accounted = scope.free_credits;
            for (effect_id, effect) in &self.effects {
                if effect.token.scope != *scope_id {
                    continue;
                }
                if effect.token.effect != *effect_id
                    || effect.parent != effect.token.parent
                    || effect.kind_domain() != effect.token.domain
                    || effect.token.authority_epoch.get() > scope.authority_epoch.get()
                    || (effect.token.domain != DomainId::VirtIo
                        && effect.token.device_generation != DeviceGeneration::new(1))
                {
                    return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                }
                let Some(owner) = scope.domains.get(&effect.token.domain) else {
                    return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                };
                if effect.token.binding_epoch.get() > owner.binding_epoch.get()
                    || effect.token.device_generation.get() > owner.device_generation.get()
                {
                    return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                }
                if effect.state.is_terminal() {
                    if effect.terminalizations != 1 || !effect.held_credits.is_zero() {
                        return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                    }
                } else {
                    if effect.terminalizations != 0 {
                        return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                    }
                    accounted = accounted.checked_add(effect.held_credits).map_err(|_| {
                        CompositionInvariantViolation::CreditConservation(*scope_id)
                    })?;
                }
                if effect.state == CompositionEffectState::Tombstoned
                    && (effect.tombstone.is_none()
                        || effect.external_quiesced
                        || effect.commit_receipt.is_none())
                {
                    return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                }
                if effect.external_quiesced
                    && !matches!(
                        effect.state,
                        CompositionEffectState::Committed | CompositionEffectState::Completed
                    )
                {
                    return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                }
                if let Some(parent) = effect.parent {
                    let parent_record = self
                        .effects
                        .get(&parent)
                        .ok_or(CompositionInvariantViolation::EffectGraph(*effect_id))?;
                    if parent >= *effect_id
                        || parent_record.token.scope != *scope_id
                        || (!effect.state.is_terminal()
                            && !parent_record.live_children.contains(effect_id))
                    {
                        return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                    }
                }
                for child in &effect.live_children {
                    let child_record = self
                        .effects
                        .get(child)
                        .ok_or(CompositionInvariantViolation::EffectGraph(*effect_id))?;
                    if child_record.parent != Some(*effect_id) || child_record.state.is_terminal() {
                        return Err(CompositionInvariantViolation::EffectGraph(*effect_id));
                    }
                }
            }
            for (tombstone_id, tombstone) in &self.tombstones {
                if tombstone.scope != *scope_id {
                    continue;
                }
                let effect = self
                    .effects
                    .get(&tombstone.effect)
                    .ok_or(CompositionInvariantViolation::Tombstone(*tombstone_id))?;
                let local = scope
                    .domains
                    .get(&tombstone.domain)
                    .ok_or(CompositionInvariantViolation::Tombstone(*tombstone_id))?;
                if effect.token.scope != tombstone.scope
                    || effect.token.domain != tombstone.domain
                    || tombstone.domain != DomainId::VirtIo
                    || effect.token.device_generation != tombstone.device_generation
                    || effect.tombstone != Some(*tombstone_id)
                {
                    return Err(CompositionInvariantViolation::Tombstone(*tombstone_id));
                }
                if tombstone.state == TombstoneState::Released {
                    if !tombstone.retained_credits.is_zero()
                        || local.tombstones.contains(tombstone_id)
                        || !matches!(
                            effect.state,
                            CompositionEffectState::Committed | CompositionEffectState::Completed
                        )
                    {
                        return Err(CompositionInvariantViolation::Tombstone(*tombstone_id));
                    }
                    continue;
                }
                if effect.state != CompositionEffectState::Tombstoned
                    || !local.tombstones.contains(tombstone_id)
                    || effect.held_credits != tombstone.retained_credits
                {
                    return Err(CompositionInvariantViolation::Tombstone(*tombstone_id));
                }
            }
            if accounted != scope.initial_credits {
                return Err(CompositionInvariantViolation::CreditConservation(*scope_id));
            }

            for (domain_id, domain) in &scope.domains {
                let expected_live = self
                    .effects
                    .iter()
                    .filter_map(|(id, effect)| {
                        (effect.token.scope == *scope_id
                            && effect.token.domain == *domain_id
                            && !effect.state.is_terminal())
                        .then_some(*id)
                    })
                    .collect::<BTreeSet<_>>();
                let expected_leaves = expected_live
                    .iter()
                    .filter(|id| {
                        self.effects
                            .get(id)
                            .is_some_and(|effect| effect.live_children.is_empty())
                    })
                    .copied()
                    .collect::<BTreeSet<_>>();
                if expected_live != domain.live_effects || expected_leaves != domain.leaf_effects {
                    return Err(CompositionInvariantViolation::DomainIndex(
                        *scope_id, *domain_id,
                    ));
                }
                for effect in &domain.recovery_cohort {
                    let Some(record) = self.effects.get(effect) else {
                        return Err(CompositionInvariantViolation::AdoptionCohort(
                            *scope_id, *domain_id,
                        ));
                    };
                    if record.token.scope != *scope_id
                        || record.token.domain != *domain_id
                        || !matches!(
                            record.state,
                            CompositionEffectState::Registered | CompositionEffectState::Prepared
                        )
                        || !domain.live_effects.contains(effect)
                    {
                        return Err(CompositionInvariantViolation::AdoptionCohort(
                            *scope_id, *domain_id,
                        ));
                    }
                }
                for tombstone in &domain.tombstones {
                    let Some(record) = self.tombstones.get(tombstone) else {
                        return Err(CompositionInvariantViolation::Tombstone(*tombstone));
                    };
                    if record.scope != *scope_id
                        || record.domain != *domain_id
                        || record.state == TombstoneState::Released
                    {
                        return Err(CompositionInvariantViolation::Tombstone(*tombstone));
                    }
                }
            }

            match (scope.state, &scope.revocation) {
                (ScopeState::Active, None) => {}
                (ScopeState::Closing | ScopeState::Revoked, Some(revocation)) => {
                    if !revocation
                        .frozen_domains
                        .iter()
                        .all(|domain| scope.domains.contains_key(domain))
                        || revocation.progress.keys().copied().collect::<BTreeSet<_>>()
                            != revocation.frozen_domains
                        || revocation
                            .progress
                            .values()
                            .any(|progress| progress.target_count == 0)
                    {
                        return Err(CompositionInvariantViolation::Revocation(*scope_id));
                    }
                    for domain in &revocation.frozen_domains {
                        let progress = revocation
                            .progress
                            .get(domain)
                            .ok_or(CompositionInvariantViolation::Revocation(*scope_id))?;
                        let remaining = scope
                            .domains
                            .get(domain)
                            .ok_or(CompositionInvariantViolation::Revocation(*scope_id))?
                            .live_effects
                            .len();
                        if progress.target_count != progress.terminalized + remaining
                            || progress.index_selections > progress.terminalized
                        {
                            return Err(CompositionInvariantViolation::Revocation(*scope_id));
                        }
                    }
                    for (domain, receipt) in &revocation.accepted {
                        let local = scope
                            .domains
                            .get(domain)
                            .ok_or(CompositionInvariantViolation::Revocation(*scope_id))?;
                        let status_exact = match &receipt.status {
                            ClosureStatus::Closed => {
                                local.live_effects.is_empty() && local.tombstones.is_empty()
                            }
                            ClosureStatus::TimedOut {
                                tombstones,
                                retained_credits,
                            } => {
                                let exact_retained = tombstones.iter().try_fold(
                                    CreditBundle::ZERO,
                                    |sum, tombstone| {
                                        self.tombstones.get(tombstone).and_then(|record| {
                                            sum.checked_add(record.retained_credits).ok()
                                        })
                                    },
                                );
                                !tombstones.is_empty()
                                    && tombstones.iter().copied().collect::<BTreeSet<_>>()
                                        == local.tombstones
                                    && exact_retained == Some(*retained_credits)
                                    && local.live_effects.iter().all(|effect| {
                                        self.effects.get(effect).is_some_and(|effect| {
                                            effect.state == CompositionEffectState::Tombstoned
                                        })
                                    })
                            }
                        };
                        if local.issued_receipt.as_ref() != Some(receipt)
                            || receipt.revision != local.closure_revision
                            || receipt.binding_epoch != local.binding_epoch
                            || receipt.device_generation != local.device_generation
                            || !status_exact
                        {
                            return Err(CompositionInvariantViolation::Revocation(*scope_id));
                        }
                    }
                    if scope.state == ScopeState::Revoked
                        && (scope.free_credits != scope.initial_credits
                            || revocation.accepted.len() != revocation.frozen_domains.len()
                            || revocation
                                .accepted
                                .values()
                                .any(|receipt| receipt.status != ClosureStatus::Closed))
                    {
                        return Err(CompositionInvariantViolation::Revocation(*scope_id));
                    }
                }
                _ => return Err(CompositionInvariantViolation::Revocation(*scope_id)),
            }
        }
        Ok(())
    }
}
