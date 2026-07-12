use alloc::collections::BTreeSet;

use super::*;

impl RuntimeFsModel {
    /// Returns a read-only projection of one root scope.
    #[must_use]
    pub fn scope(&self, scope: ScopeId) -> Option<RuntimeFsScopeView> {
        let record = self.scopes.get(&scope)?;
        let mut live_effects = 0usize;
        let mut pending_publications = 0usize;
        let mut tombstones = 0usize;
        for effect in &record.effects {
            let Some(effect) = self.effects.get(effect) else {
                continue;
            };
            live_effects += usize::from(!effect.phase.is_terminal());
            pending_publications += usize::from(effect.publication.is_some());
            tombstones += usize::from(effect.tombstone.is_some());
        }
        let (closure_target_count, closure_steps) =
            record.revocation.as_ref().map_or((0, 0), |revocation| {
                (revocation.frozen.len(), revocation.closure_steps)
            });
        Some(RuntimeFsScopeView {
            state: record.state,
            authority_epoch: record.authority_epoch,
            address_space_generation: record.address_space_generation,
            inode_generation: record.inode_generation,
            device_generation: record.device_generation,
            initial_credits: record.initial_credits,
            free_credits: record.free_credits,
            inode_version: record.inode_version,
            inode_word: record.inode_word,
            mapping_publications: record.mapping_publications,
            pwrite_publications: record.pwrite_publications,
            avail_index: record.avail_index,
            reply_publications: record.reply_publications,
            effects: record.effects.len(),
            live_effects,
            pending_publications,
            tombstones,
            closure_target_count,
            closure_steps,
        })
    }

    /// Returns a read-only projection of one independently restartable domain.
    #[must_use]
    pub fn domain(&self, scope: ScopeId, domain: FsDomain) -> Option<RuntimeFsDomainView> {
        let record = self.scopes.get(&scope)?.domains.get(&domain)?;
        Some(RuntimeFsDomainView {
            binding_epoch: record.binding_epoch,
            service: record.service,
            fallback: record.fallback,
            revision: record.revision,
            recovery_cohort: record.recovery_cohort.iter().copied().collect(),
        })
    }

    /// Returns a read-only projection of one effect.
    #[must_use]
    pub fn effect(&self, effect: EffectId) -> Option<RuntimeFsEffectView> {
        self.effects.get(&effect).map(|record| RuntimeFsEffectView {
            token: record.token,
            phase: record.phase,
            credit: record.credit,
            commit_sequence: record.commit_sequence,
            dma_state: record.dma_state,
            device_completed: record.device_completed,
            publication_pending: record.publication.is_some(),
            terminalizations: record.terminalizations,
        })
    }

    /// Reconstructs the complete current binding set while all domains are live.
    #[must_use]
    pub fn bindings(&self, scope: ScopeId) -> Option<RuntimeFsBindings> {
        let record = self.scopes.get(&scope)?;
        if record.state != ScopeState::Active {
            return None;
        }
        let binding = |domain| {
            let domain_record = record.domains.get(&domain)?;
            Some(RuntimeFsBindingToken {
                scope,
                domain,
                service: domain_record.service?,
                authority_epoch: record.authority_epoch,
                binding_epoch: domain_record.binding_epoch,
            })
        };
        Some(RuntimeFsBindings {
            personality: binding(FsDomain::Personality)?,
            pager: binding(FsDomain::Pager)?,
            filesystem: binding(FsDomain::Filesystem)?,
            block: binding(FsDomain::Block)?,
        })
    }

    /// Audits the complete fixed graph, typed credits, recovery, and closure state.
    pub fn check_invariants(&self) -> Result<(), RuntimeFsInvariantViolation> {
        let mut commit_sequences = BTreeSet::new();
        let mut publication_sequences = BTreeSet::new();
        let mut revoke_sequences = BTreeSet::new();
        let mut tombstone_ids = BTreeSet::new();

        for (scope_id, scope) in &self.scopes {
            self.check_scope_index(*scope_id, scope)?;
            self.check_scope_graph(*scope_id, scope)?;
            self.check_scope_credits(*scope_id, scope)?;
            self.check_scope_accounting(*scope_id, scope)?;
            self.check_scope_recovery(*scope_id, scope)?;
            self.check_scope_revocation(*scope_id, scope)?;
            if let Some(revocation) = &scope.revocation
                && !revoke_sequences.insert(revocation.ticket.sequence)
            {
                return Err(RuntimeFsInvariantViolation::RevocationState(*scope_id));
            }

            for effect in &scope.effects {
                let record = self
                    .effects
                    .get(effect)
                    .ok_or(RuntimeFsInvariantViolation::ScopeIndex(*scope_id))?;
                self.check_effect_state(*effect, record)?;
                if let Some(sequence) = record.commit_sequence
                    && !commit_sequences.insert(sequence)
                {
                    return Err(RuntimeFsInvariantViolation::GenerationAccounting(*scope_id));
                }
                if let Some(publication) = record.publication
                    && !publication_sequences.insert(publication.ticket_sequence)
                {
                    return Err(RuntimeFsInvariantViolation::GenerationAccounting(*scope_id));
                }
                if let Some(tombstone) = record.tombstone
                    && !tombstone_ids.insert(tombstone.token.id)
                {
                    return Err(RuntimeFsInvariantViolation::DmaSafety(*effect));
                }
            }
        }

        for (effect_id, effect) in &self.effects {
            let scope = self
                .scopes
                .get(&effect.token.scope)
                .ok_or(RuntimeFsInvariantViolation::EffectGraph(*effect_id))?;
            if effect.token.effect != *effect_id || !scope.effects.contains(effect_id) {
                return Err(RuntimeFsInvariantViolation::ScopeIndex(effect.token.scope));
            }
        }

        let max_scope = self
            .scopes
            .keys()
            .map(|scope| scope.get())
            .max()
            .unwrap_or(0);
        let max_effect = self
            .effects
            .keys()
            .map(|effect| effect.get())
            .max()
            .unwrap_or(0);
        let max_commit = commit_sequences.iter().copied().max().unwrap_or(0);
        let max_publication = publication_sequences.iter().copied().max().unwrap_or(0);
        let max_revoke = revoke_sequences.iter().copied().max().unwrap_or(0);
        let max_tombstone = tombstone_ids
            .iter()
            .map(|tombstone| tombstone.get())
            .max()
            .unwrap_or(0);
        if self.next_scope <= max_scope
            || self.next_effect <= max_effect
            || self.next_commit_sequence <= max_commit
            || self.next_publication_sequence <= max_publication
            || self.next_revoke_sequence <= max_revoke
            || self.next_tombstone <= max_tombstone
        {
            let scope = self
                .scopes
                .keys()
                .next()
                .copied()
                .unwrap_or(ScopeId::new(0));
            return Err(RuntimeFsInvariantViolation::GenerationAccounting(scope));
        }

        Ok(())
    }

    fn check_scope_index(
        &self,
        scope_id: ScopeId,
        scope: &ScopeRecord,
    ) -> Result<(), RuntimeFsInvariantViolation> {
        let derived: BTreeSet<_> = self
            .effects
            .iter()
            .filter_map(|(effect, record)| (record.token.scope == scope_id).then_some(*effect))
            .collect();
        if derived != scope.effects
            || scope.domains.len() != FsDomain::ALL.len()
            || FsDomain::ALL
                .iter()
                .any(|domain| !scope.domains.contains_key(domain))
        {
            return Err(RuntimeFsInvariantViolation::ScopeIndex(scope_id));
        }
        Ok(())
    }

    fn check_scope_graph(
        &self,
        scope_id: ScopeId,
        scope: &ScopeRecord,
    ) -> Result<(), RuntimeFsInvariantViolation> {
        for effect_id in &scope.effects {
            let effect = self
                .effects
                .get(effect_id)
                .ok_or(RuntimeFsInvariantViolation::ScopeIndex(scope_id))?;
            let domain = scope
                .domains
                .get(&effect.token.kind.domain())
                .ok_or(RuntimeFsInvariantViolation::EffectGraph(*effect_id))?;
            if effect.credit != effect.token.kind.credit()
                || effect.token.authority_epoch > scope.authority_epoch
                || effect.token.binding_epoch > domain.binding_epoch
                || effect.token.address_space_generation > scope.address_space_generation
                || effect.token.inode_generation > scope.inode_generation
                || effect.token.device_generation > scope.device_generation
            {
                return Err(RuntimeFsInvariantViolation::EffectGraph(*effect_id));
            }
            let valid_parent = match effect.token.kind {
                FsEffectKind::Syscall => effect.token.parent.is_none(),
                FsEffectKind::PagerMap | FsEffectKind::FsOperation => effect
                    .token
                    .parent
                    .and_then(|parent| self.effects.get(&parent))
                    .is_some_and(|parent| {
                        parent.token.scope == scope_id && parent.token.kind == FsEffectKind::Syscall
                    }),
                FsEffectKind::BlockRequest => effect
                    .token
                    .parent
                    .and_then(|parent| self.effects.get(&parent))
                    .is_some_and(|parent| {
                        parent.token.scope == scope_id
                            && parent.token.kind == FsEffectKind::FsOperation
                    }),
            };
            if !valid_parent {
                return Err(RuntimeFsInvariantViolation::EffectGraph(*effect_id));
            }
            if effect.phase.is_terminal() && self.has_live_children(*effect_id) {
                return Err(RuntimeFsInvariantViolation::EffectGraph(*effect_id));
            }

            let mut pager_children = 0usize;
            let mut filesystem_children = 0usize;
            let mut block_children = 0usize;
            for child in self.effects.values().filter(|candidate| {
                candidate.token.scope == scope_id && candidate.token.parent == Some(*effect_id)
            }) {
                match child.token.kind {
                    FsEffectKind::PagerMap => pager_children += 1,
                    FsEffectKind::FsOperation => filesystem_children += 1,
                    FsEffectKind::BlockRequest => block_children += 1,
                    FsEffectKind::Syscall => {
                        return Err(RuntimeFsInvariantViolation::EffectGraph(*effect_id));
                    }
                }
            }
            let children_valid = match effect.token.kind {
                FsEffectKind::Syscall => {
                    pager_children == 1 && filesystem_children == 1 && block_children == 0
                }
                FsEffectKind::FsOperation => {
                    pager_children == 0 && filesystem_children == 0 && block_children == 1
                }
                FsEffectKind::PagerMap | FsEffectKind::BlockRequest => {
                    pager_children == 0 && filesystem_children == 0 && block_children == 0
                }
            };
            if !children_valid {
                return Err(RuntimeFsInvariantViolation::EffectGraph(*effect_id));
            }
        }
        Ok(())
    }

    fn check_scope_credits(
        &self,
        scope_id: ScopeId,
        scope: &ScopeRecord,
    ) -> Result<(), RuntimeFsInvariantViolation> {
        let mut held = FsCredits::ZERO;
        for effect in &scope.effects {
            let record = self
                .effects
                .get(effect)
                .ok_or(RuntimeFsInvariantViolation::ScopeIndex(scope_id))?;
            if !record.phase.is_terminal() {
                held = held
                    .checked_add(FsCredits::one(record.credit))
                    .ok_or(RuntimeFsInvariantViolation::CreditConservation(scope_id))?;
            }
        }
        if !scope.initial_credits.contains(scope.free_credits)
            || scope
                .free_credits
                .checked_add(held)
                .is_none_or(|accounted| accounted != scope.initial_credits)
        {
            return Err(RuntimeFsInvariantViolation::CreditConservation(scope_id));
        }
        Ok(())
    }

    fn check_scope_accounting(
        &self,
        scope_id: ScopeId,
        scope: &ScopeRecord,
    ) -> Result<(), RuntimeFsInvariantViolation> {
        let mut mappings = 0u64;
        let mut pwrites = 0u64;
        let mut blocks = 0u64;
        let mut replies = 0u64;
        let mut avail_indices = BTreeSet::new();
        for effect in &scope.effects {
            let record = self
                .effects
                .get(effect)
                .ok_or(RuntimeFsInvariantViolation::ScopeIndex(scope_id))?;
            match record.token.kind {
                FsEffectKind::PagerMap if record.commit_sequence.is_some() => mappings += 1,
                FsEffectKind::FsOperation if record.commit_sequence.is_some() => pwrites += 1,
                FsEffectKind::BlockRequest if record.block_receipt.is_some() => {
                    blocks += 1;
                    let receipt = record.block_receipt.expect("checked Some");
                    if receipt.effect != *effect
                        || receipt.sequence != record.commit_sequence.unwrap_or(0)
                        || receipt.device_generation > scope.device_generation
                        || !avail_indices.insert(receipt.avail_index)
                    {
                        return Err(RuntimeFsInvariantViolation::GenerationAccounting(scope_id));
                    }
                }
                FsEffectKind::Syscall if record.phase == FsEffectPhase::Completed => replies += 1,
                _ => {}
            }
        }
        let address_generation = mappings.checked_add(1);
        let inode_generation = pwrites.checked_add(1);
        let contiguous_avail = blocks == 0
            || (avail_indices.len() == usize::try_from(blocks).unwrap_or(usize::MAX)
                && avail_indices.first() == Some(&1)
                && avail_indices.last() == Some(&blocks));
        if scope.mapping_publications != mappings
            || scope.pwrite_publications != pwrites
            || scope.avail_index != blocks
            || scope.reply_publications != replies
            || address_generation != Some(scope.address_space_generation.get())
            || inode_generation != Some(scope.inode_generation.get())
            || scope.inode_version != pwrites
            || (pwrites == 0 && scope.inode_word != 0)
            || (pwrites != 0 && scope.inode_word != 0x0000_7879)
            || !contiguous_avail
            || scope.device_generation.get() == 0
        {
            return Err(RuntimeFsInvariantViolation::GenerationAccounting(scope_id));
        }
        Ok(())
    }

    fn check_effect_state(
        &self,
        effect_id: EffectId,
        effect: &EffectRecord,
    ) -> Result<(), RuntimeFsInvariantViolation> {
        if effect.terminalizations != u8::from(effect.phase.is_terminal())
            || (effect.phase.is_terminal() && effect.publication.is_some())
        {
            return Err(RuntimeFsInvariantViolation::Terminalization(effect_id));
        }
        let commit_valid = match effect.phase {
            FsEffectPhase::Registered | FsEffectPhase::Prepared | FsEffectPhase::Aborted => {
                effect.commit_sequence.is_none()
            }
            FsEffectPhase::Committed | FsEffectPhase::Completed => effect.commit_sequence.is_some(),
            FsEffectPhase::Tombstoned => effect.tombstone.is_some_and(|tombstone| {
                effect.commit_sequence.is_some()
                    == (tombstone.prior_phase == FsEffectPhase::Committed)
            }),
        };
        if !commit_valid {
            return Err(RuntimeFsInvariantViolation::Terminalization(effect_id));
        }
        if let Some(publication) = effect.publication
            && (effect.token.kind != FsEffectKind::Syscall
                || effect.phase != FsEffectPhase::Committed
                || effect.commit_sequence != Some(publication.commit_sequence)
                || publication.scope != effect.token.scope
                || publication.effect != effect_id)
        {
            return Err(RuntimeFsInvariantViolation::Terminalization(effect_id));
        }
        if effect.token.kind == FsEffectKind::Syscall
            && (effect.phase == FsEffectPhase::Committed) != effect.publication.is_some()
        {
            return Err(RuntimeFsInvariantViolation::Terminalization(effect_id));
        }

        if effect.token.kind != FsEffectKind::BlockRequest {
            if effect.dma_state != FsDmaState::NotApplicable
                || effect.dma_attempt != 0
                || effect.device_completed
                || effect.block_receipt.is_some()
                || effect.tombstone.is_some()
            {
                return Err(RuntimeFsInvariantViolation::DmaSafety(effect_id));
            }
            return Ok(());
        }

        let pair_valid = matches!(
            (effect.phase, effect.dma_state, effect.tombstone),
            (FsEffectPhase::Registered, FsDmaState::Reserved, None)
                | (FsEffectPhase::Prepared, FsDmaState::Mapped, None)
                | (FsEffectPhase::Prepared, FsDmaState::IotlbInFlight, None)
                | (FsEffectPhase::Committed, FsDmaState::Mapped, None)
                | (FsEffectPhase::Committed, FsDmaState::ResetInFlight, None)
                | (FsEffectPhase::Committed, FsDmaState::IotlbInFlight, None)
                | (FsEffectPhase::Completed, FsDmaState::Released, None)
                | (FsEffectPhase::Aborted, FsDmaState::Released, None)
                | (
                    FsEffectPhase::Tombstoned,
                    FsDmaState::ResetTimedOut | FsDmaState::IotlbTimedOut,
                    Some(_),
                )
        );
        let receipt_valid = match effect.phase {
            FsEffectPhase::Registered | FsEffectPhase::Prepared | FsEffectPhase::Aborted => {
                effect.block_receipt.is_none()
            }
            FsEffectPhase::Committed | FsEffectPhase::Completed => effect.block_receipt.is_some(),
            FsEffectPhase::Tombstoned => effect.tombstone.is_some_and(|tombstone| {
                effect.block_receipt.is_some()
                    == (tombstone.prior_phase == FsEffectPhase::Committed)
            }),
        };
        let attempt_valid = match effect.dma_state {
            FsDmaState::Reserved | FsDmaState::Mapped => effect.dma_attempt == 0,
            FsDmaState::ResetInFlight
            | FsDmaState::IotlbInFlight
            | FsDmaState::ResetTimedOut
            | FsDmaState::IotlbTimedOut => effect.dma_attempt != 0,
            FsDmaState::Released => true,
            FsDmaState::NotApplicable => false,
        };
        let completion_valid = !effect.device_completed
            || (effect.block_receipt.is_some()
                && matches!(
                    effect.dma_state,
                    FsDmaState::IotlbInFlight | FsDmaState::IotlbTimedOut | FsDmaState::Released
                ));
        if !pair_valid || !receipt_valid || !attempt_valid || !completion_valid {
            return Err(RuntimeFsInvariantViolation::DmaSafety(effect_id));
        }
        if let Some(tombstone) = effect.tombstone {
            let token = tombstone.token;
            let scope = self
                .scopes
                .get(&effect.token.scope)
                .ok_or(RuntimeFsInvariantViolation::DmaSafety(effect_id))?;
            let state_matches_kind = matches!(
                (token.kind, effect.dma_state, tombstone.prior_phase),
                (
                    FsDmaRecoveryKind::Reset,
                    FsDmaState::ResetTimedOut,
                    FsEffectPhase::Committed
                ) | (
                    FsDmaRecoveryKind::Iotlb,
                    FsDmaState::IotlbTimedOut,
                    FsEffectPhase::Prepared | FsEffectPhase::Committed
                )
            );
            if token.scope != effect.token.scope
                || token.effect != effect_id
                || token.attempt != effect.dma_attempt
                || token.device_generation != scope.device_generation
                || scope.state != ScopeState::Closing
                || scope
                    .revocation
                    .as_ref()
                    .is_none_or(|revocation| revocation.ticket.sequence != token.revoke_sequence)
                || !state_matches_kind
            {
                return Err(RuntimeFsInvariantViolation::DmaSafety(effect_id));
            }
        }
        Ok(())
    }

    fn check_scope_recovery(
        &self,
        scope_id: ScopeId,
        scope: &ScopeRecord,
    ) -> Result<(), RuntimeFsInvariantViolation> {
        for domain_id in FsDomain::ALL {
            let domain = scope
                .domains
                .get(&domain_id)
                .ok_or(RuntimeFsInvariantViolation::RecoveryState(scope_id))?;
            let fallback_valid = match (domain.service, domain.fallback, &domain.ready) {
                (Some(service), FsFallbackState::Standby, None) => service.get() != 0,
                (None, FsFallbackState::Required | FsFallbackState::Running, None) => true,
                (None, FsFallbackState::ReplacementReady, Some(ready)) => {
                    ready.replacement.get() != 0
                        && ready.authority_epoch == scope.authority_epoch
                        && ready.binding_epoch == domain.binding_epoch
                        && ready.address_space_generation == scope.address_space_generation
                        && ready.inode_generation == scope.inode_generation
                        && ready.device_generation == scope.device_generation
                        && ready.domain_revision == domain.revision
                        && ready.cohort == domain.recovery_cohort
                }
                _ => false,
            };
            if !fallback_valid || domain.binding_epoch.get() == 0 {
                return Err(RuntimeFsInvariantViolation::RecoveryState(scope_id));
            }
            for effect in &domain.recovery_cohort {
                let record = self
                    .effects
                    .get(effect)
                    .ok_or(RuntimeFsInvariantViolation::RecoveryState(scope_id))?;
                if record.token.scope != scope_id
                    || record.token.kind.domain() != domain_id
                    || !record.phase.is_uncommitted()
                    || record.token.binding_epoch >= domain.binding_epoch
                {
                    return Err(RuntimeFsInvariantViolation::RecoveryState(scope_id));
                }
            }
            if scope.state == ScopeState::Active {
                let expected: BTreeSet<_> = scope
                    .effects
                    .iter()
                    .filter_map(|effect| {
                        let record = self.effects.get(effect)?;
                        (record.token.kind.domain() == domain_id
                            && record.phase.is_uncommitted()
                            && record.token.binding_epoch < domain.binding_epoch)
                            .then_some(*effect)
                    })
                    .collect();
                if expected != domain.recovery_cohort {
                    return Err(RuntimeFsInvariantViolation::RecoveryState(scope_id));
                }
            } else if !domain.recovery_cohort.is_empty() || domain.ready.is_some() {
                return Err(RuntimeFsInvariantViolation::RecoveryState(scope_id));
            }
        }
        Ok(())
    }

    fn check_scope_revocation(
        &self,
        scope_id: ScopeId,
        scope: &ScopeRecord,
    ) -> Result<(), RuntimeFsInvariantViolation> {
        match (scope.state, &scope.revocation) {
            (ScopeState::Active, None) => return Ok(()),
            (ScopeState::Closing | ScopeState::Revoked, Some(revocation)) => {
                let ticket = revocation.ticket;
                let epochs_valid = ticket.scope == scope_id
                    && ticket.authority_epoch == scope.authority_epoch
                    && ticket
                        .closed_epoch
                        .get()
                        .checked_add(1)
                        .is_some_and(|next| next == scope.authority_epoch.get());
                let frozen_valid = revocation.frozen.iter().all(|effect| {
                    scope.effects.contains(effect)
                        && self.effects.get(effect).is_some_and(|record| {
                            record.token.scope == scope_id
                                && record.token.authority_epoch == ticket.closed_epoch
                        })
                });
                let live_are_frozen = scope.effects.iter().all(|effect| {
                    self.effects
                        .get(effect)
                        .is_some_and(|record| record.phase.is_terminal())
                        || revocation.frozen.contains(effect)
                });
                let terminalized = revocation
                    .frozen
                    .iter()
                    .filter(|effect| {
                        self.effects
                            .get(effect)
                            .is_some_and(|record| record.phase.is_terminal())
                    })
                    .count();
                if !epochs_valid
                    || !frozen_valid
                    || !live_are_frozen
                    || revocation.closure_steps != terminalized
                {
                    return Err(RuntimeFsInvariantViolation::RevocationState(scope_id));
                }
                if scope.state == ScopeState::Revoked {
                    let retained = scope.effects.iter().any(|effect| {
                        self.effects.get(effect).is_none_or(|record| {
                            !record.phase.is_terminal()
                                || record.publication.is_some()
                                || record.tombstone.is_some()
                        })
                    });
                    if retained
                        || scope.free_credits != scope.initial_credits
                        || revocation.closure_steps != revocation.frozen.len()
                    {
                        return Err(RuntimeFsInvariantViolation::RevokedScope(scope_id));
                    }
                }
                return Ok(());
            }
            _ => {}
        }
        Err(RuntimeFsInvariantViolation::RevocationState(scope_id))
    }
}
