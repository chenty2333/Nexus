use alloc::collections::BTreeSet;

use super::*;

impl CompositionModel {
    pub(super) fn insert_effect(
        &mut self,
        token: CompositionEffectToken,
        credits: CreditBundle,
    ) -> Result<(), CompositionError> {
        self.effects.insert(
            token.effect,
            EffectRecord {
                token,
                parent: token.parent,
                live_children: BTreeSet::new(),
                state: CompositionEffectState::Registered,
                held_credits: credits,
                commit_receipt: None,
                tombstone: None,
                external_quiesced: false,
                terminalizations: 0,
            },
        );
        let domain = self.domain_record_mut(token.scope, token.domain)?;
        domain.live_effects.insert(token.effect);
        domain.leaf_effects.insert(token.effect);
        domain.mutation_generation = domain
            .mutation_generation
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        Ok(())
    }

    pub(super) fn terminalize(
        &mut self,
        effect: EffectId,
        terminal: CompositionEffectState,
        return_credits: bool,
        index_selection: bool,
    ) -> Result<(), CompositionError> {
        debug_assert!(terminal.is_terminal());
        let record = self.effect_record(effect)?;
        if record.state.is_terminal() {
            return Err(CompositionError::InvalidEffectState(record.state));
        }
        if !record.live_children.is_empty() {
            return Err(CompositionError::LiveDescendants);
        }
        let scope = record.token.scope;
        let domain = record.token.domain;
        let parent = record.parent;
        let credits = record.held_credits;
        let mut cross_domain_parent = None;
        {
            let record = self.effect_record_mut(effect)?;
            record.state = terminal;
            record.terminalizations = record
                .terminalizations
                .checked_add(1)
                .ok_or(CompositionError::CounterOverflow)?;
            if return_credits {
                record.held_credits = CreditBundle::ZERO;
            }
        }
        {
            let local = self.domain_record_mut(scope, domain)?;
            local.live_effects.remove(&effect);
            local.leaf_effects.remove(&effect);
            local.recovery_cohort.remove(&effect);
        }
        if let Some(parent_id) = parent {
            let parent_domain = self.effect_record(parent_id)?.token.domain;
            let parent_record = self.effect_record_mut(parent_id)?;
            parent_record.live_children.remove(&effect);
            if return_credits {
                parent_record.held_credits = parent_record.held_credits.checked_add(credits)?;
            }
            if parent_record.live_children.is_empty() && !parent_record.state.is_terminal() {
                self.domain_record_mut(scope, parent_domain)?
                    .leaf_effects
                    .insert(parent_id);
            }
            if parent_domain != domain {
                cross_domain_parent = Some(parent_domain);
            }
        } else if return_credits {
            let free = self
                .scope_record(scope)?
                .free_credits
                .checked_add(credits)?;
            self.scope_record_mut(scope)?.free_credits = free;
        }
        self.bump_domain_mutation(scope, domain)?;
        if let Some(parent_domain) = cross_domain_parent {
            self.bump_domain_mutation(scope, parent_domain)?;
        }
        if self.scope_record(scope)?.state == ScopeState::Closing {
            let progress = self
                .revocation_mut(scope)?
                .progress
                .get_mut(&domain)
                .ok_or(CompositionError::InvariantViolation(
                    "missing domain progress",
                ))?;
            progress.terminalized = progress
                .terminalized
                .checked_add(1)
                .ok_or(CompositionError::CounterOverflow)?;
            if index_selection {
                progress.index_selections = progress
                    .index_selections
                    .checked_add(1)
                    .ok_or(CompositionError::CounterOverflow)?;
            }
            self.invalidate_closure(scope, domain)?;
            if let Some(parent_domain) = cross_domain_parent {
                self.invalidate_closure(scope, parent_domain)?;
            }
        }
        Ok(())
    }

    pub(super) fn validate_binding(
        &self,
        binding: DomainBindingToken,
    ) -> Result<(), CompositionError> {
        let scope = self.scope_record(binding.scope)?;
        if scope.state != ScopeState::Active {
            return Err(CompositionError::ScopeNotActive(scope.state));
        }
        let domain = scope
            .domains
            .get(&binding.domain)
            .ok_or(CompositionError::UnknownDomain(binding.domain))?;
        if domain.service != Some(binding.service)
            || domain.binding_epoch != binding.binding_epoch
            || domain.device_generation != binding.device_generation
            || scope.authority_epoch != binding.authority_epoch
        {
            return Err(CompositionError::StaleBinding);
        }
        Ok(())
    }

    pub(super) fn validate_effect_current(
        &self,
        token: CompositionEffectToken,
    ) -> Result<(), CompositionError> {
        let record = self.effect_record(token.effect)?;
        if record.token != token {
            return Err(CompositionError::EffectIdentityMismatch);
        }
        let scope = self.scope_record(token.scope)?;
        if scope.state != ScopeState::Active {
            return Err(CompositionError::ScopeNotActive(scope.state));
        }
        let domain = self.domain_record(token.scope, token.domain)?;
        if token.authority_epoch != scope.authority_epoch
            || token.binding_epoch != domain.binding_epoch
            || token.device_generation != domain.device_generation
            || domain.service.is_none()
        {
            return Err(CompositionError::EffectIdentityMismatch);
        }
        Ok(())
    }

    pub(super) fn validate_binding_for_effect(
        &self,
        binding: DomainBindingToken,
        token: CompositionEffectToken,
    ) -> Result<(), CompositionError> {
        self.validate_effect_current(token)?;
        if binding.scope != token.scope
            || binding.domain != token.domain
            || binding.authority_epoch != token.authority_epoch
            || binding.binding_epoch != token.binding_epoch
            || binding.device_generation != token.device_generation
        {
            return Err(CompositionError::EffectIdentityMismatch);
        }
        Ok(())
    }

    pub(super) fn validate_ticket(&self, ticket: RootRevokeTicket) -> Result<(), CompositionError> {
        let scope = self.scope_record(ticket.scope)?;
        if scope.state != ScopeState::Closing {
            return Err(CompositionError::ScopeNotClosing(scope.state));
        }
        if scope.revocation.as_ref().map(|record| record.ticket) != Some(ticket) {
            return Err(CompositionError::StaleRevokeTicket);
        }
        Ok(())
    }

    pub(super) fn validate_retry(
        &self,
        retry: TombstoneRetryToken,
    ) -> Result<(), CompositionError> {
        self.validate_ticket(retry.ticket)?;
        let record = self.tombstone_record(retry.tombstone)?;
        if record.scope != retry.ticket.scope
            || record.state != TombstoneState::Retrying
            || record.attempts != retry.attempt
            || record.device_generation != retry.device_generation
            || self
                .domain_record(record.scope, record.domain)?
                .device_generation
                != retry.device_generation
        {
            return Err(CompositionError::StaleTombstoneRetry);
        }
        Ok(())
    }

    pub(super) fn require_active(&self, scope: ScopeId) -> Result<(), CompositionError> {
        let state = self.scope_record(scope)?.state;
        if state != ScopeState::Active {
            return Err(CompositionError::ScopeNotActive(state));
        }
        Ok(())
    }

    pub(super) fn require_frozen(
        &self,
        scope: ScopeId,
        domain: DomainId,
    ) -> Result<(), CompositionError> {
        if !self.revocation(scope)?.frozen_domains.contains(&domain) {
            return Err(CompositionError::DomainNotFrozen(domain));
        }
        Ok(())
    }

    pub(super) fn invalidate_closure(
        &mut self,
        scope: ScopeId,
        domain: DomainId,
    ) -> Result<(), CompositionError> {
        let local = self.domain_record_mut(scope, domain)?;
        local.closure_revision = local
            .closure_revision
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        local.issued_receipt = None;
        if let Some(revocation) = self.scope_record_mut(scope)?.revocation.as_mut() {
            revocation.accepted.remove(&domain);
        }
        Ok(())
    }

    pub(super) fn bump_domain_mutation(
        &mut self,
        scope: ScopeId,
        domain: DomainId,
    ) -> Result<(), CompositionError> {
        let local = self.domain_record_mut(scope, domain)?;
        local.mutation_generation = local
            .mutation_generation
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        Ok(())
    }

    pub(super) fn scope_record(&self, scope: ScopeId) -> Result<&ScopeRecord, CompositionError> {
        self.scopes
            .get(&scope)
            .ok_or(CompositionError::UnknownScope(scope))
    }

    pub(super) fn scope_record_mut(
        &mut self,
        scope: ScopeId,
    ) -> Result<&mut ScopeRecord, CompositionError> {
        self.scopes
            .get_mut(&scope)
            .ok_or(CompositionError::UnknownScope(scope))
    }

    pub(super) fn domain_record(
        &self,
        scope: ScopeId,
        domain: DomainId,
    ) -> Result<&DomainRecord, CompositionError> {
        self.scope_record(scope)?
            .domains
            .get(&domain)
            .ok_or(CompositionError::UnknownDomain(domain))
    }

    pub(super) fn domain_record_mut(
        &mut self,
        scope: ScopeId,
        domain: DomainId,
    ) -> Result<&mut DomainRecord, CompositionError> {
        self.scope_record_mut(scope)?
            .domains
            .get_mut(&domain)
            .ok_or(CompositionError::UnknownDomain(domain))
    }

    pub(super) fn effect_record(
        &self,
        effect: EffectId,
    ) -> Result<&EffectRecord, CompositionError> {
        self.effects
            .get(&effect)
            .ok_or(CompositionError::UnknownEffect(effect))
    }

    pub(super) fn effect_record_mut(
        &mut self,
        effect: EffectId,
    ) -> Result<&mut EffectRecord, CompositionError> {
        self.effects
            .get_mut(&effect)
            .ok_or(CompositionError::UnknownEffect(effect))
    }

    pub(super) fn tombstone_record(
        &self,
        tombstone: TombstoneId,
    ) -> Result<&TombstoneRecord, CompositionError> {
        self.tombstones
            .get(&tombstone)
            .ok_or(CompositionError::UnknownTombstone(tombstone))
    }

    pub(super) fn revocation(&self, scope: ScopeId) -> Result<&RevocationRecord, CompositionError> {
        self.scope_record(scope)?
            .revocation
            .as_ref()
            .ok_or(CompositionError::StaleRevokeTicket)
    }

    pub(super) fn revocation_mut(
        &mut self,
        scope: ScopeId,
    ) -> Result<&mut RevocationRecord, CompositionError> {
        self.scope_record_mut(scope)?
            .revocation
            .as_mut()
            .ok_or(CompositionError::StaleRevokeTicket)
    }
}

impl EffectRecord {
    pub(super) const fn kind_domain(&self) -> DomainId {
        self.token.kind.domain()
    }
}
