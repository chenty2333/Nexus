use alloc::collections::BTreeSet;

use super::*;

impl RuntimeNetModel {
    pub(super) fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, RuntimeNetError>,
    ) -> Result<T, RuntimeNetError> {
        let mut candidate = self.clone();
        let result = operation(&mut candidate)?;
        candidate
            .check_invariants()
            .map_err(|_| RuntimeNetError::InvariantViolation("post-transition invariant"))?;
        *self = candidate;
        Ok(result)
    }

    pub(super) fn scope_record(&self, scope: ScopeId) -> Result<&ScopeRecord, RuntimeNetError> {
        self.scopes
            .get(&scope)
            .ok_or(RuntimeNetError::UnknownScope(scope))
    }

    pub(super) fn scope_record_mut(
        &mut self,
        scope: ScopeId,
    ) -> Result<&mut ScopeRecord, RuntimeNetError> {
        self.scopes
            .get_mut(&scope)
            .ok_or(RuntimeNetError::UnknownScope(scope))
    }

    pub(super) fn effect_record(&self, effect: EffectId) -> Result<&EffectRecord, RuntimeNetError> {
        self.effects
            .get(&effect)
            .ok_or(RuntimeNetError::UnknownEffect(effect))
    }

    pub(super) fn effect_record_mut(
        &mut self,
        effect: EffectId,
    ) -> Result<&mut EffectRecord, RuntimeNetError> {
        self.effects
            .get_mut(&effect)
            .ok_or(RuntimeNetError::UnknownEffect(effect))
    }

    pub(super) fn validate_binding(
        &self,
        binding: RuntimeNetBindingToken,
    ) -> Result<&ScopeRecord, RuntimeNetError> {
        let scope = self.scope_record(binding.scope)?;
        if binding.authority_epoch != scope.authority_epoch {
            return Err(RuntimeNetError::StaleAuthority {
                presented: binding.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if scope.state != ScopeState::Active {
            return Err(RuntimeNetError::InvalidScopeState(scope.state));
        }
        let domain = scope
            .domains
            .get(&binding.domain)
            .ok_or(RuntimeNetError::WrongDomain)?;
        if binding.binding_epoch != domain.binding_epoch {
            return Err(RuntimeNetError::StaleBinding {
                presented: binding.binding_epoch,
                current: domain.binding_epoch,
            });
        }
        match domain.service {
            Some(service) if service == binding.service => Ok(scope),
            Some(_) => Err(RuntimeNetError::WrongService),
            None => Err(RuntimeNetError::ServiceUnavailable),
        }
    }

    pub(super) fn validate_effect_identity(
        &self,
        token: RuntimeNetEffectToken,
    ) -> Result<&EffectRecord, RuntimeNetError> {
        let record = self.effect_record(token.effect)?;
        if record.token != token {
            return Err(RuntimeNetError::EffectIdentityMismatch);
        }
        Ok(record)
    }

    pub(super) fn validate_service_effect(
        &self,
        binding: RuntimeNetBindingToken,
        token: RuntimeNetEffectToken,
        kind: NetEffectKind,
    ) -> Result<&EffectRecord, RuntimeNetError> {
        let scope = self.validate_binding(binding)?;
        if binding.scope != token.scope || binding.domain != kind.domain() || token.kind != kind {
            return Err(RuntimeNetError::WrongDomain);
        }
        if token.authority_epoch != scope.authority_epoch {
            return Err(RuntimeNetError::StaleAuthority {
                presented: token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        let current_binding = scope
            .domains
            .get(&binding.domain)
            .ok_or(RuntimeNetError::WrongDomain)?
            .binding_epoch;
        if token.binding_epoch != current_binding {
            return Err(RuntimeNetError::StaleBinding {
                presented: token.binding_epoch,
                current: current_binding,
            });
        }
        self.validate_effect_identity(token)
    }

    pub(super) fn validate_generation(
        &self,
        token: RuntimeNetEffectToken,
    ) -> Result<(), RuntimeNetError> {
        let scope = self.scope_record(token.scope)?;
        match token.kind {
            NetEffectKind::NetOperation | NetEffectKind::BufferLease
                if token.socket_generation != scope.socket_generation =>
            {
                Err(RuntimeNetError::StaleSocketGeneration {
                    presented: token.socket_generation,
                    current: scope.socket_generation,
                })
            }
            NetEffectKind::ReadinessWait if token.source_generation != scope.source_generation => {
                Err(RuntimeNetError::StaleSourceGeneration {
                    presented: token.source_generation,
                    current: scope.source_generation,
                })
            }
            _ => Ok(()),
        }
    }

    pub(super) fn validate_net_receipt(
        &self,
        receipt: NetCommitReceipt,
    ) -> Result<&EffectRecord, RuntimeNetError> {
        let record = self.effect_record(receipt.effect)?;
        if record.token.scope != receipt.scope
            || record.token.kind != NetEffectKind::NetOperation
            || record.net_receipt != Some(receipt)
            || record.commit_sequence != Some(receipt.sequence)
            || !matches!(
                record.phase,
                NetEffectPhase::Committed | NetEffectPhase::Completed
            )
        {
            return Err(RuntimeNetError::InvalidNetReceipt);
        }
        let buffer = self.effect_record(receipt.buffer_effect)?;
        if buffer.token.scope != receipt.scope
            || buffer.token.kind != NetEffectKind::BufferLease
            || buffer.token.parent != Some(receipt.effect)
            || buffer.commit_sequence != Some(receipt.sequence)
            || buffer.net_receipt != Some(receipt)
            || buffer.phase == NetEffectPhase::Aborted
        {
            return Err(RuntimeNetError::InvalidNetReceipt);
        }
        Ok(record)
    }

    pub(super) fn validate_ready_receipt(
        &self,
        receipt: ReadyCommitReceipt,
    ) -> Result<&EffectRecord, RuntimeNetError> {
        let record = self.effect_record(receipt.effect)?;
        if record.token.scope != receipt.scope
            || record.token.kind != NetEffectKind::ReadinessWait
            || record.ready_receipt != Some(receipt)
            || record.commit_sequence != Some(receipt.sequence)
            || !matches!(
                record.phase,
                NetEffectPhase::Committed | NetEffectPhase::Completed
            )
        {
            return Err(RuntimeNetError::InvalidReadyReceipt);
        }
        let network = self.effect_record(receipt.network_effect)?;
        if network.token.scope != receipt.scope
            || network.token.kind != NetEffectKind::NetOperation
            || network.commit_sequence != Some(receipt.network_sequence)
            || network
                .net_receipt
                .is_none_or(|net| net.sequence != receipt.network_sequence)
        {
            return Err(RuntimeNetError::InvalidReadyReceipt);
        }
        Ok(record)
    }

    pub(super) fn validate_revoke_ticket(
        &self,
        ticket: RuntimeNetRevokeTicket,
    ) -> Result<&RevocationRecord, RuntimeNetError> {
        let scope = self.scope_record(ticket.scope)?;
        if scope.state != ScopeState::Closing {
            return Err(RuntimeNetError::InvalidScopeState(scope.state));
        }
        let revocation = scope
            .revocation
            .as_ref()
            .ok_or(RuntimeNetError::StaleRevokeTicket)?;
        if revocation.ticket != ticket {
            return Err(RuntimeNetError::StaleRevokeTicket);
        }
        Ok(revocation)
    }

    pub(super) fn take_effect_id(&mut self) -> Result<EffectId, RuntimeNetError> {
        let effect = EffectId::new(self.next_effect);
        self.next_effect = self
            .next_effect
            .checked_add(1)
            .ok_or(RuntimeNetError::CounterOverflow)?;
        Ok(effect)
    }

    pub(super) fn take_commit_sequence(&mut self) -> Result<u64, RuntimeNetError> {
        let sequence = self.next_commit_sequence;
        self.next_commit_sequence = self
            .next_commit_sequence
            .checked_add(1)
            .ok_or(RuntimeNetError::CounterOverflow)?;
        Ok(sequence)
    }

    pub(super) fn take_publication_sequence(&mut self) -> Result<u64, RuntimeNetError> {
        let sequence = self.next_publication_sequence;
        self.next_publication_sequence = self
            .next_publication_sequence
            .checked_add(1)
            .ok_or(RuntimeNetError::CounterOverflow)?;
        Ok(sequence)
    }

    pub(super) fn bump_domain_revision(
        &mut self,
        scope: ScopeId,
        domain: NetDomain,
    ) -> Result<(), RuntimeNetError> {
        let record = self
            .scope_record_mut(scope)?
            .domains
            .get_mut(&domain)
            .ok_or(RuntimeNetError::WrongDomain)?;
        record.revision = record
            .revision
            .checked_add(1)
            .ok_or(RuntimeNetError::CounterOverflow)?;
        record.ready = None;
        if record.fallback == NetFallbackState::ReplacementReady {
            record.fallback = NetFallbackState::Running;
        }
        Ok(())
    }

    pub(super) fn has_live_children(&self, effect: EffectId) -> bool {
        self.effects.values().any(|candidate| {
            candidate.token.parent == Some(effect) && !candidate.phase.is_terminal()
        })
    }

    pub(super) fn live_leaves(
        &self,
        scope: ScopeId,
        frozen: &BTreeSet<EffectId>,
    ) -> Result<Vec<EffectId>, RuntimeNetError> {
        let mut leaves = Vec::new();
        for effect in frozen {
            let record = self.effect_record(*effect)?;
            if record.token.scope == scope
                && !record.phase.is_terminal()
                && !self.has_live_children(*effect)
            {
                leaves.push(*effect);
            }
        }
        Ok(leaves)
    }

    pub(super) fn terminalize(
        &mut self,
        effect: EffectId,
        phase: NetEffectPhase,
    ) -> Result<(), RuntimeNetError> {
        if !phase.is_terminal() {
            return Err(RuntimeNetError::InvariantViolation(
                "terminalize requires terminal phase",
            ));
        }
        if self.has_live_children(effect) {
            return Err(RuntimeNetError::LiveDescendants);
        }
        let record = *self.effect_record(effect)?;
        if record.phase.is_terminal() {
            return Err(RuntimeNetError::InvalidEffectState(record.phase));
        }
        if record.publication.is_some() {
            return Err(RuntimeNetError::InvalidPublication);
        }
        if record.token.kind == NetEffectKind::BufferLease
            && self
                .scope_record(record.token.scope)?
                .buffers
                .contains_key(&effect)
        {
            return Err(RuntimeNetError::InvalidBufferLease);
        }
        let credit = NetCredits::one(record.credit);
        let free = self
            .scope_record(record.token.scope)?
            .free_credits
            .checked_add(credit)
            .ok_or(RuntimeNetError::CounterOverflow)?;
        let target = self.effect_record_mut(effect)?;
        target.phase = phase;
        target.terminalizations = target
            .terminalizations
            .checked_add(1)
            .ok_or(RuntimeNetError::CounterOverflow)?;
        let scope = self.scope_record_mut(record.token.scope)?;
        scope.free_credits = free;
        for domain in scope.domains.values_mut() {
            domain.recovery_cohort.remove(&effect);
        }
        self.bump_domain_revision(record.token.scope, record.token.kind.domain())
    }

    pub(super) fn record_closure_step(&mut self, scope: ScopeId) -> Result<(), RuntimeNetError> {
        let revocation = self
            .scope_record_mut(scope)?
            .revocation
            .as_mut()
            .ok_or(RuntimeNetError::StaleRevokeTicket)?;
        revocation.closure_steps = revocation
            .closure_steps
            .checked_add(1)
            .ok_or(RuntimeNetError::CounterOverflow)?;
        Ok(())
    }

    pub(super) fn make_recovery_snapshot(
        &self,
        scope: ScopeId,
        domain: NetDomain,
        replacement: NetServiceId,
    ) -> Result<RuntimeNetRecoverySnapshot, RuntimeNetError> {
        let scope_record = self.scope_record(scope)?;
        if scope_record.state != ScopeState::Active {
            return Err(RuntimeNetError::InvalidScopeState(scope_record.state));
        }
        if replacement.get() == 0
            || scope_record
                .domains
                .values()
                .any(|candidate| candidate.service == Some(replacement))
        {
            return Err(RuntimeNetError::ServiceAlreadyBound);
        }
        let record = scope_record
            .domains
            .get(&domain)
            .ok_or(RuntimeNetError::WrongDomain)?;
        if record.service.is_some() || record.fallback != NetFallbackState::Running {
            return Err(RuntimeNetError::FallbackUnavailable);
        }
        let cohort = record
            .recovery_cohort
            .iter()
            .map(|effect| self.effect_record(*effect).map(|entry| entry.token))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RuntimeNetRecoverySnapshot {
            scope,
            domain,
            replacement,
            authority_epoch: scope_record.authority_epoch,
            binding_epoch: record.binding_epoch,
            socket_generation: scope_record.socket_generation,
            source_generation: scope_record.source_generation,
            domain_revision: record.revision,
            cohort,
        })
    }
}

impl ReadyRecord {
    pub(super) fn from_snapshot(snapshot: &RuntimeNetRecoverySnapshot) -> Self {
        Self {
            replacement: snapshot.replacement,
            authority_epoch: snapshot.authority_epoch,
            binding_epoch: snapshot.binding_epoch,
            socket_generation: snapshot.socket_generation,
            source_generation: snapshot.source_generation,
            domain_revision: snapshot.domain_revision,
            cohort: snapshot.cohort.iter().map(|token| token.effect).collect(),
        }
    }
}
