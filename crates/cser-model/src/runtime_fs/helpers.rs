use alloc::collections::BTreeSet;

use super::*;

impl RuntimeFsModel {
    pub(super) fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, RuntimeFsError>,
    ) -> Result<T, RuntimeFsError> {
        let mut candidate = self.clone();
        let result = operation(&mut candidate)?;
        candidate
            .check_invariants()
            .map_err(|_| RuntimeFsError::InvariantViolation("post-transition invariant"))?;
        *self = candidate;
        Ok(result)
    }

    pub(super) fn scope_record(&self, scope: ScopeId) -> Result<&ScopeRecord, RuntimeFsError> {
        self.scopes
            .get(&scope)
            .ok_or(RuntimeFsError::UnknownScope(scope))
    }

    pub(super) fn scope_record_mut(
        &mut self,
        scope: ScopeId,
    ) -> Result<&mut ScopeRecord, RuntimeFsError> {
        self.scopes
            .get_mut(&scope)
            .ok_or(RuntimeFsError::UnknownScope(scope))
    }

    pub(super) fn effect_record(&self, effect: EffectId) -> Result<&EffectRecord, RuntimeFsError> {
        self.effects
            .get(&effect)
            .ok_or(RuntimeFsError::UnknownEffect(effect))
    }

    pub(super) fn effect_record_mut(
        &mut self,
        effect: EffectId,
    ) -> Result<&mut EffectRecord, RuntimeFsError> {
        self.effects
            .get_mut(&effect)
            .ok_or(RuntimeFsError::UnknownEffect(effect))
    }

    pub(super) fn validate_binding(
        &self,
        binding: RuntimeFsBindingToken,
    ) -> Result<&ScopeRecord, RuntimeFsError> {
        let scope = self.scope_record(binding.scope)?;
        if binding.authority_epoch != scope.authority_epoch {
            return Err(RuntimeFsError::StaleAuthority {
                presented: binding.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if scope.state != ScopeState::Active {
            return Err(RuntimeFsError::InvalidScopeState(scope.state));
        }
        let domain = scope
            .domains
            .get(&binding.domain)
            .ok_or(RuntimeFsError::WrongDomain)?;
        if binding.binding_epoch != domain.binding_epoch {
            return Err(RuntimeFsError::StaleBinding {
                presented: binding.binding_epoch,
                current: domain.binding_epoch,
            });
        }
        match domain.service {
            Some(service) if service == binding.service => Ok(scope),
            Some(_) => Err(RuntimeFsError::WrongService),
            None => Err(RuntimeFsError::ServiceUnavailable),
        }
    }

    pub(super) fn validate_effect_identity(
        &self,
        token: RuntimeFsEffectToken,
    ) -> Result<&EffectRecord, RuntimeFsError> {
        let record = self.effect_record(token.effect)?;
        if record.token != token {
            return Err(RuntimeFsError::EffectIdentityMismatch);
        }
        Ok(record)
    }

    pub(super) fn validate_service_effect(
        &self,
        binding: RuntimeFsBindingToken,
        token: RuntimeFsEffectToken,
        kind: FsEffectKind,
    ) -> Result<&EffectRecord, RuntimeFsError> {
        let scope = self.validate_binding(binding)?;
        if binding.scope != token.scope || binding.domain != kind.domain() || token.kind != kind {
            return Err(RuntimeFsError::WrongDomain);
        }
        if token.authority_epoch != scope.authority_epoch {
            return Err(RuntimeFsError::StaleAuthority {
                presented: token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        let current_binding = scope
            .domains
            .get(&binding.domain)
            .ok_or(RuntimeFsError::WrongDomain)?
            .binding_epoch;
        if token.binding_epoch != current_binding {
            return Err(RuntimeFsError::StaleBinding {
                presented: token.binding_epoch,
                current: current_binding,
            });
        }
        self.validate_effect_identity(token)
    }

    pub(super) fn validate_generation(
        &self,
        token: RuntimeFsEffectToken,
    ) -> Result<(), RuntimeFsError> {
        let scope = self.scope_record(token.scope)?;
        match token.kind {
            FsEffectKind::PagerMap
                if token.address_space_generation != scope.address_space_generation =>
            {
                Err(RuntimeFsError::StaleAddressSpaceGeneration {
                    presented: token.address_space_generation,
                    current: scope.address_space_generation,
                })
            }
            FsEffectKind::FsOperation if token.inode_generation != scope.inode_generation => {
                Err(RuntimeFsError::StaleInodeGeneration {
                    presented: token.inode_generation,
                    current: scope.inode_generation,
                })
            }
            FsEffectKind::BlockRequest if token.device_generation != scope.device_generation => {
                Err(RuntimeFsError::StaleDeviceGeneration {
                    presented: token.device_generation,
                    current: scope.device_generation,
                })
            }
            _ => Ok(()),
        }
    }

    pub(super) fn validate_revoke_ticket(
        &self,
        ticket: RuntimeFsRevokeTicket,
    ) -> Result<&RevocationRecord, RuntimeFsError> {
        let scope = self.scope_record(ticket.scope)?;
        if scope.state != ScopeState::Closing {
            return Err(RuntimeFsError::InvalidScopeState(scope.state));
        }
        let revocation = scope
            .revocation
            .as_ref()
            .ok_or(RuntimeFsError::StaleRevokeTicket)?;
        if revocation.ticket != ticket {
            return Err(RuntimeFsError::StaleRevokeTicket);
        }
        Ok(revocation)
    }

    pub(super) fn validate_dma_recovery(
        &self,
        token: FsDmaRecoveryToken,
    ) -> Result<&EffectRecord, RuntimeFsError> {
        let scope = self.scope_record(token.scope)?;
        if token.revoke_sequence == 0 {
            if scope.state != ScopeState::Active || token.kind != FsDmaRecoveryKind::Iotlb {
                return Err(RuntimeFsError::InvalidScopeState(scope.state));
            }
        } else if scope.state != ScopeState::Closing
            || scope.revocation.as_ref().is_none_or(|revocation| {
                revocation.ticket.sequence != token.revoke_sequence
                    || revocation.ticket.authority_epoch != scope.authority_epoch
            })
        {
            return Err(RuntimeFsError::StaleRevokeTicket);
        }
        if token.device_generation != scope.device_generation {
            return Err(RuntimeFsError::StaleDeviceGeneration {
                presented: token.device_generation,
                current: scope.device_generation,
            });
        }
        let effect = self.effect_record(token.effect)?;
        if effect.token.kind != FsEffectKind::BlockRequest || effect.dma_attempt != token.attempt {
            return Err(RuntimeFsError::StaleDmaAttempt);
        }
        let expected = match token.kind {
            FsDmaRecoveryKind::Reset => FsDmaState::ResetInFlight,
            FsDmaRecoveryKind::Iotlb => FsDmaState::IotlbInFlight,
        };
        if effect.dma_state != expected {
            return Err(RuntimeFsError::InvalidDmaState(effect.dma_state));
        }
        Ok(effect)
    }

    pub(super) fn current_dma_token(
        &self,
        ticket: RuntimeFsRevokeTicket,
        effect: EffectId,
        kind: FsDmaRecoveryKind,
    ) -> Result<FsDmaRecoveryToken, RuntimeFsError> {
        self.validate_revoke_ticket(ticket)?;
        let record = self.effect_record(effect)?;
        Ok(FsDmaRecoveryToken {
            scope: ticket.scope,
            effect,
            revoke_sequence: ticket.sequence,
            attempt: record.dma_attempt,
            device_generation: self.scope_record(ticket.scope)?.device_generation,
            kind,
        })
    }

    pub(super) fn bump_domain_revision(
        &mut self,
        scope: ScopeId,
        domain: FsDomain,
    ) -> Result<(), RuntimeFsError> {
        let record = self
            .scope_record_mut(scope)?
            .domains
            .get_mut(&domain)
            .ok_or(RuntimeFsError::WrongDomain)?;
        record.revision = record
            .revision
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        record.ready = None;
        if record.fallback == FsFallbackState::ReplacementReady {
            record.fallback = FsFallbackState::Running;
        }
        Ok(())
    }

    pub(super) fn take_effect_id(&mut self) -> Result<EffectId, RuntimeFsError> {
        let effect = EffectId::new(self.next_effect);
        self.next_effect = self
            .next_effect
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        Ok(effect)
    }

    pub(super) fn take_commit_sequence(&mut self) -> Result<u64, RuntimeFsError> {
        let sequence = self.next_commit_sequence;
        self.next_commit_sequence = self
            .next_commit_sequence
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        Ok(sequence)
    }

    pub(super) fn take_publication_sequence(&mut self) -> Result<u64, RuntimeFsError> {
        let sequence = self.next_publication_sequence;
        self.next_publication_sequence = self
            .next_publication_sequence
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        Ok(sequence)
    }

    pub(super) fn take_tombstone_id(&mut self) -> Result<TombstoneId, RuntimeFsError> {
        let tombstone = TombstoneId::new(self.next_tombstone);
        self.next_tombstone = self
            .next_tombstone
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        Ok(tombstone)
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
    ) -> Result<Vec<EffectId>, RuntimeFsError> {
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
        phase: FsEffectPhase,
    ) -> Result<(), RuntimeFsError> {
        if !phase.is_terminal() {
            return Err(RuntimeFsError::InvariantViolation(
                "terminalize requires terminal phase",
            ));
        }
        if self.has_live_children(effect) {
            return Err(RuntimeFsError::LiveDescendants);
        }
        let record = *self.effect_record(effect)?;
        if record.phase.is_terminal() {
            return Err(RuntimeFsError::InvalidEffectState(record.phase));
        }
        if record.token.kind == FsEffectKind::BlockRequest
            && record.dma_state != FsDmaState::Released
        {
            return Err(RuntimeFsError::InvalidDmaState(record.dma_state));
        }
        let credit = FsCredits::one(record.credit);
        let scope = self.scope_record(record.token.scope)?;
        let free = scope
            .free_credits
            .checked_add(credit)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        if !scope.initial_credits.contains(free) {
            return Err(RuntimeFsError::InvariantViolation("credit return overflow"));
        }
        let target = self.effect_record_mut(effect)?;
        target.phase = phase;
        target.terminalizations = target
            .terminalizations
            .checked_add(1)
            .ok_or(RuntimeFsError::CounterOverflow)?;
        target.publication = None;
        self.scope_record_mut(record.token.scope)?.free_credits = free;
        self.bump_domain_revision(record.token.scope, record.token.kind.domain())?;
        Ok(())
    }

    pub(super) fn make_recovery_snapshot(
        &self,
        scope: ScopeId,
        domain: FsDomain,
        replacement: ServiceId,
    ) -> Result<RuntimeFsRecoverySnapshot, RuntimeFsError> {
        let scope_record = self.scope_record(scope)?;
        let domain_record = scope_record
            .domains
            .get(&domain)
            .ok_or(RuntimeFsError::WrongDomain)?;
        if scope_record.state != ScopeState::Active
            || domain_record.service.is_some()
            || domain_record.fallback != FsFallbackState::Running
        {
            return Err(RuntimeFsError::FallbackUnavailable);
        }
        let mut cohort = Vec::new();
        for effect in &domain_record.recovery_cohort {
            cohort.push(self.effect_record(*effect)?.token);
        }
        Ok(RuntimeFsRecoverySnapshot {
            scope,
            domain,
            replacement,
            authority_epoch: scope_record.authority_epoch,
            binding_epoch: domain_record.binding_epoch,
            address_space_generation: scope_record.address_space_generation,
            inode_generation: scope_record.inode_generation,
            device_generation: scope_record.device_generation,
            domain_revision: domain_record.revision,
            cohort,
        })
    }
}

impl ReadyRecord {
    pub(super) fn from_snapshot(snapshot: &RuntimeFsRecoverySnapshot) -> Self {
        Self {
            replacement: snapshot.replacement,
            authority_epoch: snapshot.authority_epoch,
            binding_epoch: snapshot.binding_epoch,
            address_space_generation: snapshot.address_space_generation,
            inode_generation: snapshot.inode_generation,
            device_generation: snapshot.device_generation,
            domain_revision: snapshot.domain_revision,
            cohort: snapshot.cohort.iter().map(|token| token.effect).collect(),
        }
    }
}
