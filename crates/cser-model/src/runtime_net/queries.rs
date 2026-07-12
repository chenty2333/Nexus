use alloc::collections::BTreeSet;

use super::*;

impl RuntimeNetModel {
    /// Returns the read-only projection of one root scope.
    pub fn scope(&self, scope: ScopeId) -> Result<RuntimeNetScopeView, RuntimeNetError> {
        let record = self.scope_record(scope)?;
        let live_effects = record
            .effects
            .iter()
            .filter(|effect| {
                self.effects
                    .get(effect)
                    .is_some_and(|entry| !entry.phase.is_terminal())
            })
            .count();
        let pending_publications = record
            .effects
            .iter()
            .filter(|effect| {
                self.effects
                    .get(effect)
                    .is_some_and(|entry| entry.publication.is_some())
            })
            .count();
        let (closure_target_count, closure_steps) =
            record.revocation.as_ref().map_or((0, 0), |revocation| {
                (revocation.frozen.len(), revocation.closure_steps)
            });
        Ok(RuntimeNetScopeView {
            state: record.state,
            authority_epoch: record.authority_epoch,
            socket_generation: record.socket_generation,
            source_generation: record.source_generation,
            initial_credits: record.initial_credits,
            free_credits: record.free_credits,
            network_publications: record.network_publications,
            readiness_publications: record.readiness_publications,
            ready_deliveries: record.ready_deliveries,
            guest_replies: record.guest_replies,
            buffer_consumptions: record.buffer_consumptions,
            visible_buffers: record.buffers.len(),
            effects: record.effects.len(),
            live_effects,
            pending_publications,
            closure_target_count,
            closure_steps,
        })
    }

    /// Returns the read-only projection of one service domain.
    pub fn domain(
        &self,
        scope: ScopeId,
        domain: NetDomain,
    ) -> Result<RuntimeNetDomainView, RuntimeNetError> {
        let record = self
            .scope_record(scope)?
            .domains
            .get(&domain)
            .ok_or(RuntimeNetError::WrongDomain)?;
        Ok(RuntimeNetDomainView {
            binding_epoch: record.binding_epoch,
            service: record.service,
            fallback: record.fallback,
            revision: record.revision,
            recovery_cohort: record.recovery_cohort.iter().copied().collect(),
        })
    }

    /// Returns the read-only projection of one effect.
    pub fn effect(&self, effect: EffectId) -> Result<RuntimeNetEffectView, RuntimeNetError> {
        let record = self.effect_record(effect)?;
        Ok(RuntimeNetEffectView {
            token: record.token,
            phase: record.phase,
            credit: record.credit,
            commit_sequence: record.commit_sequence,
            publication_pending: record.publication.is_some(),
            guest_published: record.guest_published,
            terminalizations: record.terminalizations,
        })
    }

    /// Returns the immutable network receipt retained for one effect.
    pub fn net_receipt(
        &self,
        effect: EffectId,
    ) -> Result<Option<NetCommitReceipt>, RuntimeNetError> {
        Ok(self.effect_record(effect)?.net_receipt)
    }

    /// Returns the immutable readiness receipt retained for one effect.
    pub fn ready_receipt(
        &self,
        effect: EffectId,
    ) -> Result<Option<ReadyCommitReceipt>, RuntimeNetError> {
        Ok(self.effect_record(effect)?.ready_receipt)
    }

    /// Returns a currently visible payload for one exact buffer lease.
    pub fn buffer_payload(
        &self,
        scope: ScopeId,
        buffer: EffectId,
    ) -> Result<Option<[u8; 4]>, RuntimeNetError> {
        Ok(self
            .scope_record(scope)?
            .buffers
            .get(&buffer)
            .map(|record| record.payload))
    }

    /// Audits graph identity, credits, publications, recovery, and closure.
    pub fn check_invariants(&self) -> Result<(), RuntimeNetInvariantViolation> {
        let mut global_commit_sequences = BTreeSet::new();
        let mut global_ticket_sequences = BTreeSet::new();

        for (scope_id, scope) in &self.scopes {
            if scope.domains.len() != NetDomain::ALL.len()
                || NetDomain::ALL
                    .iter()
                    .any(|domain| !scope.domains.contains_key(domain))
            {
                return Err(RuntimeNetInvariantViolation::RecoveryState(*scope_id));
            }

            let mut held = NetCredits::ZERO;
            let mut counted_network = 0u64;
            let mut counted_ready = 0u64;
            let mut counted_ready_deliveries = 0u64;
            let mut counted_replies = 0u64;
            for effect_id in &scope.effects {
                let Some(effect) = self.effects.get(effect_id) else {
                    return Err(RuntimeNetInvariantViolation::ScopeIndex(*scope_id));
                };
                if effect.token.scope != *scope_id {
                    return Err(RuntimeNetInvariantViolation::ScopeIndex(*scope_id));
                }
                if !effect.phase.is_terminal() {
                    held = held
                        .checked_add(NetCredits::one(effect.credit))
                        .ok_or(RuntimeNetInvariantViolation::CreditConservation(*scope_id))?;
                }
                self.check_effect_graph(*effect_id, effect)?;
                self.check_effect_publication(*effect_id, effect, scope)?;

                if effect.token.kind == NetEffectKind::NetOperation && effect.net_receipt.is_some()
                {
                    counted_network = counted_network.checked_add(1).ok_or(
                        RuntimeNetInvariantViolation::GenerationAccounting(*scope_id),
                    )?;
                }
                if effect.token.kind == NetEffectKind::ReadinessWait
                    && effect.ready_receipt.is_some()
                {
                    counted_ready = counted_ready.checked_add(1).ok_or(
                        RuntimeNetInvariantViolation::GenerationAccounting(*scope_id),
                    )?;
                }
                if effect.token.kind == NetEffectKind::ReadinessWait
                    && effect.ready_receipt.is_some()
                    && effect.phase == NetEffectPhase::Completed
                {
                    counted_ready_deliveries = counted_ready_deliveries.checked_add(1).ok_or(
                        RuntimeNetInvariantViolation::GenerationAccounting(*scope_id),
                    )?;
                }
                if effect.guest_published {
                    counted_replies = counted_replies.checked_add(1).ok_or(
                        RuntimeNetInvariantViolation::GenerationAccounting(*scope_id),
                    )?;
                }
                if effect.token.kind != NetEffectKind::BufferLease
                    && let Some(sequence) = effect.commit_sequence
                    && !global_commit_sequences.insert(sequence)
                {
                    return Err(RuntimeNetInvariantViolation::PublicationState(*effect_id));
                }
                if let Some(ticket) = effect.publication
                    && !global_ticket_sequences.insert(ticket.ticket_sequence)
                {
                    return Err(RuntimeNetInvariantViolation::PublicationState(*effect_id));
                }
            }

            let total = scope
                .free_credits
                .checked_add(held)
                .ok_or(RuntimeNetInvariantViolation::CreditConservation(*scope_id))?;
            if total != scope.initial_credits || !scope.initial_credits.contains(scope.free_credits)
            {
                return Err(RuntimeNetInvariantViolation::CreditConservation(*scope_id));
            }
            if counted_network != scope.network_publications
                || counted_ready != scope.readiness_publications
                || counted_ready_deliveries != scope.ready_deliveries
                || scope.ready_deliveries > scope.readiness_publications
                || counted_replies != scope.guest_replies
                || scope.socket_generation.get() != counted_network.saturating_add(1)
                || scope.source_generation.get() != counted_ready.saturating_add(1)
                || scope.buffer_consumptions > scope.network_publications
            {
                return Err(RuntimeNetInvariantViolation::GenerationAccounting(
                    *scope_id,
                ));
            }

            for (buffer_effect, buffer) in &scope.buffers {
                let Some(effect) = self.effects.get(buffer_effect) else {
                    return Err(RuntimeNetInvariantViolation::ScopeIndex(*scope_id));
                };
                if buffer.effect != *buffer_effect
                    || effect.token.scope != *scope_id
                    || effect.token.kind != NetEffectKind::BufferLease
                    || effect.phase != NetEffectPhase::Committed
                    || effect.commit_sequence != Some(buffer.net_sequence)
                    || effect.net_receipt.is_none_or(|receipt| {
                        receipt.effect != buffer.network_effect
                            || receipt.buffer_effect != *buffer_effect
                            || receipt.sequence != buffer.net_sequence
                            || receipt.payload != buffer.payload
                    })
                {
                    return Err(RuntimeNetInvariantViolation::PublicationState(
                        *buffer_effect,
                    ));
                }
            }

            self.check_recovery_state(*scope_id, scope)?;
            self.check_revocation_state(*scope_id, scope)?;
        }

        for (effect_id, effect) in &self.effects {
            let Some(scope) = self.scopes.get(&effect.token.scope) else {
                return Err(RuntimeNetInvariantViolation::ScopeIndex(effect.token.scope));
            };
            if !scope.effects.contains(effect_id) {
                return Err(RuntimeNetInvariantViolation::ScopeIndex(effect.token.scope));
            }
        }
        Ok(())
    }

    fn check_effect_graph(
        &self,
        effect_id: EffectId,
        effect: &EffectRecord,
    ) -> Result<(), RuntimeNetInvariantViolation> {
        if effect.credit != effect.token.kind.credit()
            || effect.token.authority_epoch.get()
                > self
                    .scopes
                    .get(&effect.token.scope)
                    .map_or(0, |scope| scope.authority_epoch.get())
        {
            return Err(RuntimeNetInvariantViolation::EffectGraph(effect_id));
        }
        let scope = self
            .scopes
            .get(&effect.token.scope)
            .ok_or(RuntimeNetInvariantViolation::EffectGraph(effect_id))?;
        let domain = scope
            .domains
            .get(&effect.token.kind.domain())
            .ok_or(RuntimeNetInvariantViolation::EffectGraph(effect_id))?;
        if effect.token.binding_epoch.get() > domain.binding_epoch.get() {
            return Err(RuntimeNetInvariantViolation::EffectGraph(effect_id));
        }
        let parent_kind = effect
            .token
            .parent
            .and_then(|parent| self.effects.get(&parent))
            .map(|parent| (parent.token.scope, parent.token.kind));
        let valid_parent = match effect.token.kind {
            NetEffectKind::Syscall => effect.token.parent.is_none(),
            NetEffectKind::NetOperation => {
                parent_kind == Some((effect.token.scope, NetEffectKind::Syscall))
            }
            NetEffectKind::ReadinessWait | NetEffectKind::BufferLease => {
                parent_kind == Some((effect.token.scope, NetEffectKind::NetOperation))
            }
        };
        if !valid_parent
            || effect.terminalizations > 1
            || effect.phase.is_terminal() != (effect.terminalizations == 1)
        {
            return Err(if !valid_parent {
                RuntimeNetInvariantViolation::EffectGraph(effect_id)
            } else {
                RuntimeNetInvariantViolation::Terminalization(effect_id)
            });
        }
        Ok(())
    }

    fn check_effect_publication(
        &self,
        effect_id: EffectId,
        effect: &EffectRecord,
        scope: &ScopeRecord,
    ) -> Result<(), RuntimeNetInvariantViolation> {
        let uncommitted = matches!(
            effect.phase,
            NetEffectPhase::Registered | NetEffectPhase::Prepared | NetEffectPhase::Aborted
        );
        let valid = match effect.token.kind {
            NetEffectKind::NetOperation => {
                if uncommitted {
                    effect.commit_sequence.is_none()
                        && effect.net_receipt.is_none()
                        && effect.ready_receipt.is_none()
                        && effect.publication.is_none()
                        && !effect.guest_published
                } else {
                    effect.net_receipt.is_some_and(|receipt| {
                        receipt.scope == effect.token.scope
                            && receipt.effect == effect_id
                            && receipt.sequence == effect.commit_sequence.unwrap_or(0)
                            && receipt.payload == LOOPBACK_PAYLOAD
                    }) && effect.ready_receipt.is_none()
                        && effect.publication.is_none()
                        && !effect.guest_published
                }
            }
            NetEffectKind::BufferLease => {
                if uncommitted {
                    effect.commit_sequence.is_none()
                        && effect.net_receipt.is_none()
                        && !scope.buffers.contains_key(&effect_id)
                } else {
                    effect.net_receipt.is_some_and(|receipt| {
                        receipt.scope == effect.token.scope
                            && receipt.buffer_effect == effect_id
                            && receipt.sequence == effect.commit_sequence.unwrap_or(0)
                            && receipt.payload == LOOPBACK_PAYLOAD
                    }) && (effect.phase == NetEffectPhase::Committed)
                        == scope.buffers.contains_key(&effect_id)
                }
            }
            NetEffectKind::ReadinessWait => {
                if uncommitted {
                    effect.commit_sequence.is_none() && effect.ready_receipt.is_none()
                } else {
                    effect.ready_receipt.is_some_and(|receipt| {
                        receipt.scope == effect.token.scope
                            && receipt.effect == effect_id
                            && receipt.sequence == effect.commit_sequence.unwrap_or(0)
                            && self
                                .effects
                                .get(&receipt.network_effect)
                                .is_some_and(|network| {
                                    network.net_receipt.is_some_and(|net| {
                                        net.sequence == receipt.network_sequence
                                            && net.effect == receipt.network_effect
                                    })
                                })
                    })
                }
            }
            NetEffectKind::Syscall => match effect.phase {
                NetEffectPhase::Registered | NetEffectPhase::Prepared | NetEffectPhase::Aborted => {
                    effect.commit_sequence.is_none()
                        && effect.publication.is_none()
                        && !effect.guest_published
                }
                NetEffectPhase::Committed => {
                    effect.commit_sequence.is_some()
                        && effect.publication.is_some_and(|ticket| {
                            ticket.scope == effect.token.scope
                                && ticket.effect == effect_id
                                && ticket.commit_sequence
                                    == effect.commit_sequence.unwrap_or_default()
                                && self.effects.get(&ticket.ready_effect).is_some_and(|ready| {
                                    ready.ready_receipt.is_some_and(|receipt| {
                                        receipt.sequence == ticket.ready_sequence
                                    })
                                })
                        })
                        && !effect.guest_published
                }
                NetEffectPhase::Completed => {
                    effect.commit_sequence.is_some()
                        && effect.publication.is_none()
                        && effect.guest_published
                }
            },
        };
        if !valid {
            return Err(RuntimeNetInvariantViolation::PublicationState(effect_id));
        }
        Ok(())
    }

    fn check_recovery_state(
        &self,
        scope_id: ScopeId,
        scope: &ScopeRecord,
    ) -> Result<(), RuntimeNetInvariantViolation> {
        for (domain_kind, domain) in &scope.domains {
            let binding_shape = matches!(
                (domain.service, domain.fallback),
                (Some(_), NetFallbackState::Standby)
                    | (
                        None,
                        NetFallbackState::Required
                            | NetFallbackState::Running
                            | NetFallbackState::ReplacementReady,
                    )
            );
            if !binding_shape
                || (domain.fallback == NetFallbackState::ReplacementReady) != domain.ready.is_some()
                || (scope.state != ScopeState::Active && !domain.recovery_cohort.is_empty())
            {
                return Err(RuntimeNetInvariantViolation::RecoveryState(scope_id));
            }
            for effect_id in &domain.recovery_cohort {
                let Some(effect) = self.effects.get(effect_id) else {
                    return Err(RuntimeNetInvariantViolation::RecoveryState(scope_id));
                };
                if effect.token.scope != scope_id
                    || effect.token.kind.domain() != *domain_kind
                    || !effect.phase.is_uncommitted()
                    || effect.token.binding_epoch.get() >= domain.binding_epoch.get()
                {
                    return Err(RuntimeNetInvariantViolation::RecoveryState(scope_id));
                }
            }
            if let Some(ready) = &domain.ready
                && (domain.service.is_some()
                    || ready.authority_epoch != scope.authority_epoch
                    || ready.binding_epoch != domain.binding_epoch
                    || ready.socket_generation != scope.socket_generation
                    || ready.source_generation != scope.source_generation
                    || ready.domain_revision != domain.revision
                    || ready.cohort != domain.recovery_cohort
                    || ready.replacement.get() == 0
                    || scope
                        .domains
                        .values()
                        .any(|candidate| candidate.service == Some(ready.replacement)))
            {
                return Err(RuntimeNetInvariantViolation::RecoveryState(scope_id));
            }
        }
        Ok(())
    }

    fn check_revocation_state(
        &self,
        scope_id: ScopeId,
        scope: &ScopeRecord,
    ) -> Result<(), RuntimeNetInvariantViolation> {
        match (scope.state, scope.revocation.as_ref()) {
            (ScopeState::Active, None) => Ok(()),
            (ScopeState::Closing | ScopeState::Revoked, Some(revocation)) => {
                let closed_plus_one = revocation.ticket.closed_epoch.get().checked_add(1);
                let terminal = revocation
                    .frozen
                    .iter()
                    .filter(|effect| {
                        self.effects
                            .get(effect)
                            .is_some_and(|record| record.phase.is_terminal())
                    })
                    .count();
                let shape_valid = revocation.ticket.scope == scope_id
                    && revocation.ticket.authority_epoch == scope.authority_epoch
                    && closed_plus_one == Some(scope.authority_epoch.get())
                    && revocation.closure_steps == terminal
                    && revocation.closure_steps <= revocation.frozen.len()
                    && revocation.frozen.iter().all(|effect| {
                        scope.effects.contains(effect)
                            && self
                                .effects
                                .get(effect)
                                .is_some_and(|record| record.token.scope == scope_id)
                    });
                if !shape_valid {
                    return Err(RuntimeNetInvariantViolation::RevocationState(scope_id));
                }
                if scope.state == ScopeState::Revoked {
                    let live = scope.effects.iter().any(|effect| {
                        self.effects
                            .get(effect)
                            .is_some_and(|record| !record.phase.is_terminal())
                    });
                    let pending = scope.effects.iter().any(|effect| {
                        self.effects
                            .get(effect)
                            .is_some_and(|record| record.publication.is_some())
                    });
                    if live
                        || pending
                        || !scope.buffers.is_empty()
                        || scope.free_credits != scope.initial_credits
                        || revocation.closure_steps != revocation.frozen.len()
                    {
                        return Err(RuntimeNetInvariantViolation::RevokedScope(scope_id));
                    }
                }
                Ok(())
            }
            _ => Err(RuntimeNetInvariantViolation::RevocationState(scope_id)),
        }
    }
}
