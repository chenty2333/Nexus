use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::*;

impl Default for CompositionModel {
    fn default() -> Self {
        Self::new()
    }
}

impl CompositionModel {
    /// Creates an empty composition model.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_scope: 1,
            next_effect: 1,
            next_commit: 1,
            next_tombstone: 1,
            next_revoke: 1,
            next_closure_receipt: 1,
            scopes: BTreeMap::new(),
            effects: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        }
    }

    /// Creates one active root scope with a typed-credit ledger.
    pub fn create_scope(&mut self, credits: CreditBundle) -> Result<ScopeId, CompositionError> {
        let scope = ScopeId::new(self.next_scope);
        let next = self
            .next_scope
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        self.scopes.insert(
            scope,
            ScopeRecord {
                state: ScopeState::Active,
                authority_epoch: AuthorityEpoch::new(1),
                initial_credits: credits,
                free_credits: credits,
                domains: BTreeMap::new(),
                revocation: None,
            },
        );
        self.next_scope = next;
        Ok(scope)
    }

    /// Registers one independently restartable domain under an active root.
    pub fn register_domain(
        &mut self,
        scope: ScopeId,
        domain: DomainId,
        service: ServiceId,
    ) -> Result<DomainBindingToken, CompositionError> {
        let record = self.scope_record(scope)?;
        if record.state != ScopeState::Active {
            return Err(CompositionError::ScopeNotActive(record.state));
        }
        if record.domains.contains_key(&domain) {
            return Err(CompositionError::DomainAlreadyRegistered(domain));
        }
        let authority_epoch = record.authority_epoch;
        let binding_epoch = BindingEpoch::new(1);
        let device_generation = DeviceGeneration::new(1);
        self.scope_record_mut(scope)?.domains.insert(
            domain,
            DomainRecord {
                service: Some(service),
                binding_epoch,
                device_generation,
                fallback: DomainFallbackState::Standby,
                mutation_generation: 1,
                recovery_cohort: BTreeSet::new(),
                live_effects: BTreeSet::new(),
                leaf_effects: BTreeSet::new(),
                tombstones: BTreeSet::new(),
                closure_revision: 0,
                issued_receipt: None,
            },
        );
        Ok(DomainBindingToken {
            scope,
            domain,
            service,
            authority_epoch,
            binding_epoch,
            device_generation,
        })
    }

    /// Registers a parentless effect and transfers credits from the root pool.
    pub fn register_root(
        &mut self,
        binding: DomainBindingToken,
        kind: CompositionEffectKind,
        credits: CreditBundle,
    ) -> Result<CompositionEffectToken, CompositionError> {
        self.validate_binding(binding)?;
        if kind.domain() != binding.domain {
            return Err(CompositionError::WrongDomain);
        }
        if credits.is_zero() {
            return Err(CompositionError::EmptyCreditTransfer);
        }
        let free_after = self
            .scope_record(binding.scope)?
            .free_credits
            .checked_sub(credits)?;
        let effect = EffectId::new(self.next_effect);
        let next = self
            .next_effect
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        let token = CompositionEffectToken {
            scope: binding.scope,
            effect,
            parent: None,
            domain: binding.domain,
            kind,
            authority_epoch: binding.authority_epoch,
            binding_epoch: binding.binding_epoch,
            device_generation: binding.device_generation,
        };
        self.scope_record_mut(binding.scope)?.free_credits = free_after;
        self.insert_effect(token, credits)?;
        self.next_effect = next;
        Ok(token)
    }

    /// Failure-atomically derives one causal child and transfers typed credits.
    pub fn derive_child(
        &mut self,
        parent: CompositionEffectToken,
        target: DomainBindingToken,
        kind: CompositionEffectKind,
        credits: CreditBundle,
    ) -> Result<CompositionEffectToken, CompositionError> {
        let mut candidate = self.clone();
        let token = candidate.derive_child_inner(parent, target, kind, credits)?;
        *self = candidate;
        Ok(token)
    }

    fn derive_child_inner(
        &mut self,
        parent: CompositionEffectToken,
        target: DomainBindingToken,
        kind: CompositionEffectKind,
        credits: CreditBundle,
    ) -> Result<CompositionEffectToken, CompositionError> {
        self.validate_binding(target)?;
        if kind.domain() != target.domain || parent.scope != target.scope {
            return Err(CompositionError::WrongDomain);
        }
        if credits.is_zero() {
            return Err(CompositionError::EmptyCreditTransfer);
        }
        self.validate_effect_current(parent)?;
        let parent_record = self.effect_record(parent.effect)?;
        if parent_record.state.is_terminal() {
            return Err(CompositionError::InvalidEffectState(parent_record.state));
        }
        let parent_after = parent_record.held_credits.checked_sub(credits)?;
        let effect = EffectId::new(self.next_effect);
        let next = self
            .next_effect
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        let token = CompositionEffectToken {
            scope: parent.scope,
            effect,
            parent: Some(parent.effect),
            domain: target.domain,
            kind,
            authority_epoch: target.authority_epoch,
            binding_epoch: target.binding_epoch,
            device_generation: target.device_generation,
        };

        self.effect_record_mut(parent.effect)?.held_credits = parent_after;
        self.effect_record_mut(parent.effect)?
            .live_children
            .insert(effect);
        self.domain_record_mut(parent.scope, parent.domain)?
            .leaf_effects
            .remove(&parent.effect);
        self.insert_effect(token, credits)?;
        if parent.domain != target.domain {
            self.bump_domain_mutation(parent.scope, parent.domain)?;
        }
        self.next_effect = next;
        Ok(token)
    }

    /// Marks a current uncommitted effect ready for its domain commit point.
    pub fn prepare(
        &mut self,
        binding: DomainBindingToken,
        token: CompositionEffectToken,
    ) -> Result<(), CompositionError> {
        self.validate_binding(binding)?;
        self.validate_binding_for_effect(binding, token)?;
        let state = self.effect_record(token.effect)?.state;
        if state != CompositionEffectState::Registered {
            return Err(CompositionError::InvalidEffectState(state));
        }
        self.effect_record_mut(token.effect)?.state = CompositionEffectState::Prepared;
        self.bump_domain_mutation(token.scope, token.domain)?;
        Ok(())
    }

    /// Crosses one commit point under the root and domain generation gates.
    pub fn commit(
        &mut self,
        binding: DomainBindingToken,
        token: CompositionEffectToken,
    ) -> Result<CompositionCommitReceipt, CompositionError> {
        self.validate_binding(binding)?;
        self.validate_binding_for_effect(binding, token)?;
        let record = self.effect_record(token.effect)?;
        if record.state != CompositionEffectState::Prepared {
            return Err(CompositionError::InvalidEffectState(record.state));
        }
        let receipt = CompositionCommitReceipt {
            token,
            sequence: self.next_commit,
        };
        let next = self
            .next_commit
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        let record = self.effect_record_mut(token.effect)?;
        record.state = CompositionEffectState::Committed;
        record.commit_receipt = Some(receipt);
        self.next_commit = next;
        self.bump_domain_mutation(token.scope, token.domain)?;
        Ok(receipt)
    }

    /// Completes one committed effect through its immutable kernel receipt.
    pub fn complete(&mut self, receipt: CompositionCommitReceipt) -> Result<(), CompositionError> {
        let record = self.effect_record(receipt.effect())?;
        if record.commit_receipt != Some(receipt) {
            return Err(CompositionError::CommitReceiptMismatch);
        }
        if record.state != CompositionEffectState::Committed {
            return Err(CompositionError::InvalidEffectState(record.state));
        }
        if !record.live_children.is_empty() {
            return Err(CompositionError::LiveDescendants);
        }
        self.terminalize(
            receipt.effect(),
            CompositionEffectState::Completed,
            true,
            false,
        )
    }

    /// Fences a crashed service by advancing only its binding generation.
    pub fn crash(&mut self, binding: DomainBindingToken) -> Result<(), CompositionError> {
        self.validate_binding(binding)?;
        let next = BindingEpoch::new(
            binding
                .binding_epoch
                .get()
                .checked_add(1)
                .ok_or(CompositionError::CounterOverflow)?,
        );
        let live = self
            .domain_record(binding.scope, binding.domain)?
            .live_effects
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let mut cohort = BTreeSet::new();
        for effect in live {
            let state = self.effect_record(effect)?.state;
            if matches!(
                state,
                CompositionEffectState::Registered | CompositionEffectState::Prepared
            ) {
                cohort.insert(effect);
            }
        }
        let domain = self.domain_record_mut(binding.scope, binding.domain)?;
        domain.service = None;
        domain.binding_epoch = next;
        domain.fallback = DomainFallbackState::Required;
        domain.recovery_cohort = cohort;
        domain.mutation_generation = domain
            .mutation_generation
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        Ok(())
    }

    /// Selects the kernel fallback for one crashed domain.
    pub fn fallback_pick(
        &mut self,
        scope: ScopeId,
        domain: DomainId,
    ) -> Result<(), CompositionError> {
        self.require_active(scope)?;
        let state = self.domain_record(scope, domain)?.fallback;
        if state != DomainFallbackState::Required {
            return Err(CompositionError::InvalidFallbackState(state));
        }
        self.domain_record_mut(scope, domain)?.fallback = DomainFallbackState::Running;
        Ok(())
    }

    /// Captures an exact domain-local recovery snapshot.
    pub fn recovery_snapshot(
        &self,
        scope: ScopeId,
        domain: DomainId,
        replacement: ServiceId,
    ) -> Result<DomainRecoverySnapshot, CompositionError> {
        self.require_active(scope)?;
        let record = self.domain_record(scope, domain)?;
        if record.fallback != DomainFallbackState::Running {
            return Err(CompositionError::InvalidFallbackState(record.fallback));
        }
        let mut effects = Vec::with_capacity(record.live_effects.len());
        for effect in &record.live_effects {
            let effect_record = self.effect_record(*effect)?;
            effects.push(RecoveryEffectSnapshot {
                token: effect_record.token,
                state: effect_record.state,
            });
        }
        Ok(DomainRecoverySnapshot {
            scope,
            domain,
            replacement,
            authority_epoch: self.scope_record(scope)?.authority_epoch,
            binding_epoch: record.binding_epoch,
            device_generation: record.device_generation,
            mutation_generation: record.mutation_generation,
            effects,
            adoption_cohort: record.recovery_cohort.iter().copied().collect(),
        })
    }

    /// Accepts an exact recovery snapshot and issues one Ready proof.
    pub fn ready(
        &mut self,
        snapshot: &DomainRecoverySnapshot,
    ) -> Result<DomainReadyToken, CompositionError> {
        let current =
            self.recovery_snapshot(snapshot.scope, snapshot.domain, snapshot.replacement)?;
        if current != *snapshot {
            return Err(CompositionError::StaleRecoveryProof);
        }
        self.domain_record_mut(snapshot.scope, snapshot.domain)?
            .fallback = DomainFallbackState::ReplacementReady;
        Ok(DomainReadyToken {
            scope: snapshot.scope,
            domain: snapshot.domain,
            replacement: snapshot.replacement,
            authority_epoch: snapshot.authority_epoch,
            binding_epoch: snapshot.binding_epoch,
            device_generation: snapshot.device_generation,
            mutation_generation: snapshot.mutation_generation,
        })
    }

    /// Installs the replacement represented by one current Ready proof.
    pub fn rebind(
        &mut self,
        ready: DomainReadyToken,
    ) -> Result<DomainBindingToken, CompositionError> {
        self.require_active(ready.scope)?;
        let scope_epoch = self.scope_record(ready.scope)?.authority_epoch;
        let domain = self.domain_record(ready.scope, ready.domain)?;
        if domain.fallback != DomainFallbackState::ReplacementReady
            || ready.authority_epoch != scope_epoch
            || ready.binding_epoch != domain.binding_epoch
            || ready.device_generation != domain.device_generation
            || ready.mutation_generation != domain.mutation_generation
        {
            return Err(CompositionError::StaleRecoveryProof);
        }
        let record = self.domain_record_mut(ready.scope, ready.domain)?;
        record.service = Some(ready.replacement);
        record.fallback = DomainFallbackState::Standby;
        Ok(DomainBindingToken {
            scope: ready.scope,
            domain: ready.domain,
            service: ready.replacement,
            authority_epoch: ready.authority_epoch,
            binding_epoch: ready.binding_epoch,
            device_generation: ready.device_generation,
        })
    }

    /// Explicitly transfers one uncommitted crash orphan to a replacement.
    pub fn adopt(
        &mut self,
        binding: DomainBindingToken,
        old: CompositionEffectToken,
    ) -> Result<CompositionEffectToken, CompositionError> {
        self.validate_binding(binding)?;
        let record = self.effect_record(old.effect)?;
        if record.token != old {
            return Err(CompositionError::EffectIdentityMismatch);
        }
        if old.scope != binding.scope || old.domain != binding.domain {
            return Err(CompositionError::NotAdoptable);
        }
        if !matches!(
            record.state,
            CompositionEffectState::Registered | CompositionEffectState::Prepared
        ) || !self
            .domain_record(binding.scope, binding.domain)?
            .recovery_cohort
            .contains(&old.effect)
        {
            return Err(CompositionError::NotAdoptable);
        }
        let mut adopted = old;
        adopted.authority_epoch = binding.authority_epoch;
        adopted.binding_epoch = binding.binding_epoch;
        adopted.device_generation = binding.device_generation;
        self.effect_record_mut(old.effect)?.token = adopted;
        self.domain_record_mut(binding.scope, binding.domain)?
            .recovery_cohort
            .remove(&old.effect);
        self.bump_domain_mutation(binding.scope, binding.domain)?;
        Ok(adopted)
    }

    /// Linearizes root revocation, closes child registration and commit, and
    /// freezes the exact registered-domain cohort without scanning effects.
    pub fn revoke_begin(&mut self, scope: ScopeId) -> Result<RootRevokeTicket, CompositionError> {
        let record = self.scope_record(scope)?;
        if record.state != ScopeState::Active {
            return Err(CompositionError::ScopeNotActive(record.state));
        }
        let closed_epoch = record.authority_epoch;
        let new_epoch = AuthorityEpoch::new(
            closed_epoch
                .get()
                .checked_add(1)
                .ok_or(CompositionError::CounterOverflow)?,
        );
        let generation = self.next_revoke;
        let next_revoke = generation
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        let ticket = RootRevokeTicket {
            scope,
            closed_epoch,
            generation,
        };
        let frozen_domains = record
            .domains
            .iter()
            .filter_map(|(domain, local)| (!local.live_effects.is_empty()).then_some(*domain))
            .collect::<BTreeSet<_>>();
        let mut progress = BTreeMap::new();
        for domain in &frozen_domains {
            let local = record
                .domains
                .get(domain)
                .ok_or(CompositionError::InvariantViolation(
                    "missing frozen domain",
                ))?;
            progress.insert(
                *domain,
                ProgressRecord {
                    target_count: local.live_effects.len(),
                    terminalized: 0,
                    index_selections: 0,
                },
            );
        }
        let record = self.scope_record_mut(scope)?;
        record.state = ScopeState::Closing;
        record.authority_epoch = new_epoch;
        for domain in record.domains.values_mut() {
            domain.closure_revision = domain
                .closure_revision
                .checked_add(1)
                .ok_or(CompositionError::CounterOverflow)?;
            domain.issued_receipt = None;
        }
        record.revocation = Some(RevocationRecord {
            ticket,
            frozen_domains,
            progress,
            accepted: BTreeMap::new(),
        });
        self.next_revoke = next_revoke;
        Ok(ticket)
    }

    /// Advances one leaf effect through a domain-local closure index.
    pub fn close_next(
        &mut self,
        ticket: RootRevokeTicket,
        domain: DomainId,
    ) -> Result<Option<DomainCloseStep>, CompositionError> {
        self.validate_ticket(ticket)?;
        self.require_frozen(ticket.scope, domain)?;
        let local = self.domain_record(ticket.scope, domain)?;
        let Some(effect) = local.leaf_effects.iter().next().copied() else {
            if local.live_effects.is_empty() {
                return Ok(None);
            }
            return Ok(Some(DomainCloseStep::BlockedByDescendants {
                remaining: local.live_effects.len(),
            }));
        };
        let state = self.effect_record(effect)?.state;
        match state {
            CompositionEffectState::Registered | CompositionEffectState::Prepared => {
                self.terminalize(effect, CompositionEffectState::Aborted, true, true)?;
                Ok(Some(DomainCloseStep::Aborted(effect)))
            }
            CompositionEffectState::Committed if domain == DomainId::VirtIo => {
                if self.effect_record(effect)?.external_quiesced {
                    self.terminalize(effect, CompositionEffectState::Completed, true, true)?;
                    Ok(Some(DomainCloseStep::Completed(effect)))
                } else {
                    Ok(Some(DomainCloseStep::NeedsQuiescence(effect)))
                }
            }
            CompositionEffectState::Committed => {
                self.terminalize(effect, CompositionEffectState::Completed, true, true)?;
                Ok(Some(DomainCloseStep::Completed(effect)))
            }
            CompositionEffectState::Tombstoned if domain == DomainId::VirtIo => {
                Ok(Some(DomainCloseStep::NeedsQuiescence(effect)))
            }
            _ => Err(CompositionError::InvalidEffectState(state)),
        }
    }

    /// Retains one committed VirtIO leaf and its credits behind a tombstone.
    pub fn timeout_committed(
        &mut self,
        ticket: RootRevokeTicket,
        token: CompositionEffectToken,
    ) -> Result<TombstoneId, CompositionError> {
        let mut candidate = self.clone();
        let tombstone = candidate.timeout_committed_inner(ticket, token)?;
        *self = candidate;
        Ok(tombstone)
    }

    fn timeout_committed_inner(
        &mut self,
        ticket: RootRevokeTicket,
        token: CompositionEffectToken,
    ) -> Result<TombstoneId, CompositionError> {
        self.validate_ticket(ticket)?;
        self.require_frozen(ticket.scope, DomainId::VirtIo)?;
        if token.scope != ticket.scope {
            return Err(CompositionError::CrossScopeEffect {
                ticket_scope: ticket.scope,
                effect_scope: token.scope,
            });
        }
        let record = self.effect_record(token.effect)?;
        if record.token != token {
            return Err(CompositionError::EffectIdentityMismatch);
        }
        if token.domain != DomainId::VirtIo
            || record.state != CompositionEffectState::Committed
            || !record.live_children.is_empty()
            || !self
                .domain_record(ticket.scope, DomainId::VirtIo)?
                .tombstones
                .is_empty()
        {
            return Err(CompositionError::NotTombstoneEligible);
        }
        let id = TombstoneId::new(self.next_tombstone);
        let next = self
            .next_tombstone
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        let credits = record.held_credits;
        let device_generation = record.token.device_generation;
        let effect = self
            .effects
            .get_mut(&token.effect)
            .expect("validated effect");
        effect.state = CompositionEffectState::Tombstoned;
        effect.tombstone = Some(id);
        effect.external_quiesced = false;
        self.tombstones.insert(
            id,
            TombstoneRecord {
                scope: ticket.scope,
                domain: DomainId::VirtIo,
                effect: token.effect,
                device_generation,
                retained_credits: credits,
                state: TombstoneState::Retained,
                attempts: 0,
            },
        );
        self.domain_record_mut(ticket.scope, DomainId::VirtIo)?
            .tombstones
            .insert(id);
        self.bump_domain_mutation(ticket.scope, DomainId::VirtIo)?;
        self.invalidate_closure(ticket.scope, DomainId::VirtIo)?;
        self.next_tombstone = next;
        Ok(id)
    }

    /// Issues an exact Closed receipt or an honest retained-timeout receipt.
    pub fn issue_domain_receipt(
        &mut self,
        ticket: RootRevokeTicket,
        domain: DomainId,
    ) -> Result<DomainClosureReceipt, CompositionError> {
        self.validate_ticket(ticket)?;
        self.require_frozen(ticket.scope, domain)?;
        let local = self.domain_record(ticket.scope, domain)?;
        if local.issued_receipt.is_some() {
            return Err(CompositionError::DuplicateClosureReceipt);
        }
        let mut retained = CreditBundle::ZERO;
        let mut tombstones = Vec::with_capacity(local.tombstones.len());
        for id in &local.tombstones {
            let record = self.tombstone_record(*id)?;
            if record.state == TombstoneState::Retrying {
                return Err(CompositionError::DomainNotQuiescent { remaining: 1 });
            }
            if record.state == TombstoneState::Retained {
                retained = retained.checked_add(record.retained_credits)?;
                tombstones.push(*id);
            }
        }
        let status = if !tombstones.is_empty() {
            let all_live_are_retained = local.live_effects.iter().all(|effect| {
                self.effects.get(effect).is_some_and(|record| {
                    record.state == CompositionEffectState::Tombstoned
                        && record
                            .tombstone
                            .is_some_and(|id| local.tombstones.contains(&id))
                })
            });
            if domain != DomainId::VirtIo || !all_live_are_retained {
                return Err(CompositionError::DomainNotQuiescent {
                    remaining: local.live_effects.len(),
                });
            }
            ClosureStatus::TimedOut {
                tombstones,
                retained_credits: retained,
            }
        } else if local.live_effects.is_empty() {
            ClosureStatus::Closed
        } else {
            return Err(CompositionError::DomainNotQuiescent {
                remaining: local.live_effects.len(),
            });
        };
        let sequence = self.next_closure_receipt;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        let receipt = DomainClosureReceipt {
            ticket,
            domain,
            revision: local.closure_revision,
            sequence,
            binding_epoch: local.binding_epoch,
            device_generation: local.device_generation,
            status,
        };
        self.domain_record_mut(ticket.scope, domain)?.issued_receipt = Some(receipt.clone());
        self.next_closure_receipt = next_sequence;
        Ok(receipt)
    }

    /// Accepts one exact domain receipt; duplicates and stale revisions reject.
    pub fn accept_domain_receipt(
        &mut self,
        ticket: RootRevokeTicket,
        receipt: &DomainClosureReceipt,
    ) -> Result<(), CompositionError> {
        self.validate_ticket(ticket)?;
        if receipt.ticket != ticket {
            return Err(CompositionError::StaleClosureReceipt);
        }
        self.require_frozen(ticket.scope, receipt.domain)?;
        let local = self.domain_record(ticket.scope, receipt.domain)?;
        if local.issued_receipt.as_ref() != Some(receipt)
            || receipt.revision != local.closure_revision
            || receipt.binding_epoch != local.binding_epoch
            || receipt.device_generation != local.device_generation
        {
            return Err(CompositionError::StaleClosureReceipt);
        }
        let revocation = self.revocation(ticket.scope)?;
        if let Some(accepted) = revocation.accepted.get(&receipt.domain) {
            return if accepted == receipt {
                Err(CompositionError::DuplicateClosureReceipt)
            } else {
                Err(CompositionError::StaleClosureReceipt)
            };
        }
        self.revocation_mut(ticket.scope)?
            .accepted
            .insert(receipt.domain, receipt.clone());
        Ok(())
    }

    /// Publishes root closure or an honest aggregate timeout result.
    pub fn revoke_complete(
        &mut self,
        ticket: RootRevokeTicket,
    ) -> Result<RevokeOutcome, CompositionError> {
        self.validate_ticket(ticket)?;
        let revocation = self.revocation(ticket.scope)?;
        let mut pending_domains = Vec::new();
        let mut tombstones = Vec::new();
        let mut retained_credits = CreditBundle::ZERO;
        for (domain, receipt) in &revocation.accepted {
            match &receipt.status {
                ClosureStatus::Closed => {}
                ClosureStatus::TimedOut {
                    tombstones: local,
                    retained_credits: retained,
                } => {
                    pending_domains.push(*domain);
                    tombstones.extend(local.iter().copied());
                    retained_credits = retained_credits.checked_add(*retained)?;
                }
            }
        }
        if !pending_domains.is_empty() {
            return Ok(RevokeOutcome::TimedOut {
                pending_domains,
                tombstones,
                retained_credits,
            });
        }
        let missing = revocation
            .frozen_domains
            .iter()
            .filter(|domain| !revocation.accepted.contains_key(domain))
            .copied()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(CompositionError::MissingClosureReceipts(missing));
        }
        let scope = self.scope_record(ticket.scope)?;
        if scope.free_credits != scope.initial_credits {
            return Err(CompositionError::InvariantViolation(
                "closed receipts did not return every credit",
            ));
        }
        self.scope_record_mut(ticket.scope)?.state = ScopeState::Revoked;
        Ok(RevokeOutcome::Revoked)
    }

    /// Begins a retry while retaining ownership and invalidating old receipts.
    pub fn begin_tombstone_retry(
        &mut self,
        ticket: RootRevokeTicket,
        tombstone: TombstoneId,
    ) -> Result<TombstoneRetryToken, CompositionError> {
        self.validate_ticket(ticket)?;
        let record = *self.tombstone_record(tombstone)?;
        if record.scope != ticket.scope || record.state != TombstoneState::Retained {
            return Err(CompositionError::StaleTombstoneRetry);
        }
        let attempt = record
            .attempts
            .checked_add(1)
            .ok_or(CompositionError::CounterOverflow)?;
        let current_device = self
            .domain_record(ticket.scope, record.domain)?
            .device_generation;
        if current_device != record.device_generation {
            return Err(CompositionError::StaleTombstoneRetry);
        }
        let mutable = self
            .tombstones
            .get_mut(&tombstone)
            .expect("validated tombstone");
        mutable.state = TombstoneState::Retrying;
        mutable.attempts = attempt;
        self.invalidate_closure(ticket.scope, record.domain)?;
        Ok(TombstoneRetryToken {
            ticket,
            tombstone,
            attempt,
            device_generation: record.device_generation,
        })
    }

    /// Records a retry timeout without releasing retained ownership.
    pub fn tombstone_retry_timeout(
        &mut self,
        retry: TombstoneRetryToken,
    ) -> Result<(), CompositionError> {
        self.validate_retry(retry)?;
        let domain = self.tombstone_record(retry.tombstone)?.domain;
        self.tombstones
            .get_mut(&retry.tombstone)
            .expect("validated tombstone")
            .state = TombstoneState::Retained;
        self.invalidate_closure(retry.ticket.scope, domain)
    }

    /// Acknowledges quiescence, advances only the device generation, and
    /// reopens the same committed effect for child-first closure.
    pub fn tombstone_retry_ack(
        &mut self,
        retry: TombstoneRetryToken,
    ) -> Result<(), CompositionError> {
        self.validate_retry(retry)?;
        let record = *self.tombstone_record(retry.tombstone)?;
        let new_device = DeviceGeneration::new(
            record
                .device_generation
                .get()
                .checked_add(1)
                .ok_or(CompositionError::CounterOverflow)?,
        );
        let effect = self.effect_record(record.effect)?;
        if effect.state != CompositionEffectState::Tombstoned
            || effect.tombstone != Some(retry.tombstone)
            || effect.held_credits != record.retained_credits
        {
            return Err(CompositionError::StaleTombstoneRetry);
        }
        let mutable = self
            .tombstones
            .get_mut(&retry.tombstone)
            .expect("validated tombstone");
        mutable.state = TombstoneState::Released;
        mutable.retained_credits = CreditBundle::ZERO;
        self.domain_record_mut(record.scope, record.domain)?
            .tombstones
            .remove(&retry.tombstone);
        self.domain_record_mut(record.scope, record.domain)?
            .device_generation = new_device;
        let effect = self.effect_record_mut(record.effect)?;
        effect.state = CompositionEffectState::Committed;
        effect.external_quiesced = true;
        self.invalidate_closure(record.scope, record.domain)
    }
}
