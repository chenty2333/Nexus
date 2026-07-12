use alloc::collections::BTreeSet;

use super::*;

impl IoModel {
    /// Returns a read-only scope projection.
    #[must_use]
    pub fn scope(&self, scope: ScopeId) -> Option<IoScopeView> {
        let record = self.scopes.get(&scope)?;
        Some(IoScopeView {
            state: record.state,
            authority_epoch: record.authority_epoch,
            binding_epoch: record.binding_epoch,
            device_generation: record.device_generation,
            device: record.device,
            queue: record.queue,
            service: record.service,
            fallback: record.fallback,
            initial_budget: record.initial_budget,
            free_lease_credits: record.free_lease_credits,
            free_commit_charges: record.free_commit_charges,
            held_commit_charges: record.held_commit_charges,
            spent_commit_charges: record.spent_commit_charges,
            avail_idx: record.avail_idx,
            historical_requests: record.requests.len(),
            live_obligations: record.live_obligations.len(),
            unpublished_obligations: record.unpublished_obligations.len(),
            nonterminal_requests: record.nonterminal_requests,
            queue_slot_obligations: record.queue_slot_obligations.len(),
            device_quiesced: record.device_quiesced,
            reset: record.reset.view(),
            invalidation: record.queue_lease.invalidation.view(),
            revocation: record.revocation.map(|revocation| IoRevocationProgress {
                closed_epoch: revocation.closed_epoch,
                target_count: revocation.target_count,
                cancel_steps: revocation.cancel_steps,
                cancel_index_visits: revocation.cancel_index_visits,
                reset_index_visits: revocation.reset_index_visits,
                reset_terminalizations: revocation.reset_terminalizations,
                invalidated_request_leases: revocation.invalidated_request_leases,
            }),
        })
    }

    /// Returns a read-only request projection.
    #[must_use]
    pub fn request(&self, request: RequestId) -> Option<IoRequestView> {
        self.requests.get(&request).map(|request| IoRequestView {
            token: request.token,
            state: request.state,
            grant: request.grant,
            commit_disposition: request.commit_disposition,
            dma: request.dma,
            dma_state: request.dma_state,
            invalidation: request.invalidation.view(),
            avail_publications: request.avail_publications,
            notified: request.notified,
            queue_slot_owned: request.queue_slot_owned,
            terminalizations: request.terminalizations,
        })
    }

    /// Returns the scope-owned queue lease projection.
    #[must_use]
    pub fn queue_lease(&self, scope: ScopeId) -> Option<QueueLeaseView> {
        self.scopes.get(&scope).map(|record| QueueLeaseView {
            queue: record.queue_lease.queue,
            dma: record.queue_lease.dma,
            dma_state: record.queue_lease.state,
            invalidation: record.queue_lease.invalidation.view(),
            credits: record.queue_lease.credits,
        })
    }

    /// Returns whether any live scope still retains a component of this identity.
    #[must_use]
    pub fn dma_identity_retained(&self, dma: DmaIdentity) -> bool {
        self.active_dma_leases.contains(&dma.lease)
            || self.active_mappings.contains(&dma.mapping)
            || self.active_iovas.contains(&dma.iova)
    }

    /// Returns the number of scopes in the model.
    #[must_use]
    pub fn scope_count(&self) -> usize {
        self.scopes.len()
    }

    /// Returns the number of requests across every scope.
    #[must_use]
    pub fn global_request_count(&self) -> usize {
        self.requests.len()
    }

    /// Returns the immutable successful-operation trace.
    #[must_use]
    pub fn trace(&self) -> &[IoTraceEvent] {
        &self.trace
    }

    /// Audits typed budgets, generation fences, ownership, and closure state.
    pub fn check_invariants(&self) -> Result<(), IoInvariantViolation> {
        let mut expected_issued_dma_leases = BTreeSet::new();
        let mut expected_issued_mappings = BTreeSet::new();
        let mut expected_active_dma_leases = BTreeSet::new();
        let mut expected_active_mappings = BTreeSet::new();
        let mut expected_active_iovas = BTreeSet::new();
        for (scope_id, scope) in &self.scopes {
            let mut retained_lease = if scope.queue_lease.state == DmaLeaseState::Released {
                LeaseCredits::ZERO
            } else {
                scope.queue_lease.credits
            };
            let mut held_commit = 0u64;
            let mut derived_live = BTreeSet::new();
            let mut derived_unpublished = BTreeSet::new();
            let mut derived_queue_slots = BTreeSet::new();
            let mut derived_nonterminal = 0usize;
            if !expected_issued_dma_leases.insert(scope.queue_lease.dma.lease)
                || !expected_issued_mappings.insert(scope.queue_lease.dma.mapping)
            {
                return Err(IoInvariantViolation::DmaIdentityIndex(
                    scope.queue_lease.dma,
                ));
            }
            if scope.queue_lease.state != DmaLeaseState::Released
                && (!expected_active_dma_leases.insert(scope.queue_lease.dma.lease)
                    || !expected_active_mappings.insert(scope.queue_lease.dma.mapping)
                    || !expected_active_iovas.insert(scope.queue_lease.dma.iova))
            {
                return Err(IoInvariantViolation::DmaIdentityIndex(
                    scope.queue_lease.dma,
                ));
            }
            for request_id in &scope.requests {
                let request = self
                    .requests
                    .get(request_id)
                    .ok_or(IoInvariantViolation::OrphanRequest(*request_id))?;
                if request.token.scope != *scope_id
                    || request.token.device != scope.device
                    || request.token.queue != scope.queue
                {
                    return Err(IoInvariantViolation::OrphanRequest(*request_id));
                }
                if request.token.authority_epoch.get() > scope.authority_epoch.get()
                    || request.token.binding_epoch.get() > scope.binding_epoch.get()
                    || request.token.device_generation.get() > scope.device_generation.get()
                {
                    return Err(IoInvariantViolation::FutureGeneration(*request_id));
                }
                if !expected_issued_dma_leases.insert(request.dma.lease)
                    || !expected_issued_mappings.insert(request.dma.mapping)
                {
                    return Err(IoInvariantViolation::DmaIdentityIndex(request.dma));
                }
                if request.dma_state != DmaLeaseState::Released {
                    retained_lease = retained_lease
                        .checked_add(request.grant.lease)
                        .ok_or(IoInvariantViolation::LeaseBudgetConservation(*scope_id))?;
                    if !self.dma_identity_indexed(request.dma) {
                        return Err(IoInvariantViolation::DmaIdentityIndex(request.dma));
                    }
                    if !expected_active_dma_leases.insert(request.dma.lease)
                        || !expected_active_mappings.insert(request.dma.mapping)
                        || !expected_active_iovas.insert(request.dma.iova)
                    {
                        return Err(IoInvariantViolation::DmaIdentityIndex(request.dma));
                    }
                } else if self.active_dma_leases.contains(&request.dma.lease)
                    || self.active_mappings.contains(&request.dma.mapping)
                {
                    return Err(IoInvariantViolation::DmaIdentityIndex(request.dma));
                }
                match (request.state, request.commit_disposition) {
                    (
                        IoEffectState::Registered | IoEffectState::Prepared,
                        CommitDisposition::Held,
                    ) => {
                        held_commit = held_commit
                            .checked_add(request.grant.commit_charge.get())
                            .ok_or(IoInvariantViolation::CommitBudgetConservation(*scope_id))?;
                    }
                    (
                        IoEffectState::Committed
                        | IoEffectState::Completed
                        | IoEffectState::IndeterminateAfterReset,
                        CommitDisposition::Spent,
                    )
                    | (
                        IoEffectState::Cancelling | IoEffectState::Cancelled,
                        CommitDisposition::Returned,
                    ) => {}
                    _ => return Err(IoInvariantViolation::RequestChargeState(*request_id)),
                }
                let published = matches!(
                    request.state,
                    IoEffectState::Committed
                        | IoEffectState::Completed
                        | IoEffectState::IndeterminateAfterReset
                );
                if request.avail_publications != u8::from(published)
                    || (request.notified && !published)
                {
                    return Err(IoInvariantViolation::PublicationState(*request_id));
                }
                if request.terminalizations != u8::from(request.state.is_terminal()) {
                    return Err(IoInvariantViolation::Terminalization(*request_id));
                }
                if !request.state.is_terminal() {
                    derived_nonterminal = derived_nonterminal
                        .checked_add(1)
                        .ok_or(IoInvariantViolation::NonterminalCount(*scope_id))?;
                }
                if matches!(
                    request.state,
                    IoEffectState::Registered | IoEffectState::Prepared
                ) {
                    derived_unpublished.insert(*request_id);
                }
                let should_own_queue_slot = matches!(
                    request.state,
                    IoEffectState::Prepared | IoEffectState::Committed
                );
                if request.queue_slot_owned != should_own_queue_slot {
                    return Err(IoInvariantViolation::QueueSlotIndex(*scope_id));
                }
                if request.queue_slot_owned {
                    derived_queue_slots.insert(*request_id);
                }
                if request.dma_state != DmaLeaseState::Released {
                    derived_live.insert(*request_id);
                }
            }
            let lease_sum = scope
                .free_lease_credits
                .checked_add(retained_lease)
                .ok_or(IoInvariantViolation::LeaseBudgetConservation(*scope_id))?;
            if lease_sum != scope.initial_budget.leases {
                return Err(IoInvariantViolation::LeaseBudgetConservation(*scope_id));
            }
            let charge_sum = scope
                .free_commit_charges
                .get()
                .checked_add(held_commit)
                .and_then(|value| value.checked_add(scope.spent_commit_charges.get()))
                .ok_or(IoInvariantViolation::CommitBudgetConservation(*scope_id))?;
            if charge_sum != scope.initial_budget.commit_charges.get() {
                return Err(IoInvariantViolation::CommitBudgetConservation(*scope_id));
            }
            if scope.held_commit_charges != CommitCharges::new(held_commit) {
                return Err(IoInvariantViolation::CommitBudgetConservation(*scope_id));
            }
            if derived_live != scope.live_obligations {
                return Err(IoInvariantViolation::LiveReverseIndex(*scope_id));
            }
            if derived_unpublished != scope.unpublished_obligations {
                return Err(IoInvariantViolation::UnpublishedReverseIndex(*scope_id));
            }
            if derived_nonterminal != scope.nonterminal_requests {
                return Err(IoInvariantViolation::NonterminalCount(*scope_id));
            }
            if derived_queue_slots != scope.queue_slot_obligations {
                return Err(IoInvariantViolation::QueueSlotIndex(*scope_id));
            }
            if scope.queue_lease.state != DmaLeaseState::Released {
                if !self.dma_identity_indexed(scope.queue_lease.dma) {
                    return Err(IoInvariantViolation::DmaIdentityIndex(
                        scope.queue_lease.dma,
                    ));
                }
            } else if self
                .active_dma_leases
                .contains(&scope.queue_lease.dma.lease)
                || self
                    .active_mappings
                    .contains(&scope.queue_lease.dma.mapping)
            {
                return Err(IoInvariantViolation::DmaIdentityIndex(
                    scope.queue_lease.dma,
                ));
            }
            if !Self::dma_invalidation_pair_valid(
                scope.queue_lease.state,
                scope.queue_lease.invalidation,
                false,
            ) || scope.requests.iter().any(|request| {
                self.requests.get(request).is_none_or(|request| {
                    !Self::dma_invalidation_pair_valid(
                        request.dma_state,
                        request.invalidation,
                        true,
                    ) || !Self::request_dma_state_valid(request)
                })
            }) {
                return Err(IoInvariantViolation::DmaLeaseSafety(*scope_id));
            }
            match scope.reset {
                ResetRecord::Idle if scope.state != ScopeState::Active => {
                    return Err(IoInvariantViolation::ResetState(*scope_id));
                }
                ResetRecord::Required if scope.state != ScopeState::Closing => {
                    return Err(IoInvariantViolation::ResetState(*scope_id));
                }
                ResetRecord::InFlight { .. } | ResetRecord::TimedOut { .. }
                    if scope.state != ScopeState::Closing =>
                {
                    return Err(IoInvariantViolation::ResetState(*scope_id));
                }
                ResetRecord::Acknowledged
                    if !scope.device_quiesced
                        || scope.live_obligations.iter().any(|request| {
                            self.requests
                                .get(request)
                                .is_some_and(|request| request.state == IoEffectState::Committed)
                        }) =>
                {
                    return Err(IoInvariantViolation::ResetState(*scope_id));
                }
                ResetRecord::Acknowledged => {}
                _ if scope.device_quiesced => {
                    return Err(IoInvariantViolation::ResetState(*scope_id));
                }
                _ => {}
            }
            match scope.state {
                ScopeState::Active if scope.revocation.is_some() => {
                    return Err(IoInvariantViolation::RevocationState(*scope_id));
                }
                ScopeState::Closing | ScopeState::Revoked if scope.revocation.is_none() => {
                    return Err(IoInvariantViolation::RevocationState(*scope_id));
                }
                _ => {}
            }
            if let Some(revocation) = scope.revocation
                && (revocation.cancel_steps != revocation.cancel_index_visits
                    || revocation.cancel_steps > revocation.target_count
                    || revocation.reset_index_visits > revocation.target_count
                    || revocation.reset_terminalizations > revocation.reset_index_visits
                    || revocation.invalidated_request_leases > revocation.target_count
                    || scope.live_obligations.len() > revocation.target_count)
            {
                return Err(IoInvariantViolation::RevocationState(*scope_id));
            }
            if scope.state == ScopeState::Revoked
                && (!scope.device_quiesced
                    || scope.reset != ResetRecord::Acknowledged
                    || scope.queue_lease.invalidation != InvalidationRecord::Acknowledged
                    || !scope.live_obligations.is_empty()
                    || !scope.unpublished_obligations.is_empty()
                    || scope.nonterminal_requests != 0
                    || !scope.queue_slot_obligations.is_empty()
                    || retained_lease != LeaseCredits::ZERO
                    || held_commit != 0
                    || scope.held_commit_charges != CommitCharges::ZERO
                    || self.device_owners.get(&scope.device) == Some(scope_id)
                    || self.queue_owners.get(&scope.queue) == Some(scope_id))
            {
                return Err(IoInvariantViolation::RevokedScope(*scope_id));
            }
            if scope.state != ScopeState::Revoked
                && (self.device_owners.get(&scope.device) != Some(scope_id)
                    || self.queue_owners.get(&scope.queue) != Some(scope_id))
            {
                return Err(IoInvariantViolation::ExclusiveOwner(*scope_id));
            }
            let fallback_ok = match scope.fallback {
                IoFallbackState::Standby => {
                    scope.service.is_some() || scope.state != ScopeState::Active
                }
                IoFallbackState::Required | IoFallbackState::Running => scope.service.is_none(),
                IoFallbackState::ReplacementReady => {
                    scope.service.is_none() && scope.ready.is_some()
                }
            };
            if !fallback_ok {
                return Err(IoInvariantViolation::FallbackState(*scope_id));
            }
        }
        if expected_issued_dma_leases != self.issued_dma_leases
            || expected_issued_mappings != self.issued_mappings
            || expected_active_dma_leases != self.active_dma_leases
            || expected_active_mappings != self.active_mappings
            || expected_active_iovas != self.active_iovas
        {
            return Err(IoInvariantViolation::DmaOwnershipIndex);
        }
        for (request_id, request) in &self.requests {
            let scope = self
                .scopes
                .get(&request.token.scope)
                .ok_or(IoInvariantViolation::OrphanRequest(*request_id))?;
            if !scope.requests.contains(request_id) {
                return Err(IoInvariantViolation::OrphanRequest(*request_id));
            }
        }
        Ok(())
    }
}
