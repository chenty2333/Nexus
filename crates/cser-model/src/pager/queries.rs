use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::*;

impl PagerModel {
    /// Returns a read-only projection of a pager scope.
    #[must_use]
    pub fn scope(&self, scope: ScopeId) -> Option<PagerScopeView> {
        self.scopes.get(&scope).map(|record| PagerScopeView {
            state: record.state,
            authority_epoch: record.authority_epoch,
            binding_epoch: record.binding_epoch,
            address_space: record.address_space,
            address_space_generation: record.address_space_generation,
            pager: record.pager,
            fallback: record.fallback,
            initial_budget: record.initial_budget,
            free_budget: record.free_budget,
            spent_budget: record.spent_budget,
            live_faults: record.live_faults.len(),
            recovery_deadline_armed: record.recovery_deadline_armed,
            recovery_deadline_completion_pending: record.recovery_deadline_completion_pending,
            revocation: record.revocation.map(|revocation| PagerRevocationProgress {
                closed_epoch: revocation.closed_epoch,
                target_count: revocation.target_count,
                steps: revocation.steps,
                remaining: record.live_faults.len(),
            }),
        })
    }

    /// Returns a read-only projection of one fault.
    #[must_use]
    pub fn fault(&self, fault: FaultId) -> Option<FaultView> {
        self.faults.get(&fault).map(|record| FaultView {
            token: record.token,
            state: record.state,
            continuation: record.continuation,
            budget: record.budget,
            budget_disposition: record.budget_disposition,
            prepared_frame: record.prepared_frame,
            mapped_frame: record.mapped_frame,
            resolved_mapping: record.resolved_mapping,
            mapping_publications: record.mapping_publications,
            continuation_consumptions: record.continuation_consumptions,
            terminalizations: record.terminalizations,
            wakes: record.wakes,
            resumes: record.resumes,
        })
    }

    /// Returns a read-only projection of one frame identity.
    #[must_use]
    pub fn frame(&self, frame: FrameId) -> Option<FrameView> {
        self.frames.get(&frame).map(|record| FrameView {
            state: record.state,
        })
    }

    /// Returns one mapping currently installed in the PTE abstraction.
    #[must_use]
    pub fn mapping(&self, key: MappingKey) -> Option<MappingView> {
        self.current_mappings.get(&key).map(|record| MappingView {
            frame: record.frame,
            fault: record.fault,
        })
    }

    /// Returns the number of mappings currently installed.
    #[must_use]
    pub fn mapping_count(&self) -> usize {
        self.current_mappings.len()
    }

    /// Returns immutable evidence of one historical mapping publication.
    #[must_use]
    pub fn publication(&self, key: MappingKey) -> Option<MappingView> {
        self.publication_history
            .get(&key)
            .map(|record| MappingView {
                frame: record.frame,
                fault: record.fault,
            })
    }

    /// Returns the number of unique historical mapping publications.
    #[must_use]
    pub fn publication_count(&self) -> usize {
        self.publication_history.len()
    }

    /// Returns the deterministic contents of one scope's live reverse index.
    pub fn live_faults(&self, scope: ScopeId) -> Result<Vec<FaultId>, PagerError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        Ok(record.live_faults.iter().copied().collect())
    }

    /// Returns successful operations in total linearization order.
    #[must_use]
    pub fn trace(&self) -> &[PagerTraceEvent] {
        &self.trace
    }

    /// Audits fencing, one-shot continuation, frame, mapping, budget, and work invariants.
    pub fn check_invariants(&self) -> Result<(), PagerInvariantViolation> {
        for (scope_id, scope) in &self.scopes {
            let mut expected_live = BTreeSet::new();
            let mut held = 0u128;
            let mut spent = 0u128;

            for (fault_id, fault) in self
                .faults
                .iter()
                .filter(|(_, fault)| fault.token.scope == *scope_id)
            {
                if fault.token.address_space != scope.address_space {
                    return Err(PagerInvariantViolation::OrphanFault(*fault_id));
                }
                if fault.token.authority_epoch > scope.authority_epoch
                    || fault.token.binding_epoch > scope.binding_epoch
                    || fault.token.address_space_generation > scope.address_space_generation
                {
                    return Err(PagerInvariantViolation::FutureGeneration(*fault_id));
                }
                if !fault.state.is_terminal() {
                    expected_live.insert(*fault_id);
                }
                let expected_disposition = match fault.state {
                    FaultState::Registered | FaultState::Prepared => BudgetDisposition::Held,
                    FaultState::Committed => BudgetDisposition::Spent,
                    FaultState::Completed if fault.mapped_frame.is_some() => {
                        BudgetDisposition::Spent
                    }
                    FaultState::Completed => BudgetDisposition::Returned,
                    FaultState::Aborted => BudgetDisposition::Returned,
                };
                if fault.budget_disposition != expected_disposition {
                    return Err(PagerInvariantViolation::FaultBudgetState(*fault_id));
                }
                match fault.budget_disposition {
                    BudgetDisposition::Held => held += u128::from(fault.budget.units()),
                    BudgetDisposition::Spent => spent += u128::from(fault.budget.units()),
                    BudgetDisposition::Returned => {}
                }
                self.check_fault_invariants(*fault_id, fault)?;
            }

            if expected_live != scope.live_faults {
                return Err(PagerInvariantViolation::LiveReverseIndex(*scope_id));
            }
            if u128::from(scope.spent_budget.units()) != spent {
                return Err(PagerInvariantViolation::SpentAccounting(*scope_id));
            }
            let accounted = u128::from(scope.free_budget.units()) + held + spent;
            if accounted != u128::from(scope.initial_budget.units()) {
                return Err(PagerInvariantViolation::BudgetConservation(*scope_id));
            }
            match scope.state {
                ScopeState::Active if scope.revocation.is_some() => {
                    return Err(PagerInvariantViolation::RevocationMetadata(*scope_id));
                }
                ScopeState::Closing | ScopeState::Revoked if scope.revocation.is_none() => {
                    return Err(PagerInvariantViolation::RevocationMetadata(*scope_id));
                }
                _ => {}
            }
            if scope.state == ScopeState::Revoked && !scope.live_faults.is_empty() {
                return Err(PagerInvariantViolation::RevokedScopeLive(*scope_id));
            }
            if let Some(revocation) = scope.revocation
                && revocation.steps > revocation.target_count
            {
                return Err(PagerInvariantViolation::RevocationWorkBound(*scope_id));
            }
            let fallback_valid = match (scope.pager, scope.fallback, scope.ready) {
                (Some(_), PagerFallbackState::Standby, None) => true,
                (None, PagerFallbackState::Required | PagerFallbackState::Running, None) => true,
                (None, PagerFallbackState::ReplacementReady, Some(ready)) => {
                    ready.authority_epoch == scope.authority_epoch
                        && ready.binding_epoch == scope.binding_epoch
                        && ready.address_space_generation == scope.address_space_generation
                        && ready.recovery_revision == scope.recovery_revision
                }
                _ => false,
            };
            if !fallback_valid {
                return Err(PagerInvariantViolation::FallbackState(*scope_id));
            }
            let deadline_valid = match scope.state {
                ScopeState::Active => match (
                    scope.live_faults.is_empty(),
                    scope.recovery_deadline_armed,
                    scope.recovery_deadline_completion_pending,
                ) {
                    (true, false, false) | (true, true, true) => true,
                    (false, true, false) => true,
                    (false, true, true) => scope.live_faults.iter().all(|fault_id| {
                        self.faults
                            .get(fault_id)
                            .is_some_and(|fault| fault.state == FaultState::Committed)
                    }),
                    _ => false,
                },
                ScopeState::Closing | ScopeState::Revoked => {
                    !scope.recovery_deadline_armed && !scope.recovery_deadline_completion_pending
                }
            };
            if !deadline_valid {
                return Err(PagerInvariantViolation::RecoveryDeadlineState(*scope_id));
            }
            if self.address_spaces.get(&scope.address_space) != Some(scope_id) {
                return Err(PagerInvariantViolation::AddressSpaceIndex(
                    scope.address_space,
                ));
            }
        }

        for (address_space, scope_id) in &self.address_spaces {
            let Some(scope) = self.scopes.get(scope_id) else {
                return Err(PagerInvariantViolation::AddressSpaceIndex(*address_space));
            };
            if scope.address_space != *address_space {
                return Err(PagerInvariantViolation::AddressSpaceIndex(*address_space));
            }
        }
        for (fault_id, fault) in &self.faults {
            if !self.scopes.contains_key(&fault.token.scope) {
                return Err(PagerInvariantViolation::OrphanFault(*fault_id));
            }
        }
        for (frame_id, frame) in &self.frames {
            match frame.state {
                FrameState::Prepared(fault_id) => {
                    let Some(fault) = self.faults.get(&fault_id) else {
                        return Err(PagerInvariantViolation::OrphanFrame(*frame_id));
                    };
                    if fault.state != FaultState::Prepared
                        || fault.prepared_frame != Some(*frame_id)
                    {
                        return Err(PagerInvariantViolation::OrphanFrame(*frame_id));
                    }
                }
                FrameState::Mapped { key, fault } => {
                    let Some(mapping) = self.current_mappings.get(&key) else {
                        return Err(PagerInvariantViolation::OrphanFrame(*frame_id));
                    };
                    if mapping.frame != *frame_id || mapping.fault != fault {
                        return Err(PagerInvariantViolation::OrphanFrame(*frame_id));
                    }
                }
                FrameState::Released(fault_id) => {
                    let Some(fault) = self.faults.get(&fault_id) else {
                        return Err(PagerInvariantViolation::OrphanFrame(*frame_id));
                    };
                    if !fault.state.is_terminal()
                        || fault.prepared_frame.is_some()
                        || fault.mapped_frame.is_some()
                        || fault.budget_disposition != BudgetDisposition::Returned
                    {
                        return Err(PagerInvariantViolation::OrphanFrame(*frame_id));
                    }
                }
            }
        }
        for (key, mapping) in &self.current_mappings {
            let Some(fault) = self.faults.get(&mapping.fault) else {
                return Err(PagerInvariantViolation::MappingOwnership(*key));
            };
            let current_generation_matches = self
                .address_spaces
                .get(&key.address_space)
                .and_then(|scope| self.scopes.get(scope))
                .is_some_and(|scope| scope.address_space_generation == key.generation);
            if !matches!(fault.state, FaultState::Committed | FaultState::Completed)
                || !current_generation_matches
                || fault.mapped_frame != Some(mapping.frame)
                || fault.resolved_mapping != Some(*key)
                || fault.mapping_publications != 1
                || fault.budget_disposition != BudgetDisposition::Spent
                || fault.token.address_space != key.address_space
                || fault.token.address_space_generation != key.generation
                || fault.token.page != key.page
                || self.publication_history.get(key) != Some(mapping)
            {
                return Err(PagerInvariantViolation::MappingOwnership(*key));
            }
        }
        for (key, publication) in &self.publication_history {
            let Some(fault) = self.faults.get(&publication.fault) else {
                return Err(PagerInvariantViolation::MappingOwnership(*key));
            };
            let identity_matches = fault.mapping_publications == 1
                && fault.resolved_mapping == Some(*key)
                && fault.token.address_space == key.address_space
                && fault.token.address_space_generation == key.generation
                && fault.token.page == key.page;
            let ownership_matches = match self.current_mappings.get(key) {
                Some(current) => {
                    current == publication
                        && fault.mapped_frame == Some(publication.frame)
                        && fault.budget_disposition == BudgetDisposition::Spent
                        && self.frames.get(&publication.frame).map(|frame| frame.state)
                            == Some(FrameState::Mapped {
                                key: *key,
                                fault: publication.fault,
                            })
                }
                None => {
                    let generation_is_historical = self
                        .address_spaces
                        .get(&key.address_space)
                        .and_then(|scope| self.scopes.get(scope))
                        .is_some_and(|scope| scope.address_space_generation > key.generation);
                    fault.state == FaultState::Completed
                        && generation_is_historical
                        && fault.mapped_frame.is_none()
                        && fault.budget_disposition == BudgetDisposition::Returned
                        && self.frames.get(&publication.frame).map(|frame| frame.state)
                            == Some(FrameState::Released(publication.fault))
                }
            };
            if !identity_matches || !ownership_matches {
                return Err(PagerInvariantViolation::MappingOwnership(*key));
            }
        }
        Ok(())
    }

    fn check_fault_invariants(
        &self,
        fault_id: FaultId,
        fault: &FaultRecord,
    ) -> Result<(), PagerInvariantViolation> {
        let terminal = u8::from(fault.state.is_terminal());
        if fault.terminalizations != terminal {
            return Err(PagerInvariantViolation::Terminalization(fault_id));
        }
        let expected_continuation = match fault.state {
            FaultState::Registered | FaultState::Prepared => (ContinuationState::Pending, 0),
            FaultState::Committed | FaultState::Completed => (ContinuationState::Resolved, 1),
            FaultState::Aborted => (ContinuationState::Aborted, 1),
        };
        if (fault.continuation, fault.continuation_consumptions) != expected_continuation {
            return Err(PagerInvariantViolation::ContinuationConsumption(fault_id));
        }
        let expected_wake_resume = match fault.state {
            FaultState::Registered | FaultState::Prepared | FaultState::Committed => (0, 0),
            FaultState::Completed => (1, 1),
            FaultState::Aborted => (1, 0),
        };
        if (fault.wakes, fault.resumes) != expected_wake_resume {
            return Err(PagerInvariantViolation::WakeResume(fault_id));
        }
        let shape_valid = match fault.state {
            FaultState::Registered => {
                fault.mapping_publications == 0
                    && fault.resolved_mapping.is_none()
                    && fault.prepared_frame.is_none()
                    && fault.mapped_frame.is_none()
            }
            FaultState::Prepared => {
                fault.mapping_publications == 0
                    && fault.resolved_mapping.is_none()
                    && fault.prepared_frame.is_some()
                    && fault.mapped_frame.is_none()
            }
            FaultState::Committed => {
                fault.mapping_publications == 1
                    && fault.resolved_mapping.is_some()
                    && fault.prepared_frame.is_none()
                    && fault.mapped_frame.is_some()
            }
            FaultState::Completed => {
                fault.mapping_publications <= 1
                    && fault.resolved_mapping.is_some()
                    && fault.prepared_frame.is_none()
                    && (fault.mapping_publications == 1 || fault.mapped_frame.is_none())
            }
            FaultState::Aborted => {
                fault.mapping_publications == 0
                    && fault.resolved_mapping.is_none()
                    && fault.prepared_frame.is_none()
                    && fault.mapped_frame.is_none()
            }
        };
        if !shape_valid {
            return Err(PagerInvariantViolation::MappingPublication(fault_id));
        }
        if let Some(frame) = fault.prepared_frame
            && self.frames.get(&frame).map(|record| record.state)
                != Some(FrameState::Prepared(fault_id))
        {
            return Err(PagerInvariantViolation::FrameOwnership(fault_id));
        }
        if let Some(key) = fault.resolved_mapping
            && (key.address_space != fault.token.address_space
                || key.generation != fault.token.address_space_generation
                || key.page != fault.token.page
                || !self.publication_history.contains_key(&key))
        {
            return Err(PagerInvariantViolation::MappingPublication(fault_id));
        }
        if let Some(frame) = fault.mapped_frame {
            let Some(key) = fault.resolved_mapping else {
                return Err(PagerInvariantViolation::FrameOwnership(fault_id));
            };
            if self.current_mappings.get(&key)
                != Some(&MappingRecord {
                    frame,
                    fault: fault_id,
                })
                || self.frames.get(&frame).map(|record| record.state)
                    != Some(FrameState::Mapped {
                        key,
                        fault: fault_id,
                    })
            {
                return Err(PagerInvariantViolation::FrameOwnership(fault_id));
            }
        }
        Ok(())
    }
}
