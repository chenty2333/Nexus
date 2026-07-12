use super::*;

impl PagerModel {
    pub(super) fn validate_binding(
        &self,
        binding: PagerBindingToken,
    ) -> Result<&PagerScopeRecord, PagerError> {
        let scope = self
            .scopes
            .get(&binding.scope)
            .ok_or(PagerError::UnknownScope(binding.scope))?;
        if binding.address_space != scope.address_space {
            return Err(PagerError::AddressSpaceMismatch);
        }
        if binding.authority_epoch != scope.authority_epoch {
            return Err(PagerError::StaleAuthority {
                presented: binding.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if binding.binding_epoch != scope.binding_epoch {
            return Err(PagerError::StaleBinding {
                presented: binding.binding_epoch,
                current: scope.binding_epoch,
            });
        }
        match scope.pager {
            Some(pager) if pager == binding.pager => {}
            Some(_) => return Err(PagerError::WrongPager),
            None => return Err(PagerError::PagerUnavailable),
        }
        if scope.state != ScopeState::Active {
            return Err(PagerError::InvalidScopeState { state: scope.state });
        }
        Ok(scope)
    }

    pub(super) fn validate_fault_token(
        &self,
        token: FaultToken,
    ) -> Result<&FaultRecord, PagerError> {
        let fault = self
            .faults
            .get(&token.fault)
            .ok_or(PagerError::UnknownFault(token.fault))?;
        if token.scope != fault.token.scope {
            return Err(PagerError::ScopeMismatch);
        }
        if token.address_space != fault.token.address_space
            || token.thread != fault.token.thread
            || token.page != fault.token.page
            || token.access != fault.token.access
        {
            return Err(PagerError::FaultIdentityMismatch);
        }
        if token.authority_epoch != fault.token.authority_epoch {
            return Err(PagerError::StaleAuthority {
                presented: token.authority_epoch,
                current: fault.token.authority_epoch,
            });
        }
        if token.binding_epoch != fault.token.binding_epoch {
            return Err(PagerError::FaultBindingFenced {
                fault_binding: token.binding_epoch,
                current_binding: fault.token.binding_epoch,
            });
        }
        if token.address_space_generation != fault.token.address_space_generation {
            return Err(PagerError::StaleAddressSpaceGeneration {
                presented: token.address_space_generation,
                current: fault.token.address_space_generation,
            });
        }
        Ok(fault)
    }

    pub(super) fn validate_current_fault_reply(
        &self,
        binding: PagerBindingToken,
        token: FaultToken,
    ) -> Result<(), PagerError> {
        let scope = self.validate_binding(binding)?;
        let fault = self.validate_fault_token(token)?;
        if token.scope != binding.scope {
            return Err(PagerError::ScopeMismatch);
        }
        if token.address_space != binding.address_space {
            return Err(PagerError::AddressSpaceMismatch);
        }
        if fault.token.authority_epoch != scope.authority_epoch {
            return Err(PagerError::StaleAuthority {
                presented: fault.token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if fault.token.binding_epoch != scope.binding_epoch {
            return Err(PagerError::FaultBindingFenced {
                fault_binding: fault.token.binding_epoch,
                current_binding: scope.binding_epoch,
            });
        }
        if fault.token.address_space_generation != scope.address_space_generation {
            return Err(PagerError::StaleAddressSpaceGeneration {
                presented: fault.token.address_space_generation,
                current: scope.address_space_generation,
            });
        }
        Ok(())
    }

    pub(super) fn validate_snapshot(
        &self,
        scope: &PagerScopeRecord,
        snapshot: &RecoverySnapshot,
    ) -> Result<(), PagerError> {
        if snapshot.address_space != scope.address_space {
            return Err(PagerError::AddressSpaceMismatch);
        }
        if snapshot.authority_epoch != scope.authority_epoch {
            return Err(PagerError::StaleAuthority {
                presented: snapshot.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if snapshot.binding_epoch != scope.binding_epoch {
            return Err(PagerError::StaleBinding {
                presented: snapshot.binding_epoch,
                current: scope.binding_epoch,
            });
        }
        if snapshot.address_space_generation != scope.address_space_generation {
            return Err(PagerError::StaleAddressSpaceGeneration {
                presented: snapshot.address_space_generation,
                current: scope.address_space_generation,
            });
        }
        if snapshot.recovery_revision != scope.recovery_revision {
            return Err(PagerError::StaleRecoverySnapshot);
        }
        Ok(())
    }

    pub(super) fn validate_ready(
        &self,
        scope: &PagerScopeRecord,
        ready: PagerReadyToken,
    ) -> Result<(), PagerError> {
        if ready.address_space != scope.address_space {
            return Err(PagerError::AddressSpaceMismatch);
        }
        if ready.authority_epoch != scope.authority_epoch {
            return Err(PagerError::StaleAuthority {
                presented: ready.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if ready.binding_epoch != scope.binding_epoch {
            return Err(PagerError::StaleBinding {
                presented: ready.binding_epoch,
                current: scope.binding_epoch,
            });
        }
        if ready.address_space_generation != scope.address_space_generation {
            return Err(PagerError::StaleAddressSpaceGeneration {
                presented: ready.address_space_generation,
                current: scope.address_space_generation,
            });
        }
        if ready.recovery_revision != scope.recovery_revision {
            return Err(PagerError::StaleRecoverySnapshot);
        }
        let Some(record) = scope.ready else {
            return Err(PagerError::FallbackUnavailable);
        };
        if record.pager != ready.pager
            || record.authority_epoch != ready.authority_epoch
            || record.binding_epoch != ready.binding_epoch
            || record.address_space_generation != ready.address_space_generation
            || record.recovery_revision != ready.recovery_revision
        {
            return Err(PagerError::StaleRecoverySnapshot);
        }
        Ok(())
    }

    pub(super) fn terminalize_uncommitted(
        &mut self,
        fault_id: FaultId,
        action: PagerAction,
    ) -> Result<(), PagerError> {
        let fault = *self
            .faults
            .get(&fault_id)
            .ok_or(PagerError::UnknownFault(fault_id))?;
        if fault.state.is_terminal() {
            return Err(PagerError::AlreadyTerminal);
        }
        if !matches!(fault.state, FaultState::Registered | FaultState::Prepared) {
            return Err(if fault.continuation != ContinuationState::Pending {
                PagerError::ContinuationAlreadyConsumed
            } else {
                PagerError::InvalidFaultState { state: fault.state }
            });
        }
        if fault.continuation != ContinuationState::Pending
            || fault.budget_disposition != BudgetDisposition::Held
        {
            return Err(PagerError::InvariantViolation(
                "uncommitted fault lacks pending continuation or held budget",
            ));
        }
        if let Some(frame) = fault.prepared_frame
            && self.frames.get(&frame).map(|record| record.state)
                != Some(FrameState::Prepared(fault_id))
        {
            return Err(PagerError::FrameOwnershipMismatch(frame));
        }
        let scope = self
            .scopes
            .get(&fault.token.scope)
            .ok_or(PagerError::UnknownScope(fault.token.scope))?;
        let free_after = scope
            .free_budget
            .units()
            .checked_add(fault.budget.units())
            .ok_or(PagerError::CounterOverflow)?;
        let revision_after = Self::next_revision(scope)?;

        let fault_record = self
            .faults
            .get_mut(&fault_id)
            .ok_or(PagerError::UnknownFault(fault_id))?;
        fault_record.state = FaultState::Aborted;
        fault_record.continuation = ContinuationState::Aborted;
        fault_record.budget_disposition = BudgetDisposition::Returned;
        fault_record.prepared_frame = None;
        fault_record.continuation_consumptions = 1;
        fault_record.terminalizations = 1;
        fault_record.wakes = 1;
        if let Some(frame) = fault.prepared_frame {
            self.frames
                .get_mut(&frame)
                .ok_or(PagerError::FrameOwnershipMismatch(frame))?
                .state = FrameState::Released(fault_id);
        }
        let scope = self
            .scopes
            .get_mut(&fault.token.scope)
            .ok_or(PagerError::UnknownScope(fault.token.scope))?;
        scope.free_budget = Budget::new(free_after);
        scope.live_faults.remove(&fault_id);
        if scope.state == ScopeState::Active
            && scope.live_faults.is_empty()
            && !scope.recovery_deadline_completion_pending
        {
            scope.recovery_deadline_armed = false;
        }
        Self::publish_recovery_revision(scope, revision_after);
        self.push_trace(action, fault.token.scope, Some(fault_id));
        Ok(())
    }

    pub(super) fn terminalize_committed(
        &mut self,
        fault_id: FaultId,
        action: PagerAction,
    ) -> Result<(), PagerError> {
        let fault = *self
            .faults
            .get(&fault_id)
            .ok_or(PagerError::UnknownFault(fault_id))?;
        if fault.state.is_terminal() {
            return Err(PagerError::AlreadyTerminal);
        }
        if fault.state != FaultState::Committed {
            return Err(PagerError::InvalidFaultState { state: fault.state });
        }
        if fault.continuation != ContinuationState::Resolved
            || fault.continuation_consumptions != 1
            || fault.mapping_publications != 1
            || fault.mapped_frame.is_none()
            || fault.resolved_mapping.is_none()
        {
            return Err(PagerError::InvariantViolation(
                "committed fault lacks resolved mapping state",
            ));
        }
        let key = fault
            .resolved_mapping
            .ok_or(PagerError::InvariantViolation(
                "committed fault lacks mapping identity",
            ))?;
        let frame = fault.mapped_frame.ok_or(PagerError::InvariantViolation(
            "committed fault lacks mapped frame",
        ))?;
        if self.current_mappings.get(&key)
            != Some(&MappingRecord {
                frame,
                fault: fault_id,
            })
        {
            return Err(PagerError::InvariantViolation(
                "committed fault mapping is not current",
            ));
        }
        let scope = self
            .scopes
            .get(&fault.token.scope)
            .ok_or(PagerError::UnknownScope(fault.token.scope))?;
        let revision_after = Self::next_revision(scope)?;
        let fault_record = self
            .faults
            .get_mut(&fault_id)
            .ok_or(PagerError::UnknownFault(fault_id))?;
        fault_record.state = FaultState::Completed;
        fault_record.terminalizations = 1;
        fault_record.wakes = 1;
        fault_record.resumes = 1;
        let scope = self
            .scopes
            .get_mut(&fault.token.scope)
            .ok_or(PagerError::UnknownScope(fault.token.scope))?;
        scope.live_faults.remove(&fault_id);
        if scope.state == ScopeState::Active
            && scope.live_faults.is_empty()
            && !scope.recovery_deadline_completion_pending
        {
            scope.recovery_deadline_armed = false;
        }
        Self::publish_recovery_revision(scope, revision_after);
        self.push_trace(action, fault.token.scope, Some(fault_id));
        Ok(())
    }

    pub(super) fn next_revision(scope: &PagerScopeRecord) -> Result<u64, PagerError> {
        scope
            .recovery_revision
            .checked_add(1)
            .ok_or(PagerError::CounterOverflow)
    }

    pub(super) fn publish_recovery_revision(scope: &mut PagerScopeRecord, revision: u64) {
        scope.recovery_revision = revision;
        if scope.fallback == PagerFallbackState::ReplacementReady {
            scope.fallback = PagerFallbackState::Running;
            scope.ready = None;
        }
    }

    pub(super) fn push_trace(
        &mut self,
        action: PagerAction,
        scope: ScopeId,
        fault: Option<FaultId>,
    ) {
        let record = self
            .scopes
            .get(&scope)
            .expect("trace requires an existing pager scope");
        self.trace.push(PagerTraceEvent {
            seq: self.trace.len(),
            action,
            scope,
            fault,
            authority_epoch: record.authority_epoch,
            binding_epoch: record.binding_epoch,
            address_space_generation: record.address_space_generation,
        });
    }
}
