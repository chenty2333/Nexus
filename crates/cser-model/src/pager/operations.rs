use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::*;

impl Default for PagerModel {
    fn default() -> Self {
        Self::new()
    }
}

impl PagerModel {
    /// Creates an empty pager protocol model.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_scope: 1,
            next_address_space: 1,
            next_fault: 1,
            scopes: BTreeMap::new(),
            address_spaces: BTreeMap::new(),
            faults: BTreeMap::new(),
            frames: BTreeMap::new(),
            current_mappings: BTreeMap::new(),
            publication_history: BTreeMap::new(),
            trace: Vec::new(),
        }
    }

    /// Creates one active scope, address space, and initial pager binding.
    pub fn create_address_space(
        &mut self,
        pager: PagerId,
        budget: Budget,
    ) -> Result<(ScopeId, AddressSpaceId, PagerBindingToken), PagerError> {
        let scope = ScopeId::new(self.next_scope);
        let address_space = AddressSpaceId::new(self.next_address_space);
        let next_scope = self
            .next_scope
            .checked_add(1)
            .ok_or(PagerError::CounterOverflow)?;
        let next_address_space = self
            .next_address_space
            .checked_add(1)
            .ok_or(PagerError::CounterOverflow)?;
        let authority_epoch = AuthorityEpoch::new(1);
        let binding_epoch = BindingEpoch::new(1);
        let address_space_generation = AddressSpaceGeneration::new(1);
        self.next_scope = next_scope;
        self.next_address_space = next_address_space;
        self.scopes.insert(
            scope,
            PagerScopeRecord {
                state: ScopeState::Active,
                authority_epoch,
                binding_epoch,
                address_space,
                address_space_generation,
                pager: Some(pager),
                fallback: PagerFallbackState::Standby,
                ready: None,
                initial_budget: budget,
                free_budget: budget,
                spent_budget: Budget::ZERO,
                live_faults: BTreeSet::new(),
                revocation: None,
                recovery_revision: 0,
                recovery_deadline_armed: false,
                recovery_deadline_completion_pending: false,
            },
        );
        self.address_spaces.insert(address_space, scope);
        self.push_trace(PagerAction::CreateAddressSpace, scope, None);
        Ok((
            scope,
            address_space,
            PagerBindingToken {
                scope,
                address_space,
                pager,
                authority_epoch,
                binding_epoch,
            },
        ))
    }

    /// Registers one fault and atomically moves its credit from free to held.
    pub fn register_fault(
        &mut self,
        binding: PagerBindingToken,
        thread: ThreadId,
        page: PageAddress,
        access: FaultAccess,
        budget: Budget,
    ) -> Result<FaultToken, PagerError> {
        if budget == Budget::ZERO {
            return Err(PagerError::ZeroBudget);
        }
        let scope = self.validate_binding(binding)?;
        if scope.recovery_deadline_completion_pending {
            return Err(PagerError::RecoveryDeadlineCompletionPending);
        }
        if scope.free_budget.units() < budget.units() {
            return Err(PagerError::BudgetExhausted {
                requested: budget,
                available: scope.free_budget,
            });
        }
        let free_after = scope
            .free_budget
            .units()
            .checked_sub(budget.units())
            .ok_or(PagerError::InvariantViolation("budget underflow"))?;
        let revision_after = Self::next_revision(scope)?;
        let fault = FaultId::new(self.next_fault);
        let next_fault = self
            .next_fault
            .checked_add(1)
            .ok_or(PagerError::CounterOverflow)?;
        let token = FaultToken {
            scope: binding.scope,
            fault,
            authority_epoch: scope.authority_epoch,
            binding_epoch: scope.binding_epoch,
            address_space: scope.address_space,
            address_space_generation: scope.address_space_generation,
            thread,
            page,
            access,
        };

        self.next_fault = next_fault;
        let scope = self
            .scopes
            .get_mut(&binding.scope)
            .ok_or(PagerError::UnknownScope(binding.scope))?;
        scope.free_budget = Budget::new(free_after);
        scope.live_faults.insert(fault);
        scope.recovery_deadline_armed = true;
        scope.recovery_deadline_completion_pending = false;
        Self::publish_recovery_revision(scope, revision_after);
        self.faults.insert(
            fault,
            FaultRecord {
                token,
                state: FaultState::Registered,
                continuation: ContinuationState::Pending,
                budget,
                budget_disposition: BudgetDisposition::Held,
                prepared_frame: None,
                mapped_frame: None,
                resolved_mapping: None,
                mapping_publications: 0,
                continuation_consumptions: 0,
                terminalizations: 0,
                wakes: 0,
                resumes: 0,
            },
        );
        self.push_trace(PagerAction::Register, binding.scope, Some(fault));
        Ok(token)
    }

    /// Retains one uniquely identified zeroed frame for a registered fault.
    pub fn prepare_zero(
        &mut self,
        binding: PagerBindingToken,
        token: FaultToken,
        frame: FrameId,
    ) -> Result<(), PagerError> {
        self.validate_current_fault_reply(binding, token)?;
        let fault = *self
            .faults
            .get(&token.fault)
            .ok_or(PagerError::UnknownFault(token.fault))?;
        if fault.state != FaultState::Registered {
            return Err(if fault.state.is_terminal() {
                PagerError::AlreadyTerminal
            } else {
                PagerError::InvalidFaultState { state: fault.state }
            });
        }
        if self.frames.contains_key(&frame) {
            return Err(PagerError::FrameAlreadyKnown(frame));
        }
        let revision_after = Self::next_revision(
            self.scopes
                .get(&token.scope)
                .ok_or(PagerError::UnknownScope(token.scope))?,
        )?;

        let fault = self
            .faults
            .get_mut(&token.fault)
            .ok_or(PagerError::UnknownFault(token.fault))?;
        fault.state = FaultState::Prepared;
        fault.prepared_frame = Some(frame);
        self.frames.insert(
            frame,
            FrameRecord {
                state: FrameState::Prepared(token.fault),
            },
        );
        self.scopes
            .get_mut(&token.scope)
            .map(|scope| Self::publish_recovery_revision(scope, revision_after))
            .ok_or(PagerError::UnknownScope(token.scope))?;
        self.push_trace(PagerAction::Prepare, token.scope, Some(token.fault));
        Ok(())
    }

    /// Fences a crashed pager and advances only the binding generation.
    pub fn crash(&mut self, binding: PagerBindingToken) -> Result<(), PagerError> {
        let scope = self.validate_binding(binding)?;
        let next_binding = BindingEpoch::new(
            scope
                .binding_epoch
                .get()
                .checked_add(1)
                .ok_or(PagerError::CounterOverflow)?,
        );
        let scope = self
            .scopes
            .get_mut(&binding.scope)
            .ok_or(PagerError::UnknownScope(binding.scope))?;
        scope.binding_epoch = next_binding;
        scope.pager = None;
        scope.fallback = PagerFallbackState::Required;
        scope.ready = None;
        self.push_trace(PagerAction::Crash, binding.scope, None);
        Ok(())
    }

    /// Selects the minimal kernel fallback after pager failure.
    pub fn fallback_pick(&mut self, scope: ScopeId) -> Result<(), PagerError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        if record.pager.is_some() || record.fallback != PagerFallbackState::Required {
            return Err(PagerError::FallbackUnavailable);
        }
        self.scopes
            .get_mut(&scope)
            .ok_or(PagerError::UnknownScope(scope))?
            .fallback = PagerFallbackState::Running;
        self.push_trace(PagerAction::FallbackPick, scope, None);
        Ok(())
    }

    /// Captures the deterministic orphan set for a fresh replacement pager.
    pub fn recovery_snapshot(
        &self,
        scope: ScopeId,
        pager: PagerId,
    ) -> Result<RecoverySnapshot, PagerError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        if record.state != ScopeState::Active {
            return Err(PagerError::InvalidScopeState {
                state: record.state,
            });
        }
        if record.pager.is_some() || record.fallback != PagerFallbackState::Running {
            return Err(PagerError::FallbackUnavailable);
        }
        let mut faults = Vec::new();
        for fault_id in &record.live_faults {
            let fault = self
                .faults
                .get(fault_id)
                .ok_or(PagerError::UnknownFault(*fault_id))?;
            if matches!(fault.state, FaultState::Registered | FaultState::Prepared) {
                faults.push(FaultSnapshot {
                    token: fault.token,
                    state: fault.state,
                    prepared_frame: fault.prepared_frame,
                });
            }
        }
        Ok(RecoverySnapshot {
            scope,
            address_space: record.address_space,
            pager,
            authority_epoch: record.authority_epoch,
            binding_epoch: record.binding_epoch,
            address_space_generation: record.address_space_generation,
            recovery_revision: record.recovery_revision,
            faults,
        })
    }

    /// Accepts replacement readiness only from a still-fresh recovery snapshot.
    pub fn ready(&mut self, snapshot: &RecoverySnapshot) -> Result<PagerReadyToken, PagerError> {
        let scope = self
            .scopes
            .get(&snapshot.scope)
            .ok_or(PagerError::UnknownScope(snapshot.scope))?;
        if scope.state != ScopeState::Active {
            return Err(PagerError::InvalidScopeState { state: scope.state });
        }
        if scope.pager.is_some() || scope.fallback != PagerFallbackState::Running {
            return Err(PagerError::FallbackUnavailable);
        }
        self.validate_snapshot(scope, snapshot)?;
        let token = PagerReadyToken {
            scope: snapshot.scope,
            address_space: snapshot.address_space,
            pager: snapshot.pager,
            authority_epoch: snapshot.authority_epoch,
            binding_epoch: snapshot.binding_epoch,
            address_space_generation: snapshot.address_space_generation,
            recovery_revision: snapshot.recovery_revision,
        };
        let scope = self
            .scopes
            .get_mut(&snapshot.scope)
            .ok_or(PagerError::UnknownScope(snapshot.scope))?;
        scope.fallback = PagerFallbackState::ReplacementReady;
        scope.ready = Some(ReadyRecord {
            pager: token.pager,
            authority_epoch: token.authority_epoch,
            binding_epoch: token.binding_epoch,
            address_space_generation: token.address_space_generation,
            recovery_revision: token.recovery_revision,
        });
        self.push_trace(PagerAction::Ready, snapshot.scope, None);
        Ok(token)
    }

    /// Installs a ready replacement without advancing the binding generation.
    pub fn rebind(&mut self, ready: PagerReadyToken) -> Result<PagerBindingToken, PagerError> {
        let scope = self
            .scopes
            .get(&ready.scope)
            .ok_or(PagerError::UnknownScope(ready.scope))?;
        if scope.state != ScopeState::Active {
            return Err(PagerError::InvalidScopeState { state: scope.state });
        }
        if scope.pager.is_some() {
            return Err(PagerError::PagerAlreadyBound);
        }
        if scope.fallback != PagerFallbackState::ReplacementReady {
            return Err(PagerError::FallbackUnavailable);
        }
        self.validate_ready(scope, ready)?;
        let binding = PagerBindingToken {
            scope: ready.scope,
            address_space: ready.address_space,
            pager: ready.pager,
            authority_epoch: ready.authority_epoch,
            binding_epoch: ready.binding_epoch,
        };
        let scope = self
            .scopes
            .get_mut(&ready.scope)
            .ok_or(PagerError::UnknownScope(ready.scope))?;
        scope.pager = Some(ready.pager);
        scope.fallback = PagerFallbackState::Standby;
        scope.ready = None;
        self.push_trace(PagerAction::Rebind, ready.scope, None);
        Ok(binding)
    }

    /// Explicitly transfers an orphan uncommitted fault to the replacement.
    pub fn adopt(
        &mut self,
        binding: PagerBindingToken,
        token: FaultToken,
    ) -> Result<FaultToken, PagerError> {
        let scope = self.validate_binding(binding)?;
        let fault = self.validate_fault_token(token)?;
        if token.scope != binding.scope {
            return Err(PagerError::ScopeMismatch);
        }
        if token.authority_epoch != scope.authority_epoch {
            return Err(PagerError::StaleAuthority {
                presented: token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if token.address_space_generation != scope.address_space_generation {
            return Err(PagerError::StaleAddressSpaceGeneration {
                presented: token.address_space_generation,
                current: scope.address_space_generation,
            });
        }
        if !matches!(fault.state, FaultState::Registered | FaultState::Prepared)
            || fault.token.binding_epoch == scope.binding_epoch
        {
            return Err(PagerError::NotAdoptable);
        }
        let revision_after = Self::next_revision(scope)?;
        let mut adopted = token;
        adopted.binding_epoch = scope.binding_epoch;
        self.faults
            .get_mut(&token.fault)
            .ok_or(PagerError::UnknownFault(token.fault))?
            .token = adopted;
        self.scopes
            .get_mut(&token.scope)
            .map(|scope| Self::publish_recovery_revision(scope, revision_after))
            .ok_or(PagerError::UnknownScope(token.scope))?;
        self.push_trace(PagerAction::Adopt, token.scope, Some(token.fault));
        Ok(adopted)
    }

    /// Atomically publishes a mapping and consumes the fault continuation.
    ///
    /// This is the pager effect's commit linearization point.  Every authority,
    /// binding, address-space, identity, state, frame, and mapping-slot check is
    /// performed before either the mapping or continuation state is mutated.
    pub fn commit(
        &mut self,
        binding: PagerBindingToken,
        token: FaultToken,
    ) -> Result<MappingKey, PagerError> {
        self.validate_current_fault_reply(binding, token)?;
        let fault = *self
            .faults
            .get(&token.fault)
            .ok_or(PagerError::UnknownFault(token.fault))?;
        if fault.state.is_terminal() {
            return Err(PagerError::AlreadyTerminal);
        }
        if fault.continuation != ContinuationState::Pending {
            return Err(PagerError::ContinuationAlreadyConsumed);
        }
        if fault.state != FaultState::Prepared {
            return Err(PagerError::InvalidFaultState { state: fault.state });
        }
        let frame = fault.prepared_frame.ok_or(PagerError::InvariantViolation(
            "prepared fault lacks a frame",
        ))?;
        let frame_record = self
            .frames
            .get(&frame)
            .ok_or(PagerError::FrameOwnershipMismatch(frame))?;
        if frame_record.state != FrameState::Prepared(token.fault) {
            return Err(PagerError::FrameOwnershipMismatch(frame));
        }
        let key = MappingKey {
            address_space: token.address_space,
            generation: token.address_space_generation,
            page: token.page,
        };
        if self.current_mappings.contains_key(&key) || self.publication_history.contains_key(&key) {
            return Err(PagerError::MappingAlreadyPublished(key));
        }
        if fault.budget_disposition != BudgetDisposition::Held {
            return Err(PagerError::InvariantViolation(
                "prepared fault does not hold its budget",
            ));
        }
        let scope = self
            .scopes
            .get(&token.scope)
            .ok_or(PagerError::UnknownScope(token.scope))?;
        let spent_after = scope
            .spent_budget
            .units()
            .checked_add(fault.budget.units())
            .ok_or(PagerError::CounterOverflow)?;
        let revision_after = Self::next_revision(scope)?;

        let fault_record = self
            .faults
            .get_mut(&token.fault)
            .ok_or(PagerError::UnknownFault(token.fault))?;
        fault_record.state = FaultState::Committed;
        fault_record.continuation = ContinuationState::Resolved;
        fault_record.budget_disposition = BudgetDisposition::Spent;
        fault_record.prepared_frame = None;
        fault_record.mapped_frame = Some(frame);
        fault_record.resolved_mapping = Some(key);
        fault_record.mapping_publications = 1;
        fault_record.continuation_consumptions = 1;
        self.frames
            .get_mut(&frame)
            .ok_or(PagerError::FrameOwnershipMismatch(frame))?
            .state = FrameState::Mapped {
            key,
            fault: token.fault,
        };
        let mapping = MappingRecord {
            frame,
            fault: token.fault,
        };
        self.current_mappings.insert(key, mapping);
        self.publication_history.insert(key, mapping);
        let scope = self
            .scopes
            .get_mut(&token.scope)
            .ok_or(PagerError::UnknownScope(token.scope))?;
        scope.spent_budget = Budget::new(spent_after);
        Self::publish_recovery_revision(scope, revision_after);
        self.push_trace(PagerAction::Commit, token.scope, Some(token.fault));
        Ok(key)
    }

    /// Resolves a same-page fault from an already published current mapping.
    ///
    /// This is a kernel-owned coalescing transition. It consumes the losing
    /// continuation exactly once, releases any redundant prepared frame,
    /// returns that fault's held credit, and publishes one success wake/resume
    /// without incrementing the mapping-publication count.
    pub fn satisfy_mapped(&mut self, token: FaultToken) -> Result<MappingKey, PagerError> {
        let fault = *self.validate_fault_token(token)?;
        let scope = self
            .scopes
            .get(&token.scope)
            .ok_or(PagerError::UnknownScope(token.scope))?;
        if scope.state != ScopeState::Active {
            return Err(PagerError::InvalidScopeState { state: scope.state });
        }
        if token.authority_epoch != scope.authority_epoch {
            return Err(PagerError::StaleAuthority {
                presented: token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if token.address_space_generation != scope.address_space_generation {
            return Err(PagerError::StaleAddressSpaceGeneration {
                presented: token.address_space_generation,
                current: scope.address_space_generation,
            });
        }
        if fault.state.is_terminal() {
            return Err(PagerError::AlreadyTerminal);
        }
        if !matches!(fault.state, FaultState::Registered | FaultState::Prepared) {
            return Err(PagerError::InvalidFaultState { state: fault.state });
        }
        if fault.continuation != ContinuationState::Pending
            || fault.budget_disposition != BudgetDisposition::Held
        {
            return Err(PagerError::InvariantViolation(
                "coalesced fault lacks pending continuation or held budget",
            ));
        }
        if let Some(frame) = fault.prepared_frame
            && self.frames.get(&frame).map(|record| record.state)
                != Some(FrameState::Prepared(token.fault))
        {
            return Err(PagerError::FrameOwnershipMismatch(frame));
        }
        let key = MappingKey {
            address_space: token.address_space,
            generation: token.address_space_generation,
            page: token.page,
        };
        if !self.current_mappings.contains_key(&key) {
            return Err(PagerError::MappingUnavailable(key));
        }
        let free_after = scope
            .free_budget
            .units()
            .checked_add(fault.budget.units())
            .ok_or(PagerError::CounterOverflow)?;
        let revision_after = Self::next_revision(scope)?;

        let fault_record = self
            .faults
            .get_mut(&token.fault)
            .ok_or(PagerError::UnknownFault(token.fault))?;
        fault_record.state = FaultState::Completed;
        fault_record.continuation = ContinuationState::Resolved;
        fault_record.budget_disposition = BudgetDisposition::Returned;
        fault_record.prepared_frame = None;
        fault_record.mapped_frame = None;
        fault_record.resolved_mapping = Some(key);
        fault_record.mapping_publications = 0;
        fault_record.continuation_consumptions = 1;
        fault_record.terminalizations = 1;
        fault_record.wakes = 1;
        fault_record.resumes = 1;
        if let Some(frame) = fault.prepared_frame {
            self.frames
                .get_mut(&frame)
                .ok_or(PagerError::FrameOwnershipMismatch(frame))?
                .state = FrameState::Released(token.fault);
        }
        let scope = self
            .scopes
            .get_mut(&token.scope)
            .ok_or(PagerError::UnknownScope(token.scope))?;
        scope.free_budget = Budget::new(free_after);
        scope.live_faults.remove(&token.fault);
        if scope.live_faults.is_empty() && !scope.recovery_deadline_completion_pending {
            scope.recovery_deadline_armed = false;
        }
        Self::publish_recovery_revision(scope, revision_after);
        self.push_trace(PagerAction::SatisfyMapped, token.scope, Some(token.fault));
        Ok(key)
    }

    /// Delivers the unique successful wake/resume for a committed mapping.
    pub fn complete(&mut self, fault: FaultId) -> Result<(), PagerError> {
        self.terminalize_committed(fault, PagerAction::Complete)?;
        Ok(())
    }

    /// Aborts one stale-AS or closing-scope continuation and returns held resources.
    ///
    /// Because the full fault token is checked, an orphan-abort token loses a
    /// race against successful adoption and cannot abort the newly owned fault.
    pub fn abort(&mut self, token: FaultToken) -> Result<(), PagerError> {
        self.validate_fault_token(token)?;
        let scope = self
            .scopes
            .get(&token.scope)
            .ok_or(PagerError::UnknownScope(token.scope))?;
        let permitted = scope.state == ScopeState::Closing
            || (scope.state == ScopeState::Active
                && token.address_space_generation != scope.address_space_generation);
        if !permitted {
            return Err(PagerError::AbortNotPermitted);
        }
        self.terminalize_uncommitted(token.fault, PagerAction::Abort)?;
        Ok(())
    }

    /// Tears down current mappings and advances the address-space generation.
    ///
    /// Every mapping publisher must first reach `Completed`; mutation is
    /// rejected while a committed continuation still awaits its success wake.
    /// Teardown removes the current PTE abstraction, releases each mapped frame,
    /// and returns its page/pin credit while retaining immutable publication
    /// history for differential checks.
    pub fn advance_address_space_generation(
        &mut self,
        address_space: AddressSpaceId,
    ) -> Result<AddressSpaceGeneration, PagerError> {
        let scope_id = *self
            .address_spaces
            .get(&address_space)
            .ok_or(PagerError::UnknownAddressSpace(address_space))?;
        let scope = self
            .scopes
            .get(&scope_id)
            .ok_or(PagerError::UnknownScope(scope_id))?;
        if scope.state != ScopeState::Active {
            return Err(PagerError::InvalidScopeState { state: scope.state });
        }
        let committed = scope
            .live_faults
            .iter()
            .filter(|fault_id| {
                self.faults
                    .get(fault_id)
                    .is_some_and(|fault| fault.state == FaultState::Committed)
            })
            .count();
        if committed != 0 {
            return Err(PagerError::CommittedMappingOutstanding {
                remaining: committed,
            });
        }
        let current_generation = scope.address_space_generation;
        let mappings: Vec<_> = self
            .current_mappings
            .iter()
            .filter(|(key, _)| {
                key.address_space == address_space && key.generation == current_generation
            })
            .map(|(key, mapping)| (*key, *mapping))
            .collect();
        let mut returned_credit = 0u64;
        for (key, mapping) in &mappings {
            let fault = self
                .faults
                .get(&mapping.fault)
                .ok_or(PagerError::UnknownFault(mapping.fault))?;
            if fault.state != FaultState::Completed
                || fault.budget_disposition != BudgetDisposition::Spent
                || fault.mapped_frame != Some(mapping.frame)
                || fault.resolved_mapping != Some(*key)
            {
                return Err(PagerError::InvariantViolation(
                    "current mapping lacks one completed publisher",
                ));
            }
            if self.frames.get(&mapping.frame).map(|frame| frame.state)
                != Some(FrameState::Mapped {
                    key: *key,
                    fault: mapping.fault,
                })
            {
                return Err(PagerError::FrameOwnershipMismatch(mapping.frame));
            }
            if self.publication_history.get(key) != Some(mapping) {
                return Err(PagerError::InvariantViolation(
                    "current mapping lacks publication history",
                ));
            }
            returned_credit = returned_credit
                .checked_add(fault.budget.units())
                .ok_or(PagerError::CounterOverflow)?;
        }
        let generation = AddressSpaceGeneration::new(
            scope
                .address_space_generation
                .get()
                .checked_add(1)
                .ok_or(PagerError::CounterOverflow)?,
        );
        let free_after = scope
            .free_budget
            .units()
            .checked_add(returned_credit)
            .ok_or(PagerError::CounterOverflow)?;
        let spent_after = scope
            .spent_budget
            .units()
            .checked_sub(returned_credit)
            .ok_or(PagerError::InvariantViolation("spent budget underflow"))?;
        let revision_after = Self::next_revision(scope)?;

        for (key, mapping) in mappings {
            self.current_mappings.remove(&key);
            self.frames
                .get_mut(&mapping.frame)
                .ok_or(PagerError::FrameOwnershipMismatch(mapping.frame))?
                .state = FrameState::Released(mapping.fault);
            let fault = self
                .faults
                .get_mut(&mapping.fault)
                .ok_or(PagerError::UnknownFault(mapping.fault))?;
            fault.mapped_frame = None;
            fault.budget_disposition = BudgetDisposition::Returned;
        }
        let scope = self
            .scopes
            .get_mut(&scope_id)
            .ok_or(PagerError::UnknownScope(scope_id))?;
        scope.address_space_generation = generation;
        scope.free_budget = Budget::new(free_after);
        scope.spent_budget = Budget::new(spent_after);
        Self::publish_recovery_revision(scope, revision_after);
        self.push_trace(PagerAction::AdvanceAddressSpaceGeneration, scope_id, None);
        Ok(generation)
    }

    /// Linearizes timeout closure and advances only the authority generation.
    pub fn revoke_begin(&mut self, scope: ScopeId) -> Result<(), PagerError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        if record.state != ScopeState::Active {
            return Err(PagerError::InvalidScopeState {
                state: record.state,
            });
        }
        let closed_epoch = record.authority_epoch;
        let authority_epoch = AuthorityEpoch::new(
            record
                .authority_epoch
                .get()
                .checked_add(1)
                .ok_or(PagerError::CounterOverflow)?,
        );
        let target_count = record.live_faults.len();
        let revision_after = Self::next_revision(record)?;
        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        record.state = ScopeState::Closing;
        record.authority_epoch = authority_epoch;
        record.revocation = Some(RevocationRecord {
            closed_epoch,
            target_count,
            steps: 0,
        });
        record.recovery_deadline_armed = false;
        record.recovery_deadline_completion_pending = false;
        Self::publish_recovery_revision(record, revision_after);
        self.push_trace(PagerAction::RevokeBegin, scope, None);
        Ok(())
    }

    /// Kernel-owned deadline path for a stalled pager recovery cohort.
    ///
    /// It requires no pager or fault token, so adoption cannot fence the
    /// watchdog out. Any still-uncommitted fault enters the same `RevokeBegin`
    /// linearization point used by explicit revocation. If every remaining
    /// fault is already committed or terminal, the scope stays active whether
    /// the pager is present or absent; new registration is gated and trusted
    /// `complete` operations drain the committed-only batch. The pager fallback
    /// independently records service availability because this deadline protects
    /// blocked fault continuations rather than the pager lease.
    pub fn recovery_timeout_begin(
        &mut self,
        scope: ScopeId,
    ) -> Result<RecoveryTimeoutResult, PagerError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        if !record.recovery_deadline_armed {
            return Err(PagerError::RecoveryDeadlineUnavailable);
        }
        let uncommitted = record
            .live_faults
            .iter()
            .filter(|fault_id| {
                self.faults.get(fault_id).is_some_and(|fault| {
                    matches!(fault.state, FaultState::Registered | FaultState::Prepared)
                })
            })
            .count();
        if uncommitted == 0 {
            let committed = record.live_faults.len();
            if !record.recovery_deadline_completion_pending {
                self.scopes
                    .get_mut(&scope)
                    .ok_or(PagerError::UnknownScope(scope))?
                    .recovery_deadline_completion_pending = true;
                self.push_trace(PagerAction::DeadlineCompletionPending, scope, None);
            }
            return Ok(RecoveryTimeoutResult::CompletionPending { committed });
        }
        self.revoke_begin(scope)?;
        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        record.pager = None;
        record.fallback = PagerFallbackState::Running;
        record.ready = None;
        Ok(RecoveryTimeoutResult::RevocationStarted)
    }

    /// Clears an expired recovery batch after trusted completion terminalized it.
    pub fn deadline_complete(&mut self, scope: ScopeId) -> Result<(), PagerError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        if record.state != ScopeState::Active {
            return Err(PagerError::InvalidScopeState {
                state: record.state,
            });
        }
        if !record.recovery_deadline_armed
            || !record.recovery_deadline_completion_pending
            || !record.live_faults.is_empty()
        {
            return Err(PagerError::RecoveryDeadlineNotComplete);
        }
        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        record.recovery_deadline_armed = false;
        record.recovery_deadline_completion_pending = false;
        self.push_trace(PagerAction::DeadlineComplete, scope, None);
        Ok(())
    }

    /// Visits and terminalizes one fault from the closing scope's reverse index.
    ///
    /// This is kernel-owned work selected by fault identity from the scope's
    /// reverse index.  It deliberately does not require an old or newly adopted
    /// pager token, so adoption cannot fence the recovery watchdog out.
    pub fn revoke_next(
        &mut self,
        scope: ScopeId,
    ) -> Result<Option<PagerRevocationStep>, PagerError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        if record.state != ScopeState::Closing {
            return Err(PagerError::InvalidScopeState {
                state: record.state,
            });
        }
        let Some(fault_id) = record.live_faults.first().copied() else {
            return Ok(None);
        };
        let fault = *self
            .faults
            .get(&fault_id)
            .ok_or(PagerError::UnknownFault(fault_id))?;
        let step = match fault.state {
            FaultState::Registered | FaultState::Prepared => {
                let released_frame = fault.prepared_frame;
                let returned_budget = fault.budget;
                self.terminalize_uncommitted(fault_id, PagerAction::RevokeStep)?;
                PagerRevocationStep {
                    fault: fault_id,
                    from: fault.state,
                    to: FaultState::Aborted,
                    released_frame,
                    returned_budget,
                }
            }
            FaultState::Committed => {
                self.terminalize_committed(fault_id, PagerAction::RevokeStep)?;
                PagerRevocationStep {
                    fault: fault_id,
                    from: FaultState::Committed,
                    to: FaultState::Completed,
                    released_frame: None,
                    returned_budget: Budget::ZERO,
                }
            }
            FaultState::Completed | FaultState::Aborted => {
                return Err(PagerError::InvariantViolation(
                    "terminal fault remained in reverse index",
                ));
            }
        };
        let progress = self
            .scopes
            .get_mut(&scope)
            .ok_or(PagerError::UnknownScope(scope))?
            .revocation
            .as_mut()
            .ok_or(PagerError::InvariantViolation(
                "closing scope lacks revocation metadata",
            ))?;
        progress.steps = progress
            .steps
            .checked_add(1)
            .ok_or(PagerError::CounterOverflow)?;
        Ok(Some(step))
    }

    /// Publishes closure only after every indexed fault has terminalized.
    pub fn revoke_complete(&mut self, scope: ScopeId) -> Result<(), PagerError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(PagerError::UnknownScope(scope))?;
        if record.state != ScopeState::Closing {
            return Err(PagerError::InvalidScopeState {
                state: record.state,
            });
        }
        if !record.live_faults.is_empty() {
            return Err(PagerError::RevocationNotQuiescent {
                remaining: record.live_faults.len(),
            });
        }
        self.scopes
            .get_mut(&scope)
            .ok_or(PagerError::UnknownScope(scope))?
            .state = ScopeState::Revoked;
        self.push_trace(PagerAction::RevokeComplete, scope, None);
        Ok(())
    }
}
