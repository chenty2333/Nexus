use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::*;

impl Default for IoModel {
    fn default() -> Self {
        Self::new()
    }
}

impl IoModel {
    /// Creates an empty mediated-I/O model.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_scope: 1,
            next_request: 1,
            scopes: BTreeMap::new(),
            requests: BTreeMap::new(),
            device_owners: BTreeMap::new(),
            queue_owners: BTreeMap::new(),
            issued_dma_leases: BTreeSet::new(),
            issued_mappings: BTreeSet::new(),
            active_dma_leases: BTreeSet::new(),
            active_mappings: BTreeSet::new(),
            active_iovas: BTreeSet::new(),
            trace: Vec::new(),
        }
    }

    /// Creates one active scope that exclusively owns one device and queue.
    pub fn create_scope(
        &mut self,
        service: IoServiceId,
        device: DeviceId,
        queue: QueueId,
        initial_budget: IoBudget,
        queue_dma: DmaIdentity,
        queue_credits: LeaseCredits,
    ) -> Result<(ScopeId, IoBindingToken), IoError> {
        if queue_credits.queue_slots != 0
            || queue_credits.pinned_pages == 0
            || queue_credits.dma_bytes == 0
        {
            return Err(IoError::InvalidQueueLease);
        }
        if self.device_owners.contains_key(&device) {
            return Err(IoError::DeviceInUse(device));
        }
        if self.queue_owners.contains_key(&queue) {
            return Err(IoError::QueueInUse(queue));
        }
        self.validate_dma_available(queue_dma)?;
        if !initial_budget.leases.contains(queue_credits) {
            return Err(IoError::LeaseBudgetExhausted {
                requested: queue_credits,
                available: initial_budget.leases,
            });
        }
        let free_lease_credits = initial_budget
            .leases
            .checked_sub(queue_credits)
            .ok_or(IoError::InvariantViolation("queue lease budget underflow"))?;
        let scope = ScopeId::new(self.next_scope);
        let next_scope = self
            .next_scope
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let authority_epoch = AuthorityEpoch::new(1);
        let binding_epoch = BindingEpoch::new(1);
        let device_generation = DeviceGeneration::new(1);
        self.next_scope = next_scope;
        self.reserve_dma(queue_dma);
        self.device_owners.insert(device, scope);
        self.queue_owners.insert(queue, scope);
        self.scopes.insert(
            scope,
            IoScopeRecord {
                state: ScopeState::Active,
                authority_epoch,
                binding_epoch,
                device_generation,
                device,
                queue,
                service: Some(service),
                fallback: IoFallbackState::Standby,
                ready: None,
                recovery_revision: 0,
                initial_budget,
                free_lease_credits,
                free_commit_charges: initial_budget.commit_charges,
                held_commit_charges: CommitCharges::ZERO,
                spent_commit_charges: CommitCharges::ZERO,
                queue_lease: QueueLeaseRecord {
                    queue,
                    dma: queue_dma,
                    state: DmaLeaseState::Mapped,
                    invalidation: InvalidationRecord::NotStarted,
                    credits: queue_credits,
                },
                requests: BTreeSet::new(),
                live_obligations: BTreeSet::new(),
                unpublished_obligations: BTreeSet::new(),
                nonterminal_requests: 0,
                queue_slot_obligations: BTreeSet::new(),
                avail_idx: 0,
                device_quiesced: false,
                reset: ResetRecord::Idle,
                next_attempt: 1,
                revocation: None,
            },
        );
        self.push_trace(IoAction::CreateScope, scope, None);
        Ok((
            scope,
            IoBindingToken {
                scope,
                service,
                authority_epoch,
                binding_epoch,
            },
        ))
    }

    /// Registers one request and reserves its typed grant and DMA identity.
    pub fn register(
        &mut self,
        binding: IoBindingToken,
        grant: RequestGrant,
        dma: DmaIdentity,
    ) -> Result<RequestToken, IoError> {
        if grant.lease.queue_slots != 1
            || grant.lease.pinned_pages == 0
            || grant.lease.dma_bytes == 0
            || grant.commit_charge == CommitCharges::ZERO
        {
            return Err(IoError::InvalidGrant);
        }
        self.validate_dma_available(dma)?;
        let scope = self.validate_binding(binding)?;
        if !scope.free_lease_credits.contains(grant.lease) {
            return Err(IoError::LeaseBudgetExhausted {
                requested: grant.lease,
                available: scope.free_lease_credits,
            });
        }
        if scope.free_commit_charges.get() < grant.commit_charge.get() {
            return Err(IoError::CommitBudgetExhausted {
                requested: grant.commit_charge,
                available: scope.free_commit_charges,
            });
        }
        let free_lease = scope.free_lease_credits.checked_sub(grant.lease).ok_or(
            IoError::InvariantViolation("request lease budget underflow"),
        )?;
        let free_commit = scope
            .free_commit_charges
            .get()
            .checked_sub(grant.commit_charge.get())
            .ok_or(IoError::InvariantViolation("commit budget underflow"))?;
        let held_commit = scope
            .held_commit_charges
            .get()
            .checked_add(grant.commit_charge.get())
            .ok_or(IoError::CounterOverflow)?;
        let nonterminal_requests = scope
            .nonterminal_requests
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let revision = scope
            .recovery_revision
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let request = RequestId::new(self.next_request);
        let next_request = self
            .next_request
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let token = RequestToken {
            scope: binding.scope,
            request,
            authority_epoch: scope.authority_epoch,
            binding_epoch: scope.binding_epoch,
            device: scope.device,
            queue: scope.queue,
            device_generation: scope.device_generation,
        };

        self.next_request = next_request;
        self.reserve_dma(dma);
        self.requests.insert(
            request,
            RequestRecord {
                token,
                state: IoEffectState::Registered,
                grant,
                commit_disposition: CommitDisposition::Held,
                dma,
                dma_state: DmaLeaseState::Absent,
                invalidation: InvalidationRecord::NotStarted,
                avail_publications: 0,
                notified: false,
                queue_slot_owned: false,
                terminalizations: 0,
            },
        );
        let scope = self
            .scopes
            .get_mut(&binding.scope)
            .ok_or(IoError::UnknownScope(binding.scope))?;
        scope.free_lease_credits = free_lease;
        scope.free_commit_charges = CommitCharges::new(free_commit);
        scope.held_commit_charges = CommitCharges::new(held_commit);
        scope.nonterminal_requests = nonterminal_requests;
        scope.recovery_revision = revision;
        scope.requests.insert(request);
        scope.live_obligations.insert(request);
        scope.unpublished_obligations.insert(request);
        self.push_trace(IoAction::Register, binding.scope, Some(request));
        Ok(token)
    }

    /// Completes descriptor construction without crossing the commit point.
    pub fn prepare(&mut self, binding: IoBindingToken, token: RequestToken) -> Result<(), IoError> {
        self.validate_current_reply(binding, token)?;
        let request = self
            .requests
            .get(&token.request)
            .ok_or(IoError::UnknownRequest(token.request))?;
        if request.state != IoEffectState::Registered {
            return Err(if request.state.is_terminal() {
                IoError::AlreadyTerminal
            } else {
                IoError::InvalidRequestState {
                    state: request.state,
                }
            });
        }
        if request.dma_state != DmaLeaseState::Absent
            || request.invalidation != InvalidationRecord::NotStarted
            || request.queue_slot_owned
        {
            return Err(IoError::InvariantViolation(
                "registered request does not own one reserved DMA identity",
            ));
        }
        let scope = self
            .scopes
            .get(&token.scope)
            .ok_or(IoError::UnknownScope(token.scope))?;
        if scope.queue_slot_obligations.contains(&token.request) {
            return Err(IoError::InvariantViolation(
                "registered request already owns a queue slot",
            ));
        }
        let revision = scope
            .recovery_revision
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let request = self
            .requests
            .get_mut(&token.request)
            .ok_or(IoError::UnknownRequest(token.request))?;
        request.state = IoEffectState::Prepared;
        request.dma_state = DmaLeaseState::Mapped;
        request.queue_slot_owned = true;
        let scope = self
            .scopes
            .get_mut(&token.scope)
            .ok_or(IoError::UnknownScope(token.scope))?;
        scope.recovery_revision = revision;
        scope.queue_slot_obligations.insert(token.request);
        self.push_trace(IoAction::Prepare, token.scope, Some(token.request));
        Ok(())
    }

    /// Fences a crashed service by advancing only the binding generation.
    pub fn crash(&mut self, binding: IoBindingToken) -> Result<(), IoError> {
        let scope = self.validate_binding(binding)?;
        let binding_epoch = BindingEpoch::new(
            scope
                .binding_epoch
                .get()
                .checked_add(1)
                .ok_or(IoError::CounterOverflow)?,
        );
        let scope = self
            .scopes
            .get_mut(&binding.scope)
            .ok_or(IoError::UnknownScope(binding.scope))?;
        scope.binding_epoch = binding_epoch;
        scope.service = None;
        scope.fallback = IoFallbackState::Required;
        scope.ready = None;
        self.push_trace(IoAction::Crash, binding.scope, None);
        Ok(())
    }

    /// Selects the minimal kernel fallback after service failure.
    pub fn fallback_pick(&mut self, scope: ScopeId) -> Result<(), IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        if record.state != ScopeState::Active
            || record.service.is_some()
            || record.fallback != IoFallbackState::Required
        {
            return Err(IoError::FallbackUnavailable);
        }
        self.scopes
            .get_mut(&scope)
            .ok_or(IoError::UnknownScope(scope))?
            .fallback = IoFallbackState::Running;
        self.push_trace(IoAction::FallbackPick, scope, None);
        Ok(())
    }

    /// Captures orphaned `Registered` and `Prepared` work for a replacement.
    pub fn recovery_snapshot(
        &self,
        scope: ScopeId,
        service: IoServiceId,
    ) -> Result<IoRecoverySnapshot, IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        if record.state != ScopeState::Active
            || record.service.is_some()
            || record.fallback != IoFallbackState::Running
        {
            return Err(IoError::FallbackUnavailable);
        }
        let mut requests = Vec::new();
        for request in &record.unpublished_obligations {
            let request = self
                .requests
                .get(request)
                .ok_or(IoError::UnknownRequest(*request))?;
            if matches!(
                request.state,
                IoEffectState::Registered | IoEffectState::Prepared
            ) {
                requests.push(IoRequestSnapshot {
                    token: request.token,
                    state: request.state,
                    dma: request.dma,
                    grant: request.grant,
                });
            }
        }
        Ok(IoRecoverySnapshot {
            scope,
            service,
            authority_epoch: record.authority_epoch,
            binding_epoch: record.binding_epoch,
            device_generation: record.device_generation,
            recovery_revision: record.recovery_revision,
            requests,
        })
    }

    /// Accepts replacement readiness only from a still-current snapshot.
    pub fn ready(&mut self, snapshot: &IoRecoverySnapshot) -> Result<IoReadyToken, IoError> {
        let scope = self
            .scopes
            .get(&snapshot.scope)
            .ok_or(IoError::UnknownScope(snapshot.scope))?;
        if scope.state != ScopeState::Active
            || scope.service.is_some()
            || scope.fallback != IoFallbackState::Running
        {
            return Err(IoError::FallbackUnavailable);
        }
        if snapshot.authority_epoch != scope.authority_epoch
            || snapshot.binding_epoch != scope.binding_epoch
            || snapshot.device_generation != scope.device_generation
            || snapshot.recovery_revision != scope.recovery_revision
        {
            return Err(IoError::StaleRecoverySnapshot);
        }
        let token = IoReadyToken {
            scope: snapshot.scope,
            service: snapshot.service,
            authority_epoch: snapshot.authority_epoch,
            binding_epoch: snapshot.binding_epoch,
            device_generation: snapshot.device_generation,
            recovery_revision: snapshot.recovery_revision,
        };
        let scope = self
            .scopes
            .get_mut(&snapshot.scope)
            .ok_or(IoError::UnknownScope(snapshot.scope))?;
        scope.fallback = IoFallbackState::ReplacementReady;
        scope.ready = Some(ReadyRecord {
            service: token.service,
            authority_epoch: token.authority_epoch,
            binding_epoch: token.binding_epoch,
            device_generation: token.device_generation,
            recovery_revision: token.recovery_revision,
        });
        self.push_trace(IoAction::Ready, snapshot.scope, None);
        Ok(token)
    }

    /// Installs a ready replacement without changing any generation.
    pub fn rebind(&mut self, ready: IoReadyToken) -> Result<IoBindingToken, IoError> {
        let scope = self
            .scopes
            .get(&ready.scope)
            .ok_or(IoError::UnknownScope(ready.scope))?;
        if scope.state != ScopeState::Active {
            return Err(IoError::InvalidScopeState { state: scope.state });
        }
        if scope.service.is_some() {
            return Err(IoError::ServiceAlreadyBound);
        }
        if scope.fallback != IoFallbackState::ReplacementReady {
            return Err(IoError::FallbackUnavailable);
        }
        let expected = ReadyRecord {
            service: ready.service,
            authority_epoch: ready.authority_epoch,
            binding_epoch: ready.binding_epoch,
            device_generation: ready.device_generation,
            recovery_revision: ready.recovery_revision,
        };
        if scope.ready != Some(expected)
            || ready.authority_epoch != scope.authority_epoch
            || ready.binding_epoch != scope.binding_epoch
            || ready.device_generation != scope.device_generation
            || ready.recovery_revision != scope.recovery_revision
        {
            return Err(IoError::StaleRecoverySnapshot);
        }
        let binding = IoBindingToken {
            scope: ready.scope,
            service: ready.service,
            authority_epoch: ready.authority_epoch,
            binding_epoch: ready.binding_epoch,
        };
        let scope = self
            .scopes
            .get_mut(&ready.scope)
            .ok_or(IoError::UnknownScope(ready.scope))?;
        scope.service = Some(ready.service);
        scope.fallback = IoFallbackState::Standby;
        scope.ready = None;
        self.push_trace(IoAction::Rebind, ready.scope, None);
        Ok(binding)
    }

    /// Explicitly transfers one orphaned unpublished request to a replacement.
    pub fn adopt(
        &mut self,
        binding: IoBindingToken,
        token: RequestToken,
    ) -> Result<RequestToken, IoError> {
        let scope = self.validate_binding(binding)?;
        let request = self.validate_request_token(token)?;
        if token.scope != binding.scope {
            return Err(IoError::RequestIdentityMismatch);
        }
        if token.authority_epoch != scope.authority_epoch {
            return Err(IoError::StaleAuthority {
                presented: token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if token.device_generation != scope.device_generation {
            return Err(IoError::StaleDeviceGeneration {
                presented: token.device_generation,
                current: scope.device_generation,
            });
        }
        if !matches!(
            request.state,
            IoEffectState::Registered | IoEffectState::Prepared
        ) || request.token.binding_epoch == scope.binding_epoch
        {
            return Err(IoError::NotAdoptable);
        }
        let revision = scope
            .recovery_revision
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let mut adopted = token;
        adopted.binding_epoch = scope.binding_epoch;
        self.requests
            .get_mut(&token.request)
            .ok_or(IoError::UnknownRequest(token.request))?
            .token = adopted;
        self.scopes
            .get_mut(&token.scope)
            .ok_or(IoError::UnknownScope(token.scope))?
            .recovery_revision = revision;
        self.push_trace(IoAction::Adopt, token.scope, Some(token.request));
        Ok(adopted)
    }

    /// Release-publishes `avail.idx`, the mediated request commit point.
    ///
    /// Descriptor construction and notification are deliberately outside this
    /// transition. Once this method succeeds, reset may report an
    /// indeterminate outcome but can never turn the request into `Cancelled`.
    pub fn publish_avail(
        &mut self,
        binding: IoBindingToken,
        token: RequestToken,
    ) -> Result<u64, IoError> {
        self.validate_current_reply(binding, token)?;
        let request = *self
            .requests
            .get(&token.request)
            .ok_or(IoError::UnknownRequest(token.request))?;
        if request.state.is_terminal() {
            return Err(IoError::AlreadyTerminal);
        }
        if request.state == IoEffectState::Committed {
            return Err(IoError::AlreadyPublished);
        }
        if request.state != IoEffectState::Prepared {
            return Err(IoError::InvalidRequestState {
                state: request.state,
            });
        }
        if request.commit_disposition != CommitDisposition::Held {
            return Err(IoError::InvariantViolation(
                "prepared request does not hold commit charge",
            ));
        }
        if request.dma_state != DmaLeaseState::Mapped
            || request.invalidation != InvalidationRecord::NotStarted
            || !request.queue_slot_owned
        {
            return Err(IoError::InvariantViolation(
                "prepared publication lacks one live DMA mapping",
            ));
        }
        let scope = self
            .scopes
            .get(&token.scope)
            .ok_or(IoError::UnknownScope(token.scope))?;
        let avail_idx = scope
            .avail_idx
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let spent = scope
            .spent_commit_charges
            .get()
            .checked_add(request.grant.commit_charge.get())
            .ok_or(IoError::CounterOverflow)?;
        let held = scope
            .held_commit_charges
            .get()
            .checked_sub(request.grant.commit_charge.get())
            .ok_or(IoError::InvariantViolation(
                "prepared request commit charge is not in the held ledger",
            ))?;
        let revision = scope
            .recovery_revision
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;

        let request = self
            .requests
            .get_mut(&token.request)
            .ok_or(IoError::UnknownRequest(token.request))?;
        request.state = IoEffectState::Committed;
        request.commit_disposition = CommitDisposition::Spent;
        request.avail_publications = 1;
        let scope = self
            .scopes
            .get_mut(&token.scope)
            .ok_or(IoError::UnknownScope(token.scope))?;
        scope.avail_idx = avail_idx;
        scope.held_commit_charges = CommitCharges::new(held);
        scope.spent_commit_charges = CommitCharges::new(spent);
        scope.recovery_revision = revision;
        scope.unpublished_obligations.remove(&token.request);
        self.push_trace(IoAction::PublishAvail, token.scope, Some(token.request));
        Ok(avail_idx)
    }

    /// Records the optional post-commit notification hint.
    ///
    /// A polling device may observe `avail.idx` before this operation, so this
    /// action never changes publication, charge, or terminal state. The
    /// binding identifies the original publisher; it may be crash-fenced after
    /// commit because committed work is owned by the kernel/device path.
    pub fn notify(&mut self, binding: IoBindingToken, token: RequestToken) -> Result<(), IoError> {
        let scope = self
            .scopes
            .get(&token.scope)
            .ok_or(IoError::UnknownScope(token.scope))?;
        self.validate_request_token(token)?;
        if binding.scope != token.scope
            || binding.authority_epoch != token.authority_epoch
            || binding.binding_epoch != token.binding_epoch
            || token.device != scope.device
            || token.queue != scope.queue
        {
            return Err(IoError::RequestIdentityMismatch);
        }
        if token.authority_epoch != scope.authority_epoch {
            return Err(IoError::StaleAuthority {
                presented: token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if scope.state != ScopeState::Active {
            return Err(IoError::InvalidScopeState { state: scope.state });
        }
        if token.device_generation != scope.device_generation {
            return Err(IoError::StaleDeviceGeneration {
                presented: token.device_generation,
                current: scope.device_generation,
            });
        }
        let request = self
            .requests
            .get(&token.request)
            .ok_or(IoError::UnknownRequest(token.request))?;
        if request.state.is_terminal() {
            return Err(IoError::AlreadyTerminal);
        }
        if request.state != IoEffectState::Committed {
            return Err(IoError::NotifyBeforePublish);
        }
        if request.notified {
            return Err(IoError::AlreadyNotified);
        }
        self.requests
            .get_mut(&token.request)
            .ok_or(IoError::UnknownRequest(token.request))?
            .notified = true;
        self.push_trace(IoAction::Notify, token.scope, Some(token.request));
        Ok(())
    }

    /// Creates an authenticated completion witness for a committed request.
    pub fn completion_for(&self, request: RequestId) -> Result<DeviceCompletion, IoError> {
        let request = self
            .requests
            .get(&request)
            .ok_or(IoError::UnknownRequest(request))?;
        if request.state != IoEffectState::Committed {
            return Err(if request.state.is_terminal() {
                IoError::AlreadyTerminal
            } else {
                IoError::InvalidRequestState {
                    state: request.state,
                }
            });
        }
        Ok(DeviceCompletion {
            scope: request.token.scope,
            request: request.token.request,
            device: request.token.device,
            queue: request.token.queue,
            device_generation: request.token.device_generation,
        })
    }

    /// Terminalizes a committed request from one current-generation completion.
    pub fn device_complete(&mut self, completion: DeviceCompletion) -> Result<(), IoError> {
        let scope = self
            .scopes
            .get(&completion.scope)
            .ok_or(IoError::UnknownScope(completion.scope))?;
        if completion.device_generation != scope.device_generation {
            return Err(IoError::StaleDeviceGeneration {
                presented: completion.device_generation,
                current: scope.device_generation,
            });
        }
        if completion.device != scope.device || completion.queue != scope.queue {
            return Err(IoError::RequestIdentityMismatch);
        }
        let request = self
            .requests
            .get(&completion.request)
            .ok_or(IoError::UnknownRequest(completion.request))?;
        if request.token.scope != completion.scope
            || request.token.device != completion.device
            || request.token.queue != completion.queue
            || request.token.device_generation != completion.device_generation
        {
            return Err(IoError::RequestIdentityMismatch);
        }
        if request.state.is_terminal() {
            return Err(IoError::AlreadyTerminal);
        }
        if request.state != IoEffectState::Committed {
            return Err(IoError::InvalidRequestState {
                state: request.state,
            });
        }
        if !request.queue_slot_owned || !scope.queue_slot_obligations.contains(&completion.request)
        {
            return Err(IoError::InvariantViolation(
                "committed request lacks its queue-slot obligation",
            ));
        }
        let nonterminal_requests =
            scope
                .nonterminal_requests
                .checked_sub(1)
                .ok_or(IoError::InvariantViolation(
                    "completion underflowed nonterminal request count",
                ))?;
        let request = self
            .requests
            .get_mut(&completion.request)
            .ok_or(IoError::UnknownRequest(completion.request))?;
        request.state = IoEffectState::Completed;
        request.queue_slot_owned = false;
        request.terminalizations = 1;
        let scope = self
            .scopes
            .get_mut(&completion.scope)
            .ok_or(IoError::UnknownScope(completion.scope))?;
        scope.nonterminal_requests = nonterminal_requests;
        scope.queue_slot_obligations.remove(&completion.request);
        self.push_trace(
            IoAction::DeviceComplete,
            completion.scope,
            Some(completion.request),
        );
        Ok(())
    }

    /// Closes the `avail.idx` publication gate and advances only authority.
    pub fn revoke_begin(&mut self, scope: ScopeId) -> Result<(), IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        if record.state != ScopeState::Active {
            return Err(IoError::InvalidScopeState {
                state: record.state,
            });
        }
        let closed_epoch = record.authority_epoch;
        let authority_epoch = AuthorityEpoch::new(
            record
                .authority_epoch
                .get()
                .checked_add(1)
                .ok_or(IoError::CounterOverflow)?,
        );
        let target_count = record.live_obligations.len();
        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        record.state = ScopeState::Closing;
        record.authority_epoch = authority_epoch;
        record.service = None;
        record.ready = None;
        record.reset = ResetRecord::Required;
        record.revocation = Some(RevocationRecord {
            closed_epoch,
            target_count,
            cancel_steps: 0,
            cancel_index_visits: 0,
            reset_index_visits: 0,
            reset_terminalizations: 0,
            invalidated_request_leases: 0,
        });
        self.push_trace(IoAction::RevokeBegin, scope, None);
        Ok(())
    }

    /// Cancels the next unpublished request through the target scope's index.
    pub fn cancel_unpublished(&mut self, scope: ScopeId) -> Result<Option<RequestId>, IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        if record.state != ScopeState::Closing {
            return Err(IoError::InvalidScopeState {
                state: record.state,
            });
        }
        let request_id = record.unpublished_obligations.iter().next().copied();
        let Some(request_id) = request_id else {
            return Ok(None);
        };
        let request = *self
            .requests
            .get(&request_id)
            .ok_or(IoError::UnknownRequest(request_id))?;
        if request.commit_disposition != CommitDisposition::Held {
            return Err(IoError::InvariantViolation(
                "unpublished request lacks held commit charge",
            ));
        }
        if !matches!(
            request.state,
            IoEffectState::Registered | IoEffectState::Prepared
        ) {
            return Err(IoError::InvariantViolation(
                "unpublished index contains a published or terminal request",
            ));
        }
        let free_commit = record
            .free_commit_charges
            .get()
            .checked_add(request.grant.commit_charge.get())
            .ok_or(IoError::CounterOverflow)?;
        let held_commit = record
            .held_commit_charges
            .get()
            .checked_sub(request.grant.commit_charge.get())
            .ok_or(IoError::InvariantViolation(
                "unpublished request charge is absent from held ledger",
            ))?;
        let direct_cancel = request.state == IoEffectState::Registered;
        let free_lease = if direct_cancel {
            Some(
                record
                    .free_lease_credits
                    .checked_add(request.grant.lease)
                    .ok_or(IoError::CounterOverflow)?,
            )
        } else {
            None
        };
        if direct_cancel && request.dma_state != DmaLeaseState::Absent {
            return Err(IoError::InvariantViolation(
                "registered cancellation found an established DMA mapping",
            ));
        }
        if direct_cancel && request.queue_slot_owned {
            return Err(IoError::InvariantViolation(
                "registered cancellation found a queue-slot obligation",
            ));
        }
        if !direct_cancel
            && (request.dma_state != DmaLeaseState::Mapped
                || !request.queue_slot_owned
                || !record.queue_slot_obligations.contains(&request_id))
        {
            return Err(IoError::InvariantViolation(
                "prepared cancellation lacks its DMA or queue-slot obligation",
            ));
        }
        let nonterminal_requests =
            if direct_cancel {
                Some(record.nonterminal_requests.checked_sub(1).ok_or(
                    IoError::InvariantViolation(
                        "registered cancellation underflowed nonterminal request count",
                    ),
                )?)
            } else {
                None
            };
        let revocation = record
            .revocation
            .as_ref()
            .ok_or(IoError::InvariantViolation(
                "closing scope lacks revocation",
            ))?;
        let cancel_steps = revocation
            .cancel_steps
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let cancel_index_visits = revocation
            .cancel_index_visits
            .checked_add(1)
            .ok_or(IoError::CounterOverflow)?;
        let request_dma = request.dma;
        let request = self
            .requests
            .get_mut(&request_id)
            .ok_or(IoError::UnknownRequest(request_id))?;
        request.state = if direct_cancel {
            IoEffectState::Cancelled
        } else {
            IoEffectState::Cancelling
        };
        request.commit_disposition = CommitDisposition::Returned;
        request.terminalizations = u8::from(direct_cancel);
        request.queue_slot_owned = false;
        if direct_cancel {
            request.dma_state = DmaLeaseState::Released;
        }
        let scope_record = self
            .scopes
            .get_mut(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        scope_record.free_commit_charges = CommitCharges::new(free_commit);
        scope_record.held_commit_charges = CommitCharges::new(held_commit);
        scope_record.unpublished_obligations.remove(&request_id);
        scope_record.queue_slot_obligations.remove(&request_id);
        if let Some(free_lease) = free_lease {
            scope_record.free_lease_credits = free_lease;
            scope_record.live_obligations.remove(&request_id);
        }
        if let Some(nonterminal_requests) = nonterminal_requests {
            scope_record.nonterminal_requests = nonterminal_requests;
        }
        let revocation = scope_record
            .revocation
            .as_mut()
            .ok_or(IoError::InvariantViolation(
                "closing scope lacks revocation",
            ))?;
        revocation.cancel_steps = cancel_steps;
        revocation.cancel_index_visits = cancel_index_visits;
        if direct_cancel {
            self.release_dma(request_dma);
        }
        self.push_trace(IoAction::CancelUnpublished, scope, Some(request_id));
        Ok(Some(request_id))
    }

    /// Issues a whole-device reset after the publication gate closes.
    ///
    /// Reset may run in parallel with cancellation and invalidation of work
    /// that was never published. Its acknowledgement affects only requests
    /// that are still `Committed` at that linearization point.
    pub fn begin_reset(&mut self, scope: ScopeId) -> Result<ResetAttempt, IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        if record.state != ScopeState::Closing {
            return Err(IoError::InvalidScopeState {
                state: record.state,
            });
        }
        if record.reset != ResetRecord::Required {
            return Err(IoError::InvalidResetState {
                state: record.reset.view(),
            });
        }
        let attempt = record.next_attempt;
        let next_attempt = attempt.checked_add(1).ok_or(IoError::CounterOverflow)?;
        let token = ResetAttempt {
            scope,
            attempt,
            device_generation: record.device_generation,
        };
        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        record.next_attempt = next_attempt;
        record.reset = ResetRecord::InFlight {
            attempt,
            device_generation: token.device_generation,
        };
        self.push_trace(IoAction::BeginReset, scope, None);
        Ok(token)
    }

    /// Records reset timeout without releasing any DMA object or credit.
    pub fn reset_timeout(&mut self, attempt: ResetAttempt) -> Result<ResetTombstone, IoError> {
        let record = self
            .scopes
            .get(&attempt.scope)
            .ok_or(IoError::UnknownScope(attempt.scope))?;
        self.validate_reset_attempt(record, attempt)?;
        let retained = self.reset_retained_summary(attempt.scope)?;
        self.scopes
            .get_mut(&attempt.scope)
            .ok_or(IoError::UnknownScope(attempt.scope))?
            .reset = ResetRecord::TimedOut {
            attempt: attempt.attempt,
            device_generation: attempt.device_generation,
        };
        self.push_trace(IoAction::ResetTimeout, attempt.scope, None);
        Ok(ResetTombstone {
            scope: attempt.scope,
            failed_attempt: attempt.attempt,
            device_generation: attempt.device_generation,
            retained,
        })
    }

    /// Reissues reset by consuming a matching retained-ownership tombstone.
    pub fn retry_reset(
        &mut self,
        tombstone: ResetTombstone,
    ) -> Result<ResetAttempt, Box<ResetRetryError>> {
        match self.retry_reset_inner(&tombstone) {
            Ok(attempt) => Ok(attempt),
            Err(error) => Err(Box::new(ResetRetryError { error, tombstone })),
        }
    }

    /// Acknowledges whole-device reset and establishes quiescence.
    ///
    /// Every still-`Committed` request becomes
    /// `IndeterminateAfterReset`. Requests whose completion linearized first
    /// remain `Completed`. The device generation advances exactly once.
    pub fn reset_ack(&mut self, attempt: ResetAttempt) -> Result<usize, IoError> {
        let record = self
            .scopes
            .get(&attempt.scope)
            .ok_or(IoError::UnknownScope(attempt.scope))?;
        self.validate_reset_attempt(record, attempt)?;
        let new_generation = DeviceGeneration::new(
            record
                .device_generation
                .get()
                .checked_add(1)
                .ok_or(IoError::CounterOverflow)?,
        );
        let committed: Vec<_> = record
            .live_obligations
            .iter()
            .copied()
            .filter(|request| {
                self.requests
                    .get(request)
                    .is_some_and(|request| request.state == IoEffectState::Committed)
            })
            .collect();
        if committed.iter().any(|request| {
            self.requests
                .get(request)
                .is_none_or(|request| !request.queue_slot_owned)
                || !record.queue_slot_obligations.contains(request)
        }) {
            return Err(IoError::InvariantViolation(
                "committed reset target lacks a queue-slot obligation",
            ));
        }
        let nonterminal_requests = record
            .nonterminal_requests
            .checked_sub(committed.len())
            .ok_or(IoError::InvariantViolation(
                "reset terminalization underflowed nonterminal request count",
            ))?;
        let revocation = record
            .revocation
            .as_ref()
            .ok_or(IoError::InvariantViolation("reset lacks revocation"))?;
        let reset_index_visits = revocation
            .reset_index_visits
            .checked_add(record.live_obligations.len())
            .ok_or(IoError::CounterOverflow)?;
        for request in &committed {
            let record = self
                .requests
                .get_mut(request)
                .ok_or(IoError::UnknownRequest(*request))?;
            record.state = IoEffectState::IndeterminateAfterReset;
            record.queue_slot_owned = false;
            record.terminalizations = 1;
        }
        let scope = self
            .scopes
            .get_mut(&attempt.scope)
            .ok_or(IoError::UnknownScope(attempt.scope))?;
        scope.device_generation = new_generation;
        scope.device_quiesced = true;
        scope.reset = ResetRecord::Acknowledged;
        scope.nonterminal_requests = nonterminal_requests;
        for request in &committed {
            scope.queue_slot_obligations.remove(request);
        }
        let revocation = scope
            .revocation
            .as_mut()
            .ok_or(IoError::InvariantViolation("reset lacks revocation"))?;
        revocation.reset_index_visits = reset_index_visits;
        revocation.reset_terminalizations = committed.len();
        self.push_trace(IoAction::ResetAck, attempt.scope, None);
        Ok(committed.len())
    }

    /// Removes one safe queue/request mapping and issues synchronous invalidation.
    ///
    /// A `Cancelling` request was never published, and a `Completed` request
    /// has a device completion proving it is no longer accessed; either may be
    /// cleaned independently. An indeterminate request and the queue require
    /// reset acknowledgement first.
    pub fn begin_invalidate(
        &mut self,
        scope: ScopeId,
        target: InvalidateTarget,
    ) -> Result<InvalidateAttempt, IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        if record.state == ScopeState::Revoked {
            return Err(IoError::InvalidScopeState {
                state: record.state,
            });
        }
        match target {
            InvalidateTarget::Queue => {
                if !record.device_quiesced || record.reset != ResetRecord::Acknowledged {
                    return Err(IoError::DeviceNotQuiescent);
                }
                if !record.queue_slot_obligations.is_empty() {
                    return Err(IoError::QueueSlotsOutstanding {
                        remaining: record.queue_slot_obligations.len(),
                    });
                }
                if record.queue_lease.invalidation != InvalidationRecord::NotStarted {
                    return Err(IoError::InvalidInvalidationState {
                        state: record.queue_lease.invalidation.view(),
                    });
                }
                if record.queue_lease.state != DmaLeaseState::Mapped {
                    return Err(IoError::InvariantViolation(
                        "queue is not mapped at invalidation begin",
                    ));
                }
            }
            InvalidateTarget::Request(request) => {
                let request = self
                    .requests
                    .get(&request)
                    .ok_or(IoError::UnknownRequest(request))?;
                if request.token.scope != scope {
                    return Err(IoError::RequestIdentityMismatch);
                }
                if !matches!(
                    request.state,
                    IoEffectState::Cancelling
                        | IoEffectState::Completed
                        | IoEffectState::IndeterminateAfterReset
                ) {
                    return Err(IoError::InvalidRequestState {
                        state: request.state,
                    });
                }
                if request.state == IoEffectState::IndeterminateAfterReset
                    && (!record.device_quiesced || record.reset != ResetRecord::Acknowledged)
                {
                    return Err(IoError::DeviceNotQuiescent);
                }
                if request.invalidation != InvalidationRecord::NotStarted {
                    return Err(IoError::InvalidInvalidationState {
                        state: request.invalidation.view(),
                    });
                }
                if request.dma_state != DmaLeaseState::Mapped {
                    return Err(IoError::InvariantViolation(
                        "request is not mapped at invalidation begin",
                    ));
                }
            }
        }
        let attempt = record.next_attempt;
        let next_attempt = attempt.checked_add(1).ok_or(IoError::CounterOverflow)?;
        let token = InvalidateAttempt {
            scope,
            target,
            attempt,
            device_generation: record.device_generation,
        };
        let record = self
            .scopes
            .get_mut(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        record.next_attempt = next_attempt;
        let invalidation = InvalidationRecord::InFlight {
            attempt,
            device_generation: token.device_generation,
        };
        match target {
            InvalidateTarget::Queue => {
                record.queue_lease.state = DmaLeaseState::UnmappedAwaitingInvalidation;
                record.queue_lease.invalidation = invalidation;
            }
            InvalidateTarget::Request(request) => {
                let request = self
                    .requests
                    .get_mut(&request)
                    .ok_or(IoError::UnknownRequest(request))?;
                request.dma_state = DmaLeaseState::UnmappedAwaitingInvalidation;
                request.invalidation = invalidation;
            }
        }
        self.push_trace(
            IoAction::BeginInvalidate,
            scope,
            match target {
                InvalidateTarget::Queue => None,
                InvalidateTarget::Request(request) => Some(request),
            },
        );
        Ok(token)
    }

    /// Records invalidation timeout while retaining the target identity and credit.
    pub fn invalidate_timeout(
        &mut self,
        attempt: InvalidateAttempt,
    ) -> Result<InvalidateTombstone, IoError> {
        let record = self
            .scopes
            .get(&attempt.scope)
            .ok_or(IoError::UnknownScope(attempt.scope))?;
        self.validate_invalidate_attempt(record, attempt)?;
        let retained = self.target_retained_summary(attempt.scope, attempt.target)?;
        let timed_out = InvalidationRecord::TimedOut {
            attempt: attempt.attempt,
            device_generation: attempt.device_generation,
        };
        match attempt.target {
            InvalidateTarget::Queue => {
                self.scopes
                    .get_mut(&attempt.scope)
                    .ok_or(IoError::UnknownScope(attempt.scope))?
                    .queue_lease
                    .invalidation = timed_out;
            }
            InvalidateTarget::Request(request) => {
                self.requests
                    .get_mut(&request)
                    .ok_or(IoError::UnknownRequest(request))?
                    .invalidation = timed_out;
            }
        }
        self.push_trace(
            IoAction::InvalidateTimeout,
            attempt.scope,
            match attempt.target {
                InvalidateTarget::Queue => None,
                InvalidateTarget::Request(request) => Some(request),
            },
        );
        Ok(InvalidateTombstone {
            scope: attempt.scope,
            target: attempt.target,
            failed_attempt: attempt.attempt,
            device_generation: attempt.device_generation,
            retained,
        })
    }

    /// Reissues invalidation by consuming a retained-ownership tombstone.
    pub fn retry_invalidate(
        &mut self,
        tombstone: InvalidateTombstone,
    ) -> Result<InvalidateAttempt, Box<InvalidateRetryError>> {
        match self.retry_invalidate_inner(&tombstone) {
            Ok(attempt) => Ok(attempt),
            Err(error) => Err(Box::new(InvalidateRetryError { error, tombstone })),
        }
    }

    /// Accepts synchronous IOTLB completion and releases one DMA lease.
    pub fn invalidate_ack(&mut self, attempt: InvalidateAttempt) -> Result<(), IoError> {
        let record = self
            .scopes
            .get(&attempt.scope)
            .ok_or(IoError::UnknownScope(attempt.scope))?;
        self.validate_invalidate_attempt(record, attempt)?;
        let (dma, returned, terminalize_cancellation) = match attempt.target {
            InvalidateTarget::Queue => (record.queue_lease.dma, record.queue_lease.credits, false),
            InvalidateTarget::Request(request) => {
                let request = self
                    .requests
                    .get(&request)
                    .ok_or(IoError::UnknownRequest(request))?;
                (
                    request.dma,
                    request.grant.lease,
                    request.state == IoEffectState::Cancelling,
                )
            }
        };
        let free_after = record
            .free_lease_credits
            .checked_add(returned)
            .ok_or(IoError::CounterOverflow)?;
        let nonterminal_after =
            if terminalize_cancellation {
                Some(record.nonterminal_requests.checked_sub(1).ok_or(
                    IoError::InvariantViolation(
                        "cancel completion underflowed nonterminal request count",
                    ),
                )?)
            } else {
                None
            };
        let invalidated_request_leases = if matches!(attempt.target, InvalidateTarget::Request(_)) {
            record
                .revocation
                .as_ref()
                .map(|revocation| {
                    revocation
                        .invalidated_request_leases
                        .checked_add(1)
                        .ok_or(IoError::CounterOverflow)
                })
                .transpose()?
        } else {
            None
        };
        match attempt.target {
            InvalidateTarget::Queue => {
                let record = self
                    .scopes
                    .get_mut(&attempt.scope)
                    .ok_or(IoError::UnknownScope(attempt.scope))?;
                record.queue_lease.state = DmaLeaseState::Released;
                record.queue_lease.invalidation = InvalidationRecord::Acknowledged;
                record.free_lease_credits = free_after;
            }
            InvalidateTarget::Request(request_id) => {
                let request = self
                    .requests
                    .get_mut(&request_id)
                    .ok_or(IoError::UnknownRequest(request_id))?;
                request.dma_state = DmaLeaseState::Released;
                request.invalidation = InvalidationRecord::Acknowledged;
                if terminalize_cancellation {
                    request.state = IoEffectState::Cancelled;
                    request.terminalizations = 1;
                }
                let record = self
                    .scopes
                    .get_mut(&attempt.scope)
                    .ok_or(IoError::UnknownScope(attempt.scope))?;
                record.free_lease_credits = free_after;
                record.live_obligations.remove(&request_id);
                if let Some(nonterminal_after) = nonterminal_after {
                    record.nonterminal_requests = nonterminal_after;
                }
                if let (Some(revocation), Some(invalidated_request_leases)) =
                    (record.revocation.as_mut(), invalidated_request_leases)
                {
                    revocation.invalidated_request_leases = invalidated_request_leases;
                }
            }
        }
        self.release_dma(dma);
        self.push_trace(
            IoAction::InvalidateAck,
            attempt.scope,
            match attempt.target {
                InvalidateTarget::Queue => None,
                InvalidateTarget::Request(request) => Some(request),
            },
        );
        Ok(())
    }

    /// Publishes quiescent closure after reset and invalidation complete.
    pub fn revoke_complete(&mut self, scope: ScopeId) -> Result<(), IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        if record.state != ScopeState::Closing {
            return Err(IoError::InvalidScopeState {
                state: record.state,
            });
        }
        if !record.device_quiesced
            || record.reset != ResetRecord::Acknowledged
            || record.queue_lease.invalidation != InvalidationRecord::Acknowledged
            || !record.live_obligations.is_empty()
            || !record.unpublished_obligations.is_empty()
            || record.nonterminal_requests != 0
            || !record.queue_slot_obligations.is_empty()
            || record.queue_lease.state != DmaLeaseState::Released
            || record.held_commit_charges != CommitCharges::ZERO
            || record.free_lease_credits != record.initial_budget.leases
        {
            return Err(IoError::RevocationNotQuiescent);
        }
        let device = record.device;
        let queue = record.queue;
        self.scopes
            .get_mut(&scope)
            .ok_or(IoError::UnknownScope(scope))?
            .state = ScopeState::Revoked;
        self.device_owners.remove(&device);
        self.queue_owners.remove(&queue);
        self.push_trace(IoAction::RevokeComplete, scope, None);
        Ok(())
    }
}
