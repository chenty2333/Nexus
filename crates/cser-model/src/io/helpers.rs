use super::*;

impl IoModel {
    pub(super) fn validate_binding(
        &self,
        token: IoBindingToken,
    ) -> Result<&IoScopeRecord, IoError> {
        let scope = self
            .scopes
            .get(&token.scope)
            .ok_or(IoError::UnknownScope(token.scope))?;
        if token.authority_epoch != scope.authority_epoch {
            return Err(IoError::StaleAuthority {
                presented: token.authority_epoch,
                current: scope.authority_epoch,
            });
        }
        if scope.state != ScopeState::Active {
            return Err(IoError::InvalidScopeState { state: scope.state });
        }
        if token.binding_epoch != scope.binding_epoch {
            return Err(IoError::StaleBinding {
                presented: token.binding_epoch,
                current: scope.binding_epoch,
            });
        }
        let service = scope.service.ok_or(IoError::ServiceUnavailable)?;
        if token.service != service {
            return Err(IoError::WrongService);
        }
        Ok(scope)
    }

    pub(super) fn validate_request_token(
        &self,
        token: RequestToken,
    ) -> Result<&RequestRecord, IoError> {
        let request = self
            .requests
            .get(&token.request)
            .ok_or(IoError::UnknownRequest(token.request))?;
        if request.token != token {
            return Err(IoError::RequestIdentityMismatch);
        }
        Ok(request)
    }

    pub(super) fn validate_current_reply(
        &self,
        binding: IoBindingToken,
        token: RequestToken,
    ) -> Result<(), IoError> {
        let scope = self.validate_binding(binding)?;
        let request = self.validate_request_token(token)?;
        if token.scope != binding.scope
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
        if token.binding_epoch != scope.binding_epoch {
            return Err(IoError::RequestBindingFenced {
                request_binding: token.binding_epoch,
                current_binding: scope.binding_epoch,
            });
        }
        if token.device_generation != scope.device_generation {
            return Err(IoError::StaleDeviceGeneration {
                presented: token.device_generation,
                current: scope.device_generation,
            });
        }
        if request.token != token {
            return Err(IoError::RequestIdentityMismatch);
        }
        Ok(())
    }

    pub(super) fn validate_dma_available(&self, dma: DmaIdentity) -> Result<(), IoError> {
        if self.issued_dma_leases.contains(&dma.lease)
            || self.issued_mappings.contains(&dma.mapping)
            || self.active_iovas.contains(&dma.iova)
        {
            return Err(IoError::DmaIdentityInUse(dma));
        }
        Ok(())
    }

    pub(super) fn reserve_dma(&mut self, dma: DmaIdentity) {
        self.issued_dma_leases.insert(dma.lease);
        self.issued_mappings.insert(dma.mapping);
        self.active_dma_leases.insert(dma.lease);
        self.active_mappings.insert(dma.mapping);
        self.active_iovas.insert(dma.iova);
    }

    pub(super) fn release_dma(&mut self, dma: DmaIdentity) {
        self.active_dma_leases.remove(&dma.lease);
        self.active_mappings.remove(&dma.mapping);
        self.active_iovas.remove(&dma.iova);
    }

    pub(super) fn dma_identity_indexed(&self, dma: DmaIdentity) -> bool {
        self.active_dma_leases.contains(&dma.lease)
            && self.active_mappings.contains(&dma.mapping)
            && self.active_iovas.contains(&dma.iova)
    }

    pub(super) fn reset_retained_summary(
        &self,
        scope: ScopeId,
    ) -> Result<RetainedDmaSummary, IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        let mut credits = if record.queue_lease.state == DmaLeaseState::Released {
            LeaseCredits::ZERO
        } else {
            record.queue_lease.credits
        };
        let mut request_leases = 0usize;
        for request in &record.live_obligations {
            let request = self
                .requests
                .get(request)
                .ok_or(IoError::UnknownRequest(*request))?;
            if request.state == IoEffectState::Committed
                && request.dma_state != DmaLeaseState::Released
            {
                request_leases += 1;
                credits = credits
                    .checked_add(request.grant.lease)
                    .ok_or(IoError::CounterOverflow)?;
            }
        }
        Ok(RetainedDmaSummary {
            queue_lease: record.queue_lease.state != DmaLeaseState::Released,
            request_leases,
            lease_credits: credits,
            held_commit_charges: record.held_commit_charges,
        })
    }

    pub(super) fn target_retained_summary(
        &self,
        scope: ScopeId,
        target: InvalidateTarget,
    ) -> Result<RetainedDmaSummary, IoError> {
        let record = self
            .scopes
            .get(&scope)
            .ok_or(IoError::UnknownScope(scope))?;
        match target {
            InvalidateTarget::Queue => Ok(RetainedDmaSummary {
                queue_lease: record.queue_lease.state != DmaLeaseState::Released,
                request_leases: 0,
                lease_credits: if record.queue_lease.state == DmaLeaseState::Released {
                    LeaseCredits::ZERO
                } else {
                    record.queue_lease.credits
                },
                held_commit_charges: CommitCharges::ZERO,
            }),
            InvalidateTarget::Request(request) => {
                let request = self
                    .requests
                    .get(&request)
                    .ok_or(IoError::UnknownRequest(request))?;
                if request.token.scope != scope {
                    return Err(IoError::RequestIdentityMismatch);
                }
                Ok(RetainedDmaSummary {
                    queue_lease: false,
                    request_leases: usize::from(request.dma_state != DmaLeaseState::Released),
                    lease_credits: if request.dma_state == DmaLeaseState::Released {
                        LeaseCredits::ZERO
                    } else {
                        request.grant.lease
                    },
                    held_commit_charges: if request.commit_disposition == CommitDisposition::Held {
                        request.grant.commit_charge
                    } else {
                        CommitCharges::ZERO
                    },
                })
            }
        }
    }

    pub(super) fn validate_reset_attempt(
        &self,
        scope: &IoScopeRecord,
        attempt: ResetAttempt,
    ) -> Result<(), IoError> {
        if scope.state != ScopeState::Closing {
            return Err(IoError::InvalidScopeState { state: scope.state });
        }
        match scope.reset {
            ResetRecord::InFlight {
                attempt: expected,
                device_generation,
            } if expected == attempt.attempt
                && device_generation == attempt.device_generation
                && scope.device_generation == attempt.device_generation =>
            {
                Ok(())
            }
            ResetRecord::InFlight { .. } => Err(IoError::StaleResetAttempt),
            _ => Err(IoError::InvalidResetState {
                state: scope.reset.view(),
            }),
        }
    }

    pub(super) fn retry_reset_inner(
        &mut self,
        tombstone: &ResetTombstone,
    ) -> Result<ResetAttempt, IoError> {
        let record = self
            .scopes
            .get(&tombstone.scope)
            .ok_or(IoError::UnknownScope(tombstone.scope))?;
        if record.state != ScopeState::Closing {
            return Err(IoError::InvalidScopeState {
                state: record.state,
            });
        }
        match record.reset {
            ResetRecord::TimedOut {
                attempt,
                device_generation,
            } if attempt == tombstone.failed_attempt
                && device_generation == tombstone.device_generation
                && record.device_generation == tombstone.device_generation => {}
            ResetRecord::TimedOut { .. } => return Err(IoError::StaleResetAttempt),
            _ => {
                return Err(IoError::InvalidResetState {
                    state: record.reset.view(),
                });
            }
        }
        let attempt = record.next_attempt;
        let next_attempt = attempt.checked_add(1).ok_or(IoError::CounterOverflow)?;
        let token = ResetAttempt {
            scope: tombstone.scope,
            attempt,
            device_generation: record.device_generation,
        };
        let record = self
            .scopes
            .get_mut(&tombstone.scope)
            .ok_or(IoError::UnknownScope(tombstone.scope))?;
        record.next_attempt = next_attempt;
        record.reset = ResetRecord::InFlight {
            attempt,
            device_generation: token.device_generation,
        };
        self.push_trace(IoAction::RetryReset, tombstone.scope, None);
        Ok(token)
    }

    pub(super) fn validate_invalidate_attempt(
        &self,
        scope: &IoScopeRecord,
        attempt: InvalidateAttempt,
    ) -> Result<(), IoError> {
        if scope.state == ScopeState::Revoked {
            return Err(IoError::InvalidScopeState { state: scope.state });
        }
        let invalidation = match attempt.target {
            InvalidateTarget::Queue => scope.queue_lease.invalidation,
            InvalidateTarget::Request(request) => {
                let request = self
                    .requests
                    .get(&request)
                    .ok_or(IoError::UnknownRequest(request))?;
                if request.token.scope != attempt.scope {
                    return Err(IoError::RequestIdentityMismatch);
                }
                request.invalidation
            }
        };
        match invalidation {
            InvalidationRecord::InFlight {
                attempt: expected,
                device_generation,
            } if expected == attempt.attempt
                && device_generation == attempt.device_generation
                && (attempt.target != InvalidateTarget::Queue
                    || scope.device_generation == attempt.device_generation) =>
            {
                Ok(())
            }
            InvalidationRecord::InFlight { .. } => Err(IoError::StaleInvalidateAttempt),
            _ => Err(IoError::InvalidInvalidationState {
                state: invalidation.view(),
            }),
        }
    }

    pub(super) fn retry_invalidate_inner(
        &mut self,
        tombstone: &InvalidateTombstone,
    ) -> Result<InvalidateAttempt, IoError> {
        let record = self
            .scopes
            .get(&tombstone.scope)
            .ok_or(IoError::UnknownScope(tombstone.scope))?;
        if record.state == ScopeState::Revoked {
            return Err(IoError::InvalidScopeState {
                state: record.state,
            });
        }
        let invalidation = match tombstone.target {
            InvalidateTarget::Queue => record.queue_lease.invalidation,
            InvalidateTarget::Request(request) => {
                let request = self
                    .requests
                    .get(&request)
                    .ok_or(IoError::UnknownRequest(request))?;
                if request.token.scope != tombstone.scope {
                    return Err(IoError::RequestIdentityMismatch);
                }
                request.invalidation
            }
        };
        match invalidation {
            InvalidationRecord::TimedOut {
                attempt,
                device_generation,
            } if attempt == tombstone.failed_attempt
                && device_generation == tombstone.device_generation
                && (tombstone.target != InvalidateTarget::Queue
                    || record.device_generation == tombstone.device_generation) => {}
            InvalidationRecord::TimedOut { .. } => {
                return Err(IoError::StaleInvalidateAttempt);
            }
            _ => {
                return Err(IoError::InvalidInvalidationState {
                    state: invalidation.view(),
                });
            }
        }
        let attempt = record.next_attempt;
        let next_attempt = attempt.checked_add(1).ok_or(IoError::CounterOverflow)?;
        let token = InvalidateAttempt {
            scope: tombstone.scope,
            target: tombstone.target,
            attempt,
            device_generation: if tombstone.target == InvalidateTarget::Queue {
                record.device_generation
            } else {
                tombstone.device_generation
            },
        };
        let record = self
            .scopes
            .get_mut(&tombstone.scope)
            .ok_or(IoError::UnknownScope(tombstone.scope))?;
        record.next_attempt = next_attempt;
        let in_flight = InvalidationRecord::InFlight {
            attempt,
            device_generation: token.device_generation,
        };
        match tombstone.target {
            InvalidateTarget::Queue => record.queue_lease.invalidation = in_flight,
            InvalidateTarget::Request(request) => {
                self.requests
                    .get_mut(&request)
                    .ok_or(IoError::UnknownRequest(request))?
                    .invalidation = in_flight;
            }
        }
        self.push_trace(
            IoAction::RetryInvalidate,
            tombstone.scope,
            match tombstone.target {
                InvalidateTarget::Queue => None,
                InvalidateTarget::Request(request) => Some(request),
            },
        );
        Ok(token)
    }

    pub(super) fn dma_invalidation_pair_valid(
        state: DmaLeaseState,
        invalidation: InvalidationRecord,
        allow_reserved: bool,
    ) -> bool {
        matches!(
            (state, invalidation),
            (DmaLeaseState::Absent, InvalidationRecord::NotStarted) if allow_reserved
        ) || matches!(
            (state, invalidation),
            (DmaLeaseState::Mapped, InvalidationRecord::NotStarted)
                | (
                    DmaLeaseState::UnmappedAwaitingInvalidation,
                    InvalidationRecord::InFlight { .. } | InvalidationRecord::TimedOut { .. }
                )
                | (DmaLeaseState::Released, InvalidationRecord::Acknowledged)
                | (DmaLeaseState::Released, InvalidationRecord::NotStarted)
        )
    }

    pub(super) fn request_dma_state_valid(request: &RequestRecord) -> bool {
        match request.state {
            IoEffectState::Registered => request.dma_state == DmaLeaseState::Absent,
            IoEffectState::Prepared | IoEffectState::Committed => {
                request.dma_state == DmaLeaseState::Mapped
            }
            IoEffectState::Cancelling => matches!(
                request.dma_state,
                DmaLeaseState::Mapped | DmaLeaseState::UnmappedAwaitingInvalidation
            ),
            IoEffectState::Completed | IoEffectState::IndeterminateAfterReset => matches!(
                request.dma_state,
                DmaLeaseState::Mapped
                    | DmaLeaseState::UnmappedAwaitingInvalidation
                    | DmaLeaseState::Released
            ),
            IoEffectState::Cancelled => request.dma_state == DmaLeaseState::Released,
        }
    }

    pub(super) fn push_trace(
        &mut self,
        action: IoAction,
        scope: ScopeId,
        request: Option<RequestId>,
    ) {
        let Some(record) = self.scopes.get(&scope) else {
            return;
        };
        self.trace.push(IoTraceEvent {
            seq: self.trace.len(),
            action,
            scope,
            request,
            authority_epoch: record.authority_epoch,
            binding_epoch: record.binding_epoch,
            device_generation: record.device_generation,
        });
    }
}
