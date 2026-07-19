// SPDX-License-Identifier: MPL-2.0

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use super::{
    DeadlineAdoption, DeadlineClockBasis, DeadlineDescriptor, DeadlineExhaustedDisposition,
    DeadlineExpiryAuthority, DeadlineExpiryReceipt, DeadlineLease, DeadlinePhase,
    DeadlineQuarantineReleaseReceipt, DeadlineQuarantineTicket, DeadlineReconciliationOutcome,
    DeadlineReconciliationReceipt, DeadlineRecord, DeadlineRecoveryProjection,
    DeadlineRecoveryState, DeadlineSupervisorRetry, EnteredTaskLease, InfrastructureError,
    InfrastructureEventKind, InfrastructureKind, InfrastructureState, LinearResult, ParentStamp,
    RequestKey, ReverseIndexRecord, ReverseParent, ScopeInfrastructure, ScopeKey, TaskPhase,
    TaskWorkDescriptor, WorkloadContext, bearer_state, checked_add, checked_sub,
    context_from_stamp, linear_apply, mint_deadline_key, next_deadline_bearer_generation,
    preview_bearer_stamp, preview_nonce, preview_nonces, preview_revision, preview_task_child_add,
    preview_task_child_sub, preview_workload_child_add, preview_workload_child_sub,
    require_vacancy, validate_active_admission, validate_context, validate_deadline_key,
    validate_task_stamp,
};

enum PreparedDeadlineAdoption {
    Armed,
    Fired,
    Exhausted,
    Quarantined,
}

struct PreparedDeadlineFinish {
    series_id: u64,
    generation: u64,
    workload_request: RequestKey,
    parent_task: TaskWorkDescriptor,
    bearer_generation: u64,
    next_revision: u64,
    next_live: u32,
    next_workload_children: u32,
    next_task_children: u32,
    terminal: DeadlinePhase,
}

impl InfrastructureState {
    pub(in super::super) fn arm_deadline(
        &mut self,
        task: &EnteredTaskLease,
        descriptor: DeadlineDescriptor,
    ) -> Result<DeadlineLease, InfrastructureError> {
        self.require_authoritative()?;
        descriptor.validate()?;
        if descriptor.attempt != 1 {
            return Err(InfrastructureError::InvalidIdentity);
        }
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(task.0.root.scope)?;
        validate_task_stamp(scope, registry_instance, &task.0)?;
        validate_active_admission(scope)?;
        if scope.tasks.get(task.0.identity.work_id).unwrap().phase != TaskPhase::Entered {
            return Err(InfrastructureError::InvalidState);
        }
        if let Some(existing) = scope.deadlines.get(descriptor.series_id) {
            return if existing.stamp.identity == descriptor
                && existing.stamp.parent == ParentStamp::Task(task.0.identity)
            {
                Err(InfrastructureError::ExactReplay)
            } else if existing.stamp.identity.generation > descriptor.generation {
                Err(InfrastructureError::StaleGeneration)
            } else {
                Err(InfrastructureError::IdentityConflict)
            };
        }
        require_vacancy(
            &scope.deadlines,
            descriptor.series_id,
            InfrastructureKind::Deadline,
        )?;
        let context = context_from_stamp(scope, task.0.workload)?;
        let (stamp, next_nonce) = preview_bearer_stamp(
            scope,
            &context,
            descriptor,
            ParentStamp::Task(task.0.identity),
        )?;
        require_vacancy(
            &scope.reverse_indexes,
            stamp.nonce,
            InfrastructureKind::Deadline,
        )?;
        let next_revision = preview_revision(scope)?;
        let next_live = checked_add(scope.live.deadlines, 1)?;
        let next_workload_children = preview_workload_child_add(scope, stamp.workload.request)?;
        let next_task_children = preview_task_child_add(scope, task.0.identity)?;
        let index = ReverseIndexRecord {
            slot: stamp.nonce,
            kind: InfrastructureKind::Deadline,
            root_effect: stamp.root.root_effect,
            parent: ReverseParent::Task(task.0.identity),
            task: Some(task.0.identity.task),
            domain: stamp.domain.domain,
            binding_epoch: stamp.domain.binding_epoch,
            source_domain: None,
            source_binding_epoch: None,
            resource: None,
            actor_slot: None,
            retry_generation: descriptor.generation,
        };
        let record = DeadlineRecord {
            stamp,
            series_nonce: stamp.nonce,
            quarantine_generation: 0,
            last_reconciliation: None,
            terminal_evidence_digest: None,
            phase: DeadlinePhase::Armed,
            closure_sequence: None,
        };

        // Both vacancies and every counter successor were prepared above.
        // FixedSlots::install therefore cannot fail in this exclusive apply.
        scope
            .deadlines
            .install(record, InfrastructureKind::Deadline)
            .unwrap();
        scope
            .reverse_indexes
            .install(index, InfrastructureKind::Deadline)
            .unwrap();
        scope.next_nonce = next_nonce;
        scope.revision = next_revision;
        scope.live.deadlines = next_live;
        scope
            .workloads
            .get_mut(stamp.workload.request.id)
            .unwrap()
            .live_children = next_workload_children;
        scope
            .tasks
            .get_mut(task.0.identity.work_id)
            .unwrap()
            .live_children = next_task_children;
        scope.events.push(
            InfrastructureEventKind::DeadlineArmed,
            descriptor.series_id,
            descriptor.generation,
        );
        Ok(DeadlineLease(mint_deadline_key::<
            bearer_state::DeadlineArmed,
        >(
            scope.deadlines.get(descriptor.series_id).unwrap(),
        )))
    }

    pub(in super::super) fn fire_deadline(
        &mut self,
        lease: DeadlineLease,
        clock: DeadlineClockBasis,
        observed_tick: u64,
    ) -> LinearResult<DeadlineLease, DeadlineExpiryReceipt> {
        linear_apply(lease, |lease| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(lease.0.authority.scope)?;
            let record = validate_deadline_key(scope, registry_instance, &lease.0)?;
            if record.phase != DeadlinePhase::Armed {
                return Err(InfrastructureError::ExactReplay);
            }
            let descriptor = record.stamp.identity;
            if descriptor.clock != clock || observed_tick < descriptor.deadline_tick {
                return Err(InfrastructureError::InvalidState);
            }
            let exhausted = descriptor.attempt == descriptor.max_attempts;
            let bearer_generation = next_deadline_bearer_generation(record)?;
            let (expiry_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;

            let record = scope.deadlines.get_mut(descriptor.series_id).unwrap();
            record.stamp.nonce = expiry_nonce;
            record.stamp.bearer_generation = bearer_generation;
            record.phase = if exhausted {
                DeadlinePhase::ExhaustedRetained {
                    expiry_nonce,
                    observed_tick,
                }
            } else {
                DeadlinePhase::Fired {
                    expiry_nonce,
                    observed_tick,
                }
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::DeadlineFired,
                descriptor.series_id,
                descriptor.generation,
            );
            let record = scope.deadlines.get(descriptor.series_id).unwrap();
            Ok(if exhausted {
                mint_exhausted_deadline(record)
            } else {
                mint_fired_deadline(record)
            })
        })
    }

    pub(in super::super) fn rearm_deadline(
        &mut self,
        expiry: DeadlineExpiryReceipt,
        next_generation: u64,
        next_deadline_tick: u64,
    ) -> LinearResult<DeadlineExpiryReceipt, DeadlineLease> {
        linear_apply(expiry, |expiry| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(deadline_expiry_scope(expiry))?;
            let (record, exhausted) = validate_deadline_expiry(scope, registry_instance, expiry)?;
            if exhausted {
                return Err(InfrastructureError::ClosureRetained);
            }
            let observed_tick = match record.phase {
                DeadlinePhase::Fired {
                    expiry_nonce,
                    observed_tick,
                } if record.stamp.nonce == expiry_nonce => observed_tick,
                _ => return Err(InfrastructureError::StaleClaim),
            };
            let descriptor = record.stamp.identity;
            if next_generation
                != descriptor
                    .generation
                    .checked_add(1)
                    .ok_or(InfrastructureError::CounterOverflow)?
            {
                return Err(InfrastructureError::StaleGeneration);
            }
            let minimum_tick = observed_tick
                .checked_add(descriptor.backoff_ticks)
                .ok_or(InfrastructureError::CounterOverflow)?;
            if next_deadline_tick < minimum_tick {
                return Err(InfrastructureError::InvalidIdentity);
            }
            let next_attempt = descriptor
                .attempt
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            if next_attempt > descriptor.max_attempts {
                return Err(InfrastructureError::ClosureRetained);
            }
            let bearer_generation = next_deadline_bearer_generation(record)?;
            let (nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let descriptor = DeadlineDescriptor {
                generation: next_generation,
                deadline_tick: next_deadline_tick,
                attempt: next_attempt,
                ..descriptor
            };
            let series_nonce = record.series_nonce;

            let record = scope.deadlines.get_mut(descriptor.series_id).unwrap();
            record.stamp.identity = descriptor;
            record.stamp.nonce = nonce;
            record.stamp.bearer_generation = bearer_generation;
            record.phase = DeadlinePhase::Armed;
            let index = scope.reverse_indexes.get_mut(series_nonce).unwrap();
            index.retry_generation = next_generation;
            index.binding_epoch = record.stamp.domain.binding_epoch;
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::DeadlineRearmed,
                descriptor.series_id,
                descriptor.generation,
            );
            Ok(DeadlineLease(mint_deadline_key::<
                bearer_state::DeadlineArmed,
            >(
                scope.deadlines.get(descriptor.series_id).unwrap(),
            )))
        })
    }

    pub(in super::super) fn cancel_deadline(
        &mut self,
        lease: DeadlineLease,
    ) -> LinearResult<DeadlineLease, ()> {
        linear_apply(lease, |lease| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(lease.0.authority.scope)?;
            let record = validate_deadline_key(scope, registry_instance, &lease.0)?;
            if record.phase != DeadlinePhase::Armed {
                return Err(InfrastructureError::InvalidState);
            }
            let finish = prepare_deadline_finish(scope, record, DeadlinePhase::Cancelled)?;
            apply_deadline_finish(scope, finish);
            Ok(())
        })
    }

    pub(in super::super) fn resolve_fired_deadline(
        &mut self,
        expiry: DeadlineExpiryReceipt,
    ) -> LinearResult<DeadlineExpiryReceipt, ()> {
        linear_apply(expiry, |expiry| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(deadline_expiry_scope(expiry))?;
            let (record, exhausted) = validate_deadline_expiry(scope, registry_instance, expiry)?;
            if exhausted {
                return Err(InfrastructureError::ClosureRetained);
            }
            if !__cser_core::matches!(
                record.phase,
                DeadlinePhase::Fired {
                    expiry_nonce,
                    ..
                } if expiry_nonce == record.stamp.nonce
            ) {
                return Err(InfrastructureError::StaleClaim);
            }
            let finish = prepare_deadline_finish(
                scope,
                record,
                DeadlinePhase::Resolved {
                    reconciliation: None,
                    terminal_evidence_digest: None,
                },
            )?;
            apply_deadline_finish(scope, finish);
            Ok(())
        })
    }

    pub(in super::super) fn reconcile_exhausted_deadline(
        &mut self,
        expiry: DeadlineExpiryReceipt,
        receipt: DeadlineReconciliationReceipt,
        supervisor_retry: Option<DeadlineSupervisorRetry>,
    ) -> LinearResult<DeadlineExpiryReceipt, DeadlineReconciliationOutcome> {
        linear_apply(expiry, |expiry| {
            self.require_authoritative()?;
            if !deadline_expiry_is_exhausted(expiry) || receipt.evidence_digest == 0 {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(deadline_expiry_scope(expiry))?;
            let (record, exhausted) = validate_deadline_expiry(scope, registry_instance, expiry)?;
            if !exhausted {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let observed_tick = match record.phase {
                DeadlinePhase::ExhaustedRetained {
                    expiry_nonce,
                    observed_tick,
                } if record.stamp.nonce == expiry_nonce => observed_tick,
                _ => return Err(InfrastructureError::StaleClaim),
            };
            let descriptor = record.stamp.identity;
            match receipt.disposition {
                DeadlineExhaustedDisposition::AbortWork => {
                    if supervisor_retry.is_some() {
                        return Err(InfrastructureError::InvalidReceipt);
                    }
                    let finish = prepare_deadline_finish(
                        scope,
                        record,
                        DeadlinePhase::Resolved {
                            reconciliation: Some(receipt),
                            terminal_evidence_digest: Some(receipt.evidence_digest),
                        },
                    )?;
                    apply_deadline_finish(scope, finish);
                    Ok(DeadlineReconciliationOutcome::Aborted)
                }
                DeadlineExhaustedDisposition::RetryBySupervisor => {
                    let retry = supervisor_retry.ok_or(InfrastructureError::InvalidReceipt)?;
                    let minimum_tick = observed_tick
                        .checked_add(retry.backoff_ticks)
                        .ok_or(InfrastructureError::CounterOverflow)?;
                    if retry.generation
                        != descriptor
                            .generation
                            .checked_add(1)
                            .ok_or(InfrastructureError::CounterOverflow)?
                        || retry.deadline_tick < minimum_tick
                        || retry.max_attempts == 0
                        || retry.backoff_ticks == 0
                    {
                        return Err(InfrastructureError::InvalidReceipt);
                    }
                    let bearer_generation = next_deadline_bearer_generation(record)?;
                    let (nonce, next_nonce) = preview_nonce(scope)?;
                    let next_revision = preview_revision(scope)?;
                    let series_nonce = record.series_nonce;
                    let mut next_descriptor = descriptor;
                    next_descriptor.generation = retry.generation;
                    next_descriptor.deadline_tick = retry.deadline_tick;
                    next_descriptor.attempt = 1;
                    next_descriptor.max_attempts = retry.max_attempts;
                    next_descriptor.backoff_ticks = retry.backoff_ticks;

                    let record = scope.deadlines.get_mut(descriptor.series_id).unwrap();
                    record.stamp.identity = next_descriptor;
                    record.stamp.nonce = nonce;
                    record.stamp.bearer_generation = bearer_generation;
                    record.phase = DeadlinePhase::Armed;
                    record.last_reconciliation = Some(receipt);
                    record.terminal_evidence_digest = None;
                    let index = scope.reverse_indexes.get_mut(series_nonce).unwrap();
                    index.retry_generation = retry.generation;
                    index.binding_epoch = record.stamp.domain.binding_epoch;
                    scope.next_nonce = next_nonce;
                    scope.revision = next_revision;
                    scope.events.push(
                        InfrastructureEventKind::DeadlineRearmed,
                        next_descriptor.series_id,
                        next_descriptor.generation,
                    );
                    Ok(DeadlineReconciliationOutcome::Retried(DeadlineLease(
                        mint_deadline_key::<bearer_state::DeadlineArmed>(
                            scope.deadlines.get(next_descriptor.series_id).unwrap(),
                        ),
                    )))
                }
                DeadlineExhaustedDisposition::Quarantine => {
                    if supervisor_retry.is_some() {
                        return Err(InfrastructureError::InvalidReceipt);
                    }
                    let quarantine_generation = record
                        .quarantine_generation
                        .checked_add(1)
                        .ok_or(InfrastructureError::CounterOverflow)?;
                    let bearer_generation = next_deadline_bearer_generation(record)?;
                    let (quarantine_nonce, next_nonce) = preview_nonce(scope)?;
                    let next_revision = preview_revision(scope)?;

                    let record = scope.deadlines.get_mut(descriptor.series_id).unwrap();
                    record.stamp.nonce = quarantine_nonce;
                    record.stamp.bearer_generation = bearer_generation;
                    record.quarantine_generation = quarantine_generation;
                    record.last_reconciliation = Some(receipt);
                    record.terminal_evidence_digest = None;
                    record.phase = DeadlinePhase::QuarantinedRetained {
                        observed_tick,
                        receipt,
                        quarantine_generation,
                        quarantine_nonce,
                    };
                    scope.next_nonce = next_nonce;
                    scope.revision = next_revision;
                    Ok(DeadlineReconciliationOutcome::Quarantined(
                        DeadlineQuarantineTicket(mint_deadline_key::<
                            bearer_state::DeadlineQuarantined,
                        >(
                            scope.deadlines.get(descriptor.series_id).unwrap(),
                        )),
                    ))
                }
            }
        })
    }

    pub(in super::super) fn resolve_quarantined_deadline(
        &mut self,
        ticket: DeadlineQuarantineTicket,
        receipt: DeadlineQuarantineReleaseReceipt,
    ) -> LinearResult<DeadlineQuarantineTicket, ()> {
        linear_apply(ticket, |ticket| {
            self.require_authoritative()?;
            if receipt.evidence_digest == 0 {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(ticket.0.authority.scope)?;
            let record = validate_deadline_key(scope, registry_instance, &ticket.0)?;
            let reconciliation = match record.phase {
                DeadlinePhase::QuarantinedRetained {
                    receipt,
                    quarantine_generation,
                    quarantine_nonce,
                    ..
                } if quarantine_generation == record.quarantine_generation
                    && quarantine_nonce == record.stamp.nonce =>
                {
                    receipt
                }
                _ => return Err(InfrastructureError::StaleClaim),
            };
            let finish = prepare_deadline_finish(
                scope,
                record,
                DeadlinePhase::Resolved {
                    reconciliation: Some(reconciliation),
                    terminal_evidence_digest: Some(receipt.evidence_digest),
                },
            )?;
            apply_deadline_finish(scope, finish);
            Ok(())
        })
    }

    pub(in super::super) fn query_deadline(
        &self,
        context: &WorkloadContext,
        series_id: u64,
        generation: u64,
    ) -> Result<DeadlineRecoveryProjection, InfrastructureError> {
        self.require_authoritative()?;
        let scope = self.scope(context.root.scope)?;
        validate_context(scope, self.registry_instance, context)?;
        let record = scope
            .deadlines
            .get(series_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
        if record.stamp.identity.generation != generation {
            return Err(InfrastructureError::StaleGeneration);
        }
        if record.stamp.workload.request != context.workload.request {
            return Err(InfrastructureError::ForeignWorkload);
        }
        let parent_task = match record.stamp.parent {
            ParentStamp::Task(parent) => parent,
            _ => return Err(InfrastructureError::ForeignParent),
        };
        Ok(DeadlineRecoveryProjection {
            descriptor: record.stamp.identity,
            parent_task,
            state: match record.phase {
                DeadlinePhase::Armed => DeadlineRecoveryState::Armed,
                DeadlinePhase::Fired { .. } => DeadlineRecoveryState::Fired,
                DeadlinePhase::ExhaustedRetained { .. } => DeadlineRecoveryState::ExhaustedRetained,
                DeadlinePhase::QuarantinedRetained { .. } => {
                    DeadlineRecoveryState::QuarantinedRetained
                }
                DeadlinePhase::Cancelled => DeadlineRecoveryState::Cancelled,
                DeadlinePhase::Resolved { .. } => DeadlineRecoveryState::Resolved,
            },
            observed_tick: match record.phase {
                DeadlinePhase::Fired { observed_tick, .. }
                | DeadlinePhase::ExhaustedRetained { observed_tick, .. }
                | DeadlinePhase::QuarantinedRetained { observed_tick, .. } => Some(observed_tick),
                _ => None,
            },
            reconciliation: record.last_reconciliation,
            terminal_evidence_digest: record.terminal_evidence_digest,
        })
    }

    pub(in super::super) fn adopt_deadline_after_fence(
        &mut self,
        context: &WorkloadContext,
        series_id: u64,
        generation: u64,
    ) -> Result<DeadlineAdoption, InfrastructureError> {
        self.require_authoritative()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(context.root.scope)?;
        validate_context(scope, registry_instance, context)?;
        let record = scope
            .deadlines
            .get(series_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
        if record.stamp.identity.generation != generation {
            return Err(InfrastructureError::StaleGeneration);
        }
        if record.stamp.root.registry_instance != registry_instance
            || record.stamp.root.scope != context.root.scope
            || record.stamp.root.root_effect != context.root.root_effect
            || record.stamp.root.authority_epoch != context.root.authority_epoch
        {
            return Err(InfrastructureError::StaleAuthority);
        }
        let parent_task = match record.stamp.parent {
            ParentStamp::Task(parent) => parent,
            _ => return Err(InfrastructureError::ForeignParent),
        };
        let task = scope
            .tasks
            .get(parent_task.work_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
        validate_task_stamp(scope, registry_instance, &task.stamp)?;
        if task.phase != TaskPhase::Entered
            || task.stamp.root != context.root
            || task.stamp.domain != context.domain
            || task.stamp.workload != context.workload
            || task.stamp.parent != ParentStamp::Request(context.workload.request)
            || task.stamp.identity != parent_task
        {
            return Err(InfrastructureError::ForeignParent);
        }
        if record.stamp.workload.request != context.workload.request
            || record.stamp.domain.domain != context.domain.domain
            || record.stamp.domain.binding_epoch >= context.domain.binding_epoch
        {
            return Err(InfrastructureError::StaleBinding);
        }
        let previous_phase = record.phase;
        if __cser_core::matches!(
            previous_phase,
            DeadlinePhase::Cancelled | DeadlinePhase::Resolved { .. }
        ) {
            return Err(InfrastructureError::InvalidState);
        }
        validate_deadline_reverse_index(scope, record)?;
        let bearer_generation = next_deadline_bearer_generation(record)?;
        let nonce_count = usize::from(!__cser_core::matches!(previous_phase, DeadlinePhase::Armed));
        let (nonces, next_nonce) = preview_nonces(scope, nonce_count)?;
        let next_revision = preview_revision(scope)?;
        let index_slot = record.series_nonce;
        let mut stamp = record.stamp;
        stamp.domain = context.domain;
        stamp.workload = context.workload;
        stamp.bearer_generation = bearer_generation;

        let (next_phase, prepared) = match previous_phase {
            DeadlinePhase::Armed => (DeadlinePhase::Armed, PreparedDeadlineAdoption::Armed),
            DeadlinePhase::Fired { observed_tick, .. } => {
                let expiry_nonce = nonces[0];
                stamp.nonce = expiry_nonce;
                (
                    DeadlinePhase::Fired {
                        expiry_nonce,
                        observed_tick,
                    },
                    PreparedDeadlineAdoption::Fired,
                )
            }
            DeadlinePhase::ExhaustedRetained { observed_tick, .. } => {
                let expiry_nonce = nonces[0];
                stamp.nonce = expiry_nonce;
                (
                    DeadlinePhase::ExhaustedRetained {
                        expiry_nonce,
                        observed_tick,
                    },
                    PreparedDeadlineAdoption::Exhausted,
                )
            }
            DeadlinePhase::QuarantinedRetained {
                observed_tick,
                receipt,
                quarantine_generation,
                ..
            } => {
                let quarantine_generation = quarantine_generation
                    .checked_add(1)
                    .ok_or(InfrastructureError::CounterOverflow)?;
                let quarantine_nonce = nonces[0];
                stamp.nonce = quarantine_nonce;
                (
                    DeadlinePhase::QuarantinedRetained {
                        observed_tick,
                        receipt,
                        quarantine_generation,
                        quarantine_nonce,
                    },
                    PreparedDeadlineAdoption::Quarantined,
                )
            }
            DeadlinePhase::Cancelled | DeadlinePhase::Resolved { .. } => {
                return Err(InfrastructureError::InvalidState);
            }
        };

        let record = scope.deadlines.get_mut(series_id).unwrap();
        record.stamp = stamp;
        record.phase = next_phase;
        if let DeadlinePhase::QuarantinedRetained {
            quarantine_generation,
            ..
        } = next_phase
        {
            record.quarantine_generation = quarantine_generation;
        }
        // The exact row was checked before the first mutation. This apply is
        // allocation-free and cannot return an error.
        scope
            .reverse_indexes
            .get_mut(index_slot)
            .unwrap()
            .binding_epoch = context.domain.binding_epoch;
        scope.next_nonce = next_nonce;
        scope.revision = next_revision;

        let record = scope.deadlines.get(series_id).unwrap();
        Ok(match prepared {
            PreparedDeadlineAdoption::Armed => {
                DeadlineAdoption::Armed(DeadlineLease(mint_deadline_key::<
                    bearer_state::DeadlineArmed,
                >(record)))
            }
            PreparedDeadlineAdoption::Fired => DeadlineAdoption::Fired(mint_fired_deadline(record)),
            PreparedDeadlineAdoption::Exhausted => {
                DeadlineAdoption::Exhausted(mint_exhausted_deadline(record))
            }
            PreparedDeadlineAdoption::Quarantined => {
                DeadlineAdoption::Quarantined(DeadlineQuarantineTicket(mint_deadline_key::<
                    bearer_state::DeadlineQuarantined,
                >(record)))
            }
        })
    }
}

fn deadline_expiry_scope(expiry: &DeadlineExpiryReceipt) -> ScopeKey {
    match &expiry.0 {
        DeadlineExpiryAuthority::Fired(key) => key.authority.scope,
        DeadlineExpiryAuthority::Exhausted(key) => key.authority.scope,
    }
}

fn deadline_expiry_is_exhausted(expiry: &DeadlineExpiryReceipt) -> bool {
    __cser_core::matches!(expiry.0, DeadlineExpiryAuthority::Exhausted(_))
}

fn validate_deadline_expiry<'a>(
    scope: &'a ScopeInfrastructure,
    registry_instance: u64,
    expiry: &DeadlineExpiryReceipt,
) -> Result<(&'a DeadlineRecord, bool), InfrastructureError> {
    match &expiry.0 {
        DeadlineExpiryAuthority::Fired(key) => {
            let record = validate_deadline_key(scope, registry_instance, key)?;
            if !__cser_core::matches!(
                record.phase,
                DeadlinePhase::Fired { expiry_nonce, .. }
                    if expiry_nonce == record.stamp.nonce
            ) {
                return Err(InfrastructureError::StaleClaim);
            }
            Ok((record, false))
        }
        DeadlineExpiryAuthority::Exhausted(key) => {
            let record = validate_deadline_key(scope, registry_instance, key)?;
            if !__cser_core::matches!(
                record.phase,
                DeadlinePhase::ExhaustedRetained { expiry_nonce, .. }
                    if expiry_nonce == record.stamp.nonce
            ) {
                return Err(InfrastructureError::StaleClaim);
            }
            Ok((record, true))
        }
    }
}

fn mint_fired_deadline(record: &DeadlineRecord) -> DeadlineExpiryReceipt {
    DeadlineExpiryReceipt(DeadlineExpiryAuthority::Fired(mint_deadline_key::<
        bearer_state::DeadlineFired,
    >(record)))
}

fn mint_exhausted_deadline(record: &DeadlineRecord) -> DeadlineExpiryReceipt {
    DeadlineExpiryReceipt(DeadlineExpiryAuthority::Exhausted(mint_deadline_key::<
        bearer_state::DeadlineExhausted,
    >(record)))
}

fn validate_deadline_reverse_index(
    scope: &ScopeInfrastructure,
    record: &DeadlineRecord,
) -> Result<(), InfrastructureError> {
    let stamp = record.stamp;
    let parent = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    let index =
        scope
            .reverse_indexes
            .get(record.series_nonce)
            .ok_or(InfrastructureError::Invariant(
                "missing deadline reverse index",
            ))?;
    if index.slot != record.series_nonce
        || index.kind != InfrastructureKind::Deadline
        || index.root_effect != stamp.root.root_effect
        || index.parent != ReverseParent::Task(parent)
        || index.task != Some(parent.task)
        || index.domain != stamp.domain.domain
        || index.binding_epoch != stamp.domain.binding_epoch
        || index.source_domain.is_some()
        || index.source_binding_epoch.is_some()
        || index.resource.is_some()
        || index.actor_slot.is_some()
        || index.retry_generation != stamp.identity.generation
    {
        return Err(InfrastructureError::Invariant(
            "deadline reverse index mismatch",
        ));
    }
    Ok(())
}

fn prepare_deadline_finish(
    scope: &ScopeInfrastructure,
    record: &DeadlineRecord,
    terminal: DeadlinePhase,
) -> Result<PreparedDeadlineFinish, InfrastructureError> {
    let stamp = record.stamp;
    let parent_task = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    Ok(PreparedDeadlineFinish {
        series_id: stamp.identity.series_id,
        generation: stamp.identity.generation,
        workload_request: stamp.workload.request,
        parent_task,
        bearer_generation: next_deadline_bearer_generation(record)?,
        next_revision: preview_revision(scope)?,
        next_live: checked_sub(scope.live.deadlines, 1)?,
        next_workload_children: preview_workload_child_sub(scope, stamp.workload.request)?,
        next_task_children: preview_task_child_sub(scope, parent_task)?,
        terminal,
    })
}

fn apply_deadline_finish(scope: &mut ScopeInfrastructure, finish: PreparedDeadlineFinish) {
    let record = scope.deadlines.get_mut(finish.series_id).unwrap();
    record.stamp.bearer_generation = finish.bearer_generation;
    record.phase = finish.terminal;
    if let DeadlinePhase::Resolved {
        reconciliation,
        terminal_evidence_digest,
    } = finish.terminal
    {
        record.last_reconciliation = reconciliation;
        record.terminal_evidence_digest = terminal_evidence_digest;
    }
    scope.revision = finish.next_revision;
    scope.live.deadlines = finish.next_live;
    scope
        .workloads
        .get_mut(finish.workload_request.id)
        .unwrap()
        .live_children = finish.next_workload_children;
    scope
        .tasks
        .get_mut(finish.parent_task.work_id)
        .unwrap()
        .live_children = finish.next_task_children;
    scope.events.push(
        if __cser_core::matches!(finish.terminal, DeadlinePhase::Cancelled) {
            InfrastructureEventKind::DeadlineCancelled
        } else {
            InfrastructureEventKind::DeadlineResolved
        },
        finish.series_id,
        finish.generation,
    );
}
