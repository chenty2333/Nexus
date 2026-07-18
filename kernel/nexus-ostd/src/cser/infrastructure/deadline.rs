// SPDX-License-Identifier: MPL-2.0

use super::{
    BearerStamp, DeadlineAdoption, DeadlineClockBasis, DeadlineDescriptor,
    DeadlineExhaustedDisposition, DeadlineExpiryReceipt, DeadlineLease, DeadlinePhase,
    DeadlineQuarantineReleaseReceipt, DeadlineQuarantineTicket, DeadlineReconciliationOutcome,
    DeadlineReconciliationReceipt, DeadlineRecord, DeadlineRecoveryProjection,
    DeadlineRecoveryState, DeadlineSupervisorRetry, EnteredTaskLease, InfrastructureError,
    InfrastructureEventKind, InfrastructureKind, InfrastructureState, LinearResult, ParentStamp,
    ReverseIndexRecord, ReverseParent, ScopeInfrastructure, TaskPhase, WorkloadContext,
    checked_add, checked_sub, context_from_stamp, linear_apply, preview_bearer_stamp,
    preview_nonce, preview_nonces, preview_revision, preview_task_child_add,
    preview_task_child_sub, preview_workload_child_add, preview_workload_child_sub,
    require_vacancy, validate_active_admission, validate_context, validate_deadline_bearer,
    validate_task_stamp,
};

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
        scope.deadlines.install(
            DeadlineRecord {
                stamp,
                series_nonce: stamp.nonce,
                quarantine_generation: 0,
                last_reconciliation: None,
                terminal_evidence_digest: None,
                phase: DeadlinePhase::Armed,
                closure_sequence: None,
            },
            InfrastructureKind::Deadline,
        )?;
        scope
            .reverse_indexes
            .install(index, InfrastructureKind::Deadline)?;
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
        Ok(DeadlineLease(
            scope.deadlines.get(descriptor.series_id).unwrap().stamp,
        ))
    }

    pub(in super::super) fn fire_deadline(
        &mut self,
        lease: DeadlineLease,
        clock: DeadlineClockBasis,
        observed_tick: u64,
    ) -> LinearResult<DeadlineLease, DeadlineExpiryReceipt> {
        linear_apply(lease, |lease| {
            self.require_authoritative()?;
            let stamp = lease.0;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_deadline_bearer(scope, registry_instance, &stamp)?;
            let record = scope.deadlines.get(stamp.identity.series_id).unwrap();
            if record.phase != DeadlinePhase::Armed {
                return Err(InfrastructureError::ExactReplay);
            }
            if stamp.identity.clock != clock || observed_tick < stamp.identity.deadline_tick {
                return Err(InfrastructureError::InvalidState);
            }
            let (expiry_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let exhausted = stamp.identity.attempt == stamp.identity.max_attempts;
            scope
                .deadlines
                .get_mut(stamp.identity.series_id)
                .unwrap()
                .phase = if exhausted {
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
                stamp.identity.series_id,
                stamp.identity.generation,
            );
            Ok(DeadlineExpiryReceipt {
                deadline: stamp,
                observed_tick,
                expiry_nonce,
                exhausted,
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
            let old = expiry.deadline;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(old.root.scope)?;
            validate_deadline_bearer(scope, registry_instance, &old)?;
            if expiry.exhausted {
                return Err(InfrastructureError::ClosureRetained);
            }
            let record = scope.deadlines.get(old.identity.series_id).unwrap();
            if record.phase
                != (DeadlinePhase::Fired {
                    expiry_nonce: expiry.expiry_nonce,
                    observed_tick: expiry.observed_tick,
                })
            {
                return Err(InfrastructureError::StaleClaim);
            }
            if next_generation
                != old
                    .identity
                    .generation
                    .checked_add(1)
                    .ok_or(InfrastructureError::CounterOverflow)?
            {
                return Err(InfrastructureError::StaleGeneration);
            }
            let minimum_tick = expiry
                .observed_tick
                .checked_add(old.identity.backoff_ticks)
                .ok_or(InfrastructureError::CounterOverflow)?;
            if next_deadline_tick < minimum_tick {
                return Err(InfrastructureError::InvalidIdentity);
            }
            let next_attempt = old
                .identity
                .attempt
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            if next_attempt > old.identity.max_attempts {
                return Err(InfrastructureError::ClosureRetained);
            }
            let (nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let bearer_generation = old
                .bearer_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let descriptor = DeadlineDescriptor {
                generation: next_generation,
                deadline_tick: next_deadline_tick,
                attempt: next_attempt,
                ..old.identity
            };
            let stamp = BearerStamp {
                identity: descriptor,
                nonce,
                bearer_generation,
                ..old
            };
            let series_nonce = record.series_nonce;
            let record = scope.deadlines.get_mut(descriptor.series_id).unwrap();
            record.stamp = stamp;
            record.phase = DeadlinePhase::Armed;
            let index = scope.reverse_indexes.get_mut(series_nonce).unwrap();
            index.retry_generation = next_generation;
            index.binding_epoch = stamp.domain.binding_epoch;
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::DeadlineRearmed,
                descriptor.series_id,
                descriptor.generation,
            );
            Ok(DeadlineLease(stamp))
        })
    }

    pub(in super::super) fn cancel_deadline(
        &mut self,
        lease: DeadlineLease,
    ) -> LinearResult<DeadlineLease, ()> {
        linear_apply(lease, |lease| {
            self.require_authoritative()?;
            let stamp = lease.0;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_deadline_bearer(scope, registry_instance, &stamp)?;
            if scope.deadlines.get(stamp.identity.series_id).unwrap().phase != DeadlinePhase::Armed
            {
                return Err(InfrastructureError::InvalidState);
            }
            finish_deadline(scope, stamp, DeadlinePhase::Cancelled)
        })
    }

    pub(in super::super) fn resolve_fired_deadline(
        &mut self,
        expiry: DeadlineExpiryReceipt,
    ) -> LinearResult<DeadlineExpiryReceipt, ()> {
        linear_apply(expiry, |expiry| {
            self.require_authoritative()?;
            let stamp = expiry.deadline;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_deadline_bearer(scope, registry_instance, &stamp)?;
            if expiry.exhausted {
                return Err(InfrastructureError::ClosureRetained);
            }
            let expected = DeadlinePhase::Fired {
                expiry_nonce: expiry.expiry_nonce,
                observed_tick: expiry.observed_tick,
            };
            if scope.deadlines.get(stamp.identity.series_id).unwrap().phase != expected {
                return Err(InfrastructureError::StaleClaim);
            }
            finish_deadline(
                scope,
                stamp,
                DeadlinePhase::Resolved {
                    reconciliation: None,
                    terminal_evidence_digest: None,
                },
            )
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
            if !expiry.exhausted || receipt.evidence_digest == 0 {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let stamp = expiry.deadline;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_deadline_bearer(scope, registry_instance, &stamp)?;
            if scope.deadlines.get(stamp.identity.series_id).unwrap().phase
                != (DeadlinePhase::ExhaustedRetained {
                    expiry_nonce: expiry.expiry_nonce,
                    observed_tick: expiry.observed_tick,
                })
            {
                return Err(InfrastructureError::StaleClaim);
            }
            match receipt.disposition {
                DeadlineExhaustedDisposition::AbortWork => {
                    if supervisor_retry.is_some() {
                        return Err(InfrastructureError::InvalidReceipt);
                    }
                    finish_deadline(
                        scope,
                        stamp,
                        DeadlinePhase::Resolved {
                            reconciliation: Some(receipt),
                            terminal_evidence_digest: Some(receipt.evidence_digest),
                        },
                    )?;
                    Ok(DeadlineReconciliationOutcome::Aborted)
                }
                DeadlineExhaustedDisposition::RetryBySupervisor => {
                    let retry = supervisor_retry.ok_or(InfrastructureError::InvalidReceipt)?;
                    let minimum_tick = expiry
                        .observed_tick
                        .checked_add(retry.backoff_ticks)
                        .ok_or(InfrastructureError::CounterOverflow)?;
                    if retry.generation
                        != stamp
                            .identity
                            .generation
                            .checked_add(1)
                            .ok_or(InfrastructureError::CounterOverflow)?
                        || retry.deadline_tick < minimum_tick
                        || retry.max_attempts == 0
                        || retry.backoff_ticks == 0
                    {
                        return Err(InfrastructureError::InvalidReceipt);
                    }
                    let bearer_generation = stamp
                        .bearer_generation
                        .checked_add(1)
                        .ok_or(InfrastructureError::CounterOverflow)?;
                    let next_revision = preview_revision(scope)?;
                    let mut next_stamp = stamp;
                    next_stamp.identity.generation = retry.generation;
                    next_stamp.identity.deadline_tick = retry.deadline_tick;
                    next_stamp.identity.attempt = 1;
                    next_stamp.identity.max_attempts = retry.max_attempts;
                    next_stamp.identity.backoff_ticks = retry.backoff_ticks;
                    next_stamp.bearer_generation = bearer_generation;
                    let series_nonce = scope
                        .deadlines
                        .get(stamp.identity.series_id)
                        .unwrap()
                        .series_nonce;
                    let record = scope.deadlines.get_mut(stamp.identity.series_id).unwrap();
                    record.stamp = next_stamp;
                    record.phase = DeadlinePhase::Armed;
                    record.last_reconciliation = Some(receipt);
                    record.terminal_evidence_digest = None;
                    let index = scope.reverse_indexes.get_mut(series_nonce).ok_or(
                        InfrastructureError::Invariant("missing deadline reverse index"),
                    )?;
                    index.retry_generation = retry.generation;
                    scope.revision = next_revision;
                    scope.events.push(
                        InfrastructureEventKind::DeadlineRearmed,
                        next_stamp.identity.series_id,
                        next_stamp.identity.generation,
                    );
                    Ok(DeadlineReconciliationOutcome::Retried(DeadlineLease(
                        next_stamp,
                    )))
                }
                DeadlineExhaustedDisposition::Quarantine => {
                    if supervisor_retry.is_some() {
                        return Err(InfrastructureError::InvalidReceipt);
                    }
                    let quarantine_generation = scope
                        .deadlines
                        .get(stamp.identity.series_id)
                        .unwrap()
                        .quarantine_generation
                        .checked_add(1)
                        .ok_or(InfrastructureError::CounterOverflow)?;
                    let (quarantine_nonce, next_nonce) = preview_nonce(scope)?;
                    let next_revision = preview_revision(scope)?;
                    let record = scope.deadlines.get_mut(stamp.identity.series_id).unwrap();
                    record.quarantine_generation = quarantine_generation;
                    record.last_reconciliation = Some(receipt);
                    record.terminal_evidence_digest = None;
                    record.phase = DeadlinePhase::QuarantinedRetained {
                        observed_tick: expiry.observed_tick,
                        receipt,
                        quarantine_generation,
                        quarantine_nonce,
                    };
                    scope.next_nonce = next_nonce;
                    scope.revision = next_revision;
                    Ok(DeadlineReconciliationOutcome::Quarantined(
                        DeadlineQuarantineTicket {
                            deadline: stamp,
                            receipt,
                            quarantine_generation,
                            quarantine_nonce,
                        },
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
            let stamp = ticket.deadline;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_deadline_bearer(scope, registry_instance, &stamp)?;
            if scope.deadlines.get(stamp.identity.series_id).unwrap().phase
                != (DeadlinePhase::QuarantinedRetained {
                    observed_tick: match scope
                        .deadlines
                        .get(stamp.identity.series_id)
                        .unwrap()
                        .phase
                    {
                        DeadlinePhase::QuarantinedRetained { observed_tick, .. } => observed_tick,
                        _ => 0,
                    },
                    receipt: ticket.receipt,
                    quarantine_generation: ticket.quarantine_generation,
                    quarantine_nonce: ticket.quarantine_nonce,
                })
            {
                return Err(InfrastructureError::StaleClaim);
            }
            finish_deadline(
                scope,
                stamp,
                DeadlinePhase::Resolved {
                    reconciliation: Some(ticket.receipt),
                    terminal_evidence_digest: Some(receipt.evidence_digest),
                },
            )
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
        if record.stamp.workload.request != context.workload.request
            || record.stamp.domain.domain != context.domain.domain
            || record.stamp.domain.binding_epoch >= context.domain.binding_epoch
        {
            return Err(InfrastructureError::StaleBinding);
        }
        let phase = record.phase;
        if matches!(
            phase,
            DeadlinePhase::Cancelled | DeadlinePhase::Resolved { .. }
        ) {
            return Err(InfrastructureError::InvalidState);
        }
        let bearer_generation = record
            .stamp
            .bearer_generation
            .checked_add(1)
            .ok_or(InfrastructureError::CounterOverflow)?;
        let needs_successor_nonce = !matches!(phase, DeadlinePhase::Armed);
        let (nonces, next_nonce) =
            preview_nonces(scope, if needs_successor_nonce { 1 } else { 0 })?;
        let next_revision = preview_revision(scope)?;
        let index_slot = record.series_nonce;
        let mut stamp = record.stamp;
        stamp.domain = context.domain;
        stamp.workload = context.workload;
        stamp.bearer_generation = bearer_generation;
        enum AdoptionData {
            Armed,
            Fired {
                expiry_nonce: u64,
                observed_tick: u64,
                exhausted: bool,
            },
            Quarantined {
                observed_tick: u64,
                receipt: DeadlineReconciliationReceipt,
                quarantine_generation: u64,
                quarantine_nonce: u64,
            },
        }
        let (next_phase, adoption) = match phase {
            DeadlinePhase::Armed => (DeadlinePhase::Armed, AdoptionData::Armed),
            DeadlinePhase::Fired { observed_tick, .. } => {
                let expiry_nonce = nonces[0];
                (
                    DeadlinePhase::Fired {
                        expiry_nonce,
                        observed_tick,
                    },
                    AdoptionData::Fired {
                        expiry_nonce,
                        observed_tick,
                        exhausted: false,
                    },
                )
            }
            DeadlinePhase::ExhaustedRetained { observed_tick, .. } => {
                let expiry_nonce = nonces[0];
                (
                    DeadlinePhase::ExhaustedRetained {
                        expiry_nonce,
                        observed_tick,
                    },
                    AdoptionData::Fired {
                        expiry_nonce,
                        observed_tick,
                        exhausted: true,
                    },
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
                (
                    DeadlinePhase::QuarantinedRetained {
                        observed_tick,
                        receipt,
                        quarantine_generation,
                        quarantine_nonce,
                    },
                    AdoptionData::Quarantined {
                        observed_tick,
                        receipt,
                        quarantine_generation,
                        quarantine_nonce,
                    },
                )
            }
            DeadlinePhase::Cancelled | DeadlinePhase::Resolved { .. } => {
                return Err(InfrastructureError::InvalidState);
            }
        };
        let record = scope.deadlines.get_mut(series_id).unwrap();
        record.stamp = stamp;
        record.phase = next_phase;
        scope
            .reverse_indexes
            .get_mut(index_slot)
            .unwrap()
            .binding_epoch = context.domain.binding_epoch;
        scope.next_nonce = next_nonce;
        scope.revision = next_revision;
        if let DeadlinePhase::QuarantinedRetained {
            quarantine_generation,
            ..
        } = next_phase
        {
            record.quarantine_generation = quarantine_generation;
        }
        Ok(match adoption {
            AdoptionData::Armed => DeadlineAdoption::Armed(DeadlineLease(stamp)),
            AdoptionData::Fired {
                expiry_nonce,
                observed_tick,
                exhausted: false,
            } => DeadlineAdoption::Fired(DeadlineExpiryReceipt {
                deadline: stamp,
                observed_tick,
                expiry_nonce,
                exhausted: false,
            }),
            AdoptionData::Fired {
                expiry_nonce,
                observed_tick,
                exhausted: true,
            } => DeadlineAdoption::Exhausted(DeadlineExpiryReceipt {
                deadline: stamp,
                observed_tick,
                expiry_nonce,
                exhausted: true,
            }),
            AdoptionData::Quarantined {
                observed_tick: _,
                receipt,
                quarantine_generation,
                quarantine_nonce,
            } => DeadlineAdoption::Quarantined(DeadlineQuarantineTicket {
                deadline: stamp,
                receipt,
                quarantine_generation,
                quarantine_nonce,
            }),
        })
    }
}

fn finish_deadline(
    scope: &mut ScopeInfrastructure,
    stamp: BearerStamp<DeadlineDescriptor>,
    terminal: DeadlinePhase,
) -> Result<(), InfrastructureError> {
    let next_revision = preview_revision(scope)?;
    let next_live = checked_sub(scope.live.deadlines, 1)?;
    let next_workload_children = preview_workload_child_sub(scope, stamp.workload.request)?;
    let parent_task = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    let next_task_children = preview_task_child_sub(scope, parent_task)?;
    let record = scope.deadlines.get_mut(stamp.identity.series_id).unwrap();
    record.phase = terminal;
    if let DeadlinePhase::Resolved {
        reconciliation,
        terminal_evidence_digest,
    } = terminal
    {
        record.last_reconciliation = reconciliation;
        record.terminal_evidence_digest = terminal_evidence_digest;
    }
    scope.revision = next_revision;
    scope.live.deadlines = next_live;
    scope
        .workloads
        .get_mut(stamp.workload.request.id)
        .unwrap()
        .live_children = next_workload_children;
    scope
        .tasks
        .get_mut(parent_task.work_id)
        .unwrap()
        .live_children = next_task_children;
    scope.events.push(
        if matches!(terminal, DeadlinePhase::Cancelled) {
            InfrastructureEventKind::DeadlineCancelled
        } else {
            InfrastructureEventKind::DeadlineResolved
        },
        stamp.identity.series_id,
        stamp.identity.generation,
    );
    Ok(())
}
