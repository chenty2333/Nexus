// SPDX-License-Identifier: MPL-2.0

use super::{
    BearerStamp, ContinuationAckReceipt, ContinuationAdoption, ContinuationDescriptor,
    ContinuationLease, ContinuationPhase, ContinuationPublicationIntent,
    ContinuationPublicationReceipt, ContinuationRecord, ContinuationRecoveryProjection,
    ContinuationRecoveryState, ContinuationResumeIntent, ContinuationResumeReceipt, DomainStamp,
    EnteredTaskLease, InfrastructureError, InfrastructureEventKind, InfrastructureKind,
    InfrastructureState, LinearResult, ParentStamp, ReverseIndexRecord, ReverseParent,
    ScopeInfrastructure, TaskPhase, VmAuthorityKey, WakeClaim, WorkloadContext, checked_add,
    checked_sub, context_from_stamp, linear_apply, preview_bearer_stamp, preview_nonce,
    preview_nonces, preview_revision, preview_task_child_add, preview_task_child_sub,
    preview_workload_child_add, preview_workload_child_sub, require_vacancy,
    validate_active_admission, validate_context, validate_continuation_bearer, validate_task_stamp,
};

impl InfrastructureState {
    pub(in super::super) fn create_continuation(
        &mut self,
        task: &EnteredTaskLease,
        descriptor: ContinuationDescriptor,
    ) -> Result<ContinuationLease, InfrastructureError> {
        self.require_authoritative()?;
        descriptor.validate()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(task.0.root.scope)?;
        validate_task_stamp(scope, registry_instance, &task.0)?;
        validate_active_admission(scope)?;
        if scope.binding_epoch(descriptor.source_domain)? != descriptor.source_binding_epoch {
            return Err(InfrastructureError::StaleBinding);
        }
        let task_record = scope.tasks.get(task.0.identity.work_id).unwrap();
        if task_record.phase != TaskPhase::Entered {
            return Err(InfrastructureError::InvalidState);
        }
        if task.0.identity.vm.map(VmAuthorityKey::generation) != Some(descriptor.vm_generation) {
            return Err(InfrastructureError::StaleGeneration);
        }
        if let Some(existing) = scope.continuations.get(descriptor.continuation_id) {
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
            &scope.continuations,
            descriptor.continuation_id,
            InfrastructureKind::Continuation,
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
            InfrastructureKind::Continuation,
        )?;
        let next_revision = preview_revision(scope)?;
        let next_live = checked_add(scope.live.continuations, 1)?;
        let next_workload_children = preview_workload_child_add(scope, stamp.workload.request)?;
        let next_task_children = preview_task_child_add(scope, task.0.identity)?;
        let index = ReverseIndexRecord {
            slot: stamp.nonce,
            kind: InfrastructureKind::Continuation,
            root_effect: stamp.root.root_effect,
            parent: ReverseParent::Task(task.0.identity),
            task: Some(task.0.identity.task),
            domain: stamp.domain.domain,
            binding_epoch: stamp.domain.binding_epoch,
            source_domain: Some(descriptor.source_domain),
            source_binding_epoch: Some(descriptor.source_binding_epoch),
            resource: None,
            actor_slot: None,
            retry_generation: descriptor.generation,
        };
        scope.continuations.install(
            ContinuationRecord {
                stamp,
                origin_source: DomainStamp {
                    domain: descriptor.source_domain,
                    binding_epoch: descriptor.source_binding_epoch,
                },
                claim_generation: 0,
                apply_generation: 0,
                ack_generation: 0,
                resume_generation: 0,
                service_owner: None,
                phase: ContinuationPhase::Pending,
                closure_sequence: None,
            },
            InfrastructureKind::Continuation,
        )?;
        scope
            .reverse_indexes
            .install(index, InfrastructureKind::Continuation)?;
        scope.next_nonce = next_nonce;
        scope.revision = next_revision;
        scope.live.continuations = next_live;
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
            InfrastructureEventKind::ContinuationCreated,
            descriptor.continuation_id,
            descriptor.generation,
        );
        Ok(ContinuationLease(
            scope
                .continuations
                .get(descriptor.continuation_id)
                .unwrap()
                .stamp,
        ))
    }

    pub(in super::super) fn claim_continuation(
        &mut self,
        lease: ContinuationLease,
        outcome_digest: u64,
    ) -> LinearResult<ContinuationLease, WakeClaim> {
        linear_apply(lease, |lease| {
            self.require_authoritative()?;
            if outcome_digest == 0 {
                return Err(InfrastructureError::InvalidIdentity);
            }
            let stamp = lease.0;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_continuation_bearer(scope, registry_instance, &stamp)?;
            let record = scope
                .continuations
                .get(stamp.identity.continuation_id)
                .unwrap();
            if record.service_owner.is_some() {
                return Err(InfrastructureError::InvalidState);
            }
            if record.phase != ContinuationPhase::Pending {
                return Err(
                    if matches!(
                        record.phase,
                        ContinuationPhase::Claimed { .. }
                            | ContinuationPhase::Publishing { .. }
                            | ContinuationPhase::Acknowledged { .. }
                            | ContinuationPhase::Resuming { .. }
                            | ContinuationPhase::Resumed { .. }
                    ) {
                        InfrastructureError::ExactReplay
                    } else {
                        InfrastructureError::InvalidState
                    },
                );
            }
            let claim_generation = record
                .claim_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let (claim_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let record = scope
                .continuations
                .get_mut(stamp.identity.continuation_id)
                .unwrap();
            record.claim_generation = claim_generation;
            record.phase = ContinuationPhase::Claimed {
                claim_generation,
                claim_nonce,
                outcome_digest,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ContinuationClaimed,
                stamp.identity.continuation_id,
                stamp.identity.generation,
            );
            Ok(WakeClaim {
                continuation: stamp,
                claim_generation,
                claim_nonce,
                outcome_digest,
            })
        })
    }

    pub(in super::super) fn begin_continuation_publication(
        &mut self,
        claim: WakeClaim,
        receipt: ContinuationPublicationReceipt,
    ) -> LinearResult<WakeClaim, ContinuationPublicationIntent> {
        linear_apply(claim, |claim| {
            self.require_authoritative()?;
            let stamp = claim.continuation;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_continuation_bearer(scope, registry_instance, &stamp)?;
            if receipt.vm_generation != stamp.identity.vm_generation
                || receipt.source_domain != stamp.identity.source_domain
                || receipt.source_binding_epoch != stamp.identity.source_binding_epoch
                || receipt.outcome_digest != claim.outcome_digest
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let record = scope
                .continuations
                .get(stamp.identity.continuation_id)
                .unwrap();
            if record.phase
                != (ContinuationPhase::Claimed {
                    claim_generation: claim.claim_generation,
                    claim_nonce: claim.claim_nonce,
                    outcome_digest: claim.outcome_digest,
                })
            {
                return Err(InfrastructureError::StaleClaim);
            }
            let apply_generation = record
                .apply_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let (apply_nonce, next_nonce) = preview_nonce(scope)?;
            let publication_sequence = scope.next_publication_sequence;
            let next_publication_sequence = publication_sequence
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let next_revision = preview_revision(scope)?;
            let record = scope
                .continuations
                .get_mut(stamp.identity.continuation_id)
                .unwrap();
            record.apply_generation = apply_generation;
            record.phase = ContinuationPhase::Publishing {
                claim_generation: claim.claim_generation,
                claim_nonce: claim.claim_nonce,
                apply_generation,
                apply_nonce,
                publication_sequence,
                receipt,
            };
            scope.next_nonce = next_nonce;
            scope.next_publication_sequence = next_publication_sequence;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ContinuationPublishing,
                stamp.identity.continuation_id,
                stamp.identity.generation,
            );
            Ok(ContinuationPublicationIntent {
                continuation: stamp,
                claim_generation: claim.claim_generation,
                claim_nonce: claim.claim_nonce,
                apply_generation,
                apply_nonce,
                publication_sequence,
                receipt,
            })
        })
    }

    pub(in super::super) fn acknowledge_continuation_publication(
        &mut self,
        intent: ContinuationPublicationIntent,
    ) -> LinearResult<ContinuationPublicationIntent, ContinuationAckReceipt> {
        linear_apply(intent, |intent| {
            self.require_authoritative()?;
            let stamp = intent.continuation;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_continuation_bearer(scope, registry_instance, &stamp)?;
            let expected = ContinuationPhase::Publishing {
                claim_generation: intent.claim_generation,
                claim_nonce: intent.claim_nonce,
                apply_generation: intent.apply_generation,
                apply_nonce: intent.apply_nonce,
                publication_sequence: intent.publication_sequence,
                receipt: intent.receipt,
            };
            if scope
                .continuations
                .get(stamp.identity.continuation_id)
                .unwrap()
                .phase
                != expected
            {
                return Err(InfrastructureError::StaleClaim);
            }
            let ack_generation = scope
                .continuations
                .get(stamp.identity.continuation_id)
                .unwrap()
                .ack_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let (ack_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let record = scope
                .continuations
                .get_mut(stamp.identity.continuation_id)
                .unwrap();
            record.ack_generation = ack_generation;
            record.phase = ContinuationPhase::Acknowledged {
                publication_sequence: intent.publication_sequence,
                outcome_digest: intent.receipt.outcome_digest,
                ack_generation,
                ack_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ContinuationAcknowledged,
                stamp.identity.continuation_id,
                stamp.identity.generation,
            );
            Ok(ContinuationAckReceipt {
                continuation: stamp,
                publication_sequence: intent.publication_sequence,
                outcome_digest: intent.receipt.outcome_digest,
                ack_generation,
                ack_nonce,
            })
        })
    }

    pub(in super::super) fn begin_continuation_resume(
        &mut self,
        ack: ContinuationAckReceipt,
    ) -> LinearResult<ContinuationAckReceipt, ContinuationResumeIntent> {
        linear_apply(ack, |ack| {
            self.require_authoritative()?;
            let stamp = ack.continuation;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_continuation_bearer(scope, registry_instance, &stamp)?;
            let record = scope
                .continuations
                .get(stamp.identity.continuation_id)
                .unwrap();
            if record.phase
                != (ContinuationPhase::Acknowledged {
                    publication_sequence: ack.publication_sequence,
                    outcome_digest: ack.outcome_digest,
                    ack_generation: ack.ack_generation,
                    ack_nonce: ack.ack_nonce,
                })
            {
                return Err(InfrastructureError::StaleClaim);
            }
            let resume_generation = record
                .resume_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let (resume_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let record = scope
                .continuations
                .get_mut(stamp.identity.continuation_id)
                .unwrap();
            record.resume_generation = resume_generation;
            record.phase = ContinuationPhase::Resuming {
                publication_sequence: ack.publication_sequence,
                outcome_digest: ack.outcome_digest,
                ack_generation: ack.ack_generation,
                ack_nonce: ack.ack_nonce,
                resume_generation,
                resume_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            Ok(ContinuationResumeIntent {
                continuation: stamp,
                publication_sequence: ack.publication_sequence,
                outcome_digest: ack.outcome_digest,
                ack_generation: ack.ack_generation,
                ack_nonce: ack.ack_nonce,
                resume_generation,
                resume_nonce,
            })
        })
    }

    pub(in super::super) fn complete_continuation_resume(
        &mut self,
        intent: ContinuationResumeIntent,
        receipt: ContinuationResumeReceipt,
    ) -> LinearResult<ContinuationResumeIntent, ContinuationResumeReceipt> {
        linear_apply(intent, |intent| {
            self.require_authoritative()?;
            let stamp = intent.continuation;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_continuation_bearer(scope, registry_instance, &stamp)?;
            if receipt.publication_sequence != intent.publication_sequence
                || receipt.vm_generation != stamp.identity.vm_generation
                || receipt.external_receipt_digest == 0
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let expected = ContinuationPhase::Resuming {
                publication_sequence: intent.publication_sequence,
                outcome_digest: intent.outcome_digest,
                ack_generation: intent.ack_generation,
                ack_nonce: intent.ack_nonce,
                resume_generation: intent.resume_generation,
                resume_nonce: intent.resume_nonce,
            };
            let record = scope
                .continuations
                .get(stamp.identity.continuation_id)
                .unwrap();
            if record.phase != expected {
                return Err(InfrastructureError::StaleClaim);
            }
            if receipt.outcome_digest != intent.outcome_digest {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let next_revision = preview_revision(scope)?;
            let next_live = checked_sub(scope.live.continuations, 1)?;
            let next_workload_children = preview_workload_child_sub(scope, stamp.workload.request)?;
            let parent_task = match stamp.parent {
                ParentStamp::Task(parent) => parent,
                _ => return Err(InfrastructureError::ForeignParent),
            };
            let next_task_children = preview_task_child_sub(scope, parent_task)?;
            scope
                .continuations
                .get_mut(stamp.identity.continuation_id)
                .unwrap()
                .phase = ContinuationPhase::Resumed {
                publication_sequence: intent.publication_sequence,
                receipt,
            };
            scope.revision = next_revision;
            scope.live.continuations = next_live;
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
            Ok(receipt)
        })
    }

    pub(in super::super) fn cancel_continuation(
        &mut self,
        lease: ContinuationLease,
    ) -> LinearResult<ContinuationLease, ()> {
        linear_apply(lease, |lease| {
            self.require_authoritative()?;
            let stamp = lease.0;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_continuation_bearer(scope, registry_instance, &stamp)?;
            let phase = scope
                .continuations
                .get(stamp.identity.continuation_id)
                .unwrap()
                .phase;
            if phase == ContinuationPhase::Cancelled {
                return Ok(());
            }
            if phase != ContinuationPhase::Pending {
                return Err(InfrastructureError::InvalidState);
            }
            finish_continuation_cancel(scope, stamp)
        })
    }

    pub(in super::super) fn query_continuation(
        &self,
        context: &WorkloadContext,
        continuation_id: u64,
        generation: u64,
    ) -> Result<ContinuationRecoveryProjection, InfrastructureError> {
        self.require_authoritative()?;
        let scope = self.scope(context.root.scope)?;
        validate_context(scope, self.registry_instance, context)?;
        let record = scope
            .continuations
            .get(continuation_id)
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
        Ok(ContinuationRecoveryProjection {
            descriptor: record.stamp.identity,
            parent_task,
            state: match record.phase {
                ContinuationPhase::Pending => ContinuationRecoveryState::Pending,
                ContinuationPhase::Claimed { .. } => ContinuationRecoveryState::Claimed,
                ContinuationPhase::Publishing { .. } => {
                    ContinuationRecoveryState::PublicationUncertain
                }
                ContinuationPhase::Acknowledged {
                    publication_sequence,
                    ..
                } => ContinuationRecoveryState::AcknowledgedPendingResume {
                    publication_sequence,
                },
                ContinuationPhase::Resuming {
                    publication_sequence,
                    ..
                } => ContinuationRecoveryState::ResumeUncertain {
                    publication_sequence,
                },
                ContinuationPhase::Resumed {
                    publication_sequence,
                    ..
                } => ContinuationRecoveryState::Resumed {
                    publication_sequence,
                },
                ContinuationPhase::Cancelled => ContinuationRecoveryState::Cancelled,
            },
            claim_generation: record.claim_generation,
            resume_receipt: match record.phase {
                ContinuationPhase::Resumed { receipt, .. } => Some(receipt),
                _ => None,
            },
        })
    }

    pub(in super::super) fn adopt_continuation_after_fence(
        &mut self,
        context: &WorkloadContext,
        continuation_id: u64,
        generation: u64,
        current_source_binding_epoch: u64,
    ) -> Result<ContinuationAdoption, InfrastructureError> {
        self.require_authoritative()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(context.root.scope)?;
        validate_context(scope, registry_instance, context)?;
        let record = scope
            .continuations
            .get(continuation_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
        if record.service_owner.is_some() {
            return Err(InfrastructureError::InvalidState);
        }
        if record.stamp.identity.generation != generation {
            return Err(InfrastructureError::StaleGeneration);
        }
        if record.stamp.workload.request != context.workload.request
            || record.stamp.domain.domain != context.domain.domain
            || record.stamp.domain.binding_epoch > context.domain.binding_epoch
            || record.stamp.identity.source_binding_epoch >= current_source_binding_epoch
            || scope.binding_epoch(record.stamp.identity.source_domain)?
                != current_source_binding_epoch
        {
            return Err(InfrastructureError::StaleBinding);
        }
        let previous_phase = record.phase;
        if matches!(
            previous_phase,
            ContinuationPhase::Resumed { .. } | ContinuationPhase::Cancelled
        ) {
            return Err(InfrastructureError::InvalidState);
        }
        let claim_generation = if matches!(
            previous_phase,
            ContinuationPhase::Claimed { .. } | ContinuationPhase::Publishing { .. }
        ) {
            record
                .claim_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?
        } else {
            record.claim_generation
        };
        let ack_generation = if matches!(
            previous_phase,
            ContinuationPhase::Acknowledged { .. } | ContinuationPhase::Resuming { .. }
        ) {
            record
                .ack_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?
        } else {
            record.ack_generation
        };
        let resume_generation = if matches!(previous_phase, ContinuationPhase::Resuming { .. }) {
            record
                .resume_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?
        } else {
            record.resume_generation
        };
        let bearer_generation = record
            .stamp
            .bearer_generation
            .checked_add(1)
            .ok_or(InfrastructureError::CounterOverflow)?;
        let nonce_count = match previous_phase {
            ContinuationPhase::Pending => 0,
            ContinuationPhase::Claimed { .. } | ContinuationPhase::Acknowledged { .. } => 1,
            ContinuationPhase::Publishing { .. } | ContinuationPhase::Resuming { .. } => 2,
            ContinuationPhase::Resumed { .. } | ContinuationPhase::Cancelled => {
                return Err(InfrastructureError::InvalidState);
            }
        };
        let (nonces, next_nonce) = preview_nonces(scope, nonce_count)?;
        let next_revision = preview_revision(scope)?;
        let index_slot = record.stamp.nonce;
        let mut stamp = record.stamp;
        stamp.domain = context.domain;
        stamp.workload = context.workload;
        stamp.identity.source_binding_epoch = current_source_binding_epoch;
        stamp.bearer_generation = bearer_generation;
        let next_phase = match previous_phase {
            ContinuationPhase::Pending => ContinuationPhase::Pending,
            ContinuationPhase::Claimed { outcome_digest, .. } => ContinuationPhase::Claimed {
                claim_generation,
                claim_nonce: nonces[0],
                outcome_digest,
            },
            ContinuationPhase::Publishing {
                apply_generation,
                publication_sequence,
                receipt,
                ..
            } => {
                let apply_generation = apply_generation
                    .checked_add(1)
                    .ok_or(InfrastructureError::CounterOverflow)?;
                ContinuationPhase::Publishing {
                    claim_generation,
                    claim_nonce: nonces[0],
                    apply_generation,
                    apply_nonce: nonces[1],
                    publication_sequence,
                    receipt: ContinuationPublicationReceipt {
                        source_binding_epoch: current_source_binding_epoch,
                        ..receipt
                    },
                }
            }
            ContinuationPhase::Acknowledged {
                publication_sequence,
                outcome_digest,
                ..
            } => ContinuationPhase::Acknowledged {
                publication_sequence,
                outcome_digest,
                ack_generation,
                ack_nonce: nonces[0],
            },
            ContinuationPhase::Resuming {
                publication_sequence,
                outcome_digest,
                ..
            } => ContinuationPhase::Resuming {
                publication_sequence,
                outcome_digest,
                ack_generation,
                ack_nonce: nonces[0],
                resume_generation,
                resume_nonce: nonces[1],
            },
            ContinuationPhase::Resumed { .. } | ContinuationPhase::Cancelled => {
                return Err(InfrastructureError::InvalidState);
            }
        };
        let record = scope.continuations.get_mut(continuation_id).unwrap();
        record.stamp = stamp;
        record.claim_generation = claim_generation;
        record.ack_generation = ack_generation;
        record.resume_generation = resume_generation;
        if let ContinuationPhase::Publishing {
            apply_generation, ..
        } = next_phase
        {
            record.apply_generation = apply_generation;
        }
        record.phase = next_phase;
        let index =
            scope
                .reverse_indexes
                .get_mut(index_slot)
                .ok_or(InfrastructureError::Invariant(
                    "missing continuation reverse index",
                ))?;
        index.binding_epoch = context.domain.binding_epoch;
        index.source_binding_epoch = Some(current_source_binding_epoch);
        scope.next_nonce = next_nonce;
        scope.revision = next_revision;
        scope.events.push(
            InfrastructureEventKind::ContinuationClaimed,
            continuation_id,
            generation,
        );
        Ok(match next_phase {
            ContinuationPhase::Pending => ContinuationAdoption::Pending(ContinuationLease(stamp)),
            ContinuationPhase::Claimed { outcome_digest, .. } => {
                ContinuationAdoption::Claimed(WakeClaim {
                    continuation: stamp,
                    claim_generation,
                    claim_nonce: nonces[0],
                    outcome_digest,
                })
            }
            ContinuationPhase::Publishing {
                apply_generation,
                apply_nonce,
                publication_sequence,
                receipt,
                ..
            } => ContinuationAdoption::ReplayPublication(ContinuationPublicationIntent {
                continuation: stamp,
                claim_generation,
                claim_nonce: nonces[0],
                apply_generation,
                apply_nonce,
                publication_sequence,
                receipt,
            }),
            ContinuationPhase::Acknowledged {
                publication_sequence,
                outcome_digest,
                ack_generation,
                ack_nonce,
            } => ContinuationAdoption::Acknowledged(ContinuationAckReceipt {
                continuation: stamp,
                publication_sequence,
                outcome_digest,
                ack_generation,
                ack_nonce,
            }),
            ContinuationPhase::Resuming {
                publication_sequence,
                outcome_digest,
                ack_generation,
                ack_nonce,
                resume_generation,
                resume_nonce,
            } => ContinuationAdoption::ReplayResume(ContinuationResumeIntent {
                continuation: stamp,
                publication_sequence,
                outcome_digest,
                ack_generation,
                ack_nonce,
                resume_generation,
                resume_nonce,
            }),
            _ => {
                return Err(InfrastructureError::Invariant(
                    "invalid adopted continuation",
                ));
            }
        })
    }
}

fn finish_continuation_cancel(
    scope: &mut ScopeInfrastructure,
    stamp: BearerStamp<ContinuationDescriptor>,
) -> Result<(), InfrastructureError> {
    let next_revision = preview_revision(scope)?;
    let next_live = checked_sub(scope.live.continuations, 1)?;
    let next_workload_children = preview_workload_child_sub(scope, stamp.workload.request)?;
    let parent_task = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    let next_task_children = preview_task_child_sub(scope, parent_task)?;
    scope
        .continuations
        .get_mut(stamp.identity.continuation_id)
        .unwrap()
        .phase = ContinuationPhase::Cancelled;
    scope.revision = next_revision;
    scope.live.continuations = next_live;
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
        InfrastructureEventKind::ContinuationCancelled,
        stamp.identity.continuation_id,
        stamp.identity.generation,
    );
    Ok(())
}
