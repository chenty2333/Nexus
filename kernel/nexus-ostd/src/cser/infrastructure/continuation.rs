// SPDX-License-Identifier: MPL-2.0

use super::{
    BearerStamp, ContinuationAckReceipt, ContinuationAdoption, ContinuationDescriptor,
    ContinuationLease, ContinuationPhase, ContinuationPublicationAckReceipt,
    ContinuationPublicationAuthority, ContinuationPublicationIntent, ContinuationPublicationPlan,
    ContinuationPublicationReceipt, ContinuationRecord, ContinuationRecoveryProjection,
    ContinuationRecoveryState, ContinuationResumeAuthority, ContinuationResumeIntent,
    ContinuationResumePlan, ContinuationResumeReceipt, DomainStamp, EnteredTaskLease,
    InfrastructureError, InfrastructureEventKind, InfrastructureKind, InfrastructureState,
    LinearResult, ParentStamp, ReverseIndexRecord, ReverseParent, ScopeInfrastructure, TaskPhase,
    VmAuthorityKey, WakeClaim, WorkloadContext, bearer_state, checked_add, checked_sub,
    context_from_stamp, linear_apply, mint_continuation_key, next_continuation_bearer_generation,
    preview_bearer_stamp, preview_nonce, preview_nonces, preview_revision, preview_task_child_add,
    preview_task_child_sub, preview_workload_child_add, preview_workload_child_sub,
    require_vacancy, validate_active_admission, validate_context, validate_continuation_key,
    validate_task_stamp,
};

enum PreparedContinuationAdoption {
    Pending,
    Claimed,
    ReplayPublication(ContinuationPublicationPlan),
    Acknowledged,
    ReplayResume(ContinuationResumePlan),
}

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
                publication_ack: None,
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
        Ok(ContinuationLease(mint_continuation_key::<
            bearer_state::ContinuationPending,
        >(
            scope.continuations.get(descriptor.continuation_id).unwrap(),
        )))
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
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(lease.0.authority.scope)?;
            let record = validate_continuation_key(scope, registry_instance, &lease.0)?;
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
            let bearer_generation = next_continuation_bearer_generation(record)?;
            let continuation_id = record.stamp.identity.continuation_id;
            let object_generation = record.stamp.identity.generation;
            let (claim_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let record = scope.continuations.get_mut(continuation_id).unwrap();
            record.claim_generation = claim_generation;
            record.stamp.bearer_generation = bearer_generation;
            record.phase = ContinuationPhase::Claimed {
                claim_generation,
                claim_nonce,
                outcome_digest,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ContinuationClaimed,
                continuation_id,
                object_generation,
            );
            Ok(WakeClaim(mint_continuation_key::<
                bearer_state::ContinuationClaimed,
            >(
                scope.continuations.get(continuation_id).unwrap(),
            )))
        })
    }

    pub(in super::super) fn begin_continuation_publication(
        &mut self,
        claim: WakeClaim,
        receipt: ContinuationPublicationReceipt,
    ) -> LinearResult<WakeClaim, ContinuationPublicationIntent> {
        linear_apply(claim, |claim| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(claim.0.authority.scope)?;
            let record = validate_continuation_key(scope, registry_instance, &claim.0)?;
            if record.service_owner.is_some() {
                return Err(InfrastructureError::InvalidState);
            }
            let (claim_generation, claim_nonce, outcome_digest) = match record.phase {
                ContinuationPhase::Claimed {
                    claim_generation,
                    claim_nonce,
                    outcome_digest,
                } => (claim_generation, claim_nonce, outcome_digest),
                _ => return Err(InfrastructureError::StaleClaim),
            };
            let descriptor = record.stamp.identity;
            if receipt.vm_generation != descriptor.vm_generation
                || receipt.source_domain != descriptor.source_domain
                || receipt.source_binding_epoch != descriptor.source_binding_epoch
                || receipt.outcome_digest != outcome_digest
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let apply_generation = record
                .apply_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let bearer_generation = next_continuation_bearer_generation(record)?;
            let (apply_nonce, next_nonce) = preview_nonce(scope)?;
            let publication_sequence = scope.next_publication_sequence;
            let next_publication_sequence = publication_sequence
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let next_revision = preview_revision(scope)?;
            let record = scope
                .continuations
                .get_mut(descriptor.continuation_id)
                .unwrap();
            record.apply_generation = apply_generation;
            record.stamp.bearer_generation = bearer_generation;
            record.phase = ContinuationPhase::Publishing {
                claim_generation,
                claim_nonce,
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
                descriptor.continuation_id,
                descriptor.generation,
            );
            Ok(ContinuationPublicationIntent {
                authority: ContinuationPublicationAuthority(mint_continuation_key::<
                    bearer_state::ContinuationPublishing,
                >(
                    scope.continuations.get(descriptor.continuation_id).unwrap(),
                )),
                plan: ContinuationPublicationPlan {
                    descriptor,
                    claim_generation,
                    claim_nonce,
                    apply_generation,
                    apply_nonce,
                    publication_sequence,
                    receipt,
                },
            })
        })
    }

    pub(in super::super) fn acknowledge_continuation_publication(
        &mut self,
        authority: ContinuationPublicationAuthority,
        receipt: ContinuationPublicationAckReceipt,
    ) -> LinearResult<ContinuationPublicationAuthority, ContinuationAckReceipt> {
        linear_apply(authority, |authority| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(authority.0.authority.scope)?;
            let record = validate_continuation_key(scope, registry_instance, &authority.0)?;
            if record.service_owner.is_some() {
                return Err(InfrastructureError::InvalidState);
            }
            let (
                claim_generation,
                claim_nonce,
                apply_generation,
                apply_nonce,
                publication_sequence,
                publication_receipt,
            ) = match record.phase {
                ContinuationPhase::Publishing {
                    claim_generation,
                    claim_nonce,
                    apply_generation,
                    apply_nonce,
                    publication_sequence,
                    receipt,
                } => (
                    claim_generation,
                    claim_nonce,
                    apply_generation,
                    apply_nonce,
                    publication_sequence,
                    receipt,
                ),
                _ => return Err(InfrastructureError::StaleClaim),
            };
            let descriptor = record.stamp.identity;
            if receipt.continuation_id != descriptor.continuation_id
                || receipt.generation != descriptor.generation
                || receipt.claim_generation != claim_generation
                || receipt.claim_nonce != claim_nonce
                || receipt.apply_generation != apply_generation
                || receipt.apply_nonce != apply_nonce
                || receipt.publication_sequence != publication_sequence
                || receipt.vm_generation != descriptor.vm_generation
                || receipt.source_domain != descriptor.source_domain
                || receipt.source_binding_epoch != descriptor.source_binding_epoch
                || receipt.outcome_digest != publication_receipt.outcome_digest
                || receipt.external_receipt_digest == 0
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            if record.publication_ack.is_some() {
                return Err(InfrastructureError::Invariant(
                    "publishing continuation retains acknowledgement",
                ));
            }
            let continuation_id = record.stamp.identity.continuation_id;
            let object_generation = record.stamp.identity.generation;
            let ack_generation = record
                .ack_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let bearer_generation = next_continuation_bearer_generation(record)?;
            let (ack_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let record = scope.continuations.get_mut(continuation_id).unwrap();
            record.ack_generation = ack_generation;
            record.stamp.bearer_generation = bearer_generation;
            record.publication_ack = Some(receipt);
            record.phase = ContinuationPhase::Acknowledged {
                publication_sequence,
                outcome_digest: publication_receipt.outcome_digest,
                ack_generation,
                ack_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ContinuationAcknowledged,
                continuation_id,
                object_generation,
            );
            Ok(ContinuationAckReceipt(mint_continuation_key::<
                bearer_state::ContinuationAcknowledged,
            >(
                scope.continuations.get(continuation_id).unwrap(),
            )))
        })
    }

    pub(in super::super) fn begin_continuation_resume(
        &mut self,
        ack: ContinuationAckReceipt,
    ) -> LinearResult<ContinuationAckReceipt, ContinuationResumeIntent> {
        linear_apply(ack, |ack| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(ack.0.authority.scope)?;
            let record = validate_continuation_key(scope, registry_instance, &ack.0)?;
            if record.service_owner.is_some() {
                return Err(InfrastructureError::InvalidState);
            }
            let (publication_sequence, outcome_digest, ack_generation, ack_nonce) =
                match record.phase {
                    ContinuationPhase::Acknowledged {
                        publication_sequence,
                        outcome_digest,
                        ack_generation,
                        ack_nonce,
                    } => (
                        publication_sequence,
                        outcome_digest,
                        ack_generation,
                        ack_nonce,
                    ),
                    _ => return Err(InfrastructureError::StaleClaim),
                };
            let publication_ack = record
                .publication_ack
                .ok_or(InfrastructureError::Invariant(
                    "acknowledged continuation is missing publication receipt",
                ))?;
            let descriptor = record.stamp.identity;
            let resume_generation = record
                .resume_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let bearer_generation = next_continuation_bearer_generation(record)?;
            let (resume_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let record = scope
                .continuations
                .get_mut(descriptor.continuation_id)
                .unwrap();
            record.resume_generation = resume_generation;
            record.stamp.bearer_generation = bearer_generation;
            record.phase = ContinuationPhase::Resuming {
                publication_sequence,
                outcome_digest,
                ack_generation,
                ack_nonce,
                resume_generation,
                resume_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            Ok(ContinuationResumeIntent {
                authority: ContinuationResumeAuthority(mint_continuation_key::<
                    bearer_state::ContinuationResuming,
                >(
                    scope.continuations.get(descriptor.continuation_id).unwrap(),
                )),
                plan: ContinuationResumePlan {
                    descriptor,
                    publication_ack,
                    publication_sequence,
                    outcome_digest,
                    ack_generation,
                    ack_nonce,
                    resume_generation,
                    resume_nonce,
                },
            })
        })
    }

    pub(in super::super) fn complete_continuation_resume(
        &mut self,
        authority: ContinuationResumeAuthority,
        receipt: ContinuationResumeReceipt,
    ) -> LinearResult<ContinuationResumeAuthority, ContinuationResumeReceipt> {
        linear_apply(authority, |authority| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(authority.0.authority.scope)?;
            let record = validate_continuation_key(scope, registry_instance, &authority.0)?;
            if record.service_owner.is_some() {
                return Err(InfrastructureError::InvalidState);
            }
            let (
                publication_sequence,
                outcome_digest,
                ack_generation,
                ack_nonce,
                resume_generation,
                resume_nonce,
            ) = match record.phase {
                ContinuationPhase::Resuming {
                    publication_sequence,
                    outcome_digest,
                    ack_generation,
                    ack_nonce,
                    resume_generation,
                    resume_nonce,
                } => (
                    publication_sequence,
                    outcome_digest,
                    ack_generation,
                    ack_nonce,
                    resume_generation,
                    resume_nonce,
                ),
                _ => return Err(InfrastructureError::StaleClaim),
            };
            let stamp = record.stamp;
            if receipt.continuation_id != stamp.identity.continuation_id
                || receipt.generation != stamp.identity.generation
                || receipt.publication_sequence != publication_sequence
                || receipt.vm_generation != stamp.identity.vm_generation
                || receipt.source_domain != stamp.identity.source_domain
                || receipt.source_binding_epoch != stamp.identity.source_binding_epoch
                || receipt.ack_generation != ack_generation
                || receipt.ack_nonce != ack_nonce
                || receipt.resume_generation != resume_generation
                || receipt.resume_nonce != resume_nonce
                || receipt.external_receipt_digest == 0
                || receipt.outcome_digest != outcome_digest
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let expected = ContinuationPhase::Resuming {
                publication_sequence,
                outcome_digest,
                ack_generation,
                ack_nonce,
                resume_generation,
                resume_nonce,
            };
            if record.phase != expected {
                return Err(InfrastructureError::StaleClaim);
            }
            let bearer_generation = next_continuation_bearer_generation(record)?;
            let next_revision = preview_revision(scope)?;
            let next_live = checked_sub(scope.live.continuations, 1)?;
            let next_workload_children = preview_workload_child_sub(scope, stamp.workload.request)?;
            let parent_task = match stamp.parent {
                ParentStamp::Task(parent) => parent,
                _ => return Err(InfrastructureError::ForeignParent),
            };
            let next_task_children = preview_task_child_sub(scope, parent_task)?;
            let record = scope
                .continuations
                .get_mut(stamp.identity.continuation_id)
                .unwrap();
            record.stamp.bearer_generation = bearer_generation;
            record.phase = ContinuationPhase::Resumed {
                publication_sequence,
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
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(lease.0.authority.scope)?;
            let record = validate_continuation_key(scope, registry_instance, &lease.0)?;
            if record.service_owner.is_some() || record.phase != ContinuationPhase::Pending {
                return Err(InfrastructureError::InvalidState);
            }
            finish_continuation_cancel(scope, record.stamp)
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
        validate_continuation_publication_ack(record)?;
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
            publication_ack: record.publication_ack,
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
        validate_continuation_publication_ack(record)?;
        if record.service_owner.is_some() {
            return Err(InfrastructureError::InvalidState);
        }
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
            || parent_task.vm.map(VmAuthorityKey::generation)
                != Some(record.stamp.identity.vm_generation)
        {
            return Err(InfrastructureError::ForeignParent);
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
        let publication_ack = record.publication_ack;
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
        let index_slot = validate_continuation_reverse_index(scope, &record.stamp)?;
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
        let prepared = match next_phase {
            ContinuationPhase::Pending => PreparedContinuationAdoption::Pending,
            ContinuationPhase::Claimed { .. } => PreparedContinuationAdoption::Claimed,
            ContinuationPhase::Publishing {
                apply_generation,
                apply_nonce,
                publication_sequence,
                receipt,
                claim_generation,
                claim_nonce,
            } => PreparedContinuationAdoption::ReplayPublication(ContinuationPublicationPlan {
                descriptor: stamp.identity,
                claim_generation,
                claim_nonce,
                apply_generation,
                apply_nonce,
                publication_sequence,
                receipt,
            }),
            ContinuationPhase::Acknowledged { .. } => PreparedContinuationAdoption::Acknowledged,
            ContinuationPhase::Resuming {
                publication_sequence,
                outcome_digest,
                ack_generation,
                ack_nonce,
                resume_generation,
                resume_nonce,
            } => PreparedContinuationAdoption::ReplayResume(ContinuationResumePlan {
                descriptor: stamp.identity,
                publication_ack: publication_ack.ok_or(InfrastructureError::Invariant(
                    "resuming continuation is missing publication receipt",
                ))?,
                publication_sequence,
                outcome_digest,
                ack_generation,
                ack_nonce,
                resume_generation,
                resume_nonce,
            }),
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
        // The exact index was fully checked before the first mutation.  The
        // apply section is allocation-free and cannot fail under the same
        // exclusive ledger borrow.
        let index = scope.reverse_indexes.get_mut(index_slot).unwrap();
        index.binding_epoch = context.domain.binding_epoch;
        index.source_binding_epoch = Some(current_source_binding_epoch);
        scope.next_nonce = next_nonce;
        scope.revision = next_revision;
        scope.events.push(
            InfrastructureEventKind::ContinuationClaimed,
            continuation_id,
            generation,
        );
        let record = scope.continuations.get(continuation_id).unwrap();
        Ok(match prepared {
            PreparedContinuationAdoption::Pending => {
                ContinuationAdoption::Pending(ContinuationLease(mint_continuation_key::<
                    bearer_state::ContinuationPending,
                >(record)))
            }
            PreparedContinuationAdoption::Claimed => {
                ContinuationAdoption::Claimed(WakeClaim(mint_continuation_key::<
                    bearer_state::ContinuationClaimed,
                >(record)))
            }
            PreparedContinuationAdoption::ReplayPublication(plan) => {
                ContinuationAdoption::ReplayPublication(ContinuationPublicationIntent {
                    authority: ContinuationPublicationAuthority(mint_continuation_key::<
                        bearer_state::ContinuationPublishing,
                    >(record)),
                    plan,
                })
            }
            PreparedContinuationAdoption::Acknowledged => {
                ContinuationAdoption::Acknowledged(ContinuationAckReceipt(mint_continuation_key::<
                    bearer_state::ContinuationAcknowledged,
                >(record)))
            }
            PreparedContinuationAdoption::ReplayResume(plan) => {
                ContinuationAdoption::ReplayResume(ContinuationResumeIntent {
                    authority: ContinuationResumeAuthority(mint_continuation_key::<
                        bearer_state::ContinuationResuming,
                    >(record)),
                    plan,
                })
            }
        })
    }
}

pub(super) fn validate_continuation_publication_ack(
    record: &ContinuationRecord,
) -> Result<(), InfrastructureError> {
    let expected_publication = match record.phase {
        ContinuationPhase::Pending
        | ContinuationPhase::Claimed { .. }
        | ContinuationPhase::Publishing { .. }
        | ContinuationPhase::Cancelled => None,
        ContinuationPhase::Acknowledged {
            publication_sequence,
            outcome_digest,
            ..
        }
        | ContinuationPhase::Resuming {
            publication_sequence,
            outcome_digest,
            ..
        } => Some((publication_sequence, outcome_digest)),
        ContinuationPhase::Resumed {
            publication_sequence,
            receipt,
        } => {
            if receipt.continuation_id != record.stamp.identity.continuation_id
                || receipt.generation != record.stamp.identity.generation
                || receipt.publication_sequence != publication_sequence
                || receipt.vm_generation != record.stamp.identity.vm_generation
                || receipt.source_domain != record.stamp.identity.source_domain
                || receipt.source_binding_epoch != record.stamp.identity.source_binding_epoch
                || receipt.ack_generation == 0
                || receipt.ack_generation != record.ack_generation
                || receipt.ack_nonce == 0
                || receipt.resume_generation == 0
                || receipt.resume_generation != record.resume_generation
                || receipt.resume_nonce == 0
                || receipt.external_receipt_digest == 0
            {
                return Err(InfrastructureError::Invariant(
                    "resumed continuation receipt mismatch",
                ));
            }
            Some((publication_sequence, receipt.outcome_digest))
        }
    };

    let Some((publication_sequence, outcome_digest)) = expected_publication else {
        return if record.publication_ack.is_none() {
            Ok(())
        } else {
            Err(InfrastructureError::Invariant(
                "pre-ack continuation retains publication acknowledgement",
            ))
        };
    };
    let ack = record
        .publication_ack
        .ok_or(InfrastructureError::Invariant(
            "post-ack continuation is missing publication acknowledgement",
        ))?;
    if ack.claim_generation == 0
        || ack.continuation_id != record.stamp.identity.continuation_id
        || ack.generation != record.stamp.identity.generation
        || ack.claim_generation != record.claim_generation
        || ack.claim_nonce == 0
        || ack.apply_generation == 0
        || ack.apply_generation != record.apply_generation
        || ack.apply_nonce == 0
        || ack.publication_sequence == 0
        || ack.publication_sequence != publication_sequence
        || ack.vm_generation != record.stamp.identity.vm_generation
        || ack.source_domain != record.stamp.identity.source_domain
        || ack.source_binding_epoch == 0
        || ack.source_binding_epoch < record.origin_source.binding_epoch
        || ack.source_binding_epoch > record.stamp.identity.source_binding_epoch
        || ack.outcome_digest == 0
        || ack.outcome_digest != outcome_digest
        || ack.external_receipt_digest == 0
    {
        return Err(InfrastructureError::Invariant(
            "continuation publication acknowledgement mismatch",
        ));
    }
    Ok(())
}

fn validate_continuation_reverse_index(
    scope: &ScopeInfrastructure,
    stamp: &BearerStamp<ContinuationDescriptor>,
) -> Result<u64, InfrastructureError> {
    let parent = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    let index = scope
        .reverse_indexes
        .get(stamp.nonce)
        .ok_or(InfrastructureError::Invariant(
            "missing continuation reverse index",
        ))?;
    if index.slot != stamp.nonce
        || index.kind != InfrastructureKind::Continuation
        || index.root_effect != stamp.root.root_effect
        || index.parent != ReverseParent::Task(parent)
        || index.task != Some(parent.task)
        || index.domain != stamp.domain.domain
        || index.binding_epoch != stamp.domain.binding_epoch
        || index.source_domain != Some(stamp.identity.source_domain)
        || index.source_binding_epoch != Some(stamp.identity.source_binding_epoch)
        || index.resource.is_some()
        || index.actor_slot.is_some()
        || index.retry_generation != stamp.identity.generation
    {
        return Err(InfrastructureError::Invariant(
            "continuation reverse index mismatch",
        ));
    }
    Ok(stamp.nonce)
}

fn finish_continuation_cancel(
    scope: &mut ScopeInfrastructure,
    stamp: BearerStamp<ContinuationDescriptor>,
) -> Result<(), InfrastructureError> {
    let bearer_generation = next_continuation_bearer_generation(
        scope
            .continuations
            .get(stamp.identity.continuation_id)
            .ok_or(InfrastructureError::UnknownObligation)?,
    )?;
    let next_revision = preview_revision(scope)?;
    let next_live = checked_sub(scope.live.continuations, 1)?;
    let next_workload_children = preview_workload_child_sub(scope, stamp.workload.request)?;
    let parent_task = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    let next_task_children = preview_task_child_sub(scope, parent_task)?;
    let record = scope
        .continuations
        .get_mut(stamp.identity.continuation_id)
        .unwrap();
    record.stamp.bearer_generation = bearer_generation;
    record.phase = ContinuationPhase::Cancelled;
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
