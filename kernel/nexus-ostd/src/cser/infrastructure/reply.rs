// SPDX-License-Identifier: MPL-2.0

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use super::{
    BearerStamp, EnteredTaskLease, InfrastructureError, InfrastructureEventKind,
    InfrastructureKind, InfrastructureState, LinearResult, ParentStamp, ReplyAbortAuthority,
    ReplyAckReceipt, ReplyAdoption, ReplyClaim, ReplyCompletionReceipt, ReplyDescriptor,
    ReplyPhase, ReplyPublicationIntent, ReplyPublicationReceipt, ReplyRecord,
    ReplyRecoveryProjection, ReplyRecoveryState, ReplyStateRecord, ReverseIndexRecord,
    ReverseParent, ScopeInfrastructure, TaskPhase, ValidatedCommitProof, VmAuthorityKey,
    WorkloadContext, checked_add, checked_sub, context_from_stamp, install_task_child_count,
    linear_apply, preview_bearer_stamp, preview_nonce, preview_nonces, preview_revision,
    preview_task_child_add, preview_task_child_sub, preview_workload_child_add,
    preview_workload_child_sub, require_vacancy, validate_active_admission, validate_context,
    validate_task_child_stamp, validate_task_key,
};

impl InfrastructureState {
    pub(in super::super) fn prepare_reply(
        &mut self,
        task: &EnteredTaskLease,
        descriptor: ReplyDescriptor,
        proof: ValidatedCommitProof,
    ) -> LinearResult<ValidatedCommitProof, ReplyRecord> {
        linear_apply(proof, |proof| {
            self.require_authoritative()?;
            descriptor.validate()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(task.0.authority.scope)?;
            let task_record = validate_task_key(scope, registry_instance, &task.0)?;
            let task_stamp = task_record.stamp;
            validate_active_admission(scope)?;
            if task_record.phase != TaskPhase::Entered
                || task_record.stamp.identity.role != super::TaskWorkRole::GuestSyscallWork
                || descriptor.guest_task != task_stamp.identity.task
                || task_stamp.identity.vm.map(VmAuthorityKey::generation)
                    != Some(descriptor.guest_vm_generation)
            {
                return Err(InfrastructureError::ForeignParent);
            }
            if scope.binding_epoch(descriptor.source_domain)? != descriptor.source_binding_epoch {
                return Err(InfrastructureError::StaleBinding);
            }
            let commit = &proof.receipt;
            if commit.registry_instance_id != registry_instance
                || commit.scope != task_stamp.root.scope
                || commit.authority_epoch != task_stamp.root.authority_epoch
                || commit.sequence == 0
                || commit.effect.generation() == 0
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            if let Some(existing) = scope.replies.get(descriptor.reply_id) {
                return if existing.stamp.identity == descriptor
                    && existing.backend_commit == *commit
                    && existing.stamp.parent == ParentStamp::Task(task_stamp.identity)
                {
                    Err(InfrastructureError::ExactReplay)
                } else if existing.stamp.identity.generation > descriptor.generation {
                    Err(InfrastructureError::StaleGeneration)
                } else {
                    Err(InfrastructureError::IdentityConflict)
                };
            }
            if scope.replies.iter().any(|record| {
                !__cser_core::matches!(
                    record.phase,
                    ReplyPhase::Completed { .. } | ReplyPhase::Cancelled { .. }
                ) && (record.stamp.identity.payload_slot == descriptor.payload_slot
                    || record.stamp.identity.flight_cookie == descriptor.flight_cookie)
            }) {
                return Err(InfrastructureError::IdentityConflict);
            }
            require_vacancy(
                &scope.replies,
                descriptor.reply_id,
                InfrastructureKind::Reply,
            )?;
            let context = context_from_stamp(scope, task_stamp.workload)?;
            let (stamp, next_nonce) = preview_bearer_stamp(
                scope,
                &context,
                descriptor,
                ParentStamp::Task(task_stamp.identity),
            )?;
            require_vacancy(
                &scope.reverse_indexes,
                stamp.nonce,
                InfrastructureKind::Reply,
            )?;
            let next_revision = preview_revision(scope)?;
            let next_live = checked_add(scope.live.replies, 1)?;
            let next_workload_children = preview_workload_child_add(scope, stamp.workload.request)?;
            let next_task_children = preview_task_child_add(scope, task_stamp.identity)?;
            let index = ReverseIndexRecord {
                slot: stamp.nonce,
                kind: InfrastructureKind::Reply,
                root_effect: stamp.root.root_effect,
                parent: ReverseParent::Task(task_stamp.identity),
                task: Some(descriptor.guest_task),
                domain: stamp.domain.domain,
                binding_epoch: stamp.domain.binding_epoch,
                source_domain: Some(descriptor.source_domain),
                source_binding_epoch: Some(descriptor.source_binding_epoch),
                resource: None,
                actor_slot: Some(descriptor.payload_slot),
                actor_generation: Some(descriptor.payload_generation),
                retry_generation: descriptor.generation,
            };
            scope.replies.install(
                ReplyStateRecord {
                    stamp,
                    backend_commit: commit.clone(),
                    claim_generation: 0,
                    apply_generation: 0,
                    ack_generation: 0,
                    phase: ReplyPhase::Prepared,
                    closure_sequence: None,
                },
                InfrastructureKind::Reply,
            )?;
            scope
                .reverse_indexes
                .install(index, InfrastructureKind::Reply)?;
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.live.replies = next_live;
            scope
                .workloads
                .get_mut(stamp.workload.request.id)
                .unwrap()
                .live_children = next_workload_children;
            scope
                .tasks
                .get_mut(task_stamp.identity.work_id)
                .unwrap()
                .live_children = next_task_children;
            scope.events.push(
                InfrastructureEventKind::ReplyPrepared,
                descriptor.reply_id,
                descriptor.generation,
            );
            Ok(ReplyRecord(stamp))
        })
    }

    pub(in super::super) fn claim_reply(
        &mut self,
        reply: ReplyRecord,
    ) -> LinearResult<ReplyRecord, ReplyClaim> {
        linear_apply(reply, |reply| {
            self.require_authoritative()?;
            let stamp = reply.0;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_reply_bearer(scope, registry_instance, &stamp)?;
            let record = scope.replies.get(stamp.identity.reply_id).unwrap();
            if validate_task_child_stamp(scope, registry_instance, &record.stamp)? {
                return Err(InfrastructureError::InvalidState);
            }
            if record.phase != ReplyPhase::Prepared {
                return Err(InfrastructureError::InvalidState);
            }
            let claim_generation = record
                .claim_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let (claim_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let record = scope.replies.get_mut(stamp.identity.reply_id).unwrap();
            record.claim_generation = claim_generation;
            record.phase = ReplyPhase::Claimed {
                claim_generation,
                claim_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ReplyClaimed,
                stamp.identity.reply_id,
                stamp.identity.generation,
            );
            Ok(ReplyClaim {
                reply: stamp,
                claim_generation,
                claim_nonce,
            })
        })
    }

    pub(in super::super) fn begin_reply_publication(
        &mut self,
        claim: ReplyClaim,
    ) -> LinearResult<ReplyClaim, ReplyPublicationIntent> {
        linear_apply(claim, |claim| {
            self.require_authoritative()?;
            let stamp = claim.reply;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_reply_bearer(scope, registry_instance, &stamp)?;
            let record = scope.replies.get(stamp.identity.reply_id).unwrap();
            if validate_task_child_stamp(scope, registry_instance, &record.stamp)? {
                return Err(InfrastructureError::InvalidState);
            }
            if record.phase
                != (ReplyPhase::Claimed {
                    claim_generation: claim.claim_generation,
                    claim_nonce: claim.claim_nonce,
                })
            {
                return Err(InfrastructureError::StaleClaim);
            }
            let apply_generation = record
                .apply_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let (apply_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let record = scope.replies.get_mut(stamp.identity.reply_id).unwrap();
            record.apply_generation = apply_generation;
            record.phase = ReplyPhase::Publishing {
                claim_generation: claim.claim_generation,
                claim_nonce: claim.claim_nonce,
                apply_generation,
                apply_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ReplyPublishing,
                stamp.identity.reply_id,
                stamp.identity.generation,
            );
            Ok(ReplyPublicationIntent {
                reply: stamp,
                claim_generation: claim.claim_generation,
                claim_nonce: claim.claim_nonce,
                apply_generation,
                apply_nonce,
            })
        })
    }

    pub(in super::super) fn acknowledge_reply_publication(
        &mut self,
        intent: ReplyPublicationIntent,
        receipt: ReplyPublicationReceipt,
    ) -> LinearResult<ReplyPublicationIntent, ReplyAckReceipt> {
        linear_apply(intent, |intent| {
            self.require_authoritative()?;
            let stamp = intent.reply;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_reply_bearer(scope, registry_instance, &stamp)?;
            let record = scope.replies.get(stamp.identity.reply_id).unwrap();
            if record.phase
                != (ReplyPhase::Publishing {
                    claim_generation: intent.claim_generation,
                    claim_nonce: intent.claim_nonce,
                    apply_generation: intent.apply_generation,
                    apply_nonce: intent.apply_nonce,
                })
            {
                return Err(InfrastructureError::StaleClaim);
            }
            let descriptor = stamp.identity;
            if receipt.payload_slot != descriptor.payload_slot
                || receipt.payload_generation != descriptor.payload_generation
                || receipt.flight_cookie != descriptor.flight_cookie
                || receipt.descriptor_digest != descriptor.descriptor_digest
                || receipt.result_digest != descriptor.result_digest
                || receipt.byte_count != descriptor.byte_count
                || receipt.destination_digest != descriptor.destination_digest
                || receipt.backend_effect != record.backend_commit.effect
                || receipt.backend_commit_sequence != record.backend_commit.sequence
                || receipt.external_apply_digest == 0
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let ack_generation = record
                .ack_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let (ack_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let backend_effect = record.backend_commit.effect;
            let backend_commit_sequence = record.backend_commit.sequence;
            let record = scope.replies.get_mut(stamp.identity.reply_id).unwrap();
            record.ack_generation = ack_generation;
            record.phase = ReplyPhase::Acknowledged {
                publication_receipt: receipt,
                ack_generation,
                ack_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ReplyAcknowledged,
                stamp.identity.reply_id,
                stamp.identity.generation,
            );
            Ok(ReplyAckReceipt {
                reply: stamp,
                backend_effect,
                backend_commit_sequence,
                publication_receipt: receipt,
                ack_generation,
                ack_nonce,
            })
        })
    }

    pub(in super::super) fn complete_reply_wake(
        &mut self,
        ack: ReplyAckReceipt,
    ) -> LinearResult<ReplyAckReceipt, ReplyCompletionReceipt> {
        linear_apply(ack, |ack| {
            self.require_authoritative()?;
            let stamp = ack.reply;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_reply_bearer(scope, registry_instance, &stamp)?;
            let record = scope.replies.get(stamp.identity.reply_id).unwrap();
            if record.backend_commit.effect != ack.backend_effect
                || record.backend_commit.sequence != ack.backend_commit_sequence
                || record.phase
                    != (ReplyPhase::Acknowledged {
                        publication_receipt: ack.publication_receipt,
                        ack_generation: ack.ack_generation,
                        ack_nonce: ack.ack_nonce,
                    })
            {
                return Err(InfrastructureError::StaleClaim);
            }
            let completion = ReplyCompletionReceipt {
                reply_id: stamp.identity.reply_id,
                generation: stamp.identity.generation,
                backend_effect: ack.backend_effect,
                backend_commit_sequence: ack.backend_commit_sequence,
                external_apply_digest: ack.publication_receipt.external_apply_digest,
            };
            finish_reply(
                scope,
                stamp,
                ReplyPhase::Completed {
                    receipt: completion,
                },
            )?;
            Ok(completion)
        })
    }

    pub(in super::super) fn cancel_reply(
        &mut self,
        authority: ReplyAbortAuthority,
        evidence_digest: u64,
    ) -> LinearResult<ReplyAbortAuthority, ()> {
        linear_apply(authority, |authority| {
            self.require_authoritative()?;
            if evidence_digest == 0 {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let (stamp, expected_phase) = match &authority {
                ReplyAbortAuthority::Prepared(reply) => (reply.0, ReplyPhase::Prepared),
                ReplyAbortAuthority::Claimed(claim) => (
                    claim.reply,
                    ReplyPhase::Claimed {
                        claim_generation: claim.claim_generation,
                        claim_nonce: claim.claim_nonce,
                    },
                ),
            };
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_reply_bearer(scope, registry_instance, &stamp)?;
            if scope.replies.get(stamp.identity.reply_id).unwrap().phase != expected_phase {
                return Err(InfrastructureError::InvalidState);
            }
            finish_reply(scope, stamp, ReplyPhase::Cancelled { evidence_digest })
        })
    }

    pub(in super::super) fn query_reply(
        &self,
        context: &WorkloadContext,
        reply_id: u64,
        generation: u64,
    ) -> Result<ReplyRecoveryProjection, InfrastructureError> {
        self.require_authoritative()?;
        let scope = self.scope(context.root.scope)?;
        validate_context(scope, self.registry_instance, context)?;
        let record = scope
            .replies
            .get(reply_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
        if record.stamp.identity.generation != generation {
            return Err(InfrastructureError::StaleGeneration);
        }
        if record.stamp.workload.request != context.workload.request {
            return Err(InfrastructureError::ForeignWorkload);
        }
        Ok(ReplyRecoveryProjection {
            descriptor: record.stamp.identity,
            backend_effect: record.backend_commit.effect,
            backend_commit_sequence: record.backend_commit.sequence,
            state: match record.phase {
                ReplyPhase::Prepared => ReplyRecoveryState::Prepared,
                ReplyPhase::Claimed { .. } => ReplyRecoveryState::Claimed,
                ReplyPhase::Publishing { .. } => ReplyRecoveryState::PublicationUncertain,
                ReplyPhase::Acknowledged { .. } => ReplyRecoveryState::AcknowledgedPendingWake,
                ReplyPhase::Completed { .. } => ReplyRecoveryState::Completed,
                ReplyPhase::Cancelled { .. } => ReplyRecoveryState::Cancelled,
            },
            claim_generation: record.claim_generation,
            publication_receipt: match record.phase {
                ReplyPhase::Acknowledged {
                    publication_receipt,
                    ..
                } => Some(publication_receipt),
                ReplyPhase::Completed { receipt } => Some(ReplyPublicationReceipt {
                    payload_slot: record.stamp.identity.payload_slot,
                    payload_generation: record.stamp.identity.payload_generation,
                    flight_cookie: record.stamp.identity.flight_cookie,
                    descriptor_digest: record.stamp.identity.descriptor_digest,
                    result_digest: record.stamp.identity.result_digest,
                    byte_count: record.stamp.identity.byte_count,
                    destination_digest: record.stamp.identity.destination_digest,
                    backend_effect: receipt.backend_effect,
                    backend_commit_sequence: receipt.backend_commit_sequence,
                    external_apply_digest: receipt.external_apply_digest,
                }),
                _ => None,
            },
            completion_receipt: match record.phase {
                ReplyPhase::Completed { receipt } => Some(receipt),
                _ => None,
            },
        })
    }

    pub(in super::super) fn adopt_reply_after_fence(
        &mut self,
        context: &WorkloadContext,
        reply_id: u64,
        generation: u64,
        current_source_binding_epoch: u64,
    ) -> Result<ReplyAdoption, InfrastructureError> {
        self.require_authoritative()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(context.root.scope)?;
        validate_context(scope, registry_instance, context)?;
        let record = scope
            .replies
            .get(reply_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
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
        let phase = record.phase;
        if __cser_core::matches!(
            phase,
            ReplyPhase::Completed { .. } | ReplyPhase::Cancelled { .. }
        ) {
            return Err(InfrastructureError::InvalidState);
        }
        let bearer_generation = record
            .stamp
            .bearer_generation
            .checked_add(1)
            .ok_or(InfrastructureError::CounterOverflow)?;
        let claim_generation = if __cser_core::matches!(
            phase,
            ReplyPhase::Claimed { .. } | ReplyPhase::Publishing { .. }
        ) {
            record
                .claim_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?
        } else {
            record.claim_generation
        };
        let apply_generation = if __cser_core::matches!(phase, ReplyPhase::Publishing { .. }) {
            record
                .apply_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?
        } else {
            record.apply_generation
        };
        let ack_generation = if __cser_core::matches!(phase, ReplyPhase::Acknowledged { .. }) {
            record
                .ack_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?
        } else {
            record.ack_generation
        };
        let nonce_count = match phase {
            ReplyPhase::Prepared => 0,
            ReplyPhase::Claimed { .. } | ReplyPhase::Acknowledged { .. } => 1,
            ReplyPhase::Publishing { .. } => 2,
            ReplyPhase::Completed { .. } | ReplyPhase::Cancelled { .. } => {
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
        let next_phase = match phase {
            ReplyPhase::Prepared => ReplyPhase::Prepared,
            ReplyPhase::Claimed { .. } => ReplyPhase::Claimed {
                claim_generation,
                claim_nonce: nonces[0],
            },
            ReplyPhase::Publishing { .. } => ReplyPhase::Publishing {
                claim_generation,
                claim_nonce: nonces[0],
                apply_generation,
                apply_nonce: nonces[1],
            },
            ReplyPhase::Acknowledged {
                publication_receipt,
                ..
            } => ReplyPhase::Acknowledged {
                publication_receipt,
                ack_generation,
                ack_nonce: nonces[0],
            },
            ReplyPhase::Completed { .. } | ReplyPhase::Cancelled { .. } => {
                return Err(InfrastructureError::InvalidState);
            }
        };
        let backend_effect = record.backend_commit.effect;
        let backend_commit_sequence = record.backend_commit.sequence;
        let record = scope.replies.get_mut(reply_id).unwrap();
        record.stamp = stamp;
        record.claim_generation = claim_generation;
        record.apply_generation = apply_generation;
        record.ack_generation = ack_generation;
        record.phase = next_phase;
        let index =
            scope
                .reverse_indexes
                .get_mut(index_slot)
                .ok_or(InfrastructureError::Invariant(
                    "missing reply reverse index",
                ))?;
        index.binding_epoch = context.domain.binding_epoch;
        index.source_binding_epoch = Some(current_source_binding_epoch);
        scope.next_nonce = next_nonce;
        scope.revision = next_revision;
        Ok(match next_phase {
            ReplyPhase::Prepared => ReplyAdoption::Prepared(ReplyRecord(stamp)),
            ReplyPhase::Claimed {
                claim_generation,
                claim_nonce,
            } => ReplyAdoption::Claimed(ReplyClaim {
                reply: stamp,
                claim_generation,
                claim_nonce,
            }),
            ReplyPhase::Publishing {
                claim_generation,
                claim_nonce,
                apply_generation,
                apply_nonce,
            } => ReplyAdoption::ReplayPublication(ReplyPublicationIntent {
                reply: stamp,
                claim_generation,
                claim_nonce,
                apply_generation,
                apply_nonce,
            }),
            ReplyPhase::Acknowledged {
                publication_receipt,
                ack_generation,
                ack_nonce,
            } => ReplyAdoption::Acknowledged(ReplyAckReceipt {
                reply: stamp,
                backend_effect,
                backend_commit_sequence,
                publication_receipt,
                ack_generation,
                ack_nonce,
            }),
            ReplyPhase::Completed { .. } | ReplyPhase::Cancelled { .. } => {
                return Err(InfrastructureError::Invariant("invalid reply adoption"));
            }
        })
    }
}

fn validate_reply_bearer(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    stamp: &BearerStamp<ReplyDescriptor>,
) -> Result<(), InfrastructureError> {
    let terminal_parent = validate_task_child_stamp(scope, registry_instance, stamp)?;
    let record = scope
        .replies
        .get(stamp.identity.reply_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp != *stamp {
        return Err(InfrastructureError::StaleGeneration);
    }
    let source_binding_epoch = scope.binding_epoch(stamp.identity.source_domain)?;
    if (!terminal_parent && source_binding_epoch != stamp.identity.source_binding_epoch)
        || (terminal_parent && source_binding_epoch < stamp.identity.source_binding_epoch)
    {
        return Err(InfrastructureError::StaleBinding);
    }
    let parent = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    if parent.vm.map(VmAuthorityKey::generation) != Some(stamp.identity.guest_vm_generation) {
        return Err(InfrastructureError::StaleGeneration);
    }
    Ok(())
}

fn finish_reply(
    scope: &mut ScopeInfrastructure,
    stamp: BearerStamp<ReplyDescriptor>,
    terminal: ReplyPhase,
) -> Result<(), InfrastructureError> {
    let next_revision = preview_revision(scope)?;
    let next_live = checked_sub(scope.live.replies, 1)?;
    let next_workload_children = preview_workload_child_sub(scope, stamp.workload.request)?;
    let parent_task = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    let next_task_children = preview_task_child_sub(scope, parent_task)?;
    scope
        .replies
        .get_mut(stamp.identity.reply_id)
        .unwrap()
        .phase = terminal;
    scope.revision = next_revision;
    scope.live.replies = next_live;
    scope
        .workloads
        .get_mut(stamp.workload.request.id)
        .unwrap()
        .live_children = next_workload_children;
    install_task_child_count(
        scope.tasks.get_mut(parent_task.work_id).unwrap(),
        next_task_children,
    );
    Ok(())
}
