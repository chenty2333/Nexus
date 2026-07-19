// SPDX-License-Identifier: MPL-2.0

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use super::{
    BearerKey, BearerStamp, EnteredTaskLease, InfrastructureError, InfrastructureEventKind,
    InfrastructureKind, InfrastructureState, LinearResult, ParentStamp, ReplyAbortAuthority,
    ReplyAckReceipt, ReplyAdoption, ReplyClaim, ReplyCompletionReceipt, ReplyDescriptor,
    ReplyPhase, ReplyPublicationIntent, ReplyPublicationReceipt, ReplyRecord,
    ReplyRecoveryProjection, ReplyRecoveryState, ReplyStateRecord, RequestKey, ReverseIndexRecord,
    ReverseParent, ScopeInfrastructure, TaskPhase, ValidatedCommitProof, VmAuthorityKey,
    WorkloadContext, bearer_state, checked_add, checked_sub, context_from_stamp,
    install_task_child_count, linear_apply, preview_bearer_stamp, preview_nonce, preview_nonces,
    preview_revision, preview_task_child_add, preview_task_child_sub, preview_workload_child_add,
    preview_workload_child_sub, require_vacancy, validate_active_admission, validate_context,
    validate_task_child_stamp, validate_task_key, validate_task_stamp,
};

enum PreparedReplyAdoption {
    Prepared,
    Claimed,
    Publishing,
    Acknowledged,
}

struct PreparedReplyFinish {
    reply_id: u64,
    workload_request: RequestKey,
    parent_task: super::TaskWorkDescriptor,
    bearer_generation: u64,
    next_revision: u64,
    next_live: u32,
    next_workload_children: u32,
    next_task_children: u32,
    terminal: ReplyPhase,
}

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
            if task.0.authority.registry_instance != registry_instance {
                return Err(InfrastructureError::ForeignRegistry);
            }
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
            validate_reply_backend_commit(registry_instance, task_stamp.root, commit)?;
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
            if scope.reverse_indexes.get(stamp.nonce).is_some() {
                return Err(InfrastructureError::IdentityConflict);
            }
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

            // Both fixed-slot vacancies and every fallible counter successor
            // were established above. This exclusive apply cannot fail.
            scope
                .replies
                .install(
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
                )
                .unwrap();
            scope
                .reverse_indexes
                .install(index, InfrastructureKind::Reply)
                .unwrap();
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
            Ok(ReplyRecord(mint_reply_key::<bearer_state::ReplyPrepared>(
                scope.replies.get(descriptor.reply_id).unwrap(),
            )))
        })
    }

    pub(in super::super) fn claim_reply(
        &mut self,
        reply: ReplyRecord,
    ) -> LinearResult<ReplyRecord, ReplyClaim> {
        linear_apply(reply, |reply| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            reject_foreign_reply_registry(registry_instance, &reply.0)?;
            let scope = self.scope_mut(reply.0.authority.scope)?;
            let (record, terminal_parent) = validate_reply_key(scope, registry_instance, &reply.0)?;
            if terminal_parent {
                return Err(InfrastructureError::InvalidState);
            }
            if record.phase != ReplyPhase::Prepared {
                return Err(InfrastructureError::InvalidState);
            }
            let claim_generation = record
                .claim_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let bearer_generation = next_reply_bearer_generation(record)?;
            let reply_id = record.stamp.identity.reply_id;
            let generation = record.stamp.identity.generation;
            let (claim_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;

            let record = scope.replies.get_mut(reply_id).unwrap();
            record.claim_generation = claim_generation;
            record.stamp.bearer_generation = bearer_generation;
            record.phase = ReplyPhase::Claimed {
                claim_generation,
                claim_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope
                .events
                .push(InfrastructureEventKind::ReplyClaimed, reply_id, generation);
            Ok(ReplyClaim(mint_reply_key::<bearer_state::ReplyClaimed>(
                scope.replies.get(reply_id).unwrap(),
            )))
        })
    }

    pub(in super::super) fn begin_reply_publication(
        &mut self,
        claim: ReplyClaim,
    ) -> LinearResult<ReplyClaim, ReplyPublicationIntent> {
        linear_apply(claim, |claim| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            reject_foreign_reply_registry(registry_instance, &claim.0)?;
            let scope = self.scope_mut(claim.0.authority.scope)?;
            let (record, terminal_parent) = validate_reply_key(scope, registry_instance, &claim.0)?;
            if terminal_parent {
                return Err(InfrastructureError::InvalidState);
            }
            let (claim_generation, claim_nonce) = match record.phase {
                ReplyPhase::Claimed {
                    claim_generation,
                    claim_nonce,
                } => (claim_generation, claim_nonce),
                _ => return Err(InfrastructureError::StaleClaim),
            };
            let apply_generation = record
                .apply_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let bearer_generation = next_reply_bearer_generation(record)?;
            let reply_id = record.stamp.identity.reply_id;
            let generation = record.stamp.identity.generation;
            let (apply_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;

            let record = scope.replies.get_mut(reply_id).unwrap();
            record.apply_generation = apply_generation;
            record.stamp.bearer_generation = bearer_generation;
            record.phase = ReplyPhase::Publishing {
                claim_generation,
                claim_nonce,
                apply_generation,
                apply_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ReplyPublishing,
                reply_id,
                generation,
            );
            Ok(ReplyPublicationIntent(mint_reply_key::<
                bearer_state::ReplyPublishing,
            >(
                scope.replies.get(reply_id).unwrap(),
            )))
        })
    }

    pub(in super::super) fn acknowledge_reply_publication(
        &mut self,
        intent: ReplyPublicationIntent,
        receipt: ReplyPublicationReceipt,
    ) -> LinearResult<ReplyPublicationIntent, ReplyAckReceipt> {
        linear_apply(intent, |intent| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            reject_foreign_reply_registry(registry_instance, &intent.0)?;
            let scope = self.scope_mut(intent.0.authority.scope)?;
            let (record, _) = validate_reply_key(scope, registry_instance, &intent.0)?;
            if !__cser_core::matches!(record.phase, ReplyPhase::Publishing { .. }) {
                return Err(InfrastructureError::StaleClaim);
            }
            validate_reply_publication_receipt(record, receipt)?;
            let ack_generation = record
                .ack_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let bearer_generation = next_reply_bearer_generation(record)?;
            let reply_id = record.stamp.identity.reply_id;
            let generation = record.stamp.identity.generation;
            let (ack_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;

            let record = scope.replies.get_mut(reply_id).unwrap();
            record.ack_generation = ack_generation;
            record.stamp.bearer_generation = bearer_generation;
            record.phase = ReplyPhase::Acknowledged {
                publication_receipt: receipt,
                ack_generation,
                ack_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ReplyAcknowledged,
                reply_id,
                generation,
            );
            Ok(ReplyAckReceipt(mint_reply_key::<
                bearer_state::ReplyAcknowledged,
            >(
                scope.replies.get(reply_id).unwrap()
            )))
        })
    }

    pub(in super::super) fn complete_reply_wake(
        &mut self,
        ack: ReplyAckReceipt,
    ) -> LinearResult<ReplyAckReceipt, ReplyCompletionReceipt> {
        linear_apply(ack, |ack| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            reject_foreign_reply_registry(registry_instance, &ack.0)?;
            let scope = self.scope_mut(ack.0.authority.scope)?;
            let (record, _) = validate_reply_key(scope, registry_instance, &ack.0)?;
            let publication_receipt = match record.phase {
                ReplyPhase::Acknowledged {
                    publication_receipt,
                    ..
                } => publication_receipt,
                _ => return Err(InfrastructureError::StaleClaim),
            };
            let completion = ReplyCompletionReceipt {
                reply_id: record.stamp.identity.reply_id,
                generation: record.stamp.identity.generation,
                backend_effect: record.backend_commit.effect,
                backend_commit_sequence: record.backend_commit.sequence,
                external_apply_digest: publication_receipt.external_apply_digest,
            };
            let finish = prepare_reply_finish(
                scope,
                record,
                ReplyPhase::Completed {
                    receipt: completion,
                },
            )?;
            apply_reply_finish(scope, finish);
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
            let registry_instance = self.registry_instance;
            let (scope_key, prepared) = match authority {
                ReplyAbortAuthority::Prepared(reply) => {
                    reject_foreign_reply_registry(registry_instance, &reply.0)?;
                    (reply.0.authority.scope, true)
                }
                ReplyAbortAuthority::Claimed(claim) => {
                    reject_foreign_reply_registry(registry_instance, &claim.0)?;
                    (claim.0.authority.scope, false)
                }
            };
            let scope = self.scope_mut(scope_key)?;
            let record = match authority {
                ReplyAbortAuthority::Prepared(reply) => {
                    validate_reply_key(scope, registry_instance, &reply.0)?.0
                }
                ReplyAbortAuthority::Claimed(claim) => {
                    validate_reply_key(scope, registry_instance, &claim.0)?.0
                }
            };
            let phase_matches = if prepared {
                record.phase == ReplyPhase::Prepared
            } else {
                __cser_core::matches!(record.phase, ReplyPhase::Claimed { .. })
            };
            if !phase_matches {
                return Err(InfrastructureError::InvalidState);
            }
            let finish =
                prepare_reply_finish(scope, record, ReplyPhase::Cancelled { evidence_digest })?;
            apply_reply_finish(scope, finish);
            Ok(())
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
        if context.root.registry_instance != registry_instance {
            return Err(InfrastructureError::ForeignRegistry);
        }
        let scope = self.scope_mut(context.root.scope)?;
        validate_context(scope, registry_instance, context)?;
        let record = scope
            .replies
            .get(reply_id)
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
        record.stamp.identity.validate()?;
        validate_reply_stamp_coordinates(&record.stamp)?;
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
            || parent_task.role != super::TaskWorkRole::GuestSyscallWork
            || record.stamp.identity.guest_task != parent_task.task
            || parent_task.vm.map(VmAuthorityKey::generation)
                != Some(record.stamp.identity.guest_vm_generation)
        {
            return Err(InfrastructureError::ForeignParent);
        }
        if record.stamp.workload.request != context.workload.request
            || record.stamp.workload.nonce != context.workload.nonce
        {
            return Err(InfrastructureError::ForeignWorkload);
        }
        if record.stamp.workload.bearer_generation > context.workload.bearer_generation {
            return Err(InfrastructureError::StaleGeneration);
        }
        if record.stamp.domain.domain != context.domain.domain
            || record.stamp.domain.binding_epoch > context.domain.binding_epoch
            || record.stamp.identity.source_binding_epoch >= current_source_binding_epoch
            || scope.binding_epoch(record.stamp.identity.source_domain)?
                != current_source_binding_epoch
        {
            return Err(InfrastructureError::StaleBinding);
        }
        validate_reply_backend_commit(
            registry_instance,
            record.stamp.root,
            &record.backend_commit,
        )?;
        validate_reply_phase(record)?;
        validate_reply_reverse_index(scope, record)?;
        let previous_phase = record.phase;
        if __cser_core::matches!(
            previous_phase,
            ReplyPhase::Completed { .. } | ReplyPhase::Cancelled { .. }
        ) {
            return Err(InfrastructureError::InvalidState);
        }
        let bearer_generation = next_reply_bearer_generation(record)?;
        let claim_generation = if __cser_core::matches!(
            previous_phase,
            ReplyPhase::Claimed { .. } | ReplyPhase::Publishing { .. }
        ) {
            record
                .claim_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?
        } else {
            record.claim_generation
        };
        let apply_generation =
            if __cser_core::matches!(previous_phase, ReplyPhase::Publishing { .. }) {
                record
                    .apply_generation
                    .checked_add(1)
                    .ok_or(InfrastructureError::CounterOverflow)?
            } else {
                record.apply_generation
            };
        let ack_generation =
            if __cser_core::matches!(previous_phase, ReplyPhase::Acknowledged { .. }) {
                record
                    .ack_generation
                    .checked_add(1)
                    .ok_or(InfrastructureError::CounterOverflow)?
            } else {
                record.ack_generation
            };
        let nonce_count = match previous_phase {
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
        let (next_phase, prepared) = match previous_phase {
            ReplyPhase::Prepared => (ReplyPhase::Prepared, PreparedReplyAdoption::Prepared),
            ReplyPhase::Claimed { .. } => (
                ReplyPhase::Claimed {
                    claim_generation,
                    claim_nonce: nonces[0],
                },
                PreparedReplyAdoption::Claimed,
            ),
            ReplyPhase::Publishing { .. } => (
                ReplyPhase::Publishing {
                    claim_generation,
                    claim_nonce: nonces[0],
                    apply_generation,
                    apply_nonce: nonces[1],
                },
                PreparedReplyAdoption::Publishing,
            ),
            ReplyPhase::Acknowledged {
                publication_receipt,
                ..
            } => (
                ReplyPhase::Acknowledged {
                    publication_receipt,
                    ack_generation,
                    ack_nonce: nonces[0],
                },
                PreparedReplyAdoption::Acknowledged,
            ),
            ReplyPhase::Completed { .. } | ReplyPhase::Cancelled { .. } => {
                return Err(InfrastructureError::InvalidState);
            }
        };

        let record = scope.replies.get_mut(reply_id).unwrap();
        record.stamp = stamp;
        record.claim_generation = claim_generation;
        record.apply_generation = apply_generation;
        record.ack_generation = ack_generation;
        record.phase = next_phase;
        // The exact row was fully checked before the first mutation. This
        // allocation-free apply cannot fail under the exclusive scope borrow.
        let index = scope.reverse_indexes.get_mut(index_slot).unwrap();
        index.binding_epoch = context.domain.binding_epoch;
        index.source_binding_epoch = Some(current_source_binding_epoch);
        scope.next_nonce = next_nonce;
        scope.revision = next_revision;

        let record = scope.replies.get(reply_id).unwrap();
        Ok(match prepared {
            PreparedReplyAdoption::Prepared => ReplyAdoption::Prepared(ReplyRecord(
                mint_reply_key::<bearer_state::ReplyPrepared>(record),
            )),
            PreparedReplyAdoption::Claimed => {
                ReplyAdoption::Claimed(ReplyClaim(mint_reply_key::<bearer_state::ReplyClaimed>(
                    record,
                )))
            }
            PreparedReplyAdoption::Publishing => {
                ReplyAdoption::ReplayPublication(ReplyPublicationIntent(mint_reply_key::<
                    bearer_state::ReplyPublishing,
                >(record)))
            }
            PreparedReplyAdoption::Acknowledged => {
                ReplyAdoption::Acknowledged(ReplyAckReceipt(mint_reply_key::<
                    bearer_state::ReplyAcknowledged,
                >(record)))
            }
        })
    }
}

fn reject_foreign_reply_registry<State: bearer_state::Sealed>(
    registry_instance: u64,
    key: &BearerKey<State>,
) -> Result<(), InfrastructureError> {
    if key.authority.registry_instance != registry_instance {
        return Err(InfrastructureError::ForeignRegistry);
    }
    Ok(())
}

fn mint_reply_key<State: bearer_state::Sealed>(record: &ReplyStateRecord) -> BearerKey<State> {
    BearerKey {
        authority: super::AuthorityKey {
            registry_instance: record.stamp.root.registry_instance,
            scope: record.stamp.root.scope,
            authority_epoch: record.stamp.root.authority_epoch,
        },
        slot: record.stamp.identity.reply_id,
        object_generation: record.stamp.identity.generation,
        bearer_generation: record.stamp.bearer_generation,
        nonce: record.stamp.nonce,
        state: __cser_core::marker::PhantomData,
    }
}

fn validate_reply_key<'a, State: bearer_state::Sealed>(
    scope: &'a ScopeInfrastructure,
    registry_instance: u64,
    key: &BearerKey<State>,
) -> Result<(&'a ReplyStateRecord, bool), InfrastructureError> {
    if key.authority.registry_instance != registry_instance
        || scope.root.registry_instance != registry_instance
    {
        return Err(InfrastructureError::ForeignRegistry);
    }
    if key.authority.scope != scope.root.scope {
        return Err(InfrastructureError::ForeignScope);
    }
    if key.authority.authority_epoch != scope.root.authority_epoch {
        return Err(InfrastructureError::StaleAuthority);
    }
    let record = scope
        .replies
        .get(key.slot)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp.identity.reply_id != key.slot {
        return Err(InfrastructureError::IdentityConflict);
    }
    if record.stamp.identity.generation != key.object_generation
        || record.stamp.bearer_generation != key.bearer_generation
        || record.stamp.nonce != key.nonce
    {
        return Err(InfrastructureError::StaleGeneration);
    }
    let terminal_parent = validate_reply_record(scope, registry_instance, record)?;
    Ok((record, terminal_parent))
}

fn validate_reply_record(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    record: &ReplyStateRecord,
) -> Result<bool, InfrastructureError> {
    let stamp = &record.stamp;
    stamp.identity.validate()?;
    validate_reply_stamp_coordinates(stamp)?;
    let terminal_parent = validate_task_child_stamp(scope, registry_instance, stamp)?;
    let parent = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    if parent.role != super::TaskWorkRole::GuestSyscallWork
        || stamp.identity.guest_task != parent.task
        || parent.vm.map(VmAuthorityKey::generation) != Some(stamp.identity.guest_vm_generation)
    {
        return Err(InfrastructureError::ForeignParent);
    }
    let source_binding_epoch = scope.binding_epoch(stamp.identity.source_domain)?;
    if (!terminal_parent && source_binding_epoch != stamp.identity.source_binding_epoch)
        || (terminal_parent && source_binding_epoch < stamp.identity.source_binding_epoch)
    {
        return Err(InfrastructureError::StaleBinding);
    }
    validate_reply_backend_commit(registry_instance, stamp.root, &record.backend_commit)?;
    validate_reply_phase(record)?;
    validate_reply_reverse_index(scope, record)?;
    Ok(terminal_parent)
}

fn validate_reply_stamp_coordinates(
    stamp: &BearerStamp<ReplyDescriptor>,
) -> Result<(), InfrastructureError> {
    if stamp.nonce == 0
        || stamp.bearer_generation == 0
        || stamp.domain.binding_epoch == 0
        || stamp.workload.nonce == 0
        || stamp.workload.bearer_generation == 0
    {
        return Err(InfrastructureError::InvalidIdentity);
    }
    Ok(())
}

fn validate_reply_backend_commit(
    registry_instance: u64,
    root: super::RootStamp,
    commit: &super::super::CommitReceipt,
) -> Result<(), InfrastructureError> {
    if commit.registry_instance_id != registry_instance
        || commit.scope != root.scope
        || commit.authority_epoch != root.authority_epoch
        || commit.effect.generation() == 0
        || commit.binding_epoch == 0
        || commit.sequence == 0
    {
        return Err(InfrastructureError::InvalidReceipt);
    }
    Ok(())
}

fn validate_reply_phase(record: &ReplyStateRecord) -> Result<(), InfrastructureError> {
    match record.phase {
        ReplyPhase::Prepared => {
            if record.claim_generation != 0
                || record.apply_generation != 0
                || record.ack_generation != 0
            {
                return Err(InfrastructureError::Invariant(
                    "prepared reply retains phase generation",
                ));
            }
        }
        ReplyPhase::Claimed {
            claim_generation,
            claim_nonce,
        } => {
            if claim_generation == 0
                || claim_generation != record.claim_generation
                || claim_nonce == 0
                || record.apply_generation != 0
                || record.ack_generation != 0
            {
                return Err(InfrastructureError::Invariant("reply claim mismatch"));
            }
        }
        ReplyPhase::Publishing {
            claim_generation,
            claim_nonce,
            apply_generation,
            apply_nonce,
        } => {
            if claim_generation == 0
                || claim_generation != record.claim_generation
                || claim_nonce == 0
                || apply_generation == 0
                || apply_generation != record.apply_generation
                || apply_nonce == 0
                || record.ack_generation != 0
            {
                return Err(InfrastructureError::Invariant(
                    "reply publication claim mismatch",
                ));
            }
        }
        ReplyPhase::Acknowledged {
            publication_receipt,
            ack_generation,
            ack_nonce,
        } => {
            if record.claim_generation == 0
                || record.apply_generation == 0
                || ack_generation == 0
                || ack_generation != record.ack_generation
                || ack_nonce == 0
            {
                return Err(InfrastructureError::Invariant(
                    "reply acknowledgement mismatch",
                ));
            }
            validate_reply_publication_receipt(record, publication_receipt)?;
        }
        ReplyPhase::Completed { receipt } => {
            if record.claim_generation == 0
                || record.apply_generation == 0
                || record.ack_generation == 0
                || receipt.reply_id != record.stamp.identity.reply_id
                || receipt.generation != record.stamp.identity.generation
                || receipt.backend_effect != record.backend_commit.effect
                || receipt.backend_commit_sequence != record.backend_commit.sequence
                || receipt.external_apply_digest == 0
            {
                return Err(InfrastructureError::Invariant(
                    "reply completion receipt mismatch",
                ));
            }
        }
        ReplyPhase::Cancelled { evidence_digest } => {
            if evidence_digest == 0 || record.apply_generation != 0 || record.ack_generation != 0 {
                return Err(InfrastructureError::Invariant(
                    "reply cancellation evidence mismatch",
                ));
            }
        }
    }
    Ok(())
}

fn validate_reply_publication_receipt(
    record: &ReplyStateRecord,
    receipt: ReplyPublicationReceipt,
) -> Result<(), InfrastructureError> {
    let descriptor = record.stamp.identity;
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
    Ok(())
}

fn validate_reply_reverse_index(
    scope: &ScopeInfrastructure,
    record: &ReplyStateRecord,
) -> Result<u64, InfrastructureError> {
    let stamp = record.stamp;
    let parent = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    let index = scope
        .reverse_indexes
        .get(stamp.nonce)
        .ok_or(InfrastructureError::Invariant(
            "missing reply reverse index",
        ))?;
    if index.slot != stamp.nonce
        || index.kind != InfrastructureKind::Reply
        || index.root_effect != stamp.root.root_effect
        || index.parent != ReverseParent::Task(parent)
        || index.task != Some(stamp.identity.guest_task)
        || index.domain != stamp.domain.domain
        || index.binding_epoch != stamp.domain.binding_epoch
        || index.source_domain != Some(stamp.identity.source_domain)
        || index.source_binding_epoch != Some(stamp.identity.source_binding_epoch)
        || index.resource.is_some()
        || index.actor_slot != Some(stamp.identity.payload_slot)
        || index.actor_generation != Some(stamp.identity.payload_generation)
        || index.retry_generation != stamp.identity.generation
    {
        return Err(InfrastructureError::Invariant(
            "reply reverse index mismatch",
        ));
    }
    Ok(stamp.nonce)
}

fn next_reply_bearer_generation(record: &ReplyStateRecord) -> Result<u64, InfrastructureError> {
    record
        .stamp
        .bearer_generation
        .checked_add(1)
        .ok_or(InfrastructureError::CounterOverflow)
}

fn prepare_reply_finish(
    scope: &ScopeInfrastructure,
    record: &ReplyStateRecord,
    terminal: ReplyPhase,
) -> Result<PreparedReplyFinish, InfrastructureError> {
    let stamp = record.stamp;
    let parent_task = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    Ok(PreparedReplyFinish {
        reply_id: stamp.identity.reply_id,
        workload_request: stamp.workload.request,
        parent_task,
        bearer_generation: next_reply_bearer_generation(record)?,
        next_revision: preview_revision(scope)?,
        next_live: checked_sub(scope.live.replies, 1)?,
        next_workload_children: preview_workload_child_sub(scope, stamp.workload.request)?,
        next_task_children: preview_task_child_sub(scope, parent_task)?,
        terminal,
    })
}

fn apply_reply_finish(scope: &mut ScopeInfrastructure, finish: PreparedReplyFinish) {
    let record = scope.replies.get_mut(finish.reply_id).unwrap();
    record.stamp.bearer_generation = finish.bearer_generation;
    record.phase = finish.terminal;
    scope.revision = finish.next_revision;
    scope.live.replies = finish.next_live;
    scope
        .workloads
        .get_mut(finish.workload_request.id)
        .unwrap()
        .live_children = finish.next_workload_children;
    install_task_child_count(
        scope.tasks.get_mut(finish.parent_task.work_id).unwrap(),
        finish.next_task_children,
    );
}
