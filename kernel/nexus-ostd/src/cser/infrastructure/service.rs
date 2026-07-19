// SPDX-License-Identifier: MPL-2.0

use super::{
    BearerStamp, BoundServiceRequest, ContinuationLease, ContinuationPhase, EnqueuedServiceRequest,
    EnteredTaskLease, InfrastructureError, InfrastructureEventKind, InfrastructureKind,
    InfrastructureState, LinearResult, ParentStamp, RequestKey, ReverseIndexRecord, ReverseParent,
    ScopeInfrastructure, ServiceArmIntent, ServiceArmReceipt, ServiceClaim,
    ServiceCompletionOutcome, ServiceCompletionReceipt, ServiceEnqueueIntent,
    ServiceEnqueueReceipt, ServiceRequestDescriptor, ServiceRequestPhase,
    ServiceRequestRecoveryProjection, ServiceRequestRecoveryState, ServiceRequestStateRecord,
    ServiceRequestTicket, TaskPhase, UnarmedServiceRequest, ValidatedAbortProof,
    ValidatedServiceChildProof, WorkloadContext, bearer_state, checked_add, checked_sub,
    context_from_stamp, linear_apply, mint_continuation_key, next_continuation_bearer_generation,
    preview_bearer_stamp, preview_nonce, preview_revision, preview_task_child_add,
    preview_task_child_sub, preview_workload_child_add, preview_workload_child_sub,
    require_vacancy, validate_active_admission, validate_context, validate_continuation_bearer,
    validate_continuation_key, validate_stamp_common, validate_task_stamp,
};

impl InfrastructureState {
    pub(in super::super) fn reserve_service_request(
        &mut self,
        task: &EnteredTaskLease,
        descriptor: ServiceRequestDescriptor,
    ) -> Result<ServiceRequestTicket, InfrastructureError> {
        self.require_authoritative()?;
        descriptor.validate()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(task.0.root.scope)?;
        validate_task_stamp(scope, registry_instance, &task.0)?;
        validate_active_admission(scope)?;
        if scope.tasks.get(task.0.identity.work_id).unwrap().phase != TaskPhase::Entered {
            return Err(InfrastructureError::ForeignParent);
        }
        if scope.binding_epoch(descriptor.destination_domain)?
            != descriptor.destination_binding_epoch
        {
            return Err(InfrastructureError::StaleBinding);
        }
        if let Some(existing) = scope.service_requests.get(descriptor.request_id) {
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
        if scope.service_requests.iter().any(|record| {
            service_request_phase_live(record.phase)
                && (record.stamp.identity.payload_slot == descriptor.payload_slot
                    || (record.stamp.identity.queue == descriptor.queue
                        && record.stamp.identity.response_slot_id == descriptor.response_slot_id))
        }) {
            return Err(InfrastructureError::IdentityConflict);
        }
        require_vacancy(
            &scope.service_requests,
            descriptor.request_id,
            InfrastructureKind::ServiceRequest,
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
            InfrastructureKind::ServiceRequest,
        )?;
        let next_revision = preview_revision(scope)?;
        let next_live = checked_add(scope.live.service_requests, 1)?;
        let next_workload_children = preview_workload_child_add(scope, stamp.workload.request)?;
        let next_task_children = preview_task_child_add(scope, task.0.identity)?;
        let index = ReverseIndexRecord {
            slot: stamp.nonce,
            kind: InfrastructureKind::ServiceRequest,
            root_effect: stamp.root.root_effect,
            parent: ReverseParent::Task(task.0.identity),
            task: Some(task.0.identity.task),
            domain: stamp.domain.domain,
            binding_epoch: stamp.domain.binding_epoch,
            source_domain: Some(descriptor.destination_domain),
            source_binding_epoch: Some(descriptor.destination_binding_epoch),
            resource: Some(descriptor.queue),
            actor_slot: Some(descriptor.payload_slot),
            retry_generation: descriptor.generation,
        };
        scope.service_requests.install(
            ServiceRequestStateRecord {
                stamp,
                bound_continuation: None,
                apply_generation: 0,
                arm_generation: 0,
                claim_generation: 0,
                phase: ServiceRequestPhase::ReservedUnbound,
                closure_sequence: None,
            },
            InfrastructureKind::ServiceRequest,
        )?;
        scope
            .reverse_indexes
            .install(index, InfrastructureKind::ServiceRequest)?;
        scope.next_nonce = next_nonce;
        scope.revision = next_revision;
        scope.live.service_requests = next_live;
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
            InfrastructureEventKind::ServiceRequestReserved,
            descriptor.request_id,
            descriptor.generation,
        );
        Ok(ServiceRequestTicket(stamp))
    }

    pub(in super::super) fn bind_service_response_continuation(
        &mut self,
        ticket: ServiceRequestTicket,
        continuation: ContinuationLease,
    ) -> LinearResult<(ServiceRequestTicket, ContinuationLease), ServiceRequestTicket> {
        linear_apply((ticket, continuation), |(ticket, continuation)| {
            self.require_authoritative()?;
            let stamp = ticket.0;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_service_request_bearer(scope, registry_instance, &stamp)?;
            let continuation_record =
                validate_continuation_key(scope, registry_instance, &continuation.0)?;
            let continuation_stamp = continuation_record.stamp;
            let request = scope
                .service_requests
                .get(stamp.identity.request_id)
                .unwrap();
            if request.phase != ServiceRequestPhase::ReservedUnbound
                || request.bound_continuation.is_some()
                || continuation_stamp.workload != stamp.workload
                || continuation_stamp.parent != stamp.parent
                || continuation_record.phase != ContinuationPhase::Pending
                || continuation_record.service_owner.is_some()
            {
                return Err(InfrastructureError::InvalidState);
            }
            let bearer_generation = next_continuation_bearer_generation(continuation_record)?;
            let continuation_id = continuation_stamp.identity.continuation_id;
            let next_revision = preview_revision(scope)?;
            let owner = RequestKey {
                id: stamp.identity.request_id,
                generation: stamp.identity.generation,
            };
            let continuation_record = scope.continuations.get_mut(continuation_id).unwrap();
            continuation_record.stamp.bearer_generation = bearer_generation;
            continuation_record.service_owner = Some(owner);
            let bound_continuation = continuation_record.stamp;
            let request = scope
                .service_requests
                .get_mut(stamp.identity.request_id)
                .unwrap();
            request.bound_continuation = Some(bound_continuation);
            request.phase = ServiceRequestPhase::ReservedBound;
            scope.revision = next_revision;
            Ok(ServiceRequestTicket(stamp))
        })
    }

    pub(in super::super) fn begin_service_enqueue(
        &mut self,
        ticket: ServiceRequestTicket,
    ) -> LinearResult<ServiceRequestTicket, ServiceEnqueueIntent> {
        linear_apply(ticket, |ticket| {
            self.require_authoritative()?;
            let stamp = ticket.0;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_service_request_bearer(scope, registry_instance, &stamp)?;
            let record = scope
                .service_requests
                .get(stamp.identity.request_id)
                .unwrap();
            let bound_continuation = record
                .bound_continuation
                .ok_or(InfrastructureError::InvalidState)?;
            if record.phase != ServiceRequestPhase::ReservedBound
                || scope
                    .continuations
                    .get(bound_continuation.identity.continuation_id)
                    .is_none_or(|continuation| {
                        continuation.stamp != bound_continuation
                            || continuation.phase != ContinuationPhase::Pending
                    })
            {
                return Err(InfrastructureError::InvalidState);
            }
            let apply_generation = record
                .apply_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let (apply_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let record = scope
                .service_requests
                .get_mut(stamp.identity.request_id)
                .unwrap();
            record.apply_generation = apply_generation;
            record.phase = ServiceRequestPhase::Publishing {
                apply_generation,
                apply_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ServiceRequestPublishing,
                stamp.identity.request_id,
                stamp.identity.generation,
            );
            Ok(ServiceEnqueueIntent {
                request: stamp,
                bound_continuation,
                apply_generation,
                apply_nonce,
            })
        })
    }

    pub(in super::super) fn acknowledge_service_enqueue(
        &mut self,
        intent: ServiceEnqueueIntent,
        receipt: ServiceEnqueueReceipt,
    ) -> LinearResult<ServiceEnqueueIntent, UnarmedServiceRequest> {
        linear_apply(intent, |intent| {
            self.require_authoritative()?;
            let stamp = intent.request;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_service_request_bearer(scope, registry_instance, &stamp)?;
            if receipt.queue != stamp.identity.queue
                || receipt.queue_generation != stamp.identity.queue_generation
                || receipt.payload_slot != stamp.identity.payload_slot
                || receipt.payload_generation != stamp.identity.payload_generation
                || receipt.transport_receipt_digest == 0
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            if scope
                .service_requests
                .get(stamp.identity.request_id)
                .unwrap()
                .phase
                != (ServiceRequestPhase::Publishing {
                    apply_generation: intent.apply_generation,
                    apply_nonce: intent.apply_nonce,
                })
                || scope
                    .service_requests
                    .get(stamp.identity.request_id)
                    .unwrap()
                    .bound_continuation
                    != Some(intent.bound_continuation)
            {
                return Err(InfrastructureError::StaleClaim);
            }
            let next_revision = preview_revision(scope)?;
            scope
                .service_requests
                .get_mut(stamp.identity.request_id)
                .unwrap()
                .phase = ServiceRequestPhase::QueueWrittenUnarmed {
                queue_receipt: receipt,
            };
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ServiceRequestEnqueued,
                stamp.identity.request_id,
                stamp.identity.generation,
            );
            Ok(UnarmedServiceRequest {
                request: stamp,
                receipt,
            })
        })
    }

    pub(in super::super) fn begin_service_arm(
        &mut self,
        unarmed: UnarmedServiceRequest,
    ) -> LinearResult<UnarmedServiceRequest, ServiceArmIntent> {
        linear_apply(unarmed, |unarmed| {
            self.require_authoritative()?;
            let stamp = unarmed.request;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_service_request_bearer(scope, registry_instance, &stamp)?;
            let record = scope
                .service_requests
                .get(stamp.identity.request_id)
                .unwrap();
            let bound_continuation = record
                .bound_continuation
                .ok_or(InfrastructureError::InvalidState)?;
            if record.phase
                != (ServiceRequestPhase::QueueWrittenUnarmed {
                    queue_receipt: unarmed.receipt,
                })
                || scope
                    .continuations
                    .get(bound_continuation.identity.continuation_id)
                    .is_none_or(|continuation| {
                        continuation.stamp != bound_continuation
                            || continuation.phase != ContinuationPhase::Pending
                            || continuation.service_owner
                                != Some(RequestKey {
                                    id: stamp.identity.request_id,
                                    generation: stamp.identity.generation,
                                })
                    })
            {
                return Err(InfrastructureError::InvalidState);
            }
            let arm_generation = record
                .arm_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let (arm_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let record = scope
                .service_requests
                .get_mut(stamp.identity.request_id)
                .unwrap();
            record.arm_generation = arm_generation;
            record.phase = ServiceRequestPhase::Arming {
                queue_receipt: unarmed.receipt,
                arm_generation,
                arm_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            Ok(ServiceArmIntent {
                request: stamp,
                queue_receipt: unarmed.receipt,
                bound_continuation,
                arm_generation,
                arm_nonce,
            })
        })
    }

    pub(in super::super) fn acknowledge_service_arm(
        &mut self,
        intent: ServiceArmIntent,
        receipt: ServiceArmReceipt,
    ) -> LinearResult<ServiceArmIntent, EnqueuedServiceRequest> {
        linear_apply(intent, |intent| {
            self.require_authoritative()?;
            let stamp = intent.request;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_service_request_bearer(scope, registry_instance, &stamp)?;
            if receipt.response_slot_id != stamp.identity.response_slot_id
                || receipt.response_slot_generation != stamp.identity.response_slot_generation
                || receipt.bound_continuation_id
                    != intent.bound_continuation.identity.continuation_id
                || receipt.bound_continuation_generation
                    != intent.bound_continuation.identity.generation
                || receipt.arm_generation != intent.arm_generation
                || receipt.transport_receipt_digest == 0
                || scope
                    .service_requests
                    .get(stamp.identity.request_id)
                    .unwrap()
                    .bound_continuation
                    != Some(intent.bound_continuation)
                || scope
                    .service_requests
                    .get(stamp.identity.request_id)
                    .unwrap()
                    .phase
                    != (ServiceRequestPhase::Arming {
                        queue_receipt: intent.queue_receipt,
                        arm_generation: intent.arm_generation,
                        arm_nonce: intent.arm_nonce,
                    })
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let next_revision = preview_revision(scope)?;
            scope
                .service_requests
                .get_mut(stamp.identity.request_id)
                .unwrap()
                .phase = ServiceRequestPhase::Armed {
                queue_receipt: intent.queue_receipt,
                arm_receipt: receipt,
            };
            scope.revision = next_revision;
            Ok(EnqueuedServiceRequest {
                request: stamp,
                queue_receipt: intent.queue_receipt,
                arm_receipt: receipt,
            })
        })
    }

    pub(in super::super) fn claim_service_request(
        &mut self,
        enqueued: EnqueuedServiceRequest,
        claimant: &EnteredTaskLease,
    ) -> LinearResult<EnqueuedServiceRequest, ServiceClaim> {
        linear_apply(enqueued, |enqueued| {
            self.require_authoritative()?;
            let stamp = enqueued.request;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_service_request_bearer(scope, registry_instance, &stamp)?;
            validate_task_stamp(scope, registry_instance, &claimant.0)?;
            let destination_binding_epoch = claimant.0.domain.binding_epoch;
            if scope.binding_epoch(stamp.identity.destination_domain)? != destination_binding_epoch
                || stamp.identity.destination_binding_epoch != destination_binding_epoch
                || claimant.0.domain.domain != stamp.identity.destination_domain
                || scope.tasks.get(claimant.0.identity.work_id).unwrap().phase != TaskPhase::Entered
            {
                return Err(InfrastructureError::StaleBinding);
            }
            let record = scope
                .service_requests
                .get(stamp.identity.request_id)
                .unwrap();
            let bound_continuation = record
                .bound_continuation
                .ok_or(InfrastructureError::InvalidState)?;
            if record.phase
                != (ServiceRequestPhase::Armed {
                    queue_receipt: enqueued.queue_receipt,
                    arm_receipt: enqueued.arm_receipt,
                })
                || enqueued.arm_receipt.response_slot_id != stamp.identity.response_slot_id
                || enqueued.arm_receipt.response_slot_generation
                    != stamp.identity.response_slot_generation
                || enqueued.arm_receipt.bound_continuation_id
                    != bound_continuation.identity.continuation_id
                || enqueued.arm_receipt.bound_continuation_generation
                    != bound_continuation.identity.generation
                || scope
                    .continuations
                    .get(bound_continuation.identity.continuation_id)
                    .is_none_or(|continuation| {
                        continuation.stamp != bound_continuation
                            || continuation.phase != ContinuationPhase::Pending
                    })
            {
                return Err(InfrastructureError::StaleClaim);
            }
            let claim_generation = record
                .claim_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let (claim_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let record = scope
                .service_requests
                .get_mut(stamp.identity.request_id)
                .unwrap();
            record.claim_generation = claim_generation;
            record.phase = ServiceRequestPhase::Claimed {
                queue_receipt: enqueued.queue_receipt,
                arm_receipt: enqueued.arm_receipt,
                claim_generation,
                claim_nonce,
                claimant: claimant.0.identity,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ServiceRequestClaimed,
                stamp.identity.request_id,
                stamp.identity.generation,
            );
            Ok(ServiceClaim {
                request: stamp,
                queue_receipt: enqueued.queue_receipt,
                arm_receipt: enqueued.arm_receipt,
                claim_generation,
                claim_nonce,
                claimant: claimant.0.identity,
            })
        })
    }

    pub(in super::super) fn bind_service_child(
        &mut self,
        claim: ServiceClaim,
        proof: ValidatedServiceChildProof,
    ) -> LinearResult<ServiceClaim, BoundServiceRequest> {
        linear_apply(claim, |claim| {
            self.require_authoritative()?;
            let stamp = claim.request;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_service_request_bearer(scope, registry_instance, &stamp)?;
            let claimant = scope
                .tasks
                .get(claim.claimant.work_id)
                .ok_or(InfrastructureError::UnknownObligation)?;
            if claimant.stamp.identity != claim.claimant
                || claimant.phase != TaskPhase::Entered
                || claimant.stamp.domain.domain != stamp.identity.destination_domain
                || claimant.stamp.domain.binding_epoch != stamp.identity.destination_binding_epoch
                || scope.binding_epoch(stamp.identity.destination_domain)?
                    != stamp.identity.destination_binding_epoch
            {
                return Err(InfrastructureError::StaleBinding);
            }
            if proof.receipt.child_effect.generation() == 0
                || proof.receipt.registration_digest == 0
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            if scope
                .service_requests
                .get(stamp.identity.request_id)
                .unwrap()
                .phase
                != (ServiceRequestPhase::Claimed {
                    queue_receipt: claim.queue_receipt,
                    arm_receipt: claim.arm_receipt,
                    claim_generation: claim.claim_generation,
                    claim_nonce: claim.claim_nonce,
                    claimant: claim.claimant,
                })
            {
                return Err(InfrastructureError::StaleClaim);
            }
            let next_revision = preview_revision(scope)?;
            scope
                .service_requests
                .get_mut(stamp.identity.request_id)
                .unwrap()
                .phase = ServiceRequestPhase::ChildBound {
                queue_receipt: claim.queue_receipt,
                arm_receipt: claim.arm_receipt,
                child_receipt: proof.receipt,
                claimant: claim.claimant,
            };
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ServiceRequestChildBound,
                stamp.identity.request_id,
                stamp.identity.generation,
            );
            Ok(BoundServiceRequest {
                request: stamp,
                queue_receipt: claim.queue_receipt,
                arm_receipt: claim.arm_receipt,
                child_receipt: proof.receipt,
                claimant: claim.claimant,
            })
        })
    }

    pub(in super::super) fn complete_service_request(
        &mut self,
        bound: BoundServiceRequest,
        result_digest: u64,
    ) -> LinearResult<BoundServiceRequest, ServiceCompletionOutcome> {
        linear_apply(bound, |bound| {
            self.require_authoritative()?;
            if result_digest == 0 {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let stamp = bound.request;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_service_request_bearer(scope, registry_instance, &stamp)?;
            if scope
                .service_requests
                .get(stamp.identity.request_id)
                .unwrap()
                .phase
                != (ServiceRequestPhase::ChildBound {
                    queue_receipt: bound.queue_receipt,
                    arm_receipt: bound.arm_receipt,
                    child_receipt: bound.child_receipt,
                    claimant: bound.claimant,
                })
            {
                return Err(InfrastructureError::StaleClaim);
            }
            let receipt = ServiceCompletionReceipt {
                request_id: stamp.identity.request_id,
                generation: stamp.identity.generation,
                child_effect: bound.child_receipt.child_effect,
                result_digest,
            };
            let response = scope
                .service_requests
                .get(stamp.identity.request_id)
                .unwrap()
                .bound_continuation
                .ok_or(InfrastructureError::Invariant(
                    "bound service request lacks response continuation",
                ))?;
            if scope
                .continuations
                .get(response.identity.continuation_id)
                .is_none_or(|continuation| {
                    continuation.stamp != response
                        || continuation.phase != ContinuationPhase::Pending
                        || continuation.service_owner
                            != Some(RequestKey {
                                id: stamp.identity.request_id,
                                generation: stamp.identity.generation,
                            })
                })
            {
                return Err(InfrastructureError::InvalidState);
            }
            validate_continuation_bearer(scope, registry_instance, &response)?;
            let bearer_generation = next_continuation_bearer_generation(
                scope
                    .continuations
                    .get(response.identity.continuation_id)
                    .unwrap(),
            )?;
            finish_service_request(scope, stamp, ServiceRequestPhase::Completed { receipt })?;
            // All fallible service-request accounting is complete.  The exact
            // continuation record was prevalidated above, so releasing its
            // service ownership cannot fail after the request became terminal.
            let continuation = scope
                .continuations
                .get_mut(response.identity.continuation_id)
                .unwrap();
            continuation.stamp.bearer_generation = bearer_generation;
            continuation.service_owner = None;
            Ok(ServiceCompletionOutcome {
                receipt,
                response: ContinuationLease(mint_continuation_key::<
                    bearer_state::ContinuationPending,
                >(continuation)),
            })
        })
    }

    pub(in super::super) fn cancel_service_request(
        &mut self,
        ticket: ServiceRequestTicket,
        proof: ValidatedAbortProof,
    ) -> LinearResult<ServiceRequestTicket, Option<ContinuationLease>> {
        linear_apply(ticket, |ticket| {
            self.require_authoritative()?;
            if proof.evidence_digest == 0 {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let stamp = ticket.0;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_service_request_bearer(scope, registry_instance, &stamp)?;
            if scope
                .service_requests
                .get(stamp.identity.request_id)
                .unwrap()
                .phase
                != ServiceRequestPhase::ReservedUnbound
                && scope
                    .service_requests
                    .get(stamp.identity.request_id)
                    .unwrap()
                    .phase
                    != ServiceRequestPhase::ReservedBound
            {
                return Err(InfrastructureError::InvalidState);
            }
            let response = scope
                .service_requests
                .get(stamp.identity.request_id)
                .unwrap()
                .bound_continuation;
            let bearer_generation = if let Some(response) = response.as_ref() {
                let owner = scope
                    .continuations
                    .get(response.identity.continuation_id)
                    .ok_or(InfrastructureError::Invariant(
                        "bound service request lacks response continuation",
                    ))?;
                validate_continuation_bearer(scope, registry_instance, response)?;
                if owner.stamp != *response
                    || owner.phase != ContinuationPhase::Pending
                    || owner.service_owner
                        != Some(RequestKey {
                            id: stamp.identity.request_id,
                            generation: stamp.identity.generation,
                        })
                {
                    return Err(InfrastructureError::InvalidState);
                }
                Some(next_continuation_bearer_generation(owner)?)
            } else {
                None
            };
            finish_service_request(
                scope,
                stamp,
                ServiceRequestPhase::Cancelled {
                    evidence_digest: proof.evidence_digest,
                },
            )?;
            let response = if let Some(response) = response.as_ref() {
                // This lookup and mutation are infallible because the exact
                // record and owner were checked before terminal accounting.
                let continuation = scope
                    .continuations
                    .get_mut(response.identity.continuation_id)
                    .unwrap();
                continuation.stamp.bearer_generation = bearer_generation.unwrap();
                continuation.service_owner = None;
                Some(ContinuationLease(mint_continuation_key::<
                    bearer_state::ContinuationPending,
                >(continuation)))
            } else {
                None
            };
            Ok(response)
        })
    }

    pub(in super::super) fn query_service_request(
        &self,
        context: &WorkloadContext,
        request_id: u64,
        generation: u64,
    ) -> Result<ServiceRequestRecoveryProjection, InfrastructureError> {
        self.require_authoritative()?;
        let scope = self.scope(context.root.scope)?;
        validate_context(scope, self.registry_instance, context)?;
        let record = scope
            .service_requests
            .get(request_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
        if record.stamp.identity.generation != generation {
            return Err(InfrastructureError::StaleGeneration);
        }
        if record.stamp.workload.request != context.workload.request {
            return Err(InfrastructureError::ForeignWorkload);
        }
        let (state, enqueue_receipt, arm_receipt, child_receipt, completion_receipt) =
            match record.phase {
                ServiceRequestPhase::ReservedUnbound => (
                    ServiceRequestRecoveryState::ReservedUnbound,
                    None,
                    None,
                    None,
                    None,
                ),
                ServiceRequestPhase::ReservedBound => (
                    ServiceRequestRecoveryState::ReservedBound,
                    None,
                    None,
                    None,
                    None,
                ),
                ServiceRequestPhase::Publishing { .. } => (
                    ServiceRequestRecoveryState::EnqueueUncertain,
                    None,
                    None,
                    None,
                    None,
                ),
                ServiceRequestPhase::QueueWrittenUnarmed { queue_receipt } => (
                    ServiceRequestRecoveryState::QueueWrittenUnarmed,
                    Some(queue_receipt),
                    None,
                    None,
                    None,
                ),
                ServiceRequestPhase::Arming { queue_receipt, .. } => (
                    ServiceRequestRecoveryState::ArmUncertain,
                    Some(queue_receipt),
                    None,
                    None,
                    None,
                ),
                ServiceRequestPhase::Armed {
                    queue_receipt,
                    arm_receipt,
                } => (
                    ServiceRequestRecoveryState::Armed,
                    Some(queue_receipt),
                    Some(arm_receipt),
                    None,
                    None,
                ),
                ServiceRequestPhase::Claimed {
                    queue_receipt,
                    arm_receipt,
                    ..
                } => (
                    ServiceRequestRecoveryState::Claimed,
                    Some(queue_receipt),
                    Some(arm_receipt),
                    None,
                    None,
                ),
                ServiceRequestPhase::ChildBound {
                    queue_receipt,
                    arm_receipt,
                    child_receipt,
                    ..
                } => (
                    ServiceRequestRecoveryState::ChildBound,
                    Some(queue_receipt),
                    Some(arm_receipt),
                    Some(child_receipt),
                    None,
                ),
                ServiceRequestPhase::Completed { receipt } => (
                    ServiceRequestRecoveryState::Completed,
                    None,
                    None,
                    None,
                    Some(receipt),
                ),
                ServiceRequestPhase::Cancelled { .. } => (
                    ServiceRequestRecoveryState::Cancelled,
                    None,
                    None,
                    None,
                    None,
                ),
            };
        Ok(ServiceRequestRecoveryProjection {
            descriptor: record.stamp.identity,
            state,
            enqueue_receipt,
            arm_receipt,
            child_receipt,
            completion_receipt,
        })
    }
}

pub(super) fn validate_service_request_bearer(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    stamp: &BearerStamp<ServiceRequestDescriptor>,
) -> Result<(), InfrastructureError> {
    validate_stamp_common(scope, registry_instance, stamp)?;
    let record = scope
        .service_requests
        .get(stamp.identity.request_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp != *stamp {
        return Err(InfrastructureError::StaleGeneration);
    }
    if scope.binding_epoch(stamp.identity.destination_domain)?
        != stamp.identity.destination_binding_epoch
    {
        return Err(InfrastructureError::StaleBinding);
    }
    Ok(())
}

fn finish_service_request(
    scope: &mut ScopeInfrastructure,
    stamp: BearerStamp<ServiceRequestDescriptor>,
    terminal: ServiceRequestPhase,
) -> Result<(), InfrastructureError> {
    let next_revision = preview_revision(scope)?;
    let next_live = checked_sub(scope.live.service_requests, 1)?;
    let next_workload_children = preview_workload_child_sub(scope, stamp.workload.request)?;
    let parent_task = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    let next_task_children = preview_task_child_sub(scope, parent_task)?;
    scope
        .service_requests
        .get_mut(stamp.identity.request_id)
        .unwrap()
        .phase = terminal;
    scope.revision = next_revision;
    scope.live.service_requests = next_live;
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
    Ok(())
}

pub(super) fn service_request_phase_live(phase: ServiceRequestPhase) -> bool {
    !matches!(
        phase,
        ServiceRequestPhase::Completed { .. } | ServiceRequestPhase::Cancelled { .. }
    )
}
