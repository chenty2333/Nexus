// SPDX-License-Identifier: MPL-2.0

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use super::continuation::{apply_service_owned_continuation, prepare_service_owned_continuation};
use super::{
    AuthorityKey, BearerKey, BearerStamp, BoundServiceCancellationOutcome, BoundServiceRequest,
    ContinuationDescriptor, ContinuationLease, ContinuationPhase, EnqueuedServiceRequest,
    EnteredTaskLease, InfrastructureError, InfrastructureEventKind, InfrastructureKind,
    InfrastructureState, LinearResult, ParentStamp, RequestKey, ReverseIndexRecord, ReverseParent,
    ScopeInfrastructure, ServiceArmAuthority, ServiceArmPlan, ServiceArmReceipt, ServiceBoundKey,
    ServiceCancellationPoint, ServiceCancellationReceipt, ServiceChildBindingReceipt,
    ServiceClaimantSnapshot, ServiceCompletionOutcome, ServiceCompletionReceipt,
    ServiceEnqueueAuthority, ServiceEnqueuePlan, ServiceEnqueueReceipt, ServiceLineageCommitment,
    ServiceRequestCausalIdentity, ServiceRequestDescriptor, ServiceRequestPhase,
    ServiceRequestRecoveryProjection, ServiceRequestRecoveryState, ServiceRequestStateRecord,
    ServiceRequestTicket, TaskPhase, TaskRecord, TaskWorkRole, UnarmedServiceRequest,
    UnboundServiceRequest, ValidatedAbortProof, ValidatedServiceChildProof, WorkloadContext,
    bearer_state, checked_add, checked_sub, context_from_stamp, linear_apply,
    mint_continuation_key, next_continuation_bearer_generation, preview_bearer_stamp,
    preview_nonce, preview_revision, preview_task_child_add, preview_workload_child_add,
    preview_workload_child_sub, require_vacancy, validate_active_admission, validate_context,
    validate_continuation_bearer, validate_stamp_common, validate_task_stamp,
};
use sha2::{Digest, Sha256};

impl InfrastructureState {
    pub(in super::super) fn reserve_service_request(
        &mut self,
        task: &EnteredTaskLease,
        descriptor: ServiceRequestDescriptor,
    ) -> Result<UnboundServiceRequest, InfrastructureError> {
        self.require_authoritative()?;
        descriptor.validate()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(task.0.root.scope)?;
        validate_task_stamp(scope, registry_instance, &task.0)?;
        validate_active_admission(scope)?;
        let parent_task = scope
            .tasks
            .get(task.0.identity.work_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
        if parent_task.phase != TaskPhase::Entered {
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
                response_identity: None,
                response_commitment: None,
                child_binding_commitment: None,
                bound_commitment: None,
                bind_bearer_generation: 0,
                apply_generation: 0,
                apply_bearer_generation: 0,
                apply_nonce_high_water: 0,
                arm_generation: 0,
                arm_bearer_generation: 0,
                arm_nonce_high_water: 0,
                claim_generation: 0,
                claim_bearer_generation: 0,
                claim_nonce_high_water: 0,
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
        let workload = scope
            .workloads
            .get_mut(stamp.workload.request.id)
            .ok_or(InfrastructureError::UnknownWorkload)?;
        workload.live_children = next_workload_children;
        let task_record = scope
            .tasks
            .get_mut(task.0.identity.work_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
        task_record.live_children = next_task_children;
        scope.events.push(
            InfrastructureEventKind::ServiceRequestReserved,
            descriptor.request_id,
            descriptor.generation,
        );
        Ok(UnboundServiceRequest(mint_service_key::<
            bearer_state::ServiceReservedUnbound,
        >(&stamp)))
    }

    /// Creates and binds the response continuation in one logical Registry
    /// transition. No independent continuation bearer is ever minted.
    pub(in super::super) fn bind_service_response_continuation(
        &mut self,
        unbound: UnboundServiceRequest,
        descriptor: ContinuationDescriptor,
    ) -> LinearResult<UnboundServiceRequest, ServiceRequestTicket> {
        linear_apply(unbound, |unbound| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(unbound.0.authority.scope)?;
            let service = validate_service_request_key(scope, registry_instance, &unbound.0)?;
            if service.phase != ServiceRequestPhase::ReservedUnbound
                || service.bound_continuation.is_some()
                || service.response_identity.is_some()
                || service.response_commitment.is_some()
                || service.child_binding_commitment.is_some()
                || service.bound_commitment.is_some()
                || service.bind_bearer_generation != 0
            {
                return Err(InfrastructureError::InvalidState);
            }
            let next_bearer_generation = next_service_bearer_generation(service)?;
            let mut successor = service.stamp;
            successor.bearer_generation = next_bearer_generation;
            let prepared =
                prepare_service_owned_continuation(scope, registry_instance, service, descriptor)?;
            apply_service_owned_continuation(scope, prepared, |service, continuation| {
                service.stamp = successor;
                service.bound_continuation = Some(continuation);
                service.response_identity = Some(continuation.identity);
                service.response_commitment =
                    Some(service_response_commitment(continuation.identity));
                service.bind_bearer_generation = next_bearer_generation;
                service.phase = ServiceRequestPhase::ReservedBound;
            })?;
            scope.events.push(
                InfrastructureEventKind::ServiceRequestBound,
                successor.identity.request_id,
                successor.identity.generation,
            );
            Ok(ServiceRequestTicket(mint_service_bound_key::<
                bearer_state::ServiceReservedBound,
            >(
                &successor,
                service_response_commitment(descriptor),
            )))
        })
    }

    pub(in super::super) fn begin_service_enqueue(
        &mut self,
        ticket: ServiceRequestTicket,
    ) -> LinearResult<ServiceRequestTicket, (ServiceEnqueuePlan, ServiceEnqueueAuthority)> {
        linear_apply(ticket, |ticket| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(ticket.0.authority.scope)?;
            let record = validate_service_bound_key(scope, registry_instance, &ticket.0)?;
            if record.phase != ServiceRequestPhase::ReservedBound {
                return Err(InfrastructureError::InvalidState);
            }
            let response = validate_service_owned_continuation(scope, registry_instance, record)?;
            let apply_generation = record
                .apply_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let bearer_generation = next_service_bearer_generation(record)?;
            let (apply_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let mut successor = record.stamp;
            successor.bearer_generation = bearer_generation;
            let plan = ServiceEnqueuePlan {
                causal: service_request_causal_identity(&successor, response.identity)?,
                bearer_generation,
                apply_generation,
                apply_nonce,
            };
            let record = scope
                .service_requests
                .get_mut(successor.identity.request_id)
                .ok_or(InfrastructureError::UnknownObligation)?;
            record.stamp = successor;
            record.apply_generation = apply_generation;
            record.apply_bearer_generation = bearer_generation;
            record.apply_nonce_high_water = apply_nonce;
            record.phase = ServiceRequestPhase::Publishing {
                apply_generation,
                apply_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ServiceRequestPublishing,
                successor.identity.request_id,
                successor.identity.generation,
            );
            Ok((
                plan,
                ServiceEnqueueAuthority(mint_service_bound_key::<
                    bearer_state::ServiceEnqueuePublishing,
                >(
                    &successor, service_enqueue_plan_commitment(plan)
                )),
            ))
        })
    }

    /// Consumes only the compact authority. The copyable enqueue plan cannot
    /// acknowledge an external write.
    pub(in super::super) fn acknowledge_service_enqueue(
        &mut self,
        authority: ServiceEnqueueAuthority,
        receipt: ServiceEnqueueReceipt,
    ) -> LinearResult<ServiceEnqueueAuthority, UnarmedServiceRequest> {
        linear_apply(authority, |authority| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(authority.0.authority.scope)?;
            let record = validate_service_bound_key(scope, registry_instance, &authority.0)?;
            let (apply_generation, apply_nonce) = match record.phase {
                ServiceRequestPhase::Publishing {
                    apply_generation,
                    apply_nonce,
                } => (apply_generation, apply_nonce),
                _ => return Err(InfrastructureError::InvalidState),
            };
            let response = validate_service_owned_continuation(scope, registry_instance, record)?;
            let expected = ServiceEnqueuePlan {
                causal: service_request_causal_identity(&record.stamp, response.identity)?,
                bearer_generation: record.apply_bearer_generation,
                apply_generation,
                apply_nonce,
            };
            if !valid_service_enqueue_receipt(expected, receipt) {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let next_bearer_generation = next_service_bearer_generation(record)?;
            let next_revision = preview_revision(scope)?;
            let mut successor = record.stamp;
            successor.bearer_generation = next_bearer_generation;
            let record = scope
                .service_requests
                .get_mut(successor.identity.request_id)
                .ok_or(InfrastructureError::UnknownObligation)?;
            record.stamp = successor;
            record.phase = ServiceRequestPhase::QueueWrittenUnarmed {
                queue_receipt: receipt,
            };
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ServiceRequestEnqueued,
                successor.identity.request_id,
                successor.identity.generation,
            );
            Ok(UnarmedServiceRequest(mint_service_bound_key::<
                bearer_state::ServiceQueueWritten,
            >(
                &successor,
                service_enqueue_receipt_commitment(receipt),
            )))
        })
    }

    pub(in super::super) fn begin_service_arm(
        &mut self,
        unarmed: UnarmedServiceRequest,
    ) -> LinearResult<UnarmedServiceRequest, (ServiceArmPlan, ServiceArmAuthority)> {
        linear_apply(unarmed, |unarmed| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(unarmed.0.authority.scope)?;
            let record = validate_service_bound_key(scope, registry_instance, &unarmed.0)?;
            let queue_receipt = match record.phase {
                ServiceRequestPhase::QueueWrittenUnarmed { queue_receipt } => queue_receipt,
                _ => return Err(InfrastructureError::InvalidState),
            };
            let response = validate_service_owned_continuation(scope, registry_instance, record)?;
            let arm_generation = record
                .arm_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let bearer_generation = next_service_bearer_generation(record)?;
            let (arm_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let mut successor = record.stamp;
            successor.bearer_generation = bearer_generation;
            let plan = ServiceArmPlan {
                causal: service_request_causal_identity(&successor, response.identity)?,
                queue_receipt,
                bearer_generation,
                arm_generation,
                arm_nonce,
            };
            let record = scope
                .service_requests
                .get_mut(successor.identity.request_id)
                .ok_or(InfrastructureError::UnknownObligation)?;
            record.stamp = successor;
            record.arm_generation = arm_generation;
            record.arm_bearer_generation = bearer_generation;
            record.arm_nonce_high_water = arm_nonce;
            record.phase = ServiceRequestPhase::Arming {
                queue_receipt,
                arm_generation,
                arm_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            Ok((
                plan,
                ServiceArmAuthority(
                    mint_service_bound_key::<bearer_state::ServiceArmPublishing>(
                        &successor,
                        service_arm_plan_commitment(plan),
                    ),
                ),
            ))
        })
    }

    /// Consumes only the compact authority and checks every coordinate echoed
    /// by the external response-slot receipt.
    pub(in super::super) fn acknowledge_service_arm(
        &mut self,
        authority: ServiceArmAuthority,
        receipt: ServiceArmReceipt,
    ) -> LinearResult<ServiceArmAuthority, EnqueuedServiceRequest> {
        linear_apply(authority, |authority| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(authority.0.authority.scope)?;
            let record = validate_service_bound_key(scope, registry_instance, &authority.0)?;
            let (queue_receipt, arm_generation, arm_nonce) = match record.phase {
                ServiceRequestPhase::Arming {
                    queue_receipt,
                    arm_generation,
                    arm_nonce,
                } => (queue_receipt, arm_generation, arm_nonce),
                _ => return Err(InfrastructureError::InvalidState),
            };
            let response = validate_service_owned_continuation(scope, registry_instance, record)?;
            let expected = ServiceArmPlan {
                causal: service_request_causal_identity(&record.stamp, response.identity)?,
                queue_receipt,
                bearer_generation: record.arm_bearer_generation,
                arm_generation,
                arm_nonce,
            };
            if !valid_service_arm_receipt(expected, receipt) {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let next_bearer_generation = next_service_bearer_generation(record)?;
            let next_revision = preview_revision(scope)?;
            let mut successor = record.stamp;
            successor.bearer_generation = next_bearer_generation;
            let record = scope
                .service_requests
                .get_mut(successor.identity.request_id)
                .ok_or(InfrastructureError::UnknownObligation)?;
            record.stamp = successor;
            record.phase = ServiceRequestPhase::Armed {
                queue_receipt,
                arm_receipt: receipt,
            };
            scope.revision = next_revision;
            Ok(EnqueuedServiceRequest(mint_service_bound_key::<
                bearer_state::ServiceArmed,
            >(
                &successor,
                service_armed_commitment(queue_receipt, receipt),
            )))
        })
    }

    /// Claims the armed request and installs its child receipt as one logical
    /// transition. There is no observable claimed bearer or claimed phase.
    pub(in super::super) fn claim_and_bind_service_child(
        &mut self,
        enqueued: EnqueuedServiceRequest,
        claimant: &EnteredTaskLease,
        proof: ValidatedServiceChildProof,
    ) -> LinearResult<EnqueuedServiceRequest, BoundServiceRequest> {
        linear_apply(enqueued, |enqueued| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(enqueued.0.authority.scope)?;
            let record = validate_service_bound_key(scope, registry_instance, &enqueued.0)?;
            validate_task_stamp(scope, registry_instance, &claimant.0)?;
            if proof.receipt.child_effect.generation() == 0
                || proof.receipt.registration_digest == 0
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let destination_binding_epoch = claimant.0.domain.binding_epoch;
            let claimant_record = scope
                .tasks
                .get(claimant.0.identity.work_id)
                .ok_or(InfrastructureError::UnknownObligation)?;
            if scope.binding_epoch(record.stamp.identity.destination_domain)?
                != destination_binding_epoch
                || record.stamp.identity.destination_binding_epoch != destination_binding_epoch
                || claimant.0.domain.domain != record.stamp.identity.destination_domain
                || claimant_record.phase != TaskPhase::Entered
                || claimant_record.stamp.identity != claimant.0.identity
            {
                return Err(InfrastructureError::StaleBinding);
            }
            let (queue_receipt, arm_receipt) = match record.phase {
                ServiceRequestPhase::Armed {
                    queue_receipt,
                    arm_receipt,
                } => (queue_receipt, arm_receipt),
                _ => return Err(InfrastructureError::InvalidState),
            };
            let response = validate_service_owned_continuation(scope, registry_instance, record)?;
            let claim_generation = record
                .claim_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let bearer_generation = next_service_bearer_generation(record)?;
            let (claim_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let next_claimant_children = preview_task_child_add(scope, claimant.0.identity)?;
            let mut successor = record.stamp;
            successor.bearer_generation = bearer_generation;
            let binding_receipt = ServiceChildBindingReceipt {
                request_id: successor.identity.request_id,
                generation: successor.identity.generation,
                service_bearer_generation: bearer_generation,
                claim_generation,
                claim_nonce,
                claimant: service_claimant_snapshot(&claimant.0),
                child: proof.receipt,
            };
            let bound_commitment = service_child_bound_commitment(
                queue_receipt,
                arm_receipt,
                response.identity,
                binding_receipt,
            );
            let service_record = scope
                .service_requests
                .get_mut(successor.identity.request_id)
                .ok_or(InfrastructureError::UnknownObligation)?;
            let claimant_record = scope
                .tasks
                .get_mut(claimant.0.identity.work_id)
                .ok_or(InfrastructureError::UnknownObligation)?;
            service_record.stamp = successor;
            service_record.claim_generation = claim_generation;
            service_record.claim_bearer_generation = bearer_generation;
            service_record.claim_nonce_high_water = claim_nonce;
            service_record.child_binding_commitment = Some(binding_receipt);
            service_record.bound_commitment = Some(bound_commitment);
            service_record.phase = ServiceRequestPhase::ChildBound {
                queue_receipt,
                arm_receipt,
                binding_receipt,
            };
            claimant_record.live_children = next_claimant_children;
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::ServiceRequestChildBound,
                successor.identity.request_id,
                successor.identity.generation,
            );
            Ok(BoundServiceRequest(mint_service_bound_key::<
                bearer_state::ServiceChildBound,
            >(
                &successor, bound_commitment
            )))
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
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(bound.0.authority.scope)?;
            let record = validate_bound_service_request(scope, registry_instance, bound)?;
            let (queue_receipt, arm_receipt, binding_receipt) = match record.phase {
                ServiceRequestPhase::ChildBound {
                    queue_receipt,
                    arm_receipt,
                    binding_receipt,
                } => (queue_receipt, arm_receipt, binding_receipt),
                _ => return Err(InfrastructureError::InvalidState),
            };
            let validated_binding =
                validate_live_service_child_binding(scope, registry_instance, record)?;
            if validated_binding != binding_receipt {
                return Err(InfrastructureError::InvalidState);
            }
            let response = validate_service_owned_continuation(scope, registry_instance, record)?;
            let continuation_generation = next_continuation_bearer_generation(
                scope
                    .continuations
                    .get(response.identity.continuation_id)
                    .ok_or(InfrastructureError::UnknownObligation)?,
            )?;
            let service_generation = next_service_bearer_generation(record)?;
            let lineage_commitment = record
                .bound_commitment
                .ok_or(InfrastructureError::InvalidState)?;
            let receipt = ServiceCompletionReceipt {
                request_id: record.stamp.identity.request_id,
                generation: record.stamp.identity.generation,
                bearer_generation: service_generation,
                lineage_commitment,
                binding_receipt,
                child_effect: binding_receipt.child.child_effect,
                response: response.identity,
                result_digest,
            };
            let terminal = prepare_service_terminal(scope, record, service_generation)?;
            let response = apply_bound_service_terminal(
                scope,
                terminal,
                response,
                continuation_generation,
                ServiceRequestPhase::Completed {
                    queue_receipt,
                    arm_receipt,
                    receipt,
                },
            )?;
            scope.events.push(
                InfrastructureEventKind::ServiceRequestCompleted,
                receipt.request_id,
                receipt.generation,
            );
            Ok(ServiceCompletionOutcome { receipt, response })
        })
    }

    pub(in super::super) fn cancel_unbound_service_request(
        &mut self,
        unbound: UnboundServiceRequest,
        proof: ValidatedAbortProof,
    ) -> LinearResult<UnboundServiceRequest, ServiceCancellationReceipt> {
        linear_apply(unbound, |unbound| {
            self.require_authoritative()?;
            if proof.evidence_digest == 0 {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(unbound.0.authority.scope)?;
            let record = validate_service_request_key(scope, registry_instance, &unbound.0)?;
            if record.phase != ServiceRequestPhase::ReservedUnbound
                || record.bound_continuation.is_some()
                || record.response_identity.is_some()
                || record.response_commitment.is_some()
                || record.child_binding_commitment.is_some()
                || record.bound_commitment.is_some()
                || record.bind_bearer_generation != 0
            {
                return Err(InfrastructureError::InvalidState);
            }
            let bearer_generation = next_service_bearer_generation(record)?;
            let receipt = ServiceCancellationReceipt {
                request_id: record.stamp.identity.request_id,
                generation: record.stamp.identity.generation,
                bearer_generation,
                evidence_digest: proof.evidence_digest,
                point: ServiceCancellationPoint::ReservedUnbound,
                response: None,
            };
            let terminal = prepare_service_terminal(scope, record, bearer_generation)?;
            apply_unbound_service_terminal(
                scope,
                terminal,
                ServiceRequestPhase::Cancelled { receipt },
            )?;
            scope.events.push(
                InfrastructureEventKind::ServiceRequestCancelled,
                receipt.request_id,
                receipt.generation,
            );
            Ok(receipt)
        })
    }

    pub(in super::super) fn cancel_bound_service_request(
        &mut self,
        ticket: ServiceRequestTicket,
        proof: ValidatedAbortProof,
    ) -> LinearResult<ServiceRequestTicket, BoundServiceCancellationOutcome> {
        linear_apply(ticket, |ticket| {
            self.require_authoritative()?;
            if proof.evidence_digest == 0 {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(ticket.0.authority.scope)?;
            let record = validate_service_bound_key(scope, registry_instance, &ticket.0)?;
            if record.phase != ServiceRequestPhase::ReservedBound {
                return Err(InfrastructureError::InvalidState);
            }
            if record.child_binding_commitment.is_some() || record.bound_commitment.is_some() {
                return Err(InfrastructureError::InvalidState);
            }
            let response = validate_service_owned_continuation(scope, registry_instance, record)?;
            let continuation_generation = next_continuation_bearer_generation(
                scope
                    .continuations
                    .get(response.identity.continuation_id)
                    .ok_or(InfrastructureError::UnknownObligation)?,
            )?;
            let bearer_generation = next_service_bearer_generation(record)?;
            let receipt = ServiceCancellationReceipt {
                request_id: record.stamp.identity.request_id,
                generation: record.stamp.identity.generation,
                bearer_generation,
                evidence_digest: proof.evidence_digest,
                point: ServiceCancellationPoint::ReservedBound,
                response: Some(response.identity),
            };
            let terminal = prepare_service_terminal(scope, record, bearer_generation)?;
            let response = apply_bound_service_terminal(
                scope,
                terminal,
                response,
                continuation_generation,
                ServiceRequestPhase::Cancelled { receipt },
            )?;
            scope.events.push(
                InfrastructureEventKind::ServiceRequestCancelled,
                receipt.request_id,
                receipt.generation,
            );
            Ok(BoundServiceCancellationOutcome { receipt, response })
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
        let (
            state,
            enqueue_receipt,
            arm_receipt,
            child_binding_receipt,
            completion_receipt,
            cancellation_receipt,
        ) = match record.phase {
            ServiceRequestPhase::ReservedUnbound => (
                ServiceRequestRecoveryState::ReservedUnbound,
                None,
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
                None,
            ),
            ServiceRequestPhase::Publishing { .. } => (
                ServiceRequestRecoveryState::EnqueueUncertain,
                None,
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
                None,
            ),
            ServiceRequestPhase::Arming { queue_receipt, .. } => (
                ServiceRequestRecoveryState::ArmUncertain,
                Some(queue_receipt),
                None,
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
                None,
            ),
            ServiceRequestPhase::ChildBound {
                queue_receipt,
                arm_receipt,
                binding_receipt,
            } => (
                ServiceRequestRecoveryState::ChildBound,
                Some(queue_receipt),
                Some(arm_receipt),
                Some(binding_receipt),
                None,
                None,
            ),
            ServiceRequestPhase::Completed {
                queue_receipt,
                arm_receipt,
                receipt,
            } => (
                ServiceRequestRecoveryState::Completed,
                Some(queue_receipt),
                Some(arm_receipt),
                Some(receipt.binding_receipt),
                Some(receipt),
                None,
            ),
            ServiceRequestPhase::Cancelled { receipt } => (
                ServiceRequestRecoveryState::Cancelled,
                None,
                None,
                None,
                None,
                Some(receipt),
            ),
        };
        Ok(ServiceRequestRecoveryProjection {
            descriptor: record.stamp.identity,
            state,
            enqueue_receipt,
            arm_receipt,
            child_binding_receipt,
            completion_receipt,
            cancellation_receipt,
            bearer_generation: record.stamp.bearer_generation,
        })
    }
}

fn mint_service_key<State: bearer_state::Sealed>(
    stamp: &BearerStamp<ServiceRequestDescriptor>,
) -> BearerKey<State> {
    BearerKey {
        authority: AuthorityKey {
            registry_instance: stamp.root.registry_instance,
            scope: stamp.root.scope,
            authority_epoch: stamp.root.authority_epoch,
        },
        slot: stamp.identity.request_id,
        object_generation: stamp.identity.generation,
        bearer_generation: stamp.bearer_generation,
        nonce: stamp.nonce,
        state: __cser_core::marker::PhantomData,
    }
}

fn mint_service_bound_key<State: bearer_state::Sealed>(
    stamp: &BearerStamp<ServiceRequestDescriptor>,
    lineage_commitment: ServiceLineageCommitment,
) -> ServiceBoundKey<State> {
    ServiceBoundKey {
        authority: AuthorityKey {
            registry_instance: stamp.root.registry_instance,
            scope: stamp.root.scope,
            authority_epoch: stamp.root.authority_epoch,
        },
        slot: stamp.identity.request_id,
        object_generation: stamp.identity.generation,
        bearer_generation: stamp.bearer_generation,
        nonce: stamp.nonce,
        lineage_commitment,
        state: __cser_core::marker::PhantomData,
    }
}

pub(super) fn validate_service_request_key<'a, State: bearer_state::Sealed>(
    scope: &'a ScopeInfrastructure,
    registry_instance: u64,
    key: &BearerKey<State>,
) -> Result<&'a ServiceRequestStateRecord, InfrastructureError> {
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
        .service_requests
        .get(key.slot)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp.identity.request_id != key.slot {
        return Err(InfrastructureError::IdentityConflict);
    }
    if record.stamp.identity.generation != key.object_generation
        || record.stamp.bearer_generation != key.bearer_generation
        || record.stamp.nonce != key.nonce
    {
        return Err(InfrastructureError::StaleGeneration);
    }
    validate_service_request_stamp(scope, registry_instance, &record.stamp)?;
    Ok(record)
}

pub(super) fn validate_service_bound_key<'a, State: bearer_state::Sealed>(
    scope: &'a ScopeInfrastructure,
    registry_instance: u64,
    key: &ServiceBoundKey<State>,
) -> Result<&'a ServiceRequestStateRecord, InfrastructureError> {
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
        .service_requests
        .get(key.slot)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp.identity.request_id != key.slot {
        return Err(InfrastructureError::IdentityConflict);
    }
    if record.stamp.identity.generation != key.object_generation
        || record.stamp.bearer_generation != key.bearer_generation
        || record.stamp.nonce != key.nonce
    {
        return Err(InfrastructureError::StaleGeneration);
    }
    validate_service_request_stamp(scope, registry_instance, &record.stamp)?;
    let response = record
        .response_identity
        .ok_or(InfrastructureError::InvalidState)?;
    let response_commitment = service_response_commitment(response);
    if record.response_commitment != Some(response_commitment) {
        return Err(InfrastructureError::InvalidReceipt);
    }
    let expected = match record.phase {
        ServiceRequestPhase::ReservedBound => {
            if record.child_binding_commitment.is_some() || record.bound_commitment.is_some() {
                return Err(InfrastructureError::InvalidState);
            }
            response_commitment
        }
        ServiceRequestPhase::Publishing {
            apply_generation,
            apply_nonce,
        } => {
            if record.child_binding_commitment.is_some() || record.bound_commitment.is_some() {
                return Err(InfrastructureError::InvalidState);
            }
            service_enqueue_plan_commitment(ServiceEnqueuePlan {
                causal: service_request_causal_identity(&record.stamp, response)?,
                bearer_generation: record.apply_bearer_generation,
                apply_generation,
                apply_nonce,
            })
        }
        ServiceRequestPhase::QueueWrittenUnarmed { queue_receipt } => {
            if record.child_binding_commitment.is_some() || record.bound_commitment.is_some() {
                return Err(InfrastructureError::InvalidState);
            }
            service_enqueue_receipt_commitment(queue_receipt)
        }
        ServiceRequestPhase::Arming {
            queue_receipt,
            arm_generation,
            arm_nonce,
        } => {
            if record.child_binding_commitment.is_some() || record.bound_commitment.is_some() {
                return Err(InfrastructureError::InvalidState);
            }
            service_arm_plan_commitment(ServiceArmPlan {
                causal: service_request_causal_identity(&record.stamp, response)?,
                queue_receipt,
                bearer_generation: record.arm_bearer_generation,
                arm_generation,
                arm_nonce,
            })
        }
        ServiceRequestPhase::Armed {
            queue_receipt,
            arm_receipt,
        } => {
            if record.child_binding_commitment.is_some() || record.bound_commitment.is_some() {
                return Err(InfrastructureError::InvalidState);
            }
            service_armed_commitment(queue_receipt, arm_receipt)
        }
        ServiceRequestPhase::ChildBound {
            queue_receipt,
            arm_receipt,
            binding_receipt,
        } => {
            if record.child_binding_commitment != Some(binding_receipt) {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let bound_commitment = service_child_bound_commitment(
                queue_receipt,
                arm_receipt,
                response,
                binding_receipt,
            );
            if record.bound_commitment != Some(bound_commitment) {
                return Err(InfrastructureError::InvalidReceipt);
            }
            bound_commitment
        }
        _ => return Err(InfrastructureError::InvalidState),
    };
    if key.lineage_commitment != expected {
        return Err(InfrastructureError::InvalidReceipt);
    }
    Ok(record)
}

pub(super) fn validate_bound_service_request<'a>(
    scope: &'a ScopeInfrastructure,
    registry_instance: u64,
    bound: &BoundServiceRequest,
) -> Result<&'a ServiceRequestStateRecord, InfrastructureError> {
    validate_service_bound_key(scope, registry_instance, &bound.0)
}

fn validate_service_request_stamp(
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
    let expected_index = ReverseIndexRecord {
        slot: stamp.nonce,
        kind: InfrastructureKind::ServiceRequest,
        root_effect: stamp.root.root_effect,
        parent: match stamp.parent {
            ParentStamp::Task(parent) => ReverseParent::Task(parent),
            _ => return Err(InfrastructureError::ForeignParent),
        },
        task: match stamp.parent {
            ParentStamp::Task(parent) => Some(parent.task),
            _ => return Err(InfrastructureError::ForeignParent),
        },
        domain: stamp.domain.domain,
        binding_epoch: stamp.domain.binding_epoch,
        source_domain: Some(stamp.identity.destination_domain),
        source_binding_epoch: Some(stamp.identity.destination_binding_epoch),
        resource: Some(stamp.identity.queue),
        actor_slot: Some(stamp.identity.payload_slot),
        retry_generation: stamp.identity.generation,
    };
    if scope.reverse_indexes.get(stamp.nonce) != Some(&expected_index) {
        return Err(InfrastructureError::InvalidState);
    }
    Ok(())
}

/// Stable schema: `nexus.cser.service-response.v1` followed by every response
/// descriptor coordinate as a big-endian u64 in declaration order.
pub(super) fn service_response_commitment(
    response: ContinuationDescriptor,
) -> ServiceLineageCommitment {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.service-response.v1");
    hash_service_response(&mut hasher, response);
    ServiceLineageCommitment(hasher.finalize().into())
}

pub(super) fn service_enqueue_plan_commitment(
    plan: ServiceEnqueuePlan,
) -> ServiceLineageCommitment {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.service-enqueue-plan.v1");
    hash_service_causal_identity(&mut hasher, plan.causal);
    hash_service_word(&mut hasher, plan.bearer_generation);
    hash_service_word(&mut hasher, plan.apply_generation);
    hash_service_word(&mut hasher, plan.apply_nonce);
    ServiceLineageCommitment(hasher.finalize().into())
}

pub(super) fn service_enqueue_receipt_commitment(
    receipt: ServiceEnqueueReceipt,
) -> ServiceLineageCommitment {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.service-enqueue-receipt.v1");
    hash_service_commitment(&mut hasher, service_enqueue_plan_commitment(receipt.plan));
    hash_service_resource(&mut hasher, receipt.queue);
    hash_service_word(&mut hasher, receipt.queue_generation);
    hash_service_word(&mut hasher, u64::from(receipt.payload_slot));
    hash_service_word(&mut hasher, receipt.payload_generation);
    hash_service_word(&mut hasher, receipt.transport_receipt_digest);
    ServiceLineageCommitment(hasher.finalize().into())
}

pub(super) fn service_arm_plan_commitment(plan: ServiceArmPlan) -> ServiceLineageCommitment {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.service-arm-plan.v1");
    hash_service_causal_identity(&mut hasher, plan.causal);
    hash_service_commitment(
        &mut hasher,
        service_enqueue_receipt_commitment(plan.queue_receipt),
    );
    hash_service_word(&mut hasher, plan.bearer_generation);
    hash_service_word(&mut hasher, plan.arm_generation);
    hash_service_word(&mut hasher, plan.arm_nonce);
    ServiceLineageCommitment(hasher.finalize().into())
}

pub(super) fn service_armed_commitment(
    queue_receipt: ServiceEnqueueReceipt,
    arm_receipt: ServiceArmReceipt,
) -> ServiceLineageCommitment {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.service-armed.v1");
    hash_service_commitment(
        &mut hasher,
        service_enqueue_receipt_commitment(queue_receipt),
    );
    hash_service_commitment(&mut hasher, service_arm_plan_commitment(arm_receipt.plan));
    hash_service_word(&mut hasher, arm_receipt.response_slot_id);
    hash_service_word(&mut hasher, arm_receipt.response_slot_generation);
    hash_service_word(&mut hasher, arm_receipt.bound_continuation_id);
    hash_service_word(&mut hasher, arm_receipt.bound_continuation_generation);
    hash_service_word(&mut hasher, arm_receipt.transport_receipt_digest);
    ServiceLineageCommitment(hasher.finalize().into())
}

/// Stable schema: `nexus.cser.service-bound.v1`, the exact bind-time response,
/// then every child-binding receipt coordinate as a big-endian u64 in
/// declaration order. Optional VM authority uses a presence word followed by
/// two zero words when absent.
pub(super) fn service_bound_commitment(
    response: ContinuationDescriptor,
    receipt: ServiceChildBindingReceipt,
) -> ServiceLineageCommitment {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.service-bound.v1");
    hash_service_response(&mut hasher, response);
    hash_service_word(&mut hasher, receipt.request_id);
    hash_service_word(&mut hasher, receipt.generation);
    hash_service_word(&mut hasher, receipt.service_bearer_generation);
    hash_service_word(&mut hasher, receipt.claim_generation);
    hash_service_word(&mut hasher, receipt.claim_nonce);

    let claimant = receipt.claimant;
    hash_service_word(&mut hasher, claimant.registry_instance);
    hash_service_word(&mut hasher, claimant.scope.id());
    hash_service_word(&mut hasher, claimant.scope.generation());
    hash_service_word(&mut hasher, claimant.authority_epoch);
    hash_service_word(&mut hasher, claimant.root_effect.id());
    hash_service_word(&mut hasher, claimant.root_effect.generation());
    hash_service_word(&mut hasher, claimant.workload_request_id);
    hash_service_word(&mut hasher, claimant.workload_request_generation);
    hash_service_word(&mut hasher, claimant.workload_nonce);
    hash_service_word(&mut hasher, claimant.workload_bearer_generation);
    hash_service_word(&mut hasher, u64::from(claimant.domain.value()));
    hash_service_word(&mut hasher, claimant.binding_epoch);
    hash_service_word(&mut hasher, claimant.task.work_id);
    hash_service_word(&mut hasher, claimant.task.generation);
    hash_service_word(&mut hasher, claimant.task.task.id());
    hash_service_word(&mut hasher, claimant.task.task.generation());
    hash_service_word(
        &mut hasher,
        match claimant.task.role {
            TaskWorkRole::GuestSyscallWork => 1,
            TaskWorkRole::ServiceRequest => 2,
            TaskWorkRole::ReplacementRecovery => 3,
            TaskWorkRole::SupervisorControl => 4,
        },
    );
    match claimant.task.vm {
        Some(vm) => {
            hash_service_word(&mut hasher, 1);
            hash_service_word(&mut hasher, vm.id());
            hash_service_word(&mut hasher, vm.generation());
        }
        None => {
            hash_service_word(&mut hasher, 0);
            hash_service_word(&mut hasher, 0);
            hash_service_word(&mut hasher, 0);
        }
    }
    hash_service_word(&mut hasher, claimant.task_nonce);
    hash_service_word(&mut hasher, claimant.task_bearer_generation);
    hash_service_word(&mut hasher, receipt.child.child_effect.id());
    hash_service_word(&mut hasher, receipt.child.child_effect.generation());
    hash_service_word(&mut hasher, receipt.child.registration_digest);
    ServiceLineageCommitment(hasher.finalize().into())
}

pub(super) fn service_child_bound_commitment(
    queue_receipt: ServiceEnqueueReceipt,
    arm_receipt: ServiceArmReceipt,
    response: ContinuationDescriptor,
    binding_receipt: ServiceChildBindingReceipt,
) -> ServiceLineageCommitment {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.service-child-bound.v1");
    hash_service_commitment(
        &mut hasher,
        service_armed_commitment(queue_receipt, arm_receipt),
    );
    hash_service_commitment(
        &mut hasher,
        service_bound_commitment(response, binding_receipt),
    );
    ServiceLineageCommitment(hasher.finalize().into())
}

fn hash_service_causal_identity(hasher: &mut Sha256, causal: ServiceRequestCausalIdentity) {
    hash_service_word(hasher, causal.registry_instance);
    hash_service_word(hasher, causal.scope.id());
    hash_service_word(hasher, causal.scope.generation());
    hash_service_word(hasher, causal.authority_epoch);
    hash_service_word(hasher, causal.root_effect.id());
    hash_service_word(hasher, causal.root_effect.generation());
    hash_service_word(hasher, causal.workload_request_id);
    hash_service_word(hasher, causal.workload_request_generation);
    hash_service_word(hasher, causal.workload_nonce);
    hash_service_word(hasher, causal.workload_bearer_generation);
    hash_service_word(hasher, u64::from(causal.admission_domain.value()));
    hash_service_word(hasher, causal.admission_binding_epoch);
    hash_service_task(hasher, causal.parent_task);
    hash_service_word(hasher, causal.request_nonce);
    hash_service_descriptor(hasher, causal.descriptor);
    hash_service_response(hasher, causal.response);
}

fn hash_service_descriptor(hasher: &mut Sha256, descriptor: ServiceRequestDescriptor) {
    hash_service_word(hasher, descriptor.request_id);
    hash_service_word(hasher, descriptor.generation);
    hash_service_resource(hasher, descriptor.queue);
    hash_service_word(hasher, descriptor.queue_generation);
    hash_service_word(hasher, u64::from(descriptor.destination_domain.value()));
    hash_service_word(hasher, descriptor.destination_binding_epoch);
    hash_service_word(hasher, descriptor.command_digest);
    hash_service_word(hasher, u64::from(descriptor.payload_slot));
    hash_service_word(hasher, descriptor.payload_generation);
    hash_service_word(hasher, descriptor.response_slot_id);
    hash_service_word(hasher, descriptor.response_slot_generation);
}

fn hash_service_task(hasher: &mut Sha256, task: super::TaskWorkDescriptor) {
    hash_service_word(hasher, task.work_id);
    hash_service_word(hasher, task.generation);
    hash_service_word(hasher, task.task.id());
    hash_service_word(hasher, task.task.generation());
    hash_service_word(
        hasher,
        match task.role {
            TaskWorkRole::GuestSyscallWork => 1,
            TaskWorkRole::ServiceRequest => 2,
            TaskWorkRole::ReplacementRecovery => 3,
            TaskWorkRole::SupervisorControl => 4,
        },
    );
    match task.vm {
        Some(vm) => {
            hash_service_word(hasher, 1);
            hash_service_word(hasher, vm.id());
            hash_service_word(hasher, vm.generation());
        }
        None => {
            hash_service_word(hasher, 0);
            hash_service_word(hasher, 0);
            hash_service_word(hasher, 0);
        }
    }
}

fn hash_service_resource(hasher: &mut Sha256, resource: super::ResourceKey) {
    hash_service_word(hasher, u64::from(resource.namespace()));
    hash_service_word(hasher, resource.id());
    hash_service_word(hasher, resource.generation());
}

fn hash_service_commitment(hasher: &mut Sha256, commitment: ServiceLineageCommitment) {
    hasher.update(commitment.0);
}

fn hash_service_response(hasher: &mut Sha256, response: ContinuationDescriptor) {
    hash_service_word(hasher, response.continuation_id);
    hash_service_word(hasher, response.generation);
    hash_service_word(hasher, response.vm_generation);
    hash_service_word(hasher, u64::from(response.source_domain.value()));
    hash_service_word(hasher, response.source_binding_epoch);
}

fn hash_service_word(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_be_bytes());
}

fn validate_service_owned_continuation(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    service: &ServiceRequestStateRecord,
) -> Result<BearerStamp<ContinuationDescriptor>, InfrastructureError> {
    let response = service
        .bound_continuation
        .ok_or(InfrastructureError::InvalidState)?;
    if service.response_identity != Some(response.identity)
        || service.response_commitment != Some(service_response_commitment(response.identity))
    {
        return Err(InfrastructureError::InvalidState);
    }
    validate_continuation_bearer(scope, registry_instance, &response)?;
    let continuation = scope
        .continuations
        .get(response.identity.continuation_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if continuation.stamp != response
        || continuation.phase != ContinuationPhase::Pending
        || continuation.service_owner
            != Some(RequestKey {
                id: service.stamp.identity.request_id,
                generation: service.stamp.identity.generation,
            })
    {
        return Err(InfrastructureError::InvalidState);
    }
    Ok(response)
}

fn next_service_bearer_generation(
    record: &ServiceRequestStateRecord,
) -> Result<u64, InfrastructureError> {
    record
        .stamp
        .bearer_generation
        .checked_add(1)
        .ok_or(InfrastructureError::CounterOverflow)
}

fn service_request_causal_identity(
    stamp: &BearerStamp<ServiceRequestDescriptor>,
    response: ContinuationDescriptor,
) -> Result<ServiceRequestCausalIdentity, InfrastructureError> {
    let parent_task = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    Ok(ServiceRequestCausalIdentity {
        registry_instance: stamp.root.registry_instance,
        scope: stamp.root.scope,
        authority_epoch: stamp.root.authority_epoch,
        root_effect: stamp.root.root_effect,
        workload_request_id: stamp.workload.request.id,
        workload_request_generation: stamp.workload.request.generation,
        workload_nonce: stamp.workload.nonce,
        workload_bearer_generation: stamp.workload.bearer_generation,
        admission_domain: stamp.domain.domain,
        admission_binding_epoch: stamp.domain.binding_epoch,
        parent_task,
        request_nonce: stamp.nonce,
        descriptor: stamp.identity,
        response,
    })
}

fn valid_service_enqueue_receipt(
    expected: ServiceEnqueuePlan,
    receipt: ServiceEnqueueReceipt,
) -> bool {
    receipt.plan == expected
        && receipt.queue == expected.causal.descriptor.queue
        && receipt.queue_generation == expected.causal.descriptor.queue_generation
        && receipt.payload_slot == expected.causal.descriptor.payload_slot
        && receipt.payload_generation == expected.causal.descriptor.payload_generation
        && receipt.transport_receipt_digest != 0
}

fn valid_service_arm_receipt(expected: ServiceArmPlan, receipt: ServiceArmReceipt) -> bool {
    receipt.plan == expected
        && receipt.response_slot_id == expected.causal.descriptor.response_slot_id
        && receipt.response_slot_generation == expected.causal.descriptor.response_slot_generation
        && receipt.bound_continuation_id == expected.causal.response.continuation_id
        && receipt.bound_continuation_generation == expected.causal.response.generation
        && receipt.transport_receipt_digest != 0
}

fn service_claimant_snapshot(
    stamp: &BearerStamp<super::TaskWorkDescriptor>,
) -> ServiceClaimantSnapshot {
    ServiceClaimantSnapshot {
        registry_instance: stamp.root.registry_instance,
        scope: stamp.root.scope,
        authority_epoch: stamp.root.authority_epoch,
        root_effect: stamp.root.root_effect,
        workload_request_id: stamp.workload.request.id,
        workload_request_generation: stamp.workload.request.generation,
        workload_nonce: stamp.workload.nonce,
        workload_bearer_generation: stamp.workload.bearer_generation,
        domain: stamp.domain.domain,
        binding_epoch: stamp.domain.binding_epoch,
        task: stamp.identity,
        task_nonce: stamp.nonce,
        task_bearer_generation: stamp.bearer_generation,
    }
}

pub(super) fn validate_live_service_child_binding(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    record: &ServiceRequestStateRecord,
) -> Result<ServiceChildBindingReceipt, InfrastructureError> {
    let receipt = match record.phase {
        ServiceRequestPhase::ChildBound {
            binding_receipt, ..
        } => binding_receipt,
        _ => return Err(InfrastructureError::InvalidState),
    };
    if !valid_service_child_binding_commitment(record, receipt) {
        return Err(InfrastructureError::InvalidReceipt);
    }
    let task = scope
        .tasks
        .get(receipt.claimant.task.work_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    validate_task_stamp(scope, registry_instance, &task.stamp)?;
    if task.phase != TaskPhase::Entered
        || service_claimant_snapshot(&task.stamp) != receipt.claimant
        || task.live_children == 0
    {
        return Err(InfrastructureError::InvalidState);
    }
    Ok(receipt)
}

pub(super) fn valid_service_child_binding_commitment(
    record: &ServiceRequestStateRecord,
    receipt: ServiceChildBindingReceipt,
) -> bool {
    let descriptor = record.stamp.identity;
    let lineage_matches = match record.phase {
        ServiceRequestPhase::ChildBound {
            queue_receipt,
            arm_receipt,
            binding_receipt,
        }
        | ServiceRequestPhase::Completed {
            queue_receipt,
            arm_receipt,
            receipt: ServiceCompletionReceipt {
                binding_receipt, ..
            },
        } => {
            binding_receipt == receipt
                && record.response_identity.is_some_and(|response| {
                    record.bound_commitment
                        == Some(service_child_bound_commitment(
                            queue_receipt,
                            arm_receipt,
                            response,
                            receipt,
                        ))
                })
        }
        _ => false,
    };
    record.child_binding_commitment == Some(receipt)
        && lineage_matches
        && receipt.request_id == descriptor.request_id
        && receipt.generation == descriptor.generation
        && receipt.service_bearer_generation == record.claim_bearer_generation
        && receipt.claim_generation == record.claim_generation
        && receipt.claim_nonce == record.claim_nonce_high_water
        && receipt.service_bearer_generation != 0
        && receipt.claim_generation != 0
        && receipt.claim_nonce != 0
        && receipt.child.child_effect.generation() != 0
        && receipt.child.registration_digest != 0
        && receipt.claimant.registry_instance == record.stamp.root.registry_instance
        && receipt.claimant.scope == record.stamp.root.scope
        && receipt.claimant.authority_epoch == record.stamp.root.authority_epoch
        && receipt.claimant.root_effect == record.stamp.root.root_effect
        && receipt.claimant.domain == descriptor.destination_domain
        && receipt.claimant.binding_epoch == descriptor.destination_binding_epoch
}

struct PreparedServiceTerminal {
    service_slot: usize,
    workload_slot: usize,
    task_slot: usize,
    claimant_task_slot: Option<usize>,
    expected_service: BearerStamp<ServiceRequestDescriptor>,
    expected_phase: ServiceRequestPhase,
    expected_workload_children: u32,
    expected_task_children: u32,
    expected_claimant_task_children: Option<u32>,
    expected_live_services: u32,
    base_revision: u64,
    next_revision: u64,
    next_service: BearerStamp<ServiceRequestDescriptor>,
    next_workload_children: u32,
    next_task_children: u32,
    next_claimant_task_children: Option<u32>,
    next_live_services: u32,
}

fn prepare_service_terminal(
    scope: &ScopeInfrastructure,
    record: &ServiceRequestStateRecord,
    bearer_generation: u64,
) -> Result<PreparedServiceTerminal, InfrastructureError> {
    let parent_task = match record.stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    let service_slot = scope
        .service_requests
        .slots
        .iter()
        .position(|slot| {
            slot.as_ref()
                .is_some_and(|candidate| candidate.stamp == record.stamp)
        })
        .ok_or(InfrastructureError::UnknownObligation)?;
    let workload_slot = scope
        .workloads
        .slots
        .iter()
        .position(|slot| {
            slot.as_ref()
                .is_some_and(|workload| workload.request == record.stamp.workload.request)
        })
        .ok_or(InfrastructureError::UnknownWorkload)?;
    let task_slot = scope
        .tasks
        .slots
        .iter()
        .position(|slot| {
            slot.as_ref()
                .is_some_and(|task| task.stamp.identity == parent_task)
        })
        .ok_or(InfrastructureError::UnknownObligation)?;
    let workload = scope
        .workloads
        .slots
        .get(workload_slot)
        .and_then(Option::as_ref)
        .ok_or(InfrastructureError::UnknownWorkload)?;
    let task = scope
        .tasks
        .slots
        .get(task_slot)
        .and_then(Option::as_ref)
        .ok_or(InfrastructureError::UnknownObligation)?;
    let claimant_task = match record.phase {
        ServiceRequestPhase::ChildBound {
            queue_receipt,
            arm_receipt,
            binding_receipt,
        } if record.child_binding_commitment == Some(binding_receipt)
            && record.response_identity.is_some_and(|response| {
                record.bound_commitment
                    == Some(service_child_bound_commitment(
                        queue_receipt,
                        arm_receipt,
                        response,
                        binding_receipt,
                    ))
            }) =>
        {
            Some(binding_receipt.claimant.task)
        }
        ServiceRequestPhase::ChildBound { .. } => {
            return Err(InfrastructureError::InvalidState);
        }
        _ if record.child_binding_commitment.is_some() || record.bound_commitment.is_some() => {
            return Err(InfrastructureError::InvalidState);
        }
        _ => None,
    };
    let claimant_task_slot = claimant_task
        .filter(|claimant| *claimant != parent_task)
        .map(|claimant| {
            scope
                .tasks
                .slots
                .iter()
                .position(|slot| {
                    slot.as_ref()
                        .is_some_and(|task| task.stamp.identity == claimant)
                })
                .ok_or(InfrastructureError::UnknownObligation)
        })
        .transpose()?;
    let claimant_task_record = claimant_task_slot
        .map(|slot| {
            scope
                .tasks
                .slots
                .get(slot)
                .and_then(Option::as_ref)
                .ok_or(InfrastructureError::UnknownObligation)
        })
        .transpose()?;
    let parent_decrement = if claimant_task == Some(parent_task) {
        2
    } else {
        1
    };
    let mut next_service = record.stamp;
    next_service.bearer_generation = bearer_generation;
    Ok(PreparedServiceTerminal {
        service_slot,
        workload_slot,
        task_slot,
        claimant_task_slot,
        expected_service: record.stamp,
        expected_phase: record.phase,
        expected_workload_children: workload.live_children,
        expected_task_children: task.live_children,
        expected_claimant_task_children: claimant_task_record.map(|task| task.live_children),
        expected_live_services: scope.live.service_requests,
        base_revision: scope.revision,
        next_revision: preview_revision(scope)?,
        next_service,
        next_workload_children: preview_workload_child_sub(scope, record.stamp.workload.request)?,
        next_task_children: checked_sub(task.live_children, parent_decrement)?,
        next_claimant_task_children: claimant_task_record
            .map(|task| checked_sub(task.live_children, 1))
            .transpose()?,
        next_live_services: checked_sub(scope.live.service_requests, 1)?,
    })
}

fn apply_unbound_service_terminal(
    scope: &mut ScopeInfrastructure,
    prepared: PreparedServiceTerminal,
    terminal: ServiceRequestPhase,
) -> Result<(), InfrastructureError> {
    let PreparedServiceTerminal {
        service_slot,
        workload_slot,
        task_slot,
        claimant_task_slot,
        expected_service,
        expected_phase,
        expected_workload_children,
        expected_task_children,
        expected_claimant_task_children,
        expected_live_services,
        base_revision,
        next_revision,
        next_service,
        next_workload_children,
        next_task_children,
        next_claimant_task_children,
        next_live_services,
    } = prepared;
    if claimant_task_slot.is_some()
        || expected_claimant_task_children.is_some()
        || next_claimant_task_children.is_some()
        || scope.revision != base_revision
        || scope.live.service_requests != expected_live_services
    {
        return Err(InfrastructureError::StaleClaim);
    }
    let service = scope
        .service_requests
        .slots
        .get_mut(service_slot)
        .and_then(Option::as_mut)
        .ok_or(InfrastructureError::UnknownObligation)?;
    let workload = scope
        .workloads
        .slots
        .get_mut(workload_slot)
        .and_then(Option::as_mut)
        .ok_or(InfrastructureError::UnknownWorkload)?;
    let task = scope
        .tasks
        .slots
        .get_mut(task_slot)
        .and_then(Option::as_mut)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if service.stamp != expected_service
        || service.phase != expected_phase
        || service.bound_continuation.is_some()
        || service.response_identity.is_some()
        || service.response_commitment.is_some()
        || service.child_binding_commitment.is_some()
        || service.bound_commitment.is_some()
        || service.bind_bearer_generation != 0
        || workload.live_children != expected_workload_children
        || task.live_children != expected_task_children
    {
        return Err(InfrastructureError::StaleClaim);
    }
    service.stamp = next_service;
    service.bound_continuation = None;
    service.phase = terminal;
    workload.live_children = next_workload_children;
    task.live_children = next_task_children;
    scope.live.service_requests = next_live_services;
    scope.revision = next_revision;
    Ok(())
}

fn apply_bound_service_terminal(
    scope: &mut ScopeInfrastructure,
    prepared: PreparedServiceTerminal,
    response: BearerStamp<ContinuationDescriptor>,
    continuation_generation: u64,
    terminal: ServiceRequestPhase,
) -> Result<ContinuationLease, InfrastructureError> {
    let PreparedServiceTerminal {
        service_slot,
        workload_slot,
        task_slot,
        claimant_task_slot,
        expected_service,
        expected_phase,
        expected_workload_children,
        expected_task_children,
        expected_claimant_task_children,
        expected_live_services,
        base_revision,
        next_revision,
        next_service,
        next_workload_children,
        next_task_children,
        next_claimant_task_children,
        next_live_services,
    } = prepared;
    if scope.revision != base_revision || scope.live.service_requests != expected_live_services {
        return Err(InfrastructureError::StaleClaim);
    }
    let service = scope
        .service_requests
        .slots
        .get(service_slot)
        .and_then(Option::as_ref)
        .ok_or(InfrastructureError::UnknownObligation)?;
    let workload = scope
        .workloads
        .slots
        .get(workload_slot)
        .and_then(Option::as_ref)
        .ok_or(InfrastructureError::UnknownWorkload)?;
    let task = scope
        .tasks
        .slots
        .get(task_slot)
        .and_then(Option::as_ref)
        .ok_or(InfrastructureError::UnknownObligation)?;
    let claimant_task = claimant_task_slot
        .map(|slot| {
            scope
                .tasks
                .slots
                .get(slot)
                .and_then(Option::as_ref)
                .ok_or(InfrastructureError::UnknownObligation)
        })
        .transpose()?;
    let continuation = scope
        .continuations
        .slots
        .iter()
        .filter_map(Option::as_ref)
        .find(|record| record.stamp == response)
        .ok_or(InfrastructureError::UnknownObligation)?;
    let owner = RequestKey {
        id: expected_service.identity.request_id,
        generation: expected_service.identity.generation,
    };
    if service.stamp != expected_service
        || service.phase != expected_phase
        || service.bound_continuation != Some(response)
        || service.response_identity != Some(response.identity)
        || service.response_commitment != Some(service_response_commitment(response.identity))
        || workload.live_children != expected_workload_children
        || task.live_children != expected_task_children
        || claimant_task.map(|task| task.live_children) != expected_claimant_task_children
        || claimant_task_slot.is_some() != next_claimant_task_children.is_some()
        || continuation.phase != ContinuationPhase::Pending
        || continuation.service_owner != Some(owner)
    {
        return Err(InfrastructureError::StaleClaim);
    }

    let service = scope
        .service_requests
        .slots
        .get_mut(service_slot)
        .and_then(Option::as_mut)
        .ok_or(InfrastructureError::UnknownObligation)?;
    let workload = scope
        .workloads
        .slots
        .get_mut(workload_slot)
        .and_then(Option::as_mut)
        .ok_or(InfrastructureError::UnknownWorkload)?;
    let continuation = scope
        .continuations
        .slots
        .iter_mut()
        .filter_map(Option::as_mut)
        .find(|record| record.stamp == response)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if let Some(claimant_task_slot) = claimant_task_slot {
        let (task, claimant_task) =
            two_task_records_mut(&mut scope.tasks.slots, task_slot, claimant_task_slot)?;
        let next_claimant_task_children =
            next_claimant_task_children.ok_or(InfrastructureError::StaleClaim)?;
        service.stamp = next_service;
        service.bound_continuation = None;
        service.phase = terminal;
        workload.live_children = next_workload_children;
        task.live_children = next_task_children;
        claimant_task.live_children = next_claimant_task_children;
    } else {
        if expected_claimant_task_children.is_some() || next_claimant_task_children.is_some() {
            return Err(InfrastructureError::StaleClaim);
        }
        let task = scope
            .tasks
            .slots
            .get_mut(task_slot)
            .and_then(Option::as_mut)
            .ok_or(InfrastructureError::UnknownObligation)?;
        service.stamp = next_service;
        service.bound_continuation = None;
        service.phase = terminal;
        workload.live_children = next_workload_children;
        task.live_children = next_task_children;
    }
    scope.live.service_requests = next_live_services;
    scope.revision = next_revision;
    continuation.stamp.bearer_generation = continuation_generation;
    continuation.service_owner = None;
    Ok(ContinuationLease(mint_continuation_key::<
        bearer_state::ContinuationPending,
    >(continuation)))
}

fn two_task_records_mut(
    slots: &mut [Option<TaskRecord>],
    first: usize,
    second: usize,
) -> Result<(&mut TaskRecord, &mut TaskRecord), InfrastructureError> {
    if first == second {
        return Err(InfrastructureError::Invariant(
            "duplicate prepared service task slot",
        ));
    }
    let (first_slot, second_slot) = if first < second {
        let (lower, upper) = slots.split_at_mut(second);
        (
            lower
                .get_mut(first)
                .ok_or(InfrastructureError::UnknownObligation)?,
            upper
                .get_mut(0)
                .ok_or(InfrastructureError::UnknownObligation)?,
        )
    } else {
        let (lower, upper) = slots.split_at_mut(first);
        (
            upper
                .get_mut(0)
                .ok_or(InfrastructureError::UnknownObligation)?,
            lower
                .get_mut(second)
                .ok_or(InfrastructureError::UnknownObligation)?,
        )
    };
    Ok((
        first_slot
            .as_mut()
            .ok_or(InfrastructureError::UnknownObligation)?,
        second_slot
            .as_mut()
            .ok_or(InfrastructureError::UnknownObligation)?,
    ))
}

pub(super) fn service_request_phase_live(phase: ServiceRequestPhase) -> bool {
    !__cser_core::matches!(
        phase,
        ServiceRequestPhase::Completed { .. } | ServiceRequestPhase::Cancelled { .. }
    )
}
