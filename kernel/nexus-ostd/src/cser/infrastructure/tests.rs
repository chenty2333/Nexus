// SPDX-License-Identifier: MPL-2.0

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use super::{
    ArmedFaultTask, AuthorityKey, BearerKey, BoundServiceRequest, ContinuationAckReceipt,
    ContinuationAdoption, ContinuationDescriptor, ContinuationLease,
    ContinuationPublicationAckReceipt, ContinuationPublicationAuthority,
    ContinuationPublicationReceipt, ContinuationResumeAuthority, ContinuationResumePlan,
    ContinuationResumeReceipt, DeadlineAdoption, DeadlineClockBasis, DeadlineDescriptor,
    DeadlineExhaustedDisposition, DeadlineExpiryAuthority, DeadlineExpiryReceipt, DeadlineLease,
    DeadlinePurpose, DeadlineQuarantineReleaseReceipt, DeadlineQuarantineTicket,
    DeadlineReconciliationOutcome, DeadlineReconciliationReceipt, DeadlineRecoveryState,
    DeadlineSupervisorRetry, DelayedCommandDescriptor, DelayedCommandIntent, DelayedCommandReceipt,
    DelayedCommandRejectionReason, DelayedCommandRejectionReceipt, DelayedCommandTicket,
    DeviceAdoption, DeviceApplyIntent, DeviceCohortIdentity, DeviceEnvelope, DeviceHardwareReceipt,
    DeviceMaterializationPlan, DevicePreparationTicket, DeviceReservationCoordinates,
    DeviceRollbackReceipt, DomainKey, EffectKey, EnqueuedServiceRequest, EnteredTaskLease,
    FaultAccess, FaultDisposition, FaultObservation, FaultPhase, FaultSlotDescriptor,
    InfrastructureClosureProgress, InfrastructureClosureReceipt, InfrastructureError,
    InfrastructureKind, InfrastructureLimits, InfrastructureState, LinearFailure,
    MaterializedDeviceTicket, PortalHandle, PreparedDeviceTicket, RegistryDeviceClosureReceipt,
    ReplyAbortAuthority, ReplyAckReceipt, ReplyAdoption, ReplyClaim, ReplyDescriptor,
    ReplyPublicationIntent, ReplyPublicationReceipt, ReplyRecord, ReservedFaultTask, ResourceKey,
    ReverseIndexRecord, ReverseParent, ScopeKey, ServiceArmAuthority, ServiceArmPlan,
    ServiceArmReceipt, ServiceBoundKey, ServiceCancellationPoint, ServiceChildBindingReceipt,
    ServiceChildReceipt, ServiceClaimantSnapshot, ServiceEnqueueAuthority, ServiceEnqueuePlan,
    ServiceEnqueueReceipt, ServiceLineageCommitment, ServiceRequestCausalIdentity,
    ServiceRequestDescriptor, ServiceRequestPhase, ServiceRequestRecoveryState,
    ServiceRequestTicket, TaskAdoption, TaskAnchorRecoveryState, TaskKey, TaskPhase,
    TaskWorkDescriptor, TaskWorkRole, UnarmedServiceRequest, UnboundServiceRequest,
    ValidatedAbortProof, ValidatedCommitProof, ValidatedDeviceClosureProof,
    ValidatedServiceChildProof, VmAuthorityKey, WakeClaim, WorkloadContext,
    WorkloadRequestPresentation, WorkloadRootPresentation, bearer_state,
};

const SCOPE: ScopeKey = ScopeKey::new(0x9100, 1);
const ROOT: EffectKey = EffectKey::new(0x9200, 1);
const GUEST: DomainKey = DomainKey::new(0x91);
const SERVICE: DomainKey = DomainKey::new(0x92);

fn limits() -> InfrastructureLimits {
    InfrastructureLimits::new(8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 16, 8, 8).unwrap()
}

const COMPACT_REQUEST: u64 = 0xd300;
const COMPACT_WORK: u64 = 0xd400;
const COMPACT_TASK: u64 = 0xd500;
const COMPACT_VM: u64 = 0xd600;
const COMPACT_CONTINUATION: u64 = 0xd700;
const COMPACT_SERVICE_REQUEST: u64 = 0xd800;
const COMPACT_RESPONSE_SLOT: u64 = 0xd900;
const COMPACT_REPLY: u64 = 0xda00;
const COMPACT_REPLY_EFFECT: u64 = 0xda10;
const COMPACT_DEVICE_PREPARATION: u64 = 0xda00;

fn compact_device_coordinates() -> DeviceReservationCoordinates {
    DeviceReservationCoordinates {
        preparation_id: COMPACT_DEVICE_PREPARATION,
        generation: 1,
        owned_device: ResourceKey::new(0xda, 1, 1),
        queue: 2,
        device_generation: 1,
        operation_digest: 0xda01,
        queue_credit_class: super::super::CreditClass::new(0xda02),
        pinned_credit_class: super::super::CreditClass::new(0xda03),
        dma_credit_class: super::super::CreditClass::new(0xda04),
        actor_slot: 3,
        actor_generation: 1,
    }
}

fn compact_reserved_device_state(
    registry_instance: u64,
) -> (
    InfrastructureState,
    WorkloadContext,
    DevicePreparationTicket,
    DeviceReservationCoordinates,
) {
    let (mut state, workload, _) = compact_task_state(registry_instance);
    let coordinates = compact_device_coordinates();
    let ticket = state
        .reserve_device_preparation(&workload, ROOT, coordinates)
        .unwrap();
    (state, workload, ticket, coordinates)
}

fn compact_prepared_device_state(
    registry_instance: u64,
) -> (
    InfrastructureState,
    WorkloadContext,
    PreparedDeviceTicket,
    DeviceReservationCoordinates,
) {
    let (mut state, workload, ticket, coordinates) =
        compact_reserved_device_state(registry_instance);
    let intent = state.begin_device_hardware_apply(ticket).unwrap();
    let device = DeviceEnvelope::new(
        registry_instance + 1,
        coordinates.queue,
        7,
        coordinates.device_generation,
    )
    .unwrap();
    let prepared = state
        .acknowledge_device_prepared(
            intent,
            DeviceHardwareReceipt {
                owned_device: coordinates.owned_device,
                device,
                operation_digest: coordinates.operation_digest,
                actor_slot: coordinates.actor_slot,
                actor_generation: coordinates.actor_generation,
                hardware_receipt_digest: registry_instance + 2,
            },
        )
        .unwrap();
    (state, workload, prepared, coordinates)
}

fn compact_materialized_device_state(
    registry_instance: u64,
) -> (
    InfrastructureState,
    WorkloadContext,
    MaterializedDeviceTicket,
    DeviceReservationCoordinates,
    DeviceEnvelope,
) {
    let (mut state, workload, prepared, coordinates) =
        compact_prepared_device_state(registry_instance);
    let authority = state.prepare_device_materialization(prepared).unwrap();
    let cohort = DeviceCohortIdentity {
        block: EffectKey::new(registry_instance + 0x10, 1),
        dma: [
            EffectKey::new(registry_instance + 0x11, 1),
            EffectKey::new(registry_instance + 0x12, 1),
            EffectKey::new(registry_instance + 0x13, 1),
        ],
        digest: registry_instance + 0x14,
    };
    let mut candidate = state.try_private_candidate().unwrap();
    let materialization = candidate
        .prepare_materialize_device_in_candidate(&authority, cohort)
        .unwrap();
    candidate.apply_materialize_device_in_candidate(materialization, cohort);
    candidate
        .validate_materialized_device_candidate(&authority, cohort)
        .unwrap();
    candidate.promote_full_candidate_for_install().unwrap();
    state = candidate;
    let materialized = state.mint_materialized_device_ticket_after_install(authority, cohort);
    let device = DeviceEnvelope::new(
        registry_instance + 1,
        coordinates.queue,
        7,
        coordinates.device_generation,
    )
    .unwrap();
    (state, workload, materialized, coordinates, device)
}

fn adopt_compact_device_workload(state: &mut InfrastructureState) -> WorkloadContext {
    *state
        .scope_mut(SCOPE)
        .unwrap()
        .binding_epoch_mut(GUEST)
        .unwrap() = 2;
    state
        .adopt_workload_after_fence(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 2, COMPACT_REQUEST, 1),
        )
        .unwrap()
}

fn device_key_coordinates<State: bearer_state::Sealed>(
    key: &BearerKey<State>,
) -> (u64, ScopeKey, u64, u64, u64, u64, u64) {
    service_key_coordinates(key)
}

fn compact_task_state(
    registry_instance: u64,
) -> (InfrastructureState, WorkloadContext, EnteredTaskLease) {
    let mut state = InfrastructureState::new(registry_instance);
    state
        .enable(SCOPE, 1, ROOT, limits(), &[(GUEST, 1), (SERVICE, 1)])
        .unwrap();
    let workload = state
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 1, COMPACT_REQUEST, 1),
        )
        .unwrap();
    let task = state
        .admit_task(
            &workload,
            TaskWorkDescriptor {
                work_id: COMPACT_WORK,
                generation: 1,
                task: TaskKey::new(COMPACT_TASK, 1),
                role: TaskWorkRole::GuestSyscallWork,
                vm: Some(VmAuthorityKey::new(COMPACT_VM, 1).unwrap()),
            },
        )
        .unwrap();
    let entered = state.claim_task_entry(task).unwrap();
    (state, workload, entered)
}

fn compact_reply_descriptor() -> ReplyDescriptor {
    ReplyDescriptor {
        reply_id: COMPACT_REPLY,
        generation: 1,
        guest_task: TaskKey::new(COMPACT_TASK, 1),
        guest_vm_generation: 1,
        descriptor_digest: 0xda20,
        result_digest: 0xda21,
        byte_count: 8,
        destination_digest: 0xda22,
        source_domain: GUEST,
        source_binding_epoch: 1,
        payload_slot: 3,
        payload_generation: 1,
        flight_cookie: 0xda23,
    }
}

fn compact_reply_proof(registry_instance: u64) -> ValidatedCommitProof {
    ValidatedCommitProof::new(super::super::CommitReceipt {
        registry_instance_id: registry_instance,
        effect: EffectKey::new(COMPACT_REPLY_EFFECT, 1),
        scope: SCOPE,
        authority_epoch: 1,
        binding_epoch: 1,
        sequence: 7,
        result: 0,
        domain_revision: 1,
        descriptor_digest: 0xda24,
    })
}

fn compact_reply_publication_receipt() -> ReplyPublicationReceipt {
    let descriptor = compact_reply_descriptor();
    ReplyPublicationReceipt {
        payload_slot: descriptor.payload_slot,
        payload_generation: descriptor.payload_generation,
        flight_cookie: descriptor.flight_cookie,
        descriptor_digest: descriptor.descriptor_digest,
        result_digest: descriptor.result_digest,
        byte_count: descriptor.byte_count,
        destination_digest: descriptor.destination_digest,
        backend_effect: EffectKey::new(COMPACT_REPLY_EFFECT, 1),
        backend_commit_sequence: 7,
        external_apply_digest: 0xda25,
    }
}

fn compact_reply_state(
    registry_instance: u64,
) -> (
    InfrastructureState,
    WorkloadContext,
    EnteredTaskLease,
    ReplyRecord,
) {
    let (mut state, workload, entered) = compact_task_state(registry_instance);
    let reply = state
        .prepare_reply(
            &entered,
            compact_reply_descriptor(),
            compact_reply_proof(registry_instance),
        )
        .unwrap();
    (state, workload, entered, reply)
}

fn reply_bearer_generation(state: &InfrastructureState) -> u64 {
    state
        .scope(SCOPE)
        .unwrap()
        .replies
        .get(COMPACT_REPLY)
        .unwrap()
        .stamp
        .bearer_generation
}

fn compact_continuation_state(
    registry_instance: u64,
) -> (
    InfrastructureState,
    WorkloadContext,
    EnteredTaskLease,
    ContinuationLease,
) {
    let (mut state, workload, entered) = compact_task_state(registry_instance);
    let continuation = state
        .create_continuation(
            &entered,
            ContinuationDescriptor {
                continuation_id: COMPACT_CONTINUATION,
                generation: 1,
                vm_generation: 1,
                source_domain: GUEST,
                source_binding_epoch: 1,
            },
        )
        .unwrap();
    (state, workload, entered, continuation)
}

fn compact_bearer_generation(state: &InfrastructureState) -> u64 {
    state
        .scope(SCOPE)
        .unwrap()
        .continuations
        .get(COMPACT_CONTINUATION)
        .unwrap()
        .stamp
        .bearer_generation
}

fn service_key_coordinates<State: bearer_state::Sealed>(
    key: &BearerKey<State>,
) -> (u64, ScopeKey, u64, u64, u64, u64, u64) {
    (
        key.authority.registry_instance,
        key.authority.scope,
        key.authority.authority_epoch,
        key.slot,
        key.object_generation,
        key.bearer_generation,
        key.nonce,
    )
}

fn delayed_key_coordinates<State: bearer_state::Sealed>(
    key: &BearerKey<State>,
) -> (u64, ScopeKey, u64, u64, u64, u64, u64) {
    service_key_coordinates(key)
}

fn service_bound_key_coordinates<State: bearer_state::Sealed>(
    key: &ServiceBoundKey<State>,
) -> (
    u64,
    ScopeKey,
    u64,
    u64,
    u64,
    u64,
    u64,
    ServiceLineageCommitment,
) {
    (
        key.authority.registry_instance,
        key.authority.scope,
        key.authority.authority_epoch,
        key.slot,
        key.object_generation,
        key.bearer_generation,
        key.nonce,
        key.lineage_commitment,
    )
}

fn compact_service_descriptor() -> ServiceRequestDescriptor {
    ServiceRequestDescriptor {
        request_id: COMPACT_SERVICE_REQUEST,
        generation: 1,
        queue: ResourceKey::new(0xda, 1, 1),
        queue_generation: 1,
        destination_domain: SERVICE,
        destination_binding_epoch: 1,
        command_digest: 0xdb,
        payload_slot: 3,
        payload_generation: 1,
        response_slot_id: COMPACT_RESPONSE_SLOT,
        response_slot_generation: 1,
    }
}

fn compact_response_descriptor() -> ContinuationDescriptor {
    ContinuationDescriptor {
        continuation_id: COMPACT_CONTINUATION,
        generation: 1,
        vm_generation: 1,
        source_domain: GUEST,
        source_binding_epoch: 1,
    }
}

fn compact_unbound_service_state(
    registry_instance: u64,
) -> (InfrastructureState, UnboundServiceRequest) {
    let (mut state, _, entered) = compact_task_state(registry_instance);
    let service = state
        .reserve_service_request(&entered, compact_service_descriptor())
        .unwrap();
    (state, service)
}

fn continuation_resume_receipt(
    plan: ContinuationResumePlan,
    external_receipt_digest: u64,
) -> ContinuationResumeReceipt {
    ContinuationResumeReceipt {
        continuation_id: plan.descriptor.continuation_id,
        generation: plan.descriptor.generation,
        publication_sequence: plan.publication_sequence,
        vm_generation: plan.descriptor.vm_generation,
        source_domain: plan.descriptor.source_domain,
        source_binding_epoch: plan.descriptor.source_binding_epoch,
        outcome_digest: plan.outcome_digest,
        ack_generation: plan.ack_generation,
        ack_nonce: plan.ack_nonce,
        resume_generation: plan.resume_generation,
        resume_nonce: plan.resume_nonce,
        external_receipt_digest,
    }
}

fn compact_bound_service_state(
    registry_instance: u64,
) -> (InfrastructureState, ServiceRequestTicket) {
    let (mut state, service) = compact_unbound_service_state(registry_instance);
    let service = state
        .bind_service_response_continuation(service, compact_response_descriptor())
        .unwrap();
    (state, service)
}

fn compact_bound_service_state_with_sibling_response(
    registry_instance: u64,
) -> (
    InfrastructureState,
    ServiceRequestTicket,
    ContinuationDescriptor,
) {
    let (mut state, service) = compact_bound_service_state(registry_instance);
    let parent = {
        let scope = state.scope(SCOPE).unwrap();
        let service_record = scope.service_requests.get(COMPACT_SERVICE_REQUEST).unwrap();
        let parent = match service_record.stamp.parent {
            super::ParentStamp::Task(parent) => parent,
            _ => __cser_core::unreachable!(),
        };
        EnteredTaskLease(super::mint_task_key::<bearer_state::TaskEntered>(
            scope.tasks.get(parent.work_id).unwrap(),
        ))
    };
    let sibling = ContinuationDescriptor {
        continuation_id: COMPACT_CONTINUATION + 1,
        ..compact_response_descriptor()
    };
    let _sibling_lease = state.create_continuation(&parent, sibling).unwrap();
    (state, service, sibling)
}

fn add_service_claimant(state: &mut InfrastructureState, identity_base: u64) -> ArmedFaultTask {
    let workload = state
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(SERVICE, 1, identity_base, 1),
        )
        .unwrap();
    let task = state
        .admit_task(
            &workload,
            TaskWorkDescriptor {
                work_id: identity_base + 1,
                generation: 1,
                task: TaskKey::new(identity_base + 2, 1),
                role: TaskWorkRole::ServiceRequest,
                vm: Some(VmAuthorityKey::new(identity_base + 3, 1).unwrap()),
            },
        )
        .unwrap();
    let reserved = state
        .reserve_fault_event(
            task,
            FaultSlotDescriptor {
                fault_id: identity_base + 8,
                generation: 1,
                task: TaskKey::new(identity_base + 2, 1),
                vm_generation: 1,
                service_domain: SERVICE,
                admission_binding_epoch: 1,
            },
        )
        .unwrap();
    state.claim_service_task_entry(reserved).unwrap()
}

fn compact_child_bound_service_state(
    registry_instance: u64,
    claimant_base: u64,
) -> (InfrastructureState, BoundServiceRequest) {
    let (mut state, ticket) = compact_bound_service_state(registry_instance);
    let (enqueue_plan, enqueue_authority) = state.begin_service_enqueue(ticket).unwrap();
    let unarmed = state
        .acknowledge_service_enqueue(
            enqueue_authority,
            service_enqueue_receipt(enqueue_plan, claimant_base + 5),
        )
        .unwrap();
    let (arm_plan, arm_authority) = state.begin_service_arm(unarmed).unwrap();
    let enqueued = state
        .acknowledge_service_arm(
            arm_authority,
            service_arm_receipt(arm_plan, claimant_base + 6),
        )
        .unwrap();
    let claimant = add_service_claimant(&mut state, claimant_base);
    let bound = state
        .claim_and_bind_service_child(
            enqueued,
            &claimant,
            ValidatedServiceChildProof::new(ServiceChildReceipt {
                child_effect: EffectKey::new(claimant_base + 4, 1),
                registration_digest: claimant_base + 7,
            }),
        )
        .unwrap();
    (state, bound)
}

const COMPACT_DELAYED_CLAIMANT: u64 = 0xee00;
const COMPACT_DELAYED_COMMAND: u64 = 0xee20;

fn compact_delayed_descriptor() -> DelayedCommandDescriptor {
    DelayedCommandDescriptor {
        command_id: COMPACT_DELAYED_COMMAND,
        generation: 1,
        request_id: COMPACT_SERVICE_REQUEST,
        request_generation: 1,
        destination_domain: SERVICE,
        destination_binding_epoch: 1,
        sender: TaskKey::new(COMPACT_DELAYED_CLAIMANT + 2, 1),
        target: PortalHandle {
            scope: SCOPE,
            effect: EffectKey::new(COMPACT_DELAYED_CLAIMANT + 4, 1),
            domain: SERVICE,
            authority_epoch: 1,
            binding_epoch: 1,
            nonce: COMPACT_DELAYED_COMMAND + 1,
        },
        command_digest: COMPACT_DELAYED_COMMAND + 2,
        actor_slot: 7,
        actor_generation: 1,
    }
}

fn compact_delayed_state(
    registry_instance: u64,
) -> (
    InfrastructureState,
    DelayedCommandTicket,
    DelayedCommandDescriptor,
) {
    let (mut state, bound) =
        compact_child_bound_service_state(registry_instance, COMPACT_DELAYED_CLAIMANT);
    let armed = ArmedFaultTask(super::mint_task_key::<bearer_state::TaskFaultArmed>(
        state
            .scope(SCOPE)
            .unwrap()
            .tasks
            .get(COMPACT_DELAYED_CLAIMANT + 1)
            .unwrap(),
    ));
    let descriptor = compact_delayed_descriptor();
    let ticket = state
        .reserve_delayed_command(&armed, &bound, descriptor)
        .unwrap();
    (state, ticket, descriptor)
}

fn current_delayed_ticket(state: &InfrastructureState) -> DelayedCommandTicket {
    DelayedCommandTicket(super::delayed::mint_delayed_command_key::<
        bearer_state::DelayedReserved,
    >(
        state
            .scope(SCOPE)
            .unwrap()
            .delayed_commands
            .get(COMPACT_DELAYED_COMMAND)
            .unwrap(),
    ))
}

fn delayed_receipt(
    descriptor: DelayedCommandDescriptor,
    transport_receipt_digest: u64,
) -> DelayedCommandReceipt {
    DelayedCommandReceipt {
        actor_slot: descriptor.actor_slot,
        actor_generation: descriptor.actor_generation,
        command_digest: descriptor.command_digest,
        transport_receipt_digest,
    }
}

fn delayed_rejection(
    descriptor: DelayedCommandDescriptor,
    reason: DelayedCommandRejectionReason,
    evidence_digest: u64,
) -> DelayedCommandRejectionReceipt {
    DelayedCommandRejectionReceipt {
        reason,
        target_effect: descriptor.target.effect(),
        evidence_digest,
    }
}

fn assert_delayed_record_mutation_rejected(
    registry_instance: u64,
    mutate: impl FnOnce(&mut super::DelayedCommandStateRecord),
    expected_error: InfrastructureError,
) {
    let (mut state, ticket, _) = compact_delayed_state(registry_instance);
    let presented = delayed_key_coordinates(&ticket.0);
    mutate(
        state
            .scope_mut(SCOPE)
            .unwrap()
            .delayed_commands
            .get_mut(COMPACT_DELAYED_COMMAND)
            .unwrap(),
    );
    let before = state.private_full_clone();
    let failure = state.begin_delayed_command_delivery(ticket).unwrap_err();
    __cser_core::assert_eq!(failure.error(), expected_error);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(delayed_key_coordinates(&failure.into_input().0), presented);
}

fn assert_delayed_ack_mutation_rejected(
    registry_instance: u64,
    mutate: impl FnOnce(&mut DelayedCommandReceipt),
) {
    let (mut state, ticket, descriptor) = compact_delayed_state(registry_instance);
    let intent = state.begin_delayed_command_delivery(ticket).unwrap();
    let presented = delayed_key_coordinates(&intent.0);
    let mut receipt = delayed_receipt(descriptor, registry_instance + 0x100);
    mutate(&mut receipt);
    let before = state.private_full_clone();
    let failure = state
        .acknowledge_delayed_command(intent, receipt)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(delayed_key_coordinates(&failure.into_input().0), presented);
}

fn substitute_queue_response(
    mut receipt: ServiceEnqueueReceipt,
    response: ContinuationDescriptor,
) -> ServiceEnqueueReceipt {
    receipt.plan.causal.response = response;
    receipt
}

fn substitute_arm_response(
    mut receipt: ServiceArmReceipt,
    queue_receipt: ServiceEnqueueReceipt,
    response: ContinuationDescriptor,
) -> ServiceArmReceipt {
    receipt.plan.causal.response = response;
    receipt.plan.queue_receipt = queue_receipt;
    receipt.bound_continuation_id = response.continuation_id;
    receipt.bound_continuation_generation = response.generation;
    receipt
}

fn synchronously_substitute_service_response(
    state: &mut InfrastructureState,
    response: ContinuationDescriptor,
) {
    let scope = state.scope_mut(SCOPE).unwrap();
    let (old_response, owner) = {
        let service = scope.service_requests.get(COMPACT_SERVICE_REQUEST).unwrap();
        (
            service.response_identity.unwrap(),
            super::RequestKey {
                id: service.stamp.identity.request_id,
                generation: service.stamp.identity.generation,
            },
        )
    };
    scope
        .continuations
        .get_mut(old_response.continuation_id)
        .unwrap()
        .service_owner = None;
    scope
        .continuations
        .get_mut(response.continuation_id)
        .unwrap()
        .service_owner = Some(owner);
    let response_stamp = scope
        .continuations
        .get(response.continuation_id)
        .unwrap()
        .stamp;
    let service = scope
        .service_requests
        .get_mut(COMPACT_SERVICE_REQUEST)
        .unwrap();
    service.bound_continuation = Some(response_stamp);
    service.response_identity = Some(response);
    service.response_commitment = Some(super::service::service_response_commitment(response));
    service.phase = match service.phase {
        ServiceRequestPhase::ReservedBound | ServiceRequestPhase::Publishing { .. } => {
            service.phase
        }
        ServiceRequestPhase::QueueWrittenUnarmed { queue_receipt } => {
            ServiceRequestPhase::QueueWrittenUnarmed {
                queue_receipt: substitute_queue_response(queue_receipt, response),
            }
        }
        ServiceRequestPhase::Arming {
            queue_receipt,
            arm_generation,
            arm_nonce,
        } => ServiceRequestPhase::Arming {
            queue_receipt: substitute_queue_response(queue_receipt, response),
            arm_generation,
            arm_nonce,
        },
        ServiceRequestPhase::Armed {
            queue_receipt,
            arm_receipt,
        } => {
            let queue_receipt = substitute_queue_response(queue_receipt, response);
            ServiceRequestPhase::Armed {
                queue_receipt,
                arm_receipt: substitute_arm_response(arm_receipt, queue_receipt, response),
            }
        }
        ServiceRequestPhase::ChildBound {
            queue_receipt,
            arm_receipt,
            binding_receipt,
        } => {
            let queue_receipt = substitute_queue_response(queue_receipt, response);
            let arm_receipt = substitute_arm_response(arm_receipt, queue_receipt, response);
            service.bound_commitment = Some(super::service::service_child_bound_commitment(
                queue_receipt,
                arm_receipt,
                response,
                binding_receipt,
            ));
            ServiceRequestPhase::ChildBound {
                queue_receipt,
                arm_receipt,
                binding_receipt,
            }
        }
        _ => __cser_core::panic!("response substitution requires a live bound service"),
    };
    state.check_invariants().unwrap();
}

fn service_enqueue_receipt(
    plan: ServiceEnqueuePlan,
    transport_receipt_digest: u64,
) -> ServiceEnqueueReceipt {
    ServiceEnqueueReceipt {
        plan,
        queue: plan.causal.descriptor.queue,
        queue_generation: plan.causal.descriptor.queue_generation,
        payload_slot: plan.causal.descriptor.payload_slot,
        payload_generation: plan.causal.descriptor.payload_generation,
        transport_receipt_digest,
    }
}

fn service_arm_receipt(plan: ServiceArmPlan, transport_receipt_digest: u64) -> ServiceArmReceipt {
    ServiceArmReceipt {
        plan,
        response_slot_id: plan.causal.descriptor.response_slot_id,
        response_slot_generation: plan.causal.descriptor.response_slot_generation,
        bound_continuation_id: plan.causal.response.continuation_id,
        bound_continuation_generation: plan.causal.response.generation,
        transport_receipt_digest,
    }
}

fn assert_enqueue_receipt_mutation_rejected(
    registry_instance: u64,
    mutate: fn(&mut ServiceEnqueueReceipt),
) {
    let (mut state, service) = compact_bound_service_state(registry_instance);
    let (plan, authority) = state.begin_service_enqueue(service).unwrap();
    let presented = service_bound_key_coordinates(&authority.0);
    let mut receipt = service_enqueue_receipt(plan, 0xed01);
    mutate(&mut receipt);
    let before = state.private_full_clone();
    let failure = state
        .acknowledge_service_enqueue(authority, receipt)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        presented
    );
}

fn assert_arm_receipt_mutation_rejected(
    registry_instance: u64,
    mutate: fn(&mut ServiceArmReceipt),
) {
    let (mut state, service) = compact_bound_service_state(registry_instance);
    let (enqueue_plan, enqueue_authority) = state.begin_service_enqueue(service).unwrap();
    let unarmed = state
        .acknowledge_service_enqueue(
            enqueue_authority,
            service_enqueue_receipt(enqueue_plan, 0xed02),
        )
        .unwrap();
    let (plan, authority) = state.begin_service_arm(unarmed).unwrap();
    let presented = service_bound_key_coordinates(&authority.0);
    let mut receipt = service_arm_receipt(plan, 0xed03);
    mutate(&mut receipt);
    let before = state.private_full_clone();
    let failure = state
        .acknowledge_service_arm(authority, receipt)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        presented
    );
}

const COMPACT_DEADLINE_REQUEST: u64 = 0xf300;
const COMPACT_DEADLINE_WORK: u64 = 0xf400;
const COMPACT_DEADLINE_TASK: u64 = 0xf500;
const COMPACT_DEADLINE_VM: u64 = 0xf600;
const COMPACT_DEADLINE: u64 = 0xf700;

fn compact_deadline_parent_state(
    registry_instance: u64,
) -> (InfrastructureState, WorkloadContext, EnteredTaskLease) {
    let mut state = InfrastructureState::new(registry_instance);
    state
        .enable(SCOPE, 1, ROOT, limits(), &[(GUEST, 1), (SERVICE, 1)])
        .unwrap();
    let workload = state
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 1, COMPACT_DEADLINE_REQUEST, 1),
        )
        .unwrap();
    let task = state
        .admit_task(
            &workload,
            TaskWorkDescriptor {
                work_id: COMPACT_DEADLINE_WORK,
                generation: 1,
                task: TaskKey::new(COMPACT_DEADLINE_TASK, 1),
                role: TaskWorkRole::GuestSyscallWork,
                vm: Some(VmAuthorityKey::new(COMPACT_DEADLINE_VM, 1).unwrap()),
            },
        )
        .unwrap();
    let entered = state.claim_task_entry(task).unwrap();
    (state, workload, entered)
}

fn compact_deadline_state(
    registry_instance: u64,
    max_attempts: u32,
) -> (
    InfrastructureState,
    WorkloadContext,
    EnteredTaskLease,
    DeadlineLease,
) {
    let (mut state, workload, entered) = compact_deadline_parent_state(registry_instance);
    let deadline = state
        .arm_deadline(
            &entered,
            DeadlineDescriptor {
                series_id: COMPACT_DEADLINE,
                generation: 1,
                purpose: DeadlinePurpose::Wait,
                clock: DeadlineClockBasis::ObservedCallbackTick,
                deadline_tick: 10,
                attempt: 1,
                max_attempts,
                backoff_ticks: 5,
            },
        )
        .unwrap();
    (state, workload, entered, deadline)
}

fn deadline_coordinates(state: &InfrastructureState) -> (u64, u64, u64) {
    let record = state
        .scope(SCOPE)
        .unwrap()
        .deadlines
        .get(COMPACT_DEADLINE)
        .unwrap();
    (
        record.stamp.identity.generation,
        record.stamp.bearer_generation,
        record.stamp.nonce,
    )
}

fn deadline_expiry_coordinates(
    expiry: &DeadlineExpiryReceipt,
) -> (bool, u64, ScopeKey, u64, u64, u64, u64, u64) {
    match &expiry.0 {
        DeadlineExpiryAuthority::Fired(key) => (
            false,
            key.authority.registry_instance,
            key.authority.scope,
            key.authority.authority_epoch,
            key.slot,
            key.object_generation,
            key.bearer_generation,
            key.nonce,
        ),
        DeadlineExpiryAuthority::Exhausted(key) => (
            true,
            key.authority.registry_instance,
            key.authority.scope,
            key.authority.authority_epoch,
            key.slot,
            key.object_generation,
            key.bearer_generation,
            key.nonce,
        ),
    }
}

fn assert_deadline_key_rejected_without_mutation(
    registry_instance: u64,
    mutate: impl FnOnce(&mut DeadlineLease),
    expected_error: InfrastructureError,
) {
    let (mut state, _, _, mut deadline) = compact_deadline_state(registry_instance, 2);
    mutate(&mut deadline);
    let presented = (
        deadline.0.authority.registry_instance,
        deadline.0.authority.scope,
        deadline.0.authority.authority_epoch,
        deadline.0.slot,
        deadline.0.object_generation,
        deadline.0.bearer_generation,
        deadline.0.nonce,
    );
    let before = state.private_full_clone();
    let failure = state
        .fire_deadline(deadline, DeadlineClockBasis::ObservedCallbackTick, 10)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), expected_error);
    __cser_core::assert_eq!(state, before);
    let returned = failure.into_input();
    __cser_core::assert_eq!(
        (
            returned.0.authority.registry_instance,
            returned.0.authority.scope,
            returned.0.authority.authority_epoch,
            returned.0.slot,
            returned.0.object_generation,
            returned.0.bearer_generation,
            returned.0.nonce,
        ),
        presented
    );
}

#[test]
fn continuation_compact_authority_layout_is_bounded() {
    __cser_core::assert!(__cser_core::mem::size_of::<AuthorityKey>() <= 32);
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::ContinuationPending>>() <= 64
    );
    __cser_core::assert!(__cser_core::mem::size_of::<ContinuationLease>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<WakeClaim>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<ContinuationPublicationAuthority>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<ContinuationPublicationAckReceipt>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<ContinuationAckReceipt>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<ContinuationResumeAuthority>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<ContinuationResumeReceipt>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<ContinuationLease>>() <= 120);
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<WakeClaim>>() <= 120);
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<ContinuationPublicationAuthority>>() <= 120
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<ContinuationAckReceipt>>() <= 120
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<ContinuationResumeAuthority>>() <= 120
    );
}

#[test]
fn service_compact_authority_layout_is_bounded() {
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::ServiceReservedUnbound>>() <= 64
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceReservedBound>>() <= 96
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceEnqueuePublishing>>()
            <= 96
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceQueueWritten>>() <= 96
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceArmPublishing>>() <= 96
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceArmed>>() <= 96
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceChildBound>>() <= 96
    );
    __cser_core::assert!(__cser_core::mem::size_of::<UnboundServiceRequest>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceRequestTicket>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceEnqueueAuthority>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<UnarmedServiceRequest>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceArmAuthority>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<EnqueuedServiceRequest>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<BoundServiceRequest>() <= 96);
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<UnboundServiceRequest>>() <= 120
    );
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<ServiceRequestTicket>>() <= 120);
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<ServiceEnqueueAuthority>>() <= 120
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<UnarmedServiceRequest>>() <= 120
    );
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<ServiceArmAuthority>>() <= 120);
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<EnqueuedServiceRequest>>() <= 120
    );
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<BoundServiceRequest>>() <= 120);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceRequestCausalIdentity>() <= 512);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceEnqueuePlan>() <= 512);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceEnqueueReceipt>() <= 640);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceArmPlan>() <= 1_280);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceArmReceipt>() <= 1_408);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceClaimantSnapshot>() <= 320);
    __cser_core::assert!(__cser_core::mem::size_of::<ServiceChildBindingReceipt>() <= 384);
}

#[test]
fn device_compact_authority_layout_is_bounded() {
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::DeviceReserved>>() <= 64
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::DeviceApplying>>() <= 64
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::DevicePrepared>>() <= 64
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::DeviceMaterialized>>() <= 64
    );
    __cser_core::assert!(__cser_core::mem::size_of::<DevicePreparationTicket>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<DeviceApplyIntent>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<PreparedDeviceTicket>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<DeviceMaterializationPlan>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<MaterializedDeviceTicket>() <= 96);
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<DevicePreparationTicket>>() <= 120
    );
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<DeviceApplyIntent>>() <= 120);
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<PreparedDeviceTicket>>() <= 120);
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<DeviceMaterializationPlan>>() <= 120
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<MaterializedDeviceTicket>>() <= 120
    );
}

#[test]
fn device_compact_key_rejects_each_stale_coordinate_without_mutation() {
    fn reject(
        state: &mut InfrastructureState,
        ticket: &DevicePreparationTicket,
        expected: InfrastructureError,
        mutate: impl FnOnce(&mut DevicePreparationTicket),
    ) {
        let mut presented = ticket.duplicate_for_test();
        mutate(&mut presented);
        let exact = device_key_coordinates(&presented.0);
        let before = state.private_full_clone();
        let failure = state.begin_device_hardware_apply(presented).unwrap_err();
        __cser_core::assert_eq!(failure.error(), expected);
        __cser_core::assert_eq!(*state, before);
        __cser_core::assert_eq!(device_key_coordinates(&failure.into_input().0), exact);
    }

    let (mut state, _, ticket, _) = compact_reserved_device_state(0xda10);
    reject(
        &mut state,
        &ticket,
        InfrastructureError::ForeignRegistry,
        |presented| presented.0.authority.registry_instance += 1,
    );
    reject(
        &mut state,
        &ticket,
        InfrastructureError::NotEnabled,
        |presented| presented.0.authority.scope = ScopeKey::new(0xda11, 1),
    );
    reject(
        &mut state,
        &ticket,
        InfrastructureError::StaleAuthority,
        |presented| presented.0.authority.authority_epoch += 1,
    );
    reject(
        &mut state,
        &ticket,
        InfrastructureError::UnknownObligation,
        |presented| presented.0.slot += 1,
    );
    reject(
        &mut state,
        &ticket,
        InfrastructureError::StaleGeneration,
        |presented| presented.0.object_generation += 1,
    );
    reject(
        &mut state,
        &ticket,
        InfrastructureError::StaleGeneration,
        |presented| presented.0.bearer_generation += 1,
    );
    reject(
        &mut state,
        &ticket,
        InfrastructureError::StaleGeneration,
        |presented| presented.0.nonce += 1,
    );

    state.begin_device_hardware_apply(ticket).unwrap();
    state.check_invariants().unwrap();
}

#[test]
fn device_transition_revalidates_primary_lineage_phase_and_reverse_index() {
    fn reject(
        mut state: InfrastructureState,
        ticket: &DevicePreparationTicket,
        expected: InfrastructureError,
        mutate: impl FnOnce(&mut InfrastructureState),
    ) {
        mutate(&mut state);
        let presented = ticket.duplicate_for_test();
        let exact = device_key_coordinates(&presented.0);
        let before = state.private_full_clone();
        let failure = state.begin_device_hardware_apply(presented).unwrap_err();
        __cser_core::assert_eq!(failure.error(), expected);
        __cser_core::assert_eq!(state, before);
        __cser_core::assert_eq!(device_key_coordinates(&failure.into_input().0), exact);
    }

    let (state, _, ticket, coordinates) = compact_reserved_device_state(0xda20);
    reject(
        state.private_full_clone(),
        &ticket,
        InfrastructureError::ForeignRootEffect,
        |candidate| {
            candidate
                .scope_mut(SCOPE)
                .unwrap()
                .devices
                .get_mut(coordinates.preparation_id)
                .unwrap()
                .stamp
                .root
                .root_effect = EffectKey::new(ROOT.id() + 1, ROOT.generation());
        },
    );
    reject(
        state.private_full_clone(),
        &ticket,
        InfrastructureError::StaleBinding,
        |candidate| {
            candidate
                .scope_mut(SCOPE)
                .unwrap()
                .devices
                .get_mut(coordinates.preparation_id)
                .unwrap()
                .stamp
                .domain
                .binding_epoch += 1;
        },
    );
    reject(
        state.private_full_clone(),
        &ticket,
        InfrastructureError::ForeignWorkload,
        |candidate| {
            candidate
                .scope_mut(SCOPE)
                .unwrap()
                .devices
                .get_mut(coordinates.preparation_id)
                .unwrap()
                .stamp
                .workload
                .nonce += 1;
        },
    );
    reject(
        state.private_full_clone(),
        &ticket,
        InfrastructureError::ForeignParent,
        |candidate| {
            candidate
                .scope_mut(SCOPE)
                .unwrap()
                .devices
                .get_mut(coordinates.preparation_id)
                .unwrap()
                .stamp
                .parent = super::ParentStamp::RootEffect(ROOT);
        },
    );
    reject(
        state.private_full_clone(),
        &ticket,
        InfrastructureError::Invariant("device reverse index mismatch"),
        |candidate| {
            let scope = candidate.scope_mut(SCOPE).unwrap();
            let nonce = scope
                .devices
                .get(coordinates.preparation_id)
                .unwrap()
                .stamp
                .nonce;
            scope
                .reverse_indexes
                .get_mut(nonce)
                .unwrap()
                .actor_generation = Some(coordinates.actor_generation + 1);
        },
    );
    reject(
        state,
        &ticket,
        InfrastructureError::InvalidState,
        |candidate| {
            let record = candidate
                .scope_mut(SCOPE)
                .unwrap()
                .devices
                .get_mut(coordinates.preparation_id)
                .unwrap();
            record.apply_generation = 1;
            record.credit_ownership = super::DeviceCreditOwnership::Retained;
            record.phase = super::DevicePhase::Applying {
                apply_generation: 1,
                apply_nonce: 0xda21,
            };
        },
    );
}

#[test]
fn device_success_and_terminal_paths_advance_bearer_generation() {
    fn closure_proof(
        registry_instance: u64,
        device: DeviceEnvelope,
        batch_sequence: Option<u64>,
    ) -> ValidatedDeviceClosureProof {
        ValidatedDeviceClosureProof::new(RegistryDeviceClosureReceipt {
            registry_instance_id: registry_instance,
            scope: SCOPE,
            enrollment_sequence: 1,
            batch_sequence,
            device,
            sequence: 1,
            outcome: super::super::DeviceClosureResult::Completed(0),
        })
    }

    let (mut cancelled, _, reserved, coordinates) = compact_reserved_device_state(0xda22);
    let reserved_generation = reserved.0.bearer_generation;
    cancelled.cancel_reserved_device(reserved).unwrap();
    let record = cancelled
        .scope(SCOPE)
        .unwrap()
        .devices
        .get(coordinates.preparation_id)
        .unwrap();
    __cser_core::assert_eq!(record.stamp.bearer_generation, reserved_generation + 1);
    __cser_core::assert!(__cser_core::matches!(
        record.phase,
        super::DevicePhase::Cancelled { rollback: None }
    ));
    cancelled.check_invariants().unwrap();

    let (mut rolled_back, _, reserved, coordinates) = compact_reserved_device_state(0xda23);
    let intent = rolled_back.begin_device_hardware_apply(reserved).unwrap();
    let applying_generation = intent.0.bearer_generation;
    rolled_back
        .acknowledge_device_apply_rollback(
            intent,
            DeviceRollbackReceipt {
                owned_device: coordinates.owned_device,
                queue: coordinates.queue,
                device_generation: coordinates.device_generation,
                operation_digest: coordinates.operation_digest,
                actor_slot: coordinates.actor_slot,
                actor_generation: coordinates.actor_generation,
                rollback_receipt_digest: 0xda24,
            },
        )
        .unwrap();
    let record = rolled_back
        .scope(SCOPE)
        .unwrap()
        .devices
        .get(coordinates.preparation_id)
        .unwrap();
    __cser_core::assert_eq!(record.stamp.bearer_generation, applying_generation + 1);
    __cser_core::assert!(__cser_core::matches!(
        record.phase,
        super::DevicePhase::Cancelled { rollback: Some(_) }
    ));
    rolled_back.check_invariants().unwrap();

    let (mut unmaterialized, _, prepared, coordinates) = compact_prepared_device_state(0xda25);
    let prepared_generation = prepared.0.bearer_generation;
    let device =
        DeviceEnvelope::new(0xda26, coordinates.queue, 7, coordinates.device_generation).unwrap();
    unmaterialized
        .release_unmaterialized_retained_device(prepared, closure_proof(0xda25, device, None))
        .unwrap();
    let record = unmaterialized
        .scope(SCOPE)
        .unwrap()
        .devices
        .get(coordinates.preparation_id)
        .unwrap();
    __cser_core::assert_eq!(record.stamp.bearer_generation, prepared_generation + 1);
    __cser_core::assert!(__cser_core::matches!(
        record.phase,
        super::DevicePhase::Released { cohort: None, .. }
    ));
    unmaterialized.check_invariants().unwrap();

    let (mut materialized, _, ticket, coordinates, device) =
        compact_materialized_device_state(0xda27);
    let materialized_generation = ticket.0.bearer_generation;
    materialized
        .release_materialized_device(ticket, closure_proof(0xda27, device, Some(1)))
        .unwrap();
    let record = materialized
        .scope(SCOPE)
        .unwrap()
        .devices
        .get(coordinates.preparation_id)
        .unwrap();
    __cser_core::assert_eq!(record.stamp.bearer_generation, materialized_generation + 1);
    __cser_core::assert!(__cser_core::matches!(
        record.phase,
        super::DevicePhase::Released {
            cohort: Some(_),
            ..
        }
    ));
    materialized.check_invariants().unwrap();
}

#[test]
fn device_adoption_fences_every_live_typestate_and_is_failure_atomic() {
    fn assert_next_generation(previous: u64, current: u64) {
        __cser_core::assert_eq!(current, previous.checked_add(1).unwrap());
    }

    let (mut reserved_state, _, reserved, coordinates) = compact_reserved_device_state(0xda30);
    let reserved_generation = reserved.0.bearer_generation;
    let adopted_workload = adopt_compact_device_workload(&mut reserved_state);
    let adopted_reserved = reserved_state
        .adopt_device_after_fence(
            &adopted_workload,
            coordinates.preparation_id,
            coordinates.generation,
        )
        .unwrap();
    let DeviceAdoption::Reserved(current_reserved) = adopted_reserved else {
        __cser_core::panic!("reserved adoption changed typestate");
    };
    assert_next_generation(reserved_generation, current_reserved.0.bearer_generation);
    __cser_core::assert_eq!(
        reserved_state.device_preparation_coordinates(&reserved),
        Err(InfrastructureError::StaleGeneration)
    );
    reserved_state
        .device_preparation_coordinates(&current_reserved)
        .unwrap();

    let (mut applying_state, _, reserved, coordinates) = compact_reserved_device_state(0xda40);
    let applying = applying_state
        .begin_device_hardware_apply(reserved)
        .unwrap();
    let old_bearer_generation = applying.0.bearer_generation;
    let (old_apply_generation, old_apply_nonce) = {
        let record = applying_state
            .scope(SCOPE)
            .unwrap()
            .devices
            .get(coordinates.preparation_id)
            .unwrap();
        let super::DevicePhase::Applying {
            apply_generation,
            apply_nonce,
        } = record.phase
        else {
            __cser_core::unreachable!();
        };
        (apply_generation, apply_nonce)
    };
    let adopted_workload = adopt_compact_device_workload(&mut applying_state);
    let adopted_applying = applying_state
        .adopt_device_after_fence(
            &adopted_workload,
            coordinates.preparation_id,
            coordinates.generation,
        )
        .unwrap();
    let DeviceAdoption::ReplayApply(current_applying) = adopted_applying else {
        __cser_core::panic!("applying adoption changed typestate");
    };
    assert_next_generation(old_bearer_generation, current_applying.0.bearer_generation);
    let record = applying_state
        .scope(SCOPE)
        .unwrap()
        .devices
        .get(coordinates.preparation_id)
        .unwrap();
    let super::DevicePhase::Applying {
        apply_generation,
        apply_nonce,
    } = record.phase
    else {
        __cser_core::unreachable!();
    };
    assert_next_generation(old_apply_generation, apply_generation);
    __cser_core::assert_ne!(apply_nonce, old_apply_nonce);
    __cser_core::assert_eq!(
        applying_state.device_apply_coordinates(&applying),
        Err(InfrastructureError::StaleGeneration)
    );
    applying_state
        .device_apply_coordinates(&current_applying)
        .unwrap();

    let (mut prepared_state, _, prepared, coordinates) = compact_prepared_device_state(0xda50);
    let prepared_generation = prepared.0.bearer_generation;
    let adopted_workload = adopt_compact_device_workload(&mut prepared_state);
    let adopted_prepared = prepared_state
        .adopt_device_after_fence(
            &adopted_workload,
            coordinates.preparation_id,
            coordinates.generation,
        )
        .unwrap();
    let DeviceAdoption::Prepared(current_prepared) = adopted_prepared else {
        __cser_core::panic!("prepared adoption changed typestate");
    };
    assert_next_generation(prepared_generation, current_prepared.0.bearer_generation);
    __cser_core::assert_eq!(
        prepared_state.prepared_device_coordinates(&prepared),
        Err(InfrastructureError::StaleGeneration)
    );
    prepared_state
        .prepared_device_coordinates(&current_prepared)
        .unwrap();

    let (mut materialized_state, _, prepared, coordinates) = compact_prepared_device_state(0xda60);
    let authority = materialized_state
        .prepare_device_materialization(prepared)
        .unwrap();
    let cohort = DeviceCohortIdentity {
        block: EffectKey::new(0xda61, 1),
        dma: [
            EffectKey::new(0xda62, 1),
            EffectKey::new(0xda63, 1),
            EffectKey::new(0xda64, 1),
        ],
        digest: 0xda65,
    };
    let mut candidate = materialized_state.try_private_candidate().unwrap();
    let materialization = candidate
        .prepare_materialize_device_in_candidate(&authority, cohort)
        .unwrap();
    candidate.apply_materialize_device_in_candidate(materialization, cohort);
    let foreign_authority = DeviceMaterializationPlan(BearerKey {
        authority: AuthorityKey {
            registry_instance: authority.0.authority.registry_instance + 1,
            scope: authority.0.authority.scope,
            authority_epoch: authority.0.authority.authority_epoch,
        },
        slot: authority.0.slot,
        object_generation: authority.0.object_generation,
        bearer_generation: authority.0.bearer_generation,
        nonce: authority.0.nonce,
        state: __cser_core::marker::PhantomData,
    });
    __cser_core::assert_eq!(
        candidate.validate_materialized_device_candidate(&foreign_authority, cohort),
        Err(InfrastructureError::ForeignRegistry)
    );
    candidate
        .validate_materialized_device_candidate(&authority, cohort)
        .unwrap();
    candidate.promote_full_candidate_for_install().unwrap();
    materialized_state = candidate;
    let materialized =
        materialized_state.mint_materialized_device_ticket_after_install(authority, cohort);
    let materialized_generation = materialized.0.bearer_generation;
    let adopted_workload = adopt_compact_device_workload(&mut materialized_state);
    let adopted_materialized = materialized_state
        .adopt_device_after_fence(
            &adopted_workload,
            coordinates.preparation_id,
            coordinates.generation,
        )
        .unwrap();
    let DeviceAdoption::Materialized(current_materialized) = adopted_materialized else {
        __cser_core::panic!("materialized adoption changed typestate");
    };
    assert_next_generation(
        materialized_generation,
        current_materialized.0.bearer_generation,
    );
    __cser_core::assert_eq!(materialized.0.nonce, current_materialized.0.nonce);

    let (mut failed_state, _, _, coordinates) = compact_prepared_device_state(0xda70);
    let adopted_workload = adopt_compact_device_workload(&mut failed_state);
    let nonce = failed_state
        .scope(SCOPE)
        .unwrap()
        .devices
        .get(coordinates.preparation_id)
        .unwrap()
        .stamp
        .nonce;
    failed_state
        .scope_mut(SCOPE)
        .unwrap()
        .reverse_indexes
        .get_mut(nonce)
        .unwrap()
        .actor_slot = Some(coordinates.actor_slot + 1);
    let before = failed_state.private_full_clone();
    __cser_core::assert_eq!(
        failed_state.adopt_device_after_fence(
            &adopted_workload,
            coordinates.preparation_id,
            coordinates.generation,
        ),
        Err(InfrastructureError::Invariant(
            "device reverse index mismatch"
        ))
    );
    __cser_core::assert_eq!(failed_state, before);
}

#[test]
fn service_lineage_commitment_schema_has_frozen_vectors_and_full_field_coverage() {
    let response = ContinuationDescriptor {
        continuation_id: 0x101,
        generation: 2,
        vm_generation: 3,
        source_domain: DomainKey::new(0x44),
        source_binding_epoch: 5,
    };
    let binding = ServiceChildBindingReceipt {
        request_id: 0x201,
        generation: 2,
        service_bearer_generation: 7,
        claim_generation: 3,
        claim_nonce: 0x301,
        claimant: ServiceClaimantSnapshot {
            registry_instance: 0x401,
            scope: ScopeKey::new(0x402, 4),
            authority_epoch: 5,
            root_effect: EffectKey::new(0x403, 6),
            workload_request_id: 0x404,
            workload_request_generation: 7,
            workload_nonce: 0x405,
            workload_bearer_generation: 8,
            domain: DomainKey::new(0x44),
            binding_epoch: 5,
            task: TaskWorkDescriptor {
                work_id: 0x406,
                generation: 9,
                task: TaskKey::new(0x407, 10),
                role: TaskWorkRole::ServiceRequest,
                vm: Some(VmAuthorityKey::new(0x408, 11).unwrap()),
            },
            task_nonce: 0x409,
            task_bearer_generation: 12,
        },
        child: ServiceChildReceipt {
            child_effect: EffectKey::new(0x40a, 13),
            registration_digest: 0x40b,
        },
    };
    __cser_core::assert_eq!(
        super::service::service_response_commitment(response),
        ServiceLineageCommitment([
            0x4d, 0xc6, 0x06, 0x7a, 0x80, 0xec, 0xf3, 0x60, 0x5d, 0x55, 0xae, 0xc7, 0x2d, 0x28,
            0x98, 0xfd, 0x39, 0x73, 0x38, 0x2f, 0xac, 0x15, 0x47, 0x9c, 0xcf, 0x59, 0x70, 0x84,
            0x40, 0xdb, 0x0a, 0x0a,
        ])
    );
    let bound = super::service::service_bound_commitment(response, binding);
    __cser_core::assert_eq!(
        bound,
        ServiceLineageCommitment([
            0xc8, 0x1e, 0x33, 0xdb, 0x9f, 0xdc, 0x9b, 0xd0, 0x06, 0xd3, 0x63, 0xe6, 0x22, 0x53,
            0x5c, 0x8a, 0xe1, 0x8d, 0x4a, 0xa3, 0x29, 0x03, 0xac, 0xf6, 0x23, 0xc3, 0xbb, 0xe8,
            0xde, 0x15, 0x7c, 0x41,
        ])
    );
    let causal = ServiceRequestCausalIdentity {
        registry_instance: 0x501,
        scope: ScopeKey::new(0x502, 5),
        authority_epoch: 6,
        root_effect: EffectKey::new(0x503, 7),
        workload_request_id: 0x504,
        workload_request_generation: 8,
        workload_nonce: 0x505,
        workload_bearer_generation: 9,
        admission_domain: DomainKey::new(0x45),
        admission_binding_epoch: 10,
        parent_task: TaskWorkDescriptor {
            work_id: 0x50a,
            generation: 17,
            task: TaskKey::new(0x50b, 18),
            role: TaskWorkRole::GuestSyscallWork,
            vm: Some(VmAuthorityKey::new(0x50c, 19).unwrap()),
        },
        request_nonce: 0x506,
        descriptor: ServiceRequestDescriptor {
            request_id: 0x201,
            generation: 2,
            queue: ResourceKey::new(0x46, 0x507, 11),
            queue_generation: 12,
            destination_domain: DomainKey::new(0x47),
            destination_binding_epoch: 13,
            command_digest: 0x508,
            payload_slot: 14,
            payload_generation: 15,
            response_slot_id: 0x509,
            response_slot_generation: 16,
        },
        response,
    };
    let enqueue_plan = ServiceEnqueuePlan {
        causal,
        bearer_generation: 3,
        apply_generation: 2,
        apply_nonce: 0x50d,
    };
    __cser_core::assert_eq!(
        super::service::service_enqueue_plan_commitment(enqueue_plan),
        ServiceLineageCommitment([
            0x24, 0xf7, 0xe9, 0x68, 0x1f, 0x22, 0x69, 0x2f, 0x7d, 0xc5, 0xde, 0xc9, 0x7e, 0x94,
            0xa2, 0xf1, 0x7c, 0xff, 0x3f, 0x0f, 0x79, 0x9b, 0xf4, 0xb0, 0x1f, 0x40, 0x48, 0x71,
            0x67, 0x56, 0xd0, 0x0a,
        ])
    );
    let enqueue_receipt = ServiceEnqueueReceipt {
        plan: enqueue_plan,
        queue: causal.descriptor.queue,
        queue_generation: 12,
        payload_slot: 14,
        payload_generation: 15,
        transport_receipt_digest: 0x50e,
    };
    __cser_core::assert_eq!(
        super::service::service_enqueue_receipt_commitment(enqueue_receipt),
        ServiceLineageCommitment([
            0x5e, 0x35, 0x6e, 0x39, 0xbf, 0x1f, 0xcd, 0x44, 0x4a, 0x1b, 0x36, 0x11, 0xc7, 0xa4,
            0xfd, 0x5d, 0x45, 0x8d, 0xfe, 0x78, 0x23, 0xc4, 0x85, 0x5e, 0xbf, 0x12, 0x51, 0xf3,
            0x73, 0x8a, 0xc5, 0x8c,
        ])
    );
    let arm_plan = ServiceArmPlan {
        causal,
        queue_receipt: enqueue_receipt,
        bearer_generation: 5,
        arm_generation: 4,
        arm_nonce: 0x50f,
    };
    __cser_core::assert_eq!(
        super::service::service_arm_plan_commitment(arm_plan),
        ServiceLineageCommitment([
            0x65, 0x9f, 0x34, 0xed, 0xc7, 0x39, 0x38, 0xd7, 0xe8, 0xc0, 0x16, 0x7c, 0x6d, 0x0c,
            0x00, 0x0a, 0x82, 0x76, 0x35, 0xd3, 0x19, 0x3c, 0xd7, 0x88, 0x9d, 0xda, 0x94, 0x65,
            0x72, 0x6e, 0xb5, 0xcd,
        ])
    );
    let arm_receipt = ServiceArmReceipt {
        plan: arm_plan,
        response_slot_id: 0x509,
        response_slot_generation: 16,
        bound_continuation_id: 0x101,
        bound_continuation_generation: 2,
        transport_receipt_digest: 0x510,
    };
    __cser_core::assert_eq!(
        super::service::service_armed_commitment(enqueue_receipt, arm_receipt),
        ServiceLineageCommitment([
            0x88, 0x49, 0x24, 0xe4, 0x9e, 0x29, 0x4f, 0xf5, 0x0f, 0x8f, 0x66, 0xb5, 0x7a, 0x5b,
            0xb2, 0x9e, 0x32, 0x5f, 0x65, 0x39, 0x0f, 0xdf, 0x58, 0x73, 0xd1, 0x45, 0xd5, 0x67,
            0xbe, 0x0f, 0xd0, 0xcc,
        ])
    );
    __cser_core::assert_eq!(
        super::service::service_child_bound_commitment(
            enqueue_receipt,
            arm_receipt,
            response,
            binding,
        ),
        ServiceLineageCommitment([
            0x5e, 0xd5, 0x39, 0x95, 0x4e, 0x71, 0x0a, 0xe7, 0xbf, 0xee, 0x8e, 0x9c, 0xa4, 0x1c,
            0xbe, 0xf7, 0x8f, 0x95, 0xdd, 0x27, 0xb0, 0xd3, 0xed, 0xe5, 0xed, 0xd9, 0x1a, 0x01,
            0x02, 0x3a, 0x50, 0xa0,
        ])
    );

    macro_rules! assert_enqueue_plan_change {
        ($change:expr) => {{
            let mut changed_plan = enqueue_plan;
            ($change)(&mut changed_plan);
            __cser_core::assert_ne!(
                super::service::service_enqueue_plan_commitment(changed_plan),
                super::service::service_enqueue_plan_commitment(enqueue_plan)
            );
            let mut changed_queue = enqueue_receipt;
            changed_queue.plan = changed_plan;
            __cser_core::assert_ne!(
                super::service::service_enqueue_receipt_commitment(changed_queue),
                super::service::service_enqueue_receipt_commitment(enqueue_receipt)
            );
            let mut changed_arm_plan = arm_plan;
            changed_arm_plan.queue_receipt = changed_queue;
            let mut changed_arm = arm_receipt;
            changed_arm.plan = changed_arm_plan;
            __cser_core::assert_ne!(
                super::service::service_armed_commitment(changed_queue, changed_arm),
                super::service::service_armed_commitment(enqueue_receipt, arm_receipt)
            );
            __cser_core::assert_ne!(
                super::service::service_child_bound_commitment(
                    changed_queue,
                    changed_arm,
                    response,
                    binding,
                ),
                super::service::service_child_bound_commitment(
                    enqueue_receipt,
                    arm_receipt,
                    response,
                    binding,
                )
            );
        }};
    }
    macro_rules! assert_enqueue_receipt_change {
        ($change:expr) => {{
            let mut changed_queue = enqueue_receipt;
            ($change)(&mut changed_queue);
            __cser_core::assert_ne!(
                super::service::service_enqueue_receipt_commitment(changed_queue),
                super::service::service_enqueue_receipt_commitment(enqueue_receipt)
            );
            let mut changed_arm_plan = arm_plan;
            changed_arm_plan.queue_receipt = changed_queue;
            __cser_core::assert_ne!(
                super::service::service_arm_plan_commitment(changed_arm_plan),
                super::service::service_arm_plan_commitment(arm_plan)
            );
            let mut changed_arm = arm_receipt;
            changed_arm.plan = changed_arm_plan;
            __cser_core::assert_ne!(
                super::service::service_armed_commitment(changed_queue, changed_arm),
                super::service::service_armed_commitment(enqueue_receipt, arm_receipt)
            );
            __cser_core::assert_ne!(
                super::service::service_child_bound_commitment(
                    changed_queue,
                    changed_arm,
                    response,
                    binding,
                ),
                super::service::service_child_bound_commitment(
                    enqueue_receipt,
                    arm_receipt,
                    response,
                    binding,
                )
            );
        }};
    }
    macro_rules! assert_arm_plan_change {
        ($change:expr) => {{
            let mut changed_plan = arm_plan;
            ($change)(&mut changed_plan);
            __cser_core::assert_ne!(
                super::service::service_arm_plan_commitment(changed_plan),
                super::service::service_arm_plan_commitment(arm_plan)
            );
            let mut changed_arm = arm_receipt;
            changed_arm.plan = changed_plan;
            __cser_core::assert_ne!(
                super::service::service_armed_commitment(enqueue_receipt, changed_arm),
                super::service::service_armed_commitment(enqueue_receipt, arm_receipt)
            );
            __cser_core::assert_ne!(
                super::service::service_child_bound_commitment(
                    enqueue_receipt,
                    changed_arm,
                    response,
                    binding,
                ),
                super::service::service_child_bound_commitment(
                    enqueue_receipt,
                    arm_receipt,
                    response,
                    binding,
                )
            );
        }};
    }
    macro_rules! assert_arm_receipt_change {
        ($change:expr) => {{
            let mut changed = arm_receipt;
            ($change)(&mut changed);
            __cser_core::assert_ne!(
                super::service::service_armed_commitment(enqueue_receipt, changed),
                super::service::service_armed_commitment(enqueue_receipt, arm_receipt)
            );
            __cser_core::assert_ne!(
                super::service::service_child_bound_commitment(
                    enqueue_receipt,
                    changed,
                    response,
                    binding,
                ),
                super::service::service_child_bound_commitment(
                    enqueue_receipt,
                    arm_receipt,
                    response,
                    binding,
                )
            );
        }};
    }

    let causal_mutations: [fn(&mut ServiceRequestCausalIdentity); 21] = [
        |value| value.registry_instance += 1,
        |value| value.scope = ScopeKey::new(value.scope.id() + 1, value.scope.generation()),
        |value| value.scope = ScopeKey::new(value.scope.id(), value.scope.generation() + 1),
        |value| value.authority_epoch += 1,
        |value| {
            value.root_effect =
                EffectKey::new(value.root_effect.id() + 1, value.root_effect.generation())
        },
        |value| {
            value.root_effect =
                EffectKey::new(value.root_effect.id(), value.root_effect.generation() + 1)
        },
        |value| value.workload_request_id += 1,
        |value| value.workload_request_generation += 1,
        |value| value.workload_nonce += 1,
        |value| value.workload_bearer_generation += 1,
        |value| value.admission_domain = DomainKey::new(value.admission_domain.value() + 1),
        |value| value.admission_binding_epoch += 1,
        |value| value.parent_task.work_id += 1,
        |value| value.parent_task.generation += 1,
        |value| {
            value.parent_task.task = TaskKey::new(
                value.parent_task.task.id() + 1,
                value.parent_task.task.generation(),
            )
        },
        |value| {
            value.parent_task.task = TaskKey::new(
                value.parent_task.task.id(),
                value.parent_task.task.generation() + 1,
            )
        },
        |value| value.parent_task.role = TaskWorkRole::ReplacementRecovery,
        |value| value.parent_task.vm = None,
        |value| {
            let vm = value.parent_task.vm.unwrap();
            value.parent_task.vm = Some(VmAuthorityKey::new(vm.id() + 1, vm.generation()).unwrap())
        },
        |value| {
            let vm = value.parent_task.vm.unwrap();
            value.parent_task.vm = Some(VmAuthorityKey::new(vm.id(), vm.generation() + 1).unwrap())
        },
        |value| value.request_nonce += 1,
    ];
    for mutate in causal_mutations {
        assert_enqueue_plan_change!(|value: &mut ServiceEnqueuePlan| mutate(&mut value.causal));
        assert_arm_plan_change!(|value: &mut ServiceArmPlan| mutate(&mut value.causal));
    }

    let descriptor_mutations: [fn(&mut ServiceRequestDescriptor); 13] = [
        |value| value.request_id += 1,
        |value| value.generation += 1,
        |value| {
            value.queue = ResourceKey::new(
                value.queue.namespace() + 1,
                value.queue.id(),
                value.queue.generation(),
            )
        },
        |value| {
            value.queue = ResourceKey::new(
                value.queue.namespace(),
                value.queue.id() + 1,
                value.queue.generation(),
            )
        },
        |value| {
            value.queue = ResourceKey::new(
                value.queue.namespace(),
                value.queue.id(),
                value.queue.generation() + 1,
            )
        },
        |value| value.queue_generation += 1,
        |value| value.destination_domain = DomainKey::new(value.destination_domain.value() + 1),
        |value| value.destination_binding_epoch += 1,
        |value| value.command_digest += 1,
        |value| value.payload_slot += 1,
        |value| value.payload_generation += 1,
        |value| value.response_slot_id += 1,
        |value| value.response_slot_generation += 1,
    ];
    for mutate in descriptor_mutations {
        assert_enqueue_plan_change!(|value: &mut ServiceEnqueuePlan| {
            mutate(&mut value.causal.descriptor)
        });
        assert_arm_plan_change!(|value: &mut ServiceArmPlan| {
            mutate(&mut value.causal.descriptor)
        });
    }

    let enqueue_plan_scalar_mutations: [fn(&mut ServiceEnqueuePlan); 3] = [
        |value| value.bearer_generation += 1,
        |value| value.apply_generation += 1,
        |value| value.apply_nonce += 1,
    ];
    for mutate in enqueue_plan_scalar_mutations {
        assert_enqueue_plan_change!(mutate);
    }

    let enqueue_receipt_mutations: [fn(&mut ServiceEnqueueReceipt); 7] = [
        |value| {
            value.queue = ResourceKey::new(
                value.queue.namespace() + 1,
                value.queue.id(),
                value.queue.generation(),
            )
        },
        |value| {
            value.queue = ResourceKey::new(
                value.queue.namespace(),
                value.queue.id() + 1,
                value.queue.generation(),
            )
        },
        |value| {
            value.queue = ResourceKey::new(
                value.queue.namespace(),
                value.queue.id(),
                value.queue.generation() + 1,
            )
        },
        |value| value.queue_generation += 1,
        |value| value.payload_slot += 1,
        |value| value.payload_generation += 1,
        |value| value.transport_receipt_digest += 1,
    ];
    for mutate in enqueue_receipt_mutations {
        assert_enqueue_receipt_change!(mutate);
    }

    let arm_plan_scalar_mutations: [fn(&mut ServiceArmPlan); 3] = [
        |value| value.bearer_generation += 1,
        |value| value.arm_generation += 1,
        |value| value.arm_nonce += 1,
    ];
    for mutate in arm_plan_scalar_mutations {
        assert_arm_plan_change!(mutate);
    }

    let arm_receipt_mutations: [fn(&mut ServiceArmReceipt); 5] = [
        |value| value.response_slot_id += 1,
        |value| value.response_slot_generation += 1,
        |value| value.bound_continuation_id += 1,
        |value| value.bound_continuation_generation += 1,
        |value| value.transport_receipt_digest += 1,
    ];
    for mutate in arm_receipt_mutations {
        assert_arm_receipt_change!(mutate);
    }

    let response_mutations: [fn(&mut ContinuationDescriptor); 5] = [
        |value| value.continuation_id += 1,
        |value| value.generation += 1,
        |value| value.vm_generation += 1,
        |value| value.source_domain = DomainKey::new(value.source_domain.value() + 1),
        |value| value.source_binding_epoch += 1,
    ];
    for mutate in response_mutations {
        let mut substituted = response;
        mutate(&mut substituted);
        __cser_core::assert_ne!(
            super::service::service_response_commitment(substituted),
            super::service::service_response_commitment(response)
        );
        __cser_core::assert_ne!(
            super::service::service_bound_commitment(substituted, binding),
            bound
        );
        assert_enqueue_plan_change!(|value: &mut ServiceEnqueuePlan| {
            mutate(&mut value.causal.response)
        });
        assert_arm_plan_change!(|value: &mut ServiceArmPlan| {
            mutate(&mut value.causal.response)
        });
        __cser_core::assert_ne!(
            super::service::service_child_bound_commitment(
                enqueue_receipt,
                arm_receipt,
                substituted,
                binding,
            ),
            super::service::service_child_bound_commitment(
                enqueue_receipt,
                arm_receipt,
                response,
                binding,
            )
        );
    }

    let binding_mutations: [fn(&mut ServiceChildBindingReceipt); 30] = [
        |value| value.request_id += 1,
        |value| value.generation += 1,
        |value| value.service_bearer_generation += 1,
        |value| value.claim_generation += 1,
        |value| value.claim_nonce += 1,
        |value| value.claimant.registry_instance += 1,
        |value| {
            value.claimant.scope = ScopeKey::new(
                value.claimant.scope.id() + 1,
                value.claimant.scope.generation(),
            )
        },
        |value| {
            value.claimant.scope = ScopeKey::new(
                value.claimant.scope.id(),
                value.claimant.scope.generation() + 1,
            )
        },
        |value| value.claimant.authority_epoch += 1,
        |value| {
            value.claimant.root_effect = EffectKey::new(
                value.claimant.root_effect.id() + 1,
                value.claimant.root_effect.generation(),
            )
        },
        |value| {
            value.claimant.root_effect = EffectKey::new(
                value.claimant.root_effect.id(),
                value.claimant.root_effect.generation() + 1,
            )
        },
        |value| value.claimant.workload_request_id += 1,
        |value| value.claimant.workload_request_generation += 1,
        |value| value.claimant.workload_nonce += 1,
        |value| value.claimant.workload_bearer_generation += 1,
        |value| value.claimant.domain = DomainKey::new(value.claimant.domain.value() + 1),
        |value| value.claimant.binding_epoch += 1,
        |value| value.claimant.task.work_id += 1,
        |value| value.claimant.task.generation += 1,
        |value| {
            value.claimant.task.task = TaskKey::new(
                value.claimant.task.task.id() + 1,
                value.claimant.task.task.generation(),
            )
        },
        |value| {
            value.claimant.task.task = TaskKey::new(
                value.claimant.task.task.id(),
                value.claimant.task.task.generation() + 1,
            )
        },
        |value| value.claimant.task.role = TaskWorkRole::ReplacementRecovery,
        |value| {
            let vm = value.claimant.task.vm.unwrap();
            value.claimant.task.vm =
                Some(VmAuthorityKey::new(vm.id() + 1, vm.generation()).unwrap())
        },
        |value| {
            let vm = value.claimant.task.vm.unwrap();
            value.claimant.task.vm =
                Some(VmAuthorityKey::new(vm.id(), vm.generation() + 1).unwrap())
        },
        |value| value.claimant.task_nonce += 1,
        |value| value.claimant.task_bearer_generation += 1,
        |value| {
            value.child.child_effect = EffectKey::new(
                value.child.child_effect.id() + 1,
                value.child.child_effect.generation(),
            )
        },
        |value| {
            value.child.child_effect = EffectKey::new(
                value.child.child_effect.id(),
                value.child.child_effect.generation() + 1,
            )
        },
        |value| value.child.registration_digest += 1,
        |value| value.claimant.task.vm = None,
    ];
    for mutate in binding_mutations {
        let mut substituted = binding;
        mutate(&mut substituted);
        __cser_core::assert_ne!(
            super::service::service_bound_commitment(response, substituted),
            bound
        );
        __cser_core::assert_ne!(
            super::service::service_child_bound_commitment(
                enqueue_receipt,
                arm_receipt,
                response,
                substituted,
            ),
            super::service::service_child_bound_commitment(
                enqueue_receipt,
                arm_receipt,
                response,
                binding,
            )
        );
    }
}

#[test]
fn service_bind_is_owned_atomic_and_returns_exact_unbound_authority_on_failure() {
    let (mut state, unbound) = compact_unbound_service_state(0xd0a1);
    let presented = service_key_coordinates(&unbound.0);
    let before = state.private_full_clone();
    let failure = state
        .bind_service_response_continuation(
            unbound,
            ContinuationDescriptor {
                source_binding_epoch: 2,
                ..compact_response_descriptor()
            },
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::StaleBinding);
    __cser_core::assert_eq!(state, before);
    let unbound = failure.into_input();
    __cser_core::assert_eq!(service_key_coordinates(&unbound.0), presented);
    __cser_core::assert_eq!(state.scope(SCOPE).unwrap().live.continuations, 0);

    let bound = state
        .bind_service_response_continuation(unbound, compact_response_descriptor())
        .unwrap();
    __cser_core::assert_eq!(bound.0.bearer_generation, 2);
    let scope = state.scope(SCOPE).unwrap();
    let service = scope.service_requests.get(COMPACT_SERVICE_REQUEST).unwrap();
    let continuation = scope.continuations.get(COMPACT_CONTINUATION).unwrap();
    __cser_core::assert_eq!(service.bound_continuation, Some(continuation.stamp));
    __cser_core::assert_eq!(
        continuation.service_owner,
        Some(super::RequestKey {
            id: COMPACT_SERVICE_REQUEST,
            generation: 1,
        })
    );
    __cser_core::assert_eq!(continuation.stamp.bearer_generation, 1);
    state.check_invariants().unwrap();
}

#[test]
fn service_owned_continuation_rejects_independent_fenced_adoption() {
    let (mut state, _service) = compact_bound_service_state(0xd0a7);
    *state
        .scope_mut(SCOPE)
        .unwrap()
        .binding_epoch_mut(GUEST)
        .unwrap() = 2;
    let workload = state
        .adopt_workload_after_fence(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 2, COMPACT_REQUEST, 1),
        )
        .unwrap();
    state
        .adopt_task_after_fence(&workload, COMPACT_WORK, 1)
        .unwrap();
    let before = state.private_full_clone();
    __cser_core::assert_eq!(
        state
            .adopt_continuation_after_fence(&workload, COMPACT_CONTINUATION, 1, 2)
            .unwrap_err(),
        InfrastructureError::InvalidState
    );
    __cser_core::assert_eq!(state, before);
}

#[test]
fn service_transition_rejects_substituted_reverse_index_without_mutation() {
    let (mut state, unbound) = compact_unbound_service_state(0xd0a8);
    let presented = service_key_coordinates(&unbound.0);
    state
        .scope_mut(SCOPE)
        .unwrap()
        .reverse_indexes
        .get_mut(unbound.0.nonce)
        .unwrap()
        .actor_slot = Some(compact_service_descriptor().payload_slot + 1);
    let before = state.private_full_clone();
    let failure = state
        .bind_service_response_continuation(unbound, compact_response_descriptor())
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidState);
    __cser_core::assert_eq!(state, before);
    let unbound = failure.into_input();
    __cser_core::assert_eq!(service_key_coordinates(&unbound.0), presented);
    __cser_core::assert_eq!(state.scope(SCOPE).unwrap().live.continuations, 0);
}

#[test]
fn service_unbound_cancel_has_no_continuation_authority_or_post_queue_path() {
    let (mut state, unbound) = compact_unbound_service_state(0xd0a2);
    let receipt = state
        .cancel_unbound_service_request(unbound, ValidatedAbortProof::new(0xd0a2))
        .unwrap();
    __cser_core::assert_eq!(receipt.point, ServiceCancellationPoint::ReservedUnbound);
    __cser_core::assert_eq!(receipt.response, None);
    __cser_core::assert_eq!(receipt.bearer_generation, 2);
    let scope = state.scope(SCOPE).unwrap();
    __cser_core::assert_eq!(scope.live.continuations, 0);
    let service = scope.service_requests.get(COMPACT_SERVICE_REQUEST).unwrap();
    __cser_core::assert!(service.bound_continuation.is_none());
    __cser_core::assert!(__cser_core::matches!(
        service.phase,
        ServiceRequestPhase::Cancelled {
            receipt: stored
        } if stored == receipt
    ));
    state.check_invariants().unwrap();

    let mut lower_generation = state.private_full_clone();
    if let ServiceRequestPhase::Cancelled { receipt } = &mut lower_generation
        .scope_mut(SCOPE)
        .unwrap()
        .service_requests
        .get_mut(COMPACT_SERVICE_REQUEST)
        .unwrap()
        .phase
    {
        receipt.bearer_generation -= 1;
    }
    assert_invariant_read_only(lower_generation);
}

#[test]
fn service_external_receipts_are_exact_and_claim_child_is_one_transition() {
    let (mut state, service) = compact_bound_service_state(0xd0a3);
    let (enqueue_plan, enqueue_authority) = state.begin_service_enqueue(service).unwrap();
    __cser_core::assert_eq!(enqueue_plan.bearer_generation, 3);
    let enqueue_coordinates = service_bound_key_coordinates(&enqueue_authority.0);
    let mut bad_enqueue = service_enqueue_receipt(enqueue_plan, 0xd0a4);
    bad_enqueue.plan.apply_nonce = bad_enqueue.plan.apply_nonce.checked_add(1).unwrap();
    let before_bad_enqueue = state.private_full_clone();
    let failure = state
        .acknowledge_service_enqueue(enqueue_authority, bad_enqueue)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before_bad_enqueue);
    let enqueue_authority = failure.into_input();
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&enqueue_authority.0),
        enqueue_coordinates
    );
    let unarmed = state
        .acknowledge_service_enqueue(
            enqueue_authority,
            service_enqueue_receipt(enqueue_plan, 0xd0a4),
        )
        .unwrap();

    // A forged reserved-state phantom cannot turn a queue-written request
    // back into a cancellable request. The Registry phase remains decisive.
    let forged_reserved = ServiceRequestTicket(test_service_bound_key::<
        bearer_state::ServiceReservedBound,
    >(&state, COMPACT_SERVICE_REQUEST));
    let before_forbidden_cancel = state.private_full_clone();
    let failure = state
        .cancel_bound_service_request(forged_reserved, ValidatedAbortProof::new(0xd0a5))
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidState);
    __cser_core::assert_eq!(state, before_forbidden_cancel);

    let (arm_plan, arm_authority) = state.begin_service_arm(unarmed).unwrap();
    __cser_core::assert_eq!(arm_plan.bearer_generation, 5);
    let arm_coordinates = service_bound_key_coordinates(&arm_authority.0);
    let mut bad_arm = service_arm_receipt(arm_plan, 0xd0a6);
    bad_arm.plan.arm_nonce = bad_arm.plan.arm_nonce.checked_add(1).unwrap();
    let before_bad_arm = state.private_full_clone();
    let failure = state
        .acknowledge_service_arm(arm_authority, bad_arm)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before_bad_arm);
    let arm_authority = failure.into_input();
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&arm_authority.0),
        arm_coordinates
    );
    let enqueued = state
        .acknowledge_service_arm(arm_authority, service_arm_receipt(arm_plan, 0xd0a6))
        .unwrap();

    let claimant = add_service_claimant(&mut state, 0xd0b0);
    let enqueued_coordinates = service_bound_key_coordinates(&enqueued.0);
    let before_invalid_child = state.private_full_clone();
    let failure = state
        .claim_and_bind_service_child(
            enqueued,
            &claimant,
            ValidatedServiceChildProof::new(ServiceChildReceipt {
                child_effect: EffectKey::new(0xd0b4, 1),
                registration_digest: 0,
            }),
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before_invalid_child);
    let enqueued = failure.into_input();
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&enqueued.0),
        enqueued_coordinates
    );
    let before_revision = state.scope(SCOPE).unwrap().revision;
    let bound = state
        .claim_and_bind_service_child(
            enqueued,
            &claimant,
            ValidatedServiceChildProof::new(ServiceChildReceipt {
                child_effect: EffectKey::new(0xd0b4, 1),
                registration_digest: 0xd0b5,
            }),
        )
        .unwrap();
    __cser_core::assert_eq!(bound.0.bearer_generation, 7);
    let service = state
        .scope(SCOPE)
        .unwrap()
        .service_requests
        .get(COMPACT_SERVICE_REQUEST)
        .unwrap();
    __cser_core::assert_eq!(state.scope(SCOPE).unwrap().revision, before_revision + 1);
    __cser_core::assert!(__cser_core::matches!(
        service.phase,
        ServiceRequestPhase::ChildBound {
            binding_receipt,
            ..
        } if binding_receipt.claim_generation == 1
    ));
    state.check_invariants().unwrap();
}

#[test]
fn service_claim_and_completion_preview_failures_are_atomic() {
    let (mut state, ticket) = compact_bound_service_state(0xd0c0);
    let (enqueue_plan, enqueue_authority) = state.begin_service_enqueue(ticket).unwrap();
    let unarmed = state
        .acknowledge_service_enqueue(
            enqueue_authority,
            service_enqueue_receipt(enqueue_plan, 0xd0c1),
        )
        .unwrap();
    let (arm_plan, arm_authority) = state.begin_service_arm(unarmed).unwrap();
    let enqueued = state
        .acknowledge_service_arm(arm_authority, service_arm_receipt(arm_plan, 0xd0c2))
        .unwrap();
    let claimant = add_service_claimant(&mut state, 0xd0d0);
    state
        .scope_mut(SCOPE)
        .unwrap()
        .tasks
        .get_mut(claimant.0.slot)
        .unwrap()
        .live_children = u32::MAX;
    let presented = service_bound_key_coordinates(&enqueued.0);
    let before = state.private_full_clone();
    let failure = state
        .claim_and_bind_service_child(
            enqueued,
            &claimant,
            ValidatedServiceChildProof::new(ServiceChildReceipt {
                child_effect: EffectKey::new(0xd0d4, 1),
                registration_digest: 0xd0d5,
            }),
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::CounterOverflow);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        presented
    );

    let (mut revision_state, bound) = compact_child_bound_service_state(0xd0e0, 0xd0f0);
    revision_state.scope_mut(SCOPE).unwrap().revision = u64::MAX;
    let presented = service_bound_key_coordinates(&bound.0);
    let before = revision_state.private_full_clone();
    let failure = revision_state
        .complete_service_request(bound, 0xd0e1)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::CounterOverflow);
    __cser_core::assert_eq!(revision_state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        presented
    );

    let (mut workload_state, bound) = compact_child_bound_service_state(0xd100, 0xd110);
    workload_state
        .scope_mut(SCOPE)
        .unwrap()
        .workloads
        .get_mut(COMPACT_REQUEST)
        .unwrap()
        .live_children = 0;
    let presented = service_bound_key_coordinates(&bound.0);
    let before = workload_state.private_full_clone();
    let failure = workload_state
        .complete_service_request(bound, 0xd101)
        .unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        InfrastructureError::Invariant("live counter underflow")
    );
    __cser_core::assert_eq!(workload_state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        presented
    );

    let (mut parent_state, bound) = compact_child_bound_service_state(0xd120, 0xd130);
    parent_state
        .scope_mut(SCOPE)
        .unwrap()
        .tasks
        .get_mut(COMPACT_WORK)
        .unwrap()
        .live_children = 0;
    let presented = service_bound_key_coordinates(&bound.0);
    let before = parent_state.private_full_clone();
    let failure = parent_state
        .complete_service_request(bound, 0xd121)
        .unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        InfrastructureError::Invariant("live counter underflow")
    );
    __cser_core::assert_eq!(parent_state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        presented
    );
}

#[test]
fn service_bound_keys_reject_synchronous_response_lineage_substitution() {
    let (mut state, ticket, sibling) = compact_bound_service_state_with_sibling_response(0xd510);
    let coordinates = service_bound_key_coordinates(&ticket.0);
    synchronously_substitute_service_response(&mut state, sibling);
    let before = state.private_full_clone();
    let failure = state.begin_service_enqueue(ticket).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        coordinates
    );

    let (mut state, ticket, sibling) = compact_bound_service_state_with_sibling_response(0xd511);
    let (plan, authority) = state.begin_service_enqueue(ticket).unwrap();
    let coordinates = service_bound_key_coordinates(&authority.0);
    synchronously_substitute_service_response(&mut state, sibling);
    let before = state.private_full_clone();
    let failure = state
        .acknowledge_service_enqueue(authority, service_enqueue_receipt(plan, 0xd512))
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        coordinates
    );

    let (mut state, ticket, sibling) = compact_bound_service_state_with_sibling_response(0xd513);
    let (enqueue_plan, enqueue_authority) = state.begin_service_enqueue(ticket).unwrap();
    let unarmed = state
        .acknowledge_service_enqueue(
            enqueue_authority,
            service_enqueue_receipt(enqueue_plan, 0xd514),
        )
        .unwrap();
    let coordinates = service_bound_key_coordinates(&unarmed.0);
    synchronously_substitute_service_response(&mut state, sibling);
    let before = state.private_full_clone();
    let failure = state.begin_service_arm(unarmed).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        coordinates
    );

    let (mut state, ticket, sibling) = compact_bound_service_state_with_sibling_response(0xd515);
    let (enqueue_plan, enqueue_authority) = state.begin_service_enqueue(ticket).unwrap();
    let unarmed = state
        .acknowledge_service_enqueue(
            enqueue_authority,
            service_enqueue_receipt(enqueue_plan, 0xd516),
        )
        .unwrap();
    let (arm_plan, arm_authority) = state.begin_service_arm(unarmed).unwrap();
    let coordinates = service_bound_key_coordinates(&arm_authority.0);
    synchronously_substitute_service_response(&mut state, sibling);
    let before = state.private_full_clone();
    let failure = state
        .acknowledge_service_arm(arm_authority, service_arm_receipt(arm_plan, 0xd517))
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        coordinates
    );

    let (mut state, ticket, sibling) = compact_bound_service_state_with_sibling_response(0xd518);
    let (enqueue_plan, enqueue_authority) = state.begin_service_enqueue(ticket).unwrap();
    let unarmed = state
        .acknowledge_service_enqueue(
            enqueue_authority,
            service_enqueue_receipt(enqueue_plan, 0xd519),
        )
        .unwrap();
    let (arm_plan, arm_authority) = state.begin_service_arm(unarmed).unwrap();
    let enqueued = state
        .acknowledge_service_arm(arm_authority, service_arm_receipt(arm_plan, 0xd51a))
        .unwrap();
    let claimant = add_service_claimant(&mut state, 0xd520);
    let coordinates = service_bound_key_coordinates(&enqueued.0);
    synchronously_substitute_service_response(&mut state, sibling);
    let before = state.private_full_clone();
    let failure = state
        .claim_and_bind_service_child(
            enqueued,
            &claimant,
            ValidatedServiceChildProof::new(ServiceChildReceipt {
                child_effect: EffectKey::new(0xd524, 1),
                registration_digest: 0xd525,
            }),
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        coordinates
    );

    let (mut state, ticket, sibling) = compact_bound_service_state_with_sibling_response(0xd526);
    let (enqueue_plan, enqueue_authority) = state.begin_service_enqueue(ticket).unwrap();
    let unarmed = state
        .acknowledge_service_enqueue(
            enqueue_authority,
            service_enqueue_receipt(enqueue_plan, 0xd527),
        )
        .unwrap();
    let (arm_plan, arm_authority) = state.begin_service_arm(unarmed).unwrap();
    let enqueued = state
        .acknowledge_service_arm(arm_authority, service_arm_receipt(arm_plan, 0xd528))
        .unwrap();
    let claimant = add_service_claimant(&mut state, 0xd530);
    let bound = state
        .claim_and_bind_service_child(
            enqueued,
            &claimant,
            ValidatedServiceChildProof::new(ServiceChildReceipt {
                child_effect: EffectKey::new(0xd534, 1),
                registration_digest: 0xd535,
            }),
        )
        .unwrap();
    let coordinates = service_bound_key_coordinates(&bound.0);
    synchronously_substitute_service_response(&mut state, sibling);
    let before = state.private_full_clone();
    let failure = state.complete_service_request(bound, 0xd536).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        coordinates
    );

    let (mut state, ticket) = compact_bound_service_state(0xd556);
    let (enqueue_plan, enqueue_authority) = state.begin_service_enqueue(ticket).unwrap();
    let unarmed = state
        .acknowledge_service_enqueue(
            enqueue_authority,
            service_enqueue_receipt(enqueue_plan, 0xd557),
        )
        .unwrap();
    let (arm_plan, arm_authority) = state.begin_service_arm(unarmed).unwrap();
    let enqueued = state
        .acknowledge_service_arm(arm_authority, service_arm_receipt(arm_plan, 0xd558))
        .unwrap();
    let claimant = add_service_claimant(&mut state, 0xd560);
    let bound = state
        .claim_and_bind_service_child(
            enqueued,
            &claimant,
            ValidatedServiceChildProof::new(ServiceChildReceipt {
                child_effect: EffectKey::new(0xd564, 1),
                registration_digest: 0xd565,
            }),
        )
        .unwrap();
    {
        let service = state
            .scope_mut(SCOPE)
            .unwrap()
            .service_requests
            .get_mut(COMPACT_SERVICE_REQUEST)
            .unwrap();
        let (queue_receipt, mut arm_receipt, binding_receipt) = match service.phase {
            ServiceRequestPhase::ChildBound {
                queue_receipt,
                arm_receipt,
                binding_receipt,
            } => (queue_receipt, arm_receipt, binding_receipt),
            _ => __cser_core::unreachable!(),
        };
        arm_receipt.transport_receipt_digest += 1;
        let lineage = super::service::service_child_bound_commitment(
            queue_receipt,
            arm_receipt,
            service.response_identity.unwrap(),
            binding_receipt,
        );
        service.bound_commitment = Some(lineage);
        service.phase = ServiceRequestPhase::ChildBound {
            queue_receipt,
            arm_receipt,
            binding_receipt,
        };
    }
    state.check_invariants().unwrap();
    let coordinates = service_bound_key_coordinates(&bound.0);
    let before = state.private_full_clone();
    let failure = state.complete_service_request(bound, 0xd566).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        coordinates
    );
}

#[test]
fn service_phase_keys_reject_synchronous_plan_and_receipt_substitution() {
    let (mut state, ticket) = compact_bound_service_state(0xd540);
    let (mut plan, authority) = state.begin_service_enqueue(ticket).unwrap();
    {
        let record = state
            .scope_mut(SCOPE)
            .unwrap()
            .service_requests
            .get_mut(COMPACT_SERVICE_REQUEST)
            .unwrap();
        record.apply_generation += 1;
        if let ServiceRequestPhase::Publishing {
            apply_generation, ..
        } = &mut record.phase
        {
            *apply_generation += 1;
        } else {
            __cser_core::unreachable!();
        }
    }
    plan.apply_generation += 1;
    state.check_invariants().unwrap();
    let coordinates = service_bound_key_coordinates(&authority.0);
    let before = state.private_full_clone();
    let failure = state
        .acknowledge_service_enqueue(authority, service_enqueue_receipt(plan, 0xd541))
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        coordinates
    );

    let (mut state, ticket) = compact_bound_service_state(0xd542);
    let (enqueue_plan, enqueue_authority) = state.begin_service_enqueue(ticket).unwrap();
    let unarmed = state
        .acknowledge_service_enqueue(
            enqueue_authority,
            service_enqueue_receipt(enqueue_plan, 0xd543),
        )
        .unwrap();
    if let ServiceRequestPhase::QueueWrittenUnarmed { queue_receipt } = &mut state
        .scope_mut(SCOPE)
        .unwrap()
        .service_requests
        .get_mut(COMPACT_SERVICE_REQUEST)
        .unwrap()
        .phase
    {
        queue_receipt.transport_receipt_digest += 1;
    } else {
        __cser_core::unreachable!();
    }
    state.check_invariants().unwrap();
    let coordinates = service_bound_key_coordinates(&unarmed.0);
    let before = state.private_full_clone();
    let failure = state.begin_service_arm(unarmed).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        coordinates
    );

    let (mut state, ticket) = compact_bound_service_state(0xd544);
    let (enqueue_plan, enqueue_authority) = state.begin_service_enqueue(ticket).unwrap();
    let unarmed = state
        .acknowledge_service_enqueue(
            enqueue_authority,
            service_enqueue_receipt(enqueue_plan, 0xd545),
        )
        .unwrap();
    let (mut arm_plan, arm_authority) = state.begin_service_arm(unarmed).unwrap();
    {
        let record = state
            .scope_mut(SCOPE)
            .unwrap()
            .service_requests
            .get_mut(COMPACT_SERVICE_REQUEST)
            .unwrap();
        record.arm_generation += 1;
        if let ServiceRequestPhase::Arming { arm_generation, .. } = &mut record.phase {
            *arm_generation += 1;
        } else {
            __cser_core::unreachable!();
        }
    }
    arm_plan.arm_generation += 1;
    state.check_invariants().unwrap();
    let coordinates = service_bound_key_coordinates(&arm_authority.0);
    let before = state.private_full_clone();
    let failure = state
        .acknowledge_service_arm(arm_authority, service_arm_receipt(arm_plan, 0xd546))
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        coordinates
    );

    let (mut state, ticket) = compact_bound_service_state(0xd547);
    let (enqueue_plan, enqueue_authority) = state.begin_service_enqueue(ticket).unwrap();
    let unarmed = state
        .acknowledge_service_enqueue(
            enqueue_authority,
            service_enqueue_receipt(enqueue_plan, 0xd548),
        )
        .unwrap();
    let (arm_plan, arm_authority) = state.begin_service_arm(unarmed).unwrap();
    let enqueued = state
        .acknowledge_service_arm(arm_authority, service_arm_receipt(arm_plan, 0xd549))
        .unwrap();
    if let ServiceRequestPhase::Armed { arm_receipt, .. } = &mut state
        .scope_mut(SCOPE)
        .unwrap()
        .service_requests
        .get_mut(COMPACT_SERVICE_REQUEST)
        .unwrap()
        .phase
    {
        arm_receipt.transport_receipt_digest += 1;
    } else {
        __cser_core::unreachable!();
    }
    state.check_invariants().unwrap();
    let claimant = add_service_claimant(&mut state, 0xd550);
    let coordinates = service_bound_key_coordinates(&enqueued.0);
    let before = state.private_full_clone();
    let failure = state
        .claim_and_bind_service_child(
            enqueued,
            &claimant,
            ValidatedServiceChildProof::new(ServiceChildReceipt {
                child_effect: EffectKey::new(0xd554, 1),
                registration_digest: 0xd555,
            }),
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&failure.into_input().0),
        coordinates
    );
}

#[test]
fn service_external_receipts_bind_every_causal_coordinate_family() {
    let enqueue_mutations: [fn(&mut ServiceEnqueueReceipt); 21] = [
        |receipt| receipt.plan.causal.registry_instance ^= 1,
        |receipt| receipt.plan.causal.root_effect = EffectKey::new(0xed10, 1),
        |receipt| receipt.plan.causal.scope = ScopeKey::new(0xed11, 1),
        |receipt| receipt.plan.causal.authority_epoch += 1,
        |receipt| receipt.plan.causal.workload_request_id += 1,
        |receipt| receipt.plan.causal.workload_nonce += 1,
        |receipt| receipt.plan.causal.workload_bearer_generation += 1,
        |receipt| receipt.plan.causal.admission_domain = DomainKey::new(0xed),
        |receipt| receipt.plan.causal.admission_binding_epoch += 1,
        |receipt| receipt.plan.causal.parent_task.work_id += 1,
        |receipt| receipt.plan.causal.request_nonce += 1,
        |receipt| receipt.plan.causal.descriptor.destination_domain = DomainKey::new(0xee),
        |receipt| receipt.plan.causal.descriptor.destination_binding_epoch += 1,
        |receipt| receipt.plan.causal.descriptor.command_digest ^= 1,
        |receipt| receipt.plan.causal.descriptor.response_slot_id += 1,
        |receipt| receipt.plan.causal.response.continuation_id += 1,
        |receipt| receipt.plan.causal.response.vm_generation += 1,
        |receipt| receipt.plan.causal.response.source_domain = DomainKey::new(0xef),
        |receipt| receipt.plan.causal.response.source_binding_epoch += 1,
        |receipt| receipt.plan.apply_generation += 1,
        |receipt| receipt.plan.bearer_generation -= 1,
    ];
    for (index, mutate) in enqueue_mutations.into_iter().enumerate() {
        assert_enqueue_receipt_mutation_rejected(0xed20 + index as u64, mutate);
    }
    for (index, mutate) in [
        (|receipt: &mut ServiceEnqueueReceipt| {
            receipt.queue = ResourceKey::new(0xed30, 1, 1);
        }) as fn(&mut ServiceEnqueueReceipt),
        |receipt| receipt.queue_generation += 1,
        |receipt| receipt.payload_slot += 1,
        |receipt| receipt.payload_generation += 1,
        |receipt| receipt.transport_receipt_digest = 0,
    ]
    .into_iter()
    .enumerate()
    {
        assert_enqueue_receipt_mutation_rejected(0xed40 + index as u64, mutate);
    }

    let arm_mutations: [fn(&mut ServiceArmReceipt); 22] = [
        |receipt| receipt.plan.causal.registry_instance ^= 1,
        |receipt| receipt.plan.causal.root_effect = EffectKey::new(0xed50, 1),
        |receipt| receipt.plan.causal.scope = ScopeKey::new(0xed51, 1),
        |receipt| receipt.plan.causal.authority_epoch += 1,
        |receipt| receipt.plan.causal.workload_request_id += 1,
        |receipt| receipt.plan.causal.workload_nonce += 1,
        |receipt| receipt.plan.causal.workload_bearer_generation += 1,
        |receipt| receipt.plan.causal.admission_domain = DomainKey::new(0xed),
        |receipt| receipt.plan.causal.admission_binding_epoch += 1,
        |receipt| receipt.plan.causal.parent_task.work_id += 1,
        |receipt| receipt.plan.causal.request_nonce += 1,
        |receipt| receipt.plan.causal.descriptor.destination_domain = DomainKey::new(0xee),
        |receipt| receipt.plan.causal.descriptor.destination_binding_epoch += 1,
        |receipt| receipt.plan.causal.descriptor.command_digest ^= 1,
        |receipt| receipt.plan.causal.descriptor.response_slot_generation += 1,
        |receipt| receipt.plan.causal.response.continuation_id += 1,
        |receipt| receipt.plan.causal.response.vm_generation += 1,
        |receipt| receipt.plan.causal.response.source_domain = DomainKey::new(0xef),
        |receipt| receipt.plan.causal.response.source_binding_epoch += 1,
        |receipt| receipt.plan.queue_receipt.transport_receipt_digest ^= 1,
        |receipt| receipt.plan.arm_generation += 1,
        |receipt| receipt.plan.bearer_generation -= 1,
    ];
    for (index, mutate) in arm_mutations.into_iter().enumerate() {
        assert_arm_receipt_mutation_rejected(0xed60 + index as u64, mutate);
    }
    for (index, mutate) in [
        (|receipt: &mut ServiceArmReceipt| receipt.response_slot_id += 1)
            as fn(&mut ServiceArmReceipt),
        |receipt| receipt.response_slot_generation += 1,
        |receipt| receipt.bound_continuation_id += 1,
        |receipt| receipt.bound_continuation_generation += 1,
        |receipt| receipt.transport_receipt_digest = 0,
    ]
    .into_iter()
    .enumerate()
    {
        assert_arm_receipt_mutation_rejected(0xed80 + index as u64, mutate);
    }
}

#[test]
fn continuation_retry_returns_exact_authority_without_mutation() {
    let (mut state, _, _, continuation) = compact_continuation_state(0xd001);
    __cser_core::assert_eq!(compact_bearer_generation(&state), 1);

    let before_claim = state.private_full_clone();
    let failure = state.claim_continuation(continuation, 0).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidIdentity);
    __cser_core::assert_eq!(state, before_claim);
    let continuation = failure.into_input();

    let claim = state.claim_continuation(continuation, 0xd8).unwrap();
    __cser_core::assert_eq!(compact_bearer_generation(&state), 2);
    let before_publication = state.private_full_clone();
    let failure = state
        .begin_continuation_publication(
            claim,
            ContinuationPublicationReceipt {
                vm_generation: 1,
                source_domain: GUEST,
                source_binding_epoch: 2,
                outcome_digest: 0xd8,
            },
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before_publication);
    let claim = failure.into_input();

    let publication = state
        .begin_continuation_publication(
            claim,
            ContinuationPublicationReceipt {
                vm_generation: 1,
                source_domain: GUEST,
                source_binding_epoch: 1,
                outcome_digest: 0xd8,
            },
        )
        .unwrap();
    __cser_core::assert_eq!(compact_bearer_generation(&state), 3);
    let publication_plan = publication.plan();
    __cser_core::assert_eq!(publication_plan, publication.plan());
    __cser_core::assert_eq!(
        publication_plan.descriptor.continuation_id,
        COMPACT_CONTINUATION
    );
    let authority = publication.into_authority();
    let acknowledgement = ContinuationPublicationAckReceipt {
        continuation_id: publication_plan.descriptor.continuation_id,
        generation: publication_plan.descriptor.generation,
        claim_generation: publication_plan.claim_generation,
        claim_nonce: publication_plan.claim_nonce,
        apply_generation: publication_plan.apply_generation,
        apply_nonce: publication_plan.apply_nonce,
        publication_sequence: publication_plan.publication_sequence,
        vm_generation: publication_plan.descriptor.vm_generation,
        source_domain: publication_plan.descriptor.source_domain,
        source_binding_epoch: publication_plan.descriptor.source_binding_epoch,
        outcome_digest: publication_plan.receipt.outcome_digest,
        external_receipt_digest: 0,
    };
    let before_ack = state.private_full_clone();
    let failure = state
        .acknowledge_continuation_publication(authority, acknowledgement)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before_ack);
    let authority = failure.into_input();
    let failure = state
        .acknowledge_continuation_publication(
            authority,
            ContinuationPublicationAckReceipt {
                apply_nonce: publication_plan.apply_nonce ^ 1,
                external_receipt_digest: 0xd9,
                ..acknowledgement
            },
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before_ack);
    let authority = failure.into_input();
    let acknowledgement = ContinuationPublicationAckReceipt {
        external_receipt_digest: 0xd9,
        ..acknowledgement
    };
    let ack = state
        .acknowledge_continuation_publication(authority, acknowledgement)
        .unwrap();
    __cser_core::assert_eq!(compact_bearer_generation(&state), 4);

    let resume = state.begin_continuation_resume(ack).unwrap();
    __cser_core::assert_eq!(compact_bearer_generation(&state), 5);
    let resume_plan = resume.plan();
    __cser_core::assert_eq!(resume_plan, resume.plan());
    __cser_core::assert_eq!(resume_plan.publication_ack, acknowledgement);
    let completion = ContinuationResumeReceipt {
        continuation_id: resume_plan.descriptor.continuation_id,
        generation: resume_plan.descriptor.generation,
        publication_sequence: resume_plan.publication_sequence,
        vm_generation: resume_plan.descriptor.vm_generation,
        source_domain: resume_plan.descriptor.source_domain,
        source_binding_epoch: resume_plan.descriptor.source_binding_epoch,
        outcome_digest: resume_plan.outcome_digest,
        ack_generation: resume_plan.ack_generation,
        ack_nonce: resume_plan.ack_nonce,
        resume_generation: resume_plan.resume_generation,
        resume_nonce: resume_plan.resume_nonce,
        external_receipt_digest: 0,
    };
    let before_complete = state.private_full_clone();
    let failure = state
        .complete_continuation_resume(resume.into_authority(), completion)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before_complete);
    let authority = failure.into_input();
    state
        .complete_continuation_resume(
            authority,
            ContinuationResumeReceipt {
                external_receipt_digest: 0xd9,
                ..completion
            },
        )
        .unwrap();
    __cser_core::assert_eq!(compact_bearer_generation(&state), 6);
    state.check_invariants().unwrap();
}

#[test]
fn foreign_registry_rejects_compact_continuation_and_returns_it() {
    let (mut owner, _, _, continuation) = compact_continuation_state(0xd011);
    let (mut foreign, _, _, _foreign_continuation) = compact_continuation_state(0xd012);
    let before_owner = owner.private_full_clone();
    let before_foreign = foreign.private_full_clone();

    let failure = foreign.claim_continuation(continuation, 0xda).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::ForeignRegistry);
    __cser_core::assert_eq!(foreign, before_foreign);
    __cser_core::assert_eq!(owner, before_owner);

    owner
        .claim_continuation(failure.into_input(), 0xda)
        .unwrap();
    __cser_core::assert_eq!(compact_bearer_generation(&owner), 2);
}

#[test]
fn continuation_adoption_fences_old_compact_bearer() {
    let (mut state, _old_workload, _old_entered, stale) = compact_continuation_state(0xd021);
    *state
        .scope_mut(SCOPE)
        .unwrap()
        .binding_epoch_mut(GUEST)
        .unwrap() = 2;
    let workload = state
        .adopt_workload_after_fence(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 2, COMPACT_REQUEST, 1),
        )
        .unwrap();
    let before_parent_adoption = state.private_full_clone();
    __cser_core::assert_eq!(
        state
            .adopt_continuation_after_fence(&workload, COMPACT_CONTINUATION, 1, 2)
            .unwrap_err(),
        InfrastructureError::StaleBinding
    );
    __cser_core::assert_eq!(state, before_parent_adoption);
    __cser_core::assert!(__cser_core::matches!(
        state
            .adopt_task_after_fence(&workload, COMPACT_WORK, 1)
            .unwrap(),
        TaskAdoption::Entered(_)
    ));
    let mut missing_index = state.private_full_clone();
    let index_slot = missing_index
        .scope(SCOPE)
        .unwrap()
        .continuations
        .get(COMPACT_CONTINUATION)
        .unwrap()
        .stamp
        .nonce;
    missing_index
        .scope_mut(SCOPE)
        .unwrap()
        .reverse_indexes
        .remove(index_slot)
        .unwrap();
    let before_missing_index = missing_index.private_full_clone();
    __cser_core::assert_eq!(
        missing_index
            .adopt_continuation_after_fence(&workload, COMPACT_CONTINUATION, 1, 2)
            .unwrap_err(),
        InfrastructureError::Invariant("missing continuation reverse index")
    );
    __cser_core::assert_eq!(missing_index, before_missing_index);

    let current = match state
        .adopt_continuation_after_fence(&workload, COMPACT_CONTINUATION, 1, 2)
        .unwrap()
    {
        ContinuationAdoption::Pending(lease) => lease,
        _ => __cser_core::panic!("pending continuation adopted into the wrong phase"),
    };
    __cser_core::assert_eq!(compact_bearer_generation(&state), 2);
    state.check_invariants().unwrap();

    let before_stale = state.private_full_clone();
    let failure = state.claim_continuation(stale, 0xdb).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::StaleGeneration);
    __cser_core::assert_eq!(state, before_stale);
    state.claim_continuation(current, 0xdb).unwrap();
    __cser_core::assert_eq!(compact_bearer_generation(&state), 3);
}

#[test]
fn continuation_adoption_retains_exact_historical_publication_ack() {
    let (mut state, _old_workload, _old_entered, continuation) = compact_continuation_state(0xd029);
    let claim = state.claim_continuation(continuation, 0xdb01).unwrap();
    let publication = state
        .begin_continuation_publication(
            claim,
            ContinuationPublicationReceipt {
                vm_generation: 1,
                source_domain: GUEST,
                source_binding_epoch: 1,
                outcome_digest: 0xdb01,
            },
        )
        .unwrap();
    let publication_plan = publication.plan();
    let acknowledgement = ContinuationPublicationAckReceipt {
        continuation_id: publication_plan.descriptor.continuation_id,
        generation: publication_plan.descriptor.generation,
        claim_generation: publication_plan.claim_generation,
        claim_nonce: publication_plan.claim_nonce,
        apply_generation: publication_plan.apply_generation,
        apply_nonce: publication_plan.apply_nonce,
        publication_sequence: publication_plan.publication_sequence,
        vm_generation: publication_plan.descriptor.vm_generation,
        source_domain: publication_plan.descriptor.source_domain,
        source_binding_epoch: publication_plan.descriptor.source_binding_epoch,
        outcome_digest: publication_plan.receipt.outcome_digest,
        external_receipt_digest: 0xdb02,
    };
    let stale_ack = state
        .acknowledge_continuation_publication(publication.into_authority(), acknowledgement)
        .unwrap();

    *state
        .scope_mut(SCOPE)
        .unwrap()
        .binding_epoch_mut(GUEST)
        .unwrap() = 2;
    let workload = state
        .adopt_workload_after_fence(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 2, COMPACT_REQUEST, 1),
        )
        .unwrap();
    __cser_core::assert!(__cser_core::matches!(
        state
            .adopt_task_after_fence(&workload, COMPACT_WORK, 1)
            .unwrap(),
        TaskAdoption::Entered(_)
    ));
    let current_ack = match state
        .adopt_continuation_after_fence(&workload, COMPACT_CONTINUATION, 1, 2)
        .unwrap()
    {
        ContinuationAdoption::Acknowledged(ack) => ack,
        _ => __cser_core::panic!("acknowledged continuation adopted into the wrong phase"),
    };
    let projection = state
        .query_continuation(&workload, COMPACT_CONTINUATION, 1)
        .unwrap();
    __cser_core::assert_eq!(projection.descriptor.source_binding_epoch, 2);
    __cser_core::assert_eq!(projection.publication_ack, Some(acknowledgement));
    __cser_core::assert_eq!(projection.publication_ack.unwrap().source_binding_epoch, 1);

    let before_stale = state.private_full_clone();
    let failure = state.begin_continuation_resume(stale_ack).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::StaleGeneration);
    __cser_core::assert_eq!(state, before_stale);

    let stale_resume = state.begin_continuation_resume(current_ack).unwrap();
    let stale_resume_plan = stale_resume.plan();
    __cser_core::assert_eq!(stale_resume_plan.descriptor.source_binding_epoch, 2);
    __cser_core::assert_eq!(stale_resume_plan.publication_ack, acknowledgement);

    *state
        .scope_mut(SCOPE)
        .unwrap()
        .binding_epoch_mut(GUEST)
        .unwrap() = 3;
    let workload = state
        .adopt_workload_after_fence(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 3, COMPACT_REQUEST, 1),
        )
        .unwrap();
    __cser_core::assert!(__cser_core::matches!(
        state
            .adopt_task_after_fence(&workload, COMPACT_WORK, 1)
            .unwrap(),
        TaskAdoption::Entered(_)
    ));
    let current_resume = match state
        .adopt_continuation_after_fence(&workload, COMPACT_CONTINUATION, 1, 3)
        .unwrap()
    {
        ContinuationAdoption::ReplayResume(resume) => resume,
        _ => __cser_core::panic!("resuming continuation adopted into the wrong phase"),
    };
    let before_stale_resume = state.private_full_clone();
    let failure = state
        .complete_continuation_resume(
            stale_resume.into_authority(),
            continuation_resume_receipt(stale_resume_plan, 0xdb03),
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::StaleGeneration);
    __cser_core::assert_eq!(state, before_stale_resume);

    let current_resume_plan = current_resume.plan();
    __cser_core::assert_eq!(current_resume_plan.descriptor.source_binding_epoch, 3);
    __cser_core::assert_eq!(current_resume_plan.publication_ack, acknowledgement);
    let before_substitution = state.private_full_clone();
    let failure = state
        .complete_continuation_resume(
            current_resume.into_authority(),
            continuation_resume_receipt(stale_resume_plan, 0xdb03),
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before_substitution);
    state
        .complete_continuation_resume(
            failure.into_input(),
            continuation_resume_receipt(current_resume_plan, 0xdb04),
        )
        .unwrap();
    let projection = state
        .query_continuation(&workload, COMPACT_CONTINUATION, 1)
        .unwrap();
    __cser_core::assert_eq!(projection.publication_ack, Some(acknowledgement));
    __cser_core::assert_eq!(
        projection.resume_receipt,
        Some(continuation_resume_receipt(current_resume_plan, 0xdb04))
    );
    state.check_invariants().unwrap();

    let mut missing_ack = state.private_full_clone();
    missing_ack
        .scope_mut(SCOPE)
        .unwrap()
        .continuations
        .get_mut(COMPACT_CONTINUATION)
        .unwrap()
        .publication_ack = None;
    assert_invariant_read_only(missing_ack);

    let mut corrupt_ack = state.private_full_clone();
    corrupt_ack
        .scope_mut(SCOPE)
        .unwrap()
        .continuations
        .get_mut(COMPACT_CONTINUATION)
        .unwrap()
        .publication_ack
        .as_mut()
        .unwrap()
        .external_receipt_digest = 0;
    assert_invariant_read_only(corrupt_ack);

    let mut nonce_rollback = state.private_full_clone();
    nonce_rollback.scope_mut(SCOPE).unwrap().next_nonce = current_resume_plan.resume_nonce;
    assert_invariant_read_only(nonce_rollback);

    let mut publication_rollback = state.private_full_clone();
    publication_rollback
        .scope_mut(SCOPE)
        .unwrap()
        .next_publication_sequence = acknowledgement.publication_sequence;
    assert_invariant_read_only(publication_rollback);
}

#[test]
fn service_cancel_returns_fresh_compact_continuation_authority() {
    let (mut state, service) = compact_bound_service_state(0xd031);
    let workload = super::workload_bearer(state.scope(SCOPE).unwrap(), COMPACT_REQUEST).unwrap();
    __cser_core::assert_eq!(compact_bearer_generation(&state), 1);
    let historical_generation = state
        .scope(SCOPE)
        .unwrap()
        .service_requests
        .get(COMPACT_SERVICE_REQUEST)
        .unwrap()
        .bound_continuation
        .unwrap()
        .bearer_generation;
    __cser_core::assert_eq!(historical_generation, 1);

    let cancelled = state
        .cancel_bound_service_request(service, ValidatedAbortProof::new(0xdc))
        .unwrap();
    __cser_core::assert_eq!(cancelled.receipt.bearer_generation, 3);
    __cser_core::assert_eq!(
        cancelled.receipt.response.unwrap().continuation_id,
        COMPACT_CONTINUATION
    );
    __cser_core::assert_eq!(compact_bearer_generation(&state), 2);
    __cser_core::assert!(
        state
            .scope(SCOPE)
            .unwrap()
            .service_requests
            .get(COMPACT_SERVICE_REQUEST)
            .unwrap()
            .bound_continuation
            .is_none()
    );
    let projection = state
        .query_service_request(&workload, COMPACT_SERVICE_REQUEST, 1)
        .unwrap();
    __cser_core::assert_eq!(projection.state, ServiceRequestRecoveryState::Cancelled);
    __cser_core::assert_eq!(projection.cancellation_receipt, Some(cancelled.receipt));
    __cser_core::assert_eq!(projection.enqueue_receipt, None);
    __cser_core::assert_eq!(projection.arm_receipt, None);
    __cser_core::assert_eq!(projection.child_binding_receipt, None);
    __cser_core::assert_eq!(projection.completion_receipt, None);

    let mut lower_generation = state.private_full_clone();
    if let ServiceRequestPhase::Cancelled { receipt } = &mut lower_generation
        .scope_mut(SCOPE)
        .unwrap()
        .service_requests
        .get_mut(COMPACT_SERVICE_REQUEST)
        .unwrap()
        .phase
    {
        receipt.bearer_generation -= 1;
    }
    assert_invariant_read_only(lower_generation);

    state.claim_continuation(cancelled.response, 0xdd).unwrap();
    __cser_core::assert_eq!(compact_bearer_generation(&state), 3);
    state.check_invariants().unwrap();
}

#[test]
fn service_completion_returns_fresh_compact_continuation_authority() {
    let (mut state, service) = compact_bound_service_state(0xd041);
    let guest_workload =
        super::workload_bearer(state.scope(SCOPE).unwrap(), COMPACT_REQUEST).unwrap();
    let alternate_parent = state
        .admit_task(
            &guest_workload,
            TaskWorkDescriptor {
                work_id: 0xe430,
                generation: 1,
                task: TaskKey::new(0xe530, 1),
                role: TaskWorkRole::GuestSyscallWork,
                vm: Some(VmAuthorityKey::new(0xe630, 1).unwrap()),
            },
        )
        .unwrap();
    let alternate_parent = state.claim_task_entry(alternate_parent).unwrap();
    let alternate_parent_response = ContinuationDescriptor {
        continuation_id: 0xe710,
        generation: 1,
        vm_generation: 1,
        source_domain: GUEST,
        source_binding_epoch: 1,
    };
    let _alternate_parent_lease = state
        .create_continuation(&alternate_parent, alternate_parent_response)
        .unwrap();
    let alternate_workload = state
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 1, 0xe320, 1),
        )
        .unwrap();
    let alternate_workload_parent = state
        .admit_task(
            &alternate_workload,
            TaskWorkDescriptor {
                work_id: 0xe420,
                generation: 1,
                task: TaskKey::new(0xe520, 1),
                role: TaskWorkRole::GuestSyscallWork,
                vm: Some(VmAuthorityKey::new(0xe620, 1).unwrap()),
            },
        )
        .unwrap();
    let alternate_workload_parent = state.claim_task_entry(alternate_workload_parent).unwrap();
    let alternate_workload_response = ContinuationDescriptor {
        continuation_id: 0xe720,
        generation: 1,
        vm_generation: 1,
        source_domain: GUEST,
        source_binding_epoch: 1,
    };
    let _alternate_workload_lease = state
        .create_continuation(&alternate_workload_parent, alternate_workload_response)
        .unwrap();
    let (enqueue_plan, enqueue_authority) = state.begin_service_enqueue(service).unwrap();
    __cser_core::assert_eq!(enqueue_plan.bearer_generation, 3);
    let enqueue_receipt = service_enqueue_receipt(enqueue_plan, 0xde);
    let unarmed = state
        .acknowledge_service_enqueue(enqueue_authority, enqueue_receipt)
        .unwrap();
    let (arm_plan, arm_authority) = state.begin_service_arm(unarmed).unwrap();
    __cser_core::assert_eq!(arm_plan.bearer_generation, 5);
    let arm_receipt = service_arm_receipt(arm_plan, 0xdf);
    let enqueued = state
        .acknowledge_service_arm(arm_authority, arm_receipt)
        .unwrap();

    let service_workload = state
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(SERVICE, 1, 0xe300, 1),
        )
        .unwrap();
    let claimant = state
        .admit_task(
            &service_workload,
            TaskWorkDescriptor {
                work_id: 0xe400,
                generation: 1,
                task: TaskKey::new(0xe500, 1),
                role: TaskWorkRole::ServiceRequest,
                vm: Some(VmAuthorityKey::new(0xe600, 1).unwrap()),
            },
        )
        .unwrap();
    let claimant = state
        .reserve_fault_event(
            claimant,
            FaultSlotDescriptor {
                fault_id: 0xe408,
                generation: 1,
                task: TaskKey::new(0xe500, 1),
                vm_generation: 1,
                service_domain: SERVICE,
                admission_binding_epoch: 1,
            },
        )
        .unwrap();
    let claimant = state.claim_service_task_entry(claimant).unwrap();
    let alternate_claimant = state
        .admit_task(
            &service_workload,
            TaskWorkDescriptor {
                work_id: 0xe410,
                generation: 1,
                task: TaskKey::new(0xe510, 1),
                role: TaskWorkRole::GuestSyscallWork,
                vm: Some(VmAuthorityKey::new(0xe610, 1).unwrap()),
            },
        )
        .unwrap();
    let alternate_claimant = state.claim_task_entry(alternate_claimant).unwrap();
    let _alternate_claimant_child = state
        .create_continuation(
            &alternate_claimant,
            ContinuationDescriptor {
                continuation_id: 0xe730,
                generation: 1,
                vm_generation: 1,
                source_domain: SERVICE,
                source_binding_epoch: 1,
            },
        )
        .unwrap();
    let mut bound = state
        .claim_and_bind_service_child(
            enqueued,
            &claimant,
            ValidatedServiceChildProof::new(ServiceChildReceipt {
                child_effect: EffectKey::new(0xe700, 1),
                registration_digest: 0xe8,
            }),
        )
        .unwrap();
    let mut binding_receipt = None;
    if let ServiceRequestPhase::ChildBound {
        binding_receipt: stored,
        ..
    } = state
        .scope(SCOPE)
        .unwrap()
        .service_requests
        .get(COMPACT_SERVICE_REQUEST)
        .unwrap()
        .phase
    {
        binding_receipt = Some(stored);
    }
    __cser_core::assert!(binding_receipt.is_some());
    let binding_receipt = binding_receipt.unwrap();
    __cser_core::assert_eq!(binding_receipt.service_bearer_generation, 7);
    __cser_core::assert_eq!(binding_receipt.claim_generation, 1);
    let claimant_stamp = state
        .scope(SCOPE)
        .unwrap()
        .tasks
        .get(claimant.0.slot)
        .unwrap()
        .stamp;
    __cser_core::assert_eq!(binding_receipt.claimant.task, claimant_stamp.identity);
    __cser_core::assert_eq!(
        binding_receipt.claimant.task_bearer_generation,
        claimant.0.bearer_generation
    );
    state.check_invariants().unwrap();

    let claimant_mutations: [fn(&mut ServiceChildBindingReceipt); 16] = [
        |receipt| receipt.claim_generation += 1,
        |receipt| receipt.claim_nonce += 1,
        |receipt| receipt.service_bearer_generation -= 1,
        |receipt| receipt.child.registration_digest ^= 1,
        |receipt| receipt.claimant.registry_instance ^= 1,
        |receipt| receipt.claimant.root_effect = EffectKey::new(0xe730, 1),
        |receipt| receipt.claimant.scope = ScopeKey::new(0xe731, 1),
        |receipt| receipt.claimant.authority_epoch += 1,
        |receipt| receipt.claimant.workload_request_id += 1,
        |receipt| receipt.claimant.workload_nonce += 1,
        |receipt| receipt.claimant.workload_bearer_generation += 1,
        |receipt| receipt.claimant.domain = DomainKey::new(0xe7),
        |receipt| receipt.claimant.binding_epoch += 1,
        |receipt| receipt.claimant.task.generation += 1,
        |receipt| receipt.claimant.task_nonce += 1,
        |receipt| receipt.claimant.task_bearer_generation += 1,
    ];
    for mutate in claimant_mutations {
        let mut substituted = state.private_full_clone();
        let mut replaced = false;
        if let ServiceRequestPhase::ChildBound {
            binding_receipt, ..
        } = &mut substituted
            .scope_mut(SCOPE)
            .unwrap()
            .service_requests
            .get_mut(COMPACT_SERVICE_REQUEST)
            .unwrap()
            .phase
        {
            mutate(binding_receipt);
            replaced = true;
        }
        __cser_core::assert!(replaced);
        assert_invariant_read_only(substituted.private_full_clone());
        let coordinates = service_bound_key_coordinates(&bound.0);
        let before = substituted.private_full_clone();
        let failure = substituted
            .complete_service_request(bound, 0xe9)
            .unwrap_err();
        __cser_core::assert!(__cser_core::matches!(
            failure.error(),
            InfrastructureError::InvalidReceipt | InfrastructureError::InvalidState
        ));
        __cser_core::assert_eq!(substituted, before);
        bound = failure.into_input();
        __cser_core::assert_eq!(service_bound_key_coordinates(&bound.0), coordinates);
    }

    let mut substituted_claimant = state.private_full_clone();
    let alternate_stamp = state
        .scope(SCOPE)
        .unwrap()
        .tasks
        .get(alternate_claimant.0.slot)
        .unwrap()
        .stamp;
    let alternate_snapshot = ServiceClaimantSnapshot {
        registry_instance: alternate_stamp.root.registry_instance,
        scope: alternate_stamp.root.scope,
        authority_epoch: alternate_stamp.root.authority_epoch,
        root_effect: alternate_stamp.root.root_effect,
        workload_request_id: alternate_stamp.workload.request.id,
        workload_request_generation: alternate_stamp.workload.request.generation,
        workload_nonce: alternate_stamp.workload.nonce,
        workload_bearer_generation: alternate_stamp.workload.bearer_generation,
        domain: alternate_stamp.domain.domain,
        binding_epoch: alternate_stamp.domain.binding_epoch,
        task: alternate_stamp.identity,
        task_nonce: alternate_stamp.nonce,
        task_bearer_generation: alternate_stamp.bearer_generation,
    };
    {
        let scope = substituted_claimant.scope_mut(SCOPE).unwrap();
        scope
            .tasks
            .get_mut(binding_receipt.claimant.task.work_id)
            .unwrap()
            .live_children -= 1;
        scope
            .tasks
            .get_mut(alternate_snapshot.task.work_id)
            .unwrap()
            .live_children += 1;
        let service = scope
            .service_requests
            .get_mut(COMPACT_SERVICE_REQUEST)
            .unwrap();
        let (queue_receipt, arm_receipt, mut substituted_binding) = match service.phase {
            ServiceRequestPhase::ChildBound {
                queue_receipt,
                arm_receipt,
                binding_receipt,
            } => (queue_receipt, arm_receipt, binding_receipt),
            _ => __cser_core::unreachable!(),
        };
        substituted_binding.claimant = alternate_snapshot;
        substituted_binding.child = ServiceChildReceipt {
            child_effect: EffectKey::new(0xe711, 1),
            registration_digest: 0xe712,
        };
        service.child_binding_commitment = Some(substituted_binding);
        service.bound_commitment = Some(super::service::service_child_bound_commitment(
            queue_receipt,
            arm_receipt,
            service.response_identity.unwrap(),
            substituted_binding,
        ));
        service.phase = ServiceRequestPhase::ChildBound {
            queue_receipt,
            arm_receipt,
            binding_receipt: substituted_binding,
        };
    }
    substituted_claimant.check_invariants().unwrap();
    let coordinates = service_bound_key_coordinates(&bound.0);
    let before = substituted_claimant.private_full_clone();
    let failure = substituted_claimant
        .complete_service_request(bound, 0xe9)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(substituted_claimant, before);
    bound = failure.into_input();
    __cser_core::assert_eq!(service_bound_key_coordinates(&bound.0), coordinates);

    let mut corrupted_claimant = state.private_full_clone();
    corrupted_claimant
        .scope_mut(SCOPE)
        .unwrap()
        .tasks
        .get_mut(binding_receipt.claimant.task.work_id)
        .unwrap()
        .phase = TaskPhase::Reaped;
    let corrupted_bound_coordinates = service_bound_key_coordinates(&bound.0);
    let before_corrupt_completion = corrupted_claimant.private_full_clone();
    let failure = corrupted_claimant
        .complete_service_request(bound, 0xe9)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidState);
    __cser_core::assert_eq!(corrupted_claimant, before_corrupt_completion);
    bound = failure.into_input();
    __cser_core::assert_eq!(
        service_bound_key_coordinates(&bound.0),
        corrupted_bound_coordinates
    );

    let before_early_reap = state.private_full_clone();
    let failure = state
        .finish_service_task_without_fault(claimant, 0xe8f0)
        .unwrap_err();
    __cser_core::assert!(__cser_core::matches!(
        failure.error(),
        InfrastructureError::ClosureBlocked { live: 1, .. }
    ));
    __cser_core::assert_eq!(state, before_early_reap);
    let _claimant = failure.into_input();
    let claim_nonce = state
        .scope(SCOPE)
        .unwrap()
        .service_requests
        .get(COMPACT_SERVICE_REQUEST)
        .unwrap()
        .claim_nonce_high_water;
    let outcome = state.complete_service_request(bound, 0xe9).unwrap();
    __cser_core::assert_eq!(outcome.receipt.bearer_generation, 8);
    __cser_core::assert_eq!(compact_bearer_generation(&state), 2);
    let service = state
        .scope(SCOPE)
        .unwrap()
        .service_requests
        .get(COMPACT_SERVICE_REQUEST)
        .unwrap();
    __cser_core::assert!(service.bound_continuation.is_none());
    __cser_core::assert_eq!(
        service.bound_commitment,
        Some(outcome.receipt.lineage_commitment)
    );
    __cser_core::assert!(__cser_core::matches!(
        service.phase,
        ServiceRequestPhase::Completed {
            queue_receipt: stored_queue,
            arm_receipt: stored_arm,
            receipt,
        } if stored_queue == enqueue_receipt
            && stored_arm == arm_receipt
            && receipt.binding_receipt == binding_receipt
            && receipt == outcome.receipt
    ));
    __cser_core::assert_eq!(service.apply_nonce_high_water, enqueue_plan.apply_nonce);
    __cser_core::assert_eq!(service.arm_nonce_high_water, arm_plan.arm_nonce);
    __cser_core::assert_eq!(service.claim_nonce_high_water, claim_nonce);
    let projection = state
        .query_service_request(&guest_workload, COMPACT_SERVICE_REQUEST, 1)
        .unwrap();
    __cser_core::assert_eq!(projection.state, ServiceRequestRecoveryState::Completed);
    __cser_core::assert_eq!(projection.enqueue_receipt, Some(enqueue_receipt));
    __cser_core::assert_eq!(projection.arm_receipt, Some(arm_receipt));
    __cser_core::assert_eq!(projection.child_binding_receipt, Some(binding_receipt));
    __cser_core::assert_eq!(projection.completion_receipt, Some(outcome.receipt));
    __cser_core::assert_eq!(projection.cancellation_receipt, None);

    let mut synchronously_lowered_bearers = state.private_full_clone();
    {
        let record = synchronously_lowered_bearers
            .scope_mut(SCOPE)
            .unwrap()
            .service_requests
            .get_mut(COMPACT_SERVICE_REQUEST)
            .unwrap();
        record.apply_bearer_generation -= 1;
        record.arm_bearer_generation -= 1;
        record.claim_bearer_generation -= 1;
        record.stamp.bearer_generation -= 1;
        let (mut queue_receipt, mut arm_receipt, mut receipt) = match record.phase {
            ServiceRequestPhase::Completed {
                queue_receipt,
                arm_receipt,
                receipt,
            } => (queue_receipt, arm_receipt, receipt),
            _ => __cser_core::unreachable!(),
        };
        queue_receipt.plan.bearer_generation -= 1;
        arm_receipt.plan.queue_receipt = queue_receipt;
        arm_receipt.plan.bearer_generation -= 1;
        receipt.binding_receipt.service_bearer_generation -= 1;
        receipt.bearer_generation -= 1;
        receipt.lineage_commitment = super::service::service_child_bound_commitment(
            queue_receipt,
            arm_receipt,
            receipt.response,
            receipt.binding_receipt,
        );
        record.child_binding_commitment = Some(receipt.binding_receipt);
        record.bound_commitment = Some(receipt.lineage_commitment);
        record.phase = ServiceRequestPhase::Completed {
            queue_receipt,
            arm_receipt,
            receipt,
        };
    }
    assert_invariant_read_only(synchronously_lowered_bearers);

    let mut allocator_rollback = state.private_full_clone();
    allocator_rollback.scope_mut(SCOPE).unwrap().next_nonce = service.claim_nonce_high_water;
    assert_invariant_read_only(allocator_rollback);

    let mut lower_completion_generation = state.private_full_clone();
    if let ServiceRequestPhase::Completed { receipt, .. } = &mut lower_completion_generation
        .scope_mut(SCOPE)
        .unwrap()
        .service_requests
        .get_mut(COMPACT_SERVICE_REQUEST)
        .unwrap()
        .phase
    {
        receipt.bearer_generation -= 1;
    }
    assert_invariant_read_only(lower_completion_generation);

    let mut lower_enqueue_generation = state.private_full_clone();
    if let ServiceRequestPhase::Completed {
        queue_receipt,
        arm_receipt,
        ..
    } = &mut lower_enqueue_generation
        .scope_mut(SCOPE)
        .unwrap()
        .service_requests
        .get_mut(COMPACT_SERVICE_REQUEST)
        .unwrap()
        .phase
    {
        queue_receipt.plan.bearer_generation -= 1;
        arm_receipt.plan.queue_receipt.plan.bearer_generation -= 1;
    }
    assert_invariant_read_only(lower_enqueue_generation);

    let mut lower_arm_generation = state.private_full_clone();
    if let ServiceRequestPhase::Completed { arm_receipt, .. } = &mut lower_arm_generation
        .scope_mut(SCOPE)
        .unwrap()
        .service_requests
        .get_mut(COMPACT_SERVICE_REQUEST)
        .unwrap()
        .phase
    {
        arm_receipt.plan.bearer_generation -= 1;
    }
    assert_invariant_read_only(lower_arm_generation);

    let mut substituted_claim_nonce = state.private_full_clone();
    if let ServiceRequestPhase::Completed { receipt, .. } = &mut substituted_claim_nonce
        .scope_mut(SCOPE)
        .unwrap()
        .service_requests
        .get_mut(COMPACT_SERVICE_REQUEST)
        .unwrap()
        .phase
    {
        receipt.binding_receipt.claim_nonce += 1;
    }
    assert_invariant_read_only(substituted_claim_nonce);

    let mut substituted_claimant_workload = state.private_full_clone();
    if let ServiceRequestPhase::Completed { receipt, .. } = &mut substituted_claimant_workload
        .scope_mut(SCOPE)
        .unwrap()
        .service_requests
        .get_mut(COMPACT_SERVICE_REQUEST)
        .unwrap()
        .phase
    {
        receipt.binding_receipt.claimant.workload_request_id += 1;
    }
    assert_invariant_read_only(substituted_claimant_workload);

    for substituted_response in [alternate_parent_response, alternate_workload_response] {
        let mut substituted = state.private_full_clone();
        let service = substituted
            .scope_mut(SCOPE)
            .unwrap()
            .service_requests
            .get_mut(COMPACT_SERVICE_REQUEST)
            .unwrap();
        let mut replaced = false;
        if let ServiceRequestPhase::Completed {
            queue_receipt,
            arm_receipt,
            receipt,
            ..
        } = &mut service.phase
        {
            queue_receipt.plan.causal.response = substituted_response;
            arm_receipt.plan.causal.response = substituted_response;
            arm_receipt.plan.queue_receipt.plan.causal.response = substituted_response;
            arm_receipt.bound_continuation_id = substituted_response.continuation_id;
            arm_receipt.bound_continuation_generation = substituted_response.generation;
            receipt.response = substituted_response;
            replaced = true;
        }
        __cser_core::assert!(replaced);
        assert_invariant_read_only(substituted);
    }

    *state
        .scope_mut(SCOPE)
        .unwrap()
        .binding_epoch_mut(SERVICE)
        .unwrap() = 2;
    let adopted_service_workload = state
        .adopt_workload_after_fence(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(SERVICE, 2, 0xe300, 1),
        )
        .unwrap();
    let adopted_claimant = state
        .adopt_task_after_fence(&adopted_service_workload, 0xe400, 1)
        .unwrap();
    state.check_invariants().unwrap();
    let mut armed_claimant = None;
    if let TaskAdoption::FaultArmed(armed) = adopted_claimant {
        armed_claimant = Some(armed);
    }
    __cser_core::assert!(armed_claimant.is_some());
    state
        .finish_service_task_without_fault(armed_claimant.unwrap(), 0xeaf0)
        .unwrap();
    state.check_invariants().unwrap();

    state.claim_continuation(outcome.response, 0xea).unwrap();
    __cser_core::assert_eq!(compact_bearer_generation(&state), 3);
    state.check_invariants().unwrap();
}

#[test]
fn deadline_compact_authority_layout_is_bounded() {
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::DeadlineArmed>>() <= 64
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::DeadlineFired>>() <= 64
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::DeadlineExhausted>>() <= 64
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::DeadlineQuarantined>>() <= 64
    );
    __cser_core::assert!(__cser_core::mem::size_of::<DeadlineLease>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<DeadlineExpiryReceipt>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<DeadlineQuarantineTicket>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<DeadlineLease>>() <= 120);
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<DeadlineExpiryReceipt>>() <= 120
    );
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<DeadlineQuarantineTicket>>() <= 120
    );
}

#[test]
fn device_closure_deadline_fails_closed_without_device_owner() {
    let (mut state, _, entered, _) = compact_deadline_state(0xf001, 2);
    let before = state.private_full_clone();
    __cser_core::assert_eq!(
        state
            .arm_deadline(
                &entered,
                DeadlineDescriptor {
                    series_id: COMPACT_DEADLINE + 1,
                    generation: 1,
                    purpose: DeadlinePurpose::DeviceClosure,
                    clock: DeadlineClockBasis::ObservedCallbackTick,
                    deadline_tick: 20,
                    attempt: 1,
                    max_attempts: 2,
                    backoff_ticks: 5,
                },
            )
            .unwrap_err(),
        InfrastructureError::NotEnabled
    );
    __cser_core::assert_eq!(state, before);
}

#[test]
fn deadline_rearm_is_failure_atomic_and_exhaustion_is_retained() {
    let (mut state, workload, _, deadline) = compact_deadline_state(0xf011, 2);
    let initial_nonce = deadline_coordinates(&state).2;
    let before_early = state.private_full_clone();
    let failure = state
        .fire_deadline(deadline, DeadlineClockBasis::ObservedCallbackTick, 9)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidState);
    __cser_core::assert_eq!(state, before_early);
    let deadline = failure.into_input();

    let expiry = state
        .fire_deadline(deadline, DeadlineClockBasis::ObservedCallbackTick, 10)
        .unwrap();
    let fired = deadline_coordinates(&state);
    __cser_core::assert_eq!((fired.0, fired.1), (1, 2));
    __cser_core::assert_ne!(fired.2, initial_nonce);
    let projection = state
        .query_deadline(&workload, COMPACT_DEADLINE, 1)
        .unwrap();
    __cser_core::assert_eq!(projection.state, DeadlineRecoveryState::Fired);
    __cser_core::assert_eq!(projection.observed_tick, Some(10));

    let before_bad_generation = state.private_full_clone();
    let failure = state.rearm_deadline(expiry, 3, 15).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::StaleGeneration);
    __cser_core::assert_eq!(state, before_bad_generation);
    let expiry = failure.into_input();
    let deadline = state.rearm_deadline(expiry, 2, 15).unwrap();
    let rearmed = deadline_coordinates(&state);
    __cser_core::assert_eq!((rearmed.0, rearmed.1), (2, 3));
    __cser_core::assert_ne!(rearmed.2, fired.2);

    let exhausted = state
        .fire_deadline(deadline, DeadlineClockBasis::ObservedCallbackTick, 15)
        .unwrap();
    __cser_core::assert_eq!(deadline_coordinates(&state).1, 4);
    let before_retained = state.private_full_clone();
    let failure = state.rearm_deadline(exhausted, 3, 20).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::ClosureRetained);
    __cser_core::assert_eq!(state, before_retained);
    let exhausted = failure.into_input();
    let failure = state.resolve_fired_deadline(exhausted).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::ClosureRetained);
    __cser_core::assert_eq!(state, before_retained);
    state.check_invariants().unwrap();
}

#[test]
fn foreign_registry_returns_exact_deadline_authority() {
    let (mut owner, _, _, deadline) = compact_deadline_state(0xf021, 2);
    let (mut foreign, _, _, _foreign_deadline) = compact_deadline_state(0xf022, 2);
    let before_owner = owner.private_full_clone();
    let before_foreign = foreign.private_full_clone();

    let failure = foreign
        .fire_deadline(deadline, DeadlineClockBasis::ObservedCallbackTick, 10)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::ForeignRegistry);
    __cser_core::assert_eq!(foreign, before_foreign);
    __cser_core::assert_eq!(owner, before_owner);

    owner
        .fire_deadline(
            failure.into_input(),
            DeadlineClockBasis::ObservedCallbackTick,
            10,
        )
        .unwrap();
    __cser_core::assert_eq!(deadline_coordinates(&owner).1, 2);
}

#[test]
fn deadline_compact_key_rejects_each_stale_coordinate_without_mutation() {
    assert_deadline_key_rejected_without_mutation(
        0xf023,
        |deadline| deadline.0.authority.authority_epoch += 1,
        InfrastructureError::StaleAuthority,
    );
    assert_deadline_key_rejected_without_mutation(
        0xf024,
        |deadline| deadline.0.slot += 1,
        InfrastructureError::UnknownObligation,
    );
    assert_deadline_key_rejected_without_mutation(
        0xf025,
        |deadline| deadline.0.object_generation += 1,
        InfrastructureError::StaleGeneration,
    );
    assert_deadline_key_rejected_without_mutation(
        0xf026,
        |deadline| deadline.0.bearer_generation += 1,
        InfrastructureError::StaleGeneration,
    );
    assert_deadline_key_rejected_without_mutation(
        0xf027,
        |deadline| deadline.0.nonce += 1,
        InfrastructureError::StaleGeneration,
    );
    assert_deadline_key_rejected_without_mutation(
        0xf028,
        |deadline| {
            deadline.0.authority.scope =
                ScopeKey::new(deadline.0.authority.scope.id(), SCOPE.generation() + 1);
        },
        InfrastructureError::NotEnabled,
    );
}

#[test]
fn deadline_expiry_typestate_must_match_the_authoritative_phase() {
    let (mut fired_state, _, _, deadline) = compact_deadline_state(0xf029, 2);
    let fired = fired_state
        .fire_deadline(deadline, DeadlineClockBasis::ObservedCallbackTick, 10)
        .unwrap();
    let fired_key = match fired.0 {
        DeadlineExpiryAuthority::Fired(key) => key,
        DeadlineExpiryAuthority::Exhausted(_) => {
            __cser_core::panic!("nonterminal attempt exhausted")
        }
    };
    let forged_exhausted = DeadlineExpiryReceipt(DeadlineExpiryAuthority::Exhausted(BearerKey {
        authority: fired_key.authority,
        slot: fired_key.slot,
        object_generation: fired_key.object_generation,
        bearer_generation: fired_key.bearer_generation,
        nonce: fired_key.nonce,
        state: __cser_core::marker::PhantomData,
    }));
    let before_fired = fired_state.private_full_clone();
    let failure = fired_state
        .reconcile_exhausted_deadline(
            forged_exhausted,
            DeadlineReconciliationReceipt {
                disposition: DeadlineExhaustedDisposition::AbortWork,
                evidence_digest: 0xf29,
            },
            None,
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::StaleClaim);
    __cser_core::assert_eq!(fired_state, before_fired);

    let (mut exhausted_state, _, _, deadline) = compact_deadline_state(0xf02a, 1);
    let exhausted = exhausted_state
        .fire_deadline(deadline, DeadlineClockBasis::ObservedCallbackTick, 10)
        .unwrap();
    let exhausted_key = match exhausted.0 {
        DeadlineExpiryAuthority::Exhausted(key) => key,
        DeadlineExpiryAuthority::Fired(_) => {
            __cser_core::panic!("terminal attempt did not exhaust")
        }
    };
    let forged_fired = DeadlineExpiryReceipt(DeadlineExpiryAuthority::Fired(BearerKey {
        authority: exhausted_key.authority,
        slot: exhausted_key.slot,
        object_generation: exhausted_key.object_generation,
        bearer_generation: exhausted_key.bearer_generation,
        nonce: exhausted_key.nonce,
        state: __cser_core::marker::PhantomData,
    }));
    let before_exhausted = exhausted_state.private_full_clone();
    let failure = exhausted_state
        .resolve_fired_deadline(forged_fired)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::StaleClaim);
    __cser_core::assert_eq!(exhausted_state, before_exhausted);
}

#[test]
fn supervisor_retry_mints_new_object_bearer_and_nonce() {
    let (mut state, workload, _, deadline) = compact_deadline_state(0xf031, 1);
    let expiry = state
        .fire_deadline(deadline, DeadlineClockBasis::ObservedCallbackTick, 10)
        .unwrap();
    let exhausted_coordinates = deadline_coordinates(&state);
    let reconciliation = DeadlineReconciliationReceipt {
        disposition: DeadlineExhaustedDisposition::RetryBySupervisor,
        evidence_digest: 0xf31,
    };
    let before_invalid = state.private_full_clone();
    let failure = state
        .reconcile_exhausted_deadline(
            expiry,
            reconciliation,
            Some(DeadlineSupervisorRetry {
                generation: 1,
                deadline_tick: 20,
                max_attempts: 2,
                backoff_ticks: 4,
            }),
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before_invalid);

    let deadline = match state
        .reconcile_exhausted_deadline(
            failure.into_input(),
            reconciliation,
            Some(DeadlineSupervisorRetry {
                generation: 2,
                deadline_tick: 20,
                max_attempts: 2,
                backoff_ticks: 4,
            }),
        )
        .unwrap()
    {
        DeadlineReconciliationOutcome::Retried(deadline) => deadline,
        _ => __cser_core::panic!("supervisor retry returned the wrong outcome"),
    };
    let retried = deadline_coordinates(&state);
    __cser_core::assert_eq!((retried.0, retried.1), (2, 3));
    __cser_core::assert_ne!(retried.2, exhausted_coordinates.2);
    let projection = state
        .query_deadline(&workload, COMPACT_DEADLINE, 2)
        .unwrap();
    __cser_core::assert_eq!(projection.state, DeadlineRecoveryState::Armed);
    __cser_core::assert_eq!(projection.reconciliation, Some(reconciliation));
    __cser_core::assert_eq!(projection.descriptor.attempt, 1);
    __cser_core::assert_eq!(projection.descriptor.max_attempts, 2);
    __cser_core::assert_eq!(projection.descriptor.backoff_ticks, 4);
    state.check_invariants().unwrap();

    let mut high_water_rollback = state.private_full_clone();
    high_water_rollback.scope_mut(SCOPE).unwrap().next_nonce = retried.2;
    assert_invariant_read_only(high_water_rollback);

    state.cancel_deadline(deadline).unwrap();
    __cser_core::assert_eq!(deadline_coordinates(&state).1, 4);
    state.check_invariants().unwrap();
}

#[test]
fn quarantined_deadline_adoption_fences_stale_ticket_and_is_failure_atomic() {
    let (mut state, _old_workload, _, deadline) = compact_deadline_state(0xf041, 1);
    let exhausted = state
        .fire_deadline(deadline, DeadlineClockBasis::ObservedCallbackTick, 10)
        .unwrap();
    let quarantine_receipt = DeadlineReconciliationReceipt {
        disposition: DeadlineExhaustedDisposition::Quarantine,
        evidence_digest: 0xf41,
    };
    let ticket = match state
        .reconcile_exhausted_deadline(exhausted, quarantine_receipt, None)
        .unwrap()
    {
        DeadlineReconciliationOutcome::Quarantined(ticket) => ticket,
        _ => __cser_core::panic!("quarantine reconciliation returned the wrong outcome"),
    };
    let quarantined = deadline_coordinates(&state);
    __cser_core::assert_eq!(quarantined.1, 3);
    let before_bad_release = state.private_full_clone();
    let failure = state
        .resolve_quarantined_deadline(
            ticket,
            DeadlineQuarantineReleaseReceipt { evidence_digest: 0 },
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before_bad_release);
    let stale_ticket = failure.into_input();

    *state
        .scope_mut(SCOPE)
        .unwrap()
        .binding_epoch_mut(GUEST)
        .unwrap() = 2;
    let workload = state
        .adopt_workload_after_fence(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 2, COMPACT_DEADLINE_REQUEST, 1),
        )
        .unwrap();
    let before_parent_adoption = state.private_full_clone();
    __cser_core::assert_eq!(
        state
            .adopt_deadline_after_fence(&workload, COMPACT_DEADLINE, 1)
            .unwrap_err(),
        InfrastructureError::StaleBinding
    );
    __cser_core::assert_eq!(state, before_parent_adoption);
    __cser_core::assert!(__cser_core::matches!(
        state
            .adopt_task_after_fence(&workload, COMPACT_DEADLINE_WORK, 1)
            .unwrap(),
        TaskAdoption::Entered(_)
    ));

    let mut missing_index = state.private_full_clone();
    let index_slot = missing_index
        .scope(SCOPE)
        .unwrap()
        .deadlines
        .get(COMPACT_DEADLINE)
        .unwrap()
        .series_nonce;
    missing_index
        .scope_mut(SCOPE)
        .unwrap()
        .reverse_indexes
        .remove(index_slot)
        .unwrap();
    let before_missing_index = missing_index.private_full_clone();
    __cser_core::assert_eq!(
        missing_index
            .adopt_deadline_after_fence(&workload, COMPACT_DEADLINE, 1)
            .unwrap_err(),
        InfrastructureError::Invariant("missing deadline reverse index")
    );
    __cser_core::assert_eq!(missing_index, before_missing_index);

    let current_ticket = match state
        .adopt_deadline_after_fence(&workload, COMPACT_DEADLINE, 1)
        .unwrap()
    {
        DeadlineAdoption::Quarantined(ticket) => ticket,
        _ => __cser_core::panic!("quarantined deadline adopted into the wrong phase"),
    };
    let adopted = deadline_coordinates(&state);
    __cser_core::assert_eq!(adopted.1, 4);
    __cser_core::assert_ne!(adopted.2, quarantined.2);
    let before_stale = state.private_full_clone();
    let failure = state
        .resolve_quarantined_deadline(
            stale_ticket,
            DeadlineQuarantineReleaseReceipt {
                evidence_digest: 0xf42,
            },
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::StaleGeneration);
    __cser_core::assert_eq!(state, before_stale);

    state
        .resolve_quarantined_deadline(
            current_ticket,
            DeadlineQuarantineReleaseReceipt {
                evidence_digest: 0xf43,
            },
        )
        .unwrap();
    __cser_core::assert_eq!(deadline_coordinates(&state).1, 5);
    let projection = state
        .query_deadline(&workload, COMPACT_DEADLINE, 1)
        .unwrap();
    __cser_core::assert_eq!(projection.state, DeadlineRecoveryState::Resolved);
    __cser_core::assert_eq!(projection.reconciliation, Some(quarantine_receipt));
    __cser_core::assert_eq!(projection.terminal_evidence_digest, Some(0xf43));
    state.check_invariants().unwrap();

    let mut mismatched_reconciliation = state.private_full_clone();
    mismatched_reconciliation
        .scope_mut(SCOPE)
        .unwrap()
        .deadlines
        .get_mut(COMPACT_DEADLINE)
        .unwrap()
        .last_reconciliation
        .as_mut()
        .unwrap()
        .evidence_digest ^= 1;
    assert_invariant_read_only(mismatched_reconciliation);
}

#[test]
fn deadline_terminal_paths_advance_bearer_generation() {
    let (mut cancelled, cancelled_workload, _, deadline) = compact_deadline_state(0xf051, 2);
    cancelled.cancel_deadline(deadline).unwrap();
    __cser_core::assert_eq!(deadline_coordinates(&cancelled).1, 2);
    __cser_core::assert_eq!(
        cancelled
            .query_deadline(&cancelled_workload, COMPACT_DEADLINE, 1)
            .unwrap()
            .state,
        DeadlineRecoveryState::Cancelled
    );
    cancelled.check_invariants().unwrap();

    let (mut resolved, resolved_workload, _, deadline) = compact_deadline_state(0xf052, 2);
    let fired = resolved
        .fire_deadline(deadline, DeadlineClockBasis::ObservedCallbackTick, 10)
        .unwrap();
    resolved.resolve_fired_deadline(fired).unwrap();
    __cser_core::assert_eq!(deadline_coordinates(&resolved).1, 3);
    __cser_core::assert_eq!(
        resolved
            .query_deadline(&resolved_workload, COMPACT_DEADLINE, 1)
            .unwrap()
            .state,
        DeadlineRecoveryState::Resolved
    );
    resolved.check_invariants().unwrap();

    let (mut aborted, _, _, deadline) = compact_deadline_state(0xf053, 1);
    let exhausted = aborted
        .fire_deadline(deadline, DeadlineClockBasis::ObservedCallbackTick, 10)
        .unwrap();
    __cser_core::assert!(__cser_core::matches!(
        aborted
            .reconcile_exhausted_deadline(
                exhausted,
                DeadlineReconciliationReceipt {
                    disposition: DeadlineExhaustedDisposition::AbortWork,
                    evidence_digest: 0xf53,
                },
                None,
            )
            .unwrap(),
        DeadlineReconciliationOutcome::Aborted
    ));
    __cser_core::assert_eq!(deadline_coordinates(&aborted).1, 3);
    aborted.check_invariants().unwrap();
}

fn seeded_state() -> InfrastructureState {
    let mut state = InfrastructureState::new(0x9000);
    state
        .enable(SCOPE, 1, ROOT, limits(), &[(GUEST, 1), (SERVICE, 1)])
        .unwrap();
    let workload = state
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 1, 0x9300, 1),
        )
        .unwrap();
    let task = state
        .admit_task(
            &workload,
            TaskWorkDescriptor {
                work_id: 0x9400,
                generation: 1,
                task: TaskKey::new(0x9500, 1),
                role: TaskWorkRole::GuestSyscallWork,
                vm: Some(VmAuthorityKey::new(0x9600, 1).unwrap()),
            },
        )
        .unwrap();
    let entered = state.claim_task_entry(task).unwrap();
    let service = state
        .reserve_service_request(
            &entered,
            ServiceRequestDescriptor {
                request_id: 0x9800,
                generation: 1,
                queue: ResourceKey::new(0x99, 1, 1),
                queue_generation: 1,
                destination_domain: SERVICE,
                destination_binding_epoch: 1,
                command_digest: 0x9a,
                payload_slot: 1,
                payload_generation: 1,
                response_slot_id: 0x9b00,
                response_slot_generation: 1,
            },
        )
        .unwrap();
    state
        .bind_service_response_continuation(
            service,
            ContinuationDescriptor {
                continuation_id: 0x9700,
                generation: 1,
                vm_generation: 1,
                source_domain: GUEST,
                source_binding_epoch: 1,
            },
        )
        .unwrap();
    state
        .reserve_device_preparation(
            &workload,
            ROOT,
            DeviceReservationCoordinates {
                preparation_id: 0x9c00,
                generation: 1,
                owned_device: ResourceKey::new(0x9d, 1, 1),
                queue: 0,
                device_generation: 1,
                operation_digest: 0x9e,
                queue_credit_class: super::super::CreditClass::new(0xa1),
                pinned_credit_class: super::super::CreditClass::new(0xa2),
                dma_credit_class: super::super::CreditClass::new(0xa3),
                actor_slot: 2,
                actor_generation: 1,
            },
        )
        .unwrap();
    state.check_invariants().unwrap();
    state
}

fn test_service_key<State: bearer_state::Sealed>(
    state: &InfrastructureState,
    request_id: u64,
) -> BearerKey<State> {
    let record = state
        .scope(SCOPE)
        .unwrap()
        .service_requests
        .get(request_id)
        .unwrap();
    BearerKey {
        authority: AuthorityKey {
            registry_instance: record.stamp.root.registry_instance,
            scope: record.stamp.root.scope,
            authority_epoch: record.stamp.root.authority_epoch,
        },
        slot: record.stamp.identity.request_id,
        object_generation: record.stamp.identity.generation,
        bearer_generation: record.stamp.bearer_generation,
        nonce: record.stamp.nonce,
        state: __cser_core::marker::PhantomData,
    }
}

fn test_service_bound_key<State: bearer_state::Sealed>(
    state: &InfrastructureState,
    request_id: u64,
) -> ServiceBoundKey<State> {
    let record = state
        .scope(SCOPE)
        .unwrap()
        .service_requests
        .get(request_id)
        .unwrap();
    let response = record.response_identity.unwrap();
    let lineage_commitment = match record.phase {
        ServiceRequestPhase::ReservedBound => super::service::service_response_commitment(response),
        ServiceRequestPhase::Publishing {
            apply_generation,
            apply_nonce,
        } => super::service::service_enqueue_plan_commitment(ServiceEnqueuePlan {
            causal: record_service_causal_identity(record, response),
            bearer_generation: record.apply_bearer_generation,
            apply_generation,
            apply_nonce,
        }),
        ServiceRequestPhase::QueueWrittenUnarmed { queue_receipt } => {
            super::service::service_enqueue_receipt_commitment(queue_receipt)
        }
        ServiceRequestPhase::Arming {
            queue_receipt,
            arm_generation,
            arm_nonce,
        } => super::service::service_arm_plan_commitment(ServiceArmPlan {
            causal: record_service_causal_identity(record, response),
            queue_receipt,
            bearer_generation: record.arm_bearer_generation,
            arm_generation,
            arm_nonce,
        }),
        ServiceRequestPhase::Armed {
            queue_receipt,
            arm_receipt,
        } => super::service::service_armed_commitment(queue_receipt, arm_receipt),
        ServiceRequestPhase::ChildBound {
            queue_receipt,
            arm_receipt,
            binding_receipt,
        } => super::service::service_child_bound_commitment(
            queue_receipt,
            arm_receipt,
            response,
            binding_receipt,
        ),
        _ => __cser_core::panic!("test service bound key requires a live bound phase"),
    };
    ServiceBoundKey {
        authority: AuthorityKey {
            registry_instance: record.stamp.root.registry_instance,
            scope: record.stamp.root.scope,
            authority_epoch: record.stamp.root.authority_epoch,
        },
        slot: record.stamp.identity.request_id,
        object_generation: record.stamp.identity.generation,
        bearer_generation: record.stamp.bearer_generation,
        nonce: record.stamp.nonce,
        lineage_commitment,
        state: __cser_core::marker::PhantomData,
    }
}

fn record_service_causal_identity(
    record: &super::ServiceRequestStateRecord,
    response: ContinuationDescriptor,
) -> ServiceRequestCausalIdentity {
    let parent_task = match record.stamp.parent {
        super::ParentStamp::Task(parent) => parent,
        _ => __cser_core::unreachable!(),
    };
    ServiceRequestCausalIdentity {
        registry_instance: record.stamp.root.registry_instance,
        scope: record.stamp.root.scope,
        authority_epoch: record.stamp.root.authority_epoch,
        root_effect: record.stamp.root.root_effect,
        workload_request_id: record.stamp.workload.request.id,
        workload_request_generation: record.stamp.workload.request.generation,
        workload_nonce: record.stamp.workload.nonce,
        workload_bearer_generation: record.stamp.workload.bearer_generation,
        admission_domain: record.stamp.domain.domain,
        admission_binding_epoch: record.stamp.domain.binding_epoch,
        parent_task,
        request_nonce: record.stamp.nonce,
        descriptor: record.stamp.identity,
        response,
    }
}

fn test_bound_service_authority(
    state: &InfrastructureState,
    request_id: u64,
) -> ServiceRequestTicket {
    ServiceRequestTicket(
        test_service_bound_key::<bearer_state::ServiceReservedBound>(state, request_id),
    )
}

fn assert_invariant_read_only(state: InfrastructureState) {
    let before = state.private_full_clone();
    __cser_core::assert!(__cser_core::matches!(
        state.check_invariants(),
        Err(InfrastructureError::Invariant(_))
    ));
    __cser_core::assert_eq!(state, before);
}

fn assert_invariant_message_read_only(state: InfrastructureState, message: &'static str) {
    let before = state.private_full_clone();
    __cser_core::assert_eq!(
        state.check_invariants(),
        Err(InfrastructureError::Invariant(message))
    );
    __cser_core::assert_eq!(state, before);
}

fn publication_state() -> InfrastructureState {
    let mut state = InfrastructureState::new(0x9010);
    state
        .enable(SCOPE, 1, ROOT, limits(), &[(GUEST, 1)])
        .unwrap();
    let workload = state
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 1, 0xa300, 1),
        )
        .unwrap();
    let task = state
        .admit_task(
            &workload,
            TaskWorkDescriptor {
                work_id: 0xa400,
                generation: 1,
                task: TaskKey::new(0xa500, 1),
                role: TaskWorkRole::GuestSyscallWork,
                vm: Some(VmAuthorityKey::new(0xa600, 1).unwrap()),
            },
        )
        .unwrap();
    let entered = state.claim_task_entry(task).unwrap();
    let continuation = state
        .create_continuation(
            &entered,
            ContinuationDescriptor {
                continuation_id: 0xa700,
                generation: 1,
                vm_generation: 1,
                source_domain: GUEST,
                source_binding_epoch: 1,
            },
        )
        .unwrap();
    let claim = state.claim_continuation(continuation, 0xa8).unwrap();
    state
        .begin_continuation_publication(
            claim,
            ContinuationPublicationReceipt {
                vm_generation: 1,
                source_domain: GUEST,
                source_binding_epoch: 1,
                outcome_digest: 0xa8,
            },
        )
        .unwrap();
    state.check_invariants().unwrap();
    state
}

fn reserved_fault_state(
    registry_instance: u64,
) -> (InfrastructureState, WorkloadContext, ReservedFaultTask) {
    let mut state = InfrastructureState::new(registry_instance);
    state
        .enable(SCOPE, 1, ROOT, limits(), &[(SERVICE, 1)])
        .unwrap();
    let workload = state
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(SERVICE, 1, 0xfc10, 1),
        )
        .unwrap();
    let task_key = TaskKey::new(0xfc20, 1);
    let task = state
        .admit_task(
            &workload,
            TaskWorkDescriptor {
                work_id: 0xfc30,
                generation: 1,
                task: task_key,
                role: TaskWorkRole::ServiceRequest,
                vm: Some(VmAuthorityKey::new(0xfc40, 1).unwrap()),
            },
        )
        .unwrap();
    __cser_core::assert_eq!(task.0.bearer_generation, 1);
    let reserved = state
        .reserve_fault_event(
            task,
            FaultSlotDescriptor {
                fault_id: 0xfc50,
                generation: 1,
                task: task_key,
                vm_generation: 1,
                service_domain: SERVICE,
                admission_binding_epoch: 1,
            },
        )
        .unwrap();
    __cser_core::assert_eq!(reserved.0.bearer_generation, 2);
    state.check_invariants().unwrap();
    (state, workload, reserved)
}

fn armed_fault_state(
    registry_instance: u64,
) -> (
    InfrastructureState,
    WorkloadContext,
    ArmedFaultTask,
    FaultObservation,
) {
    let (mut state, workload, reserved) = reserved_fault_state(registry_instance);
    let armed = state.claim_service_task_entry(reserved).unwrap();
    __cser_core::assert_eq!(armed.0.bearer_generation, 3);
    __cser_core::assert_eq!(
        state
            .scope(SCOPE)
            .unwrap()
            .faults
            .get(0xfc50)
            .unwrap()
            .stamp
            .bearer_generation,
        2
    );
    let observation = FaultObservation {
        task: TaskKey::new(0xfc20, 1),
        vm_generation: 1,
        instruction_pointer: 0xfc60,
        address: 0xfc70,
        access: FaultAccess::Write,
        architecture_error: 0xfc80,
        evidence_digest: 0xfc90,
    };
    state.check_invariants().unwrap();
    (state, workload, armed, observation)
}

#[test]
fn service_task_entry_rejects_every_substituted_fault_coordinate_without_consuming_authority() {
    type MutateReserved = fn(&mut super::FaultStateRecord);
    let mutations: &[MutateReserved] = &[
        |fault| fault.stamp.parent = super::ParentStamp::RootEffect(ROOT),
        |fault| fault.stamp.root.root_effect = EffectKey::new(ROOT.id() + 1, ROOT.generation()),
        |fault| fault.stamp.domain.binding_epoch += 1,
        |fault| fault.stamp.workload.request.id += 1,
        |fault| fault.stamp.identity.service_domain = GUEST,
        |fault| fault.stamp.identity.admission_binding_epoch += 1,
        |fault| fault.stamp.identity.vm_generation += 1,
        |fault| {
            fault.stamp.identity.task = TaskKey::new(
                fault.stamp.identity.task.id() + 1,
                fault.stamp.identity.task.generation(),
            )
        },
    ];

    for mutate in mutations {
        let (mut state, _, reserved) = reserved_fault_state(0x90f0);
        mutate(
            state
                .scope_mut(SCOPE)
                .unwrap()
                .faults
                .get_mut(0xfc50)
                .unwrap(),
        );
        let authority = service_key_coordinates(&reserved.0);
        let before = state.private_full_clone();
        let failure = state.claim_service_task_entry(reserved).unwrap_err();
        __cser_core::assert_eq!(
            failure.error(),
            InfrastructureError::Invariant("task-fault pair mismatch")
        );
        let returned = failure.into_input();
        __cser_core::assert_eq!(service_key_coordinates(&returned.0), authority);
        __cser_core::assert_eq!(state, before);
    }
}

fn install_additional_fault(
    state: &mut InfrastructureState,
    identity_base: u64,
    disposition: FaultDisposition,
) -> (u64, u64) {
    let binding_epoch = state.scope(SCOPE).unwrap().binding_epoch(SERVICE).unwrap();
    let workload = state
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(SERVICE, binding_epoch, identity_base, 1),
        )
        .unwrap();
    let work_id = identity_base + 1;
    let task_key = TaskKey::new(identity_base + 2, 1);
    let task = state
        .admit_task(
            &workload,
            TaskWorkDescriptor {
                work_id,
                generation: 1,
                task: task_key,
                role: TaskWorkRole::ServiceRequest,
                vm: Some(VmAuthorityKey::new(identity_base + 3, 1).unwrap()),
            },
        )
        .unwrap();
    let fault_id = identity_base + 4;
    let reserved = state
        .reserve_fault_event(
            task,
            FaultSlotDescriptor {
                fault_id,
                generation: 1,
                task: task_key,
                vm_generation: 1,
                service_domain: SERVICE,
                admission_binding_epoch: binding_epoch,
            },
        )
        .unwrap();
    let armed = state.claim_service_task_entry(reserved).unwrap();
    let (intent, plan) = state
        .prepare_fault_disposition(
            armed,
            FaultObservation {
                task: task_key,
                vm_generation: 1,
                instruction_pointer: identity_base + 5,
                address: identity_base + 6,
                access: FaultAccess::Read,
                architecture_error: identity_base + 7,
                evidence_digest: identity_base + 8,
            },
            disposition,
        )
        .unwrap();
    state.install_fault_disposition(intent, plan).unwrap();
    (work_id, fault_id)
}

fn current_armed_fault(state: &InfrastructureState) -> ArmedFaultTask {
    ArmedFaultTask(super::mint_task_key::<bearer_state::TaskFaultArmed>(
        state.scope(SCOPE).unwrap().tasks.get(0xfc30).unwrap(),
    ))
}

#[test]
fn task_fault_compact_key_coordinates_are_all_fenced() {
    type Mutate = fn(&mut BearerKey<bearer_state::TaskFaultArmed>);
    let mutations: [Mutate; 7] = [
        |key| key.authority.registry_instance ^= 1,
        |key| key.authority.scope = ScopeKey::new(SCOPE.id() + 1, SCOPE.generation()),
        |key| key.authority.authority_epoch += 1,
        |key| key.slot += 1,
        |key| key.object_generation += 1,
        |key| key.bearer_generation += 1,
        |key| key.nonce += 1,
    ];
    for mutate in mutations {
        let (state, _, _, observation) = armed_fault_state(0xfc00);
        let mut forged = current_armed_fault(&state);
        mutate(&mut forged.0);
        let presented = service_key_coordinates(&forged.0);
        let before = state.private_full_clone();
        let failure = state
            .prepare_fault_disposition(forged, observation, FaultDisposition::CrashService)
            .unwrap_err();
        __cser_core::assert!(__cser_core::matches!(
            failure.error(),
            InfrastructureError::ForeignRegistry
                | InfrastructureError::ForeignScope
                | InfrastructureError::StaleAuthority
                | InfrastructureError::NotEnabled
                | InfrastructureError::UnknownObligation
                | InfrastructureError::IdentityConflict
                | InfrastructureError::StaleGeneration
        ));
        __cser_core::assert_eq!(state, before);
        let returned = failure.into_input();
        __cser_core::assert_eq!(service_key_coordinates(&returned.0), presented);
    }
}

#[test]
fn fault_plan_commitment_is_frozen_and_every_field_is_bound() {
    let (state, _, armed, observation) = armed_fault_state(0xfc00);
    let (_, plan) = state
        .prepare_fault_disposition(armed, observation, FaultDisposition::CrashService)
        .unwrap();
    __cser_core::assert_eq!(
        plan.commitment.0,
        [
            0x1c, 0xde, 0xeb, 0xe8, 0x8c, 0x92, 0xd3, 0x78, 0x71, 0x54, 0x50, 0x11, 0xd5, 0xd1,
            0xe2, 0x5f, 0x1f, 0xdc, 0xd9, 0x95, 0x27, 0x5e, 0x79, 0x9f, 0x0b, 0x7b, 0x99, 0x88,
            0xe3, 0x37, 0xa5, 0x85,
        ]
    );

    type Mutate = fn(&mut super::FaultDispositionPlan);
    let mutations: &[Mutate] = &[
        |plan| plan.scope = ScopeKey::new(plan.scope.id() + 1, plan.scope.generation()),
        |plan| plan.task.work_id += 1,
        |plan| plan.task.generation += 1,
        |plan| plan.task.task = TaskKey::new(plan.task.task.id() + 1, plan.task.task.generation()),
        |plan| plan.task.role = TaskWorkRole::ReplacementRecovery,
        |plan| plan.task.vm = Some(VmAuthorityKey::new(0xfd00, 1).unwrap()),
        |plan| plan.fault.fault_id += 1,
        |plan| plan.fault.generation += 1,
        |plan| plan.fault.task = TaskKey::new(plan.fault.task.id() + 1, 1),
        |plan| plan.fault.vm_generation += 1,
        |plan| plan.fault.service_domain = DomainKey::new(SERVICE.value() + 1),
        |plan| plan.fault.admission_binding_epoch += 1,
        |plan| plan.task_nonce += 1,
        |plan| plan.task_bearer_generation += 1,
        |plan| plan.fault_nonce += 1,
        |plan| plan.fault_bearer_generation += 1,
        |plan| plan.observation.task = TaskKey::new(plan.observation.task.id() + 1, 1),
        |plan| plan.observation.vm_generation += 1,
        |plan| plan.observation.instruction_pointer += 1,
        |plan| plan.observation.address += 1,
        |plan| plan.observation.access = FaultAccess::Execute,
        |plan| plan.observation.architecture_error += 1,
        |plan| plan.observation.evidence_digest += 1,
        |plan| plan.projection.fault_id += 1,
        |plan| plan.projection.generation += 1,
        |plan| {
            plan.projection.task = TaskKey::new(
                plan.projection.task.id() + 1,
                plan.projection.task.generation(),
            )
        },
        |plan| plan.projection.vm_generation += 1,
        |plan| plan.projection.disposition = FaultDisposition::IsolateTask,
        |plan| plan.projection.service_domain = DomainKey::new(SERVICE.value() + 1),
        |plan| plan.projection.closed_binding_epoch += 1,
        |plan| plan.projection.crash_generation += 1,
        |plan| plan.projection.evidence_digest += 1,
        |plan| plan.base_revision += 1,
        |plan| plan.next_binding_epoch += 1,
        |plan| plan.business.scope_revision += 1,
        |plan| plan.business.domain_revision += 1,
        |plan| plan.business.supervisor = Some(TaskKey::new(0xfd10, 1)),
        |plan| plan.business.fallback_running = !plan.business.fallback_running,
        |plan| plan.business.cohort_digest[0] ^= 1,
        |plan| plan.business.cohort_count += 1,
        |plan| plan.commitment.0[0] ^= 1,
    ];
    for mutate in mutations {
        let (mut state, _, armed, observation) = armed_fault_state(0xfc00);
        let (intent, mut plan) = state
            .prepare_fault_disposition(armed, observation, FaultDisposition::CrashService)
            .unwrap();
        mutate(&mut plan);
        let before = state.private_full_clone();
        let failure = state.install_fault_disposition(intent, plan).unwrap_err();
        __cser_core::assert!(__cser_core::matches!(
            failure.error(),
            InfrastructureError::InvalidReceipt
                | InfrastructureError::StaleClaim
                | InfrastructureError::UnknownDomain
                | InfrastructureError::StaleBinding
        ));
        __cser_core::assert_eq!(state, before);
        __cser_core::assert_eq!(
            service_key_coordinates(&failure.into_input().0),
            service_key_coordinates(&current_armed_fault(&state).0)
        );
    }
}

#[test]
fn fault_install_rejects_noncanonical_projection_with_matching_commitment() {
    type Mutate = fn(&mut super::FaultDispositionPlan);
    let mutations: &[Mutate] = &[
        |plan| plan.projection.fault_id += 1,
        |plan| plan.projection.generation += 1,
        |plan| {
            plan.projection.task = TaskKey::new(
                plan.projection.task.id() + 1,
                plan.projection.task.generation(),
            )
        },
        |plan| plan.projection.vm_generation += 1,
        |plan| plan.projection.service_domain = DomainKey::new(SERVICE.value() + 1),
        |plan| plan.projection.closed_binding_epoch += 1,
        |plan| plan.projection.evidence_digest += 1,
    ];
    for mutate in mutations {
        let (mut state, _, armed, observation) = armed_fault_state(0xfc10);
        let (mut intent, mut plan) = state
            .prepare_fault_disposition(armed, observation, FaultDisposition::CrashService)
            .unwrap();
        mutate(&mut plan);
        plan.commitment = super::fault::fault_plan_commitment(state.scope(SCOPE).unwrap(), plan);
        intent.commitment = plan.commitment.0;
        let before = state.private_full_clone();
        let failure = state.install_fault_disposition(intent, plan).unwrap_err();
        __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
        __cser_core::assert_eq!(state, before);
        __cser_core::assert_eq!(
            service_key_coordinates(&failure.into_input().0),
            service_key_coordinates(&current_armed_fault(&state).0)
        );
    }
}

#[test]
fn reserved_fault_adoption_is_composite_and_preflight_failure_is_atomic() {
    let mut state = InfrastructureState::new(0xfd00);
    state
        .enable(SCOPE, 1, ROOT, limits(), &[(SERVICE, 1)])
        .unwrap();
    let workload = state
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(SERVICE, 1, 0xfd01, 1),
        )
        .unwrap();
    let task_key = TaskKey::new(0xfd02, 1);
    let task = state
        .admit_task(
            &workload,
            TaskWorkDescriptor {
                work_id: 0xfd03,
                generation: 1,
                task: task_key,
                role: TaskWorkRole::ServiceRequest,
                vm: Some(VmAuthorityKey::new(0xfd04, 1).unwrap()),
            },
        )
        .unwrap();
    let stale_reserved = state
        .reserve_fault_event(
            task,
            FaultSlotDescriptor {
                fault_id: 0xfd05,
                generation: 1,
                task: task_key,
                vm_generation: 1,
                service_domain: SERVICE,
                admission_binding_epoch: 1,
            },
        )
        .unwrap();
    *state
        .scope_mut(SCOPE)
        .unwrap()
        .binding_epoch_mut(SERVICE)
        .unwrap() = 2;
    let workload = state
        .adopt_workload_after_fence(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(SERVICE, 2, 0xfd01, 1),
        )
        .unwrap();

    let mut corrupt = state.private_full_clone();
    let fault_nonce = corrupt
        .scope(SCOPE)
        .unwrap()
        .faults
        .get(0xfd05)
        .unwrap()
        .stamp
        .nonce;
    corrupt
        .scope_mut(SCOPE)
        .unwrap()
        .reverse_indexes
        .get_mut(fault_nonce)
        .unwrap()
        .kind = InfrastructureKind::Deadline;
    let before = corrupt.private_full_clone();
    __cser_core::assert_eq!(
        corrupt.adopt_task_after_fence(&workload, 0xfd03, 1),
        Err(InfrastructureError::Invariant(
            "invalid fault reverse index"
        ))
    );
    __cser_core::assert_eq!(corrupt, before);

    let adopted = state.adopt_task_after_fence(&workload, 0xfd03, 1).unwrap();
    let reserved = match adopted {
        TaskAdoption::FaultReserved(reserved) => reserved,
        _ => __cser_core::panic!("reserved task/fault composite adopted into the wrong state"),
    };
    __cser_core::assert_eq!(
        state
            .scope(SCOPE)
            .unwrap()
            .faults
            .get(0xfd05)
            .unwrap()
            .stamp
            .identity
            .admission_binding_epoch,
        2
    );
    let stale_failure = state.claim_service_task_entry(stale_reserved).unwrap_err();
    __cser_core::assert_eq!(stale_failure.error(), InfrastructureError::StaleGeneration);
    let armed = state.claim_service_task_entry(reserved).unwrap();
    __cser_core::assert_eq!(armed.0.bearer_generation, 4);
    state.check_invariants().unwrap();
}

fn fault_adoption_preflight_state(
    registry_instance: u64,
    armed: bool,
) -> (InfrastructureState, WorkloadContext) {
    let mut state = InfrastructureState::new(registry_instance);
    state
        .enable(SCOPE, 1, ROOT, limits(), &[(SERVICE, 1)])
        .unwrap();
    let workload = state
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(SERVICE, 1, 0xfd81, 1),
        )
        .unwrap();
    let task_key = TaskKey::new(0xfd82, 1);
    let task = state
        .admit_task(
            &workload,
            TaskWorkDescriptor {
                work_id: 0xfd83,
                generation: 1,
                task: task_key,
                role: TaskWorkRole::ServiceRequest,
                vm: Some(VmAuthorityKey::new(0xfd84, 1).unwrap()),
            },
        )
        .unwrap();
    let reserved = state
        .reserve_fault_event(
            task,
            FaultSlotDescriptor {
                fault_id: 0xfd85,
                generation: 1,
                task: task_key,
                vm_generation: 1,
                service_domain: SERVICE,
                admission_binding_epoch: 1,
            },
        )
        .unwrap();
    if armed {
        let _armed = state.claim_service_task_entry(reserved).unwrap();
    }
    *state
        .scope_mut(SCOPE)
        .unwrap()
        .binding_epoch_mut(SERVICE)
        .unwrap() = 2;
    let workload = state
        .adopt_workload_after_fence(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(SERVICE, 2, 0xfd81, 1),
        )
        .unwrap();
    (state, workload)
}

#[test]
fn fault_adoption_validates_every_task_and_fault_reverse_coordinate() {
    type Mutate = fn(&mut ReverseIndexRecord);
    let mutations: &[Mutate] = &[
        |index| index.slot += 1,
        |index| index.kind = InfrastructureKind::Deadline,
        |index| index.root_effect = EffectKey::new(ROOT.id() + 1, ROOT.generation()),
        |index| index.parent = ReverseParent::RootEffect(ROOT),
        |index| index.task = Some(TaskKey::new(0xfda0, 1)),
        |index| index.domain = GUEST,
        |index| index.binding_epoch += 1,
        |index| index.source_domain = Some(SERVICE),
        |index| index.source_binding_epoch = Some(1),
        |index| index.resource = Some(ResourceKey::new(0xfd, 1, 1)),
        |index| index.actor_slot = Some(1),
        |index| index.actor_generation = Some(1),
        |index| index.retry_generation += 1,
    ];
    let mut registry_instance = 0xfd90;
    for armed in [false, true] {
        for fault_row in [false, true] {
            for mutate in mutations {
                registry_instance += 1;
                let (mut state, workload) =
                    fault_adoption_preflight_state(registry_instance, armed);
                let slot = {
                    let scope = state.scope(SCOPE).unwrap();
                    if fault_row {
                        scope.faults.get(0xfd85).unwrap().stamp.nonce
                    } else {
                        scope.tasks.get(0xfd83).unwrap().stamp.nonce
                    }
                };
                mutate(
                    state
                        .scope_mut(SCOPE)
                        .unwrap()
                        .reverse_indexes
                        .get_mut(slot)
                        .unwrap(),
                );
                let before = state.private_full_clone();
                __cser_core::assert_eq!(
                    state.adopt_task_after_fence(&workload, 0xfd83, 1),
                    Err(InfrastructureError::Invariant(if fault_row {
                        "invalid fault reverse index"
                    } else {
                        "invalid task reverse index"
                    }))
                );
                __cser_core::assert_eq!(state, before);
            }
        }
    }

    for (instance, armed) in [(0xfde0, false), (0xfde1, true)] {
        let (mut state, workload) = fault_adoption_preflight_state(instance, armed);
        let adoption = state.adopt_task_after_fence(&workload, 0xfd83, 1).unwrap();
        __cser_core::assert!(__cser_core::matches!(
            (armed, adoption),
            (false, TaskAdoption::FaultReserved(_)) | (true, TaskAdoption::FaultArmed(_))
        ));
        state.check_invariants().unwrap();
    }
}

#[test]
fn terminal_fault_retains_deadline_then_drains_historical_task_anchor() {
    let (mut state, workload, armed, observation) = armed_fault_state(0xfd20);
    let deadline = state
        .arm_service_deadline(
            &armed,
            DeadlineDescriptor {
                series_id: 0xfd30,
                generation: 1,
                purpose: DeadlinePurpose::Recovery,
                clock: DeadlineClockBasis::ObservedCallbackTick,
                deadline_tick: 10,
                attempt: 1,
                max_attempts: 1,
                backoff_ticks: 1,
            },
        )
        .unwrap();
    let (intent, plan) = state
        .prepare_fault_disposition(armed, observation, FaultDisposition::CrashService)
        .unwrap();
    state.install_fault_disposition(intent, plan).unwrap();
    let retained = state.query_task(&workload, 0xfc30, 1).unwrap();
    __cser_core::assert_eq!(retained.live_children, 1);
    __cser_core::assert_eq!(retained.anchor, TaskAnchorRecoveryState::TerminalRetained);

    // Even a synchronously forged marker with the current compact coordinates
    // cannot turn a terminal historical anchor back into admission authority.
    let forged = current_armed_fault(&state);
    let before = state.private_full_clone();
    __cser_core::assert!(__cser_core::matches!(
        state.arm_service_deadline(
            &forged,
            DeadlineDescriptor {
                series_id: 0xfd31,
                generation: 1,
                purpose: DeadlinePurpose::Recovery,
                clock: DeadlineClockBasis::ObservedCallbackTick,
                deadline_tick: 20,
                attempt: 1,
                max_attempts: 1,
                backoff_ticks: 1,
            },
        ),
        Err(InfrastructureError::InvalidState | InfrastructureError::StaleBinding)
    ));
    __cser_core::assert_eq!(state, before);

    state.cancel_deadline(deadline).unwrap();
    let drained = state.query_task(&workload, 0xfc30, 1).unwrap();
    __cser_core::assert_eq!(drained.live_children, 0);
    __cser_core::assert_eq!(drained.anchor, TaskAnchorRecoveryState::TerminalDrained);
    state.check_invariants().unwrap();
}

#[test]
fn terminal_deadline_may_drain_armed_fire_but_cannot_rearm_or_supervisor_retry() {
    let (mut state, workload, armed, observation) = armed_fault_state(0xfd40);
    let fired_deadline = state
        .arm_service_deadline(
            &armed,
            DeadlineDescriptor {
                series_id: 0xfd41,
                generation: 1,
                purpose: DeadlinePurpose::Recovery,
                clock: DeadlineClockBasis::ObservedCallbackTick,
                deadline_tick: 10,
                attempt: 1,
                max_attempts: 2,
                backoff_ticks: 1,
            },
        )
        .unwrap();
    let exhausted_deadline = state
        .arm_service_deadline(
            &armed,
            DeadlineDescriptor {
                series_id: 0xfd42,
                generation: 1,
                purpose: DeadlinePurpose::Recovery,
                clock: DeadlineClockBasis::ObservedCallbackTick,
                deadline_tick: 10,
                attempt: 1,
                max_attempts: 1,
                backoff_ticks: 1,
            },
        )
        .unwrap();
    let (intent, plan) = state
        .prepare_fault_disposition(armed, observation, FaultDisposition::CrashService)
        .unwrap();
    state.install_fault_disposition(intent, plan).unwrap();

    let fired = state
        .fire_deadline(fired_deadline, DeadlineClockBasis::ObservedCallbackTick, 10)
        .unwrap();
    let fired_coordinates = deadline_expiry_coordinates(&fired);
    let before = state.private_full_clone();
    let failure = state.rearm_deadline(fired, 2, 11).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidState);
    __cser_core::assert_eq!(state, before);
    let fired = failure.into_input();
    __cser_core::assert_eq!(deadline_expiry_coordinates(&fired), fired_coordinates);
    state.resolve_fired_deadline(fired).unwrap();

    let exhausted = state
        .fire_deadline(
            exhausted_deadline,
            DeadlineClockBasis::ObservedCallbackTick,
            10,
        )
        .unwrap();
    let exhausted_coordinates = deadline_expiry_coordinates(&exhausted);
    let before = state.private_full_clone();
    let failure = state
        .reconcile_exhausted_deadline(
            exhausted,
            DeadlineReconciliationReceipt {
                disposition: DeadlineExhaustedDisposition::RetryBySupervisor,
                evidence_digest: 0xfd43,
            },
            Some(DeadlineSupervisorRetry {
                generation: 2,
                deadline_tick: 11,
                max_attempts: 1,
                backoff_ticks: 1,
            }),
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidState);
    __cser_core::assert_eq!(state, before);
    let exhausted = failure.into_input();
    __cser_core::assert_eq!(
        deadline_expiry_coordinates(&exhausted),
        exhausted_coordinates
    );
    __cser_core::assert!(__cser_core::matches!(
        state
            .reconcile_exhausted_deadline(
                exhausted,
                DeadlineReconciliationReceipt {
                    disposition: DeadlineExhaustedDisposition::AbortWork,
                    evidence_digest: 0xfd44,
                },
                None,
            )
            .unwrap(),
        DeadlineReconciliationOutcome::Aborted
    ));

    let drained = state.query_task(&workload, 0xfc30, 1).unwrap();
    __cser_core::assert_eq!(drained.live_children, 0);
    __cser_core::assert_eq!(drained.anchor, TaskAnchorRecoveryState::TerminalDrained);
    state.check_invariants().unwrap();
}

#[test]
fn delayed_compact_authority_is_bounded_and_every_transition_fences_its_input() {
    __cser_core::assert!(
        __cser_core::mem::size_of::<BearerKey<bearer_state::DelayedReserved>>() <= 64
    );
    __cser_core::assert!(__cser_core::mem::size_of::<DelayedCommandTicket>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<DelayedCommandIntent>() <= 96);
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<DelayedCommandTicket>>() <= 120);
    __cser_core::assert!(__cser_core::mem::size_of::<LinearFailure<DelayedCommandIntent>>() <= 120);

    let (mut state, ticket, descriptor) = compact_delayed_state(0xee40);
    let stale = current_delayed_ticket(&state);
    let reserved = delayed_key_coordinates(&ticket.0);
    let intent = state.begin_delayed_command_delivery(ticket).unwrap();
    let publishing = delayed_key_coordinates(&intent.0);
    __cser_core::assert_eq!(publishing.0, reserved.0);
    __cser_core::assert_eq!(publishing.1, reserved.1);
    __cser_core::assert_eq!(publishing.2, reserved.2);
    __cser_core::assert_eq!(publishing.3, reserved.3);
    __cser_core::assert_eq!(publishing.4, reserved.4);
    __cser_core::assert_eq!(publishing.5, reserved.5 + 1);
    __cser_core::assert_eq!(publishing.6, reserved.6);

    let before_stale = state.private_full_clone();
    let failure = state
        .reject_delayed_command(
            stale,
            delayed_rejection(
                descriptor,
                DelayedCommandRejectionReason::RequestAborted,
                0xee41,
            ),
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::StaleGeneration);
    __cser_core::assert_eq!(state, before_stale);
    __cser_core::assert_eq!(delayed_key_coordinates(&failure.into_input().0), reserved);

    state
        .acknowledge_delayed_command(intent, delayed_receipt(descriptor, 0xee42))
        .unwrap();
    let record = state
        .scope(SCOPE)
        .unwrap()
        .delayed_commands
        .get(COMPACT_DELAYED_COMMAND)
        .unwrap();
    __cser_core::assert_eq!(record.stamp.bearer_generation, publishing.5 + 1);
    __cser_core::assert!(__cser_core::matches!(
        record.phase,
        super::DelayedCommandPhase::Issued { .. }
    ));
    state.check_invariants().unwrap();

    let (mut state, ticket, descriptor) = compact_delayed_state(0xee43);
    let reserved = delayed_key_coordinates(&ticket.0);
    state
        .reject_delayed_command(
            ticket,
            delayed_rejection(
                descriptor,
                DelayedCommandRejectionReason::RequestAborted,
                0xee44,
            ),
        )
        .unwrap();
    let record = state
        .scope(SCOPE)
        .unwrap()
        .delayed_commands
        .get(COMPACT_DELAYED_COMMAND)
        .unwrap();
    __cser_core::assert_eq!(record.stamp.bearer_generation, reserved.5 + 1);
    __cser_core::assert!(__cser_core::matches!(
        record.phase,
        super::DelayedCommandPhase::Rejected { .. }
    ));
    state.check_invariants().unwrap();

    let (mut state, ticket, descriptor) = compact_delayed_state(0xee45);
    let intent = state.begin_delayed_command_delivery(ticket).unwrap();
    let publishing = delayed_key_coordinates(&intent.0);
    state
        .reject_delayed_command_intent(
            intent,
            delayed_rejection(
                descriptor,
                DelayedCommandRejectionReason::ClosureDrain,
                0xee46,
            ),
        )
        .unwrap();
    let record = state
        .scope(SCOPE)
        .unwrap()
        .delayed_commands
        .get(COMPACT_DELAYED_COMMAND)
        .unwrap();
    __cser_core::assert_eq!(record.stamp.bearer_generation, publishing.5 + 1);
    __cser_core::assert!(__cser_core::matches!(
        record.phase,
        super::DelayedCommandPhase::Rejected { .. }
    ));
    state.check_invariants().unwrap();
}

#[test]
fn delayed_compact_key_rejects_foreign_and_stale_coordinates_atomically() {
    let (mut owner, ticket, _) = compact_delayed_state(0xee50);
    let (mut foreign, _, _) = compact_delayed_state(0xee51);
    let presented = delayed_key_coordinates(&ticket.0);
    let before_owner = owner.private_full_clone();
    let before_foreign = foreign.private_full_clone();
    let failure = foreign.begin_delayed_command_delivery(ticket).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::ForeignRegistry);
    __cser_core::assert_eq!(owner, before_owner);
    __cser_core::assert_eq!(foreign, before_foreign);
    let ticket = failure.into_input();
    __cser_core::assert_eq!(delayed_key_coordinates(&ticket.0), presented);
    owner.begin_delayed_command_delivery(ticket).unwrap();

    let (mut owner, ticket, _) = compact_delayed_state(0xee52);
    let mut candidate = owner.try_scope_candidate(SCOPE).unwrap();
    let before_owner = owner.private_full_clone();
    let before_candidate = candidate.private_full_clone();
    let failure = candidate
        .begin_delayed_command_delivery(ticket)
        .unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        InfrastructureError::CandidateHasNoAuthority
    );
    __cser_core::assert_eq!(owner, before_owner);
    __cser_core::assert_eq!(candidate, before_candidate);
    owner
        .begin_delayed_command_delivery(failure.into_input())
        .unwrap();

    type Mutate = fn(&mut BearerKey<bearer_state::DelayedReserved>);
    let mutations: [(Mutate, InfrastructureError); 5] = [
        (
            |key| key.authority.scope = ScopeKey::new(SCOPE.id() + 1, SCOPE.generation()),
            InfrastructureError::NotEnabled,
        ),
        (
            |key| key.authority.authority_epoch += 1,
            InfrastructureError::StaleAuthority,
        ),
        (
            |key| key.object_generation += 1,
            InfrastructureError::StaleGeneration,
        ),
        (
            |key| key.bearer_generation += 1,
            InfrastructureError::StaleGeneration,
        ),
        (|key| key.nonce += 1, InfrastructureError::StaleGeneration),
    ];
    for (index, (mutate, expected)) in mutations.into_iter().enumerate() {
        let (mut state, mut ticket, _) = compact_delayed_state(0xee60 + index as u64);
        mutate(&mut ticket.0);
        let presented = delayed_key_coordinates(&ticket.0);
        let before = state.private_full_clone();
        let failure = state.begin_delayed_command_delivery(ticket).unwrap_err();
        __cser_core::assert_eq!(failure.error(), expected);
        __cser_core::assert_eq!(state, before);
        __cser_core::assert_eq!(delayed_key_coordinates(&failure.into_input().0), presented);
    }
}

#[test]
fn delayed_transition_revalidates_lineage_descriptor_and_exact_reverse_index() {
    assert_delayed_record_mutation_rejected(
        0xee70,
        |record| record.stamp.identity.actor_slot += 1,
        InfrastructureError::Invariant("delayed command reverse index mismatch"),
    );
    assert_delayed_record_mutation_rejected(
        0xee71,
        |record| {
            record.stamp.identity.target.effect = EffectKey::new(COMPACT_DELAYED_CLAIMANT + 5, 1);
        },
        InfrastructureError::InvalidState,
    );
    assert_delayed_record_mutation_rejected(
        0xee72,
        |record| record.stamp.identity.destination_domain = GUEST,
        InfrastructureError::InvalidState,
    );
    assert_delayed_record_mutation_rejected(
        0xee73,
        |record| record.stamp.identity.sender = TaskKey::new(COMPACT_DELAYED_CLAIMANT + 3, 1),
        InfrastructureError::InvalidState,
    );
    assert_delayed_record_mutation_rejected(
        0xee74,
        |record| record.stamp.identity.request_generation += 1,
        InfrastructureError::InvalidState,
    );
    assert_delayed_record_mutation_rejected(
        0xee75,
        |record| record.stamp.identity.target.nonce = 0,
        InfrastructureError::InvalidIdentity,
    );

    let (mut missing, ticket, _) = compact_delayed_state(0xee76);
    let nonce = ticket.0.nonce;
    missing
        .scope_mut(SCOPE)
        .unwrap()
        .reverse_indexes
        .remove(nonce)
        .unwrap();
    let before_missing = missing.private_full_clone();
    let failure = missing.begin_delayed_command_delivery(ticket).unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        InfrastructureError::Invariant("missing delayed command reverse index")
    );
    __cser_core::assert_eq!(missing, before_missing);

    let (mut mismatch, ticket, _) = compact_delayed_state(0xee77);
    mismatch
        .scope_mut(SCOPE)
        .unwrap()
        .reverse_indexes
        .get_mut(ticket.0.nonce)
        .unwrap()
        .actor_generation = Some(2);
    let before_mismatch = mismatch.private_full_clone();
    let failure = mismatch.begin_delayed_command_delivery(ticket).unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        InfrastructureError::Invariant("delayed command reverse index mismatch")
    );
    __cser_core::assert_eq!(mismatch, before_mismatch);
}

#[test]
fn delayed_receipt_and_publication_phase_substitution_return_the_intent_unchanged() {
    assert_delayed_ack_mutation_rejected(0xee80, |receipt| receipt.actor_slot += 1);
    assert_delayed_ack_mutation_rejected(0xee81, |receipt| receipt.actor_generation += 1);
    assert_delayed_ack_mutation_rejected(0xee82, |receipt| receipt.command_digest += 1);
    assert_delayed_ack_mutation_rejected(0xee83, |receipt| {
        receipt.transport_receipt_digest = 0;
    });

    let (mut state, ticket, descriptor) = compact_delayed_state(0xee84);
    let intent = state.begin_delayed_command_delivery(ticket).unwrap();
    let presented = delayed_key_coordinates(&intent.0);
    let phase = state
        .scope(SCOPE)
        .unwrap()
        .delayed_commands
        .get(COMPACT_DELAYED_COMMAND)
        .unwrap()
        .phase;
    let (apply_generation, apply_nonce) = match phase {
        super::DelayedCommandPhase::Publishing {
            apply_generation,
            apply_nonce,
        } => (apply_generation, apply_nonce),
        _ => __cser_core::unreachable!(),
    };
    state
        .scope_mut(SCOPE)
        .unwrap()
        .delayed_commands
        .get_mut(COMPACT_DELAYED_COMMAND)
        .unwrap()
        .phase = super::DelayedCommandPhase::Publishing {
        apply_generation: apply_generation + 1,
        apply_nonce,
    };
    let before = state.private_full_clone();
    let failure = state
        .acknowledge_delayed_command(intent, delayed_receipt(descriptor, 0xee85))
        .unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        InfrastructureError::Invariant("invalid delayed command publication phase")
    );
    __cser_core::assert_eq!(state, before);
    let intent = failure.into_input();
    __cser_core::assert_eq!(delayed_key_coordinates(&intent.0), presented);

    state
        .scope_mut(SCOPE)
        .unwrap()
        .delayed_commands
        .get_mut(COMPACT_DELAYED_COMMAND)
        .unwrap()
        .phase = super::DelayedCommandPhase::Publishing {
        apply_generation,
        apply_nonce: 0,
    };
    let before = state.private_full_clone();
    let failure = state
        .acknowledge_delayed_command(intent, delayed_receipt(descriptor, 0xee86))
        .unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        InfrastructureError::Invariant("invalid delayed command publication phase")
    );
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(delayed_key_coordinates(&failure.into_input().0), presented);
}

#[test]
fn delayed_rejection_validates_target_and_is_failure_atomic() {
    let (mut state, ticket, descriptor) = compact_delayed_state(0xee90);
    let presented = delayed_key_coordinates(&ticket.0);
    let mut rejection = delayed_rejection(
        descriptor,
        DelayedCommandRejectionReason::RequestAborted,
        0xee91,
    );
    rejection.target_effect = EffectKey::new(COMPACT_DELAYED_CLAIMANT + 5, 1);
    let before = state.private_full_clone();
    let failure = state.reject_delayed_command(ticket, rejection).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    __cser_core::assert_eq!(state, before);
    let ticket = failure.into_input();
    __cser_core::assert_eq!(delayed_key_coordinates(&ticket.0), presented);

    state.scope_mut(SCOPE).unwrap().revision = u64::MAX;
    let before_overflow = state.private_full_clone();
    let failure = state.begin_delayed_command_delivery(ticket).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::CounterOverflow);
    __cser_core::assert_eq!(state, before_overflow);
    __cser_core::assert_eq!(delayed_key_coordinates(&failure.into_input().0), presented);

    let (mut state, bound) = compact_child_bound_service_state(0xee92, COMPACT_DELAYED_CLAIMANT);
    let armed = ArmedFaultTask(super::mint_task_key::<bearer_state::TaskFaultArmed>(
        state
            .scope(SCOPE)
            .unwrap()
            .tasks
            .get(COMPACT_DELAYED_CLAIMANT + 1)
            .unwrap(),
    ));
    let occupied_nonce = state
        .scope(SCOPE)
        .unwrap()
        .service_requests
        .get(COMPACT_SERVICE_REQUEST)
        .unwrap()
        .stamp
        .nonce;
    state.scope_mut(SCOPE).unwrap().next_nonce = occupied_nonce;
    let before_collision = state.private_full_clone();
    __cser_core::assert_eq!(
        state
            .reserve_delayed_command(&armed, &bound, compact_delayed_descriptor())
            .unwrap_err(),
        InfrastructureError::IdentityConflict
    );
    __cser_core::assert_eq!(state, before_collision);
}

#[test]
fn authoritative_scope_install_fences_old_delayed_bearer_and_keeps_current_authority_live() {
    let (mut state, stale, descriptor) = compact_delayed_state(0xeea0);
    let stale_coordinates = delayed_key_coordinates(&stale.0);
    let base = state.root_binding(SCOPE).unwrap();
    let mut successor = state.private_full_clone();
    let current = successor
        .begin_delayed_command_delivery(current_delayed_ticket(&successor))
        .unwrap();
    let current_coordinates = delayed_key_coordinates(&current.0);
    let mut candidate = successor.try_scope_candidate(SCOPE).unwrap();
    let plan = state
        .prepare_exact_scope_install(SCOPE, base, &mut candidate)
        .unwrap();
    state.install_exact_scope(plan);
    state.check_invariants().unwrap();

    let before_stale = state.private_full_clone();
    let failure = state.begin_delayed_command_delivery(stale).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::StaleGeneration);
    __cser_core::assert_eq!(state, before_stale);
    __cser_core::assert_eq!(
        delayed_key_coordinates(&failure.into_input().0),
        stale_coordinates
    );
    __cser_core::assert_eq!(current_coordinates.5, stale_coordinates.5 + 1);
    state
        .acknowledge_delayed_command(current, delayed_receipt(descriptor, 0xeea1))
        .unwrap();
    state.check_invariants().unwrap();
}

#[test]
fn terminal_fault_preserves_service_and_delayed_children_until_each_drains() {
    const CLAIMANT: u64 = 0xfe00;
    let (mut state, bound) = compact_child_bound_service_state(0xfe10, CLAIMANT);
    let claimant_task = TaskKey::new(CLAIMANT + 2, 1);
    let context = super::workload_bearer(state.scope(SCOPE).unwrap(), CLAIMANT).unwrap();
    let armed = ArmedFaultTask(super::mint_task_key::<bearer_state::TaskFaultArmed>(
        state.scope(SCOPE).unwrap().tasks.get(CLAIMANT + 1).unwrap(),
    ));
    let target_effect = EffectKey::new(CLAIMANT + 4, 1);
    let delayed_descriptor = DelayedCommandDescriptor {
        command_id: 0xfe20,
        generation: 1,
        request_id: COMPACT_SERVICE_REQUEST,
        request_generation: 1,
        destination_domain: SERVICE,
        destination_binding_epoch: 1,
        sender: claimant_task,
        target: PortalHandle {
            scope: SCOPE,
            effect: target_effect,
            domain: SERVICE,
            authority_epoch: 1,
            binding_epoch: 1,
            nonce: 0xfe21,
        },
        command_digest: 0xfe22,
        actor_slot: 7,
        actor_generation: 1,
    };
    let delayed = state
        .reserve_delayed_command(&armed, &bound, delayed_descriptor)
        .unwrap();
    let (intent, plan) = state
        .prepare_fault_disposition(
            armed,
            FaultObservation {
                task: claimant_task,
                vm_generation: 1,
                instruction_pointer: 0xfe30,
                address: 0xfe31,
                access: FaultAccess::Read,
                architecture_error: 0xfe32,
                evidence_digest: 0xfe33,
            },
            FaultDisposition::CrashService,
        )
        .unwrap();
    state.install_fault_disposition(intent, plan).unwrap();
    let retained = state.query_task(&context, CLAIMANT + 1, 1).unwrap();
    __cser_core::assert_eq!(retained.live_children, 2);
    __cser_core::assert_eq!(retained.anchor, TaskAnchorRecoveryState::TerminalRetained);

    let delayed_coordinates = delayed_key_coordinates(&delayed.0);
    let before = state.private_full_clone();
    let failure = state.begin_delayed_command_delivery(delayed).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidState);
    __cser_core::assert_eq!(state, before);
    let delayed = failure.into_input();
    __cser_core::assert_eq!(delayed_key_coordinates(&delayed.0), delayed_coordinates);
    state
        .reject_delayed_command(
            delayed,
            DelayedCommandRejectionReceipt {
                reason: DelayedCommandRejectionReason::RequestAborted,
                target_effect,
                evidence_digest: 0xfe34,
            },
        )
        .unwrap();
    let retained = state.query_task(&context, CLAIMANT + 1, 1).unwrap();
    __cser_core::assert_eq!(retained.live_children, 1);
    __cser_core::assert_eq!(retained.anchor, TaskAnchorRecoveryState::TerminalRetained);

    let _outcome = state.complete_service_request(bound, 0xfe35).unwrap();
    let drained = state.query_task(&context, CLAIMANT + 1, 1).unwrap();
    __cser_core::assert_eq!(drained.live_children, 0);
    __cser_core::assert_eq!(drained.anchor, TaskAnchorRecoveryState::TerminalDrained);
    state.check_invariants().unwrap();
}

#[test]
fn terminal_reserved_bound_service_cannot_start_queue_publication_and_can_cancel() {
    let (mut state, ticket) = compact_bound_service_state(0xfe30);
    let parent = {
        let scope = state.scope(SCOPE).unwrap();
        let service = scope.service_requests.get(COMPACT_SERVICE_REQUEST).unwrap();
        let parent = match service.stamp.parent {
            super::ParentStamp::Task(parent) => parent,
            _ => __cser_core::unreachable!(),
        };
        EnteredTaskLease(super::mint_task_key::<bearer_state::TaskEntered>(
            scope.tasks.get(parent.work_id).unwrap(),
        ))
    };
    state.reap_task(parent).unwrap();
    let coordinates = service_bound_key_coordinates(&ticket.0);
    let before = state.private_full_clone();
    let failure = state.begin_service_enqueue(ticket).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidState);
    __cser_core::assert_eq!(state, before);
    let ticket = failure.into_input();
    __cser_core::assert_eq!(service_bound_key_coordinates(&ticket.0), coordinates);
    state
        .cancel_bound_service_request(ticket, ValidatedAbortProof::new(0xfe31))
        .unwrap();
    state.check_invariants().unwrap();
}

fn assert_reply_record_mutation_rejected(
    registry_instance: u64,
    mutate: impl FnOnce(&mut super::ReplyStateRecord),
    expected_error: InfrastructureError,
) {
    let (mut state, _, _, reply) = compact_reply_state(registry_instance);
    mutate(
        state
            .scope_mut(SCOPE)
            .unwrap()
            .replies
            .get_mut(COMPACT_REPLY)
            .unwrap(),
    );
    let presented = service_key_coordinates(&reply.0);
    let before = state.private_full_clone();
    let failure = state.claim_reply(reply).unwrap_err();
    __cser_core::assert_eq!(failure.error(), expected_error);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(service_key_coordinates(&failure.into_input().0), presented);
}

fn advance_reply_parent_after_fence(state: &mut InfrastructureState) -> WorkloadContext {
    *state
        .scope_mut(SCOPE)
        .unwrap()
        .binding_epoch_mut(GUEST)
        .unwrap() = 2;
    let workload = state
        .adopt_workload_after_fence(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 2, COMPACT_REQUEST, 1),
        )
        .unwrap();
    __cser_core::assert!(__cser_core::matches!(
        state
            .adopt_task_after_fence(&workload, COMPACT_WORK, 1)
            .unwrap(),
        TaskAdoption::Entered(_)
    ));
    workload
}

#[test]
fn reply_compact_authority_layout_and_successor_generations_are_bounded() {
    __cser_core::assert!(__cser_core::mem::size_of::<ReplyRecord>() <= 64);
    __cser_core::assert!(__cser_core::mem::size_of::<ReplyClaim>() <= 64);
    __cser_core::assert!(__cser_core::mem::size_of::<ReplyPublicationIntent>() <= 64);
    __cser_core::assert!(__cser_core::mem::size_of::<ReplyAckReceipt>() <= 64);
    __cser_core::assert!(__cser_core::mem::size_of::<ReplyAbortAuthority>() <= 96);
    __cser_core::assert!(
        __cser_core::mem::size_of::<LinearFailure<ReplyPublicationIntent>>() <= 120
    );

    let (mut state, _, _, reply) = compact_reply_state(0xfe36);
    __cser_core::assert_eq!(reply.0.bearer_generation, 1);
    let claim = state.claim_reply(reply).unwrap();
    __cser_core::assert_eq!(claim.0.bearer_generation, 2);
    let intent = state.begin_reply_publication(claim).unwrap();
    __cser_core::assert_eq!(intent.0.bearer_generation, 3);
    let ack = state
        .acknowledge_reply_publication(intent, compact_reply_publication_receipt())
        .unwrap();
    __cser_core::assert_eq!(ack.0.bearer_generation, 4);
    let completion = state.complete_reply_wake(ack).unwrap();
    __cser_core::assert_eq!(completion.reply_id, COMPACT_REPLY);
    __cser_core::assert_eq!(reply_bearer_generation(&state), 5);
    state.check_invariants().unwrap();

    let (mut state, _, _, reply) = compact_reply_state(0xfe37);
    state
        .cancel_reply(ReplyAbortAuthority::Prepared(reply), 0xfe38)
        .unwrap();
    __cser_core::assert_eq!(reply_bearer_generation(&state), 2);
    state.check_invariants().unwrap();

    let (mut state, _, _, reply) = compact_reply_state(0xfe39);
    let claim = state.claim_reply(reply).unwrap();
    state
        .cancel_reply(ReplyAbortAuthority::Claimed(claim), 0xfe3a)
        .unwrap();
    __cser_core::assert_eq!(reply_bearer_generation(&state), 3);
    state.check_invariants().unwrap();

    // A commit may legitimately describe the initial domain revision. It is
    // not a sentinel and must not be rejected by the compact Reply boundary.
    let (mut state, _, entered) = compact_task_state(0xfe3b);
    let mut proof = compact_reply_proof(0xfe3b);
    proof.receipt.domain_revision = 0;
    let reply = state
        .prepare_reply(&entered, compact_reply_descriptor(), proof)
        .unwrap();
    state
        .cancel_reply(ReplyAbortAuthority::Prepared(reply), 0xfe3c)
        .unwrap();
    state.check_invariants().unwrap();
}

#[test]
fn reply_compact_key_rejects_foreign_candidate_and_stale_coordinates_atomically() {
    let (mut owner, _, _, reply) = compact_reply_state(0xfe80);
    let (mut foreign, _, _, _) = compact_reply_state(0xfe81);
    let presented = service_key_coordinates(&reply.0);
    let before_owner = owner.private_full_clone();
    let before_foreign = foreign.private_full_clone();
    let failure = foreign.claim_reply(reply).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::ForeignRegistry);
    __cser_core::assert_eq!(owner, before_owner);
    __cser_core::assert_eq!(foreign, before_foreign);
    let reply = failure.into_input();
    __cser_core::assert_eq!(service_key_coordinates(&reply.0), presented);
    owner.claim_reply(reply).unwrap();

    let (mut owner, _, _, reply) = compact_reply_state(0xfe82);
    let mut candidate = owner.try_scope_candidate(SCOPE).unwrap();
    let before_owner = owner.private_full_clone();
    let before_candidate = candidate.private_full_clone();
    let failure = candidate.claim_reply(reply).unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        InfrastructureError::CandidateHasNoAuthority
    );
    __cser_core::assert_eq!(owner, before_owner);
    __cser_core::assert_eq!(candidate, before_candidate);
    owner.claim_reply(failure.into_input()).unwrap();

    type Mutate = fn(&mut BearerKey<bearer_state::ReplyPrepared>);
    let mutations: [(Mutate, InfrastructureError); 6] = [
        (
            |key| key.authority.scope = ScopeKey::new(SCOPE.id() + 1, SCOPE.generation()),
            InfrastructureError::NotEnabled,
        ),
        (
            |key| key.authority.authority_epoch += 1,
            InfrastructureError::StaleAuthority,
        ),
        (|key| key.slot += 1, InfrastructureError::UnknownObligation),
        (
            |key| key.object_generation += 1,
            InfrastructureError::StaleGeneration,
        ),
        (
            |key| key.bearer_generation += 1,
            InfrastructureError::StaleGeneration,
        ),
        (|key| key.nonce += 1, InfrastructureError::StaleGeneration),
    ];
    for (offset, (mutate, expected)) in mutations.into_iter().enumerate() {
        let (mut state, _, _, mut reply) = compact_reply_state(0xfe90 + offset as u64);
        mutate(&mut reply.0);
        let presented = service_key_coordinates(&reply.0);
        let before = state.private_full_clone();
        let failure = state.claim_reply(reply).unwrap_err();
        __cser_core::assert_eq!(failure.error(), expected);
        __cser_core::assert_eq!(state, before);
        __cser_core::assert_eq!(service_key_coordinates(&failure.into_input().0), presented);
    }
}

#[test]
fn reply_transition_revalidates_record_backend_payload_and_exact_reverse_index() {
    assert_reply_record_mutation_rejected(
        0xfe9c,
        |record| record.stamp.root.registry_instance ^= 1,
        InfrastructureError::ForeignRegistry,
    );
    assert_reply_record_mutation_rejected(
        0xfe9d,
        |record| record.stamp.root.scope = ScopeKey::new(SCOPE.id() + 1, SCOPE.generation()),
        InfrastructureError::ForeignScope,
    );
    assert_reply_record_mutation_rejected(
        0xfe9e,
        |record| record.stamp.root.authority_epoch += 1,
        InfrastructureError::StaleAuthority,
    );
    assert_reply_record_mutation_rejected(
        0xfe9f,
        |record| record.stamp.domain.binding_epoch += 1,
        InfrastructureError::StaleBinding,
    );
    assert_reply_record_mutation_rejected(
        0xfea0,
        |record| record.stamp.root.root_effect = EffectKey::new(ROOT.id() + 1, 1),
        InfrastructureError::ForeignRootEffect,
    );
    assert_reply_record_mutation_rejected(
        0xfea1,
        |record| record.stamp.workload.request.id += 1,
        InfrastructureError::UnknownWorkload,
    );
    assert_reply_record_mutation_rejected(
        0xfea2,
        |record| {
            record.stamp.parent = super::ParentStamp::Task(TaskWorkDescriptor {
                work_id: COMPACT_WORK + 1,
                ..match record.stamp.parent {
                    super::ParentStamp::Task(parent) => parent,
                    _ => __cser_core::unreachable!(),
                }
            })
        },
        InfrastructureError::UnknownObligation,
    );
    assert_reply_record_mutation_rejected(
        0xfea3,
        |record| record.stamp.identity.guest_vm_generation += 1,
        InfrastructureError::ForeignParent,
    );
    assert_reply_record_mutation_rejected(
        0xfea4,
        |record| record.stamp.identity.source_binding_epoch += 1,
        InfrastructureError::StaleBinding,
    );
    assert_reply_record_mutation_rejected(
        0xfeab,
        |record| record.stamp.identity.source_domain = SERVICE,
        InfrastructureError::Invariant("reply reverse index mismatch"),
    );
    assert_reply_record_mutation_rejected(
        0xfeac,
        |record| record.backend_commit.registry_instance_id ^= 1,
        InfrastructureError::InvalidReceipt,
    );
    assert_reply_record_mutation_rejected(
        0xfead,
        |record| record.backend_commit.scope = ScopeKey::new(SCOPE.id() + 1, 1),
        InfrastructureError::InvalidReceipt,
    );
    assert_reply_record_mutation_rejected(
        0xfeae,
        |record| record.backend_commit.authority_epoch += 1,
        InfrastructureError::InvalidReceipt,
    );
    assert_reply_record_mutation_rejected(
        0xfeaf,
        |record| record.backend_commit.effect = EffectKey::new(COMPACT_REPLY_EFFECT, 0),
        InfrastructureError::InvalidReceipt,
    );
    assert_reply_record_mutation_rejected(
        0xfea5,
        |record| record.backend_commit.sequence = 0,
        InfrastructureError::InvalidReceipt,
    );
    assert_reply_record_mutation_rejected(
        0xfea6,
        |record| record.backend_commit.binding_epoch = 0,
        InfrastructureError::InvalidReceipt,
    );
    assert_reply_record_mutation_rejected(
        0xfea7,
        |record| record.stamp.identity.payload_slot += 1,
        InfrastructureError::Invariant("reply reverse index mismatch"),
    );
    assert_reply_record_mutation_rejected(
        0xfea8,
        |record| record.stamp.identity.result_digest = 0,
        InfrastructureError::InvalidIdentity,
    );

    let (mut role_state, workload, _, reply) = compact_reply_state(0xfebf);
    let supervisor_task = TaskWorkDescriptor {
        work_id: COMPACT_WORK + 1,
        generation: 1,
        task: TaskKey::new(COMPACT_TASK + 1, 1),
        role: TaskWorkRole::SupervisorControl,
        vm: Some(VmAuthorityKey::new(COMPACT_VM + 1, 1).unwrap()),
    };
    let supervisor = role_state.admit_task(&workload, supervisor_task).unwrap();
    role_state.claim_task_entry(supervisor).unwrap();
    let reply_nonce = reply.0.nonce;
    let record = role_state
        .scope_mut(SCOPE)
        .unwrap()
        .replies
        .get_mut(COMPACT_REPLY)
        .unwrap();
    record.stamp.parent = super::ParentStamp::Task(supervisor_task);
    record.stamp.identity.guest_task = supervisor_task.task;
    let index = role_state
        .scope_mut(SCOPE)
        .unwrap()
        .reverse_indexes
        .get_mut(reply_nonce)
        .unwrap();
    index.parent = ReverseParent::Task(supervisor_task);
    index.task = Some(supervisor_task.task);
    let before = role_state.private_full_clone();
    let failure = role_state.claim_reply(reply).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::ForeignParent);
    __cser_core::assert_eq!(role_state, before);

    let (mut missing, _, _, reply) = compact_reply_state(0xfea9);
    let index_slot = reply.0.nonce;
    missing
        .scope_mut(SCOPE)
        .unwrap()
        .reverse_indexes
        .remove(index_slot)
        .unwrap();
    let before = missing.private_full_clone();
    let failure = missing.claim_reply(reply).unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        InfrastructureError::Invariant("missing reply reverse index")
    );
    __cser_core::assert_eq!(missing, before);

    let (mut mismatch, _, _, reply) = compact_reply_state(0xfeaa);
    mismatch
        .scope_mut(SCOPE)
        .unwrap()
        .reverse_indexes
        .get_mut(reply.0.nonce)
        .unwrap()
        .actor_generation = Some(2);
    let before = mismatch.private_full_clone();
    let failure = mismatch.claim_reply(reply).unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        InfrastructureError::Invariant("reply reverse index mismatch")
    );
    __cser_core::assert_eq!(mismatch, before);
}

#[test]
fn reply_phase_typestate_and_receipt_substitution_return_exact_authority() {
    let (mut state, _, _, reply) = compact_reply_state(0xfeb0);
    let forged = ReplyClaim(BearerKey {
        authority: AuthorityKey {
            registry_instance: reply.0.authority.registry_instance,
            scope: reply.0.authority.scope,
            authority_epoch: reply.0.authority.authority_epoch,
        },
        slot: reply.0.slot,
        object_generation: reply.0.object_generation,
        bearer_generation: reply.0.bearer_generation,
        nonce: reply.0.nonce,
        state: __cser_core::marker::PhantomData,
    });
    let presented = service_key_coordinates(&forged.0);
    let before = state.private_full_clone();
    let failure = state.begin_reply_publication(forged).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::StaleClaim);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(service_key_coordinates(&failure.into_input().0), presented);

    let (mut state, _, _, reply) = compact_reply_state(0xfeb1);
    let claim = state.claim_reply(reply).unwrap();
    let phase = state
        .scope(SCOPE)
        .unwrap()
        .replies
        .get(COMPACT_REPLY)
        .unwrap()
        .phase;
    let (claim_generation, claim_nonce) = match phase {
        super::ReplyPhase::Claimed {
            claim_generation,
            claim_nonce,
        } => (claim_generation, claim_nonce),
        _ => __cser_core::unreachable!(),
    };
    state
        .scope_mut(SCOPE)
        .unwrap()
        .replies
        .get_mut(COMPACT_REPLY)
        .unwrap()
        .phase = super::ReplyPhase::Claimed {
        claim_generation: claim_generation + 1,
        claim_nonce,
    };
    let presented = service_key_coordinates(&claim.0);
    let before = state.private_full_clone();
    let failure = state.begin_reply_publication(claim).unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        InfrastructureError::Invariant("reply claim mismatch")
    );
    __cser_core::assert_eq!(state, before);
    let claim = failure.into_input();
    __cser_core::assert_eq!(service_key_coordinates(&claim.0), presented);
    state
        .scope_mut(SCOPE)
        .unwrap()
        .replies
        .get_mut(COMPACT_REPLY)
        .unwrap()
        .phase = super::ReplyPhase::Claimed {
        claim_generation,
        claim_nonce: 0,
    };
    let before = state.private_full_clone();
    let failure = state.begin_reply_publication(claim).unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        InfrastructureError::Invariant("reply claim mismatch")
    );
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(service_key_coordinates(&failure.into_input().0), presented);

    type MutateReceipt = fn(&mut ReplyPublicationReceipt);
    let mutations: [MutateReceipt; 10] = [
        |receipt| receipt.payload_slot += 1,
        |receipt| receipt.payload_generation += 1,
        |receipt| receipt.flight_cookie += 1,
        |receipt| receipt.descriptor_digest += 1,
        |receipt| receipt.result_digest += 1,
        |receipt| receipt.byte_count += 1,
        |receipt| receipt.destination_digest += 1,
        |receipt| receipt.backend_effect = EffectKey::new(COMPACT_REPLY_EFFECT + 1, 1),
        |receipt| receipt.backend_commit_sequence += 1,
        |receipt| receipt.external_apply_digest = 0,
    ];
    for (offset, mutate) in mutations.into_iter().enumerate() {
        let (mut state, _, _, reply) = compact_reply_state(0xfec0 + offset as u64);
        let claim = state.claim_reply(reply).unwrap();
        let intent = state.begin_reply_publication(claim).unwrap();
        let presented = service_key_coordinates(&intent.0);
        let mut receipt = compact_reply_publication_receipt();
        mutate(&mut receipt);
        let before = state.private_full_clone();
        let failure = state
            .acknowledge_reply_publication(intent, receipt)
            .unwrap_err();
        __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
        __cser_core::assert_eq!(state, before);
        __cser_core::assert_eq!(service_key_coordinates(&failure.into_input().0), presented);
    }
}

#[test]
fn reply_overflow_collision_and_terminal_preflight_are_failure_atomic() {
    let (mut state, _, _, reply) = compact_reply_state(0xfed0);
    let presented = service_key_coordinates(&reply.0);
    state.scope_mut(SCOPE).unwrap().revision = u64::MAX;
    let before = state.private_full_clone();
    let failure = state.claim_reply(reply).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::CounterOverflow);
    __cser_core::assert_eq!(state, before);
    __cser_core::assert_eq!(service_key_coordinates(&failure.into_input().0), presented);

    let (mut state, _, entered) = compact_task_state(0xfed1);
    let occupied_nonce = state
        .scope(SCOPE)
        .unwrap()
        .reverse_indexes
        .iter()
        .next()
        .unwrap()
        .slot;
    state.scope_mut(SCOPE).unwrap().next_nonce = occupied_nonce;
    let proof = compact_reply_proof(0xfed1);
    let expected = proof.receipt.clone();
    let before = state.private_full_clone();
    let failure = state
        .prepare_reply(&entered, compact_reply_descriptor(), proof)
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::IdentityConflict);
    __cser_core::assert_eq!(failure.into_input().receipt, expected);
    __cser_core::assert_eq!(state, before);

    let (mut state, _, _, reply) = compact_reply_state(0xfed2);
    state.scope_mut(SCOPE).unwrap().live.replies = 0;
    let presented = service_key_coordinates(&reply.0);
    let before = state.private_full_clone();
    let failure = state
        .cancel_reply(ReplyAbortAuthority::Prepared(reply), 0xfed3)
        .unwrap_err();
    __cser_core::assert_eq!(
        failure.error(),
        InfrastructureError::Invariant("live counter underflow")
    );
    __cser_core::assert_eq!(state, before);
    let returned = match failure.into_input() {
        ReplyAbortAuthority::Prepared(reply) => reply,
        ReplyAbortAuthority::Claimed(_) => __cser_core::unreachable!(),
    };
    __cser_core::assert_eq!(service_key_coordinates(&returned.0), presented);
}

#[test]
fn reply_adoption_fences_every_live_phase_and_preflights_reverse_index() {
    let (mut state, _, _, stale) = compact_reply_state(0xfee0);
    let workload = advance_reply_parent_after_fence(&mut state);
    let before = state.private_full_clone();
    __cser_core::assert_eq!(
        state
            .adopt_reply_after_fence(&workload, COMPACT_REPLY, 2, 2)
            .unwrap_err(),
        InfrastructureError::StaleGeneration
    );
    __cser_core::assert_eq!(state, before);

    let mut zero_bearer = state.private_full_clone();
    zero_bearer
        .scope_mut(SCOPE)
        .unwrap()
        .replies
        .get_mut(COMPACT_REPLY)
        .unwrap()
        .stamp
        .bearer_generation = 0;
    let before = zero_bearer.private_full_clone();
    __cser_core::assert_eq!(
        zero_bearer
            .adopt_reply_after_fence(&workload, COMPACT_REPLY, 1, 2)
            .unwrap_err(),
        InfrastructureError::InvalidIdentity
    );
    __cser_core::assert_eq!(zero_bearer, before);

    let mut wrong_nonce = state.private_full_clone();
    wrong_nonce
        .scope_mut(SCOPE)
        .unwrap()
        .replies
        .get_mut(COMPACT_REPLY)
        .unwrap()
        .stamp
        .workload
        .nonce += 1;
    let before = wrong_nonce.private_full_clone();
    __cser_core::assert_eq!(
        wrong_nonce
            .adopt_reply_after_fence(&workload, COMPACT_REPLY, 1, 2)
            .unwrap_err(),
        InfrastructureError::ForeignWorkload
    );
    __cser_core::assert_eq!(wrong_nonce, before);

    let mut future_workload = state.private_full_clone();
    future_workload
        .scope_mut(SCOPE)
        .unwrap()
        .replies
        .get_mut(COMPACT_REPLY)
        .unwrap()
        .stamp
        .workload
        .bearer_generation = workload.workload.bearer_generation + 1;
    let before = future_workload.private_full_clone();
    __cser_core::assert_eq!(
        future_workload
            .adopt_reply_after_fence(&workload, COMPACT_REPLY, 1, 2)
            .unwrap_err(),
        InfrastructureError::StaleGeneration
    );
    __cser_core::assert_eq!(future_workload, before);
    let mut missing = state.private_full_clone();
    let index_slot = missing
        .scope(SCOPE)
        .unwrap()
        .replies
        .get(COMPACT_REPLY)
        .unwrap()
        .stamp
        .nonce;
    missing
        .scope_mut(SCOPE)
        .unwrap()
        .reverse_indexes
        .remove(index_slot)
        .unwrap();
    let before = missing.private_full_clone();
    __cser_core::assert_eq!(
        missing
            .adopt_reply_after_fence(&workload, COMPACT_REPLY, 1, 2)
            .unwrap_err(),
        InfrastructureError::Invariant("missing reply reverse index")
    );
    __cser_core::assert_eq!(missing, before);

    let mut mismatch = state.private_full_clone();
    mismatch
        .scope_mut(SCOPE)
        .unwrap()
        .reverse_indexes
        .get_mut(index_slot)
        .unwrap()
        .source_binding_epoch = Some(2);
    let before = mismatch.private_full_clone();
    __cser_core::assert_eq!(
        mismatch
            .adopt_reply_after_fence(&workload, COMPACT_REPLY, 1, 2)
            .unwrap_err(),
        InfrastructureError::Invariant("reply reverse index mismatch")
    );
    __cser_core::assert_eq!(mismatch, before);

    let mut overflow = state.private_full_clone();
    overflow
        .scope_mut(SCOPE)
        .unwrap()
        .replies
        .get_mut(COMPACT_REPLY)
        .unwrap()
        .stamp
        .bearer_generation = u64::MAX;
    let before = overflow.private_full_clone();
    __cser_core::assert_eq!(
        overflow
            .adopt_reply_after_fence(&workload, COMPACT_REPLY, 1, 2)
            .unwrap_err(),
        InfrastructureError::CounterOverflow
    );
    __cser_core::assert_eq!(overflow, before);

    let current = match state
        .adopt_reply_after_fence(&workload, COMPACT_REPLY, 1, 2)
        .unwrap()
    {
        ReplyAdoption::Prepared(reply) => reply,
        _ => __cser_core::panic!("prepared reply adopted into wrong phase"),
    };
    __cser_core::assert_eq!(reply_bearer_generation(&state), 2);
    let before = state.private_full_clone();
    let failure = state.claim_reply(stale).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::StaleGeneration);
    __cser_core::assert_eq!(state, before);
    state.claim_reply(current).unwrap();
    state.check_invariants().unwrap();

    let (mut state, _, _, reply) = compact_reply_state(0xfee1);
    let stale = state.claim_reply(reply).unwrap();
    let workload = advance_reply_parent_after_fence(&mut state);
    let current = match state
        .adopt_reply_after_fence(&workload, COMPACT_REPLY, 1, 2)
        .unwrap()
    {
        ReplyAdoption::Claimed(claim) => claim,
        _ => __cser_core::panic!("claimed reply adopted into wrong phase"),
    };
    let before = state.private_full_clone();
    let failure = state.begin_reply_publication(stale).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::StaleGeneration);
    __cser_core::assert_eq!(state, before);
    state.begin_reply_publication(current).unwrap();
    state.check_invariants().unwrap();

    let (mut state, _, _, reply) = compact_reply_state(0xfee2);
    let claim = state.claim_reply(reply).unwrap();
    let stale = state.begin_reply_publication(claim).unwrap();
    let workload = advance_reply_parent_after_fence(&mut state);
    let current = match state
        .adopt_reply_after_fence(&workload, COMPACT_REPLY, 1, 2)
        .unwrap()
    {
        ReplyAdoption::ReplayPublication(intent) => intent,
        _ => __cser_core::panic!("publishing reply adopted into wrong phase"),
    };
    let before = state.private_full_clone();
    let failure = state
        .acknowledge_reply_publication(stale, compact_reply_publication_receipt())
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::StaleGeneration);
    __cser_core::assert_eq!(state, before);
    state
        .acknowledge_reply_publication(current, compact_reply_publication_receipt())
        .unwrap();
    state.check_invariants().unwrap();

    let (mut state, _, _, reply) = compact_reply_state(0xfee3);
    let claim = state.claim_reply(reply).unwrap();
    let intent = state.begin_reply_publication(claim).unwrap();
    let publication = compact_reply_publication_receipt();
    let stale = state
        .acknowledge_reply_publication(intent, publication)
        .unwrap();
    let workload = advance_reply_parent_after_fence(&mut state);
    let current = match state
        .adopt_reply_after_fence(&workload, COMPACT_REPLY, 1, 2)
        .unwrap()
    {
        ReplyAdoption::Acknowledged(ack) => ack,
        _ => __cser_core::panic!("acknowledged reply adopted into wrong phase"),
    };
    __cser_core::assert_eq!(
        state
            .query_reply(&workload, COMPACT_REPLY, 1)
            .unwrap()
            .publication_receipt,
        Some(publication)
    );
    let before = state.private_full_clone();
    let failure = state.complete_reply_wake(stale).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::StaleGeneration);
    __cser_core::assert_eq!(state, before);
    state.complete_reply_wake(current).unwrap();
    state.check_invariants().unwrap();
}

#[test]
fn normal_task_exit_retains_continuation_and_reply_until_both_drain() {
    const REGISTRY: u64 = 0xfe40;
    let (mut state, workload, entered) = compact_task_state(REGISTRY);
    let continuation = state
        .create_continuation(
            &entered,
            ContinuationDescriptor {
                continuation_id: 0xfe41,
                generation: 1,
                vm_generation: 1,
                source_domain: GUEST,
                source_binding_epoch: 1,
            },
        )
        .unwrap();
    let reply = state
        .prepare_reply(
            &entered,
            ReplyDescriptor {
                reply_id: 0xfe42,
                generation: 1,
                guest_task: TaskKey::new(COMPACT_TASK, 1),
                guest_vm_generation: 1,
                descriptor_digest: 0xfe43,
                result_digest: 0xfe44,
                byte_count: 8,
                destination_digest: 0xfe45,
                source_domain: GUEST,
                source_binding_epoch: 1,
                payload_slot: 3,
                payload_generation: 1,
                flight_cookie: 0xfe46,
            },
            ValidatedCommitProof::new(super::super::CommitReceipt {
                registry_instance_id: REGISTRY,
                effect: EffectKey::new(0xfe47, 1),
                scope: SCOPE,
                authority_epoch: 1,
                binding_epoch: 1,
                sequence: 1,
                result: 0,
                domain_revision: 1,
                descriptor_digest: 0xfe48,
            }),
        )
        .unwrap();

    state.reap_task(entered).unwrap();
    let retained = state.query_task(&workload, COMPACT_WORK, 1).unwrap();
    __cser_core::assert_eq!(retained.live_children, 2);
    __cser_core::assert_eq!(retained.anchor, TaskAnchorRecoveryState::TerminalRetained);

    let continuation_coordinates = service_key_coordinates(&continuation.0);
    let before = state.private_full_clone();
    let failure = state.claim_continuation(continuation, 0xfe4a).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidState);
    __cser_core::assert_eq!(state, before);
    let continuation = failure.into_input();
    __cser_core::assert_eq!(
        service_key_coordinates(&continuation.0),
        continuation_coordinates
    );
    state.cancel_continuation(continuation).unwrap();
    let retained = state.query_task(&workload, COMPACT_WORK, 1).unwrap();
    __cser_core::assert_eq!(retained.live_children, 1);
    __cser_core::assert_eq!(retained.anchor, TaskAnchorRecoveryState::TerminalRetained);

    let reply_coordinates = service_key_coordinates(&reply.0);
    let before = state.private_full_clone();
    let failure = state.claim_reply(reply).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidState);
    __cser_core::assert_eq!(state, before);
    let reply = failure.into_input();
    __cser_core::assert_eq!(service_key_coordinates(&reply.0), reply_coordinates);
    state
        .cancel_reply(ReplyAbortAuthority::Prepared(reply), 0xfe49)
        .unwrap();
    let drained = state.query_task(&workload, COMPACT_WORK, 1).unwrap();
    __cser_core::assert_eq!(drained.live_children, 0);
    __cser_core::assert_eq!(drained.anchor, TaskAnchorRecoveryState::TerminalDrained);
    state.check_invariants().unwrap();
}

#[test]
fn terminal_claimed_continuation_and_reply_can_only_cancel_before_publication() {
    const REGISTRY: u64 = 0xfe60;
    let (mut state, workload, entered) = compact_task_state(REGISTRY);
    let continuation = state
        .create_continuation(
            &entered,
            ContinuationDescriptor {
                continuation_id: 0xfe61,
                generation: 1,
                vm_generation: 1,
                source_domain: GUEST,
                source_binding_epoch: 1,
            },
        )
        .unwrap();
    let claim = state.claim_continuation(continuation, 0xfe62).unwrap();
    let reply = state
        .prepare_reply(
            &entered,
            ReplyDescriptor {
                reply_id: 0xfe63,
                generation: 1,
                guest_task: TaskKey::new(COMPACT_TASK, 1),
                guest_vm_generation: 1,
                descriptor_digest: 0xfe64,
                result_digest: 0xfe65,
                byte_count: 8,
                destination_digest: 0xfe66,
                source_domain: GUEST,
                source_binding_epoch: 1,
                payload_slot: 3,
                payload_generation: 1,
                flight_cookie: 0xfe67,
            },
            ValidatedCommitProof::new(super::super::CommitReceipt {
                registry_instance_id: REGISTRY,
                effect: EffectKey::new(0xfe68, 1),
                scope: SCOPE,
                authority_epoch: 1,
                binding_epoch: 1,
                sequence: 1,
                result: 0,
                domain_revision: 1,
                descriptor_digest: 0xfe69,
            }),
        )
        .unwrap();
    let reply_claim = state.claim_reply(reply).unwrap();
    state.reap_task(entered).unwrap();

    let claim_coordinates = service_key_coordinates(&claim.0);
    let before = state.private_full_clone();
    let failure = state
        .begin_continuation_publication(
            claim,
            ContinuationPublicationReceipt {
                vm_generation: 1,
                source_domain: GUEST,
                source_binding_epoch: 1,
                outcome_digest: 0xfe62,
            },
        )
        .unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidState);
    __cser_core::assert_eq!(state, before);
    let claim = failure.into_input();
    __cser_core::assert_eq!(service_key_coordinates(&claim.0), claim_coordinates);
    state.cancel_claimed_continuation(claim).unwrap();

    let reply_claim_coordinates = service_key_coordinates(&reply_claim.0);
    let before = state.private_full_clone();
    let failure = state.begin_reply_publication(reply_claim).unwrap_err();
    __cser_core::assert_eq!(failure.error(), InfrastructureError::InvalidState);
    __cser_core::assert_eq!(state, before);
    let reply_claim = failure.into_input();
    __cser_core::assert_eq!(
        service_key_coordinates(&reply_claim.0),
        reply_claim_coordinates
    );
    state
        .cancel_reply(ReplyAbortAuthority::Claimed(reply_claim), 0xfe6a)
        .unwrap();

    let drained = state.query_task(&workload, COMPACT_WORK, 1).unwrap();
    __cser_core::assert_eq!(drained.live_children, 0);
    __cser_core::assert_eq!(drained.anchor, TaskAnchorRecoveryState::TerminalDrained);
    state.check_invariants().unwrap();
}

#[test]
fn terminal_publication_uncertainty_can_reconcile_and_committed_work_can_drain() {
    const REGISTRY: u64 = 0xfe70;
    let (mut state, workload, entered) = compact_task_state(REGISTRY);
    let continuation = state
        .create_continuation(
            &entered,
            ContinuationDescriptor {
                continuation_id: 0xfe71,
                generation: 1,
                vm_generation: 1,
                source_domain: GUEST,
                source_binding_epoch: 1,
            },
        )
        .unwrap();
    let claim = state.claim_continuation(continuation, 0xfe72).unwrap();
    let publication = state
        .begin_continuation_publication(
            claim,
            ContinuationPublicationReceipt {
                vm_generation: 1,
                source_domain: GUEST,
                source_binding_epoch: 1,
                outcome_digest: 0xfe72,
            },
        )
        .unwrap();
    let continuation_plan = publication.plan();
    let continuation_authority = publication.into_authority();

    let backend_effect = EffectKey::new(0xfe73, 1);
    let reply = state
        .prepare_reply(
            &entered,
            ReplyDescriptor {
                reply_id: 0xfe74,
                generation: 1,
                guest_task: TaskKey::new(COMPACT_TASK, 1),
                guest_vm_generation: 1,
                descriptor_digest: 0xfe75,
                result_digest: 0xfe76,
                byte_count: 8,
                destination_digest: 0xfe77,
                source_domain: GUEST,
                source_binding_epoch: 1,
                payload_slot: 3,
                payload_generation: 1,
                flight_cookie: 0xfe78,
            },
            ValidatedCommitProof::new(super::super::CommitReceipt {
                registry_instance_id: REGISTRY,
                effect: backend_effect,
                scope: SCOPE,
                authority_epoch: 1,
                binding_epoch: 1,
                sequence: 7,
                result: 0,
                domain_revision: 1,
                descriptor_digest: 0xfe79,
            }),
        )
        .unwrap();
    let reply_claim = state.claim_reply(reply).unwrap();
    let reply_publication = state.begin_reply_publication(reply_claim).unwrap();
    state.reap_task(entered).unwrap();

    let acknowledgement = ContinuationPublicationAckReceipt {
        continuation_id: continuation_plan.descriptor.continuation_id,
        generation: continuation_plan.descriptor.generation,
        claim_generation: continuation_plan.claim_generation,
        claim_nonce: continuation_plan.claim_nonce,
        apply_generation: continuation_plan.apply_generation,
        apply_nonce: continuation_plan.apply_nonce,
        publication_sequence: continuation_plan.publication_sequence,
        vm_generation: continuation_plan.descriptor.vm_generation,
        source_domain: continuation_plan.descriptor.source_domain,
        source_binding_epoch: continuation_plan.descriptor.source_binding_epoch,
        outcome_digest: continuation_plan.receipt.outcome_digest,
        external_receipt_digest: 0xfe7a,
    };
    let ack = state
        .acknowledge_continuation_publication(continuation_authority, acknowledgement)
        .unwrap();
    let resume = state.begin_continuation_resume(ack).unwrap();
    let resume_plan = resume.plan();
    state
        .complete_continuation_resume(
            resume.into_authority(),
            continuation_resume_receipt(resume_plan, 0xfe7b),
        )
        .unwrap();

    let reply_ack = state
        .acknowledge_reply_publication(
            reply_publication,
            ReplyPublicationReceipt {
                payload_slot: 3,
                payload_generation: 1,
                flight_cookie: 0xfe78,
                descriptor_digest: 0xfe75,
                result_digest: 0xfe76,
                byte_count: 8,
                destination_digest: 0xfe77,
                backend_effect,
                backend_commit_sequence: 7,
                external_apply_digest: 0xfe7c,
            },
        )
        .unwrap();
    state.complete_reply_wake(reply_ack).unwrap();

    let drained = state.query_task(&workload, COMPACT_WORK, 1).unwrap();
    __cser_core::assert_eq!(drained.live_children, 0);
    __cser_core::assert_eq!(drained.anchor, TaskAnchorRecoveryState::TerminalDrained);
    state.check_invariants().unwrap();
}

fn applied_fault_state(disposition: FaultDisposition) -> InfrastructureState {
    let mut state = InfrastructureState::new(0x9020);
    state
        .enable(SCOPE, 1, ROOT, limits(), &[(SERVICE, 1)])
        .unwrap();
    let workload = state
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(SERVICE, 1, 0xb300, 1),
        )
        .unwrap();
    let task_key = TaskKey::new(0xb500, 1);
    let task = state
        .admit_task(
            &workload,
            TaskWorkDescriptor {
                work_id: 0xb400,
                generation: 1,
                task: task_key,
                role: TaskWorkRole::ServiceRequest,
                vm: Some(VmAuthorityKey::new(0xb600, 1).unwrap()),
            },
        )
        .unwrap();
    let reserved = state
        .reserve_fault_event(
            task,
            FaultSlotDescriptor {
                fault_id: 0xb700,
                generation: 1,
                task: task_key,
                vm_generation: 1,
                service_domain: SERVICE,
                admission_binding_epoch: 1,
            },
        )
        .unwrap();
    let armed = state.claim_service_task_entry(reserved).unwrap();
    let (intent, plan) = state
        .prepare_fault_disposition(
            armed,
            FaultObservation {
                task: task_key,
                vm_generation: 1,
                instruction_pointer: 0xb800,
                address: 0xb900,
                access: FaultAccess::Read,
                architecture_error: 0xba,
                evidence_digest: 0xbb,
            },
            disposition,
        )
        .unwrap();
    state.install_fault_disposition(intent, plan).unwrap();
    state.check_invariants().unwrap();
    state
}

#[test]
fn persisted_sequence_high_watermarks_reject_allocator_rollback() {
    let base = publication_state();

    let mut nonce = base.private_full_clone();
    nonce.scope_mut(SCOPE).unwrap().next_nonce -= 1;
    assert_invariant_read_only(nonce);

    let mut publication = base.private_full_clone();
    publication
        .scope_mut(SCOPE)
        .unwrap()
        .next_publication_sequence -= 1;
    assert_invariant_read_only(publication);

    let mut closure = base.private_full_clone();
    let plan = closure.prepare_closure_start(SCOPE, 1).unwrap();
    closure.apply_closure_start(plan);
    closure.check_invariants().unwrap();
    closure.scope_mut(SCOPE).unwrap().next_closure_sequence = 1;
    assert_invariant_read_only(closure);
}

#[test]
fn full_scope_closure_is_stamped_blocking_and_exactly_replayable() {
    let mut live = publication_state();
    let plan = live.prepare_closure_start(SCOPE, 1).unwrap();
    let selection = live.apply_closure_start(plan);
    __cser_core::assert_eq!(
        live.closure_progress(SCOPE).unwrap(),
        InfrastructureClosureProgress::Closing(selection)
    );
    live.check_invariants().unwrap();

    let before_duplicate = live.private_full_clone();
    let duplicate = match live.prepare_closure_start(SCOPE, 1) {
        Ok(_) => __cser_core::panic!("duplicate closure start prepared"),
        Err(error) => error,
    };
    __cser_core::assert_eq!(duplicate, InfrastructureError::ClosureAlreadyStarted);
    __cser_core::assert_eq!(live, before_duplicate);

    let before_admission = live.private_full_clone();
    __cser_core::assert_eq!(
        live.open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 1, 0xa301, 1),
        ),
        Err(InfrastructureError::ScopeNotActive)
    );
    __cser_core::assert_eq!(live, before_admission);

    let before_finish = live.private_full_clone();
    let blocked = match live.prepare_closure_finish(selection) {
        Ok(_) => __cser_core::panic!("live closure prepared completion"),
        Err(error) => error,
    };
    __cser_core::assert_eq!(
        blocked,
        InfrastructureError::ClosureBlocked {
            kind: InfrastructureKind::Continuation,
            live: 1,
        }
    );
    __cser_core::assert_eq!(live, before_finish);

    let mut impossible_closed = live.private_full_clone();
    {
        let closure = impossible_closed
            .scope_mut(SCOPE)
            .unwrap()
            .closure
            .as_mut()
            .unwrap();
        closure.finished = true;
        closure.receipt = Some(InfrastructureClosureReceipt {
            registry_instance: 0x9011,
            scope: SCOPE,
            authority_epoch: 1,
            root_effect: ROOT,
            sequence: closure.sequence,
            nonce: closure.nonce,
            closed_revision: 1,
        });
    }
    assert_invariant_message_read_only(
        impossible_closed,
        "closed infrastructure scope retains an obligation",
    );

    let mut missing_stamp = live.private_full_clone();
    missing_stamp
        .scope_mut(SCOPE)
        .unwrap()
        .continuations
        .iter_mut()
        .next()
        .unwrap()
        .closure_sequence = None;
    assert_invariant_message_read_only(missing_stamp, "infrastructure closure cohort mismatch");

    let mut empty = InfrastructureState::new(0x9011);
    empty
        .enable(SCOPE, 1, ROOT, limits(), &[(GUEST, 1)])
        .unwrap();
    let domain_before = empty.scope(SCOPE).unwrap().domains.clone();
    let plan = empty.prepare_closure_start(SCOPE, 1).unwrap();
    let selection = empty.apply_closure_start(plan);
    let (plan, expected) = empty.prepare_closure_finish(selection).unwrap();
    let installed = empty.apply_closure_finish(plan);
    __cser_core::assert_eq!(installed, expected);
    __cser_core::assert_eq!(empty.scope(SCOPE).unwrap().domains, domain_before);
    __cser_core::assert_eq!(
        empty.closure_progress(SCOPE).unwrap(),
        InfrastructureClosureProgress::Closed(expected)
    );
    empty.verify_closure_receipt(expected).unwrap();
    empty.check_invariants().unwrap();

    let before_substitution = empty.private_full_clone();
    let mut substituted = expected;
    substituted.closed_revision += 1;
    __cser_core::assert_eq!(
        empty.verify_closure_receipt(substituted),
        Err(InfrastructureError::InvalidReceipt)
    );
    __cser_core::assert_eq!(empty, before_substitution);
}

#[test]
fn workload_close_intent_is_exact_failure_atomic_and_projects_root_finish() {
    let mut state = InfrastructureState::new(0x9012);
    state
        .enable(SCOPE, 1, ROOT, limits(), &[(GUEST, 1)])
        .unwrap();
    let workload = state
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 1, 0xa310, 1),
        )
        .unwrap();
    let selection = state.apply_closure_start(state.prepare_closure_start(SCOPE, 1).unwrap());

    let before_prepare = state.private_full_clone();
    let intent = state.prepare_workload_close(&workload).unwrap();
    __cser_core::assert_eq!(state, before_prepare);
    let (finish, expected) = state
        .prepare_closure_finish_after_workload_close(selection, &intent)
        .unwrap();
    __cser_core::assert_eq!(state, before_prepare);

    // A standalone workload apply is deliberately not a full infrastructure
    // root closure. Only the separately prepared root finish installs the
    // durable zero-live receipt.
    state.apply_workload_close(intent, &workload);
    __cser_core::assert_eq!(
        state.closure_progress(SCOPE).unwrap(),
        InfrastructureClosureProgress::Closing(selection)
    );
    let installed = state.apply_closure_finish(finish);
    __cser_core::assert_eq!(installed, expected);
    __cser_core::assert_eq!(
        state.closure_progress(SCOPE).unwrap(),
        InfrastructureClosureProgress::Closed(expected)
    );
    state.check_invariants().unwrap();

    // Independently prepared intents share one base revision, but applying
    // one closes the bearer and makes the other an exact stale replay.
    let mut duplicate = InfrastructureState::new(0x9013);
    duplicate
        .enable(SCOPE, 1, ROOT, limits(), &[(GUEST, 1)])
        .unwrap();
    let workload = duplicate
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 1, 0xa311, 1),
        )
        .unwrap();
    let first = duplicate.prepare_workload_close(&workload).unwrap();
    let replay = duplicate.prepare_workload_close(&workload).unwrap();
    duplicate.apply_workload_close(first, &workload);
    let before_replay = duplicate.private_full_clone();
    __cser_core::assert_eq!(
        duplicate.validate_workload_close_intent(&replay, None),
        Err(InfrastructureError::InvalidState)
    );
    __cser_core::assert_eq!(duplicate, before_replay);
    duplicate.check_invariants().unwrap();

    // A live child blocks preflight without consuming its exact workload
    // context or changing any authoritative or diagnostic counter.
    let mut blocked = InfrastructureState::new(0x9014);
    blocked
        .enable(SCOPE, 1, ROOT, limits(), &[(GUEST, 1)])
        .unwrap();
    let workload = blocked
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 1, 0xa312, 1),
        )
        .unwrap();
    let _task = blocked
        .admit_task(
            &workload,
            TaskWorkDescriptor {
                work_id: 0xa412,
                generation: 1,
                task: TaskKey::new(0xa512, 1),
                role: TaskWorkRole::GuestSyscallWork,
                vm: Some(VmAuthorityKey::new(0xa612, 1).unwrap()),
            },
        )
        .unwrap();
    let before_blocked = blocked.private_full_clone();
    __cser_core::assert_eq!(
        blocked.prepare_workload_close(&workload).unwrap_err(),
        InfrastructureError::ClosureBlocked {
            kind: InfrastructureKind::Task,
            live: 1,
        }
    );
    __cser_core::assert_eq!(blocked, before_blocked);

    // Counter exhaustion is discovered during preparation, never after an
    // external side effect or partial close installation.
    let mut overflow = InfrastructureState::new(0x9015);
    overflow
        .enable(SCOPE, 1, ROOT, limits(), &[(GUEST, 1)])
        .unwrap();
    let workload = overflow
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 1, 0xa313, 1),
        )
        .unwrap();
    overflow.scope_mut(SCOPE).unwrap().revision = u64::MAX;
    let before_overflow = overflow.private_full_clone();
    __cser_core::assert_eq!(
        overflow.prepare_workload_close(&workload).unwrap_err(),
        InfrastructureError::CounterOverflow
    );
    __cser_core::assert_eq!(overflow, before_overflow);

    // Neither a different Registry instance nor a same-Registry workload may
    // substitute for the identity against which the intent was prepared.
    let mut owner = InfrastructureState::new(0x9016);
    owner
        .enable(SCOPE, 1, ROOT, limits(), &[(GUEST, 1)])
        .unwrap();
    let owner_workload = owner
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 1, 0xa314, 1),
        )
        .unwrap();
    let intent = owner.prepare_workload_close(&owner_workload).unwrap();
    let mut foreign = InfrastructureState::new(0x9017);
    foreign
        .enable(SCOPE, 1, ROOT, limits(), &[(GUEST, 1)])
        .unwrap();
    let before_foreign = foreign.private_full_clone();
    __cser_core::assert_eq!(
        foreign.validate_workload_close_intent(&intent, Some(&owner_workload)),
        Err(InfrastructureError::ForeignRegistry)
    );
    __cser_core::assert_eq!(foreign, before_foreign);

    let second_workload = owner
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 1, 0xa315, 1),
        )
        .unwrap();
    let first_intent = owner.prepare_workload_close(&owner_workload).unwrap();
    let before_substitution = owner.private_full_clone();
    __cser_core::assert_eq!(
        owner.validate_workload_close_intent(&first_intent, Some(&second_workload)),
        Err(InfrastructureError::ForeignWorkload)
    );
    __cser_core::assert_eq!(owner, before_substitution);
}

#[test]
fn observed_fault_requires_atomic_task_and_domain_disposition() {
    let crash = applied_fault_state(FaultDisposition::CrashService);

    let mut partial_task = crash.private_full_clone();
    partial_task
        .scope_mut(SCOPE)
        .unwrap()
        .tasks
        .iter_mut()
        .next()
        .unwrap()
        .phase = TaskPhase::Entered;
    assert_invariant_read_only(partial_task);

    let mut partial_domain = crash.private_full_clone();
    *partial_domain
        .scope_mut(SCOPE)
        .unwrap()
        .binding_epoch_mut(SERVICE)
        .unwrap() = 1;
    assert_invariant_read_only(partial_domain);

    let mut missing_crash_generation = crash.private_full_clone();
    let fault = missing_crash_generation
        .scope_mut(SCOPE)
        .unwrap()
        .faults
        .iter_mut()
        .next()
        .unwrap();
    if let FaultPhase::InstalledAwaitingClaim {
        ref mut projection, ..
    } = fault.phase
    {
        projection.crash_generation = 0;
    }
    assert_invariant_read_only(missing_crash_generation);

    let mut missing_evidence = crash.private_full_clone();
    let fault = missing_evidence
        .scope_mut(SCOPE)
        .unwrap()
        .faults
        .iter_mut()
        .next()
        .unwrap();
    if let FaultPhase::InstalledAwaitingClaim {
        ref mut projection, ..
    } = fault.phase
    {
        projection.evidence_digest = 0;
    }
    assert_invariant_read_only(missing_evidence);

    let isolate = applied_fault_state(FaultDisposition::IsolateTask);
    let mut later_crash = isolate.private_full_clone();
    let workload = later_crash
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(SERVICE, 1, 0xc300, 1),
        )
        .unwrap();
    let task_key = TaskKey::new(0xc500, 1);
    let task = later_crash
        .admit_task(
            &workload,
            TaskWorkDescriptor {
                work_id: 0xc400,
                generation: 1,
                task: task_key,
                role: TaskWorkRole::ServiceRequest,
                vm: Some(VmAuthorityKey::new(0xc600, 1).unwrap()),
            },
        )
        .unwrap();
    let reserved = later_crash
        .reserve_fault_event(
            task,
            FaultSlotDescriptor {
                fault_id: 0xc700,
                generation: 1,
                task: task_key,
                vm_generation: 1,
                service_domain: SERVICE,
                admission_binding_epoch: 1,
            },
        )
        .unwrap();
    let armed = later_crash.claim_service_task_entry(reserved).unwrap();
    let (intent, plan) = later_crash
        .prepare_fault_disposition(
            armed,
            FaultObservation {
                task: task_key,
                vm_generation: 1,
                instruction_pointer: 0xc800,
                address: 0xc900,
                access: FaultAccess::Read,
                architecture_error: 0xca,
                evidence_digest: 0xcb,
            },
            FaultDisposition::CrashService,
        )
        .unwrap();
    later_crash.install_fault_disposition(intent, plan).unwrap();
    later_crash.check_invariants().unwrap();

    let mut fabricated_crash = isolate.private_full_clone();
    let fault = fabricated_crash
        .scope_mut(SCOPE)
        .unwrap()
        .faults
        .iter_mut()
        .next()
        .unwrap();
    if let FaultPhase::InstalledAwaitingClaim {
        ref mut projection, ..
    } = fault.phase
    {
        projection.crash_generation = 1;
    }
    assert_invariant_read_only(fabricated_crash);
}

#[test]
fn domain_fault_recovery_projection_is_revision_independent_and_rejects_duplicates() {
    let mut state = applied_fault_state(FaultDisposition::CrashService);
    let (_, current_fault_id) =
        install_additional_fault(&mut state, 0xbd00, FaultDisposition::CrashService);
    state.check_invariants().unwrap();
    let binding_epoch = state.scope(SCOPE).unwrap().binding_epoch(SERVICE).unwrap();
    let projection = state
        .domain_fault_recovery_projection(SCOPE, SERVICE, binding_epoch)
        .unwrap()
        .unwrap();
    __cser_core::assert_eq!(projection.fault_id, current_fault_id);

    let historical = state
        .scope_mut(SCOPE)
        .unwrap()
        .faults
        .get_mut(0xb700)
        .unwrap();
    if let FaultPhase::InstalledAwaitingClaim {
        ref mut projection, ..
    } = historical.phase
    {
        projection.closed_binding_epoch = binding_epoch - 1;
    } else {
        __cser_core::panic!("historical crash fault changed phase")
    }
    __cser_core::assert_eq!(
        state.domain_fault_recovery_projection(SCOPE, SERVICE, binding_epoch),
        Err(InfrastructureError::Invariant(
            "duplicate domain fault recovery projection"
        ))
    );
}

#[test]
fn task_fault_invariants_bind_both_directions_disposition_and_exact_exit_digest() {
    let installed = applied_fault_state(FaultDisposition::CrashService);

    let mut deleted_terminal = installed.private_full_clone();
    let fault_nonce = deleted_terminal
        .scope(SCOPE)
        .unwrap()
        .faults
        .get(0xb700)
        .unwrap()
        .stamp
        .nonce;
    let scope = deleted_terminal.scope_mut(SCOPE).unwrap();
    __cser_core::assert!(scope.faults.remove(0xb700).is_some());
    __cser_core::assert!(scope.reverse_indexes.remove(fault_nonce).is_some());
    assert_invariant_message_read_only(deleted_terminal, "task-fault pair missing");

    let mut substituted_terminal = installed.private_full_clone();
    let (second_work_id, _) = install_additional_fault(
        &mut substituted_terminal,
        0xbc00,
        FaultDisposition::IsolateTask,
    );
    let substitute = substituted_terminal
        .scope(SCOPE)
        .unwrap()
        .tasks
        .get(second_work_id)
        .unwrap()
        .service_fault
        .unwrap();
    substituted_terminal
        .scope_mut(SCOPE)
        .unwrap()
        .tasks
        .get_mut(0xb400)
        .unwrap()
        .service_fault = Some(substitute);
    assert_invariant_message_read_only(substituted_terminal, "task-fault pair mismatch");

    type MutatePair = fn(&mut InfrastructureState);
    let pair_mutations: &[MutatePair] = &[
        |state| {
            state
                .scope_mut(SCOPE)
                .unwrap()
                .tasks
                .get_mut(0xb400)
                .unwrap()
                .service_fault
                .as_mut()
                .unwrap()
                .fault_object_generation += 1
        },
        |state| {
            state
                .scope_mut(SCOPE)
                .unwrap()
                .tasks
                .get_mut(0xb400)
                .unwrap()
                .service_fault
                .as_mut()
                .unwrap()
                .fault_bearer_generation += 1
        },
        |state| {
            state
                .scope_mut(SCOPE)
                .unwrap()
                .tasks
                .get_mut(0xb400)
                .unwrap()
                .service_fault
                .as_mut()
                .unwrap()
                .fault_nonce += 1
        },
        |state| {
            state
                .scope_mut(SCOPE)
                .unwrap()
                .faults
                .get_mut(0xb700)
                .unwrap()
                .owner
                .task_object_nonce += 1
        },
        |state| {
            state
                .scope_mut(SCOPE)
                .unwrap()
                .faults
                .get_mut(0xb700)
                .unwrap()
                .owner
                .task_bearer_generation += 1
        },
        |state| {
            state
                .scope_mut(SCOPE)
                .unwrap()
                .faults
                .get_mut(0xb700)
                .unwrap()
                .stamp
                .identity
                .admission_binding_epoch += 1
        },
    ];
    for mutate in pair_mutations {
        let mut corrupt = installed.private_full_clone();
        mutate(&mut corrupt);
        assert_invariant_message_read_only(corrupt, "task-fault pair mismatch");
    }

    let mut isolate = applied_fault_state(FaultDisposition::IsolateTask);
    let context = super::workload_bearer(isolate.scope(SCOPE).unwrap(), 0xb300).unwrap();
    let selector = isolate
        .query_fault(&context, 0xb700, 1)
        .unwrap()
        .selector
        .unwrap();
    __cser_core::assert!(__cser_core::matches!(
        isolate.claim_fault_receipt(&context, selector).unwrap(),
        super::FaultReceiptClaimOutcome::Isolate(_)
    ));
    if let FaultPhase::Claimed {
        ref mut cause_claimed,
        ..
    } = isolate
        .scope_mut(SCOPE)
        .unwrap()
        .faults
        .get_mut(0xb700)
        .unwrap()
        .phase
    {
        *cause_claimed = true;
    } else {
        __cser_core::panic!("claimed isolate fault changed phase")
    }
    assert_invariant_message_read_only(isolate, "fault phase projection mismatch");

    let (mut exited, _, armed, _) = armed_fault_state(0xfef0);
    exited
        .finish_service_task_without_fault(armed, 0xfef1)
        .unwrap();
    let mut bad_digest = exited.private_full_clone();
    bad_digest
        .scope_mut(SCOPE)
        .unwrap()
        .tasks
        .get_mut(0xfc30)
        .unwrap()
        .service_fault
        .as_mut()
        .unwrap()
        .terminal_install_digest
        .as_mut()
        .unwrap()[0] ^= 1;
    assert_invariant_message_read_only(bad_digest, "fault phase projection mismatch");

    type MutateExit = fn(&mut super::ServiceTaskExitReceipt);
    let exit_mutations: &[MutateExit] = &[
        |receipt| receipt.fault_id += 1,
        |receipt| receipt.generation += 1,
        |receipt| receipt.task = TaskKey::new(receipt.task.id() + 1, receipt.task.generation()),
        |receipt| receipt.evidence_digest += 1,
    ];
    for mutate in exit_mutations {
        let mut corrupt = exited.private_full_clone();
        let fault = corrupt
            .scope_mut(SCOPE)
            .unwrap()
            .faults
            .get_mut(0xfc50)
            .unwrap();
        if let FaultPhase::Exited { ref mut receipt } = fault.phase {
            mutate(receipt);
        } else {
            __cser_core::panic!("service exit changed fault phase")
        }
        assert_invariant_message_read_only(corrupt, "fault phase projection mismatch");
    }
}

#[test]
fn terminal_service_history_survives_fence_and_adoption_but_live_owner_stays_strict() {
    let mut stale_live = seeded_state();
    *stale_live
        .scope_mut(SCOPE)
        .unwrap()
        .binding_epoch_mut(GUEST)
        .unwrap() = 2;
    assert_invariant_read_only(stale_live);

    let mut terminal = seeded_state();
    let request = test_bound_service_authority(&terminal, 0x9800);
    terminal
        .cancel_bound_service_request(request, ValidatedAbortProof::new(0xc1))
        .unwrap();
    terminal.check_invariants().unwrap();

    let mut pre_adoption_substitution = terminal.private_full_clone();
    let mut replaced = false;
    if let ServiceRequestPhase::Cancelled { receipt } = &mut pre_adoption_substitution
        .scope_mut(SCOPE)
        .unwrap()
        .service_requests
        .get_mut(0x9800)
        .unwrap()
        .phase
        && let Some(response) = receipt.response.as_mut()
    {
        response.source_binding_epoch = 2;
        replaced = true;
    }
    __cser_core::assert!(replaced);
    assert_invariant_read_only(pre_adoption_substitution);

    *terminal
        .scope_mut(SCOPE)
        .unwrap()
        .binding_epoch_mut(GUEST)
        .unwrap() = 2;
    let workload = terminal
        .adopt_workload_after_fence(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(GUEST, 2, 0x9300, 1),
        )
        .unwrap();
    terminal
        .adopt_task_after_fence(&workload, 0x9400, 1)
        .unwrap();
    terminal
        .adopt_continuation_after_fence(&workload, 0x9700, 1, 2)
        .unwrap();
    terminal.check_invariants().unwrap();

    let mut post_adoption_substitution = terminal.private_full_clone();
    let mut replaced = false;
    if let ServiceRequestPhase::Cancelled { receipt } = &mut post_adoption_substitution
        .scope_mut(SCOPE)
        .unwrap()
        .service_requests
        .get_mut(0x9800)
        .unwrap()
        .phase
        && let Some(response) = receipt.response.as_mut()
    {
        response.source_binding_epoch = 2;
        replaced = true;
    }
    __cser_core::assert!(replaced);
    assert_invariant_read_only(post_adoption_substitution);
}

#[test]
fn full_recompute_rejects_each_derived_ledger_corruption_without_mutation() {
    let base = seeded_state();

    let mut primary = base.private_full_clone();
    primary
        .scope_mut(SCOPE)
        .unwrap()
        .tasks
        .iter_mut()
        .next()
        .unwrap()
        .stamp
        .identity
        .generation = 2;
    assert_invariant_read_only(primary);

    let mut missing_index = base.private_full_clone();
    let index_slot = missing_index
        .scope(SCOPE)
        .unwrap()
        .tasks
        .iter()
        .next()
        .unwrap()
        .stamp
        .nonce;
    missing_index
        .scope_mut(SCOPE)
        .unwrap()
        .reverse_indexes
        .remove(index_slot)
        .unwrap();
    assert_invariant_read_only(missing_index);

    let mut index_field = base.private_full_clone();
    index_field
        .scope_mut(SCOPE)
        .unwrap()
        .reverse_indexes
        .iter_mut()
        .next()
        .unwrap()
        .retry_generation = 77;
    assert_invariant_read_only(index_field);

    let device_index_slot = base
        .scope(SCOPE)
        .unwrap()
        .devices
        .iter()
        .next()
        .unwrap()
        .stamp
        .nonce;
    let mut device_actor_generation = base.private_full_clone();
    device_actor_generation
        .scope_mut(SCOPE)
        .unwrap()
        .reverse_indexes
        .get_mut(device_index_slot)
        .unwrap()
        .actor_generation = Some(2);
    assert_invariant_read_only(device_actor_generation);

    let mut device_obligation_generation = base.private_full_clone();
    device_obligation_generation
        .scope_mut(SCOPE)
        .unwrap()
        .reverse_indexes
        .get_mut(device_index_slot)
        .unwrap()
        .retry_generation = 2;
    assert_invariant_read_only(device_obligation_generation);

    let mut live = base.private_full_clone();
    live.scope_mut(SCOPE).unwrap().live.tasks += 1;
    assert_invariant_read_only(live);

    let mut workload_child = base.private_full_clone();
    workload_child
        .scope_mut(SCOPE)
        .unwrap()
        .workloads
        .iter_mut()
        .next()
        .unwrap()
        .live_children += 1;
    assert_invariant_read_only(workload_child);

    let mut task_child = base.private_full_clone();
    task_child
        .scope_mut(SCOPE)
        .unwrap()
        .tasks
        .iter_mut()
        .next()
        .unwrap()
        .live_children += 1;
    assert_invariant_read_only(task_child);

    let mut credit = base.private_full_clone();
    credit.scope_mut(SCOPE).unwrap().live.queue_slots += 1;
    assert_invariant_read_only(credit);

    let mut owner = base.private_full_clone();
    owner
        .scope_mut(SCOPE)
        .unwrap()
        .continuations
        .iter_mut()
        .next()
        .unwrap()
        .service_owner = None;
    assert_invariant_read_only(owner);

    let mut domain_epoch = base.private_full_clone();
    *domain_epoch
        .scope_mut(SCOPE)
        .unwrap()
        .binding_epoch_mut(SERVICE)
        .unwrap() = 2;
    assert_invariant_read_only(domain_epoch);

    let mut phase = base.private_full_clone();
    phase
        .scope_mut(SCOPE)
        .unwrap()
        .service_requests
        .iter_mut()
        .next()
        .unwrap()
        .phase = ServiceRequestPhase::ReservedUnbound;
    assert_invariant_read_only(phase);
}
