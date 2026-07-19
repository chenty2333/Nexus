// SPDX-License-Identifier: MPL-2.0

use super::{
    AuthorityKey, BearerKey, BoundServiceRequest, ContinuationAckReceipt, ContinuationAdoption,
    ContinuationDescriptor, ContinuationLease, ContinuationPublicationAckReceipt,
    ContinuationPublicationAuthority, ContinuationPublicationReceipt, ContinuationResumeAuthority,
    ContinuationResumePlan, ContinuationResumeReceipt, DeadlineAdoption, DeadlineClockBasis,
    DeadlineDescriptor, DeadlineExhaustedDisposition, DeadlineExpiryAuthority,
    DeadlineExpiryReceipt, DeadlineLease, DeadlinePurpose, DeadlineQuarantineReleaseReceipt,
    DeadlineQuarantineTicket, DeadlineReconciliationOutcome, DeadlineReconciliationReceipt,
    DeadlineRecoveryState, DeadlineSupervisorRetry, DeviceReservationCoordinates, DomainKey,
    EffectKey, EnqueuedServiceRequest, EnteredTaskLease, FaultAccess, FaultDescriptor,
    FaultDisposition, FaultObservation, FaultPhase, InfrastructureError, InfrastructureLimits,
    InfrastructureState, LinearFailure, ResourceKey, ScopeKey, ServiceArmAuthority, ServiceArmPlan,
    ServiceArmReceipt, ServiceBoundKey, ServiceCancellationPoint, ServiceChildBindingReceipt,
    ServiceChildReceipt, ServiceClaimantSnapshot, ServiceEnqueueAuthority, ServiceEnqueuePlan,
    ServiceEnqueueReceipt, ServiceLineageCommitment, ServiceRequestCausalIdentity,
    ServiceRequestDescriptor, ServiceRequestPhase, ServiceRequestRecoveryState,
    ServiceRequestTicket, TaskAdoption, TaskKey, TaskPhase, TaskWorkDescriptor, TaskWorkRole,
    UnarmedServiceRequest, UnboundServiceRequest, ValidatedAbortProof, ValidatedServiceChildProof,
    VmAuthorityKey, WakeClaim, WorkloadContext, WorkloadRequestPresentation,
    WorkloadRootPresentation, bearer_state,
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
            _ => unreachable!(),
        };
        EnteredTaskLease(scope.tasks.get(parent.work_id).unwrap().stamp)
    };
    let sibling = ContinuationDescriptor {
        continuation_id: COMPACT_CONTINUATION + 1,
        ..compact_response_descriptor()
    };
    let _sibling_lease = state.create_continuation(&parent, sibling).unwrap();
    (state, service, sibling)
}

fn add_service_claimant(state: &mut InfrastructureState, identity_base: u64) -> EnteredTaskLease {
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
                role: TaskWorkRole::GuestSyscallWork,
                vm: Some(VmAuthorityKey::new(identity_base + 3, 1).unwrap()),
            },
        )
        .unwrap();
    state.claim_task_entry(task).unwrap()
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
        _ => panic!("response substitution requires a live bound service"),
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before);
    assert_eq!(
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before);
    assert_eq!(
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
    assert_eq!(failure.error(), expected_error);
    assert_eq!(state, before);
    let returned = failure.into_input();
    assert_eq!(
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
    assert!(core::mem::size_of::<AuthorityKey>() <= 32);
    assert!(core::mem::size_of::<BearerKey<bearer_state::ContinuationPending>>() <= 64);
    assert!(core::mem::size_of::<ContinuationLease>() <= 96);
    assert!(core::mem::size_of::<WakeClaim>() <= 96);
    assert!(core::mem::size_of::<ContinuationPublicationAuthority>() <= 96);
    assert!(core::mem::size_of::<ContinuationPublicationAckReceipt>() <= 96);
    assert!(core::mem::size_of::<ContinuationAckReceipt>() <= 96);
    assert!(core::mem::size_of::<ContinuationResumeAuthority>() <= 96);
    assert!(core::mem::size_of::<ContinuationResumeReceipt>() <= 96);
    assert!(core::mem::size_of::<LinearFailure<ContinuationLease>>() <= 120);
    assert!(core::mem::size_of::<LinearFailure<WakeClaim>>() <= 120);
    assert!(core::mem::size_of::<LinearFailure<ContinuationPublicationAuthority>>() <= 120);
    assert!(core::mem::size_of::<LinearFailure<ContinuationAckReceipt>>() <= 120);
    assert!(core::mem::size_of::<LinearFailure<ContinuationResumeAuthority>>() <= 120);
}

#[test]
fn service_compact_authority_layout_is_bounded() {
    assert!(core::mem::size_of::<BearerKey<bearer_state::ServiceReservedUnbound>>() <= 64);
    assert!(core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceReservedBound>>() <= 96);
    assert!(core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceEnqueuePublishing>>() <= 96);
    assert!(core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceQueueWritten>>() <= 96);
    assert!(core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceArmPublishing>>() <= 96);
    assert!(core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceArmed>>() <= 96);
    assert!(core::mem::size_of::<ServiceBoundKey<bearer_state::ServiceChildBound>>() <= 96);
    assert!(core::mem::size_of::<UnboundServiceRequest>() <= 96);
    assert!(core::mem::size_of::<ServiceRequestTicket>() <= 96);
    assert!(core::mem::size_of::<ServiceEnqueueAuthority>() <= 96);
    assert!(core::mem::size_of::<UnarmedServiceRequest>() <= 96);
    assert!(core::mem::size_of::<ServiceArmAuthority>() <= 96);
    assert!(core::mem::size_of::<EnqueuedServiceRequest>() <= 96);
    assert!(core::mem::size_of::<BoundServiceRequest>() <= 96);
    assert!(core::mem::size_of::<LinearFailure<UnboundServiceRequest>>() <= 120);
    assert!(core::mem::size_of::<LinearFailure<ServiceRequestTicket>>() <= 120);
    assert!(core::mem::size_of::<LinearFailure<ServiceEnqueueAuthority>>() <= 120);
    assert!(core::mem::size_of::<LinearFailure<UnarmedServiceRequest>>() <= 120);
    assert!(core::mem::size_of::<LinearFailure<ServiceArmAuthority>>() <= 120);
    assert!(core::mem::size_of::<LinearFailure<EnqueuedServiceRequest>>() <= 120);
    assert!(core::mem::size_of::<LinearFailure<BoundServiceRequest>>() <= 120);
    assert!(core::mem::size_of::<ServiceRequestCausalIdentity>() <= 512);
    assert!(core::mem::size_of::<ServiceEnqueuePlan>() <= 512);
    assert!(core::mem::size_of::<ServiceEnqueueReceipt>() <= 640);
    assert!(core::mem::size_of::<ServiceArmPlan>() <= 1_280);
    assert!(core::mem::size_of::<ServiceArmReceipt>() <= 1_408);
    assert!(core::mem::size_of::<ServiceClaimantSnapshot>() <= 320);
    assert!(core::mem::size_of::<ServiceChildBindingReceipt>() <= 384);
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
    assert_eq!(
        super::service::service_response_commitment(response),
        ServiceLineageCommitment([
            0x4d, 0xc6, 0x06, 0x7a, 0x80, 0xec, 0xf3, 0x60, 0x5d, 0x55, 0xae, 0xc7, 0x2d, 0x28,
            0x98, 0xfd, 0x39, 0x73, 0x38, 0x2f, 0xac, 0x15, 0x47, 0x9c, 0xcf, 0x59, 0x70, 0x84,
            0x40, 0xdb, 0x0a, 0x0a,
        ])
    );
    let bound = super::service::service_bound_commitment(response, binding);
    assert_eq!(
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
    assert_eq!(
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
    assert_eq!(
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
    assert_eq!(
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
    assert_eq!(
        super::service::service_armed_commitment(enqueue_receipt, arm_receipt),
        ServiceLineageCommitment([
            0x88, 0x49, 0x24, 0xe4, 0x9e, 0x29, 0x4f, 0xf5, 0x0f, 0x8f, 0x66, 0xb5, 0x7a, 0x5b,
            0xb2, 0x9e, 0x32, 0x5f, 0x65, 0x39, 0x0f, 0xdf, 0x58, 0x73, 0xd1, 0x45, 0xd5, 0x67,
            0xbe, 0x0f, 0xd0, 0xcc,
        ])
    );
    assert_eq!(
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
            assert_ne!(
                super::service::service_enqueue_plan_commitment(changed_plan),
                super::service::service_enqueue_plan_commitment(enqueue_plan)
            );
            let mut changed_queue = enqueue_receipt;
            changed_queue.plan = changed_plan;
            assert_ne!(
                super::service::service_enqueue_receipt_commitment(changed_queue),
                super::service::service_enqueue_receipt_commitment(enqueue_receipt)
            );
            let mut changed_arm_plan = arm_plan;
            changed_arm_plan.queue_receipt = changed_queue;
            let mut changed_arm = arm_receipt;
            changed_arm.plan = changed_arm_plan;
            assert_ne!(
                super::service::service_armed_commitment(changed_queue, changed_arm),
                super::service::service_armed_commitment(enqueue_receipt, arm_receipt)
            );
            assert_ne!(
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
            assert_ne!(
                super::service::service_enqueue_receipt_commitment(changed_queue),
                super::service::service_enqueue_receipt_commitment(enqueue_receipt)
            );
            let mut changed_arm_plan = arm_plan;
            changed_arm_plan.queue_receipt = changed_queue;
            assert_ne!(
                super::service::service_arm_plan_commitment(changed_arm_plan),
                super::service::service_arm_plan_commitment(arm_plan)
            );
            let mut changed_arm = arm_receipt;
            changed_arm.plan = changed_arm_plan;
            assert_ne!(
                super::service::service_armed_commitment(changed_queue, changed_arm),
                super::service::service_armed_commitment(enqueue_receipt, arm_receipt)
            );
            assert_ne!(
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
            assert_ne!(
                super::service::service_arm_plan_commitment(changed_plan),
                super::service::service_arm_plan_commitment(arm_plan)
            );
            let mut changed_arm = arm_receipt;
            changed_arm.plan = changed_plan;
            assert_ne!(
                super::service::service_armed_commitment(enqueue_receipt, changed_arm),
                super::service::service_armed_commitment(enqueue_receipt, arm_receipt)
            );
            assert_ne!(
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
            assert_ne!(
                super::service::service_armed_commitment(enqueue_receipt, changed),
                super::service::service_armed_commitment(enqueue_receipt, arm_receipt)
            );
            assert_ne!(
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
        assert_ne!(
            super::service::service_response_commitment(substituted),
            super::service::service_response_commitment(response)
        );
        assert_ne!(
            super::service::service_bound_commitment(substituted, binding),
            bound
        );
        assert_enqueue_plan_change!(|value: &mut ServiceEnqueuePlan| {
            mutate(&mut value.causal.response)
        });
        assert_arm_plan_change!(|value: &mut ServiceArmPlan| {
            mutate(&mut value.causal.response)
        });
        assert_ne!(
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
        assert_ne!(
            super::service::service_bound_commitment(response, substituted),
            bound
        );
        assert_ne!(
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
    assert_eq!(failure.error(), InfrastructureError::StaleBinding);
    assert_eq!(state, before);
    let unbound = failure.into_input();
    assert_eq!(service_key_coordinates(&unbound.0), presented);
    assert_eq!(state.scope(SCOPE).unwrap().live.continuations, 0);

    let bound = state
        .bind_service_response_continuation(unbound, compact_response_descriptor())
        .unwrap();
    assert_eq!(bound.0.bearer_generation, 2);
    let scope = state.scope(SCOPE).unwrap();
    let service = scope.service_requests.get(COMPACT_SERVICE_REQUEST).unwrap();
    let continuation = scope.continuations.get(COMPACT_CONTINUATION).unwrap();
    assert_eq!(service.bound_continuation, Some(continuation.stamp));
    assert_eq!(
        continuation.service_owner,
        Some(super::RequestKey {
            id: COMPACT_SERVICE_REQUEST,
            generation: 1,
        })
    );
    assert_eq!(continuation.stamp.bearer_generation, 1);
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
    assert_eq!(
        state
            .adopt_continuation_after_fence(&workload, COMPACT_CONTINUATION, 1, 2)
            .unwrap_err(),
        InfrastructureError::InvalidState
    );
    assert_eq!(state, before);
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
    assert_eq!(failure.error(), InfrastructureError::InvalidState);
    assert_eq!(state, before);
    let unbound = failure.into_input();
    assert_eq!(service_key_coordinates(&unbound.0), presented);
    assert_eq!(state.scope(SCOPE).unwrap().live.continuations, 0);
}

#[test]
fn service_unbound_cancel_has_no_continuation_authority_or_post_queue_path() {
    let (mut state, unbound) = compact_unbound_service_state(0xd0a2);
    let receipt = state
        .cancel_unbound_service_request(unbound, ValidatedAbortProof::new(0xd0a2))
        .unwrap();
    assert_eq!(receipt.point, ServiceCancellationPoint::ReservedUnbound);
    assert_eq!(receipt.response, None);
    assert_eq!(receipt.bearer_generation, 2);
    let scope = state.scope(SCOPE).unwrap();
    assert_eq!(scope.live.continuations, 0);
    let service = scope.service_requests.get(COMPACT_SERVICE_REQUEST).unwrap();
    assert!(service.bound_continuation.is_none());
    assert!(matches!(
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
    assert_eq!(enqueue_plan.bearer_generation, 3);
    let enqueue_coordinates = service_bound_key_coordinates(&enqueue_authority.0);
    let mut bad_enqueue = service_enqueue_receipt(enqueue_plan, 0xd0a4);
    bad_enqueue.plan.apply_nonce = bad_enqueue.plan.apply_nonce.checked_add(1).unwrap();
    let before_bad_enqueue = state.private_full_clone();
    let failure = state
        .acknowledge_service_enqueue(enqueue_authority, bad_enqueue)
        .unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before_bad_enqueue);
    let enqueue_authority = failure.into_input();
    assert_eq!(
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
    assert_eq!(failure.error(), InfrastructureError::InvalidState);
    assert_eq!(state, before_forbidden_cancel);

    let (arm_plan, arm_authority) = state.begin_service_arm(unarmed).unwrap();
    assert_eq!(arm_plan.bearer_generation, 5);
    let arm_coordinates = service_bound_key_coordinates(&arm_authority.0);
    let mut bad_arm = service_arm_receipt(arm_plan, 0xd0a6);
    bad_arm.plan.arm_nonce = bad_arm.plan.arm_nonce.checked_add(1).unwrap();
    let before_bad_arm = state.private_full_clone();
    let failure = state
        .acknowledge_service_arm(arm_authority, bad_arm)
        .unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before_bad_arm);
    let arm_authority = failure.into_input();
    assert_eq!(
        service_bound_key_coordinates(&arm_authority.0),
        arm_coordinates
    );
    let enqueued = state
        .acknowledge_service_arm(arm_authority, service_arm_receipt(arm_plan, 0xd0a6))
        .unwrap();

    let service_workload = state
        .open_workload(
            WorkloadRootPresentation::new(SCOPE, 1, ROOT),
            WorkloadRequestPresentation::new(SERVICE, 1, 0xd0b0, 1),
        )
        .unwrap();
    let claimant = state
        .admit_task(
            &service_workload,
            TaskWorkDescriptor {
                work_id: 0xd0b1,
                generation: 1,
                task: TaskKey::new(0xd0b2, 1),
                role: TaskWorkRole::GuestSyscallWork,
                vm: Some(VmAuthorityKey::new(0xd0b3, 1).unwrap()),
            },
        )
        .unwrap();
    let claimant = state.claim_task_entry(claimant).unwrap();
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before_invalid_child);
    let enqueued = failure.into_input();
    assert_eq!(
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
    assert_eq!(bound.0.bearer_generation, 7);
    let service = state
        .scope(SCOPE)
        .unwrap()
        .service_requests
        .get(COMPACT_SERVICE_REQUEST)
        .unwrap();
    assert_eq!(state.scope(SCOPE).unwrap().revision, before_revision + 1);
    assert!(matches!(
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
        .get_mut(claimant.0.identity.work_id)
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
    assert_eq!(failure.error(), InfrastructureError::CounterOverflow);
    assert_eq!(state, before);
    assert_eq!(
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
    assert_eq!(failure.error(), InfrastructureError::CounterOverflow);
    assert_eq!(revision_state, before);
    assert_eq!(
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
    assert_eq!(
        failure.error(),
        InfrastructureError::Invariant("live counter underflow")
    );
    assert_eq!(workload_state, before);
    assert_eq!(
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
    assert_eq!(
        failure.error(),
        InfrastructureError::Invariant("live counter underflow")
    );
    assert_eq!(parent_state, before);
    assert_eq!(
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before);
    assert_eq!(
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before);
    assert_eq!(
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before);
    assert_eq!(
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before);
    assert_eq!(
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before);
    assert_eq!(
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before);
    assert_eq!(
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
            _ => unreachable!(),
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before);
    assert_eq!(
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
            unreachable!();
        }
    }
    plan.apply_generation += 1;
    state.check_invariants().unwrap();
    let coordinates = service_bound_key_coordinates(&authority.0);
    let before = state.private_full_clone();
    let failure = state
        .acknowledge_service_enqueue(authority, service_enqueue_receipt(plan, 0xd541))
        .unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before);
    assert_eq!(
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
        unreachable!();
    }
    state.check_invariants().unwrap();
    let coordinates = service_bound_key_coordinates(&unarmed.0);
    let before = state.private_full_clone();
    let failure = state.begin_service_arm(unarmed).unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before);
    assert_eq!(
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
            unreachable!();
        }
    }
    arm_plan.arm_generation += 1;
    state.check_invariants().unwrap();
    let coordinates = service_bound_key_coordinates(&arm_authority.0);
    let before = state.private_full_clone();
    let failure = state
        .acknowledge_service_arm(arm_authority, service_arm_receipt(arm_plan, 0xd546))
        .unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before);
    assert_eq!(
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
        unreachable!();
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before);
    assert_eq!(
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
    assert_eq!(compact_bearer_generation(&state), 1);

    let before_claim = state.private_full_clone();
    let failure = state.claim_continuation(continuation, 0).unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::InvalidIdentity);
    assert_eq!(state, before_claim);
    let continuation = failure.into_input();

    let claim = state.claim_continuation(continuation, 0xd8).unwrap();
    assert_eq!(compact_bearer_generation(&state), 2);
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before_publication);
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
    assert_eq!(compact_bearer_generation(&state), 3);
    let publication_plan = publication.plan();
    assert_eq!(publication_plan, publication.plan());
    assert_eq!(
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before_ack);
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before_ack);
    let authority = failure.into_input();
    let acknowledgement = ContinuationPublicationAckReceipt {
        external_receipt_digest: 0xd9,
        ..acknowledgement
    };
    let ack = state
        .acknowledge_continuation_publication(authority, acknowledgement)
        .unwrap();
    assert_eq!(compact_bearer_generation(&state), 4);

    let resume = state.begin_continuation_resume(ack).unwrap();
    assert_eq!(compact_bearer_generation(&state), 5);
    let resume_plan = resume.plan();
    assert_eq!(resume_plan, resume.plan());
    assert_eq!(resume_plan.publication_ack, acknowledgement);
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before_complete);
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
    assert_eq!(compact_bearer_generation(&state), 6);
    state.check_invariants().unwrap();
}

#[test]
fn foreign_registry_rejects_compact_continuation_and_returns_it() {
    let (mut owner, _, _, continuation) = compact_continuation_state(0xd011);
    let (mut foreign, _, _, _foreign_continuation) = compact_continuation_state(0xd012);
    let before_owner = owner.private_full_clone();
    let before_foreign = foreign.private_full_clone();

    let failure = foreign.claim_continuation(continuation, 0xda).unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::ForeignRegistry);
    assert_eq!(foreign, before_foreign);
    assert_eq!(owner, before_owner);

    owner
        .claim_continuation(failure.into_input(), 0xda)
        .unwrap();
    assert_eq!(compact_bearer_generation(&owner), 2);
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
    assert_eq!(
        state
            .adopt_continuation_after_fence(&workload, COMPACT_CONTINUATION, 1, 2)
            .unwrap_err(),
        InfrastructureError::StaleBinding
    );
    assert_eq!(state, before_parent_adoption);
    assert!(matches!(
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
    assert_eq!(
        missing_index
            .adopt_continuation_after_fence(&workload, COMPACT_CONTINUATION, 1, 2)
            .unwrap_err(),
        InfrastructureError::Invariant("missing continuation reverse index")
    );
    assert_eq!(missing_index, before_missing_index);

    let current = match state
        .adopt_continuation_after_fence(&workload, COMPACT_CONTINUATION, 1, 2)
        .unwrap()
    {
        ContinuationAdoption::Pending(lease) => lease,
        _ => panic!("pending continuation adopted into the wrong phase"),
    };
    assert_eq!(compact_bearer_generation(&state), 2);
    state.check_invariants().unwrap();

    let before_stale = state.private_full_clone();
    let failure = state.claim_continuation(stale, 0xdb).unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::StaleGeneration);
    assert_eq!(state, before_stale);
    state.claim_continuation(current, 0xdb).unwrap();
    assert_eq!(compact_bearer_generation(&state), 3);
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
    assert!(matches!(
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
        _ => panic!("acknowledged continuation adopted into the wrong phase"),
    };
    let projection = state
        .query_continuation(&workload, COMPACT_CONTINUATION, 1)
        .unwrap();
    assert_eq!(projection.descriptor.source_binding_epoch, 2);
    assert_eq!(projection.publication_ack, Some(acknowledgement));
    assert_eq!(projection.publication_ack.unwrap().source_binding_epoch, 1);

    let before_stale = state.private_full_clone();
    let failure = state.begin_continuation_resume(stale_ack).unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::StaleGeneration);
    assert_eq!(state, before_stale);

    let stale_resume = state.begin_continuation_resume(current_ack).unwrap();
    let stale_resume_plan = stale_resume.plan();
    assert_eq!(stale_resume_plan.descriptor.source_binding_epoch, 2);
    assert_eq!(stale_resume_plan.publication_ack, acknowledgement);

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
    assert!(matches!(
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
        _ => panic!("resuming continuation adopted into the wrong phase"),
    };
    let before_stale_resume = state.private_full_clone();
    let failure = state
        .complete_continuation_resume(
            stale_resume.into_authority(),
            continuation_resume_receipt(stale_resume_plan, 0xdb03),
        )
        .unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::StaleGeneration);
    assert_eq!(state, before_stale_resume);

    let current_resume_plan = current_resume.plan();
    assert_eq!(current_resume_plan.descriptor.source_binding_epoch, 3);
    assert_eq!(current_resume_plan.publication_ack, acknowledgement);
    let before_substitution = state.private_full_clone();
    let failure = state
        .complete_continuation_resume(
            current_resume.into_authority(),
            continuation_resume_receipt(stale_resume_plan, 0xdb03),
        )
        .unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before_substitution);
    state
        .complete_continuation_resume(
            failure.into_input(),
            continuation_resume_receipt(current_resume_plan, 0xdb04),
        )
        .unwrap();
    let projection = state
        .query_continuation(&workload, COMPACT_CONTINUATION, 1)
        .unwrap();
    assert_eq!(projection.publication_ack, Some(acknowledgement));
    assert_eq!(
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
    assert_eq!(compact_bearer_generation(&state), 1);
    let historical_generation = state
        .scope(SCOPE)
        .unwrap()
        .service_requests
        .get(COMPACT_SERVICE_REQUEST)
        .unwrap()
        .bound_continuation
        .unwrap()
        .bearer_generation;
    assert_eq!(historical_generation, 1);

    let cancelled = state
        .cancel_bound_service_request(service, ValidatedAbortProof::new(0xdc))
        .unwrap();
    assert_eq!(cancelled.receipt.bearer_generation, 3);
    assert_eq!(
        cancelled.receipt.response.unwrap().continuation_id,
        COMPACT_CONTINUATION
    );
    assert_eq!(compact_bearer_generation(&state), 2);
    assert!(
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
    assert_eq!(projection.state, ServiceRequestRecoveryState::Cancelled);
    assert_eq!(projection.cancellation_receipt, Some(cancelled.receipt));
    assert_eq!(projection.enqueue_receipt, None);
    assert_eq!(projection.arm_receipt, None);
    assert_eq!(projection.child_binding_receipt, None);
    assert_eq!(projection.completion_receipt, None);

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
    assert_eq!(compact_bearer_generation(&state), 3);
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
    assert_eq!(enqueue_plan.bearer_generation, 3);
    let enqueue_receipt = service_enqueue_receipt(enqueue_plan, 0xde);
    let unarmed = state
        .acknowledge_service_enqueue(enqueue_authority, enqueue_receipt)
        .unwrap();
    let (arm_plan, arm_authority) = state.begin_service_arm(unarmed).unwrap();
    assert_eq!(arm_plan.bearer_generation, 5);
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
                role: TaskWorkRole::GuestSyscallWork,
                vm: Some(VmAuthorityKey::new(0xe600, 1).unwrap()),
            },
        )
        .unwrap();
    let claimant = state.claim_task_entry(claimant).unwrap();
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
    assert!(binding_receipt.is_some());
    let binding_receipt = binding_receipt.unwrap();
    assert_eq!(binding_receipt.service_bearer_generation, 7);
    assert_eq!(binding_receipt.claim_generation, 1);
    assert_eq!(binding_receipt.claimant.task, claimant.0.identity);
    assert_eq!(
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
        assert!(replaced);
        assert_invariant_read_only(substituted.private_full_clone());
        let coordinates = service_bound_key_coordinates(&bound.0);
        let before = substituted.private_full_clone();
        let failure = substituted
            .complete_service_request(bound, 0xe9)
            .unwrap_err();
        assert!(matches!(
            failure.error(),
            InfrastructureError::InvalidReceipt | InfrastructureError::InvalidState
        ));
        assert_eq!(substituted, before);
        bound = failure.into_input();
        assert_eq!(service_bound_key_coordinates(&bound.0), coordinates);
    }

    let mut substituted_claimant = state.private_full_clone();
    let alternate_snapshot = ServiceClaimantSnapshot {
        registry_instance: alternate_claimant.0.root.registry_instance,
        scope: alternate_claimant.0.root.scope,
        authority_epoch: alternate_claimant.0.root.authority_epoch,
        root_effect: alternate_claimant.0.root.root_effect,
        workload_request_id: alternate_claimant.0.workload.request.id,
        workload_request_generation: alternate_claimant.0.workload.request.generation,
        workload_nonce: alternate_claimant.0.workload.nonce,
        workload_bearer_generation: alternate_claimant.0.workload.bearer_generation,
        domain: alternate_claimant.0.domain.domain,
        binding_epoch: alternate_claimant.0.domain.binding_epoch,
        task: alternate_claimant.0.identity,
        task_nonce: alternate_claimant.0.nonce,
        task_bearer_generation: alternate_claimant.0.bearer_generation,
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
            _ => unreachable!(),
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(substituted_claimant, before);
    bound = failure.into_input();
    assert_eq!(service_bound_key_coordinates(&bound.0), coordinates);

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
    assert_eq!(failure.error(), InfrastructureError::InvalidState);
    assert_eq!(corrupted_claimant, before_corrupt_completion);
    bound = failure.into_input();
    assert_eq!(
        service_bound_key_coordinates(&bound.0),
        corrupted_bound_coordinates
    );

    let before_early_reap = state.private_full_clone();
    let failure = state.reap_task(claimant).unwrap_err();
    assert!(matches!(
        failure.error(),
        InfrastructureError::ClosureBlocked { live: 1, .. }
    ));
    assert_eq!(state, before_early_reap);
    let _claimant = failure.into_input();
    let claim_nonce = state
        .scope(SCOPE)
        .unwrap()
        .service_requests
        .get(COMPACT_SERVICE_REQUEST)
        .unwrap()
        .claim_nonce_high_water;
    let outcome = state.complete_service_request(bound, 0xe9).unwrap();
    assert_eq!(outcome.receipt.bearer_generation, 8);
    assert_eq!(compact_bearer_generation(&state), 2);
    let service = state
        .scope(SCOPE)
        .unwrap()
        .service_requests
        .get(COMPACT_SERVICE_REQUEST)
        .unwrap();
    assert!(service.bound_continuation.is_none());
    assert_eq!(
        service.bound_commitment,
        Some(outcome.receipt.lineage_commitment)
    );
    assert!(matches!(
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
    assert_eq!(service.apply_nonce_high_water, enqueue_plan.apply_nonce);
    assert_eq!(service.arm_nonce_high_water, arm_plan.arm_nonce);
    assert_eq!(service.claim_nonce_high_water, claim_nonce);
    let projection = state
        .query_service_request(&guest_workload, COMPACT_SERVICE_REQUEST, 1)
        .unwrap();
    assert_eq!(projection.state, ServiceRequestRecoveryState::Completed);
    assert_eq!(projection.enqueue_receipt, Some(enqueue_receipt));
    assert_eq!(projection.arm_receipt, Some(arm_receipt));
    assert_eq!(projection.child_binding_receipt, Some(binding_receipt));
    assert_eq!(projection.completion_receipt, Some(outcome.receipt));
    assert_eq!(projection.cancellation_receipt, None);

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
            _ => unreachable!(),
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
        assert!(replaced);
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
    let mut entered_claimant = None;
    if let TaskAdoption::Entered(entered) = adopted_claimant {
        entered_claimant = Some(entered);
    }
    assert!(entered_claimant.is_some());
    state.reap_task(entered_claimant.unwrap()).unwrap();
    state.check_invariants().unwrap();

    state.claim_continuation(outcome.response, 0xea).unwrap();
    assert_eq!(compact_bearer_generation(&state), 3);
    state.check_invariants().unwrap();
}

#[test]
fn deadline_compact_authority_layout_is_bounded() {
    assert!(core::mem::size_of::<BearerKey<bearer_state::DeadlineArmed>>() <= 64);
    assert!(core::mem::size_of::<BearerKey<bearer_state::DeadlineFired>>() <= 64);
    assert!(core::mem::size_of::<BearerKey<bearer_state::DeadlineExhausted>>() <= 64);
    assert!(core::mem::size_of::<BearerKey<bearer_state::DeadlineQuarantined>>() <= 64);
    assert!(core::mem::size_of::<DeadlineLease>() <= 96);
    assert!(core::mem::size_of::<DeadlineExpiryReceipt>() <= 96);
    assert!(core::mem::size_of::<DeadlineQuarantineTicket>() <= 96);
    assert!(core::mem::size_of::<LinearFailure<DeadlineLease>>() <= 120);
    assert!(core::mem::size_of::<LinearFailure<DeadlineExpiryReceipt>>() <= 120);
    assert!(core::mem::size_of::<LinearFailure<DeadlineQuarantineTicket>>() <= 120);
}

#[test]
fn device_closure_deadline_fails_closed_without_device_owner() {
    let (mut state, _, entered, _) = compact_deadline_state(0xf001, 2);
    let before = state.private_full_clone();
    assert_eq!(
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
    assert_eq!(state, before);
}

#[test]
fn deadline_rearm_is_failure_atomic_and_exhaustion_is_retained() {
    let (mut state, workload, _, deadline) = compact_deadline_state(0xf011, 2);
    let initial_nonce = deadline_coordinates(&state).2;
    let before_early = state.private_full_clone();
    let failure = state
        .fire_deadline(deadline, DeadlineClockBasis::ObservedCallbackTick, 9)
        .unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::InvalidState);
    assert_eq!(state, before_early);
    let deadline = failure.into_input();

    let expiry = state
        .fire_deadline(deadline, DeadlineClockBasis::ObservedCallbackTick, 10)
        .unwrap();
    let fired = deadline_coordinates(&state);
    assert_eq!((fired.0, fired.1), (1, 2));
    assert_ne!(fired.2, initial_nonce);
    let projection = state
        .query_deadline(&workload, COMPACT_DEADLINE, 1)
        .unwrap();
    assert_eq!(projection.state, DeadlineRecoveryState::Fired);
    assert_eq!(projection.observed_tick, Some(10));

    let before_bad_generation = state.private_full_clone();
    let failure = state.rearm_deadline(expiry, 3, 15).unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::StaleGeneration);
    assert_eq!(state, before_bad_generation);
    let expiry = failure.into_input();
    let deadline = state.rearm_deadline(expiry, 2, 15).unwrap();
    let rearmed = deadline_coordinates(&state);
    assert_eq!((rearmed.0, rearmed.1), (2, 3));
    assert_ne!(rearmed.2, fired.2);

    let exhausted = state
        .fire_deadline(deadline, DeadlineClockBasis::ObservedCallbackTick, 15)
        .unwrap();
    assert_eq!(deadline_coordinates(&state).1, 4);
    let before_retained = state.private_full_clone();
    let failure = state.rearm_deadline(exhausted, 3, 20).unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::ClosureRetained);
    assert_eq!(state, before_retained);
    let exhausted = failure.into_input();
    let failure = state.resolve_fired_deadline(exhausted).unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::ClosureRetained);
    assert_eq!(state, before_retained);
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
    assert_eq!(failure.error(), InfrastructureError::ForeignRegistry);
    assert_eq!(foreign, before_foreign);
    assert_eq!(owner, before_owner);

    owner
        .fire_deadline(
            failure.into_input(),
            DeadlineClockBasis::ObservedCallbackTick,
            10,
        )
        .unwrap();
    assert_eq!(deadline_coordinates(&owner).1, 2);
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
        DeadlineExpiryAuthority::Exhausted(_) => panic!("nonterminal attempt exhausted"),
    };
    let forged_exhausted = DeadlineExpiryReceipt(DeadlineExpiryAuthority::Exhausted(BearerKey {
        authority: fired_key.authority,
        slot: fired_key.slot,
        object_generation: fired_key.object_generation,
        bearer_generation: fired_key.bearer_generation,
        nonce: fired_key.nonce,
        state: core::marker::PhantomData,
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
    assert_eq!(failure.error(), InfrastructureError::StaleClaim);
    assert_eq!(fired_state, before_fired);

    let (mut exhausted_state, _, _, deadline) = compact_deadline_state(0xf02a, 1);
    let exhausted = exhausted_state
        .fire_deadline(deadline, DeadlineClockBasis::ObservedCallbackTick, 10)
        .unwrap();
    let exhausted_key = match exhausted.0 {
        DeadlineExpiryAuthority::Exhausted(key) => key,
        DeadlineExpiryAuthority::Fired(_) => panic!("terminal attempt did not exhaust"),
    };
    let forged_fired = DeadlineExpiryReceipt(DeadlineExpiryAuthority::Fired(BearerKey {
        authority: exhausted_key.authority,
        slot: exhausted_key.slot,
        object_generation: exhausted_key.object_generation,
        bearer_generation: exhausted_key.bearer_generation,
        nonce: exhausted_key.nonce,
        state: core::marker::PhantomData,
    }));
    let before_exhausted = exhausted_state.private_full_clone();
    let failure = exhausted_state
        .resolve_fired_deadline(forged_fired)
        .unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::StaleClaim);
    assert_eq!(exhausted_state, before_exhausted);
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
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before_invalid);

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
        _ => panic!("supervisor retry returned the wrong outcome"),
    };
    let retried = deadline_coordinates(&state);
    assert_eq!((retried.0, retried.1), (2, 3));
    assert_ne!(retried.2, exhausted_coordinates.2);
    let projection = state
        .query_deadline(&workload, COMPACT_DEADLINE, 2)
        .unwrap();
    assert_eq!(projection.state, DeadlineRecoveryState::Armed);
    assert_eq!(projection.reconciliation, Some(reconciliation));
    assert_eq!(projection.descriptor.attempt, 1);
    assert_eq!(projection.descriptor.max_attempts, 2);
    assert_eq!(projection.descriptor.backoff_ticks, 4);
    state.check_invariants().unwrap();

    let mut high_water_rollback = state.private_full_clone();
    high_water_rollback.scope_mut(SCOPE).unwrap().next_nonce = retried.2;
    assert_invariant_read_only(high_water_rollback);

    state.cancel_deadline(deadline).unwrap();
    assert_eq!(deadline_coordinates(&state).1, 4);
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
        _ => panic!("quarantine reconciliation returned the wrong outcome"),
    };
    let quarantined = deadline_coordinates(&state);
    assert_eq!(quarantined.1, 3);
    let before_bad_release = state.private_full_clone();
    let failure = state
        .resolve_quarantined_deadline(
            ticket,
            DeadlineQuarantineReleaseReceipt { evidence_digest: 0 },
        )
        .unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::InvalidReceipt);
    assert_eq!(state, before_bad_release);
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
    assert_eq!(
        state
            .adopt_deadline_after_fence(&workload, COMPACT_DEADLINE, 1)
            .unwrap_err(),
        InfrastructureError::StaleBinding
    );
    assert_eq!(state, before_parent_adoption);
    assert!(matches!(
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
    assert_eq!(
        missing_index
            .adopt_deadline_after_fence(&workload, COMPACT_DEADLINE, 1)
            .unwrap_err(),
        InfrastructureError::Invariant("missing deadline reverse index")
    );
    assert_eq!(missing_index, before_missing_index);

    let current_ticket = match state
        .adopt_deadline_after_fence(&workload, COMPACT_DEADLINE, 1)
        .unwrap()
    {
        DeadlineAdoption::Quarantined(ticket) => ticket,
        _ => panic!("quarantined deadline adopted into the wrong phase"),
    };
    let adopted = deadline_coordinates(&state);
    assert_eq!(adopted.1, 4);
    assert_ne!(adopted.2, quarantined.2);
    let before_stale = state.private_full_clone();
    let failure = state
        .resolve_quarantined_deadline(
            stale_ticket,
            DeadlineQuarantineReleaseReceipt {
                evidence_digest: 0xf42,
            },
        )
        .unwrap_err();
    assert_eq!(failure.error(), InfrastructureError::StaleGeneration);
    assert_eq!(state, before_stale);

    state
        .resolve_quarantined_deadline(
            current_ticket,
            DeadlineQuarantineReleaseReceipt {
                evidence_digest: 0xf43,
            },
        )
        .unwrap();
    assert_eq!(deadline_coordinates(&state).1, 5);
    let projection = state
        .query_deadline(&workload, COMPACT_DEADLINE, 1)
        .unwrap();
    assert_eq!(projection.state, DeadlineRecoveryState::Resolved);
    assert_eq!(projection.reconciliation, Some(quarantine_receipt));
    assert_eq!(projection.terminal_evidence_digest, Some(0xf43));
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
    assert_eq!(deadline_coordinates(&cancelled).1, 2);
    assert_eq!(
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
    assert_eq!(deadline_coordinates(&resolved).1, 3);
    assert_eq!(
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
    assert!(matches!(
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
    assert_eq!(deadline_coordinates(&aborted).1, 3);
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
                queue_slots: 1,
                pinned_pages: 2,
                dma_mappings: 1,
                actor_slot: 2,
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
        state: core::marker::PhantomData,
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
        _ => panic!("test service bound key requires a live bound phase"),
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
        state: core::marker::PhantomData,
    }
}

fn record_service_causal_identity(
    record: &super::ServiceRequestStateRecord,
    response: ContinuationDescriptor,
) -> ServiceRequestCausalIdentity {
    let parent_task = match record.stamp.parent {
        super::ParentStamp::Task(parent) => parent,
        _ => unreachable!(),
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
    assert!(matches!(
        state.check_invariants(),
        Err(InfrastructureError::Invariant(_))
    ));
    assert_eq!(state, before);
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
    let fault = state
        .reserve_fault_event(
            &task,
            FaultDescriptor {
                fault_id: 0xb700,
                generation: 1,
                task: task_key,
                vm_generation: 1,
                instruction_pointer: 0xb800,
                address: 0xb900,
                access: FaultAccess::Read,
                architecture_error: 0xba,
                service_domain: SERVICE,
                service_binding_epoch: 1,
            },
        )
        .unwrap();
    let (entered, armed) = state.claim_service_task_entry(task, fault).unwrap();
    let (next_binding_epoch, crash_generation) = match disposition {
        FaultDisposition::CrashService => (2, 1),
        FaultDisposition::IsolateTask => (1, 0),
    };
    let plan = state
        .prepare_fault_disposition(
            armed,
            entered,
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
            next_binding_epoch,
            crash_generation,
        )
        .unwrap();
    let base = state.root_binding(SCOPE).unwrap();
    let mut candidate = state.try_private_candidate().unwrap();
    candidate
        .apply_fault_disposition_in_candidate(plan)
        .unwrap();
    candidate.check_invariants().unwrap();
    let install = state
        .prepare_exact_scope_install(SCOPE, base, &mut candidate)
        .unwrap();
    state.install_exact_scope(install);
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
    let scope = closure.scope_mut(SCOPE).unwrap();
    scope.workloads.iter_mut().next().unwrap().closure_sequence = Some(1);
    scope.next_closure_sequence = 2;
    closure.check_invariants().unwrap();
    closure.scope_mut(SCOPE).unwrap().next_closure_sequence = 1;
    assert_invariant_read_only(closure);
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
    if let FaultPhase::Observed {
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
    if let FaultPhase::Observed {
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
    let fault = later_crash
        .reserve_fault_event(
            &task,
            FaultDescriptor {
                fault_id: 0xc700,
                generation: 1,
                task: task_key,
                vm_generation: 1,
                instruction_pointer: 0xc800,
                address: 0xc900,
                access: FaultAccess::Read,
                architecture_error: 0xca,
                service_domain: SERVICE,
                service_binding_epoch: 1,
            },
        )
        .unwrap();
    let (entered, armed) = later_crash.claim_service_task_entry(task, fault).unwrap();
    let plan = later_crash
        .prepare_fault_disposition(
            armed,
            entered,
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
            2,
            1,
        )
        .unwrap();
    let base = later_crash.root_binding(SCOPE).unwrap();
    let mut candidate = later_crash.try_private_candidate().unwrap();
    candidate
        .apply_fault_disposition_in_candidate(plan)
        .unwrap();
    candidate.check_invariants().unwrap();
    let install = later_crash
        .prepare_exact_scope_install(SCOPE, base, &mut candidate)
        .unwrap();
    later_crash.install_exact_scope(install);
    later_crash.check_invariants().unwrap();

    let mut fabricated_crash = isolate.private_full_clone();
    let fault = fabricated_crash
        .scope_mut(SCOPE)
        .unwrap()
        .faults
        .iter_mut()
        .next()
        .unwrap();
    if let FaultPhase::Observed {
        ref mut projection, ..
    } = fault.phase
    {
        projection.crash_generation = 1;
    }
    assert_invariant_read_only(fabricated_crash);
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
    assert!(replaced);
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
    assert!(replaced);
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
