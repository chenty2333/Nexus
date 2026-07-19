// SPDX-License-Identifier: MPL-2.0

use super::{
    AuthorityKey, BearerKey, ContinuationAckReceipt, ContinuationAdoption, ContinuationDescriptor,
    ContinuationLease, ContinuationPublicationAckReceipt, ContinuationPublicationAuthority,
    ContinuationPublicationReceipt, ContinuationResumeAuthority, ContinuationResumePlan,
    ContinuationResumeReceipt, DeviceReservationCoordinates, DomainKey, EffectKey,
    EnteredTaskLease, FaultAccess, FaultDescriptor, FaultDisposition, FaultObservation, FaultPhase,
    InfrastructureError, InfrastructureLimits, InfrastructureState, LinearFailure, ResourceKey,
    ScopeKey, ServiceArmReceipt, ServiceChildReceipt, ServiceEnqueueReceipt,
    ServiceRequestDescriptor, ServiceRequestPhase, ServiceRequestTicket, TaskAdoption, TaskKey,
    TaskPhase, TaskWorkDescriptor, TaskWorkRole, ValidatedAbortProof, ValidatedServiceChildProof,
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

fn compact_continuation_state(
    registry_instance: u64,
) -> (
    InfrastructureState,
    WorkloadContext,
    EnteredTaskLease,
    ContinuationLease,
) {
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
    let (mut state, _, entered, continuation) = compact_continuation_state(registry_instance);
    let service = state
        .reserve_service_request(
            &entered,
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
            },
        )
        .unwrap();
    let service = state
        .bind_service_response_continuation(service, continuation)
        .unwrap();
    (state, service)
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
    assert_eq!(compact_bearer_generation(&state), 2);
    let historical_generation = state
        .scope(SCOPE)
        .unwrap()
        .service_requests
        .get(COMPACT_SERVICE_REQUEST)
        .unwrap()
        .bound_continuation
        .unwrap()
        .bearer_generation;
    assert_eq!(historical_generation, 2);

    let continuation = state
        .cancel_service_request(service, ValidatedAbortProof::new(0xdc))
        .unwrap()
        .unwrap();
    assert_eq!(compact_bearer_generation(&state), 3);
    assert_eq!(
        state
            .scope(SCOPE)
            .unwrap()
            .service_requests
            .get(COMPACT_SERVICE_REQUEST)
            .unwrap()
            .bound_continuation
            .unwrap()
            .bearer_generation,
        historical_generation
    );
    state.claim_continuation(continuation, 0xdd).unwrap();
    assert_eq!(compact_bearer_generation(&state), 4);
    state.check_invariants().unwrap();
}

#[test]
fn service_completion_returns_fresh_compact_continuation_authority() {
    let (mut state, service) = compact_bound_service_state(0xd041);
    let enqueue = state.begin_service_enqueue(service).unwrap();
    let unarmed = state
        .acknowledge_service_enqueue(
            enqueue,
            ServiceEnqueueReceipt {
                queue: ResourceKey::new(0xda, 1, 1),
                queue_generation: 1,
                payload_slot: 3,
                payload_generation: 1,
                transport_receipt_digest: 0xde,
            },
        )
        .unwrap();
    let arm = state.begin_service_arm(unarmed).unwrap();
    let arm_generation = arm.arm_generation;
    let enqueued = state
        .acknowledge_service_arm(
            arm,
            ServiceArmReceipt {
                response_slot_id: COMPACT_RESPONSE_SLOT,
                response_slot_generation: 1,
                bound_continuation_id: COMPACT_CONTINUATION,
                bound_continuation_generation: 1,
                arm_generation,
                transport_receipt_digest: 0xdf,
            },
        )
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
    let claim = state.claim_service_request(enqueued, &claimant).unwrap();
    let bound = state
        .bind_service_child(
            claim,
            ValidatedServiceChildProof::new(ServiceChildReceipt {
                child_effect: EffectKey::new(0xe700, 1),
                registration_digest: 0xe8,
            }),
        )
        .unwrap();
    let outcome = state.complete_service_request(bound, 0xe9).unwrap();
    assert_eq!(compact_bearer_generation(&state), 3);
    state.claim_continuation(outcome.response, 0xea).unwrap();
    assert_eq!(compact_bearer_generation(&state), 4);
    state.check_invariants().unwrap();
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
    let continuation = state
        .create_continuation(
            &entered,
            ContinuationDescriptor {
                continuation_id: 0x9700,
                generation: 1,
                vm_generation: 1,
                source_domain: GUEST,
                source_binding_epoch: 1,
            },
        )
        .unwrap();
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
        .bind_service_response_continuation(service, continuation)
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
    let request_stamp = terminal
        .scope(SCOPE)
        .unwrap()
        .service_requests
        .iter()
        .next()
        .unwrap()
        .stamp;
    terminal
        .cancel_service_request(
            ServiceRequestTicket(request_stamp),
            ValidatedAbortProof::new(0xc1),
        )
        .unwrap();
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
