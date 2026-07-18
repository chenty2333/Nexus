// SPDX-License-Identifier: MPL-2.0

use super::{
    ContinuationDescriptor, ContinuationPublicationReceipt, DeviceReservationCoordinates,
    DomainKey, EffectKey, FaultAccess, FaultDescriptor, FaultDisposition, FaultObservation,
    FaultPhase, InfrastructureError, InfrastructureLimits, InfrastructureState, ResourceKey,
    ScopeKey, ServiceRequestDescriptor, ServiceRequestPhase, ServiceRequestTicket, TaskKey,
    TaskPhase, TaskWorkDescriptor, TaskWorkRole, ValidatedAbortProof, VmAuthorityKey,
    WorkloadRequestPresentation, WorkloadRootPresentation,
};

const SCOPE: ScopeKey = ScopeKey::new(0x9100, 1);
const ROOT: EffectKey = EffectKey::new(0x9200, 1);
const GUEST: DomainKey = DomainKey::new(0x91);
const SERVICE: DomainKey = DomainKey::new(0x92);

fn limits() -> InfrastructureLimits {
    InfrastructureLimits::new(8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 16, 8, 8).unwrap()
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
