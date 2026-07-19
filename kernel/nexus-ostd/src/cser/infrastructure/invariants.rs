// SPDX-License-Identifier: MPL-2.0

use alloc::vec::Vec;

use super::fault::{exit_receipt_digest, validate_exact_task_fault_pair};
use super::{
    BearerStamp, ContinuationPhase, ContinuationRecord, DeadlineExhaustedDisposition,
    DeadlinePhase, DeadlineRecord, DelayedCommandPhase, DelayedCommandStateRecord, DevicePhase,
    DeviceRecord, DeviceReservationCoordinates, FaultDisposition, FaultPhase, FaultStateRecord,
    FixedSlots, InfrastructureError, InfrastructureKind, InfrastructureLiveCounts, ParentStamp,
    ReplyPhase, ReplyStateRecord, RequestKey, ResourceUsage, ReverseIndexRecord, ReverseParent,
    ScopeInfrastructure, ServiceArmReceipt, ServiceCancellationPoint, ServiceChildBindingReceipt,
    ServiceClaimantSnapshot, ServiceEnqueueReceipt, ServiceRequestCausalIdentity,
    ServiceRequestPhase, ServiceRequestStateRecord, SlotIdentity, TaskAnchorPhase, TaskPhase,
    TaskWorkDescriptor, VmAuthorityKey, WorkloadPhase, delayed_command_phase_live,
    device_phase_live, reverse_index_for_fault, reverse_index_for_task, service_request_phase_live,
    validate_continuation_publication_ack,
};

pub(super) fn check_scope_invariants(
    scope: &ScopeInfrastructure,
) -> Result<(), InfrastructureError> {
    validate_scope_slot_shape(scope)?;

    if scope.active != scope.closure.is_none() {
        return Err(InfrastructureError::Invariant(
            "infrastructure lifecycle projection mismatch",
        ));
    }

    let primary_count = [
        scope.workloads.iter().count(),
        scope.tasks.iter().count(),
        scope.service_requests.iter().count(),
        scope.delayed_commands.iter().count(),
        scope.faults.iter().count(),
        scope.continuations.iter().count(),
        scope.deadlines.iter().count(),
        scope.devices.iter().count(),
        scope.replies.iter().count(),
    ]
    .into_iter()
    .try_fold(0_usize, |total, count| total.checked_add(count))
    .ok_or(InfrastructureError::Invariant(
        "infrastructure primary cardinality overflow",
    ))?;
    let mut expected_indexes = Vec::new();
    expected_indexes
        .try_reserve_exact(primary_count)
        .map_err(|_| InfrastructureError::AllocationFailed)?;
    let mut expected_live = InfrastructureLiveCounts::default();
    let mut expected_usage = ResourceUsage::default();
    let mut workload_children = Vec::new();
    workload_children
        .try_reserve_exact(scope.workloads.iter().count())
        .map_err(|_| InfrastructureError::AllocationFailed)?;
    workload_children.extend(scope.workloads.iter().map(|record| (record.request, 0_u32)));
    let mut task_children = Vec::new();
    task_children
        .try_reserve_exact(scope.tasks.iter().count())
        .map_err(|_| InfrastructureError::AllocationFailed)?;
    task_children.extend(
        scope
            .tasks
            .iter()
            .map(|record| (record.stamp.identity, 0_u32)),
    );

    for record in scope.workloads.iter() {
        let current_epoch = scope
            .binding_epoch(record.domain)
            .map_err(|_| InfrastructureError::Invariant("workload references unknown domain"))?;
        if record.request.id == 0
            || record.request.generation == 0
            || record.root_effect != scope.root.root_effect
            || record.parent != ParentStamp::RootEffect(scope.root.root_effect)
            || record.nonce == 0
            || record.bearer_generation == 0
            || record.admission_binding_epoch == 0
            || record.admission_binding_epoch > record.current_binding_epoch
            || record.current_binding_epoch > current_epoch
        {
            return Err(InfrastructureError::Invariant(
                "invalid workload primary record",
            ));
        }
        if record.phase == WorkloadPhase::Open {
            increment_invariant(&mut expected_live.workloads)?;
        }
        push_expected_index(
            &mut expected_indexes,
            ReverseIndexRecord {
                slot: record.nonce,
                kind: InfrastructureKind::Workload,
                root_effect: record.root_effect,
                parent: ReverseParent::RootEffect(record.root_effect),
                task: None,
                domain: record.domain,
                binding_epoch: record.current_binding_epoch,
                source_domain: None,
                source_binding_epoch: None,
                resource: None,
                actor_slot: None,
                retry_generation: record.request.generation,
            },
        )?;
    }

    for record in scope.tasks.iter() {
        record
            .stamp
            .identity
            .validate()
            .map_err(|_| InfrastructureError::Invariant("invalid task descriptor"))?;
        validate_primary_stamp(scope, &record.stamp)?;
        if record.stamp.parent != ParentStamp::Request(record.stamp.workload.request) {
            return Err(InfrastructureError::Invariant("invalid task parent"));
        }
        if task_phase_live(record.phase) {
            increment_invariant(&mut expected_live.tasks)?;
            increment_workload_child(&mut workload_children, record.stamp.workload.request)?;
        }
        push_expected_index(&mut expected_indexes, reverse_index_for_task(record))?;
    }

    for record in scope.service_requests.iter() {
        record
            .stamp
            .identity
            .validate()
            .map_err(|_| InfrastructureError::Invariant("invalid service descriptor"))?;
        validate_task_child_stamp(scope, &record.stamp)?;
        check_service_phase(scope, record)?;
        if service_request_phase_live(record.phase) {
            increment_invariant(&mut expected_live.service_requests)?;
            account_live_task_child(&mut workload_children, &mut task_children, &record.stamp)?;
        }
        if let ServiceRequestPhase::ChildBound {
            binding_receipt, ..
        } = record.phase
        {
            increment_task_child(&mut task_children, binding_receipt.claimant.task)?;
        }
        push_expected_index(&mut expected_indexes, reverse_index_for_service(record))?;
    }

    for record in scope.delayed_commands.iter() {
        record
            .stamp
            .identity
            .validate()
            .map_err(|_| InfrastructureError::Invariant("invalid delayed descriptor"))?;
        validate_task_child_stamp(scope, &record.stamp)?;
        if delayed_command_phase_live(record.phase) {
            increment_invariant(&mut expected_live.delayed_commands)?;
            account_live_task_child(&mut workload_children, &mut task_children, &record.stamp)?;
        }
        push_expected_index(&mut expected_indexes, reverse_index_for_delayed(record))?;
    }

    for record in scope.faults.iter() {
        record
            .stamp
            .identity
            .validate()
            .map_err(|_| InfrastructureError::Invariant("invalid fault descriptor"))?;
        validate_task_child_stamp(scope, &record.stamp)?;
        let parent = task_parent(&record.stamp)?;
        if record.stamp.identity.task != parent.task
            || parent.vm.map(VmAuthorityKey::generation)
                != Some(record.stamp.identity.vm_generation)
        {
            return Err(InfrastructureError::Invariant(
                "fault task or VM linkage mismatch",
            ));
        }
        check_fault_phase(scope, record)?;
        if matches!(record.phase, FaultPhase::Reserved | FaultPhase::Armed) {
            increment_invariant(&mut expected_live.faults)?;
            account_live_task_child(&mut workload_children, &mut task_children, &record.stamp)?;
        }
        push_expected_index(&mut expected_indexes, reverse_index_for_fault(record))?;
    }

    for record in scope.continuations.iter() {
        record
            .stamp
            .identity
            .validate()
            .map_err(|_| InfrastructureError::Invariant("invalid continuation descriptor"))?;
        validate_task_child_stamp(scope, &record.stamp)?;
        let parent = task_parent(&record.stamp)?;
        if parent.vm.map(VmAuthorityKey::generation) != Some(record.stamp.identity.vm_generation)
            || record.origin_source.domain != record.stamp.identity.source_domain
            || record.origin_source.binding_epoch == 0
            || record.origin_source.binding_epoch > record.stamp.identity.source_binding_epoch
        {
            return Err(InfrastructureError::Invariant(
                "continuation task or source linkage mismatch",
            ));
        }
        check_continuation_phase(record)?;
        if continuation_phase_live(record.phase) {
            increment_invariant(&mut expected_live.continuations)?;
            account_live_task_child(&mut workload_children, &mut task_children, &record.stamp)?;
        } else if record.service_owner.is_some() {
            return Err(InfrastructureError::Invariant(
                "terminal continuation retains service owner",
            ));
        }
        push_expected_index(
            &mut expected_indexes,
            reverse_index_for_continuation(record),
        )?;
    }

    for record in scope.deadlines.iter() {
        record
            .stamp
            .identity
            .validate()
            .map_err(|_| InfrastructureError::Invariant("invalid deadline descriptor"))?;
        validate_task_child_stamp(scope, &record.stamp)?;
        if record.series_nonce == 0 {
            return Err(InfrastructureError::Invariant("zero deadline series nonce"));
        }
        check_deadline_phase(record)?;
        if deadline_phase_live(record.phase) {
            increment_invariant(&mut expected_live.deadlines)?;
            account_live_task_child(&mut workload_children, &mut task_children, &record.stamp)?;
        }
        push_expected_index(&mut expected_indexes, reverse_index_for_deadline(record))?;
    }

    for record in scope.devices.iter() {
        record
            .stamp
            .identity
            .validate()
            .map_err(|_| InfrastructureError::Invariant("invalid device coordinates"))?;
        validate_primary_stamp(scope, &record.stamp)?;
        if !matches!(record.stamp.parent, ParentStamp::Effect(_)) {
            return Err(InfrastructureError::Invariant("invalid device parent"));
        }
        if device_phase_live(record.phase) {
            increment_invariant(&mut expected_live.device_preparations)?;
            increment_workload_child(&mut workload_children, record.stamp.workload.request)?;
        }
        match record.phase {
            DevicePhase::Reserved
            | DevicePhase::Applying { .. }
            | DevicePhase::PreparedRetained { .. } => {
                add_device_usage(&mut expected_usage, record.stamp.identity)?;
            }
            DevicePhase::Materialized {
                preparation_credits_transferred: true,
                ..
            }
            | DevicePhase::Released { .. }
            | DevicePhase::Cancelled { .. } => {}
            DevicePhase::Materialized {
                preparation_credits_transferred: false,
                ..
            } => {
                return Err(InfrastructureError::Invariant(
                    "materialized device retained preparation credits",
                ));
            }
        }
        push_expected_index(&mut expected_indexes, reverse_index_for_device(record)?)?;
    }

    for record in scope.replies.iter() {
        record
            .stamp
            .identity
            .validate()
            .map_err(|_| InfrastructureError::Invariant("invalid reply descriptor"))?;
        validate_task_child_stamp(scope, &record.stamp)?;
        let parent = task_parent(&record.stamp)?;
        if parent.task != record.stamp.identity.guest_task
            || parent.vm.map(VmAuthorityKey::generation)
                != Some(record.stamp.identity.guest_vm_generation)
        {
            return Err(InfrastructureError::Invariant(
                "reply task or VM linkage mismatch",
            ));
        }
        if reply_phase_live(record.phase) {
            increment_invariant(&mut expected_live.replies)?;
            account_live_task_child(&mut workload_children, &mut task_children, &record.stamp)?;
        }
        push_expected_index(&mut expected_indexes, reverse_index_for_reply(record))?;
    }

    check_service_continuation_owners(scope)?;
    check_reverse_indexes(scope, &expected_indexes)?;
    check_monotonic_sequences(scope)?;

    for record in scope.workloads.iter() {
        let expected = workload_children
            .iter()
            .find_map(|(request, count)| (*request == record.request).then_some(*count))
            .ok_or(InfrastructureError::Invariant(
                "missing workload child projection",
            ))?;
        if record.live_children != expected
            || (record.phase == WorkloadPhase::Closed && expected != 0)
        {
            return Err(InfrastructureError::Invariant(
                "workload live-child count mismatch",
            ));
        }
    }
    for record in scope.tasks.iter() {
        let expected = task_children
            .iter()
            .find_map(|(task, count)| (*task == record.stamp.identity).then_some(*count))
            .ok_or(InfrastructureError::Invariant(
                "missing task child projection",
            ))?;
        let anchor_valid = match record.anchor {
            TaskAnchorPhase::Live => task_phase_live(record.phase),
            TaskAnchorPhase::TerminalRetained => !task_phase_live(record.phase) && expected != 0,
            TaskAnchorPhase::TerminalDrained => !task_phase_live(record.phase) && expected == 0,
        };
        if record.live_children != expected || !anchor_valid {
            return Err(InfrastructureError::Invariant(
                "task live-child count mismatch",
            ));
        }
    }

    expected_live.queue_slots = expected_usage.queue_slots;
    expected_live.pinned_pages = expected_usage.pinned_pages;
    expected_live.dma_mappings = expected_usage.dma_mappings;
    if scope.live != expected_live {
        return Err(InfrastructureError::Invariant(
            "infrastructure live count mismatch",
        ));
    }
    if expected_usage.queue_slots > scope.limits.queue_slots
        || expected_usage.pinned_pages > scope.limits.pinned_pages
        || expected_usage.dma_mappings > scope.limits.dma_mappings
    {
        return Err(InfrastructureError::Invariant(
            "recomputed infrastructure resource usage exceeds limits",
        ));
    }
    if scope.closure.is_some_and(|closure| {
        closure.finished && scope.live != InfrastructureLiveCounts::default()
    }) {
        return Err(InfrastructureError::Invariant(
            "finished infrastructure closure retains live obligations",
        ));
    }
    Ok(())
}

fn validate_scope_slot_shape(scope: &ScopeInfrastructure) -> Result<(), InfrastructureError> {
    let expected_index_slots = scope
        .limits
        .workloads
        .checked_add(scope.limits.tasks)
        .and_then(|value| value.checked_add(scope.limits.service_requests))
        .and_then(|value| value.checked_add(scope.limits.delayed_commands))
        .and_then(|value| value.checked_add(scope.limits.faults))
        .and_then(|value| value.checked_add(scope.limits.continuations))
        .and_then(|value| value.checked_add(scope.limits.deadline_series))
        .and_then(|value| value.checked_add(scope.limits.device_preparations))
        .and_then(|value| value.checked_add(scope.limits.replies))
        .ok_or(InfrastructureError::Invariant(
            "infrastructure slot limit overflow",
        ))?;
    let slot_shapes = [
        (scope.workloads.slots.len(), scope.limits.workloads),
        (scope.tasks.slots.len(), scope.limits.tasks),
        (
            scope.service_requests.slots.len(),
            scope.limits.service_requests,
        ),
        (
            scope.delayed_commands.slots.len(),
            scope.limits.delayed_commands,
        ),
        (scope.faults.slots.len(), scope.limits.faults),
        (scope.continuations.slots.len(), scope.limits.continuations),
        (scope.deadlines.slots.len(), scope.limits.deadline_series),
        (scope.devices.slots.len(), scope.limits.device_preparations),
        (scope.replies.slots.len(), scope.limits.replies),
        (scope.reverse_indexes.slots.len(), expected_index_slots),
    ];
    if slot_shapes
        .iter()
        .any(|(actual, expected)| usize::try_from(*expected) != Ok(*actual))
    {
        return Err(InfrastructureError::Invariant(
            "infrastructure slot capacity mismatch",
        ));
    }
    validate_unique_slot_ids(&scope.workloads)?;
    validate_unique_slot_ids(&scope.tasks)?;
    validate_unique_slot_ids(&scope.service_requests)?;
    validate_unique_slot_ids(&scope.delayed_commands)?;
    validate_unique_slot_ids(&scope.faults)?;
    validate_unique_slot_ids(&scope.continuations)?;
    validate_unique_slot_ids(&scope.deadlines)?;
    validate_unique_slot_ids(&scope.devices)?;
    validate_unique_slot_ids(&scope.replies)?;
    validate_unique_slot_ids(&scope.reverse_indexes)?;
    Ok(())
}

fn validate_unique_slot_ids<T: SlotIdentity>(
    slots: &FixedSlots<T>,
) -> Result<(), InfrastructureError> {
    for (index, record) in slots.iter().enumerate() {
        if record.slot_id() == 0
            || slots
                .iter()
                .skip(index + 1)
                .any(|candidate| candidate.slot_id() == record.slot_id())
        {
            return Err(InfrastructureError::Invariant(
                "duplicate or zero primary slot identity",
            ));
        }
    }
    Ok(())
}

fn validate_primary_stamp<I>(
    scope: &ScopeInfrastructure,
    stamp: &BearerStamp<I>,
) -> Result<(), InfrastructureError> {
    if stamp.root != scope.root
        || stamp.nonce == 0
        || stamp.bearer_generation == 0
        || stamp.workload.nonce == 0
        || stamp.workload.bearer_generation == 0
        || stamp.domain.binding_epoch == 0
    {
        return Err(InfrastructureError::Invariant(
            "invalid infrastructure primary stamp",
        ));
    }
    let workload =
        scope
            .workloads
            .get(stamp.workload.request.id)
            .ok_or(InfrastructureError::Invariant(
                "primary stamp lacks workload",
            ))?;
    let current_domain_epoch = scope
        .binding_epoch(stamp.domain.domain)
        .map_err(|_| InfrastructureError::Invariant("primary stamp references unknown domain"))?;
    if workload.request != stamp.workload.request
        || workload.nonce != stamp.workload.nonce
        || workload.domain != stamp.domain.domain
        || stamp.workload.bearer_generation > workload.bearer_generation
        || stamp.domain.binding_epoch > workload.current_binding_epoch
        || workload.current_binding_epoch > current_domain_epoch
    {
        return Err(InfrastructureError::Invariant(
            "primary stamp workload linkage mismatch",
        ));
    }
    Ok(())
}

fn validate_task_child_stamp<I>(
    scope: &ScopeInfrastructure,
    stamp: &BearerStamp<I>,
) -> Result<(), InfrastructureError> {
    validate_primary_stamp(scope, stamp)?;
    let parent = task_parent(stamp)?;
    let task = scope
        .tasks
        .get(parent.work_id)
        .ok_or(InfrastructureError::Invariant(
            "task child lacks parent task",
        ))?;
    if task.stamp.identity != parent || task.stamp.workload.request != stamp.workload.request {
        return Err(InfrastructureError::Invariant(
            "task child parent linkage mismatch",
        ));
    }
    Ok(())
}

fn task_parent<I>(stamp: &BearerStamp<I>) -> Result<TaskWorkDescriptor, InfrastructureError> {
    match stamp.parent {
        ParentStamp::Task(parent) => Ok(parent),
        _ => Err(InfrastructureError::Invariant(
            "infrastructure record lacks task parent",
        )),
    }
}

fn increment_invariant(value: &mut u32) -> Result<(), InfrastructureError> {
    *value = value.checked_add(1).ok_or(InfrastructureError::Invariant(
        "infrastructure recomputation overflow",
    ))?;
    Ok(())
}

fn increment_workload_child(
    children: &mut [(RequestKey, u32)],
    request: RequestKey,
) -> Result<(), InfrastructureError> {
    let count = children
        .iter_mut()
        .find_map(|(candidate, count)| (*candidate == request).then_some(count))
        .ok_or(InfrastructureError::Invariant(
            "live child lacks exact workload",
        ))?;
    increment_invariant(count)
}

fn increment_task_child(
    children: &mut [(TaskWorkDescriptor, u32)],
    task: TaskWorkDescriptor,
) -> Result<(), InfrastructureError> {
    let count = children
        .iter_mut()
        .find_map(|(candidate, count)| (*candidate == task).then_some(count))
        .ok_or(InfrastructureError::Invariant(
            "live child lacks exact task",
        ))?;
    increment_invariant(count)
}

fn account_live_task_child<I>(
    workload_children: &mut [(RequestKey, u32)],
    task_children: &mut [(TaskWorkDescriptor, u32)],
    stamp: &BearerStamp<I>,
) -> Result<(), InfrastructureError> {
    increment_workload_child(workload_children, stamp.workload.request)?;
    increment_task_child(task_children, task_parent(stamp)?)
}

fn add_device_usage(
    usage: &mut ResourceUsage,
    coordinates: DeviceReservationCoordinates,
) -> Result<(), InfrastructureError> {
    usage.queue_slots = usage
        .queue_slots
        .checked_add(coordinates.queue_slots)
        .ok_or(InfrastructureError::Invariant("queue usage overflow"))?;
    usage.pinned_pages = usage
        .pinned_pages
        .checked_add(coordinates.pinned_pages)
        .ok_or(InfrastructureError::Invariant("pinned-page usage overflow"))?;
    usage.dma_mappings = usage
        .dma_mappings
        .checked_add(coordinates.dma_mappings)
        .ok_or(InfrastructureError::Invariant("DMA usage overflow"))?;
    Ok(())
}

fn push_expected_index(
    indexes: &mut Vec<ReverseIndexRecord>,
    index: ReverseIndexRecord,
) -> Result<(), InfrastructureError> {
    if index.slot == 0 || indexes.iter().any(|candidate| candidate.slot == index.slot) {
        return Err(InfrastructureError::Invariant(
            "primary records alias a reverse-index slot",
        ));
    }
    indexes.push(index);
    Ok(())
}

fn check_reverse_indexes(
    scope: &ScopeInfrastructure,
    expected: &[ReverseIndexRecord],
) -> Result<(), InfrastructureError> {
    if scope.reverse_indexes.iter().count() != expected.len() {
        return Err(InfrastructureError::Invariant(
            "primary and reverse-index cardinality mismatch",
        ));
    }
    for index in expected {
        if scope
            .reverse_indexes
            .iter()
            .filter(|candidate| *candidate == index)
            .count()
            != 1
        {
            return Err(InfrastructureError::Invariant(
                "missing or conflicting reverse index",
            ));
        }
    }
    for index in scope.reverse_indexes.iter() {
        if expected
            .iter()
            .filter(|candidate| *candidate == index)
            .count()
            != 1
        {
            return Err(InfrastructureError::Invariant(
                "orphan or duplicate reverse index",
            ));
        }
    }
    Ok(())
}

fn check_monotonic_sequences(scope: &ScopeInfrastructure) -> Result<(), InfrastructureError> {
    let mut max_nonce = 0_u64;
    let mut max_publication = 0_u64;
    let mut max_closure = 0_u64;

    for record in scope.workloads.iter() {
        observe_sequence(&mut max_nonce, record.nonce, "zero workload nonce")?;
        observe_optional_sequence(
            &mut max_closure,
            record.closure_sequence,
            "zero workload closure sequence",
        )?;
    }
    for record in scope.tasks.iter() {
        observe_stamp_nonces(&mut max_nonce, &record.stamp)?;
        observe_optional_sequence(
            &mut max_closure,
            record.closure_sequence,
            "zero task closure sequence",
        )?;
    }
    for record in scope.service_requests.iter() {
        observe_stamp_nonces(&mut max_nonce, &record.stamp)?;
        if let Some(bound) = record.bound_continuation.as_ref() {
            observe_stamp_nonces(&mut max_nonce, bound)?;
        }
        for (high_water, zero_error) in [
            (
                record.apply_nonce_high_water,
                "zero service apply nonce high-water",
            ),
            (
                record.arm_nonce_high_water,
                "zero service arm nonce high-water",
            ),
            (
                record.claim_nonce_high_water,
                "zero service claim nonce high-water",
            ),
        ] {
            if high_water != 0 {
                observe_sequence(&mut max_nonce, high_water, zero_error)?;
            }
        }
        match record.phase {
            ServiceRequestPhase::Publishing { apply_nonce, .. } => {
                observe_sequence(&mut max_nonce, apply_nonce, "zero service apply nonce")?;
            }
            ServiceRequestPhase::Arming { arm_nonce, .. } => {
                observe_sequence(&mut max_nonce, arm_nonce, "zero service arm nonce")?;
            }
            ServiceRequestPhase::ChildBound {
                binding_receipt, ..
            } => {
                observe_sequence(
                    &mut max_nonce,
                    binding_receipt.claim_nonce,
                    "zero service claim nonce",
                )?;
            }
            _ => {}
        }
        observe_optional_sequence(
            &mut max_closure,
            record.closure_sequence,
            "zero service closure sequence",
        )?;
    }
    for record in scope.delayed_commands.iter() {
        observe_stamp_nonces(&mut max_nonce, &record.stamp)?;
        if let DelayedCommandPhase::Publishing { apply_nonce, .. } = record.phase {
            observe_sequence(&mut max_nonce, apply_nonce, "zero delayed apply nonce")?;
        }
        observe_optional_sequence(
            &mut max_closure,
            record.closure_sequence,
            "zero delayed closure sequence",
        )?;
    }
    for record in scope.faults.iter() {
        observe_stamp_nonces(&mut max_nonce, &record.stamp)?;
        observe_optional_sequence(
            &mut max_closure,
            record.closure_sequence,
            "zero fault closure sequence",
        )?;
    }
    for record in scope.continuations.iter() {
        observe_stamp_nonces(&mut max_nonce, &record.stamp)?;
        match record.phase {
            ContinuationPhase::Claimed { claim_nonce, .. } => {
                observe_sequence(&mut max_nonce, claim_nonce, "zero continuation claim nonce")?;
            }
            ContinuationPhase::Publishing {
                claim_nonce,
                apply_nonce,
                publication_sequence,
                ..
            } => {
                observe_sequence(&mut max_nonce, claim_nonce, "zero continuation claim nonce")?;
                observe_sequence(&mut max_nonce, apply_nonce, "zero continuation apply nonce")?;
                observe_sequence(
                    &mut max_publication,
                    publication_sequence,
                    "zero continuation publication sequence",
                )?;
            }
            ContinuationPhase::Acknowledged {
                publication_sequence,
                ack_nonce,
                ..
            } => {
                observe_sequence(&mut max_nonce, ack_nonce, "zero continuation ack nonce")?;
                observe_sequence(
                    &mut max_publication,
                    publication_sequence,
                    "zero continuation publication sequence",
                )?;
            }
            ContinuationPhase::Resuming {
                publication_sequence,
                ack_nonce,
                resume_nonce,
                ..
            } => {
                observe_sequence(&mut max_nonce, ack_nonce, "zero continuation ack nonce")?;
                observe_sequence(
                    &mut max_nonce,
                    resume_nonce,
                    "zero continuation resume nonce",
                )?;
                observe_sequence(
                    &mut max_publication,
                    publication_sequence,
                    "zero continuation publication sequence",
                )?;
            }
            ContinuationPhase::Resumed {
                publication_sequence,
                receipt,
            } => {
                observe_sequence(
                    &mut max_nonce,
                    receipt.ack_nonce,
                    "zero retained continuation ack nonce",
                )?;
                observe_sequence(
                    &mut max_nonce,
                    receipt.resume_nonce,
                    "zero retained continuation resume nonce",
                )?;
                observe_sequence(
                    &mut max_publication,
                    publication_sequence,
                    "zero continuation publication sequence",
                )?;
                observe_sequence(
                    &mut max_publication,
                    receipt.publication_sequence,
                    "zero continuation receipt publication sequence",
                )?;
            }
            ContinuationPhase::Pending | ContinuationPhase::Cancelled => {}
        }
        if let Some(ack) = record.publication_ack {
            observe_sequence(
                &mut max_nonce,
                ack.claim_nonce,
                "zero retained continuation claim nonce",
            )?;
            observe_sequence(
                &mut max_nonce,
                ack.apply_nonce,
                "zero retained continuation apply nonce",
            )?;
            observe_sequence(
                &mut max_publication,
                ack.publication_sequence,
                "zero retained continuation publication sequence",
            )?;
        }
        observe_optional_sequence(
            &mut max_closure,
            record.closure_sequence,
            "zero continuation closure sequence",
        )?;
    }
    for record in scope.deadlines.iter() {
        observe_stamp_nonces(&mut max_nonce, &record.stamp)?;
        observe_sequence(
            &mut max_nonce,
            record.series_nonce,
            "zero deadline series nonce",
        )?;
        match record.phase {
            DeadlinePhase::Fired { expiry_nonce, .. }
            | DeadlinePhase::ExhaustedRetained { expiry_nonce, .. } => {
                observe_sequence(&mut max_nonce, expiry_nonce, "zero deadline expiry nonce")?;
            }
            DeadlinePhase::QuarantinedRetained {
                quarantine_nonce, ..
            } => {
                observe_sequence(
                    &mut max_nonce,
                    quarantine_nonce,
                    "zero deadline quarantine nonce",
                )?;
            }
            _ => {}
        }
        observe_optional_sequence(
            &mut max_closure,
            record.closure_sequence,
            "zero deadline closure sequence",
        )?;
    }
    for record in scope.devices.iter() {
        observe_stamp_nonces(&mut max_nonce, &record.stamp)?;
        if let DevicePhase::Applying { apply_nonce, .. } = record.phase {
            observe_sequence(&mut max_nonce, apply_nonce, "zero device apply nonce")?;
        }
        observe_optional_sequence(
            &mut max_closure,
            record.closure_sequence,
            "zero device closure sequence",
        )?;
    }
    for record in scope.replies.iter() {
        observe_stamp_nonces(&mut max_nonce, &record.stamp)?;
        match record.phase {
            ReplyPhase::Claimed { claim_nonce, .. } => {
                observe_sequence(&mut max_nonce, claim_nonce, "zero reply claim nonce")?;
            }
            ReplyPhase::Publishing {
                claim_nonce,
                apply_nonce,
                ..
            } => {
                observe_sequence(&mut max_nonce, claim_nonce, "zero reply claim nonce")?;
                observe_sequence(&mut max_nonce, apply_nonce, "zero reply apply nonce")?;
            }
            ReplyPhase::Acknowledged { ack_nonce, .. } => {
                observe_sequence(&mut max_nonce, ack_nonce, "zero reply ack nonce")?;
            }
            _ => {}
        }
        observe_optional_sequence(
            &mut max_closure,
            record.closure_sequence,
            "zero reply closure sequence",
        )?;
    }
    if let Some(closure) = scope.closure {
        observe_sequence(&mut max_nonce, closure.nonce, "zero scope closure nonce")?;
        observe_sequence(
            &mut max_closure,
            closure.sequence,
            "zero scope closure sequence",
        )?;
    }

    if scope.next_nonce <= max_nonce
        || scope.next_publication_sequence <= max_publication
        || scope.next_closure_sequence <= max_closure
    {
        return Err(InfrastructureError::Invariant(
            "infrastructure sequence allocator rolled back",
        ));
    }
    Ok(())
}

fn observe_stamp_nonces<I>(
    maximum: &mut u64,
    stamp: &BearerStamp<I>,
) -> Result<(), InfrastructureError> {
    observe_sequence(maximum, stamp.nonce, "zero primary stamp nonce")?;
    observe_sequence(maximum, stamp.workload.nonce, "zero workload stamp nonce")
}

fn observe_optional_sequence(
    maximum: &mut u64,
    sequence: Option<u64>,
    zero_error: &'static str,
) -> Result<(), InfrastructureError> {
    if let Some(sequence) = sequence {
        observe_sequence(maximum, sequence, zero_error)?;
    }
    Ok(())
}

fn observe_sequence(
    maximum: &mut u64,
    sequence: u64,
    zero_error: &'static str,
) -> Result<(), InfrastructureError> {
    if sequence == 0 {
        return Err(InfrastructureError::Invariant(zero_error));
    }
    *maximum = (*maximum).max(sequence);
    Ok(())
}

fn reverse_index_for_service(record: &ServiceRequestStateRecord) -> ReverseIndexRecord {
    let descriptor = record.stamp.identity;
    ReverseIndexRecord {
        slot: record.stamp.nonce,
        kind: InfrastructureKind::ServiceRequest,
        root_effect: record.stamp.root.root_effect,
        parent: ReverseParent::Task(task_parent(&record.stamp).unwrap()),
        task: Some(task_parent(&record.stamp).unwrap().task),
        domain: record.stamp.domain.domain,
        binding_epoch: record.stamp.domain.binding_epoch,
        source_domain: Some(descriptor.destination_domain),
        source_binding_epoch: Some(descriptor.destination_binding_epoch),
        resource: Some(descriptor.queue),
        actor_slot: Some(descriptor.payload_slot),
        retry_generation: descriptor.generation,
    }
}

fn reverse_index_for_delayed(record: &DelayedCommandStateRecord) -> ReverseIndexRecord {
    let descriptor = record.stamp.identity;
    ReverseIndexRecord {
        slot: record.stamp.nonce,
        kind: InfrastructureKind::DelayedCommand,
        root_effect: record.stamp.root.root_effect,
        parent: ReverseParent::Task(task_parent(&record.stamp).unwrap()),
        task: Some(descriptor.sender),
        domain: record.stamp.domain.domain,
        binding_epoch: record.stamp.domain.binding_epoch,
        source_domain: Some(descriptor.destination_domain),
        source_binding_epoch: Some(descriptor.destination_binding_epoch),
        resource: None,
        actor_slot: Some(descriptor.actor_slot),
        retry_generation: descriptor.actor_generation,
    }
}

fn reverse_index_for_continuation(record: &ContinuationRecord) -> ReverseIndexRecord {
    let descriptor = record.stamp.identity;
    ReverseIndexRecord {
        slot: record.stamp.nonce,
        kind: InfrastructureKind::Continuation,
        root_effect: record.stamp.root.root_effect,
        parent: ReverseParent::Task(task_parent(&record.stamp).unwrap()),
        task: Some(task_parent(&record.stamp).unwrap().task),
        domain: record.stamp.domain.domain,
        binding_epoch: record.stamp.domain.binding_epoch,
        source_domain: Some(descriptor.source_domain),
        source_binding_epoch: Some(descriptor.source_binding_epoch),
        resource: None,
        actor_slot: None,
        retry_generation: descriptor.generation,
    }
}

fn reverse_index_for_deadline(record: &DeadlineRecord) -> ReverseIndexRecord {
    let descriptor = record.stamp.identity;
    ReverseIndexRecord {
        slot: record.series_nonce,
        kind: InfrastructureKind::Deadline,
        root_effect: record.stamp.root.root_effect,
        parent: ReverseParent::Task(task_parent(&record.stamp).unwrap()),
        task: Some(task_parent(&record.stamp).unwrap().task),
        domain: record.stamp.domain.domain,
        binding_epoch: record.stamp.domain.binding_epoch,
        source_domain: None,
        source_binding_epoch: None,
        resource: None,
        actor_slot: None,
        retry_generation: descriptor.generation,
    }
}

fn reverse_index_for_device(
    record: &DeviceRecord,
) -> Result<ReverseIndexRecord, InfrastructureError> {
    let descriptor = record.stamp.identity;
    let parent = match record.stamp.parent {
        ParentStamp::Effect(parent) => parent,
        _ => return Err(InfrastructureError::Invariant("invalid device parent")),
    };
    Ok(ReverseIndexRecord {
        slot: record.stamp.nonce,
        kind: InfrastructureKind::DevicePreparation,
        root_effect: record.stamp.root.root_effect,
        parent: ReverseParent::Effect(parent),
        task: None,
        domain: record.stamp.domain.domain,
        binding_epoch: record.stamp.domain.binding_epoch,
        source_domain: None,
        source_binding_epoch: None,
        resource: Some(descriptor.owned_device),
        actor_slot: Some(descriptor.actor_slot),
        retry_generation: descriptor.generation,
    })
}

fn reverse_index_for_reply(record: &ReplyStateRecord) -> ReverseIndexRecord {
    let descriptor = record.stamp.identity;
    ReverseIndexRecord {
        slot: record.stamp.nonce,
        kind: InfrastructureKind::Reply,
        root_effect: record.stamp.root.root_effect,
        parent: ReverseParent::Task(task_parent(&record.stamp).unwrap()),
        task: Some(descriptor.guest_task),
        domain: record.stamp.domain.domain,
        binding_epoch: record.stamp.domain.binding_epoch,
        source_domain: Some(descriptor.source_domain),
        source_binding_epoch: Some(descriptor.source_binding_epoch),
        resource: None,
        actor_slot: Some(descriptor.payload_slot),
        retry_generation: descriptor.payload_generation,
    }
}

fn task_phase_live(phase: TaskPhase) -> bool {
    matches!(phase, TaskPhase::Admitted | TaskPhase::Entered)
}

fn continuation_phase_live(phase: ContinuationPhase) -> bool {
    !matches!(
        phase,
        ContinuationPhase::Resumed { .. } | ContinuationPhase::Cancelled
    )
}

fn deadline_phase_live(phase: DeadlinePhase) -> bool {
    !matches!(
        phase,
        DeadlinePhase::Cancelled | DeadlinePhase::Resolved { .. }
    )
}

fn reply_phase_live(phase: ReplyPhase) -> bool {
    !matches!(
        phase,
        ReplyPhase::Completed { .. } | ReplyPhase::Cancelled { .. }
    )
}

fn check_fault_phase(
    scope: &ScopeInfrastructure,
    record: &FaultStateRecord,
) -> Result<(), InfrastructureError> {
    let parent = task_parent(&record.stamp)?;
    let parent_record = scope
        .tasks
        .get(parent.work_id)
        .filter(|task| task.stamp.identity == parent)
        .ok_or(InfrastructureError::Invariant(
            "fault lacks exact parent task",
        ))?;
    let (link, exact_fault) = validate_exact_task_fault_pair(scope, parent_record)?;
    if exact_fault.stamp.identity != record.stamp.identity {
        return Err(InfrastructureError::Invariant("task-fault pair mismatch"));
    }
    let expected_pair = match record.phase {
        FaultPhase::Reserved => {
            parent_record.phase == TaskPhase::Admitted
                && parent_record.anchor == TaskAnchorPhase::Live
                && link.terminal_install_digest.is_none()
        }
        FaultPhase::Armed => {
            parent_record.phase == TaskPhase::Entered
                && parent_record.anchor == TaskAnchorPhase::Live
                && link.terminal_install_digest.is_none()
        }
        FaultPhase::Exited { receipt } => {
            receipt.fault_id == record.stamp.identity.fault_id
                && receipt.generation == record.stamp.identity.generation
                && receipt.task == record.stamp.identity.task
                && receipt.evidence_digest != 0
                && parent_record.phase == TaskPhase::Reaped
                && parent_record.anchor == TaskAnchorPhase::TerminalDrained
                && parent_record.live_children == 0
                && link.terminal_install_digest == Some(exit_receipt_digest(receipt))
        }
        phase @ (FaultPhase::InstalledAwaitingClaim { .. } | FaultPhase::Claimed { .. }) => {
            let (projection, observation, commitment, cause_claimed) = match phase {
                FaultPhase::InstalledAwaitingClaim {
                    projection,
                    observation,
                    commitment,
                } => (projection, observation, commitment, false),
                FaultPhase::Claimed {
                    projection,
                    observation,
                    commitment,
                    cause_claimed,
                } => (projection, observation, commitment, cause_claimed),
                FaultPhase::Reserved | FaultPhase::Armed | FaultPhase::Exited { .. } => {
                    unreachable!()
                }
            };
            let current_domain_epoch = scope
                .binding_epoch(projection.service_domain)
                .map_err(|_| InfrastructureError::Invariant("fault references unknown domain"))?;
            let disposition_valid = match projection.disposition {
                FaultDisposition::CrashService => {
                    projection.crash_generation != 0
                        && current_domain_epoch > projection.closed_binding_epoch
                }
                FaultDisposition::IsolateTask => {
                    projection.crash_generation == 0
                        && current_domain_epoch >= projection.closed_binding_epoch
                }
            };
            projection.fault_id == record.stamp.identity.fault_id
                && projection.generation == record.stamp.identity.generation
                && projection.task == record.stamp.identity.task
                && projection.vm_generation == record.stamp.identity.vm_generation
                && projection.service_domain == record.stamp.identity.service_domain
                && projection.closed_binding_epoch == record.stamp.identity.admission_binding_epoch
                && projection.evidence_digest != 0
                && observation.task == projection.task
                && observation.vm_generation == projection.vm_generation
                && observation.instruction_pointer != 0
                && observation.evidence_digest == projection.evidence_digest
                && parent_record.phase == TaskPhase::Isolated
                && parent_record.anchor != TaskAnchorPhase::Live
                && link.terminal_install_digest == Some(commitment.0)
                && (!cause_claimed || projection.disposition == FaultDisposition::CrashService)
                && disposition_valid
        }
    };
    if !expected_pair {
        return Err(InfrastructureError::Invariant(
            "fault phase projection mismatch",
        ));
    }
    Ok(())
}

fn check_continuation_phase(record: &ContinuationRecord) -> Result<(), InfrastructureError> {
    validate_continuation_publication_ack(record)?;
    let valid = match record.phase {
        ContinuationPhase::Pending => {
            record.claim_generation == 0
                && record.apply_generation == 0
                && record.ack_generation == 0
                && record.resume_generation == 0
        }
        ContinuationPhase::Cancelled => {
            record.apply_generation == 0
                && record.ack_generation == 0
                && record.resume_generation == 0
        }
        ContinuationPhase::Claimed {
            claim_generation, ..
        } => {
            claim_generation != 0
                && claim_generation == record.claim_generation
                && record.apply_generation == 0
                && record.ack_generation == 0
                && record.resume_generation == 0
        }
        ContinuationPhase::Publishing {
            claim_generation,
            apply_generation,
            receipt,
            ..
        } => {
            claim_generation != 0
                && apply_generation != 0
                && claim_generation == record.claim_generation
                && apply_generation == record.apply_generation
                && record.ack_generation == 0
                && record.resume_generation == 0
                && receipt.vm_generation == record.stamp.identity.vm_generation
                && receipt.source_domain == record.stamp.identity.source_domain
                && receipt.source_binding_epoch == record.stamp.identity.source_binding_epoch
        }
        ContinuationPhase::Acknowledged { ack_generation, .. } => {
            ack_generation != 0
                && ack_generation == record.ack_generation
                && record.resume_generation == 0
        }
        ContinuationPhase::Resuming {
            ack_generation,
            resume_generation,
            ..
        } => {
            ack_generation != 0
                && ack_generation == record.ack_generation
                && resume_generation != 0
                && resume_generation == record.resume_generation
        }
        ContinuationPhase::Resumed { receipt, .. } => {
            receipt.vm_generation == record.stamp.identity.vm_generation
                && receipt.external_receipt_digest != 0
                && record.ack_generation != 0
                && receipt.ack_generation == record.ack_generation
                && record.resume_generation != 0
                && receipt.resume_generation == record.resume_generation
        }
    };
    if !valid {
        return Err(InfrastructureError::Invariant(
            "continuation phase generation mismatch",
        ));
    }
    Ok(())
}

fn check_deadline_phase(record: &DeadlineRecord) -> Result<(), InfrastructureError> {
    if record
        .last_reconciliation
        .is_some_and(|receipt| receipt.evidence_digest == 0)
        || record.terminal_evidence_digest == Some(0)
    {
        return Err(InfrastructureError::Invariant(
            "deadline retains zero reconciliation evidence",
        ));
    }

    let retry_history_is_valid = record.last_reconciliation.is_none_or(|receipt| {
        receipt.disposition == DeadlineExhaustedDisposition::RetryBySupervisor
    });
    let valid = match record.phase {
        DeadlinePhase::Armed => record.terminal_evidence_digest.is_none() && retry_history_is_valid,
        DeadlinePhase::Fired { expiry_nonce, .. }
        | DeadlinePhase::ExhaustedRetained { expiry_nonce, .. } => {
            expiry_nonce != 0
                && expiry_nonce == record.stamp.nonce
                && record.terminal_evidence_digest.is_none()
                && retry_history_is_valid
        }
        DeadlinePhase::QuarantinedRetained {
            receipt,
            quarantine_generation,
            quarantine_nonce,
            ..
        } => {
            receipt.disposition == DeadlineExhaustedDisposition::Quarantine
                && receipt.evidence_digest != 0
                && record.last_reconciliation == Some(receipt)
                && record.terminal_evidence_digest.is_none()
                && quarantine_generation != 0
                && quarantine_generation == record.quarantine_generation
                && quarantine_nonce != 0
                && quarantine_nonce == record.stamp.nonce
        }
        DeadlinePhase::Cancelled => {
            record.terminal_evidence_digest.is_none() && retry_history_is_valid
        }
        DeadlinePhase::Resolved {
            reconciliation,
            terminal_evidence_digest,
        } => {
            record.last_reconciliation == reconciliation
                && record.terminal_evidence_digest == terminal_evidence_digest
                && match reconciliation {
                    None => terminal_evidence_digest.is_none(),
                    Some(receipt) => {
                        matches!(
                            receipt.disposition,
                            DeadlineExhaustedDisposition::AbortWork
                                | DeadlineExhaustedDisposition::Quarantine
                        ) && receipt.evidence_digest != 0
                            && terminal_evidence_digest.is_some_and(|digest| digest != 0)
                            && (receipt.disposition != DeadlineExhaustedDisposition::Quarantine
                                || record.quarantine_generation != 0)
                    }
                }
        }
    };
    if !valid {
        return Err(InfrastructureError::Invariant(
            "deadline phase or reconciliation mismatch",
        ));
    }
    Ok(())
}

fn check_service_phase(
    scope: &ScopeInfrastructure,
    record: &ServiceRequestStateRecord,
) -> Result<(), InfrastructureError> {
    let descriptor = record.stamp.identity;
    if service_request_phase_live(record.phase)
        && scope
            .binding_epoch(descriptor.destination_domain)
            .map_err(|_| {
                InfrastructureError::Invariant("service request references unknown destination")
            })?
            != descriptor.destination_binding_epoch
    {
        return Err(InfrastructureError::Invariant(
            "live service request has stale destination binding",
        ));
    }
    let live_bound = matches!(
        record.phase,
        ServiceRequestPhase::ReservedBound
            | ServiceRequestPhase::Publishing { .. }
            | ServiceRequestPhase::QueueWrittenUnarmed { .. }
            | ServiceRequestPhase::Arming { .. }
            | ServiceRequestPhase::Armed { .. }
            | ServiceRequestPhase::ChildBound { .. }
    );
    if live_bound != record.bound_continuation.is_some() {
        return Err(InfrastructureError::Invariant(
            "service continuation ownership link mismatches phase",
        ));
    }
    if !service_request_phase_live(record.phase) && record.bound_continuation.is_some() {
        return Err(InfrastructureError::Invariant(
            "terminal service request retains continuation ownership link",
        ));
    }
    let response_commitment = record
        .response_identity
        .map(super::service::service_response_commitment);
    let response_anchor_valid = record.response_commitment == response_commitment;
    let live_response = record
        .bound_continuation
        .map(|continuation| continuation.identity)
        .filter(|identity| {
            record.response_identity == Some(*identity)
                && record.response_commitment
                    == Some(super::service::service_response_commitment(*identity))
        });
    let base_bind_chain = service_bearer_after(1, 1, record.bind_bearer_generation);
    let apply_chain = base_bind_chain
        && service_bearer_after(
            record.bind_bearer_generation,
            1,
            record.apply_bearer_generation,
        );
    let arm_chain = apply_chain
        && service_bearer_after(
            record.apply_bearer_generation,
            2,
            record.arm_bearer_generation,
        );
    let claim_chain = arm_chain
        && service_bearer_after(
            record.arm_bearer_generation,
            2,
            record.claim_bearer_generation,
        );
    let valid_generations = match record.phase {
        ServiceRequestPhase::ReservedUnbound => {
            record.stamp.bearer_generation == 1
                && record.bind_bearer_generation == 0
                && record.response_identity.is_none()
                && record.response_commitment.is_none()
                && record.child_binding_commitment.is_none()
                && record.bound_commitment.is_none()
                && empty_service_action_history(record)
        }
        ServiceRequestPhase::ReservedBound => {
            base_bind_chain
                && record.stamp.bearer_generation == record.bind_bearer_generation
                && live_response.is_some()
                && response_anchor_valid
                && record.child_binding_commitment.is_none()
                && record.bound_commitment.is_none()
                && empty_service_action_history(record)
                && record
                    .bound_continuation
                    .is_some_and(|continuation| continuation.bearer_generation != 0)
        }
        ServiceRequestPhase::Publishing {
            apply_generation,
            apply_nonce,
        } => {
            apply_chain
                && record.apply_bearer_generation == record.stamp.bearer_generation
                && live_response.is_some()
                && response_anchor_valid
                && record.child_binding_commitment.is_none()
                && record.bound_commitment.is_none()
                && apply_generation != 0
                && apply_generation == record.apply_generation
                && apply_nonce != 0
                && apply_nonce == record.apply_nonce_high_water
                && record.arm_generation == 0
                && record.arm_bearer_generation == 0
                && record.arm_nonce_high_water == 0
                && record.claim_generation == 0
                && record.claim_bearer_generation == 0
                && record.claim_nonce_high_water == 0
        }
        ServiceRequestPhase::QueueWrittenUnarmed { queue_receipt } => {
            apply_chain
                && service_bearer_after(
                    record.apply_bearer_generation,
                    1,
                    record.stamp.bearer_generation,
                )
                && response_anchor_valid
                && record.child_binding_commitment.is_none()
                && record.bound_commitment.is_none()
                && live_response.is_some_and(|response| {
                    valid_service_queue_receipt(record, response, queue_receipt)
                })
                && record.arm_generation == 0
                && record.arm_bearer_generation == 0
                && record.arm_nonce_high_water == 0
                && record.claim_generation == 0
                && record.claim_bearer_generation == 0
                && record.claim_nonce_high_water == 0
        }
        ServiceRequestPhase::Arming {
            queue_receipt,
            arm_generation,
            arm_nonce,
        } => {
            arm_chain
                && record.arm_bearer_generation == record.stamp.bearer_generation
                && response_anchor_valid
                && record.child_binding_commitment.is_none()
                && record.bound_commitment.is_none()
                && live_response.is_some_and(|response| {
                    valid_service_queue_receipt(record, response, queue_receipt)
                })
                && arm_generation != 0
                && arm_generation == record.arm_generation
                && arm_nonce != 0
                && arm_nonce == record.arm_nonce_high_water
                && record.claim_generation == 0
                && record.claim_bearer_generation == 0
                && record.claim_nonce_high_water == 0
        }
        ServiceRequestPhase::Armed {
            queue_receipt,
            arm_receipt,
        } => {
            arm_chain
                && service_bearer_after(
                    record.arm_bearer_generation,
                    1,
                    record.stamp.bearer_generation,
                )
                && response_anchor_valid
                && record.child_binding_commitment.is_none()
                && record.bound_commitment.is_none()
                && live_response.is_some_and(|response| {
                    valid_service_queue_receipt(record, response, queue_receipt)
                        && valid_service_arm_receipt(record, response, queue_receipt, arm_receipt)
                })
                && record.claim_generation == 0
                && record.claim_bearer_generation == 0
                && record.claim_nonce_high_water == 0
        }
        ServiceRequestPhase::ChildBound {
            queue_receipt,
            arm_receipt,
            binding_receipt,
        } => {
            claim_chain
                && record.stamp.bearer_generation == record.claim_bearer_generation
                && response_anchor_valid
                && record.child_binding_commitment == Some(binding_receipt)
                && record.response_identity.is_some_and(|response| {
                    record.bound_commitment
                        == Some(super::service::service_child_bound_commitment(
                            queue_receipt,
                            arm_receipt,
                            response,
                            binding_receipt,
                        ))
                })
                && live_response.is_some_and(|response| {
                    valid_service_queue_receipt(record, response, queue_receipt)
                        && valid_service_arm_receipt(record, response, queue_receipt, arm_receipt)
                })
                && valid_service_child_binding(record, binding_receipt)
                && super::service::validate_service_child_binding_for_drain(
                    scope,
                    scope.root.registry_instance,
                    record,
                )
                .is_ok()
        }
        ServiceRequestPhase::Completed {
            queue_receipt,
            arm_receipt,
            receipt,
        } => {
            let binding_receipt = receipt.binding_receipt;
            claim_chain
                && service_bearer_after(
                    record.claim_bearer_generation,
                    1,
                    record.stamp.bearer_generation,
                )
                && record.response_identity == Some(receipt.response)
                && response_anchor_valid
                && record.child_binding_commitment == Some(binding_receipt)
                && record.bound_commitment
                    == Some(super::service::service_child_bound_commitment(
                        queue_receipt,
                        arm_receipt,
                        receipt.response,
                        binding_receipt,
                    ))
                && receipt.lineage_commitment
                    == super::service::service_child_bound_commitment(
                        queue_receipt,
                        arm_receipt,
                        receipt.response,
                        binding_receipt,
                    )
                && receipt.binding_receipt == binding_receipt
                && valid_service_queue_receipt(record, receipt.response, queue_receipt)
                && valid_service_arm_receipt(record, receipt.response, queue_receipt, arm_receipt)
                && valid_service_child_binding(record, binding_receipt)
                && receipt.request_id == descriptor.request_id
                && receipt.generation == descriptor.generation
                && receipt.bearer_generation == record.stamp.bearer_generation
                && receipt.child_effect == binding_receipt.child.child_effect
                && receipt.response.validate().is_ok()
                && receipt.result_digest != 0
                && terminal_response_exists(scope, record, receipt.response)
                && terminal_claimant_dominates(scope, binding_receipt.claimant)
        }
        ServiceRequestPhase::Cancelled { receipt } => {
            receipt.request_id == descriptor.request_id
                && receipt.generation == descriptor.generation
                && receipt.bearer_generation == record.stamp.bearer_generation
                && receipt.evidence_digest != 0
                && record.child_binding_commitment.is_none()
                && record.bound_commitment.is_none()
                && empty_service_action_history(record)
                && match (receipt.point, receipt.response) {
                    (ServiceCancellationPoint::ReservedUnbound, None) => {
                        record.response_identity.is_none()
                            && record.response_commitment.is_none()
                            && record.bind_bearer_generation == 0
                            && service_bearer_after(1, 1, record.stamp.bearer_generation)
                    }
                    (ServiceCancellationPoint::ReservedBound, Some(response)) => {
                        base_bind_chain
                            && record.response_identity == Some(response)
                            && record.response_commitment
                                == Some(super::service::service_response_commitment(response))
                            && service_bearer_after(
                                record.bind_bearer_generation,
                                1,
                                record.stamp.bearer_generation,
                            )
                            && response.validate().is_ok()
                            && terminal_response_exists(scope, record, response)
                    }
                    _ => false,
                }
        }
    };
    if !valid_generations {
        return Err(InfrastructureError::Invariant(
            "service request phase or receipt mismatch",
        ));
    }
    Ok(())
}

fn service_bearer_after(base: u64, transitions: u64, actual: u64) -> bool {
    base.checked_add(transitions) == Some(actual)
}

fn empty_service_action_history(record: &ServiceRequestStateRecord) -> bool {
    record.apply_generation == 0
        && record.apply_bearer_generation == 0
        && record.apply_nonce_high_water == 0
        && record.arm_generation == 0
        && record.arm_bearer_generation == 0
        && record.arm_nonce_high_water == 0
        && record.claim_generation == 0
        && record.claim_bearer_generation == 0
        && record.claim_nonce_high_water == 0
}

fn valid_service_queue_receipt(
    record: &ServiceRequestStateRecord,
    response: super::ContinuationDescriptor,
    receipt: ServiceEnqueueReceipt,
) -> bool {
    let descriptor = record.stamp.identity;
    record.apply_bearer_generation != 0
        && record.apply_generation != 0
        && record.apply_nonce_high_water != 0
        && valid_service_causal_identity(record, response, receipt.plan.causal)
        && receipt.plan.bearer_generation == record.apply_bearer_generation
        && receipt.plan.apply_generation == record.apply_generation
        && receipt.plan.apply_nonce == record.apply_nonce_high_water
        && receipt.queue == descriptor.queue
        && receipt.queue_generation == descriptor.queue_generation
        && receipt.payload_slot == descriptor.payload_slot
        && receipt.payload_generation == descriptor.payload_generation
        && receipt.transport_receipt_digest != 0
}

fn valid_service_arm_receipt(
    record: &ServiceRequestStateRecord,
    response: super::ContinuationDescriptor,
    queue_receipt: ServiceEnqueueReceipt,
    receipt: ServiceArmReceipt,
) -> bool {
    let descriptor = record.stamp.identity;
    record.arm_bearer_generation != 0
        && record.arm_generation != 0
        && record.arm_nonce_high_water != 0
        && valid_service_causal_identity(record, response, receipt.plan.causal)
        && receipt.plan.queue_receipt == queue_receipt
        && receipt.plan.bearer_generation == record.arm_bearer_generation
        && receipt.plan.arm_generation == record.arm_generation
        && receipt.plan.arm_nonce == record.arm_nonce_high_water
        && receipt.response_slot_id == descriptor.response_slot_id
        && receipt.response_slot_generation == descriptor.response_slot_generation
        && receipt.bound_continuation_id == response.continuation_id
        && receipt.bound_continuation_generation == response.generation
        && receipt.transport_receipt_digest != 0
}

fn valid_service_causal_identity(
    record: &ServiceRequestStateRecord,
    response: super::ContinuationDescriptor,
    causal: ServiceRequestCausalIdentity,
) -> bool {
    let parent_task = match record.stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return false,
    };
    causal.registry_instance == record.stamp.root.registry_instance
        && causal.scope == record.stamp.root.scope
        && causal.authority_epoch == record.stamp.root.authority_epoch
        && causal.root_effect == record.stamp.root.root_effect
        && causal.workload_request_id == record.stamp.workload.request.id
        && causal.workload_request_generation == record.stamp.workload.request.generation
        && causal.workload_nonce == record.stamp.workload.nonce
        && causal.workload_bearer_generation == record.stamp.workload.bearer_generation
        && causal.admission_domain == record.stamp.domain.domain
        && causal.admission_binding_epoch == record.stamp.domain.binding_epoch
        && causal.parent_task == parent_task
        && causal.request_nonce == record.stamp.nonce
        && causal.descriptor == record.stamp.identity
        && causal.response == response
}

fn valid_service_child_binding(
    record: &ServiceRequestStateRecord,
    receipt: ServiceChildBindingReceipt,
) -> bool {
    let claimant = receipt.claimant;
    super::service::valid_service_child_binding_commitment(record, receipt)
        && claimant.registry_instance == record.stamp.root.registry_instance
        && claimant.scope == record.stamp.root.scope
        && claimant.authority_epoch == record.stamp.root.authority_epoch
        && claimant.root_effect == record.stamp.root.root_effect
        && claimant.workload_request_id != 0
        && claimant.workload_request_generation != 0
        && claimant.workload_nonce != 0
        && claimant.workload_bearer_generation != 0
        && claimant.domain == record.stamp.identity.destination_domain
        && claimant.binding_epoch == record.stamp.identity.destination_binding_epoch
        && claimant.task.validate().is_ok()
        && claimant.task_nonce != 0
        && claimant.task_bearer_generation != 0
}

fn terminal_claimant_dominates(
    scope: &ScopeInfrastructure,
    historical: ServiceClaimantSnapshot,
) -> bool {
    scope
        .tasks
        .get(historical.task.work_id)
        .is_some_and(|task| {
            task.stamp.root.registry_instance == historical.registry_instance
                && task.stamp.root.scope == historical.scope
                && task.stamp.root.root_effect == historical.root_effect
                && task.stamp.root.authority_epoch >= historical.authority_epoch
                && task.stamp.workload.request.id == historical.workload_request_id
                && task.stamp.workload.request.generation == historical.workload_request_generation
                && task.stamp.workload.nonce == historical.workload_nonce
                && task.stamp.workload.bearer_generation >= historical.workload_bearer_generation
                && task.stamp.domain.domain == historical.domain
                && task.stamp.domain.binding_epoch >= historical.binding_epoch
                && task.stamp.identity == historical.task
                && task.stamp.nonce == historical.task_nonce
                && task.stamp.bearer_generation >= historical.task_bearer_generation
                && task.stamp.parent == ParentStamp::Request(task.stamp.workload.request)
                && matches!(
                    task.phase,
                    TaskPhase::Entered | TaskPhase::Isolated | TaskPhase::Reaped
                )
        })
}

fn terminal_response_exists(
    scope: &ScopeInfrastructure,
    service: &ServiceRequestStateRecord,
    response: super::ContinuationDescriptor,
) -> bool {
    service.response_identity == Some(response)
        && scope
            .continuations
            .get(response.continuation_id)
            .is_some_and(|continuation| {
                continuation.service_owner.is_none()
                    && continuation.stamp.root.registry_instance
                        == service.stamp.root.registry_instance
                    && continuation.stamp.root.scope == service.stamp.root.scope
                    && continuation.stamp.root.root_effect == service.stamp.root.root_effect
                    && continuation.stamp.root.authority_epoch >= service.stamp.root.authority_epoch
                    && continuation.stamp.workload.request == service.stamp.workload.request
                    && continuation.stamp.workload.nonce == service.stamp.workload.nonce
                    && continuation.stamp.workload.bearer_generation
                        >= service.stamp.workload.bearer_generation
                    && continuation.stamp.domain.domain == service.stamp.domain.domain
                    && continuation.stamp.domain.binding_epoch >= service.stamp.domain.binding_epoch
                    && matches!(
                        (continuation.stamp.parent, service.stamp.parent),
                        (ParentStamp::Task(current), ParentStamp::Task(historical))
                            if current == historical
                    )
                    && continuation.stamp.identity.continuation_id == response.continuation_id
                    && continuation.stamp.identity.generation == response.generation
                    && continuation.stamp.identity.vm_generation == response.vm_generation
                    && response.source_domain == continuation.origin_source.domain
                    && response.source_binding_epoch == continuation.origin_source.binding_epoch
                    && continuation.stamp.identity.source_domain
                        == continuation.origin_source.domain
                    && continuation.stamp.identity.source_binding_epoch
                        >= continuation.origin_source.binding_epoch
            })
}

fn check_service_continuation_owners(
    scope: &ScopeInfrastructure,
) -> Result<(), InfrastructureError> {
    for request in scope.service_requests.iter() {
        let owner = RequestKey {
            id: request.stamp.identity.request_id,
            generation: request.stamp.identity.generation,
        };
        let Some(bound) = request.bound_continuation else {
            if service_request_phase_live(request.phase)
                && !matches!(request.phase, ServiceRequestPhase::ReservedUnbound)
            {
                return Err(InfrastructureError::Invariant(
                    "live bound service request lacks continuation owner",
                ));
            }
            continue;
        };
        let continuation = scope
            .continuations
            .get(bound.identity.continuation_id)
            .ok_or(InfrastructureError::Invariant(
                "service request bound continuation is missing",
            ))?;
        let current_source = scope
            .binding_epoch(continuation.stamp.identity.source_domain)
            .map_err(|_| {
                InfrastructureError::Invariant(
                    "service continuation references unknown source domain",
                )
            })?;
        if !service_request_phase_live(request.phase)
            || continuation.stamp != bound
            || continuation.stamp.workload != request.stamp.workload
            || continuation.stamp.parent != request.stamp.parent
            || continuation.service_owner != Some(owner)
            || continuation.phase != ContinuationPhase::Pending
            || continuation.stamp.identity.source_binding_epoch != current_source
        {
            return Err(InfrastructureError::Invariant(
                "live service continuation owner mismatch",
            ));
        }
        if scope
            .service_requests
            .iter()
            .filter(|candidate| {
                candidate
                    .bound_continuation
                    .is_some_and(|candidate| candidate == bound)
                    && service_request_phase_live(candidate.phase)
            })
            .count()
            > 1
        {
            return Err(InfrastructureError::Invariant(
                "continuation has multiple live service requests",
            ));
        }
    }
    for continuation in scope.continuations.iter() {
        let Some(owner) = continuation.service_owner else {
            continue;
        };
        if scope
            .service_requests
            .iter()
            .filter(|request| {
                request.stamp.identity.request_id == owner.id
                    && request.stamp.identity.generation == owner.generation
                    && request.bound_continuation == Some(continuation.stamp)
                    && service_request_phase_live(request.phase)
            })
            .count()
            != 1
        {
            return Err(InfrastructureError::Invariant(
                "continuation owner lacks unique live service request",
            ));
        }
    }
    Ok(())
}
