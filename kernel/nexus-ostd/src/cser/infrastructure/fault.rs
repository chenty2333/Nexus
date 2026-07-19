// SPDX-License-Identifier: MPL-2.0

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use super::{
    AppliedFaultDisposition, ArmedFaultEvent, BearerStamp, EnteredTaskLease, FaultDescriptor,
    FaultDisposition, FaultDispositionPlan, FaultEvent, FaultObservation, FaultPhase,
    FaultRecoveryProjection, FaultStateRecord, InfrastructureError, InfrastructureEventKind,
    InfrastructureKind, InfrastructureState, LedgerMode, LinearResult, ParentStamp,
    ReverseIndexRecord, ReverseParent, ScopeInfrastructure, ServiceCrashCause,
    ServiceFaultProjection, ServiceFaultReceipt, TaskLease, TaskPhase, TaskWorkRole,
    VmAuthorityKey, WorkloadContext, checked_add, checked_sub, context_from_stamp, linear_apply,
    preview_bearer_stamp, preview_nonce, preview_revision, preview_workload_child_add,
    require_vacancy, validate_active_admission, validate_context, validate_stamp_common,
    validate_task_bearer, validate_task_stamp,
};

impl InfrastructureState {
    pub(in super::super) fn reserve_fault_event(
        &mut self,
        task: &TaskLease,
        descriptor: FaultDescriptor,
    ) -> Result<FaultEvent, InfrastructureError> {
        self.require_authoritative()?;
        descriptor.validate()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(task.0.root.scope)?;
        validate_task_bearer(scope, registry_instance, task)?;
        validate_active_admission(scope)?;
        if scope.tasks.get(task.0.identity.work_id).unwrap().phase != TaskPhase::Admitted
            || descriptor.task != task.0.identity.task
            || task.0.identity.vm.map(VmAuthorityKey::generation) != Some(descriptor.vm_generation)
            || descriptor.service_domain != task.0.domain.domain
            || descriptor.service_binding_epoch != task.0.domain.binding_epoch
            || !__cser_core::matches!(
                task.0.identity.role,
                TaskWorkRole::ServiceRequest | TaskWorkRole::ReplacementRecovery
            )
        {
            return Err(InfrastructureError::InvalidState);
        }
        if let Some(existing) = scope.faults.get(descriptor.fault_id) {
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
        if scope.faults.iter().any(|record| {
            __cser_core::matches!(record.phase, FaultPhase::Reserved)
                && record.stamp.identity.task == descriptor.task
        }) {
            return Err(InfrastructureError::IdentityConflict);
        }
        require_vacancy(
            &scope.faults,
            descriptor.fault_id,
            InfrastructureKind::Fault,
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
            InfrastructureKind::Fault,
        )?;
        let task_record = scope.tasks.get(task.0.identity.work_id).unwrap();
        let next_task_children = checked_add(task_record.live_children, 1)?;
        let next_workload_children = preview_workload_child_add(scope, stamp.workload.request)?;
        let next_live = checked_add(scope.live.faults, 1)?;
        let next_revision = preview_revision(scope)?;
        let index = ReverseIndexRecord {
            slot: stamp.nonce,
            kind: InfrastructureKind::Fault,
            root_effect: stamp.root.root_effect,
            parent: ReverseParent::Task(task.0.identity),
            task: Some(descriptor.task),
            domain: descriptor.service_domain,
            binding_epoch: descriptor.service_binding_epoch,
            source_domain: None,
            source_binding_epoch: None,
            resource: None,
            actor_slot: None,
            retry_generation: descriptor.vm_generation,
        };
        scope.faults.install(
            FaultStateRecord {
                stamp,
                phase: FaultPhase::Reserved,
                receipt_generation: 0,
                closure_sequence: None,
            },
            InfrastructureKind::Fault,
        )?;
        scope
            .reverse_indexes
            .install(index, InfrastructureKind::Fault)?;
        scope.next_nonce = next_nonce;
        scope.revision = next_revision;
        scope.live.faults = next_live;
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
            InfrastructureEventKind::FaultReserved,
            descriptor.fault_id,
            descriptor.generation,
        );
        Ok(FaultEvent(stamp))
    }

    #[allow(clippy::too_many_arguments)]
    pub(in super::super) fn prepare_fault_disposition(
        &self,
        fault: ArmedFaultEvent,
        task: EnteredTaskLease,
        observation: FaultObservation,
        disposition: FaultDisposition,
        next_binding_epoch: u64,
        crash_generation: u64,
    ) -> LinearResult<(ArmedFaultEvent, EnteredTaskLease), FaultDispositionPlan> {
        linear_apply((fault, task), |(fault, task)| {
            self.require_authoritative()?;
            let event = fault.0;
            let task_stamp = task.0;
            let scope = self.scope(event.root.scope)?;
            validate_fault_bearer(scope, self.registry_instance, &event)?;
            validate_task_stamp(scope, self.registry_instance, &task_stamp)?;
            if event.parent != ParentStamp::Task(task_stamp.identity)
                || event.identity.task != task_stamp.identity.task
                || scope.faults.get(event.identity.fault_id).unwrap().phase != FaultPhase::Reserved
                || scope.tasks.get(task_stamp.identity.work_id).unwrap().phase != TaskPhase::Entered
                || scope
                    .tasks
                    .get(task_stamp.identity.work_id)
                    .unwrap()
                    .live_children
                    != 1
            {
                return Err(InfrastructureError::InvalidState);
            }
            let descriptor = event.identity;
            if observation.task != descriptor.task
                || observation.vm_generation != descriptor.vm_generation
                || observation.instruction_pointer != descriptor.instruction_pointer
                || observation.address != descriptor.address
                || observation.access != descriptor.access
                || observation.architecture_error != descriptor.architecture_error
                || observation.evidence_digest == 0
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let current_binding = scope.binding_epoch(descriptor.service_domain)?;
            match disposition {
                FaultDisposition::CrashService => {
                    if current_binding != descriptor.service_binding_epoch
                        || next_binding_epoch
                            != current_binding
                                .checked_add(1)
                                .ok_or(InfrastructureError::CounterOverflow)?
                        || crash_generation == 0
                    {
                        return Err(InfrastructureError::StaleBinding);
                    }
                }
                FaultDisposition::IsolateTask => {
                    if next_binding_epoch != current_binding || crash_generation != 0 {
                        return Err(InfrastructureError::InvalidIdentity);
                    }
                }
            }
            let receipt_generation = scope
                .faults
                .get(descriptor.fault_id)
                .unwrap()
                .receipt_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let (receipt_nonce, next_nonce) = preview_nonce(scope)?;
            Ok(FaultDispositionPlan {
                event,
                task: task_stamp,
                projection: ServiceFaultProjection {
                    fault_id: descriptor.fault_id,
                    generation: descriptor.generation,
                    task: descriptor.task,
                    vm_generation: descriptor.vm_generation,
                    disposition,
                    service_domain: descriptor.service_domain,
                    closed_binding_epoch: descriptor.service_binding_epoch,
                    crash_generation,
                    evidence_digest: observation.evidence_digest,
                },
                base_revision: scope.revision,
                next_binding_epoch,
                receipt_generation,
                receipt_nonce,
                next_nonce,
            })
        })
    }

    pub(in super::super) fn apply_fault_disposition_in_candidate(
        &mut self,
        plan: FaultDispositionPlan,
    ) -> LinearResult<FaultDispositionPlan, AppliedFaultDisposition> {
        linear_apply(plan, |plan| {
            if self.mode != LedgerMode::NonAuthoritativeCandidate {
                return Err(InfrastructureError::CandidateHasNoAuthority);
            }
            let scope = self.scope_mut(plan.event.root.scope)?;
            if scope.revision != plan.base_revision
                || scope.next_nonce != plan.receipt_nonce
                || scope.binding_epoch(plan.projection.service_domain)?
                    != plan.projection.closed_binding_epoch
            {
                return Err(InfrastructureError::StaleAuthority);
            }
            let fault = scope
                .faults
                .get(plan.event.identity.fault_id)
                .ok_or(InfrastructureError::UnknownObligation)?;
            let task = scope
                .tasks
                .get(plan.task.identity.work_id)
                .ok_or(InfrastructureError::UnknownObligation)?;
            if fault.stamp != plan.event
                || fault.phase != FaultPhase::Reserved
                || task.stamp != plan.task
                || task.phase != TaskPhase::Entered
                || task.live_children != 1
            {
                return Err(InfrastructureError::StaleClaim);
            }
            let next_revision = preview_revision(scope)?;
            let next_faults = checked_sub(scope.live.faults, 1)?;
            let next_tasks = checked_sub(scope.live.tasks, 1)?;
            let workload = scope
                .workloads
                .get(plan.event.workload.request.id)
                .ok_or(InfrastructureError::UnknownWorkload)?;
            if workload.request != plan.event.workload.request || workload.live_children < 2 {
                return Err(InfrastructureError::Invariant(
                    "fault disposition workload child underflow",
                ));
            }
            let next_workload_children = workload.live_children - 2;
            scope
                .faults
                .get_mut(plan.event.identity.fault_id)
                .unwrap()
                .phase = FaultPhase::Observed {
                projection: plan.projection,
                receipt_generation: plan.receipt_generation,
                receipt_nonce: plan.receipt_nonce,
                consumed: false,
                consume_generation: 0,
            };
            scope
                .faults
                .get_mut(plan.event.identity.fault_id)
                .unwrap()
                .receipt_generation = plan.receipt_generation;
            let task = scope.tasks.get_mut(plan.task.identity.work_id).unwrap();
            task.phase = TaskPhase::Isolated;
            task.live_children = 0;
            scope
                .workloads
                .get_mut(plan.event.workload.request.id)
                .unwrap()
                .live_children = next_workload_children;
            *scope.binding_epoch_mut(plan.projection.service_domain)? = plan.next_binding_epoch;
            scope.live.faults = next_faults;
            scope.live.tasks = next_tasks;
            scope.next_nonce = plan.next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::FaultObserved,
                plan.projection.fault_id,
                plan.projection.generation,
            );
            Ok(AppliedFaultDisposition {
                event: plan.event,
                projection: plan.projection,
                receipt_generation: plan.receipt_generation,
                receipt_nonce: plan.receipt_nonce,
            })
        })
    }

    pub(in super::super) fn consume_service_fault(
        &mut self,
        receipt: ServiceFaultReceipt,
    ) -> LinearResult<ServiceFaultReceipt, ServiceCrashCause> {
        linear_apply(receipt, |receipt| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(receipt.fault.root.scope)?;
            let record = scope
                .faults
                .get(receipt.projection.fault_id)
                .ok_or(InfrastructureError::UnknownObligation)?;
            if record.stamp.root.registry_instance != registry_instance
                || record.phase
                    != (FaultPhase::Observed {
                        projection: receipt.projection,
                        receipt_generation: receipt.receipt_generation,
                        receipt_nonce: receipt.receipt_nonce,
                        consumed: false,
                        consume_generation: 0,
                    })
            {
                return Err(InfrastructureError::StaleClaim);
            }
            let consume_generation = 1;
            let (consume_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            scope
                .faults
                .get_mut(receipt.projection.fault_id)
                .unwrap()
                .phase = FaultPhase::Observed {
                projection: receipt.projection,
                receipt_generation: receipt.receipt_generation,
                receipt_nonce: receipt.receipt_nonce,
                consumed: true,
                consume_generation,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            Ok(ServiceCrashCause {
                projection: receipt.projection,
                consume_generation,
                consume_nonce,
            })
        })
    }

    pub(in super::super) fn query_fault(
        &self,
        context: &WorkloadContext,
        fault_id: u64,
        generation: u64,
    ) -> Result<FaultRecoveryProjection, InfrastructureError> {
        self.require_authoritative()?;
        let scope = self.scope(context.root.scope)?;
        validate_context(scope, self.registry_instance, context)?;
        let record = scope
            .faults
            .get(fault_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
        if record.stamp.identity.generation != generation {
            return Err(InfrastructureError::StaleGeneration);
        }
        if record.stamp.workload.request != context.workload.request {
            return Err(InfrastructureError::ForeignWorkload);
        }
        Ok(FaultRecoveryProjection {
            descriptor: record.stamp.identity,
            receipt: match record.phase {
                FaultPhase::Observed { projection, .. } => Some(projection),
                FaultPhase::Reserved => None,
            },
            consumed: __cser_core::matches!(
                record.phase,
                FaultPhase::Observed { consumed: true, .. }
            ),
        })
    }
}

impl AppliedFaultDisposition {
    pub(in super::super) fn into_receipt(self) -> ServiceFaultReceipt {
        ServiceFaultReceipt {
            fault: self.event,
            projection: self.projection,
            receipt_generation: self.receipt_generation,
            receipt_nonce: self.receipt_nonce,
        }
    }
}

pub(super) fn validate_fault_bearer(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    stamp: &BearerStamp<FaultDescriptor>,
) -> Result<(), InfrastructureError> {
    validate_stamp_common(scope, registry_instance, stamp)?;
    let record = scope
        .faults
        .get(stamp.identity.fault_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp != *stamp {
        return Err(InfrastructureError::StaleGeneration);
    }
    let parent = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    let task = scope
        .tasks
        .get(parent.work_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if task.stamp.identity != parent
        || parent.task != stamp.identity.task
        || parent.vm.map(VmAuthorityKey::generation) != Some(stamp.identity.vm_generation)
    {
        return Err(InfrastructureError::StaleGeneration);
    }
    Ok(())
}
