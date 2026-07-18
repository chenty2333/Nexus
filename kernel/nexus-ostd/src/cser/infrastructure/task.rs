// SPDX-License-Identifier: MPL-2.0

use super::{
    ArmedFaultEvent, BearerStamp, EnteredTaskLease, FaultEvent, FaultPhase, InfrastructureError,
    InfrastructureEventKind, InfrastructureKind, InfrastructureState, LinearResult, ParentStamp,
    ReverseIndexRecord, ReverseParent, ScopeInfrastructure, TaskAdoption, TaskLease, TaskPhase,
    TaskRecord, TaskRecoveryProjection, TaskRecoveryState, TaskWorkDescriptor, TaskWorkRole,
    WorkloadContext, checked_add, checked_sub, first_task_child_kind, linear_apply,
    preview_bearer_stamp, preview_revision, preview_workload_child_add, preview_workload_child_sub,
    require_vacancy, validate_active_admission, validate_context, validate_fault_bearer,
    validate_task_stamp,
};

impl InfrastructureState {
    pub(in super::super) fn admit_task(
        &mut self,
        context: &WorkloadContext,
        descriptor: TaskWorkDescriptor,
    ) -> Result<TaskLease, InfrastructureError> {
        self.require_authoritative()?;
        descriptor.validate()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(context.root.scope)?;
        validate_context(scope, registry_instance, context)?;
        validate_active_admission(scope)?;
        if let Some(existing) = scope.tasks.get(descriptor.work_id) {
            return if existing.stamp.identity == descriptor
                && existing.stamp.workload.request == context.workload.request
            {
                Err(InfrastructureError::ExactReplay)
            } else if existing.stamp.identity.generation > descriptor.generation {
                Err(InfrastructureError::StaleGeneration)
            } else {
                Err(InfrastructureError::IdentityConflict)
            };
        }
        if scope.tasks.iter().any(|record| {
            matches!(record.phase, TaskPhase::Admitted | TaskPhase::Entered)
                && record.stamp.identity.task == descriptor.task
        }) {
            return Err(InfrastructureError::IdentityConflict);
        }
        require_vacancy(&scope.tasks, descriptor.work_id, InfrastructureKind::Task)?;
        let (stamp, next_nonce) = preview_bearer_stamp(
            scope,
            context,
            descriptor,
            ParentStamp::Request(context.workload.request),
        )?;
        require_vacancy(
            &scope.reverse_indexes,
            stamp.nonce,
            InfrastructureKind::Task,
        )?;
        let next_revision = preview_revision(scope)?;
        let next_tasks = checked_add(scope.live.tasks, 1)?;
        let next_children = preview_workload_child_add(scope, context.workload.request)?;
        let index = ReverseIndexRecord {
            slot: stamp.nonce,
            kind: InfrastructureKind::Task,
            root_effect: stamp.root.root_effect,
            parent: ReverseParent::Request(stamp.workload.request),
            task: Some(descriptor.task),
            domain: stamp.domain.domain,
            binding_epoch: stamp.domain.binding_epoch,
            source_domain: None,
            source_binding_epoch: None,
            resource: None,
            actor_slot: None,
            retry_generation: descriptor.generation,
        };
        scope.tasks.install(
            TaskRecord {
                stamp,
                phase: TaskPhase::Admitted,
                live_children: 0,
                closure_sequence: None,
            },
            InfrastructureKind::Task,
        )?;
        scope
            .reverse_indexes
            .install(index, InfrastructureKind::Task)?;
        scope.next_nonce = next_nonce;
        scope.revision = next_revision;
        scope.live.tasks = next_tasks;
        scope
            .workloads
            .get_mut(context.workload.request.id)
            .unwrap()
            .live_children = next_children;
        scope.events.push(
            InfrastructureEventKind::TaskAdmitted,
            descriptor.work_id,
            descriptor.generation,
        );
        Ok(TaskLease(
            scope.tasks.get(descriptor.work_id).unwrap().stamp,
        ))
    }

    pub(in super::super) fn claim_task_entry(
        &mut self,
        lease: TaskLease,
    ) -> LinearResult<TaskLease, EnteredTaskLease> {
        linear_apply(lease, |lease| {
            self.require_authoritative()?;
            let stamp = lease.0;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_task_stamp(scope, registry_instance, &stamp)?;
            if matches!(
                stamp.identity.role,
                TaskWorkRole::ServiceRequest | TaskWorkRole::ReplacementRecovery
            ) {
                return Err(InfrastructureError::InvalidState);
            }
            match scope.tasks.get(stamp.identity.work_id).unwrap().phase {
                TaskPhase::Admitted => {}
                TaskPhase::Entered => return Err(InfrastructureError::ExactReplay),
                _ => return Err(InfrastructureError::InvalidState),
            }
            let next_revision = preview_revision(scope)?;
            scope.tasks.get_mut(stamp.identity.work_id).unwrap().phase = TaskPhase::Entered;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::TaskEntered,
                stamp.identity.work_id,
                stamp.identity.generation,
            );
            Ok(EnteredTaskLease(stamp))
        })
    }

    pub(in super::super) fn claim_service_task_entry(
        &mut self,
        lease: TaskLease,
        fault: FaultEvent,
    ) -> LinearResult<(TaskLease, FaultEvent), (EnteredTaskLease, ArmedFaultEvent)> {
        linear_apply((lease, fault), |(lease, fault)| {
            self.require_authoritative()?;
            let stamp = lease.0;
            let fault_stamp = fault.0;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_task_stamp(scope, registry_instance, &stamp)?;
            validate_fault_bearer(scope, registry_instance, &fault_stamp)?;
            if !matches!(
                stamp.identity.role,
                TaskWorkRole::ServiceRequest | TaskWorkRole::ReplacementRecovery
            ) || fault_stamp.parent != ParentStamp::Task(stamp.identity)
                || fault_stamp.identity.task != stamp.identity.task
                || scope.tasks.get(stamp.identity.work_id).unwrap().phase != TaskPhase::Admitted
                || scope
                    .faults
                    .get(fault_stamp.identity.fault_id)
                    .unwrap()
                    .phase
                    != FaultPhase::Reserved
            {
                return Err(InfrastructureError::InvalidState);
            }
            let next_revision = preview_revision(scope)?;
            scope.tasks.get_mut(stamp.identity.work_id).unwrap().phase = TaskPhase::Entered;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::TaskEntered,
                stamp.identity.work_id,
                stamp.identity.generation,
            );
            Ok((EnteredTaskLease(stamp), ArmedFaultEvent(fault_stamp)))
        })
    }

    pub(in super::super) fn reject_task_construction(
        &mut self,
        lease: TaskLease,
    ) -> LinearResult<TaskLease, ()> {
        linear_apply(lease, |lease| {
            self.finish_task_stamp(&lease.0, TaskPhase::Admitted, TaskPhase::Rejected)
        })
    }

    pub(in super::super) fn isolate_task(
        &mut self,
        lease: TaskLease,
    ) -> LinearResult<TaskLease, ()> {
        linear_apply(lease, |lease| self.isolate_task_stamp(&lease.0))
    }

    pub(in super::super) fn isolate_entered_task(
        &mut self,
        lease: EnteredTaskLease,
    ) -> LinearResult<EnteredTaskLease, ()> {
        linear_apply(lease, |lease| self.isolate_task_stamp(&lease.0))
    }

    fn isolate_task_stamp(
        &mut self,
        stamp: &BearerStamp<TaskWorkDescriptor>,
    ) -> Result<(), InfrastructureError> {
        self.require_authoritative()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(stamp.root.scope)?;
        validate_task_stamp(scope, registry_instance, stamp)?;
        let phase = scope.tasks.get(stamp.identity.work_id).unwrap().phase;
        if matches!(
            phase,
            TaskPhase::Isolated | TaskPhase::Reaped | TaskPhase::Rejected
        ) {
            return Ok(());
        }
        if !matches!(phase, TaskPhase::Admitted | TaskPhase::Entered) {
            return Err(InfrastructureError::InvalidState);
        }
        finish_task_record(scope, stamp, TaskPhase::Isolated)
    }

    pub(in super::super) fn reap_task(
        &mut self,
        lease: EnteredTaskLease,
    ) -> LinearResult<EnteredTaskLease, ()> {
        linear_apply(lease, |lease| {
            self.finish_task_stamp(&lease.0, TaskPhase::Entered, TaskPhase::Reaped)
        })
    }

    fn finish_task_stamp(
        &mut self,
        stamp: &BearerStamp<TaskWorkDescriptor>,
        required: TaskPhase,
        terminal: TaskPhase,
    ) -> Result<(), InfrastructureError> {
        self.require_authoritative()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(stamp.root.scope)?;
        validate_task_stamp(scope, registry_instance, stamp)?;
        let phase = scope.tasks.get(stamp.identity.work_id).unwrap().phase;
        if phase == terminal {
            return Ok(());
        }
        if phase != required {
            return Err(InfrastructureError::InvalidState);
        }
        finish_task_record(scope, stamp, terminal)
    }

    pub(in super::super) fn query_task(
        &self,
        context: &WorkloadContext,
        work_id: u64,
        generation: u64,
    ) -> Result<TaskRecoveryProjection, InfrastructureError> {
        self.require_authoritative()?;
        let scope = self.scope(context.root.scope)?;
        validate_context(scope, self.registry_instance, context)?;
        let record = scope
            .tasks
            .get(work_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
        if record.stamp.identity.generation != generation {
            return Err(InfrastructureError::StaleGeneration);
        }
        if record.stamp.workload.request != context.workload.request {
            return Err(InfrastructureError::ForeignWorkload);
        }
        Ok(TaskRecoveryProjection {
            descriptor: record.stamp.identity,
            state: match record.phase {
                TaskPhase::Admitted => TaskRecoveryState::Admitted,
                TaskPhase::Entered => TaskRecoveryState::Entered,
                TaskPhase::Rejected => TaskRecoveryState::Rejected,
                TaskPhase::Isolated => TaskRecoveryState::Isolated,
                TaskPhase::Reaped => TaskRecoveryState::Reaped,
            },
            live_children: record.live_children,
        })
    }

    pub(in super::super) fn adopt_task_after_fence(
        &mut self,
        context: &WorkloadContext,
        work_id: u64,
        generation: u64,
    ) -> Result<TaskAdoption, InfrastructureError> {
        self.require_authoritative()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(context.root.scope)?;
        validate_context(scope, registry_instance, context)?;
        let record = scope
            .tasks
            .get(work_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
        if record.stamp.identity.generation != generation {
            return Err(InfrastructureError::StaleGeneration);
        }
        if record.stamp.workload.request != context.workload.request
            || record.stamp.domain.domain != context.domain.domain
            || record.stamp.domain.binding_epoch >= context.domain.binding_epoch
        {
            return Err(InfrastructureError::StaleBinding);
        }
        let phase = record.phase;
        if !matches!(phase, TaskPhase::Admitted | TaskPhase::Entered) {
            return Err(InfrastructureError::InvalidState);
        }
        let bearer_generation = record
            .stamp
            .bearer_generation
            .checked_add(1)
            .ok_or(InfrastructureError::CounterOverflow)?;
        let next_revision = preview_revision(scope)?;
        let index_slot = record.stamp.nonce;
        let mut stamp = record.stamp;
        stamp.domain = context.domain;
        stamp.workload = context.workload;
        stamp.bearer_generation = bearer_generation;
        scope.tasks.get_mut(work_id).unwrap().stamp = stamp;
        let index = scope
            .reverse_indexes
            .get_mut(index_slot)
            .ok_or(InfrastructureError::Invariant("missing task reverse index"))?;
        index.binding_epoch = context.domain.binding_epoch;
        scope.revision = next_revision;
        scope.events.push(
            InfrastructureEventKind::AuthorityAdvanced,
            work_id,
            generation,
        );
        Ok(match phase {
            TaskPhase::Admitted => TaskAdoption::Admitted(TaskLease(stamp)),
            TaskPhase::Entered => TaskAdoption::Entered(EnteredTaskLease(stamp)),
            _ => return Err(InfrastructureError::Invariant("invalid task adoption")),
        })
    }
}

fn finish_task_record(
    scope: &mut ScopeInfrastructure,
    stamp: &BearerStamp<TaskWorkDescriptor>,
    terminal: TaskPhase,
) -> Result<(), InfrastructureError> {
    let record = scope.tasks.get(stamp.identity.work_id).unwrap();
    if record.live_children != 0 {
        return Err(InfrastructureError::ClosureBlocked {
            kind: first_task_child_kind(scope, stamp.identity)?,
            live: record.live_children,
        });
    }
    let next_revision = preview_revision(scope)?;
    let next_tasks = checked_sub(scope.live.tasks, 1)?;
    let next_children = preview_workload_child_sub(scope, stamp.workload.request)?;
    scope.tasks.get_mut(stamp.identity.work_id).unwrap().phase = terminal;
    scope.live.tasks = next_tasks;
    scope
        .workloads
        .get_mut(stamp.workload.request.id)
        .unwrap()
        .live_children = next_children;
    scope.revision = next_revision;
    let kind = match terminal {
        TaskPhase::Rejected => InfrastructureEventKind::TaskRejected,
        TaskPhase::Isolated => InfrastructureEventKind::TaskIsolated,
        TaskPhase::Reaped => InfrastructureEventKind::TaskReaped,
        TaskPhase::Admitted | TaskPhase::Entered => {
            return Err(InfrastructureError::Invariant("nonterminal task finish"));
        }
    };
    scope
        .events
        .push(kind, stamp.identity.work_id, stamp.identity.generation);
    Ok(())
}
