// SPDX-License-Identifier: MPL-2.0

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use super::fault::validate_exact_task_fault_pair;
use super::{
    ArmedFaultTask, EnteredTaskLease, FaultPhase, InfrastructureError, InfrastructureEventKind,
    InfrastructureKind, InfrastructureState, LinearResult, ParentStamp, ReservedFaultTask,
    ReverseIndexRecord, ReverseParent, ScopeInfrastructure, TaskAdoption, TaskAnchorPhase,
    TaskAnchorRecoveryState, TaskLease, TaskPhase, TaskRecoveryProjection, TaskRecoveryState,
    TaskWorkDescriptor, TaskWorkRole, WorkloadContext, bearer_state, checked_add, checked_sub,
    linear_apply, mint_task_key, next_task_bearer_generation, preview_bearer_stamp,
    preview_revision, preview_workload_child_add, preview_workload_child_sub, require_vacancy,
    reverse_index_for_fault, reverse_index_for_task, validate_active_admission, validate_context,
    validate_recovery_context, validate_task_key,
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
            __cser_core::matches!(record.phase, TaskPhase::Admitted | TaskPhase::Entered)
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
            super::TaskRecord {
                stamp,
                phase: TaskPhase::Admitted,
                anchor: TaskAnchorPhase::Live,
                service_fault: None,
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
        Ok(TaskLease(mint_task_key::<bearer_state::TaskAdmitted>(
            scope.tasks.get(descriptor.work_id).unwrap(),
        )))
    }

    pub(in super::super) fn claim_task_entry(
        &mut self,
        lease: TaskLease,
    ) -> LinearResult<TaskLease, EnteredTaskLease> {
        linear_apply(lease, |lease| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(lease.0.authority.scope)?;
            let record = validate_task_key(scope, registry_instance, &lease.0)?;
            if __cser_core::matches!(
                record.stamp.identity.role,
                TaskWorkRole::ServiceRequest | TaskWorkRole::ReplacementRecovery
            ) || record.phase != TaskPhase::Admitted
                || record.anchor != TaskAnchorPhase::Live
                || record.service_fault.is_some()
            {
                return Err(InfrastructureError::InvalidState);
            }
            let work_id = record.stamp.identity.work_id;
            let next_bearer_generation = next_task_bearer_generation(record)?;
            let next_revision = preview_revision(scope)?;
            let record = scope.tasks.get_mut(work_id).unwrap();
            record.phase = TaskPhase::Entered;
            record.stamp.bearer_generation = next_bearer_generation;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::TaskEntered,
                work_id,
                record.stamp.identity.generation,
            );
            Ok(EnteredTaskLease(
                mint_task_key::<bearer_state::TaskEntered>(record),
            ))
        })
    }

    pub(in super::super) fn claim_service_task_entry(
        &mut self,
        reserved: ReservedFaultTask,
    ) -> LinearResult<ReservedFaultTask, ArmedFaultTask> {
        linear_apply(reserved, |reserved| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(reserved.0.authority.scope)?;
            let task = validate_task_key(scope, registry_instance, &reserved.0)?;
            let task_stamp = task.stamp;
            if task.phase != TaskPhase::Admitted
                || task.anchor != TaskAnchorPhase::Live
                || !__cser_core::matches!(
                    task_stamp.identity.role,
                    TaskWorkRole::ServiceRequest | TaskWorkRole::ReplacementRecovery
                )
            {
                return Err(InfrastructureError::InvalidState);
            }
            let (link, fault) = validate_exact_task_fault_pair(scope, task)?;
            if fault.phase != FaultPhase::Reserved {
                return Err(InfrastructureError::StaleClaim);
            }
            let link = *link;
            let next_task_generation = next_task_bearer_generation(task)?;
            let next_fault_generation = fault
                .stamp
                .bearer_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let next_revision = preview_revision(scope)?;

            let fault = scope.faults.get_mut(link.fault_id).unwrap();
            fault.phase = FaultPhase::Armed;
            fault.stamp.bearer_generation = next_fault_generation;
            fault.owner.task_bearer_generation = next_task_generation;
            let task = scope.tasks.get_mut(task_stamp.identity.work_id).unwrap();
            task.phase = TaskPhase::Entered;
            task.stamp.bearer_generation = next_task_generation;
            let task_link = task.service_fault.as_mut().unwrap();
            task_link.fault_bearer_generation = next_fault_generation;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::TaskEntered,
                task_stamp.identity.work_id,
                task_stamp.identity.generation,
            );
            Ok(ArmedFaultTask(
                mint_task_key::<bearer_state::TaskFaultArmed>(task),
            ))
        })
    }

    pub(in super::super) fn reject_task_construction(
        &mut self,
        lease: TaskLease,
    ) -> LinearResult<TaskLease, ()> {
        linear_apply(lease, |lease| {
            self.finish_task_key(&lease.0, TaskPhase::Admitted, TaskPhase::Rejected)
        })
    }

    pub(in super::super) fn isolate_task(
        &mut self,
        lease: TaskLease,
    ) -> LinearResult<TaskLease, ()> {
        linear_apply(lease, |lease| {
            self.finish_task_key(&lease.0, TaskPhase::Admitted, TaskPhase::Isolated)
        })
    }

    pub(in super::super) fn isolate_entered_task(
        &mut self,
        lease: EnteredTaskLease,
    ) -> LinearResult<EnteredTaskLease, ()> {
        linear_apply(lease, |lease| {
            self.finish_task_key(&lease.0, TaskPhase::Entered, TaskPhase::Isolated)
        })
    }

    pub(in super::super) fn reap_task(
        &mut self,
        lease: EnteredTaskLease,
    ) -> LinearResult<EnteredTaskLease, ()> {
        linear_apply(lease, |lease| {
            self.finish_task_key(&lease.0, TaskPhase::Entered, TaskPhase::Reaped)
        })
    }

    fn finish_task_key<State: bearer_state::Sealed>(
        &mut self,
        key: &super::BearerKey<State>,
        required: TaskPhase,
        terminal: TaskPhase,
    ) -> Result<(), InfrastructureError> {
        self.require_authoritative()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(key.authority.scope)?;
        let record = validate_task_key(scope, registry_instance, key)?;
        if record.phase != required
            || record.anchor != TaskAnchorPhase::Live
            || record.service_fault.is_some()
        {
            return Err(InfrastructureError::InvalidState);
        }
        finish_task_record(scope, record.stamp, terminal)
    }

    pub(in super::super) fn query_task(
        &self,
        context: &WorkloadContext,
        work_id: u64,
        generation: u64,
    ) -> Result<TaskRecoveryProjection, InfrastructureError> {
        self.require_authoritative()?;
        let scope = self.scope(context.root.scope)?;
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
        if record.anchor == TaskAnchorPhase::Live {
            validate_context(scope, self.registry_instance, context)?;
        } else {
            validate_recovery_context(scope, self.registry_instance, context)?;
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
            anchor: match record.anchor {
                TaskAnchorPhase::Live => TaskAnchorRecoveryState::Live,
                TaskAnchorPhase::TerminalRetained => TaskAnchorRecoveryState::TerminalRetained,
                TaskAnchorPhase::TerminalDrained => TaskAnchorRecoveryState::TerminalDrained,
            },
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
        if record.anchor != TaskAnchorPhase::Live
            || !__cser_core::matches!(record.phase, TaskPhase::Admitted | TaskPhase::Entered)
        {
            return Err(InfrastructureError::InvalidState);
        }

        // Complete every lookup and arithmetic check before the first write.
        let phase = record.phase;
        let task_stamp = record.stamp;
        let task_generation = next_task_bearer_generation(record)?;
        let task_index_slot = task_stamp.nonce;
        let task_index = scope
            .reverse_indexes
            .get(task_index_slot)
            .ok_or(InfrastructureError::Invariant("invalid task reverse index"))?;
        if *task_index != reverse_index_for_task(record) {
            return Err(InfrastructureError::Invariant("invalid task reverse index"));
        }
        let composite = if let Some(link) = record.service_fault {
            let (_, fault) = validate_exact_task_fault_pair(scope, record)?;
            if !__cser_core::matches!(
                (phase, fault.phase),
                (TaskPhase::Admitted, FaultPhase::Reserved)
                    | (TaskPhase::Entered, FaultPhase::Armed)
            ) {
                return Err(InfrastructureError::StaleClaim);
            }
            let fault_generation = fault
                .stamp
                .bearer_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let fault_index = scope.reverse_indexes.get(fault.stamp.nonce).ok_or(
                InfrastructureError::Invariant("invalid fault reverse index"),
            )?;
            if *fault_index != reverse_index_for_fault(fault) {
                return Err(InfrastructureError::Invariant(
                    "invalid fault reverse index",
                ));
            }
            Some((link, fault_generation))
        } else {
            None
        };
        let next_revision = preview_revision(scope)?;

        let mut installed_task_stamp = task_stamp;
        installed_task_stamp.domain = context.domain;
        installed_task_stamp.workload = context.workload;
        installed_task_stamp.bearer_generation = task_generation;
        if let Some((link, fault_generation)) = composite {
            let fault = scope.faults.get_mut(link.fault_id).unwrap();
            fault.stamp.domain = context.domain;
            fault.stamp.workload = context.workload;
            fault.stamp.identity.admission_binding_epoch = context.domain.binding_epoch;
            fault.stamp.bearer_generation = fault_generation;
            fault.owner.task_bearer_generation = task_generation;
            scope
                .reverse_indexes
                .get_mut(link.fault_nonce)
                .unwrap()
                .binding_epoch = context.domain.binding_epoch;
            let task = scope.tasks.get_mut(work_id).unwrap();
            task.stamp = installed_task_stamp;
            task.service_fault.as_mut().unwrap().fault_bearer_generation = fault_generation;
        } else {
            scope.tasks.get_mut(work_id).unwrap().stamp = installed_task_stamp;
        }
        scope
            .reverse_indexes
            .get_mut(task_index_slot)
            .unwrap()
            .binding_epoch = context.domain.binding_epoch;
        scope.revision = next_revision;
        scope.events.push(
            InfrastructureEventKind::AuthorityAdvanced,
            work_id,
            generation,
        );
        let task = scope.tasks.get(work_id).unwrap();
        Ok(match (phase, composite.is_some()) {
            (TaskPhase::Admitted, false) => {
                TaskAdoption::Admitted(TaskLease(mint_task_key::<bearer_state::TaskAdmitted>(task)))
            }
            (TaskPhase::Entered, false) => TaskAdoption::Entered(EnteredTaskLease(
                mint_task_key::<bearer_state::TaskEntered>(task),
            )),
            (TaskPhase::Admitted, true) => {
                TaskAdoption::FaultReserved(ReservedFaultTask(mint_task_key::<
                    bearer_state::TaskFaultReserved,
                >(task)))
            }
            (TaskPhase::Entered, true) => {
                TaskAdoption::FaultArmed(ArmedFaultTask(mint_task_key::<
                    bearer_state::TaskFaultArmed,
                >(task)))
            }
            _ => return Err(InfrastructureError::Invariant("invalid task adoption")),
        })
    }
}

fn finish_task_record(
    scope: &mut ScopeInfrastructure,
    stamp: super::BearerStamp<TaskWorkDescriptor>,
    terminal: TaskPhase,
) -> Result<(), InfrastructureError> {
    let record = scope.tasks.get(stamp.identity.work_id).unwrap();
    let next_bearer_generation = next_task_bearer_generation(record)?;
    let next_revision = preview_revision(scope)?;
    let next_tasks = checked_sub(scope.live.tasks, 1)?;
    let next_children = preview_workload_child_sub(scope, stamp.workload.request)?;
    let record = scope.tasks.get_mut(stamp.identity.work_id).unwrap();
    record.phase = terminal;
    record.anchor = if record.live_children == 0 {
        TaskAnchorPhase::TerminalDrained
    } else {
        TaskAnchorPhase::TerminalRetained
    };
    record.stamp.bearer_generation = next_bearer_generation;
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
