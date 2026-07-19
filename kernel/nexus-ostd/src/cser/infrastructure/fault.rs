// SPDX-License-Identifier: MPL-2.0

use super::{
    ArmedFaultTask, BearerKey, CrashServiceReceipt, DomainFaultRecoveryProjection, FaultAccess,
    FaultBusinessPlan, FaultClaimProjection, FaultDisposition, FaultDispositionIntent,
    FaultDispositionPlan, FaultPhase, FaultPlanCommitment, FaultReceiptClaimOutcome,
    FaultRecoveryProjection, FaultSlotDescriptor, FaultStateRecord, FaultTaskOwner,
    InfrastructureError, InfrastructureEventKind, InfrastructureKind, InfrastructureState,
    InstalledFaultObservation, InstalledFaultProjection, IsolateTaskReceipt, LedgerMode,
    LinearFailure, LinearResult, ParentStamp, ReservedFaultTask, ReverseIndexRecord, ReverseParent,
    ScopeInfrastructure, ServiceCrashCause, ServiceFaultProjection, TaskAnchorPhase, TaskFaultLink,
    TaskLease, TaskPhase, TaskWorkRole, VmAuthorityKey, WorkloadContext, bearer_state, checked_add,
    checked_sub, context_from_stamp, linear_apply, mint_task_key, next_task_bearer_generation,
    preview_bearer_stamp, preview_revision, preview_workload_child_add, preview_workload_child_sub,
    require_vacancy, validate_active_admission, validate_recovery_context, validate_task_key,
};
use core::marker::PhantomData;
use sha2::{Digest, Sha256};

impl InfrastructureState {
    pub(in super::super) fn describe_armed_fault(
        &self,
        armed: &ArmedFaultTask,
    ) -> Result<(super::ScopeKey, FaultSlotDescriptor), InfrastructureError> {
        self.require_authoritative()?;
        let scope = self.scope(armed.0.authority.scope)?;
        let task = validate_task_key(scope, self.registry_instance, &armed.0)?;
        let (_, fault) = validate_exact_task_fault_pair(scope, task)?;
        if task.phase != TaskPhase::Entered
            || task.anchor != TaskAnchorPhase::Live
            || fault.phase != FaultPhase::Armed
        {
            return Err(InfrastructureError::StaleClaim);
        }
        Ok((scope.root.scope, fault.stamp.identity))
    }

    pub(in super::super) fn reserve_fault_event(
        &mut self,
        task: TaskLease,
        descriptor: FaultSlotDescriptor,
    ) -> LinearResult<TaskLease, ReservedFaultTask> {
        linear_apply(task, |task| {
            self.require_authoritative()?;
            descriptor.validate()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(task.0.authority.scope)?;
            let task_record = validate_task_key(scope, registry_instance, &task.0)?;
            validate_active_admission(scope)?;
            let task_stamp = task_record.stamp;
            if task_record.phase != TaskPhase::Admitted
                || task_record.anchor != TaskAnchorPhase::Live
                || task_record.service_fault.is_some()
                || descriptor.task != task_stamp.identity.task
                || task_stamp.identity.vm.map(VmAuthorityKey::generation)
                    != Some(descriptor.vm_generation)
                || descriptor.service_domain != task_stamp.domain.domain
                || descriptor.admission_binding_epoch != task_stamp.domain.binding_epoch
                || !matches!(
                    task_stamp.identity.role,
                    TaskWorkRole::ServiceRequest | TaskWorkRole::ReplacementRecovery
                )
            {
                return Err(InfrastructureError::InvalidState);
            }
            if let Some(existing) = scope.faults.get(descriptor.fault_id) {
                return if existing.stamp.identity == descriptor
                    && existing.stamp.parent == ParentStamp::Task(task_stamp.identity)
                {
                    Err(InfrastructureError::ExactReplay)
                } else if existing.stamp.identity.generation > descriptor.generation {
                    Err(InfrastructureError::StaleGeneration)
                } else {
                    Err(InfrastructureError::IdentityConflict)
                };
            }
            if scope.faults.iter().any(|record| {
                matches!(record.phase, FaultPhase::Reserved | FaultPhase::Armed)
                    && record.stamp.identity.task == descriptor.task
            }) {
                return Err(InfrastructureError::IdentityConflict);
            }
            require_vacancy(
                &scope.faults,
                descriptor.fault_id,
                InfrastructureKind::Fault,
            )?;
            let context = context_from_stamp(scope, task_stamp.workload)?;
            let (stamp, next_nonce) = preview_bearer_stamp(
                scope,
                &context,
                descriptor,
                ParentStamp::Task(task_stamp.identity),
            )?;
            require_vacancy(
                &scope.reverse_indexes,
                stamp.nonce,
                InfrastructureKind::Fault,
            )?;
            let next_task_children = checked_add(task_record.live_children, 1)?;
            let next_workload_children = preview_workload_child_add(scope, stamp.workload.request)?;
            let next_live = checked_add(scope.live.faults, 1)?;
            let next_task_generation = next_task_bearer_generation(task_record)?;
            let next_revision = preview_revision(scope)?;
            let index = ReverseIndexRecord {
                slot: stamp.nonce,
                kind: InfrastructureKind::Fault,
                root_effect: stamp.root.root_effect,
                parent: ReverseParent::Task(task_stamp.identity),
                task: Some(descriptor.task),
                domain: descriptor.service_domain,
                binding_epoch: descriptor.admission_binding_epoch,
                source_domain: None,
                source_binding_epoch: None,
                resource: None,
                actor_slot: None,
                retry_generation: descriptor.vm_generation,
            };
            scope.faults.install(
                FaultStateRecord {
                    stamp,
                    owner: FaultTaskOwner {
                        task: task_stamp.identity,
                        task_object_nonce: task_stamp.nonce,
                        task_bearer_generation: next_task_generation,
                    },
                    phase: FaultPhase::Reserved,
                    closure_sequence: None,
                },
                InfrastructureKind::Fault,
            )?;
            scope
                .reverse_indexes
                .install(index, InfrastructureKind::Fault)?;

            // From this point all operations are infallible existing-slot writes.
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.live.faults = next_live;
            scope
                .workloads
                .get_mut(stamp.workload.request.id)
                .unwrap()
                .live_children = next_workload_children;
            let task_record = scope.tasks.get_mut(task_stamp.identity.work_id).unwrap();
            task_record.stamp.bearer_generation = next_task_generation;
            task_record.live_children = next_task_children;
            task_record.service_fault = Some(TaskFaultLink {
                fault_id: descriptor.fault_id,
                fault_object_generation: descriptor.generation,
                fault_bearer_generation: stamp.bearer_generation,
                fault_nonce: stamp.nonce,
                terminal_install_digest: None,
            });
            scope.events.push(
                InfrastructureEventKind::FaultReserved,
                descriptor.fault_id,
                descriptor.generation,
            );
            Ok(ReservedFaultTask(mint_task_key::<
                bearer_state::TaskFaultReserved,
            >(task_record)))
        })
    }

    pub(in super::super) fn prepare_fault_disposition(
        &self,
        armed: ArmedFaultTask,
        observation: super::FaultObservation,
        disposition: FaultDisposition,
    ) -> LinearResult<ArmedFaultTask, (FaultDispositionIntent, FaultDispositionPlan)> {
        self.prepare_fault_disposition_with_business(
            armed,
            observation,
            disposition,
            FaultBusinessPlan::INFRASTRUCTURE_ONLY,
        )
    }

    pub(in super::super) fn prepare_fault_disposition_with_business(
        &self,
        armed: ArmedFaultTask,
        observation: super::FaultObservation,
        disposition: FaultDisposition,
        business: FaultBusinessPlan,
    ) -> LinearResult<ArmedFaultTask, (FaultDispositionIntent, FaultDispositionPlan)> {
        match self.preview_fault_disposition(&armed, observation, disposition, business) {
            Ok(plan) => Ok((
                FaultDispositionIntent {
                    armed,
                    commitment: plan.commitment.0,
                },
                plan,
            )),
            Err(error) => Err(LinearFailure {
                error,
                input: armed,
            }),
        }
    }

    pub(in super::super) fn finish_service_task_without_fault(
        &mut self,
        armed: ArmedFaultTask,
        evidence_digest: u64,
    ) -> LinearResult<ArmedFaultTask, super::ServiceTaskExitReceipt> {
        linear_apply(armed, |armed| {
            self.require_authoritative()?;
            if evidence_digest == 0 {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(armed.0.authority.scope)?;
            let task = validate_task_key(scope, registry_instance, &armed.0)?;
            let task_stamp = task.stamp;
            let (link, fault) = validate_exact_task_fault_pair(scope, task)?;
            if task.phase != TaskPhase::Entered
                || task.anchor != TaskAnchorPhase::Live
                || fault.phase != FaultPhase::Armed
            {
                return Err(InfrastructureError::StaleClaim);
            }
            if task.live_children != 1 {
                return Err(InfrastructureError::ClosureBlocked {
                    kind: InfrastructureKind::ServiceRequest,
                    live: task.live_children.saturating_sub(1),
                });
            }
            let next_revision = preview_revision(scope)?;
            let next_tasks = checked_sub(scope.live.tasks, 1)?;
            let next_faults = checked_sub(scope.live.faults, 1)?;
            let after_fault = preview_workload_child_sub(scope, task_stamp.workload.request)?;
            let next_workload_children = checked_sub(after_fault, 1)?;
            let next_task_generation = next_task_bearer_generation(task)?;
            let next_fault_generation = fault
                .stamp
                .bearer_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let receipt = super::ServiceTaskExitReceipt {
                fault_id: fault.stamp.identity.fault_id,
                generation: fault.stamp.identity.generation,
                task: task_stamp.identity.task,
                evidence_digest,
            };

            let fault = scope.faults.get_mut(link.fault_id).unwrap();
            fault.phase = FaultPhase::Exited { receipt };
            fault.stamp.bearer_generation = next_fault_generation;
            fault.owner.task_bearer_generation = next_task_generation;
            let task = scope.tasks.get_mut(task_stamp.identity.work_id).unwrap();
            task.phase = TaskPhase::Reaped;
            task.anchor = TaskAnchorPhase::TerminalDrained;
            task.live_children = 0;
            task.stamp.bearer_generation = next_task_generation;
            let task_link = task.service_fault.as_mut().unwrap();
            task_link.fault_bearer_generation = next_fault_generation;
            task_link.terminal_install_digest = Some(exit_receipt_digest(receipt));
            scope
                .workloads
                .get_mut(task_stamp.workload.request.id)
                .unwrap()
                .live_children = next_workload_children;
            scope.live.tasks = next_tasks;
            scope.live.faults = next_faults;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::TaskReaped,
                task_stamp.identity.work_id,
                task_stamp.identity.generation,
            );
            Ok(receipt)
        })
    }

    fn preview_fault_disposition(
        &self,
        armed: &ArmedFaultTask,
        observation: super::FaultObservation,
        disposition: FaultDisposition,
        business: FaultBusinessPlan,
    ) -> Result<FaultDispositionPlan, InfrastructureError> {
        self.require_authoritative()?;
        if observation.instruction_pointer == 0 || observation.evidence_digest == 0 {
            return Err(InfrastructureError::InvalidReceipt);
        }
        let scope = self.scope(armed.0.authority.scope)?;
        let task = validate_task_key(scope, self.registry_instance, &armed.0)?;
        let task_stamp = task.stamp;
        let (_, fault) = validate_exact_task_fault_pair(scope, task)?;
        if task.phase != TaskPhase::Entered
            || task.anchor != TaskAnchorPhase::Live
            || fault.phase != FaultPhase::Armed
            || observation.task != fault.stamp.identity.task
            || observation.vm_generation != fault.stamp.identity.vm_generation
        {
            return Err(InfrastructureError::StaleClaim);
        }
        let descriptor = fault.stamp.identity;
        let current_binding = scope.binding_epoch(descriptor.service_domain)?;
        if current_binding != descriptor.admission_binding_epoch {
            return Err(InfrastructureError::StaleBinding);
        }
        let next_binding_epoch = match disposition {
            FaultDisposition::CrashService => current_binding
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?,
            FaultDisposition::IsolateTask => current_binding,
        };
        let crash_generation = match disposition {
            FaultDisposition::CrashService => {
                if business == FaultBusinessPlan::INFRASTRUCTURE_ONLY {
                    scope
                        .revision
                        .checked_add(1)
                        .ok_or(InfrastructureError::CounterOverflow)?
                } else {
                    business
                        .domain_revision
                        .checked_add(1)
                        .ok_or(InfrastructureError::CounterOverflow)?
                }
            }
            FaultDisposition::IsolateTask => 0,
        };
        let projection = ServiceFaultProjection {
            fault_id: descriptor.fault_id,
            generation: descriptor.generation,
            task: descriptor.task,
            vm_generation: descriptor.vm_generation,
            disposition,
            service_domain: descriptor.service_domain,
            closed_binding_epoch: descriptor.admission_binding_epoch,
            crash_generation,
            evidence_digest: observation.evidence_digest,
        };
        let mut plan = FaultDispositionPlan {
            scope: scope.root.scope,
            task: task_stamp.identity,
            fault: descriptor,
            task_nonce: task_stamp.nonce,
            task_bearer_generation: task_stamp.bearer_generation,
            fault_nonce: fault.stamp.nonce,
            fault_bearer_generation: fault.stamp.bearer_generation,
            observation,
            projection,
            base_revision: scope.revision,
            next_binding_epoch,
            business,
            commitment: FaultPlanCommitment([0; 32]),
        };
        plan.commitment = fault_plan_commitment(scope, plan);
        Ok(plan)
    }

    pub(in super::super) fn validate_fault_disposition_intent(
        &self,
        intent: &FaultDispositionIntent,
        plan: FaultDispositionPlan,
    ) -> Result<(), InfrastructureError> {
        if intent.commitment != plan.commitment.0 {
            return Err(InfrastructureError::InvalidReceipt);
        }
        let expected = self.preview_fault_disposition(
            &intent.armed,
            plan.observation,
            plan.projection.disposition,
            plan.business,
        )?;
        if expected != plan {
            return Err(InfrastructureError::StaleClaim);
        }
        Ok(())
    }

    /// A generic non-authoritative candidate cannot acquire or spend fault
    /// authority. The outer Registry transaction uses the narrow staging hook
    /// after validating the exact live intent.
    pub(in super::super) fn apply_fault_disposition_in_candidate(
        &mut self,
        plan: FaultDispositionPlan,
    ) -> Result<super::AppliedFaultDisposition, InfrastructureError> {
        if self.mode != LedgerMode::NonAuthoritativeCandidate {
            return Err(InfrastructureError::CandidateHasNoAuthority);
        }
        let scope = self.scope_mut(plan.scope)?;
        validate_fault_plan_canonical(scope, plan)?;
        if plan.commitment != fault_plan_commitment(scope, plan)
            || plan.base_revision != scope.revision
        {
            return Err(InfrastructureError::StaleAuthority);
        }
        let task = scope
            .tasks
            .get(plan.task.work_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
        let (_, fault) = validate_exact_task_fault_pair(scope, task)?;
        if plan.task_nonce != task.stamp.nonce
            || plan.task_bearer_generation != task.stamp.bearer_generation
            || plan.fault != fault.stamp.identity
            || plan.fault_nonce != fault.stamp.nonce
            || plan.fault_bearer_generation != fault.stamp.bearer_generation
            || task.phase != TaskPhase::Entered
            || task.anchor != TaskAnchorPhase::Live
            || fault.phase != FaultPhase::Armed
        {
            return Err(InfrastructureError::StaleClaim);
        }
        let domain_position = scope
            .domains
            .iter()
            .position(|(domain, _)| *domain == plan.projection.service_domain)
            .ok_or(InfrastructureError::UnknownDomain)?;
        if scope.domains[domain_position].1 != plan.projection.closed_binding_epoch {
            return Err(InfrastructureError::StaleBinding);
        }
        let next_revision = preview_revision(scope)?;
        let next_faults = checked_sub(scope.live.faults, 1)?;
        let next_tasks = checked_sub(scope.live.tasks, 1)?;
        let workload = scope
            .workloads
            .get(task.stamp.workload.request.id)
            .ok_or(InfrastructureError::UnknownWorkload)?;
        if workload.request != task.stamp.workload.request || workload.live_children < 2 {
            return Err(InfrastructureError::Invariant(
                "fault disposition workload child underflow",
            ));
        }
        let next_workload_children = workload.live_children - 2;
        let next_task_children = checked_sub(task.live_children, 1)?;
        let next_task_generation = next_task_bearer_generation(task)?;
        let next_fault_generation = fault
            .stamp
            .bearer_generation
            .checked_add(1)
            .ok_or(InfrastructureError::CounterOverflow)?;
        let task_workload = task.stamp.workload.request;

        let fault = scope.faults.get_mut(plan.fault.fault_id).unwrap();
        fault.phase = FaultPhase::InstalledAwaitingClaim {
            projection: plan.projection,
            observation: plan.observation,
            commitment: plan.commitment,
        };
        fault.stamp.bearer_generation = next_fault_generation;
        fault.owner.task_bearer_generation = next_task_generation;
        let task = scope.tasks.get_mut(plan.task.work_id).unwrap();
        task.phase = TaskPhase::Isolated;
        task.live_children = next_task_children;
        task.anchor = if next_task_children == 0 {
            TaskAnchorPhase::TerminalDrained
        } else {
            TaskAnchorPhase::TerminalRetained
        };
        task.stamp.bearer_generation = next_task_generation;
        let link = task.service_fault.as_mut().unwrap();
        link.fault_bearer_generation = next_fault_generation;
        link.terminal_install_digest = Some(plan.commitment.0);
        scope
            .workloads
            .get_mut(task_workload.id)
            .unwrap()
            .live_children = next_workload_children;
        scope.domains[domain_position].1 = plan.next_binding_epoch;
        scope.live.faults = next_faults;
        scope.live.tasks = next_tasks;
        scope.revision = next_revision;
        scope.events.push(
            InfrastructureEventKind::FaultObserved,
            plan.projection.fault_id,
            plan.projection.generation,
        );
        Ok(super::AppliedFaultDisposition {
            projection: plan.projection,
            commitment: plan.commitment,
        })
    }

    pub(in super::super) fn install_fault_disposition(
        &mut self,
        intent: FaultDispositionIntent,
        plan: FaultDispositionPlan,
    ) -> LinearResult<ArmedFaultTask, InstalledFaultObservation> {
        let FaultDispositionIntent { armed, commitment } = intent;
        linear_apply(armed, |armed| {
            self.require_authoritative()?;
            if commitment != plan.commitment.0 {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(armed.0.authority.scope)?;
            let task = validate_task_key(scope, registry_instance, &armed.0)?;
            let task_stamp = task.stamp;
            let (link, fault) = validate_exact_task_fault_pair(scope, task)?;
            validate_fault_plan_canonical(scope, plan)?;
            if plan.commitment != fault_plan_commitment(scope, plan)
                || plan.base_revision != scope.revision
                || plan.task != task_stamp.identity
                || plan.task_nonce != task_stamp.nonce
                || plan.task_bearer_generation != task_stamp.bearer_generation
                || plan.fault != fault.stamp.identity
                || plan.fault_nonce != fault.stamp.nonce
                || plan.fault_bearer_generation != fault.stamp.bearer_generation
                || task.phase != TaskPhase::Entered
                || task.anchor != TaskAnchorPhase::Live
                || fault.phase != FaultPhase::Armed
            {
                return Err(InfrastructureError::StaleClaim);
            }
            let domain_position = scope
                .domains
                .iter()
                .position(|(domain, _)| *domain == plan.projection.service_domain)
                .ok_or(InfrastructureError::UnknownDomain)?;
            if scope.domains[domain_position].1 != plan.projection.closed_binding_epoch
                || (matches!(plan.projection.disposition, FaultDisposition::CrashService)
                    && plan.next_binding_epoch
                        != plan
                            .projection
                            .closed_binding_epoch
                            .checked_add(1)
                            .ok_or(InfrastructureError::CounterOverflow)?)
                || (matches!(plan.projection.disposition, FaultDisposition::IsolateTask)
                    && plan.next_binding_epoch != plan.projection.closed_binding_epoch)
            {
                return Err(InfrastructureError::StaleBinding);
            }
            let next_revision = preview_revision(scope)?;
            let next_faults = checked_sub(scope.live.faults, 1)?;
            let next_tasks = checked_sub(scope.live.tasks, 1)?;
            let workload = scope
                .workloads
                .get(task_stamp.workload.request.id)
                .ok_or(InfrastructureError::UnknownWorkload)?;
            if workload.request != task_stamp.workload.request || workload.live_children < 2 {
                return Err(InfrastructureError::Invariant(
                    "fault disposition workload child underflow",
                ));
            }
            let next_workload_children = workload.live_children - 2;
            let next_task_children = checked_sub(task.live_children, 1)?;
            let next_task_generation = next_task_bearer_generation(task)?;
            let next_fault_generation = fault
                .stamp
                .bearer_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;

            // Infallible install: every lookup and arithmetic operation above
            // completed before the first authoritative write below.
            let fault = scope.faults.get_mut(link.fault_id).unwrap();
            fault.phase = FaultPhase::InstalledAwaitingClaim {
                projection: plan.projection,
                observation: plan.observation,
                commitment: plan.commitment,
            };
            fault.stamp.bearer_generation = next_fault_generation;
            fault.owner.task_bearer_generation = next_task_generation;
            let task = scope.tasks.get_mut(task_stamp.identity.work_id).unwrap();
            task.phase = TaskPhase::Isolated;
            task.live_children = next_task_children;
            task.anchor = if next_task_children == 0 {
                TaskAnchorPhase::TerminalDrained
            } else {
                TaskAnchorPhase::TerminalRetained
            };
            task.stamp.bearer_generation = next_task_generation;
            let task_link = task.service_fault.as_mut().unwrap();
            task_link.fault_bearer_generation = next_fault_generation;
            task_link.terminal_install_digest = Some(plan.commitment.0);
            scope
                .workloads
                .get_mut(task_stamp.workload.request.id)
                .unwrap()
                .live_children = next_workload_children;
            scope.domains[domain_position].1 = plan.next_binding_epoch;
            scope.live.faults = next_faults;
            scope.live.tasks = next_tasks;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::FaultObserved,
                plan.projection.fault_id,
                plan.projection.generation,
            );
            let installed = InstalledFaultProjection {
                projection: plan.projection,
                commitment: plan.commitment,
            };
            Ok(match plan.projection.disposition {
                FaultDisposition::CrashService => InstalledFaultObservation::Crash(installed),
                FaultDisposition::IsolateTask => InstalledFaultObservation::Isolate(installed),
            })
        })
    }

    pub(in super::super) fn claim_fault_receipt(
        &mut self,
        context: &WorkloadContext,
        installed: InstalledFaultObservation,
    ) -> Result<FaultReceiptClaimOutcome, InfrastructureError> {
        self.require_authoritative()?;
        let projection = validate_installed_fault_variant(installed)?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(context.root.scope)?;
        validate_recovery_context(scope, registry_instance, context)?;
        let record = scope
            .faults
            .get(projection.projection.fault_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
        if record.stamp.identity.generation != projection.projection.generation
            || record.stamp.workload.request != context.workload.request
        {
            return Err(InfrastructureError::StaleGeneration);
        }
        match record.phase {
            FaultPhase::InstalledAwaitingClaim {
                projection: canonical,
                observation,
                commitment,
            } if canonical == projection.projection && commitment == projection.commitment => {
                let next_generation = record
                    .stamp
                    .bearer_generation
                    .checked_add(1)
                    .ok_or(InfrastructureError::CounterOverflow)?;
                let next_revision = preview_revision(scope)?;
                let owner_work_id = record.owner.task.work_id;
                let owner = scope
                    .tasks
                    .get(owner_work_id)
                    .ok_or(InfrastructureError::UnknownObligation)?;
                let (_, linked_fault) = validate_exact_task_fault_pair(scope, owner)?;
                if linked_fault.stamp.identity != record.stamp.identity {
                    return Err(InfrastructureError::Invariant("task-fault pair mismatch"));
                }
                let record = scope
                    .faults
                    .get_mut(projection.projection.fault_id)
                    .unwrap();
                record.stamp.bearer_generation = next_generation;
                record.phase = FaultPhase::Claimed {
                    projection: canonical,
                    observation,
                    commitment,
                    cause_claimed: false,
                };
                scope
                    .tasks
                    .get_mut(owner_work_id)
                    .unwrap()
                    .service_fault
                    .as_mut()
                    .unwrap()
                    .fault_bearer_generation = next_generation;
                scope.revision = next_revision;
                Ok(match canonical.disposition {
                    FaultDisposition::CrashService => {
                        FaultReceiptClaimOutcome::Crash(CrashServiceReceipt(mint_fault_key::<
                            bearer_state::FaultCrashReceiptClaimed,
                        >(
                            record
                        )))
                    }
                    FaultDisposition::IsolateTask => {
                        FaultReceiptClaimOutcome::Isolate(IsolateTaskReceipt(mint_fault_key::<
                            bearer_state::FaultIsolateReceiptClaimed,
                        >(
                            record
                        )))
                    }
                })
            }
            FaultPhase::Claimed {
                projection: canonical,
                commitment,
                ..
            } if canonical == projection.projection && commitment == projection.commitment => Ok(
                FaultReceiptClaimOutcome::AlreadyClaimed(match canonical.disposition {
                    FaultDisposition::CrashService => FaultClaimProjection::Crash(canonical),
                    FaultDisposition::IsolateTask => FaultClaimProjection::Isolate(canonical),
                }),
            ),
            FaultPhase::InstalledAwaitingClaim { .. } | FaultPhase::Claimed { .. } => {
                Err(InfrastructureError::InvalidReceipt)
            }
            FaultPhase::Reserved | FaultPhase::Armed | FaultPhase::Exited { .. } => {
                Err(InfrastructureError::InvalidState)
            }
        }
    }

    pub(in super::super) fn consume_service_fault(
        &mut self,
        receipt: CrashServiceReceipt,
    ) -> LinearResult<CrashServiceReceipt, ServiceCrashCause> {
        linear_apply(receipt, |receipt| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(receipt.0.authority.scope)?;
            let record = validate_fault_key(scope, registry_instance, &receipt.0)?;
            let (projection, observation, commitment) = match record.phase {
                FaultPhase::Claimed {
                    projection,
                    observation,
                    commitment,
                    cause_claimed: false,
                } if projection.disposition == FaultDisposition::CrashService => {
                    (projection, observation, commitment)
                }
                _ => return Err(InfrastructureError::InvalidState),
            };
            let next_generation = record
                .stamp
                .bearer_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let next_revision = preview_revision(scope)?;
            let owner_work_id = record.owner.task.work_id;
            let owner = scope
                .tasks
                .get(owner_work_id)
                .ok_or(InfrastructureError::UnknownObligation)?;
            let (_, linked_fault) = validate_exact_task_fault_pair(scope, owner)?;
            if linked_fault.stamp.identity != record.stamp.identity {
                return Err(InfrastructureError::Invariant("task-fault pair mismatch"));
            }
            let record = scope.faults.get_mut(projection.fault_id).unwrap();
            record.stamp.bearer_generation = next_generation;
            record.phase = FaultPhase::Claimed {
                projection,
                observation,
                commitment,
                cause_claimed: true,
            };
            scope
                .tasks
                .get_mut(owner_work_id)
                .unwrap()
                .service_fault
                .as_mut()
                .unwrap()
                .fault_bearer_generation = next_generation;
            scope.revision = next_revision;
            Ok(ServiceCrashCause(mint_fault_key::<
                bearer_state::FaultCrashCauseClaimed,
            >(record)))
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
        validate_recovery_context(scope, self.registry_instance, context)?;
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
        let (receipt, selector) = match record.phase {
            FaultPhase::InstalledAwaitingClaim {
                projection,
                commitment,
                ..
            }
            | FaultPhase::Claimed {
                projection,
                commitment,
                ..
            } => (
                Some(projection),
                Some(installed_fault_observation(projection, commitment)),
            ),
            FaultPhase::Reserved | FaultPhase::Armed | FaultPhase::Exited { .. } => (None, None),
        };
        Ok(FaultRecoveryProjection {
            descriptor: record.stamp.identity,
            receipt,
            selector,
            consumed: matches!(
                record.phase,
                FaultPhase::Claimed {
                    cause_claimed: true,
                    ..
                }
            ),
            awaiting_claim: matches!(record.phase, FaultPhase::InstalledAwaitingClaim { .. }),
        })
    }

    pub(in super::super) fn domain_fault_recovery_projection(
        &self,
        scope_key: super::ScopeKey,
        service_domain: super::DomainKey,
        binding_epoch: u64,
        crash_generation: u64,
    ) -> Result<Option<DomainFaultRecoveryProjection>, InfrastructureError> {
        let scope = match self.scope(scope_key) {
            Ok(scope) => scope,
            Err(InfrastructureError::NotEnabled) => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut current = None;
        for record in scope.faults.iter() {
            let (projection, commitment) = match record.phase {
                FaultPhase::InstalledAwaitingClaim {
                    projection,
                    commitment,
                    ..
                }
                | FaultPhase::Claimed {
                    projection,
                    commitment,
                    ..
                } if projection.disposition == FaultDisposition::CrashService => {
                    (projection, commitment)
                }
                FaultPhase::Reserved
                | FaultPhase::Armed
                | FaultPhase::Exited { .. }
                | FaultPhase::InstalledAwaitingClaim { .. }
                | FaultPhase::Claimed { .. } => continue,
            };
            if projection.service_domain != service_domain
                || projection.crash_generation != crash_generation
                || projection
                    .closed_binding_epoch
                    .checked_add(1)
                    .is_none_or(|epoch| epoch != binding_epoch)
            {
                continue;
            }
            let candidate = DomainFaultRecoveryProjection {
                fault_id: projection.fault_id,
                generation: projection.generation,
                task: projection.task,
                vm_generation: projection.vm_generation,
                service_domain: projection.service_domain,
                closed_binding_epoch: projection.closed_binding_epoch,
                crash_generation: projection.crash_generation,
                evidence_digest: projection.evidence_digest,
                plan_commitment: commitment.0,
            };
            if current.replace(candidate).is_some() {
                return Err(InfrastructureError::Invariant(
                    "duplicate domain fault recovery projection",
                ));
            }
        }
        Ok(current)
    }
}

impl super::AppliedFaultDisposition {
    pub(in super::super) fn into_installed(self) -> InstalledFaultObservation {
        let installed = InstalledFaultProjection {
            projection: self.projection,
            commitment: self.commitment,
        };
        match self.projection.disposition {
            FaultDisposition::CrashService => InstalledFaultObservation::Crash(installed),
            FaultDisposition::IsolateTask => InstalledFaultObservation::Isolate(installed),
        }
    }
}

fn mint_fault_key<State: bearer_state::Sealed>(record: &FaultStateRecord) -> BearerKey<State> {
    BearerKey {
        authority: super::AuthorityKey {
            registry_instance: record.stamp.root.registry_instance,
            scope: record.stamp.root.scope,
            authority_epoch: record.stamp.root.authority_epoch,
        },
        slot: record.stamp.identity.fault_id,
        object_generation: record.stamp.identity.generation,
        bearer_generation: record.stamp.bearer_generation,
        nonce: record.stamp.nonce,
        state: PhantomData,
    }
}

fn validate_fault_key<'a, State: bearer_state::Sealed>(
    scope: &'a ScopeInfrastructure,
    registry_instance: u64,
    key: &BearerKey<State>,
) -> Result<&'a FaultStateRecord, InfrastructureError> {
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
        .faults
        .get(key.slot)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp.identity.fault_id != key.slot {
        return Err(InfrastructureError::IdentityConflict);
    }
    if record.stamp.identity.generation != key.object_generation
        || record.stamp.bearer_generation != key.bearer_generation
        || record.stamp.nonce != key.nonce
    {
        return Err(InfrastructureError::StaleGeneration);
    }
    Ok(record)
}

pub(super) fn fault_plan_commitment(
    scope: &ScopeInfrastructure,
    plan: FaultDispositionPlan,
) -> FaultPlanCommitment {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.task-fault-plan.v1\0");
    hash_word(&mut hasher, scope.root.registry_instance);
    hash_word(&mut hasher, scope.root.scope.id());
    hash_word(&mut hasher, scope.root.scope.generation());
    hash_word(&mut hasher, plan.scope.id());
    hash_word(&mut hasher, plan.scope.generation());
    hash_word(&mut hasher, scope.root.authority_epoch);
    hash_word(&mut hasher, scope.root.root_effect.id());
    hash_word(&mut hasher, scope.root.root_effect.generation());
    hash_word(&mut hasher, plan.task.work_id);
    hash_word(&mut hasher, plan.task.generation);
    hash_word(&mut hasher, plan.task.task.id());
    hash_word(&mut hasher, plan.task.task.generation());
    hash_word(&mut hasher, task_role_tag(plan.task.role));
    hash_word(&mut hasher, plan.task.vm.map_or(0, VmAuthorityKey::id));
    hash_word(
        &mut hasher,
        plan.task.vm.map_or(0, VmAuthorityKey::generation),
    );
    hash_word(&mut hasher, plan.task_nonce);
    hash_word(&mut hasher, plan.task_bearer_generation);
    hash_word(&mut hasher, plan.fault.fault_id);
    hash_word(&mut hasher, plan.fault.generation);
    hash_word(&mut hasher, plan.fault.task.id());
    hash_word(&mut hasher, plan.fault.task.generation());
    hash_word(&mut hasher, plan.fault.vm_generation);
    hash_word(&mut hasher, u64::from(plan.fault.service_domain.value()));
    hash_word(&mut hasher, plan.fault.admission_binding_epoch);
    hash_word(&mut hasher, plan.fault_nonce);
    hash_word(&mut hasher, plan.fault_bearer_generation);
    hash_word(&mut hasher, plan.observation.task.id());
    hash_word(&mut hasher, plan.observation.task.generation());
    hash_word(&mut hasher, plan.observation.vm_generation);
    hash_word(&mut hasher, plan.observation.instruction_pointer);
    hash_word(&mut hasher, plan.observation.address);
    hash_word(&mut hasher, access_tag(plan.observation.access));
    hash_word(&mut hasher, plan.observation.architecture_error);
    hash_word(&mut hasher, plan.observation.evidence_digest);
    hash_word(&mut hasher, plan.projection.fault_id);
    hash_word(&mut hasher, plan.projection.generation);
    hash_word(&mut hasher, plan.projection.task.id());
    hash_word(&mut hasher, plan.projection.task.generation());
    hash_word(&mut hasher, plan.projection.vm_generation);
    hash_word(&mut hasher, disposition_tag(plan.projection.disposition));
    hash_word(
        &mut hasher,
        u64::from(plan.projection.service_domain.value()),
    );
    hash_word(&mut hasher, plan.projection.closed_binding_epoch);
    hash_word(&mut hasher, plan.projection.crash_generation);
    hash_word(&mut hasher, plan.projection.evidence_digest);
    hash_word(&mut hasher, plan.base_revision);
    hash_word(&mut hasher, plan.next_binding_epoch);
    hash_word(&mut hasher, plan.business.scope_revision);
    hash_word(&mut hasher, plan.business.domain_revision);
    hash_word(
        &mut hasher,
        plan.business.supervisor.map_or(0, |task| task.id()),
    );
    hash_word(
        &mut hasher,
        plan.business.supervisor.map_or(0, |task| task.generation()),
    );
    hash_word(&mut hasher, u64::from(plan.business.fallback_running));
    hasher.update(plan.business.cohort_digest);
    hash_word(&mut hasher, plan.business.cohort_count);
    FaultPlanCommitment(hasher.finalize().into())
}

pub(super) fn validate_exact_task_fault_pair<'a>(
    scope: &'a ScopeInfrastructure,
    task: &'a super::TaskRecord,
) -> Result<(&'a TaskFaultLink, &'a FaultStateRecord), InfrastructureError> {
    let link = task
        .service_fault
        .as_ref()
        .ok_or(InfrastructureError::Invariant("task-fault pair missing"))?;
    let fault = scope
        .faults
        .get(link.fault_id)
        .ok_or(InfrastructureError::Invariant("task-fault pair missing"))?;
    let descriptor = fault.stamp.identity;
    if fault.stamp.parent != ParentStamp::Task(task.stamp.identity)
        || fault.stamp.root != task.stamp.root
        || fault.stamp.domain != task.stamp.domain
        || fault.stamp.workload != task.stamp.workload
        || descriptor.task != task.stamp.identity.task
        || task.stamp.identity.vm.map(VmAuthorityKey::generation) != Some(descriptor.vm_generation)
        || descriptor.service_domain != fault.stamp.domain.domain
        || fault.owner.task != task.stamp.identity
        || fault.owner.task_object_nonce != task.stamp.nonce
        || fault.owner.task_bearer_generation != task.stamp.bearer_generation
        || link.fault_id != descriptor.fault_id
        || link.fault_object_generation != descriptor.generation
        || link.fault_bearer_generation != fault.stamp.bearer_generation
        || link.fault_nonce != fault.stamp.nonce
    {
        return Err(InfrastructureError::Invariant("task-fault pair mismatch"));
    }
    Ok((link, fault))
}

fn validate_fault_plan_canonical(
    scope: &ScopeInfrastructure,
    plan: FaultDispositionPlan,
) -> Result<(), InfrastructureError> {
    let expected_next_binding = match plan.projection.disposition {
        FaultDisposition::CrashService => plan
            .fault
            .admission_binding_epoch
            .checked_add(1)
            .ok_or(InfrastructureError::CounterOverflow)?,
        FaultDisposition::IsolateTask => plan.fault.admission_binding_epoch,
    };
    let expected_crash_generation = match plan.projection.disposition {
        FaultDisposition::CrashService => {
            if plan.business == FaultBusinessPlan::INFRASTRUCTURE_ONLY {
                scope
                    .revision
                    .checked_add(1)
                    .ok_or(InfrastructureError::CounterOverflow)?
            } else {
                plan.business
                    .domain_revision
                    .checked_add(1)
                    .ok_or(InfrastructureError::CounterOverflow)?
            }
        }
        FaultDisposition::IsolateTask => 0,
    };
    if plan.scope != scope.root.scope
        || plan.task.task != plan.fault.task
        || plan.task.vm.map(VmAuthorityKey::generation) != Some(plan.fault.vm_generation)
        || plan.observation.task != plan.fault.task
        || plan.observation.vm_generation != plan.fault.vm_generation
        || plan.observation.instruction_pointer == 0
        || plan.observation.evidence_digest == 0
        || plan.projection.fault_id != plan.fault.fault_id
        || plan.projection.generation != plan.fault.generation
        || plan.projection.task != plan.fault.task
        || plan.projection.vm_generation != plan.fault.vm_generation
        || plan.projection.service_domain != plan.fault.service_domain
        || plan.projection.closed_binding_epoch != plan.fault.admission_binding_epoch
        || plan.projection.crash_generation != expected_crash_generation
        || plan.projection.evidence_digest != plan.observation.evidence_digest
        || plan.next_binding_epoch != expected_next_binding
    {
        return Err(InfrastructureError::InvalidReceipt);
    }
    Ok(())
}

fn installed_fault_observation(
    projection: ServiceFaultProjection,
    commitment: FaultPlanCommitment,
) -> InstalledFaultObservation {
    let installed = InstalledFaultProjection {
        projection,
        commitment,
    };
    match projection.disposition {
        FaultDisposition::CrashService => InstalledFaultObservation::Crash(installed),
        FaultDisposition::IsolateTask => InstalledFaultObservation::Isolate(installed),
    }
}

fn validate_installed_fault_variant(
    installed: InstalledFaultObservation,
) -> Result<InstalledFaultProjection, InfrastructureError> {
    match installed {
        InstalledFaultObservation::Crash(installed)
            if installed.projection.disposition == FaultDisposition::CrashService =>
        {
            Ok(installed)
        }
        InstalledFaultObservation::Isolate(installed)
            if installed.projection.disposition == FaultDisposition::IsolateTask =>
        {
            Ok(installed)
        }
        InstalledFaultObservation::Crash(_) | InstalledFaultObservation::Isolate(_) => {
            Err(InfrastructureError::InvalidReceipt)
        }
    }
}

fn hash_word(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

pub(super) fn exit_receipt_digest(receipt: super::ServiceTaskExitReceipt) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.task-fault-exit.v1\0");
    hash_word(&mut hasher, receipt.fault_id);
    hash_word(&mut hasher, receipt.generation);
    hash_word(&mut hasher, receipt.task.id());
    hash_word(&mut hasher, receipt.task.generation());
    hash_word(&mut hasher, receipt.evidence_digest);
    hasher.finalize().into()
}

const fn access_tag(access: FaultAccess) -> u64 {
    match access {
        FaultAccess::Read => 1,
        FaultAccess::Write => 2,
        FaultAccess::Execute => 3,
    }
}

const fn disposition_tag(disposition: FaultDisposition) -> u64 {
    match disposition {
        FaultDisposition::CrashService => 1,
        FaultDisposition::IsolateTask => 2,
    }
}

const fn task_role_tag(role: TaskWorkRole) -> u64 {
    match role {
        TaskWorkRole::GuestSyscallWork => 1,
        TaskWorkRole::ServiceRequest => 2,
        TaskWorkRole::ReplacementRecovery => 3,
        TaskWorkRole::SupervisorControl => 4,
    }
}
