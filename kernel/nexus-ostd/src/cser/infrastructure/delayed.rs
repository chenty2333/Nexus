// SPDX-License-Identifier: MPL-2.0

use super::service::{validate_bound_service_request, validate_live_service_child_binding};
use super::{
    ArmedFaultTask, BearerStamp, BoundServiceRequest, DelayedCommandDescriptor,
    DelayedCommandIntent, DelayedCommandPhase, DelayedCommandReceipt,
    DelayedCommandRecoveryProjection, DelayedCommandRecoveryState, DelayedCommandRejectionReason,
    DelayedCommandRejectionReceipt, DelayedCommandStateRecord, DelayedCommandTicket,
    InfrastructureError, InfrastructureEventKind, InfrastructureKind, InfrastructureState,
    LinearResult, ParentStamp, ReverseIndexRecord, ReverseParent, ScopeInfrastructure, ScopeKey,
    WorkloadContext, checked_add, checked_sub, context_from_stamp, install_task_child_count,
    linear_apply, preview_bearer_stamp, preview_nonce, preview_revision, preview_task_child_add,
    preview_task_child_sub, preview_workload_child_add, preview_workload_child_sub,
    require_vacancy, validate_active_admission, validate_context, validate_task_child_stamp,
    validate_task_key,
};

impl InfrastructureState {
    pub(in super::super) fn reserve_delayed_command(
        &mut self,
        task: &ArmedFaultTask,
        bound: &BoundServiceRequest,
        descriptor: DelayedCommandDescriptor,
    ) -> Result<DelayedCommandTicket, InfrastructureError> {
        self.require_authoritative()?;
        descriptor.validate()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(task.0.authority.scope)?;
        let task_record = validate_task_key(scope, registry_instance, &task.0)?;
        let task_stamp = task_record.stamp;
        let bound_record = validate_bound_service_request(scope, registry_instance, bound)?;
        let bound_stamp = bound_record.stamp;
        let binding_receipt =
            validate_live_service_child_binding(scope, registry_instance, bound_record)?;
        validate_active_admission(scope)?;
        if descriptor.request_id != bound_stamp.identity.request_id
            || descriptor.request_generation != bound_stamp.identity.generation
            || descriptor.sender != task_stamp.identity.task
            || descriptor.sender != binding_receipt.claimant.task.task
            || task_stamp.identity != binding_receipt.claimant.task
            || task_record.service_fault.is_none()
            || descriptor.target.scope() != stamp_scope(&bound_stamp)
            || descriptor.target.effect() != binding_receipt.child.child_effect
            || descriptor.target.domain() != descriptor.destination_domain
            || descriptor.target.authority_epoch() != bound_stamp.root.authority_epoch
            || descriptor.target.binding_epoch() != descriptor.destination_binding_epoch
            || scope.binding_epoch(descriptor.destination_domain)?
                != descriptor.destination_binding_epoch
        {
            return Err(InfrastructureError::InvalidState);
        }
        if let Some(existing) = scope.delayed_commands.get(descriptor.command_id) {
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
        if scope.delayed_commands.iter().any(|record| {
            delayed_command_phase_live(record.phase)
                && (record.stamp.identity.actor_slot == descriptor.actor_slot
                    || record.stamp.identity.target == descriptor.target)
        }) {
            return Err(InfrastructureError::IdentityConflict);
        }
        require_vacancy(
            &scope.delayed_commands,
            descriptor.command_id,
            InfrastructureKind::DelayedCommand,
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
            InfrastructureKind::DelayedCommand,
        )?;
        let next_revision = preview_revision(scope)?;
        let next_live = checked_add(scope.live.delayed_commands, 1)?;
        let next_workload_children = preview_workload_child_add(scope, stamp.workload.request)?;
        let next_task_children = preview_task_child_add(scope, task_stamp.identity)?;
        let index = ReverseIndexRecord {
            slot: stamp.nonce,
            kind: InfrastructureKind::DelayedCommand,
            root_effect: stamp.root.root_effect,
            parent: ReverseParent::Task(task_stamp.identity),
            task: Some(descriptor.sender),
            domain: stamp.domain.domain,
            binding_epoch: stamp.domain.binding_epoch,
            source_domain: Some(descriptor.destination_domain),
            source_binding_epoch: Some(descriptor.destination_binding_epoch),
            resource: None,
            actor_slot: Some(descriptor.actor_slot),
            retry_generation: descriptor.actor_generation,
        };
        scope.delayed_commands.install(
            DelayedCommandStateRecord {
                stamp,
                apply_generation: 0,
                phase: DelayedCommandPhase::Reserved,
                closure_sequence: None,
            },
            InfrastructureKind::DelayedCommand,
        )?;
        scope
            .reverse_indexes
            .install(index, InfrastructureKind::DelayedCommand)?;
        scope.next_nonce = next_nonce;
        scope.revision = next_revision;
        scope.live.delayed_commands = next_live;
        scope
            .workloads
            .get_mut(stamp.workload.request.id)
            .unwrap()
            .live_children = next_workload_children;
        scope
            .tasks
            .get_mut(task_stamp.identity.work_id)
            .unwrap()
            .live_children = next_task_children;
        scope.events.push(
            InfrastructureEventKind::DelayedCommandReserved,
            descriptor.command_id,
            descriptor.generation,
        );
        Ok(DelayedCommandTicket(stamp))
    }

    pub(in super::super) fn begin_delayed_command_delivery(
        &mut self,
        ticket: DelayedCommandTicket,
    ) -> LinearResult<DelayedCommandTicket, DelayedCommandIntent> {
        linear_apply(ticket, |ticket| {
            self.require_authoritative()?;
            let stamp = ticket.0;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_delayed_command_bearer(scope, registry_instance, &stamp)?;
            let record = scope
                .delayed_commands
                .get(stamp.identity.command_id)
                .unwrap();
            if validate_task_child_stamp(scope, registry_instance, &record.stamp)? {
                return Err(InfrastructureError::InvalidState);
            }
            if scope.binding_epoch(stamp.identity.destination_domain)?
                != stamp.identity.destination_binding_epoch
                || record.phase != DelayedCommandPhase::Reserved
            {
                return Err(InfrastructureError::StaleBinding);
            }
            let apply_generation = record
                .apply_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let (apply_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let record = scope
                .delayed_commands
                .get_mut(stamp.identity.command_id)
                .unwrap();
            record.apply_generation = apply_generation;
            record.phase = DelayedCommandPhase::Publishing {
                apply_generation,
                apply_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::DelayedCommandPublishing,
                stamp.identity.command_id,
                stamp.identity.generation,
            );
            Ok(DelayedCommandIntent {
                command: stamp,
                apply_generation,
                apply_nonce,
            })
        })
    }

    pub(in super::super) fn acknowledge_delayed_command(
        &mut self,
        intent: DelayedCommandIntent,
        receipt: DelayedCommandReceipt,
    ) -> LinearResult<DelayedCommandIntent, DelayedCommandReceipt> {
        linear_apply(intent, |intent| {
            self.require_authoritative()?;
            let stamp = intent.command;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_delayed_command_bearer(scope, registry_instance, &stamp)?;
            if receipt.actor_slot != stamp.identity.actor_slot
                || receipt.actor_generation != stamp.identity.actor_generation
                || receipt.command_digest != stamp.identity.command_digest
                || receipt.transport_receipt_digest == 0
                || scope
                    .delayed_commands
                    .get(stamp.identity.command_id)
                    .unwrap()
                    .phase
                    != (DelayedCommandPhase::Publishing {
                        apply_generation: intent.apply_generation,
                        apply_nonce: intent.apply_nonce,
                    })
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            finish_delayed_command(scope, stamp, DelayedCommandPhase::Issued { receipt })?;
            scope.events.push(
                InfrastructureEventKind::DelayedCommandIssued,
                stamp.identity.command_id,
                stamp.identity.generation,
            );
            Ok(receipt)
        })
    }

    pub(in super::super) fn reject_delayed_command(
        &mut self,
        ticket: DelayedCommandTicket,
        receipt: DelayedCommandRejectionReceipt,
    ) -> LinearResult<DelayedCommandTicket, DelayedCommandRejectionReceipt> {
        linear_apply(ticket, |ticket| {
            self.reject_delayed_command_stamp(ticket.0, receipt, false)?;
            Ok(receipt)
        })
    }

    pub(in super::super) fn reject_delayed_command_intent(
        &mut self,
        intent: DelayedCommandIntent,
        receipt: DelayedCommandRejectionReceipt,
    ) -> LinearResult<DelayedCommandIntent, DelayedCommandRejectionReceipt> {
        linear_apply(intent, |intent| {
            self.reject_delayed_command_stamp(intent.command, receipt, true)?;
            Ok(receipt)
        })
    }

    fn reject_delayed_command_stamp(
        &mut self,
        stamp: BearerStamp<DelayedCommandDescriptor>,
        receipt: DelayedCommandRejectionReceipt,
        publishing: bool,
    ) -> Result<(), InfrastructureError> {
        self.require_authoritative()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(stamp.root.scope)?;
        validate_delayed_command_bearer(scope, registry_instance, &stamp)?;
        if receipt.target_effect != stamp.identity.target.effect()
            || receipt.evidence_digest == 0
            || matches!(receipt.reason, DelayedCommandRejectionReason::StaleTarget)
                && scope.binding_epoch(stamp.identity.destination_domain)?
                    == stamp.identity.destination_binding_epoch
        {
            return Err(InfrastructureError::InvalidReceipt);
        }
        let phase = scope
            .delayed_commands
            .get(stamp.identity.command_id)
            .unwrap()
            .phase;
        if publishing != matches!(phase, DelayedCommandPhase::Publishing { .. })
            || (!publishing && phase != DelayedCommandPhase::Reserved)
        {
            return Err(InfrastructureError::InvalidState);
        }
        finish_delayed_command(scope, stamp, DelayedCommandPhase::Rejected { receipt })?;
        scope.events.push(
            InfrastructureEventKind::DelayedCommandRejected,
            stamp.identity.command_id,
            stamp.identity.generation,
        );
        Ok(())
    }

    pub(in super::super) fn query_delayed_command(
        &self,
        context: &WorkloadContext,
        command_id: u64,
        generation: u64,
    ) -> Result<DelayedCommandRecoveryProjection, InfrastructureError> {
        self.require_authoritative()?;
        let scope = self.scope(context.root.scope)?;
        validate_context(scope, self.registry_instance, context)?;
        let record = scope
            .delayed_commands
            .get(command_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
        if record.stamp.identity.generation != generation {
            return Err(InfrastructureError::StaleGeneration);
        }
        if record.stamp.workload.request != context.workload.request {
            return Err(InfrastructureError::ForeignWorkload);
        }
        Ok(DelayedCommandRecoveryProjection {
            descriptor: record.stamp.identity,
            state: match record.phase {
                DelayedCommandPhase::Reserved => DelayedCommandRecoveryState::Reserved,
                DelayedCommandPhase::Publishing { .. } => {
                    DelayedCommandRecoveryState::PublicationUncertain
                }
                DelayedCommandPhase::Issued { .. } => DelayedCommandRecoveryState::Issued,
                DelayedCommandPhase::Rejected { .. } => DelayedCommandRecoveryState::Rejected,
            },
            receipt: match record.phase {
                DelayedCommandPhase::Issued { receipt } => Some(receipt),
                _ => None,
            },
            rejection: match record.phase {
                DelayedCommandPhase::Rejected { receipt } => Some(receipt),
                _ => None,
            },
        })
    }
}

fn stamp_scope<I>(stamp: &BearerStamp<I>) -> ScopeKey {
    stamp.root.scope
}

fn validate_delayed_command_bearer(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    stamp: &BearerStamp<DelayedCommandDescriptor>,
) -> Result<(), InfrastructureError> {
    validate_task_child_stamp(scope, registry_instance, stamp)?;
    let record = scope
        .delayed_commands
        .get(stamp.identity.command_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp != *stamp {
        return Err(InfrastructureError::StaleGeneration);
    }
    Ok(())
}

fn finish_delayed_command(
    scope: &mut ScopeInfrastructure,
    stamp: BearerStamp<DelayedCommandDescriptor>,
    terminal: DelayedCommandPhase,
) -> Result<(), InfrastructureError> {
    let next_revision = preview_revision(scope)?;
    let next_live = checked_sub(scope.live.delayed_commands, 1)?;
    let next_workload_children = preview_workload_child_sub(scope, stamp.workload.request)?;
    let parent_task = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    let next_task_children = preview_task_child_sub(scope, parent_task)?;
    scope
        .delayed_commands
        .get_mut(stamp.identity.command_id)
        .unwrap()
        .phase = terminal;
    scope.revision = next_revision;
    scope.live.delayed_commands = next_live;
    scope
        .workloads
        .get_mut(stamp.workload.request.id)
        .unwrap()
        .live_children = next_workload_children;
    install_task_child_count(
        scope.tasks.get_mut(parent_task.work_id).unwrap(),
        next_task_children,
    );
    Ok(())
}

pub(super) fn delayed_command_phase_live(phase: DelayedCommandPhase) -> bool {
    matches!(
        phase,
        DelayedCommandPhase::Reserved | DelayedCommandPhase::Publishing { .. }
    )
}
