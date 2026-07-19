// SPDX-License-Identifier: MPL-2.0

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use super::service::{
    validate_bound_service_request, validate_live_service_child_binding,
    validate_service_child_binding_for_drain,
};
use super::{
    ArmedFaultTask, BearerKey, BoundServiceRequest, DelayedCommandDescriptor, DelayedCommandIntent,
    DelayedCommandPhase, DelayedCommandReceipt, DelayedCommandRecoveryProjection,
    DelayedCommandRecoveryState, DelayedCommandRejectionReason, DelayedCommandRejectionReceipt,
    DelayedCommandStateRecord, DelayedCommandTicket, InfrastructureError, InfrastructureEventKind,
    InfrastructureKind, InfrastructureState, LinearResult, ParentStamp, RequestKey,
    ReverseIndexRecord, ReverseParent, ScopeInfrastructure, TaskWorkDescriptor, WorkloadContext,
    bearer_state, checked_add, checked_sub, context_from_stamp, install_task_child_count,
    linear_apply, preview_bearer_stamp, preview_nonce, preview_revision, preview_task_child_add,
    preview_task_child_sub, preview_workload_child_add, preview_workload_child_sub,
    require_vacancy, validate_active_admission, validate_context, validate_task_child_stamp,
    validate_task_key,
};

struct PreparedDelayedFinish {
    command_id: u64,
    bearer_generation: u64,
    workload_request: RequestKey,
    parent_task: TaskWorkDescriptor,
    next_revision: u64,
    next_live: u32,
    next_workload_children: u32,
    next_task_children: u32,
    terminal: DelayedCommandPhase,
}

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
            || descriptor.target.scope() != bound_stamp.root.scope
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
        if scope.reverse_indexes.get(stamp.nonce).is_some() {
            return Err(InfrastructureError::IdentityConflict);
        }
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
            actor_generation: Some(descriptor.actor_generation),
            retry_generation: descriptor.generation,
        };
        scope
            .delayed_commands
            .install(
                DelayedCommandStateRecord {
                    stamp,
                    apply_generation: 0,
                    phase: DelayedCommandPhase::Reserved,
                    closure_sequence: None,
                },
                InfrastructureKind::DelayedCommand,
            )
            .unwrap();
        scope
            .reverse_indexes
            .install(index, InfrastructureKind::DelayedCommand)
            .unwrap();
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
        Ok(DelayedCommandTicket(mint_delayed_command_key::<
            bearer_state::DelayedReserved,
        >(
            scope.delayed_commands.get(descriptor.command_id).unwrap(),
        )))
    }

    pub(in super::super) fn begin_delayed_command_delivery(
        &mut self,
        ticket: DelayedCommandTicket,
    ) -> LinearResult<DelayedCommandTicket, DelayedCommandIntent> {
        linear_apply(ticket, |ticket| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            if ticket.0.authority.registry_instance != registry_instance {
                return Err(InfrastructureError::ForeignRegistry);
            }
            let scope = self.scope_mut(ticket.0.authority.scope)?;
            let (record, terminal_parent) =
                validate_delayed_command_key(scope, registry_instance, &ticket.0)?;
            if terminal_parent {
                return Err(InfrastructureError::InvalidState);
            }
            if record.phase != DelayedCommandPhase::Reserved {
                return Err(InfrastructureError::InvalidState);
            }
            let descriptor = record.stamp.identity;
            if scope.binding_epoch(descriptor.destination_domain)?
                != descriptor.destination_binding_epoch
            {
                return Err(InfrastructureError::StaleBinding);
            }
            let apply_generation = record
                .apply_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let bearer_generation = next_delayed_command_bearer_generation(record)?;
            let (apply_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let record = scope
                .delayed_commands
                .get_mut(descriptor.command_id)
                .unwrap();
            record.apply_generation = apply_generation;
            record.stamp.bearer_generation = bearer_generation;
            record.phase = DelayedCommandPhase::Publishing {
                apply_generation,
                apply_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::DelayedCommandPublishing,
                descriptor.command_id,
                descriptor.generation,
            );
            Ok(DelayedCommandIntent(mint_delayed_command_key::<
                bearer_state::DelayedPublishing,
            >(
                scope.delayed_commands.get(descriptor.command_id).unwrap(),
            )))
        })
    }

    pub(in super::super) fn acknowledge_delayed_command(
        &mut self,
        intent: DelayedCommandIntent,
        receipt: DelayedCommandReceipt,
    ) -> LinearResult<DelayedCommandIntent, DelayedCommandReceipt> {
        linear_apply(intent, |intent| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            if intent.0.authority.registry_instance != registry_instance {
                return Err(InfrastructureError::ForeignRegistry);
            }
            let scope = self.scope_mut(intent.0.authority.scope)?;
            let (record, _) = validate_delayed_command_key(scope, registry_instance, &intent.0)?;
            if !__cser_core::matches!(record.phase, DelayedCommandPhase::Publishing { .. }) {
                return Err(InfrastructureError::InvalidState);
            }
            let descriptor = record.stamp.identity;
            if receipt.actor_slot != descriptor.actor_slot
                || receipt.actor_generation != descriptor.actor_generation
                || receipt.command_digest != descriptor.command_digest
                || receipt.transport_receipt_digest == 0
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let prepared =
                prepare_delayed_finish(scope, record, DelayedCommandPhase::Issued { receipt })?;
            apply_delayed_finish(scope, prepared);
            scope.events.push(
                InfrastructureEventKind::DelayedCommandIssued,
                descriptor.command_id,
                descriptor.generation,
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
            self.reject_delayed_command_key(&ticket.0, receipt, false)?;
            Ok(receipt)
        })
    }

    pub(in super::super) fn reject_delayed_command_intent(
        &mut self,
        intent: DelayedCommandIntent,
        receipt: DelayedCommandRejectionReceipt,
    ) -> LinearResult<DelayedCommandIntent, DelayedCommandRejectionReceipt> {
        linear_apply(intent, |intent| {
            self.reject_delayed_command_key(&intent.0, receipt, true)?;
            Ok(receipt)
        })
    }

    fn reject_delayed_command_key<State: bearer_state::Sealed>(
        &mut self,
        key: &BearerKey<State>,
        receipt: DelayedCommandRejectionReceipt,
        publishing: bool,
    ) -> Result<(), InfrastructureError> {
        self.require_authoritative()?;
        let registry_instance = self.registry_instance;
        if key.authority.registry_instance != registry_instance {
            return Err(InfrastructureError::ForeignRegistry);
        }
        let scope = self.scope_mut(key.authority.scope)?;
        let (record, _) = validate_delayed_command_key(scope, registry_instance, key)?;
        let phase_matches = if publishing {
            __cser_core::matches!(record.phase, DelayedCommandPhase::Publishing { .. })
        } else {
            record.phase == DelayedCommandPhase::Reserved
        };
        if !phase_matches {
            return Err(InfrastructureError::InvalidState);
        }
        let descriptor = record.stamp.identity;
        if receipt.target_effect != descriptor.target.effect()
            || receipt.evidence_digest == 0
            || __cser_core::matches!(receipt.reason, DelayedCommandRejectionReason::StaleTarget)
                && scope.binding_epoch(descriptor.destination_domain)?
                    == descriptor.destination_binding_epoch
        {
            return Err(InfrastructureError::InvalidReceipt);
        }
        let prepared =
            prepare_delayed_finish(scope, record, DelayedCommandPhase::Rejected { receipt })?;
        apply_delayed_finish(scope, prepared);
        scope.events.push(
            InfrastructureEventKind::DelayedCommandRejected,
            descriptor.command_id,
            descriptor.generation,
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

pub(super) fn mint_delayed_command_key<State: bearer_state::Sealed>(
    record: &DelayedCommandStateRecord,
) -> BearerKey<State> {
    BearerKey {
        authority: super::AuthorityKey {
            registry_instance: record.stamp.root.registry_instance,
            scope: record.stamp.root.scope,
            authority_epoch: record.stamp.root.authority_epoch,
        },
        slot: record.stamp.identity.command_id,
        object_generation: record.stamp.identity.generation,
        bearer_generation: record.stamp.bearer_generation,
        nonce: record.stamp.nonce,
        state: __cser_core::marker::PhantomData,
    }
}

fn validate_delayed_command_key<'a, State: bearer_state::Sealed>(
    scope: &'a ScopeInfrastructure,
    registry_instance: u64,
    key: &BearerKey<State>,
) -> Result<(&'a DelayedCommandStateRecord, bool), InfrastructureError> {
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
        .delayed_commands
        .get(key.slot)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp.identity.command_id != key.slot {
        return Err(InfrastructureError::IdentityConflict);
    }
    if record.stamp.identity.generation != key.object_generation
        || record.stamp.bearer_generation != key.bearer_generation
        || record.stamp.nonce != key.nonce
    {
        return Err(InfrastructureError::StaleGeneration);
    }
    let terminal_parent = validate_delayed_command_record(scope, registry_instance, record)?;
    Ok((record, terminal_parent))
}

fn validate_delayed_command_record(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    record: &DelayedCommandStateRecord,
) -> Result<bool, InfrastructureError> {
    let stamp = &record.stamp;
    stamp.identity.validate()?;
    let terminal_parent = validate_task_child_stamp(scope, registry_instance, stamp)?;
    let parent_task = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    let descriptor = stamp.identity;
    let service = scope
        .service_requests
        .get(descriptor.request_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    let binding = validate_service_child_binding_for_drain(scope, registry_instance, service)?;
    if service.stamp.identity.request_id != descriptor.request_id
        || service.stamp.identity.generation != descriptor.request_generation
        || service.stamp.root != stamp.root
        || descriptor.sender != parent_task.task
        || binding.claimant.task != parent_task
        || descriptor.sender != binding.claimant.task.task
        || descriptor.destination_domain != stamp.domain.domain
        || descriptor.destination_binding_epoch != stamp.domain.binding_epoch
        || descriptor.destination_domain != binding.claimant.domain
        || descriptor.destination_binding_epoch != binding.claimant.binding_epoch
        || descriptor.target.scope() != stamp.root.scope
        || descriptor.target.authority_epoch() != stamp.root.authority_epoch
        || descriptor.target.domain() != descriptor.destination_domain
        || descriptor.target.binding_epoch() != descriptor.destination_binding_epoch
        || descriptor.target.effect() != binding.child.child_effect
    {
        return Err(InfrastructureError::InvalidState);
    }
    let expected_index = ReverseIndexRecord {
        slot: stamp.nonce,
        kind: InfrastructureKind::DelayedCommand,
        root_effect: stamp.root.root_effect,
        parent: ReverseParent::Task(parent_task),
        task: Some(descriptor.sender),
        domain: stamp.domain.domain,
        binding_epoch: stamp.domain.binding_epoch,
        source_domain: Some(descriptor.destination_domain),
        source_binding_epoch: Some(descriptor.destination_binding_epoch),
        resource: None,
        actor_slot: Some(descriptor.actor_slot),
        actor_generation: Some(descriptor.actor_generation),
        retry_generation: descriptor.generation,
    };
    match scope.reverse_indexes.get(stamp.nonce) {
        None => {
            return Err(InfrastructureError::Invariant(
                "missing delayed command reverse index",
            ));
        }
        Some(index) if *index != expected_index => {
            return Err(InfrastructureError::Invariant(
                "delayed command reverse index mismatch",
            ));
        }
        Some(_) => {}
    }
    match record.phase {
        DelayedCommandPhase::Reserved if record.apply_generation != 0 => {
            return Err(InfrastructureError::Invariant(
                "reserved delayed command has apply generation",
            ));
        }
        DelayedCommandPhase::Publishing {
            apply_generation,
            apply_nonce,
        } if apply_generation == 0
            || apply_generation != record.apply_generation
            || apply_nonce == 0 =>
        {
            return Err(InfrastructureError::Invariant(
                "invalid delayed command publication phase",
            ));
        }
        _ => {}
    }
    Ok(terminal_parent)
}

fn next_delayed_command_bearer_generation(
    record: &DelayedCommandStateRecord,
) -> Result<u64, InfrastructureError> {
    record
        .stamp
        .bearer_generation
        .checked_add(1)
        .ok_or(InfrastructureError::CounterOverflow)
}

fn prepare_delayed_finish(
    scope: &ScopeInfrastructure,
    record: &DelayedCommandStateRecord,
    terminal: DelayedCommandPhase,
) -> Result<PreparedDelayedFinish, InfrastructureError> {
    let stamp = record.stamp;
    let bearer_generation = next_delayed_command_bearer_generation(record)?;
    let next_revision = preview_revision(scope)?;
    let next_live = checked_sub(scope.live.delayed_commands, 1)?;
    let next_workload_children = preview_workload_child_sub(scope, stamp.workload.request)?;
    let parent_task = match stamp.parent {
        ParentStamp::Task(parent) => parent,
        _ => return Err(InfrastructureError::ForeignParent),
    };
    let next_task_children = preview_task_child_sub(scope, parent_task)?;
    Ok(PreparedDelayedFinish {
        command_id: stamp.identity.command_id,
        bearer_generation,
        workload_request: stamp.workload.request,
        parent_task,
        next_revision,
        next_live,
        next_workload_children,
        next_task_children,
        terminal,
    })
}

fn apply_delayed_finish(scope: &mut ScopeInfrastructure, prepared: PreparedDelayedFinish) {
    let PreparedDelayedFinish {
        command_id,
        bearer_generation,
        workload_request,
        parent_task,
        next_revision,
        next_live,
        next_workload_children,
        next_task_children,
        terminal,
    } = prepared;
    let record = scope.delayed_commands.get_mut(command_id).unwrap();
    record.stamp.bearer_generation = bearer_generation;
    record.phase = terminal;
    scope.revision = next_revision;
    scope.live.delayed_commands = next_live;
    scope
        .workloads
        .get_mut(workload_request.id)
        .unwrap()
        .live_children = next_workload_children;
    install_task_child_count(
        scope.tasks.get_mut(parent_task.work_id).unwrap(),
        next_task_children,
    );
}

pub(super) fn delayed_command_phase_live(phase: DelayedCommandPhase) -> bool {
    __cser_core::matches!(
        phase,
        DelayedCommandPhase::Reserved | DelayedCommandPhase::Publishing { .. }
    )
}
