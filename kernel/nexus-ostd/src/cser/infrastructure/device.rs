// SPDX-License-Identifier: MPL-2.0

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use super::{
    BearerKey, DEVICE_DMA_MAPPINGS, DEVICE_PINNED_PAGES, DEVICE_QUEUE_SLOTS, DeviceAdoption,
    DeviceApplyIntent, DeviceCohortIdentity, DeviceCreditOwnership, DeviceHardwareReceipt,
    DeviceMaterializationPlan, DevicePhase, DevicePreparationCreditOwnership,
    DevicePreparationCreditProjection, DevicePreparationRecoveryProjection,
    DevicePreparationRecoveryState, DevicePreparationTicket, DeviceRecord,
    DeviceReservationCoordinates, DeviceReservationInstall, DeviceRollbackReceipt, EffectKey,
    InfrastructureError, InfrastructureEventKind, InfrastructureKind, InfrastructureState,
    LedgerMode, LinearResult, MaterializedDeviceTicket, ParentStamp, PreparedDeviceDescription,
    PreparedDeviceIdentity, PreparedDeviceTicket, PreparedOwner, RegistryDeviceClosureReceipt,
    RequestKey, ReverseIndexRecord, ReverseParent, ScopeInfrastructure,
    ValidatedDeviceClosureProof, WorkloadContext, WorkloadStamp, bearer_state, checked_add,
    checked_sub, linear_apply, preview_bearer_stamp, preview_nonce, preview_nonces,
    preview_revision, preview_workload_child_add, preview_workload_child_sub, require_vacancy,
    validate_active_admission, validate_context, validate_stamp_common_historical,
};

use super::device_receipt_bridge::VerifiedDeviceClosure;

pub(in super::super) struct PreparedDeviceFinish {
    scope: super::ScopeKey,
    preparation_id: u64,
    bearer_generation: u64,
    workload_request: RequestKey,
    next_revision: u64,
    next_live: u32,
    next_queue_slots: u32,
    next_pinned_pages: u32,
    next_dma_mappings: u32,
    next_workload_children: u32,
    credit_ownership: DeviceCreditOwnership,
}

pub(in super::super) struct PreparedDeviceBegin {
    scope: super::ScopeKey,
    preparation_id: u64,
    bearer_generation: u64,
    apply_generation: u64,
    apply_nonce: u64,
    next_nonce: u64,
    next_revision: u64,
}

pub(in super::super) struct PreparedDeviceAcknowledge {
    scope: super::ScopeKey,
    preparation_id: u64,
    bearer_generation: u64,
    next_revision: u64,
}

pub(in super::super) struct PreparedDeviceIndeterminate {
    scope: super::ScopeKey,
    preparation_id: u64,
    bearer_generation: u64,
    preparation_owner_id: u64,
    preparation_sequence: u64,
    observation_digest: u64,
    next_revision: u64,
}

pub(in super::super) struct PreparedDeviceMaterialization {
    scope: super::ScopeKey,
    preparation_id: u64,
    bearer_generation: u64,
    next_queue_slots: u32,
    next_pinned_pages: u32,
    next_dma_mappings: u32,
    next_revision: u64,
}

pub(in super::super) struct PreparedMaterializedDeviceRelease {
    finish: PreparedDeviceFinish,
    owner: PreparedOwner,
    cohort: DeviceCohortIdentity,
    closure: RegistryDeviceClosureReceipt,
}

struct PreparedDeviceAdoption {
    scope: super::ScopeKey,
    preparation_id: u64,
    domain: super::DomainStamp,
    workload: WorkloadStamp,
    bearer_generation: u64,
    apply_generation: u64,
    apply_nonce: Option<u64>,
    next_nonce: u64,
    next_revision: u64,
    index_slot: u64,
}

impl InfrastructureState {
    pub(in super::super) fn reserve_device_preparation(
        &mut self,
        context: &WorkloadContext,
        parent_effect: EffectKey,
        coordinates: DeviceReservationCoordinates,
    ) -> Result<DevicePreparationTicket, InfrastructureError> {
        let install = self.reserve_device_preparation_for_mode(
            context,
            parent_effect,
            coordinates,
            LedgerMode::Authoritative,
        )?;
        Ok(self.mint_reserved_device_ticket_after_install(install))
    }

    pub(in super::super) fn reserve_device_preparation_in_candidate(
        &mut self,
        context: &WorkloadContext,
        parent_effect: EffectKey,
        coordinates: DeviceReservationCoordinates,
    ) -> Result<DeviceReservationInstall, InfrastructureError> {
        self.reserve_device_preparation_for_mode(
            context,
            parent_effect,
            coordinates,
            LedgerMode::NonAuthoritativeCandidate,
        )
    }

    fn reserve_device_preparation_for_mode(
        &mut self,
        context: &WorkloadContext,
        parent_effect: EffectKey,
        coordinates: DeviceReservationCoordinates,
        expected_mode: LedgerMode,
    ) -> Result<DeviceReservationInstall, InfrastructureError> {
        require_device_ledger_mode(self, expected_mode)?;
        coordinates.validate()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope_mut(context.root.scope)?;
        validate_context(scope, registry_instance, context)?;
        validate_active_admission(scope)?;
        if let Some(existing) = scope.devices.get(coordinates.preparation_id) {
            return if existing.stamp.identity == coordinates
                && existing.stamp.parent == ParentStamp::Effect(parent_effect)
            {
                Err(InfrastructureError::ExactReplay)
            } else if existing.stamp.identity.generation > coordinates.generation {
                Err(InfrastructureError::StaleGeneration)
            } else {
                Err(InfrastructureError::IdentityConflict)
            };
        }
        if scope.devices.iter().any(|record| {
            device_phase_live(record.phase)
                && (record.stamp.identity.actor_slot == coordinates.actor_slot
                    || (record.stamp.identity.owned_device == coordinates.owned_device
                        && record.stamp.identity.queue == coordinates.queue))
        }) {
            return Err(InfrastructureError::IdentityConflict);
        }
        require_vacancy(
            &scope.devices,
            coordinates.preparation_id,
            InfrastructureKind::DevicePreparation,
        )?;
        let next_queue_slots = scope
            .live
            .queue_slots
            .checked_add(DEVICE_QUEUE_SLOTS)
            .ok_or(InfrastructureError::CounterOverflow)?;
        if next_queue_slots > scope.limits.queue_slots {
            return Err(InfrastructureError::QueueSlotQuotaExceeded);
        }
        let next_pinned = scope
            .live
            .pinned_pages
            .checked_add(DEVICE_PINNED_PAGES)
            .ok_or(InfrastructureError::CounterOverflow)?;
        if next_pinned > scope.limits.pinned_pages {
            return Err(InfrastructureError::PinnedPageQuotaExceeded);
        }
        let next_dma = scope
            .live
            .dma_mappings
            .checked_add(DEVICE_DMA_MAPPINGS)
            .ok_or(InfrastructureError::CounterOverflow)?;
        if next_dma > scope.limits.dma_mappings {
            return Err(InfrastructureError::DmaMappingQuotaExceeded);
        }
        let (stamp, next_nonce) = preview_bearer_stamp(
            scope,
            context,
            coordinates,
            ParentStamp::Effect(parent_effect),
        )?;
        require_vacancy(
            &scope.reverse_indexes,
            stamp.nonce,
            InfrastructureKind::DevicePreparation,
        )?;
        let next_revision = preview_revision(scope)?;
        let next_live = checked_add(scope.live.device_preparations, 1)?;
        let next_workload_children = preview_workload_child_add(scope, stamp.workload.request)?;
        let index = ReverseIndexRecord {
            slot: stamp.nonce,
            kind: InfrastructureKind::DevicePreparation,
            root_effect: stamp.root.root_effect,
            parent: ReverseParent::Effect(parent_effect),
            task: None,
            domain: stamp.domain.domain,
            binding_epoch: stamp.domain.binding_epoch,
            source_domain: None,
            source_binding_epoch: None,
            resource: Some(coordinates.owned_device),
            actor_slot: Some(coordinates.actor_slot),
            actor_generation: Some(coordinates.actor_generation),
            retry_generation: coordinates.generation,
        };
        // Both fixed slots and every arithmetic edge were preflighted above.
        // No fallible work remains once the candidate/live mutation begins.
        scope
            .devices
            .install(
                DeviceRecord {
                    stamp,
                    apply_generation: 0,
                    credit_ownership: DeviceCreditOwnership::Held,
                    phase: DevicePhase::Reserved,
                    closure_sequence: None,
                },
                InfrastructureKind::DevicePreparation,
            )
            .unwrap();
        scope
            .reverse_indexes
            .install(index, InfrastructureKind::DevicePreparation)
            .unwrap();
        scope.next_nonce = next_nonce;
        scope.revision = next_revision;
        scope.live.device_preparations = next_live;
        scope.live.queue_slots = next_queue_slots;
        scope.live.pinned_pages = next_pinned;
        scope.live.dma_mappings = next_dma;
        scope
            .workloads
            .get_mut(stamp.workload.request.id)
            .unwrap()
            .live_children = next_workload_children;
        scope.events.push(
            InfrastructureEventKind::DeviceReserved,
            coordinates.preparation_id,
            coordinates.generation,
        );
        Ok(DeviceReservationInstall {
            scope: context.root.scope,
            preparation_id: coordinates.preparation_id,
            generation: coordinates.generation,
        })
    }

    /// Mints reservation authority only after the containing candidate has
    /// become authoritative. A non-authoritative ledger never calls this.
    pub(in super::super) fn mint_reserved_device_ticket_after_install(
        &self,
        install: DeviceReservationInstall,
    ) -> DevicePreparationTicket {
        __cser_core::debug_assert_eq!(self.mode, LedgerMode::Authoritative);
        let record = installed_scope(self, install.scope)
            .devices
            .get(install.preparation_id)
            .unwrap();
        __cser_core::debug_assert_eq!(record.stamp.identity.generation, install.generation);
        __cser_core::debug_assert_eq!(record.phase, DevicePhase::Reserved);
        DevicePreparationTicket(mint_device_key::<bearer_state::DeviceReserved>(record))
    }

    pub(in super::super) fn cancel_reserved_device(
        &mut self,
        ticket: DevicePreparationTicket,
    ) -> LinearResult<DevicePreparationTicket, ()> {
        linear_apply(ticket, |ticket| {
            let prepared =
                self.prepare_cancel_reserved_device(ticket, LedgerMode::Authoritative)?;
            self.apply_cancel_reserved_device(prepared);
            Ok(())
        })
    }

    pub(in super::super) fn prepare_cancel_reserved_device_in_candidate(
        &self,
        ticket: &DevicePreparationTicket,
    ) -> Result<PreparedDeviceFinish, InfrastructureError> {
        self.prepare_cancel_reserved_device(ticket, LedgerMode::NonAuthoritativeCandidate)
    }

    fn prepare_cancel_reserved_device(
        &self,
        ticket: &DevicePreparationTicket,
        expected_mode: LedgerMode,
    ) -> Result<PreparedDeviceFinish, InfrastructureError> {
        require_device_ledger_mode(self, expected_mode)?;
        let scope = self.scope(ticket.0.authority.scope)?;
        let record = validate_device_key(scope, self.registry_instance, &ticket.0)?;
        if record.phase != DevicePhase::Reserved {
            return Err(InfrastructureError::InvalidState);
        }
        prepare_device_finish(scope, record, DeviceCreditOwnership::Released)
    }

    pub(in super::super) fn apply_cancel_reserved_device_in_candidate(
        &mut self,
        prepared: PreparedDeviceFinish,
    ) {
        __cser_core::debug_assert_eq!(self.mode, LedgerMode::NonAuthoritativeCandidate);
        self.apply_cancel_reserved_device(prepared);
    }

    fn apply_cancel_reserved_device(&mut self, prepared: PreparedDeviceFinish) {
        let scope = installed_scope_mut(self, prepared.scope);
        apply_device_finish(scope, prepared, DevicePhase::Cancelled { rollback: None });
    }

    pub(in super::super) fn begin_device_hardware_apply(
        &mut self,
        ticket: DevicePreparationTicket,
    ) -> LinearResult<DevicePreparationTicket, DeviceApplyIntent> {
        linear_apply(ticket, |ticket| {
            let prepared =
                self.prepare_begin_device_hardware_apply(ticket, LedgerMode::Authoritative)?;
            let scope = prepared.scope;
            let preparation_id = prepared.preparation_id;
            self.apply_begin_device_hardware_apply(prepared);
            let record = installed_scope(self, scope)
                .devices
                .get(preparation_id)
                .unwrap();
            Ok(DeviceApplyIntent(mint_device_key::<
                bearer_state::DeviceApplying,
            >(record)))
        })
    }

    pub(in super::super) fn prepare_begin_device_hardware_apply_in_candidate(
        &self,
        ticket: &DevicePreparationTicket,
    ) -> Result<PreparedDeviceBegin, InfrastructureError> {
        self.prepare_begin_device_hardware_apply(ticket, LedgerMode::NonAuthoritativeCandidate)
    }

    fn prepare_begin_device_hardware_apply(
        &self,
        ticket: &DevicePreparationTicket,
        expected_mode: LedgerMode,
    ) -> Result<PreparedDeviceBegin, InfrastructureError> {
        require_device_ledger_mode(self, expected_mode)?;
        let scope = self.scope(ticket.0.authority.scope)?;
        let record = validate_device_key(scope, self.registry_instance, &ticket.0)?;
        if record.phase != DevicePhase::Reserved {
            return Err(InfrastructureError::InvalidState);
        }
        let apply_generation = record
            .apply_generation
            .checked_add(1)
            .ok_or(InfrastructureError::CounterOverflow)?;
        let bearer_generation = next_device_bearer_generation(record)?;
        let (apply_nonce, next_nonce) = preview_nonce(scope)?;
        Ok(PreparedDeviceBegin {
            scope: record.stamp.root.scope,
            preparation_id: record.stamp.identity.preparation_id,
            bearer_generation,
            apply_generation,
            apply_nonce,
            next_nonce,
            next_revision: preview_revision(scope)?,
        })
    }

    pub(in super::super) fn apply_begin_device_hardware_apply_in_candidate(
        &mut self,
        prepared: PreparedDeviceBegin,
    ) {
        __cser_core::debug_assert_eq!(self.mode, LedgerMode::NonAuthoritativeCandidate);
        self.apply_begin_device_hardware_apply(prepared);
    }

    fn apply_begin_device_hardware_apply(&mut self, prepared: PreparedDeviceBegin) {
        let scope = installed_scope_mut(self, prepared.scope);
        let record = scope.devices.get_mut(prepared.preparation_id).unwrap();
        record.apply_generation = prepared.apply_generation;
        record.stamp.bearer_generation = prepared.bearer_generation;
        record.credit_ownership = DeviceCreditOwnership::Retained;
        record.phase = DevicePhase::Applying {
            apply_generation: prepared.apply_generation,
            apply_nonce: prepared.apply_nonce,
        };
        scope.next_nonce = prepared.next_nonce;
        scope.revision = prepared.next_revision;
        scope.events.push(
            InfrastructureEventKind::DeviceApplying,
            record.stamp.identity.preparation_id,
            record.stamp.identity.generation,
        );
    }

    pub(in super::super) fn mint_device_apply_intent_after_install(
        &self,
        ticket: DevicePreparationTicket,
    ) -> DeviceApplyIntent {
        let previous = ticket.0;
        let record = installed_device_successor(self, &previous);
        __cser_core::debug_assert!(__cser_core::matches!(
            record.phase,
            DevicePhase::Applying { .. }
        ));
        DeviceApplyIntent(mint_device_key::<bearer_state::DeviceApplying>(record))
    }

    pub(in super::super) fn acknowledge_device_apply_rollback(
        &mut self,
        intent: DeviceApplyIntent,
        rollback: DeviceRollbackReceipt,
    ) -> LinearResult<DeviceApplyIntent, DeviceRollbackReceipt> {
        linear_apply(intent, |intent| {
            let prepared =
                self.prepare_device_apply_rollback(intent, rollback, LedgerMode::Authoritative)?;
            self.apply_device_apply_rollback(prepared, rollback);
            Ok(rollback)
        })
    }

    pub(in super::super) fn prepare_device_apply_rollback_in_candidate(
        &self,
        intent: &DeviceApplyIntent,
        rollback: DeviceRollbackReceipt,
    ) -> Result<PreparedDeviceFinish, InfrastructureError> {
        self.prepare_device_apply_rollback(intent, rollback, LedgerMode::NonAuthoritativeCandidate)
    }

    fn prepare_device_apply_rollback(
        &self,
        intent: &DeviceApplyIntent,
        rollback: DeviceRollbackReceipt,
        expected_mode: LedgerMode,
    ) -> Result<PreparedDeviceFinish, InfrastructureError> {
        require_device_ledger_mode(self, expected_mode)?;
        let scope = self.scope(intent.0.authority.scope)?;
        let record = validate_device_key(scope, self.registry_instance, &intent.0)?;
        if !__cser_core::matches!(record.phase, DevicePhase::Applying { .. }) {
            return Err(InfrastructureError::InvalidState);
        }
        let coordinates = record.stamp.identity;
        if rollback.owned_device != coordinates.owned_device
            || rollback.queue != coordinates.queue
            || rollback.device_generation != coordinates.device_generation
            || rollback.operation_digest != coordinates.operation_digest
            || rollback.actor_slot != coordinates.actor_slot
            || rollback.actor_generation != coordinates.actor_generation
            || rollback.rollback_receipt_digest == 0
            || rollback.preparation_owner_id == 0
            || rollback.preparation_sequence == 0
        {
            return Err(InfrastructureError::InvalidReceipt);
        }
        prepare_device_finish(scope, record, DeviceCreditOwnership::Released)
    }

    pub(in super::super) fn prepare_device_indeterminate_in_candidate(
        &self,
        intent: &DeviceApplyIntent,
        preparation_owner_id: u64,
        preparation_sequence: u64,
        observation_digest: u64,
    ) -> Result<PreparedDeviceIndeterminate, InfrastructureError> {
        require_device_ledger_mode(self, LedgerMode::NonAuthoritativeCandidate)?;
        let scope = self.scope(intent.0.authority.scope)?;
        let record = validate_device_key(scope, self.registry_instance, &intent.0)?;
        if !__cser_core::matches!(record.phase, DevicePhase::Applying { .. })
            || preparation_owner_id == 0
            || preparation_sequence == 0
            || observation_digest == 0
        {
            return Err(InfrastructureError::InvalidReceipt);
        }
        Ok(PreparedDeviceIndeterminate {
            scope: record.stamp.root.scope,
            preparation_id: record.stamp.identity.preparation_id,
            bearer_generation: next_device_bearer_generation(record)?,
            preparation_owner_id,
            preparation_sequence,
            observation_digest,
            next_revision: preview_revision(scope)?,
        })
    }

    pub(in super::super) fn apply_device_indeterminate_in_candidate(
        &mut self,
        prepared: PreparedDeviceIndeterminate,
    ) {
        __cser_core::debug_assert_eq!(self.mode, LedgerMode::NonAuthoritativeCandidate);
        let scope = installed_scope_mut(self, prepared.scope);
        let record = scope.devices.get_mut(prepared.preparation_id).unwrap();
        record.stamp.bearer_generation = prepared.bearer_generation;
        record.phase = DevicePhase::IndeterminateRetained {
            preparation_owner_id: prepared.preparation_owner_id,
            preparation_sequence: prepared.preparation_sequence,
            observation_digest: prepared.observation_digest,
        };
        scope.revision = prepared.next_revision;
        scope.events.push(
            InfrastructureEventKind::DeviceIndeterminateRetained,
            record.stamp.identity.preparation_id,
            record.stamp.identity.generation,
        );
    }

    pub(in super::super) fn apply_device_apply_rollback_in_candidate(
        &mut self,
        prepared: PreparedDeviceFinish,
        rollback: DeviceRollbackReceipt,
    ) {
        __cser_core::debug_assert_eq!(self.mode, LedgerMode::NonAuthoritativeCandidate);
        self.apply_device_apply_rollback(prepared, rollback);
    }

    fn apply_device_apply_rollback(
        &mut self,
        prepared: PreparedDeviceFinish,
        rollback: DeviceRollbackReceipt,
    ) {
        let scope = installed_scope_mut(self, prepared.scope);
        let preparation_id = prepared.preparation_id;
        let generation = scope
            .devices
            .get(preparation_id)
            .unwrap()
            .stamp
            .identity
            .generation;
        apply_device_finish(
            scope,
            prepared,
            DevicePhase::Cancelled {
                rollback: Some(rollback),
            },
        );
        scope.events.push(
            InfrastructureEventKind::DeviceRolledBack,
            preparation_id,
            generation,
        );
    }

    pub(in super::super) fn acknowledge_device_prepared(
        &mut self,
        intent: DeviceApplyIntent,
        receipt: DeviceHardwareReceipt,
    ) -> LinearResult<DeviceApplyIntent, PreparedDeviceTicket> {
        linear_apply(intent, |intent| {
            let prepared =
                self.prepare_device_prepared(intent, receipt, LedgerMode::Authoritative)?;
            let scope = prepared.scope;
            let preparation_id = prepared.preparation_id;
            self.apply_device_prepared(prepared, receipt);
            let record = installed_scope(self, scope)
                .devices
                .get(preparation_id)
                .unwrap();
            Ok(PreparedDeviceTicket(mint_device_key::<
                bearer_state::DevicePrepared,
            >(record)))
        })
    }

    pub(in super::super) fn prepare_device_prepared_in_candidate(
        &self,
        intent: &DeviceApplyIntent,
        receipt: DeviceHardwareReceipt,
    ) -> Result<PreparedDeviceAcknowledge, InfrastructureError> {
        self.prepare_device_prepared(intent, receipt, LedgerMode::NonAuthoritativeCandidate)
    }

    fn prepare_device_prepared(
        &self,
        intent: &DeviceApplyIntent,
        receipt: DeviceHardwareReceipt,
        expected_mode: LedgerMode,
    ) -> Result<PreparedDeviceAcknowledge, InfrastructureError> {
        require_device_ledger_mode(self, expected_mode)?;
        let scope = self.scope(intent.0.authority.scope)?;
        let record = validate_device_key(scope, self.registry_instance, &intent.0)?;
        if !__cser_core::matches!(record.phase, DevicePhase::Applying { .. }) {
            return Err(InfrastructureError::InvalidState);
        }
        let coordinates = record.stamp.identity;
        receipt
            .device
            .validate()
            .map_err(|_| InfrastructureError::InvalidReceipt)?;
        if receipt.owned_device != coordinates.owned_device
            || receipt.device.queue() != coordinates.queue
            || receipt.device.device_generation() != coordinates.device_generation
            || receipt.operation_digest != coordinates.operation_digest
            || receipt.actor_slot != coordinates.actor_slot
            || receipt.actor_generation != coordinates.actor_generation
            || receipt.hardware_receipt_digest == 0
            || receipt.preparation_owner_id == 0
            || receipt.preparation_sequence == 0
        {
            return Err(InfrastructureError::InvalidReceipt);
        }
        Ok(PreparedDeviceAcknowledge {
            scope: record.stamp.root.scope,
            preparation_id: coordinates.preparation_id,
            bearer_generation: next_device_bearer_generation(record)?,
            next_revision: preview_revision(scope)?,
        })
    }

    pub(in super::super) fn apply_device_prepared_in_candidate(
        &mut self,
        prepared: PreparedDeviceAcknowledge,
        receipt: DeviceHardwareReceipt,
    ) {
        __cser_core::debug_assert_eq!(self.mode, LedgerMode::NonAuthoritativeCandidate);
        self.apply_device_prepared(prepared, receipt);
    }

    fn apply_device_prepared(
        &mut self,
        prepared: PreparedDeviceAcknowledge,
        receipt: DeviceHardwareReceipt,
    ) {
        let scope = installed_scope_mut(self, prepared.scope);
        let record = scope.devices.get_mut(prepared.preparation_id).unwrap();
        record.stamp.bearer_generation = prepared.bearer_generation;
        record.phase = DevicePhase::PreparedRetained {
            owner: PreparedOwner {
                owned_device: receipt.owned_device,
                device: receipt.device,
                operation_digest: receipt.operation_digest,
                actor_slot: receipt.actor_slot,
                actor_generation: receipt.actor_generation,
                hardware_receipt_digest: receipt.hardware_receipt_digest,
                preparation_owner_id: receipt.preparation_owner_id,
                preparation_sequence: receipt.preparation_sequence,
            },
        };
        scope.revision = prepared.next_revision;
        scope.events.push(
            InfrastructureEventKind::DevicePreparedRetained,
            record.stamp.identity.preparation_id,
            record.stamp.identity.generation,
        );
    }

    pub(in super::super) fn mint_prepared_device_ticket_after_install(
        &self,
        intent: DeviceApplyIntent,
    ) -> PreparedDeviceTicket {
        let previous = intent.0;
        let record = installed_device_successor(self, &previous);
        __cser_core::debug_assert!(__cser_core::matches!(
            record.phase,
            DevicePhase::PreparedRetained { .. }
        ));
        PreparedDeviceTicket(mint_device_key::<bearer_state::DevicePrepared>(record))
    }

    pub(in super::super) fn prepare_device_materialization(
        &self,
        ticket: PreparedDeviceTicket,
    ) -> LinearResult<PreparedDeviceTicket, DeviceMaterializationPlan> {
        linear_apply(ticket, |ticket| {
            self.require_authoritative()?;
            let scope = self.scope(ticket.0.authority.scope)?;
            let record = validate_device_key(scope, self.registry_instance, &ticket.0)?;
            if !__cser_core::matches!(record.phase, DevicePhase::PreparedRetained { .. }) {
                return Err(InfrastructureError::InvalidState);
            }
            Ok(DeviceMaterializationPlan(restate_device_key_ref(&ticket.0)))
        })
    }

    pub(in super::super) fn describe_device_materialization(
        &self,
        plan: &DeviceMaterializationPlan,
    ) -> Result<PreparedDeviceDescription, InfrastructureError> {
        let scope = self.scope(plan.0.authority.scope)?;
        let record = validate_device_key(scope, self.registry_instance, &plan.0)?;
        let owner = match record.phase {
            DevicePhase::PreparedRetained { owner } => owner,
            _ => return Err(InfrastructureError::InvalidState),
        };
        Ok(PreparedDeviceDescription {
            coordinates: record.stamp.identity,
            scope: record.stamp.root.scope,
            parent_effect: device_parent(record)?,
            prepared: prepared_identity(record, owner),
        })
    }

    /// Candidate-only half of the Registry transaction which installs the
    /// business-effect cohort and transfers the prepared owner in one swap.
    pub(in super::super) fn prepare_materialize_device_in_candidate(
        &self,
        plan: &DeviceMaterializationPlan,
        cohort: DeviceCohortIdentity,
    ) -> Result<PreparedDeviceMaterialization, InfrastructureError> {
        require_device_ledger_mode(self, LedgerMode::NonAuthoritativeCandidate)?;
        cohort.validate()?;
        let scope = self.scope(plan.0.authority.scope)?;
        let record = validate_device_key(scope, self.registry_instance, &plan.0)?;
        if record.credit_ownership != DeviceCreditOwnership::Retained
            || !__cser_core::matches!(record.phase, DevicePhase::PreparedRetained { .. })
        {
            return Err(InfrastructureError::InvalidState);
        }
        Ok(PreparedDeviceMaterialization {
            scope: record.stamp.root.scope,
            preparation_id: record.stamp.identity.preparation_id,
            bearer_generation: next_device_bearer_generation(record)?,
            next_queue_slots: scope
                .live
                .queue_slots
                .checked_sub(DEVICE_QUEUE_SLOTS)
                .ok_or(InfrastructureError::Invariant("queue slot underflow"))?,
            next_pinned_pages: scope
                .live
                .pinned_pages
                .checked_sub(DEVICE_PINNED_PAGES)
                .ok_or(InfrastructureError::Invariant("pinned-page underflow"))?,
            next_dma_mappings: scope
                .live
                .dma_mappings
                .checked_sub(DEVICE_DMA_MAPPINGS)
                .ok_or(InfrastructureError::Invariant("DMA-mapping underflow"))?,
            next_revision: preview_revision(scope)?,
        })
    }

    pub(in super::super) fn apply_materialize_device_in_candidate(
        &mut self,
        prepared: PreparedDeviceMaterialization,
        cohort: DeviceCohortIdentity,
    ) {
        __cser_core::debug_assert_eq!(self.mode, LedgerMode::NonAuthoritativeCandidate);
        let scope = installed_scope_mut(self, prepared.scope);
        let record = scope.devices.get_mut(prepared.preparation_id).unwrap();
        let owner = match record.phase {
            DevicePhase::PreparedRetained { owner } => owner,
            _ => __cser_core::unreachable!(),
        };
        record.stamp.bearer_generation = prepared.bearer_generation;
        record.credit_ownership = DeviceCreditOwnership::Transferred;
        record.phase = DevicePhase::Materialized {
            owner,
            cohort,
            preparation_credits_transferred: true,
        };
        scope.live.queue_slots = prepared.next_queue_slots;
        scope.live.pinned_pages = prepared.next_pinned_pages;
        scope.live.dma_mappings = prepared.next_dma_mappings;
        scope.revision = prepared.next_revision;
        scope.events.push(
            InfrastructureEventKind::DeviceMaterialized,
            record.stamp.identity.preparation_id,
            record.stamp.identity.generation,
        );
    }

    pub(in super::super) fn validate_materialized_device_candidate(
        &self,
        plan: &DeviceMaterializationPlan,
        cohort: DeviceCohortIdentity,
    ) -> Result<(), InfrastructureError> {
        require_device_ledger_mode(self, LedgerMode::NonAuthoritativeCandidate)?;
        cohort.validate()?;
        let scope = self.scope(plan.0.authority.scope)?;
        if plan.0.authority.registry_instance != self.registry_instance
            || scope.root.registry_instance != self.registry_instance
        {
            return Err(InfrastructureError::ForeignRegistry);
        }
        if plan.0.authority.scope != scope.root.scope {
            return Err(InfrastructureError::ForeignScope);
        }
        if plan.0.authority.authority_epoch != scope.root.authority_epoch {
            return Err(InfrastructureError::StaleAuthority);
        }
        let record = scope
            .devices
            .get(plan.0.slot)
            .ok_or(InfrastructureError::UnknownObligation)?;
        if record.stamp.identity.preparation_id != plan.0.slot {
            return Err(InfrastructureError::IdentityConflict);
        }
        if record.stamp.identity.generation != plan.0.object_generation
            || record.stamp.nonce != plan.0.nonce
            || record.stamp.bearer_generation
                != plan
                    .0
                    .bearer_generation
                    .checked_add(1)
                    .ok_or(InfrastructureError::CounterOverflow)?
            || record.credit_ownership != DeviceCreditOwnership::Transferred
            || !__cser_core::matches!(
                record.phase,
                DevicePhase::Materialized {
                    cohort: installed,
                    preparation_credits_transferred: true,
                    ..
                } if installed == cohort
            )
        {
            return Err(InfrastructureError::StaleClaim);
        }
        validate_device_record(scope, self.registry_instance, record)
    }

    /// Mints the linear materialized successor only from the authoritative
    /// record after the containing Registry candidate has been installed.
    /// Every fallible candidate/cohort check has already completed, so this
    /// post-install projection is deliberately infallible.
    pub(in super::super) fn mint_materialized_device_ticket_after_install(
        &self,
        plan: DeviceMaterializationPlan,
        cohort: DeviceCohortIdentity,
    ) -> MaterializedDeviceTicket {
        let previous = plan.0;
        let record = installed_device_successor(self, &previous);
        __cser_core::debug_assert_eq!(record.credit_ownership, DeviceCreditOwnership::Transferred);
        __cser_core::debug_assert!(__cser_core::matches!(
            record.phase,
            DevicePhase::Materialized {
                cohort: installed,
                preparation_credits_transferred: true,
                ..
            } if installed == cohort
        ));
        MaterializedDeviceTicket(mint_device_key::<bearer_state::DeviceMaterialized>(record))
    }

    pub(in super::super) fn device_preparation_credit_projections(
        &self,
    ) -> __cser_alloc::vec::Vec<DevicePreparationCreditProjection> {
        self.scopes
            .iter()
            .flat_map(|(scope, state)| {
                state.devices.iter().map(|record| {
                    let ownership = match record.credit_ownership {
                        DeviceCreditOwnership::Held => {
                            DevicePreparationCreditOwnership::HeldByPreparation
                        }
                        DeviceCreditOwnership::Retained => {
                            DevicePreparationCreditOwnership::RetainedByPreparation
                        }
                        DeviceCreditOwnership::Transferred => {
                            DevicePreparationCreditOwnership::TransferredToCohort
                        }
                        DeviceCreditOwnership::Released => {
                            DevicePreparationCreditOwnership::Released
                        }
                    };
                    let parent_effect = match record.stamp.parent {
                        ParentStamp::Effect(parent) => parent,
                        _ => __cser_core::unreachable!(),
                    };
                    let (owner, cohort) = match record.phase {
                        DevicePhase::PreparedRetained { owner }
                        | DevicePhase::Materialized { owner, .. }
                        | DevicePhase::Released { owner, .. } => {
                            let cohort = match record.phase {
                                DevicePhase::Materialized { cohort, .. } => Some(cohort),
                                DevicePhase::Released { cohort, .. } => cohort,
                                DevicePhase::PreparedRetained { .. }
                                | DevicePhase::Reserved
                                | DevicePhase::Applying { .. }
                                | DevicePhase::IndeterminateRetained { .. }
                                | DevicePhase::Cancelled { .. } => None,
                            };
                            (Some(owner), cohort)
                        }
                        DevicePhase::Reserved
                        | DevicePhase::Applying { .. }
                        | DevicePhase::IndeterminateRetained { .. }
                        | DevicePhase::Cancelled { .. } => (None, None),
                    };
                    let prepared = owner.map(|owner| PreparedDeviceIdentity {
                        preparation_id: record.stamp.identity.preparation_id,
                        preparation_generation: record.stamp.identity.generation,
                        owned_device: owner.owned_device,
                        device: owner.device,
                        operation_digest: owner.operation_digest,
                        actor_slot: owner.actor_slot,
                        actor_generation: owner.actor_generation,
                        hardware_receipt_digest: owner.hardware_receipt_digest,
                        preparation_owner_id: owner.preparation_owner_id,
                        preparation_sequence: owner.preparation_sequence,
                    });
                    DevicePreparationCreditProjection {
                        scope: *scope,
                        parent_effect,
                        charges: record.stamp.identity.credit_charges(),
                        ownership,
                        prepared,
                        cohort,
                    }
                })
            })
            .collect()
    }

    pub(in super::super) fn release_materialized_device(
        &mut self,
        ticket: MaterializedDeviceTicket,
        proof: ValidatedDeviceClosureProof,
    ) -> LinearResult<MaterializedDeviceTicket, RegistryDeviceClosureReceipt> {
        linear_apply(ticket, |ticket| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope(ticket.0.authority.scope)?;
            let record = validate_device_key(scope, registry_instance, &ticket.0)?;
            let (owner, cohort) = match record.phase {
                DevicePhase::Materialized {
                    owner,
                    cohort,
                    preparation_credits_transferred: true,
                } => (owner, cohort),
                _ => return Err(InfrastructureError::InvalidState),
            };
            let closure = proof.receipt;
            if !valid_materialized_closure(registry_instance, record, owner, closure) {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let prepared =
                prepare_device_finish(scope, record, DeviceCreditOwnership::Transferred)?;
            let scope = installed_scope_mut(self, prepared.scope);
            apply_device_finish(
                scope,
                prepared,
                DevicePhase::Released {
                    owner,
                    cohort: Some(cohort),
                    closure,
                },
            );
            Ok(closure)
        })
    }

    /// Candidate-only half of the production closure transaction. It binds
    /// Registry reset/IOTLB closure and facade DMA closure to the same retained
    /// preparation before the materialized bearer is consumed.
    pub(in super::super) fn prepare_materialized_device_release_in_candidate(
        &self,
        ticket: &MaterializedDeviceTicket,
        proof: ValidatedDeviceClosureProof,
        device_closure: VerifiedDeviceClosure,
    ) -> Result<PreparedMaterializedDeviceRelease, InfrastructureError> {
        require_device_ledger_mode(self, LedgerMode::NonAuthoritativeCandidate)?;
        let scope = self.scope(ticket.0.authority.scope)?;
        let record = validate_device_key(scope, self.registry_instance, &ticket.0)?;
        let (owner, cohort) = match record.phase {
            DevicePhase::Materialized {
                owner,
                cohort,
                preparation_credits_transferred: true,
            } => (owner, cohort),
            _ => return Err(InfrastructureError::InvalidState),
        };
        let closure = proof.receipt;
        if !valid_materialized_closure(self.registry_instance, record, owner, closure)
            || device_closure.preparation_owner_id != owner.preparation_owner_id
            || device_closure.preparation_sequence != owner.preparation_sequence
            || device_closure.device != owner.device
        {
            return Err(InfrastructureError::InvalidReceipt);
        }
        Ok(PreparedMaterializedDeviceRelease {
            finish: prepare_device_finish(scope, record, DeviceCreditOwnership::Transferred)?,
            owner,
            cohort,
            closure,
        })
    }

    pub(in super::super) fn apply_materialized_device_release_in_candidate(
        &mut self,
        prepared: PreparedMaterializedDeviceRelease,
    ) {
        __cser_core::debug_assert_eq!(self.mode, LedgerMode::NonAuthoritativeCandidate);
        let scope = installed_scope_mut(self, prepared.finish.scope);
        apply_device_finish(
            scope,
            prepared.finish,
            DevicePhase::Released {
                owner: prepared.owner,
                cohort: Some(prepared.cohort),
                closure: prepared.closure,
            },
        );
        scope.events.push(
            InfrastructureEventKind::DeviceReleased,
            prepared.closure.sequence,
            prepared.closure.device.device_generation(),
        );
    }

    pub(in super::super) fn consume_materialized_ticket_after_release(
        &self,
        ticket: MaterializedDeviceTicket,
    ) -> RegistryDeviceClosureReceipt {
        let previous = ticket.0;
        let record = installed_device_successor(self, &previous);
        match record.phase {
            DevicePhase::Released {
                cohort: Some(_),
                closure,
                ..
            } => closure,
            _ => __cser_core::unreachable!(),
        }
    }

    pub(in super::super) fn release_unmaterialized_retained_device(
        &mut self,
        ticket: PreparedDeviceTicket,
        proof: ValidatedDeviceClosureProof,
    ) -> LinearResult<PreparedDeviceTicket, RegistryDeviceClosureReceipt> {
        linear_apply(ticket, |ticket| {
            self.require_authoritative()?;
            let registry_instance = self.registry_instance;
            let scope = self.scope(ticket.0.authority.scope)?;
            let record = validate_device_key(scope, registry_instance, &ticket.0)?;
            let owner = match record.phase {
                DevicePhase::PreparedRetained { owner } => owner,
                _ => return Err(InfrastructureError::InvalidState),
            };
            let closure = proof.receipt;
            if closure.registry_instance_id != registry_instance
                || closure.scope != record.stamp.root.scope
                || closure.device != owner.device
                || closure.sequence == 0
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let prepared = prepare_device_finish(scope, record, DeviceCreditOwnership::Released)?;
            let scope = installed_scope_mut(self, prepared.scope);
            apply_device_finish(
                scope,
                prepared,
                DevicePhase::Released {
                    owner,
                    cohort: None,
                    closure,
                },
            );
            Ok(closure)
        })
    }

    pub(in super::super) fn device_preparation_coordinates(
        &self,
        ticket: &DevicePreparationTicket,
    ) -> Result<DeviceReservationCoordinates, InfrastructureError> {
        let scope = self.scope(ticket.0.authority.scope)?;
        let record = validate_device_key(scope, self.registry_instance, &ticket.0)?;
        if record.phase != DevicePhase::Reserved {
            return Err(InfrastructureError::InvalidState);
        }
        Ok(record.stamp.identity)
    }

    pub(in super::super) fn device_apply_coordinates(
        &self,
        intent: &DeviceApplyIntent,
    ) -> Result<DeviceReservationCoordinates, InfrastructureError> {
        let scope = self.scope(intent.0.authority.scope)?;
        let record = validate_device_key(scope, self.registry_instance, &intent.0)?;
        if !__cser_core::matches!(record.phase, DevicePhase::Applying { .. }) {
            return Err(InfrastructureError::InvalidState);
        }
        Ok(record.stamp.identity)
    }

    pub(in super::super) fn prepared_device_coordinates(
        &self,
        ticket: &PreparedDeviceTicket,
    ) -> Result<DeviceReservationCoordinates, InfrastructureError> {
        let scope = self.scope(ticket.0.authority.scope)?;
        let record = validate_device_key(scope, self.registry_instance, &ticket.0)?;
        if !__cser_core::matches!(record.phase, DevicePhase::PreparedRetained { .. }) {
            return Err(InfrastructureError::InvalidState);
        }
        Ok(record.stamp.identity)
    }

    pub(in super::super) fn materialized_device_identity(
        &self,
        ticket: &MaterializedDeviceTicket,
    ) -> Result<PreparedDeviceIdentity, InfrastructureError> {
        let scope = self.scope(ticket.0.authority.scope)?;
        let record = validate_device_key(scope, self.registry_instance, &ticket.0)?;
        match record.phase {
            DevicePhase::Materialized {
                owner,
                preparation_credits_transferred: true,
                ..
            } => Ok(prepared_identity(record, owner)),
            _ => Err(InfrastructureError::InvalidState),
        }
    }

    pub(in super::super) fn query_device_preparation(
        &self,
        context: &WorkloadContext,
        preparation_id: u64,
        generation: u64,
    ) -> Result<DevicePreparationRecoveryProjection, InfrastructureError> {
        self.require_authoritative()?;
        let scope = self.scope(context.root.scope)?;
        validate_context(scope, self.registry_instance, context)?;
        let record = scope
            .devices
            .get(preparation_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
        if record.stamp.identity.generation != generation {
            return Err(InfrastructureError::StaleGeneration);
        }
        if record.stamp.workload.request != context.workload.request {
            return Err(InfrastructureError::ForeignWorkload);
        }
        validate_device_record(scope, self.registry_instance, record)?;
        let credit_ownership = match record.credit_ownership {
            DeviceCreditOwnership::Held => DevicePreparationCreditOwnership::HeldByPreparation,
            DeviceCreditOwnership::Retained => {
                DevicePreparationCreditOwnership::RetainedByPreparation
            }
            DeviceCreditOwnership::Transferred => {
                DevicePreparationCreditOwnership::TransferredToCohort
            }
            DeviceCreditOwnership::Released => DevicePreparationCreditOwnership::Released,
        };
        let (state, prepared_device, cohort, rollback_receipt, closure_receipt, observation_digest) =
            match record.phase {
                DevicePhase::Reserved => (
                    DevicePreparationRecoveryState::Reserved,
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
                DevicePhase::Applying { .. } => (
                    DevicePreparationRecoveryState::ApplyingHardware,
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
                DevicePhase::IndeterminateRetained {
                    observation_digest, ..
                } => (
                    DevicePreparationRecoveryState::IndeterminateRetained,
                    None,
                    None,
                    None,
                    None,
                    Some(observation_digest),
                ),
                DevicePhase::PreparedRetained { owner } => (
                    DevicePreparationRecoveryState::PreparedRetained,
                    Some(owner.device),
                    None,
                    None,
                    None,
                    None,
                ),
                DevicePhase::Materialized { owner, cohort, .. } => (
                    DevicePreparationRecoveryState::Materialized,
                    Some(owner.device),
                    Some(cohort),
                    None,
                    None,
                    None,
                ),
                DevicePhase::Released {
                    owner,
                    cohort,
                    closure,
                } => (
                    DevicePreparationRecoveryState::Released,
                    Some(owner.device),
                    cohort,
                    None,
                    Some(closure),
                    None,
                ),
                DevicePhase::Cancelled { rollback } => (
                    DevicePreparationRecoveryState::Cancelled,
                    None,
                    None,
                    rollback,
                    None,
                    None,
                ),
            };
        let parent_effect = match record.stamp.parent {
            ParentStamp::Effect(parent) => parent,
            _ => return Err(InfrastructureError::ForeignParent),
        };
        let prepared_identity = match record.phase {
            DevicePhase::PreparedRetained { owner }
            | DevicePhase::Materialized { owner, .. }
            | DevicePhase::Released { owner, .. } => Some(PreparedDeviceIdentity {
                preparation_id: record.stamp.identity.preparation_id,
                preparation_generation: record.stamp.identity.generation,
                owned_device: owner.owned_device,
                device: owner.device,
                operation_digest: owner.operation_digest,
                actor_slot: owner.actor_slot,
                actor_generation: owner.actor_generation,
                hardware_receipt_digest: owner.hardware_receipt_digest,
                preparation_owner_id: owner.preparation_owner_id,
                preparation_sequence: owner.preparation_sequence,
            }),
            DevicePhase::Reserved
            | DevicePhase::Applying { .. }
            | DevicePhase::IndeterminateRetained { .. }
            | DevicePhase::Cancelled { .. } => None,
        };
        Ok(DevicePreparationRecoveryProjection {
            coordinates: record.stamp.identity,
            parent_effect,
            state,
            credit_ownership,
            prepared_device,
            prepared_identity,
            cohort,
            rollback_receipt,
            closure_receipt,
            observation_digest,
        })
    }

    pub(in super::super) fn adopt_device_after_fence(
        &mut self,
        context: &WorkloadContext,
        preparation_id: u64,
        generation: u64,
    ) -> Result<DeviceAdoption, InfrastructureError> {
        self.require_authoritative()?;
        let registry_instance = self.registry_instance;
        let scope = self.scope(context.root.scope)?;
        validate_context(scope, registry_instance, context)?;
        let record = scope
            .devices
            .get(preparation_id)
            .ok_or(InfrastructureError::UnknownObligation)?;
        if record.stamp.identity.generation != generation {
            return Err(InfrastructureError::StaleGeneration);
        }
        validate_device_record_historical(scope, registry_instance, record)?;
        if record.stamp.workload.request != context.workload.request
            || record.stamp.domain.domain != context.domain.domain
            || record.stamp.domain.binding_epoch >= context.domain.binding_epoch
        {
            return Err(InfrastructureError::StaleBinding);
        }
        if __cser_core::matches!(
            record.phase,
            DevicePhase::IndeterminateRetained { .. }
                | DevicePhase::Released { .. }
                | DevicePhase::Cancelled { .. }
        ) {
            return Err(InfrastructureError::InvalidState);
        }
        let phase = record.phase;
        let replay_apply = __cser_core::matches!(phase, DevicePhase::Applying { .. });
        let next_bearer = next_device_bearer_generation(record)?;
        let (nonces, next_nonce) = preview_nonces(scope, usize::from(replay_apply))?;
        let index_slot = record.stamp.nonce;
        // The reverse index is validated before any primary record is changed.
        let index = scope
            .reverse_indexes
            .get(index_slot)
            .ok_or(InfrastructureError::Invariant(
                "missing device reverse index",
            ))?;
        if *index != reverse_index_for_device_record(record)? {
            return Err(InfrastructureError::Invariant(
                "device reverse index mismatch",
            ));
        }
        let apply_generation = if replay_apply {
            record
                .apply_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?
        } else {
            record.apply_generation
        };
        let prepared = PreparedDeviceAdoption {
            scope: context.root.scope,
            preparation_id,
            domain: context.domain,
            workload: context.workload,
            bearer_generation: next_bearer,
            apply_generation,
            apply_nonce: if replay_apply { Some(nonces[0]) } else { None },
            next_nonce,
            next_revision: preview_revision(scope)?,
            index_slot,
        };
        self.apply_device_adoption(prepared);
        let scope = installed_scope(self, context.root.scope);
        let record = scope.devices.get(preparation_id).unwrap();
        Ok(match record.phase {
            DevicePhase::Reserved => {
                DeviceAdoption::Reserved(DevicePreparationTicket(mint_device_key::<
                    bearer_state::DeviceReserved,
                >(record)))
            }
            DevicePhase::Applying { .. } => {
                DeviceAdoption::ReplayApply(DeviceApplyIntent(mint_device_key::<
                    bearer_state::DeviceApplying,
                >(record)))
            }
            DevicePhase::PreparedRetained { .. } => {
                DeviceAdoption::Prepared(PreparedDeviceTicket(mint_device_key::<
                    bearer_state::DevicePrepared,
                >(record)))
            }
            DevicePhase::Materialized { .. } => {
                DeviceAdoption::Materialized(MaterializedDeviceTicket(mint_device_key::<
                    bearer_state::DeviceMaterialized,
                >(record)))
            }
            DevicePhase::IndeterminateRetained { .. }
            | DevicePhase::Released { .. }
            | DevicePhase::Cancelled { .. } => {
                __cser_core::unreachable!()
            }
        })
    }

    fn apply_device_adoption(&mut self, prepared: PreparedDeviceAdoption) {
        let scope = installed_scope_mut(self, prepared.scope);
        let record = scope.devices.get_mut(prepared.preparation_id).unwrap();
        record.stamp.domain = prepared.domain;
        record.stamp.workload = prepared.workload;
        record.stamp.bearer_generation = prepared.bearer_generation;
        record.apply_generation = prepared.apply_generation;
        if let Some(apply_nonce) = prepared.apply_nonce {
            record.phase = DevicePhase::Applying {
                apply_generation: prepared.apply_generation,
                apply_nonce,
            };
        }
        scope
            .reverse_indexes
            .get_mut(prepared.index_slot)
            .unwrap()
            .binding_epoch = prepared.domain.binding_epoch;
        scope.next_nonce = prepared.next_nonce;
        scope.revision = prepared.next_revision;
    }
}

impl DevicePreparationTicket {
    pub(in super::super) const fn scope(&self) -> super::ScopeKey {
        self.0.authority.scope
    }

    pub(in super::super) const fn preparation_id(&self) -> u64 {
        self.0.slot
    }

    pub(in super::super) const fn generation(&self) -> u64 {
        self.0.object_generation
    }

    #[cfg(test)]
    pub(in super::super) fn duplicate_for_test(&self) -> Self {
        Self(duplicate_device_key_for_test(&self.0))
    }

    #[cfg(test)]
    pub(in super::super) fn stale_bearer_for_test(&self) -> Self {
        Self(stale_device_key_for_test(&self.0))
    }
}

impl DeviceApplyIntent {
    pub(in super::super) const fn scope(&self) -> super::ScopeKey {
        self.0.authority.scope
    }

    pub(in super::super) const fn preparation_id(&self) -> u64 {
        self.0.slot
    }

    pub(in super::super) const fn generation(&self) -> u64 {
        self.0.object_generation
    }
}

impl PreparedDeviceTicket {
    pub(in super::super) const fn scope(&self) -> super::ScopeKey {
        self.0.authority.scope
    }

    pub(in super::super) const fn preparation_id(&self) -> u64 {
        self.0.slot
    }

    pub(in super::super) const fn generation(&self) -> u64 {
        self.0.object_generation
    }

    #[cfg(test)]
    pub(in super::super) fn duplicate_for_test(&self) -> Self {
        Self(duplicate_device_key_for_test(&self.0))
    }

    #[cfg(test)]
    pub(in super::super) fn stale_bearer_for_test(&self) -> Self {
        Self(stale_device_key_for_test(&self.0))
    }
}

impl MaterializedDeviceTicket {
    pub(in super::super) const fn scope(&self) -> super::ScopeKey {
        self.0.authority.scope
    }

    pub(in super::super) const fn preparation_id(&self) -> u64 {
        self.0.slot
    }

    pub(in super::super) const fn generation(&self) -> u64 {
        self.0.object_generation
    }
}

impl DeviceMaterializationPlan {
    pub(in super::super) const fn scope(&self) -> super::ScopeKey {
        self.0.authority.scope
    }

    pub(in super::super) const fn preparation_id(&self) -> u64 {
        self.0.slot
    }

    pub(in super::super) const fn generation(&self) -> u64 {
        self.0.object_generation
    }

    pub(in super::super) fn into_prepared_device_ticket(self) -> PreparedDeviceTicket {
        PreparedDeviceTicket(restate_device_key(self.0))
    }
}

fn require_device_ledger_mode(
    state: &InfrastructureState,
    expected: LedgerMode,
) -> Result<(), InfrastructureError> {
    if state.mode != expected {
        return Err(InfrastructureError::CandidateHasNoAuthority);
    }
    Ok(())
}

fn installed_scope(state: &InfrastructureState, key: super::ScopeKey) -> &ScopeInfrastructure {
    state
        .scopes
        .iter()
        .find_map(|(candidate, scope)| (*candidate == key).then_some(scope))
        .unwrap()
}

fn installed_scope_mut(
    state: &mut InfrastructureState,
    key: super::ScopeKey,
) -> &mut ScopeInfrastructure {
    state
        .scopes
        .iter_mut()
        .find_map(|(candidate, scope)| (*candidate == key).then_some(scope))
        .unwrap()
}

fn prepare_device_finish(
    scope: &ScopeInfrastructure,
    record: &DeviceRecord,
    credit_ownership: DeviceCreditOwnership,
) -> Result<PreparedDeviceFinish, InfrastructureError> {
    let stamp = record.stamp;
    let current = record.phase;
    let preparation_credits_live = __cser_core::matches!(
        current,
        DevicePhase::Reserved | DevicePhase::Applying { .. } | DevicePhase::PreparedRetained { .. }
    );
    let next_revision = preview_revision(scope)?;
    let next_live = checked_sub(scope.live.device_preparations, 1)?;
    let next_queue_slots = if preparation_credits_live {
        scope
            .live
            .queue_slots
            .checked_sub(DEVICE_QUEUE_SLOTS)
            .ok_or(InfrastructureError::Invariant("queue slot underflow"))?
    } else {
        scope.live.queue_slots
    };
    let next_pinned = if preparation_credits_live {
        scope
            .live
            .pinned_pages
            .checked_sub(DEVICE_PINNED_PAGES)
            .ok_or(InfrastructureError::Invariant("pinned-page underflow"))?
    } else {
        scope.live.pinned_pages
    };
    let next_dma = if preparation_credits_live {
        scope
            .live
            .dma_mappings
            .checked_sub(DEVICE_DMA_MAPPINGS)
            .ok_or(InfrastructureError::Invariant("DMA-mapping underflow"))?
    } else {
        scope.live.dma_mappings
    };
    let next_workload_children = preview_workload_child_sub(scope, stamp.workload.request)?;
    Ok(PreparedDeviceFinish {
        scope: stamp.root.scope,
        preparation_id: stamp.identity.preparation_id,
        bearer_generation: next_device_bearer_generation(record)?,
        workload_request: stamp.workload.request,
        next_revision,
        next_live,
        next_queue_slots,
        next_pinned_pages: next_pinned,
        next_dma_mappings: next_dma,
        next_workload_children,
        credit_ownership,
    })
}

fn apply_device_finish(
    scope: &mut ScopeInfrastructure,
    prepared: PreparedDeviceFinish,
    terminal: DevicePhase,
) {
    let record = scope.devices.get_mut(prepared.preparation_id).unwrap();
    record.stamp.bearer_generation = prepared.bearer_generation;
    record.credit_ownership = prepared.credit_ownership;
    record.phase = terminal;
    let generation = record.stamp.identity.generation;
    scope.revision = prepared.next_revision;
    scope.live.device_preparations = prepared.next_live;
    scope.live.queue_slots = prepared.next_queue_slots;
    scope.live.pinned_pages = prepared.next_pinned_pages;
    scope.live.dma_mappings = prepared.next_dma_mappings;
    scope
        .workloads
        .get_mut(prepared.workload_request.id)
        .unwrap()
        .live_children = prepared.next_workload_children;
    scope.events.push(
        if __cser_core::matches!(terminal, DevicePhase::Released { .. }) {
            InfrastructureEventKind::DeviceReleased
        } else {
            InfrastructureEventKind::DeviceCancelled
        },
        prepared.preparation_id,
        generation,
    );
}

fn mint_device_key<State: bearer_state::Sealed>(record: &DeviceRecord) -> BearerKey<State> {
    BearerKey {
        authority: super::AuthorityKey {
            registry_instance: record.stamp.root.registry_instance,
            scope: record.stamp.root.scope,
            authority_epoch: record.stamp.root.authority_epoch,
        },
        slot: record.stamp.identity.preparation_id,
        object_generation: record.stamp.identity.generation,
        bearer_generation: record.stamp.bearer_generation,
        nonce: record.stamp.nonce,
        state: __cser_core::marker::PhantomData,
    }
}

fn restate_device_key<From: bearer_state::Sealed, To: bearer_state::Sealed>(
    key: BearerKey<From>,
) -> BearerKey<To> {
    BearerKey {
        authority: key.authority,
        slot: key.slot,
        object_generation: key.object_generation,
        bearer_generation: key.bearer_generation,
        nonce: key.nonce,
        state: __cser_core::marker::PhantomData,
    }
}

fn restate_device_key_ref<From: bearer_state::Sealed, To: bearer_state::Sealed>(
    key: &BearerKey<From>,
) -> BearerKey<To> {
    BearerKey {
        authority: super::AuthorityKey {
            registry_instance: key.authority.registry_instance,
            scope: key.authority.scope,
            authority_epoch: key.authority.authority_epoch,
        },
        slot: key.slot,
        object_generation: key.object_generation,
        bearer_generation: key.bearer_generation,
        nonce: key.nonce,
        state: __cser_core::marker::PhantomData,
    }
}

#[cfg(test)]
fn duplicate_device_key_for_test<State: bearer_state::Sealed>(
    key: &BearerKey<State>,
) -> BearerKey<State> {
    BearerKey {
        authority: super::AuthorityKey {
            registry_instance: key.authority.registry_instance,
            scope: key.authority.scope,
            authority_epoch: key.authority.authority_epoch,
        },
        slot: key.slot,
        object_generation: key.object_generation,
        bearer_generation: key.bearer_generation,
        nonce: key.nonce,
        state: __cser_core::marker::PhantomData,
    }
}

#[cfg(test)]
fn stale_device_key_for_test<State: bearer_state::Sealed>(
    key: &BearerKey<State>,
) -> BearerKey<State> {
    let mut duplicate = duplicate_device_key_for_test(key);
    duplicate.bearer_generation = duplicate.bearer_generation.checked_add(1).unwrap();
    duplicate
}

fn installed_device_successor<'a, State: bearer_state::Sealed>(
    state: &'a InfrastructureState,
    previous: &BearerKey<State>,
) -> &'a DeviceRecord {
    __cser_core::debug_assert_eq!(state.mode, LedgerMode::Authoritative);
    let record = installed_scope(state, previous.authority.scope)
        .devices
        .get(previous.slot)
        .unwrap();
    __cser_core::debug_assert_eq!(
        record.stamp.bearer_generation,
        previous.bearer_generation.checked_add(1).unwrap()
    );
    __cser_core::debug_assert_eq!(record.stamp.identity.generation, previous.object_generation);
    __cser_core::debug_assert_eq!(record.stamp.nonce, previous.nonce);
    record
}

fn validate_device_key<'a, State: bearer_state::Sealed>(
    scope: &'a ScopeInfrastructure,
    registry_instance: u64,
    key: &BearerKey<State>,
) -> Result<&'a DeviceRecord, InfrastructureError> {
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
        .devices
        .get(key.slot)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp.identity.preparation_id != key.slot {
        return Err(InfrastructureError::IdentityConflict);
    }
    if record.stamp.identity.generation != key.object_generation
        || record.stamp.bearer_generation != key.bearer_generation
        || record.stamp.nonce != key.nonce
    {
        return Err(InfrastructureError::StaleGeneration);
    }
    validate_device_record(scope, registry_instance, record)?;
    Ok(record)
}

fn validate_device_record(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    record: &DeviceRecord,
) -> Result<(), InfrastructureError> {
    super::validate_stamp_common(scope, registry_instance, &record.stamp)?;
    validate_device_record_body(scope, record)
}

fn validate_device_record_historical(
    scope: &ScopeInfrastructure,
    registry_instance: u64,
    record: &DeviceRecord,
) -> Result<(), InfrastructureError> {
    validate_stamp_common_historical(scope, registry_instance, &record.stamp)?;
    validate_device_record_body(scope, record)
}

fn validate_device_record_body(
    scope: &ScopeInfrastructure,
    record: &DeviceRecord,
) -> Result<(), InfrastructureError> {
    record.stamp.identity.validate()?;
    let expected_index = reverse_index_for_device_record(record)?;
    match scope.reverse_indexes.get(record.stamp.nonce) {
        None => {
            return Err(InfrastructureError::Invariant(
                "missing device reverse index",
            ));
        }
        Some(index) if *index != expected_index => {
            return Err(InfrastructureError::Invariant(
                "device reverse index mismatch",
            ));
        }
        Some(_) => {}
    }
    let phase_valid = match record.phase {
        DevicePhase::Reserved => {
            record.apply_generation == 0 && record.credit_ownership == DeviceCreditOwnership::Held
        }
        DevicePhase::Applying {
            apply_generation,
            apply_nonce,
        } => {
            apply_generation != 0
                && apply_nonce != 0
                && apply_generation == record.apply_generation
                && record.credit_ownership == DeviceCreditOwnership::Retained
        }
        DevicePhase::IndeterminateRetained {
            preparation_owner_id,
            preparation_sequence,
            observation_digest,
        } => {
            record.apply_generation != 0
                && record.credit_ownership == DeviceCreditOwnership::Retained
                && preparation_owner_id != 0
                && preparation_sequence != 0
                && observation_digest != 0
        }
        DevicePhase::PreparedRetained { owner } => {
            record.apply_generation != 0
                && record.credit_ownership == DeviceCreditOwnership::Retained
                && validate_prepared_owner(record, owner).is_ok()
        }
        DevicePhase::Materialized {
            owner,
            cohort,
            preparation_credits_transferred,
        } => {
            record.apply_generation != 0
                && record.credit_ownership == DeviceCreditOwnership::Transferred
                && preparation_credits_transferred
                && validate_prepared_owner(record, owner).is_ok()
                && cohort.validate().is_ok()
        }
        DevicePhase::Released {
            owner,
            cohort,
            closure,
        } => {
            let ownership_matches = if cohort.is_some() {
                record.credit_ownership == DeviceCreditOwnership::Transferred
            } else {
                record.credit_ownership == DeviceCreditOwnership::Released
            };
            ownership_matches
                && validate_prepared_owner(record, owner).is_ok()
                && cohort.is_none_or(|cohort| cohort.validate().is_ok())
                && valid_materialized_closure(
                    record.stamp.root.registry_instance,
                    record,
                    owner,
                    closure,
                )
        }
        DevicePhase::Cancelled { rollback } => {
            record.credit_ownership == DeviceCreditOwnership::Released
                && rollback.is_none_or(|rollback| validate_rollback(record, rollback))
        }
    };
    if !phase_valid {
        return Err(InfrastructureError::Invariant("invalid device phase"));
    }
    Ok(())
}

fn validate_prepared_owner(
    record: &DeviceRecord,
    owner: PreparedOwner,
) -> Result<(), InfrastructureError> {
    owner
        .device
        .validate()
        .map_err(|_| InfrastructureError::InvalidReceipt)?;
    let coordinates = record.stamp.identity;
    if owner.owned_device != coordinates.owned_device
        || owner.device.queue() != coordinates.queue
        || owner.device.device_generation() != coordinates.device_generation
        || owner.operation_digest != coordinates.operation_digest
        || owner.actor_slot != coordinates.actor_slot
        || owner.actor_generation != coordinates.actor_generation
        || owner.hardware_receipt_digest == 0
        || owner.preparation_owner_id == 0
        || owner.preparation_sequence == 0
    {
        return Err(InfrastructureError::InvalidReceipt);
    }
    Ok(())
}

fn valid_materialized_closure(
    registry_instance: u64,
    record: &DeviceRecord,
    owner: PreparedOwner,
    closure: RegistryDeviceClosureReceipt,
) -> bool {
    let next_generation = owner.device.device_generation().checked_add(1);
    closure.registry_instance_id == registry_instance
        && closure.scope == record.stamp.root.scope
        && closure.sequence != 0
        && closure.device.device_session() == owner.device.device_session()
        && closure.device.queue() == owner.device.queue()
        && closure.device.descriptor_token() == owner.device.descriptor_token()
        && Some(closure.device.device_generation()) == next_generation
}

fn validate_rollback(record: &DeviceRecord, rollback: DeviceRollbackReceipt) -> bool {
    let coordinates = record.stamp.identity;
    rollback.owned_device == coordinates.owned_device
        && rollback.queue == coordinates.queue
        && rollback.device_generation == coordinates.device_generation
        && rollback.operation_digest == coordinates.operation_digest
        && rollback.actor_slot == coordinates.actor_slot
        && rollback.actor_generation == coordinates.actor_generation
        && rollback.rollback_receipt_digest != 0
        && rollback.preparation_owner_id != 0
        && rollback.preparation_sequence != 0
}

fn reverse_index_for_device_record(
    record: &DeviceRecord,
) -> Result<ReverseIndexRecord, InfrastructureError> {
    let coordinates = record.stamp.identity;
    Ok(ReverseIndexRecord {
        slot: record.stamp.nonce,
        kind: InfrastructureKind::DevicePreparation,
        root_effect: record.stamp.root.root_effect,
        parent: ReverseParent::Effect(device_parent(record)?),
        task: None,
        domain: record.stamp.domain.domain,
        binding_epoch: record.stamp.domain.binding_epoch,
        source_domain: None,
        source_binding_epoch: None,
        resource: Some(coordinates.owned_device),
        actor_slot: Some(coordinates.actor_slot),
        actor_generation: Some(coordinates.actor_generation),
        retry_generation: coordinates.generation,
    })
}

fn device_parent(record: &DeviceRecord) -> Result<EffectKey, InfrastructureError> {
    match record.stamp.parent {
        ParentStamp::Effect(parent) => Ok(parent),
        _ => Err(InfrastructureError::ForeignParent),
    }
}

fn prepared_identity(record: &DeviceRecord, owner: PreparedOwner) -> PreparedDeviceIdentity {
    PreparedDeviceIdentity {
        preparation_id: record.stamp.identity.preparation_id,
        preparation_generation: record.stamp.identity.generation,
        owned_device: owner.owned_device,
        device: owner.device,
        operation_digest: owner.operation_digest,
        actor_slot: owner.actor_slot,
        actor_generation: owner.actor_generation,
        hardware_receipt_digest: owner.hardware_receipt_digest,
        preparation_owner_id: owner.preparation_owner_id,
        preparation_sequence: owner.preparation_sequence,
    }
}

fn next_device_bearer_generation(record: &DeviceRecord) -> Result<u64, InfrastructureError> {
    record
        .stamp
        .bearer_generation
        .checked_add(1)
        .ok_or(InfrastructureError::CounterOverflow)
}

pub(super) fn device_phase_live(phase: DevicePhase) -> bool {
    !__cser_core::matches!(
        phase,
        DevicePhase::Released { .. } | DevicePhase::Cancelled { .. }
    )
}
