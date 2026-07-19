// SPDX-License-Identifier: MPL-2.0

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use super::{
    BearerStamp, DEVICE_DMA_MAPPINGS, DEVICE_PINNED_PAGES, DEVICE_QUEUE_SLOTS, DeviceAdoption,
    DeviceApplyIntent, DeviceCohortIdentity, DeviceCreditOwnership, DeviceHardwareReceipt,
    DeviceMaterializationPlan, DevicePhase, DevicePreparationCreditOwnership,
    DevicePreparationCreditProjection, DevicePreparationRecoveryProjection,
    DevicePreparationRecoveryState, DevicePreparationTicket, DeviceRecord,
    DeviceReservationCoordinates, DeviceRollbackReceipt, EffectKey, InfrastructureError,
    InfrastructureEventKind, InfrastructureKind, InfrastructureState, LedgerMode, LinearResult,
    MaterializedDeviceTicket, ParentStamp, PreparedDeviceIdentity, PreparedOwner,
    RegistryDeviceClosureReceipt, ReverseIndexRecord, ReverseParent, ScopeInfrastructure,
    ValidatedDeviceClosureProof, WorkloadContext, checked_add, checked_sub, linear_apply,
    preview_bearer_stamp, preview_nonce, preview_nonces, preview_revision,
    preview_workload_child_add, preview_workload_child_sub, require_vacancy,
    validate_active_admission, validate_context, validate_device_bearer,
};

impl InfrastructureState {
    pub(in super::super) fn reserve_device_preparation(
        &mut self,
        context: &WorkloadContext,
        parent_effect: EffectKey,
        coordinates: DeviceReservationCoordinates,
    ) -> Result<DevicePreparationTicket, InfrastructureError> {
        self.reserve_device_preparation_for_mode(
            context,
            parent_effect,
            coordinates,
            LedgerMode::Authoritative,
        )
    }

    pub(in super::super) fn reserve_device_preparation_in_candidate(
        &mut self,
        context: &WorkloadContext,
        parent_effect: EffectKey,
        coordinates: DeviceReservationCoordinates,
    ) -> Result<DevicePreparationTicket, InfrastructureError> {
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
    ) -> Result<DevicePreparationTicket, InfrastructureError> {
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
        scope.devices.install(
            DeviceRecord {
                stamp,
                apply_generation: 0,
                credit_ownership: DeviceCreditOwnership::Held,
                phase: DevicePhase::Reserved,
                closure_sequence: None,
            },
            InfrastructureKind::DevicePreparation,
        )?;
        scope
            .reverse_indexes
            .install(index, InfrastructureKind::DevicePreparation)?;
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
        Ok(DevicePreparationTicket(
            scope.devices.get(coordinates.preparation_id).unwrap().stamp,
        ))
    }

    pub(in super::super) fn cancel_reserved_device(
        &mut self,
        ticket: DevicePreparationTicket,
    ) -> LinearResult<DevicePreparationTicket, ()> {
        self.cancel_reserved_device_for_mode(ticket, LedgerMode::Authoritative)
            .map(|_| ())
    }

    pub(in super::super) fn cancel_reserved_device_in_candidate(
        &mut self,
        ticket: DevicePreparationTicket,
    ) -> LinearResult<DevicePreparationTicket, DevicePreparationTicket> {
        self.cancel_reserved_device_for_mode(ticket, LedgerMode::NonAuthoritativeCandidate)
    }

    fn cancel_reserved_device_for_mode(
        &mut self,
        ticket: DevicePreparationTicket,
        expected_mode: LedgerMode,
    ) -> LinearResult<DevicePreparationTicket, DevicePreparationTicket> {
        linear_apply(ticket, |ticket| {
            require_device_ledger_mode(self, expected_mode)?;
            let stamp = ticket.0;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_device_bearer(scope, registry_instance, &stamp)?;
            if scope
                .devices
                .get(stamp.identity.preparation_id)
                .unwrap()
                .phase
                != DevicePhase::Reserved
            {
                return Err(InfrastructureError::InvalidState);
            }
            finish_device(scope, stamp, DevicePhase::Cancelled { rollback: None })?;
            Ok(DevicePreparationTicket(stamp))
        })
    }

    pub(in super::super) fn begin_device_hardware_apply(
        &mut self,
        ticket: DevicePreparationTicket,
    ) -> LinearResult<DevicePreparationTicket, DeviceApplyIntent> {
        self.begin_device_hardware_apply_for_mode(ticket, LedgerMode::Authoritative)
    }

    pub(in super::super) fn begin_device_hardware_apply_in_candidate(
        &mut self,
        ticket: DevicePreparationTicket,
    ) -> LinearResult<DevicePreparationTicket, DeviceApplyIntent> {
        self.begin_device_hardware_apply_for_mode(ticket, LedgerMode::NonAuthoritativeCandidate)
    }

    fn begin_device_hardware_apply_for_mode(
        &mut self,
        ticket: DevicePreparationTicket,
        expected_mode: LedgerMode,
    ) -> LinearResult<DevicePreparationTicket, DeviceApplyIntent> {
        linear_apply(ticket, |ticket| {
            require_device_ledger_mode(self, expected_mode)?;
            let stamp = ticket.0;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_device_bearer(scope, registry_instance, &stamp)?;
            let record = scope.devices.get(stamp.identity.preparation_id).unwrap();
            if record.phase != DevicePhase::Reserved {
                return Err(InfrastructureError::ExactReplay);
            }
            let apply_generation = record
                .apply_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?;
            let (apply_nonce, next_nonce) = preview_nonce(scope)?;
            let next_revision = preview_revision(scope)?;
            let record = scope
                .devices
                .get_mut(stamp.identity.preparation_id)
                .unwrap();
            record.apply_generation = apply_generation;
            record.credit_ownership = DeviceCreditOwnership::Retained;
            record.phase = DevicePhase::Applying {
                apply_generation,
                apply_nonce,
            };
            scope.next_nonce = next_nonce;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::DeviceApplying,
                stamp.identity.preparation_id,
                stamp.identity.generation,
            );
            Ok(DeviceApplyIntent {
                preparation: stamp,
                apply_generation,
                apply_nonce,
            })
        })
    }

    pub(in super::super) fn acknowledge_device_apply_rollback(
        &mut self,
        intent: DeviceApplyIntent,
        rollback: DeviceRollbackReceipt,
    ) -> LinearResult<DeviceApplyIntent, DeviceRollbackReceipt> {
        self.acknowledge_device_apply_rollback_for_mode(intent, rollback, LedgerMode::Authoritative)
            .map(|(_, receipt)| receipt)
    }

    pub(in super::super) fn acknowledge_device_apply_rollback_in_candidate(
        &mut self,
        intent: DeviceApplyIntent,
        rollback: DeviceRollbackReceipt,
    ) -> LinearResult<DeviceApplyIntent, (DeviceApplyIntent, DeviceRollbackReceipt)> {
        self.acknowledge_device_apply_rollback_for_mode(
            intent,
            rollback,
            LedgerMode::NonAuthoritativeCandidate,
        )
    }

    fn acknowledge_device_apply_rollback_for_mode(
        &mut self,
        intent: DeviceApplyIntent,
        rollback: DeviceRollbackReceipt,
        expected_mode: LedgerMode,
    ) -> LinearResult<DeviceApplyIntent, (DeviceApplyIntent, DeviceRollbackReceipt)> {
        linear_apply(intent, |intent| {
            require_device_ledger_mode(self, expected_mode)?;
            let stamp = intent.preparation;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_device_bearer(scope, registry_instance, &stamp)?;
            validate_device_applying(scope, intent)?;
            let coordinates = stamp.identity;
            if rollback.owned_device != coordinates.owned_device
                || rollback.queue != coordinates.queue
                || rollback.device_generation != coordinates.device_generation
                || rollback.operation_digest != coordinates.operation_digest
                || rollback.actor_slot != coordinates.actor_slot
                || rollback.actor_generation != coordinates.actor_generation
                || rollback.rollback_receipt_digest == 0
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            finish_device(
                scope,
                stamp,
                DevicePhase::Cancelled {
                    rollback: Some(rollback),
                },
            )?;
            scope.events.push(
                InfrastructureEventKind::DeviceRolledBack,
                coordinates.preparation_id,
                coordinates.generation,
            );
            Ok((
                DeviceApplyIntent {
                    preparation: intent.preparation,
                    apply_generation: intent.apply_generation,
                    apply_nonce: intent.apply_nonce,
                },
                rollback,
            ))
        })
    }

    pub(in super::super) fn acknowledge_device_prepared(
        &mut self,
        intent: DeviceApplyIntent,
        receipt: DeviceHardwareReceipt,
    ) -> LinearResult<DeviceApplyIntent, DevicePreparationTicket> {
        self.acknowledge_device_prepared_for_mode(intent, receipt, LedgerMode::Authoritative)
            .map(DeviceApplyIntent::into_preparation_ticket)
    }

    pub(in super::super) fn acknowledge_device_prepared_in_candidate(
        &mut self,
        intent: DeviceApplyIntent,
        receipt: DeviceHardwareReceipt,
    ) -> LinearResult<DeviceApplyIntent, DeviceApplyIntent> {
        self.acknowledge_device_prepared_for_mode(
            intent,
            receipt,
            LedgerMode::NonAuthoritativeCandidate,
        )
    }

    fn acknowledge_device_prepared_for_mode(
        &mut self,
        intent: DeviceApplyIntent,
        receipt: DeviceHardwareReceipt,
        expected_mode: LedgerMode,
    ) -> LinearResult<DeviceApplyIntent, DeviceApplyIntent> {
        linear_apply(intent, |intent| {
            require_device_ledger_mode(self, expected_mode)?;
            let stamp = intent.preparation;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_device_bearer(scope, registry_instance, &stamp)?;
            validate_device_applying(scope, intent)?;
            let coordinates = stamp.identity;
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
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            let next_revision = preview_revision(scope)?;
            let owner = PreparedOwner {
                owned_device: receipt.owned_device,
                device: receipt.device,
                operation_digest: receipt.operation_digest,
                actor_slot: receipt.actor_slot,
                actor_generation: receipt.actor_generation,
                hardware_receipt_digest: receipt.hardware_receipt_digest,
            };
            scope
                .devices
                .get_mut(coordinates.preparation_id)
                .unwrap()
                .phase = DevicePhase::PreparedRetained { owner };
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::DevicePreparedRetained,
                coordinates.preparation_id,
                coordinates.generation,
            );
            Ok(DeviceApplyIntent {
                preparation: intent.preparation,
                apply_generation: intent.apply_generation,
                apply_nonce: intent.apply_nonce,
            })
        })
    }

    pub(in super::super) fn prepare_device_materialization(
        &self,
        ticket: DevicePreparationTicket,
    ) -> LinearResult<DevicePreparationTicket, DeviceMaterializationPlan> {
        linear_apply(ticket, |ticket| {
            self.require_authoritative()?;
            let stamp = ticket.0;
            let scope = self.scope(stamp.root.scope)?;
            validate_device_bearer(scope, self.registry_instance, &stamp)?;
            let owner = match scope
                .devices
                .get(stamp.identity.preparation_id)
                .unwrap()
                .phase
            {
                DevicePhase::PreparedRetained { owner } => owner,
                _ => return Err(InfrastructureError::InvalidState),
            };
            Ok(DeviceMaterializationPlan {
                preparation: stamp,
                owner,
                base_revision: scope.revision,
            })
        })
    }

    /// Candidate-only half of the Registry transaction which installs the
    /// business-effect cohort and transfers the prepared owner in one swap.
    pub(in super::super) fn materialize_device_in_candidate(
        &mut self,
        plan: DeviceMaterializationPlan,
        cohort: DeviceCohortIdentity,
    ) -> LinearResult<DeviceMaterializationPlan, DeviceMaterializationPlan> {
        linear_apply(plan, |plan| {
            if self.mode != LedgerMode::NonAuthoritativeCandidate {
                return Err(InfrastructureError::CandidateHasNoAuthority);
            }
            cohort.validate()?;
            let stamp = plan.preparation;
            let scope = self.scope_mut(stamp.root.scope)?;
            let record = scope
                .devices
                .get(stamp.identity.preparation_id)
                .ok_or(InfrastructureError::UnknownObligation)?;
            if scope.revision != plan.base_revision
                || record.stamp != stamp
                || record.phase != (DevicePhase::PreparedRetained { owner: plan.owner })
            {
                return Err(InfrastructureError::StaleClaim);
            }
            let next_queue_slots = scope
                .live
                .queue_slots
                .checked_sub(DEVICE_QUEUE_SLOTS)
                .ok_or(InfrastructureError::Invariant("queue slot underflow"))?;
            let next_pinned_pages = scope
                .live
                .pinned_pages
                .checked_sub(DEVICE_PINNED_PAGES)
                .ok_or(InfrastructureError::Invariant("pinned-page underflow"))?;
            let next_dma_mappings = scope
                .live
                .dma_mappings
                .checked_sub(DEVICE_DMA_MAPPINGS)
                .ok_or(InfrastructureError::Invariant("DMA-mapping underflow"))?;
            let next_revision = preview_revision(scope)?;
            let record = scope
                .devices
                .get_mut(stamp.identity.preparation_id)
                .unwrap();
            record.credit_ownership = DeviceCreditOwnership::Transferred;
            record.phase = DevicePhase::Materialized {
                owner: plan.owner,
                cohort,
                preparation_credits_transferred: true,
            };
            scope.live.queue_slots = next_queue_slots;
            scope.live.pinned_pages = next_pinned_pages;
            scope.live.dma_mappings = next_dma_mappings;
            scope.revision = next_revision;
            scope.events.push(
                InfrastructureEventKind::DeviceMaterialized,
                stamp.identity.preparation_id,
                stamp.identity.generation,
            );
            Ok(DeviceMaterializationPlan {
                preparation: plan.preparation,
                owner: plan.owner,
                base_revision: plan.base_revision,
            })
        })
    }

    /// Mints the linear materialized successor only from the authoritative
    /// record after the containing Registry candidate has been installed.
    /// Failure returns the exact preparation plan so the outer Registry can
    /// restore its pre-install snapshot without losing authority.
    pub(in super::super) fn mint_materialized_device_ticket_after_install(
        &self,
        plan: DeviceMaterializationPlan,
        cohort: DeviceCohortIdentity,
    ) -> LinearResult<DeviceMaterializationPlan, MaterializedDeviceTicket> {
        linear_apply(plan, |plan| {
            self.require_authoritative()?;
            let stamp = plan.preparation;
            let scope = self.scope(stamp.root.scope)?;
            validate_device_bearer(scope, self.registry_instance, &stamp)?;
            let record = scope
                .devices
                .get(stamp.identity.preparation_id)
                .ok_or(InfrastructureError::UnknownObligation)?;
            if record.credit_ownership != DeviceCreditOwnership::Transferred
                || record.phase
                    != (DevicePhase::Materialized {
                        owner: plan.owner,
                        cohort,
                        preparation_credits_transferred: true,
                    })
            {
                return Err(InfrastructureError::StaleClaim);
            }
            Ok(MaterializedDeviceTicket {
                preparation: plan.preparation,
                owner: plan.owner,
                cohort,
            })
        })
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
                                | DevicePhase::Cancelled { .. } => None,
                            };
                            (Some(owner), cohort)
                        }
                        DevicePhase::Reserved
                        | DevicePhase::Applying { .. }
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
            let stamp = ticket.preparation;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_device_bearer(scope, registry_instance, &stamp)?;
            let (owner, cohort) = match scope
                .devices
                .get(stamp.identity.preparation_id)
                .unwrap()
                .phase
            {
                DevicePhase::Materialized {
                    owner,
                    cohort,
                    preparation_credits_transferred: true,
                } => (owner, cohort),
                _ => return Err(InfrastructureError::InvalidState),
            };
            if owner != ticket.owner || cohort != ticket.cohort {
                return Err(InfrastructureError::StaleClaim);
            }
            let closure = proof.receipt;
            if closure.registry_instance_id != registry_instance
                || closure.scope != stamp.root.scope
                || closure.device != owner.device
                || closure.sequence == 0
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            finish_device(
                scope,
                stamp,
                DevicePhase::Released {
                    owner,
                    cohort: Some(cohort),
                    closure,
                },
            )?;
            Ok(closure)
        })
    }

    pub(in super::super) fn release_unmaterialized_retained_device(
        &mut self,
        ticket: DevicePreparationTicket,
        proof: ValidatedDeviceClosureProof,
    ) -> LinearResult<DevicePreparationTicket, RegistryDeviceClosureReceipt> {
        linear_apply(ticket, |ticket| {
            self.require_authoritative()?;
            let stamp = ticket.0;
            let registry_instance = self.registry_instance;
            let scope = self.scope_mut(stamp.root.scope)?;
            validate_device_bearer(scope, registry_instance, &stamp)?;
            let owner = match scope
                .devices
                .get(stamp.identity.preparation_id)
                .unwrap()
                .phase
            {
                DevicePhase::PreparedRetained { owner } => owner,
                _ => return Err(InfrastructureError::InvalidState),
            };
            let closure = proof.receipt;
            if closure.registry_instance_id != registry_instance
                || closure.scope != stamp.root.scope
                || closure.device != owner.device
                || closure.sequence == 0
            {
                return Err(InfrastructureError::InvalidReceipt);
            }
            finish_device(
                scope,
                stamp,
                DevicePhase::Released {
                    owner,
                    cohort: None,
                    closure,
                },
            )?;
            Ok(closure)
        })
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
        let (state, prepared_device, cohort, rollback_receipt, closure_receipt) = match record.phase
        {
            DevicePhase::Reserved => (
                DevicePreparationRecoveryState::Reserved,
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
            ),
            DevicePhase::PreparedRetained { owner } => (
                DevicePreparationRecoveryState::PreparedRetained,
                Some(owner.device),
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
            ),
            DevicePhase::Cancelled { rollback } => (
                DevicePreparationRecoveryState::Cancelled,
                None,
                None,
                rollback,
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
            }),
            DevicePhase::Reserved
            | DevicePhase::Applying { .. }
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
        let scope = self.scope_mut(context.root.scope)?;
        validate_context(scope, registry_instance, context)?;
        let record = scope
            .devices
            .get(preparation_id)
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
        if __cser_core::matches!(
            record.phase,
            DevicePhase::Released { .. } | DevicePhase::Cancelled { .. }
        ) {
            return Err(InfrastructureError::InvalidState);
        }
        let phase = record.phase;
        let next_bearer = record
            .stamp
            .bearer_generation
            .checked_add(1)
            .ok_or(InfrastructureError::CounterOverflow)?;
        let (nonces, next_nonce) = preview_nonces(
            scope,
            usize::from(__cser_core::matches!(phase, DevicePhase::Applying { .. })),
        )?;
        let next_revision = preview_revision(scope)?;
        let index_slot = record.stamp.nonce;
        let apply_generation = if __cser_core::matches!(phase, DevicePhase::Applying { .. }) {
            record
                .apply_generation
                .checked_add(1)
                .ok_or(InfrastructureError::CounterOverflow)?
        } else {
            record.apply_generation
        };
        let next_phase = match phase {
            DevicePhase::Reserved => DevicePhase::Reserved,
            DevicePhase::Applying { .. } => DevicePhase::Applying {
                apply_generation,
                apply_nonce: nonces[0],
            },
            DevicePhase::PreparedRetained { owner } => DevicePhase::PreparedRetained { owner },
            DevicePhase::Materialized {
                owner,
                cohort,
                preparation_credits_transferred,
            } => DevicePhase::Materialized {
                owner,
                cohort,
                preparation_credits_transferred,
            },
            DevicePhase::Released { .. } | DevicePhase::Cancelled { .. } => {
                return Err(InfrastructureError::InvalidState);
            }
        };
        let record = scope.devices.get_mut(preparation_id).unwrap();
        record.stamp.domain = context.domain;
        record.stamp.workload = context.workload;
        record.stamp.bearer_generation = next_bearer;
        record.apply_generation = apply_generation;
        record.phase = next_phase;
        let stamp = record.stamp;
        let index =
            scope
                .reverse_indexes
                .get_mut(index_slot)
                .ok_or(InfrastructureError::Invariant(
                    "missing device reverse index",
                ))?;
        index.binding_epoch = context.domain.binding_epoch;
        scope.next_nonce = next_nonce;
        scope.revision = next_revision;
        Ok(match next_phase {
            DevicePhase::Reserved => DeviceAdoption::Reserved(DevicePreparationTicket(stamp)),
            DevicePhase::Applying { apply_nonce, .. } => {
                DeviceAdoption::ReplayApply(DeviceApplyIntent {
                    preparation: stamp,
                    apply_generation,
                    apply_nonce,
                })
            }
            DevicePhase::PreparedRetained { .. } => {
                DeviceAdoption::Prepared(DevicePreparationTicket(stamp))
            }
            DevicePhase::Materialized { owner, cohort, .. } => {
                DeviceAdoption::Materialized(MaterializedDeviceTicket {
                    preparation: stamp,
                    owner,
                    cohort,
                })
            }
            DevicePhase::Released { .. } | DevicePhase::Cancelled { .. } => {
                return Err(InfrastructureError::Invariant("invalid device adoption"));
            }
        })
    }
}

fn validate_device_applying(
    scope: &ScopeInfrastructure,
    intent: &DeviceApplyIntent,
) -> Result<(), InfrastructureError> {
    let record = scope
        .devices
        .get(intent.preparation.identity.preparation_id)
        .ok_or(InfrastructureError::UnknownObligation)?;
    if record.stamp != intent.preparation
        || record.credit_ownership != DeviceCreditOwnership::Retained
        || record.phase
            != (DevicePhase::Applying {
                apply_generation: intent.apply_generation,
                apply_nonce: intent.apply_nonce,
            })
    {
        return Err(InfrastructureError::StaleClaim);
    }
    Ok(())
}

impl DevicePreparationTicket {
    pub(in super::super) const fn coordinates(&self) -> DeviceReservationCoordinates {
        self.0.identity
    }

    pub(in super::super) const fn scope(&self) -> super::ScopeKey {
        self.0.root.scope
    }

    #[cfg(test)]
    pub(in super::super) const fn duplicate_for_test(&self) -> Self {
        Self(self.0)
    }

    #[cfg(test)]
    pub(in super::super) fn stale_bearer_for_test(&self) -> Self {
        let mut stamp = self.0;
        stamp.bearer_generation = stamp.bearer_generation.checked_add(1).unwrap();
        Self(stamp)
    }
}

impl DeviceApplyIntent {
    pub(in super::super) const fn coordinates(&self) -> DeviceReservationCoordinates {
        self.preparation.identity
    }

    pub(in super::super) const fn scope(&self) -> super::ScopeKey {
        self.preparation.root.scope
    }

    pub(in super::super) fn into_preparation_ticket(self) -> DevicePreparationTicket {
        DevicePreparationTicket(self.preparation)
    }
}

impl DeviceMaterializationPlan {
    pub(in super::super) const fn coordinates(&self) -> DeviceReservationCoordinates {
        self.preparation.identity
    }

    pub(in super::super) const fn scope(&self) -> super::ScopeKey {
        self.preparation.root.scope
    }

    pub(in super::super) const fn parent_effect(&self) -> EffectKey {
        match self.preparation.parent {
            ParentStamp::Effect(parent) => parent,
            _ => __cser_core::unreachable!(),
        }
    }

    pub(in super::super) const fn prepared_device(&self) -> super::DeviceEnvelope {
        self.owner.device
    }

    pub(in super::super) const fn prepared_identity(&self) -> PreparedDeviceIdentity {
        PreparedDeviceIdentity {
            preparation_id: self.preparation.identity.preparation_id,
            preparation_generation: self.preparation.identity.generation,
            owned_device: self.owner.owned_device,
            device: self.owner.device,
            operation_digest: self.owner.operation_digest,
            actor_slot: self.owner.actor_slot,
            actor_generation: self.owner.actor_generation,
            hardware_receipt_digest: self.owner.hardware_receipt_digest,
        }
    }

    pub(in super::super) fn into_preparation_ticket(self) -> DevicePreparationTicket {
        DevicePreparationTicket(self.preparation)
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

fn finish_device(
    scope: &mut ScopeInfrastructure,
    stamp: BearerStamp<DeviceReservationCoordinates>,
    terminal: DevicePhase,
) -> Result<(), InfrastructureError> {
    let current = scope
        .devices
        .get(stamp.identity.preparation_id)
        .ok_or(InfrastructureError::UnknownObligation)?
        .phase;
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
    let credit_ownership = match terminal {
        DevicePhase::Released {
            cohort: Some(_), ..
        } => DeviceCreditOwnership::Transferred,
        DevicePhase::Released { cohort: None, .. } | DevicePhase::Cancelled { .. } => {
            DeviceCreditOwnership::Released
        }
        _ => {
            return Err(InfrastructureError::Invariant(
                "nonterminal device finish phase",
            ));
        }
    };
    let record = scope
        .devices
        .get_mut(stamp.identity.preparation_id)
        .unwrap();
    record.credit_ownership = credit_ownership;
    record.phase = terminal;
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
        if __cser_core::matches!(terminal, DevicePhase::Released { .. }) {
            InfrastructureEventKind::DeviceReleased
        } else {
            InfrastructureEventKind::DeviceCancelled
        },
        stamp.identity.preparation_id,
        stamp.identity.generation,
    );
    Ok(())
}

pub(super) fn device_phase_live(phase: DevicePhase) -> bool {
    !__cser_core::matches!(
        phase,
        DevicePhase::Released { .. } | DevicePhase::Cancelled { .. }
    )
}
