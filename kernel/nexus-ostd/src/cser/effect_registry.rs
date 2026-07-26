// SPDX-License-Identifier: MPL-2.0

//! Domain-neutral CSER effect bookkeeping for Linux-personality slices.
//!
//! The registry deliberately stores no futex queue, readiness source, pager
//! frame, or device payload.  Those typed indexes belong to the runtime layer.
//! It owns only immutable operation descriptors, generational identities,
//! scope/binding gates, reverse indexes, credits, recovery metadata, commit
//! receipts, and the publication ticket that crosses a lock boundary.

#![allow(dead_code)]

extern crate alloc as __cser_alloc;
extern crate core as __cser_core;

use __cser_alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use __cser_core::sync::atomic::{AtomicU64, Ordering};

use cser_transition_gates::handoff::{
    FreezeContext as KernelFreezeContext, FreezeReceipt as KernelFreezeReceipt,
    HandoffAdmissionGate, HandoffGateError, OwnershipDecision, OwnershipDecisionReceipt,
    PrepareIntent,
};
use sha2::{Digest, Sha256};

#[path = "effect_registry/root_lanes.rs"]
mod root_lanes;

#[path = "effect_registry/runtime_causal.rs"]
pub(crate) mod runtime_causal;

#[path = "effect_registry/runtime_task.rs"]
pub(crate) mod runtime_task;

#[path = "effect_registry/runtime_service_task.rs"]
pub(crate) mod runtime_service_task;

#[path = "effect_registry/evidence.rs"]
pub(crate) mod evidence;

#[path = "infrastructure/mod.rs"]
mod infrastructure;

pub(crate) use infrastructure::{
    DeviceApplyIntent, DevicePreparationRecoveryProjection, DevicePreparationTicket,
    DeviceReservationCoordinates, MaterializedDeviceTicket, PreparedDeviceIdentity,
    PreparedDeviceTicket,
};

/// Provider-neutral lineage of a verified hardware-preparation rollback.
///
/// The Registry never imports a concrete device facade. A narrow kernel
/// adapter maps its nonconstructible receipt onto this read-only vocabulary,
/// while the Registry independently validates every presented coordinate.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum DeviceRollbackEvidenceKind {
    UnexposedFailure,
    PreparedCancellation,
}

pub(crate) trait DevicePreparedReceiptView {
    fn preparation_owner_id(&self) -> u64;
    fn preparation_sequence(&self) -> u64;
    fn device_session(&self) -> u64;
    fn packed_device_bdf(&self) -> u64;
    fn queue(&self) -> u16;
    fn descriptor_token(&self) -> u16;
    fn device_generation(&self) -> u64;
    fn dma_owner_count(&self) -> usize;
    fn dma_share_count(&self) -> usize;
    fn transport_claim_count(&self) -> usize;
    fn receipt_digest(&self) -> u64;
}

pub(crate) trait DeviceRollbackReceiptView {
    fn preparation_owner_id(&self) -> u64;
    fn preparation_sequence(&self) -> u64;
    fn packed_device_bdf(&self) -> u64;
    fn attempt_device_generation(&self) -> u64;
    fn quiescent_device_generation(&self) -> u64;
    fn kind(&self) -> DeviceRollbackEvidenceKind;
    fn request_packed_device_bdf(&self) -> Option<u64>;
    fn request_queue(&self) -> Option<u16>;
    fn request_device_generation(&self) -> Option<u64>;
    fn receipt_digest(&self) -> u64;
}

pub(crate) trait DeviceIndeterminateReceiptView {
    fn preparation_owner_id(&self) -> u64;
    fn preparation_sequence(&self) -> u64;
    fn packed_device_bdf(&self) -> u64;
    fn attempt_device_generation(&self) -> u64;
    fn observation_digest(&self) -> u64;
}

pub(crate) trait DeviceClosureReceiptView {
    fn preparation_owner_id(&self) -> u64;
    fn preparation_sequence(&self) -> u64;
    fn device_session(&self) -> u64;
    fn packed_device_bdf(&self) -> u64;
    fn queue(&self) -> u16;
    fn descriptor_token(&self) -> u16;
    fn device_generation(&self) -> u64;
    fn completed_pages(&self) -> usize;
}

static NEXT_REGISTRY_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

fn fault_cohort_digest(cohort: Option<&BTreeSet<EffectKey>>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.fault-business-cohort.v1\0");
    for effect in cohort.into_iter().flatten() {
        hasher.update(effect.id().to_le_bytes());
        hasher.update(effect.generation().to_le_bytes());
    }
    hasher.finalize().into()
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::Ord,
    __cser_core::cmp::PartialEq,
    __cser_core::cmp::PartialOrd,
)]
pub(crate) struct ScopeKey {
    id: u64,
    generation: u64,
}

impl ScopeKey {
    pub(crate) const fn new(id: u64, generation: u64) -> Self {
        Self { id, generation }
    }

    pub(crate) const fn id(self) -> u64 {
        self.id
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::Ord,
    __cser_core::cmp::PartialEq,
    __cser_core::cmp::PartialOrd,
)]
pub(crate) struct TaskKey {
    id: u64,
    generation: u64,
}

/// Identifies one independently restartable service domain inside a root
/// authority scope. Domain zero is reserved for the legacy single-binding API;
/// production-identity successors use explicit nonzero domains.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::Ord,
    __cser_core::cmp::PartialEq,
    __cser_core::cmp::PartialOrd,
)]
pub(crate) struct DomainKey(u32);

impl DomainKey {
    pub(crate) const LEGACY: Self = Self(0);

    pub(crate) const fn new(value: u32) -> Self {
        Self(value)
    }

    pub(crate) const fn value(self) -> u32 {
        self.0
    }
}

impl TaskKey {
    pub(crate) const fn new(id: u64, generation: u64) -> Self {
        Self { id, generation }
    }

    pub(crate) const fn id(self) -> u64 {
        self.id
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::Ord,
    __cser_core::cmp::PartialEq,
    __cser_core::cmp::PartialOrd,
)]
pub(crate) struct ResourceKey {
    namespace: u32,
    id: u64,
    generation: u64,
}

impl ResourceKey {
    pub(crate) const fn new(namespace: u32, id: u64, generation: u64) -> Self {
        Self {
            namespace,
            id,
            generation,
        }
    }

    pub(crate) const fn namespace(self) -> u32 {
        self.namespace
    }

    pub(crate) const fn id(self) -> u64 {
        self.id
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::Ord,
    __cser_core::cmp::PartialEq,
    __cser_core::cmp::PartialOrd,
)]
pub(crate) struct EffectKey {
    id: u64,
    generation: u64,
}

impl EffectKey {
    pub(crate) const fn new(id: u64, generation: u64) -> Self {
        Self { id, generation }
    }

    pub(crate) const fn id(self) -> u64 {
        self.id
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::Ord,
    __cser_core::cmp::PartialEq,
    __cser_core::cmp::PartialOrd,
)]
pub(crate) struct OperationClass(u32);

impl OperationClass {
    pub(crate) const fn new(value: u32) -> Self {
        Self(value)
    }

    pub(crate) const fn value(self) -> u32 {
        self.0
    }
}

/// Immutable hardware identity captured before a device-backed effect can be
/// prepared or published.
///
/// This is descriptive identity owned by the production registry, not a
/// second authority namespace.  The opaque [`PortalHandle`] and a
/// [`KernelRootAuthority`] still authorize every transition.  In particular,
/// a device adapter cannot replace the workload effect by presenting matching
/// integers from another registry, root, or session.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::Ord,
    __cser_core::cmp::PartialEq,
    __cser_core::cmp::PartialOrd,
)]
pub(crate) struct DeviceEnvelope {
    device_session: u64,
    queue: u16,
    descriptor_token: u16,
    device_generation: u64,
}

impl DeviceEnvelope {
    pub(crate) fn new(
        device_session: u64,
        queue: u16,
        descriptor_token: u16,
        device_generation: u64,
    ) -> Result<Self, RegistryError> {
        if device_session == 0 || device_generation == 0 {
            return Err(RegistryError::InvalidDeviceEnvelope);
        }
        Ok(Self {
            device_session,
            queue,
            descriptor_token,
            device_generation,
        })
    }

    pub(crate) const fn device_session(self) -> u64 {
        self.device_session
    }

    pub(crate) const fn queue(self) -> u16 {
        self.queue
    }

    pub(crate) const fn descriptor_token(self) -> u16 {
        self.descriptor_token
    }

    pub(crate) const fn device_generation(self) -> u64 {
        self.device_generation
    }

    fn validate(self) -> Result<(), RegistryError> {
        if self.device_session == 0 || self.device_generation == 0 {
            return Err(RegistryError::InvalidDeviceEnvelope);
        }
        Ok(())
    }

    fn same_device_except_generation(self, other: Self) -> bool {
        self.device_session == other.device_session
            && self.queue == other.queue
            && self.descriptor_token == other.descriptor_token
    }

    fn next_generation(self) -> Result<Self, RegistryError> {
        Ok(Self {
            device_generation: self
                .device_generation
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?,
            ..self
        })
    }
}

/// A kernel-owned snapshot of the Linux syscall number and all six arguments.
///
/// The descriptor is copied out for inspection but has no mutating API.  A
/// portal operation presents an opaque [`PortalHandle`], never a rewritten set
/// of syscall argument registers.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct SyscallDescriptor {
    number: usize,
    arguments: [usize; 6],
}

impl SyscallDescriptor {
    pub(crate) const fn new(number: usize, arguments: [usize; 6]) -> Self {
        Self { number, arguments }
    }

    pub(crate) const fn number(self) -> usize {
        self.number
    }

    pub(crate) const fn argument(self, index: usize) -> usize {
        self.arguments[index]
    }

    pub(crate) const fn arguments(self) -> [usize; 6] {
        self.arguments
    }

    pub(crate) fn digest(self) -> u64 {
        let mut digest = 0xcbf2_9ce4_8422_2325_u64;
        digest = (digest ^ self.number as u64).wrapping_mul(0x0000_0100_0000_01b3);
        let mut index = 0;
        while index < self.arguments.len() {
            digest = (digest ^ self.arguments[index] as u64).wrapping_mul(0x0000_0100_0000_01b3);
            index += 1;
        }
        digest
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::Ord,
    __cser_core::cmp::PartialEq,
    __cser_core::cmp::PartialOrd,
)]
pub(crate) struct CreditClass(u16);

impl CreditClass {
    pub(crate) const fn new(value: u16) -> Self {
        Self(value)
    }

    pub(crate) const fn value(self) -> u16 {
        self.0
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CreditLimit {
    class: CreditClass,
    units: u64,
}

impl CreditLimit {
    pub(crate) const fn new(class: CreditClass, units: u64) -> Self {
        Self { class, units }
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CreditCharge {
    class: CreditClass,
    units: u64,
}

impl CreditCharge {
    pub(crate) const fn new(class: CreditClass, units: u64) -> Self {
        Self { class, units }
    }

    pub(crate) const fn class(self) -> CreditClass {
        self.class
    }

    pub(crate) const fn units(self) -> u64 {
        self.units
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct CreditBalance {
    capacity: u64,
    free: u64,
    held: u64,
    committed: u64,
    retained: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct CreditLedger {
    balances: BTreeMap<CreditClass, CreditBalance>,
}

impl CreditLedger {
    fn new(limits: &[CreditLimit]) -> Result<Self, RegistryError> {
        let mut balances = BTreeMap::new();
        for limit in limits {
            if limit.units == 0 || balances.contains_key(&limit.class) {
                return Err(RegistryError::InvalidCreditConfiguration);
            }
            balances.insert(
                limit.class,
                CreditBalance {
                    capacity: limit.units,
                    free: limit.units,
                    held: 0,
                    committed: 0,
                    retained: 0,
                },
            );
        }
        Ok(Self { balances })
    }

    fn reserve(&mut self, charges: &[CreditCharge]) -> Result<(), RegistryError> {
        for charge in charges {
            let balance = self
                .balances
                .get(&charge.class)
                .ok_or(RegistryError::UnknownCreditClass)?;
            if charge.units == 0 || balance.free < charge.units {
                return Err(RegistryError::CreditExhausted);
            }
        }
        for charge in charges {
            let balance = self.balances.get_mut(&charge.class).unwrap();
            balance.free -= charge.units;
            balance.held = balance
                .held
                .checked_add(charge.units)
                .ok_or(RegistryError::CounterOverflow)?;
        }
        Ok(())
    }

    fn commit(&mut self, charges: &[CreditCharge]) -> Result<(), RegistryError> {
        self.validate_commit(charges)?;
        self.commit_validated(charges);
        Ok(())
    }

    fn validate_commit(&self, charges: &[CreditCharge]) -> Result<(), RegistryError> {
        for charge in charges {
            let balance = self
                .balances
                .get(&charge.class)
                .ok_or(RegistryError::UnknownCreditClass)?;
            if charge.units == 0 || balance.held < charge.units {
                return Err(RegistryError::InvalidState);
            }
            balance
                .committed
                .checked_add(charge.units)
                .ok_or(RegistryError::CounterOverflow)?;
        }
        Ok(())
    }

    fn commit_validated(&mut self, charges: &[CreditCharge]) {
        for charge in charges {
            let balance = self.balances.get_mut(&charge.class).unwrap();
            balance.held -= charge.units;
            balance.committed = balance
                .committed
                .checked_add(charge.units)
                .expect("validated committed-credit addition cannot overflow");
        }
    }

    fn validate_retain(
        &self,
        charges: &[CreditCharge],
        from: CreditState,
    ) -> Result<(), RegistryError> {
        for charge in charges {
            let balance = self
                .balances
                .get(&charge.class)
                .ok_or(RegistryError::UnknownCreditClass)?;
            let owned = match from {
                CreditState::Held => balance.held,
                CreditState::Committed => balance.committed,
                CreditState::Retained | CreditState::Released => {
                    return Err(RegistryError::InvalidState);
                }
            };
            if charge.units == 0 || owned < charge.units {
                return Err(RegistryError::InvalidState);
            }
            balance
                .retained
                .checked_add(charge.units)
                .ok_or(RegistryError::CounterOverflow)?;
        }
        Ok(())
    }

    fn retain_validated(&mut self, charges: &[CreditCharge], from: CreditState) {
        for charge in charges {
            let balance = self.balances.get_mut(&charge.class).unwrap();
            match from {
                CreditState::Held => balance.held -= charge.units,
                CreditState::Committed => balance.committed -= charge.units,
                CreditState::Retained | CreditState::Released => {
                    __cser_core::unreachable!("retention source was prevalidated")
                }
            }
            balance.retained = balance
                .retained
                .checked_add(charge.units)
                .expect("validated retained-credit addition cannot overflow");
        }
    }

    /// Moves one already-retained owner directly into held effect ownership.
    /// `free` is deliberately untouched: device materialization transfers the
    /// exact preparation credits and never releases/re-reserves substitutes.
    fn transfer_retained_to_held(&mut self, charges: &[CreditCharge]) -> Result<(), RegistryError> {
        for charge in charges {
            let balance = self
                .balances
                .get(&charge.class)
                .ok_or(RegistryError::UnknownCreditClass)?;
            if charge.units == 0 || balance.retained < charge.units {
                return Err(RegistryError::InvalidState);
            }
            balance
                .held
                .checked_add(charge.units)
                .ok_or(RegistryError::CounterOverflow)?;
        }
        for charge in charges {
            let balance = self.balances.get_mut(&charge.class).unwrap();
            balance.retained -= charge.units;
            balance.held = balance
                .held
                .checked_add(charge.units)
                .expect("validated retained-to-held transfer cannot overflow");
        }
        Ok(())
    }

    fn release(
        &mut self,
        charges: &[CreditCharge],
        state: CreditState,
    ) -> Result<(), RegistryError> {
        self.validate_release(charges, state)?;
        self.release_validated(charges, state);
        Ok(())
    }

    fn validate_release(
        &self,
        charges: &[CreditCharge],
        state: CreditState,
    ) -> Result<(), RegistryError> {
        for (index, charge) in charges.iter().enumerate() {
            if charges[..index]
                .iter()
                .any(|previous| previous.class == charge.class)
            {
                continue;
            }
            let balance = self
                .balances
                .get(&charge.class)
                .ok_or(RegistryError::UnknownCreditClass)?;
            let units = charges[index..]
                .iter()
                .filter(|candidate| candidate.class == charge.class)
                .try_fold(0_u64, |total, candidate| total.checked_add(candidate.units))
                .ok_or(RegistryError::CounterOverflow)?;
            let owned = match state {
                CreditState::Held => balance.held,
                CreditState::Committed => balance.committed,
                CreditState::Retained => balance.retained,
                CreditState::Released => return Err(RegistryError::InvalidState),
            };
            if owned < units {
                return Err(RegistryError::InvalidState);
            }
            let free = balance
                .free
                .checked_add(units)
                .ok_or(RegistryError::CounterOverflow)?;
            if free > balance.capacity {
                return Err(RegistryError::InvalidState);
            }
        }
        Ok(())
    }

    fn release_validated(&mut self, charges: &[CreditCharge], state: CreditState) {
        for charge in charges {
            let balance = self.balances.get_mut(&charge.class).unwrap();
            match state {
                CreditState::Held => balance.held -= charge.units,
                CreditState::Committed => balance.committed -= charge.units,
                CreditState::Retained => balance.retained -= charge.units,
                CreditState::Released => __cser_core::unreachable!(),
            }
            balance.free = balance
                .free
                .checked_add(charge.units)
                .expect("release capacity was validated");
        }
    }

    fn is_idle_after_validated_release(
        &self,
        charges: &[CreditCharge],
        state: CreditState,
    ) -> bool {
        self.balances.iter().all(|(class, balance)| {
            let released = charges
                .iter()
                .filter(|charge| charge.class == *class)
                .try_fold(0_u64, |total, charge| total.checked_add(charge.units));
            let Some(released) = released else {
                return false;
            };
            let held = balance.held
                - if state == CreditState::Held {
                    released
                } else {
                    0
                };
            let committed = balance.committed
                - if state == CreditState::Committed {
                    released
                } else {
                    0
                };
            let retained = balance.retained
                - if state == CreditState::Retained {
                    released
                } else {
                    0
                };
            balance.free.checked_add(released) == Some(balance.capacity)
                && held == 0
                && committed == 0
                && retained == 0
        })
    }

    fn is_idle(&self) -> bool {
        self.balances.values().all(|balance| {
            balance.free == balance.capacity
                && balance.held == 0
                && balance.committed == 0
                && balance.retained == 0
        })
    }

    fn totals(&self) -> CreditTotals {
        self.balances.values().fold(
            CreditTotals {
                capacity: 0,
                free: 0,
                held: 0,
                committed: 0,
                retained: 0,
            },
            |mut totals, balance| {
                totals.capacity += balance.capacity;
                totals.free += balance.free;
                totals.held += balance.held;
                totals.committed += balance.committed;
                totals.retained += balance.retained;
                totals
            },
        )
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CreditTotals {
    pub(crate) capacity: u64,
    pub(crate) free: u64,
    pub(crate) held: u64,
    pub(crate) committed: u64,
    pub(crate) retained: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
enum CreditState {
    Held,
    Committed,
    Retained,
    Released,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum ScopePhase {
    Active,
    Closing,
    Revoked,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum TerminalOutcome {
    Completed,
    IndeterminateAfterReset,
    Aborted,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum EffectPhase {
    Registered,
    Prepared,
    Committed,
    Terminal(TerminalOutcome),
}

impl EffectPhase {
    pub(crate) const fn is_terminal(self) -> bool {
        __cser_core::matches!(self, Self::Terminal(_))
    }
}

/// Provider-neutral classification of one canonical post-commit outcome.
///
/// This type deliberately does not depend on a transport ABI.  Kernel portal
/// adapters translate their wire enum at the boundary and store the resulting
/// record here so the Registry, rather than an adapter-local phase machine,
/// remains authoritative for whether an outcome exists.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum EffectOutcomeClass {
    Data,
    Error,
    Indeterminate,
}

/// Canonical backend outcome attached exactly once after commit.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct EffectOutcomeRecord {
    class: EffectOutcomeClass,
    result: i64,
    digest: [u8; 32],
}

impl EffectOutcomeRecord {
    pub(crate) fn new(
        class: EffectOutcomeClass,
        result: i64,
        digest: [u8; 32],
    ) -> Result<Self, RegistryError> {
        if digest.iter().all(|byte| *byte == 0) {
            return Err(RegistryError::InvalidState);
        }
        Ok(Self {
            class,
            result,
            digest,
        })
    }

    pub(crate) const fn class(self) -> EffectOutcomeClass {
        self.class
    }

    pub(crate) const fn result(self) -> i64 {
        self.result
    }

    pub(crate) const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum PublicationMode {
    None,
    Required,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct EffectIdentity {
    effect: EffectKey,
    scope: ScopeKey,
    domain: DomainKey,
    parent: Option<EffectKey>,
    task: TaskKey,
    operation: OperationClass,
    authority_epoch: u64,
    origin_binding_epoch: u64,
    binding_epoch: u64,
    device: Option<DeviceEnvelope>,
    resources: BTreeSet<ResourceKey>,
}

impl EffectIdentity {
    pub(crate) const fn effect(&self) -> EffectKey {
        self.effect
    }

    pub(crate) const fn scope(&self) -> ScopeKey {
        self.scope
    }

    pub(crate) const fn domain(&self) -> DomainKey {
        self.domain
    }

    pub(crate) const fn parent(&self) -> Option<EffectKey> {
        self.parent
    }

    pub(crate) const fn task(&self) -> TaskKey {
        self.task
    }

    pub(crate) const fn operation(&self) -> OperationClass {
        self.operation
    }

    pub(crate) const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub(crate) const fn binding_epoch(&self) -> u64 {
        self.binding_epoch
    }

    pub(crate) const fn origin_binding_epoch(&self) -> u64 {
        self.origin_binding_epoch
    }

    pub(crate) const fn device_envelope(&self) -> Option<DeviceEnvelope> {
        self.device
    }

    pub(crate) fn resources(&self) -> &BTreeSet<ResourceKey> {
        &self.resources
    }
}

/// Opaque authority presented by a user-space service.
///
/// Fields are intentionally private.  A future portal ABI may serialize the
/// values, but callers cannot construct a valid handle through this module.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct PortalHandle {
    scope: ScopeKey,
    effect: EffectKey,
    domain: DomainKey,
    authority_epoch: u64,
    binding_epoch: u64,
    nonce: u64,
}

impl PortalHandle {
    pub(crate) const fn effect(self) -> EffectKey {
        self.effect
    }

    pub(crate) const fn scope(self) -> ScopeKey {
        self.scope
    }

    pub(crate) const fn domain(self) -> DomainKey {
        self.domain
    }

    pub(crate) const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    pub(crate) const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CommitMetadata {
    result: i64,
    domain_revision: u64,
}

impl CommitMetadata {
    pub(crate) const fn new(result: i64, domain_revision: u64) -> Self {
        Self {
            result,
            domain_revision,
        }
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CommitReceipt {
    registry_instance_id: u64,
    effect: EffectKey,
    scope: ScopeKey,
    authority_epoch: u64,
    binding_epoch: u64,
    sequence: u64,
    result: i64,
    domain_revision: u64,
    descriptor_digest: u64,
}

impl CommitReceipt {
    pub(crate) const fn effect(&self) -> EffectKey {
        self.effect
    }

    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) const fn result(&self) -> i64 {
        self.result
    }

    pub(crate) const fn domain_revision(&self) -> u64 {
        self.domain_revision
    }

    /// Preserves every semantic receipt field while removing only the
    /// process-local registry-allocation ordinal from a diagnostic projection.
    pub(crate) fn failure_atomic_projection(&self) -> Self {
        let mut projected = self.clone();
        projected.registry_instance_id = 1;
        projected
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum CommitOutcome {
    Applied(CommitReceipt),
    AlreadyCommitted(CommitReceipt),
}

/// Opaque kernel authority for one active root.
///
/// Domain supervisors cannot construct this value.  It permits a single
/// root-gated device publication to validate effects from several service
/// domains without pretending that one domain supervisor owns another
/// domain's portal handle.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct KernelRootAuthority {
    registry_instance_id: u64,
    scope: ScopeKey,
    authority_epoch: u64,
    owner: TaskKey,
}

impl KernelRootAuthority {
    pub(crate) const fn scope(self) -> ScopeKey {
        self.scope
    }

    pub(crate) const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }
}

/// Receipt for one root-wide publication batch whose hardware commit point is
/// supplied by the caller's infallible closure.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeviceBatchCommitReceipt {
    registry_instance_id: u64,
    scope: ScopeKey,
    authority_epoch: u64,
    batch_sequence: u64,
    device: DeviceEnvelope,
    commits: Vec<CommitReceipt>,
    device_effects: Vec<EffectKey>,
}

/// Freezes the exact live root cohort that is permitted to cross one device
/// publication point. Registration may continue while a scope is merely
/// device-backed, but no generic commit is permitted once any device effect
/// exists, and no registration is permitted after this receipt is minted.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeviceBatchEnrollmentReceipt {
    registry_instance_id: u64,
    scope: ScopeKey,
    authority_epoch: u64,
    enrollment_sequence: u64,
    device: DeviceEnvelope,
    effects: Vec<EffectKey>,
    cancel_only: bool,
}

impl DeviceBatchEnrollmentReceipt {
    pub(crate) const fn scope(&self) -> ScopeKey {
        self.scope
    }

    pub(crate) const fn enrollment_sequence(&self) -> u64 {
        self.enrollment_sequence
    }

    pub(crate) const fn device(&self) -> DeviceEnvelope {
        self.device
    }

    pub(crate) fn effects(&self) -> &[EffectKey] {
        &self.effects
    }

    pub(crate) const fn cancel_only(&self) -> bool {
        self.cancel_only
    }
}

impl DeviceBatchCommitReceipt {
    pub(crate) const fn registry_instance_id(&self) -> u64 {
        self.registry_instance_id
    }

    pub(crate) const fn scope(&self) -> ScopeKey {
        self.scope
    }

    pub(crate) const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub(crate) const fn batch_sequence(&self) -> u64 {
        self.batch_sequence
    }

    pub(crate) const fn device(&self) -> DeviceEnvelope {
        self.device
    }

    pub(crate) fn commits(&self) -> &[CommitReceipt] {
        &self.commits
    }

    pub(crate) fn device_effects(&self) -> &[EffectKey] {
        &self.device_effects
    }

    pub(crate) fn commit_for(&self, effect: EffectKey) -> Option<&CommitReceipt> {
        self.commits.iter().find(|receipt| receipt.effect == effect)
    }

    pub(crate) fn failure_atomic_projection(&self) -> Self {
        let mut projected = self.clone();
        projected.rewrite_registry_instance(1);
        projected
    }

    fn rewrite_registry_instance(&mut self, registry_instance_id: u64) {
        self.registry_instance_id = registry_instance_id;
        for commit in &mut self.commits {
            commit.registry_instance_id = registry_instance_id;
        }
    }
}

/// A full replay returns the authoritative receipt without executing the
/// publication closure a second time.
#[derive(__cser_core::fmt::Debug)]
pub(crate) enum DeviceBatchCommitOutcome<T> {
    Applied {
        receipt: DeviceBatchCommitReceipt,
        publication: T,
    },
    AlreadyCommitted {
        receipt: DeviceBatchCommitReceipt,
    },
}

impl<T> DeviceBatchCommitOutcome<T> {
    pub(crate) const fn receipt(&self) -> &DeviceBatchCommitReceipt {
        match self {
            Self::Applied { receipt, .. } | Self::AlreadyCommitted { receipt } => receipt,
        }
    }
}

/// Registry-minted identity for one caller-chosen close operation.
///
/// Every field is private: a caller may copy an issued identity for retry, but
/// cannot construct an operation that aliases another Registry, enrollment,
/// device, root owner, or caller nonce.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeviceCloseOperationId {
    registry_instance_id: u64,
    scope: ScopeKey,
    authority_epoch: u64,
    enrollment_sequence: u64,
    device: DeviceEnvelope,
    owner: TaskKey,
    caller_nonce: u64,
}

impl DeviceCloseOperationId {
    pub(crate) const fn registry_instance_id(self) -> u64 {
        self.registry_instance_id
    }

    pub(crate) const fn scope(self) -> ScopeKey {
        self.scope
    }

    pub(crate) const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    pub(crate) const fn enrollment_sequence(self) -> u64 {
        self.enrollment_sequence
    }

    pub(crate) const fn device(self) -> DeviceEnvelope {
        self.device
    }

    pub(crate) const fn caller_nonce(self) -> u64 {
        self.caller_nonce
    }

    fn rewrite_registry_instance(&mut self, registry_instance_id: u64) {
        self.registry_instance_id = registry_instance_id;
    }
}

/// Fresh publication and an exact same-operation recovery are the only two
/// successful production close results. Recovery never republishes and never
/// advances Registry state.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) enum DeviceCloseOutcome<T> {
    Applied {
        receipt: DeviceBatchCommitReceipt,
        publication: T,
        selection: RevokeSelection,
    },
    Recovered {
        receipt: DeviceBatchCommitReceipt,
        selection: RevokeSelection,
    },
}

/// Caller-visible projection of the private root publication provenance.
///
/// `PossiblyPublished` is deliberately conservative: the Registry installed
/// the exact operation and batch before entering the hardware publication
/// closure, but that closure did not return.  The caller must fence the device
/// rather than retry publication or claim a precommit abort.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum DevicePublishedStatus {
    Legacy,
    PossiblyPublished,
    Applied,
    CorruptPublished,
}

/// Allocation-free root-local summary of all published ownership progress,
/// built without a scan over global effect history. The exact operation batch
/// remains stored in the root for recovery validation; legacy or corrupt
/// committed roots remain honestly classified as published even when their
/// batch sequence or new idempotency record is missing.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DevicePublishedObligation {
    registry_instance_id: u64,
    scope: ScopeKey,
    device: DeviceEnvelope,
    batch_sequence: Option<u64>,
    operation: Option<DeviceCloseOperationId>,
    status: DevicePublishedStatus,
    phase: ScopePhase,
    revoke: Option<RevokeSelection>,
    reset_ticket: Option<DeviceResetTicket>,
    reset_tombstone: Option<DeviceResetTombstone>,
    reset_retry_issued: bool,
    reset_receipt: Option<DeviceResetReceipt>,
    iotlb_ticket: Option<DeviceIotlbTicket>,
    iotlb_tombstone: Option<DeviceIotlbTombstone>,
    iotlb_retry_issued: bool,
    closure: Option<DeviceClosureReceipt>,
}

impl DevicePublishedObligation {
    pub(crate) const fn registry_instance_id(&self) -> u64 {
        self.registry_instance_id
    }

    pub(crate) const fn scope(&self) -> ScopeKey {
        self.scope
    }

    pub(crate) const fn device(&self) -> DeviceEnvelope {
        self.device
    }

    pub(crate) const fn batch_sequence(&self) -> Option<u64> {
        self.batch_sequence
    }

    pub(crate) const fn operation(&self) -> Option<DeviceCloseOperationId> {
        self.operation
    }

    pub(crate) const fn status(&self) -> DevicePublishedStatus {
        self.status
    }

    pub(crate) const fn phase(&self) -> ScopePhase {
        self.phase
    }

    pub(crate) const fn revoke(&self) -> Option<&RevokeSelection> {
        self.revoke.as_ref()
    }

    pub(crate) const fn reset_ticket(&self) -> Option<DeviceResetTicket> {
        self.reset_ticket
    }

    pub(crate) const fn reset_tombstone(&self) -> Option<DeviceResetTombstone> {
        self.reset_tombstone
    }

    pub(crate) const fn reset_receipt(&self) -> Option<DeviceResetReceipt> {
        self.reset_receipt
    }

    pub(crate) const fn reset_retry_issued(&self) -> bool {
        self.reset_retry_issued
    }

    pub(crate) const fn iotlb_ticket(&self) -> Option<DeviceIotlbTicket> {
        self.iotlb_ticket
    }

    pub(crate) const fn iotlb_tombstone(&self) -> Option<DeviceIotlbTombstone> {
        self.iotlb_tombstone
    }

    pub(crate) const fn iotlb_retry_issued(&self) -> bool {
        self.iotlb_retry_issued
    }

    pub(crate) const fn closure(&self) -> Option<DeviceClosureReceipt> {
        self.closure
    }
}

/// Only an unpublished error licenses the caller to use precommit closure.
/// Every failure observed after a device publication carries root-local
/// ownership progress, including corrupt or legacy committed state.
// Keep the published obligation inline so reporting a possibly published
// operation remains allocation-free and cannot lose its recovery authority.
#[allow(clippy::large_enum_variant)]
#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum DeviceCloseError {
    Unpublished(RegistryError),
    Published {
        obligation: DevicePublishedObligation,
        error: RegistryError,
    },
}

/// Honest backend result retained through reset and IOTLB closure.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum DeviceClosureResult {
    Completed(i64),
    IndeterminateAfterReset,
    AbortedBeforeCommit,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeviceCompletionReceipt {
    registry_instance_id: u64,
    scope: ScopeKey,
    batch_sequence: u64,
    device: DeviceEnvelope,
    sequence: u64,
    causal_root: EffectKey,
    causal_commit_sequence: u64,
    result: i64,
}

impl DeviceCompletionReceipt {
    pub(crate) const fn device(self) -> DeviceEnvelope {
        self.device
    }

    pub(crate) const fn result(self) -> i64 {
        self.result
    }

    pub(crate) const fn causal_root(self) -> EffectKey {
        self.causal_root
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeviceResetTicket {
    registry_instance_id: u64,
    scope: ScopeKey,
    enrollment_sequence: u64,
    batch_sequence: Option<u64>,
    device: DeviceEnvelope,
    sequence: u64,
}

impl DeviceResetTicket {
    pub(crate) const fn device(self) -> DeviceEnvelope {
        self.device
    }
}

/// One failure-atomic ownership claim for a replayed device publication.
/// Returning this value means revocation is already Closing and reset owns the
/// completion race; there is no caller-visible candidate-only state.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct DeviceReplayResetClaim {
    selection: RevokeSelection,
    reset_ticket: DeviceResetTicket,
}

/// One failure-atomic precommit ownership close. Returning this receipt means
/// the caller's prevalidated hardware cancel/reset intent ran exactly once,
/// the root is Closing, every enrolled credit is retained, and the reset
/// ticket is installed with an honest `AbortedBeforeCommit` outcome.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DevicePrecommitCloseReceipt {
    pub(crate) selection: RevokeSelection,
    pub(crate) enrollment: DeviceBatchEnrollmentReceipt,
    pub(crate) reset_ticket: DeviceResetTicket,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeviceResetTombstone {
    ticket: DeviceResetTicket,
    sequence: u64,
}

impl DeviceResetTombstone {
    pub(crate) const fn device(self) -> DeviceEnvelope {
        self.ticket.device
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeviceResetReceipt {
    registry_instance_id: u64,
    scope: ScopeKey,
    enrollment_sequence: u64,
    batch_sequence: Option<u64>,
    old_device: DeviceEnvelope,
    new_device: DeviceEnvelope,
    sequence: u64,
    outcome: DeviceClosureResult,
}

impl DeviceResetReceipt {
    pub(crate) const fn old_device(self) -> DeviceEnvelope {
        self.old_device
    }

    pub(crate) const fn new_device(self) -> DeviceEnvelope {
        self.new_device
    }

    pub(crate) const fn outcome(self) -> DeviceClosureResult {
        self.outcome
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeviceIotlbTicket {
    registry_instance_id: u64,
    scope: ScopeKey,
    enrollment_sequence: u64,
    batch_sequence: Option<u64>,
    device: DeviceEnvelope,
    reset_sequence: u64,
    sequence: u64,
}

impl DeviceIotlbTicket {
    pub(crate) const fn device(self) -> DeviceEnvelope {
        self.device
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeviceIotlbTombstone {
    ticket: DeviceIotlbTicket,
    sequence: u64,
}

impl DeviceIotlbTombstone {
    pub(crate) const fn device(self) -> DeviceEnvelope {
        self.ticket.device
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeviceClosureReceipt {
    registry_instance_id: u64,
    scope: ScopeKey,
    enrollment_sequence: u64,
    batch_sequence: Option<u64>,
    device: DeviceEnvelope,
    sequence: u64,
    outcome: DeviceClosureResult,
}

impl DeviceClosureReceipt {
    pub(crate) const fn device(self) -> DeviceEnvelope {
        self.device
    }

    pub(crate) const fn outcome(self) -> DeviceClosureResult {
        self.outcome
    }

    pub(crate) const fn published(self) -> bool {
        self.batch_sequence.is_some()
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct TerminalRequest {
    outcome: TerminalOutcome,
    result: i64,
    causal_commit: Option<CommitReceipt>,
    manifest_digest: Option<[u8; 32]>,
}

impl TerminalRequest {
    pub(crate) const fn aborted(result: i64) -> Self {
        Self {
            outcome: TerminalOutcome::Aborted,
            result,
            causal_commit: None,
            manifest_digest: None,
        }
    }

    pub(crate) const fn completed(result: i64) -> Self {
        Self {
            outcome: TerminalOutcome::Completed,
            result,
            causal_commit: None,
            manifest_digest: None,
        }
    }

    pub(crate) fn completed_by(result: i64, causal_commit: CommitReceipt) -> Self {
        Self {
            outcome: TerminalOutcome::Completed,
            result,
            causal_commit: Some(causal_commit),
            manifest_digest: None,
        }
    }

    pub(crate) const fn indeterminate_after_reset(result: i64) -> Self {
        Self {
            outcome: TerminalOutcome::IndeterminateAfterReset,
            result,
            causal_commit: None,
            manifest_digest: None,
        }
    }

    /// Binds an opaque, non-zero canonical terminal manifest to this request.
    ///
    /// The Registry does not choose the caller's canonicalization or hash
    /// algorithm. It stores these exact bytes in the authoritative terminal
    /// receipt so a restarted portal/provider can compare the same manifest
    /// without keeping a second terminal winner.
    pub(crate) fn with_manifest_digest(mut self, digest: [u8; 32]) -> Result<Self, RegistryError> {
        if digest.iter().all(|byte| *byte == 0) {
            return Err(RegistryError::InvalidState);
        }
        self.manifest_digest = Some(digest);
        Ok(self)
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct TerminalReceipt {
    effect: EffectKey,
    outcome: TerminalOutcome,
    result: i64,
    sequence: u64,
    causal_commit: Option<CommitReceipt>,
    manifest_digest: Option<[u8; 32]>,
}

impl TerminalReceipt {
    pub(crate) const fn effect(&self) -> EffectKey {
        self.effect
    }

    pub(crate) const fn outcome(&self) -> TerminalOutcome {
        self.outcome
    }

    pub(crate) const fn result(&self) -> i64 {
        self.result
    }

    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) const fn manifest_digest(&self) -> Option<[u8; 32]> {
        self.manifest_digest
    }
}

/// A receipt extracted while the runtime lock is held and acknowledged only
/// after the corresponding continuation is published outside that lock.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct PublicationTicket {
    effect: EffectKey,
    scope: ScopeKey,
    terminal_sequence: u64,
    ticket_sequence: u64,
    outcome: TerminalOutcome,
    result: i64,
}

impl PublicationTicket {
    pub(crate) const fn effect(&self) -> EffectKey {
        self.effect
    }

    pub(crate) const fn outcome(&self) -> TerminalOutcome {
        self.outcome
    }

    pub(crate) const fn result(&self) -> i64 {
        self.result
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct Terminalization {
    pub(crate) receipt: TerminalReceipt,
    pub(crate) publication: Option<PublicationTicket>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct RegisterRequest {
    pub(crate) scope: ScopeKey,
    pub(crate) task: TaskKey,
    pub(crate) operation: OperationClass,
    pub(crate) descriptor: SyscallDescriptor,
    pub(crate) resources: Vec<ResourceKey>,
    pub(crate) credits: Vec<CreditCharge>,
    pub(crate) publication: PublicationMode,
}

/// Registration metadata for a production effect derived inside a root scope.
///
/// The legacy [`RegisterRequest`] remains the single-domain compatibility API.
/// New workload paths use this wrapper so domain membership and immutable
/// ancestry are installed by the registry in the same transition as identity,
/// credit, and reverse-index state.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DerivedRegisterRequest {
    pub(crate) request: RegisterRequest,
    pub(crate) domain: DomainKey,
    pub(crate) parent: Option<EffectKey>,
}

/// Registers a derived effect whose immutable identity is tied to one exact
/// device session, queue, descriptor token, and device generation.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeviceDerivedRegisterRequest {
    pub(crate) derived: DerivedRegisterRequest,
    pub(crate) device: DeviceEnvelope,
}

/// Resolves one parent without requiring a caller to predict an effect key
/// that the Registry has not allocated yet.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum DeviceCohortParent {
    Existing(EffectKey),
    BatchIndex(usize),
}

/// One fixed-position member of the production block/DMA registration cohort.
///
/// Batch index zero is the block request. Indices one through three are its
/// DMA owners. Keeping the index explicit lets validation reject duplicate,
/// missing, self, forward, and out-of-range references before the live
/// Registry changes.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DeviceDerivedCohortEntry {
    pub(crate) batch_index: usize,
    pub(crate) request: RegisterRequest,
    pub(crate) domain: DomainKey,
    pub(crate) parent: DeviceCohortParent,
    pub(crate) device: DeviceEnvelope,
}

/// One successful direct transfer from a retained preparation into the exact
/// four-effect block/DMA cohort. The materialized ticket is the only linear
/// successor and remains required by the later exact device-closure path.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct DeviceCohortMaterialization {
    pub(crate) registered: [RegisteredEffect; 4],
    pub(crate) authority: infrastructure::MaterializedDeviceTicket,
    pub(crate) cohort: infrastructure::DeviceCohortIdentity,
}

/// One failure-atomic update of an effect's current resource membership.
///
/// `handle` authenticates the complete immutable effect identity. Only the
/// registry's current reverse-index association changes.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ResourceMove {
    pub(crate) handle: PortalHandle,
    pub(crate) current_resources: Vec<ResourceKey>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct RegisteredEffect {
    pub(crate) identity: EffectIdentity,
    pub(crate) handle: PortalHandle,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct EffectView {
    pub(crate) identity: EffectIdentity,
    /// Mutable current membership used by domain indexes. The authenticated
    /// identity above retains the immutable origin resources.
    pub(crate) current_resources: BTreeSet<ResourceKey>,
    pub(crate) descriptor: SyscallDescriptor,
    pub(crate) phase: EffectPhase,
    pub(crate) commit: Option<CommitReceipt>,
    pub(crate) outcome: Option<EffectOutcomeRecord>,
    pub(crate) outcome_required: bool,
    pub(crate) terminal: Option<TerminalReceipt>,
    pub(crate) publication_pending: bool,
}

impl EffectView {
    /// Returns an exact failure-atomic view whose nested receipt provenance is
    /// namespace-neutral. The live receipt remains unchanged and authoritative.
    pub(crate) fn failure_atomic_projection(&self) -> Self {
        let mut projected = self.clone();
        projected.commit = projected
            .commit
            .as_ref()
            .map(CommitReceipt::failure_atomic_projection);
        if let Some(terminal) = projected.terminal.as_mut() {
            terminal.causal_commit = terminal
                .causal_commit
                .as_ref()
                .map(CommitReceipt::failure_atomic_projection);
        }
        projected
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct EffectRecord {
    identity: EffectIdentity,
    current_resources: BTreeSet<ResourceKey>,
    descriptor: SyscallDescriptor,
    nonce: u64,
    phase: EffectPhase,
    credits: Vec<CreditCharge>,
    credit_state: CreditState,
    publication_mode: PublicationMode,
    commit: Option<CommitReceipt>,
    outcome: Option<EffectOutcomeRecord>,
    outcome_required: bool,
    device_batch: Option<DeviceBatchMembership>,
    terminal: Option<TerminalReceipt>,
    pending_publication: Option<PublicationTicket>,
    terminalizations: u8,
    publication_acks: u8,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct DeviceBatchMembership {
    sequence: u64,
    ordinal: usize,
    size: usize,
    device: DeviceEnvelope,
}

#[derive(__cser_core::clone::Clone, __cser_core::marker::Copy)]
enum RegistrationCreditSource {
    ReserveFree,
    TransferRetainedPreparation,
}

/// One root-local source of truth for device publication provenance.
///
/// Keeping the operation and its authoritative batch in the enum prevents a
/// torn pair of optional fields from silently degrading into a legacy batch.
/// `Publishing` is installed before the external publication closure and is a
/// valid conservative state after unwind. `Applied` is reached only after the
/// prevalidated batch and revoke transitions have both been applied.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
enum DevicePublicationProvenance {
    None,
    Legacy,
    Publishing {
        operation: DeviceCloseOperationId,
        batch: DeviceBatchCommitReceipt,
    },
    Applied {
        operation: DeviceCloseOperationId,
        batch: DeviceBatchCommitReceipt,
    },
}

impl DevicePublicationProvenance {
    const fn is_none(&self) -> bool {
        __cser_core::matches!(self, Self::None)
    }

    const fn operation(&self) -> Option<DeviceCloseOperationId> {
        match self {
            Self::Publishing { operation, .. } | Self::Applied { operation, .. } => {
                Some(*operation)
            }
            Self::None | Self::Legacy => None,
        }
    }

    const fn batch(&self) -> Option<&DeviceBatchCommitReceipt> {
        match self {
            Self::Publishing { batch, .. } | Self::Applied { batch, .. } => Some(batch),
            Self::None | Self::Legacy => None,
        }
    }

    const fn published_status(&self) -> Option<DevicePublishedStatus> {
        match self {
            Self::None => None,
            Self::Legacy => Some(DevicePublishedStatus::Legacy),
            Self::Publishing { .. } => Some(DevicePublishedStatus::PossiblyPublished),
            Self::Applied { .. } => Some(DevicePublishedStatus::Applied),
        }
    }

    fn rewrite_registry_instance(&mut self, registry_instance_id: u64) {
        match self {
            Self::Publishing { operation, batch } | Self::Applied { operation, batch } => {
                operation.rewrite_registry_instance(registry_instance_id);
                batch.rewrite_registry_instance(registry_instance_id);
            }
            Self::None | Self::Legacy => {}
        }
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct DeviceRootState {
    initial_device: DeviceEnvelope,
    current_device: DeviceEnvelope,
    enrollment: Option<DeviceBatchEnrollmentReceipt>,
    batch_sequence: Option<u64>,
    publication: DevicePublicationProvenance,
    completion: Option<DeviceCompletionReceipt>,
    outcome: Option<DeviceClosureResult>,
    reset_ticket: Option<DeviceResetTicket>,
    reset_tombstone: Option<DeviceResetTombstone>,
    reset_retry_issued: bool,
    reset_receipt: Option<DeviceResetReceipt>,
    iotlb_ticket: Option<DeviceIotlbTicket>,
    iotlb_tombstone: Option<DeviceIotlbTombstone>,
    iotlb_retry_issued: bool,
    closure: Option<DeviceClosureReceipt>,
}

impl DeviceRootState {
    const fn pending(device: DeviceEnvelope) -> Self {
        Self {
            initial_device: device,
            current_device: device,
            enrollment: None,
            batch_sequence: None,
            publication: DevicePublicationProvenance::None,
            completion: None,
            outcome: None,
            reset_ticket: None,
            reset_tombstone: None,
            reset_retry_issued: false,
            reset_receipt: None,
            iotlb_ticket: None,
            iotlb_tombstone: None,
            iotlb_retry_issued: false,
            closure: None,
        }
    }

    fn rewrite_registry_instance(&mut self, registry_instance_id: u64) {
        if let Some(enrollment) = self.enrollment.as_mut() {
            enrollment.registry_instance_id = registry_instance_id;
        }
        self.publication
            .rewrite_registry_instance(registry_instance_id);
        if let Some(completion) = self.completion.as_mut() {
            completion.registry_instance_id = registry_instance_id;
        }
        if let Some(ticket) = self.reset_ticket.as_mut() {
            ticket.registry_instance_id = registry_instance_id;
        }
        if let Some(tombstone) = self.reset_tombstone.as_mut() {
            tombstone.ticket.registry_instance_id = registry_instance_id;
        }
        if let Some(receipt) = self.reset_receipt.as_mut() {
            receipt.registry_instance_id = registry_instance_id;
        }
        if let Some(ticket) = self.iotlb_ticket.as_mut() {
            ticket.registry_instance_id = registry_instance_id;
        }
        if let Some(tombstone) = self.iotlb_tombstone.as_mut() {
            tombstone.ticket.registry_instance_id = registry_instance_id;
        }
        if let Some(receipt) = self.closure.as_mut() {
            receipt.registry_instance_id = registry_instance_id;
        }
    }
}

struct DeviceBatchApplyPlan {
    receipt: DeviceBatchCommitReceipt,
    charges: Vec<CreditCharge>,
    next_commit_sequence: u64,
    next_device_batch_sequence: u64,
    next_scope_revision: u64,
}

struct DeviceClosePreparePlan {
    operation: DeviceCloseOperationId,
    batch: DeviceBatchApplyPlan,
    stored_batch: DeviceBatchCommitReceipt,
    revoke: RevokeBeginPlan,
    publishing_revision: u64,
}

struct DeviceCloseApplyPlan {
    operation: DeviceCloseOperationId,
    batch: DeviceBatchApplyPlan,
    revoke: RevokeBeginPlan,
}

struct DeviceDerivedCohortPlan {
    candidate: EffectRegistry,
    registered: [RegisteredEffect; 4],
}

/// Fully staged, non-authoritative whole-Registry replacement. The duplicated
/// base is an exact stale fence for the temporary O(N) implementation; it is
/// never exposed outside this module and final replacement performs no
/// allocation or callback.
struct DeviceCohortMaterializationPlan {
    base: EffectRegistry,
    candidate: EffectRegistry,
    authority: infrastructure::DeviceMaterializationPlan,
    registered: [RegisteredEffect; 4],
    cohort: infrastructure::DeviceCohortIdentity,
}

/// A non-authoritative, exact-scope transaction candidate spanning the
/// business Registry and its private causal-infrastructure child.  It never
/// escapes this module and is never promoted wholesale: successful install
/// moves only the two prevalidated scope records into the still-authoritative
/// live Registry.
struct CombinedScopeCandidate {
    scope: ScopeKey,
    registry_instance: u64,
    base_registry_revision: u64,
    base_infrastructure: infrastructure::InfrastructureRootBinding,
    replacement: EffectRegistry,
}

struct CombinedScopeInstallPlan {
    scope: ScopeKey,
    replacement_scope: Box<ScopeRecord>,
    infrastructure: infrastructure::InfrastructureScopeInstallPlan,
}

/// Restricted pure-state editor for the foundation transaction.  Keeping the
/// candidate field private to this child module prevents a future caller of
/// `combined_scope_transaction` from invoking a Registry `*_with_apply`
/// callback before the candidate is accepted.  Real fault/device transitions
/// must add narrow editor methods that stage records only; external apply
/// remains after authoritative installation.
mod combined_scope_editor {
    extern crate alloc as __cser_alloc;
    extern crate core as __cser_core;

    use super::{CombinedScopeCandidate, RegistryError};

    pub(super) struct Editor<'a> {
        candidate: &'a mut CombinedScopeCandidate,
    }

    impl<'a> Editor<'a> {
        pub(super) fn new(candidate: &'a mut CombinedScopeCandidate) -> Self {
            Self { candidate }
        }

        pub(super) fn advance_scope_revisions(&mut self) -> Result<(), RegistryError> {
            let scope = self.candidate.scope;
            let business = self
                .candidate
                .replacement
                .scopes
                .get_mut(&scope)
                .ok_or(RegistryError::UnknownScope)?;
            business.revision = business
                .revision
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
            self.candidate
                .replacement
                .infrastructure
                .advance_candidate_scope_revision(scope)?;
            Ok(())
        }
    }
}

struct DeviceResetApplyPlan {
    receipt: DeviceResetReceipt,
    next_device_closure_sequence: u64,
    next_scope_revision: u64,
}

struct DeviceCompletionApplyPlan {
    receipt: DeviceCompletionReceipt,
    next_device_closure_sequence: u64,
    next_scope_revision: u64,
}

/// A completion and the reset claim which follows it without leaving an
/// externally visible gap.  The Registry installs both before the device
/// reset closure can run.
struct DeviceCompletionAndResetApplyPlan {
    completion: DeviceCompletionReceipt,
    reset_ticket: DeviceResetTicket,
    next_device_closure_sequence: u64,
    next_scope_revision: u64,
}

struct DeviceResetTicketApplyPlan {
    ticket: DeviceResetTicket,
    next_device_closure_sequence: u64,
    next_scope_revision: u64,
}

struct DeviceReplayResetPlan {
    reset_ticket: DeviceResetTicket,
    revoke: RevokeBeginPlan,
    next_device_closure_sequence: u64,
    next_scope_revision: u64,
}

struct DevicePrecommitClosePlan {
    enrollment: DeviceBatchEnrollmentReceipt,
    enrollment_apply: DevicePrecommitEnrollmentApply,
    retention: DeviceRetentionPlan,
    reset_ticket: DeviceResetTicket,
    revoke: RevokeBeginPlan,
    next_device_closure_sequence: u64,
    next_scope_revision: u64,
}

enum DevicePrecommitEnrollmentApply {
    Existing,
    Install {
        enrollment: DeviceBatchEnrollmentReceipt,
        next_device_enrollment_sequence: u64,
        next_scope_revision: u64,
    },
}

struct RevokeBeginPlan {
    selection: RevokeSelection,
    next_revoke_sequence: u64,
    next_scope_revision: u64,
    infrastructure: Option<infrastructure::InfrastructureClosureStartPlan>,
}

struct DeviceIotlbApplyPlan {
    receipt: DeviceClosureReceipt,
    next_device_closure_sequence: u64,
    next_scope_revision: u64,
}

struct DeviceIotlbTicketApplyPlan {
    ticket: DeviceIotlbTicket,
    next_device_closure_sequence: u64,
    next_scope_revision: u64,
}

struct DeviceRetentionPlan {
    charges: Vec<CreditCharge>,
    from: CreditState,
}

struct PublicationAckApplyPlan {
    effect: EffectKey,
    scope: ScopeKey,
    credit_state: CreditState,
    next_scope_revision: u64,
    next_pending_publications: usize,
}

struct RevokeCompleteApplyPlan {
    scope: ScopeKey,
    next_scope_revision: u64,
    work: RevokeWorkCounters,
    infrastructure: Option<infrastructure::InfrastructureClosureFinishPlan>,
    receipt: ScopeClosureReceipt,
}

enum PreparedDeviceBatch {
    Apply(DeviceBatchApplyPlan),
    Replay(DeviceBatchCommitReceipt),
}

impl EffectRecord {
    fn handle(&self) -> PortalHandle {
        PortalHandle {
            scope: self.identity.scope,
            effect: self.identity.effect,
            domain: self.identity.domain,
            authority_epoch: self.identity.authority_epoch,
            binding_epoch: self.identity.binding_epoch,
            nonce: self.nonce,
        }
    }

    fn view(&self) -> EffectView {
        EffectView {
            identity: self.identity.clone(),
            current_resources: self.current_resources.clone(),
            descriptor: self.descriptor,
            phase: self.phase,
            commit: self.commit.clone(),
            outcome: self.outcome,
            outcome_required: self.outcome_required,
            terminal: self.terminal.clone(),
            publication_pending: self.pending_publication.is_some(),
        }
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ScopeConfig {
    pub(crate) key: ScopeKey,
    pub(crate) authority_epoch: u64,
    pub(crate) binding_epoch: u64,
    pub(crate) supervisor: TaskKey,
    pub(crate) credits: Vec<CreditLimit>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DomainConfig {
    pub(crate) key: DomainKey,
    pub(crate) binding_epoch: u64,
    pub(crate) supervisor: TaskKey,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct RecoveryState {
    crash_revision: u64,
    cohort: BTreeSet<EffectKey>,
    unadopted: BTreeSet<EffectKey>,
    snapshot: Option<RecoverySnapshot>,
    ready: Option<TaskKey>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct DomainRecoveryState {
    crash_revision: u64,
    cohort: BTreeSet<EffectKey>,
    unadopted: BTreeSet<EffectKey>,
    snapshot: Option<DomainRecoverySnapshot>,
    ready: Option<TaskKey>,
    highest_attempt: u32,
    last_abort: Option<DomainRecoveryAbortReceipt>,
    origin: DomainRecoveryOrigin,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
enum DomainRecoveryOrigin {
    /// A supervisor-reported crash has no infrastructure fault anchor.
    SupervisorCrash,
    /// A fault-triggered crash carries its exact immutable infrastructure anchor.
    ServiceFault(DomainFaultRecoveryAnchor),
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct DomainFaultRecoveryAnchor {
    fault_id: u64,
    generation: u64,
    task: TaskKey,
    vm_generation: u64,
    evidence_digest: u64,
    plan_commitment: [u8; 32],
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct DomainBindingRecord {
    binding_epoch: u64,
    supervisor: Option<TaskKey>,
    fallback_running: bool,
    revision: u64,
    recovery: Option<DomainRecoveryState>,
    quarantine: Option<DomainQuarantineReceipt>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct RevokeState {
    sequence: u64,
    cohort: BTreeSet<EffectKey>,
    closed_authority_epoch: u64,
    authority_epoch: u64,
    target_count: usize,
    selected_head: Option<EffectKey>,
    retired_recovery: Option<RecoveryState>,
    work: RevokeWorkCounters,
    infrastructure: Option<infrastructure::InfrastructureClosureSelection>,
    closure: Option<ScopeClosureReceipt>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::default::Default,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct RevokeWorkCounters {
    begin_target_record_visits: u64,
    next_calls: u64,
    head_selections: u64,
    terminalized: u64,
    completion_members_checked: u64,
    target_index_removals: u64,
    unrelated_effect_visits: u64,
    history_effect_visits: u64,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
enum RevokeRecordAccess {
    Begin,
    Transition,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct ScopeRecord {
    key: ScopeKey,
    phase: ScopePhase,
    authority_epoch: u64,
    binding_epoch: u64,
    supervisor: Option<TaskKey>,
    fallback_running: bool,
    revision: u64,
    domain_revision: u64,
    credits: CreditLedger,
    closure_candidates: BTreeSet<EffectKey>,
    handoff_candidates: BTreeSet<EffectKey>,
    pending_publications: usize,
    recovery: Option<RecoveryState>,
    domains: BTreeMap<DomainKey, DomainBindingRecord>,
    revoke: Option<RevokeState>,
    device_root: Option<DeviceRootState>,
    handoff_gate: HandoffAdmissionGate,
    handoff: Option<ProductionHandoffState>,
}

#[derive(__cser_core::default::Default)]
struct ExpectedReverseIndexes {
    by_scope: BTreeMap<ScopeKey, BTreeSet<EffectKey>>,
    by_domain: BTreeMap<(ScopeKey, DomainKey), BTreeSet<EffectKey>>,
    by_task: BTreeMap<TaskKey, BTreeSet<EffectKey>>,
    by_resource: BTreeMap<ResourceKey, BTreeSet<EffectKey>>,
    children_by_parent: BTreeMap<EffectKey, BTreeSet<EffectKey>>,
    leaves_by_scope: BTreeMap<ScopeKey, BTreeSet<EffectKey>>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::default::Default,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct ProductionIndexes {
    by_domain: BTreeMap<(ScopeKey, DomainKey), BTreeSet<EffectKey>>,
    children_by_parent: BTreeMap<EffectKey, BTreeSet<EffectKey>>,
    leaves_by_scope: BTreeMap<ScopeKey, BTreeSet<EffectKey>>,
}

impl ScopeRecord {
    /// Any root-registry mutation makes a previously issued recovery proof
    /// conservative rather than allowing a replacement to bind against a
    /// snapshot that omitted the mutation.  Domain-local snapshots carry both
    /// revisions, so a root revision change invalidates every ready proof.
    fn invalidate_recovery_readiness(&mut self) {
        if let Some(recovery) = self.recovery.as_mut() {
            recovery.ready = None;
        }
        for binding in self.domains.values_mut() {
            if let Some(recovery) = binding.recovery.as_mut() {
                recovery.ready = None;
            }
        }
    }
}

fn advance_device_preparation_scope(scope: &mut ScopeRecord) -> Result<(), RegistryError> {
    scope.revision = scope
        .revision
        .checked_add(1)
        .ok_or(RegistryError::CounterOverflow)?;
    scope.invalidate_recovery_readiness();
    Ok(())
}

/// Registry-canonical identity of one ordered domain recovery cohort.
///
/// Both the crash transition and every recovery snapshot carry this exact
/// value. Adapters must not hash the effect list with a second algorithm.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DomainCohortIdentity {
    len: u64,
    digest: [u8; 32],
}

impl DomainCohortIdentity {
    const fn new(len: u64, digest: [u8; 32]) -> Self {
        Self { len, digest }
    }

    pub(crate) const fn len(self) -> u64 {
        self.len
    }

    pub(crate) const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

fn domain_cohort_identity(
    cohort: Option<&BTreeSet<EffectKey>>,
) -> Result<DomainCohortIdentity, RegistryError> {
    let len = u64::try_from(cohort.map_or(0, BTreeSet::len))
        .map_err(|_| RegistryError::CounterOverflow)?;
    Ok(DomainCohortIdentity::new(len, fault_cohort_digest(cohort)))
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct RecoveryEffectSummary {
    pub(crate) effect: EffectKey,
    pub(crate) binding_epoch: u64,
    pub(crate) phase: EffectPhase,
    pub(crate) descriptor_digest: u64,
    pub(crate) commit_sequence: Option<u64>,
    pub(crate) outcome_required: bool,
    pub(crate) outcome: Option<EffectOutcomeRecord>,
    pub(crate) terminal_manifest_digest: Option<[u8; 32]>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct RecoverySnapshot {
    pub(crate) scope: ScopeKey,
    pub(crate) replacement: TaskKey,
    pub(crate) authority_epoch: u64,
    pub(crate) binding_epoch: u64,
    pub(crate) revision: u64,
    pub(crate) domain_revision: u64,
    pub(crate) effects: Vec<RecoveryEffectSummary>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DomainRecoverySnapshot {
    registry_instance_id: u64,
    pub(crate) scope: ScopeKey,
    pub(crate) domain: DomainKey,
    pub(crate) replacement: TaskKey,
    pub(crate) attempt: u32,
    pub(crate) authority_epoch: u64,
    pub(crate) binding_epoch: u64,
    crash_revision: u64,
    pub(crate) root_revision: u64,
    pub(crate) domain_revision: u64,
    cohort_identity: DomainCohortIdentity,
    pub(crate) effects: Vec<RecoveryEffectSummary>,
    digest: [u8; 32],
}

impl DomainRecoverySnapshot {
    pub(crate) const fn registry_instance_id(&self) -> u64 {
        self.registry_instance_id
    }

    pub(crate) const fn attempt(&self) -> u32 {
        self.attempt
    }

    pub(crate) const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) const fn cohort_identity(&self) -> DomainCohortIdentity {
        self.cohort_identity
    }
}

fn domain_recovery_snapshot_digest(snapshot: &DomainRecoverySnapshot) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus.cser.domain-recovery-snapshot.v1\0");
    hasher.update(snapshot.scope.id().to_le_bytes());
    hasher.update(snapshot.scope.generation().to_le_bytes());
    hasher.update(snapshot.domain.value().to_le_bytes());
    hasher.update(snapshot.replacement.id().to_le_bytes());
    hasher.update(snapshot.replacement.generation().to_le_bytes());
    hasher.update(snapshot.attempt.to_le_bytes());
    hasher.update(snapshot.authority_epoch.to_le_bytes());
    hasher.update(snapshot.binding_epoch.to_le_bytes());
    hasher.update(snapshot.crash_revision.to_le_bytes());
    hasher.update(snapshot.root_revision.to_le_bytes());
    hasher.update(snapshot.domain_revision.to_le_bytes());
    hasher.update(snapshot.cohort_identity.len.to_le_bytes());
    hasher.update(snapshot.cohort_identity.digest);
    hasher.update((snapshot.effects.len() as u128).to_le_bytes());
    for effect in &snapshot.effects {
        hasher.update(effect.effect.id().to_le_bytes());
        hasher.update(effect.effect.generation().to_le_bytes());
        hasher.update(effect.binding_epoch.to_le_bytes());
        let (phase, terminal) = match effect.phase {
            EffectPhase::Registered => (0_u8, 0_u8),
            EffectPhase::Prepared => (1, 0),
            EffectPhase::Committed => (2, 0),
            EffectPhase::Terminal(TerminalOutcome::Completed) => (3, 1),
            EffectPhase::Terminal(TerminalOutcome::IndeterminateAfterReset) => (3, 2),
            EffectPhase::Terminal(TerminalOutcome::Aborted) => (3, 3),
        };
        hasher.update([phase, terminal]);
        hasher.update(effect.descriptor_digest.to_le_bytes());
        match effect.commit_sequence {
            Some(sequence) => {
                hasher.update([1]);
                hasher.update(sequence.to_le_bytes());
            }
            None => hasher.update([0]),
        }
        hasher.update([u8::from(effect.outcome_required)]);
        match effect.outcome {
            Some(outcome) => {
                hasher.update([1]);
                hasher.update([match outcome.class() {
                    EffectOutcomeClass::Data => 1,
                    EffectOutcomeClass::Error => 2,
                    EffectOutcomeClass::Indeterminate => 3,
                }]);
                hasher.update(outcome.result().to_le_bytes());
                hasher.update(outcome.digest());
            }
            None => hasher.update([0]),
        }
        match effect.terminal_manifest_digest {
            Some(digest) => {
                hasher.update([1]);
                hasher.update(digest);
            }
            None => hasher.update([0]),
        }
    }
    hasher.finalize().into()
}

/// Why one manager-owned, pre-rebind domain recovery attempt was abandoned.
///
/// This is deliberately Registry-local instead of depending on the supervisor
/// crate. The eventual OSTD adapter must translate its typed stop reason at the
/// private backend boundary.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum DomainRecoveryAbortReason {
    ExitedBeforeReady,
    ReadyTimeout,
    RecoveryRejected,
    PartialRecoveryFailed,
}

/// Fixed-size evidence that one exact recovery attempt was cleared without
/// consuming or replacing any member of the crash-frozen cohort.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DomainRecoveryAbortReceipt {
    registry_instance_id: u64,
    scope: ScopeKey,
    domain: DomainKey,
    replacement: TaskKey,
    binding_epoch: u64,
    crash_revision: u64,
    attempt: u32,
    snapshot_digest: [u8; 32],
    reason: DomainRecoveryAbortReason,
}

impl DomainRecoveryAbortReceipt {
    pub(crate) const fn attempt(self) -> u32 {
        self.attempt
    }

    pub(crate) const fn reason(self) -> DomainRecoveryAbortReason {
        self.reason
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum DomainRecoveryAbortOutcome {
    Aborted(DomainRecoveryAbortReceipt),
    AlreadyAborted(DomainRecoveryAbortReceipt),
}

impl DomainRecoveryAbortOutcome {
    pub(crate) const fn receipt(self) -> DomainRecoveryAbortReceipt {
        match self {
            Self::Aborted(receipt) | Self::AlreadyAborted(receipt) => receipt,
        }
    }
}

/// Permanent, counter-independent control-plane fence for one service domain.
///
/// The marker lives in the already allocated domain binding record. Installing
/// it never allocates and never advances a fallible epoch/revision counter.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DomainQuarantineReceipt {
    registry_instance_id: u64,
    scope: ScopeKey,
    domain: DomainKey,
    service: TaskKey,
    binding_epoch: u64,
    observed_binding_epoch: Option<u64>,
    crash_revision: Option<u64>,
    recovery_attempt: Option<u32>,
    retained_effects_at_isolation: usize,
    unadopted_effects_at_isolation: usize,
}

impl DomainQuarantineReceipt {
    pub(crate) const fn service(self) -> TaskKey {
        self.service
    }

    pub(crate) const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }

    pub(crate) const fn observed_binding_epoch(self) -> Option<u64> {
        self.observed_binding_epoch
    }
}

/// Infallible result of a bounded authority-isolation request. Missing or
/// invalid coordinates carry no authority to revoke and therefore do not
/// require an allocated error object.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum DomainIsolationOutcome {
    Isolated(DomainQuarantineReceipt),
    AlreadyIsolated(DomainQuarantineReceipt),
    UnknownScope,
    UnknownDomain,
    InvalidTarget,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct RecoveryItem {
    pub(crate) handle: PortalHandle,
    pub(crate) descriptor: SyscallDescriptor,
    pub(crate) phase: EffectPhase,
    pub(crate) commit: Option<CommitReceipt>,
    pub(crate) outcome_required: bool,
    pub(crate) outcome: Option<EffectOutcomeRecord>,
    pub(crate) terminal_manifest_digest: Option<[u8; 32]>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct CrashReceipt {
    pub(crate) scope: ScopeKey,
    pub(crate) previous_binding_epoch: u64,
    pub(crate) binding_epoch: u64,
    pub(crate) cohort: BTreeSet<EffectKey>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct RebindReceipt {
    pub(crate) scope: ScopeKey,
    pub(crate) binding_epoch: u64,
    pub(crate) supervisor: TaskKey,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DomainCrashReceipt {
    pub(crate) scope: ScopeKey,
    pub(crate) domain: DomainKey,
    pub(crate) previous_binding_epoch: u64,
    pub(crate) binding_epoch: u64,
    pub(crate) cohort: BTreeSet<EffectKey>,
    pub(crate) cohort_identity: DomainCohortIdentity,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DomainRebindReceipt {
    pub(crate) scope: ScopeKey,
    pub(crate) domain: DomainKey,
    pub(crate) binding_epoch: u64,
    pub(crate) supervisor: TaskKey,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct DomainProjection {
    pub(crate) binding_epoch: u64,
    pub(crate) supervisor: Option<TaskKey>,
    pub(crate) fallback_running: bool,
    pub(crate) revision: u64,
    pub(crate) live_effects: usize,
    pub(crate) recovery_remaining: usize,
    pub(crate) recovery_attempt: Option<u32>,
    pub(crate) last_aborted_attempt: Option<u32>,
    pub(crate) quarantine: Option<DomainQuarantineReceipt>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct RevokeSelection {
    pub(crate) scope: ScopeKey,
    pub(crate) sequence: u64,
    pub(crate) closed_authority_epoch: u64,
    pub(crate) authority_epoch: u64,
    pub(crate) target_count: usize,
}

/// Durable completion of the business revoke and its optional causal
/// infrastructure child. The receipt is installed by the same Registry
/// transaction that advances the business scope to `Revoked`.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ScopeClosureReceipt {
    registry_instance_id: u64,
    revoke: RevokeSelection,
    infrastructure: Option<infrastructure::InfrastructureClosureReceipt>,
    closed_scope_revision: u64,
}

impl ScopeClosureReceipt {
    pub(crate) const fn registry_instance_id(&self) -> u64 {
        self.registry_instance_id
    }

    pub(crate) const fn revoke(&self) -> &RevokeSelection {
        &self.revoke
    }

    const fn infrastructure(&self) -> Option<infrastructure::InfrastructureClosureReceipt> {
        self.infrastructure
    }

    pub(crate) const fn closed_scope_revision(&self) -> u64 {
        self.closed_scope_revision
    }

    fn rewrite_registry_instance(&mut self, registry_instance_id: u64) {
        self.registry_instance_id = registry_instance_id;
        if let Some(infrastructure) = self.infrastructure.as_mut() {
            infrastructure.rewrite_registry_instance(registry_instance_id);
        }
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum ScopeClosureProgress {
    Active,
    Closing(RevokeSelection),
    Retained(RevokeSelection),
    Closed(ScopeClosureReceipt),
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct RevokeWorkProjection {
    pub(crate) target_count: usize,
    pub(crate) begin_target_record_visits: u64,
    pub(crate) next_calls: u64,
    pub(crate) head_selections: u64,
    pub(crate) terminalized: u64,
    pub(crate) completion_members_checked: u64,
    pub(crate) target_index_removals: u64,
    pub(crate) unrelated_effect_visits: u64,
    pub(crate) history_effect_visits: u64,
    pub(crate) pending_targets: usize,
    pub(crate) target_state: ScopePhase,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum RevokeDisposition {
    Abort,
    Drain(CommitReceipt),
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct RevokeEffect {
    pub(crate) effect: EffectKey,
    pub(crate) disposition: RevokeDisposition,
    pub(crate) publication_required: bool,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct RegistryProjection {
    pub(crate) phase: ScopePhase,
    pub(crate) authority_epoch: u64,
    pub(crate) binding_epoch: u64,
    pub(crate) supervisor: Option<TaskKey>,
    pub(crate) fallback_running: bool,
    pub(crate) revision: u64,
    pub(crate) domain_revision: u64,
    pub(crate) live_effects: usize,
    pub(crate) pending_publications: usize,
    pub(crate) credits: CreditTotals,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum HandoffFreezeReadiness {
    ReadyToCommit,
    NeedsAbort,
    PublicationPending,
    BlockedRetained,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ProductionHandoffFreezeReceipt {
    freeze: KernelFreezeReceipt,
    readiness: HandoffFreezeReadiness,
    cohort_size: usize,
    committed_at_freeze: usize,
}

impl ProductionHandoffFreezeReceipt {
    pub(crate) const fn freeze(self) -> KernelFreezeReceipt {
        self.freeze
    }

    pub(crate) const fn readiness(self) -> HandoffFreezeReadiness {
        self.readiness
    }

    pub(crate) const fn cohort_size(self) -> usize {
        self.cohort_size
    }

    pub(crate) const fn committed_at_freeze(self) -> usize {
        self.committed_at_freeze
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct HandoffAbortProgress {
    pub(crate) aborted: usize,
    pub(crate) publications: Vec<PublicationTicket>,
    pub(crate) readiness: HandoffFreezeReadiness,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct HandoffThawReceipt {
    freeze: KernelFreezeReceipt,
    decision: OwnershipDecisionReceipt,
    source_recovery_required: bool,
}

impl HandoffThawReceipt {
    pub(crate) const fn source_recovery_required(self) -> bool {
        self.source_recovery_required
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct ProductionHandoffClosureReceipt {
    freeze: KernelFreezeReceipt,
    decision: OwnershipDecisionReceipt,
    revoke: RevokeSelection,
    scope_closure: ScopeClosureReceipt,
    terminal_manifest_digest: u64,
    closed_scope_revision: u64,
}

impl ProductionHandoffClosureReceipt {
    pub(crate) const fn freeze(&self) -> KernelFreezeReceipt {
        self.freeze
    }

    pub(crate) const fn decision(&self) -> OwnershipDecisionReceipt {
        self.decision
    }

    pub(crate) const fn terminal_manifest_digest(&self) -> u64 {
        self.terminal_manifest_digest
    }

    pub(crate) const fn scope_closure(&self) -> &ScopeClosureReceipt {
        &self.scope_closure
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum ProductionHandoffProgress {
    Frozen(HandoffFreezeReadiness),
    Aborted(HandoffThawReceipt),
    Closing(RevokeSelection),
    Retained(RevokeSelection),
    Closed(ProductionHandoffClosureReceipt),
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
struct ProductionHandoffState {
    freeze: KernelFreezeReceipt,
    cohort: BTreeSet<EffectKey>,
    committed_at_freeze: BTreeSet<EffectKey>,
    thaw: Option<HandoffThawReceipt>,
    decision: Option<OwnershipDecisionReceipt>,
    revoke: Option<RevokeSelection>,
    closure: Option<ProductionHandoffClosureReceipt>,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum RegistryError {
    InvalidGeneration,
    InvalidCreditConfiguration,
    ScopeAlreadyExists,
    DomainAlreadyExists,
    UnknownScope,
    UnknownDomain,
    UnknownEffect,
    UnknownCreditClass,
    CreditExhausted,
    CounterOverflow,
    ScopeNotActive,
    ScopeNotClosing,
    StaleAuthority,
    StaleBinding,
    NoSupervisor,
    InvalidHandle,
    InvalidState,
    SnapshotChanged,
    ForeignRecoverySnapshot,
    StaleRecoveryAttempt,
    ConflictingRecoveryAttempt,
    RecoveryNotReady,
    NotAdoptable,
    DomainQuarantined,
    LiveDescendants,
    AlreadyTerminal,
    CommitConflict,
    InvalidDeviceEnvelope,
    StaleDeviceGeneration,
    InvalidBatchReceipt,
    DeviceBatchNotEnrolled,
    DeviceClosurePending,
    InvalidRevokeSelection,
    InvalidPublication,
    PublicationPending,
    NotQuiescent,
    HandoffAdmissionFrozen,
    InvalidHandoffReceipt,
    HandoffNotReady,
    HandoffDevicePrecommitPending,
    Infrastructure(infrastructure::InfrastructureError),
    CombinedCandidateStale,
    CombinedCandidateShapeChanged,
    Invariant(&'static str),
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct FaultRegistryFailure {
    error: RegistryError,
    input: infrastructure::ArmedFaultTask,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct DevicePreparationRegistryFailure<T> {
    error: RegistryError,
    input: T,
}

impl<T> DevicePreparationRegistryFailure<T> {
    pub(crate) const fn error(&self) -> &RegistryError {
        &self.error
    }

    pub(crate) fn into_input(self) -> T {
        self.input
    }
}

impl FaultRegistryFailure {
    pub(crate) const fn error(&self) -> &RegistryError {
        &self.error
    }

    pub(crate) fn into_input(self) -> infrastructure::ArmedFaultTask {
        self.input
    }
}

impl From<infrastructure::InfrastructureError> for RegistryError {
    fn from(error: infrastructure::InfrastructureError) -> Self {
        Self::Infrastructure(error)
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
enum DevicePublicationMode {
    Unique,
    DisabledNonDeviceCandidate,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct EffectRegistry {
    instance_id: u64,
    device_publication_mode: DevicePublicationMode,
    scopes: BTreeMap<ScopeKey, Box<ScopeRecord>>,
    effects: BTreeMap<EffectKey, EffectRecord>,
    by_scope: BTreeMap<ScopeKey, BTreeSet<EffectKey>>,
    by_task: BTreeMap<TaskKey, BTreeSet<EffectKey>>,
    by_resource: BTreeMap<ResourceKey, BTreeSet<EffectKey>>,
    production: Box<ProductionIndexes>,
    next_effect_id: u64,
    next_nonce: u64,
    next_commit_sequence: u64,
    next_device_enrollment_sequence: u64,
    next_device_batch_sequence: u64,
    next_device_closure_sequence: u64,
    next_terminal_sequence: u64,
    next_publication_sequence: u64,
    next_revoke_sequence: u64,
    /// The only authoritative causal-infrastructure ledger.  It is a private
    /// child, not a peer Registry or a service-owned side table.
    infrastructure: infrastructure::InfrastructureState,
}

impl EffectRegistry {
    pub(crate) fn new() -> Self {
        let instance_id = next_registry_instance_id();
        Self {
            instance_id,
            device_publication_mode: DevicePublicationMode::Unique,
            scopes: BTreeMap::new(),
            effects: BTreeMap::new(),
            by_scope: BTreeMap::new(),
            by_task: BTreeMap::new(),
            by_resource: BTreeMap::new(),
            production: Box::default(),
            next_effect_id: 1,
            next_nonce: 1,
            next_commit_sequence: 1,
            next_device_enrollment_sequence: 1,
            next_device_batch_sequence: 1,
            next_device_closure_sequence: 1,
            next_terminal_sequence: 1,
            next_publication_sequence: 1,
            next_revoke_sequence: 1,
            infrastructure: infrastructure::InfrastructureState::new(instance_id),
        }
    }

    /// Private evidence snapshot. `EffectRegistry` deliberately does not
    /// implement `Clone`: a production caller cannot duplicate the registry
    /// instance namespace and publish twice with copied authority. Only code
    /// in this module can take a read-only evidence snapshot or build a
    /// private failure-atomic registration candidate that never escapes.
    fn clone(&self) -> Self {
        Self {
            instance_id: self.instance_id,
            device_publication_mode: self.device_publication_mode,
            scopes: self.scopes.clone(),
            effects: self.effects.clone(),
            by_scope: self.by_scope.clone(),
            by_task: self.by_task.clone(),
            by_resource: self.by_resource.clone(),
            production: self.production.clone(),
            next_effect_id: self.next_effect_id,
            next_nonce: self.next_nonce,
            next_commit_sequence: self.next_commit_sequence,
            next_device_enrollment_sequence: self.next_device_enrollment_sequence,
            next_device_batch_sequence: self.next_device_batch_sequence,
            next_device_closure_sequence: self.next_device_closure_sequence,
            next_terminal_sequence: self.next_terminal_sequence,
            next_publication_sequence: self.next_publication_sequence,
            next_revoke_sequence: self.next_revoke_sequence,
            infrastructure: self.infrastructure.private_full_clone(),
        }
    }

    /// Builds a private transaction candidate containing only one scope and
    /// its effects.  Unlike the evidence clone above, cost is independent of
    /// unrelated tenants and history.
    fn scope_transaction_candidate(&self, scope_key: ScopeKey) -> Result<Self, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?
            .clone();
        let effects = self
            .effects
            .iter()
            .filter(|(_, record)| record.identity.scope == scope_key)
            .map(|(key, record)| (*key, record.clone()))
            .collect::<BTreeMap<_, _>>();
        let keys = effects.keys().copied().collect::<BTreeSet<_>>();

        let by_scope = self
            .by_scope
            .get(&scope_key)
            .cloned()
            .map(|members| BTreeMap::from([(scope_key, members)]))
            .unwrap_or_default();
        let by_task = self
            .by_task
            .iter()
            .filter_map(|(task, members)| {
                let selected = members
                    .intersection(&keys)
                    .copied()
                    .collect::<BTreeSet<_>>();
                (!selected.is_empty()).then_some((*task, selected))
            })
            .collect();
        let by_resource = self
            .by_resource
            .iter()
            .filter_map(|(resource, members)| {
                let selected = members
                    .intersection(&keys)
                    .copied()
                    .collect::<BTreeSet<_>>();
                (!selected.is_empty()).then_some((*resource, selected))
            })
            .collect();
        let by_domain = self
            .production
            .by_domain
            .iter()
            .filter(|((scope, _), _)| *scope == scope_key)
            .map(|(key, members)| (*key, members.clone()))
            .collect();
        let children_by_parent = self
            .production
            .children_by_parent
            .iter()
            .filter_map(|(parent, children)| {
                if !keys.contains(parent) {
                    return None;
                }
                let selected = children
                    .intersection(&keys)
                    .copied()
                    .collect::<BTreeSet<_>>();
                (!selected.is_empty()).then_some((*parent, selected))
            })
            .collect();
        let leaves_by_scope = self
            .production
            .leaves_by_scope
            .get(&scope_key)
            .cloned()
            .map(|members| BTreeMap::from([(scope_key, members)]))
            .unwrap_or_default();

        Ok(Self {
            instance_id: self.instance_id,
            device_publication_mode: self.device_publication_mode,
            scopes: BTreeMap::from([(scope_key, scope)]),
            effects,
            by_scope,
            by_task,
            by_resource,
            production: Box::new(ProductionIndexes {
                by_domain,
                children_by_parent,
                leaves_by_scope,
            }),
            next_effect_id: self.next_effect_id,
            next_nonce: self.next_nonce,
            next_commit_sequence: self.next_commit_sequence,
            next_device_enrollment_sequence: self.next_device_enrollment_sequence,
            next_device_batch_sequence: self.next_device_batch_sequence,
            next_device_closure_sequence: self.next_device_closure_sequence,
            next_terminal_sequence: self.next_terminal_sequence,
            next_publication_sequence: self.next_publication_sequence,
            next_revoke_sequence: self.next_revoke_sequence,
            infrastructure: self.infrastructure.try_scope_candidate(scope_key)?,
        })
    }

    /// Attaches the bounded infrastructure child to an already-registered
    /// business root.  Every business-side check and domain-vector allocation
    /// completes before the authoritative infrastructure ledger is touched.
    /// This is module-private until a production portal owns the lifecycle.
    fn enable_infrastructure_for_scope(
        &mut self,
        scope_key: ScopeKey,
        root_effect: EffectKey,
        limits: infrastructure::InfrastructureLimits,
    ) -> Result<(), RegistryError> {
        // Any pre-existing cross-ledger defect is rejected before the target
        // ledger can change. `InfrastructureState::enable` itself prepares
        // every allocation/counter check before its single Vec insertion.
        self.check_infrastructure_root_links()?;
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        let root = self
            .effects
            .get(&root_effect)
            .ok_or(RegistryError::UnknownEffect)?;
        if scope.phase != ScopePhase::Active
            || root.identity.scope != scope_key
            || root.identity.parent.is_some()
            || root.identity.authority_epoch != scope.authority_epoch
            || root.phase.is_terminal()
        {
            return Err(RegistryError::InvalidState);
        }
        let mut domains = Vec::new();
        domains
            .try_reserve_exact(scope.domains.len())
            .map_err(|_| {
                RegistryError::Infrastructure(infrastructure::InfrastructureError::AllocationFailed)
            })?;
        domains.extend(
            scope
                .domains
                .iter()
                .map(|(domain, binding)| (*domain, binding.binding_epoch)),
        );
        self.infrastructure.enable(
            scope_key,
            scope.authority_epoch,
            root_effect,
            limits,
            &domains,
        )?;
        __cser_core::debug_assert!(self.check_infrastructure_root_links().is_ok());
        Ok(())
    }

    fn check_infrastructure_root_links(&self) -> Result<(), RegistryError> {
        self.infrastructure.check_invariants()?;
        for binding in self.infrastructure.scope_links() {
            let scope = self
                .scopes
                .get(&binding.scope)
                .ok_or(RegistryError::Invariant(
                    "infrastructure scope lacks business scope",
                ))?;
            let root = self
                .effects
                .get(&binding.root_effect)
                .ok_or(RegistryError::Invariant(
                    "infrastructure root lacks business effect",
                ))?;
            let linked_authority_epoch = match scope.phase {
                ScopePhase::Active => scope.authority_epoch,
                ScopePhase::Closing | ScopePhase::Revoked => {
                    let revoke = scope.revoke.as_ref().ok_or(RegistryError::Invariant(
                        "inactive infrastructure scope lacks revoke identity",
                    ))?;
                    let current = revoke.closed_authority_epoch.checked_add(1).ok_or(
                        RegistryError::Invariant("infrastructure revoke authority overflow"),
                    )?;
                    if scope.authority_epoch != current || revoke.authority_epoch != current {
                        return Err(RegistryError::Invariant(
                            "infrastructure revoke authority linkage mismatch",
                        ));
                    }
                    revoke.closed_authority_epoch
                }
            };
            if binding.authority_epoch != linked_authority_epoch
                || root.identity.scope != binding.scope
                || root.identity.authority_epoch != linked_authority_epoch
                || root.identity.effect != binding.root_effect
                || root.identity.parent.is_some()
            {
                return Err(RegistryError::Invariant(
                    "infrastructure/business root linkage mismatch",
                ));
            }
            let root_is_indexed = self
                .by_scope
                .get(&binding.scope)
                .is_some_and(|effects| effects.contains(&binding.root_effect));
            let lifecycle_matches = match scope.phase {
                ScopePhase::Active => {
                    binding.active
                        && binding.closure_finished.is_none()
                        && !root.phase.is_terminal()
                        && root_is_indexed
                }
                // Revoke terminalizes cohort members one at a time.  The last
                // root can therefore be durably terminal (and absent from the
                // live reverse index) before `revoke_complete` advances the
                // scope to Revoked.  Both Closing presentations are valid,
                // but index membership must exactly mirror terminality.
                ScopePhase::Closing => {
                    !binding.active
                        && binding.closure_finished == Some(false)
                        && scope
                            .revoke
                            .as_ref()
                            .is_some_and(|revoke| revoke.cohort.contains(&binding.root_effect))
                        && root_is_indexed != root.phase.is_terminal()
                }
                ScopePhase::Revoked => {
                    !binding.active
                        && binding.closure_finished == Some(true)
                        && root.phase.is_terminal()
                        && !root_is_indexed
                }
            };
            if !lifecycle_matches {
                return Err(RegistryError::Invariant(
                    "infrastructure/business lifecycle mismatch",
                ));
            }
            if binding.domains.len() != scope.domains.len()
                || binding.domains.iter().any(|(domain, epoch)| {
                    scope
                        .domains
                        .get(domain)
                        .is_none_or(|business| business.binding_epoch != *epoch)
                })
            {
                return Err(RegistryError::Invariant(
                    "infrastructure/business domain set mismatch",
                ));
            }
        }
        Ok(())
    }

    /// Builds a non-authoritative exact-scope candidate.  The caller can
    /// stage only module-private work and cannot receive a bearer from
    /// `combined_scope_transaction`, whose output is deliberately `()`.
    fn combined_scope_candidate(
        &self,
        scope_key: ScopeKey,
    ) -> Result<CombinedScopeCandidate, RegistryError> {
        self.check_invariants()?;
        let base_registry_revision = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?
            .revision;
        let base_infrastructure = self.infrastructure.root_binding(scope_key)?;
        let replacement = self.scope_transaction_candidate(scope_key)?;
        replacement.check_invariants()?;
        Ok(CombinedScopeCandidate {
            scope: scope_key,
            registry_instance: self.instance_id,
            base_registry_revision,
            base_infrastructure,
            replacement,
        })
    }

    /// Atomically binds one pre-hardware device preparation to both ledgers.
    /// The returned bearer is usable only after the exact-scope install has
    /// made its queue/pinned/DMA credits authoritative.
    pub(crate) fn reserve_device_preparation(
        &mut self,
        context: &infrastructure::WorkloadContext,
        parent_effect: EffectKey,
        coordinates: infrastructure::DeviceReservationCoordinates,
    ) -> Result<infrastructure::DevicePreparationTicket, RegistryError> {
        let scope_key = context.scope();
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        let parent = self
            .effects
            .get(&parent_effect)
            .ok_or(RegistryError::UnknownEffect)?;
        if parent.identity.scope != scope_key
            || parent.identity.authority_epoch != scope.authority_epoch
            || parent.phase.is_terminal()
        {
            return Err(RegistryError::InvalidHandle);
        }

        let charges = coordinates.credit_charges();
        let mut candidate = self.combined_scope_candidate(scope_key)?;
        let reservation = candidate
            .replacement
            .infrastructure
            .reserve_device_preparation_in_candidate(context, parent_effect, coordinates)?;
        let candidate_scope = candidate
            .replacement
            .scopes
            .get_mut(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        candidate_scope.credits.reserve(&charges)?;
        advance_device_preparation_scope(candidate_scope)?;
        let install = self.prepare_combined_scope_install(candidate)?;
        self.install_combined_scope(install);
        Ok(self
            .infrastructure
            .mint_reserved_device_ticket_after_install(reservation))
    }

    /// Reserves a device preparation through an opaque causal-workload
    /// session. The caller names the immediate business parent, but the
    /// Registry proves that its complete live ancestry terminates at the
    /// session's exact root before the infrastructure context is used.
    pub(crate) fn reserve_device_preparation_for_session(
        &mut self,
        session: &runtime_causal::CausalWorkloadSession,
        parent_effect: EffectKey,
        coordinates: DeviceReservationCoordinates,
    ) -> Result<DevicePreparationTicket, RegistryError> {
        let identity =
            self.verify_causal_workload_session(session)
                .map_err(|error| match error {
                    runtime_causal::CausalWorkloadError::Registry(error) => error,
                    runtime_causal::CausalWorkloadError::Infrastructure(error) => error.into(),
                    _ => RegistryError::InvalidHandle,
                })?;
        let mut cursor = Some(parent_effect);
        let mut rooted = false;
        while let Some(effect) = cursor {
            let record = self
                .effects
                .get(&effect)
                .ok_or(RegistryError::UnknownEffect)?;
            if record.identity.scope != identity.scope()
                || record.identity.authority_epoch != identity.authority_epoch
                || record.phase.is_terminal()
            {
                return Err(RegistryError::InvalidHandle);
            }
            if effect == identity.root_effect() {
                rooted = true;
                break;
            }
            cursor = record.identity.parent;
        }
        if !rooted {
            return Err(RegistryError::InvalidHandle);
        }
        self.reserve_device_preparation(
            session.infrastructure_context(),
            parent_effect,
            coordinates,
        )
    }

    /// Pre-hardware cancellation. The exact ticket is returned on every
    /// failure, including a stale combined candidate after staging.
    pub(crate) fn cancel_device_preparation(
        &mut self,
        ticket: infrastructure::DevicePreparationTicket,
    ) -> Result<(), DevicePreparationRegistryFailure<infrastructure::DevicePreparationTicket>> {
        let scope_key = ticket.scope();
        let coordinates = match self.infrastructure.device_preparation_coordinates(&ticket) {
            Ok(coordinates) => coordinates,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input: ticket,
                });
            }
        };
        let charges = coordinates.credit_charges();
        let mut candidate = match self.combined_scope_candidate(scope_key) {
            Ok(candidate) => candidate,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error,
                    input: ticket,
                });
            }
        };
        if let Err(error) = candidate.replacement.scopes[&scope_key]
            .credits
            .validate_release(&charges, CreditState::Held)
        {
            return Err(DevicePreparationRegistryFailure {
                error,
                input: ticket,
            });
        }
        let prepared = match candidate
            .replacement
            .infrastructure
            .prepare_cancel_reserved_device_in_candidate(&ticket)
        {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input: ticket,
                });
            }
        };
        let candidate_scope = candidate.replacement.scopes.get_mut(&scope_key).unwrap();
        candidate_scope
            .credits
            .release_validated(&charges, CreditState::Held);
        if let Err(error) = advance_device_preparation_scope(candidate_scope) {
            return Err(DevicePreparationRegistryFailure {
                error,
                input: ticket,
            });
        }
        candidate
            .replacement
            .infrastructure
            .apply_cancel_reserved_device_in_candidate(prepared);
        let install = match self.prepare_combined_scope_install(candidate) {
            Ok(install) => install,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error,
                    input: ticket,
                });
            }
        };
        self.install_combined_scope(install);
        Ok(())
    }

    /// Installs the retained uncertainty owner before any hardware callback
    /// may run. The caller invokes hardware only after this method returns.
    pub(crate) fn begin_device_hardware_apply(
        &mut self,
        ticket: infrastructure::DevicePreparationTicket,
    ) -> Result<
        infrastructure::DeviceApplyIntent,
        DevicePreparationRegistryFailure<infrastructure::DevicePreparationTicket>,
    > {
        let scope_key = ticket.scope();
        let coordinates = match self.infrastructure.device_preparation_coordinates(&ticket) {
            Ok(coordinates) => coordinates,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input: ticket,
                });
            }
        };
        let charges = coordinates.credit_charges();
        let scope = match self.scopes.get(&scope_key) {
            Some(scope) => scope,
            None => {
                return Err(DevicePreparationRegistryFailure {
                    error: RegistryError::UnknownScope,
                    input: ticket,
                });
            }
        };
        if scope.phase != ScopePhase::Active {
            return Err(DevicePreparationRegistryFailure {
                error: RegistryError::ScopeNotActive,
                input: ticket,
            });
        }
        let mut candidate = match self.combined_scope_candidate(scope_key) {
            Ok(candidate) => candidate,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error,
                    input: ticket,
                });
            }
        };
        if let Err(error) = candidate.replacement.scopes[&scope_key]
            .credits
            .validate_retain(&charges, CreditState::Held)
        {
            return Err(DevicePreparationRegistryFailure {
                error,
                input: ticket,
            });
        }
        let prepared = match candidate
            .replacement
            .infrastructure
            .prepare_begin_device_hardware_apply_in_candidate(&ticket)
        {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input: ticket,
                });
            }
        };
        let candidate_scope = candidate.replacement.scopes.get_mut(&scope_key).unwrap();
        candidate_scope
            .credits
            .retain_validated(&charges, CreditState::Held);
        if let Err(error) = advance_device_preparation_scope(candidate_scope) {
            return Err(DevicePreparationRegistryFailure {
                error,
                input: ticket,
            });
        }
        candidate
            .replacement
            .infrastructure
            .apply_begin_device_hardware_apply_in_candidate(prepared);
        let install = match self.prepare_combined_scope_install(candidate) {
            Ok(install) => install,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error,
                    input: ticket,
                });
            }
        };
        self.install_combined_scope(install);
        Ok(self
            .infrastructure
            .mint_device_apply_intent_after_install(ticket))
    }

    /// Acknowledges exact rollback evidence and releases the retained credit
    /// owner in the same exact-scope install.
    pub(crate) fn acknowledge_device_apply_rollback(
        &mut self,
        intent: infrastructure::DeviceApplyIntent,
        rollback: infrastructure::DeviceRollbackReceipt,
    ) -> Result<
        infrastructure::DeviceRollbackReceipt,
        DevicePreparationRegistryFailure<infrastructure::DeviceApplyIntent>,
    > {
        let scope_key = intent.scope();
        let coordinates = match self.infrastructure.device_apply_coordinates(&intent) {
            Ok(coordinates) => coordinates,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input: intent,
                });
            }
        };
        let charges = coordinates.credit_charges();
        let mut candidate = match self.combined_scope_candidate(scope_key) {
            Ok(candidate) => candidate,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error,
                    input: intent,
                });
            }
        };
        if let Err(error) = candidate.replacement.scopes[&scope_key]
            .credits
            .validate_release(&charges, CreditState::Retained)
        {
            return Err(DevicePreparationRegistryFailure {
                error,
                input: intent,
            });
        }
        let prepared = match candidate
            .replacement
            .infrastructure
            .prepare_device_apply_rollback_in_candidate(&intent, rollback)
        {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input: intent,
                });
            }
        };
        let candidate_scope = candidate.replacement.scopes.get_mut(&scope_key).unwrap();
        candidate_scope
            .credits
            .release_validated(&charges, CreditState::Retained);
        if let Err(error) = advance_device_preparation_scope(candidate_scope) {
            return Err(DevicePreparationRegistryFailure {
                error,
                input: intent,
            });
        }
        candidate
            .replacement
            .infrastructure
            .apply_device_apply_rollback_in_candidate(prepared, rollback);
        let install = match self.prepare_combined_scope_install(candidate) {
            Ok(install) => install,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error,
                    input: intent,
                });
            }
        };
        self.install_combined_scope(install);
        Ok(rollback)
    }

    /// Hardware acknowledgement contains no callback and leaves the exact
    /// retained owner queryable for materialization or recovery.
    pub(crate) fn acknowledge_device_prepared(
        &mut self,
        intent: infrastructure::DeviceApplyIntent,
        receipt: infrastructure::DeviceHardwareReceipt,
    ) -> Result<
        infrastructure::PreparedDeviceTicket,
        DevicePreparationRegistryFailure<infrastructure::DeviceApplyIntent>,
    > {
        let scope_key = intent.scope();
        let mut candidate = match self.combined_scope_candidate(scope_key) {
            Ok(candidate) => candidate,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error,
                    input: intent,
                });
            }
        };
        let prepared = match candidate
            .replacement
            .infrastructure
            .prepare_device_prepared_in_candidate(&intent, receipt)
        {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input: intent,
                });
            }
        };
        let candidate_scope = candidate.replacement.scopes.get_mut(&scope_key).unwrap();
        if let Err(error) = advance_device_preparation_scope(candidate_scope) {
            return Err(DevicePreparationRegistryFailure {
                error,
                input: intent,
            });
        }
        candidate
            .replacement
            .infrastructure
            .apply_device_prepared_in_candidate(prepared, receipt);
        let install = match self.prepare_combined_scope_install(candidate) {
            Ok(install) => install,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error,
                    input: intent,
                });
            }
        };
        self.install_combined_scope(install);
        Ok(self
            .infrastructure
            .mint_prepared_device_ticket_after_install(intent))
    }

    /// Provider-neutral acknowledgement of one hardware preparation view.
    /// The private infrastructure bridge reconstructs and validates every
    /// Registry coordinate before it can mint retained hardware evidence.
    pub(crate) fn acknowledge_device_prepared_from_view(
        &mut self,
        intent: DeviceApplyIntent,
        receipt_view: &(impl DevicePreparedReceiptView + ?Sized),
    ) -> Result<
        (PreparedDeviceTicket, PreparedDeviceIdentity),
        DevicePreparationRegistryFailure<DeviceApplyIntent>,
    > {
        let coordinates = match self.infrastructure.device_apply_coordinates(&intent) {
            Ok(coordinates) => coordinates,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input: intent,
                });
            }
        };
        let (receipt, prepared_identity) =
            match infrastructure::device_receipt_bridge::verify_preparation(
                coordinates,
                receipt_view,
            ) {
                Ok(verified) => verified,
                Err(error) => {
                    return Err(DevicePreparationRegistryFailure {
                        error: error.into(),
                        input: intent,
                    });
                }
            };
        self.acknowledge_device_prepared(intent, receipt)
            .map(|ticket| (ticket, prepared_identity))
    }

    /// Publishes a verified rollback view for one exact started attempt.
    pub(crate) fn acknowledge_device_rollback_from_view(
        &mut self,
        intent: DeviceApplyIntent,
        receipt_view: &(impl DeviceRollbackReceiptView + ?Sized),
    ) -> Result<(), DevicePreparationRegistryFailure<DeviceApplyIntent>> {
        let coordinates = match self.infrastructure.device_apply_coordinates(&intent) {
            Ok(coordinates) => coordinates,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input: intent,
                });
            }
        };
        let rollback =
            match infrastructure::device_receipt_bridge::verify_rollback(coordinates, receipt_view)
            {
                Ok(rollback) => rollback,
                Err(error) => {
                    return Err(DevicePreparationRegistryFailure {
                        error: error.into(),
                        input: intent,
                    });
                }
            };
        self.acknowledge_device_apply_rollback(intent, rollback)
            .map(|_| ())
    }

    /// Installs a fail-closed preparation observation while preserving the
    /// retained queue/pinned/DMA credits. No prepared or materialized bearer
    /// can be minted from this state.
    pub(crate) fn retain_device_indeterminate_from_view(
        &mut self,
        intent: DeviceApplyIntent,
        observation: &(impl DeviceIndeterminateReceiptView + ?Sized),
    ) -> Result<u64, DevicePreparationRegistryFailure<DeviceApplyIntent>> {
        let scope_key = intent.scope();
        let coordinates = match self.infrastructure.device_apply_coordinates(&intent) {
            Ok(coordinates) => coordinates,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input: intent,
                });
            }
        };
        let (owner_id, sequence, observation_digest) =
            match infrastructure::device_receipt_bridge::verify_indeterminate(
                coordinates,
                observation,
            ) {
                Ok(verified) => verified,
                Err(error) => {
                    return Err(DevicePreparationRegistryFailure {
                        error: error.into(),
                        input: intent,
                    });
                }
            };
        let mut candidate = match self.combined_scope_candidate(scope_key) {
            Ok(candidate) => candidate,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error,
                    input: intent,
                });
            }
        };
        let prepared = match candidate
            .replacement
            .infrastructure
            .prepare_device_indeterminate_in_candidate(
                &intent,
                owner_id,
                sequence,
                observation_digest,
            ) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input: intent,
                });
            }
        };
        if let Err(error) = advance_device_preparation_scope(
            candidate.replacement.scopes.get_mut(&scope_key).unwrap(),
        ) {
            return Err(DevicePreparationRegistryFailure {
                error,
                input: intent,
            });
        }
        candidate
            .replacement
            .infrastructure
            .apply_device_indeterminate_in_candidate(prepared);
        let install = match self.prepare_combined_scope_install(candidate) {
            Ok(install) => install,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error,
                    input: intent,
                });
            }
        };
        self.install_combined_scope(install);
        Ok(observation_digest)
    }

    pub(crate) fn query_device_preparation(
        &self,
        context: &infrastructure::WorkloadContext,
        preparation_id: u64,
        generation: u64,
    ) -> Result<infrastructure::DevicePreparationRecoveryProjection, RegistryError> {
        self.check_invariants()?;
        self.infrastructure
            .query_device_preparation(context, preparation_id, generation)
            .map_err(Into::into)
    }

    pub(crate) fn query_device_preparation_for_session(
        &self,
        session: &runtime_causal::CausalWorkloadSession,
        preparation_id: u64,
        generation: u64,
    ) -> Result<DevicePreparationRecoveryProjection, RegistryError> {
        self.verify_causal_workload_session(session)
            .map_err(|error| match error {
                runtime_causal::CausalWorkloadError::Registry(error) => error,
                runtime_causal::CausalWorkloadError::Infrastructure(error) => error.into(),
                _ => RegistryError::InvalidHandle,
            })?;
        self.query_device_preparation(session.infrastructure_context(), preparation_id, generation)
    }

    /// Atomically transfers one exact `PreparedRetained` authority into the
    /// fixed block-plus-three-DMA business cohort. The temporary implementation
    /// stages a private full Registry replacement, so candidate construction is
    /// still O(N) and allocator-pressure handling is not yet a production
    /// claim. The final linearization itself performs no allocation or callback.
    pub(crate) fn materialize_device_cohort_from_preparation(
        &mut self,
        ticket: infrastructure::PreparedDeviceTicket,
        prepared: infrastructure::PreparedDeviceIdentity,
        entries: [DeviceDerivedCohortEntry; 4],
    ) -> Result<
        DeviceCohortMaterialization,
        DevicePreparationRegistryFailure<infrastructure::PreparedDeviceTicket>,
    > {
        let plan = self.prepare_device_cohort_materialization(ticket, prepared, entries)?;
        self.apply_device_cohort_materialization(plan)
    }

    fn prepare_device_cohort_materialization(
        &self,
        ticket: infrastructure::PreparedDeviceTicket,
        prepared: infrastructure::PreparedDeviceIdentity,
        entries: [DeviceDerivedCohortEntry; 4],
    ) -> Result<
        DeviceCohortMaterializationPlan,
        DevicePreparationRegistryFailure<infrastructure::PreparedDeviceTicket>,
    > {
        let scope_key = ticket.scope();
        let scope = match self.scopes.get(&scope_key) {
            Some(scope) => scope,
            None => {
                return Err(DevicePreparationRegistryFailure {
                    error: RegistryError::UnknownScope,
                    input: ticket,
                });
            }
        };
        if scope.phase != ScopePhase::Active {
            return Err(DevicePreparationRegistryFailure {
                error: RegistryError::ScopeNotActive,
                input: ticket,
            });
        }
        let authority = match self.infrastructure.prepare_device_materialization(ticket) {
            Ok(authority) => authority,
            Err(failure) => {
                let (error, input) = failure.into_parts();
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input,
                });
            }
        };
        let description = match self
            .infrastructure
            .describe_device_materialization(&authority)
        {
            Ok(description) => description,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input: authority.into_prepared_device_ticket(),
                });
            }
        };
        if description.prepared != prepared {
            return Err(DevicePreparationRegistryFailure {
                error: RegistryError::InvalidHandle,
                input: authority.into_prepared_device_ticket(),
            });
        }
        let entries = match validate_prepared_device_cohort_entries(description, prepared, entries)
        {
            Ok(entries) => entries,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error,
                    input: authority.into_prepared_device_ticket(),
                });
            }
        };

        let base = self.clone();
        let mut candidate = self.clone();
        candidate.infrastructure = match self.infrastructure.try_private_candidate() {
            Ok(infrastructure) => infrastructure,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input: authority.into_prepared_device_ticket(),
                });
            }
        };
        let registered = match candidate.register_prepared_device_cohort(description, entries) {
            Ok(registered) => registered,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error,
                    input: authority.into_prepared_device_ticket(),
                });
            }
        };
        let cohort = device_cohort_identity(prepared, &registered);
        let materialization = match candidate
            .infrastructure
            .prepare_materialize_device_in_candidate(&authority, cohort)
        {
            Ok(materialization) => materialization,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input: authority.into_prepared_device_ticket(),
                });
            }
        };
        candidate
            .infrastructure
            .apply_materialize_device_in_candidate(materialization, cohort);
        if let Err(error) = candidate.check_invariants() {
            return Err(DevicePreparationRegistryFailure {
                error,
                input: authority.into_prepared_device_ticket(),
            });
        }
        Ok(DeviceCohortMaterializationPlan {
            base,
            candidate,
            authority,
            registered,
            cohort,
        })
    }

    fn apply_device_cohort_materialization(
        &mut self,
        plan: DeviceCohortMaterializationPlan,
    ) -> Result<
        DeviceCohortMaterialization,
        DevicePreparationRegistryFailure<infrastructure::PreparedDeviceTicket>,
    > {
        let DeviceCohortMaterializationPlan {
            base,
            mut candidate,
            authority,
            registered,
            cohort,
        } = plan;
        let scope_key = authority.scope();
        let scope = match self.scopes.get(&scope_key) {
            Some(scope) => scope,
            None => {
                return Err(DevicePreparationRegistryFailure {
                    error: RegistryError::UnknownScope,
                    input: authority.into_prepared_device_ticket(),
                });
            }
        };
        if scope.phase != ScopePhase::Active {
            return Err(DevicePreparationRegistryFailure {
                error: RegistryError::ScopeNotActive,
                input: authority.into_prepared_device_ticket(),
            });
        }
        if self != &base {
            return Err(DevicePreparationRegistryFailure {
                error: RegistryError::CombinedCandidateStale,
                input: authority.into_prepared_device_ticket(),
            });
        }
        if let Err(error) = candidate.check_invariants() {
            return Err(DevicePreparationRegistryFailure {
                error,
                input: authority.into_prepared_device_ticket(),
            });
        }
        if let Err(error) = candidate
            .infrastructure
            .validate_materialized_device_candidate(&authority, cohort)
        {
            return Err(DevicePreparationRegistryFailure {
                error: error.into(),
                input: authority.into_prepared_device_ticket(),
            });
        }
        if let Err(error) = candidate
            .infrastructure
            .promote_full_candidate_for_install()
        {
            return Err(DevicePreparationRegistryFailure {
                error: error.into(),
                input: authority.into_prepared_device_ticket(),
            });
        }

        *self = candidate;
        let materialized = self
            .infrastructure
            .mint_materialized_device_ticket_after_install(authority, cohort);
        Ok(DeviceCohortMaterialization {
            registered,
            authority: materialized,
            cohort,
        })
    }

    fn register_prepared_device_cohort(
        &mut self,
        description: infrastructure::PreparedDeviceDescription,
        entries: [DeviceDerivedCohortEntry; 4],
    ) -> Result<[RegisteredEffect; 4], RegistryError> {
        let [block_entry, dma_a_entry, dma_b_entry, dma_request_entry] = entries;
        let block = self.register_in_domain_with_credit_source(
            block_entry.request,
            block_entry.domain,
            Some(description.parent_effect),
            Some(block_entry.device),
            false,
            RegistrationCreditSource::TransferRetainedPreparation,
        )?;
        let block_effect = block.identity.effect();
        let dma_a = self.register_in_domain_with_credit_source(
            dma_a_entry.request,
            dma_a_entry.domain,
            Some(block_effect),
            Some(dma_a_entry.device),
            false,
            RegistrationCreditSource::TransferRetainedPreparation,
        )?;
        let dma_b = self.register_in_domain_with_credit_source(
            dma_b_entry.request,
            dma_b_entry.domain,
            Some(block_effect),
            Some(dma_b_entry.device),
            false,
            RegistrationCreditSource::TransferRetainedPreparation,
        )?;
        let dma_request = self.register_in_domain_with_credit_source(
            dma_request_entry.request,
            dma_request_entry.domain,
            Some(block_effect),
            Some(dma_request_entry.device),
            false,
            RegistrationCreditSource::TransferRetainedPreparation,
        )?;
        Ok([block, dma_a, dma_b, dma_request])
    }

    /// Prepares the one task-owned fault plan which may later enter the
    /// specialized business/infrastructure install below.  No Registry state
    /// changes here and every failure returns the exact armed task authority.
    pub(crate) fn prepare_service_fault_disposition(
        &self,
        armed: infrastructure::ArmedFaultTask,
        observation: infrastructure::FaultObservation,
        disposition: infrastructure::FaultDisposition,
    ) -> Result<
        (
            infrastructure::FaultDispositionIntent,
            infrastructure::FaultDispositionPlan,
        ),
        FaultRegistryFailure,
    > {
        let (scope_key, descriptor) = match self.infrastructure.describe_armed_fault(&armed) {
            Ok(description) => description,
            Err(error) => {
                return Err(FaultRegistryFailure {
                    error: error.into(),
                    input: armed,
                });
            }
        };
        let scope = match self.scopes.get(&scope_key) {
            Some(scope) => scope,
            None => {
                return Err(FaultRegistryFailure {
                    error: RegistryError::UnknownScope,
                    input: armed,
                });
            }
        };
        if scope.phase != ScopePhase::Active {
            return Err(FaultRegistryFailure {
                error: RegistryError::ScopeNotActive,
                input: armed,
            });
        }
        let binding = match scope.domains.get(&descriptor.service_domain) {
            Some(binding) => binding,
            None => {
                return Err(FaultRegistryFailure {
                    error: RegistryError::UnknownDomain,
                    input: armed,
                });
            }
        };
        if binding.quarantine.is_some() {
            return Err(FaultRegistryFailure {
                error: RegistryError::DomainQuarantined,
                input: armed,
            });
        }
        if binding.binding_epoch != descriptor.admission_binding_epoch {
            return Err(FaultRegistryFailure {
                error: RegistryError::StaleBinding,
                input: armed,
            });
        }
        if disposition == infrastructure::FaultDisposition::CrashService
            && (binding.supervisor != Some(descriptor.task) || binding.fallback_running)
        {
            return Err(FaultRegistryFailure {
                error: RegistryError::NoSupervisor,
                input: armed,
            });
        }
        let cohort = self
            .production
            .by_domain
            .get(&(scope_key, descriptor.service_domain));
        let cohort_identity = match domain_cohort_identity(cohort) {
            Ok(identity) => identity,
            Err(_) => {
                return Err(FaultRegistryFailure {
                    error: RegistryError::CounterOverflow,
                    input: armed,
                });
            }
        };
        let business = infrastructure::FaultBusinessPlan {
            scope_revision: scope.revision,
            domain_revision: binding.revision,
            supervisor: binding.supervisor,
            fallback_running: binding.fallback_running,
            cohort_digest: cohort_identity.digest,
            cohort_count: cohort_identity.len,
        };
        self.infrastructure
            .prepare_fault_disposition_with_business(armed, observation, disposition, business)
            .map_err(|failure| {
                let (error, input) = failure.into_parts();
                FaultRegistryFailure {
                    error: error.into(),
                    input,
                }
            })
    }

    /// Specialized exact-scope transaction for a task-owned fault.  The
    /// candidate receives only a copyable plan, never bearer authority.  The
    /// final live install is two prevalidated existing-slot replacements and
    /// is therefore allocation-free and infallible.
    pub(crate) fn install_service_fault_disposition(
        &mut self,
        intent: infrastructure::FaultDispositionIntent,
        plan: infrastructure::FaultDispositionPlan,
    ) -> Result<infrastructure::InstalledFaultObservation, FaultRegistryFailure> {
        let prepared = (|| -> Result<_, RegistryError> {
            self.infrastructure
                .validate_fault_disposition_intent(&intent, plan)?;
            let live_scope = self
                .scopes
                .get(&plan.scope)
                .ok_or(RegistryError::UnknownScope)?;
            let live_binding = live_scope
                .domains
                .get(&plan.projection.service_domain)
                .ok_or(RegistryError::UnknownDomain)?;
            if live_binding.quarantine.is_some() {
                return Err(RegistryError::DomainQuarantined);
            }
            let cohort = self
                .production
                .by_domain
                .get(&(plan.scope, plan.projection.service_domain));
            let cohort_identity = domain_cohort_identity(cohort)?;
            let current_business = infrastructure::FaultBusinessPlan {
                scope_revision: live_scope.revision,
                domain_revision: live_binding.revision,
                supervisor: live_binding.supervisor,
                fallback_running: live_binding.fallback_running,
                cohort_digest: cohort_identity.digest,
                cohort_count: cohort_identity.len,
            };
            if current_business != plan.business || live_scope.phase != ScopePhase::Active {
                return Err(RegistryError::CombinedCandidateStale);
            }

            let mut candidate = self.combined_scope_candidate(plan.scope)?;
            if plan.projection.disposition == infrastructure::FaultDisposition::CrashService {
                let scope = candidate
                    .replacement
                    .scopes
                    .get_mut(&plan.scope)
                    .ok_or(RegistryError::UnknownScope)?;
                let next_scope_revision = scope
                    .revision
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
                let binding = scope
                    .domains
                    .get_mut(&plan.projection.service_domain)
                    .ok_or(RegistryError::UnknownDomain)?;
                if binding.quarantine.is_some() {
                    return Err(RegistryError::DomainQuarantined);
                }
                let next_domain_revision = binding
                    .revision
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
                if binding.supervisor != Some(plan.projection.task)
                    || binding.fallback_running
                    || next_domain_revision != plan.projection.crash_generation
                {
                    return Err(RegistryError::NoSupervisor);
                }
                let cohort = candidate
                    .replacement
                    .production
                    .by_domain
                    .get(&(plan.scope, plan.projection.service_domain))
                    .cloned()
                    .unwrap_or_default();
                scope.revision = next_scope_revision;
                binding.binding_epoch = binding
                    .binding_epoch
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
                binding.supervisor = None;
                binding.fallback_running = true;
                binding.revision = next_domain_revision;
                binding.recovery = Some(DomainRecoveryState {
                    crash_revision: next_domain_revision,
                    cohort: cohort.clone(),
                    unadopted: cohort,
                    snapshot: None,
                    ready: None,
                    highest_attempt: 0,
                    last_abort: None,
                    origin: DomainRecoveryOrigin::ServiceFault(DomainFaultRecoveryAnchor {
                        fault_id: plan.projection.fault_id,
                        generation: plan.projection.generation,
                        task: plan.projection.task,
                        vm_generation: plan.projection.vm_generation,
                        evidence_digest: plan.projection.evidence_digest,
                        plan_commitment: plan.commitment.0,
                    }),
                });
                scope.invalidate_recovery_readiness();
            }
            let applied = candidate
                .replacement
                .infrastructure
                .apply_fault_disposition_in_candidate(plan)
                .map_err(RegistryError::Infrastructure)?;
            let install = self.prepare_combined_scope_install(candidate)?;
            Ok((install, applied))
        })();

        match prepared {
            Ok((install, applied)) => {
                self.install_combined_scope(install);
                Ok(applied.into_installed())
            }
            Err(error) => Err(FaultRegistryFailure {
                error,
                input: intent.armed,
            }),
        }
    }

    /// First usable outer transaction skeleton.  It supports scope-record
    /// mutations on both ledgers while requiring target EffectRecords, index
    /// shape, and global allocators to remain unchanged.  Fault/device paths
    /// must not use it until the follow-on same-key EffectRecord replacement
    /// and full infrastructure recomputation tranche lands.
    fn combined_scope_transaction(
        &mut self,
        scope_key: ScopeKey,
        stage: impl FnOnce(&mut combined_scope_editor::Editor<'_>) -> Result<(), RegistryError>,
    ) -> Result<(), RegistryError> {
        let mut candidate = self.combined_scope_candidate(scope_key)?;
        stage(&mut combined_scope_editor::Editor::new(&mut candidate))?;
        let plan = self.prepare_combined_scope_install(candidate)?;
        self.install_combined_scope(plan);
        Ok(())
    }

    fn prepare_combined_scope_install(
        &self,
        mut candidate: CombinedScopeCandidate,
    ) -> Result<CombinedScopeInstallPlan, RegistryError> {
        self.check_invariants()?;
        if candidate.registry_instance != self.instance_id
            || candidate.scope != candidate.base_infrastructure.scope
        {
            return Err(RegistryError::CombinedCandidateStale);
        }
        let live_scope = self
            .scopes
            .get(&candidate.scope)
            .ok_or(RegistryError::UnknownScope)?;
        if live_scope.revision != candidate.base_registry_revision {
            return Err(RegistryError::CombinedCandidateStale);
        }

        candidate.replacement.check_invariants()?;
        if candidate.replacement.instance_id != self.instance_id
            || candidate.replacement.scopes.len() != 1
            || !candidate.replacement.scopes.contains_key(&candidate.scope)
            || candidate.replacement.device_publication_mode != self.device_publication_mode
        {
            return Err(RegistryError::CombinedCandidateShapeChanged);
        }

        // Foundation-only shape gate: effect values and every derived index
        // remain exactly those of the live target scope.  This makes the final
        // install two existing-slot replacements and prevents an unrelated
        // tenant or global allocator from being overwritten.
        let mut live_effect_count = 0_usize;
        for (key, record) in self
            .effects
            .iter()
            .filter(|(_, record)| record.identity.scope == candidate.scope)
        {
            live_effect_count = live_effect_count
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
            if candidate.replacement.effects.get(key) != Some(record) {
                return Err(RegistryError::CombinedCandidateShapeChanged);
            }
        }
        if candidate.replacement.effects.len() != live_effect_count
            || candidate.replacement.next_effect_id != self.next_effect_id
            || candidate.replacement.next_nonce != self.next_nonce
            || candidate.replacement.next_commit_sequence != self.next_commit_sequence
            || candidate.replacement.next_device_enrollment_sequence
                != self.next_device_enrollment_sequence
            || candidate.replacement.next_device_batch_sequence != self.next_device_batch_sequence
            || candidate.replacement.next_device_closure_sequence
                != self.next_device_closure_sequence
            || candidate.replacement.next_terminal_sequence != self.next_terminal_sequence
            || candidate.replacement.next_publication_sequence != self.next_publication_sequence
            || candidate.replacement.next_revoke_sequence != self.next_revoke_sequence
        {
            return Err(RegistryError::CombinedCandidateShapeChanged);
        }

        let infrastructure = self.infrastructure.prepare_exact_scope_install(
            candidate.scope,
            candidate.base_infrastructure,
            &mut candidate.replacement.infrastructure,
        )?;
        let replacement_scope = candidate
            .replacement
            .scopes
            .remove(&candidate.scope)
            .ok_or(RegistryError::CombinedCandidateShapeChanged)?;
        Ok(CombinedScopeInstallPlan {
            scope: candidate.scope,
            replacement_scope,
            infrastructure,
        })
    }

    /// No allocation, validation, user callback, or `Result` remains here.
    /// The live Registry retains authority throughout; neither candidate is
    /// ever promoted as a whole.
    fn install_combined_scope(&mut self, plan: CombinedScopeInstallPlan) {
        __cser_core::debug_assert!(self.scopes.contains_key(&plan.scope));
        *self.scopes.get_mut(&plan.scope).unwrap() = plan.replacement_scope;
        self.infrastructure.install_exact_scope(plan.infrastructure);
    }

    /// Installs a successfully revoked single-scope transaction without any
    /// allocation or fallible transition after live state begins to change.
    fn install_revoked_scope_candidate(
        &mut self,
        scope_key: ScopeKey,
        mut candidate: Self,
    ) -> Result<(), RegistryError> {
        candidate.check_invariants()?;
        if candidate.instance_id != self.instance_id
            || candidate.scopes.len() != 1
            || !candidate.scopes.contains_key(&scope_key)
        {
            return Err(RegistryError::CombinedCandidateShapeChanged);
        }
        let infrastructure = match (
            self.infrastructure.is_enabled(scope_key),
            candidate.infrastructure.is_enabled(scope_key),
        ) {
            (true, true) => {
                let base = self.infrastructure.root_binding(scope_key)?;
                Some(self.infrastructure.prepare_exact_scope_install(
                    scope_key,
                    base,
                    &mut candidate.infrastructure,
                )?)
            }
            (false, false) => None,
            _ => {
                return Err(RegistryError::CombinedCandidateShapeChanged);
            }
        };
        let live_scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        self.validate_live_scope_replacement_indexes(scope_key, live_scope)?;
        let keys = live_scope
            .closure_candidates
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let replacement_scope = candidate
            .scopes
            .remove(&scope_key)
            .filter(|scope| scope.phase == ScopePhase::Revoked)
            .ok_or(RegistryError::InvalidState)?;
        let mut replacements = Vec::with_capacity(keys.len());
        for key in &keys {
            if !self.effects.contains_key(key) {
                return Err(RegistryError::UnknownEffect);
            }
            let replacement = candidate
                .effects
                .remove(key)
                .ok_or(RegistryError::UnknownEffect)?;
            replacements.push((*key, replacement));
        }
        if candidate.effects.iter().any(|(key, record)| {
            keys.contains(key)
                || record.identity.scope != scope_key
                || self.effects.get(key) != Some(record)
        }) || !candidate.by_scope.is_empty()
            || !candidate.by_task.is_empty()
            || !candidate.by_resource.is_empty()
            || !candidate.production.by_domain.is_empty()
            || !candidate.production.children_by_parent.is_empty()
            || !candidate.production.leaves_by_scope.is_empty()
        {
            return Err(RegistryError::CombinedCandidateShapeChanged);
        }

        for key in &keys {
            let record = &self.effects[key];
            remove_index_member(&mut self.by_task, record.identity.task, *key);
            for resource in &record.current_resources {
                remove_index_member(&mut self.by_resource, *resource, *key);
            }
            if let Some(parent) = record.identity.parent {
                remove_index_member(&mut self.production.children_by_parent, parent, *key);
            }
        }
        self.by_scope.remove(&scope_key);
        self.production
            .by_domain
            .retain(|(scope, _), _| *scope != scope_key);
        self.production.leaves_by_scope.remove(&scope_key);
        for key in &keys {
            self.production.children_by_parent.remove(key);
        }
        for (key, replacement) in replacements {
            *self
                .effects
                .get_mut(&key)
                .expect("prevalidated replacement effect remains present") = replacement;
        }
        *self
            .scopes
            .get_mut(&scope_key)
            .expect("prevalidated replacement scope remains present") = replacement_scope;
        if let Some(infrastructure) = infrastructure {
            self.infrastructure.install_exact_scope(infrastructure);
        }
        self.next_terminal_sequence = candidate.next_terminal_sequence;
        self.next_publication_sequence = candidate.next_publication_sequence;
        self.next_revoke_sequence = candidate.next_revoke_sequence;
        Ok(())
    }

    /// Checks every index entry which the infallible exact-scope install will
    /// remove. The walk is bounded by this scope's effects, domains, resources,
    /// and causal children; it never scans unrelated effect history.
    fn validate_live_scope_replacement_indexes(
        &self,
        scope_key: ScopeKey,
        scope: &ScopeRecord,
    ) -> Result<(), RegistryError> {
        let keys = &scope.closure_candidates;
        if scope.phase != ScopePhase::Active
            || scope.revoke.is_some()
            || self.by_scope.get(&scope_key) != Some(keys)
        {
            return Err(RegistryError::CombinedCandidateShapeChanged);
        }

        let leaves = self.production.leaves_by_scope.get(&scope_key);
        let mut expected_leaf_count = 0_usize;
        for key in keys {
            let record = self
                .effects
                .get(key)
                .ok_or(RegistryError::CombinedCandidateShapeChanged)?;
            if record.identity.scope != scope_key
                || record.phase.is_terminal()
                || self
                    .by_task
                    .get(&record.identity.task)
                    .is_none_or(|members| !members.contains(key))
                || record.current_resources.iter().any(|resource| {
                    self.by_resource
                        .get(resource)
                        .is_none_or(|members| !members.contains(key))
                })
                || self
                    .production
                    .by_domain
                    .get(&(scope_key, record.identity.domain))
                    .is_none_or(|members| !members.contains(key))
                || record.identity.parent.is_some_and(|parent| {
                    self.production
                        .children_by_parent
                        .get(&parent)
                        .is_none_or(|members| !members.contains(key))
                })
            {
                return Err(RegistryError::CombinedCandidateShapeChanged);
            }

            let children = self.production.children_by_parent.get(key);
            if let Some(children) = children {
                if children.is_empty()
                    || children.iter().any(|child| {
                        !keys.contains(child)
                            || self
                                .effects
                                .get(child)
                                .is_none_or(|record| record.identity.parent != Some(*key))
                    })
                    || leaves.is_some_and(|leaves| leaves.contains(key))
                {
                    return Err(RegistryError::CombinedCandidateShapeChanged);
                }
            } else {
                expected_leaf_count = expected_leaf_count
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
                if leaves.is_none_or(|leaves| !leaves.contains(key)) {
                    return Err(RegistryError::CombinedCandidateShapeChanged);
                }
            }
        }
        if leaves.map_or(0, BTreeSet::len) != expected_leaf_count {
            return Err(RegistryError::CombinedCandidateShapeChanged);
        }

        for domain in scope.domains.keys() {
            let observed = self.production.by_domain.get(&(scope_key, *domain));
            let expected_count = keys
                .iter()
                .filter(|effect| self.effects[effect].identity.domain == *domain)
                .count();
            if observed.map_or(0, BTreeSet::len) != expected_count
                || observed.is_some_and(|members| {
                    members.iter().any(|effect| {
                        !keys.contains(effect)
                            || self.effects.get(effect).is_none_or(|record| {
                                record.identity.scope != scope_key
                                    || record.identity.domain != *domain
                            })
                    })
                })
            {
                return Err(RegistryError::CombinedCandidateShapeChanged);
            }
        }
        Ok(())
    }

    /// Clones a legacy composition candidate without duplicating device
    /// publication authority.
    ///
    /// The old bounded composition evaluators use clone/validate/swap for
    /// generic registry mutations. Their candidates may never attach a device
    /// envelope, mint a kernel root authority, or enter the production batch
    /// gate. This keeps `EffectRegistry` itself non-`Clone` while making that
    /// historical transaction shape explicit and fail closed.
    pub(super) fn clone_non_device_candidate(&self) -> Result<Self, RegistryError> {
        if self
            .scopes
            .values()
            .any(|scope| scope.device_root.is_some())
        {
            return Err(RegistryError::InvalidDeviceEnvelope);
        }
        let mut candidate = self.clone();
        candidate.device_publication_mode = DevicePublicationMode::DisabledNonDeviceCandidate;
        Ok(candidate)
    }

    fn require_unique_device_publication(&self) -> Result<(), RegistryError> {
        if self.device_publication_mode != DevicePublicationMode::Unique {
            return Err(RegistryError::InvalidDeviceEnvelope);
        }
        Ok(())
    }

    /// Returns the complete registry debug projection used by failure-atomic
    /// before/after checks. A registry without handoff history normalizes only
    /// its allocator-assigned namespace. Handoff receipts remain immutable
    /// authority in another crate, so a registry with any handoff state keeps
    /// its original namespace instead of creating a mixed synthetic identity.
    ///
    /// `instance_id` and the matching provenance field embedded in commit
    /// receipts intentionally distinguish otherwise identical live
    /// registries. They are authority, but their process-local allocation
    /// order is not semantic mutation within one registry. Diagnostic hashes
    /// must therefore remain stable when an earlier negative test creates and
    /// destroys an unrelated registry. The live object is never modified.
    pub(crate) fn failure_atomic_projection(&self) -> String {
        const NORMALIZED_REGISTRY_INSTANCE: u64 = 1;

        let mut normalized = self.clone();
        if normalized
            .scopes
            .values()
            .all(|scope| scope.handoff.is_none())
        {
            normalized.rewrite_registry_instance(NORMALIZED_REGISTRY_INSTANCE);
        }
        __cser_alloc::format!("{normalized:?}")
    }

    #[cfg(test)]
    pub(crate) fn set_scope_revision_for_handoff_test(&mut self, scope: ScopeKey, revision: u64) {
        self.scopes.get_mut(&scope).unwrap().revision = revision;
    }

    #[cfg(test)]
    pub(crate) fn set_next_terminal_sequence_for_handoff_test(&mut self, sequence: u64) {
        self.next_terminal_sequence = sequence;
    }

    fn rewrite_registry_instance(&mut self, registry_instance_id: u64) {
        __cser_core::assert_ne!(registry_instance_id, 0);
        __cser_core::assert!(
            self.scopes.values().all(|scope| scope.handoff.is_none()),
            "handoff authority receipts cannot be renamespaced"
        );
        self.instance_id = registry_instance_id;
        self.infrastructure
            .rewrite_private_registry_instance(registry_instance_id);
        for scope in self.scopes.values_mut() {
            for binding in scope.domains.values_mut() {
                if let Some(quarantine) = binding.quarantine.as_mut() {
                    quarantine.registry_instance_id = registry_instance_id;
                }
                if let Some(recovery) = binding.recovery.as_mut() {
                    if let Some(snapshot) = recovery.snapshot.as_mut() {
                        snapshot.registry_instance_id = registry_instance_id;
                    }
                    if let Some(abort) = recovery.last_abort.as_mut() {
                        abort.registry_instance_id = registry_instance_id;
                    }
                }
            }
            if let Some(device_root) = scope.device_root.as_mut() {
                device_root.rewrite_registry_instance(registry_instance_id);
            }
            if let Some(revoke) = scope.revoke.as_mut() {
                if let Some(infrastructure) = revoke.infrastructure.as_mut() {
                    infrastructure.rewrite_registry_instance(registry_instance_id);
                }
                if let Some(closure) = revoke.closure.as_mut() {
                    closure.rewrite_registry_instance(registry_instance_id);
                }
            }
        }
        for record in self.effects.values_mut() {
            if let Some(commit) = record.commit.as_mut() {
                commit.registry_instance_id = registry_instance_id;
            }
            if let Some(terminal) = record.terminal.as_mut()
                && let Some(causal_commit) = terminal.causal_commit.as_mut()
            {
                causal_commit.registry_instance_id = registry_instance_id;
            }
        }
    }

    pub(crate) fn create_scope(&mut self, config: ScopeConfig) -> Result<(), RegistryError> {
        validate_generation(config.key.generation)?;
        validate_generation(config.supervisor.generation)?;
        if config.authority_epoch == 0 || config.binding_epoch == 0 {
            return Err(RegistryError::InvalidGeneration);
        }
        if self.scopes.contains_key(&config.key) {
            return Err(RegistryError::ScopeAlreadyExists);
        }
        let credits = CreditLedger::new(&config.credits)?;
        let mut domains = BTreeMap::new();
        domains.insert(
            DomainKey::LEGACY,
            DomainBindingRecord {
                binding_epoch: config.binding_epoch,
                supervisor: Some(config.supervisor),
                fallback_running: false,
                revision: 0,
                recovery: None,
                quarantine: None,
            },
        );
        self.scopes.insert(
            config.key,
            Box::new(ScopeRecord {
                key: config.key,
                phase: ScopePhase::Active,
                authority_epoch: config.authority_epoch,
                binding_epoch: config.binding_epoch,
                supervisor: Some(config.supervisor),
                fallback_running: false,
                revision: 0,
                domain_revision: 0,
                credits,
                closure_candidates: BTreeSet::new(),
                handoff_candidates: BTreeSet::new(),
                pending_publications: 0,
                recovery: None,
                domains,
                revoke: None,
                device_root: None,
                handoff_gate: HandoffAdmissionGate::new(),
                handoff: None,
            }),
        );
        Ok(())
    }

    pub(crate) fn add_domain(
        &mut self,
        scope_key: ScopeKey,
        config: DomainConfig,
    ) -> Result<(), RegistryError> {
        validate_generation(config.supervisor.generation)?;
        if config.key == DomainKey::LEGACY || config.binding_epoch == 0 {
            return Err(RegistryError::InvalidGeneration);
        }
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        map_handoff_gate(scope.handoff_gate.require_open())?;
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        if scope.domains.contains_key(&config.key) {
            return Err(RegistryError::DomainAlreadyExists);
        }
        let next_revision = scope
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        self.scopes.get_mut(&scope_key).unwrap().domains.insert(
            config.key,
            DomainBindingRecord {
                binding_epoch: config.binding_epoch,
                supervisor: Some(config.supervisor),
                fallback_running: false,
                revision: 0,
                recovery: None,
                quarantine: None,
            },
        );
        let scope = self.scopes.get_mut(&scope_key).unwrap();
        scope.revision = next_revision;
        scope.invalidate_recovery_readiness();
        Ok(())
    }

    pub(crate) fn domain_projection(
        &self,
        scope_key: ScopeKey,
        domain: DomainKey,
    ) -> Result<DomainProjection, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        let binding = scope
            .domains
            .get(&domain)
            .ok_or(RegistryError::UnknownDomain)?;
        Ok(DomainProjection {
            binding_epoch: binding.binding_epoch,
            supervisor: binding.supervisor,
            fallback_running: binding.fallback_running,
            revision: binding.revision,
            live_effects: self
                .production
                .by_domain
                .get(&(scope_key, domain))
                .map_or(0, BTreeSet::len),
            recovery_remaining: binding
                .recovery
                .as_ref()
                .map_or(0, |recovery| recovery.unadopted.len()),
            recovery_attempt: binding
                .recovery
                .as_ref()
                .and_then(|recovery| recovery.snapshot.as_ref())
                .map(|snapshot| snapshot.attempt),
            last_aborted_attempt: binding
                .recovery
                .as_ref()
                .and_then(|recovery| recovery.last_abort)
                .map(DomainRecoveryAbortReceipt::attempt),
            quarantine: binding.quarantine,
        })
    }

    /// Reports whether device-backed registration has installed the unique
    /// root for this scope.  Hardware-only cancellation may proceed without a
    /// registry receipt only when this returns `false` for the exact scope.
    pub(crate) fn device_root_installed(&self, scope_key: ScopeKey) -> Result<bool, RegistryError> {
        Ok(self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?
            .device_root
            .is_some())
    }

    /// Mints the kernel-only authority used to linearize one root-wide device
    /// publication. Service-domain supervisors continue to use their opaque
    /// portal handles and cannot use this token to act on a different root or
    /// registry instance.
    pub(crate) fn kernel_root_authority(
        &self,
        scope_key: ScopeKey,
        owner: TaskKey,
    ) -> Result<KernelRootAuthority, RegistryError> {
        self.require_unique_device_publication()?;
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        map_handoff_gate(scope.handoff_gate.require_open())?;
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        if scope.supervisor != Some(owner) || scope.fallback_running {
            return Err(RegistryError::NoSupervisor);
        }
        Ok(KernelRootAuthority {
            registry_instance_id: self.instance_id,
            scope: scope_key,
            authority_epoch: scope.authority_epoch,
            owner,
        })
    }

    pub(crate) fn register(
        &mut self,
        request: RegisterRequest,
    ) -> Result<RegisteredEffect, RegistryError> {
        self.register_in_domain(request, DomainKey::LEGACY, None, None, false)
    }

    /// Registers an effect in the legacy service domain while preserving one
    /// already-authoritative parent identity.
    ///
    /// This is used by provider-neutral kernel portals whose wire contract has
    /// effect ancestry but no service-domain selector.  The parent key is
    /// resolved from an opaque Registry handle by the adapter; callers cannot
    /// manufacture it from wire fields.
    pub(crate) fn register_with_parent(
        &mut self,
        request: RegisterRequest,
        parent: Option<EffectKey>,
    ) -> Result<RegisteredEffect, RegistryError> {
        self.register_in_domain(request, DomainKey::LEGACY, parent, None, false)
    }

    /// Registers a provider effect whose committed terminalization is blocked
    /// until the Registry contains a determinate canonical outcome.
    pub(crate) fn register_with_parent_requiring_outcome(
        &mut self,
        request: RegisterRequest,
        parent: Option<EffectKey>,
    ) -> Result<RegisteredEffect, RegistryError> {
        self.register_in_domain(request, DomainKey::LEGACY, parent, None, true)
    }

    pub(crate) fn register_derived(
        &mut self,
        request: DerivedRegisterRequest,
    ) -> Result<RegisteredEffect, RegistryError> {
        if request.domain == DomainKey::LEGACY {
            return Err(RegistryError::InvalidState);
        }
        self.register_in_domain(request.request, request.domain, request.parent, None, false)
    }

    pub(crate) fn register_device_derived(
        &mut self,
        request: DeviceDerivedRegisterRequest,
    ) -> Result<RegisteredEffect, RegistryError> {
        self.require_unique_device_publication()?;
        if request.derived.domain == DomainKey::LEGACY {
            return Err(RegistryError::InvalidState);
        }
        request.device.validate()?;
        self.register_in_domain(
            request.derived.request,
            request.derived.domain,
            request.derived.parent,
            Some(request.device),
            false,
        )
    }

    fn register_in_domain(
        &mut self,
        request: RegisterRequest,
        domain: DomainKey,
        parent: Option<EffectKey>,
        device: Option<DeviceEnvelope>,
        outcome_required: bool,
    ) -> Result<RegisteredEffect, RegistryError> {
        self.register_in_domain_with_credit_source(
            request,
            domain,
            parent,
            device,
            outcome_required,
            RegistrationCreditSource::ReserveFree,
        )
    }

    fn register_in_domain_with_credit_source(
        &mut self,
        request: RegisterRequest,
        domain: DomainKey,
        parent: Option<EffectKey>,
        device: Option<DeviceEnvelope>,
        outcome_required: bool,
        credit_source: RegistrationCreditSource,
    ) -> Result<RegisteredEffect, RegistryError> {
        validate_generation(request.scope.generation)?;
        validate_generation(request.task.generation)?;
        for resource in &request.resources {
            validate_generation(resource.generation)?;
        }
        let credits = normalize_charges(&request.credits)?;
        let resources: BTreeSet<_> = request.resources.into_iter().collect();
        let (authority_epoch, binding_epoch, next_scope_revision) = {
            let scope = self
                .scopes
                .get(&request.scope)
                .ok_or(RegistryError::UnknownScope)?;
            map_handoff_gate(scope.handoff_gate.require_open())?;
            if scope.phase != ScopePhase::Active {
                return Err(RegistryError::ScopeNotActive);
            }
            let binding = scope
                .domains
                .get(&domain)
                .ok_or(RegistryError::UnknownDomain)?;
            if binding.quarantine.is_some() {
                return Err(RegistryError::DomainQuarantined);
            }
            if binding.supervisor.is_none() || binding.fallback_running {
                return Err(RegistryError::NoSupervisor);
            }
            if scope
                .device_root
                .as_ref()
                .is_some_and(|root| root.enrollment.is_some())
            {
                return Err(RegistryError::InvalidState);
            }
            if scope.device_root.is_some() && parent.is_none() {
                return Err(RegistryError::InvalidState);
            }
            if device.is_some() && scope.device_root.is_none() {
                let live = self.by_scope.get(&request.scope);
                let root_count = live.map_or(0, |effects| {
                    effects
                        .iter()
                        .filter(|effect| self.effects[effect].identity.parent.is_none())
                        .count()
                });
                if live.is_some_and(|effects| !effects.is_empty())
                    && (parent.is_none() || root_count != 1)
                {
                    return Err(RegistryError::InvalidState);
                }
            }
            if let (Some(device), Some(root)) = (device, scope.device_root.as_ref())
                && device != root.initial_device
            {
                return Err(device_envelope_mismatch(root.initial_device, device));
            }
            if device.is_some()
                && scope.device_root.is_none()
                && self.effects.values().any(|record| {
                    record.identity.scope == request.scope
                        && (record.commit.is_some() || record.phase.is_terminal())
                })
            {
                return Err(RegistryError::InvalidState);
            }
            let next_scope_revision = scope
                .revision
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
            (
                scope.authority_epoch,
                binding.binding_epoch,
                next_scope_revision,
            )
        };

        if let Some(parent) = parent {
            let record = self
                .effects
                .get(&parent)
                .ok_or(RegistryError::UnknownEffect)?;
            if record.identity.scope != request.scope
                || record.identity.authority_epoch != authority_epoch
                || record.phase.is_terminal()
            {
                return Err(RegistryError::InvalidHandle);
            }
            let parent_binding = self.scopes[&request.scope]
                .domains
                .get(&record.identity.domain)
                .ok_or(RegistryError::UnknownDomain)?;
            if record.identity.binding_epoch != parent_binding.binding_epoch {
                return Err(RegistryError::StaleBinding);
            }
            if device.is_some() {
                let mut ancestor = Some(parent);
                while let Some(effect) = ancestor {
                    let record = self
                        .effects
                        .get(&effect)
                        .ok_or(RegistryError::UnknownEffect)?;
                    if record.commit.is_some() || record.phase.is_terminal() {
                        return Err(RegistryError::InvalidState);
                    }
                    ancestor = record.identity.parent;
                }
            }
        }

        let effect_id = self.next_effect_id;
        let next_effect_id = effect_id
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let nonce = self.next_nonce;
        let next_nonce = nonce.checked_add(1).ok_or(RegistryError::CounterOverflow)?;

        let ledger = &mut self.scopes.get_mut(&request.scope).unwrap().credits;
        match credit_source {
            RegistrationCreditSource::ReserveFree => ledger.reserve(&credits)?,
            RegistrationCreditSource::TransferRetainedPreparation => {
                ledger.transfer_retained_to_held(&credits)?;
            }
        }
        self.next_effect_id = next_effect_id;
        self.next_nonce = next_nonce;
        let effect = EffectKey::new(effect_id, 1);
        let identity = EffectIdentity {
            effect,
            scope: request.scope,
            domain,
            parent,
            task: request.task,
            operation: request.operation,
            authority_epoch,
            origin_binding_epoch: binding_epoch,
            binding_epoch,
            device,
            resources,
        };
        let record = EffectRecord {
            identity: identity.clone(),
            current_resources: identity.resources.clone(),
            descriptor: request.descriptor,
            nonce,
            phase: EffectPhase::Registered,
            credits,
            credit_state: CreditState::Held,
            publication_mode: request.publication,
            commit: None,
            outcome: None,
            outcome_required,
            device_batch: None,
            terminal: None,
            pending_publication: None,
            terminalizations: 0,
            publication_acks: 0,
        };
        let handle = record.handle();
        self.insert_reverse_indexes(&record.identity, &record.current_resources);
        self.effects.insert(effect, record);
        let scope = self.scopes.get_mut(&request.scope).unwrap();
        if let Some(device) = device
            && scope.device_root.is_none()
        {
            scope.device_root = Some(DeviceRootState::pending(device));
        }
        scope.revision = next_scope_revision;
        scope.invalidate_recovery_readiness();
        Ok(RegisteredEffect { identity, handle })
    }

    /// Failure-atomically installs the fixed production block/DMA cohort.
    ///
    /// The returned order is always `[block, dma_a, dma_b, dma_request]`.
    /// Every allocation and every ordinary registration check happens in a
    /// private candidate first. The live apply is one infallible replacement,
    /// so a failure in any middle entry cannot leak a device root, credit,
    /// reverse-index member, or advanced counter.
    pub(crate) fn register_device_derived_cohort(
        &mut self,
        entries: [DeviceDerivedCohortEntry; 4],
    ) -> Result<[RegisteredEffect; 4], RegistryError> {
        self.require_unique_device_publication()?;
        let plan = self.prepare_device_derived_cohort(entries)?;
        Ok(self.apply_device_derived_cohort(plan))
    }

    fn prepare_device_derived_cohort(
        &self,
        entries: [DeviceDerivedCohortEntry; 4],
    ) -> Result<DeviceDerivedCohortPlan, RegistryError> {
        let mut slots = [None, None, None, None];
        for entry in entries {
            let batch_index = entry.batch_index;
            if batch_index >= slots.len() || slots[batch_index].is_some() {
                return Err(RegistryError::InvalidState);
            }
            if let DeviceCohortParent::BatchIndex(parent_index) = entry.parent
                && (parent_index >= slots.len() || parent_index >= batch_index)
            {
                return Err(RegistryError::InvalidState);
            }
            slots[batch_index] = Some(entry);
        }
        let [
            Some(block_entry),
            Some(dma_a_entry),
            Some(dma_b_entry),
            Some(dma_request_entry),
        ] = slots
        else {
            return Err(RegistryError::InvalidState);
        };
        let block_parent = match block_entry.parent {
            DeviceCohortParent::Existing(parent) => parent,
            DeviceCohortParent::BatchIndex(_) => return Err(RegistryError::InvalidState),
        };
        if dma_a_entry.parent != DeviceCohortParent::BatchIndex(0)
            || dma_b_entry.parent != DeviceCohortParent::BatchIndex(0)
            || dma_request_entry.parent != DeviceCohortParent::BatchIndex(0)
        {
            return Err(RegistryError::InvalidState);
        }

        let mut candidate = self.clone();
        let block = candidate.register_device_derived(DeviceDerivedRegisterRequest {
            derived: DerivedRegisterRequest {
                request: block_entry.request,
                domain: block_entry.domain,
                parent: Some(block_parent),
            },
            device: block_entry.device,
        })?;
        let block_effect = block.identity.effect();
        let dma_a = candidate.register_device_derived(DeviceDerivedRegisterRequest {
            derived: DerivedRegisterRequest {
                request: dma_a_entry.request,
                domain: dma_a_entry.domain,
                parent: Some(block_effect),
            },
            device: dma_a_entry.device,
        })?;
        let dma_b = candidate.register_device_derived(DeviceDerivedRegisterRequest {
            derived: DerivedRegisterRequest {
                request: dma_b_entry.request,
                domain: dma_b_entry.domain,
                parent: Some(block_effect),
            },
            device: dma_b_entry.device,
        })?;
        let dma_request = candidate.register_device_derived(DeviceDerivedRegisterRequest {
            derived: DerivedRegisterRequest {
                request: dma_request_entry.request,
                domain: dma_request_entry.domain,
                parent: Some(block_effect),
            },
            device: dma_request_entry.device,
        })?;
        candidate.check_invariants()?;
        Ok(DeviceDerivedCohortPlan {
            candidate,
            registered: [block, dma_a, dma_b, dma_request],
        })
    }

    fn apply_device_derived_cohort(
        &mut self,
        plan: DeviceDerivedCohortPlan,
    ) -> [RegisteredEffect; 4] {
        let DeviceDerivedCohortPlan {
            candidate,
            registered,
        } = plan;
        *self = candidate;
        registered
    }

    pub(crate) fn descriptor(
        &self,
        sender: TaskKey,
        handle: PortalHandle,
    ) -> Result<SyscallDescriptor, RegistryError> {
        let effect = self.validate_portal(sender, handle)?;
        Ok(self.effects.get(&effect).unwrap().descriptor)
    }

    pub(crate) fn effect_view(&self, effect: EffectKey) -> Result<EffectView, RegistryError> {
        self.effects
            .get(&effect)
            .map(EffectRecord::view)
            .ok_or(RegistryError::UnknownEffect)
    }

    pub(crate) fn prepare(
        &mut self,
        sender: TaskKey,
        handle: PortalHandle,
    ) -> Result<(), RegistryError> {
        let effect = self.validate_portal(sender, handle)?;
        let scope = self.effects.get(&effect).unwrap().identity.scope;
        match self.effects.get(&effect).unwrap().phase {
            EffectPhase::Registered => {
                let next_scope_revision = self.scopes[&scope]
                    .revision
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
                self.effects.get_mut(&effect).unwrap().phase = EffectPhase::Prepared;
                let scope = self.scopes.get_mut(&scope).unwrap();
                scope.revision = next_scope_revision;
                scope.invalidate_recovery_readiness();
                Ok(())
            }
            EffectPhase::Prepared => Ok(()),
            EffectPhase::Committed => Err(RegistryError::InvalidState),
            EffectPhase::Terminal(_) => Err(RegistryError::AlreadyTerminal),
        }
    }

    /// Publishes one domain-owned state revision into recovery freshness.
    ///
    /// Domain state and this update are serialized by the caller's outer
    /// runtime lock.  Revisions must be consecutive so a forgotten domain
    /// publication cannot silently produce an apparently exact snapshot.
    pub(crate) fn domain_changed(
        &mut self,
        scope_key: ScopeKey,
        domain_revision: u64,
    ) -> Result<(), RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        map_handoff_gate(scope.handoff_gate.require_open())?;
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        let expected = scope
            .domain_revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        if domain_revision != expected {
            return Err(RegistryError::InvalidState);
        }
        let revision = scope
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let scope = self.scopes.get_mut(&scope_key).unwrap();
        scope.domain_revision = domain_revision;
        scope.revision = revision;
        scope.invalidate_recovery_readiness();
        Ok(())
    }

    pub(crate) fn commit(
        &mut self,
        sender: TaskKey,
        handle: PortalHandle,
        metadata: CommitMetadata,
    ) -> Result<CommitOutcome, RegistryError> {
        Ok(self
            .commit_with_moves(sender, &[(handle, metadata)], &[])?
            .pop()
            .expect("one commit produces one outcome"))
    }

    /// Atomically advances one provider-domain revision and commits one
    /// prepared effect against that exact revision.
    pub(crate) fn commit_after_domain_change(
        &mut self,
        sender: TaskKey,
        handle: PortalHandle,
        metadata: CommitMetadata,
    ) -> Result<CommitOutcome, RegistryError> {
        Ok(self
            .commit_with_moves_inner(
                sender,
                &[(handle, metadata)],
                &[],
                Some(metadata.domain_revision),
            )?
            .pop()
            .expect("one commit produces one outcome"))
    }

    /// Attaches one canonical backend outcome to an already committed effect.
    ///
    /// The outcome is Registry state, not adapter-local lifecycle state.  An
    /// exact repeat is idempotent; any different class, result, or digest for
    /// the same committed effect is a permanent commit conflict.  The scope
    /// revision advances only for the first accepted record.
    pub(crate) fn record_outcome(
        &mut self,
        sender: TaskKey,
        handle: PortalHandle,
        outcome: EffectOutcomeRecord,
    ) -> Result<EffectOutcomeRecord, RegistryError> {
        let effect = self.validate_portal(sender, handle)?;
        let record = self.effects.get(&effect).unwrap();
        if record.phase != EffectPhase::Committed {
            return Err(RegistryError::InvalidState);
        }
        if let Some(existing) = record.outcome {
            if existing == outcome {
                return Ok(existing);
            }
            if existing.class() != EffectOutcomeClass::Indeterminate
                || outcome.class() == EffectOutcomeClass::Indeterminate
            {
                return Err(RegistryError::CommitConflict);
            }
        }
        let scope_key = record.identity.scope;
        let next_scope_revision = self.scopes[&scope_key]
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        self.effects.get_mut(&effect).unwrap().outcome = Some(outcome);
        let scope = self.scopes.get_mut(&scope_key).unwrap();
        scope.revision = next_scope_revision;
        scope.invalidate_recovery_readiness();
        Ok(outcome)
    }

    /// Atomically commits a nonempty batch and migrates disjoint live effects
    /// between opaque current-resource indexes.
    ///
    /// This is the generic transaction required by two-address futex requeue:
    /// the controller and selected wake commit together while a different
    /// waiter remains prepared, with the same effect identity and credit, on
    /// its target key. Every handle, phase, result, counter, and resource is
    /// validated before any ledger or reverse-index mutation.
    pub(crate) fn commit_with_moves(
        &mut self,
        sender: TaskKey,
        commits: &[(PortalHandle, CommitMetadata)],
        moves: &[ResourceMove],
    ) -> Result<Vec<CommitOutcome>, RegistryError> {
        self.commit_with_moves_inner(sender, commits, moves, None)
    }

    fn commit_with_moves_inner(
        &mut self,
        sender: TaskKey,
        commits: &[(PortalHandle, CommitMetadata)],
        moves: &[ResourceMove],
        domain_change: Option<u64>,
    ) -> Result<Vec<CommitOutcome>, RegistryError> {
        if commits.is_empty() {
            return Err(RegistryError::InvalidState);
        }

        let mut seen = BTreeSet::new();
        let mut scope_key = None;
        let mut already_committed = Vec::with_capacity(commits.len());
        let mut all_already_committed = true;
        for (handle, metadata) in commits {
            let effect = self.validate_portal(sender, *handle)?;
            if !seen.insert(effect) {
                return Err(RegistryError::InvalidState);
            }
            let record = self.effects.get(&effect).unwrap();
            if self.scopes[&record.identity.scope].device_root.is_some() {
                // Once any device-derived effect exists, every ancestor and
                // descendant in this root is reserved for explicit cohort
                // enrollment and the single hardware publication gate. This
                // prevents a non-device ancestor from becoming a partial
                // authoritative commit before `avail.idx` is published.
                return Err(RegistryError::InvalidDeviceEnvelope);
            }
            match scope_key {
                None => scope_key = Some(record.identity.scope),
                Some(scope) if scope != record.identity.scope => {
                    return Err(RegistryError::InvalidState);
                }
                Some(_) => {}
            }
            if let Some(receipt) = record.commit.clone() {
                if receipt.result != metadata.result
                    || receipt.domain_revision != metadata.domain_revision
                {
                    return Err(RegistryError::CommitConflict);
                }
                already_committed.push(CommitOutcome::AlreadyCommitted(receipt));
            } else {
                all_already_committed = false;
                if record.phase != EffectPhase::Prepared || record.credit_state != CreditState::Held
                {
                    return Err(RegistryError::InvalidState);
                }
            }
        }

        if all_already_committed {
            if !moves.is_empty() {
                return Err(RegistryError::InvalidState);
            }
            return Ok(already_committed);
        }
        if !already_committed.is_empty() {
            // Mixed replay/application would make the domain transaction
            // ambiguous. Callers replay a previously frozen batch as a whole.
            return Err(RegistryError::InvalidState);
        }

        let mut normalized_moves = Vec::with_capacity(moves.len());
        for movement in moves {
            let effect = self.validate_portal(sender, movement.handle)?;
            if !seen.insert(effect) {
                return Err(RegistryError::InvalidState);
            }
            let record = self.effects.get(&effect).unwrap();
            if scope_key != Some(record.identity.scope)
                || !__cser_core::matches!(
                    record.phase,
                    EffectPhase::Registered | EffectPhase::Prepared
                )
                || record.credit_state != CreditState::Held
            {
                return Err(RegistryError::InvalidState);
            }
            let mut current_resources = BTreeSet::new();
            for resource in &movement.current_resources {
                validate_generation(resource.generation)?;
                current_resources.insert(*resource);
            }
            if current_resources == record.current_resources {
                return Err(RegistryError::InvalidState);
            }
            normalized_moves.push((effect, current_resources));
        }

        let count = u64::try_from(commits.len()).map_err(|_| RegistryError::CounterOverflow)?;
        let next_commit_sequence = self
            .next_commit_sequence
            .checked_add(count)
            .ok_or(RegistryError::CounterOverflow)?;
        let scope_key = scope_key.expect("nonempty commit batch has a scope");
        let next_domain_revision = if let Some(presented) = domain_change {
            let expected = self.scopes[&scope_key]
                .domain_revision
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
            if presented != expected
                || commits
                    .iter()
                    .any(|(_, metadata)| metadata.domain_revision != expected)
            {
                return Err(RegistryError::InvalidState);
            }
            Some(expected)
        } else {
            None
        };
        let revision_advance = if next_domain_revision.is_some() { 2 } else { 1 };
        let next_scope_revision = self.scopes[&scope_key]
            .revision
            .checked_add(revision_advance)
            .ok_or(RegistryError::CounterOverflow)?;
        let mut receipts = Vec::with_capacity(commits.len());
        for (offset, (handle, metadata)) in commits.iter().enumerate() {
            let effect = handle.effect;
            let record = self.effects.get(&effect).unwrap();
            let offset = u64::try_from(offset).map_err(|_| RegistryError::CounterOverflow)?;
            receipts.push(CommitReceipt {
                registry_instance_id: self.instance_id,
                effect,
                scope: record.identity.scope,
                authority_epoch: record.identity.authority_epoch,
                binding_epoch: record.identity.binding_epoch,
                sequence: self.next_commit_sequence + offset,
                result: metadata.result,
                domain_revision: metadata.domain_revision,
                descriptor_digest: record.descriptor.digest(),
            });
        }

        // Everything below is infallible after the validation pass.
        self.next_commit_sequence = next_commit_sequence;
        for (effect, current_resources) in normalized_moves {
            let previous_resources = self.effects.get(&effect).unwrap().current_resources.clone();
            self.remove_resource_indexes(effect, &previous_resources);
            self.insert_resource_indexes(effect, &current_resources);
            self.effects.get_mut(&effect).unwrap().current_resources = current_resources;
        }
        for receipt in &receipts {
            let charges = self.effects.get(&receipt.effect).unwrap().credits.clone();
            self.scopes
                .get_mut(&receipt.scope)
                .unwrap()
                .credits
                .commit(&charges)
                .expect("commit ledger was validated");
            let record = self.effects.get_mut(&receipt.effect).unwrap();
            record.phase = EffectPhase::Committed;
            record.credit_state = CreditState::Committed;
            record.commit = Some(receipt.clone());
        }
        let scope = self.scopes.get_mut(&scope_key).unwrap();
        if let Some(domain_revision) = next_domain_revision {
            scope.domain_revision = domain_revision;
        }
        scope.revision = next_scope_revision;
        scope.invalidate_recovery_readiness();
        Ok(receipts.into_iter().map(CommitOutcome::Applied).collect())
    }

    /// Freezes one complete prepared root before any hardware-visible commit.
    ///
    /// The enrollment is explicit and root-gated. It covers every live effect
    /// in the scope, fixes their order, requires exactly one causal root and at
    /// least one device-derived member, and prevents later registration or a
    /// generic per-domain commit from splitting the cohort.
    pub(crate) fn enroll_device_batch(
        &mut self,
        authority: KernelRootAuthority,
        handles: &[PortalHandle],
        expected_device: DeviceEnvelope,
    ) -> Result<DeviceBatchEnrollmentReceipt, RegistryError> {
        self.validate_kernel_root_authority(authority)?;
        expected_device.validate()?;
        if handles.is_empty() {
            return Err(RegistryError::InvalidState);
        }
        let root_state = self.scopes[&authority.scope]
            .device_root
            .as_ref()
            .ok_or(RegistryError::DeviceBatchNotEnrolled)?;
        if root_state.initial_device != expected_device {
            return Err(device_envelope_mismatch(
                root_state.initial_device,
                expected_device,
            ));
        }
        if root_state.enrollment.is_some()
            || root_state.batch_sequence.is_some()
            || !root_state.publication.is_none()
        {
            return Err(RegistryError::InvalidState);
        }

        let mut seen = BTreeSet::new();
        let mut effects = Vec::with_capacity(handles.len());
        let mut root_count = 0_usize;
        let mut device_count = 0_usize;
        for handle in handles {
            let effect = self.validate_root_portal(authority, *handle)?;
            if !seen.insert(effect) {
                return Err(RegistryError::InvalidState);
            }
            let record = &self.effects[&effect];
            if record.phase != EffectPhase::Prepared
                || record.credit_state != CreditState::Held
                || record.commit.is_some()
                || record.device_batch.is_some()
            {
                return Err(RegistryError::InvalidState);
            }
            if record.identity.parent.is_none() {
                root_count = root_count
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
            }
            if let Some(device) = record.identity.device {
                if device != expected_device {
                    return Err(device_envelope_mismatch(expected_device, device));
                }
                device_count = device_count
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
            }
            effects.push(effect);
        }
        let live = self
            .by_scope
            .get(&authority.scope)
            .ok_or(RegistryError::InvalidState)?;
        if live != &seen || root_count != 1 || device_count == 0 {
            return Err(RegistryError::InvalidState);
        }
        for effect in &seen {
            if let Some(parent) = self.effects[effect].identity.parent
                && !seen.contains(&parent)
            {
                return Err(RegistryError::InvalidHandle);
            }
        }

        let enrollment_sequence = self.next_device_enrollment_sequence;
        let next_device_enrollment_sequence = enrollment_sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let next_scope_revision = self.scopes[&authority.scope]
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let receipt = DeviceBatchEnrollmentReceipt {
            registry_instance_id: self.instance_id,
            scope: authority.scope,
            authority_epoch: authority.authority_epoch,
            enrollment_sequence,
            device: expected_device,
            effects,
            cancel_only: false,
        };

        // The receipt and every potentially fallible counter were prepared
        // before this point; freezing the scope is now infallible.
        self.next_device_enrollment_sequence = next_device_enrollment_sequence;
        let scope = self.scopes.get_mut(&authority.scope).unwrap();
        scope.device_root.as_mut().unwrap().enrollment = Some(receipt.clone());
        scope.revision = next_scope_revision;
        scope.invalidate_recovery_readiness();
        Ok(receipt)
    }

    /// Emergency, cancellation-only freeze when revocation wins after device
    /// preparation created `device_root` but before normal enrollment. It can
    /// never authorize publication. Registered and Prepared members are both
    /// conservatively retained; disconnected/multi-root or otherwise
    /// inconsistent live state remains fail closed with credits untouched.
    pub(crate) fn freeze_pending_device_cancel(
        &mut self,
        scope_key: ScopeKey,
    ) -> Result<DeviceBatchEnrollmentReceipt, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        let root = scope
            .device_root
            .as_ref()
            .ok_or(RegistryError::DeviceBatchNotEnrolled)?;
        if scope.phase != ScopePhase::Closing
            || root.enrollment.is_some()
            || root.batch_sequence.is_some()
            || !root.publication.is_none()
        {
            return Err(RegistryError::InvalidState);
        }
        let closed_authority_epoch = scope
            .revoke
            .as_ref()
            .ok_or(RegistryError::InvalidRevokeSelection)?
            .closed_authority_epoch;
        let live = self
            .by_scope
            .get(&scope_key)
            .ok_or(RegistryError::InvalidState)?;
        if live.is_empty() {
            return Err(RegistryError::InvalidState);
        }
        let mut roots = 0_usize;
        let mut device_count = 0_usize;
        let mut effects = Vec::with_capacity(live.len());
        for effect in live {
            let record = &self.effects[effect];
            if record.identity.scope != scope_key
                || record.identity.authority_epoch != closed_authority_epoch
                || !__cser_core::matches!(
                    record.phase,
                    EffectPhase::Registered | EffectPhase::Prepared
                )
                || record.credit_state != CreditState::Held
                || record.commit.is_some()
                || record.device_batch.is_some()
            {
                return Err(RegistryError::InvalidState);
            }
            if record.identity.parent.is_none() {
                roots = roots.checked_add(1).ok_or(RegistryError::CounterOverflow)?;
            } else if record
                .identity
                .parent
                .is_some_and(|parent| !live.contains(&parent))
            {
                return Err(RegistryError::InvalidHandle);
            }
            if let Some(device) = record.identity.device {
                if device != root.initial_device {
                    return Err(device_envelope_mismatch(root.initial_device, device));
                }
                device_count = device_count
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
            }
            effects.push(*effect);
        }
        if roots != 1 || device_count == 0 {
            return Err(RegistryError::InvalidState);
        }
        let enrollment_sequence = self.next_device_enrollment_sequence;
        let next_device_enrollment_sequence = enrollment_sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let next_revision = scope
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let receipt = DeviceBatchEnrollmentReceipt {
            registry_instance_id: self.instance_id,
            scope: scope_key,
            authority_epoch: closed_authority_epoch,
            enrollment_sequence,
            device: root.initial_device,
            effects,
            cancel_only: true,
        };
        self.next_device_enrollment_sequence = next_device_enrollment_sequence;
        let scope = self.scopes.get_mut(&scope_key).unwrap();
        scope.device_root.as_mut().unwrap().enrollment = Some(receipt.clone());
        scope.revision = next_revision;
        scope.invalidate_recovery_readiness();
        Ok(receipt)
    }

    /// Closes an already enrolled, unpublished device root as one
    /// failure-atomic cross-object transition.
    ///
    /// Registry validation and every allocation complete before mutation. The
    /// Registry then installs revoke, retention, the precommit outcome, and the
    /// reset ticket before entering the caller's preflighted hardware apply.
    /// Therefore an ordinary `Err` proves the hardware closure was not called
    /// and the complete Registry is unchanged; an unexpected unwind leaves the
    /// exact Registry fence discoverable.
    pub(crate) fn close_enrolled_device_precommit_with_apply<T>(
        &mut self,
        enrollment: &DeviceBatchEnrollmentReceipt,
        apply_hardware: impl FnOnce(&DeviceResetTicket) -> T,
    ) -> Result<(DevicePrecommitCloseReceipt, T), RegistryError> {
        self.validate_device_enrollment_receipt(enrollment)?;
        let plan = self.prepare_device_precommit_close(enrollment.clone(), None, None)?;
        let receipt = self.apply_device_precommit_close(plan);
        let hardware = apply_hardware(&receipt.reset_ticket);
        Ok((receipt, hardware))
    }

    /// Freezes and closes an unpublished device root that has not yet minted a
    /// normal enrollment. The cancel-only enrollment, revoke, retained-credit
    /// transition, honest precommit outcome, and reset ticket are prepared as
    /// one unit before the caller's infallible hardware intent runs.
    pub(crate) fn close_pending_device_precommit_with_apply<T>(
        &mut self,
        scope_key: ScopeKey,
        apply_hardware: impl FnOnce(&DeviceResetTicket) -> T,
    ) -> Result<(DevicePrecommitCloseReceipt, T), RegistryError> {
        let (enrollment, next_device_enrollment_sequence) =
            self.prepare_pending_device_cancel_enrollment(scope_key)?;
        let install_enrollment = enrollment.clone();
        let plan = self.prepare_device_precommit_close(
            enrollment,
            Some(install_enrollment),
            Some(next_device_enrollment_sequence),
        )?;
        let receipt = self.apply_device_precommit_close(plan);
        let hardware = apply_hardware(&receipt.reset_ticket);
        Ok((receipt, hardware))
    }

    fn prepare_pending_device_cancel_enrollment(
        &self,
        scope_key: ScopeKey,
    ) -> Result<(DeviceBatchEnrollmentReceipt, u64), RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        let root = scope
            .device_root
            .as_ref()
            .ok_or(RegistryError::DeviceBatchNotEnrolled)?;
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        if root.enrollment.is_some() || root.batch_sequence.is_some() || !root.publication.is_none()
        {
            return Err(RegistryError::InvalidState);
        }
        let live = self
            .by_scope
            .get(&scope_key)
            .ok_or(RegistryError::InvalidState)?;
        if live.is_empty() {
            return Err(RegistryError::InvalidState);
        }

        let mut roots = 0_usize;
        let mut device_count = 0_usize;
        let mut effects = Vec::with_capacity(live.len());
        for effect in live {
            let record = self
                .effects
                .get(effect)
                .ok_or(RegistryError::UnknownEffect)?;
            if record.identity.scope != scope_key
                || record.identity.authority_epoch != scope.authority_epoch
                || !__cser_core::matches!(
                    record.phase,
                    EffectPhase::Registered | EffectPhase::Prepared
                )
                || record.credit_state != CreditState::Held
                || record.commit.is_some()
                || record.device_batch.is_some()
                || record.terminal.is_some()
                || record.pending_publication.is_some()
            {
                return Err(RegistryError::InvalidState);
            }
            if record.identity.parent.is_none() {
                roots = roots.checked_add(1).ok_or(RegistryError::CounterOverflow)?;
            } else if record
                .identity
                .parent
                .is_some_and(|parent| !live.contains(&parent))
            {
                return Err(RegistryError::InvalidHandle);
            }
            if let Some(device) = record.identity.device {
                if device != root.initial_device {
                    return Err(device_envelope_mismatch(root.initial_device, device));
                }
                device_count = device_count
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
            }
            effects.push(*effect);
        }
        if roots != 1 || device_count == 0 {
            return Err(RegistryError::InvalidState);
        }

        let enrollment_sequence = self.next_device_enrollment_sequence;
        let next_device_enrollment_sequence = enrollment_sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        Ok((
            DeviceBatchEnrollmentReceipt {
                registry_instance_id: self.instance_id,
                scope: scope_key,
                authority_epoch: scope.authority_epoch,
                enrollment_sequence,
                device: root.initial_device,
                effects,
                cancel_only: true,
            },
            next_device_enrollment_sequence,
        ))
    }

    fn prepare_device_precommit_close(
        &self,
        enrollment: DeviceBatchEnrollmentReceipt,
        install_enrollment: Option<DeviceBatchEnrollmentReceipt>,
        next_device_enrollment_sequence: Option<u64>,
    ) -> Result<DevicePrecommitClosePlan, RegistryError> {
        let scope = self
            .scopes
            .get(&enrollment.scope)
            .ok_or(RegistryError::UnknownScope)?;
        map_handoff_gate(scope.handoff_gate.require_open())?;
        let root = scope
            .device_root
            .as_ref()
            .ok_or(RegistryError::DeviceBatchNotEnrolled)?;
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }

        let installs_enrollment = install_enrollment.is_some();
        let enrollment_state_valid = if installs_enrollment {
            enrollment.cancel_only
                && root.enrollment.is_none()
                && install_enrollment.as_ref() == Some(&enrollment)
                && next_device_enrollment_sequence.is_some()
        } else {
            !enrollment.cancel_only
                && root.enrollment.as_ref() == Some(&enrollment)
                && next_device_enrollment_sequence.is_none()
        };
        if !enrollment_state_valid
            || enrollment.registry_instance_id != self.instance_id
            || enrollment.authority_epoch != scope.authority_epoch
            || enrollment.device != root.initial_device
            || enrollment.effects.is_empty()
            || root.current_device != root.initial_device
            || root.batch_sequence.is_some()
            || !root.publication.is_none()
            || root.completion.is_some()
            || root.outcome.is_some()
            || root.reset_ticket.is_some()
            || root.reset_tombstone.is_some()
            || root.reset_retry_issued
            || root.reset_receipt.is_some()
            || root.iotlb_ticket.is_some()
            || root.iotlb_tombstone.is_some()
            || root.iotlb_retry_issued
            || root.closure.is_some()
        {
            return Err(RegistryError::InvalidState);
        }

        let enrolled: BTreeSet<_> = enrollment.effects.iter().copied().collect();
        let live = self
            .by_scope
            .get(&enrollment.scope)
            .ok_or(RegistryError::InvalidState)?;
        if enrolled.len() != enrollment.effects.len()
            || &enrolled != live
            || &scope.closure_candidates != live
        {
            return Err(RegistryError::InvalidState);
        }
        let mut roots = 0_usize;
        let mut device_count = 0_usize;
        for effect in &enrollment.effects {
            let record = self
                .effects
                .get(effect)
                .ok_or(RegistryError::UnknownEffect)?;
            let phase_valid = if installs_enrollment {
                __cser_core::matches!(
                    record.phase,
                    EffectPhase::Registered | EffectPhase::Prepared
                )
            } else {
                record.phase == EffectPhase::Prepared
            };
            if record.identity.scope != enrollment.scope
                || record.identity.authority_epoch != enrollment.authority_epoch
                || !phase_valid
                || record.credit_state != CreditState::Held
                || record.commit.is_some()
                || record.device_batch.is_some()
                || record.terminal.is_some()
                || record.pending_publication.is_some()
            {
                return Err(RegistryError::InvalidState);
            }
            if let Some(parent) = record.identity.parent {
                if !enrolled.contains(&parent) {
                    return Err(RegistryError::InvalidHandle);
                }
            } else {
                roots = roots.checked_add(1).ok_or(RegistryError::CounterOverflow)?;
            }
            if let Some(device) = record.identity.device {
                if device != enrollment.device {
                    return Err(device_envelope_mismatch(enrollment.device, device));
                }
                device_count = device_count
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
            }
        }
        if roots != 1 || device_count == 0 {
            return Err(RegistryError::InvalidState);
        }

        let revoke = self.prepare_revoke_begin(enrollment.scope)?;
        if revoke.selection.target_count != enrollment.effects.len() {
            return Err(RegistryError::InvalidState);
        }
        let retention = self
            .prepare_device_root_retention(&enrollment)?
            .ok_or(RegistryError::InvalidState)?;
        if retention.from != CreditState::Held {
            return Err(RegistryError::InvalidState);
        }

        let enrollment_scope_revision = if installs_enrollment {
            Some(
                revoke
                    .next_scope_revision
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?,
            )
        } else {
            None
        };
        let revision_before_ticket =
            enrollment_scope_revision.unwrap_or(revoke.next_scope_revision);
        let next_scope_revision = revision_before_ticket
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let sequence = self.next_device_closure_sequence;
        let next_device_closure_sequence = sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let reset_ticket = DeviceResetTicket {
            registry_instance_id: self.instance_id,
            scope: enrollment.scope,
            enrollment_sequence: enrollment.enrollment_sequence,
            batch_sequence: None,
            device: root.current_device,
            sequence,
        };

        let enrollment_apply = match (
            install_enrollment,
            next_device_enrollment_sequence,
            enrollment_scope_revision,
        ) {
            (
                Some(enrollment),
                Some(next_device_enrollment_sequence),
                Some(next_scope_revision),
            ) => DevicePrecommitEnrollmentApply::Install {
                enrollment,
                next_device_enrollment_sequence,
                next_scope_revision,
            },
            (None, None, None) => DevicePrecommitEnrollmentApply::Existing,
            _ => return Err(RegistryError::InvalidState),
        };

        Ok(DevicePrecommitClosePlan {
            enrollment,
            enrollment_apply,
            retention,
            reset_ticket,
            revoke,
            next_device_closure_sequence,
            next_scope_revision,
        })
    }

    fn apply_device_precommit_close(
        &mut self,
        plan: DevicePrecommitClosePlan,
    ) -> DevicePrecommitCloseReceipt {
        let DevicePrecommitClosePlan {
            enrollment,
            enrollment_apply,
            retention,
            reset_ticket,
            revoke,
            next_device_closure_sequence,
            next_scope_revision,
        } = plan;
        let selection = self.apply_revoke_begin(revoke);

        if let DevicePrecommitEnrollmentApply::Install {
            enrollment: installed,
            next_device_enrollment_sequence,
            next_scope_revision,
        } = enrollment_apply
        {
            self.next_device_enrollment_sequence = next_device_enrollment_sequence;
            let scope = self
                .scopes
                .get_mut(&enrollment.scope)
                .expect("prevalidated scope cannot disappear under exclusive Registry access");
            scope
                .device_root
                .as_mut()
                .expect("prevalidated device root cannot disappear under exclusive Registry access")
                .enrollment = Some(installed);
            scope.revision = next_scope_revision;
            scope.invalidate_recovery_readiness();
        }

        self.apply_device_root_retention(&enrollment, Some(&retention));
        self.next_device_closure_sequence = next_device_closure_sequence;
        let scope = self
            .scopes
            .get_mut(&enrollment.scope)
            .expect("prevalidated scope cannot disappear under exclusive Registry access");
        let root = scope
            .device_root
            .as_mut()
            .expect("prevalidated device root cannot disappear under exclusive Registry access");
        root.outcome = Some(DeviceClosureResult::AbortedBeforeCommit);
        root.reset_ticket = Some(reset_ticket);
        scope.revision = next_scope_revision;
        scope.invalidate_recovery_readiness();
        DevicePrecommitCloseReceipt {
            selection,
            enrollment,
            reset_ticket,
        }
    }

    /// Commits one complete production root at the caller-supplied hardware
    /// publication point.
    ///
    /// The caller must already hold the root runtime lock which also excludes
    /// `revoke_begin`. This method validates every root, binding, effect,
    /// ancestry, credit, counter, and device field and allocates the complete
    /// receipt before invoking `publish`. The closure is deliberately
    /// infallible: the production VirtIO typestate performs descriptor/DMA
    /// preparation first and uses the closure only for the single
    /// `avail.idx` Release. Once it returns, applying the prevalidated plan
    /// performs no allocation and has no error path. A full replay returns the
    /// stored authoritative receipt without invoking `publish` again.
    pub(crate) fn commit_device_batch_with_publish<T>(
        &mut self,
        authority: KernelRootAuthority,
        enrollment: &DeviceBatchEnrollmentReceipt,
        commits: &[(PortalHandle, CommitMetadata)],
        publish: impl FnOnce(&DeviceBatchCommitReceipt) -> T,
    ) -> Result<DeviceBatchCommitOutcome<T>, RegistryError> {
        match self.prepare_device_batch(authority, enrollment, commits)? {
            PreparedDeviceBatch::Replay(receipt) => {
                Ok(DeviceBatchCommitOutcome::AlreadyCommitted { receipt })
            }
            PreparedDeviceBatch::Apply(plan) => {
                let publication = publish(&plan.receipt);
                let receipt = self.apply_device_batch(plan);
                let root = self
                    .scopes
                    .get_mut(&receipt.scope)
                    .expect("prevalidated legacy scope remains present")
                    .device_root
                    .as_mut()
                    .expect("prevalidated legacy device root remains present");
                __cser_core::debug_assert!(root.publication.is_none());
                root.publication = DevicePublicationProvenance::Legacy;
                Ok(DeviceBatchCommitOutcome::Applied {
                    receipt,
                    publication,
                })
            }
        }
    }

    /// Mints a copyable but unforgeable identity for one exact enrolled root.
    /// The caller supplies a stable nonzero nonce; minting does not mutate the
    /// Registry and remains valid only while this root is unpublished Active
    /// state owned by its current kernel supervisor.
    pub(crate) fn mint_device_close_operation(
        &self,
        enrollment: &DeviceBatchEnrollmentReceipt,
        caller_nonce: u64,
    ) -> Result<DeviceCloseOperationId, RegistryError> {
        self.require_unique_device_publication()?;
        if caller_nonce == 0 {
            return Err(RegistryError::InvalidGeneration);
        }
        if enrollment.cancel_only {
            return Err(RegistryError::InvalidState);
        }
        self.validate_device_enrollment_receipt(enrollment)?;
        let scope = self
            .scopes
            .get(&enrollment.scope)
            .ok_or(RegistryError::UnknownScope)?;
        let root = scope
            .device_root
            .as_ref()
            .ok_or(RegistryError::DeviceBatchNotEnrolled)?;
        let owner = scope.supervisor.ok_or(RegistryError::NoSupervisor)?;
        if scope.phase != ScopePhase::Active
            || scope.fallback_running
            || root.batch_sequence.is_some()
            || !root.publication.is_none()
        {
            return Err(RegistryError::InvalidState);
        }
        Ok(DeviceCloseOperationId {
            registry_instance_id: self.instance_id,
            scope: enrollment.scope,
            authority_epoch: enrollment.authority_epoch,
            enrollment_sequence: enrollment.enrollment_sequence,
            device: enrollment.device,
            owner,
            caller_nonce,
        })
    }

    /// Publishes and revokes one fresh root, or recovers the exact stored
    /// result of the same caller operation without publishing again.
    ///
    /// Fresh state prevalidates and preallocates the batch, its root-local
    /// stored copy, the operation identity, all three scope revisions, and the
    /// succeeding revoke. It then installs `Publishing` provenance before
    /// entering `publish`. Consequently unwind cannot erase a possibly
    /// published operation or license precommit cancellation. Normal return
    /// applies the batch and revoke without allocation or failure and changes
    /// the same provenance to `Applied`. Once publication provenance exists,
    /// every input error is `Published`; only an exact applied-operation retry
    /// returns `Recovered`, with no closure call or Registry mutation.
    // The large error is deliberate: boxing it would allocate after the
    // operation may already have crossed the publication boundary.
    #[allow(clippy::result_large_err)]
    pub(crate) fn commit_or_recover_device_close_with_apply<T>(
        &mut self,
        operation: DeviceCloseOperationId,
        authority: KernelRootAuthority,
        enrollment: &DeviceBatchEnrollmentReceipt,
        commits: &[(PortalHandle, CommitMetadata)],
        publish: impl FnOnce(&DeviceBatchCommitReceipt) -> T,
    ) -> Result<DeviceCloseOutcome<T>, DeviceCloseError> {
        if let Some(obligation) =
            self.device_published_obligation_for_attempt(operation, enrollment)
        {
            return match self.recover_device_close(operation, authority, enrollment, commits) {
                Ok((receipt, selection)) => {
                    Ok(DeviceCloseOutcome::Recovered { receipt, selection })
                }
                Err(error) => Err(DeviceCloseError::Published { obligation, error }),
            };
        }

        let prepared = self
            .prepare_device_close(operation, authority, enrollment, commits)
            .map_err(DeviceCloseError::Unpublished)?;
        let plan = self.install_device_close_publishing(prepared);
        let publication = publish(&plan.batch.receipt);
        let (receipt, selection) = self.apply_device_close(plan);
        Ok(DeviceCloseOutcome::Applied {
            receipt,
            publication,
            selection,
        })
    }

    fn prepare_device_close(
        &self,
        operation: DeviceCloseOperationId,
        authority: KernelRootAuthority,
        enrollment: &DeviceBatchEnrollmentReceipt,
        commits: &[(PortalHandle, CommitMetadata)],
    ) -> Result<DeviceClosePreparePlan, RegistryError> {
        self.validate_device_close_coordinates(operation, authority, enrollment)?;
        self.validate_kernel_root_authority(authority)?;
        let root = self.scopes[&operation.scope]
            .device_root
            .as_ref()
            .ok_or(RegistryError::DeviceBatchNotEnrolled)?;
        if root.batch_sequence.is_some() || !root.publication.is_none() {
            return Err(RegistryError::InvalidState);
        }
        let mut batch = match self.prepare_device_batch(authority, enrollment, commits)? {
            PreparedDeviceBatch::Apply(plan) => plan,
            PreparedDeviceBatch::Replay(_) => return Err(RegistryError::InvalidState),
        };
        let stored_batch = batch.receipt.clone();
        let publishing_revision = batch.next_scope_revision;
        batch.next_scope_revision = publishing_revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let revoke = self.prepare_revoke_begin_after_publishing_and_batch(
            operation.scope,
            batch.next_scope_revision,
        )?;
        Ok(DeviceClosePreparePlan {
            operation,
            batch,
            stored_batch,
            revoke,
            publishing_revision,
        })
    }

    fn install_device_close_publishing(
        &mut self,
        plan: DeviceClosePreparePlan,
    ) -> DeviceCloseApplyPlan {
        let DeviceClosePreparePlan {
            operation,
            batch,
            stored_batch,
            revoke,
            publishing_revision,
        } = plan;
        let scope = self
            .scopes
            .get_mut(&operation.scope)
            .expect("prevalidated publishing scope remains present");
        let root = scope
            .device_root
            .as_mut()
            .expect("prevalidated publishing device root remains present");
        __cser_core::debug_assert!(root.publication.is_none());
        root.publication = DevicePublicationProvenance::Publishing {
            operation,
            batch: stored_batch,
        };
        scope.revision = publishing_revision;
        scope.invalidate_recovery_readiness();
        DeviceCloseApplyPlan {
            operation,
            batch,
            revoke,
        }
    }

    fn apply_device_close(
        &mut self,
        plan: DeviceCloseApplyPlan,
    ) -> (DeviceBatchCommitReceipt, RevokeSelection) {
        let DeviceCloseApplyPlan {
            operation,
            batch,
            revoke,
        } = plan;
        let receipt = self.apply_device_batch(batch);
        let selection = self.apply_revoke_begin(revoke);
        let root = self
            .scopes
            .get_mut(&operation.scope)
            .expect("prevalidated device-close scope remains present")
            .device_root
            .as_mut()
            .expect("prevalidated device-close root remains present");
        let publishing =
            __cser_core::mem::replace(&mut root.publication, DevicePublicationProvenance::None);
        root.publication = match publishing {
            DevicePublicationProvenance::Publishing {
                operation: stored_operation,
                batch,
            } if stored_operation == operation && batch == receipt => {
                DevicePublicationProvenance::Applied {
                    operation: stored_operation,
                    batch,
                }
            }
            _ => __cser_core::unreachable!(
                "prevalidated Publishing provenance cannot drift under root lock"
            ),
        };
        (receipt, selection)
    }

    fn recover_device_close(
        &self,
        operation: DeviceCloseOperationId,
        authority: KernelRootAuthority,
        enrollment: &DeviceBatchEnrollmentReceipt,
        commits: &[(PortalHandle, CommitMetadata)],
    ) -> Result<(DeviceBatchCommitReceipt, RevokeSelection), RegistryError> {
        self.validate_device_close_coordinates(operation, authority, enrollment)?;
        let scope = self
            .scopes
            .get(&operation.scope)
            .ok_or(RegistryError::UnknownScope)?;
        let root = scope
            .device_root
            .as_ref()
            .ok_or(RegistryError::DeviceBatchNotEnrolled)?;
        let (stored_operation, stored) = match &root.publication {
            DevicePublicationProvenance::Applied { operation, batch } => (*operation, batch),
            DevicePublicationProvenance::None
            | DevicePublicationProvenance::Legacy
            | DevicePublicationProvenance::Publishing { .. } => {
                return Err(RegistryError::InvalidState);
            }
        };
        if stored_operation != operation
            || root.batch_sequence != Some(stored.batch_sequence)
            || stored.registry_instance_id != self.instance_id
            || stored.scope != operation.scope
            || stored.authority_epoch != operation.authority_epoch
            || stored.device != operation.device
            || stored.commits.len() != enrollment.effects.len()
            || stored
                .commits
                .iter()
                .map(|commit| commit.effect)
                .ne(enrollment.effects.iter().copied())
            || commits.len() != stored.commits.len()
        {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        for (ordinal, ((handle, metadata), authoritative)) in
            commits.iter().zip(&stored.commits).enumerate()
        {
            let record = self
                .effects
                .get(&authoritative.effect)
                .ok_or(RegistryError::InvalidBatchReceipt)?;
            if *handle != record.handle()
                || metadata.result != authoritative.result
                || metadata.domain_revision != authoritative.domain_revision
                || record.commit.as_ref() != Some(authoritative)
                || record.device_batch.is_none_or(|membership| {
                    membership.sequence != stored.batch_sequence
                        || membership.ordinal != ordinal
                        || membership.size != stored.commits.len()
                        || membership.device != stored.device
                })
            {
                return Err(RegistryError::CommitConflict);
            }
        }
        let selection = Self::device_revoke_selection(operation.scope, scope)
            .ok_or(RegistryError::InvalidState)?;
        if !__cser_core::matches!(scope.phase, ScopePhase::Closing | ScopePhase::Revoked)
            || selection.closed_authority_epoch != operation.authority_epoch
            || selection.target_count != stored.commits.len()
        {
            return Err(RegistryError::InvalidState);
        }
        Ok((stored.clone(), selection))
    }

    fn validate_device_close_coordinates(
        &self,
        operation: DeviceCloseOperationId,
        authority: KernelRootAuthority,
        enrollment: &DeviceBatchEnrollmentReceipt,
    ) -> Result<(), RegistryError> {
        self.require_unique_device_publication()?;
        if operation.registry_instance_id != self.instance_id
            || operation.caller_nonce == 0
            || operation.scope != enrollment.scope
            || operation.authority_epoch != enrollment.authority_epoch
            || operation.enrollment_sequence != enrollment.enrollment_sequence
            || operation.device != enrollment.device
            || authority.registry_instance_id != operation.registry_instance_id
            || authority.scope != operation.scope
            || authority.owner != operation.owner
        {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        if authority.authority_epoch != operation.authority_epoch {
            return Err(RegistryError::StaleAuthority);
        }
        self.validate_device_enrollment_receipt(enrollment)?;
        Ok(())
    }

    fn device_published_obligation_for_attempt(
        &self,
        operation: DeviceCloseOperationId,
        enrollment: &DeviceBatchEnrollmentReceipt,
    ) -> Option<DevicePublishedObligation> {
        self.device_published_obligation(operation.scope)
            .or_else(|| {
                (enrollment.scope != operation.scope)
                    .then(|| self.device_published_obligation(enrollment.scope))
                    .flatten()
            })
    }

    fn device_published_obligation(
        &self,
        scope_key: ScopeKey,
    ) -> Option<DevicePublishedObligation> {
        let scope = self.scopes.get(&scope_key)?;
        let root = scope.device_root.as_ref()?;
        let has_published_or_closure_progress = root.batch_sequence.is_some()
            || !root.publication.is_none()
            || root.completion.is_some()
            || root
                .reset_ticket
                .is_some_and(|ticket| ticket.batch_sequence.is_some())
            || root
                .reset_tombstone
                .is_some_and(|tombstone| tombstone.ticket.batch_sequence.is_some())
            || root
                .reset_receipt
                .is_some_and(|reset| reset.batch_sequence.is_some())
            || root
                .iotlb_ticket
                .is_some_and(|ticket| ticket.batch_sequence.is_some())
            || root
                .iotlb_tombstone
                .is_some_and(|tombstone| tombstone.ticket.batch_sequence.is_some())
            || root
                .closure
                .is_some_and(|closure| closure.batch_sequence.is_some());
        if !has_published_or_closure_progress {
            return None;
        }
        let batch_sequence = root
            .batch_sequence
            .or_else(|| root.publication.batch().map(|batch| batch.batch_sequence))
            .or_else(|| root.completion.map(|completion| completion.batch_sequence))
            .or_else(|| root.reset_ticket.and_then(|ticket| ticket.batch_sequence))
            .or_else(|| {
                root.reset_tombstone
                    .and_then(|tombstone| tombstone.ticket.batch_sequence)
            })
            .or_else(|| root.reset_receipt.and_then(|reset| reset.batch_sequence))
            .or_else(|| root.iotlb_ticket.and_then(|ticket| ticket.batch_sequence))
            .or_else(|| {
                root.iotlb_tombstone
                    .and_then(|tombstone| tombstone.ticket.batch_sequence)
            })
            .or_else(|| root.closure.and_then(|closure| closure.batch_sequence));
        Some(DevicePublishedObligation {
            registry_instance_id: self.instance_id,
            scope: scope_key,
            device: root.initial_device,
            batch_sequence,
            operation: root.publication.operation(),
            status: root
                .publication
                .published_status()
                .unwrap_or(DevicePublishedStatus::CorruptPublished),
            phase: scope.phase,
            revoke: Self::device_revoke_selection(scope_key, scope),
            reset_ticket: root.reset_ticket,
            reset_tombstone: root.reset_tombstone,
            reset_retry_issued: root.reset_retry_issued,
            reset_receipt: root.reset_receipt,
            iotlb_ticket: root.iotlb_ticket,
            iotlb_tombstone: root.iotlb_tombstone,
            iotlb_retry_issued: root.iotlb_retry_issued,
            closure: root.closure,
        })
    }

    fn device_revoke_selection(
        scope_key: ScopeKey,
        scope: &ScopeRecord,
    ) -> Option<RevokeSelection> {
        let revoke = scope.revoke.as_ref()?;
        Some(RevokeSelection {
            scope: scope_key,
            sequence: revoke.sequence,
            closed_authority_epoch: revoke.closed_authority_epoch,
            authority_epoch: revoke.authority_epoch,
            target_count: revoke.target_count,
        })
    }

    /// Validates a completion/reset receipt against the authoritative batch
    /// after publication. This deliberately remains usable while the root is
    /// Closing: post-commit device ownership must be drained or retained, not
    /// erased merely because `revoke_begin` advanced the authority epoch.
    pub(crate) fn validate_device_batch_receipt(
        &self,
        presented: &DeviceBatchCommitReceipt,
    ) -> Result<(), RegistryError> {
        if presented.registry_instance_id != self.instance_id {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        presented.device.validate()?;
        let authoritative =
            self.reconstruct_device_batch_receipt(presented.scope, presented.batch_sequence)?;
        if presented.device != authoritative.device {
            return Err(device_envelope_mismatch(
                authoritative.device,
                presented.device,
            ));
        }
        let root = self
            .scopes
            .get(&presented.scope)
            .and_then(|scope| scope.device_root.as_ref())
            .ok_or(RegistryError::InvalidBatchReceipt)?;
        let publication_matches =
            __cser_core::matches!(&root.publication, DevicePublicationProvenance::Legacy)
                || __cser_core::matches!(
                    &root.publication,
                    DevicePublicationProvenance::Applied { batch, .. } if batch == presented
                );
        if root.batch_sequence != Some(presented.batch_sequence)
            || root.initial_device != presented.device
            || !publication_matches
            || root.enrollment.as_ref().is_none_or(|enrollment| {
                enrollment.effects
                    != authoritative
                        .commits
                        .iter()
                        .map(|commit| commit.effect)
                        .collect::<Vec<_>>()
            })
        {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        if presented != &authoritative {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        Ok(())
    }

    /// Claims the narrow post-commit fence fallback for a replay whose
    /// hardware publication closure was not invoked in the current call.
    ///
    /// The authoritative batch must still be in its initial committed state:
    /// no completion, reset, IOTLB, outcome, or closure authority may already
    /// exist, and revocation must not have begun. A successful return is the
    /// ownership linearization point, not a read-only eligibility check. It
    /// does not turn descriptive device coordinates into publication
    /// authority; before calling this transition,
    /// the adapter must separately prove exclusive ownership of the matching
    /// physical device and DMA generation. Eligibility validation, revoke
    /// begin, and reset-ticket installation form one Registry transition, so
    /// an IRQ completion actor cannot win between them. The workload outcome
    /// remains unset until ResetAck actually advances the device generation.
    /// Every counter and both scope revisions are checked before the first
    /// mutation.
    /// Legacy module-private recovery primitive retained only for direct
    /// invariant tests. A batch receipt alone is not a production close
    /// operation and this path is intentionally unavailable to callers.
    fn claim_device_replay_reset_and_revoke(
        &mut self,
        presented: &DeviceBatchCommitReceipt,
    ) -> Result<DeviceReplayResetClaim, RegistryError> {
        let plan = self.prepare_device_replay_reset_and_revoke(presented)?;
        Ok(self.apply_device_replay_reset_and_revoke(plan))
    }

    fn prepare_device_replay_reset_and_revoke(
        &self,
        presented: &DeviceBatchCommitReceipt,
    ) -> Result<DeviceReplayResetPlan, RegistryError> {
        self.validate_device_batch_receipt(presented)?;
        let scope = self
            .scopes
            .get(&presented.scope)
            .ok_or(RegistryError::InvalidBatchReceipt)?;
        map_handoff_gate(scope.handoff_gate.require_open())?;
        let root = scope
            .device_root
            .as_ref()
            .ok_or(RegistryError::InvalidBatchReceipt)?;
        if scope.phase != ScopePhase::Active
            || scope.revoke.is_some()
            || root.current_device != root.initial_device
            || root.completion.is_some()
            || root.outcome.is_some()
            || root.reset_ticket.is_some()
            || root.reset_tombstone.is_some()
            || root.reset_retry_issued
            || root.reset_receipt.is_some()
            || root.iotlb_ticket.is_some()
            || root.iotlb_tombstone.is_some()
            || root.iotlb_retry_issued
            || root.closure.is_some()
        {
            return Err(RegistryError::InvalidState);
        }
        let reset_sequence = self.next_device_closure_sequence;
        let next_device_closure_sequence = reset_sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let enrollment_sequence = root
            .enrollment
            .as_ref()
            .ok_or(RegistryError::InvalidBatchReceipt)?
            .enrollment_sequence;
        let reset_ticket = DeviceResetTicket {
            registry_instance_id: self.instance_id,
            scope: presented.scope,
            enrollment_sequence,
            batch_sequence: Some(presented.batch_sequence),
            device: root.current_device,
            sequence: reset_sequence,
        };
        let revoke = self.prepare_revoke_begin(presented.scope)?;
        let next_scope_revision = revoke
            .next_scope_revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        Ok(DeviceReplayResetPlan {
            reset_ticket,
            revoke,
            next_device_closure_sequence,
            next_scope_revision,
        })
    }

    fn apply_device_replay_reset_and_revoke(
        &mut self,
        plan: DeviceReplayResetPlan,
    ) -> DeviceReplayResetClaim {
        let DeviceReplayResetPlan {
            reset_ticket,
            revoke,
            next_device_closure_sequence,
            next_scope_revision,
        } = plan;
        self.next_device_closure_sequence = next_device_closure_sequence;
        let selection = self.apply_revoke_begin(revoke);
        let scope = self
            .scopes
            .get_mut(&selection.scope)
            .expect("prepared replay scope must remain present");
        let root = scope
            .device_root
            .as_mut()
            .expect("prepared replay device root must remain present");
        root.reset_ticket = Some(reset_ticket);
        scope.revision = next_scope_revision;
        scope.invalidate_recovery_readiness();
        DeviceReplayResetClaim {
            selection,
            reset_ticket,
        }
    }

    fn validate_device_enrollment_receipt(
        &self,
        presented: &DeviceBatchEnrollmentReceipt,
    ) -> Result<&DeviceRootState, RegistryError> {
        if presented.registry_instance_id != self.instance_id || presented.enrollment_sequence == 0
        {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        let root = self
            .scopes
            .get(&presented.scope)
            .and_then(|scope| scope.device_root.as_ref())
            .ok_or(RegistryError::InvalidBatchReceipt)?;
        if presented.device != root.initial_device {
            return Err(device_envelope_mismatch(
                root.initial_device,
                presented.device,
            ));
        }
        if root.enrollment.as_ref() != Some(presented) {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        Ok(root)
    }

    fn validate_device_closure_context(
        &self,
        scope: ScopeKey,
        enrollment_sequence: u64,
        batch_sequence: Option<u64>,
    ) -> Result<DeviceBatchEnrollmentReceipt, RegistryError> {
        let root = self
            .scopes
            .get(&scope)
            .and_then(|scope| scope.device_root.as_ref())
            .ok_or(RegistryError::InvalidBatchReceipt)?;
        let enrollment = root
            .enrollment
            .as_ref()
            .ok_or(RegistryError::DeviceBatchNotEnrolled)?;
        if enrollment.enrollment_sequence != enrollment_sequence {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        self.validate_device_enrollment_receipt(enrollment)?;
        match batch_sequence {
            Some(sequence) => {
                if root.batch_sequence != Some(sequence) {
                    return Err(RegistryError::InvalidBatchReceipt);
                }
                let batch = self.reconstruct_device_batch_receipt(scope, sequence)?;
                self.validate_device_batch_receipt(&batch)?;
            }
            None => {
                if root.batch_sequence.is_some() {
                    return Err(RegistryError::InvalidBatchReceipt);
                }
            }
        }
        Ok(enrollment.clone())
    }

    fn device_batch_causal_root_commit<'a>(
        &self,
        batch: &'a DeviceBatchCommitReceipt,
    ) -> Result<&'a CommitReceipt, RegistryError> {
        let mut causal_root = None;
        for commit in &batch.commits {
            let record = self
                .effects
                .get(&commit.effect)
                .ok_or(RegistryError::InvalidBatchReceipt)?;
            if record.identity.scope != batch.scope {
                return Err(RegistryError::InvalidBatchReceipt);
            }
            if record.identity.parent.is_none() && causal_root.replace(commit).is_some() {
                return Err(RegistryError::InvalidBatchReceipt);
            }
        }
        causal_root.ok_or(RegistryError::InvalidBatchReceipt)
    }

    /// Records one backend completion only for the exact committed batch and
    /// current device generation. The reported result must equal the commit
    /// result of the batch's unique causal root; a device leaf cannot rewrite
    /// the user-visible result. Once reset begins, late completion is not a
    /// substitute for reset/IOTLB closure.
    pub(crate) fn record_device_completion(
        &mut self,
        batch: &DeviceBatchCommitReceipt,
        presented_device: DeviceEnvelope,
        result: i64,
    ) -> Result<DeviceCompletionReceipt, RegistryError> {
        let plan = self.prepare_device_completion(batch, presented_device, result)?;
        Ok(self.apply_device_completion(plan))
    }

    fn prepare_device_completion(
        &self,
        batch: &DeviceBatchCommitReceipt,
        presented_device: DeviceEnvelope,
        result: i64,
    ) -> Result<DeviceCompletionApplyPlan, RegistryError> {
        self.validate_device_batch_receipt(batch)?;
        let causal_root = self.device_batch_causal_root_commit(batch)?;
        if result != causal_root.result {
            return Err(RegistryError::CommitConflict);
        }
        let root = self.scopes[&batch.scope]
            .device_root
            .as_ref()
            .ok_or(RegistryError::InvalidBatchReceipt)?;
        if presented_device != root.current_device {
            return Err(device_envelope_mismatch(
                root.current_device,
                presented_device,
            ));
        }
        if root.completion.is_some()
            || root.reset_ticket.is_some()
            || root.reset_tombstone.is_some()
            || root.reset_receipt.is_some()
            || root.iotlb_ticket.is_some()
            || root.iotlb_tombstone.is_some()
            || root.closure.is_some()
        {
            return Err(RegistryError::InvalidState);
        }
        let sequence = self.next_device_closure_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let next_revision = self.scopes[&batch.scope]
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let completion = DeviceCompletionReceipt {
            registry_instance_id: self.instance_id,
            scope: batch.scope,
            batch_sequence: batch.batch_sequence,
            device: presented_device,
            sequence,
            causal_root: causal_root.effect,
            causal_commit_sequence: causal_root.sequence,
            result,
        };
        Ok(DeviceCompletionApplyPlan {
            receipt: completion,
            next_device_closure_sequence: next_sequence,
            next_scope_revision: next_revision,
        })
    }

    fn apply_device_completion(
        &mut self,
        plan: DeviceCompletionApplyPlan,
    ) -> DeviceCompletionReceipt {
        let DeviceCompletionApplyPlan {
            receipt,
            next_device_closure_sequence,
            next_scope_revision,
        } = plan;
        self.next_device_closure_sequence = next_device_closure_sequence;
        let scope = self.scopes.get_mut(&receipt.scope).unwrap();
        let root = scope.device_root.as_mut().unwrap();
        root.completion = Some(receipt);
        root.outcome = Some(DeviceClosureResult::Completed(receipt.result));
        scope.revision = next_scope_revision;
        scope.invalidate_recovery_readiness();
        receipt
    }

    /// Records a completed request and installs the reset winner before the
    /// caller invokes its device reset closure.  If that closure panics, the
    /// returned-from-unwind Registry still records both the completion and the
    /// exact reset ticket, so a retry cannot publish a competing outcome.
    pub(crate) fn record_device_completion_and_begin_reset_with_apply<T>(
        &mut self,
        batch: &DeviceBatchCommitReceipt,
        presented_device: DeviceEnvelope,
        result: i64,
        apply_reset: impl FnOnce(&DeviceResetTicket) -> T,
    ) -> Result<(DeviceCompletionReceipt, DeviceResetTicket, T), RegistryError> {
        let plan = self.prepare_device_completion_and_reset(batch, presented_device, result)?;
        let (completion, reset_ticket) = self.apply_device_completion_and_reset(plan);
        let applied = apply_reset(&reset_ticket);
        Ok((completion, reset_ticket, applied))
    }

    fn prepare_device_completion_and_reset(
        &self,
        batch: &DeviceBatchCommitReceipt,
        presented_device: DeviceEnvelope,
        result: i64,
    ) -> Result<DeviceCompletionAndResetApplyPlan, RegistryError> {
        let completion = self.prepare_device_completion(batch, presented_device, result)?;
        let root = self.scopes[&batch.scope]
            .device_root
            .as_ref()
            .ok_or(RegistryError::InvalidBatchReceipt)?;
        // `prepare_device_completion` established the empty closure state.
        // Project its one sequence/revision advance, then validate and mint
        // the reset ticket without mutating the live root.
        let reset_sequence = completion.next_device_closure_sequence;
        let next_device_closure_sequence = reset_sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let next_scope_revision = completion
            .next_scope_revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let reset_ticket = DeviceResetTicket {
            registry_instance_id: self.instance_id,
            scope: batch.scope,
            enrollment_sequence: root
                .enrollment
                .as_ref()
                .ok_or(RegistryError::DeviceBatchNotEnrolled)?
                .enrollment_sequence,
            batch_sequence: Some(batch.batch_sequence),
            device: root.current_device,
            sequence: reset_sequence,
        };
        Ok(DeviceCompletionAndResetApplyPlan {
            completion: completion.receipt,
            reset_ticket,
            next_device_closure_sequence,
            next_scope_revision,
        })
    }

    fn apply_device_completion_and_reset(
        &mut self,
        plan: DeviceCompletionAndResetApplyPlan,
    ) -> (DeviceCompletionReceipt, DeviceResetTicket) {
        let DeviceCompletionAndResetApplyPlan {
            completion,
            reset_ticket,
            next_device_closure_sequence,
            next_scope_revision,
        } = plan;
        self.next_device_closure_sequence = next_device_closure_sequence;
        let scope = self.scopes.get_mut(&completion.scope).unwrap();
        let root = scope.device_root.as_mut().unwrap();
        root.completion = Some(completion);
        root.outcome = Some(DeviceClosureResult::Completed(completion.result));
        root.reset_ticket = Some(reset_ticket);
        scope.revision = next_scope_revision;
        scope.invalidate_recovery_readiness();
        (completion, reset_ticket)
    }

    /// Issues the exact reset attempt that must close device ownership even
    /// after a normal backend completion.
    pub(crate) fn begin_device_reset(
        &mut self,
        batch: &DeviceBatchCommitReceipt,
    ) -> Result<DeviceResetTicket, RegistryError> {
        self.validate_device_batch_receipt(batch)?;
        self.install_device_reset_ticket(batch)
    }

    /// Installs the Registry reset fence before entering the caller's
    /// prevalidated hardware reset-intent apply. If the external closure
    /// unwinds after mutating the device, the exact ticket remains
    /// discoverable and late completion stays rejected.
    pub(crate) fn begin_device_reset_with_apply<T>(
        &mut self,
        batch: &DeviceBatchCommitReceipt,
        apply_hardware: impl FnOnce(&DeviceResetTicket) -> T,
    ) -> Result<(DeviceResetTicket, T), RegistryError> {
        let ticket = self.begin_device_reset(batch)?;
        let hardware = apply_hardware(&ticket);
        Ok((ticket, hardware))
    }

    fn install_device_reset_ticket(
        &mut self,
        batch: &DeviceBatchCommitReceipt,
    ) -> Result<DeviceResetTicket, RegistryError> {
        let root = self.scopes[&batch.scope].device_root.as_ref().unwrap();
        if root.reset_ticket.is_some()
            || root.reset_tombstone.is_some()
            || root.reset_receipt.is_some()
            || root.iotlb_ticket.is_some()
            || root.iotlb_tombstone.is_some()
            || root.closure.is_some()
        {
            return Err(RegistryError::InvalidState);
        }
        if __cser_core::matches!(
            root.outcome,
            Some(
                DeviceClosureResult::IndeterminateAfterReset
                    | DeviceClosureResult::AbortedBeforeCommit
            )
        ) {
            return Err(RegistryError::InvalidState);
        }
        let sequence = self.next_device_closure_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let next_revision = self.scopes[&batch.scope]
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let ticket = DeviceResetTicket {
            registry_instance_id: self.instance_id,
            scope: batch.scope,
            enrollment_sequence: root
                .enrollment
                .as_ref()
                .expect("committed device batch remains enrolled")
                .enrollment_sequence,
            batch_sequence: Some(batch.batch_sequence),
            device: root.current_device,
            sequence,
        };
        self.next_device_closure_sequence = next_sequence;
        let scope = self.scopes.get_mut(&batch.scope).unwrap();
        let root = scope.device_root.as_mut().unwrap();
        root.reset_ticket = Some(ticket);
        scope.revision = next_revision;
        scope.invalidate_recovery_readiness();
        Ok(ticket)
    }

    /// Cancels a fully prepared but unpublished cohort after root revocation.
    /// Prepared descriptor/DMA ownership is retained before the reset ticket
    /// becomes visible; `Abort` cannot release it until reset and IOTLB close.
    pub(crate) fn begin_unpublished_device_cancel(
        &mut self,
        enrollment: &DeviceBatchEnrollmentReceipt,
    ) -> Result<DeviceResetTicket, RegistryError> {
        let root = self.validate_device_enrollment_receipt(enrollment)?;
        if self.scopes[&enrollment.scope].phase != ScopePhase::Closing
            || root.batch_sequence.is_some()
            || !root.publication.is_none()
            || root.reset_ticket.is_some()
            || root.reset_tombstone.is_some()
            || root.reset_receipt.is_some()
            || root.iotlb_ticket.is_some()
            || root.iotlb_tombstone.is_some()
            || root.closure.is_some()
        {
            return Err(RegistryError::InvalidState);
        }
        let retention = self.prepare_device_root_retention(enrollment)?;
        let sequence = self.next_device_closure_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let next_revision = self.scopes[&enrollment.scope]
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let ticket = DeviceResetTicket {
            registry_instance_id: self.instance_id,
            scope: enrollment.scope,
            enrollment_sequence: enrollment.enrollment_sequence,
            batch_sequence: None,
            device: root.current_device,
            sequence,
        };
        self.apply_device_root_retention(enrollment, retention.as_ref());
        self.next_device_closure_sequence = next_sequence;
        let scope = self.scopes.get_mut(&enrollment.scope).unwrap();
        let root = scope.device_root.as_mut().unwrap();
        root.outcome = Some(DeviceClosureResult::AbortedBeforeCommit);
        root.reset_ticket = Some(ticket);
        scope.revision = next_revision;
        scope.invalidate_recovery_readiness();
        Ok(ticket)
    }

    /// A reset timeout retains every cohort credit. It changes closure
    /// progress, not an already authoritative workload result.
    pub(crate) fn retain_device_reset_timeout(
        &mut self,
        ticket: &DeviceResetTicket,
    ) -> Result<DeviceResetTombstone, RegistryError> {
        let enrollment = self.validate_device_closure_context(
            ticket.scope,
            ticket.enrollment_sequence,
            ticket.batch_sequence,
        )?;
        let root = self.scopes[&ticket.scope].device_root.as_ref().unwrap();
        if ticket.registry_instance_id != self.instance_id
            || root.reset_ticket.as_ref() != Some(ticket)
            || ticket.device != root.current_device
            || root.reset_receipt.is_some()
            || root.closure.is_some()
        {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        let retention = self.prepare_device_root_retention(&enrollment)?;
        let sequence = self.next_device_closure_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let next_revision = self.scopes[&ticket.scope]
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let tombstone = DeviceResetTombstone {
            ticket: *ticket,
            sequence,
        };
        self.apply_device_root_retention(&enrollment, retention.as_ref());
        self.next_device_closure_sequence = next_sequence;
        let scope = self.scopes.get_mut(&ticket.scope).unwrap();
        let root = scope.device_root.as_mut().unwrap();
        root.reset_ticket = None;
        root.reset_tombstone = Some(tombstone);
        scope.revision = next_revision;
        scope.invalidate_recovery_readiness();
        Ok(tombstone)
    }

    pub(crate) fn retry_device_reset(
        &mut self,
        tombstone: &DeviceResetTombstone,
    ) -> Result<DeviceResetTicket, RegistryError> {
        self.validate_device_closure_context(
            tombstone.ticket.scope,
            tombstone.ticket.enrollment_sequence,
            tombstone.ticket.batch_sequence,
        )?;
        let root = self.scopes[&tombstone.ticket.scope]
            .device_root
            .as_ref()
            .unwrap();
        if tombstone.ticket.registry_instance_id != self.instance_id
            || root.reset_tombstone.as_ref() != Some(tombstone)
            || root.reset_ticket.is_some()
            || root.reset_receipt.is_some()
            || root.reset_retry_issued
            || tombstone.ticket.device != root.current_device
        {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        let sequence = self.next_device_closure_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let next_revision = self.scopes[&tombstone.ticket.scope]
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let ticket = DeviceResetTicket {
            registry_instance_id: self.instance_id,
            scope: tombstone.ticket.scope,
            enrollment_sequence: tombstone.ticket.enrollment_sequence,
            batch_sequence: tombstone.ticket.batch_sequence,
            device: root.current_device,
            sequence,
        };
        self.next_device_closure_sequence = next_sequence;
        let scope = self.scopes.get_mut(&tombstone.ticket.scope).unwrap();
        let root = scope.device_root.as_mut().unwrap();
        root.reset_ticket = Some(ticket);
        root.reset_retry_issued = true;
        scope.revision = next_revision;
        scope.invalidate_recovery_readiness();
        Ok(ticket)
    }

    /// Couples the facade's prevalidated generation plan to the Registry's
    /// generation advance. Everything fallible is prepared first, then the
    /// Registry installs the reset receipt and new generation before entering
    /// the one external `apply_generation` closure. If that direct apply
    /// unexpectedly unwinds, Registry ownership remains conservatively fenced
    /// and the facade retains its fail-closed owner.
    pub(crate) fn acknowledge_device_reset_with_apply<T>(
        &mut self,
        ticket: &DeviceResetTicket,
        apply_generation: impl FnOnce(&DeviceResetReceipt) -> T,
    ) -> Result<(DeviceResetReceipt, T), RegistryError> {
        let plan = self.prepare_device_reset_apply(ticket)?;
        let receipt = self.apply_device_reset(plan);
        let publication = apply_generation(&receipt);
        Ok((receipt, publication))
    }

    fn prepare_device_reset_apply(
        &self,
        ticket: &DeviceResetTicket,
    ) -> Result<DeviceResetApplyPlan, RegistryError> {
        self.validate_device_closure_context(
            ticket.scope,
            ticket.enrollment_sequence,
            ticket.batch_sequence,
        )?;
        let root = self.scopes[&ticket.scope].device_root.as_ref().unwrap();
        if ticket.registry_instance_id != self.instance_id
            || root.reset_ticket.as_ref() != Some(ticket)
            || ticket.device != root.current_device
            || root.reset_receipt.is_some()
            || root.closure.is_some()
        {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        let new_device = root.current_device.next_generation()?;
        let outcome = match root.outcome {
            Some(outcome) => outcome,
            None if ticket.batch_sequence.is_some() => DeviceClosureResult::IndeterminateAfterReset,
            None => return Err(RegistryError::InvalidState),
        };
        let sequence = self.next_device_closure_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let next_revision = self.scopes[&ticket.scope]
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let receipt = DeviceResetReceipt {
            registry_instance_id: self.instance_id,
            scope: ticket.scope,
            enrollment_sequence: ticket.enrollment_sequence,
            batch_sequence: ticket.batch_sequence,
            old_device: ticket.device,
            new_device,
            sequence,
            outcome,
        };
        Ok(DeviceResetApplyPlan {
            receipt,
            next_device_closure_sequence: next_sequence,
            next_scope_revision: next_revision,
        })
    }

    fn apply_device_reset(&mut self, plan: DeviceResetApplyPlan) -> DeviceResetReceipt {
        let DeviceResetApplyPlan {
            receipt,
            next_device_closure_sequence,
            next_scope_revision,
        } = plan;
        self.next_device_closure_sequence = next_device_closure_sequence;
        let scope = self.scopes.get_mut(&receipt.scope).unwrap();
        let root = scope.device_root.as_mut().unwrap();
        root.current_device = receipt.new_device;
        root.outcome = Some(receipt.outcome);
        root.reset_ticket = None;
        root.reset_receipt = Some(receipt);
        scope.revision = next_scope_revision;
        scope.invalidate_recovery_readiness();
        receipt
    }

    pub(crate) fn begin_device_iotlb(
        &mut self,
        reset: &DeviceResetReceipt,
    ) -> Result<DeviceIotlbTicket, RegistryError> {
        let root = self
            .scopes
            .get(&reset.scope)
            .and_then(|scope| scope.device_root.as_ref())
            .ok_or(RegistryError::InvalidBatchReceipt)?;
        if reset.registry_instance_id != self.instance_id
            || root.reset_receipt.as_ref() != Some(reset)
            || reset.new_device != root.current_device
            || root.iotlb_ticket.is_some()
            || root.iotlb_tombstone.is_some()
            || root.closure.is_some()
        {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        let sequence = self.next_device_closure_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let next_revision = self.scopes[&reset.scope]
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let ticket = DeviceIotlbTicket {
            registry_instance_id: self.instance_id,
            scope: reset.scope,
            enrollment_sequence: reset.enrollment_sequence,
            batch_sequence: reset.batch_sequence,
            device: reset.new_device,
            reset_sequence: reset.sequence,
            sequence,
        };
        self.next_device_closure_sequence = next_sequence;
        let scope = self.scopes.get_mut(&reset.scope).unwrap();
        scope.device_root.as_mut().unwrap().iotlb_ticket = Some(ticket);
        scope.revision = next_revision;
        scope.invalidate_recovery_readiness();
        Ok(ticket)
    }

    /// Installs the Registry IOTLB fence before entering the caller's
    /// prevalidated hardware invalidation-intent apply. An unwind cannot make
    /// the root appear eligible for a second unfenced ownership transition.
    pub(crate) fn begin_device_iotlb_with_apply<T>(
        &mut self,
        reset: &DeviceResetReceipt,
        apply_hardware: impl FnOnce(&DeviceIotlbTicket) -> T,
    ) -> Result<(DeviceIotlbTicket, T), RegistryError> {
        let ticket = self.begin_device_iotlb(reset)?;
        let hardware = apply_hardware(&ticket);
        Ok((ticket, hardware))
    }

    pub(crate) fn retain_device_iotlb_timeout(
        &mut self,
        ticket: &DeviceIotlbTicket,
    ) -> Result<DeviceIotlbTombstone, RegistryError> {
        let enrollment = self.validate_device_closure_context(
            ticket.scope,
            ticket.enrollment_sequence,
            ticket.batch_sequence,
        )?;
        let root = self.scopes[&ticket.scope].device_root.as_ref().unwrap();
        if ticket.registry_instance_id != self.instance_id
            || root.iotlb_ticket.as_ref() != Some(ticket)
            || ticket.device != root.current_device
            || root.reset_receipt.as_ref().is_none_or(|reset| {
                reset.sequence != ticket.reset_sequence || reset.new_device != ticket.device
            })
            || root.closure.is_some()
        {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        let retention = self.prepare_device_root_retention(&enrollment)?;
        let sequence = self.next_device_closure_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let next_revision = self.scopes[&ticket.scope]
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let tombstone = DeviceIotlbTombstone {
            ticket: *ticket,
            sequence,
        };
        self.apply_device_root_retention(&enrollment, retention.as_ref());
        self.next_device_closure_sequence = next_sequence;
        let scope = self.scopes.get_mut(&ticket.scope).unwrap();
        let root = scope.device_root.as_mut().unwrap();
        root.iotlb_ticket = None;
        root.iotlb_tombstone = Some(tombstone);
        scope.revision = next_revision;
        scope.invalidate_recovery_readiness();
        Ok(tombstone)
    }

    pub(crate) fn retry_device_iotlb(
        &mut self,
        reset: &DeviceResetReceipt,
        tombstone: &DeviceIotlbTombstone,
    ) -> Result<DeviceIotlbTicket, RegistryError> {
        let root = self
            .scopes
            .get(&reset.scope)
            .and_then(|scope| scope.device_root.as_ref())
            .ok_or(RegistryError::InvalidBatchReceipt)?;
        if reset.registry_instance_id != self.instance_id
            || root.reset_receipt.as_ref() != Some(reset)
            || root.iotlb_tombstone.as_ref() != Some(tombstone)
            || tombstone.ticket.registry_instance_id != self.instance_id
            || tombstone.ticket.enrollment_sequence != reset.enrollment_sequence
            || tombstone.ticket.batch_sequence != reset.batch_sequence
            || tombstone.ticket.device != root.current_device
            || root.iotlb_ticket.is_some()
            || root.iotlb_retry_issued
            || root.closure.is_some()
        {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        let sequence = self.next_device_closure_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let next_revision = self.scopes[&reset.scope]
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let ticket = DeviceIotlbTicket {
            registry_instance_id: self.instance_id,
            scope: reset.scope,
            enrollment_sequence: reset.enrollment_sequence,
            batch_sequence: reset.batch_sequence,
            device: root.current_device,
            reset_sequence: reset.sequence,
            sequence,
        };
        self.next_device_closure_sequence = next_sequence;
        let scope = self.scopes.get_mut(&reset.scope).unwrap();
        let root = scope.device_root.as_mut().unwrap();
        root.iotlb_ticket = Some(ticket);
        root.iotlb_retry_issued = true;
        scope.revision = next_revision;
        scope.invalidate_recovery_readiness();
        Ok(ticket)
    }

    /// Couples a prevalidated facade quiescence plan to the authoritative
    /// Registry closure. All validation, receipt construction, and overflow
    /// checks precede mutation; the Registry then installs the closure receipt
    /// before the one external quiescence apply. If that direct apply unwinds,
    /// the Registry cannot reopen or republish ownership and the facade keeps
    /// the concrete owner fail-closed.
    pub(crate) fn acknowledge_device_iotlb_with_apply<T>(
        &mut self,
        ticket: &DeviceIotlbTicket,
        apply_quiescence: impl FnOnce(&DeviceClosureReceipt) -> T,
    ) -> Result<(DeviceClosureReceipt, T), RegistryError> {
        let plan = self.prepare_device_iotlb_apply(ticket)?;
        let receipt = self.apply_device_iotlb(plan);
        let publication = apply_quiescence(&receipt);
        Ok((receipt, publication))
    }

    fn prepare_device_iotlb_apply(
        &self,
        ticket: &DeviceIotlbTicket,
    ) -> Result<DeviceIotlbApplyPlan, RegistryError> {
        self.validate_device_closure_context(
            ticket.scope,
            ticket.enrollment_sequence,
            ticket.batch_sequence,
        )?;
        let root = self.scopes[&ticket.scope].device_root.as_ref().unwrap();
        if ticket.registry_instance_id != self.instance_id
            || root.iotlb_ticket.as_ref() != Some(ticket)
            || ticket.device != root.current_device
            || root.reset_receipt.as_ref().is_none_or(|reset| {
                reset.sequence != ticket.reset_sequence || reset.new_device != ticket.device
            })
            || root.closure.is_some()
        {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        let outcome = root.outcome.ok_or(RegistryError::InvalidState)?;
        let sequence = self.next_device_closure_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let next_revision = self.scopes[&ticket.scope]
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let receipt = DeviceClosureReceipt {
            registry_instance_id: self.instance_id,
            scope: ticket.scope,
            enrollment_sequence: ticket.enrollment_sequence,
            batch_sequence: ticket.batch_sequence,
            device: ticket.device,
            sequence,
            outcome,
        };
        Ok(DeviceIotlbApplyPlan {
            receipt,
            next_device_closure_sequence: next_sequence,
            next_scope_revision: next_revision,
        })
    }

    fn apply_device_iotlb(&mut self, plan: DeviceIotlbApplyPlan) -> DeviceClosureReceipt {
        let DeviceIotlbApplyPlan {
            receipt,
            next_device_closure_sequence,
            next_scope_revision,
        } = plan;
        self.next_device_closure_sequence = next_device_closure_sequence;
        let scope = self.scopes.get_mut(&receipt.scope).unwrap();
        let root = scope.device_root.as_mut().unwrap();
        root.iotlb_ticket = None;
        root.closure = Some(receipt);
        scope.revision = next_scope_revision;
        scope.invalidate_recovery_readiness();
        receipt
    }

    pub(crate) fn validate_device_closure_receipt(
        &self,
        presented: &DeviceClosureReceipt,
    ) -> Result<(), RegistryError> {
        if presented.registry_instance_id != self.instance_id || presented.sequence == 0 {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        self.validate_device_closure_context(
            presented.scope,
            presented.enrollment_sequence,
            presented.batch_sequence,
        )?;
        let root = self.scopes[&presented.scope].device_root.as_ref().unwrap();
        if presented.device != root.current_device {
            return Err(device_envelope_mismatch(
                root.current_device,
                presented.device,
            ));
        }
        if root.closure.as_ref() != Some(presented) {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        Ok(())
    }

    /// Atomically installs the facade's exact three-owner IOTLB closure and
    /// consumes the materialized preparation bearer. Business-effect draining
    /// may begin only after this transition succeeds.
    pub(crate) fn install_materialized_device_closure_from_view(
        &mut self,
        ticket: MaterializedDeviceTicket,
        registry_closure: &DeviceClosureReceipt,
        closure_view: &(impl DeviceClosureReceiptView + ?Sized),
    ) -> Result<(), DevicePreparationRegistryFailure<MaterializedDeviceTicket>> {
        if let Err(error) = self.validate_device_closure_receipt(registry_closure) {
            return Err(DevicePreparationRegistryFailure {
                error,
                input: ticket,
            });
        }
        let prepared = match self.infrastructure.materialized_device_identity(&ticket) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input: ticket,
                });
            }
        };
        let device_closure =
            match infrastructure::device_receipt_bridge::verify_closure(prepared, closure_view) {
                Ok(device_closure) => device_closure,
                Err(error) => {
                    return Err(DevicePreparationRegistryFailure {
                        error: error.into(),
                        input: ticket,
                    });
                }
            };
        let scope_key = ticket.scope();
        let mut candidate = match self.combined_scope_candidate(scope_key) {
            Ok(candidate) => candidate,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error,
                    input: ticket,
                });
            }
        };
        let release = match candidate
            .replacement
            .infrastructure
            .prepare_materialized_device_release_in_candidate(
                &ticket,
                infrastructure::ValidatedDeviceClosureProof::new(*registry_closure),
                device_closure,
            ) {
            Ok(release) => release,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error: error.into(),
                    input: ticket,
                });
            }
        };
        if let Err(error) = advance_device_preparation_scope(
            candidate.replacement.scopes.get_mut(&scope_key).unwrap(),
        ) {
            return Err(DevicePreparationRegistryFailure {
                error,
                input: ticket,
            });
        }
        candidate
            .replacement
            .infrastructure
            .apply_materialized_device_release_in_candidate(release);
        let install = match self.prepare_combined_scope_install(candidate) {
            Ok(install) => install,
            Err(error) => {
                return Err(DevicePreparationRegistryFailure {
                    error,
                    input: ticket,
                });
            }
        };
        self.install_combined_scope(install);
        let installed = self
            .infrastructure
            .consume_materialized_ticket_after_release(ticket);
        __cser_core::debug_assert_eq!(installed, *registry_closure);
        Ok(())
    }

    /// Terminalizes one leaf of a closed device cohort. Generic terminal and
    /// revoke APIs remain unable to release these credits even after IOTLB
    /// closure; callers must present the exact registry-native receipt.
    pub(crate) fn stage_device_batch_terminal(
        &mut self,
        closure: &DeviceClosureReceipt,
        effect: EffectKey,
        request: TerminalRequest,
    ) -> Result<Terminalization, RegistryError> {
        const INDETERMINATE_EIO: i64 = -5;

        self.validate_device_closure_receipt(closure)?;
        let record = self
            .effects
            .get(&effect)
            .ok_or(RegistryError::UnknownEffect)?;
        let enrollment = self.scopes[&closure.scope]
            .device_root
            .as_ref()
            .and_then(|root| root.enrollment.as_ref())
            .ok_or(RegistryError::DeviceBatchNotEnrolled)?;
        if !enrollment.effects.contains(&effect)
            || match closure.batch_sequence {
                Some(sequence) => record
                    .device_batch
                    .is_none_or(|membership| membership.sequence != sequence),
                None => record.device_batch.is_some() || record.commit.is_some(),
            }
        {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        match closure.outcome {
            DeviceClosureResult::Completed(_) => {
                if request.outcome != TerminalOutcome::Completed
                    || record
                        .commit
                        .as_ref()
                        .is_none_or(|commit| commit.result != request.result)
                {
                    return Err(RegistryError::InvalidState);
                }
            }
            DeviceClosureResult::IndeterminateAfterReset => {
                if request.outcome != TerminalOutcome::IndeterminateAfterReset
                    || request.result != INDETERMINATE_EIO
                {
                    return Err(RegistryError::InvalidState);
                }
            }
            DeviceClosureResult::AbortedBeforeCommit => {
                if request.outcome != TerminalOutcome::Aborted || record.commit.is_some() {
                    return Err(RegistryError::InvalidState);
                }
            }
        }
        self.stage_terminal_inner(effect, request, Some(closure.enrollment_sequence))
    }

    fn prepare_device_root_retention(
        &self,
        enrollment: &DeviceBatchEnrollmentReceipt,
    ) -> Result<Option<DeviceRetentionPlan>, RegistryError> {
        let mut aggregate = BTreeMap::<CreditClass, u64>::new();
        let mut state = None;
        let retained_unpublished = self.scopes.get(&enrollment.scope).is_some_and(|scope| {
            scope.phase == ScopePhase::Closing
                && scope.device_root.as_ref().is_some_and(|root| {
                    root.enrollment.as_ref() == Some(enrollment)
                        && root.batch_sequence.is_none()
                        && root.outcome == Some(DeviceClosureResult::AbortedBeforeCommit)
                })
        });
        for effect in &enrollment.effects {
            let record = self
                .effects
                .get(effect)
                .ok_or(RegistryError::UnknownEffect)?;
            let valid_unpublished = __cser_core::matches!(
                record.phase,
                EffectPhase::Registered | EffectPhase::Prepared
            ) && (record.credit_state == CreditState::Held
                || (record.credit_state == CreditState::Retained && retained_unpublished));
            let valid_published = record.phase == EffectPhase::Committed
                && __cser_core::matches!(
                    record.credit_state,
                    CreditState::Committed | CreditState::Retained
                );
            if !valid_unpublished && !valid_published {
                return Err(RegistryError::InvalidState);
            }
            match state {
                None => state = Some(record.credit_state),
                Some(existing) if existing != record.credit_state => {
                    return Err(RegistryError::InvalidState);
                }
                Some(_) => {}
            }
            for charge in &record.credits {
                let units = aggregate.entry(charge.class).or_default();
                *units = units
                    .checked_add(charge.units)
                    .ok_or(RegistryError::CounterOverflow)?;
            }
        }
        if state == Some(CreditState::Retained) {
            return Ok(None);
        }
        if state != Some(CreditState::Committed) && state != Some(CreditState::Held) {
            return Err(RegistryError::InvalidState);
        }
        let charges: Vec<_> = aggregate
            .into_iter()
            .map(|(class, units)| CreditCharge { class, units })
            .collect();
        let from = state.unwrap();
        self.scopes[&enrollment.scope]
            .credits
            .validate_retain(&charges, from)?;
        Ok(Some(DeviceRetentionPlan { charges, from }))
    }

    fn apply_device_root_retention(
        &mut self,
        enrollment: &DeviceBatchEnrollmentReceipt,
        plan: Option<&DeviceRetentionPlan>,
    ) {
        let Some(plan) = plan else {
            return;
        };
        self.scopes
            .get_mut(&enrollment.scope)
            .unwrap()
            .credits
            .retain_validated(&plan.charges, plan.from);
        for effect in &enrollment.effects {
            self.effects.get_mut(effect).unwrap().credit_state = CreditState::Retained;
        }
    }

    fn prepare_device_batch(
        &self,
        authority: KernelRootAuthority,
        enrollment: &DeviceBatchEnrollmentReceipt,
        commits: &[(PortalHandle, CommitMetadata)],
    ) -> Result<PreparedDeviceBatch, RegistryError> {
        self.validate_kernel_root_authority(authority)?;
        if enrollment.registry_instance_id != self.instance_id
            || enrollment.scope != authority.scope
            || enrollment.authority_epoch != authority.authority_epoch
            || enrollment.cancel_only
        {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        let root_state = self.scopes[&authority.scope]
            .device_root
            .as_ref()
            .ok_or(RegistryError::DeviceBatchNotEnrolled)?;
        if root_state.enrollment.as_ref() != Some(enrollment) {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        let expected_device = enrollment.device;
        expected_device.validate()?;
        if commits.is_empty() || commits.len() != enrollment.effects.len() {
            return Err(RegistryError::InvalidState);
        }

        let mut seen = BTreeSet::new();
        let mut committed = 0_usize;
        let mut device_effects = Vec::with_capacity(commits.len());
        let mut root_count = 0_usize;
        for ((handle, metadata), enrolled_effect) in commits.iter().zip(&enrollment.effects) {
            let effect = self.validate_root_portal(authority, *handle)?;
            if effect != *enrolled_effect || !seen.insert(effect) {
                return Err(RegistryError::InvalidState);
            }
            let record = self.effects.get(&effect).unwrap();
            if record.identity.parent.is_none() {
                root_count = root_count
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
            }
            if let Some(device) = record.identity.device {
                if device != expected_device {
                    return Err(device_envelope_mismatch(expected_device, device));
                }
                device_effects.push(effect);
            }
            if let Some(receipt) = &record.commit {
                committed = committed
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
                if receipt.result != metadata.result
                    || receipt.domain_revision != metadata.domain_revision
                {
                    return Err(RegistryError::CommitConflict);
                }
            } else if record.phase != EffectPhase::Prepared
                || record.credit_state != CreditState::Held
                || record.device_batch.is_some()
            {
                return Err(RegistryError::InvalidState);
            }
        }

        let live = self
            .by_scope
            .get(&authority.scope)
            .ok_or(RegistryError::InvalidState)?;
        if live != &seen || root_count != 1 || device_effects.is_empty() {
            return Err(RegistryError::InvalidState);
        }
        for effect in &seen {
            if let Some(parent) = self.effects[effect].identity.parent
                && !seen.contains(&parent)
            {
                return Err(RegistryError::InvalidHandle);
            }
        }

        if committed != 0 {
            if committed != commits.len() {
                return Err(RegistryError::InvalidState);
            }
            let first = self.effects[&commits[0].0.effect]
                .device_batch
                .ok_or(RegistryError::InvalidBatchReceipt)?;
            if root_state.batch_sequence != Some(first.sequence) {
                return Err(RegistryError::InvalidBatchReceipt);
            }
            let receipt = self.reconstruct_device_batch_receipt(authority.scope, first.sequence)?;
            if receipt.device != expected_device {
                return Err(device_envelope_mismatch(expected_device, receipt.device));
            }
            if receipt.commits.len() != commits.len() {
                return Err(RegistryError::InvalidBatchReceipt);
            }
            for ((handle, metadata), authoritative) in commits.iter().zip(&receipt.commits) {
                if handle.effect != authoritative.effect
                    || metadata.result != authoritative.result
                    || metadata.domain_revision != authoritative.domain_revision
                {
                    return Err(RegistryError::CommitConflict);
                }
            }
            match &root_state.publication {
                DevicePublicationProvenance::Legacy => {}
                DevicePublicationProvenance::Applied { batch, .. } if batch == &receipt => {}
                DevicePublicationProvenance::None
                | DevicePublicationProvenance::Publishing { .. }
                | DevicePublicationProvenance::Applied { .. } => {
                    return Err(RegistryError::InvalidBatchReceipt);
                }
            }
            return Ok(PreparedDeviceBatch::Replay(receipt));
        }
        if root_state.batch_sequence.is_some() || !root_state.publication.is_none() {
            return Err(RegistryError::InvalidBatchReceipt);
        }

        let count = u64::try_from(commits.len()).map_err(|_| RegistryError::CounterOverflow)?;
        let next_commit_sequence = self
            .next_commit_sequence
            .checked_add(count)
            .ok_or(RegistryError::CounterOverflow)?;
        let batch_sequence = self.next_device_batch_sequence;
        let next_device_batch_sequence = batch_sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let next_scope_revision = self.scopes[&authority.scope]
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;

        let mut aggregate = BTreeMap::<CreditClass, u64>::new();
        for (handle, _) in commits {
            for charge in &self.effects[&handle.effect].credits {
                let units = aggregate.entry(charge.class).or_default();
                *units = units
                    .checked_add(charge.units)
                    .ok_or(RegistryError::CounterOverflow)?;
            }
        }
        let mut charges = Vec::with_capacity(aggregate.len());
        for (class, units) in aggregate {
            charges.push(CreditCharge { class, units });
        }
        self.scopes[&authority.scope]
            .credits
            .validate_commit(&charges)?;

        let mut receipts = Vec::with_capacity(commits.len());
        for (offset, (handle, metadata)) in commits.iter().enumerate() {
            let offset = u64::try_from(offset).map_err(|_| RegistryError::CounterOverflow)?;
            let sequence = self
                .next_commit_sequence
                .checked_add(offset)
                .ok_or(RegistryError::CounterOverflow)?;
            let record = &self.effects[&handle.effect];
            receipts.push(CommitReceipt {
                registry_instance_id: self.instance_id,
                effect: handle.effect,
                scope: authority.scope,
                authority_epoch: authority.authority_epoch,
                binding_epoch: record.identity.binding_epoch,
                sequence,
                result: metadata.result,
                domain_revision: metadata.domain_revision,
                descriptor_digest: record.descriptor.digest(),
            });
        }
        let receipt = DeviceBatchCommitReceipt {
            registry_instance_id: self.instance_id,
            scope: authority.scope,
            authority_epoch: authority.authority_epoch,
            batch_sequence,
            device: expected_device,
            commits: receipts,
            device_effects,
        };
        Ok(PreparedDeviceBatch::Apply(DeviceBatchApplyPlan {
            receipt,
            charges,
            next_commit_sequence,
            next_device_batch_sequence,
            next_scope_revision,
        }))
    }

    fn apply_device_batch(&mut self, plan: DeviceBatchApplyPlan) -> DeviceBatchCommitReceipt {
        let DeviceBatchApplyPlan {
            receipt,
            charges,
            next_commit_sequence,
            next_device_batch_sequence,
            next_scope_revision,
        } = plan;
        let size = receipt.commits.len();

        self.next_commit_sequence = next_commit_sequence;
        self.next_device_batch_sequence = next_device_batch_sequence;
        let scope = self
            .scopes
            .get_mut(&receipt.scope)
            .expect("prevalidated device-batch scope remains present");
        scope.credits.commit_validated(&charges);
        scope
            .device_root
            .as_mut()
            .expect("prevalidated device root remains present")
            .batch_sequence = Some(receipt.batch_sequence);
        for (ordinal, commit) in receipt.commits.iter().enumerate() {
            let record = self
                .effects
                .get_mut(&commit.effect)
                .expect("prevalidated device-batch effect remains present");
            record.phase = EffectPhase::Committed;
            record.credit_state = CreditState::Committed;
            record.commit = Some(commit.clone());
            record.device_batch = Some(DeviceBatchMembership {
                sequence: receipt.batch_sequence,
                ordinal,
                size,
                device: receipt.device,
            });
        }
        let scope = self.scopes.get_mut(&receipt.scope).unwrap();
        scope.revision = next_scope_revision;
        scope.invalidate_recovery_readiness();
        receipt
    }

    fn reconstruct_device_batch_receipt(
        &self,
        scope_key: ScopeKey,
        batch_sequence: u64,
    ) -> Result<DeviceBatchCommitReceipt, RegistryError> {
        if batch_sequence == 0 {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        let first = self
            .effects
            .values()
            .find_map(|record| {
                record.device_batch.filter(|membership| {
                    record.identity.scope == scope_key && membership.sequence == batch_sequence
                })
            })
            .ok_or(RegistryError::InvalidBatchReceipt)?;
        if first.size == 0 || first.sequence >= self.next_device_batch_sequence {
            return Err(RegistryError::InvalidBatchReceipt);
        }

        let mut slots = __cser_alloc::vec![None::<CommitReceipt>; first.size];
        let mut device_slots = __cser_alloc::vec![false; first.size];
        let mut authority_epoch = None;
        for record in self.effects.values() {
            let Some(membership) = record.device_batch else {
                continue;
            };
            if record.identity.scope != scope_key || membership.sequence != batch_sequence {
                continue;
            }
            if membership.size != first.size
                || membership.device != first.device
                || membership.ordinal >= first.size
                || slots[membership.ordinal].is_some()
            {
                return Err(RegistryError::InvalidBatchReceipt);
            }
            let commit = record
                .commit
                .clone()
                .ok_or(RegistryError::InvalidBatchReceipt)?;
            if commit.registry_instance_id != self.instance_id
                || commit.scope != scope_key
                || commit.effect != record.identity.effect
            {
                return Err(RegistryError::InvalidBatchReceipt);
            }
            match authority_epoch {
                None => authority_epoch = Some(commit.authority_epoch),
                Some(epoch) if epoch != commit.authority_epoch => {
                    return Err(RegistryError::InvalidBatchReceipt);
                }
                Some(_) => {}
            }
            if let Some(device) = record.identity.device {
                if device != first.device {
                    return Err(device_envelope_mismatch(first.device, device));
                }
                device_slots[membership.ordinal] = true;
            }
            slots[membership.ordinal] = Some(commit);
        }
        if slots.iter().any(Option::is_none) || !device_slots.iter().any(|is_device| *is_device) {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        let commits: Vec<_> = slots
            .into_iter()
            .map(|slot| slot.expect("all device-batch ordinals were validated"))
            .collect();
        let device_effects = commits
            .iter()
            .enumerate()
            .filter_map(|(index, commit)| device_slots[index].then_some(commit.effect))
            .collect();
        Ok(DeviceBatchCommitReceipt {
            registry_instance_id: self.instance_id,
            scope: scope_key,
            authority_epoch: authority_epoch.ok_or(RegistryError::InvalidBatchReceipt)?,
            batch_sequence,
            device: first.device,
            commits,
            device_effects,
        })
    }

    pub(crate) fn crash(
        &mut self,
        scope_key: ScopeKey,
        sender: TaskKey,
    ) -> Result<CrashReceipt, RegistryError> {
        let cohort = self
            .production
            .by_domain
            .get(&(scope_key, DomainKey::LEGACY))
            .cloned()
            .unwrap_or_default();
        let scope = self
            .scopes
            .get_mut(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        if scope.supervisor != Some(sender) {
            return Err(RegistryError::NoSupervisor);
        }
        let next_legacy_revision = scope.domains[&DomainKey::LEGACY]
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let previous_binding_epoch = scope.binding_epoch;
        let binding_epoch = scope
            .binding_epoch
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let revision = scope
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        scope.binding_epoch = binding_epoch;
        scope.supervisor = None;
        scope.fallback_running = true;
        scope.revision = revision;
        scope.recovery = Some(RecoveryState {
            crash_revision: scope.revision,
            cohort: cohort.clone(),
            unadopted: cohort.clone(),
            snapshot: None,
            ready: None,
        });
        let legacy = scope
            .domains
            .get_mut(&DomainKey::LEGACY)
            .expect("legacy binding is created with the scope");
        legacy.binding_epoch = scope.binding_epoch;
        legacy.supervisor = None;
        legacy.fallback_running = true;
        legacy.revision = next_legacy_revision;
        scope.invalidate_recovery_readiness();
        Ok(CrashReceipt {
            scope: scope_key,
            previous_binding_epoch,
            binding_epoch: scope.binding_epoch,
            cohort,
        })
    }

    pub(crate) fn recovery_snapshot(
        &mut self,
        scope_key: ScopeKey,
        replacement: TaskKey,
    ) -> Result<RecoverySnapshot, RegistryError> {
        validate_generation(replacement.generation)?;
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        if scope.phase != ScopePhase::Active
            || !scope.fallback_running
            || scope.supervisor.is_some()
        {
            return Err(RegistryError::InvalidState);
        }
        let recovery = scope.recovery.as_ref().ok_or(RegistryError::InvalidState)?;
        let mut effects = Vec::with_capacity(recovery.cohort.len());
        for effect in &recovery.cohort {
            let record = self
                .effects
                .get(effect)
                .ok_or(RegistryError::UnknownEffect)?;
            effects.push(RecoveryEffectSummary {
                effect: *effect,
                binding_epoch: record.identity.binding_epoch,
                phase: record.phase,
                descriptor_digest: record.descriptor.digest(),
                commit_sequence: record.commit.as_ref().map(CommitReceipt::sequence),
                outcome_required: record.outcome_required,
                outcome: record.outcome,
                terminal_manifest_digest: record
                    .terminal
                    .as_ref()
                    .and_then(TerminalReceipt::manifest_digest),
            });
        }
        let snapshot = RecoverySnapshot {
            scope: scope_key,
            replacement,
            authority_epoch: scope.authority_epoch,
            binding_epoch: scope.binding_epoch,
            revision: scope.revision,
            domain_revision: scope.domain_revision,
            effects,
        };
        let recovery = self
            .scopes
            .get_mut(&scope_key)
            .unwrap()
            .recovery
            .as_mut()
            .unwrap();
        recovery.snapshot = Some(snapshot.clone());
        recovery.ready = None;
        Ok(snapshot)
    }

    pub(crate) fn ready(
        &mut self,
        scope_key: ScopeKey,
        replacement: TaskKey,
        snapshot: &RecoverySnapshot,
    ) -> Result<(), RegistryError> {
        let scope = self
            .scopes
            .get_mut(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        map_handoff_gate(scope.handoff_gate.require_open())?;
        if scope.phase != ScopePhase::Active
            || !scope.fallback_running
            || scope.supervisor.is_some()
        {
            return Err(RegistryError::InvalidState);
        }
        let recovery = scope.recovery.as_mut().ok_or(RegistryError::InvalidState)?;
        if recovery.snapshot.as_ref() != Some(snapshot)
            || snapshot.scope != scope_key
            || snapshot.replacement != replacement
            || snapshot.revision != scope.revision
            || recovery.crash_revision > snapshot.revision
        {
            return Err(RegistryError::SnapshotChanged);
        }
        recovery.ready = Some(replacement);
        Ok(())
    }

    pub(crate) fn rebind(
        &mut self,
        scope_key: ScopeKey,
        replacement: TaskKey,
    ) -> Result<RebindReceipt, RegistryError> {
        let scope = self
            .scopes
            .get_mut(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        map_handoff_gate(scope.handoff_gate.require_open())?;
        if scope.phase != ScopePhase::Active
            || !scope.fallback_running
            || scope.supervisor.is_some()
            || scope.recovery.as_ref().and_then(|recovery| recovery.ready) != Some(replacement)
        {
            return Err(RegistryError::RecoveryNotReady);
        }
        scope.supervisor = Some(replacement);
        scope.fallback_running = false;
        scope.recovery.as_mut().unwrap().ready = None;
        let legacy = scope
            .domains
            .get_mut(&DomainKey::LEGACY)
            .expect("legacy binding is created with the scope");
        legacy.supervisor = Some(replacement);
        legacy.fallback_running = false;
        Ok(RebindReceipt {
            scope: scope_key,
            binding_epoch: scope.binding_epoch,
            supervisor: replacement,
        })
    }

    pub(crate) fn recover_next(
        &self,
        scope_key: ScopeKey,
        sender: TaskKey,
    ) -> Result<Option<RecoveryItem>, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        if scope.phase != ScopePhase::Active || scope.supervisor != Some(sender) {
            return Err(RegistryError::NoSupervisor);
        }
        let recovery = scope.recovery.as_ref().ok_or(RegistryError::InvalidState)?;
        let Some(effect) = recovery.unadopted.first() else {
            return Ok(None);
        };
        let record = self
            .effects
            .get(effect)
            .ok_or(RegistryError::UnknownEffect)?;
        Ok(Some(RecoveryItem {
            handle: record.handle(),
            descriptor: record.descriptor,
            phase: record.phase,
            commit: record.commit.clone(),
            outcome_required: record.outcome_required,
            outcome: record.outcome,
            terminal_manifest_digest: record
                .terminal
                .as_ref()
                .and_then(TerminalReceipt::manifest_digest),
        }))
    }

    pub(crate) fn adopt(
        &mut self,
        scope_key: ScopeKey,
        sender: TaskKey,
        old_handle: PortalHandle,
    ) -> Result<PortalHandle, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        map_handoff_gate(scope.handoff_gate.require_open())?;
        if old_handle.authority_epoch != scope.authority_epoch {
            return Err(RegistryError::StaleAuthority);
        }
        if scope.phase != ScopePhase::Active || scope.supervisor != Some(sender) {
            return Err(RegistryError::NoSupervisor);
        }
        if old_handle.scope != scope_key || old_handle.domain != DomainKey::LEGACY {
            return Err(RegistryError::InvalidHandle);
        }
        let effect = old_handle.effect;
        let record = self
            .effects
            .get(&effect)
            .ok_or(RegistryError::UnknownEffect)?;
        if record.identity.scope != scope_key || record.identity.domain != DomainKey::LEGACY {
            return Err(RegistryError::InvalidHandle);
        }
        let recovery = scope.recovery.as_ref().ok_or(RegistryError::NotAdoptable)?;
        if !recovery.unadopted.contains(&effect) {
            return Err(RegistryError::NotAdoptable);
        }
        if record.phase.is_terminal()
            || old_handle.binding_epoch >= scope.binding_epoch
            || record.identity.binding_epoch != old_handle.binding_epoch
            || record.nonce != old_handle.nonce
        {
            return Err(RegistryError::NotAdoptable);
        }
        let binding_epoch = scope.binding_epoch;
        let next_revision = scope
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let nonce = self.take_nonce()?;
        let record = self.effects.get_mut(&effect).unwrap();
        record.identity.binding_epoch = binding_epoch;
        record.nonce = nonce;
        let new_handle = record.handle();
        let scope = self.scopes.get_mut(&scope_key).unwrap();
        scope.recovery.as_mut().unwrap().unadopted.remove(&effect);
        scope.revision = next_revision;
        scope.invalidate_recovery_readiness();
        Ok(new_handle)
    }

    pub(crate) fn recovery_remaining(&self, scope_key: ScopeKey) -> Result<usize, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        Ok(scope
            .recovery
            .as_ref()
            .map_or(0, |recovery| recovery.unadopted.len()))
    }

    /// Permanently removes service authority from one existing domain without
    /// allocating or advancing a fallible counter.
    ///
    /// `observed_binding_epoch` is retained only as an audit hint. It is never
    /// used to narrow the fence: once installed, the marker blocks every portal
    /// and recovery entry for the domain until the enclosing scope is retired.
    /// This tranche deliberately exposes no clear/retry operation.
    pub(crate) fn isolate_domain_authority(
        &mut self,
        scope_key: ScopeKey,
        domain: DomainKey,
        service: TaskKey,
        observed_binding_epoch: Option<u64>,
    ) -> DomainIsolationOutcome {
        if domain == DomainKey::LEGACY || service.generation() == 0 {
            return DomainIsolationOutcome::InvalidTarget;
        }
        let retained_effects_at_isolation = self
            .production
            .by_domain
            .get(&(scope_key, domain))
            .map_or(0, BTreeSet::len);
        let Some(scope) = self.scopes.get_mut(&scope_key) else {
            return DomainIsolationOutcome::UnknownScope;
        };
        let Some(binding) = scope.domains.get_mut(&domain) else {
            return DomainIsolationOutcome::UnknownDomain;
        };
        if let Some(receipt) = binding.quarantine {
            return DomainIsolationOutcome::AlreadyIsolated(receipt);
        }
        let (crash_revision, recovery_attempt, unadopted_effects_at_isolation) = binding
            .recovery
            .as_ref()
            .map_or((None, None, 0), |recovery| {
                (
                    Some(recovery.crash_revision),
                    recovery.snapshot.as_ref().map(|snapshot| snapshot.attempt),
                    recovery.unadopted.len(),
                )
            });
        let receipt = DomainQuarantineReceipt {
            registry_instance_id: self.instance_id,
            scope: scope_key,
            domain,
            service,
            binding_epoch: binding.binding_epoch,
            observed_binding_epoch,
            crash_revision,
            recovery_attempt,
            retained_effects_at_isolation,
            unadopted_effects_at_isolation,
        };

        // These are fixed-size writes into an existing binding record. In
        // particular, do not advance binding/revision counters: this fence must
        // remain available when every counter is already at its maximum.
        binding.supervisor = None;
        binding.fallback_running = false;
        if let Some(recovery) = binding.recovery.as_mut() {
            recovery.ready = None;
        }
        binding.quarantine = Some(receipt);
        DomainIsolationOutcome::Isolated(receipt)
    }

    pub(crate) fn crash_domain(
        &mut self,
        scope_key: ScopeKey,
        domain: DomainKey,
        sender: TaskKey,
    ) -> Result<DomainCrashReceipt, RegistryError> {
        if domain == DomainKey::LEGACY {
            return Err(RegistryError::InvalidState);
        }
        let cohort = self
            .production
            .by_domain
            .get(&(scope_key, domain))
            .cloned()
            .unwrap_or_default();
        let cohort_identity = domain_cohort_identity(Some(&cohort))?;
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        let binding = scope
            .domains
            .get(&domain)
            .ok_or(RegistryError::UnknownDomain)?;
        if binding.quarantine.is_some() {
            return Err(RegistryError::DomainQuarantined);
        }
        if binding.supervisor != Some(sender) || binding.fallback_running {
            return Err(RegistryError::NoSupervisor);
        }
        let previous_binding_epoch = binding.binding_epoch;
        let binding_epoch = previous_binding_epoch
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let root_revision = scope
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let domain_revision = binding
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let infrastructure_fence = if self.infrastructure.is_enabled(scope_key) {
            Some(self.infrastructure.prepare_domain_fence(
                scope_key,
                domain,
                previous_binding_epoch,
                binding_epoch,
            )?)
        } else {
            None
        };

        let scope = self.scopes.get_mut(&scope_key).unwrap();
        scope.revision = root_revision;
        let binding = scope.domains.get_mut(&domain).unwrap();
        binding.binding_epoch = binding_epoch;
        binding.supervisor = None;
        binding.fallback_running = true;
        binding.revision = domain_revision;
        binding.recovery = Some(DomainRecoveryState {
            crash_revision: domain_revision,
            cohort: cohort.clone(),
            unadopted: cohort.clone(),
            snapshot: None,
            ready: None,
            highest_attempt: 0,
            last_abort: None,
            origin: DomainRecoveryOrigin::SupervisorCrash,
        });
        scope.invalidate_recovery_readiness();
        if let Some(fence) = infrastructure_fence {
            self.infrastructure.apply_domain_fence(fence);
        }
        __cser_core::debug_assert!(self.check_infrastructure_root_links().is_ok());
        Ok(DomainCrashReceipt {
            scope: scope_key,
            domain,
            previous_binding_epoch,
            binding_epoch,
            cohort,
            cohort_identity,
        })
    }

    /// Captures or exactly replays one manager-numbered recovery attempt.
    ///
    /// The attempt number is a fence, not an allocator coordinate. A manager
    /// may skip numbers after failing before snapshot construction, but it may
    /// never reuse or move backwards across an aborted attempt.
    pub(crate) fn domain_recovery_snapshot(
        &mut self,
        scope_key: ScopeKey,
        domain: DomainKey,
        replacement: TaskKey,
        attempt: u32,
    ) -> Result<DomainRecoverySnapshot, RegistryError> {
        validate_generation(replacement.generation)?;
        if attempt == 0 {
            return Err(RegistryError::InvalidGeneration);
        }
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        let binding = scope
            .domains
            .get(&domain)
            .ok_or(RegistryError::UnknownDomain)?;
        if binding.quarantine.is_some() {
            return Err(RegistryError::DomainQuarantined);
        }
        if !binding.fallback_running || binding.supervisor.is_some() {
            return Err(RegistryError::InvalidState);
        }
        let recovery = binding
            .recovery
            .as_ref()
            .ok_or(RegistryError::InvalidState)?;
        if let Some(snapshot) = recovery.snapshot.as_ref() {
            if snapshot.attempt != attempt || snapshot.replacement != replacement {
                return Err(RegistryError::ConflictingRecoveryAttempt);
            }
            if snapshot.registry_instance_id != self.instance_id
                || snapshot.digest != domain_recovery_snapshot_digest(snapshot)
            {
                return Err(RegistryError::ConflictingRecoveryAttempt);
            }
            return Ok(snapshot.clone());
        }
        if attempt <= recovery.highest_attempt {
            return Err(RegistryError::StaleRecoveryAttempt);
        }
        let cohort_identity = domain_cohort_identity(Some(&recovery.cohort))?;
        let mut effects = Vec::with_capacity(recovery.cohort.len());
        for effect in &recovery.cohort {
            let record = self
                .effects
                .get(effect)
                .ok_or(RegistryError::UnknownEffect)?;
            effects.push(RecoveryEffectSummary {
                effect: *effect,
                binding_epoch: record.identity.binding_epoch,
                phase: record.phase,
                descriptor_digest: record.descriptor.digest(),
                commit_sequence: record.commit.as_ref().map(CommitReceipt::sequence),
                outcome_required: record.outcome_required,
                outcome: record.outcome,
                terminal_manifest_digest: record
                    .terminal
                    .as_ref()
                    .and_then(TerminalReceipt::manifest_digest),
            });
        }
        let mut snapshot = DomainRecoverySnapshot {
            registry_instance_id: self.instance_id,
            scope: scope_key,
            domain,
            replacement,
            attempt,
            authority_epoch: scope.authority_epoch,
            binding_epoch: binding.binding_epoch,
            crash_revision: recovery.crash_revision,
            root_revision: scope.revision,
            domain_revision: binding.revision,
            cohort_identity,
            effects,
            digest: [0; 32],
        };
        snapshot.digest = domain_recovery_snapshot_digest(&snapshot);
        let recovery = self
            .scopes
            .get_mut(&scope_key)
            .unwrap()
            .domains
            .get_mut(&domain)
            .unwrap()
            .recovery
            .as_mut()
            .unwrap();
        recovery.highest_attempt = attempt;
        recovery.snapshot = Some(snapshot.clone());
        recovery.ready = None;
        Ok(snapshot)
    }

    pub(crate) fn domain_ready(
        &mut self,
        scope_key: ScopeKey,
        domain: DomainKey,
        replacement: TaskKey,
        snapshot: &DomainRecoverySnapshot,
    ) -> Result<(), RegistryError> {
        if snapshot.registry_instance_id != self.instance_id {
            return Err(RegistryError::ForeignRecoverySnapshot);
        }
        if snapshot.scope != scope_key
            || snapshot.domain != domain
            || snapshot.replacement != replacement
            || snapshot.attempt == 0
            || snapshot.digest != domain_recovery_snapshot_digest(snapshot)
        {
            return Err(RegistryError::ConflictingRecoveryAttempt);
        }
        let scope = self
            .scopes
            .get_mut(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        map_handoff_gate(scope.handoff_gate.require_open())?;
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        let binding = scope
            .domains
            .get_mut(&domain)
            .ok_or(RegistryError::UnknownDomain)?;
        if binding.quarantine.is_some() {
            return Err(RegistryError::DomainQuarantined);
        }
        if !binding.fallback_running || binding.supervisor.is_some() {
            return Err(RegistryError::InvalidState);
        }
        let recovery = binding
            .recovery
            .as_mut()
            .ok_or(RegistryError::InvalidState)?;
        if recovery.snapshot.as_ref() != Some(snapshot)
            || snapshot.scope != scope_key
            || snapshot.domain != domain
            || snapshot.replacement != replacement
            || snapshot.root_revision != scope.revision
            || snapshot.domain_revision != binding.revision
            || recovery.crash_revision != snapshot.crash_revision
            || recovery.highest_attempt != snapshot.attempt
        {
            return Err(RegistryError::SnapshotChanged);
        }
        recovery.ready = Some(replacement);
        Ok(())
    }

    /// Clears one exact pre-rebind recovery attempt while retaining the exact
    /// live crash cohort and every still-unadopted member.
    ///
    /// No mutable recovery selector exists outside the snapshot/Ready pair:
    /// `recover_next_domain` derives its peek from `unadopted.first()`. Clearing
    /// these two attempt-local fields therefore also removes all attempt-local
    /// selector authority without advancing the cohort.
    pub(crate) fn abort_domain_recovery_attempt(
        &mut self,
        scope_key: ScopeKey,
        domain: DomainKey,
        replacement: TaskKey,
        attempt: u32,
        snapshot: &DomainRecoverySnapshot,
        reason: DomainRecoveryAbortReason,
    ) -> Result<DomainRecoveryAbortOutcome, RegistryError> {
        if snapshot.registry_instance_id != self.instance_id {
            return Err(RegistryError::ForeignRecoverySnapshot);
        }
        if snapshot.scope != scope_key
            || snapshot.domain != domain
            || snapshot.replacement != replacement
            || snapshot.attempt != attempt
            || attempt == 0
            || snapshot.digest != domain_recovery_snapshot_digest(snapshot)
        {
            return Err(RegistryError::ConflictingRecoveryAttempt);
        }
        let expected = DomainRecoveryAbortReceipt {
            registry_instance_id: self.instance_id,
            scope: scope_key,
            domain,
            replacement,
            binding_epoch: snapshot.binding_epoch,
            crash_revision: snapshot.crash_revision,
            attempt,
            snapshot_digest: snapshot.digest,
            reason,
        };
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        let binding = scope
            .domains
            .get(&domain)
            .ok_or(RegistryError::UnknownDomain)?;
        if binding.quarantine.is_some() {
            return Err(RegistryError::DomainQuarantined);
        }
        let recovery = binding
            .recovery
            .as_ref()
            .ok_or(RegistryError::InvalidState)?;
        match recovery.snapshot.as_ref() {
            Some(active) => {
                if attempt < active.attempt {
                    return Err(RegistryError::StaleRecoveryAttempt);
                }
                if active != snapshot
                    || attempt != recovery.highest_attempt
                    || snapshot.binding_epoch != binding.binding_epoch
                    || snapshot.crash_revision != recovery.crash_revision
                {
                    return Err(RegistryError::ConflictingRecoveryAttempt);
                }
                if !binding.fallback_running || binding.supervisor.is_some() {
                    return Err(RegistryError::InvalidState);
                }
            }
            None => {
                if recovery.last_abort == Some(expected) {
                    return Ok(DomainRecoveryAbortOutcome::AlreadyAborted(expected));
                }
                return if attempt < recovery.highest_attempt {
                    Err(RegistryError::StaleRecoveryAttempt)
                } else {
                    Err(RegistryError::ConflictingRecoveryAttempt)
                };
            }
        }

        let recovery = self
            .scopes
            .get_mut(&scope_key)
            .unwrap()
            .domains
            .get_mut(&domain)
            .unwrap()
            .recovery
            .as_mut()
            .unwrap();
        recovery.snapshot = None;
        recovery.ready = None;
        recovery.last_abort = Some(expected);
        Ok(DomainRecoveryAbortOutcome::Aborted(expected))
    }

    pub(crate) fn rebind_domain(
        &mut self,
        scope_key: ScopeKey,
        domain: DomainKey,
        replacement: TaskKey,
    ) -> Result<DomainRebindReceipt, RegistryError> {
        let scope = self
            .scopes
            .get_mut(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        map_handoff_gate(scope.handoff_gate.require_open())?;
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        let binding = scope
            .domains
            .get_mut(&domain)
            .ok_or(RegistryError::UnknownDomain)?;
        if binding.quarantine.is_some() {
            return Err(RegistryError::DomainQuarantined);
        }
        if !binding.fallback_running
            || binding.supervisor.is_some()
            || binding
                .recovery
                .as_ref()
                .and_then(|recovery| recovery.ready)
                != Some(replacement)
        {
            return Err(RegistryError::RecoveryNotReady);
        }
        binding.supervisor = Some(replacement);
        binding.fallback_running = false;
        binding.recovery.as_mut().unwrap().ready = None;
        Ok(DomainRebindReceipt {
            scope: scope_key,
            domain,
            binding_epoch: binding.binding_epoch,
            supervisor: replacement,
        })
    }

    pub(crate) fn recover_next_domain(
        &self,
        scope_key: ScopeKey,
        domain: DomainKey,
        sender: TaskKey,
    ) -> Result<Option<RecoveryItem>, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        let binding = scope
            .domains
            .get(&domain)
            .ok_or(RegistryError::UnknownDomain)?;
        if binding.quarantine.is_some() {
            return Err(RegistryError::DomainQuarantined);
        }
        if binding.supervisor != Some(sender) {
            return Err(RegistryError::NoSupervisor);
        }
        let recovery = binding
            .recovery
            .as_ref()
            .ok_or(RegistryError::InvalidState)?;
        let Some(effect) = recovery.unadopted.first() else {
            return Ok(None);
        };
        let record = self
            .effects
            .get(effect)
            .ok_or(RegistryError::UnknownEffect)?;
        Ok(Some(RecoveryItem {
            handle: record.handle(),
            descriptor: record.descriptor,
            phase: record.phase,
            commit: record.commit.clone(),
            outcome_required: record.outcome_required,
            outcome: record.outcome,
            terminal_manifest_digest: record
                .terminal
                .as_ref()
                .and_then(TerminalReceipt::manifest_digest),
        }))
    }

    pub(crate) fn adopt_domain(
        &mut self,
        scope_key: ScopeKey,
        domain: DomainKey,
        sender: TaskKey,
        old_handle: PortalHandle,
    ) -> Result<PortalHandle, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        map_handoff_gate(scope.handoff_gate.require_open())?;
        if old_handle.authority_epoch != scope.authority_epoch {
            return Err(RegistryError::StaleAuthority);
        }
        if scope.phase != ScopePhase::Active
            || old_handle.scope != scope_key
            || old_handle.domain != domain
        {
            return Err(RegistryError::InvalidHandle);
        }
        let binding = scope
            .domains
            .get(&domain)
            .ok_or(RegistryError::UnknownDomain)?;
        if binding.quarantine.is_some() {
            return Err(RegistryError::DomainQuarantined);
        }
        if binding.supervisor != Some(sender) || binding.fallback_running {
            return Err(RegistryError::NoSupervisor);
        }
        let effect = old_handle.effect;
        let record = self
            .effects
            .get(&effect)
            .ok_or(RegistryError::UnknownEffect)?;
        if record.identity.scope != scope_key || record.identity.domain != domain {
            return Err(RegistryError::InvalidHandle);
        }
        let recovery = binding
            .recovery
            .as_ref()
            .ok_or(RegistryError::NotAdoptable)?;
        if !recovery.unadopted.contains(&effect)
            || record.phase.is_terminal()
            || old_handle.binding_epoch >= binding.binding_epoch
            || record.identity.binding_epoch != old_handle.binding_epoch
            || record.nonce != old_handle.nonce
        {
            return Err(RegistryError::NotAdoptable);
        }
        let next_root_revision = scope
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let next_domain_revision = binding
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let binding_epoch = binding.binding_epoch;
        let nonce = self.take_nonce()?;
        let record = self.effects.get_mut(&effect).unwrap();
        record.identity.binding_epoch = binding_epoch;
        record.nonce = nonce;
        let new_handle = record.handle();
        let scope = self.scopes.get_mut(&scope_key).unwrap();
        scope.revision = next_root_revision;
        let binding = scope.domains.get_mut(&domain).unwrap();
        binding.revision = next_domain_revision;
        binding.recovery.as_mut().unwrap().unadopted.remove(&effect);
        scope.invalidate_recovery_readiness();
        Ok(new_handle)
    }

    pub(crate) fn domain_recovery_remaining(
        &self,
        scope_key: ScopeKey,
        domain: DomainKey,
    ) -> Result<usize, RegistryError> {
        Ok(self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?
            .domains
            .get(&domain)
            .ok_or(RegistryError::UnknownDomain)?
            .recovery
            .as_ref()
            .map_or(0, |recovery| recovery.unadopted.len()))
    }

    pub(crate) fn stage_terminal(
        &mut self,
        sender: TaskKey,
        handle: PortalHandle,
        request: TerminalRequest,
    ) -> Result<Terminalization, RegistryError> {
        let effect = self.validate_portal(sender, handle)?;
        self.stage_terminal_inner(effect, request, None)
    }

    /// Lets the kernel finish a previously committed effect from its exact
    /// immutable receipt, including while no user-space supervisor is bound.
    pub(crate) fn stage_kernel_completion(
        &mut self,
        receipt: &CommitReceipt,
    ) -> Result<Terminalization, RegistryError> {
        let record = self
            .effects
            .get(&receipt.effect)
            .ok_or(RegistryError::UnknownEffect)?;
        if record.phase != EffectPhase::Committed || record.commit.as_ref() != Some(receipt) {
            return Err(RegistryError::CommitConflict);
        }
        self.stage_terminal_inner(
            receipt.effect,
            TerminalRequest::completed(receipt.result),
            None,
        )
    }

    pub(crate) fn acknowledge_publication(
        &mut self,
        ticket: &PublicationTicket,
    ) -> Result<(), RegistryError> {
        let plan = self.prepare_publication_ack(ticket)?;
        self.apply_publication_ack(plan);
        Ok(())
    }

    /// Acknowledges the final publication and completes its already-drained
    /// revoke cohort as one failure-atomic Registry transition.
    ///
    /// Both revision advances, the projected credit release, pending count,
    /// exact frozen cohort, work counters, and every terminal member are
    /// validated before either half mutates state. The two applies are then
    /// allocation-free and have no error path under exclusive Registry access.
    pub(crate) fn acknowledge_publication_and_revoke_complete(
        &mut self,
        ticket: &PublicationTicket,
        selection: &RevokeSelection,
    ) -> Result<(), RegistryError> {
        self.acknowledge_publication_and_revoke_complete_with_apply(ticket, selection, || ())
    }

    /// Prevalidates the final guest publication and revoke completion before
    /// entering the caller's infallible publication boundary. The Registry
    /// applies both prepared transitions only after that boundary returns, so
    /// every ordinary `Err` proves that no guest publication was attempted.
    pub(crate) fn acknowledge_publication_and_revoke_complete_with_apply<T>(
        &mut self,
        ticket: &PublicationTicket,
        selection: &RevokeSelection,
        apply_publication: impl FnOnce() -> T,
    ) -> Result<T, RegistryError> {
        let publication = self.prepare_publication_ack(ticket)?;
        let revoke = self.prepare_revoke_complete_apply(selection, Some(&publication), None)?;
        let applied = apply_publication();
        self.apply_publication_ack(publication);
        self.apply_revoke_complete(revoke);
        Ok(applied)
    }

    fn prepare_publication_ack(
        &self,
        ticket: &PublicationTicket,
    ) -> Result<PublicationAckApplyPlan, RegistryError> {
        let record = self
            .effects
            .get(&ticket.effect)
            .ok_or(RegistryError::UnknownEffect)?;
        if record.pending_publication.as_ref() != Some(ticket)
            || record.publication_acks != 0
            || record.terminalizations != 1
        {
            return Err(RegistryError::InvalidPublication);
        }
        let scope_key = record.identity.scope;
        let credit_state = record.credit_state;
        let (next_scope_revision, next_pending_publications) = {
            let scope = self
                .scopes
                .get(&scope_key)
                .ok_or(RegistryError::UnknownScope)?;
            let pending = scope
                .pending_publications
                .checked_sub(1)
                .ok_or(RegistryError::InvalidPublication)?;
            let revision = scope
                .revision
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
            scope
                .credits
                .validate_release(&record.credits, credit_state)?;
            (revision, pending)
        };

        Ok(PublicationAckApplyPlan {
            effect: ticket.effect,
            scope: scope_key,
            credit_state,
            next_scope_revision,
            next_pending_publications,
        })
    }

    fn apply_publication_ack(&mut self, plan: PublicationAckApplyPlan) {
        let PublicationAckApplyPlan {
            effect,
            scope,
            credit_state,
            next_scope_revision,
            next_pending_publications,
        } = plan;
        let (scopes, effects) = (&mut self.scopes, &mut self.effects);
        let scope_record = scopes
            .get_mut(&scope)
            .expect("prevalidated publication scope remains present");
        let record = effects
            .get_mut(&effect)
            .expect("prevalidated publication effect remains present");
        scope_record
            .credits
            .release_validated(&record.credits, credit_state);
        record.credit_state = CreditState::Released;
        record.pending_publication = None;
        record.publication_acks = 1;
        scope_record.pending_publications = next_pending_publications;
        __cser_core::assert!(
            scope_record.handoff_candidates.remove(&effect),
            "acknowledged publication must leave the handoff index"
        );
        scope_record.revision = next_scope_revision;
        scope_record.invalidate_recovery_readiness();
    }

    pub(crate) fn freeze_admission(
        &mut self,
        scope_key: ScopeKey,
        intent: PrepareIntent,
    ) -> Result<ProductionHandoffFreezeReceipt, RegistryError> {
        if let Some(existing) = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?
            .handoff
            .as_ref()
        {
            if existing.decision.map(OwnershipDecisionReceipt::decision)
                == Some(OwnershipDecision::Abort)
            {
                if existing.freeze.intent() == intent {
                    return Err(RegistryError::InvalidHandoffReceipt);
                }
            } else {
                if existing.freeze.intent() != intent {
                    return Err(RegistryError::InvalidHandoffReceipt);
                }
                let readiness = handoff_readiness(&existing.cohort, &self.effects)?;
                return Ok(ProductionHandoffFreezeReceipt {
                    freeze: existing.freeze,
                    readiness,
                    cohort_size: existing.cohort.len(),
                    committed_at_freeze: existing.committed_at_freeze.len(),
                });
            }
        }

        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        if scope
            .device_root
            .as_ref()
            .is_some_and(|root| root.batch_sequence.is_none())
        {
            return Err(RegistryError::HandoffDevicePrecommitPending);
        }
        map_handoff_gate(scope.handoff_gate.require_open())?;
        let cohort = scope.handoff_candidates.clone();
        let (cohort_digest, classification_digest) =
            handoff_cohort_digests(&cohort, &self.effects)?;
        let committed_at_freeze = cohort
            .iter()
            .filter(|effect| self.effects[effect].commit.is_some())
            .copied()
            .collect::<BTreeSet<_>>();
        let readiness = handoff_readiness(&cohort, &self.effects)?;
        let context = KernelFreezeContext {
            registry_instance: self.instance_id,
            // The current profile is explicitly same-boot. A reboot-capable
            // successor must provision this value from a persistent boot ID.
            boot_incarnation: 1,
            scope_id: scope_key.id,
            scope_generation: scope_key.generation,
            authority_epoch: scope.authority_epoch,
            binding_epoch: scope.binding_epoch,
            scope_revision: scope.revision,
            cohort_digest,
            classification_digest,
        };
        let mut gate = scope.handoff_gate;
        let freeze = gate.freeze(intent, context).map_err(|error| match error {
            HandoffGateError::CounterOverflow => RegistryError::CounterOverflow,
            HandoffGateError::AdmissionFrozen => RegistryError::HandoffAdmissionFrozen,
            _ => RegistryError::InvalidHandoffReceipt,
        })?;
        let scope = self.scopes.get_mut(&scope_key).unwrap();
        scope.handoff_gate = gate;
        scope.handoff = Some(ProductionHandoffState {
            freeze,
            cohort: cohort.clone(),
            committed_at_freeze: committed_at_freeze.clone(),
            thaw: None,
            decision: None,
            revoke: None,
            closure: None,
        });
        Ok(ProductionHandoffFreezeReceipt {
            freeze,
            readiness,
            cohort_size: cohort.len(),
            committed_at_freeze: committed_at_freeze.len(),
        })
    }

    pub(crate) fn abort_handoff_uncommitted(
        &mut self,
        scope_key: ScopeKey,
        presented: ProductionHandoffFreezeReceipt,
    ) -> Result<HandoffAbortProgress, RegistryError> {
        self.validate_handoff_freeze(scope_key, presented)?;
        let cohort = self.scopes[&scope_key]
            .handoff
            .as_ref()
            .unwrap()
            .cohort
            .clone();
        let mut publications = Vec::new();
        let mut aborted = 0_usize;
        loop {
            let next = cohort.iter().copied().find(|effect| {
                self.effects.get(effect).is_some_and(|record| {
                    __cser_core::matches!(
                        record.phase,
                        EffectPhase::Registered | EffectPhase::Prepared
                    ) && self
                        .production
                        .children_by_parent
                        .get(effect)
                        .is_none_or(BTreeSet::is_empty)
                })
            });
            let Some(effect) = next else {
                break;
            };
            let next_aborted = aborted
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
            let terminal =
                match self.stage_terminal_inner(effect, TerminalRequest::aborted(-125), None) {
                    Ok(terminal) => terminal,
                    Err(error) if aborted == 0 => return Err(error),
                    Err(_) => break,
                };
            if let Some(ticket) = terminal.publication {
                publications.push(ticket);
            }
            aborted = next_aborted;
        }
        let state = self.scopes[&scope_key].handoff.as_ref().unwrap();
        Ok(HandoffAbortProgress {
            aborted,
            publications,
            readiness: handoff_readiness(&state.cohort, &self.effects)?,
        })
    }

    pub(crate) fn unfreeze_handoff(
        &mut self,
        scope_key: ScopeKey,
        decision: OwnershipDecisionReceipt,
    ) -> Result<HandoffThawReceipt, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        let state = scope
            .handoff
            .as_ref()
            .ok_or(RegistryError::InvalidHandoffReceipt)?;
        if let Some(thaw) = state.thaw {
            return if thaw.decision == decision {
                Ok(thaw)
            } else {
                Err(RegistryError::InvalidHandoffReceipt)
            };
        }
        let mut gate = scope.handoff_gate;
        if map_handoff_decision(gate.accept_decision(decision))? != OwnershipDecision::Abort {
            return Err(RegistryError::InvalidHandoffReceipt);
        }
        let source_recovery_required = scope.supervisor.is_none()
            || scope.fallback_running
            || scope
                .domains
                .values()
                .any(|binding| binding.supervisor.is_none() || binding.fallback_running);
        let thaw = HandoffThawReceipt {
            freeze: state.freeze,
            decision,
            source_recovery_required,
        };
        let scope = self.scopes.get_mut(&scope_key).unwrap();
        scope.handoff_gate = gate;
        let state = scope.handoff.as_mut().unwrap();
        state.decision = Some(decision);
        state.thaw = Some(thaw);
        Ok(thaw)
    }

    pub(crate) fn commit_handoff_close(
        &mut self,
        scope_key: ScopeKey,
        decision: OwnershipDecisionReceipt,
    ) -> Result<ProductionHandoffProgress, RegistryError> {
        {
            let scope = self
                .scopes
                .get(&scope_key)
                .ok_or(RegistryError::UnknownScope)?;
            let state = scope
                .handoff
                .as_ref()
                .ok_or(RegistryError::InvalidHandoffReceipt)?;
            if let Some(existing) = state.decision {
                if existing != decision {
                    return Err(RegistryError::InvalidHandoffReceipt);
                }
                return self.query_handoff(scope_key, state.freeze);
            }
            if handoff_readiness(&state.cohort, &self.effects)?
                != HandoffFreezeReadiness::ReadyToCommit
            {
                return Err(RegistryError::HandoffNotReady);
            }
        }

        let mut gate = self.scopes[&scope_key].handoff_gate;
        if map_handoff_decision(gate.accept_decision(decision))? != OwnershipDecision::Commit {
            return Err(RegistryError::InvalidHandoffReceipt);
        }
        let plan = self.prepare_revoke_begin(scope_key)?;
        if plan.selection.target_count == 0 {
            plan.next_scope_revision
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
        }
        {
            let scope = self.scopes.get_mut(&scope_key).unwrap();
            scope.handoff_gate = gate;
            scope.handoff.as_mut().unwrap().decision = Some(decision);
        }
        let selection = self.apply_revoke_begin(plan);
        self.scopes
            .get_mut(&scope_key)
            .unwrap()
            .handoff
            .as_mut()
            .unwrap()
            .revoke = Some(selection.clone());
        if selection.target_count == 0 {
            self.revoke_complete(&selection)?;
        }
        let freeze = self.scopes[&scope_key].handoff.as_ref().unwrap().freeze;
        self.query_handoff(scope_key, freeze)
    }

    pub(crate) fn query_handoff(
        &mut self,
        scope_key: ScopeKey,
        freeze: KernelFreezeReceipt,
    ) -> Result<ProductionHandoffProgress, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        let state = scope
            .handoff
            .as_ref()
            .ok_or(RegistryError::InvalidHandoffReceipt)?;
        if state.freeze != freeze {
            return Err(RegistryError::InvalidHandoffReceipt);
        }
        if let Some(closure) = state.closure.clone() {
            self.verify_handoff_closure(scope_key, &closure)?;
            return Ok(ProductionHandoffProgress::Closed(closure));
        }
        if let Some(thaw) = state.thaw {
            return Ok(ProductionHandoffProgress::Aborted(thaw));
        }
        let Some(decision) = state.decision else {
            return Ok(ProductionHandoffProgress::Frozen(handoff_readiness(
                &state.cohort,
                &self.effects,
            )?));
        };
        let selection = state
            .revoke
            .clone()
            .ok_or(RegistryError::InvalidHandoffReceipt)?;
        if scope.phase != ScopePhase::Revoked {
            let retained = match self.query_scope_closure(scope_key)? {
                ScopeClosureProgress::Closing(observed) if observed == selection => false,
                ScopeClosureProgress::Retained(observed) if observed == selection => true,
                _ => {
                    return Err(RegistryError::Invariant(
                        "handoff and full-scope closure progress differ",
                    ));
                }
            };
            return Ok(if retained {
                ProductionHandoffProgress::Retained(selection)
            } else {
                ProductionHandoffProgress::Closing(selection)
            });
        }
        if !scope.handoff_candidates.is_empty()
            || scope.pending_publications != 0
            || !scope.credits.is_idle()
        {
            return Err(RegistryError::NotQuiescent);
        }
        let scope_closure = scope
            .revoke
            .as_ref()
            .and_then(|revoke| revoke.closure.clone())
            .ok_or(RegistryError::InvalidHandoffReceipt)?;
        self.verify_scope_closure(scope_key, &scope_closure)?;
        let closure = ProductionHandoffClosureReceipt {
            freeze,
            decision,
            revoke: selection,
            scope_closure,
            terminal_manifest_digest: handoff_terminal_manifest_digest(
                &state.cohort,
                &self.effects,
            )?,
            closed_scope_revision: scope.revision,
        };
        self.scopes
            .get_mut(&scope_key)
            .unwrap()
            .handoff
            .as_mut()
            .unwrap()
            .closure = Some(closure.clone());
        Ok(ProductionHandoffProgress::Closed(closure))
    }

    pub(crate) fn verify_handoff_closure(
        &self,
        scope_key: ScopeKey,
        receipt: &ProductionHandoffClosureReceipt,
    ) -> Result<(), RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        let state = scope
            .handoff
            .as_ref()
            .ok_or(RegistryError::InvalidHandoffReceipt)?;
        if state.closure.as_ref() != Some(receipt)
            || state.freeze != receipt.freeze
            || state.decision != Some(receipt.decision)
            || state.revoke.as_ref() != Some(&receipt.revoke)
            || receipt.revoke != *receipt.scope_closure.revoke()
            || receipt.closed_scope_revision != scope.revision
            || receipt.scope_closure.closed_scope_revision() != scope.revision
            || handoff_terminal_manifest_digest(&state.cohort, &self.effects)?
                != receipt.terminal_manifest_digest
        {
            return Err(RegistryError::InvalidHandoffReceipt);
        }
        self.verify_scope_closure(scope_key, &receipt.scope_closure)?;
        Ok(())
    }

    fn validate_handoff_freeze(
        &self,
        scope_key: ScopeKey,
        presented: ProductionHandoffFreezeReceipt,
    ) -> Result<(), RegistryError> {
        let state = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?
            .handoff
            .as_ref()
            .ok_or(RegistryError::InvalidHandoffReceipt)?;
        if state.freeze != presented.freeze
            || state.cohort.len() != presented.cohort_size
            || state.committed_at_freeze.len() != presented.committed_at_freeze
            || state.decision.is_some()
        {
            return Err(RegistryError::InvalidHandoffReceipt);
        }
        Ok(())
    }

    pub(crate) fn revoke_begin(
        &mut self,
        scope_key: ScopeKey,
    ) -> Result<RevokeSelection, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        map_handoff_gate(scope.handoff_gate.require_open())?;
        let plan = self.prepare_revoke_begin(scope_key)?;
        Ok(self.apply_revoke_begin(plan))
    }

    /// Failure-atomically closes one non-device, non-publishing scope whose
    /// committed effects all have determinate recorded outcomes.
    ///
    /// This is the bounded portal-v2 closure primitive.  It deliberately
    /// rejects an indeterminate or missing committed outcome before freezing
    /// authority: such work must remain queryable for a future reconcile path,
    /// never be reported as closed.  The private candidate Registry is not an
    /// authority clone exposed to callers; it is installed only after every
    /// revoke transition and the final quiescence check succeed.
    pub(crate) fn revoke_nonpublishing_with_recorded_outcomes(
        &mut self,
        scope_key: ScopeKey,
    ) -> Result<RevokeSelection, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        map_handoff_gate(scope.handoff_gate.require_open())?;
        if scope.phase != ScopePhase::Active || scope.device_root.is_some() {
            return Err(RegistryError::InvalidState);
        }
        for effect in &scope.closure_candidates {
            let record = self
                .effects
                .get(effect)
                .ok_or(RegistryError::UnknownEffect)?;
            if record.publication_mode != PublicationMode::None {
                return Err(RegistryError::PublicationPending);
            }
            if record.commit.is_some()
                && !record
                    .outcome
                    .is_some_and(|outcome| outcome.class() != EffectOutcomeClass::Indeterminate)
            {
                return Err(RegistryError::NotQuiescent);
            }
        }

        let mut candidate = self.scope_transaction_candidate(scope_key)?;
        let selection = candidate.revoke_begin(scope_key)?;
        while let Some(next) = candidate.revoke_next(&selection)? {
            let terminal = match next.disposition {
                RevokeDisposition::Abort => TerminalRequest::aborted(-125),
                RevokeDisposition::Drain(_) => {
                    let outcome = candidate
                        .effects
                        .get(&next.effect)
                        .and_then(|record| record.outcome)
                        .ok_or(RegistryError::NotQuiescent)?;
                    TerminalRequest::completed(outcome.result())
                        .with_manifest_digest(outcome.digest())?
                }
            };
            let terminalization =
                candidate.stage_revoke_terminal(&selection, next.effect, terminal)?;
            if terminalization.publication.is_some() {
                return Err(RegistryError::InvalidPublication);
            }
        }
        candidate.revoke_complete(&selection)?;
        self.install_revoked_scope_candidate(scope_key, candidate)?;
        Ok(selection)
    }

    fn prepare_revoke_begin(&self, scope_key: ScopeKey) -> Result<RevokeBeginPlan, RegistryError> {
        let revision = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?
            .revision;
        self.prepare_revoke_begin_from_revision(scope_key, revision)
    }

    /// Prevalidates a revoke that will be applied immediately after one
    /// already-prepared device-batch commit. The live revision is unchanged
    /// during preparation, so the supplied batch revision must be its exact
    /// successor; this checks the commit and revoke revision advances before
    /// hardware publication.
    fn prepare_revoke_begin_after_device_batch(
        &self,
        scope_key: ScopeKey,
        batch_revision: u64,
    ) -> Result<RevokeBeginPlan, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        let expected_batch_revision = scope
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        if batch_revision != expected_batch_revision {
            return Err(RegistryError::InvalidState);
        }
        self.prepare_revoke_begin_from_revision(scope_key, batch_revision)
    }

    /// Like [`Self::prepare_revoke_begin_after_device_batch`], but accounts
    /// for the separately persisted `Publishing` provenance.  A fresh close
    /// advances the revision once when it records the operation before the
    /// external publication boundary and once when it commits the batch.
    /// Keeping this check distinct prevents ordinary batch paths from silently
    /// accepting an extra projected mutation.
    fn prepare_revoke_begin_after_publishing_and_batch(
        &self,
        scope_key: ScopeKey,
        batch_revision: u64,
    ) -> Result<RevokeBeginPlan, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        let expected_batch_revision = scope
            .revision
            .checked_add(2)
            .ok_or(RegistryError::CounterOverflow)?;
        if batch_revision != expected_batch_revision {
            return Err(RegistryError::InvalidState);
        }
        self.prepare_revoke_begin_from_revision(scope_key, batch_revision)
    }

    fn prepare_revoke_begin_from_revision(
        &self,
        scope_key: ScopeKey,
        revision_before_revoke: u64,
    ) -> Result<RevokeBeginPlan, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        if scope.revoke.is_some() {
            return Err(RegistryError::InvalidState);
        }
        if scope.device_root.as_ref().is_some_and(|root| {
            __cser_core::matches!(
                root.publication,
                DevicePublicationProvenance::Publishing { .. }
            )
        }) {
            return Err(RegistryError::DeviceClosurePending);
        }
        let authority_epoch = scope
            .authority_epoch
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let next_scope_revision = revision_before_revoke
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let target_count = scope.closure_candidates.len();
        u64::try_from(target_count).map_err(|_| RegistryError::CounterOverflow)?;
        let sequence = self.next_revoke_sequence;
        let next_revoke_sequence = sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let infrastructure = self
            .infrastructure
            .is_enabled(scope_key)
            .then(|| {
                self.infrastructure
                    .prepare_closure_start(scope_key, scope.authority_epoch)
            })
            .transpose()?;
        Ok(RevokeBeginPlan {
            selection: RevokeSelection {
                scope: scope_key,
                sequence,
                closed_authority_epoch: scope.authority_epoch,
                authority_epoch,
                target_count,
            },
            next_revoke_sequence,
            next_scope_revision,
            infrastructure,
        })
    }

    fn apply_revoke_begin(&mut self, plan: RevokeBeginPlan) -> RevokeSelection {
        let RevokeBeginPlan {
            selection,
            next_revoke_sequence,
            next_scope_revision,
            infrastructure,
        } = plan;

        // All validation and overflow checks precede this point. Moving the
        // two indexes is allocation-free and does not visit any target record.
        let infrastructure =
            infrastructure.map(|plan| self.infrastructure.apply_closure_start(plan));
        self.next_revoke_sequence = next_revoke_sequence;
        let scope = self
            .scopes
            .get_mut(&selection.scope)
            .expect("validated revoke scope must remain present");
        let cohort = __cser_core::mem::take(&mut scope.closure_candidates);
        let retired_recovery = scope.recovery.take();
        __cser_core::debug_assert_eq!(cohort.len(), selection.target_count);
        scope.authority_epoch = selection.authority_epoch;
        scope.phase = ScopePhase::Closing;
        scope.supervisor = None;
        scope.fallback_running = false;
        for binding in scope.domains.values_mut() {
            binding.supervisor = None;
            binding.fallback_running = false;
            binding.recovery = None;
        }
        scope.revision = next_scope_revision;
        scope.revoke = Some(RevokeState {
            sequence: selection.sequence,
            cohort,
            closed_authority_epoch: selection.closed_authority_epoch,
            authority_epoch: selection.authority_epoch,
            target_count: selection.target_count,
            selected_head: None,
            retired_recovery,
            work: RevokeWorkCounters::default(),
            infrastructure,
            closure: None,
        });
        selection
    }

    pub(crate) fn revoke_targets(
        &self,
        selection: &RevokeSelection,
    ) -> Result<&BTreeSet<EffectKey>, RegistryError> {
        self.validate_revoke_selection(selection)?;
        Ok(&self.scopes[&selection.scope]
            .revoke
            .as_ref()
            .unwrap()
            .cohort)
    }

    pub(crate) fn revoke_next(
        &mut self,
        selection: &RevokeSelection,
    ) -> Result<Option<RevokeEffect>, RegistryError> {
        self.validate_revoke_selection(selection)?;
        let (selected, next_calls, head_selections) = {
            let revoke = self.scopes[&selection.scope].revoke.as_ref().unwrap();
            let selected = revoke.selected_head.or_else(|| {
                self.production
                    .leaves_by_scope
                    .get(&selection.scope)
                    .and_then(BTreeSet::first)
                    .copied()
            });
            let next_calls = revoke
                .work
                .next_calls
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
            let head_selections = if selected.is_some() && revoke.selected_head.is_none() {
                revoke
                    .work
                    .head_selections
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?
            } else {
                revoke.work.head_selections
            };
            (selected, next_calls, head_selections)
        };
        let next = if let Some(effect) = selected {
            let (scopes, effects) = (&mut self.scopes, &self.effects);
            let revoke = scopes
                .get_mut(&selection.scope)
                .unwrap()
                .revoke
                .as_mut()
                .unwrap();
            let record = instrument_revoke_record_access(
                &mut revoke.work,
                &revoke.cohort,
                effects,
                selection.scope,
                effect,
                RevokeRecordAccess::Transition,
            )?;
            if record.identity.scope != selection.scope || record.phase.is_terminal() {
                return Err(RegistryError::Invariant("invalid revoke target head"));
            }
            Some(RevokeEffect {
                effect,
                disposition: record
                    .commit
                    .clone()
                    .map_or(RevokeDisposition::Abort, RevokeDisposition::Drain),
                publication_required: record.publication_mode == PublicationMode::Required,
            })
        } else {
            None
        };
        let revoke = self
            .scopes
            .get_mut(&selection.scope)
            .unwrap()
            .revoke
            .as_mut()
            .unwrap();
        revoke.work.next_calls = next_calls;
        revoke.work.head_selections = head_selections;
        if revoke.selected_head.is_none() {
            revoke.selected_head = selected;
        }
        Ok(next)
    }

    pub(crate) fn stage_revoke_terminal(
        &mut self,
        selection: &RevokeSelection,
        effect: EffectKey,
        request: TerminalRequest,
    ) -> Result<Terminalization, RegistryError> {
        self.validate_revoke_selection(selection)?;
        if !self.scopes[&selection.scope]
            .revoke
            .as_ref()
            .unwrap()
            .cohort
            .contains(&effect)
        {
            return Err(RegistryError::InvalidRevokeSelection);
        }
        self.stage_terminal_inner(effect, request, None)
    }

    pub(crate) fn revoke_complete(
        &mut self,
        selection: &RevokeSelection,
    ) -> Result<(), RegistryError> {
        let plan = self.prepare_revoke_complete_apply(selection, None, None)?;
        self.apply_revoke_complete(plan);
        Ok(())
    }

    /// Returns the durable full-scope lifecycle without minting authority.
    ///
    /// A caller which loses the response after `revoke_complete` receives the
    /// exact stored `Closed` receipt here. `Retained` is conservative: either
    /// the business credit ledger or the infrastructure child still names a
    /// retained owner.
    pub(crate) fn query_scope_closure(
        &self,
        scope_key: ScopeKey,
    ) -> Result<ScopeClosureProgress, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        match scope.phase {
            ScopePhase::Active => {
                if scope.revoke.is_some()
                    || (self.infrastructure.is_enabled(scope_key)
                        && self.infrastructure.closure_progress(scope_key)?
                            != infrastructure::InfrastructureClosureProgress::Active)
                {
                    return Err(RegistryError::Invariant(
                        "active scope has closure progress",
                    ));
                }
                Ok(ScopeClosureProgress::Active)
            }
            ScopePhase::Closing => {
                let revoke = scope
                    .revoke
                    .as_ref()
                    .ok_or(RegistryError::Invariant("closing scope lacks revoke"))?;
                let selection = RevokeSelection {
                    scope: scope_key,
                    sequence: revoke.sequence,
                    closed_authority_epoch: revoke.closed_authority_epoch,
                    authority_epoch: revoke.authority_epoch,
                    target_count: revoke.target_count,
                };
                let infrastructure_retained = match (
                    revoke.infrastructure,
                    self.infrastructure.is_enabled(scope_key),
                ) {
                    (Some(expected), true) => {
                        match self.infrastructure.closure_progress(scope_key)? {
                            infrastructure::InfrastructureClosureProgress::Closing(observed) => {
                                if observed != expected {
                                    return Err(RegistryError::Invariant(
                                        "infrastructure closure selection drifted",
                                    ));
                                }
                                false
                            }
                            infrastructure::InfrastructureClosureProgress::Retained(observed) => {
                                if observed != expected {
                                    return Err(RegistryError::Invariant(
                                        "infrastructure closure selection drifted",
                                    ));
                                }
                                true
                            }
                            infrastructure::InfrastructureClosureProgress::Active
                            | infrastructure::InfrastructureClosureProgress::Closed(_) => {
                                return Err(RegistryError::Invariant(
                                    "business and infrastructure closure phases differ",
                                ));
                            }
                        }
                    }
                    (None, false) => false,
                    _ => {
                        return Err(RegistryError::Invariant(
                            "business and infrastructure closure ownership differ",
                        ));
                    }
                };
                let business_retained = scope
                    .credits
                    .balances
                    .values()
                    .any(|balance| balance.retained != 0);
                Ok(if infrastructure_retained || business_retained {
                    ScopeClosureProgress::Retained(selection)
                } else {
                    ScopeClosureProgress::Closing(selection)
                })
            }
            ScopePhase::Revoked => {
                let receipt = scope
                    .revoke
                    .as_ref()
                    .and_then(|revoke| revoke.closure.clone())
                    .ok_or(RegistryError::Invariant(
                        "revoked scope lacks closure receipt",
                    ))?;
                self.verify_scope_closure(scope_key, &receipt)?;
                Ok(ScopeClosureProgress::Closed(receipt))
            }
        }
    }

    pub(crate) fn verify_scope_closure(
        &self,
        scope_key: ScopeKey,
        receipt: &ScopeClosureReceipt,
    ) -> Result<(), RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        let revoke = scope
            .revoke
            .as_ref()
            .ok_or(RegistryError::InvalidRevokeSelection)?;
        if scope.phase != ScopePhase::Revoked
            || self.instance_id != receipt.registry_instance_id
            || receipt.revoke.scope != scope_key
            || receipt.closed_scope_revision != scope.revision
            || revoke.closure.as_ref() != Some(receipt)
            || revoke.sequence != receipt.revoke.sequence
            || revoke.closed_authority_epoch != receipt.revoke.closed_authority_epoch
            || revoke.authority_epoch != receipt.revoke.authority_epoch
            || revoke.target_count != receipt.revoke.target_count
        {
            return Err(RegistryError::InvalidRevokeSelection);
        }
        match (revoke.infrastructure, receipt.infrastructure) {
            (Some(selection), Some(infrastructure)) if selection.binds_receipt(infrastructure) => {
                self.infrastructure.verify_closure_receipt(infrastructure)?;
            }
            (None, None) if !self.infrastructure.is_enabled(scope_key) => {}
            _ => {
                return Err(RegistryError::InvalidRevokeSelection);
            }
        }
        Ok(())
    }

    fn prepare_revoke_complete_apply(
        &self,
        selection: &RevokeSelection,
        publication: Option<&PublicationAckApplyPlan>,
        projected_workload_close: Option<&infrastructure::WorkloadCloseIntent>,
    ) -> Result<RevokeCompleteApplyPlan, RegistryError> {
        self.validate_revoke_selection(selection)?;
        if self
            .by_scope
            .get(&selection.scope)
            .is_some_and(|effects| !effects.is_empty())
        {
            return Err(RegistryError::NotQuiescent);
        }
        let scope = &self.scopes[&selection.scope];
        let revoke = scope.revoke.as_ref().unwrap();
        let target_count =
            u64::try_from(revoke.target_count).map_err(|_| RegistryError::CounterOverflow)?;
        if revoke.cohort.len() != revoke.target_count {
            return Err(RegistryError::InvalidRevokeSelection);
        }

        let (projected_pending, next_scope_revision) = if let Some(publication) = publication {
            if publication.scope != selection.scope || !revoke.cohort.contains(&publication.effect)
            {
                return Err(RegistryError::InvalidRevokeSelection);
            }
            let expected_ack_revision = scope
                .revision
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
            if publication.next_scope_revision != expected_ack_revision
                || publication.next_pending_publications
                    != scope
                        .pending_publications
                        .checked_sub(1)
                        .ok_or(RegistryError::InvalidPublication)?
            {
                return Err(RegistryError::InvalidPublication);
            }
            let next_revision = publication
                .next_scope_revision
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
            (publication.next_pending_publications, next_revision)
        } else {
            let next_revision = scope
                .revision
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
            (scope.pending_publications, next_revision)
        };
        if revoke.selected_head.is_some()
            || projected_pending != 0
            || revoke.work.terminalized != target_count
            || revoke.work.target_index_removals != target_count
            || revoke.work.completion_members_checked != 0
        {
            return Err(RegistryError::NotQuiescent);
        }

        let mut projected_work = revoke.work;
        let mut credits_idle = publication.is_none() && scope.credits.is_idle();
        let mut members_checked = 0_u64;
        for effect in &revoke.cohort {
            let record = instrument_revoke_record_access(
                &mut projected_work,
                &revoke.cohort,
                &self.effects,
                selection.scope,
                *effect,
                RevokeRecordAccess::Transition,
            )?;
            let projected_ack = publication.is_some_and(|plan| plan.effect == *effect);
            if !record.phase.is_terminal()
                || (!projected_ack && record.pending_publication.is_some())
                || (!projected_ack && record.credit_state != CreditState::Released)
            {
                return Err(RegistryError::NotQuiescent);
            }
            if projected_ack
                && publication.is_none_or(|plan| {
                    record.pending_publication.is_none() || record.credit_state != plan.credit_state
                })
            {
                return Err(RegistryError::InvalidPublication);
            }
            if let Some(plan) = publication.filter(|plan| plan.effect == *effect) {
                credits_idle = scope
                    .credits
                    .is_idle_after_validated_release(&record.credits, plan.credit_state);
            }
            if record.identity.scope != selection.scope {
                return Err(RegistryError::InvalidRevokeSelection);
            }
            members_checked = members_checked
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
        }
        if members_checked != target_count {
            return Err(RegistryError::InvalidRevokeSelection);
        }
        if !credits_idle {
            return Err(RegistryError::NotQuiescent);
        }
        projected_work.completion_members_checked = members_checked;

        let (infrastructure, infrastructure_receipt) = match revoke.infrastructure {
            Some(infrastructure_selection) => {
                if !self.infrastructure.is_enabled(selection.scope) {
                    return Err(RegistryError::Invariant(
                        "revoke retains missing infrastructure closure",
                    ));
                }
                let (plan, receipt) = match projected_workload_close {
                    Some(close) => self
                        .infrastructure
                        .prepare_closure_finish_after_workload_close(
                            infrastructure_selection,
                            close,
                        )?,
                    None => self
                        .infrastructure
                        .prepare_closure_finish(infrastructure_selection)?,
                };
                (Some(plan), Some(receipt))
            }
            None => {
                if projected_workload_close.is_some() {
                    return Err(RegistryError::Invariant(
                        "projected workload close lacks infrastructure closure",
                    ));
                }
                if self.infrastructure.is_enabled(selection.scope) {
                    return Err(RegistryError::Invariant(
                        "revoke lacks infrastructure closure",
                    ));
                }
                (None, None)
            }
        };
        let receipt = ScopeClosureReceipt {
            registry_instance_id: self.instance_id,
            revoke: selection.clone(),
            infrastructure: infrastructure_receipt,
            closed_scope_revision: next_scope_revision,
        };
        Ok(RevokeCompleteApplyPlan {
            scope: selection.scope,
            next_scope_revision,
            work: projected_work,
            infrastructure,
            receipt,
        })
    }

    fn apply_revoke_complete(&mut self, plan: RevokeCompleteApplyPlan) {
        let RevokeCompleteApplyPlan {
            scope,
            next_scope_revision,
            work,
            infrastructure,
            receipt,
        } = plan;
        let installed_infrastructure =
            infrastructure.map(|plan| self.infrastructure.apply_closure_finish(plan));
        __cser_core::debug_assert_eq!(installed_infrastructure, receipt.infrastructure);
        let scope = self
            .scopes
            .get_mut(&scope)
            .expect("prevalidated revoke scope remains present");
        let revoke = scope
            .revoke
            .as_mut()
            .expect("prevalidated revoke state remains present");
        revoke.work = work;
        revoke.cohort.clear();
        revoke.retired_recovery = None;
        revoke.closure = Some(receipt);
        scope.phase = ScopePhase::Revoked;
        scope.revision = next_scope_revision;
    }

    pub(crate) fn revoke_work_projection(
        &self,
        selection: &RevokeSelection,
    ) -> Result<RevokeWorkProjection, RegistryError> {
        let scope = self
            .scopes
            .get(&selection.scope)
            .ok_or(RegistryError::UnknownScope)?;
        let revoke = scope
            .revoke
            .as_ref()
            .ok_or(RegistryError::InvalidRevokeSelection)?;
        if revoke.sequence != selection.sequence
            || revoke.closed_authority_epoch != selection.closed_authority_epoch
            || revoke.authority_epoch != selection.authority_epoch
            || revoke.target_count != selection.target_count
        {
            return Err(RegistryError::InvalidRevokeSelection);
        }
        Ok(RevokeWorkProjection {
            target_count: revoke.target_count,
            begin_target_record_visits: revoke.work.begin_target_record_visits,
            next_calls: revoke.work.next_calls,
            head_selections: revoke.work.head_selections,
            terminalized: revoke.work.terminalized,
            completion_members_checked: revoke.work.completion_members_checked,
            target_index_removals: revoke.work.target_index_removals,
            unrelated_effect_visits: revoke.work.unrelated_effect_visits,
            history_effect_visits: revoke.work.history_effect_visits,
            pending_targets: self.by_scope.get(&selection.scope).map_or(0, BTreeSet::len),
            target_state: scope.phase,
        })
    }

    pub(crate) fn scope_projection(
        &self,
        scope_key: ScopeKey,
    ) -> Result<RegistryProjection, RegistryError> {
        let scope = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        let live_effects = self.by_scope.get(&scope_key).map_or(0, BTreeSet::len);
        Ok(RegistryProjection {
            phase: scope.phase,
            authority_epoch: scope.authority_epoch,
            binding_epoch: scope.binding_epoch,
            supervisor: scope.supervisor,
            fallback_running: scope.fallback_running,
            revision: scope.revision,
            domain_revision: scope.domain_revision,
            live_effects,
            pending_publications: scope.pending_publications,
            credits: scope.credits.totals(),
        })
    }

    pub(crate) fn effects_for_scope(&self, scope: ScopeKey) -> BTreeSet<EffectKey> {
        self.by_scope.get(&scope).cloned().unwrap_or_default()
    }

    pub(crate) fn effects_for_task(&self, task: TaskKey) -> BTreeSet<EffectKey> {
        self.by_task.get(&task).cloned().unwrap_or_default()
    }

    pub(crate) fn effects_for_resource(&self, resource: ResourceKey) -> BTreeSet<EffectKey> {
        self.by_resource.get(&resource).cloned().unwrap_or_default()
    }

    // Keep this cross-ledger oracle out of the already-large invariant frame.
    // Loom's modeled coroutine stack is intentionally small.
    #[inline(never)]
    fn check_domain_recovery_origin(
        &self,
        scope: ScopeKey,
        domain: DomainKey,
        binding: &DomainBindingRecord,
        recovery: &DomainRecoveryState,
    ) -> Result<(), RegistryError> {
        let projection = self
            .infrastructure
            .domain_fault_recovery_projection(scope, domain, binding.binding_epoch)
            .map_err(|_| RegistryError::Invariant("domain recovery origin mismatch"))?;
        let anchor = match (recovery.origin, projection) {
            (DomainRecoveryOrigin::SupervisorCrash, None) => return Ok(()),
            (DomainRecoveryOrigin::ServiceFault(anchor), Some(projection)) => (anchor, projection),
            (DomainRecoveryOrigin::SupervisorCrash, Some(_))
            | (DomainRecoveryOrigin::ServiceFault(_), None) => {
                return Err(RegistryError::Invariant("domain recovery origin mismatch"));
            }
        };
        let (anchor, projection) = anchor;
        if projection.fault_id != anchor.fault_id
            || projection.generation != anchor.generation
            || projection.task != anchor.task
            || projection.vm_generation != anchor.vm_generation
            || projection.service_domain != domain
            || projection
                .closed_binding_epoch
                .checked_add(1)
                .is_none_or(|epoch| epoch != binding.binding_epoch)
            || projection.crash_generation != recovery.crash_revision
            || projection.evidence_digest != anchor.evidence_digest
            || projection.plan_commitment != anchor.plan_commitment
        {
            return Err(RegistryError::Invariant(
                "domain fault recovery anchor mismatch",
            ));
        }
        Ok(())
    }

    pub(crate) fn check_invariants(&self) -> Result<(), RegistryError> {
        if self.instance_id == 0 {
            return Err(RegistryError::Invariant("invalid Registry instance"));
        }
        self.check_infrastructure_root_links()?;
        if self.device_publication_mode == DevicePublicationMode::DisabledNonDeviceCandidate
            && self
                .scopes
                .values()
                .any(|scope| scope.device_root.is_some())
        {
            return Err(RegistryError::Invariant(
                "non-device candidate acquired device publication state",
            ));
        }
        // Loom's modeled coroutine stack is intentionally small. Keep the
        // independently reconstructed index oracle on the heap so adding
        // production indexes does not turn a semantic check into stack-size
        // dependent evidence.
        let mut expected = Box::<ExpectedReverseIndexes>::default();
        let mut expected_credits: BTreeMap<ScopeKey, BTreeMap<CreditClass, (u64, u64, u64)>> =
            BTreeMap::new();
        let mut expected_pending_publications = BTreeMap::<ScopeKey, usize>::new();
        let mut expected_handoff_candidates = BTreeMap::<ScopeKey, BTreeSet<EffectKey>>::new();
        let mut nonces = BTreeSet::new();
        let mut tickets = BTreeSet::new();
        let mut device_batches = BTreeSet::<(ScopeKey, u64)>::new();

        for (key, scope) in &self.scopes {
            if key != &scope.key || key.generation == 0 {
                return Err(RegistryError::Invariant("scope identity mismatch"));
            }
            let legacy = scope
                .domains
                .get(&DomainKey::LEGACY)
                .ok_or(RegistryError::Invariant("scope lacks legacy domain"))?;
            if scope.binding_epoch != legacy.binding_epoch
                || scope.supervisor != legacy.supervisor
                || scope.fallback_running != legacy.fallback_running
            {
                return Err(RegistryError::Invariant(
                    "legacy domain projection mismatch",
                ));
            }
            for (domain, binding) in scope.domains.iter() {
                if binding.binding_epoch == 0 {
                    return Err(RegistryError::Invariant("invalid domain binding epoch"));
                }
                match scope.phase {
                    ScopePhase::Active => {
                        if binding.quarantine.is_some() {
                            if binding.supervisor.is_some() || binding.fallback_running {
                                return Err(RegistryError::Invariant(
                                    "quarantined domain retains authority",
                                ));
                            }
                        } else if binding.fallback_running == binding.supervisor.is_some() {
                            return Err(RegistryError::Invariant("invalid active domain binding"));
                        }
                    }
                    ScopePhase::Closing | ScopePhase::Revoked => {
                        if binding.supervisor.is_some()
                            || binding.fallback_running
                            || binding.recovery.is_some()
                        {
                            return Err(RegistryError::Invariant("unfenced inactive domain"));
                        }
                    }
                }
                if let Some(quarantine) = binding.quarantine {
                    if *domain == DomainKey::LEGACY
                        || quarantine.registry_instance_id != self.instance_id
                        || quarantine.scope != *key
                        || quarantine.domain != *domain
                        || quarantine.service.generation() == 0
                        || quarantine.binding_epoch != binding.binding_epoch
                    {
                        return Err(RegistryError::Invariant("invalid domain quarantine marker"));
                    }
                    if scope.phase == ScopePhase::Active {
                        let expected = binding.recovery.as_ref().map_or((None, None), |recovery| {
                            (
                                Some(recovery.crash_revision),
                                recovery.snapshot.as_ref().map(|snapshot| snapshot.attempt),
                            )
                        });
                        if expected != (quarantine.crash_revision, quarantine.recovery_attempt) {
                            return Err(RegistryError::Invariant(
                                "domain quarantine recovery marker drift",
                            ));
                        }
                    }
                }
                if let Some(recovery) = &binding.recovery {
                    if scope.phase != ScopePhase::Active
                        || recovery.crash_revision == 0
                        || recovery.crash_revision > binding.revision
                        || !recovery.unadopted.is_subset(&recovery.cohort)
                        || (recovery.highest_attempt == 0
                            && (recovery.snapshot.is_some() || recovery.last_abort.is_some()))
                    {
                        return Err(RegistryError::Invariant("invalid domain recovery state"));
                    }
                    for effect in &recovery.cohort {
                        let record = self
                            .effects
                            .get(effect)
                            .ok_or(RegistryError::Invariant("unknown domain recovery effect"))?;
                        if record.identity.scope != *key
                            || record.identity.domain != *domain
                            || record.identity.binding_epoch > binding.binding_epoch
                        {
                            return Err(RegistryError::Invariant("invalid domain recovery cohort"));
                        }
                    }
                    for effect in &recovery.unadopted {
                        if self.effects[effect].phase.is_terminal()
                            || self.effects[effect].identity.binding_epoch >= binding.binding_epoch
                        {
                            return Err(RegistryError::Invariant(
                                "invalid unadopted domain effect",
                            ));
                        }
                    }
                    if let Some(snapshot) = &recovery.snapshot
                        && (snapshot.registry_instance_id != self.instance_id
                            || snapshot.scope != *key
                            || snapshot.domain != *domain
                            || snapshot.replacement.generation() == 0
                            || snapshot.attempt == 0
                            || snapshot.attempt != recovery.highest_attempt
                            || snapshot.authority_epoch != scope.authority_epoch
                            || snapshot.binding_epoch != binding.binding_epoch
                            || snapshot.crash_revision != recovery.crash_revision
                            || snapshot.root_revision > scope.revision
                            || snapshot.domain_revision > binding.revision
                            || snapshot.cohort_identity
                                != domain_cohort_identity(Some(&recovery.cohort))?
                            || snapshot.digest != domain_recovery_snapshot_digest(snapshot))
                    {
                        return Err(RegistryError::Invariant(
                            "domain recovery snapshot mismatch",
                        ));
                    }
                    if let Some(abort) = recovery.last_abort
                        && (abort.registry_instance_id != self.instance_id
                            || abort.scope != *key
                            || abort.domain != *domain
                            || abort.replacement.generation() == 0
                            || abort.binding_epoch != binding.binding_epoch
                            || abort.crash_revision != recovery.crash_revision
                            || abort.attempt == 0
                            || abort.attempt > recovery.highest_attempt
                            || abort.snapshot_digest == [0; 32]
                            || recovery
                                .snapshot
                                .as_ref()
                                .is_some_and(|snapshot| abort.attempt >= snapshot.attempt))
                    {
                        return Err(RegistryError::Invariant(
                            "domain recovery abort receipt mismatch",
                        ));
                    }
                    if let Some(ready) = recovery.ready
                        && recovery.snapshot.as_ref().is_none_or(|snapshot| {
                            snapshot.replacement != ready
                                || snapshot.root_revision != scope.revision
                                || snapshot.domain_revision != binding.revision
                        })
                    {
                        return Err(RegistryError::Invariant("stale domain ready proof"));
                    }
                    self.check_domain_recovery_origin(*key, *domain, binding, recovery)?;
                } else if binding.fallback_running && *domain != DomainKey::LEGACY {
                    return Err(RegistryError::Invariant(
                        "fallback domain lacks recovery state",
                    ));
                }
            }
            for balance in scope.credits.balances.values() {
                if balance.free + balance.held + balance.committed + balance.retained
                    != balance.capacity
                {
                    return Err(RegistryError::Invariant("credit conservation"));
                }
            }
            match scope.phase {
                ScopePhase::Active => {
                    if scope.revoke.is_some() {
                        return Err(RegistryError::Invariant(
                            "active scope retains revoke state",
                        ));
                    }
                }
                ScopePhase::Closing => {
                    if scope.revoke.is_none()
                        || !scope.closure_candidates.is_empty()
                        || scope.recovery.is_some()
                        || scope.supervisor.is_some()
                        || scope.fallback_running
                    {
                        return Err(RegistryError::Invariant("invalid closing scope state"));
                    }
                }
                ScopePhase::Revoked => {
                    if scope.revoke.is_none()
                        || !scope.closure_candidates.is_empty()
                        || !scope.handoff_candidates.is_empty()
                        || scope.recovery.is_some()
                        || scope.supervisor.is_some()
                        || scope.fallback_running
                        || scope.pending_publications != 0
                        || !scope.credits.is_idle()
                    {
                        return Err(RegistryError::Invariant("invalid revoked scope state"));
                    }
                }
            }
            let admission = scope.handoff_gate.projection();
            match scope.handoff.as_ref() {
                None => {
                    if admission.phase != cser_transition_gates::handoff::AdmissionPhase::Open
                        || admission.freeze.is_some()
                        || admission.decision.is_some()
                    {
                        return Err(RegistryError::Invariant(
                            "handoff gate advanced without Registry state",
                        ));
                    }
                }
                Some(handoff) => {
                    if !handoff.committed_at_freeze.is_subset(&handoff.cohort)
                        || handoff.cohort.iter().any(|effect| {
                            self.effects
                                .get(effect)
                                .is_none_or(|record| record.identity.scope != *key)
                        })
                    {
                        return Err(RegistryError::Invariant(
                            "handoff Registry and gate identity mismatch",
                        ));
                    }
                    match (
                        handoff.decision.map(OwnershipDecisionReceipt::decision),
                        scope.phase,
                    ) {
                        (None, ScopePhase::Active) => {
                            if admission.phase
                                != cser_transition_gates::handoff::AdmissionPhase::Frozen
                                || admission.freeze != Some(handoff.freeze)
                                || admission.decision.is_some()
                                || !scope.handoff_candidates.is_subset(&handoff.cohort)
                            {
                                return Err(RegistryError::Invariant(
                                    "frozen handoff admitted an untracked effect",
                                ));
                            }
                        }
                        (
                            Some(OwnershipDecision::Abort),
                            ScopePhase::Active | ScopePhase::Closing | ScopePhase::Revoked,
                        ) => {
                            if admission.phase
                                != cser_transition_gates::handoff::AdmissionPhase::Open
                                || admission.freeze.is_some()
                                || admission.decision.is_some()
                                || admission.last_abort != handoff.decision
                                || handoff.thaw.is_none()
                                || handoff.revoke.is_some()
                                || handoff.closure.is_some()
                            {
                                return Err(RegistryError::Invariant(
                                    "aborted handoff did not reopen admission",
                                ));
                            }
                        }
                        (
                            Some(OwnershipDecision::Commit),
                            ScopePhase::Closing | ScopePhase::Revoked,
                        ) => {
                            if admission.phase
                                != cser_transition_gates::handoff::AdmissionPhase::CommitAccepted
                                || admission.freeze != Some(handoff.freeze)
                                || admission.decision != handoff.decision
                                || handoff.revoke.is_none()
                                || (handoff.closure.is_some() && scope.phase != ScopePhase::Revoked)
                            {
                                return Err(RegistryError::Invariant(
                                    "committed handoff lacks irreversible closure state",
                                ));
                            }
                        }
                        _ => {
                            return Err(RegistryError::Invariant(
                                "handoff decision and authority phase disagree",
                            ));
                        }
                    }
                    if let Some(closure) = handoff.closure.as_ref() {
                        let manifest_digest =
                            handoff_terminal_manifest_digest(&handoff.cohort, &self.effects)
                                .map_err(|_| {
                                    RegistryError::Invariant(
                                        "handoff closure manifest cannot be recomputed",
                                    )
                                })?;
                        if closure.freeze != handoff.freeze
                            || handoff.decision != Some(closure.decision)
                            || handoff.revoke.as_ref() != Some(&closure.revoke)
                            || closure.revoke != *closure.scope_closure.revoke()
                            || closure.closed_scope_revision != scope.revision
                            || closure.scope_closure.closed_scope_revision() != scope.revision
                            || closure.terminal_manifest_digest != manifest_digest
                        {
                            return Err(RegistryError::Invariant(
                                "stored handoff closure drifted from its authority state",
                            ));
                        }
                        self.verify_scope_closure(*key, &closure.scope_closure)
                            .map_err(|_| {
                                RegistryError::Invariant(
                                    "stored handoff closure has invalid scope receipt",
                                )
                            })?;
                    }
                }
            }
            if let Some(revoke) = &scope.revoke {
                let target_count = u64::try_from(revoke.target_count)
                    .map_err(|_| RegistryError::Invariant("revoke target count overflow"))?;
                if revoke.infrastructure.is_some() != self.infrastructure.is_enabled(*key) {
                    return Err(RegistryError::Invariant(
                        "revoke infrastructure ownership mismatch",
                    ));
                }
                if revoke.sequence == 0
                    || revoke.authority_epoch != scope.authority_epoch
                    || revoke
                        .closed_authority_epoch
                        .checked_add(1)
                        .is_none_or(|epoch| epoch != revoke.authority_epoch)
                    || revoke.work.head_selections > revoke.work.next_calls
                    || revoke.work.terminalized > target_count
                    || revoke.work.target_index_removals > target_count
                    || revoke.work.terminalized != revoke.work.target_index_removals
                {
                    return Err(RegistryError::Invariant("invalid revoke accounting"));
                }
                match scope.phase {
                    ScopePhase::Active => __cser_core::unreachable!(),
                    ScopePhase::Closing => {
                        if revoke.cohort.len() != revoke.target_count
                            || revoke.work.completion_members_checked != 0
                            || revoke.closure.is_some()
                            || revoke
                                .selected_head
                                .is_some_and(|effect| !revoke.cohort.contains(&effect))
                        {
                            return Err(RegistryError::Invariant("invalid closing revoke state"));
                        }
                    }
                    ScopePhase::Revoked => {
                        if !revoke.cohort.is_empty()
                            || revoke.selected_head.is_some()
                            || revoke.retired_recovery.is_some()
                            || revoke.work.terminalized != target_count
                            || revoke.work.target_index_removals != target_count
                            || revoke.work.completion_members_checked != target_count
                            || revoke.closure.is_none()
                        {
                            return Err(RegistryError::Invariant("invalid completed revoke state"));
                        }
                        let closure = revoke.closure.as_ref().unwrap();
                        if closure.registry_instance_id != self.instance_id
                            || closure.closed_scope_revision != scope.revision
                            || closure.revoke.scope != *key
                            || closure.revoke.sequence != revoke.sequence
                            || closure.revoke.closed_authority_epoch
                                != revoke.closed_authority_epoch
                            || closure.revoke.authority_epoch != revoke.authority_epoch
                            || closure.revoke.target_count != revoke.target_count
                            || closure.infrastructure.is_some() != revoke.infrastructure.is_some()
                        {
                            return Err(RegistryError::Invariant(
                                "invalid combined scope closure receipt",
                            ));
                        }
                        if let (Some(selection), Some(infrastructure)) =
                            (revoke.infrastructure, closure.infrastructure)
                        {
                            if !selection.binds_receipt(infrastructure) {
                                return Err(RegistryError::Invariant(
                                    "infrastructure closure selector and receipt differ",
                                ));
                            }
                            self.infrastructure
                                .verify_closure_receipt(infrastructure)
                                .map_err(|_| {
                                    RegistryError::Invariant(
                                        "invalid stored infrastructure closure receipt",
                                    )
                                })?;
                        }
                    }
                }
            }
            if let Some(recovery) = &scope.recovery {
                if scope.phase != ScopePhase::Active {
                    return Err(RegistryError::Invariant("inactive recovery state"));
                }
                if !recovery.unadopted.is_subset(&recovery.cohort) {
                    return Err(RegistryError::Invariant("recovery cohort mismatch"));
                }
                for effect in &recovery.unadopted {
                    let record = self
                        .effects
                        .get(effect)
                        .ok_or(RegistryError::Invariant("unknown recovery effect"))?;
                    if record.identity.scope != *key
                        || record.identity.domain != DomainKey::LEGACY
                        || record.phase.is_terminal()
                        || record.identity.binding_epoch >= scope.binding_epoch
                    {
                        return Err(RegistryError::Invariant("invalid unadopted effect"));
                    }
                }
                if recovery.cohort.iter().any(|effect| {
                    self.effects.get(effect).is_none_or(|record| {
                        record.identity.scope != *key
                            || record.identity.domain != DomainKey::LEGACY
                            || record.phase.is_terminal()
                    })
                }) {
                    return Err(RegistryError::Invariant("invalid recovery cohort effect"));
                }
                if let Some(ready) = recovery.ready
                    && recovery.snapshot.as_ref().is_none_or(|snapshot| {
                        snapshot.replacement != ready
                            || snapshot.revision != scope.revision
                            || snapshot.domain_revision != scope.domain_revision
                    })
                {
                    return Err(RegistryError::Invariant("stale legacy ready proof"));
                }
            }
        }

        for (key, record) in &self.effects {
            if key != &record.identity.effect
                || key.generation == 0
                || record.identity.scope.generation == 0
                || record.identity.task.generation == 0
                || record
                    .identity
                    .resources
                    .iter()
                    .any(|resource| resource.generation == 0)
                || record
                    .current_resources
                    .iter()
                    .any(|resource| resource.generation == 0)
            {
                return Err(RegistryError::Invariant("effect identity mismatch"));
            }
            let scope = self
                .scopes
                .get(&record.identity.scope)
                .ok_or(RegistryError::Invariant("effect references unknown scope"))?;
            let binding = scope
                .domains
                .get(&record.identity.domain)
                .ok_or(RegistryError::Invariant("effect references unknown domain"))?;
            if record.identity.origin_binding_epoch == 0
                || record.identity.origin_binding_epoch > record.identity.binding_epoch
                || record.identity.binding_epoch > binding.binding_epoch
            {
                return Err(RegistryError::Invariant("effect has future binding"));
            }
            if let Some(parent) = record.identity.parent {
                let parent_record = self
                    .effects
                    .get(&parent)
                    .ok_or(RegistryError::Invariant("effect references unknown parent"))?;
                if parent.id >= key.id
                    || parent_record.identity.scope != record.identity.scope
                    || parent_record.identity.authority_epoch != record.identity.authority_epoch
                    || (!record.phase.is_terminal() && parent_record.phase.is_terminal())
                {
                    return Err(RegistryError::Invariant("invalid effect ancestry"));
                }
            }
            if !nonces.insert(record.nonce) {
                return Err(RegistryError::Invariant("duplicate portal nonce"));
            }
            if record.outcome.is_some_and(|outcome| {
                record.commit.is_none() || outcome.digest().iter().all(|byte| *byte == 0)
            }) {
                return Err(RegistryError::Invariant(
                    "canonical outcome lacks committed cause",
                ));
            }

            match record.phase {
                EffectPhase::Registered | EffectPhase::Prepared => {
                    let retained_unpublished = record.credit_state == CreditState::Retained
                        && scope.device_root.as_ref().is_some_and(|root| {
                            root.batch_sequence.is_none()
                                && root.outcome == Some(DeviceClosureResult::AbortedBeforeCommit)
                                && root.enrollment.as_ref().is_some_and(|enrollment| {
                                    enrollment.effects.contains(&record.identity.effect)
                                })
                        });
                    if record.commit.is_some()
                        || record.outcome.is_some()
                        || record.device_batch.is_some()
                        || record.terminal.is_some()
                        || record.terminalizations != 0
                        || record.publication_acks != 0
                        || record.pending_publication.is_some()
                        || (record.credit_state != CreditState::Held && !retained_unpublished)
                    {
                        return Err(RegistryError::Invariant("invalid uncommitted effect"));
                    }
                }
                EffectPhase::Committed => {
                    if record.commit.is_none()
                        || record.terminal.is_some()
                        || record.terminalizations != 0
                        || record.publication_acks != 0
                        || record.pending_publication.is_some()
                        || !__cser_core::matches!(
                            record.credit_state,
                            CreditState::Committed | CreditState::Retained
                        )
                        || (record.credit_state == CreditState::Retained
                            && record.device_batch.is_none())
                    {
                        return Err(RegistryError::Invariant("invalid committed effect"));
                    }
                }
                EffectPhase::Terminal(outcome) => {
                    let terminal = record
                        .terminal
                        .as_ref()
                        .ok_or(RegistryError::Invariant("terminal receipt missing"))?;
                    if record.terminalizations != 1 || terminal.outcome != outcome {
                        return Err(RegistryError::Invariant("single terminalization"));
                    }
                    if outcome == TerminalOutcome::Aborted && record.commit.is_some() {
                        return Err(RegistryError::Invariant("committed effect aborted"));
                    }
                    if outcome == TerminalOutcome::Aborted && record.outcome.is_some() {
                        return Err(RegistryError::Invariant("aborted effect recorded outcome"));
                    }
                    if outcome == TerminalOutcome::Completed
                        && record.commit.is_none()
                        && terminal.causal_commit.is_none()
                    {
                        return Err(RegistryError::Invariant("completion lacks commit cause"));
                    }
                    if outcome == TerminalOutcome::Completed
                        && record.outcome.is_some_and(|recorded| {
                            recorded.class() == EffectOutcomeClass::Indeterminate
                                || recorded.result() != terminal.result
                        })
                    {
                        return Err(RegistryError::Invariant(
                            "completion conflicts with canonical outcome",
                        ));
                    }
                    if outcome == TerminalOutcome::Completed
                        && record.outcome_required
                        && record.outcome.is_none()
                    {
                        return Err(RegistryError::Invariant(
                            "required completion lacks canonical outcome",
                        ));
                    }
                    if terminal.causal_commit.as_ref().is_some_and(|causal| {
                        !causal_commit_matches(
                            self.instance_id,
                            &self.effects,
                            &record.identity,
                            causal,
                        )
                    }) {
                        return Err(RegistryError::Invariant(
                            "completion has invalid causal commit",
                        ));
                    }
                    if outcome == TerminalOutcome::IndeterminateAfterReset
                        && (record.commit.is_none()
                            || record.device_batch.is_none()
                            || terminal.causal_commit.is_some())
                    {
                        return Err(RegistryError::Invariant(
                            "indeterminate terminal lacks committed device cause",
                        ));
                    }
                    if outcome == TerminalOutcome::IndeterminateAfterReset
                        && record.outcome.is_some_and(|recorded| {
                            recorded.class() != EffectOutcomeClass::Indeterminate
                                || recorded.result() != terminal.result
                        })
                    {
                        return Err(RegistryError::Invariant(
                            "indeterminate terminal conflicts with recorded outcome",
                        ));
                    }
                    match record.publication_mode {
                        PublicationMode::None => {
                            if record.pending_publication.is_some()
                                || record.publication_acks != 0
                                || record.credit_state != CreditState::Released
                            {
                                return Err(RegistryError::Invariant("unexpected publication"));
                            }
                        }
                        PublicationMode::Required => match record.pending_publication.as_ref() {
                            Some(ticket) => {
                                if record.publication_acks != 0
                                    || record.credit_state == CreditState::Released
                                    || !tickets.insert(ticket.ticket_sequence)
                                {
                                    return Err(RegistryError::Invariant(
                                        "invalid pending publication",
                                    ));
                                }
                                let pending = expected_pending_publications
                                    .entry(record.identity.scope)
                                    .or_default();
                                *pending = pending.checked_add(1).ok_or(
                                    RegistryError::Invariant("pending publication overflow"),
                                )?;
                            }
                            None => {
                                if record.publication_acks != 1
                                    || record.credit_state != CreditState::Released
                                {
                                    return Err(RegistryError::Invariant(
                                        "publication not acknowledged",
                                    ));
                                }
                            }
                        },
                    }
                }
            }

            if let Some(membership) = record.device_batch {
                if membership.sequence == 0
                    || membership.sequence >= self.next_device_batch_sequence
                    || membership.size == 0
                    || membership.ordinal >= membership.size
                    || record.commit.is_none()
                    || record.phase == EffectPhase::Terminal(TerminalOutcome::Aborted)
                {
                    return Err(RegistryError::Invariant("invalid device batch membership"));
                }
                if let Some(device) = record.identity.device
                    && device != membership.device
                {
                    return Err(RegistryError::Invariant("device batch envelope mismatch"));
                }
                device_batches.insert((record.identity.scope, membership.sequence));
            } else if record.identity.device.is_some()
                && __cser_core::matches!(
                    record.phase,
                    EffectPhase::Committed
                        | EffectPhase::Terminal(TerminalOutcome::Completed)
                        | EffectPhase::Terminal(TerminalOutcome::IndeterminateAfterReset)
                )
            {
                return Err(RegistryError::Invariant("device effect escaped root batch"));
            }

            if let Some(commit) = &record.commit
                && (commit.effect != *key
                    || commit.scope != record.identity.scope
                    || commit.authority_epoch != record.identity.authority_epoch
                    || commit.binding_epoch > record.identity.binding_epoch
                    || commit.sequence == 0
                    || commit.descriptor_digest != record.descriptor.digest())
            {
                return Err(RegistryError::Invariant("commit receipt identity mismatch"));
            }
            if let Some(terminal) = &record.terminal
                && (terminal.effect != *key
                    || terminal.sequence == 0
                    || terminal
                        .manifest_digest
                        .is_some_and(|digest| digest.iter().all(|byte| *byte == 0)))
            {
                return Err(RegistryError::Invariant(
                    "terminal receipt identity mismatch",
                ));
            }

            if !record.phase.is_terminal() {
                expected
                    .by_scope
                    .entry(record.identity.scope)
                    .or_default()
                    .insert(*key);
                expected
                    .by_domain
                    .entry((record.identity.scope, record.identity.domain))
                    .or_default()
                    .insert(*key);
                expected
                    .by_task
                    .entry(record.identity.task)
                    .or_default()
                    .insert(*key);
                if let Some(parent) = record.identity.parent {
                    expected
                        .children_by_parent
                        .entry(parent)
                        .or_default()
                        .insert(*key);
                }
                for resource in &record.current_resources {
                    expected
                        .by_resource
                        .entry(*resource)
                        .or_default()
                        .insert(*key);
                }
            }
            match record.credit_state {
                CreditState::Held => add_expected_credits(
                    &mut expected_credits,
                    record.identity.scope,
                    &record.credits,
                    CreditState::Held,
                )?,
                CreditState::Committed => add_expected_credits(
                    &mut expected_credits,
                    record.identity.scope,
                    &record.credits,
                    CreditState::Committed,
                )?,
                CreditState::Retained => add_expected_credits(
                    &mut expected_credits,
                    record.identity.scope,
                    &record.credits,
                    CreditState::Retained,
                )?,
                CreditState::Released => {}
            }
            if !record.phase.is_terminal() || record.pending_publication.is_some() {
                expected_handoff_candidates
                    .entry(record.identity.scope)
                    .or_default()
                    .insert(*key);
            }
        }

        // Device preparation is the only infrastructure obligation which
        // owns business credits. Reconstruct that ownership from its primary
        // record rather than trusting stored CreditLedger totals. Once
        // materialized, the same units are attributed only to EffectRecords.
        for owner in self.infrastructure.device_preparation_credit_projections() {
            let parent = self
                .effects
                .get(&owner.parent_effect)
                .ok_or(RegistryError::Invariant(
                    "device preparation parent effect missing",
                ))?;
            if parent.identity.scope != owner.scope {
                return Err(RegistryError::Invariant(
                    "device preparation parent scope mismatch",
                ));
            }
            match owner.ownership {
                infrastructure::DevicePreparationCreditOwnership::HeldByPreparation => {
                    add_expected_credits(
                        &mut expected_credits,
                        owner.scope,
                        &owner.charges,
                        CreditState::Held,
                    )?;
                }
                infrastructure::DevicePreparationCreditOwnership::RetainedByPreparation => {
                    add_expected_credits(
                        &mut expected_credits,
                        owner.scope,
                        &owner.charges,
                        CreditState::Retained,
                    )?;
                }
                infrastructure::DevicePreparationCreditOwnership::TransferredToCohort => {
                    self.check_materialized_device_preparation(&owner)?;
                }
                infrastructure::DevicePreparationCreditOwnership::Released => {}
            }
        }

        if self.next_device_enrollment_sequence == 0
            || self.next_device_batch_sequence == 0
            || self.next_device_closure_sequence == 0
        {
            return Err(RegistryError::Invariant(
                "invalid next device transition sequence",
            ));
        }
        for (scope, sequence) in device_batches {
            self.reconstruct_device_batch_receipt(scope, sequence)
                .map_err(|_| RegistryError::Invariant("invalid reconstructed device batch"))?;
        }
        for (scope, record) in &self.scopes {
            if let Some(device_root) = &record.device_root {
                self.check_device_root_invariants(*scope, device_root)?;
            } else if self
                .effects
                .values()
                .any(|effect| effect.identity.scope == *scope && effect.identity.device.is_some())
            {
                return Err(RegistryError::Invariant(
                    "device effect lacks root enrollment state",
                ));
            }
        }

        for (scope, effects) in &expected.by_scope {
            for effect in effects {
                if !expected.children_by_parent.contains_key(effect) {
                    expected
                        .leaves_by_scope
                        .entry(*scope)
                        .or_default()
                        .insert(*effect);
                }
            }
        }

        if self.by_scope != expected.by_scope
            || self.production.by_domain != expected.by_domain
            || self.by_task != expected.by_task
            || self.by_resource != expected.by_resource
            || self.production.children_by_parent != expected.children_by_parent
            || self.production.leaves_by_scope != expected.leaves_by_scope
        {
            return Err(RegistryError::Invariant("reverse index mismatch"));
        }

        for (scope_key, scope) in &self.scopes {
            let expected_live = expected.by_scope.get(scope_key);
            let live_count = expected_live.map_or(0, BTreeSet::len);
            match scope.phase {
                ScopePhase::Active => {
                    if expected_live != Some(&scope.closure_candidates)
                        && !(expected_live.is_none() && scope.closure_candidates.is_empty())
                    {
                        return Err(RegistryError::Invariant(
                            "active closure candidate mismatch",
                        ));
                    }
                }
                ScopePhase::Closing => {
                    let revoke = scope.revoke.as_ref().unwrap();
                    if expected_live.is_some_and(|live| !live.is_subset(&revoke.cohort))
                        || u64::try_from(live_count)
                            .ok()
                            .and_then(|live| live.checked_add(revoke.work.terminalized))
                            != u64::try_from(revoke.target_count).ok()
                        || revoke.selected_head.is_some_and(|effect| {
                            expected_live.is_none_or(|live| !live.contains(&effect))
                        })
                        || revoke.selected_head.is_some_and(|effect| {
                            expected
                                .leaves_by_scope
                                .get(scope_key)
                                .is_none_or(|leaves| !leaves.contains(&effect))
                        })
                    {
                        return Err(RegistryError::Invariant("closing live target mismatch"));
                    }
                    for effect in &revoke.cohort {
                        let record = self
                            .effects
                            .get(effect)
                            .ok_or(RegistryError::Invariant("unknown frozen revoke effect"))?;
                        if record.identity.scope != *scope_key
                            || record.identity.authority_epoch != revoke.closed_authority_epoch
                        {
                            return Err(RegistryError::Invariant(
                                "frozen revoke identity mismatch",
                            ));
                        }
                    }
                }
                ScopePhase::Revoked => {
                    if live_count != 0 {
                        return Err(RegistryError::Invariant(
                            "revoked scope retains live effects",
                        ));
                    }
                }
            }
            if scope.pending_publications
                != expected_pending_publications
                    .get(scope_key)
                    .copied()
                    .unwrap_or(0)
            {
                return Err(RegistryError::Invariant(
                    "pending publication count mismatch",
                ));
            }
            let expected_handoff = expected_handoff_candidates.get(scope_key);
            if expected_handoff != Some(&scope.handoff_candidates)
                && !(expected_handoff.is_none() && scope.handoff_candidates.is_empty())
            {
                return Err(RegistryError::Invariant("handoff candidate index mismatch"));
            }
            let expected = expected_credits.get(scope_key);
            if expected.is_some_and(|classes| {
                classes
                    .keys()
                    .any(|class| !scope.credits.balances.contains_key(class))
            }) {
                return Err(RegistryError::Invariant(
                    "credit owner references unknown class",
                ));
            }
            for (class, balance) in &scope.credits.balances {
                let (held, committed, retained) = expected
                    .and_then(|classes| classes.get(class))
                    .copied()
                    .unwrap_or((0, 0, 0));
                if balance.held != held
                    || balance.committed != committed
                    || balance.retained != retained
                {
                    return Err(RegistryError::Invariant("credit ownership mismatch"));
                }
            }
        }

        Ok(())
    }

    fn check_materialized_device_preparation(
        &self,
        owner: &infrastructure::DevicePreparationCreditProjection,
    ) -> Result<(), RegistryError> {
        let prepared = owner.prepared.ok_or(RegistryError::Invariant(
            "transferred preparation lacks prepared owner",
        ))?;
        let cohort = owner.cohort.ok_or(RegistryError::Invariant(
            "transferred preparation lacks exact cohort",
        ))?;
        let effects = cohort.ordered_effects();
        if cohort.digest != device_cohort_digest(prepared, effects) {
            return Err(RegistryError::Invariant("device cohort digest mismatch"));
        }
        let records = effects.map(|effect| self.effects.get(&effect));
        let [Some(block), Some(dma_a), Some(dma_b), Some(dma_request)] = records else {
            return Err(RegistryError::Invariant(
                "materialized preparation cohort effect missing",
            ));
        };
        let cohort_domain = block.identity.domain;
        let cohort_task = block.identity.task;
        if block.identity.scope != owner.scope
            || block.identity.parent != Some(owner.parent_effect)
            || block.identity.device != Some(prepared.device)
            || block.descriptor.digest() != prepared.operation_digest
            || block
                .identity
                .resources
                .iter()
                .filter(|resource| **resource == prepared.owned_device)
                .count()
                != 1
            || block.credits.as_slice()
                != [CreditCharge::new(
                    owner.charges[0].class,
                    owner.charges[0].units,
                )]
            || block.publication_mode != PublicationMode::None
        {
            return Err(RegistryError::Invariant(
                "materialized block preparation mismatch",
            ));
        }
        let expected_dma = [
            CreditCharge::new(owner.charges[1].class, 1),
            CreditCharge::new(owner.charges[2].class, 1),
        ];
        for dma in [dma_a, dma_b, dma_request] {
            if dma.identity.scope != owner.scope
                || dma.identity.domain != cohort_domain
                || dma.identity.parent != Some(cohort.block)
                || dma.identity.task != cohort_task
                || dma.identity.device != Some(prepared.device)
                || dma.credits.len() != 2
                || !expected_dma
                    .iter()
                    .all(|expected| dma.credits.contains(expected))
                || dma.publication_mode != PublicationMode::None
            {
                return Err(RegistryError::Invariant(
                    "materialized DMA preparation mismatch",
                ));
            }
        }
        Ok(())
    }

    fn check_device_root_invariants(
        &self,
        scope_key: ScopeKey,
        root: &DeviceRootState,
    ) -> Result<(), RegistryError> {
        root.initial_device.validate()?;
        root.current_device.validate()?;
        if !root
            .initial_device
            .same_device_except_generation(root.current_device)
            || root.current_device.device_generation < root.initial_device.device_generation
        {
            return Err(RegistryError::Invariant("device root generation mismatch"));
        }
        let device_effects = self
            .effects
            .values()
            .filter(|record| record.identity.scope == scope_key && record.identity.device.is_some())
            .count();
        if device_effects == 0 {
            return Err(RegistryError::Invariant("device root lacks device effects"));
        }

        let Some(enrollment) = root.enrollment.as_ref() else {
            if root.batch_sequence.is_some()
                || !root.publication.is_none()
                || root.completion.is_some()
                || root.outcome.is_some()
                || root.reset_ticket.is_some()
                || root.reset_tombstone.is_some()
                || root.reset_retry_issued
                || root.reset_receipt.is_some()
                || root.iotlb_ticket.is_some()
                || root.iotlb_tombstone.is_some()
                || root.iotlb_retry_issued
                || root.closure.is_some()
                || root.current_device != root.initial_device
            {
                return Err(RegistryError::Invariant(
                    "unenrolled device root advanced closure state",
                ));
            }
            return Ok(());
        };
        if enrollment.registry_instance_id != self.instance_id
            || enrollment.scope != scope_key
            || enrollment.authority_epoch == 0
            || enrollment.enrollment_sequence == 0
            || enrollment.enrollment_sequence >= self.next_device_enrollment_sequence
            || enrollment.device != root.initial_device
            || enrollment.effects.is_empty()
        {
            return Err(RegistryError::Invariant(
                "invalid device enrollment receipt",
            ));
        }
        if enrollment.cancel_only
            && (root.batch_sequence.is_some()
                || self.scopes[&scope_key].phase == ScopePhase::Active)
        {
            return Err(RegistryError::Invariant(
                "cancel-only enrollment escaped closing root",
            ));
        }
        let enrolled: BTreeSet<_> = enrollment.effects.iter().copied().collect();
        if enrolled.len() != enrollment.effects.len() {
            return Err(RegistryError::Invariant(
                "duplicate device enrollment member",
            ));
        }
        let mut roots = 0_usize;
        let mut enrolled_devices = 0_usize;
        for effect in &enrollment.effects {
            let record = self
                .effects
                .get(effect)
                .ok_or(RegistryError::Invariant("unknown device enrollment member"))?;
            if record.identity.scope != scope_key
                || record.identity.authority_epoch != enrollment.authority_epoch
            {
                return Err(RegistryError::Invariant(
                    "device enrollment identity mismatch",
                ));
            }
            if let Some(parent) = record.identity.parent {
                if !enrolled.contains(&parent) {
                    return Err(RegistryError::Invariant(
                        "disconnected device enrollment ancestry",
                    ));
                }
            } else {
                roots = roots
                    .checked_add(1)
                    .ok_or(RegistryError::Invariant("device enrollment root overflow"))?;
            }
            if let Some(device) = record.identity.device {
                if device != root.initial_device {
                    return Err(RegistryError::Invariant(
                        "device enrollment envelope mismatch",
                    ));
                }
                enrolled_devices = enrolled_devices
                    .checked_add(1)
                    .ok_or(RegistryError::Invariant("device enrollment count overflow"))?;
            }
        }
        if roots != 1 || enrolled_devices == 0 {
            return Err(RegistryError::Invariant("invalid device enrollment graph"));
        }

        if let Some(batch_sequence) = root.batch_sequence {
            let batch = self
                .reconstruct_device_batch_receipt(scope_key, batch_sequence)
                .map_err(|_| RegistryError::Invariant("device root batch reconstruction failed"))?;
            if batch.device != root.initial_device
                || batch
                    .commits
                    .iter()
                    .map(|commit| commit.effect)
                    .ne(enrollment.effects.iter().copied())
            {
                return Err(RegistryError::Invariant(
                    "device root batch enrollment drift",
                ));
            }
            if root.outcome == Some(DeviceClosureResult::AbortedBeforeCommit) {
                return Err(RegistryError::Invariant(
                    "published device root reported precommit abort",
                ));
            }
            match &root.publication {
                DevicePublicationProvenance::Legacy => {}
                DevicePublicationProvenance::Applied {
                    operation,
                    batch: stored,
                } => {
                    let scope = &self.scopes[&scope_key];
                    let selection = Self::device_revoke_selection(scope_key, scope).ok_or(
                        RegistryError::Invariant("device close operation lacks revoke progress"),
                    )?;
                    if operation.registry_instance_id != self.instance_id
                        || operation.scope != scope_key
                        || operation.authority_epoch != enrollment.authority_epoch
                        || operation.enrollment_sequence != enrollment.enrollment_sequence
                        || operation.device != root.initial_device
                        || operation.owner.generation() == 0
                        || operation.caller_nonce == 0
                        || stored != &batch
                        || selection.closed_authority_epoch != operation.authority_epoch
                        || selection.target_count != enrollment.effects.len()
                        || !__cser_core::matches!(
                            scope.phase,
                            ScopePhase::Closing | ScopePhase::Revoked
                        )
                    {
                        return Err(RegistryError::Invariant(
                            "device close operation identity drift",
                        ));
                    }
                }
                DevicePublicationProvenance::None
                | DevicePublicationProvenance::Publishing { .. } => {
                    return Err(RegistryError::Invariant(
                        "published root lacks applied publication provenance",
                    ));
                }
            }
        } else {
            match &root.publication {
                DevicePublicationProvenance::None => {}
                DevicePublicationProvenance::Publishing { operation, batch } => {
                    let scope = &self.scopes[&scope_key];
                    if scope.phase != ScopePhase::Active
                        || scope.revoke.is_some()
                        || operation.registry_instance_id != self.instance_id
                        || operation.scope != scope_key
                        || operation.authority_epoch != enrollment.authority_epoch
                        || operation.enrollment_sequence != enrollment.enrollment_sequence
                        || operation.device != root.initial_device
                        || operation.owner.generation() == 0
                        || operation.caller_nonce == 0
                        || batch.registry_instance_id != self.instance_id
                        || batch.scope != scope_key
                        || batch.authority_epoch != enrollment.authority_epoch
                        || batch.device != root.initial_device
                        || batch.commits.len() != enrollment.effects.len()
                        || batch
                            .commits
                            .iter()
                            .map(|commit| commit.effect)
                            .ne(enrollment.effects.iter().copied())
                    {
                        return Err(RegistryError::Invariant(
                            "publishing device close provenance drift",
                        ));
                    }
                }
                DevicePublicationProvenance::Legacy
                | DevicePublicationProvenance::Applied { .. } => {
                    return Err(RegistryError::Invariant(
                        "unpublished root retained applied publication provenance",
                    ));
                }
            }
            if enrollment.effects.iter().any(|effect| {
                self.effects[effect].commit.is_some() || self.effects[effect].device_batch.is_some()
            }) {
                return Err(RegistryError::Invariant(
                    "unpublished device enrollment contains committed effect",
                ));
            }
            if root.completion.is_some()
                || (root.outcome.is_some()
                    && root.outcome != Some(DeviceClosureResult::AbortedBeforeCommit))
            {
                return Err(RegistryError::Invariant(
                    "unpublished device root has invalid workload outcome",
                ));
            }
        }
        let valid_sequence =
            |sequence: u64| sequence != 0 && sequence < self.next_device_closure_sequence;
        if let Some(completion) = root.completion
            && (completion.registry_instance_id != self.instance_id
                || completion.scope != scope_key
                || Some(completion.batch_sequence) != root.batch_sequence
                || completion.device != root.initial_device
                || !valid_sequence(completion.sequence))
        {
            return Err(RegistryError::Invariant(
                "invalid device completion receipt",
            ));
        }
        if let Some(completion) = root.completion {
            let batch = self
                .reconstruct_device_batch_receipt(scope_key, completion.batch_sequence)
                .map_err(|_| RegistryError::Invariant("completion lacks authoritative batch"))?;
            let causal_root = self
                .device_batch_causal_root_commit(&batch)
                .map_err(|_| RegistryError::Invariant("completion lacks unique causal root"))?;
            if completion.causal_root != causal_root.effect
                || completion.causal_commit_sequence != causal_root.sequence
                || completion.result != causal_root.result
            {
                return Err(RegistryError::Invariant(
                    "device completion causal root drift",
                ));
            }
        }
        if let Some(ticket) = root.reset_ticket
            && (ticket.registry_instance_id != self.instance_id
                || ticket.scope != scope_key
                || ticket.enrollment_sequence != enrollment.enrollment_sequence
                || ticket.batch_sequence != root.batch_sequence
                || ticket.device != root.initial_device
                || !valid_sequence(ticket.sequence)
                || root.reset_receipt.is_some())
        {
            return Err(RegistryError::Invariant("invalid device reset ticket"));
        }
        if let Some(tombstone) = root.reset_tombstone
            && (tombstone.ticket.registry_instance_id != self.instance_id
                || tombstone.ticket.scope != scope_key
                || tombstone.ticket.enrollment_sequence != enrollment.enrollment_sequence
                || tombstone.ticket.batch_sequence != root.batch_sequence
                || tombstone.ticket.device != root.initial_device
                || !valid_sequence(tombstone.ticket.sequence)
                || !valid_sequence(tombstone.sequence))
        {
            return Err(RegistryError::Invariant("invalid device reset tombstone"));
        }
        if root.reset_retry_issued && root.reset_tombstone.is_none() {
            return Err(RegistryError::Invariant("reset retry lacks tombstone"));
        }
        if let Some(reset) = root.reset_receipt {
            if reset.registry_instance_id != self.instance_id
                || reset.scope != scope_key
                || reset.enrollment_sequence != enrollment.enrollment_sequence
                || reset.batch_sequence != root.batch_sequence
                || reset.old_device != root.initial_device
                || reset.new_device != root.current_device
                || reset.new_device.device_generation
                    != reset
                        .old_device
                        .device_generation
                        .checked_add(1)
                        .ok_or(RegistryError::Invariant("reset generation overflow"))?
                || !valid_sequence(reset.sequence)
                || root.reset_ticket.is_some()
                || Some(reset.outcome) != root.outcome
            {
                return Err(RegistryError::Invariant("invalid device reset receipt"));
            }
        } else if root.current_device != root.initial_device
            || root.iotlb_ticket.is_some()
            || root.iotlb_tombstone.is_some()
            || root.iotlb_retry_issued
            || root.closure.is_some()
        {
            return Err(RegistryError::Invariant(
                "IOTLB state precedes device reset",
            ));
        }
        if let Some(ticket) = root.iotlb_ticket
            && (ticket.registry_instance_id != self.instance_id
                || ticket.scope != scope_key
                || ticket.enrollment_sequence != enrollment.enrollment_sequence
                || ticket.batch_sequence != root.batch_sequence
                || ticket.device != root.current_device
                || root
                    .reset_receipt
                    .is_none_or(|reset| reset.sequence != ticket.reset_sequence)
                || !valid_sequence(ticket.sequence)
                || root.closure.is_some())
        {
            return Err(RegistryError::Invariant("invalid device IOTLB ticket"));
        }
        if let Some(tombstone) = root.iotlb_tombstone
            && (tombstone.ticket.registry_instance_id != self.instance_id
                || tombstone.ticket.scope != scope_key
                || tombstone.ticket.enrollment_sequence != enrollment.enrollment_sequence
                || tombstone.ticket.batch_sequence != root.batch_sequence
                || tombstone.ticket.device != root.current_device
                || !valid_sequence(tombstone.ticket.sequence)
                || !valid_sequence(tombstone.sequence))
        {
            return Err(RegistryError::Invariant("invalid device IOTLB tombstone"));
        }
        if root.iotlb_retry_issued && root.iotlb_tombstone.is_none() {
            return Err(RegistryError::Invariant("IOTLB retry lacks tombstone"));
        }
        if let Some(closure) = root.closure
            && (closure.registry_instance_id != self.instance_id
                || closure.scope != scope_key
                || closure.enrollment_sequence != enrollment.enrollment_sequence
                || closure.batch_sequence != root.batch_sequence
                || closure.device != root.current_device
                || closure.outcome
                    != root.outcome.ok_or(RegistryError::Invariant(
                        "device closure lacks honest outcome",
                    ))?
                || !valid_sequence(closure.sequence)
                || root.iotlb_ticket.is_some()
                || root.reset_receipt.is_none())
        {
            return Err(RegistryError::Invariant("invalid device closure receipt"));
        }
        if let Some(DeviceClosureResult::Completed(result)) = root.outcome
            && root
                .completion
                .is_none_or(|completion| completion.result != result)
        {
            return Err(RegistryError::Invariant("device completion result drift"));
        }
        if root.outcome == Some(DeviceClosureResult::IndeterminateAfterReset)
            && (root.batch_sequence.is_none() || root.completion.is_some())
        {
            return Err(RegistryError::Invariant(
                "indeterminate result conflicts with publication/completion",
            ));
        }
        let has_retained = enrollment
            .effects
            .iter()
            .any(|effect| self.effects[effect].credit_state == CreditState::Retained);
        let has_held = enrollment
            .effects
            .iter()
            .any(|effect| self.effects[effect].credit_state == CreditState::Held);
        let has_live_enrolled = enrollment
            .effects
            .iter()
            .any(|effect| !self.effects[effect].phase.is_terminal());
        if has_retained
            && root.batch_sequence.is_some()
            && root.reset_tombstone.is_none()
            && root.iotlb_tombstone.is_none()
        {
            return Err(RegistryError::Invariant(
                "retained published credits lack timeout tombstone",
            ));
        }
        if root.batch_sequence.is_none()
            && ((has_retained && root.outcome != Some(DeviceClosureResult::AbortedBeforeCommit))
                || (root.outcome == Some(DeviceClosureResult::AbortedBeforeCommit)
                    && has_live_enrolled
                    && (self.scopes[&scope_key].phase != ScopePhase::Closing || has_held)))
        {
            return Err(RegistryError::Invariant(
                "retained unpublished credits lack uniform closing precommit abort",
            ));
        }
        Ok(())
    }

    fn validate_portal(
        &self,
        sender: TaskKey,
        handle: PortalHandle,
    ) -> Result<EffectKey, RegistryError> {
        let scope = self
            .scopes
            .get(&handle.scope)
            .ok_or(RegistryError::UnknownScope)?;
        map_handoff_gate(scope.handoff_gate.require_open())?;
        if handle.authority_epoch != scope.authority_epoch {
            return Err(RegistryError::StaleAuthority);
        }
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        let record = self
            .effects
            .get(&handle.effect)
            .ok_or(RegistryError::UnknownEffect)?;
        if record.identity.scope != handle.scope || record.identity.domain != handle.domain {
            return Err(RegistryError::InvalidHandle);
        }
        let binding = scope
            .domains
            .get(&handle.domain)
            .ok_or(RegistryError::UnknownDomain)?;
        if binding.quarantine.is_some() {
            return Err(RegistryError::DomainQuarantined);
        }
        if handle.binding_epoch != binding.binding_epoch
            || record.identity.binding_epoch != handle.binding_epoch
        {
            return Err(RegistryError::StaleBinding);
        }
        if record.nonce != handle.nonce {
            return Err(RegistryError::InvalidHandle);
        }
        if binding.supervisor != Some(sender) || binding.fallback_running {
            return Err(RegistryError::NoSupervisor);
        }
        Ok(handle.effect)
    }

    fn validate_kernel_root_authority(
        &self,
        authority: KernelRootAuthority,
    ) -> Result<(), RegistryError> {
        self.require_unique_device_publication()?;
        if authority.registry_instance_id != self.instance_id {
            return Err(RegistryError::InvalidBatchReceipt);
        }
        let scope = self
            .scopes
            .get(&authority.scope)
            .ok_or(RegistryError::UnknownScope)?;
        map_handoff_gate(scope.handoff_gate.require_open())?;
        if authority.authority_epoch != scope.authority_epoch {
            return Err(RegistryError::StaleAuthority);
        }
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        if scope.supervisor != Some(authority.owner) || scope.fallback_running {
            return Err(RegistryError::NoSupervisor);
        }
        Ok(())
    }

    fn validate_root_portal(
        &self,
        authority: KernelRootAuthority,
        handle: PortalHandle,
    ) -> Result<EffectKey, RegistryError> {
        if handle.scope != authority.scope {
            return Err(RegistryError::InvalidHandle);
        }
        if handle.authority_epoch != authority.authority_epoch {
            return Err(RegistryError::StaleAuthority);
        }
        let record = self
            .effects
            .get(&handle.effect)
            .ok_or(RegistryError::UnknownEffect)?;
        if record.identity.scope != authority.scope
            || record.identity.domain != handle.domain
            || record.identity.authority_epoch != authority.authority_epoch
            || record.nonce != handle.nonce
        {
            return Err(RegistryError::InvalidHandle);
        }
        let scope = self
            .scopes
            .get(&authority.scope)
            .ok_or(RegistryError::UnknownScope)?;
        let binding = scope
            .domains
            .get(&handle.domain)
            .ok_or(RegistryError::UnknownDomain)?;
        if binding.quarantine.is_some() {
            return Err(RegistryError::DomainQuarantined);
        }
        if handle.binding_epoch != binding.binding_epoch
            || record.identity.binding_epoch != handle.binding_epoch
        {
            return Err(RegistryError::StaleBinding);
        }
        if binding.supervisor.is_none() || binding.fallback_running {
            return Err(RegistryError::NoSupervisor);
        }
        Ok(handle.effect)
    }

    fn stage_terminal_inner(
        &mut self,
        effect: EffectKey,
        request: TerminalRequest,
        authorized_device_enrollment: Option<u64>,
    ) -> Result<Terminalization, RegistryError> {
        let (
            phase,
            own_commit,
            recorded_outcome,
            scope_key,
            identity,
            current_resources,
            charges,
            credit_state,
            publication_mode,
            device_batch,
        ) = {
            let record = self
                .effects
                .get(&effect)
                .ok_or(RegistryError::UnknownEffect)?;
            (
                record.phase,
                record.commit.clone(),
                record.outcome,
                record.identity.scope,
                record.identity.clone(),
                record.current_resources.clone(),
                record.credits.clone(),
                record.credit_state,
                record.publication_mode,
                record.device_batch,
            )
        };
        if let Some(root) = self.scopes[&scope_key].device_root.as_ref() {
            let Some(enrollment) = root.enrollment.as_ref() else {
                return Err(RegistryError::DeviceClosurePending);
            };
            if enrollment.effects.contains(&effect)
                && authorized_device_enrollment != Some(enrollment.enrollment_sequence)
            {
                return Err(RegistryError::DeviceClosurePending);
            }
        }
        if phase.is_terminal() {
            return Err(RegistryError::AlreadyTerminal);
        }
        if self
            .production
            .children_by_parent
            .get(&effect)
            .is_some_and(|children| !children.is_empty())
        {
            return Err(RegistryError::LiveDescendants);
        }
        match request.outcome {
            TerminalOutcome::Aborted => {
                if own_commit.is_some() || request.causal_commit.is_some() {
                    return Err(RegistryError::InvalidState);
                }
            }
            TerminalOutcome::Completed => {
                if own_commit.is_none() && request.causal_commit.is_none() {
                    return Err(RegistryError::InvalidState);
                }
                if request.causal_commit.as_ref().is_some_and(|causal| {
                    !causal_commit_matches(self.instance_id, &self.effects, &identity, causal)
                }) {
                    return Err(RegistryError::CommitConflict);
                }
                if self.effects[&effect].outcome_required && recorded_outcome.is_none() {
                    return Err(RegistryError::InvalidState);
                }
                if let Some(outcome) = recorded_outcome
                    && (outcome.class() == EffectOutcomeClass::Indeterminate
                        || outcome.result() != request.result)
                {
                    return Err(RegistryError::CommitConflict);
                }
            }
            TerminalOutcome::IndeterminateAfterReset => {
                if own_commit.is_none() || device_batch.is_none() || request.causal_commit.is_some()
                {
                    return Err(RegistryError::InvalidState);
                }
                if let Some(outcome) = recorded_outcome
                    && (outcome.class() != EffectOutcomeClass::Indeterminate
                        || outcome.result() != request.result)
                {
                    return Err(RegistryError::CommitConflict);
                }
            }
        }
        let terminal_sequence = self.next_terminal_sequence;
        let next_terminal_sequence = terminal_sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let (ticket_sequence, next_publication_sequence) =
            if publication_mode == PublicationMode::Required {
                let ticket_sequence = self.next_publication_sequence;
                let next = ticket_sequence
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
                (Some(ticket_sequence), Some(next))
            } else {
                (None, None)
            };
        let (
            next_scope_revision,
            next_pending_publications,
            next_terminalized,
            next_target_index_removals,
        ) = {
            let scope = self
                .scopes
                .get(&scope_key)
                .ok_or(RegistryError::UnknownScope)?;
            let revision = scope
                .revision
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
            let pending = if publication_mode == PublicationMode::Required {
                scope
                    .pending_publications
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?
            } else {
                scope.pending_publications
            };
            match scope.phase {
                ScopePhase::Active => (revision, pending, None, None),
                ScopePhase::Closing => {
                    let revoke = scope
                        .revoke
                        .as_ref()
                        .ok_or(RegistryError::InvalidRevokeSelection)?;
                    if !revoke.cohort.contains(&effect) {
                        return Err(RegistryError::InvalidRevokeSelection);
                    }
                    let terminalized = revoke
                        .work
                        .terminalized
                        .checked_add(1)
                        .ok_or(RegistryError::CounterOverflow)?;
                    let removals = revoke
                        .work
                        .target_index_removals
                        .checked_add(1)
                        .ok_or(RegistryError::CounterOverflow)?;
                    (revision, pending, Some(terminalized), Some(removals))
                }
                ScopePhase::Revoked => return Err(RegistryError::InvalidState),
            }
        };
        let terminal = TerminalReceipt {
            effect,
            outcome: request.outcome,
            result: request.result,
            sequence: terminal_sequence,
            causal_commit: request.causal_commit,
            manifest_digest: request.manifest_digest,
        };
        let ticket = ticket_sequence.map(|ticket_sequence| PublicationTicket {
            effect,
            scope: scope_key,
            terminal_sequence: terminal.sequence,
            ticket_sequence,
            outcome: terminal.outcome,
            result: terminal.result,
        });

        // Credit release is the last validation that can still return an
        // error. Its first pass is non-mutating; after success all remaining
        // closure updates are infallible under the registry invariants.
        if ticket.is_none() {
            self.scopes
                .get_mut(&scope_key)
                .unwrap()
                .credits
                .release(&charges, credit_state)?;
        }
        self.next_terminal_sequence = next_terminal_sequence;
        if let Some(next) = next_publication_sequence {
            self.next_publication_sequence = next;
        }
        self.remove_reverse_indexes(&identity, &current_resources);
        let record = self.effects.get_mut(&effect).unwrap();
        record.phase = EffectPhase::Terminal(terminal.outcome);
        record.terminal = Some(terminal.clone());
        record.pending_publication = ticket.clone();
        record.terminalizations = 1;
        if ticket.is_none() {
            record.credit_state = CreditState::Released;
        }
        let scope = self.scopes.get_mut(&scope_key).unwrap();
        if let Some(recovery) = scope.recovery.as_mut() {
            recovery.unadopted.remove(&effect);
            recovery.cohort.remove(&effect);
        }
        if let Some(recovery) = scope
            .domains
            .get_mut(&identity.domain)
            .and_then(|binding| binding.recovery.as_mut())
        {
            recovery.unadopted.remove(&effect);
        }
        scope.revision = next_scope_revision;
        scope.pending_publications = next_pending_publications;
        if ticket.is_none() {
            __cser_core::assert!(
                scope.handoff_candidates.remove(&effect),
                "terminal effect without publication must leave the handoff index"
            );
        }
        scope.invalidate_recovery_readiness();
        if let (Some(terminalized), Some(removals)) =
            (next_terminalized, next_target_index_removals)
        {
            let revoke = scope.revoke.as_mut().unwrap();
            revoke.work.terminalized = terminalized;
            revoke.work.target_index_removals = removals;
            if revoke.selected_head == Some(effect) {
                revoke.selected_head = None;
            }
        }
        Ok(Terminalization {
            receipt: terminal,
            publication: ticket,
        })
    }

    fn validate_revoke_selection(&self, selection: &RevokeSelection) -> Result<(), RegistryError> {
        let scope = self
            .scopes
            .get(&selection.scope)
            .ok_or(RegistryError::UnknownScope)?;
        let revoke = scope
            .revoke
            .as_ref()
            .ok_or(RegistryError::InvalidRevokeSelection)?;
        if scope.phase != ScopePhase::Closing
            || revoke.sequence != selection.sequence
            || revoke.closed_authority_epoch != selection.closed_authority_epoch
            || revoke.authority_epoch != selection.authority_epoch
            || revoke.target_count != selection.target_count
            || scope.authority_epoch != selection.authority_epoch
        {
            return Err(RegistryError::InvalidRevokeSelection);
        }
        Ok(())
    }

    fn insert_reverse_indexes(
        &mut self,
        identity: &EffectIdentity,
        current_resources: &BTreeSet<ResourceKey>,
    ) {
        self.by_scope
            .entry(identity.scope)
            .or_default()
            .insert(identity.effect);
        self.production
            .by_domain
            .entry((identity.scope, identity.domain))
            .or_default()
            .insert(identity.effect);
        self.by_task
            .entry(identity.task)
            .or_default()
            .insert(identity.effect);
        for resource in current_resources {
            self.by_resource
                .entry(*resource)
                .or_default()
                .insert(identity.effect);
        }
        __cser_core::assert!(
            self.scopes
                .get_mut(&identity.scope)
                .expect("effect scope must exist before reverse-index insertion")
                .closure_candidates
                .insert(identity.effect),
            "effect must be new to the closure candidate index"
        );
        __cser_core::assert!(
            self.scopes
                .get_mut(&identity.scope)
                .expect("effect scope must exist before handoff-index insertion")
                .handoff_candidates
                .insert(identity.effect),
            "effect must be new to the handoff candidate index"
        );
        if let Some(parent) = identity.parent {
            let children = self
                .production
                .children_by_parent
                .entry(parent)
                .or_default();
            let was_leaf = children.is_empty();
            __cser_core::assert!(
                children.insert(identity.effect),
                "derived effect must be new to its parent index"
            );
            if was_leaf {
                remove_index_member(&mut self.production.leaves_by_scope, identity.scope, parent);
            }
        }
        __cser_core::assert!(
            self.production
                .leaves_by_scope
                .entry(identity.scope)
                .or_default()
                .insert(identity.effect),
            "new effect must be a new live leaf"
        );
    }

    fn remove_reverse_indexes(
        &mut self,
        identity: &EffectIdentity,
        current_resources: &BTreeSet<ResourceKey>,
    ) {
        remove_index_member(&mut self.by_scope, identity.scope, identity.effect);
        remove_index_member(
            &mut self.production.by_domain,
            (identity.scope, identity.domain),
            identity.effect,
        );
        remove_index_member(&mut self.by_task, identity.task, identity.effect);
        for resource in current_resources {
            remove_index_member(&mut self.by_resource, *resource, identity.effect);
        }
        remove_index_member(
            &mut self.production.leaves_by_scope,
            identity.scope,
            identity.effect,
        );
        if let Some(parent) = identity.parent {
            remove_index_member(
                &mut self.production.children_by_parent,
                parent,
                identity.effect,
            );
            if !self.production.children_by_parent.contains_key(&parent) {
                let parent_record = self
                    .effects
                    .get(&parent)
                    .expect("live child must reference a known parent");
                __cser_core::assert!(
                    !parent_record.phase.is_terminal(),
                    "a live child cannot outlive its parent"
                );
                __cser_core::assert!(
                    self.production
                        .leaves_by_scope
                        .entry(identity.scope)
                        .or_default()
                        .insert(parent),
                    "parent must become a unique leaf after its last child closes"
                );
            }
        }
        let scope = self
            .scopes
            .get_mut(&identity.scope)
            .expect("effect scope must exist during reverse-index removal");
        match scope.phase {
            ScopePhase::Active => __cser_core::assert!(
                scope.closure_candidates.remove(&identity.effect),
                "active effect must exist in the closure candidate index"
            ),
            ScopePhase::Closing => __cser_core::assert!(
                scope
                    .revoke
                    .as_ref()
                    .is_some_and(|revoke| revoke.cohort.contains(&identity.effect)),
                "closing effect must remain in the frozen revoke cohort"
            ),
            ScopePhase::Revoked => __cser_core::panic!("revoked scope cannot retain a live effect"),
        }
    }

    fn insert_resource_indexes(
        &mut self,
        effect: EffectKey,
        current_resources: &BTreeSet<ResourceKey>,
    ) {
        for resource in current_resources {
            self.by_resource
                .entry(*resource)
                .or_default()
                .insert(effect);
        }
    }

    fn remove_resource_indexes(
        &mut self,
        effect: EffectKey,
        current_resources: &BTreeSet<ResourceKey>,
    ) {
        for resource in current_resources {
            remove_index_member(&mut self.by_resource, *resource, effect);
        }
    }

    fn take_effect_id(&mut self) -> Result<u64, RegistryError> {
        take_counter(&mut self.next_effect_id)
    }

    fn take_nonce(&mut self) -> Result<u64, RegistryError> {
        take_counter(&mut self.next_nonce)
    }

    fn take_commit_sequence(&mut self) -> Result<u64, RegistryError> {
        take_counter(&mut self.next_commit_sequence)
    }

    fn take_terminal_sequence(&mut self) -> Result<u64, RegistryError> {
        take_counter(&mut self.next_terminal_sequence)
    }

    fn take_publication_sequence(&mut self) -> Result<u64, RegistryError> {
        take_counter(&mut self.next_publication_sequence)
    }

    fn take_revoke_sequence(&mut self) -> Result<u64, RegistryError> {
        take_counter(&mut self.next_revoke_sequence)
    }
}

fn validate_prepared_device_cohort_entries(
    description: infrastructure::PreparedDeviceDescription,
    prepared: infrastructure::PreparedDeviceIdentity,
    entries: [DeviceDerivedCohortEntry; 4],
) -> Result<[DeviceDerivedCohortEntry; 4], RegistryError> {
    let mut slots = [None, None, None, None];
    for entry in entries {
        let index = entry.batch_index;
        if index >= slots.len() || slots[index].is_some() {
            return Err(RegistryError::InvalidState);
        }
        slots[index] = Some(entry);
    }
    let [Some(block), Some(dma_a), Some(dma_b), Some(dma_request)] = slots else {
        return Err(RegistryError::InvalidState);
    };
    let entries = [block, dma_a, dma_b, dma_request];
    let coordinates = description.coordinates;
    if description.prepared != prepared
        || prepared.preparation_id != coordinates.preparation_id
        || prepared.preparation_generation != coordinates.generation
        || prepared.owned_device != coordinates.owned_device
        || prepared.operation_digest != coordinates.operation_digest
        || prepared.actor_slot != coordinates.actor_slot
        || prepared.actor_generation != coordinates.actor_generation
        || prepared.device != description.prepared.device
        || prepared.hardware_receipt_digest == 0
    {
        return Err(RegistryError::InvalidHandle);
    }
    if entries[0].parent != DeviceCohortParent::Existing(description.parent_effect)
        || entries[1..]
            .iter()
            .any(|entry| entry.parent != DeviceCohortParent::BatchIndex(0))
    {
        return Err(RegistryError::InvalidState);
    }
    let domain = entries[0].domain;
    let task = entries[0].request.task;
    for entry in &entries {
        if entry.request.scope != description.scope
            || entry.device != prepared.device
            || entry.domain != domain
            || entry.request.task != task
            || entry.request.publication != PublicationMode::None
        {
            return Err(RegistryError::InvalidState);
        }
    }
    if entries[0].request.descriptor.digest() != prepared.operation_digest
        || entries[0]
            .request
            .resources
            .iter()
            .filter(|resource| **resource == prepared.owned_device)
            .count()
            != 1
    {
        return Err(RegistryError::InvalidHandle);
    }
    if entries[0].request.credits.as_slice()
        != [CreditCharge::new(coordinates.queue_credit_class, 1)]
    {
        return Err(RegistryError::InvalidState);
    }
    let expected_dma = [
        CreditCharge::new(coordinates.pinned_credit_class, 1),
        CreditCharge::new(coordinates.dma_credit_class, 1),
    ];
    for entry in &entries[1..] {
        let credits = entry.request.credits.as_slice();
        if credits.len() != 2
            || !expected_dma
                .iter()
                .all(|expected| credits.contains(expected))
        {
            return Err(RegistryError::InvalidState);
        }
    }
    Ok(entries)
}

fn device_cohort_identity(
    prepared: infrastructure::PreparedDeviceIdentity,
    registered: &[RegisteredEffect; 4],
) -> infrastructure::DeviceCohortIdentity {
    let effects = registered.each_ref().map(|effect| effect.identity.effect());
    infrastructure::DeviceCohortIdentity {
        block: effects[0],
        dma: [effects[1], effects[2], effects[3]],
        digest: device_cohort_digest(prepared, effects),
    }
}

fn device_cohort_digest(
    prepared: infrastructure::PreparedDeviceIdentity,
    effects: [EffectKey; 4],
) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for word in [
        prepared.preparation_id,
        prepared.preparation_generation,
        u64::from(prepared.owned_device.namespace()),
        prepared.owned_device.id(),
        prepared.owned_device.generation(),
        prepared.device.device_session(),
        u64::from(prepared.device.queue()),
        u64::from(prepared.device.descriptor_token()),
        prepared.device.device_generation(),
        prepared.operation_digest,
        u64::from(prepared.actor_slot),
        prepared.actor_generation,
        prepared.hardware_receipt_digest,
    ] {
        digest = digest_handoff_word(digest, word);
    }
    for effect in effects {
        digest = digest_handoff_word(digest, effect.id());
        digest = digest_handoff_word(digest, effect.generation());
    }
    nonzero_digest(digest)
}

fn validate_generation(generation: u64) -> Result<(), RegistryError> {
    if generation == 0 {
        Err(RegistryError::InvalidGeneration)
    } else {
        Ok(())
    }
}

fn map_handoff_gate(result: Result<(), HandoffGateError>) -> Result<(), RegistryError> {
    result.map_err(|error| match error {
        HandoffGateError::AdmissionFrozen => RegistryError::HandoffAdmissionFrozen,
        HandoffGateError::CounterOverflow => RegistryError::CounterOverflow,
        HandoffGateError::InvalidIdentity
        | HandoffGateError::AdmissionOpen
        | HandoffGateError::ReceiptMismatch
        | HandoffGateError::StaleDecision
        | HandoffGateError::ConflictingDecision => RegistryError::InvalidHandoffReceipt,
    })
}

fn map_handoff_decision(
    result: Result<OwnershipDecision, HandoffGateError>,
) -> Result<OwnershipDecision, RegistryError> {
    result.map_err(|error| match error {
        HandoffGateError::AdmissionFrozen => RegistryError::HandoffAdmissionFrozen,
        HandoffGateError::CounterOverflow => RegistryError::CounterOverflow,
        HandoffGateError::InvalidIdentity
        | HandoffGateError::AdmissionOpen
        | HandoffGateError::ReceiptMismatch
        | HandoffGateError::StaleDecision
        | HandoffGateError::ConflictingDecision => RegistryError::InvalidHandoffReceipt,
    })
}

fn handoff_readiness(
    cohort: &BTreeSet<EffectKey>,
    effects: &BTreeMap<EffectKey, EffectRecord>,
) -> Result<HandoffFreezeReadiness, RegistryError> {
    let mut needs_abort = false;
    let mut publication_pending = false;
    for effect in cohort {
        let record = effects.get(effect).ok_or(RegistryError::UnknownEffect)?;
        if record.credit_state == CreditState::Retained {
            return Ok(HandoffFreezeReadiness::BlockedRetained);
        }
        if record.pending_publication.is_some() {
            publication_pending = true;
        }
        if __cser_core::matches!(
            record.phase,
            EffectPhase::Registered | EffectPhase::Prepared
        ) {
            needs_abort = true;
        }
    }
    Ok(if publication_pending {
        HandoffFreezeReadiness::PublicationPending
    } else if needs_abort {
        HandoffFreezeReadiness::NeedsAbort
    } else {
        HandoffFreezeReadiness::ReadyToCommit
    })
}

fn handoff_cohort_digests(
    cohort: &BTreeSet<EffectKey>,
    effects: &BTreeMap<EffectKey, EffectRecord>,
) -> Result<(u64, u64), RegistryError> {
    let mut cohort_digest = 0xcbf2_9ce4_8422_2325_u64;
    let mut classification_digest = 0x8422_2325_cbf2_9ce4_u64;
    for effect in cohort {
        cohort_digest = digest_handoff_word(cohort_digest, effect.id);
        cohort_digest = digest_handoff_word(cohort_digest, effect.generation);
        let record = effects.get(effect).ok_or(RegistryError::UnknownEffect)?;
        classification_digest = digest_handoff_word(classification_digest, effect.id);
        classification_digest = digest_handoff_word(classification_digest, effect.generation);
        classification_digest = digest_handoff_word(
            classification_digest,
            u64::from(record.identity.domain.value()),
        );
        let phase = match record.phase {
            EffectPhase::Registered => 1,
            EffectPhase::Prepared => 2,
            EffectPhase::Committed => 3,
            EffectPhase::Terminal(TerminalOutcome::Completed) => 4,
            EffectPhase::Terminal(TerminalOutcome::IndeterminateAfterReset) => 5,
            EffectPhase::Terminal(TerminalOutcome::Aborted) => 6,
        };
        classification_digest = digest_handoff_word(classification_digest, phase);
        let credit = match record.credit_state {
            CreditState::Held => 1,
            CreditState::Committed => 2,
            CreditState::Retained => 3,
            CreditState::Released => 4,
        };
        classification_digest = digest_handoff_word(classification_digest, credit);
        classification_digest = digest_handoff_word(
            classification_digest,
            record.commit.as_ref().map_or(0, CommitReceipt::sequence),
        );
        classification_digest = digest_handoff_word(
            classification_digest,
            record
                .pending_publication
                .as_ref()
                .map_or(0, |ticket| ticket.ticket_sequence),
        );
    }
    Ok((
        nonzero_digest(cohort_digest),
        nonzero_digest(classification_digest),
    ))
}

fn handoff_terminal_manifest_digest(
    cohort: &BTreeSet<EffectKey>,
    effects: &BTreeMap<EffectKey, EffectRecord>,
) -> Result<u64, RegistryError> {
    let mut digest = 0x9e37_79b9_7f4a_7c15_u64;
    for effect in cohort {
        let record = effects.get(effect).ok_or(RegistryError::UnknownEffect)?;
        let terminal = record
            .terminal
            .as_ref()
            .ok_or(RegistryError::NotQuiescent)?;
        if record.pending_publication.is_some() || record.credit_state != CreditState::Released {
            return Err(RegistryError::NotQuiescent);
        }
        digest = digest_handoff_word(digest, effect.id);
        digest = digest_handoff_word(digest, effect.generation);
        digest = digest_handoff_word(digest, terminal.sequence);
        digest = digest_handoff_word(
            digest,
            match terminal.outcome {
                TerminalOutcome::Completed => 1,
                TerminalOutcome::IndeterminateAfterReset => 2,
                TerminalOutcome::Aborted => 3,
            },
        );
        digest = digest_handoff_word(digest, u64::from(record.publication_acks));
    }
    Ok(nonzero_digest(digest))
}

const fn digest_handoff_word(state: u64, value: u64) -> u64 {
    (state ^ value).wrapping_mul(0x0000_0100_0000_01b3)
}

const fn nonzero_digest(value: u64) -> u64 {
    if value == 0 { 1 } else { value }
}

fn device_envelope_mismatch(expected: DeviceEnvelope, presented: DeviceEnvelope) -> RegistryError {
    if expected.same_device_except_generation(presented)
        && expected.device_generation != presented.device_generation
    {
        RegistryError::StaleDeviceGeneration
    } else {
        RegistryError::InvalidBatchReceipt
    }
}

/// Authenticates an explicit completion cause against the exact commit stored
/// by this Registry. Cross-effect completion is allowed only inside one scope
/// causal envelope. Binding epochs are ordered only inside one independently
/// restartable domain; cross-domain causality is fenced by the shared root
/// authority epoch and authenticated source receipt instead.
fn causal_commit_matches(
    registry_instance_id: u64,
    effects: &BTreeMap<EffectKey, EffectRecord>,
    target: &EffectIdentity,
    causal: &CommitReceipt,
) -> bool {
    if causal.registry_instance_id != registry_instance_id
        || causal.scope != target.scope
        || causal.authority_epoch != target.authority_epoch
    {
        return false;
    }
    effects.get(&causal.effect).is_some_and(|source| {
        source.identity.scope == target.scope
            && (source.identity.domain != target.domain
                || causal.binding_epoch <= target.binding_epoch)
            && source.commit.as_ref() == Some(causal)
            && __cser_core::matches!(
                source.phase,
                EffectPhase::Committed
                    | EffectPhase::Terminal(TerminalOutcome::Completed)
                    | EffectPhase::Terminal(TerminalOutcome::IndeterminateAfterReset)
            )
    })
}

fn next_registry_instance_id() -> u64 {
    NEXT_REGISTRY_INSTANCE_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .expect("EffectRegistry instance namespace exhausted")
}

fn normalize_charges(charges: &[CreditCharge]) -> Result<Vec<CreditCharge>, RegistryError> {
    let mut totals = BTreeMap::<CreditClass, u64>::new();
    for charge in charges {
        if charge.units == 0 {
            return Err(RegistryError::InvalidCreditConfiguration);
        }
        let total = totals.entry(charge.class).or_default();
        *total = total
            .checked_add(charge.units)
            .ok_or(RegistryError::CounterOverflow)?;
    }
    Ok(totals
        .into_iter()
        .map(|(class, units)| CreditCharge { class, units })
        .collect())
}

fn take_counter(counter: &mut u64) -> Result<u64, RegistryError> {
    let value = *counter;
    *counter = counter
        .checked_add(1)
        .ok_or(RegistryError::CounterOverflow)?;
    Ok(value)
}

/// Returns one effect record through the revoke evaluator's instrumented
/// access boundary. Target records are expected during normal selection and
/// completion. Any access to a target during begin, to another live scope, or
/// to retained terminal history is counted on the exact revoke token that
/// performed it instead of being inferred as zero by the projection layer.
fn instrument_revoke_record_access<'a>(
    work: &mut RevokeWorkCounters,
    cohort: &BTreeSet<EffectKey>,
    effects: &'a BTreeMap<EffectKey, EffectRecord>,
    target_scope: ScopeKey,
    effect: EffectKey,
    access: RevokeRecordAccess,
) -> Result<&'a EffectRecord, RegistryError> {
    let record = effects.get(&effect).ok_or(RegistryError::UnknownEffect)?;
    let counter = if record.identity.scope == target_scope && cohort.contains(&effect) {
        (access == RevokeRecordAccess::Begin).then_some(&mut work.begin_target_record_visits)
    } else if record.phase.is_terminal() {
        Some(&mut work.history_effect_visits)
    } else {
        Some(&mut work.unrelated_effect_visits)
    };
    if let Some(counter) = counter {
        *counter = counter
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
    }
    Ok(record)
}

fn remove_index_member<K: Ord + Copy>(
    index: &mut BTreeMap<K, BTreeSet<EffectKey>>,
    key: K,
    effect: EffectKey,
) {
    let remove_entry = if let Some(members) = index.get_mut(&key) {
        __cser_core::assert!(
            members.remove(&effect),
            "effect must exist in every reverse index"
        );
        members.is_empty()
    } else {
        __cser_core::panic!("effect reverse index is missing");
    };
    if remove_entry {
        index.remove(&key);
    }
}

fn add_expected_credits(
    expected: &mut BTreeMap<ScopeKey, BTreeMap<CreditClass, (u64, u64, u64)>>,
    scope: ScopeKey,
    charges: &[CreditCharge],
    state: CreditState,
) -> Result<(), RegistryError> {
    for charge in charges {
        let entry = expected
            .entry(scope)
            .or_default()
            .entry(charge.class)
            .or_insert((0, 0, 0));
        let counter = match state {
            CreditState::Held => &mut entry.0,
            CreditState::Committed => &mut entry.1,
            CreditState::Retained => &mut entry.2,
            CreditState::Released => return Err(RegistryError::InvalidState),
        };
        *counter = counter
            .checked_add(charge.units)
            .ok_or(RegistryError::CounterOverflow)?;
    }
    Ok(())
}
