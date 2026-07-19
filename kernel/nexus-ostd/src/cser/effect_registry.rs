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

#[path = "effect_registry/root_lanes.rs"]
mod root_lanes;

#[path = "infrastructure/mod.rs"]
mod infrastructure;

static NEXT_REGISTRY_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

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

    fn digest(self) -> u64 {
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
    pub(crate) scope: ScopeKey,
    pub(crate) domain: DomainKey,
    pub(crate) replacement: TaskKey,
    pub(crate) authority_epoch: u64,
    pub(crate) binding_epoch: u64,
    pub(crate) root_revision: u64,
    pub(crate) domain_revision: u64,
    pub(crate) effects: Vec<RecoveryEffectSummary>,
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
    RecoveryNotReady,
    NotAdoptable,
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
        let keys = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?
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
            if let Some(record) = self.effects.get_mut(&key) {
                *record = replacement;
            }
        }
        if let Some(scope) = self.scopes.get_mut(&scope_key) {
            *scope = replacement_scope;
        }
        self.next_terminal_sequence = candidate.next_terminal_sequence;
        self.next_publication_sequence = candidate.next_publication_sequence;
        self.next_revoke_sequence = candidate.next_revoke_sequence;
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
    /// before/after checks, with only the allocator-assigned registry
    /// namespace normalized.
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
        normalized.rewrite_registry_instance(NORMALIZED_REGISTRY_INSTANCE);
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
        self.instance_id = registry_instance_id;
        self.infrastructure
            .rewrite_private_registry_instance(registry_instance_id);
        for scope in self.scopes.values_mut() {
            if let Some(device_root) = scope.device_root.as_mut() {
                device_root.rewrite_registry_instance(registry_instance_id);
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

        self.scopes
            .get_mut(&request.scope)
            .unwrap()
            .credits
            .reserve(&credits)?;
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
        });
        scope.invalidate_recovery_readiness();
        Ok(DomainCrashReceipt {
            scope: scope_key,
            domain,
            previous_binding_epoch,
            binding_epoch,
            cohort,
        })
    }

    pub(crate) fn domain_recovery_snapshot(
        &mut self,
        scope_key: ScopeKey,
        domain: DomainKey,
        replacement: TaskKey,
    ) -> Result<DomainRecoverySnapshot, RegistryError> {
        validate_generation(replacement.generation)?;
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
        if !binding.fallback_running || binding.supervisor.is_some() {
            return Err(RegistryError::InvalidState);
        }
        let recovery = binding
            .recovery
            .as_ref()
            .ok_or(RegistryError::InvalidState)?;
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
        let snapshot = DomainRecoverySnapshot {
            scope: scope_key,
            domain,
            replacement,
            authority_epoch: scope.authority_epoch,
            binding_epoch: binding.binding_epoch,
            root_revision: scope.revision,
            domain_revision: binding.revision,
            effects,
        };
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
            || recovery.crash_revision > snapshot.domain_revision
        {
            return Err(RegistryError::SnapshotChanged);
        }
        recovery.ready = Some(replacement);
        Ok(())
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
        let revoke = self.prepare_revoke_complete_apply(selection, Some(&publication))?;
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
            let retained = state.cohort.iter().any(|effect| {
                self.effects
                    .get(effect)
                    .is_some_and(|record| record.credit_state == CreditState::Retained)
            });
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
        let closure = ProductionHandoffClosureReceipt {
            freeze,
            decision,
            revoke: selection,
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
        let state = self
            .scopes
            .get(&scope_key)
            .ok_or(RegistryError::UnknownScope)?
            .handoff
            .as_ref()
            .ok_or(RegistryError::InvalidHandoffReceipt)?;
        if state.closure.as_ref() != Some(receipt) {
            return Err(RegistryError::InvalidHandoffReceipt);
        }
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
        })
    }

    fn apply_revoke_begin(&mut self, plan: RevokeBeginPlan) -> RevokeSelection {
        let RevokeBeginPlan {
            selection,
            next_revoke_sequence,
            next_scope_revision,
        } = plan;

        // All validation and overflow checks precede this point. Moving the
        // two indexes is allocation-free and does not visit any target record.
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
        let plan = self.prepare_revoke_complete_apply(selection, None)?;
        self.apply_revoke_complete(plan);
        Ok(())
    }

    fn prepare_revoke_complete_apply(
        &self,
        selection: &RevokeSelection,
        publication: Option<&PublicationAckApplyPlan>,
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

        Ok(RevokeCompleteApplyPlan {
            scope: selection.scope,
            next_scope_revision,
            work: projected_work,
        })
    }

    fn apply_revoke_complete(&mut self, plan: RevokeCompleteApplyPlan) {
        let RevokeCompleteApplyPlan {
            scope,
            next_scope_revision,
            work,
        } = plan;
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
                        if binding.fallback_running == binding.supervisor.is_some() {
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
                if let Some(recovery) = &binding.recovery {
                    if scope.phase != ScopePhase::Active
                        || recovery.crash_revision > binding.revision
                        || !recovery.unadopted.is_subset(&recovery.cohort)
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
                            || record.phase.is_terminal()
                            || record.identity.binding_epoch > binding.binding_epoch
                        {
                            return Err(RegistryError::Invariant("invalid domain recovery cohort"));
                        }
                    }
                    for effect in &recovery.unadopted {
                        if self.effects[effect].identity.binding_epoch >= binding.binding_epoch {
                            return Err(RegistryError::Invariant(
                                "invalid unadopted domain effect",
                            ));
                        }
                    }
                    if let Some(snapshot) = &recovery.snapshot
                        && (snapshot.scope != *key
                            || snapshot.domain != *domain
                            || snapshot.authority_epoch != scope.authority_epoch
                            || snapshot.binding_epoch != binding.binding_epoch
                            || snapshot.root_revision > scope.revision
                            || snapshot.domain_revision > binding.revision)
                    {
                        return Err(RegistryError::Invariant(
                            "domain recovery snapshot mismatch",
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
                }
            }
            if let Some(revoke) = &scope.revoke {
                let target_count = u64::try_from(revoke.target_count)
                    .map_err(|_| RegistryError::Invariant("revoke target count overflow"))?;
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
                        {
                            return Err(RegistryError::Invariant("invalid completed revoke state"));
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
            recovery.cohort.remove(&effect);
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

/// A production-registry fixture used by the Stage 7B structural and timing
/// evaluators. `n` is the total live population, `k` is the target scope's
/// live population, and `h` is retained terminal history.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct Stage7bFixtureConfig {
    pub(crate) n: usize,
    pub(crate) k: usize,
    pub(crate) h: usize,
}

/// Exact Stage 7B fault-matrix identity.  Credit capacity is frozen here so a
/// fault adapter cannot manufacture a passing ledger from a gate population
/// such as `waiter_count` or `effect_count`.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::Ord,
    __cser_core::cmp::PartialEq,
    __cser_core::cmp::PartialOrd,
)]
pub(crate) enum Stage7bFaultCase {
    SchedulerLeaseExpiryBeforeProposal,
    SchedulerCrashAfterProposalBeforePick,
    SchedulerStaleProposalBeforeRebind,
    SchedulerStaleProposalAfterRebind,
    SchedulerRepeatedCrashFallbackProgress,
    PagerSamePageConcurrentFault,
    PagerCrashBeforePrepare,
    PagerCrashAfterPrepareBeforeCommit,
    PagerCrashAfterCommitBeforeResume,
    PagerTimeoutVsLateReply,
    ReadinessCrashBeforeBackendCommit,
    ReadinessCrashAfterBackendCommit,
    ReadinessReadyVsTimeout,
    ReadinessRevokeVsReady,
    ReadinessStaleDeadlineAfterRearm,
    IoRevokeBeforeDevicePublication,
    IoCompletionVsResetAck,
    IoResetTimeoutRetry,
    IoIotlbTimeoutLateAck,
    IoStaleDuplicateCompletion,
}

impl Stage7bFaultCase {
    pub(crate) const fn tag(self) -> u32 {
        match self {
            Self::SchedulerLeaseExpiryBeforeProposal => 1,
            Self::SchedulerCrashAfterProposalBeforePick => 2,
            Self::SchedulerStaleProposalBeforeRebind => 3,
            Self::SchedulerStaleProposalAfterRebind => 4,
            Self::SchedulerRepeatedCrashFallbackProgress => 5,
            Self::PagerSamePageConcurrentFault => 6,
            Self::PagerCrashBeforePrepare => 7,
            Self::PagerCrashAfterPrepareBeforeCommit => 8,
            Self::PagerCrashAfterCommitBeforeResume => 9,
            Self::PagerTimeoutVsLateReply => 10,
            Self::ReadinessCrashBeforeBackendCommit => 11,
            Self::ReadinessCrashAfterBackendCommit => 12,
            Self::ReadinessReadyVsTimeout => 13,
            Self::ReadinessRevokeVsReady => 14,
            Self::ReadinessStaleDeadlineAfterRearm => 15,
            Self::IoRevokeBeforeDevicePublication => 16,
            Self::IoCompletionVsResetAck => 17,
            Self::IoResetTimeoutRetry => 18,
            Self::IoIotlbTimeoutLateAck => 19,
            Self::IoStaleDuplicateCompletion => 20,
        }
    }

    pub(crate) const fn credit_capacity(self) -> usize {
        match self {
            Self::SchedulerLeaseExpiryBeforeProposal
            | Self::SchedulerCrashAfterProposalBeforePick
            | Self::SchedulerStaleProposalBeforeRebind
            | Self::SchedulerStaleProposalAfterRebind
            | Self::SchedulerRepeatedCrashFallbackProgress => 0,
            Self::PagerSamePageConcurrentFault => 2,
            _ => 1,
        }
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
pub(crate) enum Stage7bFaultOperation {
    SchedulerFallbackPick,
    PagerContinuation,
    ReadinessCompletion,
    IoRequest,
}

impl Stage7bFaultOperation {
    const fn tag(self) -> u32 {
        match self {
            Self::SchedulerFallbackPick => 1,
            Self::PagerContinuation => 2,
            Self::ReadinessCompletion => 3,
            Self::IoRequest => 4,
        }
    }
}

/// The semantic half of a composite credit authority.  The opaque registry
/// handle is held separately in [`Stage7bFaultCredit`]; every commit and
/// terminal transition must present this exact case/operation/identity again.
#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::Ord,
    __cser_core::cmp::PartialEq,
    __cser_core::cmp::PartialOrd,
)]
pub(crate) struct Stage7bFaultBinding {
    case: Stage7bFaultCase,
    operation: Stage7bFaultOperation,
    authority: [u64; 5],
}

impl Stage7bFaultBinding {
    pub(crate) const fn new(
        case: Stage7bFaultCase,
        operation: Stage7bFaultOperation,
        authority: [u64; 5],
    ) -> Self {
        Self {
            case,
            operation,
            authority,
        }
    }

    pub(crate) const fn case(self) -> Stage7bFaultCase {
        self.case
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) enum Stage7bFaultTerminal {
    Aborted(i64),
    Completed(i64),
}

/// Linear pairing of one semantic authority and one opaque production
/// registry handle.  It is intentionally neither `Clone` nor `Copy`.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct Stage7bFaultCredit {
    instance_id: u64,
    binding: Stage7bFaultBinding,
    handle: PortalHandle,
    commit: Option<CommitReceipt>,
    terminalized: bool,
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct Stage7bFaultBudgetProjection {
    pub(crate) case: Stage7bFaultCase,
    pub(crate) instance_id: u64,
    pub(crate) scope: ScopeKey,
    pub(crate) registry: RegistryProjection,
    pub(crate) reservations: usize,
    pub(crate) commit_operations: usize,
    pub(crate) terminal_operations: usize,
}

impl Stage7bFaultBudgetProjection {
    /// Observes live credit ownership before closure and returned credit after
    /// closure. Capacity is checked separately as an invariant; it is not the
    /// fault counter reported by the evaluator.
    pub(crate) fn observed_credit_units(&self) -> Result<usize, RegistryError> {
        let credits = self.registry.credits;
        let units = match self.registry.phase {
            ScopePhase::Active | ScopePhase::Closing => credits
                .held
                .checked_add(credits.committed)
                .and_then(|owned| owned.checked_add(credits.retained))
                .ok_or(RegistryError::CounterOverflow)?,
            ScopePhase::Revoked => credits.free,
        };
        usize::try_from(units).map_err(|_| RegistryError::CounterOverflow)
    }
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct Stage7bFaultBudget {
    case: Stage7bFaultCase,
    instance_id: u64,
    registry: EffectRegistry,
    scope: ScopeKey,
    task: TaskKey,
    credit: CreditClass,
    bindings: BTreeSet<Stage7bFaultBinding>,
    commit_operations: usize,
    terminal_operations: usize,
}

/// Read-only, complete failure-atomicity snapshot of one case-local ledger.
/// Its fields remain private so cloning this value cannot mint usable Registry
/// handles or transition authority.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct Stage7bFaultBudgetState {
    case: Stage7bFaultCase,
    instance_id: u64,
    registry: EffectRegistry,
    scope: ScopeKey,
    task: TaskKey,
    credit: CreditClass,
    bindings: BTreeSet<Stage7bFaultBinding>,
    commit_operations: usize,
    terminal_operations: usize,
}

impl Clone for Stage7bFaultBudgetState {
    fn clone(&self) -> Self {
        Self {
            case: self.case,
            instance_id: self.instance_id,
            registry: self.registry.clone(),
            scope: self.scope,
            task: self.task,
            credit: self.credit,
            bindings: self.bindings.clone(),
            commit_operations: self.commit_operations,
            terminal_operations: self.terminal_operations,
        }
    }
}

impl Stage7bFaultBudget {
    /// Creates one case-local evaluation ledger in a caller-allocated instance
    /// namespace. `instance_id` must be nonzero and unique among simultaneously
    /// live fault budgets whose linear credits could meet.
    pub(crate) fn new(case: Stage7bFaultCase, instance_id: u64) -> Result<Self, RegistryError> {
        let capacity = case.credit_capacity();
        if capacity == 0 || instance_id == 0 {
            return Err(RegistryError::InvalidCreditConfiguration);
        }
        let tag = u64::from(case.tag());
        let scope = ScopeKey::new(instance_id, tag);
        let task = TaskKey::new(instance_id, tag);
        let credit = CreditClass::new(
            u16::try_from(0x7b00_u32 + case.tag()).map_err(|_| RegistryError::CounterOverflow)?,
        );
        let units = u64::try_from(capacity).map_err(|_| RegistryError::CounterOverflow)?;
        let mut registry = EffectRegistry::new();
        registry.create_scope(ScopeConfig {
            key: scope,
            authority_epoch: 1,
            binding_epoch: 1,
            supervisor: task,
            credits: __cser_alloc::vec![CreditLimit::new(credit, units)],
        })?;
        registry.check_invariants()?;
        Ok(Self {
            case,
            instance_id,
            registry,
            scope,
            task,
            credit,
            bindings: BTreeSet::new(),
            commit_operations: 0,
            terminal_operations: 0,
        })
    }

    pub(crate) fn reserve(
        &mut self,
        binding: Stage7bFaultBinding,
    ) -> Result<Stage7bFaultCredit, RegistryError> {
        if binding.case != self.case
            || self.bindings.contains(&binding)
            || self.bindings.len() >= self.case.credit_capacity()
        {
            return Err(RegistryError::InvalidState);
        }
        let ordinal = self.bindings.len();
        let resource_id = u64::try_from(ordinal)
            .map_err(|_| RegistryError::CounterOverflow)?
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        let namespace = 0x7b10_u32
            .checked_add(self.case.tag())
            .ok_or(RegistryError::CounterOverflow)?;
        let operation = binding.operation.tag();
        let registered = self.registry.register(RegisterRequest {
            scope: self.scope,
            task: self.task,
            operation: OperationClass::new(operation),
            descriptor: SyscallDescriptor::new(
                usize::try_from(0x7b10_u32 + self.case.tag())
                    .map_err(|_| RegistryError::CounterOverflow)?,
                [
                    usize::try_from(self.instance_id)
                        .map_err(|_| RegistryError::CounterOverflow)?,
                    usize::try_from(binding.authority[0])
                        .map_err(|_| RegistryError::CounterOverflow)?,
                    usize::try_from(binding.authority[1])
                        .map_err(|_| RegistryError::CounterOverflow)?,
                    usize::try_from(binding.authority[2])
                        .map_err(|_| RegistryError::CounterOverflow)?,
                    usize::try_from(binding.authority[3])
                        .map_err(|_| RegistryError::CounterOverflow)?,
                    usize::try_from(binding.authority[4])
                        .map_err(|_| RegistryError::CounterOverflow)?,
                ],
            ),
            resources: __cser_alloc::vec![ResourceKey::new(namespace, resource_id, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(self.credit, 1)],
            publication: PublicationMode::None,
        })?;
        self.bindings.insert(binding);
        self.registry.check_invariants()?;
        Ok(Stage7bFaultCredit {
            instance_id: self.instance_id,
            binding,
            handle: registered.handle,
            commit: None,
            terminalized: false,
        })
    }

    pub(crate) fn commit(
        &mut self,
        credit: &mut Stage7bFaultCredit,
        binding: Stage7bFaultBinding,
        result: i64,
    ) -> Result<(), RegistryError> {
        self.validate_credit(credit, binding)?;
        if credit.commit.is_some() || credit.terminalized {
            return Err(RegistryError::InvalidState);
        }
        self.registry.prepare(self.task, credit.handle)?;
        let commit = match self.registry.commit(
            self.task,
            credit.handle,
            CommitMetadata::new(result, u64::from(self.case.tag())),
        )? {
            CommitOutcome::Applied(receipt) => receipt,
            CommitOutcome::AlreadyCommitted(_) => return Err(RegistryError::CommitConflict),
        };
        credit.commit = Some(commit);
        self.commit_operations = self
            .commit_operations
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        self.registry.check_invariants()
    }

    pub(crate) fn terminalize(
        &mut self,
        credit: &mut Stage7bFaultCredit,
        binding: Stage7bFaultBinding,
        terminal: Stage7bFaultTerminal,
    ) -> Result<TerminalOutcome, RegistryError> {
        self.validate_credit(credit, binding)?;
        if credit.terminalized {
            return Err(RegistryError::InvalidState);
        }
        let request = match (terminal, credit.commit.clone()) {
            (Stage7bFaultTerminal::Aborted(result), None) => TerminalRequest::aborted(result),
            (Stage7bFaultTerminal::Completed(result), Some(commit)) => {
                TerminalRequest::completed_by(result, commit)
            }
            _ => return Err(RegistryError::InvalidState),
        };
        let terminal = self
            .registry
            .stage_terminal(self.task, credit.handle, request)?;
        if terminal.publication.is_some() {
            return Err(RegistryError::InvalidState);
        }
        credit.terminalized = true;
        self.terminal_operations = self
            .terminal_operations
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        self.registry.check_invariants()?;
        Ok(terminal.receipt.outcome())
    }

    pub(crate) fn projection(&self) -> Result<Stage7bFaultBudgetProjection, RegistryError> {
        Ok(Stage7bFaultBudgetProjection {
            case: self.case,
            instance_id: self.instance_id,
            scope: self.scope,
            registry: self.registry.scope_projection(self.scope)?,
            reservations: self.bindings.len(),
            commit_operations: self.commit_operations,
            terminal_operations: self.terminal_operations,
        })
    }

    pub(crate) fn state_snapshot(&self) -> Stage7bFaultBudgetState {
        Stage7bFaultBudgetState {
            case: self.case,
            instance_id: self.instance_id,
            registry: self.registry.clone(),
            scope: self.scope,
            task: self.task,
            credit: self.credit,
            bindings: self.bindings.clone(),
            commit_operations: self.commit_operations,
            terminal_operations: self.terminal_operations,
        }
    }

    pub(crate) fn finish(&mut self) -> Result<Stage7bFaultBudgetProjection, RegistryError> {
        if self.bindings.len() != self.case.credit_capacity()
            || self.terminal_operations != self.case.credit_capacity()
        {
            return Err(RegistryError::NotQuiescent);
        }
        let active = self.registry.scope_projection(self.scope)?;
        if active.live_effects != 0
            || active.pending_publications != 0
            || active.credits.held != 0
            || active.credits.committed != 0
            || active.credits.free != active.credits.capacity
        {
            return Err(RegistryError::NotQuiescent);
        }
        let selection = self.registry.revoke_begin(self.scope)?;
        if selection.target_count != 0 || self.registry.revoke_next(&selection)?.is_some() {
            return Err(RegistryError::NotQuiescent);
        }
        self.registry.revoke_complete(&selection)?;
        self.registry.check_invariants()?;
        self.projection()
    }

    fn validate_credit(
        &self,
        credit: &Stage7bFaultCredit,
        binding: Stage7bFaultBinding,
    ) -> Result<(), RegistryError> {
        if binding.case != self.case
            || credit.instance_id != self.instance_id
            || credit.binding != binding
            || !self.bindings.contains(&binding)
        {
            return Err(RegistryError::InvalidHandle);
        }
        Ok(())
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct Stage7bNoCreditProjection {
    pub(crate) case: Stage7bFaultCase,
    pub(crate) binding: Stage7bFaultBinding,
    pub(crate) consumed: bool,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct Stage7bNoCredit {
    case: Stage7bFaultCase,
    binding: Stage7bFaultBinding,
    consumed: bool,
}

impl Stage7bNoCredit {
    pub(crate) fn new(
        case: Stage7bFaultCase,
        binding: Stage7bFaultBinding,
    ) -> Result<Self, RegistryError> {
        if case.credit_capacity() != 0 || binding.case != case {
            return Err(RegistryError::InvalidCreditConfiguration);
        }
        Ok(Self {
            case,
            binding,
            consumed: false,
        })
    }

    pub(crate) fn consume(&mut self, binding: Stage7bFaultBinding) -> Result<(), RegistryError> {
        if self.consumed || binding != self.binding {
            return Err(RegistryError::InvalidHandle);
        }
        self.consumed = true;
        Ok(())
    }

    pub(crate) const fn projection(&self) -> Stage7bNoCreditProjection {
        Stage7bNoCreditProjection {
            case: self.case,
            binding: self.binding,
            consumed: self.consumed,
        }
    }
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct Stage7bActiveFixture {
    config: Stage7bFixtureConfig,
    registry: EffectRegistry,
    target_scope: ScopeKey,
}

#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct Stage7bCompleteFixture {
    config: Stage7bFixtureConfig,
    registry: EffectRegistry,
    target_scope: ScopeKey,
    selection: RevokeSelection,
}

impl Clone for Stage7bActiveFixture {
    fn clone(&self) -> Self {
        Self {
            config: self.config,
            registry: self.registry.clone(),
            target_scope: self.target_scope,
        }
    }
}

impl Clone for Stage7bCompleteFixture {
    fn clone(&self) -> Self {
        Self {
            config: self.config,
            registry: self.registry.clone(),
            target_scope: self.target_scope,
            selection: self.selection.clone(),
        }
    }
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct Stage7bScaleObservation {
    pub(crate) config: Stage7bFixtureConfig,
    pub(crate) work: RevokeWorkProjection,
    pub(crate) target: RegistryProjection,
}

impl Stage7bActiveFixture {
    pub(crate) fn new(config: Stage7bFixtureConfig) -> Result<Self, RegistryError> {
        const TARGET_SCOPE: ScopeKey = ScopeKey::new(0x7b01, 1);
        const UNRELATED_SCOPE: ScopeKey = ScopeKey::new(0x7b02, 1);
        const HISTORY_SCOPE: ScopeKey = ScopeKey::new(0x7b03, 1);
        const TARGET_TASK: TaskKey = TaskKey::new(0x7b01, 1);
        const UNRELATED_TASK: TaskKey = TaskKey::new(0x7b02, 1);
        const HISTORY_TASK: TaskKey = TaskKey::new(0x7b03, 1);
        const TARGET_CREDIT: CreditClass = CreditClass::new(0x7b01);
        const UNRELATED_CREDIT: CreditClass = CreditClass::new(0x7b02);
        const HISTORY_CREDIT: CreditClass = CreditClass::new(0x7b03);

        if config.k > config.n {
            return Err(RegistryError::InvalidState);
        }
        let target_capacity =
            u64::try_from(config.k).map_err(|_| RegistryError::CounterOverflow)?;
        let unrelated = config.n - config.k;
        let unrelated_capacity =
            u64::try_from(unrelated.max(1)).map_err(|_| RegistryError::CounterOverflow)?;
        let mut registry = EffectRegistry::new();
        registry.create_scope(ScopeConfig {
            key: TARGET_SCOPE,
            authority_epoch: 1,
            binding_epoch: 1,
            supervisor: TARGET_TASK,
            credits: if target_capacity == 0 {
                Vec::new()
            } else {
                __cser_alloc::vec![CreditLimit::new(TARGET_CREDIT, target_capacity)]
            },
        })?;
        for (key, supervisor, credit, units) in [
            (
                UNRELATED_SCOPE,
                UNRELATED_TASK,
                UNRELATED_CREDIT,
                unrelated_capacity,
            ),
            (HISTORY_SCOPE, HISTORY_TASK, HISTORY_CREDIT, 1),
        ] {
            registry.create_scope(ScopeConfig {
                key,
                authority_epoch: 1,
                binding_epoch: 1,
                supervisor,
                credits: __cser_alloc::vec![CreditLimit::new(credit, units)],
            })?;
        }

        // History is deliberately older than the live population. One credit
        // is reused sequentially while the terminal records remain retained.
        for ordinal in 0..config.h {
            let registered = register_stage7b_effect(
                &mut registry,
                HISTORY_SCOPE,
                HISTORY_TASK,
                HISTORY_CREDIT,
                0x7b03,
                ordinal,
            )?;
            let terminal = registry.stage_terminal(
                HISTORY_TASK,
                registered.handle,
                TerminalRequest::aborted(-125),
            )?;
            if terminal.publication.is_some() {
                return Err(RegistryError::InvalidState);
            }
        }
        for ordinal in 0..config.k {
            register_stage7b_effect(
                &mut registry,
                TARGET_SCOPE,
                TARGET_TASK,
                TARGET_CREDIT,
                0x7b01,
                ordinal,
            )?;
        }
        for ordinal in 0..unrelated {
            register_stage7b_effect(
                &mut registry,
                UNRELATED_SCOPE,
                UNRELATED_TASK,
                UNRELATED_CREDIT,
                0x7b02,
                ordinal,
            )?;
        }
        registry.check_invariants()?;
        Ok(Self {
            config,
            registry,
            target_scope: TARGET_SCOPE,
        })
    }

    pub(crate) fn begin(&mut self) -> Result<RevokeSelection, RegistryError> {
        self.registry.revoke_begin(self.target_scope)
    }

    /// Prepares the fixture's sole target for the production commit-vs-revoke
    /// Loom race. The caller's modeled outer mutex supplies serialization.
    pub(crate) fn prepare_single_target(&mut self) -> Result<PortalHandle, RegistryError> {
        if self.config.k != 1 {
            return Err(RegistryError::InvalidState);
        }
        let effect = self
            .registry
            .by_scope
            .get(&self.target_scope)
            .and_then(BTreeSet::first)
            .copied()
            .ok_or(RegistryError::UnknownEffect)?;
        let handle = self.registry.effects[&effect].handle();
        self.registry.prepare(TaskKey::new(0x7b01, 1), handle)?;
        Ok(handle)
    }

    pub(crate) fn commit_single_target(
        &mut self,
        handle: PortalHandle,
    ) -> Result<CommitOutcome, RegistryError> {
        self.registry
            .commit(TaskKey::new(0x7b01, 1), handle, CommitMetadata::new(1, 1))
    }

    pub(crate) fn single_target_terminal(
        &self,
        handle: PortalHandle,
    ) -> Result<TerminalOutcome, RegistryError> {
        match self.registry.effect_view(handle.effect)?.phase {
            EffectPhase::Terminal(outcome) => Ok(outcome),
            _ => Err(RegistryError::InvalidState),
        }
    }

    pub(crate) fn finish_revoke(
        &mut self,
        selection: &RevokeSelection,
    ) -> Result<(), RegistryError> {
        drain_stage7b_selection(&mut self.registry, selection)?;
        self.registry.revoke_complete(selection)
    }

    pub(crate) fn prepare_complete_baseline(
        &self,
    ) -> Result<Stage7bCompleteFixture, RegistryError> {
        let mut candidate = self.clone();
        let selection = candidate.begin()?;
        drain_stage7b_selection(&mut candidate.registry, &selection)?;
        Ok(Stage7bCompleteFixture {
            config: candidate.config,
            registry: candidate.registry,
            target_scope: candidate.target_scope,
            selection,
        })
    }

    pub(crate) fn close_all(&mut self) -> Result<RevokeSelection, RegistryError> {
        let selection = self.begin()?;
        self.finish_revoke(&selection)?;
        Ok(selection)
    }

    pub(crate) fn target_projection(&self) -> Result<RegistryProjection, RegistryError> {
        self.registry.scope_projection(self.target_scope)
    }

    pub(crate) fn check_invariants(&self) -> Result<(), RegistryError> {
        self.registry.check_invariants()
    }

    pub(crate) fn observation(
        &self,
        selection: &RevokeSelection,
    ) -> Result<Stage7bScaleObservation, RegistryError> {
        Ok(Stage7bScaleObservation {
            config: self.config,
            work: self.registry.revoke_work_projection(selection)?,
            target: self.registry.scope_projection(self.target_scope)?,
        })
    }
}

impl Stage7bCompleteFixture {
    pub(crate) fn complete(&mut self) -> Result<(), RegistryError> {
        self.registry.revoke_complete(&self.selection)
    }

    pub(crate) fn observation(&self) -> Result<Stage7bScaleObservation, RegistryError> {
        Ok(Stage7bScaleObservation {
            config: self.config,
            work: self.registry.revoke_work_projection(&self.selection)?,
            target: self.registry.scope_projection(self.target_scope)?,
        })
    }

    pub(crate) fn check_invariants(&self) -> Result<(), RegistryError> {
        self.registry.check_invariants()
    }
}

fn register_stage7b_effect(
    registry: &mut EffectRegistry,
    scope: ScopeKey,
    task: TaskKey,
    credit: CreditClass,
    namespace: u32,
    ordinal: usize,
) -> Result<RegisteredEffect, RegistryError> {
    let ordinal_argument = ordinal;
    let ordinal = u64::try_from(ordinal).map_err(|_| RegistryError::CounterOverflow)?;
    let resource_id = ordinal
        .checked_add(1)
        .ok_or(RegistryError::CounterOverflow)?;
    let namespace_argument =
        usize::try_from(namespace).map_err(|_| RegistryError::CounterOverflow)?;
    registry.register(RegisterRequest {
        scope,
        task,
        operation: OperationClass::new(namespace),
        descriptor: SyscallDescriptor::new(
            0x7b00,
            [namespace_argument, ordinal_argument, 0, 0, 0, 0],
        ),
        resources: __cser_alloc::vec![ResourceKey::new(namespace, resource_id, 1)],
        credits: __cser_alloc::vec![CreditCharge::new(credit, 1)],
        publication: PublicationMode::None,
    })
}

fn drain_stage7b_selection(
    registry: &mut EffectRegistry,
    selection: &RevokeSelection,
) -> Result<(), RegistryError> {
    while let Some(effect) = registry.revoke_next(selection)? {
        if effect.publication_required {
            return Err(RegistryError::InvalidState);
        }
        let request = match effect.disposition {
            RevokeDisposition::Abort => TerminalRequest::aborted(-125),
            RevokeDisposition::Drain(receipt) => TerminalRequest::completed(receipt.result()),
        };
        let terminal = registry.stage_revoke_terminal(selection, effect.effect, request)?;
        if terminal.publication.is_some() {
            return Err(RegistryError::InvalidState);
        }
    }
    Ok(())
}

#[derive(
    __cser_core::clone::Clone,
    __cser_core::marker::Copy,
    __cser_core::fmt::Debug,
    __cser_core::cmp::Eq,
    __cser_core::cmp::PartialEq,
)]
pub(crate) struct RegistrySelfTestReceipt {
    pub(crate) effects: usize,
    pub(crate) recovery_adoptions: usize,
    pub(crate) committed_drains: usize,
    pub(crate) uncommitted_aborts: usize,
    pub(crate) publication_acks: usize,
    pub(crate) stale_authority_rejected: bool,
    pub(crate) quiescent: bool,
}

fn bounded_kernel_completion_during_recovery_self_test() {
    let scope = ScopeKey::new(51, 1);
    let v1 = TaskKey::new(620, 1);
    let v2 = TaskKey::new(621, 1);
    let task = TaskKey::new(622, 1);
    let credit = CreditClass::new(1);
    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: scope,
            authority_epoch: 112,
            binding_epoch: 1,
            supervisor: v1,
            credits: __cser_alloc::vec![CreditLimit::new(credit, 1)],
        })
        .unwrap();
    let effect = registry
        .register(RegisterRequest {
            scope,
            task,
            operation: OperationClass::new(9),
            descriptor: SyscallDescriptor::new(202, [0x402020, 129, 1, 0, 0, 0]),
            resources: __cser_alloc::vec![ResourceKey::new(9, 1, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(credit, 1)],
            publication: PublicationMode::Required,
        })
        .unwrap();
    registry.prepare(v1, effect.handle).unwrap();
    let commit = match registry
        .commit(v1, effect.handle, CommitMetadata::new(1, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => __cser_core::unreachable!(),
    };

    registry.crash(scope, v1).unwrap();
    let stale_snapshot = registry.recovery_snapshot(scope, v2).unwrap();
    registry.ready(scope, v2, &stale_snapshot).unwrap();
    let terminal = registry.stage_kernel_completion(&commit).unwrap();
    registry.check_invariants().unwrap();
    __cser_core::assert_eq!(registry.recovery_remaining(scope), Ok(0));
    __cser_core::assert_eq!(
        registry.rebind(scope, v2),
        Err(RegistryError::RecoveryNotReady),
    );
    registry
        .acknowledge_publication(&terminal.publication.unwrap())
        .unwrap();

    let snapshot = registry.recovery_snapshot(scope, v2).unwrap();
    __cser_core::assert!(snapshot.effects.is_empty());
    registry.ready(scope, v2, &snapshot).unwrap();
    registry.rebind(scope, v2).unwrap();
    __cser_core::assert!(registry.recover_next(scope, v2).unwrap().is_none());
    let selection = registry.revoke_begin(scope).unwrap();
    __cser_core::assert!(registry.revoke_next(&selection).unwrap().is_none());
    registry.revoke_complete(&selection).unwrap();
    registry.check_invariants().unwrap();
}

fn committed_causal_test_registry(
    scope: ScopeKey,
    task: TaskKey,
    credit: CreditClass,
    namespace: u32,
) -> (EffectRegistry, PortalHandle, CommitReceipt) {
    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: scope,
            authority_epoch: 1,
            binding_epoch: 1,
            supervisor: task,
            credits: __cser_alloc::vec![CreditLimit::new(credit, 1)],
        })
        .unwrap();
    let registered = registry
        .register(RegisterRequest {
            scope,
            task,
            operation: OperationClass::new(namespace),
            descriptor: SyscallDescriptor::new(namespace as usize, [0; 6]),
            resources: __cser_alloc::vec![ResourceKey::new(namespace, 1, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(credit, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    registry.prepare(task, registered.handle).unwrap();
    let commit = match registry
        .commit(task, registered.handle, CommitMetadata::new(1, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => __cser_core::unreachable!(),
    };
    registry.check_invariants().unwrap();
    (registry, registered.handle, commit)
}

/// Stage 7B executable checks for the explicit causal completion envelope.
/// They keep legitimate same-scope cross-effect completion while proving that
/// foreign scope and same-value foreign Registry receipts are rejected in both
/// directions without mutating either complete Registry state.
pub(crate) fn stage7b_causal_commit_self_test() {
    const POSITIVE_SCOPE: ScopeKey = ScopeKey::new(0x7bca_0001, 1);
    const POSITIVE_TASK: TaskKey = TaskKey::new(0x7bca_1001, 1);
    const POSITIVE_CREDIT: CreditClass = CreditClass::new(0x7bca);

    let mut positive = EffectRegistry::new();
    positive
        .create_scope(ScopeConfig {
            key: POSITIVE_SCOPE,
            authority_epoch: 1,
            binding_epoch: 1,
            supervisor: POSITIVE_TASK,
            credits: __cser_alloc::vec![CreditLimit::new(POSITIVE_CREDIT, 2)],
        })
        .unwrap();
    let source = positive
        .register(RegisterRequest {
            scope: POSITIVE_SCOPE,
            task: POSITIVE_TASK,
            operation: OperationClass::new(1),
            descriptor: SyscallDescriptor::new(1, [1, 0, 0, 0, 0, 0]),
            resources: __cser_alloc::vec![ResourceKey::new(0x7bca, 1, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(POSITIVE_CREDIT, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    let target = positive
        .register(RegisterRequest {
            scope: POSITIVE_SCOPE,
            task: POSITIVE_TASK,
            operation: OperationClass::new(2),
            descriptor: SyscallDescriptor::new(2, [2, 0, 0, 0, 0, 0]),
            resources: __cser_alloc::vec![ResourceKey::new(0x7bca, 2, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(POSITIVE_CREDIT, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    positive.prepare(POSITIVE_TASK, source.handle).unwrap();
    let source_commit = match positive
        .commit(POSITIVE_TASK, source.handle, CommitMetadata::new(1, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => __cser_core::unreachable!(),
    };
    let target_terminal = positive
        .stage_terminal(
            POSITIVE_TASK,
            target.handle,
            TerminalRequest::completed_by(2, source_commit.clone()),
        )
        .unwrap();
    __cser_core::assert_eq!(
        target_terminal.receipt.outcome(),
        TerminalOutcome::Completed
    );
    positive.stage_kernel_completion(&source_commit).unwrap();
    positive.check_invariants().unwrap();

    const SCOPE_A: ScopeKey = ScopeKey::new(0x7bca_0002, 1);
    const SCOPE_B: ScopeKey = ScopeKey::new(0x7bca_0003, 1);
    const TASK_A: TaskKey = TaskKey::new(0x7bca_1002, 1);
    const TASK_B: TaskKey = TaskKey::new(0x7bca_1003, 1);
    const CREDIT_A: CreditClass = CreditClass::new(0x7bcb);
    const CREDIT_B: CreditClass = CreditClass::new(0x7bcc);

    let mut cross_scope = EffectRegistry::new();
    for (scope, task, credit) in [(SCOPE_A, TASK_A, CREDIT_A), (SCOPE_B, TASK_B, CREDIT_B)] {
        cross_scope
            .create_scope(ScopeConfig {
                key: scope,
                authority_epoch: 1,
                binding_epoch: 1,
                supervisor: task,
                credits: __cser_alloc::vec![CreditLimit::new(credit, 1)],
            })
            .unwrap();
    }
    let effect_a = cross_scope
        .register(RegisterRequest {
            scope: SCOPE_A,
            task: TASK_A,
            operation: OperationClass::new(3),
            descriptor: SyscallDescriptor::new(3, [0; 6]),
            resources: __cser_alloc::vec![ResourceKey::new(0x7bcb, 1, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(CREDIT_A, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    let effect_b = cross_scope
        .register(RegisterRequest {
            scope: SCOPE_B,
            task: TASK_B,
            operation: OperationClass::new(4),
            descriptor: SyscallDescriptor::new(4, [0; 6]),
            resources: __cser_alloc::vec![ResourceKey::new(0x7bcc, 1, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(CREDIT_B, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    cross_scope.prepare(TASK_A, effect_a.handle).unwrap();
    cross_scope.prepare(TASK_B, effect_b.handle).unwrap();
    let commit_a = match cross_scope
        .commit(TASK_A, effect_a.handle, CommitMetadata::new(3, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => __cser_core::unreachable!(),
    };
    let commit_b = match cross_scope
        .commit(TASK_B, effect_b.handle, CommitMetadata::new(4, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => __cser_core::unreachable!(),
    };
    let cross_scope_before = cross_scope.clone();
    __cser_core::assert_eq!(
        cross_scope.stage_terminal(
            TASK_A,
            effect_a.handle,
            TerminalRequest::completed_by(3, commit_b.clone()),
        ),
        Err(RegistryError::CommitConflict)
    );
    __cser_core::assert_eq!(cross_scope, cross_scope_before);
    __cser_core::assert_eq!(
        cross_scope.stage_terminal(
            TASK_B,
            effect_b.handle,
            TerminalRequest::completed_by(4, commit_a.clone()),
        ),
        Err(RegistryError::CommitConflict)
    );
    __cser_core::assert_eq!(cross_scope, cross_scope_before);
    cross_scope.stage_kernel_completion(&commit_a).unwrap();
    cross_scope.stage_kernel_completion(&commit_b).unwrap();
    cross_scope.check_invariants().unwrap();

    const SHARED_SCOPE: ScopeKey = ScopeKey::new(0x7bca_0010, 1);
    const SHARED_TASK: TaskKey = TaskKey::new(0x7bca_1010, 1);
    const SHARED_CREDIT: CreditClass = CreditClass::new(0x7bd0);
    let (mut first, first_handle, first_commit) =
        committed_causal_test_registry(SHARED_SCOPE, SHARED_TASK, SHARED_CREDIT, 0x7bd0);
    let (mut second, second_handle, second_commit) =
        committed_causal_test_registry(SHARED_SCOPE, SHARED_TASK, SHARED_CREDIT, 0x7bd0);
    __cser_core::assert_ne!(
        first_commit.registry_instance_id,
        second_commit.registry_instance_id
    );
    __cser_core::assert_eq!(first_commit.effect, second_commit.effect);
    __cser_core::assert_eq!(first_commit.scope, second_commit.scope);
    __cser_core::assert_eq!(first_commit.authority_epoch, second_commit.authority_epoch);
    __cser_core::assert_eq!(first_commit.binding_epoch, second_commit.binding_epoch);
    __cser_core::assert_eq!(first_commit.sequence, second_commit.sequence);
    __cser_core::assert_eq!(first_commit.result, second_commit.result);
    __cser_core::assert_eq!(first_commit.domain_revision, second_commit.domain_revision);
    __cser_core::assert_eq!(
        first_commit.descriptor_digest,
        second_commit.descriptor_digest
    );
    let first_before = first.clone();
    let second_before = second.clone();
    __cser_core::assert_eq!(
        first.stage_terminal(
            SHARED_TASK,
            first_handle,
            TerminalRequest::completed_by(1, second_commit.clone()),
        ),
        Err(RegistryError::CommitConflict)
    );
    __cser_core::assert_eq!(first, first_before);
    __cser_core::assert_eq!(second, second_before);
    __cser_core::assert_eq!(
        second.stage_terminal(
            SHARED_TASK,
            second_handle,
            TerminalRequest::completed_by(1, first_commit.clone()),
        ),
        Err(RegistryError::CommitConflict)
    );
    __cser_core::assert_eq!(first, first_before);
    __cser_core::assert_eq!(second, second_before);
    first.stage_kernel_completion(&first_commit).unwrap();
    second.stage_kernel_completion(&second_commit).unwrap();
    first.check_invariants().unwrap();
    second.check_invariants().unwrap();
}

fn stage7b_registry_refactor_self_test() {
    // Public transition failures must not leave half-applied phase, counter,
    // credit, or index state when the root revision cannot advance.
    let atomic_scope = ScopeKey::new(0x7bf0, 1);
    let atomic_task = TaskKey::new(0x7bf0, 1);
    let atomic_credit = CreditClass::new(0x7bf0);
    let mut atomic = EffectRegistry::new();
    atomic
        .create_scope(ScopeConfig {
            key: atomic_scope,
            authority_epoch: 1,
            binding_epoch: 1,
            supervisor: atomic_task,
            credits: __cser_alloc::vec![CreditLimit::new(atomic_credit, 1)],
        })
        .unwrap();
    let request = || RegisterRequest {
        scope: atomic_scope,
        task: atomic_task,
        operation: OperationClass::new(0x7bf0),
        descriptor: SyscallDescriptor::new(0x7bf0, [0; 6]),
        resources: __cser_alloc::vec![ResourceKey::new(0x7bf0, 1, 1)],
        credits: __cser_alloc::vec![CreditCharge::new(atomic_credit, 1)],
        publication: PublicationMode::None,
    };
    atomic.scopes.get_mut(&atomic_scope).unwrap().revision = u64::MAX;
    let before = atomic.clone();
    __cser_core::assert_eq!(
        atomic.register(request()),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(atomic, before);
    atomic.scopes.get_mut(&atomic_scope).unwrap().revision = 0;
    let registered = atomic.register(request()).unwrap();
    atomic.scopes.get_mut(&atomic_scope).unwrap().revision = u64::MAX;
    let before = atomic.clone();
    __cser_core::assert_eq!(
        atomic.prepare(atomic_task, registered.handle),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(atomic, before);
    atomic.scopes.get_mut(&atomic_scope).unwrap().revision = 1;
    atomic.prepare(atomic_task, registered.handle).unwrap();
    atomic.scopes.get_mut(&atomic_scope).unwrap().revision = u64::MAX;
    let before = atomic.clone();
    __cser_core::assert_eq!(
        atomic.crash(atomic_scope, atomic_task),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(atomic, before);
    {
        let scope = atomic.scopes.get_mut(&atomic_scope).unwrap();
        scope.revision = 2;
        scope.binding_epoch = u64::MAX;
        scope
            .domains
            .get_mut(&DomainKey::LEGACY)
            .unwrap()
            .binding_epoch = u64::MAX;
    }
    let before = atomic.clone();
    __cser_core::assert_eq!(
        atomic.crash(atomic_scope, atomic_task),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(atomic, before);

    let config = Stage7bFixtureConfig { n: 8, k: 3, h: 2 };
    let fixture = Stage7bActiveFixture::new(config).unwrap();
    __cser_core::assert_eq!(fixture.target_projection().unwrap().live_effects, config.k);
    fixture.check_invariants().unwrap();

    // The three zero-valued scale metrics are real counters, not constants in
    // the projection. Exercise their classification boundary without changing
    // the production close path measured below.
    let mut instrumented = fixture.clone();
    let instrumented_selection = instrumented.begin().unwrap();
    let target = *instrumented
        .registry
        .scopes
        .get(&instrumented.target_scope)
        .unwrap()
        .revoke
        .as_ref()
        .unwrap()
        .cohort
        .first()
        .unwrap();
    let unrelated = instrumented
        .registry
        .effects
        .iter()
        .find_map(|(effect, record)| {
            (record.identity.scope != instrumented.target_scope && !record.phase.is_terminal())
                .then_some(*effect)
        })
        .unwrap();
    let history = instrumented
        .registry
        .effects
        .iter()
        .find_map(|(effect, record)| record.phase.is_terminal().then_some(*effect))
        .unwrap();
    {
        let (scopes, effects) = (
            &mut instrumented.registry.scopes,
            &instrumented.registry.effects,
        );
        let revoke = scopes
            .get_mut(&instrumented.target_scope)
            .unwrap()
            .revoke
            .as_mut()
            .unwrap();
        for (effect, access) in [
            (target, RevokeRecordAccess::Begin),
            (unrelated, RevokeRecordAccess::Transition),
            (history, RevokeRecordAccess::Transition),
        ] {
            instrument_revoke_record_access(
                &mut revoke.work,
                &revoke.cohort,
                effects,
                instrumented.target_scope,
                effect,
                access,
            )
            .unwrap();
        }
    }
    let work = instrumented
        .registry
        .revoke_work_projection(&instrumented_selection)
        .unwrap();
    __cser_core::assert_eq!(work.begin_target_record_visits, 1);
    __cser_core::assert_eq!(work.unrelated_effect_visits, 1);
    __cser_core::assert_eq!(work.history_effect_visits, 1);

    let mut closed = fixture.clone();
    let selection = closed.close_all().unwrap();
    let observation = closed.observation(&selection).unwrap();
    __cser_core::assert_eq!(observation.config, config);
    __cser_core::assert_eq!(observation.work.target_count, 3);
    __cser_core::assert_eq!(observation.work.begin_target_record_visits, 0);
    __cser_core::assert_eq!(observation.work.next_calls, 4);
    __cser_core::assert_eq!(observation.work.head_selections, 3);
    __cser_core::assert_eq!(observation.work.terminalized, 3);
    __cser_core::assert_eq!(observation.work.completion_members_checked, 3);
    __cser_core::assert_eq!(observation.work.target_index_removals, 3);
    __cser_core::assert_eq!(observation.work.unrelated_effect_visits, 0);
    __cser_core::assert_eq!(observation.work.history_effect_visits, 0);
    __cser_core::assert_eq!(observation.work.pending_targets, 0);
    __cser_core::assert_eq!(observation.work.target_state, ScopePhase::Revoked);
    __cser_core::assert_eq!(observation.target.phase, ScopePhase::Revoked);
    closed.check_invariants().unwrap();
    let before = closed.registry.clone();
    __cser_core::assert_eq!(closed.begin(), Err(RegistryError::ScopeNotActive));
    __cser_core::assert_eq!(closed.registry, before);

    let mut empty = Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 4, k: 0, h: 3 }).unwrap();
    let empty_active = empty.target_projection().unwrap();
    __cser_core::assert_eq!(empty_active.credits.capacity, 0);
    __cser_core::assert_eq!(empty_active.credits.free, 0);
    __cser_core::assert_eq!(empty_active.credits.held, 0);
    __cser_core::assert_eq!(empty_active.credits.committed, 0);
    let selection = empty.close_all().unwrap();
    let empty_observation = empty.observation(&selection).unwrap();
    __cser_core::assert_eq!(empty_observation.work.target_count, 0);
    __cser_core::assert_eq!(empty_observation.work.next_calls, 1);
    __cser_core::assert_eq!(empty_observation.work.head_selections, 0);
    __cser_core::assert_eq!(empty_observation.work.terminalized, 0);
    __cser_core::assert_eq!(empty_observation.work.completion_members_checked, 0);
    __cser_core::assert_eq!(empty_observation.work.target_state, ScopePhase::Revoked);
    __cser_core::assert_eq!(empty_observation.target.credits, empty_active.credits);
    empty.check_invariants().unwrap();

    // Unknown and overflow failures do not consume the revoke sequence or
    // alter any registry-owned state.
    let mut unknown = fixture.clone();
    let before = unknown.registry.clone();
    __cser_core::assert_eq!(
        unknown.registry.revoke_begin(ScopeKey::new(0xffff, 1)),
        Err(RegistryError::UnknownScope)
    );
    __cser_core::assert_eq!(unknown.registry, before);

    let mut sequence_overflow = fixture.clone();
    sequence_overflow.registry.next_revoke_sequence = u64::MAX;
    let before = sequence_overflow.registry.clone();
    __cser_core::assert_eq!(
        sequence_overflow.begin(),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(sequence_overflow.registry, before);

    let mut authority_overflow = fixture.clone();
    authority_overflow
        .registry
        .scopes
        .get_mut(&authority_overflow.target_scope)
        .unwrap()
        .authority_epoch = u64::MAX;
    let before = authority_overflow.registry.clone();
    __cser_core::assert_eq!(
        authority_overflow.begin(),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(authority_overflow.registry, before);

    let mut revision_overflow = fixture.clone();
    revision_overflow
        .registry
        .scopes
        .get_mut(&revision_overflow.target_scope)
        .unwrap()
        .revision = u64::MAX;
    let before = revision_overflow.registry.clone();
    __cser_core::assert_eq!(
        revision_overflow.begin(),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(revision_overflow.registry, before);

    let mut tampered = fixture.clone();
    let mut selection = tampered.begin().unwrap();
    selection.closed_authority_epoch += 1;
    let before = tampered.registry.clone();
    __cser_core::assert_eq!(
        tampered.registry.revoke_next(&selection),
        Err(RegistryError::InvalidRevokeSelection)
    );
    __cser_core::assert_eq!(tampered.registry, before);

    let mut complete_overflow = fixture.prepare_complete_baseline().unwrap();
    complete_overflow
        .registry
        .scopes
        .get_mut(&complete_overflow.target_scope)
        .unwrap()
        .revision = u64::MAX;
    let before = complete_overflow.registry.clone();
    __cser_core::assert_eq!(
        complete_overflow.complete(),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(complete_overflow.registry, before);

    let mut terminal_overflow =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 2, k: 1, h: 0 }).unwrap();
    let selection = terminal_overflow.begin().unwrap();
    let effect = terminal_overflow
        .registry
        .revoke_next(&selection)
        .unwrap()
        .unwrap()
        .effect;
    terminal_overflow.registry.next_terminal_sequence = u64::MAX;
    let before = terminal_overflow.registry.clone();
    __cser_core::assert_eq!(
        terminal_overflow.registry.stage_revoke_terminal(
            &selection,
            effect,
            TerminalRequest::aborted(-125),
        ),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(terminal_overflow.registry, before);

    let mut publication_overflow =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 2, k: 1, h: 0 }).unwrap();
    let effect = *publication_overflow
        .registry
        .by_scope
        .get(&publication_overflow.target_scope)
        .unwrap()
        .first()
        .unwrap();
    publication_overflow
        .registry
        .effects
        .get_mut(&effect)
        .unwrap()
        .publication_mode = PublicationMode::Required;
    let selection = publication_overflow.begin().unwrap();
    publication_overflow
        .registry
        .revoke_next(&selection)
        .unwrap()
        .unwrap();
    publication_overflow.registry.next_publication_sequence = u64::MAX;
    let before = publication_overflow.registry.clone();
    __cser_core::assert_eq!(
        publication_overflow.registry.stage_revoke_terminal(
            &selection,
            effect,
            TerminalRequest::aborted(-125),
        ),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(publication_overflow.registry, before);

    let mut revision_overflow =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 2, k: 1, h: 0 }).unwrap();
    let selection = revision_overflow.begin().unwrap();
    let effect = revision_overflow
        .registry
        .revoke_next(&selection)
        .unwrap()
        .unwrap()
        .effect;
    revision_overflow
        .registry
        .scopes
        .get_mut(&revision_overflow.target_scope)
        .unwrap()
        .revision = u64::MAX;
    let before = revision_overflow.registry.clone();
    __cser_core::assert_eq!(
        revision_overflow.registry.stage_revoke_terminal(
            &selection,
            effect,
            TerminalRequest::aborted(-125),
        ),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(revision_overflow.registry, before);

    let mut ack_overflow =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 2, k: 1, h: 0 }).unwrap();
    let effect = *ack_overflow
        .registry
        .by_scope
        .get(&ack_overflow.target_scope)
        .unwrap()
        .first()
        .unwrap();
    ack_overflow
        .registry
        .effects
        .get_mut(&effect)
        .unwrap()
        .publication_mode = PublicationMode::Required;
    let selection = ack_overflow.begin().unwrap();
    ack_overflow
        .registry
        .revoke_next(&selection)
        .unwrap()
        .unwrap();
    let ticket = ack_overflow
        .registry
        .stage_revoke_terminal(&selection, effect, TerminalRequest::aborted(-125))
        .unwrap()
        .publication
        .unwrap();
    __cser_core::assert_eq!(
        ack_overflow
            .target_projection()
            .unwrap()
            .pending_publications,
        1
    );
    ack_overflow
        .registry
        .scopes
        .get_mut(&ack_overflow.target_scope)
        .unwrap()
        .revision = u64::MAX;
    let before = ack_overflow.registry.clone();
    __cser_core::assert_eq!(
        ack_overflow.registry.acknowledge_publication(&ticket),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(ack_overflow.registry, before);

    let mut commit_overflow =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 2, k: 1, h: 0 }).unwrap();
    let effect = *commit_overflow
        .registry
        .by_scope
        .get(&commit_overflow.target_scope)
        .unwrap()
        .first()
        .unwrap();
    let handle = commit_overflow.registry.effects[&effect].handle();
    let supervisor = TaskKey::new(0x7b01, 1);
    commit_overflow
        .registry
        .prepare(supervisor, handle)
        .unwrap();
    commit_overflow
        .registry
        .scopes
        .get_mut(&commit_overflow.target_scope)
        .unwrap()
        .revision = u64::MAX;
    let before = commit_overflow.registry.clone();
    __cser_core::assert_eq!(
        commit_overflow
            .registry
            .commit(supervisor, handle, CommitMetadata::new(1, 1)),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(commit_overflow.registry, before);

    // Re-reading a selected head is idempotent: it neither skips the target
    // nor counts a second head selection.
    let mut duplicate =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 2, k: 1, h: 1 }).unwrap();
    let selection = duplicate.begin().unwrap();
    let first = duplicate.registry.revoke_next(&selection).unwrap().unwrap();
    let second = duplicate.registry.revoke_next(&selection).unwrap().unwrap();
    __cser_core::assert_eq!(first, second);
    let work = duplicate
        .registry
        .revoke_work_projection(&selection)
        .unwrap();
    __cser_core::assert_eq!(work.next_calls, 2);
    __cser_core::assert_eq!(work.head_selections, 1);
    duplicate
        .registry
        .stage_revoke_terminal(&selection, first.effect, TerminalRequest::aborted(-125))
        .unwrap();
    __cser_core::assert!(
        duplicate
            .registry
            .revoke_next(&selection)
            .unwrap()
            .is_none()
    );
    duplicate.registry.revoke_complete(&selection).unwrap();
    duplicate.check_invariants().unwrap();

    // The same production methods are included by registry_loom.rs under a
    // modeled outer mutex. These sequential endpoints pin both linearization
    // outcomes before Loom explores their interleavings.
    let mut commit_first =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 1, k: 1, h: 0 }).unwrap();
    let handle = commit_first.prepare_single_target().unwrap();
    __cser_core::assert!(__cser_core::matches!(
        commit_first.commit_single_target(handle).unwrap(),
        CommitOutcome::Applied(_)
    ));
    let selection = commit_first.begin().unwrap();
    commit_first.finish_revoke(&selection).unwrap();
    __cser_core::assert_eq!(
        commit_first.single_target_terminal(handle).unwrap(),
        TerminalOutcome::Completed
    );
    let observation = commit_first.observation(&selection).unwrap();
    __cser_core::assert_eq!(observation.target.credits.free, 1);
    __cser_core::assert_eq!(observation.target.credits.held, 0);
    __cser_core::assert_eq!(observation.target.credits.committed, 0);
    commit_first.check_invariants().unwrap();

    let mut revoke_first =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 1, k: 1, h: 0 }).unwrap();
    let handle = revoke_first.prepare_single_target().unwrap();
    let selection = revoke_first.begin().unwrap();
    revoke_first.finish_revoke(&selection).unwrap();
    __cser_core::assert_eq!(
        revoke_first.commit_single_target(handle),
        Err(RegistryError::StaleAuthority)
    );
    __cser_core::assert_eq!(
        revoke_first.single_target_terminal(handle).unwrap(),
        TerminalOutcome::Aborted
    );
    let observation = revoke_first.observation(&selection).unwrap();
    __cser_core::assert_eq!(observation.target.credits.free, 1);
    __cser_core::assert_eq!(observation.target.credits.held, 0);
    __cser_core::assert_eq!(observation.target.credits.committed, 0);
    revoke_first.check_invariants().unwrap();
}

fn publication_ack_and_revoke_complete_self_test() {
    use __cser_core::cell::Cell;

    const SCOPE: ScopeKey = ScopeKey::new(0x1f00, 1);
    const SUPERVISOR: TaskKey = TaskKey::new(0x1f00, 1);
    const ROOT_TASK: TaskKey = TaskKey::new(0x1f01, 1);
    const CHILD_TASK: TaskKey = TaskKey::new(0x1f02, 1);
    const CREDIT: CreditClass = CreditClass::new(0x1f0);
    const CHILD_DOMAIN: DomainKey = DomainKey::new(1);

    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: SCOPE,
            authority_epoch: 1,
            binding_epoch: 1,
            supervisor: SUPERVISOR,
            credits: __cser_alloc::vec![CreditLimit::new(CREDIT, 2)],
        })
        .unwrap();
    registry
        .add_domain(
            SCOPE,
            DomainConfig {
                key: CHILD_DOMAIN,
                binding_epoch: 1,
                supervisor: SUPERVISOR,
            },
        )
        .unwrap();
    let root = registry
        .register(RegisterRequest {
            scope: SCOPE,
            task: ROOT_TASK,
            operation: OperationClass::new(1),
            descriptor: SyscallDescriptor::new(1, [0; 6]),
            resources: __cser_alloc::vec![ResourceKey::new(0x1f0, 1, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(CREDIT, 1)],
            publication: PublicationMode::Required,
        })
        .unwrap();
    let child = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: CHILD_TASK,
                operation: OperationClass::new(2),
                descriptor: SyscallDescriptor::new(2, [0; 6]),
                resources: __cser_alloc::vec![ResourceKey::new(0x1f0, 2, 1)],
                credits: __cser_alloc::vec![CreditCharge::new(CREDIT, 1)],
                publication: PublicationMode::Required,
            },
            domain: CHILD_DOMAIN,
            parent: Some(root.identity.effect()),
        })
        .unwrap();
    registry.prepare(SUPERVISOR, root.handle).unwrap();
    registry.prepare(SUPERVISOR, child.handle).unwrap();

    let selection = registry.revoke_begin(SCOPE).unwrap();
    let selected_child = registry.revoke_next(&selection).unwrap().unwrap();
    __cser_core::assert_eq!(selected_child.effect, child.identity.effect());
    let child_ticket = registry
        .stage_revoke_terminal(
            &selection,
            selected_child.effect,
            TerminalRequest::aborted(-125),
        )
        .unwrap()
        .publication
        .unwrap();
    let selected_root = registry.revoke_next(&selection).unwrap().unwrap();
    __cser_core::assert_eq!(selected_root.effect, root.identity.effect());
    let root_ticket = registry
        .stage_revoke_terminal(
            &selection,
            selected_root.effect,
            TerminalRequest::aborted(-125),
        )
        .unwrap()
        .publication
        .unwrap();
    __cser_core::assert!(registry.revoke_next(&selection).unwrap().is_none());
    registry.check_invariants().unwrap();

    let two_pending_before = registry.clone();
    let two_pending_applies = Cell::new(0_u8);
    __cser_core::assert_eq!(
        registry.acknowledge_publication_and_revoke_complete_with_apply(
            &child_ticket,
            &selection,
            || two_pending_applies.set(1),
        ),
        Err(RegistryError::NotQuiescent)
    );
    __cser_core::assert_eq!(two_pending_applies.get(), 0);
    __cser_core::assert_eq!(registry, two_pending_before);

    registry.acknowledge_publication(&child_ticket).unwrap();
    registry.check_invariants().unwrap();
    let ready = registry.clone();

    let mut wrong_selection = selection.clone();
    wrong_selection.sequence = wrong_selection.sequence.checked_add(1).unwrap();
    let mut wrong = ready.clone();
    let wrong_before = wrong.clone();
    let wrong_applies = Cell::new(0_u8);
    __cser_core::assert_eq!(
        wrong.acknowledge_publication_and_revoke_complete_with_apply(
            &root_ticket,
            &wrong_selection,
            || wrong_applies.set(1),
        ),
        Err(RegistryError::InvalidRevokeSelection)
    );
    __cser_core::assert_eq!(wrong_applies.get(), 0);
    __cser_core::assert_eq!(wrong, wrong_before);

    let mut overflow = ready.clone();
    overflow.scopes.get_mut(&SCOPE).unwrap().revision = u64::MAX - 1;
    let overflow_before = overflow.clone();
    let overflow_applies = Cell::new(0_u8);
    __cser_core::assert_eq!(
        overflow.acknowledge_publication_and_revoke_complete_with_apply(
            &root_ticket,
            &selection,
            || overflow_applies.set(1),
        ),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(overflow_applies.get(), 0);
    __cser_core::assert_eq!(overflow, overflow_before);

    let revision_before = registry.scopes[&SCOPE].revision;
    let successful_applies = Cell::new(0_u8);
    __cser_core::assert_eq!(
        registry
            .acknowledge_publication_and_revoke_complete_with_apply(
                &root_ticket,
                &selection,
                || {
                    successful_applies.set(1);
                    0x51_u8
                },
            )
            .unwrap(),
        0x51
    );
    __cser_core::assert_eq!(successful_applies.get(), 1);
    __cser_core::assert_eq!(registry.scopes[&SCOPE].revision, revision_before + 2);
    let projection = registry.scope_projection(SCOPE).unwrap();
    __cser_core::assert_eq!(projection.phase, ScopePhase::Revoked);
    __cser_core::assert_eq!(projection.pending_publications, 0);
    __cser_core::assert_eq!(projection.credits.free, projection.credits.capacity);
    registry.check_invariants().unwrap();
}

#[cfg(test)]
fn combined_scope_candidate_self_test() {
    const TARGET: ScopeKey = ScopeKey::new(0xc051, 1);
    const UNRELATED: ScopeKey = ScopeKey::new(0xc052, 1);
    const TARGET_OWNER: TaskKey = TaskKey::new(0xc061, 1);
    const UNRELATED_OWNER: TaskKey = TaskKey::new(0xc062, 1);
    const TARGET_CREDIT: CreditClass = CreditClass::new(0xc071);
    const UNRELATED_CREDIT: CreditClass = CreditClass::new(0xc072);

    fn fixture() -> (EffectRegistry, EffectKey, EffectKey) {
        let mut registry = EffectRegistry::new();
        for (scope, owner, credit) in [
            (TARGET, TARGET_OWNER, TARGET_CREDIT),
            (UNRELATED, UNRELATED_OWNER, UNRELATED_CREDIT),
        ] {
            registry
                .create_scope(ScopeConfig {
                    key: scope,
                    authority_epoch: 7,
                    binding_epoch: 1,
                    supervisor: owner,
                    credits: __cser_alloc::vec![CreditLimit::new(credit, 1)],
                })
                .unwrap();
        }
        let target_root = registry
            .register(RegisterRequest {
                scope: TARGET,
                task: TARGET_OWNER,
                operation: OperationClass::new(0xc081),
                descriptor: SyscallDescriptor::new(0xc081, [0; 6]),
                resources: __cser_alloc::vec![ResourceKey::new(0xc081, 1, 1)],
                credits: __cser_alloc::vec![CreditCharge::new(TARGET_CREDIT, 1)],
                publication: PublicationMode::None,
            })
            .unwrap()
            .identity
            .effect();
        let unrelated_root = registry
            .register(RegisterRequest {
                scope: UNRELATED,
                task: UNRELATED_OWNER,
                operation: OperationClass::new(0xc082),
                descriptor: SyscallDescriptor::new(0xc082, [0; 6]),
                resources: __cser_alloc::vec![ResourceKey::new(0xc082, 1, 1)],
                credits: __cser_alloc::vec![CreditCharge::new(UNRELATED_CREDIT, 1)],
                publication: PublicationMode::None,
            })
            .unwrap()
            .identity
            .effect();
        let limits =
            infrastructure::InfrastructureLimits::new(2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4)
                .unwrap();
        registry
            .enable_infrastructure_for_scope(TARGET, target_root, limits)
            .unwrap();
        registry
            .enable_infrastructure_for_scope(UNRELATED, unrelated_root, limits)
            .unwrap();
        registry.check_invariants().unwrap();
        (registry, target_root, unrelated_root)
    }

    // The ordinary Registry invariant entry point, not only the combined
    // installer, recomputes infrastructure and checks the exact business
    // domain/lifecycle linkage.  Every rejection is observationally
    // read-only.
    let (mut wrong_domain_epoch, _, _) = fixture();
    wrong_domain_epoch
        .infrastructure
        .corrupt_domain_epoch_for_test(TARGET, DomainKey::LEGACY, 2);
    let before = wrong_domain_epoch.clone();
    __cser_core::assert!(__cser_core::matches!(
        wrong_domain_epoch.check_invariants(),
        Err(RegistryError::Invariant(_))
    ));
    __cser_core::assert_eq!(wrong_domain_epoch, before);

    let (mut extra_domain, _, _) = fixture();
    extra_domain
        .infrastructure
        .add_domain_for_test(TARGET, DomainKey::new(0xc0f0), 1);
    let before = extra_domain.clone();
    __cser_core::assert!(__cser_core::matches!(
        extra_domain.check_invariants(),
        Err(RegistryError::Invariant(_))
    ));
    __cser_core::assert_eq!(extra_domain, before);

    let (mut wrong_lifecycle, _, _) = fixture();
    wrong_lifecycle
        .infrastructure
        .set_closing_lifecycle_for_test(TARGET);
    let before = wrong_lifecycle.clone();
    __cser_core::assert!(__cser_core::matches!(
        wrong_lifecycle.check_invariants(),
        Err(RegistryError::Invariant(_))
    ));
    __cser_core::assert_eq!(wrong_lifecycle, before);

    // Active roots use the current epoch. Closing and revoked roots retain
    // the exact closed epoch while the business scope advances exactly once.
    let (mut closing, target_root, _) = fixture();
    let selection = closing.revoke_begin(TARGET).unwrap();
    closing
        .infrastructure
        .set_closing_lifecycle_for_test(TARGET);
    closing.check_invariants().unwrap();

    let mut rolled_authority = closing.clone();
    rolled_authority
        .scopes
        .get_mut(&TARGET)
        .unwrap()
        .authority_epoch += 1;
    let before = rolled_authority.clone();
    __cser_core::assert!(__cser_core::matches!(
        rolled_authority.check_invariants(),
        Err(RegistryError::Invariant(_))
    ));
    __cser_core::assert_eq!(rolled_authority, before);

    let terminal = closing
        .stage_revoke_terminal(&selection, target_root, TerminalRequest::aborted(-125))
        .unwrap();
    __cser_core::assert!(terminal.publication.is_none());
    // The last member is terminal before revoke completion.  This is a legal
    // public Registry return state: the immutable infrastructure root remains
    // Closing while the business live index has already dropped the root.
    closing.check_invariants().unwrap();
    closing.revoke_complete(&selection).unwrap();
    closing
        .infrastructure
        .set_revoked_lifecycle_for_test(TARGET);
    closing.check_invariants().unwrap();

    // A target business revision change after candidate construction fences
    // the exact-scope candidate.  The failed install leaves both ledgers and
    // the unrelated tenant byte-for-byte (including authority mode) intact.
    let (mut stale, _, _) = fixture();
    let stale_candidate = stale.combined_scope_candidate(TARGET).unwrap();
    stale.scopes.get_mut(&TARGET).unwrap().revision += 1;
    let before_stale_install = stale.clone();
    __cser_core::assert!(__cser_core::matches!(
        stale.prepare_combined_scope_install(stale_candidate),
        Err(RegistryError::CombinedCandidateStale),
    ));
    __cser_core::assert_eq!(stale, before_stale_install);
    __cser_core::assert!(stale.infrastructure.is_authoritative_for_test());

    // The independent infrastructure base revision is fenced as well; a
    // business revision match cannot authorize an older infrastructure view.
    let (mut stale_infrastructure, _, _) = fixture();
    let stale_candidate = stale_infrastructure
        .combined_scope_candidate(TARGET)
        .unwrap();
    stale_infrastructure
        .infrastructure
        .advance_authoritative_scope_revision_for_test(TARGET);
    let before_stale_install = stale_infrastructure.clone();
    __cser_core::assert!(__cser_core::matches!(
        stale_infrastructure.prepare_combined_scope_install(stale_candidate),
        Err(RegistryError::Infrastructure(
            infrastructure::InfrastructureError::StaleAuthority
        )),
    ));
    __cser_core::assert_eq!(stale_infrastructure, before_stale_install);
    __cser_core::assert!(
        stale_infrastructure
            .infrastructure
            .is_authoritative_for_test()
    );

    // Infrastructure-side validation happens while live is untouched.
    let (invalid_infrastructure, _, _) = fixture();
    let mut candidate = invalid_infrastructure
        .combined_scope_candidate(TARGET)
        .unwrap();
    candidate
        .replacement
        .infrastructure
        .corrupt_candidate_sequence_for_test(TARGET);
    let before_invalid_infrastructure = invalid_infrastructure.clone();
    __cser_core::assert!(__cser_core::matches!(
        invalid_infrastructure.prepare_combined_scope_install(candidate),
        Err(RegistryError::Infrastructure(
            infrastructure::InfrastructureError::Invariant(_)
        )),
    ));
    __cser_core::assert_eq!(invalid_infrastructure, before_invalid_infrastructure);
    __cser_core::assert!(
        invalid_infrastructure
            .infrastructure
            .is_authoritative_for_test()
    );

    // Root binding is part of the exact infrastructure identity, not a
    // caller-supplied scalar that can be rewritten inside a candidate.
    let (invalid_root, _, unrelated_root) = fixture();
    let mut candidate = invalid_root.combined_scope_candidate(TARGET).unwrap();
    candidate
        .replacement
        .infrastructure
        .corrupt_candidate_root_for_test(TARGET, unrelated_root);
    let before_invalid_root = invalid_root.clone();
    __cser_core::assert!(__cser_core::matches!(
        invalid_root.prepare_combined_scope_install(candidate),
        Err(RegistryError::Invariant(_)),
    ));
    __cser_core::assert_eq!(invalid_root, before_invalid_root);

    // The business Registry's own invariant checker rejects a malformed
    // candidate before either authoritative scope is replaced.
    let (invalid_business, _, _) = fixture();
    let mut candidate = invalid_business.combined_scope_candidate(TARGET).unwrap();
    candidate.replacement.scopes.get_mut(&TARGET).unwrap().key = ScopeKey::new(0xc0ff, 1);
    let before_invalid_business = invalid_business.clone();
    __cser_core::assert!(__cser_core::matches!(
        invalid_business.prepare_combined_scope_install(candidate),
        Err(RegistryError::Invariant(_)),
    ));
    __cser_core::assert_eq!(invalid_business, before_invalid_business);

    // A fallible staging step is also failure-atomic: no install plan exists
    // until the closure returns success and both validation gates pass.
    let (mut stage_failure, _, _) = fixture();
    let before_stage_failure = stage_failure.clone();
    __cser_core::assert_eq!(
        stage_failure.combined_scope_transaction(TARGET, |_| Err(RegistryError::InvalidState)),
        Err(RegistryError::InvalidState),
    );
    __cser_core::assert_eq!(stage_failure, before_stage_failure);

    // This foundation is deliberately shape-preserving.  A global allocator
    // or target EffectRecord change is rejected rather than partly installed.
    let (changed_shape, _, _) = fixture();
    let mut candidate = changed_shape.combined_scope_candidate(TARGET).unwrap();
    candidate.replacement.next_effect_id += 1;
    let before_changed_shape = changed_shape.clone();
    __cser_core::assert!(__cser_core::matches!(
        changed_shape.prepare_combined_scope_install(candidate),
        Err(RegistryError::CombinedCandidateShapeChanged),
    ));
    __cser_core::assert_eq!(changed_shape, before_changed_shape);

    // Success replaces exactly the target business scope and target
    // infrastructure scope.  Effect records, allocators, and the unrelated
    // business/infrastructure projections remain unchanged.
    let (mut success, target_root, unrelated_root) = fixture();
    let target_effect_before = success.effects[&target_root].clone();
    let unrelated_scope_before = success.scopes[&UNRELATED].clone();
    let unrelated_effect_before = success.effects[&unrelated_root].clone();
    let unrelated_infrastructure_before = success.infrastructure.root_binding(UNRELATED).unwrap();
    let target_registry_revision = success.scopes[&TARGET].revision;
    let target_infrastructure_revision = success
        .infrastructure
        .root_binding(TARGET)
        .unwrap()
        .revision;
    let allocator_projection = (
        success.next_effect_id,
        success.next_nonce,
        success.next_commit_sequence,
        success.next_terminal_sequence,
        success.next_publication_sequence,
        success.next_revoke_sequence,
    );
    success
        .combined_scope_transaction(TARGET, |editor| editor.advance_scope_revisions())
        .unwrap();
    __cser_core::assert_eq!(
        success.scopes[&TARGET].revision,
        target_registry_revision + 1
    );
    __cser_core::assert_eq!(
        success
            .infrastructure
            .root_binding(TARGET)
            .unwrap()
            .revision,
        target_infrastructure_revision + 1,
    );
    __cser_core::assert_eq!(success.effects[&target_root], target_effect_before);
    __cser_core::assert_eq!(success.scopes[&UNRELATED], unrelated_scope_before);
    __cser_core::assert_eq!(success.effects[&unrelated_root], unrelated_effect_before);
    __cser_core::assert_eq!(
        success.infrastructure.root_binding(UNRELATED).unwrap(),
        unrelated_infrastructure_before,
    );
    __cser_core::assert_eq!(
        (
            success.next_effect_id,
            success.next_nonce,
            success.next_commit_sequence,
            success.next_terminal_sequence,
            success.next_publication_sequence,
            success.next_revoke_sequence,
        ),
        allocator_projection,
    );
    __cser_core::assert!(success.infrastructure.is_authoritative_for_test());
    success.check_invariants().unwrap();
}

/// Pins the first registry-native production identity chain independently of
/// the later runtime wiring.  These are real registry records with one shared
/// credit ledger, distinct service bindings, and immutable effect ancestry;
/// no synthetic cohort or side ledger is constructed for the assertion.
pub(crate) fn production_identity_registry_self_test() {
    #[cfg(test)]
    combined_scope_candidate_self_test();
    publication_ack_and_revoke_complete_self_test();

    const PERSONALITY_CREDIT: CreditClass = CreditClass::new(0x201);
    const FILESYSTEM_CREDIT: CreditClass = CreditClass::new(0x202);
    const BLOCK_CREDIT: CreditClass = CreditClass::new(0x203);
    const UNRELATED_CREDIT: CreditClass = CreditClass::new(0x204);

    const PERSONALITY_DOMAIN: DomainKey = DomainKey::new(1);
    const FILESYSTEM_DOMAIN: DomainKey = DomainKey::new(2);
    const BLOCK_DOMAIN: DomainKey = DomainKey::new(3);

    let scope = ScopeKey::new(0x200, 1);
    let legacy_supervisor = TaskKey::new(0x200, 1);
    let personality_supervisor = TaskKey::new(0x201, 1);
    let filesystem_v1 = TaskKey::new(0x202, 1);
    let filesystem_v2 = TaskKey::new(0x202, 2);
    let block_supervisor = TaskKey::new(0x203, 1);
    let personality_task = TaskKey::new(0x211, 1);
    let filesystem_task = TaskKey::new(0x212, 1);
    let block_task = TaskKey::new(0x213, 1);
    let personality_resource = ResourceKey::new(0x20, 1, 1);
    let filesystem_resource = ResourceKey::new(0x20, 2, 1);
    let block_resource = ResourceKey::new(0x20, 3, 1);

    let unrelated_scope = ScopeKey::new(0x2ff, 1);
    let unrelated_supervisor = TaskKey::new(0x2ff, 1);
    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: scope,
            authority_epoch: 7,
            binding_epoch: 1,
            supervisor: legacy_supervisor,
            credits: __cser_alloc::vec![
                CreditLimit::new(PERSONALITY_CREDIT, 1),
                CreditLimit::new(FILESYSTEM_CREDIT, 1),
                CreditLimit::new(BLOCK_CREDIT, 1),
            ],
        })
        .unwrap();
    for config in [
        DomainConfig {
            key: PERSONALITY_DOMAIN,
            binding_epoch: 1,
            supervisor: personality_supervisor,
        },
        DomainConfig {
            key: FILESYSTEM_DOMAIN,
            binding_epoch: 1,
            supervisor: filesystem_v1,
        },
        DomainConfig {
            key: BLOCK_DOMAIN,
            binding_epoch: 1,
            supervisor: block_supervisor,
        },
    ] {
        registry.add_domain(scope, config).unwrap();
    }
    registry
        .create_scope(ScopeConfig {
            key: unrelated_scope,
            authority_epoch: 9,
            binding_epoch: 1,
            supervisor: unrelated_supervisor,
            credits: __cser_alloc::vec![CreditLimit::new(UNRELATED_CREDIT, 1)],
        })
        .unwrap();
    let unrelated = registry
        .register(RegisterRequest {
            scope: unrelated_scope,
            task: unrelated_supervisor,
            operation: OperationClass::new(0x2ff),
            descriptor: SyscallDescriptor::new(0x2ff, [0; 6]),
            resources: __cser_alloc::vec![ResourceKey::new(0x2f, 1, 1)],
            credits: __cser_alloc::vec![CreditCharge::new(UNRELATED_CREDIT, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();

    let personality = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope,
                task: personality_task,
                operation: OperationClass::new(0x201),
                descriptor: SyscallDescriptor::new(0, [17, 0, 0, 0, 0, 0]),
                resources: __cser_alloc::vec![personality_resource],
                credits: __cser_alloc::vec![CreditCharge::new(PERSONALITY_CREDIT, 1)],
                publication: PublicationMode::None,
            },
            domain: PERSONALITY_DOMAIN,
            parent: None,
        })
        .unwrap();
    let filesystem = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope,
                task: filesystem_task,
                operation: OperationClass::new(0x202),
                descriptor: SyscallDescriptor::new(17, [3, 0x1000, 4096, 0, 0, 0]),
                resources: __cser_alloc::vec![filesystem_resource],
                credits: __cser_alloc::vec![CreditCharge::new(FILESYSTEM_CREDIT, 1)],
                publication: PublicationMode::None,
            },
            domain: FILESYSTEM_DOMAIN,
            parent: Some(personality.identity.effect()),
        })
        .unwrap();
    let block = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope,
                task: block_task,
                operation: OperationClass::new(0x203),
                descriptor: SyscallDescriptor::new(0x203, [0, 8, 0x1000, 4096, 0, 0]),
                resources: __cser_alloc::vec![block_resource],
                credits: __cser_alloc::vec![CreditCharge::new(BLOCK_CREDIT, 1)],
                publication: PublicationMode::None,
            },
            domain: BLOCK_DOMAIN,
            parent: Some(filesystem.identity.effect()),
        })
        .unwrap();

    __cser_core::assert_eq!(personality.identity.scope(), scope);
    __cser_core::assert_eq!(filesystem.identity.scope(), scope);
    __cser_core::assert_eq!(block.identity.scope(), scope);
    __cser_core::assert_eq!(personality.identity.domain(), PERSONALITY_DOMAIN);
    __cser_core::assert_eq!(filesystem.identity.domain(), FILESYSTEM_DOMAIN);
    __cser_core::assert_eq!(block.identity.domain(), BLOCK_DOMAIN);
    __cser_core::assert_eq!(personality.identity.parent(), None);
    __cser_core::assert_eq!(
        filesystem.identity.parent(),
        Some(personality.identity.effect())
    );
    __cser_core::assert_eq!(block.identity.parent(), Some(filesystem.identity.effect()));

    registry
        .prepare(personality_supervisor, personality.handle)
        .unwrap();
    registry.prepare(filesystem_v1, filesystem.handle).unwrap();
    registry.prepare(block_supervisor, block.handle).unwrap();
    registry.check_invariants().unwrap();

    let before_adopt = registry.effect_view(filesystem.identity.effect()).unwrap();
    let crash = registry
        .crash_domain(scope, FILESYSTEM_DOMAIN, filesystem_v1)
        .unwrap();
    __cser_core::assert_eq!(crash.cohort, BTreeSet::from([filesystem.identity.effect()]));
    let before_stale_parent = registry.clone();
    __cser_core::assert_eq!(
        registry.register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope,
                task: block_task,
                operation: OperationClass::new(0x204),
                descriptor: SyscallDescriptor::new(0x204, [0; 6]),
                resources: __cser_alloc::vec![ResourceKey::new(0x20, 4, 1)],
                credits: __cser_alloc::vec![CreditCharge::new(BLOCK_CREDIT, 1)],
                publication: PublicationMode::None,
            },
            domain: BLOCK_DOMAIN,
            parent: Some(filesystem.identity.effect()),
        }),
        Err(RegistryError::StaleBinding)
    );
    __cser_core::assert_eq!(registry, before_stale_parent);
    __cser_core::assert_eq!(
        registry
            .domain_projection(scope, PERSONALITY_DOMAIN)
            .unwrap()
            .supervisor,
        Some(personality_supervisor)
    );
    __cser_core::assert_eq!(
        registry
            .domain_projection(scope, BLOCK_DOMAIN)
            .unwrap()
            .supervisor,
        Some(block_supervisor)
    );
    let snapshot = registry
        .domain_recovery_snapshot(scope, FILESYSTEM_DOMAIN, filesystem_v2)
        .unwrap();
    __cser_core::assert_eq!(snapshot.effects.len(), 1);
    __cser_core::assert_eq!(snapshot.effects[0].effect, filesystem.identity.effect());
    registry
        .domain_ready(scope, FILESYSTEM_DOMAIN, filesystem_v2, &snapshot)
        .unwrap();
    registry
        .rebind_domain(scope, FILESYSTEM_DOMAIN, filesystem_v2)
        .unwrap();
    let recovery = registry
        .recover_next_domain(scope, FILESYSTEM_DOMAIN, filesystem_v2)
        .unwrap()
        .unwrap();
    __cser_core::assert_eq!(recovery.handle.effect(), filesystem.identity.effect());
    let filesystem_v2_handle = registry
        .adopt_domain(scope, FILESYSTEM_DOMAIN, filesystem_v2, recovery.handle)
        .unwrap();
    __cser_core::assert_eq!(
        registry.domain_recovery_remaining(scope, FILESYSTEM_DOMAIN),
        Ok(0)
    );
    let after_adopt = registry.effect_view(filesystem.identity.effect()).unwrap();
    __cser_core::assert_eq!(
        after_adopt.identity.effect(),
        before_adopt.identity.effect()
    );
    __cser_core::assert_eq!(after_adopt.identity.scope(), before_adopt.identity.scope());
    __cser_core::assert_eq!(
        after_adopt.identity.domain(),
        before_adopt.identity.domain()
    );
    __cser_core::assert_eq!(
        after_adopt.identity.parent(),
        before_adopt.identity.parent()
    );
    __cser_core::assert_eq!(after_adopt.identity.task(), before_adopt.identity.task());
    __cser_core::assert_eq!(
        after_adopt.identity.operation(),
        before_adopt.identity.operation()
    );
    __cser_core::assert_eq!(
        after_adopt.identity.authority_epoch(),
        before_adopt.identity.authority_epoch()
    );
    __cser_core::assert_eq!(
        after_adopt.identity.origin_binding_epoch(),
        before_adopt.identity.origin_binding_epoch()
    );
    __cser_core::assert_eq!(
        after_adopt.identity.resources(),
        before_adopt.identity.resources()
    );
    __cser_core::assert_eq!(
        after_adopt.current_resources,
        before_adopt.current_resources
    );
    __cser_core::assert_eq!(after_adopt.identity.binding_epoch(), 2);
    __cser_core::assert_eq!(
        registry.descriptor(filesystem_v2, filesystem.handle),
        Err(RegistryError::StaleBinding)
    );
    registry
        .descriptor(filesystem_v2, filesystem_v2_handle)
        .unwrap();
    registry
        .descriptor(personality_supervisor, personality.handle)
        .unwrap();
    registry.descriptor(block_supervisor, block.handle).unwrap();
    registry.check_invariants().unwrap();

    let selection = registry.revoke_begin(scope).unwrap();
    __cser_core::assert_eq!(selection.target_count, 3);
    for domain in [PERSONALITY_DOMAIN, FILESYSTEM_DOMAIN, BLOCK_DOMAIN] {
        let projection = registry.domain_projection(scope, domain).unwrap();
        __cser_core::assert_eq!(projection.supervisor, None);
        __cser_core::assert!(!projection.fallback_running);
    }
    let before_rejected_commits = registry.clone();
    for (sender, handle) in [
        (personality_supervisor, personality.handle),
        (filesystem_v2, filesystem_v2_handle),
        (block_supervisor, block.handle),
    ] {
        __cser_core::assert_eq!(
            registry.commit(sender, handle, CommitMetadata::new(0, 0)),
            Err(RegistryError::StaleAuthority)
        );
    }
    __cser_core::assert_eq!(registry, before_rejected_commits);

    for expected in [
        block.identity.effect(),
        filesystem.identity.effect(),
        personality.identity.effect(),
    ] {
        let next = registry.revoke_next(&selection).unwrap().unwrap();
        __cser_core::assert_eq!(next.effect, expected);
        __cser_core::assert_eq!(next.disposition, RevokeDisposition::Abort);
        let terminal = registry
            .stage_revoke_terminal(&selection, expected, TerminalRequest::aborted(-125))
            .unwrap();
        __cser_core::assert_eq!(terminal.receipt.effect(), expected);
        __cser_core::assert!(terminal.publication.is_none());
    }
    __cser_core::assert!(registry.revoke_next(&selection).unwrap().is_none());
    registry.revoke_complete(&selection).unwrap();
    let target = registry.scope_projection(scope).unwrap();
    __cser_core::assert_eq!(target.phase, ScopePhase::Revoked);
    __cser_core::assert_eq!(target.credits.capacity, 3);
    __cser_core::assert_eq!(target.credits.free, 3);
    __cser_core::assert_eq!(target.credits.held, 0);
    __cser_core::assert_eq!(target.credits.committed, 0);
    let work = registry.revoke_work_projection(&selection).unwrap();
    __cser_core::assert_eq!(work.target_count, 3);
    __cser_core::assert_eq!(work.terminalized, 3);
    __cser_core::assert_eq!(work.target_index_removals, 3);
    __cser_core::assert_eq!(work.unrelated_effect_visits, 0);
    __cser_core::assert_eq!(work.history_effect_visits, 0);
    __cser_core::assert_eq!(registry.effects_for_scope(unrelated_scope).len(), 1);

    registry
        .stage_terminal(
            unrelated_supervisor,
            unrelated.handle,
            TerminalRequest::aborted(-125),
        )
        .unwrap();
    let unrelated_projection = registry.scope_projection(unrelated_scope).unwrap();
    __cser_core::assert_eq!(unrelated_projection.credits.free, 1);
    __cser_core::assert_eq!(unrelated_projection.credits.held, 0);
    production_device_batch_registry_self_test(&mut registry);
    registry.check_invariants().unwrap();
}

/// Pins the exact production transition source used by the same-boot device
/// successor: six workload effects, four device-enveloped effects, one root
/// authority, and one publish closure. All negative fixtures clone this same
/// registry state; none creates a detached evaluator registry or ledger.
fn production_device_batch_registry_self_test(registry: &mut EffectRegistry) {
    use __cser_core::cell::Cell;

    const SCOPE: ScopeKey = ScopeKey::new(0x300, 1);
    const ROOT_OWNER: TaskKey = TaskKey::new(0x300, 1);
    const PERSONALITY: TaskKey = TaskKey::new(0x301, 1);
    const FILESYSTEM: TaskKey = TaskKey::new(0x302, 1);
    const VIRTIO: TaskKey = TaskKey::new(0x303, 1);
    const PERSONALITY_DOMAIN: DomainKey = DomainKey::new(1);
    const FILESYSTEM_DOMAIN: DomainKey = DomainKey::new(2);
    const VIRTIO_DOMAIN: DomainKey = DomainKey::new(3);
    const CONTROL: CreditClass = CreditClass::new(0x301);
    const FILESYSTEM_OP: CreditClass = CreditClass::new(0x302);
    const QUEUE_SLOT: CreditClass = CreditClass::new(0x303);
    const DMA_OWNER: CreditClass = CreditClass::new(0x304);

    let device = DeviceEnvelope::new(0x51, 0, 0, 1).unwrap();
    registry
        .create_scope(ScopeConfig {
            key: SCOPE,
            authority_epoch: 17,
            binding_epoch: 1,
            supervisor: ROOT_OWNER,
            credits: __cser_alloc::vec![
                CreditLimit::new(CONTROL, 2),
                CreditLimit::new(FILESYSTEM_OP, 1),
                CreditLimit::new(QUEUE_SLOT, 1),
                CreditLimit::new(DMA_OWNER, 3),
            ],
        })
        .unwrap();
    for config in [
        DomainConfig {
            key: PERSONALITY_DOMAIN,
            binding_epoch: 1,
            supervisor: PERSONALITY,
        },
        DomainConfig {
            key: FILESYSTEM_DOMAIN,
            binding_epoch: 1,
            supervisor: FILESYSTEM,
        },
        DomainConfig {
            key: VIRTIO_DOMAIN,
            binding_epoch: 1,
            supervisor: VIRTIO,
        },
    ] {
        registry.add_domain(SCOPE, config).unwrap();
    }

    let mut non_device_candidate = registry.clone_non_device_candidate().unwrap();
    __cser_core::assert_eq!(
        non_device_candidate.kernel_root_authority(SCOPE, ROOT_OWNER),
        Err(RegistryError::InvalidDeviceEnvelope)
    );
    let non_device_before_registration = non_device_candidate.clone();
    __cser_core::assert_eq!(
        non_device_candidate.register_device_derived(DeviceDerivedRegisterRequest {
            derived: DerivedRegisterRequest {
                request: RegisterRequest {
                    scope: SCOPE,
                    task: VIRTIO,
                    operation: OperationClass::new(3),
                    descriptor: SyscallDescriptor::new(3, [0, 0, 512, 0, 0, 0]),
                    resources: __cser_alloc::vec![ResourceKey::new(0x31, 3, 1)],
                    credits: __cser_alloc::vec![CreditCharge::new(QUEUE_SLOT, 1)],
                    publication: PublicationMode::None,
                },
                domain: VIRTIO_DOMAIN,
                parent: None,
            },
            device,
        }),
        Err(RegistryError::InvalidDeviceEnvelope)
    );
    __cser_core::assert_eq!(non_device_candidate, non_device_before_registration);
    non_device_candidate.check_invariants().unwrap();

    let syscall = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: PERSONALITY,
                operation: OperationClass::new(1),
                descriptor: SyscallDescriptor::new(17, [3, 0x1000, 4, 0, 0, 0]),
                resources: __cser_alloc::vec![ResourceKey::new(0x31, 1, 1)],
                credits: __cser_alloc::vec![CreditCharge::new(CONTROL, 1)],
                publication: PublicationMode::None,
            },
            domain: PERSONALITY_DOMAIN,
            parent: None,
        })
        .unwrap();
    let filesystem = registry
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: FILESYSTEM,
                operation: OperationClass::new(2),
                descriptor: SyscallDescriptor::new(17, [3, 0x1000, 4, 0, 0, 0]),
                resources: __cser_alloc::vec![ResourceKey::new(0x31, 2, 1)],
                credits: __cser_alloc::vec![CreditCharge::new(FILESYSTEM_OP, 1)],
                publication: PublicationMode::None,
            },
            domain: FILESYSTEM_DOMAIN,
            parent: Some(syscall.identity.effect()),
        })
        .unwrap();
    __cser_core::assert_eq!(registry.device_root_installed(SCOPE), Ok(false));
    __cser_core::assert_eq!(
        registry.device_root_installed(ScopeKey::new(0xdead, 1)),
        Err(RegistryError::UnknownScope)
    );
    let device_cohort = || {
        [
            DeviceDerivedCohortEntry {
                batch_index: 0,
                request: RegisterRequest {
                    scope: SCOPE,
                    task: VIRTIO,
                    operation: OperationClass::new(3),
                    descriptor: SyscallDescriptor::new(3, [0, 0, 512, 0, 0, 0]),
                    resources: __cser_alloc::vec![ResourceKey::new(0x31, 3, 1)],
                    credits: __cser_alloc::vec![CreditCharge::new(QUEUE_SLOT, 1)],
                    publication: PublicationMode::None,
                },
                domain: VIRTIO_DOMAIN,
                parent: DeviceCohortParent::Existing(filesystem.identity.effect()),
                device,
            },
            DeviceDerivedCohortEntry {
                batch_index: 1,
                request: RegisterRequest {
                    scope: SCOPE,
                    task: VIRTIO,
                    operation: OperationClass::new(4),
                    descriptor: SyscallDescriptor::new(4, [0; 6]),
                    resources: __cser_alloc::vec![ResourceKey::new(0x31, 4, 1)],
                    credits: __cser_alloc::vec![CreditCharge::new(DMA_OWNER, 1)],
                    publication: PublicationMode::None,
                },
                domain: VIRTIO_DOMAIN,
                parent: DeviceCohortParent::BatchIndex(0),
                device,
            },
            DeviceDerivedCohortEntry {
                batch_index: 2,
                request: RegisterRequest {
                    scope: SCOPE,
                    task: VIRTIO,
                    operation: OperationClass::new(5),
                    descriptor: SyscallDescriptor::new(5, [0; 6]),
                    resources: __cser_alloc::vec![ResourceKey::new(0x31, 5, 1)],
                    credits: __cser_alloc::vec![CreditCharge::new(DMA_OWNER, 1)],
                    publication: PublicationMode::None,
                },
                domain: VIRTIO_DOMAIN,
                parent: DeviceCohortParent::BatchIndex(0),
                device,
            },
            DeviceDerivedCohortEntry {
                batch_index: 3,
                request: RegisterRequest {
                    scope: SCOPE,
                    task: VIRTIO,
                    operation: OperationClass::new(6),
                    descriptor: SyscallDescriptor::new(6, [0; 6]),
                    resources: __cser_alloc::vec![ResourceKey::new(0x31, 6, 1)],
                    credits: __cser_alloc::vec![CreditCharge::new(DMA_OWNER, 1)],
                    publication: PublicationMode::None,
                },
                domain: VIRTIO_DOMAIN,
                parent: DeviceCohortParent::BatchIndex(0),
                device,
            },
        ]
    };
    let reject_cohort =
        |label: &str, entries: [DeviceDerivedCohortEntry; 4], expected: RegistryError| {
            let mut negative = registry.clone();
            let before = negative.clone();
            __cser_core::assert_eq!(
                negative.register_device_derived_cohort(entries),
                Err(expected),
                "{label}"
            );
            __cser_core::assert_eq!(negative, before, "{label}");
        };

    let mut credit_failure = device_cohort();
    credit_failure[1].request.credits = __cser_alloc::vec![CreditCharge::new(DMA_OWNER, 4)];
    reject_cohort(
        "middle credit",
        credit_failure,
        RegistryError::CreditExhausted,
    );

    let mut resource_failure = device_cohort();
    resource_failure[1].request.resources = __cser_alloc::vec![ResourceKey::new(0x31, 4, 0)];
    reject_cohort(
        "middle resource",
        resource_failure,
        RegistryError::InvalidGeneration,
    );

    let mut ancestry_failure = device_cohort();
    ancestry_failure[1].parent = DeviceCohortParent::Existing(filesystem.identity.effect());
    reject_cohort(
        "middle ancestry",
        ancestry_failure,
        RegistryError::InvalidState,
    );

    let mut device_failure = device_cohort();
    device_failure[1].device = DeviceEnvelope::new(0x51, 0, 0, 2).unwrap();
    reject_cohort(
        "middle device",
        device_failure,
        RegistryError::StaleDeviceGeneration,
    );

    let mut forward_parent = device_cohort();
    forward_parent[1].parent = DeviceCohortParent::BatchIndex(2);
    reject_cohort(
        "forward parent",
        forward_parent,
        RegistryError::InvalidState,
    );

    let mut self_parent = device_cohort();
    self_parent[1].parent = DeviceCohortParent::BatchIndex(1);
    reject_cohort("self parent", self_parent, RegistryError::InvalidState);

    let mut invalid_parent = device_cohort();
    invalid_parent[1].parent = DeviceCohortParent::BatchIndex(4);
    reject_cohort(
        "invalid parent",
        invalid_parent,
        RegistryError::InvalidState,
    );

    let mut duplicate_slot = device_cohort();
    duplicate_slot[2].batch_index = 1;
    reject_cohort(
        "duplicate slot",
        duplicate_slot,
        RegistryError::InvalidState,
    );

    let mut missing_slot = device_cohort();
    missing_slot[3].batch_index = 4;
    reject_cohort("missing slot", missing_slot, RegistryError::InvalidState);

    let mut counter_failure = registry.clone();
    counter_failure.next_effect_id = u64::MAX - 1;
    let counter_before = counter_failure.clone();
    __cser_core::assert_eq!(
        counter_failure.register_device_derived_cohort(device_cohort()),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(counter_failure, counter_before);

    let mut disabled_cohort = registry.clone_non_device_candidate().unwrap();
    let disabled_cohort_before = disabled_cohort.clone();
    __cser_core::assert_eq!(
        disabled_cohort.register_device_derived_cohort(device_cohort()),
        Err(RegistryError::InvalidDeviceEnvelope)
    );
    __cser_core::assert_eq!(disabled_cohort, disabled_cohort_before);

    let [block, dma_a, dma_b, dma_request] = registry
        .register_device_derived_cohort(device_cohort())
        .unwrap();
    __cser_core::assert_eq!(registry.device_root_installed(SCOPE), Ok(true));
    __cser_core::assert!(__cser_core::matches!(
        registry.clone_non_device_candidate(),
        Err(RegistryError::InvalidDeviceEnvelope)
    ));

    let registered = [&syscall, &filesystem, &block, &dma_a, &dma_b, &dma_request];
    __cser_core::assert_eq!(block.identity.parent(), Some(filesystem.identity.effect()));
    for dma in [&dma_a, &dma_b, &dma_request] {
        __cser_core::assert_eq!(dma.identity.parent(), Some(block.identity.effect()));
    }
    for (sender, effect) in [
        (PERSONALITY, &syscall),
        (FILESYSTEM, &filesystem),
        (VIRTIO, &block),
        (VIRTIO, &dma_a),
        (VIRTIO, &dma_b),
        (VIRTIO, &dma_request),
    ] {
        registry.prepare(sender, effect.handle).unwrap();
    }
    __cser_core::assert_eq!(registry.effects_for_scope(SCOPE).len(), 6);
    __cser_core::assert_eq!(
        registered
            .iter()
            .filter(|effect| effect.identity.device.is_some())
            .count(),
        4
    );
    registry.check_invariants().unwrap();

    let authority = registry.kernel_root_authority(SCOPE, ROOT_OWNER).unwrap();
    let commits = [
        (syscall.handle, CommitMetadata::new(4, 1)),
        (filesystem.handle, CommitMetadata::new(4, 1)),
        (block.handle, CommitMetadata::new(512, 1)),
        (dma_a.handle, CommitMetadata::new(1, 1)),
        (dma_b.handle, CommitMetadata::new(1, 1)),
        (dma_request.handle, CommitMetadata::new(1, 1)),
    ];
    let handles = [
        syscall.handle,
        filesystem.handle,
        block.handle,
        dma_a.handle,
        dma_b.handle,
        dma_request.handle,
    ];

    let mut disabled_enrollment = registry.clone();
    disabled_enrollment.device_publication_mode = DevicePublicationMode::DisabledNonDeviceCandidate;
    let disabled_enrollment_before = disabled_enrollment.clone();
    __cser_core::assert_eq!(
        disabled_enrollment.enroll_device_batch(authority, &handles, device),
        Err(RegistryError::InvalidDeviceEnvelope)
    );
    __cser_core::assert_eq!(disabled_enrollment, disabled_enrollment_before);

    for (label, wrong_device, expected) in [
        (
            "generation",
            DeviceEnvelope::new(0x51, 0, 0, 2).unwrap(),
            RegistryError::StaleDeviceGeneration,
        ),
        (
            "session",
            DeviceEnvelope::new(0x52, 0, 0, 1).unwrap(),
            RegistryError::InvalidBatchReceipt,
        ),
        (
            "queue",
            DeviceEnvelope::new(0x51, 1, 0, 1).unwrap(),
            RegistryError::InvalidBatchReceipt,
        ),
        (
            "descriptor",
            DeviceEnvelope::new(0x51, 0, 1, 1).unwrap(),
            RegistryError::InvalidBatchReceipt,
        ),
    ] {
        let mut negative = registry.clone();
        let before = negative.clone();
        let result = negative.enroll_device_batch(authority, &handles, wrong_device);
        __cser_core::assert!(
            __cser_core::matches!(result, Err(error) if error == expected),
            "{label}"
        );
        __cser_core::assert_eq!(negative, before, "{label}");
    }

    let mut missing = registry.clone();
    let missing_before = missing.clone();
    __cser_core::assert!(__cser_core::matches!(
        missing.enroll_device_batch(authority, &handles[..handles.len() - 1], device),
        Err(RegistryError::InvalidState)
    ));
    __cser_core::assert_eq!(missing, missing_before);

    let mut wrong_ancestry = registry.clone();
    let ancestry_before = wrong_ancestry.clone();
    __cser_core::assert_eq!(
        wrong_ancestry.register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: PERSONALITY,
                operation: OperationClass::new(7),
                descriptor: SyscallDescriptor::new(7, [0; 6]),
                resources: __cser_alloc::vec![ResourceKey::new(0x31, 7, 1)],
                credits: __cser_alloc::vec![CreditCharge::new(CONTROL, 1)],
                publication: PublicationMode::None,
            },
            domain: PERSONALITY_DOMAIN,
            parent: None,
        }),
        Err(RegistryError::InvalidState)
    );
    __cser_core::assert_eq!(wrong_ancestry, ancestry_before);

    // Merely deriving a device child reserves the whole root. A non-device
    // ancestor cannot acquire a partial authoritative commit before explicit
    // enrollment or hardware publication.
    let mut split = registry.clone();
    let split_before = split.clone();
    __cser_core::assert_eq!(
        split.commit(PERSONALITY, syscall.handle, commits[0].1),
        Err(RegistryError::InvalidDeviceEnvelope)
    );
    __cser_core::assert_eq!(split, split_before);

    // Conversely, a service cannot attach a device-derived child beneath an
    // ancestor that was already committed through the generic path.
    let mut attached_after_commit = registry.clone();
    let attach_scope = ScopeKey::new(0x310, 1);
    let attach_owner = TaskKey::new(0x310, 1);
    let attach_service = TaskKey::new(0x311, 1);
    let attach_domain = DomainKey::new(1);
    attached_after_commit
        .create_scope(ScopeConfig {
            key: attach_scope,
            authority_epoch: 1,
            binding_epoch: 1,
            supervisor: attach_owner,
            credits: __cser_alloc::vec![CreditLimit::new(CONTROL, 2)],
        })
        .unwrap();
    attached_after_commit
        .add_domain(
            attach_scope,
            DomainConfig {
                key: attach_domain,
                binding_epoch: 1,
                supervisor: attach_service,
            },
        )
        .unwrap();
    let committed_parent = attached_after_commit
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: attach_scope,
                task: attach_service,
                operation: OperationClass::new(1),
                descriptor: SyscallDescriptor::new(1, [0; 6]),
                resources: __cser_alloc::vec![],
                credits: __cser_alloc::vec![CreditCharge::new(CONTROL, 1)],
                publication: PublicationMode::None,
            },
            domain: attach_domain,
            parent: None,
        })
        .unwrap();
    attached_after_commit
        .prepare(attach_service, committed_parent.handle)
        .unwrap();
    attached_after_commit
        .commit(
            attach_service,
            committed_parent.handle,
            CommitMetadata::new(0, 0),
        )
        .unwrap();
    let attach_before = attached_after_commit.clone();
    __cser_core::assert_eq!(
        attached_after_commit.register_device_derived(DeviceDerivedRegisterRequest {
            derived: DerivedRegisterRequest {
                request: RegisterRequest {
                    scope: attach_scope,
                    task: attach_service,
                    operation: OperationClass::new(2),
                    descriptor: SyscallDescriptor::new(2, [0; 6]),
                    resources: __cser_alloc::vec![],
                    credits: __cser_alloc::vec![CreditCharge::new(CONTROL, 1)],
                    publication: PublicationMode::None,
                },
                domain: attach_domain,
                parent: Some(committed_parent.identity.effect()),
            },
            device,
        }),
        Err(RegistryError::InvalidState)
    );
    __cser_core::assert_eq!(attached_after_commit, attach_before);

    // If revoke wins the device-root/enrollment window, generic Abort remains
    // blocked. A Closing-only emergency freeze records the exact prepared live
    // cohort as cancel-only before ownership can be retained and closed.
    let mut pending_direct = registry.clone();
    let pending_direct_before = pending_direct.clone();
    __cser_core::assert_eq!(
        pending_direct.stage_terminal(VIRTIO, dma_a.handle, TerminalRequest::aborted(-125),),
        Err(RegistryError::DeviceClosurePending)
    );
    __cser_core::assert_eq!(pending_direct, pending_direct_before);

    let assert_pending_precommit_error =
        |candidate: &mut EffectRegistry, expected: RegistryError| {
            let before = candidate.clone();
            let hardware_calls = Cell::new(0_u8);
            __cser_core::assert_eq!(
                candidate.close_pending_device_precommit_with_apply(SCOPE, |_| {
                    hardware_calls.set(hardware_calls.get().checked_add(1).unwrap())
                }),
                Err(expected)
            );
            __cser_core::assert_eq!(hardware_calls.get(), 0);
            __cser_core::assert_eq!(*candidate, before);
        };

    let mut compound_pending = registry.clone();
    let compound_pending_before = compound_pending.scope_projection(SCOPE).unwrap();
    let compound_pending_revoke_sequence = compound_pending.next_revoke_sequence;
    let compound_pending_enrollment_sequence = compound_pending.next_device_enrollment_sequence;
    let compound_pending_closure_sequence = compound_pending.next_device_closure_sequence;
    let compound_pending_hardware_calls = Cell::new(0_u8);
    let (compound_pending_close, compound_pending_hardware) = compound_pending
        .close_pending_device_precommit_with_apply(SCOPE, |ticket| {
            compound_pending_hardware_calls.set(
                compound_pending_hardware_calls
                    .get()
                    .checked_add(1)
                    .unwrap(),
            );
            __cser_core::assert_eq!(ticket.batch_sequence, None);
            __cser_core::assert_eq!(ticket.device(), device);
            ticket.sequence
        })
        .unwrap();
    __cser_core::assert_eq!(compound_pending_hardware_calls.get(), 1);
    __cser_core::assert_eq!(
        compound_pending_hardware,
        compound_pending_close.reset_ticket.sequence
    );
    __cser_core::assert_eq!(compound_pending_close.selection.scope, SCOPE);
    __cser_core::assert_eq!(compound_pending_close.selection.target_count, 6);
    __cser_core::assert!(compound_pending_close.enrollment.cancel_only());
    __cser_core::assert_eq!(compound_pending_close.enrollment.effects().len(), 6);
    __cser_core::assert_eq!(
        compound_pending
            .scope_projection(SCOPE)
            .unwrap()
            .authority_epoch,
        compound_pending_before.authority_epoch + 1
    );
    __cser_core::assert_eq!(
        compound_pending.scope_projection(SCOPE).unwrap().revision,
        compound_pending_before.revision + 3
    );
    __cser_core::assert_eq!(
        compound_pending.next_revoke_sequence,
        compound_pending_revoke_sequence + 1
    );
    __cser_core::assert_eq!(
        compound_pending.next_device_enrollment_sequence,
        compound_pending_enrollment_sequence + 1
    );
    __cser_core::assert_eq!(
        compound_pending.next_device_closure_sequence,
        compound_pending_closure_sequence + 1
    );
    let compound_pending_root = compound_pending.scopes[&SCOPE]
        .device_root
        .as_ref()
        .unwrap();
    __cser_core::assert_eq!(
        compound_pending_root.enrollment.as_ref(),
        Some(&compound_pending_close.enrollment)
    );
    __cser_core::assert_eq!(
        compound_pending_root.outcome,
        Some(DeviceClosureResult::AbortedBeforeCommit)
    );
    __cser_core::assert_eq!(
        compound_pending_root.reset_ticket,
        Some(compound_pending_close.reset_ticket)
    );
    let compound_pending_credits = compound_pending.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!(compound_pending_credits.held, 0);
    __cser_core::assert_eq!(compound_pending_credits.retained, 6);
    compound_pending.check_invariants().unwrap();

    let mut pending_revoke_overflow = registry.clone();
    pending_revoke_overflow.next_revoke_sequence = u64::MAX;
    assert_pending_precommit_error(&mut pending_revoke_overflow, RegistryError::CounterOverflow);

    let mut pending_enrollment_overflow = registry.clone();
    pending_enrollment_overflow.next_device_enrollment_sequence = u64::MAX;
    assert_pending_precommit_error(
        &mut pending_enrollment_overflow,
        RegistryError::CounterOverflow,
    );

    let mut pending_closure_overflow = registry.clone();
    pending_closure_overflow.next_device_closure_sequence = u64::MAX;
    assert_pending_precommit_error(
        &mut pending_closure_overflow,
        RegistryError::CounterOverflow,
    );

    for revision in [u64::MAX, u64::MAX - 1, u64::MAX - 2] {
        let mut pending_revision_overflow = registry.clone();
        pending_revision_overflow
            .scopes
            .get_mut(&SCOPE)
            .unwrap()
            .revision = revision;
        assert_pending_precommit_error(
            &mut pending_revision_overflow,
            RegistryError::CounterOverflow,
        );
    }

    let mut pending_authority_overflow = registry.clone();
    pending_authority_overflow
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .authority_epoch = u64::MAX;
    let pending_authority_effects: Vec<_> = pending_authority_overflow.by_scope[&SCOPE]
        .iter()
        .copied()
        .collect();
    for effect in pending_authority_effects {
        pending_authority_overflow
            .effects
            .get_mut(&effect)
            .unwrap()
            .identity
            .authority_epoch = u64::MAX;
    }
    assert_pending_precommit_error(
        &mut pending_authority_overflow,
        RegistryError::CounterOverflow,
    );

    let mut pending_closing = registry.clone();
    pending_closing.revoke_begin(SCOPE).unwrap();
    assert_pending_precommit_error(&mut pending_closing, RegistryError::ScopeNotActive);

    let mut pending_outcome = registry.clone();
    pending_outcome
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .device_root
        .as_mut()
        .unwrap()
        .outcome = Some(DeviceClosureResult::AbortedBeforeCommit);
    assert_pending_precommit_error(&mut pending_outcome, RegistryError::InvalidState);

    let mut pending_credit_state = registry.clone();
    pending_credit_state
        .effects
        .get_mut(&dma_a.identity.effect())
        .unwrap()
        .credit_state = CreditState::Released;
    assert_pending_precommit_error(&mut pending_credit_state, RegistryError::InvalidState);

    let mut pending_retention_overflow = registry.clone();
    pending_retention_overflow
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .credits
        .balances
        .get_mut(&CONTROL)
        .unwrap()
        .retained = u64::MAX;
    assert_pending_precommit_error(
        &mut pending_retention_overflow,
        RegistryError::CounterOverflow,
    );

    let mut pending_wrong_revoke_cohort = registry.clone();
    let pending_wrong_candidates = &mut pending_wrong_revoke_cohort
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .closure_candidates;
    __cser_core::assert!(pending_wrong_candidates.remove(&dma_a.identity.effect()));
    __cser_core::assert!(pending_wrong_candidates.insert(EffectKey::new(u64::MAX, 1)));
    assert_pending_precommit_error(
        &mut pending_wrong_revoke_cohort,
        RegistryError::InvalidState,
    );

    let mut pending_missing_root = registry.clone();
    pending_missing_root
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .device_root = None;
    assert_pending_precommit_error(
        &mut pending_missing_root,
        RegistryError::DeviceBatchNotEnrolled,
    );

    let mut pending_cancel = registry.clone();
    let pending_selection = pending_cancel.revoke_begin(SCOPE).unwrap();
    let pending_head = pending_cancel
        .revoke_next(&pending_selection)
        .unwrap()
        .unwrap();
    let pending_before_abort = pending_cancel.clone();
    __cser_core::assert_eq!(
        pending_cancel.stage_revoke_terminal(
            &pending_selection,
            pending_head.effect,
            TerminalRequest::aborted(-125),
        ),
        Err(RegistryError::DeviceClosurePending)
    );
    __cser_core::assert_eq!(pending_cancel, pending_before_abort);
    let cancel_enrollment = pending_cancel.freeze_pending_device_cancel(SCOPE).unwrap();
    __cser_core::assert!(cancel_enrollment.cancel_only());
    let cancel_ticket = pending_cancel
        .begin_unpublished_device_cancel(&cancel_enrollment)
        .unwrap();
    __cser_core::assert_eq!(
        pending_cancel
            .scope_projection(SCOPE)
            .unwrap()
            .credits
            .retained,
        6
    );
    let (cancel_reset, ()) = pending_cancel
        .acknowledge_device_reset_with_apply(&cancel_ticket, |_| ())
        .unwrap();
    let cancel_iotlb = pending_cancel.begin_device_iotlb(&cancel_reset).unwrap();
    let (cancel_closure, ()) = pending_cancel
        .acknowledge_device_iotlb_with_apply(&cancel_iotlb, |_| ())
        .unwrap();
    __cser_core::assert_eq!(
        cancel_closure.outcome(),
        DeviceClosureResult::AbortedBeforeCommit
    );
    for expected in [
        dma_a.identity.effect(),
        dma_b.identity.effect(),
        dma_request.identity.effect(),
        block.identity.effect(),
        filesystem.identity.effect(),
        syscall.identity.effect(),
    ] {
        let next = pending_cancel
            .revoke_next(&pending_selection)
            .unwrap()
            .unwrap();
        __cser_core::assert_eq!(next.effect, expected);
        pending_cancel
            .stage_device_batch_terminal(&cancel_closure, expected, TerminalRequest::aborted(-125))
            .unwrap();
    }
    pending_cancel.revoke_complete(&pending_selection).unwrap();
    pending_cancel.check_invariants().unwrap();

    let mut registered_cancel = registry.clone();
    let registered_child = registered_cancel
        .register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: PERSONALITY,
                operation: OperationClass::new(8),
                descriptor: SyscallDescriptor::new(8, [0; 6]),
                resources: __cser_alloc::vec![],
                credits: __cser_alloc::vec![CreditCharge::new(CONTROL, 1)],
                publication: PublicationMode::None,
            },
            domain: PERSONALITY_DOMAIN,
            parent: Some(dma_request.identity.effect()),
        })
        .unwrap();
    __cser_core::assert_eq!(
        registered_cancel
            .effect_view(registered_child.identity.effect())
            .unwrap()
            .phase,
        EffectPhase::Registered
    );
    let registered_selection = registered_cancel.revoke_begin(SCOPE).unwrap();
    let registered_enrollment = registered_cancel
        .freeze_pending_device_cancel(SCOPE)
        .unwrap();
    __cser_core::assert!(registered_enrollment.cancel_only());
    __cser_core::assert_eq!(registered_enrollment.effects().len(), 7);
    let registered_ticket = registered_cancel
        .begin_unpublished_device_cancel(&registered_enrollment)
        .unwrap();
    __cser_core::assert_eq!(
        registered_cancel
            .scope_projection(SCOPE)
            .unwrap()
            .credits
            .retained,
        7
    );
    let (registered_reset, ()) = registered_cancel
        .acknowledge_device_reset_with_apply(&registered_ticket, |_| ())
        .unwrap();
    let registered_iotlb = registered_cancel
        .begin_device_iotlb(&registered_reset)
        .unwrap();
    let (registered_closure, ()) = registered_cancel
        .acknowledge_device_iotlb_with_apply(&registered_iotlb, |_| ())
        .unwrap();
    let mut registered_closed = 0_usize;
    while let Some(next) = registered_cancel
        .revoke_next(&registered_selection)
        .unwrap()
    {
        registered_cancel
            .stage_device_batch_terminal(
                &registered_closure,
                next.effect,
                TerminalRequest::aborted(-125),
            )
            .unwrap();
        registered_closed += 1;
    }
    __cser_core::assert_eq!(registered_closed, 7);
    registered_cancel
        .revoke_complete(&registered_selection)
        .unwrap();
    registered_cancel.check_invariants().unwrap();

    let enrollment = registry
        .enroll_device_batch(authority, &handles, device)
        .unwrap();
    __cser_core::assert_eq!(enrollment.scope(), SCOPE);
    __cser_core::assert_eq!(enrollment.enrollment_sequence(), 1);
    __cser_core::assert_eq!(enrollment.device(), device);
    __cser_core::assert_eq!(enrollment.effects().len(), 6);

    let assert_enrolled_precommit_error =
        |candidate: &mut EffectRegistry,
         presented: &DeviceBatchEnrollmentReceipt,
         expected: RegistryError| {
            let before = candidate.clone();
            let hardware_calls = Cell::new(0_u8);
            __cser_core::assert_eq!(
                candidate.close_enrolled_device_precommit_with_apply(presented, |_| {
                    hardware_calls.set(hardware_calls.get().checked_add(1).unwrap())
                }),
                Err(expected)
            );
            __cser_core::assert_eq!(hardware_calls.get(), 0);
            __cser_core::assert_eq!(*candidate, before);
        };

    let mut compound_enrolled = registry.clone();
    let compound_enrolled_before = compound_enrolled.scope_projection(SCOPE).unwrap();
    let compound_enrolled_revoke_sequence = compound_enrolled.next_revoke_sequence;
    let compound_enrolled_enrollment_sequence = compound_enrolled.next_device_enrollment_sequence;
    let compound_enrolled_closure_sequence = compound_enrolled.next_device_closure_sequence;
    let compound_enrolled_hardware_calls = Cell::new(0_u8);
    let (compound_enrolled_close, compound_enrolled_hardware) = compound_enrolled
        .close_enrolled_device_precommit_with_apply(&enrollment, |ticket| {
            compound_enrolled_hardware_calls.set(
                compound_enrolled_hardware_calls
                    .get()
                    .checked_add(1)
                    .unwrap(),
            );
            __cser_core::assert_eq!(ticket.batch_sequence, None);
            __cser_core::assert_eq!(ticket.device(), device);
            ticket.sequence
        })
        .unwrap();
    __cser_core::assert_eq!(compound_enrolled_hardware_calls.get(), 1);
    __cser_core::assert_eq!(
        compound_enrolled_hardware,
        compound_enrolled_close.reset_ticket.sequence
    );
    __cser_core::assert_eq!(compound_enrolled_close.selection.scope, SCOPE);
    __cser_core::assert_eq!(compound_enrolled_close.selection.target_count, 6);
    __cser_core::assert_eq!(compound_enrolled_close.enrollment, enrollment);
    __cser_core::assert!(!compound_enrolled_close.enrollment.cancel_only());
    __cser_core::assert_eq!(
        compound_enrolled
            .scope_projection(SCOPE)
            .unwrap()
            .authority_epoch,
        compound_enrolled_before.authority_epoch + 1
    );
    __cser_core::assert_eq!(
        compound_enrolled.scope_projection(SCOPE).unwrap().revision,
        compound_enrolled_before.revision + 2
    );
    __cser_core::assert_eq!(
        compound_enrolled.next_revoke_sequence,
        compound_enrolled_revoke_sequence + 1
    );
    __cser_core::assert_eq!(
        compound_enrolled.next_device_enrollment_sequence,
        compound_enrolled_enrollment_sequence
    );
    __cser_core::assert_eq!(
        compound_enrolled.next_device_closure_sequence,
        compound_enrolled_closure_sequence + 1
    );
    let compound_enrolled_root = compound_enrolled.scopes[&SCOPE]
        .device_root
        .as_ref()
        .unwrap();
    __cser_core::assert_eq!(
        compound_enrolled_root.enrollment.as_ref(),
        Some(&compound_enrolled_close.enrollment)
    );
    __cser_core::assert_eq!(
        compound_enrolled_root.outcome,
        Some(DeviceClosureResult::AbortedBeforeCommit)
    );
    __cser_core::assert_eq!(
        compound_enrolled_root.reset_ticket,
        Some(compound_enrolled_close.reset_ticket)
    );
    let compound_enrolled_credits = compound_enrolled.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!(compound_enrolled_credits.held, 0);
    __cser_core::assert_eq!(compound_enrolled_credits.retained, 6);
    compound_enrolled.check_invariants().unwrap();

    let mut enrolled_revoke_overflow = registry.clone();
    enrolled_revoke_overflow.next_revoke_sequence = u64::MAX;
    assert_enrolled_precommit_error(
        &mut enrolled_revoke_overflow,
        &enrollment,
        RegistryError::CounterOverflow,
    );

    let mut enrolled_closure_overflow = registry.clone();
    enrolled_closure_overflow.next_device_closure_sequence = u64::MAX;
    assert_enrolled_precommit_error(
        &mut enrolled_closure_overflow,
        &enrollment,
        RegistryError::CounterOverflow,
    );

    for revision in [u64::MAX, u64::MAX - 1] {
        let mut enrolled_revision_overflow = registry.clone();
        enrolled_revision_overflow
            .scopes
            .get_mut(&SCOPE)
            .unwrap()
            .revision = revision;
        assert_enrolled_precommit_error(
            &mut enrolled_revision_overflow,
            &enrollment,
            RegistryError::CounterOverflow,
        );
    }

    let mut enrolled_authority_overflow = registry.clone();
    let mut overflow_enrollment = enrollment.clone();
    overflow_enrollment.authority_epoch = u64::MAX;
    {
        let scope = enrolled_authority_overflow.scopes.get_mut(&SCOPE).unwrap();
        scope.authority_epoch = u64::MAX;
        scope.device_root.as_mut().unwrap().enrollment = Some(overflow_enrollment.clone());
    }
    let enrolled_authority_effects: Vec<_> = enrolled_authority_overflow.by_scope[&SCOPE]
        .iter()
        .copied()
        .collect();
    for effect in enrolled_authority_effects {
        enrolled_authority_overflow
            .effects
            .get_mut(&effect)
            .unwrap()
            .identity
            .authority_epoch = u64::MAX;
    }
    assert_enrolled_precommit_error(
        &mut enrolled_authority_overflow,
        &overflow_enrollment,
        RegistryError::CounterOverflow,
    );

    let mut enrolled_closing = registry.clone();
    enrolled_closing.revoke_begin(SCOPE).unwrap();
    assert_enrolled_precommit_error(
        &mut enrolled_closing,
        &enrollment,
        RegistryError::ScopeNotActive,
    );

    let mut enrolled_wrong_outcome = registry.clone();
    enrolled_wrong_outcome
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .device_root
        .as_mut()
        .unwrap()
        .outcome = Some(DeviceClosureResult::AbortedBeforeCommit);
    assert_enrolled_precommit_error(
        &mut enrolled_wrong_outcome,
        &enrollment,
        RegistryError::InvalidState,
    );

    let mut enrolled_credit_state = registry.clone();
    enrolled_credit_state
        .effects
        .get_mut(&dma_a.identity.effect())
        .unwrap()
        .credit_state = CreditState::Released;
    assert_enrolled_precommit_error(
        &mut enrolled_credit_state,
        &enrollment,
        RegistryError::InvalidState,
    );

    let mut enrolled_retention_overflow = registry.clone();
    enrolled_retention_overflow
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .credits
        .balances
        .get_mut(&CONTROL)
        .unwrap()
        .retained = u64::MAX;
    assert_enrolled_precommit_error(
        &mut enrolled_retention_overflow,
        &enrollment,
        RegistryError::CounterOverflow,
    );

    let mut enrolled_wrong_revoke_cohort = registry.clone();
    let enrolled_wrong_candidates = &mut enrolled_wrong_revoke_cohort
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .closure_candidates;
    __cser_core::assert!(enrolled_wrong_candidates.remove(&dma_a.identity.effect()));
    __cser_core::assert!(enrolled_wrong_candidates.insert(EffectKey::new(u64::MAX, 1)));
    assert_enrolled_precommit_error(
        &mut enrolled_wrong_revoke_cohort,
        &enrollment,
        RegistryError::InvalidState,
    );

    let mut foreign_close_enrollment = enrollment.clone();
    foreign_close_enrollment.registry_instance_id = foreign_close_enrollment
        .registry_instance_id
        .checked_add(1)
        .unwrap();
    let mut enrolled_foreign_receipt = registry.clone();
    assert_enrolled_precommit_error(
        &mut enrolled_foreign_receipt,
        &foreign_close_enrollment,
        RegistryError::InvalidBatchReceipt,
    );

    let mut pending_with_enrollment = registry.clone();
    assert_pending_precommit_error(&mut pending_with_enrollment, RegistryError::InvalidState);

    let enrollment_before_registration = registry.clone();
    __cser_core::assert_eq!(
        registry.register_derived(DerivedRegisterRequest {
            request: RegisterRequest {
                scope: SCOPE,
                task: PERSONALITY,
                operation: OperationClass::new(7),
                descriptor: SyscallDescriptor::new(7, [0; 6]),
                resources: __cser_alloc::vec![],
                credits: __cser_alloc::vec![CreditCharge::new(CONTROL, 1)],
                publication: PublicationMode::None,
            },
            domain: PERSONALITY_DOMAIN,
            parent: None,
        }),
        Err(RegistryError::InvalidState)
    );
    __cser_core::assert_eq!(*registry, enrollment_before_registration);

    let mut foreign_registry = registry.clone();
    foreign_registry.rewrite_registry_instance(registry.instance_id + 1);
    let foreign_before = foreign_registry.clone();
    let foreign_publications = Cell::new(0_u8);
    __cser_core::assert!(__cser_core::matches!(
        foreign_registry.commit_device_batch_with_publish(authority, &enrollment, &commits, |_| {
            foreign_publications.set(1)
        },),
        Err(RegistryError::InvalidBatchReceipt)
    ));
    __cser_core::assert_eq!(foreign_publications.get(), 0);
    __cser_core::assert_eq!(foreign_registry, foreign_before);

    let unrelated_authority = registry
        .kernel_root_authority(ScopeKey::new(0x2ff, 1), TaskKey::new(0x2ff, 1))
        .unwrap();
    let mut wrong_root = registry.clone();
    let wrong_root_before = wrong_root.clone();
    let wrong_root_publications = Cell::new(0_u8);
    __cser_core::assert!(__cser_core::matches!(
        wrong_root.commit_device_batch_with_publish(
            unrelated_authority,
            &enrollment,
            &commits,
            |_| wrong_root_publications.set(1),
        ),
        Err(RegistryError::InvalidBatchReceipt)
    ));
    __cser_core::assert_eq!(wrong_root_publications.get(), 0);
    __cser_core::assert_eq!(wrong_root, wrong_root_before);

    let mut forged_enrollment = enrollment.clone();
    forged_enrollment.device.device_generation += 1;
    let forged_before = registry.clone();
    let forged_publications = Cell::new(0_u8);
    __cser_core::assert!(__cser_core::matches!(
        registry.commit_device_batch_with_publish(authority, &forged_enrollment, &commits, |_| {
            forged_publications.set(1)
        },),
        Err(RegistryError::InvalidBatchReceipt)
    ));
    __cser_core::assert_eq!(forged_publications.get(), 0);
    __cser_core::assert_eq!(*registry, forged_before);

    let mut overflow = registry.clone();
    overflow.next_device_batch_sequence = u64::MAX;
    let overflow_before = overflow.clone();
    let overflow_publications = Cell::new(0_u8);
    __cser_core::assert!(__cser_core::matches!(
        overflow.commit_device_batch_with_publish(authority, &enrollment, &commits, |_| {
            overflow_publications.set(1)
        },),
        Err(RegistryError::CounterOverflow)
    ));
    __cser_core::assert_eq!(overflow_publications.get(), 0);
    __cser_core::assert_eq!(overflow, overflow_before);

    let mut revoke_first = registry.clone();
    let revoke_first_selection = revoke_first.revoke_begin(SCOPE).unwrap();
    let revoke_first_before = revoke_first.clone();
    let revoke_first_publications = Cell::new(0_u8);
    __cser_core::assert!(__cser_core::matches!(
        revoke_first.commit_device_batch_with_publish(authority, &enrollment, &commits, |_| {
            revoke_first_publications.set(1)
        },),
        Err(RegistryError::StaleAuthority)
    ));
    __cser_core::assert_eq!(revoke_first_publications.get(), 0);
    __cser_core::assert_eq!(revoke_first, revoke_first_before);
    let selected = revoke_first
        .revoke_next(&revoke_first_selection)
        .unwrap()
        .unwrap();
    __cser_core::assert_eq!(selected.disposition, RevokeDisposition::Abort);
    let before_early_abort = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.stage_revoke_terminal(
            &revoke_first_selection,
            selected.effect,
            TerminalRequest::aborted(-125),
        ),
        Err(RegistryError::DeviceClosurePending)
    );
    __cser_core::assert_eq!(revoke_first, before_early_abort);
    let cancel = revoke_first
        .begin_unpublished_device_cancel(&enrollment)
        .unwrap();
    let retained = revoke_first.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!(retained.held, 0);
    __cser_core::assert_eq!(retained.retained, 6);
    let mut forged_cancel = cancel;
    forged_cancel.sequence = forged_cancel.sequence.checked_add(1).unwrap();
    let before_forged_cancel = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.retain_device_reset_timeout(&forged_cancel),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(revoke_first, before_forged_cancel);
    let mut foreign_cancel = cancel;
    foreign_cancel.registry_instance_id =
        foreign_cancel.registry_instance_id.checked_add(1).unwrap();
    let before_foreign_cancel = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.retain_device_reset_timeout(&foreign_cancel),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(revoke_first, before_foreign_cancel);
    let mut cancel_overflow = revoke_first.clone();
    cancel_overflow.next_device_closure_sequence = u64::MAX;
    let before_cancel_overflow = cancel_overflow.clone();
    __cser_core::assert_eq!(
        cancel_overflow.retain_device_reset_timeout(&cancel),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(cancel_overflow, before_cancel_overflow);
    let cancel_tombstone = revoke_first.retain_device_reset_timeout(&cancel).unwrap();
    __cser_core::assert_eq!(cancel_tombstone.device(), device);
    __cser_core::assert_eq!(
        revoke_first.scope_projection(SCOPE).unwrap().credits,
        retained
    );
    revoke_first.check_invariants().unwrap();
    let mut mixed_unpublished_retention = revoke_first.clone();
    mixed_unpublished_retention
        .effects
        .get_mut(&enrollment.effects[0])
        .unwrap()
        .credit_state = CreditState::Held;
    __cser_core::assert_eq!(
        mixed_unpublished_retention.check_invariants(),
        Err(RegistryError::Invariant(
            "retained unpublished credits lack uniform closing precommit abort"
        ))
    );
    let mut held_unpublished_abort = revoke_first.clone();
    for effect in &enrollment.effects {
        held_unpublished_abort
            .effects
            .get_mut(effect)
            .unwrap()
            .credit_state = CreditState::Held;
    }
    __cser_core::assert_eq!(
        held_unpublished_abort.check_invariants(),
        Err(RegistryError::Invariant(
            "retained unpublished credits lack uniform closing precommit abort"
        ))
    );
    let before_cancel_replay = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.retain_device_reset_timeout(&cancel),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(revoke_first, before_cancel_replay);
    let mut cancel_retry_overflow = revoke_first.clone();
    cancel_retry_overflow.next_device_closure_sequence = u64::MAX;
    let before_cancel_retry_overflow = cancel_retry_overflow.clone();
    __cser_core::assert_eq!(
        cancel_retry_overflow.retry_device_reset(&cancel_tombstone),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(cancel_retry_overflow, before_cancel_retry_overflow);
    let cancel_retry = revoke_first.retry_device_reset(&cancel_tombstone).unwrap();
    let before_cancel_retry_replay = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.retry_device_reset(&cancel_tombstone),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(revoke_first, before_cancel_retry_replay);
    let mut final_reset_timeout = revoke_first.clone();
    let final_reset_tombstone = final_reset_timeout
        .retain_device_reset_timeout(&cancel_retry)
        .unwrap();
    final_reset_timeout.check_invariants().unwrap();
    let before_final_reset_retry = final_reset_timeout.clone();
    __cser_core::assert_eq!(
        final_reset_timeout.retry_device_reset(&final_reset_tombstone),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(final_reset_timeout, before_final_reset_retry);
    let (reset, ()) = revoke_first
        .acknowledge_device_reset_with_apply(&cancel_retry, |_| ())
        .unwrap();
    __cser_core::assert_eq!(reset.outcome(), DeviceClosureResult::AbortedBeforeCommit);
    let iotlb = revoke_first.begin_device_iotlb(&reset).unwrap();
    let mut forged_iotlb = iotlb;
    forged_iotlb.sequence = forged_iotlb.sequence.checked_add(1).unwrap();
    let before_forged_iotlb = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.retain_device_iotlb_timeout(&forged_iotlb),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(revoke_first, before_forged_iotlb);
    let mut foreign_iotlb = iotlb;
    foreign_iotlb.registry_instance_id = foreign_iotlb.registry_instance_id.checked_add(1).unwrap();
    let before_foreign_iotlb = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.retain_device_iotlb_timeout(&foreign_iotlb),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(revoke_first, before_foreign_iotlb);
    let mut iotlb_overflow = revoke_first.clone();
    iotlb_overflow.next_device_closure_sequence = u64::MAX;
    let before_iotlb_overflow = iotlb_overflow.clone();
    __cser_core::assert_eq!(
        iotlb_overflow.retain_device_iotlb_timeout(&iotlb),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(iotlb_overflow, before_iotlb_overflow);
    let iotlb_tombstone = revoke_first.retain_device_iotlb_timeout(&iotlb).unwrap();
    __cser_core::assert_eq!(iotlb_tombstone.device(), reset.new_device());
    __cser_core::assert_eq!(
        revoke_first.scope_projection(SCOPE).unwrap().credits,
        retained
    );
    revoke_first.check_invariants().unwrap();
    let before_iotlb_replay = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.retain_device_iotlb_timeout(&iotlb),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(revoke_first, before_iotlb_replay);
    let mut iotlb_retry_overflow = revoke_first.clone();
    iotlb_retry_overflow.next_device_closure_sequence = u64::MAX;
    let before_iotlb_retry_overflow = iotlb_retry_overflow.clone();
    __cser_core::assert_eq!(
        iotlb_retry_overflow.retry_device_iotlb(&reset, &iotlb_tombstone),
        Err(RegistryError::CounterOverflow)
    );
    __cser_core::assert_eq!(iotlb_retry_overflow, before_iotlb_retry_overflow);
    let iotlb_retry = revoke_first
        .retry_device_iotlb(&reset, &iotlb_tombstone)
        .unwrap();
    let before_iotlb_retry_replay = revoke_first.clone();
    __cser_core::assert_eq!(
        revoke_first.retry_device_iotlb(&reset, &iotlb_tombstone),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(revoke_first, before_iotlb_retry_replay);
    let mut final_iotlb_timeout = revoke_first.clone();
    let final_iotlb_tombstone = final_iotlb_timeout
        .retain_device_iotlb_timeout(&iotlb_retry)
        .unwrap();
    final_iotlb_timeout.check_invariants().unwrap();
    let before_final_iotlb_retry = final_iotlb_timeout.clone();
    __cser_core::assert_eq!(
        final_iotlb_timeout.retry_device_iotlb(&reset, &final_iotlb_tombstone),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(final_iotlb_timeout, before_final_iotlb_retry);
    let (cancelled, ()) = revoke_first
        .acknowledge_device_iotlb_with_apply(&iotlb_retry, |_| ())
        .unwrap();
    __cser_core::assert!(!cancelled.published());
    __cser_core::assert_eq!(
        cancelled.outcome(),
        DeviceClosureResult::AbortedBeforeCommit
    );
    for expected in [
        dma_a.identity.effect(),
        dma_b.identity.effect(),
        dma_request.identity.effect(),
        block.identity.effect(),
        filesystem.identity.effect(),
        syscall.identity.effect(),
    ] {
        let next = revoke_first
            .revoke_next(&revoke_first_selection)
            .unwrap()
            .unwrap();
        __cser_core::assert_eq!(next.effect, expected);
        __cser_core::assert_eq!(next.disposition, RevokeDisposition::Abort);
        revoke_first
            .stage_device_batch_terminal(&cancelled, expected, TerminalRequest::aborted(-125))
            .unwrap();
    }
    __cser_core::assert!(
        revoke_first
            .revoke_next(&revoke_first_selection)
            .unwrap()
            .is_none()
    );
    revoke_first
        .revoke_complete(&revoke_first_selection)
        .unwrap();
    __cser_core::assert_eq!(
        revoke_first.scope_projection(SCOPE).unwrap().credits.free,
        7
    );
    revoke_first.check_invariants().unwrap();

    let close_operation = registry
        .mint_device_close_operation(&enrollment, 0x51_0001)
        .unwrap();
    __cser_core::assert_eq!(close_operation.registry_instance_id(), registry.instance_id);
    __cser_core::assert_eq!(close_operation.scope(), SCOPE);
    __cser_core::assert_eq!(close_operation.authority_epoch(), 17);
    __cser_core::assert_eq!(
        close_operation.enrollment_sequence(),
        enrollment.enrollment_sequence()
    );
    __cser_core::assert_eq!(close_operation.device(), device);
    __cser_core::assert_eq!(close_operation.caller_nonce(), 0x51_0001);
    __cser_core::assert_eq!(
        registry.mint_device_close_operation(&enrollment, 0),
        Err(RegistryError::InvalidGeneration)
    );

    // Model an unwind immediately after `Publishing` is installed and before
    // the external publication closure returns. The projected batch remains
    // root-local, the first revision is durable, and every retry is classified
    // as possibly published without entering either publication or precommit
    // hardware closure again.
    let mut interrupted_close = registry.clone();
    let interrupted_before = interrupted_close.scope_projection(SCOPE).unwrap();
    let interrupted_plan = interrupted_close
        .prepare_device_close(close_operation, authority, &enrollment, &commits)
        .unwrap();
    __cser_core::assert_eq!(
        interrupted_plan.publishing_revision,
        interrupted_before.revision + 1
    );
    __cser_core::assert_eq!(
        interrupted_plan.batch.next_scope_revision,
        interrupted_before.revision + 2
    );
    __cser_core::assert_eq!(
        interrupted_plan.revoke.next_scope_revision,
        interrupted_before.revision + 3
    );
    let interrupted_batch = interrupted_plan.stored_batch.clone();
    let abandoned_apply = interrupted_close.install_device_close_publishing(interrupted_plan);
    __cser_core::assert_eq!(
        interrupted_close.scope_projection(SCOPE).unwrap().revision,
        interrupted_before.revision + 1
    );
    __cser_core::assert_eq!(
        interrupted_close.scope_projection(SCOPE).unwrap().phase,
        ScopePhase::Active
    );
    __cser_core::assert!(__cser_core::matches!(
        &interrupted_close.scopes[&SCOPE]
            .device_root
            .as_ref()
            .unwrap()
            .publication,
        DevicePublicationProvenance::Publishing { operation, batch }
            if *operation == close_operation && batch == &interrupted_batch
    ));
    interrupted_close.check_invariants().unwrap();
    let publishing_before_revoke = interrupted_close.clone();
    __cser_core::assert_eq!(
        interrupted_close.revoke_begin(SCOPE),
        Err(RegistryError::DeviceClosurePending)
    );
    __cser_core::assert_eq!(interrupted_close, publishing_before_revoke);

    // Independently harden the legacy unpublished-cancel API even against an
    // already-corrupt Closing+Publishing state. It must never convert a
    // possibly published operation into AbortedBeforeCommit.
    let DeviceCloseApplyPlan {
        revoke: abandoned_revoke,
        ..
    } = abandoned_apply;
    let mut forced_closing = interrupted_close.clone();
    forced_closing.apply_revoke_begin(abandoned_revoke);
    let forced_closing_before = forced_closing.clone();
    __cser_core::assert_eq!(
        forced_closing.begin_unpublished_device_cancel(&enrollment),
        Err(RegistryError::InvalidState)
    );
    __cser_core::assert_eq!(forced_closing, forced_closing_before);

    let interrupted_retry_before = interrupted_close.clone();
    let interrupted_retry_publications = Cell::new(0_u8);
    match interrupted_close.commit_or_recover_device_close_with_apply(
        close_operation,
        authority,
        &enrollment,
        &commits,
        |_| {
            interrupted_retry_publications
                .set(interrupted_retry_publications.get().checked_add(1).unwrap())
        },
    ) {
        Err(DeviceCloseError::Published { obligation, error }) => {
            __cser_core::assert_eq!(
                obligation.status(),
                DevicePublishedStatus::PossiblyPublished
            );
            __cser_core::assert_eq!(obligation.operation(), Some(close_operation));
            __cser_core::assert_eq!(
                obligation.batch_sequence(),
                Some(interrupted_batch.batch_sequence())
            );
            __cser_core::assert_eq!(obligation.phase(), ScopePhase::Active);
            __cser_core::assert_eq!(obligation.revoke(), None);
            __cser_core::assert_eq!(error, RegistryError::InvalidState);
        }
        _ => __cser_core::panic!("interrupted publication was retried or classified unpublished"),
    }
    __cser_core::assert_eq!(interrupted_retry_publications.get(), 0);
    __cser_core::assert_eq!(interrupted_close, interrupted_retry_before);
    let interrupted_cancel_applies = Cell::new(0_u8);
    __cser_core::assert_eq!(
        interrupted_close.close_enrolled_device_precommit_with_apply(&enrollment, |_| {
            interrupted_cancel_applies.set(1)
        }),
        Err(RegistryError::InvalidState)
    );
    __cser_core::assert_eq!(interrupted_cancel_applies.get(), 0);
    __cser_core::assert_eq!(interrupted_close, interrupted_retry_before);

    let mut fresh_close = registry.clone();
    let fresh_close_before = fresh_close.scope_projection(SCOPE).unwrap();
    let fresh_close_revoke_sequence = fresh_close.next_revoke_sequence;
    let fresh_close_commit_sequence = fresh_close.next_commit_sequence;
    let fresh_close_batch_sequence = fresh_close.next_device_batch_sequence;
    let fresh_close_enrollment_sequence = fresh_close.next_device_enrollment_sequence;
    let fresh_close_closure_sequence = fresh_close.next_device_closure_sequence;
    let fresh_close_publications = Cell::new(0_u8);
    let (fresh_close_receipt, fresh_close_selection) = match fresh_close
        .commit_or_recover_device_close_with_apply(
            close_operation,
            authority,
            &enrollment,
            &commits,
            |prepared| {
                fresh_close_publications
                    .set(fresh_close_publications.get().checked_add(1).unwrap());
                prepared.device().descriptor_token()
            },
        )
        .unwrap()
    {
        DeviceCloseOutcome::Applied {
            receipt,
            publication,
            selection,
        } => {
            __cser_core::assert_eq!(publication, device.descriptor_token());
            (receipt, selection)
        }
        DeviceCloseOutcome::Recovered { .. } => __cser_core::panic!("fresh device close recovered"),
    };
    __cser_core::assert_eq!(fresh_close_publications.get(), 1);
    __cser_core::assert_eq!(fresh_close_receipt.scope(), SCOPE);
    __cser_core::assert_eq!(fresh_close_selection.scope, SCOPE);
    __cser_core::assert_eq!(fresh_close_selection.target_count, 6);
    __cser_core::assert_eq!(
        fresh_close.scope_projection(SCOPE).unwrap().authority_epoch,
        fresh_close_before.authority_epoch + 1
    );
    __cser_core::assert_eq!(
        fresh_close.scope_projection(SCOPE).unwrap().revision,
        fresh_close_before.revision + 3
    );
    __cser_core::assert_eq!(
        fresh_close.next_revoke_sequence,
        fresh_close_revoke_sequence + 1
    );
    __cser_core::assert_eq!(
        fresh_close.next_commit_sequence,
        fresh_close_commit_sequence + 6
    );
    __cser_core::assert_eq!(
        fresh_close.next_device_batch_sequence,
        fresh_close_batch_sequence + 1
    );
    __cser_core::assert_eq!(
        fresh_close.next_device_enrollment_sequence,
        fresh_close_enrollment_sequence
    );
    __cser_core::assert_eq!(
        fresh_close.next_device_closure_sequence,
        fresh_close_closure_sequence
    );
    __cser_core::assert_eq!(
        fresh_close.scope_projection(SCOPE).unwrap().phase,
        ScopePhase::Closing
    );
    let fresh_close_root = fresh_close.scopes[&SCOPE].device_root.as_ref().unwrap();
    __cser_core::assert!(__cser_core::matches!(
        &fresh_close_root.publication,
        DevicePublicationProvenance::Applied { operation, batch }
            if *operation == close_operation && batch == &fresh_close_receipt
    ));
    fresh_close.check_invariants().unwrap();

    let mut rewritten_close = fresh_close.clone();
    let rewritten_close_id = rewritten_close.instance_id.checked_add(1).unwrap();
    rewritten_close.rewrite_registry_instance(rewritten_close_id);
    let rewritten_root = rewritten_close.scopes[&SCOPE].device_root.as_ref().unwrap();
    let DevicePublicationProvenance::Applied {
        operation: rewritten_operation,
        batch: rewritten_batch,
    } = &rewritten_root.publication
    else {
        __cser_core::panic!("rewritten close lost applied provenance");
    };
    __cser_core::assert_eq!(
        rewritten_operation.registry_instance_id(),
        rewritten_close_id
    );
    __cser_core::assert_eq!(rewritten_operation.scope(), SCOPE);
    __cser_core::assert_eq!(
        rewritten_operation.caller_nonce(),
        close_operation.caller_nonce()
    );
    __cser_core::assert_eq!(rewritten_batch.registry_instance_id(), rewritten_close_id);
    __cser_core::assert!(
        rewritten_batch
            .commits()
            .iter()
            .all(|commit| commit.registry_instance_id == rewritten_close_id)
    );
    rewritten_close.check_invariants().unwrap();

    let before_closing_recovery = fresh_close.clone();
    let closing_recovery_publications = Cell::new(0_u8);
    match fresh_close
        .commit_or_recover_device_close_with_apply(
            close_operation,
            authority,
            &enrollment,
            &commits,
            |_| {
                closing_recovery_publications
                    .set(closing_recovery_publications.get().checked_add(1).unwrap())
            },
        )
        .unwrap()
    {
        DeviceCloseOutcome::Recovered { receipt, selection } => {
            __cser_core::assert_eq!(receipt, fresh_close_receipt);
            __cser_core::assert_eq!(selection, fresh_close_selection);
        }
        DeviceCloseOutcome::Applied { .. } => __cser_core::panic!("same operation republished"),
    }
    __cser_core::assert_eq!(closing_recovery_publications.get(), 0);
    __cser_core::assert_eq!(fresh_close, before_closing_recovery);

    let assert_published_close_error =
        |candidate: &mut EffectRegistry,
         operation: DeviceCloseOperationId,
         presented: &DeviceBatchEnrollmentReceipt,
         presented_commits: &[(PortalHandle, CommitMetadata)]| {
            let before = candidate.clone();
            let publish_calls = Cell::new(0_u8);
            match candidate.commit_or_recover_device_close_with_apply(
                operation,
                authority,
                presented,
                presented_commits,
                |_| publish_calls.set(publish_calls.get().checked_add(1).unwrap()),
            ) {
                Err(DeviceCloseError::Published { obligation, .. }) => {
                    __cser_core::assert_eq!(
                        obligation.registry_instance_id(),
                        registry.instance_id
                    );
                    __cser_core::assert_eq!(obligation.scope(), SCOPE);
                    __cser_core::assert_eq!(obligation.device(), device);
                    __cser_core::assert_eq!(
                        obligation.batch_sequence(),
                        Some(fresh_close_receipt.batch_sequence())
                    );
                    __cser_core::assert_eq!(obligation.operation(), Some(close_operation));
                    __cser_core::assert_eq!(obligation.phase(), ScopePhase::Closing);
                    __cser_core::assert_eq!(obligation.revoke(), Some(&fresh_close_selection));
                    __cser_core::assert_eq!(obligation.reset_ticket(), None);
                    __cser_core::assert_eq!(obligation.reset_tombstone(), None);
                    __cser_core::assert!(!obligation.reset_retry_issued());
                    __cser_core::assert_eq!(obligation.reset_receipt(), None);
                    __cser_core::assert_eq!(obligation.iotlb_ticket(), None);
                    __cser_core::assert_eq!(obligation.iotlb_tombstone(), None);
                    __cser_core::assert!(!obligation.iotlb_retry_issued());
                    __cser_core::assert_eq!(obligation.closure(), None);
                }
                _ => __cser_core::panic!("published input drift lacked ownership obligation"),
            }
            __cser_core::assert_eq!(publish_calls.get(), 0);
            __cser_core::assert_eq!(*candidate, before);
        };

    let mut wrong_operation = close_operation;
    wrong_operation.caller_nonce = wrong_operation.caller_nonce.checked_add(1).unwrap();
    let mut wrong_operation_candidate = fresh_close.clone();
    assert_published_close_error(
        &mut wrong_operation_candidate,
        wrong_operation,
        &enrollment,
        &commits,
    );

    let mut wrong_operation_registry = close_operation;
    wrong_operation_registry.registry_instance_id = wrong_operation_registry
        .registry_instance_id
        .checked_add(1)
        .unwrap();
    let mut wrong_registry_candidate = fresh_close.clone();
    assert_published_close_error(
        &mut wrong_registry_candidate,
        wrong_operation_registry,
        &enrollment,
        &commits,
    );

    let mut wrong_close_enrollment = enrollment.clone();
    wrong_close_enrollment.enrollment_sequence = wrong_close_enrollment
        .enrollment_sequence
        .checked_add(1)
        .unwrap();
    let mut wrong_enrollment_candidate = fresh_close.clone();
    assert_published_close_error(
        &mut wrong_enrollment_candidate,
        close_operation,
        &wrong_close_enrollment,
        &commits,
    );

    let mut wrong_close_commits = commits;
    wrong_close_commits[0].1 = CommitMetadata::new(5, 1);
    let mut wrong_metadata_candidate = fresh_close.clone();
    assert_published_close_error(
        &mut wrong_metadata_candidate,
        close_operation,
        &enrollment,
        &wrong_close_commits,
    );

    let mut corrupt_operation_state = fresh_close.clone();
    {
        let root = corrupt_operation_state
            .scopes
            .get_mut(&SCOPE)
            .unwrap()
            .device_root
            .as_mut()
            .unwrap();
        root.batch_sequence = None;
        root.publication = DevicePublicationProvenance::Applied {
            operation: close_operation,
            batch: fresh_close_receipt.clone(),
        };
    }
    let corrupt_before = corrupt_operation_state.clone();
    let corrupt_publish_calls = Cell::new(0_u8);
    match corrupt_operation_state.commit_or_recover_device_close_with_apply(
        close_operation,
        authority,
        &enrollment,
        &commits,
        |_| corrupt_publish_calls.set(corrupt_publish_calls.get().checked_add(1).unwrap()),
    ) {
        Err(DeviceCloseError::Published { obligation, error }) => {
            __cser_core::assert_eq!(
                obligation.batch_sequence(),
                Some(fresh_close_receipt.batch_sequence())
            );
            __cser_core::assert_eq!(obligation.operation(), Some(close_operation));
            __cser_core::assert_eq!(error, RegistryError::InvalidBatchReceipt);
        }
        _ => __cser_core::panic!("corrupt operation state was misclassified as unpublished"),
    }
    __cser_core::assert_eq!(corrupt_publish_calls.get(), 0);
    __cser_core::assert_eq!(corrupt_operation_state, corrupt_before);

    let assert_fresh_close_overflow = |candidate: &mut EffectRegistry| {
        let before = candidate.clone();
        let publish_calls = Cell::new(0_u8);
        __cser_core::assert!(__cser_core::matches!(
            candidate.commit_or_recover_device_close_with_apply(
                close_operation,
                authority,
                &enrollment,
                &commits,
                |_| publish_calls.set(publish_calls.get().checked_add(1).unwrap()),
            ),
            Err(DeviceCloseError::Unpublished(
                RegistryError::CounterOverflow
            ))
        ));
        __cser_core::assert_eq!(publish_calls.get(), 0);
        __cser_core::assert_eq!(*candidate, before);
    };

    let mut close_revoke_overflow = registry.clone();
    close_revoke_overflow.next_revoke_sequence = u64::MAX;
    assert_fresh_close_overflow(&mut close_revoke_overflow);

    let mut close_commit_overflow = registry.clone();
    close_commit_overflow.next_commit_sequence = u64::MAX - 5;
    assert_fresh_close_overflow(&mut close_commit_overflow);

    let mut close_batch_overflow = registry.clone();
    close_batch_overflow.next_device_batch_sequence = u64::MAX;
    assert_fresh_close_overflow(&mut close_batch_overflow);

    let mut close_commit_revision_overflow = registry.clone();
    close_commit_revision_overflow
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .revision = u64::MAX;
    assert_fresh_close_overflow(&mut close_commit_revision_overflow);

    let mut close_revoke_revision_overflow = registry.clone();
    close_revoke_revision_overflow
        .scopes
        .get_mut(&SCOPE)
        .unwrap()
        .revision = u64::MAX - 1;
    assert_fresh_close_overflow(&mut close_revoke_revision_overflow);

    let mut close_authority_overflow = registry.clone();
    let mut overflow_enrollment = enrollment.clone();
    overflow_enrollment.authority_epoch = u64::MAX;
    {
        let scope = close_authority_overflow.scopes.get_mut(&SCOPE).unwrap();
        scope.authority_epoch = u64::MAX;
        scope.device_root.as_mut().unwrap().enrollment = Some(overflow_enrollment.clone());
    }
    for effect in &overflow_enrollment.effects {
        close_authority_overflow
            .effects
            .get_mut(effect)
            .unwrap()
            .identity
            .authority_epoch = u64::MAX;
    }
    let mut overflow_authority = authority;
    overflow_authority.authority_epoch = u64::MAX;
    let mut overflow_commits = commits;
    for (handle, _) in &mut overflow_commits {
        handle.authority_epoch = u64::MAX;
    }
    let overflow_operation = close_authority_overflow
        .mint_device_close_operation(&overflow_enrollment, 0x51_0002)
        .unwrap();
    let close_authority_before = close_authority_overflow.clone();
    let authority_publish_calls = Cell::new(0_u8);
    __cser_core::assert!(__cser_core::matches!(
        close_authority_overflow.commit_or_recover_device_close_with_apply(
            overflow_operation,
            overflow_authority,
            &overflow_enrollment,
            &overflow_commits,
            |_| authority_publish_calls.set(authority_publish_calls.get().checked_add(1).unwrap()),
        ),
        Err(DeviceCloseError::Unpublished(
            RegistryError::CounterOverflow
        ))
    ));
    __cser_core::assert_eq!(authority_publish_calls.get(), 0);
    __cser_core::assert_eq!(close_authority_overflow, close_authority_before);

    let mut revoked_recovery = fresh_close.clone();
    let reset_ticket = revoked_recovery
        .begin_device_reset(&fresh_close_receipt)
        .unwrap();
    let (reset_receipt, ()) = revoked_recovery
        .acknowledge_device_reset_with_apply(&reset_ticket, |_| ())
        .unwrap();
    let iotlb_ticket = revoked_recovery.begin_device_iotlb(&reset_receipt).unwrap();
    let (closure, ()) = revoked_recovery
        .acknowledge_device_iotlb_with_apply(&iotlb_ticket, |_| ())
        .unwrap();
    for expected in [
        dma_a.identity.effect(),
        dma_b.identity.effect(),
        dma_request.identity.effect(),
        block.identity.effect(),
        filesystem.identity.effect(),
        syscall.identity.effect(),
    ] {
        let next = revoked_recovery
            .revoke_next(&fresh_close_selection)
            .unwrap()
            .unwrap();
        __cser_core::assert_eq!(next.effect, expected);
        revoked_recovery
            .stage_device_batch_terminal(
                &closure,
                expected,
                TerminalRequest::indeterminate_after_reset(-5),
            )
            .unwrap();
    }
    __cser_core::assert!(
        revoked_recovery
            .revoke_next(&fresh_close_selection)
            .unwrap()
            .is_none()
    );
    revoked_recovery
        .revoke_complete(&fresh_close_selection)
        .unwrap();
    __cser_core::assert_eq!(
        revoked_recovery.scope_projection(SCOPE).unwrap().phase,
        ScopePhase::Revoked
    );
    revoked_recovery.check_invariants().unwrap();
    let before_revoked_recovery = revoked_recovery.clone();
    let revoked_recovery_publications = Cell::new(0_u8);
    match revoked_recovery
        .commit_or_recover_device_close_with_apply(
            close_operation,
            authority,
            &enrollment,
            &commits,
            |_| {
                revoked_recovery_publications
                    .set(revoked_recovery_publications.get().checked_add(1).unwrap())
            },
        )
        .unwrap()
    {
        DeviceCloseOutcome::Recovered { receipt, selection } => {
            __cser_core::assert_eq!(receipt, fresh_close_receipt);
            __cser_core::assert_eq!(selection, fresh_close_selection);
        }
        DeviceCloseOutcome::Applied { .. } => __cser_core::panic!("revoked operation republished"),
    }
    __cser_core::assert_eq!(revoked_recovery_publications.get(), 0);
    __cser_core::assert_eq!(revoked_recovery, before_revoked_recovery);

    let legacy_operation = registry
        .mint_device_close_operation(&enrollment, 0x51_1001)
        .unwrap();
    let publications = Cell::new(0_u8);
    let receipt = match registry
        .commit_device_batch_with_publish(authority, &enrollment, &commits, |prepared| {
            __cser_core::assert_eq!(prepared.commits().len(), 6);
            __cser_core::assert_eq!(prepared.device_effects().len(), 4);
            publications.set(publications.get() + 1);
            prepared.device().descriptor_token()
        })
        .unwrap()
    {
        DeviceBatchCommitOutcome::Applied {
            receipt,
            publication,
        } => {
            __cser_core::assert_eq!(publication, 0);
            receipt
        }
        DeviceBatchCommitOutcome::AlreadyCommitted { .. } => {
            __cser_core::panic!("fresh device batch replayed")
        }
    };
    __cser_core::assert_eq!(publications.get(), 1);
    __cser_core::assert_eq!(receipt.registry_instance_id(), registry.instance_id);
    __cser_core::assert_eq!(receipt.scope(), SCOPE);
    __cser_core::assert_eq!(receipt.authority_epoch(), 17);
    __cser_core::assert_eq!(receipt.batch_sequence(), 1);
    __cser_core::assert_eq!(receipt.device(), device);
    __cser_core::assert_eq!(receipt.commits().len(), 6);
    __cser_core::assert_eq!(receipt.device_effects().len(), 4);
    registry.validate_device_batch_receipt(&receipt).unwrap();
    registry.check_invariants().unwrap();
    let committed = registry.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!(committed.capacity, 7);
    __cser_core::assert_eq!(committed.free, 1);
    __cser_core::assert_eq!(committed.held, 0);
    __cser_core::assert_eq!(committed.committed, 6);
    __cser_core::assert_eq!(committed.retained, 0);

    let replay_publications = Cell::new(0_u8);
    match registry
        .commit_device_batch_with_publish(authority, &enrollment, &commits, |_| {
            replay_publications.set(1)
        })
        .unwrap()
    {
        DeviceBatchCommitOutcome::AlreadyCommitted { receipt: replay } => {
            __cser_core::assert_eq!(replay, receipt)
        }
        DeviceBatchCommitOutcome::Applied { .. } => {
            __cser_core::panic!("device batch published twice")
        }
    }
    __cser_core::assert_eq!(replay_publications.get(), 0);

    let legacy_before = registry.clone();
    let legacy_publish_calls = Cell::new(0_u8);
    match registry.commit_or_recover_device_close_with_apply(
        legacy_operation,
        authority,
        &enrollment,
        &commits,
        |_| legacy_publish_calls.set(legacy_publish_calls.get().checked_add(1).unwrap()),
    ) {
        Err(DeviceCloseError::Published { obligation, error }) => {
            __cser_core::assert_eq!(obligation.registry_instance_id(), registry.instance_id);
            __cser_core::assert_eq!(obligation.scope(), SCOPE);
            __cser_core::assert_eq!(obligation.device(), device);
            __cser_core::assert_eq!(obligation.batch_sequence(), Some(receipt.batch_sequence()));
            __cser_core::assert_eq!(obligation.operation(), None);
            __cser_core::assert_eq!(obligation.phase(), ScopePhase::Active);
            __cser_core::assert_eq!(obligation.revoke(), None);
            __cser_core::assert_eq!(obligation.reset_ticket(), None);
            __cser_core::assert_eq!(obligation.closure(), None);
            __cser_core::assert_eq!(error, RegistryError::InvalidState);
        }
        _ => __cser_core::panic!("legacy committed state was not an honest Published error"),
    }
    __cser_core::assert_eq!(legacy_publish_calls.get(), 0);
    __cser_core::assert_eq!(*registry, legacy_before);

    let replay_before = registry.clone();
    __cser_core::assert_eq!(
        registry.commit(PERSONALITY, syscall.handle, commits[0].1),
        Err(RegistryError::InvalidDeviceEnvelope)
    );
    __cser_core::assert_eq!(*registry, replay_before);

    let mut wrong_receipt = receipt.clone();
    wrong_receipt.device.device_generation += 1;
    __cser_core::assert_eq!(
        registry.validate_device_batch_receipt(&wrong_receipt),
        Err(RegistryError::StaleDeviceGeneration)
    );
    let mut wrong_receipt = receipt.clone();
    wrong_receipt.device.device_session += 1;
    __cser_core::assert_eq!(
        registry.validate_device_batch_receipt(&wrong_receipt),
        Err(RegistryError::InvalidBatchReceipt)
    );
    let mut wrong_receipt = receipt.clone();
    wrong_receipt.commits.swap(0, 1);
    __cser_core::assert_eq!(
        registry.validate_device_batch_receipt(&wrong_receipt),
        Err(RegistryError::InvalidBatchReceipt)
    );
    let mut wrong_receipt = receipt.clone();
    wrong_receipt.device_effects.pop();
    __cser_core::assert_eq!(
        registry.validate_device_batch_receipt(&wrong_receipt),
        Err(RegistryError::InvalidBatchReceipt)
    );
    let mut wrong_receipt = receipt.clone();
    wrong_receipt.registry_instance_id += 1;
    __cser_core::assert_eq!(
        registry.validate_device_batch_receipt(&wrong_receipt),
        Err(RegistryError::InvalidBatchReceipt)
    );

    let mut wrong_completion_result = registry.clone();
    let wrong_completion_before = wrong_completion_result.clone();
    __cser_core::assert_eq!(
        wrong_completion_result.record_device_completion(&receipt, device, 512),
        Err(RegistryError::CommitConflict)
    );
    __cser_core::assert_eq!(wrong_completion_result, wrong_completion_before);

    // Normal completion still requires whole-device reset and IOTLB closure.
    let mut normal = registry.clone();
    let completion = normal
        .record_device_completion(&receipt, device, 4)
        .unwrap();
    __cser_core::assert_eq!(completion.device(), device);
    __cser_core::assert_eq!(completion.result(), 4);
    __cser_core::assert_eq!(completion.causal_root(), syscall.identity.effect());
    let reset_ticket = normal.begin_device_reset(&receipt).unwrap();
    let reset_applies = Cell::new(0_u8);
    let (reset, ()) = normal
        .acknowledge_device_reset_with_apply(&reset_ticket, |prepared| {
            __cser_core::assert_eq!(prepared.old_device(), device);
            reset_applies.set(1);
        })
        .unwrap();
    __cser_core::assert_eq!(reset_applies.get(), 1);
    __cser_core::assert_eq!(reset.old_device(), device);
    __cser_core::assert_eq!(reset.new_device().device_generation(), 2);
    __cser_core::assert_eq!(reset.outcome(), DeviceClosureResult::Completed(4));
    let iotlb = normal.begin_device_iotlb(&reset).unwrap();
    let mut iotlb_overflow = normal.clone();
    iotlb_overflow.next_device_closure_sequence = u64::MAX;
    let iotlb_overflow_before = iotlb_overflow.clone();
    let overflow_applies = Cell::new(0_u8);
    __cser_core::assert!(__cser_core::matches!(
        iotlb_overflow.acknowledge_device_iotlb_with_apply(&iotlb, |_| { overflow_applies.set(1) }),
        Err(RegistryError::CounterOverflow)
    ));
    __cser_core::assert_eq!(overflow_applies.get(), 0);
    __cser_core::assert_eq!(iotlb_overflow, iotlb_overflow_before);

    let iotlb_applies = Cell::new(0_u8);
    let (normal_closure, ()) = normal
        .acknowledge_device_iotlb_with_apply(&iotlb, |prepared| {
            __cser_core::assert_eq!(prepared.device(), reset.new_device());
            iotlb_applies.set(1);
        })
        .unwrap();
    __cser_core::assert_eq!(iotlb_applies.get(), 1);
    let normal_after_closure = normal.clone();
    let duplicate_applies = Cell::new(0_u8);
    __cser_core::assert_eq!(
        normal.acknowledge_device_iotlb_with_apply(&iotlb, |_| duplicate_applies.set(1)),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(duplicate_applies.get(), 0);
    __cser_core::assert_eq!(normal, normal_after_closure);
    __cser_core::assert_eq!(normal_closure.outcome(), DeviceClosureResult::Completed(4));
    let normal_before_generic = normal.clone();
    __cser_core::assert_eq!(
        normal.stage_kernel_completion(receipt.commit_for(dma_a.identity.effect()).unwrap()),
        Err(RegistryError::DeviceClosurePending)
    );
    __cser_core::assert_eq!(normal, normal_before_generic);
    for expected in [
        dma_a.identity.effect(),
        dma_b.identity.effect(),
        dma_request.identity.effect(),
        block.identity.effect(),
        filesystem.identity.effect(),
        syscall.identity.effect(),
    ] {
        let commit = receipt.commit_for(expected).unwrap();
        normal
            .stage_device_batch_terminal(
                &normal_closure,
                expected,
                TerminalRequest::completed(commit.result()),
            )
            .unwrap();
    }
    let normal_projection = normal.scope_projection(SCOPE).unwrap();
    __cser_core::assert_eq!(normal_projection.live_effects, 0);
    __cser_core::assert_eq!(normal_projection.credits.free, 7);
    __cser_core::assert_eq!(normal_projection.credits.retained, 0);
    normal.check_invariants().unwrap();

    // Published ownership with no authoritative completion becomes a real
    // indeterminate terminal only when reset advances the device generation.
    let mut indeterminate = registry.clone();
    let reset_ticket = indeterminate.begin_device_reset(&receipt).unwrap();
    __cser_core::assert_eq!(
        indeterminate.scopes[&SCOPE]
            .device_root
            .as_ref()
            .unwrap()
            .outcome,
        None
    );
    let (reset, ()) = indeterminate
        .acknowledge_device_reset_with_apply(&reset_ticket, |_| ())
        .unwrap();
    __cser_core::assert_eq!(
        reset.outcome(),
        DeviceClosureResult::IndeterminateAfterReset
    );
    let iotlb = indeterminate.begin_device_iotlb(&reset).unwrap();
    let (indeterminate_closure, ()) = indeterminate
        .acknowledge_device_iotlb_with_apply(&iotlb, |_| ())
        .unwrap();
    indeterminate
        .stage_device_batch_terminal(
            &indeterminate_closure,
            dma_a.identity.effect(),
            TerminalRequest::indeterminate_after_reset(-5),
        )
        .unwrap();
    __cser_core::assert_eq!(
        indeterminate
            .effect_view(dma_a.identity.effect())
            .unwrap()
            .phase,
        EffectPhase::Terminal(TerminalOutcome::IndeterminateAfterReset)
    );
    indeterminate.check_invariants().unwrap();

    let selection = registry.revoke_begin(SCOPE).unwrap();
    registry.validate_device_batch_receipt(&receipt).unwrap();
    let after_revoke = registry.clone();
    let late_publications = Cell::new(0_u8);
    __cser_core::assert!(__cser_core::matches!(
        registry.commit_device_batch_with_publish(authority, &enrollment, &commits, |_| {
            late_publications.set(1)
        },),
        Err(RegistryError::StaleAuthority)
    ));
    __cser_core::assert_eq!(late_publications.get(), 0);
    __cser_core::assert_eq!(*registry, after_revoke);

    let selected = registry.revoke_next(&selection).unwrap().unwrap();
    __cser_core::assert_eq!(selected.effect, dma_a.identity.effect());
    let before_generic_drain = registry.clone();
    __cser_core::assert_eq!(
        registry.stage_revoke_terminal(
            &selection,
            selected.effect,
            TerminalRequest::completed(match selected.disposition {
                RevokeDisposition::Drain(ref commit) => commit.result(),
                RevokeDisposition::Abort =>
                    __cser_core::panic!("committed device batch became abortable"),
            }),
        ),
        Err(RegistryError::DeviceClosurePending)
    );
    __cser_core::assert_eq!(*registry, before_generic_drain);
    __cser_core::assert_eq!(
        registry.revoke_complete(&selection),
        Err(RegistryError::NotQuiescent)
    );

    registry
        .record_device_completion(&receipt, device, 4)
        .unwrap();
    let reset_ticket = registry.begin_device_reset(&receipt).unwrap();
    let reset_tombstone = registry.retain_device_reset_timeout(&reset_ticket).unwrap();
    __cser_core::assert_eq!(reset_tombstone.device(), device);
    let retained = registry.scope_projection(SCOPE).unwrap().credits;
    __cser_core::assert_eq!(retained.free, 1);
    __cser_core::assert_eq!(retained.held, 0);
    __cser_core::assert_eq!(retained.committed, 0);
    __cser_core::assert_eq!(retained.retained, 6);
    registry.check_invariants().unwrap();
    __cser_core::assert_eq!(
        registry.revoke_complete(&selection),
        Err(RegistryError::NotQuiescent)
    );
    let retry = registry.retry_device_reset(&reset_tombstone).unwrap();
    let reset_applies = Cell::new(0_u8);
    let (reset, ()) = registry
        .acknowledge_device_reset_with_apply(&retry, |_| reset_applies.set(1))
        .unwrap();
    __cser_core::assert_eq!(reset_applies.get(), 1);
    __cser_core::assert_eq!(reset.new_device().device_generation(), 2);
    __cser_core::assert_eq!(reset.outcome(), DeviceClosureResult::Completed(4));
    registry.check_invariants().unwrap();

    let before_late_completion = registry.clone();
    __cser_core::assert_eq!(
        registry.record_device_completion(&receipt, device, 4),
        Err(RegistryError::StaleDeviceGeneration)
    );
    __cser_core::assert_eq!(*registry, before_late_completion);

    let iotlb = registry.begin_device_iotlb(&reset).unwrap();
    let iotlb_tombstone = registry.retain_device_iotlb_timeout(&iotlb).unwrap();
    __cser_core::assert_eq!(iotlb_tombstone.device().device_generation(), 2);
    let iotlb_retry = registry
        .retry_device_iotlb(&reset, &iotlb_tombstone)
        .unwrap();
    let (closure, ()) = registry
        .acknowledge_device_iotlb_with_apply(&iotlb_retry, |_| ())
        .unwrap();
    __cser_core::assert_eq!(closure.device().device_generation(), 2);
    __cser_core::assert_eq!(closure.outcome(), DeviceClosureResult::Completed(4));
    registry.validate_device_closure_receipt(&closure).unwrap();
    registry.check_invariants().unwrap();
    let mut stale_closure = closure;
    stale_closure.device = device;
    let before_stale_closure = registry.clone();
    __cser_core::assert_eq!(
        registry.validate_device_closure_receipt(&stale_closure),
        Err(RegistryError::StaleDeviceGeneration)
    );
    __cser_core::assert_eq!(*registry, before_stale_closure);
    let mut forged_closure = closure;
    forged_closure.batch_sequence = forged_closure
        .batch_sequence
        .and_then(|sequence| sequence.checked_add(1));
    let before_forged_closure = registry.clone();
    __cser_core::assert_eq!(
        registry.stage_device_batch_terminal(
            &forged_closure,
            dma_a.identity.effect(),
            TerminalRequest::completed(1),
        ),
        Err(RegistryError::InvalidBatchReceipt)
    );
    __cser_core::assert_eq!(*registry, before_forged_closure);

    for expected in [
        dma_a.identity.effect(),
        dma_b.identity.effect(),
        dma_request.identity.effect(),
        block.identity.effect(),
        filesystem.identity.effect(),
        syscall.identity.effect(),
    ] {
        let next = registry.revoke_next(&selection).unwrap().unwrap();
        __cser_core::assert_eq!(next.effect, expected);
        let result = match next.disposition {
            RevokeDisposition::Drain(commit) => commit.result(),
            RevokeDisposition::Abort => {
                __cser_core::panic!("committed device batch became abortable")
            }
        };
        registry
            .stage_device_batch_terminal(&closure, expected, TerminalRequest::completed(result))
            .unwrap();
    }
    __cser_core::assert!(registry.revoke_next(&selection).unwrap().is_none());
    registry.revoke_complete(&selection).unwrap();
    registry.validate_device_batch_receipt(&receipt).unwrap();
    let closed = registry.scope_projection(SCOPE).unwrap();
    __cser_core::assert_eq!(closed.phase, ScopePhase::Revoked);
    __cser_core::assert_eq!(closed.live_effects, 0);
    __cser_core::assert_eq!(closed.credits.free, 7);
    __cser_core::assert_eq!(closed.credits.held, 0);
    __cser_core::assert_eq!(closed.credits.committed, 0);
    __cser_core::assert_eq!(closed.credits.retained, 0);
    registry.check_invariants().unwrap();
}

/// Exercises the staged registry without changing the kernel's current run
/// sequence.  A later OSTD runner can call this and print the returned receipt.
pub(crate) fn bounded_registry_self_test() -> RegistrySelfTestReceipt {
    const WAIT_CREDIT: CreditClass = CreditClass::new(1);
    const SYSCALL_CREDIT: CreditClass = CreditClass::new(2);

    bounded_kernel_completion_during_recovery_self_test();
    stage7b_registry_refactor_self_test();
    production_identity_registry_self_test();

    let scope = ScopeKey::new(50, 1);
    let v1 = TaskKey::new(600, 1);
    let v2 = TaskKey::new(601, 1);
    let waiter = TaskKey::new(610, 1);
    let caller = TaskKey::new(611, 1);
    let futex_a = ResourceKey::new(1, 700, 1);
    let futex_b = ResourceKey::new(1, 701, 1);
    let mut registry = EffectRegistry::new();
    registry
        .create_scope(ScopeConfig {
            key: scope,
            authority_epoch: 111,
            binding_epoch: 1,
            supervisor: v1,
            credits: __cser_alloc::vec![
                CreditLimit::new(WAIT_CREDIT, 1),
                CreditLimit::new(SYSCALL_CREDIT, 1),
            ],
        })
        .unwrap();

    let wait = registry
        .register(RegisterRequest {
            scope,
            task: waiter,
            operation: OperationClass::new(1),
            descriptor: SyscallDescriptor::new(202, [0x402010, 128, 0, 0, 0, 0]),
            resources: __cser_alloc::vec![futex_a],
            credits: __cser_alloc::vec![CreditCharge::new(WAIT_CREDIT, 1)],
            publication: PublicationMode::Required,
        })
        .unwrap();
    registry.prepare(v1, wait.handle).unwrap();

    let requeue = registry
        .register(RegisterRequest {
            scope,
            task: caller,
            operation: OperationClass::new(3),
            descriptor: SyscallDescriptor::new(202, [0x402010, 131, 0, 1, 0x402018, 0]),
            resources: __cser_alloc::vec![futex_a, futex_b],
            credits: __cser_alloc::vec![CreditCharge::new(SYSCALL_CREDIT, 1)],
            publication: PublicationMode::Required,
        })
        .unwrap();
    registry.prepare(v1, requeue.handle).unwrap();
    let committed = match registry
        .commit_with_moves(
            v1,
            &[(requeue.handle, CommitMetadata::new(1, 7))],
            &[ResourceMove {
                handle: wait.handle,
                current_resources: __cser_alloc::vec![futex_b],
            }],
        )
        .unwrap()
        .pop()
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => __cser_core::unreachable!(),
    };
    __cser_core::assert!(
        !registry
            .effects_for_resource(futex_a)
            .contains(&wait.identity.effect())
    );
    __cser_core::assert!(
        registry
            .effects_for_resource(futex_b)
            .contains(&wait.identity.effect())
    );
    registry.check_invariants().unwrap();

    let crash = registry.crash(scope, v1).unwrap();
    __cser_core::assert_eq!(crash.cohort.len(), 2);
    let snapshot = registry.recovery_snapshot(scope, v2).unwrap();
    registry.ready(scope, v2, &snapshot).unwrap();
    registry.rebind(scope, v2).unwrap();

    let mut adopted = BTreeMap::new();
    while let Some(item) = registry.recover_next(scope, v2).unwrap() {
        let effect = item.handle.effect();
        let handle = registry.adopt(scope, v2, item.handle).unwrap();
        adopted.insert(effect, handle);
    }
    __cser_core::assert_eq!(adopted.len(), 2);
    __cser_core::assert_eq!(registry.recovery_remaining(scope).unwrap(), 0);
    __cser_core::assert_eq!(
        registry
            .commit(
                v2,
                *adopted.get(&requeue.identity.effect()).unwrap(),
                CommitMetadata::new(1, 7),
            )
            .unwrap(),
        CommitOutcome::AlreadyCommitted(committed.clone())
    );

    let selection = registry.revoke_begin(scope).unwrap();
    __cser_core::assert_eq!(
        registry.prepare(v2, *adopted.get(&wait.identity.effect()).unwrap()),
        Err(RegistryError::StaleAuthority)
    );

    let mut tickets = Vec::new();
    while let Some(effect) = registry.revoke_next(&selection).unwrap() {
        let request = match effect.disposition {
            RevokeDisposition::Abort => TerminalRequest::aborted(-125),
            RevokeDisposition::Drain(ref receipt) => TerminalRequest::completed(receipt.result()),
        };
        let terminal = registry
            .stage_revoke_terminal(&selection, effect.effect, request)
            .unwrap();
        tickets.push(terminal.publication.unwrap());
    }
    __cser_core::assert_eq!(
        registry.revoke_complete(&selection),
        Err(RegistryError::NotQuiescent)
    );
    for ticket in &tickets {
        registry.acknowledge_publication(ticket).unwrap();
    }
    registry.revoke_complete(&selection).unwrap();
    registry.check_invariants().unwrap();
    let projection = registry.scope_projection(scope).unwrap();
    __cser_core::assert_eq!(projection.phase, ScopePhase::Revoked);
    __cser_core::assert_eq!(projection.live_effects, 0);
    __cser_core::assert_eq!(projection.pending_publications, 0);
    __cser_core::assert_eq!(projection.credits.free, projection.credits.capacity);

    // A diagnostic before/after hash must not depend on how many unrelated
    // negative registries happened to be allocated earlier in the boot. The
    // authoritative live receipts retain their original instance namespace.
    let mut renamespaced = registry.clone();
    let renamespaced_id = registry.instance_id.checked_add(1).unwrap();
    renamespaced.rewrite_registry_instance(renamespaced_id);
    renamespaced.check_invariants().unwrap();
    __cser_core::assert_ne!(registry.instance_id, renamespaced.instance_id);
    __cser_core::assert_ne!(
        __cser_alloc::format!("{registry:?}"),
        __cser_alloc::format!("{renamespaced:?}")
    );
    __cser_core::assert_eq!(
        registry.failure_atomic_projection(),
        renamespaced.failure_atomic_projection()
    );

    RegistrySelfTestReceipt {
        effects: 2,
        recovery_adoptions: adopted.len(),
        committed_drains: 1,
        uncommitted_aborts: 1,
        publication_acks: tickets.len(),
        stale_authority_rejected: true,
        quiescent: true,
    }
}

/// Minimal two-effect harness for exploring the production device
/// enrollment+commit/revoke winner under a modeled outer lock. The six-effect
/// workload population is pinned by `production_device_batch_registry_self_test`;
/// this smaller harness isolates the pending-enrollment publication boundary so
/// Loom does not turn graph construction into the race under test.
#[derive(__cser_core::fmt::Debug, __cser_core::cmp::Eq, __cser_core::cmp::PartialEq)]
pub(crate) struct ProductionDeviceBatchRaceFixture {
    registry: EffectRegistry,
    scope: ScopeKey,
    authority: KernelRootAuthority,
    enrollment: Option<DeviceBatchEnrollmentReceipt>,
    commits: [(PortalHandle, CommitMetadata); 2],
    device: DeviceEnvelope,
    batch: Option<DeviceBatchCommitReceipt>,
    publications: u8,
    closures: u8,
}

impl ProductionDeviceBatchRaceFixture {
    pub(crate) fn from_empty_registry(mut registry: EffectRegistry) -> Self {
        const SCOPE: ScopeKey = ScopeKey::new(0x3f0, 1);
        const ROOT_OWNER: TaskKey = TaskKey::new(0x3f0, 1);
        const CONTROL: TaskKey = TaskKey::new(0x3f1, 1);
        const DEVICE: TaskKey = TaskKey::new(0x3f2, 1);
        const CONTROL_DOMAIN: DomainKey = DomainKey::new(1);
        const DEVICE_DOMAIN: DomainKey = DomainKey::new(2);
        const CONTROL_CREDIT: CreditClass = CreditClass::new(0x3f1);
        const DEVICE_CREDIT: CreditClass = CreditClass::new(0x3f2);

        __cser_core::assert!(registry.scopes.is_empty());
        let device = DeviceEnvelope::new(0x3f, 0, 0, 1).unwrap();
        registry
            .create_scope(ScopeConfig {
                key: SCOPE,
                authority_epoch: 31,
                binding_epoch: 1,
                supervisor: ROOT_OWNER,
                credits: __cser_alloc::vec![
                    CreditLimit::new(CONTROL_CREDIT, 1),
                    CreditLimit::new(DEVICE_CREDIT, 1),
                ],
            })
            .unwrap();
        for config in [
            DomainConfig {
                key: CONTROL_DOMAIN,
                binding_epoch: 1,
                supervisor: CONTROL,
            },
            DomainConfig {
                key: DEVICE_DOMAIN,
                binding_epoch: 1,
                supervisor: DEVICE,
            },
        ] {
            registry.add_domain(SCOPE, config).unwrap();
        }
        let root = registry
            .register_derived(DerivedRegisterRequest {
                request: RegisterRequest {
                    scope: SCOPE,
                    task: CONTROL,
                    operation: OperationClass::new(1),
                    descriptor: SyscallDescriptor::new(17, [0; 6]),
                    resources: __cser_alloc::vec![ResourceKey::new(0x3f, 1, 1)],
                    credits: __cser_alloc::vec![CreditCharge::new(CONTROL_CREDIT, 1)],
                    publication: PublicationMode::None,
                },
                domain: CONTROL_DOMAIN,
                parent: None,
            })
            .unwrap();
        let child = registry
            .register_device_derived(DeviceDerivedRegisterRequest {
                derived: DerivedRegisterRequest {
                    request: RegisterRequest {
                        scope: SCOPE,
                        task: DEVICE,
                        operation: OperationClass::new(2),
                        descriptor: SyscallDescriptor::new(2, [0; 6]),
                        resources: __cser_alloc::vec![ResourceKey::new(0x3f, 2, 1)],
                        credits: __cser_alloc::vec![CreditCharge::new(DEVICE_CREDIT, 1)],
                        publication: PublicationMode::None,
                    },
                    domain: DEVICE_DOMAIN,
                    parent: Some(root.identity.effect()),
                },
                device,
            })
            .unwrap();
        registry.prepare(CONTROL, root.handle).unwrap();
        registry.prepare(DEVICE, child.handle).unwrap();
        let authority = registry.kernel_root_authority(SCOPE, ROOT_OWNER).unwrap();
        let commits = [
            (root.handle, CommitMetadata::new(1, 1)),
            (child.handle, CommitMetadata::new(1, 1)),
        ];
        registry.check_invariants().unwrap();
        Self {
            registry,
            scope: SCOPE,
            authority,
            enrollment: None,
            commits,
            device,
            batch: None,
            publications: 0,
            closures: 0,
        }
    }

    pub(crate) fn commit(&mut self) -> Result<bool, RegistryError> {
        if self.enrollment.is_none() {
            self.enrollment = Some(self.registry.enroll_device_batch(
                self.authority,
                &[self.commits[0].0, self.commits[1].0],
                self.device,
            )?);
        }
        let outcome = self.registry.commit_device_batch_with_publish(
            self.authority,
            self.enrollment.as_ref().unwrap(),
            &self.commits,
            |_| (),
        )?;
        match outcome {
            DeviceBatchCommitOutcome::Applied { receipt, .. } => {
                self.publications = self
                    .publications
                    .checked_add(1)
                    .ok_or(RegistryError::CounterOverflow)?;
                self.batch = Some(receipt);
                Ok(true)
            }
            DeviceBatchCommitOutcome::AlreadyCommitted { receipt } => {
                self.batch = Some(receipt);
                Ok(false)
            }
        }
    }

    pub(crate) fn revoke_to_completion(&mut self) -> Result<(), RegistryError> {
        let selection = self.registry.revoke_begin(self.scope)?;
        let closure = if let Some(batch) = self.batch.as_ref() {
            let reset_ticket = self.registry.begin_device_reset(batch)?;
            let (reset, ()) = self
                .registry
                .acknowledge_device_reset_with_apply(&reset_ticket, |_| ())?;
            let iotlb = self.registry.begin_device_iotlb(&reset)?;
            self.registry
                .acknowledge_device_iotlb_with_apply(&iotlb, |_| ())?
                .0
        } else {
            if self.enrollment.is_none() {
                self.enrollment = Some(self.registry.freeze_pending_device_cancel(self.scope)?);
            }
            let reset_ticket = self
                .registry
                .begin_unpublished_device_cancel(self.enrollment.as_ref().unwrap())?;
            let (reset, ()) = self
                .registry
                .acknowledge_device_reset_with_apply(&reset_ticket, |_| ())?;
            let iotlb = self.registry.begin_device_iotlb(&reset)?;
            self.registry
                .acknowledge_device_iotlb_with_apply(&iotlb, |_| ())?
                .0
        };
        self.closures = self
            .closures
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        while let Some(effect) = self.registry.revoke_next(&selection)? {
            match (closure.outcome, effect.disposition) {
                (DeviceClosureResult::AbortedBeforeCommit, RevokeDisposition::Abort) => {
                    self.registry.stage_device_batch_terminal(
                        &closure,
                        effect.effect,
                        TerminalRequest::aborted(-125),
                    )?;
                }
                (DeviceClosureResult::IndeterminateAfterReset, RevokeDisposition::Drain(_)) => {
                    self.registry.stage_device_batch_terminal(
                        &closure,
                        effect.effect,
                        TerminalRequest::indeterminate_after_reset(-5),
                    )?;
                }
                (DeviceClosureResult::Completed(_), RevokeDisposition::Drain(receipt)) => self
                    .registry
                    .stage_device_batch_terminal(
                        &closure,
                        effect.effect,
                        TerminalRequest::completed(receipt.result()),
                    )
                    .map(|_| ())?,
                _ => return Err(RegistryError::InvalidState),
            }
        }
        self.registry.revoke_complete(&selection)?;
        self.registry.check_invariants()
    }

    pub(crate) fn phase(&self) -> ScopePhase {
        self.registry.scope_projection(self.scope).unwrap().phase
    }

    pub(crate) fn publications(&self) -> u8 {
        self.publications
    }

    pub(crate) fn closures(&self) -> u8 {
        self.closures
    }

    pub(crate) fn failure_atomic_projection(&self) -> String {
        __cser_alloc::format!("{self:?}")
    }

    pub(crate) fn is_quiescent(&self) -> bool {
        let projection = self.registry.scope_projection(self.scope).unwrap();
        projection.phase == ScopePhase::Revoked
            && projection.live_effects == 0
            && projection.pending_publications == 0
            && projection.credits.free == projection.credits.capacity
            && projection.credits.held == 0
            && projection.credits.committed == 0
            && projection.credits.retained == 0
    }
}

pub(crate) fn production_handoff_retained_self_test(
    blocked_registry: EffectRegistry,
    retained_registry: EffectRegistry,
) {
    use cser_transition_gates::handoff::{HandoffId, LogPosition};

    fn intent(id: u64) -> PrepareIntent {
        PrepareIntent::new(
            HandoffId::new(id).unwrap(),
            0xa10,
            LogPosition::new(0xa11).unwrap(),
            0xa12,
            0xa13,
            0xa14,
        )
        .unwrap()
    }

    let mut blocked = ProductionDeviceBatchRaceFixture::from_empty_registry(blocked_registry);
    blocked.commit().unwrap();
    let batch = blocked.batch.clone().unwrap();
    let reset = blocked.registry.begin_device_reset(&batch).unwrap();
    blocked
        .registry
        .retain_device_reset_timeout(&reset)
        .unwrap();
    let prepare = intent(0xa20);
    let freeze = blocked
        .registry
        .freeze_admission(blocked.scope, prepare)
        .unwrap();
    __cser_core::assert_eq!(freeze.readiness(), HandoffFreezeReadiness::BlockedRetained);
    let commit = OwnershipDecisionReceipt::new(
        freeze.freeze(),
        LogPosition::new(0xa21).unwrap(),
        prepare.request_digest(),
        OwnershipDecision::Commit,
    )
    .unwrap();
    let before = blocked.registry.failure_atomic_projection();
    __cser_core::assert_eq!(
        blocked.registry.commit_handoff_close(blocked.scope, commit),
        Err(RegistryError::HandoffNotReady)
    );
    __cser_core::assert_eq!(blocked.registry.failure_atomic_projection(), before);

    let mut retained = ProductionDeviceBatchRaceFixture::from_empty_registry(retained_registry);
    retained.commit().unwrap();
    let batch = retained.batch.clone().unwrap();
    let prepare = intent(0xa30);
    let freeze = retained
        .registry
        .freeze_admission(retained.scope, prepare)
        .unwrap();
    let commit = OwnershipDecisionReceipt::new(
        freeze.freeze(),
        LogPosition::new(0xa31).unwrap(),
        prepare.request_digest(),
        OwnershipDecision::Commit,
    )
    .unwrap();
    let selection = match retained
        .registry
        .commit_handoff_close(retained.scope, commit)
        .unwrap()
    {
        ProductionHandoffProgress::Closing(selection) => selection,
        other => __cser_core::panic!("unexpected committed handoff progress: {other:?}"),
    };
    let reset_ticket = retained.registry.begin_device_reset(&batch).unwrap();
    let tombstone = retained
        .registry
        .retain_device_reset_timeout(&reset_ticket)
        .unwrap();
    __cser_core::assert_eq!(
        retained
            .registry
            .query_handoff(retained.scope, freeze.freeze())
            .unwrap(),
        ProductionHandoffProgress::Retained(selection.clone())
    );
    __cser_core::assert_eq!(
        retained
            .registry
            .commit_handoff_close(retained.scope, commit)
            .unwrap(),
        ProductionHandoffProgress::Retained(selection.clone())
    );

    let retry = retained.registry.retry_device_reset(&tombstone).unwrap();
    let (reset, ()) = retained
        .registry
        .acknowledge_device_reset_with_apply(&retry, |_| ())
        .unwrap();
    let iotlb = retained.registry.begin_device_iotlb(&reset).unwrap();
    let (closure, ()) = retained
        .registry
        .acknowledge_device_iotlb_with_apply(&iotlb, |_| ())
        .unwrap();
    while let Some(effect) = retained.registry.revoke_next(&selection).unwrap() {
        __cser_core::assert!(__cser_core::matches!(
            effect.disposition,
            RevokeDisposition::Drain(_)
        ));
        retained
            .registry
            .stage_device_batch_terminal(
                &closure,
                effect.effect,
                TerminalRequest::indeterminate_after_reset(-5),
            )
            .unwrap();
    }
    retained.registry.revoke_complete(&selection).unwrap();
    let local_closure = match retained
        .registry
        .query_handoff(retained.scope, freeze.freeze())
        .unwrap()
    {
        ProductionHandoffProgress::Closed(receipt) => receipt,
        other => __cser_core::panic!("unexpected recovered handoff progress: {other:?}"),
    };
    retained
        .registry
        .verify_handoff_closure(retained.scope, &local_closure)
        .unwrap();
    retained.registry.check_invariants().unwrap();
}

#[cfg(test)]
pub(crate) struct RetainedSemanticTestFixture {
    pub(crate) exact_operation: DeviceCloseOperationId,
    pub(crate) foreign_operation: DeviceCloseOperationId,
    pub(crate) obligation: DevicePublishedObligation,
    pub(crate) error: RegistryError,
}

#[cfg(test)]
pub(crate) fn retained_semantic_test_fixture() -> RetainedSemanticTestFixture {
    let mut fixture = ProductionDeviceBatchRaceFixture::from_empty_registry(EffectRegistry::new());
    let authority = fixture.authority;
    let commits = fixture.commits;
    let enrollment = fixture
        .registry
        .enroll_device_batch(authority, &[commits[0].0, commits[1].0], fixture.device)
        .unwrap();
    let exact_operation = fixture
        .registry
        .mint_device_close_operation(&enrollment, 0x3f_0001)
        .unwrap();
    __cser_core::assert!(__cser_core::matches!(
        fixture
            .registry
            .commit_or_recover_device_close_with_apply(
                exact_operation,
                authority,
                &enrollment,
                &commits,
                |_| (),
            )
            .unwrap(),
        DeviceCloseOutcome::Applied { .. }
    ));

    let mut foreign_operation = exact_operation;
    foreign_operation.caller_nonce = foreign_operation.caller_nonce.checked_add(1).unwrap();
    let (obligation, error) = match fixture.registry.commit_or_recover_device_close_with_apply(
        foreign_operation,
        authority,
        &enrollment,
        &commits,
        |_| __cser_core::panic!("foreign close operation republished"),
    ) {
        Err(DeviceCloseError::Published { obligation, error }) => (obligation, error),
        _ => __cser_core::panic!("foreign close operation lacked authoritative obligation"),
    };
    __cser_core::assert_eq!(obligation.operation(), Some(exact_operation));

    RetainedSemanticTestFixture {
        exact_operation,
        foreign_operation,
        obligation,
        error,
    }
}
