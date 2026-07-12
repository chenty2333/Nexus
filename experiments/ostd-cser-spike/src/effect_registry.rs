// SPDX-License-Identifier: MPL-2.0

//! Domain-neutral CSER effect bookkeeping for Linux-personality slices.
//!
//! The registry deliberately stores no futex queue, readiness source, pager
//! frame, or device payload.  Those typed indexes belong to the runtime layer.
//! It owns only immutable operation descriptors, generational identities,
//! scope/binding gates, reverse indexes, credits, recovery metadata, commit
//! receipts, and the publication ticket that crosses a lock boundary.

#![allow(dead_code)]

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct TaskKey {
    id: u64,
    generation: u64,
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct OperationClass(u32);

impl OperationClass {
    pub(crate) const fn new(value: u32) -> Self {
        Self(value)
    }

    pub(crate) const fn value(self) -> u32 {
        self.0
    }
}

/// A kernel-owned snapshot of the Linux syscall number and all six arguments.
///
/// The descriptor is copied out for inspection but has no mutating API.  A
/// portal operation presents an opaque [`PortalHandle`], never a rewritten set
/// of syscall argument registers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct CreditClass(u16);

impl CreditClass {
    pub(crate) const fn new(value: u16) -> Self {
        Self(value)
    }

    pub(crate) const fn value(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CreditLimit {
    class: CreditClass,
    units: u64,
}

impl CreditLimit {
    pub(crate) const fn new(class: CreditClass, units: u64) -> Self {
        Self { class, units }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CreditBalance {
    capacity: u64,
    free: u64,
    held: u64,
    committed: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
        for charge in charges {
            let balance = self
                .balances
                .get(&charge.class)
                .ok_or(RegistryError::UnknownCreditClass)?;
            if balance.held < charge.units {
                return Err(RegistryError::InvalidState);
            }
        }
        for charge in charges {
            let balance = self.balances.get_mut(&charge.class).unwrap();
            balance.held -= charge.units;
            balance.committed = balance
                .committed
                .checked_add(charge.units)
                .ok_or(RegistryError::CounterOverflow)?;
        }
        Ok(())
    }

    fn release(
        &mut self,
        charges: &[CreditCharge],
        state: CreditState,
    ) -> Result<(), RegistryError> {
        for charge in charges {
            let balance = self
                .balances
                .get(&charge.class)
                .ok_or(RegistryError::UnknownCreditClass)?;
            let owned = match state {
                CreditState::Held => balance.held,
                CreditState::Committed => balance.committed,
                CreditState::Released => return Err(RegistryError::InvalidState),
            };
            if owned < charge.units {
                return Err(RegistryError::InvalidState);
            }
        }
        for charge in charges {
            let balance = self.balances.get_mut(&charge.class).unwrap();
            match state {
                CreditState::Held => balance.held -= charge.units,
                CreditState::Committed => balance.committed -= charge.units,
                CreditState::Released => unreachable!(),
            }
            balance.free = balance
                .free
                .checked_add(charge.units)
                .ok_or(RegistryError::CounterOverflow)?;
        }
        Ok(())
    }

    fn is_idle(&self) -> bool {
        self.balances.values().all(|balance| {
            balance.free == balance.capacity && balance.held == 0 && balance.committed == 0
        })
    }

    fn totals(&self) -> CreditTotals {
        self.balances.values().fold(
            CreditTotals {
                capacity: 0,
                free: 0,
                held: 0,
                committed: 0,
            },
            |mut totals, balance| {
                totals.capacity += balance.capacity;
                totals.free += balance.free;
                totals.held += balance.held;
                totals.committed += balance.committed;
                totals
            },
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CreditTotals {
    pub(crate) capacity: u64,
    pub(crate) free: u64,
    pub(crate) held: u64,
    pub(crate) committed: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreditState {
    Held,
    Committed,
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScopePhase {
    Active,
    Closing,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalOutcome {
    Completed,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectPhase {
    Registered,
    Prepared,
    Committed,
    Terminal(TerminalOutcome),
}

impl EffectPhase {
    const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationMode {
    None,
    Required,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectIdentity {
    effect: EffectKey,
    scope: ScopeKey,
    task: TaskKey,
    operation: OperationClass,
    authority_epoch: u64,
    binding_epoch: u64,
    resources: BTreeSet<ResourceKey>,
}

impl EffectIdentity {
    pub(crate) const fn effect(&self) -> EffectKey {
        self.effect
    }

    pub(crate) const fn scope(&self) -> ScopeKey {
        self.scope
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

    pub(crate) fn resources(&self) -> &BTreeSet<ResourceKey> {
        &self.resources
    }
}

/// Opaque authority presented by a user-space service.
///
/// Fields are intentionally private.  A future portal ABI may serialize the
/// values, but callers cannot construct a valid handle through this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PortalHandle {
    scope: ScopeKey,
    effect: EffectKey,
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

    pub(crate) const fn authority_epoch(self) -> u64 {
        self.authority_epoch
    }

    pub(crate) const fn binding_epoch(self) -> u64 {
        self.binding_epoch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommitReceipt {
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CommitOutcome {
    Applied(CommitReceipt),
    AlreadyCommitted(CommitReceipt),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TerminalRequest {
    outcome: TerminalOutcome,
    result: i64,
    causal_commit: Option<CommitReceipt>,
}

impl TerminalRequest {
    pub(crate) const fn aborted(result: i64) -> Self {
        Self {
            outcome: TerminalOutcome::Aborted,
            result,
            causal_commit: None,
        }
    }

    pub(crate) const fn completed(result: i64) -> Self {
        Self {
            outcome: TerminalOutcome::Completed,
            result,
            causal_commit: None,
        }
    }

    pub(crate) fn completed_by(result: i64, causal_commit: CommitReceipt) -> Self {
        Self {
            outcome: TerminalOutcome::Completed,
            result,
            causal_commit: Some(causal_commit),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TerminalReceipt {
    effect: EffectKey,
    outcome: TerminalOutcome,
    result: i64,
    sequence: u64,
    causal_commit: Option<CommitReceipt>,
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
}

/// A receipt extracted while the runtime lock is held and acknowledged only
/// after the corresponding continuation is published outside that lock.
#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Terminalization {
    pub(crate) receipt: TerminalReceipt,
    pub(crate) publication: Option<PublicationTicket>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RegisterRequest {
    pub(crate) scope: ScopeKey,
    pub(crate) task: TaskKey,
    pub(crate) operation: OperationClass,
    pub(crate) descriptor: SyscallDescriptor,
    pub(crate) resources: Vec<ResourceKey>,
    pub(crate) credits: Vec<CreditCharge>,
    pub(crate) publication: PublicationMode,
}

/// One failure-atomic update of an effect's current resource membership.
///
/// `handle` authenticates the complete immutable effect identity. Only the
/// registry's current reverse-index association changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResourceMove {
    pub(crate) handle: PortalHandle,
    pub(crate) current_resources: Vec<ResourceKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RegisteredEffect {
    pub(crate) identity: EffectIdentity,
    pub(crate) handle: PortalHandle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectView {
    pub(crate) identity: EffectIdentity,
    /// Mutable current membership used by domain indexes. The authenticated
    /// identity above retains the immutable origin resources.
    pub(crate) current_resources: BTreeSet<ResourceKey>,
    pub(crate) descriptor: SyscallDescriptor,
    pub(crate) phase: EffectPhase,
    pub(crate) commit: Option<CommitReceipt>,
    pub(crate) terminal: Option<TerminalReceipt>,
    pub(crate) publication_pending: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
    terminal: Option<TerminalReceipt>,
    pending_publication: Option<PublicationTicket>,
    terminalizations: u8,
    publication_acks: u8,
}

impl EffectRecord {
    fn handle(&self) -> PortalHandle {
        PortalHandle {
            scope: self.identity.scope,
            effect: self.identity.effect,
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
            terminal: self.terminal.clone(),
            publication_pending: self.pending_publication.is_some(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScopeConfig {
    pub(crate) key: ScopeKey,
    pub(crate) authority_epoch: u64,
    pub(crate) binding_epoch: u64,
    pub(crate) supervisor: TaskKey,
    pub(crate) credits: Vec<CreditLimit>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecoveryState {
    crash_revision: u64,
    cohort: BTreeSet<EffectKey>,
    unadopted: BTreeSet<EffectKey>,
    snapshot: Option<RecoverySnapshot>,
    ready: Option<TaskKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RevokeState {
    sequence: u64,
    cohort: BTreeSet<EffectKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
    recovery: Option<RecoveryState>,
    revoke: Option<RevokeState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryEffectSummary {
    pub(crate) effect: EffectKey,
    pub(crate) binding_epoch: u64,
    pub(crate) phase: EffectPhase,
    pub(crate) descriptor_digest: u64,
    pub(crate) commit_sequence: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoverySnapshot {
    pub(crate) scope: ScopeKey,
    pub(crate) replacement: TaskKey,
    pub(crate) authority_epoch: u64,
    pub(crate) binding_epoch: u64,
    pub(crate) revision: u64,
    pub(crate) domain_revision: u64,
    pub(crate) effects: Vec<RecoveryEffectSummary>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryItem {
    pub(crate) handle: PortalHandle,
    pub(crate) descriptor: SyscallDescriptor,
    pub(crate) phase: EffectPhase,
    pub(crate) commit: Option<CommitReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CrashReceipt {
    pub(crate) scope: ScopeKey,
    pub(crate) previous_binding_epoch: u64,
    pub(crate) binding_epoch: u64,
    pub(crate) cohort: BTreeSet<EffectKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RebindReceipt {
    pub(crate) scope: ScopeKey,
    pub(crate) binding_epoch: u64,
    pub(crate) supervisor: TaskKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RevokeSelection {
    pub(crate) scope: ScopeKey,
    pub(crate) sequence: u64,
    pub(crate) closed_authority_epoch: u64,
    pub(crate) authority_epoch: u64,
    pub(crate) effects: BTreeSet<EffectKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RevokeDisposition {
    Abort,
    Drain(CommitReceipt),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RevokeEffect {
    pub(crate) effect: EffectKey,
    pub(crate) disposition: RevokeDisposition,
    pub(crate) publication_required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RegistryError {
    InvalidGeneration,
    InvalidCreditConfiguration,
    ScopeAlreadyExists,
    UnknownScope,
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
    AlreadyTerminal,
    CommitConflict,
    InvalidRevokeSelection,
    InvalidPublication,
    PublicationPending,
    NotQuiescent,
    Invariant(&'static str),
}

#[derive(Debug)]
pub(crate) struct EffectRegistry {
    scopes: BTreeMap<ScopeKey, ScopeRecord>,
    effects: BTreeMap<EffectKey, EffectRecord>,
    by_scope: BTreeMap<ScopeKey, BTreeSet<EffectKey>>,
    by_task: BTreeMap<TaskKey, BTreeSet<EffectKey>>,
    by_resource: BTreeMap<ResourceKey, BTreeSet<EffectKey>>,
    next_effect_id: u64,
    next_nonce: u64,
    next_commit_sequence: u64,
    next_terminal_sequence: u64,
    next_publication_sequence: u64,
    next_revoke_sequence: u64,
}

impl EffectRegistry {
    pub(crate) fn new() -> Self {
        Self {
            scopes: BTreeMap::new(),
            effects: BTreeMap::new(),
            by_scope: BTreeMap::new(),
            by_task: BTreeMap::new(),
            by_resource: BTreeMap::new(),
            next_effect_id: 1,
            next_nonce: 1,
            next_commit_sequence: 1,
            next_terminal_sequence: 1,
            next_publication_sequence: 1,
            next_revoke_sequence: 1,
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
        self.scopes.insert(
            config.key,
            ScopeRecord {
                key: config.key,
                phase: ScopePhase::Active,
                authority_epoch: config.authority_epoch,
                binding_epoch: config.binding_epoch,
                supervisor: Some(config.supervisor),
                fallback_running: false,
                revision: 0,
                domain_revision: 0,
                credits,
                recovery: None,
                revoke: None,
            },
        );
        Ok(())
    }

    pub(crate) fn register(
        &mut self,
        request: RegisterRequest,
    ) -> Result<RegisteredEffect, RegistryError> {
        validate_generation(request.scope.generation)?;
        validate_generation(request.task.generation)?;
        for resource in &request.resources {
            validate_generation(resource.generation)?;
        }
        let credits = normalize_charges(&request.credits)?;
        let resources: BTreeSet<_> = request.resources.into_iter().collect();
        let (authority_epoch, binding_epoch) = {
            let scope = self
                .scopes
                .get(&request.scope)
                .ok_or(RegistryError::UnknownScope)?;
            if scope.phase != ScopePhase::Active {
                return Err(RegistryError::ScopeNotActive);
            }
            if scope.supervisor.is_none() {
                return Err(RegistryError::NoSupervisor);
            }
            (scope.authority_epoch, scope.binding_epoch)
        };

        self.scopes
            .get_mut(&request.scope)
            .unwrap()
            .credits
            .reserve(&credits)?;
        let effect = EffectKey::new(self.take_effect_id()?, 1);
        let nonce = self.take_nonce()?;
        let identity = EffectIdentity {
            effect,
            scope: request.scope,
            task: request.task,
            operation: request.operation,
            authority_epoch,
            binding_epoch,
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
            terminal: None,
            pending_publication: None,
            terminalizations: 0,
            publication_acks: 0,
        };
        let handle = record.handle();
        self.insert_reverse_indexes(&record.identity, &record.current_resources);
        self.effects.insert(effect, record);
        self.bump_scope_revision(request.scope)?;
        Ok(RegisteredEffect { identity, handle })
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
                self.effects.get_mut(&effect).unwrap().phase = EffectPhase::Prepared;
                self.bump_scope_revision(scope)?;
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
        if scope.fallback_running {
            scope.recovery.as_mut().unwrap().ready = None;
        }
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
                || !matches!(
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
        let mut receipts = Vec::with_capacity(commits.len());
        for (offset, (handle, metadata)) in commits.iter().enumerate() {
            let effect = handle.effect;
            let record = self.effects.get(&effect).unwrap();
            let offset = u64::try_from(offset).map_err(|_| RegistryError::CounterOverflow)?;
            receipts.push(CommitReceipt {
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
        self.bump_scope_revision(scope_key.expect("nonempty commit batch has a scope"))?;
        Ok(receipts.into_iter().map(CommitOutcome::Applied).collect())
    }

    pub(crate) fn crash(
        &mut self,
        scope_key: ScopeKey,
        sender: TaskKey,
    ) -> Result<CrashReceipt, RegistryError> {
        let cohort = self.by_scope.get(&scope_key).cloned().unwrap_or_default();
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
        let previous_binding_epoch = scope.binding_epoch;
        scope.binding_epoch = scope
            .binding_epoch
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        scope.supervisor = None;
        scope.fallback_running = true;
        scope.revision = scope
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        scope.recovery = Some(RecoveryState {
            crash_revision: scope.revision,
            cohort: cohort.clone(),
            unadopted: cohort.clone(),
            snapshot: None,
            ready: None,
        });
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
        self.scopes
            .get_mut(&scope_key)
            .unwrap()
            .recovery
            .as_mut()
            .unwrap()
            .snapshot = Some(snapshot.clone());
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
        if old_handle.authority_epoch != scope.authority_epoch {
            return Err(RegistryError::StaleAuthority);
        }
        if scope.phase != ScopePhase::Active || scope.supervisor != Some(sender) {
            return Err(RegistryError::NoSupervisor);
        }
        if old_handle.scope != scope_key {
            return Err(RegistryError::InvalidHandle);
        }
        let effect = old_handle.effect;
        let record = self
            .effects
            .get(&effect)
            .ok_or(RegistryError::UnknownEffect)?;
        if record.identity.scope != scope_key {
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
        let nonce = self.take_nonce()?;
        let record = self.effects.get_mut(&effect).unwrap();
        record.identity.binding_epoch = binding_epoch;
        record.nonce = nonce;
        let new_handle = record.handle();
        let scope = self.scopes.get_mut(&scope_key).unwrap();
        scope.recovery.as_mut().unwrap().unadopted.remove(&effect);
        scope.revision = scope
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
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

    pub(crate) fn stage_terminal(
        &mut self,
        sender: TaskKey,
        handle: PortalHandle,
        request: TerminalRequest,
    ) -> Result<Terminalization, RegistryError> {
        let effect = self.validate_portal(sender, handle)?;
        self.stage_terminal_inner(effect, request)
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
        self.stage_terminal_inner(receipt.effect, TerminalRequest::completed(receipt.result))
    }

    pub(crate) fn acknowledge_publication(
        &mut self,
        ticket: &PublicationTicket,
    ) -> Result<(), RegistryError> {
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
        let charges = record.credits.clone();
        let credit_state = record.credit_state;
        self.scopes
            .get_mut(&scope_key)
            .unwrap()
            .credits
            .release(&charges, credit_state)?;
        let record = self.effects.get_mut(&ticket.effect).unwrap();
        record.credit_state = CreditState::Released;
        record.pending_publication = None;
        record.publication_acks = 1;
        self.bump_scope_revision(scope_key)?;
        Ok(())
    }

    pub(crate) fn revoke_begin(
        &mut self,
        scope_key: ScopeKey,
    ) -> Result<RevokeSelection, RegistryError> {
        let cohort = self.by_scope.get(&scope_key).cloned().unwrap_or_default();
        let sequence = self.take_revoke_sequence()?;
        let scope = self
            .scopes
            .get_mut(&scope_key)
            .ok_or(RegistryError::UnknownScope)?;
        if scope.phase != ScopePhase::Active {
            return Err(RegistryError::ScopeNotActive);
        }
        let closed_authority_epoch = scope.authority_epoch;
        scope.authority_epoch = scope
            .authority_epoch
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        scope.phase = ScopePhase::Closing;
        scope.supervisor = None;
        scope.fallback_running = false;
        scope.recovery = None;
        scope.revision = scope
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        scope.revoke = Some(RevokeState {
            sequence,
            cohort: cohort.clone(),
        });
        Ok(RevokeSelection {
            scope: scope_key,
            sequence,
            closed_authority_epoch,
            authority_epoch: scope.authority_epoch,
            effects: cohort,
        })
    }

    pub(crate) fn revoke_next(
        &self,
        selection: &RevokeSelection,
    ) -> Result<Option<RevokeEffect>, RegistryError> {
        self.validate_revoke_selection(selection)?;
        for effect in &selection.effects {
            let record = self
                .effects
                .get(effect)
                .ok_or(RegistryError::UnknownEffect)?;
            if record.phase.is_terminal() {
                continue;
            }
            return Ok(Some(RevokeEffect {
                effect: *effect,
                disposition: record
                    .commit
                    .clone()
                    .map_or(RevokeDisposition::Abort, RevokeDisposition::Drain),
                publication_required: record.publication_mode == PublicationMode::Required,
            }));
        }
        Ok(None)
    }

    pub(crate) fn stage_revoke_terminal(
        &mut self,
        selection: &RevokeSelection,
        effect: EffectKey,
        request: TerminalRequest,
    ) -> Result<Terminalization, RegistryError> {
        self.validate_revoke_selection(selection)?;
        if !selection.effects.contains(&effect) {
            return Err(RegistryError::InvalidRevokeSelection);
        }
        self.stage_terminal_inner(effect, request)
    }

    pub(crate) fn revoke_complete(
        &mut self,
        selection: &RevokeSelection,
    ) -> Result<(), RegistryError> {
        self.validate_revoke_selection(selection)?;
        if self
            .by_scope
            .get(&selection.scope)
            .is_some_and(|effects| !effects.is_empty())
        {
            return Err(RegistryError::NotQuiescent);
        }
        for effect in &selection.effects {
            let record = self
                .effects
                .get(effect)
                .ok_or(RegistryError::UnknownEffect)?;
            if !record.phase.is_terminal()
                || record.pending_publication.is_some()
                || record.credit_state != CreditState::Released
            {
                return Err(RegistryError::NotQuiescent);
            }
        }
        let scope = self.scopes.get_mut(&selection.scope).unwrap();
        if !scope.credits.is_idle() {
            return Err(RegistryError::NotQuiescent);
        }
        scope.phase = ScopePhase::Revoked;
        scope.revision = scope
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        Ok(())
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
        let pending_publications = self
            .effects
            .values()
            .filter(|record| {
                record.identity.scope == scope_key && record.pending_publication.is_some()
            })
            .count();
        Ok(RegistryProjection {
            phase: scope.phase,
            authority_epoch: scope.authority_epoch,
            binding_epoch: scope.binding_epoch,
            supervisor: scope.supervisor,
            fallback_running: scope.fallback_running,
            revision: scope.revision,
            domain_revision: scope.domain_revision,
            live_effects,
            pending_publications,
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
        let mut expected_by_scope: BTreeMap<ScopeKey, BTreeSet<EffectKey>> = BTreeMap::new();
        let mut expected_by_task: BTreeMap<TaskKey, BTreeSet<EffectKey>> = BTreeMap::new();
        let mut expected_by_resource: BTreeMap<ResourceKey, BTreeSet<EffectKey>> = BTreeMap::new();
        let mut expected_credits: BTreeMap<ScopeKey, BTreeMap<CreditClass, (u64, u64)>> =
            BTreeMap::new();
        let mut nonces = BTreeSet::new();
        let mut tickets = BTreeSet::new();

        for (key, scope) in &self.scopes {
            if key != &scope.key || key.generation == 0 {
                return Err(RegistryError::Invariant("scope identity mismatch"));
            }
            for balance in scope.credits.balances.values() {
                if balance.free + balance.held + balance.committed != balance.capacity {
                    return Err(RegistryError::Invariant("credit conservation"));
                }
            }
            if scope.phase == ScopePhase::Closing && scope.revoke.is_none() {
                return Err(RegistryError::Invariant(
                    "closing scope lacks revoke cohort",
                ));
            }
            if scope.phase == ScopePhase::Revoked && !scope.credits.is_idle() {
                return Err(RegistryError::Invariant("revoked scope retains credits"));
            }
            if let Some(recovery) = &scope.recovery {
                if !recovery.unadopted.is_subset(&recovery.cohort) {
                    return Err(RegistryError::Invariant("recovery cohort mismatch"));
                }
                for effect in &recovery.unadopted {
                    let record = self
                        .effects
                        .get(effect)
                        .ok_or(RegistryError::Invariant("unknown recovery effect"))?;
                    if record.identity.scope != *key
                        || record.phase.is_terminal()
                        || record.identity.binding_epoch >= scope.binding_epoch
                    {
                        return Err(RegistryError::Invariant("invalid unadopted effect"));
                    }
                }
                if recovery.cohort.iter().any(|effect| {
                    self.effects.get(effect).is_none_or(|record| {
                        record.identity.scope != *key || record.phase.is_terminal()
                    })
                }) {
                    return Err(RegistryError::Invariant("invalid recovery cohort effect"));
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
            if record.identity.binding_epoch > scope.binding_epoch {
                return Err(RegistryError::Invariant("effect has future binding"));
            }
            if !nonces.insert(record.nonce) {
                return Err(RegistryError::Invariant("duplicate portal nonce"));
            }

            match record.phase {
                EffectPhase::Registered | EffectPhase::Prepared => {
                    if record.commit.is_some()
                        || record.terminal.is_some()
                        || record.terminalizations != 0
                        || record.publication_acks != 0
                        || record.pending_publication.is_some()
                        || record.credit_state != CreditState::Held
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
                        || record.credit_state != CreditState::Committed
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
                    if outcome == TerminalOutcome::Completed
                        && record.commit.is_none()
                        && terminal.causal_commit.is_none()
                    {
                        return Err(RegistryError::Invariant("completion lacks commit cause"));
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
                && (terminal.effect != *key || terminal.sequence == 0)
            {
                return Err(RegistryError::Invariant(
                    "terminal receipt identity mismatch",
                ));
            }

            if !record.phase.is_terminal() {
                expected_by_scope
                    .entry(record.identity.scope)
                    .or_default()
                    .insert(*key);
                expected_by_task
                    .entry(record.identity.task)
                    .or_default()
                    .insert(*key);
                for resource in &record.current_resources {
                    expected_by_resource
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
                    true,
                )?,
                CreditState::Committed => add_expected_credits(
                    &mut expected_credits,
                    record.identity.scope,
                    &record.credits,
                    false,
                )?,
                CreditState::Released => {}
            }
        }

        if self.by_scope != expected_by_scope
            || self.by_task != expected_by_task
            || self.by_resource != expected_by_resource
        {
            return Err(RegistryError::Invariant("reverse index mismatch"));
        }

        for (scope_key, scope) in &self.scopes {
            let expected = expected_credits.get(scope_key);
            for (class, balance) in &scope.credits.balances {
                let (held, committed) = expected
                    .and_then(|classes| classes.get(class))
                    .copied()
                    .unwrap_or((0, 0));
                if balance.held != held || balance.committed != committed {
                    return Err(RegistryError::Invariant("credit ownership mismatch"));
                }
            }
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
        if record.identity.scope != handle.scope {
            return Err(RegistryError::InvalidHandle);
        }
        if handle.binding_epoch != scope.binding_epoch
            || record.identity.binding_epoch != handle.binding_epoch
        {
            return Err(RegistryError::StaleBinding);
        }
        if record.nonce != handle.nonce {
            return Err(RegistryError::InvalidHandle);
        }
        if scope.supervisor != Some(sender) {
            return Err(RegistryError::NoSupervisor);
        }
        Ok(handle.effect)
    }

    fn stage_terminal_inner(
        &mut self,
        effect: EffectKey,
        request: TerminalRequest,
    ) -> Result<Terminalization, RegistryError> {
        let (phase, own_commit, scope_key, identity, publication_mode) = {
            let record = self
                .effects
                .get(&effect)
                .ok_or(RegistryError::UnknownEffect)?;
            (
                record.phase,
                record.commit.clone(),
                record.identity.scope,
                record.identity.clone(),
                record.publication_mode,
            )
        };
        if phase.is_terminal() {
            return Err(RegistryError::AlreadyTerminal);
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
            }
        }
        let terminal = TerminalReceipt {
            effect,
            outcome: request.outcome,
            result: request.result,
            sequence: self.take_terminal_sequence()?,
            causal_commit: request.causal_commit,
        };
        let ticket = if publication_mode == PublicationMode::Required {
            Some(PublicationTicket {
                effect,
                scope: scope_key,
                terminal_sequence: terminal.sequence,
                ticket_sequence: self.take_publication_sequence()?,
                outcome: terminal.outcome,
                result: terminal.result,
            })
        } else {
            None
        };

        let current_resources = self.effects.get(&effect).unwrap().current_resources.clone();
        self.remove_reverse_indexes(&identity, &current_resources);
        let record = self.effects.get_mut(&effect).unwrap();
        record.phase = EffectPhase::Terminal(terminal.outcome);
        record.terminal = Some(terminal.clone());
        record.pending_publication = ticket.clone();
        record.terminalizations = 1;
        if let Some(recovery) = self
            .scopes
            .get_mut(&scope_key)
            .and_then(|scope| scope.recovery.as_mut())
        {
            recovery.unadopted.remove(&effect);
            recovery.cohort.remove(&effect);
        }
        if ticket.is_none() {
            let charges = record.credits.clone();
            let credit_state = record.credit_state;
            self.scopes
                .get_mut(&scope_key)
                .unwrap()
                .credits
                .release(&charges, credit_state)?;
            self.effects.get_mut(&effect).unwrap().credit_state = CreditState::Released;
        }
        self.bump_scope_revision(scope_key)?;
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
            || revoke.cohort != selection.effects
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
    }

    fn remove_reverse_indexes(
        &mut self,
        identity: &EffectIdentity,
        current_resources: &BTreeSet<ResourceKey>,
    ) {
        remove_index_member(&mut self.by_scope, identity.scope, identity.effect);
        remove_index_member(&mut self.by_task, identity.task, identity.effect);
        for resource in current_resources {
            remove_index_member(&mut self.by_resource, *resource, identity.effect);
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

    fn bump_scope_revision(&mut self, scope: ScopeKey) -> Result<(), RegistryError> {
        let scope = self
            .scopes
            .get_mut(&scope)
            .ok_or(RegistryError::UnknownScope)?;
        scope.revision = scope
            .revision
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;
        if scope.fallback_running {
            scope.recovery.as_mut().unwrap().ready = None;
        }
        Ok(())
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

fn remove_index_member<K: Ord + Copy>(
    index: &mut BTreeMap<K, BTreeSet<EffectKey>>,
    key: K,
    effect: EffectKey,
) {
    let remove_entry = if let Some(members) = index.get_mut(&key) {
        assert!(
            members.remove(&effect),
            "effect must exist in every reverse index"
        );
        members.is_empty()
    } else {
        panic!("effect reverse index is missing");
    };
    if remove_entry {
        index.remove(&key);
    }
}

fn add_expected_credits(
    expected: &mut BTreeMap<ScopeKey, BTreeMap<CreditClass, (u64, u64)>>,
    scope: ScopeKey,
    charges: &[CreditCharge],
    held: bool,
) -> Result<(), RegistryError> {
    for charge in charges {
        let entry = expected
            .entry(scope)
            .or_default()
            .entry(charge.class)
            .or_insert((0, 0));
        let counter = if held { &mut entry.0 } else { &mut entry.1 };
        *counter = counter
            .checked_add(charge.units)
            .ok_or(RegistryError::CounterOverflow)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
            credits: alloc::vec![CreditLimit::new(credit, 1)],
        })
        .unwrap();
    let effect = registry
        .register(RegisterRequest {
            scope,
            task,
            operation: OperationClass::new(9),
            descriptor: SyscallDescriptor::new(202, [0x402020, 129, 1, 0, 0, 0]),
            resources: alloc::vec![ResourceKey::new(9, 1, 1)],
            credits: alloc::vec![CreditCharge::new(credit, 1)],
            publication: PublicationMode::Required,
        })
        .unwrap();
    registry.prepare(v1, effect.handle).unwrap();
    let commit = match registry
        .commit(v1, effect.handle, CommitMetadata::new(1, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => unreachable!(),
    };

    registry.crash(scope, v1).unwrap();
    let stale_snapshot = registry.recovery_snapshot(scope, v2).unwrap();
    registry.ready(scope, v2, &stale_snapshot).unwrap();
    let terminal = registry.stage_kernel_completion(&commit).unwrap();
    registry.check_invariants().unwrap();
    assert_eq!(registry.recovery_remaining(scope), Ok(0));
    assert_eq!(
        registry.rebind(scope, v2),
        Err(RegistryError::RecoveryNotReady),
    );
    registry
        .acknowledge_publication(&terminal.publication.unwrap())
        .unwrap();

    let snapshot = registry.recovery_snapshot(scope, v2).unwrap();
    assert!(snapshot.effects.is_empty());
    registry.ready(scope, v2, &snapshot).unwrap();
    registry.rebind(scope, v2).unwrap();
    assert!(registry.recover_next(scope, v2).unwrap().is_none());
    let selection = registry.revoke_begin(scope).unwrap();
    assert!(registry.revoke_next(&selection).unwrap().is_none());
    registry.revoke_complete(&selection).unwrap();
    registry.check_invariants().unwrap();
}

/// Exercises the staged registry without changing the kernel's current run
/// sequence.  A later OSTD runner can call this and print the returned receipt.
pub(crate) fn bounded_registry_self_test() -> RegistrySelfTestReceipt {
    const WAIT_CREDIT: CreditClass = CreditClass::new(1);
    const SYSCALL_CREDIT: CreditClass = CreditClass::new(2);

    bounded_kernel_completion_during_recovery_self_test();

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
            credits: alloc::vec![
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
            resources: alloc::vec![futex_a],
            credits: alloc::vec![CreditCharge::new(WAIT_CREDIT, 1)],
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
            resources: alloc::vec![futex_a, futex_b],
            credits: alloc::vec![CreditCharge::new(SYSCALL_CREDIT, 1)],
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
                current_resources: alloc::vec![futex_b],
            }],
        )
        .unwrap()
        .pop()
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => unreachable!(),
    };
    assert!(
        !registry
            .effects_for_resource(futex_a)
            .contains(&wait.identity.effect())
    );
    assert!(
        registry
            .effects_for_resource(futex_b)
            .contains(&wait.identity.effect())
    );
    registry.check_invariants().unwrap();

    let crash = registry.crash(scope, v1).unwrap();
    assert_eq!(crash.cohort.len(), 2);
    let snapshot = registry.recovery_snapshot(scope, v2).unwrap();
    registry.ready(scope, v2, &snapshot).unwrap();
    registry.rebind(scope, v2).unwrap();

    let mut adopted = BTreeMap::new();
    while let Some(item) = registry.recover_next(scope, v2).unwrap() {
        let effect = item.handle.effect();
        let handle = registry.adopt(scope, v2, item.handle).unwrap();
        adopted.insert(effect, handle);
    }
    assert_eq!(adopted.len(), 2);
    assert_eq!(registry.recovery_remaining(scope).unwrap(), 0);
    assert_eq!(
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
    assert_eq!(
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
    assert_eq!(
        registry.revoke_complete(&selection),
        Err(RegistryError::NotQuiescent)
    );
    for ticket in &tickets {
        registry.acknowledge_publication(ticket).unwrap();
    }
    registry.revoke_complete(&selection).unwrap();
    registry.check_invariants().unwrap();
    let projection = registry.scope_projection(scope).unwrap();
    assert_eq!(projection.phase, ScopePhase::Revoked);
    assert_eq!(projection.live_effects, 0);
    assert_eq!(projection.pending_publications, 0);
    assert_eq!(projection.credits.free, projection.credits.capacity);

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
