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
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_REGISTRY_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

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
            let free = balance
                .free
                .checked_add(charge.units)
                .ok_or(RegistryError::CounterOverflow)?;
            if free > balance.capacity {
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
                .expect("release capacity was validated");
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

    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
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
    closed_authority_epoch: u64,
    authority_epoch: u64,
    target_count: usize,
    selected_head: Option<EffectKey>,
    retired_recovery: Option<RecoveryState>,
    work: RevokeWorkCounters,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RevokeRecordAccess {
    Begin,
    Transition,
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
    closure_candidates: BTreeSet<EffectKey>,
    pending_publications: usize,
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
    pub(crate) target_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectRegistry {
    instance_id: u64,
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
            instance_id: next_registry_instance_id(),
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
                closure_candidates: BTreeSet::new(),
                pending_publications: 0,
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
        let scope_key = scope_key.expect("nonempty commit batch has a scope");
        let next_scope_revision = self.scopes[&scope_key]
            .revision
            .checked_add(1)
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
        scope.revision = next_scope_revision;
        if scope.fallback_running {
            scope.recovery.as_mut().unwrap().ready = None;
        }
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
        let (next_scope_revision, next_pending_publications) = {
            let scope = self.scopes.get(&scope_key).unwrap();
            let pending = scope
                .pending_publications
                .checked_sub(1)
                .ok_or(RegistryError::InvalidPublication)?;
            let revision = scope
                .revision
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
            (revision, pending)
        };
        self.scopes
            .get_mut(&scope_key)
            .unwrap()
            .credits
            .release(&charges, credit_state)?;
        let record = self.effects.get_mut(&ticket.effect).unwrap();
        record.credit_state = CreditState::Released;
        record.pending_publication = None;
        record.publication_acks = 1;
        let scope = self.scopes.get_mut(&scope_key).unwrap();
        scope.pending_publications = next_pending_publications;
        scope.revision = next_scope_revision;
        if scope.fallback_running {
            scope.recovery.as_mut().unwrap().ready = None;
        }
        Ok(())
    }

    pub(crate) fn revoke_begin(
        &mut self,
        scope_key: ScopeKey,
    ) -> Result<RevokeSelection, RegistryError> {
        let (closed_authority_epoch, authority_epoch, revision, target_count) = {
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
            let authority_epoch = scope
                .authority_epoch
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
            let revision = scope
                .revision
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
            let target_count = scope.closure_candidates.len();
            u64::try_from(target_count).map_err(|_| RegistryError::CounterOverflow)?;
            (
                scope.authority_epoch,
                authority_epoch,
                revision,
                target_count,
            )
        };
        let sequence = self.next_revoke_sequence;
        let next_revoke_sequence = sequence
            .checked_add(1)
            .ok_or(RegistryError::CounterOverflow)?;

        // All validation and overflow checks precede this point. Moving the
        // two indexes is allocation-free and does not visit any target record.
        self.next_revoke_sequence = next_revoke_sequence;
        let scope = self
            .scopes
            .get_mut(&scope_key)
            .expect("validated revoke scope must remain present");
        let cohort = core::mem::take(&mut scope.closure_candidates);
        let retired_recovery = scope.recovery.take();
        debug_assert_eq!(cohort.len(), target_count);
        scope.authority_epoch = authority_epoch;
        scope.phase = ScopePhase::Closing;
        scope.supervisor = None;
        scope.fallback_running = false;
        scope.revision = revision;
        scope.revoke = Some(RevokeState {
            sequence,
            cohort,
            closed_authority_epoch,
            authority_epoch,
            target_count,
            selected_head: None,
            retired_recovery,
            work: RevokeWorkCounters::default(),
        });
        Ok(RevokeSelection {
            scope: scope_key,
            sequence,
            closed_authority_epoch,
            authority_epoch,
            target_count,
        })
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
                self.by_scope
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
        let (next_revision, target_count) = {
            let scope = &self.scopes[&selection.scope];
            let revoke = scope.revoke.as_ref().unwrap();
            let target_count =
                u64::try_from(revoke.target_count).map_err(|_| RegistryError::CounterOverflow)?;
            if revoke.selected_head.is_some()
                || scope.pending_publications != 0
                || !scope.credits.is_idle()
                || revoke.work.terminalized != target_count
                || revoke.work.target_index_removals != target_count
                || revoke.work.completion_members_checked != 0
            {
                return Err(RegistryError::NotQuiescent);
            }
            let revision = scope
                .revision
                .checked_add(1)
                .ok_or(RegistryError::CounterOverflow)?;
            (revision, target_count)
        };
        let (scopes, effects) = (&mut self.scopes, &self.effects);
        let scope = scopes.get_mut(&selection.scope).unwrap();
        let revoke = scope.revoke.as_mut().unwrap();
        let mut members_checked = 0_u64;
        for effect in &revoke.cohort {
            let record = instrument_revoke_record_access(
                &mut revoke.work,
                &revoke.cohort,
                effects,
                selection.scope,
                *effect,
                RevokeRecordAccess::Transition,
            )?;
            if !record.phase.is_terminal()
                || record.pending_publication.is_some()
                || record.credit_state != CreditState::Released
            {
                return Err(RegistryError::NotQuiescent);
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

        // No fallible operation remains after the exact cohort validation.
        revoke.work.completion_members_checked = members_checked;
        revoke.cohort.clear();
        revoke.retired_recovery = None;
        scope.phase = ScopePhase::Revoked;
        scope.revision = next_revision;
        Ok(())
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
        let mut expected_by_scope: BTreeMap<ScopeKey, BTreeSet<EffectKey>> = BTreeMap::new();
        let mut expected_by_task: BTreeMap<TaskKey, BTreeSet<EffectKey>> = BTreeMap::new();
        let mut expected_by_resource: BTreeMap<ResourceKey, BTreeSet<EffectKey>> = BTreeMap::new();
        let mut expected_credits: BTreeMap<ScopeKey, BTreeMap<CreditClass, (u64, u64)>> =
            BTreeMap::new();
        let mut expected_pending_publications = BTreeMap::<ScopeKey, usize>::new();
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
                    ScopePhase::Active => unreachable!(),
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
            let expected_live = expected_by_scope.get(scope_key);
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
        let (
            phase,
            own_commit,
            scope_key,
            identity,
            current_resources,
            charges,
            credit_state,
            publication_mode,
        ) = {
            let record = self
                .effects
                .get(&effect)
                .ok_or(RegistryError::UnknownEffect)?;
            (
                record.phase,
                record.commit.clone(),
                record.identity.scope,
                record.identity.clone(),
                record.current_resources.clone(),
                record.credits.clone(),
                record.credit_state,
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
                if request.causal_commit.as_ref().is_some_and(|causal| {
                    !causal_commit_matches(self.instance_id, &self.effects, &identity, causal)
                }) {
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
        if let Some(recovery) = self
            .scopes
            .get_mut(&scope_key)
            .and_then(|scope| scope.recovery.as_mut())
        {
            recovery.unadopted.remove(&effect);
            recovery.cohort.remove(&effect);
        }
        let scope = self.scopes.get_mut(&scope_key).unwrap();
        scope.revision = next_scope_revision;
        scope.pending_publications = next_pending_publications;
        if scope.fallback_running {
            scope.recovery.as_mut().unwrap().ready = None;
        }
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
        assert!(
            self.scopes
                .get_mut(&identity.scope)
                .expect("effect scope must exist before reverse-index insertion")
                .closure_candidates
                .insert(identity.effect),
            "effect must be new to the closure candidate index"
        );
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
        let scope = self
            .scopes
            .get_mut(&identity.scope)
            .expect("effect scope must exist during reverse-index removal");
        match scope.phase {
            ScopePhase::Active => assert!(
                scope.closure_candidates.remove(&identity.effect),
                "active effect must exist in the closure candidate index"
            ),
            ScopePhase::Closing => assert!(
                scope
                    .revoke
                    .as_ref()
                    .is_some_and(|revoke| revoke.cohort.contains(&identity.effect)),
                "closing effect must remain in the frozen revoke cohort"
            ),
            ScopePhase::Revoked => panic!("revoked scope cannot retain a live effect"),
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

/// Authenticates an explicit completion cause against the exact commit stored
/// by this Registry. Cross-effect completion is allowed only inside one scope
/// causal envelope. A source commit may precede target adoption, but it may
/// never come from a future target binding or another authority epoch.
fn causal_commit_matches(
    registry_instance_id: u64,
    effects: &BTreeMap<EffectKey, EffectRecord>,
    target: &EffectIdentity,
    causal: &CommitReceipt,
) -> bool {
    if causal.registry_instance_id != registry_instance_id
        || causal.scope != target.scope
        || causal.authority_epoch != target.authority_epoch
        || causal.binding_epoch > target.binding_epoch
    {
        return false;
    }
    effects.get(&causal.effect).is_some_and(|source| {
        source.identity.scope == target.scope
            && source.commit.as_ref() == Some(causal)
            && matches!(
                source.phase,
                EffectPhase::Committed | EffectPhase::Terminal(TerminalOutcome::Completed)
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

/// A production-registry fixture used by the Stage 7B structural and timing
/// evaluators. `n` is the total live population, `k` is the target scope's
/// live population, and `h` is retained terminal history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Stage7bFixtureConfig {
    pub(crate) n: usize,
    pub(crate) k: usize,
    pub(crate) h: usize,
}

/// Exact Stage 7B fault-matrix identity.  Credit capacity is frozen here so a
/// fault adapter cannot manufacture a passing ledger from a gate population
/// such as `waiter_count` or `effect_count`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
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
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stage7bFaultTerminal {
    Aborted(i64),
    Completed(i64),
}

/// Linear pairing of one semantic authority and one opaque production
/// registry handle.  It is intentionally neither `Clone` nor `Copy`.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Stage7bFaultCredit {
    instance_id: u64,
    binding: Stage7bFaultBinding,
    handle: PortalHandle,
    commit: Option<CommitReceipt>,
    terminalized: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
                .ok_or(RegistryError::CounterOverflow)?,
            ScopePhase::Revoked => credits.free,
        };
        usize::try_from(units).map_err(|_| RegistryError::CounterOverflow)
    }
}

#[derive(Debug, Eq, PartialEq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
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
            credits: alloc::vec![CreditLimit::new(credit, units)],
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
            resources: alloc::vec![ResourceKey::new(namespace, resource_id, 1)],
            credits: alloc::vec![CreditCharge::new(self.credit, 1)],
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Stage7bNoCreditProjection {
    pub(crate) case: Stage7bFaultCase,
    pub(crate) binding: Stage7bFaultBinding,
    pub(crate) consumed: bool,
}

#[derive(Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Stage7bActiveFixture {
    config: Stage7bFixtureConfig,
    registry: EffectRegistry,
    target_scope: ScopeKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Stage7bCompleteFixture {
    config: Stage7bFixtureConfig,
    registry: EffectRegistry,
    target_scope: ScopeKey,
    selection: RevokeSelection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
                alloc::vec![CreditLimit::new(TARGET_CREDIT, target_capacity)]
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
                credits: alloc::vec![CreditLimit::new(credit, units)],
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
        resources: alloc::vec![ResourceKey::new(namespace, resource_id, 1)],
        credits: alloc::vec![CreditCharge::new(credit, 1)],
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
            credits: alloc::vec![CreditLimit::new(credit, 1)],
        })
        .unwrap();
    let registered = registry
        .register(RegisterRequest {
            scope,
            task,
            operation: OperationClass::new(namespace),
            descriptor: SyscallDescriptor::new(namespace as usize, [0; 6]),
            resources: alloc::vec![ResourceKey::new(namespace, 1, 1)],
            credits: alloc::vec![CreditCharge::new(credit, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    registry.prepare(task, registered.handle).unwrap();
    let commit = match registry
        .commit(task, registered.handle, CommitMetadata::new(1, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => unreachable!(),
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
            credits: alloc::vec![CreditLimit::new(POSITIVE_CREDIT, 2)],
        })
        .unwrap();
    let source = positive
        .register(RegisterRequest {
            scope: POSITIVE_SCOPE,
            task: POSITIVE_TASK,
            operation: OperationClass::new(1),
            descriptor: SyscallDescriptor::new(1, [1, 0, 0, 0, 0, 0]),
            resources: alloc::vec![ResourceKey::new(0x7bca, 1, 1)],
            credits: alloc::vec![CreditCharge::new(POSITIVE_CREDIT, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    let target = positive
        .register(RegisterRequest {
            scope: POSITIVE_SCOPE,
            task: POSITIVE_TASK,
            operation: OperationClass::new(2),
            descriptor: SyscallDescriptor::new(2, [2, 0, 0, 0, 0, 0]),
            resources: alloc::vec![ResourceKey::new(0x7bca, 2, 1)],
            credits: alloc::vec![CreditCharge::new(POSITIVE_CREDIT, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    positive.prepare(POSITIVE_TASK, source.handle).unwrap();
    let source_commit = match positive
        .commit(POSITIVE_TASK, source.handle, CommitMetadata::new(1, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => unreachable!(),
    };
    let target_terminal = positive
        .stage_terminal(
            POSITIVE_TASK,
            target.handle,
            TerminalRequest::completed_by(2, source_commit.clone()),
        )
        .unwrap();
    assert_eq!(
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
                credits: alloc::vec![CreditLimit::new(credit, 1)],
            })
            .unwrap();
    }
    let effect_a = cross_scope
        .register(RegisterRequest {
            scope: SCOPE_A,
            task: TASK_A,
            operation: OperationClass::new(3),
            descriptor: SyscallDescriptor::new(3, [0; 6]),
            resources: alloc::vec![ResourceKey::new(0x7bcb, 1, 1)],
            credits: alloc::vec![CreditCharge::new(CREDIT_A, 1)],
            publication: PublicationMode::None,
        })
        .unwrap();
    let effect_b = cross_scope
        .register(RegisterRequest {
            scope: SCOPE_B,
            task: TASK_B,
            operation: OperationClass::new(4),
            descriptor: SyscallDescriptor::new(4, [0; 6]),
            resources: alloc::vec![ResourceKey::new(0x7bcc, 1, 1)],
            credits: alloc::vec![CreditCharge::new(CREDIT_B, 1)],
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
        CommitOutcome::AlreadyCommitted(_) => unreachable!(),
    };
    let commit_b = match cross_scope
        .commit(TASK_B, effect_b.handle, CommitMetadata::new(4, 1))
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => unreachable!(),
    };
    let cross_scope_before = cross_scope.clone();
    assert_eq!(
        cross_scope.stage_terminal(
            TASK_A,
            effect_a.handle,
            TerminalRequest::completed_by(3, commit_b.clone()),
        ),
        Err(RegistryError::CommitConflict)
    );
    assert_eq!(cross_scope, cross_scope_before);
    assert_eq!(
        cross_scope.stage_terminal(
            TASK_B,
            effect_b.handle,
            TerminalRequest::completed_by(4, commit_a.clone()),
        ),
        Err(RegistryError::CommitConflict)
    );
    assert_eq!(cross_scope, cross_scope_before);
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
    assert_ne!(
        first_commit.registry_instance_id,
        second_commit.registry_instance_id
    );
    assert_eq!(first_commit.effect, second_commit.effect);
    assert_eq!(first_commit.scope, second_commit.scope);
    assert_eq!(first_commit.authority_epoch, second_commit.authority_epoch);
    assert_eq!(first_commit.binding_epoch, second_commit.binding_epoch);
    assert_eq!(first_commit.sequence, second_commit.sequence);
    assert_eq!(first_commit.result, second_commit.result);
    assert_eq!(first_commit.domain_revision, second_commit.domain_revision);
    assert_eq!(
        first_commit.descriptor_digest,
        second_commit.descriptor_digest
    );
    let first_before = first.clone();
    let second_before = second.clone();
    assert_eq!(
        first.stage_terminal(
            SHARED_TASK,
            first_handle,
            TerminalRequest::completed_by(1, second_commit.clone()),
        ),
        Err(RegistryError::CommitConflict)
    );
    assert_eq!(first, first_before);
    assert_eq!(second, second_before);
    assert_eq!(
        second.stage_terminal(
            SHARED_TASK,
            second_handle,
            TerminalRequest::completed_by(1, first_commit.clone()),
        ),
        Err(RegistryError::CommitConflict)
    );
    assert_eq!(first, first_before);
    assert_eq!(second, second_before);
    first.stage_kernel_completion(&first_commit).unwrap();
    second.stage_kernel_completion(&second_commit).unwrap();
    first.check_invariants().unwrap();
    second.check_invariants().unwrap();
}

fn stage7b_registry_refactor_self_test() {
    let config = Stage7bFixtureConfig { n: 8, k: 3, h: 2 };
    let fixture = Stage7bActiveFixture::new(config).unwrap();
    assert_eq!(fixture.target_projection().unwrap().live_effects, config.k);
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
    assert_eq!(work.begin_target_record_visits, 1);
    assert_eq!(work.unrelated_effect_visits, 1);
    assert_eq!(work.history_effect_visits, 1);

    let mut closed = fixture.clone();
    let selection = closed.close_all().unwrap();
    let observation = closed.observation(&selection).unwrap();
    assert_eq!(observation.config, config);
    assert_eq!(observation.work.target_count, 3);
    assert_eq!(observation.work.begin_target_record_visits, 0);
    assert_eq!(observation.work.next_calls, 4);
    assert_eq!(observation.work.head_selections, 3);
    assert_eq!(observation.work.terminalized, 3);
    assert_eq!(observation.work.completion_members_checked, 3);
    assert_eq!(observation.work.target_index_removals, 3);
    assert_eq!(observation.work.unrelated_effect_visits, 0);
    assert_eq!(observation.work.history_effect_visits, 0);
    assert_eq!(observation.work.pending_targets, 0);
    assert_eq!(observation.work.target_state, ScopePhase::Revoked);
    assert_eq!(observation.target.phase, ScopePhase::Revoked);
    closed.check_invariants().unwrap();
    let before = closed.registry.clone();
    assert_eq!(closed.begin(), Err(RegistryError::ScopeNotActive));
    assert_eq!(closed.registry, before);

    let mut empty = Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 4, k: 0, h: 3 }).unwrap();
    let empty_active = empty.target_projection().unwrap();
    assert_eq!(empty_active.credits.capacity, 0);
    assert_eq!(empty_active.credits.free, 0);
    assert_eq!(empty_active.credits.held, 0);
    assert_eq!(empty_active.credits.committed, 0);
    let selection = empty.close_all().unwrap();
    let empty_observation = empty.observation(&selection).unwrap();
    assert_eq!(empty_observation.work.target_count, 0);
    assert_eq!(empty_observation.work.next_calls, 1);
    assert_eq!(empty_observation.work.head_selections, 0);
    assert_eq!(empty_observation.work.terminalized, 0);
    assert_eq!(empty_observation.work.completion_members_checked, 0);
    assert_eq!(empty_observation.work.target_state, ScopePhase::Revoked);
    assert_eq!(empty_observation.target.credits, empty_active.credits);
    empty.check_invariants().unwrap();

    // Unknown and overflow failures do not consume the revoke sequence or
    // alter any registry-owned state.
    let mut unknown = fixture.clone();
    let before = unknown.registry.clone();
    assert_eq!(
        unknown.registry.revoke_begin(ScopeKey::new(0xffff, 1)),
        Err(RegistryError::UnknownScope)
    );
    assert_eq!(unknown.registry, before);

    let mut sequence_overflow = fixture.clone();
    sequence_overflow.registry.next_revoke_sequence = u64::MAX;
    let before = sequence_overflow.registry.clone();
    assert_eq!(
        sequence_overflow.begin(),
        Err(RegistryError::CounterOverflow)
    );
    assert_eq!(sequence_overflow.registry, before);

    let mut authority_overflow = fixture.clone();
    authority_overflow
        .registry
        .scopes
        .get_mut(&authority_overflow.target_scope)
        .unwrap()
        .authority_epoch = u64::MAX;
    let before = authority_overflow.registry.clone();
    assert_eq!(
        authority_overflow.begin(),
        Err(RegistryError::CounterOverflow)
    );
    assert_eq!(authority_overflow.registry, before);

    let mut revision_overflow = fixture.clone();
    revision_overflow
        .registry
        .scopes
        .get_mut(&revision_overflow.target_scope)
        .unwrap()
        .revision = u64::MAX;
    let before = revision_overflow.registry.clone();
    assert_eq!(
        revision_overflow.begin(),
        Err(RegistryError::CounterOverflow)
    );
    assert_eq!(revision_overflow.registry, before);

    let mut tampered = fixture.clone();
    let mut selection = tampered.begin().unwrap();
    selection.closed_authority_epoch += 1;
    let before = tampered.registry.clone();
    assert_eq!(
        tampered.registry.revoke_next(&selection),
        Err(RegistryError::InvalidRevokeSelection)
    );
    assert_eq!(tampered.registry, before);

    let mut complete_overflow = fixture.prepare_complete_baseline().unwrap();
    complete_overflow
        .registry
        .scopes
        .get_mut(&complete_overflow.target_scope)
        .unwrap()
        .revision = u64::MAX;
    let before = complete_overflow.registry.clone();
    assert_eq!(
        complete_overflow.complete(),
        Err(RegistryError::CounterOverflow)
    );
    assert_eq!(complete_overflow.registry, before);

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
    assert_eq!(
        terminal_overflow.registry.stage_revoke_terminal(
            &selection,
            effect,
            TerminalRequest::aborted(-125),
        ),
        Err(RegistryError::CounterOverflow)
    );
    assert_eq!(terminal_overflow.registry, before);

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
    assert_eq!(
        publication_overflow.registry.stage_revoke_terminal(
            &selection,
            effect,
            TerminalRequest::aborted(-125),
        ),
        Err(RegistryError::CounterOverflow)
    );
    assert_eq!(publication_overflow.registry, before);

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
    assert_eq!(
        revision_overflow.registry.stage_revoke_terminal(
            &selection,
            effect,
            TerminalRequest::aborted(-125),
        ),
        Err(RegistryError::CounterOverflow)
    );
    assert_eq!(revision_overflow.registry, before);

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
    assert_eq!(
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
    assert_eq!(
        ack_overflow.registry.acknowledge_publication(&ticket),
        Err(RegistryError::CounterOverflow)
    );
    assert_eq!(ack_overflow.registry, before);

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
    assert_eq!(
        commit_overflow
            .registry
            .commit(supervisor, handle, CommitMetadata::new(1, 1)),
        Err(RegistryError::CounterOverflow)
    );
    assert_eq!(commit_overflow.registry, before);

    // Re-reading a selected head is idempotent: it neither skips the target
    // nor counts a second head selection.
    let mut duplicate =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 2, k: 1, h: 1 }).unwrap();
    let selection = duplicate.begin().unwrap();
    let first = duplicate.registry.revoke_next(&selection).unwrap().unwrap();
    let second = duplicate.registry.revoke_next(&selection).unwrap().unwrap();
    assert_eq!(first, second);
    let work = duplicate
        .registry
        .revoke_work_projection(&selection)
        .unwrap();
    assert_eq!(work.next_calls, 2);
    assert_eq!(work.head_selections, 1);
    duplicate
        .registry
        .stage_revoke_terminal(&selection, first.effect, TerminalRequest::aborted(-125))
        .unwrap();
    assert!(
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
    assert!(matches!(
        commit_first.commit_single_target(handle).unwrap(),
        CommitOutcome::Applied(_)
    ));
    let selection = commit_first.begin().unwrap();
    commit_first.finish_revoke(&selection).unwrap();
    assert_eq!(
        commit_first.single_target_terminal(handle).unwrap(),
        TerminalOutcome::Completed
    );
    let observation = commit_first.observation(&selection).unwrap();
    assert_eq!(observation.target.credits.free, 1);
    assert_eq!(observation.target.credits.held, 0);
    assert_eq!(observation.target.credits.committed, 0);
    commit_first.check_invariants().unwrap();

    let mut revoke_first =
        Stage7bActiveFixture::new(Stage7bFixtureConfig { n: 1, k: 1, h: 0 }).unwrap();
    let handle = revoke_first.prepare_single_target().unwrap();
    let selection = revoke_first.begin().unwrap();
    revoke_first.finish_revoke(&selection).unwrap();
    assert_eq!(
        revoke_first.commit_single_target(handle),
        Err(RegistryError::StaleAuthority)
    );
    assert_eq!(
        revoke_first.single_target_terminal(handle).unwrap(),
        TerminalOutcome::Aborted
    );
    let observation = revoke_first.observation(&selection).unwrap();
    assert_eq!(observation.target.credits.free, 1);
    assert_eq!(observation.target.credits.held, 0);
    assert_eq!(observation.target.credits.committed, 0);
    revoke_first.check_invariants().unwrap();
}

/// Exercises the staged registry without changing the kernel's current run
/// sequence.  A later OSTD runner can call this and print the returned receipt.
pub(crate) fn bounded_registry_self_test() -> RegistrySelfTestReceipt {
    const WAIT_CREDIT: CreditClass = CreditClass::new(1);
    const SYSCALL_CREDIT: CreditClass = CreditClass::new(2);

    bounded_kernel_completion_during_recovery_self_test();
    stage7b_registry_refactor_self_test();

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
