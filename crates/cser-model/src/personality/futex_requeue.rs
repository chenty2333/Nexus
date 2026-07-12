//! Two-key private-futex requeue successor over the common effect registry.
//!
//! The model is deliberately bounded to `max_wake <= 1` and
//! `max_requeue <= 1`, matching the retained Round 4 pressure input while
//! allowing arbitrary source and target queue lengths.  `RequeueCommit`
//! atomically freezes a disjoint woken/moved partition, commits the controller
//! and woken waiter, and moves the still-registered waiter between opaque
//! resource indexes.  Kernel publication later consumes only the controller
//! and woken waiter; a moved waiter remains pending with the same identity and
//! credit.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec;
use alloc::vec::Vec;

use crate::{EffectId, ScopeId};

use super::futex::FutexKey;
use super::registry::{
    EffectRegistry, RegistryBudget, RegistryCommitReceipt, RegistryCreditClass, RegistryEffectKind,
    RegistryEffectState, RegistryEffectToken, RegistryError, RegistryReadyToken,
    RegistryRecoverySnapshot, RegistryResourceKey, RegistryResourceMove, RegistryResources,
    RegistryRevocationStep, RegistryScopeView,
};
use super::{PersonalityBindingToken, PersonalityId, TaskId};

/// Authenticated futex operation descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexRequeueOperation {
    /// Wait on one private key if the word equals `expected`.
    Wait {
        /// Original private futex key.
        key: FutexKey,
        /// Expected word value.
        expected: u32,
    },
    /// Wake at most one waiter on `key`.
    Wake {
        /// Current queue key to match.
        key: FutexKey,
        /// Requested maximum, bounded to zero or one.
        max_wake: u32,
    },
    /// Wake and migrate waiters atomically between two keys.
    Requeue {
        /// Source queue key.
        source: FutexKey,
        /// Target queue key.
        target: FutexKey,
        /// Maximum woken waiters, bounded to zero or one.
        max_wake: u32,
        /// Maximum migrated waiters, bounded to zero or one.
        max_requeue: u32,
    },
}

/// Complete domain plus generic-registry identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutexRequeueToken {
    registry: RegistryEffectToken,
    operation: FutexRequeueOperation,
}

impl FutexRequeueToken {
    /// Constructs an inspectable token for deliberate negative tests.
    #[must_use]
    pub const fn from_parts(
        registry: RegistryEffectToken,
        operation: FutexRequeueOperation,
    ) -> Self {
        Self {
            registry,
            operation,
        }
    }

    /// Returns the generic registry identity.
    #[must_use]
    pub const fn registry(self) -> RegistryEffectToken {
        self.registry
    }

    /// Returns the immutable futex operation descriptor.
    #[must_use]
    pub const fn operation(self) -> FutexRequeueOperation {
        self.operation
    }

    /// Returns the inherited authority scope.
    #[must_use]
    pub const fn scope(self) -> ScopeId {
        self.registry.scope()
    }

    /// Returns the stable effect identity.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        self.registry.effect()
    }

    /// Returns the trapped task identity.
    #[must_use]
    pub const fn task(self) -> TaskId {
        self.registry.task()
    }
}

/// Domain lifecycle of one futex effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexRequeueState {
    /// Wait owns exactly one key queue position.
    WaitQueued,
    /// Wait was selected by a committed wake or requeue.
    WaitClaimed,
    /// Wake or requeue controller is captured but uncommitted.
    ControlCaptured,
    /// Controller owns an immutable receipt awaiting kernel publication.
    ControlCommitted,
    /// Unique success publication completed the continuation.
    Completed,
    /// Revocation consumed the uncommitted continuation.
    Aborted,
}

impl FutexRequeueState {
    /// Returns whether no later transition is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }
}

/// Immutable wake commit receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutexWakeReceipt {
    /// Wake controller identity at capture.
    pub token: FutexRequeueToken,
    /// Generic controller commit receipt.
    pub control: RegistryCommitReceipt,
    /// Selected waiter, if any.
    pub selected_wait: Option<EffectId>,
    /// Generic selected-wait commit receipt, if any.
    pub wait: Option<RegistryCommitReceipt>,
    /// Linux result frozen at commit.
    pub frozen_count: u32,
}

/// Immutable two-key requeue commit receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutexRequeueReceipt {
    /// Requeue controller identity at capture.
    pub token: FutexRequeueToken,
    /// Generic controller commit receipt.
    pub control: RegistryCommitReceipt,
    /// Waiter selected for wake, if any.
    pub woken_wait: Option<EffectId>,
    /// Generic woken-wait commit receipt, if any.
    pub woken: Option<RegistryCommitReceipt>,
    /// Waiter moved without terminalization, if any.
    pub moved_wait: Option<EffectId>,
    /// Frozen number selected for wake.
    pub woken_count: u32,
    /// Frozen number migrated to the target.
    pub requeued_count: u32,
    /// Linux result: `woken_count + requeued_count`.
    pub affected_count: u32,
}

/// Either committed controller receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexControlReceipt {
    /// One-key wake receipt.
    Wake(FutexWakeReceipt),
    /// Two-key requeue receipt.
    Requeue(FutexRequeueReceipt),
}

impl FutexControlReceipt {
    /// Returns the controller effect.
    #[must_use]
    pub const fn effect(self) -> EffectId {
        match self {
            Self::Wake(receipt) => receipt.token.effect(),
            Self::Requeue(receipt) => receipt.token.effect(),
        }
    }
}

/// Read-only projection of one futex effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutexRequeueEffectView {
    /// Complete current identity.
    pub token: FutexRequeueToken,
    /// Domain lifecycle state.
    pub state: FutexRequeueState,
    /// Current queue key for a queued wait.
    pub queued_on: Option<FutexKey>,
    /// Controller that claimed this wait, if any.
    pub selected_by: Option<EffectId>,
    /// Number of successful key migrations.
    pub migration_count: u32,
    /// Immutable controller receipt, if committed.
    pub receipt: Option<FutexControlReceipt>,
}

/// One key queue in a deterministic projection or snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FutexQueueView {
    /// Private futex key.
    pub key: FutexKey,
    /// Waiters in Nexus FIFO policy order.
    pub waits: Vec<EffectId>,
}

/// Read-only projection of one two-key futex scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FutexRequeueScopeView {
    /// Common registry state and indexes.
    pub registry: RegistryScopeView,
    /// Configured source key.
    pub source: FutexKey,
    /// Configured target key.
    pub target: FutexKey,
    /// Deterministic source and target queues.
    pub queues: Vec<FutexQueueView>,
    /// Committed controller effects awaiting publication.
    pub committed_controls: Vec<EffectId>,
}

/// Exact two-key recovery image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FutexRequeueRecoverySnapshot {
    registry: RegistryRecoverySnapshot,
    effects: Vec<FutexRequeueEffectView>,
    queues: Vec<FutexQueueView>,
    committed_controls: Vec<EffectId>,
}

impl FutexRequeueRecoverySnapshot {
    /// Returns the represented scope.
    #[must_use]
    pub const fn scope(&self) -> ScopeId {
        self.registry.scope()
    }

    /// Returns the prospective replacement identity.
    #[must_use]
    pub const fn personality(&self) -> PersonalityId {
        self.registry.personality()
    }

    /// Returns exact domain effect state.
    #[must_use]
    pub fn effects(&self) -> &[FutexRequeueEffectView] {
        &self.effects
    }

    /// Returns exact per-key queues.
    #[must_use]
    pub fn queues(&self) -> &[FutexQueueView] {
        &self.queues
    }
}

/// Ready proof for one exact registry plus futex snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutexRequeueReadyToken {
    registry: RegistryReadyToken,
}

/// One scope-local futex closure step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexRequeueRevocationStep {
    /// A committed controller and its woken waiter were drained together.
    DrainedControl {
        /// Controller effect.
        control: EffectId,
        /// Woken waiter, if any.
        wait: Option<EffectId>,
    },
    /// One uncommitted queued wait or captured controller was aborted.
    Aborted {
        /// Terminalized effect.
        effect: EffectId,
    },
}

/// Rejected two-key futex transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexRequeueError {
    /// Common registry or authority-gate rejection.
    Registry(RegistryError),
    /// Wait comparison failed and must return Linux `EAGAIN`.
    Again {
        /// Observed word value.
        observed: u32,
    },
    /// Key is not one of this bounded scope's configured private keys.
    WrongPrivateKey,
    /// Requeue source and target must be distinct in this bounded successor.
    SamePrivateKey,
    /// Source and target do not share one private address-space identity.
    WrongAddressSpace,
    /// Requested wake/requeue count exceeds the bounded value one.
    UnsupportedCount,
    /// Presented futex token differs from the complete recorded identity.
    EffectIdentityMismatch,
    /// Unknown domain effect.
    UnknownEffect(EffectId),
    /// Operation kind does not match the requested transition.
    WrongOperation,
    /// Domain state does not permit the transition.
    InvalidState {
        /// Actual domain state.
        state: FutexRequeueState,
    },
    /// Immutable domain receipt differs from committed state.
    ReceiptMismatch,
    /// Counter arithmetic overflowed.
    CounterOverflow,
    /// Internal domain relationships were inconsistent.
    InvariantViolation(&'static str),
}

impl From<RegistryError> for FutexRequeueError {
    fn from(error: RegistryError) -> Self {
        Self::Registry(error)
    }
}

/// Failure reported by a complete two-key invariant audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexRequeueInvariantViolation {
    /// Common registry invariant failed.
    Registry(super::registry::RegistryInvariantViolation),
    /// Queue membership and queued-wait records disagree.
    QueuePartition(ScopeId),
    /// Generic registry resource membership disagrees with queue location.
    ResourceMembership(EffectId),
    /// Wait identity, migration, selection, or state is inconsistent.
    WaitState(EffectId),
    /// Frozen controller result or selected relation is inconsistent.
    FrozenReceipt(EffectId),
    /// Committed-control reverse index is not exact.
    CommittedControlIndex(ScopeId),
    /// Domain and generic lifecycle states disagree.
    RegistryRefinement(EffectId),
}

impl From<super::registry::RegistryInvariantViolation> for FutexRequeueInvariantViolation {
    fn from(error: super::registry::RegistryInvariantViolation) -> Self {
        Self::Registry(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DomainRecordKind {
    Wait {
        queued_on: Option<FutexKey>,
        selected_by: Option<EffectId>,
        migration_count: u32,
    },
    Wake {
        receipt: Option<FutexWakeReceipt>,
    },
    Requeue {
        receipt: Option<FutexRequeueReceipt>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DomainRecord {
    token: FutexRequeueToken,
    state: FutexRequeueState,
    kind: DomainRecordKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FutexScopeRecord {
    source: FutexKey,
    target: FutexKey,
    words: BTreeMap<FutexKey, u32>,
    queues: BTreeMap<FutexKey, VecDeque<EffectId>>,
    committed_controls: BTreeSet<EffectId>,
}

/// Deterministic two-key private-futex requeue reference model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FutexRequeueModel {
    registry: EffectRegistry,
    next_domain_receipt: u64,
    scopes: BTreeMap<ScopeId, FutexScopeRecord>,
    effects: BTreeMap<EffectId, DomainRecord>,
}

impl Default for FutexRequeueModel {
    fn default() -> Self {
        Self::new()
    }
}

impl FutexRequeueModel {
    /// Creates an empty successor model.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            registry: EffectRegistry::new(),
            next_domain_receipt: 1,
            scopes: BTreeMap::new(),
            effects: BTreeMap::new(),
        }
    }

    /// Creates one active scope containing two distinct private keys.
    pub fn create_scope(
        &mut self,
        personality: PersonalityId,
        budget: RegistryBudget,
        source: FutexKey,
        source_word: u32,
        target: FutexKey,
        target_word: u32,
    ) -> Result<(ScopeId, PersonalityBindingToken), FutexRequeueError> {
        if source == target {
            return Err(FutexRequeueError::SamePrivateKey);
        }
        if source.address_space() != target.address_space()
            || source.address_space_generation() != target.address_space_generation()
        {
            return Err(FutexRequeueError::WrongAddressSpace);
        }
        let (scope, binding) = self.registry.create_scope(personality, budget)?;
        self.scopes.insert(
            scope,
            FutexScopeRecord {
                source,
                target,
                words: BTreeMap::from([(source, source_word), (target, target_word)]),
                queues: BTreeMap::from([(source, VecDeque::new()), (target, VecDeque::new())]),
                committed_controls: BTreeSet::new(),
            },
        );
        Ok((scope, binding))
    }

    /// Atomically compares, registers, charges, and queues one wait.
    pub fn wait_register(
        &mut self,
        binding: PersonalityBindingToken,
        task: TaskId,
        key: FutexKey,
        expected: u32,
    ) -> Result<FutexRequeueToken, FutexRequeueError> {
        let scope = self.local_scope(binding.scope())?;
        let observed = *scope
            .words
            .get(&key)
            .ok_or(FutexRequeueError::WrongPrivateKey)?;
        if observed != expected {
            return Err(FutexRequeueError::Again { observed });
        }
        let generic = self.registry.register(
            binding,
            task,
            RegistryEffectKind::FutexWait,
            RegistryResources::one(Self::resource(key)),
            RegistryCreditClass::FutexWait,
        )?;
        let token = FutexRequeueToken {
            registry: generic,
            operation: FutexRequeueOperation::Wait { key, expected },
        };
        self.effects.insert(
            token.effect(),
            DomainRecord {
                token,
                state: FutexRequeueState::WaitQueued,
                kind: DomainRecordKind::Wait {
                    queued_on: Some(key),
                    selected_by: None,
                    migration_count: 0,
                },
            },
        );
        self.local_scope_mut(binding.scope())?
            .queues
            .get_mut(&key)
            .expect("validated key retains a queue")
            .push_back(token.effect());
        Ok(token)
    }

    /// Captures a bounded wake controller without committing selection.
    pub fn capture_wake(
        &mut self,
        binding: PersonalityBindingToken,
        task: TaskId,
        key: FutexKey,
        max_wake: u32,
    ) -> Result<FutexRequeueToken, FutexRequeueError> {
        if max_wake > 1 {
            return Err(FutexRequeueError::UnsupportedCount);
        }
        self.validate_key(binding.scope(), key)?;
        let generic = self.registry.register(
            binding,
            task,
            RegistryEffectKind::FutexWake,
            RegistryResources::one(Self::resource(key)),
            RegistryCreditClass::Continuation,
        )?;
        let token = FutexRequeueToken {
            registry: generic,
            operation: FutexRequeueOperation::Wake { key, max_wake },
        };
        self.effects.insert(
            token.effect(),
            DomainRecord {
                token,
                state: FutexRequeueState::ControlCaptured,
                kind: DomainRecordKind::Wake { receipt: None },
            },
        );
        Ok(token)
    }

    /// Captures a bounded two-key requeue controller without committing.
    pub fn capture_requeue(
        &mut self,
        binding: PersonalityBindingToken,
        task: TaskId,
        source: FutexKey,
        target: FutexKey,
        max_wake: u32,
        max_requeue: u32,
    ) -> Result<FutexRequeueToken, FutexRequeueError> {
        if max_wake > 1 || max_requeue > 1 {
            return Err(FutexRequeueError::UnsupportedCount);
        }
        let scope = self.local_scope(binding.scope())?;
        if source == target {
            return Err(FutexRequeueError::SamePrivateKey);
        }
        if source != scope.source || target != scope.target {
            return Err(FutexRequeueError::WrongPrivateKey);
        }
        let generic = self.registry.register(
            binding,
            task,
            RegistryEffectKind::FutexRequeue,
            RegistryResources::pair(Self::resource(source), Self::resource(target)),
            RegistryCreditClass::Continuation,
        )?;
        let token = FutexRequeueToken {
            registry: generic,
            operation: FutexRequeueOperation::Requeue {
                source,
                target,
                max_wake,
                max_requeue,
            },
        };
        self.effects.insert(
            token.effect(),
            DomainRecord {
                token,
                state: FutexRequeueState::ControlCaptured,
                kind: DomainRecordKind::Requeue { receipt: None },
            },
        );
        Ok(token)
    }

    /// Commits one captured wake and freezes its selected waiter/count.
    pub fn wake_commit(
        &mut self,
        binding: PersonalityBindingToken,
        token: FutexRequeueToken,
    ) -> Result<FutexWakeReceipt, FutexRequeueError> {
        let record = *self.validate_domain_token(token)?;
        let FutexRequeueOperation::Wake { key, max_wake } = token.operation else {
            return Err(FutexRequeueError::WrongOperation);
        };
        if record.state != FutexRequeueState::ControlCaptured
            || record.kind != (DomainRecordKind::Wake { receipt: None })
        {
            return Err(FutexRequeueError::InvalidState {
                state: record.state,
            });
        }
        if !self.registry.is_current(binding, token.registry) {
            return Err(FutexRequeueError::EffectIdentityMismatch);
        }
        let selected_wait = if max_wake == 0 {
            None
        } else {
            self.current_queue_head(binding, key)?
        };
        let receipt_id = self.next_domain_receipt;
        let next_receipt = receipt_id
            .checked_add(1)
            .ok_or(FutexRequeueError::CounterOverflow)?;
        let mut requests = Vec::with_capacity(2);
        requests.push((token.registry, receipt_id));
        if let Some(wait) = selected_wait {
            requests.push((self.domain(wait)?.token.registry, receipt_id));
        }
        let generic = self.registry.commit_many(binding, &requests)?;
        let receipt = FutexWakeReceipt {
            token,
            control: generic[0],
            selected_wait,
            wait: selected_wait.map(|_| generic[1]),
            frozen_count: u32::from(selected_wait.is_some()),
        };
        self.next_domain_receipt = next_receipt;
        if let Some(wait) = selected_wait {
            let removed = self
                .local_scope_mut(binding.scope())?
                .queues
                .get_mut(&key)
                .expect("validated key retains queue")
                .pop_front();
            debug_assert_eq!(removed, Some(wait));
            let wait_record = self.effects.get_mut(&wait).expect("selected wait exists");
            wait_record.state = FutexRequeueState::WaitClaimed;
            wait_record.kind = match wait_record.kind {
                DomainRecordKind::Wait {
                    migration_count, ..
                } => DomainRecordKind::Wait {
                    queued_on: None,
                    selected_by: Some(token.effect()),
                    migration_count,
                },
                _ => unreachable!("queue contains only waits"),
            };
        }
        let control = self
            .effects
            .get_mut(&token.effect())
            .expect("control exists");
        control.state = FutexRequeueState::ControlCommitted;
        control.kind = DomainRecordKind::Wake {
            receipt: Some(receipt),
        };
        self.local_scope_mut(binding.scope())?
            .committed_controls
            .insert(token.effect());
        Ok(receipt)
    }

    /// Atomically commits one bounded two-key requeue.
    pub fn requeue_commit(
        &mut self,
        binding: PersonalityBindingToken,
        token: FutexRequeueToken,
    ) -> Result<FutexRequeueReceipt, FutexRequeueError> {
        let record = *self.validate_domain_token(token)?;
        let FutexRequeueOperation::Requeue {
            source,
            target,
            max_wake,
            max_requeue,
        } = token.operation
        else {
            return Err(FutexRequeueError::WrongOperation);
        };
        if record.state != FutexRequeueState::ControlCaptured
            || record.kind != (DomainRecordKind::Requeue { receipt: None })
        {
            return Err(FutexRequeueError::InvalidState {
                state: record.state,
            });
        }
        if !self.registry.is_current(binding, token.registry) {
            return Err(FutexRequeueError::EffectIdentityMismatch);
        }
        let queue = self
            .local_scope(binding.scope())?
            .queues
            .get(&source)
            .ok_or(FutexRequeueError::WrongPrivateKey)?;
        let mut cursor = 0usize;
        let woken_wait = if max_wake > 0 {
            queue.get(cursor).copied().filter(|effect| {
                self.effects.get(effect).is_some_and(|record| {
                    record.state == FutexRequeueState::WaitQueued
                        && self.registry.is_current(binding, record.token.registry)
                })
            })
        } else {
            None
        };
        if woken_wait.is_some() {
            cursor += 1;
        }
        let moved_wait = if max_requeue > 0 {
            queue.get(cursor).copied().filter(|effect| {
                self.effects.get(effect).is_some_and(|record| {
                    record.state == FutexRequeueState::WaitQueued
                        && self.registry.is_current(binding, record.token.registry)
                })
            })
        } else {
            None
        };
        let receipt_id = self.next_domain_receipt;
        let next_receipt = receipt_id
            .checked_add(1)
            .ok_or(FutexRequeueError::CounterOverflow)?;
        let mut requests = Vec::with_capacity(2);
        requests.push((token.registry, receipt_id));
        if let Some(wait) = woken_wait {
            requests.push((self.domain(wait)?.token.registry, receipt_id));
        }
        let moves: Vec<_> = moved_wait
            .map(|wait| RegistryResourceMove {
                token: self
                    .domain(wait)
                    .expect("selected moved wait exists")
                    .token
                    .registry,
                current_resources: RegistryResources::one(Self::resource(target)),
            })
            .into_iter()
            .collect();
        let generic = self
            .registry
            .commit_with_moves(binding, &requests, &moves)?;
        let woken_count = u32::from(woken_wait.is_some());
        let requeued_count = u32::from(moved_wait.is_some());
        let affected_count = woken_count
            .checked_add(requeued_count)
            .ok_or(FutexRequeueError::CounterOverflow)?;
        let receipt = FutexRequeueReceipt {
            token,
            control: generic[0],
            woken_wait,
            woken: woken_wait.map(|_| generic[1]),
            moved_wait,
            woken_count,
            requeued_count,
            affected_count,
        };
        self.next_domain_receipt = next_receipt;
        for expected in [woken_wait, moved_wait].into_iter().flatten() {
            let removed = self
                .local_scope_mut(binding.scope())?
                .queues
                .get_mut(&source)
                .expect("source queue remains present")
                .pop_front();
            debug_assert_eq!(removed, Some(expected));
        }
        if let Some(wait) = woken_wait {
            let wait_record = self.effects.get_mut(&wait).expect("woken wait exists");
            wait_record.state = FutexRequeueState::WaitClaimed;
            wait_record.kind = match wait_record.kind {
                DomainRecordKind::Wait {
                    migration_count, ..
                } => DomainRecordKind::Wait {
                    queued_on: None,
                    selected_by: Some(token.effect()),
                    migration_count,
                },
                _ => unreachable!("queue contains only waits"),
            };
        }
        if let Some(wait) = moved_wait {
            let wait_record = self.effects.get_mut(&wait).expect("moved wait exists");
            wait_record.kind = match wait_record.kind {
                DomainRecordKind::Wait {
                    migration_count, ..
                } => DomainRecordKind::Wait {
                    queued_on: Some(target),
                    selected_by: None,
                    migration_count: migration_count
                        .checked_add(1)
                        .expect("bounded migration count"),
                },
                _ => unreachable!("queue contains only waits"),
            };
            self.local_scope_mut(binding.scope())?
                .queues
                .get_mut(&target)
                .expect("target queue remains present")
                .push_back(wait);
        }
        let control = self
            .effects
            .get_mut(&token.effect())
            .expect("control exists");
        control.state = FutexRequeueState::ControlCommitted;
        control.kind = DomainRecordKind::Requeue {
            receipt: Some(receipt),
        };
        self.local_scope_mut(binding.scope())?
            .committed_controls
            .insert(token.effect());
        Ok(receipt)
    }

    /// Publishes a committed controller and its frozen woken waiter together.
    pub fn kernel_publish(
        &mut self,
        receipt: FutexControlReceipt,
    ) -> Result<(), FutexRequeueError> {
        let effect = receipt.effect();
        let record = *self.domain(effect)?;
        if record.state != FutexRequeueState::ControlCommitted {
            return Err(FutexRequeueError::InvalidState {
                state: record.state,
            });
        }
        let (stored, wait, generic): (FutexControlReceipt, Option<EffectId>, Vec<_>) = match receipt
        {
            FutexControlReceipt::Wake(wake) => {
                if record.kind
                    != (DomainRecordKind::Wake {
                        receipt: Some(wake),
                    })
                {
                    return Err(FutexRequeueError::ReceiptMismatch);
                }
                let mut generic = vec![wake.control];
                if let Some(wait_receipt) = wake.wait {
                    generic.push(wait_receipt);
                }
                (FutexControlReceipt::Wake(wake), wake.selected_wait, generic)
            }
            FutexControlReceipt::Requeue(requeue) => {
                if record.kind
                    != (DomainRecordKind::Requeue {
                        receipt: Some(requeue),
                    })
                {
                    return Err(FutexRequeueError::ReceiptMismatch);
                }
                let mut generic = vec![requeue.control];
                if let Some(wait_receipt) = requeue.woken {
                    generic.push(wait_receipt);
                }
                (
                    FutexControlReceipt::Requeue(requeue),
                    requeue.woken_wait,
                    generic,
                )
            }
        };
        if let Some(wait) = wait {
            let wait_record = self.domain(wait)?;
            if wait_record.state != FutexRequeueState::WaitClaimed {
                return Err(FutexRequeueError::InvariantViolation(
                    "receipt-selected wait is not claimed",
                ));
            }
        }
        self.registry.complete_many(&generic)?;
        if let Some(wait) = wait {
            self.effects
                .get_mut(&wait)
                .expect("selected wait exists")
                .state = FutexRequeueState::Completed;
        }
        let control = self.effects.get_mut(&effect).expect("control exists");
        control.state = FutexRequeueState::Completed;
        self.local_scope_mut(record.token.scope())?
            .committed_controls
            .remove(&effect);
        debug_assert_eq!(self.domain(effect)?.kind, record.kind);
        let _ = stored;
        Ok(())
    }

    /// Fences a crashed personality through the common registry.
    pub fn crash(&mut self, binding: PersonalityBindingToken) -> Result<(), FutexRequeueError> {
        self.registry.crash(binding)?;
        Ok(())
    }

    /// Selects kernel fallback through the common registry.
    pub fn fallback_pick(&mut self, scope: ScopeId) -> Result<(), FutexRequeueError> {
        self.registry.fallback_pick(scope)?;
        Ok(())
    }

    /// Captures an exact generic plus two-key domain recovery image.
    pub fn recovery_snapshot(
        &self,
        scope: ScopeId,
        personality: PersonalityId,
    ) -> Result<FutexRequeueRecoverySnapshot, FutexRequeueError> {
        let registry = self.registry.recovery_snapshot(scope, personality)?;
        let local = self.local_scope(scope)?;
        let effects = self
            .registry
            .scope(scope)
            .ok_or(FutexRequeueError::InvariantViolation(
                "missing registry scope",
            ))?
            .live_effects
            .iter()
            .map(|effect| {
                self.effect(*effect)
                    .ok_or(FutexRequeueError::UnknownEffect(*effect))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FutexRequeueRecoverySnapshot {
            registry,
            effects,
            queues: Self::queue_views(local),
            committed_controls: local.committed_controls.iter().copied().collect(),
        })
    }

    /// Accepts readiness only while the complete domain image remains exact.
    pub fn ready(
        &mut self,
        snapshot: &FutexRequeueRecoverySnapshot,
    ) -> Result<FutexRequeueReadyToken, FutexRequeueError> {
        let current = self.recovery_snapshot(snapshot.scope(), snapshot.personality())?;
        if current != *snapshot {
            return Err(FutexRequeueError::Registry(RegistryError::Personality(
                super::PersonalityError::StaleRecoverySnapshot,
            )));
        }
        let registry = self.registry.ready(&snapshot.registry)?;
        Ok(FutexRequeueReadyToken { registry })
    }

    /// Installs one ready replacement without implicit adoption.
    pub fn rebind(
        &mut self,
        ready: FutexRequeueReadyToken,
    ) -> Result<PersonalityBindingToken, FutexRequeueError> {
        Ok(self.registry.rebind(ready.registry)?)
    }

    /// Explicitly transfers one old-binding futex continuation.
    pub fn adopt(
        &mut self,
        binding: PersonalityBindingToken,
        token: FutexRequeueToken,
    ) -> Result<FutexRequeueToken, FutexRequeueError> {
        let record = *self.validate_domain_token(token)?;
        let generic = self.registry.adopt(binding, token.registry)?;
        let adopted = FutexRequeueToken {
            registry: generic,
            operation: token.operation,
        };
        self.effects
            .get_mut(&record.token.effect())
            .expect("validated domain effect exists")
            .token = adopted;
        Ok(adopted)
    }

    /// Closes authority explicitly.
    pub fn revoke_begin(&mut self, scope: ScopeId) -> Result<(), FutexRequeueError> {
        self.registry.revoke_begin(scope)?;
        Ok(())
    }

    /// Expires an incomplete recovery cohort and closes authority.
    pub fn watchdog_expire(&mut self, scope: ScopeId) -> Result<(), FutexRequeueError> {
        self.registry.watchdog_expire(scope)?;
        Ok(())
    }

    /// Performs one domain-aware scope-local closure step.
    pub fn revoke_next(
        &mut self,
        scope: ScopeId,
    ) -> Result<Option<FutexRequeueRevocationStep>, FutexRequeueError> {
        if let Some(control) = self
            .local_scope(scope)?
            .committed_controls
            .iter()
            .next()
            .copied()
        {
            let record = *self.domain(control)?;
            let receipt = match record.kind {
                DomainRecordKind::Wake {
                    receipt: Some(receipt),
                } => FutexControlReceipt::Wake(receipt),
                DomainRecordKind::Requeue {
                    receipt: Some(receipt),
                } => FutexControlReceipt::Requeue(receipt),
                _ => {
                    return Err(FutexRequeueError::InvariantViolation(
                        "committed-control index contains noncontroller",
                    ));
                }
            };
            let wait = match receipt {
                FutexControlReceipt::Wake(receipt) => receipt.selected_wait,
                FutexControlReceipt::Requeue(receipt) => receipt.woken_wait,
            };
            self.kernel_publish(receipt)?;
            return Ok(Some(FutexRequeueRevocationStep::DrainedControl {
                control,
                wait,
            }));
        }
        match self.registry.revoke_next(scope)? {
            None => Ok(None),
            Some(RegistryRevocationStep::Aborted { effect }) => {
                let record = *self.domain(effect)?;
                if let DomainRecordKind::Wait {
                    queued_on: Some(key),
                    selected_by,
                    migration_count,
                } = record.kind
                {
                    let queue = self
                        .local_scope_mut(scope)?
                        .queues
                        .get_mut(&key)
                        .expect("queued wait key remains configured");
                    let position = queue
                        .iter()
                        .position(|candidate| *candidate == effect)
                        .expect("registered wait remains queued");
                    queue.remove(position);
                    self.effects
                        .get_mut(&effect)
                        .expect("aborted wait exists")
                        .kind = DomainRecordKind::Wait {
                        queued_on: None,
                        selected_by,
                        migration_count,
                    };
                }
                self.effects
                    .get_mut(&effect)
                    .expect("aborted effect exists")
                    .state = FutexRequeueState::Aborted;
                Ok(Some(FutexRequeueRevocationStep::Aborted { effect }))
            }
            Some(RegistryRevocationStep::Drained { .. }) => {
                Err(FutexRequeueError::InvariantViolation(
                    "generic registry drained a committed effect outside controller index",
                ))
            }
        }
    }

    /// Publishes quiescent closure after all domain and generic indexes empty.
    pub fn revoke_complete(&mut self, scope: ScopeId) -> Result<(), FutexRequeueError> {
        let local = self.local_scope(scope)?;
        if !local.committed_controls.is_empty()
            || local.queues.values().any(|queue| !queue.is_empty())
        {
            return Err(FutexRequeueError::InvariantViolation(
                "domain queue or committed-control index is not quiescent",
            ));
        }
        self.registry.revoke_complete(scope)?;
        Ok(())
    }

    /// Returns a read-only scope projection.
    #[must_use]
    pub fn scope(&self, scope: ScopeId) -> Option<FutexRequeueScopeView> {
        let registry = self.registry.scope(scope)?;
        let local = self.scopes.get(&scope)?;
        Some(FutexRequeueScopeView {
            registry,
            source: local.source,
            target: local.target,
            queues: Self::queue_views(local),
            committed_controls: local.committed_controls.iter().copied().collect(),
        })
    }

    /// Returns a read-only domain effect projection.
    #[must_use]
    pub fn effect(&self, effect: EffectId) -> Option<FutexRequeueEffectView> {
        self.effects.get(&effect).map(|record| {
            let (queued_on, selected_by, migration_count, receipt) = match record.kind {
                DomainRecordKind::Wait {
                    queued_on,
                    selected_by,
                    migration_count,
                } => (queued_on, selected_by, migration_count, None),
                DomainRecordKind::Wake { receipt } => {
                    (None, None, 0, receipt.map(FutexControlReceipt::Wake))
                }
                DomainRecordKind::Requeue { receipt } => {
                    (None, None, 0, receipt.map(FutexControlReceipt::Requeue))
                }
            };
            FutexRequeueEffectView {
                token: record.token,
                state: record.state,
                queued_on,
                selected_by,
                migration_count,
                receipt,
            }
        })
    }

    /// Audits queue partition, migration, receipts, and registry refinement.
    pub fn check_invariants(&self) -> Result<(), FutexRequeueInvariantViolation> {
        self.registry.check_invariants()?;
        for (scope_id, local) in &self.scopes {
            let mut queued = BTreeSet::new();
            for (key, queue) in &local.queues {
                for effect in queue {
                    if !queued.insert(*effect) {
                        return Err(FutexRequeueInvariantViolation::QueuePartition(*scope_id));
                    }
                    let Some(record) = self.effects.get(effect) else {
                        return Err(FutexRequeueInvariantViolation::QueuePartition(*scope_id));
                    };
                    if record.state != FutexRequeueState::WaitQueued
                        || !matches!(
                            record.kind,
                            DomainRecordKind::Wait {
                                queued_on: Some(record_key),
                                ..
                            } if record_key == *key
                        )
                    {
                        return Err(FutexRequeueInvariantViolation::QueuePartition(*scope_id));
                    }
                    let generic = self
                        .registry
                        .effect(*effect)
                        .ok_or(FutexRequeueInvariantViolation::RegistryRefinement(*effect))?;
                    if generic.current_resources != RegistryResources::one(Self::resource(*key)) {
                        return Err(FutexRequeueInvariantViolation::ResourceMembership(*effect));
                    }
                }
            }
            let expected_queued: BTreeSet<_> = self
                .effects
                .iter()
                .filter_map(|(effect, record)| {
                    (record.token.scope() == *scope_id
                        && record.state == FutexRequeueState::WaitQueued)
                        .then_some(*effect)
                })
                .collect();
            if queued != expected_queued {
                return Err(FutexRequeueInvariantViolation::QueuePartition(*scope_id));
            }
            let expected_controls: BTreeSet<_> = self
                .effects
                .iter()
                .filter_map(|(effect, record)| {
                    (record.token.scope() == *scope_id
                        && record.state == FutexRequeueState::ControlCommitted)
                        .then_some(*effect)
                })
                .collect();
            if local.committed_controls != expected_controls {
                return Err(FutexRequeueInvariantViolation::CommittedControlIndex(
                    *scope_id,
                ));
            }
        }

        for (effect, record) in &self.effects {
            let generic = self
                .registry
                .effect(*effect)
                .ok_or(FutexRequeueInvariantViolation::RegistryRefinement(*effect))?;
            if generic.token != record.token.registry {
                return Err(FutexRequeueInvariantViolation::RegistryRefinement(*effect));
            }
            let expected_generic = match record.state {
                FutexRequeueState::WaitQueued | FutexRequeueState::ControlCaptured => {
                    RegistryEffectState::Registered
                }
                FutexRequeueState::WaitClaimed | FutexRequeueState::ControlCommitted => {
                    RegistryEffectState::Committed
                }
                FutexRequeueState::Completed => RegistryEffectState::Completed,
                FutexRequeueState::Aborted => RegistryEffectState::Aborted,
            };
            if generic.state != expected_generic {
                return Err(FutexRequeueInvariantViolation::RegistryRefinement(*effect));
            }
            match record.kind {
                DomainRecordKind::Wait {
                    queued_on,
                    selected_by,
                    migration_count,
                } => {
                    if !matches!(record.token.operation, FutexRequeueOperation::Wait { .. })
                        || (record.state == FutexRequeueState::WaitQueued
                            && (queued_on.is_none() || selected_by.is_some()))
                        || (record.state == FutexRequeueState::WaitClaimed
                            && (queued_on.is_some() || selected_by.is_none()))
                        || migration_count > 1
                    {
                        return Err(FutexRequeueInvariantViolation::WaitState(*effect));
                    }
                }
                DomainRecordKind::Wake { receipt } => {
                    if !matches!(record.token.operation, FutexRequeueOperation::Wake { .. })
                        || !Self::receipt_state_matches(record.state, receipt.is_some())
                    {
                        return Err(FutexRequeueInvariantViolation::FrozenReceipt(*effect));
                    }
                    if let Some(receipt) = receipt
                        && (receipt.frozen_count != u32::from(receipt.selected_wait.is_some())
                            || receipt.wait.is_some() != receipt.selected_wait.is_some())
                    {
                        return Err(FutexRequeueInvariantViolation::FrozenReceipt(*effect));
                    }
                }
                DomainRecordKind::Requeue { receipt } => {
                    if !matches!(
                        record.token.operation,
                        FutexRequeueOperation::Requeue { .. }
                    ) || !Self::receipt_state_matches(record.state, receipt.is_some())
                    {
                        return Err(FutexRequeueInvariantViolation::FrozenReceipt(*effect));
                    }
                    if let Some(receipt) = receipt
                        && (receipt.woken_count != u32::from(receipt.woken_wait.is_some())
                            || receipt.requeued_count != u32::from(receipt.moved_wait.is_some())
                            || receipt.affected_count
                                != receipt.woken_count + receipt.requeued_count
                            || receipt.woken.is_some() != receipt.woken_wait.is_some()
                            || (receipt.woken_wait.is_some()
                                && receipt.woken_wait == receipt.moved_wait))
                    {
                        return Err(FutexRequeueInvariantViolation::FrozenReceipt(*effect));
                    }
                }
            }
        }
        Ok(())
    }

    fn receipt_state_matches(state: FutexRequeueState, has_receipt: bool) -> bool {
        match state {
            FutexRequeueState::ControlCaptured | FutexRequeueState::Aborted => !has_receipt,
            FutexRequeueState::ControlCommitted | FutexRequeueState::Completed => has_receipt,
            FutexRequeueState::WaitQueued | FutexRequeueState::WaitClaimed => false,
        }
    }

    fn resource(key: FutexKey) -> RegistryResourceKey {
        RegistryResourceKey::new(key.aligned_address())
    }

    fn local_scope(&self, scope: ScopeId) -> Result<&FutexScopeRecord, FutexRequeueError> {
        self.scopes
            .get(&scope)
            .ok_or(FutexRequeueError::InvariantViolation(
                "registry scope lacks futex-requeue state",
            ))
    }

    fn local_scope_mut(
        &mut self,
        scope: ScopeId,
    ) -> Result<&mut FutexScopeRecord, FutexRequeueError> {
        self.scopes
            .get_mut(&scope)
            .ok_or(FutexRequeueError::InvariantViolation(
                "registry scope lacks futex-requeue state",
            ))
    }

    fn domain(&self, effect: EffectId) -> Result<&DomainRecord, FutexRequeueError> {
        self.effects
            .get(&effect)
            .ok_or(FutexRequeueError::UnknownEffect(effect))
    }

    fn validate_domain_token(
        &self,
        token: FutexRequeueToken,
    ) -> Result<&DomainRecord, FutexRequeueError> {
        let record = self.domain(token.effect())?;
        if record.token != token {
            return Err(FutexRequeueError::EffectIdentityMismatch);
        }
        Ok(record)
    }

    fn validate_key(&self, scope: ScopeId, key: FutexKey) -> Result<(), FutexRequeueError> {
        if !self.local_scope(scope)?.words.contains_key(&key) {
            return Err(FutexRequeueError::WrongPrivateKey);
        }
        Ok(())
    }

    fn current_queue_head(
        &self,
        binding: PersonalityBindingToken,
        key: FutexKey,
    ) -> Result<Option<EffectId>, FutexRequeueError> {
        let head = self
            .local_scope(binding.scope())?
            .queues
            .get(&key)
            .ok_or(FutexRequeueError::WrongPrivateKey)?
            .front()
            .copied();
        Ok(head.filter(|effect| {
            self.effects.get(effect).is_some_and(|record| {
                record.state == FutexRequeueState::WaitQueued
                    && self.registry.is_current(binding, record.token.registry)
            })
        }))
    }

    fn queue_views(scope: &FutexScopeRecord) -> Vec<FutexQueueView> {
        [scope.source, scope.target]
            .into_iter()
            .map(|key| FutexQueueView {
                key,
                waits: scope
                    .queues
                    .get(&key)
                    .expect("configured key retains queue")
                    .iter()
                    .copied()
                    .collect(),
            })
            .collect()
    }
}
