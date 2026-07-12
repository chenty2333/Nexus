//! Bounded readiness/timeout successor over the common personality registry.
//!
//! The model deliberately owns no file-descriptor ABI.  It fixes the reusable
//! mechanism below epoll-like domains: generational sources and subscriptions,
//! atomic sample-and-arm, level/edge/one-shot selection, one immutable delivery
//! receipt, a positive timeout effect, crash/rebind/adopt, and scope closure.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use crate::{EffectId, ScopeId};

use super::registry::{
    EffectRegistry, RegistryBudget, RegistryCommitReceipt, RegistryCreditClass, RegistryEffectKind,
    RegistryEffectState, RegistryEffectToken, RegistryError, RegistryReadyToken,
    RegistryRecoverySnapshot, RegistryResourceKey, RegistryResources, RegistryRevocationStep,
    RegistryScopeView,
};
use super::{PersonalityBindingToken, PersonalityId, TaskId};

/// Readable readiness bit used by the bounded successor.
pub const READY_READABLE: u32 = 1 << 0;
/// Writable readiness bit used by the bounded successor.
pub const READY_WRITABLE: u32 = 1 << 1;
const READY_MASK: u32 = READY_READABLE | READY_WRITABLE;

/// Stable readiness-source identity.  Service generation is tracked
/// separately and fences stale source updates after restart.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReadySourceId(u64);

impl ReadySourceId {
    /// Returns the stable numeric identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Stable ready-set identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReadySetId(u64);

impl ReadySetId {
    /// Returns the stable numeric identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Generational handle for one persistent subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadinessSubscriptionToken {
    registry: RegistryEffectToken,
    id: u64,
    generation: u64,
}

impl ReadinessSubscriptionToken {
    /// Returns the common-registry effect.
    #[must_use]
    pub const fn registry(self) -> RegistryEffectToken {
        self.registry
    }

    /// Returns the subscription identity.
    #[must_use]
    pub const fn id(self) -> u64 {
        self.id
    }

    /// Returns the subscription generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// One readiness wait plus its positive timeout deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadinessWaitToken {
    wait: RegistryEffectToken,
    timer: RegistryEffectToken,
    set: ReadySetId,
}

impl ReadinessWaitToken {
    /// Returns the blocked wait effect.
    #[must_use]
    pub const fn wait(self) -> RegistryEffectToken {
        self.wait
    }

    /// Returns the timeout effect paired with the wait.
    #[must_use]
    pub const fn timer(self) -> RegistryEffectToken {
        self.timer
    }

    /// Returns the watched set.
    #[must_use]
    pub const fn set(self) -> ReadySetId {
        self.set
    }
}

/// Subscription trigger discipline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TriggerMode {
    /// Requeue after every delivery while the source remains ready.
    Level,
    /// Queue only on a not-ready to ready transition.
    Edge,
    /// Disable after the first delivery until explicit modification.
    OneShot,
}

/// Immutable parameters used when atomically arming a subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscriptionSpec {
    /// Readiness bits of interest.
    pub interest: u32,
    /// Level, edge, or one-shot trigger discipline.
    pub mode: TriggerMode,
    /// Domain-owned opaque user cookie.
    pub cookie: u64,
}

/// One event frozen into an immutable readiness receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadyEvent {
    /// Subscription identity and generation at selection.
    pub subscription_id: u64,
    /// Subscription generation at selection.
    pub subscription_generation: u64,
    /// Stable source identity.
    pub source: ReadySourceId,
    /// Source-service generation at selection.
    pub source_generation: u64,
    /// Source sequence sampled by the delivery.
    pub source_sequence: u64,
    /// Ready bits intersected with the subscription interest.
    pub observed_mask: u32,
    /// Domain-owned opaque user cookie.
    pub cookie: u64,
}

/// The unique winner for one wait/timeout/revoke race.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadinessOutcome {
    /// A nonempty event batch won.
    Ready,
    /// The positive timeout deadline won.
    TimedOut,
}

/// Immutable proof of a frozen wait outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyDeliveryReceipt {
    wait: ReadinessWaitToken,
    wait_commit: RegistryCommitReceipt,
    timer_commit: RegistryCommitReceipt,
    sequence: u64,
    outcome: ReadinessOutcome,
    events: Vec<ReadyEvent>,
}

impl ReadyDeliveryReceipt {
    /// Returns the wait identity.
    #[must_use]
    pub const fn wait(&self) -> ReadinessWaitToken {
        self.wait
    }

    /// Returns the domain receipt sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the frozen winner.
    #[must_use]
    pub const fn outcome(&self) -> ReadinessOutcome {
        self.outcome
    }

    /// Returns the frozen ordered event batch.
    #[must_use]
    pub fn events(&self) -> &[ReadyEvent] {
        &self.events
    }
}

/// Read-only readiness scope projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadinessScopeView {
    /// Common registry and lifecycle gate.
    pub registry: RegistryScopeView,
    /// Configured source.
    pub source: ReadySourceId,
    /// Current source-service generation.
    pub source_generation: u64,
    /// Current source sequence.
    pub source_sequence: u64,
    /// Current ready mask.
    pub source_mask: u32,
    /// Configured ready set.
    pub set: ReadySetId,
    /// Subscription IDs currently queued for delivery.
    pub queued: Vec<u64>,
    /// Number of live subscriptions.
    pub live_subscriptions: usize,
    /// Number of waits not yet terminal.
    pub live_waits: usize,
}

/// Exact generic and readiness-domain crash image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadinessRecoverySnapshot {
    registry: RegistryRecoverySnapshot,
    domain: ReadinessDomainSnapshot,
}

impl ReadinessRecoverySnapshot {
    /// Returns the represented scope.
    #[must_use]
    pub const fn scope(&self) -> ScopeId {
        self.registry.scope()
    }

    /// Returns the prospective replacement service.
    #[must_use]
    pub const fn personality(&self) -> PersonalityId {
        self.registry.personality()
    }
}

/// Ready proof wrapping the common registry proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadinessReadyToken {
    registry: RegistryReadyToken,
}

/// One domain-aware closure step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadinessRevocationStep {
    /// A frozen ready/timeout result was kernel-published as one batch.
    DrainedResolution {
        /// Wait effect whose frozen batch was published.
        wait: EffectId,
    },
    /// One remaining generic effect drained or aborted.
    Generic(RegistryRevocationStep),
}

/// Rejected readiness transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadinessError {
    /// Common registry rejection.
    Registry(RegistryError),
    /// Unknown stable source.
    UnknownSource,
    /// Unknown ready set.
    UnknownSet,
    /// Unknown or stale subscription token.
    StaleSubscription,
    /// Source update came from an old service generation.
    StaleSourceGeneration,
    /// Invalid readiness mask or zero interest.
    InvalidMask,
    /// Wait has no ready event to freeze.
    NotReady,
    /// Wait has already selected ready, timeout, or revoke.
    WinnerAlreadyChosen,
    /// Receipt is not the exact frozen receipt.
    ReceiptMismatch,
    /// Recovery image changed before ready.
    StaleRecoverySnapshot,
    /// Bounded counter overflow.
    CounterOverflow,
    /// Internal domain/registry refinement failed.
    InvariantViolation(&'static str),
}

impl From<RegistryError> for ReadinessError {
    fn from(value: RegistryError) -> Self {
        Self::Registry(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceRecord {
    id: ReadySourceId,
    generation: u64,
    sequence: u64,
    mask: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SubscriptionRecord {
    token: ReadinessSubscriptionToken,
    source: ReadySourceId,
    set: ReadySetId,
    interest: u32,
    mode: TriggerMode,
    cookie: u64,
    enabled: bool,
    active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WaitState {
    Pending,
    Resolved,
    Published,
    Revoking,
    Aborted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WaitRecord {
    token: ReadinessWaitToken,
    timeout_ticks: u64,
    state: WaitState,
    receipt: Option<ReadyDeliveryReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReadinessScopeRecord {
    source: SourceRecord,
    set: ReadySetId,
    subscriptions: BTreeSet<u64>,
    waits: BTreeSet<EffectId>,
    queue: VecDeque<u64>,
    queued: BTreeSet<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReadinessDomainSnapshot {
    source: SourceRecord,
    queue: Vec<u64>,
    subscriptions: Vec<SubscriptionRecord>,
    waits: Vec<WaitRecord>,
}

/// Deterministic `no_std + alloc` readiness successor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadinessModel {
    registry: EffectRegistry,
    next_source: u64,
    next_set: u64,
    next_subscription: u64,
    next_receipt: u64,
    scopes: BTreeMap<ScopeId, ReadinessScopeRecord>,
    subscriptions: BTreeMap<u64, SubscriptionRecord>,
    waits: BTreeMap<EffectId, WaitRecord>,
    timer_to_wait: BTreeMap<EffectId, EffectId>,
}

impl Default for ReadinessModel {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadinessModel {
    /// Creates an empty readiness model.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            registry: EffectRegistry::new(),
            next_source: 1,
            next_set: 1,
            next_subscription: 1,
            next_receipt: 1,
            scopes: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            waits: BTreeMap::new(),
            timer_to_wait: BTreeMap::new(),
        }
    }

    /// Creates one scope with one source and one ready set.
    pub fn create_scope(
        &mut self,
        personality: PersonalityId,
        budget: RegistryBudget,
        source_generation: u64,
        initial_mask: u32,
    ) -> Result<(ScopeId, PersonalityBindingToken, ReadySourceId, ReadySetId), ReadinessError> {
        Self::validate_mask(initial_mask, true)?;
        if source_generation == 0 {
            return Err(ReadinessError::StaleSourceGeneration);
        }
        let source = ReadySourceId(self.next_source);
        let set = ReadySetId(self.next_set);
        let next_source = self
            .next_source
            .checked_add(1)
            .ok_or(ReadinessError::CounterOverflow)?;
        let next_set = self
            .next_set
            .checked_add(1)
            .ok_or(ReadinessError::CounterOverflow)?;
        let (scope, binding) = self.registry.create_scope(personality, budget)?;
        self.next_source = next_source;
        self.next_set = next_set;
        self.scopes.insert(
            scope,
            ReadinessScopeRecord {
                source: SourceRecord {
                    id: source,
                    generation: source_generation,
                    sequence: 1,
                    mask: initial_mask,
                },
                set,
                subscriptions: BTreeSet::new(),
                waits: BTreeSet::new(),
                queue: VecDeque::new(),
                queued: BTreeSet::new(),
            },
        );
        Ok((scope, binding, source, set))
    }

    /// Atomically samples a source and arms one persistent subscription.
    pub fn attach(
        &mut self,
        binding: PersonalityBindingToken,
        task: TaskId,
        set: ReadySetId,
        source: ReadySourceId,
        spec: SubscriptionSpec,
    ) -> Result<ReadinessSubscriptionToken, ReadinessError> {
        Self::validate_mask(spec.interest, false)?;
        let local = self.local_scope(binding.scope())?;
        if local.set != set {
            return Err(ReadinessError::UnknownSet);
        }
        if local.source.id != source {
            return Err(ReadinessError::UnknownSource);
        }
        let sampled_ready = local.source.mask & spec.interest;
        let id = self.next_subscription;
        let next = id.checked_add(1).ok_or(ReadinessError::CounterOverflow)?;
        let registry = self.registry.register(
            binding,
            task,
            RegistryEffectKind::ReadinessSubscription,
            RegistryResources::pair(Self::set_resource(set), Self::source_resource(source)),
            RegistryCreditClass::ReadinessSubscription,
        )?;
        let token = ReadinessSubscriptionToken {
            registry,
            id,
            generation: 1,
        };
        self.next_subscription = next;
        self.subscriptions.insert(
            id,
            SubscriptionRecord {
                token,
                source,
                set,
                interest: spec.interest,
                mode: spec.mode,
                cookie: spec.cookie,
                enabled: true,
                active: true,
            },
        );
        let local = self.local_scope_mut(binding.scope())?;
        local.subscriptions.insert(id);
        if sampled_ready != 0 {
            Self::queue(local, id);
        }
        Ok(token)
    }

    /// Re-arms and advances one subscription generation.
    pub fn modify(
        &mut self,
        binding: PersonalityBindingToken,
        token: ReadinessSubscriptionToken,
        interest: u32,
        mode: TriggerMode,
        cookie: u64,
    ) -> Result<ReadinessSubscriptionToken, ReadinessError> {
        Self::validate_mask(interest, false)?;
        let record = *self.validate_subscription(token)?;
        if !self.registry.is_current(binding, token.registry) {
            return Err(ReadinessError::Registry(
                RegistryError::EffectIdentityMismatch,
            ));
        }
        let generation = token
            .generation
            .checked_add(1)
            .ok_or(ReadinessError::CounterOverflow)?;
        let scope = token.registry.scope();
        let ready = self.local_scope(scope)?.source.mask & interest;
        self.registry.domain_changed(scope)?;
        Self::remove_queued(self.local_scope_mut(scope)?, token.id);
        let replacement = ReadinessSubscriptionToken {
            generation,
            ..token
        };
        let current = self
            .subscriptions
            .get_mut(&token.id)
            .ok_or(ReadinessError::StaleSubscription)?;
        debug_assert_eq!(*current, record);
        current.token = replacement;
        current.interest = interest;
        current.mode = mode;
        current.cookie = cookie;
        current.enabled = true;
        if ready != 0 {
            Self::queue(self.local_scope_mut(scope)?, token.id);
        }
        Ok(replacement)
    }

    /// Updates one source under a service-generation fence.
    pub fn source_update(
        &mut self,
        scope: ScopeId,
        source: ReadySourceId,
        service_generation: u64,
        new_mask: u32,
    ) -> Result<u64, ReadinessError> {
        Self::validate_mask(new_mask, true)?;
        let local = self.local_scope(scope)?;
        if local.source.id != source {
            return Err(ReadinessError::UnknownSource);
        }
        if local.source.generation != service_generation {
            return Err(ReadinessError::StaleSourceGeneration);
        }
        if local.source.mask == new_mask {
            return Ok(local.source.sequence);
        }
        let sequence = local
            .source
            .sequence
            .checked_add(1)
            .ok_or(ReadinessError::CounterOverflow)?;
        let previous = local.source.mask;
        let subscriptions = local
            .subscriptions
            .iter()
            .map(|id| {
                self.subscriptions
                    .get(id)
                    .copied()
                    .ok_or(ReadinessError::InvariantViolation(
                        "scope names missing subscription",
                    ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.registry.domain_changed(scope)?;
        {
            let local = self.local_scope_mut(scope)?;
            local.source.mask = new_mask;
            local.source.sequence = sequence;
        }
        for subscription in subscriptions {
            let id = subscription.token.id;
            if !subscription.active || !subscription.enabled {
                continue;
            }
            let was = previous & subscription.interest;
            let now = new_mask & subscription.interest;
            if now == 0 {
                Self::remove_queued(self.local_scope_mut(scope)?, id);
                continue;
            }
            let should_queue = match subscription.mode {
                TriggerMode::Level => true,
                TriggerMode::Edge | TriggerMode::OneShot => was == 0,
            };
            if should_queue {
                Self::queue(self.local_scope_mut(scope)?, id);
            }
        }
        Ok(sequence)
    }

    /// Restarts the source service, clears readiness, and advances generation.
    pub fn source_restart(
        &mut self,
        scope: ScopeId,
        source: ReadySourceId,
        old_generation: u64,
    ) -> Result<u64, ReadinessError> {
        let local = self.local_scope(scope)?;
        if local.source.id != source {
            return Err(ReadinessError::UnknownSource);
        }
        if local.source.generation != old_generation {
            return Err(ReadinessError::StaleSourceGeneration);
        }
        let generation = old_generation
            .checked_add(1)
            .ok_or(ReadinessError::CounterOverflow)?;
        let sequence = local
            .source
            .sequence
            .checked_add(1)
            .ok_or(ReadinessError::CounterOverflow)?;
        self.registry.domain_changed(scope)?;
        let local = self.local_scope_mut(scope)?;
        local.source.generation = generation;
        local.source.sequence = sequence;
        local.source.mask = 0;
        local.queue.clear();
        local.queued.clear();
        Ok(generation)
    }

    /// Registers one blocking wait and one positive timeout effect atomically.
    pub fn wait_register(
        &mut self,
        binding: PersonalityBindingToken,
        task: TaskId,
        set: ReadySetId,
        timeout_ticks: u64,
    ) -> Result<ReadinessWaitToken, ReadinessError> {
        if timeout_ticks == 0 {
            return Err(ReadinessError::WinnerAlreadyChosen);
        }
        if self.local_scope(binding.scope())?.set != set {
            return Err(ReadinessError::UnknownSet);
        }
        let checkpoint = self.registry.clone();
        let wait = self.registry.register(
            binding,
            task,
            RegistryEffectKind::ReadinessWait,
            RegistryResources::one(Self::set_resource(set)),
            RegistryCreditClass::ReadinessWait,
        )?;
        let timer = match self.registry.register(
            binding,
            task,
            RegistryEffectKind::TimerDeadline,
            RegistryResources::one(Self::timer_resource(wait.effect())),
            RegistryCreditClass::Timer,
        ) {
            Ok(timer) => timer,
            Err(error) => {
                self.registry = checkpoint;
                return Err(error.into());
            }
        };
        let token = ReadinessWaitToken { wait, timer, set };
        self.waits.insert(
            wait.effect(),
            WaitRecord {
                token,
                timeout_ticks,
                state: WaitState::Pending,
                receipt: None,
            },
        );
        self.timer_to_wait.insert(timer.effect(), wait.effect());
        self.local_scope_mut(binding.scope())?
            .waits
            .insert(wait.effect());
        Ok(token)
    }

    /// Lets readiness win and freezes a nonempty ordered event batch.
    pub fn ready_commit(
        &mut self,
        binding: PersonalityBindingToken,
        token: ReadinessWaitToken,
        max_events: usize,
    ) -> Result<ReadyDeliveryReceipt, ReadinessError> {
        if max_events == 0 {
            return Err(ReadinessError::NotReady);
        }
        self.validate_wait(binding, token)?;
        let local = self.local_scope(binding.scope())?;
        let selected: Vec<_> = local.queue.iter().copied().take(max_events).collect();
        if selected.is_empty() {
            return Err(ReadinessError::NotReady);
        }
        for id in &selected {
            let subscription =
                self.subscriptions
                    .get(id)
                    .ok_or(ReadinessError::InvariantViolation(
                        "ready queue names missing subscription",
                    ))?;
            if !self
                .registry
                .is_current(binding, subscription.token.registry)
            {
                return Err(ReadinessError::Registry(
                    RegistryError::EffectIdentityMismatch,
                ));
            }
        }
        let events = selected
            .iter()
            .map(|id| {
                let subscription =
                    self.subscriptions
                        .get(id)
                        .ok_or(ReadinessError::InvariantViolation(
                            "ready queue names missing subscription",
                        ))?;
                let source = local.source;
                Ok(ReadyEvent {
                    subscription_id: *id,
                    subscription_generation: subscription.token.generation,
                    source: source.id,
                    source_generation: source.generation,
                    source_sequence: source.sequence,
                    observed_mask: source.mask & subscription.interest,
                    cookie: subscription.cookie,
                })
            })
            .collect::<Result<Vec<_>, ReadinessError>>()?;
        if events.iter().any(|event| event.observed_mask == 0) {
            return Err(ReadinessError::InvariantViolation(
                "queued subscription is no longer ready",
            ));
        }
        self.resolve(binding, token, ReadinessOutcome::Ready, events, &selected)
    }

    /// Lets the positive timeout win without fabricating readiness.
    pub fn timeout_commit(
        &mut self,
        binding: PersonalityBindingToken,
        token: ReadinessWaitToken,
    ) -> Result<ReadyDeliveryReceipt, ReadinessError> {
        self.validate_wait(binding, token)?;
        self.resolve(binding, token, ReadinessOutcome::TimedOut, Vec::new(), &[])
    }

    /// Publishes one frozen result and consumes both wait and timer once.
    pub fn publish(&mut self, receipt: &ReadyDeliveryReceipt) -> Result<(), ReadinessError> {
        let wait = receipt.wait.wait.effect();
        let record = self
            .waits
            .get(&wait)
            .ok_or(ReadinessError::ReceiptMismatch)?;
        if record.state != WaitState::Resolved || record.receipt.as_ref() != Some(receipt) {
            return Err(ReadinessError::ReceiptMismatch);
        }
        self.registry
            .complete_many(&[receipt.wait_commit, receipt.timer_commit])?;
        self.waits
            .get_mut(&wait)
            .expect("validated wait remains present")
            .state = WaitState::Published;
        Ok(())
    }

    /// Fences the crashed personality and preserves exact domain state.
    pub fn crash(&mut self, binding: PersonalityBindingToken) -> Result<(), ReadinessError> {
        self.registry.crash(binding)?;
        Ok(())
    }

    /// Selects the common kernel fallback.
    pub fn fallback_pick(&mut self, scope: ScopeId) -> Result<(), ReadinessError> {
        self.registry.fallback_pick(scope)?;
        Ok(())
    }

    /// Captures an exact registry plus readiness-domain recovery image.
    pub fn recovery_snapshot(
        &self,
        scope: ScopeId,
        personality: PersonalityId,
    ) -> Result<ReadinessRecoverySnapshot, ReadinessError> {
        let registry = self.registry.recovery_snapshot(scope, personality)?;
        Ok(ReadinessRecoverySnapshot {
            registry,
            domain: self.domain_snapshot(scope)?,
        })
    }

    /// Accepts readiness only while the complete image remains unchanged.
    pub fn ready(
        &mut self,
        snapshot: &ReadinessRecoverySnapshot,
    ) -> Result<ReadinessReadyToken, ReadinessError> {
        let current = self.recovery_snapshot(snapshot.scope(), snapshot.personality())?;
        if current != *snapshot {
            return Err(ReadinessError::StaleRecoverySnapshot);
        }
        Ok(ReadinessReadyToken {
            registry: self.registry.ready(&snapshot.registry)?,
        })
    }

    /// Installs a ready replacement without implicit effect adoption.
    pub fn rebind(
        &mut self,
        ready: ReadinessReadyToken,
    ) -> Result<PersonalityBindingToken, ReadinessError> {
        Ok(self.registry.rebind(ready.registry)?)
    }

    /// Explicitly adopts one subscription, wait, or timeout effect.
    pub fn adopt(
        &mut self,
        binding: PersonalityBindingToken,
        token: RegistryEffectToken,
    ) -> Result<RegistryEffectToken, ReadinessError> {
        let adopted = self.registry.adopt(binding, token)?;
        if let Some(subscription) = self
            .subscriptions
            .values_mut()
            .find(|subscription| subscription.token.registry.effect() == token.effect())
        {
            subscription.token.registry = adopted;
            return Ok(adopted);
        }
        if let Some(wait) = self.waits.get_mut(&token.effect()) {
            wait.token.wait = adopted;
            return Ok(adopted);
        }
        if let Some(wait_effect) = self.timer_to_wait.get(&token.effect()).copied() {
            self.waits
                .get_mut(&wait_effect)
                .ok_or(ReadinessError::InvariantViolation("timer lost wait"))?
                .token
                .timer = adopted;
            return Ok(adopted);
        }
        Err(ReadinessError::InvariantViolation(
            "registry effect lacks readiness-domain record",
        ))
    }

    /// Closes authority; ready and timeout commits are fenced after this point.
    pub fn revoke_begin(&mut self, scope: ScopeId) -> Result<(), ReadinessError> {
        self.registry.revoke_begin(scope)?;
        Ok(())
    }

    /// Performs one domain-aware closure step.
    pub fn revoke_next(
        &mut self,
        scope: ScopeId,
    ) -> Result<Option<ReadinessRevocationStep>, ReadinessError> {
        if let Some(wait) = self
            .local_scope(scope)?
            .waits
            .iter()
            .find(|effect| {
                self.waits
                    .get(effect)
                    .is_some_and(|wait| wait.state == WaitState::Resolved)
            })
            .copied()
        {
            let receipt = self
                .waits
                .get(&wait)
                .and_then(|wait| wait.receipt.clone())
                .ok_or(ReadinessError::InvariantViolation(
                    "resolved wait lacks receipt",
                ))?;
            self.publish(&receipt)?;
            return Ok(Some(ReadinessRevocationStep::DrainedResolution { wait }));
        }
        let Some(step) = self.registry.revoke_next(scope)? else {
            return Ok(None);
        };
        let effect = match step {
            RegistryRevocationStep::Drained { effect }
            | RegistryRevocationStep::Aborted { effect } => effect,
        };
        if let Some(subscription) = self
            .subscriptions
            .values_mut()
            .find(|subscription| subscription.token.registry.effect() == effect)
        {
            subscription.active = false;
            subscription.enabled = false;
            let id = subscription.token.id;
            Self::remove_queued(self.local_scope_mut(scope)?, id);
        } else {
            let wait_effect = self.timer_to_wait.get(&effect).copied().unwrap_or(effect);
            if let Some(wait) = self.waits.get_mut(&wait_effect) {
                wait.state = WaitState::Revoking;
                let wait_terminal = self
                    .registry
                    .effect(wait.token.wait.effect())
                    .is_some_and(|view| view.state.is_terminal());
                let timer_terminal = self
                    .registry
                    .effect(wait.token.timer.effect())
                    .is_some_and(|view| view.state.is_terminal());
                if wait_terminal && timer_terminal {
                    wait.state = WaitState::Aborted;
                }
            }
        }
        Ok(Some(ReadinessRevocationStep::Generic(step)))
    }

    /// Publishes quiescent closure after every domain and generic effect ends.
    pub fn revoke_complete(&mut self, scope: ScopeId) -> Result<(), ReadinessError> {
        if self.local_scope(scope)?.waits.iter().any(|effect| {
            self.waits.get(effect).is_some_and(|wait| {
                !matches!(wait.state, WaitState::Published | WaitState::Aborted)
            })
        }) || self.local_scope(scope)?.subscriptions.iter().any(|id| {
            self.subscriptions
                .get(id)
                .is_some_and(|record| record.active)
        }) || !self.local_scope(scope)?.queue.is_empty()
        {
            return Err(ReadinessError::InvariantViolation(
                "readiness domain is not quiescent",
            ));
        }
        self.registry.revoke_complete(scope)?;
        Ok(())
    }

    /// Returns one read-only scope projection.
    #[must_use]
    pub fn scope(&self, scope: ScopeId) -> Option<ReadinessScopeView> {
        let registry = self.registry.scope(scope)?;
        let local = self.scopes.get(&scope)?;
        Some(ReadinessScopeView {
            registry,
            source: local.source.id,
            source_generation: local.source.generation,
            source_sequence: local.source.sequence,
            source_mask: local.source.mask,
            set: local.set,
            queued: local.queue.iter().copied().collect(),
            live_subscriptions: local
                .subscriptions
                .iter()
                .filter(|id| {
                    self.subscriptions
                        .get(id)
                        .is_some_and(|record| record.active)
                })
                .count(),
            live_waits: local
                .waits
                .iter()
                .filter(|effect| {
                    self.waits.get(effect).is_some_and(|wait| {
                        !matches!(wait.state, WaitState::Published | WaitState::Aborted)
                    })
                })
                .count(),
        })
    }

    /// Returns the current generational identity of one wait.
    #[must_use]
    pub fn wait(&self, effect: EffectId) -> Option<ReadinessWaitToken> {
        self.waits.get(&effect).map(|record| record.token)
    }

    /// Audits queue, generation, receipt, typed-credit, and registry refinement.
    pub fn check_invariants(&self) -> Result<(), ReadinessError> {
        self.registry
            .check_invariants()
            .map_err(|_| ReadinessError::InvariantViolation("registry invariant"))?;
        for (scope, local) in &self.scopes {
            if local.source.generation == 0
                || local.source.sequence == 0
                || local.source.mask & !READY_MASK != 0
            {
                return Err(ReadinessError::InvariantViolation("invalid source state"));
            }
            let queued: BTreeSet<_> = local.queue.iter().copied().collect();
            if queued != local.queued || queued.len() != local.queue.len() {
                return Err(ReadinessError::InvariantViolation("queue/set mismatch"));
            }
            for id in &local.queue {
                let subscription =
                    self.subscriptions
                        .get(id)
                        .ok_or(ReadinessError::InvariantViolation(
                            "queue names missing subscription",
                        ))?;
                if !subscription.active
                    || !subscription.enabled
                    || subscription.set != local.set
                    || subscription.source != local.source.id
                    || subscription.interest & local.source.mask == 0
                {
                    return Err(ReadinessError::InvariantViolation("stale queued event"));
                }
            }
            for id in &local.subscriptions {
                let subscription =
                    self.subscriptions
                        .get(id)
                        .ok_or(ReadinessError::InvariantViolation(
                            "scope names missing subscription",
                        ))?;
                if subscription.token.registry.scope() != *scope
                    || subscription.token.id != *id
                    || subscription.token.generation == 0
                {
                    return Err(ReadinessError::InvariantViolation(
                        "invalid subscription identity",
                    ));
                }
                let generic = self
                    .registry
                    .effect(subscription.token.registry.effect())
                    .ok_or(ReadinessError::InvariantViolation(
                        "subscription missing registry effect",
                    ))?;
                if subscription.active == generic.state.is_terminal() {
                    return Err(ReadinessError::InvariantViolation(
                        "subscription registry refinement",
                    ));
                }
            }
            for effect in &local.waits {
                let wait = self
                    .waits
                    .get(effect)
                    .ok_or(ReadinessError::InvariantViolation(
                        "scope names missing wait",
                    ))?;
                if wait.token.wait.scope() != *scope
                    || wait.token.wait.effect() != *effect
                    || wait.timeout_ticks == 0
                    || self.timer_to_wait.get(&wait.token.timer.effect()) != Some(effect)
                {
                    return Err(ReadinessError::InvariantViolation("invalid wait identity"));
                }
                let wait_state = self
                    .registry
                    .effect(wait.token.wait.effect())
                    .ok_or(ReadinessError::InvariantViolation(
                        "wait missing registry effect",
                    ))?
                    .state;
                let timer_state = self
                    .registry
                    .effect(wait.token.timer.effect())
                    .ok_or(ReadinessError::InvariantViolation(
                        "timer missing registry effect",
                    ))?
                    .state;
                let valid = match wait.state {
                    WaitState::Pending => {
                        wait.receipt.is_none()
                            && wait_state == RegistryEffectState::Registered
                            && timer_state == RegistryEffectState::Registered
                    }
                    WaitState::Resolved => {
                        wait.receipt.is_some()
                            && wait_state == RegistryEffectState::Committed
                            && timer_state == RegistryEffectState::Committed
                    }
                    WaitState::Published => {
                        wait.receipt.is_some()
                            && wait_state == RegistryEffectState::Completed
                            && timer_state == RegistryEffectState::Completed
                    }
                    WaitState::Revoking => {
                        wait.receipt.is_none()
                            && (wait_state.is_terminal() || timer_state.is_terminal())
                    }
                    WaitState::Aborted => {
                        wait.receipt.is_none()
                            && wait_state == RegistryEffectState::Aborted
                            && timer_state == RegistryEffectState::Aborted
                    }
                };
                if !valid {
                    return Err(ReadinessError::InvariantViolation(
                        "wait registry refinement",
                    ));
                }
            }
        }
        Ok(())
    }

    fn resolve(
        &mut self,
        binding: PersonalityBindingToken,
        token: ReadinessWaitToken,
        outcome: ReadinessOutcome,
        events: Vec<ReadyEvent>,
        selected: &[u64],
    ) -> Result<ReadyDeliveryReceipt, ReadinessError> {
        let sequence = self.next_receipt;
        let next = sequence
            .checked_add(1)
            .ok_or(ReadinessError::CounterOverflow)?;
        let commits = self
            .registry
            .commit_many(binding, &[(token.wait, sequence), (token.timer, sequence)])?;
        let receipt = ReadyDeliveryReceipt {
            wait: token,
            wait_commit: commits[0],
            timer_commit: commits[1],
            sequence,
            outcome,
            events,
        };
        self.next_receipt = next;
        if outcome == ReadinessOutcome::Ready {
            let scope = binding.scope();
            let mut level = Vec::new();
            for id in selected {
                let removed = self.local_scope_mut(scope)?.queue.pop_front();
                debug_assert_eq!(removed, Some(*id));
                self.local_scope_mut(scope)?.queued.remove(id);
                let subscription = self
                    .subscriptions
                    .get_mut(id)
                    .expect("selected subscription remains present");
                match subscription.mode {
                    TriggerMode::Level => level.push(*id),
                    TriggerMode::Edge => {}
                    TriggerMode::OneShot => subscription.enabled = false,
                }
            }
            for id in level {
                Self::queue(self.local_scope_mut(scope)?, id);
            }
        }
        let record = self
            .waits
            .get_mut(&token.wait.effect())
            .expect("validated wait remains present");
        record.state = WaitState::Resolved;
        record.receipt = Some(receipt.clone());
        Ok(receipt)
    }

    fn validate_wait(
        &self,
        binding: PersonalityBindingToken,
        token: ReadinessWaitToken,
    ) -> Result<(), ReadinessError> {
        let record = self
            .waits
            .get(&token.wait.effect())
            .ok_or(ReadinessError::WinnerAlreadyChosen)?;
        if record.token != token || record.state != WaitState::Pending {
            return Err(ReadinessError::WinnerAlreadyChosen);
        }
        if !self.registry.is_current(binding, token.wait)
            || !self.registry.is_current(binding, token.timer)
        {
            return Err(ReadinessError::Registry(
                RegistryError::EffectIdentityMismatch,
            ));
        }
        Ok(())
    }

    fn validate_subscription(
        &self,
        token: ReadinessSubscriptionToken,
    ) -> Result<&SubscriptionRecord, ReadinessError> {
        self.subscriptions
            .get(&token.id)
            .filter(|record| record.token == token && record.active)
            .ok_or(ReadinessError::StaleSubscription)
    }

    fn domain_snapshot(&self, scope: ScopeId) -> Result<ReadinessDomainSnapshot, ReadinessError> {
        let local = self.local_scope(scope)?;
        Ok(ReadinessDomainSnapshot {
            source: local.source,
            queue: local.queue.iter().copied().collect(),
            subscriptions: local
                .subscriptions
                .iter()
                .map(|id| {
                    self.subscriptions
                        .get(id)
                        .copied()
                        .ok_or(ReadinessError::InvariantViolation(
                            "snapshot missing subscription",
                        ))
                })
                .collect::<Result<Vec<_>, _>>()?,
            waits: local
                .waits
                .iter()
                .map(|effect| {
                    self.waits
                        .get(effect)
                        .cloned()
                        .ok_or(ReadinessError::InvariantViolation("snapshot missing wait"))
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    fn local_scope(&self, scope: ScopeId) -> Result<&ReadinessScopeRecord, ReadinessError> {
        self.scopes
            .get(&scope)
            .ok_or(ReadinessError::InvariantViolation(
                "registry scope lacks readiness domain",
            ))
    }

    fn local_scope_mut(
        &mut self,
        scope: ScopeId,
    ) -> Result<&mut ReadinessScopeRecord, ReadinessError> {
        self.scopes
            .get_mut(&scope)
            .ok_or(ReadinessError::InvariantViolation(
                "registry scope lacks readiness domain",
            ))
    }

    fn queue(scope: &mut ReadinessScopeRecord, subscription: u64) {
        if scope.queued.insert(subscription) {
            scope.queue.push_back(subscription);
        }
    }

    fn remove_queued(scope: &mut ReadinessScopeRecord, subscription: u64) {
        scope.queued.remove(&subscription);
        scope.queue.retain(|candidate| *candidate != subscription);
    }

    const fn source_resource(source: ReadySourceId) -> RegistryResourceKey {
        RegistryResourceKey::new(0x1000_0000_0000_0000 | source.0)
    }

    const fn set_resource(set: ReadySetId) -> RegistryResourceKey {
        RegistryResourceKey::new(0x2000_0000_0000_0000 | set.0)
    }

    const fn timer_resource(wait: EffectId) -> RegistryResourceKey {
        RegistryResourceKey::new(0x3000_0000_0000_0000 | wait.get())
    }

    fn validate_mask(mask: u32, allow_zero: bool) -> Result<(), ReadinessError> {
        if mask & !READY_MASK != 0 || (!allow_zero && mask == 0) {
            Err(ReadinessError::InvalidMask)
        } else {
            Ok(())
        }
    }
}
