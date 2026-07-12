// SPDX-License-Identifier: MPL-2.0

//! Kernel-owned readiness source/set foundation.
//!
//! Linux epoll remains a personality policy adapter. This module owns the
//! generational source/subscription identities, atomic sample+arm boundary,
//! queued source sequence, and immutable one-shot delivery receipt that CSER
//! needs below that adapter. The caller holds the common `LinuxRuntime` lock
//! while invoking these transitions and registers the named effects/resources
//! in `EffectRegistry` in the same critical section.

#![allow(dead_code)]

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec::Vec,
};

use crate::effect_registry::EffectKey;

/// Generic readable readiness bit used by the bounded successor.
pub(crate) const READY_READABLE: u32 = 1 << 0;
/// Generic writable readiness bit used by the bounded successor.
pub(crate) const READY_WRITABLE: u32 = 1 << 1;
/// Generic error readiness bit, always reported when observed.
pub(crate) const READY_ERROR: u32 = 1 << 2;
/// Generic hangup readiness bit, always reported when observed.
pub(crate) const READY_HANGUP: u32 = 1 << 3;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ReadySourceId {
    id: u64,
    generation: u64,
}

impl ReadySourceId {
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
pub(crate) struct ReadySetId {
    id: u64,
    generation: u64,
}

impl ReadySetId {
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
pub(crate) struct SubscriptionToken {
    id: u64,
    generation: u64,
}

impl SubscriptionToken {
    pub(crate) const fn id(self) -> u64 {
        self.id
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TriggerMode {
    Level,
    Edge,
    OneShot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadyEvent {
    pub(crate) subscription: SubscriptionToken,
    pub(crate) source: ReadySourceId,
    pub(crate) source_sequence: u64,
    pub(crate) observed_mask: u32,
    pub(crate) cookie: u64,
    pub(crate) binding_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadyDeliveryReceipt {
    id: u64,
    sequence: u64,
    wait_effect: EffectKey,
    events: Vec<ReadyEvent>,
}

impl ReadyDeliveryReceipt {
    pub(crate) const fn id(&self) -> u64 {
        self.id
    }

    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) const fn wait_effect(&self) -> EffectKey {
        self.wait_effect
    }

    pub(crate) fn events(&self) -> &[ReadyEvent] {
        &self.events
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QueuedReady {
    subscription: SubscriptionToken,
    source: ReadySourceId,
    source_sequence: u64,
    observed_mask: u32,
}

#[derive(Clone, Debug)]
struct SourceRecord {
    id: ReadySourceId,
    service_generation: u64,
    sequence: u64,
    mask: u32,
    subscriptions: BTreeSet<u64>,
}

#[derive(Clone, Debug)]
struct SubscriptionRecord {
    token: SubscriptionToken,
    effect: EffectKey,
    set: ReadySetId,
    source: ReadySourceId,
    interest: u32,
    mode: TriggerMode,
    cookie: u64,
    binding_generation: u64,
    enabled: bool,
    last_delivered_sequence: u64,
}

#[derive(Clone, Debug)]
struct ReadySetRecord {
    id: ReadySetId,
    subscriptions: BTreeSet<u64>,
    queue: VecDeque<QueuedReady>,
    queued: BTreeSet<u64>,
}

#[derive(Clone, Debug)]
struct DeliveryRecord {
    receipt: ReadyDeliveryReceipt,
    published: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReadinessError {
    InvalidGeneration,
    UnknownSource,
    UnknownSet,
    UnknownSubscription,
    StaleSource,
    StaleSubscription,
    DuplicateSubscription,
    InvalidInterest,
    InvalidMaxEvents,
    UnknownDelivery,
    ReceiptMismatch,
    AlreadyPublished,
    CounterOverflow,
    Invariant(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadinessCounts {
    pub(crate) sources: usize,
    pub(crate) sets: usize,
    pub(crate) subscriptions: usize,
    pub(crate) queued: usize,
    pub(crate) deliveries: usize,
    pub(crate) unpublished_deliveries: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct ReadinessCore {
    sources: BTreeMap<ReadySourceId, SourceRecord>,
    retired_source_generation: BTreeMap<u64, u64>,
    sets: BTreeMap<ReadySetId, ReadySetRecord>,
    subscriptions: BTreeMap<u64, SubscriptionRecord>,
    retired_subscription_generation: BTreeMap<u64, u64>,
    deliveries: BTreeMap<u64, DeliveryRecord>,
    next_source: u64,
    next_set: u64,
    next_subscription: u64,
    next_delivery: u64,
    next_delivery_sequence: u64,
    revision: u64,
}

impl ReadinessCore {
    pub(crate) fn new() -> Self {
        Self {
            sources: BTreeMap::new(),
            retired_source_generation: BTreeMap::new(),
            sets: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            retired_subscription_generation: BTreeMap::new(),
            deliveries: BTreeMap::new(),
            next_source: 1,
            next_set: 1,
            next_subscription: 1,
            next_delivery: 1,
            next_delivery_sequence: 1,
            revision: 0,
        }
    }

    pub(crate) fn create_source(
        &mut self,
        service_generation: u64,
        initial_mask: u32,
    ) -> Result<ReadySourceId, ReadinessError> {
        validate_generation(service_generation)?;
        validate_mask(initial_mask)?;
        let id = ReadySourceId::new(self.take_source_id()?, 1);
        self.sources.insert(
            id,
            SourceRecord {
                id,
                service_generation,
                sequence: 1,
                mask: initial_mask,
                subscriptions: BTreeSet::new(),
            },
        );
        self.bump_revision()?;
        Ok(id)
    }

    pub(crate) fn create_set(&mut self) -> Result<ReadySetId, ReadinessError> {
        let id = ReadySetId::new(self.take_set_id()?, 1);
        self.sets.insert(
            id,
            ReadySetRecord {
                id,
                subscriptions: BTreeSet::new(),
                queue: VecDeque::new(),
                queued: BTreeSet::new(),
            },
        );
        self.bump_revision()?;
        Ok(id)
    }

    /// Atomically samples the source and installs the subscription. If the
    /// source is already ready, the exact sampled sequence is queued before
    /// this transition returns; no sample->arm lost-wakeup window exists.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn attach(
        &mut self,
        set: ReadySetId,
        source: ReadySourceId,
        effect: EffectKey,
        binding_generation: u64,
        interest: u32,
        mode: TriggerMode,
        cookie: u64,
    ) -> Result<SubscriptionToken, ReadinessError> {
        validate_interest(interest)?;
        validate_generation(binding_generation)?;
        if !self.sets.contains_key(&set) {
            return Err(ReadinessError::UnknownSet);
        }
        let source_record = self
            .sources
            .get(&source)
            .ok_or(ReadinessError::UnknownSource)?;
        let sampled_mask = filter_ready(interest, source_record.mask);
        let sampled_sequence = source_record.sequence;
        let id = self.take_subscription_id()?;
        let token = SubscriptionToken { id, generation: 1 };
        self.subscriptions.insert(
            id,
            SubscriptionRecord {
                token,
                effect,
                set,
                source,
                interest,
                mode,
                cookie,
                binding_generation,
                enabled: true,
                last_delivered_sequence: 0,
            },
        );
        self.sources
            .get_mut(&source)
            .unwrap()
            .subscriptions
            .insert(id);
        self.sets.get_mut(&set).unwrap().subscriptions.insert(id);
        if sampled_mask != 0 {
            self.queue_if_new(token, source, sampled_sequence, sampled_mask)?;
        }
        self.bump_revision()?;
        Ok(token)
    }

    pub(crate) fn modify(
        &mut self,
        token: SubscriptionToken,
        binding_generation: u64,
        interest: u32,
        mode: TriggerMode,
        cookie: u64,
    ) -> Result<SubscriptionToken, ReadinessError> {
        validate_interest(interest)?;
        validate_generation(binding_generation)?;
        let record = self.validate_subscription(token)?.clone();
        if record.binding_generation != binding_generation {
            return Err(ReadinessError::StaleSubscription);
        }
        self.remove_queued(record.set, record.token.id);
        let generation = record
            .token
            .generation
            .checked_add(1)
            .ok_or(ReadinessError::CounterOverflow)?;
        let replacement = SubscriptionToken {
            id: record.token.id,
            generation,
        };
        let source = self
            .sources
            .get(&record.source)
            .ok_or(ReadinessError::UnknownSource)?;
        let sampled_mask = filter_ready(interest, source.mask);
        let sampled_sequence = source.sequence;
        let current = self.subscriptions.get_mut(&record.token.id).unwrap();
        current.token = replacement;
        current.interest = interest;
        current.mode = mode;
        current.cookie = cookie;
        current.enabled = true;
        current.last_delivered_sequence = 0;
        if sampled_mask != 0 {
            self.queue_if_new(replacement, record.source, sampled_sequence, sampled_mask)?;
        }
        self.bump_revision()?;
        Ok(replacement)
    }

    /// Transfers one live subscription to a replacement service binding.
    pub(crate) fn adopt_subscription(
        &mut self,
        token: SubscriptionToken,
        old_binding_generation: u64,
        new_binding_generation: u64,
    ) -> Result<(), ReadinessError> {
        validate_generation(old_binding_generation)?;
        validate_generation(new_binding_generation)?;
        if old_binding_generation >= new_binding_generation {
            return Err(ReadinessError::StaleSubscription);
        }
        let record = self.validate_subscription(token)?;
        if record.binding_generation != old_binding_generation {
            return Err(ReadinessError::StaleSubscription);
        }
        self.subscriptions
            .get_mut(&token.id)
            .unwrap()
            .binding_generation = new_binding_generation;
        self.bump_revision()?;
        Ok(())
    }

    pub(crate) fn detach(&mut self, token: SubscriptionToken) -> Result<EffectKey, ReadinessError> {
        let record = self.validate_subscription(token)?.clone();
        self.remove_queued(record.set, record.token.id);
        self.sources
            .get_mut(&record.source)
            .ok_or(ReadinessError::UnknownSource)?
            .subscriptions
            .remove(&record.token.id);
        self.sets
            .get_mut(&record.set)
            .ok_or(ReadinessError::UnknownSet)?
            .subscriptions
            .remove(&record.token.id);
        self.subscriptions.remove(&record.token.id);
        self.retired_subscription_generation.insert(
            record.token.id,
            record
                .token
                .generation
                .checked_add(1)
                .ok_or(ReadinessError::CounterOverflow)?,
        );
        self.bump_revision()?;
        Ok(record.effect)
    }

    pub(crate) fn source_update(
        &mut self,
        source: ReadySourceId,
        service_generation: u64,
        new_mask: u32,
    ) -> Result<u64, ReadinessError> {
        validate_mask(new_mask)?;
        let Some(record) = self.sources.get(&source) else {
            return if self.retired_source_generation.contains_key(&source.id) {
                Err(ReadinessError::StaleSource)
            } else {
                Err(ReadinessError::UnknownSource)
            };
        };
        if record.service_generation != service_generation {
            return Err(ReadinessError::StaleSource);
        }
        if record.mask == new_mask {
            return Ok(record.sequence);
        }
        let sequence = record
            .sequence
            .checked_add(1)
            .ok_or(ReadinessError::CounterOverflow)?;
        let subscriptions: Vec<_> = record.subscriptions.iter().copied().collect();
        let previous_mask = record.mask;
        let source_record = self.sources.get_mut(&source).unwrap();
        source_record.mask = new_mask;
        source_record.sequence = sequence;

        for id in subscriptions {
            let subscription = self
                .subscriptions
                .get(&id)
                .ok_or(ReadinessError::Invariant(
                    "source names missing subscription",
                ))?
                .clone();
            if !subscription.enabled {
                continue;
            }
            let now = filter_ready(subscription.interest, new_mask);
            if now == 0 {
                self.remove_queued(subscription.set, id);
                continue;
            }
            let was = filter_ready(subscription.interest, previous_mask);
            let should_queue = match subscription.mode {
                TriggerMode::Level => true,
                TriggerMode::Edge | TriggerMode::OneShot => was == 0 || now != was,
            };
            if should_queue {
                self.queue_if_new(subscription.token, source, sequence, now)?;
            }
        }
        self.bump_revision()?;
        Ok(sequence)
    }

    pub(crate) fn retire_source(&mut self, source: ReadySourceId) -> Result<(), ReadinessError> {
        let record = self
            .sources
            .get(&source)
            .ok_or(ReadinessError::UnknownSource)?;
        if !record.subscriptions.is_empty() {
            return Err(ReadinessError::DuplicateSubscription);
        }
        self.sources.remove(&source);
        self.retired_source_generation.insert(
            source.id,
            source
                .generation
                .checked_add(1)
                .ok_or(ReadinessError::CounterOverflow)?,
        );
        self.bump_revision()?;
        Ok(())
    }

    pub(crate) fn destroy_set(&mut self, set: ReadySetId) -> Result<(), ReadinessError> {
        let record = self.sets.get(&set).ok_or(ReadinessError::UnknownSet)?;
        if !record.subscriptions.is_empty() || !record.queue.is_empty() {
            return Err(ReadinessError::DuplicateSubscription);
        }
        self.sets.remove(&set);
        self.bump_revision()?;
        Ok(())
    }

    /// Freezes a bounded ordered delivery and updates ET/ONESHOT state in the
    /// same transition. The resulting receipt is immutable across personality
    /// crash/rebind and may be published exactly once.
    pub(crate) fn commit_delivery(
        &mut self,
        set: ReadySetId,
        wait_effect: EffectKey,
        max_events: usize,
        binding_generation: u64,
    ) -> Result<ReadyDeliveryReceipt, ReadinessError> {
        if max_events == 0 {
            return Err(ReadinessError::InvalidMaxEvents);
        }
        validate_generation(binding_generation)?;
        if !self.sets.contains_key(&set) {
            return Err(ReadinessError::UnknownSet);
        }
        let mut selected = Vec::new();
        let mut level_requeue = Vec::new();
        while selected.len() < max_events {
            let queued = {
                let ready_set = self.sets.get_mut(&set).unwrap();
                let Some(queued) = ready_set.queue.pop_front() else {
                    break;
                };
                ready_set.queued.remove(&queued.subscription.id);
                queued
            };
            let Some(subscription) = self.subscriptions.get(&queued.subscription.id).cloned()
            else {
                continue;
            };
            if subscription.binding_generation != binding_generation {
                let ready_set = self.sets.get_mut(&set).unwrap();
                ready_set.queue.push_front(queued);
                ready_set.queued.insert(queued.subscription.id);
                break;
            }
            if subscription.token != queued.subscription
                || !subscription.enabled
                || subscription.source != queued.source
            {
                continue;
            }
            let source = self
                .sources
                .get(&queued.source)
                .ok_or(ReadinessError::UnknownSource)?;
            let current_mask = filter_ready(subscription.interest, source.mask);
            if current_mask == 0 {
                continue;
            }
            let observed_mask = queued.observed_mask & current_mask;
            if observed_mask == 0 {
                continue;
            }
            selected.push(ReadyEvent {
                subscription: subscription.token,
                source: subscription.source,
                source_sequence: queued.source_sequence,
                observed_mask,
                cookie: subscription.cookie,
                binding_generation: subscription.binding_generation,
            });
            let current = self.subscriptions.get_mut(&subscription.token.id).unwrap();
            current.last_delivered_sequence = queued.source_sequence;
            match current.mode {
                TriggerMode::Level => level_requeue.push(current.token),
                TriggerMode::Edge => {}
                TriggerMode::OneShot => current.enabled = false,
            }
        }

        // Level-triggered sources remain eligible for the next wait, but not a
        // second slot in this same frozen batch.
        for token in level_requeue {
            let subscription = self.validate_subscription(token)?.clone();
            let source = self.sources.get(&subscription.source).unwrap();
            let ready = filter_ready(subscription.interest, source.mask);
            if ready != 0 {
                self.queue_if_new(token, subscription.source, source.sequence, ready)?;
            }
        }

        let id = self.take_delivery_id()?;
        let sequence = self.take_delivery_sequence()?;
        let receipt = ReadyDeliveryReceipt {
            id,
            sequence,
            wait_effect,
            events: selected,
        };
        self.deliveries.insert(
            id,
            DeliveryRecord {
                receipt: receipt.clone(),
                published: false,
            },
        );
        self.bump_revision()?;
        Ok(receipt)
    }

    pub(crate) fn publish_delivery(
        &mut self,
        receipt: &ReadyDeliveryReceipt,
    ) -> Result<(), ReadinessError> {
        let record = self
            .deliveries
            .get_mut(&receipt.id)
            .ok_or(ReadinessError::UnknownDelivery)?;
        if record.receipt != *receipt {
            return Err(ReadinessError::ReceiptMismatch);
        }
        if record.published {
            return Err(ReadinessError::AlreadyPublished);
        }
        record.published = true;
        self.bump_revision()?;
        Ok(())
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) fn counts(&self) -> ReadinessCounts {
        ReadinessCounts {
            sources: self.sources.len(),
            sets: self.sets.len(),
            subscriptions: self.subscriptions.len(),
            queued: self.sets.values().map(|set| set.queue.len()).sum(),
            deliveries: self.deliveries.len(),
            unpublished_deliveries: self
                .deliveries
                .values()
                .filter(|delivery| !delivery.published)
                .count(),
        }
    }

    pub(crate) fn check_invariants(&self) -> Result<(), ReadinessError> {
        let mut seen_source_ids = BTreeSet::new();
        for (id, source) in &self.sources {
            if *id != source.id
                || id.generation == 0
                || source.service_generation == 0
                || source.sequence == 0
                || !seen_source_ids.insert(id.id)
            {
                return Err(ReadinessError::Invariant("invalid source identity"));
            }
            for subscription in &source.subscriptions {
                if self
                    .subscriptions
                    .get(subscription)
                    .is_none_or(|record| record.source != *id)
                {
                    return Err(ReadinessError::Invariant(
                        "source subscription reverse index mismatch",
                    ));
                }
            }
        }
        for (id, generation) in &self.retired_source_generation {
            if *generation == 0 || self.sources.keys().any(|source| source.id == *id) {
                return Err(ReadinessError::Invariant(
                    "invalid retired source generation",
                ));
            }
        }

        for (id, set) in &self.sets {
            if *id != set.id || id.generation == 0 {
                return Err(ReadinessError::Invariant("invalid ready-set identity"));
            }
            let queued_ids: BTreeSet<_> = set
                .queue
                .iter()
                .map(|queued| queued.subscription.id)
                .collect();
            if queued_ids != set.queued || queued_ids.len() != set.queue.len() {
                return Err(ReadinessError::Invariant("ready queue/set mismatch"));
            }
            for queued in &set.queue {
                let subscription = self.subscriptions.get(&queued.subscription.id).ok_or(
                    ReadinessError::Invariant("queue names missing subscription"),
                )?;
                if subscription.token != queued.subscription
                    || subscription.set != *id
                    || subscription.source != queued.source
                    || !subscription.enabled
                {
                    return Err(ReadinessError::Invariant("stale queued readiness"));
                }
            }
            for subscription in &set.subscriptions {
                if self
                    .subscriptions
                    .get(subscription)
                    .is_none_or(|record| record.set != *id)
                {
                    return Err(ReadinessError::Invariant(
                        "set subscription reverse index mismatch",
                    ));
                }
            }
        }

        for (id, subscription) in &self.subscriptions {
            if *id != subscription.token.id
                || subscription.token.generation == 0
                || subscription.interest == 0
                || subscription.binding_generation == 0
                || !self
                    .sources
                    .get(&subscription.source)
                    .is_some_and(|source| source.subscriptions.contains(id))
                || !self
                    .sets
                    .get(&subscription.set)
                    .is_some_and(|set| set.subscriptions.contains(id))
            {
                return Err(ReadinessError::Invariant("invalid subscription"));
            }
        }
        for (id, generation) in &self.retired_subscription_generation {
            if *generation == 0 || self.subscriptions.contains_key(id) {
                return Err(ReadinessError::Invariant(
                    "invalid retired subscription generation",
                ));
            }
        }
        for (id, delivery) in &self.deliveries {
            if *id != delivery.receipt.id || delivery.receipt.sequence == 0 {
                return Err(ReadinessError::Invariant("invalid delivery receipt"));
            }
        }
        Ok(())
    }

    fn validate_subscription(
        &self,
        token: SubscriptionToken,
    ) -> Result<&SubscriptionRecord, ReadinessError> {
        let Some(record) = self.subscriptions.get(&token.id) else {
            return if self.retired_subscription_generation.contains_key(&token.id) {
                Err(ReadinessError::StaleSubscription)
            } else {
                Err(ReadinessError::UnknownSubscription)
            };
        };
        if record.token != token {
            return Err(ReadinessError::StaleSubscription);
        }
        Ok(record)
    }

    fn queue_if_new(
        &mut self,
        token: SubscriptionToken,
        source: ReadySourceId,
        source_sequence: u64,
        observed_mask: u32,
    ) -> Result<(), ReadinessError> {
        let subscription = self.validate_subscription(token)?;
        if !subscription.enabled {
            return Ok(());
        }
        let set = subscription.set;
        let ready_set = self.sets.get_mut(&set).ok_or(ReadinessError::UnknownSet)?;
        if ready_set.queued.insert(token.id) {
            ready_set.queue.push_back(QueuedReady {
                subscription: token,
                source,
                source_sequence,
                observed_mask,
            });
        } else if let Some(queued) = ready_set
            .queue
            .iter_mut()
            .find(|queued| queued.subscription.id == token.id)
        {
            queued.source_sequence = source_sequence;
            queued.observed_mask |= observed_mask;
        }
        Ok(())
    }

    fn remove_queued(&mut self, set: ReadySetId, subscription: u64) {
        if let Some(ready_set) = self.sets.get_mut(&set) {
            ready_set.queued.remove(&subscription);
            ready_set
                .queue
                .retain(|queued| queued.subscription.id != subscription);
        }
    }

    fn take_source_id(&mut self) -> Result<u64, ReadinessError> {
        take_counter(&mut self.next_source)
    }

    fn take_set_id(&mut self) -> Result<u64, ReadinessError> {
        take_counter(&mut self.next_set)
    }

    fn take_subscription_id(&mut self) -> Result<u64, ReadinessError> {
        take_counter(&mut self.next_subscription)
    }

    fn take_delivery_id(&mut self) -> Result<u64, ReadinessError> {
        take_counter(&mut self.next_delivery)
    }

    fn take_delivery_sequence(&mut self) -> Result<u64, ReadinessError> {
        take_counter(&mut self.next_delivery_sequence)
    }

    fn bump_revision(&mut self) -> Result<(), ReadinessError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(ReadinessError::CounterOverflow)?;
        Ok(())
    }
}

fn filter_ready(interest: u32, mask: u32) -> u32 {
    mask & (interest | READY_ERROR | READY_HANGUP)
}

fn validate_interest(interest: u32) -> Result<(), ReadinessError> {
    if interest == 0 || interest & !(READY_READABLE | READY_WRITABLE) != 0 {
        return Err(ReadinessError::InvalidInterest);
    }
    Ok(())
}

fn validate_mask(mask: u32) -> Result<(), ReadinessError> {
    if mask & !(READY_READABLE | READY_WRITABLE | READY_ERROR | READY_HANGUP) != 0 {
        return Err(ReadinessError::InvalidInterest);
    }
    Ok(())
}

fn validate_generation(generation: u64) -> Result<(), ReadinessError> {
    if generation == 0 {
        return Err(ReadinessError::InvalidGeneration);
    }
    Ok(())
}

fn take_counter(counter: &mut u64) -> Result<u64, ReadinessError> {
    let value = *counter;
    *counter = counter
        .checked_add(1)
        .ok_or(ReadinessError::CounterOverflow)?;
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadinessSelfTestReceipt {
    pub(crate) edge_deliveries: usize,
    pub(crate) level_deliveries: usize,
    pub(crate) oneshot_deliveries: usize,
    pub(crate) immediate_deliveries: usize,
    pub(crate) stale_source_rejected: bool,
    pub(crate) stale_subscription_rejected: bool,
    pub(crate) duplicate_publication_rejected: bool,
}

/// Executes a deterministic foundation receipt without Linux fd/epoll policy.
pub(crate) fn bounded_readiness_self_test() -> ReadinessSelfTestReceipt {
    let mut core = ReadinessCore::new();
    let set = core.create_set().unwrap();
    let edge_source = core.create_source(1, 0).unwrap();
    let edge = core
        .attach(
            set,
            edge_source,
            EffectKey::new(1, 1),
            1,
            READY_READABLE,
            TriggerMode::Edge,
            0x11,
        )
        .unwrap();
    core.source_update(edge_source, 1, READY_READABLE).unwrap();
    let first = core
        .commit_delivery(set, EffectKey::new(101, 1), 4, 1)
        .unwrap();
    assert_eq!(first.events().len(), 1);
    assert_eq!(first.events()[0].cookie, 0x11);
    let empty_edge = core
        .commit_delivery(set, EffectKey::new(102, 1), 4, 1)
        .unwrap();
    assert!(empty_edge.events().is_empty());
    core.source_update(edge_source, 1, 0).unwrap();
    core.source_update(edge_source, 1, READY_READABLE).unwrap();
    let second = core
        .commit_delivery(set, EffectKey::new(103, 1), 4, 1)
        .unwrap();
    assert_eq!(second.events().len(), 1);

    let oneshot = core
        .modify(edge, 1, READY_READABLE, TriggerMode::OneShot, 0x22)
        .unwrap();
    let oneshot_delivery = core
        .commit_delivery(set, EffectKey::new(104, 1), 4, 1)
        .unwrap();
    assert_eq!(oneshot_delivery.events().len(), 1);
    let oneshot_empty = core
        .commit_delivery(set, EffectKey::new(105, 1), 4, 1)
        .unwrap();
    assert!(oneshot_empty.events().is_empty());

    let level_source = core.create_source(1, READY_READABLE).unwrap();
    core.attach(
        set,
        level_source,
        EffectKey::new(2, 1),
        1,
        READY_READABLE,
        TriggerMode::Level,
        0x33,
    )
    .unwrap();
    let level_first = core
        .commit_delivery(set, EffectKey::new(106, 1), 4, 1)
        .unwrap();
    assert_eq!(level_first.events().len(), 1);
    let level_second = core
        .commit_delivery(set, EffectKey::new(107, 1), 4, 1)
        .unwrap();
    assert_eq!(level_second.events().len(), 1);

    let immediate_source = core.create_source(1, READY_READABLE).unwrap();
    core.attach(
        set,
        immediate_source,
        EffectKey::new(3, 1),
        1,
        READY_READABLE,
        TriggerMode::Edge,
        0x44,
    )
    .unwrap();
    let immediate = core
        .commit_delivery(set, EffectKey::new(108, 1), 4, 1)
        .unwrap();
    // The still-ready LT source shares the batch; identify the immediate event
    // by cookie instead of assuming a single event.
    assert!(immediate.events().iter().any(|event| event.cookie == 0x44));

    let before_stale_source = format_projection(&core);
    assert_eq!(
        core.source_update(immediate_source, 0, 0),
        Err(ReadinessError::StaleSource)
    );
    assert_eq!(format_projection(&core), before_stale_source);

    let before_stale_subscription = format_projection(&core);
    assert_eq!(
        core.modify(edge, 1, READY_READABLE, TriggerMode::Edge, 0x55),
        Err(ReadinessError::StaleSubscription)
    );
    assert_eq!(format_projection(&core), before_stale_subscription);

    core.publish_delivery(&first).unwrap();
    assert_eq!(
        core.publish_delivery(&first),
        Err(ReadinessError::AlreadyPublished)
    );
    let detached_effect = core.detach(oneshot).unwrap();
    assert_eq!(detached_effect, EffectKey::new(1, 1));
    core.check_invariants().unwrap();

    ReadinessSelfTestReceipt {
        edge_deliveries: first.events().len() + second.events().len(),
        level_deliveries: level_first.events().len() + level_second.events().len(),
        oneshot_deliveries: oneshot_delivery.events().len(),
        immediate_deliveries: immediate
            .events()
            .iter()
            .filter(|event| event.cookie == 0x44)
            .count(),
        stale_source_rejected: true,
        stale_subscription_rejected: true,
        duplicate_publication_rejected: true,
    }
}

type SubscriptionProjection = (
    SubscriptionToken,
    EffectKey,
    ReadySetId,
    ReadySourceId,
    u32,
    TriggerMode,
    u64,
    u64,
    bool,
    u64,
);

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReadinessProjection {
    revision: u64,
    sources: Vec<(ReadySourceId, u64, u64, u32, Vec<u64>)>,
    sets: Vec<(ReadySetId, Vec<u64>, Vec<QueuedReady>)>,
    subscriptions: Vec<SubscriptionProjection>,
    deliveries: Vec<(ReadyDeliveryReceipt, bool)>,
    retired_sources: Vec<(u64, u64)>,
}

fn format_projection(core: &ReadinessCore) -> ReadinessProjection {
    ReadinessProjection {
        revision: core.revision,
        sources: core
            .sources
            .values()
            .map(|source| {
                (
                    source.id,
                    source.service_generation,
                    source.sequence,
                    source.mask,
                    source.subscriptions.iter().copied().collect(),
                )
            })
            .collect(),
        sets: core
            .sets
            .values()
            .map(|set| {
                (
                    set.id,
                    set.subscriptions.iter().copied().collect(),
                    set.queue.iter().copied().collect(),
                )
            })
            .collect(),
        subscriptions: core
            .subscriptions
            .values()
            .map(|subscription| {
                (
                    subscription.token,
                    subscription.effect,
                    subscription.set,
                    subscription.source,
                    subscription.interest,
                    subscription.mode,
                    subscription.cookie,
                    subscription.binding_generation,
                    subscription.enabled,
                    subscription.last_delivered_sequence,
                )
            })
            .collect(),
        deliveries: core
            .deliveries
            .values()
            .map(|delivery| (delivery.receipt.clone(), delivery.published))
            .collect(),
        retired_sources: core
            .retired_source_generation
            .iter()
            .map(|(id, generation)| (*id, *generation))
            .collect(),
    }
}
