// SPDX-License-Identifier: MPL-2.0

//! Bounded, single-CPU coordinator over existing domain-local CSER registries.
//!
//! One authoritative root scope derives five domain-local children under one
//! composition gate. Derivation installs the immutable causal edge, binding
//! and device-generation envelope, delegated credit, effect registration, and
//! coordinator reverse indexes in one clone/validate/swap transaction. Root
//! revocation uses the same gate to fence derivation/commit and freeze the
//! exact domain/effect cohort. This is not a global object registry or object
//! scan: scheduler, pager, personality, readiness, and external VirtIO remain
//! typed local domains. The VirtIO envelope is a consistency check against an
//! independent Stage 5B component receipt, not identity-preserving recovery of
//! the same effect/generation. Runtime filesystem/network and SMP are outside
//! this slice.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
};

use ostd::{prelude::*, sync::SpinLock};

use crate::{
    effect_registry::{
        CommitMetadata, CommitOutcome, CreditCharge, CreditClass, CreditLimit, EffectKey,
        EffectPhase, EffectRegistry, OperationClass, PublicationMode, PublicationTicket,
        RegisterRequest, RegisteredEffect, RegistryError, RegistryProjection, ResourceKey,
        RevokeSelection, ScopeConfig, ScopeKey, ScopePhase, SyscallDescriptor, TaskKey,
        TerminalOutcome, TerminalRequest,
    },
    pager::PagerSliceReceipt,
    readiness::{READY_READABLE, ReadinessCore, ReadinessError, TriggerMode},
    scheduler::CserScheduler,
};

const ROOT_SCOPE: ScopeKey = ScopeKey::new(70, 1);
const ROOT_AUTHORITY_EPOCH: u64 = 121;
const ROOT_SUPERVISOR: TaskKey = TaskKey::new(900, 1);
const DOMAIN_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum DomainId {
    Personality,
    Pager,
    Scheduler,
    Readiness,
    VirtIo,
}

const DOMAINS: [DomainId; DOMAIN_COUNT] = [
    DomainId::Personality,
    DomainId::Pager,
    DomainId::Scheduler,
    DomainId::Readiness,
    DomainId::VirtIo,
];

const CLOSURE_ORDER: [DomainId; DOMAIN_COUNT] = [
    DomainId::Scheduler,
    DomainId::Pager,
    DomainId::VirtIo,
    DomainId::Readiness,
    DomainId::Personality,
];

impl DomainId {
    const fn label(self) -> &'static str {
        match self {
            Self::Personality => "personality",
            Self::Pager => "pager",
            Self::Scheduler => "scheduler",
            Self::Readiness => "readiness",
            Self::VirtIo => "virtio",
        }
    }

    const fn local_scope(self) -> u64 {
        match self {
            Self::Scheduler => 71,
            Self::Pager => 72,
            Self::Personality => 73,
            Self::Readiness => 74,
            Self::VirtIo => 75,
        }
    }

    const fn ordinal(self) -> u16 {
        match self {
            Self::Personality => 1,
            Self::Pager => 2,
            Self::Scheduler => 3,
            Self::Readiness => 4,
            Self::VirtIo => 5,
        }
    }

    const fn expected_parent(self) -> Parent {
        match self {
            Self::Personality => Parent::Root,
            Self::Pager => Parent::Domain(Self::Personality),
            Self::Scheduler => Parent::Domain(Self::Pager),
            Self::Readiness => Parent::Domain(Self::Personality),
            Self::VirtIo => Parent::Domain(Self::Readiness),
        }
    }

    const fn expected_binding(self, scheduler_epoch: u64, pager_epoch: u64) -> u64 {
        match self {
            Self::Scheduler => scheduler_epoch,
            Self::Pager => pager_epoch,
            Self::Personality | Self::Readiness => 2,
            Self::VirtIo => 3,
        }
    }

    const fn expected_device_generation(self) -> Option<u64> {
        match self {
            Self::VirtIo => Some(3),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Parent {
    Root,
    Domain(DomainId),
}

impl Parent {
    const fn label(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Domain(domain) => domain.label(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DomainEnvelope {
    root_authority_epoch: u64,
    binding_epoch: u64,
    device_generation: Option<u64>,
}

#[derive(Clone, Debug)]
struct DomainRecord {
    domain: DomainId,
    local_scope: u64,
    parent: Parent,
    envelope: DomainEnvelope,
    credit_class: CreditClass,
    registered: RegisteredEffect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootPhase {
    Active,
    Closing,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CreditBundle {
    class: CreditClass,
    units: u64,
    effect: EffectKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TombstoneId(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VirtIoState {
    Open,
    TimedOut,
    Retried,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExternalVirtIoAdapter {
    binding_epoch: u64,
    device_generation: u64,
    state: VirtIoState,
    tombstone: Option<TombstoneId>,
    credit: CreditBundle,
    retries: u64,
}

impl ExternalVirtIoAdapter {
    fn new(effect: EffectKey, envelope: DomainEnvelope, credit: CreditBundle) -> Self {
        assert_eq!(envelope.binding_epoch, 3);
        assert_eq!(envelope.device_generation, Some(3));
        assert_eq!(credit.effect, effect);
        Self {
            binding_epoch: envelope.binding_epoch,
            device_generation: envelope.device_generation.unwrap(),
            state: VirtIoState::Open,
            tombstone: None,
            credit,
            retries: 0,
        }
    }

    fn timeout(&mut self) -> Result<TombstoneId, CompositionError> {
        if self.state != VirtIoState::Open {
            return Err(CompositionError::InvalidState);
        }
        let tombstone = TombstoneId(1);
        self.state = VirtIoState::TimedOut;
        self.tombstone = Some(tombstone);
        Ok(tombstone)
    }

    fn accepts_receipt(&self, binding_epoch: u64, device_generation: u64) -> bool {
        binding_epoch == self.binding_epoch && device_generation == self.device_generation
    }

    fn retry(&mut self, tombstone: TombstoneId) -> Result<(), CompositionError> {
        if self.state != VirtIoState::TimedOut || self.tombstone != Some(tombstone) {
            return Err(CompositionError::InvalidReceipt);
        }
        self.tombstone = None;
        self.retries += 1;
        self.device_generation += 1;
        self.state = VirtIoState::Retried;
        Ok(())
    }

    fn close(&mut self) -> Result<(), CompositionError> {
        if self.state != VirtIoState::Retried || self.tombstone.is_some() {
            return Err(CompositionError::InvalidState);
        }
        self.state = VirtIoState::Closed;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClosureDisposition {
    Abort,
    Drain,
}

impl ClosureDisposition {
    const fn label(self) -> &'static str {
        match self {
            Self::Abort => "Abort",
            Self::Drain => "Drain",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClosureStatus {
    TimedOut,
    Closed(TerminalOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DomainClosureReceipt {
    domain: DomainId,
    effect: EffectKey,
    sequence: u64,
    revision: u64,
    domain_revision: u64,
    revoke_sequence: u64,
    closed_authority_epoch: u64,
    authority_epoch: u64,
    binding_epoch: u64,
    device_generation: Option<u64>,
    terminal_sequence: Option<u64>,
    status: ClosureStatus,
}

#[derive(Clone, Debug)]
struct PendingClosure {
    receipt: DomainClosureReceipt,
    publication: Option<PublicationTicket>,
    disposition: Option<ClosureDisposition>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IssuedClosure {
    receipt: DomainClosureReceipt,
    disposition: ClosureDisposition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CompositionError {
    Registry(RegistryError),
    RootNotActive,
    StaleAuthority,
    DuplicateDomain,
    ParentMissing,
    StaleParentEnvelope,
    StaleTargetEnvelope,
    InvalidTopology,
    InvalidEnvelope,
    InvalidReceipt,
    LiveDescendant,
    DuplicateReceipt,
    StaleReceipt,
    StaleClosureReceipt,
    OutOfOrderReceipt,
    ClosureReceiptsIncomplete,
    RevokeTimedOut,
    InvalidState,
}

impl From<RegistryError> for CompositionError {
    fn from(error: RegistryError) -> Self {
        Self::Registry(error)
    }
}

impl From<ReadinessError> for CompositionError {
    fn from(_: ReadinessError) -> Self {
        Self::InvalidState
    }
}

#[derive(Clone, Debug)]
struct CompositionState {
    root_phase: RootPhase,
    root_authority_epoch: u64,
    registry: EffectRegistry,
    readiness: ReadinessCore,
    enrollment_by_domain: BTreeMap<DomainId, DomainEnvelope>,
    current_envelope_by_domain: BTreeMap<DomainId, DomainEnvelope>,
    domains: BTreeMap<DomainId, DomainRecord>,
    children_by_parent: BTreeMap<Parent, BTreeSet<DomainId>>,
    domain_by_effect: BTreeMap<EffectKey, DomainId>,
    domain_by_local_scope: BTreeMap<u64, DomainId>,
    credit_by_domain: BTreeMap<DomainId, CreditBundle>,
    domain_revisions: BTreeMap<DomainId, u64>,
    frozen_domains: BTreeSet<DomainId>,
    frozen_effects: BTreeSet<EffectKey>,
    active_revoke: Option<RootRevokeTicket>,
    pending_closure: Option<PendingClosure>,
    closure_receipts: BTreeMap<DomainId, DomainClosureReceipt>,
    accepted_receipts: BTreeMap<u64, DomainClosureReceipt>,
    latest_receipt_by_domain: BTreeMap<DomainId, u64>,
    invalidated_receipts: BTreeSet<u64>,
    receipt_revision: u64,
    next_receipt_sequence: u64,
    virtio: Option<ExternalVirtIoAdapter>,
}

impl CompositionState {
    fn new(scheduler_epoch: u64, pager_epoch: u64) -> Self {
        let mut registry = EffectRegistry::new();
        registry
            .create_scope(ScopeConfig {
                key: ROOT_SCOPE,
                authority_epoch: ROOT_AUTHORITY_EPOCH,
                binding_epoch: 1,
                supervisor: ROOT_SUPERVISOR,
                credits: DOMAINS
                    .into_iter()
                    .map(|domain| CreditLimit::new(CreditClass::new(domain.ordinal()), 1))
                    .collect(),
            })
            .unwrap();
        let enrollment_by_domain: BTreeMap<DomainId, DomainEnvelope> = DOMAINS
            .into_iter()
            .map(|domain| {
                (
                    domain,
                    DomainEnvelope {
                        root_authority_epoch: ROOT_AUTHORITY_EPOCH,
                        binding_epoch: domain.expected_binding(scheduler_epoch, pager_epoch),
                        device_generation: domain.expected_device_generation(),
                    },
                )
            })
            .collect();
        let current_envelope_by_domain = enrollment_by_domain.clone();
        Self {
            root_phase: RootPhase::Active,
            root_authority_epoch: ROOT_AUTHORITY_EPOCH,
            registry,
            readiness: ReadinessCore::new(),
            enrollment_by_domain,
            current_envelope_by_domain,
            domains: BTreeMap::new(),
            children_by_parent: BTreeMap::new(),
            domain_by_effect: BTreeMap::new(),
            domain_by_local_scope: BTreeMap::new(),
            credit_by_domain: BTreeMap::new(),
            domain_revisions: BTreeMap::new(),
            frozen_domains: BTreeSet::new(),
            frozen_effects: BTreeSet::new(),
            active_revoke: None,
            pending_closure: None,
            closure_receipts: BTreeMap::new(),
            accepted_receipts: BTreeMap::new(),
            latest_receipt_by_domain: BTreeMap::new(),
            invalidated_receipts: BTreeSet::new(),
            receipt_revision: 0,
            next_receipt_sequence: 1,
            virtio: None,
        }
    }

    fn apply_derive(
        &mut self,
        domain: DomainId,
        parent: Parent,
        parent_envelope: Option<DomainEnvelope>,
        envelope: DomainEnvelope,
    ) -> Result<RegisteredEffect, CompositionError> {
        if self.root_phase != RootPhase::Active {
            return Err(CompositionError::RootNotActive);
        }
        if envelope.root_authority_epoch != self.root_authority_epoch {
            return Err(CompositionError::StaleAuthority);
        }
        if self.enrollment_by_domain.get(&domain) != Some(&envelope) {
            return Err(CompositionError::StaleTargetEnvelope);
        }
        if self.domains.contains_key(&domain) {
            return Err(CompositionError::DuplicateDomain);
        }
        if parent != domain.expected_parent() {
            return Err(CompositionError::InvalidTopology);
        }
        match parent {
            Parent::Root => {
                if parent_envelope.is_some() {
                    return Err(CompositionError::InvalidEnvelope);
                }
            }
            Parent::Domain(parent_domain) => {
                if !self.domains.contains_key(&parent_domain) {
                    return Err(CompositionError::ParentMissing);
                }
                if parent_envelope != Some(self.current_envelope_by_domain[&parent_domain]) {
                    return Err(CompositionError::StaleParentEnvelope);
                }
            }
        }
        if envelope.binding_epoch == 0
            || (domain == DomainId::VirtIo) != envelope.device_generation.is_some()
        {
            return Err(CompositionError::InvalidEnvelope);
        }
        if self
            .domain_by_local_scope
            .contains_key(&domain.local_scope())
        {
            return Err(CompositionError::DuplicateDomain);
        }

        let credit_class = CreditClass::new(domain.ordinal());
        let registered = self.registry.register(RegisterRequest {
            scope: ROOT_SCOPE,
            task: TaskKey::new(domain.local_scope(), 1),
            operation: OperationClass::new(u32::from(domain.ordinal())),
            descriptor: SyscallDescriptor::new(
                usize::from(domain.ordinal()),
                [domain.local_scope() as usize, 0, 0, 0, 0, 0],
            ),
            resources: vec![ResourceKey::new(
                u32::from(domain.ordinal()),
                domain.local_scope(),
                1,
            )],
            credits: vec![CreditCharge::new(credit_class, 1)],
            publication: PublicationMode::Required,
        })?;
        self.registry.prepare(ROOT_SUPERVISOR, registered.handle)?;
        let domain_revision =
            u64::try_from(self.domains.len() + 1).map_err(|_| CompositionError::InvalidState)?;
        self.registry.domain_changed(ROOT_SCOPE, domain_revision)?;

        let effect = registered.identity.effect();
        let credit = CreditBundle {
            class: credit_class,
            units: 1,
            effect,
        };
        self.children_by_parent
            .entry(parent)
            .or_default()
            .insert(domain);
        self.domain_by_effect.insert(effect, domain);
        self.domain_by_local_scope
            .insert(domain.local_scope(), domain);
        self.credit_by_domain.insert(domain, credit);
        self.domain_revisions.insert(domain, 1);
        self.domains.insert(
            domain,
            DomainRecord {
                domain,
                local_scope: domain.local_scope(),
                parent,
                envelope,
                credit_class,
                registered: registered.clone(),
            },
        );
        if domain == DomainId::VirtIo {
            self.virtio = Some(ExternalVirtIoAdapter::new(effect, envelope, credit));
        }
        self.check_invariants()?;
        Ok(registered)
    }

    fn ticket_is_current(&self, ticket: &RootRevokeTicket) -> bool {
        self.active_revoke.as_ref() == Some(ticket)
            && self.frozen_domains == ticket.frozen_domains
            && self.frozen_effects == ticket.frozen_effects
    }

    fn has_unclosed_child(&self, domain: DomainId) -> bool {
        self.children_by_parent
            .get(&Parent::Domain(domain))
            .is_some_and(|children| {
                children.iter().any(|child| {
                    self.frozen_domains.contains(child)
                        && !self.closure_receipts.contains_key(child)
                })
            })
    }

    fn validate_receipt_identity(
        &self,
        ticket: &RootRevokeTicket,
        receipt: &DomainClosureReceipt,
    ) -> Result<(), CompositionError> {
        let record = self
            .domains
            .get(&receipt.domain)
            .ok_or(CompositionError::InvalidReceipt)?;
        if receipt.revoke_sequence != ticket.selection.sequence
            || receipt.closed_authority_epoch != ticket.selection.closed_authority_epoch
            || receipt.authority_epoch != ticket.selection.authority_epoch
            || receipt.effect != record.registered.identity.effect()
            || receipt.binding_epoch != record.envelope.binding_epoch
            || (receipt.domain == DomainId::VirtIo) != receipt.device_generation.is_some()
            || receipt.device_generation == Some(0)
        {
            return Err(CompositionError::StaleReceipt);
        }
        Ok(())
    }

    fn check_invariants(&self) -> Result<(), CompositionError> {
        self.registry.check_invariants()?;
        self.readiness
            .check_invariants()
            .map_err(CompositionError::from)?;
        let registry_projection = self.registry.scope_projection(ROOT_SCOPE)?;
        let expected_scope_phase = match self.root_phase {
            RootPhase::Active => ScopePhase::Active,
            RootPhase::Closing => ScopePhase::Closing,
            RootPhase::Revoked => ScopePhase::Revoked,
        };
        if self.root_authority_epoch == 0
            || registry_projection.phase != expected_scope_phase
            || registry_projection.authority_epoch != self.root_authority_epoch
            || self.domains.len() != self.domain_by_effect.len()
            || self.domains.len() != self.domain_by_local_scope.len()
            || self.domains.len() != self.credit_by_domain.len()
            || self.domains.len() != self.domain_revisions.len()
            || self.enrollment_by_domain.len() != DOMAIN_COUNT
            || self.current_envelope_by_domain.len() != DOMAIN_COUNT
            || self.receipt_revision
                != u64::try_from(self.accepted_receipts.len())
                    .map_err(|_| CompositionError::InvalidState)?
            || self.next_receipt_sequence != self.receipt_revision + 1
        {
            return Err(CompositionError::InvalidState);
        }
        let indexed_children: usize = self.children_by_parent.values().map(BTreeSet::len).sum();
        if indexed_children != self.domains.len() {
            return Err(CompositionError::InvalidState);
        }
        for (domain, record) in &self.domains {
            if record.domain != *domain
                || record.local_scope != domain.local_scope()
                || record.parent != domain.expected_parent()
                || self.enrollment_by_domain.get(domain) != Some(&record.envelope)
                || self.current_envelope_by_domain[domain].binding_epoch
                    != record.envelope.binding_epoch
                || (domain == &DomainId::VirtIo)
                    != self.current_envelope_by_domain[domain]
                        .device_generation
                        .is_some()
                || record.envelope.root_authority_epoch != ROOT_AUTHORITY_EPOCH
                || record.credit_class != CreditClass::new(domain.ordinal())
                || self
                    .domain_by_effect
                    .get(&record.registered.identity.effect())
                    != Some(domain)
                || self.domain_by_local_scope.get(&record.local_scope) != Some(domain)
                || self.credit_by_domain.get(domain)
                    != Some(&CreditBundle {
                        class: record.credit_class,
                        units: 1,
                        effect: record.registered.identity.effect(),
                    })
                || self
                    .domain_revisions
                    .get(domain)
                    .is_none_or(|revision| *revision == 0)
                || !self
                    .children_by_parent
                    .get(&record.parent)
                    .is_some_and(|children| children.contains(domain))
            {
                return Err(CompositionError::InvalidState);
            }
            if let Parent::Domain(parent) = record.parent
                && !self.domains.contains_key(&parent)
            {
                return Err(CompositionError::ParentMissing);
            }
            let mut cursor = *domain;
            let mut seen = BTreeSet::new();
            loop {
                if !seen.insert(cursor) {
                    return Err(CompositionError::InvalidTopology);
                }
                match self.domains.get(&cursor).unwrap().parent {
                    Parent::Root => break,
                    Parent::Domain(parent) => cursor = parent,
                }
            }
        }
        match (self.domains.get(&DomainId::VirtIo), self.virtio) {
            (None, None) => {}
            (Some(record), Some(adapter))
                if adapter.binding_epoch
                    == self.current_envelope_by_domain[&DomainId::VirtIo].binding_epoch
                    && Some(adapter.device_generation)
                        == self.current_envelope_by_domain[&DomainId::VirtIo].device_generation
                    && record.envelope.device_generation == Some(3)
                    && self.credit_by_domain.get(&DomainId::VirtIo) == Some(&adapter.credit) => {}
            _ => return Err(CompositionError::InvalidState),
        }
        if self.closure_receipts.contains_key(&DomainId::VirtIo)
            && self.virtio.map(|adapter| adapter.state) != Some(VirtIoState::Closed)
        {
            return Err(CompositionError::InvalidState);
        }

        if self.root_phase != RootPhase::Active {
            let ticket = self
                .active_revoke
                .as_ref()
                .ok_or(CompositionError::InvalidState)?;
            if !self.ticket_is_current(ticket) {
                return Err(CompositionError::InvalidState);
            }
            let mut expected_live = self.frozen_effects.clone();
            let mut expected_latest = BTreeMap::new();
            for (expected_sequence, (sequence, receipt)) in (1_u64..).zip(&self.accepted_receipts) {
                self.validate_receipt_identity(ticket, receipt)?;
                let current_domain_revision = self.domain_revisions[&receipt.domain];
                let current_envelope = self.current_envelope_by_domain[&receipt.domain];
                let invalidated = self.invalidated_receipts.contains(sequence);
                if *sequence != expected_sequence
                    || receipt.sequence != *sequence
                    || receipt.revision != *sequence
                    || receipt.domain_revision == 0
                    || receipt.domain_revision > current_domain_revision
                    || (!invalidated && receipt.domain_revision != current_domain_revision)
                    || (!invalidated
                        && (receipt.binding_epoch != current_envelope.binding_epoch
                            || receipt.device_generation != current_envelope.device_generation))
                {
                    return Err(CompositionError::InvalidState);
                }
                let view = self.registry.effect_view(receipt.effect)?;
                match receipt.status {
                    ClosureStatus::TimedOut => {
                        if receipt.domain != DomainId::VirtIo
                            || receipt.terminal_sequence.is_some()
                            || (!invalidated
                                && (view.phase != EffectPhase::Committed
                                    || view.publication_pending))
                            || (invalidated && receipt.domain_revision >= current_domain_revision)
                            || (invalidated
                                && receipt.device_generation.is_none_or(|generation| {
                                    current_envelope
                                        .device_generation
                                        .is_none_or(|current| generation >= current)
                                }))
                        {
                            return Err(CompositionError::InvalidState);
                        }
                    }
                    ClosureStatus::Closed(outcome) => {
                        if invalidated
                            || receipt.terminal_sequence.is_none()
                            || self.closure_receipts.get(&receipt.domain) != Some(receipt)
                            || view.phase != EffectPhase::Terminal(outcome)
                            || view.publication_pending
                            || !expected_live.remove(&receipt.effect)
                        {
                            return Err(CompositionError::InvalidState);
                        }
                        if self
                            .children_by_parent
                            .get(&Parent::Domain(receipt.domain))
                            .is_some_and(|children| {
                                children.iter().any(|child| {
                                    self.frozen_domains.contains(child)
                                        && self.closure_receipts.get(child).is_none_or(
                                            |child_receipt| {
                                                child_receipt.sequence >= receipt.sequence
                                            },
                                        )
                                })
                            })
                        {
                            return Err(CompositionError::LiveDescendant);
                        }
                    }
                }
                if !invalidated {
                    expected_latest.insert(receipt.domain, *sequence);
                }
            }
            if self.latest_receipt_by_domain != expected_latest
                || self.invalidated_receipts.iter().any(|sequence| {
                    self.accepted_receipts
                        .get(sequence)
                        .is_none_or(|receipt| receipt.status != ClosureStatus::TimedOut)
                })
                || self.closure_receipts.values().any(|receipt| {
                    !matches!(receipt.status, ClosureStatus::Closed(_))
                        || self.accepted_receipts.get(&receipt.sequence) != Some(receipt)
                })
            {
                return Err(CompositionError::InvalidState);
            }
            if let Some(pending) = &self.pending_closure {
                self.validate_receipt_identity(ticket, &pending.receipt)?;
                if pending.receipt.sequence != self.next_receipt_sequence
                    || pending.receipt.revision != self.receipt_revision + 1
                    || pending.receipt.domain_revision
                        != self.domain_revisions[&pending.receipt.domain]
                    || pending.receipt.binding_epoch
                        != self.current_envelope_by_domain[&pending.receipt.domain].binding_epoch
                    || pending.receipt.device_generation
                        != self.current_envelope_by_domain[&pending.receipt.domain]
                            .device_generation
                    || self.closure_receipts.contains_key(&pending.receipt.domain)
                    || self.has_unclosed_child(pending.receipt.domain)
                {
                    return Err(CompositionError::InvalidState);
                }
                let view = self.registry.effect_view(pending.receipt.effect)?;
                match pending.receipt.status {
                    ClosureStatus::TimedOut => {
                        if pending.publication.is_some()
                            || pending.disposition.is_some()
                            || pending.receipt.domain != DomainId::VirtIo
                            || pending.receipt.terminal_sequence.is_some()
                            || view.phase != EffectPhase::Committed
                            || view.publication_pending
                        {
                            return Err(CompositionError::InvalidState);
                        }
                    }
                    ClosureStatus::Closed(outcome) => {
                        if pending.publication.is_none()
                            || pending.disposition.is_none()
                            || pending.receipt.terminal_sequence.is_none()
                            || view.phase != EffectPhase::Terminal(outcome)
                            || !view.publication_pending
                            || !expected_live.remove(&pending.receipt.effect)
                        {
                            return Err(CompositionError::InvalidState);
                        }
                    }
                }
            }
            if self.registry.effects_for_scope(ROOT_SCOPE) != expected_live {
                return Err(CompositionError::InvalidState);
            }
        }
        match self.root_phase {
            RootPhase::Active => {
                if !self.frozen_domains.is_empty()
                    || !self.frozen_effects.is_empty()
                    || self.active_revoke.is_some()
                    || self.pending_closure.is_some()
                    || !self.closure_receipts.is_empty()
                    || !self.accepted_receipts.is_empty()
                    || !self.latest_receipt_by_domain.is_empty()
                    || !self.invalidated_receipts.is_empty()
                    || self.receipt_revision != 0
                    || self.next_receipt_sequence != 1
                {
                    return Err(CompositionError::InvalidState);
                }
            }
            RootPhase::Closing | RootPhase::Revoked => {
                let indexed_frozen_domains: BTreeSet<_> = self
                    .frozen_effects
                    .iter()
                    .map(|effect| self.domain_by_effect[effect])
                    .collect();
                if self.frozen_domains != indexed_frozen_domains {
                    return Err(CompositionError::InvalidState);
                }
                if self.root_phase == RootPhase::Revoked
                    && (self.pending_closure.is_some()
                        || self
                            .closure_receipts
                            .keys()
                            .copied()
                            .collect::<BTreeSet<_>>()
                            != self.frozen_domains
                        || self
                            .closure_receipts
                            .values()
                            .map(|receipt| receipt.effect)
                            .collect::<BTreeSet<_>>()
                            != self.frozen_effects)
                {
                    return Err(CompositionError::ClosureReceiptsIncomplete);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompositionProjection {
    phase: RootPhase,
    authority_epoch: u64,
    domains: usize,
    edges: usize,
    by_effect: usize,
    by_local_scope: usize,
    credits: usize,
    frozen_domains: usize,
    frozen_effects: usize,
    accepted_receipts: usize,
    accepted_closure_receipts: usize,
    pending_closure_receipts: usize,
    invalidated_receipts: usize,
    receipt_revision: u64,
    next_receipt_sequence: u64,
    registry: RegistryProjection,
    readiness_sources: usize,
    readiness_sets: usize,
    readiness_subscriptions: usize,
    readiness_queued: usize,
    readiness_unpublished: usize,
    virtio: Option<ExternalVirtIoAdapter>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RootRevokeTicket {
    selection: RevokeSelection,
    frozen_domains: BTreeSet<DomainId>,
    frozen_effects: BTreeSet<EffectKey>,
}

struct CompositionBackbone {
    state: SpinLock<CompositionState>,
}

impl CompositionBackbone {
    fn new(scheduler_epoch: u64, pager_epoch: u64) -> Self {
        Self {
            state: SpinLock::new(CompositionState::new(scheduler_epoch, pager_epoch)),
        }
    }

    /// Failure-atomic child derivation under the one composition gate.
    fn derive_child(
        &self,
        domain: DomainId,
        parent: Parent,
        parent_envelope: Option<DomainEnvelope>,
        envelope: DomainEnvelope,
    ) -> Result<RegisteredEffect, CompositionError> {
        let mut state = self.state.lock();
        let mut candidate = state.clone();
        let registered = candidate.apply_derive(domain, parent, parent_envelope, envelope)?;
        *state = candidate;
        Ok(registered)
    }

    fn projection(&self) -> CompositionProjection {
        let state = self.state.lock();
        let readiness = state.readiness.counts();
        CompositionProjection {
            phase: state.root_phase,
            authority_epoch: state.root_authority_epoch,
            domains: state.domains.len(),
            edges: state.children_by_parent.values().map(BTreeSet::len).sum(),
            by_effect: state.domain_by_effect.len(),
            by_local_scope: state.domain_by_local_scope.len(),
            credits: state.credit_by_domain.len(),
            frozen_domains: state.frozen_domains.len(),
            frozen_effects: state.frozen_effects.len(),
            accepted_receipts: state.accepted_receipts.len(),
            accepted_closure_receipts: state.closure_receipts.len(),
            pending_closure_receipts: usize::from(state.pending_closure.is_some()),
            invalidated_receipts: state.invalidated_receipts.len(),
            receipt_revision: state.receipt_revision,
            next_receipt_sequence: state.next_receipt_sequence,
            registry: state.registry.scope_projection(ROOT_SCOPE).unwrap(),
            readiness_sources: readiness.sources,
            readiness_sets: readiness.sets,
            readiness_subscriptions: readiness.subscriptions,
            readiness_queued: readiness.queued,
            readiness_unpublished: readiness.unpublished_deliveries,
            virtio: state.virtio,
        }
    }

    fn record(&self, domain: DomainId) -> DomainRecord {
        self.state.lock().domains.get(&domain).unwrap().clone()
    }

    fn exercise_readiness(&self) -> Result<(EffectKey, u64), CompositionError> {
        let mut state = self.state.lock();
        let mut candidate = state.clone();
        let effect = candidate.domains[&DomainId::Readiness]
            .registered
            .identity
            .effect();
        let source = candidate.readiness.create_source(2, READY_READABLE)?;
        let set = candidate.readiness.create_set()?;
        let subscription = candidate.readiness.attach(
            set,
            source,
            effect,
            2,
            READY_READABLE,
            TriggerMode::OneShot,
            0x4353_4552,
        )?;
        let delivery = candidate.readiness.commit_delivery(set, effect, 1, 2)?;
        if delivery.events().len() != 1 {
            return Err(CompositionError::InvalidState);
        }
        candidate.readiness.publish_delivery(&delivery)?;
        let published_counts = candidate.readiness.counts();
        if candidate.readiness.publish_delivery(&delivery) != Err(ReadinessError::AlreadyPublished)
            || candidate.readiness.counts() != published_counts
            || candidate.readiness.detach(subscription)? != effect
        {
            return Err(CompositionError::InvalidReceipt);
        }
        candidate.readiness.retire_source(source)?;
        candidate.readiness.destroy_set(set)?;
        candidate.check_invariants()?;
        let counts = candidate.readiness.counts();
        if counts.sources != 0
            || counts.sets != 0
            || counts.subscriptions != 0
            || counts.queued != 0
            || counts.unpublished_deliveries != 0
        {
            return Err(CompositionError::InvalidState);
        }
        let sequence = delivery.sequence();
        *state = candidate;
        Ok((effect, sequence))
    }

    fn commit_domain(
        &self,
        domain: DomainId,
        presented_authority_epoch: u64,
        metadata: CommitMetadata,
    ) -> Result<CommitOutcome, CompositionError> {
        let mut state = self.state.lock();
        if presented_authority_epoch != state.root_authority_epoch {
            return Err(CompositionError::StaleAuthority);
        }
        if state.root_phase != RootPhase::Active {
            return Err(CompositionError::RootNotActive);
        }
        let mut candidate = state.clone();
        let handle = candidate.domains[&domain].registered.handle;
        let outcome = candidate
            .registry
            .commit(ROOT_SUPERVISOR, handle, metadata)?;
        candidate.check_invariants()?;
        *state = candidate;
        Ok(outcome)
    }

    fn revoke_begin(&self) -> Result<RootRevokeTicket, CompositionError> {
        let mut state = self.state.lock();
        if state.root_phase != RootPhase::Active {
            return Err(CompositionError::RootNotActive);
        }
        let mut candidate = state.clone();
        let selection = candidate.registry.revoke_begin(ROOT_SCOPE)?;
        candidate.root_phase = RootPhase::Closing;
        candidate.root_authority_epoch = selection.authority_epoch;
        candidate.frozen_effects = selection.effects.clone();
        candidate.frozen_domains = candidate
            .frozen_effects
            .iter()
            .map(|effect| candidate.domain_by_effect[effect])
            .collect();
        let ticket = RootRevokeTicket {
            selection,
            frozen_domains: candidate.frozen_domains.clone(),
            frozen_effects: candidate.frozen_effects.clone(),
        };
        candidate.active_revoke = Some(ticket.clone());
        candidate.check_invariants()?;
        *state = candidate;
        Ok(ticket)
    }

    fn validate_child(
        &self,
        domain: DomainId,
        envelope: DomainEnvelope,
    ) -> Result<(), CompositionError> {
        let state = self.state.lock();
        if envelope.root_authority_epoch != state.root_authority_epoch {
            return Err(CompositionError::StaleAuthority);
        }
        let record = state
            .domains
            .get(&domain)
            .ok_or(CompositionError::ParentMissing)?;
        if envelope != record.envelope {
            return Err(CompositionError::InvalidEnvelope);
        }
        if state.root_phase != RootPhase::Active {
            return Err(CompositionError::RootNotActive);
        }
        Ok(())
    }

    fn validate_virtio_receipt(
        &self,
        binding_epoch: u64,
        device_generation: u64,
    ) -> Result<(), CompositionError> {
        let state = self.state.lock();
        if state
            .virtio
            .as_ref()
            .is_none_or(|adapter| !adapter.accepts_receipt(binding_epoch, device_generation))
        {
            return Err(CompositionError::InvalidReceipt);
        }
        Ok(())
    }

    fn stage_closure(
        &self,
        ticket: &RootRevokeTicket,
        domain: DomainId,
    ) -> Result<IssuedClosure, CompositionError> {
        let mut state = self.state.lock();
        if state.root_phase != RootPhase::Closing || !state.ticket_is_current(ticket) {
            return Err(CompositionError::InvalidState);
        }
        let mut candidate = state.clone();
        if candidate.pending_closure.is_some() {
            return Err(CompositionError::InvalidState);
        }
        if candidate.closure_receipts.contains_key(&domain) {
            return Err(CompositionError::DuplicateReceipt);
        }
        if !candidate.frozen_domains.contains(&domain) {
            return Err(CompositionError::InvalidState);
        }
        if candidate.has_unclosed_child(domain) {
            return Err(CompositionError::LiveDescendant);
        }
        if domain == DomainId::VirtIo
            && candidate.virtio.as_ref().map(|adapter| adapter.state) != Some(VirtIoState::Retried)
        {
            return Err(CompositionError::InvalidState);
        }
        let record = candidate.domains.get(&domain).unwrap().clone();
        let current_envelope = candidate.current_envelope_by_domain[&domain];
        let effect = record.registered.identity.effect();
        let view = candidate.registry.effect_view(effect)?;
        let (request, disposition) = match view.commit {
            None => (TerminalRequest::aborted(-125), ClosureDisposition::Abort),
            Some(ref commit) => (
                TerminalRequest::completed(commit.result()),
                ClosureDisposition::Drain,
            ),
        };
        let terminal =
            candidate
                .registry
                .stage_revoke_terminal(&ticket.selection, effect, request)?;
        let receipt = DomainClosureReceipt {
            domain,
            effect: terminal.receipt.effect(),
            sequence: candidate.next_receipt_sequence,
            revision: candidate.receipt_revision + 1,
            domain_revision: candidate.domain_revisions[&domain],
            revoke_sequence: ticket.selection.sequence,
            closed_authority_epoch: ticket.selection.closed_authority_epoch,
            authority_epoch: ticket.selection.authority_epoch,
            binding_epoch: current_envelope.binding_epoch,
            device_generation: current_envelope.device_generation,
            terminal_sequence: Some(terminal.receipt.sequence()),
            status: ClosureStatus::Closed(terminal.receipt.outcome()),
        };
        candidate.pending_closure = Some(PendingClosure {
            receipt,
            publication: Some(terminal.publication.ok_or(CompositionError::InvalidState)?),
            disposition: Some(disposition),
        });
        candidate.check_invariants()?;
        *state = candidate;
        Ok(IssuedClosure {
            receipt,
            disposition,
        })
    }

    fn accept_closure_receipt(
        &self,
        ticket: &RootRevokeTicket,
        receipt: DomainClosureReceipt,
    ) -> Result<(), CompositionError> {
        let mut state = self.state.lock();
        if state.root_phase != RootPhase::Closing || !state.ticket_is_current(ticket) {
            return Err(CompositionError::InvalidState);
        }
        if let Some(accepted) = state.accepted_receipts.get(&receipt.sequence) {
            if state.invalidated_receipts.contains(&receipt.sequence) {
                return Err(CompositionError::StaleClosureReceipt);
            }
            return if accepted == &receipt {
                Err(CompositionError::DuplicateReceipt)
            } else {
                Err(CompositionError::InvalidReceipt)
            };
        }
        state.validate_receipt_identity(ticket, &receipt)?;
        let current_envelope = state.current_envelope_by_domain[&receipt.domain];
        if receipt.domain_revision != state.domain_revisions[&receipt.domain]
            || receipt.binding_epoch != current_envelope.binding_epoch
            || receipt.device_generation != current_envelope.device_generation
        {
            return Err(CompositionError::StaleClosureReceipt);
        }
        if receipt.sequence != state.next_receipt_sequence
            || receipt.revision != state.receipt_revision + 1
        {
            return Err(CompositionError::OutOfOrderReceipt);
        }
        let pending = state
            .pending_closure
            .as_ref()
            .ok_or(CompositionError::InvalidReceipt)?;
        if pending.receipt != receipt {
            return Err(CompositionError::InvalidReceipt);
        }
        let mut candidate = state.clone();
        let pending = candidate.pending_closure.take().unwrap();
        match receipt.status {
            ClosureStatus::TimedOut => {
                if pending.publication.is_some() || pending.disposition.is_some() {
                    return Err(CompositionError::InvalidState);
                }
            }
            ClosureStatus::Closed(_) => {
                let publication = pending
                    .publication
                    .as_ref()
                    .ok_or(CompositionError::InvalidState)?;
                candidate.registry.acknowledge_publication(publication)?;
                if receipt.domain == DomainId::VirtIo {
                    candidate
                        .virtio
                        .as_mut()
                        .ok_or(CompositionError::InvalidState)?
                        .close()?;
                }
                candidate.closure_receipts.insert(receipt.domain, receipt);
            }
        }
        candidate
            .accepted_receipts
            .insert(receipt.sequence, receipt);
        candidate
            .latest_receipt_by_domain
            .insert(receipt.domain, receipt.sequence);
        candidate.receipt_revision = receipt.revision;
        candidate.next_receipt_sequence = receipt.sequence + 1;
        candidate.check_invariants()?;
        *state = candidate;
        Ok(())
    }

    fn virtio_timeout(&self) -> Result<(TombstoneId, CreditBundle), CompositionError> {
        let mut state = self.state.lock();
        let mut candidate = state.clone();
        let effect = candidate.domains[&DomainId::VirtIo]
            .registered
            .identity
            .effect();
        if candidate.root_phase != RootPhase::Closing
            || !candidate.frozen_domains.contains(&DomainId::VirtIo)
            || !candidate.frozen_effects.contains(&effect)
            || candidate.pending_closure.is_some()
            || candidate.registry.effect_view(effect)?.phase != EffectPhase::Committed
        {
            return Err(CompositionError::InvalidState);
        }
        let adapter = candidate
            .virtio
            .as_mut()
            .ok_or(CompositionError::InvalidState)?;
        let tombstone = adapter.timeout()?;
        let credit = adapter.credit;
        candidate.check_invariants()?;
        *state = candidate;
        Ok((tombstone, credit))
    }

    fn issue_virtio_timeout_receipt(
        &self,
        ticket: &RootRevokeTicket,
    ) -> Result<DomainClosureReceipt, CompositionError> {
        let mut state = self.state.lock();
        if state.root_phase != RootPhase::Closing || !state.ticket_is_current(ticket) {
            return Err(CompositionError::InvalidState);
        }
        let mut candidate = state.clone();
        if candidate.pending_closure.is_some()
            || candidate.closure_receipts.contains_key(&DomainId::VirtIo)
            || candidate.has_unclosed_child(DomainId::VirtIo)
            || candidate.virtio.as_ref().map(|adapter| adapter.state) != Some(VirtIoState::TimedOut)
        {
            return Err(CompositionError::InvalidState);
        }
        let record = candidate.domains[&DomainId::VirtIo].clone();
        let current_envelope = candidate.current_envelope_by_domain[&DomainId::VirtIo];
        let effect = record.registered.identity.effect();
        let view = candidate.registry.effect_view(effect)?;
        if view.phase != EffectPhase::Committed || view.publication_pending {
            return Err(CompositionError::InvalidState);
        }
        let receipt = DomainClosureReceipt {
            domain: DomainId::VirtIo,
            effect,
            sequence: candidate.next_receipt_sequence,
            revision: candidate.receipt_revision + 1,
            domain_revision: candidate.domain_revisions[&DomainId::VirtIo],
            revoke_sequence: ticket.selection.sequence,
            closed_authority_epoch: ticket.selection.closed_authority_epoch,
            authority_epoch: ticket.selection.authority_epoch,
            binding_epoch: current_envelope.binding_epoch,
            device_generation: current_envelope.device_generation,
            terminal_sequence: None,
            status: ClosureStatus::TimedOut,
        };
        candidate.pending_closure = Some(PendingClosure {
            receipt,
            publication: None,
            disposition: None,
        });
        candidate.check_invariants()?;
        *state = candidate;
        Ok(receipt)
    }

    fn virtio_retry(&self, tombstone: TombstoneId) -> Result<(), CompositionError> {
        let mut state = self.state.lock();
        let mut candidate = state.clone();
        let timeout_sequence = *candidate
            .latest_receipt_by_domain
            .get(&DomainId::VirtIo)
            .ok_or(CompositionError::InvalidReceipt)?;
        let timeout_receipt = candidate.accepted_receipts[&timeout_sequence];
        if timeout_receipt.status != ClosureStatus::TimedOut
            || candidate.pending_closure.is_some()
            || candidate.invalidated_receipts.contains(&timeout_sequence)
        {
            return Err(CompositionError::InvalidState);
        }
        let device_generation = {
            let adapter = candidate
                .virtio
                .as_mut()
                .ok_or(CompositionError::InvalidState)?;
            adapter.retry(tombstone)?;
            adapter.device_generation
        };
        candidate
            .current_envelope_by_domain
            .get_mut(&DomainId::VirtIo)
            .unwrap()
            .device_generation = Some(device_generation);
        let revision = candidate
            .domain_revisions
            .get_mut(&DomainId::VirtIo)
            .unwrap();
        *revision += 1;
        candidate.invalidated_receipts.insert(timeout_sequence);
        candidate.latest_receipt_by_domain.remove(&DomainId::VirtIo);
        candidate.check_invariants()?;
        *state = candidate;
        Ok(())
    }

    fn try_revoke_complete(&self, ticket: &RootRevokeTicket) -> Result<(), CompositionError> {
        let mut state = self.state.lock();
        if state.root_phase != RootPhase::Closing || !state.ticket_is_current(ticket) {
            return Err(CompositionError::InvalidState);
        }
        if state
            .latest_receipt_by_domain
            .values()
            .any(|sequence| state.accepted_receipts[sequence].status == ClosureStatus::TimedOut)
        {
            return Err(CompositionError::RevokeTimedOut);
        }
        if state.pending_closure.is_some()
            || state
                .closure_receipts
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                != state.frozen_domains
            || state
                .closure_receipts
                .values()
                .map(|receipt| receipt.effect)
                .collect::<BTreeSet<_>>()
                != state.frozen_effects
            || state
                .latest_receipt_by_domain
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                != state.frozen_domains
        {
            return Err(CompositionError::ClosureReceiptsIncomplete);
        }
        let mut candidate = state.clone();
        candidate.registry.revoke_complete(&ticket.selection)?;
        candidate.root_phase = RootPhase::Revoked;
        candidate.check_invariants()?;
        *state = candidate;
        Ok(())
    }
}

pub(crate) fn run_composition_slice(scheduler: &CserScheduler, pager_receipt: PagerSliceReceipt) {
    let scheduler_binding = scheduler.binding();
    assert_eq!(scheduler_binding.authority_epoch, 41);
    assert_eq!(scheduler_binding.binding_epoch, 4);
    assert_eq!(pager_receipt.binding_epoch, 2);
    assert_eq!(pager_receipt.terminalizations, 2);
    assert!(pager_receipt.quiescent);

    println!(
        "COMPOSITION_SLICE BEGIN root_scope=70 authority_epoch=121 domains=5 bounded=true single_cpu=true runtime_fs=false runtime_net=false virtio_adapter=external_stage5b_consistency"
    );
    let backbone =
        CompositionBackbone::new(scheduler_binding.binding_epoch, pager_receipt.binding_epoch);

    // The rejected transaction exercises clone/apply/validate/swap: no edge,
    // credit, effect, envelope, or reverse-index entry may leak on failure.
    let before_failed_derive = backbone.projection();
    assert_eq!(
        backbone.derive_child(
            DomainId::Personality,
            Parent::Root,
            None,
            DomainEnvelope {
                root_authority_epoch: ROOT_AUTHORITY_EPOCH - 1,
                binding_epoch: 2,
                device_generation: None,
            },
        ),
        Err(CompositionError::StaleAuthority)
    );
    assert_eq!(backbone.projection(), before_failed_derive);
    println!(
        "COMPOSITION_DERIVE Reject root_scope=70 domain=personality reason=StaleAuthority failure_atomic=true mutation=false"
    );

    for domain in DOMAINS {
        let parent = domain.expected_parent();
        let parent_envelope = match parent {
            Parent::Root => None,
            Parent::Domain(parent_domain) => Some(backbone.record(parent_domain).envelope),
        };
        let envelope = DomainEnvelope {
            root_authority_epoch: ROOT_AUTHORITY_EPOCH,
            binding_epoch: domain
                .expected_binding(scheduler_binding.binding_epoch, pager_receipt.binding_epoch),
            device_generation: domain.expected_device_generation(),
        };

        if domain == DomainId::Pager {
            let mut stale_parent = parent_envelope.unwrap();
            stale_parent.binding_epoch -= 1;
            let before_stale_parent = backbone.projection();
            assert_eq!(
                backbone.derive_child(domain, parent, Some(stale_parent), envelope),
                Err(CompositionError::StaleParentEnvelope)
            );
            assert_eq!(backbone.projection(), before_stale_parent);
            println!(
                "COMPOSITION_DERIVE Reject root_scope=70 domain=pager parent=personality presented_parent_binding_epoch=1 current_parent_binding_epoch=2 reason=StaleParentEnvelope failure_atomic=true mutation=false"
            );
            let mut stale_target = envelope;
            stale_target.binding_epoch = 1;
            let before_stale_target = backbone.projection();
            assert_eq!(
                backbone.derive_child(domain, parent, parent_envelope, stale_target),
                Err(CompositionError::StaleTargetEnvelope)
            );
            assert_eq!(backbone.projection(), before_stale_target);
            println!(
                "COMPOSITION_DERIVE Reject root_scope=70 domain=pager parent=personality presented_binding_epoch=1 current_binding_epoch=2 reason=StaleTargetEnvelope failure_atomic=true mutation=false"
            );
        }
        let registered = backbone
            .derive_child(domain, parent, parent_envelope, envelope)
            .unwrap();
        assert_eq!(
            registered.identity.effect().id(),
            u64::from(domain.ordinal())
        );
        println!(
            "COMPOSITION_DERIVE Applied root_scope=70 domain_scope={} domain={} effect={} parent={} authority_epoch=121 binding_epoch={} device_generation={} credit_class={} units=1 edge_indexed=true effect_indexed=true local_scope_indexed=true failure_atomic=true",
            domain.local_scope(),
            domain.label(),
            registered.identity.effect().id(),
            parent.label(),
            envelope.binding_epoch,
            envelope.device_generation.map_or("none", |_| "3"),
            domain.ordinal(),
        );
    }
    let active = backbone.projection();
    assert_eq!(active.domains, DOMAIN_COUNT);
    assert_eq!(active.edges, DOMAIN_COUNT);
    assert_eq!(active.by_effect, DOMAIN_COUNT);
    assert_eq!(active.by_local_scope, DOMAIN_COUNT);
    assert_eq!(active.credits, DOMAIN_COUNT);
    assert_eq!(active.registry.credits.free, 0);
    assert_eq!(active.registry.credits.held, DOMAIN_COUNT as u64);
    println!(
        "COMPOSITION_BACKBONE Active root_scope=70 authority_epoch=121 domains=5 causal_nodes=6 causal_edges=5 delegated_credits=5 reverse_effects=5 reverse_local_scopes=5 gate=single"
    );

    for domain in DOMAINS {
        let record = backbone.record(domain);
        match record.envelope.device_generation {
            Some(device_generation) => println!(
                "COMPOSITION_BINDING Attach root_scope=70 domain_scope={} domain={} binding_epoch={} device_generation={} independent=true",
                record.local_scope,
                domain.label(),
                record.envelope.binding_epoch,
                device_generation,
            ),
            None => println!(
                "COMPOSITION_BINDING Attach root_scope=70 domain_scope={} domain={} binding_epoch={} device_generation=none independent=true",
                record.local_scope,
                domain.label(),
                record.envelope.binding_epoch,
            ),
        }
    }

    let (readiness_effect, delivery_sequence) = backbone.exercise_readiness().unwrap();
    println!(
        "COMPOSITION_READINESS Receipt domain_scope=74 effect={} delivery_sequence={} events=1 binding_epoch=2 replay_rejected=true live_sources=0 live_sets=0 subscriptions=0 queued=0 unpublished=0",
        readiness_effect.id(),
        delivery_sequence,
    );

    let virtio_record = backbone.record(DomainId::VirtIo);
    let virtio_effect = virtio_record.registered.identity.effect();
    println!(
        "COMPOSITION_VIRTIO Adapter domain_scope=75 effect={} source=external_stage5b_consistency binding_epoch=3 device_generation=3 commit_point=avail_idx_release reset_timeout=tombstone iotlb_completion_before_release=true identity_preserving=false",
        virtio_effect.id(),
    );
    let virtio_commit = match backbone
        .commit_domain(
            DomainId::VirtIo,
            ROOT_AUTHORITY_EPOCH,
            CommitMetadata::new(0, 5),
        )
        .unwrap()
    {
        CommitOutcome::Applied(receipt) => receipt,
        CommitOutcome::AlreadyCommitted(_) => unreachable!(),
    };
    println!(
        "COMPOSITION_VIRTIO Commit root_scope=70 domain_scope=75 effect={} binding_epoch=3 device_generation=3 commit_sequence={} point=avail_idx_release",
        virtio_effect.id(),
        virtio_commit.sequence(),
    );

    let revoke = backbone.revoke_begin().unwrap();
    assert_eq!(
        revoke.selection.closed_authority_epoch,
        ROOT_AUTHORITY_EPOCH
    );
    assert_eq!(revoke.selection.authority_epoch, ROOT_AUTHORITY_EPOCH + 1);
    assert_eq!(revoke.frozen_domains.len(), DOMAIN_COUNT);
    assert_eq!(revoke.frozen_effects.len(), DOMAIN_COUNT);
    println!(
        "COMPOSITION_REVOKE Begin root_scope=70 authority_epoch_old=121 authority_epoch_new=122 frozen_domains=5 frozen_effects=5 cohort_source=registry_live_selection gate=closed"
    );

    let stale_projection = backbone.projection();
    assert_eq!(
        backbone.validate_child(
            DomainId::Scheduler,
            DomainEnvelope {
                root_authority_epoch: ROOT_AUTHORITY_EPOCH,
                binding_epoch: scheduler_binding.binding_epoch,
                device_generation: None,
            },
        ),
        Err(CompositionError::StaleAuthority)
    );
    assert_eq!(backbone.projection(), stale_projection);
    println!(
        "COMPOSITION_REJECT stage=closing kind=stale_child domain=scheduler presented_authority_epoch=121 current_authority_epoch=122 mutation=false"
    );

    assert_eq!(
        backbone.commit_domain(
            DomainId::Scheduler,
            ROOT_AUTHORITY_EPOCH,
            CommitMetadata::new(0, 5),
        ),
        Err(CompositionError::StaleAuthority)
    );
    assert_eq!(backbone.projection(), stale_projection);
    println!(
        "COMPOSITION_REJECT stage=closing kind=stale_commit domain=scheduler effect=3 presented_authority_epoch=121 current_authority_epoch=122 mutation=false"
    );

    assert_eq!(
        backbone.validate_virtio_receipt(2, 2),
        Err(CompositionError::InvalidReceipt)
    );
    assert_eq!(backbone.projection(), stale_projection);
    println!(
        "COMPOSITION_REJECT stage=closing kind=stale_receipt domain=virtio presented_binding_epoch=2 current_binding_epoch=3 presented_device_generation=2 current_device_generation=3 mutation=false"
    );

    assert_eq!(
        backbone.try_revoke_complete(&revoke),
        Err(CompositionError::ClosureReceiptsIncomplete)
    );
    println!(
        "COMPOSITION_REVOKE Pending root_scope=70 reason=domain_closure_receipts_incomplete live=5 credits_free=0 accepted_receipts=0"
    );

    let before_parent_reject = backbone.projection();
    assert_eq!(
        backbone.stage_closure(&revoke, DomainId::Personality),
        Err(CompositionError::LiveDescendant)
    );
    assert_eq!(backbone.projection(), before_parent_reject);
    println!(
        "COMPOSITION_REJECT stage=closing kind=live_descendant domain=personality live_children=pager+readiness child_first=true mutation=false"
    );

    for domain in CLOSURE_ORDER {
        let record = backbone.record(domain);
        let effect = record.registered.identity.effect();

        if domain == DomainId::VirtIo {
            let (tombstone, credit) = backbone.virtio_timeout().unwrap();
            let timeout = backbone.projection();
            assert_eq!(timeout.registry.live_effects, 3);
            assert_eq!(timeout.registry.pending_publications, 0);
            assert_eq!(timeout.registry.credits.free, 2);
            assert_eq!(timeout.registry.credits.held, 2);
            assert_eq!(timeout.registry.credits.committed, 1);
            assert_eq!(credit.effect, effect);
            println!(
                "COMPOSITION_VIRTIO Timeout root_scope=70 domain_scope=75 effect={} binding_epoch=3 device_generation=3 tombstone={} retained_credit_class={} retained_units={} owners_retained=true status=TimedOut",
                effect.id(),
                tombstone.0,
                credit.class.value(),
                credit.units,
            );
            let timeout_receipt = backbone.issue_virtio_timeout_receipt(&revoke).unwrap();
            assert_eq!(timeout_receipt.sequence, 3);
            assert_eq!(timeout_receipt.revision, 3);
            assert_eq!(timeout_receipt.domain_revision, 1);
            assert_eq!(timeout_receipt.status, ClosureStatus::TimedOut);
            println!(
                "COMPOSITION_RECEIPT Issue root_scope=70 domain=virtio effect=5 receipt_sequence=3 receipt_revision=3 domain_revision=1 revoke_sequence=1 binding_epoch=3 device_generation=3 status=TimedOut effect_live=true credit_live=true"
            );
            backbone
                .accept_closure_receipt(&revoke, timeout_receipt)
                .unwrap();
            println!(
                "COMPOSITION_RECEIPT Accept root_scope=70 domain=virtio effect=5 receipt_sequence=3 receipt_revision=3 domain_revision=1 status=TimedOut root_state=Closing effect_live=true credit_live=true"
            );
            println!(
                "COMPOSITION_REVOKE TimedOut root_scope=70 domain=virtio receipt_sequence=3 receipt_revision=3 domain_revision=1 result=RevokeTimedOut root_state=Closing effect_live=true credit_live=true closure_receipts=2"
            );
            assert_eq!(
                backbone.try_revoke_complete(&revoke),
                Err(CompositionError::RevokeTimedOut)
            );
            backbone.virtio_retry(tombstone).unwrap();
            println!(
                "COMPOSITION_VIRTIO Retry root_scope=70 domain_scope=75 effect={} tombstone={} attempt=1 domain_revision_before=1 domain_revision_after=2 invalidated_receipt_sequence=3 device_generation_before=3 device_generation_after=4 external_reset_ack_observed=true external_iotlb_complete_observed=true evidence_relation=component_consistency identity_preserving=false credit_retained_until_close=true tombstone_invalidated=true",
                effect.id(),
                tombstone.0,
            );
            let before_timeout_replay = backbone.projection();
            assert_eq!(
                backbone.accept_closure_receipt(&revoke, timeout_receipt),
                Err(CompositionError::StaleClosureReceipt)
            );
            assert_eq!(backbone.projection(), before_timeout_replay);
            println!(
                "COMPOSITION_RECEIPT REJECT stage=retry kind=stale_timeout_replay domain=virtio receipt_sequence=3 presented_domain_revision=1 current_domain_revision=2 result=StaleClosureReceipt failure_atomic=true mutation=false"
            );
        }

        let issued = backbone.stage_closure(&revoke, domain).unwrap();
        let receipt = issued.receipt;
        assert_eq!(receipt.effect, effect);
        assert_eq!(receipt.closed_authority_epoch, ROOT_AUTHORITY_EPOCH);
        assert_eq!(receipt.authority_epoch, ROOT_AUTHORITY_EPOCH + 1);
        let outcome = match receipt.status {
            ClosureStatus::Closed(TerminalOutcome::Completed) => "Completed",
            ClosureStatus::Closed(TerminalOutcome::Aborted) => "Aborted",
            ClosureStatus::TimedOut => unreachable!(),
        };
        let terminal_sequence = receipt.terminal_sequence.unwrap();
        match receipt.device_generation {
            Some(device_generation) => println!(
                "COMPOSITION_CLOSURE Issue root_scope=70 domain_scope={} domain={} effect={} receipt_sequence={} receipt_revision={} domain_revision={} revoke_sequence={} terminal_sequence={} binding_epoch={} device_generation={} disposition={} outcome={} status=Closed publication_pending=true",
                record.local_scope,
                domain.label(),
                receipt.effect.id(),
                receipt.sequence,
                receipt.revision,
                receipt.domain_revision,
                receipt.revoke_sequence,
                terminal_sequence,
                receipt.binding_epoch,
                device_generation,
                issued.disposition.label(),
                outcome,
            ),
            None => println!(
                "COMPOSITION_CLOSURE Issue root_scope=70 domain_scope={} domain={} effect={} receipt_sequence={} receipt_revision={} domain_revision={} revoke_sequence={} terminal_sequence={} binding_epoch={} device_generation=none disposition={} outcome={} status=Closed publication_pending=true",
                record.local_scope,
                domain.label(),
                receipt.effect.id(),
                receipt.sequence,
                receipt.revision,
                receipt.domain_revision,
                receipt.revoke_sequence,
                terminal_sequence,
                receipt.binding_epoch,
                issued.disposition.label(),
                outcome,
            ),
        }

        if domain == DomainId::Scheduler {
            let issued_projection = backbone.projection();
            let mut stale = receipt;
            stale.authority_epoch = ROOT_AUTHORITY_EPOCH;
            assert_eq!(
                backbone.accept_closure_receipt(&revoke, stale),
                Err(CompositionError::StaleReceipt)
            );
            assert_eq!(backbone.projection(), issued_projection);
            println!(
                "COMPOSITION_RECEIPT REJECT stage=accept kind=stale domain=scheduler receipt_sequence=1 presented_authority_epoch=121 current_authority_epoch=122 failure_atomic=true mutation=false"
            );
            let mut out_of_order = receipt;
            out_of_order.sequence += 1;
            out_of_order.revision += 1;
            assert_eq!(
                backbone.accept_closure_receipt(&revoke, out_of_order),
                Err(CompositionError::OutOfOrderReceipt)
            );
            assert_eq!(backbone.projection(), issued_projection);
            println!(
                "COMPOSITION_RECEIPT REJECT stage=accept kind=out_of_order domain=scheduler presented_sequence=2 expected_sequence=1 result=OutOfOrderReceipt failure_atomic=true mutation=false"
            );
        }

        backbone.accept_closure_receipt(&revoke, receipt).unwrap();
        println!(
            "COMPOSITION_CLOSURE Accept root_scope=70 domain={} effect={} receipt_sequence={} receipt_revision={} status=Closed acknowledgement=Applied credit=Free",
            domain.label(),
            receipt.effect.id(),
            receipt.sequence,
            receipt.revision,
        );

        if domain == DomainId::Scheduler {
            let accepted_projection = backbone.projection();
            assert_eq!(
                backbone.accept_closure_receipt(&revoke, receipt),
                Err(CompositionError::DuplicateReceipt)
            );
            assert_eq!(backbone.projection(), accepted_projection);
            println!(
                "COMPOSITION_RECEIPT REJECT stage=accept kind=duplicate domain=scheduler receipt_sequence=1 result=DuplicateReceipt failure_atomic=true mutation=false"
            );
        }
    }

    backbone.try_revoke_complete(&revoke).unwrap();
    let final_projection = backbone.projection();
    assert_eq!(final_projection.phase, RootPhase::Revoked);
    assert_eq!(final_projection.authority_epoch, ROOT_AUTHORITY_EPOCH + 1);
    assert_eq!(final_projection.frozen_domains, DOMAIN_COUNT);
    assert_eq!(final_projection.frozen_effects, DOMAIN_COUNT);
    assert_eq!(final_projection.accepted_receipts, DOMAIN_COUNT + 1);
    assert_eq!(final_projection.accepted_closure_receipts, DOMAIN_COUNT);
    assert_eq!(final_projection.pending_closure_receipts, 0);
    assert_eq!(final_projection.invalidated_receipts, 1);
    assert_eq!(final_projection.receipt_revision, DOMAIN_COUNT as u64 + 1);
    assert_eq!(
        final_projection.next_receipt_sequence,
        DOMAIN_COUNT as u64 + 2
    );
    assert_eq!(final_projection.registry.phase, ScopePhase::Revoked);
    assert_eq!(final_projection.registry.live_effects, 0);
    assert_eq!(final_projection.registry.pending_publications, 0);
    assert_eq!(
        final_projection.registry.credits.capacity,
        DOMAIN_COUNT as u64
    );
    assert_eq!(final_projection.registry.credits.free, DOMAIN_COUNT as u64);
    assert_eq!(final_projection.registry.credits.held, 0);
    assert_eq!(final_projection.registry.credits.committed, 0);
    assert_eq!(final_projection.readiness_sources, 0);
    assert_eq!(final_projection.readiness_sets, 0);
    assert_eq!(final_projection.readiness_subscriptions, 0);
    assert_eq!(final_projection.readiness_queued, 0);
    assert_eq!(final_projection.readiness_unpublished, 0);
    let virtio = final_projection.virtio.unwrap();
    assert_eq!(virtio.state, VirtIoState::Closed);
    assert_eq!(virtio.retries, 1);
    assert_eq!(virtio.device_generation, 4);
    assert!(virtio.tombstone.is_none());
    println!(
        "COMPOSITION_REVOKE Complete root_scope=70 authority_epoch=122 frozen_domains=5 closure_receipts=5 accepted_receipts=6 invalidated_receipts=1 receipt_revision=6 credits_free=5 live=0 pending=0 state=Revoked"
    );
    println!(
        "COMPOSITION_SLICE PASS root_scope=70 authority_epoch_old=121 authority_epoch_new=122 domains=5 causal_nodes=6 causal_edges=5 parent_chain_immutable=true stale_parent_rejected=true stale_target_rejected=true delegated_credits=5 binding_epochs=scheduler:4,pager:2,personality:2,readiness:2,virtio:3 device_generations=virtio:3->4 frozen_domains=5 cohort_source=registry_live_selection closure_order=scheduler,pager,virtio,readiness,personality child_first=true live_descendant_rejected=true closure_receipts=5 receipt_sequences=6 receipt_revision=6 receipt_acceptance=authoritative closure_sequences_unique=true timeout_receipts=1 timeout_replay_rejected=true duplicate_receipt_rejected=true out_of_order_receipt_rejected=true virtio_tombstones=1 virtio_retries=1 stale_child_rejected=true stale_commit_rejected=true stale_receipt_rejected=true virtio_evidence=component_consistency identity_preserving=false credits_free=5 live=0 pending=0 final_quiescent=true bounded=true single_cpu=true runtime_fs=false runtime_net=false"
    );
}
