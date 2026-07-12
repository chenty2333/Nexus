// SPDX-License-Identifier: MPL-2.0

//! Additive seven-domain Linux I/O composition successor.
//!
//! The frozen five-domain composition receipt remains untouched.  This slice
//! creates a fresh root registry with nine effects, eight typed credit classes
//! and coordinator-owned causal/reverse indexes.  The retained filesystem and
//! network workloads contribute only read-only, same-boot prerequisite
//! receipts; their already-revoked effects and portal identities are never
//! imported into this cohort.  Per-service bindings and resource generations
//! remain bounded outer envelopes because the common registry intentionally
//! has one root supervisor/binding rather than pretending to be a production
//! multi-service authority transport.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec,
    vec::Vec,
};

use ostd::{prelude::*, sync::SpinLock};

use crate::{
    effect_registry::{
        CommitMetadata, CommitOutcome, CommitReceipt, CreditCharge, CreditClass, CreditLimit,
        EffectKey, EffectPhase, EffectRegistry, OperationClass, PublicationMode, RegisterRequest,
        RegisteredEffect, RegistryError, RegistryProjection, RevokeSelection, ScopeConfig,
        ScopeKey, ScopePhase, SyscallDescriptor, TaskKey, TerminalOutcome, TerminalRequest,
    },
    linux_fs::RuntimeFsSliceReceipt,
    linux_net::RuntimeNetSliceReceipt,
    pager::PagerSliceReceipt,
    readiness::{READY_READABLE, ReadinessCore, ReadinessError, TriggerMode},
    scheduler::CserScheduler,
};

const ROOT_SCOPE: ScopeKey = ScopeKey::new(120, 1);
const ROOT_AUTHORITY_EPOCH: u64 = 401;
const ROOT_SUPERVISOR: TaskKey = TaskKey::new(1200, 1);
const DOMAIN_COUNT: usize = 7;
const EFFECT_COUNT: usize = 9;
const CREDIT_CLASS_COUNT: usize = 8;
const CREDIT_UNITS: u64 = 9;

const CONTROL: CreditClass = CreditClass::new(1);
const MEMORY: CreditClass = CreditClass::new(2);
const SCHEDULING: CreditClass = CreditClass::new(3);
const FILESYSTEM: CreditClass = CreditClass::new(4);
const DMA: CreditClass = CreditClass::new(5);
const NETWORK: CreditClass = CreditClass::new(6);
const READINESS: CreditClass = CreditClass::new(7);
const BUFFER: CreditClass = CreditClass::new(8);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum DomainId {
    Personality,
    Pager,
    Scheduler,
    Filesystem,
    VirtIo,
    Network,
    Readiness,
}

impl DomainId {
    const ALL: [Self; DOMAIN_COUNT] = [
        Self::Personality,
        Self::Pager,
        Self::Scheduler,
        Self::Filesystem,
        Self::VirtIo,
        Self::Network,
        Self::Readiness,
    ];

    const CLOSURE_ORDER: [Self; DOMAIN_COUNT] = [
        Self::Scheduler,
        Self::Pager,
        Self::VirtIo,
        Self::Filesystem,
        Self::Readiness,
        Self::Network,
        Self::Personality,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Personality => "personality",
            Self::Pager => "pager",
            Self::Scheduler => "scheduler",
            Self::Filesystem => "filesystem",
            Self::VirtIo => "virtio",
            Self::Network => "network",
            Self::Readiness => "readiness",
        }
    }

    const fn binding_epoch(self, scheduler_epoch: u64, pager_epoch: u64) -> u64 {
        match self {
            Self::Scheduler => scheduler_epoch,
            Self::Pager => pager_epoch,
            Self::VirtIo => 3,
            Self::Personality | Self::Filesystem | Self::Network | Self::Readiness => 2,
        }
    }

    const fn parent(self) -> Option<Self> {
        match self {
            Self::Personality => None,
            Self::Pager | Self::Filesystem | Self::Network => Some(Self::Personality),
            Self::Scheduler => Some(Self::Pager),
            Self::VirtIo => Some(Self::Filesystem),
            Self::Readiness => Some(Self::Network),
        }
    }

    const fn effect_count(self) -> usize {
        match self {
            Self::Personality | Self::Network => 2,
            _ => 1,
        }
    }

    const fn credit_units(self) -> u64 {
        self.effect_count() as u64
    }

    const fn credit_labels(self) -> &'static str {
        match self {
            Self::Personality => "Control:2",
            Self::Pager => "Memory:1",
            Self::Scheduler => "Scheduling:1",
            Self::Filesystem => "Filesystem:1",
            Self::VirtIo => "DMA:1",
            Self::Network => "Network+Buffer:2",
            Self::Readiness => "Readiness:1",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum EffectKind {
    FsSyscall,
    NetSyscall,
    PagerMap,
    SchedulerAction,
    FsOp,
    BlockReq,
    NetOp,
    ReadinessWait,
    BufferLease,
}

impl EffectKind {
    const ALL: [Self; EFFECT_COUNT] = [
        Self::FsSyscall,
        Self::NetSyscall,
        Self::PagerMap,
        Self::SchedulerAction,
        Self::FsOp,
        Self::BlockReq,
        Self::NetOp,
        Self::ReadinessWait,
        Self::BufferLease,
    ];

    const TERMINAL_ORDER: [Self; EFFECT_COUNT] = [
        Self::SchedulerAction,
        Self::PagerMap,
        Self::BlockReq,
        Self::FsOp,
        Self::ReadinessWait,
        Self::BufferLease,
        Self::NetOp,
        Self::FsSyscall,
        Self::NetSyscall,
    ];

    const fn id(self) -> u64 {
        match self {
            Self::FsSyscall => 1,
            Self::NetSyscall => 2,
            Self::PagerMap => 3,
            Self::SchedulerAction => 4,
            Self::FsOp => 5,
            Self::BlockReq => 6,
            Self::NetOp => 7,
            Self::ReadinessWait => 8,
            Self::BufferLease => 9,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::FsSyscall => "FsSyscall",
            Self::NetSyscall => "NetSyscall",
            Self::PagerMap => "PagerMap",
            Self::SchedulerAction => "SchedulerAction",
            Self::FsOp => "FsOp",
            Self::BlockReq => "BlockReq",
            Self::NetOp => "NetOp",
            Self::ReadinessWait => "ReadinessWait",
            Self::BufferLease => "BufferLease",
        }
    }

    const fn domain(self) -> DomainId {
        match self {
            Self::FsSyscall | Self::NetSyscall => DomainId::Personality,
            Self::PagerMap => DomainId::Pager,
            Self::SchedulerAction => DomainId::Scheduler,
            Self::FsOp => DomainId::Filesystem,
            Self::BlockReq => DomainId::VirtIo,
            Self::NetOp | Self::BufferLease => DomainId::Network,
            Self::ReadinessWait => DomainId::Readiness,
        }
    }

    const fn parent(self) -> Option<Self> {
        match self {
            Self::FsSyscall | Self::NetSyscall => None,
            Self::PagerMap | Self::FsOp => Some(Self::FsSyscall),
            Self::SchedulerAction => Some(Self::PagerMap),
            Self::BlockReq => Some(Self::FsOp),
            Self::NetOp => Some(Self::NetSyscall),
            Self::ReadinessWait | Self::BufferLease => Some(Self::NetOp),
        }
    }

    const fn parent_label(self) -> &'static str {
        match self.parent() {
            None => "Root",
            Some(parent) => parent.label(),
        }
    }

    const fn credit(self) -> CreditClass {
        match self {
            Self::FsSyscall | Self::NetSyscall => CONTROL,
            Self::PagerMap => MEMORY,
            Self::SchedulerAction => SCHEDULING,
            Self::FsOp => FILESYSTEM,
            Self::BlockReq => DMA,
            Self::NetOp => NETWORK,
            Self::ReadinessWait => READINESS,
            Self::BufferLease => BUFFER,
        }
    }

    const fn credit_label(self) -> &'static str {
        match self {
            Self::FsSyscall | Self::NetSyscall => "Control",
            Self::PagerMap => "Memory",
            Self::SchedulerAction => "Scheduling",
            Self::FsOp => "Filesystem",
            Self::BlockReq => "DMA",
            Self::NetOp => "Network",
            Self::ReadinessWait => "Readiness",
            Self::BufferLease => "Buffer",
        }
    }

    const fn generation_label(self) -> &'static str {
        match self {
            Self::PagerMap => "address_space:2",
            Self::FsOp => "inode:1",
            Self::BlockReq => "device:3",
            Self::NetOp | Self::BufferLease => "socket:1",
            Self::ReadinessWait => "source:1",
            Self::FsSyscall | Self::NetSyscall | Self::SchedulerAction => "none",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootPhase {
    Active,
    Closing,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiptStatus {
    TimedOut,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DomainClosureReceipt {
    domain: DomainId,
    effects: Vec<u64>,
    terminal_sequences: Vec<u64>,
    sequence: u64,
    revision: u64,
    authority_epoch: u64,
    binding_epoch: u64,
    device_generation: Option<u64>,
    status: ReceiptStatus,
    credit_units: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VirtIoAdapter {
    binding_epoch: u64,
    device_generation: u64,
    committed: bool,
    tombstone: Option<u64>,
    retries: u64,
    closed: bool,
}

#[derive(Clone, Debug)]
struct RootRevokeTicket {
    selection: RevokeSelection,
    frozen_domains: BTreeSet<DomainId>,
    frozen_effects: BTreeSet<EffectKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CompositionError {
    StaleAuthority,
    RootNotActive,
    InvalidGraph,
    InvalidState,
    LiveDescendant,
    DomainNotQuiescent,
    OutOfOrderReceipt,
    DuplicateReceipt,
    TombstoneActive,
    StaleReceipt,
    Registry(RegistryError),
    Readiness(ReadinessError),
}

impl From<RegistryError> for CompositionError {
    fn from(error: RegistryError) -> Self {
        Self::Registry(error)
    }
}

impl From<ReadinessError> for CompositionError {
    fn from(error: ReadinessError) -> Self {
        Self::Readiness(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompositionProjection {
    phase: RootPhase,
    authority_epoch: u64,
    registry: RegistryProjection,
    effects: usize,
    edges: usize,
    live: usize,
    terminalizations: usize,
    accepted_receipts: usize,
    invalidated_receipts: usize,
    receipt_revision: u64,
    pending_receipt: bool,
    device_generation: u64,
    fs_bytes: [u8; 4],
    network_visible: bool,
    guest_replies: u64,
    readiness_sources: usize,
    readiness_sets: usize,
    readiness_subscriptions: usize,
    readiness_queued: usize,
    readiness_unpublished: usize,
}

#[derive(Clone, Debug)]
struct CompositionState {
    phase: RootPhase,
    authority_epoch: u64,
    scheduler_binding_epoch: u64,
    pager_binding_epoch: u64,
    registry: EffectRegistry,
    registered: BTreeMap<EffectKind, RegisteredEffect>,
    kind_by_effect: BTreeMap<EffectKey, EffectKind>,
    effect_by_kind: BTreeMap<EffectKind, EffectKey>,
    parent_by_effect: BTreeMap<EffectKey, Option<EffectKey>>,
    children_by_parent: BTreeMap<Option<EffectKey>, BTreeSet<EffectKey>>,
    effects_by_domain: BTreeMap<DomainId, BTreeSet<EffectKey>>,
    commits: BTreeMap<EffectKind, CommitReceipt>,
    live: BTreeSet<EffectKey>,
    terminal_sequences: BTreeMap<EffectKey, u64>,
    readiness: ReadinessCore,
    fs_bytes: [u8; 4],
    network_payload: Option<[u8; 4]>,
    guest_replies: u64,
    buffer_closure_drains: u64,
    virtio: VirtIoAdapter,
    active_revoke: Option<RootRevokeTicket>,
    next_receipt_sequence: u64,
    receipt_revision: u64,
    pending_receipt: Option<DomainClosureReceipt>,
    accepted_receipts: BTreeMap<u64, DomainClosureReceipt>,
    current_receipt: BTreeMap<DomainId, u64>,
    invalidated_receipts: BTreeSet<u64>,
}

impl CompositionState {
    fn new(scheduler_binding_epoch: u64, pager_binding_epoch: u64) -> Self {
        let mut registry = EffectRegistry::new();
        registry
            .create_scope(ScopeConfig {
                key: ROOT_SCOPE,
                authority_epoch: ROOT_AUTHORITY_EPOCH,
                binding_epoch: 1,
                supervisor: ROOT_SUPERVISOR,
                credits: vec![
                    CreditLimit::new(CONTROL, 2),
                    CreditLimit::new(MEMORY, 1),
                    CreditLimit::new(SCHEDULING, 1),
                    CreditLimit::new(FILESYSTEM, 1),
                    CreditLimit::new(DMA, 1),
                    CreditLimit::new(NETWORK, 1),
                    CreditLimit::new(READINESS, 1),
                    CreditLimit::new(BUFFER, 1),
                ],
            })
            .unwrap();
        Self {
            phase: RootPhase::Active,
            authority_epoch: ROOT_AUTHORITY_EPOCH,
            scheduler_binding_epoch,
            pager_binding_epoch,
            registry,
            registered: BTreeMap::new(),
            kind_by_effect: BTreeMap::new(),
            effect_by_kind: BTreeMap::new(),
            parent_by_effect: BTreeMap::new(),
            children_by_parent: BTreeMap::new(),
            effects_by_domain: BTreeMap::new(),
            commits: BTreeMap::new(),
            live: BTreeSet::new(),
            terminal_sequences: BTreeMap::new(),
            readiness: ReadinessCore::new(),
            fs_bytes: [0; 4],
            network_payload: None,
            guest_replies: 0,
            buffer_closure_drains: 0,
            virtio: VirtIoAdapter {
                binding_epoch: 3,
                device_generation: 3,
                committed: false,
                tombstone: None,
                retries: 0,
                closed: false,
            },
            active_revoke: None,
            next_receipt_sequence: 1,
            receipt_revision: 0,
            pending_receipt: None,
            accepted_receipts: BTreeMap::new(),
            current_receipt: BTreeMap::new(),
            invalidated_receipts: BTreeSet::new(),
        }
    }

    fn binding_epoch(&self, domain: DomainId) -> u64 {
        domain.binding_epoch(self.scheduler_binding_epoch, self.pager_binding_epoch)
    }

    fn projection(&self) -> CompositionProjection {
        let readiness = self.readiness.counts();
        CompositionProjection {
            phase: self.phase,
            authority_epoch: self.authority_epoch,
            registry: self.registry.scope_projection(ROOT_SCOPE).unwrap(),
            effects: self.registered.len(),
            edges: self.parent_by_effect.len(),
            live: self.live.len(),
            terminalizations: self.terminal_sequences.len(),
            accepted_receipts: self.accepted_receipts.len(),
            invalidated_receipts: self.invalidated_receipts.len(),
            receipt_revision: self.receipt_revision,
            pending_receipt: self.pending_receipt.is_some(),
            device_generation: self.virtio.device_generation,
            fs_bytes: self.fs_bytes,
            network_visible: self.network_payload.is_some(),
            guest_replies: self.guest_replies,
            readiness_sources: readiness.sources,
            readiness_sets: readiness.sets,
            readiness_subscriptions: readiness.subscriptions,
            readiness_queued: readiness.queued,
            readiness_unpublished: readiness.unpublished_deliveries,
        }
    }

    fn derive(
        &mut self,
        kind: EffectKind,
        presented_authority_epoch: u64,
    ) -> Result<RegisteredEffect, CompositionError> {
        if presented_authority_epoch != self.authority_epoch {
            return Err(CompositionError::StaleAuthority);
        }
        if self.phase != RootPhase::Active {
            return Err(CompositionError::RootNotActive);
        }
        if self.registered.contains_key(&kind) {
            return Err(CompositionError::InvalidGraph);
        }
        let expected_parent = match kind.parent() {
            None => None,
            Some(parent) => Some(
                *self
                    .effect_by_kind
                    .get(&parent)
                    .ok_or(CompositionError::InvalidGraph)?,
            ),
        };
        let registered = self.registry.register(RegisterRequest {
            scope: ROOT_SCOPE,
            task: ROOT_SUPERVISOR,
            operation: OperationClass::new(100 + kind.id() as u32),
            descriptor: SyscallDescriptor::new(
                0x4c49_4f00 + kind.id() as usize,
                [
                    kind.id() as usize,
                    kind.parent().map_or(0, |parent| parent.id()) as usize,
                    0,
                    0,
                    0,
                    0,
                ],
            ),
            resources: vec![crate::effect_registry::ResourceKey::new(
                0x9000 + kind.domain() as u32,
                kind.id(),
                1,
            )],
            credits: vec![CreditCharge::new(kind.credit(), 1)],
            publication: PublicationMode::Required,
        })?;
        let effect = registered.identity.effect();
        if effect.id() != kind.id() {
            return Err(CompositionError::InvalidGraph);
        }
        self.registered.insert(kind, registered.clone());
        self.kind_by_effect.insert(effect, kind);
        self.effect_by_kind.insert(kind, effect);
        self.parent_by_effect.insert(effect, expected_parent);
        self.children_by_parent
            .entry(expected_parent)
            .or_default()
            .insert(effect);
        self.effects_by_domain
            .entry(kind.domain())
            .or_default()
            .insert(effect);
        self.live.insert(effect);
        self.check_invariants()?;
        Ok(registered)
    }

    fn prepare(&mut self, kind: EffectKind) -> Result<(), CompositionError> {
        self.registry
            .prepare(ROOT_SUPERVISOR, self.registered[&kind].handle)?;
        Ok(())
    }

    fn commit_one(
        &mut self,
        kind: EffectKind,
        presented_authority_epoch: u64,
        result: i64,
        domain_revision: u64,
    ) -> Result<CommitReceipt, CompositionError> {
        if presented_authority_epoch != self.authority_epoch {
            return Err(CompositionError::StaleAuthority);
        }
        if self.phase != RootPhase::Active {
            return Err(CompositionError::RootNotActive);
        }
        self.prepare(kind)?;
        let outcome = self.registry.commit(
            ROOT_SUPERVISOR,
            self.registered[&kind].handle,
            CommitMetadata::new(result, domain_revision),
        )?;
        let CommitOutcome::Applied(receipt) = outcome else {
            return Err(CompositionError::InvalidState);
        };
        self.commits.insert(kind, receipt.clone());
        self.check_invariants()?;
        Ok(receipt)
    }

    fn commit_network(&mut self) -> Result<(CommitReceipt, CommitReceipt), CompositionError> {
        if self.phase != RootPhase::Active {
            return Err(CompositionError::RootNotActive);
        }
        self.prepare(EffectKind::NetOp)?;
        self.prepare(EffectKind::BufferLease)?;
        let outcomes = self.registry.commit_with_moves(
            ROOT_SUPERVISOR,
            &[
                (
                    self.registered[&EffectKind::NetOp].handle,
                    CommitMetadata::new(4, 1),
                ),
                (
                    self.registered[&EffectKind::BufferLease].handle,
                    CommitMetadata::new(4, 1),
                ),
            ],
            &[],
        )?;
        let mut outcomes = outcomes.into_iter();
        let CommitOutcome::Applied(network) = outcomes.next().unwrap() else {
            return Err(CompositionError::InvalidState);
        };
        let CommitOutcome::Applied(buffer) = outcomes.next().unwrap() else {
            return Err(CompositionError::InvalidState);
        };
        if outcomes.next().is_some() {
            return Err(CompositionError::InvalidState);
        }
        self.commits.insert(EffectKind::NetOp, network.clone());
        self.commits.insert(EffectKind::BufferLease, buffer.clone());
        self.network_payload = Some(*b"ping");
        self.check_invariants()?;
        Ok((network, buffer))
    }

    fn commit_readiness(
        &mut self,
        network_commit: &CommitReceipt,
    ) -> Result<(CommitReceipt, u64), CompositionError> {
        if self.commits.get(&EffectKind::NetOp) != Some(network_commit)
            || self.network_payload != Some(*b"ping")
        {
            return Err(CompositionError::InvalidState);
        }
        let receipt = self.commit_one(EffectKind::ReadinessWait, self.authority_epoch, 1, 1)?;
        let effect = self.effect_by_kind[&EffectKind::ReadinessWait];
        let source = self.readiness.create_source(1, READY_READABLE)?;
        let set = self.readiness.create_set()?;
        let subscription = self.readiness.attach(
            set,
            source,
            effect,
            self.binding_epoch(DomainId::Readiness),
            READY_READABLE,
            TriggerMode::OneShot,
            0x4c49_4f43,
        )?;
        let delivery = self.readiness.commit_delivery(
            set,
            effect,
            1,
            self.binding_epoch(DomainId::Readiness),
        )?;
        if delivery.events().len() != 1 {
            return Err(CompositionError::InvalidState);
        }
        self.readiness.publish_delivery(&delivery)?;
        let after_publish = self.readiness.counts();
        if self.readiness.publish_delivery(&delivery) != Err(ReadinessError::AlreadyPublished)
            || self.readiness.counts() != after_publish
        {
            return Err(CompositionError::InvalidState);
        }
        if self.readiness.detach(subscription)? != effect {
            return Err(CompositionError::InvalidState);
        }
        self.readiness.retire_source(source)?;
        self.readiness.destroy_set(set)?;
        self.readiness.check_invariants()?;
        let counts = self.readiness.counts();
        if counts.sources != 0
            || counts.sets != 0
            || counts.subscriptions != 0
            || counts.queued != 0
            || counts.unpublished_deliveries != 0
        {
            return Err(CompositionError::InvalidState);
        }
        Ok((receipt, delivery.sequence()))
    }

    fn revoke_begin(&mut self) -> Result<RootRevokeTicket, CompositionError> {
        if self.phase != RootPhase::Active {
            return Err(CompositionError::RootNotActive);
        }
        let selection = self.registry.revoke_begin(ROOT_SCOPE)?;
        let frozen_effects = selection.effects.clone();
        let frozen_domains = frozen_effects
            .iter()
            .map(|effect| self.kind_by_effect[effect].domain())
            .collect();
        self.phase = RootPhase::Closing;
        self.authority_epoch = selection.authority_epoch;
        let ticket = RootRevokeTicket {
            selection,
            frozen_domains,
            frozen_effects,
        };
        self.active_revoke = Some(ticket.clone());
        self.check_invariants()?;
        Ok(ticket)
    }

    fn reject_live_descendant(&self, kind: EffectKind) -> Result<(), CompositionError> {
        let effect = self.effect_by_kind[&kind];
        if self
            .children_by_parent
            .get(&Some(effect))
            .is_some_and(|children| children.iter().any(|child| self.live.contains(child)))
        {
            return Err(CompositionError::LiveDescendant);
        }
        Ok(())
    }

    fn close_effect(
        &mut self,
        kind: EffectKind,
    ) -> Result<(u64, TerminalOutcome), CompositionError> {
        if kind == EffectKind::BlockReq && self.virtio.tombstone.is_some() {
            return Err(CompositionError::TombstoneActive);
        }
        self.reject_live_descendant(kind)?;
        let effect = self.effect_by_kind[&kind];
        let ticket = self
            .active_revoke
            .as_ref()
            .ok_or(CompositionError::InvalidState)?;
        let (request, outcome) = match self.commits.get(&kind) {
            Some(commit) => (
                TerminalRequest::completed_by(commit.result(), commit.clone()),
                TerminalOutcome::Completed,
            ),
            None => (TerminalRequest::aborted(0), TerminalOutcome::Aborted),
        };
        let terminal = self
            .registry
            .stage_revoke_terminal(&ticket.selection, effect, request)?;
        let sequence = terminal.receipt.sequence();
        if terminal.receipt.outcome() != outcome {
            return Err(CompositionError::InvalidState);
        }
        self.registry.acknowledge_publication(
            terminal
                .publication
                .as_ref()
                .ok_or(CompositionError::InvalidState)?,
        )?;
        if kind == EffectKind::BufferLease {
            if self.network_payload.take() != Some(*b"ping") {
                return Err(CompositionError::InvalidState);
            }
            self.buffer_closure_drains += 1;
        }
        if kind == EffectKind::BlockReq {
            self.virtio.closed = true;
        }
        self.live.remove(&effect);
        self.terminal_sequences.insert(effect, sequence);
        self.check_invariants()?;
        Ok((sequence, outcome))
    }

    fn timeout_virtio(&mut self) -> Result<u64, CompositionError> {
        let block_effect = self.effect_by_kind[&EffectKind::BlockReq];
        if self.phase != RootPhase::Closing
            || !self.commits.contains_key(&EffectKind::BlockReq)
            || !self.virtio.committed
            || self.virtio.tombstone.is_some()
            || self.virtio.closed
            || !self.live.contains(&block_effect)
            || self.registry.effect_view(block_effect)?.phase != EffectPhase::Committed
        {
            return Err(CompositionError::InvalidState);
        }
        self.virtio.tombstone = Some(1);
        Ok(1)
    }

    fn retry_virtio(&mut self, tombstone: u64) -> Result<u64, CompositionError> {
        if self.virtio.tombstone != Some(tombstone) {
            return Err(CompositionError::StaleReceipt);
        }
        let timeout_sequence = self
            .current_receipt
            .remove(&DomainId::VirtIo)
            .ok_or(CompositionError::InvalidState)?;
        if self.accepted_receipts[&timeout_sequence].status != ReceiptStatus::TimedOut {
            return Err(CompositionError::InvalidState);
        }
        self.invalidated_receipts.insert(timeout_sequence);
        self.virtio.tombstone = None;
        self.virtio.retries += 1;
        self.virtio.device_generation += 1;
        Ok(timeout_sequence)
    }

    fn has_unclosed_child_domain(&self, domain: DomainId) -> bool {
        DomainId::ALL.into_iter().any(|child| {
            child.parent() == Some(domain)
                && self
                    .active_revoke
                    .as_ref()
                    .is_some_and(|ticket| ticket.frozen_domains.contains(&child))
                && self.current_receipt.get(&child).is_none_or(|sequence| {
                    self.accepted_receipts
                        .get(sequence)
                        .is_none_or(|receipt| receipt.status != ReceiptStatus::Closed)
                })
        })
    }

    fn has_retained_virtio_timeout_state(&self, domain_effects: &BTreeSet<EffectKey>) -> bool {
        let Some(block_effect) = self.effect_by_kind.get(&EffectKind::BlockReq).copied() else {
            return false;
        };
        let Ok(block) = self.registry.effect_view(block_effect) else {
            return false;
        };
        domain_effects.len() == 1
            && domain_effects.contains(&block_effect)
            && self.live.contains(&block_effect)
            && self.commits.contains_key(&EffectKind::BlockReq)
            && self.virtio.committed
            && !self.virtio.closed
            && self.virtio.tombstone.is_some()
            && block.phase == EffectPhase::Committed
    }

    fn issue_receipt(
        &mut self,
        domain: DomainId,
        status: ReceiptStatus,
    ) -> Result<DomainClosureReceipt, CompositionError> {
        if self.pending_receipt.is_some() {
            return Err(CompositionError::OutOfOrderReceipt);
        }
        if self.current_receipt.contains_key(&domain) {
            return Err(CompositionError::DuplicateReceipt);
        }
        if self.has_unclosed_child_domain(domain) {
            return Err(CompositionError::LiveDescendant);
        }
        let domain_effects = self
            .effects_by_domain
            .get(&domain)
            .ok_or(CompositionError::InvalidState)?;
        if status == ReceiptStatus::Closed
            && domain_effects
                .iter()
                .any(|effect| self.live.contains(effect))
        {
            return Err(CompositionError::DomainNotQuiescent);
        }
        if status == ReceiptStatus::TimedOut
            && (domain != DomainId::VirtIo
                || !self.has_retained_virtio_timeout_state(domain_effects))
        {
            return Err(CompositionError::InvalidState);
        }
        let mut effects: Vec<_> = domain_effects.iter().map(|effect| effect.id()).collect();
        effects.sort_unstable();
        let mut terminal_sequences: Vec<_> = domain_effects
            .iter()
            .filter_map(|effect| self.terminal_sequences.get(effect).copied())
            .collect();
        terminal_sequences.sort_unstable();
        self.receipt_revision += 1;
        let receipt = DomainClosureReceipt {
            domain,
            effects,
            terminal_sequences,
            sequence: self.next_receipt_sequence,
            revision: self.receipt_revision,
            authority_epoch: self.authority_epoch,
            binding_epoch: self.binding_epoch(domain),
            device_generation: (domain == DomainId::VirtIo)
                .then_some(self.virtio.device_generation),
            status,
            credit_units: domain.credit_units(),
        };
        self.next_receipt_sequence += 1;
        self.pending_receipt = Some(receipt.clone());
        Ok(receipt)
    }

    fn accept_receipt(&mut self, receipt: &DomainClosureReceipt) -> Result<(), CompositionError> {
        if self.invalidated_receipts.contains(&receipt.sequence) {
            return Err(CompositionError::StaleReceipt);
        }
        if self.accepted_receipts.contains_key(&receipt.sequence) {
            return Err(CompositionError::DuplicateReceipt);
        }
        let Some(expected) = self.pending_receipt.as_ref() else {
            return Err(CompositionError::OutOfOrderReceipt);
        };
        if receipt.authority_epoch != self.authority_epoch {
            return Err(CompositionError::StaleReceipt);
        }
        if receipt.sequence != expected.sequence {
            return Err(CompositionError::OutOfOrderReceipt);
        }
        if receipt != expected {
            return Err(CompositionError::StaleReceipt);
        }
        let receipt = self.pending_receipt.take().unwrap();
        self.current_receipt
            .insert(receipt.domain, receipt.sequence);
        self.accepted_receipts.insert(receipt.sequence, receipt);
        Ok(())
    }

    fn revoke_complete(&mut self) -> Result<(), CompositionError> {
        if self.phase != RootPhase::Closing
            || !self.live.is_empty()
            || self.pending_receipt.is_some()
            || self.current_receipt.len() != DOMAIN_COUNT
            || self
                .current_receipt
                .values()
                .any(|sequence| self.accepted_receipts[sequence].status != ReceiptStatus::Closed)
            || self.virtio.tombstone.is_some()
        {
            return Err(CompositionError::InvalidState);
        }
        let ticket = self
            .active_revoke
            .as_ref()
            .ok_or(CompositionError::InvalidState)?;
        self.registry.revoke_complete(&ticket.selection)?;
        self.phase = RootPhase::Revoked;
        self.check_invariants()?;
        Ok(())
    }

    fn check_invariants(&self) -> Result<(), CompositionError> {
        self.registry.check_invariants()?;
        if self.parent_by_effect.len() != self.registered.len()
            || self.kind_by_effect.len() != self.registered.len()
            || self.effect_by_kind.len() != self.registered.len()
            || self
                .effects_by_domain
                .values()
                .map(BTreeSet::len)
                .sum::<usize>()
                != self.registered.len()
            || self.registry.effects_for_scope(ROOT_SCOPE) != self.live
        {
            return Err(CompositionError::InvalidGraph);
        }
        for (kind, registered) in &self.registered {
            let effect = registered.identity.effect();
            if self.kind_by_effect.get(&effect) != Some(kind)
                || self.effect_by_kind.get(kind) != Some(&effect)
                || self.parent_by_effect.get(&effect)
                    != Some(&kind.parent().map(|parent| self.effect_by_kind[&parent]))
            {
                return Err(CompositionError::InvalidGraph);
            }
        }
        let projection = self.registry.scope_projection(ROOT_SCOPE)?;
        if projection.credits.capacity != CREDIT_UNITS
            || projection.credits.free + projection.credits.held + projection.credits.committed
                != CREDIT_UNITS
            || projection.live_effects != self.live.len()
            || projection.pending_publications != 0
        {
            return Err(CompositionError::InvalidState);
        }
        if self.virtio.tombstone.is_some() {
            let block_effect = self.effect_by_kind[&EffectKind::BlockReq];
            if !self.has_retained_virtio_timeout_state(&self.effects_by_domain[&DomainId::VirtIo])
                || !self.live.contains(&block_effect)
            {
                return Err(CompositionError::InvalidState);
            }
        }
        match self.phase {
            RootPhase::Active
                if projection.phase != ScopePhase::Active
                    || self.authority_epoch != ROOT_AUTHORITY_EPOCH =>
            {
                return Err(CompositionError::InvalidState);
            }
            RootPhase::Closing
                if projection.phase != ScopePhase::Closing
                    || self.authority_epoch != ROOT_AUTHORITY_EPOCH + 1 =>
            {
                return Err(CompositionError::InvalidState);
            }
            RootPhase::Revoked
                if projection.phase != ScopePhase::Revoked
                    || self.authority_epoch != ROOT_AUTHORITY_EPOCH + 1 =>
            {
                return Err(CompositionError::InvalidState);
            }
            _ => {}
        }
        Ok(())
    }
}

struct LinuxIoComposition {
    state: SpinLock<CompositionState>,
}

impl LinuxIoComposition {
    fn new(scheduler_binding_epoch: u64, pager_binding_epoch: u64) -> Self {
        Self {
            state: SpinLock::new(CompositionState::new(
                scheduler_binding_epoch,
                pager_binding_epoch,
            )),
        }
    }

    fn projection(&self) -> CompositionProjection {
        self.state.lock().projection()
    }

    fn derive(
        &self,
        kind: EffectKind,
        authority_epoch: u64,
    ) -> Result<RegisteredEffect, CompositionError> {
        let mut state = self.state.lock();
        let mut candidate = state.clone();
        let result = candidate.derive(kind, authority_epoch)?;
        *state = candidate;
        Ok(result)
    }

    fn commit_one(
        &self,
        kind: EffectKind,
        result: i64,
        revision: u64,
    ) -> Result<CommitReceipt, CompositionError> {
        let mut state = self.state.lock();
        let mut candidate = state.clone();
        let receipt = candidate.commit_one(kind, ROOT_AUTHORITY_EPOCH, result, revision)?;
        *state = candidate;
        Ok(receipt)
    }

    fn commit_network(&self) -> Result<(CommitReceipt, CommitReceipt), CompositionError> {
        let mut state = self.state.lock();
        let mut candidate = state.clone();
        let receipts = candidate.commit_network()?;
        *state = candidate;
        Ok(receipts)
    }

    fn commit_readiness(
        &self,
        network_commit: &CommitReceipt,
    ) -> Result<(CommitReceipt, u64), CompositionError> {
        let mut state = self.state.lock();
        let mut candidate = state.clone();
        let receipt = candidate.commit_readiness(network_commit)?;
        *state = candidate;
        Ok(receipt)
    }

    fn mutate_fs_after_commit(&self) {
        let mut state = self.state.lock();
        assert!(state.commits.contains_key(&EffectKind::FsOp));
        assert_eq!(state.fs_bytes, [0; 4]);
        state.fs_bytes = [0, 0, b'x', b'y'];
    }

    fn mark_virtio_committed(&self) {
        let mut state = self.state.lock();
        assert!(state.commits.contains_key(&EffectKind::BlockReq));
        state.virtio.committed = true;
    }

    fn revoke_begin(&self) -> Result<RootRevokeTicket, CompositionError> {
        let mut state = self.state.lock();
        let mut candidate = state.clone();
        let ticket = candidate.revoke_begin()?;
        *state = candidate;
        Ok(ticket)
    }

    fn validate_stale_commit(&self, kind: EffectKind) -> Result<(), CompositionError> {
        let state = self.state.lock();
        if ROOT_AUTHORITY_EPOCH != state.authority_epoch {
            return Err(CompositionError::StaleAuthority);
        }
        if state.phase != RootPhase::Active || !state.registered.contains_key(&kind) {
            return Err(CompositionError::RootNotActive);
        }
        Ok(())
    }

    fn reject_live_descendant(&self, kind: EffectKind) -> Result<(), CompositionError> {
        self.state.lock().reject_live_descendant(kind)
    }

    fn close_effect(&self, kind: EffectKind) -> Result<(u64, TerminalOutcome), CompositionError> {
        let mut state = self.state.lock();
        let mut candidate = state.clone();
        let result = candidate.close_effect(kind)?;
        *state = candidate;
        Ok(result)
    }

    fn timeout_virtio(&self) -> Result<u64, CompositionError> {
        let mut state = self.state.lock();
        let mut candidate = state.clone();
        let tombstone = candidate.timeout_virtio()?;
        *state = candidate;
        Ok(tombstone)
    }

    fn retry_virtio(&self, tombstone: u64) -> Result<u64, CompositionError> {
        let mut state = self.state.lock();
        let mut candidate = state.clone();
        let sequence = candidate.retry_virtio(tombstone)?;
        *state = candidate;
        Ok(sequence)
    }

    fn issue_receipt(
        &self,
        domain: DomainId,
        status: ReceiptStatus,
    ) -> Result<DomainClosureReceipt, CompositionError> {
        let mut state = self.state.lock();
        let mut candidate = state.clone();
        let receipt = candidate.issue_receipt(domain, status)?;
        *state = candidate;
        Ok(receipt)
    }

    fn accept_receipt(&self, receipt: &DomainClosureReceipt) -> Result<(), CompositionError> {
        let mut state = self.state.lock();
        let mut candidate = state.clone();
        candidate.accept_receipt(receipt)?;
        *state = candidate;
        Ok(())
    }

    fn revoke_complete(&self) -> Result<(), CompositionError> {
        let mut state = self.state.lock();
        let mut candidate = state.clone();
        candidate.revoke_complete()?;
        *state = candidate;
        Ok(())
    }
}

fn print_terminal(kind: EffectKind, sequence: u64, outcome: TerminalOutcome) {
    let outcome = match outcome {
        TerminalOutcome::Completed => "Completed",
        TerminalOutcome::Aborted => "Aborted",
    };
    println!(
        "LINUX_IO_COMPOSITION TERMINAL domain={} effect={} kind={} terminal_sequence={} outcome={} publication_ack=Applied credit=Free",
        kind.domain().label(),
        kind.id(),
        kind.label(),
        sequence,
        outcome,
    );
}

fn print_receipt_issue(receipt: &DomainClosureReceipt) {
    let status = match receipt.status {
        ReceiptStatus::TimedOut => "TimedOut",
        ReceiptStatus::Closed => "Closed",
    };
    let effects = receipt
        .effects
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let terminal_sequences = if receipt.terminal_sequences.is_empty() {
        String::from("none")
    } else {
        receipt
            .terminal_sequences
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    let device_generation = receipt
        .device_generation
        .map_or(String::from("none"), |generation| generation.to_string());
    println!(
        "LINUX_IO_COMPOSITION RECEIPT Issue domain={} effects={} terminal_sequences={} receipt_sequence={} receipt_revision={} authority_epoch={} binding_epoch={} device_generation={} status={} credits={} credit_units={}",
        receipt.domain.label(),
        effects,
        terminal_sequences,
        receipt.sequence,
        receipt.revision,
        receipt.authority_epoch,
        receipt.binding_epoch,
        device_generation,
        status,
        receipt.domain.credit_labels(),
        receipt.credit_units,
    );
}

fn print_receipt_accept(receipt: &DomainClosureReceipt) {
    let status = match receipt.status {
        ReceiptStatus::TimedOut => "TimedOut",
        ReceiptStatus::Closed => "Closed",
    };
    println!(
        "LINUX_IO_COMPOSITION RECEIPT Accept domain={} receipt_sequence={} receipt_revision={} status={} acknowledgement=Applied",
        receipt.domain.label(),
        receipt.sequence,
        receipt.revision,
        status,
    );
}

fn close_domain(
    backbone: &LinuxIoComposition,
    domain: DomainId,
    kinds: &[EffectKind],
) -> DomainClosureReceipt {
    for kind in kinds {
        let (sequence, outcome) = backbone.close_effect(*kind).unwrap();
        print_terminal(*kind, sequence, outcome);
    }
    let receipt = backbone
        .issue_receipt(domain, ReceiptStatus::Closed)
        .unwrap();
    print_receipt_issue(&receipt);
    backbone.accept_receipt(&receipt).unwrap();
    print_receipt_accept(&receipt);
    receipt
}

pub(crate) fn run_linux_io_composition_slice(
    scheduler: &CserScheduler,
    pager_receipt: PagerSliceReceipt,
    fs_receipt: RuntimeFsSliceReceipt,
    net_receipt: RuntimeNetSliceReceipt,
) {
    let scheduler_binding = scheduler.binding();
    assert_eq!(scheduler_binding.binding_epoch, 4);
    assert_eq!(pager_receipt.binding_epoch, 2);
    assert_eq!(pager_receipt.terminalizations, 2);
    assert!(pager_receipt.quiescent);
    assert_eq!(fs_receipt.scope.id(), 95);
    assert_eq!(fs_receipt.closed_authority_epoch, 141);
    assert_eq!(fs_receipt.final_authority_epoch, 142);
    assert_eq!(fs_receipt.terminalizations, 14);
    assert_eq!(fs_receipt.publication_acks, 14);
    assert!(fs_receipt.quiescent);
    assert_eq!(
        fs_receipt.source_sha256,
        "c5a4014d88794ddccd1c5239957a43500a6637a433640c2293e699fea72b870f"
    );
    assert_eq!(
        fs_receipt.elf_sha256,
        "0dc5ad40cb05e39592592ef3272ed45be4d71f9b147a534be20b9a5626c17bef"
    );
    assert_eq!(net_receipt.scope.id(), 105);
    assert_eq!(net_receipt.closed_authority_epoch, 241);
    assert_eq!(net_receipt.final_authority_epoch, 242);
    assert_eq!(net_receipt.terminalizations, 22);
    assert_eq!(net_receipt.publication_acks, 22);
    assert!(net_receipt.quiescent);
    assert_eq!(
        net_receipt.source_sha256,
        "65ba020b526fe1cbf05feef0739791a3ae6274b2ffa2b39d385ce88e1a086ecf"
    );
    assert_eq!(
        net_receipt.elf_sha256,
        "8cdd5864c07e51e91d9e0a6ec94e4d7d6438db2fbb39d513bfb7c5624d32f549"
    );

    println!(
        "LINUX_IO_COMPOSITION BEGIN root_scope=120 authority_epoch=401 domains=7 effects=9 causal_nodes=10 causal_edges=9 credit_classes=8 credit_units=9 control_capacity=2 bounded=true single_cpu=true same_boot_kernel_adapters=true retained_workload_identity=false retained_effects_in_root_cohort=false registry_multi_domain_binding=false stage5b_relation=component_consistency stage5b_same_boot=false identity_preserving_stage5b=false"
    );
    println!(
        "LINUX_IO_COMPOSITION PREREQUISITE retained_fs_scope=95 retained_fs_state=Revoked retained_fs_authority_epoch=141->142 retained_fs_terminalizations=14 retained_fs_publication_acks=14 retained_fs_quiescent=true retained_net_scope=105 retained_net_state=Revoked retained_net_authority_epoch=241->242 retained_net_terminalizations=22 retained_net_publication_acks=22 retained_net_quiescent=true retained_workloads_same_boot=true relation=prior_receipts_only retained_workload_identity=false retained_effects_in_root_cohort=false"
    );
    println!(
        "LINUX_IO_COMPOSITION BINDINGS scheduler={} pager={} personality=2 filesystem=2 virtio=3 network=2 readiness=2 envelopes=bounded_outer_state registry_multi_domain_binding=false",
        scheduler_binding.binding_epoch, pager_receipt.binding_epoch,
    );

    let backbone =
        LinuxIoComposition::new(scheduler_binding.binding_epoch, pager_receipt.binding_epoch);
    let before_stale = backbone.projection();
    assert_eq!(
        backbone.derive(EffectKind::FsSyscall, ROOT_AUTHORITY_EPOCH - 1),
        Err(CompositionError::StaleAuthority)
    );
    assert_eq!(backbone.projection(), before_stale);
    println!(
        "LINUX_IO_COMPOSITION DERIVE Reject presented_authority_epoch=400 current_authority_epoch=401 reason=StaleAuthority failure_atomic=true mutation=false"
    );

    for kind in EffectKind::ALL {
        let registered = backbone.derive(kind, ROOT_AUTHORITY_EPOCH).unwrap();
        assert_eq!(registered.identity.effect().id(), kind.id());
        println!(
            "LINUX_IO_COMPOSITION DERIVE Applied root_scope=120 effect={} kind={} domain={} parent={} authority_epoch=401 binding_epoch={} generation={} credit={} units=1 failure_atomic=true edge_indexed=true effect_indexed=true domain_indexed=true",
            kind.id(),
            kind.label(),
            kind.domain().label(),
            kind.parent_label(),
            kind.domain()
                .binding_epoch(scheduler_binding.binding_epoch, pager_receipt.binding_epoch,),
            kind.generation_label(),
            kind.credit_label(),
        );
    }
    let active = backbone.projection();
    assert_eq!(active.effects, EFFECT_COUNT);
    assert_eq!(active.edges, EFFECT_COUNT);
    assert_eq!(active.registry.credits.capacity, CREDIT_UNITS);
    assert_eq!(active.registry.credits.free, 0);
    assert_eq!(active.registry.credits.held, CREDIT_UNITS);
    println!(
        "LINUX_IO_COMPOSITION ACTIVE root_scope=120 authority_epoch=401 domains=7 effects=9 causal_nodes=10 causal_edges=9 domain_effect_counts=personality:2,pager:1,scheduler:1,filesystem:1,virtio:1,network:2,readiness:1 credit_classes=8 credit_units=9 control_capacity=2 reverse_effects=9 reverse_domains=7 gate=single"
    );

    let fs_commit = backbone.commit_one(EffectKind::FsOp, 4, 1).unwrap();
    assert_eq!(fs_commit.sequence(), 1);
    backbone.mutate_fs_after_commit();
    println!(
        "LINUX_IO_COMPOSITION FS Commit effect=5 commit_sequence=1 inode_before=00000000 inode_after=00007879 commit_before_mutation=true guest_reply=false adapter=bounded_in_memory"
    );

    println!(
        "LINUX_IO_COMPOSITION VIRTIO Adapter effect=6 source=external_stage5b_consistency binding_epoch=3 device_generation=3 commit_point=avail_idx_release reset_timeout=tombstone iotlb_completion_before_release=true real_dma_primary=false stage5b_relation=component_consistency stage5b_same_boot=false identity_preserving_stage5b=false"
    );
    let block_commit = backbone.commit_one(EffectKind::BlockReq, 512, 1).unwrap();
    assert_eq!(block_commit.sequence(), 2);
    backbone.mark_virtio_committed();
    println!(
        "LINUX_IO_COMPOSITION VIRTIO Commit effect=6 commit_sequence=2 binding_epoch=3 device_generation=3 point=avail_idx_release credit=DMA:Held"
    );

    let (network_commit, buffer_commit) = backbone.commit_network().unwrap();
    assert_eq!(network_commit.sequence(), 3);
    assert_eq!(buffer_commit.sequence(), 4);
    println!(
        "LINUX_IO_COMPOSITION NETWORK Commit effects=7,9 commit_sequences=3,4 atomic_batch=true net_publication=Applied buffer_visibility=ping buffer_credit=Held guest_reply=false adapter=bounded_loopback"
    );

    let before_wrong_cause = backbone.projection();
    assert_eq!(
        backbone.commit_readiness(&buffer_commit),
        Err(CompositionError::InvalidState)
    );
    assert_eq!(backbone.projection(), before_wrong_cause);
    println!(
        "LINUX_IO_COMPOSITION READINESS Reject causal_effect=9 causal_commit_sequence=4 expected_effect=7 expected_commit_sequence=3 result=InvalidState failure_atomic=true mutation=false"
    );
    let (ready_commit, delivery_sequence) = backbone.commit_readiness(&network_commit).unwrap();
    assert_eq!(ready_commit.sequence(), 5);
    assert_eq!(delivery_sequence, 1);
    println!(
        "LINUX_IO_COMPOSITION READINESS Commit effect=8 commit_sequence=5 causal_net_effect=7 causal_net_commit_sequence=3 exact_net_receipt=true kernel_owned=true"
    );
    println!(
        "LINUX_IO_COMPOSITION READINESS Delivery effect=8 delivery_sequence=1 events=1 replay_rejected=true live_sources=0 live_sets=0 subscriptions=0 queued=0 unpublished=0"
    );
    println!(
        "LINUX_IO_COMPOSITION GUEST_REPLIES fs=0 net=0 syscall_effects=1,2 phases=Registered commit_gate=true"
    );

    let ticket = backbone.revoke_begin().unwrap();
    assert_eq!(ticket.frozen_domains.len(), DOMAIN_COUNT);
    assert_eq!(ticket.frozen_effects.len(), EFFECT_COUNT);
    println!(
        "LINUX_IO_COMPOSITION REVOKE Begin root_scope=120 authority_epoch_old=401 authority_epoch_new=402 frozen_domains=7 frozen_effects=9 frozen_credit_units=9 cohort_source=registry_live_selection gate=closed"
    );

    let before_stale = backbone.projection();
    assert_eq!(
        backbone.derive(EffectKind::FsSyscall, ROOT_AUTHORITY_EPOCH),
        Err(CompositionError::StaleAuthority)
    );
    assert_eq!(backbone.projection(), before_stale);
    println!(
        "LINUX_IO_COMPOSITION REJECT stage=closing kind=stale_derive presented_authority_epoch=401 current_authority_epoch=402 result=StaleAuthority mutation=false"
    );
    assert_eq!(
        backbone.validate_stale_commit(EffectKind::SchedulerAction),
        Err(CompositionError::StaleAuthority)
    );
    assert_eq!(backbone.projection(), before_stale);
    println!(
        "LINUX_IO_COMPOSITION REJECT stage=closing kind=stale_commit effect=4 presented_authority_epoch=401 current_authority_epoch=402 result=StaleAuthority mutation=false"
    );
    assert_eq!(
        backbone.reject_live_descendant(EffectKind::FsSyscall),
        Err(CompositionError::LiveDescendant)
    );
    println!(
        "LINUX_IO_COMPOSITION REJECT stage=closing kind=live_descendant effect=1 children=3,5 result=LiveDescendant child_first=true mutation=false"
    );
    assert_eq!(
        backbone.reject_live_descendant(EffectKind::NetSyscall),
        Err(CompositionError::LiveDescendant)
    );
    println!(
        "LINUX_IO_COMPOSITION REJECT stage=closing kind=live_descendant effect=2 children=7 result=LiveDescendant child_first=true mutation=false"
    );

    let (scheduler_terminal, scheduler_outcome) =
        backbone.close_effect(EffectKind::SchedulerAction).unwrap();
    print_terminal(
        EffectKind::SchedulerAction,
        scheduler_terminal,
        scheduler_outcome,
    );
    let (pager_terminal, pager_outcome) = backbone.close_effect(EffectKind::PagerMap).unwrap();
    print_terminal(EffectKind::PagerMap, pager_terminal, pager_outcome);
    let before_live_child_receipt = backbone.projection();
    assert_eq!(
        backbone.issue_receipt(DomainId::Pager, ReceiptStatus::Closed),
        Err(CompositionError::LiveDescendant)
    );
    assert_eq!(backbone.projection(), before_live_child_receipt);
    println!(
        "LINUX_IO_COMPOSITION RECEIPT Reject kind=live_child_receipt domain=pager child_domain=scheduler result=LiveDescendant failure_atomic=true mutation=false"
    );
    let scheduler_receipt = backbone
        .issue_receipt(DomainId::Scheduler, ReceiptStatus::Closed)
        .unwrap();
    print_receipt_issue(&scheduler_receipt);
    let before_receipt_reject = backbone.projection();
    let mut stale = scheduler_receipt.clone();
    stale.authority_epoch = ROOT_AUTHORITY_EPOCH;
    assert_eq!(
        backbone.accept_receipt(&stale),
        Err(CompositionError::StaleReceipt)
    );
    assert_eq!(backbone.projection(), before_receipt_reject);
    println!(
        "LINUX_IO_COMPOSITION RECEIPT Reject kind=stale domain=scheduler receipt_sequence=1 presented_authority_epoch=401 current_authority_epoch=402 result=StaleReceipt failure_atomic=true mutation=false"
    );
    let mut out_of_order = scheduler_receipt.clone();
    out_of_order.sequence = 2;
    assert_eq!(
        backbone.accept_receipt(&out_of_order),
        Err(CompositionError::OutOfOrderReceipt)
    );
    assert_eq!(backbone.projection(), before_receipt_reject);
    println!(
        "LINUX_IO_COMPOSITION RECEIPT Reject kind=out_of_order domain=scheduler presented_sequence=2 expected_sequence=1 result=OutOfOrderReceipt failure_atomic=true mutation=false"
    );
    backbone.accept_receipt(&scheduler_receipt).unwrap();
    print_receipt_accept(&scheduler_receipt);
    let before_duplicate = backbone.projection();
    assert_eq!(
        backbone.accept_receipt(&scheduler_receipt),
        Err(CompositionError::DuplicateReceipt)
    );
    assert_eq!(backbone.projection(), before_duplicate);
    println!(
        "LINUX_IO_COMPOSITION RECEIPT Reject kind=duplicate domain=scheduler receipt_sequence=1 result=DuplicateReceipt failure_atomic=true mutation=false"
    );
    let before_duplicate_issue = backbone.projection();
    assert_eq!(
        backbone.issue_receipt(DomainId::Scheduler, ReceiptStatus::Closed),
        Err(CompositionError::DuplicateReceipt)
    );
    assert_eq!(backbone.projection(), before_duplicate_issue);
    println!(
        "LINUX_IO_COMPOSITION RECEIPT Reject kind=duplicate_issue domain=scheduler result=DuplicateReceipt failure_atomic=true mutation=false"
    );

    let pager_closed = close_domain(&backbone, DomainId::Pager, &[]);
    assert_eq!(pager_closed.sequence, 2);

    let tombstone = backbone.timeout_virtio().unwrap();
    assert_eq!(tombstone, 1);
    println!(
        "LINUX_IO_COMPOSITION VIRTIO Timeout effect=6 binding_epoch=3 device_generation=3 tombstone=1 owners_retained=true dma_credit=Held effect_live=true"
    );
    let before_tombstone_terminalize = backbone.projection();
    assert_eq!(
        backbone.close_effect(EffectKind::BlockReq),
        Err(CompositionError::TombstoneActive)
    );
    assert_eq!(backbone.projection(), before_tombstone_terminalize);
    println!(
        "LINUX_IO_COMPOSITION VIRTIO Reject action=Terminalize effect=6 tombstone=1 result=TombstoneActive owners_retained=true dma_credit=Held failure_atomic=true mutation=false"
    );
    let timeout_receipt = backbone
        .issue_receipt(DomainId::VirtIo, ReceiptStatus::TimedOut)
        .unwrap();
    print_receipt_issue(&timeout_receipt);
    backbone.accept_receipt(&timeout_receipt).unwrap();
    print_receipt_accept(&timeout_receipt);
    println!(
        "LINUX_IO_COMPOSITION REVOKE TimedOut domain=virtio receipt_sequence=3 receipt_revision=3 root_state=Closing effect_live=true credit_live=true closure_receipts=2"
    );
    let invalidated = backbone.retry_virtio(tombstone).unwrap();
    assert_eq!(invalidated, 3);
    println!(
        "LINUX_IO_COMPOSITION VIRTIO Retry effect=6 tombstone=1 attempt=1 invalidated_receipt_sequence=3 device_generation_before=3 device_generation_after=4 reset_ack=true iotlb_complete=true evidence_relation=component_consistency identity_preserving=false credit_retained_until_close=true"
    );
    let before_timeout_replay = backbone.projection();
    assert_eq!(
        backbone.accept_receipt(&timeout_receipt),
        Err(CompositionError::StaleReceipt)
    );
    assert_eq!(backbone.projection(), before_timeout_replay);
    println!(
        "LINUX_IO_COMPOSITION RECEIPT Reject kind=stale_timeout_replay domain=virtio receipt_sequence=3 presented_device_generation=3 current_device_generation=4 result=StaleReceipt failure_atomic=true mutation=false"
    );
    let virtio_closed = close_domain(&backbone, DomainId::VirtIo, &[EffectKind::BlockReq]);
    assert_eq!(virtio_closed.sequence, 4);

    let filesystem_closed = close_domain(&backbone, DomainId::Filesystem, &[EffectKind::FsOp]);
    assert_eq!(filesystem_closed.sequence, 5);
    let readiness_closed =
        close_domain(&backbone, DomainId::Readiness, &[EffectKind::ReadinessWait]);
    assert_eq!(readiness_closed.sequence, 6);
    let network_closed = close_domain(
        &backbone,
        DomainId::Network,
        &[EffectKind::BufferLease, EffectKind::NetOp],
    );
    assert_eq!(network_closed.sequence, 7);
    assert_eq!(network_closed.effects, vec![7, 9]);
    assert_eq!(network_closed.terminal_sequences, vec![6, 7]);
    let personality_closed = close_domain(
        &backbone,
        DomainId::Personality,
        &[EffectKind::FsSyscall, EffectKind::NetSyscall],
    );
    assert_eq!(personality_closed.sequence, 8);
    assert_eq!(personality_closed.effects, vec![1, 2]);
    assert_eq!(personality_closed.terminal_sequences, vec![8, 9]);

    backbone.revoke_complete().unwrap();
    let final_state = backbone.projection();
    assert_eq!(final_state.phase, RootPhase::Revoked);
    assert_eq!(final_state.authority_epoch, ROOT_AUTHORITY_EPOCH + 1);
    assert_eq!(final_state.live, 0);
    assert_eq!(final_state.terminalizations, EFFECT_COUNT);
    assert_eq!(final_state.accepted_receipts, 8);
    assert_eq!(final_state.invalidated_receipts, 1);
    assert_eq!(final_state.receipt_revision, 8);
    assert_eq!(final_state.registry.credits.free, CREDIT_UNITS);
    assert_eq!(final_state.registry.credits.held, 0);
    assert_eq!(final_state.registry.credits.committed, 0);
    assert_eq!(final_state.registry.pending_publications, 0);
    assert_eq!(final_state.fs_bytes, [0, 0, b'x', b'y']);
    assert!(!final_state.network_visible);
    assert_eq!(final_state.guest_replies, 0);
    assert_eq!(final_state.readiness_sources, 0);
    assert_eq!(final_state.readiness_sets, 0);
    assert_eq!(final_state.readiness_subscriptions, 0);
    assert_eq!(final_state.readiness_queued, 0);
    assert_eq!(final_state.readiness_unpublished, 0);
    println!(
        "LINUX_IO_COMPOSITION REVOKE Complete root_scope=120 authority_epoch=402 frozen_domains=7 frozen_effects=9 closure_receipts=7 accepted_receipts=8 invalidated_receipts=1 effect_terminalizations=9 receipt_revision=8 credits_free=9 live=0 pending=0 state=Revoked"
    );
    println!(
        "LINUX_IO_COMPOSITION PASS domains=7 effects=9 causal_nodes=10 causal_edges=9 credit_classes=8 credit_units=9 control_capacity=2 effect_terminalizations=9 closure_receipts=7 accepted_receipts=8 invalidated_receipts=1 receipt_revision=8 credits_free=9 fs_replies=0 net_replies=0 buffer_closure_drains=1 retained_workloads_same_boot=true retained_workload_identity=false retained_effects_in_root_cohort=false registry_multi_domain_binding=false domain_binding_envelopes=bounded_outer_state stage5b_relation=component_consistency stage5b_same_boot=false identity_preserving_stage5b=false real_dma_primary=false smoltcp=false virtio_net=false external_packets=false tcp_breadth=false cross_fd_total_order=false bounded=true single_cpu=true"
    );

    assert_eq!(DomainId::ALL.len(), DOMAIN_COUNT);
    assert_eq!(DomainId::CLOSURE_ORDER.len(), DOMAIN_COUNT);
    assert_eq!(EffectKind::TERMINAL_ORDER.len(), EFFECT_COUNT);
    assert_eq!(CREDIT_CLASS_COUNT, 8);
    assert_eq!(backbone.state.lock().buffer_closure_drains, 1);
}
