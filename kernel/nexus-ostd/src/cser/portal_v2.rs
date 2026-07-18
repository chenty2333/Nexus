// SPDX-License-Identifier: MPL-2.0

//! Kernel adapter from `nexus.portal.v2` to the authoritative effect Registry.
//!
//! The wire handles retained here are session-local selectors.  They never
//! replace [`PortalHandle`]: every mutation resolves its selector and presents
//! the original opaque Registry handle plus the session owner [`TaskKey`] to
//! [`EffectRegistry`].  The adapter retains only bounded routing metadata,
//! request/receipt digests, and quota policy.  Effect phase, outcome, terminal
//! winner, scope epochs, credit ownership, and closure remain Registry state.
//!
//! This first adapter tranche supports finite root scopes and non-device effect
//! closure.  Child scopes, publication acknowledgements, retained-device
//! ownership, persistent recovery, and a user/kernel transport are deliberately
//! not advertised as completed by this module.

use nexus_portal_abi::{
    CapabilityOffer, ClosureReceipt, ClosureStatus, CommitEffectRequest, CompleteEffectRequest,
    CompletionDisposition, CreateScopeFlags, CreateScopeRequest, CreditKind, Digest, EffectHandle,
    EffectObservation, EffectOutcomeObservation, EffectPhase as AbiEffectPhase, LifecycleFlags,
    LifecycleReceipt, MutationContext, OutcomeKind, PortalBackend, PortalCapabilities,
    PortalErrorCode, PortalFailure, PortalLimits, PortalWireError, PrepareEffectRequest,
    ProviderCapabilities, QueryEffectRequest, QueryReceiptRequest, QueryScopeRequest,
    ReceiptHandle, ReceiptKind, ReceiptObservation, ReceiptStatus, RecordOutcomeRequest,
    RegisterEffectRequest, RegisterFlags, RetryClass, RevokeReason, RevokeScopeRequest,
    ScopeCreatedResponse, ScopeHandle, ScopeObservation, ScopePhase as AbiScopePhase,
    SessionHandle,
};

#[cfg(test)]
use nexus_portal_abi::{
    AbiResponse, CapabilityRequest, ErrorResponse, HeaderFlags, MAX_MESSAGE_SIZE, MessageHeader,
    MessageKind, NegotiateRequest, NegotiatedResponse, PortalDispatcher, QueryAbiRequest,
    RequestBody, ResponseBody, decode_message, encode_message,
};

use super::effect_registry::{
    CommitMetadata, CommitOutcome, CreditCharge, CreditClass, CreditLimit, EffectKey,
    EffectOutcomeClass, EffectOutcomeRecord, EffectPhase, EffectRegistry, EffectView,
    OperationClass, PortalHandle, PublicationMode, RegisterRequest, RegistryError,
    RegistryProjection, ScopeConfig, ScopeKey, ScopePhase, SyscallDescriptor, TaskKey,
    TerminalOutcome, TerminalRequest,
};

const PORTAL_QUEUE_CREDIT_CLASS: CreditClass = CreditClass::new(0x7001);
const PORTAL_PAGE_CREDIT_CLASS: CreditClass = CreditClass::new(0x7002);
const SELECTOR_SCOPE: u64 = 0x5343_4f50_455f_5632;
const SELECTOR_EFFECT: u64 = 0x4546_4645_4354_5632;
const SELECTOR_RECEIPT: u64 = 0x5243_5054_5f56_3201;
const SELECTOR_SCOPE_KEY: u64 = 0x5343_4f50_454b_4559;
const SELECTOR_AUTHORITY: u64 = 0x4155_5448_5f56_3201;
const DIGEST_RECEIPT: u64 = 0x5245_4345_4950_5432;
const DIGEST_SCOPE_STATE: u64 = 0x5343_4f50_4553_5432;
const DIGEST_EFFECT_STATE: u64 = 0x4546_4645_4353_5432;
const DIGEST_CLOSURE: u64 = 0x434c_4f53_5552_4532;

/// Capabilities implemented by the current Registry-backed adapter tranche.
pub(crate) const PORTAL_V2_KERNEL_OFFER: CapabilityOffer = CapabilityOffer {
    portal: PortalCapabilities::QUERY_ABI
        .union(PortalCapabilities::NEGOTIATE)
        .union(PortalCapabilities::CREATE_SCOPE)
        .union(PortalCapabilities::QUERY_SCOPE)
        .union(PortalCapabilities::QUERY_EFFECT)
        .union(PortalCapabilities::QUERY_RECEIPT)
        .union(PortalCapabilities::EFFECT_LIFECYCLE)
        .union(PortalCapabilities::REVOKE_SCOPE),
    provider: ProviderCapabilities::EFFECT_CLOSURE
        .union(ProviderCapabilities::OUTCOME_RECORDING)
        .union(ProviderCapabilities::EFFECT_COMPLETION)
        .union(ProviderCapabilities::SESSION_QUERY),
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegisterSpec {
    parent: EffectHandle,
    operation_class: u32,
    flags: RegisterFlags,
    credit_kind: CreditKind,
    credit_units: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OutcomeSpec {
    kind: OutcomeKind,
    result: i64,
    digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompletionSpec {
    disposition: CompletionDisposition,
    terminal_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StageRecord {
    request_digest: Digest,
    receipt: ReceiptHandle,
    sequence: u64,
    receipt_digest: Digest,
    kind: ReceiptKind,
    phase: AbiEffectPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RevokeRecord {
    request_digest: Digest,
    reason: RevokeReason,
    authority_epoch: u64,
    binding_epoch: u64,
    receipt: ReceiptHandle,
    sequence: u64,
    receipt_digest: Digest,
    closure_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScopeSlot {
    selector: ScopeHandle,
    key: ScopeKey,
    creation_authority_epoch: u64,
    creation_binding_epoch: u64,
    create_digest: Digest,
    flags: CreateScopeFlags,
    max_effects: u32,
    max_tombstones: u32,
    queue_credits: u32,
    page_credits: u32,
    creation: StageRecord,
    latest_receipt: ReceiptHandle,
    revoke: Option<RevokeRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectSlot {
    selector: EffectHandle,
    scope: ScopeHandle,
    key: EffectKey,
    portal: PortalHandle,
    register_spec: RegisterSpec,
    registration: StageRecord,
    prepare: Option<StageRecord>,
    commit: Option<StageRecord>,
    outcome: Option<(StageRecord, OutcomeSpec)>,
    completion: Option<(StageRecord, CompletionSpec)>,
    latest_receipt: ReceiptHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiptSubject {
    Scope(ScopeKey),
    Effect(EffectKey),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReceiptSlot {
    selector: ReceiptHandle,
    subject: ReceiptSubject,
    authority_epoch: u64,
    binding_epoch: u64,
    sequence: u64,
    kind: ReceiptKind,
    request_digest: Digest,
    receipt_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReceiptReservation {
    index: usize,
    selector: ReceiptHandle,
    sequence: u64,
    request_digest: Digest,
    receipt_digest: Digest,
    kind: ReceiptKind,
}

#[derive(Clone, Copy)]
struct ReceiptDigestContext {
    authority_epoch: u64,
    binding_epoch: u64,
    subject_selector: [u8; 16],
}

impl ReceiptReservation {
    const fn stage(self, phase: AbiEffectPhase) -> StageRecord {
        StageRecord {
            request_digest: self.request_digest,
            receipt: self.selector,
            sequence: self.sequence,
            receipt_digest: self.receipt_digest,
            kind: self.kind,
            phase,
        }
    }
}

/// Bounded session-local selector adapter over one unique Registry.
///
/// Const generic capacities make every selector table finite.  Exhaustion is
/// reported before a Registry mutation, so the dispatcher can return typed
/// backpressure without silently evicting an authority selector or receipt.
pub(crate) struct PortalV2Adapter<
    'registry,
    const SCOPE_SLOTS: usize,
    const EFFECT_SLOTS: usize,
    const RECEIPT_SLOTS: usize,
> {
    registry: &'registry mut EffectRegistry,
    session: SessionHandle,
    owner: TaskKey,
    scopes: [Option<ScopeSlot>; SCOPE_SLOTS],
    effects: [Option<EffectSlot>; EFFECT_SLOTS],
    receipts: [Option<ReceiptSlot>; RECEIPT_SLOTS],
    next_scope_sequence: u64,
    next_effect_sequence: u64,
    next_receipt_sequence: u64,
}

impl<'registry, const SCOPE_SLOTS: usize, const EFFECT_SLOTS: usize, const RECEIPT_SLOTS: usize>
    PortalV2Adapter<'registry, SCOPE_SLOTS, EFFECT_SLOTS, RECEIPT_SLOTS>
{
    pub(crate) fn new(
        registry: &'registry mut EffectRegistry,
        session: SessionHandle,
        owner: TaskKey,
    ) -> Result<Self, PortalFailure> {
        if session.is_null() {
            return Err(failure(PortalErrorCode::InvalidSession, RetryClass::Never));
        }
        if owner.generation() == 0 {
            return Err(failure(
                PortalErrorCode::GenerationMismatch,
                RetryClass::Never,
            ));
        }
        Ok(Self {
            registry,
            session,
            owner,
            scopes: core::array::from_fn(|_| None),
            effects: core::array::from_fn(|_| None),
            receipts: core::array::from_fn(|_| None),
            next_scope_sequence: 1,
            next_effect_sequence: 1,
            next_receipt_sequence: 1,
        })
    }

    pub(crate) const fn offer() -> CapabilityOffer {
        PORTAL_V2_KERNEL_OFFER
    }

    fn require_session(&self, presented: SessionHandle) -> Result<(), PortalFailure> {
        if presented == self.session {
            Ok(())
        } else {
            Err(failure(PortalErrorCode::InvalidSession, RetryClass::Never))
        }
    }

    fn scope_index(&self, selector: ScopeHandle) -> Result<usize, PortalFailure> {
        self.scopes
            .iter()
            .position(|slot| slot.is_some_and(|slot| slot.selector == selector))
            .ok_or_else(|| failure(PortalErrorCode::NotFound, RetryClass::Never))
    }

    fn effect_index(&self, selector: EffectHandle) -> Result<usize, PortalFailure> {
        self.effects
            .iter()
            .position(|slot| slot.is_some_and(|slot| slot.selector == selector))
            .ok_or_else(|| failure(PortalErrorCode::NotFound, RetryClass::Never))
    }

    fn receipt_index(&self, selector: ReceiptHandle) -> Result<usize, PortalFailure> {
        self.receipts
            .iter()
            .position(|slot| slot.is_some_and(|slot| slot.selector == selector))
            .ok_or_else(|| failure(PortalErrorCode::NotFound, RetryClass::Never))
    }

    fn scope_effect_count(&self, scope: ScopeHandle) -> usize {
        self.effects
            .iter()
            .filter(|slot| slot.is_some_and(|slot| slot.scope == scope))
            .count()
    }

    fn scope_tombstone_count(&self, scope: ScopeHandle) -> Result<usize, PortalFailure> {
        let mut count = 0_usize;
        for slot in self
            .effects
            .iter()
            .flatten()
            .copied()
            .filter(|slot| slot.scope == scope)
        {
            if self.effect_view(slot)?.phase.is_terminal() {
                count = count
                    .checked_add(1)
                    .ok_or_else(|| failure(PortalErrorCode::Backpressure, RetryClass::Never))?;
            }
        }
        Ok(count)
    }

    fn require_context(
        &self,
        context: MutationContext,
        scope: ScopeKey,
    ) -> Result<RegistryProjection, PortalFailure> {
        self.require_session(context.session())?;
        let projection = self
            .registry
            .scope_projection(scope)
            .map_err(map_registry_error)?;
        if context.authority_epoch() != projection.authority_epoch
            || context.binding_epoch() != projection.binding_epoch
        {
            return Err(
                failure(PortalErrorCode::GenerationMismatch, RetryClass::AfterQuery)
                    .with_epochs(projection.authority_epoch, projection.binding_epoch),
            );
        }
        if projection.supervisor != Some(self.owner) || projection.fallback_running {
            return Err(
                failure(PortalErrorCode::CallerMismatch, RetryClass::AfterQuery)
                    .with_epochs(projection.authority_epoch, projection.binding_epoch),
            );
        }
        Ok(projection)
    }

    fn reserve_receipt(
        &self,
        request_digest: Digest,
        kind: ReceiptKind,
        authority_epoch: u64,
        binding_epoch: u64,
        subject_selector: [u8; 16],
    ) -> Result<ReceiptReservation, PortalFailure> {
        let index = self
            .receipts
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| failure(PortalErrorCode::Backpressure, RetryClass::NewSession))?;
        let sequence = self.next_receipt_sequence;
        sequence
            .checked_add(1)
            .ok_or_else(|| failure(PortalErrorCode::Backpressure, RetryClass::NewSession))?;
        let selector =
            ReceiptHandle::from_wire_bytes(make_selector(self.session, SELECTOR_RECEIPT, sequence));
        if self
            .receipts
            .iter()
            .flatten()
            .any(|existing| existing.selector == selector)
        {
            return Err(failure(
                PortalErrorCode::Backpressure,
                RetryClass::NewSession,
            ));
        }
        let receipt_digest = make_receipt_digest(
            self.session,
            request_digest,
            selector,
            kind,
            sequence,
            ReceiptDigestContext {
                authority_epoch,
                binding_epoch,
                subject_selector,
            },
        );
        debug_assert!(!selector.is_null());
        debug_assert!(!receipt_digest.is_zero());
        Ok(ReceiptReservation {
            index,
            selector,
            sequence,
            request_digest,
            receipt_digest,
            kind,
        })
    }

    fn install_receipt(
        &mut self,
        reservation: ReceiptReservation,
        subject: ReceiptSubject,
        authority_epoch: u64,
        binding_epoch: u64,
    ) {
        debug_assert!(self.receipts[reservation.index].is_none());
        self.receipts[reservation.index] = Some(ReceiptSlot {
            selector: reservation.selector,
            subject,
            authority_epoch,
            binding_epoch,
            sequence: reservation.sequence,
            kind: reservation.kind,
            request_digest: reservation.request_digest,
            receipt_digest: reservation.receipt_digest,
        });
        self.next_receipt_sequence = reservation.sequence + 1;
    }

    fn lifecycle_receipt(
        scope: ScopeHandle,
        effect: EffectHandle,
        authority_epoch: u64,
        binding_epoch: u64,
        stage: StageRecord,
    ) -> Result<LifecycleReceipt, PortalFailure> {
        LifecycleReceipt::new(
            scope,
            effect,
            stage.receipt,
            authority_epoch,
            binding_epoch,
            stage.sequence,
            stage.phase,
            stage.kind,
            lifecycle_flags(stage.phase, false),
            stage.request_digest,
            stage.receipt_digest,
        )
        .map_err(map_wire_invariant)
    }

    fn conflict(presented: Digest, existing: Digest) -> PortalFailure {
        failure(PortalErrorCode::Conflict, RetryClass::AfterQuery).with_digests(presented, existing)
    }

    fn effect_view(&self, slot: EffectSlot) -> Result<EffectView, PortalFailure> {
        self.registry
            .effect_view(slot.key)
            .map_err(map_registry_error)
    }
}

fn failure(code: PortalErrorCode, retry: RetryClass) -> PortalFailure {
    PortalFailure::new(code, retry, 0)
}

fn map_wire_invariant(error: nexus_portal_abi::PortalWireError) -> PortalFailure {
    PortalFailure::new(
        PortalErrorCode::InternalInvariant,
        RetryClass::Never,
        u32::try_from(error.offset()).unwrap_or(u32::MAX),
    )
}

fn map_registry_error(error: RegistryError) -> PortalFailure {
    let (code, retry) = match error {
        RegistryError::InvalidGeneration
        | RegistryError::StaleDeviceGeneration
        | RegistryError::InvalidDeviceEnvelope => {
            (PortalErrorCode::GenerationMismatch, RetryClass::AfterQuery)
        }
        RegistryError::InvalidCreditConfiguration => {
            (PortalErrorCode::LimitExceeded, RetryClass::Never)
        }
        RegistryError::ScopeAlreadyExists
        | RegistryError::DomainAlreadyExists
        | RegistryError::CommitConflict
        | RegistryError::InvalidBatchReceipt
        | RegistryError::InvalidHandoffReceipt => {
            (PortalErrorCode::Conflict, RetryClass::AfterQuery)
        }
        RegistryError::UnknownScope
        | RegistryError::UnknownDomain
        | RegistryError::UnknownEffect
        | RegistryError::UnknownCreditClass => (PortalErrorCode::NotFound, RetryClass::Never),
        RegistryError::CreditExhausted => (PortalErrorCode::NoCredit, RetryClass::AfterCapacity),
        RegistryError::CounterOverflow => (PortalErrorCode::Backpressure, RetryClass::Never),
        RegistryError::StaleAuthority | RegistryError::StaleBinding => {
            (PortalErrorCode::StaleHandle, RetryClass::AfterQuery)
        }
        RegistryError::NoSupervisor => (PortalErrorCode::CallerMismatch, RetryClass::AfterQuery),
        RegistryError::InvalidHandle => (PortalErrorCode::InvalidHandle, RetryClass::Never),
        RegistryError::AlreadyTerminal => {
            (PortalErrorCode::ReceiptConsumed, RetryClass::AfterQuery)
        }
        RegistryError::ScopeNotActive
        | RegistryError::ScopeNotClosing
        | RegistryError::InvalidState
        | RegistryError::SnapshotChanged
        | RegistryError::RecoveryNotReady
        | RegistryError::NotAdoptable
        | RegistryError::LiveDescendants
        | RegistryError::DeviceBatchNotEnrolled
        | RegistryError::DeviceClosurePending
        | RegistryError::InvalidRevokeSelection
        | RegistryError::InvalidPublication
        | RegistryError::PublicationPending
        | RegistryError::NotQuiescent
        | RegistryError::HandoffAdmissionFrozen
        | RegistryError::HandoffNotReady
        | RegistryError::HandoffDevicePrecommitPending => {
            (PortalErrorCode::OutOfOrder, RetryClass::AfterQuery)
        }
        RegistryError::Invariant(_) => (PortalErrorCode::InternalInvariant, RetryClass::Never),
    };
    failure(code, retry)
}

fn lifecycle_flags(phase: AbiEffectPhase, publication_pending: bool) -> LifecycleFlags {
    let mut flags = LifecycleFlags::empty();
    if publication_pending {
        flags |= LifecycleFlags::PUBLICATION_PENDING;
    }
    if phase.is_terminal() {
        flags |= LifecycleFlags::TERMINAL;
    }
    if phase == AbiEffectPhase::Retained {
        flags |= LifecycleFlags::RETAINED;
    }
    flags
}

fn map_scope_phase(phase: ScopePhase) -> AbiScopePhase {
    match phase {
        ScopePhase::Active => AbiScopePhase::Active,
        ScopePhase::Closing => AbiScopePhase::Closing,
        ScopePhase::Revoked => AbiScopePhase::Revoked,
    }
}

fn map_outcome_class(class: EffectOutcomeClass) -> OutcomeKind {
    match class {
        EffectOutcomeClass::Data => OutcomeKind::Data,
        EffectOutcomeClass::Error => OutcomeKind::Error,
        EffectOutcomeClass::Indeterminate => OutcomeKind::Indeterminate,
    }
}

fn registry_outcome_class(kind: OutcomeKind) -> EffectOutcomeClass {
    match kind {
        OutcomeKind::Data => EffectOutcomeClass::Data,
        OutcomeKind::Error => EffectOutcomeClass::Error,
        OutcomeKind::Indeterminate => EffectOutcomeClass::Indeterminate,
    }
}

fn project_effect_phase(view: &EffectView) -> AbiEffectPhase {
    match view.phase {
        EffectPhase::Registered => AbiEffectPhase::Registered,
        EffectPhase::Prepared => AbiEffectPhase::Prepared,
        EffectPhase::Committed if view.outcome.is_some() => AbiEffectPhase::OutcomeRecorded,
        EffectPhase::Committed => AbiEffectPhase::Committed,
        EffectPhase::Terminal(TerminalOutcome::Completed) => AbiEffectPhase::Completed,
        EffectPhase::Terminal(TerminalOutcome::Aborted) => AbiEffectPhase::Aborted,
        EffectPhase::Terminal(TerminalOutcome::IndeterminateAfterReset) => AbiEffectPhase::Retained,
    }
}

fn wire_revision(registry_revision: u64) -> Result<u64, PortalFailure> {
    registry_revision
        .checked_add(1)
        .ok_or_else(|| failure(PortalErrorCode::Backpressure, RetryClass::Never))
}

fn descriptor_for(request: RegisterEffectRequest) -> SyscallDescriptor {
    let bytes = request.context().request_digest().to_wire_bytes();
    let mut words = [0_usize; 4];
    for (index, chunk) in bytes.chunks_exact(8).enumerate() {
        words[index] = u64::from_le_bytes(chunk.try_into().unwrap()) as usize;
    }
    SyscallDescriptor::new(
        request.operation_class() as usize,
        [
            words[0],
            words[1],
            words[2],
            words[3],
            (u64::from(request.flags().bits())
                | (u64::from(request.credit_kind().wire_value()) << 32)) as usize,
            request.credit_units() as usize,
        ],
    )
}

#[derive(Clone, Copy)]
struct DigestMixer {
    lanes: [u64; 4],
}

impl DigestMixer {
    fn new(domain: u64) -> Self {
        let mut mixer = Self {
            lanes: [
                0xcbf2_9ce4_8422_2325,
                0x8422_2325_cbf2_9ce4,
                0x9e37_79b9_7f4a_7c15,
                0xd6e8_feb8_6659_fd93,
            ],
        };
        mixer.update_u64(domain);
        mixer
    }

    fn update_bytes(&mut self, bytes: &[u8]) {
        for (index, byte) in bytes.iter().copied().enumerate() {
            let lane = index & 3;
            self.lanes[lane] ^= u64::from(byte);
            self.lanes[lane] = self.lanes[lane]
                .wrapping_mul(0x0000_0100_0000_01b3)
                .rotate_left((lane as u32) + 5);
        }
    }

    fn update_u64(&mut self, value: u64) {
        self.update_bytes(&value.to_le_bytes());
    }

    fn finish(mut self) -> Digest {
        for round in 0..4 {
            let neighbor = self.lanes[(round + 1) & 3];
            self.lanes[round] ^= neighbor.rotate_left(17 + round as u32);
            self.lanes[round] = self.lanes[round].wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
        let mut bytes = [0_u8; 32];
        for (index, lane) in self.lanes.into_iter().enumerate() {
            bytes[index * 8..(index + 1) * 8].copy_from_slice(&lane.to_le_bytes());
        }
        if bytes.iter().all(|byte| *byte == 0) {
            bytes[0] = 1;
        }
        Digest::from_wire_bytes(bytes)
    }
}

fn make_selector(session: SessionHandle, domain: u64, sequence: u64) -> [u8; 16] {
    let mut mixer = DigestMixer::new(domain);
    mixer.update_bytes(&session.to_wire_bytes());
    mixer.update_u64(sequence);
    let digest = mixer.finish().to_wire_bytes();
    let mut selector = [0_u8; 16];
    selector.copy_from_slice(&digest[..16]);
    if selector.iter().all(|byte| *byte == 0) {
        selector[0] = 1;
    }
    selector
}

fn selector_word(session: SessionHandle, domain: u64, sequence: u64) -> u64 {
    let selector = make_selector(session, domain, sequence);
    let mut word = u64::from_le_bytes(selector[..8].try_into().unwrap());
    if word == 0 {
        word = 1;
    }
    word
}

fn make_receipt_digest(
    session: SessionHandle,
    request_digest: Digest,
    receipt: ReceiptHandle,
    kind: ReceiptKind,
    sequence: u64,
    context: ReceiptDigestContext,
) -> Digest {
    let mut mixer = DigestMixer::new(DIGEST_RECEIPT);
    mixer.update_bytes(&session.to_wire_bytes());
    mixer.update_bytes(&request_digest.to_wire_bytes());
    mixer.update_bytes(&receipt.to_wire_bytes());
    mixer.update_u64(u64::from(kind.wire_value()));
    mixer.update_u64(sequence);
    mixer.update_u64(context.authority_epoch);
    mixer.update_u64(context.binding_epoch);
    mixer.update_bytes(&context.subject_selector);
    mixer.finish()
}

fn make_scope_state_digest(scope: ScopeHandle, projection: RegistryProjection) -> Digest {
    let mut mixer = DigestMixer::new(DIGEST_SCOPE_STATE);
    mixer.update_bytes(&scope.to_wire_bytes());
    mixer.update_u64(match projection.phase {
        ScopePhase::Active => 1,
        ScopePhase::Closing => 2,
        ScopePhase::Revoked => 3,
    });
    mixer.update_u64(projection.authority_epoch);
    mixer.update_u64(projection.binding_epoch);
    mixer.update_u64(projection.revision);
    mixer.update_u64(projection.domain_revision);
    mixer.update_u64(u64::try_from(projection.live_effects).unwrap_or(u64::MAX));
    mixer.update_u64(u64::try_from(projection.pending_publications).unwrap_or(u64::MAX));
    mixer.update_u64(projection.credits.capacity);
    mixer.update_u64(projection.credits.free);
    mixer.update_u64(projection.credits.held);
    mixer.update_u64(projection.credits.committed);
    mixer.update_u64(projection.credits.retained);
    mixer.finish()
}

fn make_effect_state_digest(
    scope: ScopeHandle,
    effect: EffectHandle,
    projection: RegistryProjection,
    view: &EffectView,
) -> Digest {
    let mut mixer = DigestMixer::new(DIGEST_EFFECT_STATE);
    mixer.update_bytes(&scope.to_wire_bytes());
    mixer.update_bytes(&effect.to_wire_bytes());
    mixer.update_u64(projection.authority_epoch);
    mixer.update_u64(projection.binding_epoch);
    mixer.update_u64(projection.revision);
    mixer.update_u64(u64::from(project_effect_phase(view).wire_value()));
    mixer.update_u64(view.identity.effect().id());
    mixer.update_u64(view.identity.effect().generation());
    mixer.update_u64(view.identity.operation().value().into());
    mixer.update_u64(view.identity.authority_epoch());
    mixer.update_u64(view.identity.binding_epoch());
    if let Some(parent) = view.identity.parent() {
        mixer.update_u64(parent.id());
        mixer.update_u64(parent.generation());
    }
    if let Some(commit) = view.commit.as_ref() {
        mixer.update_u64(commit.sequence());
        mixer.update_bytes(&commit.result().to_le_bytes());
        mixer.update_u64(commit.domain_revision());
    }
    if let Some(outcome) = view.outcome {
        mixer.update_u64(u64::from(map_outcome_class(outcome.class()).wire_value()));
        mixer.update_bytes(&outcome.result().to_le_bytes());
        mixer.update_bytes(&outcome.digest());
    }
    if let Some(terminal) = view.terminal.as_ref() {
        mixer.update_u64(terminal.sequence());
        mixer.update_bytes(&terminal.result().to_le_bytes());
        mixer.update_u64(match terminal.outcome() {
            TerminalOutcome::Completed => 1,
            TerminalOutcome::IndeterminateAfterReset => 2,
            TerminalOutcome::Aborted => 3,
        });
        if let Some(digest) = terminal.manifest_digest() {
            mixer.update_bytes(&digest);
        }
    }
    mixer.update_u64(u64::from(view.publication_pending));
    mixer.finish()
}

fn make_closure_digest(
    scope: ScopeHandle,
    projection: RegistryProjection,
    reason: RevokeReason,
) -> Digest {
    let mut mixer = DigestMixer::new(DIGEST_CLOSURE);
    mixer.update_bytes(&make_scope_state_digest(scope, projection).to_wire_bytes());
    mixer.update_u64(u64::from(reason.wire_value()));
    mixer.finish()
}

fn receipt_status(
    registry: &EffectRegistry,
    receipt: ReceiptSlot,
) -> Result<ReceiptStatus, PortalFailure> {
    match receipt.subject {
        ReceiptSubject::Scope(scope) => {
            let projection = registry
                .scope_projection(scope)
                .map_err(map_registry_error)?;
            match receipt.kind {
                ReceiptKind::ScopeCreated => {
                    if projection.phase == ScopePhase::Active {
                        Ok(ReceiptStatus::Live)
                    } else {
                        Ok(ReceiptStatus::Consumed)
                    }
                }
                ReceiptKind::ScopeRevoked | ReceiptKind::Closure => {
                    if projection.phase == ScopePhase::Closing {
                        Ok(ReceiptStatus::Live)
                    } else {
                        Ok(ReceiptStatus::Consumed)
                    }
                }
                _ => Err(failure(
                    PortalErrorCode::InternalInvariant,
                    RetryClass::Never,
                )),
            }
        }
        ReceiptSubject::Effect(effect) => {
            let view = registry.effect_view(effect).map_err(map_registry_error)?;
            let phase = project_effect_phase(&view);
            match receipt.kind {
                ReceiptKind::EffectRegistered => {
                    if phase == AbiEffectPhase::Registered {
                        Ok(ReceiptStatus::Live)
                    } else {
                        Ok(ReceiptStatus::Consumed)
                    }
                }
                ReceiptKind::EffectPrepared => {
                    if phase == AbiEffectPhase::Prepared {
                        Ok(ReceiptStatus::Live)
                    } else {
                        Ok(ReceiptStatus::Consumed)
                    }
                }
                ReceiptKind::EffectCommitted => {
                    if phase == AbiEffectPhase::Committed {
                        Ok(ReceiptStatus::Live)
                    } else {
                        Ok(ReceiptStatus::Consumed)
                    }
                }
                ReceiptKind::OutcomeRecorded => {
                    if phase == AbiEffectPhase::OutcomeRecorded {
                        Ok(ReceiptStatus::Live)
                    } else {
                        Ok(ReceiptStatus::Consumed)
                    }
                }
                ReceiptKind::EffectCompleted if phase == AbiEffectPhase::Retained => {
                    Ok(ReceiptStatus::Retained)
                }
                ReceiptKind::EffectCompleted => Ok(ReceiptStatus::Consumed),
                _ => Err(failure(
                    PortalErrorCode::InternalInvariant,
                    RetryClass::Never,
                )),
            }
        }
    }
}

#[cfg(test)]
fn test_digest(tag: u8) -> Digest {
    Digest::from_wire_bytes([tag; 32])
}

#[cfg(test)]
fn test_context(
    session: SessionHandle,
    authority_epoch: u64,
    binding_epoch: u64,
    tag: u8,
) -> MutationContext {
    MutationContext::new(session, authority_epoch, binding_epoch, test_digest(tag)).unwrap()
}

#[cfg(test)]
fn dispatch_test_request<B: PortalBackend, const REPLAY: usize, T: RequestBody>(
    dispatcher: &mut PortalDispatcher<B, REPLAY>,
    request_id: u64,
    request: &T,
) -> alloc::vec::Vec<u8> {
    let mut body = alloc::vec![0; T::WIRE_SIZE];
    request.encode_wire(&mut body).unwrap();
    let header = MessageHeader::new(
        MessageKind::Request,
        T::OPCODE,
        HeaderFlags::EXPECT_REPLY,
        request_id,
    )
    .unwrap();
    let mut input = alloc::vec![0; MAX_MESSAGE_SIZE];
    let input_length = encode_message(header, &body, &mut input).unwrap();
    input.truncate(input_length);
    let mut output = alloc::vec![0; MAX_MESSAGE_SIZE];
    let output_length = dispatcher.dispatch(&input, &mut output).unwrap();
    output.truncate(output_length);
    output
}

#[cfg(test)]
fn decode_test_response<T: ResponseBody>(response: &[u8], opcode: nexus_portal_abi::Opcode) -> T {
    let message = decode_message(response).unwrap();
    assert_eq!(message.header.kind(), MessageKind::Response);
    assert_eq!(message.header.opcode(), opcode);
    T::decode_wire(message.body).unwrap()
}

#[cfg(test)]
fn create_test_scope<const S: usize, const E: usize, const R: usize>(
    adapter: &mut PortalV2Adapter<'_, S, E, R>,
    session: SessionHandle,
    tag: u8,
    max_effects: u32,
    credits: u32,
) -> ScopeCreatedResponse {
    create_test_scope_with_limits(
        adapter,
        session,
        tag,
        max_effects,
        max_effects,
        credits,
        credits,
    )
}

#[cfg(test)]
fn create_test_scope_with_limits<const S: usize, const E: usize, const R: usize>(
    adapter: &mut PortalV2Adapter<'_, S, E, R>,
    session: SessionHandle,
    tag: u8,
    max_effects: u32,
    max_tombstones: u32,
    queue_credits: u32,
    page_credits: u32,
) -> ScopeCreatedResponse {
    adapter
        .create_scope(
            CreateScopeRequest::new(
                session,
                ScopeHandle::NULL,
                0,
                0,
                test_digest(tag),
                CreateScopeFlags::empty(),
                max_effects,
                max_tombstones,
                queue_credits,
                page_credits,
            )
            .unwrap(),
        )
        .unwrap()
}

#[cfg(test)]
fn register_test_effect<const S: usize, const E: usize, const R: usize>(
    adapter: &mut PortalV2Adapter<'_, S, E, R>,
    session: SessionHandle,
    scope: ScopeCreatedResponse,
    tag: u8,
) -> LifecycleReceipt {
    register_test_effect_with_kind(adapter, session, scope, tag, CreditKind::Queue)
}

#[cfg(test)]
fn register_test_effect_with_kind<const S: usize, const E: usize, const R: usize>(
    adapter: &mut PortalV2Adapter<'_, S, E, R>,
    session: SessionHandle,
    scope: ScopeCreatedResponse,
    tag: u8,
    credit_kind: CreditKind,
) -> LifecycleReceipt {
    adapter
        .register(
            RegisterEffectRequest::new(
                test_context(session, scope.authority_epoch(), scope.binding_epoch(), tag),
                scope.scope(),
                EffectHandle::NULL,
                u32::from(tag),
                RegisterFlags::empty(),
                credit_kind,
                1,
            )
            .unwrap(),
        )
        .unwrap()
}

/// Host-executed production-source gate for the exact Registry adapter.
///
/// The integration test includes this file and effect_registry.rs as sibling
/// modules, so these assertions exercise the same code compiled into the OSTD
/// kernel instead of a reference reimplementation.
#[cfg(test)]
pub(crate) fn production_portal_v2_self_test() {
    const OWNER: TaskKey = TaskKey::new(0x7000, 9);
    let session = SessionHandle::from_wire_bytes([0x5a; 16]);

    // Exercise the actual encoded dispatcher/backend composition, rather than
    // letting the ABI dispatcher and Registry adapter pass only against
    // independent fake/direct tests.
    let mut wire_registry = EffectRegistry::new();
    let wire_adapter =
        PortalV2Adapter::<1, 1, 16>::new(&mut wire_registry, session, OWNER).unwrap();
    let mut dispatcher =
        PortalDispatcher::<_, 8>::new(PORTAL_V2_KERNEL_OFFER, session, wire_adapter).unwrap();
    let abi_bytes = dispatch_test_request(&mut dispatcher, 1, &QueryAbiRequest::new());
    let abi = decode_test_response::<AbiResponse>(&abi_bytes, nexus_portal_abi::Opcode::QueryAbi);
    assert_eq!(abi.offer(), PORTAL_V2_KERNEL_OFFER);
    assert_eq!(abi.limits().max_scopes(), 1);
    assert_eq!(abi.limits().max_effects_per_scope(), 1);
    assert_eq!(abi.limits().max_effect_selectors(), 1);
    assert_eq!(abi.limits().max_tombstones_per_scope(), 1);
    assert_eq!(abi.limits().max_receipts(), 16);
    assert_eq!(abi.limits().max_replay_entries(), 8);

    let negotiation = NegotiateRequest::new(CapabilityRequest {
        requested_portal: PORTAL_V2_KERNEL_OFFER.portal,
        required_portal: PORTAL_V2_KERNEL_OFFER.portal,
        requested_provider: PORTAL_V2_KERNEL_OFFER.provider,
        required_provider: PORTAL_V2_KERNEL_OFFER.provider,
    });
    let negotiated_bytes = dispatch_test_request(&mut dispatcher, 2, &negotiation);
    let negotiated = decode_test_response::<NegotiatedResponse>(
        &negotiated_bytes,
        nexus_portal_abi::Opcode::Negotiate,
    );
    assert_eq!(negotiated.session(), session);
    assert_eq!(negotiated.selected().portal, PORTAL_V2_KERNEL_OFFER.portal);
    assert_eq!(
        negotiated.selected().provider,
        PORTAL_V2_KERNEL_OFFER.provider
    );

    let oversized_create = CreateScopeRequest::new(
        session,
        ScopeHandle::NULL,
        0,
        0,
        test_digest(59),
        CreateScopeFlags::empty(),
        2,
        1,
        1,
        1,
    )
    .unwrap();
    let oversized_bytes = dispatch_test_request(&mut dispatcher, 90, &oversized_create);
    let oversized_message = decode_message(&oversized_bytes).unwrap();
    assert_eq!(oversized_message.header.kind(), MessageKind::Error);
    assert_eq!(
        ErrorResponse::decode_wire(oversized_message.body)
            .unwrap()
            .failure()
            .code(),
        PortalErrorCode::LimitExceeded
    );
    assert_eq!(
        dispatch_test_request(&mut dispatcher, 90, &oversized_create),
        oversized_bytes
    );

    let create = CreateScopeRequest::new(
        session,
        ScopeHandle::NULL,
        0,
        0,
        test_digest(60),
        CreateScopeFlags::empty(),
        1,
        1,
        1,
        1,
    )
    .unwrap();
    let created_bytes = dispatch_test_request(&mut dispatcher, 3, &create);
    let created = decode_test_response::<ScopeCreatedResponse>(
        &created_bytes,
        nexus_portal_abi::Opcode::CreateScope,
    );
    let context = |tag| {
        test_context(
            session,
            created.authority_epoch(),
            created.binding_epoch(),
            tag,
        )
    };
    let register = RegisterEffectRequest::new(
        context(61),
        created.scope(),
        EffectHandle::NULL,
        61,
        RegisterFlags::empty(),
        CreditKind::Queue,
        1,
    )
    .unwrap();
    let registered_bytes = dispatch_test_request(&mut dispatcher, 4, &register);
    let registered = decode_test_response::<LifecycleReceipt>(
        &registered_bytes,
        nexus_portal_abi::Opcode::Register,
    );
    assert_eq!(registered.phase(), AbiEffectPhase::Registered);
    assert_eq!(
        dispatch_test_request(&mut dispatcher, 4, &register),
        registered_bytes
    );
    let prepared = decode_test_response::<LifecycleReceipt>(
        &dispatch_test_request(
            &mut dispatcher,
            5,
            &PrepareEffectRequest::new(context(62), registered.effect()).unwrap(),
        ),
        nexus_portal_abi::Opcode::Prepare,
    );
    assert_eq!(prepared.phase(), AbiEffectPhase::Prepared);
    let committed = decode_test_response::<LifecycleReceipt>(
        &dispatch_test_request(
            &mut dispatcher,
            6,
            &CommitEffectRequest::new(context(63), registered.effect(), 1).unwrap(),
        ),
        nexus_portal_abi::Opcode::Commit,
    );
    assert_eq!(committed.phase(), AbiEffectPhase::Committed);
    let outcome = decode_test_response::<LifecycleReceipt>(
        &dispatch_test_request(
            &mut dispatcher,
            7,
            &RecordOutcomeRequest::new(
                context(64),
                registered.effect(),
                OutcomeKind::Data,
                37,
                test_digest(65),
            )
            .unwrap(),
        ),
        nexus_portal_abi::Opcode::RecordOutcome,
    );
    assert_eq!(outcome.phase(), AbiEffectPhase::OutcomeRecorded);
    let complete_request = CompleteEffectRequest::new(
        context(66),
        registered.effect(),
        CompletionDisposition::Completed,
        test_digest(67),
    )
    .unwrap();
    let completed_bytes = dispatch_test_request(&mut dispatcher, 8, &complete_request);
    let completed = decode_test_response::<LifecycleReceipt>(
        &completed_bytes,
        nexus_portal_abi::Opcode::Complete,
    );
    assert_eq!(completed.phase(), AbiEffectPhase::Completed);
    assert_eq!(
        dispatch_test_request(&mut dispatcher, 8, &complete_request),
        completed_bytes
    );
    let observation = decode_test_response::<EffectObservation>(
        &dispatch_test_request(
            &mut dispatcher,
            100,
            &QueryEffectRequest::new(registered.effect()),
        ),
        nexus_portal_abi::Opcode::QueryEffect,
    );
    assert_eq!(observation.phase(), AbiEffectPhase::Completed);
    assert_eq!(observation.outcome().unwrap().kind(), OutcomeKind::Data);
    assert_eq!(observation.outcome().unwrap().result(), 37);
    assert_eq!(observation.outcome().unwrap().digest(), test_digest(65));
    assert_eq!(observation.terminal_digest(), Some(test_digest(67)));
    let receipt = decode_test_response::<ReceiptObservation>(
        &dispatch_test_request(
            &mut dispatcher,
            101,
            &QueryReceiptRequest::new(completed.receipt()),
        ),
        nexus_portal_abi::Opcode::QueryReceipt,
    );
    assert_eq!(receipt.status(), ReceiptStatus::Consumed);
    assert_eq!(dispatcher.replay_len(), 7);

    // Receipt pressure must fail before prepare mutates the Registry.  A stale
    // context is also distinguished from capacity pressure and leaves the
    // exact observation unchanged.
    let mut pressure_registry = EffectRegistry::new();
    let mut pressure =
        PortalV2Adapter::<1, 1, 2>::new(&mut pressure_registry, session, OWNER).unwrap();
    let pressure_scope = create_test_scope(&mut pressure, session, 1, 1, 1);
    let pressure_effect = register_test_effect(&mut pressure, session, pressure_scope, 2);
    let before = pressure
        .query_effect(session, QueryEffectRequest::new(pressure_effect.effect()))
        .unwrap();
    let stale = pressure
        .prepare(
            PrepareEffectRequest::new(
                test_context(
                    session,
                    pressure_scope.authority_epoch() + 1,
                    pressure_scope.binding_epoch(),
                    3,
                ),
                pressure_effect.effect(),
            )
            .unwrap(),
        )
        .unwrap_err();
    assert_eq!(stale.code(), PortalErrorCode::GenerationMismatch);
    assert_eq!(
        pressure
            .prepare(
                PrepareEffectRequest::new(
                    test_context(
                        session,
                        pressure_scope.authority_epoch(),
                        pressure_scope.binding_epoch(),
                        4,
                    ),
                    pressure_effect.effect(),
                )
                .unwrap(),
            )
            .unwrap_err()
            .code(),
        PortalErrorCode::Backpressure
    );
    let after = pressure
        .query_effect(session, QueryEffectRequest::new(pressure_effect.effect()))
        .unwrap();
    assert_eq!(before, after);
    assert_eq!(after.phase(), AbiEffectPhase::Registered);
    pressure.registry.check_invariants().unwrap();

    // Queue and page admission are independent Registry ledgers. Exhausting
    // one pool must neither consume the other nor reserve a failed selector or
    // receipt.
    let mut credit_registry = EffectRegistry::new();
    let mut credit_adapter =
        PortalV2Adapter::<1, 3, 8>::new(&mut credit_registry, session, OWNER).unwrap();
    let credit_scope = create_test_scope_with_limits(&mut credit_adapter, session, 40, 3, 3, 1, 1);
    register_test_effect_with_kind(
        &mut credit_adapter,
        session,
        credit_scope,
        41,
        CreditKind::Queue,
    );
    register_test_effect_with_kind(
        &mut credit_adapter,
        session,
        credit_scope,
        42,
        CreditKind::Page,
    );
    let before_exhausted_queue = credit_adapter
        .query_scope(session, QueryScopeRequest::new(credit_scope.scope()))
        .unwrap();
    let exhausted_queue = credit_adapter
        .register(
            RegisterEffectRequest::new(
                test_context(
                    session,
                    credit_scope.authority_epoch(),
                    credit_scope.binding_epoch(),
                    43,
                ),
                credit_scope.scope(),
                EffectHandle::NULL,
                43,
                RegisterFlags::empty(),
                CreditKind::Queue,
                1,
            )
            .unwrap(),
        )
        .unwrap_err();
    assert_eq!(exhausted_queue.code(), PortalErrorCode::NoCredit);
    assert_eq!(exhausted_queue.retry(), RetryClass::AfterCapacity);
    assert_eq!(
        credit_adapter
            .query_scope(session, QueryScopeRequest::new(credit_scope.scope()))
            .unwrap(),
        before_exhausted_queue
    );
    credit_adapter.registry.check_invariants().unwrap();

    // Tombstone pressure is a lifetime scope quota in this preview: without a
    // retirement opcode, neither Complete nor Revoke may silently exceed it.
    let mut tombstone_registry = EffectRegistry::new();
    let mut tombstone_adapter =
        PortalV2Adapter::<1, 2, 8>::new(&mut tombstone_registry, session, OWNER).unwrap();
    let tombstone_scope =
        create_test_scope_with_limits(&mut tombstone_adapter, session, 50, 2, 1, 2, 0);
    let first_tombstone =
        register_test_effect(&mut tombstone_adapter, session, tombstone_scope, 51);
    tombstone_adapter
        .complete(
            CompleteEffectRequest::new(
                test_context(
                    session,
                    tombstone_scope.authority_epoch(),
                    tombstone_scope.binding_epoch(),
                    52,
                ),
                first_tombstone.effect(),
                CompletionDisposition::AbortedBeforeCommit,
                test_digest(53),
            )
            .unwrap(),
        )
        .unwrap();
    let blocked_tombstone =
        register_test_effect(&mut tombstone_adapter, session, tombstone_scope, 54);
    let before_tombstone_pressure = tombstone_adapter
        .query_effect(session, QueryEffectRequest::new(blocked_tombstone.effect()))
        .unwrap();
    let tombstone_failure = tombstone_adapter
        .complete(
            CompleteEffectRequest::new(
                test_context(
                    session,
                    tombstone_scope.authority_epoch(),
                    tombstone_scope.binding_epoch(),
                    55,
                ),
                blocked_tombstone.effect(),
                CompletionDisposition::AbortedBeforeCommit,
                test_digest(56),
            )
            .unwrap(),
        )
        .unwrap_err();
    assert_eq!(tombstone_failure.code(), PortalErrorCode::Backpressure);
    assert_eq!(tombstone_failure.retry(), RetryClass::Never);
    assert_eq!(
        tombstone_adapter
            .query_effect(session, QueryEffectRequest::new(blocked_tombstone.effect()),)
            .unwrap(),
        before_tombstone_pressure
    );
    let before_tombstone_revoke = tombstone_adapter
        .query_scope(session, QueryScopeRequest::new(tombstone_scope.scope()))
        .unwrap();
    assert_eq!(
        tombstone_adapter
            .revoke(
                RevokeScopeRequest::new(
                    test_context(
                        session,
                        tombstone_scope.authority_epoch(),
                        tombstone_scope.binding_epoch(),
                        57,
                    ),
                    tombstone_scope.scope(),
                    RevokeReason::Requested,
                )
                .unwrap(),
            )
            .unwrap_err()
            .code(),
        PortalErrorCode::Backpressure
    );
    assert_eq!(
        tombstone_adapter
            .query_scope(session, QueryScopeRequest::new(tombstone_scope.scope()))
            .unwrap(),
        before_tombstone_revoke
    );
    tombstone_adapter.registry.check_invariants().unwrap();

    let mut registry = EffectRegistry::new();
    let mut adapter = PortalV2Adapter::<1, 3, 16>::new(&mut registry, session, OWNER).unwrap();
    let scope = create_test_scope(&mut adapter, session, 10, 3, 3);

    // A complete logical-request lifecycle is projected from Registry phase
    // plus its canonical outcome record.  Conflicting outcome mutation cannot
    // rewrite the accepted record.
    let effect_a = register_test_effect(&mut adapter, session, scope, 11);
    let prepared_a = adapter
        .prepare(
            PrepareEffectRequest::new(
                test_context(session, scope.authority_epoch(), scope.binding_epoch(), 12),
                effect_a.effect(),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(prepared_a.phase(), AbiEffectPhase::Prepared);
    let committed_a = adapter
        .commit(
            CommitEffectRequest::new(
                test_context(session, scope.authority_epoch(), scope.binding_epoch(), 13),
                effect_a.effect(),
                1,
            )
            .unwrap(),
        )
        .unwrap();
    let outcome_request_a = RecordOutcomeRequest::new(
        test_context(session, scope.authority_epoch(), scope.binding_epoch(), 14),
        effect_a.effect(),
        OutcomeKind::Data,
        37,
        test_digest(15),
    )
    .unwrap();
    let outcome_a = adapter.record_outcome(outcome_request_a).unwrap();
    assert_eq!(
        adapter.record_outcome(outcome_request_a).unwrap(),
        outcome_a
    );
    let conflict = adapter
        .record_outcome(
            RecordOutcomeRequest::new(
                test_context(session, scope.authority_epoch(), scope.binding_epoch(), 16),
                effect_a.effect(),
                OutcomeKind::Error,
                -5,
                test_digest(17),
            )
            .unwrap(),
        )
        .unwrap_err();
    assert_eq!(conflict.code(), PortalErrorCode::Conflict);
    assert_eq!(
        adapter
            .query_effect(session, QueryEffectRequest::new(effect_a.effect()))
            .unwrap()
            .phase(),
        AbiEffectPhase::OutcomeRecorded
    );
    let completed_a = adapter
        .complete(
            CompleteEffectRequest::new(
                test_context(session, scope.authority_epoch(), scope.binding_epoch(), 18),
                effect_a.effect(),
                CompletionDisposition::Completed,
                test_digest(19),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(completed_a.phase(), AbiEffectPhase::Completed);
    assert_eq!(
        adapter
            .query_receipt(session, QueryReceiptRequest::new(committed_a.receipt()),)
            .unwrap()
            .status(),
        ReceiptStatus::Consumed
    );
    assert_eq!(
        adapter
            .query_receipt(session, QueryReceiptRequest::new(outcome_a.receipt()))
            .unwrap()
            .status(),
        ReceiptStatus::Consumed
    );

    // Revoke refuses to cut authority while a committed effect lacks an
    // outcome, then closes that committed effect and one uncommitted effect
    // after the missing outcome is recorded.
    let effect_b = register_test_effect(&mut adapter, session, scope, 20);
    adapter
        .prepare(
            PrepareEffectRequest::new(
                test_context(session, scope.authority_epoch(), scope.binding_epoch(), 21),
                effect_b.effect(),
            )
            .unwrap(),
        )
        .unwrap();
    adapter
        .commit(
            CommitEffectRequest::new(
                test_context(session, scope.authority_epoch(), scope.binding_epoch(), 22),
                effect_b.effect(),
                2,
            )
            .unwrap(),
        )
        .unwrap();
    let revoke_context = test_context(session, scope.authority_epoch(), scope.binding_epoch(), 23);
    let before_revoke = adapter
        .query_scope(session, QueryScopeRequest::new(scope.scope()))
        .unwrap();
    assert_eq!(
        adapter
            .revoke(
                RevokeScopeRequest::new(revoke_context, scope.scope(), RevokeReason::Requested)
                    .unwrap(),
            )
            .unwrap_err()
            .code(),
        PortalErrorCode::Conflict
    );
    assert_eq!(
        adapter
            .query_scope(session, QueryScopeRequest::new(scope.scope()))
            .unwrap(),
        before_revoke
    );
    adapter
        .record_outcome(
            RecordOutcomeRequest::new(
                test_context(session, scope.authority_epoch(), scope.binding_epoch(), 24),
                effect_b.effect(),
                OutcomeKind::Error,
                -11,
                test_digest(25),
            )
            .unwrap(),
        )
        .unwrap();
    let effect_c = register_test_effect(&mut adapter, session, scope, 26);
    let closure = adapter
        .revoke(
            RevokeScopeRequest::new(revoke_context, scope.scope(), RevokeReason::Requested)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(closure.status(), ClosureStatus::Closed);
    let closed = adapter
        .query_scope(session, QueryScopeRequest::new(scope.scope()))
        .unwrap();
    assert_eq!(closed.phase(), AbiScopePhase::Revoked);
    assert_eq!(closed.live_effects(), 0);
    assert_eq!(
        adapter
            .query_effect(session, QueryEffectRequest::new(effect_b.effect()))
            .unwrap()
            .phase(),
        AbiEffectPhase::Completed
    );
    assert_eq!(
        adapter
            .query_effect(session, QueryEffectRequest::new(effect_c.effect()))
            .unwrap()
            .phase(),
        AbiEffectPhase::Aborted
    );
    assert_eq!(
        adapter
            .query_receipt(session, QueryReceiptRequest::new(closure.receipt()))
            .unwrap()
            .status(),
        ReceiptStatus::Consumed
    );
    adapter.registry.check_invariants().unwrap();
}

impl<const SCOPE_SLOTS: usize, const EFFECT_SLOTS: usize, const RECEIPT_SLOTS: usize> PortalBackend
    for PortalV2Adapter<'_, SCOPE_SLOTS, EFFECT_SLOTS, RECEIPT_SLOTS>
{
    fn portal_limits(&self) -> Result<PortalLimits, PortalWireError> {
        let max_scopes = u32::try_from(SCOPE_SLOTS).unwrap_or(u32::MAX);
        let max_effect_selectors = u32::try_from(EFFECT_SLOTS).unwrap_or(u32::MAX);
        let max_receipts = u32::try_from(RECEIPT_SLOTS).unwrap_or(u32::MAX);
        let max_effects_per_scope =
            max_effect_selectors.min(nexus_portal_abi::MAX_EFFECTS_PER_SCOPE);
        let max_tombstones_per_scope =
            max_effects_per_scope.min(nexus_portal_abi::MAX_TOMBSTONES_PER_SCOPE);
        PortalLimits::new(
            max_scopes,
            max_effects_per_scope,
            max_effect_selectors,
            max_tombstones_per_scope,
            nexus_portal_abi::MAX_QUEUE_CREDITS_PER_SCOPE,
            nexus_portal_abi::MAX_PAGE_CREDITS_PER_SCOPE,
            max_receipts,
            u32::MAX,
        )
    }

    fn create_scope(
        &mut self,
        request: CreateScopeRequest,
    ) -> Result<ScopeCreatedResponse, PortalFailure> {
        self.require_session(request.session())?;

        if let Some(existing) = self
            .scopes
            .iter()
            .flatten()
            .copied()
            .find(|slot| slot.create_digest == request.request_digest())
        {
            if !request.parent().is_null()
                || request.flags() != existing.flags
                || request.max_effects() != existing.max_effects
                || request.max_tombstones() != existing.max_tombstones
                || request.queue_credits() != existing.queue_credits
                || request.page_credits() != existing.page_credits
            {
                return Err(Self::conflict(
                    request.request_digest(),
                    existing.create_digest,
                ));
            }
            return ScopeCreatedResponse::new(
                existing.selector,
                existing.creation.receipt,
                existing.creation_authority_epoch,
                existing.creation_binding_epoch,
                existing.creation.sequence,
                existing.create_digest,
                existing.creation.receipt_digest,
            )
            .map_err(map_wire_invariant);
        }

        // Scope ancestry is not yet represented by EffectRegistry.  Reject it
        // rather than creating an unrelated root that merely carries matching
        // wire integers.
        if !request.parent().is_null()
            || request
                .flags()
                .contains(CreateScopeFlags::ALLOW_CHILD_SCOPES)
        {
            return Err(failure(
                PortalErrorCode::PermissionDenied,
                RetryClass::Never,
            ));
        }

        let limits = self.portal_limits().map_err(map_wire_invariant)?;
        if request.max_effects() > limits.max_effects_per_scope()
            || request.max_tombstones() > limits.max_tombstones_per_scope()
            || request.queue_credits() > limits.max_queue_credits_per_scope()
            || request.page_credits() > limits.max_page_credits_per_scope()
        {
            return Err(failure(PortalErrorCode::LimitExceeded, RetryClass::Never));
        }

        let scope_index = self
            .scopes
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| failure(PortalErrorCode::Backpressure, RetryClass::NewSession))?;
        let sequence = self.next_scope_sequence;
        sequence
            .checked_add(1)
            .ok_or_else(|| failure(PortalErrorCode::Backpressure, RetryClass::NewSession))?;
        let selector =
            ScopeHandle::from_wire_bytes(make_selector(self.session, SELECTOR_SCOPE, sequence));
        if self
            .scopes
            .iter()
            .flatten()
            .any(|existing| existing.selector == selector)
        {
            return Err(failure(
                PortalErrorCode::Backpressure,
                RetryClass::NewSession,
            ));
        }
        let key = ScopeKey::new(selector_word(self.session, SELECTOR_SCOPE_KEY, sequence), 1);
        let authority_epoch = selector_word(self.session, SELECTOR_AUTHORITY, sequence);
        let binding_epoch = self.owner.generation();
        let receipt = self.reserve_receipt(
            request.request_digest(),
            ReceiptKind::ScopeCreated,
            authority_epoch,
            binding_epoch,
            selector.to_wire_bytes(),
        )?;
        let creation = receipt.stage(AbiEffectPhase::Registered);
        let response = ScopeCreatedResponse::new(
            selector,
            receipt.selector,
            authority_epoch,
            binding_epoch,
            receipt.sequence,
            request.request_digest(),
            receipt.receipt_digest,
        )
        .map_err(map_wire_invariant)?;
        let mut credits = alloc::vec![];
        if request.queue_credits() != 0 {
            credits.push(CreditLimit::new(
                PORTAL_QUEUE_CREDIT_CLASS,
                u64::from(request.queue_credits()),
            ));
        }
        if request.page_credits() != 0 {
            credits.push(CreditLimit::new(
                PORTAL_PAGE_CREDIT_CLASS,
                u64::from(request.page_credits()),
            ));
        }

        self.registry
            .create_scope(ScopeConfig {
                key,
                authority_epoch,
                binding_epoch,
                supervisor: self.owner,
                credits,
            })
            .map_err(map_registry_error)?;

        self.scopes[scope_index] = Some(ScopeSlot {
            selector,
            key,
            creation_authority_epoch: authority_epoch,
            creation_binding_epoch: binding_epoch,
            create_digest: request.request_digest(),
            flags: request.flags(),
            max_effects: request.max_effects(),
            max_tombstones: request.max_tombstones(),
            queue_credits: request.queue_credits(),
            page_credits: request.page_credits(),
            creation,
            latest_receipt: receipt.selector,
            revoke: None,
        });
        self.next_scope_sequence = sequence + 1;
        self.install_receipt(
            receipt,
            ReceiptSubject::Scope(key),
            authority_epoch,
            binding_epoch,
        );
        Ok(response)
    }

    fn register(
        &mut self,
        request: RegisterEffectRequest,
    ) -> Result<LifecycleReceipt, PortalFailure> {
        let scope_index = self.scope_index(request.scope())?;
        let scope = self.scopes[scope_index].unwrap();
        let projection = self.require_context(request.context(), scope.key)?;

        if request
            .flags()
            .contains(RegisterFlags::PUBLICATION_REQUIRED)
        {
            // v2 has no publication-ack opcode yet.  Accepting this flag would
            // leave a terminal credit permanently pending behind no callable
            // transition.
            return Err(failure(
                PortalErrorCode::PermissionDenied,
                RetryClass::Never,
            ));
        }

        let spec = RegisterSpec {
            parent: request.parent(),
            operation_class: request.operation_class(),
            flags: request.flags(),
            credit_kind: request.credit_kind(),
            credit_units: request.credit_units(),
        };
        if let Some(existing) = self.effects.iter().flatten().copied().find(|slot| {
            slot.scope == request.scope()
                && slot.registration.request_digest == request.context().request_digest()
        }) {
            if existing.register_spec != spec {
                return Err(Self::conflict(
                    request.context().request_digest(),
                    existing.registration.request_digest,
                ));
            }
            return Self::lifecycle_receipt(
                existing.scope,
                existing.selector,
                projection.authority_epoch,
                projection.binding_epoch,
                existing.registration,
            );
        }

        let (credit_class, scope_credit_capacity) = match request.credit_kind() {
            CreditKind::Queue => (PORTAL_QUEUE_CREDIT_CLASS, scope.queue_credits),
            CreditKind::Page => (PORTAL_PAGE_CREDIT_CLASS, scope.page_credits),
        };
        if request.credit_units() > scope_credit_capacity {
            return Err(failure(
                PortalErrorCode::NoCredit,
                RetryClass::AfterCapacity,
            ));
        }

        if self.scope_effect_count(request.scope())
            >= usize::try_from(scope.max_effects).unwrap_or(usize::MAX)
        {
            return Err(failure(
                PortalErrorCode::Backpressure,
                RetryClass::NewSession,
            ));
        }
        let effect_index = self
            .effects
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| failure(PortalErrorCode::Backpressure, RetryClass::NewSession))?;
        let effect_sequence = self.next_effect_sequence;
        effect_sequence
            .checked_add(1)
            .ok_or_else(|| failure(PortalErrorCode::Backpressure, RetryClass::NewSession))?;
        let selector = EffectHandle::from_wire_bytes(make_selector(
            self.session,
            SELECTOR_EFFECT,
            effect_sequence,
        ));
        if self
            .effects
            .iter()
            .flatten()
            .any(|existing| existing.selector == selector)
        {
            return Err(failure(
                PortalErrorCode::Backpressure,
                RetryClass::NewSession,
            ));
        }
        let parent = if request.parent().is_null() {
            None
        } else {
            let parent = self.effects[self.effect_index(request.parent())?].unwrap();
            if parent.scope != request.scope() {
                return Err(failure(PortalErrorCode::InvalidHandle, RetryClass::Never));
            }
            // Descriptor lookup is a non-mutating current-handle validation.
            self.registry
                .descriptor(self.owner, parent.portal)
                .map_err(map_registry_error)?;
            Some(parent.key)
        };
        let receipt = self.reserve_receipt(
            request.context().request_digest(),
            ReceiptKind::EffectRegistered,
            projection.authority_epoch,
            projection.binding_epoch,
            selector.to_wire_bytes(),
        )?;
        let registration = receipt.stage(AbiEffectPhase::Registered);
        let response = Self::lifecycle_receipt(
            request.scope(),
            selector,
            projection.authority_epoch,
            projection.binding_epoch,
            registration,
        )?;

        let registered = self
            .registry
            .register_with_parent_requiring_outcome(
                RegisterRequest {
                    scope: scope.key,
                    task: self.owner,
                    operation: OperationClass::new(request.operation_class()),
                    descriptor: descriptor_for(request),
                    resources: alloc::vec![],
                    credits: alloc::vec![CreditCharge::new(
                        credit_class,
                        u64::from(request.credit_units()),
                    )],
                    publication: PublicationMode::None,
                },
                parent,
            )
            .map_err(map_registry_error)?;

        self.effects[effect_index] = Some(EffectSlot {
            selector,
            scope: request.scope(),
            key: registered.identity.effect(),
            portal: registered.handle,
            register_spec: spec,
            registration,
            prepare: None,
            commit: None,
            outcome: None,
            completion: None,
            latest_receipt: receipt.selector,
        });
        self.next_effect_sequence = effect_sequence + 1;
        self.scopes[scope_index].as_mut().unwrap().latest_receipt = receipt.selector;
        self.install_receipt(
            receipt,
            ReceiptSubject::Effect(registered.identity.effect()),
            projection.authority_epoch,
            projection.binding_epoch,
        );
        Ok(response)
    }

    fn prepare(
        &mut self,
        request: PrepareEffectRequest,
    ) -> Result<LifecycleReceipt, PortalFailure> {
        let effect_index = self.effect_index(request.effect())?;
        let slot = self.effects[effect_index].unwrap();
        let scope_index = self.scope_index(slot.scope)?;
        let scope = self.scopes[scope_index].unwrap();
        let projection = self.require_context(request.context(), scope.key)?;
        if let Some(existing) = slot.prepare {
            if existing.request_digest == request.context().request_digest() {
                return Self::lifecycle_receipt(
                    slot.scope,
                    slot.selector,
                    projection.authority_epoch,
                    projection.binding_epoch,
                    existing,
                );
            }
            return Err(Self::conflict(
                request.context().request_digest(),
                existing.request_digest,
            ));
        }
        if self.effect_view(slot)?.phase != EffectPhase::Registered {
            return Err(failure(PortalErrorCode::OutOfOrder, RetryClass::AfterQuery));
        }
        let receipt = self.reserve_receipt(
            request.context().request_digest(),
            ReceiptKind::EffectPrepared,
            projection.authority_epoch,
            projection.binding_epoch,
            slot.selector.to_wire_bytes(),
        )?;
        let stage = receipt.stage(AbiEffectPhase::Prepared);
        let response = Self::lifecycle_receipt(
            slot.scope,
            slot.selector,
            projection.authority_epoch,
            projection.binding_epoch,
            stage,
        )?;
        self.registry
            .prepare(self.owner, slot.portal)
            .map_err(map_registry_error)?;
        let effect = self.effects[effect_index].as_mut().unwrap();
        effect.prepare = Some(stage);
        effect.latest_receipt = receipt.selector;
        self.scopes[scope_index].as_mut().unwrap().latest_receipt = receipt.selector;
        self.install_receipt(
            receipt,
            ReceiptSubject::Effect(slot.key),
            projection.authority_epoch,
            projection.binding_epoch,
        );
        Ok(response)
    }

    fn commit(&mut self, request: CommitEffectRequest) -> Result<LifecycleReceipt, PortalFailure> {
        let effect_index = self.effect_index(request.effect())?;
        let slot = self.effects[effect_index].unwrap();
        let scope_index = self.scope_index(slot.scope)?;
        let scope = self.scopes[scope_index].unwrap();
        let projection = self.require_context(request.context(), scope.key)?;
        if let Some(existing) = slot.commit {
            let view = self.effect_view(slot)?;
            let same_revision = view
                .commit
                .as_ref()
                .is_some_and(|commit| commit.domain_revision() == request.domain_revision());
            if existing.request_digest == request.context().request_digest() && same_revision {
                return Self::lifecycle_receipt(
                    slot.scope,
                    slot.selector,
                    projection.authority_epoch,
                    projection.binding_epoch,
                    existing,
                );
            }
            return Err(Self::conflict(
                request.context().request_digest(),
                existing.request_digest,
            ));
        }
        if self.effect_view(slot)?.phase != EffectPhase::Prepared {
            return Err(failure(PortalErrorCode::OutOfOrder, RetryClass::AfterQuery));
        }
        let expected_domain_revision = projection
            .domain_revision
            .checked_add(1)
            .ok_or_else(|| failure(PortalErrorCode::Backpressure, RetryClass::Never))?;
        if request.domain_revision() != expected_domain_revision {
            return Err(
                failure(PortalErrorCode::GenerationMismatch, RetryClass::AfterQuery)
                    .with_epochs(projection.authority_epoch, projection.binding_epoch),
            );
        }
        let receipt = self.reserve_receipt(
            request.context().request_digest(),
            ReceiptKind::EffectCommitted,
            projection.authority_epoch,
            projection.binding_epoch,
            slot.selector.to_wire_bytes(),
        )?;
        let stage = receipt.stage(AbiEffectPhase::Committed);
        let response = Self::lifecycle_receipt(
            slot.scope,
            slot.selector,
            projection.authority_epoch,
            projection.binding_epoch,
            stage,
        )?;
        let outcome = self
            .registry
            .commit_after_domain_change(
                self.owner,
                slot.portal,
                // For the portal profile this is the successful admission
                // publication result.  The backend result is attached later
                // by EffectRegistry::record_outcome.
                CommitMetadata::new(0, request.domain_revision()),
            )
            .map_err(map_registry_error)?;
        if !matches!(outcome, CommitOutcome::Applied(_)) {
            return Err(failure(
                PortalErrorCode::InternalInvariant,
                RetryClass::Never,
            ));
        }
        let effect = self.effects[effect_index].as_mut().unwrap();
        effect.commit = Some(stage);
        effect.latest_receipt = receipt.selector;
        self.scopes[scope_index].as_mut().unwrap().latest_receipt = receipt.selector;
        self.install_receipt(
            receipt,
            ReceiptSubject::Effect(slot.key),
            projection.authority_epoch,
            projection.binding_epoch,
        );
        Ok(response)
    }

    fn record_outcome(
        &mut self,
        request: RecordOutcomeRequest,
    ) -> Result<LifecycleReceipt, PortalFailure> {
        let effect_index = self.effect_index(request.effect())?;
        let slot = self.effects[effect_index].unwrap();
        let scope_index = self.scope_index(slot.scope)?;
        let scope = self.scopes[scope_index].unwrap();
        let projection = self.require_context(request.context(), scope.key)?;
        let spec = OutcomeSpec {
            kind: request.outcome_kind(),
            result: request.result(),
            digest: request.outcome_digest(),
        };
        let mut reconciles_indeterminate = false;
        if let Some((existing, existing_spec)) = slot.outcome {
            let view = self.effect_view(slot)?;
            let authoritative = EffectOutcomeRecord::new(
                registry_outcome_class(spec.kind),
                spec.result,
                spec.digest.to_wire_bytes(),
            )
            .map_err(map_registry_error)?;
            if existing.request_digest == request.context().request_digest()
                && existing_spec == spec
                && view.outcome == Some(authoritative)
            {
                return Self::lifecycle_receipt(
                    slot.scope,
                    slot.selector,
                    projection.authority_epoch,
                    projection.binding_epoch,
                    existing,
                );
            }
            if existing_spec.kind == OutcomeKind::Indeterminate
                && spec.kind != OutcomeKind::Indeterminate
                && view.outcome.is_some_and(|outcome| {
                    outcome.class() == EffectOutcomeClass::Indeterminate
                        && outcome.result() == existing_spec.result
                        && outcome.digest() == existing_spec.digest.to_wire_bytes()
                })
            {
                reconciles_indeterminate = true;
            } else {
                return Err(Self::conflict(
                    request.context().request_digest(),
                    existing.request_digest,
                ));
            }
        }
        let view = self.effect_view(slot)?;
        if view.phase != EffectPhase::Committed
            || (view.outcome.is_some() && !reconciles_indeterminate)
        {
            return Err(failure(PortalErrorCode::OutOfOrder, RetryClass::AfterQuery));
        }
        let authoritative = EffectOutcomeRecord::new(
            registry_outcome_class(spec.kind),
            spec.result,
            spec.digest.to_wire_bytes(),
        )
        .map_err(map_registry_error)?;
        let receipt = self.reserve_receipt(
            request.context().request_digest(),
            ReceiptKind::OutcomeRecorded,
            projection.authority_epoch,
            projection.binding_epoch,
            slot.selector.to_wire_bytes(),
        )?;
        let stage = receipt.stage(AbiEffectPhase::OutcomeRecorded);
        let response = Self::lifecycle_receipt(
            slot.scope,
            slot.selector,
            projection.authority_epoch,
            projection.binding_epoch,
            stage,
        )?;
        self.registry
            .record_outcome(self.owner, slot.portal, authoritative)
            .map_err(map_registry_error)?;
        let effect = self.effects[effect_index].as_mut().unwrap();
        effect.outcome = Some((stage, spec));
        effect.latest_receipt = receipt.selector;
        self.scopes[scope_index].as_mut().unwrap().latest_receipt = receipt.selector;
        self.install_receipt(
            receipt,
            ReceiptSubject::Effect(slot.key),
            projection.authority_epoch,
            projection.binding_epoch,
        );
        Ok(response)
    }

    fn complete(
        &mut self,
        request: CompleteEffectRequest,
    ) -> Result<LifecycleReceipt, PortalFailure> {
        let effect_index = self.effect_index(request.effect())?;
        let slot = self.effects[effect_index].unwrap();
        let scope_index = self.scope_index(slot.scope)?;
        let scope = self.scopes[scope_index].unwrap();
        let projection = self.require_context(request.context(), scope.key)?;
        let spec = CompletionSpec {
            disposition: request.disposition(),
            terminal_digest: request.terminal_digest(),
        };
        if let Some((existing, existing_spec)) = slot.completion {
            let view = self.effect_view(slot)?;
            if existing.request_digest == request.context().request_digest()
                && existing_spec == spec
                && view.terminal.as_ref().is_some_and(|terminal| {
                    terminal.manifest_digest() == Some(request.terminal_digest().to_wire_bytes())
                })
            {
                return Self::lifecycle_receipt(
                    slot.scope,
                    slot.selector,
                    projection.authority_epoch,
                    projection.binding_epoch,
                    existing,
                );
            }
            return Err(Self::conflict(
                request.context().request_digest(),
                existing.request_digest,
            ));
        }

        let view = self.effect_view(slot)?;
        let (terminal, abi_phase) = match request.disposition() {
            CompletionDisposition::Completed => {
                if view.phase != EffectPhase::Committed {
                    return Err(failure(PortalErrorCode::OutOfOrder, RetryClass::AfterQuery));
                }
                let outcome = view
                    .outcome
                    .ok_or_else(|| failure(PortalErrorCode::OutOfOrder, RetryClass::AfterQuery))?;
                if outcome.class() == EffectOutcomeClass::Indeterminate {
                    return Err(failure(PortalErrorCode::Conflict, RetryClass::AfterQuery));
                }
                (
                    TerminalRequest::completed(outcome.result())
                        .with_manifest_digest(request.terminal_digest().to_wire_bytes())
                        .map_err(map_registry_error)?,
                    AbiEffectPhase::Completed,
                )
            }
            CompletionDisposition::AbortedBeforeCommit => {
                if !matches!(view.phase, EffectPhase::Registered | EffectPhase::Prepared)
                    || view.outcome.is_some()
                {
                    return Err(failure(PortalErrorCode::OutOfOrder, RetryClass::AfterQuery));
                }
                (
                    TerminalRequest::aborted(-125)
                        .with_manifest_digest(request.terminal_digest().to_wire_bytes())
                        .map_err(map_registry_error)?,
                    AbiEffectPhase::Aborted,
                )
            }
        };
        if self.scope_tombstone_count(slot.scope)?
            >= usize::try_from(scope.max_tombstones).unwrap_or(usize::MAX)
        {
            return Err(failure(PortalErrorCode::Backpressure, RetryClass::Never));
        }
        let receipt = self.reserve_receipt(
            request.context().request_digest(),
            ReceiptKind::EffectCompleted,
            projection.authority_epoch,
            projection.binding_epoch,
            slot.selector.to_wire_bytes(),
        )?;
        let stage = receipt.stage(abi_phase);
        let response = Self::lifecycle_receipt(
            slot.scope,
            slot.selector,
            projection.authority_epoch,
            projection.binding_epoch,
            stage,
        )?;
        let terminalization = self
            .registry
            .stage_terminal(self.owner, slot.portal, terminal)
            .map_err(map_registry_error)?;
        if terminalization.publication.is_some() {
            return Err(failure(
                PortalErrorCode::InternalInvariant,
                RetryClass::Never,
            ));
        }
        let effect = self.effects[effect_index].as_mut().unwrap();
        effect.completion = Some((stage, spec));
        effect.latest_receipt = receipt.selector;
        self.scopes[scope_index].as_mut().unwrap().latest_receipt = receipt.selector;
        self.install_receipt(
            receipt,
            ReceiptSubject::Effect(slot.key),
            projection.authority_epoch,
            projection.binding_epoch,
        );
        Ok(response)
    }

    fn revoke(&mut self, request: RevokeScopeRequest) -> Result<ClosureReceipt, PortalFailure> {
        self.require_session(request.context().session())?;
        let scope_index = self.scope_index(request.scope())?;
        let scope = self.scopes[scope_index].unwrap();
        if let Some(existing) = scope.revoke {
            if existing.request_digest != request.context().request_digest()
                || existing.reason != request.reason()
                || existing.authority_epoch != request.context().authority_epoch()
                || existing.binding_epoch != request.context().binding_epoch()
            {
                return Err(Self::conflict(
                    request.context().request_digest(),
                    existing.request_digest,
                ));
            }
            let projection = self
                .registry
                .scope_projection(scope.key)
                .map_err(map_registry_error)?;
            return ClosureReceipt::new(
                scope.selector,
                existing.receipt,
                projection.authority_epoch,
                projection.binding_epoch,
                existing.sequence,
                ClosureStatus::Closed,
                0,
                0,
                0,
                existing.closure_digest,
                existing.request_digest,
                existing.receipt_digest,
            )
            .map_err(map_wire_invariant);
        }

        let projection = self.require_context(request.context(), scope.key)?;
        let tombstones = self.scope_tombstone_count(scope.selector)?;
        let terminalized = tombstones
            .checked_add(projection.live_effects)
            .ok_or_else(|| failure(PortalErrorCode::Backpressure, RetryClass::Never))?;
        if terminalized > usize::try_from(scope.max_tombstones).unwrap_or(usize::MAX) {
            return Err(failure(PortalErrorCode::Backpressure, RetryClass::Never));
        }
        for effect in self
            .effects
            .iter()
            .flatten()
            .copied()
            .filter(|effect| effect.scope == scope.selector)
        {
            let view = self.effect_view(effect)?;
            if view.phase == EffectPhase::Committed
                && !view
                    .outcome
                    .is_some_and(|outcome| outcome.class() != EffectOutcomeClass::Indeterminate)
            {
                // Revoking now would cut off the only service binding capable
                // of recording or reconciling an honest committed outcome.
                return Err(failure(PortalErrorCode::Conflict, RetryClass::AfterQuery));
            }
            if view.publication_pending {
                return Err(failure(PortalErrorCode::OutOfOrder, RetryClass::AfterQuery));
            }
        }

        let receipt = self.reserve_receipt(
            request.context().request_digest(),
            ReceiptKind::Closure,
            projection
                .authority_epoch
                .checked_add(1)
                .ok_or_else(|| failure(PortalErrorCode::Backpressure, RetryClass::Never))?,
            projection.binding_epoch,
            scope.selector.to_wire_bytes(),
        )?;
        self.registry
            .revoke_nonpublishing_with_recorded_outcomes(scope.key)
            .map_err(map_registry_error)?;
        let closed = self
            .registry
            .scope_projection(scope.key)
            .map_err(map_registry_error)?;
        if closed.phase != ScopePhase::Revoked
            || closed.live_effects != 0
            || closed.pending_publications != 0
            || closed.credits.retained != 0
        {
            return Err(failure(
                PortalErrorCode::InternalInvariant,
                RetryClass::Never,
            ));
        }
        let closure_digest = make_closure_digest(scope.selector, closed, request.reason());
        let response = ClosureReceipt::new(
            scope.selector,
            receipt.selector,
            closed.authority_epoch,
            closed.binding_epoch,
            receipt.sequence,
            ClosureStatus::Closed,
            0,
            0,
            0,
            closure_digest,
            request.context().request_digest(),
            receipt.receipt_digest,
        )
        .map_err(map_wire_invariant)?;
        self.scopes[scope_index].as_mut().unwrap().revoke = Some(RevokeRecord {
            request_digest: request.context().request_digest(),
            reason: request.reason(),
            authority_epoch: request.context().authority_epoch(),
            binding_epoch: request.context().binding_epoch(),
            receipt: receipt.selector,
            sequence: receipt.sequence,
            receipt_digest: receipt.receipt_digest,
            closure_digest,
        });
        self.scopes[scope_index].as_mut().unwrap().latest_receipt = receipt.selector;
        self.install_receipt(
            receipt,
            ReceiptSubject::Scope(scope.key),
            closed.authority_epoch,
            closed.binding_epoch,
        );
        Ok(response)
    }

    fn query_scope(
        &mut self,
        session: SessionHandle,
        request: QueryScopeRequest,
    ) -> Result<ScopeObservation, PortalFailure> {
        self.require_session(session)?;
        let scope = self.scopes[self.scope_index(request.handle())?].unwrap();
        let projection = self
            .registry
            .scope_projection(scope.key)
            .map_err(map_registry_error)?;
        let live_effects = u32::try_from(projection.live_effects)
            .map_err(|_| failure(PortalErrorCode::LimitExceeded, RetryClass::Never))?;
        let pending_publications = u32::try_from(projection.pending_publications)
            .map_err(|_| failure(PortalErrorCode::LimitExceeded, RetryClass::Never))?;
        let retained_owners = u32::try_from(projection.credits.retained)
            .map_err(|_| failure(PortalErrorCode::LimitExceeded, RetryClass::Never))?;
        let state_digest = make_scope_state_digest(scope.selector, projection);
        ScopeObservation::new(
            scope.selector,
            projection.authority_epoch,
            projection.binding_epoch,
            wire_revision(projection.revision)?,
            projection.domain_revision,
            map_scope_phase(projection.phase),
            live_effects,
            pending_publications,
            retained_owners,
            scope.latest_receipt,
            state_digest,
        )
        .map_err(map_wire_invariant)
    }

    fn query_effect(
        &mut self,
        session: SessionHandle,
        request: QueryEffectRequest,
    ) -> Result<EffectObservation, PortalFailure> {
        self.require_session(session)?;
        let slot = self.effects[self.effect_index(request.handle())?].unwrap();
        let scope = self.scopes[self.scope_index(slot.scope)?].unwrap();
        let projection = self
            .registry
            .scope_projection(scope.key)
            .map_err(map_registry_error)?;
        let view = self.effect_view(slot)?;
        if projection.phase == ScopePhase::Active
            && (slot.portal.authority_epoch() != projection.authority_epoch
                || slot.portal.binding_epoch() != projection.binding_epoch
                || view.identity.binding_epoch() != slot.portal.binding_epoch())
        {
            return Err(
                failure(PortalErrorCode::StaleHandle, RetryClass::AfterQuery)
                    .with_epochs(projection.authority_epoch, projection.binding_epoch),
            );
        }
        let phase = project_effect_phase(&view);
        let outcome = view
            .outcome
            .map(|outcome| {
                EffectOutcomeObservation::new(
                    map_outcome_class(outcome.class()),
                    outcome.result(),
                    Digest::from_wire_bytes(outcome.digest()),
                )
            })
            .transpose()
            .map_err(map_wire_invariant)?;
        let terminal_digest = view
            .terminal
            .as_ref()
            .and_then(|terminal| terminal.manifest_digest())
            .map(Digest::from_wire_bytes);
        let state_digest =
            make_effect_state_digest(scope.selector, slot.selector, projection, &view);
        EffectObservation::new(
            scope.selector,
            slot.selector,
            projection.authority_epoch,
            view.identity.binding_epoch(),
            wire_revision(projection.revision)?,
            phase,
            outcome,
            terminal_digest,
            lifecycle_flags(phase, view.publication_pending),
            slot.latest_receipt,
            slot.registration.request_digest,
            state_digest,
        )
        .map_err(map_wire_invariant)
    }

    fn query_receipt(
        &mut self,
        session: SessionHandle,
        request: QueryReceiptRequest,
    ) -> Result<ReceiptObservation, PortalFailure> {
        self.require_session(session)?;
        let receipt = self.receipts[self.receipt_index(request.handle())?].unwrap();
        let status = receipt_status(self.registry, receipt)?;
        ReceiptObservation::new(
            receipt.selector,
            receipt.authority_epoch,
            receipt.binding_epoch,
            receipt.sequence,
            receipt.kind,
            status,
            receipt.request_digest,
            receipt.receipt_digest,
        )
        .map_err(map_wire_invariant)
    }
}
