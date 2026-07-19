// SPDX-License-Identifier: MPL-2.0

//! Hardware-only production typestate for a registry-owned CSER adapter.
//!
//! This module deliberately owns no effect, scope, binding, or commit gate.
//! Its identities are descriptive hardware coordinates which a kernel adapter
//! may bind to its own authoritative registry. The legacy Stage 5B `Portal`
//! remains a separate regression API.

use alloc::boxed::Box;
use bitflags::bitflags;
use core::{
    hint::spin_loop,
    marker::PhantomPinned,
    mem::{ManuallyDrop, forget, size_of},
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
};

use zerocopy::IntoBytes;

use virtio_drivers::{
    Error as VirtioError,
    device::blk::{BlkReq, BlkResp, RespStatus, SECTOR_SIZE},
    queue::{PreparedVirtQueue, VirtQueue},
    transport::{
        DeviceStatus, DeviceType, InterruptStatus, Transport,
        pci::{
            PciTransport, VirtioPciError,
            bus::{Command, DeviceFunction},
        },
    },
};

use crate::{
    dma::{self, OstdHal},
    pci::{self, DeviceBdf, Root},
};

const QUEUE_INDEX: u16 = 0;
const QUEUE_SIZE: usize = 16;
const POLL_LIMIT: usize = 10_000_000;
const EXPECTED_USED_LEN: u32 = (SECTOR_SIZE + size_of::<BlkResp>()) as u32;
const PUBLISHED_REQUEST_SHARE_COUNTS: (usize, usize) = (3, 0);
const POPPED_REQUEST_SHARE_COUNTS: (usize, usize) = (3, 3);
const SESSION_NAMESPACE: u64 = 0x4e58_5052_0000_0000;
const SESSION_SEQUENCE_MASK: u64 = 0xffff;
const PREPARATION_RECEIPT_DOMAIN: u64 = 0x4e58_5052_4550_4152;
const PREPARATION_ROLLBACK_DOMAIN: u64 = 0x4e58_5052_524f_4c4c;
const PREPARATION_INDETERMINATE_DOMAIN: u64 = 0x4e58_5052_494e_4445;
const PREPARATION_DMA_OWNER_COUNT: usize = 3;
const PREPARATION_REQUEST_SHARE_COUNT: usize = 3;
const MIN_TRANSPORT_CLAIM_COUNT: usize = 3;
const MAX_TRANSPORT_CLAIM_COUNT: usize = 4;

static NEXT_PRODUCTION_OWNER_ID: AtomicU64 = AtomicU64::new(1);
static PREPARATION_GATE_OWNER: AtomicU64 = AtomicU64::new(0);

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct NexusBlkFeatures: u64 {
        const RO = 1 << 5;
        const VERSION_1 = 1 << 32;
        const ACCESS_PLATFORM = 1 << 33;
    }
}

const REQUIRED_FEATURES: NexusBlkFeatures = NexusBlkFeatures::RO
    .union(NexusBlkFeatures::VERSION_1)
    .union(NexusBlkFeatures::ACCESS_PLATFORM);

type Queue = VirtQueue<OstdHal, QUEUE_SIZE>;
type PreparedQueue = PreparedVirtQueue<OstdHal, QUEUE_SIZE>;

/// Completion-delivery mode selected before the queue becomes device-visible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionMode {
    /// Preserve the Stage-5-compatible used-ring polling path.
    Polling,
    /// Request used-buffer interrupts for a real IRQ actor.
    Interrupt,
}

impl CompletionMode {
    const fn device_notifications_enabled(self) -> bool {
        matches!(self, Self::Interrupt)
    }

    const fn receipt_tag(self) -> u64 {
        match self {
            Self::Polling => 1,
            Self::Interrupt => 2,
        }
    }
}

/// Opaque identity of one hardware-preparation attempt.
///
/// Unlike [`DeviceSessionIdentity`], callers cannot reconstruct this value
/// from coordinates. It binds a request to the unique `ProductionDevice`
/// owner which started the attempt, including attempts that fail before a
/// descriptor token exists. It is descriptive after issuance and grants no
/// queue, DMA, or transport authority by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparationAttemptIdentity {
    owner_id: u64,
    sequence: u64,
}

impl PreparationAttemptIdentity {
    /// Returns the facade-local owner namespace.
    pub const fn owner_id(self) -> u64 {
        self.owner_id
    }

    /// Returns the monotonically allocated attempt sequence for that owner.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// Successful hardware-preparation evidence for one exact live request.
///
/// Only [`ProductionDevice::issue_preparation_receipt`] can place this
/// non-copyable value inside a [`ReceiptedPreparedRequest`]. Before issuance it
/// rechecks the device owner, active session, attempt, BDF, queue, descriptor
/// token, device generation, all three live DMA owners and shares, and the live
/// PCI transport claims. Callers can only borrow the receipt while that wrapper
/// continues to own the exact prepared request.
#[must_use = "bind the verified hardware preparation to the owning causal transition"]
#[derive(Debug, Eq, PartialEq)]
pub struct PreparationReceipt {
    attempt: PreparationAttemptIdentity,
    identity: DeviceSessionIdentity,
    completion_mode: CompletionMode,
    dma_owner_count: u8,
    dma_share_count: u8,
    transport_claim_count: u8,
    digest: u64,
}

impl PreparationReceipt {
    /// Returns the opaque preparation-attempt identity.
    pub const fn attempt(&self) -> PreparationAttemptIdentity {
        self.attempt
    }

    /// Returns the exact live request coordinates which were revalidated.
    pub const fn identity(&self) -> DeviceSessionIdentity {
        self.identity
    }

    /// Returns the completion mode fixed before queue exposure.
    pub const fn completion_mode(&self) -> CompletionMode {
        self.completion_mode
    }

    /// Returns the number of exact active DMA owners observed at issuance.
    pub const fn dma_owner_count(&self) -> u8 {
        self.dma_owner_count
    }

    /// Returns the number of live request-buffer shares observed at issuance.
    pub const fn dma_share_count(&self) -> u8 {
        self.dma_share_count
    }

    /// Returns the number of owner-backed MMIO subrange claims observed.
    pub const fn transport_claim_count(&self) -> u8 {
        self.transport_claim_count
    }

    /// Returns a domain-separated digest of every validated coordinate.
    pub const fn digest(&self) -> u64 {
        self.digest
    }
}

/// How one preparation attempt reached verified rollback quiescence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparationRollbackKind {
    /// Preparation failed before a live `PreparedRequest` was returned.
    UnexposedFailure,
    /// A returned prepared owner completed reset and IOTLB closure.
    PreparedCancellation,
}

impl PreparationRollbackKind {
    const fn receipt_tag(self) -> u64 {
        match self {
            Self::UnexposedFailure => 1,
            Self::PreparedCancellation => 2,
        }
    }
}

/// Verified absence of a preparation attempt from active hardware state.
///
/// This receipt is emitted only after the owning facade observes no active
/// request, no DMA generation, owner, or share, and no live transport claim.
/// It is opaque and deliberately neither `Clone` nor `Copy`.
#[must_use = "bind verified rollback quiescence to the owning causal transition"]
#[derive(Debug, Eq, PartialEq)]
pub struct PreparationRollbackReceipt {
    attempt: PreparationAttemptIdentity,
    request_identity: Option<DeviceSessionIdentity>,
    device_bdf: DeviceBdf,
    attempt_device_generation: u64,
    quiescent_device_generation: u64,
    kind: PreparationRollbackKind,
    digest: u64,
}

impl PreparationRollbackReceipt {
    /// Returns the exact opaque attempt which became quiescent.
    pub const fn attempt(&self) -> PreparationAttemptIdentity {
        self.attempt
    }

    /// Returns prepared-request coordinates when a live request had existed.
    pub const fn request_identity(&self) -> Option<DeviceSessionIdentity> {
        self.request_identity
    }

    /// Returns the device owned by the preparation attempt.
    pub const fn device_bdf(&self) -> DeviceBdf {
        self.device_bdf
    }

    /// Returns the generation in which the preparation attempt began.
    pub const fn device_generation(&self) -> u64 {
        self.attempt_device_generation
    }

    /// Returns the facade generation after rollback became quiescent.
    ///
    /// An unexposed constructor failure leaves the generation unchanged. A
    /// prepared cancellation records the successor generation installed by
    /// its acknowledged whole-device reset.
    pub const fn quiescent_device_generation(&self) -> u64 {
        self.quiescent_device_generation
    }

    /// Returns the path which established quiescence.
    pub const fn kind(&self) -> PreparationRollbackKind {
        self.kind
    }

    /// Returns a domain-separated digest of the attempt and zero-owner state.
    pub const fn digest(&self) -> u64 {
        self.digest
    }
}

/// Fail-closed observation returned instead of forged rollback evidence.
///
/// The owner itself remains in the production facade or its static DMA/MMIO
/// ledgers. This value is diagnostic, not teardown authority; dropping it does
/// not release retained hardware state.
#[must_use = "retain the hardware owner and resolve the indeterminate preparation"]
#[derive(Debug, Eq, PartialEq)]
pub struct PreparationIndeterminate {
    attempt: PreparationAttemptIdentity,
    device_bdf: DeviceBdf,
    device_generation: u64,
    current_device_generation: u64,
    active_request: bool,
    hardware_certain: bool,
    dma_generation: u64,
    dma_device_exposed: bool,
    dma_reset_acked: bool,
    dma_owner_count: u8,
    dma_active_owner_count: u8,
    dma_owner_generations_match: bool,
    dma_request_share_count: u8,
    dma_request_unshare_count: u8,
    dma_active_request_shares: u8,
    transport_active: bool,
    transport_claim_count: u8,
    observation_digest: u64,
}

impl PreparationIndeterminate {
    /// Returns the exact attempt whose rollback could not be certified.
    pub const fn attempt(&self) -> PreparationAttemptIdentity {
        self.attempt
    }

    /// Returns the owned device coordinates.
    pub const fn device_bdf(&self) -> DeviceBdf {
        self.device_bdf
    }

    /// Returns the preparation's device generation.
    pub const fn device_generation(&self) -> u64 {
        self.device_generation
    }

    /// Returns the facade generation observed when certification failed.
    pub const fn current_device_generation(&self) -> u64 {
        self.current_device_generation
    }

    /// Reports whether the facade still retains an active request record.
    pub const fn active_request(&self) -> bool {
        self.active_request
    }

    /// Reports whether every attempted PCI status/command rollback readback was exact.
    pub const fn hardware_certain(&self) -> bool {
        self.hardware_certain
    }

    /// Returns the DMA generation still observed by the owner ledger.
    pub const fn dma_generation(&self) -> u64 {
        self.dma_generation
    }

    /// Reports whether any address in the observed DMA generation was exposed.
    pub const fn dma_device_exposed(&self) -> bool {
        self.dma_device_exposed
    }

    /// Reports whether reset was acknowledged for the observed DMA generation.
    pub const fn dma_reset_acked(&self) -> bool {
        self.dma_reset_acked
    }

    /// Returns the number of DMA owners still retained in the ledger.
    pub const fn dma_owner_count(&self) -> u8 {
        self.dma_owner_count
    }

    /// Returns the number of DMA owners still in their active state.
    pub const fn dma_active_owner_count(&self) -> u8 {
        self.dma_active_owner_count
    }

    /// Reports whether every retained owner matches the observed generation.
    pub const fn dma_owner_generations_match(&self) -> bool {
        self.dma_owner_generations_match
    }

    /// Returns the request-buffer share count observed by the DMA ledger.
    pub const fn dma_request_share_count(&self) -> u8 {
        self.dma_request_share_count
    }

    /// Returns the request-buffer unshare count observed by the DMA ledger.
    pub const fn dma_request_unshare_count(&self) -> u8 {
        self.dma_request_unshare_count
    }

    /// Returns the number of request shares still device-active.
    pub const fn dma_active_request_shares(&self) -> u8 {
        self.dma_active_request_shares
    }

    /// Reports whether the transport-claim lifecycle remains active.
    pub const fn transport_active(&self) -> bool {
        self.transport_active
    }

    /// Returns the number of retained MMIO subrange claims.
    pub const fn transport_claim_count(&self) -> u8 {
        self.transport_claim_count
    }

    /// Returns a domain-separated fingerprint of the complete observation.
    ///
    /// This supports stable comparison and persistence; it is not a MAC,
    /// signature, capability, or recovery authority.
    pub const fn observation_digest(&self) -> u64 {
        self.observation_digest
    }
}

/// Evidence attached to a recoverable preparation rejection.
#[must_use = "inspect rollback evidence or retain the indeterminate hardware state"]
#[derive(Debug, Eq, PartialEq)]
pub enum PreparationFailureEvidence {
    /// A preflight rejection occurred before any preparation attempt began.
    NotStarted,
    /// The exact attempt is fully quiescent and has a typed receipt.
    RolledBack(PreparationRollbackReceipt),
    /// At least one owner or claim remains uncertain and no receipt exists.
    Indeterminate(PreparationIndeterminate),
}

/// Evidence for a hardware attempt whose global start permit was consumed.
///
/// There is intentionally no `NotStarted` variant: every failure after permit
/// consumption must either prove rollback or retain an indeterminate latch.
#[must_use = "publish rollback or retain the indeterminate hardware state"]
#[derive(Debug, Eq, PartialEq)]
pub enum StartedPreparationFailureEvidence {
    /// The exact started attempt returned to complete quiescence.
    RolledBack(PreparationRollbackReceipt),
    /// The attempt remains fail-closed and no rollback receipt exists.
    Indeterminate(PreparationIndeterminate),
}

/// Failure from consuming an owner-bound [`PreparationStartPermit`].
#[must_use = "inspect the cause and started-attempt evidence"]
#[derive(Debug, Eq, PartialEq)]
pub struct StartedPrepareReadFailure {
    error: PrepareReadError,
    evidence: StartedPreparationFailureEvidence,
}

impl StartedPrepareReadFailure {
    /// Returns the hardware preparation rejection.
    pub const fn error(&self) -> &PrepareReadError {
        &self.error
    }

    /// Borrows rollback or indeterminate evidence for the started attempt.
    pub const fn evidence(&self) -> &StartedPreparationFailureEvidence {
        &self.evidence
    }

    /// Splits the cause from its non-copyable evidence.
    pub fn into_parts(self) -> (PrepareReadError, StartedPreparationFailureEvidence) {
        (self.error, self.evidence)
    }

    fn into_legacy_error(self) -> PrepareReadError {
        if matches!(
            self.evidence,
            StartedPreparationFailureEvidence::Indeterminate(_)
        ) {
            PrepareReadError::RollbackIndeterminate
        } else {
            self.error
        }
    }
}

/// Recoverable preparation failure paired with trustworthy hardware evidence.
#[must_use = "inspect the cause and retain its preparation evidence"]
#[derive(Debug, Eq, PartialEq)]
pub struct PrepareReadFailure {
    error: PrepareReadError,
    evidence: PreparationFailureEvidence,
}

impl PrepareReadFailure {
    const fn not_started(error: PrepareReadError) -> Self {
        Self {
            error,
            evidence: PreparationFailureEvidence::NotStarted,
        }
    }

    fn from_started(failure: StartedPrepareReadFailure) -> Self {
        let evidence = match failure.evidence {
            StartedPreparationFailureEvidence::RolledBack(receipt) => {
                PreparationFailureEvidence::RolledBack(receipt)
            }
            StartedPreparationFailureEvidence::Indeterminate(indeterminate) => {
                PreparationFailureEvidence::Indeterminate(indeterminate)
            }
        };
        Self {
            error: failure.error,
            evidence,
        }
    }

    /// Returns the original preparation rejection.
    pub const fn error(&self) -> &PrepareReadError {
        &self.error
    }

    /// Borrows the rollback, preflight, or indeterminate evidence.
    pub const fn evidence(&self) -> &PreparationFailureEvidence {
        &self.evidence
    }

    /// Splits the cause from its non-copyable evidence.
    pub fn into_parts(self) -> (PrepareReadError, PreparationFailureEvidence) {
        (self.error, self.evidence)
    }
}

/// Failure-atomic rejection before a preparation success receipt is issued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparationEvidenceError {
    /// The facade no longer has a live preparation session.
    NoActiveRequest,
    /// The request belongs to another `ProductionDevice` owner.
    ForeignOwner,
    /// The request belongs to another preparation attempt.
    WrongAttempt,
    /// The active facade session and prepared request disagree.
    WrongSession,
    /// The request names another PCI function or BDF.
    WrongDevice,
    /// The request names another VirtIO queue.
    WrongQueue,
    /// The live prepared queue contains another descriptor head.
    DescriptorTokenMismatch,
    /// The retained transport no longer reports `FEATURES_OK | DRIVER_OK`.
    TransportStatusMismatch,
    /// The facade, active request, and ledger disagree on device generation.
    StaleDeviceGeneration,
    /// The DMA ledger belongs to another or unexposed generation.
    DmaGenerationMismatch,
    /// The exact three active DMA owners are not retained.
    DmaOwnerStateMismatch,
    /// The exact three still-active request shares are not retained.
    DmaShareStateMismatch,
    /// The PCI transport does not retain its complete owner-backed claims.
    TransportClaimMismatch,
    /// This exact preparation attempt already issued its sole receipt.
    DuplicateIssuance,
    /// The coupled receipt differs from the freshly revalidated live projection.
    ReceiptMismatch,
}

/// A rejected receipt issuance which returns the exact prepared owner.
///
/// No issuance bit, queue state, DMA state, transport claim, or request owner
/// changes on failure.
#[must_use = "inspect the error and recover or retain the exact prepared request"]
pub struct PreparationEvidenceFailure {
    error: PreparationEvidenceError,
    owner: PreparedRequest,
}

impl PreparationEvidenceFailure {
    /// Returns the read-only evidence rejection.
    pub const fn error(&self) -> PreparationEvidenceError {
        self.error
    }

    /// Borrows the unchanged prepared request.
    pub const fn owner(&self) -> &PreparedRequest {
        &self.owner
    }

    /// Recovers the exact prepared request supplied to issuance.
    pub fn into_owner(self) -> PreparedRequest {
        self.owner
    }
}

/// Exact prepared owner coupled to its sole successful receipt.
///
/// The receipt has no public extraction method: it can only be borrowed while
/// this wrapper retains the real transport, queue, buffers, and DMA lifecycle.
/// Consuming publication or cancellation consumes both together.
#[must_use = "publish, cancel, or retain the receipted prepared request"]
pub struct ReceiptedPreparedRequest {
    request: PreparedRequest,
    receipt: PreparationReceipt,
}

/// Failed publication preflight which returns the complete receipted owner.
#[must_use = "inspect the error and recover or retain the receipted request"]
pub struct PreparationPublishFailure {
    error: PreparationEvidenceError,
    owner: ReceiptedPreparedRequest,
}

impl PreparationPublishFailure {
    /// Returns the read-only publication rejection.
    pub const fn error(&self) -> PreparationEvidenceError {
        self.error
    }

    /// Borrows the unchanged receipted owner.
    pub const fn owner(&self) -> &ReceiptedPreparedRequest {
        &self.owner
    }

    /// Recovers the exact receipted owner supplied to preflight.
    pub fn into_owner(self) -> ReceiptedPreparedRequest {
        self.owner
    }
}

/// Sole authority for the infallible `avail.idx` Release publication.
///
/// It can only be constructed by `ProductionDevice` after revalidating the
/// active attempt, coupled receipt, DMA ownership, and transport status.
#[must_use = "apply publication or retain the prevalidated owner"]
pub struct PreparedPublishIntent {
    owner: ReceiptedPreparedRequest,
}

const _: () = assert!(size_of::<PreparationReceipt>() == 56);
const _: () = assert!(size_of::<PreparationRollbackReceipt>() == 80);
const _: () = assert!(size_of::<PreparationIndeterminate>() == 64);
const _: () = assert!(size_of::<PrepareReadFailure>() <= 192);

/// Descriptive coordinates of one prepared hardware request.
///
/// This value is not transition authority. In particular, presenting the same
/// integers to another registry cannot authorize publication or completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceSessionIdentity {
    device_session: u64,
    device_bdf: DeviceBdf,
    queue: u16,
    descriptor_token: u16,
    device_generation: u64,
}

impl DeviceSessionIdentity {
    /// Reconstructs descriptive coordinates from a registry envelope.
    ///
    /// This does not claim a device or grant transition authority. It exists
    /// so the main adapter can compare independently retained registry fields
    /// with the facade's immutable prepared-request identity.
    pub const fn from_coordinates(
        device_session: u64,
        device_bdf: DeviceBdf,
        queue: u16,
        descriptor_token: u16,
        device_generation: u64,
    ) -> Self {
        Self {
            device_session,
            device_bdf,
            queue,
            descriptor_token,
            device_generation,
        }
    }

    /// Returns the facade-local device-session namespace.
    pub const fn device_session(self) -> u64 {
        self.device_session
    }

    /// Returns the exact owned PCI function.
    pub const fn device_bdf(self) -> DeviceBdf {
        self.device_bdf
    }

    /// Returns the VirtIO queue index.
    pub const fn queue(self) -> u16 {
        self.queue
    }

    /// Returns the prepared descriptor-head token.
    pub const fn descriptor_token(self) -> u16 {
        self.descriptor_token
    }

    /// Returns the device generation in which the descriptor was prepared.
    pub const fn device_generation(self) -> u64 {
        self.device_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveSession {
    identity: DeviceSessionIdentity,
    attempt: PreparationAttemptIdentity,
    preparation_receipt_issued: bool,
    reset_acknowledged: bool,
}

#[derive(Clone, Copy)]
struct PreparationDeviceProjection {
    owner_id: u64,
    device_function: DeviceFunction,
    device_bdf: DeviceBdf,
    device_generation: u64,
}

#[derive(Clone, Copy)]
struct PreparationRequestProjection {
    attempt: PreparationAttemptIdentity,
    identity: DeviceSessionIdentity,
    completion_mode: CompletionMode,
    device_function: DeviceFunction,
    descriptor_token: u16,
    transport_ready: bool,
}

fn preparation_request_projection(request: &PreparedRequest) -> PreparationRequestProjection {
    PreparationRequestProjection {
        attempt: request.attempt,
        identity: request.identity,
        completion_mode: request.completion_mode,
        device_function: request.device_function,
        descriptor_token: request.queue.token(),
        transport_ready: request
            .transport
            .get_status()
            .contains(DeviceStatus::FEATURES_OK | DeviceStatus::DRIVER_OK),
    }
}

fn allocate_production_owner_id() -> Result<u64, ProductionDeviceClaimError> {
    NEXT_PRODUCTION_OWNER_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .map_err(|_| ProductionDeviceClaimError::OwnerIdentityExhausted)
}

const fn next_device_generation(generation: u64) -> Result<u64, ResetGenerationError> {
    match generation.checked_add(1) {
        Some(next) => Ok(next),
        None => Err(ResetGenerationError::GenerationOverflow),
    }
}

const fn receipt_mix(accumulator: u64, value: u64) -> u64 {
    accumulator
        .rotate_left(9)
        .wrapping_add(value ^ 0x9e37_79b9_7f4a_7c15)
        .wrapping_mul(0x1000_0000_01b3)
}

fn preparation_receipt_digest(
    request: PreparationRequestProjection,
    dma_owner_count: usize,
    dma_share_count: usize,
    transport_claim_count: usize,
) -> u64 {
    let identity = request.identity;
    let bdf = identity.device_bdf();
    let mut digest = PREPARATION_RECEIPT_DOMAIN;
    for value in [
        request.attempt.owner_id,
        request.attempt.sequence,
        identity.device_session(),
        u64::from(bdf.bus()),
        u64::from(bdf.device()),
        u64::from(bdf.function()),
        u64::from(identity.queue()),
        u64::from(identity.descriptor_token()),
        identity.device_generation(),
        request.completion_mode.receipt_tag(),
        dma_owner_count as u64,
        dma_share_count as u64,
        transport_claim_count as u64,
    ] {
        digest = receipt_mix(digest, value);
    }
    digest | 1
}

fn prepare_success_receipt(
    device: PreparationDeviceProjection,
    active: ActiveSession,
    request: PreparationRequestProjection,
    dma: dma::PreparationDmaObservation,
    transport: pci::TransportClaimObservation,
    expected_issued: bool,
) -> Result<PreparationReceipt, PreparationEvidenceError> {
    if request.attempt.owner_id != device.owner_id || active.attempt.owner_id != device.owner_id {
        return Err(PreparationEvidenceError::ForeignOwner);
    }
    if request.attempt.sequence != active.attempt.sequence {
        return Err(PreparationEvidenceError::WrongAttempt);
    }
    if request.identity != active.identity {
        return Err(PreparationEvidenceError::WrongSession);
    }
    if request.device_function != device.device_function
        || request.identity.device_bdf() != device.device_bdf
    {
        return Err(PreparationEvidenceError::WrongDevice);
    }
    if request.identity.queue() != QUEUE_INDEX {
        return Err(PreparationEvidenceError::WrongQueue);
    }
    if request.descriptor_token != request.identity.descriptor_token() {
        return Err(PreparationEvidenceError::DescriptorTokenMismatch);
    }
    if !request.transport_ready {
        return Err(PreparationEvidenceError::TransportStatusMismatch);
    }
    if request.identity.device_generation() != device.device_generation
        || active.identity.device_generation() != device.device_generation
    {
        return Err(PreparationEvidenceError::StaleDeviceGeneration);
    }
    if dma.generation != device.device_generation || !dma.device_exposed || dma.reset_acked {
        return Err(PreparationEvidenceError::DmaGenerationMismatch);
    }
    if dma.owner_count != PREPARATION_DMA_OWNER_COUNT
        || dma.active_owner_count != PREPARATION_DMA_OWNER_COUNT
        || !dma.owner_generations_match
    {
        return Err(PreparationEvidenceError::DmaOwnerStateMismatch);
    }
    if dma.request_share_count != PREPARATION_REQUEST_SHARE_COUNT
        || dma.request_unshare_count != 0
        || dma.active_request_shares != PREPARATION_REQUEST_SHARE_COUNT
    {
        return Err(PreparationEvidenceError::DmaShareStateMismatch);
    }
    if !transport.active
        || !(MIN_TRANSPORT_CLAIM_COUNT..=MAX_TRANSPORT_CLAIM_COUNT).contains(&transport.claim_count)
    {
        return Err(PreparationEvidenceError::TransportClaimMismatch);
    }
    if active.preparation_receipt_issued != expected_issued {
        return Err(PreparationEvidenceError::DuplicateIssuance);
    }

    Ok(PreparationReceipt {
        attempt: request.attempt,
        identity: request.identity,
        completion_mode: request.completion_mode,
        dma_owner_count: dma.owner_count as u8,
        dma_share_count: dma.active_request_shares as u8,
        transport_claim_count: transport.claim_count as u8,
        digest: preparation_receipt_digest(
            request,
            dma.owner_count,
            dma.active_request_shares,
            transport.claim_count,
        ),
    })
}

const fn dma_preparation_is_quiescent(observation: dma::PreparationDmaObservation) -> bool {
    observation.generation == 0
        && !observation.device_exposed
        && !observation.reset_acked
        && observation.owner_count == 0
        && observation.active_owner_count == 0
        && observation.owner_generations_match
        && observation.request_share_count == 0
        && observation.request_unshare_count == 0
        && observation.active_request_shares == 0
}

const fn transport_preparation_is_quiescent(observation: pci::TransportClaimObservation) -> bool {
    !observation.active && observation.claim_count == 0
}

struct PreparedRollbackReceipt {
    attempt: PreparationAttemptIdentity,
    request_identity: Option<DeviceSessionIdentity>,
    device_bdf: DeviceBdf,
    attempt_device_generation: u64,
    quiescent_device_generation: u64,
    kind: PreparationRollbackKind,
    digest: u64,
}

impl PreparedRollbackReceipt {
    fn finish(self) -> PreparationRollbackReceipt {
        PreparationRollbackReceipt {
            attempt: self.attempt,
            request_identity: self.request_identity,
            device_bdf: self.device_bdf,
            attempt_device_generation: self.attempt_device_generation,
            quiescent_device_generation: self.quiescent_device_generation,
            kind: self.kind,
            digest: self.digest,
        }
    }
}

fn rollback_receipt_digest(
    attempt: PreparationAttemptIdentity,
    request_identity: Option<DeviceSessionIdentity>,
    device_bdf: DeviceBdf,
    attempt_generation: u64,
    quiescent_generation: u64,
    kind: PreparationRollbackKind,
) -> u64 {
    let (device_session, queue, descriptor_token) = match request_identity {
        Some(request) => (
            request.device_session(),
            request.queue(),
            request.descriptor_token(),
        ),
        None => (0, QUEUE_INDEX, 0),
    };
    let mut digest = PREPARATION_ROLLBACK_DOMAIN;
    for value in [
        attempt.owner_id,
        attempt.sequence,
        device_session,
        u64::from(device_bdf.bus()),
        u64::from(device_bdf.device()),
        u64::from(device_bdf.function()),
        u64::from(queue),
        u64::from(descriptor_token),
        attempt_generation,
        quiescent_generation,
        kind.receipt_tag(),
    ] {
        digest = receipt_mix(digest, value);
    }
    digest | 1
}

#[derive(Clone, Copy)]
struct IndeterminateAttemptProjection {
    attempt: PreparationAttemptIdentity,
    device_bdf: DeviceBdf,
    attempt_generation: u64,
    current_generation: u64,
    active_request: bool,
    hardware_certain: bool,
}

fn preparation_indeterminate(
    attempt_projection: IndeterminateAttemptProjection,
    dma: dma::PreparationDmaObservation,
    transport: pci::TransportClaimObservation,
) -> PreparationIndeterminate {
    let IndeterminateAttemptProjection {
        attempt,
        device_bdf,
        attempt_generation,
        current_generation,
        active_request,
        hardware_certain,
    } = attempt_projection;
    let mut observation_digest = PREPARATION_INDETERMINATE_DOMAIN;
    for value in [
        attempt.owner_id,
        attempt.sequence,
        u64::from(device_bdf.bus()),
        u64::from(device_bdf.device()),
        u64::from(device_bdf.function()),
        attempt_generation,
        current_generation,
        u64::from(active_request),
        u64::from(hardware_certain),
        dma.generation,
        u64::from(dma.device_exposed),
        u64::from(dma.reset_acked),
        dma.owner_count as u64,
        dma.active_owner_count as u64,
        u64::from(dma.owner_generations_match),
        dma.request_share_count as u64,
        dma.request_unshare_count as u64,
        dma.active_request_shares as u64,
        u64::from(transport.active),
        transport.claim_count as u64,
    ] {
        observation_digest = receipt_mix(observation_digest, value);
    }
    PreparationIndeterminate {
        attempt,
        device_bdf,
        device_generation: attempt_generation,
        current_device_generation: current_generation,
        active_request,
        hardware_certain,
        dma_generation: dma.generation,
        dma_device_exposed: dma.device_exposed,
        dma_reset_acked: dma.reset_acked,
        dma_owner_count: dma.owner_count as u8,
        dma_active_owner_count: dma.active_owner_count as u8,
        dma_owner_generations_match: dma.owner_generations_match,
        dma_request_share_count: dma.request_share_count as u8,
        dma_request_unshare_count: dma.request_unshare_count as u8,
        dma_active_request_shares: dma.active_request_shares as u8,
        transport_active: transport.active,
        transport_claim_count: transport.claim_count as u8,
        observation_digest: observation_digest | 1,
    }
}

#[derive(Clone, Copy)]
struct PreparationQuiescenceProjection {
    active_request: bool,
    hardware_certain: bool,
    dma: dma::PreparationDmaObservation,
    transport: pci::TransportClaimObservation,
}

fn prepare_rollback_receipt(
    device: PreparationDeviceProjection,
    attempt: PreparationAttemptIdentity,
    request_identity: Option<DeviceSessionIdentity>,
    kind: PreparationRollbackKind,
    quiescence: PreparationQuiescenceProjection,
) -> Result<PreparedRollbackReceipt, PreparationIndeterminate> {
    let attempt_generation = request_identity.map_or(device.device_generation, |identity| {
        identity.device_generation()
    });
    let lineage_matches = match kind {
        PreparationRollbackKind::UnexposedFailure => {
            request_identity.is_none() && device.device_generation == attempt_generation
        }
        PreparationRollbackKind::PreparedCancellation => {
            request_identity.is_some()
                && attempt_generation.checked_add(1) == Some(device.device_generation)
        }
    };
    let identity_matches = attempt.owner_id == device.owner_id
        && request_identity.is_none_or(|identity| identity.device_bdf() == device.device_bdf);

    if quiescence.active_request
        || !quiescence.hardware_certain
        || !identity_matches
        || !lineage_matches
        || !dma_preparation_is_quiescent(quiescence.dma)
        || !transport_preparation_is_quiescent(quiescence.transport)
    {
        return Err(preparation_indeterminate(
            IndeterminateAttemptProjection {
                attempt,
                device_bdf: device.device_bdf,
                attempt_generation,
                current_generation: device.device_generation,
                active_request: quiescence.active_request,
                hardware_certain: quiescence.hardware_certain,
            },
            quiescence.dma,
            quiescence.transport,
        ));
    }

    Ok(PreparedRollbackReceipt {
        attempt,
        request_identity,
        device_bdf: device.device_bdf,
        attempt_device_generation: attempt_generation,
        quiescent_device_generation: device.device_generation,
        kind,
        digest: rollback_receipt_digest(
            attempt,
            request_identity,
            device.device_bdf,
            attempt_generation,
            device.device_generation,
            kind,
        ),
    })
}

/// A preparation rejection which leaves the device facade reusable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrepareReadError {
    /// Another request/reset/IOTLB lifecycle still owns this device.
    ActiveSession,
    /// A prior failed attempt retained indeterminate DMA or transport state.
    HardwareQuarantined,
    /// The DMA ledger is not quiescent before a new attempt.
    DmaPreparationBusy,
    /// PCI transport claims remain live before a new attempt.
    TransportPreparationBusy,
    /// Another facade preparation permit owns the global DMA/MMIO start gate.
    PreparationGateBusy,
    /// The supplied PCI root does not own this production device.
    ForeignRoot,
    /// A live unmasked or poisoned INTx lifecycle forbids preparation.
    PciCommandStateUnavailable,
    /// Enabling the exact PCI command bits did not survive readback.
    PciCommandReadbackMismatch,
    /// No further stable session identity can be represented.
    SessionSequenceExhausted,
    /// No further owner-bound preparation attempt can be represented.
    AttemptSequenceExhausted,
    /// The pinned PCI transport rejected the owned function.
    Transport(VirtioPciError),
    /// The owned function is not a VirtIO block device.
    WrongDeviceType,
    /// The device did not offer every required production feature.
    MissingRequiredFeatures,
    /// The device rejected the negotiated production features.
    FeatureNegotiationRejected,
    /// The queue could not be constructed.
    Queue(VirtioError),
    /// The request bounce owner could not be allocated.
    RequestDmaUnavailable,
    /// Descriptor validation failed before any available-index publication.
    Descriptor(VirtioError),
    /// Legacy preparation could not certify complete hardware rollback.
    ///
    /// Causal adapters should use `prepare_*_with_evidence` so they retain the
    /// typed [`PreparationIndeterminate`] observation instead of this summary.
    RollbackIndeterminate,
}

/// Failure-atomic validation error for a hardware generation advance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResetGenerationError {
    /// No hardware session is active.
    NoActiveSession,
    /// The reset receipt names another session or generation.
    WrongIdentity,
    /// The reset receipt belongs to another preparation attempt.
    WrongAttempt,
    /// This reset acknowledgement was already consumed.
    AlreadyApplied,
    /// The next hardware generation cannot be represented.
    GenerationOverflow,
}

/// Typed rejection before consuming reset acknowledgement into IOTLB closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionIotlbBeginError {
    /// No hardware session is active.
    NoActiveSession,
    /// The reset acknowledgement names another session or device generation.
    WrongIdentity,
    /// The reset acknowledgement belongs to another preparation attempt.
    WrongAttempt,
    /// The facade or reset acknowledgement has not consumed the generation fence.
    ResetNotApplied,
}

/// A failed IOTLB begin which returns the exact reset authority unchanged.
#[must_use = "recover or retain the unchanged reset acknowledgement"]
pub struct ProductionIotlbBeginFailure {
    error: ProductionIotlbBeginError,
    reset: ProductionResetAck,
}

impl ProductionIotlbBeginFailure {
    /// Returns the validation error without consuming the reset owner.
    pub const fn error(&self) -> ProductionIotlbBeginError {
        self.error
    }

    /// Borrows the unchanged reset owner.
    pub const fn reset(&self) -> &ProductionResetAck {
        &self.reset
    }

    /// Recovers the unchanged reset owner.
    pub fn into_reset(self) -> ProductionResetAck {
        self.reset
    }
}

/// Typed rejection while polling one retained IOTLB owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionIotlbRetryError {
    /// A zero budget cannot make progress and is rejected without consuming authority.
    ZeroPollBudget,
}

/// A failed IOTLB retry which returns the exact retained tombstone unchanged.
#[must_use = "recover or retain the unchanged IOTLB tombstone"]
pub struct ProductionIotlbRetryFailure {
    error: ProductionIotlbRetryError,
    tombstone: ProductionIotlbTombstone,
}

impl ProductionIotlbRetryFailure {
    /// Returns the retry error without consuming the tombstone.
    pub const fn error(&self) -> ProductionIotlbRetryError {
        self.error
    }

    /// Borrows the unchanged IOTLB tombstone.
    pub const fn tombstone(&self) -> &ProductionIotlbTombstone {
        &self.tombstone
    }

    /// Recovers the unchanged IOTLB tombstone.
    pub fn into_tombstone(self) -> ProductionIotlbTombstone {
        self.tombstone
    }
}

/// Typed reset-poll outcome which retains the complete reset owner on failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionResetRetryError {
    /// The bounded observation did not yet see device status zero.
    Pending,
    /// The supplied PCI root does not own this reset session.
    ForeignRoot,
    /// A live unmasked or poisoned INTx lifecycle forbids fail-closed reset.
    PciCommandStateUnavailable,
    /// Disabling bus mastering did not survive PCI command readback.
    PciCommandReadbackMismatch,
}

/// A pending or failed reset observation carrying the exact retained tombstone.
#[must_use = "retry, quarantine, or retain the unchanged reset tombstone"]
pub struct ProductionResetRetryFailure {
    error: ProductionResetRetryError,
    tombstone: ProductionResetTombstone,
}

impl ProductionResetRetryFailure {
    /// Returns the reset observation error.
    pub const fn error(&self) -> ProductionResetRetryError {
        self.error
    }

    /// Borrows the complete retained reset owner.
    pub const fn tombstone(&self) -> &ProductionResetTombstone {
        &self.tombstone
    }

    /// Recovers the complete retained reset owner.
    pub fn into_tombstone(self) -> ProductionResetTombstone {
        self.tombstone
    }
}

/// Read-only rejection before a linear hardware cancellation/reset intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareIntentError {
    /// The adapter named another retained hardware request.
    WrongIdentity,
    /// The prepared queue token no longer matches its immutable identity.
    DescriptorTokenMismatch,
    /// The request DMA ledger does not match the retained typestate projection.
    RequestShareStateMismatch {
        /// The checked share/unshare counters, or `None` for a foreign generation.
        observed: Option<(usize, usize)>,
    },
    /// A published typestate no longer contains every reset owner.
    MissingResetOwner,
}

/// A failed hardware-intent preflight which returns the unchanged linear owner.
///
/// Preflight performs read-only identity and ownership checks. Consuming this
/// value with [`Self::into_owner`] therefore recovers the exact request that
/// entered the rejected call, without reconstructing authority from its
/// descriptive coordinates.
#[must_use = "inspect the error and recover or retain the unchanged hardware owner"]
pub struct HardwareIntentFailure<T> {
    error: HardwareIntentError,
    owner: T,
}

impl<T> HardwareIntentFailure<T> {
    /// Returns the read-only preflight rejection.
    pub const fn error(&self) -> HardwareIntentError {
        self.error
    }

    /// Borrows the unchanged linear owner.
    pub const fn owner(&self) -> &T {
        &self.owner
    }

    /// Recovers the unchanged linear owner.
    pub fn into_owner(self) -> T {
        self.owner
    }
}

/// Failure-atomic validation error before software quiescence publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuiescenceApplyError {
    /// No hardware session is active.
    NoActiveSession,
    /// The IOTLB receipt names another request.
    WrongIdentity,
    /// The IOTLB receipt belongs to another preparation attempt.
    WrongAttempt,
    /// The matching whole-device reset generation was not applied.
    ResetNotApplied,
    /// The DMA closure completed for another device generation.
    WrongGeneration,
    /// The DMA closure did not cover all three retained owners.
    WrongCompletedPages,
    /// This closure receipt was already applied.
    AlreadyApplied,
}

/// Validation failure while closing a prepared request whose device cohort
/// was never installed in the semantic registry.
///
/// This is deliberately separate from the normal registry-coupled reset and
/// IOTLB plans. It exists only for the failure-atomic window in which hardware
/// preparation succeeded but no device cohort was installed. Possession
/// of [`UnregisteredPreparedCancellation`] proves that the request entered
/// this path through [`PreparedRequest::cancel_unregistered`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnregisteredCancellationError {
    /// No hardware session is active for the cancellation authority.
    NoActiveSession,
    /// The cancellation authority, facade, and hardware receipt disagree.
    WrongIdentity,
    /// The cancellation authority belongs to another preparation attempt.
    WrongAttempt,
    /// The descriptor was made visible and therefore requires registry closure.
    WasPublished,
    /// The descriptor was consumed and therefore is not a prepublication cancel.
    DescriptorPopped,
    /// The request completed and therefore is not a prepublication cancel.
    Completed,
    /// Reset did not retain exactly the three production DMA owners.
    WrongRetainedPages,
    /// The reset generation was already applied to this cancellation.
    AlreadyApplied,
    /// The next hardware generation cannot be represented.
    GenerationOverflow,
    /// IOTLB closure began before the matching reset generation was applied.
    ResetNotApplied,
    /// The closure receipt belongs to another hardware generation.
    WrongGeneration,
    /// IOTLB closure did not cover exactly the three production DMA owners.
    WrongCompletedPages,
}

/// Failure while turning completed cancellation closure into rollback evidence.
///
/// Validation errors leave every borrowed input unchanged. `Indeterminate`
/// means the typed closure receipt exists but the live facade/DMA/transport
/// projections cannot yet prove zero ownership, so no rollback receipt was
/// fabricated.
#[must_use = "retain the closure owners and resolve or report rollback failure"]
#[derive(Debug, Eq, PartialEq)]
pub enum PreparationRollbackError {
    /// The cancellation or closure coordinates were rejected before mutation.
    Cancellation(UnregisteredCancellationError),
    /// Hardware ownership could not be proven quiescent.
    Indeterminate(PreparationIndeterminate),
}

impl From<UnregisteredCancellationError> for PreparationRollbackError {
    fn from(error: UnregisteredCancellationError) -> Self {
        Self::Cancellation(error)
    }
}

/// Linear authority for the exceptional hardware-only closure which follows a
/// failure-atomic window before device-cohort installation.
///
/// This token is intentionally not cloneable. Normal enrolled requests never
/// receive one and must continue to couple facade apply with the registry's
/// reset and IOTLB acknowledgement boundaries.
///
/// The facade cannot inspect the external semantic registry: this token proves
/// the hardware cancellation path, not registry absence by itself. The owning
/// adapter must establish that no device root was installed under its
/// authoritative transition gate before constructing it.
#[must_use = "finish the unregistered reset and IOTLB closure"]
pub struct UnregisteredPreparedCancellation {
    attempt: PreparationAttemptIdentity,
    identity: DeviceSessionIdentity,
    reset_applied: bool,
    quiescence_applied: bool,
}

impl UnregisteredPreparedCancellation {
    /// Returns the owner-bound preparation attempt being closed.
    pub const fn attempt(&self) -> PreparationAttemptIdentity {
        self.attempt
    }

    /// Returns the exact unpublished hardware identity being closed.
    pub const fn identity(&self) -> DeviceSessionIdentity {
        self.identity
    }

    /// Reports whether the hardware-only exception reached full quiescence.
    pub const fn is_complete(&self) -> bool {
        self.quiescence_applied
    }
}

/// Prevalidated, linear hardware generation update.
///
/// A main-kernel adapter must create this plan while holding its root runtime
/// lock, prevalidate the matching registry reset transition, and consume both
/// in the registry's single infallible apply boundary. Creating the plan does
/// not mutate hardware or facade state; [`Self::apply`] performs only direct
/// writes through the exclusive references captured during validation.
#[must_use = "apply the generation plan in the registry reset linearization boundary"]
pub struct PreparedGenerationAdvance<'a> {
    active_reset_acknowledged: &'a mut bool,
    device_generation: &'a mut u64,
    reset_generation_applied: &'a mut bool,
    next_generation: u64,
}

impl PreparedGenerationAdvance<'_> {
    /// Applies the fully prevalidated generation update without allocation,
    /// lookup, branching, or an error path.
    pub fn apply(self) -> u64 {
        *self.active_reset_acknowledged = true;
        *self.device_generation = self.next_generation;
        *self.reset_generation_applied = true;
        self.next_generation
    }
}

/// Prevalidated, linear software-quiescence update.
///
/// The main adapter prevalidates this plan and its registry IOTLB transition
/// under the same runtime lock, then invokes [`Self::apply`] inside the
/// registry's infallible acknowledgement boundary.
#[must_use = "apply quiescence in the registry IOTLB acknowledgement boundary"]
pub struct PreparedQuiescenceApply<'a> {
    active: &'a mut Option<ActiveSession>,
    closure_applied: &'a mut bool,
    identity: DeviceSessionIdentity,
}

impl PreparedQuiescenceApply<'_> {
    /// Applies the fully prevalidated update using direct writes only.
    pub fn apply(self) -> DeviceSessionIdentity {
        *self.closure_applied = true;
        *self.active = None;
        self.identity
    }
}

/// Owner-bound read-only permission to start one hardware preparation.
///
/// The permit exclusively borrows both the production device and its opaque
/// PCI root. A normal adapter obtains it before moving its Registry record to
/// `ApplyingHardware`, keeps it across that Registry transition, and then
/// consumes [`Self::apply`]. Safe code cannot change facade/root preparation
/// state between preflight and apply, so every later hardware failure belongs
/// to a started attempt and carries rollback or indeterminate evidence.
#[must_use = "consume the permit after the causal Registry begins hardware apply"]
pub struct PreparationStartPermit<'a> {
    device: &'a mut ProductionDevice,
    root: &'a mut Root,
    start: PreparedStartCoordinates,
    gate: PreparationGate,
}

#[derive(Clone, Copy)]
struct PreparedStartCoordinates {
    attempt: PreparationAttemptIdentity,
    completion_mode: CompletionMode,
    session_sequence: u64,
    next_session_sequence: u64,
    next_attempt_sequence: u64,
}

struct PreparationGate {
    owner_id: u64,
}

impl PreparationGate {
    fn acquire(owner_id: u64) -> Option<Self> {
        PREPARATION_GATE_OWNER
            .compare_exchange(0, owner_id, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self { owner_id })
    }
}

impl Drop for PreparationGate {
    fn drop(&mut self) {
        let _ = PREPARATION_GATE_OWNER.compare_exchange(
            self.owner_id,
            0,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }
}

impl PreparationStartPermit<'_> {
    /// Returns the generation the coming attempt will bind.
    pub const fn device_generation(&self) -> u64 {
        self.device.device_generation
    }

    /// Returns the queue selected by this bounded block facade.
    pub const fn queue(&self) -> u16 {
        QUEUE_INDEX
    }

    /// Returns the prevalidated completion mode.
    pub const fn completion_mode(&self) -> CompletionMode {
        self.start.completion_mode
    }

    /// Starts the exact prevalidated attempt.
    pub fn apply(self) -> Result<PreparedRequest, StartedPrepareReadFailure> {
        self.device
            .prepare_read_sector0_with_mode(self.root, self.start, self.gate)
    }
}

/// Exclusive descriptive owner of the production hardware lifecycle.
///
/// The kernel's production registry remains the only semantic authority. This
/// object merely prevents overlapping PCI/queue/DMA generations inside the
/// facade and records when reset and IOTLB hardware closure have completed.
/// One opaque [`Root`] grants only one device claim, and `active` admits only
/// one request/reset/IOTLB lifecycle for that claimed BDF. The registry's
/// descriptive envelope does not independently prove this cross-root physical
/// exclusivity or contain whole-function reset blast radius; that obligation
/// remains here at the hardware owner boundary.
pub struct ProductionDevice {
    owner_id: u64,
    device_function: DeviceFunction,
    device_bdf: DeviceBdf,
    next_attempt_sequence: u64,
    next_session_sequence: u64,
    device_generation: u64,
    active: Option<ActiveSession>,
    indeterminate_preparation: Option<PreparationAttemptIdentity>,
}

/// Typed rejection while binding a production owner to an owned PCI root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionDeviceClaimError {
    /// The process-wide, non-zero owner namespace cannot advance without
    /// wrapping and is therefore permanently exhausted.
    OwnerIdentityExhausted,
    /// This exact [`Root`] has already transferred its device-function claim.
    DeviceAlreadyClaimed,
}

impl ProductionDevice {
    /// Claims the exact block device already owned by `root`.
    ///
    /// Failure leaves all hardware state untouched. A duplicate-root caller
    /// may consume an unused facade-local owner number, but it receives no
    /// device claim or transition authority.
    pub fn for_owned_device(root: &mut Root) -> Result<Self, ProductionDeviceClaimError> {
        let owner_id = allocate_production_owner_id()?;
        let device_function = root
            .try_claim_device_function()
            .ok_or(ProductionDeviceClaimError::DeviceAlreadyClaimed)?;
        Ok(Self {
            owner_id,
            device_function,
            device_bdf: root.device_bdf(),
            next_attempt_sequence: 1,
            next_session_sequence: 1,
            device_generation: 1,
            active: None,
            indeterminate_preparation: None,
        })
    }

    /// Returns the generation authorized by the latest acknowledged reset.
    pub const fn device_generation(&self) -> u64 {
        self.device_generation
    }

    /// Preflights the polling preparation before an external Registry begins apply.
    pub fn preflight_read_sector0<'a>(
        &'a mut self,
        root: &'a mut Root,
    ) -> Result<PreparationStartPermit<'a>, PrepareReadError> {
        self.preflight_preparation_start(root, CompletionMode::Polling)
    }

    /// Preflights interrupt-mode preparation before Registry apply begins.
    ///
    /// This does not install an IRQ actor or establish interrupt delivery.
    pub fn preflight_read_sector0_irq<'a>(
        &'a mut self,
        root: &'a mut Root,
    ) -> Result<PreparationStartPermit<'a>, PrepareReadError> {
        self.preflight_preparation_start(root, CompletionMode::Interrupt)
    }

    fn preflight_preparation_start<'a>(
        &'a mut self,
        root: &'a mut Root,
        completion_mode: CompletionMode,
    ) -> Result<PreparationStartPermit<'a>, PrepareReadError> {
        if self.indeterminate_preparation.is_some() {
            return Err(PrepareReadError::HardwareQuarantined);
        }
        if self.active.is_some() {
            return Err(PrepareReadError::ActiveSession);
        }
        if root.device_function() != self.device_function {
            return Err(PrepareReadError::ForeignRoot);
        }
        let session_sequence = self.next_session_sequence;
        if !(1..=SESSION_SEQUENCE_MASK).contains(&session_sequence) {
            return Err(PrepareReadError::SessionSequenceExhausted);
        }
        let next_session_sequence = session_sequence
            .checked_add(1)
            .ok_or(PrepareReadError::SessionSequenceExhausted)?;
        let attempt_sequence = self.next_attempt_sequence;
        if attempt_sequence == 0 {
            return Err(PrepareReadError::AttemptSequenceExhausted);
        }
        let next_attempt_sequence = attempt_sequence
            .checked_add(1)
            .ok_or(PrepareReadError::AttemptSequenceExhausted)?;
        let gate =
            PreparationGate::acquire(self.owner_id).ok_or(PrepareReadError::PreparationGateBusy)?;
        if !dma_preparation_is_quiescent(dma::preparation_observation()) {
            return Err(PrepareReadError::DmaPreparationBusy);
        }
        if !transport_preparation_is_quiescent(pci::transport_claim_observation()) {
            return Err(PrepareReadError::TransportPreparationBusy);
        }
        let start = PreparedStartCoordinates {
            attempt: PreparationAttemptIdentity {
                owner_id: self.owner_id,
                sequence: attempt_sequence,
            },
            completion_mode,
            session_sequence,
            next_session_sequence,
            next_attempt_sequence,
        };
        Ok(PreparationStartPermit {
            device: self,
            root,
            start,
            gate,
        })
    }

    /// Revalidates and receipts one exact live prepared request.
    ///
    /// The prepared owner is consumed so the returned receipt cannot be
    /// separated from the transport, queue, buffers, and DMA lifecycle it
    /// describes. Every fallible check is read-only. On rejection the exact
    /// owner is returned unchanged; on success the sole mutation is the active
    /// session's issuance bit after the complete receipt has been prepared.
    pub fn issue_preparation_receipt(
        &mut self,
        request: PreparedRequest,
    ) -> Result<ReceiptedPreparedRequest, PreparationEvidenceFailure> {
        let device = PreparationDeviceProjection {
            owner_id: self.owner_id,
            device_function: self.device_function,
            device_bdf: self.device_bdf,
            device_generation: self.device_generation,
        };
        let request_projection = preparation_request_projection(&request);
        let dma = dma::preparation_observation();
        let transport = pci::transport_claim_observation();
        let Some(active) = self.active.as_mut() else {
            return Err(PreparationEvidenceFailure {
                error: PreparationEvidenceError::NoActiveRequest,
                owner: request,
            });
        };
        let receipt = match prepare_success_receipt(
            device,
            *active,
            request_projection,
            dma,
            transport,
            false,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                return Err(PreparationEvidenceFailure {
                    error,
                    owner: request,
                });
            }
        };

        active.preparation_receipt_issued = true;
        Ok(ReceiptedPreparedRequest { request, receipt })
    }

    /// Revalidates the complete receipted owner before queue publication.
    ///
    /// This consumes the wrapper and returns it unchanged on every rejection.
    /// The resulting intent is the only public path to the underlying Release
    /// publication, so identity-only preflight cannot be bypassed.
    pub fn preflight_publish(
        &self,
        owner: ReceiptedPreparedRequest,
        expected: DeviceSessionIdentity,
    ) -> Result<PreparedPublishIntent, PreparationPublishFailure> {
        if owner.request.identity != expected {
            return Err(PreparationPublishFailure {
                error: PreparationEvidenceError::WrongSession,
                owner,
            });
        }
        let Some(active) = self.active else {
            return Err(PreparationPublishFailure {
                error: PreparationEvidenceError::NoActiveRequest,
                owner,
            });
        };
        let device = PreparationDeviceProjection {
            owner_id: self.owner_id,
            device_function: self.device_function,
            device_bdf: self.device_bdf,
            device_generation: self.device_generation,
        };
        let request = preparation_request_projection(&owner.request);
        let expected_receipt = match prepare_success_receipt(
            device,
            active,
            request,
            dma::preparation_observation(),
            pci::transport_claim_observation(),
            true,
        ) {
            Ok(receipt) => receipt,
            Err(error) => return Err(PreparationPublishFailure { error, owner }),
        };
        if expected_receipt != owner.receipt {
            return Err(PreparationPublishFailure {
                error: PreparationEvidenceError::ReceiptMismatch,
                owner,
            });
        }
        Ok(PreparedPublishIntent { owner })
    }

    /// Initializes and prepares one read of sector zero without publishing the
    /// available index.
    ///
    /// The returned token owns the PCI transport, queue DMA, request DMA, exact
    /// buffers, descriptor chain, and available-ring slot. Device visibility is
    /// still impossible at return. Preparing while another lifecycle is active
    /// is rejected before any hardware or facade state changes; the existing
    /// lifecycle and its owners remain retained fail closed.
    pub fn prepare_read_sector0(
        &mut self,
        root: &mut Root,
    ) -> Result<PreparedRequest, PrepareReadError> {
        // The started implementation remains `prepare_read_sector0_with_mode`.
        match self.preflight_read_sector0(root) {
            Ok(permit) => permit
                .apply()
                .map_err(StartedPrepareReadFailure::into_legacy_error),
            Err(error) => Err(error),
        }
    }

    /// Prepares the polling request while preserving typed rollback evidence.
    ///
    /// This is the normal entry point for a causal adapter. A rejection before
    /// hardware mutation is marked `NotStarted`; a started attempt returns
    /// either an opaque rollback receipt or a typed indeterminate projection.
    pub fn prepare_read_sector0_with_evidence(
        &mut self,
        root: &mut Root,
    ) -> Result<PreparedRequest, PrepareReadFailure> {
        match self.preflight_read_sector0(root) {
            Ok(permit) => permit.apply().map_err(PrepareReadFailure::from_started),
            Err(error) => Err(PrepareReadFailure::not_started(error)),
        }
    }

    /// Initializes an interrupt-driven read of sector zero without publishing
    /// the available index.
    ///
    /// This successor differs from [`Self::prepare_read_sector0`] only in its
    /// pre-publication used-buffer notification mode. PCI INTx remains masked
    /// until the owning kernel has installed its IRQ actor and explicitly
    /// consumes a [`crate::MaskedIntx`] through [`crate::Root::unmask_intx`].
    pub fn prepare_read_sector0_irq(
        &mut self,
        root: &mut Root,
    ) -> Result<PreparedRequest, PrepareReadError> {
        // The started implementation remains `prepare_read_sector0_with_mode`.
        match self.preflight_read_sector0_irq(root) {
            Ok(permit) => permit
                .apply()
                .map_err(StartedPrepareReadFailure::into_legacy_error),
            Err(error) => Err(error),
        }
    }

    /// Prepares the interrupt-mode request while preserving typed evidence.
    ///
    /// This does not install an IRQ actor or prove interrupt delivery; it only
    /// selects used-buffer notifications before the same split publication.
    pub fn prepare_read_sector0_irq_with_evidence(
        &mut self,
        root: &mut Root,
    ) -> Result<PreparedRequest, PrepareReadFailure> {
        match self.preflight_read_sector0_irq(root) {
            Ok(permit) => permit.apply().map_err(PrepareReadFailure::from_started),
            Err(error) => Err(PrepareReadFailure::not_started(error)),
        }
    }

    fn prepare_read_sector0_with_mode(
        &mut self,
        root: &mut Root,
        start: PreparedStartCoordinates,
        _gate: PreparationGate,
    ) -> Result<PreparedRequest, StartedPrepareReadFailure> {
        let attempt = start.attempt;
        let completion_mode = start.completion_mode;
        let sequence = start.session_sequence;
        let device_session = SESSION_NAMESPACE
            | (u64::from(self.device_function.bus) << 24)
            | (u64::from(self.device_function.device) << 19)
            | (u64::from(self.device_function.function) << 16)
            | sequence;

        // Once hardware mutation starts this attempt identity is never reused,
        // including when rollback completes successfully.
        self.next_attempt_sequence = start.next_attempt_sequence;

        let original_command =
            match pci::enable_device_for_prepare_checked(root, self.device_function) {
                Ok(command) => command,
                Err(pci::PrepareCommandFailure::ForeignRoot) => {
                    return Err(self.finish_failed_preparation(
                        attempt,
                        PrepareReadError::ForeignRoot,
                        true,
                    ));
                }
                Err(pci::PrepareCommandFailure::IntxStateUnavailable) => {
                    return Err(self.finish_failed_preparation(
                        attempt,
                        PrepareReadError::PciCommandStateUnavailable,
                        true,
                    ));
                }
                Err(pci::PrepareCommandFailure::ReadbackMismatch { original_command }) => {
                    // Best-effort convergence may make the device safer, but
                    // the mismatching write/readback keeps this attempt
                    // indeterminate and permanently latched either way.
                    let _ = pci::restore_device_command_checked(
                        root,
                        self.device_function,
                        original_command,
                    );
                    return Err(self.finish_failed_preparation(
                        attempt,
                        PrepareReadError::PciCommandReadbackMismatch,
                        false,
                    ));
                }
            };
        if dma::try_begin_generation(self.device_generation).is_err() {
            let hardware_certain =
                pci::restore_device_command_checked(root, self.device_function, original_command);
            return Err(self.finish_failed_preparation(
                attempt,
                PrepareReadError::DmaPreparationBusy,
                hardware_certain,
            ));
        }
        if pci::try_begin_transport_claims().is_err() {
            let mut hardware_certain = dma::abort_unexposed_generation(self.device_generation);
            hardware_certain &=
                pci::restore_device_command_checked(root, self.device_function, original_command);
            return Err(self.finish_failed_preparation(
                attempt,
                PrepareReadError::TransportPreparationBusy,
                hardware_certain,
            ));
        }

        let mut transport =
            match PciTransport::new::<OstdHal, _>(root.raw_mut(), self.device_function) {
                Ok(transport) => transport,
                Err(error) => {
                    return Err(self.rollback_failed_preparation(
                        root,
                        original_command,
                        attempt,
                        PrepareReadError::Transport(error),
                        None,
                        None,
                        None,
                    ));
                }
            };
        if transport.device_type() != DeviceType::Block {
            return Err(self.rollback_failed_preparation(
                root,
                original_command,
                attempt,
                PrepareReadError::WrongDeviceType,
                Some(transport),
                None,
                None,
            ));
        }
        let negotiated = transport.begin_init(REQUIRED_FEATURES);
        if negotiated != REQUIRED_FEATURES {
            return Err(self.rollback_failed_preparation(
                root,
                original_command,
                attempt,
                PrepareReadError::MissingRequiredFeatures,
                Some(transport),
                None,
                None,
            ));
        }
        if !transport.get_status().contains(DeviceStatus::FEATURES_OK) {
            return Err(self.rollback_failed_preparation(
                root,
                original_command,
                attempt,
                PrepareReadError::FeatureNegotiationRejected,
                Some(transport),
                None,
                None,
            ));
        }

        let mut queue = match Queue::new(&mut transport, QUEUE_INDEX, false, false) {
            Ok(queue) => queue,
            Err(error) => {
                return Err(self.rollback_failed_preparation(
                    root,
                    original_command,
                    attempt,
                    PrepareReadError::Queue(error),
                    Some(transport),
                    None,
                    None,
                ));
            }
        };
        queue.set_dev_notify(completion_mode.device_notifications_enabled());

        if dma::try_arm_request_bounce(self.device_generation).is_none() {
            return Err(self.rollback_failed_preparation(
                root,
                original_command,
                attempt,
                PrepareReadError::RequestDmaUnavailable,
                Some(transport),
                Some(queue),
                None,
            ));
        }

        let mut buffers = Box::pin(RequestBuffers::new());
        // SAFETY: only fields are borrowed. The allocation remains pinned in
        // every successor typestate until pop or reset acknowledgement.
        let request_buffers = unsafe { buffers.as_mut().get_unchecked_mut() };
        let inputs = [request_buffers.request.as_bytes()];
        let mut outputs: [&mut [u8]; 2] = [
            &mut request_buffers.data[..],
            request_buffers.response.as_mut_bytes(),
        ];
        // SAFETY: the pinned allocation and all three fields are retained by
        // the returned typestate until explicit publish/pop or cancellation.
        let prepared = match unsafe { queue.prepare_add(&inputs, &mut outputs) } {
            Ok(prepared) => prepared,
            Err(error) => {
                let error_kind = error.error();
                let queue = error.into_queue();
                return Err(self.rollback_failed_preparation(
                    root,
                    original_command,
                    attempt,
                    PrepareReadError::Descriptor(error_kind),
                    Some(transport),
                    Some(queue),
                    Some(buffers),
                ));
            }
        };
        let identity = DeviceSessionIdentity {
            device_session,
            device_bdf: self.device_bdf,
            queue: QUEUE_INDEX,
            descriptor_token: prepared.token(),
            device_generation: self.device_generation,
        };
        // Every fallible validation and allocation is complete. From here to
        // return there are only direct ownership moves and device-visible
        // initialization writes.
        dma::mark_queue_exposed(self.device_generation);
        transport.finish_init();
        self.next_session_sequence = start.next_session_sequence;
        self.active = Some(ActiveSession {
            identity,
            attempt,
            preparation_receipt_issued: false,
            reset_acknowledged: false,
        });

        Ok(PreparedRequest {
            attempt,
            identity,
            completion_mode,
            device_function: self.device_function,
            transport: ManuallyDrop::new(transport),
            queue: ManuallyDrop::new(prepared),
            buffers: ManuallyDrop::new(buffers),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn rollback_failed_preparation(
        &mut self,
        root: &mut Root,
        original_command: Command,
        attempt: PreparationAttemptIdentity,
        error: PrepareReadError,
        transport: Option<PciTransport>,
        queue: Option<Queue>,
        buffers: Option<Pin<Box<RequestBuffers>>>,
    ) -> StartedPrepareReadFailure {
        let generation = self.device_generation;
        let hardware_certain = rollback_unexposed_preparation(
            root,
            self.device_function,
            original_command,
            generation,
            transport,
            queue,
            buffers,
        );
        self.finish_failed_preparation(attempt, error, hardware_certain)
    }

    fn finish_failed_preparation(
        &mut self,
        attempt: PreparationAttemptIdentity,
        error: PrepareReadError,
        hardware_certain: bool,
    ) -> StartedPrepareReadFailure {
        let device = PreparationDeviceProjection {
            owner_id: self.owner_id,
            device_function: self.device_function,
            device_bdf: self.device_bdf,
            device_generation: self.device_generation,
        };
        let prepared = prepare_rollback_receipt(
            device,
            attempt,
            None,
            PreparationRollbackKind::UnexposedFailure,
            PreparationQuiescenceProjection {
                active_request: self.active.is_some(),
                hardware_certain,
                dma: dma::preparation_observation(),
                transport: pci::transport_claim_observation(),
            },
        );
        let evidence = match prepared {
            Ok(prepared) => StartedPreparationFailureEvidence::RolledBack(prepared.finish()),
            Err(indeterminate) => {
                // The latch is independent of the diagnostic value. Dropping
                // that value cannot make the retained static owners reusable.
                self.indeterminate_preparation = Some(attempt);
                StartedPreparationFailureEvidence::Indeterminate(indeterminate)
            }
        };
        StartedPrepareReadFailure { error, evidence }
    }

    /// Prevalidates consumption of a reset acknowledgement without mutation.
    ///
    /// The returned plan borrows both objects exclusively, preventing either
    /// projection from changing between validation and its infallible apply.
    pub fn prepare_generation_advance<'a>(
        &'a mut self,
        reset: &'a mut ProductionResetAck,
    ) -> Result<PreparedGenerationAdvance<'a>, ResetGenerationError> {
        let active = self
            .active
            .as_mut()
            .ok_or(ResetGenerationError::NoActiveSession)?;
        if active.identity != reset.identity {
            return Err(ResetGenerationError::WrongIdentity);
        }
        if active.attempt != reset.attempt {
            return Err(ResetGenerationError::WrongAttempt);
        }
        if active.reset_acknowledged || reset.generation_applied {
            return Err(ResetGenerationError::AlreadyApplied);
        }
        let next = next_device_generation(self.device_generation)?;
        Ok(PreparedGenerationAdvance {
            active_reset_acknowledged: &mut active.reset_acknowledged,
            device_generation: &mut self.device_generation,
            reset_generation_applied: &mut reset.generation_applied,
            next_generation: next,
        })
    }

    /// Applies a reset generation without a registry reset receipt only when
    /// the still-unpublished request has no installed registry device cohort.
    ///
    /// The non-cloneable cancellation authority is created exclusively by
    /// [`PreparedRequest::cancel_unregistered`]. This method independently
    /// checks the active identity and the complete reset projection before
    /// consuming the same failure-atomic generation plan used by the normal
    /// registry-coupled path.
    pub fn apply_unregistered_reset(
        &mut self,
        reset: &mut ProductionResetAck,
        cancellation: &mut UnregisteredPreparedCancellation,
    ) -> Result<u64, UnregisteredCancellationError> {
        if cancellation.reset_applied {
            return Err(UnregisteredCancellationError::AlreadyApplied);
        }
        validate_unregistered_reset_projection(
            self.active.map(|active| (active.attempt, active.identity)),
            cancellation.attempt,
            cancellation.identity,
            unregistered_reset_projection(reset),
        )?;
        let plan = self
            .prepare_generation_advance(reset)
            .map_err(map_unregistered_reset_error)?;
        let generation = plan.apply();
        cancellation.reset_applied = true;
        Ok(generation)
    }

    /// Begins the hardware-only IOTLB phase for an unregistered prepared
    /// cancellation after its exact reset generation was applied.
    /// A rejected validation returns the unchanged linear reset owner with the
    /// error, so no DMA closure authority can be lost through this API.
    pub fn begin_unregistered_iotlb(
        &self,
        reset: ProductionResetAck,
        cancellation: &UnregisteredPreparedCancellation,
        inject_one_pending: bool,
    ) -> Result<ProductionClosureProgress, (UnregisteredCancellationError, ProductionResetAck)>
    {
        if let Err(error) = validate_unregistered_reset_projection(
            self.active.map(|active| (active.attempt, active.identity)),
            cancellation.attempt,
            cancellation.identity,
            unregistered_reset_projection(&reset),
        ) {
            return Err((error, reset));
        }
        if !cancellation.reset_applied || !reset.generation_applied {
            return Err((UnregisteredCancellationError::ResetNotApplied, reset));
        }
        Ok(Self::begin_iotlb_validated(reset, inject_one_pending))
    }

    /// Clears the active facade session after an unregistered cancellation's
    /// exact three-owner IOTLB closure.
    pub fn apply_unregistered_quiescence(
        &mut self,
        closure: &mut ProductionClosureReceipt,
        cancellation: &mut UnregisteredPreparedCancellation,
    ) -> Result<PreparationRollbackReceipt, PreparationRollbackError> {
        if cancellation.quiescence_applied {
            return Err(UnregisteredCancellationError::AlreadyApplied.into());
        }
        let active = self
            .active
            .ok_or(UnregisteredCancellationError::NoActiveSession)?;
        validate_unregistered_quiescence_projection(
            Some((active.attempt, active.identity)),
            cancellation.attempt,
            cancellation.identity,
            cancellation.reset_applied,
            closure.attempt,
            closure.identity,
            closure.completed_pages(),
        )
        .map_err(PreparationRollbackError::from)?;
        let device = PreparationDeviceProjection {
            owner_id: self.owner_id,
            device_function: self.device_function,
            device_bdf: self.device_bdf,
            device_generation: self.device_generation,
        };
        let prepared = match prepare_rollback_receipt(
            device,
            cancellation.attempt,
            Some(cancellation.identity),
            PreparationRollbackKind::PreparedCancellation,
            PreparationQuiescenceProjection {
                active_request: false,
                hardware_certain: true,
                dma: dma::preparation_observation(),
                transport: pci::transport_claim_observation(),
            },
        ) {
            Ok(prepared) => prepared,
            Err(indeterminate) => {
                self.indeterminate_preparation = Some(cancellation.attempt);
                return Err(PreparationRollbackError::Indeterminate(indeterminate));
            }
        };
        let plan = self
            .prepare_quiescence_apply(closure)
            .map_err(map_unregistered_quiescence_error)
            .map_err(PreparationRollbackError::from)?;
        let _identity = plan.apply();
        cancellation.quiescence_applied = true;
        Ok(prepared.finish())
    }

    /// Begins IOTLB closure after this device consumed the matching reset ack.
    pub fn begin_iotlb(
        &self,
        reset: ProductionResetAck,
        inject_one_pending: bool,
    ) -> Result<ProductionClosureProgress, ProductionIotlbBeginFailure> {
        let Some(active) = self.active else {
            return Err(ProductionIotlbBeginFailure {
                error: ProductionIotlbBeginError::NoActiveSession,
                reset,
            });
        };
        if active.identity != reset.identity {
            return Err(ProductionIotlbBeginFailure {
                error: ProductionIotlbBeginError::WrongIdentity,
                reset,
            });
        }
        if active.attempt != reset.attempt {
            return Err(ProductionIotlbBeginFailure {
                error: ProductionIotlbBeginError::WrongAttempt,
                reset,
            });
        }
        if !active.reset_acknowledged || !reset.generation_applied {
            return Err(ProductionIotlbBeginFailure {
                error: ProductionIotlbBeginError::ResetNotApplied,
                reset,
            });
        }
        Ok(Self::begin_iotlb_validated(reset, inject_one_pending))
    }

    fn begin_iotlb_validated(
        reset: ProductionResetAck,
        inject_one_pending: bool,
    ) -> ProductionClosureProgress {
        production_closure_progress(
            reset.attempt,
            reset.identity,
            dma::begin_closure(reset.closure_authority, inject_one_pending),
        )
    }

    /// Prevalidates software quiescence publication without mutation.
    ///
    /// The returned plan exclusively borrows both facade state and the linear
    /// closure receipt. A rejected registry transition may drop the plan and
    /// retry with the unchanged receipt; successful registry acknowledgement
    /// invokes the plan's infallible direct-write apply.
    pub fn prepare_quiescence_apply<'a>(
        &'a mut self,
        closure: &'a mut ProductionClosureReceipt,
    ) -> Result<PreparedQuiescenceApply<'a>, QuiescenceApplyError> {
        let active = self
            .active
            .as_ref()
            .ok_or(QuiescenceApplyError::NoActiveSession)?;
        if active.identity != closure.identity {
            return Err(QuiescenceApplyError::WrongIdentity);
        }
        if active.attempt != closure.attempt {
            return Err(QuiescenceApplyError::WrongAttempt);
        }
        if !active.reset_acknowledged {
            return Err(QuiescenceApplyError::ResetNotApplied);
        }
        if closure.dma.generation() != active.identity.device_generation() {
            return Err(QuiescenceApplyError::WrongGeneration);
        }
        if closure.dma.completed_pages() != 3 {
            return Err(QuiescenceApplyError::WrongCompletedPages);
        }
        if closure.applied {
            return Err(QuiescenceApplyError::AlreadyApplied);
        }
        let identity = active.identity;
        Ok(PreparedQuiescenceApply {
            active: &mut self.active,
            closure_applied: &mut closure.applied,
            identity,
        })
    }
}

#[derive(Clone, Copy)]
struct UnregisteredResetProjection {
    attempt: PreparationAttemptIdentity,
    identity: DeviceSessionIdentity,
    published: bool,
    descriptor_popped: bool,
    completed: bool,
    retained_pages: usize,
}

const fn unregistered_reset_projection(reset: &ProductionResetAck) -> UnregisteredResetProjection {
    UnregisteredResetProjection {
        attempt: reset.attempt,
        identity: reset.identity,
        published: reset.published,
        descriptor_popped: reset.descriptor_popped,
        completed: reset.completed,
        retained_pages: reset.retained_dma_pages,
    }
}

fn validate_unregistered_reset_projection(
    active: Option<(PreparationAttemptIdentity, DeviceSessionIdentity)>,
    cancellation_attempt: PreparationAttemptIdentity,
    cancellation: DeviceSessionIdentity,
    reset: UnregisteredResetProjection,
) -> Result<(), UnregisteredCancellationError> {
    let active = active.ok_or(UnregisteredCancellationError::NoActiveSession)?;
    if active.0 != cancellation_attempt || reset.attempt != cancellation_attempt {
        return Err(UnregisteredCancellationError::WrongAttempt);
    }
    if active.1 != cancellation || reset.identity != cancellation {
        return Err(UnregisteredCancellationError::WrongIdentity);
    }
    if reset.published {
        return Err(UnregisteredCancellationError::WasPublished);
    }
    if reset.descriptor_popped {
        return Err(UnregisteredCancellationError::DescriptorPopped);
    }
    if reset.completed {
        return Err(UnregisteredCancellationError::Completed);
    }
    if reset.retained_pages != 3 {
        return Err(UnregisteredCancellationError::WrongRetainedPages);
    }
    Ok(())
}

fn validate_unregistered_quiescence_projection(
    active: Option<(PreparationAttemptIdentity, DeviceSessionIdentity)>,
    cancellation_attempt: PreparationAttemptIdentity,
    cancellation: DeviceSessionIdentity,
    reset_applied: bool,
    closure_attempt: PreparationAttemptIdentity,
    closure: DeviceSessionIdentity,
    completed_pages: usize,
) -> Result<(), UnregisteredCancellationError> {
    let active = active.ok_or(UnregisteredCancellationError::NoActiveSession)?;
    if active.0 != cancellation_attempt || closure_attempt != cancellation_attempt {
        return Err(UnregisteredCancellationError::WrongAttempt);
    }
    if active.1 != cancellation || closure != cancellation {
        return Err(UnregisteredCancellationError::WrongIdentity);
    }
    if !reset_applied {
        return Err(UnregisteredCancellationError::ResetNotApplied);
    }
    if completed_pages != 3 {
        return Err(UnregisteredCancellationError::WrongCompletedPages);
    }
    Ok(())
}

const fn map_unregistered_reset_error(
    error: ResetGenerationError,
) -> UnregisteredCancellationError {
    match error {
        ResetGenerationError::NoActiveSession => UnregisteredCancellationError::NoActiveSession,
        ResetGenerationError::WrongIdentity => UnregisteredCancellationError::WrongIdentity,
        ResetGenerationError::WrongAttempt => UnregisteredCancellationError::WrongAttempt,
        ResetGenerationError::AlreadyApplied => UnregisteredCancellationError::AlreadyApplied,
        ResetGenerationError::GenerationOverflow => {
            UnregisteredCancellationError::GenerationOverflow
        }
    }
}

const fn map_unregistered_quiescence_error(
    error: QuiescenceApplyError,
) -> UnregisteredCancellationError {
    match error {
        QuiescenceApplyError::NoActiveSession => UnregisteredCancellationError::NoActiveSession,
        QuiescenceApplyError::WrongIdentity => UnregisteredCancellationError::WrongIdentity,
        QuiescenceApplyError::WrongAttempt => UnregisteredCancellationError::WrongAttempt,
        QuiescenceApplyError::ResetNotApplied => UnregisteredCancellationError::ResetNotApplied,
        QuiescenceApplyError::WrongGeneration => UnregisteredCancellationError::WrongGeneration,
        QuiescenceApplyError::WrongCompletedPages => {
            UnregisteredCancellationError::WrongCompletedPages
        }
        QuiescenceApplyError::AlreadyApplied => UnregisteredCancellationError::AlreadyApplied,
    }
}

struct RequestBuffers {
    request: BlkReq,
    data: [u8; SECTOR_SIZE],
    response: BlkResp,
    _pin: PhantomPinned,
}

impl RequestBuffers {
    fn new() -> Self {
        Self {
            request: BlkReq::default(),
            data: [0; SECTOR_SIZE],
            response: BlkResp::default(),
            _pin: PhantomPinned,
        }
    }
}

fn rollback_unexposed_preparation(
    root: &mut Root,
    device_function: DeviceFunction,
    original_command: Command,
    generation: u64,
    mut transport: Option<PciTransport>,
    queue: Option<Queue>,
    buffers: Option<Pin<Box<RequestBuffers>>>,
) -> bool {
    let mut status_certain = true;
    if let Some(transport) = transport.as_mut() {
        transport.set_status(DeviceStatus::empty());
        status_certain = transport.get_status() == DeviceStatus::empty();
    }
    let bus_master_certain = pci::disable_bus_master_checked(root, device_function).is_ok();
    if !status_certain || !bus_master_certain {
        // The device may still hold a live DMA/MMIO view. Leak the exact
        // owners into their fail-closed static ledgers instead of running
        // ordinary teardown or fabricating a zero-owner observation.
        forget(queue);
        forget(transport);
        forget(buffers);
        return false;
    }

    drop(queue);
    drop(transport);
    // SAFETY: no transport was returned from the failed constructor, or the
    // only returned transport was destroyed immediately above. The queue was
    // never exposed to a DRIVER_OK device and no raw MMIO pointer remains.
    let mut hardware_certain = unsafe { pci::release_unexposed_transport_claims_checked() };
    hardware_certain &=
        pci::restore_device_command_checked(root, device_function, original_command);
    drop(buffers);
    hardware_certain &= dma::abort_unexposed_generation(generation);
    hardware_certain
}

/// A request whose descriptors and DMA shares are ready but unpublished.
#[must_use = "publish, cancel, or retain the complete prepared request"]
pub struct PreparedRequest {
    attempt: PreparationAttemptIdentity,
    identity: DeviceSessionIdentity,
    completion_mode: CompletionMode,
    device_function: DeviceFunction,
    transport: ManuallyDrop<PciTransport>,
    queue: ManuallyDrop<PreparedQueue>,
    buffers: ManuallyDrop<Pin<Box<RequestBuffers>>>,
}

impl PreparedRequest {
    /// Returns the opaque owner-bound preparation attempt.
    pub const fn attempt(&self) -> PreparationAttemptIdentity {
        self.attempt
    }

    /// Returns descriptive coordinates for registration in the kernel registry.
    pub const fn identity(&self) -> DeviceSessionIdentity {
        self.identity
    }

    /// Returns the completion-delivery mode fixed before queue publication.
    pub const fn completion_mode(&self) -> CompletionMode {
        self.completion_mode
    }

    /// Prevalidates unpublished cancellation and returns its linear hardware intent.
    ///
    /// This consumes the owner so identity, queue token, and request-share
    /// state cannot change between validation and [`PreparedCancelIntent::apply_reset`].
    /// Every rejection returns the unchanged owner and performs no queue, DMA,
    /// transport, or facade mutation.
    pub fn preflight_cancel(
        self,
        expected_cancel_identity: DeviceSessionIdentity,
    ) -> Result<PreparedCancelIntent, HardwareIntentFailure<PreparedRequest>> {
        if self.identity != expected_cancel_identity {
            return Err(HardwareIntentFailure {
                error: HardwareIntentError::WrongIdentity,
                owner: self,
            });
        }
        if self.queue.token() != self.identity.descriptor_token {
            return Err(HardwareIntentFailure {
                error: HardwareIntentError::DescriptorTokenMismatch,
                owner: self,
            });
        }
        let observed = dma::request_share_counts_checked(self.identity.device_generation);
        if observed != Some((3, 0)) {
            return Err(HardwareIntentFailure {
                error: HardwareIntentError::RequestShareStateMismatch { observed },
                owner: self,
            });
        }
        Ok(PreparedCancelIntent { request: self })
    }

    /// Performs the unique infallible `avail.idx` Release publication after a
    /// `ProductionDevice` constructed the consuming publish intent.
    fn publish_prepared_unchecked(self) -> PublishedRequest {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: suppressing PreparedRequest::drop makes these the only
        // extractions of the exact retained preparation owners.
        let prepared = unsafe { ManuallyDrop::take(&mut this.queue) };
        let (queue, _token) = prepared.publish_prepared();
        PublishedRequest {
            attempt: this.attempt,
            identity: this.identity,
            completion_mode: this.completion_mode,
            device_function: this.device_function,
            // SAFETY: the enclosing ManuallyDrop is consumed once here.
            transport: Some(unsafe { ManuallyDrop::take(&mut this.transport) }),
            queue: Some(queue),
            // SAFETY: the enclosing ManuallyDrop is consumed once here.
            buffers: Some(unsafe { ManuallyDrop::take(&mut this.buffers) }),
            notification_resolved: false,
        }
    }

    /// Rolls back an unpublished descriptor chain and all three request shares.
    pub fn cancel_prepared(self) -> CancelledRequest {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: the enclosing ManuallyDrop is consumed once here.
        let prepared = unsafe { ManuallyDrop::take(&mut this.queue) };
        // SAFETY: the enclosing ManuallyDrop is consumed once here.
        let mut buffers = unsafe { ManuallyDrop::take(&mut this.buffers) };
        // SAFETY: these are the exact pinned fields supplied to prepare_add;
        // `avail.idx` has not been published and they remain inaccessible.
        let request_buffers = unsafe { buffers.as_mut().get_unchecked_mut() };
        let inputs = [request_buffers.request.as_bytes()];
        let mut outputs: [&mut [u8]; 2] = [
            &mut request_buffers.data[..],
            request_buffers.response.as_mut_bytes(),
        ];
        // SAFETY: exact buffers and the linear token are consumed together.
        let queue = unsafe { prepared.cancel_prepared(&inputs, &mut outputs) };
        assert_eq!(
            dma::request_share_counts(this.identity.device_generation),
            (3, 3)
        );
        CancelledRequest {
            session: Some(ResetSession {
                attempt: this.attempt,
                identity: this.identity,
                device_function: this.device_function,
                // SAFETY: the enclosing ManuallyDrop is consumed once here.
                transport: Some(unsafe { ManuallyDrop::take(&mut this.transport) }),
                queue: Some(queue),
                buffers: Some(buffers),
                published: false,
                descriptor_popped: false,
                completed: false,
            }),
        }
    }

    /// Rolls back hardware preparation which could not be installed as a
    /// device cohort in the semantic registry.
    ///
    /// The returned wrapper is the only constructor for the linear exception
    /// authority consumed by [`ProductionDevice::apply_unregistered_reset`]
    /// and [`ProductionDevice::apply_unregistered_quiescence`]. Enrolled
    /// requests must use [`Self::cancel_prepared`] and the registry-coupled
    /// acknowledgement path instead.
    ///
    /// The caller is responsible for proving, under the external registry's
    /// transition gate, that this request has no installed device cohort. That
    /// cross-component fact is deliberately not claimed as a facade type
    /// property.
    pub fn cancel_unregistered(self) -> UnregisteredCancelledRequest {
        let attempt = self.attempt;
        let identity = self.identity;
        UnregisteredCancelledRequest {
            request: Some(self.cancel_prepared()),
            cancellation: Some(UnregisteredPreparedCancellation {
                attempt,
                identity,
                reset_applied: false,
                quiescence_applied: false,
            }),
        }
    }
}

impl ReceiptedPreparedRequest {
    /// Borrows the non-copyable preparation receipt while retaining its owner.
    pub const fn receipt(&self) -> &PreparationReceipt {
        &self.receipt
    }

    /// Returns the exact prepared request coordinates.
    pub const fn identity(&self) -> DeviceSessionIdentity {
        self.request.identity
    }

    /// Returns the owner-bound preparation attempt.
    pub const fn attempt(&self) -> PreparationAttemptIdentity {
        self.request.attempt
    }

    /// Returns the completion mode fixed before queue exposure.
    pub const fn completion_mode(&self) -> CompletionMode {
        self.request.completion_mode
    }

    /// Prevalidates cancellation and returns the complete wrapper on rejection.
    pub fn preflight_cancel(
        self,
        expected_cancel_identity: DeviceSessionIdentity,
    ) -> Result<PreparedCancelIntent, HardwareIntentFailure<ReceiptedPreparedRequest>> {
        let Self { request, receipt } = self;
        match request.preflight_cancel(expected_cancel_identity) {
            Ok(intent) => Ok(intent),
            Err(failure) => Err(HardwareIntentFailure {
                error: failure.error,
                owner: Self {
                    request: failure.owner,
                    receipt,
                },
            }),
        }
    }

    /// Consumes receipt and exact owner in unpublished cancellation.
    pub fn cancel_prepared(self) -> CancelledRequest {
        self.request.cancel_prepared()
    }

    /// Begins exceptional closure after registry installation failed.
    pub fn cancel_unregistered(self) -> UnregisteredCancelledRequest {
        self.request.cancel_unregistered()
    }
}

impl PreparedPublishIntent {
    /// Returns the exact request coordinates selected for publication.
    pub const fn identity(&self) -> DeviceSessionIdentity {
        self.owner.request.identity
    }

    /// Performs the sole infallible `avail.idx` Release publication.
    pub fn apply(self) -> PublishedRequest {
        self.owner.request.publish_prepared_unchecked()
    }
}

impl Drop for PreparedRequest {
    fn drop(&mut self) {
        // Fail closed. Only a PreparedPublishIntent or cancellation may
        // extract these owners and discharge the preparation obligation.
    }
}

/// Linear, prevalidated authority to cancel one unpublished request and reset
/// its real retained device/queue/DMA owners.
///
/// Descriptive [`DeviceSessionIdentity`] values cannot construct this type;
/// only [`PreparedRequest::preflight_cancel`] can move the prepared owner into
/// it. It is deliberately neither `Clone` nor `Copy`.
#[must_use = "apply reset or retain the prevalidated prepared hardware owner"]
pub struct PreparedCancelIntent {
    request: PreparedRequest,
}

impl PreparedCancelIntent {
    /// Returns descriptive coordinates for binding to an external operation.
    pub const fn identity(&self) -> DeviceSessionIdentity {
        self.request.identity
    }

    /// Infallibly cancels the exact unpublished chain and starts device reset.
    pub fn apply_reset(self, inject_pending_once: bool) -> ProductionResetTombstone {
        self.request
            .cancel_prepared()
            .begin_reset(inject_pending_once)
    }
}

/// A retained completion-path failure which still permits mandatory reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionFailure {
    /// Completion was polled before notification suppression/kick was resolved.
    NotificationUnresolved,
    /// The next used-ring entry names another descriptor chain.
    WrongToken { expected: u16, observed: u16 },
    /// The queue rejected the matching pop without consuming the descriptor.
    Pop(VirtioError),
    /// The device consumed the descriptor but did not report the complete output length.
    UnexpectedUsedLength { expected: u32, observed: u32 },
    /// The descriptor was popped, but the device returned a non-success status.
    DeviceResponse(RespStatus),
    /// The descriptor was popped, but exact request-share retirement was not observed.
    ShareAccountingMismatch { observed: Option<(usize, usize)> },
}

/// Result of resolving the post-publication queue notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationDisposition {
    /// The device requested and received a queue kick.
    Kicked,
    /// The device suppressed the kick; polling may proceed without one.
    Suppressed,
    /// This published request had already resolved notification exactly once.
    AlreadyResolved,
}

/// Typed cause decoded from one VirtIO ISR-status read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptCause {
    /// No queue or device-configuration cause was pending.
    Spurious,
    /// A used-buffer notification was pending for a virtqueue.
    Queue,
    /// Only a device-configuration change was pending.
    Configuration,
    /// Queue and device-configuration causes were pending together.
    QueueAndConfiguration,
}

impl InterruptCause {
    /// Reports whether this acknowledgement authorizes a used-ring probe.
    pub const fn includes_queue(self) -> bool {
        matches!(self, Self::Queue | Self::QueueAndConfiguration)
    }
}

fn decode_interrupt_status(status: InterruptStatus) -> InterruptCause {
    match (
        status.contains(InterruptStatus::QUEUE_INTERRUPT),
        status.contains(InterruptStatus::DEVICE_CONFIGURATION_INTERRUPT),
    ) {
        (false, false) => InterruptCause::Spurious,
        (true, false) => InterruptCause::Queue,
        (false, true) => InterruptCause::Configuration,
        (true, true) => InterruptCause::QueueAndConfiguration,
    }
}

/// Exact request identity and cause returned by one ISR acknowledgement.
///
/// This is descriptive evidence, not registry completion authority. Its fields
/// are private so callers cannot manufacture a queue cause for another request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptReceipt {
    attempt: PreparationAttemptIdentity,
    identity: DeviceSessionIdentity,
    cause: InterruptCause,
}

impl InterruptReceipt {
    /// Returns the preparation attempt whose transport ISR was read.
    pub const fn attempt(self) -> PreparationAttemptIdentity {
        self.attempt
    }

    /// Returns the request whose transport ISR was read.
    pub const fn identity(self) -> DeviceSessionIdentity {
        self.identity
    }

    /// Returns the typed queue/configuration/spurious cause.
    pub const fn cause(self) -> InterruptCause {
        self.cause
    }
}

/// Why task-context IRQ completion retained a request for a later actor turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptNotReadyReason {
    /// The receipt was produced for another preparation attempt.
    WrongAttempt,
    /// The receipt was produced for another exact hardware request.
    WrongIdentity {
        expected: DeviceSessionIdentity,
        observed: DeviceSessionIdentity,
    },
    /// The request selected the legacy polling completion mode.
    PollingRequest,
    /// The acknowledged ISR did not contain a queue cause.
    NonQueueCause(InterruptCause),
    /// A queue cause was acknowledged before the used entry became visible.
    UsedRingNotReady,
}

/// Linear task-context IRQ completion result.
///
/// `NotReady` deliberately returns the exact [`PublishedRequest`] owner rather
/// than converting it into the polling timeout/reset typestate. An IRQ actor
/// may therefore put the request back into its protected slot and retry on a
/// later interrupt without losing ownership or inventing a terminal result.
#[must_use = "publish completion, retain the request in its IRQ slot, or reset it"]
pub enum InterruptCompletionProgress {
    /// The matching descriptor was popped and validated successfully.
    Complete(CompletedRequest),
    /// No authorized ready descriptor was available; the owner is unchanged.
    NotReady {
        request: PublishedRequest,
        reason: InterruptNotReadyReason,
    },
    /// A ready descriptor failed the same validation used by polling.
    Failed(FailedCompletion),
}

enum CompletionAttempt {
    Complete(CompletedRequest),
    NotReady(PublishedRequest),
    Failed(FailedCompletion),
}

/// Linear result of one non-spinning task-context completion probe.
///
/// `NotReady` returns the exact published owner for reinsertion into a
/// runtime-resident actor slot; it does not leave the owner on a long-lived
/// polling stack.
#[must_use = "consume completion, reinsert the unchanged owner, or reset the failure"]
pub enum CompletionProbeProgress {
    /// The matching descriptor was popped and validated successfully.
    Complete(CompletedRequest),
    /// No used descriptor is currently visible; the owner is unchanged.
    NotReady(PublishedRequest),
    /// A visible descriptor failed the shared completion validator.
    Failed(FailedCompletion),
}

/// Linear result of one bounded completion poll.
#[must_use = "consume the completion, reset the retained request, or retain its owner"]
pub enum CompletionProgress {
    /// The matching descriptor was popped and validated successfully.
    Complete(CompletedRequest),
    /// No used descriptor arrived before the bounded deadline.
    Pending(PendingCompletion),
    /// Validation failed while the complete request owner remained recoverable.
    Failed(FailedCompletion),
}

fn preflight_completion_reset_owner(
    request: Option<&PublishedRequest>,
    expected_reset_identity: DeviceSessionIdentity,
    expected_share_counts: (usize, usize),
) -> Result<(), HardwareIntentError> {
    let Some(request) = request else {
        return Err(HardwareIntentError::MissingResetOwner);
    };
    if request.identity != expected_reset_identity {
        return Err(HardwareIntentError::WrongIdentity);
    }
    if request.transport.is_none() || request.queue.is_none() || request.buffers.is_none() {
        return Err(HardwareIntentError::MissingResetOwner);
    }
    let observed = dma::request_share_counts_checked(request.identity.device_generation);
    if observed != Some(expected_share_counts) {
        return Err(HardwareIntentError::RequestShareStateMismatch { observed });
    }
    Ok(())
}

/// A timed-out poll which retains every published request owner.
#[must_use = "retry at a higher layer or begin mandatory device reset"]
pub struct PendingCompletion {
    request: Option<PublishedRequest>,
}

impl PendingCompletion {
    /// Returns the retained hardware identity.
    pub fn identity(&self) -> DeviceSessionIdentity {
        self.request.as_ref().expect("pending request").identity
    }

    /// No descriptor is consumed on the pending path.
    pub const fn descriptor_popped(&self) -> bool {
        false
    }

    /// Starts whole-device reset while retaining the unpublished used-chain owner.
    pub fn begin_reset(mut self, inject_pending_once: bool) -> ProductionResetTombstone {
        self.request
            .take()
            .expect("pending request")
            .into_reset_session(false, false)
            .begin_reset(inject_pending_once)
    }
}

/// A failed completion validation with a retained reset path.
#[must_use = "inspect the failure and begin mandatory device reset"]
pub struct FailedCompletion {
    request: Option<PublishedRequest>,
    failure: CompletionFailure,
    descriptor_popped: bool,
    used_len: Option<u32>,
}

impl FailedCompletion {
    fn new(
        request: PublishedRequest,
        failure: CompletionFailure,
        descriptor_popped: bool,
        used_len: Option<u32>,
    ) -> Self {
        Self {
            request: Some(request),
            failure,
            descriptor_popped,
            used_len,
        }
    }

    /// Returns the retained hardware identity.
    pub fn identity(&self) -> DeviceSessionIdentity {
        self.request.as_ref().expect("failed request").identity
    }

    /// Returns the exact completion validation failure.
    pub const fn failure(&self) -> CompletionFailure {
        self.failure
    }

    /// Reports whether `pop_used` consumed and recycled the descriptor chain.
    pub const fn descriptor_popped(&self) -> bool {
        self.descriptor_popped
    }

    /// Returns the device-reported used length when the descriptor was popped.
    pub const fn used_len(&self) -> Option<u32> {
        self.used_len
    }

    /// Starts whole-device reset without discarding either popped or live owners.
    pub fn begin_reset(mut self, inject_pending_once: bool) -> ProductionResetTombstone {
        self.request
            .take()
            .expect("failed request")
            .into_reset_session(self.descriptor_popped, false)
            .begin_reset(inject_pending_once)
    }
}

/// A device-visible request which has not yet completed.
#[must_use = "notify and complete, or retain/reset the published request"]
pub struct PublishedRequest {
    attempt: PreparationAttemptIdentity,
    identity: DeviceSessionIdentity,
    completion_mode: CompletionMode,
    device_function: DeviceFunction,
    transport: Option<PciTransport>,
    queue: Option<Queue>,
    buffers: Option<Pin<Box<RequestBuffers>>>,
    notification_resolved: bool,
}

impl PublishedRequest {
    /// Returns the owner-bound preparation attempt carried through publication.
    pub const fn attempt(&self) -> PreparationAttemptIdentity {
        self.attempt
    }

    /// Returns descriptive coordinates of the published request.
    pub const fn identity(&self) -> DeviceSessionIdentity {
        self.identity
    }

    /// Returns the completion-delivery mode fixed during preparation.
    pub const fn completion_mode(&self) -> CompletionMode {
        self.completion_mode
    }

    /// Prevalidates mandatory reset and returns its linear hardware intent.
    ///
    /// The returned intent owns the exact published transport, queue, buffers,
    /// and generation. A rejected identity, missing owner, or foreign DMA
    /// projection returns this [`PublishedRequest`] unchanged and performs no
    /// transport, queue, DMA, or facade mutation.
    pub fn preflight_reset(
        self,
        expected_reset_identity: DeviceSessionIdentity,
    ) -> Result<PreparedPublishedResetIntent, HardwareIntentFailure<PublishedRequest>> {
        if self.identity != expected_reset_identity {
            return Err(HardwareIntentFailure {
                error: HardwareIntentError::WrongIdentity,
                owner: self,
            });
        }
        if self.transport.is_none() || self.queue.is_none() || self.buffers.is_none() {
            return Err(HardwareIntentFailure {
                error: HardwareIntentError::MissingResetOwner,
                owner: self,
            });
        }
        let observed = dma::request_share_counts_checked(self.identity.device_generation);
        if observed != Some((3, 0)) {
            return Err(HardwareIntentFailure {
                error: HardwareIntentError::RequestShareStateMismatch { observed },
                owner: self,
            });
        }
        Ok(PreparedPublishedResetIntent { request: self })
    }

    /// Resolves the one queue notification after external commit application.
    ///
    /// VirtIO notification suppression is a successful outcome, not an error:
    /// the device has already observed the available ring and requested that
    /// the driver skip the kick. Repeated resolution is reported without
    /// panicking away the published request owner.
    pub fn notify(&mut self) -> NotificationDisposition {
        if self.notification_resolved {
            return NotificationDisposition::AlreadyResolved;
        }
        let disposition = if self.queue.as_ref().expect("live queue").should_notify() {
            self.transport
                .as_mut()
                .expect("live transport")
                .notify(QUEUE_INDEX);
            NotificationDisposition::Kicked
        } else {
            NotificationDisposition::Suppressed
        };
        self.notification_resolved = true;
        disposition
    }

    /// Hard-IRQ top-half acknowledgement for this request's VirtIO ISR.
    ///
    /// The operation performs exactly the transport ISR read/acknowledgement;
    /// it does not allocate, log, spin, pop a descriptor, or publish guest
    /// state. Reading the ISR may deassert a level-triggered INTx line. This is
    /// the only [`PublishedRequest`] method intended for hard-IRQ context; the
    /// receipt must be handed to a task-context completion actor.
    pub fn ack_interrupt(&mut self) -> InterruptReceipt {
        let status = self
            .transport
            .as_mut()
            .expect("live transport")
            .ack_interrupt();
        InterruptReceipt {
            attempt: self.attempt,
            identity: self.identity,
            cause: decode_interrupt_status(status),
        }
    }

    /// Task-context completion after an exact interrupt acknowledgement.
    ///
    /// This method has no explicit polling loop, but it may take the internal
    /// DMA ledger lock while recycling a ready descriptor and therefore must
    /// not run in hard-IRQ context. A foreign receipt, polling-mode request,
    /// configuration-only/spurious interrupt, or queue interrupt observed
    /// before its used entry is ready returns the unchanged linear request
    /// owner in [`InterruptCompletionProgress::NotReady`]. Only a matching
    /// queue cause with a ready used entry may reach descriptor validation.
    pub fn complete_after_interrupt(
        self,
        receipt: InterruptReceipt,
    ) -> InterruptCompletionProgress {
        if self.attempt != receipt.attempt {
            return InterruptCompletionProgress::NotReady {
                request: self,
                reason: InterruptNotReadyReason::WrongAttempt,
            };
        }
        if self.identity != receipt.identity {
            let expected = self.identity;
            return InterruptCompletionProgress::NotReady {
                request: self,
                reason: InterruptNotReadyReason::WrongIdentity {
                    expected,
                    observed: receipt.identity,
                },
            };
        }
        if self.completion_mode != CompletionMode::Interrupt {
            return InterruptCompletionProgress::NotReady {
                request: self,
                reason: InterruptNotReadyReason::PollingRequest,
            };
        }
        if !receipt.cause.includes_queue() {
            return InterruptCompletionProgress::NotReady {
                request: self,
                reason: InterruptNotReadyReason::NonQueueCause(receipt.cause),
            };
        }

        match self.probe_completion_once() {
            CompletionProbeProgress::Complete(request) => {
                InterruptCompletionProgress::Complete(request)
            }
            CompletionProbeProgress::NotReady(request) => InterruptCompletionProgress::NotReady {
                request,
                reason: InterruptNotReadyReason::UsedRingNotReady,
            },
            CompletionProbeProgress::Failed(failure) => {
                InterruptCompletionProgress::Failed(failure)
            }
        }
    }

    /// Performs one non-spinning task-context used-ring probe.
    ///
    /// This is the runtime-actor successor to the bounded polling wrapper. It
    /// consumes the slot owner for one shared validation step and returns that
    /// same owner in [`CompletionProbeProgress::NotReady`] when no used entry
    /// is visible.
    pub fn probe_completion_once(self) -> CompletionProbeProgress {
        match self.complete_once() {
            CompletionAttempt::Complete(request) => CompletionProbeProgress::Complete(request),
            CompletionAttempt::NotReady(request) => CompletionProbeProgress::NotReady(request),
            CompletionAttempt::Failed(failure) => CompletionProbeProgress::Failed(failure),
        }
    }

    /// Polls the Stage-5-compatible diagnostic completion path.
    ///
    /// This method does not establish an interrupt-delivery claim. The future
    /// main adapter must select a real IRQ completion API instead.
    pub fn poll_completion(self) -> CompletionProgress {
        let mut request = self;
        for _ in 0..POLL_LIMIT {
            match request.probe_completion_once() {
                CompletionProbeProgress::Complete(request) => {
                    return CompletionProgress::Complete(request);
                }
                CompletionProbeProgress::NotReady(retained) => request = retained,
                CompletionProbeProgress::Failed(failure) => {
                    return CompletionProgress::Failed(failure);
                }
            }
            spin_loop();
        }
        CompletionProgress::Pending(PendingCompletion {
            request: Some(request),
        })
    }

    /// Performs one non-spinning used-ring probe and the sole completion
    /// validation implementation shared by polling and IRQ delivery.
    fn complete_once(self) -> CompletionAttempt {
        let observed = if self.notification_resolved {
            self.queue.as_ref().expect("live queue").peek_used()
        } else {
            None
        };
        self.complete_observed(observed)
    }

    fn complete_observed(mut self, observed: Option<u16>) -> CompletionAttempt {
        if !self.notification_resolved {
            return CompletionAttempt::Failed(FailedCompletion::new(
                self,
                CompletionFailure::NotificationUnresolved,
                false,
                None,
            ));
        }
        let Some(observed) = observed else {
            return CompletionAttempt::NotReady(self);
        };
        let expected = self.identity.descriptor_token;
        if observed != expected {
            return CompletionAttempt::Failed(FailedCompletion::new(
                self,
                CompletionFailure::WrongToken { expected, observed },
                false,
                None,
            ));
        }

        let queue = self.queue.as_mut().expect("live queue");
        let buffers = self.buffers.as_mut().expect("pinned request buffers");
        // SAFETY: only fields of the stable pinned allocation are borrowed.
        let request_buffers = unsafe { buffers.as_mut().get_unchecked_mut() };
        let inputs = [request_buffers.request.as_bytes()];
        let mut outputs: [&mut [u8]; 2] = [
            &mut request_buffers.data[..],
            request_buffers.response.as_mut_bytes(),
        ];
        // SAFETY: token and buffers exactly match the published prepared chain.
        let used_len = match unsafe { queue.pop_used(expected, &inputs, &mut outputs) } {
            Ok(used_len) => used_len,
            Err(error) => {
                return CompletionAttempt::Failed(FailedCompletion::new(
                    self,
                    CompletionFailure::Pop(error),
                    false,
                    None,
                ));
            }
        };
        if used_len != EXPECTED_USED_LEN {
            return CompletionAttempt::Failed(FailedCompletion::new(
                self,
                CompletionFailure::UnexpectedUsedLength {
                    expected: EXPECTED_USED_LEN,
                    observed: used_len,
                },
                true,
                Some(used_len),
            ));
        }
        let response = request_buffers.response.status();
        if response != RespStatus::OK {
            return CompletionAttempt::Failed(FailedCompletion::new(
                self,
                CompletionFailure::DeviceResponse(response),
                true,
                Some(used_len),
            ));
        }
        let share_counts = dma::request_share_counts_checked(self.identity.device_generation);
        if share_counts != Some((3, 3)) {
            return CompletionAttempt::Failed(FailedCompletion::new(
                self,
                CompletionFailure::ShareAccountingMismatch {
                    observed: share_counts,
                },
                true,
                Some(used_len),
            ));
        }

        CompletionAttempt::Complete(CompletedRequest {
            request: Some(self),
            used_len,
        })
    }

    /// Starts whole-device reset for a published request without completion.
    pub fn begin_reset(self, inject_pending_once: bool) -> ProductionResetTombstone {
        self.into_reset_session(false, false)
            .begin_reset(inject_pending_once)
    }

    fn into_reset_session(mut self, descriptor_popped: bool, completed: bool) -> ResetSession {
        ResetSession {
            attempt: self.attempt,
            identity: self.identity,
            device_function: self.device_function,
            transport: self.transport.take(),
            queue: self.queue.take(),
            buffers: self.buffers.take(),
            published: true,
            descriptor_popped,
            completed,
        }
    }
}

impl Drop for PublishedRequest {
    fn drop(&mut self) {
        quarantine(&mut self.queue);
        quarantine(&mut self.transport);
        quarantine(&mut self.buffers);
    }
}

/// Linear, prevalidated authority to reset one real published request.
///
/// This type contains the retained [`PublishedRequest`] itself, not registry
/// coordinates or a replayable operation identifier. Only
/// [`PublishedRequest::preflight_reset`] can construct it, and it is
/// deliberately neither `Clone` nor `Copy`.
#[must_use = "apply reset or retain the prevalidated published hardware owner"]
pub struct PreparedPublishedResetIntent {
    request: PublishedRequest,
}

impl PreparedPublishedResetIntent {
    /// Returns descriptive coordinates for binding to an external operation.
    pub const fn identity(&self) -> DeviceSessionIdentity {
        self.request.identity
    }

    /// Infallibly starts reset for the exact retained published owners.
    pub fn apply_reset(self, inject_pending_once: bool) -> ProductionResetTombstone {
        self.request
            .into_reset_session(false, false)
            .begin_reset(inject_pending_once)
    }
}

/// A successfully popped request whose sector buffer is kernel-readable.
#[must_use = "copy the data and close the complete hardware generation"]
pub struct CompletedRequest {
    request: Option<PublishedRequest>,
    used_len: u32,
}

impl CompletedRequest {
    /// Returns the retained hardware identity.
    pub fn identity(&self) -> DeviceSessionIdentity {
        self.request.as_ref().expect("completed request").identity
    }

    /// Returns the used length reported by the device.
    pub const fn used_len(&self) -> u32 {
        self.used_len
    }

    /// Returns the complete sector-zero result after successful pop.
    pub fn data(&self) -> &[u8; SECTOR_SIZE] {
        &self
            .request
            .as_ref()
            .expect("completed request")
            .buffers
            .as_ref()
            .expect("pinned request buffers")
            .as_ref()
            .get_ref()
            .data
    }

    /// Prevalidates reset after successful descriptor completion.
    ///
    /// The descriptor has already been popped, so the exact request DMA
    /// projection is three shares and three matching unshares, not the live
    /// published-request projection. Every rejection returns this completed
    /// owner unchanged and performs no transport, queue, DMA, or facade
    /// mutation.
    pub fn preflight_reset(
        self,
        expected_reset_identity: DeviceSessionIdentity,
    ) -> Result<PreparedRequestResetIntent, HardwareIntentFailure<CompletedRequest>> {
        match preflight_completion_reset_owner(
            self.request.as_ref(),
            expected_reset_identity,
            POPPED_REQUEST_SHARE_COUNTS,
        ) {
            Ok(()) => Ok(PreparedRequestResetIntent {
                owner: PreparedRequestResetOwner::Completed(self),
            }),
            Err(error) => Err(HardwareIntentFailure { error, owner: self }),
        }
    }

    /// Starts mandatory whole-device reset after normal completion.
    pub fn begin_reset(mut self, inject_pending_once: bool) -> ProductionResetTombstone {
        self.request
            .take()
            .expect("completed request")
            .into_reset_session(true, true)
            .begin_reset(inject_pending_once)
    }
}

impl PendingCompletion {
    /// Prevalidates reset for a published request whose descriptor remains live.
    ///
    /// Every rejection returns this pending owner unchanged and performs no
    /// transport, queue, DMA, or facade mutation.
    pub fn preflight_reset(
        self,
        expected_reset_identity: DeviceSessionIdentity,
    ) -> Result<PreparedRequestResetIntent, HardwareIntentFailure<PendingCompletion>> {
        match preflight_completion_reset_owner(
            self.request.as_ref(),
            expected_reset_identity,
            PUBLISHED_REQUEST_SHARE_COUNTS,
        ) {
            Ok(()) => Ok(PreparedRequestResetIntent {
                owner: PreparedRequestResetOwner::Pending(self),
            }),
            Err(error) => Err(HardwareIntentFailure { error, owner: self }),
        }
    }
}

impl FailedCompletion {
    /// Prevalidates reset after a retained completion-path failure.
    ///
    /// The required DMA projection follows the type-retained pop state: a
    /// pre-pop failure still has three live shares, while a post-pop failure
    /// has three matching unshares. Every rejection returns this failed owner
    /// unchanged and performs no transport, queue, DMA, or facade mutation.
    pub fn preflight_reset(
        self,
        expected_reset_identity: DeviceSessionIdentity,
    ) -> Result<PreparedRequestResetIntent, HardwareIntentFailure<FailedCompletion>> {
        let expected_share_counts = if self.descriptor_popped {
            POPPED_REQUEST_SHARE_COUNTS
        } else {
            PUBLISHED_REQUEST_SHARE_COUNTS
        };
        match preflight_completion_reset_owner(
            self.request.as_ref(),
            expected_reset_identity,
            expected_share_counts,
        ) {
            Ok(()) => Ok(PreparedRequestResetIntent {
                owner: PreparedRequestResetOwner::Failed(self),
            }),
            Err(error) => Err(HardwareIntentFailure { error, owner: self }),
        }
    }
}

enum PreparedRequestResetOwner {
    Completed(CompletedRequest),
    Pending(PendingCompletion),
    Failed(FailedCompletion),
}

/// Linear, prevalidated reset authority returned by every completion actor state.
///
/// The private owner enum retains the exact completed, pending, or failed
/// request wrapper. Descriptive [`DeviceSessionIdentity`] values cannot
/// construct this type, and it is deliberately neither `Clone` nor `Copy`.
#[must_use = "apply reset or retain the prevalidated completion hardware owner"]
pub struct PreparedRequestResetIntent {
    owner: PreparedRequestResetOwner,
}

impl PreparedRequestResetIntent {
    /// Returns descriptive coordinates for binding to an external operation.
    pub fn identity(&self) -> DeviceSessionIdentity {
        match &self.owner {
            PreparedRequestResetOwner::Completed(request) => request.identity(),
            PreparedRequestResetOwner::Pending(request) => request.identity(),
            PreparedRequestResetOwner::Failed(request) => request.identity(),
        }
    }

    /// Infallibly starts reset through the retained wrapper's sole implementation.
    pub fn apply_reset(self, inject_pending_once: bool) -> ProductionResetTombstone {
        match self.owner {
            PreparedRequestResetOwner::Completed(request) => {
                request.begin_reset(inject_pending_once)
            }
            PreparedRequestResetOwner::Pending(request) => request.begin_reset(inject_pending_once),
            PreparedRequestResetOwner::Failed(request) => request.begin_reset(inject_pending_once),
        }
    }
}

/// An explicitly cancelled, never-published request awaiting device closure.
#[must_use = "reset and close the queue/DMA generation"]
pub struct CancelledRequest {
    session: Option<ResetSession>,
}

/// An unpublished request cancelled because its registry device cohort was
/// never installed.
#[must_use = "begin reset and retain the unregistered cancellation authority"]
pub struct UnregisteredCancelledRequest {
    request: Option<CancelledRequest>,
    cancellation: Option<UnregisteredPreparedCancellation>,
}

impl UnregisteredCancelledRequest {
    /// Returns the exact unpublished hardware identity being cancelled.
    pub fn identity(&self) -> DeviceSessionIdentity {
        self.cancellation
            .as_ref()
            .expect("unregistered cancellation authority")
            .identity
    }

    /// Starts mandatory whole-device reset and returns the unique authority
    /// for applying hardware-only generation and quiescence updates.
    pub fn begin_reset(
        mut self,
        inject_pending_once: bool,
    ) -> (ProductionResetTombstone, UnregisteredPreparedCancellation) {
        let reset = self
            .request
            .take()
            .expect("unregistered cancelled request")
            .begin_reset(inject_pending_once);
        let cancellation = self
            .cancellation
            .take()
            .expect("unregistered cancellation authority");
        (reset, cancellation)
    }
}

impl CancelledRequest {
    /// Starts mandatory whole-device reset after unpublished cancellation.
    pub fn begin_reset(mut self, inject_pending_once: bool) -> ProductionResetTombstone {
        ProductionResetTombstone::new(
            self.session.take().expect("cancelled request session"),
            inject_pending_once,
        )
    }
}

impl Drop for CancelledRequest {
    fn drop(&mut self) {
        if let Some(mut session) = self.session.take() {
            session.quarantine();
        }
    }
}

struct ResetSession {
    attempt: PreparationAttemptIdentity,
    identity: DeviceSessionIdentity,
    device_function: DeviceFunction,
    transport: Option<PciTransport>,
    queue: Option<Queue>,
    buffers: Option<Pin<Box<RequestBuffers>>>,
    published: bool,
    descriptor_popped: bool,
    completed: bool,
}

impl ResetSession {
    fn begin_reset(self, inject_pending_once: bool) -> ProductionResetTombstone {
        ProductionResetTombstone::new(self, inject_pending_once)
    }

    fn quarantine(&mut self) {
        quarantine(&mut self.queue);
        quarantine(&mut self.transport);
        quarantine(&mut self.buffers);
    }
}

/// A retained whole-device reset attempt.
#[must_use = "retry reset or retain the complete device and DMA owners"]
pub struct ProductionResetTombstone {
    session: ManuallyDrop<ResetSession>,
    inject_pending_once: bool,
}

impl ProductionResetTombstone {
    fn new(mut session: ResetSession, inject_pending_once: bool) -> Self {
        session
            .transport
            .as_mut()
            .expect("live transport")
            .set_status(DeviceStatus::empty());
        Self {
            session: ManuallyDrop::new(session),
            inject_pending_once,
        }
    }

    /// Returns the preparation attempt retained by this reset owner.
    pub fn attempt(&self) -> PreparationAttemptIdentity {
        self.session.attempt
    }

    /// Returns the number of retained DMA pages.
    pub fn retained_dma_pages(&self) -> usize {
        dma::retained_pages(self.session.identity.device_generation)
    }

    /// Performs at most one reset-status observation for a runtime actor.
    ///
    /// The injected first-pending result and a not-yet-empty status both
    /// return this exact tombstone for reinsertion into its actor slot. A ready
    /// observation consumes the sole shared reset-finalization path.
    pub fn probe_ack_once(
        mut self,
        root: &mut Root,
    ) -> Result<ProductionResetAck, ProductionResetRetryFailure> {
        if self.inject_pending_once {
            self.inject_pending_once = false;
            return Err(ProductionResetRetryFailure {
                error: ProductionResetRetryError::Pending,
                tombstone: self,
            });
        }
        if !self.reset_status_acknowledged() {
            return Err(ProductionResetRetryFailure {
                error: ProductionResetRetryError::Pending,
                tombstone: self,
            });
        }
        self.finalize_acknowledged_reset(root)
    }

    /// Polls for reset acknowledgement, retaining this tombstone on timeout.
    pub fn retry_ack(
        mut self,
        root: &mut Root,
    ) -> Result<ProductionResetAck, ProductionResetRetryFailure> {
        if self.inject_pending_once {
            self.inject_pending_once = false;
            return Err(ProductionResetRetryFailure {
                error: ProductionResetRetryError::Pending,
                tombstone: self,
            });
        }
        for _ in 0..POLL_LIMIT {
            if self.reset_status_acknowledged() {
                return self.finalize_acknowledged_reset(root);
            }
            spin_loop();
        }
        Err(ProductionResetRetryFailure {
            error: ProductionResetRetryError::Pending,
            tombstone: self,
        })
    }

    fn reset_status_acknowledged(&self) -> bool {
        self.session
            .transport
            .as_ref()
            .expect("retained transport")
            .get_status()
            == DeviceStatus::empty()
    }

    fn finalize_acknowledged_reset(
        mut self,
        root: &mut Root,
    ) -> Result<ProductionResetAck, ProductionResetRetryFailure> {
        if let Err(error) = pci::disable_bus_master_checked(root, self.session.device_function) {
            let error = match error {
                pci::PrepareCommandFailure::ForeignRoot => ProductionResetRetryError::ForeignRoot,
                pci::PrepareCommandFailure::IntxStateUnavailable => {
                    ProductionResetRetryError::PciCommandStateUnavailable
                }
                pci::PrepareCommandFailure::ReadbackMismatch { .. } => {
                    ProductionResetRetryError::PciCommandReadbackMismatch
                }
            };
            return Err(ProductionResetRetryFailure {
                error,
                tombstone: self,
            });
        }
        let _ = self
            .session
            .transport
            .as_mut()
            .expect("retained transport")
            .ack_interrupt();
        let generation = self.session.identity.device_generation;
        // SAFETY: status zero and BUS_MASTER=false were observed for the exact
        // transport and generation above.
        let reset = unsafe { dma::acknowledge_device_reset(generation) };
        // SAFETY: all preceding fallible branches retained `self`; only the
        // acknowledged path extracts its complete reset session.
        let mut session = unsafe { ManuallyDrop::take(&mut self.session) };
        let queue = session.queue.take().expect("retained queue");
        // SAFETY: device reset was acknowledged and original buffers remain
        // pinned until the queue has been destroyed.
        unsafe { abandon_queue_after_reset(queue) };
        let closure_authority = dma::seal_queue_retirement(reset);
        drop(session.transport.take().expect("retained transport"));
        // SAFETY: queue and transport are both gone, so no raw BAR capability
        // pointer remains live.
        unsafe { pci::release_transport_claims() };
        assert_eq!(dma::retained_pages(generation), 3);

        Ok(ProductionResetAck {
            attempt: session.attempt,
            identity: session.identity,
            published: session.published,
            descriptor_popped: session.descriptor_popped,
            completed: session.completed,
            retained_dma_pages: 3,
            closure_authority,
            generation_applied: false,
        })
    }
}

/// Reset acknowledgement carrying the only IOTLB-closure authority.
#[must_use = "apply the generation fence and begin IOTLB closure"]
pub struct ProductionResetAck {
    attempt: PreparationAttemptIdentity,
    identity: DeviceSessionIdentity,
    published: bool,
    descriptor_popped: bool,
    completed: bool,
    retained_dma_pages: usize,
    closure_authority: dma::DmaClosureAuthority,
    generation_applied: bool,
}

impl ProductionResetAck {
    /// Returns the preparation attempt retained through reset.
    pub const fn attempt(&self) -> PreparationAttemptIdentity {
        self.attempt
    }

    /// Returns the closed request identity.
    pub const fn identity(&self) -> DeviceSessionIdentity {
        self.identity
    }

    /// Reports whether `avail.idx` was published before reset.
    pub const fn was_published(&self) -> bool {
        self.published
    }

    /// Reports whether the matching descriptor chain was popped before reset.
    pub const fn was_descriptor_popped(&self) -> bool {
        self.descriptor_popped
    }

    /// Reports whether pop, response status, and share accounting all succeeded.
    pub const fn was_completed(&self) -> bool {
        self.completed
    }

    /// Returns the retained DMA page count.
    pub const fn retained_dma_pages(&self) -> usize {
        self.retained_dma_pages
    }
}

/// IOTLB completion progress for one reset generation.
#[must_use = "complete IOTLB closure or retain its tombstone"]
pub enum ProductionClosureProgress {
    /// All three owners completed invalidation.
    Complete(ProductionClosureReceipt),
    /// One owner remains pending or fail-closed.
    Pending(ProductionIotlbTombstone),
}

/// Retained IOTLB owner and retry authority.
#[must_use = "retry or retain the pending IOTLB owner"]
pub struct ProductionIotlbTombstone {
    attempt: PreparationAttemptIdentity,
    identity: DeviceSessionIdentity,
    dma: dma::IotlbTombstone,
}

impl ProductionIotlbTombstone {
    /// Returns the preparation attempt retained through IOTLB retry.
    pub const fn attempt(&self) -> PreparationAttemptIdentity {
        self.attempt
    }

    /// Returns the retained request identity.
    pub const fn identity(&self) -> DeviceSessionIdentity {
        self.identity
    }

    /// Returns all still-retained DMA pages.
    pub fn retained_pages(&self) -> usize {
        self.dma.retained_pages()
    }

    /// Reports whether OSTD retained a terminal invalidation failure.
    pub fn failure_retained(&self) -> bool {
        self.dma.failure_retained()
    }

    /// Polls the same retained owner with a bounded budget.
    pub fn retry(
        self,
        poll_budget: usize,
    ) -> Result<ProductionClosureProgress, ProductionIotlbRetryFailure> {
        if poll_budget == 0 {
            return Err(ProductionIotlbRetryFailure {
                error: ProductionIotlbRetryError::ZeroPollBudget,
                tombstone: self,
            });
        }
        Ok(production_closure_progress(
            self.attempt,
            self.identity,
            self.dma.retry(poll_budget),
        ))
    }
}

/// Completed IOTLB receipt paired with a quiescence apply plan.
#[must_use = "publish hardware quiescence through the owning device"]
pub struct ProductionClosureReceipt {
    attempt: PreparationAttemptIdentity,
    identity: DeviceSessionIdentity,
    dma: dma::ClosureReceipt,
    applied: bool,
}

impl ProductionClosureReceipt {
    /// Returns the exact preparation attempt whose DMA owners closed.
    pub const fn attempt(&self) -> PreparationAttemptIdentity {
        self.attempt
    }

    /// Returns the closed request identity.
    pub const fn identity(&self) -> DeviceSessionIdentity {
        self.identity
    }

    /// Returns the number of completed DMA owners.
    pub const fn completed_pages(&self) -> usize {
        self.dma.completed_pages()
    }
}

fn production_closure_progress(
    attempt: PreparationAttemptIdentity,
    identity: DeviceSessionIdentity,
    progress: dma::ClosureProgress,
) -> ProductionClosureProgress {
    match progress {
        dma::ClosureProgress::Complete(dma) => {
            ProductionClosureProgress::Complete(ProductionClosureReceipt {
                attempt,
                identity,
                dma,
                applied: false,
            })
        }
        dma::ClosureProgress::Pending(dma) => {
            ProductionClosureProgress::Pending(ProductionIotlbTombstone {
                attempt,
                identity,
                dma,
            })
        }
    }
}

/// Ends queue ownership after an acknowledged whole-device reset.
///
/// # Safety
///
/// The exact device must have status zero and BUS_MASTER=false, and all original
/// request buffers must remain pinned until this function returns.
unsafe fn abandon_queue_after_reset(queue: Queue) {
    drop(queue);
}

fn quarantine<T>(slot: &mut Option<T>) {
    if let Some(owner) = slot.take() {
        forget(owner);
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    const SOURCE: &str = include_str!("production.rs");

    const IDENTITY: DeviceSessionIdentity = DeviceSessionIdentity::from_coordinates(
        0x4300_0000_0000_0001,
        DeviceBdf::from_coordinates(0, 5, 0),
        0,
        7,
        3,
    );
    const FOREIGN_IDENTITY: DeviceSessionIdentity = DeviceSessionIdentity::from_coordinates(
        0x4300_0000_0000_0002,
        DeviceBdf::from_coordinates(0, 5, 0),
        0,
        8,
        3,
    );
    const ATTEMPT: PreparationAttemptIdentity = PreparationAttemptIdentity {
        owner_id: 11,
        sequence: 7,
    };
    const FOREIGN_ATTEMPT: PreparationAttemptIdentity = PreparationAttemptIdentity {
        owner_id: 12,
        sequence: 9,
    };
    const DEVICE_FUNCTION: DeviceFunction = DeviceFunction {
        bus: 0,
        device: 5,
        function: 0,
    };

    fn preparation_device() -> PreparationDeviceProjection {
        PreparationDeviceProjection {
            owner_id: ATTEMPT.owner_id,
            device_function: DEVICE_FUNCTION,
            device_bdf: IDENTITY.device_bdf,
            device_generation: IDENTITY.device_generation,
        }
    }

    fn active_session(issued: bool) -> ActiveSession {
        ActiveSession {
            identity: IDENTITY,
            attempt: ATTEMPT,
            preparation_receipt_issued: issued,
            reset_acknowledged: false,
        }
    }

    fn preparation_request() -> PreparationRequestProjection {
        PreparationRequestProjection {
            attempt: ATTEMPT,
            identity: IDENTITY,
            completion_mode: CompletionMode::Polling,
            device_function: DEVICE_FUNCTION,
            descriptor_token: IDENTITY.descriptor_token,
            transport_ready: true,
        }
    }

    fn live_dma() -> dma::PreparationDmaObservation {
        dma::PreparationDmaObservation {
            generation: IDENTITY.device_generation,
            device_exposed: true,
            reset_acked: false,
            owner_count: 3,
            active_owner_count: 3,
            owner_generations_match: true,
            request_share_count: 3,
            request_unshare_count: 0,
            active_request_shares: 3,
        }
    }

    fn quiescent_dma() -> dma::PreparationDmaObservation {
        dma::PreparationDmaObservation {
            generation: 0,
            device_exposed: false,
            reset_acked: false,
            owner_count: 0,
            active_owner_count: 0,
            owner_generations_match: true,
            request_share_count: 0,
            request_unshare_count: 0,
            active_request_shares: 0,
        }
    }

    const fn live_transport() -> pci::TransportClaimObservation {
        pci::TransportClaimObservation {
            active: true,
            claim_count: 3,
        }
    }

    const fn quiescent_transport() -> pci::TransportClaimObservation {
        pci::TransportClaimObservation {
            active: false,
            claim_count: 0,
        }
    }

    const fn quiescence_projection(
        active_request: bool,
        hardware_certain: bool,
        dma: dma::PreparationDmaObservation,
        transport: pci::TransportClaimObservation,
    ) -> PreparationQuiescenceProjection {
        PreparationQuiescenceProjection {
            active_request,
            hardware_certain,
            dma,
            transport,
        }
    }

    fn expect_success_error(
        device: PreparationDeviceProjection,
        active: ActiveSession,
        request: PreparationRequestProjection,
        dma: dma::PreparationDmaObservation,
        transport: pci::TransportClaimObservation,
        expected_issued: bool,
        expected: PreparationEvidenceError,
    ) {
        assert_eq!(
            prepare_success_receipt(device, active, request, dma, transport, expected_issued),
            Err(expected)
        );
    }

    fn function_body<'a>(source: &'a str, signature: &str) -> &'a str {
        let start = source.find(signature).expect("function signature exists");
        let open = source[start..]
            .find('{')
            .map(|offset| start + offset)
            .expect("function body opens");
        let mut depth = 0usize;
        for (offset, byte) in source[open..].bytes().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &source[start..=open + offset];
                    }
                }
                _ => {}
            }
        }
        panic!("function body closes");
    }

    #[test]
    fn completion_modes_select_distinct_device_notification_flags() {
        assert!(!CompletionMode::Polling.device_notifications_enabled());
        assert!(CompletionMode::Interrupt.device_notifications_enabled());

        let polling = function_body(SOURCE, "pub fn prepare_read_sector0(");
        let interrupt = function_body(SOURCE, "pub fn prepare_read_sector0_irq(");
        let common = function_body(SOURCE, "fn prepare_read_sector0_with_mode(");
        assert!(polling.contains("CompletionMode::Polling"));
        assert!(interrupt.contains("CompletionMode::Interrupt"));
        assert!(
            common
                .contains("queue.set_dev_notify(completion_mode.device_notifications_enabled());")
        );
    }

    #[test]
    fn interrupt_status_decodes_all_queue_and_configuration_causes() {
        let queue = InterruptStatus::QUEUE_INTERRUPT;
        let configuration = InterruptStatus::DEVICE_CONFIGURATION_INTERRUPT;
        assert_eq!(
            decode_interrupt_status(InterruptStatus::empty()),
            InterruptCause::Spurious
        );
        assert_eq!(decode_interrupt_status(queue), InterruptCause::Queue);
        assert_eq!(
            decode_interrupt_status(configuration),
            InterruptCause::Configuration
        );
        assert_eq!(
            decode_interrupt_status(queue | configuration),
            InterruptCause::QueueAndConfiguration
        );
    }

    #[test]
    fn polling_and_irq_share_one_non_spinning_completion_validator() {
        let acknowledgement = function_body(SOURCE, "pub fn ack_interrupt(");
        let interrupt = function_body(SOURCE, "pub fn complete_after_interrupt(");
        let probe = function_body(SOURCE, "pub fn probe_completion_once(");
        let polling = function_body(SOURCE, "pub fn poll_completion(");
        let once = function_body(SOURCE, "fn complete_once(");
        let validator = function_body(SOURCE, "fn complete_observed(");

        assert!(acknowledgement.contains(".ack_interrupt()"));
        assert!(!acknowledgement.contains("spin_loop"));
        assert!(!acknowledgement.contains("Box::"));
        assert!(interrupt.contains("self.probe_completion_once()"));
        assert!(!interrupt.contains("spin_loop"));
        assert!(probe.contains("self.complete_once()"));
        assert!(!probe.contains("spin_loop"));
        assert!(!probe.contains("pop_used"));
        assert!(polling.contains("request.probe_completion_once()"));
        assert!(once.contains("self.complete_observed(observed)"));
        assert!(!once.contains("spin_loop"));
        assert!(!validator.contains("spin_loop"));
        assert!(validator.contains("queue.pop_used(expected, &inputs, &mut outputs)"));
        assert!(validator.contains("CompletionFailure::UnexpectedUsedLength"));
        assert!(validator.contains("CompletionFailure::DeviceResponse"));
        assert!(validator.contains("CompletionFailure::ShareAccountingMismatch"));
        let implementation = SOURCE
            .split_once("#[cfg(test)]")
            .expect("test module follows implementation")
            .0;
        assert_eq!(
            implementation
                .matches("queue.pop_used(expected, &inputs, &mut outputs)")
                .count(),
            1,
            "completion validation must not fork between polling and IRQ"
        );
    }

    #[test]
    fn successful_preparation_receipt_binds_every_live_projection() {
        let receipt = prepare_success_receipt(
            preparation_device(),
            active_session(false),
            preparation_request(),
            live_dma(),
            live_transport(),
            false,
        )
        .expect("complete live projection");

        assert_eq!(receipt.attempt(), ATTEMPT);
        assert_eq!(receipt.identity(), IDENTITY);
        assert_eq!(receipt.completion_mode(), CompletionMode::Polling);
        assert_eq!(receipt.dma_owner_count(), 3);
        assert_eq!(receipt.dma_share_count(), 3);
        assert_eq!(receipt.transport_claim_count(), 3);
        assert_ne!(receipt.digest(), 0);

        let revalidated = prepare_success_receipt(
            preparation_device(),
            active_session(true),
            preparation_request(),
            live_dma(),
            live_transport(),
            true,
        )
        .expect("publication revalidation");
        assert_eq!(receipt, revalidated);
    }

    #[test]
    fn preparation_receipt_rejects_owner_attempt_session_and_device_substitution() {
        let mut device = preparation_device();
        device.owner_id = FOREIGN_ATTEMPT.owner_id;
        expect_success_error(
            device,
            active_session(false),
            preparation_request(),
            live_dma(),
            live_transport(),
            false,
            PreparationEvidenceError::ForeignOwner,
        );

        let mut active = active_session(false);
        active.attempt.owner_id = FOREIGN_ATTEMPT.owner_id;
        expect_success_error(
            preparation_device(),
            active,
            preparation_request(),
            live_dma(),
            live_transport(),
            false,
            PreparationEvidenceError::ForeignOwner,
        );

        let mut request = preparation_request();
        request.attempt.owner_id = FOREIGN_ATTEMPT.owner_id;
        expect_success_error(
            preparation_device(),
            active_session(false),
            request,
            live_dma(),
            live_transport(),
            false,
            PreparationEvidenceError::ForeignOwner,
        );

        let mut active = active_session(false);
        active.attempt.sequence += 1;
        expect_success_error(
            preparation_device(),
            active,
            preparation_request(),
            live_dma(),
            live_transport(),
            false,
            PreparationEvidenceError::WrongAttempt,
        );

        let mut request = preparation_request();
        request.attempt.sequence += 1;
        expect_success_error(
            preparation_device(),
            active_session(false),
            request,
            live_dma(),
            live_transport(),
            false,
            PreparationEvidenceError::WrongAttempt,
        );

        let mut active = active_session(false);
        active.identity = FOREIGN_IDENTITY;
        expect_success_error(
            preparation_device(),
            active,
            preparation_request(),
            live_dma(),
            live_transport(),
            false,
            PreparationEvidenceError::WrongSession,
        );

        let mut request = preparation_request();
        request.identity = FOREIGN_IDENTITY;
        expect_success_error(
            preparation_device(),
            active_session(false),
            request,
            live_dma(),
            live_transport(),
            false,
            PreparationEvidenceError::WrongSession,
        );

        let mut request = preparation_request();
        request.device_function.device += 1;
        expect_success_error(
            preparation_device(),
            active_session(false),
            request,
            live_dma(),
            live_transport(),
            false,
            PreparationEvidenceError::WrongDevice,
        );

        let substituted = DeviceSessionIdentity::from_coordinates(
            IDENTITY.device_session,
            DeviceBdf::from_coordinates(0, 6, 0),
            IDENTITY.queue,
            IDENTITY.descriptor_token,
            IDENTITY.device_generation,
        );
        let mut active = active_session(false);
        active.identity = substituted;
        let mut request = preparation_request();
        request.identity = substituted;
        expect_success_error(
            preparation_device(),
            active,
            request,
            live_dma(),
            live_transport(),
            false,
            PreparationEvidenceError::WrongDevice,
        );
    }

    #[test]
    fn preparation_receipt_rejects_queue_token_status_and_stale_generation() {
        let mut identity = IDENTITY;
        identity.queue = 1;
        let mut active = active_session(false);
        active.identity = identity;
        let mut request = preparation_request();
        request.identity = identity;
        expect_success_error(
            preparation_device(),
            active,
            request,
            live_dma(),
            live_transport(),
            false,
            PreparationEvidenceError::WrongQueue,
        );

        let mut request = preparation_request();
        request.descriptor_token += 1;
        expect_success_error(
            preparation_device(),
            active_session(false),
            request,
            live_dma(),
            live_transport(),
            false,
            PreparationEvidenceError::DescriptorTokenMismatch,
        );

        let mut request = preparation_request();
        request.transport_ready = false;
        expect_success_error(
            preparation_device(),
            active_session(false),
            request,
            live_dma(),
            live_transport(),
            false,
            PreparationEvidenceError::TransportStatusMismatch,
        );

        let mut device = preparation_device();
        device.device_generation += 1;
        expect_success_error(
            device,
            active_session(false),
            preparation_request(),
            live_dma(),
            live_transport(),
            false,
            PreparationEvidenceError::StaleDeviceGeneration,
        );

        let mut identity = IDENTITY;
        identity.device_generation += 1;
        let mut active = active_session(false);
        active.identity = identity;
        let mut request = preparation_request();
        request.identity = identity;
        expect_success_error(
            preparation_device(),
            active,
            request,
            live_dma(),
            live_transport(),
            false,
            PreparationEvidenceError::StaleDeviceGeneration,
        );
    }

    #[test]
    fn preparation_receipt_rejects_each_dma_and_transport_claim_mutation() {
        for dma in [
            dma::PreparationDmaObservation {
                generation: IDENTITY.device_generation + 1,
                ..live_dma()
            },
            dma::PreparationDmaObservation {
                device_exposed: false,
                ..live_dma()
            },
            dma::PreparationDmaObservation {
                reset_acked: true,
                ..live_dma()
            },
        ] {
            expect_success_error(
                preparation_device(),
                active_session(false),
                preparation_request(),
                dma,
                live_transport(),
                false,
                PreparationEvidenceError::DmaGenerationMismatch,
            );
        }

        for dma in [
            dma::PreparationDmaObservation {
                owner_count: 2,
                ..live_dma()
            },
            dma::PreparationDmaObservation {
                active_owner_count: 2,
                ..live_dma()
            },
            dma::PreparationDmaObservation {
                owner_generations_match: false,
                ..live_dma()
            },
        ] {
            expect_success_error(
                preparation_device(),
                active_session(false),
                preparation_request(),
                dma,
                live_transport(),
                false,
                PreparationEvidenceError::DmaOwnerStateMismatch,
            );
        }

        for dma in [
            dma::PreparationDmaObservation {
                request_share_count: 2,
                ..live_dma()
            },
            dma::PreparationDmaObservation {
                request_unshare_count: 1,
                ..live_dma()
            },
            dma::PreparationDmaObservation {
                active_request_shares: 2,
                ..live_dma()
            },
        ] {
            expect_success_error(
                preparation_device(),
                active_session(false),
                preparation_request(),
                dma,
                live_transport(),
                false,
                PreparationEvidenceError::DmaShareStateMismatch,
            );
        }

        for transport in [
            pci::TransportClaimObservation {
                active: false,
                claim_count: 3,
            },
            pci::TransportClaimObservation {
                active: true,
                claim_count: 2,
            },
            pci::TransportClaimObservation {
                active: true,
                claim_count: 5,
            },
        ] {
            expect_success_error(
                preparation_device(),
                active_session(false),
                preparation_request(),
                live_dma(),
                transport,
                false,
                PreparationEvidenceError::TransportClaimMismatch,
            );
        }
    }

    #[test]
    fn preparation_receipt_rejects_duplicate_or_wrong_issuance_phase() {
        expect_success_error(
            preparation_device(),
            active_session(true),
            preparation_request(),
            live_dma(),
            live_transport(),
            false,
            PreparationEvidenceError::DuplicateIssuance,
        );
        expect_success_error(
            preparation_device(),
            active_session(false),
            preparation_request(),
            live_dma(),
            live_transport(),
            true,
            PreparationEvidenceError::DuplicateIssuance,
        );
    }

    #[test]
    fn rollback_receipts_distinguish_unexposed_and_prepared_generation_lineage() {
        let unexposed = prepare_rollback_receipt(
            preparation_device(),
            ATTEMPT,
            None,
            PreparationRollbackKind::UnexposedFailure,
            quiescence_projection(false, true, quiescent_dma(), quiescent_transport()),
        )
        .expect("unexposed G to G rollback")
        .finish();
        assert_eq!(unexposed.attempt(), ATTEMPT);
        assert_eq!(unexposed.request_identity(), None);
        assert_eq!(unexposed.device_generation(), 3);
        assert_eq!(unexposed.quiescent_device_generation(), 3);
        assert_eq!(unexposed.kind(), PreparationRollbackKind::UnexposedFailure);
        assert_ne!(unexposed.digest(), 0);

        let mut successor = preparation_device();
        successor.device_generation = 4;
        let prepared = prepare_rollback_receipt(
            successor,
            ATTEMPT,
            Some(IDENTITY),
            PreparationRollbackKind::PreparedCancellation,
            quiescence_projection(false, true, quiescent_dma(), quiescent_transport()),
        )
        .expect("prepared G to G+1 rollback")
        .finish();
        assert_eq!(prepared.request_identity(), Some(IDENTITY));
        assert_eq!(prepared.device_generation(), 3);
        assert_eq!(prepared.quiescent_device_generation(), 4);
        assert_eq!(
            prepared.kind(),
            PreparationRollbackKind::PreparedCancellation
        );
        assert_ne!(unexposed.digest(), prepared.digest());
    }

    #[test]
    fn rollback_receipt_rejects_uncertainty_lineage_and_every_nonzero_owner_field() {
        let reject = |device, attempt, identity, kind, quiescence| {
            assert!(prepare_rollback_receipt(device, attempt, identity, kind, quiescence).is_err());
        };

        reject(
            preparation_device(),
            ATTEMPT,
            None,
            PreparationRollbackKind::UnexposedFailure,
            quiescence_projection(true, true, quiescent_dma(), quiescent_transport()),
        );
        reject(
            preparation_device(),
            ATTEMPT,
            None,
            PreparationRollbackKind::UnexposedFailure,
            quiescence_projection(false, false, quiescent_dma(), quiescent_transport()),
        );
        reject(
            preparation_device(),
            FOREIGN_ATTEMPT,
            None,
            PreparationRollbackKind::UnexposedFailure,
            quiescence_projection(false, true, quiescent_dma(), quiescent_transport()),
        );
        reject(
            preparation_device(),
            ATTEMPT,
            Some(IDENTITY),
            PreparationRollbackKind::UnexposedFailure,
            quiescence_projection(false, true, quiescent_dma(), quiescent_transport()),
        );
        reject(
            preparation_device(),
            ATTEMPT,
            None,
            PreparationRollbackKind::PreparedCancellation,
            quiescence_projection(false, true, quiescent_dma(), quiescent_transport()),
        );
        reject(
            preparation_device(),
            ATTEMPT,
            Some(IDENTITY),
            PreparationRollbackKind::PreparedCancellation,
            quiescence_projection(false, true, quiescent_dma(), quiescent_transport()),
        );

        for dma in [
            dma::PreparationDmaObservation {
                generation: 3,
                ..quiescent_dma()
            },
            dma::PreparationDmaObservation {
                device_exposed: true,
                ..quiescent_dma()
            },
            dma::PreparationDmaObservation {
                reset_acked: true,
                ..quiescent_dma()
            },
            dma::PreparationDmaObservation {
                owner_count: 1,
                ..quiescent_dma()
            },
            dma::PreparationDmaObservation {
                active_owner_count: 1,
                ..quiescent_dma()
            },
            dma::PreparationDmaObservation {
                owner_generations_match: false,
                ..quiescent_dma()
            },
            dma::PreparationDmaObservation {
                request_share_count: 1,
                ..quiescent_dma()
            },
            dma::PreparationDmaObservation {
                request_unshare_count: 1,
                ..quiescent_dma()
            },
            dma::PreparationDmaObservation {
                active_request_shares: 1,
                ..quiescent_dma()
            },
        ] {
            reject(
                preparation_device(),
                ATTEMPT,
                None,
                PreparationRollbackKind::UnexposedFailure,
                quiescence_projection(false, true, dma, quiescent_transport()),
            );
        }
        for transport in [
            pci::TransportClaimObservation {
                active: true,
                claim_count: 0,
            },
            pci::TransportClaimObservation {
                active: false,
                claim_count: 1,
            },
        ] {
            reject(
                preparation_device(),
                ATTEMPT,
                None,
                PreparationRollbackKind::UnexposedFailure,
                quiescence_projection(false, true, quiescent_dma(), transport),
            );
        }
    }

    #[test]
    fn indeterminate_reports_observation_but_cannot_become_a_receipt() {
        let dma = dma::PreparationDmaObservation {
            generation: 3,
            device_exposed: true,
            reset_acked: true,
            owner_count: 2,
            active_owner_count: 1,
            owner_generations_match: false,
            request_share_count: 3,
            request_unshare_count: 2,
            active_request_shares: 1,
            ..quiescent_dma()
        };
        let transport = pci::TransportClaimObservation {
            active: true,
            claim_count: 4,
        };
        let indeterminate = match prepare_rollback_receipt(
            preparation_device(),
            ATTEMPT,
            None,
            PreparationRollbackKind::UnexposedFailure,
            quiescence_projection(true, false, dma, transport),
        ) {
            Ok(_) => panic!("uncertain hardware cannot be receipted"),
            Err(indeterminate) => indeterminate,
        };
        assert_eq!(indeterminate.attempt(), ATTEMPT);
        assert_eq!(indeterminate.device_bdf(), IDENTITY.device_bdf());
        assert_eq!(indeterminate.device_generation(), 3);
        assert_eq!(indeterminate.current_device_generation(), 3);
        assert!(indeterminate.active_request());
        assert!(!indeterminate.hardware_certain());
        assert_eq!(indeterminate.dma_generation(), 3);
        assert!(indeterminate.dma_device_exposed());
        assert!(indeterminate.dma_reset_acked());
        assert_eq!(indeterminate.dma_owner_count(), 2);
        assert_eq!(indeterminate.dma_active_owner_count(), 1);
        assert!(!indeterminate.dma_owner_generations_match());
        assert_eq!(indeterminate.dma_request_share_count(), 3);
        assert_eq!(indeterminate.dma_request_unshare_count(), 2);
        assert_eq!(indeterminate.dma_active_request_shares(), 1);
        assert!(indeterminate.transport_active());
        assert_eq!(indeterminate.transport_claim_count(), 4);
        assert_ne!(indeterminate.observation_digest(), 0);

        let changed = preparation_indeterminate(
            IndeterminateAttemptProjection {
                attempt: ATTEMPT,
                device_bdf: IDENTITY.device_bdf(),
                attempt_generation: 3,
                current_generation: 3,
                active_request: true,
                hardware_certain: false,
            },
            dma::PreparationDmaObservation {
                request_unshare_count: 1,
                ..dma
            },
            transport,
        );
        assert_ne!(
            indeterminate.observation_digest(),
            changed.observation_digest(),
            "every retained-state coordinate binds the observation"
        );
    }

    #[test]
    fn indeterminate_digest_binds_every_observed_coordinate() {
        let digest = |attempt,
                      bdf,
                      attempt_generation,
                      current_generation,
                      active,
                      certain,
                      dma,
                      transport| {
            preparation_indeterminate(
                IndeterminateAttemptProjection {
                    attempt,
                    device_bdf: bdf,
                    attempt_generation,
                    current_generation,
                    active_request: active,
                    hardware_certain: certain,
                },
                dma,
                transport,
            )
            .observation_digest()
        };
        let dma = live_dma();
        let transport = live_transport();
        let base = digest(
            ATTEMPT,
            IDENTITY.device_bdf(),
            3,
            4,
            true,
            false,
            dma,
            transport,
        );
        let mutations = [
            digest(
                PreparationAttemptIdentity {
                    owner_id: ATTEMPT.owner_id + 1,
                    ..ATTEMPT
                },
                IDENTITY.device_bdf(),
                3,
                4,
                true,
                false,
                dma,
                transport,
            ),
            digest(
                PreparationAttemptIdentity {
                    sequence: ATTEMPT.sequence + 1,
                    ..ATTEMPT
                },
                IDENTITY.device_bdf(),
                3,
                4,
                true,
                false,
                dma,
                transport,
            ),
            digest(
                ATTEMPT,
                DeviceBdf::from_coordinates(1, 5, 0),
                3,
                4,
                true,
                false,
                dma,
                transport,
            ),
            digest(
                ATTEMPT,
                DeviceBdf::from_coordinates(0, 6, 0),
                3,
                4,
                true,
                false,
                dma,
                transport,
            ),
            digest(
                ATTEMPT,
                DeviceBdf::from_coordinates(0, 5, 1),
                3,
                4,
                true,
                false,
                dma,
                transport,
            ),
            digest(
                ATTEMPT,
                IDENTITY.device_bdf(),
                2,
                4,
                true,
                false,
                dma,
                transport,
            ),
            digest(
                ATTEMPT,
                IDENTITY.device_bdf(),
                3,
                5,
                true,
                false,
                dma,
                transport,
            ),
            digest(
                ATTEMPT,
                IDENTITY.device_bdf(),
                3,
                4,
                false,
                false,
                dma,
                transport,
            ),
            digest(
                ATTEMPT,
                IDENTITY.device_bdf(),
                3,
                4,
                true,
                true,
                dma,
                transport,
            ),
            digest(
                ATTEMPT,
                IDENTITY.device_bdf(),
                3,
                4,
                true,
                false,
                dma::PreparationDmaObservation {
                    generation: dma.generation + 1,
                    ..dma
                },
                transport,
            ),
            digest(
                ATTEMPT,
                IDENTITY.device_bdf(),
                3,
                4,
                true,
                false,
                dma::PreparationDmaObservation {
                    device_exposed: !dma.device_exposed,
                    ..dma
                },
                transport,
            ),
            digest(
                ATTEMPT,
                IDENTITY.device_bdf(),
                3,
                4,
                true,
                false,
                dma::PreparationDmaObservation {
                    reset_acked: !dma.reset_acked,
                    ..dma
                },
                transport,
            ),
            digest(
                ATTEMPT,
                IDENTITY.device_bdf(),
                3,
                4,
                true,
                false,
                dma::PreparationDmaObservation {
                    owner_count: 2,
                    ..dma
                },
                transport,
            ),
            digest(
                ATTEMPT,
                IDENTITY.device_bdf(),
                3,
                4,
                true,
                false,
                dma::PreparationDmaObservation {
                    active_owner_count: 2,
                    ..dma
                },
                transport,
            ),
            digest(
                ATTEMPT,
                IDENTITY.device_bdf(),
                3,
                4,
                true,
                false,
                dma::PreparationDmaObservation {
                    owner_generations_match: !dma.owner_generations_match,
                    ..dma
                },
                transport,
            ),
            digest(
                ATTEMPT,
                IDENTITY.device_bdf(),
                3,
                4,
                true,
                false,
                dma::PreparationDmaObservation {
                    request_share_count: 2,
                    ..dma
                },
                transport,
            ),
            digest(
                ATTEMPT,
                IDENTITY.device_bdf(),
                3,
                4,
                true,
                false,
                dma::PreparationDmaObservation {
                    request_unshare_count: 1,
                    ..dma
                },
                transport,
            ),
            digest(
                ATTEMPT,
                IDENTITY.device_bdf(),
                3,
                4,
                true,
                false,
                dma::PreparationDmaObservation {
                    active_request_shares: 2,
                    ..dma
                },
                transport,
            ),
            digest(
                ATTEMPT,
                IDENTITY.device_bdf(),
                3,
                4,
                true,
                false,
                dma,
                pci::TransportClaimObservation {
                    active: false,
                    ..transport
                },
            ),
            digest(
                ATTEMPT,
                IDENTITY.device_bdf(),
                3,
                4,
                true,
                false,
                dma,
                pci::TransportClaimObservation {
                    claim_count: 4,
                    ..transport
                },
            ),
        ];
        assert_ne!(base, 0);
        for mutation in mutations {
            assert_ne!(base, mutation);
        }
    }

    #[test]
    fn preparation_gate_is_exclusive_and_releases_on_drop() {
        assert_eq!(PREPARATION_GATE_OWNER.load(Ordering::Relaxed), 0);
        let first = PreparationGate::acquire(ATTEMPT.owner_id).expect("first owner acquires");
        assert_eq!(
            PREPARATION_GATE_OWNER.load(Ordering::Relaxed),
            ATTEMPT.owner_id
        );
        assert!(PreparationGate::acquire(FOREIGN_ATTEMPT.owner_id).is_none());
        drop(first);
        assert_eq!(PREPARATION_GATE_OWNER.load(Ordering::Relaxed), 0);
        let second =
            PreparationGate::acquire(FOREIGN_ATTEMPT.owner_id).expect("drop releases gate");
        drop(second);
        assert_eq!(PREPARATION_GATE_OWNER.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn started_failure_type_and_raii_gate_exclude_not_started() {
        let evidence = function_body(SOURCE, "pub enum StartedPreparationFailureEvidence");
        assert!(evidence.contains("RolledBack(PreparationRollbackReceipt)"));
        assert!(evidence.contains("Indeterminate(PreparationIndeterminate)"));
        assert!(!evidence.contains("NotStarted"));

        let started = function_body(SOURCE, "fn prepare_read_sector0_with_mode(");
        assert!(started.contains("_gate: PreparationGate"));
        assert!(started.contains("Result<PreparedRequest, StartedPrepareReadFailure>"));
        assert!(!started.contains("PrepareReadFailure::not_started"));
        assert!(!started.contains("forget(_gate)"));
        assert!(started.matches("rollback_failed_preparation(").count() >= 6);

        let preflight = function_body(SOURCE, "fn preflight_preparation_start<'a>(");
        let gate = preflight
            .find("PreparationGate::acquire")
            .expect("gate acquisition");
        let dma = preflight
            .find("dma_preparation_is_quiescent")
            .expect("DMA preflight");
        let transport = preflight
            .find("transport_preparation_is_quiescent")
            .expect("transport preflight");
        assert!(gate < dma && dma < transport);
        assert!(!preflight.contains("forget(gate)"));
    }

    #[test]
    fn uncertain_status_or_bus_master_readback_retains_every_owner() {
        let rollback = function_body(SOURCE, "fn rollback_unexposed_preparation(");
        let status = rollback
            .find("status_certain = transport.get_status()")
            .expect("status readback");
        let bus_master = rollback
            .find("disable_bus_master_checked")
            .expect("bus-master readback");
        let uncertainty = rollback
            .find("if !status_certain || !bus_master_certain")
            .expect("uncertainty branch");
        let forget_queue = rollback.find("forget(queue)").expect("retain queue");
        let forget_transport = rollback
            .find("forget(transport)")
            .expect("retain transport");
        let forget_buffers = rollback.find("forget(buffers)").expect("retain buffers");
        let reject = rollback
            .find("return false")
            .expect("typed indeterminate path");
        let drop_queue = rollback.find("drop(queue)").expect("safe teardown");
        let release_claims = rollback
            .find("release_unexposed_transport_claims_checked")
            .expect("checked claim release");
        let abort_dma = rollback
            .find("abort_unexposed_generation")
            .expect("checked DMA release");
        assert!(status < bus_master && bus_master < uncertainty);
        assert!(
            uncertainty < forget_queue
                && forget_queue < forget_transport
                && forget_transport < forget_buffers
                && forget_buffers < reject
                && reject < drop_queue
                && drop_queue < release_claims
                && release_claims < abort_dma
        );

        let started = function_body(SOURCE, "fn prepare_read_sector0_with_mode(");
        assert!(started.contains("enable_device_for_prepare_checked"));
        assert!(started.contains("PrepareReadError::PciCommandStateUnavailable"));
        assert!(started.contains("PrepareReadError::PciCommandReadbackMismatch"));
        assert!(started.contains("finish_failed_preparation(\n                        attempt"));
        assert!(started.contains(
            "PrepareReadError::PciCommandReadbackMismatch,\n                        false"
        ));
    }

    #[test]
    fn receipt_owners_are_opaque_noncopyable_and_publication_is_not_bypassable() {
        let implementation = SOURCE
            .split_once("#[cfg(test)]")
            .expect("test module follows implementation")
            .0;
        for (name, derive) in [
            (
                "PreparationReceipt",
                "#[derive(Debug, Eq, PartialEq)]\npub struct PreparationReceipt",
            ),
            (
                "PreparationRollbackReceipt",
                "#[derive(Debug, Eq, PartialEq)]\npub struct PreparationRollbackReceipt",
            ),
            (
                "PreparationIndeterminate",
                "#[derive(Debug, Eq, PartialEq)]\npub struct PreparationIndeterminate",
            ),
        ] {
            assert!(
                implementation.contains(derive),
                "{name} stays non-Clone/Copy"
            );
            let body = function_body(implementation, &format!("pub struct {name}"));
            let fields = body.split_once('{').expect("struct body").1;
            assert!(!fields.contains("pub "), "{name} fields stay private");
        }
        let owner = function_body(implementation, "pub struct ReceiptedPreparedRequest");
        assert!(!owner.contains("pub request"));
        assert!(!owner.contains("pub receipt"));
        let owner_impl = function_body(implementation, "impl ReceiptedPreparedRequest");
        assert!(owner_impl.contains("receipt(&self) -> &PreparationReceipt"));
        assert!(!owner_impl.contains("into_receipt"));
        assert!(!owner_impl.contains("receipt(self)"));

        assert_eq!(implementation.matches("Ok(PreparationReceipt {").count(), 1);
        assert_eq!(
            implementation
                .matches("PreparationRollbackReceipt {\n            attempt:")
                .count(),
            1,
            "public rollback receipt has exactly one private finish constructor"
        );
        assert_eq!(
            implementation
                .matches("publish_prepared_unchecked()")
                .count(),
            1,
            "only PreparedPublishIntent invokes the private Release"
        );
        assert_eq!(
            implementation
                .matches("prepared.publish_prepared()")
                .count(),
            1,
            "one low-level Release call exists"
        );
        assert!(!implementation.contains("pub fn publish_prepared_unchecked"));
        let publish = function_body(implementation, "impl PreparedPublishIntent");
        assert!(publish.contains("pub fn apply(self) -> PublishedRequest"));
        assert!(publish.contains("publish_prepared_unchecked()"));
    }

    #[test]
    fn issuance_and_quiescence_ordering_make_failures_atomic() {
        let issue = function_body(SOURCE, "pub fn issue_preparation_receipt(");
        let validate = issue.find("prepare_success_receipt(").expect("validation");
        let mark = issue
            .find("active.preparation_receipt_issued = true")
            .expect("issuance mark");
        let wrap = issue
            .find("Ok(ReceiptedPreparedRequest")
            .expect("owner coupling");
        assert!(validate < mark && mark < wrap);
        assert_eq!(
            issue
                .matches("active.preparation_receipt_issued = true")
                .count(),
            1
        );

        let quiescence = function_body(SOURCE, "pub fn apply_unregistered_quiescence(");
        let validate = quiescence
            .find("validate_unregistered_quiescence_projection(")
            .expect("coordinate validation");
        let prepare_receipt = quiescence
            .find("let prepared = match prepare_rollback_receipt(")
            .expect("private receipt preparation");
        let prepare_apply = quiescence
            .find(".prepare_quiescence_apply(closure)")
            .expect("infallible apply preparation");
        let apply = quiescence.find("plan.apply()").expect("active clear");
        let mark = quiescence
            .find("cancellation.quiescence_applied = true")
            .expect("cancellation mark");
        let finish = quiescence
            .find("prepared.finish()")
            .expect("public receipt finish");
        assert!(
            validate < prepare_receipt
                && prepare_receipt < prepare_apply
                && prepare_apply < apply
                && apply < mark
                && mark < finish
        );
    }

    #[test]
    fn indeterminate_rollback_latches_facade_before_diagnostic_returns() {
        let rollback = function_body(SOURCE, "fn rollback_failed_preparation(");
        let error = rollback
            .find("Err(indeterminate)")
            .expect("indeterminate branch");
        let latch = rollback
            .find("self.indeterminate_preparation = Some(attempt)")
            .expect("facade latch");
        let return_value = rollback
            .find("StartedPreparationFailureEvidence::Indeterminate(indeterminate)")
            .expect("diagnostic return");
        assert!(error < latch && latch < return_value);

        let preflight = function_body(SOURCE, "fn preflight_preparation_start<'a>(");
        let quarantine = preflight
            .find("self.indeterminate_preparation.is_some()")
            .expect("latched quarantine check");
        let gate = preflight
            .find("PreparationGate::acquire")
            .expect("gate acquisition");
        assert!(quarantine < gate);
        assert!(preflight.contains("PrepareReadError::HardwareQuarantined"));

        let quiescence = function_body(SOURCE, "pub fn apply_unregistered_quiescence(");
        let indeterminate = quiescence
            .find("Err(indeterminate)")
            .expect("quiescence uncertainty");
        let latch = quiescence
            .find("self.indeterminate_preparation = Some(cancellation.attempt)")
            .expect("quiescence latch");
        let returned = quiescence
            .find("PreparationRollbackError::Indeterminate(indeterminate)")
            .expect("typed quiescence diagnostic");
        assert!(indeterminate < latch && latch < returned);
    }

    #[test]
    fn receipt_shapes_are_fixed_and_bounded() {
        assert_eq!(size_of::<PreparationReceipt>(), 56);
        assert_eq!(size_of::<PreparationRollbackReceipt>(), 80);
        assert_eq!(size_of::<PreparationIndeterminate>(), 64);
        assert!(size_of::<PrepareReadFailure>() <= 192);
        assert!(size_of::<PreparationReceipt>() > 0);
        assert!(size_of::<PreparationRollbackReceipt>() > 0);
    }

    #[test]
    fn device_generation_overflow_is_typed_and_failure_atomic() {
        assert_eq!(next_device_generation(3), Ok(4));
        assert_eq!(
            next_device_generation(u64::MAX),
            Err(ResetGenerationError::GenerationOverflow)
        );
    }

    #[test]
    fn unregistered_reset_projection_requires_exact_attempt_unpublished_three_owner_ack() {
        let base = UnregisteredResetProjection {
            attempt: ATTEMPT,
            identity: IDENTITY,
            published: false,
            descriptor_popped: false,
            completed: false,
            retained_pages: 3,
        };
        assert_eq!(
            validate_unregistered_reset_projection(
                Some((ATTEMPT, IDENTITY)),
                ATTEMPT,
                IDENTITY,
                base,
            ),
            Ok(())
        );
        for (published, descriptor_popped, completed, pages, expected) in [
            (
                true,
                false,
                false,
                3,
                UnregisteredCancellationError::WasPublished,
            ),
            (
                false,
                true,
                false,
                3,
                UnregisteredCancellationError::DescriptorPopped,
            ),
            (
                false,
                false,
                true,
                3,
                UnregisteredCancellationError::Completed,
            ),
            (
                false,
                false,
                false,
                2,
                UnregisteredCancellationError::WrongRetainedPages,
            ),
        ] {
            assert_eq!(
                validate_unregistered_reset_projection(
                    Some((ATTEMPT, IDENTITY)),
                    ATTEMPT,
                    IDENTITY,
                    UnregisteredResetProjection {
                        published,
                        descriptor_popped,
                        completed,
                        retained_pages: pages,
                        ..base
                    },
                ),
                Err(expected)
            );
        }
        assert_eq!(
            validate_unregistered_reset_projection(
                Some((ATTEMPT, IDENTITY)),
                ATTEMPT,
                IDENTITY,
                UnregisteredResetProjection {
                    identity: FOREIGN_IDENTITY,
                    ..base
                },
            ),
            Err(UnregisteredCancellationError::WrongIdentity)
        );
        assert_eq!(
            validate_unregistered_reset_projection(
                Some((ATTEMPT, IDENTITY)),
                ATTEMPT,
                IDENTITY,
                UnregisteredResetProjection {
                    attempt: FOREIGN_ATTEMPT,
                    ..base
                },
            ),
            Err(UnregisteredCancellationError::WrongAttempt)
        );
        assert_eq!(
            validate_unregistered_reset_projection(None, ATTEMPT, IDENTITY, base),
            Err(UnregisteredCancellationError::NoActiveSession)
        );
    }

    #[test]
    fn unregistered_quiescence_requires_attempt_reset_and_exact_three_owner_closure() {
        assert_eq!(
            validate_unregistered_quiescence_projection(
                Some((ATTEMPT, IDENTITY)),
                ATTEMPT,
                IDENTITY,
                true,
                ATTEMPT,
                IDENTITY,
                3,
            ),
            Ok(())
        );
        assert_eq!(
            validate_unregistered_quiescence_projection(
                Some((ATTEMPT, IDENTITY)),
                ATTEMPT,
                IDENTITY,
                false,
                ATTEMPT,
                IDENTITY,
                3,
            ),
            Err(UnregisteredCancellationError::ResetNotApplied)
        );
        assert_eq!(
            validate_unregistered_quiescence_projection(
                Some((ATTEMPT, IDENTITY)),
                ATTEMPT,
                IDENTITY,
                true,
                ATTEMPT,
                FOREIGN_IDENTITY,
                3,
            ),
            Err(UnregisteredCancellationError::WrongIdentity)
        );
        assert_eq!(
            validate_unregistered_quiescence_projection(
                Some((ATTEMPT, IDENTITY)),
                ATTEMPT,
                IDENTITY,
                true,
                ATTEMPT,
                IDENTITY,
                2,
            ),
            Err(UnregisteredCancellationError::WrongCompletedPages)
        );
        assert_eq!(
            validate_unregistered_quiescence_projection(
                Some((ATTEMPT, IDENTITY)),
                ATTEMPT,
                IDENTITY,
                true,
                FOREIGN_ATTEMPT,
                IDENTITY,
                3,
            ),
            Err(UnregisteredCancellationError::WrongAttempt)
        );
    }

    #[test]
    fn attempt_identity_propagates_through_every_hardware_successor() {
        for type_name in [
            "PreparedRequest",
            "ActiveSession",
            "UnregisteredPreparedCancellation",
            "PublishedRequest",
            "ResetSession",
            "ProductionResetAck",
            "ProductionIotlbTombstone",
            "ProductionClosureReceipt",
            "InterruptReceipt",
        ] {
            let body = function_body(SOURCE, &format!("struct {type_name}"));
            assert!(
                body.contains("attempt: PreparationAttemptIdentity"),
                "{type_name} must retain exact preparation attempt"
            );
        }
    }
}
